use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio::sync::Mutex;

const CLEANUP_DELAY_MS: u64 = 60_000;
const HEARTBEAT_INTERVAL_MS: u64 = 30_000;
const MAC_ABSENCE_GRACE_MS: u64 = 15_000;
const CLOSE_CODE_INVALID: u16 = 4000;
const CLOSE_CODE_MAC_REPLACED: u16 = 4001;
const CLOSE_CODE_SESSION_UNAVAILABLE: u16 = 4002;
const CLOSE_CODE_IPHONE_REPLACED: u16 = 4003;
const CLOSE_CODE_MAC_ABSENCE_BUFFER_FULL: u16 = 4004;
const TRUSTED_SESSION_RESOLVE_TAG: &str = "remodex-trusted-session-resolve-v1";
const TRUSTED_SESSION_RESOLVE_SKEW_MS: u64 = 90_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Mac,
    Iphone,
}

impl Role {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.trim() {
            "mac" => Some(Role::Mac),
            "iphone" => Some(Role::Iphone),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Mac => "mac",
            Role::Iphone => "iphone",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MacRegistration {
    pub session_id: String,
    pub mac_device_id: String,
    pub mac_identity_public_key: String,
    pub display_name: String,
    pub trusted_phone_device_id: String,
    pub trusted_phone_public_key: String,
}

type ClientId = u64;

/// A handle to send messages to a connected WebSocket client.
#[derive(Clone)]
pub struct ClientHandle {
    id: ClientId,
    tx: mpsc::UnboundedSender<ClientMessage>,
}

enum ClientMessage {
    Text(String),
    Close(u16, String),
    Ping,
}

struct Session {
    mac: Option<ClientHandle>,
    clients: HashMap<ClientId, ClientHandle>,
    cleanup_timer: Option<tokio::task::JoinHandle<()>>,
    mac_absence_timer: Option<tokio::task::JoinHandle<()>>,
    notification_secret: Option<String>,
    mac_registration: Option<MacRegistration>,
}

/// Nonce entry for replay prevention.
struct UsedNonce {
    expires_at_ms: u64,
}

pub struct RelayState {
    sessions: Mutex<HashMap<String, Session>>,
    next_client_id: Mutex<u64>,
    /// Maps mac_device_id -> MacRegistration for live session lookup.
    live_sessions_by_mac_device_id: Mutex<HashMap<String, MacRegistration>>,
    /// Replay prevention: (mac_device_id, phone_device_id, nonce) -> expiry.
    used_resolve_nonces: Mutex<HashMap<String, UsedNonce>>,
}

impl RelayState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            sessions: Mutex::new(HashMap::new()),
            next_client_id: Mutex::new(1),
            live_sessions_by_mac_device_id: Mutex::new(HashMap::new()),
            used_resolve_nonces: Mutex::new(HashMap::new()),
        })
    }

    async fn next_id(&self) -> ClientId {
        let mut id = self.next_client_id.lock().await;
        let current = *id;
        *id += 1;
        current
    }
}

pub fn relay_session_log_label(session_id: &str) -> String {
    let normalized = session_id.trim();
    if normalized.is_empty() {
        return "session=[redacted]".to_string();
    }
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    let digest = hex::encode(hasher.finalize());
    format!("session#{}", &digest[..8])
}

pub async fn get_relay_stats(state: &Arc<RelayState>) -> RelayStats {
    let sessions = state.sessions.lock().await;
    let mut total_clients = 0usize;
    let mut sessions_with_mac = 0usize;

    for session in sessions.values() {
        total_clients += session.clients.len();
        if session.mac.is_some() {
            sessions_with_mac += 1;
        }
    }

    RelayStats {
        active_sessions: sessions.len(),
        sessions_with_mac,
        total_clients,
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayStats {
    pub active_sessions: usize,
    pub sessions_with_mac: usize,
    pub total_clients: usize,
}

pub async fn has_active_mac_session(state: &Arc<RelayState>, session_id: &str) -> bool {
    let trimmed = session_id.trim();
    if trimmed.is_empty() {
        return false;
    }
    let sessions = state.sessions.lock().await;
    matches!(
        sessions.get(trimmed),
        Some(session) if session.mac.as_ref().is_some_and(|m| !m.tx.is_closed())
    )
}

pub async fn has_authenticated_mac_session(
    state: &Arc<RelayState>,
    session_id: &str,
    notification_secret: &str,
) -> bool {
    if !has_active_mac_session(state, session_id).await {
        return false;
    }
    let sessions = state.sessions.lock().await;
    let trimmed = session_id.trim();
    match sessions.get(trimmed) {
        Some(session) => match &session.notification_secret {
            Some(stored) => {
                let secret = notification_secret.trim();
                if secret.is_empty() || stored.is_empty() {
                    return false;
                }
                timing_safe_eq(stored.as_bytes(), secret.as_bytes())
            }
            None => false,
        },
        None => false,
    }
}

fn timing_safe_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

pub async fn handle_ws_connection(
    state: Arc<RelayState>,
    session_id: String,
    role: Option<Role>,
    notification_secret: Option<String>,
    mac_registration_headers: Option<MacRegistrationHeaders>,
    socket: WebSocket,
) {
    let session_id_trimmed = session_id.trim().to_string();

    let role = match role {
        Some(r) if !session_id_trimmed.is_empty() => r,
        _ => {
            let (mut sink, _) = socket.split();
            let _ = sink
                .send(Message::Close(Some(CloseFrame {
                    code: CLOSE_CODE_INVALID,
                    reason: "Missing sessionId or invalid x-role header".into(),
                })))
                .await;
            return;
        }
    };

    let client_id = state.next_id().await;
    let (msg_tx, mut msg_rx) = mpsc::unbounded_channel::<ClientMessage>();
    let handle = ClientHandle {
        id: client_id,
        tx: msg_tx,
    };

    // Session setup under lock
    {
        let mut sessions = state.sessions.lock().await;

        // iPhone can only join if session exists
        if role == Role::Iphone && !sessions.contains_key(&session_id_trimmed) {
            drop(sessions);
            let (mut sink, _) = socket.split();
            let _ = sink
                .send(Message::Close(Some(CloseFrame {
                    code: CLOSE_CODE_SESSION_UNAVAILABLE,
                    reason: "Mac session not available".into(),
                })))
                .await;
            return;
        }

        // Create session if doesn't exist (only Mac reaches here)
        if !sessions.contains_key(&session_id_trimmed) {
            sessions.insert(
                session_id_trimmed.clone(),
                Session {
                    mac: None,
                    clients: HashMap::new(),
                    cleanup_timer: None,
                    mac_absence_timer: None,
                    notification_secret: None,
                    mac_registration: None,
                },
            );
        }

        let session = sessions.get_mut(&session_id_trimmed).unwrap();

        // iPhone requires active Mac or an active mac-absence grace window
        if role == Role::Iphone
            && session.mac.is_none()
            && session.mac_absence_timer.is_none()
        {
            drop(sessions);
            let (mut sink, _) = socket.split();
            let _ = sink
                .send(Message::Close(Some(CloseFrame {
                    code: CLOSE_CODE_SESSION_UNAVAILABLE,
                    reason: "Mac session not available".into(),
                })))
                .await;
            return;
        }

        // Cancel cleanup timer
        if let Some(timer) = session.cleanup_timer.take() {
            timer.abort();
        }

        match role {
            Role::Mac => {
                // Clear mac absence timer if Mac reconnects during grace period
                if let Some(timer) = session.mac_absence_timer.take() {
                    timer.abort();
                }

                session.notification_secret = notification_secret
                    .as_deref()
                    .and_then(|s| {
                        let trimmed = s.trim();
                        if trimmed.is_empty() {
                            None
                        } else {
                            Some(trimmed.to_string())
                        }
                    });

                // Build mac registration from headers
                let registration = mac_registration_headers
                    .as_ref()
                    .map(|h| normalize_mac_registration(h, &session_id_trimmed));
                session.mac_registration = registration.clone();

                // Replace existing Mac connection
                if let Some(old_mac) = session.mac.take() {
                    let _ = old_mac.tx.send(ClientMessage::Close(
                        CLOSE_CODE_MAC_REPLACED,
                        "Replaced by new Mac connection".to_string(),
                    ));
                }
                session.mac = Some(handle.clone());

                // Register live session for trusted resolve
                if let Some(ref reg) = registration {
                    register_live_mac_session(&state, reg).await;
                }

                tracing::info!(
                    "[relay] Mac connected -> {}",
                    relay_session_log_label(&session_id_trimmed)
                );
            }
            Role::Iphone => {
                // Close all existing iPhone connections (keep one live)
                let old_ids: Vec<ClientId> = session.clients.keys().copied().collect();
                for old_id in old_ids {
                    if old_id != client_id {
                        if let Some(old_client) = session.clients.remove(&old_id) {
                            let _ = old_client.tx.send(ClientMessage::Close(
                                CLOSE_CODE_IPHONE_REPLACED,
                                "Replaced by newer iPhone connection".to_string(),
                            ));
                        }
                    }
                }
                session.clients.insert(client_id, handle.clone());
                tracing::info!(
                    "[relay] iPhone connected -> {} ({} client(s))",
                    relay_session_log_label(&session_id_trimmed),
                    session.clients.len()
                );
            }
        }
    }

    // Split the WebSocket
    let (mut ws_sink, mut ws_stream) = socket.split();

    // Spawn a task to forward messages from the channel to the WebSocket
    let send_task = tokio::spawn(async move {
        while let Some(msg) = msg_rx.recv().await {
            let result = match msg {
                ClientMessage::Text(text) => ws_sink.send(Message::Text(text.into())).await,
                ClientMessage::Close(code, reason) => {
                    let _ = ws_sink
                        .send(Message::Close(Some(CloseFrame {
                            code,
                            reason: reason.into(),
                        })))
                        .await;
                    break;
                }
                ClientMessage::Ping => ws_sink.send(Message::Ping(Vec::new().into())).await,
            };
            if result.is_err() {
                break;
            }
        }
    });

    // Heartbeat task — sends pings every 30s, terminates if no pong received since last ping.
    let heartbeat_handle = handle.clone();
    let alive_flag = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let alive_flag_reader = alive_flag.clone();
    let heartbeat_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(HEARTBEAT_INTERVAL_MS));
        interval.tick().await; // skip immediate first tick
        loop {
            interval.tick().await;
            if !alive_flag_reader.load(std::sync::atomic::Ordering::Relaxed) {
                // No pong received since last ping — terminate
                let _ = heartbeat_handle.tx.send(ClientMessage::Close(
                    1000,
                    "Heartbeat timeout".to_string(),
                ));
                break;
            }
            alive_flag_reader.store(false, std::sync::atomic::Ordering::Relaxed);
            if heartbeat_handle.tx.send(ClientMessage::Ping).is_err() {
                break;
            }
        }
    });

    // Read messages from the WebSocket and forward to the appropriate target
    while let Some(msg_result) = ws_stream.next().await {
        match msg_result {
            Ok(Message::Text(text)) => {
                // Intercept mac registration update messages
                if role == Role::Mac {
                    if apply_mac_registration_message(&state, &session_id_trimmed, &text).await {
                        continue;
                    }
                }

                let sessions = state.sessions.lock().await;
                if let Some(session) = sessions.get(&session_id_trimmed) {
                    match role {
                        Role::Mac => {
                            for client in session.clients.values() {
                                let _ = client.tx.send(ClientMessage::Text(text.to_string()));
                            }
                        }
                        Role::Iphone => {
                            if let Some(mac) = &session.mac {
                                let _ = mac.tx.send(ClientMessage::Text(text.to_string()));
                            } else {
                                let _ = handle.tx.send(ClientMessage::Close(
                                    CLOSE_CODE_MAC_ABSENCE_BUFFER_FULL,
                                    "Mac temporarily unavailable".to_string(),
                                ));
                            }
                        }
                    }
                }
            }
            Ok(Message::Binary(data)) => {
                let text = String::from_utf8_lossy(&data).to_string();

                // Intercept mac registration update messages (same as text path)
                if role == Role::Mac {
                    if apply_mac_registration_message(&state, &session_id_trimmed, &text).await {
                        continue;
                    }
                }

                let sessions = state.sessions.lock().await;
                if let Some(session) = sessions.get(&session_id_trimmed) {
                    match role {
                        Role::Mac => {
                            for client in session.clients.values() {
                                let _ = client.tx.send(ClientMessage::Text(text.clone()));
                            }
                        }
                        Role::Iphone => {
                            if let Some(mac) = &session.mac {
                                let _ = mac.tx.send(ClientMessage::Text(text.clone()));
                            } else {
                                let _ = handle.tx.send(ClientMessage::Close(
                                    CLOSE_CODE_MAC_ABSENCE_BUFFER_FULL,
                                    "Mac temporarily unavailable".to_string(),
                                ));
                            }
                        }
                    }
                }
            }
            Ok(Message::Pong(_)) => {
                alive_flag.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            Ok(Message::Ping(_)) => {
                // Pong is sent automatically by tungstenite
            }
            Ok(Message::Close(_)) | Err(_) => {
                break;
            }
        }
    }

    // Cleanup on disconnect
    heartbeat_task.abort();
    send_task.abort();

    {
        let mut sessions = state.sessions.lock().await;
        if let Some(session) = sessions.get_mut(&session_id_trimmed) {
            match role {
                Role::Mac => {
                    if session.mac.as_ref().is_some_and(|m| m.id == client_id) {
                        session.mac = None;
                        unregister_live_mac_session(
                            &state,
                            session.mac_registration.as_ref(),
                            &session_id_trimmed,
                        )
                        .await;
                        tracing::info!(
                            "[relay] Mac disconnected -> {}",
                            relay_session_log_label(&session_id_trimmed)
                        );

                        if !session.clients.is_empty() {
                            // Start mac absence grace period instead of immediately closing iPhones.
                            // iPhone can rejoin or keep sending during this window.
                            if session.mac_absence_timer.is_none() {
                                let state_clone = state.clone();
                                let sid = session_id_trimmed.clone();
                                session.mac_absence_timer =
                                    Some(tokio::spawn(async move {
                                        tokio::time::sleep(Duration::from_millis(
                                            MAC_ABSENCE_GRACE_MS,
                                        ))
                                        .await;
                                        let mut sessions = state_clone.sessions.lock().await;
                                        if let Some(session) = sessions.get_mut(&sid) {
                                            session.mac_absence_timer = None;
                                            session.notification_secret = None;
                                            // Unregister live session after grace period
                                            let reg = session.mac_registration.clone();
                                            drop(sessions);
                                            unregister_live_mac_session(
                                                &state_clone,
                                                reg.as_ref(),
                                                &sid,
                                            )
                                            .await;
                                            let mut sessions =
                                                state_clone.sessions.lock().await;
                                            if let Some(session) = sessions.get_mut(&sid) {
                                                // Close all iPhone clients after grace period expires
                                                for client in session.clients.values() {
                                                    let _ =
                                                        client.tx.send(ClientMessage::Close(
                                                            CLOSE_CODE_SESSION_UNAVAILABLE,
                                                            "Mac disconnected".to_string(),
                                                        ));
                                                }
                                                // Schedule cleanup
                                                schedule_cleanup(&state_clone, &sid, session);
                                            }
                                        }
                                    }));
                                // Cancel cleanup timer while grace period is active
                                if let Some(timer) = session.cleanup_timer.take() {
                                    timer.abort();
                                }
                            }
                        } else {
                            session.notification_secret = None;
                        }
                    }
                }
                Role::Iphone => {
                    session.clients.remove(&client_id);
                    tracing::info!(
                        "[relay] iPhone disconnected -> {} ({} remaining)",
                        relay_session_log_label(&session_id_trimmed),
                        session.clients.len()
                    );
                }
            }

            // Schedule cleanup if session is empty and no grace timer active
            schedule_cleanup(&state, &session_id_trimmed, session);
        }
    }
}

fn schedule_cleanup(state: &Arc<RelayState>, session_id: &str, session: &mut Session) {
    if session.mac.is_some()
        || !session.clients.is_empty()
        || session.cleanup_timer.is_some()
        || session.mac_absence_timer.is_some()
    {
        return;
    }

    let state_clone = state.clone();
    let sid = session_id.to_string();
    session.cleanup_timer = Some(tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(CLEANUP_DELAY_MS)).await;
        let mut sessions = state_clone.sessions.lock().await;
        if let Some(session) = sessions.get(&sid) {
            if session.mac.is_none()
                && session.clients.is_empty()
                && session.mac_absence_timer.is_none()
            {
                let reg = session.mac_registration.clone();
                sessions.remove(&sid);
                drop(sessions);
                unregister_live_mac_session(&state_clone, reg.as_ref(), &sid).await;
                tracing::info!("[relay] {} cleaned up", relay_session_log_label(&sid));
            }
        }
    }));
}

// --- Mac registration helpers ---

/// Raw header values extracted from the WebSocket upgrade request.
pub struct MacRegistrationHeaders {
    pub mac_device_id: Option<String>,
    pub mac_identity_public_key: Option<String>,
    pub machine_name: Option<String>,
    pub trusted_phone_device_id: Option<String>,
    pub trusted_phone_public_key: Option<String>,
}

fn normalize_non_empty_string(value: Option<&str>) -> String {
    match value {
        Some(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                String::new()
            } else {
                trimmed.to_string()
            }
        }
        None => String::new(),
    }
}

fn normalize_mac_registration(headers: &MacRegistrationHeaders, session_id: &str) -> MacRegistration {
    MacRegistration {
        session_id: session_id.to_string(),
        mac_device_id: normalize_non_empty_string(headers.mac_device_id.as_deref()),
        mac_identity_public_key: normalize_non_empty_string(
            headers.mac_identity_public_key.as_deref(),
        ),
        display_name: normalize_non_empty_string(headers.machine_name.as_deref()),
        trusted_phone_device_id: normalize_non_empty_string(
            headers.trusted_phone_device_id.as_deref(),
        ),
        trusted_phone_public_key: normalize_non_empty_string(
            headers.trusted_phone_public_key.as_deref(),
        ),
    }
}

async fn register_live_mac_session(state: &Arc<RelayState>, registration: &MacRegistration) {
    if registration.mac_device_id.is_empty() {
        return;
    }
    let mut live = state.live_sessions_by_mac_device_id.lock().await;
    live.insert(registration.mac_device_id.clone(), registration.clone());
}

async fn unregister_live_mac_session(
    state: &Arc<RelayState>,
    registration: Option<&MacRegistration>,
    session_id: &str,
) {
    let registration = match registration {
        Some(r) if !r.mac_device_id.is_empty() => r,
        _ => return,
    };
    let mut live = state.live_sessions_by_mac_device_id.lock().await;
    // Only remove if the session_id still matches (prevent race conditions)
    if let Some(existing) = live.get(&registration.mac_device_id) {
        if existing.session_id == session_id {
            live.remove(&registration.mac_device_id);
        }
    }
}

/// Intercepts `relayMacRegistration` messages from the Mac to update trusted phone metadata.
async fn apply_mac_registration_message(
    state: &Arc<RelayState>,
    session_id: &str,
    raw_message: &str,
) -> bool {
    let parsed: serde_json::Value = match serde_json::from_str(raw_message) {
        Ok(v) => v,
        Err(_) => return false,
    };

    if parsed.get("kind").and_then(|v| v.as_str()) != Some("relayMacRegistration") {
        return false;
    }

    // JS reads from parsed.registration (nested object), not the top level
    let registration = match parsed.get("registration") {
        Some(reg) if reg.is_object() => reg,
        _ => return false,
    };

    let headers = MacRegistrationHeaders {
        mac_device_id: registration
            .get("macDeviceId")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        mac_identity_public_key: registration
            .get("macIdentityPublicKey")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        machine_name: registration
            .get("displayName")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        trusted_phone_device_id: registration
            .get("trustedPhoneDeviceId")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        trusted_phone_public_key: registration
            .get("trustedPhonePublicKey")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    };

    let registration = normalize_mac_registration(&headers, session_id);

    {
        let mut sessions = state.sessions.lock().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.mac_registration = Some(registration.clone());
        }
    }

    register_live_mac_session(state, &registration).await;
    true
}

// --- Trusted session resolve ---

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedSessionResolveRequest {
    pub mac_device_id: Option<String>,
    pub phone_device_id: Option<String>,
    pub phone_identity_public_key: Option<String>,
    pub timestamp: Option<serde_json::Value>,
    pub nonce: Option<String>,
    pub signature: Option<String>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedSessionResolveResponse {
    pub ok: bool,
    pub mac_device_id: String,
    pub mac_identity_public_key: String,
    pub display_name: Option<String>,
    pub session_id: String,
}

pub struct RelayError {
    pub status: u16,
    pub code: String,
    pub message: String,
}

fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub async fn resolve_trusted_mac_session(
    state: &Arc<RelayState>,
    req: TrustedSessionResolveRequest,
) -> Result<TrustedSessionResolveResponse, RelayError> {
    let mac_device_id = normalize_non_empty_string(req.mac_device_id.as_deref());
    let phone_device_id = normalize_non_empty_string(req.phone_device_id.as_deref());
    let phone_public_key = normalize_non_empty_string(req.phone_identity_public_key.as_deref());
    let nonce = normalize_non_empty_string(req.nonce.as_deref());
    let signature = normalize_non_empty_string(req.signature.as_deref());

    // Parse timestamp from number or string
    let timestamp: u64 = match &req.timestamp {
        Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(0),
        Some(serde_json::Value::String(s)) => s.trim().parse().unwrap_or(0),
        _ => 0,
    };

    if mac_device_id.is_empty()
        || phone_device_id.is_empty()
        || phone_public_key.is_empty()
        || nonce.is_empty()
        || signature.is_empty()
        || timestamp == 0
    {
        return Err(RelayError {
            status: 400,
            code: "invalid_request".to_string(),
            message: "Missing required fields".to_string(),
        });
    }

    // Check timestamp freshness
    let now = current_time_ms();
    let diff = if now > timestamp {
        now - timestamp
    } else {
        timestamp - now
    };
    if diff > TRUSTED_SESSION_RESOLVE_SKEW_MS {
        return Err(RelayError {
            status: 401,
            code: "resolve_request_expired".to_string(),
            message: "Resolve request expired".to_string(),
        });
    }

    // Prune expired nonces and check for replay
    let nonce_key = format!("{}|{}|{}", mac_device_id, phone_device_id, nonce);
    {
        let mut nonces = state.used_resolve_nonces.lock().await;
        nonces.retain(|_, v| v.expires_at_ms > now);
        if nonces.contains_key(&nonce_key) {
            return Err(RelayError {
                status: 409,
                code: "resolve_request_replayed".to_string(),
                message: "Resolve request replayed".to_string(),
            });
        }
    }

    // Look up live session and verify Mac WebSocket is still open
    let registration = {
        let live = state.live_sessions_by_mac_device_id.lock().await;
        live.get(&mac_device_id).cloned()
    };
    let registration = match registration {
        Some(ref r) if has_active_mac_session(state, &r.session_id).await => r.clone(),
        _ => {
            return Err(RelayError {
                status: 404,
                code: "session_unavailable".to_string(),
                message: "Mac session not available".to_string(),
            });
        }
    };

    // Verify phone is trusted
    if registration.trusted_phone_device_id != phone_device_id
        || registration.trusted_phone_public_key != phone_public_key
    {
        return Err(RelayError {
            status: 403,
            code: "phone_not_trusted".to_string(),
            message: "Phone is not trusted for this Mac".to_string(),
        });
    }

    // Build transcript and verify signature
    let transcript =
        build_trusted_session_resolve_bytes(&mac_device_id, &phone_device_id, &phone_public_key, &nonce, timestamp);
    let transcript = match transcript {
        Some(t) => t,
        None => {
            return Err(RelayError {
                status: 400,
                code: "invalid_request".to_string(),
                message: "Failed to build transcript".to_string(),
            });
        }
    };

    if !verify_ed25519_signature(&phone_public_key, &transcript, &signature) {
        return Err(RelayError {
            status: 403,
            code: "invalid_signature".to_string(),
            message: "Invalid signature".to_string(),
        });
    }

    // Record nonce as consumed
    {
        let mut nonces = state.used_resolve_nonces.lock().await;
        nonces.insert(
            nonce_key,
            UsedNonce {
                expires_at_ms: now + TRUSTED_SESSION_RESOLVE_SKEW_MS,
            },
        );
    }

    let display_name = if registration.display_name.is_empty() {
        None
    } else {
        Some(registration.display_name.clone())
    };

    Ok(TrustedSessionResolveResponse {
        ok: true,
        mac_device_id: registration.mac_device_id,
        mac_identity_public_key: registration.mac_identity_public_key,
        display_name,
        session_id: registration.session_id,
    })
}

// --- Crypto helpers ---

fn build_trusted_session_resolve_bytes(
    mac_device_id: &str,
    phone_device_id: &str,
    phone_public_key_base64: &str,
    nonce: &str,
    timestamp: u64,
) -> Option<Vec<u8>> {
    let engine = base64::engine::general_purpose::STANDARD;
    let phone_public_key_bytes = engine.decode(phone_public_key_base64).ok()?;

    let mut buf = Vec::new();

    // Length-prefixed fields matching the JS implementation
    let tag_bytes = TRUSTED_SESSION_RESOLVE_TAG.as_bytes();
    buf.extend_from_slice(&(tag_bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(tag_bytes);

    let mac_bytes = mac_device_id.as_bytes();
    buf.extend_from_slice(&(mac_bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(mac_bytes);

    let phone_id_bytes = phone_device_id.as_bytes();
    buf.extend_from_slice(&(phone_id_bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(phone_id_bytes);

    buf.extend_from_slice(&(phone_public_key_bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(&phone_public_key_bytes);

    let nonce_bytes = nonce.as_bytes();
    buf.extend_from_slice(&(nonce_bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(nonce_bytes);

    let ts_str = timestamp.to_string();
    let ts_bytes = ts_str.as_bytes();
    buf.extend_from_slice(&(ts_bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(ts_bytes);

    Some(buf)
}

fn verify_ed25519_signature(
    public_key_base64: &str,
    message: &[u8],
    signature_base64: &str,
) -> bool {
    let engine = base64::engine::general_purpose::STANDARD;

    let pk_bytes = match engine.decode(public_key_base64) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let sig_bytes = match engine.decode(signature_base64) {
        Ok(b) => b,
        Err(_) => return false,
    };

    // Ed25519 public key is 32 bytes
    let pk_bytes: [u8; 32] = match pk_bytes.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };

    let verifying_key = match VerifyingKey::from_bytes(&pk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let signature = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    use ed25519_dalek::Verifier;
    verifying_key.verify(message, &signature).is_ok()
}
