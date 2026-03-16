use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio::sync::Mutex;

const CLEANUP_DELAY_MS: u64 = 60_000;
const HEARTBEAT_INTERVAL_MS: u64 = 30_000;
const CLOSE_CODE_INVALID: u16 = 4000;
const CLOSE_CODE_MAC_REPLACED: u16 = 4001;
const CLOSE_CODE_SESSION_UNAVAILABLE: u16 = 4002;
const CLOSE_CODE_IPHONE_REPLACED: u16 = 4003;

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
    notification_secret: Option<String>,
}

pub struct RelayState {
    sessions: Mutex<HashMap<String, Session>>,
    next_client_id: Mutex<u64>,
}

impl RelayState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            sessions: Mutex::new(HashMap::new()),
            next_client_id: Mutex::new(1),
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
                    notification_secret: None,
                },
            );
        }

        let session = sessions.get_mut(&session_id_trimmed).unwrap();

        // iPhone requires active Mac
        if role == Role::Iphone && session.mac.is_none() {
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

                // Replace existing Mac connection
                if let Some(old_mac) = session.mac.take() {
                    let _ = old_mac.tx.send(ClientMessage::Close(
                        CLOSE_CODE_MAC_REPLACED,
                        "Replaced by new Mac connection".to_string(),
                    ));
                }
                session.mac = Some(handle.clone());
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
                            }
                        }
                    }
                }
            }
            Ok(Message::Binary(data)) => {
                let text = String::from_utf8_lossy(&data).to_string();
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
                        session.notification_secret = None;
                        tracing::info!(
                            "[relay] Mac disconnected -> {}",
                            relay_session_log_label(&session_id_trimmed)
                        );
                        // Close all iPhone clients
                        for client in session.clients.values() {
                            let _ = client.tx.send(ClientMessage::Close(
                                CLOSE_CODE_SESSION_UNAVAILABLE,
                                "Mac disconnected".to_string(),
                            ));
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

            // Schedule cleanup if session is empty
            if session.mac.is_none() && session.clients.is_empty() && session.cleanup_timer.is_none()
            {
                let state_clone = state.clone();
                let sid = session_id_trimmed.clone();
                session.cleanup_timer = Some(tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(CLEANUP_DELAY_MS)).await;
                    let mut sessions = state_clone.sessions.lock().await;
                    if let Some(session) = sessions.get(&sid) {
                        if session.mac.is_none() && session.clients.is_empty() {
                            sessions.remove(&sid);
                            tracing::info!(
                                "[relay] {} cleaned up",
                                relay_session_log_label(&sid)
                            );
                        }
                    }
                }));
            }
        }
    }
}
