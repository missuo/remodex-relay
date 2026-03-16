use crate::apns_client::ApnsClient;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;

const PUSH_DEDUPE_TTL_MS: u64 = 24 * 60 * 60 * 1000;
const PUSH_SESSION_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000;
const PUSH_PREVIEW_MAX_CHARS: usize = 160;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushSessionEntry {
    pub notification_secret: String,
    pub device_token: String,
    pub alerts_enabled: bool,
    pub apns_environment: String,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedState {
    sessions: Vec<(String, PushSessionEntry)>,
    delivered_dedupe_keys: Vec<(String, u64)>,
}

pub struct PushSessionService {
    apns_client: Arc<ApnsClient>,
    sessions: Mutex<HashMap<String, PushSessionEntry>>,
    delivered_dedupe_keys: Mutex<HashMap<String, u64>>,
    state_file_path: Option<PathBuf>,
    relay_state: Arc<crate::relay::RelayState>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PushStats {
    pub registered_sessions: usize,
    pub delivered_dedupe_keys: usize,
    pub apns_configured: bool,
}

#[derive(Debug)]
pub struct PushServiceError {
    pub code: String,
    pub message: String,
    pub status: u16,
}

impl PushSessionService {
    pub fn new(
        apns_client: Arc<ApnsClient>,
        state_file_path: Option<PathBuf>,
        relay_state: Arc<crate::relay::RelayState>,
    ) -> Arc<Self> {
        let persisted = state_file_path
            .as_ref()
            .and_then(|p| read_state_file(p))
            .unwrap_or_else(empty_state);

        let mut sessions: HashMap<String, PushSessionEntry> = persisted
            .sessions
            .into_iter()
            .collect();
        let mut dedupe_keys: HashMap<String, u64> = persisted
            .delivered_dedupe_keys
            .into_iter()
            .collect();

        let now = now_ms();
        // Prune stale state
        let session_cutoff = now.saturating_sub(PUSH_SESSION_TTL_MS);
        sessions.retain(|_, v| v.updated_at >= session_cutoff);
        let dedupe_cutoff = now.saturating_sub(PUSH_DEDUPE_TTL_MS);
        dedupe_keys.retain(|_, v| *v >= dedupe_cutoff);

        let service = Arc::new(Self {
            apns_client,
            sessions: Mutex::new(sessions),
            delivered_dedupe_keys: Mutex::new(dedupe_keys),
            state_file_path,
            relay_state,
        });

        // Persist after pruning
        let service_clone = service.clone();
        tokio::spawn(async move {
            service_clone.persist_state("pruneStaleState").await;
        });

        service
    }

    pub async fn register_device(
        &self,
        body: &RegisterDeviceRequest,
    ) -> Result<serde_json::Value, PushServiceError> {
        let session_id = read_string(&body.session_id);
        let secret = read_string(&body.notification_secret);
        let device_token = normalize_device_token(&body.device_token);

        if session_id.is_empty() || secret.is_empty() || device_token.is_empty() {
            return Err(PushServiceError {
                code: "invalid_request".to_string(),
                message: "Push registration requires sessionId, notificationSecret, and deviceToken.".to_string(),
                status: 400,
            });
        }

        // Check relay has active authenticated mac session
        if !crate::relay::has_authenticated_mac_session(&self.relay_state, &session_id, &secret)
            .await
        {
            return Err(PushServiceError {
                code: "session_unavailable".to_string(),
                message: "Push registration requires an active relay session.".to_string(),
                status: 403,
            });
        }

        let mut sessions = self.sessions.lock().await;

        // If existing entry, verify secret matches
        if let Some(existing) = sessions.get(&session_id) {
            if !secrets_equal(&existing.notification_secret, &secret) {
                return Err(PushServiceError {
                    code: "unauthorized".to_string(),
                    message: "Invalid notification secret for this session.".to_string(),
                    status: 403,
                });
            }
        }

        let apns_env = if body.apns_environment.as_deref() == Some("development") {
            "development"
        } else {
            "production"
        };

        sessions.insert(
            session_id,
            PushSessionEntry {
                notification_secret: secret,
                device_token,
                alerts_enabled: body.alerts_enabled.unwrap_or(false),
                apns_environment: apns_env.to_string(),
                updated_at: now_ms(),
            },
        );
        drop(sessions);

        self.persist_state("registerDevice").await;
        Ok(serde_json::json!({ "ok": true }))
    }

    pub async fn notify_completion(
        &self,
        body: &NotifyCompletionRequest,
    ) -> Result<serde_json::Value, PushServiceError> {
        let session_id = read_string(&body.session_id);
        let secret = read_string(&body.notification_secret);
        let thread_id = read_string(&body.thread_id);
        let result = if body.result.as_deref() == Some("failed") {
            "failed"
        } else {
            "completed"
        };
        let dedupe_key = read_string(&body.dedupe_key);

        if session_id.is_empty() || secret.is_empty() || thread_id.is_empty() || dedupe_key.is_empty()
        {
            return Err(PushServiceError {
                code: "invalid_request".to_string(),
                message: "Push completion requires sessionId, notificationSecret, threadId, and dedupeKey.".to_string(),
                status: 400,
            });
        }

        // Check relay has active authenticated mac session
        if !crate::relay::has_authenticated_mac_session(&self.relay_state, &session_id, &secret)
            .await
        {
            return Err(PushServiceError {
                code: "session_unavailable".to_string(),
                message: "Push completion requires an active relay session.".to_string(),
                status: 403,
            });
        }

        // Prune and check dedupe
        {
            let mut dedupe_keys = self.delivered_dedupe_keys.lock().await;
            let cutoff = now_ms().saturating_sub(PUSH_DEDUPE_TTL_MS);
            dedupe_keys.retain(|_, v| *v >= cutoff);

            if dedupe_keys.contains_key(&dedupe_key) {
                return Ok(serde_json::json!({ "ok": true, "deduped": true }));
            }
        }

        let sessions = self.sessions.lock().await;
        let session = sessions.get(&session_id).ok_or_else(|| PushServiceError {
            code: "unauthorized".to_string(),
            message: "Invalid notification secret for this session.".to_string(),
            status: 403,
        })?;

        if !secrets_equal(&session.notification_secret, &secret) {
            return Err(PushServiceError {
                code: "unauthorized".to_string(),
                message: "Invalid notification secret for this session.".to_string(),
                status: 403,
            });
        }

        if !session.alerts_enabled || session.device_token.is_empty() {
            return Ok(serde_json::json!({ "ok": true, "skipped": true }));
        }

        let device_token = session.device_token.clone();
        let apns_environment = session.apns_environment.clone();
        drop(sessions);

        let title = normalize_preview_text(body.title.as_deref().unwrap_or(""));
        let title = if title.is_empty() {
            "Conversation".to_string()
        } else {
            title
        };
        let body_text = normalize_preview_text(body.body.as_deref().unwrap_or(""));
        let body_text = if body_text.is_empty() {
            fallback_body_for_result(result)
        } else {
            body_text
        };

        let turn_id = read_string(&body.turn_id);

        let payload = serde_json::json!({
            "source": "codex.runCompletion",
            "threadId": thread_id,
            "turnId": turn_id,
            "result": result,
        });

        self.apns_client
            .send_notification(&device_token, &apns_environment, &title, &body_text, payload)
            .await
            .map_err(|e| PushServiceError {
                code: e.code,
                message: e.message,
                status: e.status,
            })?;

        {
            let mut dedupe_keys = self.delivered_dedupe_keys.lock().await;
            dedupe_keys.insert(dedupe_key, now_ms());
        }

        self.persist_state("notifyCompletion").await;
        Ok(serde_json::json!({ "ok": true }))
    }

    pub async fn get_stats(&self) -> PushStats {
        let sessions = self.sessions.lock().await;
        let mut dedupe_keys = self.delivered_dedupe_keys.lock().await;
        let cutoff = now_ms().saturating_sub(PUSH_DEDUPE_TTL_MS);
        dedupe_keys.retain(|_, v| *v >= cutoff);

        PushStats {
            registered_sessions: sessions.len(),
            delivered_dedupe_keys: dedupe_keys.len(),
            apns_configured: self.apns_client.is_configured(),
        }
    }

    async fn persist_state(&self, reason: &str) {
        let Some(ref path) = self.state_file_path else {
            return;
        };

        let sessions = self.sessions.lock().await;
        let dedupe_keys = self.delivered_dedupe_keys.lock().await;

        let state = PersistedState {
            sessions: sessions.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            delivered_dedupe_keys: dedupe_keys.iter().map(|(k, v)| (k.clone(), *v)).collect(),
        };
        drop(sessions);
        drop(dedupe_keys);

        if let Err(e) = write_state_file(path, &state) {
            tracing::error!(
                "[relay] push state persistence failed during {}: {}",
                reason,
                e
            );
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceRequest {
    pub session_id: Option<String>,
    pub notification_secret: Option<String>,
    pub device_token: Option<String>,
    pub alerts_enabled: Option<bool>,
    pub apns_environment: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotifyCompletionRequest {
    pub session_id: Option<String>,
    pub notification_secret: Option<String>,
    pub thread_id: Option<String>,
    pub turn_id: Option<String>,
    pub result: Option<String>,
    pub title: Option<String>,
    pub body: Option<String>,
    pub dedupe_key: Option<String>,
}

fn read_string(value: &Option<String>) -> String {
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

fn normalize_device_token(value: &Option<String>) -> String {
    let s = read_string(value);
    if s.is_empty() {
        return String::new();
    }
    s.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_lowercase()
}

fn normalize_preview_text(value: &str) -> String {
    let normalized: String = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        return String::new();
    }
    if normalized.len() > PUSH_PREVIEW_MAX_CHARS {
        let truncated: String = normalized.chars().take(PUSH_PREVIEW_MAX_CHARS - 1).collect();
        format!("{}…", truncated.trim_end())
    } else {
        normalized
    }
}

fn fallback_body_for_result(result: &str) -> String {
    if result == "failed" {
        "Run failed".to_string()
    } else {
        "Response ready".to_string()
    }
}

fn secrets_equal(left: &str, right: &str) -> bool {
    let left = left.trim();
    let right = right.trim();
    if left.is_empty() || left.len() != right.len() {
        return false;
    }
    left.as_bytes().ct_eq(right.as_bytes()).into()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn read_state_file(path: &Path) -> Option<PersistedState> {
    let content = fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

fn empty_state() -> PersistedState {
    PersistedState {
        sessions: Vec::new(),
        delivered_dedupe_keys: Vec::new(),
    }
}

fn write_state_file(path: &Path, state: &PersistedState) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let temp_path = path.with_extension("tmp");
    let json = serde_json::to_string(state)?;
    fs::write(&temp_path, &json)?;

    // Set permissions to 0o600
    let metadata = fs::metadata(&temp_path)?;
    let mut perms = metadata.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&temp_path, perms)?;

    fs::rename(&temp_path, path)?;

    // Best-effort chmod on final file
    if let Ok(metadata) = fs::metadata(path) {
        let mut perms = metadata.permissions();
        perms.set_mode(0o600);
        let _ = fs::set_permissions(path, perms);
    }

    Ok(())
}

pub fn resolve_push_state_file_path() -> PathBuf {
    // Check explicit env var
    for key in &["REMODEX_PUSH_STATE_FILE", "PHODEX_PUSH_STATE_FILE"] {
        if let Ok(val) = std::env::var(key) {
            let trimmed = val.trim().to_string();
            if !trimmed.is_empty() {
                return PathBuf::from(trimmed);
            }
        }
    }

    let codex_home = std::env::var("CODEX_HOME")
        .ok()
        .and_then(|v| {
            let trimmed = v.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(PathBuf::from(trimmed))
            }
        })
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".codex")
        });

    codex_home.join("remodex").join("push-state.json")
}

/// Stats for when push is disabled
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DisabledPushStats {
    pub enabled: bool,
    pub registered_sessions: usize,
    pub delivered_dedupe_keys: usize,
    pub apns_configured: bool,
}

pub fn disabled_push_stats() -> DisabledPushStats {
    DisabledPushStats {
        enabled: false,
        registered_sessions: 0,
        delivered_dedupe_keys: 0,
        apns_configured: false,
    }
}
