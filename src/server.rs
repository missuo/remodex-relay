use crate::apns_client::{ApnsClient, ApnsConfig};
use crate::push_service::{
    NotifyCompletionRequest, PushSessionService, RegisterDeviceRequest,
    disabled_push_stats, resolve_push_state_file_path,
};
use crate::rate_limiter::FixedWindowRateLimiter;
use crate::relay::{
    self, MacRegistrationHeaders, RelayState, Role, TrustedSessionResolveRequest,
    handle_ws_connection, resolve_trusted_mac_session,
};
use axum::body::Body;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct AppState {
    pub relay_state: Arc<RelayState>,
    pub push_service: Option<Arc<PushSessionService>>,
    pub push_enabled: bool,
    pub expose_detailed_health: bool,
    pub trust_proxy: bool,
    pub http_rate_limiter: Mutex<FixedWindowRateLimiter>,
    pub push_rate_limiter: Mutex<FixedWindowRateLimiter>,
    pub upgrade_rate_limiter: Mutex<FixedWindowRateLimiter>,
}

pub fn create_app(
    enable_push_service: bool,
    trust_proxy: bool,
    expose_detailed_health: bool,
) -> (Router, Arc<AppState>) {
    let relay_state = RelayState::new();

    let push_service = if enable_push_service {
        let apns_config = ApnsConfig::from_env();
        let apns_client = Arc::new(ApnsClient::new(apns_config));
        let state_file = resolve_push_state_file_path();
        Some(PushSessionService::new(
            apns_client,
            Some(state_file),
            relay_state.clone(),
        ))
    } else {
        None
    };

    let app_state = Arc::new(AppState {
        relay_state,
        push_service,
        push_enabled: enable_push_service,
        expose_detailed_health,
        trust_proxy,
        http_rate_limiter: Mutex::new(FixedWindowRateLimiter::new(60_000, 120)),
        push_rate_limiter: Mutex::new(FixedWindowRateLimiter::new(60_000, 30)),
        upgrade_rate_limiter: Mutex::new(FixedWindowRateLimiter::new(60_000, 60)),
    });

    let app = Router::new()
        .route("/", get(root_handler))
        .route("/health", get(health_handler))
        .route(
            "/v1/push/session/register-device",
            post(register_device_handler),
        )
        .route(
            "/v1/push/session/notify-completion",
            post(notify_completion_handler),
        )
        .route(
            "/v1/trusted/session/resolve",
            post(trusted_session_resolve_handler),
        )
        .route("/relay/{session_id}", get(ws_upgrade_handler))
        .fallback(fallback_handler)
        .with_state(app_state.clone());

    (app, app_state)
}

async fn root_handler() -> impl IntoResponse {
    json_response(
        StatusCode::OK,
        json!({
            "ok": true,
            "version": env!("CARGO_PKG_VERSION"),
        }),
    )
}

async fn health_handler(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    if state.expose_detailed_health {
        let relay_stats = relay::get_relay_stats(&state.relay_state).await;
        let push_stats = if let Some(ref push) = state.push_service {
            serde_json::to_value(push.get_stats().await).unwrap_or(json!(null))
        } else {
            serde_json::to_value(disabled_push_stats()).unwrap_or(json!(null))
        };

        json_response(
            StatusCode::OK,
            json!({
                "ok": true,
                "relay": relay_stats,
                "push": push_stats,
            }),
        )
    } else {
        json_response(StatusCode::OK, json!({ "ok": true }))
    }
}

async fn register_device_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    if !state.push_enabled {
        return json_response(
            StatusCode::NOT_FOUND,
            json!({ "ok": false, "error": "Not found" }),
        );
    }

    let client_key = client_address_key_from_headers(&headers, addr, state.trust_proxy);

    {
        let mut limiter = state.http_rate_limiter.lock().await;
        if !limiter.allow(&client_key) {
            return rate_limit_response();
        }
    }
    {
        let mut limiter = state.push_rate_limiter.lock().await;
        if !limiter.allow(&format!("{}:register-device", client_key)) {
            return rate_limit_response();
        }
    }

    let body: RegisterDeviceRequest = match parse_json_body(&body) {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    match state.push_service.as_ref().unwrap().register_device(&body).await {
        Ok(result) => json_response(StatusCode::OK, result),
        Err(e) => json_response(
            StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            json!({
                "ok": false,
                "error": e.message,
                "code": e.code,
            }),
        ),
    }
}

async fn notify_completion_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    if !state.push_enabled {
        return json_response(
            StatusCode::NOT_FOUND,
            json!({ "ok": false, "error": "Not found" }),
        );
    }

    let client_key = client_address_key_from_headers(&headers, addr, state.trust_proxy);

    {
        let mut limiter = state.http_rate_limiter.lock().await;
        if !limiter.allow(&client_key) {
            return rate_limit_response();
        }
    }
    {
        let mut limiter = state.push_rate_limiter.lock().await;
        if !limiter.allow(&format!("{}:notify-completion", client_key)) {
            return rate_limit_response();
        }
    }

    let body: NotifyCompletionRequest = match parse_json_body(&body) {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    match state
        .push_service
        .as_ref()
        .unwrap()
        .notify_completion(&body)
        .await
    {
        Ok(result) => json_response(StatusCode::OK, result),
        Err(e) => json_response(
            StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            json!({
                "ok": false,
                "error": e.message,
                "code": e.code,
            }),
        ),
    }
}

async fn trusted_session_resolve_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let client_key = client_address_key_from_headers(&headers, addr, state.trust_proxy);

    {
        let mut limiter = state.http_rate_limiter.lock().await;
        if !limiter.allow(&client_key) {
            return rate_limit_response();
        }
    }

    let req: TrustedSessionResolveRequest = match parse_json_body(&body) {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    match resolve_trusted_mac_session(&state.relay_state, req).await {
        Ok(result) => json_response(StatusCode::OK, serde_json::to_value(result).unwrap()),
        Err(e) => json_response(
            StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            json!({
                "ok": false,
                "error": e.message,
                "code": e.code,
            }),
        ),
    }
}

async fn ws_upgrade_handler(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    let client_key = client_address_key_from_headers(&headers, addr, state.trust_proxy);
    let role_str = headers
        .get("x-role")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_string();

    let log_label = redact_relay_pathname(&format!("/relay/{}", session_id));
    tracing::info!(
        "[relay] upgrade request path={} remote={} role={}",
        log_label,
        client_key,
        if role_str.is_empty() { "missing" } else { &role_str }
    );

    {
        let mut limiter = state.upgrade_rate_limiter.lock().await;
        if !limiter.allow(&client_key) {
            tracing::info!("[relay] rejecting upgrade due to rate limit: {}", log_label);
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        }
    }

    let notification_secret = headers
        .get("x-notification-secret")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let mac_reg_headers = MacRegistrationHeaders {
        mac_device_id: headers
            .get("x-mac-device-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        mac_identity_public_key: headers
            .get("x-mac-identity-public-key")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        machine_name: headers
            .get("x-machine-name")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        trusted_phone_device_id: headers
            .get("x-trusted-phone-device-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        trusted_phone_public_key: headers
            .get("x-trusted-phone-public-key")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
    };

    let relay_state = state.relay_state.clone();

    // Role validation happens AFTER upgrade (inside the WS handler) to match the JS
    // behavior which accepts the upgrade first and then closes with code 4000.
    ws.on_upgrade(move |socket| async move {
        handle_ws_connection(relay_state, session_id, Role::from_str(&role_str), notification_secret, Some(mac_reg_headers), socket).await;
    })
}

async fn fallback_handler() -> impl IntoResponse {
    json_response(
        StatusCode::NOT_FOUND,
        json!({ "ok": false, "error": "Not found" }),
    )
}

fn json_response(status: StatusCode, body: serde_json::Value) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap_or_default()))
        .unwrap()
}

fn rate_limit_response() -> Response {
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("content-type", "application/json")
        .header("retry-after", "60")
        .body(Body::from(
            serde_json::to_string(&json!({
                "ok": false,
                "error": "Too many requests",
                "code": "rate_limited",
            }))
            .unwrap_or_default(),
        ))
        .unwrap()
}

fn parse_json_body<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, Response> {
    if body.len() > 64 * 1024 {
        return Err(json_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            json!({
                "ok": false,
                "error": "Request body too large",
                "code": "body_too_large",
            }),
        ));
    }

    let raw = String::from_utf8_lossy(body);
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        // Parse empty as default
        return serde_json::from_str("{}").map_err(|_| {
            json_response(
                StatusCode::BAD_REQUEST,
                json!({
                    "ok": false,
                    "error": "Invalid JSON body",
                    "code": "invalid_json",
                }),
            )
        });
    }

    serde_json::from_str(trimmed).map_err(|_| {
        json_response(
            StatusCode::BAD_REQUEST,
            json!({
                "ok": false,
                "error": "Invalid JSON body",
                "code": "invalid_json",
            }),
        )
    })
}

fn client_address_key_from_headers(
    headers: &HeaderMap,
    addr: SocketAddr,
    trust_proxy: bool,
) -> String {
    if trust_proxy {
        // Check x-real-ip first
        if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            let trimmed = real_ip.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }

        // Check x-forwarded-for
        if let Some(forwarded) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            let first_hop = forwarded
                .split(',')
                .map(|s| s.trim())
                .find(|s| !s.is_empty());
            if let Some(hop) = first_hop {
                return hop.to_string();
            }
        }
    }

    addr.ip().to_string()
}

fn redact_relay_pathname(pathname: &str) -> String {
    if !pathname.starts_with("/relay/") {
        return pathname.to_string();
    }

    let parts: Vec<&str> = pathname.splitn(3, '/').collect();
    if parts.len() >= 2 {
        let suffix = if parts.len() > 2 {
            // parts[0] is "", parts[1] is "relay", parts[2] is "sessionId/..."
            let rest_parts: Vec<&str> = parts[2].splitn(2, '/').collect();
            if rest_parts.len() > 1 {
                format!("/{}", rest_parts[1])
            } else {
                String::new()
            }
        } else {
            String::new()
        };
        format!("/relay/[session]{}", suffix)
    } else {
        pathname.to_string()
    }
}

pub fn read_optional_boolean_env(keys: &[&str]) -> Option<bool> {
    for key in keys {
        if let Ok(val) = std::env::var(key) {
            let trimmed = val.trim().to_lowercase();
            if trimmed.is_empty() {
                continue;
            }
            match trimmed.as_str() {
                "1" | "true" | "yes" | "on" => return Some(true),
                "0" | "false" | "no" | "off" => return Some(false),
                _ => {}
            }
        }
    }
    None
}
