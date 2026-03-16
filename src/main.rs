mod apns_client;
mod push_service;
mod rate_limiter;
mod relay;
mod server;

use server::{create_app, read_optional_boolean_env};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(9000);

    let trust_proxy =
        read_optional_boolean_env(&["REMODEX_TRUST_PROXY", "PHODEX_TRUST_PROXY"]).unwrap_or(false);
    let enable_push_service = read_optional_boolean_env(&[
        "REMODEX_ENABLE_PUSH_SERVICE",
        "PHODEX_ENABLE_PUSH_SERVICE",
    ])
    .unwrap_or(false);

    let (app, _state) = create_app(enable_push_service, trust_proxy, false);

    let bind_host = std::env::var("REMODEX_RELAY_BIND_HOST")
        .ok()
        .and_then(|v| {
            let trimmed = v.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        })
        .unwrap_or_else(|| "127.0.0.1".to_string());

    let addr: SocketAddr = format!("{}:{}", bind_host, port)
        .parse()
        .expect("Invalid bind address");

    tracing::info!("[relay] listening on :{}", port);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
