use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const APNS_TOKEN_TTL_SECONDS: u64 = 50 * 60;

#[derive(Clone)]
pub struct ApnsConfig {
    pub team_id: String,
    pub key_id: String,
    pub bundle_id: String,
    pub private_key: String,
}

impl ApnsConfig {
    pub fn from_env() -> Self {
        Self {
            team_id: read_first_defined_env(&[
                "REMODEX_APNS_TEAM_ID",
                "PHODEX_APNS_TEAM_ID",
            ]),
            key_id: read_first_defined_env(&[
                "REMODEX_APNS_KEY_ID",
                "PHODEX_APNS_KEY_ID",
            ]),
            bundle_id: read_first_defined_env(&[
                "REMODEX_APNS_BUNDLE_ID",
                "PHODEX_APNS_BUNDLE_ID",
            ]),
            private_key: read_apns_private_key(),
        }
    }
}

fn read_first_defined_env(keys: &[&str]) -> String {
    for key in keys {
        if let Ok(val) = std::env::var(key) {
            let trimmed = val.trim().to_string();
            if !trimmed.is_empty() {
                return trimmed;
            }
        }
    }
    String::new()
}

fn read_apns_private_key() -> String {
    let raw = read_first_defined_env(&[
        "REMODEX_APNS_PRIVATE_KEY",
        "PHODEX_APNS_PRIVATE_KEY",
    ]);
    if !raw.is_empty() {
        return raw;
    }

    let file_path = read_first_defined_env(&[
        "REMODEX_APNS_PRIVATE_KEY_FILE",
        "PHODEX_APNS_PRIVATE_KEY_FILE",
    ]);
    if file_path.is_empty() {
        return String::new();
    }

    std::fs::read_to_string(&file_path).unwrap_or_default()
}

struct CachedToken {
    value: String,
    expires_at: u64,
}

pub struct ApnsClient {
    config: ApnsConfig,
    signing_key: Option<SigningKey>,
    http_client: reqwest::Client,
    cached_token: Mutex<Option<CachedToken>>,
}

impl ApnsClient {
    pub fn new(config: ApnsConfig) -> Self {
        let signing_key = if !config.private_key.is_empty() {
            SigningKey::from_pkcs8_pem(&config.private_key).ok()
        } else {
            None
        };

        let http_client = reqwest::Client::builder()
            .http2_prior_knowledge()
            .build()
            .unwrap_or_default();

        Self {
            config,
            signing_key,
            http_client,
            cached_token: Mutex::new(None),
        }
    }

    pub fn is_configured(&self) -> bool {
        !self.config.team_id.is_empty()
            && !self.config.key_id.is_empty()
            && !self.config.bundle_id.is_empty()
            && self.signing_key.is_some()
    }

    pub async fn send_notification(
        &self,
        device_token: &str,
        apns_environment: &str,
        title: &str,
        body: &str,
        payload: serde_json::Value,
    ) -> Result<(), ApnsError> {
        if !self.is_configured() {
            return Err(ApnsError {
                code: "apns_not_configured".to_string(),
                message: "APNs credentials are not configured.".to_string(),
                status: 503,
            });
        }

        let normalized_token = normalize_device_token(device_token);
        if normalized_token.is_empty() {
            return Err(ApnsError {
                code: "invalid_device_token".to_string(),
                message: "A valid APNs device token is required.".to_string(),
                status: 400,
            });
        }

        let authority = if apns_environment == "development" {
            "https://api.sandbox.push.apple.com"
        } else {
            "https://api.push.apple.com"
        };

        let token = self.authorization_token()?;

        let title_str = if title.trim().is_empty() {
            "Remodex"
        } else {
            title
        };
        let body_str = if body.trim().is_empty() {
            "Response ready"
        } else {
            body
        };

        let mut notification_body = serde_json::json!({
            "aps": {
                "alert": {
                    "title": title_str,
                    "body": body_str,
                },
                "sound": "default",
            },
        });

        // Merge extra payload fields
        if let serde_json::Value::Object(extra) = payload {
            if let serde_json::Value::Object(ref mut obj) = notification_body {
                for (k, v) in extra {
                    obj.insert(k, v);
                }
            }
        }

        let url = format!("{}/3/device/{}", authority, normalized_token);
        let response = self
            .http_client
            .post(&url)
            .header("authorization", format!("bearer {}", token))
            .header("apns-topic", &self.config.bundle_id)
            .header("apns-push-type", "alert")
            .header("apns-priority", "10")
            .header("content-type", "application/json")
            .body(serde_json::to_string(&notification_body).unwrap_or_default())
            .send()
            .await
            .map_err(|e| ApnsError {
                code: "apns_request_failed".to_string(),
                message: format!("APNs request failed: {}", e),
                status: 502,
            })?;

        let status = response.status().as_u16();
        if status >= 400 {
            let body: serde_json::Value = response.json().await.unwrap_or_default();
            let reason = body
                .get("reason")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("APNs request failed with HTTP {}.", status));
            return Err(ApnsError {
                code: "apns_request_failed".to_string(),
                message: reason,
                status,
            });
        }

        Ok(())
    }

    fn authorization_token(&self) -> Result<String, ApnsError> {
        let signing_key = self.signing_key.as_ref().ok_or_else(|| ApnsError {
            code: "apns_not_configured".to_string(),
            message: "APNs signing key not available.".to_string(),
            status: 503,
        })?;

        let issued_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Check cache
        {
            let cache = self.cached_token.lock().unwrap();
            if let Some(ref cached) = *cache {
                if cached.expires_at > issued_at + 30 {
                    return Ok(cached.value.clone());
                }
            }
        }

        let header = base64_url_json(&serde_json::json!({
            "alg": "ES256",
            "kid": self.config.key_id,
        }));
        let claims = base64_url_json(&serde_json::json!({
            "iss": self.config.team_id,
            "iat": issued_at,
        }));
        let signing_input = format!("{}.{}", header, claims);

        let signature: Signature = signing_key.sign(signing_input.as_bytes());
        let sig_bytes = signature.to_bytes();
        let sig_b64 = URL_SAFE_NO_PAD.encode(&sig_bytes[..]);

        let token = format!("{}.{}", signing_input, sig_b64);

        let mut cache = self.cached_token.lock().unwrap();
        *cache = Some(CachedToken {
            value: token.clone(),
            expires_at: issued_at + APNS_TOKEN_TTL_SECONDS,
        });

        Ok(token)
    }
}

fn base64_url_json(value: &serde_json::Value) -> String {
    let json_bytes = serde_json::to_vec(value).unwrap_or_default();
    URL_SAFE_NO_PAD.encode(&json_bytes)
}

fn normalize_device_token(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    trimmed
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_lowercase()
}

#[derive(Debug)]
pub struct ApnsError {
    pub code: String,
    pub message: String,
    pub status: u16,
}
