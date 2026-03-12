use serde_json::{json, Value};
use std::time::Duration;

use crate::config::Config;
use crate::project::preauth_config;
use crate::routes::{resolve_command_spec, RoutingClass};

#[derive(Debug)]
pub struct PreAuthSuccess {
    pub token: Option<String>,
    pub user_id: Option<String>,
    pub client_instance_id: String,
    pub success_payload: Option<Value>,
}

#[derive(Debug)]
pub struct PreAuthFailure {
    pub code: String,
    pub message: String,
    pub request_id: Option<String>,
}

pub async fn resolve_initial_auth(
    config: &Config,
    auth_payload: &Value,
) -> Result<PreAuthSuccess, PreAuthFailure> {
    let request_id = normalize_request_id(auth_payload.get("request_id").and_then(Value::as_str));
    let client_instance_id = auth_payload
        .get("client_instance_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let auth_type = auth_payload
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();

    let command_spec = resolve_command_spec(auth_type.as_str()).ok_or_else(|| PreAuthFailure {
        code: "invalid_auth_type".to_string(),
        message: "Unsupported auth payload type.".to_string(),
        request_id: request_id.clone(),
    })?;
    if !matches!(command_spec.routing_class, RoutingClass::NoAuth) {
        return Err(PreAuthFailure {
            code: "invalid_auth_type".to_string(),
            message: "Unsupported auth payload type.".to_string(),
            request_id: request_id.clone(),
        });
    }

    match auth_type.as_str() {
        "auth" => {
            let token = auth_payload
                .get("token")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| PreAuthFailure {
                    code: "missing_token".to_string(),
                    message: "Missing token.".to_string(),
                    request_id,
                })?
                .to_string();

            Ok(PreAuthSuccess {
                token: Some(token),
                user_id: None,
                client_instance_id,
                success_payload: None,
            })
        }
        "auth_login_request" => {
            let email = auth_payload
                .get("email")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("")
                .to_string();
            let password = auth_payload
                .get("password")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("")
                .to_string();
            if email.is_empty() || password.is_empty() {
                return Err(PreAuthFailure {
                    code: "invalid_auth_payload".to_string(),
                    message: "Email and password are required.".to_string(),
                    request_id,
                });
            }

            let (token, user_payload) = authenticate_via_http(
                config,
                resolve_preauth_http_path(auth_type.as_str(), request_id.clone())?,
                json!({ "email": email, "password": password }),
                request_id.clone(),
            )
            .await?;
            let mut payload = json!({
                "type": "auth_login_ok",
                "token": token,
                "ts": chrono::Utc::now().timestamp(),
            });
            if let Some(id) = request_id.clone() {
                payload["request_id"] = Value::String(id);
            }
            if !user_payload.is_null() {
                payload["user"] = user_payload;
            }

            Ok(PreAuthSuccess {
                token: Some(payload
                    .get("token")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string()),
                user_id: None,
                client_instance_id,
                success_payload: Some(payload),
            })
        }
        "auth_register_request" => {
            let name = auth_payload
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("")
                .to_string();
            let email = auth_payload
                .get("email")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("")
                .to_string();
            let password = auth_payload
                .get("password")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("")
                .to_string();
            let key_id = auth_payload
                .get("key_id")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("")
                .to_string();
            let algorithm = auth_payload
                .get("algorithm")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("")
                .to_string();
            let public_key = auth_payload
                .get("public_key")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("")
                .to_string();
            let challenge = auth_payload
                .get("challenge")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("")
                .to_string();
            let signature = auth_payload
                .get("signature")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("")
                .to_string();
            if name.is_empty() || email.is_empty() || password.is_empty() {
                return Err(PreAuthFailure {
                    code: "invalid_auth_payload".to_string(),
                    message: "Name, email and password are required.".to_string(),
                    request_id,
                });
            }
            let identity_requested = !key_id.is_empty()
                || !algorithm.is_empty()
                || !public_key.is_empty()
                || !challenge.is_empty()
                || !signature.is_empty();
            if identity_requested
                && (key_id.is_empty()
                    || algorithm.is_empty()
                    || public_key.is_empty()
                    || challenge.is_empty()
                    || signature.is_empty())
            {
                return Err(PreAuthFailure {
                    code: "invalid_auth_payload".to_string(),
                    message: "Identity registration payload is incomplete.".to_string(),
                    request_id,
                });
            }

            let mut register_payload = json!({
                "name": name,
                "email": email,
                "password": password,
            });
            if identity_requested {
                register_payload["key_id"] = Value::String(key_id);
                register_payload["algorithm"] = Value::String(algorithm);
                register_payload["public_key"] = Value::String(public_key);
                register_payload["challenge"] = Value::String(challenge);
                register_payload["signature"] = Value::String(signature);
            }

            let (token, user_payload) = authenticate_via_http(
                config,
                resolve_preauth_http_path(auth_type.as_str(), request_id.clone())?,
                register_payload,
                request_id.clone(),
            )
            .await?;

            let mut payload = json!({
                "type": "auth_register_ok",
                "token": token,
                "ts": chrono::Utc::now().timestamp(),
            });
            if let Some(id) = request_id.clone() {
                payload["request_id"] = Value::String(id);
            }
            if !user_payload.is_null() {
                payload["user"] = user_payload;
            }

            Ok(PreAuthSuccess {
                token: Some(payload
                    .get("token")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string()),
                user_id: None,
                client_instance_id,
                success_payload: Some(payload),
            })
        }
        "auth_identity_request" => {
            let email = auth_payload
                .get("email")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("")
                .to_string();
            let key_id = auth_payload
                .get("key_id")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("")
                .to_string();
            let algorithm = auth_payload
                .get("algorithm")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("")
                .to_string();
            let public_key = auth_payload
                .get("public_key")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("")
                .to_string();
            let challenge = auth_payload
                .get("challenge")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("")
                .to_string();
            let signature = auth_payload
                .get("signature")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("")
                .to_string();

            if email.is_empty()
                || key_id.is_empty()
                || algorithm.is_empty()
                || public_key.is_empty()
                || challenge.is_empty()
                || signature.is_empty()
            {
                return Err(PreAuthFailure {
                    code: "invalid_auth_payload".to_string(),
                    message: "Identity auth payload is incomplete.".to_string(),
                    request_id,
                });
            }

            let (token, user_payload) = authenticate_via_http(
                config,
                resolve_preauth_http_path(auth_type.as_str(), request_id.clone())?,
                json!({
                    "email": email,
                    "key_id": key_id,
                    "algorithm": algorithm,
                    "public_key": public_key,
                    "challenge": challenge,
                    "signature": signature,
                }),
                request_id.clone(),
            )
            .await?;

            let mut payload = json!({
                "type": "auth_identity_ok",
                "token": token,
                "ts": chrono::Utc::now().timestamp(),
            });
            if let Some(id) = request_id.clone() {
                payload["request_id"] = Value::String(id);
            }
            if !user_payload.is_null() {
                payload["user"] = user_payload;
            }

            Ok(PreAuthSuccess {
                token: Some(payload
                    .get("token")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string()),
                user_id: None,
                client_instance_id,
                success_payload: Some(payload),
            })
        }
        "dropbox_public_auth" => {
            let slug = auth_payload
                .get("slug")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("")
                .to_string();
            if !is_valid_dropbox_slug(&slug) {
                return Err(PreAuthFailure {
                    code: "invalid_dropbox_slug".to_string(),
                    message: "Invalid dropbox slug.".to_string(),
                    request_id,
                });
            }

            let guest_connection_id = preauth_config::compose_dropbox_guest_user_id(
                &slug,
                chrono::Utc::now().timestamp_micros(),
            );

            let mut payload = json!({
                "type": "dropbox_public_auth_ok",
                "slug": slug,
                "ts": chrono::Utc::now().timestamp(),
            });
            if let Some(id) = request_id.clone() {
                payload["request_id"] = Value::String(id);
            }

            Ok(PreAuthSuccess {
                token: None,
                user_id: Some(guest_connection_id),
                client_instance_id,
                success_payload: Some(payload),
            })
        }
        _ => Err(PreAuthFailure {
            code: "invalid_auth_type".to_string(),
            message: "Unsupported auth payload type.".to_string(),
            request_id,
        }),
    }
}

fn is_valid_dropbox_slug(slug: &str) -> bool {
    if slug.is_empty() || slug.len() > 64 {
        return false;
    }

    slug.chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

async fn authenticate_via_http(
    config: &Config,
    path: &str,
    body: Value,
    request_id: Option<String>,
) -> Result<(String, Value), PreAuthFailure> {
    let base = config.auth_backend_base_url.trim().trim_end_matches('/');
    if base.is_empty() {
        return Err(PreAuthFailure {
            code: "auth_backend_unavailable".to_string(),
            message: "Auth backend is not configured.".to_string(),
            request_id,
        });
    }
    let url = format!("{base}{path}");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(config.auth_request_timeout_ms))
        .build()
        .map_err(|_| PreAuthFailure {
            code: "auth_backend_unavailable".to_string(),
            message: "Could not initialize auth client.".to_string(),
            request_id: request_id.clone(),
        })?;

    let response = client
        .post(url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|_| PreAuthFailure {
            code: "auth_backend_timeout".to_string(),
            message: "Auth backend request failed.".to_string(),
            request_id: request_id.clone(),
        })?;

    let status = response.status();
    let parsed = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    if !status.is_success() {
        let error_message = extract_error_message(&parsed).unwrap_or_else(|| {
            if status.as_u16() == 401 {
                "Invalid credentials.".to_string()
            } else {
                format!("Authentication failed ({})", status.as_u16())
            }
        });
        let error_code = extract_error_code(&parsed)
            .unwrap_or_else(|| format!("auth_http_{}", status.as_u16()));
        return Err(PreAuthFailure {
            code: error_code,
            message: error_message,
            request_id,
        });
    }

    let token = parsed
        .get("token")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| PreAuthFailure {
            code: "token_missing".to_string(),
            message: "Auth backend did not return a token.".to_string(),
            request_id: request_id.clone(),
        })?
        .to_string();
    let user_payload = parsed.get("user").cloned().unwrap_or(Value::Null);

    Ok((token, user_payload))
}

fn normalize_request_id(value: Option<&str>) -> Option<String> {
    let request_id = value?.trim();
    if request_id.is_empty() {
        return None;
    }
    Some(request_id.chars().take(128).collect::<String>())
}

fn resolve_preauth_http_path(
    command_name: &str,
    request_id: Option<String>,
) -> Result<&'static str, PreAuthFailure> {
    preauth_config::resolve_http_path(command_name).ok_or_else(|| PreAuthFailure {
        code: "auth_route_unconfigured".to_string(),
        message: format!("No auth backend route configured for '{command_name}'."),
        request_id,
    })
}

fn extract_error_message(value: &Value) -> Option<String> {
    value
        .get("message")
        .and_then(Value::as_str)
        .or_else(|| value.get("error").and_then(Value::as_str))
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| item.to_string())
}

fn extract_error_code(value: &Value) -> Option<String> {
    value
        .get("error")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| item.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config {
            transport: "websocket".to_string(),
            jwt_alg: "RS256".to_string(),
            jwt_user_id_claim: "user_id".to_string(),
            jwt_public_key: String::new(),
            jwt_public_key_file: String::new(),
            jwt_jwks_url: String::new(),
            jwt_issuer: String::new(),
            jwt_audience: String::new(),
            jwt_leeway: 0,
            gateway_api_key: String::new(),
            auth_backend_base_url: "http://localhost".to_string(),
            auth_request_timeout_ms: 1000,
            redis_dsn: String::new(),
            redis_stream: "ws.outbox".to_string(),
            redis_inbox_stream: "ws.inbox".to_string(),
            redis_events_stream: "ws.events".to_string(),
            max_connections_per_user: None,
            stale_connection_timeout_seconds: 0,
            stale_prune_interval_seconds: 1,
            webtransport_port: 4433,
            websocket_port: 8081,
            http_api_port: 8080,
            cert_pemfile: String::new(),
            key_pemfile: String::new(),
        }
    }

    #[tokio::test]
    async fn rejects_non_preauth_commands() {
        let config = test_config();
        let payload = json!({
            "type": "chat_message_send",
            "request_id": "req-1"
        });
        let result = resolve_initial_auth(&config, &payload).await;
        let error = result.expect_err("chat command must be rejected in preauth stage");
        assert_eq!(error.code, "invalid_auth_type");
    }
}
