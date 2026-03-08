use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tracing::{info, warn};
use tracing::{info_span, Instrument};
use uuid::Uuid;
use wtransport::endpoint::endpoint_side::Server;
use wtransport::endpoint::IncomingSession;
use wtransport::Endpoint;
use wtransport::Identity;
use wtransport::ServerConfig;

use crate::auth::{verify_jwt, AuthError};
use crate::broker::publish_event;
use crate::config::Config;
use crate::gateway_core::handle_client_message;
use crate::preauth::{resolve_initial_auth, PreAuthFailure};
use crate::state::{GatewayState, OutboundMessage};

use super::TransportAdapter;

pub struct WebTransportServer {
    endpoint: Endpoint<Server>,
    config: Config,
    state: GatewayState,
    redis: Option<redis::Client>,
}

impl WebTransportServer {
    pub async fn from_config(config: Config, state: GatewayState) -> Result<Self> {
        let cert_pem = config.cert_pemfile.clone();
        let key_pem = config.key_pemfile.clone();
        let identity = Identity::load_pemfiles(cert_pem, key_pem)
            .await
            .context("failed to load TLS identity from PEM files")?;
        Self::new(identity, config, state)
    }

    pub fn new(identity: Identity, config: Config, state: GatewayState) -> Result<Self> {
        let server_config = ServerConfig::builder()
            .with_bind_default(config.webtransport_port)
            .with_identity(identity)
            .keep_alive_interval(Some(Duration::from_secs(3)))
            .build();

        let endpoint = Endpoint::server(server_config)?;
        let redis = if config.redis_dsn.is_empty() {
            None
        } else {
            redis::Client::open(config.redis_dsn.as_str()).ok()
        };

        Ok(Self {
            endpoint,
            config,
            state,
            redis,
        })
    }

    pub fn local_port(&self) -> u16 {
        self.endpoint.local_addr().unwrap().port()
    }

    pub async fn serve(self) -> Result<()> {
        info!("WebTransport listening on UDP port {}", self.local_port());

        for id in 0.. {
            let incoming_session = self.endpoint.accept().await;
            let state = self.state.clone();
            let config = self.config.clone();
            let redis = self.redis.clone();
            tokio::spawn(
                Self::handle_incoming_session(incoming_session, state, config, redis)
                    .instrument(info_span!("wt", id)),
            );
        }

        Ok(())
    }

    async fn handle_incoming_session(
        incoming_session: IncomingSession,
        state: GatewayState,
        config: Config,
        redis: Option<redis::Client>,
    ) {
        let connection_id = Uuid::new_v4().to_string();

        async fn impl_(
            incoming_session: IncomingSession,
            connection_id: String,
            state: GatewayState,
            config: Config,
            redis: Option<redis::Client>,
        ) -> Result<()> {
            let session_request = incoming_session.await?;
            let authority = session_request.authority().to_string();
            let path = session_request.path().to_string();
            info!(
                "New session: id='{connection_id}' authority='{}' path='{}'",
                authority,
                path
            );

            let connection = Arc::new(session_request.accept().await?);
            let mut bootstrap_success_payload: Option<Value> = None;

            let (token, mut client_instance_id) = if let Some(raw_token) = query_param(&path, "token") {
                (
                    normalize_bearer_token(&raw_token).to_string(),
                    query_param(&path, "client_instance_id").unwrap_or_default(),
                )
            } else {
                let auth_payload = read_auth_message(connection.clone()).await?;
                let resolved = match resolve_initial_auth(&config, &auth_payload).await {
                    Ok(result) => result,
                    Err(failure) => {
                        let _ = send_auth_error(connection.clone(), &failure).await;
                        return Err(anyhow!("auth rejected: {}", failure.code));
                    }
                };
                bootstrap_success_payload = resolved.success_payload;
                (resolved.token, resolved.client_instance_id)
            };

            client_instance_id = client_instance_id.trim().to_string();
            if client_instance_id.len() > 128
                || !client_instance_id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
            {
                client_instance_id.clear();
            }

            let claims = verify_jwt(&config, &token).await.map_err(|_| AuthError::InvalidToken)?;
            let user_id = claims
                .get(&config.jwt_user_id_claim)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if user_id.is_empty() {
                return Err(AuthError::InvalidToken.into());
            }

            let connected_at = chrono::Utc::now().timestamp();
            let subjects = vec![format!("user:{user_id}")];
            let (info, mut outbound_rx, evicted) = state.register_connection(
                connection_id.clone(),
                user_id.clone(),
                client_instance_id,
                subjects.clone(),
                connected_at,
            );

            if !evicted.is_empty() {
                info!(
                    "evicted {} stale connection(s) for user '{}'",
                    evicted.len(),
                    user_id
                );
            }

            if let Some(payload) = bootstrap_success_payload {
                send_unicast(connection.clone(), &payload).await?;
            }
            send_unicast(connection.clone(), &json!({"type":"auth_ok","user_id":user_id})).await?;

            if let Some(redis) = redis.as_ref() {
                let payload = json!({
                    "type": "connected",
                    "connection_id": info.connection_id,
                    "user_id": info.user_id,
                    "subjects": info.subjects,
                    "connected_at": info.connected_at,
                });
                let _ = publish_event(redis, &config.redis_events_stream, &payload).await;
            }

            info!("Session ready; waiting for client data...");

            loop {
                tokio::select! {
                    outbound = outbound_rx.recv() => {
                        match outbound {
                            Some(OutboundMessage::Text(text)) => {
                                if let Err(err) = send_unicast(connection.clone(), &Value::String(text.clone())).await {
                                    let outbound_meta = classify_outbound_event(&text);
                                    warn!(
                                        "outbound send failed for connection {connection_id}: {err}; dispatch_mode={} request_id={} event_type={}",
                                        outbound_meta.mode.as_str(),
                                        outbound_meta.request_id.as_deref().unwrap_or(""),
                                        outbound_meta.event_type.as_deref().unwrap_or(""),
                                    );
                                    if matches!(outbound_meta.mode, OutboundDeliveryMode::Push) {
                                        state.requeue_for_subjects(&info.subjects, text);
                                    }
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                    stream = connection.accept_uni() => {
                        let mut stream = match stream {
                            Ok(stream) => stream,
                            Err(_) => break,
                        };

                        let mut buffer = Vec::new();
                        let read_result = tokio::time::timeout(
                            Duration::from_secs(5),
                            stream.read_to_end(&mut buffer),
                        )
                        .await;

                        match read_result {
                            Ok(Ok(_)) => {
                                if buffer.is_empty() {
                                    continue;
                                }
                                let raw = std::str::from_utf8(&buffer).unwrap_or("").to_string();
                                handle_client_message(
                                    &state,
                                    &connection_id,
                                    &info,
                                    raw,
                                    &config,
                                    redis.as_ref(),
                                )
                                .await;
                            }
                            Ok(Err(err)) => {
                                warn!("failed reading uni stream for {connection_id}: {err}");
                                break;
                            }
                            Err(_) => {
                                warn!("timed out reading uni stream for {connection_id}");
                                break;
                            }
                        }
                    }
                }
            }

            Ok(())
        }

        let result = impl_(
            incoming_session,
            connection_id.clone(),
            state.clone(),
            config.clone(),
            redis.clone(),
        )
        .await;

        if let Some(info) = state.unregister_connection(&connection_id) {
            if let Some(redis) = redis.as_ref() {
                let payload = json!({
                    "type": "disconnected",
                    "connection_id": info.connection_id,
                    "user_id": info.user_id,
                    "subjects": info.subjects,
                    "connected_at": info.connected_at,
                });
                let _ = publish_event(redis, &config.redis_events_stream, &payload).await;
            }
        }

        if let Err(err) = result {
            warn!("session error: {err}");
        }
    }
}

#[async_trait::async_trait]
impl TransportAdapter for WebTransportServer {
    fn name(&self) -> &'static str {
        "webtransport"
    }

    fn local_port(&self) -> u16 {
        WebTransportServer::local_port(self)
    }

    async fn serve(self) -> Result<()> {
        WebTransportServer::serve(self).await
    }
}

fn normalize_bearer_token(token: &str) -> &str {
    token.trim().strip_prefix("Bearer ").unwrap_or(token).trim()
}

fn query_param(path: &str, key: &str) -> Option<String> {
    let query = path.split_once('?')?.1;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == key {
            return Some(v.to_string());
        }
    }
    None
}

#[derive(Clone, Copy, Debug)]
enum OutboundDeliveryMode {
    RequestResponse,
    Push,
}

impl OutboundDeliveryMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::RequestResponse => "request_response",
            Self::Push => "push",
        }
    }
}

#[derive(Clone, Debug)]
struct OutboundEventMeta {
    mode: OutboundDeliveryMode,
    request_id: Option<String>,
    event_type: Option<String>,
}

fn classify_outbound_event(raw_text: &str) -> OutboundEventMeta {
    let parsed: Value = match serde_json::from_str(raw_text) {
        Ok(value) => value,
        Err(_) => {
            return OutboundEventMeta {
                mode: OutboundDeliveryMode::Push,
                request_id: None,
                event_type: None,
            };
        }
    };

    let payload = match parsed.get("payload") {
        Some(value) => value,
        None => {
            return OutboundEventMeta {
                mode: OutboundDeliveryMode::Push,
                request_id: None,
                event_type: None,
            };
        }
    };

    let request_id = payload
        .get("request_id")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());

    let event_type = payload
        .get("type")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());

    let mode = if request_id.is_some() {
        OutboundDeliveryMode::RequestResponse
    } else {
        OutboundDeliveryMode::Push
    };

    OutboundEventMeta {
        mode,
        request_id,
        event_type,
    }
}

async fn send_auth_error(
    connection: Arc<wtransport::Connection>,
    failure: &PreAuthFailure,
) -> Result<()> {
    let mut payload = json!({
        "type": "auth_error",
        "error": failure.code,
        "message": failure.message,
        "ts": chrono::Utc::now().timestamp(),
    });
    if let Some(request_id) = failure.request_id.clone() {
        payload["request_id"] = Value::String(request_id);
    }
    send_unicast(connection, &payload).await
}

async fn read_auth_message(connection: Arc<wtransport::Connection>) -> Result<Value> {
    let auth_timeout = tokio::time::sleep(Duration::from_secs(5));
    tokio::pin!(auth_timeout);

    tokio::select! {
        _ = &mut auth_timeout => {
            Err(anyhow!("auth_timeout"))
        }
        stream = connection.accept_uni() => {
            let mut stream = stream?;
            let mut buffer = Vec::new();
            stream.read_to_end(&mut buffer).await?;
            let raw = std::str::from_utf8(&buffer).unwrap_or("");
            let payload: Value = serde_json::from_str(raw)?;
            Ok(payload)
        }
    }
}

async fn send_unicast(connection: Arc<wtransport::Connection>, payload: &Value) -> Result<()> {
    let text = if payload.is_string() {
        payload.as_str().unwrap_or("").to_string()
    } else {
        serde_json::to_string(payload)?
    };
    let send_result = tokio::time::timeout(Duration::from_secs(3), async {
        let mut stream = connection.open_uni().await?.await?;
        stream.write_all(text.as_bytes()).await?;
        stream.finish().await?;
        Ok::<(), anyhow::Error>(())
    })
    .await;

    match send_result {
        Ok(inner) => inner?,
        Err(_) => return Err(anyhow!("webtransport outbound send timeout")),
    }
    Ok(())
}
