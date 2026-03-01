use anyhow::Result;
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
use crate::message::{extract_channel_id, extract_flags, extract_payload, InternalMessage};
use crate::state::{GatewayState, OutboundMessage};

pub struct WebTransportServer {
    endpoint: Endpoint<Server>,
    config: Config,
    state: GatewayState,
    redis: Option<redis::Client>,
}

impl WebTransportServer {
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
            info!(
                "New session: id='{connection_id}' authority='{}' path='{}'",
                session_request.authority(),
                session_request.path()
            );
            let connection = session_request.accept().await?;
            let connection = Arc::new(connection);

            let auth_payload = read_auth_message(connection.clone()).await?;
            if auth_payload.get("type").and_then(|v| v.as_str()) != Some("auth") {
                return Err(AuthError::InvalidToken.into());
            }
            let token = auth_payload
                .get("token")
                .and_then(|v| v.as_str())
                .ok_or(AuthError::MissingToken)?;
            let claims = verify_jwt(&config, token).await.map_err(|_| AuthError::InvalidToken)?;
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
            let (info, mut outbound_rx) = state.register_connection(
                connection_id.clone(),
                user_id.clone(),
                subjects.clone(),
                connected_at,
            );

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

            let _outbound_task = {
                let connection = connection.clone();
                tokio::spawn(async move {
                    while let Some(outbound) = outbound_rx.recv().await {
                        if let OutboundMessage::Text(text) = outbound {
                            if send_unicast(connection.clone(), &Value::String(text)).await.is_err() {
                                break;
                            }
                        }
                    }
                })
            };

            loop {
                tokio::select! {
                    stream = connection.accept_bi() => {
                        let mut stream = match stream {
                            Ok(stream) => stream,
                            Err(_) => break,
                        };
                        let mut buffer = Vec::new();
                        stream.1.read_to_end(&mut buffer).await?;
                        if buffer.is_empty() {
                            continue;
                        }
                        let raw = std::str::from_utf8(&buffer).unwrap_or("").to_string();
                        handle_client_message(&connection_id, &info, raw, &config, redis.as_ref()).await;
                    }
                    dgram = connection.receive_datagram() => {
                        match dgram {
                            Ok(dgram) => {
                                let raw = std::str::from_utf8(&dgram).unwrap_or("").to_string();
                                handle_client_message(&connection_id, &info, raw, &config, redis.as_ref()).await;
                            }
                            Err(_) => break,
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

async fn read_auth_message(connection: Arc<wtransport::Connection>) -> Result<Value> {
    let auth_timeout = tokio::time::sleep(Duration::from_secs(5));
    tokio::pin!(auth_timeout);

    tokio::select! {
        _ = &mut auth_timeout => {
            Err(anyhow::anyhow!("auth_timeout"))
        }
        stream = connection.accept_bi() => {
            let mut stream = stream?;
            let mut buffer = Vec::new();
            stream.1.read_to_end(&mut buffer).await?;
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
    let mut stream = connection.open_uni().await?.await?;
    stream.write_all(text.as_bytes()).await?;
    stream.finish().await?;
    Ok(())
}

async fn handle_client_message(
    connection_id: &str,
    info: &crate::state::ConnectionInfo,
    raw: String,
    config: &Config,
    redis: Option<&redis::Client>,
) {
    if raw.trim().is_empty() {
        return;
    }
    let data = serde_json::from_str::<Value>(&raw).unwrap_or_else(|_| json!({"type":"raw","payload":raw}));
    let msg_type = data.get("type").and_then(|v| v.as_str()).unwrap_or("");
    if msg_type == "ping" {
        let _ = redis; // no-op, keep clippy happy
        return;
    }

    let timestamp_ms = chrono::Utc::now().timestamp_millis();
    let internal = InternalMessage {
        schema_version: 1,
        internal_id: Uuid::new_v4().to_string(),
        timestamp_ms,
        user_id: info.user_id.clone(),
        channel_id: extract_channel_id(&data, &info.user_id),
        flags: extract_flags(&data),
        payload: extract_payload(&data),
    };

    let payload = json!({
        "type": "message_received",
        "internal_id": internal.internal_id,
        "timestamp_ms": internal.timestamp_ms,
        "user_id": internal.user_id,
        "channel_id": internal.channel_id,
        "flags": internal.flags,
        "payload": internal.payload,
        "connection_id": connection_id,
        "subjects": info.subjects,
        "connected_at": info.connected_at,
        "message": data,
        "raw": raw,
    });

    if let Some(redis) = redis {
        if let Err(err) = publish_event(redis, &config.redis_inbox_stream, &payload).await {
            warn!("publish_event_failed: {err}");
        }
    }
}
