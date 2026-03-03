use anyhow::{anyhow, Result};
use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::{info, warn};
use uuid::Uuid;

use crate::auth::{verify_jwt, AuthError};
use crate::broker::publish_event;
use crate::config::Config;
use crate::gateway_core::handle_client_message;
use crate::state::{GatewayState, OutboundMessage};

use super::TransportAdapter;

#[derive(Clone)]
struct WsAppState {
    state: GatewayState,
    config: Config,
    redis: Option<redis::Client>,
}

#[derive(Default, serde::Deserialize)]
struct WsAuthQuery {
    token: Option<String>,
    client_instance_id: Option<String>,
}

pub struct WebSocketServer {
    listener: TcpListener,
    app: WsAppState,
}

impl WebSocketServer {
    pub async fn new(config: Config, state: GatewayState) -> Result<Self> {
        let bind_addr = format!("0.0.0.0:{}", config.websocket_port);
        let listener = TcpListener::bind(&bind_addr)
            .await
            .map_err(|err| anyhow!("failed to bind websocket listener on {bind_addr}: {err}"))?;
        let redis = if config.redis_dsn.is_empty() {
            None
        } else {
            redis::Client::open(config.redis_dsn.as_str()).ok()
        };
        Ok(Self {
            listener,
            app: WsAppState {
                state,
                config,
                redis,
            },
        })
    }

    pub fn local_port(&self) -> u16 {
        self.listener.local_addr().map(|addr| addr.port()).unwrap_or(0)
    }

    pub async fn serve(self) -> Result<()> {
        let router = Router::new()
            .route("/ws", get(ws_upgrade))
            .with_state(self.app.clone());

        info!("WebSocket listening on TCP port {}", self.local_port());
        axum::serve(self.listener, router).await?;
        Ok(())
    }
}

async fn ws_upgrade(
    ws: WebSocketUpgrade,
    State(app): State<WsAppState>,
    Query(query): Query<WsAuthQuery>,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, app, query))
}

async fn handle_socket(socket: WebSocket, app: WsAppState, query: WsAuthQuery) {
    let connection_id = Uuid::new_v4().to_string();

    let result = handle_socket_impl(socket, &connection_id, app.clone(), query).await;

    if let Some(info) = app.state.unregister_connection(&connection_id) {
        if let Some(redis) = app.redis.as_ref() {
            let payload = json!({
                "type": "disconnected",
                "connection_id": info.connection_id,
                "user_id": info.user_id,
                "subjects": info.subjects,
                "connected_at": info.connected_at,
            });
            let _ = publish_event(redis, &app.config.redis_events_stream, &payload).await;
        }
    }

    if let Err(err) = result {
        warn!("websocket session error: {err}");
    }
}

async fn handle_socket_impl(
    mut socket: WebSocket,
    connection_id: &str,
    app: WsAppState,
    query: WsAuthQuery,
) -> Result<()> {
    let (token, mut client_instance_id) = if let Some(raw_token) = query.token.as_deref() {
        (
            normalize_bearer_token(raw_token).to_string(),
            query.client_instance_id.unwrap_or_default(),
        )
    } else {
        let auth_payload = read_auth_message(&mut socket).await?;
        if auth_payload.get("type").and_then(|v| v.as_str()) != Some("auth") {
            return Err(AuthError::InvalidToken.into());
        }
        let token = auth_payload
            .get("token")
            .and_then(|v| v.as_str())
            .ok_or(AuthError::MissingToken)?
            .to_string();
        let client_instance_id = auth_payload
            .get("client_instance_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        (token, client_instance_id)
    };

    client_instance_id = client_instance_id.trim().to_string();
    if client_instance_id.len() > 128
        || !client_instance_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        client_instance_id.clear();
    }
    let claims = verify_jwt(&app.config, &token).await.map_err(|_| AuthError::InvalidToken)?;
    let user_id = claims
        .get(&app.config.jwt_user_id_claim)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if user_id.is_empty() {
        return Err(AuthError::InvalidToken.into());
    }

    let connected_at = chrono::Utc::now().timestamp();
    let subjects = vec![format!("user:{user_id}")];
    let (info, mut outbound_rx, _evicted) = app.state.register_connection(
        connection_id.to_string(),
        user_id.clone(),
        client_instance_id,
        subjects,
        connected_at,
    );

    socket
        .send(WsMessage::Text(
            json!({"type":"auth_ok","user_id":user_id}).to_string(),
        ))
        .await?;

    if let Some(redis) = app.redis.as_ref() {
        let payload = json!({
            "type": "connected",
            "connection_id": info.connection_id,
            "user_id": info.user_id,
            "subjects": info.subjects,
            "connected_at": info.connected_at,
        });
        let _ = publish_event(redis, &app.config.redis_events_stream, &payload).await;
    }

    let (mut sender, mut receiver) = socket.split();
    loop {
        tokio::select! {
            outbound = outbound_rx.recv() => {
                match outbound {
                    Some(OutboundMessage::Text(text)) => {
                        if sender.send(WsMessage::Text(text)).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            incoming = receiver.next() => {
                match incoming {
                    Some(Ok(WsMessage::Text(text))) => {
                        handle_client_message(
                            &app.state,
                            connection_id,
                            &info,
                            text.to_string(),
                            &app.config,
                            app.redis.as_ref(),
                        ).await;
                    }
                    Some(Ok(WsMessage::Binary(bytes))) => {
                        let text = String::from_utf8_lossy(&bytes).to_string();
                        handle_client_message(
                            &app.state,
                            connection_id,
                            &info,
                            text,
                            &app.config,
                            app.redis.as_ref(),
                        ).await;
                    }
                    Some(Ok(WsMessage::Ping(payload))) => {
                        let _ = sender.send(WsMessage::Pong(payload)).await;
                    }
                    Some(Ok(WsMessage::Close(_))) | None => break,
                    Some(Ok(_)) => {}
                    Some(Err(_)) => break,
                }
            }
        }
    }

    Ok(())
}

fn normalize_bearer_token(token: &str) -> &str {
    token.trim().strip_prefix("Bearer ").unwrap_or(token).trim()
}

async fn read_auth_message(socket: &mut WebSocket) -> Result<Value> {
    let auth_timeout = tokio::time::sleep(Duration::from_secs(5));
    tokio::pin!(auth_timeout);

    tokio::select! {
        _ = &mut auth_timeout => Err(anyhow!("auth_timeout")),
        frame = socket.recv() => {
            match frame {
                Some(Ok(WsMessage::Text(text))) => Ok(serde_json::from_str::<Value>(&text)?),
                Some(Ok(WsMessage::Binary(bytes))) => Ok(serde_json::from_slice::<Value>(&bytes)?),
                _ => Err(anyhow!("missing_auth_payload")),
            }
        }
    }
}

#[async_trait::async_trait]
impl TransportAdapter for WebSocketServer {
    fn name(&self) -> &'static str {
        "websocket"
    }

    fn local_port(&self) -> u16 {
        WebSocketServer::local_port(self)
    }

    async fn serve(self) -> Result<()> {
        WebSocketServer::serve(self).await
    }
}

