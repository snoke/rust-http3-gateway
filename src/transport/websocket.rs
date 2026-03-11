use anyhow::{anyhow, Result};
use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tracing::{info, warn};
use uuid::Uuid;

use crate::auth::verify_jwt;
use crate::broker::publish_event;
use crate::config::Config;
use crate::gateway_core::handle_client_message;
use crate::preauth::{resolve_initial_auth, PreAuthFailure};
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

struct WsAuthContext {
    user_id: String,
    client_instance_id: String,
    bootstrap_success_payload: Option<Value>,
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
    let auth_context = authenticate_socket(&mut socket, &app, &query).await?;
    let user_id = auth_context.user_id;

    let connected_at = chrono::Utc::now().timestamp();
    let mut subjects = vec![format!("user:{user_id}")];
    let normalized_user = user_id.trim().to_lowercase();
    if !normalized_user.is_empty() && normalized_user != user_id {
        subjects.push(format!("user:{normalized_user}"));
    }
    let (info, mut outbound_rx, _evicted) = app.state.register_connection(
        connection_id.to_string(),
        user_id.clone(),
        auth_context.client_instance_id,
        subjects,
        connected_at,
    );

    if let Some(payload) = auth_context.bootstrap_success_payload {
        socket.send(WsMessage::Text(payload.to_string())).await?;
    }

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

async fn authenticate_socket(
    socket: &mut WebSocket,
    app: &WsAppState,
    query: &WsAuthQuery,
) -> Result<WsAuthContext> {
    let mut pending_payload = query.token.as_deref().map(|raw_token| {
        json!({
            "type": "auth",
            "token": normalize_bearer_token(raw_token),
            "client_instance_id": query.client_instance_id.clone().unwrap_or_default(),
        })
    });

    loop {
        let auth_payload = if let Some(payload) = pending_payload.take() {
            payload
        } else {
            read_auth_message(socket).await?
        };
        let request_id = normalize_request_id(
            auth_payload
                .get("request_id")
                .and_then(Value::as_str),
        );
        let resolved = match resolve_initial_auth(&app.config, &auth_payload).await {
            Ok(result) => result,
            Err(failure) => {
                let _ = send_auth_error(socket, &failure).await;
                continue;
            }
        };

        let mut client_instance_id = resolved.client_instance_id.trim().to_string();
        if client_instance_id.len() > 128
            || !client_instance_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            client_instance_id.clear();
        }

        let user_id = if let Some(user_id) = resolved.user_id {
            user_id
        } else {
            let token = match resolved.token {
                Some(value) if !value.trim().is_empty() => value,
                _ => {
                    let _ = send_auth_error(
                        socket,
                        &PreAuthFailure {
                            code: "missing_token".to_string(),
                            message: "Missing token.".to_string(),
                            request_id: request_id.clone(),
                        },
                    )
                    .await;
                    continue;
                }
            };
            let claims = match verify_jwt(&app.config, &token).await {
                Ok(claims) => claims,
                Err(_) => {
                    let _ = send_auth_error(
                        socket,
                        &PreAuthFailure {
                            code: "invalid_token".to_string(),
                            message: "Invalid token.".to_string(),
                            request_id: request_id.clone(),
                        },
                    )
                    .await;
                    continue;
                }
            };
            claims
                .get(&app.config.jwt_user_id_claim)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };
        if user_id.is_empty() {
            let _ = send_auth_error(
                socket,
                &PreAuthFailure {
                    code: "invalid_token".to_string(),
                    message: "Invalid token.".to_string(),
                    request_id,
                },
            )
            .await;
            continue;
        }

        return Ok(WsAuthContext {
            user_id,
            client_instance_id,
            bootstrap_success_payload: resolved.success_payload,
        });
    }
}

fn normalize_bearer_token(token: &str) -> &str {
    token.trim().strip_prefix("Bearer ").unwrap_or(token).trim()
}

async fn read_auth_message(socket: &mut WebSocket) -> Result<Value> {
    loop {
        match socket.recv().await {
            Some(Ok(WsMessage::Text(text))) => return Ok(serde_json::from_str::<Value>(&text)?),
            Some(Ok(WsMessage::Binary(bytes))) => {
                return Ok(serde_json::from_slice::<Value>(&bytes)?);
            }
            Some(Ok(WsMessage::Ping(payload))) => {
                let _ = socket.send(WsMessage::Pong(payload)).await;
            }
            Some(Ok(WsMessage::Pong(_))) => {}
            Some(Ok(WsMessage::Close(_))) | None => return Err(anyhow!("missing_auth_payload")),
            Some(Ok(_)) => {}
            Some(Err(err)) => return Err(anyhow!("auth_read_failed: {err}")),
        }
    }
}

fn normalize_request_id(value: Option<&str>) -> Option<String> {
    let request_id = value?.trim();
    if request_id.is_empty() {
        return None;
    }
    Some(request_id.chars().take(128).collect::<String>())
}

async fn send_auth_error(socket: &mut WebSocket, failure: &PreAuthFailure) -> Result<()> {
    let mut payload = json!({
        "type": "auth_error",
        "error": failure.code,
        "message": failure.message,
        "ts": chrono::Utc::now().timestamp(),
    });
    if let Some(request_id) = failure.request_id.clone() {
        payload["request_id"] = Value::String(request_id);
    }
    socket.send(WsMessage::Text(payload.to_string())).await?;
    Ok(())
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
