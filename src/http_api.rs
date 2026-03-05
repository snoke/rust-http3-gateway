use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use tower_http::cors::CorsLayer;
use tracing::info;

use crate::config::Config;
use crate::state::GatewayState;

#[derive(Clone)]
struct AppState {
    config: Config,
    gateway: GatewayState,
}

#[derive(Deserialize)]
struct PublishRequest {
    subjects: Option<Vec<String>>,
    payload: serde_json::Value,
    api_key: Option<String>,
}

#[derive(Deserialize)]
struct ListQuery {
    subject: Option<String>,
    user_id: Option<String>,
}

pub async fn serve(port: u16, config: Config, gateway: GatewayState) -> anyhow::Result<()> {
    let app_state = AppState { config, gateway };
    let app = Router::new()
        .route("/internal/publish", post(publish))
        .route("/internal/connections", get(list_connections))
        .route("/internal/users/:user_id/connections", get(user_connections))
        .route("/health", get(health))
        .route("/ready", get(ready))
        .layer(CorsLayer::permissive())
        .with_state(app_state);

    let bind = format!("0.0.0.0:{port}");
    info!(%bind, "HTTP API listening");
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn publish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PublishRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !state.config.gateway_api_key.is_empty() {
        let header_key = headers
            .get("x-api-key")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string());
        let provided = req.api_key.clone().or(header_key).unwrap_or_default();
        if provided != state.config.gateway_api_key {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "ok": false, "error": "invalid_api_key" })),
            );
        }
    }

    let subjects = req.subjects.unwrap_or_default();
    if subjects.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "error": "missing_subjects" })),
        );
    }
    let envelope = json!({
        "type": "event",
        "payload": req.payload,
    });
    match serde_json::to_string(&envelope) {
        Ok(text) => {
            let sent = state.gateway.send_to_subjects(&subjects, text, true, None);
            (StatusCode::OK, Json(json!({ "ok": true, "sent": sent })))
        }
        Err(_) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "error": "invalid_payload" })),
        ),
    }
}

async fn list_connections(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    let connections = state
        .gateway
        .list_connections(query.subject.as_deref(), query.user_id.as_deref());
    (StatusCode::OK, Json(json!({ "connections": connections })))
}

async fn user_connections(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let connections = state.gateway.list_connections(None, Some(&user_id));
    (StatusCode::OK, Json(json!({ "connections": connections })))
}

async fn health() -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::OK, Json(json!({ "ok": true })))
}

async fn ready() -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::OK, Json(json!({ "ok": true })))
}
