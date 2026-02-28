use crate::state::{GatewayState, PublishError};
use axum::{
    extract::State,
    http::StatusCode,
    routing::post,
    Json, Router,
};
use serde::Deserialize;
use tracing::info;

#[derive(Clone)]
struct AppState {
    gateway: GatewayState,
}

#[derive(Deserialize)]
struct PublishRequest {
    connection_id: String,
    payload: String,
}

pub async fn serve(port: u16, gateway: GatewayState) -> anyhow::Result<()> {
    let app_state = AppState { gateway };

    let app = Router::new()
        .route("/internal/publish", post(publish))
        .with_state(app_state);

    let bind = format!("0.0.0.0:{port}");
    info!(%bind, "HTTP API listening");

    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn publish(
    State(state): State<AppState>,
    Json(req): Json<PublishRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if req.connection_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": "missing_connection_id" })),
        );
    }

    match state
        .gateway
        .publish_datagram(&req.connection_id, req.payload.into_bytes())
    {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))),
        Err(PublishError::NotFound) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "connection_not_found" })),
        ),
        Err(PublishError::Disconnected) => (
            StatusCode::GONE,
            Json(serde_json::json!({ "ok": false, "error": "connection_disconnected" })),
        ),
    }
}
