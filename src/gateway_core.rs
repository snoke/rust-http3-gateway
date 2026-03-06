use serde_json::{json, Value};
use tracing::{info, warn};
use uuid::Uuid;

use crate::broker::publish_event;
use crate::config::Config;
use crate::message::{extract_channel_id, extract_flags, extract_payload, InternalMessage};
use crate::state::{ConnectionInfo, GatewayState};

pub async fn handle_client_message(
    state: &GatewayState,
    connection_id: &str,
    info: &ConnectionInfo,
    raw: String,
    config: &Config,
    redis: Option<&redis::Client>,
) {
    if raw.trim().is_empty() {
        return;
    }
    state.mark_connection_alive(connection_id, chrono::Utc::now().timestamp());

    let data = serde_json::from_str::<Value>(&raw).unwrap_or_else(|_| json!({"type":"raw","payload":raw}));
    let msg_type = data.get("type").and_then(|v| v.as_str()).unwrap_or("");
    if let Some(request_id) = data
        .get("request_id")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        state.bind_request_route(request_id, connection_id, info.user_id.as_str());
    }
    if matches!(
        msg_type,
        "group_create"
            | "group_add"
            | "sender_keys_commit"
            | "sender_keys_welcome_request"
            | "sender_keys_welcome_ack"
            | "chat"
            | "prekey_bundle_request"
            | "messages_request"
            | "conversations_request"
    ) {
        let conversation_id = data
            .get("conversation_id")
            .and_then(|v| v.as_i64())
            .unwrap_or(-1);
        let session_epoch = data
            .get("session_epoch")
            .and_then(|v| v.as_i64())
            .unwrap_or(-1);
        info!(
            user_id = %info.user_id,
            connection_id = %connection_id,
            msg_type = %msg_type,
            conversation_id,
            session_epoch,
            "ingress message"
        );
    }

    if msg_type == "ping" {
        let _ = redis;
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

