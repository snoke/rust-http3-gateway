use serde_json::{json, Value};
use tracing::{info, warn};
use uuid::Uuid;

use crate::broker::publish_event;
use crate::config::Config;
use crate::message::{extract_channel_id, extract_flags, extract_payload, InternalMessage};
use crate::routes::{resolve_command_spec, resolve_dispatch_plan, DispatchStep, RoutingClass};
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
    if msg_type.trim().is_empty() {
        send_gateway_command_error(
            state,
            connection_id,
            "",
            "invalid_command",
            "Message type is required.",
        );
        return;
    }

    let command_spec = match resolve_command_spec(msg_type) {
        Some(spec) => spec,
        None => {
            warn!(
                user_id = %info.user_id,
                connection_id = %connection_id,
                msg_type = %msg_type,
                "rejecting unknown command"
            );
            send_gateway_command_error(
                state,
                connection_id,
                msg_type,
                "unsupported_command",
                "Command is not registered.",
            );
            return;
        }
    };

    if command_spec.deprecated {
        warn!(
            user_id = %info.user_id,
            connection_id = %connection_id,
            msg_type = %msg_type,
            owner = %command_spec.owner,
            notes = %command_spec.notes.unwrap_or(""),
            "deprecated command used"
        );
    }

    if matches!(command_spec.routing_class, RoutingClass::PreAuth) {
        send_gateway_command_error(
            state,
            connection_id,
            msg_type,
            "preauth_only_command",
            "Command is only allowed during preauth.",
        );
        return;
    }

    if matches!(command_spec.routing_class, RoutingClass::GatewayLocal) {
        if msg_type == "ping" {
            return;
        }
        send_gateway_command_error(
            state,
            connection_id,
            msg_type,
            "invalid_gateway_local_command",
            "Unsupported gateway-local command.",
        );
        return;
    }

    let dispatch_plan = match resolve_dispatch_plan(msg_type) {
        Some(plan) => plan,
        None => {
            send_gateway_command_error(
                state,
                connection_id,
                msg_type,
                "invalid_dispatch_plan",
                "Command has no dispatch plan.",
            );
            return;
        }
    };
    let dispatch_steps: Vec<&str> = dispatch_plan.iter().map(|step| step.as_str()).collect();
    let has_symfony_step = dispatch_plan.iter().any(|step| matches!(step, DispatchStep::Symfony));
    let has_subjects_step = dispatch_plan.iter().any(|step| matches!(step, DispatchStep::Subjects));
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
            | "chat_message_send"
            | "mls_commit"
            | "mls_welcome_request"
            | "chat_messages_request"
            | "chat_conversations_request"
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
            routing_class = %command_spec.routing_class.as_str(),
            semantic_type = %command_spec.message_type.as_str(),
            conversation_id,
            session_epoch,
            dispatch_plan = %dispatch_steps.join("->"),
            "ingress message"
        );
    }

    if has_subjects_step {
        let target_subjects = collect_target_subjects(&data);
        if target_subjects.is_empty() {
            warn!(
                user_id = %info.user_id,
                connection_id = %connection_id,
                msg_type = %msg_type,
                "subjects relay skipped: no target subjects"
            );
            if !has_symfony_step {
                send_gateway_command_error(
                    state,
                    connection_id,
                    msg_type,
                    "invalid_relay_targets",
                    "Relay command requires at least one target subject.",
                );
                return;
            }
        } else {
            let mut relay_payload = data.clone();
            if relay_payload
                .get("from")
                .and_then(|value| value.as_str())
                .map(str::trim)
                .unwrap_or("")
                .is_empty()
            {
                relay_payload["from"] = Value::String(info.user_id.clone());
            }
            let envelope = json!({
                "type": "event",
                "payload": relay_payload,
            });
            if let Ok(text) = serde_json::to_string(&envelope) {
                let dispatched = state.send_to_subjects(&target_subjects, text, true, None);
                info!(
                    user_id = %info.user_id,
                    connection_id = %connection_id,
                    msg_type = %msg_type,
                    subject_count = target_subjects.len(),
                    subjects = %target_subjects.join(","),
                    attempted = dispatched.attempted_count,
                    enqueued = dispatched.enqueued_count,
                    "subjects relay dispatch"
                );
            }
        }

        if !has_symfony_step {
            return;
        }
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
        "command_type": msg_type,
        "routing_class": command_spec.routing_class.as_str(),
        "semantic_type": command_spec.message_type.as_str(),
        "dispatch_plan": dispatch_steps,
    });

    if let Some(redis) = redis {
        if let Err(err) = publish_event(redis, &config.redis_inbox_stream, &payload).await {
            warn!("publish_event_failed: {err}");
        }
    }
}

fn send_gateway_command_error(
    state: &GatewayState,
    connection_id: &str,
    command: &str,
    error: &str,
    message: &str,
) {
    let payload = json!({
        "type": "gateway_command_error",
        "command": command,
        "error": error,
        "message": message,
        "ts": chrono::Utc::now().timestamp(),
    });
    let envelope = json!({
        "type": "event",
        "payload": payload,
    });
    if let Ok(text) = serde_json::to_string(&envelope) {
        let _ = state.send_to_connection(connection_id, text);
    }
}

fn collect_target_subjects(data: &Value) -> Vec<String> {
    let mut subjects = Vec::new();
    if let Some(target) = data.get("to").and_then(|value| value.as_str()) {
        append_subject_variants(target, &mut subjects);
    }
    if let Some(items) = data.get("recipients").and_then(|value| value.as_array()) {
        for item in items {
            if let Some(email) = item.as_str() {
                append_subject_variants(email, &mut subjects);
            }
        }
    }
    subjects.sort();
    subjects.dedup();
    subjects
}

fn append_subject_variants(value: &str, out: &mut Vec<String>) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return;
    }
    out.push(format!("user:{trimmed}"));
    let normalized = trimmed.to_lowercase();
    if normalized != trimmed {
        out.push(format!("user:{normalized}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::state::{GatewayState, OutboundMessage};
    use tokio::sync::mpsc::UnboundedReceiver;
    use tokio::time::{timeout, Duration};

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

    fn register_user_connection(
        state: &GatewayState,
        connection_id: &str,
        user_email: &str,
    ) -> (ConnectionInfo, UnboundedReceiver<OutboundMessage>) {
        let now = chrono::Utc::now().timestamp();
        let subjects = vec![format!("user:{user_email}")];
        let (info, rx, _evicted) = state.register_connection(
            connection_id.to_string(),
            user_email.to_string(),
            format!("client-{connection_id}"),
            subjects,
            now,
        );
        (info, rx)
    }

    async fn recv_text(receiver: &mut UnboundedReceiver<OutboundMessage>) -> Option<String> {
        match timeout(Duration::from_millis(100), receiver.recv()).await {
            Ok(Some(OutboundMessage::Text(text))) => Some(text),
            _ => None,
        }
    }

    async fn assert_no_message(receiver: &mut UnboundedReceiver<OutboundMessage>) {
        let received = timeout(Duration::from_millis(40), receiver.recv()).await;
        assert!(received.is_err(), "unexpected outbound message");
    }

    fn extract_inner_payload(event_text: &str) -> Value {
        let parsed: Value = serde_json::from_str(event_text).expect("invalid event json");
        parsed
            .get("payload")
            .cloned()
            .expect("missing payload field")
    }

    #[tokio::test]
    async fn rejects_unknown_command() {
        let state = GatewayState::new(None);
        let config = test_config();
        let (info, mut sender_rx) = register_user_connection(&state, "conn-a", "alice@test.de");

        handle_client_message(
            &state,
            "conn-a",
            &info,
            r#"{"type":"does_not_exist"}"#.to_string(),
            &config,
            None,
        )
        .await;

        let outbound = recv_text(&mut sender_rx).await.expect("expected error response");
        let payload = extract_inner_payload(&outbound);
        assert_eq!(payload.get("type").and_then(Value::as_str), Some("gateway_command_error"));
        assert_eq!(
            payload.get("error").and_then(Value::as_str),
            Some("unsupported_command")
        );
    }

    #[tokio::test]
    async fn rejects_preauth_command_in_runtime_channel() {
        let state = GatewayState::new(None);
        let config = test_config();
        let (info, mut sender_rx) = register_user_connection(&state, "conn-a", "alice@test.de");

        handle_client_message(
            &state,
            "conn-a",
            &info,
            r#"{"type":"auth_login_request","email":"a@test.de","password":"x"}"#.to_string(),
            &config,
            None,
        )
        .await;

        let outbound = recv_text(&mut sender_rx).await.expect("expected error response");
        let payload = extract_inner_payload(&outbound);
        assert_eq!(payload.get("type").and_then(Value::as_str), Some("gateway_command_error"));
        assert_eq!(
            payload.get("error").and_then(Value::as_str),
            Some("preauth_only_command")
        );
    }

    #[tokio::test]
    async fn accepts_gateway_local_ping_without_dispatch() {
        let state = GatewayState::new(None);
        let config = test_config();
        let (info, mut sender_rx) = register_user_connection(&state, "conn-a", "alice@test.de");

        handle_client_message(
            &state,
            "conn-a",
            &info,
            r#"{"type":"ping"}"#.to_string(),
            &config,
            None,
        )
        .await;

        assert_no_message(&mut sender_rx).await;
    }

    #[tokio::test]
    async fn relay_hotpath_file_transfer_offer_relays_to_target_without_backend() {
        let state = GatewayState::new(None);
        let config = test_config();
        let (alice_info, mut alice_rx) = register_user_connection(&state, "conn-a", "alice@test.de");
        let (_bob_info, mut bob_rx) = register_user_connection(&state, "conn-b", "bob@test.de");

        handle_client_message(
            &state,
            "conn-a",
            &alice_info,
            r#"{"type":"file_transfer_offer","transfer_id":"ft-1","to":"bob@test.de"}"#.to_string(),
            &config,
            None,
        )
        .await;

        let bob_event = recv_text(&mut bob_rx).await.expect("expected relay to target");
        let bob_payload = extract_inner_payload(&bob_event);
        assert_eq!(
            bob_payload.get("type").and_then(Value::as_str),
            Some("file_transfer_offer")
        );
        assert_eq!(
            bob_payload.get("from").and_then(Value::as_str),
            Some("alice@test.de")
        );
        assert_no_message(&mut alice_rx).await;
    }

    #[tokio::test]
    async fn relay_hotpath_without_target_is_rejected() {
        let state = GatewayState::new(None);
        let config = test_config();
        let (alice_info, mut alice_rx) = register_user_connection(&state, "conn-a", "alice@test.de");

        handle_client_message(
            &state,
            "conn-a",
            &alice_info,
            r#"{"type":"file_transfer_chunk","transfer_id":"ft-1","index":0}"#.to_string(),
            &config,
            None,
        )
        .await;

        let outbound = recv_text(&mut alice_rx).await.expect("expected relay target error");
        let payload = extract_inner_payload(&outbound);
        assert_eq!(payload.get("type").and_then(Value::as_str), Some("gateway_command_error"));
        assert_eq!(
            payload.get("error").and_then(Value::as_str),
            Some("invalid_relay_targets")
        );
    }

    #[tokio::test]
    async fn backend_control_chat_typing_presence_are_not_relayed_directly() {
        let state = GatewayState::new(None);
        let config = test_config();
        let (alice_info, mut alice_rx) = register_user_connection(&state, "conn-a", "alice@test.de");
        let (_bob_info, mut bob_rx) = register_user_connection(&state, "conn-b", "bob@test.de");

        handle_client_message(
            &state,
            "conn-a",
            &alice_info,
            r#"{"type":"chat_message_send","conversation_id":1,"to":"bob@test.de","ciphertext":"x"}"#.to_string(),
            &config,
            None,
        )
        .await;
        handle_client_message(
            &state,
            "conn-a",
            &alice_info,
            r#"{"type":"chat_typing_state","conversation_id":1,"to":"bob@test.de","isTyping":true}"#.to_string(),
            &config,
            None,
        )
        .await;
        handle_client_message(
            &state,
            "conn-a",
            &alice_info,
            r#"{"type":"presence_state","state":"online","to":"bob@test.de"}"#.to_string(),
            &config,
            None,
        )
        .await;

        assert_no_message(&mut bob_rx).await;
        assert_no_message(&mut alice_rx).await;
    }
}
