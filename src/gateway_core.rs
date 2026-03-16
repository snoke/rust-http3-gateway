use serde_json::{json, Value};
use tracing::{info, warn};
use uuid::Uuid;

use crate::broker::publish_event;
use crate::config::Config;
use crate::message::{extract_channel_id, extract_flags, extract_payload, InternalMessage};
use crate::routes::{
    resolve_command_spec, resolve_relay_authorization_spec, RoutingClass,
};
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

    if matches!(command_spec.routing_class, RoutingClass::NoAuth) {
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

    let has_subjects_step = matches!(command_spec.routing_class, RoutingClass::RelayHotpath);
    let has_symfony_step = matches!(command_spec.routing_class, RoutingClass::BackendControl)
        || (has_subjects_step && command_spec.mirror_to_backend);
    let runtime_path: Vec<&str> = match (has_subjects_step, has_symfony_step) {
        (true, true) => vec!["subjects", "symfony"],
        (true, false) => vec!["subjects"],
        (false, true) => vec!["symfony"],
        (false, false) => vec![],
    };
    let maybe_request_id = data
        .get("request_id")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(request_id) = maybe_request_id {
        if has_symfony_step {
            state.bind_request_route(request_id, connection_id, info.user_id.as_str());
            if msg_type == "call_session_create" {
                info!(
                    user_id = %info.user_id,
                    connection_id = %connection_id,
                    request_id = %request_id,
                    "bound request route for call_session_create"
                );
            }
        }
    } else if msg_type == "call_session_create" {
        info!(
            user_id = %info.user_id,
            connection_id = %connection_id,
            "call_session_create missing request_id (route not bound)"
        );
    }
    if msg_type == "session_ready" {
        let evicted = state.mark_session_ready(connection_id, info.user_id.as_str());
        if !evicted.is_empty() {
            info!(
                user_id = %info.user_id,
                connection_id = %connection_id,
                evicted_count = evicted.len(),
                "session_ready triggered connection eviction"
            );
        }
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
            runtime_path = %runtime_path.join("->"),
            "ingress message"
        );
    }

    if has_subjects_step {
        let relay_targets = collect_relay_targets(&data);
        if relay_targets.subjects.is_empty() {
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
            if matches!(command_spec.routing_class, RoutingClass::RelayHotpath) {
                let Some(auth_spec) = resolve_relay_authorization_spec(msg_type) else {
                    send_gateway_command_error(
                        state,
                        connection_id,
                        msg_type,
                        "relay_auth_spec_missing",
                        "Relay command has no authorization metadata.",
                    );
                    return;
                };
                let replay_nonce = data
                    .get("nonce")
                    .and_then(Value::as_str)
                    .or_else(|| data.get("header").and_then(Value::as_str));
                let operation_key = data
                    .get(auth_spec.operation_key_field)
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .unwrap_or("");
                if operation_key.is_empty() {
                    send_gateway_command_error(
                        state,
                        connection_id,
                        msg_type,
                        "relay_operation_key_missing",
                        "Relay command is missing operation key.",
                    );
                    return;
                }
                if auth_spec.requires_relay_context {
                    let payload_size_hint = data
                        .get("ciphertext")
                        .and_then(Value::as_str)
                        .map(|value| value.len());
                    let now_ts = chrono::Utc::now().timestamp();
                    match state.authorize_relay_hotpath(
                        info.user_id.as_str(),
                        msg_type,
                        auth_spec,
                        operation_key,
                        &relay_targets.emails,
                        replay_nonce,
                        payload_size_hint,
                        now_ts,
                    ) {
                        Ok(decision) => {
                            info!(
                                user_id = %info.user_id,
                                connection_id = %connection_id,
                                msg_type = %msg_type,
                                relay_context_id = %decision.context_id,
                                relay_policy_version = decision.policy_version,
                                "relay authorization passed"
                            );
                        }
                        Err(error) => {
                            send_gateway_command_error(
                                state,
                                connection_id,
                                msg_type,
                                error.code(),
                                "Relay authorization failed.",
                            );
                            return;
                        }
                    }
                }
            }
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
                let dispatched = state.send_to_subjects(&relay_targets.subjects, text, true, None);
                info!(
                    user_id = %info.user_id,
                    connection_id = %connection_id,
                    msg_type = %msg_type,
                    subject_count = relay_targets.subjects.len(),
                    subjects = %relay_targets.subjects.join(","),
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
        "runtime_path": runtime_path,
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

struct RelayTargets {
    emails: Vec<String>,
    subjects: Vec<String>,
}

fn collect_relay_targets(data: &Value) -> RelayTargets {
    let mut emails = Vec::new();
    let mut subjects = Vec::new();
    if let Some(target) = data.get("to").and_then(|value| value.as_str()) {
        append_target_variants(target, &mut emails, &mut subjects);
    }
    if let Some(items) = data.get("recipients").and_then(|value| value.as_array()) {
        for item in items {
            if let Some(email) = item.as_str() {
                append_target_variants(email, &mut emails, &mut subjects);
            }
        }
    }
    emails.sort();
    emails.dedup();
    subjects.sort();
    subjects.dedup();
    RelayTargets { emails, subjects }
}

fn append_target_variants(value: &str, emails: &mut Vec<String>, subjects: &mut Vec<String>) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return;
    }
    let normalized = trimmed.to_lowercase();
    emails.push(normalized.clone());
    subjects.push(format!("user:{trimmed}"));
    subjects.push(format!("user:{normalized}"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::routes::{AudienceScopeMode, RelayContextType};
    use crate::state::{
        GatewayState, OutboundMessage, RelayAudienceScope, RelayContextSnapshot, RelayContextState,
        RelayGrant, RelayOperationContext,
    };
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

    fn apply_file_transfer_context(
        state: &GatewayState,
        sender: &str,
        peer: &str,
        operation_key: &str,
        status: RelayContextState,
        policy_version: u64,
    ) {
        let now = chrono::Utc::now().timestamp();
        state.apply_relay_context_snapshot(RelayContextSnapshot {
            subject_email: sender.to_string(),
            context_type: RelayContextType::FileTransferPeer,
            policy_version,
            received_at: now,
            contexts: vec![RelayOperationContext {
                context_id: format!("opx-{}", operation_key),
                operation_key: operation_key.to_string(),
                operation_class: "relay_hotpath".to_string(),
                context_type: RelayContextType::FileTransferPeer,
                state: status,
                authorized_subject: sender.to_string(),
                audience_scope: RelayAudienceScope {
                    mode: AudienceScopeMode::FixedPeer,
                    peers: vec![peer.to_string()],
                },
                allowed_command_families: vec!["file_transfer".to_string()],
                policy_version,
                grant: RelayGrant {
                    grant_id: format!("grant-{}-{}", sender, peer),
                    policy_version,
                    issued_at: now,
                    expires_at: now + 3600,
                },
                opened_at: now,
                updated_at: now,
                expires_at: now + 3600,
            }],
        });
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
        apply_file_transfer_context(
            &state,
            "alice@test.de",
            "bob@test.de",
            "ft-1",
            RelayContextState::Active,
            1,
        );

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
    async fn relay_hotpath_rejects_without_context() {
        let state = GatewayState::new(None);
        let config = test_config();
        let (alice_info, mut alice_rx) = register_user_connection(&state, "conn-a", "alice@test.de");
        let (_bob_info, mut bob_rx) = register_user_connection(&state, "conn-b", "bob@test.de");

        handle_client_message(
            &state,
            "conn-a",
            &alice_info,
            r#"{"type":"file_transfer_chunk","transfer_id":"ft-1","to":"bob@test.de","index":0}"#.to_string(),
            &config,
            None,
        )
        .await;

        let outbound = recv_text(&mut alice_rx).await.expect("expected relay auth error");
        let payload = extract_inner_payload(&outbound);
        assert_eq!(payload.get("type").and_then(Value::as_str), Some("gateway_command_error"));
        assert_eq!(
            payload.get("error").and_then(Value::as_str),
            Some("relay_context_missing")
        );
        assert_no_message(&mut bob_rx).await;
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
    async fn relay_hotpath_rejects_revoked_context() {
        let state = GatewayState::new(None);
        let config = test_config();
        let (alice_info, mut alice_rx) = register_user_connection(&state, "conn-a", "alice@test.de");
        let (_bob_info, mut bob_rx) = register_user_connection(&state, "conn-b", "bob@test.de");
        apply_file_transfer_context(
            &state,
            "alice@test.de",
            "bob@test.de",
            "ft-1",
            RelayContextState::Revoked,
            4,
        );

        handle_client_message(
            &state,
            "conn-a",
            &alice_info,
            r#"{"type":"file_transfer_chunk","transfer_id":"ft-1","to":"bob@test.de","index":0}"#.to_string(),
            &config,
            None,
        )
        .await;

        let outbound = recv_text(&mut alice_rx).await.expect("expected revoked error");
        let payload = extract_inner_payload(&outbound);
        assert_eq!(payload.get("error").and_then(Value::as_str), Some("relay_context_revoked"));
        assert_no_message(&mut bob_rx).await;
    }

    #[tokio::test]
    async fn relay_hotpath_rejects_closed_context() {
        let state = GatewayState::new(None);
        let config = test_config();
        let (alice_info, mut alice_rx) = register_user_connection(&state, "conn-a", "alice@test.de");
        let (_bob_info, mut bob_rx) = register_user_connection(&state, "conn-b", "bob@test.de");
        apply_file_transfer_context(
            &state,
            "alice@test.de",
            "bob@test.de",
            "ft-1",
            RelayContextState::Closed,
            5,
        );

        handle_client_message(
            &state,
            "conn-a",
            &alice_info,
            r#"{"type":"file_transfer_chunk","transfer_id":"ft-1","to":"bob@test.de","index":0}"#.to_string(),
            &config,
            None,
        )
        .await;

        let outbound = recv_text(&mut alice_rx).await.expect("expected closed error");
        let payload = extract_inner_payload(&outbound);
        assert_eq!(payload.get("error").and_then(Value::as_str), Some("relay_context_closed"));
        assert_no_message(&mut bob_rx).await;
    }

    #[tokio::test]
    async fn relay_hotpath_rejects_policy_version_mismatch() {
        let state = GatewayState::new(None);
        let config = test_config();
        let (alice_info, mut alice_rx) = register_user_connection(&state, "conn-a", "alice@test.de");
        let (_bob_info, mut bob_rx) = register_user_connection(&state, "conn-b", "bob@test.de");
        let now = chrono::Utc::now().timestamp();
        state.apply_relay_context_snapshot(RelayContextSnapshot {
            subject_email: "alice@test.de".to_string(),
            context_type: RelayContextType::FileTransferPeer,
            policy_version: 7,
            received_at: now,
            contexts: vec![RelayOperationContext {
                context_id: "opx-ft-1".to_string(),
                operation_key: "ft-1".to_string(),
                operation_class: "relay_hotpath".to_string(),
                context_type: RelayContextType::FileTransferPeer,
                state: RelayContextState::Active,
                authorized_subject: "alice@test.de".to_string(),
                audience_scope: RelayAudienceScope {
                    mode: AudienceScopeMode::FixedPeer,
                    peers: vec!["bob@test.de".to_string()],
                },
                allowed_command_families: vec!["file_transfer".to_string()],
                policy_version: 7,
                grant: RelayGrant {
                    grant_id: "grant-1".to_string(),
                    policy_version: 6,
                    issued_at: now,
                    expires_at: now + 3600,
                },
                opened_at: now,
                updated_at: now,
                expires_at: now + 3600,
            }],
        });

        handle_client_message(
            &state,
            "conn-a",
            &alice_info,
            r#"{"type":"file_transfer_chunk","transfer_id":"ft-1","to":"bob@test.de","index":0}"#.to_string(),
            &config,
            None,
        )
        .await;

        let outbound = recv_text(&mut alice_rx).await.expect("expected version error");
        let payload = extract_inner_payload(&outbound);
        assert_eq!(
            payload.get("error").and_then(Value::as_str),
            Some("relay_policy_version_mismatch")
        );
        assert_no_message(&mut bob_rx).await;
    }

    #[tokio::test]
    async fn relay_hotpath_rejects_scope_violation() {
        let state = GatewayState::new(None);
        let config = test_config();
        let (alice_info, mut alice_rx) = register_user_connection(&state, "conn-a", "alice@test.de");
        let (_bob_info, mut bob_rx) = register_user_connection(&state, "conn-b", "bob@test.de");
        apply_file_transfer_context(
            &state,
            "alice@test.de",
            "charlie@test.de",
            "ft-1",
            RelayContextState::Active,
            2,
        );

        handle_client_message(
            &state,
            "conn-a",
            &alice_info,
            r#"{"type":"file_transfer_chunk","transfer_id":"ft-1","to":"bob@test.de","index":0}"#.to_string(),
            &config,
            None,
        )
        .await;

        let outbound = recv_text(&mut alice_rx).await.expect("expected scope violation");
        let payload = extract_inner_payload(&outbound);
        assert_eq!(
            payload.get("error").and_then(Value::as_str),
            Some("relay_scope_violation")
        );
        assert_no_message(&mut bob_rx).await;
    }

    #[tokio::test]
    async fn relay_hotpath_rejects_replay_nonce() {
        let state = GatewayState::new(None);
        let config = test_config();
        let (alice_info, mut alice_rx) = register_user_connection(&state, "conn-a", "alice@test.de");
        let (_bob_info, mut bob_rx) = register_user_connection(&state, "conn-b", "bob@test.de");
        apply_file_transfer_context(
            &state,
            "alice@test.de",
            "bob@test.de",
            "ft-1",
            RelayContextState::Active,
            3,
        );

        let message = r#"{"type":"file_transfer_chunk","transfer_id":"ft-1","to":"bob@test.de","nonce":"n-1","ciphertext":"abc"}"#.to_string();
        handle_client_message(&state, "conn-a", &alice_info, message.clone(), &config, None).await;
        let first = recv_text(&mut bob_rx).await.expect("first chunk should pass");
        let first_payload = extract_inner_payload(&first);
        assert_eq!(
            first_payload.get("type").and_then(Value::as_str),
            Some("file_transfer_chunk")
        );

        handle_client_message(&state, "conn-a", &alice_info, message, &config, None).await;
        let outbound = recv_text(&mut alice_rx).await.expect("expected replay rejection");
        let payload = extract_inner_payload(&outbound);
        assert_eq!(
            payload.get("error").and_then(Value::as_str),
            Some("relay_replay_detected")
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
