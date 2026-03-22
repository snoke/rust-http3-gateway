use serde_json::{json, Value};
use tracing::{info, warn};

use crate::config::Config;
use crate::routes::{AudienceScopeMode, RelayContextType};
use crate::state::{
    DispatchResult, GatewayState, RelayAudienceScope, RelayContextSnapshot, RelayContextState,
    RelayGrant, RelayOperationContext,
};

#[derive(Clone, Copy, Debug)]
enum DeliveryMode {
    RequestResponse,
    Push,
}

impl DeliveryMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::RequestResponse => "request_response",
            Self::Push => "push",
        }
    }
}

fn extract_request_id(payload: &Value) -> Option<String> {
    payload
        .get("request_id")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

fn parse_context_type(value: &str) -> Option<RelayContextType> {
    match value.trim().to_lowercase().as_str() {
        "file_transfer_peer" => Some(RelayContextType::FileTransferPeer),
        _ => None,
    }
}

fn parse_scope_mode(value: &str) -> Option<AudienceScopeMode> {
    match value.trim().to_lowercase().as_str() {
        "fixed_peer" => Some(AudienceScopeMode::FixedPeer),
        "context_members" => Some(AudienceScopeMode::ContextMembers),
        "explicit_subset" => Some(AudienceScopeMode::ExplicitSubset),
        _ => None,
    }
}

fn parse_context_state(value: &str) -> Option<RelayContextState> {
    match value.trim().to_lowercase().as_str() {
        "opened" => Some(RelayContextState::Opened),
        "active" => Some(RelayContextState::Active),
        "revoked" => Some(RelayContextState::Revoked),
        "closed" => Some(RelayContextState::Closed),
        "policy_version_bumped" => Some(RelayContextState::PolicyVersionBumped),
        _ => None,
    }
}

fn parse_u64(value: Option<&Value>) -> Option<u64> {
    value.and_then(|item| {
        if let Some(parsed) = item.as_u64() {
            return Some(parsed);
        }
        item.as_i64()
            .and_then(|parsed| if parsed > 0 { Some(parsed as u64) } else { None })
    })
}

fn parse_i64(value: Option<&Value>) -> Option<i64> {
    value.and_then(|item| item.as_i64())
}

fn parse_relay_context_snapshot(payload: &Value) -> Option<RelayContextSnapshot> {
    let payload_type = payload.get("type").and_then(Value::as_str).unwrap_or("");
    if payload_type != "gateway_relay_context_snapshot" {
        return None;
    }
    let operation_class = payload
        .get("operation_class")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_lowercase();
    if operation_class != "relay_hotpath" {
        return None;
    }
    let subject_email = payload
        .get("subject")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?
        .to_string();
    let context_type = parse_context_type(
        payload
            .get("context_type")
            .and_then(Value::as_str)
            .unwrap_or(""),
    )?;
    let policy_version = parse_u64(payload.get("policy_version"))?;
    let received_at = parse_i64(payload.get("ts")).unwrap_or_else(|| chrono::Utc::now().timestamp());
    let default_ttl = parse_i64(payload.get("default_ttl_seconds")).unwrap_or(24 * 60 * 60);
    let contexts = payload
        .get("contexts")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let object = item.as_object()?;
                    let context_id = object
                        .get("context_id")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())?
                        .to_string();
                    let operation_key = object
                        .get("operation_key")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())?
                        .to_string();
                    let authorized_subject = object
                        .get("authorized_subject")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())?
                        .to_string();
                    let state = parse_context_state(
                        object
                            .get("state")
                            .and_then(Value::as_str)
                            .unwrap_or("active"),
                    )?;
                    let context_policy_version =
                        parse_u64(object.get("policy_version")).unwrap_or(policy_version);
                    let opened_at =
                        parse_i64(object.get("opened_at")).unwrap_or(received_at);
                    let updated_at =
                        parse_i64(object.get("updated_at")).unwrap_or(received_at);
                    let expires_at = parse_i64(object.get("expires_at"))
                        .unwrap_or(received_at.saturating_add(default_ttl));

                    let grant_obj = object.get("grant").and_then(Value::as_object)?;
                    let grant_id = grant_obj
                        .get("grant_id")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())?
                        .to_string();
                    let grant_policy_version = parse_u64(grant_obj.get("policy_version"))
                        .unwrap_or(context_policy_version);
                    let grant_issued_at = parse_i64(grant_obj.get("issued_at")).unwrap_or(received_at);
                    let grant_expires_at = parse_i64(grant_obj.get("expires_at")).unwrap_or(expires_at);

                    let scope_obj = object.get("audience_scope").and_then(Value::as_object)?;
                    let scope_mode = parse_scope_mode(
                        scope_obj
                            .get("mode")
                            .and_then(Value::as_str)
                            .unwrap_or(""),
                    )?;
                    let peers = scope_obj
                        .get("peers")
                        .and_then(Value::as_array)
                        .map(|values| {
                            values
                                .iter()
                                .filter_map(|entry| entry.as_str().map(str::to_string))
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();

                    let allowed_families = object
                        .get("allowed_command_families")
                        .and_then(Value::as_array)
                        .map(|values| {
                            values
                                .iter()
                                .filter_map(|entry| entry.as_str().map(str::to_string))
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();

                    Some(RelayOperationContext {
                        context_id,
                        operation_key,
                        operation_class: "relay_hotpath".to_string(),
                        context_type,
                        state,
                        authorized_subject,
                        audience_scope: RelayAudienceScope {
                            mode: scope_mode,
                            peers,
                        },
                        allowed_command_families: allowed_families,
                        policy_version: context_policy_version,
                        grant: RelayGrant {
                            grant_id,
                            policy_version: grant_policy_version,
                            issued_at: grant_issued_at,
                            expires_at: grant_expires_at,
                        },
                        opened_at,
                        updated_at,
                        expires_at,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Some(RelayContextSnapshot {
        subject_email,
        context_type,
        policy_version,
        contexts,
        received_at,
    })
}

pub async fn publish_event(
    redis: &redis::Client,
    stream: &str,
    payload: &Value,
) -> anyhow::Result<()> {
    if stream.is_empty() {
        return Ok(());
    }
    let body = serde_json::to_string(payload)?;
    let mut conn = redis.get_multiplexed_async_connection().await?;
    let mut cmd = redis::cmd("XADD");
    cmd.arg(stream).arg("*").arg("data").arg(body);
    let _: () = cmd.query_async(&mut conn).await?;
    Ok(())
}

pub async fn start_outbox_consumer(state: GatewayState, config: Config, redis: redis::Client) {
    if config.redis_dsn.is_empty() {
        warn!("redis.dsn missing; outbox consumer disabled");
        return;
    }
    let stream = config.redis_stream.clone();
    if stream.is_empty() {
        warn!("redis stream missing; outbox consumer disabled");
        return;
    }
    info!(%stream, "outbox consumer starting");
    let mut last_id = "$".to_string();
    loop {
        let mut conn = match redis.get_multiplexed_async_connection().await {
            Ok(conn) => conn,
            Err(err) => {
                warn!("redis.connect_failed: {err}");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };
        let result: redis::RedisResult<redis::Value> = redis::cmd("XREAD")
            .arg("BLOCK")
            .arg(5000)
            .arg("COUNT")
            .arg(50)
            .arg("STREAMS")
            .arg(&stream)
            .arg(&last_id)
            .query_async(&mut conn)
            .await;

        let value = match result {
            Ok(value) => value,
            Err(err) => {
                warn!("redis.xread_failed: {err}");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };

        let streams = match parse_xread(value) {
            Ok(items) => items,
            Err(err) => {
                warn!("redis.xread_parse_failed: {err}");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };

        if streams.is_empty() {
            continue;
        }
        for (_stream, entries) in streams {
            for (entry_id, fields) in entries {
                last_id = entry_id.clone();
                let raw = fields
                    .get("data")
                    .cloned()
                    .unwrap_or_else(|| "{}".to_string());
                let decoded: Value = match serde_json::from_str(&raw) {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                let subjects = decoded
                    .get("subjects")
                    .and_then(|value| value.as_array())
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(|item| item.as_str().map(|s| s.to_string()))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                if subjects.is_empty() {
                    continue;
                }

                let payload = decoded.get("payload").cloned().unwrap_or(Value::Null);
                if let Some(snapshot) = parse_relay_context_snapshot(&payload) {
                    state.apply_relay_context_snapshot(snapshot);
                    info!(payload_type = "gateway_relay_context_snapshot", "relay context snapshot applied");
                    continue;
                }
                let request_id = extract_request_id(&payload);
                let payload_type = payload
                    .get("type")
                    .and_then(|value| value.as_str())
                    .unwrap_or("");
                let delivery_mode = if request_id.is_some() {
                    DeliveryMode::RequestResponse
                } else {
                    DeliveryMode::Push
                };
                let buffer_if_undelivered = matches!(delivery_mode, DeliveryMode::Push);

                let envelope = json!({
                    "type": "event",
                    "payload": payload,
                });

                if let Ok(text) = serde_json::to_string(&envelope) {
                    let mut route_found = false;
                    let mut routed_connection_id: Option<String> = None;
                    let dispatch_result = match delivery_mode {
                        DeliveryMode::RequestResponse => {
                            let mut result = DispatchResult {
                                attempted_count: 0,
                                enqueued_count: 0,
                            };
                            let mut delivered_via_route = false;
                            if let Some(req_id) = request_id.as_deref() {
                                if let Some(connection_id) = state.resolve_request_route(req_id, &subjects) {
                                    route_found = true;
                                    result.attempted_count = 1;
                                    routed_connection_id = Some(connection_id.clone());
                                    if state.send_to_connection(connection_id.as_str(), text.clone()) {
                                        result.enqueued_count = 1;
                                        delivered_via_route = true;
                                    } else {
                                        state.clear_request_route(req_id);
                                    }
                                } else {
                                    info!(
                                        request_id = %req_id,
                                        subject_count = subjects.len(),
                                        subjects = %subjects.join(","),
                                        "request_response route missing (fallback to subjects)"
                                    );
                                }
                            }
                            if !delivered_via_route {
                                // Fallback: deliver to subjects when request-route mapping is missing/stale.
                                // This avoids client timeouts after reconnects when response still carries a request_id.
                                let fallback = state.send_to_subjects(&subjects, text.clone(), true, None);
                                result.attempted_count += fallback.attempted_count;
                                result.enqueued_count += fallback.enqueued_count;
                            }
                            result
                        }
                        DeliveryMode::Push => {
                            state.send_to_subjects(&subjects, text.clone(), buffer_if_undelivered, None)
                        }
                    };

                    info!(
                        subject_count = subjects.len(),
                        dispatch_attempts = dispatch_result.attempted_count,
                        enqueued_count = dispatch_result.enqueued_count,
                        dispatch_mode = delivery_mode.as_str(),
                        payload_type,
                        delivery_scope = if matches!(delivery_mode, DeliveryMode::RequestResponse) {
                            "connection"
                        } else {
                            "subjects"
                        },
                        request_id = request_id.as_deref().unwrap_or(""),
                        route_found,
                        routed_connection_id = routed_connection_id.as_deref().unwrap_or(""),
                        buffer_if_undelivered,
                        "outbox dispatch"
                    );

                    if dispatch_result.enqueued_count == 0 {
                        warn!(
                            subject_count = subjects.len(),
                            dispatch_attempts = dispatch_result.attempted_count,
                            enqueued_count = dispatch_result.enqueued_count,
                            dispatch_mode = delivery_mode.as_str(),
                            payload_type,
                            delivery_scope = if matches!(delivery_mode, DeliveryMode::RequestResponse) {
                                "connection"
                            } else {
                                "subjects"
                            },
                            request_id = request_id.as_deref().unwrap_or(""),
                            route_found,
                            routed_connection_id = routed_connection_id.as_deref().unwrap_or(""),
                            buffer_if_undelivered,
                            "outbox enqueued to zero connections"
                        );
                    }

                    if config.outbox_delete_on_consume {
                        if let Err(err) = redis::cmd("XDEL")
                            .arg(&stream)
                            .arg(&entry_id)
                            .query_async::<_, ()>(&mut conn)
                            .await
                        {
                            warn!(%entry_id, "redis.xdel_failed: {err}");
                        }
                    }
                }
            }
        }
    }
}

fn parse_xread(
    value: redis::Value,
) -> Result<Vec<(String, Vec<(String, std::collections::HashMap<String, String>)>)>, String> {
    use redis::Value::{Bulk, Data, Nil};
    match value {
        Nil => Ok(vec![]),
        Bulk(streams) => {
            let mut parsed = Vec::new();
            for stream_entry in streams {
                let Bulk(mut parts) = stream_entry else {
                    continue;
                };
                if parts.len() != 2 {
                    continue;
                }
                let stream_name = match parts.remove(0) {
                    Data(bytes) => String::from_utf8_lossy(&bytes).to_string(),
                    _ => continue,
                };
                let entries = match parts.remove(0) {
                    Bulk(entries) => entries,
                    _ => continue,
                };
                let mut parsed_entries = Vec::new();
                for entry in entries {
                    let Bulk(mut entry_parts) = entry else {
                        continue;
                    };
                    if entry_parts.len() != 2 {
                        continue;
                    }
                    let entry_id = match entry_parts.remove(0) {
                        Data(bytes) => String::from_utf8_lossy(&bytes).to_string(),
                        _ => continue,
                    };
                    let fields = match entry_parts.remove(0) {
                        Bulk(fields) => fields,
                        _ => continue,
                    };
                    let mut field_map = std::collections::HashMap::new();
                    let mut iter = fields.into_iter();
                    while let (Some(key), Some(value)) = (iter.next(), iter.next()) {
                        let key = match key {
                            Data(bytes) => String::from_utf8_lossy(&bytes).to_string(),
                            _ => continue,
                        };
                        let value = match value {
                            Data(bytes) => String::from_utf8_lossy(&bytes).to_string(),
                            _ => continue,
                        };
                        field_map.insert(key, value);
                    }
                    parsed_entries.push((entry_id, field_map));
                }
                parsed.push((stream_name, parsed_entries));
            }
            Ok(parsed)
        }
        other => Err(format!("unexpected redis value: {other:?}")),
    }
}
