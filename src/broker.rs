use serde_json::{json, Value};
use tracing::{info, warn};

use crate::config::Config;
use crate::state::{DispatchResult, GatewayState};

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
                last_id = entry_id;
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
                    let mut fallback_subject_dispatch = false;
                    let dispatch_result = match delivery_mode {
                        DeliveryMode::RequestResponse => {
                            let mut result = DispatchResult {
                                attempted_count: 0,
                                enqueued_count: 0,
                            };
                            if let Some(req_id) = request_id.as_deref() {
                                if let Some(connection_id) = state.resolve_request_route(req_id, &subjects) {
                                    route_found = true;
                                    result.attempted_count = 1;
                                    routed_connection_id = Some(connection_id.clone());
                                    if state.send_to_connection(connection_id.as_str(), text.clone()) {
                                        result.enqueued_count = 1;
                                    } else {
                                        state.clear_request_route(req_id);
                                    }
                                }
                            }

                            // Route bindings can go stale during reconnect/HMR.
                            // Fallback to subject fanout so request-correlated responses
                            // still reach at least one active client connection.
                            if result.enqueued_count == 0 {
                                fallback_subject_dispatch = true;
                                let fallback = state.send_to_subjects(&subjects, text.clone(), false, None);
                                result.attempted_count = result
                                    .attempted_count
                                    .saturating_add(fallback.attempted_count);
                                result.enqueued_count = result
                                    .enqueued_count
                                    .saturating_add(fallback.enqueued_count);
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
                        fallback_subject_dispatch,
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
                            fallback_subject_dispatch,
                            buffer_if_undelivered,
                            "outbox enqueued to zero connections"
                        );
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
