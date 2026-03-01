use serde_json::{json, Value};
use tracing::{info, warn};

use crate::config::Config;
use crate::state::GatewayState;

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
                let envelope = json!({
                    "type": "event",
                    "payload": payload,
                });
                if let Ok(text) = serde_json::to_string(&envelope) {
                    let payload_type = decoded
                        .get("payload")
                        .and_then(|value| value.get("type"))
                        .and_then(|value| value.as_str())
                        .unwrap_or("unknown");
                    info!(
                        subject_count = subjects.len(),
                        payload_type,
                        "outbox dispatch"
                    );
                    state.send_to_subjects(&subjects, text);
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
