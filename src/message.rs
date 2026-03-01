use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageFlags {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qos: Option<String>,
}

impl MessageFlags {
    pub fn new() -> Self {
        Self {
            encrypted: None,
            qos: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InternalMessage {
    pub schema_version: i32,
    pub internal_id: String,
    pub timestamp_ms: i64,
    pub user_id: String,
    pub channel_id: String,
    pub flags: MessageFlags,
    pub payload: Value,
}

pub fn extract_channel_id(data: &Value, fallback: &str) -> String {
    for key in ["channel_id", "channel", "topic"] {
        if let Some(value) = data.get(key).and_then(|v| v.as_str()) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    fallback.to_string()
}

pub fn extract_payload(data: &Value) -> Value {
    if let Some(payload) = data.get("payload") {
        payload.clone()
    } else {
        data.clone()
    }
}

pub fn extract_flags(data: &Value) -> MessageFlags {
    let mut flags = MessageFlags::new();
    if let Some(value) = data.get("encrypted").and_then(|v| v.as_bool()) {
        flags.encrypted = Some(value);
    }
    if let Some(nested) = data.get("flags") {
        if let Some(value) = nested.get("encrypted").and_then(|v| v.as_bool()) {
            flags.encrypted = Some(value);
        }
        if let Some(qos) = nested.get("qos").and_then(|v| v.as_str()) {
            if !qos.is_empty() {
                flags.qos = Some(qos.to_string());
            }
        }
    }
    if let Some(qos) = data.get("qos").and_then(|v| v.as_str()) {
        if !qos.is_empty() {
            flags.qos = Some(qos.to_string());
        }
    }
    flags
}
