use dashmap::{DashMap, DashSet};
use serde::Serialize;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::mpsc;

const MAX_CONNECTIONS_PER_USER: usize = 2;

#[derive(Clone, Debug)]
pub enum OutboundMessage {
    Text(String),
}

#[derive(Clone, Debug, Serialize)]
pub struct ConnectionInfo {
    pub connection_id: String,
    pub user_id: String,
    pub client_instance_id: String,
    pub subjects: Vec<String>,
    pub connected_at: i64,
}

#[derive(Clone)]
struct ConnectionHandle {
    info: ConnectionInfo,
    sender: mpsc::UnboundedSender<OutboundMessage>,
}

#[derive(Clone, Default)]
pub struct GatewayState {
    connections: Arc<DashMap<String, ConnectionHandle>>,
    subjects: Arc<DashMap<String, DashSet<String>>>,
}

impl GatewayState {
    pub fn register_connection(
        &self,
        connection_id: String,
        user_id: String,
        client_instance_id: String,
        subjects: Vec<String>,
        connected_at: i64,
    ) -> (
        ConnectionInfo,
        mpsc::UnboundedReceiver<OutboundMessage>,
        Vec<ConnectionInfo>,
    ) {
        // Keep only one active connection per client instance (tab/window)
        // to avoid stale connection accumulation when a single instance reconnects.
        let stale_ids: Vec<String> = self
            .connections
            .iter()
            .filter_map(|entry| {
                let existing = &entry.value().info;
                if existing.user_id != user_id {
                    None
                } else if client_instance_id.is_empty() {
                    None
                } else if existing.client_instance_id == client_instance_id {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();
        let mut same_user_connections: Vec<(String, i64)> = self
            .connections
            .iter()
            .filter_map(|entry| {
                let existing = &entry.value().info;
                if existing.user_id != user_id {
                    return None;
                }
                Some((entry.key().clone(), existing.connected_at))
            })
            .collect();
        same_user_connections.sort_by_key(|(_, connected_at)| *connected_at);
        let mut evicted = Vec::new();
        for stale_id in stale_ids {
            if stale_id != connection_id {
                if let Some(info) = self.unregister_connection(&stale_id) {
                    evicted.push(info);
                }
            }
        }
        // Hard cap per user to prevent stale/reconnect leaks from growing without bound.
        // Keep the newest connections (oldest are removed first).
        if same_user_connections.len() >= MAX_CONNECTIONS_PER_USER {
            let overflow = (same_user_connections.len() + 1).saturating_sub(MAX_CONNECTIONS_PER_USER);
            for (stale_id, _) in same_user_connections.into_iter().take(overflow) {
                if stale_id != connection_id {
                    if let Some(info) = self.unregister_connection(&stale_id) {
                        evicted.push(info);
                    }
                }
            }
        }

        let (tx, rx) = mpsc::unbounded_channel();
        let info = ConnectionInfo {
            connection_id: connection_id.clone(),
            user_id,
            client_instance_id,
            subjects: subjects.clone(),
            connected_at,
        };
        self.connections.insert(
            connection_id.clone(),
            ConnectionHandle { info: info.clone(), sender: tx },
        );
        for subject in subjects {
            let entry = self.subjects.entry(subject).or_insert_with(DashSet::new);
            entry.insert(connection_id.clone());
        }
        (info, rx, evicted)
    }

    pub fn unregister_connection(&self, connection_id: &str) -> Option<ConnectionInfo> {
        let handle = self.connections.remove(connection_id).map(|(_, handle)| handle);
        if let Some(handle) = handle {
            for subject in &handle.info.subjects {
                if let Some(mut entry) = self.subjects.get_mut(subject) {
                    entry.remove(connection_id);
                    if entry.is_empty() {
                        drop(entry);
                        self.subjects.remove(subject);
                    }
                }
            }
            return Some(handle.info);
        }
        None
    }

    pub fn list_connections(
        &self,
        subject: Option<&str>,
        user_id: Option<&str>,
    ) -> Vec<ConnectionInfo> {
        let mut results = Vec::new();
        for entry in self.connections.iter() {
            let handle = entry.value();
            if let Some(expected) = subject {
                if !handle.info.subjects.iter().any(|item| item == expected) {
                    continue;
                }
            }
            if let Some(expected) = user_id {
                if handle.info.user_id != expected {
                    continue;
                }
            }
            results.push(handle.info.clone());
        }
        results
    }

    pub fn send_to_subjects(&self, subjects: &[String], message: String) -> usize {
        let mut sent = 0usize;
        let mut target_ids = HashSet::new();
        for subject in subjects {
            if let Some(ids) = self.subjects.get(subject) {
                for id in ids.iter() {
                    target_ids.insert(id.to_string());
                }
            }
        }
        let mut stale_ids = Vec::new();
        for id in target_ids {
            if let Some(handle) = self.connections.get(id.as_str()) {
                if handle.sender.send(OutboundMessage::Text(message.clone())).is_ok() {
                    sent += 1;
                } else {
                    stale_ids.push(id);
                }
            } else {
                stale_ids.push(id);
            }
        }
        for stale_id in stale_ids {
            let _ = self.unregister_connection(&stale_id);
        }
        sent
    }
}
