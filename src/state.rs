use dashmap::{DashMap, DashSet};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Clone, Debug)]
pub enum OutboundMessage {
    Text(String),
}

#[derive(Clone, Debug, Serialize)]
pub struct ConnectionInfo {
    pub connection_id: String,
    pub user_id: String,
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
        subjects: Vec<String>,
        connected_at: i64,
    ) -> (ConnectionInfo, mpsc::UnboundedReceiver<OutboundMessage>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let info = ConnectionInfo {
            connection_id: connection_id.clone(),
            user_id,
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
        (info, rx)
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
        let mut target_ids = DashSet::new();
        for subject in subjects {
            if let Some(ids) = self.subjects.get(subject) {
                for id in ids.iter() {
                    target_ids.insert(id.to_string());
                }
            }
        }
        for id in target_ids.iter() {
            if let Some(handle) = self.connections.get(id.as_str()) {
                if handle.sender.send(OutboundMessage::Text(message.clone())).is_ok() {
                    sent += 1;
                }
            }
        }
        sent
    }
}
