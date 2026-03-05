use dashmap::{DashMap, DashSet};
use serde::Serialize;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

#[derive(Clone, Debug)]
pub enum OutboundMessage {
    Text(String),
}

#[derive(Clone, Debug)]
struct PendingMessage {
    text: String,
    enqueued_at: i64,
    sticky_key: Option<String>,
}

const PENDING_MAX_PER_SUBJECT: usize = 256;
const PENDING_TTL_SECONDS: i64 = 30;

#[derive(Clone, Debug, Serialize)]
pub struct ConnectionInfo {
    pub connection_id: String,
    pub user_id: String,
    pub client_instance_id: String,
    pub subjects: Vec<String>,
    pub connected_at: i64,
    pub last_seen_at: i64,
}

#[derive(Clone)]
struct ConnectionHandle {
    info: ConnectionInfo,
    sender: mpsc::UnboundedSender<OutboundMessage>,
}

#[derive(Clone)]
pub struct GatewayState {
    connections: Arc<DashMap<String, ConnectionHandle>>,
    subjects: Arc<DashMap<String, DashSet<String>>>,
    pending_by_subject: Arc<DashMap<String, VecDeque<PendingMessage>>>,
    max_connections_per_user: Option<usize>,
}

impl Default for GatewayState {
    fn default() -> Self {
        Self::new(None)
    }
}

impl GatewayState {
    pub fn new(max_connections_per_user: Option<usize>) -> Self {
        Self {
            connections: Arc::new(DashMap::new()),
            subjects: Arc::new(DashMap::new()),
            pending_by_subject: Arc::new(DashMap::new()),
            max_connections_per_user,
        }
    }

    fn now_unix_seconds() -> i64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs() as i64,
            Err(_) => 0,
        }
    }

    fn prune_pending_queue(queue: &mut VecDeque<PendingMessage>, now_ts: i64) {
        while let Some(front) = queue.front() {
            if now_ts.saturating_sub(front.enqueued_at) > PENDING_TTL_SECONDS {
                queue.pop_front();
            } else {
                break;
            }
        }
        while queue.len() > PENDING_MAX_PER_SUBJECT {
            queue.pop_front();
        }
    }

    fn snapshot_pending_for_subjects(&self, subjects: &[String]) -> Vec<String> {
        let mut snapshot = Vec::new();
        let mut seen = HashSet::new();
        let now_ts = Self::now_unix_seconds();
        let mut empty_subjects = Vec::new();
        for subject in subjects {
            if let Some(mut queue) = self.pending_by_subject.get_mut(subject) {
                Self::prune_pending_queue(&mut queue, now_ts);
                for item in queue.iter() {
                    if seen.insert(item.text.clone()) {
                        snapshot.push(item.text.clone());
                    }
                }
                if queue.is_empty() {
                    empty_subjects.push(subject.clone());
                }
            }
        }
        for subject in empty_subjects {
            self.pending_by_subject.remove(&subject);
        }
        snapshot
    }

    pub fn requeue_for_subjects(&self, subjects: &[String], message: String) {
        if subjects.is_empty() || message.is_empty() {
            return;
        }
        let now_ts = Self::now_unix_seconds();
        for subject in subjects {
            let mut queue = self
                .pending_by_subject
                .entry(subject.clone())
                .or_insert_with(VecDeque::new);
            queue.push_back(PendingMessage {
                text: message.clone(),
                enqueued_at: now_ts,
                sticky_key: None,
            });
            Self::prune_pending_queue(&mut queue, now_ts);
        }
    }

    pub fn buffer_latest_for_subjects(&self, subjects: &[String], message: String, sticky_key: &str) {
        if subjects.is_empty() || message.is_empty() || sticky_key.is_empty() {
            return;
        }
        let now_ts = Self::now_unix_seconds();
        let sticky_key_owned = sticky_key.to_string();
        for subject in subjects {
            let mut queue = self
                .pending_by_subject
                .entry(subject.clone())
                .or_insert_with(VecDeque::new);
            queue.retain(|item| item.sticky_key.as_deref() != Some(sticky_key));
            queue.push_back(PendingMessage {
                text: message.clone(),
                enqueued_at: now_ts,
                sticky_key: Some(sticky_key_owned.clone()),
            });
            Self::prune_pending_queue(&mut queue, now_ts);
        }
    }

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
        // Keep one active connection per browser client instance.
        // A reconnect from the same tab/window should evict stale predecessors.
        let mut evicted = Vec::new();
        if !client_instance_id.is_empty() {
            let same_instance_connections: Vec<String> = self
                .connections
                .iter()
                .filter_map(|entry| {
                    let existing = &entry.value().info;
                    if existing.user_id == user_id
                        && existing.client_instance_id == client_instance_id
                        && entry.key().as_str() != connection_id
                    {
                        Some(entry.key().clone())
                    } else {
                        None
                    }
                })
                .collect();
            for stale_id in same_instance_connections {
                if let Some(info) = self.unregister_connection(&stale_id) {
                    evicted.push(info);
                }
            }
        }

        // Optional per-user cap on top (0/None => unlimited).
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
        // Optional cap per user; 0/None means unlimited.
        if let Some(max_connections_per_user) = self.max_connections_per_user {
            if same_user_connections.len() >= max_connections_per_user {
                let overflow =
                    (same_user_connections.len() + 1).saturating_sub(max_connections_per_user);
                for (stale_id, _) in same_user_connections.into_iter().take(overflow) {
                    if stale_id != connection_id {
                        if let Some(info) = self.unregister_connection(&stale_id) {
                            evicted.push(info);
                        }
                    }
                }
            }
        }

        let (tx, rx) = mpsc::unbounded_channel();
        let sender = tx.clone();
        let info = ConnectionInfo {
            connection_id: connection_id.clone(),
            user_id,
            client_instance_id,
            subjects: subjects.clone(),
            connected_at,
            last_seen_at: connected_at,
        };
        self.connections.insert(
            connection_id.clone(),
            ConnectionHandle {
                info: info.clone(),
                sender,
            },
        );
        for subject in subjects {
            let entry = self.subjects.entry(subject).or_insert_with(DashSet::new);
            entry.insert(connection_id.clone());
        }
        for text in self.snapshot_pending_for_subjects(&info.subjects) {
            let _ = tx.send(OutboundMessage::Text(text));
        }
        (info, rx, evicted)
    }

    pub fn unregister_connection(&self, connection_id: &str) -> Option<ConnectionInfo> {
        let handle = self.connections.remove(connection_id).map(|(_, handle)| handle);
        if let Some(handle) = handle {
            for subject in &handle.info.subjects {
                if let Some(entry) = self.subjects.get_mut(subject) {
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

    pub fn send_to_subjects(
        &self,
        subjects: &[String],
        message: String,
        buffer_if_undelivered: bool,
        sticky_key: Option<&str>,
    ) -> usize {
        if subjects.is_empty() || message.is_empty() {
            return 0;
        }

        if let Some(key) = sticky_key {
            self.buffer_latest_for_subjects(subjects, message.clone(), key);
        }

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

        if sent == 0 && buffer_if_undelivered {
            self.requeue_for_subjects(subjects, message);
        }

        sent
    }

    pub fn mark_connection_alive(&self, connection_id: &str, timestamp: i64) {
        if let Some(mut handle) = self.connections.get_mut(connection_id) {
            handle.info.last_seen_at = timestamp;
        }
    }

    pub fn prune_stale_connections(
        &self,
        now_ts: i64,
        stale_after_seconds: i64,
    ) -> Vec<ConnectionInfo> {
        if stale_after_seconds <= 0 {
            return Vec::new();
        }
        let stale_ids: Vec<String> = self
            .connections
            .iter()
            .filter_map(|entry| {
                let last_seen = entry.value().info.last_seen_at;
                if now_ts.saturating_sub(last_seen) > stale_after_seconds {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();

        let mut evicted = Vec::new();
        for stale_id in stale_ids {
            if let Some(info) = self.unregister_connection(&stale_id) {
                evicted.push(info);
            }
        }
        evicted
    }
}
