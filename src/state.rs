use dashmap::{DashMap, DashSet};
use serde::Serialize;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

use crate::routes::{AudienceScopeMode, RelayAuthorizationSpec, RelayContextType};

#[derive(Clone, Debug)]
pub enum OutboundMessage {
    Text(String),
    Close { code: u16, reason: String },
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct DispatchResult {
    pub attempted_count: usize,
    pub enqueued_count: usize,
}

#[derive(Clone, Debug)]
struct PendingMessage {
    text: String,
    enqueued_at: i64,
    sticky_key: Option<String>,
}

#[derive(Clone, Debug)]
struct RequestRoute {
    connection_id: String,
    user_id: String,
    updated_at: i64,
}

const PENDING_MAX_PER_SUBJECT: usize = 256;
const PENDING_TTL_SECONDS: i64 = 30;
const REQUEST_ROUTE_TTL_SECONDS: i64 = 120;
const REQUEST_ROUTE_MAX: usize = 8_192;
const RELAY_CONTEXT_TTL_SECONDS: i64 = 24 * 60 * 60;
const RELAY_REPLAY_TTL_SECONDS: i64 = 10 * 60;
const RELAY_REPLAY_CACHE_MAX: usize = 200_000;
const RELAY_RATE_WINDOW_SECONDS: i64 = 1;
const RELAY_RATE_LIMIT_DEFAULT: u32 = 240;
const RELAY_CHUNK_CIPHERTEXT_MAX_BYTES: usize = 2_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayContextState {
    Opened,
    Active,
    Revoked,
    Closed,
    PolicyVersionBumped,
}

impl RelayContextState {
    pub fn is_relay_permitted(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RelayGrant {
    pub grant_id: String,
    pub policy_version: u64,
    pub issued_at: i64,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct RelayAudienceScope {
    pub mode: AudienceScopeMode,
    pub peers: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RelayOperationContext {
    pub context_id: String,
    pub operation_key: String,
    pub operation_class: String,
    pub context_type: RelayContextType,
    pub state: RelayContextState,
    pub authorized_subject: String,
    pub audience_scope: RelayAudienceScope,
    pub allowed_command_families: Vec<String>,
    pub policy_version: u64,
    pub grant: RelayGrant,
    pub opened_at: i64,
    pub updated_at: i64,
    pub expires_at: i64,
}

#[derive(Clone, Debug)]
pub struct RelayContextSnapshot {
    pub subject_email: String,
    pub context_type: RelayContextType,
    pub policy_version: u64,
    pub contexts: Vec<RelayOperationContext>,
    pub received_at: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct RelaySubjectContexts {
    pub context_type: RelayContextType,
    pub policy_version: u64,
    pub updated_at: i64,
    pub contexts: Vec<RelayOperationContext>,
}

#[derive(Clone, Debug)]
pub struct RelayAuthDecision {
    pub context_id: String,
    pub policy_version: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayAuthError {
    MissingContext,
    SenderBindingInvalid,
    ScopeViolation,
    ContextStateInvalid(RelayContextState),
    GrantExpired,
    GrantInvalid,
    PolicyVersionMismatch,
    ReplayDetected,
    RateLimited,
    PayloadTooLarge,
}

impl RelayAuthError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingContext => "relay_context_missing",
            Self::SenderBindingInvalid => "relay_sender_binding_invalid",
            Self::ScopeViolation => "relay_scope_violation",
            Self::ContextStateInvalid(RelayContextState::Revoked) => "relay_context_revoked",
            Self::ContextStateInvalid(RelayContextState::Closed) => "relay_context_closed",
            Self::ContextStateInvalid(RelayContextState::PolicyVersionBumped) => {
                "relay_context_policy_version_bumped"
            }
            Self::ContextStateInvalid(RelayContextState::Opened) => "relay_context_not_active",
            Self::ContextStateInvalid(RelayContextState::Active) => "relay_context_invalid_state",
            Self::GrantExpired => "relay_grant_expired",
            Self::GrantInvalid => "relay_grant_invalid",
            Self::PolicyVersionMismatch => "relay_policy_version_mismatch",
            Self::ReplayDetected => "relay_replay_detected",
            Self::RateLimited => "relay_rate_limited",
            Self::PayloadTooLarge => "relay_payload_too_large",
        }
    }
}

#[derive(Clone, Debug)]
struct RelayReplayEntry {
    seen_at: i64,
}

#[derive(Clone, Copy, Debug)]
struct RelayRateCounter {
    window_start: i64,
    count: u32,
}

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
    request_routes: Arc<DashMap<String, RequestRoute>>,
    relay_contexts_by_subject: Arc<DashMap<String, RelaySubjectContexts>>,
    relay_replay_cache: Arc<DashMap<String, RelayReplayEntry>>,
    relay_rate_counters: Arc<DashMap<String, RelayRateCounter>>,
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
            request_routes: Arc::new(DashMap::new()),
            relay_contexts_by_subject: Arc::new(DashMap::new()),
            relay_replay_cache: Arc::new(DashMap::new()),
            relay_rate_counters: Arc::new(DashMap::new()),
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


    fn prune_request_routes(&self, now_ts: i64) {
        if self.request_routes.len() <= REQUEST_ROUTE_MAX {
            return;
        }

        let mut stale_keys = Vec::new();
        for entry in self.request_routes.iter() {
            let route = entry.value();
            if now_ts.saturating_sub(route.updated_at) > REQUEST_ROUTE_TTL_SECONDS
                || !self.connections.contains_key(route.connection_id.as_str())
            {
                stale_keys.push(entry.key().clone());
            }
        }

        for key in stale_keys {
            self.request_routes.remove(key.as_str());
        }
    }

    fn sanitize_email(value: &str) -> Option<String> {
        let normalized = value.trim().to_lowercase();
        if normalized.is_empty() {
            return None;
        }
        Some(normalized)
    }

    fn sanitize_allowed_families(values: &[String]) -> Vec<String> {
        let mut result = Vec::new();
        for value in values {
            let normalized = value.trim().to_lowercase();
            if normalized.is_empty() {
                continue;
            }
            if !result.iter().any(|item| item == &normalized) {
                result.push(normalized);
            }
        }
        result
    }

    fn sanitize_scope_peers(values: &[String]) -> Vec<String> {
        let mut result = Vec::new();
        for value in values {
            if let Some(normalized) = Self::sanitize_email(value) {
                if !result.iter().any(|item| item == &normalized) {
                    result.push(normalized);
                }
            }
        }
        result
    }

    fn prune_relay_replay_cache(&self, now_ts: i64) {
        if self.relay_replay_cache.len() <= RELAY_REPLAY_CACHE_MAX {
            return;
        }

        let mut stale_keys = Vec::new();
        for entry in self.relay_replay_cache.iter() {
            let seen_at = entry.value().seen_at;
            if now_ts.saturating_sub(seen_at) > RELAY_REPLAY_TTL_SECONDS {
                stale_keys.push(entry.key().clone());
            }
        }

        for key in stale_keys {
            self.relay_replay_cache.remove(key.as_str());
        }
    }

    fn ensure_relay_replay_fresh(&self, replay_key: &str, now_ts: i64) -> Result<(), RelayAuthError> {
        if replay_key.trim().is_empty() {
            return Ok(());
        }

        if let Some(existing) = self.relay_replay_cache.get(replay_key) {
            if now_ts.saturating_sub(existing.seen_at) <= RELAY_REPLAY_TTL_SECONDS {
                return Err(RelayAuthError::ReplayDetected);
            }
        }

        self.relay_replay_cache.insert(
            replay_key.to_string(),
            RelayReplayEntry { seen_at: now_ts },
        );
        self.prune_relay_replay_cache(now_ts);
        Ok(())
    }

    fn ensure_relay_rate_limit(
        &self,
        sender_email: &str,
        command_name: &str,
        context_id: &str,
        now_ts: i64,
    ) -> Result<(), RelayAuthError> {
        let window = now_ts / RELAY_RATE_WINDOW_SECONDS.max(1);
        let key = format!(
            "{}|{}|{}|{}",
            sender_email.trim().to_lowercase(),
            command_name.trim().to_lowercase(),
            context_id.trim().to_lowercase(),
            window
        );
        let mut counter = self
            .relay_rate_counters
            .entry(key)
            .or_insert(RelayRateCounter {
                window_start: window,
                count: 0,
            });
        if counter.window_start != window {
            counter.window_start = window;
            counter.count = 0;
        }
        if counter.count >= RELAY_RATE_LIMIT_DEFAULT {
            return Err(RelayAuthError::RateLimited);
        }
        counter.count = counter.count.saturating_add(1);
        Ok(())
    }

    fn take_pending_for_subjects(&self, subjects: &[String]) -> Vec<String> {
        let mut snapshot = Vec::new();
        let mut seen = HashSet::new();
        let now_ts = Self::now_unix_seconds();
        for subject in subjects {
            if let Some((_, mut queue)) = self.pending_by_subject.remove(subject) {
                Self::prune_pending_queue(&mut queue, now_ts);
                while let Some(item) = queue.pop_front() {
                    if seen.insert(item.text.clone()) {
                        snapshot.push(item.text);
                    }
                }
                // Pending messages are one-shot reconnect replay, not sticky snapshots.
            }
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


    pub fn bind_request_route(&self, request_id: &str, connection_id: &str, user_id: &str) {
        let request_id = request_id.trim();
        if request_id.is_empty() || connection_id.is_empty() || user_id.is_empty() {
            return;
        }

        let now_ts = Self::now_unix_seconds();
        self.request_routes.insert(
            request_id.to_string(),
            RequestRoute {
                connection_id: connection_id.to_string(),
                user_id: user_id.to_string(),
                updated_at: now_ts,
            },
        );
        self.prune_request_routes(now_ts);
    }

    pub fn clear_request_route(&self, request_id: &str) {
        let request_id = request_id.trim();
        if request_id.is_empty() {
            return;
        }
        self.request_routes.remove(request_id);
    }

    pub fn resolve_request_route(&self, request_id: &str, subjects: &[String]) -> Option<String> {
        let request_id = request_id.trim();
        if request_id.is_empty() {
            return None;
        }

        let now_ts = Self::now_unix_seconds();
        let route = self.request_routes.get(request_id)?;
        if now_ts.saturating_sub(route.updated_at) > REQUEST_ROUTE_TTL_SECONDS {
            drop(route);
            self.request_routes.remove(request_id);
            return None;
        }

        let connection_id = route.connection_id.clone();
        let user_id = route.user_id.clone();
        drop(route);

        let handle = match self.connections.get(connection_id.as_str()) {
            Some(handle) => handle,
            None => {
                self.request_routes.remove(request_id);
                return None;
            }
        };

        if handle.info.user_id != user_id {
            self.request_routes.remove(request_id);
            return None;
        }

        if !subjects.is_empty() {
            let matches_subject = subjects
                .iter()
                .any(|subject| handle.info.subjects.iter().any(|item| item == subject));
            if !matches_subject {
                return None;
            }
        }

        Some(connection_id)
    }

    pub fn apply_relay_context_snapshot(&self, snapshot: RelayContextSnapshot) {
        let Some(subject_email) = Self::sanitize_email(snapshot.subject_email.as_str()) else {
            return;
        };

        let now_ts = Self::now_unix_seconds();
        let mut incoming_contexts = Vec::new();
        for context in snapshot.contexts {
            let Some(authorized_subject) =
                Self::sanitize_email(context.authorized_subject.as_str())
            else {
                continue;
            };
            if authorized_subject != subject_email {
                continue;
            }
            if context.context_type != snapshot.context_type {
                continue;
            }

            let allowed_families = Self::sanitize_allowed_families(&context.allowed_command_families);
            if allowed_families.is_empty() {
                continue;
            }
            let peers = Self::sanitize_scope_peers(&context.audience_scope.peers);
            if peers.is_empty() {
                continue;
            }
            let context_id = context.context_id.trim().to_string();
            if context_id.is_empty() {
                continue;
            }
            let operation_key = context.operation_key.trim().to_string();
            if operation_key.is_empty() {
                continue;
            }

            let expires_at = if context.expires_at > 0 {
                context.expires_at
            } else {
                now_ts.saturating_add(RELAY_CONTEXT_TTL_SECONDS)
            };
            let grant_expires_at = if context.grant.expires_at > 0 {
                context.grant.expires_at
            } else {
                expires_at
            };

            incoming_contexts.push(RelayOperationContext {
                context_id,
                operation_key,
                operation_class: context.operation_class.trim().to_string(),
                context_type: context.context_type,
                state: context.state,
                authorized_subject,
                audience_scope: RelayAudienceScope {
                    mode: context.audience_scope.mode,
                    peers,
                },
                allowed_command_families: allowed_families,
                policy_version: context.policy_version,
                grant: RelayGrant {
                    grant_id: context.grant.grant_id.trim().to_string(),
                    policy_version: context.grant.policy_version,
                    issued_at: context.grant.issued_at,
                    expires_at: grant_expires_at,
                },
                opened_at: context.opened_at,
                updated_at: context.updated_at,
                expires_at,
            });
        }

        let existing = self
            .relay_contexts_by_subject
            .get(subject_email.as_str())
            .map(|entry| entry.value().clone());

        let mut next_contexts = Vec::new();
        let mut next_policy_version = snapshot.policy_version;
        if let Some(existing) = existing {
            if existing.context_type == snapshot.context_type
                && snapshot.policy_version < existing.policy_version
            {
                return;
            }

            if existing.context_type == snapshot.context_type {
                next_policy_version = next_policy_version.max(existing.policy_version);
                for context in existing.contexts {
                    if now_ts > context.expires_at {
                        continue;
                    }
                    next_contexts.push(context);
                }
            }
        }

        for incoming in incoming_contexts {
            next_contexts.retain(|existing| existing.operation_key != incoming.operation_key);
            next_contexts.push(incoming);
        }

        next_contexts.sort_by(|left, right| {
            left.updated_at
                .cmp(&right.updated_at)
                .then_with(|| left.operation_key.cmp(&right.operation_key))
        });

        self.relay_contexts_by_subject.insert(
            subject_email,
            RelaySubjectContexts {
                context_type: snapshot.context_type,
                policy_version: next_policy_version,
                updated_at: snapshot.received_at,
                contexts: next_contexts,
            },
        );
    }

    pub fn list_relay_contexts_for_subject(&self, subject_email: &str) -> Option<RelaySubjectContexts> {
        let normalized = Self::sanitize_email(subject_email)?;
        self.relay_contexts_by_subject
            .get(normalized.as_str())
            .map(|entry| entry.value().clone())
    }

    pub fn authorize_relay_hotpath(
        &self,
        sender_email: &str,
        command_name: &str,
        auth_spec: RelayAuthorizationSpec,
        operation_key: &str,
        target_emails: &[String],
        replay_nonce: Option<&str>,
        payload_size_hint: Option<usize>,
        now_ts: i64,
    ) -> Result<RelayAuthDecision, RelayAuthError> {
        let Some(sender_normalized) = Self::sanitize_email(sender_email) else {
            return Err(RelayAuthError::SenderBindingInvalid);
        };
        let operation_key = operation_key.trim();
        if operation_key.is_empty() {
            return Err(RelayAuthError::MissingContext);
        }
        if target_emails.is_empty() {
            return Err(RelayAuthError::ScopeViolation);
        }
        if let Some(size) = payload_size_hint {
            if size > RELAY_CHUNK_CIPHERTEXT_MAX_BYTES {
                return Err(RelayAuthError::PayloadTooLarge);
            }
        }

        let Some(subject_contexts) = self.relay_contexts_by_subject.get(sender_normalized.as_str()) else {
            return Err(RelayAuthError::MissingContext);
        };
        if subject_contexts.context_type != auth_spec.relay_context_type {
            return Err(RelayAuthError::MissingContext);
        }

        let command_family = auth_spec.command_family.trim().to_lowercase();
        for context in &subject_contexts.contexts {
            if context.context_type != auth_spec.relay_context_type {
                continue;
            }
            if context.operation_key != operation_key {
                continue;
            }
            if !context
                .allowed_command_families
                .iter()
                .any(|family| family == &command_family)
            {
                continue;
            }
            if context.authorized_subject != sender_normalized {
                continue;
            }
            if context.grant.grant_id.trim().is_empty() {
                return Err(RelayAuthError::GrantInvalid);
            }
            if context.policy_version == 0
                || context.grant.policy_version == 0
                || context.policy_version != context.grant.policy_version
            {
                return Err(RelayAuthError::PolicyVersionMismatch);
            }
            if now_ts > context.expires_at || now_ts > context.grant.expires_at {
                return Err(RelayAuthError::GrantExpired);
            }
            if context.audience_scope.mode != auth_spec.audience_scope_mode {
                continue;
            }

            let scope_peers = &context.audience_scope.peers;
            let target_in_scope = target_emails.iter().all(|target| {
                let normalized = target.trim().to_lowercase();
                scope_peers.iter().any(|peer| peer == &normalized)
            });
            if !target_in_scope {
                continue;
            }

            if !context.state.is_relay_permitted() {
                return Err(RelayAuthError::ContextStateInvalid(context.state));
            }

            if let Some(nonce) = replay_nonce {
                let nonce_trimmed = nonce.trim();
                if !nonce_trimmed.is_empty() {
                    let replay_key = format!(
                        "{}|{}|{}|{}",
                        sender_normalized, command_name, context.context_id, nonce_trimmed
                    );
                    self.ensure_relay_replay_fresh(replay_key.as_str(), now_ts)?;
                }
            }

            self.ensure_relay_rate_limit(
                sender_normalized.as_str(),
                command_name,
                context.context_id.as_str(),
                now_ts,
            )?;
            return Ok(RelayAuthDecision {
                context_id: context.context_id.clone(),
                policy_version: context.policy_version,
            });
        }

        Err(RelayAuthError::ScopeViolation)
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
                if let Some(info) = self.evict_connection(&stale_id, Some((1000, "reconnect"))) {
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
                        if let Some(info) = self.evict_connection(&stale_id, Some((4409, "session_replaced"))) {
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
        for text in self.take_pending_for_subjects(&info.subjects) {
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

            let mut stale_request_ids = Vec::new();
            for entry in self.request_routes.iter() {
                if entry.value().connection_id == connection_id {
                    stale_request_ids.push(entry.key().clone());
                }
            }
            for request_id in stale_request_ids {
                self.request_routes.remove(request_id.as_str());
            }

            return Some(handle.info);
        }
        None
    }

    fn evict_connection(&self, connection_id: &str, close: Option<(u16, &str)>) -> Option<ConnectionInfo> {
        if let Some((code, reason)) = close {
            if let Some(handle) = self.connections.get(connection_id) {
                let _ = handle.sender.send(OutboundMessage::Close {
                    code,
                    reason: reason.to_string(),
                });
            }
        }
        self.unregister_connection(connection_id)
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
    ) -> DispatchResult {
        if subjects.is_empty() || message.is_empty() {
            return DispatchResult::default();
        }

        if let Some(key) = sticky_key {
            self.buffer_latest_for_subjects(subjects, message.clone(), key);
        }

        let mut enqueued = 0usize;
        let mut target_ids = HashSet::new();
        for subject in subjects {
            if let Some(ids) = self.subjects.get(subject) {
                for id in ids.iter() {
                    target_ids.insert(id.to_string());
                }
            }
        }
        let attempted = target_ids.len();

        let mut stale_ids = Vec::new();
        for id in target_ids {
            if let Some(handle) = self.connections.get(id.as_str()) {
                if handle.sender.send(OutboundMessage::Text(message.clone())).is_ok() {
                    enqueued += 1;
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

        if enqueued == 0 && buffer_if_undelivered {
            self.requeue_for_subjects(subjects, message);
        }

        DispatchResult {
            attempted_count: attempted,
            enqueued_count: enqueued,
        }
    }



    pub fn send_to_connection(&self, connection_id: &str, message: String) -> bool {
        if connection_id.is_empty() || message.is_empty() {
            return false;
        }

        if let Some(handle) = self.connections.get(connection_id) {
            if handle.sender.send(OutboundMessage::Text(message)).is_ok() {
                return true;
            }
        }

        let _ = self.unregister_connection(connection_id);
        false
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_context(
        subject: &str,
        peer: &str,
        operation_key: &str,
        state: RelayContextState,
        policy_version: u64,
    ) -> RelayOperationContext {
        let now = GatewayState::now_unix_seconds();
        RelayOperationContext {
            context_id: format!("opx-{operation_key}-{}", policy_version),
            operation_key: operation_key.to_string(),
            operation_class: "relay_hotpath".to_string(),
            context_type: RelayContextType::FileTransferPeer,
            state,
            authorized_subject: subject.to_string(),
            audience_scope: RelayAudienceScope {
                mode: AudienceScopeMode::FixedPeer,
                peers: vec![peer.to_string()],
            },
            allowed_command_families: vec!["file_transfer".to_string()],
            policy_version,
            grant: RelayGrant {
                grant_id: format!("grant-{subject}-{peer}"),
                policy_version,
                issued_at: now,
                expires_at: now + 3600,
            },
            opened_at: now,
            updated_at: now,
            expires_at: now + 3600,
        }
    }

    #[test]
    fn relay_context_snapshot_ignores_stale_policy_version() {
        let state = GatewayState::new(None);
        state.apply_relay_context_snapshot(RelayContextSnapshot {
            subject_email: "alice@test.de".to_string(),
            context_type: RelayContextType::FileTransferPeer,
            policy_version: 3,
            received_at: 100,
            contexts: vec![sample_context(
                "alice@test.de",
                "bob@test.de",
                "ft-1",
                RelayContextState::Active,
                3,
            )],
        });
        state.apply_relay_context_snapshot(RelayContextSnapshot {
            subject_email: "alice@test.de".to_string(),
            context_type: RelayContextType::FileTransferPeer,
            policy_version: 2,
            received_at: 101,
            contexts: vec![sample_context(
                "alice@test.de",
                "charlie@test.de",
                "ft-2",
                RelayContextState::Active,
                2,
            )],
        });

        let snapshot = state
            .list_relay_contexts_for_subject("alice@test.de")
            .expect("snapshot");
        assert_eq!(snapshot.policy_version, 3);
        assert_eq!(snapshot.contexts.len(), 1);
        assert_eq!(snapshot.contexts[0].audience_scope.peers, vec!["bob@test.de"]);
    }

    #[test]
    fn relay_context_snapshot_merges_operation_updates() {
        let state = GatewayState::new(None);
        state.apply_relay_context_snapshot(RelayContextSnapshot {
            subject_email: "alice@test.de".to_string(),
            context_type: RelayContextType::FileTransferPeer,
            policy_version: 11,
            received_at: 110,
            contexts: vec![sample_context(
                "alice@test.de",
                "bob@test.de",
                "ft-1",
                RelayContextState::Active,
                11,
            )],
        });
        state.apply_relay_context_snapshot(RelayContextSnapshot {
            subject_email: "alice@test.de".to_string(),
            context_type: RelayContextType::FileTransferPeer,
            policy_version: 12,
            received_at: 112,
            contexts: vec![sample_context(
                "alice@test.de",
                "charlie@test.de",
                "ft-2",
                RelayContextState::Active,
                12,
            )],
        });

        let snapshot = state
            .list_relay_contexts_for_subject("alice@test.de")
            .expect("snapshot");
        assert_eq!(snapshot.policy_version, 12);
        assert_eq!(snapshot.contexts.len(), 2);
        assert!(snapshot
            .contexts
            .iter()
            .any(|context| context.operation_key == "ft-1"));
        assert!(snapshot
            .contexts
            .iter()
            .any(|context| context.operation_key == "ft-2"));
    }

    #[test]
    fn relay_authorization_rejects_policy_version_mismatch() {
        let state = GatewayState::new(None);
        let mut context = sample_context(
            "alice@test.de",
            "bob@test.de",
            "ft-1",
            RelayContextState::Active,
            4,
        );
        context.grant.policy_version = 3;
        state.apply_relay_context_snapshot(RelayContextSnapshot {
            subject_email: "alice@test.de".to_string(),
            context_type: RelayContextType::FileTransferPeer,
            policy_version: 4,
            received_at: 10,
            contexts: vec![context],
        });

        let auth_spec = RelayAuthorizationSpec {
            requires_relay_context: true,
            relay_context_type: RelayContextType::FileTransferPeer,
            audience_scope_mode: AudienceScopeMode::FixedPeer,
            guard_class: crate::routes::RelayGuardClass::ContextBoundPeer,
            command_family: "file_transfer",
            operation_key_field: "transfer_id",
        };
        let result = state.authorize_relay_hotpath(
            "alice@test.de",
            "file_transfer_offer",
            auth_spec,
            "ft-1",
            &["bob@test.de".to_string()],
            None,
            None,
            11,
        );
        assert_eq!(result.err(), Some(RelayAuthError::PolicyVersionMismatch));
    }
}
