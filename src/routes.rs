use serde::Serialize;
use crate::project::command_registry::{COMMAND_REGISTRY, RELAY_AUTHORIZATION_REGISTRY};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutingClass {
    NoAuth,
    GatewayLocal,
    RelayHotpath,
    BackendControl,
}

impl RoutingClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoAuth => "no_auth",
            Self::GatewayLocal => "gateway_local",
            Self::RelayHotpath => "relay_hotpath",
            Self::BackendControl => "backend_control",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageSemanticType {
    Command,
    Query,
    Event,
    Signal,
    Technical,
}

impl MessageSemanticType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::Query => "query",
            Self::Event => "event",
            Self::Signal => "signal",
            Self::Technical => "technical",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum RelayContextType {
    FileTransferPeer,
}

impl RelayContextType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FileTransferPeer => "file_transfer_peer",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum AudienceScopeMode {
    FixedPeer,
    ContextMembers,
    ExplicitSubset,
}

impl AudienceScopeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FixedPeer => "fixed_peer",
            Self::ContextMembers => "context_members",
            Self::ExplicitSubset => "explicit_subset",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum RelayGuardClass {
    ContextBoundPeer,
}

impl RelayGuardClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContextBoundPeer => "context_bound_peer",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayAuthorizationSpec {
    pub requires_relay_context: bool,
    pub relay_context_type: RelayContextType,
    pub audience_scope_mode: AudienceScopeMode,
    pub guard_class: RelayGuardClass,
    pub command_family: &'static str,
    pub operation_key_field: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayAuthorizationEntry {
    pub command_name: &'static str,
    pub spec: RelayAuthorizationSpec,
}

#[derive(Clone, Copy, Debug)]
pub struct CommandSpec {
    pub command_name: &'static str,
    pub routing_class: RoutingClass,
    pub message_type: MessageSemanticType,
    pub mirror_to_backend: bool,
}

pub fn command_registry() -> &'static [CommandSpec] {
    COMMAND_REGISTRY
}

pub fn resolve_command_spec(command_type: &str) -> Option<&'static CommandSpec> {
    command_registry()
        .iter()
        .find(|spec| spec.command_name == command_type)
}

pub fn resolve_message_type(command_type: &str) -> Option<MessageSemanticType> {
    resolve_command_spec(command_type).map(|spec| spec.message_type)
}

pub fn resolve_relay_authorization_spec(command_type: &str) -> Option<RelayAuthorizationSpec> {
    RELAY_AUTHORIZATION_REGISTRY
        .iter()
        .find(|entry| entry.command_name == command_type)
        .map(|entry| entry.spec)
}

pub fn validate_command_registry() -> Result<(), String> {
    let mut seen = std::collections::HashSet::new();
    for spec in command_registry() {
        if spec.command_name.trim().is_empty() {
            return Err("command registry contains empty command name".to_string());
        }
        if !seen.insert(spec.command_name) {
            return Err(format!(
                "command registry contains duplicate command '{}'",
                spec.command_name
            ));
        }
        if matches!(spec.message_type, MessageSemanticType::Event) {
            return Err(format!(
                "command '{}' uses semantic type 'event' in inbound command registry",
                spec.command_name
            ));
        }

        match spec.routing_class {
            RoutingClass::NoAuth | RoutingClass::GatewayLocal => {
                if !matches!(spec.message_type, MessageSemanticType::Technical) {
                    return Err(format!(
                        "command '{}' with routing class '{}' must use semantic type 'technical'",
                        spec.command_name,
                        spec.routing_class.as_str()
                    ));
                }
                if spec.mirror_to_backend {
                    return Err(format!(
                        "command '{}' with routing class '{}' cannot set backend mirror",
                        spec.command_name,
                        spec.routing_class.as_str()
                    ));
                }
            }
            RoutingClass::RelayHotpath => {
                if matches!(spec.message_type, MessageSemanticType::Technical) {
                    return Err(format!(
                        "relay command '{}' cannot use semantic type 'technical'",
                        spec.command_name
                    ));
                }
            }
            RoutingClass::BackendControl => {
                if matches!(spec.message_type, MessageSemanticType::Technical) {
                    return Err(format!(
                        "backend control command '{}' cannot use semantic type 'technical'",
                        spec.command_name
                    ));
                }
                if spec.mirror_to_backend {
                    return Err(format!(
                        "backend control command '{}' cannot set backend mirror",
                        spec.command_name
                    ));
                }
            }
        }
    }

    let relay_commands: Vec<&str> = command_registry()
        .iter()
        .filter(|spec| matches!(spec.routing_class, RoutingClass::RelayHotpath))
        .map(|spec| spec.command_name)
        .collect();
    for command in relay_commands {
        let Some(auth_spec) = resolve_relay_authorization_spec(command) else {
            return Err(format!(
                "relay command '{}' is missing relay authorization metadata",
                command
            ));
        };
        if auth_spec.command_family.trim().is_empty() {
            return Err(format!(
                "relay command '{}' has empty relay command family",
                command
            ));
        }
        if auth_spec.operation_key_field.trim().is_empty() {
            return Err(format!(
                "relay command '{}' has empty relay operation key field",
                command
            ));
        }
    }

    for spec in command_registry()
        .iter()
        .filter(|spec| !matches!(spec.routing_class, RoutingClass::RelayHotpath))
    {
        if resolve_relay_authorization_spec(spec.command_name).is_some() {
            return Err(format!(
                "non-relay command '{}' declares relay authorization metadata",
                spec.command_name
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::registry_contract_config::{
        BACKEND_HANDLER_MAP_PATH, FRONTEND_EMITTER_TYPE_FILES, FRONTEND_IGNORED_TYPE_LITERALS,
    };
    use std::collections::HashSet;
    use std::fs;
    use std::path::PathBuf;

    fn registry_names() -> HashSet<&'static str> {
        command_registry().iter().map(|spec| spec.command_name).collect()
    }

    fn project_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("gateway crate must be nested under project root")
            .to_path_buf()
    }

    fn extract_single_quoted_literals(line: &str) -> Vec<String> {
        let mut values = Vec::new();
        let mut rest = line;
        while let Some(start) = rest.find('\'') {
            let after_start = &rest[start + 1..];
            if let Some(end) = after_start.find('\'') {
                values.push(after_start[..end].to_string());
                rest = &after_start[end + 1..];
            } else {
                break;
            }
        }
        values
    }

    fn parse_backend_handler_types(path: &PathBuf) -> HashSet<String> {
        let content = fs::read_to_string(path).expect("failed to read backend handler map");
        content
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if !trimmed.contains("=>") || !trimmed.starts_with('\'') {
                    return None;
                }
                let mut literals = extract_single_quoted_literals(trimmed);
                let first = literals.drain(..1).next();
                first
            })
            .collect()
    }

    fn parse_frontend_type_literals(path: &PathBuf) -> HashSet<String> {
        let content = fs::read_to_string(path).unwrap_or_default();
        let mut values = HashSet::new();
        for line in content.lines() {
            if !line.contains("type:") && !line.contains("\"type\"") {
                continue;
            }
            for literal in extract_single_quoted_literals(line) {
                values.insert(literal);
            }
        }
        values
    }

    #[test]
    fn registry_is_valid() {
        assert!(validate_command_registry().is_ok());
    }

    #[test]
    fn backend_control_commands_have_backend_handlers() {
        let root = project_root();
        let backend_map = root.join(BACKEND_HANDLER_MAP_PATH);
        let backend_types = parse_backend_handler_types(&backend_map);

        for spec in command_registry() {
            if spec.routing_class != RoutingClass::BackendControl {
                continue;
            }
            assert!(
                backend_types.contains(spec.command_name),
                "backend_control command '{}' has no backend handler registration",
                spec.command_name
            );
        }
    }

    #[test]
    fn selected_frontend_emitter_types_are_registered_or_explicitly_ignored() {
        let root = project_root();
        let registry = registry_names();
        let ignored_literals: HashSet<&str> =
            FRONTEND_IGNORED_TYPE_LITERALS.iter().copied().collect();

        let mut unknown = Vec::new();
        for rel in FRONTEND_EMITTER_TYPE_FILES {
            let path = root.join(rel);
            for literal in parse_frontend_type_literals(&path) {
                let looks_like_command =
                    literal == "auth" || literal == "ping" || literal.contains('_');
                if !looks_like_command || ignored_literals.contains(literal.as_str()) {
                    continue;
                }
                if !registry.contains(literal.as_str()) {
                    unknown.push(format!("{rel}:{literal}"));
                }
            }
        }

        assert!(
            unknown.is_empty(),
            "frontend emits type literals not present in command registry: {unknown:?}"
        );
    }

    #[test]
    fn critical_commands_have_expected_routing_classes() {
        let cases = [
            ("auth_login_request", RoutingClass::NoAuth),
            ("ping", RoutingClass::GatewayLocal),
            ("chat_message_send", RoutingClass::BackendControl),
            ("chat_typing_state", RoutingClass::BackendControl),
            ("presence_state", RoutingClass::BackendControl),
            ("file_transfer_offer", RoutingClass::RelayHotpath),
            ("file_transfer_chunk", RoutingClass::RelayHotpath),
            ("file_transfer_complete", RoutingClass::RelayHotpath),
            ("group_membership_accept", RoutingClass::BackendControl),
        ];
        for (command, expected_class) in cases {
            let spec = resolve_command_spec(command).expect("command must exist");
            assert_eq!(
                spec.routing_class, expected_class,
                "critical command '{}' has unexpected routing class",
                command
            );
        }
    }

    #[test]
    fn critical_commands_have_expected_semantic_types() {
        let cases = [
            ("auth_login_request", MessageSemanticType::Technical),
            ("ping", MessageSemanticType::Technical),
            ("chat_message_send", MessageSemanticType::Command),
            ("chat_typing_state", MessageSemanticType::Signal),
            ("presence_state", MessageSemanticType::Signal),
            ("contacts_request", MessageSemanticType::Query),
            ("file_transfer_offer", MessageSemanticType::Command),
            ("file_transfer_chunk", MessageSemanticType::Command),
            ("file_transfer_complete", MessageSemanticType::Command),
            ("call_session_token_request", MessageSemanticType::Query),
            ("call_session_media_key", MessageSemanticType::Signal),
        ];
        for (command, expected_type) in cases {
            let spec = resolve_command_spec(command).expect("command must exist");
            assert_eq!(
                spec.message_type, expected_type,
                "critical command '{}' has unexpected semantic type",
                command
            );
        }
    }

    #[test]
    fn relay_hotpath_commands_require_relay_authorization_metadata() {
        for spec in command_registry() {
            if !matches!(spec.routing_class, RoutingClass::RelayHotpath) {
                continue;
            }
            let relay = resolve_relay_authorization_spec(spec.command_name)
                .expect("relay command must have relay auth metadata");
            if spec.command_name == "file_transfer_offer" {
                assert!(!relay.requires_relay_context);
            } else {
                assert!(relay.requires_relay_context);
            }
            assert_eq!(relay.command_family, "file_transfer");
            assert_eq!(relay.operation_key_field, "transfer_id");
            assert_eq!(relay.relay_context_type, RelayContextType::FileTransferPeer);
            assert_eq!(relay.audience_scope_mode, AudienceScopeMode::FixedPeer);
            assert_eq!(relay.guard_class, RelayGuardClass::ContextBoundPeer);
        }
    }
}
