use std::collections::HashMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchStep {
    Symfony,
    Subjects,
}

impl DispatchStep {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Symfony => "symfony",
            Self::Subjects => "subjects",
        }
    }
}

pub type DispatchPlan = &'static [DispatchStep];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutingClass {
    PreAuth,
    GatewayLocal,
    RelayHotpath,
    BackendControl,
}

impl RoutingClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreAuth => "preauth",
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

#[derive(Clone, Copy, Debug)]
pub struct CommandSpec {
    pub command_name: &'static str,
    pub routing_class: RoutingClass,
    pub message_type: MessageSemanticType,
    pub dispatch_plan: DispatchPlan,
    pub owner: &'static str,
    pub deprecated: bool,
    pub notes: Option<&'static str>,
}

const NO_DISPATCH: DispatchPlan = &[];
const SYMFONY_ONLY: DispatchPlan = &[DispatchStep::Symfony];
const SUBJECTS_ONLY: DispatchPlan = &[DispatchStep::Subjects];

pub const COMMAND_REGISTRY: &[CommandSpec] = &[
    CommandSpec {
        command_name: "auth",
        routing_class: RoutingClass::PreAuth,
        message_type: MessageSemanticType::Technical,
        dispatch_plan: NO_DISPATCH,
        owner: "auth",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "auth_login_request",
        routing_class: RoutingClass::PreAuth,
        message_type: MessageSemanticType::Technical,
        dispatch_plan: NO_DISPATCH,
        owner: "auth",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "auth_register_request",
        routing_class: RoutingClass::PreAuth,
        message_type: MessageSemanticType::Technical,
        dispatch_plan: NO_DISPATCH,
        owner: "auth",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "auth_identity_request",
        routing_class: RoutingClass::PreAuth,
        message_type: MessageSemanticType::Technical,
        dispatch_plan: NO_DISPATCH,
        owner: "auth",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "dropbox_public_auth",
        routing_class: RoutingClass::PreAuth,
        message_type: MessageSemanticType::Technical,
        dispatch_plan: NO_DISPATCH,
        owner: "dropbox",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "ping",
        routing_class: RoutingClass::GatewayLocal,
        message_type: MessageSemanticType::Technical,
        dispatch_plan: NO_DISPATCH,
        owner: "gateway",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "bootstrap_request",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Query,
        dispatch_plan: SYMFONY_ONLY,
        owner: "core",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "online_request",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Query,
        dispatch_plan: SYMFONY_ONLY,
        owner: "core",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "users_request",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Query,
        dispatch_plan: SYMFONY_ONLY,
        owner: "core",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "mls_key_package_publish",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "mls",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "mls_key_package_fetch",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Query,
        dispatch_plan: SYMFONY_ONLY,
        owner: "mls",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "contact_unblock",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "contact_book",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "contacts_request",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Query,
        dispatch_plan: SYMFONY_ONLY,
        owner: "contact_book",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "contact_profiles_request",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Query,
        dispatch_plan: SYMFONY_ONLY,
        owner: "contact_book",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "attachment_upload_init",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "attachments",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "attachment_upload_chunk",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "attachments",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "attachment_upload_finalize",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "attachments",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "audit_timeline_request",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Query,
        dispatch_plan: SYMFONY_ONLY,
        owner: "audit",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "audit_timeline_export_request",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Query,
        dispatch_plan: SYMFONY_ONLY,
        owner: "audit",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "attachment_download_chunk",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Query,
        dispatch_plan: SYMFONY_ONLY,
        owner: "attachments",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "attachment_list_request",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Query,
        dispatch_plan: SYMFONY_ONLY,
        owner: "attachments",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "attachment_delete_request",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "attachments",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "user_storage_upload_init",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "user_storage",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "user_storage_upload_resume_request",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Query,
        dispatch_plan: SYMFONY_ONLY,
        owner: "user_storage",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "user_storage_upload_chunk",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "user_storage",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "user_storage_upload_finalize",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "user_storage",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "user_storage_download_chunk",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Query,
        dispatch_plan: SYMFONY_ONLY,
        owner: "user_storage",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "user_storage_list_request",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Query,
        dispatch_plan: SYMFONY_ONLY,
        owner: "user_storage",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "user_storage_delete_request",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "user_storage",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "user_storage_share_link_create",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "user_storage",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "user_storage_share_links_request",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Query,
        dispatch_plan: SYMFONY_ONLY,
        owner: "user_storage",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "user_storage_share_link_revoke",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "user_storage",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "user_storage_share_info_request",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Query,
        dispatch_plan: SYMFONY_ONLY,
        owner: "user_storage",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "user_storage_share_download_chunk",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Query,
        dispatch_plan: SYMFONY_ONLY,
        owner: "user_storage",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "contact_add",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "contact_book",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "contact_accept",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "contact_book",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "contact_block",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "contact_book",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "contact_profile_upsert",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "contact_book",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "contact_profile_delete",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "contact_book",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "deadman_config_request",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "deadman",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "deadman_config_upsert",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "deadman",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "dropbox_endpoints_request",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Query,
        dispatch_plan: SYMFONY_ONLY,
        owner: "dropbox",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "dropbox_endpoint_upsert",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "dropbox",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "dropbox_endpoint_delete",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "dropbox",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "dropbox_messages_request",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Query,
        dispatch_plan: SYMFONY_ONLY,
        owner: "dropbox",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "dropbox_message_delete",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "dropbox",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "dropbox_public_info_request",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Query,
        dispatch_plan: SYMFONY_ONLY,
        owner: "dropbox",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "dropbox_public_submit",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "dropbox",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "chat_conversations_request",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Query,
        dispatch_plan: SYMFONY_ONLY,
        owner: "chat",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "chat_conversation_open",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "chat",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "chat_messages_request",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Query,
        dispatch_plan: SYMFONY_ONLY,
        owner: "chat",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "group_create",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "chat",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "group_add",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "chat",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "group_leave",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "chat",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "group_membership_accept",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "chat",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "history_clear",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "chat",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "identity_profile_request",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Query,
        dispatch_plan: SYMFONY_ONLY,
        owner: "identity",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "identity_profile_upsert",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "identity",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "key_trust_list_request",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Query,
        dispatch_plan: SYMFONY_ONLY,
        owner: "key_trust",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "key_trust_upsert",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "key_trust",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "key_trust_delete",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "key_trust",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "mls_commit",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "mls",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "mls_welcome_request",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "mls",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "mls_welcome_ack",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "mls",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "presence_state",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Signal,
        dispatch_plan: SYMFONY_ONLY,
        owner: "presence",
        deprecated: false,
        notes: Some("consolidated to backend_control until deterministic relay targets exist"),
    },
    CommandSpec {
        command_name: "chat_typing_state",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Signal,
        dispatch_plan: SYMFONY_ONLY,
        owner: "chat",
        deprecated: false,
        notes: Some("consolidated to backend_control until deterministic relay targets exist"),
    },
    CommandSpec {
        command_name: "chat_message_read",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "chat",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "call_token_request",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Query,
        dispatch_plan: SYMFONY_ONLY,
        owner: "calls",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "call_session_create",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "calls",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "call_session_invite",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "calls",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "call_session_join",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "calls",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "call_session_leave",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "calls",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "call_session_media_key",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Signal,
        dispatch_plan: SYMFONY_ONLY,
        owner: "calls",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "call_session_mute",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Signal,
        dispatch_plan: SYMFONY_ONLY,
        owner: "calls",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "call_session_camera",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Signal,
        dispatch_plan: SYMFONY_ONLY,
        owner: "calls",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "call_session_token_request",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Query,
        dispatch_plan: SYMFONY_ONLY,
        owner: "calls",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "call_invite",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "calls",
        deprecated: true,
        notes: Some("legacy call_* path; migrate to call_session_*"),
    },
    CommandSpec {
        command_name: "call_join",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "calls",
        deprecated: true,
        notes: Some("legacy call_* path; migrate to call_session_*"),
    },
    CommandSpec {
        command_name: "call_leave",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "calls",
        deprecated: true,
        notes: Some("legacy call_* path; migrate to call_session_*"),
    },
    CommandSpec {
        command_name: "call_mute",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Signal,
        dispatch_plan: SYMFONY_ONLY,
        owner: "calls",
        deprecated: true,
        notes: Some("legacy call_* path; migrate to call_session_*"),
    },
    CommandSpec {
        command_name: "call_camera",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Signal,
        dispatch_plan: SYMFONY_ONLY,
        owner: "calls",
        deprecated: true,
        notes: Some("legacy call_* path; migrate to call_session_*"),
    },
    CommandSpec {
        command_name: "call_media_key",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Signal,
        dispatch_plan: SYMFONY_ONLY,
        owner: "calls",
        deprecated: true,
        notes: Some("legacy call_* path; migrate to call_session_*"),
    },
    CommandSpec {
        command_name: "file_transfer_offer",
        routing_class: RoutingClass::RelayHotpath,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SUBJECTS_ONLY,
        owner: "file_transfer",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "file_transfer_accept",
        routing_class: RoutingClass::RelayHotpath,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SUBJECTS_ONLY,
        owner: "file_transfer",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "file_transfer_reject",
        routing_class: RoutingClass::RelayHotpath,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SUBJECTS_ONLY,
        owner: "file_transfer",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "file_transfer_handshake",
        routing_class: RoutingClass::RelayHotpath,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SUBJECTS_ONLY,
        owner: "file_transfer",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "file_transfer_handshake_ack",
        routing_class: RoutingClass::RelayHotpath,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SUBJECTS_ONLY,
        owner: "file_transfer",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "file_transfer_welcome",
        routing_class: RoutingClass::RelayHotpath,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SUBJECTS_ONLY,
        owner: "file_transfer",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "file_transfer_file_key",
        routing_class: RoutingClass::RelayHotpath,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SUBJECTS_ONLY,
        owner: "file_transfer",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "file_transfer_file_key_ack",
        routing_class: RoutingClass::RelayHotpath,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SUBJECTS_ONLY,
        owner: "file_transfer",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "file_transfer_chunk",
        routing_class: RoutingClass::RelayHotpath,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SUBJECTS_ONLY,
        owner: "file_transfer",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "file_transfer_complete",
        routing_class: RoutingClass::RelayHotpath,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SUBJECTS_ONLY,
        owner: "file_transfer",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "file_transfer_cancel",
        routing_class: RoutingClass::RelayHotpath,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SUBJECTS_ONLY,
        owner: "file_transfer",
        deprecated: false,
        notes: None,
    },
    CommandSpec {
        command_name: "chat_message_send",
        routing_class: RoutingClass::BackendControl,
        message_type: MessageSemanticType::Command,
        dispatch_plan: SYMFONY_ONLY,
        owner: "chat",
        deprecated: false,
        notes: Some("consolidated to backend_control to avoid route/runtime drift"),
    },
];

pub fn command_registry() -> &'static [CommandSpec] {
    COMMAND_REGISTRY
}

pub fn resolve_command_spec(command_type: &str) -> Option<&'static CommandSpec> {
    COMMAND_REGISTRY
        .iter()
        .find(|spec| spec.command_name == command_type)
}

pub fn resolve_dispatch_plan(command_type: &str) -> Option<DispatchPlan> {
    let spec = resolve_command_spec(command_type)?;
    match spec.routing_class {
        RoutingClass::RelayHotpath | RoutingClass::BackendControl => Some(spec.dispatch_plan),
        RoutingClass::PreAuth | RoutingClass::GatewayLocal => None,
    }
}

pub fn resolve_message_type(command_type: &str) -> Option<MessageSemanticType> {
    resolve_command_spec(command_type).map(|spec| spec.message_type)
}

pub fn command_route_map() -> HashMap<&'static str, DispatchPlan> {
    let mut map = HashMap::new();
    for spec in COMMAND_REGISTRY {
        if let Some(plan) = resolve_dispatch_plan(spec.command_name) {
            map.insert(spec.command_name, plan);
        }
    }
    map
}

pub fn validate_command_registry() -> Result<(), String> {
    let mut seen = std::collections::HashSet::new();
    for spec in COMMAND_REGISTRY {
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
            RoutingClass::PreAuth | RoutingClass::GatewayLocal => {
                if !matches!(spec.message_type, MessageSemanticType::Technical) {
                    return Err(format!(
                        "command '{}' with routing class '{}' must use semantic type 'technical'",
                        spec.command_name,
                        spec.routing_class.as_str()
                    ));
                }
                if !spec.dispatch_plan.is_empty() {
                    return Err(format!(
                        "command '{}' has non-empty dispatch plan for routing class '{}'",
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
                if spec.dispatch_plan.is_empty() {
                    return Err(format!(
                        "relay command '{}' must define a dispatch plan",
                        spec.command_name
                    ));
                }
                if !spec
                    .dispatch_plan
                    .iter()
                    .any(|step| matches!(step, DispatchStep::Subjects))
                {
                    return Err(format!(
                        "relay command '{}' must contain a subjects dispatch step",
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
                if spec.dispatch_plan.is_empty() {
                    return Err(format!(
                        "backend control command '{}' must define a dispatch plan",
                        spec.command_name
                    ));
                }
                if !spec
                    .dispatch_plan
                    .iter()
                    .any(|step| matches!(step, DispatchStep::Symfony))
                {
                    return Err(format!(
                        "backend control command '{}' must contain a symfony dispatch step",
                        spec.command_name
                    ));
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
                literals.drain(..1).next()
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
        let backend_map = root.join("symfony/src/Void/Interface/Realtime/MessageHandlerCollection.php");
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
        let files = [
            "frontend/src/app/core/messaging/services/messenger/transport.ts",
            "frontend/src/app/core/messaging/services/messenger/send.ts",
            "frontend/src/app/core/messaging/services/messenger/conversation.ts",
            "frontend/src/app/core/messaging/services/messenger.ts",
            "frontend/src/plugins/file-transfer/services/fileTransferService.ts",
            "frontend/src/plugins/calls/services/callManager.ts",
            "frontend/src/plugins/auth/app/services/auth.ts",
            "frontend/src/plugins/anonymous-dropbox/services/dropboxApi.ts",
            "frontend/src/plugins/contact-book/components/ContactBookHome.vue",
            "frontend/src/plugins/components/useRealtimeContactOptions.ts",
            "frontend/src/plugins/identity/components/ClientsList.vue",
            "frontend/src/plugins/chat/components/ChatDesktopHome.vue",
        ];
        let ignored_literals: HashSet<&str> = [
            "idle",
            "ok",
            "error",
            "group",
            "direct",
            "message",
            "event",
            "api_key",
            "chunked_attachment",
            "chunked_user_storage",
            "user_storage_folder_share_bundle",
        ]
        .into_iter()
        .collect();

        let mut unknown = Vec::new();
        for rel in files {
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
    fn legacy_call_commands_are_explicitly_deprecated() {
        let expected_legacy = [
            "call_invite",
            "call_join",
            "call_leave",
            "call_mute",
            "call_camera",
            "call_media_key",
        ];
        for command in expected_legacy {
            let spec = resolve_command_spec(command).expect("legacy command must exist in registry");
            assert_eq!(spec.routing_class, RoutingClass::BackendControl);
            assert!(spec.deprecated, "legacy command '{command}' must be marked deprecated");
        }
    }

    #[test]
    fn critical_commands_have_expected_routing_classes() {
        let cases = [
            ("auth_login_request", RoutingClass::PreAuth),
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
}
