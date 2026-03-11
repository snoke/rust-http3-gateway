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

const SYMFONY_ONLY: DispatchPlan = &[DispatchStep::Symfony];
const SUBJECTS_ONLY: DispatchPlan = &[DispatchStep::Subjects];
const FASTPATH_ROUTE: DispatchPlan = &[DispatchStep::Subjects, DispatchStep::Symfony];
const SYMFONY_THEN_SUBJECTS: DispatchPlan = &[DispatchStep::Symfony, DispatchStep::Subjects];

pub const COMMAND_ROUTE_TABLE: &[(&str, DispatchPlan)] = &[
    ("bootstrap_request", SYMFONY_ONLY),
    ("online_request", SYMFONY_ONLY),
    ("users_request", SYMFONY_ONLY),
    ("mls_key_package_publish", SYMFONY_ONLY),
    ("mls_key_package_fetch", SYMFONY_ONLY),
    ("contact_unblock", SYMFONY_ONLY),
    ("contacts_request", SYMFONY_ONLY),
    ("contact_profiles_request", SYMFONY_ONLY),
    ("attachment_upload_init", SYMFONY_ONLY),
    ("attachment_upload_chunk", SYMFONY_ONLY),
    ("attachment_upload_finalize", SYMFONY_ONLY),
    ("audit_timeline_request", SYMFONY_ONLY),
    ("audit_timeline_export_request", SYMFONY_ONLY),
    ("attachment_download_chunk", SYMFONY_ONLY),
    ("attachment_list_request", SYMFONY_ONLY),
    ("attachment_delete_request", SYMFONY_ONLY),
    ("user_storage_upload_init", SYMFONY_ONLY),
    ("user_storage_upload_resume_request", SYMFONY_ONLY),
    ("user_storage_upload_chunk", SYMFONY_ONLY),
    ("user_storage_upload_finalize", SYMFONY_ONLY),
    ("user_storage_download_chunk", SYMFONY_ONLY),
    ("user_storage_list_request", SYMFONY_ONLY),
    ("user_storage_delete_request", SYMFONY_ONLY),
    ("user_storage_share_link_create", SYMFONY_ONLY),
    ("user_storage_share_links_request", SYMFONY_ONLY),
    ("user_storage_share_link_revoke", SYMFONY_ONLY),
    ("user_storage_share_info_request", SYMFONY_ONLY),
    ("user_storage_share_download_chunk", SYMFONY_ONLY),
    ("contact_add", SYMFONY_ONLY),
    ("contact_accept", SYMFONY_ONLY),
    ("contact_block", SYMFONY_ONLY),
    ("contact_profile_upsert", SYMFONY_ONLY),
    ("contact_profile_delete", SYMFONY_ONLY),
    ("deadman_config_request", SYMFONY_ONLY),
    ("deadman_config_upsert", SYMFONY_ONLY),
    ("dropbox_endpoints_request", SYMFONY_ONLY),
    ("dropbox_endpoint_upsert", SYMFONY_ONLY),
    ("dropbox_endpoint_delete", SYMFONY_ONLY),
    ("dropbox_messages_request", SYMFONY_ONLY),
    ("dropbox_message_delete", SYMFONY_ONLY),
    ("dropbox_public_info_request", SYMFONY_ONLY),
    ("dropbox_public_submit", SYMFONY_ONLY),
    ("conversations_request", SYMFONY_ONLY),
    ("conversation_open", SYMFONY_ONLY),
    ("messages_request", SYMFONY_ONLY),
    ("group_create", SYMFONY_ONLY),
    ("group_add", SYMFONY_ONLY),
    ("group_leave", SYMFONY_ONLY),
    ("history_clear", SYMFONY_ONLY),
    ("identity_profile_request", SYMFONY_ONLY),
    ("identity_profile_upsert", SYMFONY_ONLY),
    ("key_trust_list_request", SYMFONY_ONLY),
    ("key_trust_upsert", SYMFONY_ONLY),
    ("key_trust_delete", SYMFONY_ONLY),
    ("mls_commit", SYMFONY_ONLY),
    ("mls_welcome_request", SYMFONY_ONLY),
    ("mls_welcome_ack", SYMFONY_ONLY),
    ("presence_state", SUBJECTS_ONLY),
    ("typing", SUBJECTS_ONLY),
    ("read", SYMFONY_ONLY),
    ("call_token_request", SYMFONY_ONLY),
    ("call_session_create", SYMFONY_ONLY),
    ("call_session_invite", SYMFONY_ONLY),
    ("call_session_join", SYMFONY_ONLY),
    ("call_session_leave", SYMFONY_ONLY),
    ("call_session_media_key", SYMFONY_ONLY),
    ("call_session_mute", SYMFONY_ONLY),
    ("call_session_camera", SYMFONY_ONLY),
    ("call_session_token_request", SYMFONY_ONLY),
    ("chat", FASTPATH_ROUTE),
];

pub fn resolve_dispatch_plan(command_type: &str) -> DispatchPlan {
    COMMAND_ROUTE_TABLE
        .iter()
        .find_map(|(key, plan)| (*key == command_type).then_some(*plan))
        .unwrap_or(SYMFONY_ONLY)
}

pub fn command_route_map() -> HashMap<&'static str, DispatchPlan> {
    COMMAND_ROUTE_TABLE.iter().copied().collect()
}

pub fn symfony_only() -> DispatchPlan {
    SYMFONY_ONLY
}

pub fn subjects_only() -> DispatchPlan {
    SUBJECTS_ONLY
}

pub fn fastpath() -> DispatchPlan {
    FASTPATH_ROUTE
}

pub fn symfony_then_subjects() -> DispatchPlan {
    SYMFONY_THEN_SUBJECTS
}
