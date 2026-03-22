pub const BACKEND_HANDLER_MAP_PATH: &str =
    "symfony/src/Void/Interface/Realtime/MessageHandlerCollection.php";

pub const FRONTEND_EMITTER_TYPE_FILES: &[&str] = &[
    "frontend/src/app/messaging/messenger/transport.ts",
    "frontend/src/app/messaging/messenger/send.ts",
    "frontend/src/app/messaging/messenger/conversation.ts",
    "frontend/src/app/messaging/messenger/index.ts",
    "frontend/src/plugins/file-transfer/services/fileTransferService.ts",
    "frontend/src/plugins/calls/services/callManager.ts",
    "frontend/src/plugins/auth/app/services/auth.ts",
    "frontend/src/plugins/anonymous-dropbox/services/dropboxApi.ts",
    "frontend/src/plugins/contact-book/components/ContactBookHome.vue",
    "frontend/src/plugins/components/useRealtimeContactOptions.ts",
    "frontend/src/plugins/identity/components/ClientsList.vue",
];

pub const FRONTEND_IGNORED_TYPE_LITERALS: &[&str] = &[
    "idle",
    "ok",
    "error",
    "group",
    "direct",
    "message",
    "event",
    "call_session",
    "api_key",
    "chunked_attachment",
    "user_storage_folder_share_bundle",
];
