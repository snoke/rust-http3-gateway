struct PreAuthHttpRoute {
    command_name: &'static str,
    path: &'static str,
}

const PREAUTH_HTTP_ROUTES: &[PreAuthHttpRoute] = &[
    PreAuthHttpRoute {
        command_name: "auth_login_request",
        path: "/api/login_check",
    },
    PreAuthHttpRoute {
        command_name: "auth_register_request",
        path: "/api/register",
    },
    PreAuthHttpRoute {
        command_name: "auth_identity_request",
        path: "/api/identity/login",
    },
];

const DROPBOX_GUEST_USER_PREFIX: &str = "public-dropbox";

pub fn resolve_http_path(command_name: &str) -> Option<&'static str> {
    PREAUTH_HTTP_ROUTES
        .iter()
        .find(|entry| entry.command_name == command_name)
        .map(|entry| entry.path)
}

pub fn compose_dropbox_guest_user_id(slug: &str, timestamp_micros: i64) -> String {
    format!("{DROPBOX_GUEST_USER_PREFIX}:{slug}:{timestamp_micros}")
}
