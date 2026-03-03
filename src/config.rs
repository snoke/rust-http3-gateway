use std::fs;

#[derive(Clone)]
pub struct Config {
    pub transport: String,
    pub jwt_alg: String,
    pub jwt_user_id_claim: String,
    pub jwt_public_key: String,
    pub jwt_public_key_file: String,
    pub jwt_jwks_url: String,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub jwt_leeway: i64,
    pub gateway_api_key: String,
    pub redis_dsn: String,
    pub redis_stream: String,
    pub redis_inbox_stream: String,
    pub redis_events_stream: String,
    pub max_connections_per_user: Option<usize>,
    pub stale_connection_timeout_seconds: i64,
    pub stale_prune_interval_seconds: u64,
    pub webtransport_port: u16,
    pub websocket_port: u16,
    pub http_api_port: u16,
    pub cert_pemfile: String,
    pub key_pemfile: String,
}

impl Config {
    pub fn from_env() -> Self {
        let transport = env_str("GATEWAY_TRANSPORT", "webtransport").to_lowercase();
        let jwt_alg = env_str("JWT_ALG", "RS256");
        let jwt_user_id_claim = env_str("JWT_USER_ID_CLAIM", "user_id");
        let jwt_public_key_file = env_str("JWT_PUBLIC_KEY_FILE", "");
        let mut jwt_public_key = env_str("JWT_PUBLIC_KEY", "");
        if jwt_public_key.is_empty() && !jwt_public_key_file.is_empty() {
            if let Ok(contents) = fs::read_to_string(&jwt_public_key_file) {
                jwt_public_key = contents;
            }
        }
        let jwt_jwks_url = env_str("JWT_JWKS_URL", "");
        let jwt_issuer = env_str("JWT_ISSUER", "");
        let jwt_audience = env_str("JWT_AUDIENCE", "");
        let jwt_leeway = env_i64("JWT_LEEWAY", 0);

        let gateway_api_key = env_str("GATEWAY_API_KEY", "");
        let redis_dsn = env_str("REDIS_DSN", "");
        let redis_stream = env_str("REDIS_STREAM", "ws.outbox");
        let redis_inbox_stream = env_str("REDIS_INBOX_STREAM", "ws.inbox");
        let redis_events_stream = env_str("REDIS_EVENTS_STREAM", "ws.events");
        let max_connections_per_user = env_usize("MAX_CONNECTIONS_PER_USER").filter(|value| *value > 0);
        let stale_connection_timeout_seconds = env_i64("CONNECTION_STALE_SECONDS", 120).max(0);
        let stale_prune_interval_seconds = env_u64("CONNECTION_PRUNE_INTERVAL_SECONDS", 15).max(1);

        let webtransport_port = env_u16("WEBTRANSPORT_PORT", 4433);
        let websocket_port = env_u16("WEBSOCKET_PORT", 8081);
        let http_api_port = env_u16("HTTP_API_PORT", 8080);
        let cert_pemfile = env_str("CERT_PEMFILE", "/run/certs/dev_cert.pem");
        let key_pemfile = env_str("KEY_PEMFILE", "/run/certs/dev_key.pem");

        Self {
            transport: match transport.as_str() {
                "websocket" | "ws" => "websocket".to_string(),
                _ => "webtransport".to_string(),
            },
            jwt_alg,
            jwt_user_id_claim,
            jwt_public_key,
            jwt_public_key_file,
            jwt_jwks_url,
            jwt_issuer,
            jwt_audience,
            jwt_leeway,
            gateway_api_key,
            redis_dsn,
            redis_stream,
            redis_inbox_stream,
            redis_events_stream,
            max_connections_per_user,
            stale_connection_timeout_seconds,
            stale_prune_interval_seconds,
            webtransport_port,
            websocket_port,
            http_api_port,
            cert_pemfile,
            key_pemfile,
        }
    }
}

fn env_str(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_i64(key: &str, default: i64) -> i64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(default)
}

fn env_u16(key: &str, default: u16) -> u16 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_usize(key: &str) -> Option<usize> {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
}
