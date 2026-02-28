use anyhow::Context;
use anyhow::Result;
use tracing::error;
use tracing::info;
use wtransport::Identity;

mod webtransport_server;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let webtransport_port = env_u16("WEBTRANSPORT_PORT").unwrap_or(4433);
    let webhook_url = std::env::var("SYMFONY_WEBHOOK_URL").ok().filter(|v| !v.is_empty());
    let cert_pem = std::env::var("CERT_PEMFILE").unwrap_or_else(|_| "/run/certs/dev_cert.pem".into());
    let key_pem =
        std::env::var("KEY_PEMFILE").unwrap_or_else(|_| "/run/certs/dev_key.pem".into());

    // Use a fixed cert/key in dev so the browser can pin the certificate hash (WebTransport
    // `serverCertificateHashes`) without needing to trust a local CA.
    let identity = Identity::load_pemfiles(cert_pem, key_pem)
        .await
        .context("failed to load TLS identity from PEM files")?;

    let webtransport_server =
        webtransport_server::WebTransportServer::new(identity, webtransport_port, webhook_url)?;

    info!(webtransport_port = webtransport_server.local_port(), "server started");

    let result = webtransport_server.serve().await;
    error!("WebTransport server stopped: {:?}", result);

    Ok(())
}

fn env_u16(key: &str) -> Option<u16> {
    std::env::var(key).ok()?.parse::<u16>().ok()
}
