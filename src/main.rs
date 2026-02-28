use anyhow::Context;
use anyhow::Result;
use tracing::error;
use tracing::info;
use wtransport::Identity;

mod state;
mod webtransport_server;
mod publisher;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let webtransport_port = env_u16("WEBTRANSPORT_PORT").unwrap_or(4433);
    let http_api_port = env_u16("HTTP_API_PORT").unwrap_or(8080);
    let webhook_url = std::env::var("SYMFONY_WEBHOOK_URL").ok().filter(|v| !v.is_empty());
    let cert_pem = std::env::var("CERT_PEMFILE").unwrap_or_else(|_| "/run/certs/dev_cert.pem".into());
    let key_pem =
        std::env::var("KEY_PEMFILE").unwrap_or_else(|_| "/run/certs/dev_key.pem".into());

    // Use a fixed cert/key in dev so the browser can pin the certificate hash (WebTransport
    // `serverCertificateHashes`) without needing to trust a local CA.
    let identity = Identity::load_pemfiles(cert_pem, key_pem)
        .await
        .context("failed to load TLS identity from PEM files")?;

    let state = state::GatewayState::default();

    let webtransport_server =
        webtransport_server::WebTransportServer::new(identity, webtransport_port, webhook_url, state.clone())?;

    info!(webtransport_port = webtransport_server.local_port(), "server started");

    let wt_task = tokio::spawn(async move { webtransport_server.serve().await });
    let api_task = tokio::spawn(async move { publisher::serve(http_api_port, state).await });

    tokio::select! {
        result = wt_task => {
            error!("WebTransport server stopped: {:?}", result);
        }
        result = api_task => {
            error!("HTTP API server stopped: {:?}", result);
        }
        _ = tokio::signal::ctrl_c() => {
            info!("shutdown requested");
        }
    }

    Ok(())
}

fn env_u16(key: &str) -> Option<u16> {
    std::env::var(key).ok()?.parse::<u16>().ok()
}
