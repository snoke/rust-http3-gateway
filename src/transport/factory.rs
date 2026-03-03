use anyhow::Result;
use tracing::info;

use crate::config::Config;
use crate::state::GatewayState;

use super::websocket::WebSocketServer;
use super::webtransport::WebTransportServer;
use super::TransportAdapter;

pub async fn spawn_transport_server(
    config: Config,
    state: GatewayState,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    match config.transport.as_str() {
        "websocket" => {
            let ws_server = WebSocketServer::new(config, state).await?;
            info!(
                transport = TransportAdapter::name(&ws_server),
                port = TransportAdapter::local_port(&ws_server),
                "server started"
            );
            Ok(tokio::spawn(async move { TransportAdapter::serve(ws_server).await }))
        }
        _ => {
            let wt_server = WebTransportServer::from_config(config, state).await?;
            info!(
                transport = TransportAdapter::name(&wt_server),
                port = TransportAdapter::local_port(&wt_server),
                "server started"
            );
            Ok(tokio::spawn(async move { TransportAdapter::serve(wt_server).await }))
        }
    }
}

