use anyhow::Result;
use reqwest::Client;
use serde::Serialize;
use std::time::Duration;
use tracing::info;
use tracing::warn;
use tracing::info_span;
use tracing::Instrument;
use uuid::Uuid;
use wtransport::endpoint::endpoint_side::Server;
use wtransport::endpoint::IncomingSession;
use wtransport::Endpoint;
use wtransport::Identity;
use wtransport::ServerConfig;

use crate::state::GatewayState;

pub struct WebTransportServer {
    endpoint: Endpoint<Server>,
    webhook: Option<Webhook>,
    state: GatewayState,
}

impl WebTransportServer {
    pub fn new(identity: Identity, port: u16, webhook_url: Option<String>, state: GatewayState) -> Result<Self> {
        let config = ServerConfig::builder()
            .with_bind_default(port)
            .with_identity(identity)
            .keep_alive_interval(Some(Duration::from_secs(3)))
            .build();

        let endpoint = Endpoint::server(config)?;
        let webhook = webhook_url.map(|url| Webhook {
            url,
            client: Client::builder()
                .timeout(Duration::from_secs(3))
                .build()
                .expect("reqwest client"),
        });

        Ok(Self { endpoint, webhook, state })
    }

    pub fn local_port(&self) -> u16 {
        self.endpoint.local_addr().unwrap().port()
    }

    pub async fn serve(self) -> Result<()> {
        info!("WebTransport listening on UDP port {}", self.local_port());

        for id in 0.. {
            let incoming_session = self.endpoint.accept().await;
            let webhook = self.webhook.clone();
            let state = self.state.clone();
            tokio::spawn(
                Self::handle_incoming_session(incoming_session, webhook, state)
                    .instrument(info_span!("wt", id)),
            );
        }

        Ok(())
    }

    async fn handle_incoming_session(
        incoming_session: IncomingSession,
        webhook: Option<Webhook>,
        state: GatewayState,
    ) {
        let connection_id = Uuid::new_v4().to_string();

        async fn impl_(
            incoming_session: IncomingSession,
            webhook: Option<Webhook>,
            connection_id: &str,
            state: GatewayState,
        ) -> Result<()> {
            let mut buffer = vec![0; 65536].into_boxed_slice();

            info!("Waiting for session request...");
            let session_request = incoming_session.await?;

            info!(
                "New session: id='{connection_id}' authority='{}' path='{}'",
                session_request.authority(),
                session_request.path()
            );

            let connection = session_request.accept().await?;
            let mut outbound_rx = state.register_connection(connection_id.to_string());
            info!("Session ready; waiting for client data...");

            if let Some(webhook) = webhook.as_ref() {
                webhook.send(GatewayEvent {
                    r#type: "connected",
                    connection_id: connection_id.to_string(),
                    transport: "webtransport",
                    payload: None,
                });
            }

            loop {
                tokio::select! {
                    outbound = outbound_rx.recv() => {
                        let Some(outbound) = outbound else {
                            continue;
                        };

                        match outbound {
                            crate::state::OutboundMessage::Datagram(bytes) => {
                                connection.send_datagram(&bytes)?;
                            }
                        }
                    }
                    stream = connection.accept_bi() => {
                        let mut stream = stream?;
                        info!("Accepted BI stream");

                        let Some(bytes_read) = stream.1.read(&mut buffer).await? else {
                            continue;
                        };

                        let str_data = std::str::from_utf8(&buffer[..bytes_read])?;
                        info!("Received (bi) '{str_data}'");

                        if let Some(webhook) = webhook.as_ref() {
                            webhook.send(GatewayEvent {
                                r#type: "message_received",
                                connection_id: connection_id.to_string(),
                                transport: "webtransport/bi",
                                payload: Some(str_data.to_string()),
                            });
                        }

                        stream.0.write_all(b"ACK").await?;
                    }
                    stream = connection.accept_uni() => {
                        let mut stream = stream?;
                        info!("Accepted UNI stream");

                        let Some(bytes_read) = stream.read(&mut buffer).await? else {
                            continue;
                        };

                        let str_data = std::str::from_utf8(&buffer[..bytes_read])?;
                        info!("Received (uni) '{str_data}'");

                        if let Some(webhook) = webhook.as_ref() {
                            webhook.send(GatewayEvent {
                                r#type: "message_received",
                                connection_id: connection_id.to_string(),
                                transport: "webtransport/uni",
                                payload: Some(str_data.to_string()),
                            });
                        }

                        let mut stream = connection.open_uni().await?.await?;
                        stream.write_all(b"ACK").await?;
                    }
                    dgram = connection.receive_datagram() => {
                        let dgram = dgram?;
                        let str_data = std::str::from_utf8(&dgram)?;
                        info!("Received (dgram) '{str_data}'");

                        if let Some(webhook) = webhook.as_ref() {
                            webhook.send(GatewayEvent {
                                r#type: "message_received",
                                connection_id: connection_id.to_string(),
                                transport: "webtransport/dgram",
                                payload: Some(str_data.to_string()),
                            });
                        }

                        connection.send_datagram(b"ACK")?;
                    }
                }
            }
        }

        let result = impl_(incoming_session, webhook.clone(), &connection_id, state.clone()).await;
        info!("Session ended: {:?}", result);

        if let (Some(webhook), Some(err)) = (webhook.as_ref(), result.as_ref().err()) {
            webhook.send(GatewayEvent {
                r#type: "error",
                connection_id: connection_id.clone(),
                transport: "webtransport",
                payload: Some(err.to_string()),
            });
        }

        state.unregister_connection(&connection_id);

        if let Some(webhook) = webhook.as_ref() {
            webhook.send(GatewayEvent {
                r#type: "disconnected",
                connection_id,
                transport: "webtransport",
                payload: Some(format!("{result:?}")),
            });
        }
    }
}

#[derive(Clone)]
struct Webhook {
    url: String,
    client: Client,
}

#[derive(Serialize)]
struct GatewayEvent {
    r#type: &'static str,
    connection_id: String,
    transport: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<String>,
}

impl Webhook {
    fn send(&self, event: GatewayEvent) {
        let client = self.client.clone();
        let url = self.url.clone();

        tokio::spawn(async move {
            let res = client.post(url).json(&event).send().await;
            if let Err(err) = res {
                warn!("webhook send failed: {err}");
            }
        });
    }
}
