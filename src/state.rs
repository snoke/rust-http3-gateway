use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Clone, Debug)]
pub enum OutboundMessage {
    Datagram(Vec<u8>),
}

#[derive(Clone, Default)]
pub struct GatewayState {
    connections: Arc<DashMap<String, mpsc::UnboundedSender<OutboundMessage>>>,
}

#[derive(Debug)]
pub enum PublishError {
    NotFound,
    Disconnected,
}

impl GatewayState {
    pub fn register_connection(&self, connection_id: String) -> mpsc::UnboundedReceiver<OutboundMessage> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.connections.insert(connection_id, tx);
        rx
    }

    pub fn unregister_connection(&self, connection_id: &str) {
        self.connections.remove(connection_id);
    }

    pub fn publish_datagram(&self, connection_id: &str, payload: Vec<u8>) -> Result<(), PublishError> {
        let Some(tx) = self.connections.get(connection_id) else {
            return Err(PublishError::NotFound);
        };

        tx.send(OutboundMessage::Datagram(payload))
            .map_err(|_| PublishError::Disconnected)
    }
}

