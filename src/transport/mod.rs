use anyhow::Result;
use async_trait::async_trait;

pub mod factory;
pub mod websocket;
pub mod webtransport;

#[async_trait]
pub trait TransportAdapter: Send {
    fn name(&self) -> &'static str;
    fn local_port(&self) -> u16;
    async fn serve(self) -> Result<()>;
}

