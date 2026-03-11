use anyhow::{anyhow, Result};
use serde_json::json;
use std::time::Duration;
use tracing::{error, info};

mod auth;
mod broker;
mod config;
mod gateway_core;
mod http_api;
mod message;
mod preauth;
mod routes;
mod state;
mod transport;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    if let Err(err) = routes::validate_command_registry() {
        error!("invalid command registry: {err}");
        return Err(anyhow!("invalid command registry: {err}"));
    }

    let config = config::Config::from_env();
    let state = state::GatewayState::new(config.max_connections_per_user);
    let transport_task = transport::factory::spawn_transport_server(config.clone(), state.clone()).await?;

    if !config.redis_dsn.is_empty() {
        if let Ok(redis) = redis::Client::open(config.redis_dsn.as_str()) {
            let state_clone = state.clone();
            let config_clone = config.clone();
            tokio::spawn(async move {
                broker::start_outbox_consumer(state_clone, config_clone, redis).await;
            });
        }
    }

    if config.stale_connection_timeout_seconds > 0 {
        let state_clone = state.clone();
        let config_clone = config.clone();
        let redis = if config.redis_dsn.is_empty() {
            None
        } else {
            redis::Client::open(config.redis_dsn.as_str()).ok()
        };

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(config_clone.stale_prune_interval_seconds));
            loop {
                interval.tick().await;
                let now_ts = chrono::Utc::now().timestamp();
                let evicted = state_clone
                    .prune_stale_connections(now_ts, config_clone.stale_connection_timeout_seconds);
                if evicted.is_empty() {
                    continue;
                }

                info!(count = evicted.len(), "pruned stale connections");

                if let Some(redis) = redis.as_ref() {
                    for info in evicted {
                        let payload = json!({
                            "type": "disconnected",
                            "connection_id": info.connection_id,
                            "user_id": info.user_id,
                            "subjects": info.subjects,
                            "connected_at": info.connected_at,
                        });
                        let _ =
                            broker::publish_event(redis, &config_clone.redis_events_stream, &payload)
                                .await;
                    }
                }
            }
        });
    }

    let api_task = tokio::spawn(async move { http_api::serve(config.http_api_port, config, state).await });

    tokio::select! {
        result = transport_task => {
            error!("Transport server stopped: {:?}", result);
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
