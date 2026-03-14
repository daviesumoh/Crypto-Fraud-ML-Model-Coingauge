use std::env;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use risk_gateway::{build_router, AppState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,risk_gateway=debug")),
        )
        .init();

    let bind_addr =
        env::var("SENTINEL_GATEWAY_ADDR").unwrap_or_else(|_| "0.0.0.0:8090".to_string());
    let ml_url = env::var("SENTINEL_ML_SERVICE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8091".to_string());

    let state = AppState::new(ml_url.clone());
    risk_gateway::spawn_live_chain_streamers(state.clone());
    let app = build_router(state);

    tracing::info!(
        "CoinGauge Risk Gateway listening on http://{} (ML sidecar: {})",
        bind_addr,
        ml_url
    );

    let listener = TcpListener::bind(&bind_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

