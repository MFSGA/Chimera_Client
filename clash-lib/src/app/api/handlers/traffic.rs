use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{ConnectInfo, State, WebSocketUpgrade, ws::Message},
    response::IntoResponse,
};
use serde::Serialize;
use tracing::warn;

use crate::app::api::AppState;

#[derive(Serialize)]
struct TrafficResponse {
    up: u64,
    down: u64,
}

pub async fn handle(
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_failed_upgrade(move |e| {
        warn!("ws upgrade error: {} with {}", e, addr);
    })
    .on_upgrade(move |mut socket| async move {
        let mgr = state.statistics_manager.clone();

        loop {
            let (up, down) = mgr.now();
            let response = TrafficResponse { up, down };
            let body = match serde_json::to_string(&response) {
                Ok(body) => body,
                Err(err) => {
                    warn!("serialize traffic snapshot failed: {}", err);
                    break;
                }
            };

            if let Err(err) = socket.send(Message::Text(body.into())).await {
                warn!("ws send error: {}", err);
                break;
            }

            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    })
}
