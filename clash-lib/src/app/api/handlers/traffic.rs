use std::sync::Arc;

use axum::{
    body::Body,
    extract::{FromRequest, Request, State, WebSocketUpgrade, ws::Message},
    http::StatusCode,
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
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> impl IntoResponse {
    let ws = match WebSocketUpgrade::from_request(req, &state).await {
        Ok(ws) => ws,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                "the /traffic endpoint requires websocket upgrade",
            )
                .into_response();
        }
    };

    ws.on_failed_upgrade(move |e| {
        warn!("ws upgrade error: {}", e);
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
