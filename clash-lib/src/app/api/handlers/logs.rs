use std::sync::Arc;

use axum::{
    body::Body,
    extract::{FromRequest, Query, Request, State, WebSocketUpgrade, ws::Message},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use tracing::{debug, warn};

use crate::{app::api::AppState, config::def::LogLevel};

#[derive(Deserialize)]
pub struct GetLogsQuery {
    level: Option<LogLevel>,
}

pub async fn handle(
    State(state): State<Arc<AppState>>,
    q: Query<GetLogsQuery>,
    req: Request<Body>,
) -> impl IntoResponse {
    let ws = match WebSocketUpgrade::from_request(req, &state).await {
        Ok(ws) => ws,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                "the /logs endpoint requires websocket upgrade",
            )
                .into_response();
        }
    };

    ws.on_failed_upgrade(|err| {
        warn!("ws upgrade error: {}", err);
    })
    .on_upgrade(move |mut socket| async move {
        let mut rx = state.log_source_tx.subscribe();
        let level = q.level.unwrap_or(LogLevel::Info);

        loop {
            let event = match rx.recv().await {
                Ok(event) => event,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    debug!("log stream lagged, skipped {} events", skipped);
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };

            if !should_send(event.level, level) {
                continue;
            }

            let body = match serde_json::to_string(&event) {
                Ok(body) => body,
                Err(err) => {
                    warn!("serialize log event failed: {}", err);
                    continue;
                }
            };

            if let Err(err) = socket.send(Message::Text(body.into())).await {
                debug!("send log event failed: {}", err);
                break;
            }
        }
    })
}

fn should_send(event: LogLevel, threshold: LogLevel) -> bool {
    rank(event) >= rank(threshold)
}

fn rank(level: LogLevel) -> u8 {
    match level {
        LogLevel::Trace => 0,
        LogLevel::Debug => 1,
        LogLevel::Info => 2,
        LogLevel::Warning => 3,
        LogLevel::Error => 4,
    }
}
