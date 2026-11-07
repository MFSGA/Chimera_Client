use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    extract::{
        Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use serde_json::json;
use tracing::{debug, warn};

use crate::app::api::{
    AppState,
    handlers::{
        connection::GetConnectionsQuery, flows::ws_handle as flows_ws_handle,
        memory::GetMemoryResponse,
    },
};

pub fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/connections", get(connections))
        .route("/traffic", get(traffic))
        .route("/memory", get(memory))
        .route("/logs", get(log))
        .route("/flows", get(flows_ws_handle))
        .with_state(state)
}

pub async fn connections(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    query: Query<GetConnectionsQuery>,
) -> impl IntoResponse {
    let Some(interval_ms) = query.interval_ms() else {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({ "message": "Body invalid" })),
        )
            .into_response();
    };

    let callback = async move |mut socket: WebSocket| {
        let mut interval = tokio::time::interval(Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;
            let snapshot = state.statistics_manager.snapshot().await;
            let body = match serde_json::to_string(&snapshot) {
                Ok(body) => body,
                Err(err) => {
                    warn!("failed to serialize connection snapshot: {}", err);
                    continue;
                }
            };

            if let Err(err) = socket.send(Message::Text(body.into())).await {
                debug!("ws connection closed with error: {}", err);
                break;
            }
        }
    };

    ws.on_failed_upgrade(|err| warn!("ws upgrade error: {}", err))
        .on_upgrade(async move |socket| callback(socket).await)
}

pub async fn traffic(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let callback = async move |mut socket: WebSocket| {
        let interval = Duration::from_secs(1);
        let start = tokio::time::Instant::now() + interval;
        let mut interval = tokio::time::interval_at(start, interval);

        loop {
            interval.tick().await;
            let (up, down) = state.statistics_manager.now();
            let (up_total, down_total) = state.statistics_manager.total();
            let response = json!({
                "up": up,
                "down": down,
                "upTotal": up_total,
                "downTotal": down_total,
            })
            .to_string();

            if let Err(err) = socket.send(Message::Text(response.into())).await {
                debug!("ws connection closed with error: {}", err);
                break;
            }
        }
    };

    ws.on_failed_upgrade(|err| warn!("ws upgrade error: {}", err))
        .on_upgrade(async move |socket| callback(socket).await)
}

pub async fn memory(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let callback = async move |mut socket: WebSocket| {
        let interval = Duration::from_secs(1);
        let start = tokio::time::Instant::now() + interval;
        let mut interval = tokio::time::interval_at(start, interval);
        let mut first = true;

        loop {
            interval.tick().await;
            let snapshot = GetMemoryResponse {
                inuse: if first {
                    first = false;
                    0
                } else {
                    state.statistics_manager.memory_usage()
                },
                oslimit: 0,
            };

            let body = match serde_json::to_string(&snapshot) {
                Ok(body) => body,
                Err(err) => {
                    warn!("failed to serialize memory snapshot: {}", err);
                    continue;
                }
            };

            if let Err(err) = socket.send(Message::Text(body.into())).await {
                debug!("ws connection closed with error: {}", err);
                break;
            }
        }
    };

    ws.on_failed_upgrade(|err| warn!("ws upgrade error: {}", err))
        .on_upgrade(async move |socket| callback(socket).await)
}

pub async fn log(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_failed_upgrade(|err| warn!("ws upgrade error: {}", err))
        .on_upgrade(move |mut socket| async move {
            let mut rx = state.log_source_tx.subscribe();
            while let Ok(evt) = rx.recv().await {
                let body = match serde_json::to_string(&evt) {
                    Ok(body) => body,
                    Err(err) => {
                        warn!("failed to serialize log event: {}", err);
                        continue;
                    }
                };

                if let Err(err) = socket.send(Message::Text(body.into())).await {
                    warn!("ws send error: {}", err);
                    break;
                }
            }
        })
}
