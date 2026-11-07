use std::sync::Arc;

use axum::{
    Json, Router,
    body::Body,
    extract::{
        FromRequest, Path, Query, Request, State, WebSocketUpgrade, ws::Message,
    },
    response::IntoResponse,
    routing::{delete, get},
};
use http::HeaderMap;
use serde::Deserialize;
use std::time::Duration;
use tracing::{debug, warn};

use crate::app::{
    api::{AppState, handlers::utils::is_request_websocket},
    dispatcher::StatisticsManager,
};

#[derive(Clone)]
struct ConnectionState {
    statistics_manager: Arc<StatisticsManager>,
}

pub fn routes(statistics_manager: Arc<StatisticsManager>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(get_connections).delete(close_all_connection))
        .route("/summary", get(get_connection_summary))
        .route("/{id}", delete(close_connection))
        .with_state(ConnectionState { statistics_manager })
}

#[derive(Deserialize)]
pub struct GetConnectionsQuery {
    pub interval: Option<String>,
}

impl GetConnectionsQuery {
    const DEFAULT_INTERVAL_MS: u64 = 1_000;
    // Avoid effectively permanent WebSocket timers from unreasonable values.
    const MAX_INTERVAL_MS: u64 = 86_400_000;

    pub fn interval_ms(&self) -> Option<u64> {
        let interval_ms = match self.interval.as_deref() {
            Some("") => Self::DEFAULT_INTERVAL_MS,
            Some(interval) => interval.parse().ok()?,
            None => Self::DEFAULT_INTERVAL_MS,
        };
        if interval_ms == 0 || interval_ms > Self::MAX_INTERVAL_MS {
            return None;
        }

        Some(interval_ms)
    }
}

async fn get_connections(
    headers: HeaderMap,
    State(state): State<ConnectionState>,
    req: Request<Body>,
) -> impl IntoResponse {
    if !is_request_websocket(&headers) {
        let mgr = state.statistics_manager.clone();
        let snapshot = mgr.snapshot().await;
        return Json(snapshot).into_response();
    }

    let query = match Query::<GetConnectionsQuery>::try_from_uri(req.uri()) {
        Ok(Query(query)) => query,
        Err(err) => return err.into_response(),
    };
    let Some(interval_ms) = query.interval_ms() else {
        return (
            http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "message": "Body invalid" })),
        )
            .into_response();
    };

    let ws = match WebSocketUpgrade::from_request(req, &state).await {
        Ok(ws) => ws,
        Err(e) => {
            warn!("ws upgrade error: {}", e);
            return e.into_response();
        }
    };

    ws.on_failed_upgrade(|e| {
        warn!("ws upgrade error: {}", e);
    })
    .on_upgrade(move |mut socket| async move {
        let mgr = state.statistics_manager.clone();

        loop {
            let snapshot = mgr.snapshot().await;
            let body = match serde_json::to_string(&snapshot) {
                Ok(body) => body,
                Err(err) => {
                    warn!("failed to serialize connection snapshot: {}", err);
                    continue;
                }
            };

            if let Err(e) = socket.send(Message::Text(body.into())).await {
                // likely client gone
                debug!("ws send error: {}", e);
                break;
            }

            tokio::time::sleep(Duration::from_millis(interval_ms)).await;
        }
    })
}

async fn get_connection_summary(
    State(state): State<ConnectionState>,
) -> impl IntoResponse {
    Json(state.statistics_manager.summary().await)
}

async fn close_connection(
    State(state): State<ConnectionState>,
    Path(id): Path<uuid::Uuid>,
) -> impl IntoResponse {
    let mgr = state.statistics_manager;
    mgr.close(id).await;
    format!("connection {id} closed").into_response()
}

async fn close_all_connection(
    State(state): State<ConnectionState>,
) -> impl IntoResponse {
    let mgr = state.statistics_manager;
    mgr.close_all().await;
    "all connections closed".into_response()
}
