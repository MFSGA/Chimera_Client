use std::sync::Arc;

use axum::{
    Json, Router,
    body::Body,
    extract::{FromRequest, Query, Request, State, WebSocketUpgrade, ws::Message},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get},
};
use http::HeaderMap;
use serde::Deserialize;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::app::api::AppState;

use super::utils::is_request_websocket;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(get_connections).delete(close_all_connections))
        .route("/{id}", delete(close_connection))
}

#[derive(Deserialize)]
pub struct GetConnectionsQuery {
    interval: Option<u64>,
}

async fn get_connections(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    q: Query<GetConnectionsQuery>,
    req: Request<Body>,
) -> impl IntoResponse {
    if !is_request_websocket(headers) {
        return Json(state.statistics_manager.snapshot().await).into_response();
    }

    let ws = match WebSocketUpgrade::from_request(req, &state).await {
        Ok(ws) => ws,
        Err(err) => {
            warn!("ws upgrade error: {}", err);
            return err.into_response();
        }
    };

    ws.on_failed_upgrade(|err| {
        warn!("ws upgrade error: {}", err);
    })
    .on_upgrade(move |mut socket| async move {
        let interval = q.interval.unwrap_or(1);
        let statistics_manager = state.statistics_manager.clone();

        loop {
            let snapshot = statistics_manager.snapshot().await;
            let body = match serde_json::to_string(&snapshot) {
                Ok(body) => body,
                Err(err) => {
                    warn!("serialize connections snapshot failed: {}", err);
                    break;
                }
            };

            if let Err(err) = socket.send(Message::Text(body.into())).await {
                debug!("send connections snapshot failed: {}", err);
                break;
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
        }
    })
}

async fn close_all_connections(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    state.statistics_manager.close_all().await;
    StatusCode::NO_CONTENT
}

async fn close_connection(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> impl IntoResponse {
    match state.statistics_manager.close(id).await {
        true => StatusCode::NO_CONTENT,
        false => StatusCode::NOT_FOUND,
    }
}
