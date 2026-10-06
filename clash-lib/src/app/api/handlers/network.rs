use std::sync::Arc;

use crate::{
    GlobalState,
    app::{
        api::AppState,
        network::{NetworkResetResponse, NetworkStatus},
    },
};
use axum::{Json, Router, extract::State, routing::post};
use http::StatusCode;
use serde::Deserialize;

#[derive(Clone)]
struct NetworkState {
    global: Arc<tokio::sync::Mutex<GlobalState>>,
}

pub fn routes(
    global: Arc<tokio::sync::Mutex<GlobalState>>,
) -> Router<Arc<AppState>> {
    Router::new()
        .route("/", axum::routing::get(network_status))
        .route("/reset", post(reset_network))
        .with_state(NetworkState { global })
}

pub fn status_routes(
    global: Arc<tokio::sync::Mutex<GlobalState>>,
) -> Router<Arc<AppState>> {
    Router::new()
        .route("/", axum::routing::get(network_status))
        .route(
            "/network/path-preference",
            axum::routing::get(get_path_preference)
                .put(put_path_preference)
                .delete(clear_temporary_path_preference),
        )
        .route(
            "/network/effective-paths",
            axum::routing::get(effective_paths),
        )
        .route(
            "/network/path-decision/{flow_id}",
            axum::routing::get(path_decision),
        )
        .with_state(NetworkState { global })
}

async fn network_status(State(state): State<NetworkState>) -> Json<NetworkStatus> {
    let status = state.global.lock().await.network_status.clone();
    Json(status.read().await.clone())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PathPreferenceRequest {
    priority: Vec<crate::app::flow::PathPriority>,
    ttl_ms: Option<u64>,
}

async fn get_path_preference(
    State(state): State<NetworkState>,
) -> Json<crate::app::runtime_state::PathPreferenceView> {
    let status = state.global.lock().await.network_status.clone();
    Json(status.write().await.path_preference_view())
}

async fn put_path_preference(
    State(state): State<NetworkState>,
    Json(request): Json<PathPreferenceRequest>,
) -> Result<Json<crate::app::runtime_state::PathPreferenceView>, (StatusCode, String)>
{
    let status = state.global.lock().await.network_status.clone();
    status
        .write()
        .await
        .set_path_priority(request.priority, request.ttl_ms)
        .map(Json)
        .map_err(|error| (StatusCode::UNPROCESSABLE_ENTITY, error))
}

async fn clear_temporary_path_preference(
    State(state): State<NetworkState>,
) -> Result<Json<crate::app::runtime_state::PathPreferenceView>, (StatusCode, String)>
{
    let status = state.global.lock().await.network_status.clone();
    status
        .write()
        .await
        .clear_temporary_path_priority()
        .map(Json)
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))
}

async fn effective_paths(
    State(state): State<NetworkState>,
) -> Json<serde_json::Value> {
    let status = state.global.lock().await.network_status.clone();
    Json(status.write().await.effective_paths_view())
}

async fn path_decision(
    State(state): State<NetworkState>,
    axum::extract::Path(flow_id): axum::extract::Path<String>,
) -> Result<Json<crate::app::flow::PathDecisionRecord>, (StatusCode, String)> {
    let flow_id = uuid::Uuid::parse_str(&flow_id)
        .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    let status = state.global.lock().await.network_status.clone();
    status
        .write()
        .await
        .path_decision(flow_id)
        .map(Json)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                "path decision not found or expired".to_owned(),
            )
        })
}

async fn reset_network(
    State(state): State<NetworkState>,
) -> Result<Json<NetworkResetResponse>, (StatusCode, String)> {
    let sender = state.global.lock().await.network_reset_tx.clone();
    let (done, receiver) = tokio::sync::oneshot::channel();
    tokio::time::timeout(std::time::Duration::from_secs(5), sender.send(done))
        .await
        .map_err(internal_error)?
        .map_err(internal_error)?;
    let response =
        tokio::time::timeout(std::time::Duration::from_secs(45), receiver)
            .await
            .map_err(internal_error)?
            .map_err(internal_error)?
            .map_err(internal_error)?;
    Ok(Json(response))
}

fn internal_error(error: impl ToString) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::NetworkResetResponse;

    #[test]
    fn response_uses_stable_camel_case_fields() {
        let value = serde_json::to_value(NetworkResetResponse {
            dns_transports_reset: 2,
            connection_pools_reset: 1,
        })
        .unwrap();

        assert_eq!(value["dnsTransportsReset"], 2);
        assert_eq!(value["connectionPoolsReset"], 1);
    }
}
