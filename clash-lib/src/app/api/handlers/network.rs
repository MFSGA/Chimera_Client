use std::sync::Arc;

use axum::{Json, Router, extract::State, routing::post};
use http::StatusCode;
use serde::Serialize;

use crate::app::{api::AppState, outbound::manager::ThreadSafeOutboundManager};

#[derive(Clone)]
struct NetworkState {
    outbound_manager: ThreadSafeOutboundManager,
}

pub fn routes(outbound_manager: ThreadSafeOutboundManager) -> Router<Arc<AppState>> {
    Router::new()
        .route("/reset", post(reset_network))
        .with_state(NetworkState { outbound_manager })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NetworkResetResponse {
    pub(crate) connection_pools_reset: u32,
}

async fn reset_network(
    State(state): State<NetworkState>,
) -> Result<Json<NetworkResetResponse>, (StatusCode, String)> {
    let connection_pools_reset = state
        .outbound_manager
        .reset_connection_pools()
        .await
        .map_err(internal_error)?;

    Ok(Json(NetworkResetResponse {
        connection_pools_reset,
    }))
}

fn internal_error(error: impl ToString) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::NetworkResetResponse;

    #[test]
    fn response_uses_stable_camel_case_field() {
        let value = serde_json::to_value(NetworkResetResponse {
            connection_pools_reset: 1,
        })
        .unwrap();

        assert_eq!(value["connectionPoolsReset"], 1);
    }
}
