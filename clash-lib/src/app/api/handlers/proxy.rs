use std::{collections::HashMap, sync::Arc};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, put},
};
use serde::Deserialize;

use crate::app::{api::AppState, outbound::manager::ThreadSafeOutboundManager};

#[derive(Clone)]
struct ProxyState {
    outbound_manager: ThreadSafeOutboundManager,
}

pub fn routes(outbound_manager: ThreadSafeOutboundManager) -> Router<Arc<AppState>> {
    let state = ProxyState { outbound_manager };

    Router::new()
        .route("/", get(get_proxies))
        .route("/{group}", put(update_proxy))
        .with_state(state)
}

async fn get_proxies(State(state): State<ProxyState>) -> impl IntoResponse {
    let outbound_manager = state.outbound_manager.clone();
    let mut res = HashMap::new();
    let proxies = outbound_manager.get_proxies().await;
    res.insert("proxies".to_owned(), proxies);
    axum::response::Json(res)
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct UpdateProxyRequest {
    name: String,
}

async fn update_proxy(
    State(state): State<ProxyState>,
    Path(group): Path<String>,
    Json(payload): Json<UpdateProxyRequest>,
) -> impl IntoResponse {
    let outbound_manager = state.outbound_manager.clone();
    match outbound_manager.select(&group, &payload.name).await {
        Ok(_) => (
            StatusCode::ACCEPTED,
            format!("selected proxy {} for {}", payload.name, group),
        ),
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()),
    }
}
