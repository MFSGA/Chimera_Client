use std::{collections::HashMap, sync::Arc};

use axum::{Router, extract::State, response::IntoResponse, routing::get};

use crate::app::{api::AppState, outbound::manager::ThreadSafeOutboundManager};

#[derive(Clone)]
struct ProxyState {
    outbound_manager: ThreadSafeOutboundManager,
}

pub fn routes(outbound_manager: ThreadSafeOutboundManager) -> Router<Arc<AppState>> {
    let state = ProxyState { outbound_manager };

    Router::new().route("/", get(get_proxies)).with_state(state)
}

async fn get_proxies(State(state): State<ProxyState>) -> impl IntoResponse {
    let outbound_manager = state.outbound_manager.clone();
    let mut res = HashMap::new();
    let proxies = outbound_manager.get_proxies().await;
    res.insert("proxies".to_owned(), proxies);
    axum::response::Json(res)
}
