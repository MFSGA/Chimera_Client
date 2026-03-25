use std::{collections::HashMap, sync::Arc, time::Duration};

use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::IntoResponse,
    routing::{get, put},
};
use http::HeaderMap;
use serde::Deserialize;

use crate::{
    app::{api::AppState, outbound::manager::ThreadSafeOutboundManager},
    proxy::AnyOutboundHandler,
};

#[derive(Clone)]
struct ProxyState {
    outbound_manager: ThreadSafeOutboundManager,
}

pub fn routes(outbound_manager: ThreadSafeOutboundManager) -> Router<Arc<AppState>> {
    let state = ProxyState { outbound_manager };

    Router::new()
        .route("/", get(get_proxies))
        .route("/{group}", put(update_proxy))
        .route("/{name}/delay", get(get_proxy_delay))
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

#[derive(Deserialize)]
struct DelayRequest {
    url: String,
    timeout: u16,
}

async fn get_proxy_delay(
    State(state): State<ProxyState>,
    Extension(proxy): Extension<AnyOutboundHandler>,
    Query(q): Query<DelayRequest>,
) -> impl IntoResponse {
    let outbound_manager = state.outbound_manager.clone();
    let timeout = Duration::from_millis(q.timeout.into());
    let n = proxy.name().to_owned();
    let mut headers = HeaderMap::new();
    headers.insert(header::CONNECTION, "close".parse().unwrap());

    let (actual, overall) = if let Some(group) = proxy.try_as_group_handler() {
        let latency_test_url = group.get_latency_test_url();
        let proxies = group.get_proxies().await;
        let results = outbound_manager
            .url_test(
                &[vec![proxy], proxies].concat(),
                &latency_test_url.unwrap_or(q.url),
                timeout,
            )
            .await;
        match results.first().unwrap() {
            Ok(latency) => *latency,
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    headers,
                    format!("get delay for {n} failed with error: {err}"),
                )
                    .into_response();
            }
        }
    } else {
        let result = outbound_manager
            .url_test(&vec![proxy], &q.url, timeout)
            .await;
        match result.first().unwrap() {
            Ok(latency) => *latency,
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    headers,
                    format!("get delay for {n} failed with error: {err}"),
                )
                    .into_response();
            }
        }
    };

    let mut r = HashMap::new();
    r.insert("delay".to_owned(), actual.as_millis());
    r.insert("overall".to_owned(), overall.as_millis());
    (headers, axum::response::Json(r)).into_response()
}
