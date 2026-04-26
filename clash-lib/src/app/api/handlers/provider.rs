use std::{collections::HashMap, sync::Arc, time::Duration};

use axum::{
    Extension, Router,
    extract::{Path, Query, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;

use crate::{
    app::{
        api::AppState, outbound::manager::ThreadSafeOutboundManager,
        remote_content_manager::providers::proxy_provider::ThreadSafeProxyProvider,
    },
    proxy::AnyOutboundHandler,
};

#[derive(Clone)]
struct ProviderState {
    outbound_manager: ThreadSafeOutboundManager,
}

pub fn routes(outbound_manager: ThreadSafeOutboundManager) -> Router<Arc<AppState>> {
    let state = ProviderState { outbound_manager };
    Router::new()
        .route("/", get(get_providers))
        .nest(
            "/{provider_name}",
            Router::new()
                .route("/", get(get_provider).put(update_provider))
                .route("/healthcheck", get(provider_healthcheck))
                .nest(
                    "/{proxy_name}",
                    Router::new()
                        .route("/", get(get_proxy))
                        .route("/healthcheck", get(get_proxy_delay))
                        .layer(middleware::from_fn_with_state(
                            state.clone(),
                            find_proxy_provider_proxy_by_name,
                        ))
                        .with_state(state.clone()),
                )
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    find_proxy_provider_by_name,
                ))
                .with_state(state.clone()),
        )
        .with_state(state)
}

async fn get_providers(State(state): State<ProviderState>) -> impl IntoResponse {
    let outbound_manager = state.outbound_manager.clone();
    let mut res = HashMap::new();
    let mut providers = HashMap::new();

    for (name, provider) in outbound_manager.get_proxy_providers() {
        let provider = provider.read().await;
        let proxies = provider.proxies().await;
        let proxies = futures::future::join_all(
            proxies
                .iter()
                .map(|proxy| outbound_manager.get_proxy(proxy)),
        )
        .await;
        let mut provider_map = provider.as_map().await;
        provider_map.insert("proxies".to_owned(), Box::new(proxies));
        providers.insert(name, provider_map);
    }

    res.insert("providers".to_owned(), providers);
    axum::response::Json(res)
}

#[derive(Deserialize)]
struct ProviderNamePath {
    provider_name: String,
}

async fn find_proxy_provider_by_name(
    State(state): State<ProviderState>,
    Path(ProviderNamePath { provider_name }): Path<ProviderNamePath>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    match state.outbound_manager.get_proxy_provider(&provider_name) {
        Some(provider) => {
            req.extensions_mut().insert(provider);
            next.run(req).await
        }
        None => (
            StatusCode::NOT_FOUND,
            format!("proxy provider {provider_name} not found"),
        )
            .into_response(),
    }
}

async fn get_provider(
    Extension(provider): Extension<ThreadSafeProxyProvider>,
) -> impl IntoResponse {
    let provider = provider.read().await;
    axum::response::Json(provider.as_map().await)
}

async fn update_provider(
    Extension(provider): Extension<ThreadSafeProxyProvider>,
) -> impl IntoResponse {
    let provider = provider.read().await;
    match provider.update().await {
        Ok(()) => (StatusCode::ACCEPTED, "provider update started").into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "update proxy provider {} failed with error {}",
                provider.name(),
                err
            ),
        )
            .into_response(),
    }
}

async fn provider_healthcheck(
    Extension(provider): Extension<ThreadSafeProxyProvider>,
) -> impl IntoResponse {
    let provider = provider.read().await;
    provider.healthcheck().await;

    (StatusCode::ACCEPTED, "provider healthcheck")
}

#[derive(Deserialize)]
struct ProviderProxyPath {
    proxy_name: String,
}

async fn find_proxy_provider_proxy_by_name(
    Extension(provider): Extension<ThreadSafeProxyProvider>,
    Path(ProviderProxyPath { proxy_name }): Path<ProviderProxyPath>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let provider = provider.read().await;
    let proxies = provider.proxies().await;
    let proxy = proxies.iter().find(|proxy| proxy.name() == proxy_name);

    if let Some(proxy) = proxy {
        req.extensions_mut().insert(proxy.clone());
        next.run(req).await
    } else {
        (
            StatusCode::NOT_FOUND,
            format!(
                "proxy {} not found in provider {}",
                proxy_name,
                provider.name()
            ),
        )
            .into_response()
    }
}

async fn get_proxy(
    Extension(proxy): Extension<AnyOutboundHandler>,
    State(state): State<ProviderState>,
) -> impl IntoResponse {
    axum::response::Json(state.outbound_manager.get_proxy(&proxy).await)
}

#[derive(Deserialize)]
struct DelayRequest {
    url: String,
    timeout: u16,
}

async fn get_proxy_delay(
    State(state): State<ProviderState>,
    Extension(proxy): Extension<AnyOutboundHandler>,
    Query(q): Query<DelayRequest>,
) -> impl IntoResponse {
    let timeout = Duration::from_millis(q.timeout.into());
    let proxy_name = proxy.name().to_owned();
    let result = state
        .outbound_manager
        .url_test(&vec![proxy], &q.url, timeout)
        .await;

    match result.first().expect("url_test always returns one result") {
        Ok((actual, overall)) => {
            let mut res = HashMap::new();
            res.insert("delay".to_owned(), actual.as_millis());
            res.insert("overall".to_owned(), overall.as_millis());
            axum::response::Json(res).into_response()
        }
        Err(err) => (
            StatusCode::BAD_REQUEST,
            format!("get delay for {proxy_name} failed with error: {err}"),
        )
            .into_response(),
    }
}
