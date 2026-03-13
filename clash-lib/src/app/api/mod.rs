use std::{net::SocketAddr, sync::Arc};

use axum::{
    Router,
    routing::{get, post},
};
use http::{Method, header};
use tokio::sync::{Mutex, broadcast::Sender};
use tower::ServiceBuilder;
use tower_http::{
    cors::{AllowOrigin, Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::{error, info, warn};

use crate::{
    GlobalState, Runner,
    app::{
        dispatcher::{Dispatcher, StatisticsManager},
        dns::ThreadSafeDNSResolver,
        inbound::manager::InboundManager,
        logging::LogEvent,
        outbound::manager::ThreadSafeOutboundManager,
        router::ThreadSafeRouter,
    },
    config::internal::config::Controller,
};

mod handlers;
mod ipc;

pub struct AppState {
    log_source_tx: Sender<LogEvent>,
    statistics_manager: Arc<StatisticsManager>,
}

#[allow(clippy::too_many_arguments)]
pub fn get_api_runner(
    controller_cfg: Controller,
    log_source: Sender<LogEvent>,
    statistics_manager: Arc<StatisticsManager>,
    inbound_manager: Arc<InboundManager>,
    dispatcher: Arc<Dispatcher>,
    global_state: Arc<Mutex<GlobalState>>,
    dns_resolver: ThreadSafeDNSResolver,
    outbound_manager: ThreadSafeOutboundManager,
    router_state: ThreadSafeRouter,
    _cwd: String,
) -> Option<Runner> {
    tracing::debug!("API controller configuration: {:?}", controller_cfg);
    let tcp_addr = controller_cfg
        .external_controller
        .clone()
        .filter(|value| !value.is_empty());
    let ipc_addr = controller_cfg.external_controller_ipc.clone();

    if tcp_addr.is_none() && ipc_addr.is_none() {
        return None;
    }

    let origins: AllowOrigin = controller_cfg
        .cors_allow_origins
        .as_ref()
        .map(|origins| {
            origins
                .iter()
                .filter_map(|value| match value.parse() {
                    Ok(origin) => Some(origin),
                    Err(err) => {
                        warn!("ignored invalid CORS origin '{}': {}", value, err);
                        None
                    }
                })
                .collect::<Vec<_>>()
                .into()
        })
        .unwrap_or_else(|| Any.into());

    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::PATCH])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .allow_private_network(true)
        .allow_origin(origins);

    let app_state = Arc::new(AppState {
        log_source_tx: log_source,
        statistics_manager: statistics_manager.clone(),
    });

    let runner = async move {
        info!("Starting API server");
        let router = Router::new()
            .route("/", get(handlers::hello::handle))
            .route("/traffic", get(handlers::traffic::handle))
            .route("/version", get(handlers::version::handle))
            .route("/logs", get(handlers::logs::handle))
            .route("/memory", get(handlers::memory::handle))
            .route("/restart", post(handlers::restart::handle))
            .nest("/connections", handlers::connections::routes())
            .nest(
                "/configs",
                handlers::config::routes(
                    inbound_manager.clone(),
                    dispatcher.clone(),
                    global_state.clone(),
                    dns_resolver.clone(),
                ),
            )
            .nest(
                "/proxies",
                handlers::proxy::routes(outbound_manager.clone()),
            )
            .nest("/rules", handlers::rule::routes(router_state.clone()))
            .layer(cors)
            .with_state(app_state.clone())
            .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()));

        // Handle TCP listening
        let tcp_fut = if let Some(bind_addr) = tcp_addr {
            let bind_addr = if bind_addr.starts_with(':') {
                info!(
                    "TCP API Server address not supplied, listening on `localhost`"
                );
                format!("127.0.0.1{bind_addr}")
            } else {
                bind_addr
            };
            let router_clone = router.clone();
            Some(async move {
                info!("Starting API server on TCP address {bind_addr}");
                let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
                // TCP related security checks
                if let Ok(addr) = listener.local_addr() {
                    if !addr.ip().is_loopback()
                        && controller_cfg.secret.unwrap_or_default().is_empty()
                    {
                        error!(
                            "API server is listening on a non-loopback address \
                             without a secret. This is insecure!"
                        );
                        error!(
                            "Please set a secret in the configuration to secure \
                             the API server."
                        );
                        return Err(crate::Error::Operation(
                            "API server is listening on a non-loopback address \
                             without a secret. This is insecure!"
                                .to_string(),
                        ));
                    }
                    if !addr.ip().is_loopback()
                        && controller_cfg.cors_allow_origins.is_none()
                    {
                        error!(
                            "API server is listening on a non-loopback address \
                             without CORS origins configured. This is insecure!"
                        );
                        error!(
                            "Please set CORS origins in the configuration to \
                             secure the API server."
                        );
                        return Err(crate::Error::Operation(
                            "API server is listening on a non-loopback address \
                             without CORS origins configured. This is insecure!"
                                .to_string(),
                        ));
                    }
                }
                axum::serve(
                    listener,
                    router_clone.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await
                .map_err(|x| {
                    error!("TCP API server error: {}", x);
                    crate::Error::Operation(format!("API server error: {x}"))
                })
            })
        } else {
            None
        };

        let ipc_fut = ipc_addr
            .map(|ipc_path| async move { ipc::serve_ipc(router, &ipc_path).await });

        match (tcp_fut, ipc_fut) {
            (Some(tcp), Some(ipc)) => {
                tokio::select! {
                    result = tcp => result,
                    result = ipc => result,
                }
            }
            (Some(tcp), None) => tcp.await,
            (None, Some(ipc)) => ipc.await,
            (None, None) => Ok(()),
        }
    };

    Some(Box::pin(runner))
}
