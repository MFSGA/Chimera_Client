use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    Router,
    routing::{get, post},
};

use http::{Method, header};
use tokio::sync::{Mutex, broadcast::Sender};
use tower::ServiceBuilder;
use tower_http::{
    cors::{AllowOrigin, Any, CorsLayer},
    services::ServeDir,
    trace::TraceLayer,
};
use tracing::{debug, error, info, warn};

use crate::{
    GlobalState,
    app::{
        api::{AppState, handlers, ipc},
        dispatcher::{self, StatisticsManager},
        dns::{ThreadSafeDNSResolver, config::DNSListenAddr},
        inbound::manager::InboundManager,
        logging::LogEvent,
        outbound::manager::ThreadSafeOutboundManager,
        profile::ThreadSafeCacheFile,
        router::ThreadSafeRouter,
    },
    config::internal::config::Controller,
    runner::Runner,
};

pub struct ApiRunner {
    controller_cfg: Controller,
    log_source: Sender<LogEvent>,
    inbound_manager: Arc<InboundManager>,
    dispatcher: Arc<dispatcher::Dispatcher>,
    global_state: Arc<Mutex<GlobalState>>,
    dns_resolver: ThreadSafeDNSResolver,
    outbound_manager: ThreadSafeOutboundManager,
    statistics_manager: Arc<StatisticsManager>,
    cache_store: ThreadSafeCacheFile,
    router: ThreadSafeRouter,
    cwd: String,

    cancellation_token: tokio_util::sync::CancellationToken,
    dns_listen_addr: DNSListenAddr,
    dns_enabled: bool,
    task:
        std::sync::Mutex<Option<tokio::task::JoinHandle<Result<(), crate::Error>>>>,
}

impl ApiRunner {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        controller_cfg: Controller,
        log_source: Sender<LogEvent>,
        inbound_manager: Arc<InboundManager>,
        dispatcher: Arc<dispatcher::Dispatcher>,
        global_state: Arc<Mutex<GlobalState>>,
        dns_resolver: ThreadSafeDNSResolver,
        outbound_manager: ThreadSafeOutboundManager,
        statistics_manager: Arc<StatisticsManager>,
        cache_store: ThreadSafeCacheFile,
        router: ThreadSafeRouter,
        cwd: String,
        cancellation_token: Option<tokio_util::sync::CancellationToken>,
        dns_listen_addr: DNSListenAddr,
        dns_enabled: bool,
    ) -> Self {
        Self {
            controller_cfg,
            log_source,
            inbound_manager,
            dispatcher,
            global_state,
            dns_resolver,
            outbound_manager,
            statistics_manager,
            cache_store,
            router,
            cwd,
            cancellation_token: cancellation_token.unwrap_or_default(),
            dns_listen_addr,
            dns_enabled,
            task: std::sync::Mutex::new(None),
        }
    }
}

impl Runner for ApiRunner {
    fn run_async(&self) {
        let inbound_manager = self.inbound_manager.clone();
        let dispatcher = self.dispatcher.clone();
        let global_state = self.global_state.clone();
        let dns_resolver = self.dns_resolver.clone();
        let outbound_manager = self.outbound_manager.clone();
        let statistics_manager = self.statistics_manager.clone();
        let cache_store = self.cache_store.clone();
        let controller_cfg = self.controller_cfg.clone();
        let router = self.router.clone();
        let cwd = self.cwd.clone();
        let dns_listen_addr = self.dns_listen_addr.clone();
        let dns_enabled = self.dns_enabled;
        let cancellation_token = self.cancellation_token.clone();

        tracing::debug!("API controller configuration: {:?}", controller_cfg);
        let ipc_addr = controller_cfg.external_controller_ipc;
        let tcp_addr = controller_cfg.external_controller;

        let origins: AllowOrigin = controller_cfg
            .cors_allow_origins
            .as_ref()
            .map(|origins| {
                origins
                    .iter()
                    .filter_map(|value| match value.parse() {
                        Ok(origin) => Some(origin),
                        Err(err) => {
                            warn!(
                                "ignored invalid CORS origin '{}': {}",
                                value, err
                            );
                            None
                        }
                    })
                    .collect::<Vec<_>>()
                    .into()
            })
            .unwrap_or_else(|| Any.into());

        let cors = CorsLayer::new()
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                // todo: decide if we want to allow DELETE method
                Method::DELETE,
            ])
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
            .allow_private_network(true)
            .allow_origin(origins);

        let app_state = Arc::new(AppState {
            log_source_tx: self.log_source.clone(),
            statistics_manager: statistics_manager.clone(),
        });

        let handle = tokio::spawn(async move {
            info!("Starting API server");
            let router = Router::new()
                .route("/", get(handlers::hello::handle))
                .route("/traffic", get(handlers::traffic::handle))
                .route("/version", get(handlers::version::handle))
                .route("/logs", get(handlers::logs::handle))
                .route("/memory", get(handlers::memory::handle))
                .route("/restart", post(handlers::restart::handle))
                .nest(
                    "/connections",
                    handlers::connection::routes(statistics_manager),
                )
                .nest(
                    "/configs",
                    handlers::config::routes(
                        inbound_manager.clone(),
                        dispatcher.clone(),
                        global_state.clone(),
                        dns_resolver.clone(),
                        dns_listen_addr,
                        dns_enabled,
                    ),
                )
                .nest(
                    "/proxies",
                    handlers::proxy::routes(outbound_manager.clone(), cache_store),
                )
                .nest(
                    "/providers/proxies",
                    handlers::provider::routes(outbound_manager.clone()),
                )
                .nest("/group", handlers::group::routes(outbound_manager.clone()))
                .nest("/dns", handlers::dns::routes(dns_resolver.clone()))
                .nest("/rules", handlers::rule::routes(router))
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
                        router_clone
                            .into_make_service_with_connect_info::<SocketAddr>(),
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

            // Handle IPC listening
            let ipc_fut = ipc_addr.as_ref().map(|ipc_path| {
                let ipc_path = ipc_path.clone();
                async move { ipc::serve_ipc(router, &ipc_path).await }
            });

            let result = match (tcp_fut, ipc_fut) {
                (Some(tcp), Some(ipc)) => {
                    tokio::select! {
                        _ = cancellation_token.cancelled() => {
                            debug!("API server shutdown signal received");
                            Ok(())
                        }
                        result = tcp => result,
                        result = ipc => result,
                    }
                }
                (Some(tcp), None) => {
                    tokio::select! {
                        _ = cancellation_token.cancelled() => {
                            debug!("API server shutdown signal received");
                            Ok(())
                        }
                        result = tcp => result,
                    }
                }
                (None, Some(ipc)) => {
                    tokio::select! {
                        _ = cancellation_token.cancelled() => {
                            debug!("API server shutdown signal received");
                            Ok(())
                        }
                        result = ipc => result,
                    }
                }
                (None, None) => {
                    cancellation_token.cancelled().await;
                    debug!("API server shutdown signal received");
                    Ok(())
                }
            };

            if let Err(err) = &result {
                error!("API server task exited with error: {}", err);
            }

            result
        });

        let mut task = self.task.lock().unwrap();
        *task = Some(handle);
    }

    fn shutdown(&self) {
        info!("Shutting down API server");
        self.cancellation_token.cancel();
    }

    fn join(&self) -> futures::future::BoxFuture<'_, Result<(), crate::Error>> {
        let handle = self.task.lock().unwrap().take();
        Box::pin(async move {
            match handle {
                Some(handle) => handle.await.map_err(|err| {
                    crate::Error::Operation(format!("api runner join error: {err}"))
                })?,
                None => Ok(()),
            }
        })
    }
}
