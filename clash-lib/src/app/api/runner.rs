use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    Router, ServiceExt, middleware,
    response::Redirect,
    routing::{get, post},
};

use http::{HeaderValue, Method, header};
use tokio::sync::{Mutex, broadcast::Sender};
use tower::{Layer, ServiceBuilder, util::MapRequestLayer};
use tower_http::{
    cors::{AllowOrigin, Any, CorsLayer},
    services::ServeDir,
    trace::TraceLayer,
};
use tracing::{debug, error, info, warn};

use crate::{
    GlobalState,
    app::{
        api::{AppState, handlers, ipc, middlewares, websocket},
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
    ipv6_allowed: bool,
    task:
        std::sync::Mutex<Option<tokio::task::JoinHandle<Result<(), crate::Error>>>>,
}

fn build_cors_layer(configured_origins: Option<&[String]>) -> (CorsLayer, usize) {
    let mut allow_any_origin = false;
    let mut valid_origins = Vec::new();

    for value in configured_origins.unwrap_or_default() {
        if value == "*" {
            allow_any_origin = true;
            continue;
        }

        if value == "null" {
            valid_origins.push(HeaderValue::from_static("null"));
            continue;
        }

        let uri = match value.parse::<http::Uri>() {
            Ok(uri) => uri,
            Err(err) => {
                warn!("ignored invalid CORS origin '{}': {}", value, err);
                continue;
            }
        };
        let (Some(scheme), Some(authority)) = (uri.scheme(), uri.authority()) else {
            warn!(
                "ignored invalid CORS origin '{}': expected scheme://authority",
                value
            );
            continue;
        };
        if uri.path() != "/" || uri.query().is_some() {
            warn!(
                "ignored invalid CORS origin '{}': paths and queries are not allowed",
                value
            );
            continue;
        }

        let normalized = format!("{scheme}://{authority}");
        match normalized.parse::<HeaderValue>() {
            Ok(origin) => valid_origins.push(origin),
            Err(err) => warn!("ignored invalid CORS origin '{}': {}", value, err),
        }
    }

    let valid_origin_count = valid_origins.len() + usize::from(allow_any_origin);
    let cors = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);

    if allow_any_origin {
        (
            cors.allow_private_network(true).allow_origin(Any),
            valid_origin_count,
        )
    } else if valid_origins.is_empty() {
        (cors, 0)
    } else {
        (
            cors.allow_private_network(true)
                .allow_origin(AllowOrigin::from(valid_origins)),
            valid_origin_count,
        )
    }
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
        ipv6_allowed: bool,
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
            ipv6_allowed,
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
        let ipv6_allowed = self.ipv6_allowed;
        let cancellation_token = self.cancellation_token.clone();

        tracing::debug!("API controller configuration: {:?}", controller_cfg);
        let ipc_addr = controller_cfg.external_controller_ipc;
        let tcp_addr = controller_cfg.external_controller;

        let (cors, valid_cors_origin_count) =
            build_cors_layer(controller_cfg.cors_allow_origins.as_deref());
        if valid_cors_origin_count == 0 {
            debug!(
                "cross-origin browser access to the API is disabled; configure \
                 cors-allow-origins to enable it"
            );
        }

        let app_state = Arc::new(AppState {
            log_source_tx: self.log_source.clone(),
            statistics_manager: statistics_manager.clone(),
        });

        let handle = tokio::spawn(async move {
            info!("Starting API server");
            let mut router = Router::new()
                .route("/", get(handlers::hello::handle))
                .route("/traffic", get(handlers::traffic::handle))
                .route("/user-stats", get(handlers::user_stats::handle))
                .route("/version", get(handlers::version::handle))
                .route("/logs", get(handlers::logs::handle))
                .route("/memory", get(handlers::memory::handle))
                .route("/restart", post(handlers::restart::handle))
                .nest("/ws", websocket::routes(app_state.clone()))
                .nest(
                    "/connections",
                    handlers::connection::routes(statistics_manager.clone()),
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
                        ipv6_allowed,
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
                .nest(
                    "/providers/rules",
                    handlers::provider::rule_routes(router.clone()),
                )
                .nest("/group", handlers::group::routes(outbound_manager.clone()))
                .nest("/flows", handlers::flows::routes(statistics_manager))
                .nest("/dns", handlers::dns::routes(dns_resolver.clone()))
                .nest("/rules", handlers::rule::routes(router))
                .layer(middleware::from_fn(
                    middlewares::fix_json_content_type::fix_content_type,
                ))
                .route_layer(cors)
                .with_state(app_state.clone())
                .layer(ServiceBuilder::new().layer(
                    TraceLayer::new_for_http().make_span_with(
                        |request: &http::Request<axum::body::Body>| {
                            tracing::debug_span!(
                                "http_request",
                                method = %request.method(),
                                path = %request.uri().path()
                            )
                        },
                    ),
                ));

            if let Some(external_ui) = controller_cfg.external_ui.clone() {
                router = router
                    .route("/ui", get(|| async { Redirect::to("/ui/") }))
                    .nest_service(
                        "/ui/",
                        ServeDir::new(PathBuf::from(cwd).join(external_ui)),
                    );
            } else {
                #[cfg(feature = "dashboard")]
                {
                    use super::embedded_dashboard;
                    router = router
                        .route("/ui", get(|| async { Redirect::to("/ui/") }))
                        .route("/ui/", get(embedded_dashboard::serve_index))
                        .route("/ui/{*path}", get(embedded_dashboard::serve_asset));
                }
            }

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
                let auth_secret = controller_cfg.secret.clone().unwrap_or_default();
                let router_clone = router.clone().route_layer(
                    middlewares::auth::AuthMiddlewareLayer::new(auth_secret),
                );
                let router_clone = MapRequestLayer::new(
                    middlewares::websocket_uri_rewrite::rewrite_websocket_uri,
                )
                .layer(router_clone);
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
                        if !addr.ip().is_loopback() && valid_cors_origin_count == 0 {
                            error!(
                                "API server is listening on a non-loopback address \
                                 without any valid CORS origins. This is insecure!"
                            );
                            error!(
                                "Please configure at least one valid \
                                 cors-allow-origins entry."
                            );
                            return Err(crate::Error::Operation(
                                "API server is listening on a non-loopback address \
                                 without any valid CORS origins"
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, routing::get};
    use http::{Request, header};
    use tower::ServiceExt as _;

    async fn call_with_cors(
        configured_origins: Option<&[String]>,
        request: Request<Body>,
    ) -> http::Response<Body> {
        let (cors, _) = build_cors_layer(configured_origins);
        Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(cors)
            .oneshot(request)
            .await
            .expect("CORS test router should respond")
    }

    #[tokio::test]
    async fn cors_is_disabled_without_explicit_origins() {
        let request = Request::builder()
            .uri("/")
            .header(header::ORIGIN, "https://evil.example")
            .body(Body::empty())
            .expect("request should build");

        let response = call_with_cors(None, request).await;

        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
    }

    #[tokio::test]
    async fn configured_origin_enables_cors_and_private_network_access() {
        let origins = vec!["https://dashboard.example".to_owned()];
        let request = Request::builder()
            .method(Method::OPTIONS)
            .uri("/")
            .header(header::ORIGIN, "https://dashboard.example")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
            .header("access-control-request-private-network", "true")
            .body(Body::empty())
            .expect("request should build");

        let response = call_with_cors(Some(&origins), request).await;

        assert_eq!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .expect("configured origin should be allowed"),
            "https://dashboard.example"
        );
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-private-network")
                .expect("private network access should be explicitly allowed"),
            "true"
        );
    }

    #[test]
    fn invalid_origins_do_not_count_as_configured() {
        let origins = vec!["https://example.com/path".to_owned()];
        let (_, valid_origin_count) = build_cors_layer(Some(&origins));

        assert_eq!(valid_origin_count, 0);
    }
}
