use std::{path::PathBuf, sync::Arc};

use axum::{
    Json, Router,
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::{
    GlobalState,
    app::{
        api::AppState,
        dispatcher::Dispatcher,
        dns::ThreadSafeDNSResolver,
        inbound::manager::{InboundManager, Ports},
    },
    config::def::{self, LogLevel, RunMode},
};

#[derive(Clone)]
struct ConfigState {
    inbound_manager: Arc<InboundManager>,
    dispatcher: Arc<Dispatcher>,
    global_state: Arc<Mutex<GlobalState>>,
    dns_resolver: ThreadSafeDNSResolver,
}

pub fn routes(
    inbound_manager: Arc<InboundManager>,
    dispatcher: Arc<Dispatcher>,
    global_state: Arc<Mutex<GlobalState>>,
    dns_resolver: ThreadSafeDNSResolver,
) -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(get_configs).put(update_configs))
        .with_state(ConfigState {
            inbound_manager,
            dispatcher,
            global_state,
            dns_resolver,
        })
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct PatchConfigRequest {
    port: Option<u16>,
    socks_port: Option<u16>,
    redir_port: Option<u16>,
    tproxy_port: Option<u16>,
    mixed_port: Option<u16>,
    bind_address: Option<String>,
    mode: Option<def::RunMode>,
    log_level: Option<def::LogLevel>,
    ipv6: Option<bool>,
    allow_lan: Option<bool>,
}

async fn get_configs(State(state): State<ConfigState>) -> impl IntoResponse {
    let run_mode = state.dispatcher.get_mode().await;
    let global_state = state.global_state.lock().await;
    let dns_resolver = state.dns_resolver;
    let inbound_manager = state.inbound_manager.clone();

    let ports = state.inbound_manager.get_ports().await;

    axum::response::Json(PatchConfigRequest {
        port: ports.port,
        socks_port: ports.socks_port,
        redir_port: ports.redir_port,
        tproxy_port: ports.tproxy_port,
        mixed_port: ports.mixed_port,
        bind_address: Some(
            state.inbound_manager.get_bind_address().await.0.to_string(),
        ),

        mode: Some(run_mode),
        log_level: Some(global_state.log_level),
        ipv6: Some(dns_resolver.ipv6()),
        allow_lan: Some(inbound_manager.get_allow_lan().await),
    })
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct UpdateConfigRequest {
    path: Option<String>,
    payload: Option<String>,
}

#[derive(Deserialize)]
struct UploadConfigQuery {
    #[allow(dead_code)]
    force: Option<bool>,
}

async fn update_configs(
    _q: Query<UploadConfigQuery>,
    State(state): State<ConfigState>,
    Json(req): Json<UpdateConfigRequest>,
) -> impl IntoResponse {
    let (done, wait) = tokio::sync::oneshot::channel();
    let g = state.global_state.lock().await;
    match (req.path, req.payload) {
        (_, Some(payload)) => {
            let msg = "config reloading from payload".to_string();
            let cfg = crate::Config::Str(payload);
            match g.reload_tx.send((cfg, done)).await {
                Ok(_) => {
                    wait.await.unwrap();
                    (StatusCode::NO_CONTENT, msg).into_response()
                }
                Err(_) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not signal config reload",
                )
                    .into_response(),
            }
        }
        (Some(mut path), None) => {
            if !PathBuf::from(&path).is_absolute() {
                path = PathBuf::from(g.cwd.clone())
                    .join(path)
                    .to_string_lossy()
                    .to_string();
            }
            if !PathBuf::from(&path).exists() {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("config file {path} not found"),
                )
                    .into_response();
            }

            let msg = format!("config reloading from file {path}");
            let cfg: crate::Config = crate::Config::File(path);
            match g.reload_tx.send((cfg, done)).await {
                Ok(_) => {
                    wait.await.unwrap();
                    (StatusCode::NO_CONTENT, msg).into_response()
                }

                Err(_) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not signal config reload",
                )
                    .into_response(),
            }
        }
        (None, None) => {
            (StatusCode::BAD_REQUEST, "no path or payload provided").into_response()
        }
    }
}
