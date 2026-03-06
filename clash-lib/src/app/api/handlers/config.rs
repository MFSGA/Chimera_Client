use std::sync::Arc;

use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;
use tokio::sync::Mutex;

use crate::{
    GlobalState,
    app::{
        api::AppState,
        dispatcher::Dispatcher,
        dns::ThreadSafeDNSResolver,
        inbound::manager::{InboundManager, Ports},
    },
    config::def::{LogLevel, RunMode},
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
        .route("/", get(get_configs))
        .with_state(ConfigState {
            inbound_manager,
            dispatcher,
            global_state,
            dns_resolver,
        })
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct GetConfigsResponse {
    port: Option<u16>,
    socks_port: Option<u16>,
    redir_port: Option<u16>,
    tproxy_port: Option<u16>,
    mixed_port: Option<u16>,
    bind_address: Option<String>,
    mode: RunMode,
    log_level: LogLevel,
    ipv6: bool,
    allow_lan: bool,
}

async fn get_configs(State(state): State<ConfigState>) -> Json<GetConfigsResponse> {
    let ports: Ports = state.inbound_manager.get_ports().await;
    let bind_address = state.inbound_manager.get_bind_address().await;
    let allow_lan = state.inbound_manager.get_allow_lan().await;
    let mode = state.dispatcher.get_mode().await;
    let log_level = state.global_state.lock().await.log_level();

    Json(GetConfigsResponse {
        port: ports.port,
        socks_port: ports.socks_port,
        redir_port: ports.redir_port,
        tproxy_port: ports.tproxy_port,
        mixed_port: ports.mixed_port,
        bind_address: Some(bind_address.0.to_string()),
        mode,
        log_level,
        ipv6: state.dns_resolver.ipv6(),
        allow_lan,
    })
}
