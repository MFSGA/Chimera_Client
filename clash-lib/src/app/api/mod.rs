use std::sync::Arc;

use tokio::sync::broadcast::Sender;

use crate::{
    Runner,
    app::{
        dispatcher::StatisticsManager, logging::LogEvent,
        outbound::manager::ThreadSafeOutboundManager,
    },
    config::internal::config::Controller,
};

pub struct AppState {
    log_source_tx: Sender<LogEvent>,
    statistics_manager: Arc<StatisticsManager>,
}

#[allow(clippy::too_many_arguments)]
pub fn get_api_runner(
    controller_cfg: Controller,
    log_source: Sender<LogEvent>,
    statistics_manager: Arc<StatisticsManager>,
    outbound_manager: ThreadSafeOutboundManager,
    cwd: String,
) -> Option<Runner> {
    let ipc_addr = controller_cfg.external_controller_ipc;
    let tcp_addr = controller_cfg.external_controller;

    if tcp_addr.is_none() && ipc_addr.is_none() {
        return None;
    }

    let app_state = Arc::new(AppState {
        log_source_tx: log_source,
        statistics_manager: statistics_manager.clone(),
    });

    todo!()
}
