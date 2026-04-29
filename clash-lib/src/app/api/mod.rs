use std::sync::Arc;

use tokio::sync::broadcast::Sender;

use crate::app::{dispatcher::StatisticsManager, logging::LogEvent};

mod handlers;
mod ipc;
mod runner;

pub use runner::ApiRunner;

pub struct AppState {
    log_source_tx: Sender<LogEvent>,
    statistics_manager: Arc<StatisticsManager>,
}
