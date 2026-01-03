use tokio::sync::broadcast::Sender;

use crate::{app::logging::LogEvent, config::internal::config::Controller};

#[allow(clippy::too_many_arguments)]
pub fn get_api_runner(controller_cfg: Controller, log_source: Sender<LogEvent>, cwd: String) {
    todo!()
}
