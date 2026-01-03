use std::{io, path::PathBuf};

use thiserror::Error;
use tokio::sync::broadcast;

use crate::config::{def, internal::InternalConfig};

/// 2
mod app;
/// todo: #[cfg(not(feature = "internal"))]
mod config;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("invalid config: {0}")]
    InvalidConfig(String),
}

pub enum TokioRuntime {
    MultiThread,
    SingleThread,
}

pub struct Options {
    pub config: Config,
    pub cwd: Option<String>,
    pub rt: Option<TokioRuntime>,
    pub log_file: Option<String>,
}

#[allow(clippy::large_enum_variant)]
pub enum Config {
    // Def(ClashConfigDef),
    Internal(InternalConfig),
    File(String),
    Str(String),
}

impl Config {
    pub fn try_parse(self) -> Result<InternalConfig> {
        match self {
            // Config::Def(c) => c.try_into(),
            Config::Internal(c) => Ok(c),
            Config::File(file) => TryInto::<def::Config>::try_into(PathBuf::from(file))?.try_into(),
            Config::Str(s) => {
                todo!()
            }
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn start_scaffold(opts: Options) -> Result<()> {
    let rt = match opts.rt.as_ref().unwrap_or(&TokioRuntime::MultiThread) {
        TokioRuntime::MultiThread => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?,
        TokioRuntime::SingleThread => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?,
    };

    let config: InternalConfig = opts.config.try_parse()?;
    let cwd = opts.cwd.unwrap_or_else(|| ".".to_string());
    let (log_tx, _) = broadcast::channel(100);

    let log_collector = app::logging::EventCollector::new(vec![log_tx.clone()]);

    app::logging::setup_logging(config.general.log_level, log_collector, &cwd, opts.log_file);

    todo!()
}
