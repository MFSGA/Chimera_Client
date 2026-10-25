// todo
#![allow(unused_features)]
#![feature(ip)]
#![cfg_attr(
    not(any(feature = "reality", feature = "tls", feature = "tun")),
    allow(dead_code)
)]
// #![feature(sync_unsafe_cell)]

use std::{
    collections::HashMap,
    io,
    path::PathBuf,
    sync::{Arc, atomic::AtomicUsize},
};

use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

use crate::{
    config::{
        def::{self, LogLevel},
        internal::InternalConfig,
    },
    runner::Runner,
};

/// 2
pub mod app;
pub(crate) use app::dns;
/// 4
mod common;
/// todo: #[cfg(not(feature = "internal"))]
pub mod config;
/// 3
mod proxy;
/// 5
mod session;

mod runner;

pub use session::Session;

pub use proxy::utils::{
    SocketProtector, clear_socket_protector, install_default_socket_protector,
    set_socket_protector,
};

pub use config::{
    DNSListen as ClashDNSListen, RuntimeConfig as ClashRuntimeConfig,
    def::{Config as ClashConfigDef, DNS as ClashDNSConfigDef},
};

mod runtime;

pub use runtime::{
    setup_default_crypto_provider, shutdown, start, start_scaffold,
    start_scaffold_instance,
};

#[cfg(test)]
pub(crate) use runtime::tests;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    IpNet(#[from] ipnet::AddrParseError),
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("dns error: {0}")]
    DNSError(String),
    #[error("operation error: {0}")]
    Operation(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub enum TokioRuntime {
    MultiThread,
    SingleThread,
}

type ArcRunner = Arc<dyn Runner>;

pub struct Options {
    pub config: Config,
    pub cwd: Option<String>,
    pub rt: Option<TokioRuntime>,
    pub log_file: Option<String>,
    /// The original config file path, used to support "reload current config"
    /// from the dashboard. Set this when starting from a file; leave `None`
    /// for string/inline configs.
    pub config_path: Option<String>,
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
            Config::Internal(c) => c.validate(),
            Config::File(file) => {
                TryInto::<def::Config>::try_into(PathBuf::from(file))?.try_into()
            }
            Config::Str(s) => s.parse::<def::Config>()?.try_into(),
        }
    }
}

pub struct GlobalState {
    log_level: LogLevel,
    #[cfg(feature = "tun")]
    tunnel_runner: ArcRunner,
    dns_listener: ArcRunner,
    reload_tx: mpsc::Sender<(Config, oneshot::Sender<Result<()>>)>,
    network_reset_tx:
        mpsc::Sender<oneshot::Sender<Result<app::network::NetworkResetResponse>>>,
    network_status: Arc<tokio::sync::RwLock<app::network::NetworkStatus>>,
    cwd: String,
    /// Path to the config file used at startup. Used by the dashboard "Reload"
    /// button which sends an empty path to mean "reload current config".
    config_path: Option<String>,
}

impl GlobalState {
    #[allow(dead_code)]
    pub(crate) fn log_level(&self) -> LogLevel {
        self.log_level
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Default)]
pub struct RuntimeController {
    runtime_counter: AtomicUsize,
    shutdown_txs: HashMap<usize, mpsc::Sender<()>>,
}

impl RuntimeController {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_runtime(&mut self, shutdown_tx: mpsc::Sender<()>) -> usize {
        let id = self
            .runtime_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.shutdown_txs.insert(id, shutdown_tx);
        id
    }
}
