use std::{
    collections::HashMap,
    io,
    path::PathBuf,
    sync::{LazyLock, OnceLock, atomic::AtomicUsize},
};

use thiserror::Error;
use tokio::sync::{broadcast, mpsc};

use crate::{
    app::logging::LogEvent,
    config::{def, internal::InternalConfig},
};

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
pub type Runner = futures::future::BoxFuture<'static, Result<()>>;

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

static RUNTIME_CONTROLLER: LazyLock<std::sync::Mutex<RuntimeController>> =
    LazyLock::new(|| std::sync::Mutex::new(RuntimeController::new()));

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

    rt.block_on(async {
        match start(config, cwd, log_tx).await {
            Err(e) => {
                eprintln!("start error: {e}");
                Err(e)
            }
            Ok(_) => Ok(()),
        }
    })
}

static CRYPTO_PROVIDER_LOCK: OnceLock<()> = OnceLock::new();

pub fn setup_default_crypto_provider() {
    CRYPTO_PROVIDER_LOCK.get_or_init(|| {
        #[cfg(feature = "aws-lc-rs")]
        {
            rustls::crypto::aws_lc_rs::default_provider()
                .install_default()
                .unwrap()
        }
        #[cfg(feature = "ring")]
        {
            rustls::crypto::ring::default_provider()
                .install_default()
                .unwrap()
        }
    });
}

pub async fn start(
    config: InternalConfig,
    cwd: String,
    log_tx: broadcast::Sender<LogEvent>,
) -> Result<()> {
    setup_default_crypto_provider();

    let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);

    {
        let mut rt_ctrl = RUNTIME_CONTROLLER.lock().unwrap();
        rt_ctrl.register_runtime(shutdown_tx);
    }

    // let mut tasks = Vec::<Runner>::new();
    // let mut runners = Vec::new();

    let cwd = PathBuf::from(cwd);

    // things we need to clone before consuming config
    let controller_cfg = config.general.controller.clone();

    let api_runner = app::api::get_api_runner(
        controller_cfg,
        log_tx.clone(),
        /* components.inbound_manager,
        components.dispatcher,
        global_state.clone(),
        components.dns_resolver,
        components.outbound_manager,
        components.statistics_manager,
        components.cache_store,
        components.router, */
        cwd.to_string_lossy().to_string(),
    );
    todo!()
}
