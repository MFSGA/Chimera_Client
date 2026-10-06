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
    sync::{Arc, OnceLock, atomic::AtomicUsize},
};

use futures::FutureExt;
use thiserror::Error;
use tokio::sync::{Mutex, broadcast, mpsc, oneshot};
use tracing::{debug, error, info, warn};

#[cfg(feature = "tun")]
use crate::{
    app::net::{clear_net_config, init_net_config},
    proxy::tun,
};
use crate::{
    app::{
        dispatcher::{Dispatcher, StatisticsManager},
        dns::{
            self, ThreadSafeDNSResolver, config::DNSListenAddr,
            resolver::SystemResolver,
        },
        inbound::manager::InboundManager,
        logging::LogEvent,
        outbound::manager::OutboundManager,
        profile,
        router::Router,
    },
    common::{
        auth,
        geodata::{self, DEFAULT_GEOSITE_DOWNLOAD_URL, GeoDataLookup},
        http::new_http_client,
        mmdb::{
            self, DEFAULT_ASN_MMDB_DOWNLOAD_URL, DEFAULT_COUNTRY_MMDB_DOWNLOAD_URL,
            MmdbLookup,
        },
    },
    config::{
        def::{self, LogLevel},
        internal::{InternalConfig, proxy::OutboundProxy},
    },
    runner::Runner,
};

/// 2
pub mod app;
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

pub fn start_scaffold(opts: Options) -> Result<()> {
    let rt = match opts.rt.as_ref().unwrap_or(&TokioRuntime::MultiThread) {
        TokioRuntime::MultiThread => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?,
        TokioRuntime::SingleThread => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?,
    };

    let config_path = opts.config_path.or_else(|| {
        if let Config::File(ref path) = opts.config {
            Some(path.clone())
        } else {
            None
        }
    });
    let config: InternalConfig = opts.config.try_parse()?;
    let cwd = opts.cwd.unwrap_or_else(|| ".".to_string());
    let (log_tx, _) = broadcast::channel(100);

    let log_collector = app::logging::EventCollector::new(vec![log_tx.clone()]);

    app::logging::setup_logging(
        config.general.log_level,
        log_collector,
        &cwd,
        opts.log_file,
    );

    rt.block_on(async {
        match start(config, cwd, config_path, log_tx).await {
            Err(e) => {
                eprintln!("start error: {e}");
                Err(e)
            }
            Ok(_) => Ok(()),
        }
    })
}

enum InstanceStartupEvent {
    Ready,
    Failed(Error),
}

/// Start one runtime in a background thread with an independent shutdown token.
/// This is primarily useful for integration tests that need an independently
/// controlled instance. When the `tun` feature is enabled, starts that need
/// process-global network/TUN state are rejected while another such runtime is
/// active.
pub fn start_scaffold_instance(
    opts: Options,
) -> Result<(
    std::thread::JoinHandle<()>,
    tokio_util::sync::CancellationToken,
)> {
    let config_path = opts.config_path.or_else(|| {
        if let Config::File(ref path) = opts.config {
            Some(path.clone())
        } else {
            None
        }
    });
    let config: InternalConfig = opts.config.try_parse()?;
    let cwd = opts.cwd.unwrap_or_else(|| ".".to_string());
    let rt_kind = opts.rt.unwrap_or(TokioRuntime::MultiThread);
    let log_file = opts.log_file;
    let token = tokio_util::sync::CancellationToken::new();
    let token_clone = token.clone();
    let network_runtime_lease =
        NetworkRuntimeLease::acquire(uses_process_global_network_state(&config))?;
    let (startup_tx, startup_rx) = std::sync::mpsc::channel();

    let handle = std::thread::spawn(move || {
        let rt = match match rt_kind {
            TokioRuntime::MultiThread => tokio::runtime::Builder::new_multi_thread(),
            TokioRuntime::SingleThread => {
                tokio::runtime::Builder::new_current_thread()
            }
        }
        .enable_all()
        .build()
        {
            Ok(rt) => rt,
            Err(err) => {
                let _ =
                    startup_tx.send(InstanceStartupEvent::Failed(Error::Io(err)));
                return;
            }
        };

        let (log_tx, _) = broadcast::channel(100);
        let log_collector = app::logging::EventCollector::new(vec![log_tx.clone()]);
        app::logging::setup_logging(
            config.general.log_level,
            log_collector,
            &cwd,
            log_file,
        );

        if let Err(err) = rt.block_on(start_with_shutdown_token(
            config,
            cwd,
            config_path,
            log_tx,
            token_clone,
            network_runtime_lease,
            Some(startup_tx.clone()),
        )) && let Err(send_err) =
            startup_tx.send(InstanceStartupEvent::Failed(err))
            && let InstanceStartupEvent::Failed(err) = send_err.0
        {
            eprintln!("independent runtime error: {err}");
        }
    });

    match startup_rx.recv() {
        Ok(InstanceStartupEvent::Ready) => Ok((handle, token)),
        Ok(InstanceStartupEvent::Failed(err)) => {
            token.cancel();
            let _ = handle.join();
            Err(err)
        }
        Err(err) => {
            token.cancel();
            let _ = handle.join();
            Err(Error::Operation(format!(
                "independent runtime startup channel closed: {err}"
            )))
        }
    }
}

static CRYPTO_PROVIDER_LOCK: OnceLock<()> = OnceLock::new();

#[cfg(feature = "tun")]
static NETWORK_RUNTIME_STATE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(feature = "tun")]
const CONFIGURED_NETWORK_RUNTIME: usize = usize::MAX;

/// Own the process-global socket/TUN configuration for the lifetime of one
/// runtime. Runtimes without an interface, mark, or TUN can coexist because
/// they do not write these slots; a runtime that needs them is exclusive.
struct NetworkRuntimeLease {
    #[cfg(feature = "tun")]
    configured: bool,
}

impl NetworkRuntimeLease {
    fn acquire(required: bool) -> Result<Self> {
        #[cfg(feature = "tun")]
        {
            if required {
                return NETWORK_RUNTIME_STATE
                    .compare_exchange(
                        0,
                        CONFIGURED_NETWORK_RUNTIME,
                        std::sync::atomic::Ordering::AcqRel,
                        std::sync::atomic::Ordering::Acquire,
                    )
                    .map(|_| Self { configured: true })
                    .map_err(|_| {
                        Error::Operation(
                            "another runtime already owns the process-global network configuration"
                                .to_owned(),
                        )
                    });
            }

            loop {
                let users =
                    NETWORK_RUNTIME_STATE.load(std::sync::atomic::Ordering::Acquire);
                if users == CONFIGURED_NETWORK_RUNTIME {
                    return Err(Error::Operation(
                        "another runtime already owns the process-global network configuration"
                            .to_owned(),
                    ));
                }
                if NETWORK_RUNTIME_STATE
                    .compare_exchange(
                        users,
                        users + 1,
                        std::sync::atomic::Ordering::AcqRel,
                        std::sync::atomic::Ordering::Acquire,
                    )
                    .is_ok()
                {
                    return Ok(Self { configured: false });
                }
            }
        }

        #[cfg(not(feature = "tun"))]
        {
            let _ = required;
            Ok(Self {})
        }
    }

    #[cfg(feature = "tun")]
    fn ensure_active(&mut self) -> Result<()> {
        if self.configured {
            return Ok(());
        }
        NETWORK_RUNTIME_STATE
            .compare_exchange(
                1,
                CONFIGURED_NETWORK_RUNTIME,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .map(|_| {
                self.configured = true;
            })
            .map_err(|_| {
                Error::Operation(
                    "another runtime already owns the process-global network configuration"
                        .to_owned(),
                )
            })
    }

    #[cfg(feature = "tun")]
    fn deactivate_to_neutral(&mut self) {
        if self.configured {
            NETWORK_RUNTIME_STATE.store(1, std::sync::atomic::Ordering::Release);
            self.configured = false;
        }
    }

    #[cfg(feature = "tun")]
    fn release(&mut self) {
        if self.configured {
            NETWORK_RUNTIME_STATE.store(0, std::sync::atomic::Ordering::Release);
            self.configured = false;
        } else {
            NETWORK_RUNTIME_STATE.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        }
    }
}

impl Drop for NetworkRuntimeLease {
    fn drop(&mut self) {
        #[cfg(feature = "tun")]
        {
            self.release();
        }
    }
}

fn uses_process_global_network_state(config: &InternalConfig) -> bool {
    #[cfg(feature = "tun")]
    {
        config.tun.enable
            || config.tun.so_mark.is_some()
            || config.general.interface.is_some()
    }

    #[cfg(not(feature = "tun"))]
    {
        let _ = config;
        false
    }
}

pub fn setup_default_crypto_provider() {
    CRYPTO_PROVIDER_LOCK.get_or_init(|| {
        #[cfg(feature = "aws-lc-rs")]
        {
            _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        }
        #[cfg(feature = "ring")]
        {
            _ = rustls::crypto::ring::default_provider().install_default();
        }
    });
}

async fn wait_for_shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        )?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

enum RuntimeExit<T> {
    Control(std::result::Result<T, tokio::task::JoinError>),
    Signal(std::io::Result<()>),
    Cancelled,
}

async fn wait_for_control_or_shutdown<T, S>(
    control: &mut tokio::task::JoinHandle<T>,
    shutdown: &tokio_util::sync::CancellationToken,
    signal: S,
) -> RuntimeExit<T>
where
    S: std::future::Future<Output = std::io::Result<()>>,
{
    tokio::select! {
        biased;
        result = control => RuntimeExit::Control(result),
        _ = shutdown.cancelled() => RuntimeExit::Cancelled,
        result = signal => RuntimeExit::Signal(result),
    }
}

async fn catch_control_panic<F>(control: F) -> Result<()>
where
    F: std::future::Future<Output = Result<()>>,
{
    match std::panic::AssertUnwindSafe(control).catch_unwind().await {
        Ok(result) => result,
        Err(_) => Err(Error::Operation("runtime control task panicked".to_owned())),
    }
}

pub async fn start(
    config: InternalConfig,
    cwd: String,
    config_path: Option<String>,
    log_tx: broadcast::Sender<LogEvent>,
) -> Result<()> {
    let config = config.validate()?;
    let network_runtime_lease =
        NetworkRuntimeLease::acquire(uses_process_global_network_state(&config))?;
    let shutdown_token = tokio_util::sync::CancellationToken::new();
    let _shutdown_registration =
        ShutdownTokenRegistration::register(shutdown_token.clone());
    start_with_shutdown_token(
        config,
        cwd,
        config_path,
        log_tx,
        shutdown_token,
        network_runtime_lease,
        None,
    )
    .await
}

async fn start_with_shutdown_token(
    config: InternalConfig,
    cwd: String,
    config_path: Option<String>,
    log_tx: broadcast::Sender<LogEvent>,
    shutdown_token: tokio_util::sync::CancellationToken,
    network_runtime_lease: NetworkRuntimeLease,
    startup_tx: Option<std::sync::mpsc::Sender<InstanceStartupEvent>>,
) -> Result<()> {
    let config = config.validate()?;
    setup_default_crypto_provider();
    let cwd = PathBuf::from(cwd);

    // things we need to clone before consuming config
    let controller_cfg = config.general.controller.clone();
    let log_level = config.general.log_level;

    let components = create_components(cwd.clone(), config, true).await?;

    let (reload_tx, mut reload_rx) = mpsc::channel(1);
    let (network_reset_tx, mut network_reset_rx) = mpsc::channel::<
        oneshot::Sender<Result<app::network::NetworkResetResponse>>,
    >(8);
    let network_status = Arc::new(tokio::sync::RwLock::new(
        app::network::NetworkStatus::default(),
    ));
    let observed_tun_exclusion = Arc::new(tokio::sync::RwLock::new(
        components.tun_candidate_exclusion(),
    ));
    let (network_samples_tx, mut network_samples) =
        tokio::sync::watch::channel(None);

    let (traffic_tx, mut traffic_rx) = mpsc::channel(128);
    let traffic_reporter = network_status.write().await.traffic_reporter(traffic_tx);
    components
        .outbound_manager
        .attach_network_status(network_status.clone())
        .await;
    components
        .outbound_manager
        .attach_traffic_reporter(traffic_reporter.clone())
        .await;
    components
        .dispatcher
        .attach_traffic_reporter(traffic_reporter.clone());
    components
        .dispatcher
        .attach_network_status(network_status.clone());
    let final_status = network_status.clone();

    let global_state = Arc::new(Mutex::new(GlobalState {
        log_level,
        #[cfg(feature = "tun")]
        tunnel_runner: components.tun_runner.clone(),
        dns_listener: components.dns_listener.clone(),
        reload_tx,
        network_reset_tx,
        network_status: network_status.clone(),
        cwd: cwd.to_string_lossy().to_string(),
        config_path,
    }));

    let api_listener = components.api_listener(
        controller_cfg.clone(),
        log_tx.clone(),
        global_state.clone(),
        &cwd,
        shutdown_token.child_token(),
    );

    // api_listener is not part of components because it requires components to be
    // initialized before it can be initialized. start it manually.
    api_listener.run_async();
    if let Err(err) = api_listener.wait_ready().await {
        network_status.write().await.set_component(
            app::runtime_state::RuntimeComponent::Api,
            app::runtime_state::RuntimeComponentPhase::Failed,
            Some(err.to_string()),
        );
        api_listener.shutdown();
        let _ = api_listener.join().await;
        components.stop_all_and_join(true).await;
        network_status.write().await.lifecycle(
            app::runtime_state::Lifecycle::Failed,
            "listenerStartupFailed",
        );
        return Err(err);
    }

    {
        let mut g = global_state.lock().await;
        #[cfg(feature = "tun")]
        {
            g.tunnel_runner = components.tun_runner.clone();
        }
        g.dns_listener = components.dns_listener.clone();
    }

    components.start_all();
    if let Err(err) = components.wait_initial_ready(&network_status).await {
        api_listener.shutdown();
        let _ = api_listener.join().await;
        components.stop_all_and_join(true).await;
        network_status.write().await.lifecycle(
            app::runtime_state::Lifecycle::Failed,
            "listenerStartupFailed",
        );
        return Err(err);
    }

    refresh_runtime_health(&components, api_listener.as_ref(), &network_status)
        .await;
    network_status
        .write()
        .await
        .lifecycle(app::runtime_state::Lifecycle::Running, "listenersReady");
    if let Some(startup_tx) = startup_tx {
        startup_tx.send(InstanceStartupEvent::Ready).map_err(|_| {
            Error::Operation(
                "independent runtime startup receiver dropped before readiness"
                    .to_owned(),
            )
        })?;
    }
    let network_sampler = app::network::AUTOMATIC_SUPPORTED.then(|| {
        let sampler_token = shutdown_token.child_token();
        let tun_exclusion = observed_tun_exclusion.clone();
        tokio::spawn(app::network::run_sampler(
            sampler_token,
            network_samples_tx,
            move || {
                let tun_exclusion = tun_exclusion.clone();
                async move {
                    let exclusion = tun_exclusion.read().await.clone();
                    app::network::snapshot_with_tun(exclusion).await
                }
            },
        ))
    });
    let sampler_started = network_sampler.is_some();

    let cwd_clone = cwd.clone();

    let reload_token = shutdown_token.clone();
    let mut reload_handle = tokio::spawn(async move {
        #[cfg(feature = "tun")]
        let mut network_runtime_lease = network_runtime_lease;
        #[cfg(not(feature = "tun"))]
        let _network_runtime_lease = network_runtime_lease;
        let mut active_components = components;
        let mut active_api_listener = api_listener;
        let mut active_controller_cfg = controller_cfg;
        let mut network_observer = app::network::NetworkObserver::default();
        let mut sampler_running = sampler_started;
        let mut health_interval =
            tokio::time::interval(std::time::Duration::from_secs(2));
        health_interval
            .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        network_status.write().await.set_component(
            app::runtime_state::RuntimeComponent::Control,
            app::runtime_state::RuntimeComponentPhase::Ready,
            None,
        );

        // Listen for config reload signal and reload config.
        let control_result = catch_control_panic(async {
            loop {
            tokio::select! {
                biased;
                _ = reload_token.cancelled() => {
                    network_status.write().await.lifecycle(app::runtime_state::Lifecycle::Stopping, "shutdownRequested");
                    info!("runtime shutdown requested");
                    break Ok(());
                }
                Some(done) = network_reset_rx.recv() => {
                    if done.is_closed() { continue; }
                    let recovery = async {
                        let (snapshot, observation_error) = if app::network::AUTOMATIC_SUPPORTED {
                            match app::network::snapshot_with_tun(
                                active_components.tun_candidate_exclusion(),
                            ).await {
                                Ok(snapshot) => (Some(snapshot), None),
                                Err(error) => (None, Some(error.to_string())),
                            }
                        } else { (None, None) };
                        active_components.perform_network_recovery(
                            &mut network_observer,
                            &network_status,
                            NetworkRecoveryRequest {
                                snapshot,
                                path_changed: true,
                                cause: app::runtime_state::RecoveryCause::ManualReset,
                                observation_error,
                            },
                            Some(&mut network_samples),
                        ).await
                    };
                    let result = tokio::select! {
                        biased;
                        _ = reload_token.cancelled() => { continue; }
                        result = recovery => result,
                    };
                    let _ = done.send(result);
                }

                maybe_reload = reload_rx.recv() => {
                    let Some((config, done)) = maybe_reload else {
                        break Err(Error::Operation(
                            "runtime reload channel closed unexpectedly".to_owned(),
                        ));
                    };

                    network_status.write().await.lifecycle(app::runtime_state::Lifecycle::Reloading, "reloadRequested");
                    info!("reloading config");
                    let config = match config.try_parse() {
                        Ok(c) => c,
                        Err(e) => {
                            error!("failed to reload config: {}", e);
                            let _ = finish_reload_status(&network_status, done, Err(e)).await;
                            continue;
                        }
                    };
                    info!("reloading get config 2");
                    let candidate_controller_cfg = config.general.controller.clone();

                    // Build the replacement runtime while the current one is still
                    // serving traffic. Construction performs all fallible config,
                    // provider, DNS, and data-file initialization without binding
                    // listeners or touching the active network configuration.
                    let new_components =
                        match create_components(cwd_clone.clone(), config, false).await {
                            Ok(components) => {
                                components.outbound_manager.attach_network_status(network_status.clone()).await;
                                components.outbound_manager.attach_traffic_reporter(traffic_reporter.clone()).await;
                                components.dispatcher.attach_traffic_reporter(traffic_reporter.clone());
                                components.dispatcher.attach_network_status(network_status.clone());
                                components
                            },
                            Err(e) => {
                                error!(
                                    "failed to prepare components during reload; keeping the active runtime: {}",
                                    e
                                );
                                let _ = finish_reload_status(&network_status, done, Err(e)).await;
                                continue;
                            }
                        };

                    // Validate and install the replacement interface/mark only after
                    // the complete candidate runtime has been prepared. A failure at
                    // this point still leaves every old listener and task running.
                    #[cfg(feature = "tun")]
                    if new_components.network_config.uses_global_state()
                        && let Err(e) = network_runtime_lease.ensure_active()
                    {
                        error!(
                            "failed to acquire network config during reload; keeping the active runtime: {}",
                            e
                        );
                        let _ = finish_reload_status(&network_status, done, Err(e)).await;
                        continue;
                    }
                    #[cfg(feature = "tun")]
                    if let Err(e) = new_components.activate_network_config().await {
                        error!(
                            "failed to activate network config during reload; keeping the active runtime: {}",
                            e
                        );
                        if let Err(restore_err) = restore_network_after_failed_reload(
                            &active_components,
                            &new_components,
                            &mut network_runtime_lease,
                        )
                        .await
                        {
                            let fatal = Error::Operation(format!(
                                "failed to restore active network configuration after reload failure: {restore_err}"
                            ));
                            let _ = finish_reload_status(&network_status, done, Err(fatal)).await;
                            reload_token.cancel();
                            break Err(Error::Operation(
                                "active network configuration could not be restored"
                                    .to_owned(),
                            ));
                        }
                        let _ = finish_reload_status(&network_status, done, Err(e)).await;
                        continue;
                    }

                    // Prepare restartable copies of the active data-plane runners
                    // before releasing any active listener. If this ever becomes
                    // fallible, the current runtime is still completely intact.
                    let rollback_components = match active_components
                        .fresh_data_plane()
                        .await
                    {
                        Ok(components) => components,
                        Err(err) => {
                            #[cfg(feature = "tun")]
                            if let Err(restore_err) = restore_network_after_failed_reload(
                                &active_components,
                                &new_components,
                                &mut network_runtime_lease,
                            )
                            .await
                            {
                                let fatal = Error::Operation(format!(
                                    "failed to restore active network configuration after rollback preparation failure: {restore_err}"
                                ));
                                let _ = finish_reload_status(&network_status, done, Err(fatal)).await;
                                reload_token.cancel();
                                break Err(Error::Operation(
                                    "active network configuration could not be restored"
                                        .to_owned(),
                                ));
                            }
                            let _ = finish_reload_status(&network_status, done, Err(Error::Operation(format!(
                                "failed to prepare active data-plane rollback: {err}"
                            )))).await;
                            continue;
                        }
                    };

                    // Validate the replacement controller before stopping the old
                    // data plane. The old controller has to release its listening
                    // socket first, but the old SOCKS/DNS/TUN runners remain alive
                    // until every replacement controller endpoint is ready.
                    let new_api_listener = new_components.api_listener(
                        candidate_controller_cfg.clone(),
                        log_tx.clone(),
                        global_state.clone(),
                        &cwd_clone,
                        reload_token.child_token(),
                    );
                    active_api_listener.shutdown();
                    if let Err(err) = active_api_listener.join().await {
                        warn!("failed waiting for api listener shutdown: {}", err);
                    }
                    new_api_listener.run_async();
                    if let Err(err) = new_api_listener.wait_ready().await {
                        network_status.write().await.set_component(
                            app::runtime_state::RuntimeComponent::Api,
                            app::runtime_state::RuntimeComponentPhase::Failed,
                            Some(err.to_string()),
                        );
                        error!(
                            "replacement API listener failed to become ready; restoring the active runtime: {}",
                            err
                        );
                        new_api_listener.shutdown();
                        let _ = new_api_listener.join().await;

                        #[cfg(feature = "tun")]
                        if let Err(restore_err) = restore_network_after_failed_reload(
                            &active_components,
                            &new_components,
                            &mut network_runtime_lease,
                        )
                        .await
                        {
                            let fatal = Error::Operation(format!(
                                "failed to restore active network configuration after controller reload failure: {restore_err}"
                            ));
                            let _ = finish_reload_status(&network_status, done, Err(fatal)).await;
                            reload_token.cancel();
                            break Err(Error::Operation(
                                "active network configuration could not be restored"
                                    .to_owned(),
                            ));
                        }

                        let restored_api_listener = active_components.api_listener(
                            active_controller_cfg.clone(),
                            log_tx.clone(),
                            global_state.clone(),
                            &cwd_clone,
                            reload_token.child_token(),
                        );
                        restored_api_listener.run_async();
                        if let Err(restore_err) = restored_api_listener.wait_ready().await {
                            network_status.write().await.set_component(
                                app::runtime_state::RuntimeComponent::Api,
                                app::runtime_state::RuntimeComponentPhase::Failed,
                                Some(restore_err.to_string()),
                            );
                            let fatal = Error::Operation(format!(
                                "failed to restore active API listener after reload failure: {restore_err}"
                            ));
                            let _ = finish_reload_status(&network_status, done, Err(fatal)).await;
                            reload_token.cancel();
                            restored_api_listener.shutdown();
                            let _ = restored_api_listener.join().await;
                            break Err(Error::Operation(
                                "active API listener could not be restored".to_owned(),
                            ));
                        }
                        active_api_listener = restored_api_listener;
                        refresh_runtime_health(
                            &active_components,
                            active_api_listener.as_ref(),
                            &network_status,
                        )
                        .await;
                        let _ = finish_reload_status(&network_status, done, Err(err)).await;
                        continue;
                    }

                    // The replacement controller is now bound successfully. Commit
                    // the data-plane switch only after that boundary has passed.
                    active_components.stop_all_and_join(false).await;
                    #[cfg(feature = "tun")]
                    if !new_components.network_config.uses_global_state() {
                        clear_net_config().await;
                        network_runtime_lease.deactivate_to_neutral();
                    }
                    new_components.start_all();
                    if let Err(err) =
                        new_components.wait_initial_ready(&network_status).await
                    {
                        error!(
                            "replacement data plane failed to become ready; restoring the active runtime: {}",
                            err
                        );
                        new_components.stop_all_and_join(false).await;
                        new_api_listener.shutdown();
                        let _ = new_api_listener.join().await;

                        #[cfg(feature = "tun")]
                        if let Err(restore_err) = restore_active_network_config(
                            &rollback_components,
                            &mut network_runtime_lease,
                        )
                        .await
                        {
                            let fatal = Error::Operation(format!(
                                "failed to restore active network configuration after data-plane reload failure: {restore_err}"
                            ));
                            let _ = finish_reload_status(&network_status, done, Err(fatal)).await;
                            reload_token.cancel();
                            break Err(Error::Operation(
                                "active network configuration could not be restored"
                                    .to_owned(),
                            ));
                        }

                        rollback_components.start_all();
                        if let Err(restore_err) =
                            rollback_components.wait_initial_ready(&network_status).await
                        {
                            let fatal = Error::Operation(format!(
                                "failed to restore active data plane after reload failure: {restore_err}"
                            ));
                            let _ = finish_reload_status(&network_status, done, Err(fatal)).await;
                            reload_token.cancel();
                            rollback_components.stop_all_and_join(true).await;
                            break Err(Error::Operation(
                                "active data plane could not be restored".to_owned(),
                            ));
                        }

                        {
                            let mut g = global_state.lock().await;
                            #[cfg(feature = "tun")]
                            {
                                g.tunnel_runner = rollback_components.tun_runner.clone();
                            }
                            g.dns_listener = rollback_components.dns_listener.clone();
                        }

                        let restored_api_listener = rollback_components.api_listener(
                            active_controller_cfg.clone(),
                            log_tx.clone(),
                            global_state.clone(),
                            &cwd_clone,
                            reload_token.child_token(),
                        );
                        restored_api_listener.run_async();
                        if let Err(restore_err) = restored_api_listener.wait_ready().await {
                            network_status.write().await.set_component(
                                app::runtime_state::RuntimeComponent::Api,
                                app::runtime_state::RuntimeComponentPhase::Failed,
                                Some(restore_err.to_string()),
                            );
                            let fatal = Error::Operation(format!(
                                "failed to restore active API listener after data-plane reload failure: {restore_err}"
                            ));
                            let _ = finish_reload_status(&network_status, done, Err(fatal)).await;
                            reload_token.cancel();
                            restored_api_listener.shutdown();
                            let _ = restored_api_listener.join().await;
                            break Err(Error::Operation(
                                "active API listener could not be restored".to_owned(),
                            ));
                        }

                        active_components = rollback_components;
                        *observed_tun_exclusion.write().await =
                            active_components.tun_candidate_exclusion();
                        active_api_listener = restored_api_listener;
                        refresh_runtime_health(
                            &active_components,
                            active_api_listener.as_ref(),
                            &network_status,
                        )
                        .await;
                        let _ = finish_reload_status(&network_status, done, Err(err)).await;
                        continue;
                    }

                    let mut g = global_state.lock().await;
                    #[cfg(feature = "tun")]
                    {
                        g.tunnel_runner = new_components.tun_runner.clone();
                    }
                    g.dns_listener = new_components.dns_listener.clone();

                    *observed_tun_exclusion.write().await =
                        new_components.tun_candidate_exclusion();
                    active_components = new_components;
                    active_api_listener = new_api_listener;
                    active_controller_cfg = candidate_controller_cfg;
                    network_observer = app::network::NetworkObserver::default();
                    refresh_runtime_health(
                        &active_components,
                        active_api_listener.as_ref(),
                        &network_status,
                    )
                    .await;

                    if finish_reload_status(&network_status, done, Ok(())).await.is_err() {
                        warn!("config reload response channel dropped before completion");
                    }
                }
                Some(proof) = traffic_rx.recv() => {
                    network_status.write().await.record_traffic(proof);
                }
                _ = health_interval.tick() => {
                    refresh_runtime_health(
                        &active_components,
                        active_api_listener.as_ref(),
                        &network_status,
                    ).await;
                }
                changed = network_samples.changed(), if sampler_running => {
                    if changed.is_err() {
                        warn!("network sampler stopped; automatic recovery is unavailable");
                        sampler_running = false;
                        network_status.write().await.observation_failed("network sampler stopped");
                        continue;
                    }
                    let sample = network_samples.borrow_and_update().clone();
                    if let Some(sample) = sample {
                        match sample.result.clone() {
                            Ok(snapshot) => {
                                network_status.write().await.observed_sample(&sample);
                                active_components.apply_network_observation(
                                    &mut network_observer,
                                    &network_status,
                                    snapshot,
                                    &mut network_samples,
                                ).await;
                            }
                            Err(error) => {
                                let mut status = network_status.write().await;
                                status.observation_failed_sample(&sample);
                                debug!(error, sample_sequence = sample.sequence, "network observation failed");
                            }
                        }
                    }
                }
            }
            }
        })
        .await;

        active_api_listener.shutdown();
        if let Err(err) = active_api_listener.join().await {
            warn!("failed waiting for API listener shutdown: {}", err);
        }
        active_components.stop_all_and_join(true).await;
        if control_result.is_ok() {
            let mut status = network_status.write().await;
            status.stop_components();
            status.lifecycle(
                app::runtime_state::Lifecycle::Stopped,
                "resourcesReleased",
            );
        } else {
            network_status.write().await.set_component(
                app::runtime_state::RuntimeComponent::Control,
                app::runtime_state::RuntimeComponentPhase::Failed,
                Some("runtime control task exited unexpectedly".to_owned()),
            );
        }
        control_result
    });

    let exit = wait_for_control_or_shutdown(
        &mut reload_handle,
        &shutdown_token,
        wait_for_shutdown_signal(),
    )
    .await;

    let result = match exit {
        RuntimeExit::Control(joined) => {
            if shutdown_token.is_cancelled() {
                joined
                    .map_err(|err| {
                        Error::Operation(format!(
                            "runtime reload task join error: {err}"
                        ))
                    })
                    .and_then(|result| result)
            } else {
                shutdown_token.cancel();
                let error = match joined {
                    Ok(Ok(())) => Error::Operation(
                        "runtime control task exited unexpectedly".to_owned(),
                    ),
                    Ok(Err(error)) => error,
                    Err(err) => Error::Operation(format!(
                        "runtime control task terminated unexpectedly: {err}"
                    )),
                };
                final_status.write().await.set_component(
                    app::runtime_state::RuntimeComponent::Control,
                    app::runtime_state::RuntimeComponentPhase::Failed,
                    Some("runtime control task exited unexpectedly".to_owned()),
                );
                Err(error)
            }
        }
        RuntimeExit::Signal(signal_result) => {
            shutdown_token.cancel();
            let joined = reload_handle
                .await
                .map_err(|err| {
                    Error::Operation(format!(
                        "runtime reload task join error: {err}"
                    ))
                })
                .and_then(|result| result);
            match signal_result {
                Ok(()) => joined,
                Err(error) => Err(Error::Io(error)),
            }
        }
        RuntimeExit::Cancelled => {
            shutdown_token.cancel();
            reload_handle
                .await
                .map_err(|err| {
                    Error::Operation(format!(
                        "runtime reload task join error: {err}"
                    ))
                })
                .and_then(|result| result)
        }
    };
    if let Some(network_sampler) = network_sampler
        && let Err(error) = network_sampler.await
    {
        warn!("network sampler task exited with error: {error}");
    }
    if result.is_err() {
        let mut status = final_status.write().await;
        status.set_component(
            app::runtime_state::RuntimeComponent::Control,
            app::runtime_state::RuntimeComponentPhase::Failed,
            Some("runtime control task or shutdown failed".to_owned()),
        );
        status.lifecycle(app::runtime_state::Lifecycle::Failed, "controlTaskFailed");
    }
    result?;

    Ok(())
}

#[cfg(feature = "tun")]
#[derive(Clone)]
struct RuntimeNetworkConfig {
    tun_enabled: bool,
    tun_so_mark: Option<u32>,
    interface: Option<app::net::Interface>,
}

#[cfg(feature = "tun")]
impl RuntimeNetworkConfig {
    fn uses_global_state(&self) -> bool {
        self.tun_enabled || self.tun_so_mark.is_some() || self.interface.is_some()
    }

    async fn activate(&self) -> Result<()> {
        if !self.uses_global_state() {
            return Ok(());
        }
        init_net_config(self.tun_enabled, self.tun_so_mark, self.interface.as_ref())
            .await?;
        install_default_socket_protector();
        Ok(())
    }
}

struct NetworkRecoveryRequest {
    snapshot: Option<app::network::NetworkSnapshot>,
    path_changed: bool,
    cause: app::runtime_state::RecoveryCause,
    observation_error: Option<String>,
}

async fn recover_to_latest_environment<F, Fut>(
    observer: &mut app::network::NetworkObserver,
    status: &tokio::sync::RwLock<app::network::NetworkStatus>,
    request: NetworkRecoveryRequest,
    mut latest_samples: Option<
        &mut tokio::sync::watch::Receiver<Option<app::network::NetworkSample>>,
    >,
    mut recover: F,
) -> Result<app::network::NetworkResetResponse>
where
    F: FnMut(Option<app::network::NetworkSnapshot>, bool) -> Fut,
    Fut: std::future::Future<Output = app::runtime_state::RecoveryReport>,
{
    const MAX_RECOVERY_ATTEMPTS_PER_CHANGE: u32 = 2;
    let mut attempts = 0_u32;
    let NetworkRecoveryRequest {
        mut snapshot,
        mut path_changed,
        mut cause,
        mut observation_error,
    } = request;
    loop {
        attempts = attempts.saturating_add(1);
        let started_at = tokio::time::Instant::now();
        let token = status
            .write()
            .await
            .begin(cause, snapshot.as_ref())
            .ok_or_else(|| {
                Error::Operation(
                    "runtime cannot recover in its current lifecycle".into(),
                )
            })?;
        let mut report = recover(snapshot.clone(), path_changed).await;
        report.observation_error = observation_error.take();

        // The sampler runs independently while DNS and pool resets wait. If a
        // newer network is already known, retain this attempt as superseded and
        // recover the latest environment before reporting success.
        if let Some(samples) = latest_samples.as_deref_mut()
            && let Some(sample) =
                app::network::take_sample_after(samples, started_at)
        {
            match sample.result.clone() {
                Ok(newest) => {
                    let changed = snapshot.as_ref() != Some(&newest);
                    status.write().await.observed_sample(&sample);
                    if changed {
                        status.write().await.supersede(token, report);
                        let retry =
                            observer.observe(&newest, tokio::time::Instant::now());
                        path_changed = retry.unwrap_or(true);
                        cause = if attempts >= MAX_RECOVERY_ATTEMPTS_PER_CHANGE {
                            app::runtime_state::RecoveryCause::Retry
                        } else {
                            app::runtime_state::RecoveryCause::NetworkChanged
                        };
                        snapshot = Some(newest);
                        observation_error = None;
                        if attempts >= MAX_RECOVERY_ATTEMPTS_PER_CHANGE {
                            let message =
                                "network changed repeatedly during recovery";
                            let token = status
                                .write()
                                .await
                                .begin(cause, snapshot.as_ref())
                                .ok_or_else(|| Error::Operation(message.into()))?;
                            let report = app::runtime_state::RecoveryReport {
                                interface:
                                    app::runtime_state::ComponentResult::skipped(),
                                dns: app::runtime_state::ComponentResult::skipped(),
                                pools: app::runtime_state::ComponentResult::skipped(
                                ),
                                observation_error: Some(message.into()),
                                offline: snapshot
                                    .as_ref()
                                    .is_none_or(|value| !value.has_path()),
                            };
                            let delay = observer
                                .retry(path_changed, tokio::time::Instant::now());
                            status.write().await.complete(
                                token,
                                report.clone(),
                                Some(delay),
                            );
                            return report.into_result();
                        }
                        continue;
                    }
                }
                Err(error) => {
                    status.write().await.observation_failed_sample(&sample);
                    report.observation_error = Some(error);
                }
            }
        }

        let failed = report.error().is_some();
        let retry = failed
            .then(|| observer.retry(path_changed, tokio::time::Instant::now()));
        if !status.write().await.complete(token, report.clone(), retry) {
            return Err(Error::Operation(
                "discarded stale network recovery result".into(),
            ));
        }
        if !failed && let Some(snapshot) = snapshot {
            observer.applied(snapshot);
        }
        return report.into_result();
    }
}

async fn finish_reload_status(
    status: &tokio::sync::RwLock<app::network::NetworkStatus>,
    done: oneshot::Sender<Result<()>>,
    result: Result<()>,
) -> std::result::Result<(), Result<()>> {
    status
        .write()
        .await
        .reload_finished(result.as_ref().err().map(ToString::to_string));
    done.send(result)
}

struct RuntimeComponents {
    cache_store: profile::ThreadSafeCacheFile,
    dns_resolver: ThreadSafeDNSResolver,
    outbound_manager: Arc<OutboundManager>,
    router: Arc<Router>,
    dispatcher: Arc<Dispatcher>,
    statistics_manager: Arc<StatisticsManager>,

    #[cfg(feature = "tun")]
    tun_runner: Arc<tun::TunRunner>,
    dns_listener: Arc<dns::DnsRunner>,
    inbound_manager: Arc<InboundManager>,
    dns_listen: DNSListenAddr,
    dns_enabled: bool,
    ipv6_allowed: bool,
    #[cfg(feature = "tun")]
    network_config: RuntimeNetworkConfig,
}

impl RuntimeComponents {
    fn tun_candidate_exclusion(&self) -> app::network::TunCandidateExclusion {
        #[cfg(feature = "tun")]
        {
            if self.tun_runner.is_enabled() {
                self.tun_runner
                    .interface_name_hint()
                    .map(app::network::TunCandidateExclusion::Named)
                    .unwrap_or(app::network::TunCandidateExclusion::Unidentified)
            } else {
                app::network::TunCandidateExclusion::Disabled
            }
        }
        #[cfg(not(feature = "tun"))]
        {
            app::network::TunCandidateExclusion::Disabled
        }
    }
}

async fn refresh_runtime_health(
    components: &RuntimeComponents,
    api_listener: &app::api::ApiRunner,
    status: &tokio::sync::RwLock<app::network::NetworkStatus>,
) {
    use app::runtime_state::{
        RuntimeComponent as Name, RuntimeComponentPhase as Phase,
    };

    let api_configured = api_listener.is_configured();
    let api_finished = api_listener.task_finished();
    let dns_configured = components.dns_listener.is_configured();
    let dns_finished = components.dns_listener.task_finished();
    let inbound_configured =
        components.inbound_manager.has_configured_listeners().await;
    let inbound_failed = components.inbound_manager.has_finished_listener().await;

    #[cfg(feature = "tun")]
    let tun_update = {
        let enabled = components.tun_runner.is_enabled();
        let failed = enabled && components.tun_runner.task_finished();
        (
            Name::Tun,
            if !enabled {
                Phase::NotConfigured
            } else if failed {
                Phase::Failed
            } else {
                Phase::Ready
            },
            failed.then(|| "TUN runner task exited unexpectedly".to_owned()),
        )
    };
    #[cfg(not(feature = "tun"))]
    let tun_update = (Name::Tun, Phase::NotConfigured, None);

    let updates = vec![
        (
            Name::Api,
            if !api_configured {
                Phase::NotConfigured
            } else if api_finished {
                Phase::Failed
            } else {
                Phase::Ready
            },
            (api_configured && api_finished)
                .then(|| "API listener task exited unexpectedly".to_owned()),
        ),
        (
            Name::Dns,
            if !dns_configured {
                Phase::NotConfigured
            } else if dns_finished {
                Phase::Failed
            } else {
                Phase::Ready
            },
            (dns_configured && dns_finished)
                .then(|| "DNS listener task exited unexpectedly".to_owned()),
        ),
        (
            Name::Inbound,
            if !inbound_configured {
                Phase::NotConfigured
            } else if inbound_failed {
                Phase::Failed
            } else {
                Phase::Ready
            },
            inbound_failed.then(|| {
                "one or more inbound listener tasks exited unexpectedly".to_owned()
            }),
        ),
        tun_update,
    ];

    let mut status = status.write().await;
    for (name, phase, error) in updates {
        if status.set_component(name, phase, error.clone()) && phase == Phase::Failed
        {
            warn!(?name, error = ?error, "runtime component failed");
        }
    }
    status.expire_health();
}

impl RuntimeComponents {
    async fn apply_network_observation(
        &self,
        observer: &mut app::network::NetworkObserver,
        status: &tokio::sync::RwLock<app::network::NetworkStatus>,
        snapshot: app::network::NetworkSnapshot,
        latest_samples: &mut tokio::sync::watch::Receiver<
            Option<app::network::NetworkSample>,
        >,
    ) {
        status.write().await.observed(&snapshot);
        let Some(path_changed) =
            observer.observe(&snapshot, tokio::time::Instant::now())
        else {
            return;
        };
        let cause = if observer.is_applied(&snapshot) {
            app::runtime_state::RecoveryCause::Retry
        } else {
            app::runtime_state::RecoveryCause::NetworkChanged
        };
        let _ = self
            .perform_network_recovery(
                observer,
                status,
                NetworkRecoveryRequest {
                    snapshot: Some(snapshot),
                    path_changed,
                    cause,
                    observation_error: None,
                },
                Some(latest_samples),
            )
            .await;
    }

    async fn perform_network_recovery(
        &self,
        observer: &mut app::network::NetworkObserver,
        status: &tokio::sync::RwLock<app::network::NetworkStatus>,
        request: NetworkRecoveryRequest,
        latest_samples: Option<
            &mut tokio::sync::watch::Receiver<Option<app::network::NetworkSample>>,
        >,
    ) -> Result<app::network::NetworkResetResponse> {
        recover_to_latest_environment(
            observer,
            status,
            request,
            latest_samples,
            |snapshot, path_changed| async move {
                self.recover_network(snapshot.as_ref(), path_changed).await
            },
        )
        .await
    }

    async fn recover_network(
        &self,
        snapshot: Option<&app::network::NetworkSnapshot>,
        path_changed: bool,
    ) -> app::runtime_state::RecoveryReport {
        #[cfg(feature = "tun")]
        let mut interface_result = app::runtime_state::ComponentResult::skipped();
        #[cfg(not(feature = "tun"))]
        let interface_result = app::runtime_state::ComponentResult::skipped();
        #[cfg(feature = "tun")]
        if self.network_config.uses_global_state()
            && let Some(snapshot) = snapshot
        {
            let selected = if self.network_config.interface.is_some() {
                app::net::resolve_outbound_interface(
                    self.network_config.interface.as_ref(),
                )
                .await
            } else if self.network_config.tun_enabled {
                match snapshot.ipv4.as_ref().or(snapshot.ipv6.as_ref()) {
                    Some(path) => {
                        app::net::resolve_outbound_interface(Some(
                            &app::net::Interface::Name(path.interface.clone()),
                        ))
                        .await
                    }
                    None => Ok(None),
                }
            } else {
                Ok(None)
            };
            match selected {
                Ok(interface) => {
                    interface_result =
                        app::runtime_state::ComponentResult::refreshed(0);
                    *app::net::DEFAULT_OUTBOUND_INTERFACE.write().await = interface;
                    #[cfg(target_os = "macos")]
                    {
                        let ipv6 = if self.network_config.interface.is_none()
                            && self.network_config.tun_enabled
                        {
                            snapshot.ipv6.as_ref().and_then(|path| {
                                app::net::get_interface_by_name(&path.interface)
                            })
                        } else {
                            None
                        };
                        *app::net::DEFAULT_OUTBOUND_INTERFACE_V6.write().await =
                            ipv6;
                    }
                    app::net::OUTBOUND_INTERFACE_UNAVAILABLE
                        .store(false, std::sync::atomic::Ordering::Release);
                }
                Err(error) => {
                    app::net::OUTBOUND_INTERFACE_UNAVAILABLE
                        .store(true, std::sync::atomic::Ordering::Release);
                    interface_result =
                        app::runtime_state::ComponentResult::failed(error);
                }
            }
        }
        if path_changed {
            self.dispatcher.invalidate_network_sessions();
        }
        let mut report = app::network::reset_resources_report(
            self.dns_resolver.reset_transports(),
            async {
                if path_changed {
                    self.outbound_manager.reset_connection_pools().await
                } else {
                    Ok(0)
                }
            },
        )
        .await;
        report.interface = interface_result;
        report.offline = snapshot.is_some_and(|snapshot| !snapshot.has_path());
        if !path_changed {
            report.pools = app::runtime_state::ComponentResult::skipped();
        }
        report
    }

    fn api_listener(
        &self,
        controller_cfg: config::internal::config::Controller,
        log_tx: broadcast::Sender<LogEvent>,
        global_state: Arc<Mutex<GlobalState>>,
        cwd: &std::path::Path,
        cancellation_token: tokio_util::sync::CancellationToken,
    ) -> Arc<app::api::ApiRunner> {
        Arc::new(app::api::ApiRunner::new(
            controller_cfg,
            log_tx,
            self.inbound_manager.clone(),
            self.dispatcher.clone(),
            global_state,
            self.dns_resolver.clone(),
            self.outbound_manager.clone(),
            self.statistics_manager.clone(),
            self.cache_store.clone(),
            self.router.clone(),
            cwd.to_string_lossy().to_string(),
            Some(cancellation_token),
            self.dns_listen.clone(),
            self.dns_enabled,
            self.ipv6_allowed,
        ))
    }

    fn start_all(&self) {
        #[cfg(all(feature = "tun", not(target_os = "macos")))]
        self.tun_runner.run_async();
        self.dns_listener.run_async();
        #[cfg(not(target_os = "macos"))]
        self.inbound_manager.run_async();
    }

    async fn wait_initial_ready(
        &self,
        status: &tokio::sync::RwLock<app::network::NetworkStatus>,
    ) -> Result<()> {
        if let Err(error) = self.dns_listener.wait_ready().await {
            status.write().await.set_component(
                app::runtime_state::RuntimeComponent::Dns,
                app::runtime_state::RuntimeComponentPhase::Failed,
                Some(error.to_string()),
            );
            return Err(error);
        }
        status.write().await.set_component(
            app::runtime_state::RuntimeComponent::Dns,
            if self.dns_listener.is_configured() {
                app::runtime_state::RuntimeComponentPhase::Ready
            } else {
                app::runtime_state::RuntimeComponentPhase::NotConfigured
            },
            None,
        );

        #[cfg(feature = "tun")]
        {
            #[cfg(target_os = "macos")]
            self.tun_runner.run_async();
            if let Err(error) = self.tun_runner.wait_ready().await {
                status.write().await.set_component(
                    app::runtime_state::RuntimeComponent::Tun,
                    app::runtime_state::RuntimeComponentPhase::Failed,
                    Some(error.to_string()),
                );
                return Err(error);
            }
            status.write().await.set_component(
                app::runtime_state::RuntimeComponent::Tun,
                if self.tun_runner.is_enabled() {
                    app::runtime_state::RuntimeComponentPhase::Ready
                } else {
                    app::runtime_state::RuntimeComponentPhase::NotConfigured
                },
                None,
            );
        }
        #[cfg(not(feature = "tun"))]
        status.write().await.set_component(
            app::runtime_state::RuntimeComponent::Tun,
            app::runtime_state::RuntimeComponentPhase::NotConfigured,
            None,
        );

        #[cfg(target_os = "macos")]
        {
            self.inbound_manager.run_async();
        }

        #[cfg(all(target_os = "macos", not(feature = "tun")))]
        self.inbound_manager.run_async();

        if let Err(error) = self.inbound_manager.wait_ready().await {
            status.write().await.set_component(
                app::runtime_state::RuntimeComponent::Inbound,
                app::runtime_state::RuntimeComponentPhase::Failed,
                Some(error.to_string()),
            );
            return Err(error);
        }
        let inbound_configured =
            self.inbound_manager.has_configured_listeners().await;
        status.write().await.set_component(
            app::runtime_state::RuntimeComponent::Inbound,
            if inbound_configured {
                app::runtime_state::RuntimeComponentPhase::Ready
            } else {
                app::runtime_state::RuntimeComponentPhase::NotConfigured
            },
            None,
        );
        Ok(())
    }

    async fn fresh_data_plane(&self) -> Result<Self> {
        let cancellation_token = tokio_util::sync::CancellationToken::new();
        Ok(Self {
            cache_store: self.cache_store.clone(),
            dns_resolver: self.dns_resolver.clone(),
            outbound_manager: self.outbound_manager.clone(),
            router: self.router.clone(),
            dispatcher: self.dispatcher.clone(),
            statistics_manager: self.statistics_manager.clone(),
            #[cfg(feature = "tun")]
            tun_runner: Arc::new(
                self.tun_runner.fresh(cancellation_token.child_token())?,
            ),
            dns_listener: Arc::new(
                self.dns_listener.fresh(cancellation_token.child_token()),
            ),
            inbound_manager: Arc::new(
                self.inbound_manager
                    .fresh(cancellation_token.child_token())
                    .await,
            ),
            dns_listen: self.dns_listen.clone(),
            dns_enabled: self.dns_enabled,
            ipv6_allowed: self.ipv6_allowed,
            #[cfg(feature = "tun")]
            network_config: self.network_config.clone(),
        })
    }

    fn stop_all(&self) {
        self.dns_listener.shutdown();
        #[cfg(feature = "tun")]
        self.tun_runner.shutdown();
        Runner::shutdown(self.inbound_manager.as_ref());
    }

    #[cfg(feature = "tun")]
    async fn activate_network_config(&self) -> Result<()> {
        self.network_config.activate().await
    }

    async fn stop_all_and_join(&self, _clear_network: bool) {
        self.stop_all();

        tracing::debug!("todo: validate");
        if let Err(err) = self.dns_listener.join().await {
            warn!("failed waiting for dns listener shutdown: {}", err);
        }

        #[cfg(feature = "tun")]
        {
            if let Err(err) = self.tun_runner.join().await {
                warn!("failed waiting for tun runner shutdown: {}", err);
            }
            if _clear_network && self.network_config.uses_global_state() {
                clear_net_config().await;
            }
        }

        if let Err(err) = self.inbound_manager.join().await {
            warn!("failed waiting for inbound manager shutdown: {}", err);
        }
    }
}

#[cfg(feature = "tun")]
async fn restore_network_after_failed_reload(
    active_components: &RuntimeComponents,
    new_components: &RuntimeComponents,
    network_runtime_lease: &mut NetworkRuntimeLease,
) -> Result<()> {
    if !new_components.network_config.uses_global_state() {
        return Ok(());
    }

    restore_active_network_config(active_components, network_runtime_lease).await
}

#[cfg(feature = "tun")]
async fn restore_active_network_config(
    active_components: &RuntimeComponents,
    network_runtime_lease: &mut NetworkRuntimeLease,
) -> Result<()> {
    if active_components.network_config.uses_global_state() {
        network_runtime_lease.ensure_active()?;
        active_components.activate_network_config().await
    } else {
        clear_net_config().await;
        network_runtime_lease.deactivate_to_neutral();
        Ok(())
    }
}

async fn create_components(
    cwd: PathBuf,
    config: InternalConfig,
    activate_network: bool,
) -> Result<RuntimeComponents> {
    let ipv6_allowed = !config.tun.enable || config.tun.gateway_v6.is_some();
    #[cfg(feature = "tun")]
    let network_config = RuntimeNetworkConfig {
        tun_enabled: config.tun.enable,
        tun_so_mark: config.tun.so_mark,
        interface: config.general.interface.clone(),
    };
    #[cfg(feature = "tun")]
    if activate_network && network_config.uses_global_state() {
        if config.tun.enable {
            debug!("tun enabled, initializing default outbound interface");
        } else if config.general.interface.is_some() {
            debug!(
                "general interface configured, initializing default outbound \
                 interface"
            );
        }
        init_net_config(
            config.tun.enable,
            config.tun.so_mark,
            config.general.interface.as_ref(),
        )
        .await?;
        install_default_socket_protector();
    }
    #[cfg(not(feature = "tun"))]
    let _ = activate_network;

    let cancellation_token = tokio_util::sync::CancellationToken::new();
    let network_path_source = crate::proxy::utils::NetworkPathSource::default();

    debug!("initializing cache store");
    let cache_store = profile::ThreadSafeCacheFile::new(
        cwd.join("cache.db").as_path().to_str().unwrap(),
        config.profile.store_selected,
    );

    let system_resolver = Arc::new(
        SystemResolver::new(config.dns.ipv6)
            .map_err(|x| Error::DNSError(x.to_string()))?,
    );

    debug!("initializing bootstrap outbounds");
    let plain_outbounds = OutboundManager::load_plain_outbounds(
        config
            .proxies
            .into_values()
            .filter_map(|x| match x {
                OutboundProxy::ProxyServer(s) => Some(s),
                _ => None,
            })
            .collect(),
    );

    // Create a shared outbound registry seeded with plain outbounds.
    // After OutboundManager is initialized it will be extended with all
    // handlers (plain + proxy groups + provider proxies), so DNS clients
    // and the HTTP client can use any of them for bootstrap traffic.
    let outbound_registry: crate::proxy::utils::OutboundHandlerRegistry =
        Arc::new(tokio::sync::RwLock::new(
            plain_outbounds
                .iter()
                .map(|x| (x.name().to_string(), x.clone()))
                .collect(),
        ));

    let control_plane_dns_resolver = build_auxiliary_dns_resolver(
        config
            .dns
            .proxy_server_nameserver
            .clone()
            .unwrap_or_else(|| config.dns.nameserver.clone()),
        config.dns.default_nameserver.clone(),
        config.general.ipv6,
        config.general.routing_mask,
        cache_store.clone(),
        outbound_registry.clone(),
        AuxiliaryDnsNetworkContext {
            system_resolver: system_resolver.clone(),
            network_path_source: network_path_source.clone(),
        },
    )
    .await?;
    let client = new_http_client(
        control_plane_dns_resolver.clone(),
        Some(outbound_registry.clone()),
    )
    .map_err(|x| Error::DNSError(x.to_string()))?;

    debug!("initializing dns resolver");
    // Clone the dns.listen for the DNS Server later before we consume the config
    // TODO: we should separate the DNS resolver and DNS server config here
    let dns_listen = config.dns.listen.clone();
    let dns_enable = config.dns.enable;
    let managed_dns_proxy_bridge = cfg!(target_os = "macos")
        && config.tun.enable
        && config.tun.dns_hijack
        && dns_enable;

    // Extract the country MMDB file/url config early so they can be consumed
    // here, while the actual MMDB loading happens after OutboundManager (like
    // geodata and asn_mmdb) so it benefits from the fully-populated outbound
    // registry when downloading the file.
    let country_mmdb_file = config.general.mmdb;
    let country_mmdb_download_url = config.general.mmdb_download_url;

    // Create a shared pending handle that the DNS resolver's GeoIPFilter holds.
    // It starts empty and is populated once the MMDB is loaded below.
    let pending_country_mmdb: Option<dns::PendingMmdb> = country_mmdb_file
        .as_ref()
        .map(|_| Arc::new(OnceLock::new()));

    let rule_dispatch = if config.dns.respect_rules {
        Some(dns::RuleDispatch::new())
    } else {
        None
    };

    let dns_resolver = dns::resolver::new_with_network_path_source(
        config.dns,
        Some(cache_store.clone()),
        pending_country_mmdb.clone(),
        outbound_registry.clone(),
        rule_dispatch.clone(),
        Some(network_path_source.clone()),
    )
    .await?;

    debug!("initializing outbound manager");
    let outbound_manager = Arc::new(
        OutboundManager::new_with_network_path_source(
            plain_outbounds,
            config
                .proxy_groups
                .into_values()
                .filter_map(|x| match x {
                    OutboundProxy::ProxyGroup(g) => Some(g),
                    _ => None,
                })
                .collect(),
            config.proxy_providers,
            config.proxy_names,
            dns_resolver.clone(),
            cache_store.clone(),
            cwd.to_string_lossy().to_string(),
            config.general.routing_mask,
            outbound_registry.clone(),
            network_path_source.clone(),
        )
        .await?,
    );

    if let Some(rd) = &rule_dispatch
        && rd
            .outbound_manager
            .set(Arc::downgrade(&outbound_manager))
            .is_err()
    {
        warn!(
            "RuleDispatch outbound_manager OnceLock was already set — this is \
             unexpected and indicates a double-initialization bug"
        );
    }

    debug!("initializing mmdb");
    let country_mmdb = if let Some(ref mmdb_file) = country_mmdb_file {
        let mmdb = Arc::new(
            mmdb::Mmdb::new(
                cwd.join(mmdb_file),
                country_mmdb_download_url
                    .unwrap_or(DEFAULT_COUNTRY_MMDB_DOWNLOAD_URL.to_string()),
                client.clone(),
            )
            .await?,
        ) as MmdbLookup;
        // Populate the shared handle so the DNS resolver's GeoIPFilter can use
        // it. Any inflight DNS fallback-IP filtering that ran before this point
        // will have been permissive (MMDB absent = pass-through), which is the
        // safe default during startup.
        if let Some(pending) = &pending_country_mmdb
            && pending.set(mmdb.clone()).is_err()
        {
            warn!(
                "country MMDB OnceLock was already set — this is unexpected and \
                 indicates a double-initialization bug"
            );
        }
        Some(mmdb)
    } else {
        debug!("country mmdb not set, skipping");
        None
    };

    debug!("initializing geosite");
    let geodata = if let Some(geosite_file) = config.general.geosite {
        Some(Arc::new(
            geodata::GeoData::new(
                cwd.join(&geosite_file),
                config
                    .general
                    .geosite_download_url
                    .unwrap_or(DEFAULT_GEOSITE_DOWNLOAD_URL.to_string()),
                client.clone(),
            )
            .await?,
        ) as GeoDataLookup)
    } else {
        debug!("geosite not set, skipping");
        None
    };

    debug!("initializing country asn mmdb");
    let asn_mmdb = if let Some(asn_mmdb_name) = config.general.asn_mmdb {
        Some(Arc::new(
            mmdb::Mmdb::new(
                cwd.join(&asn_mmdb_name),
                config
                    .general
                    .asn_mmdb_download_url
                    .unwrap_or(DEFAULT_ASN_MMDB_DOWNLOAD_URL.to_string()),
                client.clone(),
            )
            .await?,
        ) as MmdbLookup)
    } else {
        debug!("ASN mmdb not found and not configured for download, skipping");
        None
    };

    debug!("initializing router");
    let router = Arc::new(
        Router::new(
            config.rules,
            config.rule_providers,
            dns_resolver.clone(),
            country_mmdb,
            asn_mmdb,
            geodata,
            cwd.to_string_lossy().to_string(),
        )
        .await?,
    );

    if let Some(rd) = &rule_dispatch
        && rd.router.set(Arc::downgrade(&router)).is_err()
    {
        warn!(
            "RuleDispatch router OnceLock was already set — this is unexpected and \
             indicates a double-initialization bug"
        );
    }

    let tcp_buffer_size = config
        .experimental
        .as_ref()
        .and_then(|exp| exp.tcp_buffer_size);
    let proxy_resolve_local = config
        .experimental
        .as_ref()
        .is_some_and(|exp| exp.proxy_resolve_local);
    app::dispatcher::set_closed_flows_cap(
        config
            .experimental
            .as_ref()
            .and_then(|exp| exp.closed_flows_cap),
    );
    let statistics_manager = StatisticsManager::new();

    debug!("initializing dispatcher");
    let dispatcher = Arc::new(Dispatcher::new(
        outbound_manager.clone(),
        router.clone(),
        dns_resolver.clone(),
        config.general.mode,
        statistics_manager.clone(),
        tcp_buffer_size,
        proxy_resolve_local,
    ));

    debug!("initializing authenticator");
    let authenticator = Arc::new(auth::PlainAuthenticator::new(config.users));

    debug!("initializing inbound manager");
    let inbound_manager = Arc::new(
        InboundManager::new(
            dispatcher.clone(),
            authenticator,
            config.listeners,
            Some(cancellation_token.child_token()),
        )
        .await,
    );
    // if !config.inbound_providers.is_empty() {
    // debug!("loading inbound providers");
    // inbound_manager
    // .load_inbound_providers(
    // cwd.to_string_lossy().to_string(),
    // config.inbound_providers,
    // dns_resolver.clone(),
    // )
    // .await;
    // }

    #[cfg(feature = "tun")]
    debug!("initializing tun runner");
    #[cfg(feature = "tun")]
    let tun_runner = Arc::new(tun::TunRunner::new(
        config.tun,
        dispatcher.clone(),
        dns_resolver.clone(),
        Some(cancellation_token.child_token()),
    )?);

    debug!("initializing dns listener");
    let dns_listener = Arc::new(dns::DnsRunner::new_with_dns_proxy_bridge(
        dns_enable,
        dns_listen.clone(),
        dns_resolver.clone(),
        &cwd,
        Some(cancellation_token.child_token()),
        managed_dns_proxy_bridge,
    ));

    info!("all components initialized");
    Ok(RuntimeComponents {
        cache_store,
        dns_resolver,
        outbound_manager,
        router,
        dispatcher,
        statistics_manager,
        inbound_manager,
        #[cfg(feature = "tun")]
        tun_runner,
        dns_listener,
        dns_listen,
        dns_enabled: dns_enable,
        ipv6_allowed,
        #[cfg(feature = "tun")]
        network_config,
    })
}

static SHUTDOWN_TOKEN: std::sync::Mutex<Vec<tokio_util::sync::CancellationToken>> =
    std::sync::Mutex::new(Vec::new());

struct ShutdownTokenRegistration {
    token: tokio_util::sync::CancellationToken,
}

impl ShutdownTokenRegistration {
    fn register(token: tokio_util::sync::CancellationToken) -> Self {
        SHUTDOWN_TOKEN.lock().unwrap().push(token.clone());
        Self { token }
    }
}

impl Drop for ShutdownTokenRegistration {
    fn drop(&mut self) {
        self.token.cancel();
        SHUTDOWN_TOKEN
            .lock()
            .unwrap()
            .retain(|token| !token.is_cancelled());
    }
}

pub fn shutdown() -> bool {
    let mut token_guard = SHUTDOWN_TOKEN.lock().unwrap();
    if !token_guard.is_empty() {
        for token in token_guard.drain(..) {
            token.cancel();
        }
        warn!("Shutdown signal sent, waiting for shutdown to complete...");
        true
    } else {
        warn!("Shutdown token not initialized, cannot shutdown");
        false
    }
}

struct AuxiliaryDnsNetworkContext {
    system_resolver: Arc<SystemResolver>,
    network_path_source: crate::proxy::utils::NetworkPathSource,
}

async fn build_auxiliary_dns_resolver(
    nameserver: Vec<dns::config::NameServer>,
    default_nameserver: Vec<dns::config::NameServer>,
    ipv6: bool,
    fw_mark: Option<u32>,
    cache_store: profile::ThreadSafeCacheFile,
    outbounds: crate::proxy::utils::OutboundHandlerRegistry,
    network_context: AuxiliaryDnsNetworkContext,
) -> Result<ThreadSafeDNSResolver> {
    let effective_nameserver = if nameserver.is_empty() {
        default_nameserver.clone()
    } else {
        nameserver
    };

    if effective_nameserver.is_empty() {
        return Ok(network_context.system_resolver);
    }

    let cfg = dns::Config {
        enable: true,
        ipv6,
        nameserver: effective_nameserver,
        proxy_server_nameserver: None,
        direct_nameserver: None,
        fallback: Vec::new(),
        fallback_filter: Default::default(),
        listen: DNSListenAddr::default(),
        enhance_mode: def::DNSMode::Normal,
        default_nameserver,
        fake_ip_range: "198.18.0.1/16"
            .parse()
            .expect("static fake-ip-range must parse"),
        fake_ip_range6: None,
        fake_ip_filter: Vec::new(),
        store_fake_ip: false,
        store_smart_stats: false,
        hosts: None,
        nameserver_policy: HashMap::new(),
        edns_client_subnet: None,
        fw_mark,
        respect_rules: false,
    };

    dns::resolver::new_with_network_path_source(
        cfg,
        Some(cache_store),
        None,
        outbounds,
        None,
        Some(network_context.network_path_source),
    )
    .await
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Once;

    static INIT: Once = Once::new();

    pub fn initialize() {
        INIT.call_once(crate::setup_default_crypto_provider);
    }

    #[tokio::test]
    async fn control_task_completion_is_observed_without_a_shutdown_signal() {
        let token = tokio_util::sync::CancellationToken::new();
        let mut control = tokio::spawn(async { 7_u8 });
        let exit = crate::wait_for_control_or_shutdown(
            &mut control,
            &token,
            std::future::pending(),
        )
        .await;

        assert!(matches!(exit, crate::RuntimeExit::Control(Ok(7))));
        assert!(!token.is_cancelled());
    }

    #[tokio::test]
    async fn panic_in_control_loop_becomes_a_cleanup_error() {
        let result = crate::catch_control_panic(async {
            std::panic::panic_any("injected control task failure");
            #[allow(unreachable_code)]
            Ok(())
        })
        .await;

        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("control task panicked")
        );
    }

    #[tokio::test]
    async fn cancellation_interrupts_control_task_supervision() {
        let token = tokio_util::sync::CancellationToken::new();
        let mut control = tokio::spawn(std::future::pending::<()>());
        token.cancel();
        let exit = crate::wait_for_control_or_shutdown(
            &mut control,
            &token,
            std::future::pending(),
        )
        .await;

        assert!(matches!(exit, crate::RuntimeExit::Cancelled));
        control.abort();
        let _ = control.await;
    }

    #[tokio::test]
    async fn recovery_restarts_on_the_latest_network_sample_before_reporting_success()
     {
        use crate::NetworkRecoveryRequest;
        use crate::app::{
            network::{NetworkPath, NetworkSample, NetworkSnapshot},
            runtime_state::{
                ComponentResult, Lifecycle, RecoveryCause, RecoveryReport,
            },
        };
        use crate::recover_to_latest_environment;
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use tokio::sync::{Notify, watch};

        let path = |interface: &str, address: &str| NetworkSnapshot {
            ipv4: Some(NetworkPath {
                interface: interface.into(),
                index: if interface == "en0" { 1 } else { 2 },
                gateway: "192.0.2.1".into(),
                addresses: vec![address.into()],
            }),
            ..Default::default()
        };
        let old = path("en0", "192.0.2.2");
        let in_flight = path("en1", "192.0.2.3");
        let newest = path("en1", "192.0.2.4");
        let mut observer = crate::app::network::NetworkObserver::default();
        observer.applied(old);
        let mut state = crate::app::network::NetworkStatus::default();
        state.lifecycle(Lifecycle::Running, "testReady");
        let status = Arc::new(tokio::sync::RwLock::new(state));
        let (sample_tx, mut samples) = watch::channel(None);
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let recover = {
            let entered = entered.clone();
            let release = release.clone();
            let calls = calls.clone();
            move |_snapshot: Option<NetworkSnapshot>, _path_changed: bool| {
                let attempt = calls.fetch_add(1, Ordering::Relaxed);
                let entered = entered.clone();
                let release = release.clone();
                async move {
                    if attempt == 0 {
                        entered.notify_one();
                        release.notified().await;
                    }
                    RecoveryReport {
                        interface: ComponentResult::refreshed(0),
                        dns: ComponentResult::refreshed(1),
                        pools: ComponentResult::refreshed(1),
                        observation_error: None,
                        offline: false,
                    }
                }
            }
        };
        let worker_status = status.clone();
        let worker = tokio::spawn(async move {
            recover_to_latest_environment(
                &mut observer,
                &worker_status,
                NetworkRecoveryRequest {
                    snapshot: Some(in_flight),
                    path_changed: true,
                    cause: RecoveryCause::NetworkChanged,
                    observation_error: None,
                },
                Some(&mut samples),
                recover,
            )
            .await
        });

        tokio::time::timeout(std::time::Duration::from_secs(2), entered.notified())
            .await
            .expect("first recovery attempt did not start");
        sample_tx.send_replace(Some(NetworkSample {
            sequence: 7,
            sampled_at: tokio::time::Instant::now(),
            result: Ok(newest),
        }));
        release.notify_one();

        worker.await.unwrap().unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        let state = status.read().await;
        assert_eq!(
            state.phase(),
            crate::app::runtime_state::NetworkPhase::AwaitingTraffic
        );
        let json = serde_json::to_value(&*state).unwrap();
        assert_eq!(json["networkVersion"], 2);
        assert_eq!(json["lastSampleSequence"], 7);
        assert_eq!(json["operationHistory"][0]["outcome"], "superseded");
        assert_eq!(json["lastOperation"]["token"]["networkVersion"], 2);
    }

    #[tokio::test]
    async fn repeated_network_changes_during_recovery_fail_with_a_bounded_retry() {
        use crate::NetworkRecoveryRequest;
        use crate::app::{
            network::{NetworkPath, NetworkSample, NetworkSnapshot},
            runtime_state::{
                ComponentResult, Lifecycle, RecoveryCause, RecoveryReport,
            },
        };
        use crate::recover_to_latest_environment;
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use tokio::sync::watch;

        let path = |interface: &str, index: u32, address: &str| NetworkSnapshot {
            ipv4: Some(NetworkPath {
                interface: interface.into(),
                index,
                gateway: "192.0.2.1".into(),
                addresses: vec![address.into()],
            }),
            ..Default::default()
        };
        let mut observer = crate::app::network::NetworkObserver::default();
        observer.applied(path("en0", 1, "192.0.2.2"));
        let mut state = crate::app::network::NetworkStatus::default();
        state.lifecycle(Lifecycle::Running, "testReady");
        let status = Arc::new(tokio::sync::RwLock::new(state));
        let (sample_tx, mut samples) = watch::channel(None);
        let attempts = Arc::new(AtomicUsize::new(0));
        let recover = {
            let attempts = attempts.clone();
            move |_snapshot: Option<NetworkSnapshot>, _path_changed: bool| {
                let attempt = attempts.fetch_add(1, Ordering::Relaxed);
                let tx = sample_tx.clone();
                async move {
                    let next = if attempt == 0 {
                        path("en1", 2, "192.0.2.3")
                    } else {
                        path("en2", 3, "192.0.2.4")
                    };
                    tx.send_replace(Some(NetworkSample {
                        sequence: attempt as u64 + 1,
                        sampled_at: tokio::time::Instant::now(),
                        result: Ok(next),
                    }));
                    RecoveryReport {
                        interface: ComponentResult::refreshed(0),
                        dns: ComponentResult::refreshed(1),
                        pools: ComponentResult::refreshed(1),
                        observation_error: None,
                        offline: false,
                    }
                }
            }
        };
        let error = recover_to_latest_environment(
            &mut observer,
            &status,
            NetworkRecoveryRequest {
                snapshot: Some(path("en1", 4, "192.0.2.5")),
                path_changed: true,
                cause: RecoveryCause::NetworkChanged,
                observation_error: None,
            },
            Some(&mut samples),
            recover,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("changed repeatedly"));
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
        let state = status.read().await;
        assert_eq!(
            state.phase(),
            crate::app::runtime_state::NetworkPhase::Degraded
        );
        let json = serde_json::to_value(&*state).unwrap();
        assert!(
            json["lastError"]
                .as_str()
                .unwrap()
                .contains("changed repeatedly")
        );
    }

    #[tokio::test]
    async fn unchanged_snapshot_does_not_clear_failed_manual_recovery() {
        initialize();
        let cwd = tempfile::tempdir().unwrap();
        let config = crate::Config::Str(
            "mode: direct\nmmdb: null\ntun:\n  enable: false\n".into(),
        )
        .try_parse()
        .unwrap();
        let mut components =
            crate::create_components(cwd.path().to_path_buf(), config, false)
                .await
                .unwrap();
        let mut dns = crate::app::dns::MockClashResolver::new();
        dns.expect_reset_transports()
            .returning(|| Err(anyhow::anyhow!("injected DNS recovery failure")));
        components.dns_resolver = std::sync::Arc::new(dns);
        let snapshot = crate::app::network::NetworkSnapshot {
            ipv4: Some(crate::app::network::NetworkPath {
                interface: "test".into(),
                index: 1,
                gateway: "192.0.2.1".into(),
                addresses: vec!["192.0.2.2".into()],
            }),
            ..Default::default()
        };
        let mut observer = crate::app::network::NetworkObserver::default();
        observer.applied(snapshot.clone());
        let mut status = crate::app::network::NetworkStatus::default();
        status.lifecycle(crate::app::runtime_state::Lifecycle::Running, "testReady");
        let status = tokio::sync::RwLock::new(status);
        let error = components
            .perform_network_recovery(
                &mut observer,
                &status,
                crate::NetworkRecoveryRequest {
                    snapshot: Some(snapshot.clone()),
                    path_changed: true,
                    cause: crate::app::runtime_state::RecoveryCause::ManualReset,
                    observation_error: None,
                },
                None,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("injected DNS recovery failure"));
        let (_samples_tx, mut samples) = tokio::sync::watch::channel(None);
        components
            .apply_network_observation(
                &mut observer,
                &status,
                snapshot,
                &mut samples,
            )
            .await;
        assert_eq!(
            status.read().await.phase(),
            crate::app::runtime_state::NetworkPhase::Degraded
        );
        assert!(
            serde_json::to_value(&*status.read().await).unwrap()["lastError"]
                .as_str()
                .unwrap()
                .contains("injected DNS recovery failure")
        );
    }

    #[tokio::test]
    async fn automatic_network_observations_recover_and_deduplicate_without_reset_api()
     {
        initialize();
        let cwd = tempfile::tempdir().unwrap();
        let config = crate::Config::Str(
            "mode: direct\nmmdb: null\ntun:\n  enable: false\n".into(),
        )
        .try_parse()
        .unwrap();
        let mut components =
            crate::create_components(cwd.path().to_path_buf(), config, false)
                .await
                .unwrap();
        let resets = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut dns = crate::app::dns::MockClashResolver::new();
        let count = resets.clone();
        dns.expect_reset_transports().returning(move || {
            count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(1)
        });
        components.dns_resolver = std::sync::Arc::new(dns);
        let mut observer = crate::app::network::NetworkObserver::default();
        let mut state = crate::app::network::NetworkStatus::default();
        state.lifecycle(crate::app::runtime_state::Lifecycle::Running, "testReady");
        let status = tokio::sync::RwLock::new(state);
        let (_samples_tx, mut samples) = tokio::sync::watch::channel(None);
        for round in 0..20 {
            let snapshot = crate::app::network::NetworkSnapshot {
                ipv4: Some(crate::app::network::NetworkPath {
                    interface: format!("test{}", round % 2),
                    index: round + 1,
                    gateway: "192.0.2.1".into(),
                    addresses: vec![format!("192.0.2.{}", round + 2)],
                }),
                ..Default::default()
            };
            components
                .apply_network_observation(
                    &mut observer,
                    &status,
                    snapshot.clone(),
                    &mut samples,
                )
                .await;
            {
                let mut status = status.write().await;
                status.observation_failed("temporary snapshot read failure");
            }
            components
                .apply_network_observation(
                    &mut observer,
                    &status,
                    snapshot,
                    &mut samples,
                )
                .await;
            assert_eq!(
                resets.load(std::sync::atomic::Ordering::Relaxed),
                round as usize + 1
            );
            assert_eq!(
                status.read().await.phase(),
                crate::app::runtime_state::NetworkPhase::AwaitingTraffic
            );
        }
        components
            .apply_network_observation(
                &mut observer,
                &status,
                Default::default(),
                &mut samples,
            )
            .await;
        assert_eq!(
            status.read().await.phase(),
            crate::app::runtime_state::NetworkPhase::WaitingForNetwork
        );
        assert!(
            !serde_json::to_value(&*status.read().await).unwrap()["lastError"]
                .is_null()
        );
        let online = crate::app::network::NetworkSnapshot {
            ipv6: Some(crate::app::network::NetworkPath {
                interface: "test-v6".into(),
                index: 42,
                gateway: "fe80::1".into(),
                addresses: vec!["2001:db8::2".into()],
            }),
            ..Default::default()
        };
        components
            .apply_network_observation(&mut observer, &status, online, &mut samples)
            .await;
        assert_eq!(
            status.read().await.phase(),
            crate::app::runtime_state::NetworkPhase::AwaitingTraffic
        );
        assert_eq!(
            serde_json::to_value(&*status.read().await).unwrap()["failures"],
            0
        );
        assert_eq!(resets.load(std::sync::atomic::Ordering::Relaxed), 22);
    }

    #[test]
    #[serial_test::serial]
    fn shutdown_registration_is_pruned_when_runtime_exits() {
        crate::SHUTDOWN_TOKEN.lock().unwrap().clear();
        let token = tokio_util::sync::CancellationToken::new();
        let registration = crate::ShutdownTokenRegistration::register(token.clone());

        assert_eq!(crate::SHUTDOWN_TOKEN.lock().unwrap().len(), 1);
        drop(registration);

        assert!(token.is_cancelled());
        assert!(crate::SHUTDOWN_TOKEN.lock().unwrap().is_empty());
        assert!(!crate::shutdown());
    }

    #[cfg(feature = "tun")]
    #[test]
    fn network_runtime_lease_rejects_concurrent_owner() {
        let first = crate::NetworkRuntimeLease::acquire(true)
            .expect("the test should acquire the first network lease");
        let second = match crate::NetworkRuntimeLease::acquire(true) {
            Ok(_) => {
                panic!("a second runtime must not overwrite global network state")
            }
            Err(err) => err,
        };
        assert!(
            second
                .to_string()
                .contains("process-global network configuration")
        );
        drop(first);
        crate::NetworkRuntimeLease::acquire(true)
            .expect("the lease should be reusable after the owner exits");

        let first_neutral = crate::NetworkRuntimeLease::acquire(false)
            .expect("a runtime without network state should be shareable");
        let second_neutral = crate::NetworkRuntimeLease::acquire(false)
            .expect("neutral runtimes should be shareable");
        assert!(crate::NetworkRuntimeLease::acquire(true).is_err());
        drop(second_neutral);
        drop(first_neutral);
    }
}
