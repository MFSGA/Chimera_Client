// todo
#![feature(ip)]
#![feature(sync_unsafe_cell)]

use std::{
    collections::HashMap,
    io,
    path::PathBuf,
    sync::{Arc, LazyLock, OnceLock, atomic::AtomicUsize},
};

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
    proxy::OutboundHandler,
    runner::Runner,
};

/// 2
pub mod app;
/// 4
mod common;
/// todo: #[cfg(not(feature = "internal"))]
mod config;
/// 3
mod proxy;
/// 5
mod session;

mod runner;

pub use session::Session;

pub use proxy::utils::{
    SocketProtector, clear_socket_protector, set_socket_protector,
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
    cwd: String,
}

impl GlobalState {
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

    app::logging::setup_logging(
        config.general.log_level,
        log_collector,
        &cwd,
        opts.log_file,
    );

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
            _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        }
        #[cfg(feature = "ring")]
        {
            _ = rustls::crypto::ring::default_provider().install_default();
        }
    });
}

pub async fn start(
    config: InternalConfig,
    cwd: String,
    log_tx: broadcast::Sender<LogEvent>,
) -> Result<()> {
    setup_default_crypto_provider();

    let shutdown_token = tokio_util::sync::CancellationToken::new();

    {
        let mut token_guard = SHUTDOWN_TOKEN.lock().unwrap();
        token_guard.push(shutdown_token.clone());
    }

    let cwd = PathBuf::from(cwd);

    // things we need to clone before consuming config
    let controller_cfg = config.general.controller.clone();
    let log_level = config.general.log_level;

    let components = create_components(cwd.clone(), config).await?;

    let (reload_tx, mut reload_rx) = mpsc::channel(1);

    let global_state = Arc::new(Mutex::new(GlobalState {
        log_level,
        #[cfg(feature = "tun")]
        tunnel_runner: components.tun_runner.clone(),
        dns_listener: components.dns_listener.clone(),
        reload_tx,
        cwd: cwd.to_string_lossy().to_string(),
    }));

    let api_listener: ArcRunner = Arc::new(app::api::ApiRunner::new(
        controller_cfg.clone(),
        log_tx.clone(),
        components.inbound_manager.clone(),
        components.dispatcher.clone(),
        global_state.clone(),
        components.dns_resolver.clone(),
        components.outbound_manager.clone(),
        components.statistics_manager.clone(),
        components.cache_store.clone(),
        components.router.clone(),
        cwd.to_string_lossy().to_string(),
        Some(shutdown_token.child_token()),
        components.dns_listen.clone(),
        components.dns_enabled,
    ));

    // api_listener is not part of components because it requires components to be
    // initialized before it can be initialized. start it manually.
    api_listener.run_async();

    {
        let mut g = global_state.lock().await;
        #[cfg(feature = "tun")]
        {
            g.tunnel_runner = components.tun_runner.clone();
        }
        g.dns_listener = components.dns_listener.clone();
    }

    components.start_all();

    let cwd_clone = cwd.clone();

    let reload_token = shutdown_token.clone();
    tokio::spawn(async move {
        let mut active_components = components;
        let mut active_api_listener = api_listener;

        // Listen for config reload signal and reload config
        while let Some((config, done)) = reload_rx.recv().await {
            info!("reloading config");
            let config = match config.try_parse() {
                Ok(c) => c,
                Err(e) => {
                    error!("failed to reload config: {}", e);
                    let _ = done.send(Err(e));
                    continue;
                }
            };
            info!("reloading get config 2");
            let controller_cfg = config.general.controller.clone();

            active_components.stop_all_and_join().await;

            let new_components =
                match create_components(cwd_clone.clone(), config).await {
                    Ok(components) => components,
                    Err(e) => {
                        error!("failed to create components during reload: {}", e);
                        let _ = done.send(Err(e));
                        continue;
                    }
                };
            info!("reloading get components 3333");
            if done.send(Ok(())).is_err() {
                warn!("config reload response channel dropped before completion");
            }
            info!("reloading send 444");
            new_components.start_all();

            // TODO: every reload is causing the API server to restart, we should
            // make the API server reloadable instead of restarting it.
            // maybe adding APIs to replace components
            // and only recreate the listeners when necessary (e.g. when the listen
            // address or port is changed)
            let new_api_listener: ArcRunner = Arc::new(app::api::ApiRunner::new(
                controller_cfg,
                log_tx.clone(),
                new_components.inbound_manager.clone(),
                new_components.dispatcher.clone(),
                global_state.clone(),
                new_components.dns_resolver.clone(),
                new_components.outbound_manager.clone(),
                new_components.statistics_manager.clone(),
                new_components.cache_store.clone(),
                new_components.router.clone(),
                cwd_clone.to_string_lossy().to_string(),
                Some(reload_token.child_token()),
                new_components.dns_listen.clone(),
                new_components.dns_enabled,
            ));
            let mut g = global_state.lock().await;

            #[cfg(feature = "tun")]
            {
                g.tunnel_runner = new_components.tun_runner.clone();
            }
            g.dns_listener = new_components.dns_listener.clone();

            active_api_listener.shutdown();
            if let Err(err) = active_api_listener.join().await {
                warn!("failed waiting for api listener shutdown: {}", err);
            }
            new_api_listener.run_async();

            active_components = new_components;
            active_api_listener = new_api_listener;
        }
        Ok::<(), Error>(())
    });

    tokio::select! {
        result = tokio::signal::ctrl_c() => { result.map_err(Error::Io)?; }
        _ = shutdown_token.cancelled() => {}
    }
    Ok(())
}

struct RuntimeComponents {
    cache_store: profile::ThreadSafeCacheFile,
    dns_resolver: ThreadSafeDNSResolver,
    outbound_manager: Arc<OutboundManager>,
    router: Arc<Router>,
    dispatcher: Arc<Dispatcher>,
    statistics_manager: Arc<StatisticsManager>,

    #[cfg(feature = "tun")]
    tun_runner: ArcRunner,
    dns_listener: ArcRunner,
    inbound_manager: Arc<InboundManager>,
    dns_listen: DNSListenAddr,
    dns_enabled: bool,
}

impl RuntimeComponents {
    fn start_all(&self) {
        self.dns_listener.run_async();
        #[cfg(feature = "tun")]
        self.tun_runner.run_async();
        self.inbound_manager.run_async();
    }

    fn stop_all(&self) {
        #[cfg(feature = "tun")]
        self.tun_runner.shutdown();
        self.dns_listener.shutdown();
        Runner::shutdown(self.inbound_manager.as_ref());
    }

    async fn stop_all_and_join(&self) {
        self.stop_all();

        #[cfg(feature = "tun")]
        {
            if let Err(err) = self.tun_runner.join().await {
                warn!("failed waiting for tun runner shutdown: {}", err);
            }
            clear_net_config().await;
        }

        tracing::debug!("todo: validate");
        // if let Err(err) = self.dns_listener.join().await {
        // warn!("failed waiting for dns listener shutdown: {}", err);
        // }

        //  if let Err(err) = self.inbound_manager.join().await {
        // warn!("failed waiting for inbound manager shutdown: {}", err);
        // }
    }
}

fn dns_listener_is_empty(listen: &DNSListenAddr) -> bool {
    listen.udp.is_none()
        && listen.tcp.is_none()
        && listen.doh.is_none()
        && listen.dot.is_none()
        && listen.doh3.is_none()
}

async fn create_components(
    cwd: PathBuf,
    config: InternalConfig,
) -> Result<RuntimeComponents> {
    #[cfg(feature = "tun")]
    {
        if config.tun.enable {
            debug!("tun enabled, initializing default outbound interface");
        } else if config.general.interface.is_some() {
            debug!(
                "general interface configured, initializing default outbound \
                 interface"
            );
        }
        init_net_config(config.tun.so_mark, config.general.interface.as_ref()).await;
    }

    let cancellation_token = tokio_util::sync::CancellationToken::new();

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

    let client =
        new_http_client(system_resolver.clone(), Some(outbound_registry.clone()))
            .map_err(|x| Error::DNSError(x.to_string()))?;

    debug!("initializing dns resolver");
    // Clone the dns.listen for the DNS Server later before we consume the config
    // TODO: we should separate the DNS resolver and DNS server config here
    let mut dns_listen = config.dns.listen.clone();
    let dns_enable = config.dns.enable;
    #[cfg(feature = "tun")]
    let auto_manage_linux_dns = cfg!(target_os = "linux")
        && config.tun.enable
        && config.tun.dns_hijack
        && dns_enable
        && dns_listener_is_empty(&dns_listen);

    #[cfg(feature = "tun")]
    if auto_manage_linux_dns {
        let localhost_dns = std::net::SocketAddr::from((
            std::net::Ipv4Addr::LOCALHOST,
            53,
        ));
        dns_listen.udp = Some(localhost_dns);
        dns_listen.tcp = Some(localhost_dns);
        info!(
            "auto-enabling local DNS listener on {} to avoid Linux stub-resolver bypass",
            localhost_dns
        );
    }

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

    let dns_resolver = dns::new_resolver(
        config.dns,
        Some(cache_store.clone()),
        pending_country_mmdb.clone(),
        outbound_registry.clone(),
    )
    .await;

    debug!("initializing outbound manager");
    let outbound_manager = Arc::new(
        OutboundManager::new(
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
        )
        .await?,
    );

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
            dns_resolver.clone(),
            country_mmdb,
            asn_mmdb,
            geodata,
            cwd.to_string_lossy().to_string(),
        )
        .await,
    );

    let statistics_manager = StatisticsManager::new();

    debug!("initializing dispatcher");
    let dispatcher = Arc::new(Dispatcher::new(
        outbound_manager.clone(),
        router.clone(),
        dns_resolver.clone(),
        config.general.mode,
        statistics_manager.clone(),
        None, // config.experimental.and_then(|e| e.tcp_buffer_size),
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
    let tun_runner: ArcRunner = Arc::new(tun::TunRunner::new(
        config.tun,
        dispatcher.clone(),
        dns_resolver.clone(),
        Some(cancellation_token.child_token()),
    )?);

    debug!("initializing dns listener");
    let dns_listener: ArcRunner = Arc::new(dns::DnsRunner::new(
        dns_enable,
        dns_listen.clone(),
        dns_resolver.clone(),
        &cwd,
        #[cfg(feature = "tun")]
        auto_manage_linux_dns,
        #[cfg(not(feature = "tun"))]
        false,
        Some(cancellation_token.child_token()),
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
    })
}

static SHUTDOWN_TOKEN: std::sync::Mutex<Vec<tokio_util::sync::CancellationToken>> =
    std::sync::Mutex::new(Vec::new());

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
