use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, OnceLock},
};

use tracing::{debug, info, warn};

use super::components::RuntimeComponents;
#[cfg(feature = "tun")]
use super::network::RuntimeNetworkConfig;
use crate::{
    Error, Result,
    app::{
        self,
        dispatcher::{Dispatcher, StatisticsManager},
        dns::{
            self, ThreadSafeDNSResolver, config::DNSListenAddr,
            resolver::SystemResolver,
        },
        inbound::manager::InboundManager,
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
        def,
        internal::{InternalConfig, proxy::OutboundProxy},
    },
};
#[cfg(feature = "tun")]
use crate::{
    app::net::init_net_config, install_default_socket_protector, proxy::tun,
};

pub(super) async fn create_components(
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
        service_discovery_mode: def::DnsServiceDiscoveryMode::Legacy,
        store_fake_ip: false,
        store_smart_stats: false,
        hosts: None,
        nameserver_policy: HashMap::new(),
        edns_client_subnet: None,
        fw_mark,
        respect_rules: false,
        compiled_policy: Default::default(),
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
