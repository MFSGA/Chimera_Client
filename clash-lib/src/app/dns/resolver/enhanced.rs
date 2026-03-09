use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use async_trait::async_trait;
use hickory_resolver::{
    TokioResolver,
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
    name_server::TokioConnectionProvider,
};
use tracing::debug;

use crate::{
    app::{
        dns::{ClashResolver, DNSConfig},
        profile::ThreadSafeCacheFile,
    },
    common::mmdb::MmdbLookup,
    proxy::OutboundHandler,
};
use hickory_proto::xfer::Protocol;
use crate::app::dns::config::DNSNetMode;

pub struct EnhancedResolver {
    ipv6: AtomicBool,
    store: ThreadSafeCacheFile,
    resolver: Option<TokioResolver>,
    _mmdb: Option<MmdbLookup>,
    _outbounds: HashMap<String, Arc<dyn OutboundHandler>>,
}

impl EnhancedResolver {
    pub async fn new(
        cfg: DNSConfig,
        store: ThreadSafeCacheFile,
        mmdb: Option<MmdbLookup>,
        outbounds: HashMap<String, Arc<dyn OutboundHandler>>,
    ) -> Self {
        debug!(
            ipv6 = cfg.ipv6,
            nameservers = cfg.nameserver.len(),
            "creating enhanced resolver"
        );

        let resolver = build_resolver(&cfg).await;

        Self {
            ipv6: AtomicBool::new(cfg.ipv6),
            store,
            resolver,
            _mmdb: mmdb,
            _outbounds: outbounds,
        }
    }
}

#[async_trait]
impl ClashResolver for EnhancedResolver {
    async fn exchange(
        &self,
        message: &hickory_proto::op::Message,
    ) -> anyhow::Result<hickory_proto::op::Message> {
        Err(anyhow::anyhow!(
            "enhanced resolver dns exchange is not migrated yet: {:?}",
            message.queries()
        ))
    }

    fn ipv6(&self) -> bool {
        self.ipv6.load(Ordering::Relaxed)
    }

    fn set_ipv6(&self, enable: bool) {
        self.ipv6.store(enable, Ordering::Relaxed);
    }

    fn kind(&self) -> crate::app::dns::ResolverKind {
        crate::app::dns::ResolverKind::Clash
    }

    fn fake_ip_enabled(&self) -> bool {
        false
    }

    async fn is_fake_ip(&self, _: std::net::IpAddr) -> bool {
        false
    }

    async fn resolve(
        &self,
        host: &str,
        _enhanced: bool,
    ) -> anyhow::Result<Option<std::net::IpAddr>> {
        let resolved = if let Some(resolver) = &self.resolver {
            let response = resolver.lookup_ip(host).await?;
            response.into_iter().find(|ip| self.ipv6() || ip.is_ipv4())
        } else {
            let response = tokio::net::lookup_host(format!("{host}:0")).await?;
            response.map(|addr| addr.ip()).find(|ip| self.ipv6() || ip.is_ipv4())
        };

        if let Some(ip) = resolved {
            let ip = ip.to_string();
            self.store.set_host_to_ip(host, &ip).await;
            self.store.set_ip_to_host(&ip, host).await;
        }
        Ok(resolved)
    }

    async fn reverse_lookup(&self, ip: std::net::IpAddr) -> Option<String> {
        self.store.get_fake_ip(&ip.to_string()).await
    }

    async fn cached_for(&self, ip: std::net::IpAddr) -> Option<String> {
        self.store.get_fake_ip(&ip.to_string()).await
    }
}

async fn build_resolver(cfg: &DNSConfig) -> Option<TokioResolver> {
    if cfg.nameserver.is_empty() {
        return None;
    }

    let mut resolver_config = ResolverConfig::new();
    for server in &cfg.nameserver {
        let Ok(socket_addr) = server.to_socket_addr().await else {
            continue;
        };

        let protocol = match server.net {
            DNSNetMode::Udp => Protocol::Udp,
            DNSNetMode::Tcp => Protocol::Tcp,
            DNSNetMode::DoT | DNSNetMode::DoH | DNSNetMode::Dhcp => continue,
        };

        resolver_config.add_name_server(NameServerConfig::new(socket_addr, protocol));
    }

    if resolver_config.name_servers().is_empty() {
        return None;
    }

    let mut opts = ResolverOpts::default();
    opts.ip_strategy = if cfg.ipv6 {
        hickory_resolver::config::LookupIpStrategy::Ipv4AndIpv6
    } else {
        hickory_resolver::config::LookupIpStrategy::Ipv4Only
    };

    Some(
        TokioResolver::builder_with_config(
            resolver_config,
            TokioConnectionProvider::default(),
        )
        .with_options(opts)
        .build(),
    )
}
