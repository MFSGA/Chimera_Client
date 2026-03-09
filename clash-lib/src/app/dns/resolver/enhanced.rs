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

use crate::app::dns::config::DNSNetMode;
use crate::{
    app::{
        dns::{ClashResolver, DNSConfig},
        profile::ThreadSafeCacheFile,
    },
    common::mmdb::MmdbLookup,
    proxy::OutboundHandler,
};
use hickory_proto::xfer::Protocol;

pub struct EnhancedResolver {
    ipv6: AtomicBool,
    store: ThreadSafeCacheFile,
    resolver: Option<TokioResolver>,
    fallback_resolver: Option<TokioResolver>,
    policy_resolvers: Vec<(String, TokioResolver)>,
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

        let resolver = build_resolver(&cfg.nameserver, cfg.ipv6).await;
        let fallback_resolver = build_resolver(&cfg.fallback, cfg.ipv6).await;
        let policy_resolvers = build_policy_resolvers(&cfg).await;

        Self {
            ipv6: AtomicBool::new(cfg.ipv6),
            store,
            resolver,
            fallback_resolver,
            policy_resolvers,
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
        let resolved = self.resolve_with_policy_then_fallback(host).await?;

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

impl EnhancedResolver {
    async fn resolve_with_policy_then_fallback(
        &self,
        host: &str,
    ) -> anyhow::Result<Option<std::net::IpAddr>> {
        if let Some(resolver) = self.match_policy_resolver(host) {
            if let Ok(resolved) =
                lookup_with_resolver(resolver, host, self.ipv6()).await
                && resolved.is_some()
            {
                return Ok(resolved);
            }
        }

        if let Some(resolver) = &self.resolver {
            match lookup_with_resolver(resolver, host, self.ipv6()).await {
                Ok(Some(ip)) => return Ok(Some(ip)),
                Ok(None) | Err(_) => {}
            }
        }

        if let Some(resolver) = &self.fallback_resolver {
            return lookup_with_resolver(resolver, host, self.ipv6()).await;
        }

        let response = tokio::net::lookup_host(format!("{host}:0")).await?;
        Ok(response
            .map(|addr| addr.ip())
            .find(|ip| self.ipv6() || ip.is_ipv4()))
    }

    fn match_policy_resolver(&self, host: &str) -> Option<&TokioResolver> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.policy_resolvers
            .iter()
            .filter(|(pattern, _)| domain_matches(&host, pattern))
            .max_by_key(|(pattern, _)| pattern.len())
            .map(|(_, resolver)| resolver)
    }
}

async fn build_resolver(
    nameservers: &[crate::app::dns::config::NameServer],
    ipv6: bool,
) -> Option<TokioResolver> {
    if nameservers.is_empty() {
        return None;
    }

    let mut resolver_config = ResolverConfig::new();
    for server in nameservers {
        let Ok(socket_addr) = server.to_socket_addr().await else {
            continue;
        };

        let protocol = match server.net {
            DNSNetMode::Udp => Protocol::Udp,
            DNSNetMode::Tcp => Protocol::Tcp,
            DNSNetMode::DoT | DNSNetMode::DoH | DNSNetMode::Dhcp => continue,
        };

        resolver_config
            .add_name_server(NameServerConfig::new(socket_addr, protocol));
    }

    if resolver_config.name_servers().is_empty() {
        return None;
    }

    let mut opts = ResolverOpts::default();
    opts.ip_strategy = if ipv6 {
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

async fn build_policy_resolvers(cfg: &DNSConfig) -> Vec<(String, TokioResolver)> {
    let mut out = Vec::new();
    for (domain, nameserver) in &cfg.nameserver_policy {
        if let Some(resolver) =
            build_resolver(std::slice::from_ref(nameserver), cfg.ipv6).await
        {
            out.push((domain.clone(), resolver));
        }
    }
    out
}

async fn lookup_with_resolver(
    resolver: &TokioResolver,
    host: &str,
    ipv6: bool,
) -> anyhow::Result<Option<std::net::IpAddr>> {
    let response = resolver.lookup_ip(host).await?;
    Ok(response.into_iter().find(|ip| ipv6 || ip.is_ipv4()))
}

fn domain_matches(host: &str, pattern: &str) -> bool {
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    host == pattern
        || host
            .strip_suffix(&pattern)
            .is_some_and(|rest| rest.ends_with('.'))
}
