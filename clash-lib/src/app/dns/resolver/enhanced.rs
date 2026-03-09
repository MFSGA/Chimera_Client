use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use hickory_resolver::{
    TokioResolver,
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
    dns_lru::{DnsLru, TtlConfig},
    name_server::TokioConnectionProvider,
};
use hickory_proto::{
    op::ResponseCode,
    rr::RecordType,
    xfer::Protocol,
};
use lru_time_cache::LruCache;
use tokio::sync::RwLock;
use tracing::{debug, trace, warn};

use crate::{
    app::{
        dns::{
            ClashResolver, DNSConfig,
            config::DNSNetMode,
            fakeip::{FakeDns, FileStore, InMemStore, Opts as FakeDnsOpts},
        },
        dns::helper::{build_dns_response_message, ip_records},
        profile::ThreadSafeCacheFile,
    },
    common::mmdb::MmdbLookup,
    config::def::DNSMode,
    proxy::OutboundHandler,
};

pub struct EnhancedResolver {
    ipv6: AtomicBool,
    store: ThreadSafeCacheFile,
    hosts: HashMap<String, IpAddr>,
    resolver: Option<TokioResolver>,
    fallback_resolver: Option<TokioResolver>,
    policy_resolvers: Vec<(String, TokioResolver)>,
    lru_cache: Arc<RwLock<DnsLru>>,
    fake_dns: Option<Arc<RwLock<FakeDns>>>,
    reverse_lookup_cache: Arc<RwLock<LruCache<IpAddr, String>>>,
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
        let fake_dns =
            build_fake_dns(&cfg, store.clone()).expect("failed to create fake dns");

        Self {
            ipv6: AtomicBool::new(cfg.ipv6),
            store,
            hosts: cfg.hosts,
            resolver,
            fallback_resolver,
            policy_resolvers,
            lru_cache: Arc::new(RwLock::new(DnsLru::new(
                4096,
                TtlConfig::new(
                    Some(Duration::from_secs(1)),
                    Some(Duration::from_secs(1)),
                    Some(Duration::from_secs(60)),
                    Some(Duration::from_secs(10)),
                ),
            ))),
            fake_dns,
            reverse_lookup_cache: Arc::new(RwLock::new(
                LruCache::with_expiry_duration_and_capacity(
                    Duration::from_secs(3),
                    4096,
                ),
            )),
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
        let query = message
            .query()
            .ok_or_else(|| anyhow::anyhow!("invalid query message"))?;
        let query_type = query.query_type();

        if let Some(cached) = self.lru_cache.read().await.get(query, Instant::now()) {
            if !message.recursion_desired() {
                trace!(query = %query.name(), "dns cache hit");
                if let Ok(cached) = cached {
                    let mut response =
                        build_dns_response_message(message, true, false);
                    response.add_answers(cached.records().iter().cloned());
                    return Ok(response);
                }
            } else {
                trace!(query = %query.name(), "dns cache present but bypassed");
            }
        }

        if !matches!(query_type, RecordType::A | RecordType::AAAA) {
            return Err(anyhow::anyhow!(
                "unsupported dns query type in migrated path: {query_type:?}"
            ));
        }

        let host = query.name().to_ascii().trim_end_matches('.').to_string();
        let ips = match query_type {
            RecordType::A => self.resolve_v4(&host, true).await?.map(|ip| vec![ip.into()]),
            RecordType::AAAA => self.resolve_v6(&host, true).await?.map(|ip| vec![ip.into()]),
            _ => None,
        };

        let mut response = build_dns_response_message(message, true, false);
        match ips {
            Some(ips) if !ips.is_empty() => {
                let records = ip_records(
                    query.name().clone(),
                    crate::app::dns::server::DEFAULT_DNS_SERVER_TTL,
                    query_type,
                    &ips,
                );
                response.set_response_code(ResponseCode::NoError);
                response.set_answer_count(records.len() as u16);
                response.add_answers(records);
                self.lru_cache.write().await.insert_records(
                    query.clone(),
                    response.answers().iter().cloned(),
                    Instant::now(),
                );
                for ip in &ips {
                    self.save_reverse_lookup(*ip, host.clone()).await;
                }
            }
            _ => {
                warn!(host, ?query_type, "dns query returned no records");
                response.set_response_code(ResponseCode::NXDomain);
            }
        }

        Ok(response)
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
        self.fake_dns.is_some()
    }

    async fn is_fake_ip(&self, ip: std::net::IpAddr) -> bool {
        let Some(fake_dns) = &self.fake_dns else {
            return false;
        };

        fake_dns.write().await.is_fake_ip(ip).await
    }

    async fn resolve(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<std::net::IpAddr>> {
        let resolved = match self.ipv6() {
            true => {
                self.resolve_with_policy_then_fallback(host, RecordType::AAAA, enhanced)
                    .await?
                    .or(
                        self.resolve_with_policy_then_fallback(host, RecordType::A, enhanced)
                            .await?,
                    )
            }
            false => {
                self.resolve_with_policy_then_fallback(host, RecordType::A, enhanced)
                    .await?
            }
        };

        if let Some(ip) = resolved {
            let ip = ip.to_string();
            self.store.set_host_to_ip(host, &ip).await;
            self.store.set_ip_to_host(&ip, host).await;
        }
        Ok(resolved)
    }

    async fn resolve_v4(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<std::net::Ipv4Addr>> {
        let resolved = self
            .resolve_with_policy_then_fallback(host, RecordType::A, enhanced)
            .await?;
        Ok(resolved.and_then(|ip| match ip {
            std::net::IpAddr::V4(ip) => Some(ip),
            std::net::IpAddr::V6(_) => None,
        }))
    }

    async fn resolve_v6(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<std::net::Ipv6Addr>> {
        if !self.ipv6() {
            return Ok(None);
        }

        let resolved = self
            .resolve_with_policy_then_fallback(host, RecordType::AAAA, enhanced)
            .await?;
        Ok(resolved.and_then(|ip| match ip {
            std::net::IpAddr::V6(ip) => Some(ip),
            std::net::IpAddr::V4(_) => None,
        }))
    }

    async fn reverse_lookup(&self, ip: std::net::IpAddr) -> Option<String> {
        if let Some(cached) = self.reverse_lookup_cache.read().await.peek(&ip).cloned() {
            trace!(%ip, host = cached, "reverse lookup cache hit");
            return Some(cached);
        }

        let Some(fake_dns) = &self.fake_dns else {
            return None;
        };

        fake_dns.write().await.reverse_lookup(ip).await
    }

    async fn cached_for(&self, ip: std::net::IpAddr) -> Option<String> {
        if let Some(cached) = self.reverse_lookup_cache.read().await.peek(&ip).cloned() {
            return Some(cached);
        }
        self.store.get_fake_ip(&ip.to_string()).await
    }
}

impl EnhancedResolver {
    async fn resolve_with_policy_then_fallback(
        &self,
        host: &str,
        query_type: RecordType,
        enhanced: bool,
    ) -> anyhow::Result<Option<std::net::IpAddr>> {
        let normalized_host = host.trim_end_matches('.').to_ascii_lowercase();

        if enhanced && let Some(ip) = self.hosts.get(&normalized_host).copied() {
            return Ok(match query_type {
                RecordType::A if ip.is_ipv4() => Some(ip),
                RecordType::AAAA if ip.is_ipv6() => Some(ip),
                _ => None,
            });
        }

        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(Some(ip));
        }

        if enhanced
            && query_type == RecordType::A
            && let Some(fake_dns) = &self.fake_dns
        {
            let mut fake_dns = fake_dns.write().await;
            if !fake_dns.should_skip(host) {
                let ip = fake_dns.lookup(host).await;
                debug!(host, %ip, "fake dns lookup");
                return Ok(Some(ip));
            }
        }

        if let Some(resolver) = self.match_policy_resolver(host) {
            if let Ok(resolved) =
                lookup_with_resolver(resolver, host, self.ipv6(), query_type).await
                && resolved.is_some()
            {
                return Ok(resolved);
            }
        }

        if let Some(resolver) = &self.resolver {
            match lookup_with_resolver(resolver, host, self.ipv6(), query_type).await {
                Ok(Some(ip)) => return Ok(Some(ip)),
                Ok(None) | Err(_) => {}
            }
        }

        if let Some(resolver) = &self.fallback_resolver {
            return lookup_with_resolver(resolver, host, self.ipv6(), query_type).await;
        }

        let response = tokio::net::lookup_host(format!("{host}:0")).await?;
        Ok(response.map(|addr| addr.ip()).find(|ip| match query_type {
            RecordType::A => ip.is_ipv4(),
            RecordType::AAAA => self.ipv6() && ip.is_ipv6(),
            _ => false,
        }))
    }

    async fn save_reverse_lookup(&self, ip: IpAddr, host: String) {
        self.reverse_lookup_cache.write().await.insert(ip, host);
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

fn build_fake_dns(
    cfg: &DNSConfig,
    store: ThreadSafeCacheFile,
) -> Result<Option<Arc<RwLock<FakeDns>>>, crate::Error> {
    match cfg.enhance_mode {
        DNSMode::FakeIp => {
            let store: Box<dyn crate::app::dns::fakeip::Store> = if cfg.store_fake_ip {
                Box::new(FileStore::new(store))
            } else {
                Box::new(InMemStore::new(1000))
            };

            Ok(Some(Arc::new(RwLock::new(FakeDns::new(FakeDnsOpts {
                ipnet: cfg.fake_ip_range,
                skipped_hostnames: cfg.fake_ip_filter.clone(),
                store,
            })?))))
        }
        DNSMode::RedirHost => {
            warn!("dns redir-host is not supported and will not do anything");
            Ok(None)
        }
        DNSMode::Normal => Ok(None),
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
    query_type: RecordType,
) -> anyhow::Result<Option<std::net::IpAddr>> {
    let response = resolver.lookup_ip(host).await?;
    Ok(response.into_iter().find(|ip| match query_type {
        RecordType::A => ip.is_ipv4(),
        RecordType::AAAA => ipv6 && ip.is_ipv6(),
        _ => false,
    }))
}

fn domain_matches(host: &str, pattern: &str) -> bool {
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    host == pattern
        || host
            .strip_suffix(&pattern)
            .is_some_and(|rest| rest.ends_with('.'))
}
