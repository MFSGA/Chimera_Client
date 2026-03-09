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
use futures::{FutureExt, future};
use hickory_resolver::{
    TokioResolver,
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
    dns_lru::{DnsLru, TtlConfig},
    name_server::TokioConnectionProvider,
};
use hickory_proto::{
    op::Message,
    op::ResponseCode,
    rr::{RData, Record},
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
            filters::{DomainFilter, FallbackDomainFilter, FallbackIpFilter, GeoIpFilter, IpNetFilter},
        },
        dns::helper::build_dns_response_message,
        profile::ThreadSafeCacheFile,
    },
    common::{mmdb::MmdbLookup, trie::StringTrie},
    config::def::DNSMode,
    proxy::OutboundHandler,
};

pub struct EnhancedResolver {
    ipv6: AtomicBool,
    store: ThreadSafeCacheFile,
    hosts: Option<StringTrie<IpAddr>>,
    resolver: Option<TokioResolver>,
    fallback_resolver: Option<TokioResolver>,
    fallback_domain_filters: Vec<Box<dyn FallbackDomainFilter>>,
    fallback_ip_filters: Vec<Box<dyn FallbackIpFilter>>,
    policy_resolvers: Option<StringTrie<TokioResolver>>,
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
        let (fallback_domain_filters, fallback_ip_filters) =
            build_fallback_filters(&cfg, mmdb.clone());
        let policy_resolvers = build_policy_resolvers(&cfg).await;
        let hosts = build_hosts_trie(&cfg.hosts);
        let fake_dns =
            build_fake_dns(&cfg, store.clone()).expect("failed to create fake dns");

        Self {
            ipv6: AtomicBool::new(cfg.ipv6),
            store,
            hosts,
            resolver,
            fallback_resolver,
            fallback_domain_filters,
            fallback_ip_filters,
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
        message: &Message,
    ) -> anyhow::Result<Message> {
        let query = message
            .query()
            .ok_or_else(|| anyhow::anyhow!("invalid query message"))?;

        if let Some(cached) = self.lru_cache.read().await.get(query, Instant::now()) {
            if !message.recursion_desired() {
                trace!(query = %query.name(), "dns cache hit");
                if let Ok(cached) = cached {
                    let mut response = build_dns_response_message(message, true, false);
                    response.add_answers(cached.records().iter().cloned());
                    return Ok(response);
                }
            } else {
                trace!(query = %query.name(), "dns cache present but bypassed");
            }
        }

        self.exchange_no_cache(message).await.map(|mut response| {
            if let Some(edns) = response.extensions_mut() {
                edns.options_mut()
                    .remove(hickory_proto::rr::rdata::opt::EdnsCode::Padding);
            }
            response
        })
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
        let resolved = if self.ipv6() {
            let v6 = self
                .resolve_v6(host, enhanced)
                .map(|result| result.map(|ip| ip.map(IpAddr::from)));
            let v4 = self
                .resolve_v4(host, enhanced)
                .map(|result| result.map(|ip| ip.map(IpAddr::from)));

            let (first, remaining) = future::select_ok(vec![v6.boxed(), v4.boxed()]).await?;
            if first.is_some() {
                first
            } else {
                future::select_all(remaining).await.0?
            }
        } else {
            self.resolve_v4(host, enhanced).await?.map(IpAddr::from)
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
        Ok(self
            .resolve_ip_by_type(host, RecordType::A, enhanced)
            .await?
            .and_then(|ip| match ip {
                IpAddr::V4(ip) => Some(ip),
                IpAddr::V6(_) => None,
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

        Ok(self
            .resolve_ip_by_type(host, RecordType::AAAA, enhanced)
            .await?
            .and_then(|ip| match ip {
                IpAddr::V6(ip) => Some(ip),
                IpAddr::V4(_) => None,
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
    async fn lookup_ip(
        &self,
        host: &str,
        query_type: RecordType,
    ) -> anyhow::Result<Vec<IpAddr>> {
        let mut message = Message::new();
        let mut query = hickory_proto::op::Query::new();
        let name = hickory_proto::rr::Name::from_str_relaxed(host)
            .map_err(|_| anyhow::anyhow!("invalid domain: {host}"))?
            .append_domain(&hickory_proto::rr::Name::root())?;
        query.set_name(name);
        query.set_query_type(query_type);
        message.add_query(query);
        message.set_recursion_desired(true);

        let response = self.exchange(&message).await?;
        let ips = Self::ip_list_of_message(&response);
        if ips.is_empty() {
            Err(anyhow::anyhow!("no record for hostname: {host}"))
        } else {
            Ok(ips)
        }
    }

    async fn exchange_no_cache(&self, message: &Message) -> anyhow::Result<Message> {
        let query = message
            .query()
            .ok_or_else(|| anyhow::anyhow!("invalid query message"))?;
        let response = if Self::is_ip_request(query) {
            self.ip_exchange(message).await?
        } else if let Some(policy) = self.match_policy(message) {
            self.batch_exchange(vec![policy], message).await?
        } else {
            self.exchange_non_ip_query(message).await?
        };

        self.maybe_cache_response(query, &response).await;
        Ok(response)
    }

    async fn ip_exchange(&self, message: &Message) -> anyhow::Result<Message> {
        let host = Self::domain_name_of_message(message).ok_or_else(|| {
            anyhow::anyhow!("invalid query message")
        })?;

        let response = if let Some(policy) = self.match_policy(message) {
            self.batch_exchange(vec![policy], message).await?
        } else if self.should_only_query_fallback_message(message) {
            self.batch_exchange(
                self.fallback_resolver.as_ref().into_iter().collect(),
                message,
            )
            .await?
        } else {
            self.exchange_with_main_then_fallback(message).await?
        };

        for ip in Self::ip_list_of_message(&response) {
            self.save_reverse_lookup(ip, host.clone()).await;
        }

        Ok(response)
    }

    async fn maybe_cache_response(&self, query: &hickory_proto::op::Query, response: &Message) {
        if query.query_type() == RecordType::TXT
            && query.name().to_ascii().starts_with("_acme-challenge.")
        {
            return;
        }

        self.lru_cache.write().await.insert_records(
            query.clone(),
            response.answers().iter().cloned(),
            Instant::now(),
        );
    }

    fn domain_name_of_message(message: &Message) -> Option<String> {
        message
            .query()
            .map(|query| query.name().to_ascii().trim_end_matches('.').to_owned())
    }

    fn is_ip_request(query: &hickory_proto::op::Query) -> bool {
        matches!(query.query_type(), RecordType::A | RecordType::AAAA)
    }

    fn ip_list_of_message(message: &Message) -> Vec<IpAddr> {
        Self::ip_list_of_records(message.answers())
    }

    fn ip_list_of_records(records: &[Record]) -> Vec<IpAddr> {
        records
            .iter()
            .filter_map(|record| match record.data() {
                RData::A(v4) => Some(IpAddr::V4(**v4)),
                RData::AAAA(v6) => Some(IpAddr::V6(**v6)),
                _ => None,
            })
            .collect()
    }

    fn should_only_query_fallback(&self, host: &str) -> bool {
        self.fallback_domain_filters
            .iter()
            .any(|filter| filter.apply(host))
    }

    fn should_only_query_fallback_message(&self, message: &Message) -> bool {
        let Some(host) = Self::domain_name_of_message(message) else {
            return false;
        };

        self.should_only_query_fallback(&host)
    }

    fn match_policy(&self, message: &Message) -> Option<&TokioResolver> {
        let host = Self::domain_name_of_message(message)?;
        self.match_policy_resolver(&host)
    }

    async fn exchange_with_main_then_fallback(
        &self,
        message: &Message,
    ) -> anyhow::Result<Message> {
        let main_resolvers: Vec<_> = self.resolver.as_ref().into_iter().collect();
        let fallback_resolvers: Vec<_> =
            self.fallback_resolver.as_ref().into_iter().collect();

        if main_resolvers.is_empty() {
            return self.batch_exchange(fallback_resolvers, message).await;
        }

        let main_result = self.batch_exchange(main_resolvers, message).await;

        if fallback_resolvers.is_empty() {
            return main_result;
        }

        if let Ok(response) = main_result {
            let ips = Self::ip_list_of_message(&response);
            if ips.first().is_some_and(|ip| self.should_ip_fallback(ip)) {
                return self.batch_exchange(fallback_resolvers, message).await;
            }
            return Ok(response);
        }

        self.batch_exchange(fallback_resolvers, message).await
    }

    async fn exchange_non_ip_query(
        &self,
        message: &Message,
    ) -> anyhow::Result<Message> {
        let main_resolvers: Vec<_> = self.resolver.as_ref().into_iter().collect();
        let fallback_resolvers: Vec<_> =
            self.fallback_resolver.as_ref().into_iter().collect();

        if !main_resolvers.is_empty() {
            if let Ok(response) = self.batch_exchange(main_resolvers, message).await {
                return Ok(response);
            }
        }

        if !fallback_resolvers.is_empty() {
            return self.batch_exchange(fallback_resolvers, message).await;
        }

        Err(anyhow::anyhow!("no resolver available for dns query"))
    }

    fn should_ip_fallback(&self, ip: &IpAddr) -> bool {
        self.fallback_ip_filters
            .iter()
            .any(|filter| filter.apply(ip))
    }

    async fn batch_exchange(
        &self,
        resolvers: Vec<&TokioResolver>,
        message: &Message,
    ) -> anyhow::Result<Message> {
        if resolvers.is_empty() {
            return Err(anyhow::anyhow!("no resolver available"));
        }

        let mut queries = Vec::with_capacity(resolvers.len());
        for resolver in resolvers {
            queries.push(exchange_with_resolver(resolver, message).boxed());
        }

        let timeout = tokio::time::sleep(Duration::from_secs(10));
        tokio::select! {
            result = future::select_ok(queries) => match result {
                Ok((response, _)) => Ok(response),
                Err(err) => Err(err),
            },
            _ = timeout => Err(anyhow::anyhow!("dns query timeout")),
        }
    }


    async fn resolve_ip_by_type(
        &self,
        host: &str,
        query_type: RecordType,
        enhanced: bool,
    ) -> anyhow::Result<Option<IpAddr>> {
        let normalized_host = host.trim_end_matches('.').to_ascii_lowercase();

        if enhanced
            && let Some(hosts) = &self.hosts
            && let Some(node) = hosts.search(&normalized_host)
            && let Some(ip) = node.get_data()
        {
            return Ok(match query_type {
                RecordType::A if ip.is_ipv4() => Some(*ip),
                RecordType::AAAA if ip.is_ipv6() => Some(*ip),
                _ => None,
            });
        }

        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(match query_type {
                RecordType::A if ip.is_ipv4() => Some(ip),
                RecordType::AAAA if ip.is_ipv6() => Some(ip),
                _ => None,
            });
        }

        if enhanced
            && query_type == RecordType::A
            && let Some(fake_dns) = &self.fake_dns
        {
            let mut fake_dns = fake_dns.write().await;
            if !fake_dns.should_skip(host) {
                return Ok(Some(fake_dns.lookup(host).await));
            }
        }

        match self.lookup_ip(host, query_type).await {
            Ok(ips) => Ok(ips.into_iter().find(|ip| match query_type {
                RecordType::A => ip.is_ipv4(),
                RecordType::AAAA => self.ipv6() && ip.is_ipv6(),
                _ => false,
            })),
            Err(_) => {
                let response = tokio::net::lookup_host(format!("{host}:0")).await?;
                Ok(response.map(|addr| addr.ip()).find(|ip| match query_type {
                    RecordType::A => ip.is_ipv4(),
                    RecordType::AAAA => self.ipv6() && ip.is_ipv6(),
                    _ => false,
                }))
            }
        }
    }

    async fn save_reverse_lookup(&self, ip: IpAddr, host: String) {
        trace!(%ip, host = %host, "reverse lookup cache insert");
        self.reverse_lookup_cache.write().await.insert(ip, host);
    }

    fn match_policy_resolver(&self, host: &str) -> Option<&TokioResolver> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.policy_resolvers
            .as_ref()
            .and_then(|policy| policy.search(&host))
            .and_then(|node| node.get_data())
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
                skipped_hostnames: build_skipped_hostnames_trie(&cfg.fake_ip_filter),
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

fn build_fallback_filters(
    cfg: &DNSConfig,
    mmdb: Option<MmdbLookup>,
) -> (Vec<Box<dyn FallbackDomainFilter>>, Vec<Box<dyn FallbackIpFilter>>) {
    let mut domain_filters: Vec<Box<dyn FallbackDomainFilter>> = Vec::new();
    let mut ip_filters: Vec<Box<dyn FallbackIpFilter>> = Vec::new();

    if !cfg.fallback_filter.domain.is_empty() {
        domain_filters.push(Box::new(DomainFilter::new(&cfg.fallback_filter.domain)));
    }

    if cfg.fallback_filter.geo_ip || !cfg.fallback_filter.ip_cidr.is_empty() {
        if cfg.fallback_filter.geo_ip {
            ip_filters.push(Box::new(GeoIpFilter::new(
                &cfg.fallback_filter.geo_ip_code,
                mmdb,
            )));
        }

        for cidr in &cfg.fallback_filter.ip_cidr {
            ip_filters.push(Box::new(IpNetFilter::new(*cidr)));
        }
    }

    (domain_filters, ip_filters)
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

async fn build_policy_resolvers(cfg: &DNSConfig) -> Option<StringTrie<TokioResolver>> {
    let mut out = StringTrie::new();
    let mut has_entries = false;
    for (domain, nameserver) in &cfg.nameserver_policy {
        if let Some(resolver) =
            build_resolver(std::slice::from_ref(nameserver), cfg.ipv6).await
        {
            has_entries = true;
            out.insert(domain, Arc::new(resolver));
        }
    }
    has_entries.then_some(out)
}

fn build_hosts_trie(hosts: &HashMap<String, IpAddr>) -> Option<StringTrie<IpAddr>> {
    let mut out = StringTrie::new();
    let mut has_entries = false;

    for (host, ip) in hosts {
        has_entries = true;
        out.insert(host, Arc::new(*ip));
    }

    has_entries.then_some(out)
}

fn build_skipped_hostnames_trie(hosts: &[String]) -> Option<StringTrie<bool>> {
    let mut out = StringTrie::new();
    let mut has_entries = false;

    for host in hosts {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        has_entries = true;
        out.insert(&host, Arc::new(true));
    }

    has_entries.then_some(out)
}

async fn exchange_with_resolver(
    resolver: &TokioResolver,
    message: &Message,
) -> anyhow::Result<Message> {
    let query = message
        .query()
        .ok_or_else(|| anyhow::anyhow!("invalid query message"))?;
    let lookup = resolver
        .lookup(query.name().clone(), query.query_type())
        .await?;

    let records: Vec<_> = lookup.record_iter().cloned().collect();
    let mut response = build_dns_response_message(message, true, false);

    if records.is_empty() {
        response.set_response_code(ResponseCode::NXDomain);
        return Ok(response);
    }

    response.set_response_code(ResponseCode::NoError);
    response.set_answer_count(records.len() as u16);
    response.add_answers(records);
    Ok(response)
}
