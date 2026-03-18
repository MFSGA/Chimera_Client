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
use futures::{FutureExt, TryFutureExt, future};
use hickory_proto::{
    op::Message,
    rr::RecordType,
    rr::{RData, Record},
};
use hickory_resolver::dns_lru::{DnsLru, TtlConfig};
use lru_time_cache::LruCache;
use tokio::sync::RwLock;
use tracing::{debug, error, instrument, trace, warn};

use super::SystemResolver;

use crate::{
    app::{
        dns::helper::build_dns_response_message,
        dns::{
            ClashResolver, DNSConfig, ThreadSafeDNSClient,
            fakeip::{
                FakeDns, FileStore, InMemStore, Opts as FakeDnsOpts,
                ThreadSafeFakeDns,
            },
            filters::{
                DomainFilter, FallbackDomainFilter, FallbackIPFilter, GeoIPFilter,
                IPNetFilter,
            },
            helper::make_clients,
        },
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
    main: Vec<ThreadSafeDNSClient>,
    fallback: Option<Vec<ThreadSafeDNSClient>>,
    fallback_domain_filters: Option<Vec<Box<dyn FallbackDomainFilter>>>,
    fallback_ip_filters: Option<Vec<Box<dyn FallbackIPFilter>>>,
    lru_cache: Option<Arc<RwLock<DnsLru>>>,
    policy: Option<StringTrie<Vec<ThreadSafeDNSClient>>>,
    fake_dns: Option<ThreadSafeFakeDns>,
    reverse_lookup_cache: Option<Arc<RwLock<LruCache<IpAddr, String>>>>,
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

        let (fallback_domain_filters, fallback_ip_filters) =
            build_fallback_filters(&cfg, mmdb.clone());
        let fake_dns =
            build_fake_dns(&cfg, store.clone()).expect("failed to create fake dns");
        let default_resolver = Arc::new(EnhancedResolver {
            ipv6: AtomicBool::new(false),
            store: store.clone(),
            hosts: None,
            main: make_clients(
                &cfg.default_nameserver,
                None,
                outbounds.clone(),
                cfg.edns_client_subnet.clone(),
                cfg.fw_mark,
                false,
            )
            .await,
            fallback: None,
            fallback_domain_filters: None,
            fallback_ip_filters: None,
            lru_cache: None,
            policy: None,
            fake_dns: None,
            reverse_lookup_cache: None,
            _mmdb: None,
            _outbounds: outbounds.clone(),
        });
        let main = make_clients(
            &cfg.nameserver,
            Some(default_resolver.clone()),
            outbounds.clone(),
            cfg.edns_client_subnet.clone(),
            cfg.fw_mark,
            cfg.ipv6,
        )
        .await;
        let fallback = if cfg.fallback.is_empty() {
            None
        } else {
            Some(
                make_clients(
                    &cfg.fallback,
                    Some(default_resolver.clone()),
                    outbounds.clone(),
                    cfg.edns_client_subnet.clone(),
                    cfg.fw_mark,
                    cfg.ipv6,
                )
                .await,
            )
        };
        let policy = build_policy_resolvers(
            &cfg,
            Some(default_resolver.clone()),
            outbounds.clone(),
        )
        .await;

        Self {
            ipv6: AtomicBool::new(cfg.ipv6),
            store,
            hosts: cfg.hosts,
            main,
            fallback,
            fallback_domain_filters,
            fallback_ip_filters,
            lru_cache: Some(Arc::new(RwLock::new(DnsLru::new(
                4096,
                TtlConfig::new(
                    Some(Duration::from_secs(1)),
                    Some(Duration::from_secs(1)),
                    Some(Duration::from_secs(60)),
                    Some(Duration::from_secs(10)),
                ),
            )))),
            policy,
            fake_dns,
            reverse_lookup_cache: Some(Arc::new(RwLock::new(
                LruCache::with_expiry_duration_and_capacity(
                    Duration::from_secs(3),
                    4096,
                ),
            ))),
            _mmdb: mmdb,
            _outbounds: outbounds,
        }
    }
}

#[async_trait]
impl ClashResolver for EnhancedResolver {
    async fn exchange(&self, message: &Message) -> anyhow::Result<Message> {
        let query = message
            .query()
            .ok_or_else(|| anyhow::anyhow!("invalid query message"))?;

        if let Some(lru) = &self.lru_cache
            && let Some(cached) = lru.read().await.get(query, Instant::now())
        {
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

            let (first, remaining) =
                future::select_ok(vec![v6.boxed(), v4.boxed()]).await?;
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
        if let Some(lru) = &self.reverse_lookup_cache
            && let Some(cached) = lru.read().await.peek(&ip).cloned()
        {
            trace!(%ip, host = cached, "reverse lookup cache hit");
            return Some(cached);
        }

        let Some(fake_dns) = &self.fake_dns else {
            return None;
        };

        fake_dns.write().await.reverse_lookup(ip).await
    }

    async fn cached_for(&self, ip: std::net::IpAddr) -> Option<String> {
        if let Some(lru) = &self.reverse_lookup_cache
            && let Some(cached) = lru.read().await.peek(&ip).cloned()
        {
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
        let q = message
            .query()
            .ok_or_else(|| anyhow::anyhow!("invalid query message"))?;

        let query = async move {
            if Self::is_ip_request(q) {
                return self.ip_exchange(message).await;
            }

            if let Some(matched) = self.match_policy(message) {
                return Self::batch_exchange(matched, message).await;
            }

            self.exchange_non_ip_query(message).await
        };

        let rv = query.await;

        if let Ok(msg) = &rv {
            self.maybe_cache_response(q, msg).await;
        }

        rv
    }

    #[instrument(skip_all, level = "trace")]
    async fn ip_exchange(&self, message: &Message) -> anyhow::Result<Message> {
        let host = Self::domain_name_of_message(message)
            .ok_or_else(|| anyhow::anyhow!("invalid query message"))?;

        let response = if let Some(policy) = self.match_policy(message) {
            Self::batch_exchange(policy, message).await?
        } else if self.should_only_query_fallback(message) {
            Self::batch_exchange(
                self.fallback.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("no fallback resolver available")
                })?,
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

    async fn maybe_cache_response(
        &self,
        query: &hickory_proto::op::Query,
        response: &Message,
    ) {
        if query.query_type() == RecordType::TXT
            && query.name().to_ascii().starts_with("_acme-challenge.")
        {
            return;
        }

        if let Some(lru) = &self.lru_cache {
            lru.write().await.insert_records(
                query.clone(),
                response.answers().iter().cloned(),
                Instant::now(),
            );
        }
    }

    fn domain_name_of_message(message: &Message) -> Option<String> {
        message
            .query()
            .map(|query| query.name().to_ascii().trim_end_matches('.').to_owned())
    }

    fn is_ip_request(query: &hickory_proto::op::Query) -> bool {
        query.query_class() == hickory_proto::rr::DNSClass::IN
            && matches!(query.query_type(), RecordType::A | RecordType::AAAA)
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

    fn should_only_query_fallback(&self, message: &Message) -> bool {
        if let (Some(_), Some(fallback_domain_filters)) =
            (&self.fallback, &self.fallback_domain_filters)
            && let Some(domain) = Self::domain_name_of_message(message)
        {
            for filter in fallback_domain_filters.iter() {
                if filter.apply(domain.as_str()) {
                    return true;
                }
            }
        }

        false
    }

    fn match_policy(&self, message: &Message) -> Option<&Vec<ThreadSafeDNSClient>> {
        if let (Some(_fallback), Some(_fallback_domain_filters), Some(policy)) =
            (&self.fallback, &self.fallback_domain_filters, &self.policy)
            && let Some(host) = Self::domain_name_of_message(message)
        {
            return policy
                .search(&host.trim_end_matches('.').to_ascii_lowercase())
                .and_then(|node| node.get_data());
        }

        None
    }

    async fn exchange_with_main_then_fallback(
        &self,
        message: &Message,
    ) -> anyhow::Result<Message> {
        if self.main.is_empty() {
            return Self::batch_exchange(
                self.fallback
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("no resolver available"))?,
                message,
            )
            .await;
        }

        let main_result = Self::batch_exchange(&self.main, message).await;

        if self.fallback.is_none() {
            return main_result;
        }

        if let Ok(response) = main_result {
            let ips = Self::ip_list_of_message(&response);
            if ips.first().is_some_and(|ip| self.should_ip_fallback(ip)) {
                return Self::batch_exchange(
                    self.fallback.as_ref().expect("checked above"),
                    message,
                )
                .await;
            }
            return Ok(response);
        }

        Self::batch_exchange(self.fallback.as_ref().expect("checked above"), message)
            .await
    }

    async fn exchange_non_ip_query(
        &self,
        message: &Message,
    ) -> anyhow::Result<Message> {
        if !self.main.is_empty() {
            if let Ok(response) = Self::batch_exchange(&self.main, message).await {
                return Ok(response);
            }
        }

        if let Some(fallback) = &self.fallback {
            return Self::batch_exchange(fallback, message).await;
        }

        Err(anyhow::anyhow!("no resolver available for dns query"))
    }

    fn should_ip_fallback(&self, ip: &IpAddr) -> bool {
        self.fallback_ip_filters
            .as_ref()
            .is_some_and(|filters| filters.iter().any(|filter| filter.apply(ip)))
    }

    #[instrument(skip(message), level = "trace")]
    async fn batch_exchange(
        resolvers: &Vec<ThreadSafeDNSClient>,
        message: &Message,
    ) -> anyhow::Result<Message> {
        if resolvers.is_empty() {
            return Err(anyhow::anyhow!("no resolver available"));
        }

        let mut queries = Vec::new();
        for resolver in resolvers {
            queries.push(
                async move {
                    resolver
                        .exchange(message)
                        .inspect_err(|err| {
                            error!(err = ?err, "resolve error");
                        })
                        .await
                }
                .boxed(),
            );
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
        if let Some(lru) = &self.reverse_lookup_cache {
            lru.write().await.insert(ip, host);
        }
    }
}

fn build_fake_dns(
    cfg: &DNSConfig,
    store: ThreadSafeCacheFile,
) -> Result<Option<ThreadSafeFakeDns>, crate::Error> {
    match cfg.enhance_mode {
        DNSMode::FakeIp => {
            let store: Box<dyn crate::app::dns::fakeip::Store> = if cfg.store_fake_ip
            {
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
) -> (
    Option<Vec<Box<dyn FallbackDomainFilter>>>,
    Option<Vec<Box<dyn FallbackIPFilter>>>,
) {
    let mut domain_filters: Vec<Box<dyn FallbackDomainFilter>> = Vec::new();
    let mut ip_filters: Vec<Box<dyn FallbackIPFilter>> = Vec::new();

    if !cfg.fallback_filter.domain.is_empty() {
        domain_filters
            .push(Box::new(DomainFilter::new(&cfg.fallback_filter.domain)));
    }

    if cfg.fallback_filter.geo_ip
        || cfg
            .fallback_filter
            .ip_cidr
            .as_ref()
            .is_some_and(|ip_cidr| !ip_cidr.is_empty())
    {
        if cfg.fallback_filter.geo_ip {
            ip_filters.push(Box::new(GeoIPFilter::new(
                &cfg.fallback_filter.geo_ip_code,
                mmdb,
            )));
        }

        if let Some(ip_cidr) = &cfg.fallback_filter.ip_cidr {
            for cidr in ip_cidr {
                ip_filters.push(Box::new(IPNetFilter::new(*cidr)));
            }
        }
    }

    (
        (!domain_filters.is_empty()).then_some(domain_filters),
        (!ip_filters.is_empty()).then_some(ip_filters),
    )
}

async fn build_policy_resolvers(
    cfg: &DNSConfig,
    resolver: Option<Arc<dyn ClashResolver>>,
    outbounds: HashMap<String, Arc<dyn OutboundHandler>>,
) -> Option<StringTrie<Vec<ThreadSafeDNSClient>>> {
    let mut out = StringTrie::new();
    let mut has_entries = false;
    for (domain, nameserver) in &cfg.nameserver_policy {
        let resolvers = make_clients(
            std::slice::from_ref(nameserver),
            resolver.clone(),
            outbounds.clone(),
            cfg.edns_client_subnet.clone(),
            cfg.fw_mark,
            cfg.ipv6,
        )
        .await;
        if !resolvers.is_empty() {
            has_entries = true;
            out.insert(domain, Arc::new(resolvers));
        }
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
