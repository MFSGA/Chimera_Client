use crate::{
    Error,
    app::{dns::helper::DnsClientNetworkOptions, profile::ThreadSafeCacheFile},
    common::trie,
    config::def::DNSMode,
    dns::{
        ClashResolver, Config, ResolverKind, RuleDispatch, ThreadSafeDNSClient,
        ThreadSafeDNSResolver,
        fakeip::{self, FileStore, InMemStore, ThreadSafeFakeDns},
        filters::{
            DomainFilter, FallbackDomainFilter, FallbackIPFilter, GeoIPFilter,
            IPNetFilter, PendingMmdb,
        },
        health::{DnsHealthTracker, observe_clients},
        helper::make_clients,
        parse_ip_literal,
    },
    proxy::utils::NetworkPathSource,
};
use anyhow::anyhow;
use async_trait::async_trait;
use futures::{FutureExt, StreamExt};
use hickory_proto::{op, rr};
use rand::seq::IndexedRandom;
use std::{
    net,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering::Relaxed},
    },
    time::{Duration, Instant},
};
use tokio::sync::RwLock;
use tracing::{debug, error, instrument, trace, warn};

/// RFC 2308 negative answer, bounded by the authoritative SOA lifetime.
#[derive(Clone)]
struct NegativeEntry {
    response: op::Message,
    inserted: Instant,
    expires: Instant,
}

pub struct EnhancedResolver {
    ipv6: AtomicBool,
    health: Arc<DnsHealthTracker>,
    hosts: Option<trie::StringTrie<net::IpAddr>>,
    main: Vec<ThreadSafeDNSClient>,

    fallback: Option<Vec<ThreadSafeDNSClient>>,
    fallback_domain_filters: Option<Vec<Box<dyn FallbackDomainFilter>>>,
    fallback_ip_filters: Option<Vec<Box<dyn FallbackIPFilter>>>,

    lru_cache: Option<hickory_resolver::ResponseCache>,
    // The positive cache keys only by Question and cannot cache a negative
    // Message with a per-response SOA TTL. Keep a bounded negative cache
    // alongside it, activated only when the positive cache is enabled.
    negative_cache: Mutex<lru_time_cache::LruCache<String, NegativeEntry>>,
    policy: Option<trie::StringTrie<Vec<ThreadSafeDNSClient>>>,

    proxy_resolver: Option<Vec<ThreadSafeDNSClient>>,
    proxy_server_domains: Option<trie::StringTrie<bool>>,
    direct_resolver: Option<ThreadSafeDNSResolver>,

    fake_dns: Option<ThreadSafeFakeDns>,
    safe_srv: bool,

    reverse_lookup_cache:
        Option<Arc<RwLock<lru_time_cache::LruCache<net::IpAddr, String>>>>,
}

impl EnhancedResolver {
    fn negative_cache_key(query: &op::Query) -> String {
        format!(
            "{}|{}|{}",
            query.name().to_ascii().to_ascii_lowercase(),
            query.query_class(),
            query.query_type()
        )
    }

    fn negative_ttl(query: &op::Query, message: &op::Message) -> Option<u32> {
        if !matches!(
            message.metadata.response_code,
            op::ResponseCode::NXDomain | op::ResponseCode::NoError
        ) || !message.answers.is_empty()
            || message.metadata.truncation
            || message.edns.is_some()
            || message.signature.is_some()
        {
            return None;
        }
        // The SOA must belong to an ancestor zone of QNAME, not be an
        // unrelated authority record included in a response.
        message
            .authorities
            .iter()
            .filter_map(|record| {
                if !record.name.zone_of(query.name())
                    || record.dns_class != query.query_class()
                {
                    return None;
                }
                match &record.data {
                    rr::RData::SOA(soa) => {
                        let ttl = record.ttl.min(soa.minimum);
                        (ttl > 0).then_some(ttl)
                    }
                    _ => None,
                }
            })
            .min()
    }

    fn cached_negative(
        &self,
        query: &op::Query,
        request: &op::Message,
        now: Instant,
    ) -> Option<op::Message> {
        let key = Self::negative_cache_key(query);
        let mut entries = self
            .negative_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = entries.get(&key)?.clone();
        if now >= entry.expires {
            entries.remove(&key);
            return None;
        }
        let elapsed =
            u32::try_from(now.saturating_duration_since(entry.inserted).as_secs())
                .unwrap_or(u32::MAX);
        let mut response = entry.response;
        for record in response
            .answers
            .iter_mut()
            .chain(response.authorities.iter_mut())
            .chain(response.additionals.iter_mut())
        {
            record.decrement_ttl(elapsed);
        }
        response.metadata.id = request.metadata.id;
        response.metadata.recursion_desired = request.metadata.recursion_desired;
        response.metadata.checking_disabled = request.metadata.checking_disabled;
        response.queries = request.queries.clone();
        Some(response)
    }

    fn cache_negative(
        &self,
        query: &op::Query,
        response: &op::Message,
        now: Instant,
    ) {
        let Some(ttl) = Self::negative_ttl(query, response) else {
            return;
        };
        let mut response = response.clone();
        // The SOA TTL in a cached negative response cannot exceed
        // min(SOA RR TTL, SOA.MINIMUM), per RFC 2308.
        for record in &mut response.authorities {
            if matches!(record.data, rr::RData::SOA(_)) {
                record.ttl = record.ttl.min(ttl);
            }
        }
        let mut entries = self
            .negative_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.insert(
            Self::negative_cache_key(query),
            NegativeEntry {
                response,
                inserted: now,
                expires: now + Duration::from_secs(u64::from(ttl)),
            },
        );
    }

    // DNS responses can vary with EDNS, DNSSEC or per-query options, while
    // Hickory's ResponseCache uses only the Question as its key. Restrict
    // caching to ordinary, unsigned queries until those variants have
    // distinct cache keys.
    fn cache_safe_request(message: &op::Message) -> bool {
        message.queries.len() == 1
            && message.metadata.message_type == op::MessageType::Query
            && message.metadata.op_code == op::OpCode::Query
            && message.metadata.recursion_desired
            && !message.metadata.checking_disabled
            && !message.metadata.authentic_data
            && message.edns.is_none()
            && message.signature.is_none()
    }

    fn cache_safe_response(message: &op::Message) -> bool {
        message.metadata.response_code == op::ResponseCode::NoError
            && !message.answers.is_empty()
            && message.all_sections().all(|record| record.ttl > 0)
            && !message.metadata.truncation
            && !message.metadata.authentic_data
            && message.edns.is_none()
            && message.signature.is_none()
    }

    fn from_clients(main: Vec<ThreadSafeDNSClient>, ipv6: bool) -> Self {
        Self::from_clients_with_fallback(main, None, ipv6)
    }

    fn from_clients_with_fallback(
        main: Vec<ThreadSafeDNSClient>,
        fallback: Option<Vec<ThreadSafeDNSClient>>,
        ipv6: bool,
    ) -> Self {
        let health = Arc::new(DnsHealthTracker::default());
        let main = observe_clients(main, "main", &health);
        let fallback =
            fallback.map(|clients| observe_clients(clients, "fallback", &health));
        Self {
            ipv6: AtomicBool::new(ipv6),
            health,
            hosts: None,
            main,
            fallback,
            fallback_domain_filters: None,
            fallback_ip_filters: None,
            lru_cache: None,
            negative_cache: Mutex::new(lru_time_cache::LruCache::with_capacity(
                1024,
            )),
            policy: None,
            proxy_resolver: None,
            proxy_server_domains: None,
            direct_resolver: None,
            fake_dns: None,
            safe_srv: false,
            reverse_lookup_cache: None,
        }
    }

    /// For testing purpose
    #[cfg(test)]
    pub async fn new_default() -> Self {
        use std::net::Ipv4Addr;

        use crate::app::dns::dns_client::DNSNetMode;

        use crate::app::dns::config::NameServer;

        EnhancedResolver {
            ipv6: AtomicBool::new(false),
            health: Arc::new(DnsHealthTracker::default()),
            hosts: None,
            main: make_clients(
                vec![NameServer {
                    net: DNSNetMode::Udp,
                    host: url::Host::Ipv4(Ipv4Addr::from_octets([8, 8, 8, 8])),
                    port: 53,
                    interface: None,
                    proxy: None,
                    doh_path: None,
                }],
                None,
                None,
                std::sync::Arc::new(tokio::sync::RwLock::new(
                    std::collections::HashMap::new(),
                )),
                None,
                DnsClientNetworkOptions::default(),
            )
            .await
            .expect("default DNS client configuration should be valid"),
            fallback: None,
            fallback_domain_filters: None,
            fallback_ip_filters: None,
            lru_cache: None,
            negative_cache: Mutex::new(lru_time_cache::LruCache::with_capacity(
                1024,
            )),
            policy: None,

            proxy_resolver: None,
            proxy_server_domains: None,
            direct_resolver: None,

            fake_dns: None,
            safe_srv: false,

            reverse_lookup_cache: None,
        }
    }

    pub async fn new(
        cfg: Config,
        store: ThreadSafeCacheFile,
        mmdb: Option<PendingMmdb>,
        outbounds: crate::proxy::utils::OutboundHandlerRegistry,
        rule_dispatch: Option<Arc<RuleDispatch>>,
    ) -> Result<Self, Error> {
        Self::new_with_network_path_source(
            cfg,
            store,
            mmdb,
            outbounds,
            rule_dispatch,
            None,
        )
        .await
    }

    pub(crate) async fn new_with_network_path_source(
        cfg: Config,
        store: ThreadSafeCacheFile,
        mmdb: Option<PendingMmdb>,
        outbounds: crate::proxy::utils::OutboundHandlerRegistry,
        rule_dispatch: Option<Arc<RuleDispatch>>,
        network_path_source: Option<NetworkPathSource>,
    ) -> Result<Self, Error> {
        let edns_client_subnet = cfg.edns_client_subnet.clone();
        let health = Arc::new(DnsHealthTracker::default());
        let default_resolver = Arc::new(EnhancedResolver {
            ipv6: AtomicBool::new(false),
            health: health.clone(),
            hosts: None,
            main: make_clients(
                cfg.default_nameserver.clone(),
                None,
                None,
                Arc::new(RwLock::new(std::collections::HashMap::new())),
                edns_client_subnet.clone(),
                DnsClientNetworkOptions {
                    fw_mark: cfg.fw_mark,
                    network_path_source: network_path_source.clone(),
                    health: Some(health.clone()),
                    group: Some("bootstrap"),
                    ..Default::default()
                },
            )
            .await?,
            fallback: None,
            fallback_domain_filters: None,
            fallback_ip_filters: None,
            lru_cache: None,
            negative_cache: Mutex::new(lru_time_cache::LruCache::with_capacity(
                1024,
            )),
            policy: None,

            proxy_resolver: None,
            proxy_server_domains: None,
            direct_resolver: None,

            fake_dns: None,
            safe_srv: false,

            reverse_lookup_cache: None,
        });

        let proxy_resolver = if let Some(proxy_nameserver) =
            cfg.proxy_server_nameserver
        {
            let clients = make_clients(
                proxy_nameserver,
                Some(default_resolver.clone()),
                None,
                Arc::new(RwLock::new(std::collections::HashMap::new())),
                edns_client_subnet.clone(),
                DnsClientNetworkOptions {
                    fw_mark: cfg.fw_mark,
                    network_path_source: network_path_source.clone(),
                    health: Some(health.clone()),
                    group: Some("proxy_server"),
                    ..Default::default()
                },
            )
            .await?;
            if clients.is_empty() {
                warn!(
                    "no usable proxy-server-nameserver clients were initialized; \
                     proxy server domain resolution will fall back to the main \
                     nameservers"
                );
                None
            } else {
                Some(clients)
            }
        } else {
            None
        };

        let outbound_resolver: Arc<dyn ClashResolver> = proxy_resolver
            .as_ref()
            .map(|clients| {
                Arc::new(Self::from_clients(clients.clone(), cfg.ipv6))
                    as Arc<dyn ClashResolver>
            })
            .unwrap_or_else(|| default_resolver.clone());

        let main = make_clients(
            cfg.nameserver.clone(),
            Some(default_resolver.clone()),
            Some(outbound_resolver.clone()),
            outbounds.clone(),
            edns_client_subnet.clone(),
            DnsClientNetworkOptions {
                fw_mark: cfg.fw_mark,
                rule_dispatch: rule_dispatch.clone(),
                network_path_source: network_path_source.clone(),
                health: Some(health.clone()),
                group: Some("main"),
            },
        )
        .await?;

        let direct_resolver = if let Some(direct_nameserver) = cfg.direct_nameserver
        {
            let clients = make_clients(
                direct_nameserver,
                Some(default_resolver.clone()),
                Some(outbound_resolver.clone()),
                outbounds.clone(),
                edns_client_subnet.clone(),
                DnsClientNetworkOptions {
                    fw_mark: cfg.fw_mark,
                    network_path_source: network_path_source.clone(),
                    health: Some(health.clone()),
                    group: Some("direct"),
                    ..Default::default()
                },
            )
            .await?;
            Some(Arc::new(Self::from_clients_with_fallback(
                clients,
                Some(main.clone()),
                cfg.ipv6,
            )) as ThreadSafeDNSResolver)
        } else {
            None
        };

        let plain_outbounds = outbounds.read().await;
        let proxy_server_domains = plain_outbounds
            .values()
            .filter_map(|x| x.server_name())
            .collect::<Vec<_>>();

        let proxy_server_domains_trie =
            if proxy_resolver.is_some() && !proxy_server_domains.is_empty() {
                let mut domains = trie::StringTrie::new();
                for server in proxy_server_domains {
                    domains.insert(server, Arc::new(true));
                    debug!("added proxy server domain: {}", server);
                }
                Some(domains)
            } else {
                None
            };
        drop(plain_outbounds);

        Ok(Self {
            ipv6: AtomicBool::new(cfg.ipv6),
            health: health.clone(),
            main,
            hosts: cfg.hosts,
            fallback: if !cfg.fallback.is_empty() {
                Some(
                    make_clients(
                        cfg.fallback.clone(),
                        Some(default_resolver.clone()),
                        Some(outbound_resolver.clone()),
                        outbounds.clone(),
                        edns_client_subnet.clone(),
                        DnsClientNetworkOptions {
                            fw_mark: cfg.fw_mark,
                            rule_dispatch: rule_dispatch.clone(),
                            network_path_source: network_path_source.clone(),
                            health: Some(health.clone()),
                            group: Some("fallback"),
                        },
                    )
                    .await?,
                )
            } else {
                None
            },
            fallback_domain_filters: if !cfg.fallback_filter.domain.is_empty() {
                Some(vec![Box::new(DomainFilter::new(
                    cfg.fallback_filter
                        .domain
                        .iter()
                        .map(|x| x.as_str())
                        .collect(),
                )) as Box<dyn FallbackDomainFilter>])
            } else {
                None
            },
            fallback_ip_filters: if cfg.fallback_filter.ip_cidr.is_some()
                || cfg.fallback_filter.geo_ip
            {
                let mut filters = vec![];

                filters.push(Box::new(GeoIPFilter::new(
                    &cfg.fallback_filter.geo_ip_code,
                    mmdb,
                )) as Box<dyn FallbackIPFilter>);

                if let Some(ipcidr) = &cfg.fallback_filter.ip_cidr {
                    for subnet in ipcidr {
                        filters.push(Box::new(IPNetFilter::new(*subnet))
                            as Box<dyn FallbackIPFilter>)
                    }
                }

                Some(filters)
            } else {
                None
            },
            negative_cache: Mutex::new(lru_time_cache::LruCache::with_capacity(
                1024,
            )),
            lru_cache: Some(hickory_resolver::ResponseCache::new(
                4096,
                hickory_resolver::TtlConfig::default(),
            )),
            policy: if !cfg.nameserver_policy.is_empty() {
                let mut p = trie::StringTrie::new();
                for (domain, ns) in &cfg.nameserver_policy {
                    p.insert(
                        domain.as_str(),
                        Arc::new(
                            make_clients(
                                vec![ns.to_owned()],
                                Some(default_resolver.clone()),
                                Some(outbound_resolver.clone()),
                                outbounds.clone(),
                                edns_client_subnet.clone(),
                                DnsClientNetworkOptions {
                                    fw_mark: cfg.fw_mark,
                                    rule_dispatch: rule_dispatch.clone(),
                                    network_path_source: network_path_source.clone(),
                                    health: Some(health.clone()),
                                    group: Some("policy"),
                                },
                            )
                            .await?,
                        ),
                    );
                }
                Some(p)
            } else {
                None
            },
            fake_dns: match cfg.enhance_mode {
                DNSMode::FakeIp => Some(Arc::new(RwLock::new(
                    fakeip::FakeDns::new(fakeip::Opts {
                        ipnet: cfg.fake_ip_range,
                        skipped_hostnames: if !cfg.fake_ip_filter.is_empty() {
                            let mut host = trie::StringTrie::new();
                            for domain in cfg.fake_ip_filter.iter() {
                                host.insert(domain.as_str(), Arc::new(true));
                            }
                            Some(host)
                        } else {
                            None
                        },
                        store: if cfg.store_fake_ip {
                            Box::new(FileStore::new(store))
                        } else {
                            Box::new(InMemStore::new(1000))
                        },
                    })?,
                ))),
                DNSMode::RedirHost => {
                    warn!(
                        "dns redir-host is not supported and will not do anything"
                    );
                    None
                }
                _ => None,
            },

            safe_srv: cfg.service_discovery_mode
                == crate::config::def::DnsServiceDiscoveryMode::Safe,

            proxy_resolver,
            proxy_server_domains: proxy_server_domains_trie,
            direct_resolver,

            reverse_lookup_cache: Some(Arc::new(RwLock::new(
                lru_time_cache::LruCache::with_expiry_duration_and_capacity(
                    Duration::from_secs(3), /* should be shorter than TTL so
                                             * client won't be connecting to a
                                             * different server after the ip is
                                             * reverse mapped to hostname and
                                             * being resolved again */
                    4096,
                ),
            ))),
        })
    }

    #[instrument(skip(message), level = "trace")]
    pub async fn batch_exchange(
        clients: &Vec<ThreadSafeDNSClient>,
        message: &op::Message,
    ) -> anyhow::Result<op::Message> {
        if clients.is_empty() {
            return Err(Error::DNSError(
                "no DNS clients available for query".into(),
            )
            .into());
        }

        let query_name = Self::domain_name_of_message(message)
            .unwrap_or_else(|| "<invalid-query>".to_string());
        let query_type = message
            .queries
            .first()
            .map(|query| query.query_type().to_string())
            .unwrap_or_else(|| "<unknown>".to_string());

        // Preserve the identity and cause of every failed upstream rather than
        // returning whichever error happens to complete last. A DNS packet
        // with SERVFAIL/REFUSED is a transport success, but not a valid
        // resolution result; keep trying other servers in that case.
        let mut pending = futures::stream::FuturesUnordered::new();
        let client_ids: Vec<String> =
            clients.iter().map(|client| client.id()).collect();
        for (index, client) in clients.iter().enumerate() {
            pending.push(async move { (index, client.exchange(message).await) });
        }

        let mut errors = vec![None::<String>; clients.len()];
        // A fast NXDOMAIN/NODATA should not mask an already-in-flight,
        // slightly slower positive answer from another configured upstream.
        // Bound this grace period so a stalled peer does not turn negative
        // lookups into a 10-second wait.
        const NEGATIVE_GRACE: Duration = Duration::from_millis(200);
        let mut negatives = vec![None::<op::Message>; clients.len()];
        let negative_timer = tokio::time::sleep(NEGATIVE_GRACE);
        tokio::pin!(negative_timer);
        let mut negative_pending = false;
        let timeout = tokio::time::sleep(Duration::from_secs(10));
        tokio::pin!(timeout);
        let mut timed_out = false;
        while !pending.is_empty() {
            tokio::select! {
                result = pending.next() => {
                    let Some((index, result)) = result else { break };
                    let client_id = &client_ids[index];
                    match result {
                        Ok(response) if response.metadata.response_code == op::ResponseCode::NoError
                            && !response.answers.is_empty() => {
                            debug!(
                                client = %client_id,
                                query = %query_name,
                                record_type = %query_type,
                                answer_count = response.answers.len(),
                                "dns upstream returned a positive answer"
                            );
                            return Ok(response);
                        }
                        Ok(response) if matches!(
                            response.metadata.response_code,
                            op::ResponseCode::NoError | op::ResponseCode::NXDomain
                        ) => {
                            debug!(
                                client = %client_id,
                                query = %query_name,
                                record_type = %query_type,
                                response_code = %response.metadata.response_code,
                                "dns upstream returned a negative response"
                            );
                            negatives[index] = Some(response);
                            if !negative_pending {
                                negative_pending = true;
                                negative_timer.as_mut().reset(
                                    tokio::time::Instant::now() + NEGATIVE_GRACE
                                );
                            }
                        }
                        Ok(response) => {
                            let reason = format!(
                                "DNS response code {}", response.metadata.response_code
                            );
                            warn!(
                                client = %client_id,
                                query = %query_name,
                                record_type = %query_type,
                                error = %reason,
                                "dns upstream returned a server error"
                            );
                            errors[index] = Some(reason);
                        }
                        Err(err) => {
                            error!(
                                client = %client_id,
                                query = %query_name,
                                record_type = %query_type,
                                err = %err,
                                "dns upstream query failed"
                            );
                            errors[index] = Some(err.to_string());
                        }
                    }
                }
                _ = &mut negative_timer, if negative_pending => {
                    break;
                }
                _ = &mut timeout => {
                    timed_out = true;
                    // The unfinished futures are dropped on return and never
                    // reach ObservedClient::exchange's normal completion path.
                    // Record only those that did not already finish.
                    for (index, client) in clients.iter().enumerate() {
                        if errors[index].is_none() {
                            client.mark_query_timeout();
                        }
                    }
                    break;
                }
            }
        }

        // For conflicting negative responses, choose the first configured
        // upstream rather than whichever task happened to win the race.
        // Policy-selected upstreams are still isolated before batch_exchange.
        if let Some(response) = negatives.into_iter().flatten().next() {
            return Ok(response);
        }

        let details = client_ids
            .iter()
            .enumerate()
            .map(|(index, id)| {
                let reason = errors[index]
                    .as_deref()
                    .unwrap_or("no response before timeout");
                format!("{id}: {reason}")
            })
            .collect::<Vec<_>>()
            .join("; ");
        Err(Error::DNSError(format!(
            "all {} DNS upstreams failed for {query_name} ({query_type}){}: {details}",
            client_ids.len(),
            if timed_out { " within 10s" } else { "" }
        )).into())
    }

    /// guaranteed to return at least 1 IP address when Ok
    async fn lookup_ip(
        &self,
        host: &str,
        record_type: rr::RecordType,
    ) -> anyhow::Result<Vec<net::IpAddr>> {
        let mut m = op::Message::query();
        let mut q = op::Query::new();
        let name = rr::Name::from_str_relaxed(host)
            .map_err(|_x| anyhow!("invalid domain: {}", host))?
            .append_domain(&rr::Name::root())?; // makes it FQDN
        q.set_name(name);
        q.set_query_type(record_type);
        m.add_query(q);
        m.metadata.recursion_desired = true;

        let result = self.exchange(&m).await?;
        match result.metadata.response_code {
            op::ResponseCode::NoError => {}
            op::ResponseCode::NXDomain => {
                return Err(anyhow!(
                    "DNS NXDomain for hostname: {host} ({record_type})"
                ));
            }
            code => {
                return Err(anyhow!(
                    "DNS response code {code} for hostname: {host} ({record_type})"
                ));
            }
        }
        let ip_list = EnhancedResolver::ip_list_of_message(&result);
        if ip_list.is_empty() {
            return Err(anyhow!("DNS NODATA for hostname: {host} ({record_type})"));
        }
        Ok(ip_list)
    }

    #[instrument(skip_all, level = "trace")]
    async fn exchange(&self, message: &op::Message) -> anyhow::Result<op::Message> {
        let q = message
            .queries
            .first()
            .ok_or_else(|| anyhow!("invalid query"))?;

        trace!(q = q.to_string(), "start");
        if Self::cache_safe_request(message)
            && let Some(lru) = &self.lru_cache
            && let Some(Ok(mut cached)) = lru.get(q, Instant::now()).map(|c| {
                c.inspect_err(|x| warn!("failed to get cached message: {}", x))
            })
        {
            trace!(q = q.to_string(), "cache hit for DNS query");
            // Keep the already aged Answer, Authority and Additional sections,
            // RCODE and response flags. Only transaction-specific fields are
            // taken from the current request.
            cached.metadata.id = message.metadata.id;
            cached.metadata.recursion_desired = message.metadata.recursion_desired;
            cached.metadata.checking_disabled = message.metadata.checking_disabled;
            cached.queries = message.queries.clone();
            return Ok(cached);
        }
        if Self::cache_safe_request(message)
            && self.lru_cache.is_some()
            && let Some(cached) = self.cached_negative(q, message, Instant::now())
        {
            trace!(q = q.to_string(), "negative DNS cache hit");
            return Ok(cached);
        }
        trace!(q = q.to_string(), "querying resolver");
        let res = self.exchange_no_cache(message).await.map(|mut r| {
            if let Some(edns) = r.edns.as_mut() {
                // Remove only padding options, keep everything else
                edns.options_mut().remove(rr::rdata::opt::EdnsCode::Padding);
            }
            r
        });
        trace!(q = q.to_string(), "query completed");
        res
    }

    async fn exchange_no_cache(
        &self,
        message: &op::Message,
    ) -> anyhow::Result<op::Message> {
        let q = message.queries.first().unwrap();

        let query = async move {
            if EnhancedResolver::is_ip_request(q) {
                return self.ip_exchange(message).await;
            }

            if let Some(matched) = self.match_policy(message) {
                return EnhancedResolver::batch_exchange(matched, message).await;
            }

            EnhancedResolver::batch_exchange(&self.main, message).await
        };

        let rv = query.await;

        if let Ok(msg) = &rv
            && Self::cache_safe_request(message)
            && self.lru_cache.is_some()
        {
            self.cache_negative(q, msg, Instant::now());
        }

        if let Ok(msg) = &rv
            && Self::cache_safe_request(message)
            && Self::cache_safe_response(msg)
            && let Some(lru) = &self.lru_cache
            && !(q.query_type() == rr::RecordType::TXT
                && q.name().to_ascii().starts_with("_acme-challenge."))
            && {
                let ips = EnhancedResolver::ip_list_of_message(msg);
                ips.is_empty() || ips.iter().any(|ip| !ip.is_unspecified())
            }
        {
            // A subsequent real positive answer invalidates a previously
            // observed negative for the same Question. Otherwise an older
            // NXDOMAIN could reappear after the positive TTL expires.
            self.negative_cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&Self::negative_cache_key(q));
            lru.insert(q.clone(), Ok(msg.clone()), Instant::now());
        }

        rv
    }

    fn match_policy(&self, m: &op::Message) -> Option<&Vec<ThreadSafeDNSClient>> {
        if let (Some(policy), Some(domain)) =
            (&self.policy, EnhancedResolver::domain_name_of_message(m))
        {
            return policy.search(&domain).map(|n| n.get_data().unwrap());
        }
        None
    }

    #[instrument(skip_all, level = "trace")]
    async fn ip_exchange(
        &self,
        message: &op::Message,
    ) -> anyhow::Result<op::Message> {
        if let (Some(proxy_resolver), Some(proxy_domains)) =
            (&self.proxy_resolver, &self.proxy_server_domains)
            && let Some(domain) = EnhancedResolver::domain_name_of_message(message)
            && proxy_domains.search(&domain).is_some()
        {
            debug!(
                "using proxy-server-nameserver for proxy server domain: {}",
                domain
            );
            return EnhancedResolver::batch_exchange(proxy_resolver, message).await;
        }

        if let Some(matched) = self.match_policy(message) {
            return EnhancedResolver::batch_exchange(matched, message).await;
        }

        if self.should_only_query_fallback(message) {
            return EnhancedResolver::batch_exchange(
                self.fallback.as_ref().unwrap(),
                message,
            )
            .await;
        }

        let main_query = EnhancedResolver::batch_exchange(&self.main, message);

        if self.fallback.is_none() {
            return main_query.await;
        }

        let fallback_query = EnhancedResolver::batch_exchange(
            self.fallback.as_ref().unwrap(),
            message,
        );

        let main_result = main_query.await;
        if let Ok(main_response) = &main_result {
            let ip_list = EnhancedResolver::ip_list_of_message(main_response);
            if !ip_list.is_empty() && !self.should_ip_fallback(&ip_list[0]) {
                return main_result;
            }
        }

        fallback_query.await.map_err(|fallback_error| match main_result {
            Err(main_error) => anyhow!(
                "main DNS upstreams failed: {main_error}; fallback DNS upstreams failed: {fallback_error}"
            ),
            Ok(main_response) => anyhow!(
                "main DNS returned {} with no acceptable IP; fallback DNS upstreams failed: {fallback_error}",
                main_response.metadata.response_code
            ),
        })
    }

    fn should_only_query_fallback(&self, message: &op::Message) -> bool {
        if let (Some(_), Some(fallback_domain_filters)) =
            (&self.fallback, &self.fallback_domain_filters)
            && let Some(domain) = EnhancedResolver::domain_name_of_message(message)
        {
            for f in fallback_domain_filters.iter() {
                if f.apply(domain.as_str()) {
                    return true;
                }
            }
        }
        false
    }

    fn should_ip_fallback(&self, ip: &net::IpAddr) -> bool {
        if let Some(filers) = &self.fallback_ip_filters {
            for f in filers.iter() {
                if f.apply(ip) {
                    return true;
                }
            }
        }
        false
    }

    // helpers
    fn is_ip_request(q: &op::Query) -> bool {
        q.query_class() == rr::DNSClass::IN
            && (q.query_type() == rr::RecordType::A
                || q.query_type() == rr::RecordType::AAAA)
    }

    fn domain_name_of_message(m: &op::Message) -> Option<String> {
        m.queries
            .first()
            .map(|x| x.name().to_ascii().trim_end_matches('.').to_owned())
    }

    pub(crate) fn ip_list_of_message(m: &op::Message) -> Vec<net::IpAddr> {
        m.answers
            .iter()
            .filter(|r| {
                r.record_type() == rr::RecordType::A
                    || r.record_type() == rr::RecordType::AAAA
            })
            .map(|r| match &r.data {
                rr::RData::A(v4) => net::IpAddr::V4(**v4),
                rr::RData::AAAA(v6) => net::IpAddr::V6(**v6),
                _ => unreachable!("should be only A/AAAA"),
            })
            .collect()
    }

    async fn save_reverse_lookup(&self, ip: net::IpAddr, domain: String) {
        if let Some(lru) = &self.reverse_lookup_cache {
            trace!("reverse lookup cache insert: {} -> {}", ip, domain);
            lru.write().await.insert(ip, domain);
        }
    }
}

#[async_trait]
impl ClashResolver for EnhancedResolver {
    #[instrument(skip(self), level = "trace")]
    async fn resolve(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<net::IpAddr>> {
        if let Some(ip) = parse_ip_literal(host) {
            return Ok(Some(ip));
        }

        match self.ipv6.load(Relaxed) {
            true => {
                // Keep the first usable address without waiting for the
                // other family; if neither succeeds, preserve both failures.
                let mut pending = futures::stream::FuturesUnordered::new();
                pending.push(
                    async {
                        (
                            "AAAA",
                            self.resolve_v6(host, enhanced)
                                .await
                                .map(|ip| ip.map(net::IpAddr::from)),
                        )
                    }
                    .boxed(),
                );
                pending.push(
                    async {
                        (
                            "A",
                            self.resolve_v4(host, enhanced)
                                .await
                                .map(|ip| ip.map(net::IpAddr::from)),
                        )
                    }
                    .boxed(),
                );
                let mut errors = Vec::new();
                while let Some((record_type, result)) = pending.next().await {
                    match result {
                        Ok(Some(ip)) => return Ok(Some(ip)),
                        Ok(None) => {}
                        Err(error) => errors.push(format!("{record_type}: {error}")),
                    }
                }
                if errors.is_empty() {
                    Ok(None)
                } else {
                    Err(anyhow!(
                        "DNS resolution failed for {host}: {}",
                        errors.join("; ")
                    ))
                }
            }
            false => self
                .resolve_v4(host, enhanced)
                .await
                .map(|ip| ip.map(net::IpAddr::from)),
        }
    }

    async fn resolve_all(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Vec<net::IpAddr>> {
        if let Some(ip) = parse_ip_literal(host) {
            return Ok(vec![ip]);
        }
        if enhanced {
            return Ok(self.resolve(host, true).await?.into_iter().collect());
        }

        let ipv4 = self.lookup_ip(host, rr::RecordType::A);
        let ipv6_enabled = self.ipv6.load(Relaxed);
        let ipv6 = async {
            if ipv6_enabled {
                self.lookup_ip(host, rr::RecordType::AAAA).await
            } else {
                Ok(Vec::new())
            }
        };
        let (ipv4, ipv6) = tokio::join!(ipv4, ipv6);
        let mut addresses = Vec::new();
        let mut errors = Vec::new();
        match ipv4 {
            Ok(ips) => addresses.extend(ips),
            Err(error) => errors.push(format!("A: {error}")),
        }
        match ipv6 {
            Ok(ips) => addresses.extend(ips),
            Err(error) => errors.push(format!("AAAA: {error}")),
        }
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.is_empty() {
            return Err(if errors.is_empty() {
                anyhow!("no record for hostname: {host}")
            } else {
                anyhow!("DNS resolution failed for {host}: {}", errors.join("; "))
            });
        }
        Ok(addresses)
    }

    #[instrument(skip(self), level = "trace")]
    async fn resolve_v4(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<net::Ipv4Addr>> {
        if enhanced
            && let Some(hosts) = &self.hosts
            && let Some(v) = hosts.search(host)
        {
            return Ok(v.get_data().and_then(|v| match v {
                net::IpAddr::V4(v4) => Some(*v4),
                // A hosts override with only an IPv6 address has no A
                // record; it must not panic a release=abort process.
                net::IpAddr::V6(_) => None,
            }));
        }

        if let Ok(ip) = host.parse::<net::Ipv4Addr>() {
            return Ok(Some(ip));
        }

        if enhanced && self.fake_ip_enabled() {
            let mut fake_dns = self.fake_dns.as_ref().unwrap().write().await;
            if !fake_dns.should_skip(host) {
                let ip = fake_dns.lookup(host).await;
                debug!("fake dns lookup: {} -> {:?}", host, ip);
                match ip {
                    Ok(net::IpAddr::V4(v4)) => return Ok(Some(v4)),
                    Ok(other) => {
                        return Err(anyhow!("IPv4 fake-IP pool returned {other}"));
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }

        match self.lookup_ip(host, rr::RecordType::A).await {
            Ok(result) => match result.choose(&mut rand::rng()).unwrap() {
                net::IpAddr::V4(v4) => Ok(Some(*v4)),
                _ => unreachable!("invalid IP family"),
            },
            Err(e) => Err(e),
        }
    }

    #[instrument(skip(self), level = "trace")]
    async fn resolve_v6(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<net::Ipv6Addr>> {
        if let Some(std::net::IpAddr::V6(ip)) = parse_ip_literal(host) {
            return Ok(Some(ip));
        }

        if !self.ipv6.load(Relaxed) {
            return Err(Error::DNSError("ipv6 disabled".into()).into());
        }

        if enhanced
            && let Some(hosts) = &self.hosts
            && let Some(v) = hosts.search(host)
        {
            return Ok(v.get_data().map(|v| match v {
                net::IpAddr::V6(v6) => *v6,
                _ => unreachable!("invalid IP family"),
            }));
        }

        match self.lookup_ip(host, rr::RecordType::AAAA).await {
            Ok(result) => match result.choose(&mut rand::rng()).unwrap() {
                net::IpAddr::V6(v6) => Ok(Some(*v6)),
                _ => unreachable!("invalid IP family"),
            },

            Err(e) => Err(e),
        }
    }

    #[instrument(skip(self))]
    async fn cached_for(&self, ip: net::IpAddr) -> Option<String> {
        if let Some(lru) = &self.reverse_lookup_cache
            && let Some(cached) = lru.read().await.peek(&ip)
        {
            trace!("reverse lookup cache hit: {cached} -> {ip}");
            return Some(cached.clone());
        }

        None
    }

    #[instrument(skip(self), level = "trace")]
    async fn exchange(&self, message: &op::Message) -> anyhow::Result<op::Message> {
        let rv = self.exchange(message).await?;
        let hostname = message
            .queries
            .first()
            .unwrap()
            .name()
            .to_utf8()
            .trim_end_matches('.')
            .to_owned();
        let ip_list = EnhancedResolver::ip_list_of_message(&rv);
        if !ip_list.is_empty() {
            for ip in ip_list {
                self.save_reverse_lookup(ip, hostname.clone()).await;
            }
        }
        Ok(rv)
    }

    fn ipv6(&self) -> bool {
        self.ipv6.load(Relaxed)
    }

    fn set_ipv6(&self, enable: bool) {
        self.ipv6.store(enable, Relaxed);
    }

    async fn reset_transports(&self) -> anyhow::Result<u32> {
        self.health.invalidate();
        // A changed network path can expose a different split-DNS zone.
        self.negative_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        let mut clients = self.main.clone();
        if let Some(fallback) = &self.fallback {
            clients.extend(fallback.iter().cloned());
        }
        if let Some(proxy_resolver) = &self.proxy_resolver {
            clients.extend(proxy_resolver.iter().cloned());
        }
        if let Some(policy) = &self.policy {
            policy.traverse(|_, policy_clients| {
                clients.extend(policy_clients.iter().cloned());
                true
            });
        }

        let mut reset = 0_u32;
        let mut errors = Vec::new();
        let mut seen = std::collections::HashSet::new();
        clients
            .retain(|client| seen.insert(Arc::as_ptr(client) as *const () as usize));
        let mut pending = futures::stream::FuturesUnordered::new();
        for client in clients {
            pending.push(
                async move {
                    tokio::time::timeout(
                        Duration::from_secs(5),
                        client.reset_transport(),
                    )
                    .await
                }
                .boxed(),
            );
        }
        if let Some(direct_resolver) = &self.direct_resolver {
            pending.push(
                async move {
                    tokio::time::timeout(
                        Duration::from_secs(5),
                        direct_resolver.reset_transports(),
                    )
                    .await
                }
                .boxed(),
            );
        }
        while let Some(result) = pending.next().await {
            match result {
                Ok(Ok(count)) => reset = reset.saturating_add(count),
                Ok(Err(error)) => errors.push(error.to_string()),
                Err(_) => errors.push("DNS client reset timed out".to_owned()),
            }
        }
        if let Some(cache) = &self.reverse_lookup_cache {
            cache.write().await.clear();
        }
        if errors.is_empty() {
            Ok(reset)
        } else {
            Err(anyhow!(errors.join("; ")))
        }
    }

    fn kind(&self) -> ResolverKind {
        ResolverKind::Clash
    }

    fn dns_health_snapshot(&self) -> Option<crate::app::dns::DnsHealthSnapshot> {
        Some(self.health.snapshot())
    }

    fn fake_ip_enabled(&self) -> bool {
        self.fake_dns.is_some()
    }

    fn safe_srv_enabled(&self) -> bool {
        self.safe_srv
    }

    async fn should_fake_ip(&self, host: &str) -> bool {
        let Some(pool) = &self.fake_dns else {
            return false;
        };
        !pool.read().await.should_skip(host)
    }

    fn direct_resolver(&self) -> Option<ThreadSafeDNSResolver> {
        self.direct_resolver.clone()
    }

    async fn is_fake_ip(&self, ip: std::net::IpAddr) -> bool {
        if !self.fake_ip_enabled() {
            return false;
        }

        let mut fake_dns = self.fake_dns.as_ref().unwrap().write().await;
        fake_dns.is_fake_ip(ip).await
    }

    async fn reverse_lookup(&self, ip: net::IpAddr) -> Option<String> {
        debug!("reverse lookup: {}", ip);
        if !self.fake_ip_enabled() {
            return None;
        }

        let mut fake_dns = self.fake_dns.as_ref().unwrap().write().await;
        fake_dns.reverse_lookup(ip).await
    }

    async fn fake_ip_for_host(&self, host: &str) -> Option<net::IpAddr> {
        if !self.fake_ip_enabled() {
            return None;
        }

        let mut fake_dns = self.fake_dns.as_ref().unwrap().write().await;
        fake_dns.lookup_existing(host).await
    }
}

#[cfg(test)]
mod tests {

    use async_trait::async_trait;
    use hickory_net::{DnsHandle, client, udp::UdpClientStream, xfer::FirstAnswer};
    use hickory_proto::{
        op::{self, DnsRequest, DnsRequestOptions},
        rr,
    };
    use hickory_resolver::{ResponseCache, TtlConfig};
    use std::{
        net::Ipv4Addr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };
    use tokio::sync::RwLock;

    use crate::{
        app::dns::{
            ClashResolver, Config, ThreadSafeDNSClient, ThreadSafeDNSResolver,
            config::NameServer,
            dns_client::{DNSNetMode, DnsClient, Opts},
            resolver::enhanced::EnhancedResolver,
            runtime::DnsRuntimeProvider,
        },
        proxy,
    };

    #[derive(Debug)]
    struct FixedClient {
        response: op::Message,
    }

    #[async_trait]
    impl crate::app::dns::Client for FixedClient {
        fn id(&self) -> String {
            "fixed-client".to_owned()
        }

        async fn exchange(&self, _msg: &op::Message) -> anyhow::Result<op::Message> {
            Ok(self.response.clone())
        }
    }

    #[derive(Debug)]
    struct CountingClient {
        response: op::Message,
        hits: Arc<AtomicUsize>,
        id: &'static str,
    }

    #[async_trait]
    impl crate::app::dns::Client for CountingClient {
        fn id(&self) -> String {
            self.id.to_owned()
        }

        async fn exchange(&self, _msg: &op::Message) -> anyhow::Result<op::Message> {
            self.hits.fetch_add(1, Ordering::SeqCst);
            Ok(self.response.clone())
        }
    }

    #[derive(Debug)]
    struct ResetCountingClient {
        resets: Arc<AtomicUsize>,
    }

    struct EvictAfterExistStore {
        allocated_ip: std::net::IpAddr,
        mapping_present: bool,
    }

    #[async_trait]
    impl crate::app::dns::fakeip::Store for EvictAfterExistStore {
        async fn get_by_host(
            &mut self,
            _host: &str,
            _family: crate::app::dns::fakeip::IpFamily,
        ) -> Option<std::net::IpAddr> {
            None
        }

        async fn pub_by_host(
            &mut self,
            _host: &str,
            _family: crate::app::dns::fakeip::IpFamily,
            _ip: std::net::IpAddr,
        ) {
        }

        async fn get_by_ip(&mut self, ip: std::net::IpAddr) -> Option<String> {
            (self.mapping_present && ip == self.allocated_ip)
                .then(|| "evicted.example.test".to_owned())
        }

        async fn put_by_ip(&mut self, _ip: std::net::IpAddr, _host: &str) {}

        async fn del_by_host(
            &mut self,
            _host: &str,
            _family: crate::app::dns::fakeip::IpFamily,
        ) {
        }

        async fn exist(&mut self, ip: std::net::IpAddr) -> bool {
            let exists = self.mapping_present && ip == self.allocated_ip;
            if exists {
                // Model eviction immediately after existence is observed and
                // before the separate reverse-lookup call.
                self.mapping_present = false;
            }
            exists
        }

        async fn copy_to(
            &self,
            _store: &mut Box<dyn crate::app::dns::fakeip::Store>,
        ) {
        }
    }

    #[async_trait]
    impl crate::app::dns::Client for ResetCountingClient {
        fn id(&self) -> String {
            "reset-counting-client".to_owned()
        }

        async fn exchange(&self, _msg: &op::Message) -> anyhow::Result<op::Message> {
            unreachable!("reset counting client is not used for queries")
        }

        async fn reset_transport(&self) -> anyhow::Result<u32> {
            self.resets.fetch_add(1, Ordering::SeqCst);
            Ok(1)
        }
    }

    fn test_query() -> (op::Message, op::Query) {
        let mut request = op::Message::query();
        let mut query = op::Query::new();
        query.set_name(
            rr::Name::from_str_relaxed("example.com")
                .unwrap()
                .append_domain(&rr::Name::root())
                .unwrap(),
        );
        query.set_query_type(rr::RecordType::A);
        request.add_query(query.clone());
        (request, query)
    }

    fn test_query_with_type(record_type: rr::RecordType) -> op::Message {
        let mut request = op::Message::query();
        let mut query = op::Query::new();
        query.set_name(
            rr::Name::from_str_relaxed("proxy.example.com")
                .unwrap()
                .append_domain(&rr::Name::root())
                .unwrap(),
        );
        query.set_query_type(record_type);
        request.add_query(query);
        request
    }

    #[derive(Debug)]
    struct FailingClient {
        id: &'static str,
        reason: &'static str,
    }

    #[async_trait]
    impl crate::app::dns::Client for FailingClient {
        fn id(&self) -> String {
            self.id.to_owned()
        }

        async fn exchange(&self, _msg: &op::Message) -> anyhow::Result<op::Message> {
            Err(anyhow::anyhow!(self.reason))
        }
    }

    #[tokio::test]
    async fn health_only_observes_real_upstream_exchanges() {
        let resolver = EnhancedResolver::from_clients(
            vec![Arc::new(FixedClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 88)),
            })],
            false,
        );
        let health = resolver.dns_health_snapshot().unwrap();
        assert_eq!(health.status, crate::app::dns::DnsHealthStatus::Unknown);
        assert_eq!(health.groups[0].upstreams[0].successes, 0);

        resolver.exchange_no_cache(&test_query().0).await.unwrap();
        let health = resolver.dns_health_snapshot().unwrap();
        assert_eq!(health.status, crate::app::dns::DnsHealthStatus::Healthy);
        assert_eq!(health.groups[0].upstreams[0].successes, 1);
        assert_eq!(health.groups[0].upstreams[0].failures, 0);
    }

    #[tokio::test]
    async fn health_records_upstream_failures_but_not_query_cache_hits() {
        let client = Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 5)),
            hits: Arc::new(AtomicUsize::new(0)),
            id: "active-dns",
        });
        let hits = client.hits.clone();
        let mut resolver = EnhancedResolver::from_clients(vec![client], false);
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        let mut query = test_query().0;
        query.metadata.recursion_desired = true;

        resolver.exchange(&query).await.unwrap();
        resolver.exchange(&query).await.unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let health = resolver.dns_health_snapshot().unwrap();
        assert_eq!(health.groups[0].upstreams[0].successes, 1);
    }

    #[tokio::test]
    async fn missing_fake_ip_reverse_index_is_explained_by_dispatcher() {
        use crate::{
            app::{
                dispatcher::{Dispatcher, StatisticsManager},
                network::{NetworkSnapshot, NetworkStatus},
                outbound::manager::OutboundManager,
                profile::ThreadSafeCacheFile,
                router::Router,
            },
            config::{
                def::RunMode,
                internal::{
                    proxy::{OutboundDirect, OutboundProxyProtocol},
                    rule::RuleType,
                },
            },
            proxy::utils::OutboundHandlerRegistry,
            session::{Session, SocksAddr},
        };
        use std::collections::HashMap;
        use tokio::io::AsyncReadExt;

        let fake_ip: std::net::IpAddr = "198.18.0.2".parse().unwrap();
        let mut resolver = EnhancedResolver::from_clients(vec![], false);
        resolver.fake_dns = Some(Arc::new(RwLock::new(
            crate::app::dns::fakeip::FakeDns::new(crate::app::dns::fakeip::Opts {
                ipnet: "198.18.0.0/30".parse().unwrap(),
                skipped_hostnames: None,
                store: Box::new(EvictAfterExistStore {
                    allocated_ip: fake_ip,
                    mapping_present: true,
                }),
            })
            .unwrap(),
        )));
        let resolver: ThreadSafeDNSResolver = Arc::new(resolver);
        assert!(resolver.fake_ip_enabled());

        let status = Arc::new(RwLock::new(NetworkStatus::default()));
        {
            let mut status = status.write().await;
            status.set_automatic_supported_for_test(true);
            status.observed(&NetworkSnapshot::default());
        }
        let temp = tempfile::tempdir().unwrap();
        let cache = ThreadSafeCacheFile::new(
            temp.path().join("cache.db").to_str().unwrap(),
            false,
        );
        let registry: OutboundHandlerRegistry =
            Arc::new(RwLock::new(HashMap::new()));
        let direct = OutboundManager::load_plain_outbounds(vec![
            OutboundProxyProtocol::Direct(OutboundDirect {
                name: "DIRECT".to_owned(),
            }),
        ]);
        let manager = OutboundManager::new(
            direct,
            Vec::new(),
            HashMap::new(),
            Vec::new(),
            resolver.clone(),
            cache,
            temp.path().to_string_lossy().to_string(),
            None,
            registry,
        )
        .await
        .expect("failed to construct outbound manager");
        let router = Arc::new(
            Router::new(
                vec![RuleType::try_from("MATCH,DIRECT".to_owned()).unwrap()],
                HashMap::new(),
                resolver.clone(),
                None,
                None,
                None,
                temp.path().to_string_lossy().to_string(),
            )
            .await
            .expect("failed to construct test router"),
        );
        let dispatcher = Dispatcher::new(
            Arc::new(manager),
            router,
            resolver,
            RunMode::Rule,
            StatisticsManager::new(),
            None,
            false,
        );
        dispatcher.attach_network_status(status.clone());

        let destination = SocksAddr::from(std::net::SocketAddr::new(fake_ip, 443));
        let session = Session {
            source: "127.0.0.1:12345".parse().unwrap(),
            destination: destination.clone(),
            ..Session::default()
        };
        let (mut client, server) = tokio::io::duplex(64);
        tokio::time::timeout(
            Duration::from_secs(3),
            dispatcher.dispatch_stream(session, Box::new(server)),
        )
        .await
        .expect("dispatcher did not finish the missing reverse-index flow");
        let mut byte = [0u8; 1];
        assert_eq!(client.read(&mut byte).await.unwrap(), 0);

        let decision = status
            .write()
            .await
            .path_decisions_snapshot()
            .into_iter()
            .find(|decision| {
                decision.destination.as_deref()
                    == Some(destination.to_string().as_str())
            })
            .expect("missing fake-IP reverse index was not explained");
        assert_eq!(
            decision.failure_kind.as_deref(),
            Some("fakeIpMappingMissing")
        );
        assert_eq!(
            decision.outcome,
            crate::app::flow::PathExecutionOutcome::PathPlanningFailed
        );
        assert_eq!(decision.route.outbound, "notEvaluated");
        assert!(decision.route.rule.is_none());
        assert!(decision.selected_path.is_none());
        assert!(decision.reason.contains("route selection was skipped"));
    }

    #[tokio::test]
    async fn fake_ipv4_pool_exhaustion_returns_error_without_panicking() {
        let mut resolver = EnhancedResolver::from_clients(vec![], false);
        resolver.fake_dns = Some(Arc::new(RwLock::new(
            crate::app::dns::fakeip::FakeDns::new(crate::app::dns::fakeip::Opts {
                ipnet: "198.18.0.0/30".parse().unwrap(),
                skipped_hostnames: None,
                store: Box::new(crate::app::dns::fakeip::InMemStore::new(2)),
            })
            .unwrap(),
        )));
        assert_eq!(
            resolver.resolve_v4("first.example", true).await.unwrap(),
            Some("198.18.0.2".parse().unwrap()),
        );
        let error = resolver
            .resolve_v4("second.example", true)
            .await
            .expect_err("a full pool must return a recoverable DNS error");
        assert!(error.to_string().contains("pool exhausted"), "{error}");
        assert_eq!(
            resolver.resolve_v4("first.example", true).await.unwrap(),
            Some("198.18.0.2".parse().unwrap()),
            "existing mappings must remain stable",
        );
    }

    #[tokio::test]
    async fn fake_ip_filter_lets_excluded_domains_use_real_ipv4_dns() {
        let mut filter = crate::common::trie::StringTrie::new();
        filter.insert("*.lan", Arc::new(true));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(FixedClient {
                response: response_with_a(Ipv4Addr::new(203, 0, 113, 44)),
            })],
            false,
        );
        resolver.fake_dns = Some(Arc::new(RwLock::new(
            crate::app::dns::fakeip::FakeDns::new(crate::app::dns::fakeip::Opts {
                ipnet: "198.18.0.0/30".parse().unwrap(),
                skipped_hostnames: Some(filter),
                store: Box::new(crate::app::dns::fakeip::InMemStore::new(2)),
            })
            .unwrap(),
        )));
        assert!(!resolver.should_fake_ip("printer.lan").await);
        assert!(resolver.should_fake_ip("public.example").await);
        assert_eq!(
            resolver.resolve_v4("printer.lan", true).await.unwrap(),
            Some(Ipv4Addr::new(203, 0, 113, 44)),
        );
        assert!(resolver.fake_ip_for_host("printer.lan").await.is_none());
    }

    #[tokio::test]
    async fn ipv4_hosts_with_other_address_family_do_not_abort() {
        let mut hosts = crate::common::trie::StringTrie::new();
        hosts.insert("v6-only.test", Arc::new("2001:db8::1".parse().unwrap()));
        let mut resolver = EnhancedResolver::from_clients(vec![], false);
        resolver.hosts = Some(hosts);
        assert_eq!(
            resolver.resolve_v4("v6-only.test", true).await.unwrap(),
            None
        );
    }

    #[derive(Debug)]
    struct DelayedClient {
        response: op::Message,
        delay: Duration,
        name: &'static str,
    }

    #[async_trait]
    impl crate::app::dns::Client for DelayedClient {
        fn id(&self) -> String {
            self.name.to_owned()
        }
        async fn exchange(
            &self,
            _message: &op::Message,
        ) -> anyhow::Result<op::Message> {
            tokio::time::sleep(self.delay).await;
            Ok(self.response.clone())
        }
    }

    #[tokio::test]
    async fn fast_nxdomain_must_not_mask_later_positive_address() {
        let mut negative = op::Message::response(0, op::OpCode::Query);
        negative.metadata.response_code = op::ResponseCode::NXDomain;
        let clients: Vec<ThreadSafeDNSClient> = vec![
            Arc::new(DelayedClient {
                response: negative,
                delay: Duration::ZERO,
                name: "fast-negative",
            }),
            Arc::new(DelayedClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 60)),
                delay: Duration::from_millis(35),
                name: "slower-address",
            }),
        ];
        let answer = EnhancedResolver::batch_exchange(&clients, &test_query().0)
            .await
            .expect("valid address should win over early NXDOMAIN");
        assert_eq!(EnhancedResolver::ip_list_of_message(&answer).len(), 1);
    }

    #[tokio::test]
    async fn fast_nodata_must_not_mask_later_positive_address() {
        let clients: Vec<ThreadSafeDNSClient> = vec![
            Arc::new(DelayedClient {
                response: op::Message::response(0, op::OpCode::Query),
                delay: Duration::ZERO,
                name: "fast-nodata",
            }),
            Arc::new(DelayedClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 61)),
                delay: Duration::from_millis(35),
                name: "slower-address",
            }),
        ];
        let answer = EnhancedResolver::batch_exchange(&clients, &test_query().0)
            .await
            .expect("valid address should win over empty NOERROR");
        assert_eq!(EnhancedResolver::ip_list_of_message(&answer).len(), 1);
    }

    #[tokio::test]
    async fn all_negative_dns_answers_preserve_negative_rcode() {
        let mut negative = op::Message::response(0, op::OpCode::Query);
        negative.metadata.response_code = op::ResponseCode::NXDomain;
        let clients: Vec<ThreadSafeDNSClient> = vec![
            Arc::new(DelayedClient {
                response: negative,
                delay: Duration::from_millis(25),
                name: "preferred-nxdomain",
            }),
            Arc::new(DelayedClient {
                response: op::Message::response(0, op::OpCode::Query),
                delay: Duration::ZERO,
                name: "secondary-nodata",
            }),
        ];
        let answer = EnhancedResolver::batch_exchange(&clients, &test_query().0)
            .await
            .expect("negative DNS response is not a transport failure");
        assert_eq!(answer.metadata.response_code, op::ResponseCode::NXDomain);
    }

    #[tokio::test]
    async fn all_failed_upstreams_preserve_each_upstream_reason() {
        let clients: Vec<ThreadSafeDNSClient> = vec![
            Arc::new(FailingClient {
                id: "dns-a",
                reason: "connection refused",
            }),
            Arc::new(FailingClient {
                id: "dns-b",
                reason: "TLS certificate invalid",
            }),
        ];
        let err = EnhancedResolver::batch_exchange(&clients, &test_query().0)
            .await
            .expect_err("all failed upstreams must fail");
        let message = err.to_string();
        for part in [
            "dns-a",
            "connection refused",
            "dns-b",
            "TLS certificate invalid",
        ] {
            assert!(message.contains(part), "{message} lacks {part}");
        }
    }

    #[tokio::test]
    async fn server_failure_response_does_not_hide_working_upstream() {
        let mut servfail = op::Message::response(0, op::OpCode::Query);
        servfail.metadata.response_code = op::ResponseCode::ServFail;
        let clients: Vec<ThreadSafeDNSClient> = vec![
            Arc::new(FixedClient { response: servfail }),
            Arc::new(FixedClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
            }),
        ];
        let result = EnhancedResolver::batch_exchange(&clients, &test_query().0)
            .await
            .expect("successful upstream should win");
        assert_eq!(result.metadata.response_code, op::ResponseCode::NoError);
        assert_eq!(EnhancedResolver::ip_list_of_message(&result).len(), 1);
    }

    #[tokio::test]
    async fn all_servfail_upstreams_are_reported_as_failures() {
        let mut servfail = op::Message::response(0, op::OpCode::Query);
        servfail.metadata.response_code = op::ResponseCode::ServFail;
        let clients: Vec<ThreadSafeDNSClient> =
            vec![Arc::new(FixedClient { response: servfail })];
        let err = EnhancedResolver::batch_exchange(&clients, &test_query().0)
            .await
            .expect_err("SERVFAIL is not a healthy response");
        assert!(err.to_string().contains("Server Failure"), "{err}");
    }

    #[tokio::test]
    async fn nxdomain_is_preserved_as_dns_negative_answer() {
        let mut nxdomain = op::Message::response(0, op::OpCode::Query);
        nxdomain.metadata.response_code = op::ResponseCode::NXDomain;
        let clients: Vec<ThreadSafeDNSClient> =
            vec![Arc::new(FixedClient { response: nxdomain })];
        let answer = EnhancedResolver::batch_exchange(&clients, &test_query().0)
            .await
            .expect("NXDOMAIN is a valid DNS negative answer");
        assert_eq!(answer.metadata.response_code, op::ResponseCode::NXDomain);
        let resolver = EnhancedResolver::from_clients(clients, true);
        let err = resolver
            .resolve_all("example.com", false)
            .await
            .expect_err("NXDOMAIN is not a success with an IP");
        assert!(err.to_string().contains("NXDomain"), "{err}");
    }

    #[tokio::test]
    async fn resolve_all_preserves_a_and_aaaa_failures() {
        let resolver = EnhancedResolver::from_clients(
            vec![Arc::new(FailingClient {
                id: "broken-dns",
                reason: "upstream connection refused",
            })],
            true,
        );
        let err = resolver
            .resolve_all("example.com", false)
            .await
            .expect_err("dual stack must not conceal upstream failure as NODATA");
        let message = err.to_string();
        for part in ["A:", "AAAA:", "broken-dns", "upstream connection refused"] {
            assert!(message.contains(part), "{message} lacks {part}");
        }
    }

    #[tokio::test]
    async fn resolve_preserves_both_address_family_errors() {
        let resolver = EnhancedResolver::from_clients(
            vec![Arc::new(FailingClient {
                id: "all-down",
                reason: "network unreachable",
            })],
            true,
        );
        let err = resolver
            .resolve("example.com", false)
            .await
            .expect_err("all DNS address families failed");
        let message = err.to_string();
        for part in ["A:", "AAAA:", "all-down", "network unreachable"] {
            assert!(message.contains(part), "{message} lacks {part}");
        }
    }

    #[tokio::test]
    async fn noerror_without_ip_is_reported_as_nodata_not_server_failure() {
        let response = op::Message::response(0, op::OpCode::Query);
        let resolver = EnhancedResolver::from_clients(
            vec![Arc::new(FixedClient { response })],
            false,
        );
        let err = resolver
            .resolve_all("example.com", false)
            .await
            .expect_err("empty NOERROR response is NODATA, not a valid address");
        let message = err.to_string();
        assert!(message.contains("NODATA"), "{message}");
        assert!(!message.contains("all DNS upstreams failed"), "{message}");
    }

    #[tokio::test]
    async fn one_address_family_can_succeed_while_the_other_fails() {
        #[derive(Debug)]
        struct OnlyIpv4;
        #[async_trait]
        impl crate::app::dns::Client for OnlyIpv4 {
            fn id(&self) -> String {
                "ipv4-working".into()
            }
            async fn exchange(
                &self,
                query: &op::Message,
            ) -> anyhow::Result<op::Message> {
                if query
                    .queries
                    .first()
                    .is_some_and(|q| q.query_type() == rr::RecordType::AAAA)
                {
                    Err(anyhow::anyhow!("IPv6 DNS path down"))
                } else {
                    Ok(response_with_a(Ipv4Addr::new(192, 0, 2, 55)))
                }
            }
        }
        let resolver =
            EnhancedResolver::from_clients(vec![Arc::new(OnlyIpv4)], true);
        assert_eq!(
            resolver.resolve_all("example.com", false).await.unwrap(),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55))]
        );
    }

    #[tokio::test]
    async fn refused_rcode_is_reported_as_upstream_failure() {
        let mut response = op::Message::response(0, op::OpCode::Query);
        response.metadata.response_code = op::ResponseCode::Refused;
        let clients: Vec<ThreadSafeDNSClient> =
            vec![Arc::new(FixedClient { response })];
        let err = EnhancedResolver::batch_exchange(&clients, &test_query().0)
            .await
            .expect_err("REFUSED must not be treated as a healthy response");
        assert!(err.to_string().contains("Refused"), "{err}");
    }

    #[tokio::test]
    async fn main_and_fallback_errors_are_both_reported() {
        let resolver = EnhancedResolver::from_clients_with_fallback(
            vec![Arc::new(FailingClient {
                id: "main-ns",
                reason: "main refused",
            })],
            Some(vec![Arc::new(FailingClient {
                id: "fallback-ns",
                reason: "fallback timeout",
            })]),
            false,
        );
        let err = resolver
            .exchange_no_cache(&test_query().0)
            .await
            .expect_err("both upstream groups failed");
        let message = err.to_string();
        for part in ["main-ns", "main refused", "fallback-ns", "fallback timeout"] {
            assert!(message.contains(part), "{message} lacks {part}");
        }
    }

    fn response_with_a(ip: Ipv4Addr) -> op::Message {
        let mut response = op::Message::response(0, op::OpCode::Query);
        response.add_answer(rr::Record::from_rdata(
            rr::Name::from_str_relaxed("proxy.example.com")
                .unwrap()
                .append_domain(&rr::Name::root())
                .unwrap(),
            300,
            rr::RData::A(rr::rdata::A(ip)),
        ));
        response
    }

    #[tokio::test]
    async fn direct_resolver_prefers_direct_nameserver_without_fallback_query() {
        let direct_hits = Arc::new(AtomicUsize::new(0));
        let fallback_hits = Arc::new(AtomicUsize::new(0));
        let resolver = EnhancedResolver::from_clients_with_fallback(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(203, 0, 113, 10)),
                hits: direct_hits.clone(),
                id: "direct-ns",
            })],
            Some(vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(198, 51, 100, 20)),
                hits: fallback_hits.clone(),
                id: "fallback-ns",
            })]),
            false,
        );

        let ip = resolver
            .resolve_v4("example.com", false)
            .await
            .expect("direct resolver query should succeed");

        assert_eq!(ip, Some(Ipv4Addr::new(203, 0, 113, 10)));
        assert_eq!(direct_hits.load(Ordering::SeqCst), 1);
        assert_eq!(fallback_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn direct_resolver_falls_back_when_direct_nameserver_has_no_ip() {
        let direct_hits = Arc::new(AtomicUsize::new(0));
        let fallback_hits = Arc::new(AtomicUsize::new(0));
        let direct_response = op::Message::response(0, op::OpCode::Query);
        let resolver = EnhancedResolver::from_clients_with_fallback(
            vec![Arc::new(CountingClient {
                response: direct_response,
                hits: direct_hits.clone(),
                id: "direct-ns",
            })],
            Some(vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(198, 51, 100, 20)),
                hits: fallback_hits.clone(),
                id: "fallback-ns",
            })]),
            false,
        );

        let ip = resolver
            .resolve_v4("example.com", false)
            .await
            .expect("fallback resolver query should succeed");

        assert_eq!(ip, Some(Ipv4Addr::new(198, 51, 100, 20)));
        assert_eq!(direct_hits.load(Ordering::SeqCst), 1);
        assert_eq!(fallback_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn reset_transports_covers_all_upstream_collections() {
        let resets = Arc::new(AtomicUsize::new(0));
        let client = || -> ThreadSafeDNSClient {
            Arc::new(ResetCountingClient {
                resets: resets.clone(),
            })
        };
        let mut resolver = EnhancedResolver::new_default().await;
        resolver.main = vec![client()];
        resolver.fallback = Some(vec![client()]);
        resolver.proxy_resolver = Some(vec![client()]);
        resolver.direct_resolver = Some(Arc::new(EnhancedResolver::from_clients(
            vec![client()],
            false,
        )));
        let mut policy = crate::common::trie::StringTrie::new();
        assert!(policy.insert("policy.example", Arc::new(vec![client()])));
        resolver.policy = Some(policy);

        assert_eq!(resolver.reset_transports().await.unwrap(), 5);
        assert_eq!(resets.load(Ordering::SeqCst), 5);
    }

    /// Regression test for https://github.com/Watfaq/clash-rs/issues/976
    /// IPv6 literal addresses must be returned directly even when dns.ipv6 is
    /// disabled, because they do not require DNS resolution.
    #[tokio::test]
    async fn test_resolve_ipv6_literal_when_ipv6_disabled() {
        let resolver = EnhancedResolver::new_default().await;
        // Ensure ipv6 is disabled, mirroring `dns.ipv6 = false`.
        resolver.set_ipv6(false);
        assert!(!resolver.ipv6(), "ipv6 should be disabled");

        // Resolving an IPv6 literal must succeed even with ipv6 disabled.
        let result = resolver
            .resolve("::1", false)
            .await
            .expect("resolve should not error for IPv6 literal");
        assert_eq!(
            result,
            Some(std::net::IpAddr::V6("::1".parse().unwrap())),
            "IPv6 literal should be returned as-is"
        );
    }

    /// Resolving a plain IPv4 literal must still work when ipv6 is disabled.
    #[tokio::test]
    async fn test_resolve_ipv4_literal_when_ipv6_disabled() {
        let resolver = EnhancedResolver::new_default().await;
        resolver.set_ipv6(false);

        let result = resolver
            .resolve("127.0.0.1", false)
            .await
            .expect("resolve should not error for IPv4 literal");
        assert_eq!(
            result,
            Some(std::net::IpAddr::V4("127.0.0.1".parse().unwrap())),
            "IPv4 literal should be returned as-is"
        );
    }

    /// resolve_v6 must return an IPv6 literal directly even when ipv6 is
    /// disabled (no DNS lookup needed for a literal).
    #[tokio::test]
    async fn test_resolve_v6_literal_when_ipv6_disabled() {
        let resolver = EnhancedResolver::new_default().await;
        resolver.set_ipv6(false);

        let result = resolver.resolve_v6("::1", false).await.expect(
            "resolve_v6 should not error for IPv6 literal when ipv6 disabled",
        );
        assert_eq!(
            result,
            Some("::1".parse::<std::net::Ipv6Addr>().unwrap()),
            "IPv6 literal should be returned directly"
        );
    }

    #[tokio::test]
    async fn test_lru_cache_hit_with_recursion_desired() {
        let mut resolver = EnhancedResolver::new_default().await;
        resolver.main.clear();
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));

        let (mut request, query) = test_query();
        request.metadata.recursion_desired = true;

        let record = rr::Record::from_rdata(
            query.name().clone(),
            300,
            rr::RData::A(rr::rdata::A(Ipv4Addr::new(127, 0, 0, 1))),
        );
        let mut cached =
            op::Message::response(request.metadata.id, request.metadata.op_code);
        cached.add_answer(record);
        resolver.lru_cache.as_ref().unwrap().insert(
            query,
            Ok(cached),
            Instant::now(),
        );

        let response = resolver
            .exchange(&request)
            .await
            .expect("should be served from cache");
        assert_eq!(response.metadata.message_type, op::MessageType::Response);
    }

    #[tokio::test]
    async fn cached_response_preserves_authority_additional_and_metadata() {
        let mut resolver = EnhancedResolver::new_default().await;
        resolver.main.clear();
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));

        let (mut request, query) = test_query();
        request.metadata.id = 0x2727;
        request.metadata.recursion_desired = true;
        let mut original = op::Message::response(0x1111, request.metadata.op_code);
        original.metadata.authoritative = true;
        original.metadata.recursion_available = true;
        original.add_query(query.clone());
        original.add_answer(rr::Record::from_rdata(
            query.name().clone(),
            240,
            rr::RData::A(rr::rdata::A(Ipv4Addr::new(192, 0, 2, 5))),
        ));
        original.add_authority(rr::Record::from_rdata(
            query.name().clone(),
            150,
            rr::RData::A(rr::rdata::A(Ipv4Addr::new(192, 0, 2, 9))),
        ));
        original.add_additional(rr::Record::from_rdata(
            query.name().clone(),
            150,
            rr::RData::A(rr::rdata::A(Ipv4Addr::new(192, 0, 2, 10))),
        ));
        resolver.lru_cache.as_ref().unwrap().insert(
            query.clone(),
            Ok(original),
            Instant::now() - Duration::from_secs(8),
        );

        let cached = resolver.exchange(&request).await.unwrap();
        assert_eq!(cached.metadata.id, 0x2727);
        assert!(cached.metadata.authoritative);
        assert!(cached.metadata.recursion_available);
        assert!(cached.metadata.recursion_desired);
        assert_eq!(cached.queries, vec![query]);
        assert_eq!(cached.answers.len(), 1);
        assert_eq!(cached.authorities.len(), 1);
        assert_eq!(cached.additionals.len(), 1);
        assert!(cached.answers[0].ttl <= 232, "cached TTL must age");
        assert_eq!(
            op::Message::from_vec(&cached.to_vec().unwrap())
                .unwrap()
                .authorities
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn request_specific_edns_never_uses_question_only_cache() {
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(FailingClient {
                id: "not-cached",
                reason: "upstream unavailable",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        let (mut request, query) = test_query();
        request.metadata.recursion_desired = true;
        let mut response = response_with_a(Ipv4Addr::new(192, 0, 2, 1));
        response.add_query(query.clone());
        resolver.lru_cache.as_ref().unwrap().insert(
            query,
            Ok(response),
            Instant::now(),
        );
        request.set_edns(op::Edns::new());
        assert!(
            resolver.exchange(&request).await.is_err(),
            "request-specific EDNS cannot reuse a query-only cached response"
        );
    }

    #[tokio::test]
    async fn noerror_nodata_without_safe_negative_ttl_is_not_cached() {
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(FixedClient {
                response: op::Message::response(0, op::OpCode::Query),
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        let (mut request, query) = test_query();
        request.metadata.recursion_desired = true;
        let answer = resolver.exchange_no_cache(&request).await.unwrap();
        assert!(answer.answers.is_empty());
        assert_eq!(answer.metadata.response_code, op::ResponseCode::NoError);
        assert!(
            resolver
                .lru_cache
                .as_ref()
                .unwrap()
                .get(&query, Instant::now())
                .is_none()
        );
    }

    #[tokio::test]
    async fn zero_ttl_answer_is_not_cached() {
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(FixedClient {
                response: {
                    let (request, query) = test_query();
                    let mut response = op::Message::response(
                        request.metadata.id,
                        request.metadata.op_code,
                    );
                    response.add_query(query.clone());
                    response.add_answer(rr::Record::from_rdata(
                        query.name().clone(),
                        0,
                        rr::RData::A(rr::rdata::A(Ipv4Addr::new(192, 0, 2, 2))),
                    ));
                    response
                },
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        let (mut request, query) = test_query();
        request.metadata.recursion_desired = true;
        assert_eq!(
            resolver.exchange_no_cache(&request).await.unwrap().answers[0].ttl,
            0
        );
        assert!(
            resolver
                .lru_cache
                .as_ref()
                .unwrap()
                .get(&query, Instant::now())
                .is_none(),
            "zero-TTL DNS answer must not be cached"
        );
    }

    #[tokio::test]
    async fn expired_cached_address_is_not_used_as_stale_success() {
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(FailingClient {
                id: "expired",
                reason: "upstream unreachable",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        let (mut request, query) = test_query();
        request.metadata.recursion_desired = true;
        let mut response = response_with_a(Ipv4Addr::new(192, 0, 2, 3));
        response.answers[0].ttl = 5;
        resolver.lru_cache.as_ref().unwrap().insert(
            query,
            Ok(response),
            Instant::now() - Duration::from_secs(10),
        );
        assert!(
            resolver.exchange(&request).await.is_err(),
            "expired cached records must not hide DNS outage"
        );
    }

    fn negative_response(
        code: op::ResponseCode,
        soa_zone: &str,
        soa_ttl: u32,
        minimum: u32,
    ) -> op::Message {
        let (request, query) = test_query();
        let mut response =
            op::Message::response(request.metadata.id, request.metadata.op_code);
        response.metadata.response_code = code;
        response.metadata.recursion_available = true;
        response.add_query(query);
        let zone = rr::Name::from_ascii(soa_zone).unwrap();
        response.add_authority(rr::Record::from_rdata(
            zone.clone(),
            soa_ttl,
            rr::RData::SOA(rr::rdata::SOA::new(
                zone,
                rr::Name::from_ascii("hostmaster.example.com.").unwrap(),
                42,
                60,
                60,
                60,
                minimum,
            )),
        ));
        response
    }

    #[tokio::test]
    async fn soa_based_nxdomain_is_cached_with_code_and_transaction_id() {
        let hits = Arc::new(AtomicUsize::new(0));
        let response =
            negative_response(op::ResponseCode::NXDomain, "example.com.", 300, 60);
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response,
                hits: hits.clone(),
                id: "authoritative-ns",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        let (mut request, _) = test_query();
        request.metadata.recursion_desired = true;
        request.metadata.id = 0x1234;
        let first = resolver.exchange(&request).await.unwrap();
        assert_eq!(first.metadata.response_code, op::ResponseCode::NXDomain);
        request.metadata.id = 0x4321;
        let second = resolver.exchange(&request).await.unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(second.metadata.id, 0x4321);
        assert_eq!(second.metadata.response_code, op::ResponseCode::NXDomain);
        assert_eq!(second.authorities.len(), 1);
        assert_eq!(second.authorities[0].ttl, 60);
        assert_eq!(second.authorities[0].data, first.authorities[0].data);
    }

    #[tokio::test]
    async fn soa_based_nodata_is_cached_per_question_type() {
        let hits = Arc::new(AtomicUsize::new(0));
        let response =
            negative_response(op::ResponseCode::NoError, "example.com.", 120, 30);
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response,
                hits: hits.clone(),
                id: "nodata-ns",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        let (mut request, _) = test_query();
        request.metadata.recursion_desired = true;
        resolver.exchange(&request).await.unwrap();
        resolver.exchange(&request).await.unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        request.queries[0].set_query_type(rr::RecordType::TXT);
        resolver.exchange(&request).await.unwrap();
        assert_eq!(
            hits.load(Ordering::SeqCst),
            2,
            "different QTYPE must not reuse NODATA"
        );
    }

    #[tokio::test]
    async fn expired_negative_cache_does_not_hide_upstream_failure() {
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(FailingClient {
                id: "offline",
                reason: "network unavailable",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        let (mut request, query) = test_query();
        request.metadata.recursion_desired = true;
        let response =
            negative_response(op::ResponseCode::NXDomain, "example.com.", 200, 2);
        resolver.cache_negative(
            &query,
            &response,
            Instant::now() - Duration::from_secs(5),
        );
        assert!(
            resolver.exchange(&request).await.is_err(),
            "expired negative cache must re-query"
        );
    }

    #[tokio::test]
    async fn negative_ttl_uses_lower_of_soa_rr_ttl_and_soa_minimum() {
        let resolver = EnhancedResolver::from_clients(vec![], false);
        let (mut request, query) = test_query();
        request.metadata.recursion_desired = true;
        let response =
            negative_response(op::ResponseCode::NXDomain, "example.com.", 10, 300);
        let now = Instant::now();
        resolver.cache_negative(&query, &response, now - Duration::from_secs(3));
        let cached = resolver.cached_negative(&query, &request, now).unwrap();
        assert!(cached.authorities[0].ttl <= 7);
        assert_eq!(cached.metadata.response_code, op::ResponseCode::NXDomain);
        assert!(
            resolver
                .cached_negative(&query, &request, now + Duration::from_secs(8))
                .is_none()
        );
    }

    #[tokio::test]
    async fn no_soa_wrong_zone_zero_ttl_and_servfail_are_not_negative_cached() {
        let resolver = EnhancedResolver::from_clients(vec![], false);
        let (mut request, query) = test_query();
        request.metadata.recursion_desired = true;
        let now = Instant::now();
        for response in [
            op::Message::error_msg(0, op::OpCode::Query, op::ResponseCode::NXDomain),
            negative_response(
                op::ResponseCode::NXDomain,
                "unrelated.org.",
                120,
                100,
            ),
            negative_response(op::ResponseCode::NXDomain, "example.com.", 120, 0),
            {
                let mut mismatch = negative_response(
                    op::ResponseCode::NXDomain,
                    "example.com.",
                    120,
                    100,
                );
                mismatch.authorities[0].dns_class = rr::DNSClass::CH;
                mismatch
            },
            negative_response(op::ResponseCode::NoError, "example.com.", 0, 100),
            negative_response(op::ResponseCode::ServFail, "example.com.", 120, 100),
        ] {
            resolver.cache_negative(&query, &response, now);
            assert!(
                resolver.cached_negative(&query, &request, now).is_none(),
                "invalid negative response must not be cached: {:?}",
                response.metadata.response_code
            );
        }
    }

    #[tokio::test]
    async fn positive_answer_invalidates_older_negative_for_same_question() {
        let mut resolver = EnhancedResolver::from_clients(vec![], false);
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        let (mut request, query) = test_query();
        request.metadata.recursion_desired = true;
        let negative =
            negative_response(op::ResponseCode::NXDomain, "example.com.", 120, 60);
        resolver.cache_negative(&query, &negative, Instant::now());
        assert!(
            resolver
                .cached_negative(&query, &request, Instant::now())
                .is_some()
        );

        resolver.main = vec![Arc::new(FixedClient {
            response: {
                let mut answer = response_with_a(Ipv4Addr::new(192, 0, 2, 50));
                answer.answers[0].ttl = 30;
                answer
            },
        })];
        let positive = resolver.exchange_no_cache(&request).await.unwrap();
        assert_eq!(EnhancedResolver::ip_list_of_message(&positive).len(), 1);
        assert!(
            resolver
                .cached_negative(&query, &request, Instant::now())
                .is_none()
        );
    }

    #[tokio::test]
    async fn network_reset_flushes_negative_cache() {
        let resolver = EnhancedResolver::from_clients(vec![], false);
        let (mut request, query) = test_query();
        request.metadata.recursion_desired = true;
        let now = Instant::now();
        let response =
            negative_response(op::ResponseCode::NXDomain, "example.com.", 120, 60);
        resolver.cache_negative(&query, &response, now);
        assert!(resolver.cached_negative(&query, &request, now).is_some());
        resolver.reset_transports().await.unwrap();
        assert!(
            resolver
                .cached_negative(&query, &request, Instant::now())
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_lru_skips_nxdomain_response() {
        let mut resolver = EnhancedResolver::new_default().await;
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));

        let (request, query) = test_query();
        let mut response =
            op::Message::response(request.metadata.id, request.metadata.op_code);
        response.metadata.response_code = op::ResponseCode::NXDomain;
        resolver.main = vec![Arc::new(FixedClient { response })];

        resolver
            .exchange_no_cache(&request)
            .await
            .expect("fixed client returns a response");

        assert!(
            resolver
                .lru_cache
                .as_ref()
                .unwrap()
                .get(&query, Instant::now())
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_proxy_server_nameserver_only_handles_ip_queries() {
        let mut resolver = EnhancedResolver::new_default().await;
        resolver.lru_cache = None;

        let proxy_hits = Arc::new(AtomicUsize::new(0));
        let main_hits = Arc::new(AtomicUsize::new(0));

        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(203, 0, 113, 10)),
            hits: proxy_hits.clone(),
            id: "proxy-ns",
        })]);
        resolver.main = vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(198, 51, 100, 20)),
            hits: main_hits.clone(),
            id: "main-ns",
        })];

        let mut domains = crate::common::trie::StringTrie::new();
        domains.insert("proxy.example.com", Arc::new(true));
        resolver.proxy_server_domains = Some(domains);

        let a_request = test_query_with_type(rr::RecordType::A);
        let a_response = resolver
            .exchange_no_cache(&a_request)
            .await
            .expect("A query should resolve");
        assert_eq!(
            EnhancedResolver::ip_list_of_message(&a_response),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))]
        );
        assert_eq!(proxy_hits.load(Ordering::SeqCst), 1);
        assert_eq!(main_hits.load(Ordering::SeqCst), 0);

        let txt_request = test_query_with_type(rr::RecordType::TXT);
        resolver
            .exchange_no_cache(&txt_request)
            .await
            .expect("TXT query should resolve through main nameserver");
        assert_eq!(proxy_hits.load(Ordering::SeqCst), 1);
        assert_eq!(main_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn policy_negative_cache_does_not_leak_to_main_or_fallback() {
        let mut resolver = EnhancedResolver::from_clients_with_fallback(
            vec![],
            Some(vec![]),
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        let policy_hits = Arc::new(AtomicUsize::new(0));
        let main_hits = Arc::new(AtomicUsize::new(0));
        let fallback_hits = Arc::new(AtomicUsize::new(0));
        let mut policy = crate::common::trie::StringTrie::new();
        policy.insert(
            "proxy.example.com",
            Arc::new(vec![Arc::new(CountingClient {
                response: negative_response(
                    op::ResponseCode::NXDomain,
                    "example.com.",
                    120,
                    60,
                ),
                hits: policy_hits.clone(),
                id: "private-policy",
            }) as ThreadSafeDNSClient]),
        );
        resolver.policy = Some(policy);
        resolver.main = vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 77)),
            hits: main_hits.clone(),
            id: "public-main",
        })];
        resolver.fallback = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 78)),
            hits: fallback_hits.clone(),
            id: "public-fallback",
        })]);
        let mut request = test_query_with_type(rr::RecordType::A);
        request.metadata.recursion_desired = true;
        for _ in 0..2 {
            let response = resolver.exchange(&request).await.unwrap();
            assert_eq!(response.metadata.response_code, op::ResponseCode::NXDomain);
        }
        assert_eq!(policy_hits.load(Ordering::SeqCst), 1);
        assert_eq!(main_hits.load(Ordering::SeqCst), 0);
        assert_eq!(fallback_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn policy_upstream_failure_fails_closed_without_public_fallback() {
        let mut resolver = EnhancedResolver::from_clients_with_fallback(
            vec![],
            Some(vec![]),
            false,
        );
        let main_hits = Arc::new(AtomicUsize::new(0));
        let fallback_hits = Arc::new(AtomicUsize::new(0));
        let mut policy = crate::common::trie::StringTrie::new();
        policy.insert(
            "proxy.example.com",
            Arc::new(vec![Arc::new(FailingClient {
                id: "private-policy",
                reason: "private DNS offline",
            }) as ThreadSafeDNSClient]),
        );
        resolver.policy = Some(policy);
        resolver.main = vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 77)),
            hits: main_hits.clone(),
            id: "public-main",
        })];
        resolver.fallback = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 78)),
            hits: fallback_hits.clone(),
            id: "public-fallback",
        })]);
        let error = resolver
            .exchange_no_cache(&test_query_with_type(rr::RecordType::A))
            .await
            .expect_err("private policy errors must not switch to public upstreams");
        assert!(error.to_string().contains("private DNS offline"));
        assert_eq!(main_hits.load(Ordering::SeqCst), 0);
        assert_eq!(fallback_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn proxy_server_nameserver_precedes_nameserver_policy_without_leaking() {
        let mut resolver = EnhancedResolver::from_clients(vec![], false);
        let proxy_hits = Arc::new(AtomicUsize::new(0));
        let policy_hits = Arc::new(AtomicUsize::new(0));
        let main_hits = Arc::new(AtomicUsize::new(0));
        let mut domains = crate::common::trie::StringTrie::new();
        domains.insert("proxy.example.com", Arc::new(true));
        resolver.proxy_server_domains = Some(domains);
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: negative_response(
                op::ResponseCode::NXDomain,
                "example.com.",
                120,
                60,
            ),
            hits: proxy_hits.clone(),
            id: "proxy-server-ns",
        })]);
        let mut policy = crate::common::trie::StringTrie::new();
        policy.insert(
            "proxy.example.com",
            Arc::new(vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 77)),
                hits: policy_hits.clone(),
                id: "private-policy",
            }) as ThreadSafeDNSClient]),
        );
        resolver.policy = Some(policy);
        resolver.main = vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 78)),
            hits: main_hits.clone(),
            id: "public-main",
        })];
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        let mut request = test_query_with_type(rr::RecordType::A);
        request.metadata.recursion_desired = true;
        for _ in 0..2 {
            assert_eq!(
                resolver
                    .exchange(&request)
                    .await
                    .unwrap()
                    .metadata
                    .response_code,
                op::ResponseCode::NXDomain
            );
        }
        assert_eq!(proxy_hits.load(Ordering::SeqCst), 1);
        assert_eq!(policy_hits.load(Ordering::SeqCst), 0);
        assert_eq!(main_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn nameserver_policy_works_without_fallback() {
        let mut resolver = EnhancedResolver::new_default().await;
        resolver.lru_cache = None;

        let policy_hits = Arc::new(AtomicUsize::new(0));
        let main_hits = Arc::new(AtomicUsize::new(0));
        resolver.policy = {
            let mut policy: crate::common::trie::StringTrie<
                Vec<ThreadSafeDNSClient>,
            > = crate::common::trie::StringTrie::new();
            policy.insert(
                "proxy.example.com",
                Arc::new(vec![Arc::new(CountingClient {
                    response: response_with_a(Ipv4Addr::new(203, 0, 113, 10)),
                    hits: policy_hits.clone(),
                    id: "policy-ns",
                })]),
            );
            Some(policy)
        };
        resolver.main = vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(198, 51, 100, 20)),
            hits: main_hits.clone(),
            id: "main-ns",
        })];

        let response = resolver
            .exchange_no_cache(&test_query_with_type(rr::RecordType::A))
            .await
            .expect("policy nameserver should resolve the query");

        assert_eq!(
            EnhancedResolver::ip_list_of_message(&response),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))]
        );
        assert_eq!(policy_hits.load(Ordering::SeqCst), 1);
        assert_eq!(main_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    #[ignore = "network unstable on CI"]
    async fn test_bad_labels_with_custom_resolver() {
        let name = rr::Name::from_str_relaxed("some_domain.understore")
            .unwrap()
            .append_domain(&rr::Name::root())
            .unwrap();
        assert_eq!(name.to_string(), "some_domain.understore.");

        let mut m = op::Message::query();
        let mut q = op::Query::new();

        q.set_name(name);
        q.set_query_type(rr::RecordType::A);
        m.add_query(q);
        m.metadata.recursion_desired = true;

        let stream = UdpClientStream::builder(
            "1.1.1.1:53".parse().unwrap(),
            DnsRuntimeProvider::new_direct(None, None),
        )
        .build();
        let (client, bg) = client::Client::<DnsRuntimeProvider>::from_sender(stream);

        tokio::spawn(bg);

        let mut req = DnsRequest::new(m, DnsRequestOptions::default());
        req.metadata.id = rand::random::<u16>();
        let res = client.send(req).first_answer().await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    #[ignore = "network unstable on CI"]
    async fn test_udp_resolve() {
        let c = DnsClient::new_client(Opts {
            father: None,
            outbound_resolver: None,
            host: url::Host::Ipv4(Ipv4Addr::from([114, 114, 114, 114])),
            port: 53,
            net: DNSNetMode::Udp,
            iface: None,
            proxy: get_default_outbound(),
            doh_path: None,
            ecs: None,
            fw_mark: None,
            rule_dispatch: None,
            network_path_source: None,
        })
        .await
        .expect("build client");

        test_client(c).await;
    }

    #[tokio::test]
    #[ignore = "network unstable on CI"]
    async fn test_tcp_resolve() {
        let c = DnsClient::new_client(Opts {
            father: None,
            outbound_resolver: None,
            host: url::Host::Ipv4(Ipv4Addr::from([1, 1, 1, 1])),
            port: 53,
            net: DNSNetMode::Tcp,
            iface: None,
            proxy: get_default_outbound(),
            doh_path: None,
            ecs: None,
            fw_mark: None,
            rule_dispatch: None,
            network_path_source: None,
        })
        .await
        .expect("build client");

        test_client(c).await;
    }

    #[tokio::test]
    #[ignore = "network unstable on CI"]
    async fn test_dot_resolve() {
        let c = DnsClient::new_client(Opts {
            father: Some(Arc::new(EnhancedResolver::new_default().await)),
            outbound_resolver: None,
            host: url::Host::Domain("dns.google".to_string()),
            port: 853,
            net: DNSNetMode::DoT,
            iface: None,
            proxy: get_default_outbound(),
            doh_path: None,
            ecs: None,
            fw_mark: None,
            rule_dispatch: None,
            network_path_source: None,
        })
        .await
        .expect("build client");

        test_client(c).await;
    }

    #[tokio::test]
    #[ignore = "network unstable on CI"]
    async fn test_doh_resolve() {
        let default_resolver = Arc::new(EnhancedResolver::new_default().await);

        let c = DnsClient::new_client(Opts {
            father: Some(default_resolver.clone()),
            outbound_resolver: None,
            host: url::Host::Domain("cloudflare-dns.com".to_string()),
            port: 443,
            net: DNSNetMode::DoH,
            iface: None,
            proxy: get_default_outbound(),
            doh_path: None,
            ecs: None,
            fw_mark: None,
            rule_dispatch: None,
            network_path_source: None,
        })
        .await
        .expect("build client");

        test_client(c).await;
    }

    #[tokio::test]
    #[ignore = "network unstable on CI"]
    async fn test_dhcp_client() {
        let c = DnsClient::new_client(Opts {
            father: None,
            outbound_resolver: None,
            host: url::Host::Domain("en0".to_string()),
            port: 0,
            net: DNSNetMode::Dhcp,
            iface: None,
            proxy: get_default_outbound(),
            doh_path: None,
            ecs: None,
            fw_mark: None,
            rule_dispatch: None,
            network_path_source: None,
        })
        .await
        .expect("build client");

        test_client(c).await;
    }

    async fn test_client(c: ThreadSafeDNSClient) {
        let mut m = op::Message::query();
        let mut q = op::Query::new();
        q.set_name(rr::Name::from_utf8("www.google.com").unwrap());
        q.set_query_type(rr::RecordType::A);
        m.add_query(q);

        let r = EnhancedResolver::batch_exchange(&vec![c.clone()], &m)
            .await
            .expect("should exchange");

        let ips = EnhancedResolver::ip_list_of_message(&r);

        assert!(!ips.is_empty());
        assert!(!ips[0].is_unspecified());
        assert!(ips[0].is_ipv4());

        let mut m = op::Message::query();
        let mut q = op::Query::new();
        q.set_name(rr::Name::from_utf8("www.google.com").unwrap());
        q.set_query_type(rr::RecordType::AAAA);
        m.add_query(q);

        let r = EnhancedResolver::batch_exchange(&vec![c.clone()], &m)
            .await
            .expect("should exchange");

        let ips = EnhancedResolver::ip_list_of_message(&r);

        assert!(!ips.is_empty());
        assert!(!ips[0].is_unspecified());
        assert!(ips[0].is_ipv6());
    }
    fn get_default_outbound() -> Arc<dyn crate::proxy::OutboundHandler> {
        Arc::new(proxy::direct::Handler::new("default_direct"))
    }

    fn make_outbound_registry(
        entries: &[(&str, &str)],
    ) -> crate::proxy::utils::OutboundHandlerRegistry {
        use crate::proxy::{
            HandlerCommonOptions,
            socks::outbound::{
                Handler as SocksHandler, HandlerOptions as SocksHandlerOptions,
            },
        };

        let mut map = std::collections::HashMap::new();
        for (name, server) in entries {
            let handler: Arc<dyn crate::proxy::OutboundHandler> =
                Arc::new(SocksHandler::new(SocksHandlerOptions {
                    name: name.to_string(),
                    common_opts: HandlerCommonOptions::default(),
                    server: server.to_string(),
                    port: 1080,
                    user: None,
                    password: None,
                    udp: false,
                    tls_client: None,
                }));
            map.insert(name.to_string(), handler);
        }
        Arc::new(RwLock::new(map))
    }

    fn make_proxy_nameserver_config() -> Config {
        let proxy_ns = NameServer {
            net: DNSNetMode::Udp,
            host: url::Host::Ipv4("8.8.8.8".parse().unwrap()),
            port: 53,
            interface: None,
            proxy: None,
            doh_path: None,
        };
        Config {
            enable: true,
            ipv6: false,
            proxy_server_nameserver: Some(vec![proxy_ns]),
            default_nameserver: vec![NameServer {
                net: DNSNetMode::Udp,
                host: url::Host::Ipv4("114.114.114.114".parse().unwrap()),
                port: 53,
                interface: None,
                proxy: None,
                doh_path: None,
            }],
            nameserver: vec![NameServer {
                net: DNSNetMode::Udp,
                host: url::Host::Ipv4("223.5.5.5".parse().unwrap()),
                port: 53,
                interface: None,
                proxy: None,
                doh_path: None,
            }],
            ..Config::default()
        }
    }

    #[tokio::test]
    async fn missing_dhcp_interface_is_a_hard_config_error() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_store = crate::app::profile::ThreadSafeCacheFile::new(
            temp_dir.path().join("cache.db").to_str().unwrap(),
            false,
        );
        let mut config = make_proxy_nameserver_config();
        config.nameserver = vec![NameServer {
            net: DNSNetMode::Dhcp,
            host: url::Host::Domain("__chimera_missing_interface__".to_owned()),
            port: 0,
            interface: None,
            proxy: None,
            doh_path: None,
        }];

        let result = EnhancedResolver::new(
            config,
            cache_store,
            None,
            Arc::new(RwLock::new(std::collections::HashMap::new())),
            None,
        )
        .await;

        assert!(matches!(
            result,
            Err(crate::Error::InvalidConfig(message))
                if message.contains("__chimera_missing_interface__")
        ));
    }

    #[tokio::test]
    async fn test_proxy_server_nameserver_initialization() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_store = crate::app::profile::ThreadSafeCacheFile::new(
            temp_dir.path().join("cache.db").to_str().unwrap(),
            false,
        );

        let resolver = EnhancedResolver::new(
            make_proxy_nameserver_config(),
            cache_store,
            None,
            Arc::new(RwLock::new(std::collections::HashMap::new())),
            None,
        )
        .await
        .expect("proxy nameserver config should initialize");

        assert!(resolver.proxy_resolver.is_some());
        assert!(resolver.proxy_server_domains.is_none());
    }

    #[tokio::test]
    async fn test_proxy_server_nameserver_without_config() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_store = crate::app::profile::ThreadSafeCacheFile::new(
            temp_dir.path().join("cache.db").to_str().unwrap(),
            false,
        );
        let mut config = make_proxy_nameserver_config();
        config.proxy_server_nameserver = None;

        let resolver = EnhancedResolver::new(
            config,
            cache_store,
            None,
            Arc::new(RwLock::new(std::collections::HashMap::new())),
            None,
        )
        .await
        .expect("config without proxy nameserver should initialize");

        assert!(resolver.proxy_resolver.is_none());
        assert!(resolver.proxy_server_domains.is_none());
    }

    #[tokio::test]
    async fn test_direct_nameserver_initializes_direct_resolver() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_store = crate::app::profile::ThreadSafeCacheFile::new(
            temp_dir.path().join("cache.db").to_str().unwrap(),
            false,
        );
        let mut config = make_proxy_nameserver_config();
        config.direct_nameserver = Some(vec![NameServer {
            net: DNSNetMode::Udp,
            host: url::Host::Ipv4("223.5.5.5".parse().unwrap()),
            port: 53,
            interface: None,
            proxy: None,
            doh_path: None,
        }]);

        let resolver = EnhancedResolver::new(
            config,
            cache_store,
            None,
            Arc::new(RwLock::new(std::collections::HashMap::new())),
            None,
        )
        .await
        .expect("direct nameserver config should initialize");

        assert!(resolver.direct_resolver().is_some());
    }

    #[tokio::test]
    async fn test_direct_resolver_absent_without_direct_nameserver() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_store = crate::app::profile::ThreadSafeCacheFile::new(
            temp_dir.path().join("cache.db").to_str().unwrap(),
            false,
        );

        let resolver = EnhancedResolver::new(
            make_proxy_nameserver_config(),
            cache_store,
            None,
            Arc::new(RwLock::new(std::collections::HashMap::new())),
            None,
        )
        .await
        .expect("config without direct nameserver should initialize");

        assert!(resolver.direct_resolver().is_none());
    }

    #[tokio::test]
    async fn test_proxy_server_domains_populated_from_outbounds() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_store = crate::app::profile::ThreadSafeCacheFile::new(
            temp_dir.path().join("cache.db").to_str().unwrap(),
            false,
        );
        let outbounds = make_outbound_registry(&[
            ("proxy-a", "proxy.example.com"),
            ("proxy-b", "vpn.example.net"),
            ("proxy-ip", "1.2.3.4"),
        ]);

        let resolver = EnhancedResolver::new(
            make_proxy_nameserver_config(),
            cache_store,
            None,
            outbounds,
            None,
        )
        .await
        .expect("proxy domain config should initialize");

        assert!(resolver.proxy_resolver.is_some());
        let domains = resolver
            .proxy_server_domains
            .as_ref()
            .expect("proxy_server_domains should be populated");
        assert!(domains.search("proxy.example.com").is_some());
        assert!(domains.search("vpn.example.net").is_some());
        assert!(domains.search("1.2.3.4").is_some());
    }

    #[tokio::test]
    #[ignore = "network unstable on CI"]
    async fn test_proxy_server_domain_resolved_via_proxy_nameserver() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_store = crate::app::profile::ThreadSafeCacheFile::new(
            temp_dir.path().join("cache.db").to_str().unwrap(),
            false,
        );

        let outbounds = make_outbound_registry(&[("cf-proxy", "one.one.one.one")]);

        let resolver = EnhancedResolver::new(
            make_proxy_nameserver_config(),
            cache_store,
            None,
            outbounds,
            None,
        )
        .await
        .expect("proxy domain resolver should initialize");

        assert!(resolver.proxy_server_domains.is_some());
        assert!(
            resolver
                .proxy_server_domains
                .as_ref()
                .unwrap()
                .search("one.one.one.one")
                .is_some()
        );

        let ip = resolver
            .resolve("one.one.one.one", false)
            .await
            .expect("should resolve one.one.one.one")
            .expect("should return an IP for one.one.one.one");
        assert!(
            ip.to_string() == "1.1.1.1" || ip.to_string() == "1.0.0.1",
            "unexpected IP: {}",
            ip
        );
    }
}
