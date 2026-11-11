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
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed},
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

/// Bounded cache for ordinary DNS answers to hostnames that previously
/// belonged to a proxy Provider. Unlike Hickory's Question-only cache, each
/// entry carries the ownership generation that authorized its insertion.
#[derive(Clone)]
struct ProviderEpochCacheEntry {
    generation: u64,
    response: op::Message,
    inserted: Instant,
    expires: Instant,
}

const PROVIDER_EPOCH_CACHE_CAPACITY: usize = 1024;
const PROVIDER_EPOCH_CACHE_MAX_TTL: u32 = 86_400;

// Deterministic, task-local cache handoff gate for concurrency regression tests.
// Compiled out of production; unlike a global hook, parallel tests cannot
// pause each other's queries or change the runtime resolver layout.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CacheCandidateKind {
    Positive,
    Negative,
}

#[cfg(test)]
#[derive(Clone)]
struct CacheCandidateTestPause {
    kind: CacheCandidateKind,
    selected: Arc<tokio::sync::Barrier>,
    resume: Arc<tokio::sync::Barrier>,
}

#[cfg(test)]
tokio::task_local! {
    static CACHE_CANDIDATE_TEST_PAUSE: CacheCandidateTestPause;
}

// Pause only the scoped query between the public entry generation snapshot
// and the internal no-cache generation snapshot.
#[cfg(test)]
#[derive(Clone)]
struct PublicHandoffTestPause {
    selected: Arc<tokio::sync::Barrier>,
    resume: Arc<tokio::sync::Barrier>,
}

#[cfg(test)]
tokio::task_local! {
    static PUBLIC_HANDOFF_TEST_PAUSE: PublicHandoffTestPause;
}

// Pause inside the no-cache path after the outer entry has validated its
// generation but before the internal path samples ownership again.
#[cfg(test)]
tokio::task_local! {
    static INTERNAL_HANDOFF_TEST_PAUSE: PublicHandoffTestPause;
}

#[cfg(test)]
tokio::task_local! {
    static PUBLIC_CACHE_WRITE_TEST_PAUSE: PublicHandoffTestPause;
}

// Pause after internal query/cache completion, before returning to the caller.
#[cfg(test)]
tokio::task_local! {
    static PUBLIC_RETURN_TEST_PAUSE: PublicHandoffTestPause;
}

struct TransportResetGuard<'a>(&'a AtomicUsize);

impl Drop for TransportResetGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

pub struct EnhancedResolver {
    ipv6: Arc<AtomicBool>,
    dns_ipv6: bool,
    health: Arc<DnsHealthTracker>,
    hosts: Option<trie::StringTrie<net::IpAddr>>,
    main: Vec<ThreadSafeDNSClient>,

    fallback: Option<Vec<ThreadSafeDNSClient>>,
    fallback_domain_filters: Option<Vec<Box<dyn FallbackDomainFilter>>>,
    fallback_ip_filters: Option<Vec<Box<dyn FallbackIPFilter>>>,

    lru_cache: Option<hickory_resolver::ResponseCache>,
    // Positive answers learned after a reset live in a separate network epoch.
    network_positive_cache: Mutex<Option<(u64, hickory_resolver::ResponseCache)>>,
    // The positive cache keys only by Question and cannot cache a negative
    // Message with a per-response SOA TTL. Keep a bounded negative cache
    // alongside it, activated only when the positive cache is enabled.
    negative_cache: Mutex<lru_time_cache::LruCache<String, NegativeEntry>>,
    provider_epoch_cache:
        Mutex<lru_time_cache::LruCache<String, ProviderEpochCacheEntry>>,
    /// Incremented during network reset while holding provider_epoch_cache;
    /// queries from an older path cannot repopulate the cleared cache.
    provider_epoch_network_generation: AtomicU64,
    // Prevent new DNS requests from using transports during their reset.
    transport_resets_in_progress: Arc<AtomicUsize>,
    // A partial reset failure invalidates the entire transport collection.
    transport_reset_failed: Arc<AtomicBool>,
    // Irreversible owner retirement after successful runtime replacement.
    // Network resets may clear a transient failure, never this flag.
    retired: AtomicBool,
    // Candidate resolvers are constructed usable for setup; the runtime
    // coordinator suspends them before exposing any candidate listeners/API.
    published: Arc<AtomicBool>,
    // A retained DIRECT child must not publish independently of its parent.
    parent_published: Option<Arc<AtomicBool>>,
    /// DIRECT child: never reopen while its owning parent is still failed.
    /// The parent is the sole authority that clears this gate after a full reset.
    parent_transport_failed: Option<Arc<AtomicBool>>,
    /// A queued parent reset also blocks DIRECT after an earlier reset has
    /// temporarily cleared its failure flag.
    parent_resets_in_progress: Option<Arc<AtomicUsize>>,
    // Serialize recovery attempts; cancellation must leave transports invalid.
    transport_reset_lock: tokio::sync::Mutex<()>,
    policy: Option<Arc<trie::StringTrie<Vec<ThreadSafeDNSClient>>>>,
    /// The DIRECT child shares this policy and its clients with its parent;
    /// only the parent owns the policy clients' network-reset lifecycle.
    policy_is_parent_shared: bool,

    proxy_resolver: Option<Vec<ThreadSafeDNSClient>>,
    /// Ordered, per-proxy-host DNS upstream overrides.
    proxy_server_nameserver_policy:
        Vec<(Arc<trie::StringTrie<bool>>, Vec<ThreadSafeDNSClient>)>,
    /// Dedicated node resolver must honor the node policy at transport dial-time.
    proxy_node_resolver: bool,
    proxy_server_domains: Option<trie::StringTrie<bool>>,
    /// Live provider-host ownership is independent of the startup static
    /// outbound trie; each refreshed provider replaces only its own names.
    provider_proxy_server_domains:
        RwLock<std::collections::HashMap<String, std::collections::HashSet<String>>>,
    /// Monotonic registry epoch: detects remove/re-add ABA during in-flight node DNS.
    provider_dns_epoch: AtomicU64,
    /// Retain each domain's generation for the lifetime of the shared cache.
    /// Pruning this history without version-tagging/invalidation would revive
    /// public DNS responses cached before a provider's ownership transition.
    provider_domain_generations: RwLock<std::collections::HashMap<String, u64>>,
    direct_resolver: Option<ThreadSafeDNSResolver>,

    fake_dns: Option<ThreadSafeFakeDns>,
    fake_ip_ttl: u32,
    safe_srv: bool,

    reverse_lookup_cache:
        Option<Arc<RwLock<lru_time_cache::LruCache<net::IpAddr, String>>>>,
}

// A DIRECT child can outlive a parent resolver if a caller holds a cloned
// trait-object handle. Mark the shared parent recovery gate closed before
// releasing the owner; child-only resets must not reopen orphaned DNS.
impl Drop for EnhancedResolver {
    fn drop(&mut self) {
        self.transport_reset_failed
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl EnhancedResolver {
    #[cfg(test)]
    async fn pause_selected_cache_candidate_for_test(kind: CacheCandidateKind) {
        if let Ok(pause) = CACHE_CANDIDATE_TEST_PAUSE.try_with(Clone::clone) {
            assert_eq!(pause.kind, kind, "paused the wrong cache branch");
            pause.selected.wait().await;
            pause.resume.wait().await;
        }
    }

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

    fn cached_provider_epoch_response(
        &self,
        query: &op::Query,
        request: &op::Message,
        generation: u64,
        now: Instant,
    ) -> Option<op::Message> {
        // Callers must have independently confirmed that the QNAME is not a
        // live Provider endpoint, and must revalidate its generation after
        // fetching the candidate. Generation zero is reserved for ordinary
        // negative answers after the first network reset; these entries are
        // cleared on each reset under the cache commit lock.
        // No cache lock is held across an await.
        let key = Self::negative_cache_key(query);
        let mut entries = self
            .provider_epoch_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = entries.get(&key)?.clone();
        if entry.generation != generation {
            // A lagging reader must not evict a newer generation's entry.
            return None;
        }
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

    #[cfg(test)]
    fn cache_provider_epoch_response(
        &self,
        query: &op::Query,
        response: &op::Message,
        generation: u64,
        now: Instant,
    ) {
        self.cache_provider_epoch_response_for_network(
            query, response, generation, now, None,
        );
    }

    fn cache_provider_epoch_response_for_network(
        &self,
        query: &op::Query,
        response: &op::Message,
        generation: u64,
        now: Instant,
        network_generation: Option<u64>,
    ) {
        if (generation == 0
            && (network_generation.is_none_or(|epoch| epoch == 0)
                || Self::negative_ttl(query, response).is_none()))
            || response.metadata.message_type != op::MessageType::Response
            || response.metadata.authentic_data
            || response.edns.is_some()
            || response.signature.is_some()
        {
            return;
        }
        // Reuse the RFC 2308 negative TTL rules and the positive-cache
        // eligibility gates. A zero-TTL/unsigned/DNSSEC/EDNS variant must
        // never be promoted into the epoch cache by this optimization.
        let negative_ttl = Self::negative_ttl(query, response);
        let ttl = if let Some(ttl) = negative_ttl {
            ttl
        } else {
            if !Self::cache_safe_response(response)
                || (query.query_type() == rr::RecordType::TXT
                    && query.name().to_ascii().starts_with("_acme-challenge."))
            {
                return;
            }
            let ips = Self::ip_list_of_message(response);
            if !ips.is_empty() && ips.iter().all(net::IpAddr::is_unspecified) {
                return;
            }
            let Some(ttl) = response.all_sections().map(|record| record.ttl).min()
            else {
                return;
            };
            ttl
        }
        .min(PROVIDER_EPOCH_CACHE_MAX_TTL);
        if ttl == 0 {
            return;
        }
        let mut cached = response.clone();
        if negative_ttl.is_some() {
            // Negative replies use min(SOA TTL, SOA.MINIMUM) per RFC 2308.
            for record in &mut cached.authorities {
                if matches!(record.data, rr::RData::SOA(_)) {
                    record.ttl = record.ttl.min(ttl);
                }
            }
        } else {
            // Match the default Hickory maximum positive TTL: do not
            // advertise a longer lifetime than the cache retains.
            for record in cached
                .answers
                .iter_mut()
                .chain(cached.authorities.iter_mut())
                .chain(cached.additionals.iter_mut())
            {
                record.ttl = record.ttl.min(PROVIDER_EPOCH_CACHE_MAX_TTL);
            }
        }
        let key = Self::negative_cache_key(query);
        let mut entries = self
            .provider_epoch_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Reset takes the same cache lock before advancing this generation
        // and clearing entries. A pre-reset writer cannot insert afterwards.
        if network_generation.is_some_and(|expected| {
            self.provider_epoch_network_generation.load(Relaxed) != expected
        }) {
            return;
        }
        // A query which began in an older Provider generation can complete
        // after a newer query has cached its answer. Do not let an obsolete
        // writer replace that answer (even though readers would fail closed).
        if entries
            .peek(&key)
            .is_some_and(|existing| existing.generation > generation)
        {
            return;
        }
        entries.insert(
            key,
            ProviderEpochCacheEntry {
                generation,
                response: cached,
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

    #[cfg(test)]
    fn from_clients(main: Vec<ThreadSafeDNSClient>, ipv6: bool) -> Self {
        Self::from_clients_with_fallback(main, None, ipv6)
    }

    #[cfg(test)]
    fn direct_with_optional_policy(
        direct_clients: Vec<ThreadSafeDNSClient>,
        fallback_clients: Vec<ThreadSafeDNSClient>,
        ipv6: bool,
        follow_policy: bool,
        nameserver_policy: Option<Arc<trie::StringTrie<Vec<ThreadSafeDNSClient>>>>,
    ) -> Self {
        Self::direct_with_optional_ipv6_policy(
            direct_clients,
            fallback_clients,
            Arc::new(AtomicBool::new(ipv6)),
            ipv6,
            follow_policy,
            nameserver_policy,
        )
    }

    fn direct_with_optional_ipv6_policy(
        direct_clients: Vec<ThreadSafeDNSClient>,
        fallback_clients: Vec<ThreadSafeDNSClient>,
        ipv6: Arc<AtomicBool>,
        dns_ipv6: bool,
        follow_policy: bool,
        nameserver_policy: Option<Arc<trie::StringTrie<Vec<ThreadSafeDNSClient>>>>,
    ) -> Self {
        let fallback = (!follow_policy).then_some(fallback_clients);
        let mut resolver = Self::from_clients_with_ipv6_policy(
            direct_clients,
            fallback,
            ipv6,
            dns_ipv6,
        );
        if follow_policy {
            resolver.policy = nameserver_policy;
            resolver.policy_is_parent_shared = resolver.policy.is_some();
        }
        resolver
    }

    fn with_parent_transport_gate(
        mut self,
        parent_failure: Arc<AtomicBool>,
        parent_resets: Arc<AtomicUsize>,
    ) -> Self {
        self.parent_transport_failed = Some(parent_failure);
        self.parent_resets_in_progress = Some(parent_resets);
        self
    }

    fn with_parent_publication_gate(
        mut self,
        parent_published: Arc<AtomicBool>,
    ) -> Self {
        self.parent_published = Some(parent_published);
        self
    }

    #[cfg(test)]
    fn from_clients_with_fallback(
        main: Vec<ThreadSafeDNSClient>,
        fallback: Option<Vec<ThreadSafeDNSClient>>,
        ipv6: bool,
    ) -> Self {
        Self::from_clients_with_ipv6_policy(
            main,
            fallback,
            Arc::new(AtomicBool::new(ipv6)),
            ipv6,
        )
    }

    fn from_clients_with_ipv6_policy(
        main: Vec<ThreadSafeDNSClient>,
        fallback: Option<Vec<ThreadSafeDNSClient>>,
        ipv6: Arc<AtomicBool>,
        dns_ipv6: bool,
    ) -> Self {
        let health = Arc::new(DnsHealthTracker::default());
        let main = observe_clients(main, "main", &health);
        let fallback =
            fallback.map(|clients| observe_clients(clients, "fallback", &health));
        Self {
            ipv6,
            dns_ipv6,
            health,
            hosts: None,
            main,
            fallback,
            fallback_domain_filters: None,
            fallback_ip_filters: None,
            lru_cache: None,
            network_positive_cache: Mutex::new(None),
            negative_cache: Mutex::new(lru_time_cache::LruCache::with_capacity(
                1024,
            )),
            provider_epoch_cache: Mutex::new(
                lru_time_cache::LruCache::with_capacity(
                    PROVIDER_EPOCH_CACHE_CAPACITY,
                ),
            ),
            policy: None,
            policy_is_parent_shared: false,
            proxy_resolver: None,
            proxy_server_nameserver_policy: Vec::new(),
            proxy_node_resolver: false,
            proxy_server_domains: None,
            provider_proxy_server_domains: RwLock::new(Default::default()),
            provider_dns_epoch: AtomicU64::new(0),
            provider_epoch_network_generation: AtomicU64::new(0),
            transport_resets_in_progress: Arc::new(AtomicUsize::new(0)),
            transport_reset_failed: Arc::new(AtomicBool::new(false)),
            retired: AtomicBool::new(false),
            published: Arc::new(AtomicBool::new(true)),
            parent_published: None,
            parent_transport_failed: None,
            parent_resets_in_progress: None,
            transport_reset_lock: tokio::sync::Mutex::new(()),
            provider_domain_generations: RwLock::new(Default::default()),
            direct_resolver: None,
            fake_dns: None,
            fake_ip_ttl: 1,
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
            ipv6: Arc::new(AtomicBool::new(false)),
            dns_ipv6: false,
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
            network_positive_cache: Mutex::new(None),
            negative_cache: Mutex::new(lru_time_cache::LruCache::with_capacity(
                1024,
            )),
            provider_epoch_cache: Mutex::new(
                lru_time_cache::LruCache::with_capacity(
                    PROVIDER_EPOCH_CACHE_CAPACITY,
                ),
            ),
            policy: None,
            policy_is_parent_shared: false,

            proxy_resolver: None,
            proxy_server_nameserver_policy: Vec::new(),
            proxy_node_resolver: false,
            proxy_server_domains: None,
            provider_proxy_server_domains: RwLock::new(Default::default()),
            provider_dns_epoch: AtomicU64::new(0),
            provider_epoch_network_generation: AtomicU64::new(0),
            transport_resets_in_progress: Arc::new(AtomicUsize::new(0)),
            transport_reset_failed: Arc::new(AtomicBool::new(false)),
            retired: AtomicBool::new(false),
            published: Arc::new(AtomicBool::new(true)),
            parent_published: None,
            parent_transport_failed: None,
            parent_resets_in_progress: None,
            transport_reset_lock: tokio::sync::Mutex::new(()),
            provider_domain_generations: RwLock::new(Default::default()),
            direct_resolver: None,

            fake_dns: None,
            fake_ip_ttl: 1,
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
        let global_ipv6 = cfg.global_ipv6;
        let dns_ipv6 = cfg.dns_ipv6;
        let ipv6_policy = Arc::new(AtomicBool::new(global_ipv6));
        let edns_client_subnet = cfg.edns_client_subnet.clone();
        let health = Arc::new(DnsHealthTracker::default());
        // Created before DIRECT so both resolvers share one recovery gate.
        let parent_transport_failed = Arc::new(AtomicBool::new(false));
        let parent_resets_in_progress = Arc::new(AtomicUsize::new(0));
        let parent_published = Arc::new(AtomicBool::new(true));
        let default_resolver = Arc::new(EnhancedResolver {
            ipv6: ipv6_policy.clone(),
            dns_ipv6,
            health: health.clone(),
            hosts: None,
            main: make_clients(
                cfg.default_nameserver.clone(),
                None,
                Some(Arc::new(
                    crate::app::dns::execution::LiteralOnlyResolver::default(),
                )),
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
            network_positive_cache: Mutex::new(None),
            negative_cache: Mutex::new(lru_time_cache::LruCache::with_capacity(
                1024,
            )),
            provider_epoch_cache: Mutex::new(
                lru_time_cache::LruCache::with_capacity(
                    PROVIDER_EPOCH_CACHE_CAPACITY,
                ),
            ),
            policy: None,
            policy_is_parent_shared: false,

            proxy_resolver: None,
            proxy_server_nameserver_policy: Vec::new(),
            proxy_node_resolver: false,
            proxy_server_domains: None,
            provider_proxy_server_domains: RwLock::new(Default::default()),
            provider_dns_epoch: AtomicU64::new(0),
            provider_epoch_network_generation: AtomicU64::new(0),
            transport_resets_in_progress: Arc::new(AtomicUsize::new(0)),
            transport_reset_failed: Arc::new(AtomicBool::new(false)),
            retired: AtomicBool::new(false),
            published: Arc::new(AtomicBool::new(true)),
            parent_published: None,
            parent_transport_failed: None,
            parent_resets_in_progress: None,
            transport_reset_lock: tokio::sync::Mutex::new(()),
            provider_domain_generations: RwLock::new(Default::default()),
            direct_resolver: None,

            fake_dns: None,
            fake_ip_ttl: 1,
            safe_srv: false,

            reverse_lookup_cache: None,
        });

        let proxy_resolver = if let Some(proxy_nameserver) =
            cfg.proxy_server_nameserver
        {
            let clients = make_clients(
                proxy_nameserver,
                Some(default_resolver.clone()),
                Some(default_resolver.clone()),
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
                // No dedicated bootstrap clients must never be silently
                // interpreted as permission to use general DNS. In ordinary
                // YAML conversion an empty list is rejected earlier, but
                // internal configs/reloads can still construct Some(empty).
                return Err(Error::InvalidConfig(
                    "dns.proxy-server-nameserver was explicitly configured but has no usable clients; refusing DNS bootstrap fallback"
                        .to_owned(),
                ));
            }
            Some(clients)
        } else {
            None
        };

        if !cfg.proxy_server_nameserver_policy.is_empty() && proxy_resolver.is_none()
        {
            return Err(Error::InvalidConfig(
                "dns.proxy-server-nameserver-policy requires non-empty dns.proxy-server-nameserver"
                    .to_owned(),
            ));
        }

        // The node DNS resolver must not use the general nameserver path
        // when a per-node policy matches. Keep YAML order when compiling
        // domain matchers so the first applicable policy wins.
        let mut proxy_server_nameserver_policy = Vec::new();
        for (domain, servers) in &cfg.proxy_server_nameserver_policy {
            // Internal callers can bypass YAML decoding/validation. A
            // selector that cannot match is a privacy-sensitive error: do
            // not silently fall back from the requested per-node DNS pool.
            let lower = domain.to_ascii_lowercase();
            if domain.contains(',')
                || lower.starts_with("geosite:")
                || lower.starts_with("rule-set:")
                || !crate::app::dns::config::valid_nameserver_policy_domain(domain)
            {
                return Err(Error::InvalidConfig(format!(
                    "dns.proxy-server-nameserver-policy invalid domain selector: {domain}"
                )));
            }
            if servers.iter().any(|server| server.proxy.is_some()) {
                return Err(Error::InvalidConfig(format!(
                    "dns.proxy-server-nameserver-policy for {domain} cannot use #proxy: recursive bootstrap dialer is unsupported"
                )));
            }
            let clients = make_clients(
                servers.clone(),
                Some(default_resolver.clone()),
                Some(default_resolver.clone()),
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
                return Err(Error::InvalidConfig(format!(
                    "dns.proxy-server-nameserver-policy for {domain} has no usable clients"
                )));
            }
            let mut matcher = trie::StringTrie::new();
            if !matcher.insert(&lower, Arc::new(true)) {
                return Err(Error::InvalidConfig(format!(
                    "dns.proxy-server-nameserver-policy unmatchable domain selector: {domain}"
                )));
            }
            proxy_server_nameserver_policy.push((Arc::new(matcher), clients));
        }

        let outbound_resolver: Arc<dyn ClashResolver> = proxy_resolver
            .as_ref()
            .map(|clients| {
                let mut resolver = Self::from_clients_with_ipv6_policy(
                    clients.clone(),
                    None,
                    ipv6_policy.clone(),
                    dns_ipv6,
                );
                resolver.proxy_node_resolver = true;
                resolver.proxy_server_nameserver_policy =
                    proxy_server_nameserver_policy.clone();
                Arc::new(resolver) as Arc<dyn ClashResolver>
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

        let policy = if !cfg.nameserver_policy.is_empty() {
            let mut p = trie::StringTrie::new();
            for (domain, ns) in &cfg.nameserver_policy {
                // Internal reload/config constructors need the same privacy
                // validation as YAML conversion. Invalid entries must not
                // silently miss the trie and send QNAMEs to main DNS.
                let lower = domain.to_ascii_lowercase();
                if domain.contains(',')
                    || lower.starts_with("geosite:")
                    || lower.starts_with("rule-set:")
                    || !crate::app::dns::config::valid_nameserver_policy_domain(
                        domain,
                    )
                {
                    return Err(Error::InvalidConfig(format!(
                        "dns.nameserver-policy invalid domain selector: {domain}"
                    )));
                }
                let clients = make_clients(
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
                .await?;
                if clients.is_empty() || !p.insert(&lower, Arc::new(clients)) {
                    return Err(Error::InvalidConfig(format!(
                        "dns.nameserver-policy has no usable clients or unmatchable selector: {domain}"
                    )));
                }
            }
            Some(Arc::new(p))
        } else {
            None
        };

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
            Some(Arc::new(
                Self::direct_with_optional_ipv6_policy(
                    clients,
                    main.clone(),
                    ipv6_policy.clone(),
                    dns_ipv6,
                    cfg.direct_nameserver_follow_policy,
                    policy.clone(),
                )
                .with_parent_transport_gate(
                    Arc::clone(&parent_transport_failed),
                    Arc::clone(&parent_resets_in_progress),
                )
                .with_parent_publication_gate(Arc::clone(&parent_published)),
            ) as ThreadSafeDNSResolver)
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
                    domains.insert(&server.to_ascii_lowercase(), Arc::new(true));
                    debug!("added proxy server domain: {}", server);
                }
                Some(domains)
            } else {
                None
            };
        drop(plain_outbounds);

        Ok(Self {
            ipv6: ipv6_policy,
            dns_ipv6,
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
            provider_epoch_cache: Mutex::new(
                lru_time_cache::LruCache::with_capacity(
                    PROVIDER_EPOCH_CACHE_CAPACITY,
                ),
            ),
            network_positive_cache: Mutex::new(None),
            lru_cache: Some(hickory_resolver::ResponseCache::new(
                4096,
                hickory_resolver::TtlConfig::default(),
            )),
            policy,
            policy_is_parent_shared: false,
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
                    })?
                    .with_filter_mode(cfg.fake_ip_filter_mode),
                ))),
                DNSMode::RedirHost => {
                    warn!(
                        "dns redir-host is not supported and will not do anything"
                    );
                    None
                }
                _ => None,
            },

            fake_ip_ttl: cfg.fake_ip_ttl.max(1),
            safe_srv: cfg.service_discovery_mode
                == crate::config::def::DnsServiceDiscoveryMode::Safe,

            proxy_resolver,
            proxy_server_nameserver_policy,
            proxy_node_resolver: false,
            proxy_server_domains: proxy_server_domains_trie,
            provider_proxy_server_domains: RwLock::new(Default::default()),
            provider_dns_epoch: AtomicU64::new(0),
            provider_epoch_network_generation: AtomicU64::new(0),
            transport_resets_in_progress: Arc::clone(&parent_resets_in_progress),
            transport_reset_failed: Arc::clone(&parent_transport_failed),
            retired: AtomicBool::new(false),
            published: Arc::clone(&parent_published),
            parent_published: None,
            parent_transport_failed: None,
            parent_resets_in_progress: None,
            transport_reset_lock: tokio::sync::Mutex::new(()),
            provider_domain_generations: RwLock::new(Default::default()),
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

    async fn reject_mixed_proxy_node_questions(
        &self,
        message: &op::Message,
    ) -> anyhow::Result<()> {
        // A provider can register a node after the preflight but before the
        // first-question upstream decision. When a dedicated node DNS pool
        // exists, reject all multi-question packets: they cannot be safely
        // classified atomically against the mutable provider registry.
        // The dedicated bootstrap transport resolver also selects policy by
        // the first QNAME, despite not having a proxy_resolver pool.
        // Standard single-question DNS and ordinary deployments without
        // either dedicated node resolver retain their existing behavior.
        if message.queries.len() > 1
            && (self.proxy_resolver.is_some() || self.proxy_node_resolver)
        {
            return Err(anyhow!(
                "multi-question DNS packet is unsupported with dedicated node DNS"
            ));
        }
        Ok(())
    }

    // Recheck after a public cache hit: provider registration may occur after
    // the initial registry lookup but before the cached answer is returned.
    #[cfg(test)]
    async fn revalidate_public_cache_hit(
        &self,
        message: &op::Message,
        cached: op::Message,
    ) -> anyhow::Result<op::Message> {
        let domain = Self::domain_name_of_message(message);
        let generation = match domain {
            Some(ref domain) => self.provider_domain_generation(domain).await,
            None => 0,
        };
        self.revalidate_public_cache_hit_with_generation(message, cached, generation)
            .await
    }

    async fn revalidate_public_cache_hit_with_generation(
        &self,
        message: &op::Message,
        cached: op::Message,
        selected_generation: u64,
    ) -> anyhow::Result<op::Message> {
        // A provider can register and disappear after a public cache entry
        // was selected. Checking current ownership alone misses this ABA.
        if let Some(domain) = Self::domain_name_of_message(message)
            && self.provider_domain_generation(&domain).await != selected_generation
        {
            return Err(anyhow!(
                "proxy provider DNS ownership changed during public cache hit"
            ));
        }
        if self.proxy_resolver.is_some()
            && let Some(domain) = Self::domain_name_of_message(message)
            && self.is_registered_provider_domain(&domain).await
        {
            // A provider can be removed and re-added while this dedicated
            // lookup is in flight. Cache reclassification must enforce the
            // same generation check as the regular node-query path.
            let generation = self.provider_domain_generation(&domain).await;
            let result = self
                .exchange_no_cache_with_policy(message, false, true)
                .await;
            if self.provider_domain_generation(&domain).await != generation
                || !self.is_registered_provider_domain(&domain).await
            {
                return Err(anyhow!(
                    "proxy provider DNS ownership changed during cached query"
                ));
            }
            return result;
        }
        // Static endpoints do not have a mutable provider generation, but
        // they still must never return a public cache candidate.
        if self.proxy_resolver.is_some()
            && let Some(domain) = Self::domain_name_of_message(message)
            && self
                .proxy_server_domains
                .as_ref()
                .is_some_and(|static_domains| {
                    static_domains
                        .search(&domain.to_ascii_lowercase())
                        .is_some()
                })
        {
            return self
                .exchange_no_cache_with_policy(message, false, false)
                .await;
        }
        Ok(cached)
    }

    fn ensure_not_retired(&self) -> anyhow::Result<()> {
        if self.retired.load(std::sync::atomic::Ordering::SeqCst) {
            anyhow::bail!("DNS resolver owner permanently retired");
        }
        if !self.published.load(std::sync::atomic::Ordering::SeqCst)
            || self.parent_published.as_ref().is_some_and(|parent| {
                !parent.load(std::sync::atomic::Ordering::SeqCst)
            })
        {
            anyhow::bail!("DNS resolver policy not yet published by owner");
        }
        Ok(())
    }

    fn ensure_parent_transport_open(&self) -> anyhow::Result<()> {
        self.ensure_not_retired()?;
        if self
            .parent_transport_failed
            .as_ref()
            .is_some_and(|gate| gate.load(std::sync::atomic::Ordering::SeqCst))
            || self
                .parent_resets_in_progress
                .as_ref()
                .is_some_and(|pending| {
                    pending.load(std::sync::atomic::Ordering::SeqCst) != 0
                })
        {
            return Err(anyhow!(
                "DIRECT DNS owner has not completed transport recovery"
            ));
        }
        Ok(())
    }

    // Recheck immediately before every upstream dispatch. Preflight and
    // return-time validation alone can reject an answer too late: the QNAME
    // may already have escaped on an invalidated transport after an await.
    fn ensure_transport_dispatch_ready(&self) -> anyhow::Result<()> {
        self.ensure_parent_transport_open()?;
        if self
            .transport_resets_in_progress
            .load(std::sync::atomic::Ordering::SeqCst)
            != 0
        {
            return Err(anyhow!("DNS transport reset in progress"));
        }
        if self
            .transport_reset_failed
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(anyhow!(
                "DNS transport reset failed; retry reset before querying"
            ));
        }
        Ok(())
    }

    async fn batch_exchange_if_transport_usable(
        &self,
        clients: &Vec<ThreadSafeDNSClient>,
        message: &op::Message,
    ) -> anyhow::Result<op::Message> {
        self.ensure_transport_dispatch_ready()?;
        Self::batch_exchange(clients, message).await
    }

    async fn exchange(&self, message: &op::Message) -> anyhow::Result<op::Message> {
        self.ensure_transport_dispatch_ready()?;
        let result = self.exchange_inner(message).await;
        self.ensure_transport_dispatch_ready()?;
        result
    }

    #[instrument(skip_all, level = "trace")]
    async fn exchange_inner(
        &self,
        message: &op::Message,
    ) -> anyhow::Result<op::Message> {
        let q = message
            .queries
            .first()
            .ok_or_else(|| anyhow!("invalid query"))?;

        if self
            .transport_resets_in_progress
            .load(std::sync::atomic::Ordering::SeqCst)
            != 0
        {
            return Err(anyhow!("DNS transport reset in progress"));
        }
        if self
            .transport_reset_failed
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(anyhow!(
                "DNS transport reset failed; retry reset before querying"
            ));
        }
        self.reject_mixed_proxy_node_questions(message).await?;

        // Capture before classifying: a registry update anywhere during a node
        // lookup invalidates the response, including remove/re-add ABA.
        let provider_generation =
            self.provider_domain_generation(&q.name().to_ascii()).await;
        let network_generation_at_entry =
            self.provider_epoch_network_generation.load(Relaxed);

        // Provider refreshes can introduce a node hostname previously cached
        // from ordinary DNS. Isolate all record types, including TXT/SRV,
        // from the generic cache and DNS upstream.
        let provider_node_query = self.proxy_resolver.is_some()
            && self
                .is_registered_provider_domain(&q.name().to_ascii())
                .await;
        let static_node_query = self.proxy_resolver.is_some()
            && self
                .proxy_server_domains
                .as_ref()
                .is_some_and(|static_domains| {
                    Self::domain_name_of_message(message).is_some_and(|domain| {
                        // Match the normalized, trailing-dot-free QNAME used
                        // by the actual node DNS dispatch path. Otherwise
                        // a static node can be misclassified as ordinary DNS
                        // during cache bypass and final network-epoch checks.
                        static_domains
                            .search(&domain.to_ascii_lowercase())
                            .is_some()
                    })
                });

        trace!(q = q.to_string(), "start");
        // A prior Provider ownership transition invalidates *all* public
        // cache entries for this QNAME. Hickory's cache has no per-key purge
        // API or ownership provenance; continuing to read it after an ABA
        // would resurrect answers cached before the Provider was registered.
        // Keep ordinary never-owned domains cached; former node domains may
        // still resolve publicly after removal, but without shared caching.
        // Hickory's positive ResponseCache has no public clear API or network
        // epoch in its key. After a transport reset, never consult the old
        // cache: doing so can return an address learned on the prior network.
        // Fail closed on cache reuse until the resolver is reconstructed.
        let public_cache_eligible = !provider_node_query
            && !static_node_query
            && provider_generation == 0
            && network_generation_at_entry == 0;
        // The same bounded cache also holds safe negative answers for
        // never-owned domains after a network reset. Before the first reset,
        // ordinary negative answers continue using the legacy cache. A new
        // negative answer must take precedence over an older positive entry;
        // positive commits explicitly evict the corresponding negative.
        if !provider_node_query
            && !static_node_query
            && (provider_generation != 0 || network_generation_at_entry != 0)
            && Self::cache_safe_request(message)
            && self.lru_cache.is_some()
            && let Some(cached) = self.cached_provider_epoch_response(
                q,
                message,
                provider_generation,
                Instant::now(),
            )
        {
            trace!(q = q.to_string(), "provider epoch DNS cache hit");
            #[cfg(test)]
            Self::pause_selected_cache_candidate_for_test(
                if cached.metadata.response_code == op::ResponseCode::NXDomain {
                    CacheCandidateKind::Negative
                } else {
                    CacheCandidateKind::Positive
                },
            )
            .await;
            let reply = self
                .revalidate_public_cache_hit_with_generation(
                    message,
                    cached,
                    provider_generation,
                )
                .await?;
            if self.provider_epoch_network_generation.load(Relaxed)
                != network_generation_at_entry
            {
                return Err(anyhow!(
                    "network path changed during former-provider DNS cache delivery"
                ));
            }
            return Ok(reply);
        }
        // The legacy Hickory cache is unversioned. New network epochs use a
        // separate cache that is replaced lazily under the reset commit lock.
        if !provider_node_query
            && !static_node_query
            && provider_generation == 0
            && network_generation_at_entry != 0
            && Self::cache_safe_request(message)
            && self.lru_cache.is_some()
        {
            let cached = {
                let candidate = self
                    .network_positive_cache
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                candidate
                    .as_ref()
                    .filter(|(epoch, _)| *epoch == network_generation_at_entry)
                    .and_then(|(_, cache)| cache.get(q, Instant::now()))
                    .and_then(Result::ok)
            };
            if let Some(mut cached) = cached {
                #[cfg(test)]
                Self::pause_selected_cache_candidate_for_test(
                    CacheCandidateKind::Positive,
                )
                .await;
                cached.metadata.id = message.metadata.id;
                cached.metadata.recursion_desired =
                    message.metadata.recursion_desired;
                cached.metadata.checking_disabled =
                    message.metadata.checking_disabled;
                cached.queries = message.queries.clone();
                let answer = self
                    .revalidate_public_cache_hit_with_generation(
                        message,
                        cached,
                        provider_generation,
                    )
                    .await?;
                if self.provider_epoch_network_generation.load(Relaxed)
                    != network_generation_at_entry
                {
                    return Err(anyhow!(
                        "network path changed during positive DNS cache hit"
                    ));
                }
                return Ok(answer);
            }
        }
        if public_cache_eligible
            && Self::cache_safe_request(message)
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
            #[cfg(test)]
            Self::pause_selected_cache_candidate_for_test(
                CacheCandidateKind::Positive,
            )
            .await;
            return self
                .revalidate_public_cache_hit_with_generation(
                    message,
                    cached,
                    provider_generation,
                )
                .await;
        }
        if public_cache_eligible
            && Self::cache_safe_request(message)
            && self.lru_cache.is_some()
            && let Some(cached) = self.cached_negative(q, message, Instant::now())
        {
            trace!(q = q.to_string(), "negative DNS cache hit");
            #[cfg(test)]
            Self::pause_selected_cache_candidate_for_test(
                CacheCandidateKind::Negative,
            )
            .await;
            return self
                .revalidate_public_cache_hit_with_generation(
                    message,
                    cached,
                    provider_generation,
                )
                .await;
        }
        trace!(q = q.to_string(), "querying resolver");
        #[cfg(test)]
        if let Ok(pause) = PUBLIC_HANDOFF_TEST_PAUSE.try_with(Clone::clone) {
            pause.selected.wait().await;
            pause.resume.wait().await;
        }
        // The internal no-cache path takes its own generation snapshot.
        // A provider can register and unregister between the entry snapshot
        // and that second snapshot (ABA), otherwise laundering an obsolete
        // public lookup into the shared cache. Reject before dispatch.
        if !provider_node_query
            && !static_node_query
            && self.proxy_resolver.is_some()
            && self.provider_domain_generation(&q.name().to_ascii()).await
                != provider_generation
        {
            return Err(anyhow!(
                "proxy provider DNS ownership changed before public query dispatch"
            ));
        }
        let mut internal_used_dedicated_node_dns = false;
        let res = self
            .exchange_no_cache_with_policy_and_generation(
                message,
                !provider_node_query && !static_node_query,
                provider_node_query,
                Some(provider_generation),
                Some(&mut internal_used_dedicated_node_dns),
            )
            .await
            .map(|mut r| {
                if let Some(edns) = r.edns.as_mut() {
                    // Remove only padding options, keep everything else
                    edns.options_mut().remove(rr::rdata::opt::EdnsCode::Padding);
                }
                r
            });
        #[cfg(test)]
        if let Ok(pause) = PUBLIC_RETURN_TEST_PAUSE.try_with(Clone::clone) {
            pause.selected.wait().await;
            pause.resume.wait().await;
        }
        // Active provider/static proxy endpoints are network-path scoped as
        // well as provider-generation scoped. Even a still-registered node
        // must not return an old transport's address after a reset.
        if self.provider_epoch_network_generation.load(Relaxed)
            != network_generation_at_entry
        {
            return Err(anyhow!(
                "network path changed during dedicated proxy node DNS query"
            ));
        }

        // Revalidate public results after the internal cache commit too: an
        // ownership transition can occur after the internal generation guard
        // is released but before exchange hands the answer to its caller.
        if !provider_node_query
            && !static_node_query
            && self.proxy_resolver.is_some()
            && self.provider_domain_generation(&q.name().to_ascii()).await
                != provider_generation
        {
            // A newly registered node may already have been reclassified by
            // the internal resolver. Never return the possibly public result;
            // resolve through the dedicated node pool with a fresh ownership
            // snapshot instead. A completed ABA with no owner fails closed.
            let domain = q.name().to_ascii();
            if !self.is_registered_provider_domain(&domain).await {
                return Err(anyhow!(
                    "proxy provider DNS ownership changed before public answer return"
                ));
            }
            let generation = self.provider_domain_generation(&domain).await;
            // The internal query may already have reclassified the in-flight
            // public request through the dedicated node pool. Its provenance
            // is explicit; do not send a second bootstrap DNS query.
            let node_result = if internal_used_dedicated_node_dns {
                res
            } else {
                self.exchange_no_cache_with_policy_and_generation(
                    message,
                    false,
                    true,
                    Some(generation),
                    None,
                )
                .await
            };
            if self.provider_domain_generation(&domain).await != generation
                || !self.is_registered_provider_domain(&domain).await
            {
                return Err(anyhow!(
                    "proxy provider DNS ownership changed during return reclassification"
                ));
            }
            if self.provider_epoch_network_generation.load(Relaxed)
                != network_generation_at_entry
            {
                return Err(anyhow!(
                    "network path changed during proxy node DNS reclassification"
                ));
            }
            return node_result;
        }
        // A provider may be removed while its dedicated DNS request is in
        // flight. Do not return an answer for a node that is no longer owned
        // by the provider registry. Fail closed rather than silently retrying
        // through public DNS after a node-specific lookup.
        if provider_node_query
            && (self.provider_domain_generation(&q.name().to_ascii()).await
                != provider_generation
                || !self
                    .is_registered_provider_domain(&q.name().to_ascii())
                    .await)
        {
            return Err(anyhow!(
                "proxy provider DNS ownership changed during query"
            ));
        }
        trace!(q = q.to_string(), "query completed");
        res
    }

    #[cfg(test)]
    async fn exchange_no_cache(
        &self,
        message: &op::Message,
    ) -> anyhow::Result<op::Message> {
        self.exchange_no_cache_with_policy(message, true, false)
            .await
    }

    async fn exchange_no_cache_with_policy(
        &self,
        message: &op::Message,
        populate_shared_cache: bool,
        provider_node_snapshot: bool,
    ) -> anyhow::Result<op::Message> {
        self.exchange_no_cache_with_policy_and_generation(
            message,
            populate_shared_cache,
            provider_node_snapshot,
            None,
            None,
        )
        .await
    }

    async fn exchange_no_cache_with_policy_and_generation(
        &self,
        message: &op::Message,
        populate_shared_cache: bool,
        provider_node_snapshot: bool,
        entry_generation: Option<u64>,
        mut dedicated_source: Option<&mut bool>,
    ) -> anyhow::Result<op::Message> {
        // This internal entry point can be called without the public exchange
        // preflight. Never select a bootstrap policy from only the first QNAME.
        self.reject_mixed_proxy_node_questions(message).await?;
        let q = message
            .queries
            .first()
            .ok_or_else(|| anyhow!("invalid query"))?;

        let query_network_generation =
            self.provider_epoch_network_generation.load(Relaxed);
        #[cfg(test)]
        if let Ok(pause) = INTERNAL_HANDOFF_TEST_PAUSE.try_with(Clone::clone) {
            pause.selected.wait().await;
            pause.resume.wait().await;
        }
        // Carry the entry snapshot across the async internal handoff. A
        // fresh snapshot here alone would miss an ABA between these calls.
        if let (Some(expected), Some(domain)) =
            (entry_generation, Self::domain_name_of_message(message))
            && self.provider_domain_generation(&domain).await != expected
        {
            return Err(anyhow!(
                "proxy provider DNS ownership changed during internal handoff"
            ));
        }
        // A provider may register and unregister the same hostname while a
        // public lookup is in flight. Checking current ownership alone misses
        // this ABA transition and can return/cache an obsolete public answer.
        let public_generation =
            if self.proxy_resolver.is_some() && !provider_node_snapshot {
                if let Some(expected) = entry_generation {
                    Some(expected)
                } else if let Some(domain) = Self::domain_name_of_message(message) {
                    Some(self.provider_domain_generation(&domain).await)
                } else {
                    None
                }
            } else {
                None
            };
        let mut used_dedicated_node_dns = false;
        let rv = if EnhancedResolver::is_ip_request(q) {
            self.ip_exchange_with_provider_snapshot_and_source(
                message,
                provider_node_snapshot,
                &mut used_dedicated_node_dns,
            )
            .await
        } else if self.proxy_resolver.is_some()
            && let Some(domain) = EnhancedResolver::domain_name_of_message(message)
            && (provider_node_snapshot
                || self.is_registered_provider_domain(&domain).await
                || self.proxy_server_domains.as_ref().is_some_and(
                    |static_domains| {
                        static_domains
                            .search(&domain.to_ascii_lowercase())
                            .is_some()
                    },
                ))
        {
            // Static and dynamic proxy endpoints must both use dedicated
            // bootstrap DNS for TXT/SRV and other non-address questions.
            // Never let a static endpoint's QNAME escape to generic DNS.
            used_dedicated_node_dns = true;
            if let Some((_, clients)) = self
                .proxy_server_nameserver_policy
                .iter()
                .find(|(matcher, _)| {
                    matcher.search(&domain.to_ascii_lowercase()).is_some()
                })
            {
                self.batch_exchange_if_transport_usable(clients, message)
                    .await
            } else {
                self.batch_exchange_if_transport_usable(
                    self.proxy_resolver.as_ref().expect("checked above"),
                    message,
                )
                .await
            }
        } else if self.proxy_node_resolver {
            // Non-address bootstrap questions must honor the same dedicated
            // node policy as A/AAAA. Never route them via generic DNS policy.
            if let Some(domain) = EnhancedResolver::domain_name_of_message(message) {
                if let Some((_, clients)) = self
                    .proxy_server_nameserver_policy
                    .iter()
                    .find(|(matcher, _)| {
                        matcher.search(&domain.to_ascii_lowercase()).is_some()
                    })
                {
                    self.batch_exchange_if_transport_usable(clients, message)
                        .await
                } else {
                    self.batch_exchange_if_transport_usable(&self.main, message)
                        .await
                }
            } else {
                self.batch_exchange_if_transport_usable(&self.main, message)
                    .await
            }
        } else if let Some(matched) = self.match_policy(message) {
            self.batch_exchange_if_transport_usable(matched, message)
                .await
        } else {
            self.batch_exchange_if_transport_usable(&self.main, message)
                .await
        };

        if let Some(source) = dedicated_source.as_deref_mut() {
            *source = used_dedicated_node_dns;
        }
        if !used_dedicated_node_dns
            && public_generation.is_some_and(|generation| generation != 0)
            && self.provider_epoch_network_generation.load(Relaxed)
                != query_network_generation
        {
            return Err(anyhow!(
                "network path changed during former-provider public DNS lookup"
            ));
        }

        // Provider registration can happen while a public DNS request is in
        // flight. A response from that request is no longer authorized for
        // the newly protected hostname: discard it and retry via the
        // dedicated bootstrap resolver. Do not populate shared caches with
        // the obsolete public response.
        if !used_dedicated_node_dns
            && self.proxy_resolver.is_some()
            && let Some(domain) = Self::domain_name_of_message(message)
            && self.is_registered_provider_domain(&domain).await
        {
            let dedicated_result =
                Box::pin(self.exchange_no_cache_with_policy(message, false, true))
                    .await;
            if let Some(source) = dedicated_source {
                *source = true;
            }
            return dedicated_result;
        }

        if !used_dedicated_node_dns
            && let (Some(generation), Some(domain)) =
                (public_generation, Self::domain_name_of_message(message))
            && self.provider_domain_generation(&domain).await != generation
        {
            return Err(anyhow!(
                "proxy provider DNS ownership changed during public query"
            ));
        }

        #[cfg(test)]
        if let Ok(pause) = PUBLIC_CACHE_WRITE_TEST_PAUSE.try_with(Clone::clone) {
            pause.selected.wait().await;
            pause.resume.wait().await;
        }

        // Hold the generation read guard through both positive and negative
        // cache writes. Provider updates take the corresponding write guard
        // before committing a new ownership generation, so a late ABA cannot
        // slip between validation and insertion. No await while held.
        let generation_guard = if public_generation.is_some() {
            Some(self.provider_domain_generations.read().await)
        } else {
            None
        };
        if let (Some(expected), Some(generations), Some(domain)) = (
            public_generation,
            generation_guard.as_ref(),
            Self::domain_name_of_message(message),
        ) && *generations
            .get(&domain.trim_end_matches('.').to_ascii_lowercase())
            .unwrap_or(&0)
            != expected
        {
            return Err(anyhow!(
                "proxy provider DNS ownership changed before cache commit"
            ));
        }

        if self.provider_epoch_network_generation.load(Relaxed)
            != query_network_generation
        {
            return Err(anyhow!(
                "network path changed before former-provider DNS cache commit"
            ));
        }

        // The bounded, generation-tagged cache serves former Provider names
        // and, after the first network reset, SOA-validated ordinary negative
        // answers. Positive ordinary answers use network_positive_cache.
        // Keep the existing pre-reset legacy negative cache unchanged.
        if populate_shared_cache
            && !used_dedicated_node_dns
            && Self::cache_safe_request(message)
            && self.lru_cache.is_some()
            && let Ok(msg) = &rv
            && (public_generation.is_some_and(|generation| generation != 0)
                || (query_network_generation != 0
                    && Self::negative_ttl(q, msg).is_some()))
        {
            self.cache_provider_epoch_response_for_network(
                q,
                msg,
                public_generation.unwrap_or(0),
                Instant::now(),
                Some(query_network_generation),
            );
        }

        // Live provider ownership can change after the initial cache bypass
        // decision. Never insert a dedicated node answer into shared generic
        // DNS caches, even if the domain has since been removed.
        // Responses for a name ever owned by a proxy Provider cannot be
        // safely entered in a cache keyed only by DNS Question; later ABA
        // changes have no way to revoke those entries. With a dedicated
        // resolver pool, a nonzero per-domain generation marks that history.
        let populate_shared_cache = populate_shared_cache
            && !used_dedicated_node_dns
            && public_generation.is_none_or(|generation| generation == 0)
            // Never repopulate an unversioned cache after a network reset:
            // a later query could otherwise confuse old and new entries.
            && query_network_generation == 0;

        // The unversioned caches must not accept an old-network response
        // between the epoch check and insertion. Reset holds this same lock
        // while advancing the epoch and clearing negative entries.
        let mut network_commit_guard = self
            .provider_epoch_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.provider_epoch_network_generation.load(Relaxed)
            != query_network_generation
        {
            return Err(anyhow!(
                "network path changed before public DNS cache commit"
            ));
        }
        if populate_shared_cache
            && let Ok(msg) = &rv
            && Self::cache_safe_request(message)
            && self.lru_cache.is_some()
        {
            self.cache_negative(q, msg, Instant::now());
        }

        if populate_shared_cache
            && let Ok(msg) = &rv
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

        if query_network_generation != 0
            && !used_dedicated_node_dns
            && public_generation.is_none_or(|generation| generation == 0)
            && Self::cache_safe_request(message)
            && self.lru_cache.is_some()
            && let Ok(msg) = &rv
            && Self::cache_safe_response(msg)
            && !(q.query_type() == rr::RecordType::TXT
                && q.name().to_ascii().starts_with("_acme-challenge."))
            && {
                let ips = EnhancedResolver::ip_list_of_message(msg);
                ips.is_empty() || ips.iter().any(|ip| !ip.is_unspecified())
            }
        {
            // After a reset, normal negative entries share the generation-
            // tagged cache with former Provider domains. Invalidate only a
            // normal (generation zero) negative on a fresh positive answer.
            // Hold the same commit lock across invalidation and insertion so
            // a network reset cannot interleave and resurrect old NXDOMAIN.
            let negative_key = Self::negative_cache_key(q);
            if network_commit_guard
                .peek(&negative_key)
                .is_some_and(|entry| entry.generation == 0)
            {
                network_commit_guard.remove(&negative_key);
            }
            let mut cache = self
                .network_positive_cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if cache
                .as_ref()
                .is_none_or(|(epoch, _)| *epoch != query_network_generation)
            {
                *cache = Some((
                    query_network_generation,
                    hickory_resolver::ResponseCache::new(
                        4096,
                        hickory_resolver::TtlConfig::default(),
                    ),
                ));
            }
            if let Some((_, entries)) = cache.as_ref() {
                entries.insert(q.clone(), Ok(msg.clone()), Instant::now());
            }
        }
        drop(network_commit_guard);
        if self.provider_epoch_network_generation.load(Relaxed)
            != query_network_generation
        {
            return Err(anyhow!(
                "network path changed during former-provider DNS query"
            ));
        }

        rv
    }

    fn match_policy(&self, m: &op::Message) -> Option<&Vec<ThreadSafeDNSClient>> {
        if let (Some(policy), Some(domain)) =
            (&self.policy, EnhancedResolver::domain_name_of_message(m))
        {
            // DNS owner names are case-insensitive; bypassing the policy on
            // mixed-case labels could send QNAMEs to an unintended upstream.
            return policy
                .search(&domain.to_ascii_lowercase())
                .map(|n| n.get_data().unwrap());
        }
        None
    }

    async fn provider_domain_generation(&self, domain: &str) -> u64 {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        *self
            .provider_domain_generations
            .read()
            .await
            .get(&domain)
            .unwrap_or(&0)
    }

    async fn is_registered_provider_domain(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        self.provider_proxy_server_domains
            .read()
            .await
            .values()
            .any(|domains| domains.contains(&domain))
    }

    #[cfg(test)]
    async fn ip_exchange(
        &self,
        message: &op::Message,
    ) -> anyhow::Result<op::Message> {
        self.ip_exchange_with_provider_snapshot(message, false)
            .await
    }

    #[cfg(test)]
    async fn ip_exchange_with_provider_snapshot(
        &self,
        message: &op::Message,
        provider_node_snapshot: bool,
    ) -> anyhow::Result<op::Message> {
        let mut used_dedicated_node_dns = false;
        self.ip_exchange_with_provider_snapshot_and_source(
            message,
            provider_node_snapshot,
            &mut used_dedicated_node_dns,
        )
        .await
    }

    #[instrument(skip_all, level = "trace")]
    async fn ip_exchange_with_provider_snapshot_and_source(
        &self,
        message: &op::Message,
        provider_node_snapshot: bool,
        used_dedicated_node_dns: &mut bool,
    ) -> anyhow::Result<op::Message> {
        self.reject_mixed_proxy_node_questions(message).await?;
        if self.proxy_node_resolver {
            // This resolver is the transport's dedicated proxy node DNS
            // bootstrap context. It must not go through generic main DNS.
            if let Some(domain) = EnhancedResolver::domain_name_of_message(message) {
                for (matcher, clients) in &self.proxy_server_nameserver_policy {
                    if matcher.search(&domain.to_ascii_lowercase()).is_some() {
                        return self
                            .batch_exchange_if_transport_usable(clients, message)
                            .await;
                    }
                }
            }
            return self
                .batch_exchange_if_transport_usable(&self.main, message)
                .await;
        }

        // Static proxy node domains do not change within this resolver and
        // retain their historical shared-cache behavior. Dynamic provider
        // domains can be added/removed between awaits, so only those require
        // a cache-isolated answer role.
        let live_provider_domain = if self.proxy_resolver.is_none() {
            // Most ordinary DNS queries have no configured dedicated node
            // pool. They must never acquire the provider registry lock.
            false
        } else if provider_node_snapshot {
            true
        } else if let Some(domain) =
            EnhancedResolver::domain_name_of_message(message)
        {
            self.is_registered_provider_domain(&domain).await
        } else {
            false
        };
        if let Some(proxy_resolver) = &self.proxy_resolver
            && let Some(domain) = EnhancedResolver::domain_name_of_message(message)
            && (live_provider_domain
                || self.proxy_server_domains.as_ref().is_some_and(
                    |static_domains| {
                        static_domains
                            .search(&domain.to_ascii_lowercase())
                            .is_some()
                    },
                ))
        {
            *used_dedicated_node_dns = true;
            debug!(
                "using proxy-server-nameserver for proxy server domain: {}",
                domain
            );
            for (matcher, clients) in &self.proxy_server_nameserver_policy {
                if matcher.search(&domain.to_ascii_lowercase()).is_some() {
                    debug!(
                        "using proxy-server-nameserver-policy for proxy domain: {}",
                        domain
                    );
                    return self
                        .batch_exchange_if_transport_usable(clients, message)
                        .await;
                }
            }
            return self
                .batch_exchange_if_transport_usable(proxy_resolver, message)
                .await;
        }

        if let Some(matched) = self.match_policy(message) {
            return self
                .batch_exchange_if_transport_usable(matched, message)
                .await;
        }

        if self.should_only_query_fallback(message) {
            return self
                .batch_exchange_if_transport_usable(
                    self.fallback.as_ref().unwrap(),
                    message,
                )
                .await;
        }

        let main_query =
            self.batch_exchange_if_transport_usable(&self.main, message);

        if self.fallback.is_none() {
            return main_query.await;
        }

        let fallback_query = self.batch_exchange_if_transport_usable(
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
        self.ensure_not_retired()?;
        if let Some(ip) = parse_ip_literal(host) {
            if ip.is_ipv6() && !self.ipv6.load(Relaxed) {
                return Err(Error::DNSError(format!(
                    "IPv6 is disabled; cannot resolve IPv6 literal `{host}`"
                ))
                .into());
            }
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
            false => match self.resolve_v4(host, enhanced).await {
                Ok(Some(ip)) => Ok(Some(net::IpAddr::V4(ip))),
                Ok(None) => Err(Error::DNSError(format!(
                    "IPv6 is disabled and hostname `{host}` has no IPv4 address"
                ))
                .into()),
                Err(error) => {
                    let detail = error.to_string();
                    let message = if detail.contains("NODATA")
                        || detail.contains("NXDomain")
                    {
                        format!(
                            "IPv6 is disabled and hostname `{host}` has no IPv4 address: {detail}"
                        )
                    } else {
                        format!(
                            "IPv6 is disabled; IPv4 lookup for hostname `{host}` failed: {detail}"
                        )
                    };
                    Err(Error::DNSError(message).into())
                }
            },
        }
    }

    async fn resolve_all(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Vec<net::IpAddr>> {
        self.ensure_not_retired()?;
        if let Some(ip) = parse_ip_literal(host) {
            if ip.is_ipv6() && !self.ipv6.load(Relaxed) {
                return Err(Error::DNSError(format!(
                    "IPv6 is disabled; cannot resolve IPv6 literal `{host}`"
                ))
                .into());
            }
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
            let no_ipv4_record = !ipv6_enabled
                && errors.iter().any(|error| {
                    error.starts_with("A: ")
                        && (error.contains("NODATA") || error.contains("NXDomain"))
                });
            return Err(if errors.is_empty() {
                if ipv6_enabled {
                    anyhow!("no record for hostname: {host}")
                } else {
                    Error::DNSError(format!(
                        "IPv6 is disabled and hostname `{host}` has no IPv4 address"
                    ))
                    .into()
                }
            } else if no_ipv4_record {
                Error::DNSError(format!(
                    "IPv6 is disabled and hostname `{host}` has no IPv4 address: {}",
                    errors.join("; ")
                ))
                .into()
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
        self.ensure_not_retired()?;
        if let Some(ip) = parse_ip_literal(host) {
            return match ip {
                net::IpAddr::V4(ip) => Ok(Some(ip)),
                net::IpAddr::V6(_) if !self.ipv6.load(Relaxed) => {
                    Err(Error::DNSError(format!(
                        "IPv6 is disabled; cannot resolve IPv6 literal `{host}`"
                    ))
                    .into())
                }
                net::IpAddr::V6(_) => Ok(None),
            };
        }

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

        if enhanced && self.fake_ip_enabled() {
            let mut fake_dns = self.fake_dns.as_ref().unwrap().write().await;
            if !fake_dns.should_skip(host) {
                let ip = fake_dns.lookup(host).await;
                self.ensure_not_retired()?;
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
            Ok(result) => {
                Ok(result.choose(&mut rand::rng()).and_then(|ip| match ip {
                    net::IpAddr::V4(v4) => Some(*v4),
                    _ => None,
                }))
            }
            Err(e) => Err(e),
        }
    }

    #[instrument(skip(self), level = "trace")]
    async fn resolve_v6(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<net::Ipv6Addr>> {
        self.ensure_not_retired()?;
        if !self.ipv6.load(Relaxed) {
            return Err(Error::DNSError("IPv6 is disabled".into()).into());
        }
        if let Some(ip) = parse_ip_literal(host) {
            return Ok(match ip {
                net::IpAddr::V6(ip) => Some(ip),
                net::IpAddr::V4(_) => None,
            });
        }

        if enhanced
            && let Some(hosts) = &self.hosts
            && let Some(v) = hosts.search(host)
        {
            return Ok(v.get_data().and_then(|v| match v {
                net::IpAddr::V6(v6) => Some(*v6),
                net::IpAddr::V4(_) => None,
            }));
        }

        match self.lookup_ip(host, rr::RecordType::AAAA).await {
            Ok(result) => {
                Ok(result.choose(&mut rand::rng()).and_then(|ip| match ip {
                    net::IpAddr::V6(v6) => Some(*v6),
                    _ => None,
                }))
            }

            Err(e) => Err(e),
        }
    }

    #[instrument(skip(self))]
    async fn cached_for(&self, ip: net::IpAddr) -> Option<String> {
        // Reverse lookups can influence routing just like forward replies.
        // Never expose a stale DIRECT mapping while its owner is invalid.
        if self.ensure_parent_transport_open().is_err() {
            return None;
        }
        if let Some(lru) = &self.reverse_lookup_cache
            && let Some(cached) = lru.read().await.peek(&ip)
        {
            if self.ensure_parent_transport_open().is_err() {
                return None;
            }
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
        // The trait API may await the reverse-IP cache *after* the inherent
        // resolver has already checked its parent gate. Revalidate before
        // handing the answer to an independent DIRECT resolver caller.
        self.ensure_parent_transport_open()?;
        Ok(rv)
    }

    fn ipv6(&self) -> bool {
        self.ipv6.load(Relaxed)
    }

    fn dns_ipv6(&self) -> bool {
        self.dns_ipv6
    }

    fn set_ipv6(&self, enable: bool) {
        self.ipv6.store(enable, Relaxed);
    }

    fn invalidate_transports(&self) {
        self.transport_reset_failed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(direct_resolver) = &self.direct_resolver {
            direct_resolver.invalidate_transports();
        }
    }

    fn permits_background_egress(&self) -> bool {
        self.ensure_transport_dispatch_ready().is_ok()
    }

    fn pause_publication(&self) {
        self.published
            .store(false, std::sync::atomic::Ordering::SeqCst);
        if let Some(direct_resolver) = &self.direct_resolver {
            direct_resolver.pause_publication();
        }
    }

    fn publish(&self) {
        // A late commit must never revive an owner already retired.
        if !self.retired.load(std::sync::atomic::Ordering::SeqCst) {
            self.published
                .store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(direct_resolver) = &self.direct_resolver {
                direct_resolver.publish();
            }
        }
    }

    fn retire(&self) {
        self.retired
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.published
            .store(false, std::sync::atomic::Ordering::SeqCst);
        self.invalidate_transports();
        if let Some(direct_resolver) = &self.direct_resolver {
            direct_resolver.retire();
        }
    }

    async fn reset_transports(&self) -> anyhow::Result<u32> {
        self.ensure_not_retired()?;
        self.transport_resets_in_progress
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        // Drop also runs on cancellation or timeout; never leave the gate stuck.
        let _reset_guard = TransportResetGuard(&self.transport_resets_in_progress);
        // Invalidate the parent and DIRECT child before waiting for the lock:
        // a cancelled queued reset may never poll the child reset future.
        self.transport_reset_failed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(direct_resolver) = &self.direct_resolver {
            direct_resolver.invalidate_transports();
        }
        let _serial_reset = self.transport_reset_lock.lock().await;
        self.ensure_not_retired()?;
        self.transport_reset_failed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.health.invalidate();
        // Coordinate the epoch transition and negative-cache flush with
        // generic cache writers. Lock order: epoch cache -> negative cache.
        {
            let mut entries = self
                .provider_epoch_cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            self.provider_epoch_network_generation.fetch_add(1, Relaxed);
            // Drop the old network's positive answers at the epoch boundary,
            // even if no subsequent query arrives to replace this cache.
            *self
                .network_positive_cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
            self.negative_cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clear();
            entries.clear();
        }
        let mut clients = self.main.clone();
        if let Some(fallback) = &self.fallback {
            clients.extend(fallback.iter().cloned());
        }
        if let Some(proxy_resolver) = &self.proxy_resolver {
            clients.extend(proxy_resolver.iter().cloned());
        }
        for (_, policy_clients) in &self.proxy_server_nameserver_policy {
            clients.extend(policy_clients.iter().cloned());
        }
        if !self.policy_is_parent_shared
            && let Some(policy) = &self.policy
        {
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
            self.ensure_not_retired()?;
            self.transport_reset_failed
                .store(false, std::sync::atomic::Ordering::SeqCst);
            // An owner can retire while the final reset future completes.
            // The retired gate remains authoritative regardless of a stale
            // reset clearing the transient failure flag.
            self.ensure_not_retired()?;
            Ok(reset)
        } else {
            self.transport_reset_failed
                .store(true, std::sync::atomic::Ordering::SeqCst);
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

    fn fake_ip_ttl(&self) -> u32 {
        self.fake_ip_ttl.max(1)
    }

    fn safe_srv_enabled(&self) -> bool {
        self.safe_srv
    }

    async fn should_fake_ip(&self, host: &str) -> bool {
        if self.ensure_not_retired().is_err() {
            return false;
        }
        let Some(pool) = &self.fake_dns else {
            return false;
        };
        let allowed = !pool.read().await.should_skip(host);
        self.ensure_not_retired().is_ok() && allowed
    }

    fn direct_resolver(&self) -> Option<ThreadSafeDNSResolver> {
        self.direct_resolver.clone()
    }

    async fn replace_proxy_provider_dns_domains(
        &self,
        provider: &str,
        domains: Vec<String>,
    ) -> anyhow::Result<()> {
        // Provider node hostnames are loaded *after* the static proxy trie is
        // built. Register their exact DNS names so they cannot silently use
        // generic main/fallback DNS when dedicated node DNS exists.
        let domains: std::collections::HashSet<String> = domains
            .into_iter()
            .map(|host| match url::Host::parse(&host) {
                Ok(url::Host::Domain(domain))
                    if !domain.trim_end_matches('.').is_empty() =>
                {
                    // WHATWG URL host parsing normalizes IDNA to its ASCII
                    // wire name. A lowercase-only comparison would otherwise
                    // let Unicode provider endpoints fall through to main DNS.
                    Ok(Some(domain.trim_end_matches('.').to_ascii_lowercase()))
                }
                Ok(url::Host::Ipv4(_) | url::Host::Ipv6(_)) => Ok(None),
                _ => Err(anyhow!("invalid proxy provider DNS endpoint hostname")),
            })
            .collect::<anyhow::Result<Vec<Option<String>>>>()?
            .into_iter()
            .flatten()
            .collect();
        let mut providers = self.provider_proxy_server_domains.write().await;
        let previous = providers.get(provider).cloned().unwrap_or_default();
        if previous != domains {
            let mut generations = self.provider_domain_generations.write().await;
            let generation = self.provider_dns_epoch.fetch_add(1, Relaxed) + 1;
            for domain in previous.symmetric_difference(&domains) {
                // A provider update changes the DNS ownership generation only
                // when the domain enters or leaves the union of all providers.
                // Other owners must not lose in-flight bootstrap responses.
                let was_owned =
                    providers.values().any(|names| names.contains(domain));
                let still_owned_by_others = providers
                    .iter()
                    .any(|(name, names)| name != provider && names.contains(domain));
                let will_be_owned =
                    domains.contains(domain) || still_owned_by_others;
                if was_owned != will_be_owned {
                    generations.insert(domain.clone(), generation);
                }
            }
            if domains.is_empty() {
                providers.remove(provider);
            } else {
                providers.insert(provider.to_owned(), domains);
            }
        }
        Ok(())
    }

    async fn is_fake_ip(&self, ip: std::net::IpAddr) -> bool {
        if self.ensure_not_retired().is_err() || !self.fake_ip_enabled() {
            return false;
        }

        let mut fake_dns = self.fake_dns.as_ref().unwrap().write().await;
        let result = fake_dns.is_fake_ip(ip).await;
        self.ensure_not_retired().is_ok() && result
    }

    async fn reverse_lookup(&self, ip: net::IpAddr) -> Option<String> {
        debug!("reverse lookup: {}", ip);
        if self.ensure_not_retired().is_err() || !self.fake_ip_enabled() {
            return None;
        }

        let mut fake_dns = self.fake_dns.as_ref().unwrap().write().await;
        let result = fake_dns.reverse_lookup(ip).await;
        self.ensure_not_retired().ok()?;
        result
    }

    async fn fake_ip_for_host(&self, host: &str) -> Option<net::IpAddr> {
        if self.ensure_not_retired().is_err() || !self.fake_ip_enabled() {
            return None;
        }

        let mut fake_dns = self.fake_dns.as_ref().unwrap().write().await;
        let result = fake_dns.lookup_existing(host).await;
        self.ensure_not_retired().ok()?;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CACHE_CANDIDATE_TEST_PAUSE, CacheCandidateKind, CacheCandidateTestPause,
        PROVIDER_EPOCH_CACHE_CAPACITY, PROVIDER_EPOCH_CACHE_MAX_TTL,
    };
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
            atomic::{AtomicBool, AtomicUsize, Ordering},
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

    #[test]
    fn nested_resolvers_follow_global_ipv6_toggle() {
        let ipv6_policy = Arc::new(AtomicBool::new(true));
        let resolver = EnhancedResolver::from_clients_with_ipv6_policy(
            vec![],
            None,
            ipv6_policy.clone(),
            false,
        );
        let bootstrap = EnhancedResolver::from_clients_with_ipv6_policy(
            vec![],
            None,
            ipv6_policy,
            false,
        );

        assert!(bootstrap.ipv6());
        resolver.set_ipv6(false);
        assert!(!bootstrap.ipv6());
    }

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
    struct PausedClient {
        response: op::Message,
        entered: Arc<tokio::sync::Notify>,
        resume: Arc<tokio::sync::Notify>,
    }

    #[async_trait]
    impl crate::app::dns::Client for PausedClient {
        fn id(&self) -> String {
            "paused-public-dns".into()
        }
        async fn exchange(&self, _msg: &op::Message) -> anyhow::Result<op::Message> {
            self.entered.notify_one();
            self.resume.notified().await;
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
        let bytes_read =
            tokio::time::timeout(Duration::from_secs(3), client.read(&mut byte))
                .await
                .expect(
                    "duplex peer did not close after the missing reverse-index flow",
                )
                .unwrap();
        assert_eq!(bytes_read, 0);

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
    async fn retired_owner_must_not_return_old_fake_ip_mapping() {
        let mut resolver = EnhancedResolver::from_clients(vec![], false);
        resolver.fake_dns = Some(Arc::new(RwLock::new(
            crate::app::dns::fakeip::FakeDns::new(crate::app::dns::fakeip::Opts {
                ipnet: "198.18.0.0/30".parse().unwrap(),
                skipped_hostnames: None,
                store: Box::new(crate::app::dns::fakeip::InMemStore::new(2)),
            })
            .unwrap(),
        )));
        let host = "retired-fake.example";
        let ip: Ipv4Addr = "198.18.0.2".parse().unwrap();
        assert_eq!(resolver.resolve_v4(host, true).await.unwrap(), Some(ip));
        assert_eq!(
            resolver.fake_ip_for_host(host).await,
            Some(std::net::IpAddr::V4(ip))
        );
        resolver.retire();
        assert!(
            resolver.resolve_v4(host, true).await.is_err(),
            "old runtime must not synthesize a stale fake-IP after retirement"
        );
        assert!(resolver.fake_ip_for_host(host).await.is_none());
        assert!(resolver.reverse_lookup(ip.into()).await.is_none());
        assert!(!resolver.should_fake_ip(host).await);
    }

    #[tokio::test]
    async fn retirement_while_fake_ip_pool_is_locked_must_not_return_old_mapping() {
        let mut resolver = EnhancedResolver::from_clients(vec![], false);
        resolver.fake_dns = Some(Arc::new(RwLock::new(
            crate::app::dns::fakeip::FakeDns::new(crate::app::dns::fakeip::Opts {
                ipnet: "198.18.0.0/30".parse().unwrap(),
                skipped_hostnames: None,
                store: Box::new(crate::app::dns::fakeip::InMemStore::new(2)),
            })
            .unwrap(),
        )));
        let pool = resolver.fake_dns.as_ref().unwrap().clone();
        let owner = Arc::new(resolver);
        let held = pool.write().await;
        let running = {
            let owner = owner.clone();
            tokio::spawn(async move {
                owner
                    .resolve_v4("queued-before-retirement.example", true)
                    .await
            })
        };
        // The task is blocked on the pool lock; retirement must remain
        // effective when it later resumes, not just at initial preflight.
        tokio::task::yield_now().await;
        owner.retire();
        drop(held);
        let result = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .expect("fake-IP lookup stalled")
            .expect("fake-IP task panicked");
        assert!(
            result.is_err(),
            "retired resolver returned a fake-IP: {result:?}"
        );
        assert!(
            owner
                .fake_ip_for_host("queued-before-retirement.example")
                .await
                .is_none(),
            "retired owner must not disclose even a newly allocated stale mapping"
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
    async fn mihomo_whitelist_only_protects_selected_domains_from_real_dns() {
        use crate::config::def::FakeIpFilterMode;

        let hits = Arc::new(AtomicUsize::new(0));
        let client = Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(203, 0, 113, 44)),
            hits: hits.clone(),
            id: "observed-upstream",
        });
        let mut filter = crate::common::trie::StringTrie::new();
        filter.insert("*.protected.example", Arc::new(true));
        let mut resolver = EnhancedResolver::from_clients(vec![client], false);
        resolver.fake_dns = Some(Arc::new(RwLock::new(
            crate::app::dns::fakeip::FakeDns::new(crate::app::dns::fakeip::Opts {
                ipnet: "198.18.0.0/30".parse().unwrap(),
                skipped_hostnames: Some(filter),
                store: Box::new(crate::app::dns::fakeip::InMemStore::new(2)),
            })
            .unwrap()
            .with_filter_mode(FakeIpFilterMode::Whitelist),
        )));

        assert!(resolver.should_fake_ip("api.protected.example").await);
        assert!(!resolver.should_fake_ip("unlisted.example").await);

        assert_eq!(
            resolver
                .resolve_v4("api.protected.example", true)
                .await
                .unwrap(),
            Some(Ipv4Addr::new(198, 18, 0, 2)),
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "whitelisted domain must not be resolved upstream"
        );
        assert!(
            resolver
                .fake_ip_for_host("api.protected.example")
                .await
                .is_some()
        );

        assert_eq!(
            resolver.resolve_v4("unlisted.example", true).await.unwrap(),
            Some(Ipv4Addr::new(203, 0, 113, 44)),
        );
        assert!(
            hits.load(Ordering::SeqCst) > 0,
            "unlisted domain must use the real resolver"
        );
        assert!(
            resolver
                .fake_ip_for_host("unlisted.example")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn hosts_with_other_address_family_return_no_result() {
        let mut hosts = crate::common::trie::StringTrie::new();
        hosts.insert("v6-only.test", Arc::new("2001:db8::1".parse().unwrap()));
        hosts.insert("v4-only.test", Arc::new("192.0.2.1".parse().unwrap()));
        let mut resolver = EnhancedResolver::from_clients(vec![], true);
        resolver.hosts = Some(hosts);
        assert_eq!(
            resolver.resolve_v4("v6-only.test", true).await.unwrap(),
            None
        );
        assert_eq!(
            resolver.resolve_v6("v4-only.test", true).await.unwrap(),
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
    async fn ipv4_only_hostname_without_a_record_has_clear_disabled_ipv6_error() {
        let resolver = EnhancedResolver::from_clients(
            vec![Arc::new(FixedClient {
                response: op::Message::response(0, op::OpCode::Query),
            })],
            false,
        );
        let error = resolver
            .resolve("ipv4only.example", false)
            .await
            .expect_err("hostname without A record must report the IPv6 policy");
        let message = error.to_string();
        assert!(message.contains("IPv6 is disabled"), "{message}");
        assert!(message.contains("no IPv4 address"), "{message}");

        let error = resolver
            .resolve_all("ipv4only.example", false)
            .await
            .expect_err("resolve_all must report the same policy");
        let message = error.to_string();
        assert!(message.contains("IPv6 is disabled"), "{message}");
        assert!(message.contains("no IPv4 address"), "{message}");
    }

    #[tokio::test]
    async fn ipv6_literal_is_rejected_when_disabled() {
        let resolver = EnhancedResolver::from_clients(Vec::new(), false);
        let error = resolver
            .resolve("2001:db8::1", false)
            .await
            .expect_err("IPv6 literal must not bypass the global setting");
        assert!(error.to_string().contains("IPv6 is disabled"));
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
    async fn direct_nameserver_follow_policy_routes_only_matching_domain() {
        let policy_hits = Arc::new(AtomicUsize::new(0));
        let direct_hits = Arc::new(AtomicUsize::new(0));
        let general_hits = Arc::new(AtomicUsize::new(0));
        let mut matcher = crate::common::trie::StringTrie::new();
        matcher.insert(
            "proxy.example.com",
            Arc::new(vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 90)),
                hits: policy_hits.clone(),
                id: "private-policy",
            }) as ThreadSafeDNSClient]),
        );
        let policy = Some(Arc::new(matcher));
        let mk_direct = || {
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 91)),
                hits: direct_hits.clone(),
                id: "direct-nameserver",
            }) as ThreadSafeDNSClient]
        };
        let mk_general = || {
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 92)),
                hits: general_hits.clone(),
                id: "general-nameserver",
            }) as ThreadSafeDNSClient]
        };

        let with_follow = EnhancedResolver::direct_with_optional_policy(
            mk_direct(),
            mk_general(),
            false,
            true,
            policy.clone(),
        );
        assert_eq!(
            with_follow
                .resolve_v4("proxy.example.com", false)
                .await
                .unwrap(),
            Some(Ipv4Addr::new(192, 0, 2, 90)),
        );
        assert_eq!(policy_hits.load(Ordering::SeqCst), 1);
        assert_eq!(direct_hits.load(Ordering::SeqCst), 0);
        assert_eq!(general_hits.load(Ordering::SeqCst), 0);

        assert_eq!(
            with_follow
                .resolve_v4("other.example.com", false)
                .await
                .unwrap(),
            Some(Ipv4Addr::new(192, 0, 2, 91)),
        );
        assert_eq!(direct_hits.load(Ordering::SeqCst), 1);
        assert_eq!(general_hits.load(Ordering::SeqCst), 0);

        let without_follow = EnhancedResolver::direct_with_optional_policy(
            mk_direct(),
            mk_general(),
            false,
            false,
            policy,
        );
        assert_eq!(
            without_follow
                .resolve_v4("proxy.example.com", false)
                .await
                .unwrap(),
            Some(Ipv4Addr::new(192, 0, 2, 91)),
        );
        assert_eq!(policy_hits.load(Ordering::SeqCst), 1);
        assert_eq!(direct_hits.load(Ordering::SeqCst), 2);
        assert_eq!(general_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn direct_follow_policy_failure_never_falls_back_to_default_dns() {
        let direct_hits = Arc::new(AtomicUsize::new(0));
        let general_hits = Arc::new(AtomicUsize::new(0));
        let mut matcher = crate::common::trie::StringTrie::new();
        matcher.insert(
            "proxy.example.com",
            Arc::new(vec![Arc::new(FailingClient {
                id: "private-policy",
                reason: "private upstream offline",
            }) as ThreadSafeDNSClient]),
        );
        let resolver = EnhancedResolver::direct_with_optional_policy(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 91)),
                hits: direct_hits.clone(),
                id: "direct-nameserver",
            })],
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 92)),
                hits: general_hits.clone(),
                id: "general-nameserver",
            })],
            false,
            true,
            Some(Arc::new(matcher)),
        );
        let failure = resolver
            .resolve_v4("proxy.example.com", false)
            .await
            .unwrap_err();
        assert!(failure.to_string().contains("private upstream offline"));
        assert_eq!(direct_hits.load(Ordering::SeqCst), 0);
        assert_eq!(general_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn direct_follow_policy_does_not_fallback_on_unmatched_direct_failure() {
        let general_hits = Arc::new(AtomicUsize::new(0));
        let resolver = EnhancedResolver::direct_with_optional_policy(
            vec![Arc::new(FailingClient {
                id: "direct-upstream",
                reason: "direct upstream unreachable",
            })],
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 92)),
                hits: general_hits.clone(),
                id: "main-dns",
            })],
            false,
            true,
            None,
        );
        let error = resolver
            .resolve_v4("other.example.com", false)
            .await
            .expect_err("opted-in DIRECT policy must not leak QNAME into main DNS");
        assert!(
            error.to_string().contains("direct upstream unreachable"),
            "{error}"
        );
        assert_eq!(general_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn shared_direct_policy_does_not_reset_transport_twice() {
        let resets = Arc::new(AtomicUsize::new(0));
        let mut primary = EnhancedResolver::from_clients(vec![], false);
        let mut policy = crate::common::trie::StringTrie::new();
        policy.insert(
            "protected.example",
            Arc::new(vec![Arc::new(ResetCountingClient {
                resets: resets.clone(),
            }) as ThreadSafeDNSClient]),
        );
        let shared_policy = Arc::new(policy);
        primary.policy = Some(shared_policy.clone());
        let direct = EnhancedResolver::direct_with_optional_policy(
            vec![],
            vec![],
            false,
            true,
            Some(shared_policy),
        );
        primary.direct_resolver = Some(Arc::new(direct));

        assert_eq!(primary.reset_transports().await.unwrap(), 1);
        assert_eq!(resets.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn direct_child_reset_failure_keeps_parent_closed_until_child_recovers() {
        // A successful parent transport reset must not reopen queries when the
        // DIRECT child still owns a partially reset upstream collection.
        #[derive(Debug)]
        struct RecoverableClient {
            fail_reset: Arc<std::sync::atomic::AtomicBool>,
            exchanges: Arc<AtomicUsize>,
        }
        #[async_trait]
        impl crate::app::dns::Client for RecoverableClient {
            fn id(&self) -> String {
                "recoverable-direct-child".to_owned()
            }
            async fn exchange(
                &self,
                _: &op::Message,
            ) -> anyhow::Result<op::Message> {
                self.exchanges.fetch_add(1, Ordering::SeqCst);
                Ok(response_with_a(Ipv4Addr::new(192, 0, 2, 55)))
            }
            async fn reset_transport(&self) -> anyhow::Result<u32> {
                if self.fail_reset.load(Ordering::SeqCst) {
                    Err(anyhow::anyhow!("injected DIRECT reset failure"))
                } else {
                    Ok(1)
                }
            }
        }
        let fail_reset = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let parent_exchanges = Arc::new(AtomicUsize::new(0));
        let child_exchanges = Arc::new(AtomicUsize::new(0));
        let mut parent = EnhancedResolver::from_clients(
            vec![Arc::new(RecoverableClient {
                fail_reset: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                exchanges: parent_exchanges.clone(),
            })],
            false,
        );
        let child = EnhancedResolver::from_clients(
            vec![Arc::new(RecoverableClient {
                fail_reset: fail_reset.clone(),
                exchanges: child_exchanges.clone(),
            })],
            false,
        );
        parent.direct_resolver = Some(Arc::new(child));
        let (request, _) = test_query();
        let error = parent
            .reset_transports()
            .await
            .expect_err("DIRECT reset must fail");
        assert!(error.to_string().contains("injected DIRECT reset failure"));
        assert!(
            parent.exchange(&request).await.is_err(),
            "parent must fail closed"
        );
        assert!(
            parent
                .direct_resolver
                .as_ref()
                .unwrap()
                .exchange(&request)
                .await
                .is_err(),
            "DIRECT child must fail closed"
        );
        assert_eq!(parent_exchanges.load(Ordering::SeqCst), 0);
        assert_eq!(child_exchanges.load(Ordering::SeqCst), 0);

        fail_reset.store(false, Ordering::SeqCst);
        assert_eq!(parent.reset_transports().await.unwrap(), 2);
        parent.exchange(&request).await.unwrap();
        parent
            .direct_resolver
            .as_ref()
            .unwrap()
            .exchange(&request)
            .await
            .unwrap();
        assert_eq!(parent_exchanges.load(Ordering::SeqCst), 1);
        assert_eq!(child_exchanges.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn independent_direct_recovery_must_not_reopen_failed_parent() {
        // A DIRECT child may be independently reset while its parent has a
        // failed reset. Its recovery must not clear the parent's fail-closed
        // state or let the parent's main upstream receive a query.
        let parent_hits = Arc::new(AtomicUsize::new(0));
        let child_hits = Arc::new(AtomicUsize::new(0));
        let mut parent = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 70)),
                hits: parent_hits.clone(),
                id: "parent-upstream",
            })],
            false,
        );
        parent.direct_resolver = Some(Arc::new(EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 71)),
                hits: child_hits.clone(),
                id: "direct-upstream",
            })],
            false,
        )));
        parent.invalidate_transports();
        let (request, _) = test_query();
        let direct = parent.direct_resolver.as_ref().unwrap();
        assert!(parent.exchange(&request).await.is_err());
        assert!(direct.exchange(&request).await.is_err());
        assert_eq!(direct.reset_transports().await.unwrap(), 0);
        assert!(
            parent.exchange(&request).await.is_err(),
            "child-only recovery must not reopen the failed parent"
        );
        assert_eq!(parent_hits.load(Ordering::SeqCst), 0);
        // This is deliberately not a guarantee that an independently held
        // child handle remains closed: parent ownership is not shared yet.
        assert_eq!(parent.reset_transports().await.unwrap(), 0);
        parent.exchange(&request).await.unwrap();
        assert_eq!(parent_hits.load(Ordering::SeqCst), 1);
        assert_eq!(child_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn independent_direct_recovery_cannot_escape_failed_parent_gate() {
        // A DIRECT resolver may be handed to the dispatcher independently.
        // It must remain closed while its parent owns a failed reset, even
        // when the child itself has successfully reset its transports.
        let parent_hits = Arc::new(AtomicUsize::new(0));
        let child_hits = Arc::new(AtomicUsize::new(0));
        let mut parent = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 70)),
                hits: parent_hits.clone(),
                id: "parent-upstream",
            })],
            false,
        );
        let child = Arc::new(
            EnhancedResolver::from_clients(
                vec![Arc::new(CountingClient {
                    response: response_with_a(Ipv4Addr::new(192, 0, 2, 71)),
                    hits: child_hits.clone(),
                    id: "direct-upstream",
                })],
                false,
            )
            .with_parent_transport_gate(
                Arc::clone(&parent.transport_reset_failed),
                Arc::clone(&parent.transport_resets_in_progress),
            ),
        );
        parent.direct_resolver = Some(child.clone());
        parent.invalidate_transports();
        let (request, _) = test_query();
        assert!(parent.exchange(&request).await.is_err());
        assert!(child.exchange(&request).await.is_err());
        assert_eq!(child.reset_transports().await.unwrap(), 0);
        assert!(
            child.exchange(&request).await.is_err(),
            "independent DIRECT reset must not bypass parent fail-closed ownership"
        );
        assert_eq!(child_hits.load(Ordering::SeqCst), 0);
        assert_eq!(parent.reset_transports().await.unwrap(), 0);
        child.exchange(&request).await.unwrap();
        assert_eq!(child_hits.load(Ordering::SeqCst), 1);
        assert_eq!(parent_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn parent_invalidation_during_inflight_direct_query_rejects_old_answer() {
        // The DIRECT owner can fail while an upstream query is in flight.
        // No response from the old transport may leave the child afterwards.
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let mut parent = EnhancedResolver::from_clients(vec![], false);
        let child = Arc::new(
            EnhancedResolver::from_clients(
                vec![Arc::new(PausedClient {
                    response: response_with_a(Ipv4Addr::new(192, 0, 2, 73)),
                    entered: entered.clone(),
                    resume: release.clone(),
                })],
                false,
            )
            .with_parent_transport_gate(
                Arc::clone(&parent.transport_reset_failed),
                Arc::clone(&parent.transport_resets_in_progress),
            ),
        );
        parent.direct_resolver = Some(child.clone());
        let (request, _) = test_query();
        let pending = {
            let child = child.clone();
            let request = request.clone();
            tokio::spawn(async move { child.exchange(&request).await })
        };
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .expect("DIRECT query did not start");
        parent.invalidate_transports();
        release.notify_one();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), pending)
                .await
                .unwrap()
                .unwrap()
                .is_err(),
            "in-flight DIRECT DNS response must not escape parent invalidation"
        );
        assert!(
            child.exchange(&request).await.is_err(),
            "DIRECT must remain closed until parent reset completes"
        );
        assert_eq!(parent.reset_transports().await.unwrap(), 0);
        release.notify_one();
        // Transport reset succeeds; the child gate is no longer owned by a
        // failed parent. Do not require a second upstream query here because
        // PausedClient intentionally pauses all its exchanges.
        assert!(!parent.transport_reset_failed.load(Ordering::SeqCst));
        assert!(
            !child
                .parent_transport_failed
                .as_ref()
                .unwrap()
                .load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn direct_resolve_v4_cannot_bypass_parent_failure_via_independent_reset() {
        let direct_hits = Arc::new(AtomicUsize::new(0));
        let mut parent = EnhancedResolver::from_clients(vec![], false);
        let child = Arc::new(
            EnhancedResolver::from_clients(
                vec![Arc::new(CountingClient {
                    response: response_with_a(Ipv4Addr::new(192, 0, 2, 74)),
                    hits: direct_hits.clone(),
                    id: "direct-v4-upstream",
                })],
                false,
            )
            .with_parent_transport_gate(
                Arc::clone(&parent.transport_reset_failed),
                Arc::clone(&parent.transport_resets_in_progress),
            ),
        );
        parent.direct_resolver = Some(child);
        let direct_handle = parent.direct_resolver().unwrap();
        parent.invalidate_transports();
        direct_handle.reset_transports().await.unwrap();
        assert!(
            direct_handle
                .resolve_v4("proxy.example.com", false)
                .await
                .is_err(),
            "independently held DIRECT resolver handle must honor parent gate"
        );
        assert_eq!(direct_hits.load(Ordering::SeqCst), 0);
        parent.reset_transports().await.unwrap();
        assert_eq!(
            direct_handle
                .resolve_v4("proxy.example.com", false)
                .await
                .unwrap(),
            Some(Ipv4Addr::new(192, 0, 2, 74))
        );
        assert_eq!(direct_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn parent_failure_during_direct_reverse_cache_write_rejects_stale_reply() {
        // The trait's exchange() does extra async reverse-IP caching after
        // the inherent exchange() has returned. A reset in this second await
        // must still suppress delivery of the old-network DNS answer.
        let hits = Arc::new(AtomicUsize::new(0));
        let mut parent = EnhancedResolver::from_clients(vec![], false);
        let mut child = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 76)),
                hits: hits.clone(),
                id: "direct-reverse-write",
            })],
            false,
        );
        let reverse =
            Arc::new(RwLock::new(lru_time_cache::LruCache::with_capacity(16)));
        child.reverse_lookup_cache = Some(reverse.clone());
        let child = Arc::new(child.with_parent_transport_gate(
            Arc::clone(&parent.transport_reset_failed),
            Arc::clone(&parent.transport_resets_in_progress),
        ));
        parent.direct_resolver = Some(child.clone());
        let held_reverse_writer = reverse.write().await;
        let (request, _) = test_query();
        let mut running = {
            let child = child.clone();
            tokio::spawn(async move {
                ClashResolver::exchange(child.as_ref(), &request).await
            })
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut running)
                .await
                .is_err(),
            "DIRECT response should wait for reverse cache lock"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "the upstream must have responded before owner invalidation"
        );
        parent.invalidate_transports();
        drop(held_reverse_writer);
        let result = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.is_err(),
            "DIRECT trait exchange must revalidate parent after reverse caching"
        );
    }

    #[tokio::test]
    async fn direct_reverse_cache_must_not_expose_old_mapping_during_parent_failure()
    {
        let mut parent = EnhancedResolver::from_clients(vec![], false);
        let mut child = EnhancedResolver::from_clients(vec![], false);
        child.reverse_lookup_cache = Some(Arc::new(RwLock::new(
            lru_time_cache::LruCache::with_capacity(16),
        )));
        let child = Arc::new(child.with_parent_transport_gate(
            Arc::clone(&parent.transport_reset_failed),
            Arc::clone(&parent.transport_resets_in_progress),
        ));
        parent.direct_resolver = Some(child.clone());
        let ip = std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 76));
        child
            .save_reverse_lookup(ip, "old.network.example".into())
            .await;
        assert_eq!(
            ClashResolver::cached_for(child.as_ref(), ip).await,
            Some("old.network.example".into())
        );
        parent.invalidate_transports();
        assert_eq!(
            ClashResolver::cached_for(child.as_ref(), ip).await,
            None,
            "DIRECT reverse-IP cache must not expose old mappings while parent is closed"
        );
        parent.reset_transports().await.unwrap();
        assert_eq!(
            ClashResolver::cached_for(child.as_ref(), ip).await,
            None,
            "full reset must discard old-network reverse mappings"
        );
    }

    #[tokio::test]
    async fn orphaned_direct_handle_must_not_query_after_owner_is_dropped() {
        // The dispatcher may retain a cloned DIRECT handle after an old
        // resolver instance has been replaced or dropped. Such an orphan
        // must not send DNS using the former owner's network path.
        let hits = Arc::new(AtomicUsize::new(0));
        let direct_handle = {
            let mut parent = EnhancedResolver::from_clients(vec![], false);
            let child = Arc::new(
                EnhancedResolver::from_clients(
                    vec![Arc::new(CountingClient {
                        response: response_with_a(Ipv4Addr::new(192, 0, 2, 77)),
                        hits: hits.clone(),
                        id: "orphaned-direct",
                    })],
                    false,
                )
                .with_parent_transport_gate(
                    Arc::clone(&parent.transport_reset_failed),
                    Arc::clone(&parent.transport_resets_in_progress),
                ),
            );
            parent.direct_resolver = Some(child);
            parent.direct_resolver().unwrap()
        };
        let (request, _) = test_query();
        assert!(
            direct_handle.exchange(&request).await.is_err(),
            "orphaned DIRECT resolver must fail closed after parent Drop"
        );
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        direct_handle.reset_transports().await.unwrap();
        assert!(
            direct_handle
                .resolve_v4("proxy.example.com", false)
                .await
                .is_err(),
            "a child-only reset must never recreate its dropped DNS owner"
        );
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn owner_drop_during_direct_query_rejects_old_dns_response() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let mut parent = EnhancedResolver::from_clients(vec![], false);
        let child = Arc::new(
            EnhancedResolver::from_clients(
                vec![Arc::new(PausedClient {
                    response: response_with_a(Ipv4Addr::new(192, 0, 2, 78)),
                    entered: entered.clone(),
                    resume: release.clone(),
                })],
                false,
            )
            .with_parent_transport_gate(
                Arc::clone(&parent.transport_reset_failed),
                Arc::clone(&parent.transport_resets_in_progress),
            ),
        );
        parent.direct_resolver = Some(child.clone());
        let (request, _) = test_query();
        let running = {
            let child = child.clone();
            tokio::spawn(async move { child.exchange(&request).await })
        };
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .expect("DIRECT query did not start");
        drop(parent);
        release.notify_one();
        let result = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.is_err(),
            "old DNS response must not escape a dropped parent"
        );
    }

    #[tokio::test]
    async fn retained_old_dns_owner_requires_explicit_retirement_on_reload() {
        // A reload manager can retain the old owner through an Arc while
        // publishing a new resolver. Drop alone is insufficient in this case.
        let old_hits = Arc::new(AtomicUsize::new(0));
        let new_hits = Arc::new(AtomicUsize::new(0));
        let mut old_owner = EnhancedResolver::from_clients(vec![], false);
        let old_direct = Arc::new(
            EnhancedResolver::from_clients(
                vec![Arc::new(CountingClient {
                    response: response_with_a(Ipv4Addr::new(192, 0, 2, 82)),
                    hits: old_hits.clone(),
                    id: "retained-old-direct",
                })],
                false,
            )
            .with_parent_transport_gate(
                Arc::clone(&old_owner.transport_reset_failed),
                Arc::clone(&old_owner.transport_resets_in_progress),
            ),
        );
        old_owner.direct_resolver = Some(old_direct.clone());
        let retained_owner = Arc::new(old_owner);
        let new_owner = EnhancedResolver::from_clients(vec![], false);
        let new_direct = Arc::new(
            EnhancedResolver::from_clients(
                vec![Arc::new(CountingClient {
                    response: response_with_a(Ipv4Addr::new(192, 0, 2, 83)),
                    hits: new_hits.clone(),
                    id: "replacement-direct",
                })],
                false,
            )
            .with_parent_transport_gate(
                Arc::clone(&new_owner.transport_reset_failed),
                Arc::clone(&new_owner.transport_resets_in_progress),
            ),
        );
        let (request, _) = test_query();
        old_direct.exchange(&request).await.unwrap();
        // The reload coordinator must retire the old owner explicitly before
        // it publishes the new one; keeping its Arc alive is intentional.
        retained_owner.invalidate_transports();
        assert!(old_direct.exchange(&request).await.is_err());
        old_direct.reset_transports().await.unwrap();
        assert!(old_direct.exchange(&request).await.is_err());
        let answer = new_direct.exchange(&request).await.unwrap();
        assert_eq!(
            EnhancedResolver::ip_list_of_message(&answer),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 83))]
        );
        assert_eq!(old_hits.load(Ordering::SeqCst), 1);
        assert_eq!(new_hits.load(Ordering::SeqCst), 1);
        assert_eq!(Arc::strong_count(&retained_owner), 1);
    }

    #[tokio::test]
    async fn uncommitted_dns_owner_and_direct_child_must_not_query_upstream() {
        let hits = Arc::new(AtomicUsize::new(0));
        let mut owner = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 91)),
                hits: hits.clone(),
                id: "staged-parent",
            })],
            false,
        );
        let direct = Arc::new(
            EnhancedResolver::from_clients(
                vec![Arc::new(CountingClient {
                    response: response_with_a(Ipv4Addr::new(192, 0, 2, 92)),
                    hits: hits.clone(),
                    id: "staged-direct",
                })],
                false,
            )
            .with_parent_transport_gate(
                Arc::clone(&owner.transport_reset_failed),
                Arc::clone(&owner.transport_resets_in_progress),
            ),
        );
        owner.direct_resolver = Some(direct.clone());
        let (request, _) = test_query();

        owner.pause_publication();
        assert!(owner.exchange(&request).await.is_err());
        assert!(direct.exchange(&request).await.is_err());
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        owner.publish();
        assert!(owner.exchange(&request).await.is_ok());
        assert!(direct.exchange(&request).await.is_ok());
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        owner.retire();
        owner.publish();
        assert!(owner.exchange(&request).await.is_err());
        assert!(direct.exchange(&request).await.is_err());
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn direct_child_independent_publish_must_not_bypass_staged_parent() {
        // A retained DIRECT resolver handle must never act as an independent
        // authority to publish DNS policy before its parent runtime commits.
        let hits = Arc::new(AtomicUsize::new(0));
        let mut owner = EnhancedResolver::from_clients(vec![], false);
        let direct = Arc::new(
            EnhancedResolver::from_clients(
                vec![Arc::new(CountingClient {
                    response: response_with_a(Ipv4Addr::new(192, 0, 2, 91)),
                    hits: hits.clone(),
                    id: "staged-direct-independent-publish",
                })],
                false,
            )
            .with_parent_transport_gate(
                Arc::clone(&owner.transport_reset_failed),
                Arc::clone(&owner.transport_resets_in_progress),
            )
            .with_parent_publication_gate(Arc::clone(&owner.published)),
        );
        owner.direct_resolver = Some(direct.clone());
        let (request, _) = test_query();

        owner.pause_publication();
        direct.publish();
        assert!(
            direct.exchange(&request).await.is_err(),
            "DIRECT independently published before owner committed"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "uncommitted DIRECT request must never reach upstream"
        );
        owner.publish();
        assert!(direct.exchange(&request).await.is_ok());
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn parent_pause_during_inflight_direct_query_rejects_old_answer() {
        // An already-dispatched DNS packet cannot be recalled, but a staged
        // owner must not hand that stale answer back to the new runtime.
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let mut owner = EnhancedResolver::from_clients(vec![], false);
        let direct = Arc::new(
            EnhancedResolver::from_clients(
                vec![Arc::new(PausedClient {
                    response: response_with_a(Ipv4Addr::new(192, 0, 2, 93)),
                    entered: entered.clone(),
                    resume: release.clone(),
                })],
                false,
            )
            .with_parent_transport_gate(
                Arc::clone(&owner.transport_reset_failed),
                Arc::clone(&owner.transport_resets_in_progress),
            )
            .with_parent_publication_gate(Arc::clone(&owner.published)),
        );
        owner.direct_resolver = Some(direct.clone());
        let (request, _) = test_query();
        let pending = {
            let direct = direct.clone();
            tokio::spawn(async move { direct.exchange(&request).await })
        };
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .expect("DIRECT query did not enter upstream");
        owner.pause_publication();
        // A separate holder cannot undo the paused owner's authority.
        direct.publish();
        release.notify_one();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), pending)
                .await
                .unwrap()
                .unwrap()
                .is_err(),
            "old DIRECT answer escaped while parent publication was paused"
        );
        owner.publish();
        assert_eq!(
            direct.resolve("127.0.0.1", false).await.unwrap(),
            Some(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
    }

    #[tokio::test]
    async fn retired_dns_owner_cannot_be_reopened_by_old_parent_or_direct_reset() {
        let old_hits = Arc::new(AtomicUsize::new(0));
        let replacement_hits = Arc::new(AtomicUsize::new(0));
        let mut old_owner = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 44)),
                hits: old_hits.clone(),
                id: "retired-parent",
            })],
            false,
        );
        let old_direct = Arc::new(
            EnhancedResolver::from_clients(
                vec![Arc::new(CountingClient {
                    response: response_with_a(Ipv4Addr::new(192, 0, 2, 45)),
                    hits: old_hits.clone(),
                    id: "retired-direct",
                })],
                false,
            )
            .with_parent_transport_gate(
                Arc::clone(&old_owner.transport_reset_failed),
                Arc::clone(&old_owner.transport_resets_in_progress),
            ),
        );
        old_owner.direct_resolver = Some(old_direct.clone());
        let old_owner = Arc::new(old_owner);
        let replacement = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 46)),
                hits: replacement_hits.clone(),
                id: "replacement",
            })],
            false,
        );
        let (request, _) = test_query();
        old_owner.exchange(&request).await.unwrap();
        old_direct.exchange(&request).await.unwrap();

        // Retain both old Arc handles as if a user connection outlived reload.
        old_owner.retire();
        assert!(old_owner.exchange(&request).await.is_err());
        assert!(old_direct.exchange(&request).await.is_err());
        assert!(
            old_owner.reset_transports().await.is_err(),
            "retired owner must not recover with a new network reset"
        );
        assert!(
            old_direct.reset_transports().await.is_err(),
            "retired DIRECT handle must not recover separately"
        );
        assert!(old_owner.exchange(&request).await.is_err());
        assert!(old_direct.exchange(&request).await.is_err());
        assert_eq!(old_hits.load(Ordering::SeqCst), 2);

        assert_eq!(replacement.reset_transports().await.unwrap(), 0);
        replacement.exchange(&request).await.unwrap();
        assert_eq!(replacement_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn retirement_during_inflight_reset_cannot_reopen_old_dns_owner() {
        #[derive(Debug)]
        struct PausedResetClient {
            entered: Arc<tokio::sync::Notify>,
            release: Arc<tokio::sync::Notify>,
            hits: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl crate::app::dns::Client for PausedResetClient {
            fn id(&self) -> String {
                "paused-retired-reset".to_owned()
            }

            async fn exchange(
                &self,
                _: &op::Message,
            ) -> anyhow::Result<op::Message> {
                self.hits.fetch_add(1, Ordering::SeqCst);
                Ok(response_with_a(Ipv4Addr::new(192, 0, 2, 47)))
            }

            async fn reset_transport(&self) -> anyhow::Result<u32> {
                self.entered.notify_one();
                self.release.notified().await;
                Ok(1)
            }
        }

        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let hits = Arc::new(AtomicUsize::new(0));
        let resolver = Arc::new(EnhancedResolver::from_clients(
            vec![Arc::new(PausedResetClient {
                entered: entered.clone(),
                release: release.clone(),
                hits: hits.clone(),
            })],
            false,
        ));
        let resetting = {
            let resolver = resolver.clone();
            tokio::spawn(async move { resolver.reset_transports().await })
        };
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .expect("DNS transport reset did not reach the test barrier");
        resolver.retire();
        release.notify_one();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), resetting)
                .await
                .unwrap()
                .unwrap()
                .is_err(),
            "an in-flight successful transport reset must not revive its retired owner"
        );
        let (request, _) = test_query();
        assert!(resolver.exchange(&request).await.is_err());
        assert!(resolver.reset_transports().await.is_err());
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn replacing_dns_owner_retires_old_direct_without_closing_new_owner() {
        fn make_owner_and_direct(
            ip: Ipv4Addr,
            label: &'static str,
            hits: Arc<AtomicUsize>,
        ) -> (EnhancedResolver, Arc<EnhancedResolver>) {
            let mut owner = EnhancedResolver::from_clients(vec![], false);
            let child = Arc::new(
                EnhancedResolver::from_clients(
                    vec![Arc::new(CountingClient {
                        response: response_with_a(ip),
                        hits,
                        id: label,
                    })],
                    false,
                )
                .with_parent_transport_gate(
                    Arc::clone(&owner.transport_reset_failed),
                    Arc::clone(&owner.transport_resets_in_progress),
                ),
            );
            owner.direct_resolver = Some(child.clone());
            (owner, child)
        }
        let old_hits = Arc::new(AtomicUsize::new(0));
        let new_hits = Arc::new(AtomicUsize::new(0));
        let (old_owner, old_direct) = make_owner_and_direct(
            Ipv4Addr::new(192, 0, 2, 80),
            "old-direct",
            old_hits.clone(),
        );
        let (new_owner, new_direct) = make_owner_and_direct(
            Ipv4Addr::new(192, 0, 2, 81),
            "new-direct",
            new_hits.clone(),
        );
        let (request, _) = test_query();
        old_direct.exchange(&request).await.unwrap();
        drop(old_owner);
        assert!(
            old_direct.exchange(&request).await.is_err(),
            "old config's DIRECT handle must be retired after owner Drop"
        );
        let answer = new_direct.exchange(&request).await.unwrap();
        assert_eq!(
            EnhancedResolver::ip_list_of_message(&answer),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 81))]
        );
        assert_eq!(old_hits.load(Ordering::SeqCst), 1);
        assert_eq!(new_hits.load(Ordering::SeqCst), 1);
        drop(new_owner);
        assert!(
            new_direct.exchange(&request).await.is_err(),
            "new owner must independently close its DIRECT on Drop"
        );
    }

    #[tokio::test]
    async fn failed_parent_reset_keeps_healthy_direct_child_closed() {
        // A parent main DNS transport can fail even when DIRECT has already
        // reset successfully. Its independently held child cannot reopen.
        #[derive(Debug)]
        struct ResettableClient {
            fail: Arc<AtomicBool>,
            resets: Arc<AtomicUsize>,
            hits: Arc<AtomicUsize>,
            label: &'static str,
        }
        #[async_trait]
        impl crate::app::dns::Client for ResettableClient {
            fn id(&self) -> String {
                self.label.to_owned()
            }
            async fn exchange(
                &self,
                _: &op::Message,
            ) -> anyhow::Result<op::Message> {
                self.hits.fetch_add(1, Ordering::SeqCst);
                Ok(response_with_a(Ipv4Addr::new(192, 0, 2, 75)))
            }
            async fn reset_transport(&self) -> anyhow::Result<u32> {
                self.resets.fetch_add(1, Ordering::SeqCst);
                if self.fail.load(Ordering::SeqCst) {
                    Err(anyhow::anyhow!("injected parent main DNS reset failure"))
                } else {
                    Ok(1)
                }
            }
        }
        let parent_fail = Arc::new(AtomicBool::new(true));
        let parent_hits = Arc::new(AtomicUsize::new(0));
        let child_hits = Arc::new(AtomicUsize::new(0));
        let child_resets = Arc::new(AtomicUsize::new(0));
        let mut parent = EnhancedResolver::from_clients(
            vec![Arc::new(ResettableClient {
                fail: parent_fail.clone(),
                resets: Arc::new(AtomicUsize::new(0)),
                hits: parent_hits.clone(),
                label: "failing-parent",
            })],
            false,
        );
        let child = Arc::new(
            EnhancedResolver::from_clients(
                vec![Arc::new(ResettableClient {
                    fail: Arc::new(AtomicBool::new(false)),
                    resets: child_resets.clone(),
                    hits: child_hits.clone(),
                    label: "working-direct",
                })],
                false,
            )
            .with_parent_transport_gate(
                Arc::clone(&parent.transport_reset_failed),
                Arc::clone(&parent.transport_resets_in_progress),
            ),
        );
        parent.direct_resolver = Some(child.clone());
        let (request, _) = test_query();
        assert!(
            parent
                .reset_transports()
                .await
                .unwrap_err()
                .to_string()
                .contains("injected parent main DNS reset failure")
        );
        assert_eq!(
            child_resets.load(Ordering::SeqCst),
            1,
            "the healthy DIRECT transport should have completed its reset"
        );
        assert!(
            child.exchange(&request).await.is_err(),
            "healthy DIRECT cannot bypass an unsuccessful owner reset"
        );
        child.reset_transports().await.unwrap();
        assert!(
            child.exchange(&request).await.is_err(),
            "second child-only recovery cannot reopen parent-owned DNS"
        );
        assert_eq!(child_hits.load(Ordering::SeqCst), 0);
        assert_eq!(parent_hits.load(Ordering::SeqCst), 0);
        parent_fail.store(false, Ordering::SeqCst);
        assert_eq!(parent.reset_transports().await.unwrap(), 2);
        child.exchange(&request).await.unwrap();
        assert_eq!(child_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn queued_parent_reset_window_must_keep_independent_direct_closed() {
        // The first successful parent reset can clear its failure flag while
        // another reset is queued. The active-reset count remains nonzero;
        // a DIRECT handle must honor both parts of the parent's ownership.
        let hits = Arc::new(AtomicUsize::new(0));
        let mut parent = EnhancedResolver::from_clients(vec![], false);
        let child = Arc::new(
            EnhancedResolver::from_clients(
                vec![Arc::new(CountingClient {
                    response: response_with_a(Ipv4Addr::new(192, 0, 2, 72)),
                    hits: hits.clone(),
                    id: "queued-direct-upstream",
                })],
                false,
            )
            .with_parent_transport_gate(
                Arc::clone(&parent.transport_reset_failed),
                Arc::clone(&parent.transport_resets_in_progress),
            ),
        );
        parent.direct_resolver = Some(child.clone());
        // A deterministic representation of the interval after a successful
        // first reset clears failure while a second reset still has the gate.
        parent
            .transport_resets_in_progress
            .fetch_add(1, Ordering::SeqCst);
        let (request, _) = test_query();
        assert!(!parent.transport_reset_failed.load(Ordering::SeqCst));
        assert!(parent.exchange(&request).await.is_err());
        assert!(
            child.exchange(&request).await.is_err(),
            "DIRECT must not use DNS while any owner reset is still pending"
        );
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        parent
            .transport_resets_in_progress
            .fetch_sub(1, Ordering::SeqCst);
        child.exchange(&request).await.unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn parent_invalidation_during_internal_handoff_must_not_send_qname() {
        let hits = Arc::new(AtomicUsize::new(0));
        let mut owner = EnhancedResolver::from_clients(vec![], false);
        let direct = Arc::new(
            EnhancedResolver::from_clients(
                vec![Arc::new(CountingClient {
                    response: response_with_a(Ipv4Addr::new(192, 0, 2, 79)),
                    hits: hits.clone(),
                    id: "stale-internal-upstream",
                })],
                false,
            )
            .with_parent_transport_gate(
                Arc::clone(&owner.transport_reset_failed),
                Arc::clone(&owner.transport_resets_in_progress),
            ),
        );
        owner.direct_resolver = Some(direct.clone());
        let selected = Arc::new(tokio::sync::Barrier::new(2));
        let resume = Arc::new(tokio::sync::Barrier::new(2));
        let (request, _) = test_query();
        let running = {
            let direct = direct.clone();
            let selected = selected.clone();
            let resume = resume.clone();
            tokio::spawn(async move {
                super::INTERNAL_HANDOFF_TEST_PAUSE
                    .scope(
                        super::PublicHandoffTestPause { selected, resume },
                        async move { direct.exchange(&request).await },
                    )
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(5), selected.wait())
            .await
            .expect("DIRECT internal handoff was not reached");
        owner.invalidate_transports();
        tokio::time::timeout(Duration::from_secs(5), resume.wait())
            .await
            .expect("DIRECT internal handoff did not resume");
        assert!(
            tokio::time::timeout(Duration::from_secs(5), running)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "DIRECT old-network QNAME must not dispatch after internal handoff"
        );
    }

    #[tokio::test]
    async fn owner_invalidation_between_main_and_fallback_must_not_send_qname() {
        // The second DNS path must be gated after the first upstream awaits.
        // Returning an error alone is insufficient if fallback already saw
        // the QNAME on an old network.
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let fallback_hits = Arc::new(AtomicUsize::new(0));
        let main = Arc::new(PausedClient {
            response: negative_response(
                op::ResponseCode::NXDomain,
                "proxy.example.com.",
                120,
                60,
            ),
            entered: entered.clone(),
            resume: release.clone(),
        });
        let fallback = Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 90)),
            hits: fallback_hits.clone(),
            id: "forbidden-old-fallback",
        });
        let resolver = Arc::new(EnhancedResolver::from_clients_with_fallback(
            vec![main],
            Some(vec![fallback]),
            false,
        ));
        let (request, _) = test_query();
        let running = {
            let resolver = resolver.clone();
            tokio::spawn(async move { resolver.exchange(&request).await })
        };
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .expect("main DNS upstream was not reached");
        resolver.invalidate_transports();
        release.notify_one();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), running)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert_eq!(
            fallback_hits.load(Ordering::SeqCst),
            0,
            "DNS fallback must not be dispatched on invalidated transport"
        );
    }

    #[tokio::test]
    async fn invalidated_dns_policy_and_node_dispatch_stay_isolated_until_recovery()
    {
        // Real policy, dynamic Provider and static proxy-node selection must
        // all stop before the old upstream sees a QNAME after invalidation.
        for case in 0..3 {
            let main_hits = Arc::new(AtomicUsize::new(0));
            let selected_hits = Arc::new(AtomicUsize::new(0));
            let mut resolver = EnhancedResolver::from_clients(
                vec![Arc::new(CountingClient {
                    response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
                    hits: main_hits.clone(),
                    id: "unwanted-public-dns",
                })],
                false,
            );
            let selected_client: ThreadSafeDNSClient = Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 91)),
                hits: selected_hits.clone(),
                id: "selected-policy-or-node-dns",
            });
            match case {
                0 => {
                    let mut policy = crate::common::trie::StringTrie::new();
                    policy.insert(
                        "proxy.example.com",
                        Arc::new(vec![selected_client]),
                    );
                    resolver.policy = Some(Arc::new(policy));
                }
                1 => {
                    resolver.proxy_resolver = Some(vec![selected_client]);
                    resolver
                        .replace_proxy_provider_dns_domains(
                            "provider",
                            vec!["proxy.example.com".to_owned()],
                        )
                        .await
                        .unwrap();
                }
                2 => {
                    resolver.proxy_resolver = Some(vec![selected_client]);
                    let mut static_nodes = crate::common::trie::StringTrie::new();
                    static_nodes.insert("proxy.example.com", Arc::new(true));
                    resolver.proxy_server_domains = Some(static_nodes);
                }
                _ => unreachable!(),
            }
            let resolver = Arc::new(resolver);
            let selected = Arc::new(tokio::sync::Barrier::new(2));
            let resume = Arc::new(tokio::sync::Barrier::new(2));
            let mut request = test_query_with_type(if case == 0 {
                rr::RecordType::TXT
            } else {
                rr::RecordType::A
            });
            request.metadata.recursion_desired = true;
            let running = {
                let resolver = resolver.clone();
                let request = request.clone();
                let selected = selected.clone();
                let resume = resume.clone();
                tokio::spawn(async move {
                    super::INTERNAL_HANDOFF_TEST_PAUSE
                        .scope(
                            super::PublicHandoffTestPause { selected, resume },
                            async move { resolver.exchange(&request).await },
                        )
                        .await
                })
            };
            tokio::time::timeout(Duration::from_secs(5), selected.wait())
                .await
                .expect("internal DNS handoff not reached");
            resolver.invalidate_transports();
            tokio::time::timeout(Duration::from_secs(5), resume.wait())
                .await
                .expect("internal DNS query did not resume");
            assert!(
                tokio::time::timeout(Duration::from_secs(5), running)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_err(),
                "case {case}"
            );
            assert_eq!(
                main_hits.load(Ordering::SeqCst),
                0,
                "case {case}: public DNS leaked"
            );
            assert_eq!(
                selected_hits.load(Ordering::SeqCst),
                0,
                "case {case}: selected upstream saw a stale QNAME"
            );
            resolver.reset_transports().await.unwrap();
            assert!(
                resolver.exchange(&request).await.is_ok(),
                "case {case}: full reset should restore selected upstream"
            );
            assert_eq!(
                main_hits.load(Ordering::SeqCst),
                0,
                "case {case}: selected policy/node must never downgrade to main"
            );
            assert_eq!(
                selected_hits.load(Ordering::SeqCst),
                1,
                "case {case}: recovered selected upstream should be called once"
            );
        }
    }

    #[tokio::test]
    async fn own_invalidation_before_dispatch_must_not_send_qname_upstream() {
        let hits = Arc::new(AtomicUsize::new(0));
        let resolver = Arc::new(EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 79)),
                hits: hits.clone(),
                id: "stale-primary-upstream",
            })],
            false,
        ));
        let selected = Arc::new(tokio::sync::Barrier::new(2));
        let resume = Arc::new(tokio::sync::Barrier::new(2));
        let (request, _) = test_query();
        let running = {
            let resolver = resolver.clone();
            let selected = selected.clone();
            let resume = resume.clone();
            tokio::spawn(async move {
                super::PUBLIC_HANDOFF_TEST_PAUSE
                    .scope(
                        super::PublicHandoffTestPause { selected, resume },
                        async move { resolver.exchange(&request).await },
                    )
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(5), selected.wait())
            .await
            .expect("public DNS handoff was not reached");
        resolver.invalidate_transports();
        tokio::time::timeout(Duration::from_secs(5), resume.wait())
            .await
            .expect("public DNS query did not resume");
        assert!(
            tokio::time::timeout(Duration::from_secs(5), running)
                .await
                .unwrap()
                .unwrap()
                .is_err(),
            "invalidated parentless resolver must not deliver old answer"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "invalidated parentless resolver must not leak DNS QNAME"
        );
    }

    #[tokio::test]
    async fn parent_invalidation_before_direct_dispatch_does_not_send_qname_upstream()
     {
        // A DIRECT resolver can yield between its public preflight and
        // no-cache dispatch. Failing closed on return is too late if the DNS
        // QNAME was already sent on the old path during that handoff.
        let upstream_hits = Arc::new(AtomicUsize::new(0));
        let mut parent = EnhancedResolver::from_clients(vec![], false);
        let direct = Arc::new(
            EnhancedResolver::from_clients(
                vec![Arc::new(CountingClient {
                    response: response_with_a(Ipv4Addr::new(192, 0, 2, 79)),
                    hits: upstream_hits.clone(),
                    id: "old-direct-upstream",
                })],
                false,
            )
            .with_parent_transport_gate(
                Arc::clone(&parent.transport_reset_failed),
                Arc::clone(&parent.transport_resets_in_progress),
            ),
        );
        parent.direct_resolver = Some(direct.clone());
        let selected = Arc::new(tokio::sync::Barrier::new(2));
        let resume = Arc::new(tokio::sync::Barrier::new(2));
        let (request, _) = test_query();
        let running = {
            let direct = direct.clone();
            let selected = selected.clone();
            let resume = resume.clone();
            tokio::spawn(async move {
                super::PUBLIC_HANDOFF_TEST_PAUSE
                    .scope(
                        super::PublicHandoffTestPause { selected, resume },
                        async move { direct.exchange(&request).await },
                    )
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(5), selected.wait())
            .await
            .expect("DIRECT DNS query did not reach pre-dispatch handoff");
        parent.invalidate_transports();
        tokio::time::timeout(Duration::from_secs(5), resume.wait())
            .await
            .expect("DIRECT query did not resume");
        let result = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.is_err(),
            "the previous transport must not deliver DNS results"
        );
        assert_eq!(
            upstream_hits.load(Ordering::SeqCst),
            0,
            "fail-closed must prevent sending QNAME, not merely reject response"
        );
    }

    #[tokio::test]
    async fn cancelled_parent_reset_waiting_for_lock_must_close_direct_child() {
        // The DIRECT child future has not started when the parent is waiting
        // for its reset lock. Cancellation must still close the child.
        #[derive(Debug)]
        struct CountingDirectClient(Arc<AtomicUsize>);
        #[async_trait]
        impl crate::app::dns::Client for CountingDirectClient {
            fn id(&self) -> String {
                "counting-direct".to_owned()
            }
            async fn exchange(
                &self,
                _: &op::Message,
            ) -> anyhow::Result<op::Message> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(response_with_a(Ipv4Addr::new(192, 0, 2, 60)))
            }
        }
        let exchanges = Arc::new(AtomicUsize::new(0));
        let mut parent = EnhancedResolver::from_clients(vec![], false);
        parent.direct_resolver = Some(Arc::new(EnhancedResolver::from_clients(
            vec![Arc::new(CountingDirectClient(exchanges.clone()))],
            false,
        )));
        let parent = Arc::new(parent);
        let held_lock = parent.transport_reset_lock.lock().await;
        let resetting = {
            let parent = parent.clone();
            tokio::spawn(async move { parent.reset_transports().await })
        };
        tokio::task::yield_now().await;
        resetting.abort();
        assert!(resetting.await.unwrap_err().is_cancelled());
        drop(held_lock);
        let (request, _) = test_query();
        assert!(
            parent
                .direct_resolver
                .as_ref()
                .unwrap()
                .exchange(&request)
                .await
                .is_err(),
            "cancelled parent reset must not leave DIRECT child using old transport"
        );
        assert_eq!(exchanges.load(Ordering::SeqCst), 0);
        assert_eq!(parent.reset_transports().await.unwrap(), 0);
        parent
            .direct_resolver
            .as_ref()
            .unwrap()
            .exchange(&request)
            .await
            .expect("full parent/child reset must restore DIRECT DNS");
        assert_eq!(exchanges.load(Ordering::SeqCst), 1);
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
        resolver.policy = Some(Arc::new(policy));
        let mut proxy_selector = crate::common::trie::StringTrie::new();
        proxy_selector.insert("proxy.example", Arc::new(true));
        resolver
            .proxy_server_nameserver_policy
            .push((Arc::new(proxy_selector), vec![client()]));

        assert_eq!(resolver.reset_transports().await.unwrap(), 6);
        assert_eq!(resets.load(Ordering::SeqCst), 6);
    }

    /// Global IPv6 disable applies to literal endpoints as well as DNS.
    #[tokio::test]
    async fn test_resolve_ipv6_literal_when_ipv6_disabled() {
        let resolver = EnhancedResolver::new_default().await;
        resolver.set_ipv6(false);
        assert!(!resolver.ipv6(), "ipv6 should be disabled");

        let error = resolver
            .resolve("::1", false)
            .await
            .expect_err("global IPv6 disable must reject a literal endpoint");
        assert!(error.to_string().contains("IPv6 is disabled"));
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

    #[tokio::test]
    async fn test_resolve_v6_literal_when_ipv6_disabled() {
        let resolver = EnhancedResolver::new_default().await;
        resolver.set_ipv6(false);

        let error = resolver
            .resolve_v6("::1", false)
            .await
            .expect_err("resolve_v6 must honor global IPv6 disable");
        assert!(error.to_string().contains("IPv6 is disabled"));
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
    async fn network_reset_serializes_with_public_cache_commit_guard() {
        let resolver = Arc::new(EnhancedResolver::from_clients(vec![], false));
        let (mut request, query) = test_query();
        request.metadata.recursion_desired = true;
        let negative =
            negative_response(op::ResponseCode::NXDomain, "example.com.", 120, 60);
        let before = resolver
            .provider_epoch_network_generation
            .load(std::sync::atomic::Ordering::Relaxed);
        let guard = resolver.provider_epoch_cache.lock().unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let other = Arc::clone(&resolver);
        let reset = tokio::task::spawn_blocking(move || {
            let _ = started_tx.send(());
            // Reset must wait for the commit guard before advancing its epoch.
            futures::executor::block_on(other.reset_transports()).unwrap();
        });
        started_rx.recv().unwrap();
        resolver.cache_negative(&query, &negative, Instant::now());
        assert_eq!(
            resolver
                .provider_epoch_network_generation
                .load(std::sync::atomic::Ordering::Relaxed),
            before
        );
        drop(guard);
        reset.await.unwrap();
        assert_eq!(
            resolver
                .provider_epoch_network_generation
                .load(std::sync::atomic::Ordering::Relaxed),
            before + 1
        );
        assert!(
            resolver
                .cached_negative(&query, &request, Instant::now())
                .is_none()
        );
    }

    #[tokio::test]
    async fn network_reset_must_not_reuse_public_positive_cache() {
        let mut resolver = EnhancedResolver::from_clients(vec![], false);
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        let (mut request, query) = test_query();
        request.metadata.recursion_desired = true;
        let old = response_with_a(Ipv4Addr::new(192, 0, 2, 10));
        resolver
            .lru_cache
            .as_ref()
            .unwrap()
            .insert(query, Ok(old), Instant::now());
        resolver.main = vec![Arc::new(FixedClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 20)),
        })];
        // Prove the old entry is genuinely eligible before resetting.
        let old_answer = resolver.exchange(&request).await.unwrap();
        assert_eq!(
            EnhancedResolver::ip_list_of_message(&old_answer),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]
        );
        resolver.reset_transports().await.unwrap();
        let answer = resolver.exchange(&request).await.unwrap();
        assert_eq!(
            EnhancedResolver::ip_list_of_message(&answer),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20))]
        );
    }

    #[tokio::test]
    async fn network_reset_new_negative_txt_answer_is_cached_only_in_current_epoch()
    {
        // After switching networks, a normal public TXT NXDOMAIN should be
        // reusable within its network epoch, without contacting an upstream
        // for each identical QNAME. A second reset must invalidate it.
        let hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: negative_response(
                    op::ResponseCode::NXDomain,
                    "example.com.",
                    120,
                    60,
                ),
                hits: hits.clone(),
                id: "post-reset-negative-upstream",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        let mut request = test_query_with_type(rr::RecordType::TXT);
        request.metadata.recursion_desired = true;
        resolver.reset_transports().await.unwrap();
        for (index, id) in [31, 32].into_iter().enumerate() {
            request.metadata.id = id;
            let result = resolver.exchange(&request).await.unwrap();
            assert_eq!(result.metadata.response_code, op::ResponseCode::NXDomain);
            if index > 0 {
                assert_eq!(
                    result.metadata.id, id,
                    "a cache hit must echo the current DNS transaction ID"
                );
            }
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "normal negative DNS reply must be cached within a network epoch"
        );
        assert!(
            resolver
                .cached_provider_epoch_response(
                    &request.queries[0],
                    &request,
                    0,
                    Instant::now() + Duration::from_secs(61),
                )
                .is_none(),
            "a normal negative response must expire by SOA.MINIMUM"
        );
        // A second network has a different authoritative answer. Distinct
        // RCODEs ensure the test cannot pass if a stale NXDOMAIN is returned
        // while a background fetch happens to increment a counter.
        let new_hits = Arc::new(AtomicUsize::new(0));
        resolver.main = vec![Arc::new(CountingClient {
            response: negative_response(
                op::ResponseCode::NoError,
                "example.com.",
                120,
                60,
            ),
            hits: new_hits.clone(),
            id: "second-network-negative-upstream",
        })];
        resolver.reset_transports().await.unwrap();
        for _ in 0..2 {
            let result = resolver.exchange(&request).await.unwrap();
            assert_eq!(
                result.metadata.response_code,
                op::ResponseCode::NoError,
                "old-network NXDOMAIN must never reappear after a reset"
            );
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "old network must not receive fresh queries after switching"
        );
        assert_eq!(
            new_hits.load(Ordering::SeqCst),
            1,
            "new network's NODATA should be cached in its own epoch"
        );
    }

    #[tokio::test]
    async fn network_reset_new_nodata_srv_uses_safe_soa_negative_ttl() {
        let hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: negative_response(
                    op::ResponseCode::NoError,
                    "example.com.",
                    120,
                    30,
                ),
                hits: hits.clone(),
                id: "post-reset-nodata-upstream",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        let mut request = test_query_with_type(rr::RecordType::SRV);
        request.metadata.recursion_desired = true;
        resolver.reset_transports().await.unwrap();
        let first = resolver.exchange(&request).await.unwrap();
        assert_eq!(first.metadata.response_code, op::ResponseCode::NoError);
        request.metadata.id = 0x7345;
        let second = resolver.exchange(&request).await.unwrap();
        assert_eq!(second.metadata.response_code, op::ResponseCode::NoError);
        assert!(second.answers.is_empty());
        assert_eq!(second.authorities[0].ttl, 30);
        assert_eq!(second.metadata.id, request.metadata.id);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn network_reset_new_negative_cache_rejects_selected_old_network_answer() {
        let hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: negative_response(
                    op::ResponseCode::NXDomain,
                    "example.com.",
                    120,
                    30,
                ),
                hits: hits.clone(),
                id: "post-reset-negative-upstream",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        let mut request = test_query_with_type(rr::RecordType::TXT);
        request.metadata.recursion_desired = true;
        resolver.reset_transports().await.unwrap();
        resolver.exchange(&request).await.unwrap();
        let resolver = Arc::new(resolver);
        let selected = Arc::new(tokio::sync::Barrier::new(2));
        let resume = Arc::new(tokio::sync::Barrier::new(2));
        let running = {
            let resolver = resolver.clone();
            let selected = selected.clone();
            let resume = resume.clone();
            tokio::spawn(async move {
                CACHE_CANDIDATE_TEST_PAUSE
                    .scope(
                        CacheCandidateTestPause {
                            kind: CacheCandidateKind::Negative,
                            selected,
                            resume,
                        },
                        async move { resolver.exchange(&request).await },
                    )
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(5), selected.wait())
            .await
            .expect("negative epoch cache candidate not selected");
        resolver.reset_transports().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), resume.wait())
            .await
            .expect("cached query did not resume");
        let result = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.is_err(),
            "old network NXDOMAIN must not be delivered"
        );
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn network_reset_new_negative_cache_rejects_wrong_soa_and_ad_responses() {
        for bad_response in [
            negative_response(op::ResponseCode::NXDomain, "unrelated.org.", 120, 30),
            {
                let mut response = negative_response(
                    op::ResponseCode::NXDomain,
                    "example.com.",
                    120,
                    30,
                );
                response.metadata.authentic_data = true;
                response
            },
        ] {
            let hits = Arc::new(AtomicUsize::new(0));
            let mut resolver = EnhancedResolver::from_clients(
                vec![Arc::new(CountingClient {
                    response: bad_response.clone(),
                    hits: hits.clone(),
                    id: "unsafe-negative-dns",
                })],
                false,
            );
            resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
            let mut request = test_query_with_type(rr::RecordType::TXT);
            request.metadata.recursion_desired = true;
            resolver.reset_transports().await.unwrap();
            for _ in 0..2 {
                let answer = resolver.exchange(&request).await.unwrap();
                assert_eq!(
                    answer.metadata.response_code,
                    op::ResponseCode::NXDomain
                );
            }
            assert_eq!(
                hits.load(Ordering::SeqCst),
                2,
                "a wrong-zone SOA or AD response must not enter post-reset negative cache"
            );
        }
    }

    #[tokio::test]
    async fn network_reset_negative_cache_candidate_rejects_provider_registration_aba()
     {
        let public_hits = Arc::new(AtomicUsize::new(0));
        let node_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: negative_response(
                    op::ResponseCode::NXDomain,
                    "example.com.",
                    120,
                    60,
                ),
                hits: public_hits.clone(),
                id: "post-reset-public-dns",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: node_hits.clone(),
            id: "dedicated-node-dns",
        })]);
        let mut request = test_query_with_type(rr::RecordType::TXT);
        request.metadata.recursion_desired = true;
        resolver.reset_transports().await.unwrap();
        resolver.exchange(&request).await.unwrap();
        assert_eq!(public_hits.load(Ordering::SeqCst), 1);
        let resolver = Arc::new(resolver);
        let selected = Arc::new(tokio::sync::Barrier::new(2));
        let resume = Arc::new(tokio::sync::Barrier::new(2));
        let running = {
            let resolver = resolver.clone();
            let selected = selected.clone();
            let resume = resume.clone();
            tokio::spawn(async move {
                CACHE_CANDIDATE_TEST_PAUSE
                    .scope(
                        CacheCandidateTestPause {
                            kind: CacheCandidateKind::Negative,
                            selected,
                            resume,
                        },
                        async move { resolver.exchange(&request).await },
                    )
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(5), selected.wait())
            .await
            .expect("normal negative cache candidate not selected");
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), resume.wait())
            .await
            .expect("candidate did not resume");
        let result = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.is_err(),
            "old normal DNS cache candidate must fail closed after Provider ABA"
        );
        assert_eq!(public_hits.load(Ordering::SeqCst), 1);
        assert_eq!(node_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn network_reset_new_negative_with_cache_disabled_stays_uncached() {
        let hits = Arc::new(AtomicUsize::new(0));
        let resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: negative_response(
                    op::ResponseCode::NXDomain,
                    "example.com.",
                    120,
                    60,
                ),
                hits: hits.clone(),
                id: "ordinary-negative-no-cache",
            })],
            false,
        );
        assert!(resolver.lru_cache.is_none());
        let mut request = test_query_with_type(rr::RecordType::TXT);
        request.metadata.recursion_desired = true;
        resolver.reset_transports().await.unwrap();
        for _ in 0..2 {
            let result = resolver.exchange(&request).await.unwrap();
            assert_eq!(result.metadata.response_code, op::ResponseCode::NXDomain);
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            2,
            "cache-disabled config must never activate the new network cache"
        );
        assert!(resolver.provider_epoch_cache.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn new_network_negative_answer_supersedes_older_positive_cache_entry() {
        // A newer NXDOMAIN can arrive on the same network via a forced
        // refresh. It must not be hidden behind a previously cached positive
        // record; otherwise the old address will be reused until its TTL.
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(FixedClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        let (mut request, _) = test_query();
        request.metadata.recursion_desired = true;
        resolver.reset_transports().await.unwrap();
        let positive = resolver.exchange(&request).await.unwrap();
        assert_eq!(
            EnhancedResolver::ip_list_of_message(&positive),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]
        );
        resolver.main = vec![Arc::new(FixedClient {
            response: negative_response(
                op::ResponseCode::NXDomain,
                "example.com.",
                120,
                60,
            ),
        })];
        let negative = resolver.exchange_no_cache(&request).await.unwrap();
        assert_eq!(negative.metadata.response_code, op::ResponseCode::NXDomain);
        let current = resolver.exchange(&request).await.unwrap();
        assert_eq!(
            current.metadata.response_code,
            op::ResponseCode::NXDomain,
            "fresh negative answer must override obsolete positive cache entry"
        );
    }

    #[tokio::test]
    async fn new_network_positive_answer_invalidates_older_negative_epoch_entry() {
        // A fresh successful public answer must invalidate an earlier
        // NXDOMAIN for the same Question. Otherwise the negative can reappear
        // after the positive TTL expires, exactly as in the legacy cache.
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(FixedClient {
                response: negative_response(
                    op::ResponseCode::NXDomain,
                    "example.com.",
                    120,
                    60,
                ),
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        let (mut request, _) = test_query();
        request.metadata.recursion_desired = true;
        resolver.reset_transports().await.unwrap();
        let negative = resolver.exchange(&request).await.unwrap();
        assert_eq!(negative.metadata.response_code, op::ResponseCode::NXDomain);
        assert!(
            resolver
                .cached_provider_epoch_response(
                    &request.queries[0],
                    &request,
                    0,
                    Instant::now(),
                )
                .is_some(),
            "the first NXDOMAIN must actually be present in the epoch cache"
        );
        resolver.main = vec![Arc::new(FixedClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 50)),
        })];
        let positive = resolver.exchange_no_cache(&request).await.unwrap();
        assert_eq!(
            EnhancedResolver::ip_list_of_message(&positive),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50))]
        );
        assert!(
            resolver
                .cached_provider_epoch_response(
                    &request.queries[0],
                    &request,
                    0,
                    Instant::now(),
                )
                .is_none(),
            "a new positive response must revoke an obsolete negative epoch entry"
        );
    }

    #[tokio::test]
    async fn post_reset_negative_cache_does_not_merge_dnssec_or_edns_requests() {
        for use_edns in [false, true] {
            let hits = Arc::new(AtomicUsize::new(0));
            let mut resolver = EnhancedResolver::from_clients(
                vec![Arc::new(CountingClient {
                    response: negative_response(
                        op::ResponseCode::NXDomain,
                        "example.com.",
                        120,
                        60,
                    ),
                    hits: hits.clone(),
                    id: "privacy-variant-negative-dns",
                })],
                false,
            );
            resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
            let mut request = test_query_with_type(rr::RecordType::TXT);
            request.metadata.recursion_desired = true;
            if use_edns {
                request.set_edns(op::Edns::new());
            } else {
                request.metadata.checking_disabled = true;
            }
            resolver.reset_transports().await.unwrap();
            for _ in 0..2 {
                let result = resolver.exchange(&request).await.unwrap();
                assert_eq!(
                    result.metadata.response_code,
                    op::ResponseCode::NXDomain
                );
            }
            assert_eq!(
                hits.load(Ordering::SeqCst),
                2,
                "EDNS or CD-specific queries must bypass the Question-only cache"
            );
            assert!(resolver.provider_epoch_cache.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn network_reset_new_positive_answer_is_cached_within_new_epoch() {
        let mut resolver = EnhancedResolver::from_clients(vec![], false);
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        let (mut request, _) = test_query();
        request.metadata.recursion_desired = true;
        let hits = Arc::new(AtomicUsize::new(0));
        resolver.main = vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 20)),
            hits: hits.clone(),
            id: "new-network",
        })];
        resolver.reset_transports().await.unwrap();
        for _ in 0..2 {
            let answer = resolver.exchange(&request).await.unwrap();
            assert_eq!(
                EnhancedResolver::ip_list_of_message(&answer),
                vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20))]
            );
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "new-network cache must be reusable"
        );
        let third_hits = Arc::new(AtomicUsize::new(0));
        resolver.main = vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 30)),
            hits: third_hits.clone(),
            id: "third-network",
        })];
        resolver.reset_transports().await.unwrap();
        for _ in 0..2 {
            let answer = resolver.exchange(&request).await.unwrap();
            assert_eq!(
                EnhancedResolver::ip_list_of_message(&answer),
                vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 30))]
            );
        }
        assert_eq!(third_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn network_reset_rejects_selected_new_epoch_positive_cache_candidate() {
        let mut resolver = EnhancedResolver::from_clients(vec![], false);
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        let (mut request, _) = test_query();
        request.metadata.recursion_desired = true;
        resolver.main = vec![Arc::new(FixedClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 20)),
        })];
        resolver.reset_transports().await.unwrap();
        resolver.exchange(&request).await.unwrap();
        let resolver = Arc::new(resolver);
        let selected = Arc::new(tokio::sync::Barrier::new(2));
        let resume = Arc::new(tokio::sync::Barrier::new(2));
        let running = {
            let resolver = resolver.clone();
            let selected = selected.clone();
            let resume = resume.clone();
            tokio::spawn(async move {
                CACHE_CANDIDATE_TEST_PAUSE
                    .scope(
                        CacheCandidateTestPause {
                            kind: CacheCandidateKind::Positive,
                            selected,
                            resume,
                        },
                        async move { resolver.exchange(&request).await },
                    )
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(5), selected.wait())
            .await
            .expect("new-epoch positive cache candidate not selected");
        resolver.reset_transports().await.unwrap();
        resume.wait().await;
        assert!(
            running.await.unwrap().is_err(),
            "candidate selected before reset must not survive network epoch change"
        );
    }

    #[tokio::test]
    async fn network_reset_during_public_return_handoff_rejects_positive_answer() {
        // Exercise the final outer handoff, not only the internal cache
        // commit guard. A reset after the internal resolver finishes must
        // invalidate its answer before it reaches the caller.
        let hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 20)),
                hits: hits.clone(),
                id: "prior-network",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        let resolver = Arc::new(resolver);
        let selected = Arc::new(tokio::sync::Barrier::new(2));
        let resume = Arc::new(tokio::sync::Barrier::new(2));
        let (mut request, _) = test_query();
        request.metadata.recursion_desired = true;
        let running = {
            let resolver = resolver.clone();
            let selected = selected.clone();
            let resume = resume.clone();
            tokio::spawn(async move {
                super::PUBLIC_RETURN_TEST_PAUSE
                    .scope(
                        super::PublicHandoffTestPause { selected, resume },
                        async move { resolver.exchange(&request).await },
                    )
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(5), selected.wait())
            .await
            .expect("public response did not reach return handoff");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        resolver.reset_transports().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), resume.wait())
            .await
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.is_err(),
            "old-network positive answer escaped after reset"
        );
    }

    #[tokio::test]
    async fn query_during_transport_reset_must_fail_closed() {
        #[derive(Debug)]
        struct BlockingResetClient {
            entered: Arc<tokio::sync::Barrier>,
            resume: Arc<tokio::sync::Barrier>,
            exchanges: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl crate::app::dns::Client for BlockingResetClient {
            fn id(&self) -> String {
                "blocking-reset".to_owned()
            }
            async fn exchange(
                &self,
                _msg: &op::Message,
            ) -> anyhow::Result<op::Message> {
                self.exchanges.fetch_add(1, Ordering::SeqCst);
                Ok(response_with_a(Ipv4Addr::new(192, 0, 2, 10)))
            }
            async fn reset_transport(&self) -> anyhow::Result<u32> {
                self.entered.wait().await;
                self.resume.wait().await;
                Ok(1)
            }
        }

        let entered = Arc::new(tokio::sync::Barrier::new(2));
        let resume = Arc::new(tokio::sync::Barrier::new(2));
        let exchanges = Arc::new(AtomicUsize::new(0));
        let resolver = Arc::new(EnhancedResolver::from_clients(
            vec![Arc::new(BlockingResetClient {
                entered: entered.clone(),
                resume: resume.clone(),
                exchanges: exchanges.clone(),
            })],
            false,
        ));
        let resetting = {
            let resolver = resolver.clone();
            tokio::spawn(async move { resolver.reset_transports().await })
        };
        tokio::time::timeout(Duration::from_secs(5), entered.wait())
            .await
            .unwrap();
        let (request, _) = test_query();
        let result = resolver.exchange(&request).await;
        resume.wait().await;
        tokio::time::timeout(Duration::from_secs(5), resetting)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(result.is_err(), "DNS query used old transport during reset");
        assert_eq!(
            exchanges.load(Ordering::SeqCst),
            0,
            "query must not reach an upstream transport while it is resetting"
        );
    }

    #[tokio::test]
    async fn cancelled_transport_reset_releases_query_gate_and_invalidates_cache() {
        // A cancelled reset must release the fail-closed gate. The old
        // network's positive cache must still be unavailable afterwards.
        #[derive(Debug)]
        struct PendingResetClient {
            entered: Arc<tokio::sync::Notify>,
            exchanges: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl crate::app::dns::Client for PendingResetClient {
            fn id(&self) -> String {
                "pending-reset".to_owned()
            }

            async fn exchange(
                &self,
                _: &op::Message,
            ) -> anyhow::Result<op::Message> {
                self.exchanges.fetch_add(1, Ordering::SeqCst);
                Ok(response_with_a(Ipv4Addr::new(192, 0, 2, 10)))
            }

            async fn reset_transport(&self) -> anyhow::Result<u32> {
                self.entered.notify_one();
                std::future::pending().await
            }
        }

        let entered = Arc::new(tokio::sync::Notify::new());
        let exchanges = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(PendingResetClient {
                entered: entered.clone(),
                exchanges: exchanges.clone(),
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        let resolver = Arc::new(resolver);
        let (mut request, _) = test_query();
        request.metadata.recursion_desired = true;
        resolver.exchange(&request).await.unwrap();
        resolver.exchange(&request).await.unwrap();
        assert_eq!(exchanges.load(Ordering::SeqCst), 1);
        let resetting = {
            let resolver = resolver.clone();
            tokio::spawn(async move { resolver.reset_transports().await })
        };
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        assert!(resolver.exchange(&request).await.is_err());
        resetting.abort();
        assert!(resetting.await.unwrap_err().is_cancelled());
        assert_eq!(
            resolver.transport_resets_in_progress.load(Ordering::SeqCst),
            0,
            "cancelled reset must release the query gate"
        );
        assert_eq!(
            resolver
                .provider_epoch_network_generation
                .load(Ordering::Relaxed),
            1,
            "cancelled reset must retain the advanced network generation"
        );
        assert!(resolver.network_positive_cache.lock().unwrap().is_none());
        // The query may resume after cancellation; it must not reuse the
        // original pre-reset positive cache.
        assert!(
            resolver.exchange(&request).await.is_err(),
            "cancelled reset must remain fail closed"
        );
        assert_eq!(
            exchanges.load(Ordering::SeqCst),
            1,
            "old transport must not be reused"
        );
    }

    #[tokio::test]
    async fn cancelled_partial_reset_stays_fail_closed_until_successful_recovery() {
        #[derive(Debug)]
        struct CancelOnceClient {
            entered: Arc<tokio::sync::Notify>,
            attempts: AtomicUsize,
            exchanges: Arc<AtomicUsize>,
        }
        #[async_trait]
        impl crate::app::dns::Client for CancelOnceClient {
            fn id(&self) -> String {
                "cancel-once".to_owned()
            }
            async fn exchange(
                &self,
                _: &op::Message,
            ) -> anyhow::Result<op::Message> {
                self.exchanges.fetch_add(1, Ordering::SeqCst);
                Ok(response_with_a(Ipv4Addr::new(192, 0, 2, 10)))
            }
            async fn reset_transport(&self) -> anyhow::Result<u32> {
                if self.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                    self.entered.notify_one();
                    std::future::pending().await
                } else {
                    Ok(1)
                }
            }
        }
        let entered = Arc::new(tokio::sync::Notify::new());
        let exchanges = Arc::new(AtomicUsize::new(0));
        let resolver = Arc::new(EnhancedResolver::from_clients(
            vec![Arc::new(CancelOnceClient {
                entered: entered.clone(),
                attempts: AtomicUsize::new(0),
                exchanges: exchanges.clone(),
            })],
            false,
        ));
        let resetting = {
            let resolver = resolver.clone();
            tokio::spawn(async move { resolver.reset_transports().await })
        };
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        resetting.abort();
        assert!(resetting.await.unwrap_err().is_cancelled());
        let (request, _) = test_query();
        assert!(
            resolver.exchange(&request).await.is_err(),
            "cancelled reset must fail closed"
        );
        assert_eq!(exchanges.load(Ordering::SeqCst), 0);
        assert_eq!(resolver.reset_transports().await.unwrap(), 1);
        assert!(
            resolver.exchange(&request).await.is_ok(),
            "successful reset must restore DNS"
        );
        assert_eq!(exchanges.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn queued_reset_after_cancel_keeps_dns_closed_until_recovery_finishes() {
        #[derive(Debug)]
        struct TwoPhaseResetClient {
            first_entered: Arc<tokio::sync::Notify>,
            second_entered: Arc<tokio::sync::Notify>,
            second_release: Arc<tokio::sync::Notify>,
            attempts: AtomicUsize,
            exchanges: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl crate::app::dns::Client for TwoPhaseResetClient {
            fn id(&self) -> String {
                "two-phase-reset".to_owned()
            }
            async fn exchange(
                &self,
                _: &op::Message,
            ) -> anyhow::Result<op::Message> {
                self.exchanges.fetch_add(1, Ordering::SeqCst);
                Ok(response_with_a(Ipv4Addr::new(192, 0, 2, 10)))
            }
            async fn reset_transport(&self) -> anyhow::Result<u32> {
                match self.attempts.fetch_add(1, Ordering::SeqCst) {
                    0 => {
                        self.first_entered.notify_one();
                        std::future::pending().await
                    }
                    1 => {
                        self.second_entered.notify_one();
                        self.second_release.notified().await;
                        Ok(1)
                    }
                    _ => panic!("unexpected third transport reset"),
                }
            }
        }

        let first_entered = Arc::new(tokio::sync::Notify::new());
        let second_entered = Arc::new(tokio::sync::Notify::new());
        let second_release = Arc::new(tokio::sync::Notify::new());
        let exchanges = Arc::new(AtomicUsize::new(0));
        let mut owner = EnhancedResolver::from_clients(
            vec![Arc::new(TwoPhaseResetClient {
                first_entered: first_entered.clone(),
                second_entered: second_entered.clone(),
                second_release: second_release.clone(),
                attempts: AtomicUsize::new(0),
                exchanges: exchanges.clone(),
            })],
            false,
        );
        let direct_hits = Arc::new(AtomicUsize::new(0));
        let direct = Arc::new(
            EnhancedResolver::from_clients(
                vec![Arc::new(CountingClient {
                    response: response_with_a(Ipv4Addr::new(192, 0, 2, 16)),
                    hits: direct_hits.clone(),
                    id: "queued-direct",
                })],
                false,
            )
            .with_parent_transport_gate(
                Arc::clone(&owner.transport_reset_failed),
                Arc::clone(&owner.transport_resets_in_progress),
            ),
        );
        owner.direct_resolver = Some(direct.clone());
        let resolver = Arc::new(owner);
        let first = {
            let resolver = resolver.clone();
            tokio::spawn(async move { resolver.reset_transports().await })
        };
        tokio::time::timeout(Duration::from_secs(5), first_entered.notified())
            .await
            .unwrap();
        let second = {
            let resolver = resolver.clone();
            tokio::spawn(async move { resolver.reset_transports().await })
        };
        // The second reset is queued behind the first. Neither may reopen DNS.
        tokio::task::yield_now().await;
        let (request, _) = test_query();
        assert!(resolver.exchange(&request).await.is_err());
        assert!(direct.exchange(&request).await.is_err());
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(5), second_entered.notified())
            .await
            .unwrap();
        assert!(resolver.exchange(&request).await.is_err());
        direct.reset_transports().await.unwrap();
        assert!(
            direct.exchange(&request).await.is_err(),
            "independent DIRECT reset during queued parent recovery cannot reopen DNS"
        );
        assert_eq!(direct_hits.load(Ordering::SeqCst), 0);
        assert_eq!(exchanges.load(Ordering::SeqCst), 0);
        second_release.notify_one();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), second)
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            1
        );
        assert_eq!(
            resolver.transport_resets_in_progress.load(Ordering::SeqCst),
            0
        );
        assert!(resolver.exchange(&request).await.is_ok());
        assert!(direct.exchange(&request).await.is_ok());
        assert_eq!(direct_hits.load(Ordering::SeqCst), 1);
        assert_eq!(exchanges.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failed_transport_reset_invalidates_positive_cache_before_returning_error()
     {
        // A failed transport reset must never preserve a successful old-network
        // cache hit: callers may retry, but cannot trust the prior answer.
        #[derive(Debug)]
        struct FailingResetClient {
            exchanges: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl crate::app::dns::Client for FailingResetClient {
            fn id(&self) -> String {
                "failing-reset-client".to_owned()
            }

            async fn exchange(
                &self,
                _msg: &op::Message,
            ) -> anyhow::Result<op::Message> {
                self.exchanges.fetch_add(1, Ordering::SeqCst);
                Ok(response_with_a(Ipv4Addr::new(192, 0, 2, 10)))
            }

            async fn reset_transport(&self) -> anyhow::Result<u32> {
                Err(anyhow::anyhow!("transport reset unavailable"))
            }
        }

        let exchanges = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(FailingResetClient {
                exchanges: exchanges.clone(),
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        let (mut request, _) = test_query();
        request.metadata.recursion_desired = true;
        resolver.exchange(&request).await.unwrap();
        resolver.exchange(&request).await.unwrap();
        assert_eq!(
            exchanges.load(Ordering::SeqCst),
            1,
            "pre-reset positive cache must actually be hit"
        );
        resolver.reset_transports().await.unwrap_err();
        assert_eq!(
            resolver
                .provider_epoch_network_generation
                .load(Ordering::Relaxed),
            1,
            "failed reset must still advance the cache isolation epoch"
        );
        assert!(
            resolver.network_positive_cache.lock().unwrap().is_none(),
            "failed reset must not retain the old positive cache"
        );
    }

    #[tokio::test]
    async fn partial_transport_reset_failure_must_block_old_upstream_until_recovery()
    {
        // One client resets successfully while another fails. A subsequent
        // query must not silently use the partially reset transport set.
        #[derive(Debug)]
        struct PartialResetClient {
            fail: bool,
            exchanges: Arc<AtomicUsize>,
        }
        #[async_trait]
        impl crate::app::dns::Client for PartialResetClient {
            fn id(&self) -> String {
                format!("partial-reset-{}", self.fail)
            }
            async fn exchange(
                &self,
                _: &op::Message,
            ) -> anyhow::Result<op::Message> {
                self.exchanges.fetch_add(1, Ordering::SeqCst);
                Ok(response_with_a(Ipv4Addr::new(192, 0, 2, 10)))
            }
            async fn reset_transport(&self) -> anyhow::Result<u32> {
                if self.fail {
                    Err(anyhow::anyhow!("injected reset failure"))
                } else {
                    Ok(1)
                }
            }
        }
        let exchanges = Arc::new(AtomicUsize::new(0));
        let resolver = EnhancedResolver::from_clients(
            vec![
                Arc::new(PartialResetClient {
                    fail: false,
                    exchanges: exchanges.clone(),
                }),
                Arc::new(PartialResetClient {
                    fail: true,
                    exchanges: exchanges.clone(),
                }),
            ],
            false,
        );
        assert!(resolver.reset_transports().await.is_err());
        let (request, _) = test_query();
        assert!(
            resolver.exchange(&request).await.is_err(),
            "partially reset DNS transports must fail closed until a successful reset"
        );
        assert_eq!(exchanges.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn network_reset_eagerly_drops_prior_epoch_positive_cache() {
        let mut resolver = EnhancedResolver::from_clients(vec![], false);
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        let (mut request, _) = test_query();
        request.metadata.recursion_desired = true;
        resolver.main = vec![Arc::new(FixedClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 20)),
        })];
        resolver.reset_transports().await.unwrap();
        resolver.exchange(&request).await.unwrap();
        assert!(resolver.network_positive_cache.lock().unwrap().is_some());
        resolver.reset_transports().await.unwrap();
        assert!(
            resolver.network_positive_cache.lock().unwrap().is_none(),
            "reset must release old-network positive answers before another query"
        );
    }

    #[tokio::test]
    async fn network_reset_does_not_enable_disabled_positive_cache() {
        // Cache isolation must not silently turn caching on when the caller
        // deliberately disabled the legacy positive cache.
        let hits = Arc::new(AtomicUsize::new(0));
        let resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 20)),
                hits: hits.clone(),
                id: "uncached-network",
            })],
            false,
        );
        assert!(resolver.lru_cache.is_none());
        resolver.reset_transports().await.unwrap();
        let (mut request, _) = test_query();
        request.metadata.recursion_desired = true;
        resolver.exchange(&request).await.unwrap();
        resolver.exchange(&request).await.unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert!(resolver.network_positive_cache.lock().unwrap().is_none());
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
    async fn refreshed_proxy_provider_host_uses_dedicated_node_dns_not_public_main()
    {
        // Mihomo resolves proxy provider endpoints through ProxyServerNameserver
        // even if they did not exist when the primary resolver was built.
        let mut resolver = EnhancedResolver::from_clients(vec![], false);
        let main_hits = Arc::new(AtomicUsize::new(0));
        let proxy_hits = Arc::new(AtomicUsize::new(0));
        resolver.main = vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
            hits: main_hits.clone(),
            id: "public-main",
        })];
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: proxy_hits.clone(),
            id: "node-only",
        })]);
        resolver
            .replace_proxy_provider_dns_domains(
                "remote-proxies",
                vec!["PrOxY.ExAmPlE.CoM".to_owned()],
            )
            .await
            .unwrap();
        let result = resolver
            .ip_exchange(&test_query_with_type(rr::RecordType::A))
            .await
            .unwrap();
        assert_eq!(
            EnhancedResolver::ip_list_of_message(&result),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))]
        );
        assert_eq!(proxy_hits.load(Ordering::SeqCst), 1);
        assert_eq!(main_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn provider_node_txt_query_must_not_use_public_dns_or_shared_cache() {
        let public_hits = Arc::new(AtomicUsize::new(0));
        let node_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
                hits: public_hits.clone(),
                id: "public-dns",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: node_hits.clone(),
            id: "node-dns",
        })]);
        resolver
            .replace_proxy_provider_dns_domains(
                "provider",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        let query = test_query_with_type(rr::RecordType::TXT);
        resolver.exchange(&query).await.unwrap();
        assert_eq!(node_hits.load(Ordering::SeqCst), 1);
        assert_eq!(public_hits.load(Ordering::SeqCst), 0);
        resolver
            .replace_proxy_provider_dns_domains("provider", vec![])
            .await
            .unwrap();
        resolver.exchange(&query).await.unwrap();
        assert_eq!(
            public_hits.load(Ordering::SeqCst),
            1,
            "node TXT response must not poison generic DNS cache"
        );
    }

    #[tokio::test]
    async fn internal_dns_entry_rejects_empty_question_without_panicking() {
        let resolver = EnhancedResolver::from_clients(
            vec![Arc::new(FailingClient {
                id: "unreachable-upstream",
                reason: "should not be called",
            })],
            false,
        );
        let empty = op::Message::query();
        let error = resolver
            .exchange_no_cache_with_policy(&empty, true, false)
            .await
            .expect_err(
                "empty DNS question must be rejected before upstream selection",
            );
        assert!(error.to_string().contains("invalid query"));
    }

    #[tokio::test]
    async fn provider_node_txt_policy_failure_never_falls_back_to_public_dns() {
        let public_hits = Arc::new(AtomicUsize::new(0));
        let default_node_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
                hits: public_hits.clone(),
                id: "public-dns",
            })],
            false,
        );
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: default_node_hits.clone(),
            id: "default-node-dns",
        })]);
        let mut matcher = crate::common::trie::StringTrie::new();
        matcher.insert("proxy.example.com", Arc::new(true));
        resolver.proxy_server_nameserver_policy.push((
            Arc::new(matcher),
            vec![Arc::new(FailingClient {
                id: "node-policy",
                reason: "dedicated upstream unavailable",
            })],
        ));
        resolver
            .replace_proxy_provider_dns_domains(
                "provider",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        let request = test_query_with_type(rr::RecordType::TXT);
        let error = resolver
            .exchange(&request)
            .await
            .expect_err("dedicated policy failure must fail closed");
        assert!(error.to_string().contains("dedicated upstream unavailable"));
        assert_eq!(public_hits.load(Ordering::SeqCst), 0);
        assert_eq!(default_node_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn provider_node_dns_snapshot_survives_concurrent_owner_removal() {
        // A query already classified as a provider endpoint must retain the
        // dedicated DNS choice if a refresh removes its owner mid-flight.
        let main_hits = Arc::new(AtomicUsize::new(0));
        let node_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
                hits: main_hits.clone(),
                id: "public-main",
            })],
            false,
        );
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: node_hits.clone(),
            id: "node-only",
        })]);
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        let request = test_query_with_type(rr::RecordType::A);
        let provider_snapshot = resolver
            .is_registered_provider_domain("proxy.example.com")
            .await;
        assert!(provider_snapshot);
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        let result = resolver
            .ip_exchange_with_provider_snapshot(&request, provider_snapshot)
            .await
            .unwrap();
        assert_eq!(
            EnhancedResolver::ip_list_of_message(&result),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))]
        );
        assert_eq!(node_hits.load(Ordering::SeqCst), 1);
        assert_eq!(main_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn ordinary_dns_without_node_pool_does_not_wait_for_provider_registry() {
        // Without any configured proxy-node resolver, the provider registry
        // cannot affect upstream selection. Ordinary DNS must not stall
        // behind a concurrent provider-domain update holding its write lock.
        let main_hits = Arc::new(AtomicUsize::new(0));
        let resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
                hits: main_hits.clone(),
                id: "ordinary-dns",
            })],
            false,
        );
        assert!(resolver.proxy_resolver.is_none());
        let _registry_writer = resolver.provider_proxy_server_domains.write().await;
        let result = tokio::time::timeout(
            Duration::from_millis(150),
            resolver.ip_exchange(&test_query_with_type(rr::RecordType::A)),
        )
        .await
        .expect("ordinary DNS must not await irrelevant provider registry lock")
        .expect("synthetic DNS succeeds");
        assert_eq!(
            EnhancedResolver::ip_list_of_message(&result),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]
        );
        assert_eq!(main_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn provider_registration_during_query_never_caches_node_answer_as_public_dns()
     {
        // A request initially classified as generic DNS can race with a
        // provider registration before its actual upstream is selected.
        // Even if dedicated node DNS wins, its answer must not poison the
        // shared generic response cache after that provider is removed.
        let main_hits = Arc::new(AtomicUsize::new(0));
        let node_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
                hits: main_hits.clone(),
                id: "public-dns",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: node_hits.clone(),
            id: "node-dns",
        })]);
        let mut query = test_query_with_type(rr::RecordType::A);
        query.metadata.recursion_desired = true;
        let was_node_at_start = resolver
            .is_registered_provider_domain("proxy.example.com")
            .await;
        assert!(!was_node_at_start);
        resolver
            .replace_proxy_provider_dns_domains(
                "new-provider",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        let during = resolver
            .exchange_no_cache_with_policy(&query, true, was_node_at_start)
            .await
            .unwrap();
        assert_eq!(
            EnhancedResolver::ip_list_of_message(&during),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))]
        );
        resolver
            .replace_proxy_provider_dns_domains("new-provider", vec![])
            .await
            .unwrap();
        let afterward = resolver.exchange(&query).await.unwrap();
        assert_eq!(
            EnhancedResolver::ip_list_of_message(&afterward),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))],
            "removed provider's dedicated node answer must not remain in public cache"
        );
        assert_eq!(node_hits.load(Ordering::SeqCst), 1);
        assert_eq!(main_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn public_handoff_provider_aba_rejects_obsolete_public_answer() {
        let public_hits = Arc::new(AtomicUsize::new(0));
        let node_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
                hits: public_hits.clone(),
                id: "public-dns",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: node_hits.clone(),
            id: "node-dns",
        })]);
        let resolver = Arc::new(resolver);
        let selected = Arc::new(tokio::sync::Barrier::new(2));
        let resume = Arc::new(tokio::sync::Barrier::new(2));
        let mut query = test_query_with_type(rr::RecordType::A);
        query.metadata.recursion_desired = true;
        let running = {
            let resolver = resolver.clone();
            let selected = selected.clone();
            let resume = resume.clone();
            tokio::spawn(async move {
                super::PUBLIC_HANDOFF_TEST_PAUSE
                    .scope(
                        super::PublicHandoffTestPause { selected, resume },
                        async move { resolver.exchange(&query).await },
                    )
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(5), selected.wait())
            .await
            .expect("public handoff did not pause");
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), resume.wait())
            .await
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_err(), "ABA must not return a public DNS answer");
        assert_eq!(
            public_hits.load(Ordering::SeqCst),
            0,
            "public DNS must not be queried"
        );
        assert_eq!(node_hits.load(Ordering::SeqCst), 0);
        assert!(
            resolver
                .lru_cache
                .as_ref()
                .unwrap()
                .get(
                    &test_query_with_type(rr::RecordType::A).queries[0],
                    Instant::now()
                )
                .is_none(),
            "no stale shared positive cache entry"
        );
    }

    #[tokio::test]
    async fn provider_aba_after_public_cache_commit_must_reject_returned_answer() {
        let public_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
                hits: public_hits.clone(),
                id: "public-dns",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: Arc::new(AtomicUsize::new(0)),
            id: "node-dns",
        })]);
        let resolver = Arc::new(resolver);
        let selected = Arc::new(tokio::sync::Barrier::new(2));
        let resume = Arc::new(tokio::sync::Barrier::new(2));
        let mut query = test_query_with_type(rr::RecordType::A);
        query.metadata.recursion_desired = true;
        let running = {
            let resolver = resolver.clone();
            let selected = selected.clone();
            let resume = resume.clone();
            tokio::spawn(async move {
                super::PUBLIC_RETURN_TEST_PAUSE
                    .scope(
                        super::PublicHandoffTestPause { selected, resume },
                        async move { resolver.exchange(&query).await },
                    )
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(5), selected.wait())
            .await
            .expect("public return handoff did not pause");
        assert_eq!(public_hits.load(Ordering::SeqCst), 1);
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), resume.wait())
            .await
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.is_err(),
            "post-cache ABA must not return obsolete public DNS answer"
        );
    }

    #[tokio::test]
    async fn provider_aba_between_final_check_and_cache_write_rejects_public_answer()
    {
        let public_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
                hits: public_hits.clone(),
                id: "public-dns",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: Arc::new(AtomicUsize::new(0)),
            id: "node-dns",
        })]);
        let resolver = Arc::new(resolver);
        let selected = Arc::new(tokio::sync::Barrier::new(2));
        let resume = Arc::new(tokio::sync::Barrier::new(2));
        let mut query = test_query_with_type(rr::RecordType::A);
        query.metadata.recursion_desired = true;
        let running = {
            let resolver = resolver.clone();
            let selected = selected.clone();
            let resume = resume.clone();
            tokio::spawn(async move {
                super::PUBLIC_CACHE_WRITE_TEST_PAUSE
                    .scope(
                        super::PublicHandoffTestPause { selected, resume },
                        async move { resolver.exchange(&query).await },
                    )
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(5), selected.wait())
            .await
            .unwrap();
        assert_eq!(public_hits.load(Ordering::SeqCst), 1);
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), resume.wait())
            .await
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_err(), "late ABA must reject public answer");
        assert!(
            resolver
                .lru_cache
                .as_ref()
                .unwrap()
                .get(
                    &test_query_with_type(rr::RecordType::A).queries[0],
                    Instant::now()
                )
                .is_none(),
            "late ABA must not poison shared positive cache"
        );
    }

    #[tokio::test]
    async fn provider_aba_before_negative_cache_write_rejects_nxdomain() {
        let public_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: negative_response(
                    op::ResponseCode::NXDomain,
                    "example.com.",
                    300,
                    60,
                ),
                hits: public_hits.clone(),
                id: "public-dns",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: Arc::new(AtomicUsize::new(0)),
            id: "node-dns",
        })]);
        let resolver = Arc::new(resolver);
        let selected = Arc::new(tokio::sync::Barrier::new(2));
        let resume = Arc::new(tokio::sync::Barrier::new(2));
        let mut query = test_query_with_type(rr::RecordType::A);
        query.metadata.recursion_desired = true;
        let running = {
            let resolver = resolver.clone();
            let selected = selected.clone();
            let resume = resume.clone();
            tokio::spawn(async move {
                super::PUBLIC_CACHE_WRITE_TEST_PAUSE
                    .scope(
                        super::PublicHandoffTestPause { selected, resume },
                        async move { resolver.exchange(&query).await },
                    )
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(5), selected.wait())
            .await
            .unwrap();
        assert_eq!(public_hits.load(Ordering::SeqCst), 1);
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), resume.wait())
            .await
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_err(), "late ABA must reject public answer");
        assert!(
            resolver
                .cached_negative(
                    &test_query_with_type(rr::RecordType::A).queries[0],
                    &test_query_with_type(rr::RecordType::A),
                    Instant::now()
                )
                .is_none(),
            "late ABA must not poison shared negative cache"
        );
        assert!(
            resolver
                .lru_cache
                .as_ref()
                .unwrap()
                .get(
                    &test_query_with_type(rr::RecordType::A).queries[0],
                    Instant::now()
                )
                .is_none(),
            "late ABA must not poison shared positive cache"
        );
    }

    #[tokio::test]
    async fn internal_handoff_provider_aba_rejects_obsolete_public_answer() {
        let public_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
                hits: public_hits.clone(),
                id: "public-dns",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: Arc::new(AtomicUsize::new(0)),
            id: "node-dns",
        })]);
        let resolver = Arc::new(resolver);
        let selected = Arc::new(tokio::sync::Barrier::new(2));
        let resume = Arc::new(tokio::sync::Barrier::new(2));
        let mut query = test_query_with_type(rr::RecordType::A);
        query.metadata.recursion_desired = true;
        let running = {
            let resolver = resolver.clone();
            let selected = selected.clone();
            let resume = resume.clone();
            tokio::spawn(async move {
                super::INTERNAL_HANDOFF_TEST_PAUSE
                    .scope(
                        super::PublicHandoffTestPause { selected, resume },
                        async move { resolver.exchange(&query).await },
                    )
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(5), selected.wait())
            .await
            .expect("internal handoff did not pause");
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), resume.wait())
            .await
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.is_err(),
            "ABA between entry and internal snapshot must fail closed"
        );
        assert_eq!(public_hits.load(Ordering::SeqCst), 0);
        assert!(
            resolver
                .lru_cache
                .as_ref()
                .unwrap()
                .get(
                    &test_query_with_type(rr::RecordType::A).queries[0],
                    Instant::now(),
                )
                .is_none()
        );
    }

    #[tokio::test]
    async fn provider_registered_during_public_query_must_not_receive_public_answer()
    {
        let entered = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        let node_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(PausedClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
                entered: entered.clone(),
                resume: resume.clone(),
            })],
            false,
        );
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: node_hits.clone(),
            id: "node-dns",
        })]);
        let resolver = Arc::new(resolver);
        let mut query = test_query_with_type(rr::RecordType::A);
        query.metadata.recursion_desired = true;
        let running = {
            let resolver = resolver.clone();
            tokio::spawn(async move { resolver.exchange(&query).await })
        };
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains(
                "new-provider",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        resume.notify_one();
        let answer = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            EnhancedResolver::ip_list_of_message(&answer),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))],
            "a newly registered node must not receive an in-flight ordinary DNS answer"
        );
        // A reclassified public query must use the dedicated pool exactly
        // once; provenance is required to avoid redundant bootstrap traffic.
        assert_eq!(node_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn provider_reclassification_txt_and_nxdomain_use_dedicated_once() {
        for negative in [false, true] {
            let entered = Arc::new(tokio::sync::Notify::new());
            let resume = Arc::new(tokio::sync::Notify::new());
            let node_hits = Arc::new(AtomicUsize::new(0));
            let mut public_response = op::Message::response(0, op::OpCode::Query);
            let mut node_response = op::Message::response(0, op::OpCode::Query);
            if negative {
                public_response.metadata.response_code = op::ResponseCode::NXDomain;
                node_response.metadata.response_code = op::ResponseCode::NXDomain;
            } else {
                let name = rr::Name::from_str_relaxed("proxy.example.com")
                    .unwrap()
                    .append_domain(&rr::Name::root())
                    .unwrap();
                public_response.add_answer(rr::Record::from_rdata(
                    name.clone(),
                    300,
                    rr::RData::TXT(rr::rdata::TXT::new(vec!["public".into()])),
                ));
                node_response.add_answer(rr::Record::from_rdata(
                    name,
                    300,
                    rr::RData::TXT(rr::rdata::TXT::new(vec!["dedicated".into()])),
                ));
            }
            let mut resolver = EnhancedResolver::from_clients(
                vec![Arc::new(PausedClient {
                    response: public_response.clone(),
                    entered: entered.clone(),
                    resume: resume.clone(),
                })],
                false,
            );
            resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
            resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
                response: node_response.clone(),
                hits: node_hits.clone(),
                id: "node-dns",
            })]);
            let resolver = Arc::new(resolver);
            let query = test_query_with_type(rr::RecordType::TXT);
            let running = {
                let resolver = resolver.clone();
                tokio::spawn(async move { resolver.exchange(&query).await })
            };
            tokio::time::timeout(Duration::from_secs(5), entered.notified())
                .await
                .unwrap();
            resolver
                .replace_proxy_provider_dns_domains(
                    "owner",
                    vec!["proxy.example.com".into()],
                )
                .await
                .unwrap();
            resume.notify_one();
            let answer = tokio::time::timeout(Duration::from_secs(5), running)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(
                answer.metadata.response_code,
                node_response.metadata.response_code
            );
            assert_eq!(
                answer.answers, node_response.answers,
                "must return dedicated TXT/NXDOMAIN, not public"
            );
            assert_eq!(
                node_hits.load(Ordering::SeqCst),
                1,
                "dedicated lookup must occur once (negative={negative})"
            );
        }
    }

    #[tokio::test]
    async fn public_cache_candidate_rejects_provider_registration_aba() {
        // A cache hit can be selected while the provider registry is empty.
        // Registration and removal before delivery must not resurrect it.
        let mut resolver = EnhancedResolver::from_clients(vec![], false);
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: Arc::new(AtomicUsize::new(0)),
            id: "node-dns",
        })]);
        let query = test_query_with_type(rr::RecordType::A);
        let domain = "proxy.example.com";
        let selected_generation = resolver.provider_domain_generation(domain).await;
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![domain.into()])
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        let result = resolver
            .revalidate_public_cache_hit_with_generation(
                &query,
                response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
                selected_generation,
            )
            .await;
        assert!(
            result.is_err(),
            "public cache candidate must reject provider ABA"
        );
    }

    #[tokio::test]
    async fn negative_cache_candidate_rejects_provider_registration_aba() {
        // RFC 2308 negative cache is independent from the positive response
        // cache. The same generation guard must protect both paths.
        let mut resolver = EnhancedResolver::from_clients(vec![], false);
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: Arc::new(AtomicUsize::new(0)),
            id: "node-dns",
        })]);
        let query = test_query_with_type(rr::RecordType::TXT);
        let domain = "proxy.example.com";
        let negative = negative_response(
            op::ResponseCode::NXDomain,
            "proxy.example.com.",
            300,
            60,
        );
        resolver.cache_negative(&query.queries[0], &negative, Instant::now());
        let selected_generation = resolver.provider_domain_generation(domain).await;
        let selected = resolver
            .cached_negative(&query.queries[0], &query, Instant::now())
            .expect("negative cache entry must be present");
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![domain.into()])
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        let result = resolver
            .revalidate_public_cache_hit_with_generation(
                &query,
                selected,
                selected_generation,
            )
            .await;
        assert!(
            result.is_err(),
            "negative cache candidate must reject Provider ABA"
        );
    }

    #[tokio::test]
    async fn registered_provider_bypasses_existing_negative_cache_in_exchange() {
        // Exercise the real exchange path: cached NXDOMAIN cannot mask a node.
        let public_hits = Arc::new(AtomicUsize::new(0));
        let node_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: negative_response(
                    op::ResponseCode::NXDomain,
                    "proxy.example.com.",
                    300,
                    60,
                ),
                hits: public_hits.clone(),
                id: "public-dns",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: node_hits.clone(),
            id: "node-dns",
        })]);
        let mut query = test_query_with_type(rr::RecordType::A);
        query.metadata.recursion_desired = true;
        let negative = negative_response(
            op::ResponseCode::NXDomain,
            "proxy.example.com.",
            300,
            60,
        );
        resolver.cache_negative(&query.queries[0], &negative, Instant::now());
        assert!(
            resolver
                .cached_negative(&query.queries[0], &query, Instant::now())
                .is_some()
        );
        let first = resolver.exchange(&query).await.unwrap();
        assert_eq!(first.metadata.response_code, op::ResponseCode::NXDomain);
        assert_eq!(
            public_hits.load(Ordering::SeqCst),
            0,
            "first query must be a genuine negative cache hit, not a public DNS request"
        );
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        let answer = resolver.exchange(&query).await.unwrap();
        assert_eq!(
            EnhancedResolver::ip_list_of_message(&answer),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))]
        );
        assert_eq!(node_hits.load(Ordering::SeqCst), 1);
        assert_eq!(public_hits.load(Ordering::SeqCst), 0);
    }

    // The gate sits *inside* the real cache-hit branch after cache selection,
    // before generation revalidation. A generic upstream hook would not prove
    // which path ran, and could yield a false-positive regression test.
    async fn assert_exchange_cache_candidate_rejects_provider_change(
        kind: CacheCandidateKind,
        record_type: rr::RecordType,
        remove_after_registration: bool,
    ) {
        let public_hits = Arc::new(AtomicUsize::new(0));
        let node_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
                hits: public_hits.clone(),
                id: "public-dns",
            })],
            false,
        );
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: node_hits.clone(),
            id: "node-dns",
        })]);
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        let mut query = test_query_with_type(record_type);
        query.metadata.recursion_desired = true;
        match kind {
            CacheCandidateKind::Positive => {
                let mut answer = response_with_a(Ipv4Addr::new(192, 0, 2, 10));
                answer.answers[0].ttl = 120;
                resolver.lru_cache.as_ref().unwrap().insert(
                    query.queries[0].clone(),
                    Ok(answer),
                    Instant::now(),
                );
            }
            CacheCandidateKind::Negative => {
                let negative = negative_response(
                    op::ResponseCode::NXDomain,
                    "proxy.example.com.",
                    120,
                    60,
                );
                resolver.cache_negative(
                    &query.queries[0],
                    &negative,
                    Instant::now(),
                );
            }
        }
        let resolver = Arc::new(resolver);
        let selected = Arc::new(tokio::sync::Barrier::new(2));
        let resume = Arc::new(tokio::sync::Barrier::new(2));
        let running = {
            let resolver = resolver.clone();
            let selected = selected.clone();
            let resume = resume.clone();
            tokio::spawn(async move {
                CACHE_CANDIDATE_TEST_PAUSE
                    .scope(
                        CacheCandidateTestPause {
                            kind,
                            selected,
                            resume,
                        },
                        async move { resolver.exchange(&query).await },
                    )
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(5), selected.wait())
            .await
            .expect("actual cache candidate was not selected");
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        if remove_after_registration {
            resolver
                .replace_proxy_provider_dns_domains("owner", vec![])
                .await
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(5), resume.wait())
            .await
            .expect("cache candidate resume barrier timed out");
        let result = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.is_err(),
            "{kind:?} cache candidate escaped provider ownership change"
        );
        assert_eq!(public_hits.load(Ordering::SeqCst), 0);
        assert_eq!(node_hits.load(Ordering::SeqCst), 0);
        if !remove_after_registration {
            // Rejection must not poison subsequent dedicated node DNS.
            let mut retry = test_query_with_type(record_type);
            retry.metadata.recursion_desired = true;
            let recovered = resolver.exchange(&retry).await.unwrap();
            assert_eq!(
                EnhancedResolver::ip_list_of_message(&recovered),
                vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))],
            );
            assert_eq!(node_hits.load(Ordering::SeqCst), 1);
            assert_eq!(public_hits.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn exchange_negative_cache_candidate_rejects_provider_registration_aba() {
        assert_exchange_cache_candidate_rejects_provider_change(
            CacheCandidateKind::Negative,
            rr::RecordType::A,
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn exchange_negative_txt_cache_candidate_rejects_provider_registration_aba()
     {
        // Non-address records cannot use Fake-IP answers. They still must
        // reject stale generic negative cache entries after provider ABA.
        assert_exchange_cache_candidate_rejects_provider_change(
            CacheCandidateKind::Negative,
            rr::RecordType::TXT,
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn exchange_negative_srv_cache_candidate_rejects_provider_registration_aba()
     {
        // Game/service-discovery SRV records require real DNS semantics,
        // but must still reject stale ordinary negative cache after ABA.
        assert_exchange_cache_candidate_rejects_provider_change(
            CacheCandidateKind::Negative,
            rr::RecordType::SRV,
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn exchange_positive_cache_candidate_rejects_provider_registration_aba() {
        assert_exchange_cache_candidate_rejects_provider_change(
            CacheCandidateKind::Positive,
            rr::RecordType::A,
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn exchange_negative_cache_candidate_rejects_new_provider_and_recovers() {
        assert_exchange_cache_candidate_rejects_provider_change(
            CacheCandidateKind::Negative,
            rr::RecordType::A,
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn exchange_positive_cache_candidate_rejects_new_provider_and_recovers() {
        assert_exchange_cache_candidate_rejects_provider_change(
            CacheCandidateKind::Positive,
            rr::RecordType::A,
            false,
        )
        .await;
    }

    // A provider refresh for an unrelated name must not invalidate a valid
    // cache entry for this QNAME. This guards against replacing per-domain
    // epochs with a globally changing epoch (excessive fail-closed behavior).
    async fn assert_unrelated_provider_refresh_preserves_cache_candidate(
        kind: CacheCandidateKind,
    ) {
        let public_hits = Arc::new(AtomicUsize::new(0));
        let node_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 99)),
                hits: public_hits.clone(),
                id: "public-dns",
            })],
            false,
        );
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 98)),
            hits: node_hits.clone(),
            id: "node-dns",
        })]);
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        let mut query = test_query_with_type(rr::RecordType::A);
        query.metadata.recursion_desired = true;
        match kind {
            CacheCandidateKind::Positive => {
                let mut answer = response_with_a(Ipv4Addr::new(192, 0, 2, 10));
                answer.answers[0].ttl = 120;
                resolver.lru_cache.as_ref().unwrap().insert(
                    query.queries[0].clone(),
                    Ok(answer),
                    Instant::now(),
                );
            }
            CacheCandidateKind::Negative => {
                let negative = negative_response(
                    op::ResponseCode::NXDomain,
                    "proxy.example.com.",
                    120,
                    60,
                );
                resolver.cache_negative(
                    &query.queries[0],
                    &negative,
                    Instant::now(),
                );
            }
        }
        let resolver = Arc::new(resolver);
        let selected = Arc::new(tokio::sync::Barrier::new(2));
        let resume = Arc::new(tokio::sync::Barrier::new(2));
        let running = {
            let resolver = resolver.clone();
            let selected = selected.clone();
            let resume = resume.clone();
            tokio::spawn(async move {
                CACHE_CANDIDATE_TEST_PAUSE
                    .scope(
                        CacheCandidateTestPause {
                            kind,
                            selected,
                            resume,
                        },
                        async move { resolver.exchange(&query).await },
                    )
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(5), selected.wait())
            .await
            .expect("unrelated refresh test did not enter the cache-hit branch");
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["unrelated.example.com".into()],
            )
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), resume.wait())
            .await
            .expect("cache candidate resume barrier timed out");
        let result = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap()
            .expect("unrelated provider update must not invalidate cache");
        match kind {
            CacheCandidateKind::Positive => assert_eq!(
                EnhancedResolver::ip_list_of_message(&result),
                vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))],
            ),
            CacheCandidateKind::Negative => {
                assert_eq!(result.metadata.response_code, op::ResponseCode::NXDomain,)
            }
        }
        assert_eq!(public_hits.load(Ordering::SeqCst), 0);
        assert_eq!(node_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn exchange_negative_cache_candidate_survives_unrelated_provider_aba() {
        assert_unrelated_provider_refresh_preserves_cache_candidate(
            CacheCandidateKind::Negative,
        )
        .await;
    }

    #[tokio::test]
    async fn exchange_positive_cache_candidate_survives_unrelated_provider_aba() {
        assert_unrelated_provider_refresh_preserves_cache_candidate(
            CacheCandidateKind::Positive,
        )
        .await;
    }

    #[tokio::test]
    async fn provider_registration_aba_during_public_query_rejects_stale_answer() {
        for record_type in [rr::RecordType::A, rr::RecordType::TXT] {
            let entered = Arc::new(tokio::sync::Notify::new());
            let resume = Arc::new(tokio::sync::Notify::new());
            let mut resolver = EnhancedResolver::from_clients(
                vec![Arc::new(PausedClient {
                    response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
                    entered: entered.clone(),
                    resume: resume.clone(),
                })],
                false,
            );
            resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
            resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
                hits: Arc::new(AtomicUsize::new(0)),
                id: "node-dns",
            })]);
            let resolver = Arc::new(resolver);
            let query = test_query_with_type(record_type);
            let running = {
                let resolver = resolver.clone();
                tokio::spawn(async move { resolver.exchange(&query).await })
            };
            tokio::time::timeout(Duration::from_secs(5), entered.notified())
                .await
                .unwrap();
            resolver
                .replace_proxy_provider_dns_domains(
                    "owner",
                    vec!["proxy.example.com".into()],
                )
                .await
                .unwrap();
            resolver
                .replace_proxy_provider_dns_domains("owner", vec![])
                .await
                .unwrap();
            resume.notify_one();
            let result = tokio::time::timeout(Duration::from_secs(5), running)
                .await
                .unwrap()
                .unwrap();
            assert!(
                result.is_err(),
                "public answer from before provider ownership ABA must be rejected"
            );
            assert!(
                resolver
                    .lru_cache
                    .as_ref()
                    .unwrap()
                    .get(
                        &test_query_with_type(record_type).queries[0],
                        Instant::now(),
                    )
                    .is_none(),
                "provider ABA must not leave an obsolete public DNS answer in shared cache for {record_type:?}"
            );
        }
    }

    #[tokio::test]
    async fn provider_removed_during_node_query_must_not_return_stale_node_answer() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
                hits: Arc::new(AtomicUsize::new(0)),
                id: "public-dns",
            })],
            false,
        );
        resolver.proxy_resolver = Some(vec![Arc::new(PausedClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            entered: entered.clone(),
            resume: resume.clone(),
        })]);
        let resolver = Arc::new(resolver);
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        let query = test_query_with_type(rr::RecordType::TXT);
        let running = {
            let resolver = resolver.clone();
            tokio::spawn(async move { resolver.exchange(&query).await })
        };
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        resume.notify_one();
        let result = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.is_err(),
            "removed provider must not receive stale dedicated DNS answer"
        );
    }

    #[tokio::test]
    async fn provider_removed_and_reregistered_during_node_query_rejects_old_generation()
     {
        let entered = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        let mut resolver = EnhancedResolver::from_clients(vec![], false);
        resolver.proxy_resolver = Some(vec![Arc::new(PausedClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            entered: entered.clone(),
            resume: resume.clone(),
        })]);
        let resolver = Arc::new(resolver);
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        let query = test_query_with_type(rr::RecordType::TXT);
        let running = {
            let resolver = resolver.clone();
            tokio::spawn(async move { resolver.exchange(&query).await })
        };
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        resume.notify_one();
        let result = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.is_err(),
            "a new provider generation must not accept a prior generation's DNS response"
        );
    }

    #[tokio::test]
    async fn unrelated_provider_refresh_must_not_invalidate_inflight_node_dns() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        let mut resolver = EnhancedResolver::from_clients(vec![], false);
        resolver.proxy_resolver = Some(vec![Arc::new(PausedClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            entered: entered.clone(),
            resume: resume.clone(),
        })]);
        let resolver = Arc::new(resolver);
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        let query = test_query_with_type(rr::RecordType::TXT);
        let running = {
            let resolver = resolver.clone();
            tokio::spawn(async move { resolver.exchange(&query).await })
        };
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains(
                "unrelated",
                vec!["other.example.net".into()],
            )
            .await
            .unwrap();
        resume.notify_one();
        let result = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.is_ok(),
            "unrelated provider refresh must not invalidate the query's ownership"
        );
    }

    #[tokio::test]
    async fn removing_one_of_two_owners_does_not_invalidate_inflight_node_dns() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        let mut resolver = EnhancedResolver::from_clients(vec![], false);
        resolver.proxy_resolver = Some(vec![Arc::new(PausedClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            entered: entered.clone(),
            resume: resume.clone(),
        })]);
        let resolver = Arc::new(resolver);
        for owner in ["owner-a", "owner-b"] {
            resolver
                .replace_proxy_provider_dns_domains(
                    owner,
                    vec!["proxy.example.com".into()],
                )
                .await
                .unwrap();
        }
        let query = test_query_with_type(rr::RecordType::TXT);
        let running = {
            let resolver = resolver.clone();
            tokio::spawn(async move { resolver.exchange(&query).await })
        };
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner-a", vec![])
            .await
            .unwrap();
        resume.notify_one();
        let result = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.is_ok(),
            "another provider still owns the dedicated node DNS domain"
        );
    }

    #[tokio::test]
    async fn identical_provider_refresh_does_not_invalidate_inflight_node_dns() {
        // A provider refresh with an identical endpoint set is not a new
        // ownership generation. Avoid breaking healthy in-flight node DNS.
        let entered = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        let mut resolver = EnhancedResolver::from_clients(vec![], false);
        resolver.proxy_resolver = Some(vec![Arc::new(PausedClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            entered: entered.clone(),
            resume: resume.clone(),
        })]);
        let resolver = Arc::new(resolver);
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        let query = test_query_with_type(rr::RecordType::TXT);
        let running = {
            let resolver = resolver.clone();
            tokio::spawn(async move { resolver.exchange(&query).await })
        };
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["PROXY.EXAMPLE.COM.".into()],
            )
            .await
            .unwrap();
        resume.notify_one();
        let result = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.is_ok(),
            "equivalent provider refresh must preserve in-flight DNS"
        );
    }

    #[tokio::test]
    async fn cached_public_answer_must_be_reclassified_after_provider_registration()
    {
        // Simulate a cache hit selected before a concurrent provider refresh.
        // A late cache return must not expose the public answer.
        let node_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(vec![], false);
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: node_hits.clone(),
            id: "node-dns",
        })]);
        let query = test_query_with_type(rr::RecordType::A);
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        let cached = response_with_a(Ipv4Addr::new(192, 0, 2, 10));
        let result = resolver
            .revalidate_public_cache_hit(&query, cached)
            .await
            .unwrap();
        assert_eq!(
            EnhancedResolver::ip_list_of_message(&result),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))]
        );
        assert_eq!(node_hits.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn cached_negative_answer_must_be_reclassified_after_provider_registration()
     {
        // NXDOMAIN/NODATA are privacy-sensitive too: a stale negative public
        // response must not hide the dedicated node resolver after registration.
        let node_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(vec![], false);
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: node_hits.clone(),
            id: "node-dns",
        })]);
        let query = test_query_with_type(rr::RecordType::TXT);
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        let cached =
            negative_response(op::ResponseCode::NXDomain, "example.com.", 300, 60);
        let result = resolver
            .revalidate_public_cache_hit(&query, cached)
            .await
            .unwrap();
        assert_ne!(result.metadata.response_code, op::ResponseCode::NXDomain);
        assert_eq!(node_hits.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn cache_reclassification_rejects_provider_aba_during_node_lookup() {
        // Cover both address and non-address negative answers: a dedicated
        // response from an obsolete owner must never be delivered after ABA.
        for record_type in [rr::RecordType::A, rr::RecordType::TXT] {
            let entered = Arc::new(tokio::sync::Notify::new());
            let resume = Arc::new(tokio::sync::Notify::new());
            let mut node_response = response_with_a(Ipv4Addr::new(192, 0, 2, 11));
            let mut stale_public = response_with_a(Ipv4Addr::new(192, 0, 2, 10));
            if record_type == rr::RecordType::TXT {
                node_response.answers.clear();
                node_response.metadata.response_code = op::ResponseCode::NXDomain;
                stale_public.answers.clear();
                stale_public.metadata.response_code = op::ResponseCode::NXDomain;
            }
            let mut resolver = EnhancedResolver::from_clients(vec![], false);
            resolver.proxy_resolver = Some(vec![Arc::new(PausedClient {
                response: node_response,
                entered: entered.clone(),
                resume: resume.clone(),
            })]);
            let resolver = Arc::new(resolver);
            resolver
                .replace_proxy_provider_dns_domains(
                    "owner",
                    vec!["proxy.example.com".into()],
                )
                .await
                .unwrap();
            let query = test_query_with_type(record_type);
            let running = {
                let resolver = resolver.clone();
                tokio::spawn(async move {
                    resolver
                        .revalidate_public_cache_hit(&query, stale_public)
                        .await
                })
            };
            tokio::time::timeout(Duration::from_secs(5), entered.notified())
                .await
                .unwrap();
            resolver
                .replace_proxy_provider_dns_domains("owner", vec![])
                .await
                .unwrap();
            resolver
                .replace_proxy_provider_dns_domains(
                    "owner",
                    vec!["proxy.example.com".into()],
                )
                .await
                .unwrap();
            resume.notify_one();
            let result = tokio::time::timeout(Duration::from_secs(5), running)
                .await
                .unwrap()
                .unwrap();
            assert!(
                result.is_err(),
                "obsolete dedicated {record_type:?} response must fail closed"
            );
        }
    }

    #[tokio::test]
    async fn network_reset_rejects_inflight_public_txt_nxdomain_and_cache_write() {
        // A public DNS request is also network-scoped: a reset must not
        // deliver or cache a negative answer from the previous network.
        let entered = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        let mut negative = response_with_a(Ipv4Addr::new(192, 0, 2, 11));
        negative.answers.clear();
        negative.metadata.response_code = op::ResponseCode::NXDomain;
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(PausedClient {
                response: negative,
                entered: entered.clone(),
                resume: resume.clone(),
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        let resolver = Arc::new(resolver);
        let query = test_query_with_type(rr::RecordType::TXT);
        let running = {
            let resolver = resolver.clone();
            tokio::spawn(async move { resolver.exchange(&query).await })
        };
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        resolver.reset_transports().await.unwrap();
        resume.notify_one();
        let result = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.is_err(),
            "old-network public NXDOMAIN must fail closed"
        );
        assert!(
            resolver
                .lru_cache
                .as_ref()
                .unwrap()
                .get(
                    &test_query_with_type(rr::RecordType::TXT).queries[0],
                    Instant::now()
                )
                .is_none(),
            "old-network public NXDOMAIN must not enter shared cache"
        );
    }

    #[tokio::test]
    async fn provider_aba_and_network_reset_during_dedicated_negative_lookup_fail_closed()
     {
        // A node's NXDOMAIN from an obsolete owner and network must never
        // become a valid response after both ownership and transport change.
        let entered = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        let mut negative = response_with_a(Ipv4Addr::new(192, 0, 2, 11));
        negative.answers.clear();
        negative.metadata.response_code = op::ResponseCode::NXDomain;
        // The new network has a healthy public resolver; the old dedicated
        // NXDOMAIN must not shadow it after ownership is removed.
        let fresh_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 77)),
                hits: fresh_hits.clone(),
                id: "new-network-public",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        resolver.proxy_resolver = Some(vec![Arc::new(PausedClient {
            response: negative,
            entered: entered.clone(),
            resume: resume.clone(),
        })]);
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        let resolver = Arc::new(resolver);
        let mut query = test_query_with_type(rr::RecordType::TXT);
        query.metadata.recursion_desired = true;
        let running = {
            let resolver = resolver.clone();
            tokio::spawn(async move { resolver.exchange(&query).await })
        };
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        resolver.reset_transports().await.unwrap();
        resume.notify_one();
        let result = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.is_err(),
            "obsolete NXDOMAIN must not survive provider ABA and network reset"
        );
        assert!(
            resolver
                .lru_cache
                .as_ref()
                .unwrap()
                .get(
                    &test_query_with_type(rr::RecordType::TXT).queries[0],
                    Instant::now(),
                )
                .is_none(),
            "obsolete NXDOMAIN must not contaminate the shared negative cache"
        );
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        let fresh = tokio::time::timeout(
            Duration::from_secs(5),
            resolver.exchange(&test_query_with_type(rr::RecordType::TXT)),
        )
        .await
        .expect("new-network query must finish")
        .expect("new-network public DNS must be usable");
        assert_eq!(fresh.metadata.response_code, op::ResponseCode::NoError);
        assert_eq!(
            fresh_hits.load(Ordering::SeqCst),
            1,
            "new-network DNS must actually be queried, not served from stale negative cache"
        );
    }

    #[tokio::test]
    async fn provider_node_dns_never_reuses_public_answer_cached_before_registration()
     {
        // A public DNS answer could have been cached before this hostname
        // appeared in a proxy provider. Registration must revoke that trust.
        let main_hits = Arc::new(AtomicUsize::new(0));
        let node_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
                hits: main_hits.clone(),
                id: "main-dns",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: node_hits.clone(),
            id: "node-dns",
        })]);
        let mut request = test_query_with_type(rr::RecordType::A);
        request.metadata.recursion_desired = true;
        let before = resolver.exchange(&request).await.unwrap();
        assert_eq!(
            EnhancedResolver::ip_list_of_message(&before),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]
        );
        resolver
            .replace_proxy_provider_dns_domains(
                "provider-cache",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        let after = resolver.exchange(&request).await.unwrap();
        assert_eq!(
            EnhancedResolver::ip_list_of_message(&after),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))],
            "a cached ordinary DNS answer cannot override newly registered node bootstrap"
        );
        assert_eq!(main_hits.load(Ordering::SeqCst), 1);
        assert_eq!(node_hits.load(Ordering::SeqCst), 1);
    }

    // Public cache entries written before a domain ever became a Provider
    // endpoint carry no ownership epoch. They must not be resurrected once
    // the Provider registers and is later removed (historical ABA).
    async fn assert_provider_ownership_aba_invalidates_old_public_cache(
        negative: bool,
    ) {
        let public_hits = Arc::new(AtomicUsize::new(0));
        let node_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 12)),
                hits: public_hits.clone(),
                id: "new-public-dns",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: node_hits.clone(),
            id: "node-dns",
        })]);
        let mut query = test_query_with_type(rr::RecordType::A);
        query.metadata.recursion_desired = true;
        if negative {
            let nx = negative_response(
                op::ResponseCode::NXDomain,
                "proxy.example.com.",
                300,
                60,
            );
            resolver.cache_negative(&query.queries[0], &nx, Instant::now());
            assert!(
                resolver
                    .cached_negative(&query.queries[0], &query, Instant::now())
                    .is_some()
            );
        } else {
            let mut old = response_with_a(Ipv4Addr::new(192, 0, 2, 10));
            old.answers[0].ttl = 120;
            resolver.lru_cache.as_ref().unwrap().insert(
                query.queries[0].clone(),
                Ok(old),
                Instant::now(),
            );
        }
        // After the entire Provider ABA, the current owner registry is empty.
        // Checking only the current owner/generation accepts an old answer.
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        let result = resolver.exchange(&query).await.unwrap();
        assert_eq!(
            EnhancedResolver::ip_list_of_message(&result),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 12))],
            "reusing a pre-Provider public cache entry after ownership ABA is unsafe"
        );
        assert_eq!(public_hits.load(Ordering::SeqCst), 1);
        assert_eq!(node_hits.load(Ordering::SeqCst), 0);
        // Subsequent ordinary queries can reuse the new generation-tagged
        // entry, without reviving the old pre-registration public answer.
        let again = resolver.exchange(&query).await.unwrap();
        assert_eq!(
            EnhancedResolver::ip_list_of_message(&again),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 12))]
        );
        assert_eq!(public_hits.load(Ordering::SeqCst), 1);
        assert_eq!(node_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn old_public_positive_cache_is_not_reused_after_provider_ownership_aba() {
        assert_provider_ownership_aba_invalidates_old_public_cache(false).await;
    }

    #[tokio::test]
    async fn old_public_negative_cache_is_not_reused_after_provider_ownership_aba() {
        assert_provider_ownership_aba_invalidates_old_public_cache(true).await;
    }

    #[tokio::test]
    async fn former_provider_domain_uses_generation_tagged_negative_cache() {
        // After a provider relinquishes the name, an ordinary NXDOMAIN
        // response can be cached with provenance without reviving old data.
        let main_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: negative_response(
                    op::ResponseCode::NXDomain,
                    "proxy.example.com.",
                    300,
                    60,
                ),
                hits: main_hits.clone(),
                id: "ordinary-negative-dns",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: Arc::new(AtomicUsize::new(0)),
            id: "node-dns",
        })]);
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        let mut query = test_query_with_type(rr::RecordType::TXT);
        query.metadata.recursion_desired = true;
        for _ in 0..2 {
            let response = resolver.exchange(&query).await.unwrap();
            assert_eq!(response.metadata.response_code, op::ResponseCode::NXDomain);
            assert_eq!(main_hits.load(Ordering::SeqCst), 1);
            assert!(
                resolver
                    .cached_negative(&query.queries[0], &query, Instant::now())
                    .is_none()
            );
        }
    }

    #[tokio::test]
    async fn last_provider_owner_removal_invalidates_preexisting_public_cache() {
        // Two provider sets can own the same endpoint concurrently. Dropping
        // one owner must not reclassify the hostname as public; dropping the
        // final owner must not resurrect a pre-registration cache entry.
        let main_hits = Arc::new(AtomicUsize::new(0));
        let node_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 12)),
                hits: main_hits.clone(),
                id: "ordinary-public-dns",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: node_hits.clone(),
            id: "node-dns",
        })]);
        let mut query = test_query_with_type(rr::RecordType::A);
        query.metadata.recursion_desired = true;
        let mut stale = response_with_a(Ipv4Addr::new(192, 0, 2, 10));
        stale.answers[0].ttl = 120;
        resolver.lru_cache.as_ref().unwrap().insert(
            query.queries[0].clone(),
            Ok(stale),
            Instant::now(),
        );
        for owner in ["owner-a", "owner-b"] {
            resolver
                .replace_proxy_provider_dns_domains(
                    owner,
                    vec!["proxy.example.com".into()],
                )
                .await
                .unwrap();
        }
        resolver
            .replace_proxy_provider_dns_domains("owner-a", vec![])
            .await
            .unwrap();
        let node = resolver.exchange(&query).await.unwrap();
        assert_eq!(
            EnhancedResolver::ip_list_of_message(&node),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))]
        );
        assert_eq!(main_hits.load(Ordering::SeqCst), 0);
        assert_eq!(node_hits.load(Ordering::SeqCst), 1);
        resolver
            .replace_proxy_provider_dns_domains("owner-b", vec![])
            .await
            .unwrap();
        let public = resolver.exchange(&query).await.unwrap();
        assert_eq!(
            EnhancedResolver::ip_list_of_message(&public),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 12))]
        );
        assert_eq!(main_hits.load(Ordering::SeqCst), 1);
        assert_eq!(node_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn former_provider_public_positive_answer_hits_current_generation_cache() {
        let main_hits = Arc::new(AtomicUsize::new(0));
        let node_hits = Arc::new(AtomicUsize::new(0));
        let mut answer = response_with_a(Ipv4Addr::new(192, 0, 2, 42));
        answer.answers[0].ttl = 180;
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: answer,
                hits: main_hits.clone(),
                id: "public-new-epoch",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: node_hits.clone(),
            id: "dedicated-node",
        })]);
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        let mut query = test_query_with_type(rr::RecordType::A);
        query.metadata.recursion_desired = true;
        for (index, id) in [37, 38].into_iter().enumerate() {
            query.metadata.id = id;
            let answer = resolver.exchange(&query).await.unwrap();
            if index > 0 {
                // The synthetic CountingClient fixture does not echo IDs;
                // only the cached response must copy the requesting ID.
                assert_eq!(answer.metadata.id, id);
            }
            assert_eq!(
                EnhancedResolver::ip_list_of_message(&answer),
                vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42))]
            );
        }
        assert_eq!(
            main_hits.load(Ordering::SeqCst),
            1,
            "a former provider hostname should reuse only answers from its current generation"
        );
        assert_eq!(node_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn former_provider_public_negative_answer_hits_current_generation_cache() {
        let main_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: negative_response(
                    op::ResponseCode::NXDomain,
                    "proxy.example.com.",
                    120,
                    60,
                ),
                hits: main_hits.clone(),
                id: "public-negative-new-epoch",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: Arc::new(AtomicUsize::new(0)),
            id: "dedicated-node",
        })]);
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        let mut query = test_query_with_type(rr::RecordType::TXT);
        query.metadata.recursion_desired = true;
        for (index, id) in [91, 92].into_iter().enumerate() {
            query.metadata.id = id;
            let response = resolver.exchange(&query).await.unwrap();
            if index > 0 {
                assert_eq!(response.metadata.id, id);
            }
            assert_eq!(response.metadata.response_code, op::ResponseCode::NXDomain);
        }
        assert_eq!(
            main_hits.load(Ordering::SeqCst),
            1,
            "the current-epoch negative cache should obey RFC 2308 TTL"
        );
    }

    #[tokio::test]
    async fn provider_epoch_cache_survives_unrelated_provider_registry_updates() {
        let main_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 42)),
                hits: main_hits.clone(),
                id: "ordinary-public-dns",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: Arc::new(AtomicUsize::new(0)),
            id: "dedicated-node",
        })]);
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        let mut query = test_query_with_type(rr::RecordType::A);
        query.metadata.recursion_desired = true;
        resolver.exchange(&query).await.unwrap();
        assert_eq!(main_hits.load(Ordering::SeqCst), 1);
        resolver
            .replace_proxy_provider_dns_domains(
                "other-owner",
                vec!["unrelated.example.com".into(), "another.example.com".into()],
            )
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("other-owner", vec![])
            .await
            .unwrap();
        resolver.exchange(&query).await.unwrap();
        assert_eq!(
            main_hits.load(Ordering::SeqCst),
            1,
            "other domains' ownership updates must not invalidate this epoch"
        );
    }

    #[tokio::test]
    async fn provider_epoch_cache_preserves_cache_safe_request_policy() {
        let main_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 42)),
                hits: main_hits.clone(),
                id: "ordinary-public-dns",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: Arc::new(AtomicUsize::new(0)),
            id: "dedicated-node",
        })]);
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        let mut query = test_query_with_type(rr::RecordType::A);
        query.metadata.recursion_desired = true;
        query.metadata.checking_disabled = true;
        assert!(!EnhancedResolver::cache_safe_request(&query));
        resolver.exchange(&query).await.unwrap();
        resolver.exchange(&query).await.unwrap();
        assert_eq!(
            main_hits.load(Ordering::SeqCst),
            2,
            "requests with different CD semantics must not share Question-only cached answers"
        );
        assert_eq!(resolver.provider_epoch_cache.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn provider_epoch_cache_is_invalidated_on_next_ownership_cycle() {
        let main_hits = Arc::new(AtomicUsize::new(0));
        let node_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 42)),
                hits: main_hits.clone(),
                id: "new-public-dns",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: node_hits.clone(),
            id: "dedicated-node",
        })]);
        let mut query = test_query_with_type(rr::RecordType::A);
        query.metadata.recursion_desired = true;
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        resolver.exchange(&query).await.unwrap();
        resolver.exchange(&query).await.unwrap();
        assert_eq!(main_hits.load(Ordering::SeqCst), 1);
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        let node = resolver.exchange(&query).await.unwrap();
        assert_eq!(
            EnhancedResolver::ip_list_of_message(&node),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))]
        );
        assert_eq!(main_hits.load(Ordering::SeqCst), 1);
        assert_eq!(node_hits.load(Ordering::SeqCst), 1);
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        resolver.exchange(&query).await.unwrap();
        assert_eq!(
            main_hits.load(Ordering::SeqCst),
            2,
            "the prior ownership generation's cached public answer must not survive ABA"
        );
        resolver.exchange(&query).await.unwrap();
        assert_eq!(
            main_hits.load(Ordering::SeqCst),
            2,
            "the latest generation must be independently cacheable"
        );
    }

    // The epoch cache uses the same final revalidation as shared cache hits.
    // A provider ABA after selecting a cached candidate must invalidate it.
    async fn assert_provider_epoch_cache_candidate_rejects_aba(negative: bool) {
        let main_hits = Arc::new(AtomicUsize::new(0));
        let node_hits = Arc::new(AtomicUsize::new(0));
        let response = if negative {
            negative_response(
                op::ResponseCode::NXDomain,
                "proxy.example.com.",
                120,
                60,
            )
        } else {
            response_with_a(Ipv4Addr::new(192, 0, 2, 42))
        };
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response,
                hits: main_hits.clone(),
                id: "public-epoch-dns",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: node_hits.clone(),
            id: "dedicated-node",
        })]);
        let resolver = Arc::new(resolver);
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        let mut request = test_query_with_type(if negative {
            rr::RecordType::TXT
        } else {
            rr::RecordType::A
        });
        request.metadata.recursion_desired = true;
        // Populate only the current epoch (no pre-provider shared entry).
        resolver.exchange(&request).await.unwrap();
        assert_eq!(main_hits.load(Ordering::SeqCst), 1);
        let selected = Arc::new(tokio::sync::Barrier::new(2));
        let resume = Arc::new(tokio::sync::Barrier::new(2));
        let running = {
            let resolver = resolver.clone();
            let selected = selected.clone();
            let resume = resume.clone();
            tokio::spawn(async move {
                CACHE_CANDIDATE_TEST_PAUSE
                    .scope(
                        CacheCandidateTestPause {
                            kind: if negative {
                                CacheCandidateKind::Negative
                            } else {
                                CacheCandidateKind::Positive
                            },
                            selected,
                            resume,
                        },
                        async move { resolver.exchange(&request).await },
                    )
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(5), selected.wait())
            .await
            .expect("epoch cache hit was not selected");
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), resume.wait())
            .await
            .expect("epoch cache handoff did not resume");
        let result = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_err(), "obsolete cached epoch must fail closed");
        assert_eq!(main_hits.load(Ordering::SeqCst), 1);
        assert_eq!(node_hits.load(Ordering::SeqCst), 0);
        let mut retry = test_query_with_type(if negative {
            rr::RecordType::TXT
        } else {
            rr::RecordType::A
        });
        retry.metadata.recursion_desired = true;
        resolver.exchange(&retry).await.unwrap();
        assert_eq!(
            main_hits.load(Ordering::SeqCst),
            2,
            "a new epoch needs an independent ordinary DNS lookup"
        );
    }

    #[tokio::test]
    async fn public_query_started_in_former_provider_epoch_rejects_later_aba() {
        // An ordinary DNS lookup can be in flight while a former node is
        // re-registered and removed again. The result must neither return
        // nor enter a newly authorized epoch cache after this transition.
        let entered = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(PausedClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 42)),
                entered: entered.clone(),
                resume: resume.clone(),
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: Arc::new(AtomicUsize::new(0)),
            id: "dedicated-node",
        })]);
        let resolver = Arc::new(resolver);
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        let mut query = test_query_with_type(rr::RecordType::A);
        query.metadata.recursion_desired = true;
        let running = {
            let resolver = resolver.clone();
            let query = query.clone();
            tokio::spawn(async move { resolver.exchange(&query).await })
        };
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .expect("public lookup did not start");
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        resume.notify_one();
        let result = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_err(), "pre-transition answer must be rejected");
        let latest = resolver
            .provider_domain_generation("proxy.example.com")
            .await;
        assert!(
            resolver
                .cached_provider_epoch_response(
                    &query.queries[0],
                    &query,
                    latest,
                    Instant::now(),
                )
                .is_none(),
            "rejected response must not poison current epoch cache"
        );
    }

    #[tokio::test]
    async fn provider_epoch_positive_cache_handoff_rejects_aba() {
        assert_provider_epoch_cache_candidate_rejects_aba(false).await;
    }

    #[tokio::test]
    async fn provider_epoch_negative_cache_handoff_rejects_aba() {
        assert_provider_epoch_cache_candidate_rejects_aba(true).await;
    }

    #[test]
    fn provider_epoch_nodata_txt_cache_uses_soa_minimum_and_expires() {
        // Service-discovery TXT/NODATA must preserve NoError and respect
        // the RFC 2308 SOA minimum, not retain an outdated negative forever.
        let resolver = EnhancedResolver::from_clients(vec![], false);
        let mut query = test_query_with_type(rr::RecordType::TXT);
        query.metadata.recursion_desired = true;
        let now = Instant::now();
        let nodata = negative_response(
            op::ResponseCode::NoError,
            "proxy.example.com.",
            120,
            30,
        );
        resolver.cache_provider_epoch_response(&query.queries[0], &nodata, 9, now);
        let fresh = resolver
            .cached_provider_epoch_response(
                &query.queries[0],
                &query,
                9,
                now + Duration::from_secs(10),
            )
            .expect("fresh NODATA should be cached within SOA lifetime");
        assert_eq!(fresh.metadata.response_code, op::ResponseCode::NoError);
        assert!(fresh.answers.is_empty());
        assert_eq!(fresh.authorities[0].ttl, 20);
        assert!(
            resolver
                .cached_provider_epoch_response(
                    &query.queries[0],
                    &query,
                    9,
                    now + Duration::from_secs(30),
                )
                .is_none(),
            "NODATA should expire at min(SOA TTL, SOA.MINIMUM)"
        );
    }

    #[tokio::test]
    async fn provider_epoch_cache_enforces_ttl_and_owner_generation() {
        let resolver = EnhancedResolver::from_clients(vec![], false);
        let request = test_query_with_type(rr::RecordType::A);
        let query = &request.queries[0];
        let now = Instant::now();
        let mut positive = response_with_a(Ipv4Addr::new(192, 0, 2, 42));
        positive.answers[0].ttl = 2;
        resolver.cache_provider_epoch_response(query, &positive, 7, now);
        let at_one = resolver
            .cached_provider_epoch_response(
                query,
                &request,
                7,
                now + Duration::from_secs(1),
            )
            .expect("TTL=2 public answer should be valid after one second");
        assert_eq!(at_one.answers[0].ttl, 1);
        assert!(
            resolver
                .cached_provider_epoch_response(
                    query,
                    &request,
                    7,
                    now + Duration::from_secs(2),
                )
                .is_none(),
            "expired answers must fail closed"
        );
        resolver.cache_provider_epoch_response(query, &positive, 7, now);
        assert!(
            resolver
                .cached_provider_epoch_response(query, &request, 8, now)
                .is_none(),
            "a new ownership generation must reject an old cached answer"
        );

        let mut txt_request = test_query_with_type(rr::RecordType::TXT);
        txt_request.metadata.recursion_desired = true;
        let negative = negative_response(
            op::ResponseCode::NXDomain,
            "proxy.example.com.",
            120,
            2,
        );
        let txt_query = &txt_request.queries[0];
        resolver.cache_provider_epoch_response(txt_query, &negative, 8, now);
        let at_one = resolver
            .cached_provider_epoch_response(
                txt_query,
                &txt_request,
                8,
                now + Duration::from_secs(1),
            )
            .expect("RFC 2308 negative TTL=2 must be valid at one second");
        assert_eq!(at_one.metadata.response_code, op::ResponseCode::NXDomain);
        assert!(
            resolver
                .cached_provider_epoch_response(
                    txt_query,
                    &txt_request,
                    8,
                    now + Duration::from_secs(2),
                )
                .is_none(),
            "negative SOA minimum expiry must be enforced"
        );
    }

    #[tokio::test]
    async fn static_node_uses_normalized_qname_before_public_cache_selection() {
        let public_hits = Arc::new(AtomicUsize::new(0));
        let node_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 42)),
                hits: public_hits.clone(),
                id: "public-dns",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: node_hits.clone(),
            id: "dedicated-node-dns",
        })]);
        let mut domains = crate::common::trie::StringTrie::new();
        domains.insert("proxy.example.com", Arc::new(true));
        resolver.proxy_server_domains = Some(domains);
        let mut query = test_query_with_type(rr::RecordType::A);
        query.queries[0]
            .set_name(rr::Name::from_ascii("PrOxY.ExAmPlE.CoM.").unwrap());
        query.metadata.recursion_desired = true;
        let mut old_public = response_with_a(Ipv4Addr::new(192, 0, 2, 10));
        old_public.answers[0].ttl = 120;
        resolver.lru_cache.as_ref().unwrap().insert(
            query.queries[0].clone(),
            Ok(old_public),
            Instant::now(),
        );
        // This gate is intentionally never opened. If static classification
        // misses the QNAME, the generic-cache branch will deadlock at the
        // deterministic test pause and the timeout will reveal the bypass.
        let paused = CacheCandidateTestPause {
            kind: CacheCandidateKind::Positive,
            selected: Arc::new(tokio::sync::Barrier::new(2)),
            resume: Arc::new(tokio::sync::Barrier::new(2)),
        };
        let reply = tokio::time::timeout(
            Duration::from_secs(3),
            CACHE_CANDIDATE_TEST_PAUSE
                .scope(paused, async { resolver.exchange(&query).await }),
        )
        .await
        .expect(
            "static node must bypass the generic cache before candidate selection",
        )
        .unwrap();
        assert_eq!(
            EnhancedResolver::ip_list_of_message(&reply),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))]
        );
        assert_eq!(node_hits.load(Ordering::SeqCst), 1);
        assert_eq!(public_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn network_reset_during_static_proxy_node_query_fails_closed() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        let public_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 42)),
                hits: public_hits.clone(),
                id: "public-dns",
            })],
            false,
        );
        resolver.proxy_resolver = Some(vec![Arc::new(PausedClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            entered: entered.clone(),
            resume: resume.clone(),
        })]);
        let mut domains = crate::common::trie::StringTrie::new();
        domains.insert("proxy.example.com", Arc::new(true));
        resolver.proxy_server_domains = Some(domains);
        let resolver = Arc::new(resolver);
        let mut query = test_query_with_type(rr::RecordType::A);
        query.metadata.recursion_desired = true;
        let running = {
            let resolver = resolver.clone();
            tokio::spawn(async move { resolver.exchange(&query).await })
        };
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .expect("static node DNS query did not begin");
        resolver.reset_transports().await.unwrap();
        resume.notify_one();
        let result = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.is_err(),
            "old-network static node DNS response must fail closed"
        );
        assert_eq!(
            public_hits.load(Ordering::SeqCst),
            0,
            "static node DNS must not downgrade to public DNS after reset"
        );
    }

    #[tokio::test]
    async fn network_reset_during_active_provider_node_query_fails_closed() {
        // A dedicated node-DNS request started on an old network must not
        // return that network's IP after a transport reset completes.
        let entered = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        let public_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 42)),
                hits: public_hits.clone(),
                id: "public-dns",
            })],
            false,
        );
        resolver.proxy_resolver = Some(vec![Arc::new(PausedClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            entered: entered.clone(),
            resume: resume.clone(),
        })]);
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        let resolver = Arc::new(resolver);
        let mut query = test_query_with_type(rr::RecordType::A);
        query.metadata.recursion_desired = true;
        let running = {
            let resolver = resolver.clone();
            tokio::spawn(async move { resolver.exchange(&query).await })
        };
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .expect("node DNS query did not start");
        resolver.reset_transports().await.unwrap();
        resume.notify_one();
        let result = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.is_err(),
            "old-network node DNS result must fail closed"
        );
        assert_eq!(
            public_hits.load(Ordering::SeqCst),
            0,
            "node DNS failure must not fall back to public DNS"
        );
    }

    #[tokio::test]
    async fn network_reset_does_not_downgrade_active_provider_to_public_dns() {
        let public_hits = Arc::new(AtomicUsize::new(0));
        let node_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 42)),
                hits: public_hits.clone(),
                id: "public-dns",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: node_hits.clone(),
            id: "node-dns",
        })]);
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        resolver.reset_transports().await.unwrap();
        let mut query = test_query_with_type(rr::RecordType::A);
        query.metadata.recursion_desired = true;
        let response = resolver.exchange(&query).await.unwrap();
        assert_eq!(
            EnhancedResolver::ip_list_of_message(&response),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))]
        );
        assert_eq!(public_hits.load(Ordering::SeqCst), 0);
        assert_eq!(node_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn new_network_former_provider_query_caches_after_reset() {
        let public_hits = Arc::new(AtomicUsize::new(0));
        let node_hits = Arc::new(AtomicUsize::new(0));
        let mut answer = response_with_a(Ipv4Addr::new(192, 0, 2, 42));
        answer.answers[0].ttl = 120;
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: answer,
                hits: public_hits.clone(),
                id: "post-reset-public-dns",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: node_hits.clone(),
            id: "dedicated-node-dns",
        })]);
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        resolver.reset_transports().await.unwrap();
        let mut query = test_query_with_type(rr::RecordType::A);
        query.metadata.recursion_desired = true;
        for _ in 0..2 {
            let result = resolver.exchange(&query).await.unwrap();
            assert_eq!(
                EnhancedResolver::ip_list_of_message(&result),
                vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42))]
            );
        }
        assert_eq!(
            public_hits.load(Ordering::SeqCst),
            1,
            "fresh network must retain legitimate current-epoch cache acceleration"
        );
        assert_eq!(node_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn network_reset_rejects_stale_epoch_cache_writer_under_same_lock() {
        let resolver = EnhancedResolver::from_clients(vec![], false);
        let request = test_query_with_type(rr::RecordType::A);
        let now = Instant::now();
        let mut answer = response_with_a(Ipv4Addr::new(192, 0, 2, 42));
        answer.answers[0].ttl = 120;
        let old_network = resolver
            .provider_epoch_network_generation
            .load(Ordering::Relaxed);
        resolver.reset_transports().await.unwrap();
        resolver.cache_provider_epoch_response_for_network(
            &request.queries[0],
            &answer,
            7,
            now,
            Some(old_network),
        );
        assert!(
            resolver
                .cached_provider_epoch_response(
                    &request.queries[0],
                    &request,
                    7,
                    now,
                )
                .is_none(),
            "a pre-reset writer must not repopulate the new network cache"
        );
        let new_network = resolver
            .provider_epoch_network_generation
            .load(Ordering::Relaxed);
        assert_ne!(new_network, old_network);
        resolver.cache_provider_epoch_response_for_network(
            &request.queries[0],
            &answer,
            7,
            now,
            Some(new_network),
        );
        assert!(
            resolver
                .cached_provider_epoch_response(
                    &request.queries[0],
                    &request,
                    7,
                    now,
                )
                .is_some(),
            "a fresh-network response should remain cacheable"
        );
    }

    #[tokio::test]
    async fn network_reset_during_former_provider_lookup_must_not_reseed_epoch_cache()
     {
        // The upstream may finish after network-path reset has cleared the
        // epoch cache. Its answer belongs to the old network and must not
        // repopulate a cache for the new split-DNS path.
        let entered = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(PausedClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 42)),
                entered: entered.clone(),
                resume: resume.clone(),
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: Arc::new(AtomicUsize::new(0)),
            id: "dedicated-node-dns",
        })]);
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        let resolver = Arc::new(resolver);
        let mut request = test_query_with_type(rr::RecordType::A);
        request.metadata.recursion_desired = true;
        let pending = {
            let resolver = resolver.clone();
            let query = request.clone();
            tokio::spawn(async move { resolver.exchange(&query).await })
        };
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .expect("ordinary lookup did not begin");
        resolver.reset_transports().await.unwrap();
        resume.notify_one();
        let result = tokio::time::timeout(Duration::from_secs(5), pending)
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.is_err(),
            "old network's public DNS answer must fail closed after reset"
        );
        let generation = resolver
            .provider_domain_generation("proxy.example.com")
            .await;
        assert!(
            resolver
                .cached_provider_epoch_response(
                    &request.queries[0],
                    &request,
                    generation,
                    Instant::now(),
                )
                .is_none(),
            "stale old-network response must not reseed the cache"
        );
    }

    async fn assert_network_reset_rejects_selected_provider_epoch_cache(
        negative: bool,
    ) {
        let main_hits = Arc::new(AtomicUsize::new(0));
        let response = if negative {
            negative_response(
                op::ResponseCode::NXDomain,
                "proxy.example.com.",
                120,
                60,
            )
        } else {
            response_with_a(Ipv4Addr::new(192, 0, 2, 42))
        };
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response,
                hits: main_hits.clone(),
                id: "public-dns",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: Arc::new(AtomicUsize::new(0)),
            id: "dedicated-node-dns",
        })]);
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        let resolver = Arc::new(resolver);
        let mut query = test_query_with_type(if negative {
            rr::RecordType::TXT
        } else {
            rr::RecordType::A
        });
        query.metadata.recursion_desired = true;
        resolver.exchange(&query).await.unwrap();
        assert_eq!(main_hits.load(Ordering::SeqCst), 1);
        let selected = Arc::new(tokio::sync::Barrier::new(2));
        let resume = Arc::new(tokio::sync::Barrier::new(2));
        let running = {
            let resolver = resolver.clone();
            let selected = selected.clone();
            let resume = resume.clone();
            tokio::spawn(async move {
                CACHE_CANDIDATE_TEST_PAUSE
                    .scope(
                        CacheCandidateTestPause {
                            kind: if negative {
                                CacheCandidateKind::Negative
                            } else {
                                CacheCandidateKind::Positive
                            },
                            selected,
                            resume,
                        },
                        async move { resolver.exchange(&query).await },
                    )
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(5), selected.wait())
            .await
            .expect("the epoch cache candidate was not selected");
        resolver.reset_transports().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), resume.wait())
            .await
            .expect("cached query did not resume");
        let result = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.is_err(),
            "a previously selected epoch cache response cannot survive network reset"
        );
        assert_eq!(main_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn network_reset_rejects_selected_positive_provider_epoch_cache() {
        assert_network_reset_rejects_selected_provider_epoch_cache(false).await;
    }

    #[tokio::test]
    async fn network_reset_rejects_selected_negative_provider_epoch_cache() {
        assert_network_reset_rejects_selected_provider_epoch_cache(true).await;
    }

    #[test]
    fn stale_writer_must_not_replace_newer_provider_epoch_cache_entry() {
        // An older public query can finish just after a newer generation's
        // response has been cached. The stale writer must not replace it.
        let resolver = EnhancedResolver::from_clients(vec![], false);
        let request = test_query_with_type(rr::RecordType::A);
        let now = Instant::now();
        let mut newer = response_with_a(Ipv4Addr::new(192, 0, 2, 42));
        newer.answers[0].ttl = 120;
        resolver.cache_provider_epoch_response(&request.queries[0], &newer, 8, now);
        let mut older = response_with_a(Ipv4Addr::new(192, 0, 2, 43));
        older.answers[0].ttl = 120;
        resolver.cache_provider_epoch_response(&request.queries[0], &older, 7, now);
        let cached = resolver
            .cached_provider_epoch_response(&request.queries[0], &request, 8, now)
            .expect("a stale writer must not remove a newer valid answer");
        assert_eq!(
            EnhancedResolver::ip_list_of_message(&cached),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42))]
        );
    }

    #[test]
    fn stale_reader_must_not_evict_newer_provider_epoch_cache_entry() {
        // An older in-flight query can hold generation 7 while another
        // query has already populated generation 8. A stale lookup should
        // miss, but it must not evict generation 8's valid response.
        let resolver = EnhancedResolver::from_clients(vec![], false);
        let request = test_query_with_type(rr::RecordType::A);
        let now = Instant::now();
        let mut current = response_with_a(Ipv4Addr::new(192, 0, 2, 42));
        current.answers[0].ttl = 120;
        resolver.cache_provider_epoch_response(
            &request.queries[0],
            &current,
            8,
            now,
        );
        assert!(
            resolver
                .cached_provider_epoch_response(
                    &request.queries[0],
                    &request,
                    7,
                    now,
                )
                .is_none()
        );
        assert!(
            resolver
                .cached_provider_epoch_response(
                    &request.queries[0],
                    &request,
                    8,
                    now,
                )
                .is_some(),
            "stale generation must not evict newer valid cache entry"
        );
    }

    #[test]
    fn provider_epoch_positive_ttl_is_clamped_to_hickory_default_max() {
        let resolver = EnhancedResolver::from_clients(vec![], false);
        let request = test_query_with_type(rr::RecordType::A);
        let now = Instant::now();
        let mut long_ttl = response_with_a(Ipv4Addr::new(192, 0, 2, 42));
        long_ttl.answers[0].ttl = PROVIDER_EPOCH_CACHE_MAX_TTL + 60;
        resolver.cache_provider_epoch_response(
            &request.queries[0],
            &long_ttl,
            1,
            now,
        );
        let cached = resolver
            .cached_provider_epoch_response(&request.queries[0], &request, 1, now)
            .expect("cache entry should exist at insertion time");
        assert_eq!(cached.answers[0].ttl, PROVIDER_EPOCH_CACHE_MAX_TTL);
    }

    #[test]
    fn provider_epoch_cache_keys_names_case_insensitively_and_separates_record_types()
     {
        let resolver = EnhancedResolver::from_clients(vec![], false);
        let mut lower = test_query_with_type(rr::RecordType::A);
        lower.metadata.recursion_desired = true;
        let now = Instant::now();
        let mut response = response_with_a(Ipv4Addr::new(192, 0, 2, 42));
        response.answers[0].ttl = 120;
        resolver.cache_provider_epoch_response(&lower.queries[0], &response, 5, now);
        let mut upper = test_query_with_type(rr::RecordType::A);
        upper.queries[0]
            .set_name(rr::Name::from_ascii("PrOxY.ExAmPlE.CoM.").unwrap());
        upper.metadata.id = 3456;
        let hit = resolver
            .cached_provider_epoch_response(&upper.queries[0], &upper, 5, now)
            .expect("case variants of a DNS QNAME must share an epoch entry");
        assert_eq!(hit.metadata.id, 3456);
        assert_eq!(hit.queries, upper.queries);
        let txt = test_query_with_type(rr::RecordType::TXT);
        assert!(
            resolver
                .cached_provider_epoch_response(&txt.queries[0], &txt, 5, now,)
                .is_none(),
            "different record types must not share an epoch answer"
        );
    }

    #[test]
    fn provider_epoch_cache_does_not_store_zero_ttl_or_untrusted_responses() {
        let resolver = EnhancedResolver::from_clients(vec![], false);
        let request = test_query_with_type(rr::RecordType::A);
        let query = &request.queries[0];
        let now = Instant::now();
        let mut zero_ttl = response_with_a(Ipv4Addr::new(192, 0, 2, 42));
        zero_ttl.answers[0].ttl = 0;
        resolver.cache_provider_epoch_response(query, &zero_ttl, 5, now);
        assert!(
            resolver
                .cached_provider_epoch_response(query, &request, 5, now)
                .is_none()
        );
        let negative = negative_response(
            op::ResponseCode::NXDomain,
            "proxy.example.com.",
            300,
            0,
        );
        resolver.cache_provider_epoch_response(query, &negative, 5, now);
        assert!(
            resolver
                .cached_provider_epoch_response(query, &request, 5, now)
                .is_none()
        );
        let mut invalid = response_with_a(Ipv4Addr::new(192, 0, 2, 42));
        invalid.metadata.truncation = true;
        resolver.cache_provider_epoch_response(query, &invalid, 5, now);
        assert!(
            resolver
                .cached_provider_epoch_response(query, &request, 5, now)
                .is_none()
        );
    }

    #[test]
    fn provider_epoch_cache_rejects_authenticated_negative_and_non_response_messages()
     {
        let resolver = EnhancedResolver::from_clients(vec![], false);
        let request = test_query_with_type(rr::RecordType::A);
        let query = &request.queries[0];
        let now = Instant::now();
        let mut negative = negative_response(
            op::ResponseCode::NXDomain,
            "proxy.example.com.",
            120,
            60,
        );
        negative.metadata.authentic_data = true;
        resolver.cache_provider_epoch_response(query, &negative, 5, now);
        assert!(
            resolver
                .cached_provider_epoch_response(query, &request, 5, now)
                .is_none(),
            "an AD response cannot be merged into an unsigned Question-only cache"
        );
        let mut not_response = response_with_a(Ipv4Addr::new(192, 0, 2, 42));
        not_response.metadata.message_type = op::MessageType::Query;
        resolver.cache_provider_epoch_response(query, &not_response, 5, now);
        assert!(
            resolver
                .cached_provider_epoch_response(query, &request, 5, now)
                .is_none(),
            "invalid DNS message type cannot enter the cache"
        );
    }

    #[tokio::test]
    async fn former_provider_domain_with_cache_disabled_still_queries_live_dns() {
        let hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 42)),
                hits: hits.clone(),
                id: "ordinary-uncached-dns",
            })],
            false,
        );
        assert!(resolver.lru_cache.is_none());
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: Arc::new(AtomicUsize::new(0)),
            id: "dedicated-node",
        })]);
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        let mut query = test_query_with_type(rr::RecordType::A);
        query.metadata.recursion_desired = true;
        resolver.exchange(&query).await.unwrap();
        resolver.exchange(&query).await.unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert_eq!(resolver.provider_epoch_cache.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn provider_epoch_cache_has_bounded_capacity_and_network_reset_flushes() {
        let resolver = EnhancedResolver::from_clients(vec![], false);
        let now = Instant::now();
        let mut request = test_query_with_type(rr::RecordType::A);
        let mut response = response_with_a(Ipv4Addr::new(192, 0, 2, 42));
        response.answers[0].ttl = 120;
        for index in 0..=PROVIDER_EPOCH_CACHE_CAPACITY {
            request.queries[0].set_name(
                rr::Name::from_ascii(format!("unique-{index}.example.com."))
                    .unwrap(),
            );
            resolver.cache_provider_epoch_response(
                &request.queries[0],
                &response,
                1,
                now,
            );
        }
        let len = resolver.provider_epoch_cache.lock().unwrap().len();
        assert_eq!(len, PROVIDER_EPOCH_CACHE_CAPACITY);
        request.queries[0]
            .set_name(rr::Name::from_ascii("unique-0.example.com.").unwrap());
        assert!(
            resolver
                .cached_provider_epoch_response(
                    &request.queries[0],
                    &request,
                    1,
                    now,
                )
                .is_none(),
            "LRU must evict its oldest entry"
        );
        request.queries[0].set_name(
            rr::Name::from_ascii(format!(
                "unique-{}.example.com.",
                PROVIDER_EPOCH_CACHE_CAPACITY
            ))
            .unwrap(),
        );
        assert!(
            resolver
                .cached_provider_epoch_response(
                    &request.queries[0],
                    &request,
                    1,
                    now,
                )
                .is_some(),
            "newest entry should remain cached"
        );
        resolver.reset_transports().await.unwrap();
        assert!(
            resolver
                .cached_provider_epoch_response(
                    &request.queries[0],
                    &request,
                    1,
                    now,
                )
                .is_none(),
            "network transitions must flush policy-sensitive entries"
        );
    }

    #[tokio::test]
    async fn unrelated_public_cache_still_hits_after_provider_ownership_aba() {
        // Cache suppression must be domain-scoped. An unrelated ordinary
        // hostname keeps the existing shared-cache behavior and performance.
        let main_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 22)),
                hits: main_hits.clone(),
                id: "ordinary-public-dns",
            })],
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: Arc::new(AtomicUsize::new(0)),
            id: "node-dns",
        })]);
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        let mut query = test_query_with_type(rr::RecordType::A);
        query.queries[0]
            .set_name(rr::Name::from_ascii("ordinary.example.com.").unwrap());
        query.metadata.recursion_desired = true;
        let first = resolver.exchange(&query).await.unwrap();
        let second = resolver.exchange(&query).await.unwrap();
        assert_eq!(
            EnhancedResolver::ip_list_of_message(&second),
            EnhancedResolver::ip_list_of_message(&first)
        );
        assert_eq!(main_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn provider_node_dns_ownership_is_per_provider_and_removed_on_empty_refresh()
     {
        let public_hits = Arc::new(AtomicUsize::new(0));
        let node_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
                hits: public_hits.clone(),
                id: "main",
            })],
            false,
        );
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: node_hits.clone(),
            id: "node",
        })]);
        resolver
            .replace_proxy_provider_dns_domains(
                "provider-A",
                vec!["Shared.Example".into()],
            )
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains(
                "provider-B",
                vec!["shared.example".into()],
            )
            .await
            .unwrap();
        let mut q = test_query_with_type(rr::RecordType::A);
        q.queries[0].set_name(rr::Name::from_utf8("shared.example.").unwrap());
        resolver.ip_exchange(&q).await.unwrap();
        assert_eq!(node_hits.load(Ordering::SeqCst), 1);
        resolver
            .replace_proxy_provider_dns_domains("provider-A", vec![])
            .await
            .unwrap();
        resolver.ip_exchange(&q).await.unwrap();
        assert_eq!(
            node_hits.load(Ordering::SeqCst),
            2,
            "provider-B still owns the name"
        );
        resolver
            .replace_proxy_provider_dns_domains("provider-B", vec![])
            .await
            .unwrap();
        resolver.ip_exchange(&q).await.unwrap();
        assert_eq!(node_hits.load(Ordering::SeqCst), 2);
        assert_eq!(
            public_hits.load(Ordering::SeqCst),
            1,
            "unused proxy domain is no longer owned"
        );
    }

    #[tokio::test]
    async fn provider_node_dns_normalizes_unicode_hostname_to_wire_idna() {
        let public_hits = Arc::new(AtomicUsize::new(0));
        let node_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
                hits: public_hits.clone(),
                id: "main",
            })],
            false,
        );
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: node_hits.clone(),
            id: "node",
        })]);
        resolver
            .replace_proxy_provider_dns_domains(
                "unicode-node",
                vec!["bücher.example".into()],
            )
            .await
            .unwrap();
        let mut q = test_query_with_type(rr::RecordType::A);
        q.queries[0]
            .set_name(rr::Name::from_utf8("xn--bcher-kva.example.").unwrap());
        resolver.ip_exchange(&q).await.unwrap();
        assert_eq!(node_hits.load(Ordering::SeqCst), 1);
        assert_eq!(
            public_hits.load(Ordering::SeqCst),
            0,
            "IDNA node must never fall through to public DNS"
        );
    }

    #[tokio::test]
    async fn static_proxy_server_non_address_query_uses_dedicated_node_dns() {
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
            .expect("TXT query for a static proxy endpoint must use dedicated DNS");
        assert_eq!(proxy_hits.load(Ordering::SeqCst), 2);
        assert_eq!(main_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn static_proxy_node_must_not_return_preexisting_public_cache_answer() {
        // Static node bootstrap must never reuse a cached public response.
        let mut resolver = EnhancedResolver::from_clients(vec![], false);
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        let node_hits = Arc::new(AtomicUsize::new(0));
        let main_hits = Arc::new(AtomicUsize::new(0));
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: node_hits.clone(),
            id: "node-dns",
        })]);
        resolver.main = vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
            hits: main_hits.clone(),
            id: "public-dns",
        })];
        let request = test_query_with_type(rr::RecordType::A);
        resolver.lru_cache.as_ref().unwrap().insert(
            request.queries[0].clone(),
            Ok(response_with_a(Ipv4Addr::new(192, 0, 2, 10))),
            Instant::now(),
        );
        let mut domains = crate::common::trie::StringTrie::new();
        domains.insert("proxy.example.com", Arc::new(true));
        resolver.proxy_server_domains = Some(domains);
        let answer = resolver
            .revalidate_public_cache_hit(
                &request,
                response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
            )
            .await
            .unwrap();
        assert_eq!(
            EnhancedResolver::ip_list_of_message(&answer),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))]
        );
        assert_eq!(node_hits.load(Ordering::SeqCst), 1);
        assert_eq!(main_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn static_proxy_txt_specific_policy_failure_must_not_fallback() {
        let mut resolver = EnhancedResolver::from_clients(vec![], false);
        resolver.lru_cache = None;
        let default_hits = Arc::new(AtomicUsize::new(0));
        let main_hits = Arc::new(AtomicUsize::new(0));
        let fallback_hits = Arc::new(AtomicUsize::new(0));
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
            hits: default_hits.clone(),
            id: "node-default",
        })]);
        resolver.main = vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 12)),
            hits: main_hits.clone(),
            id: "public-main",
        })];
        resolver.fallback = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 13)),
            hits: fallback_hits.clone(),
            id: "public-fallback",
        })]);
        let mut selector = crate::common::trie::StringTrie::new();
        selector.insert("proxy.example.com", Arc::new(true));
        let mut static_domains = crate::common::trie::StringTrie::new();
        static_domains.insert("proxy.example.com", Arc::new(true));
        resolver.proxy_server_domains = Some(static_domains);
        resolver.proxy_server_nameserver_policy.push((
            Arc::new(selector),
            vec![Arc::new(FailingClient {
                id: "node-policy",
                reason: "injected dedicated policy outage",
            })],
        ));
        for kind in [rr::RecordType::TXT, rr::RecordType::SRV] {
            let err = resolver
                .exchange(&test_query_with_type(kind))
                .await
                .expect_err("static node policy outage must fail closed");
            assert!(
                err.to_string().contains("injected dedicated policy outage"),
                "{err}"
            );
        }
        assert_eq!(default_hits.load(Ordering::SeqCst), 0);
        assert_eq!(main_hits.load(Ordering::SeqCst), 0);
        assert_eq!(fallback_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn static_proxy_txt_bootstrap_failure_must_not_use_public_dns() {
        let mut resolver = EnhancedResolver::new_default().await;
        resolver.lru_cache = None;
        let main_hits = Arc::new(AtomicUsize::new(0));
        let fallback_hits = Arc::new(AtomicUsize::new(0));
        resolver.proxy_resolver = Some(vec![Arc::new(FailingClient {
            id: "node-only",
            reason: "injected static node DNS outage",
        })]);
        resolver.main = vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(198, 51, 100, 11)),
            hits: main_hits.clone(),
            id: "public-main",
        })];
        resolver.fallback = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(198, 51, 100, 12)),
            hits: fallback_hits.clone(),
            id: "public-fallback",
        })]);
        let mut domains = crate::common::trie::StringTrie::new();
        domains.insert("proxy.example.com", Arc::new(true));
        resolver.proxy_server_domains = Some(domains);
        for kind in [rr::RecordType::TXT, rr::RecordType::SRV] {
            let err = resolver
                .exchange_no_cache(&test_query_with_type(kind))
                .await
                .expect_err("dedicated static node DNS failure must fail closed");
            assert!(
                err.to_string().contains("injected static node DNS outage"),
                "{err}"
            );
        }
        assert_eq!(main_hits.load(Ordering::SeqCst), 0);
        assert_eq!(fallback_hits.load(Ordering::SeqCst), 0);
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
        resolver.policy = Some(Arc::new(policy));
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
        resolver.policy = Some(Arc::new(policy));
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
        resolver.policy = Some(Arc::new(policy));
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
        // Static node answers must not enter the unpartitioned public cache.
        assert_eq!(proxy_hits.load(Ordering::SeqCst), 2);
        assert_eq!(policy_hits.load(Ordering::SeqCst), 0);
        assert_eq!(main_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn proxy_server_policy_uses_specific_upstream_and_dedicated_default() {
        let mut resolver = EnhancedResolver::from_clients(vec![], false);
        let specific_hits = Arc::new(AtomicUsize::new(0));
        let default_hits = Arc::new(AtomicUsize::new(0));
        let main_hits = Arc::new(AtomicUsize::new(0));
        let generic_hits = Arc::new(AtomicUsize::new(0));

        let mut known_proxy_domains = crate::common::trie::StringTrie::new();
        known_proxy_domains.insert("proxy.example.com", Arc::new(true));
        known_proxy_domains.insert("other.example.com", Arc::new(true));
        resolver.proxy_server_domains = Some(known_proxy_domains);
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
            hits: default_hits.clone(),
            id: "proxy-server-default",
        })]);
        let mut specific = crate::common::trie::StringTrie::new();
        specific.insert("proxy.example.com", Arc::new(true));
        resolver.proxy_server_nameserver_policy.push((
            Arc::new(specific),
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
                hits: specific_hits.clone(),
                id: "proxy-server-specific",
            })],
        ));
        let mut general_policy = crate::common::trie::StringTrie::new();
        general_policy.insert(
            "proxy.example.com",
            Arc::new(vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 99)),
                hits: generic_hits.clone(),
                id: "general-policy",
            }) as ThreadSafeDNSClient]),
        );
        resolver.policy = Some(Arc::new(general_policy));
        resolver.main = vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 98)),
            hits: main_hits.clone(),
            id: "public-main",
        })];

        resolver
            .ip_exchange(&test_query_with_type(rr::RecordType::A))
            .await
            .expect("known proxy hostname must use its dedicated policy");
        assert_eq!(specific_hits.load(Ordering::SeqCst), 1);
        assert_eq!(default_hits.load(Ordering::SeqCst), 0);
        assert_eq!(generic_hits.load(Ordering::SeqCst), 0);
        assert_eq!(main_hits.load(Ordering::SeqCst), 0);

        let mut mixed_case_proxy = test_query_with_type(rr::RecordType::A);
        mixed_case_proxy.queries[0]
            .set_name(rr::Name::from_utf8("PrOxY.ExAmPlE.CoM.").unwrap());
        resolver.ip_exchange(&mixed_case_proxy).await.expect(
            "DNS proxy server domains must match regardless of query casing",
        );
        assert_eq!(specific_hits.load(Ordering::SeqCst), 2);
        assert_eq!(default_hits.load(Ordering::SeqCst), 0);
        assert_eq!(main_hits.load(Ordering::SeqCst), 0);

        let mut other_proxy = test_query_with_type(rr::RecordType::A);
        other_proxy.queries[0]
            .set_name(rr::Name::from_utf8("other.example.com.").unwrap());
        resolver.ip_exchange(&other_proxy).await.expect(
            "unmatched proxy node should use dedicated default, not main DNS",
        );
        assert_eq!(default_hits.load(Ordering::SeqCst), 1);
        assert_eq!(specific_hits.load(Ordering::SeqCst), 2);
        assert_eq!(main_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn mixed_case_proxy_server_nameserver_policy_selects_specific_dns_for_a_and_txt()
     {
        // DNS owner names are case-insensitive. Node bootstrap policy is an
        // egress boundary, not a best-effort hint: mixed case must never
        // silently fall through to the default node DNS server.
        let public_hits = Arc::new(AtomicUsize::new(0));
        let default_hits = Arc::new(AtomicUsize::new(0));
        let policy_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 20)),
                hits: public_hits.clone(),
                id: "generic-main",
            })],
            false,
        );
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 21)),
            hits: default_hits.clone(),
            id: "generic-proxy-node-dns",
        })]);
        let mut node_domain = crate::common::trie::StringTrie::new();
        node_domain.insert("proxy.example.com", Arc::new(true));
        resolver.proxy_server_domains = Some(node_domain);
        let mut matcher = crate::common::trie::StringTrie::new();
        matcher.insert("proxy.example.com", Arc::new(true));
        resolver.proxy_server_nameserver_policy.push((
            Arc::new(matcher),
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 22)),
                hits: policy_hits.clone(),
                id: "specific-proxy-node-dns",
            })],
        ));
        for record_type in [rr::RecordType::A, rr::RecordType::TXT] {
            let mut query = test_query_with_type(record_type);
            query.queries[0]
                .set_name(rr::Name::from_ascii("PrOxY.ExAmPlE.CoM.").unwrap());
            query.metadata.recursion_desired = true;
            assert!(resolver.exchange(&query).await.is_ok());
        }
        assert_eq!(
            policy_hits.load(Ordering::SeqCst),
            2,
            "mixed-case node domain must retain its exact per-host DNS policy"
        );
        assert_eq!(
            default_hits.load(Ordering::SeqCst),
            0,
            "per-host node DNS policy must not downgrade to node default"
        );
        assert_eq!(
            public_hits.load(Ordering::SeqCst),
            0,
            "proxy node QNAME must not reach public DNS"
        );
    }

    #[tokio::test]
    async fn mixed_case_dynamic_provider_node_policy_stays_isolated_through_refresh()
    {
        let public_hits = Arc::new(AtomicUsize::new(0));
        let default_hits = Arc::new(AtomicUsize::new(0));
        let specific_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 30)),
                hits: public_hits.clone(),
                id: "public-after-provider-removal",
            })],
            false,
        );
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 31)),
            hits: default_hits.clone(),
            id: "default-node-upstream",
        })]);
        let mut matcher = crate::common::trie::StringTrie::new();
        matcher.insert("proxy.example.com", Arc::new(true));
        resolver.proxy_server_nameserver_policy.push((
            Arc::new(matcher),
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 32)),
                hits: specific_hits.clone(),
                id: "specific-node-upstream",
            })],
        ));
        resolver
            .replace_proxy_provider_dns_domains(
                "provider",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        for record_type in [rr::RecordType::A, rr::RecordType::TXT] {
            let mut query = test_query_with_type(record_type);
            query.queries[0]
                .set_name(rr::Name::from_ascii("PrOxY.ExAmPlE.CoM.").unwrap());
            query.metadata.recursion_desired = true;
            resolver.exchange(&query).await.unwrap();
        }
        assert_eq!(specific_hits.load(Ordering::SeqCst), 2);
        assert_eq!(default_hits.load(Ordering::SeqCst), 0);
        assert_eq!(
            public_hits.load(Ordering::SeqCst),
            0,
            "registered Provider node QNAME must never reach public DNS"
        );
        resolver
            .replace_proxy_provider_dns_domains("provider", vec![])
            .await
            .unwrap();
        let query = test_query_with_type(rr::RecordType::A);
        resolver.exchange(&query).await.unwrap();
        assert_eq!(
            public_hits.load(Ordering::SeqCst),
            1,
            "an unregistered node should regain ordinary routing without stale policy cache"
        );
        assert_eq!(specific_hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn mixed_case_dedicated_outbound_resolver_preserves_node_policy_for_a_and_txt()
     {
        // Outbound DNS dial bootstrap uses a separate EnhancedResolver where
        // `proxy_node_resolver` is true. It must honor the same case-insensitive
        // policy as queries entering the public DNS listener.
        let default_hits = Arc::new(AtomicUsize::new(0));
        let specific_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 31)),
                hits: default_hits.clone(),
                id: "fallback-node-bootstrap",
            })],
            false,
        );
        resolver.proxy_node_resolver = true;
        let mut matcher = crate::common::trie::StringTrie::new();
        matcher.insert("proxy.example.com", Arc::new(true));
        resolver.proxy_server_nameserver_policy.push((
            Arc::new(matcher),
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 32)),
                hits: specific_hits.clone(),
                id: "specific-node-bootstrap",
            })],
        ));
        for record_type in [rr::RecordType::A, rr::RecordType::TXT] {
            let mut query = test_query_with_type(record_type);
            query.queries[0]
                .set_name(rr::Name::from_ascii("PrOxY.ExAmPlE.CoM.").unwrap());
            query.metadata.recursion_desired = true;
            resolver.exchange(&query).await.unwrap();
        }
        assert_eq!(
            specific_hits.load(Ordering::SeqCst),
            2,
            "bootstrap A and TXT must use the per-host resolver policy"
        );
        assert_eq!(
            default_hits.load(Ordering::SeqCst),
            0,
            "node bootstrap QNAME must not fall back to default resolver"
        );
    }

    #[tokio::test]
    async fn dedicated_outbound_resolver_applies_node_dns_policy_before_default() {
        // This is the resolver passed into DNS transports as
        // outbound_resolver, not the top-level DNS listener resolver.
        let default_hits = Arc::new(AtomicUsize::new(0));
        let policy_hits = Arc::new(AtomicUsize::new(0));
        let mut node_resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
                hits: default_hits.clone(),
                id: "node-default",
            })],
            false,
        );
        node_resolver.proxy_node_resolver = true;
        let mut matcher = crate::common::trie::StringTrie::new();
        matcher.insert("node.example.com", Arc::new(true));
        node_resolver.proxy_server_nameserver_policy.push((
            Arc::new(matcher),
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
                hits: policy_hits.clone(),
                id: "node-policy",
            })],
        ));

        assert_eq!(
            node_resolver
                .resolve_v4("node.example.com", false)
                .await
                .unwrap(),
            Some(Ipv4Addr::new(192, 0, 2, 11)),
        );
        assert_eq!(policy_hits.load(Ordering::SeqCst), 1);
        assert_eq!(default_hits.load(Ordering::SeqCst), 0);
        assert_eq!(
            node_resolver
                .resolve_v4("other.example.com", false)
                .await
                .unwrap(),
            Some(Ipv4Addr::new(192, 0, 2, 10)),
        );
        assert_eq!(policy_hits.load(Ordering::SeqCst), 1);
        assert_eq!(default_hits.load(Ordering::SeqCst), 1);
        // DNS QNAME casing must not bypass the dedicated node resolver policy.
        assert_eq!(
            node_resolver
                .resolve_v4("NoDe.ExAmPlE.CoM", false)
                .await
                .unwrap(),
            Some(Ipv4Addr::new(192, 0, 2, 11)),
        );
        assert_eq!(policy_hits.load(Ordering::SeqCst), 2);
        assert_eq!(default_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn node_bootstrap_mixed_case_wire_query_never_uses_default_node_dns() {
        let policy_hits = Arc::new(AtomicUsize::new(0));
        let default_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
                hits: default_hits.clone(),
                id: "node-default",
            })],
            false,
        );
        resolver.proxy_node_resolver = true;
        let mut policy = crate::common::trie::StringTrie::new();
        policy.insert("node.example.com", Arc::new(true));
        resolver.proxy_server_nameserver_policy.push((
            Arc::new(policy),
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
                hits: policy_hits.clone(),
                id: "node-specific",
            })],
        ));
        let mut raw_query = test_query_with_type(rr::RecordType::A);
        raw_query.queries[0]
            .set_name(rr::Name::from_utf8("NoDe.ExAmPlE.CoM.").unwrap());
        resolver.ip_exchange(&raw_query).await.unwrap();
        assert_eq!(
            policy_hits.load(Ordering::SeqCst),
            1,
            "node policy must handle mixed-case wire QNAME"
        );
        assert_eq!(
            default_hits.load(Ordering::SeqCst),
            0,
            "unmatched node policy must not fall back to default node DNS"
        );
    }

    #[tokio::test]
    async fn node_bootstrap_policy_failure_does_not_try_default_or_general_fallback()
    {
        let default_hits = Arc::new(AtomicUsize::new(0));
        let fallback_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
                hits: default_hits.clone(),
                id: "node-default",
            })],
            false,
        );
        resolver.proxy_node_resolver = true;
        resolver.fallback = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 12)),
            hits: fallback_hits.clone(),
            id: "general-fallback",
        })]);
        let mut matcher = crate::common::trie::StringTrie::new();
        matcher.insert("node.example.com", Arc::new(true));
        resolver.proxy_server_nameserver_policy.push((
            Arc::new(matcher),
            vec![Arc::new(FailingClient {
                id: "node-policy",
                reason: "dedicated node DNS offline",
            })],
        ));
        let mut node_query = test_query_with_type(rr::RecordType::A);
        node_query.queries[0]
            .set_name(rr::Name::from_utf8("node.example.com.").unwrap());
        let error = resolver
            .ip_exchange(&node_query)
            .await
            .expect_err("node policy failure must be terminal");
        assert!(error.to_string().contains("dedicated node DNS offline"));
        assert_eq!(default_hits.load(Ordering::SeqCst), 0);
        assert_eq!(fallback_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn non_address_bootstrap_question_respects_dedicated_node_policy() {
        // TXT/SRV lookups must not silently escape a node-specific DNS policy.
        let default_hits = Arc::new(AtomicUsize::new(0));
        let policy_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
                hits: default_hits.clone(),
                id: "bootstrap-default",
            })],
            false,
        );
        resolver.proxy_node_resolver = true;
        let mut matcher = crate::common::trie::StringTrie::new();
        matcher.insert("node.example.com", Arc::new(true));
        resolver.proxy_server_nameserver_policy.push((
            Arc::new(matcher),
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
                hits: policy_hits.clone(),
                id: "bootstrap-policy",
            })],
        ));
        let mut request = test_query_with_type(rr::RecordType::TXT);
        request.queries[0]
            .set_name(rr::Name::from_ascii("node.example.com.").unwrap());
        resolver.exchange(&request).await.unwrap();
        assert_eq!(policy_hits.load(Ordering::SeqCst), 1);
        assert_eq!(default_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn non_address_bootstrap_multi_question_must_fail_closed() {
        // TXT/SRV takes a separate exchange path from A/AAAA; the second
        // question must not escape its dedicated bootstrap policy.
        let default_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
                hits: default_hits.clone(),
                id: "node-default",
            })],
            false,
        );
        resolver.proxy_node_resolver = true;
        let mut request = op::Message::query();
        for (name, record_type) in [
            ("ordinary-node.example.com.", rr::RecordType::TXT),
            ("protected-node.example.com.", rr::RecordType::SRV),
        ] {
            let mut query = op::Query::new();
            query.set_name(rr::Name::from_ascii(name).unwrap());
            query.set_query_type(record_type);
            request.add_query(query);
        }
        resolver.exchange_no_cache_with_policy(&request, true, false).await.expect_err(
            "non-address multi-question bootstrap must reject before selecting an upstream",
        );
        assert_eq!(default_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn multi_question_with_later_proxy_node_must_not_reach_public_dns() {
        // A mixed-question packet can put an ordinary name first and a
        // dedicated node hostname second. Never route the whole packet to
        // the ordinary resolver based only on the first question.
        let mut resolver = EnhancedResolver::from_clients(vec![], false);
        let main_hits = Arc::new(AtomicUsize::new(0));
        let node_hits = Arc::new(AtomicUsize::new(0));
        resolver.main = vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 99)),
            hits: main_hits.clone(),
            id: "public-main",
        })];
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
            hits: node_hits.clone(),
            id: "node-only",
        })]);
        let mut domains = crate::common::trie::StringTrie::new();
        domains.insert("proxy.example.com", Arc::new(true));
        resolver.proxy_server_domains = Some(domains);
        let mut request = op::Message::query();
        let mut ordinary = op::Query::new();
        ordinary.set_name(rr::Name::from_ascii("ordinary.example.com.").unwrap());
        ordinary.set_query_type(rr::RecordType::A);
        request.add_query(ordinary);
        request
            .add_query(test_query_with_type(rr::RecordType::A).queries[0].clone());

        resolver
            .ip_exchange(&request)
            .await
            .expect_err("mixed node query must fail closed");
        resolver
            .exchange(&request)
            .await
            .expect_err("the public exchange entry must reject before cache lookup");
        assert_eq!(main_hits.load(Ordering::SeqCst), 0);
        assert_eq!(node_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn dedicated_bootstrap_policy_rejects_multi_question_before_upstream() {
        // The transport bootstrap resolver has no proxy_resolver pool; its
        // policy still chooses an upstream based on the first QNAME only.
        let default_hits = Arc::new(AtomicUsize::new(0));
        let policy_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
                hits: default_hits.clone(),
                id: "node-default",
            })],
            false,
        );
        resolver.proxy_node_resolver = true;
        let mut matcher = crate::common::trie::StringTrie::new();
        matcher.insert("protected-node.example.com", Arc::new(true));
        resolver.proxy_server_nameserver_policy.push((
            Arc::new(matcher),
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 11)),
                hits: policy_hits.clone(),
                id: "node-policy",
            })],
        ));
        let mut request = op::Message::query();
        for name in ["ordinary-node.example.com.", "protected-node.example.com."] {
            let mut query = op::Query::new();
            query.set_name(rr::Name::from_ascii(name).unwrap());
            query.set_query_type(rr::RecordType::A);
            request.add_query(query);
        }
        resolver.ip_exchange(&request).await.expect_err(
            "multi-question bootstrap must not bypass a later QNAME's node policy",
        );
        assert_eq!(default_hits.load(Ordering::SeqCst), 0);
        assert_eq!(policy_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn multi_question_with_node_pool_must_fail_closed_before_provider_registration()
     {
        // A provider can publish a node between the multi-question preflight
        // and upstream selection. Reject ambiguous packets even when neither
        // QNAME is registered yet, rather than allowing a time-of-check race.
        let mut resolver = EnhancedResolver::from_clients(vec![], false);
        let public_hits = Arc::new(AtomicUsize::new(0));
        resolver.main = vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 99)),
            hits: public_hits.clone(),
            id: "public-main",
        })];
        resolver.proxy_resolver = Some(vec![]);
        let mut request = op::Message::query();
        for name in ["ordinary.example.com.", "future-node.example.com."] {
            let mut q = op::Query::new();
            q.set_name(rr::Name::from_ascii(name).unwrap());
            q.set_query_type(rr::RecordType::A);
            request.add_query(q);
        }
        resolver.exchange(&request).await.expect_err(
            "multi-question queries must not race provider node publication",
        );
        assert_eq!(public_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn proxy_server_specific_policy_failure_never_falls_back_to_public_dns() {
        let mut resolver = EnhancedResolver::from_clients(vec![], false);
        let default_hits = Arc::new(AtomicUsize::new(0));
        let main_hits = Arc::new(AtomicUsize::new(0));
        let mut domains = crate::common::trie::StringTrie::new();
        domains.insert("proxy.example.com", Arc::new(true));
        resolver.proxy_server_domains = Some(domains);
        resolver.proxy_resolver = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
            hits: default_hits.clone(),
            id: "proxy-default",
        })]);
        let mut selector = crate::common::trie::StringTrie::new();
        selector.insert("proxy.example.com", Arc::new(true));
        resolver.proxy_server_nameserver_policy.push((
            Arc::new(selector),
            vec![Arc::new(FailingClient {
                id: "proxy-policy",
                reason: "dedicated node DNS unavailable",
            })],
        ));
        resolver.main = vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 99)),
            hits: main_hits.clone(),
            id: "public-main",
        })];
        let err = resolver
            .ip_exchange(&test_query_with_type(rr::RecordType::A))
            .await
            .expect_err("a failed dedicated policy must fail closed");
        assert!(err.to_string().contains("dedicated node DNS unavailable"));
        assert_eq!(default_hits.load(Ordering::SeqCst), 0);
        assert_eq!(main_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn proxy_server_policy_respects_first_matching_rule_order() {
        let mut resolver = EnhancedResolver::from_clients(vec![], false);
        let first_hits = Arc::new(AtomicUsize::new(0));
        let second_hits = Arc::new(AtomicUsize::new(0));
        let mut domains = crate::common::trie::StringTrie::new();
        domains.insert("proxy.example.com", Arc::new(true));
        resolver.proxy_server_domains = Some(domains);
        resolver.proxy_resolver = Some(vec![Arc::new(FailingClient {
            id: "proxy-default",
            reason: "default should not be used",
        })]);

        for (pattern, hits, id) in [
            ("*.example.com", first_hits.clone(), "first-rule"),
            ("proxy.example.com", second_hits.clone(), "second-rule"),
        ] {
            let mut selector = crate::common::trie::StringTrie::new();
            selector.insert(pattern, Arc::new(true));
            resolver.proxy_server_nameserver_policy.push((
                Arc::new(selector),
                vec![Arc::new(CountingClient {
                    response: response_with_a(Ipv4Addr::new(192, 0, 2, 10)),
                    hits,
                    id,
                })],
            ));
        }
        resolver
            .ip_exchange(&test_query_with_type(rr::RecordType::A))
            .await
            .expect("first matching policy wins");
        assert_eq!(first_hits.load(Ordering::SeqCst), 1);
        assert_eq!(second_hits.load(Ordering::SeqCst), 0);
    }

    #[derive(Debug)]
    struct CountingFailingClient {
        hits: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl crate::app::dns::Client for CountingFailingClient {
        fn id(&self) -> String {
            "dedicated-proxy-dns".to_owned()
        }

        async fn exchange(&self, _msg: &op::Message) -> anyhow::Result<op::Message> {
            self.hits.fetch_add(1, Ordering::SeqCst);
            Err(anyhow::anyhow!("injected bootstrap timeout"))
        }
    }

    // An actual pending upstream is different from a client that immediately
    // returns a timeout error: cancellation must not trigger a public retry.
    #[derive(Debug)]
    struct PendingBootstrapClient {
        hits: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl crate::app::dns::Client for PendingBootstrapClient {
        fn id(&self) -> String {
            "pending-bootstrap".to_owned()
        }

        async fn exchange(&self, _msg: &op::Message) -> anyhow::Result<op::Message> {
            self.hits.fetch_add(1, Ordering::SeqCst);
            std::future::pending::<anyhow::Result<op::Message>>().await
        }
    }

    #[tokio::test]
    async fn proxy_bootstrap_timeout_cancellation_never_uses_public_dns() {
        let dedicated_hits = Arc::new(AtomicUsize::new(0));
        let public_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients_with_fallback(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 91)),
                hits: public_hits.clone(),
                id: "public-main",
            })],
            Some(vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 92)),
                hits: public_hits.clone(),
                id: "public-fallback",
            })]),
            false,
        );
        let mut domains = crate::common::trie::StringTrie::new();
        domains.insert("proxy.example.com", Arc::new(true));
        resolver.proxy_server_domains = Some(domains);
        resolver.proxy_resolver = Some(vec![Arc::new(PendingBootstrapClient {
            hits: dedicated_hits.clone(),
        })]);
        // An overlapping generic policy must not become an escape hatch when
        // the dedicated node bootstrap future is cancelled.
        let mut generic_policy = crate::common::trie::StringTrie::new();
        generic_policy.insert(
            "proxy.example.com",
            Arc::new(vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 93)),
                hits: public_hits.clone(),
                id: "generic-policy",
            }) as ThreadSafeDNSClient]),
        );
        resolver.policy = Some(Arc::new(generic_policy));
        for record_type in
            [rr::RecordType::A, rr::RecordType::AAAA, rr::RecordType::TXT]
        {
            let result = tokio::time::timeout(
                Duration::from_millis(100),
                resolver.exchange_no_cache(&test_query_with_type(record_type)),
            )
            .await;
            assert!(
                result.is_err(),
                "pending dedicated bootstrap must not return public DNS"
            );
        }
        assert_eq!(dedicated_hits.load(Ordering::SeqCst), 3);
        assert_eq!(public_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn cancelled_provider_bootstrap_during_ownership_reload_never_uses_public_dns()
     {
        // A cancelled in-flight bootstrap must not schedule a retry through
        // generic DNS, even when the provider is removed and re-registered.
        let dedicated_hits = Arc::new(AtomicUsize::new(0));
        let public_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients_with_fallback(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 91)),
                hits: public_hits.clone(),
                id: "public-main",
            })],
            Some(vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 92)),
                hits: public_hits.clone(),
                id: "public-fallback",
            })]),
            false,
        );
        resolver.lru_cache = Some(ResponseCache::new(16, TtlConfig::default()));
        resolver.proxy_resolver = Some(vec![Arc::new(PendingBootstrapClient {
            hits: dedicated_hits.clone(),
        })]);
        let resolver = Arc::new(resolver);
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        let query = test_query_with_type(rr::RecordType::TXT);
        let running = {
            let resolver = resolver.clone();
            tokio::spawn(async move { resolver.exchange(&query).await })
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            while dedicated_hits.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dedicated DNS must start");
        resolver
            .replace_proxy_provider_dns_domains("owner", vec![])
            .await
            .unwrap();
        resolver
            .replace_proxy_provider_dns_domains(
                "owner",
                vec!["proxy.example.com".into()],
            )
            .await
            .unwrap();
        running.abort();
        assert!(running.await.unwrap_err().is_cancelled());
        assert_eq!(dedicated_hits.load(Ordering::SeqCst), 1);
        assert_eq!(public_hits.load(Ordering::SeqCst), 0);
        assert!(
            resolver
                .lru_cache
                .as_ref()
                .unwrap()
                .get(
                    &test_query_with_type(rr::RecordType::TXT).queries[0],
                    Instant::now(),
                )
                .is_none(),
            "cancelled node answer must not enter public cache"
        );
    }

    #[tokio::test]
    async fn proxy_bootstrap_failure_never_queries_policy_main_or_fallback() {
        let mut resolver = EnhancedResolver::from_clients_with_fallback(
            vec![],
            Some(vec![]),
            false,
        );
        let dedicated_hits = Arc::new(AtomicUsize::new(0));
        let policy_hits = Arc::new(AtomicUsize::new(0));
        let main_hits = Arc::new(AtomicUsize::new(0));
        let fallback_hits = Arc::new(AtomicUsize::new(0));
        let mut domains = crate::common::trie::StringTrie::new();
        domains.insert("proxy.example.com", Arc::new(true));
        resolver.proxy_server_domains = Some(domains);
        resolver.proxy_resolver = Some(vec![Arc::new(CountingFailingClient {
            hits: dedicated_hits.clone(),
        })]);
        let mut policy = crate::common::trie::StringTrie::new();
        policy.insert(
            "proxy.example.com",
            Arc::new(vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(192, 0, 2, 70)),
                hits: policy_hits.clone(),
                id: "policy-dns",
            }) as ThreadSafeDNSClient]),
        );
        resolver.policy = Some(Arc::new(policy));
        resolver.main = vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 71)),
            hits: main_hits.clone(),
            id: "main-dns",
        })];
        resolver.fallback = Some(vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(192, 0, 2, 72)),
            hits: fallback_hits.clone(),
            id: "fallback-dns",
        })]);

        for record_type in [rr::RecordType::A, rr::RecordType::AAAA] {
            let err = resolver
                .exchange_no_cache(&test_query_with_type(record_type))
                .await
                .expect_err("dedicated bootstrap failure must fail closed");
            assert!(err.to_string().contains("injected bootstrap timeout"));
        }
        assert_eq!(dedicated_hits.load(Ordering::SeqCst), 2);
        assert_eq!(policy_hits.load(Ordering::SeqCst), 0);
        assert_eq!(main_hits.load(Ordering::SeqCst), 0);
        assert_eq!(fallback_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn comma_delimited_nameserver_policy_uses_dedicated_upstream() {
        let parsed =
            Config::parse_nameserver_policy(&std::collections::HashMap::from([(
                "proxy.example.com,other.test".to_owned(),
                "192.0.2.53".to_owned(),
            )]))
            .expect("comma-separated selectors must compile into runtime policy");
        let mut resolver = EnhancedResolver::new_default().await;
        resolver.lru_cache = None;
        let policy_hits = Arc::new(AtomicUsize::new(0));
        let main_hits = Arc::new(AtomicUsize::new(0));
        let mut policy = crate::common::trie::StringTrie::new();
        for selector in parsed.keys() {
            assert!(policy.insert(
                selector,
                Arc::new(vec![Arc::new(CountingClient {
                    response: response_with_a(Ipv4Addr::new(203, 0, 113, 10)),
                    hits: policy_hits.clone(),
                    id: "policy-ns",
                }) as ThreadSafeDNSClient]),
            ));
        }
        resolver.policy = Some(policy);
        resolver.main = vec![Arc::new(CountingClient {
            response: response_with_a(Ipv4Addr::new(198, 51, 100, 20)),
            hits: main_hits.clone(),
            id: "main-ns",
        })];

        for domain in ["PROXY.EXAMPLE.COM", "other.test"] {
            let mut message = op::Message::query();
            let mut q = op::Query::new();
            q.set_name(rr::Name::from_utf8(domain).unwrap());
            q.set_query_type(rr::RecordType::TXT);
            message.add_query(q);
            resolver
                .exchange_no_cache(&message)
                .await
                .expect("policy-selected upstream must answer");
        }
        assert_eq!(policy_hits.load(Ordering::SeqCst), 2);
        assert_eq!(main_hits.load(Ordering::SeqCst), 0);

        let mut message = op::Message::query();
        let mut q = op::Query::new();
        q.set_name(rr::Name::from_utf8("unrelated.test").unwrap());
        q.set_query_type(rr::RecordType::TXT);
        message.add_query(q);
        resolver.exchange_no_cache(&message).await.unwrap();
        assert_eq!(main_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn dns_nameserver_policy_matches_case_insensitive_domains() {
        // The same compiled policy is reused by the normal and opt-in
        // DIRECT resolvers. Uppercase YAML keys and mixed-case DNS requests
        // must not bypass their selected upstream.
        let temp = tempfile::tempdir().unwrap();
        let store = crate::app::profile::ThreadSafeCacheFile::new(
            temp.path().join("cache.db").to_str().unwrap(),
            false,
        );
        let mut config = make_proxy_nameserver_config();
        config.nameserver_policy.insert(
            "PrOtEcTeD.ExAmPlE".to_owned(),
            NameServer {
                net: DNSNetMode::Udp,
                host: url::Host::Ipv4("9.9.9.9".parse().unwrap()),
                port: 53,
                interface: None,
                proxy: None,
                doh_path: None,
            },
        );
        config.direct_nameserver = Some(vec![NameServer {
            net: DNSNetMode::Udp,
            host: url::Host::Ipv4("192.0.2.53".parse().unwrap()),
            port: 53,
            interface: None,
            proxy: None,
            doh_path: None,
        }]);
        config.direct_nameserver_follow_policy = true;

        let resolver = EnhancedResolver::new(
            config,
            store,
            None,
            Arc::new(RwLock::new(std::collections::HashMap::new())),
            None,
        )
        .await
        .expect("DNS policy with mixed-case domains should initialize");

        let policy = resolver
            .policy
            .as_ref()
            .expect("compiled nameserver-policy");
        assert!(policy.search("protected.example").is_some());
        assert!(resolver.direct_resolver.is_some());
    }

    #[tokio::test]
    async fn mixed_case_dns_qname_cannot_bypass_nameserver_policy() {
        let protected_hits = Arc::new(AtomicUsize::new(0));
        let public_hits = Arc::new(AtomicUsize::new(0));
        let mut resolver = EnhancedResolver::from_clients(
            vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(198, 51, 100, 5)),
                hits: public_hits.clone(),
                id: "public",
            })],
            false,
        );
        let mut policy = crate::common::trie::StringTrie::new();
        policy.insert(
            "proxy.example.com",
            Arc::new(vec![Arc::new(CountingClient {
                response: response_with_a(Ipv4Addr::new(203, 0, 113, 5)),
                hits: protected_hits.clone(),
                id: "protected",
            }) as ThreadSafeDNSClient]),
        );
        resolver.policy = Some(Arc::new(policy));
        let mut query = test_query_with_type(rr::RecordType::A);
        query.queries[0]
            .set_name(rr::Name::from_utf8("PrOxY.ExAmPlE.CoM.").unwrap());
        let response = resolver.ip_exchange(&query).await.unwrap();
        assert_eq!(
            EnhancedResolver::ip_list_of_message(&response),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))],
        );
        assert_eq!(protected_hits.load(Ordering::SeqCst), 1);
        assert_eq!(public_hits.load(Ordering::SeqCst), 0);
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
            Some(Arc::new(policy))
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
    async fn configured_fake_ip_ttl_reaches_runtime_resolver() {
        let temp = tempfile::tempdir().unwrap();
        let cache_store = crate::app::profile::ThreadSafeCacheFile::new(
            temp.path().join("cache.db").to_str().unwrap(),
            false,
        );
        let mut config = make_proxy_nameserver_config();
        config.enhance_mode = crate::config::def::DNSMode::FakeIp;
        config.fake_ip_range = "198.18.0.0/16".parse().unwrap();
        config.fake_ip_ttl = 29;
        let resolver = EnhancedResolver::new(
            config,
            cache_store,
            None,
            Arc::new(RwLock::new(std::collections::HashMap::new())),
            None,
        )
        .await
        .expect("Fake-IP resolver should initialize from config");
        assert!(resolver.fake_ip_enabled());
        assert_eq!(resolver.fake_ip_ttl(), 29);
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
    async fn proxy_server_specific_policy_is_installed_from_runtime_configuration() {
        let temp = tempfile::tempdir().unwrap();
        let store = crate::app::profile::ThreadSafeCacheFile::new(
            temp.path().join("cache.db").to_str().unwrap(),
            false,
        );
        let mut config = make_proxy_nameserver_config();
        config.proxy_server_nameserver_policy.push((
            "PROXY.EXAMPLE.COM".to_owned(),
            vec![NameServer {
                net: DNSNetMode::Udp,
                host: url::Host::Ipv4("9.9.9.9".parse().unwrap()),
                port: 53,
                interface: None,
                proxy: None,
                doh_path: None,
            }],
        ));
        let resolver = EnhancedResolver::new(
            config,
            store,
            None,
            make_outbound_registry(&[("node-a", "PROXY.EXAMPLE.COM")]),
            None,
        )
        .await
        .expect("per-node policy should initialize offline");

        assert_eq!(resolver.proxy_server_nameserver_policy.len(), 1);
        assert!(
            resolver.proxy_server_nameserver_policy[0]
                .0
                .search("proxy.example.com")
                .is_some()
        );
        assert!(
            resolver
                .proxy_server_domains
                .as_ref()
                .unwrap()
                .search("proxy.example.com")
                .is_some()
        );
    }

    #[tokio::test]
    async fn direct_dns_constructor_rejects_unmatchable_public_policy_selectors() {
        // An internal app::dns::Config can bypass YAML conversion. An invalid
        // public nameserver-policy selector must fail startup, not silently
        // install a nonmatching trie and leak the query to default DNS.
        for selector in ["policy..example.com", "policy.example.com "] {
            let temp = tempfile::tempdir().unwrap();
            let store = crate::app::profile::ThreadSafeCacheFile::new(
                temp.path().join("cache.db").to_str().unwrap(),
                false,
            );
            let mut config = make_proxy_nameserver_config();
            config
                .nameserver_policy
                .insert(selector.to_owned(), config.nameserver[0].clone());
            let outcome = EnhancedResolver::new(
                config,
                store,
                None,
                Arc::new(RwLock::new(std::collections::HashMap::new())),
                None,
            )
            .await;
            assert!(
                matches!(outcome,
                Err(crate::Error::InvalidConfig(message))
                    if message.contains("nameserver-policy")),
                "invalid public policy selector {selector:?} must fail closed"
            );
        }
    }

    #[tokio::test]
    async fn direct_dns_constructor_rejects_unmatchable_proxy_node_policy_selectors()
    {
        // Internal callers can construct app::dns::Config directly, bypassing
        // YAML conversion. A malformed per-node selector must not silently
        // install an empty trie and downgrade to default node DNS.
        for selector in ["proxy..example.com", "proxy.example.com "] {
            let temp = tempfile::tempdir().unwrap();
            let store = crate::app::profile::ThreadSafeCacheFile::new(
                temp.path().join("cache.db").to_str().unwrap(),
                false,
            );
            let mut config = make_proxy_nameserver_config();
            let servers = config.proxy_server_nameserver.as_ref().unwrap().clone();
            config
                .proxy_server_nameserver_policy
                .push((selector.into(), servers));
            let outcome = EnhancedResolver::new(
                config,
                store,
                None,
                Arc::new(RwLock::new(std::collections::HashMap::new())),
                None,
            )
            .await;
            assert!(
                matches!(outcome,
                Err(crate::Error::InvalidConfig(message))
                    if message.contains("proxy-server-nameserver-policy")),
                "invalid selector {selector:?} must be rejected before DNS startup"
            );
        }
    }

    #[tokio::test]
    async fn node_policy_rejects_proxy_override_but_default_preserves_legacy_non_tun()
     {
        // Keep the established non-TUN default bootstrap #proxy behavior.
        // Per-node proxy-server-nameserver-policy #proxy remains unsupported
        // even when internal callers bypass YAML conversion.
        for per_node_policy in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let store = crate::app::profile::ThreadSafeCacheFile::new(
                temp.path().join("cache.db").to_str().unwrap(),
                false,
            );
            let mut config = make_proxy_nameserver_config();
            let mut server =
                config.proxy_server_nameserver.as_ref().unwrap()[0].clone();
            server.proxy = Some("bootstrap-cycle".to_owned());
            if per_node_policy {
                config
                    .proxy_server_nameserver_policy
                    .push(("proxy.example.com".to_owned(), vec![server]));
            } else {
                config.proxy_server_nameserver = Some(vec![server]);
            }
            let outcome = EnhancedResolver::new(
                config,
                store,
                None,
                Arc::new(RwLock::new(std::collections::HashMap::new())),
                None,
            )
            .await;
            if per_node_policy {
                assert!(
                    matches!(outcome,
                    Err(crate::Error::InvalidConfig(message))
                        if message.contains("proxy-server-nameserver-policy")
                            && message.contains("#proxy")),
                    "per-node node-DNS #proxy override must fail closed"
                );
            } else {
                assert!(
                    outcome.is_ok(),
                    "legacy non-TUN default proxy-server-nameserver #proxy must remain supported"
                );
            }
        }
    }

    #[tokio::test]
    async fn configured_proxy_nameserver_with_no_runtime_clients_fails_closed() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_store = crate::app::profile::ThreadSafeCacheFile::new(
            temp_dir.path().join("cache.db").to_str().unwrap(),
            false,
        );
        let mut config = make_proxy_nameserver_config();
        // A parsed configuration can still produce no usable clients at runtime.
        // Never silently switch proxy hostname resolution to default/main DNS.
        config.proxy_server_nameserver = Some(vec![]);
        let result = EnhancedResolver::new(
            config,
            cache_store,
            None,
            Arc::new(RwLock::new(std::collections::HashMap::new())),
            None,
        )
        .await;
        assert!(
            matches!(result, Err(crate::Error::InvalidConfig(message))
                if message == "dns.proxy-server-nameserver was explicitly configured but has no usable clients; refusing DNS bootstrap fallback"),
            "empty proxy DNS clients must fail closed with a specific configuration error"
        );
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
    async fn explicitly_configured_empty_proxy_nameserver_must_not_fall_back() {
        // "None" means no dedicated proxy bootstrap was configured.
        // "Some(empty)" means it was requested but no clients exist;
        // silently using the general resolver breaks the caller's DNS boundary.
        let temp = tempfile::tempdir().unwrap();
        let store = crate::app::profile::ThreadSafeCacheFile::new(
            temp.path().join("cache.db").to_str().unwrap(),
            false,
        );
        let mut config = make_proxy_nameserver_config();
        config.proxy_server_nameserver = Some(vec![]);
        let outcome = EnhancedResolver::new(
            config,
            store,
            None,
            Arc::new(RwLock::new(std::collections::HashMap::new())),
            None,
        )
        .await;
        let error = match outcome {
            Ok(_) => panic!("explicit empty proxy bootstrap must not fall back"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("proxy-server-nameserver"), "{error}");
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
    async fn configured_direct_resolver_inherits_parent_owner_gate() {
        // Exercise the actual Config -> resolver constructor, not only the
        // test helper that manually wires DIRECT. Use localhost exclusively
        // so a failed gate cannot send traffic to an external DNS server.
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_store = crate::app::profile::ThreadSafeCacheFile::new(
            temp_dir.path().join("cache.db").to_str().unwrap(),
            false,
        );
        let mut config = make_proxy_nameserver_config();
        config.direct_nameserver = Some(vec![NameServer {
            net: DNSNetMode::Udp,
            host: url::Host::Ipv4(Ipv4Addr::LOCALHOST),
            port: 9,
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
        .expect("loopback DIRECT nameserver should initialize");
        let direct = resolver
            .direct_resolver()
            .expect("DIRECT handle must exist");
        resolver.invalidate_transports();
        // Child reset succeeds but cannot clear the separately shared owner gate.
        direct.reset_transports().await.unwrap();
        let (request, _) = test_query();
        let error = direct.exchange(&request).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("DIRECT DNS owner has not completed transport recovery"),
            "actual configuration must wire parent owner gate: {error}"
        );
        drop(resolver);
        let error = direct.exchange(&request).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("DIRECT DNS owner has not completed transport recovery"),
            "a cloned DIRECT handle cannot outlive its configured owner: {error}"
        );
    }

    #[tokio::test]
    async fn configured_direct_cannot_publish_without_parent_commit() {
        // Exercise the production Config -> DIRECT constructor rather than
        // relying solely on manually wired parent-child test fixtures.
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_store = crate::app::profile::ThreadSafeCacheFile::new(
            temp_dir.path().join("cache.db").to_str().unwrap(),
            false,
        );
        let mut config = make_proxy_nameserver_config();
        config.direct_nameserver = Some(vec![NameServer {
            net: DNSNetMode::Udp,
            host: url::Host::Ipv4(Ipv4Addr::LOCALHOST),
            port: 9,
            interface: None,
            proxy: None,
            doh_path: None,
        }]);
        let owner = EnhancedResolver::new(
            config,
            cache_store,
            None,
            Arc::new(RwLock::new(std::collections::HashMap::new())),
            None,
        )
        .await
        .unwrap();
        let direct = owner.direct_resolver().unwrap();
        owner.pause_publication();
        direct.publish();
        let (request, _) = test_query();
        let denied = direct.exchange(&request).await.unwrap_err();
        assert!(
            denied.to_string().contains("not yet published"),
            "production DIRECT handle bypassed parent publication: {denied}"
        );
        // Do not send real DNS requests. An IP literal proves that both
        // publication gates reopen after a successful parent commit.
        owner.publish();
        assert_eq!(
            direct.resolve("127.0.0.1", false).await.unwrap(),
            Some(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
    }

    #[tokio::test]
    async fn repeated_parent_invalidation_cannot_reopen_configured_direct_resolver()
    {
        // Repeated failure notifications must be idempotent, including when a
        // child handle survives independently of its parent owner.
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_store = crate::app::profile::ThreadSafeCacheFile::new(
            temp_dir.path().join("cache.db").to_str().unwrap(),
            false,
        );
        let mut config = make_proxy_nameserver_config();
        config.direct_nameserver = Some(vec![NameServer {
            net: DNSNetMode::Udp,
            host: url::Host::Ipv4(Ipv4Addr::LOCALHOST),
            port: 9,
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
        .unwrap();
        let direct = resolver.direct_resolver().unwrap();
        resolver.invalidate_transports();
        resolver.invalidate_transports();
        direct.reset_transports().await.unwrap();
        let (request, _) = test_query();
        assert!(direct.exchange(&request).await.is_err());
        drop(resolver);
        assert!(direct.exchange(&request).await.is_err());
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
