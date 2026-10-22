//! S04a: conservative strict DNS cache partitions and bootstrap dependency
//! guards. Separate from EnhancedResolver's legacy positive/negative caches.
//! No production policy-rules path consumes this until S04/S05 activation.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    hash::{Hash, Hasher},
    io,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{DNSClass, RData, RecordType},
};

use crate::{
    proxy::{
        AnyOutboundHandler,
        utils::{OutboundHandlerRegistry, SharedNetworkStatus},
    },
    session::Session,
};

use super::{
    bootstrap::{StrictBootstrapPinSnapshot, StrictBootstrapPinStore},
    execution::{
        DnsStrictTransport, PreparedDnsExecution, StrictDnsExecution,
        prepare_dns_execution,
    },
    plan::{
        DnsPurpose, DnsQueryContext, DnsQueryFlags, DnsSourceScope, EffectiveDnsPlan,
    },
    policy::{CompiledDnsPolicy, DnsEgress},
};

/// Keep a strong reference in every cache key. Unlike a bare Arc pointer,
/// this prevents allocator reuse from making a newly selected proxy leaf
/// appear identical to a former outbound while its cache entry survives.
#[derive(Clone, Debug)]
struct LeafIdentity(AnyOutboundHandler);

impl PartialEq for LeafIdentity {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for LeafIdentity {}
impl Hash for LeafIdentity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::ptr::hash(Arc::as_ptr(&self.0), state);
    }
}

/// All context that may influence a strict DNS answer. No Fake-IP answers or
/// existing EnhancedResolver cache entries are stored here.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct StrictCacheKey {
    qname: String,
    qclass: DNSClass,
    qtype: RecordType,
    purpose: DnsPurpose,
    source: DnsSourceScope,
    flags: DnsQueryFlags,
    ecs: Option<ipnet::IpNet>,
    network_generation: u64,
    config_generation: u64,
    bootstrap_revision: u64,
    profile: String,
    egress_name: String,
    leaf: LeafIdentity,
    servers: Vec<String>,
    transport_fingerprint: String,
}

#[derive(Clone)]
struct Cached {
    answer: Message,
    born: Instant,
    lifetime: Duration,
}

#[derive(Default)]
struct CacheInner {
    values: HashMap<StrictCacheKey, Cached>,
    order: VecDeque<StrictCacheKey>,
    epoch: (u64, u64, u64),
}

/// Scoped in-memory answer store. Strict runtime is currently off; S04a's
/// cache is only used through explicit exchange_scoped and does not modify
/// the existing legacy resolver's caching or its RFC 2308 negative cache.
pub struct StrictDnsCache {
    limit: usize,
    inner: Mutex<CacheInner>,
    // Explicit DIRECT is not a dynamic group. Retain one handler identity
    // per cache so S03's fresh direct handler does not make every lookup miss.
    direct_outbound: AnyOutboundHandler,
}

/// Immutable inputs needed to prepare a strict DNS rule against the current
/// outbound registry. Do not cache this selection across requests.
pub(crate) struct StrictDnsPlanSelection<'a> {
    pub plan: &'a EffectiveDnsPlan,
    pub profiles: &'a CompiledDnsPolicy,
    pub registry: &'a OutboundHandlerRegistry,
    pub session: &'a Session,
}

struct StrictDnsBootstrapAttempt<'a> {
    pins: &'a StrictBootstrapPinStore,
    snapshot: StrictBootstrapPinSnapshot,
    parent: &'a BootstrapTrace,
}

impl StrictDnsCache {
    pub fn new(
        limit: usize,
        network_generation: u64,
        config_generation: u64,
        bootstrap_revision: u64,
    ) -> Self {
        let inner = CacheInner {
            epoch: (network_generation, config_generation, bootstrap_revision),
            ..Default::default()
        };
        Self {
            limit,
            inner: Mutex::new(inner),
            direct_outbound: Arc::new(crate::proxy::direct::Handler::new(
                crate::config::internal::proxy::PROXY_DIRECT,
            )),
        }
    }

    /// Clear old answers on network, config or bootstrap pin revision change.
    /// An older in-flight request cannot repopulate the new epoch.
    pub fn advance_epoch(
        &self,
        network_generation: u64,
        config_generation: u64,
        bootstrap_revision: u64,
    ) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let epoch = (network_generation, config_generation, bootstrap_revision);
        if inner.epoch != epoch {
            inner.values.clear();
            inner.order.clear();
            inner.epoch = epoch;
        }
    }

    /// S04b: advance from observed runtime epochs without allowing a delayed
    /// query to move the cache backwards to an earlier config/network/pin.
    /// Each source must supply monotonically increasing generations.
    fn advance_observed_epoch(&self, next: (u64, u64, u64)) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if next.0 < inner.epoch.0 || next.1 < inner.epoch.1 || next.2 < inner.epoch.2
        {
            return Err(io::Error::other(
                "strict DNS runtime epoch regressed; refusing stale DNS cache snapshot",
            ));
        }
        if inner.epoch != next {
            inner.values.clear();
            inner.order.clear();
            inner.epoch = next;
        }
        Ok(())
    }

    /// The existing RuntimeStatus, not a caller-defaulted S02 context, owns
    /// config and network generations. Network version zero has never been
    /// observed and is not a trustworthy strict-cache identity.
    async fn observed_generations(
        status: &SharedNetworkStatus,
    ) -> io::Result<(u64, u64)> {
        let (network, config) = status
            .read()
            .await
            .strict_dns_generations()
            .ok_or_else(|| io::Error::other(
                "strict DNS requires a current observed network and committed configuration",
            ))?;
        if network == 0 || config == 0 {
            return Err(io::Error::other(
                "strict DNS requires an observed network and committed configuration generation",
            ));
        }
        Ok((network, config))
    }

    /// S04b opt-in entrypoint. Read real runtime generations before a lookup
    /// and after the answer. The caller must recapture the current strict
    /// outbound leaf for *each* query and supply a trusted, monotonic pin
    /// revision; this does not enable production `policy-rules`.
    pub(crate) async fn exchange_observed<T: DnsStrictTransport>(
        &self,
        execution: &StrictDnsExecution,
        transport: &T,
        request: &Message,
        context: &DnsQueryContext,
        status: &SharedNetworkStatus,
        bootstrap_revision: u64,
    ) -> io::Result<Message> {
        let (network, config) = Self::observed_generations(status).await?;
        let epoch = (network, config, bootstrap_revision);
        self.advance_observed_epoch(epoch)?;
        let mut scoped = context.clone();
        scoped.network_generation = network;
        scoped.config_generation = config;
        let response = self
            .exchange_scoped(
                execution,
                transport,
                request,
                &scoped,
                bootstrap_revision,
            )
            .await?;
        let (current_network, current_config) =
            Self::observed_generations(status).await?;
        if (current_network, current_config) != (network, config) {
            self.advance_observed_epoch((
                current_network,
                current_config,
                bootstrap_revision,
            ))?;
            return Err(io::Error::other(
                "strict DNS runtime generation changed while querying; discarding stale answer",
            ));
        }
        Ok(response)
    }

    /// Opt-in S04b orchestration for already compiled strict rules. Re-run
    /// S03 preflight for every query so mutable selector/provider state cannot
    /// leave a cached *group name* standing in for the selected leaf. The
    /// production resolver still rejects nonempty `policy-rules`.
    #[allow(dead_code)]
    pub(crate) async fn exchange_planned_observed<T: DnsStrictTransport>(
        &self,
        selection: StrictDnsPlanSelection<'_>,
        transport: &T,
        request: &Message,
        status: &SharedNetworkStatus,
        bootstrap_revision: u64,
    ) -> io::Result<Message> {
        self.exchange_planned_observed_traced(
            selection,
            transport,
            request,
            status,
            bootstrap_revision,
            &BootstrapTrace::default(),
        )
        .await
    }

    /// Carry the caller's immutable bootstrap ancestry into nested strict DNS
    /// work. An empty trace is only suitable for a new top-level request.
    async fn exchange_planned_observed_traced<T: DnsStrictTransport>(
        &self,
        selection: StrictDnsPlanSelection<'_>,
        transport: &T,
        request: &Message,
        status: &SharedNetworkStatus,
        bootstrap_revision: u64,
        parent: &BootstrapTrace,
    ) -> io::Result<Message> {
        let StrictDnsPlanSelection {
            plan,
            profiles,
            registry,
            session,
        } = selection;
        let question = DnsQueryContext::from_message(request, plan.context.purpose)
            .map_err(io::Error::other)?;
        if question.qname != plan.context.qname
            || question.qtype != plan.context.qtype
            || question.qclass != plan.context.qclass
            || question.flags != plan.context.flags
        {
            return Err(io::Error::other(
                "strict DNS request no longer matches its prepared query plan",
            ));
        }
        let PreparedDnsExecution::Strict(mut execution) =
            prepare_dns_execution(plan, profiles, registry, session).await?
        else {
            return Err(io::Error::other(
                "strict DNS cache cannot execute legacy or local-answer paths",
            ));
        };
        // The preflight has selected the *actual* dynamic group leaf. Validate
        // dependencies and recursion before consulting any cached response.
        Self::validate_execution_bootstrap(&execution, parent)?;
        if matches!(execution.egress, DnsEgress::Direct) {
            // The newly prepared explicit-DIRECT handler has no mutable
            // selection state. Preserve its identity across queries while
            // still invalidating on network/config/bootstrap epoch changes.
            execution.outbound = self.direct_outbound.clone();
        }
        // A cache hit must not bypass bootstrap eligibility. S04b still has
        // no trusted resolver for proxy-node hostnames; reject them *before*
        // a potentially cached answer instead of silently using system DNS.
        if let Some(host) = execution.outbound.server_name()
            && host.parse::<IpAddr>().is_err()
        {
            return Err(io::Error::other(format!(
                "strict DNS proxy '{}' requires a trusted bootstrap pin for '{host}'",
                execution.outbound.name()
            )));
        }
        self.exchange_observed(
            &execution,
            transport,
            request,
            &plan.context,
            status,
            bootstrap_revision,
        )
        .await
    }

    /// S04b-b opt-in: use only a single coherent explicit-pin snapshot for
    /// this strict attempt. The pinned S03c transport is constructed from
    /// that snapshot; callers cannot substitute an arbitrary resolver.
    /// The production `policy-rules` startup gate is unchanged.
    #[allow(dead_code)]
    pub(crate) async fn exchange_planned_pinned(
        &self,
        selection: StrictDnsPlanSelection<'_>,
        request: &Message,
        status: &SharedNetworkStatus,
        pins: &StrictBootstrapPinStore,
    ) -> io::Result<Message> {
        self.exchange_planned_pinned_traced(
            selection,
            request,
            status,
            pins,
            &BootstrapTrace::default(),
        )
        .await
    }

    /// Nested bootstrap callers must propagate their ancestry. A repeated
    /// profile or selected proxy leaf is rejected even when pin data exists.
    #[allow(dead_code)]
    pub(crate) async fn exchange_planned_pinned_traced(
        &self,
        selection: StrictDnsPlanSelection<'_>,
        request: &Message,
        status: &SharedNetworkStatus,
        pins: &StrictBootstrapPinStore,
        parent: &BootstrapTrace,
    ) -> io::Result<Message> {
        let snapshot = pins.snapshot_current(status).await?;
        let transport = snapshot.transport()?;
        self.exchange_bound_snapshot(
            selection,
            &transport,
            request,
            status,
            StrictDnsBootstrapAttempt {
                pins,
                snapshot,
                parent,
            },
        )
        .await
    }

    /// Keep this small transport-injected boundary for deterministic offline
    /// tests; only `exchange_planned_pinned` constructs a real pinned wire.
    async fn exchange_bound_snapshot<T: DnsStrictTransport>(
        &self,
        selection: StrictDnsPlanSelection<'_>,
        transport: &T,
        request: &Message,
        status: &SharedNetworkStatus,
        attempt: StrictDnsBootstrapAttempt<'_>,
    ) -> io::Result<Message> {
        let StrictDnsBootstrapAttempt {
            pins,
            snapshot,
            parent,
        } = attempt;
        if !pins.still_current(status, &snapshot).await? {
            return Err(io::Error::other(
                "strict DNS bootstrap pin snapshot changed before dispatch",
            ));
        }
        let response = self
            .exchange_planned_observed_traced(
                selection,
                transport,
                request,
                status,
                snapshot.revision(),
                parent,
            )
            .await;
        // This check also runs after upstream errors: a rotation must not be
        // masked as an ordinary failure eligible for a lower-trust fallback.
        let current = pins.snapshot_current(status).await?;
        if current != snapshot {
            self.advance_observed_epoch((
                current.epoch().0,
                current.epoch().1,
                current.revision(),
            ))?;
            return Err(io::Error::other(
                "strict DNS bootstrap pin revision changed while querying; discarding stale answer",
            ));
        }
        response
    }

    /// Build a bounded dependency graph from the already selected DNS egress
    /// leaf and every upstream in the strict profile. A hostname shared by
    /// the proxy's own bootstrap and its DNS upstream is a forced cycle unless
    /// an independent bootstrap source is proven; such proof is not available
    /// to S04b-c. Unknown proxy hostnames remain rejected by the caller.
    fn validate_execution_bootstrap(
        execution: &StrictDnsExecution,
        parent: &BootstrapTrace,
    ) -> io::Result<()> {
        const MAX_BOOTSTRAP_DEPTH: usize = 16;
        let root = BootstrapNode::Profile(execution.profile.clone());
        let proxy = matches!(execution.egress, DnsEgress::Proxy(_))
            .then(|| BootstrapNode::Proxy(execution.outbound.name().to_owned()));
        let proxy_host = execution.outbound.server_name().and_then(|host| {
            (host.parse::<IpAddr>().is_err())
                .then(|| host.trim_end_matches('.').to_ascii_lowercase())
        });
        let mut graph = BootstrapGraph::default();
        for server in &execution.servers {
            let upstream = BootstrapNode::Upstream(server.to_string());
            graph.require(root.clone(), upstream.clone());
            if let Some(proxy_node) = &proxy {
                graph.require(upstream.clone(), proxy_node.clone());
                let upstream_host = server
                    .host
                    .to_string()
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                if proxy_host.as_deref() == Some(upstream_host.as_str()) {
                    graph.require(proxy_node.clone(), upstream.clone());
                }
            }
        }
        graph.validate(MAX_BOOTSTRAP_DEPTH)?;
        // Each upstream is an alternative retry path, not an additional
        // recursive nesting level. Never use a shared global recursion stack.
        for server in &execution.servers {
            let ancestry = parent.enter(root.clone(), MAX_BOOTSTRAP_DEPTH)?;
            let ancestry = ancestry.enter(
                BootstrapNode::Upstream(server.to_string()),
                MAX_BOOTSTRAP_DEPTH,
            )?;
            if let Some(proxy_node) = &proxy {
                ancestry.enter(proxy_node.clone(), MAX_BOOTSTRAP_DEPTH)?;
            }
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values
            .len()
    }

    fn key<T: DnsStrictTransport>(
        execution: &StrictDnsExecution,
        context: &DnsQueryContext,
        request: &Message,
        transport: &T,
        bootstrap_revision: u64,
    ) -> Option<StrictCacheKey> {
        if request.metadata.message_type != MessageType::Query
            || request.metadata.op_code != OpCode::Query
            || request.queries.len() != 1
            || request.edns.is_some()
            || request.signature.is_some()
            || context.qclass != DNSClass::IN
            || context.flags.has_edns
            || context.flags.dnssec_ok
            || context.flags.checking_disabled
            || context.flags.authentic_data
            || context.ecs.is_some()
            || context.purpose == DnsPurpose::Diagnostic
            || context.flags.recursion_desired != request.metadata.recursion_desired
            || request.metadata.checking_disabled
            || request.metadata.authentic_data
        {
            // Conservative: never cache unknown ECS/EDNS/security semantics.
            return None;
        }
        let question = &request.queries[0];
        if question.query_class() != context.qclass
            || question.query_type() != context.qtype
            || question
                .name()
                .to_ascii()
                .trim_end_matches('.')
                .to_ascii_lowercase()
                != context.qname
            || !matches!(context.qtype, RecordType::A | RecordType::AAAA)
        {
            return None;
        }
        let transport_fingerprint = transport.isolation_fingerprint()?;
        let servers = execution
            .servers
            .iter()
            .map(|server| {
                format!(
                    "{:?}|{}|{}|{:?}",
                    server.net, server.host, server.port, server.doh_path
                )
            })
            .collect();
        let egress_name = match &execution.egress {
            DnsEgress::Direct => "DIRECT".to_owned(),
            DnsEgress::Proxy(name) => format!("PROXY:{name}"),
        };
        Some(StrictCacheKey {
            qname: context.qname.clone(),
            qtype: context.qtype,
            qclass: context.qclass,
            purpose: context.purpose,
            source: context.source.clone(),
            flags: context.flags,
            ecs: context.ecs,
            network_generation: context.network_generation,
            config_generation: context.config_generation,
            bootstrap_revision,
            profile: execution.profile.clone(),
            egress_name,
            leaf: LeafIdentity(execution.outbound.clone()),
            servers,
            transport_fingerprint,
        })
    }

    fn safe_ttl(request: &Message, response: &Message) -> Option<u32> {
        if response.metadata.message_type != MessageType::Response
            || response.metadata.id != request.metadata.id
            || response.queries != request.queries
            || response.metadata.truncation
            || response.metadata.authentic_data
            || response.edns.is_some()
            || response.signature.is_some()
            || !response.additionals.is_empty()
        {
            return None;
        }
        let question = request.queries.first()?;
        match response.metadata.response_code {
            ResponseCode::NoError if !response.answers.is_empty() => {
                if !response.authorities.is_empty()
                    || response.answers.iter().any(|rr| {
                        rr.name != *question.name()
                            || rr.dns_class != question.query_class()
                            || rr.record_type() != question.query_type()
                    })
                {
                    return None;
                }
                response
                    .answers
                    .iter()
                    .map(|rr| rr.ttl)
                    .min()
                    .filter(|ttl| *ttl > 0)
            }
            ResponseCode::NXDomain | ResponseCode::NoError
                if response.answers.is_empty() =>
            {
                let [soa] = response.authorities.as_slice() else {
                    return None;
                };
                let RData::SOA(data) = &soa.data else {
                    return None;
                };
                if soa.dns_class != question.query_class()
                    || !soa.name.zone_of(question.name())
                {
                    return None;
                }
                Some(soa.ttl.min(data.minimum)).filter(|ttl| *ttl > 0)
            }
            _ => None,
        }
    }

    fn lookup(
        &self,
        key: &StrictCacheKey,
        request: &Message,
        now: Instant,
        epoch: (u64, u64, u64),
    ) -> Option<Message> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.epoch != epoch {
            return None;
        }
        let entry = inner.values.get(key)?;
        let elapsed = now.saturating_duration_since(entry.born);
        if elapsed >= entry.lifetime {
            inner.values.remove(key);
            return None;
        }
        let mut answer = entry.answer.clone();
        let age = elapsed.as_secs().min(u64::from(u32::MAX)) as u32;
        for record in answer
            .answers
            .iter_mut()
            .chain(answer.authorities.iter_mut())
            .chain(answer.additionals.iter_mut())
        {
            record.ttl = record.ttl.saturating_sub(age);
        }
        answer.metadata.id = request.metadata.id;
        answer.queries = request.queries.clone();
        answer.metadata.recursion_desired = request.metadata.recursion_desired;
        answer.metadata.checking_disabled = request.metadata.checking_disabled;
        Some(answer)
    }

    fn store(
        &self,
        key: StrictCacheKey,
        request: &Message,
        mut response: Message,
        now: Instant,
        epoch: (u64, u64, u64),
    ) {
        let Some(ttl) = Self::safe_ttl(request, &response) else {
            return;
        };
        if response.answers.is_empty() {
            // SOA's advertised TTL must not exceed RFC 2308 negative TTL.
            for record in &mut response.authorities {
                record.ttl = record.ttl.min(ttl);
            }
        }
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.epoch != epoch || self.limit == 0 {
            return;
        }
        inner.order.retain(|stored| stored != &key);
        if !inner.values.contains_key(&key) {
            while inner.values.len() >= self.limit {
                let Some(oldest) = inner.order.pop_front() else {
                    break;
                };
                inner.values.remove(&oldest);
            }
        }
        inner.order.push_back(key.clone());
        inner.values.insert(
            key,
            Cached {
                answer: response,
                born: now,
                lifetime: Duration::from_secs(u64::from(ttl)),
            },
        );
    }

    /// Explicit S04 cache wrapper. Bypass rather than guess when request has
    /// ECS/EDNS/DNSSEC/unknown semantics. No cache is used by production DNS.
    pub async fn exchange_scoped<T: DnsStrictTransport>(
        &self,
        execution: &StrictDnsExecution,
        transport: &T,
        request: &Message,
        context: &DnsQueryContext,
        bootstrap_revision: u64,
    ) -> io::Result<Message> {
        let epoch = (
            context.network_generation,
            context.config_generation,
            bootstrap_revision,
        );
        {
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if inner.epoch != epoch {
                return Err(io::Error::other(
                    "strict DNS cache epoch is stale; refresh network/config/bootstrap generation",
                ));
            }
        }
        // A cache hit still requires valid protocol/profile preflight.
        // Never serve an old response after transport policy turns unsafe.
        transport.validate_profile(&execution.servers)?;
        let key =
            Self::key(execution, context, request, transport, bootstrap_revision);
        if let Some(key) = &key
            && let Some(cached) = self.lookup(key, request, Instant::now(), epoch)
        {
            return Ok(cached);
        }
        let answer = execution.exchange(transport, request).await?;
        // A route or network change while this request was in flight makes
        // the answer stale for the caller too, not just unsafe to cache.
        // Do not return it as though it belonged to the new generation.
        if self.inner.lock().unwrap_or_else(|e| e.into_inner()).epoch != epoch {
            return Err(io::Error::other(
                "strict DNS isolation epoch changed while query was in flight; discarding old answer",
            ));
        }
        if let Some(key) = key {
            self.store(key, request, answer.clone(), Instant::now(), epoch);
        }
        Ok(answer)
    }
}

/// An explicit bootstrap DAG, not a DNS lookup implementation. An edge from
/// A to B means resolving A requires B. Detect all cycles before first dial.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum BootstrapNode {
    Profile(String),
    Upstream(String),
    Proxy(String),
}

#[derive(Default)]
pub struct BootstrapGraph {
    links: HashMap<BootstrapNode, Vec<BootstrapNode>>,
}

impl BootstrapGraph {
    pub fn require(&mut self, from: BootstrapNode, dependency: BootstrapNode) {
        self.links.entry(from).or_default().push(dependency);
    }

    pub fn validate(&self, max_depth: usize) -> io::Result<()> {
        fn dfs(
            node: &BootstrapNode,
            graph: &BootstrapGraph,
            active: &mut HashSet<BootstrapNode>,
            depth: usize,
            limit: usize,
        ) -> io::Result<()> {
            if active.contains(node) {
                return Err(io::Error::other(format!(
                    "strict DNS bootstrap cycle detected at {node:?}"
                )));
            }
            if depth >= limit {
                return Err(io::Error::other(format!(
                    "strict DNS bootstrap depth exceeded at {node:?}"
                )));
            }
            // Never memoize by node alone: a node reached from a deeper
            // parent still has to respect the remaining depth budget.
            active.insert(node.clone());
            if let Some(dependencies) = graph.links.get(node) {
                for dependency in dependencies {
                    dfs(dependency, graph, active, depth + 1, limit)?;
                }
            }
            active.remove(node);
            Ok(())
        }
        if max_depth == 0 {
            return Err(io::Error::other(
                "strict DNS bootstrap max depth must be positive",
            ));
        }
        for node in self.links.keys() {
            dfs(node, self, &mut HashSet::new(), 0, max_depth)?;
        }
        Ok(())
    }
}

/// Immutable per-request trace: safe for concurrent bootstrap requests,
/// unlike a global shared recursion stack.
#[derive(Clone, Debug, Default)]
pub struct BootstrapTrace {
    path: Vec<BootstrapNode>,
}

impl BootstrapTrace {
    pub fn enter(&self, next: BootstrapNode, max_depth: usize) -> io::Result<Self> {
        if self.path.contains(&next) {
            return Err(io::Error::other(format!(
                "strict DNS bootstrap recursion cycle at {next:?}"
            )));
        }
        if self.path.len() >= max_depth {
            return Err(io::Error::other(
                "strict DNS bootstrap recursion depth exceeded",
            ));
        }
        let mut path = self.path.clone();
        path.push(next);
        Ok(Self { path })
    }
}

#[cfg(test)]
mod tests;
