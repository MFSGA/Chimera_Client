//! S04a: conservative strict DNS cache partitions and bootstrap dependency
//! guards. Separate from EnhancedResolver's legacy positive/negative caches.
//! No production policy-rules path consumes this until S04/S05 activation.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    hash::{Hash, Hasher},
    io,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{DNSClass, RData, RecordType},
};

use crate::proxy::AnyOutboundHandler;

use super::{
    execution::{DnsStrictTransport, StrictDnsExecution},
    plan::{DnsPurpose, DnsQueryContext, DnsQueryFlags, DnsSourceScope},
    policy::DnsEgress,
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
