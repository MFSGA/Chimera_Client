//! S03a: strict, opt-in DNS outbound preflight and mockable transport boundary.
//!
//! No live resolver calls this module yet. A matched policy must not fall
//! through to the legacy path when explicit DNS egress cannot be enforced.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use hickory_proto::op::{Message, MessageType, ResponseCode};

use crate::{
    app::dns::{
        ClashResolver, ResolverKind,
        dns_client::{DNSNetMode, DnsClient, Opts},
    },
    config::internal::proxy::PROXY_DIRECT,
    proxy::{
        AnyOutboundHandler, OutboundType, direct, group::selector::PinnedOutbound,
        utils::OutboundHandlerRegistry,
    },
    session::Session,
};

use super::{
    config::NameServer,
    plan::{
        EffectiveDnsPlan, EgressChoice, FailureChoice, LegacyDnsPlan,
        LegacyDnsRoute, ResolverChoice,
    },
    policy::{CompiledDnsPolicy, DnsEgress, DnsFailure},
};

/// S03b bootstrap guard: no implicit system DNS lookup may escape the
/// explicit strict-DNS policy. Only literal addresses are resolvable until
/// S04 supplies a separately verified bootstrap dependency graph.
struct LiteralOnlyResolver {
    ipv6: AtomicBool,
    pins: HashMap<String, IpAddr>,
}

impl Default for LiteralOnlyResolver {
    fn default() -> Self {
        Self {
            ipv6: AtomicBool::new(true),
            pins: HashMap::new(),
        }
    }
}

#[async_trait]
impl ClashResolver for LiteralOnlyResolver {
    async fn resolve(&self, host: &str, _: bool) -> anyhow::Result<Option<IpAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(Some(ip));
        }
        let key = host.trim_end_matches('.').to_ascii_lowercase();
        self.pins.get(&key).copied().map(Some).ok_or_else(|| anyhow::anyhow!(
            "strict DNS bootstrap refused to resolve unpinned domain '{host}' via system/legacy DNS"
        ))
    }

    async fn resolve_v4(
        &self,
        host: &str,
        _: bool,
    ) -> anyhow::Result<Option<Ipv4Addr>> {
        match self.resolve(host, false).await? {
            Some(IpAddr::V4(ip)) => Ok(Some(ip)),
            _ => Ok(None),
        }
    }

    async fn resolve_v6(
        &self,
        host: &str,
        _: bool,
    ) -> anyhow::Result<Option<Ipv6Addr>> {
        match self.resolve(host, false).await? {
            Some(IpAddr::V6(ip)) => Ok(Some(ip)),
            _ => Ok(None),
        }
    }

    async fn cached_for(&self, _: IpAddr) -> Option<String> {
        None
    }
    async fn exchange(&self, _: &Message) -> anyhow::Result<Message> {
        anyhow::bail!("strict DNS bootstrap is not a recursive resolver")
    }
    async fn reverse_lookup(&self, _: IpAddr) -> Option<String> {
        None
    }
    async fn is_fake_ip(&self, _: IpAddr) -> bool {
        false
    }
    async fn fake_ip_for_host(&self, _: &str) -> Option<IpAddr> {
        None
    }
    fn fake_ip_enabled(&self) -> bool {
        false
    }
    fn ipv6(&self) -> bool {
        self.ipv6.load(Ordering::Relaxed)
    }
    fn set_ipv6(&self, enabled: bool) {
        self.ipv6.store(enabled, Ordering::Relaxed);
    }
    fn kind(&self) -> ResolverKind {
        ResolverKind::Clash
    }
}

/// Strict wire transport with no implicit bootstrap. UDP/TCP require an IP
/// literal endpoint; DoT/DoH need a separately pinned endpoint (S03c).
pub struct DnsStrictWireTransport;

/// Explicit, caller-supplied hostname -> IP bindings. This is an internal
/// S03c transport option, NOT a configuration parser or bootstrap resolver.
/// Only the exact upstream DNS identity is allowed; no OS DNS calls occur.
#[derive(Default)]
pub struct DnsStrictPinnedWireTransport {
    pins: HashMap<String, IpAddr>,
}

impl DnsStrictPinnedWireTransport {
    pub fn new(pins: HashMap<String, IpAddr>) -> io::Result<Self> {
        if pins.keys().any(|key| {
            key.is_empty()
                || key.trim() != key
                || key.ends_with('.')
                || key != &key.to_ascii_lowercase()
        }) {
            return Err(io::Error::other(
                "strict DNS bootstrap pin names must be lowercase, canonical, nonempty and without trailing dot",
            ));
        }
        Ok(Self { pins })
    }
}

fn validate_strict_wire_server(
    server: &NameServer,
    _pins: &HashMap<String, IpAddr>,
) -> io::Result<()> {
    if server.interface.is_some() || server.proxy.is_some() {
        return Err(io::Error::other(
            "strict DNS forbids a second #proxy/#interface override",
        ));
    }
    match server.net {
        DNSNetMode::Udp | DNSNetMode::Tcp => {
            if !matches!(server.host, url::Host::Ipv4(_) | url::Host::Ipv6(_)) {
                return Err(io::Error::other(format!(
                    "strict DNS upstream '{}' needs explicit bootstrap; refusing system DNS",
                    server.host
                )));
            }
        }
        DNSNetMode::DoT | DNSNetMode::DoH => {
            #[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "strict encrypted DNS needs the aws-lc-rs or ring feature",
            ));
            #[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
            {
                // Crucial: legacy DoH has an IP-hostname TLS bypass. For a
                // strict policy, always require a real, separately verified
                // DNS hostname and an explicit static IP pin.
                let url::Host::Domain(host) = &server.host else {
                    return Err(io::Error::other(
                        "strict DoT/DoH requires DNS hostname for verified TLS identity; IP-hostname bypass forbidden",
                    ));
                };
                if !_pins.contains_key(&host.to_ascii_lowercase()) {
                    return Err(io::Error::other(format!(
                        "strict encrypted DNS upstream '{host}' needs explicit IP bootstrap pin"
                    )));
                }
                rustls::pki_types::ServerName::try_from(host.to_owned())
                    .map_err(|error| io::Error::other(format!(
                        "strict encrypted DNS invalid TLS server identity '{host}': {error}"
                    )))?;
            }
        }
        DNSNetMode::Dhcp => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "strict DNS does not support DHCP transport",
            ));
        }
    }
    Ok(())
}

async fn exchange_strict_wire(
    server: &NameServer,
    outbound: AnyOutboundHandler,
    request: &Message,
    pins: &HashMap<String, IpAddr>,
) -> io::Result<Message> {
    validate_strict_wire_server(server, pins)?;
    if let Some(host) = outbound.server_name()
        && host.parse::<IpAddr>().is_err()
    {
        return Err(io::Error::other(format!(
            "strict DNS proxy '{}' requires unresolved bootstrap '{}' (S04 pending)",
            outbound.name(),
            host
        )));
    }
    let restricted_resolver = Arc::new(LiteralOnlyResolver {
        ipv6: AtomicBool::new(true),
        pins: pins.clone(),
    });
    let client = DnsClient::new_client(Opts {
        father: Some(restricted_resolver.clone()),
        outbound_resolver: Some(restricted_resolver),
        host: server.host.clone(),
        port: server.port,
        net: server.net.clone(),
        iface: None,
        proxy: outbound,
        ecs: None,
        doh_path: server.doh_path.clone(),
        fw_mark: None,
        rule_dispatch: None,
        network_path_source: None,
    })
    .await
    .map_err(io::Error::other)?;
    let result =
        tokio::time::timeout(Duration::from_secs(5), client.exchange(request)).await;
    let cleanup =
        tokio::time::timeout(Duration::from_secs(1), client.reset_transport()).await;
    match cleanup {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => {
            return Err(io::Error::other(format!(
                "strict DNS cleanup failed: {error}"
            )));
        }
        Err(_) => {
            return Err(io::Error::other("strict DNS transport cleanup timed out"));
        }
    }
    match result {
        Ok(Ok(mut message)) => {
            // Hickory TCP/TLS may allocate a fresh per-connection wire ID;
            // it validates that ID before returning, then we restore the
            // original application-request transaction identity.
            message.metadata.id = request.metadata.id;
            Ok(message)
        }
        Ok(Err(error)) => Err(io::Error::other(error)),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "strict DNS transport attempt timed out",
        )),
    }
}

#[async_trait]
impl DnsStrictTransport for DnsStrictWireTransport {
    fn validate_server(&self, server: &NameServer) -> io::Result<()> {
        validate_strict_wire_server(server, &HashMap::new())
    }

    async fn exchange(
        &self,
        server: &NameServer,
        outbound: AnyOutboundHandler,
        request: &Message,
    ) -> io::Result<Message> {
        exchange_strict_wire(server, outbound, request, &HashMap::new()).await
    }
}

#[async_trait]
impl DnsStrictTransport for DnsStrictPinnedWireTransport {
    fn validate_server(&self, server: &NameServer) -> io::Result<()> {
        validate_strict_wire_server(server, &self.pins)
    }

    async fn exchange(
        &self,
        server: &NameServer,
        outbound: AnyOutboundHandler,
        request: &Message,
    ) -> io::Result<Message> {
        exchange_strict_wire(server, outbound, request, &self.pins).await
    }
}

/// Network operations in S03b must use the exact chosen handler and server.
/// The transport cannot request a different (e.g. DIRECT) outbound from this
/// interface. S03a tests use fake implementations; no DNS socket is created.
#[async_trait]
pub trait DnsStrictTransport: Send + Sync {
    /// Validate every configured server before the first network attempt to
    /// prevent silent downgrade from unsupported TLS DNS to plaintext UDP.
    fn validate_server(&self, _server: &NameServer) -> io::Result<()> {
        Ok(())
    }

    fn validate_profile(&self, servers: &[NameServer]) -> io::Result<()> {
        // If an encrypted endpoint cannot return an answer, do not quietly
        // retry on a plaintext protocol in the same declared profile.
        let encrypted = servers
            .iter()
            .any(|s| matches!(s.net, DNSNetMode::DoT | DNSNetMode::DoH));
        let plaintext = servers
            .iter()
            .any(|s| matches!(s.net, DNSNetMode::Udp | DNSNetMode::Tcp));
        if encrypted && plaintext {
            return Err(io::Error::other(
                "strict DNS profile cannot mix encrypted DoT/DoH with plaintext UDP/TCP",
            ));
        }
        for server in servers {
            self.validate_server(server)?;
        }
        Ok(())
    }

    async fn exchange(
        &self,
        server: &NameServer,
        outbound: AnyOutboundHandler,
        query: &Message,
    ) -> io::Result<Message>;
}

pub enum PreparedDnsExecution {
    /// The legacy resolver owns local Fake-IP/hosts responses.
    LocalAnswer,
    /// Unmatched policies are delegated wholly to the existing resolver.
    Legacy(LegacyDnsPlan),
    /// Explicit policy with a pinned handler and a named resolver profile.
    Strict(StrictDnsExecution),
}

pub struct StrictDnsExecution {
    pub ordinal: usize,
    pub egress: DnsEgress,
    pub profile: String,
    pub servers: Vec<NameServer>,
    pub outbound: AnyOutboundHandler,
}

impl StrictDnsExecution {
    /// Retry only within the declared resolver profile, always through the
    /// SAME pinned outbound. Never invoke legacy fallback or business Router.
    /// A failed proxy cannot be retried via DIRECT.
    pub async fn exchange<T: DnsStrictTransport>(
        &self,
        transport: &T,
        request: &Message,
    ) -> io::Result<Message> {
        transport.validate_profile(&self.servers).map_err(|error| {
            io::Error::other(format!(
                "strict DNS rule[{}] profile '{}' cannot be safely executed: {error}",
                self.ordinal, self.profile
            ))
        })?;

        // Keep the WHOLE strict attempt bounded, including retries among
        // servers in the same declared profile. No network dial can remain
        // stuck indefinitely in this execution layer.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut failures = Vec::with_capacity(self.servers.len());
        for server in &self.servers {
            let result = tokio::time::timeout_at(
                deadline,
                transport.exchange(server, self.outbound.clone(), request),
            )
            .await;
            match result {
                Ok(Ok(answer))
                    if answer.metadata.message_type == MessageType::Response
                        && answer.metadata.id == request.metadata.id
                        && answer.queries == request.queries
                        && !answer.metadata.truncation
                        && matches!(
                            answer.metadata.response_code,
                            ResponseCode::NoError | ResponseCode::NXDomain
                        ) =>
                {
                    return Ok(answer);
                }
                Ok(Ok(answer)) => failures.push(format!(
                    "{server}: invalid, truncated or unsuccessful DNS response (rcode {}, type {:?}, id_match {}, question_match {}, tc {})",
                    answer.metadata.response_code,
                    answer.metadata.message_type,
                    answer.metadata.id == request.metadata.id,
                    answer.queries == request.queries,
                    answer.metadata.truncation
                )),
                Ok(Err(error)) => failures.push(format!("{server}: {error}")),
                Err(_) => {
                    failures.push(format!("{server}: strict DNS total deadline exceeded"));
                    break;
                }
            }
        }
        Err(io::Error::other(format!(
            "strict DNS rule[{}] profile '{}' failed via {:?};              no DIRECT/legacy fallback permitted: {}",
            self.ordinal,
            self.profile,
            self.egress,
            failures.join("; ")
        )))
    }
}

/// Prepare one immutable egress decision from an S02 plan. This is not the
/// production DNS runtime activation path: it is deliberately strict about
/// unimplemented partial-override semantics.
pub async fn prepare_dns_execution(
    plan: &EffectiveDnsPlan,
    profiles: &CompiledDnsPolicy,
    registry: &OutboundHandlerRegistry,
    session: &Session,
) -> io::Result<PreparedDnsExecution> {
    if plan.legacy.route == LegacyDnsRoute::LocalAnswer {
        return Ok(PreparedDnsExecution::LocalAnswer);
    }
    let Some(ordinal) = plan.matched_rule else {
        return Ok(PreparedDnsExecution::Legacy(plan.legacy.clone()));
    };

    // Preserve partial actions in S02, but don't pretend that an inherited
    // resolver/fallback can already satisfy a strict egress failure policy.
    let ResolverChoice::Profile(profile) = &plan.resolver else {
        return Err(io::Error::other(format!(
            "strict DNS rule[{ordinal}] cannot yet execute without an explicit resolver profile"
        )));
    };
    let EgressChoice::Explicit(egress) = &plan.egress else {
        return Err(io::Error::other(format!(
            "strict DNS rule[{ordinal}] cannot yet execute without an explicit DNS egress"
        )));
    };
    if plan.failure != FailureChoice::Explicit(DnsFailure::Fail) {
        return Err(io::Error::other(format!(
            "strict DNS rule[{ordinal}] requires on-failure: fail until bounded inheritance is implemented"
        )));
    }
    let servers = profiles.profiles.get(profile).filter(|v| !v.is_empty()).ok_or_else(|| {
        io::Error::other(format!(
            "strict DNS rule[{ordinal}] resolver profile '{profile}' is unavailable"
        ))
    })?;

    // S01 disallows forced #proxy/#interface with explicit egress. Recheck at
    // runtime too: the profile is held in public mutable compiled data.
    if servers
        .iter()
        .any(|s| s.proxy.is_some() || s.interface.is_some())
    {
        return Err(io::Error::other(format!(
            "strict DNS rule[{ordinal}] profile '{profile}' conflicts with #proxy/#interface"
        )));
    }

    let outbound: AnyOutboundHandler = match egress {
        DnsEgress::Direct => Arc::new(direct::Handler::new(PROXY_DIRECT)),
        DnsEgress::Proxy(name) => {
            // NEVER use SharedOutboundHandler: missing names silently map to DIRECT.
            let named = registry.read().await.get(name).cloned().ok_or_else(|| {
                io::Error::other(format!(
                    "strict DNS rule[{ordinal}] proxy '{name}' missing; refusing DIRECT fallback"
                ))
            })?;
            let pinned = PinnedOutbound::capture(named, session).await.map_err(|error| {
                io::Error::other(format!(
                    "strict DNS rule[{ordinal}] proxy '{name}' unavailable: {error}"
                ))
            })?;
            if matches!(
                pinned.handler.proto(),
                OutboundType::Direct | OutboundType::Reject
            ) {
                return Err(io::Error::other(format!(
                    "strict DNS rule[{ordinal}] proxy '{name}' selected a DIRECT/REJECT leaf;                      refusing downgrade"
                )));
            }
            pinned.handler
        }
    };

    Ok(PreparedDnsExecution::Strict(StrictDnsExecution {
        ordinal,
        egress: egress.clone(),
        profile: profile.clone(),
        servers: servers.clone(),
        outbound,
    }))
}

#[cfg(test)]
mod tests;
