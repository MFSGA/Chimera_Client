use async_trait::async_trait;
use futures::{FutureExt, Sink, Stream, StreamExt, stream::FuturesUnordered};
#[cfg(feature = "hysteria")]
use std::collections::HashMap;
use std::{
    collections::{HashSet, VecDeque},
    fmt::Debug,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, LazyLock},
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::trace;

use super::{new_protected_tcp_stream, new_protected_tcp_stream_with_source};
use crate::{
    app::{
        dispatcher::{
            ChainedDatagram, ChainedDatagramWrapper, ChainedStream,
            ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
        flow::{
            AddressFamily, DirectPathSelection, IntentStrength, InterfaceId,
            NetworkIntentSnapshot, NetworkPath, NetworkPathId, PathIntent,
            PathTarget, RouteDecision,
        },
        net::OutboundInterface,
        network::{NetworkStatus, PathCandidateObservation},
        path_policy::compile_path_plan,
    },
    common::errors::new_io_error,
    proxy::{
        AnyOutboundDatagram, AnyOutboundHandler, AnyStream, datagram::UdpPacket,
        direct::datagram::OutboundDatagramImpl, utils::new_protected_udp_socket,
    },
    session::{Network, Session, SocksAddr, Type},
};

const DIRECT_TCP_ATTEMPT_LIMIT: usize = 3;
const DIRECT_TCP_PARALLEL_LIMIT: usize = 2;
const DIRECT_TCP_HEDGE_DELAY: Duration = Duration::from_millis(120);
const DIRECT_TCP_TOTAL_BUDGET: Duration = Duration::from_secs(5);
const PROXY_ENDPOINT_TCP_ATTEMPT_LIMIT: usize = 3;
const PROXY_ENDPOINT_TCP_PARALLEL_LIMIT: usize = 2;
const PROXY_ENDPOINT_TCP_ADDRESS_LIMIT: usize = 3;
const PROXY_ENDPOINT_TCP_HEDGE_DELAY: Duration = Duration::from_millis(120);
const PROXY_ENDPOINT_TCP_TOTAL_BUDGET: Duration = Duration::from_secs(5);
const PROXY_UDP_PATH_ATTEMPT_LIMIT: usize = 3;

/// Structured endpoint-dial diagnostics retained through proxy protocol `?`
/// propagation so Dispatcher Explain can report the paths that were eligible
/// and attempted when the endpoint could not be reached.
#[derive(Debug)]
pub struct ProxyEndpointConnectError {
    kind: std::io::ErrorKind,
    message: String,
    candidate_paths: Vec<NetworkPathId>,
    attempted_paths: Vec<NetworkPathId>,
    rejected: Vec<crate::app::flow::CandidateRejection>,
}

impl ProxyEndpointConnectError {
    fn into_io_error(self) -> std::io::Error {
        std::io::Error::new(self.kind, self)
    }

    pub fn candidate_paths(&self) -> &[NetworkPathId] {
        &self.candidate_paths
    }

    pub fn attempted_paths(&self) -> &[NetworkPathId] {
        &self.attempted_paths
    }

    pub fn rejected(&self) -> &[crate::app::flow::CandidateRejection] {
        &self.rejected
    }
}

impl std::fmt::Display for ProxyEndpointConnectError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ProxyEndpointConnectError {}

#[derive(Clone, Debug, Default)]
pub struct NetworkPoolContext {
    pub network_generation: Option<u64>,
    pub path_id: Option<NetworkPathId>,
    /// `Some` means only these observed and policy-eligible paths may back a
    /// reusable connection. `None` keeps generation-only behavior when the
    /// connector has no shared observation source.
    pub eligible_path_ids: Option<HashSet<NetworkPathId>>,
    pub(crate) reporter: Option<crate::app::runtime_state::TrafficReporter>,
}

impl NetworkPoolContext {
    pub fn for_generation(network_generation: Option<u64>) -> Self {
        Self {
            network_generation,
            ..Self::default()
        }
    }

    pub fn permits(
        &self,
        network_generation: Option<u64>,
        path_id: Option<&NetworkPathId>,
    ) -> bool {
        self.network_generation == network_generation
            && self.eligible_path_ids.as_ref().is_none_or(|eligible| {
                path_id.is_some_and(|path_id| eligible.contains(path_id))
            })
    }

    pub fn can_pool_connected_path(&self) -> bool {
        self.eligible_path_ids.as_ref().is_none_or(|eligible| {
            self.path_id
                .as_ref()
                .is_some_and(|path_id| eligible.contains(path_id))
        })
    }

    pub(crate) fn target_response_proof(
        &self,
        kind: crate::app::runtime_state::TrafficKind,
        destination: &SocksAddr,
    ) -> Option<crate::app::runtime_state::TrafficProof> {
        let path_id = self.path_id.clone()?;
        Some(self.reporter.as_ref()?.capture_scoped(
            kind,
            Some(path_id),
            Some(destination.clone()),
        ))
    }
}

#[derive(Clone)]
struct DirectStreamAttempt {
    endpoint: SocketAddr,
    path: Option<NetworkPath>,
}

struct PathHealthStream {
    inner: AnyStream,
    proof: crate::app::runtime_state::TrafficProof,
}

impl AsyncRead for PathHealthStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(self.inner.as_mut()).poll_read(cx, buffer);
        match &result {
            Poll::Ready(Ok(())) => {
                let received = buffer.filled().len().saturating_sub(before);
                self.proof.received(received);
            }
            Poll::Ready(Err(error)) => self.proof.failed(error.kind()),
            Poll::Pending => {}
        }
        result
    }
}

impl AsyncWrite for PathHealthStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(self.inner.as_mut()).poll_write(cx, buffer);
        if let Poll::Ready(Err(error)) = &result {
            self.proof.failed(error.kind());
        }
        result
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(self.inner.as_mut()).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(self.inner.as_mut()).poll_shutdown(cx)
    }
}

async fn observe_proxy_endpoint_stream(
    stream: AnyStream,
    source: &NetworkPathSource,
    path_id: crate::app::flow::NetworkPathId,
    endpoint: SocketAddr,
) -> AnyStream {
    let Some(reporter) = source.traffic_reporter().await else {
        return stream;
    };
    let proof = reporter.capture_scoped(
        crate::app::runtime_state::TrafficKind::ProxyEndpointTcp,
        Some(path_id),
        Some(SocksAddr::Ip(endpoint)),
    );
    Box::new(PathHealthStream {
        inner: stream,
        proof,
    })
}

struct PathHealthDatagram {
    inner: AnyOutboundDatagram,
    proof: crate::app::runtime_state::TrafficProof,
}

impl Stream for PathHealthDatagram {
    type Item = UdpPacket;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(packet)) => {
                this.proof.received(packet.data.len());
                Poll::Ready(Some(packet))
            }
            result => result,
        }
    }
}

impl Sink<UdpPacket> for PathHealthDatagram {
    type Error = std::io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_ready(cx);
        if let Poll::Ready(Err(error)) = &result {
            this.proof.failed(error.kind());
        }
        result
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).start_send(item);
        if let Err(error) = &result {
            this.proof.failed(error.kind());
        }
        result
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_flush(cx);
        if let Poll::Ready(Err(error)) = &result {
            this.proof.failed(error.kind());
        }
        result
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_close(cx);
        if let Poll::Ready(Err(error)) = &result {
            this.proof.failed(error.kind());
        }
        result
    }
}

fn observe_proxy_endpoint_datagram(
    datagram: AnyOutboundDatagram,
    context: &NetworkPoolContext,
    destination: &SocksAddr,
) -> AnyOutboundDatagram {
    let Some(proof) = context.target_response_proof(
        crate::app::runtime_state::TrafficKind::ProxyEndpointUdp,
        destination,
    ) else {
        return datagram;
    };
    Box::new(PathHealthDatagram {
        inner: datagram,
        proof,
    })
}

#[cfg(feature = "hysteria")]
struct PathHealthTargetDatagram {
    inner: AnyOutboundDatagram,
    context: NetworkPoolContext,
    pending: HashMap<SocksAddr, crate::app::runtime_state::TrafficProof>,
    pending_order: VecDeque<SocksAddr>,
}

#[cfg(feature = "hysteria")]
impl Stream for PathHealthTargetDatagram {
    type Item = UdpPacket;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(packet)) => {
                if let Some(proof) = this.pending.remove(&packet.src_addr) {
                    this.pending_order
                        .retain(|target| target != &packet.src_addr);
                    proof.received(packet.data.len());
                }
                Poll::Ready(Some(packet))
            }
            result => result,
        }
    }
}

#[cfg(feature = "hysteria")]
impl Sink<UdpPacket> for PathHealthTargetDatagram {
    type Error = std::io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let this = self.get_mut();
        let target = item.dst_addr.clone();
        let proof = this.context.target_response_proof(
            crate::app::runtime_state::TrafficKind::ProxyUdp,
            &target,
        );
        if let Err(error) = Pin::new(&mut this.inner).start_send(item) {
            if let Some(proof) = proof {
                proof.failed(error.kind());
            }
            return Err(error);
        }

        if let Some(proof) = proof {
            if !this.pending.contains_key(&target) {
                while this.pending.len() >= 64 {
                    let Some(expired) = this.pending_order.pop_front() else {
                        break;
                    };
                    this.pending.remove(&expired);
                }
                this.pending_order.push_back(target.clone());
            }
            this.pending.insert(target, proof);
        }
        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
}

#[cfg(feature = "hysteria")]
pub(crate) fn observe_proxy_target_datagram(
    datagram: AnyOutboundDatagram,
    context: &NetworkPoolContext,
) -> AnyOutboundDatagram {
    if context.path_id.is_none() || context.reporter.is_none() {
        return datagram;
    }
    Box::new(PathHealthTargetDatagram {
        inner: datagram,
        context: context.clone(),
        pending: HashMap::new(),
        pending_order: VecDeque::new(),
    })
}

pub(crate) fn observe_proxy_target_stream(
    stream: AnyStream,
    context: &NetworkPoolContext,
    destination: &SocksAddr,
    kind: crate::app::runtime_state::TrafficKind,
) -> AnyStream {
    let Some(proof) = context.target_response_proof(kind, destination) else {
        return stream;
    };
    Box::new(PathHealthStream {
        inner: stream,
        proof,
    })
}

pub(crate) type SharedNetworkStatus = Arc<tokio::sync::RwLock<NetworkStatus>>;

/// Runtime status is attached after the outbound graph has been constructed.
/// Proxy endpoint dials can then use current observations without pinning a
/// handler to the snapshot that existed during configuration loading.
#[derive(Clone, Default)]
pub(crate) struct NetworkPathSource {
    status: Arc<tokio::sync::RwLock<Option<SharedNetworkStatus>>>,
    traffic_reporter:
        Arc<tokio::sync::RwLock<Option<crate::app::runtime_state::TrafficReporter>>>,
}

impl Debug for NetworkPathSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkPathSource").finish_non_exhaustive()
    }
}

impl NetworkPathSource {
    pub(crate) async fn attach(&self, status: SharedNetworkStatus) {
        *self.status.write().await = Some(status);
    }

    pub(crate) async fn attach_traffic_reporter(
        &self,
        reporter: crate::app::runtime_state::TrafficReporter,
    ) {
        *self.traffic_reporter.write().await = Some(reporter);
    }

    pub(crate) async fn traffic_reporter(
        &self,
    ) -> Option<crate::app::runtime_state::TrafficReporter> {
        self.traffic_reporter.read().await.clone()
    }

    pub(crate) async fn snapshot(
        &self,
    ) -> Option<(
        u64,
        Vec<PathCandidateObservation>,
        bool,
        SharedNetworkStatus,
        NetworkIntentSnapshot,
    )> {
        let status = self.status.read().await.clone()?;
        let snapshot = status.write().await.path_planning_snapshot()?;
        Some((snapshot.0, snapshot.1, snapshot.2, status, snapshot.3))
    }
}

/// allows a proxy to get a connection to a remote server
#[async_trait]
pub trait RemoteConnector: Send + Sync + Debug {
    /// Current observed generation used for newly opened physical paths.
    /// Connectors without shared network observation return `None`.
    async fn network_generation(&self) -> Option<u64> {
        None
    }

    /// Paths on which an existing pooled connection remains eligible.
    /// Connectors without path-level metadata return a generation-only context.
    async fn connection_pool_context(
        &self,
        _iface: Option<&OutboundInterface>,
    ) -> NetworkPoolContext {
        NetworkPoolContext::for_generation(self.network_generation().await)
    }

    async fn connect_stream(
        &self,
        resolver: ThreadSafeDNSResolver,
        address: &str,
        port: u16,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] packet_mark: Option<u32>,
    ) -> std::io::Result<AnyStream>;

    /// Establish a stream and return the path that actually won the dial.
    /// The default keeps compatibility for connectors that cannot expose it.
    async fn connect_stream_with_pool_context(
        &self,
        resolver: ThreadSafeDNSResolver,
        address: &str,
        port: u16,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] packet_mark: Option<u32>,
        pool_context: NetworkPoolContext,
    ) -> std::io::Result<(AnyStream, NetworkPoolContext)> {
        let stream = self
            .connect_stream(
                resolver,
                address,
                port,
                iface,
                #[cfg(target_os = "linux")]
                packet_mark,
            )
            .await?;
        Ok((stream, pool_context))
    }

    async fn connect_datagram(
        &self,
        resolver: ThreadSafeDNSResolver,
        src: Option<SocketAddr>,
        destination: SocksAddr,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] packet_mark: Option<u32>,
    ) -> std::io::Result<AnyOutboundDatagram>;

    /// Establish a datagram socket and return the network path that actually
    /// backs it. Connectors that cannot observe physical paths retain the
    /// supplied generation-only context.
    async fn connect_datagram_with_pool_context(
        &self,
        resolver: ThreadSafeDNSResolver,
        src: Option<SocketAddr>,
        destination: SocksAddr,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] packet_mark: Option<u32>,
        pool_context: NetworkPoolContext,
    ) -> std::io::Result<(AnyOutboundDatagram, NetworkPoolContext)> {
        let datagram = self
            .connect_datagram(
                resolver,
                src,
                destination,
                iface,
                #[cfg(target_os = "linux")]
                packet_mark,
            )
            .await?;
        Ok((datagram, pool_context))
    }
}

#[derive(Clone, Debug, Default)]
pub struct DirectConnector {
    path_source: Option<NetworkPathSource>,
}

impl DirectConnector {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn with_path_source(path_source: NetworkPathSource) -> Self {
        Self {
            path_source: Some(path_source),
        }
    }

    #[cfg(test)]
    fn endpoint_path(
        iface: Option<&OutboundInterface>,
        family: AddressFamily,
        observations: &[PathCandidateObservation],
        network_generation: u64,
        base_intent: &NetworkIntentSnapshot,
    ) -> std::io::Result<Option<NetworkPath>> {
        Ok(Self::endpoint_paths(
            iface,
            family,
            observations,
            network_generation,
            base_intent,
        )?
        .into_iter()
        .next())
    }

    #[cfg(test)]
    fn endpoint_paths(
        iface: Option<&OutboundInterface>,
        family: AddressFamily,
        observations: &[PathCandidateObservation],
        network_generation: u64,
        base_intent: &NetworkIntentSnapshot,
    ) -> std::io::Result<Vec<NetworkPath>> {
        let (paths, selected, rejected) = Self::endpoint_paths_with_selection(
            iface,
            family,
            observations,
            network_generation,
            base_intent,
        )?;
        if iface.is_some() && selected.is_none() {
            let candidate_paths = paths.iter().map(|path| path.id.clone()).collect();
            return Err(ProxyEndpointConnectError {
                kind: std::io::ErrorKind::NetworkUnreachable,
                message: format!(
                    "required proxy endpoint path unavailable for {family:?}"
                ),
                candidate_paths,
                attempted_paths: Vec::new(),
                rejected,
            }
            .into_io_error());
        }
        Ok(paths)
    }

    fn endpoint_paths_with_selection(
        iface: Option<&OutboundInterface>,
        family: AddressFamily,
        observations: &[PathCandidateObservation],
        network_generation: u64,
        base_intent: &NetworkIntentSnapshot,
    ) -> std::io::Result<(
        Vec<NetworkPath>,
        Option<crate::app::flow::NetworkPathId>,
        Vec<crate::app::flow::CandidateRejection>,
    )> {
        let mut intent = base_intent.clone();
        if let Some(iface) = iface {
            intent.intents.push(PathIntent {
                strength: IntentStrength::Require,
                target: PathTarget::Interface(InterfaceId {
                    name: iface.name.clone(),
                    index: iface.index,
                }),
            });
        }
        let result = compile_path_plan(
            observations,
            &intent,
            network_generation,
            RouteDecision {
                outbound: "PROXY_ENDPOINT".to_owned(),
                rule: None,
            },
            Some(family),
        );
        let selected = result.decision.selected.clone();
        let selected_path_id = selected.clone();
        let mut candidates = result.plan.candidates;
        if let Some(selected) = selected
            && let Some(index) = candidates
                .iter()
                .position(|candidate| candidate.id == selected)
        {
            candidates.swap(0, index);
        }
        Ok((candidates, selected_path_id, result.decision.rejected))
    }

    /// Resolve once, then make at most three bounded socket attempts over the
    /// eligible family/path pairs. A successful attempt drops pending futures;
    /// a failed attempt immediately advances the queue. Hard requirements do
    /// not gain a system-route fallback.
    pub async fn connect_stream_with_path_selection_result(
        &self,
        resolver: ThreadSafeDNSResolver,
        address: &str,
        port: u16,
        iface: Option<&OutboundInterface>,
        selection: &DirectPathSelection,
        #[cfg(target_os = "linux")] packet_mark: Option<u32>,
    ) -> std::io::Result<(AnyStream, Option<crate::app::flow::NetworkPathId>)> {
        let deadline = tokio::time::Instant::now() + DIRECT_TCP_TOTAL_BUDGET;
        let addresses = if let Ok(ip) = address.parse() {
            vec![ip]
        } else {
            tokio::time::timeout_at(
                deadline,
                resolver.resolve_all(address, false),
            )
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "DIRECT TCP DNS resolution exceeded the 5 second attempt budget",
                )
            })?
            .map_err(|error| new_io_error(format!("can't resolve dns: {error}")))?
        };
        if addresses.is_empty() {
            return Err(new_io_error("no dns result"));
        }

        let endpoints = interleave_ip_families(addresses)
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect::<Vec<_>>();
        let max_path_count = endpoints
            .iter()
            .map(|endpoint| {
                selection
                    .candidates_for_family(AddressFamily::from(endpoint.ip()))
                    .len()
            })
            .max()
            .unwrap_or_default();
        let mut planned_attempts = Vec::new();

        // Build rounds across resolved addresses so a long list in one family
        // cannot consume the attempt budget before the other family is tried.
        for path_index in 0..max_path_count {
            for endpoint in &endpoints {
                let family = AddressFamily::from(endpoint.ip());
                if let Some(path) =
                    selection.candidates_for_family(family).get(path_index)
                {
                    planned_attempts.push(DirectStreamAttempt {
                        endpoint: *endpoint,
                        path: Some(path.clone()),
                    });
                }
            }
        }
        if !selection.required {
            // Preferences may fall back to the operating system route after
            // observed, locally bindable paths have failed.
            if let Some(endpoint) = endpoints.first() {
                planned_attempts.push(DirectStreamAttempt {
                    endpoint: *endpoint,
                    path: None,
                });
            }
        }
        planned_attempts.truncate(DIRECT_TCP_ATTEMPT_LIMIT);
        if planned_attempts.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NetworkUnreachable,
                "required network path unavailable for every resolved address family",
            ));
        }

        let first_family = AddressFamily::from(endpoints[0].ip());
        let ambiguous_first_family = selection.for_family(first_family).is_none()
            && selection.candidates_for_family(first_family).len() > 1;
        let mut next_attempt = 0;
        let mut attempts = FuturesUnordered::new();
        let mut errors = Vec::new();
        let initial_count = if ambiguous_first_family {
            DIRECT_TCP_PARALLEL_LIMIT
        } else {
            1
        };
        while next_attempt < planned_attempts.len() && attempts.len() < initial_count
        {
            push_direct_stream_attempt(
                &mut attempts,
                planned_attempts[next_attempt].clone(),
                iface.cloned(),
                #[cfg(target_os = "linux")]
                packet_mark,
            );
            next_attempt += 1;
        }
        let mut next_hedge = tokio::time::Instant::now() + DIRECT_TCP_HEDGE_DELAY;

        loop {
            if attempts.is_empty() && next_attempt >= planned_attempts.len() {
                break;
            }
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(deadline) => {
                    errors.push("total DIRECT TCP attempt budget expired".to_owned());
                    break;
                }
                result = attempts.next(), if !attempts.is_empty() => {
                    let Some((attempt, result)) = result else { continue };
                    match result {
                        Ok(stream) => {
                            if let Some(path) = &attempt.path {
                                trace!(
                                    endpoint = %attempt.endpoint,
                                    interface = %path.id.interface.name,
                                    interface_index = path.id.interface.index,
                                    family = ?path.id.family,
                                    network_generation = path.id.network_generation,
                                    "DIRECT TCP path attempt won"
                                );
                            } else {
                                trace!(endpoint = %attempt.endpoint, "DIRECT TCP system-route attempt won");
                            }
                            let path_id =
                                attempt.path.map(|path| path.id);
                            return Ok((Box::new(stream) as _, path_id));
                        }
                        Err(error) => {
                            errors.push(format!(
                                "{} via {}: {error}",
                                attempt.endpoint,
                                attempt.path.as_ref().map_or_else(
                                    || "system route".to_owned(),
                                    |path| format!("{}#{}", path.id.interface.name, path.id.interface.index),
                                )
                            ));
                            trace!(
                                endpoint = %attempt.endpoint,
                                path = ?attempt.path.as_ref().map(|path| &path.id),
                                error = %error,
                                "DIRECT TCP path attempt failed"
                            );
                            if next_attempt < planned_attempts.len()
                                && attempts.len() < DIRECT_TCP_PARALLEL_LIMIT
                            {
                                push_direct_stream_attempt(
                                    &mut attempts,
                                    planned_attempts[next_attempt].clone(),
                                    iface.cloned(),
                                    #[cfg(target_os = "linux")]
                                    packet_mark,
                                );
                                next_attempt += 1;
                                next_hedge = tokio::time::Instant::now() + DIRECT_TCP_HEDGE_DELAY;
                            }
                        }
                    }
                }
                _ = tokio::time::sleep_until(next_hedge),
                    if next_attempt < planned_attempts.len()
                        && attempts.len() < DIRECT_TCP_PARALLEL_LIMIT =>
                {
                    push_direct_stream_attempt(
                        &mut attempts,
                        planned_attempts[next_attempt].clone(),
                        iface.cloned(),
                        #[cfg(target_os = "linux")]
                        packet_mark,
                    );
                    next_attempt += 1;
                    next_hedge = tokio::time::Instant::now() + DIRECT_TCP_HEDGE_DELAY;
                }
            }
        }

        Err(new_io_error(format!(
            "DIRECT TCP path attempts exhausted: {}",
            errors.join("; ")
        )))
    }
}

fn push_direct_stream_attempt(
    attempts: &mut FuturesUnordered<
        futures::future::BoxFuture<
            'static,
            (DirectStreamAttempt, std::io::Result<tokio::net::TcpStream>),
        >,
    >,
    attempt: DirectStreamAttempt,
    iface: Option<OutboundInterface>,
    #[cfg(target_os = "linux")] packet_mark: Option<u32>,
) {
    attempts.push(
        async move {
            let result = if let Some(path) = attempt.path.as_ref() {
                match (
                    crate::proxy::direct::outbound_interface_for_path(
                        path,
                        iface.as_ref(),
                    ),
                    crate::proxy::direct::source_socket_addr(path),
                ) {
                    (Ok(selected_iface), Ok(source)) => {
                        new_protected_tcp_stream_with_source(
                            attempt.endpoint,
                            &selected_iface,
                            source,
                            #[cfg(target_os = "linux")]
                            packet_mark,
                        )
                        .await
                    }
                    (Err(error), _) | (_, Err(error)) => Err(error),
                }
            } else {
                new_protected_tcp_stream(
                    attempt.endpoint,
                    iface.as_ref(),
                    #[cfg(target_os = "linux")]
                    packet_mark,
                )
                .await
            };
            (attempt, result)
        }
        .boxed(),
    );
}

fn build_proxy_endpoint_attempts(
    endpoint_candidates: &[(SocketAddr, Vec<NetworkPath>)],
    allow_system_route: bool,
) -> Vec<DirectStreamAttempt> {
    let max_paths = endpoint_candidates
        .iter()
        .map(|(_, paths)| paths.len())
        .max()
        .unwrap_or_default();
    let mut attempts = Vec::new();
    let has_observed_candidates = max_paths > 0;
    let path_attempt_limit = if allow_system_route && has_observed_candidates {
        PROXY_ENDPOINT_TCP_ATTEMPT_LIMIT.saturating_sub(1)
    } else {
        PROXY_ENDPOINT_TCP_ATTEMPT_LIMIT
    };

    // Try one candidate from each address family before trying a second
    // interface in the first family. This keeps a large DNS answer set from
    // starving another usable family.
    'path_rounds: for path_index in 0..max_paths {
        for (endpoint, paths) in endpoint_candidates {
            if let Some(path) = paths.get(path_index) {
                attempts.push(DirectStreamAttempt {
                    endpoint: *endpoint,
                    path: Some(path.clone()),
                });
                if attempts.len() >= path_attempt_limit {
                    break 'path_rounds;
                }
            }
        }
    }

    if allow_system_route {
        for (endpoint, _) in endpoint_candidates {
            attempts.push(DirectStreamAttempt {
                endpoint: *endpoint,
                path: None,
            });
            if attempts.len() >= PROXY_ENDPOINT_TCP_ATTEMPT_LIMIT {
                break;
            }
        }
    }

    attempts.truncate(PROXY_ENDPOINT_TCP_ATTEMPT_LIMIT);
    attempts
}

fn push_proxy_endpoint_stream_attempt(
    attempts: &mut FuturesUnordered<
        futures::future::BoxFuture<
            'static,
            (DirectStreamAttempt, std::io::Result<tokio::net::TcpStream>),
        >,
    >,
    attempt: DirectStreamAttempt,
    iface: Option<OutboundInterface>,
    generation_status: Option<(u64, SharedNetworkStatus)>,
    #[cfg(target_os = "linux")] packet_mark: Option<u32>,
) {
    attempts.push(
        async move {
            let result = if let Some(path) = attempt.path.as_ref() {
                match (
                    crate::proxy::direct::outbound_interface_for_path(
                        path,
                        iface.as_ref(),
                    ),
                    crate::proxy::direct::source_socket_addr(path),
                ) {
                    (Ok(selected_iface), Ok(source)) => {
                        new_protected_tcp_stream_with_source(
                            attempt.endpoint,
                            &selected_iface,
                            source,
                            #[cfg(target_os = "linux")]
                            packet_mark,
                        )
                        .await
                        .and_then(|stream| {
                            let local = stream.local_addr()?;
                            if local.ip() != source.ip() {
                                return Err(new_io_error(format!(
                                    "proxy endpoint socket used unexpected local address {} (requested {})",
                                    local.ip(),
                                    source.ip()
                                )));
                            }
                            Ok(stream)
                        })
                    }
                    (Err(error), _) | (_, Err(error)) => Err(error),
                }
            } else {
                new_protected_tcp_stream(
                    attempt.endpoint,
                    iface.as_ref(),
                    #[cfg(target_os = "linux")]
                    packet_mark,
                )
                .await
            };

            let result = match (result, generation_status.as_ref()) {
                (Ok(stream), Some((planned, status)))
                    if status
                        .read()
                        .await
                        .shadow_path_snapshot()
                        .map(|snapshot| snapshot.0)
                        != Some(*planned) =>
                {
                    drop(stream);
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "proxy endpoint dial completed on a stale network path",
                    ))
                }
                (result, _) => result,
            };
            (attempt, result)
        }
        .boxed(),
    );
}

pub static GLOBAL_DIRECT_CONNECTOR: LazyLock<Arc<dyn RemoteConnector>> =
    LazyLock::new(global_direct_connector);

fn global_direct_connector() -> Arc<dyn RemoteConnector> {
    Arc::new(DirectConnector::new())
}

fn interleave_ip_families(addresses: Vec<IpAddr>) -> Vec<IpAddr> {
    let prefer_ipv6 = addresses.first().is_some_and(IpAddr::is_ipv6);
    let (mut ipv4, mut ipv6): (VecDeque<_>, VecDeque<_>) =
        addresses.into_iter().partition(IpAddr::is_ipv4);
    let mut ordered = Vec::with_capacity(ipv4.len() + ipv6.len());

    while !ipv4.is_empty() || !ipv6.is_empty() {
        let (primary, secondary) = if prefer_ipv6 {
            (&mut ipv6, &mut ipv4)
        } else {
            (&mut ipv4, &mut ipv6)
        };
        if let Some(address) = primary.pop_front() {
            ordered.push(address);
        }
        if let Some(address) = secondary.pop_front() {
            ordered.push(address);
        }
    }
    ordered
}

fn uses_local_or_group_route(address: IpAddr) -> bool {
    address.is_loopback() || address.is_unspecified() || address.is_multicast()
}

#[async_trait]
impl RemoteConnector for DirectConnector {
    async fn network_generation(&self) -> Option<u64> {
        self.path_source
            .as_ref()?
            .snapshot()
            .await
            .map(|(generation, ..)| generation)
    }

    async fn connection_pool_context(
        &self,
        iface: Option<&OutboundInterface>,
    ) -> NetworkPoolContext {
        let Some(source) = self.path_source.as_ref() else {
            return NetworkPoolContext::default();
        };
        let Some((generation, observations, tun_enabled, status, base_intent)) =
            source.snapshot().await
        else {
            return NetworkPoolContext::for_generation(None);
        };
        if tun_enabled {
            return NetworkPoolContext::for_generation(Some(generation));
        }

        let mut intent = base_intent;
        if let Some(iface) = iface {
            intent.intents.push(PathIntent {
                strength: IntentStrength::Require,
                target: PathTarget::Interface(InterfaceId {
                    name: iface.name.clone(),
                    index: iface.index,
                }),
            });
        }
        let mut eligible_path_ids = HashSet::new();
        for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
            let plan = compile_path_plan(
                &observations,
                &intent,
                generation,
                RouteDecision {
                    outbound: "PROXY_ENDPOINT".to_owned(),
                    rule: None,
                },
                Some(family),
            );
            eligible_path_ids
                .extend(plan.plan.candidates.into_iter().map(|path| path.id));
        }
        {
            let mut status = status.write().await;
            eligible_path_ids.retain(|path| !status.path_is_unavailable(path));
        }
        NetworkPoolContext {
            network_generation: Some(generation),
            path_id: None,
            eligible_path_ids: Some(eligible_path_ids),
            reporter: source.traffic_reporter().await,
        }
    }

    async fn connect_stream(
        &self,
        resolver: ThreadSafeDNSResolver,
        address: &str,
        port: u16,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
    ) -> std::io::Result<AnyStream> {
        let pool_context = self.connection_pool_context(iface).await;
        self.connect_stream_with_pool_context(
            resolver,
            address,
            port,
            iface,
            #[cfg(target_os = "linux")]
            so_mark,
            pool_context,
        )
        .await
        .map(|(stream, _)| stream)
    }

    async fn connect_stream_with_pool_context(
        &self,
        resolver: ThreadSafeDNSResolver,
        address: &str,
        port: u16,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
        mut pool_context: NetworkPoolContext,
    ) -> std::io::Result<(AnyStream, NetworkPoolContext)> {
        let deadline = tokio::time::Instant::now() + PROXY_ENDPOINT_TCP_TOTAL_BUDGET;
        let addresses = if let Ok(ip) = address.parse() {
            vec![ip]
        } else {
            tokio::time::timeout_at(
                deadline,
                resolver.resolve_all(address, false),
            )
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "proxy endpoint DNS resolution exceeded the 5 second attempt budget",
                    )
                })?
                .map_err(|error| {
                    new_io_error(format!("can't resolve dns: {error}"))
                })?
        };
        if addresses.is_empty() {
            return Err(new_io_error("no dns result"));
        }

        let path_snapshot = if let Some(source) = self.path_source.as_ref() {
            tokio::time::timeout_at(deadline, source.snapshot())
                .await
                .map_err(|_| {
                    ProxyEndpointConnectError {
                        kind: std::io::ErrorKind::TimedOut,
                        message: "proxy endpoint path snapshot exceeded the 5 second attempt budget"
                            .to_owned(),
                        candidate_paths: pool_context
                            .eligible_path_ids
                            .clone()
                            .map(|paths| paths.into_iter().collect())
                            .unwrap_or_default(),
                        attempted_paths: Vec::new(),
                        rejected: Vec::new(),
                    }
                    .into_io_error()
                })?
        } else {
            None
        };
        if path_snapshot.is_none() && pool_context.eligible_path_ids.is_some() {
            return Err(ProxyEndpointConnectError {
                kind: std::io::ErrorKind::Interrupted,
                message: "proxy endpoint network snapshot disappeared before dial"
                    .to_owned(),
                candidate_paths: pool_context
                    .eligible_path_ids
                    .clone()
                    .map(|paths| paths.into_iter().collect())
                    .unwrap_or_default(),
                attempted_paths: Vec::new(),
                rejected: Vec::new(),
            }
            .into_io_error());
        }
        let planning_snapshot =
            path_snapshot.as_ref().filter(|snapshot| !snapshot.2);

        let mut endpoints = interleave_ip_families(addresses)
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect::<Vec<_>>();
        let mut seen_endpoints = HashSet::new();
        endpoints.retain(|endpoint| seen_endpoints.insert(*endpoint));
        endpoints.truncate(PROXY_ENDPOINT_TCP_ADDRESS_LIMIT);
        let mut endpoint_candidates = Vec::with_capacity(endpoints.len());
        let mut planning_errors = Vec::new();
        let mut candidate_paths = Vec::new();
        let mut rejected_paths = Vec::new();
        let mut found_first_path_candidates = false;
        let mut first_candidates_ambiguous = false;
        for endpoint in &endpoints {
            let mut candidates = Vec::new();
            let mut has_unambiguous_winner = false;
            if !(iface.is_none() && uses_local_or_group_route(endpoint.ip()))
                && let Some((generation, observations, _, _, intent)) =
                    planning_snapshot
            {
                match Self::endpoint_paths_with_selection(
                    iface,
                    AddressFamily::from(endpoint.ip()),
                    observations,
                    *generation,
                    intent,
                ) {
                    Ok((mut paths, selected, rejected)) => {
                        if let Some(eligible) =
                            pool_context.eligible_path_ids.as_ref()
                        {
                            for path in paths
                                .iter()
                                .filter(|path| !eligible.contains(&path.id))
                            {
                                let rejection =
                                    crate::app::flow::CandidateRejection {
                                        path: path.id.clone(),
                                        reason: crate::app::flow::PathRejectionReason::Unavailable,
                                        intent_index: None,
                                    };
                                if !rejected_paths.contains(&rejection) {
                                    rejected_paths.push(rejection);
                                }
                            }
                            paths.retain(|path| eligible.contains(&path.id));
                        }
                        for path in &paths {
                            if !candidate_paths.contains(&path.id) {
                                candidate_paths.push(path.id.clone());
                            }
                        }
                        for rejection in rejected {
                            if !rejected_paths.contains(&rejection) {
                                rejected_paths.push(rejection);
                            }
                        }
                        has_unambiguous_winner =
                            selected.as_ref().is_some_and(|winner| {
                                paths.iter().any(|path| &path.id == winner)
                            });
                        candidates = paths;
                    }
                    Err(error) => {
                        planning_errors.push(format!("{endpoint}: {error}"));
                    }
                }
            }
            if !found_first_path_candidates && !candidates.is_empty() {
                first_candidates_ambiguous =
                    candidates.len() > 1 && !has_unambiguous_winner;
                found_first_path_candidates = true;
            }
            endpoint_candidates.push((*endpoint, candidates));
        }

        let has_required_intent =
            planning_snapshot
                .as_ref()
                .is_some_and(|(_, _, _, _, intent)| {
                    intent
                        .intents
                        .iter()
                        .any(|entry| entry.strength == IntentStrength::Require)
                });
        let allow_system_route = (!has_required_intent && iface.is_none())
            || (iface.is_some() && planning_snapshot.is_none());
        let planned_attempts =
            build_proxy_endpoint_attempts(&endpoint_candidates, allow_system_route);
        if planned_attempts.is_empty() {
            return Err(ProxyEndpointConnectError {
                kind: std::io::ErrorKind::NetworkUnreachable,
                message: format!(
                    "required proxy endpoint path unavailable within the bounded attempt plan: {}",
                    planning_errors.join("; ")
                ),
                candidate_paths,
                attempted_paths: Vec::new(),
                rejected: rejected_paths,
            }
            .into_io_error());
        }

        let generation_status = path_snapshot
            .as_ref()
            .map(|(generation, _, _, status, _)| (*generation, status.clone()));
        let mut attempts = FuturesUnordered::new();
        let mut next_attempt = 0;
        let mut attempted_paths = Vec::new();
        let initial_limit = if first_candidates_ambiguous {
            PROXY_ENDPOINT_TCP_PARALLEL_LIMIT
        } else {
            1
        };
        while next_attempt < planned_attempts.len() && attempts.len() < initial_limit
        {
            if let Some(path) = planned_attempts[next_attempt].path.as_ref()
                && !candidate_paths.contains(&path.id)
            {
                candidate_paths.push(path.id.clone());
            }
            if let Some(path) = planned_attempts[next_attempt].path.as_ref()
                && !attempted_paths.contains(&path.id)
            {
                attempted_paths.push(path.id.clone());
            }
            push_proxy_endpoint_stream_attempt(
                &mut attempts,
                planned_attempts[next_attempt].clone(),
                iface.cloned(),
                generation_status.clone(),
                #[cfg(target_os = "linux")]
                so_mark,
            );
            next_attempt += 1;
        }

        let mut errors = planning_errors;
        let mut last_error_kind = None;
        let mut next_hedge =
            tokio::time::Instant::now() + PROXY_ENDPOINT_TCP_HEDGE_DELAY;
        loop {
            if attempts.is_empty() && next_attempt >= planned_attempts.len() {
                break;
            }
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(deadline) => {
                    last_error_kind = Some(std::io::ErrorKind::TimedOut);
                    errors.push("total proxy endpoint TCP attempt budget expired".to_owned());
                    break;
                }
                result = attempts.next(), if !attempts.is_empty() => {
                    let Some((attempt, result)) = result else { continue };
                    match result {
                        Ok(stream) => {
                            let dial_addr = attempt.endpoint;
                            let path_id = attempt.path.map(|path| path.id);
                            trace!(
                                endpoint = %dial_addr,
                                path = ?path_id,
                                network_generation = ?path_id.as_ref().map(|path| path.network_generation),
                                "proxy endpoint TCP attempt won"
                            );
                            pool_context.path_id = path_id.clone();
                            pool_context.network_generation = path_id
                                .as_ref()
                                .map(|path| path.network_generation)
                                .or_else(|| path_snapshot.as_ref().map(|(generation, ..)| *generation))
                                .or(pool_context.network_generation);
                            if let (Some(path_id), Some(source)) =
                                (path_id, self.path_source.as_ref())
                            {
                                let stream = observe_proxy_endpoint_stream(
                                    Box::new(stream),
                                    source,
                                    path_id,
                                    dial_addr,
                                )
                                .await;
                                return Ok((stream, pool_context));
                            }
                            return Ok((Box::new(stream) as _, pool_context));
                        }
                        Err(error) => {
                            last_error_kind = Some(error.kind());
                            trace!(
                                endpoint = %attempt.endpoint,
                                path = ?attempt.path.as_ref().map(|path| &path.id),
                                error = %error,
                                "proxy endpoint TCP path attempt failed"
                            );
                            if let (Some(path), Some(source)) =
                                (attempt.path.as_ref(), self.path_source.as_ref())
                                && let Some(reporter) = source.traffic_reporter().await
                            {
                                reporter
                                    .capture_scoped(
                                        crate::app::runtime_state::TrafficKind::ProxyEndpointTcp,
                                        Some(path.id.clone()),
                                        Some(SocksAddr::Ip(attempt.endpoint)),
                                    )
                                    .failed(error.kind());
                            }
                            errors.push(format!(
                                "{} via {:?}: {error}",
                                attempt.endpoint,
                                attempt.path.as_ref().map(|path| &path.id),
                            ));
                            if next_attempt < planned_attempts.len()
                                && attempts.len() < PROXY_ENDPOINT_TCP_PARALLEL_LIMIT
                            {
                                if let Some(path) = planned_attempts[next_attempt]
                                    .path
                                    .as_ref()
                                    && !attempted_paths.contains(&path.id)
                                {
                                    attempted_paths.push(path.id.clone());
                                }
                                push_proxy_endpoint_stream_attempt(
                                    &mut attempts,
                                    planned_attempts[next_attempt].clone(),
                                    iface.cloned(),
                                    generation_status.clone(),
                                    #[cfg(target_os = "linux")]
                                    so_mark,
                                );
                                next_attempt += 1;
                                next_hedge = tokio::time::Instant::now()
                                    + PROXY_ENDPOINT_TCP_HEDGE_DELAY;
                            }
                        }
                    }
                }
                _ = tokio::time::sleep_until(next_hedge),
                    if next_attempt < planned_attempts.len()
                        && attempts.len() < PROXY_ENDPOINT_TCP_PARALLEL_LIMIT =>
                {
                    if let Some(path) = planned_attempts[next_attempt]
                        .path
                        .as_ref()
                        && !attempted_paths.contains(&path.id)
                    {
                        attempted_paths.push(path.id.clone());
                    }
                    push_proxy_endpoint_stream_attempt(
                        &mut attempts,
                        planned_attempts[next_attempt].clone(),
                        iface.cloned(),
                        generation_status.clone(),
                        #[cfg(target_os = "linux")]
                        so_mark,
                    );
                    next_attempt += 1;
                    next_hedge = tokio::time::Instant::now()
                        + PROXY_ENDPOINT_TCP_HEDGE_DELAY;
                }
            }
        }
        Err(ProxyEndpointConnectError {
            kind: last_error_kind.unwrap_or(std::io::ErrorKind::NetworkUnreachable),
            message: format!(
                "bounded proxy endpoint TCP attempts exhausted: {}",
                errors.join("; ")
            ),
            candidate_paths,
            attempted_paths,
            rejected: rejected_paths,
        }
        .into_io_error())
    }

    async fn connect_datagram(
        &self,
        resolver: ThreadSafeDNSResolver,
        src: Option<SocketAddr>,
        destination: SocksAddr,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
    ) -> std::io::Result<AnyOutboundDatagram> {
        let pool_context = self.connection_pool_context(iface).await;
        self.connect_datagram_with_pool_context(
            resolver,
            src,
            destination,
            iface,
            #[cfg(target_os = "linux")]
            so_mark,
            pool_context,
        )
        .await
        .map(|(datagram, _)| datagram)
    }

    async fn connect_datagram_with_pool_context(
        &self,
        resolver: ThreadSafeDNSResolver,
        src: Option<SocketAddr>,
        destination: SocksAddr,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
        mut pool_context: NetworkPoolContext,
    ) -> std::io::Result<(AnyOutboundDatagram, NetworkPoolContext)> {
        let path_snapshot = if let Some(source) = self.path_source.as_ref() {
            source
                .snapshot()
                .await
                .filter(|(_, _, tun_enabled, _, _)| !tun_enabled)
        } else {
            None
        };
        let target = destination
            .ip()
            .map(|ip| SocketAddr::new(ip, destination.port()));
        let mut selected_path = None;
        let socket = if let (Some(path_snapshot), Some(target)) =
            (path_snapshot.as_ref(), target)
            && !uses_local_or_group_route(target.ip())
        {
            let (generation, observations, _, status, intent) = path_snapshot;
            let (mut candidates, selected, rejected) =
                Self::endpoint_paths_with_selection(
                    iface,
                    AddressFamily::from(target.ip()),
                    observations,
                    *generation,
                    intent,
                )?;
            if iface.is_some() && selected.is_none() {
                return Err(ProxyEndpointConnectError {
                    kind: std::io::ErrorKind::NetworkUnreachable,
                    message: format!(
                        "required proxy UDP path unavailable for {:?}",
                        AddressFamily::from(target.ip()),
                    ),
                    candidate_paths: candidates
                        .iter()
                        .map(|path| path.id.clone())
                        .collect(),
                    attempted_paths: Vec::new(),
                    rejected,
                }
                .into_io_error());
            }
            let mut endpoint_rejected_paths = rejected;
            if let Some(eligible) = pool_context.eligible_path_ids.as_ref() {
                for path in candidates
                    .iter()
                    .filter(|path| !eligible.contains(&path.id))
                {
                    endpoint_rejected_paths.push(
                        crate::app::flow::CandidateRejection {
                            path: path.id.clone(),
                            reason:
                                crate::app::flow::PathRejectionReason::Unavailable,
                            intent_index: None,
                        },
                    );
                }
                candidates.retain(|path| eligible.contains(&path.id));
            }
            candidates.truncate(PROXY_UDP_PATH_ATTEMPT_LIMIT);
            let endpoint_candidate_paths =
                candidates.iter().map(|path| path.id.clone()).collect();
            let mut endpoint_attempted_paths = Vec::new();

            let required = iface.is_some()
                || intent
                    .intents
                    .iter()
                    .any(|entry| entry.strength == IntentStrength::Require);
            let mut errors = Vec::new();
            let mut last_error_kind = None;
            let mut selected_socket = None;
            for path in candidates {
                if !endpoint_attempted_paths.contains(&path.id) {
                    endpoint_attempted_paths.push(path.id.clone());
                }
                let attempt = async {
                    let selected_iface =
                        crate::proxy::direct::outbound_interface_for_path(
                            &path,
                            iface,
                        )?;
                    let source =
                        crate::proxy::direct::source_socket_addr(&path)?;
                    let socket = new_protected_udp_socket(
                        Some(source),
                        Some(&selected_iface),
                        #[cfg(target_os = "linux")]
                        so_mark,
                        Some(target),
                    )
                    .await?;
                    let local = socket.local_addr()?;
                    if local.ip() != source.ip() {
                        return Err(new_io_error(format!(
                            "proxy UDP socket used unexpected local address {} (requested {})",
                            local.ip(),
                            source.ip()
                        )));
                    }
                    if status
                        .read()
                        .await
                        .shadow_path_snapshot()
                        .map(|snapshot| snapshot.0)
                        != Some(*generation)
                    {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Interrupted,
                            "proxy UDP dial completed on a stale network path",
                        ));
                    }
                    Ok::<_, std::io::Error>(socket)
                }
                .await;
                match attempt {
                    Ok(socket) => {
                        selected_path = Some(path);
                        selected_socket = Some(socket);
                        break;
                    }
                    Err(error) => {
                        last_error_kind = Some(error.kind());
                        if let Some(reporter) = pool_context.reporter.as_ref() {
                            reporter
                                .capture_scoped(
                                    crate::app::runtime_state::TrafficKind::ProxyEndpointUdp,
                                    Some(path.id.clone()),
                                    Some(destination.clone()),
                                )
                                .failed(error.kind());
                        }
                        errors.push(error.to_string());
                    }
                }
            }

            if let Some(socket) = selected_socket {
                socket
            } else if required {
                return Err(ProxyEndpointConnectError {
                    kind: last_error_kind
                        .unwrap_or(std::io::ErrorKind::NetworkUnreachable),
                    message: format!(
                        "required proxy UDP path unavailable after {} bounded attempts: {}",
                        PROXY_UDP_PATH_ATTEMPT_LIMIT,
                        errors.join("; ")
                    ),
                    candidate_paths: endpoint_candidate_paths,
                    attempted_paths: endpoint_attempted_paths,
                    rejected: endpoint_rejected_paths,
                }
                .into_io_error());
            } else {
                new_protected_udp_socket(
                    src,
                    iface,
                    #[cfg(target_os = "linux")]
                    so_mark,
                    Some(target),
                )
                .await
                .map_err(|error| {
                    ProxyEndpointConnectError {
                        kind: error.kind(),
                        message: format!(
                            "proxy UDP system-route fallback failed: {error}"
                        ),
                        candidate_paths: endpoint_candidate_paths,
                        attempted_paths: endpoint_attempted_paths,
                        rejected: endpoint_rejected_paths,
                    }
                    .into_io_error()
                })?
            }
        } else {
            new_protected_udp_socket(
                src,
                iface,
                #[cfg(target_os = "linux")]
                so_mark,
                target,
            )
            .await?
        };
        let dgram = OutboundDatagramImpl::new(socket, resolver);
        pool_context.path_id = selected_path.as_ref().map(|path| path.id.clone());
        pool_context.network_generation = selected_path
            .as_ref()
            .map(|path| path.id.network_generation)
            .or_else(|| path_snapshot.as_ref().map(|(generation, ..)| *generation))
            .or(pool_context.network_generation);
        let dgram = ChainedDatagramWrapper::new_with_network_path_id(
            dgram,
            pool_context.path_id.clone(),
        );
        let dgram = observe_proxy_endpoint_datagram(
            Box::new(dgram),
            &pool_context,
            &destination,
        );
        Ok((dgram, pool_context))
    }
}

pub struct ProxyConnector {
    proxy: AnyOutboundHandler,
    connector: Box<dyn RemoteConnector>,
}

impl ProxyConnector {
    pub fn new(
        proxy: AnyOutboundHandler,
        // TODO: make this Arc
        connector: Box<dyn RemoteConnector>,
    ) -> Self {
        Self { proxy, connector }
    }

    async fn connect_chained_stream(
        &self,
        resolver: ThreadSafeDNSResolver,
        address: &str,
        port: u16,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
    ) -> std::io::Result<(AnyStream, Vec<NetworkPathId>)> {
        let sess = Session {
            network: Network::Tcp,
            typ: Type::Ignore,
            destination: SocksAddr::Domain(address.to_owned(), port),
            iface: iface.cloned(),
            #[cfg(target_os = "linux")]
            so_mark,
            ..Default::default()
        };

        trace!(
            "proxy connector `{}` connecting to {}:{}",
            self.proxy.name(),
            address,
            port
        );

        let stream = self
            .proxy
            .connect_stream_with_connector(&sess, resolver, self.connector.as_ref())
            .await?;
        let paths = stream.network_path_ids();
        let chained =
            ChainedStreamWrapper::new_with_network_path_ids(stream, paths.clone());
        chained.append_to_chain(self.proxy.name()).await;
        // Erase only after keeping a parallel path snapshot for callers using
        // `connect_stream_with_pool_context` at the next relay hop.
        Ok((Box::new(chained), paths))
    }

    async fn connect_chained_datagram(
        &self,
        resolver: ThreadSafeDNSResolver,
        destination: SocksAddr,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
    ) -> std::io::Result<(AnyOutboundDatagram, Vec<NetworkPathId>)> {
        let sess = Session {
            network: Network::Udp,
            typ: Type::Ignore,
            iface: iface.cloned(),
            destination: destination.clone(),
            #[cfg(target_os = "linux")]
            so_mark,
            ..Default::default()
        };
        let datagram = self
            .proxy
            .connect_datagram_with_connector(
                &sess,
                resolver,
                self.connector.as_ref(),
            )
            .await?;
        let path_ids = datagram.network_path_ids();
        let chained = ChainedDatagramWrapper::new_with_network_path_ids(
            datagram,
            path_ids.clone(),
        );
        chained.append_to_chain(self.proxy.name()).await;
        Ok((Box::new(chained), path_ids))
    }
}

impl Debug for ProxyConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyConnector")
            .field("proxy", &self.proxy.name())
            .finish()
    }
}

#[async_trait]
impl RemoteConnector for ProxyConnector {
    async fn network_generation(&self) -> Option<u64> {
        self.connector.network_generation().await
    }

    async fn connection_pool_context(
        &self,
        iface: Option<&OutboundInterface>,
    ) -> NetworkPoolContext {
        self.connector.connection_pool_context(iface).await
    }

    async fn connect_stream(
        &self,
        resolver: ThreadSafeDNSResolver,
        address: &str,
        port: u16,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
    ) -> std::io::Result<AnyStream> {
        self.connect_chained_stream(
            resolver,
            address,
            port,
            iface,
            #[cfg(target_os = "linux")]
            so_mark,
        )
        .await
        .map(|(stream, _)| stream)
    }

    async fn connect_stream_with_pool_context(
        &self,
        resolver: ThreadSafeDNSResolver,
        address: &str,
        port: u16,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
        mut pool_context: NetworkPoolContext,
    ) -> std::io::Result<(AnyStream, NetworkPoolContext)> {
        let (stream, path_ids) = self
            .connect_chained_stream(
                resolver,
                address,
                port,
                iface,
                #[cfg(target_os = "linux")]
                so_mark,
            )
            .await?;
        if let Some(path_id) = path_ids.first() {
            // The completed chain is the source of truth. An input context
            // describes eligible paths before dialing, not the winning NIC.
            pool_context.path_id = Some(path_id.clone());
            pool_context.network_generation = Some(path_id.network_generation);
        }
        Ok((stream, pool_context))
    }

    async fn connect_datagram(
        &self,
        resolver: ThreadSafeDNSResolver,
        _src: Option<SocketAddr>,
        destination: SocksAddr,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
    ) -> std::io::Result<AnyOutboundDatagram> {
        self.connect_chained_datagram(
            resolver,
            destination,
            iface,
            #[cfg(target_os = "linux")]
            so_mark,
        )
        .await
        .map(|(datagram, _)| datagram)
    }

    async fn connect_datagram_with_pool_context(
        &self,
        resolver: ThreadSafeDNSResolver,
        _src: Option<SocketAddr>,
        destination: SocksAddr,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
        mut pool_context: NetworkPoolContext,
    ) -> std::io::Result<(AnyOutboundDatagram, NetworkPoolContext)> {
        let (datagram, path_ids) = self
            .connect_chained_datagram(
                resolver,
                destination,
                iface,
                #[cfg(target_os = "linux")]
                so_mark,
            )
            .await?;
        if let Some(path_id) = path_ids.first() {
            pool_context.path_id = Some(path_id.clone());
            pool_context.network_generation = Some(path_id.network_generation);
        }
        Ok((datagram, pool_context))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
    };

    use futures::{SinkExt, StreamExt};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
        sync::mpsc,
    };

    #[cfg(feature = "hysteria")]
    use super::observe_proxy_target_datagram;
    use super::{
        DirectConnector, NetworkPathSource, NetworkPoolContext,
        ProxyEndpointConnectError, RemoteConnector, build_proxy_endpoint_attempts,
        observe_proxy_endpoint_datagram, observe_proxy_endpoint_stream,
    };
    use crate::app::dns::MockClashResolver;
    use crate::{
        app::net::OutboundInterface,
        app::runtime_state::Lifecycle,
        app::{
            flow::{
                AddressFamily, InterfaceId, InterfaceKind, NetworkIntentSnapshot,
                NetworkPath, NetworkPathId,
            },
            network::{
                BindingStatus, DefaultRouteEvidence, NetworkSnapshot, NetworkStatus,
                PathCandidateObservation,
            },
        },
        proxy::{
            AnyOutboundDatagram, datagram::UdpPacket,
            direct::datagram::OutboundDatagramImpl,
        },
        session::SocksAddr,
    };

    #[test]
    fn pool_context_keeps_unaffected_path_eligible_within_generation() {
        let path_a = NetworkPathId {
            interface: InterfaceId {
                name: "wifi0".to_owned(),
                index: 4,
            },
            family: AddressFamily::Ipv4,
            source_address: Some("192.0.2.10".parse().unwrap()),
            network_generation: 7,
        };
        let path_b = NetworkPathId {
            interface: InterfaceId {
                name: "eth0".to_owned(),
                index: 5,
            },
            family: AddressFamily::Ipv4,
            source_address: Some("198.51.100.10".parse().unwrap()),
            network_generation: 7,
        };
        let context = NetworkPoolContext {
            network_generation: Some(7),
            path_id: None,
            eligible_path_ids: Some([path_b.clone()].into_iter().collect()),
            reporter: None,
        };

        assert!(!context.permits(Some(7), Some(&path_a)));
        assert!(context.permits(Some(7), Some(&path_b)));
        assert!(!context.permits(Some(6), Some(&path_b)));
    }

    #[tokio::test]
    async fn proxy_endpoint_response_reports_the_bound_path() {
        let mut status = NetworkStatus::default();
        status.lifecycle(Lifecycle::Running, "test");
        let (tx, mut events) = mpsc::channel(1);
        let reporter = status.traffic_reporter(tx);
        let source = NetworkPathSource::default();
        source.attach_traffic_reporter(reporter).await;

        let path_id = NetworkPathId {
            interface: InterfaceId {
                name: "wifi0".to_owned(),
                index: 4,
            },
            family: AddressFamily::Ipv4,
            source_address: Some("192.0.2.10".parse().unwrap()),
            network_generation: 0,
        };
        let endpoint: SocketAddr = "198.51.100.8:443".parse().unwrap();
        let (client, mut peer) = tokio::io::duplex(64);
        let mut observed = observe_proxy_endpoint_stream(
            Box::new(client),
            &source,
            path_id.clone(),
            endpoint,
        )
        .await;

        peer.write_all(b"proxy handshake response").await.unwrap();
        let mut response = vec![0; b"proxy handshake response".len()];
        observed.read_exact(&mut response).await.unwrap();
        status.record_traffic(events.recv().await.unwrap());

        let value = serde_json::to_value(status).unwrap();
        assert_eq!(value["trafficEvidence"][0]["kind"], "proxyEndpointTcp");
        assert_eq!(value["pathHealth"][0]["state"], "available");
        assert_eq!(value["pathHealth"][0]["path"]["interface"]["name"], "wifi0");
        assert_eq!(value["destinationPathHealth"][0]["family"], "ipv4");
        let destination_id = value["destinationPathHealth"][0]["destinationId"]
            .as_str()
            .unwrap();
        assert!(!destination_id.contains("198.51.100.8"));
    }

    #[tokio::test]
    async fn proxy_endpoint_udp_response_reports_the_bound_path() {
        let mut status = NetworkStatus::default();
        status.lifecycle(Lifecycle::Running, "test");
        let (tx, mut events) = mpsc::channel(1);
        let reporter = status.traffic_reporter(tx);
        let source = NetworkPathSource::default();
        source.attach_traffic_reporter(reporter).await;
        let path_id = NetworkPathId {
            interface: InterfaceId {
                name: "wifi0".to_owned(),
                index: 4,
            },
            family: AddressFamily::Ipv4,
            source_address: Some(Ipv4Addr::LOCALHOST.into()),
            network_generation: 0,
        };
        let endpoint_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = endpoint_socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = [0; 32];
            if let Ok((length, peer)) = endpoint_socket.recv_from(&mut buffer).await
            {
                let _ = endpoint_socket.send_to(&buffer[..length], peer).await;
            }
        });
        let context = NetworkPoolContext {
            network_generation: Some(0),
            path_id: Some(path_id),
            eligible_path_ids: None,
            reporter: source.traffic_reporter().await,
        };

        let local = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let datagram: AnyOutboundDatagram = Box::new(OutboundDatagramImpl::new(
            local,
            Arc::new(MockClashResolver::new()),
        ));
        let mut observed = observe_proxy_endpoint_datagram(
            datagram,
            &context,
            &SocksAddr::Ip(endpoint),
        );
        observed
            .send(UdpPacket {
                data: b"quic handshake".to_vec(),
                dst_addr: SocksAddr::Ip(endpoint),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(2), observed.next())
                .await
                .unwrap()
                .unwrap()
                .data,
            b"quic handshake"
        );
        status.record_traffic(events.recv().await.unwrap());
        let value = serde_json::to_value(status).unwrap();
        assert_eq!(value["trafficEvidence"][0]["kind"], "proxyEndpointUdp");
        assert_eq!(value["pathHealth"][0]["state"], "available");
        assert_eq!(value["pathHealth"][0]["path"]["interface"]["name"], "wifi0");
        assert_eq!(value["destinationPathHealth"][0]["family"], "ipv4");
    }

    #[cfg(feature = "hysteria")]
    #[tokio::test]
    async fn proxy_target_udp_response_reports_the_bound_path() {
        let mut status = NetworkStatus::default();
        status.lifecycle(Lifecycle::Running, "test");
        let (tx, mut events) = mpsc::channel(1);
        let reporter = status.traffic_reporter(tx);
        let source = NetworkPathSource::default();
        source.attach_traffic_reporter(reporter).await;
        let path_id = NetworkPathId {
            interface: InterfaceId {
                name: "wifi0".to_owned(),
                index: 4,
            },
            family: AddressFamily::Ipv4,
            source_address: Some(Ipv4Addr::LOCALHOST.into()),
            network_generation: 0,
        };
        let endpoint_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = endpoint_socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = [0; 32];
            if let Ok((length, peer)) = endpoint_socket.recv_from(&mut buffer).await
            {
                let _ = endpoint_socket.send_to(&buffer[..length], peer).await;
            }
        });
        let context = NetworkPoolContext {
            network_generation: Some(0),
            path_id: Some(path_id),
            eligible_path_ids: None,
            reporter: source.traffic_reporter().await,
        };
        let local = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let datagram: AnyOutboundDatagram = Box::new(OutboundDatagramImpl::new(
            local,
            Arc::new(MockClashResolver::new()),
        ));
        let mut observed = observe_proxy_target_datagram(datagram, &context);
        observed
            .send(UdpPacket {
                data: b"target request".to_vec(),
                dst_addr: SocksAddr::Ip(target),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(2), observed.next())
                .await
                .unwrap()
                .unwrap()
                .data,
            b"target request"
        );
        status.record_traffic(events.recv().await.unwrap());
        let value = serde_json::to_value(status).unwrap();
        assert_eq!(value["trafficEvidence"][0]["kind"], "proxyUdp");
        assert_eq!(value["pathHealth"][0]["state"], "available");
        assert_eq!(value["pathHealth"][0]["path"]["interface"]["name"], "wifi0");
        assert_eq!(value["destinationPathHealth"][0]["family"], "ipv4");
    }

    fn candidate(
        name: &str,
        index: u32,
        address: Ipv4Addr,
        route: DefaultRouteEvidence,
        binding: BindingStatus,
    ) -> PathCandidateObservation {
        PathCandidateObservation {
            interface: InterfaceId {
                name: name.to_owned(),
                index,
            },
            interface_kind: InterfaceKind::Unknown,
            family: AddressFamily::Ipv4,
            source_address: address.into(),
            scope_id: None,
            gateway: None,
            default_route: route,
            binding,
            binding_error: None,
        }
    }

    fn observed_path(
        name: &str,
        index: u32,
        source_address: IpAddr,
        network_generation: u64,
    ) -> NetworkPath {
        let family = AddressFamily::from(source_address);
        NetworkPath {
            id: NetworkPathId {
                interface: InterfaceId {
                    name: name.to_owned(),
                    index,
                },
                family,
                source_address: Some(source_address),
                network_generation,
            },
            interface_kind: InterfaceKind::Unknown,
            source_address: Some(source_address),
            scope_id: None,
            gateway: None,
        }
    }

    #[test]
    fn proxy_endpoint_attempt_plan_is_bounded_and_covers_both_families() {
        let ipv4_endpoint: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let ipv6_endpoint: SocketAddr = "[2001:db8::20]:443".parse().unwrap();
        let wifi_v4 = observed_path("wifi0", 4, "192.0.2.10".parse().unwrap(), 7);
        let ethernet_v4 =
            observed_path("eth0", 5, "198.51.100.10".parse().unwrap(), 7);
        let wifi_v6 = observed_path("wifi0", 4, "2001:db8::10".parse().unwrap(), 7);

        let attempts = build_proxy_endpoint_attempts(
            &[
                (ipv4_endpoint, vec![wifi_v4.clone(), ethernet_v4.clone()]),
                (ipv6_endpoint, vec![wifi_v6.clone()]),
            ],
            false,
        );

        assert_eq!(attempts.len(), 3);
        assert_eq!(attempts[0].endpoint, ipv4_endpoint);
        assert_eq!(attempts[0].path.as_ref().unwrap().id, wifi_v4.id);
        assert_eq!(attempts[1].endpoint, ipv6_endpoint);
        assert_eq!(attempts[1].path.as_ref().unwrap().id, wifi_v6.id);
        assert_eq!(attempts[2].endpoint, ipv4_endpoint);
        assert_eq!(attempts[2].path.as_ref().unwrap().id, ethernet_v4.id);
        assert!(attempts.iter().all(|attempt| attempt.path.is_some()));
    }

    #[test]
    fn proxy_preference_attempt_plan_reserves_one_system_route_fallback() {
        let endpoint: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let paths = vec![
            observed_path("wifi0", 4, "192.0.2.10".parse().unwrap(), 7),
            observed_path("eth0", 5, "198.51.100.10".parse().unwrap(), 7),
            observed_path("wifi1", 6, "203.0.113.10".parse().unwrap(), 7),
        ];

        let attempts = build_proxy_endpoint_attempts(&[(endpoint, paths)], true);

        assert_eq!(attempts.len(), 3);
        assert!(attempts[0].path.is_some());
        assert!(attempts[1].path.is_some());
        assert!(attempts[2].path.is_none());
    }

    #[test]
    fn proxy_endpoint_failure_keeps_structured_path_details_in_io_error() {
        let path = observed_path("wifi0", 4, "192.0.2.10".parse().unwrap(), 7);
        let error = ProxyEndpointConnectError {
            kind: std::io::ErrorKind::NetworkUnreachable,
            message: "proxy endpoint paths exhausted".to_owned(),
            candidate_paths: vec![path.id.clone()],
            attempted_paths: vec![path.id.clone()],
            rejected: Vec::new(),
        }
        .into_io_error();

        let details = error
            .get_ref()
            .and_then(|source| source.downcast_ref::<ProxyEndpointConnectError>())
            .expect("typed proxy dial details should survive io::Error propagation");
        assert_eq!(error.kind(), std::io::ErrorKind::NetworkUnreachable);
        assert_eq!(details.candidate_paths(), std::slice::from_ref(&path.id));
        assert_eq!(details.attempted_paths(), std::slice::from_ref(&path.id));
    }

    #[tokio::test]
    async fn direct_connector_exposes_the_current_network_generation() {
        let mut status = NetworkStatus::default();
        status.set_automatic_supported_for_test(true);
        status.observed(&NetworkSnapshot {
            path_candidates: vec![candidate(
                "wifi0",
                4,
                Ipv4Addr::new(192, 0, 2, 10),
                DefaultRouteEvidence::PrimaryDefaultRoute,
                BindingStatus::Verified,
            )],
            ..Default::default()
        });
        let generation = status
            .path_planning_snapshot()
            .expect("test status should expose an observed generation")
            .0;
        let source = NetworkPathSource::default();
        source
            .attach(Arc::new(tokio::sync::RwLock::new(status)))
            .await;

        assert_eq!(
            DirectConnector::with_path_source(source)
                .network_generation()
                .await,
            Some(generation)
        );
    }

    fn outbound_interface(name: &str, index: u32) -> OutboundInterface {
        OutboundInterface {
            name: name.to_owned(),
            addr_v4: None,
            netmask_v4: None,
            broadcast_v4: None,
            addr_v6: None,
            netmask_v6: None,
            broadcast_v6: None,
            index,
            mac_addr: None,
        }
    }

    #[test]
    fn proxy_endpoint_selection_uses_default_and_explicit_interface_evidence() {
        let observations = [
            candidate(
                "wifi0",
                4,
                Ipv4Addr::new(192, 0, 2, 10),
                DefaultRouteEvidence::PrimaryDefaultRoute,
                BindingStatus::Verified,
            ),
            candidate(
                "eth0",
                5,
                Ipv4Addr::new(198, 51, 100, 10),
                DefaultRouteEvidence::OtherInterface,
                BindingStatus::Verified,
            ),
        ];
        let intent = NetworkIntentSnapshot::default();

        let default = DirectConnector::endpoint_path(
            None,
            AddressFamily::Ipv4,
            &observations,
            9,
            &intent,
        )
        .unwrap()
        .expect("unique system default should be selected");
        assert_eq!(default.id.interface.name, "wifi0");
        assert_eq!(default.source_address, Some("192.0.2.10".parse().unwrap()));

        let required = DirectConnector::endpoint_path(
            Some(&outbound_interface("eth0", 5)),
            AddressFamily::Ipv4,
            &observations,
            9,
            &intent,
        )
        .unwrap()
        .expect("explicit interface should override default route preference");
        assert_eq!(required.id.interface.name, "eth0");
    }

    #[test]
    fn proxy_endpoint_selection_fails_closed_for_missing_required_path() {
        let observations = [candidate(
            "eth0",
            5,
            Ipv4Addr::new(198, 51, 100, 10),
            DefaultRouteEvidence::OtherInterface,
            BindingStatus::Failed,
        )];
        let intent = NetworkIntentSnapshot::default();
        let error = DirectConnector::endpoint_path(
            Some(&outbound_interface("eth0", 5)),
            AddressFamily::Ipv4,
            &observations,
            9,
            &intent,
        )
        .expect_err("a failed required bind candidate must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::NetworkUnreachable);
    }

    #[tokio::test]
    async fn direct_connector_tries_the_next_resolved_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut resolver = MockClashResolver::new();
        resolver
            .expect_resolve_all()
            .withf(|host, enhanced| host == "proxy.test" && !enhanced)
            .once()
            .returning(|_, _| {
                Ok(vec![
                    "127.0.0.2".parse::<IpAddr>().unwrap(),
                    "127.0.0.1".parse::<IpAddr>().unwrap(),
                ])
            });

        let stream = DirectConnector::new()
            .connect_stream(
                Arc::new(resolver),
                "proxy.test",
                port,
                None,
                #[cfg(target_os = "linux")]
                None,
            )
            .await
            .expect("second resolved address should connect");

        drop(stream);
        drop(listener);
    }

    #[tokio::test]
    async fn proxy_endpoint_connector_enforces_the_latest_explicit_interface() {
        let mut status = NetworkStatus::default();
        status.set_automatic_supported_for_test(true);
        status.observed(&NetworkSnapshot {
            path_candidates: vec![candidate(
                "wifi0",
                4,
                Ipv4Addr::new(192, 0, 2, 10),
                DefaultRouteEvidence::PrimaryDefaultRoute,
                BindingStatus::Verified,
            )],
            ..Default::default()
        });
        let source = NetworkPathSource::default();
        source
            .attach(Arc::new(tokio::sync::RwLock::new(status)))
            .await;

        let mut resolver = MockClashResolver::new();
        resolver
            .expect_resolve_all()
            .withf(|host, enhanced| host == "proxy.test" && !enhanced)
            .once()
            .returning(|_, _| Ok(vec!["127.0.0.1".parse().unwrap()]));
        let error = match DirectConnector::with_path_source(source)
            .connect_stream(
                Arc::new(resolver),
                "proxy.test",
                443,
                Some(&outbound_interface("missing0", 99)),
                #[cfg(target_os = "linux")]
                None,
            )
            .await
        {
            Err(error) => error,
            Ok(_) => panic!("connector silently used an unconfigured interface"),
        };
        assert!(
            error
                .to_string()
                .contains("required proxy endpoint path unavailable")
        );
    }

    #[test]
    fn happy_eyeballs_interleaves_address_families() {
        let addresses = ["192.0.2.1", "192.0.2.2", "2001:db8::1", "2001:db8::2"]
            .map(|address| address.parse().unwrap())
            .to_vec();

        assert_eq!(
            super::interleave_ip_families(addresses),
            ["192.0.2.1", "2001:db8::1", "192.0.2.2", "2001:db8::2",]
                .map(|address| address.parse::<IpAddr>().unwrap())
        );
    }
}
