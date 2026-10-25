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
            && path_id
                .is_none_or(|id| Some(id.network_generation) == network_generation)
            && self.eligible_path_ids.as_ref().is_none_or(|eligible| {
                path_id.is_some_and(|path_id| eligible.contains(path_id))
            })
    }

    /// A pooled stream may be selected with a previously observed path and
    /// then delivered after an awaited handshake. Recheck its recorded socket
    /// generation and eligibility at the point it crosses the caller boundary.
    /// Missing path proof stays compatible with unobserved legacy connectors,
    /// but never passes a connector that has an explicit eligible path set.
    pub(crate) fn verify_reused_path(
        &self,
        connected: &Self,
    ) -> std::io::Result<()> {
        if !self.permits(connected.network_generation, connected.path_id.as_ref()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "network path changed while borrowing a pooled transport",
            ));
        }
        Ok(())
    }

    /// Replace pre-dial planning identity with the *completed chain's*
    /// reported socket path. If no hop reports a physical path, clear any
    /// stale planned path AND generation; neither may be forwarded as proof.
    pub(crate) fn record_connected_paths(&mut self, paths: &[NetworkPathId]) {
        self.path_id = paths.first().cloned();
        self.network_generation =
            self.path_id.as_ref().map(|path| path.network_generation);
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
    /// Connectors that cannot expose physical socket IDs must not propagate
    /// a caller-supplied *planned* path as evidence.
    async fn connect_stream_with_pool_context(
        &self,
        resolver: ThreadSafeDNSResolver,
        address: &str,
        port: u16,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] packet_mark: Option<u32>,
        mut pool_context: NetworkPoolContext,
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
        pool_context.path_id = None;
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

    /// Establish a datagram socket and return its physical path. Connectors
    /// without path awareness may retain generation-only planning metadata,
    /// but must clear caller-supplied planned path IDs.
    async fn connect_datagram_with_pool_context(
        &self,
        resolver: ThreadSafeDNSResolver,
        src: Option<SocketAddr>,
        destination: SocksAddr,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] packet_mark: Option<u32>,
        mut pool_context: NetworkPoolContext,
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
        pool_context.path_id = None;
        Ok((datagram, pool_context))
    }
}

#[path = "proxy_connector/direct.rs"]
mod direct_connector;
pub use direct_connector::{DirectConnector, GLOBAL_DIRECT_CONNECTOR};

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
        // Never retain a pre-dial candidate when the completed physical
        // chain supplied no path evidence.
        pool_context.record_connected_paths(&path_ids);
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
        pool_context.record_connected_paths(&path_ids);
        Ok((datagram, pool_context))
    }
}
