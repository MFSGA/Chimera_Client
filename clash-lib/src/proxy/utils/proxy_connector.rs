use async_trait::async_trait;
use futures::{FutureExt, StreamExt, stream::FuturesUnordered};
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
        AnyOutboundDatagram, AnyOutboundHandler, AnyStream,
        direct::datagram::OutboundDatagramImpl, utils::new_protected_udp_socket,
    },
    session::{Network, Session, SocksAddr, Type},
};

const DIRECT_TCP_ATTEMPT_LIMIT: usize = 3;
const DIRECT_TCP_PARALLEL_LIMIT: usize = 2;
const DIRECT_TCP_HEDGE_DELAY: Duration = Duration::from_millis(120);
const DIRECT_TCP_TOTAL_BUDGET: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Default)]
pub struct NetworkPoolContext {
    pub network_generation: Option<u64>,
    pub path_id: Option<NetworkPathId>,
    /// `Some` means only these observed and policy-eligible paths may back a
    /// reusable connection. `None` keeps generation-only behavior where the
    /// connector cannot identify physical paths (for example, a proxy chain).
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

    fn endpoint_path(
        iface: Option<&OutboundInterface>,
        family: AddressFamily,
        observations: &[PathCandidateObservation],
        network_generation: u64,
        base_intent: &NetworkIntentSnapshot,
    ) -> std::io::Result<Option<NetworkPath>> {
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
        let selected = result.decision.selected.as_ref().and_then(|selected| {
            result
                .plan
                .candidates
                .iter()
                .find(|path| &path.id == selected)
        });
        if iface.is_some() && selected.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NetworkUnreachable,
                format!("required proxy endpoint path unavailable for {family:?}"),
            ));
        }
        Ok(selected.cloned())
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
        let addresses = if let Ok(ip) = address.parse() {
            vec![ip]
        } else {
            resolver
                .resolve_all(address, false)
                .await
                .map_err(|error| {
                    new_io_error(format!("can't resolve dns: {error}"))
                })?
        };
        if addresses.is_empty() {
            return Err(new_io_error("no dns result"));
        }

        let path_snapshot = if let Some(source) = self.path_source.as_ref() {
            source
                .snapshot()
                .await
                .filter(|(_, _, tun_enabled, _, _)| !tun_enabled)
        } else {
            None
        };

        let mut attempts = FuturesUnordered::new();
        for (attempt, dial_addr) in
            interleave_ip_families(addresses).into_iter().enumerate()
        {
            let path_plan =
                if iface.is_none() && uses_local_or_group_route(dial_addr) {
                    Ok(None)
                } else {
                    match path_snapshot.as_ref() {
                        Some((generation, observations, _, _, intent)) => {
                            Self::endpoint_path(
                                iface,
                                AddressFamily::from(dial_addr),
                                observations,
                                *generation,
                                intent,
                            )
                        }
                        None => Ok(None),
                    }
                };
            let selected_path_id = path_plan
                .as_ref()
                .ok()
                .and_then(|path| path.as_ref())
                .map(|path| path.id.clone());
            let generation_status = path_snapshot
                .as_ref()
                .map(|(generation, _, _, status, _)| (*generation, status.clone()));
            let iface = iface.cloned();
            attempts.push(
                async move {
                    if attempt > 0 {
                        tokio::time::sleep(Duration::from_millis(
                            300 * attempt as u64,
                        ))
                        .await;
                    }
                    let result = match path_plan {
                        Err(error) => Err(error),
                        Ok(Some(path)) => {
                            let result = match (
                                crate::proxy::direct::outbound_interface_for_path(
                                    &path,
                                    iface.as_ref(),
                                ),
                                crate::proxy::direct::source_socket_addr(&path),
                            ) {
                                (Ok(selected_iface), Ok(source)) => {
                                    new_protected_tcp_stream_with_source(
                                        (dial_addr, port).into(),
                                        &selected_iface,
                                        source,
                                        #[cfg(target_os = "linux")]
                                        so_mark,
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
                            };
                            match result {
                                Ok(stream) => {
                                    if let Some((planned, status)) =
                                        generation_status.as_ref()
                                        && status
                                            .read()
                                            .await
                                            .shadow_path_snapshot()
                                            .map(|snapshot| snapshot.0)
                                            != Some(*planned)
                                    {
                                        drop(stream);
                                        Err(std::io::Error::new(
                                            std::io::ErrorKind::Interrupted,
                                            "proxy endpoint dial completed on a stale network path",
                                        ))
                                    } else {
                                        Ok(stream)
                                    }
                                }
                                Err(error) => Err(error),
                            }
                        }
                        Ok(None) => new_protected_tcp_stream(
                            (dial_addr, port).into(),
                            iface.as_ref(),
                            #[cfg(target_os = "linux")]
                            so_mark,
                        )
                        .await,
                    };
                    (dial_addr, selected_path_id, result)
                }
                .boxed(),
            );
        }

        let mut errors = Vec::new();
        while let Some((dial_addr, path_id, result)) = attempts.next().await {
            match result {
                Ok(stream) => {
                    pool_context.path_id = path_id.clone();
                    pool_context.network_generation = path_id
                        .as_ref()
                        .map(|path| path.network_generation)
                        .or_else(|| {
                            path_snapshot
                                .as_ref()
                                .map(|(generation, ..)| *generation)
                        })
                        .or(pool_context.network_generation);
                    if let (Some(path_id), Some(source)) =
                        (path_id, self.path_source.as_ref())
                    {
                        let stream = observe_proxy_endpoint_stream(
                            Box::new(stream),
                            source,
                            path_id,
                            SocketAddr::new(dial_addr, port),
                        )
                        .await;
                        return Ok((stream, pool_context));
                    }
                    return Ok((Box::new(stream) as _, pool_context));
                }
                Err(error) => {
                    if let (Some(path_id), Some(source)) =
                        (path_id, self.path_source.as_ref())
                        && let Some(reporter) = source.traffic_reporter().await
                    {
                        reporter
                            .capture_scoped(
                                crate::app::runtime_state::TrafficKind::ProxyEndpointTcp,
                                Some(path_id),
                                Some(SocksAddr::Ip(SocketAddr::new(
                                    dial_addr, port,
                                ))),
                            )
                            .failed(error.kind());
                    }
                    errors.push(format!("{dial_addr}: {error}"));
                }
            }
        }
        Err(new_io_error(format!(
            "all resolved addresses failed: {}",
            errors.join("; ")
        )))
    }

    async fn connect_datagram(
        &self,
        resolver: ThreadSafeDNSResolver,
        src: Option<SocketAddr>,
        destination: SocksAddr,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
    ) -> std::io::Result<AnyOutboundDatagram> {
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
        let selected_path = match (path_snapshot.as_ref(), target) {
            (_, Some(target)) if uses_local_or_group_route(target.ip()) => None,
            (Some((generation, observations, _, _, intent)), Some(target)) => {
                Self::endpoint_path(
                    iface,
                    AddressFamily::from(target.ip()),
                    observations,
                    *generation,
                    intent,
                )?
            }
            _ => None,
        };
        let socket = if let Some(path) = selected_path.as_ref() {
            let selected_iface =
                crate::proxy::direct::outbound_interface_for_path(path, iface)?;
            let source = crate::proxy::direct::source_socket_addr(path)?;
            let socket = new_protected_udp_socket(
                Some(source),
                Some(&selected_iface),
                #[cfg(target_os = "linux")]
                so_mark,
                target,
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
            if let Some((planned, _, _, status, _)) = path_snapshot.as_ref()
                && status
                    .read()
                    .await
                    .shadow_path_snapshot()
                    .map(|snapshot| snapshot.0)
                    != Some(*planned)
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "proxy UDP dial completed on a stale network path",
                ));
            }
            socket
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

        let dgram = ChainedDatagramWrapper::new(dgram);
        Ok(Box::new(dgram))
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

    async fn connect_stream(
        &self,
        resolver: ThreadSafeDNSResolver,
        address: &str,
        port: u16,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
    ) -> std::io::Result<AnyStream> {
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

        let s = self
            .proxy
            .connect_stream_with_connector(&sess, resolver, self.connector.as_ref())
            .await?;

        let stream = ChainedStreamWrapper::new(s);
        stream.append_to_chain(self.proxy.name()).await;
        Ok(Box::new(stream))
    }

    async fn connect_datagram(
        &self,
        resolver: ThreadSafeDNSResolver,
        _src: Option<SocketAddr>,
        destination: SocksAddr,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
    ) -> std::io::Result<AnyOutboundDatagram> {
        let sess = Session {
            network: Network::Udp,
            typ: Type::Ignore,
            iface: iface.cloned(),
            destination: destination.clone(),
            #[cfg(target_os = "linux")]
            so_mark,
            ..Default::default()
        };
        let s = self
            .proxy
            .connect_datagram_with_connector(
                &sess,
                resolver,
                self.connector.as_ref(),
            )
            .await?;

        let stream = ChainedDatagramWrapper::new(s);
        stream.append_to_chain(self.proxy.name()).await;
        Ok(Box::new(stream))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::mpsc,
    };

    use super::{
        DirectConnector, NetworkPathSource, NetworkPoolContext, RemoteConnector,
        observe_proxy_endpoint_stream,
    };
    use crate::app::dns::MockClashResolver;
    use crate::{
        app::net::OutboundInterface,
        app::runtime_state::Lifecycle,
        app::{
            flow::{
                AddressFamily, InterfaceId, InterfaceKind, NetworkIntentSnapshot,
                NetworkPathId,
            },
            network::{
                BindingStatus, DefaultRouteEvidence, NetworkSnapshot, NetworkStatus,
                PathCandidateObservation,
            },
        },
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
