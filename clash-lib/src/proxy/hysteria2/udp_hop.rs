use std::{
    collections::HashSet,
    fmt::Debug,
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use quinn::{AsyncUdpSocket, UdpPoller, udp::Transmit};

use crate::{
    app::{dns::ThreadSafeDNSResolver, net::OutboundInterface},
    proxy::{
        converters::hysteria2::PortGenerator,
        transport::ConnectorUdpSocket,
        utils::{NetworkPoolContext, RemoteConnector},
    },
    session::SocksAddr,
};

type HopSocketFuture =
    Pin<Box<dyn Future<Output = io::Result<Arc<dyn AsyncUdpSocket>>> + Send>>;
type HopSocketFactory = Arc<dyn Fn() -> HopSocketFuture + Send + Sync>;

pub(super) struct UdpHopOptions {
    pub(super) server_addr: SocketAddr,
    pub(super) port_range: PortGenerator,
    pub(super) resolver: ThreadSafeDNSResolver,
    pub(super) connector: Arc<dyn RemoteConnector>,
    pub(super) iface: Option<OutboundInterface>,
    #[cfg(target_os = "linux")]
    pub(super) so_mark: Option<u32>,
    pub(super) requested_context: NetworkPoolContext,
    pub(super) connection_cancellation: tokio_util::sync::CancellationToken,
    pub(super) interval: Option<Duration>,
}

fn pin_hop_context(
    pool_context: &NetworkPoolContext,
) -> (NetworkPoolContext, Option<crate::app::flow::NetworkPathId>) {
    let expected_path_id = pool_context.path_id.clone();
    let mut hop_context = pool_context.clone();
    hop_context.path_id = None;
    match expected_path_id.as_ref() {
        Some(path_id) => {
            hop_context.eligible_path_ids = Some(HashSet::from([path_id.clone()]));
        }
        None if hop_context.eligible_path_ids.is_some() => {
            hop_context.eligible_path_ids = Some(HashSet::new());
        }
        None => {}
    }
    (hop_context, expected_path_id)
}

fn hop_context_matches(
    expected: &NetworkPoolContext,
    expected_path_id: Option<&crate::app::flow::NetworkPathId>,
    actual: &NetworkPoolContext,
) -> bool {
    actual.network_generation == expected.network_generation
        && actual.path_id.as_ref() == expected_path_id
}

#[derive(Clone)]
struct HopSocketDialer {
    endpoint: SocketAddr,
    resolver: ThreadSafeDNSResolver,
    connector: Arc<dyn RemoteConnector>,
    iface: Option<OutboundInterface>,
    #[cfg(target_os = "linux")]
    so_mark: Option<u32>,
    pool_context: NetworkPoolContext,
    expected_path_id: Option<crate::app::flow::NetworkPathId>,
}

impl HopSocketDialer {
    async fn connect(&self) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let (datagram, pool_context) = self
            .connector
            .connect_datagram_with_pool_context(
                self.resolver.clone(),
                None,
                SocksAddr::Ip(self.endpoint),
                self.iface.as_ref(),
                #[cfg(target_os = "linux")]
                self.so_mark,
                self.pool_context.clone(),
            )
            .await?;
        if !hop_context_matches(
            &self.pool_context,
            self.expected_path_id.as_ref(),
            &pool_context,
        ) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "Hysteria2 port hop resolved to a different network path",
            ));
        }
        Ok(ConnectorUdpSocket::new(datagram, self.endpoint))
    }
}

struct PreviousSocket {
    socket: Arc<dyn AsyncUdpSocket>,
    expires_at: Instant,
}

struct HopState {
    prev_conn: Option<PreviousSocket>,
    cur_conn: Arc<dyn AsyncUdpSocket>,
    generation: u64,
    last: Instant,
    new_hop_port: u16,
    pending_hop:
        Option<tokio::sync::oneshot::Receiver<io::Result<Arc<dyn AsyncUdpSocket>>>>,
}

struct UdpHopPoller {
    hop: Arc<UdpHop>,
    generation: u64,
    inner: Pin<Box<dyn UdpPoller>>,
}

impl Debug for UdpHopPoller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpHopPoller")
            .field("generation", &self.generation)
            .finish()
    }
}

impl UdpPoller for UdpHopPoller {
    fn poll_writable(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        let (generation, socket) = this.hop.get_current_conn();
        if generation != this.generation {
            this.inner = socket.create_io_poller();
            this.generation = generation;
        }
        this.inner.as_mut().poll_writable(cx)
    }
}

/// A udp socket hopper, it can hop to a new port when the time interval is
/// greater than interval
///
/// https://v2.hysteria.network/docs/advanced/Port-Hopping/
pub struct UdpHop {
    /// (prev_conn, cur_conn, last, new_hop_port), here maybe we can use struct
    state: Mutex<HopState>,
    /// The default port is the initial port when this quic connect connects to
    /// the server. Every time we call poll_recv, we must rewrite the source
    /// of the data packet inside to this port, because quic will check the
    /// source of the data packet and discard the unknown source data.
    init_port: u16,
    /// generate new port used to hop
    port_range: PortGenerator,
    /// interval to hop
    interval: Duration,
    dialer: HopSocketFactory,
    cancellation: tokio_util::sync::CancellationToken,
}

impl UdpHop {
    const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);
    const PREVIOUS_SOCKET_GRACE: Duration = Duration::from_secs(5);

    pub async fn new(
        options: UdpHopOptions,
    ) -> io::Result<(Self, NetworkPoolContext)> {
        let UdpHopOptions {
            server_addr,
            port_range,
            resolver,
            connector,
            iface,
            #[cfg(target_os = "linux")]
            so_mark,
            requested_context,
            connection_cancellation,
            interval,
        } = options;
        let (datagram, pool_context) = connector
            .connect_datagram_with_pool_context(
                resolver.clone(),
                None,
                SocksAddr::Ip(server_addr),
                iface.as_ref(),
                #[cfg(target_os = "linux")]
                so_mark,
                requested_context,
            )
            .await?;
        let socket = ConnectorUdpSocket::new(datagram, server_addr);

        // Every hop socket must use the path that established this QUIC
        // connection. If that path could not be identified, keep subsequent
        // sockets generation-only instead of silently pinning to a new NIC.
        let (hop_context, expected_path_id) = pin_hop_context(&pool_context);
        let dialer = HopSocketDialer {
            endpoint: server_addr,
            resolver,
            connector,
            iface,
            #[cfg(target_os = "linux")]
            so_mark,
            pool_context: hop_context,
            expected_path_id,
        };
        let dialer: HopSocketFactory = Arc::new(move || {
            let dialer = dialer.clone();
            Box::pin(async move { dialer.connect().await })
        });

        let state = HopState {
            prev_conn: None,
            cur_conn: socket,
            generation: 0,
            last: Instant::now(),
            new_hop_port: server_addr.port(),
            pending_hop: None,
        }
        .into();

        Ok((
            UdpHop {
                state,
                init_port: server_addr.port(),
                port_range,
                interval: interval.unwrap_or(Self::DEFAULT_INTERVAL),
                dialer,
                cancellation: connection_cancellation.child_token(),
            },
            pool_context,
        ))
    }

    fn lock_state(&self) -> MutexGuard<'_, HopState> {
        self.state.lock().unwrap_or_else(|poisoned| {
            tracing::warn!("recovering poisoned hysteria2 UDP hop state");
            poisoned.into_inner()
        })
    }

    fn expire_previous_socket(state: &mut HopState, now: Instant) {
        if state
            .prev_conn
            .as_ref()
            .is_some_and(|previous| now >= previous.expires_at)
        {
            state.prev_conn = None;
        }
    }

    fn finish_pending_hop(&self, state: &mut HopState, now: Instant) {
        use tokio::sync::oneshot::error::TryRecvError;

        let completed = match state.pending_hop.as_mut() {
            Some(receiver) => match receiver.try_recv() {
                Ok(result) => Some(result),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Closed) => Some(Err(io::Error::other(
                    "hysteria2 UDP hop socket task was cancelled",
                ))),
            },
            None => None,
        };

        let Some(result) = completed else {
            return;
        };
        state.pending_hop = None;

        match result {
            Ok(new_conn) => {
                let old_conn = std::mem::replace(&mut state.cur_conn, new_conn);
                state.generation = state.generation.wrapping_add(1);
                state.prev_conn = Some(PreviousSocket {
                    socket: old_conn,
                    expires_at: now + Self::PREVIOUS_SOCKET_GRACE,
                });
                state.new_hop_port = self.port_range.get();
                tracing::trace!(
                    port = state.new_hop_port,
                    "hysteria2 UDP port hop activated"
                );
            }
            Err(error) => {
                tracing::error!(%error, "hysteria2 UDP port hop socket creation failed");
            }
        }
    }

    fn schedule_hop(&self, state: &mut HopState, now: Instant) {
        if state.pending_hop.is_some()
            || now.duration_since(state.last) <= self.interval
        {
            return;
        }

        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            state.last = now;
            tracing::error!(
                "cannot schedule hysteria2 UDP port hop outside a Tokio runtime"
            );
            return;
        };

        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        let dialer = self.dialer.clone();
        let cancellation = self.cancellation.clone();

        runtime.spawn(async move {
            let result = tokio::select! {
                _ = cancellation.cancelled() => Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Hysteria2 port hop cancelled by connection retirement",
                )),
                result = dialer() => result,
            };
            let _ = result_tx.send(result);
        });

        state.pending_hop = Some(result_rx);
        state.last = now;
        tracing::trace!("preparing hysteria2 UDP port hop socket");
    }

    fn hop(&self) -> u16 {
        let now = Instant::now();
        let mut state = self.lock_state();
        Self::expire_previous_socket(&mut state, now);
        self.finish_pending_hop(&mut state, now);
        self.schedule_hop(&mut state, now);
        state.new_hop_port
    }

    fn get_conn(
        &self,
    ) -> (Option<Arc<dyn AsyncUdpSocket>>, Arc<dyn AsyncUdpSocket>) {
        let mut state = self.lock_state();
        Self::expire_previous_socket(&mut state, Instant::now());
        (
            state
                .prev_conn
                .as_ref()
                .map(|previous| previous.socket.clone()),
            state.cur_conn.clone(),
        )
    }

    fn get_current_conn(&self) -> (u64, Arc<dyn AsyncUdpSocket>) {
        let state = self.lock_state();
        (state.generation, state.cur_conn.clone())
    }

    fn drop_prev_conn(&self) {
        self.lock_state().prev_conn.take();
    }
}

impl Drop for UdpHop {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

impl Debug for UdpHop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpHop")
            // .field("cur_conn", &self.state)
            .finish()
    }
}

impl AsyncUdpSocket for UdpHop {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        let (generation, socket) = self.get_current_conn();
        let inner = socket.create_io_poller();
        Box::pin(UdpHopPoller {
            hop: self,
            generation,
            inner,
        })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let port = self.hop();
        let cur = self.get_conn().1;
        let mut hopped_transmit = transmit.clone();
        hopped_transmit.destination.set_port(port);
        cur.try_send(&hopped_transmit)
    }

    // fn poll_send(
    //     &self,
    //     state: &UdpState,
    //     cx: &mut Context,
    //     transmits: &[Transmit],
    // ) -> Poll<Result<usize, io::Error>> {
    //     // try to hop when we send data
    //     let port = self.hop();

    //     let (_pre_conn, io) = self.get_conn();

    //     // here just need change send addr, it is not necessary to change send
    //     // contents, so we can use unsafe
    //     unsafe {
    //         let prt = transmits.as_ptr() as *mut Transmit;
    //         let slice_mut: &mut [Transmit] =
    //             std::slice::from_raw_parts_mut(prt, transmits.len());
    //         slice_mut.iter_mut().for_each(|v| {
    //             v.destination.set_port(port);
    //         })
    //     }

    //     loop {
    //         ready!(io.poll_send_ready(cx))?;
    //         if let Ok(res) = io.try_io(Interest::WRITABLE, || {
    //             self.socket_rw.send((&io).into(), state, &transmits)
    //         }) {
    //             return Poll::Ready(Ok(res));
    //         }
    //     }
    // }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let (prev_io, io) = self.get_conn();

        // read prev conn
        let (len, should_drop) = match prev_io {
            Some(ref prev_io) => match prev_io.poll_recv(cx, bufs, meta) {
                // can readable, it is represent that the prev conn is not
                // closed, and we recv the data from prev conn
                Poll::Ready(Ok(len)) => (len, false),
                Poll::Ready(Err(e)) => {
                    tracing::trace!("poll prev conn err {}", e);
                    match e.kind() {
                        // io::ErrorKind::WouldBlock => {}
                        io::ErrorKind::TimedOut => return Poll::Ready(Err(e)),
                        _ => (0, true),
                    }
                }
                Poll::Pending => {
                    tracing::trace!("poll prev conn pending");
                    (0, false)
                }
            },
            None => (0, true),
        };

        if should_drop {
            self.drop_prev_conn();
        }
        meta.iter_mut()
            .take(len)
            .for_each(|m| m.addr.set_port(self.init_port));

        match io.poll_recv(cx, bufs, &mut meta[len..]) {
            Poll::Pending => {
                if len > 0 {
                    Poll::Ready(Ok(len))
                } else {
                    Poll::Pending
                }
            }
            Poll::Ready(Ok(res)) => {
                meta.iter_mut()
                    .skip(len)
                    .take(res)
                    .for_each(|m| m.addr.set_port(self.init_port));
                Poll::Ready(Ok(len + res))
            }
            Poll::Ready(Err(e)) => {
                tracing::trace!("poll cur conn err {}", e);
                Poll::Ready(Err(e))
            }
        }
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.get_conn().1.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.get_conn().1.may_fragment()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::atomic::{AtomicU16, Ordering},
    };

    use super::*;
    use crate::app::flow::{AddressFamily, InterfaceId, NetworkPathId};

    fn path(name: &str, index: u32, address: Ipv4Addr) -> NetworkPathId {
        NetworkPathId {
            interface: InterfaceId {
                name: name.to_owned(),
                index,
            },
            family: AddressFamily::Ipv4,
            source_address: Some(address.into()),
            network_generation: 12,
        }
    }

    #[test]
    fn port_hop_sockets_are_pinned_to_the_initial_path() {
        let wifi = path("wifi0", 4, Ipv4Addr::new(192, 0, 2, 10));
        let ethernet = path("eth0", 5, Ipv4Addr::new(198, 51, 100, 10));
        let initial = NetworkPoolContext {
            network_generation: Some(12),
            path_id: Some(wifi.clone()),
            eligible_path_ids: Some([wifi.clone(), ethernet].into_iter().collect()),
            reporter: None,
        };

        let (hop_context, expected_path) = pin_hop_context(&initial);

        assert_eq!(expected_path.as_ref(), Some(&wifi));
        assert_eq!(hop_context.path_id, None);
        assert_eq!(
            hop_context.eligible_path_ids,
            Some([wifi.clone()].into_iter().collect())
        );
        assert!(hop_context_matches(
            &hop_context,
            Some(&wifi),
            &NetworkPoolContext {
                network_generation: Some(12),
                path_id: Some(wifi.clone()),
                ..Default::default()
            }
        ));
        assert!(!hop_context_matches(
            &hop_context,
            Some(&wifi),
            &NetworkPoolContext {
                network_generation: Some(12),
                path_id: Some(path("eth0", 5, Ipv4Addr::new(198, 51, 100, 10))),
                ..Default::default()
            }
        ));
    }

    #[test]
    fn unknown_port_hop_path_does_not_select_a_new_observed_path() {
        let wifi = path("wifi0", 4, Ipv4Addr::new(192, 0, 2, 10));
        let initial = NetworkPoolContext {
            network_generation: Some(12),
            path_id: None,
            eligible_path_ids: Some([wifi].into_iter().collect()),
            reporter: None,
        };

        let (hop_context, expected_path) = pin_hop_context(&initial);

        assert!(expected_path.is_none());
        assert_eq!(hop_context.eligible_path_ids, Some(HashSet::new()));
        assert!(hop_context_matches(
            &hop_context,
            None,
            &NetworkPoolContext {
                network_generation: Some(12),
                ..Default::default()
            }
        ));
        assert!(!hop_context_matches(
            &hop_context,
            None,
            &NetworkPoolContext {
                network_generation: Some(12),
                path_id: Some(path("wifi0", 4, Ipv4Addr::new(192, 0, 2, 10))),
                ..Default::default()
            }
        ));
    }

    #[derive(Debug)]
    struct FakeSocket {
        id: u16,
        observed_port: Arc<AtomicU16>,
        polled_socket: Arc<AtomicU16>,
    }

    #[derive(Debug)]
    struct FakePoller {
        id: u16,
        polled_socket: Arc<AtomicU16>,
    }

    impl UdpPoller for FakePoller {
        fn poll_writable(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            self.polled_socket.store(self.id, Ordering::SeqCst);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncUdpSocket for FakeSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            Box::pin(FakePoller {
                id: self.id,
                polled_socket: self.polled_socket.clone(),
            })
        }

        fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
            self.observed_port
                .store(transmit.destination.port(), Ordering::SeqCst);
            Ok(())
        }

        fn poll_recv(
            &self,
            _cx: &mut Context<'_>,
            _bufs: &mut [io::IoSliceMut<'_>],
            _meta: &mut [quinn::udp::RecvMeta],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        }
    }

    fn fake_socket(
        id: u16,
        observed_port: Arc<AtomicU16>,
        polled_socket: Arc<AtomicU16>,
    ) -> Arc<dyn AsyncUdpSocket> {
        Arc::new(FakeSocket {
            id,
            observed_port,
            polled_socket,
        })
    }

    fn test_hop(socket: Arc<dyn AsyncUdpSocket>, hop_port: u16) -> UdpHop {
        UdpHop {
            state: Mutex::new(HopState {
                prev_conn: None,
                cur_conn: socket,
                generation: 0,
                last: Instant::now(),
                new_hop_port: hop_port,
                pending_hop: None,
            }),
            init_port: 443,
            port_range: PortGenerator::new(hop_port),
            interval: Duration::from_secs(60),
            dialer: Arc::new(|| {
                Box::pin(std::future::ready(Err(io::Error::other(
                    "test hop socket factory must not be called",
                ))))
            }),
            cancellation: tokio_util::sync::CancellationToken::new(),
        }
    }

    #[tokio::test]
    async fn connection_retirement_cancels_a_pending_port_hop_socket() {
        struct DropFlag(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let observed_port = Arc::new(AtomicU16::new(0));
        let polled_socket = Arc::new(AtomicU16::new(0));
        let mut hop = test_hop(fake_socket(1, observed_port, polled_socket), 8443);
        hop.interval = Duration::ZERO;
        hop.state.get_mut().unwrap().last = Instant::now() - Duration::from_secs(1);
        let cancellation = tokio_util::sync::CancellationToken::new();
        hop.cancellation = cancellation.child_token();
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dial_dropped = dropped.clone();
        hop.dialer = Arc::new(move || {
            let dial_dropped = dial_dropped.clone();
            Box::pin(async move {
                let _drop_flag = DropFlag(dial_dropped);
                std::future::pending::<io::Result<Arc<dyn AsyncUdpSocket>>>().await
            })
        });

        assert_eq!(hop.hop(), 8443);
        tokio::task::yield_now().await;
        cancellation.cancel();
        tokio::task::yield_now().await;
        assert_eq!(hop.hop(), 8443);
        assert_eq!(hop.lock_state().generation, 0);
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn try_send_rewrites_a_clone_without_mutating_the_caller() {
        let observed_port = Arc::new(AtomicU16::new(0));
        let polled_socket = Arc::new(AtomicU16::new(0));
        let hop =
            test_hop(fake_socket(1, observed_port.clone(), polled_socket), 8443);
        let transmit = Transmit {
            destination: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
            ecn: None,
            contents: b"hello",
            segment_size: None,
            src_ip: None,
        };

        hop.try_send(&transmit).expect("send should succeed");

        assert_eq!(transmit.destination.port(), 443);
        assert_eq!(observed_port.load(Ordering::SeqCst), 8443);
    }

    #[test]
    fn writable_poller_follows_the_current_socket_generation() {
        use futures::task::noop_waker_ref;

        let observed_port = Arc::new(AtomicU16::new(0));
        let polled_socket = Arc::new(AtomicU16::new(0));
        let hop = Arc::new(test_hop(
            fake_socket(1, observed_port.clone(), polled_socket.clone()),
            443,
        ));
        let mut poller = hop.clone().create_io_poller();
        let mut cx = Context::from_waker(noop_waker_ref());

        assert!(poller.as_mut().poll_writable(&mut cx).is_ready());
        assert_eq!(polled_socket.load(Ordering::SeqCst), 1);

        {
            let mut state = hop.lock_state();
            state.cur_conn = fake_socket(2, observed_port, polled_socket.clone());
            state.generation += 1;
        }

        assert!(poller.as_mut().poll_writable(&mut cx).is_ready());
        assert_eq!(polled_socket.load(Ordering::SeqCst), 2);
    }
}
