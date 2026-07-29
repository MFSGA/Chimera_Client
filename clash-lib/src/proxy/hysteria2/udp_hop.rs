use std::{
    fmt::Debug,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use quinn::{AsyncUdpSocket, Runtime, TokioRuntime, UdpPoller, udp::Transmit};

use crate::{
    app::net::OutboundInterface,
    proxy::{converters::hysteria2::PortGenerator, utils::new_protected_udp_socket},
};

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
    family_hint: SocketAddr,
    iface: Option<OutboundInterface>,
    #[cfg(target_os = "linux")]
    so_mark: Option<u32>,
}

impl UdpHop {
    const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);
    const PREVIOUS_SOCKET_GRACE: Duration = Duration::from_secs(5);

    pub async fn new(
        server_addr: SocketAddr,
        port_range: PortGenerator,
        iface: Option<OutboundInterface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
        interval: Option<Duration>,
    ) -> io::Result<Self> {
        let socket = new_protected_udp_socket(
            None,
            iface.as_ref(),
            #[cfg(target_os = "linux")]
            so_mark,
            Some(server_addr),
        )
        .await?
        .into_std()?;

        let state = HopState {
            prev_conn: None,
            cur_conn: TokioRuntime.wrap_udp_socket(socket)?,
            generation: 0,
            last: Instant::now(),
            new_hop_port: server_addr.port(),
            pending_hop: None,
        }
        .into();

        Ok(UdpHop {
            state,
            init_port: server_addr.port(),
            port_range,
            interval: interval.unwrap_or(Self::DEFAULT_INTERVAL),
            family_hint: server_addr,
            iface,
            #[cfg(target_os = "linux")]
            so_mark,
        })
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
        let iface = self.iface.clone();
        let family_hint = self.family_hint;
        #[cfg(target_os = "linux")]
        let so_mark = self.so_mark;

        runtime.spawn(async move {
            let result = new_protected_udp_socket(
                None,
                iface.as_ref(),
                #[cfg(target_os = "linux")]
                so_mark,
                Some(family_hint),
            )
            .await
            .and_then(|udp| udp.into_std())
            .and_then(|udp| TokioRuntime.wrap_udp_socket(udp));
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
            family_hint: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
            iface: None,
            #[cfg(target_os = "linux")]
            so_mark: None,
        }
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
