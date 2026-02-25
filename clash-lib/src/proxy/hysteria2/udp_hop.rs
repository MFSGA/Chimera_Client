use std::{
    fmt::Debug,
    io,
    net::SocketAddr,
    ops::Sub,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use quinn::{
    AsyncUdpSocket, Runtime, TokioRuntime, UdpPoller,
    udp::{RecvMeta, Transmit},
};

use crate::proxy::converters::hysteria2::PortGenerator;

struct HopState {
    prev_conn: Option<Arc<dyn AsyncUdpSocket>>,
    cur_conn: Arc<dyn AsyncUdpSocket>,
    last_hop: Instant,
    next_port: u16,
}

pub struct UdpHop {
    state: Mutex<HopState>,
    initial_port: u16,
    port_generator: PortGenerator,
    interval: Duration,
    bind_addr: SocketAddr,
    #[cfg(target_os = "linux")]
    so_mark: Option<u32>,
}

impl UdpHop {
    const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);

    fn build_socket(
        bind_addr: SocketAddr,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
    ) -> io::Result<std::net::UdpSocket> {
        let domain = match bind_addr {
            SocketAddr::V4(_) => socket2::Domain::IPV4,
            SocketAddr::V6(_) => socket2::Domain::IPV6,
        };
        let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, None)?;
        #[cfg(target_os = "linux")]
        if let Some(so_mark) = so_mark {
            socket.set_mark(so_mark)?;
        }
        socket.set_nonblocking(true)?;
        socket.bind(&bind_addr.into())?;
        Ok(socket.into())
    }

    pub fn new(
        initial_port: u16,
        port_generator: PortGenerator,
        interval: Option<Duration>,
        bind_addr: SocketAddr,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
    ) -> io::Result<Self> {
        let socket = Self::build_socket(
            bind_addr,
            #[cfg(target_os = "linux")]
            so_mark,
        )?;
        let state = HopState {
            prev_conn: None,
            cur_conn: TokioRuntime.wrap_udp_socket(socket)?,
            last_hop: Instant::now(),
            next_port: initial_port,
        };

        Ok(Self {
            state: Mutex::new(state),
            initial_port,
            port_generator,
            interval: interval.unwrap_or(Self::DEFAULT_INTERVAL),
            bind_addr,
            #[cfg(target_os = "linux")]
            so_mark,
        })
    }

    fn maybe_hop(&self) -> u16 {
        let mut lock = self.state.lock().expect("udp hop lock poisoned");
        if Instant::now().sub(lock.last_hop) > self.interval && lock.prev_conn.is_none() {
            match Self::build_socket(
                self.bind_addr,
                #[cfg(target_os = "linux")]
                self.so_mark,
            )
            .and_then(|socket| TokioRuntime.wrap_udp_socket(socket))
            {
                Ok(new_conn) => {
                    lock.last_hop = Instant::now();
                    lock.next_port = self.port_generator.get();
                    lock.prev_conn = Some(std::mem::replace(&mut lock.cur_conn, new_conn));
                }
                Err(err) => {
                    tracing::error!("hysteria2 port hopping failed: {err}");
                }
            }
        }
        lock.next_port
    }

    fn get_connections(&self) -> (Option<Arc<dyn AsyncUdpSocket>>, Arc<dyn AsyncUdpSocket>) {
        let lock = self.state.lock().expect("udp hop lock poisoned");
        (lock.prev_conn.clone(), lock.cur_conn.clone())
    }

    fn drop_previous_connection(&self) {
        let mut lock = self.state.lock().expect("udp hop lock poisoned");
        lock.prev_conn.take();
    }
}

impl Debug for UdpHop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpHop").finish()
    }
}

impl AsyncUdpSocket for UdpHop {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.get_connections().1.create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let hop_port = self.maybe_hop();
        let (_, current_conn) = self.get_connections();

        unsafe {
            let ptr = transmit as *const Transmit as *mut Transmit;
            (*ptr).destination.set_port(hop_port);
        }

        current_conn.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let (prev_conn, current_conn) = self.get_connections();

        let (prev_len, should_drop_prev) = match prev_conn {
            Some(ref prev_conn) => match prev_conn.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(len)) => (len, false),
                Poll::Ready(Err(err)) => {
                    tracing::trace!("hysteria2 previous conn recv error: {err}");
                    (0, true)
                }
                Poll::Pending => (0, false),
            },
            None => (0, false),
        };

        if should_drop_prev {
            self.drop_previous_connection();
        }

        meta.iter_mut()
            .take(prev_len)
            .for_each(|recv_meta| recv_meta.addr.set_port(self.initial_port));

        match current_conn.poll_recv(cx, bufs, &mut meta[prev_len..]) {
            Poll::Pending => {
                if prev_len > 0 {
                    Poll::Ready(Ok(prev_len))
                } else {
                    Poll::Pending
                }
            }
            Poll::Ready(Ok(current_len)) => {
                meta.iter_mut()
                    .skip(prev_len)
                    .take(current_len)
                    .for_each(|recv_meta| recv_meta.addr.set_port(self.initial_port));
                Poll::Ready(Ok(prev_len + current_len))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        }
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.get_connections().1.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.get_connections().1.may_fragment()
    }
}
