use std::{io, net::SocketAddr, time::Duration};

use socket2::TcpKeepalive;

use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::time::{sleep, timeout};
use tracing::{debug, error, instrument, trace, warn};

use crate::app::net::OutboundInterface;
use crate::proxy::utils::platform::{
    maybe_protect_socket, must_bind_socket_on_interface,
};
use crate::{app::dns::ThreadSafeDNSResolver, session::Session};

pub fn apply_tcp_options(s: &TcpStream) -> std::io::Result<()> {
    #[cfg(not(target_os = "windows"))]
    {
        let s = socket2::SockRef::from(s);
        s.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(10))
                .with_interval(Duration::from_secs(1))
                .with_retries(3),
        )
    }
    #[cfg(target_os = "windows")]
    {
        let s = socket2::SockRef::from(s);
        s.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(10))
                .with_interval(Duration::from_secs(1)),
        )
    }
}

/// Create dualstack socket if it can
/// If failed, fallback to single stack silently
pub fn try_create_dualstack_socket(
    addr: SocketAddr,
    tcp_or_udp: socket2::Type,
) -> std::io::Result<(socket2::Socket, bool)> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let mut dualstack = false;
    let socket = socket2::Socket::new(domain, tcp_or_udp, None)?;
    if addr.is_ipv6() && addr.ip().is_unspecified() {
        if let Err(e) = socket.set_only_v6(false) {
            // If setting dualstack fails, fallback to single stack
            tracing::warn!(
                "dualstack not supported, falling back to ipv6 only: {e}"
            );
        } else {
            dualstack = true;
        }
    };
    Ok((socket, dualstack))
}

pub fn try_create_dualstack_tcplistener(
    addr: SocketAddr,
) -> io::Result<TcpListener> {
    let (socket, _dualstack) =
        try_create_dualstack_socket(addr, socket2::Type::STREAM)?;

    socket.set_nonblocking(true)?;
    // For fast restart avoid Address In Use Error
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;

    let listener = TcpListener::from_std(socket.into())?;
    Ok(listener)
}

/// Convert ipv6 mapped ipv4 address back to ipv4. Other address remain
/// unchanged. e.g. ::ffff:127.0.0.1 -> 127.0.0.1
pub trait ToCanonical {
    fn to_canonical(self) -> SocketAddr;
}

impl ToCanonical for SocketAddr {
    fn to_canonical(mut self) -> SocketAddr {
        self.set_ip(self.ip().to_canonical());
        self
    }
}

pub async fn family_hint_for_session(
    sess: &Session,
    resolver: &ThreadSafeDNSResolver,
) -> Option<SocketAddr> {
    if let Some(resolved_ip) = sess.resolved_ip {
        Some(SocketAddr::new(resolved_ip, sess.destination.port()))
    } else if let Some(host) = sess.destination.ip() {
        Some(SocketAddr::new(host, sess.destination.port()))
    } else {
        let host = sess.destination.host();
        resolver
            .resolve_v6(&host, false)
            .await
            .map(|ip| {
                ip.map(|ip| SocketAddr::new(ip.into(), sess.destination.port()))
            })
            .ok()?
    }
}

// #[instrument(skip(so_mark))]
pub async fn new_tcp_stream(
    endpoint: SocketAddr,
    iface: Option<&OutboundInterface>,
    #[cfg(target_os = "linux")] so_mark: Option<u32>,
) -> std::io::Result<TcpStream> {
    const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
    #[cfg(target_os = "windows")]
    const MAX_RETRY_ATTEMPTS: usize = 3;

    #[cfg(not(target_os = "windows"))]
    {
        let socket = prepare_outbound_tcp_socket(
            endpoint,
            iface,
            #[cfg(target_os = "linux")]
            so_mark,
        )?;
        return timeout(
            TCP_CONNECT_TIMEOUT,
            TcpSocket::from_std_stream(socket.into()).connect(endpoint),
        )
        .await?;
    }

    #[cfg(target_os = "windows")]
    {
        let mut last_err = None;

        for attempt in 0..MAX_RETRY_ATTEMPTS {
            let socket = prepare_outbound_tcp_socket(
                endpoint,
                iface,
                #[cfg(target_os = "linux")]
                so_mark,
            )?;

            match timeout(
                TCP_CONNECT_TIMEOUT,
                TcpSocket::from_std_stream(socket.into()).connect(endpoint),
            )
            .await
            {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(err))
                    if should_retry_tcp_connect(&err)
                        && attempt + 1 < MAX_RETRY_ATTEMPTS =>
                {
                    warn!(
                        endpoint = %endpoint,
                        attempt = attempt + 1,
                        max_attempts = MAX_RETRY_ATTEMPTS,
                        err = ?err,
                        "tcp connect hit a transient local address conflict; recreating socket and retrying"
                    );
                    last_err = Some(err);
                    sleep(Duration::from_millis(25 * (attempt as u64 + 1))).await;
                }
                Ok(Err(err)) => return Err(err),
                Err(err) => return Err(err.into()),
            }
        }

        return Err(last_err.unwrap_or_else(|| {
            io::Error::other(
                "tcp connect retry loop exited without a captured error",
            )
        }));
    }
}

fn prepare_outbound_tcp_socket(
    endpoint: SocketAddr,
    iface: Option<&OutboundInterface>,
    #[cfg(target_os = "linux")] so_mark: Option<u32>,
) -> std::io::Result<socket2::Socket> {
    let (socket, family) = match endpoint {
        SocketAddr::V4(_) => (
            socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::STREAM,
                None,
            )?,
            socket2::Domain::IPV4,
        ),
        SocketAddr::V6(_) => (
            socket2::Socket::new(
                socket2::Domain::IPV6,
                socket2::Type::STREAM,
                None,
            )?,
            socket2::Domain::IPV6,
        ),
    };
    debug!("created tcp socket");

    if let Some(iface) = iface {
        must_bind_socket_on_interface(&socket, iface, family)?;
        trace!(iface = ?iface, "tcp socket prepared for outbound interface");
    }
    #[cfg(target_os = "android")]
    maybe_protect_socket(&socket)?;
    #[cfg(not(target_os = "android"))]
    if iface.is_none() {
        maybe_protect_socket(&socket)?;
    }

    #[cfg(not(target_os = "android"))]
    #[cfg(target_os = "linux")]
    if let Some(so_mark) = so_mark {
        socket.set_mark(so_mark)?;
    }

    socket.set_keepalive(true)?;
    socket.set_tcp_nodelay(true)?;
    socket.set_nonblocking(true)?;

    Ok(socket)
}

#[cfg(target_os = "windows")]
fn should_retry_tcp_connect(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(10048))
}

#[instrument(skip(so_mark))]
pub async fn new_udp_socket(
    src: Option<SocketAddr>,
    iface: Option<&OutboundInterface>,
    #[cfg(target_os = "linux")] so_mark: Option<u32>,
    // Optional family hint for the socket.
    // If not provided, the family will be determined based on the source
    // address or interface.
    family_hint: Option<std::net::SocketAddr>,
) -> std::io::Result<UdpSocket> {
    // Determine the socket family based on the source address or interface
    // logic:
    // - If family_hint is provided, use it.
    // - If src is provided and is IPv6, use IPv6.
    // - If iface is provided and is IPv6, use IPv6.
    // - Otherwise, default to IPv4.
    let (socket, family) = match (family_hint, src, iface) {
        (Some(family_hint), ..) => {
            let domain = socket2::Domain::for_address(family_hint);
            (
                socket2::Socket::new(domain, socket2::Type::DGRAM, None)?,
                domain,
            )
        }
        (None, Some(src), _) if src.is_ipv6() => (
            try_create_dualstack_socket(src, socket2::Type::DGRAM)?.0,
            socket2::Domain::IPV6,
        ),
        (None, _, Some(iface)) if iface.addr_v6.is_some() => (
            socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)?,
            socket2::Domain::IPV6,
        ),
        _ => (
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?,
            socket2::Domain::IPV4,
        ),
    };
    debug!("created udp socket");

    if !cfg!(target_os = "android") {
        match (src, iface) {
            (_, Some(iface)) => {
                must_bind_socket_on_interface(&socket, iface, family).inspect_err(
                    |x| {
                        error!("failed to bind socket to interface: {}", x);
                    },
                )?;
                // binding is not necessary for linux but is required on windows
                // Without binding local_addr can't be obtained by system call
                // which is required on quinn.
                #[cfg(target_os = "windows")]
                if let Some(addr) = src {
                    socket.bind(&socket2::SockAddr::from(addr))?;
                }

                trace!(iface = ?iface, "udp socket bound: {socket:?}");
            }
            (Some(src), None) => {
                socket.bind(&src.into())?;
                trace!(src = ?src, "udp socket bound: {socket:?}");
            }
            (None, None) => {
                // On Windows, UDP sockets must be bound to get a valid local_addr
                // which is required for some operations (e.g., quinn/QUIC)
                #[cfg(target_os = "windows")]
                {
                    let bind_addr = match family {
                        socket2::Domain::IPV4 => {
                            "0.0.0.0:0".parse::<SocketAddr>().unwrap()
                        }
                        socket2::Domain::IPV6 => {
                            "[::]:0".parse::<SocketAddr>().unwrap()
                        }
                        _ => "0.0.0.0:0".parse::<SocketAddr>().unwrap(),
                    };
                    socket.bind(&socket2::SockAddr::from(bind_addr))?;
                    trace!(addr = ?bind_addr, "udp socket bound to default address on Windows: {socket:?}");
                }
                #[cfg(not(target_os = "windows"))]
                trace!("udp socket not bound to any specific address: {socket:?}");
            }
        }
    }

    #[cfg(target_os = "linux")]
    if let Some(so_mark) = so_mark {
        socket.set_mark(so_mark)?;
    }

    #[cfg(target_os = "android")]
    maybe_protect_socket(&socket)?;
    #[cfg(not(target_os = "android"))]
    if iface.is_none() {
        maybe_protect_socket(&socket)?;
    }

    socket.set_broadcast(true)?;
    socket.set_nonblocking(true)?;

    UdpSocket::from_std(socket.into())
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::new_udp_socket;
    use crate::proxy::utils::{
        SocketProtector, clear_socket_protector, set_socket_protector,
    };

    struct CountingProtector {
        calls: Arc<AtomicUsize>,
    }

    impl SocketProtector for CountingProtector {
        fn protect_socket_handle(&self, _handle: usize) -> std::io::Result<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn udp_socket_invokes_socket_protector() {
        let calls = Arc::new(AtomicUsize::new(0));
        set_socket_protector(Arc::new(CountingProtector {
            calls: calls.clone(),
        }));

        let family_hint = Some("127.0.0.1:0".parse().expect("valid socket addr"));

        #[cfg(target_os = "linux")]
        let _socket = new_udp_socket(None, None, None, family_hint)
            .await
            .expect("udp socket should be created");

        #[cfg(not(target_os = "linux"))]
        let _socket = new_udp_socket(None, None, family_hint)
            .await
            .expect("udp socket should be created");

        clear_socket_protector();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
