use std::{io, net::SocketAddr};

use tokio::net::{TcpListener, TcpStream};

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
        todo!()
        /* let s = socket2::SockRef::from(s);
        s.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(10))
                .with_interval(Duration::from_secs(1)),
        ) */
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
            tracing::warn!("dualstack not supported, falling back to ipv6 only: {e}");
        } else {
            dualstack = true;
        }
    };
    Ok((socket, dualstack))
}

pub fn try_create_dualstack_tcplistener(addr: SocketAddr) -> io::Result<TcpListener> {
    let (socket, _dualstack) = try_create_dualstack_socket(addr, socket2::Type::STREAM)?;

    socket.set_nonblocking(true)?;
    // For fast restart avoid Address In Use Error
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;

    let listener = TcpListener::from_std(socket.into())?;
    Ok(listener)
}
