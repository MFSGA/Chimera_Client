use std::{io, net::SocketAddr};

use anyhow::Context;
use tokio::net::{TcpListener, UdpSocket};

const LOOPBACK_SOCKET_BIND_ATTEMPTS: usize = 64;

pub(crate) async fn reserve_loopback_tcp_udp_sockets()
-> anyhow::Result<(TcpListener, UdpSocket, SocketAddr)> {
    fn is_retryable_bind_error(error: &io::Error) -> bool {
        matches!(
            error.kind(),
            io::ErrorKind::AddrInUse
                | io::ErrorKind::AddrNotAvailable
                | io::ErrorKind::PermissionDenied
        )
    }

    let mut last_error = None;
    for _ in 0..LOOPBACK_SOCKET_BIND_ATTEMPTS {
        let udp = match UdpSocket::bind("127.0.0.1:0").await {
            Ok(udp) => udp,
            Err(error) if is_retryable_bind_error(&error) => {
                last_error = Some(error);
                continue;
            }
            Err(error) => {
                return Err(error).context("failed to reserve UDP DNS port");
            }
        };
        let addr = udp.local_addr().context("failed to read UDP DNS address")?;

        match TcpListener::bind(addr).await {
            Ok(tcp) => return Ok((tcp, udp, addr)),
            Err(error) if is_retryable_bind_error(&error) => {
                last_error = Some(error);
                drop(udp);
            }
            Err(error) => {
                return Err(error).context("failed to reserve TCP DNS port");
            }
        }
    }

    anyhow::bail!(
        "failed to reserve matching TCP and UDP DNS ports after {LOOPBACK_SOCKET_BIND_ATTEMPTS} attempts: {}",
        last_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "no bind candidate was produced".to_owned())
    )
}
