use std::{
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Sink, SinkExt, Stream, StreamExt};
use tokio::net::UdpSocket;
use tokio_util::udp::UdpFramed;
use tracing::{error, trace};

use crate::{
    proxy::{AnyStream, datagram::UdpPacket, socks::inbound::Socks5UDPCodec},
    session::SocksAddr,
};

pub(crate) struct Socks5Datagram {
    // RFC 1928 ties the UDP relay lifetime to the TCP control connection.
    _socket: AnyStream,
    remote: SocketAddr,
    inner: UdpFramed<Socks5UDPCodec>,
}

impl Socks5Datagram {
    pub(crate) fn new(
        socket: AnyStream,
        remote: SocketAddr,
        udp_socket: UdpSocket,
    ) -> Self {
        Self {
            _socket: socket,
            remote,
            inner: UdpFramed::new(udp_socket, Socks5UDPCodec),
        }
    }
}

impl Drop for Socks5Datagram {
    fn drop(&mut self) {
        trace!("SOCKS5 UDP relay to {} closed", self.remote);
    }
}

impl Sink<UdpPacket> for Socks5Datagram {
    type Error = std::io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.get_mut().inner.poll_ready_unpin(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let remote = self.remote;
        trace!(
            "sending SOCKS5 UDP packet via relay {}, dst {}",
            remote, item.dst_addr
        );
        self.get_mut()
            .inner
            .start_send_unpin(((item.data.into(), item.dst_addr), remote))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.get_mut().inner.poll_flush_unpin(cx)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.get_mut().inner.poll_close_unpin(cx)
    }
}

impl Stream for Socks5Datagram {
    type Item = UdpPacket;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.get_mut().inner.poll_next_unpin(cx).map(|item| {
            item.map(|res| match res {
                Ok(((src, data), dst)) => {
                    trace!("received SOCKS5 UDP packet from {} to {}", src, dst);
                    UdpPacket {
                        src_addr: src,
                        dst_addr: SocksAddr::Ip(dst),
                        data: data.into(),
                        inbound_user: None,
                    }
                }
                Err(err) => {
                    error!("failed to decode SOCKS5 UDP packet: {err}");
                    UdpPacket {
                        src_addr: SocksAddr::any_ipv4(),
                        dst_addr: SocksAddr::any_ipv4(),
                        data: Vec::new(),
                        inbound_user: None,
                    }
                }
            })
        })
    }
}
