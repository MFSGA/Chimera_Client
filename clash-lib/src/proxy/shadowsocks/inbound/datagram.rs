use std::{
    collections::HashMap,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use futures::ready;
use shadowsocks::{ProxySocket, relay::udprelay::options::UdpSocketControlData};
use tokio::io::ReadBuf;
use tracing::{debug, error};

use crate::{
    common::errors::new_io_error,
    proxy::{datagram::UdpPacket, utils::ToCanonical},
    session::SocksAddr,
};

pub(crate) struct InboundShadowsocksDatagram {
    socket: ProxySocket<shadowsocks::net::UdpSocket>,
    server_session_id: u64,
    client_controls: HashMap<SocketAddr, UdpSocketControlData>,
    flushed: bool,
    packet: Option<UdpPacket>,
    buffer: bytes::BytesMut,
}

impl std::fmt::Debug for InboundShadowsocksDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundShadowsocksDatagram")
            .field("server_session_id", &self.server_session_id)
            .field("socket", &self.socket)
            .finish()
    }
}

impl InboundShadowsocksDatagram {
    pub fn new(socket: ProxySocket<shadowsocks::net::UdpSocket>) -> Self {
        Self {
            socket,
            server_session_id: rand::random(),
            client_controls: HashMap::new(),
            flushed: true,
            packet: None,
            buffer: bytes::BytesMut::with_capacity(65_535),
        }
    }
}

impl futures::Stream for InboundShadowsocksDatagram {
    type Item = UdpPacket;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let Self {
            socket,
            server_session_id,
            client_controls,
            buffer,
            ..
        } = self.get_mut();

        loop {
            buffer.resize(buffer.capacity(), 0);
            let mut read_buffer = ReadBuf::new(buffer);
            let result =
                ready!(socket.poll_recv_from_with_ctrl(cx, &mut read_buffer));
            debug!("received Shadowsocks UDP packet: {result:?}");

            match result {
                Ok((size, source, target, _, control)) => {
                    let source = source.to_canonical();
                    if let Some(control) = control.as_ref() {
                        let entry =
                            client_controls.entry(source).or_insert_with(|| {
                                let mut entry = UdpSocketControlData::default();
                                entry.server_session_id = *server_session_id;
                                entry
                            });
                        entry.client_session_id = control.client_session_id;
                        entry.user = control.user.clone();
                    }

                    return Poll::Ready(Some(UdpPacket {
                        data: read_buffer.filled()[..size].to_vec(),
                        src_addr: source.into(),
                        dst_addr: match target {
                            shadowsocks::relay::Address::SocketAddress(addr) => {
                                addr.into()
                            }
                            shadowsocks::relay::Address::DomainNameAddress(
                                domain,
                                port,
                            ) => SocksAddr::Domain(domain, port),
                        },
                        inbound_user: control
                            .and_then(|control| control.user)
                            .map(|user| user.name().to_owned()),
                    }));
                }
                Err(err) => {
                    error!("failed to receive Shadowsocks UDP packet: {err}");
                }
            }
        }
    }
}

impl futures::Sink<UdpPacket> for InboundShadowsocksDatagram {
    type Error = std::io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(
        self: Pin<&mut Self>,
        packet: UdpPacket,
    ) -> Result<(), Self::Error> {
        let this = self.get_mut();
        this.packet = Some(packet);
        this.flushed = false;
        Ok(())
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let Self {
            socket,
            client_controls,
            packet,
            flushed,
            ..
        } = &mut *self;

        let packet_container = packet;
        let Some(packet) = packet_container.as_ref() else {
            return Poll::Ready(Err(std::io::Error::other(
                "no Shadowsocks UDP packet to send",
            )));
        };

        let source = match &packet.src_addr {
            SocksAddr::Ip(addr) => shadowsocks::relay::Address::SocketAddress(*addr),
            SocksAddr::Domain(host, port) => {
                shadowsocks::relay::Address::DomainNameAddress(host.clone(), *port)
            }
        };
        let client_addr = packet.dst_addr.clone().must_into_socket_addr();
        let control = match client_controls.get_mut(&client_addr) {
            Some(control) => control,
            None => {
                error!(
                    "missing Shadowsocks UDP control data for client {client_addr}; dropping response"
                );
                *packet_container = None;
                *flushed = true;
                return Poll::Ready(Ok(()));
            }
        };

        let written = ready!(socket.poll_send_to_with_ctrl(
            client_addr,
            &source,
            control,
            packet.data.as_ref(),
            cx,
        ))?;
        control.packet_id = control.packet_id.checked_add(1).ok_or_else(|| {
            std::io::Error::other("Shadowsocks UDP packet id overflow")
        })?;

        let expected = packet.data.len();
        *packet_container = None;
        *flushed = true;
        if written == expected {
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Err(new_io_error(format!(
                "failed to write entire Shadowsocks datagram: {written}/{expected}"
            ))))
        }
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }
}
