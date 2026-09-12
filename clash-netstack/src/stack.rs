use std::sync::Arc;

use bytes::Bytes;
use futures::{Stream, future::BoxFuture};
use log::debug;
use smoltcp::wire::IpProtocol;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::sync::mpsc;

const PACKET_QUEUE_SIZE: usize = 4096;
type PendingPacketPermit = BoxFuture<
    'static,
    Result<mpsc::OwnedPermit<Packet>, mpsc::error::SendError<()>>,
>;

use crate::{
    UdpSocket,
    debug::trace_ip_packet,
    tcp_listener::{TcpListener, TcpStreamHandle},
};

pub(crate) enum IfaceEvent<'a> {
    Icmp, // ICMP packet received
    TcpStream(Box<(smoltcp::socket::tcp::Socket<'a>, Arc<TcpStreamHandle>)>), /* new TCP stream created */
    TcpSocketReady, // at least one TCP socket is ready to read/write
    TcpSocketClosed, /* TCP socket closed by the application, e.g. the TcpStream
                     * is dropped */
    DeviceReady, // Device generated some packets
}
impl std::fmt::Debug for IfaceEvent<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IfaceEvent::Icmp => write!(f, "IfaceEvent::Icmp"),
            IfaceEvent::TcpStream(_) => write!(f, "IfaceEvent::TcpStream"),
            IfaceEvent::TcpSocketReady => write!(f, "IfaceEvent::TcpSocketReady"),
            IfaceEvent::TcpSocketClosed => write!(f, "IfaceEvent::TcpSocketClosed"),
            IfaceEvent::DeviceReady => write!(f, "IfaceEvent::DeviceReady"),
        }
    }
}
/// IO of the stack:
/// Sink to the stack with any IP packets
/// it will be demultiplexed to the correct protocol handler and each handler
/// will process the packets accordingly and write back to the stack Stream
/// Application can Stream the packets from the stack
pub struct NetStack {
    // where the packets get into UDP Stack
    udp_inbound: mpsc::Sender<Packet>,
    // inject TCP packets into the stack
    // where the packets get into TCP Stack
    tcp_inbound: mpsc::Sender<Packet>,

    // outside poll this to receive packets from the stack
    tcp_outbound: mpsc::Receiver<Packet>,
    udp_outbound: mpsc::Receiver<Packet>,
}

#[derive(Clone)]
pub struct Packet {
    data: Bytes,
}

impl Packet {
    pub fn new(data: impl Into<Bytes>) -> Self {
        Packet { data: data.into() }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn into_bytes(self) -> Bytes {
        self.data
    }
}

impl<T> From<T> for Packet
where
    T: Into<Bytes>,
{
    fn from(data: T) -> Self {
        Packet::new(data)
    }
}

/// Thin `Stream` wrapper around a bounded `mpsc::Receiver`.
struct ReceiverStream(mpsc::Receiver<Packet>);

impl Stream for ReceiverStream {
    type Item = Packet;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.0.poll_recv(cx)
    }
}

impl NetStack {
    /// Returns the NetStack instance, a TcpListener and a UdpSocket
    pub fn new() -> (
        Self,
        crate::tcp_listener::TcpListener,
        crate::udp_socket::UdpSocket,
    ) {
        let (tcp_packet_sender, tcp_packet_receiver) =
            mpsc::channel::<Packet>(PACKET_QUEUE_SIZE);
        // UDP uses a separate bounded channel. UDP is inherently lossy, so
        // drop-on-full is correct; the bound prevents unbounded memory growth
        // if a remote floods responses faster than the consumer can drain them.
        let (udp_packet_sender, udp_packet_receiver) =
            mpsc::channel::<Packet>(PACKET_QUEUE_SIZE);

        let (udp_inbound_app, udp_outbound_stack) =
            mpsc::channel::<Packet>(PACKET_QUEUE_SIZE);

        // this UdpSocket is essentially an Iface for UDP but much simpler as it only
        // does packets forwarding
        let udp_socket = UdpSocket::new(udp_outbound_stack, udp_packet_sender);
        let (tcp_inbound_app, tcp_outbound_stack) =
            mpsc::channel::<Packet>(PACKET_QUEUE_SIZE);
        let tcp_listener = TcpListener::new(tcp_outbound_stack, tcp_packet_sender);

        let stack = NetStack {
            udp_inbound: udp_inbound_app,
            tcp_inbound: tcp_inbound_app,
            tcp_outbound: tcp_packet_receiver,
            udp_outbound: udp_packet_receiver,
        };

        (stack, tcp_listener, udp_socket)
    }

    pub fn split(self) -> (StackSplitSink, StackSplitStream) {
        (
            StackSplitSink::new(self.udp_inbound, self.tcp_inbound),
            StackSplitStream::new(self.tcp_outbound, self.udp_outbound),
        )
    }
}

pub struct StackSplitSink {
    udp_inbound: mpsc::Sender<Packet>,
    tcp_inbound: mpsc::Sender<Packet>,

    packet_container: Option<(Packet, IpProtocol)>,
    pending_permit: Option<PendingPacketPermit>,
}
impl StackSplitSink {
    pub fn new(
        udp_inbound: mpsc::Sender<Packet>,
        tcp_inbound: mpsc::Sender<Packet>,
    ) -> Self {
        Self {
            udp_inbound,
            tcp_inbound,
            packet_container: None,
            pending_permit: None,
        }
    }
}
impl futures::Sink<Packet> for StackSplitSink {
    type Error = std::io::Error;

    fn poll_ready(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        if self.packet_container.is_some() {
            futures::ready!(self.as_mut().poll_flush(cx))?;
        }
        std::task::Poll::Ready(Ok(()))
    }

    fn start_send(
        mut self: std::pin::Pin<&mut Self>,
        item: Packet,
    ) -> Result<(), Self::Error> {
        if item.data().is_empty() {
            return Ok(());
        }

        trace_ip_packet("tun inbound packet", item.data());

        let protocol = {
            let packet =
                etherparse::IpSlice::from_slice(item.data()).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
                })?;
            let payload = packet.payload();
            if payload.fragmented {
                if payload.ip_number == etherparse::ip_number::UDP {
                    IpProtocol::Udp
                } else {
                    debug!(
                        "tun fragmented IP packet ignored (protocol: {:?})",
                        payload.ip_number
                    );
                    return Ok(());
                }
            } else {
                match payload.ip_number {
                    etherparse::ip_number::TCP => IpProtocol::Tcp,
                    etherparse::ip_number::UDP => IpProtocol::Udp,
                    etherparse::ip_number::ICMP => IpProtocol::Icmp,
                    etherparse::ip_number::IPV6_ICMP => IpProtocol::Icmpv6,
                    protocol => {
                        debug!("tun IP packet ignored (protocol: {protocol:?})");
                        return Ok(());
                    }
                }
            }
        };
        self.packet_container.replace((item, protocol));

        Ok(())
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        let Some((_, proto)) = self.packet_container.as_ref() else {
            self.pending_permit = None;
            return std::task::Poll::Ready(Ok(()));
        };
        let proto = *proto;

        if self.pending_permit.is_none() {
            let sender = match proto {
                IpProtocol::Udp => self.udp_inbound.clone(),
                IpProtocol::Tcp | IpProtocol::Icmp | IpProtocol::Icmpv6 => {
                    self.tcp_inbound.clone()
                }
                _ => {
                    self.packet_container = None;
                    return std::task::Poll::Ready(Ok(()));
                }
            };
            self.pending_permit = Some(Box::pin(sender.reserve_owned()));
        }

        let permit = match self
            .pending_permit
            .as_mut()
            .expect("pending permit must exist")
            .as_mut()
            .poll(cx)
        {
            std::task::Poll::Pending => return std::task::Poll::Pending,
            std::task::Poll::Ready(Ok(permit)) => permit,
            std::task::Poll::Ready(Err(_)) => {
                self.pending_permit = None;
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "stack inbound channel closed",
                )));
            }
        };

        self.pending_permit = None;
        let (item, _) = self
            .packet_container
            .take()
            .expect("packet must exist while permit is pending");
        permit.send(item);
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.poll_flush(cx)
    }
}

pub struct StackSplitStream {
    inner: futures::stream::Select<ReceiverStream, ReceiverStream>,
}
impl StackSplitStream {
    pub fn new(
        tcp_outbound: mpsc::Receiver<Packet>,
        udp_outbound: mpsc::Receiver<Packet>,
    ) -> Self {
        Self {
            inner: futures::stream::select(
                ReceiverStream(tcp_outbound),
                ReceiverStream(udp_outbound),
            ),
        }
    }
}
impl futures::Stream for StackSplitStream {
    type Item = std::io::Result<Packet>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use futures::StreamExt;
        self.inner.poll_next_unpin(cx).map(|opt| {
            opt.map(|packet| {
                trace_ip_packet("tun reply packet", packet.data());
                Ok(packet)
            })
        })
    }
}
