use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use bytes::{Bytes, BytesMut};
use smoltcp::{
    iface::{SocketHandle, SocketSet},
    phy::Device,
    socket::{tcp, udp},
};
use tokio::sync::{
    Mutex,
    mpsc::{Receiver, Sender},
};
use tracing::{Instrument, error, trace_span};

use crate::{app::dns::ThreadSafeDNSResolver, proxy::datagram::UdpPacket};

use super::{
    events::PortProtocol,
    ports::PortPool,
    stack::{
        tcp::SocketPair,
        udp::{MAX_PACKET, UdpPair},
    },
};

#[allow(clippy::large_enum_variant)]
enum Socket {
    Tcp(
        tcp::Socket<'static>,
        SocketAddr,
        Sender<Bytes>,
        Receiver<Bytes>,
    ),
    Udp(udp::Socket<'static>, Sender<UdpPacket>, Receiver<UdpPacket>),
}

enum SenderType {
    Tcp(Sender<Bytes>),
    Udp(Sender<UdpPacket>),
}

pub struct DeviceManager {
    addr: Ipv4Addr,
    addr_v6: Option<Ipv6Addr>,
    resolver: ThreadSafeDNSResolver,
    dns_servers: Vec<SocketAddr>,

    socket_set: Arc<Mutex<SocketSet<'static>>>,
    socket_pairs: Arc<Mutex<HashMap<SocketHandle, SenderType>>>,

    tcp_port_pool: PortPool,
    udp_port_pool: PortPool,

    packet_notifier: Arc<Mutex<Receiver<()>>>,

    socket_notifier: Sender<Socket>,
    socket_notifier_receiver: Arc<Mutex<Receiver<Socket>>>,
}

impl DeviceManager {
    pub fn new(
        addr: Ipv4Addr,
        addr_v6: Option<Ipv6Addr>,
        resolver: ThreadSafeDNSResolver,
        dns_servers: Vec<SocketAddr>,
        packet_notifier: Receiver<()>,
    ) -> Self {
        let socket_set = Arc::new(Mutex::new(SocketSet::new(Vec::new())));
        let socket_pairs = Arc::new(Mutex::new(HashMap::new()));

        let tcp_port_pool = PortPool::new();
        let udp_port_pool = PortPool::new();

        let (socket_notifier, socket_notifier_receiver) =
            tokio::sync::mpsc::channel(1024);

        Self {
            addr,
            addr_v6,

            resolver,
            dns_servers,

            socket_set,
            socket_pairs,

            tcp_port_pool,
            udp_port_pool,

            packet_notifier: Arc::new(Mutex::new(packet_notifier)),

            socket_notifier,
            socket_notifier_receiver: Arc::new(Mutex::new(socket_notifier_receiver)),
        }
    }

    pub async fn new_tcp_socket(&self, remote: SocketAddr) -> SocketPair {
        let socket = Self::new_client_socket();
        let read_pair = tokio::sync::mpsc::channel(1024);
        let write_pair = tokio::sync::mpsc::channel(1024);

        self.socket_notifier
            .send(Socket::Tcp(socket, remote, read_pair.0, write_pair.1))
            .await
            .unwrap();
        SocketPair::new(read_pair.1, write_pair.0)
    }

    pub async fn new_udp_socket(&self) -> UdpPair {
        let socket = Self::new_client_datagram();
        let read_pair = tokio::sync::mpsc::channel(1024);
        let write_pair = tokio::sync::mpsc::channel(1024);

        self.socket_notifier
            .send(Socket::Udp(socket, read_pair.0, write_pair.1))
            .await
            .unwrap();
        UdpPair::new(read_pair.1, write_pair.0)
    }

    async fn get_ephemeral_tcp_port(&self) -> u16 {
        self.tcp_port_pool.next().await.unwrap()
    }

    async fn release_ephemeral_tcp_port(&self, port: u16) {
        self.tcp_port_pool.release(port).await;
    }

    async fn get_ephemeral_udp_port(&self) -> u16 {
        self.udp_port_pool.next().await.unwrap()
    }

    async fn release_ephemeral_udp_port(&self, port: u16) {
        self.udp_port_pool.release(port).await;
    }

    fn new_client_socket() -> tcp::Socket<'static> {
        tcp::Socket::new(
            smoltcp::socket::tcp::SocketBuffer::new(vec![0; 65535]),
            smoltcp::socket::tcp::SocketBuffer::new(vec![0; 65535]),
        )
    }

    fn new_client_datagram() -> udp::Socket<'static> {
        let rx_meta = vec![udp::PacketMetadata::EMPTY; 10];
        let tx_meta = vec![udp::PacketMetadata::EMPTY; 10];
        let rx_data = vec![0u8; MAX_PACKET];
        let tx_data = vec![0u8; MAX_PACKET];
        let udp_rx_buffer = udp::PacketBuffer::new(rx_meta, rx_data);
        let udp_tx_buffer = udp::PacketBuffer::new(tx_meta, tx_data);

        udp::Socket::new(udp_rx_buffer, udp_tx_buffer)
    }
}

pub struct VirtualIpDevice {
    mtu: usize,

    packet_sender: Sender<Bytes>,
    packet_receiver: Receiver<(PortProtocol, Bytes)>,
}

impl VirtualIpDevice {
    pub fn new(
        // send packet to wg stack
        packet_sender: Sender<Bytes>,
        // when wg stack receives a packet, it will send it to this receiver
        mut packet_receiver: Receiver<(PortProtocol, Bytes)>,

        // when wg stack receives a packet, it will send a notification to this
        // sender
        packet_notifier: Sender<()>,
        mtu: usize,
    ) -> Self {
        let (inner_packet_sender, inner_packet_receiver) =
            tokio::sync::mpsc::channel(1024);
        tokio::spawn(async move {
            loop {
                let span = trace_span!("receive_packet");

                match packet_receiver.recv().instrument(span).await {
                    Some((proto, data)) => {
                        inner_packet_sender.send((proto, data)).await.unwrap();
                        let _ = packet_notifier.try_send(());
                    }
                    _ => {
                        break;
                    }
                }
            }
        });

        Self {
            mtu,
            packet_sender,
            packet_receiver: inner_packet_receiver,
        }
    }
}

impl Device for VirtualIpDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken;

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let next = self.packet_receiver.try_recv().ok();
        match next {
            Some((_proto, data)) => {
                // Convert to mutable buffer for potential checksum fix
                let mut buffer = BytesMut::from(&data[..]);

                // Fix UDP checksum if needed
                // Some environments (NAT, checksum offload, virtualization) may
                // corrupt the checksum We recalculate it here since
                // WireGuard AEAD already guarantees data integrity
                // Note: An alternative approach is to skip RX checksum
                // verification by setting `caps.checksum.udp =
                // smoltcp::phy::Checksum::Tx` in capabilities(), but
                // recalculating feels cleaner than disabling verification
                // entirely
                use smoltcp::wire::*;
                if let Ok(IpVersion::Ipv4) = IpVersion::of_packet(&buffer)
                    && let Ok(ipv4) = Ipv4Packet::new_checked(&buffer[..])
                    && ipv4.next_header() == IpProtocol::Udp
                {
                    let src_addr = ipv4.src_addr();
                    let dst_addr = ipv4.dst_addr();
                    let ip_header_len = ipv4.header_len() as usize;

                    // Recalculate UDP checksum
                    if let Ok(mut udp) =
                        UdpPacket::new_checked(&mut buffer[ip_header_len..])
                    {
                        udp.fill_checksum(
                            &IpAddress::Ipv4(src_addr),
                            &IpAddress::Ipv4(dst_addr),
                        );
                    }
                }

                let rx_token = RxToken { buffer };
                let tx_token = TxToken {
                    sender: self.packet_sender.clone(),
                };
                Some((rx_token, tx_token))
            }
            None => None,
        }
    }

    fn transmit(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            sender: self.packet_sender.clone(),
        })
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        caps.medium = smoltcp::phy::Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

pub struct RxToken {
    buffer: BytesMut,
}

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&mut self.buffer)
    }
}

pub struct TxToken {
    sender: Sender<Bytes>,
}

impl smoltcp::phy::TxToken for TxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        match self.sender.try_send(buffer.into()) {
            Ok(_) => {}
            Err(err) => {
                error!("failed to send packet: {}", err);
            }
        }
        result
    }
}
