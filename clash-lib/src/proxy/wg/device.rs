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
        let (socket_notifier, socket_notifier_receiver) =
            tokio::sync::mpsc::channel(1024);
        Self {
            addr,
            addr_v6,
            resolver,
            dns_servers,
            socket_set: Arc::new(Mutex::new(SocketSet::new(Vec::new()))),
            socket_pairs: Arc::new(Mutex::new(HashMap::new())),
            tcp_port_pool: PortPool::new(),
            udp_port_pool: PortPool::new(),
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
            .expect("wireguard socket manager should be alive");
        SocketPair::new(read_pair.1, write_pair.0)
    }

    pub async fn new_udp_socket(&self) -> UdpPair {
        let socket = Self::new_client_datagram();
        let read_pair = tokio::sync::mpsc::channel(1024);
        let write_pair = tokio::sync::mpsc::channel(1024);
        self.socket_notifier
            .send(Socket::Udp(socket, read_pair.0, write_pair.1))
            .await
            .expect("wireguard socket manager should be alive");
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
            tcp::SocketBuffer::new(vec![0; 65535]),
            tcp::SocketBuffer::new(vec![0; 65535]),
        )
    }

    fn new_client_datagram() -> udp::Socket<'static> {
        let rx_meta = vec![udp::PacketMetadata::EMPTY; 10];
        let tx_meta = vec![udp::PacketMetadata::EMPTY; 10];
        let rx_data = vec![0u8; MAX_PACKET];
        let tx_data = vec![0u8; MAX_PACKET];
        let rx_buffer = udp::PacketBuffer::new(rx_meta, rx_data);
        let tx_buffer = udp::PacketBuffer::new(tx_meta, tx_data);
        udp::Socket::new(rx_buffer, tx_buffer)
    }
}

pub struct VirtualIpDevice {
    mtu: usize,
    packet_sender: Sender<Bytes>,
    packet_receiver: Receiver<(PortProtocol, Bytes)>,
}

impl VirtualIpDevice {
    pub fn new(
        packet_sender: Sender<Bytes>,
        mut packet_receiver: Receiver<(PortProtocol, Bytes)>,
        packet_notifier: Sender<()>,
        mtu: usize,
    ) -> Self {
        let (inner_packet_sender, inner_packet_receiver) =
            tokio::sync::mpsc::channel(1024);
        tokio::spawn(async move {
            loop {
                let span = trace_span!("receive_packet");
                match packet_receiver.recv().instrument(span).await {
                    Some((protocol, data)) => {
                        if inner_packet_sender.send((protocol, data)).await.is_err()
                        {
                            break;
                        }
                        let _ = packet_notifier.try_send(());
                    }
                    None => break,
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
        let (_protocol, data) = self.packet_receiver.try_recv().ok()?;
        let mut buffer = BytesMut::from(&data[..]);

        use smoltcp::wire::*;
        if let Ok(IpVersion::Ipv4) = IpVersion::of_packet(&buffer)
            && let Ok(ipv4) = Ipv4Packet::new_checked(&buffer[..])
            && ipv4.next_header() == IpProtocol::Udp
        {
            let src_addr = ipv4.src_addr();
            let dst_addr = ipv4.dst_addr();
            let ip_header_len = ipv4.header_len() as usize;
            if let Ok(mut udp) = UdpPacket::new_checked(&mut buffer[ip_header_len..])
            {
                udp.fill_checksum(
                    &IpAddress::Ipv4(src_addr),
                    &IpAddress::Ipv4(dst_addr),
                );
            }
        }

        Some((
            RxToken { buffer },
            TxToken {
                sender: self.packet_sender.clone(),
            },
        ))
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
        let mut capabilities = smoltcp::phy::DeviceCapabilities::default();
        capabilities.medium = smoltcp::phy::Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities
    }
}

pub struct RxToken {
    buffer: BytesMut,
}

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
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
        if let Err(error) = self.sender.try_send(buffer.into()) {
            error!("failed to send packet: {error}");
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc};

    use bytes::Bytes;
    use smoltcp::phy::{Device, Medium, RxToken as _, TxToken as _};

    use super::*;
    use crate::proxy::utils::test_utils::noop::NoopResolver;

    fn device_manager() -> DeviceManager {
        let (_packet_tx, packet_rx) = tokio::sync::mpsc::channel(4);
        DeviceManager::new(
            Ipv4Addr::new(10, 0, 0, 2),
            None,
            Arc::new(NoopResolver),
            vec![],
            packet_rx,
        )
    }

    #[tokio::test]
    async fn wireguard_device_manager_creates_virtual_tcp_and_udp_sockets() {
        let manager = device_manager();
        let remote: SocketAddr = "203.0.113.5:443".parse().unwrap();

        let _tcp = manager.new_tcp_socket(remote).await;
        let tcp_event = manager
            .socket_notifier_receiver
            .lock()
            .await
            .recv()
            .await
            .unwrap();
        assert!(matches!(tcp_event, Socket::Tcp(_, addr, _, _) if addr == remote));

        let _udp = manager.new_udp_socket().await;
        let udp_event = manager
            .socket_notifier_receiver
            .lock()
            .await
            .recv()
            .await
            .unwrap();
        assert!(matches!(udp_event, Socket::Udp(_, _, _)));
    }

    #[tokio::test]
    async fn wireguard_virtual_device_tokens_use_memory_channels() {
        let (to_tunnel_tx, mut to_tunnel_rx) = tokio::sync::mpsc::channel(4);
        let (from_tunnel_tx, from_tunnel_rx) = tokio::sync::mpsc::channel(4);
        let (notifier_tx, mut notifier_rx) = tokio::sync::mpsc::channel(4);
        let mut device =
            VirtualIpDevice::new(to_tunnel_tx, from_tunnel_rx, notifier_tx, 1380);

        from_tunnel_tx
            .send((PortProtocol::Tcp, Bytes::from_static(b"input")))
            .await
            .unwrap();
        notifier_rx.recv().await.unwrap();

        let (rx, tx) = device
            .receive(smoltcp::time::Instant::from_millis(0))
            .expect("packet should be available");
        let received = rx.consume(|data| data.to_vec());
        assert_eq!(received, b"input");

        tx.consume(3, |buffer| buffer.copy_from_slice(b"out"));
        assert_eq!(
            to_tunnel_rx.recv().await.unwrap(),
            Bytes::from_static(b"out")
        );
    }

    #[tokio::test]
    async fn wireguard_virtual_device_reports_reference_capabilities() {
        let (to_tunnel_tx, _to_tunnel_rx) = tokio::sync::mpsc::channel(1);
        let (_from_tunnel_tx, from_tunnel_rx) = tokio::sync::mpsc::channel(1);
        let (notifier_tx, _notifier_rx) = tokio::sync::mpsc::channel(1);
        let device =
            VirtualIpDevice::new(to_tunnel_tx, from_tunnel_rx, notifier_tx, 1420);
        let capabilities = device.capabilities();
        assert_eq!(capabilities.medium, Medium::Ip);
        assert_eq!(capabilities.max_transmission_unit, 1420);
    }
}
