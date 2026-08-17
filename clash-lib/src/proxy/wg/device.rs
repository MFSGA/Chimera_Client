use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use rand::seq::IndexedRandom;
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::Device,
    socket::{
        tcp::{self, RecvError},
        udp,
    },
    time::Instant,
    wire::IpCidr,
};
use tokio::sync::{
    Mutex,
    mpsc::{Receiver, Sender},
};
use tracing::{Instrument, debug, error, trace, trace_span, warn};

use crate::{
    app::dns::ThreadSafeDNSResolver, proxy::datagram::UdpPacket, session::SocksAddr,
};

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

enum Transfer {
    Tcp(SocketHandle, Bytes, bool),
    Udp(SocketHandle, UdpPacket, bool),
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

    pub async fn look_up_dns(
        &self,
        host: &str,
        server: SocketAddr,
    ) -> Option<IpAddr> {
        debug!("looking up {host} on {server}");

        #[async_recursion::async_recursion]
        async fn query(
            record_type: hickory_proto::rr::RecordType,
            host: &str,
            server: SocketAddr,
            mut socket: UdpPair,
        ) -> Option<IpAddr> {
            let mut message = hickory_proto::op::Message::new(
                0,
                hickory_proto::op::MessageType::Query,
                hickory_proto::op::OpCode::Query,
            );
            message.add_query({
                let mut query = hickory_proto::op::Query::new();
                let name = hickory_proto::rr::Name::from_str_relaxed(host)
                    .ok()?
                    .append_domain(&hickory_proto::rr::Name::root())
                    .ok()?;
                query.set_name(name);
                query.set_query_type(record_type);
                query
            });
            message.metadata.recursion_desired = true;

            socket
                .feed(UdpPacket::new(
                    message.to_vec().ok()?,
                    SocksAddr::any_ipv4(),
                    server.into(),
                ))
                .await
                .ok()?;
            socket.flush().await.ok()?;
            trace!("sent dns query: {message:?}");

            let packet =
                match tokio::time::timeout(Duration::from_secs(5), socket.next())
                    .await
                {
                    Ok(Some(packet)) => packet,
                    _ => {
                        warn!("wg dns query timed out with server {server}");
                        return None;
                    }
                };

            let response =
                hickory_proto::op::Message::from_vec(&packet.data).ok()?;
            trace!("got dns response: {response:?}");
            for answer in &response.answers {
                if answer.record_type() != record_type {
                    continue;
                }
                match (record_type, &answer.data) {
                    (_, hickory_proto::rr::RData::CNAME(cname)) => {
                        return query(
                            record_type,
                            &cname.0.to_ascii(),
                            server,
                            socket,
                        )
                        .await;
                    }
                    (
                        hickory_proto::rr::RecordType::A,
                        hickory_proto::rr::RData::A(addr),
                    ) => return Some(IpAddr::V4(addr.0)),
                    (
                        hickory_proto::rr::RecordType::AAAA,
                        hickory_proto::rr::RData::AAAA(addr),
                    ) => return Some(IpAddr::V6(addr.0)),
                    _ => return None,
                }
            }
            None
        }

        let socket = self.new_udp_socket().await;
        let v4_query = query(hickory_proto::rr::RecordType::A, host, server, socket);
        if self.addr_v6.is_some() {
            let socket = self.new_udp_socket().await;
            let v6_query =
                query(hickory_proto::rr::RecordType::AAAA, host, server, socket);
            match tokio::time::timeout(
                Duration::from_secs(5),
                futures::future::join(v4_query, v6_query),
            )
            .await
            {
                Ok((_, Some(v6))) => Some(v6),
                Ok((v4, _)) => v4,
                _ => None,
            }
        } else {
            tokio::time::timeout(Duration::from_secs(5), v4_query)
                .await
                .ok()?
        }
    }

    pub async fn poll_sockets(&self, mut device: VirtualIpDevice) {
        let mut config = Config::new(smoltcp::wire::HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut iface = Interface::new(config, &mut device, Instant::now());
        iface.update_ip_addrs(|addrs| {
            addrs.push(IpCidr::new(self.addr.into(), 32)).unwrap();
            if let Some(addr_v6) = self.addr_v6 {
                addrs.push(IpCidr::new(addr_v6.into(), 128)).unwrap();
            }
        });

        let (device_sender, mut device_receiver) = tokio::sync::mpsc::channel(1024);
        let mut tcp_queue: HashMap<SocketHandle, VecDeque<(Bytes, bool)>> =
            HashMap::new();
        let mut udp_queue: HashMap<SocketHandle, VecDeque<(UdpPacket, bool)>> =
            HashMap::new();
        let mut next_poll = None;

        loop {
            let mut sockets = self.socket_set.lock().await;
            let mut socket_pairs = self.socket_pairs.lock().await;
            let mut packet_notifier = self.packet_notifier.lock().await;
            let mut socket_notifier_receiver =
                self.socket_notifier_receiver.lock().await;

            tokio::select! {
                Some(socket) = socket_notifier_receiver.recv() => {
                    match socket {
                        Socket::Tcp(mut socket, remote, sender, mut receiver) => {
                            socket
                                .connect(
                                    iface.context(),
                                    remote,
                                    (
                                        match remote {
                                            SocketAddr::V4(_) => IpAddr::V4(self.addr),
                                            SocketAddr::V6(_) => IpAddr::V6(
                                                self.addr_v6.expect("ipv6 wireguard address required"),
                                            ),
                                        },
                                        self.get_ephemeral_tcp_port().await,
                                    ),
                                )
                                .unwrap();
                            let handle = sockets.add(socket);
                            let device_sender = device_sender.clone();
                            tokio::spawn(async move {
                                while let Some(data) = receiver.recv().await {
                                    if device_sender
                                        .send(Transfer::Tcp(handle, data, true))
                                        .await
                                        .is_err()
                                    {
                                        return;
                                    }
                                }
                                let _ = device_sender
                                    .send(Transfer::Tcp(handle, Bytes::new(), false))
                                    .await;
                            });
                            socket_pairs.insert(handle, SenderType::Tcp(sender));
                            tcp_queue.insert(handle, VecDeque::new());
                        }
                        Socket::Udp(socket, sender, mut receiver) => {
                            let handle = sockets.add(socket);
                            let device_sender = device_sender.clone();
                            tokio::spawn(async move {
                                while let Some(packet) = receiver.recv().await {
                                    if device_sender
                                        .send(Transfer::Udp(handle, packet, true))
                                        .await
                                        .is_err()
                                    {
                                        return;
                                    }
                                }
                                let _ = device_sender
                                    .send(Transfer::Udp(
                                        handle,
                                        UdpPacket::default(),
                                        false,
                                    ))
                                    .await;
                            });
                            socket_pairs.insert(handle, SenderType::Udp(sender));
                            udp_queue.insert(handle, VecDeque::new());
                        }
                    }
                    next_poll = None;
                }
                _ = packet_notifier.recv() => {
                    next_poll = None;
                }
                Some(transfer) = device_receiver.recv() => {
                    match transfer {
                        Transfer::Tcp(handle, data, active) => {
                            if let Some(queue) = tcp_queue.get_mut(&handle) {
                                queue.push_back((data, active));
                                next_poll = None;
                            }
                        }
                        Transfer::Udp(handle, packet, active) => {
                            if let Some(queue) = udp_queue.get_mut(&handle) {
                                queue.push_back((packet, active));
                                next_poll = None;
                            }
                        }
                    }
                }
                _ = match (next_poll, socket_pairs.len()) {
                    (None, 0) => tokio::time::sleep(Duration::MAX),
                    (None, _) => tokio::time::sleep(Duration::ZERO),
                    (Some(duration), _) => tokio::time::sleep(duration),
                } => {
                    let timestamp = Instant::now();
                    iface.poll(timestamp, &mut device, &mut sockets);

                    for (handle, sender) in socket_pairs.iter_mut() {
                        match sender {
                            SenderType::Tcp(sender) => {
                                let socket = sockets.get_mut::<tcp::Socket>(*handle);
                                if socket.may_recv() {
                                    match socket.recv(|data| (data.len(), data.to_owned())) {
                                        Ok(data) if !data.is_empty() => {
                                            if sender.try_send(data.into()).is_err() {
                                                socket.abort();
                                            }
                                        }
                                        Ok(_) => {}
                                        Err(RecvError::Finished) => continue,
                                        Err(error) => warn!(
                                            "failed to receive wireguard tcp packet: {error:?}"
                                        ),
                                    }
                                }

                                if socket.may_send()
                                    && let Some(queue) = tcp_queue.get_mut(handle)
                                    && let Some((data, active)) = queue.pop_front()
                                {
                                    if !active {
                                        socket.abort();
                                    } else {
                                        let total = data.len();
                                        match socket.send_slice(&data) {
                                            Ok(sent) if sent < total => {
                                                queue.push_front((
                                                    Bytes::copy_from_slice(&data[sent..]),
                                                    true,
                                                ));
                                            }
                                            Ok(_) => {}
                                            Err(error) => error!(
                                                "failed to send virtual tcp data: {error:?}"
                                            ),
                                        }
                                    }
                                }
                            }
                            SenderType::Udp(sender) => {
                                let socket = sockets.get_mut::<udp::Socket>(*handle);
                                if socket.can_recv() {
                                    match socket.recv() {
                                        Ok((data, metadata)) if !data.is_empty() => {
                                            let packet = UdpPacket::new(
                                                data.into(),
                                                SocksAddr::Ip(SocketAddr::new(
                                                    metadata.endpoint.addr.into(),
                                                    metadata.endpoint.port,
                                                )),
                                                SocksAddr::any_ipv4(),
                                            );
                                            if sender.try_send(packet).is_err() {
                                                socket.close();
                                            }
                                        }
                                        Ok(_) | Err(udp::RecvError::Exhausted) => {}
                                        Err(udp::RecvError::Truncated) => {
                                            error!("wireguard udp packet truncated");
                                            socket.close();
                                        }
                                    }
                                }

                                if socket.can_send()
                                    && let Some(queue) = udp_queue.get_mut(handle)
                                    && let Some((packet, active)) = queue.pop_front()
                                {
                                    if !active {
                                        socket.close();
                                    } else {
                                        let ip = match &packet.dst_addr {
                                            SocksAddr::Ip(addr) => addr.ip(),
                                            SocksAddr::Domain(domain, _) => {
                                                if let Ok(ip) = domain.parse::<IpAddr>() {
                                                    ip
                                                } else if let Some(server) = {
                                                    let mut rng = rand::rng();
                                                    self.dns_servers
                                                        .choose(&mut rng)
                                                        .copied()
                                                } {
                                                    match self.look_up_dns(domain, server).await {
                                                        Some(ip) => ip,
                                                        None => continue,
                                                    }
                                                } else {
                                                    match self.resolver.resolve(domain, false).await {
                                                        Ok(Some(ip)) => ip,
                                                        _ => continue,
                                                    }
                                                }
                                            }
                                        };

                                        if !socket.is_open() {
                                            let local_addr: IpAddr = match ip {
                                                IpAddr::V4(_) => self.addr.into(),
                                                IpAddr::V6(_) => self
                                                    .addr_v6
                                                    .expect("ipv6 wireguard address required")
                                                    .into(),
                                            };
                                            socket
                                                .bind((
                                                    local_addr,
                                                    self.get_ephemeral_udp_port().await,
                                                ))
                                                .unwrap();
                                        }
                                        if let Err(error) = socket.send_slice(
                                            &packet.data,
                                            (ip, packet.dst_addr.port()),
                                        ) {
                                            error!(
                                                "failed to send virtual udp data: {error:?}"
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }

                    let mut tcp_ports = Vec::new();
                    let mut udp_ports = Vec::new();
                    socket_pairs.retain(|handle, sender_type| match sender_type {
                        SenderType::Tcp(_) => {
                            let socket = sockets.get::<tcp::Socket>(*handle);
                            if socket.is_active() {
                                true
                            } else {
                                if let Some(port) =
                                    socket.local_endpoint().map(|endpoint| endpoint.port)
                                {
                                    tcp_ports.push(port);
                                }
                                sockets.remove(*handle);
                                tcp_queue.remove(handle);
                                false
                            }
                        }
                        SenderType::Udp(_) => {
                            let socket = sockets.get::<udp::Socket>(*handle);
                            if socket.is_open() {
                                true
                            } else {
                                udp_ports.push(socket.endpoint().port);
                                sockets.remove(*handle);
                                udp_queue.remove(handle);
                                false
                            }
                        }
                    });

                    for port in tcp_ports {
                        self.release_ephemeral_tcp_port(port).await;
                    }
                    for port in udp_ports {
                        self.release_ephemeral_udp_port(port).await;
                    }

                    next_poll = match iface.poll_delay(timestamp, &sockets) {
                        Some(smoltcp::time::Duration::ZERO) => None,
                        Some(delay) => Some(delay.into()),
                        None => None,
                    };
                }
            }
        }
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
    async fn wireguard_dns_lookup_round_trips_over_virtual_udp() {
        let manager = Arc::new(device_manager());
        let server: SocketAddr = "192.0.2.53:53".parse().unwrap();
        let lookup_manager = manager.clone();
        let lookup = tokio::spawn(async move {
            lookup_manager.look_up_dns("example.com", server).await
        });

        let event = manager
            .socket_notifier_receiver
            .lock()
            .await
            .recv()
            .await
            .unwrap();
        let Socket::Udp(_socket, response_tx, mut query_rx) = event else {
            panic!("dns lookup should create virtual udp socket");
        };
        let query_packet = query_rx.recv().await.unwrap();
        let query =
            hickory_proto::op::Message::from_vec(&query_packet.data).unwrap();
        let name = query.queries[0].name().clone();

        let mut response = hickory_proto::op::Message::response(
            query.metadata.id,
            query.metadata.op_code,
        );
        response.add_query(query.queries[0].clone());
        response.add_answer(hickory_proto::rr::Record::from_rdata(
            name,
            60,
            hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(
                203, 0, 113, 8,
            ))),
        ));
        response_tx
            .send(UdpPacket::new(
                response.to_vec().unwrap(),
                server.into(),
                SocksAddr::any_ipv4(),
            ))
            .await
            .unwrap();

        assert_eq!(
            lookup.await.unwrap(),
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)))
        );
    }

    #[tokio::test]
    async fn wireguard_poll_sockets_registers_tcp_in_memory() {
        let (to_tunnel_tx, _to_tunnel_rx) = tokio::sync::mpsc::channel(8);
        let (_from_tunnel_tx, from_tunnel_rx) = tokio::sync::mpsc::channel(8);
        let (notifier_tx, notifier_rx) = tokio::sync::mpsc::channel(8);
        let device =
            VirtualIpDevice::new(to_tunnel_tx, from_tunnel_rx, notifier_tx, 1380);
        let manager = Arc::new(DeviceManager::new(
            Ipv4Addr::new(10, 0, 0, 2),
            None,
            Arc::new(NoopResolver),
            vec![],
            notifier_rx,
        ));
        let poll_manager = manager.clone();
        let poll =
            tokio::spawn(async move { poll_manager.poll_sockets(device).await });

        let _pair = manager
            .new_tcp_socket("203.0.113.5:443".parse().unwrap())
            .await;
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if !manager.socket_pairs.lock().await.is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("virtual tcp socket should be registered");
        assert_eq!(manager.socket_pairs.lock().await.len(), 1);

        poll.abort();
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
