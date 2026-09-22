use std::{
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_recursion::async_recursion;
use boringtun::{
    noise::{Tunn, TunnResult, errors::WireGuardError},
    x25519::{PublicKey, StaticSecret},
};

use bytes::Bytes;
use futures::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use ipnet::IpNet;
use smoltcp::wire::{IpProtocol, IpVersion, Ipv4Packet, Ipv6Packet};
use tokio::sync::{
    Mutex,
    mpsc::{Receiver, Sender},
};
use tracing::{Instrument, enabled, error, trace, trace_span, warn};

use crate::{
    Error,
    app::dns::ThreadSafeDNSResolver,
    proxy::{
        AnyOutboundDatagram,
        datagram::UdpPacket,
        utils::{GLOBAL_DIRECT_CONNECTOR, RemoteConnector},
    },
    session::{Session, SocksAddr},
};

use super::events::PortProtocol;

pub struct WireguardTunnel {
    pub(crate) source_peer_ip: Ipv4Addr,
    pub(crate) source_peer_ipv6: Option<Ipv6Addr>,
    peer: Arc<Mutex<Tunn>>,
    pub(crate) endpoint: SocketAddr,
    allowed_ips: Vec<IpNet>,
    reserved_bits: [u8; 3],

    // UDP socket to the remote WireGuard endpoint
    tx: tokio::sync::Mutex<SplitSink<AnyOutboundDatagram, UdpPacket>>,
    rx: tokio::sync::Mutex<SplitStream<AnyOutboundDatagram>>,

    // send side packet going out of the tunnel
    packet_writer: Sender<(PortProtocol, Bytes)>,
    // receive side packet coming into the tunnel
    packet_reader: Arc<Mutex<Receiver<Bytes>>>,
}

impl Debug for WireguardTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireguardTunnel")
            .field("source_peer_ip", &self.source_peer_ip)
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

pub struct Config {
    pub private_key: StaticSecret,
    pub endpoint_public_key: PublicKey,
    pub pre_shared_key: Option<StaticSecret>,
    pub remote_endpoint: SocketAddr,
    pub source_peer_ip: Ipv4Addr,
    pub source_peer_ipv6: Option<Ipv6Addr>,
    pub keepalive_seconds: Option<u16>,
    pub allowed_ips: Vec<IpNet>,
    pub reserved_bits: [u8; 3],
}

impl WireguardTunnel {
    pub async fn new(
        config: Config,
        packet_writer: Sender<(PortProtocol, Bytes)>,
        packet_reader: Receiver<Bytes>,
        resolver: ThreadSafeDNSResolver,
        connector: Option<Arc<dyn RemoteConnector>>,
        sess: &Session,
    ) -> Result<Self, Error> {
        let peer = Tunn::new(
            config.private_key,
            config.endpoint_public_key,
            config.pre_shared_key.map(|x| x.to_bytes()),
            config.keepalive_seconds,
            0,
            None,
        );

        let remote_endpoint = config.remote_endpoint;

        let connector = connector.unwrap_or(GLOBAL_DIRECT_CONNECTOR.clone());
        let udp = connector
            .connect_datagram(
                resolver,
                None,
                remote_endpoint.into(),
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;

        let (tx, rx) = udp.split();

        Ok(Self {
            source_peer_ip: config.source_peer_ip,
            source_peer_ipv6: config.source_peer_ipv6,
            peer: Arc::new(Mutex::new(peer)),
            endpoint: remote_endpoint,
            allowed_ips: config.allowed_ips,
            reserved_bits: config.reserved_bits,

            tx: tokio::sync::Mutex::new(tx),
            rx: tokio::sync::Mutex::new(rx),

            packet_writer,
            packet_reader: Arc::new(Mutex::new(packet_reader)),
        })
    }

    async fn udp_send(&self, packet: &mut [u8]) -> Result<(), std::io::Error> {
        if packet.len() > 3 {
            packet[1] = self.reserved_bits[0];
            packet[2] = self.reserved_bits[1];
            packet[3] = self.reserved_bits[2];
        }
        self.tx
            .lock()
            .await
            .send(UdpPacket {
                data: packet.to_vec(),
                src_addr: SocksAddr::any_ipv4(),
                dst_addr: self.endpoint.into(),
                inbound_user: None,
            })
            .await
    }

    pub async fn send_ip_packet(&self, packet: &[u8]) -> Result<(), Error> {
        trace_ip_packet("Sending IP packet", packet);

        if let Some(destination) = Self::packet_destination(packet)
            && !Self::ip_allowed(&self.allowed_ips, destination)
        {
            trace!(
                destination = %destination,
                "dropping outbound WireGuard packet outside allowed-ips"
            );
            return Ok(());
        }

        let mut send_buf = vec![0u8; 65535];
        let mut peer = self.peer.lock().await;
        match peer.encapsulate(packet, &mut send_buf) {
            boringtun::noise::TunnResult::Done => {}
            boringtun::noise::TunnResult::Err(e) => {
                error!("failed to encapsulate packet: {e:?}");
            }
            boringtun::noise::TunnResult::WriteToNetwork(packet) => {
                self.udp_send(packet).await?;
            }
            _ => {
                error!("unexpected result from encapsulate");
            }
        }
        Ok(())
    }

    pub async fn start_polling(&self) {
        tokio::select! {
            _ = self.start_forwarding() => {
                trace!("forwarding stopped")
            }
            _ = self.start_heartbeat() => {
                trace!("heartbeat stopped")
            }
            _ = self.start_receiving() => {
                trace!("receiving stopped")
            }
        }
    }

    pub async fn start_forwarding(&self) {
        let mut packet_reader = self.packet_reader.lock().await;
        loop {
            match packet_reader.recv().await {
                Some(packet) => {
                    if let Err(e) = self.send_ip_packet(&packet).await {
                        error!("failed to send packet: {}", e);
                    }
                }
                None => {
                    trace!("no active connection, stopping");
                    break;
                }
            }
        }
    }

    pub async fn start_heartbeat(&self) {
        let mut send_buf = vec![0u8; 65535];

        loop {
            let mut peer = self.peer.lock().await;
            let tun_result = peer.update_timers(&mut send_buf);
            drop(peer);

            self.handle_routine_result(tun_result).await;
        }
    }

    #[tracing::instrument]
    pub async fn start_receiving(&self) {
        let mut send_buf = vec![0u8; 65535];

        loop {
            let mut item = match self
                .rx
                .lock()
                .await
                .next()
                .instrument(trace_span!(
                    "wg_receive",
                    endpoint = %self.endpoint,
                ))
                .await
            {
                Some(item) => item,
                None => {
                    trace!("wireguard receive stream closed");
                    break;
                }
            };

            let mut peer = self.peer.lock().await;
            let data = &mut item.data;
            if data.len() > 3 {
                data[1] = 0;
                data[2] = 0;
                data[3] = 0;
            }

            let _ = trace_span!("wg_decapsulate", endpoint = %self.endpoint, size = data.len())
                .entered();

            match peer.decapsulate(None, data, &mut send_buf) {
                TunnResult::Done => {}
                TunnResult::Err(e) => {
                    error!("failed to decapsulate packet: {e:?}");
                    continue;
                }
                TunnResult::WriteToNetwork(packet) => {
                    let size = packet.len();
                    match self
                        .udp_send(packet)
                        .instrument(trace_span!(
                            "wg_send",
                            endpoint = %self.endpoint,
                            size = size,
                        ))
                        .await
                    {
                        Ok(_) => {}
                        Err(e) => {
                            error!("failed to send packet: {}", e);
                            continue;
                        }
                    }

                    let mut send_buf = vec![0u8; 65535];
                    while let TunnResult::WriteToNetwork(packet) =
                        peer.decapsulate(None, &[], &mut send_buf)
                    {
                        match self.udp_send(packet).await {
                            Ok(_) => {}
                            Err(e) => {
                                error!(
                                    "Failed to send decapsulation-instructed \
                                     packet to WireGuard endpoint: {:?}",
                                    e
                                );
                                break;
                            }
                        };
                    }
                }

                TunnResult::WriteToTunnelV4(packet, addr) => {
                    trace_ip_packet("Received IP packet", packet);

                    if !self.is_ip_allowed(addr.into()) {
                        trace!(
                            "received packet from {} which is not in allowed_ips",
                            addr.to_string()
                        );
                        continue;
                    }

                    let _ =
                        trace_span!("wg_write_stack", endpoint = %self.endpoint, size = packet.len())
                            .entered();

                    if let Some(proto) = self.route_protocol(packet) {
                        if let Err(e) = self
                            .packet_writer
                            .send((proto, packet.to_owned().into())) // TODO: avoid copy
                            .await
                        {
                            error!("failed to send packet to virtual device: {}", e);
                        }
                    } else {
                        warn!("wg stack received unknown data");
                    }
                }
                TunnResult::WriteToTunnelV6(packet, addr) => {
                    trace_ip_packet("Received IP packet", packet);

                    if !self.is_ip_allowed(addr.into()) {
                        trace!(
                            "received packet from {} which is not in allowed_ips",
                            addr.to_string()
                        );
                        continue;
                    }

                    let _ =
                        trace_span!("wg_write_stack", endpoint = %self.endpoint, size = packet.len())
                            .entered();
                    if let Some(proto) = self.route_protocol(packet) {
                        if let Err(e) = self
                            .packet_writer
                            .send((proto, packet.to_owned().into())) // TODO: avoid copy
                            .await
                        {
                            error!("failed to send packet to virtual device: {}", e);
                        }
                    } else {
                        warn!("wg stack received unknown data");
                    }
                }
            }
        }
    }

    #[async_recursion]
    async fn handle_routine_result<'a: 'async_recursion>(
        &self,
        result: TunnResult<'a>,
    ) {
        match result {
            TunnResult::Done => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                warn!("wireguard connection expired");
                let mut buf = vec![0u8; 65535];
                let mut peer = self.peer.lock().await;
                let tun_result =
                    peer.format_handshake_initiation(&mut buf[..], false);
                drop(peer);

                self.handle_routine_result(tun_result).await;
            }
            TunnResult::Err(e) => {
                error!("wireguard error: {e:?}");
            }
            TunnResult::WriteToNetwork(packet) => {
                match self.udp_send(packet).await {
                    Ok(_) => {}
                    Err(e) => {
                        error!("failed to send packet: {}", e);
                    }
                }
            }
            _ => {
                error!("unexpected result from wireguard");
            }
        }
    }

    /// Determine the inner protocol of the incoming IP packet (TCP/UDP).
    #[tracing::instrument(skip(self, packet))]
    fn route_protocol(&self, packet: &[u8]) -> Option<PortProtocol> {
        match IpVersion::of_packet(packet) {
            Ok(IpVersion::Ipv4) => Ipv4Packet::new_checked(&packet)
                .ok()
                .filter(|packet| packet.dst_addr() == self.source_peer_ip)
                .and_then(|packet| {
                    match packet.next_header() {
                        IpProtocol::Tcp => Some(PortProtocol::Tcp),
                        IpProtocol::Udp => Some(PortProtocol::Udp),
                        // Unrecognized protocol, so we cannot determine where
                        // to route
                        _ => None,
                    }
                }),
            Ok(IpVersion::Ipv6) => Ipv6Packet::new_checked(&packet)
                .ok()
                .filter(|packet| Some(packet.dst_addr()) == self.source_peer_ipv6)
                .and_then(|packet| {
                    match packet.next_header() {
                        IpProtocol::Tcp => Some(PortProtocol::Tcp),
                        IpProtocol::Udp => Some(PortProtocol::Udp),
                        // Unrecognized protocol, so we cannot determine where
                        // to route
                        _ => None,
                    }
                }),
            _ => None,
        }
    }

    fn packet_destination(packet: &[u8]) -> Option<IpAddr> {
        match IpVersion::of_packet(packet).ok()? {
            IpVersion::Ipv4 => Ipv4Packet::new_checked(packet)
                .ok()
                .map(|packet| IpAddr::V4(packet.dst_addr())),
            IpVersion::Ipv6 => Ipv6Packet::new_checked(packet)
                .ok()
                .map(|packet| IpAddr::V6(packet.dst_addr())),
        }
    }

    fn ip_allowed(allowed_ips: &[IpNet], ip: IpAddr) -> bool {
        allowed_ips.is_empty() || allowed_ips.iter().any(|net| net.contains(&ip))
    }

    fn is_ip_allowed(&self, ip: IpAddr) -> bool {
        trace!("checking if {} is allowed in {:?}", ip, self.allowed_ips);
        Self::ip_allowed(&self.allowed_ips, ip)
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use std::{
        io,
        pin::Pin,
        sync::{Arc, Mutex as StdMutex},
        task::{Context, Poll},
    };

    use async_trait::async_trait;
    use futures::{Sink, Stream};

    use crate::{
        app::dns::{MockClashResolver, ThreadSafeDNSResolver},
        app::net::OutboundInterface,
        proxy::{AnyOutboundDatagram, AnyStream},
        session::SocksAddr,
    };

    #[derive(Debug)]
    struct RecordingConnector {
        packets: Arc<StdMutex<Vec<UdpPacket>>>,
    }

    struct RecordingDatagram {
        packets: Arc<StdMutex<Vec<UdpPacket>>>,
    }

    impl Stream for RecordingDatagram {
        type Item = UdpPacket;

        fn poll_next(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }
    }

    impl Sink<UdpPacket> for RecordingDatagram {
        type Error = io::Error;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(
            self: Pin<&mut Self>,
            item: UdpPacket,
        ) -> Result<(), Self::Error> {
            self.get_mut().packets.lock().unwrap().push(item);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[async_trait]
    impl RemoteConnector for RecordingConnector {
        async fn connect_stream(
            &self,
            _resolver: ThreadSafeDNSResolver,
            _address: &str,
            _port: u16,
            _iface: Option<&OutboundInterface>,
            #[cfg(target_os = "linux")] _packet_mark: Option<u32>,
        ) -> io::Result<AnyStream> {
            Err(io::Error::other("unexpected stream dial"))
        }

        async fn connect_datagram(
            &self,
            _resolver: ThreadSafeDNSResolver,
            _src: Option<SocketAddr>,
            _destination: SocksAddr,
            _iface: Option<&OutboundInterface>,
            #[cfg(target_os = "linux")] _packet_mark: Option<u32>,
        ) -> io::Result<AnyOutboundDatagram> {
            Ok(Box::new(RecordingDatagram {
                packets: self.packets.clone(),
            }))
        }
    }

    fn ipv4_packet(destination: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(20u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    fn ipv6_packet(destination: [u8; 16]) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet[6] = 6;
        packet[7] = 64;
        packet[8..24]
            .copy_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        packet[24..40].copy_from_slice(&destination);
        packet
    }

    #[tokio::test]
    async fn reserved_bytes_are_written_to_outer_handshake_packet() {
        let packets = Arc::new(StdMutex::new(Vec::new()));
        let connector = Arc::new(RecordingConnector {
            packets: packets.clone(),
        });
        let (_to_stack_tx, _to_stack_rx) = tokio::sync::mpsc::channel(4);
        let (_from_stack_tx, from_stack_rx) = tokio::sync::mpsc::channel(4);
        let private_key = StaticSecret::from([7u8; 32]);
        let peer_secret = StaticSecret::from([9u8; 32]);
        let peer_public = PublicKey::from(&peer_secret);

        let tunnel = WireguardTunnel::new(
            Config {
                private_key,
                endpoint_public_key: peer_public,
                pre_shared_key: None,
                remote_endpoint: "198.51.100.10:51820".parse().unwrap(),
                source_peer_ip: Ipv4Addr::new(10, 0, 0, 2),
                source_peer_ipv6: None,
                keepalive_seconds: None,
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                reserved_bits: [209, 98, 59],
            },
            _to_stack_tx,
            from_stack_rx,
            Arc::new(MockClashResolver::new()),
            Some(connector),
            &Session::default(),
        )
        .await
        .unwrap();

        tunnel
            .send_ip_packet(&ipv4_packet([203, 0, 113, 9]))
            .await
            .unwrap();

        let packets = packets.lock().unwrap();
        assert_eq!(packets.len(), 1);
        assert!(packets[0].data.len() > 4);
        assert_eq!(
            packets[0].data[0], 1,
            "first packet should be a handshake initiation"
        );
        assert_eq!(&packets[0].data[1..4], &[209, 98, 59]);
    }

    #[tokio::test]
    async fn persistent_keepalive_reaches_boringtun_peer() {
        let packets = Arc::new(StdMutex::new(Vec::new()));
        let connector = Arc::new(RecordingConnector { packets });
        let (_to_stack_tx, _to_stack_rx) = tokio::sync::mpsc::channel(4);
        let (_from_stack_tx, from_stack_rx) = tokio::sync::mpsc::channel(4);
        let private_key = StaticSecret::from([7u8; 32]);
        let peer_secret = StaticSecret::from([9u8; 32]);
        let peer_public = PublicKey::from(&peer_secret);

        let tunnel = WireguardTunnel::new(
            Config {
                private_key,
                endpoint_public_key: peer_public,
                pre_shared_key: None,
                remote_endpoint: "198.51.100.10:51820".parse().unwrap(),
                source_peer_ip: Ipv4Addr::new(10, 0, 0, 2),
                source_peer_ipv6: None,
                keepalive_seconds: Some(25),
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                reserved_bits: [0, 0, 0],
            },
            _to_stack_tx,
            from_stack_rx,
            Arc::new(MockClashResolver::new()),
            Some(connector),
            &Session::default(),
        )
        .await
        .unwrap();

        assert_eq!(tunnel.peer.lock().await.persistent_keepalive(), Some(25));
    }

    #[tokio::test]
    async fn configured_ipv6_routes_tcp_packets_to_stack() {
        let packets = Arc::new(StdMutex::new(Vec::new()));
        let connector = Arc::new(RecordingConnector { packets });
        let (_to_stack_tx, _to_stack_rx) = tokio::sync::mpsc::channel(4);
        let (_from_stack_tx, from_stack_rx) = tokio::sync::mpsc::channel(4);
        let private_key = StaticSecret::from([7u8; 32]);
        let peer_secret = StaticSecret::from([9u8; 32]);
        let peer_public = PublicKey::from(&peer_secret);
        let local_ipv6: Ipv6Addr = "fd00::2".parse().unwrap();

        let tunnel = WireguardTunnel::new(
            Config {
                private_key,
                endpoint_public_key: peer_public,
                pre_shared_key: None,
                remote_endpoint: "198.51.100.10:51820".parse().unwrap(),
                source_peer_ip: Ipv4Addr::new(10, 0, 0, 2),
                source_peer_ipv6: Some(local_ipv6),
                keepalive_seconds: None,
                allowed_ips: vec!["::/0".parse().unwrap()],
                reserved_bits: [0, 0, 0],
            },
            _to_stack_tx,
            from_stack_rx,
            Arc::new(MockClashResolver::new()),
            Some(connector),
            &Session::default(),
        )
        .await
        .unwrap();

        assert_eq!(
            tunnel.route_protocol(&ipv6_packet(local_ipv6.octets())),
            Some(PortProtocol::Tcp)
        );
        assert_eq!(
            tunnel.route_protocol(&ipv6_packet(
                "fd00::3".parse::<Ipv6Addr>().unwrap().octets()
            )),
            None
        );
    }

    #[test]
    fn packet_destination_reads_ipv4_and_ipv6() {
        let v4 = ipv4_packet([203, 0, 113, 9]);
        assert_eq!(
            WireguardTunnel::packet_destination(&v4),
            Some("203.0.113.9".parse().unwrap())
        );

        let v6_destination =
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
        let v6 = ipv6_packet(v6_destination);
        assert_eq!(
            WireguardTunnel::packet_destination(&v6),
            Some("2001:db8::9".parse().unwrap())
        );
    }

    #[test]
    fn allowed_ips_filter_outbound_destinations() {
        let allowed = vec![
            "203.0.113.0/24".parse::<IpNet>().unwrap(),
            "2001:db8::/32".parse::<IpNet>().unwrap(),
        ];

        assert!(WireguardTunnel::ip_allowed(
            &allowed,
            "203.0.113.9".parse().unwrap()
        ));
        assert!(!WireguardTunnel::ip_allowed(
            &allowed,
            "198.51.100.9".parse().unwrap()
        ));
        assert!(WireguardTunnel::ip_allowed(
            &allowed,
            "2001:db8::9".parse().unwrap()
        ));
        assert!(!WireguardTunnel::ip_allowed(
            &allowed,
            "2001:db9::9".parse().unwrap()
        ));
        assert!(WireguardTunnel::ip_allowed(
            &[],
            "198.51.100.9".parse().unwrap()
        ));
    }
}

fn trace_ip_packet(message: &str, packet: &[u8]) {
    if enabled!(tracing::Level::TRACE) {
        use smoltcp::wire::*;

        match IpVersion::of_packet(packet) {
            Ok(IpVersion::Ipv4) => trace!(
                "{}: {}",
                message,
                PrettyPrinter::<Ipv4Packet<&mut [u8]>>::new("", &packet)
            ),
            Ok(IpVersion::Ipv6) => trace!(
                "{}: {}",
                message,
                PrettyPrinter::<Ipv6Packet<&mut [u8]>>::new("", &packet)
            ),
            _ => {}
        }
    }
}
