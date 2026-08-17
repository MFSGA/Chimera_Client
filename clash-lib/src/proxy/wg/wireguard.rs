use std::{
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use boringtun::{
    noise::{Tunn, TunnResult},
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
use tracing::{enabled, error, trace};

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
    tx: tokio::sync::Mutex<SplitSink<AnyOutboundDatagram, UdpPacket>>,
    rx: tokio::sync::Mutex<SplitStream<AnyOutboundDatagram>>,
    packet_writer: Sender<(PortProtocol, Bytes)>,
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
            config.pre_shared_key.map(|key| key.to_bytes()),
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
        apply_reserved_bits(packet, self.reserved_bits);
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

        let mut send_buf = vec![0u8; 65535];
        let mut peer = self.peer.lock().await;
        match peer.encapsulate(packet, &mut send_buf) {
            TunnResult::Done => {}
            TunnResult::Err(error) => {
                error!("failed to encapsulate packet: {error:?}");
            }
            TunnResult::WriteToNetwork(packet) => {
                self.udp_send(packet).await?;
            }
            _ => {
                error!("unexpected result from encapsulate");
            }
        }
        Ok(())
    }

    pub async fn start_forwarding(&self) {
        let mut packet_reader = self.packet_reader.lock().await;
        loop {
            match packet_reader.recv().await {
                Some(packet) => {
                    if let Err(error) = self.send_ip_packet(&packet).await {
                        error!("failed to send packet: {error}");
                    }
                }
                None => {
                    trace!("no active connection, stopping");
                    break;
                }
            }
        }
    }
}

fn apply_reserved_bits(packet: &mut [u8], reserved_bits: [u8; 3]) {
    if packet.len() > 3 {
        packet[1] = reserved_bits[0];
        packet[2] = reserved_bits[1];
        packet[3] = reserved_bits[2];
    }
}

fn clear_reserved_bits(packet: &mut [u8]) {
    if packet.len() > 3 {
        packet[1..4].fill(0);
    }
}

pub(crate) fn route_protocol(
    packet: &[u8],
    source_peer_ip: Ipv4Addr,
    source_peer_ipv6: Option<Ipv6Addr>,
) -> Option<PortProtocol> {
    match IpVersion::of_packet(packet) {
        Ok(IpVersion::Ipv4) => Ipv4Packet::new_checked(packet)
            .ok()
            .filter(|packet| packet.dst_addr() == source_peer_ip)
            .and_then(|packet| match packet.next_header() {
                IpProtocol::Tcp => Some(PortProtocol::Tcp),
                IpProtocol::Udp => Some(PortProtocol::Udp),
                _ => None,
            }),
        Ok(IpVersion::Ipv6) => Ipv6Packet::new_checked(packet)
            .ok()
            .filter(|packet| Some(packet.dst_addr()) == source_peer_ipv6)
            .and_then(|packet| match packet.next_header() {
                IpProtocol::Tcp => Some(PortProtocol::Tcp),
                IpProtocol::Udp => Some(PortProtocol::Udp),
                _ => None,
            }),
        _ => None,
    }
}

pub(crate) fn is_ip_allowed(allowed_ips: &[IpNet], ip: IpAddr) -> bool {
    allowed_ips.is_empty() || allowed_ips.iter().any(|network| network.contains(&ip))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_packet(protocol: u8, destination: Ipv4Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(20u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&Ipv4Addr::new(192, 0, 2, 1).octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet
    }

    fn ipv6_packet(protocol: u8, destination: Ipv6Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet[6] = protocol;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        packet
    }

    #[test]
    fn wireguard_reserved_bits_round_trip() {
        let mut packet = vec![1, 0, 0, 0, 9];
        apply_reserved_bits(&mut packet, [7, 8, 9]);
        assert_eq!(&packet[1..4], &[7, 8, 9]);
        clear_reserved_bits(&mut packet);
        assert_eq!(&packet[1..4], &[0, 0, 0]);
    }

    #[test]
    fn wireguard_allowed_ips_matches_reference_semantics() {
        let networks = vec![
            "10.0.0.0/8".parse::<IpNet>().unwrap(),
            "2001:db8::/32".parse::<IpNet>().unwrap(),
        ];
        assert!(is_ip_allowed(&networks, "10.1.2.3".parse().unwrap()));
        assert!(is_ip_allowed(&networks, "2001:db8::7".parse().unwrap()));
        assert!(!is_ip_allowed(&networks, "192.168.1.1".parse().unwrap()));
        assert!(is_ip_allowed(&[], "192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn wireguard_routes_only_packets_for_local_peer() {
        let peer_v4 = Ipv4Addr::new(10, 0, 0, 2);
        let peer_v6: Ipv6Addr = "2001:db8::2".parse().unwrap();

        assert_eq!(
            route_protocol(&ipv4_packet(6, peer_v4), peer_v4, Some(peer_v6)),
            Some(PortProtocol::Tcp)
        );
        assert_eq!(
            route_protocol(&ipv4_packet(17, peer_v4), peer_v4, Some(peer_v6)),
            Some(PortProtocol::Udp)
        );
        assert_eq!(
            route_protocol(&ipv6_packet(17, peer_v6), peer_v4, Some(peer_v6)),
            Some(PortProtocol::Udp)
        );
        assert_eq!(
            route_protocol(
                &ipv4_packet(6, Ipv4Addr::new(10, 0, 0, 99)),
                peer_v4,
                Some(peer_v6),
            ),
            None
        );
    }
}
