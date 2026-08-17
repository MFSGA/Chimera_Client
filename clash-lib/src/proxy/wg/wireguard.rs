use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use smoltcp::wire::{IpProtocol, IpVersion, Ipv4Packet, Ipv6Packet};

use super::events::PortProtocol;

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
