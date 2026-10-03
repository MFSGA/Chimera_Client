use log::{log_enabled, trace};
use std::net::{Ipv4Addr, Ipv6Addr};

pub(crate) fn trace_ip_packet(message: &str, packet: &[u8]) {
    if log_enabled!(log::Level::Trace) {
        trace!("{}", summarize_ip_packet(message, packet));
    }
}

fn summarize_ip_packet(message: &str, packet: &[u8]) -> String {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => {
            let header_len = packet
                .first()
                .map(|byte| usize::from(byte & 0x0f) * 4)
                .unwrap_or_default();
            if !(20..=60).contains(&header_len) || packet.len() < header_len {
                return format!(
                    "{message}: malformed IPv4 header, packet_len={}",
                    packet.len()
                );
            }
            let source =
                Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let destination =
                Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            let total_len = u16::from_be_bytes([packet[2], packet[3]]);
            format!(
                "{message}: IPv4 {source} -> {destination}, protocol={}, \
                 total_len={total_len}, captured_len={}",
                packet[9],
                packet.len()
            )
        }
        Some(6) if packet.len() >= 40 => {
            let source =
                Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap());
            let destination =
                Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap());
            let payload_len = u16::from_be_bytes([packet[4], packet[5]]);
            format!(
                "{message}: IPv6 {source} -> {destination}, next_header={}, \
                 payload_len={payload_len}, captured_len={}",
                packet[6],
                packet.len()
            )
        }
        Some(6) => format!(
            "{message}: malformed IPv6 header, packet_len={}",
            packet.len()
        ),
        _ => format!("{message}: non-IP packet, packet_len={}", packet.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::summarize_ip_packet;

    #[test]
    fn ip_packet_summary_omits_ipv4_transport_payload() {
        let marker = b"credential-like-payload";
        let mut packet = Vec::new();
        etherparse::PacketBuilder::ipv4([192, 0, 2, 10], [192, 0, 2, 20], 64)
            .udp(1000, 2000)
            .write(&mut packet, marker)
            .expect("build IPv4 UDP packet");

        let summary = summarize_ip_packet("TUN input", &packet);

        assert!(summary.contains("192.0.2.10 -> 192.0.2.20"));
        assert!(summary.contains(&format!("captured_len={}", packet.len())));
        assert!(!summary.contains("credential-like-payload"));
    }

    #[test]
    fn ip_packet_summary_omits_ipv6_transport_payload() {
        let marker = b"credential-like-payload";
        let mut packet = Vec::new();
        etherparse::PacketBuilder::ipv6([0x20; 16], [0x21; 16], 64)
            .udp(1000, 2000)
            .write(&mut packet, marker)
            .expect("build IPv6 UDP packet");

        let summary = summarize_ip_packet("TUN output", &packet);

        assert!(summary.contains("IPv6"));
        assert!(summary.contains(&format!("captured_len={}", packet.len())));
        assert!(!summary.contains("credential-like-payload"));
    }
}
