use log::warn;
use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

const FRAGMENT_MAX_ACTIVE: usize = 64;
const FRAGMENT_TTL: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug)]
pub(crate) enum IpHeaderTemplate {
    Ipv4 {
        source: [u8; 4],
        destination: [u8; 4],
        dscp: etherparse::IpDscp,
        ecn: etherparse::IpEcn,
        ttl: u8,
        identification: u16,
        dont_fragment: bool,
        options: [u8; 40],
        options_len: u8,
    },
    Ipv6 {
        source: [u8; 16],
        destination: [u8; 16],
        traffic_class: u8,
        flow_label: etherparse::Ipv6FlowLabel,
        hop_limit: u8,
    },
}

impl IpHeaderTemplate {
    pub(crate) fn source_ip(self) -> IpAddr {
        match self {
            Self::Ipv4 { source, .. } => IpAddr::V4(source.into()),
            Self::Ipv6 { source, .. } => IpAddr::V6(source.into()),
        }
    }

    pub(crate) fn destination_ip(self) -> IpAddr {
        match self {
            Self::Ipv4 { destination, .. } => IpAddr::V4(destination.into()),
            Self::Ipv6 { destination, .. } => IpAddr::V6(destination.into()),
        }
    }

    fn set_ecn(&mut self, ecn: etherparse::IpEcn) {
        match self {
            Self::Ipv4 { ecn: current, .. } => *current = ecn,
            Self::Ipv6 { traffic_class, .. } => {
                *traffic_class = (*traffic_class & !0b11) | ecn.value();
            }
        }
    }

    pub(crate) fn rebuild(
        self,
        protocol: etherparse::IpNumber,
        payload: &[u8],
    ) -> std::io::Result<crate::Packet> {
        match self {
            Self::Ipv4 {
                source,
                destination,
                dscp,
                ecn,
                ttl,
                identification,
                dont_fragment,
                options,
                options_len,
            } => {
                let mut header = etherparse::Ipv4Header::new(
                    0,
                    ttl,
                    protocol,
                    source,
                    destination,
                )
                .map_err(std::io::Error::other)?;
                header.dscp = dscp;
                header.ecn = ecn;
                header.identification = identification;
                header.dont_fragment = dont_fragment;
                header.options = (&options[..usize::from(options_len)])
                    .try_into()
                    .map_err(std::io::Error::other)?;
                header
                    .set_payload_len(payload.len())
                    .map_err(std::io::Error::other)?;
                header.header_checksum = header.calc_header_checksum();
                let mut out = header.to_bytes().to_vec();
                out.extend_from_slice(payload);
                Ok(crate::Packet::new(out))
            }
            Self::Ipv6 {
                source,
                destination,
                traffic_class,
                flow_label,
                hop_limit,
            } => {
                let payload_length = u16::try_from(payload.len()).map_err(|_| {
                    std::io::Error::other("reassembled payload too large")
                })?;
                let header = etherparse::Ipv6Header {
                    traffic_class,
                    flow_label,
                    payload_length,
                    next_header: protocol,
                    hop_limit,
                    source,
                    destination,
                };
                let mut out = header.to_bytes().to_vec();
                out.extend_from_slice(payload);
                Ok(crate::Packet::new(out))
            }
        }
    }
}

pub(crate) struct ReassembledTransport {
    pub(crate) template: IpHeaderTemplate,
    pub(crate) protocol: etherparse::IpNumber,
    pub(crate) payload: Vec<u8>,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
enum FragmentKey {
    Ipv4 {
        source: [u8; 4],
        destination: [u8; 4],
        identification: u16,
        protocol: etherparse::IpNumber,
    },
    Ipv6 {
        source: [u8; 16],
        destination: [u8; 16],
        identification: u32,
        next_header: etherparse::IpNumber,
    },
}

struct FragmentPiece<'a> {
    key: FragmentKey,
    template: IpHeaderTemplate,
    next_header: etherparse::IpNumber,
    ecn: etherparse::IpEcn,
    offset: etherparse::IpFragOffset,
    more_fragments: bool,
    payload: &'a [u8],
}

struct FragmentState {
    buffer: etherparse::defrag::IpDefragBuf,
    updated_at: Instant,
    template: IpHeaderTemplate,
    next_header: etherparse::IpNumber,
    saw_ce: bool,
    saw_not_ect: bool,
}

fn validate_overlap(
    piece: &FragmentPiece<'_>,
    buffer: &etherparse::defrag::IpDefragBuf,
) -> std::io::Result<()> {
    let start = piece.offset.byte_offset();
    let len = u16::try_from(piece.payload.len())
        .map_err(|_| std::io::Error::other("fragment payload too large"))?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| std::io::Error::other("fragment range overflow"))?;

    for section in buffer.sections() {
        let overlap_start = start.max(section.start);
        let overlap_end = end.min(section.end);
        if overlap_start >= overlap_end {
            continue;
        }
        if matches!(piece.key, FragmentKey::Ipv6 { .. }) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "overlapping IPv6 fragments",
            ));
        }

        let old_start = usize::from(overlap_start);
        let old_end = usize::from(overlap_end);
        let new_start = usize::from(overlap_start - start);
        let new_end = new_start + (old_end - old_start);
        if buffer.data()[old_start..old_end] != piece.payload[new_start..new_end] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "conflicting overlapping IPv4 fragments",
            ));
        }
    }
    Ok(())
}

pub(crate) struct FragmentReassembler {
    expected_protocol: Option<etherparse::IpNumber>,
    label: &'static str,
    active: HashMap<FragmentKey, FragmentState>,
}

impl FragmentReassembler {
    pub(crate) fn new(
        expected_protocol: etherparse::IpNumber,
        label: &'static str,
    ) -> Self {
        Self {
            expected_protocol: Some(expected_protocol),
            label,
            active: HashMap::new(),
        }
    }

    pub(crate) fn new_any(label: &'static str) -> Self {
        Self {
            expected_protocol: None,
            label,
            active: HashMap::new(),
        }
    }

    fn prune_expired(&mut self, now: Instant) {
        self.active
            .retain(|_, state| now.duration_since(state.updated_at) < FRAGMENT_TTL);
    }

    fn evict_oldest_if_full(&mut self) {
        if self.active.len() < FRAGMENT_MAX_ACTIVE {
            return;
        }
        if let Some(oldest) = self
            .active
            .iter()
            .min_by_key(|(_, state)| state.updated_at)
            .map(|(key, _)| key.clone())
        {
            self.active.remove(&oldest);
            warn!(
                "evicting oldest {} fragment reassembly because active limit ({FRAGMENT_MAX_ACTIVE}) was reached",
                self.label
            );
        }
    }

    pub(crate) fn push(
        &mut self,
        packet: &[u8],
    ) -> std::io::Result<Option<ReassembledTransport>> {
        let now = Instant::now();
        self.prune_expired(now);
        let piece = match fragment_piece(packet)? {
            Some(piece) => piece,
            None => return Ok(None),
        };

        if !self.active.contains_key(&piece.key) {
            self.evict_oldest_if_full();
            self.active.insert(
                piece.key.clone(),
                FragmentState {
                    buffer: etherparse::defrag::IpDefragBuf::new(
                        piece.next_header,
                        Vec::new(),
                        Vec::new(),
                    ),
                    updated_at: now,
                    template: piece.template,
                    next_header: piece.next_header,
                    saw_ce: piece.ecn == etherparse::IpEcn::CongestionExperienced,
                    saw_not_ect: piece.ecn == etherparse::IpEcn::NotEct,
                },
            );
        }

        let complete = {
            let state = self
                .active
                .get_mut(&piece.key)
                .expect("fragment state must exist after insertion");
            if state.next_header != piece.next_header {
                self.active.remove(&piece.key);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "fragment next-header changed within one datagram",
                ));
            }
            if let Err(err) = validate_overlap(&piece, &state.buffer) {
                self.active.remove(&piece.key);
                return Err(err);
            }
            let piece_is_ce = piece.ecn == etherparse::IpEcn::CongestionExperienced;
            let piece_is_not_ect = piece.ecn == etherparse::IpEcn::NotEct;
            if (piece_is_ce && state.saw_not_ect)
                || (piece_is_not_ect && state.saw_ce)
            {
                self.active.remove(&piece.key);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "fragment set mixes CE with Not-ECT",
                ));
            }
            state.saw_ce |= piece_is_ce;
            state.saw_not_ect |= piece_is_not_ect;
            state.updated_at = now;
            if piece.offset.value() == 0 {
                state.template = piece.template;
            }
            if let Err(err) =
                state
                    .buffer
                    .add(piece.offset, piece.more_fragments, piece.payload)
            {
                self.active.remove(&piece.key);
                return Err(std::io::Error::other(err));
            }
            state.buffer.is_complete()
        };
        if !complete {
            return Ok(None);
        }

        let state = self
            .active
            .remove(&piece.key)
            .expect("completed fragment state must exist");
        let mut template = state.template;
        if state.saw_ce {
            template.set_ecn(etherparse::IpEcn::CongestionExperienced);
        }
        let (payload, _) = state.buffer.take_bufs();
        let transport = transport_payload(state.next_header, &payload)?;
        if self
            .expected_protocol
            .is_some_and(|expected| transport.0 != expected)
        {
            return Ok(None);
        }

        Ok(Some(ReassembledTransport {
            template,
            protocol: transport.0,
            payload: transport.1.to_vec(),
        }))
    }
}

pub(crate) fn is_fragmented(packet: &[u8]) -> std::io::Result<bool> {
    Ok(fragment_piece(packet)?.is_some())
}

pub(crate) fn ipv6_fragment_next_header(
    packet: &[u8],
) -> std::io::Result<Option<etherparse::IpNumber>> {
    Ok(ipv6_fragment_piece(packet)?.map(|piece| piece.next_header))
}

fn fragment_piece(packet: &[u8]) -> std::io::Result<Option<FragmentPiece<'_>>> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => ipv4_fragment_piece(packet),
        Some(6) => ipv6_fragment_piece(packet),
        _ => Ok(None),
    }
}

fn ipv4_fragment_piece(packet: &[u8]) -> std::io::Result<Option<FragmentPiece<'_>>> {
    let ipv4 =
        etherparse::Ipv4Slice::from_slice(packet).map_err(std::io::Error::other)?;
    if !ipv4.payload().fragmented {
        return Ok(None);
    }
    let header = ipv4.header();
    Ok(Some(FragmentPiece {
        key: FragmentKey::Ipv4 {
            source: header.source(),
            destination: header.destination(),
            identification: header.identification(),
            protocol: ipv4.payload().ip_number,
        },
        template: IpHeaderTemplate::Ipv4 {
            source: header.source(),
            destination: header.destination(),
            dscp: header.dcp(),
            ecn: header.ecn(),
            ttl: header.ttl(),
            identification: header.identification(),
            dont_fragment: header.dont_fragment(),
            options: {
                let mut options = [0u8; 40];
                let raw = header.options();
                options[..raw.len()].copy_from_slice(raw);
                options
            },
            options_len: header.options().len() as u8,
        },
        next_header: ipv4.payload().ip_number,
        ecn: header.ecn(),
        offset: header.fragments_offset(),
        more_fragments: header.more_fragments(),
        payload: ipv4.payload().payload,
    }))
}

fn ipv6_fragment_piece(packet: &[u8]) -> std::io::Result<Option<FragmentPiece<'_>>> {
    let header = etherparse::Ipv6HeaderSlice::from_slice(packet)
        .map_err(std::io::Error::other)?;
    let payload_len = usize::from(header.payload_length());
    let end = etherparse::Ipv6Header::LEN
        .checked_add(payload_len)
        .ok_or_else(|| std::io::Error::other("IPv6 payload length overflow"))?;
    if packet.len() < end {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "truncated IPv6 packet",
        ));
    }

    let mut next = header.next_header();
    let mut rest = &packet[etherparse::Ipv6Header::LEN..end];
    loop {
        match next {
            etherparse::ip_number::IPV6_FRAG => {
                let fragment = etherparse::Ipv6FragmentHeaderSlice::from_slice(rest)
                    .map_err(std::io::Error::other)?;
                if !fragment.is_fragmenting_payload() {
                    return Ok(None);
                }
                return Ok(Some(FragmentPiece {
                    key: FragmentKey::Ipv6 {
                        source: header.source(),
                        destination: header.destination(),
                        identification: fragment.identification(),
                        next_header: fragment.next_header(),
                    },
                    template: IpHeaderTemplate::Ipv6 {
                        source: header.source(),
                        destination: header.destination(),
                        traffic_class: header.traffic_class(),
                        flow_label: header.flow_label(),
                        hop_limit: header.hop_limit(),
                    },
                    next_header: fragment.next_header(),
                    ecn: etherparse::IpEcn::try_new(header.traffic_class() & 0b11)
                        .expect("IPv6 ECN field is two bits"),
                    offset: fragment.fragment_offset(),
                    more_fragments: fragment.more_fragments(),
                    payload: &rest[etherparse::Ipv6FragmentHeader::LEN..],
                }));
            }
            etherparse::ip_number::IPV6_HOP_BY_HOP
            | etherparse::ip_number::IPV6_DEST_OPTIONS => {
                let extension = etherparse::Ipv6RawExtHeaderSlice::from_slice(rest)
                    .map_err(std::io::Error::other)?;
                validate_padding_only_ipv6_options(extension.payload())?;
                next = extension.next_header();
                rest = &rest[extension.slice().len()..];
            }
            etherparse::ip_number::IPV6_ROUTE | etherparse::ip_number::AUTH => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unsupported semantic IPv6 extension before Fragment header",
                ));
            }
            _ => return Ok(None),
        }
    }
}

fn transport_payload(
    mut next_header: etherparse::IpNumber,
    mut payload: &[u8],
) -> std::io::Result<(etherparse::IpNumber, &[u8])> {
    loop {
        match next_header {
            etherparse::ip_number::IPV6_DEST_OPTIONS => {
                let extension =
                    etherparse::Ipv6RawExtHeaderSlice::from_slice(payload)
                        .map_err(std::io::Error::other)?;
                validate_padding_only_ipv6_options(extension.payload())?;
                next_header = extension.next_header();
                payload = &payload[extension.slice().len()..];
            }
            etherparse::ip_number::IPV6_HOP_BY_HOP
            | etherparse::ip_number::IPV6_ROUTE
            | etherparse::ip_number::AUTH => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unsupported semantic IPv6 extension after Fragment header",
                ));
            }
            _ => return Ok((next_header, payload)),
        }
    }
}

fn validate_padding_only_ipv6_options(options: &[u8]) -> std::io::Result<()> {
    let mut offset = 0usize;
    while offset < options.len() {
        match options[offset] {
            0 => offset += 1, // Pad1
            1 => {
                let Some(&len) = options.get(offset + 1) else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "truncated IPv6 PadN option",
                    ));
                };
                let end =
                    offset.checked_add(2 + usize::from(len)).ok_or_else(|| {
                        std::io::Error::other("IPv6 option length overflow")
                    })?;
                let Some(data) = options.get(offset + 2..end) else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "truncated IPv6 PadN option data",
                    ));
                };
                if data.iter().any(|byte| *byte != 0) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "non-zero IPv6 PadN option data",
                    ));
                }
                offset = end;
            }
            option => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "unsupported semantic IPv6 option in fragmented packet: {option}"
                    ),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn incomplete_ipv4_fragment(identification: u16) -> Vec<u8> {
        let mut header = etherparse::Ipv4Header::new(
            8,
            64,
            etherparse::ip_number::UDP,
            [1, 1, 1, 1],
            [2, 2, 2, 2],
        )
        .unwrap();
        header.identification = identification;
        header.dont_fragment = false;
        header.more_fragments = true;
        header.header_checksum = header.calc_header_checksum();
        [header.to_bytes().as_slice(), &[0u8; 8]].concat()
    }

    #[test]
    fn ipv4_rebuild_preserves_first_fragment_header_semantics() {
        let build = |part: &[u8], offset: usize, more_fragments: bool| {
            let mut header = etherparse::Ipv4Header::new(
                0,
                42,
                etherparse::ip_number::UDP,
                [1, 1, 1, 1],
                [2, 2, 2, 2],
            )
            .unwrap();
            header.dscp = etherparse::IpDscp::try_new(0x2a).unwrap();
            header.ecn = etherparse::IpEcn::try_new(3).unwrap();
            header.options = (&[1, 1, 1, 0][..]).try_into().unwrap();
            header.set_payload_len(part.len()).unwrap();
            header.identification = 0x4242;
            header.dont_fragment = false;
            header.more_fragments = more_fragments;
            header.fragment_offset =
                etherparse::IpFragOffset::try_new((offset / 8) as u16).unwrap();
            header.header_checksum = header.calc_header_checksum();
            [header.to_bytes().as_slice(), part].concat()
        };
        let payload = [0x5au8; 16];
        let first = build(&payload[..8], 0, true);
        let second = build(&payload[8..], 8, false);
        let mut reassembler =
            FragmentReassembler::new(etherparse::ip_number::UDP, "test");
        assert!(reassembler.push(&second).unwrap().is_none());
        let reassembled = reassembler
            .push(&first)
            .unwrap()
            .expect("fragments should complete");
        let packet = reassembled
            .template
            .rebuild(reassembled.protocol, &reassembled.payload)
            .unwrap();
        let ipv4 = etherparse::Ipv4Slice::from_slice(packet.data()).unwrap();
        let header = ipv4.header();
        assert_eq!(header.dcp(), etherparse::IpDscp::try_new(0x2a).unwrap());
        assert_eq!(header.ecn(), etherparse::IpEcn::try_new(3).unwrap());
        assert_eq!(header.options(), &[1, 1, 1, 0]);
        assert_eq!(header.ttl(), 42);
        assert_eq!(header.identification(), 0x4242);
        assert!(!header.dont_fragment());
        assert!(!header.more_fragments());
        assert_eq!(header.fragments_offset().value(), 0);
    }

    #[test]
    fn fragment_reassembly_propagates_ce_from_later_ipv4_fragment() {
        let build =
            |part: &[u8], offset: usize, more: bool, ecn: etherparse::IpEcn| {
                let mut header = etherparse::Ipv4Header::new(
                    part.len() as u16,
                    64,
                    etherparse::ip_number::UDP,
                    [1, 1, 1, 1],
                    [2, 2, 2, 2],
                )
                .unwrap();
                header.ecn = ecn;
                header.identification = 0x7171;
                header.dont_fragment = false;
                header.more_fragments = more;
                header.fragment_offset =
                    etherparse::IpFragOffset::try_new((offset / 8) as u16).unwrap();
                header.header_checksum = header.calc_header_checksum();
                [header.to_bytes().as_slice(), part].concat()
            };
        let payload = [0x33u8; 16];
        let first = build(&payload[..8], 0, true, etherparse::IpEcn::Ect0);
        let second = build(
            &payload[8..],
            8,
            false,
            etherparse::IpEcn::CongestionExperienced,
        );
        let mut reassembler =
            FragmentReassembler::new(etherparse::ip_number::UDP, "test");
        assert!(reassembler.push(&first).unwrap().is_none());
        let reassembled = reassembler
            .push(&second)
            .unwrap()
            .expect("fragments should complete");
        let packet = reassembled
            .template
            .rebuild(reassembled.protocol, &reassembled.payload)
            .unwrap();
        let ipv4 = etherparse::Ipv4Slice::from_slice(packet.data()).unwrap();
        assert_eq!(
            ipv4.header().ecn(),
            etherparse::IpEcn::CongestionExperienced
        );
    }

    #[test]
    fn fragment_reassembly_rejects_ce_and_not_ect_mix() {
        let build =
            |part: &[u8], offset: usize, more: bool, ecn: etherparse::IpEcn| {
                let mut header = etherparse::Ipv4Header::new(
                    part.len() as u16,
                    64,
                    etherparse::ip_number::UDP,
                    [1, 1, 1, 1],
                    [2, 2, 2, 2],
                )
                .unwrap();
                header.ecn = ecn;
                header.identification = 0x7272;
                header.dont_fragment = false;
                header.more_fragments = more;
                header.fragment_offset =
                    etherparse::IpFragOffset::try_new((offset / 8) as u16).unwrap();
                header.header_checksum = header.calc_header_checksum();
                [header.to_bytes().as_slice(), part].concat()
            };
        let payload = [0x44u8; 16];
        let first = build(&payload[..8], 0, true, etherparse::IpEcn::NotEct);
        let second = build(
            &payload[8..],
            8,
            false,
            etherparse::IpEcn::CongestionExperienced,
        );
        let mut reassembler =
            FragmentReassembler::new(etherparse::ip_number::UDP, "test");
        assert!(reassembler.push(&first).unwrap().is_none());
        let err = match reassembler.push(&second) {
            Err(err) => err,
            Ok(_) => panic!("CE + Not-ECT fragments must be rejected"),
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(reassembler.active.is_empty());
    }

    #[test]
    fn fragment_reassembly_propagates_ce_for_ipv6() {
        let source = [0x20; 16];
        let destination = [0x21; 16];
        let build =
            |part: &[u8], offset: usize, more: bool, ecn: etherparse::IpEcn| {
                let header = etherparse::Ipv6Header {
                    traffic_class: 0b1010_1000 | ecn.value(),
                    payload_length: (etherparse::Ipv6FragmentHeader::LEN
                        + part.len()) as u16,
                    next_header: etherparse::ip_number::IPV6_FRAG,
                    hop_limit: 64,
                    source,
                    destination,
                    ..Default::default()
                };
                let fragment = etherparse::Ipv6FragmentHeader::new(
                    etherparse::ip_number::UDP,
                    etherparse::IpFragOffset::try_new((offset / 8) as u16).unwrap(),
                    more,
                    0x7373_7373,
                );
                [
                    header.to_bytes().as_slice(),
                    fragment.to_bytes().as_slice(),
                    part,
                ]
                .concat()
            };
        let payload = [0x55u8; 16];
        let first = build(&payload[..8], 0, true, etherparse::IpEcn::Ect0);
        let second = build(
            &payload[8..],
            8,
            false,
            etherparse::IpEcn::CongestionExperienced,
        );
        let mut reassembler =
            FragmentReassembler::new(etherparse::ip_number::UDP, "test");
        assert!(reassembler.push(&first).unwrap().is_none());
        let reassembled = reassembler
            .push(&second)
            .unwrap()
            .expect("fragments should complete");
        let packet = reassembled
            .template
            .rebuild(reassembled.protocol, &reassembled.payload)
            .unwrap();
        let header = etherparse::Ipv6HeaderSlice::from_slice(packet.data()).unwrap();
        assert_eq!(
            header.traffic_class() & 0b11,
            etherparse::IpEcn::THREE.value()
        );
        assert_eq!(header.traffic_class() & !0b11, 0b1010_1000);
    }

    #[test]
    fn fragment_reassembly_keys_ipv4_by_protocol() {
        let build = |protocol: etherparse::IpNumber| {
            let mut header = etherparse::Ipv4Header::new(
                8,
                64,
                protocol,
                [1, 1, 1, 1],
                [2, 2, 2, 2],
            )
            .unwrap();
            header.identification = 0x7a7a;
            header.dont_fragment = false;
            header.more_fragments = true;
            header.header_checksum = header.calc_header_checksum();
            [header.to_bytes().as_slice(), &[0u8; 8]].concat()
        };
        let mut reassembler = FragmentReassembler::new_any("test");
        assert!(
            reassembler
                .push(&build(etherparse::ip_number::TCP))
                .unwrap()
                .is_none()
        );
        assert!(
            reassembler
                .push(&build(etherparse::ip_number::ICMP))
                .unwrap()
                .is_none()
        );
        assert_eq!(reassembler.active.len(), 2);
    }

    #[test]
    fn fragment_reassembly_evicts_oldest_when_active_limit_is_reached() {
        let mut reassembler =
            FragmentReassembler::new(etherparse::ip_number::UDP, "test");

        for identification in 0..=(FRAGMENT_MAX_ACTIVE as u16) {
            let packet = incomplete_ipv4_fragment(identification);
            assert!(reassembler.push(&packet).unwrap().is_none());
        }

        assert_eq!(reassembler.active.len(), FRAGMENT_MAX_ACTIVE);
        assert!(!reassembler.active.contains_key(&FragmentKey::Ipv4 {
            source: [1, 1, 1, 1],
            destination: [2, 2, 2, 2],
            identification: 0,
            protocol: etherparse::ip_number::UDP,
        }));
        assert!(reassembler.active.contains_key(&FragmentKey::Ipv4 {
            source: [1, 1, 1, 1],
            destination: [2, 2, 2, 2],
            identification: FRAGMENT_MAX_ACTIVE as u16,
            protocol: etherparse::ip_number::UDP,
        }));
    }
}
