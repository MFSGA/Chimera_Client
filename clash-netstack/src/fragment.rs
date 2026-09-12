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
        ttl: u8,
        identification: u16,
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

    pub(crate) fn rebuild(
        self,
        protocol: etherparse::IpNumber,
        payload: &[u8],
    ) -> std::io::Result<crate::Packet> {
        match self {
            Self::Ipv4 {
                source,
                destination,
                ttl,
                identification,
            } => {
                let payload_len = u16::try_from(payload.len()).map_err(|_| {
                    std::io::Error::other("reassembled payload too large")
                })?;
                let mut header = etherparse::Ipv4Header::new(
                    payload_len,
                    ttl,
                    protocol,
                    source,
                    destination,
                )
                .map_err(std::io::Error::other)?;
                header.identification = identification;
                header.dont_fragment = true;
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
    pub(crate) payload: Vec<u8>,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
enum FragmentKey {
    Ipv4 {
        source: [u8; 4],
        destination: [u8; 4],
        identification: u16,
    },
    Ipv6 {
        source: [u8; 16],
        destination: [u8; 16],
        identification: u32,
    },
}

struct FragmentPiece<'a> {
    key: FragmentKey,
    template: IpHeaderTemplate,
    next_header: etherparse::IpNumber,
    offset: etherparse::IpFragOffset,
    more_fragments: bool,
    payload: &'a [u8],
}

struct FragmentState {
    buffer: etherparse::defrag::IpDefragBuf,
    updated_at: Instant,
    template: IpHeaderTemplate,
    next_header: etherparse::IpNumber,
}

pub(crate) struct FragmentReassembler {
    expected_protocol: etherparse::IpNumber,
    label: &'static str,
    active: HashMap<FragmentKey, FragmentState>,
}

impl FragmentReassembler {
    pub(crate) fn new(
        expected_protocol: etherparse::IpNumber,
        label: &'static str,
    ) -> Self {
        Self {
            expected_protocol,
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
        let (payload, _) = state.buffer.take_bufs();
        let transport = transport_payload(state.next_header, &payload)?;
        if transport.0 != self.expected_protocol {
            return Ok(None);
        }

        Ok(Some(ReassembledTransport {
            template: state.template,
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
        },
        template: IpHeaderTemplate::Ipv4 {
            source: header.source(),
            destination: header.destination(),
            ttl: header.ttl(),
            identification: header.identification(),
        },
        next_header: ipv4.payload().ip_number,
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
                    },
                    template: IpHeaderTemplate::Ipv6 {
                        source: header.source(),
                        destination: header.destination(),
                        traffic_class: header.traffic_class(),
                        flow_label: header.flow_label(),
                        hop_limit: header.hop_limit(),
                    },
                    next_header: fragment.next_header(),
                    offset: fragment.fragment_offset(),
                    more_fragments: fragment.more_fragments(),
                    payload: &rest[etherparse::Ipv6FragmentHeader::LEN..],
                }));
            }
            etherparse::ip_number::IPV6_HOP_BY_HOP
            | etherparse::ip_number::IPV6_DEST_OPTIONS
            | etherparse::ip_number::IPV6_ROUTE => {
                let extension = etherparse::Ipv6RawExtHeaderSlice::from_slice(rest)
                    .map_err(std::io::Error::other)?;
                next = extension.next_header();
                rest = &rest[extension.slice().len()..];
            }
            etherparse::ip_number::AUTH => {
                let extension = etherparse::IpAuthHeaderSlice::from_slice(rest)
                    .map_err(std::io::Error::other)?;
                next = extension.next_header();
                rest = &rest[extension.slice().len()..];
            }
            _ => return Ok(None),
        }
    }
}

fn transport_payload(
    next_header: etherparse::IpNumber,
    payload: &[u8],
) -> std::io::Result<(etherparse::IpNumber, &[u8])> {
    let (_, protocol, payload) =
        etherparse::Ipv6ExtensionsSlice::from_slice(next_header, payload)
            .map_err(std::io::Error::other)?;
    Ok((protocol, payload))
}
