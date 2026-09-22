use crate::{
    Packet,
    fragment::FragmentReassembler,
    outbound_queue::{BestEffortSend, FairPacketSender, OutboundFlowKey},
    packet::IpPacket,
};
use etherparse::PacketBuilder;
use log::{error, trace, warn};
use std::{
    borrow::Cow,
    collections::{HashMap, VecDeque, hash_map::RandomState},
    hash::{BuildHasher, Hash, Hasher},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{Notify, mpsc};

const PATH_MTU_CACHE_CAPACITY: usize = 64;
const PATH_MTU_CACHE_TTL: Duration = Duration::from_secs(10 * 60);
const RECENT_UDP_FLOW_CAPACITY: usize = 128;
const RECENT_UDP_FLOW_TTL: Duration = Duration::from_secs(30);
const UDP_ICMP_ERROR_CAPACITY: usize = 64;

type PathMtuCache = Arc<Mutex<HashMap<IpAddr, (usize, Instant)>>>;
type RecentUdpFlows = Arc<Mutex<HashMap<(SocketAddr, SocketAddr), Instant>>>;
type UdpIcmpErrors = Arc<Mutex<VecDeque<UdpIcmpError>>>;

#[derive(Clone)]
enum UdpOutbound {
    Channel(mpsc::Sender<Packet>),
    Fair(FairPacketSender),
}

/// A validated asynchronous ICMP error correlated with a recently sent UDP flow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpIcmpError {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    /// Address of the router or peer that originated the ICMP error.
    pub offender: IpAddr,
    /// UDP application payload preserved by the ICMP quote.
    ///
    /// Routers are only required to quote enough bytes to identify the flow,
    /// so this may be empty or a prefix of the failed datagram.
    pub quoted_payload: Box<[u8]>,
    pub kind: UdpIcmpErrorKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpIcmpErrorKind {
    PacketTooBig { path_mtu: usize },
    DestinationUnreachable { code: u8 },
    TimeExceeded { code: u8 },
    ParameterProblem { code: u8, pointer: u32 },
}

/// Linux `sock_extended_err` fields exposed by MIPS error-queue reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketErrorControlMessage {
    pub errno: u32,
    pub origin: u8,
    pub icmp_type: u8,
    pub code: u8,
    pub info: u32,
    pub offender: IpAddr,
}

/// One Linux-style UDP error-queue message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpErrorQueueMessage {
    /// Application payload bytes preserved by the ICMP quote.
    pub payload: Box<[u8]>,
    /// Original destination of the failed UDP datagram.
    pub addr: SocketAddr,
    /// Canonical Linux 64-bit little-endian `sock_extended_err` ancillary data.
    pub oob: Box<[u8]>,
}

/// Result metadata for a buffer-oriented Linux-style UDP error-queue read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpErrorQueueRead {
    /// Number of quoted payload bytes copied to the payload buffer.
    pub n: usize,
    /// Number of ancillary bytes copied to the OOB buffer.
    pub nn: usize,
    /// Linux message result flags (`MSG_TRUNC` / `MSG_CTRUNC`).
    pub flags: i32,
    /// Original destination of the failed UDP datagram.
    pub addr: SocketAddr,
}

/// Linux `MSG_CTRUNC`, returned when an error-queue OOB buffer is too small.
pub const MESSAGE_FLAG_CONTROL_TRUNCATED: i32 = 0x08;
/// Linux `MSG_TRUNC`, returned when an error-queue payload buffer is too small.
pub const MESSAGE_FLAG_TRUNCATED: i32 = 0x20;
/// Linux `MSG_DONTWAIT`; error-queue reads are already nonblocking.
pub const MESSAGE_FLAG_DONT_WAIT: i32 = 0x40;
/// Linux `MSG_ERRQUEUE`, selecting the asynchronous socket error queue.
pub const MESSAGE_FLAG_ERROR_QUEUE: i32 = 0x2000;

const LINUX_CMSG_HEADER_LEN: usize = 16;
const LINUX_SOCK_EXTENDED_ERR_LEN: usize = 16;
const LINUX_SOL_IP: i32 = 0;
const LINUX_SOL_IPV6: i32 = 41;
const LINUX_IP_RECVERR: i32 = 11;
const LINUX_IPV6_RECVERR: i32 = 25;
const LINUX_AF_INET: u16 = 2;
const LINUX_AF_INET6: u16 = 10;

impl SocketErrorControlMessage {
    /// Encode one canonical Linux 64-bit little-endian error-queue control
    /// message, including the offender sockaddr and cmsg alignment padding.
    pub fn marshal_binary(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(if self.offender.is_ipv4() { 48 } else { 64 });
        self.append_binary(&mut out);
        out
    }

    /// Append one canonical Linux error-queue control message to `out`.
    pub fn append_binary(&self, out: &mut Vec<u8>) {
        let (level, message_type, sockaddr_len) = if self.offender.is_ipv4() {
            (LINUX_SOL_IP, LINUX_IP_RECVERR, 16usize)
        } else {
            (LINUX_SOL_IPV6, LINUX_IPV6_RECVERR, 28usize)
        };
        let cmsg_len =
            LINUX_CMSG_HEADER_LEN + LINUX_SOCK_EXTENDED_ERR_LEN + sockaddr_len;
        let aligned_len = (cmsg_len + 7) & !7;
        let start = out.len();
        out.resize(start + aligned_len, 0);
        let bytes = &mut out[start..];
        bytes[..8].copy_from_slice(&(cmsg_len as u64).to_le_bytes());
        bytes[8..12].copy_from_slice(&level.to_le_bytes());
        bytes[12..16].copy_from_slice(&message_type.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.errno.to_le_bytes());
        bytes[20] = self.origin;
        bytes[21] = self.icmp_type;
        bytes[22] = self.code;
        bytes[24..28].copy_from_slice(&self.info.to_le_bytes());

        let sockaddr = &mut bytes[32..32 + sockaddr_len];
        match self.offender {
            IpAddr::V4(address) => {
                sockaddr[..2].copy_from_slice(&LINUX_AF_INET.to_le_bytes());
                sockaddr[4..8].copy_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                sockaddr[..2].copy_from_slice(&LINUX_AF_INET6.to_le_bytes());
                sockaddr[8..24].copy_from_slice(&address.octets());
            }
        }
    }

    /// Find and decode one Linux `sock_extended_err` record from a possibly
    /// compound 64-bit little-endian ancillary buffer.
    pub fn parse(mut oob: &[u8]) -> std::io::Result<Self> {
        while oob.len() >= LINUX_CMSG_HEADER_LEN {
            let cmsg_len = u64::from_le_bytes(oob[..8].try_into().unwrap()) as usize;
            if cmsg_len < LINUX_CMSG_HEADER_LEN || cmsg_len > oob.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid Linux control-message length",
                ));
            }
            let level = i32::from_le_bytes(oob[8..12].try_into().unwrap());
            let message_type = i32::from_le_bytes(oob[12..16].try_into().unwrap());
            if matches!(
                (level, message_type),
                (LINUX_SOL_IP, LINUX_IP_RECVERR)
                    | (LINUX_SOL_IPV6, LINUX_IPV6_RECVERR)
            ) {
                return Self::parse_error_record(level, &oob[16..cmsg_len]);
            }
            let aligned_len = (cmsg_len + 7) & !7;
            if aligned_len > oob.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "truncated Linux control-message padding",
                ));
            }
            oob = &oob[aligned_len..];
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no socket error control message",
        ))
    }

    fn parse_error_record(level: i32, data: &[u8]) -> std::io::Result<Self> {
        let sockaddr_len = if level == LINUX_SOL_IP { 16 } else { 28 };
        if data.len() < LINUX_SOCK_EXTENDED_ERR_LEN + sockaddr_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "truncated socket error control message",
            ));
        }
        let sockaddr = &data[LINUX_SOCK_EXTENDED_ERR_LEN..];
        let family = u16::from_le_bytes(sockaddr[..2].try_into().unwrap());
        let offender = match family {
            LINUX_AF_INET if level == LINUX_SOL_IP => {
                IpAddr::V4(std::net::Ipv4Addr::new(
                    sockaddr[4],
                    sockaddr[5],
                    sockaddr[6],
                    sockaddr[7],
                ))
            }
            LINUX_AF_INET6 if level == LINUX_SOL_IPV6 => {
                let octets: [u8; 16] = sockaddr[8..24].try_into().unwrap();
                IpAddr::V6(std::net::Ipv6Addr::from(octets))
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid socket error offender family",
                ));
            }
        };
        Ok(Self {
            errno: u32::from_le_bytes(data[..4].try_into().unwrap()),
            origin: data[4],
            icmp_type: data[5],
            code: data[6],
            info: u32::from_le_bytes(data[8..12].try_into().unwrap()),
            offender,
        })
    }
}

impl UdpIcmpError {
    /// Convert validated ICMP metadata to MIPS's Linux-compatible extended
    /// error fields used by the binary error-queue encoder below.
    pub fn socket_error_control(&self) -> SocketErrorControlMessage {
        let ipv6 = self.offender.is_ipv6();
        let (icmp_type, code, info) = match self.kind {
            UdpIcmpErrorKind::PacketTooBig { path_mtu } => {
                if ipv6 {
                    (2, 0, path_mtu as u32)
                } else {
                    (3, 4, path_mtu as u32)
                }
            }
            UdpIcmpErrorKind::DestinationUnreachable { code } => {
                (if ipv6 { 1 } else { 3 }, code, 0)
            }
            UdpIcmpErrorKind::TimeExceeded { code } => {
                (if ipv6 { 3 } else { 11 }, code, 0)
            }
            UdpIcmpErrorKind::ParameterProblem { code, pointer } => {
                (if ipv6 { 4 } else { 12 }, code, pointer)
            }
        };
        SocketErrorControlMessage {
            errno: linux_icmp_errno(ipv6, icmp_type, code),
            origin: if ipv6 { 3 } else { 2 },
            icmp_type,
            code,
            info,
            offender: self.offender,
        }
    }
}

fn linux_icmp_errno(ipv6: bool, icmp_type: u8, code: u8) -> u32 {
    if !ipv6 {
        return match icmp_type {
            3 => [
                101, 113, 92, 111, 90, 95, 101, 112, 64, 101, 113, 101, 113, 113,
                113, 113,
            ]
            .get(usize::from(code))
            .copied()
            .unwrap_or(71),
            11 => 113,
            12 => 71,
            _ => 71,
        };
    }
    match icmp_type {
        1 => [101, 13, 113, 113, 111, 13, 13]
            .get(usize::from(code))
            .copied()
            .unwrap_or(71),
        2 => 90,
        3 => 113,
        4 => 71,
        _ => 71,
    }
}

/// UDP path-MTU discovery policy matching MIPS's Linux-compatible modes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PathMtuDiscovery {
    /// Use confirmed destination PMTU and allow source fragmentation.
    #[default]
    Dont,
    /// Use confirmed destination PMTU, requesting DF for fitting IPv4 packets.
    Want,
    /// Use confirmed destination PMTU and fail oversized writes with EMSGSIZE.
    Do,
    /// Ignore destination PMTU, request DF, and enforce the link MTU.
    Probe,
    /// Ignore destination PMTU, leave DF clear, and enforce the link MTU.
    Interface,
    /// Ignore destination PMTU and allow source fragmentation at the link MTU.
    Omit,
}

#[derive(Clone)]
pub(crate) struct UdpIcmpControl {
    path_mtu: PathMtuCache,
    recent_flows: RecentUdpFlows,
    errors: UdpIcmpErrors,
    error_notify: Arc<Notify>,
    mtu: usize,
}

pub struct UdpPacket {
    pub data: Packet,
    /// src of the packet
    pub local_addr: SocketAddr,
    /// dst of the packet
    pub remote_addr: SocketAddr,
}
impl std::fmt::Debug for UdpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpPacket")
            .field("local_addr", &self.local_addr)
            .field("remote_addr", &self.remote_addr)
            .field("data_len", &self.data().len())
            .finish()
    }
}

impl<T> From<(T, SocketAddr, SocketAddr)> for UdpPacket
where
    T: Into<Packet>,
{
    fn from((data, local_addr, remote_addr): (T, SocketAddr, SocketAddr)) -> Self {
        UdpPacket {
            data: data.into(),
            local_addr,
            remote_addr,
        }
    }
}

impl UdpPacket {
    pub fn data(&self) -> &[u8] {
        self.data.data()
    }
}

fn path_mtu_for_cache(
    path_mtu: &PathMtuCache,
    link_mtu: usize,
    destination: IpAddr,
) -> usize {
    let now = Instant::now();
    let mut cache = path_mtu.lock().unwrap_or_else(|err| err.into_inner());
    let Some((mtu, updated)) = cache.get(&destination).copied() else {
        return link_mtu;
    };
    if now.duration_since(updated) >= PATH_MTU_CACHE_TTL {
        cache.remove(&destination);
        return link_mtu;
    }
    mtu
}

fn confirm_path_mtu_cache(
    path_mtu: &PathMtuCache,
    link_mtu: usize,
    destination: IpAddr,
    mtu: usize,
) {
    let minimum = if destination.is_ipv6() { 1280 } else { 68 };
    if mtu < minimum {
        return;
    }
    let mtu = mtu.min(link_mtu);
    let now = Instant::now();
    let mut cache = path_mtu.lock().unwrap_or_else(|err| err.into_inner());
    cache
        .retain(|_, (_, updated)| now.duration_since(*updated) < PATH_MTU_CACHE_TTL);
    if cache.len() >= PATH_MTU_CACHE_CAPACITY
        && !cache.contains_key(&destination)
        && let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, (_, updated))| *updated)
            .map(|(destination, _)| *destination)
    {
        cache.remove(&oldest);
    }
    cache.insert(destination, (mtu, now));
}

fn record_recent_udp_flow(
    recent_flows: &RecentUdpFlows,
    local: SocketAddr,
    remote: SocketAddr,
) {
    let now = Instant::now();
    let mut flows = recent_flows.lock().unwrap_or_else(|err| err.into_inner());
    flows.retain(|_, updated| now.duration_since(*updated) < RECENT_UDP_FLOW_TTL);
    if flows.len() >= RECENT_UDP_FLOW_CAPACITY
        && !flows.contains_key(&(local, remote))
        && let Some(oldest) = flows
            .iter()
            .min_by_key(|(_, updated)| **updated)
            .map(|(flow, _)| *flow)
    {
        flows.remove(&oldest);
    }
    flows.insert((local, remote), now);
}

fn has_recent_udp_flow(
    recent_flows: &RecentUdpFlows,
    local: SocketAddr,
    remote: SocketAddr,
) -> bool {
    let now = Instant::now();
    let mut flows = recent_flows.lock().unwrap_or_else(|err| err.into_inner());
    flows.retain(|_, updated| now.duration_since(*updated) < RECENT_UDP_FLOW_TTL);
    flows.contains_key(&(local, remote))
}

fn quoted_udp_flow_and_payload(
    payload: &[u8],
) -> Option<(SocketAddr, SocketAddr, &[u8])> {
    let (ip, stop_err) = etherparse::LaxIpSlice::from_slice(payload).ok()?;
    if stop_err.is_some() {
        return None;
    }
    if let etherparse::LaxIpSlice::Ipv4(ipv4) = &ip {
        let header = ipv4.header();
        if header.to_header().calc_header_checksum() != header.header_checksum() {
            return None;
        }
        if ip.payload().fragmented {
            // ICMP can quote the first fragment of a datagram that we source-
            // fragmented. Only offset zero contains the UDP header needed to
            // correlate the error with a recent flow.
            if header.fragments_offset().value() != 0
                || ip.payload().ip_number != etherparse::ip_number::UDP
            {
                return None;
            }
        }
    } else if ip.payload().fragmented {
        // Chimera's MIPS-compatible UDP output inserts Fragment directly after
        // the IPv6 header. Accept a quote of that first fragment so a router's
        // Packet Too Big can still lower the destination PMTU.
        let ipv6 = etherparse::Ipv6HeaderSlice::from_slice(payload).ok()?;
        if ipv6.next_header() != etherparse::ip_number::IPV6_FRAG {
            return None;
        }
        let fragment = etherparse::Ipv6FragmentHeaderSlice::from_slice(
            &payload[etherparse::Ipv6Header::LEN..],
        )
        .ok()?;
        if fragment.fragment_offset().value() != 0
            || fragment.next_header() != etherparse::ip_number::UDP
        {
            return None;
        }
        let udp_offset =
            etherparse::Ipv6Header::LEN + etherparse::Ipv6FragmentHeader::LEN;
        let udp =
            etherparse::UdpHeaderSlice::from_slice(&payload[udp_offset..]).ok()?;
        return Some((
            SocketAddr::new(ip.source_addr(), udp.source_port()),
            SocketAddr::new(ip.destination_addr(), udp.destination_port()),
            &payload[udp_offset + etherparse::UdpHeader::LEN..],
        ));
    }
    let ip_payload = ip.payload();
    if ip_payload.ip_number != etherparse::ip_number::UDP {
        return None;
    }
    let udp = etherparse::UdpHeaderSlice::from_slice(ip_payload.payload).ok()?;
    Some((
        SocketAddr::new(ip.source_addr(), udp.source_port()),
        SocketAddr::new(ip.destination_addr(), udp.destination_port()),
        &ip_payload.payload[etherparse::UdpHeader::LEN..],
    ))
}

pub struct UdpSocket {
    inbound: mpsc::Receiver<Packet>,
    outbound: UdpOutbound,
    path_mtu: PathMtuCache,
    recent_flows: RecentUdpFlows,
    errors: UdpIcmpErrors,
    error_notify: Arc<Notify>,
    receive_errors: Arc<AtomicBool>,
    mtu: usize,
}

impl UdpSocket {
    pub fn new(
        inbound: mpsc::Receiver<Packet>,
        outbound: mpsc::Sender<Packet>,
        mtu: usize,
    ) -> Self {
        Self::new_with_outbound(inbound, UdpOutbound::Channel(outbound), mtu)
    }

    pub(crate) fn new_fair(
        inbound: mpsc::Receiver<Packet>,
        outbound: FairPacketSender,
        mtu: usize,
    ) -> Self {
        Self::new_with_outbound(inbound, UdpOutbound::Fair(outbound), mtu)
    }

    fn new_with_outbound(
        inbound: mpsc::Receiver<Packet>,
        outbound: UdpOutbound,
        mtu: usize,
    ) -> Self {
        Self {
            inbound,
            outbound,
            path_mtu: Arc::new(Mutex::new(HashMap::new())),
            recent_flows: Arc::new(Mutex::new(HashMap::new())),
            errors: Arc::new(Mutex::new(VecDeque::new())),
            error_notify: Arc::new(Notify::new()),
            receive_errors: Arc::new(AtomicBool::new(false)),
            mtu,
        }
    }

    pub(crate) fn icmp_control(&self) -> UdpIcmpControl {
        UdpIcmpControl {
            path_mtu: self.path_mtu.clone(),
            recent_flows: self.recent_flows.clone(),
            errors: self.errors.clone(),
            error_notify: self.error_notify.clone(),
            mtu: self.mtu,
        }
    }

    pub fn split(self) -> (SplitRead, SplitWrite) {
        let read = SplitRead {
            recv: self.inbound,
            fragments: FragmentReassembler::new(etherparse::ip_number::UDP, "UDP"),
            errors: self.errors,
            error_notify: self.error_notify,
            receive_errors: self.receive_errors.clone(),
        };
        let write = SplitWrite {
            send: self.outbound,
            dropped_on_full: Arc::new(AtomicU64::new(0)),
            flow_label_state: RandomState::new(),
            next_fragment_id: Arc::new(AtomicU32::new(rand::random())),
            path_mtu: self.path_mtu,
            recent_flows: self.recent_flows,
            receive_errors: self.receive_errors,
            mtu: self.mtu,
            path_mtu_discovery: PathMtuDiscovery::Dont,
        };
        (read, write)
    }
}

impl UdpIcmpControl {
    pub(crate) fn new(mtu: usize) -> Self {
        Self {
            path_mtu: Arc::new(Mutex::new(HashMap::new())),
            recent_flows: Arc::new(Mutex::new(HashMap::new())),
            errors: Arc::new(Mutex::new(VecDeque::new())),
            error_notify: Arc::new(Notify::new()),
            mtu,
        }
    }

    fn reduce_path_mtu_for_recent_flow(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
        mtu: usize,
    ) -> bool {
        if !has_recent_udp_flow(&self.recent_flows, local, remote) {
            return false;
        }
        let minimum = if remote.is_ipv6() { 1280 } else { 68 };
        if mtu < minimum {
            return false;
        }
        let current = path_mtu_for_cache(&self.path_mtu, self.mtu, remote.ip());
        if mtu >= current {
            return false;
        }
        confirm_path_mtu_cache(&self.path_mtu, self.mtu, remote.ip(), mtu);
        true
    }

    fn record_packet_too_big(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
        offender: IpAddr,
        quoted_payload: &[u8],
        mtu: usize,
    ) -> bool {
        let minimum = if remote.is_ipv6() { 1280 } else { 68 };
        if mtu < minimum || !has_recent_udp_flow(&self.recent_flows, local, remote) {
            return false;
        }
        let mut errors = self.errors.lock().unwrap_or_else(|err| err.into_inner());
        if errors.len() >= UDP_ICMP_ERROR_CAPACITY {
            errors.pop_front();
        }
        errors.push_back(UdpIcmpError {
            local_addr: local,
            remote_addr: remote,
            offender,
            quoted_payload: quoted_payload.into(),
            kind: UdpIcmpErrorKind::PacketTooBig {
                path_mtu: mtu.min(self.mtu),
            },
        });
        drop(errors);
        self.error_notify.notify_one();
        self.reduce_path_mtu_for_recent_flow(local, remote, mtu)
    }

    fn record_icmp_error(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
        offender: IpAddr,
        quoted_payload: &[u8],
        kind: UdpIcmpErrorKind,
    ) -> bool {
        if !has_recent_udp_flow(&self.recent_flows, local, remote) {
            return false;
        }
        let mut errors = self.errors.lock().unwrap_or_else(|err| err.into_inner());
        if errors.len() >= UDP_ICMP_ERROR_CAPACITY {
            errors.pop_front();
        }
        errors.push_back(UdpIcmpError {
            local_addr: local,
            remote_addr: remote,
            offender,
            quoted_payload: quoted_payload.into(),
            kind,
        });
        drop(errors);
        self.error_notify.notify_one();
        true
    }

    fn record_destination_unreachable(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
        offender: IpAddr,
        quoted_payload: &[u8],
        code: u8,
    ) -> bool {
        self.record_icmp_error(
            local,
            remote,
            offender,
            quoted_payload,
            UdpIcmpErrorKind::DestinationUnreachable { code },
        )
    }

    pub(crate) fn apply_packet_too_big(&self, frame: &[u8]) -> bool {
        let outer = match IpPacket::new_checked(frame) {
            Ok(packet) if packet.verify_checksum() => packet,
            _ => return false,
        };
        let sliced = match etherparse::SlicedPacket::from_ip(frame) {
            Ok(packet) => packet,
            Err(_) => return false,
        };

        match sliced.transport {
            Some(etherparse::TransportSlice::Icmpv4(icmp)) => {
                if icmp.icmp_type().calc_checksum(icmp.payload()) != icmp.checksum()
                {
                    return false;
                }
                let mtu = match icmp.icmp_type() {
                    etherparse::Icmpv4Type::DestinationUnreachable(
                        etherparse::icmpv4::DestUnreachableHeader::FragmentationNeeded {
                            next_hop_mtu,
                        },
                    ) if next_hop_mtu != 0 => usize::from(next_hop_mtu),
                    _ => return false,
                };
                let Some((local, remote, quoted_payload)) =
                    quoted_udp_flow_and_payload(icmp.payload())
                else {
                    return false;
                };
                if !local.is_ipv4()
                    || !remote.is_ipv4()
                    || outer.dst_addr() != local.ip()
                {
                    return false;
                }
                self.record_packet_too_big(
                    local,
                    remote,
                    outer.src_addr(),
                    quoted_payload,
                    mtu,
                )
            }
            Some(etherparse::TransportSlice::Icmpv6(icmp)) => {
                let (source, destination) =
                    match (outer.src_addr(), outer.dst_addr()) {
                        (IpAddr::V6(source), IpAddr::V6(destination)) => {
                            (source.octets(), destination.octets())
                        }
                        _ => return false,
                    };
                if !icmp.is_checksum_valid(source, destination) {
                    return false;
                }
                let mtu = match icmp.icmp_type() {
                    etherparse::Icmpv6Type::PacketTooBig { mtu } => mtu as usize,
                    _ => return false,
                };
                let Some((local, remote, quoted_payload)) =
                    quoted_udp_flow_and_payload(icmp.payload())
                else {
                    return false;
                };
                if !local.is_ipv6()
                    || !remote.is_ipv6()
                    || outer.dst_addr() != local.ip()
                {
                    return false;
                }
                self.record_packet_too_big(
                    local,
                    remote,
                    outer.src_addr(),
                    quoted_payload,
                    mtu,
                )
            }
            _ => false,
        }
    }

    pub(crate) fn apply_destination_unreachable(&self, frame: &[u8]) -> bool {
        let outer = match IpPacket::new_checked(frame) {
            Ok(packet) if packet.verify_checksum() => packet,
            _ => return false,
        };
        let sliced = match etherparse::SlicedPacket::from_ip(frame) {
            Ok(packet) => packet,
            Err(_) => return false,
        };
        match sliced.transport {
            Some(etherparse::TransportSlice::Icmpv4(icmp)) => {
                if icmp.icmp_type().calc_checksum(icmp.payload()) != icmp.checksum()
                {
                    return false;
                }
                let code = match icmp.icmp_type() {
                    etherparse::Icmpv4Type::DestinationUnreachable(
                        etherparse::icmpv4::DestUnreachableHeader::FragmentationNeeded { .. },
                    ) => return false,
                    etherparse::Icmpv4Type::DestinationUnreachable(header) => header.code_u8(),
                    _ => return false,
                };
                let Some((local, remote, quoted_payload)) =
                    quoted_udp_flow_and_payload(icmp.payload())
                else {
                    return false;
                };
                if !local.is_ipv4()
                    || !remote.is_ipv4()
                    || outer.dst_addr() != local.ip()
                {
                    return false;
                }
                self.record_destination_unreachable(
                    local,
                    remote,
                    outer.src_addr(),
                    quoted_payload,
                    code,
                )
            }
            Some(etherparse::TransportSlice::Icmpv6(icmp)) => {
                let (source, destination) =
                    match (outer.src_addr(), outer.dst_addr()) {
                        (IpAddr::V6(source), IpAddr::V6(destination)) => {
                            (source.octets(), destination.octets())
                        }
                        _ => return false,
                    };
                if !icmp.is_checksum_valid(source, destination) {
                    return false;
                }
                let code = match icmp.icmp_type() {
                    etherparse::Icmpv6Type::DestinationUnreachable(code) => {
                        code.code_u8()
                    }
                    _ => return false,
                };
                let Some((local, remote, quoted_payload)) =
                    quoted_udp_flow_and_payload(icmp.payload())
                else {
                    return false;
                };
                if !local.is_ipv6()
                    || !remote.is_ipv6()
                    || outer.dst_addr() != local.ip()
                {
                    return false;
                }
                self.record_destination_unreachable(
                    local,
                    remote,
                    outer.src_addr(),
                    quoted_payload,
                    code,
                )
            }
            _ => false,
        }
    }

    pub(crate) fn apply_time_exceeded_or_parameter_problem(
        &self,
        frame: &[u8],
    ) -> bool {
        let outer = match IpPacket::new_checked(frame) {
            Ok(packet) if packet.verify_checksum() => packet,
            _ => return false,
        };
        let sliced = match etherparse::SlicedPacket::from_ip(frame) {
            Ok(packet) => packet,
            Err(_) => return false,
        };
        let (local, remote, quoted_payload, kind) = match sliced.transport {
            Some(etherparse::TransportSlice::Icmpv4(icmp)) => {
                if icmp.icmp_type().calc_checksum(icmp.payload()) != icmp.checksum()
                {
                    return false;
                }
                let kind = match icmp.icmp_type() {
                    etherparse::Icmpv4Type::TimeExceeded(code) => {
                        UdpIcmpErrorKind::TimeExceeded {
                            code: code.code_u8(),
                        }
                    }
                    etherparse::Icmpv4Type::ParameterProblem(header) => {
                        let (code, pointer) = match header {
                            etherparse::icmpv4::ParameterProblemHeader::PointerIndicatesError(
                                pointer,
                            ) => (0, u32::from(pointer)),
                            etherparse::icmpv4::ParameterProblemHeader::MissingRequiredOption => {
                                (1, 0)
                            }
                            etherparse::icmpv4::ParameterProblemHeader::BadLength => (2, 0),
                        };
                        UdpIcmpErrorKind::ParameterProblem { code, pointer }
                    }
                    _ => return false,
                };
                let Some((local, remote, quoted_payload)) =
                    quoted_udp_flow_and_payload(icmp.payload())
                else {
                    return false;
                };
                if !local.is_ipv4()
                    || !remote.is_ipv4()
                    || outer.dst_addr() != local.ip()
                {
                    return false;
                }
                (local, remote, quoted_payload, kind)
            }
            Some(etherparse::TransportSlice::Icmpv6(icmp)) => {
                let (source, destination) =
                    match (outer.src_addr(), outer.dst_addr()) {
                        (IpAddr::V6(source), IpAddr::V6(destination)) => {
                            (source.octets(), destination.octets())
                        }
                        _ => return false,
                    };
                if !icmp.is_checksum_valid(source, destination) {
                    return false;
                }
                let kind = match icmp.icmp_type() {
                    etherparse::Icmpv6Type::TimeExceeded(code) => {
                        UdpIcmpErrorKind::TimeExceeded {
                            code: code.code_u8(),
                        }
                    }
                    etherparse::Icmpv6Type::ParameterProblem(header) => {
                        UdpIcmpErrorKind::ParameterProblem {
                            code: header.code.code_u8(),
                            pointer: header.pointer,
                        }
                    }
                    _ => return false,
                };
                let Some((local, remote, quoted_payload)) =
                    quoted_udp_flow_and_payload(icmp.payload())
                else {
                    return false;
                };
                if !local.is_ipv6()
                    || !remote.is_ipv6()
                    || outer.dst_addr() != local.ip()
                {
                    return false;
                }
                (local, remote, quoted_payload, kind)
            }
            _ => return false,
        };
        self.record_icmp_error(local, remote, outer.src_addr(), quoted_payload, kind)
    }
}

pub struct SplitRead {
    recv: mpsc::Receiver<Packet>,
    fragments: FragmentReassembler,
    errors: UdpIcmpErrors,
    error_notify: Arc<Notify>,
    receive_errors: Arc<AtomicBool>,
}

impl SplitRead {
    /// Select whether correlated asynchronous ICMP errors are reserved for the
    /// explicit error queue.
    ///
    /// This mirrors MIPS's `SetReceiveErrors` policy. The default is `false`.
    /// Chimera's legacy payload-only `recv` API is intentionally unchanged;
    /// ordinary-read error delivery is exposed separately as alignment grows.
    pub fn set_receive_errors(&mut self, enabled: bool) {
        self.receive_errors.store(enabled, Ordering::Relaxed);
    }

    /// Report the current asynchronous ICMP error-delivery policy.
    pub fn receive_errors(&self) -> bool {
        self.receive_errors.load(Ordering::Relaxed)
    }

    /// Read the oldest correlated ICMP error without blocking.
    ///
    /// An empty queue uses Linux's `EAGAIN` result. When `ReceiveErrors` is
    /// enabled, ordinary reads leave this queue exclusively to this method.
    pub fn read_icmp_error(&mut self) -> std::io::Result<UdpIcmpError> {
        self.try_recv_icmp_error()
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EAGAIN))
    }

    /// Read one Linux-style `MessageFlagErrorQueue` message without blocking.
    ///
    /// The message contains the quoted failed payload, original destination,
    /// and one canonical `sock_extended_err` ancillary record. Like MIPS, an
    /// empty error queue returns `EAGAIN`.
    pub fn read_error_queue_message(
        &mut self,
    ) -> std::io::Result<UdpErrorQueueMessage> {
        let error = self.read_icmp_error()?;
        let oob = error
            .socket_error_control()
            .marshal_binary()
            .into_boxed_slice();
        Ok(UdpErrorQueueMessage {
            payload: error.quoted_payload,
            addr: error.remote_addr,
            oob,
        })
    }

    /// Read one error-queue message into caller-provided Linux message buffers.
    ///
    /// The error is consumed even when either output buffer truncates it,
    /// matching Linux/MIPS error-queue reads. `n` and `nn` report bytes copied;
    /// `flags` reports `MSG_TRUNC` and/or `MSG_CTRUNC` when appropriate.
    pub fn read_error_queue_into(
        &mut self,
        payload: &mut [u8],
        oob: &mut [u8],
    ) -> std::io::Result<UdpErrorQueueRead> {
        self.read_error_queue_into_with_flags(payload, oob, 0)
    }

    /// Read an error-queue message with Linux-compatible input flags.
    ///
    /// `MSG_TRUNC` requests the complete quoted payload length in `n` even
    /// when only a prefix fits in `payload`. `MSG_DONTWAIT` is accepted as a
    /// no-op because error-queue reads never block; `MSG_ERRQUEUE` is accepted
    /// because this method already selects that queue. Other flags return
    /// `EOPNOTSUPP` without consuming an error.
    pub fn read_error_queue_into_with_flags(
        &mut self,
        payload: &mut [u8],
        oob: &mut [u8],
        input_flags: i32,
    ) -> std::io::Result<UdpErrorQueueRead> {
        const SUPPORTED_FLAGS: i32 = MESSAGE_FLAG_TRUNCATED
            | MESSAGE_FLAG_DONT_WAIT
            | MESSAGE_FLAG_ERROR_QUEUE;
        if input_flags & !SUPPORTED_FLAGS != 0 {
            return Err(std::io::Error::from_raw_os_error(libc::EOPNOTSUPP));
        }

        let message = self.read_error_queue_message()?;
        let payload_copied = payload.len().min(message.payload.len());
        payload[..payload_copied]
            .copy_from_slice(&message.payload[..payload_copied]);
        let nn = oob.len().min(message.oob.len());
        oob[..nn].copy_from_slice(&message.oob[..nn]);

        let mut flags = 0;
        if payload_copied < message.payload.len() {
            flags |= MESSAGE_FLAG_TRUNCATED;
        }
        if nn < message.oob.len() {
            flags |= MESSAGE_FLAG_CONTROL_TRUNCATED;
        }
        let n = if input_flags & MESSAGE_FLAG_TRUNCATED != 0 {
            message.payload.len()
        } else {
            payload_copied
        };
        Ok(UdpErrorQueueRead {
            n,
            nn,
            flags,
            addr: message.addr,
        })
    }

    /// Return the oldest correlated ICMP error without blocking.
    ///
    /// This compatibility helper predates `ReceiveErrors`; new MIPS-aligned
    /// callers should prefer `read_icmp_error`.
    pub fn try_recv_icmp_error(&mut self) -> Option<UdpIcmpError> {
        self.errors
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .pop_front()
    }

    /// Receive a UDP payload or, in the default `ReceiveErrors(false)` mode,
    /// a correlated asynchronous ICMP error.
    ///
    /// Already queued payloads take precedence over errors, matching MIPS.
    /// Enabling `ReceiveErrors` reserves errors for `read_icmp_error` and makes
    /// this method behave like the legacy payload-only `recv` path.
    pub async fn recv_with_icmp_errors(
        &mut self,
    ) -> Result<Option<UdpPacket>, UdpIcmpError> {
        loop {
            if self.receive_errors() {
                return Ok(self.recv().await);
            }

            if !self.recv.is_empty() {
                return Ok(self.recv().await);
            }
            if let Some(error) = self.try_recv_icmp_error() {
                return Err(error);
            }

            let error_notify = self.error_notify.clone();
            tokio::select! {
                packet = self.recv() => return Ok(packet),
                () = error_notify.notified() => {}
            }
        }
    }

    pub async fn recv(&mut self) -> Option<UdpPacket> {
        while let Some(data) = self.recv.recv().await {
            let packet = match IpPacket::new_checked(data.data()) {
                Ok(p) => p,
                Err(err) => {
                    error!("invalid IP packet: {err}");
                    continue;
                }
            };

            if !packet.verify_checksum() {
                error!("invalid IP checksum");
                continue;
            }

            let fragmented = match crate::fragment::is_fragmented(data.data()) {
                Ok(fragmented) => fragmented,
                Err(err) => {
                    error!("invalid fragmented IP packet: {err}");
                    continue;
                }
            };

            let (src_ip, dst_ip, udp_data) = if fragmented {
                match self.fragments.push(data.data()) {
                    Ok(Some(reassembled)) => (
                        reassembled.template.source_ip(),
                        reassembled.template.destination_ip(),
                        Cow::Owned(reassembled.payload),
                    ),
                    Ok(None) => continue,
                    Err(err) => {
                        error!("invalid UDP fragment sequence: {err}");
                        continue;
                    }
                }
            } else {
                let src_ip = packet.src_addr();
                let dst_ip = packet.dst_addr();
                let sliced = match etherparse::IpSlice::from_slice(data.data()) {
                    Ok(packet) => packet,
                    Err(err) => {
                        error!("invalid IP packet: {err}");
                        continue;
                    }
                };
                let payload = sliced.payload();
                if payload.ip_number != etherparse::ip_number::UDP {
                    error!(
                        "UDP input contained non-UDP payload: {:?}",
                        payload.ip_number
                    );
                    continue;
                }
                (src_ip, dst_ip, Cow::Borrowed(payload.payload))
            };

            let packet = match smoltcp::wire::UdpPacket::new_checked(
                udp_data.as_ref(),
            ) {
                Ok(packet) => packet,
                Err(err) => {
                    error!(
                        "invalid UDP err: {err}, src_ip: {src_ip}, dst_ip: {dst_ip}, \
                         payload: {:?}",
                        udp_data.as_ref()
                    );
                    continue;
                }
            };
            // An all-zero UDP checksum is permitted for IPv4, but IPv6 makes
            // the UDP checksum mandatory. smoltcp intentionally accepts zero
            // for both families, so enforce the IPv6 rule at this boundary.
            if (src_ip.is_ipv6() && packet.checksum() == 0)
                || !packet.verify_checksum(&src_ip.into(), &dst_ip.into())
            {
                error!("invalid UDP checksum: {src_ip} -> {dst_ip}");
                continue;
            }
            let src_port = packet.src_port();
            let dst_port = packet.dst_port();

            let src_addr = SocketAddr::new(src_ip, src_port);
            let dst_addr = SocketAddr::new(dst_ip, dst_port);

            trace!("created UDP socket for {src_addr} <-> {dst_addr}");

            return Some(UdpPacket {
                data: Packet::new(packet.payload().to_vec()),
                local_addr: src_addr,
                remote_addr: dst_addr,
            });
        }

        None
    }
}

#[derive(Clone)]
pub struct SplitWrite {
    send: UdpOutbound,
    dropped_on_full: Arc<AtomicU64>,
    flow_label_state: RandomState,
    next_fragment_id: Arc<AtomicU32>,
    path_mtu: PathMtuCache,
    recent_flows: RecentUdpFlows,
    receive_errors: Arc<AtomicBool>,
    mtu: usize,
    path_mtu_discovery: PathMtuDiscovery,
}

impl SplitWrite {
    /// Select the MIPS-compatible path-MTU discovery policy for this writer.
    pub fn set_path_mtu_discovery(&mut self, policy: PathMtuDiscovery) {
        self.path_mtu_discovery = policy;
    }

    /// Return the writer's current path-MTU discovery policy.
    pub fn path_mtu_discovery(&self) -> PathMtuDiscovery {
        self.path_mtu_discovery
    }
    /// Record an application-confirmed path MTU for one destination.
    ///
    /// Values below the protocol minimum are ignored. Values above the link
    /// MTU are clamped because this stack cannot emit a larger L3 packet.
    pub fn confirm_path_mtu_for(&self, destination: IpAddr, mtu: usize) {
        confirm_path_mtu_cache(&self.path_mtu, self.mtu, destination, mtu);
    }

    /// Return the confirmed path MTU, falling back to the embedding link MTU.
    pub fn path_mtu_for(&self, destination: IpAddr) -> usize {
        path_mtu_for_cache(&self.path_mtu, self.mtu, destination)
    }

    /// Send one explicit PLPMTU probe without source fragmentation.
    ///
    /// Like MIPS `WritePathMTUProbe`, this ignores a lower confirmed
    /// destination PMTU but still enforces the first-hop MTU. Sending the
    /// probe does not raise the PMTU cache; callers must confirm delivery with
    /// [`Self::confirm_path_mtu_for`].
    pub async fn send_path_mtu_probe(
        &mut self,
        packet: UdpPacket,
    ) -> Result<(), std::io::Error> {
        let previous = self.path_mtu_discovery;
        self.path_mtu_discovery = PathMtuDiscovery::Probe;
        let result = self.send(packet).await;
        self.path_mtu_discovery = previous;
        result
    }

    fn fragment_identification(&self) -> u32 {
        self.next_fragment_id.fetch_add(1, Ordering::Relaxed)
    }

    fn ipv4_identification(&self) -> u16 {
        loop {
            let identification = self.fragment_identification() as u16;
            if identification != 0 {
                return identification;
            }
        }
    }

    fn ipv6_flow_label(&self, source: SocketAddr, target: SocketAddr) -> u32 {
        let mut hasher = self.flow_label_state.build_hasher();
        source.hash(&mut hasher);
        target.hash(&mut hasher);
        etherparse::ip_number::UDP.0.hash(&mut hasher);
        let label = (hasher.finish() as u32) & 0x000f_ffff;
        label.max(1)
    }

    fn record_queue_drop(&self) {
        let dropped = self.dropped_on_full.fetch_add(1, Ordering::Relaxed) + 1;
        if dropped == 1 || dropped.is_power_of_two() {
            warn!(
                "dropping UDP datagram because outbound queue is full; total dropped on this split writer: {dropped}"
            );
        }
    }

    fn try_send_output(
        &self,
        packet: Packet,
        flow: &OutboundFlowKey,
    ) -> Result<bool, std::io::Error> {
        let outcome = match &self.send {
            UdpOutbound::Channel(sender) => match sender.try_send(packet) {
                Ok(()) => BestEffortSend::Enqueued,
                Err(mpsc::error::TrySendError::Full(_)) => BestEffortSend::Full,
                Err(mpsc::error::TrySendError::Closed(_)) => BestEffortSend::Closed,
            },
            UdpOutbound::Fair(sender) => {
                sender.try_send_best_effort(packet, flow.clone())
            }
        };

        match outcome {
            BestEffortSend::Enqueued => Ok(true),
            BestEffortSend::Replaced => {
                self.record_queue_drop();
                Ok(true)
            }
            BestEffortSend::Full => {
                self.record_queue_drop();
                if self.receive_errors.load(Ordering::Relaxed) {
                    Err(std::io::Error::from_raw_os_error(libc::ENOBUFS))
                } else {
                    Ok(false)
                }
            }
            BestEffortSend::Closed => {
                Err(std::io::Error::other("packet outbound channel closed"))
            }
        }
    }

    fn try_send_fragments(
        &self,
        fragments: Vec<Packet>,
        flow: &OutboundFlowKey,
    ) -> Result<(), std::io::Error> {
        // MIPS admits source-fragmented external output one fragment at a time
        // in wire order. A full fair queue may replace one already-published
        // packet from the fattest flow; earlier fragments are not rolled back.
        for fragment in fragments {
            if !self.try_send_output(fragment, flow)? {
                return Ok(());
            }
        }
        Ok(())
    }

    fn try_send_packet(
        &self,
        packet: Packet,
        flow: &OutboundFlowKey,
    ) -> Result<(), std::io::Error> {
        self.try_send_output(packet, flow).map(|_| ())
    }

    fn send_ipv4_fragments(
        &self,
        packet: &[u8],
        mtu: usize,
        flow: &OutboundFlowKey,
    ) -> Result<(), std::io::Error> {
        const IPV4_HEADER_LEN: usize = 20;
        if mtu <= IPV4_HEADER_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "UDP MTU is too small for an IPv4 header",
            ));
        }

        let max_fragment_payload = ((mtu - IPV4_HEADER_LEN) / 8) * 8;
        if max_fragment_payload == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "UDP MTU is too small for IPv4 fragmentation",
            ));
        }

        let full_header = etherparse::Ipv4HeaderSlice::from_slice(packet)
            .map_err(std::io::Error::other)?;
        let payload = &packet[full_header.slice().len()..];
        // `send` assigns the datagram identification before deciding whether
        // fragmentation is needed. Preserve that ID across every fragment
        // rather than consuming a second sequence value here.
        let identification = full_header.identification();
        let mut fragments =
            Vec::with_capacity(payload.len().div_ceil(max_fragment_payload));

        for (index, chunk) in payload.chunks(max_fragment_payload).enumerate() {
            let offset_bytes = index * max_fragment_payload;
            let more_fragments = offset_bytes + chunk.len() < payload.len();
            let mut header = etherparse::Ipv4Header::new(
                chunk.len() as u16,
                full_header.ttl(),
                full_header.protocol(),
                full_header.source(),
                full_header.destination(),
            )
            .map_err(std::io::Error::other)?;
            header.identification = identification;
            header.dont_fragment = false;
            header.more_fragments = more_fragments;
            header.fragment_offset = etherparse::IpFragOffset::try_new(
                u16::try_from(offset_bytes / 8).map_err(std::io::Error::other)?,
            )
            .map_err(std::io::Error::other)?;
            header.header_checksum = header.calc_header_checksum();

            let mut out = header.to_bytes().to_vec();
            out.extend_from_slice(chunk);
            fragments.push(Packet::new(out));
        }

        self.try_send_fragments(fragments, flow)
    }

    fn send_ipv6_fragments(
        &self,
        packet: &[u8],
        mtu: usize,
        flow: &OutboundFlowKey,
    ) -> Result<(), std::io::Error> {
        const IPV6_HEADER_LEN: usize = 40;
        const FRAGMENT_HEADER_LEN: usize = etherparse::Ipv6FragmentHeader::LEN;
        if mtu <= IPV6_HEADER_LEN + FRAGMENT_HEADER_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "UDP MTU is too small for IPv6 fragmentation",
            ));
        }

        let max_fragment_payload =
            ((mtu - IPV6_HEADER_LEN - FRAGMENT_HEADER_LEN) / 8) * 8;
        if max_fragment_payload == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "UDP MTU is too small for IPv6 fragmentation",
            ));
        }

        let full_header = etherparse::Ipv6HeaderSlice::from_slice(packet)
            .map_err(std::io::Error::other)?;
        let payload = &packet[IPV6_HEADER_LEN..];
        let identification = self.fragment_identification();
        let mut fragments =
            Vec::with_capacity(payload.len().div_ceil(max_fragment_payload));

        for (index, chunk) in payload.chunks(max_fragment_payload).enumerate() {
            let offset_bytes = index * max_fragment_payload;
            let more_fragments = offset_bytes + chunk.len() < payload.len();
            let header = etherparse::Ipv6Header {
                traffic_class: full_header.traffic_class(),
                flow_label: full_header.flow_label(),
                payload_length: u16::try_from(FRAGMENT_HEADER_LEN + chunk.len())
                    .map_err(std::io::Error::other)?,
                next_header: etherparse::ip_number::IPV6_FRAG,
                hop_limit: full_header.hop_limit(),
                source: full_header.source(),
                destination: full_header.destination(),
            };
            let fragment = etherparse::Ipv6FragmentHeader::new(
                full_header.next_header(),
                etherparse::IpFragOffset::try_new(
                    u16::try_from(offset_bytes / 8)
                        .map_err(std::io::Error::other)?,
                )
                .map_err(std::io::Error::other)?,
                more_fragments,
                identification,
            );

            let mut out = header.to_bytes().to_vec();
            out.extend_from_slice(&fragment.to_bytes());
            out.extend_from_slice(chunk);
            fragments.push(Packet::new(out));
        }

        self.try_send_fragments(fragments, flow)
    }

    pub async fn send(&mut self, packet: UdpPacket) -> Result<(), std::io::Error> {
        let output_flow =
            OutboundFlowKey::udp(packet.local_addr, packet.remote_addr);
        let builder = match (packet.local_addr, packet.remote_addr) {
            (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
                PacketBuilder::ipv4(src.ip().octets(), dst.ip().octets(), 64)
                    .udp(src.port(), dst.port())
            }
            (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
                PacketBuilder::ipv6(src.ip().octets(), dst.ip().octets(), 64)
                    .udp(src.port(), dst.port())
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "UDP socket only supports IPv4 and IPv6",
                ));
            }
        };

        let mut ip_packet_writer =
            Vec::with_capacity(builder.size(packet.data.data().len()));
        builder
            .write(&mut ip_packet_writer, packet.data.data())
            .map_err(std::io::Error::other)?;

        let path_mtu = match self.path_mtu_discovery {
            PathMtuDiscovery::Dont
            | PathMtuDiscovery::Want
            | PathMtuDiscovery::Do => self.path_mtu_for(packet.remote_addr.ip()),
            PathMtuDiscovery::Probe
            | PathMtuDiscovery::Interface
            | PathMtuDiscovery::Omit => self.mtu,
        };
        let oversized = ip_packet_writer.len() > path_mtu;

        // MIPS's default PathMTUDiscoveryDont policy keeps IPv4 datagrams
        // fragmentable. Want requests DF when the packet already fits the
        // confirmed PMTU. Probe and Do always request DF; Interface and Omit
        // leave it clear while using the first-hop MTU instead of cached PMTU.
        if packet.local_addr.is_ipv4() && packet.remote_addr.is_ipv4() {
            let mut header = etherparse::Ipv4Header::from_slice(&ip_packet_writer)
                .map_err(std::io::Error::other)?
                .0;
            header.identification = self.ipv4_identification();
            header.dont_fragment = match self.path_mtu_discovery {
                PathMtuDiscovery::Dont
                | PathMtuDiscovery::Interface
                | PathMtuDiscovery::Omit => false,
                PathMtuDiscovery::Want => !oversized,
                PathMtuDiscovery::Do | PathMtuDiscovery::Probe => true,
            };
            header.header_checksum = header.calc_header_checksum();
            ip_packet_writer[..header.header_len()]
                .copy_from_slice(&header.to_bytes());
        } else if packet.local_addr.is_ipv6() && packet.remote_addr.is_ipv6() {
            let mut header = etherparse::Ipv6Header::from_slice(&ip_packet_writer)
                .map_err(std::io::Error::other)?
                .0;
            header.flow_label = etherparse::Ipv6FlowLabel::try_new(
                self.ipv6_flow_label(packet.local_addr, packet.remote_addr),
            )
            .map_err(std::io::Error::other)?;
            ip_packet_writer[..40].copy_from_slice(&header.to_bytes());
        }

        if oversized
            && matches!(
                self.path_mtu_discovery,
                PathMtuDiscovery::Do
                    | PathMtuDiscovery::Probe
                    | PathMtuDiscovery::Interface
            )
        {
            return Err(std::io::Error::from_raw_os_error(libc::EMSGSIZE));
        }

        // Only packets admitted to the output path may authorize a later ICMP
        // PMTU update. In particular, a local EMSGSIZE must not create a
        // recent-flow correlation for a datagram that never left this stack.
        // Linux-compatible Interface/Omit modes ignore ICMP PMTU feedback for
        // this socket, so omit those writes from the shared recent-flow table.
        if !matches!(
            self.path_mtu_discovery,
            PathMtuDiscovery::Interface | PathMtuDiscovery::Omit
        ) {
            record_recent_udp_flow(
                &self.recent_flows,
                packet.local_addr,
                packet.remote_addr,
            );
        }
        if oversized {
            if packet.local_addr.is_ipv4() && packet.remote_addr.is_ipv4() {
                return self.send_ipv4_fragments(
                    &ip_packet_writer,
                    path_mtu,
                    &output_flow,
                );
            }
            if packet.local_addr.is_ipv6() && packet.remote_addr.is_ipv6() {
                return self.send_ipv6_fragments(
                    &ip_packet_writer,
                    path_mtu,
                    &output_flow,
                );
            }
        }

        // UDP is inherently unreliable; drop the packet if the outbound
        // channel is full rather than blocking the UDP handler task.
        self.try_send_packet(Packet::new(ip_packet_writer), &output_flow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn writer_with_fragment_id(next: u32) -> SplitWrite {
        let (send, _recv) = mpsc::channel(1);
        SplitWrite {
            send: UdpOutbound::Channel(send),
            dropped_on_full: Arc::new(AtomicU64::new(0)),
            flow_label_state: RandomState::new(),
            next_fragment_id: Arc::new(AtomicU32::new(next)),
            path_mtu: Arc::new(Mutex::new(HashMap::new())),
            recent_flows: Arc::new(Mutex::new(HashMap::new())),
            receive_errors: Arc::new(AtomicBool::new(false)),
            mtu: 1500,
            path_mtu_discovery: PathMtuDiscovery::Dont,
        }
    }

    fn build_udp_packet(local: SocketAddr, remote: SocketAddr) -> Vec<u8> {
        let builder = match (local, remote) {
            (SocketAddr::V4(local), SocketAddr::V4(remote)) => {
                PacketBuilder::ipv4(local.ip().octets(), remote.ip().octets(), 64)
                    .udp(local.port(), remote.port())
            }
            (SocketAddr::V6(local), SocketAddr::V6(remote)) => {
                PacketBuilder::ipv6(local.ip().octets(), remote.ip().octets(), 64)
                    .udp(local.port(), remote.port())
            }
            _ => panic!("mixed address families are not supported"),
        };
        let mut packet = Vec::new();
        builder.write(&mut packet, &[0x5a; 32]).unwrap();
        packet
    }

    fn build_icmpv4_fragmentation_needed_to(
        quoted: &[u8],
        next_hop_mtu: u16,
        destination: [u8; 4],
    ) -> Vec<u8> {
        let builder = PacketBuilder::ipv4([203, 0, 113, 1], destination, 64).icmpv4(
            etherparse::Icmpv4Type::DestinationUnreachable(
                etherparse::icmpv4::DestUnreachableHeader::FragmentationNeeded {
                    next_hop_mtu,
                },
            ),
        );
        let mut packet = Vec::new();
        builder.write(&mut packet, quoted).unwrap();
        packet
    }

    fn build_icmpv4_fragmentation_needed(
        quoted: &[u8],
        next_hop_mtu: u16,
    ) -> Vec<u8> {
        build_icmpv4_fragmentation_needed_to(quoted, next_hop_mtu, [192, 0, 2, 10])
    }

    fn build_icmpv4_port_unreachable(quoted: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::ipv4([203, 0, 113, 1], [192, 0, 2, 10], 64)
            .icmpv4(etherparse::Icmpv4Type::DestinationUnreachable(
                etherparse::icmpv4::DestUnreachableHeader::Port,
            ));
        let mut packet = Vec::new();
        builder.write(&mut packet, quoted).unwrap();
        packet
    }

    fn build_icmpv4_time_exceeded(quoted: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::ipv4([203, 0, 113, 1], [192, 0, 2, 10], 64)
            .icmpv4(etherparse::Icmpv4Type::TimeExceeded(
                etherparse::icmpv4::TimeExceededCode::TtlExceededInTransit,
            ));
        let mut packet = Vec::new();
        builder.write(&mut packet, quoted).unwrap();
        packet
    }

    fn build_icmpv4_parameter_problem(quoted: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::ipv4([203, 0, 113, 1], [192, 0, 2, 10], 64)
            .icmpv4(etherparse::Icmpv4Type::ParameterProblem(
                etherparse::icmpv4::ParameterProblemHeader::PointerIndicatesError(8),
            ));
        let mut packet = Vec::new();
        builder.write(&mut packet, quoted).unwrap();
        packet
    }

    fn build_icmpv6_packet_too_big_to(
        quoted: &[u8],
        mtu: u32,
        destination: std::net::Ipv6Addr,
    ) -> Vec<u8> {
        let builder = PacketBuilder::ipv6(
            "2001:db8:ffff::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
            destination.octets(),
            64,
        )
        .icmpv6(etherparse::Icmpv6Type::PacketTooBig { mtu });
        let mut packet = Vec::new();
        builder.write(&mut packet, quoted).unwrap();
        packet
    }

    fn build_icmpv6_packet_too_big(quoted: &[u8], mtu: u32) -> Vec<u8> {
        build_icmpv6_packet_too_big_to(quoted, mtu, "2001:db8::10".parse().unwrap())
    }

    fn build_icmpv6_parameter_problem(quoted: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::ipv6(
            "2001:db8:ffff::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
            "2001:db8::10"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
            64,
        )
        .icmpv6(etherparse::Icmpv6Type::ParameterProblem(
            etherparse::icmpv6::ParameterProblemHeader {
                code: etherparse::icmpv6::ParameterProblemCode::ErroneousHeaderField,
                pointer: 12,
            },
        ));
        let mut packet = Vec::new();
        builder.write(&mut packet, quoted).unwrap();
        packet
    }

    fn build_icmpv6_time_exceeded(quoted: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::ipv6(
            "2001:db8:ffff::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
            "2001:db8::10"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
            64,
        )
        .icmpv6(etherparse::Icmpv6Type::TimeExceeded(
            etherparse::icmpv6::TimeExceededCode::HopLimitExceeded,
        ));
        let mut packet = Vec::new();
        builder.write(&mut packet, quoted).unwrap();
        packet
    }

    fn build_icmpv6_port_unreachable(quoted: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::ipv6(
            "2001:db8:ffff::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
            "2001:db8::10"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
            64,
        )
        .icmpv6(etherparse::Icmpv6Type::DestinationUnreachable(
            etherparse::icmpv6::DestUnreachableCode::Port,
        ));
        let mut packet = Vec::new();
        builder.write(&mut packet, quoted).unwrap();
        packet
    }

    #[test]
    fn confirmed_path_mtu_is_bounded_and_family_validated() {
        let writer = writer_with_fragment_id(1);
        let ipv4 = "192.0.2.1".parse().unwrap();
        let ipv6 = "2001:db8::1".parse().unwrap();

        assert_eq!(writer.path_mtu_for(ipv4), 1500);
        writer.confirm_path_mtu_for(ipv4, 1200);
        assert_eq!(writer.path_mtu_for(ipv4), 1200);
        writer.confirm_path_mtu_for(ipv4, 9000);
        assert_eq!(writer.path_mtu_for(ipv4), 1500);

        writer.confirm_path_mtu_for(ipv6, 1279);
        assert_eq!(writer.path_mtu_for(ipv6), 1500);
        writer.confirm_path_mtu_for(ipv6, 1280);
        assert_eq!(writer.path_mtu_for(ipv6), 1280);
    }

    #[test]
    fn icmp_path_mtu_update_can_only_reduce_confirmed_value() {
        let writer = writer_with_fragment_id(1);
        let control = UdpIcmpControl {
            path_mtu: writer.path_mtu.clone(),
            recent_flows: writer.recent_flows.clone(),
            errors: Arc::new(Mutex::new(VecDeque::new())),
            error_notify: Arc::new(Notify::new()),
            mtu: writer.mtu,
        };
        let local: SocketAddr = "192.0.2.10:4000".parse().unwrap();
        let remote: SocketAddr = "192.0.2.1:5000".parse().unwrap();
        record_recent_udp_flow(&writer.recent_flows, local, remote);

        assert!(control.reduce_path_mtu_for_recent_flow(local, remote, 1200));
        assert_eq!(writer.path_mtu_for(remote.ip()), 1200);
        assert!(!control.reduce_path_mtu_for_recent_flow(local, remote, 1400));
        assert_eq!(writer.path_mtu_for(remote.ip()), 1200);
        assert!(!control.reduce_path_mtu_for_recent_flow(local, remote, 67));
        assert_eq!(writer.path_mtu_for(remote.ip()), 1200);

        writer.confirm_path_mtu_for(remote.ip(), 1400);
        assert_eq!(writer.path_mtu_for(remote.ip()), 1400);
    }

    #[tokio::test]
    async fn recent_udp_flow_gates_icmp_pmtu_reduction() {
        let (_input_tx, input_rx) = mpsc::channel(1);
        let (output_tx, _output_rx) = mpsc::channel(8);
        let socket = UdpSocket::new(input_rx, output_tx, 1500);
        let control = socket.icmp_control();
        let (_reader, mut writer) = socket.split();
        let local: SocketAddr = "192.0.2.10:4000".parse().unwrap();
        let remote: SocketAddr = "198.51.100.20:5000".parse().unwrap();

        writer
            .send((vec![1, 2, 3], local, remote).into())
            .await
            .unwrap();

        assert!(control.reduce_path_mtu_for_recent_flow(local, remote, 1200));
        assert_eq!(writer.path_mtu_for(remote.ip()), 1200);
        assert!(!control.reduce_path_mtu_for_recent_flow(
            local,
            "198.51.100.20:5001".parse().unwrap(),
            1000,
        ));
        assert_eq!(writer.path_mtu_for(remote.ip()), 1200);
    }

    #[tokio::test]
    async fn validated_packet_too_big_is_available_on_async_error_queue() {
        let (_input_tx, input_rx) = mpsc::channel(1);
        let (output_tx, _output_rx) = mpsc::channel(8);
        let socket = UdpSocket::new(input_rx, output_tx, 1500);
        let control = socket.icmp_control();
        let (mut reader, mut writer) = socket.split();
        let local: SocketAddr = "192.0.2.10:4000".parse().unwrap();
        let remote: SocketAddr = "198.51.100.20:5000".parse().unwrap();

        assert_eq!(reader.try_recv_icmp_error(), None);
        writer
            .send((vec![0x5a; 32], local, remote).into())
            .await
            .unwrap();
        let quoted = build_udp_packet(local, remote);
        let icmp = build_icmpv4_fragmentation_needed(&quoted[..28], 1200);
        assert!(control.apply_packet_too_big(&icmp));
        assert!(!control.apply_destination_unreachable(&icmp));

        assert_eq!(
            reader.try_recv_icmp_error(),
            Some(UdpIcmpError {
                local_addr: local,
                remote_addr: remote,
                offender: "203.0.113.1".parse().unwrap(),
                quoted_payload: Box::default(),
                kind: UdpIcmpErrorKind::PacketTooBig { path_mtu: 1200 },
            })
        );
        assert_eq!(reader.try_recv_icmp_error(), None);
    }

    #[tokio::test]
    async fn validated_destination_unreachable_is_available_on_async_error_queue() {
        let (_input_tx, input_rx) = mpsc::channel(1);
        let (output_tx, _output_rx) = mpsc::channel(8);
        let socket = UdpSocket::new(input_rx, output_tx, 1500);
        let control = socket.icmp_control();
        let (mut reader, mut writer) = socket.split();
        let local: SocketAddr = "192.0.2.10:4000".parse().unwrap();
        let remote: SocketAddr = "198.51.100.20:5000".parse().unwrap();
        writer
            .send((vec![0x5a; 32], local, remote).into())
            .await
            .unwrap();

        let quoted = build_udp_packet(local, remote);
        let icmp = build_icmpv4_port_unreachable(&quoted);
        assert!(control.apply_destination_unreachable(&icmp));
        assert_eq!(
            reader.try_recv_icmp_error(),
            Some(UdpIcmpError {
                local_addr: local,
                remote_addr: remote,
                offender: "203.0.113.1".parse().unwrap(),
                quoted_payload: vec![0x5a; 32].into_boxed_slice(),
                kind: UdpIcmpErrorKind::DestinationUnreachable { code: 3 },
            })
        );
    }

    #[tokio::test]
    async fn validated_ipv6_destination_unreachable_is_available_on_async_error_queue()
     {
        let (_input_tx, input_rx) = mpsc::channel(1);
        let (output_tx, _output_rx) = mpsc::channel(8);
        let socket = UdpSocket::new(input_rx, output_tx, 1500);
        let control = socket.icmp_control();
        let (mut reader, mut writer) = socket.split();
        let local: SocketAddr = "[2001:db8::10]:4000".parse().unwrap();
        let remote: SocketAddr = "[2001:db8::20]:5000".parse().unwrap();
        writer
            .send((vec![0x5a; 32], local, remote).into())
            .await
            .unwrap();

        let quoted = build_udp_packet(local, remote);
        let icmp = build_icmpv6_port_unreachable(&quoted[..48]);
        assert!(control.apply_destination_unreachable(&icmp));
        assert_eq!(
            reader.try_recv_icmp_error().unwrap().kind,
            UdpIcmpErrorKind::DestinationUnreachable { code: 4 }
        );
    }

    #[test]
    fn async_icmpv4_time_exceeded_is_correlated() {
        let (send, recv) = mpsc::channel(1);
        let socket = UdpSocket::new(recv, send, 1500);
        let control = socket.icmp_control();
        let (mut reader, writer) = socket.split();
        let local = "192.0.2.10:40000".parse().unwrap();
        let remote = "198.51.100.20:53".parse().unwrap();
        record_recent_udp_flow(&writer.recent_flows, local, remote);
        let quoted = build_udp_packet(local, remote);

        assert!(control.apply_time_exceeded_or_parameter_problem(
            &build_icmpv4_time_exceeded(&quoted)
        ));
        assert_eq!(
            reader.try_recv_icmp_error(),
            Some(UdpIcmpError {
                local_addr: local,
                remote_addr: remote,
                offender: "203.0.113.1".parse().unwrap(),
                quoted_payload: vec![0x5a; 32].into_boxed_slice(),
                kind: UdpIcmpErrorKind::TimeExceeded { code: 0 },
            })
        );
    }

    #[test]
    fn async_icmpv6_time_exceeded_is_correlated() {
        let (send, recv) = mpsc::channel(1);
        let socket = UdpSocket::new(recv, send, 1500);
        let control = socket.icmp_control();
        let (mut reader, writer) = socket.split();
        let local = "[2001:db8::10]:40000".parse().unwrap();
        let remote = "[2001:db8::20]:53".parse().unwrap();
        record_recent_udp_flow(&writer.recent_flows, local, remote);
        let quoted = build_udp_packet(local, remote);

        assert!(control.apply_time_exceeded_or_parameter_problem(
            &build_icmpv6_time_exceeded(&quoted)
        ));
        assert_eq!(
            reader.try_recv_icmp_error(),
            Some(UdpIcmpError {
                local_addr: local,
                remote_addr: remote,
                offender: "2001:db8:ffff::1".parse().unwrap(),
                quoted_payload: vec![0x5a; 32].into_boxed_slice(),
                kind: UdpIcmpErrorKind::TimeExceeded { code: 0 },
            })
        );
    }

    #[test]
    fn socket_error_control_matches_linux_icmp_metadata() {
        let v4 = UdpIcmpError {
            local_addr: "192.0.2.10:4000".parse().unwrap(),
            remote_addr: "198.51.100.20:5000".parse().unwrap(),
            offender: "203.0.113.1".parse().unwrap(),
            quoted_payload: vec![1, 2, 3].into_boxed_slice(),
            kind: UdpIcmpErrorKind::DestinationUnreachable { code: 3 },
        };
        assert_eq!(
            v4.socket_error_control(),
            SocketErrorControlMessage {
                errno: 111,
                origin: 2,
                icmp_type: 3,
                code: 3,
                info: 0,
                offender: "203.0.113.1".parse().unwrap(),
            }
        );

        let v6 = UdpIcmpError {
            local_addr: "[2001:db8::10]:4000".parse().unwrap(),
            remote_addr: "[2001:db8::20]:5000".parse().unwrap(),
            offender: "2001:db8:ffff::1".parse().unwrap(),
            quoted_payload: Box::default(),
            kind: UdpIcmpErrorKind::PacketTooBig { path_mtu: 1280 },
        };
        assert_eq!(
            v6.socket_error_control(),
            SocketErrorControlMessage {
                errno: 90,
                origin: 3,
                icmp_type: 2,
                code: 0,
                info: 1280,
                offender: "2001:db8:ffff::1".parse().unwrap(),
            }
        );
    }

    #[test]
    fn socket_error_control_binary_round_trips_linux_layout() {
        for control in [
            SocketErrorControlMessage {
                errno: 111,
                origin: 2,
                icmp_type: 3,
                code: 3,
                info: 0,
                offender: "203.0.113.1".parse().unwrap(),
            },
            SocketErrorControlMessage {
                errno: 90,
                origin: 3,
                icmp_type: 2,
                code: 0,
                info: 1280,
                offender: "::ffff:192.0.2.1".parse().unwrap(),
            },
        ] {
            let encoded = control.marshal_binary();
            assert_eq!(
                encoded.len(),
                if control.offender.is_ipv4() { 48 } else { 64 }
            );
            assert_eq!(SocketErrorControlMessage::parse(&encoded).unwrap(), control);
        }
    }

    #[test]
    fn socket_error_control_parse_skips_unrelated_cmsg() {
        let control = SocketErrorControlMessage {
            errno: 113,
            origin: 2,
            icmp_type: 11,
            code: 0,
            info: 0,
            offender: "198.51.100.1".parse().unwrap(),
        };
        let mut compound = Vec::new();
        compound.extend_from_slice(&16u64.to_le_bytes());
        compound.extend_from_slice(&1i32.to_le_bytes());
        compound.extend_from_slice(&2i32.to_le_bytes());
        control.append_binary(&mut compound);
        assert_eq!(
            SocketErrorControlMessage::parse(&compound).unwrap(),
            control
        );
    }

    #[test]
    fn async_icmp_parameter_problem_preserves_code_and_pointer() {
        let (send, recv) = mpsc::channel(1);
        let socket = UdpSocket::new(recv, send, 1500);
        let control = socket.icmp_control();
        let (mut reader, writer) = socket.split();
        let local_v4 = "192.0.2.10:40000".parse().unwrap();
        let remote_v4 = "198.51.100.20:53".parse().unwrap();
        let local_v6 = "[2001:db8::10]:40000".parse().unwrap();
        let remote_v6 = "[2001:db8::20]:53".parse().unwrap();
        record_recent_udp_flow(&writer.recent_flows, local_v4, remote_v4);
        record_recent_udp_flow(&writer.recent_flows, local_v6, remote_v6);

        assert!(control.apply_time_exceeded_or_parameter_problem(
            &build_icmpv4_parameter_problem(&build_udp_packet(local_v4, remote_v4))
        ));
        assert_eq!(
            reader.try_recv_icmp_error().unwrap().kind,
            UdpIcmpErrorKind::ParameterProblem {
                code: 0,
                pointer: 8,
            }
        );
        assert!(control.apply_time_exceeded_or_parameter_problem(
            &build_icmpv6_parameter_problem(&build_udp_packet(local_v6, remote_v6))
        ));
        assert_eq!(
            reader.try_recv_icmp_error().unwrap().kind,
            UdpIcmpErrorKind::ParameterProblem {
                code: 0,
                pointer: 12,
            }
        );
    }

    #[test]
    fn error_queue_message_returns_quote_destination_and_extended_error() {
        let (send, recv) = mpsc::channel(1);
        let socket = UdpSocket::new(recv, send, 1500);
        let control = socket.icmp_control();
        let (mut reader, writer) = socket.split();
        let local = "192.0.2.10:40000".parse().unwrap();
        let remote = "198.51.100.20:53".parse().unwrap();
        record_recent_udp_flow(&writer.recent_flows, local, remote);
        let failed = build_udp_packet(local, remote);
        assert!(
            control.apply_destination_unreachable(&build_icmpv4_port_unreachable(
                &failed
            ))
        );

        let message = reader.read_error_queue_message().unwrap();
        assert_eq!(&*message.payload, &[0x5a; 32]);
        assert_eq!(message.addr, remote);
        assert_eq!(
            SocketErrorControlMessage::parse(&message.oob).unwrap(),
            SocketErrorControlMessage {
                errno: 111,
                origin: 2,
                icmp_type: 3,
                code: 3,
                info: 0,
                offender: "203.0.113.1".parse().unwrap(),
            }
        );
        assert_eq!(
            reader
                .read_error_queue_message()
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EAGAIN)
        );
    }

    #[test]
    fn error_queue_buffer_read_reports_payload_and_control_truncation() {
        let (send, recv) = mpsc::channel(1);
        let socket = UdpSocket::new(recv, send, 1500);
        let control = socket.icmp_control();
        let (mut reader, writer) = socket.split();
        let local = "192.0.2.10:40000".parse().unwrap();
        let remote = "198.51.100.20:53".parse().unwrap();
        record_recent_udp_flow(&writer.recent_flows, local, remote);
        let failed = build_udp_packet(local, remote);
        assert!(
            control.apply_destination_unreachable(&build_icmpv4_port_unreachable(
                &failed
            ))
        );

        let mut payload = [0u8; 8];
        let mut oob = [0u8; 24];
        let result = reader
            .read_error_queue_into(&mut payload, &mut oob)
            .unwrap();
        assert_eq!(payload, [0x5a; 8]);
        assert_eq!(result.n, payload.len());
        assert_eq!(result.nn, oob.len());
        assert_eq!(result.addr, remote);
        assert_eq!(
            result.flags,
            MESSAGE_FLAG_TRUNCATED | MESSAGE_FLAG_CONTROL_TRUNCATED
        );
        assert_eq!(
            reader
                .read_error_queue_into(&mut payload, &mut oob)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EAGAIN),
            "truncated reads must still consume the queued error"
        );
    }

    #[test]
    fn error_queue_buffer_read_without_truncation_has_no_result_flags() {
        let (send, recv) = mpsc::channel(1);
        let socket = UdpSocket::new(recv, send, 1500);
        let control = socket.icmp_control();
        let (mut reader, writer) = socket.split();
        let local = "192.0.2.10:40000".parse().unwrap();
        let remote = "198.51.100.20:53".parse().unwrap();
        record_recent_udp_flow(&writer.recent_flows, local, remote);
        let failed = build_udp_packet(local, remote);
        assert!(
            control.apply_destination_unreachable(&build_icmpv4_port_unreachable(
                &failed
            ))
        );

        let mut payload = [0u8; 64];
        let mut oob = [0u8; 64];
        let result = reader
            .read_error_queue_into(&mut payload, &mut oob)
            .unwrap();
        assert_eq!(result.n, 32);
        assert_eq!(result.nn, 48);
        assert_eq!(result.flags, 0);
        assert_eq!(&payload[..result.n], &[0x5a; 32]);
        assert_eq!(
            SocketErrorControlMessage::parse(&oob[..result.nn]).unwrap(),
            SocketErrorControlMessage {
                errno: libc::ECONNREFUSED as u32,
                origin: 2,
                icmp_type: 3,
                code: 3,
                info: 0,
                offender: "203.0.113.1".parse().unwrap(),
            }
        );
    }

    #[test]
    fn error_queue_msg_trunc_reports_complete_payload_length() {
        let (send, recv) = mpsc::channel(1);
        let socket = UdpSocket::new(recv, send, 1500);
        let control = socket.icmp_control();
        let (mut reader, writer) = socket.split();
        let local = "192.0.2.10:40000".parse().unwrap();
        let remote = "198.51.100.20:53".parse().unwrap();
        record_recent_udp_flow(&writer.recent_flows, local, remote);
        let failed = build_udp_packet(local, remote);
        assert!(
            control.apply_destination_unreachable(&build_icmpv4_port_unreachable(
                &failed
            ))
        );

        let mut payload = [0u8; 8];
        let mut oob = [0u8; 64];
        let result = reader
            .read_error_queue_into_with_flags(
                &mut payload,
                &mut oob,
                MESSAGE_FLAG_ERROR_QUEUE
                    | MESSAGE_FLAG_DONT_WAIT
                    | MESSAGE_FLAG_TRUNCATED,
            )
            .unwrap();
        assert_eq!(result.n, 32, "MSG_TRUNC must report the full quote length");
        assert_eq!(payload, [0x5a; 8]);
        assert_eq!(result.flags, MESSAGE_FLAG_TRUNCATED);
    }

    #[test]
    fn unsupported_error_queue_flags_do_not_consume_error() {
        let (send, recv) = mpsc::channel(1);
        let socket = UdpSocket::new(recv, send, 1500);
        let control = socket.icmp_control();
        let (mut reader, writer) = socket.split();
        let local = "192.0.2.10:40000".parse().unwrap();
        let remote = "198.51.100.20:53".parse().unwrap();
        record_recent_udp_flow(&writer.recent_flows, local, remote);
        let failed = build_udp_packet(local, remote);
        assert!(
            control.apply_destination_unreachable(&build_icmpv4_port_unreachable(
                &failed
            ))
        );

        let mut payload = [0u8; 64];
        let mut oob = [0u8; 64];
        let error = reader
            .read_error_queue_into_with_flags(&mut payload, &mut oob, 0x4000_0000)
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EOPNOTSUPP));
        assert!(
            reader.read_error_queue_message().is_ok(),
            "flag validation must happen before consuming the queued error"
        );
    }

    #[test]
    fn receive_errors_mode_reserves_icmp_errors_for_nonblocking_read_error() {
        let (_input_tx, input_rx) = mpsc::channel(1);
        let (output_tx, _output_rx) = mpsc::channel(1);
        let socket = UdpSocket::new(input_rx, output_tx, 1500);
        let control = socket.icmp_control();
        let (mut reader, writer) = socket.split();
        let local: SocketAddr = "192.0.2.10:4000".parse().unwrap();
        let remote: SocketAddr = "198.51.100.20:5000".parse().unwrap();
        record_recent_udp_flow(&writer.recent_flows, local, remote);
        assert!(control.record_destination_unreachable(
            local,
            remote,
            remote.ip(),
            &[],
            3
        ));

        assert!(!reader.receive_errors());
        reader.set_receive_errors(true);
        assert!(reader.receive_errors());
        assert_eq!(
            reader.read_icmp_error().unwrap(),
            UdpIcmpError {
                local_addr: local,
                remote_addr: remote,
                offender: remote.ip(),
                quoted_payload: Box::default(),
                kind: UdpIcmpErrorKind::DestinationUnreachable { code: 3 },
            }
        );
        assert_eq!(
            reader.read_icmp_error().unwrap_err().raw_os_error(),
            Some(libc::EAGAIN)
        );
    }

    #[tokio::test]
    async fn receive_errors_reports_output_queue_full_as_enobufs() {
        let (_input_tx, input_rx) = mpsc::channel(1);
        let (output_tx, mut output_rx) = mpsc::channel(1);
        let socket = UdpSocket::new(input_rx, output_tx, 1500);
        let (mut reader, mut writer) = socket.split();
        let local: SocketAddr = "192.0.2.10:4000".parse().unwrap();
        let remote: SocketAddr = "198.51.100.20:5000".parse().unwrap();

        writer.send((vec![1], local, remote).into()).await.unwrap();
        writer.send((vec![2], local, remote).into()).await.unwrap();
        reader.set_receive_errors(true);
        assert_eq!(
            writer
                .send((vec![3], local, remote).into())
                .await
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOBUFS)
        );

        let admitted = output_rx.recv().await.unwrap();
        assert_eq!(admitted.data().last(), Some(&1));
    }

    #[tokio::test]
    async fn ordinary_error_receive_delivers_queued_payload_before_icmp_error() {
        let (input_tx, input_rx) = mpsc::channel(2);
        let (output_tx, _output_rx) = mpsc::channel(1);
        let socket = UdpSocket::new(input_rx, output_tx, 1500);
        let control = socket.icmp_control();
        let (mut reader, writer) = socket.split();
        let local: SocketAddr = "192.0.2.10:4000".parse().unwrap();
        let remote: SocketAddr = "198.51.100.20:5000".parse().unwrap();
        record_recent_udp_flow(&writer.recent_flows, local, remote);

        input_tx
            .send(Packet::new(build_udp_packet(local, remote)))
            .await
            .unwrap();
        assert!(control.record_destination_unreachable(
            local,
            remote,
            remote.ip(),
            &[],
            3
        ));

        let packet = reader.recv_with_icmp_errors().await.unwrap().unwrap();
        assert_eq!(packet.local_addr, local);
        assert_eq!(packet.remote_addr, remote);
        assert_eq!(packet.data(), &[0x5a; 32]);
        assert_eq!(
            reader.recv_with_icmp_errors().await.unwrap_err().kind,
            UdpIcmpErrorKind::DestinationUnreachable { code: 3 }
        );
    }

    #[tokio::test]
    async fn receive_errors_mode_keeps_icmp_error_out_of_ordinary_receive() {
        let (input_tx, input_rx) = mpsc::channel(1);
        let (output_tx, _output_rx) = mpsc::channel(1);
        let socket = UdpSocket::new(input_rx, output_tx, 1500);
        let control = socket.icmp_control();
        let (mut reader, writer) = socket.split();
        let local: SocketAddr = "192.0.2.10:4000".parse().unwrap();
        let remote: SocketAddr = "198.51.100.20:5000".parse().unwrap();
        record_recent_udp_flow(&writer.recent_flows, local, remote);
        assert!(control.record_destination_unreachable(
            local,
            remote,
            remote.ip(),
            &[],
            3
        ));
        reader.set_receive_errors(true);

        input_tx
            .send(Packet::new(build_udp_packet(local, remote)))
            .await
            .unwrap();
        let packet = reader.recv_with_icmp_errors().await.unwrap().unwrap();
        assert_eq!(packet.data(), &[0x5a; 32]);
        assert_eq!(
            reader.read_icmp_error().unwrap().kind,
            UdpIcmpErrorKind::DestinationUnreachable { code: 3 }
        );
    }

    #[tokio::test]
    async fn ordinary_error_receive_wakes_for_new_icmp_error() {
        let (_input_tx, input_rx) = mpsc::channel(1);
        let (output_tx, _output_rx) = mpsc::channel(1);
        let socket = UdpSocket::new(input_rx, output_tx, 1500);
        let control = socket.icmp_control();
        let (mut reader, writer) = socket.split();
        let local: SocketAddr = "192.0.2.10:4000".parse().unwrap();
        let remote: SocketAddr = "198.51.100.20:5000".parse().unwrap();
        record_recent_udp_flow(&writer.recent_flows, local, remote);

        tokio::spawn(async move {
            tokio::task::yield_now().await;
            assert!(control.record_destination_unreachable(
                local,
                remote,
                remote.ip(),
                &[],
                3
            ));
        });

        let error = tokio::time::timeout(
            Duration::from_secs(1),
            reader.recv_with_icmp_errors(),
        )
        .await
        .expect("ICMP error should wake ordinary receive")
        .unwrap_err();
        assert_eq!(
            error.kind,
            UdpIcmpErrorKind::DestinationUnreachable { code: 3 }
        );
    }

    #[test]
    fn async_icmp_error_queue_is_bounded_and_keeps_newest_errors() {
        let (_input_tx, input_rx) = mpsc::channel(1);
        let (output_tx, _output_rx) = mpsc::channel(1);
        let socket = UdpSocket::new(input_rx, output_tx, 1500);
        let control = socket.icmp_control();
        let (mut reader, _writer) = socket.split();
        let local: SocketAddr = "192.0.2.10:4000".parse().unwrap();
        let remote: SocketAddr = "198.51.100.20:5000".parse().unwrap();
        record_recent_udp_flow(&control.recent_flows, local, remote);

        for mtu in 1000..1000 + UDP_ICMP_ERROR_CAPACITY + 2 {
            control.record_packet_too_big(local, remote, remote.ip(), &[], mtu);
        }

        assert_eq!(reader.errors.lock().unwrap().len(), UDP_ICMP_ERROR_CAPACITY);
        assert_eq!(
            reader.try_recv_icmp_error().unwrap().kind,
            UdpIcmpErrorKind::PacketTooBig { path_mtu: 1002 }
        );
    }

    #[test]
    fn recent_udp_flow_cache_expires_and_evicts_oldest() {
        let writer = writer_with_fragment_id(1);
        let local: SocketAddr = "192.0.2.10:4000".parse().unwrap();
        let expired_remote: SocketAddr = "198.51.100.1:5000".parse().unwrap();
        writer.recent_flows.lock().unwrap().insert(
            (local, expired_remote),
            Instant::now() - RECENT_UDP_FLOW_TTL,
        );
        assert!(!has_recent_udp_flow(
            &writer.recent_flows,
            local,
            expired_remote,
        ));
        assert!(writer.recent_flows.lock().unwrap().is_empty());

        for offset in 0..RECENT_UDP_FLOW_CAPACITY {
            record_recent_udp_flow(
                &writer.recent_flows,
                local,
                SocketAddr::new(
                    "198.51.100.2".parse().unwrap(),
                    10_000 + offset as u16,
                ),
            );
        }
        let oldest = (local, "198.51.100.2:10000".parse().unwrap());
        *writer
            .recent_flows
            .lock()
            .unwrap()
            .get_mut(&oldest)
            .unwrap() -= Duration::from_secs(1);
        let replacement: SocketAddr = "203.0.113.9:25000".parse().unwrap();
        record_recent_udp_flow(&writer.recent_flows, local, replacement);

        let flows = writer.recent_flows.lock().unwrap();
        assert_eq!(flows.len(), RECENT_UDP_FLOW_CAPACITY);
        assert!(!flows.contains_key(&oldest));
        assert!(flows.contains_key(&(local, replacement)));
    }

    #[tokio::test]
    async fn validated_icmpv4_fragmentation_needed_reduces_recent_udp_pmtu() {
        let (_input_tx, input_rx) = mpsc::channel(1);
        let (output_tx, _output_rx) = mpsc::channel(8);
        let socket = UdpSocket::new(input_rx, output_tx, 1500);
        let control = socket.icmp_control();
        let (_reader, mut writer) = socket.split();
        let local: SocketAddr = "192.0.2.10:4000".parse().unwrap();
        let remote: SocketAddr = "198.51.100.20:5000".parse().unwrap();

        writer
            .send((vec![0x5a; 32], local, remote).into())
            .await
            .unwrap();
        let quoted = build_udp_packet(local, remote);
        let icmp = build_icmpv4_fragmentation_needed(&quoted[..28], 1200);

        let mut corrupted = icmp.clone();
        *corrupted.last_mut().unwrap() ^= 1;
        assert!(!control.apply_packet_too_big(&corrupted));
        assert_eq!(writer.path_mtu_for(remote.ip()), 1500);

        assert!(control.apply_packet_too_big(&icmp));
        assert_eq!(writer.path_mtu_for(remote.ip()), 1200);

        let wrong_remote: SocketAddr = "198.51.100.20:5001".parse().unwrap();
        let wrong_quote = build_udp_packet(local, wrong_remote);
        let wrong_icmp = build_icmpv4_fragmentation_needed(&wrong_quote[..28], 1000);
        assert!(!control.apply_packet_too_big(&wrong_icmp));
        assert_eq!(writer.path_mtu_for(remote.ip()), 1200);

        writer.confirm_path_mtu_for(remote.ip(), 1500);
        let mut bad_quoted_header = quoted[..28].to_vec();
        bad_quoted_header[8] ^= 1;
        let bad_quote_icmp =
            build_icmpv4_fragmentation_needed(&bad_quoted_header, 1000);
        assert!(!control.apply_packet_too_big(&bad_quote_icmp));
        assert_eq!(writer.path_mtu_for(remote.ip()), 1500);
    }

    #[tokio::test]
    async fn validated_icmpv6_packet_too_big_reduces_recent_udp_pmtu() {
        let (_input_tx, input_rx) = mpsc::channel(1);
        let (output_tx, _output_rx) = mpsc::channel(8);
        let socket = UdpSocket::new(input_rx, output_tx, 1500);
        let control = socket.icmp_control();
        let (_reader, mut writer) = socket.split();
        let local: SocketAddr = "[2001:db8::10]:4000".parse().unwrap();
        let remote: SocketAddr = "[2001:db8:1::20]:5000".parse().unwrap();

        writer
            .send((vec![0x5a; 32], local, remote).into())
            .await
            .unwrap();
        let quoted = build_udp_packet(local, remote);
        let icmp = build_icmpv6_packet_too_big(&quoted[..48], 1280);

        assert!(control.apply_packet_too_big(&icmp));
        assert_eq!(writer.path_mtu_for(remote.ip()), 1280);
    }

    #[tokio::test]
    async fn icmp_pmtu_update_correlates_first_source_fragment() {
        let (send, mut recv) = mpsc::channel(16);
        let mut writer = writer_with_fragment_id(100);
        writer.send = UdpOutbound::Channel(send);
        let control = UdpIcmpControl {
            path_mtu: writer.path_mtu.clone(),
            recent_flows: writer.recent_flows.clone(),
            errors: Arc::new(Mutex::new(VecDeque::new())),
            error_notify: Arc::new(Notify::new()),
            mtu: writer.mtu,
        };

        let local_v4: SocketAddr = "192.0.2.10:4000".parse().unwrap();
        let remote_v4: SocketAddr = "198.51.100.20:5000".parse().unwrap();
        writer.confirm_path_mtu_for(remote_v4.ip(), 1200);
        writer
            .send((vec![0x5a; 1400], local_v4, remote_v4).into())
            .await
            .unwrap();
        let first_v4 = recv.recv().await.unwrap();
        let icmp_v4 = build_icmpv4_fragmentation_needed(first_v4.data(), 1000);
        assert!(control.apply_packet_too_big(&icmp_v4));
        assert_eq!(writer.path_mtu_for(remote_v4.ip()), 1000);
        while recv.try_recv().is_ok() {}

        let local_v6: SocketAddr = "[2001:db8::10]:4000".parse().unwrap();
        let remote_v6: SocketAddr = "[2001:db8:1::20]:5000".parse().unwrap();
        writer.confirm_path_mtu_for(remote_v6.ip(), 1400);
        writer
            .send((vec![0x5a; 1450], local_v6, remote_v6).into())
            .await
            .unwrap();
        let first_v6 = recv.recv().await.unwrap();
        let icmp_v6 = build_icmpv6_packet_too_big(first_v6.data(), 1280);
        assert!(control.apply_packet_too_big(&icmp_v6));
        assert_eq!(writer.path_mtu_for(remote_v6.ip()), 1280);
    }

    #[tokio::test]
    async fn icmp_pmtu_update_must_target_quoted_local_address() {
        let (_input_tx, input_rx) = mpsc::channel(1);
        let (output_tx, _output_rx) = mpsc::channel(8);
        let socket = UdpSocket::new(input_rx, output_tx, 1500);
        let control = socket.icmp_control();
        let (_reader, mut writer) = socket.split();

        let local_v4: SocketAddr = "192.0.2.10:4000".parse().unwrap();
        let remote_v4: SocketAddr = "198.51.100.20:5000".parse().unwrap();
        writer
            .send((vec![0x5a; 32], local_v4, remote_v4).into())
            .await
            .unwrap();
        let quoted_v4 = build_udp_packet(local_v4, remote_v4);
        let wrong_v4 = build_icmpv4_fragmentation_needed_to(
            &quoted_v4[..28],
            1200,
            [192, 0, 2, 99],
        );
        assert!(!control.apply_packet_too_big(&wrong_v4));
        assert_eq!(writer.path_mtu_for(remote_v4.ip()), 1500);

        let local_v6: SocketAddr = "[2001:db8::10]:4000".parse().unwrap();
        let remote_v6: SocketAddr = "[2001:db8:1::20]:5000".parse().unwrap();
        writer
            .send((vec![0x5a; 32], local_v6, remote_v6).into())
            .await
            .unwrap();
        let quoted_v6 = build_udp_packet(local_v6, remote_v6);
        let wrong_v6 = build_icmpv6_packet_too_big_to(
            &quoted_v6[..48],
            1280,
            "2001:db8::99".parse().unwrap(),
        );
        assert!(!control.apply_packet_too_big(&wrong_v6));
        assert_eq!(writer.path_mtu_for(remote_v6.ip()), 1500);
    }

    #[test]
    fn path_mtu_cache_expires_and_evicts_oldest_destination() {
        let writer = writer_with_fragment_id(1);
        let expired = "192.0.2.1".parse().unwrap();
        writer
            .path_mtu
            .lock()
            .unwrap()
            .insert(expired, (1200, Instant::now() - PATH_MTU_CACHE_TTL));
        assert_eq!(writer.path_mtu_for(expired), 1500);
        assert!(!writer.path_mtu.lock().unwrap().contains_key(&expired));

        for host in 1..=PATH_MTU_CACHE_CAPACITY {
            writer.confirm_path_mtu_for(
                IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, host as u8)),
                1200,
            );
        }
        let oldest = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 1));
        writer.path_mtu.lock().unwrap().get_mut(&oldest).unwrap().1 -=
            Duration::from_secs(1);
        let replacement = "203.0.113.1".parse().unwrap();
        writer.confirm_path_mtu_for(replacement, 1100);

        let cache = writer.path_mtu.lock().unwrap();
        assert_eq!(cache.len(), PATH_MTU_CACHE_CAPACITY);
        assert!(!cache.contains_key(&oldest));
        assert_eq!(cache.get(&replacement).map(|entry| entry.0), Some(1100));
    }

    #[tokio::test]
    async fn confirmed_path_mtu_controls_udp_fragmentation() {
        let (send, mut recv) = mpsc::channel(8);
        let mut writer = writer_with_fragment_id(100);
        writer.send = UdpOutbound::Channel(send);
        writer.confirm_path_mtu_for("1.1.1.1".parse().unwrap(), 68);

        writer
            .send(
                (
                    vec![0x5a; 100],
                    "2.2.2.2:5001".parse().unwrap(),
                    "1.1.1.1:5000".parse().unwrap(),
                )
                    .into(),
            )
            .await
            .unwrap();

        for _ in 0..3 {
            let fragment = recv.recv().await.expect("expected PMTU fragment");
            assert!(fragment.data().len() <= 68);
        }
        assert!(recv.try_recv().is_err());
    }

    #[tokio::test]
    async fn path_mtu_want_sets_df_only_when_ipv4_datagram_fits() {
        let (send, mut recv) = mpsc::channel(8);
        let mut writer = writer_with_fragment_id(100);
        writer.send = UdpOutbound::Channel(send);
        writer.set_path_mtu_discovery(PathMtuDiscovery::Want);
        writer.confirm_path_mtu_for("1.1.1.1".parse().unwrap(), 68);

        writer
            .send(
                (
                    vec![0x5a; 8],
                    "2.2.2.2:5001".parse().unwrap(),
                    "1.1.1.1:5000".parse().unwrap(),
                )
                    .into(),
            )
            .await
            .unwrap();
        let fitting = recv.recv().await.unwrap();
        assert!(
            etherparse::Ipv4HeaderSlice::from_slice(fitting.data())
                .unwrap()
                .dont_fragment()
        );

        writer
            .send(
                (
                    vec![0x5a; 100],
                    "2.2.2.2:5001".parse().unwrap(),
                    "1.1.1.1:5000".parse().unwrap(),
                )
                    .into(),
            )
            .await
            .unwrap();
        let fragment = recv.recv().await.unwrap();
        assert!(
            !etherparse::Ipv4HeaderSlice::from_slice(fragment.data())
                .unwrap()
                .dont_fragment()
        );
    }

    #[tokio::test]
    async fn link_mtu_policies_ignore_lower_confirmed_path_mtu() {
        for (policy, expect_df) in [
            (PathMtuDiscovery::Probe, true),
            (PathMtuDiscovery::Interface, false),
            (PathMtuDiscovery::Omit, false),
        ] {
            let (send, mut recv) = mpsc::channel(8);
            let mut writer = writer_with_fragment_id(100);
            writer.send = UdpOutbound::Channel(send);
            writer.set_path_mtu_discovery(policy);
            writer.confirm_path_mtu_for("1.1.1.1".parse().unwrap(), 68);

            writer
                .send(
                    (
                        vec![0x5a; 100],
                        "2.2.2.2:5001".parse().unwrap(),
                        "1.1.1.1:5000".parse().unwrap(),
                    )
                        .into(),
                )
                .await
                .unwrap();
            let packet = recv.recv().await.unwrap();
            let header =
                etherparse::Ipv4HeaderSlice::from_slice(packet.data()).unwrap();
            assert_eq!(header.dont_fragment(), expect_df, "policy {policy:?}");
            assert_eq!(packet.data().len(), 128, "policy {policy:?}");
            assert!(recv.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn probe_and_interface_reject_above_link_mtu_while_omit_fragments() {
        for policy in [PathMtuDiscovery::Probe, PathMtuDiscovery::Interface] {
            let (send, mut recv) = mpsc::channel(8);
            let mut writer = writer_with_fragment_id(100);
            writer.send = UdpOutbound::Channel(send);
            writer.mtu = 68;
            writer.set_path_mtu_discovery(policy);

            let err = writer
                .send(
                    (
                        vec![0x5a; 100],
                        "2.2.2.2:5001".parse().unwrap(),
                        "1.1.1.1:5000".parse().unwrap(),
                    )
                        .into(),
                )
                .await
                .unwrap_err();
            assert_eq!(
                err.raw_os_error(),
                Some(libc::EMSGSIZE),
                "policy {policy:?}"
            );
            assert!(recv.try_recv().is_err());
        }

        let (send, mut recv) = mpsc::channel(8);
        let mut writer = writer_with_fragment_id(100);
        writer.send = UdpOutbound::Channel(send);
        writer.mtu = 68;
        writer.set_path_mtu_discovery(PathMtuDiscovery::Omit);
        writer
            .send(
                (
                    vec![0x5a; 100],
                    "2.2.2.2:5001".parse().unwrap(),
                    "1.1.1.1:5000".parse().unwrap(),
                )
                    .into(),
            )
            .await
            .unwrap();
        for _ in 0..3 {
            let fragment = recv.recv().await.unwrap();
            assert!(fragment.data().len() <= 68);
        }
        assert!(recv.try_recv().is_err());
    }

    #[tokio::test]
    async fn explicit_path_mtu_probe_ignores_cached_reduction_without_confirming_it()
    {
        let (send, mut recv) = mpsc::channel(8);
        let mut writer = writer_with_fragment_id(100);
        writer.send = UdpOutbound::Channel(send);
        writer.set_path_mtu_discovery(PathMtuDiscovery::Dont);
        let remote: SocketAddr = "1.1.1.1:5000".parse().unwrap();
        writer.confirm_path_mtu_for(remote.ip(), 68);

        writer
            .send_path_mtu_probe(
                (vec![0x5a; 100], "2.2.2.2:5001".parse().unwrap(), remote).into(),
            )
            .await
            .unwrap();
        let probe = recv.recv().await.unwrap();
        let header = etherparse::Ipv4HeaderSlice::from_slice(probe.data()).unwrap();
        assert!(header.dont_fragment());
        assert_eq!(probe.data().len(), 128);
        assert_eq!(writer.path_mtu_for(remote.ip()), 68);
        assert_eq!(writer.path_mtu_discovery(), PathMtuDiscovery::Dont);
    }

    #[tokio::test]
    async fn explicit_path_mtu_probe_rejects_above_link_mtu_and_restores_policy() {
        let (send, mut recv) = mpsc::channel(8);
        let mut writer = writer_with_fragment_id(100);
        writer.send = UdpOutbound::Channel(send);
        writer.mtu = 1280;
        writer.set_path_mtu_discovery(PathMtuDiscovery::Want);

        let err = writer
            .send_path_mtu_probe(
                (
                    vec![0x5a; 1400],
                    "[2001:db8::1]:5001".parse().unwrap(),
                    "[2001:db8::2]:5000".parse().unwrap(),
                )
                    .into(),
            )
            .await
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EMSGSIZE));
        assert!(recv.try_recv().is_err());
        assert_eq!(writer.path_mtu_discovery(), PathMtuDiscovery::Want);
    }

    #[tokio::test]
    async fn path_mtu_do_rejects_oversized_datagram_without_output() {
        let (send, mut recv) = mpsc::channel(8);
        let mut writer = writer_with_fragment_id(100);
        writer.send = UdpOutbound::Channel(send);
        writer.set_path_mtu_discovery(PathMtuDiscovery::Do);
        writer.confirm_path_mtu_for("1.1.1.1".parse().unwrap(), 68);

        let err = writer
            .send(
                (
                    vec![0x5a; 100],
                    "2.2.2.2:5001".parse().unwrap(),
                    "1.1.1.1:5000".parse().unwrap(),
                )
                    .into(),
            )
            .await
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EMSGSIZE));
        assert!(recv.try_recv().is_err());

        let remote_v6 = "[2001:db8::2]:5000".parse().unwrap();
        writer.confirm_path_mtu_for("2001:db8::2".parse().unwrap(), 1280);
        let err = writer
            .send(
                (
                    vec![0x5a; 1400],
                    "[2001:db8::1]:5001".parse().unwrap(),
                    remote_v6,
                )
                    .into(),
            )
            .await
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EMSGSIZE));
        assert!(recv.try_recv().is_err());
    }

    #[tokio::test]
    async fn interface_and_omit_writes_do_not_authorize_icmp_pmtu_updates() {
        for policy in [PathMtuDiscovery::Interface, PathMtuDiscovery::Omit] {
            let (_input_tx, input_rx) = mpsc::channel(1);
            let (output_tx, mut output_rx) = mpsc::channel(8);
            let socket = UdpSocket::new(input_rx, output_tx, 1500);
            let control = socket.icmp_control();
            let (_reader, mut writer) = socket.split();
            writer.set_path_mtu_discovery(policy);

            let local: SocketAddr = "192.0.2.10:4000".parse().unwrap();
            let remote: SocketAddr = "198.51.100.20:5000".parse().unwrap();
            writer
                .send((vec![0x5a; 100], local, remote).into())
                .await
                .unwrap();
            let sent = output_rx.recv().await.unwrap();
            let icmp = build_icmpv4_fragmentation_needed(&sent.data()[..28], 1200);

            assert!(!control.apply_packet_too_big(&icmp), "policy {policy:?}");
            assert_eq!(writer.path_mtu_for(remote.ip()), 1500, "policy {policy:?}");
        }
    }

    #[tokio::test]
    async fn path_mtu_do_local_emsgsize_does_not_authorize_icmp_update() {
        let (_input_tx, input_rx) = mpsc::channel(1);
        let (output_tx, _output_rx) = mpsc::channel(8);
        let socket = UdpSocket::new(input_rx, output_tx, 1500);
        let control = socket.icmp_control();
        let (_reader, mut writer) = socket.split();
        writer.set_path_mtu_discovery(PathMtuDiscovery::Do);

        let local: SocketAddr = "192.0.2.10:4000".parse().unwrap();
        let remote: SocketAddr = "198.51.100.20:5000".parse().unwrap();
        writer.confirm_path_mtu_for(remote.ip(), 1200);
        let err = writer
            .send((vec![0x5a; 1300], local, remote).into())
            .await
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EMSGSIZE));

        let quoted = build_udp_packet(local, remote);
        let icmp = build_icmpv4_fragmentation_needed(&quoted[..28], 1000);
        assert!(!control.apply_packet_too_big(&icmp));
        assert_eq!(writer.path_mtu_for(remote.ip()), 1200);
    }

    #[test]
    fn fragment_identification_advances_without_random_reuse() {
        let writer = writer_with_fragment_id(0x1234_5678);
        assert_eq!(writer.fragment_identification(), 0x1234_5678);
        assert_eq!(writer.fragment_identification(), 0x1234_5679);
    }

    #[test]
    fn ipv4_identification_skips_zero_after_wrap() {
        let writer = writer_with_fragment_id(0x0000_ffff);
        assert_eq!(writer.ipv4_identification(), 0xffff);
        assert_eq!(writer.ipv4_identification(), 1);
    }

    fn udp_packet_with_zero_checksum(ipv6: bool) -> Packet {
        let mut bytes = Vec::new();
        if ipv6 {
            PacketBuilder::ipv6(
                [0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                [0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
                64,
            )
            .udp(1234, 4321)
            .write(&mut bytes, b"checksum-test")
            .unwrap();
            bytes[46..48].fill(0);
        } else {
            PacketBuilder::ipv4([192, 0, 2, 1], [192, 0, 2, 2], 64)
                .udp(1234, 4321)
                .write(&mut bytes, b"checksum-test")
                .unwrap();
            bytes[26..28].fill(0);
        }
        Packet::new(bytes)
    }

    #[tokio::test]
    async fn ipv6_zero_udp_checksum_is_rejected_but_ipv4_zero_is_allowed() {
        let (send, recv) = mpsc::channel(2);
        let (_outbound, outbound_recv) = mpsc::channel(1);
        let mut reader = UdpSocket::new(recv, _outbound, 1500).split().0;

        send.send(udp_packet_with_zero_checksum(true))
            .await
            .unwrap();
        send.send(udp_packet_with_zero_checksum(false))
            .await
            .unwrap();
        drop(send);

        let packet = reader
            .recv()
            .await
            .expect("IPv4 zero-checksum UDP must pass");
        assert_eq!(packet.local_addr, "192.0.2.1:1234".parse().unwrap());
        assert_eq!(packet.remote_addr, "192.0.2.2:4321".parse().unwrap());
        assert_eq!(packet.data(), b"checksum-test");
        assert!(reader.recv().await.is_none());
        drop(outbound_recv);
    }

    #[tokio::test]
    async fn ipv4_fragmentation_consumes_one_identification_per_datagram() {
        let (send, mut recv) = mpsc::channel(8);
        let mut writer = SplitWrite {
            send: UdpOutbound::Channel(send),
            dropped_on_full: Arc::new(AtomicU64::new(0)),
            flow_label_state: RandomState::new(),
            next_fragment_id: Arc::new(AtomicU32::new(100)),
            path_mtu: Arc::new(Mutex::new(HashMap::new())),
            recent_flows: Arc::new(Mutex::new(HashMap::new())),
            receive_errors: Arc::new(AtomicBool::new(false)),
            mtu: 68,
            path_mtu_discovery: PathMtuDiscovery::Dont,
        };

        writer
            .send(
                (
                    vec![0x5a; 100],
                    "2.2.2.2:5001".parse().unwrap(),
                    "1.1.1.1:5000".parse().unwrap(),
                )
                    .into(),
            )
            .await
            .unwrap();

        assert_eq!(writer.next_fragment_id.load(Ordering::Relaxed), 101);
        for _ in 0..3 {
            let fragment = recv.recv().await.unwrap();
            let header =
                etherparse::Ipv4HeaderSlice::from_slice(fragment.data()).unwrap();
            assert_eq!(header.identification(), 100);
        }
    }

    #[tokio::test]
    async fn fragmented_datagram_keeps_admitted_prefix_on_queue_pressure() {
        let (send, mut recv) = mpsc::channel(1);
        let mut writer = SplitWrite {
            send: UdpOutbound::Channel(send),
            dropped_on_full: Arc::new(AtomicU64::new(0)),
            flow_label_state: RandomState::new(),
            next_fragment_id: Arc::new(AtomicU32::new(1)),
            path_mtu: Arc::new(Mutex::new(HashMap::new())),
            recent_flows: Arc::new(Mutex::new(HashMap::new())),
            receive_errors: Arc::new(AtomicBool::new(false)),
            mtu: 68,
            path_mtu_discovery: PathMtuDiscovery::Dont,
        };

        writer
            .send(
                (
                    vec![0x5a; 100],
                    "2.2.2.2:5001".parse().unwrap(),
                    "1.1.1.1:5000".parse().unwrap(),
                )
                    .into(),
            )
            .await
            .unwrap();

        let first = recv
            .try_recv()
            .expect("first fragment must remain admitted");
        let first_header =
            etherparse::Ipv4HeaderSlice::from_slice(first.data()).unwrap();
        assert_eq!(first_header.fragments_offset().value(), 0);
        assert!(first_header.more_fragments());
        assert!(recv.try_recv().is_err());
        assert_eq!(writer.dropped_on_full.load(Ordering::Relaxed), 1);

        writer.receive_errors.store(true, Ordering::Relaxed);
        assert_eq!(
            writer
                .send(
                    (
                        vec![0x5a; 100],
                        "2.2.2.2:5001".parse().unwrap(),
                        "1.1.1.1:5000".parse().unwrap(),
                    )
                        .into(),
                )
                .await
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOBUFS)
        );
        assert!(
            recv.try_recv().is_ok(),
            "ReceiveErrors must not roll back an admitted fragment"
        );
        assert!(recv.try_recv().is_err());
        assert_eq!(writer.dropped_on_full.load(Ordering::Relaxed), 2);
    }
}
