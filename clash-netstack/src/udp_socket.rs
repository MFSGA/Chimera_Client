use crate::{Packet, packet::IpPacket};
use etherparse::PacketBuilder;
use log::{error, trace, warn};
use std::{
    borrow::Cow,
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::mpsc;

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

pub struct UdpSocket {
    inbound: mpsc::Receiver<Packet>,
    outbound: mpsc::Sender<Packet>,
}

impl UdpSocket {
    pub fn new(
        inbound: mpsc::Receiver<Packet>,
        outbound: mpsc::Sender<Packet>,
    ) -> Self {
        Self { inbound, outbound }
    }

    pub fn split(self) -> (SplitRead, SplitWrite) {
        let read = SplitRead {
            recv: self.inbound,
            fragments: UdpFragmentReassembler::default(),
        };
        let write = SplitWrite {
            send: self.outbound,
            dropped_on_full: Arc::new(AtomicU64::new(0)),
        };
        (read, write)
    }
}

const UDP_FRAGMENT_MAX_ACTIVE: usize = 64;
const UDP_FRAGMENT_TTL: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
enum UdpFragmentKey {
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

struct UdpFragmentState {
    buffer: etherparse::defrag::IpDefragBuf,
    updated_at: Instant,
}

#[derive(Default)]
struct UdpFragmentReassembler {
    active: HashMap<UdpFragmentKey, UdpFragmentState>,
}

impl UdpFragmentReassembler {
    fn prune_expired(&mut self, now: Instant) {
        self.active.retain(|_, state| {
            now.duration_since(state.updated_at) < UDP_FRAGMENT_TTL
        });
    }

    fn evict_oldest_if_full(&mut self) {
        if self.active.len() < UDP_FRAGMENT_MAX_ACTIVE {
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
                "evicting oldest UDP fragment reassembly because active limit ({UDP_FRAGMENT_MAX_ACTIVE}) was reached"
            );
        }
    }

    fn push(
        &mut self,
        packet: &etherparse::IpSlice<'_>,
    ) -> Result<Option<Vec<u8>>, etherparse::defrag::IpDefragError> {
        let now = Instant::now();
        self.prune_expired(now);

        let (key, offset, more_fragments, payload) = match packet {
            etherparse::IpSlice::Ipv4(ipv4) => {
                let header = ipv4.header();
                (
                    UdpFragmentKey::Ipv4 {
                        source: header.source(),
                        destination: header.destination(),
                        identification: header.identification(),
                    },
                    header.fragments_offset(),
                    header.more_fragments(),
                    ipv4.payload().payload,
                )
            }
            etherparse::IpSlice::Ipv6(ipv6) => {
                let fragment =
                    ipv6.extensions().clone().into_iter().find_map(|extension| {
                        match extension {
                            etherparse::Ipv6ExtensionSlice::Fragment(fragment) => {
                                Some(fragment)
                            }
                            _ => None,
                        }
                    });
                let Some(fragment) = fragment else {
                    return Ok(None);
                };

                (
                    UdpFragmentKey::Ipv6 {
                        source: ipv6.header().source(),
                        destination: ipv6.header().destination(),
                        identification: fragment.identification(),
                    },
                    fragment.fragment_offset(),
                    fragment.more_fragments(),
                    ipv6.payload().payload,
                )
            }
        };

        if !self.active.contains_key(&key) {
            self.evict_oldest_if_full();
            self.active.insert(
                key.clone(),
                UdpFragmentState {
                    buffer: etherparse::defrag::IpDefragBuf::new(
                        etherparse::ip_number::UDP,
                        Vec::new(),
                        Vec::new(),
                    ),
                    updated_at: now,
                },
            );
        }

        let complete = {
            let state = self
                .active
                .get_mut(&key)
                .expect("UDP fragment state must exist after insertion");
            state.updated_at = now;
            if let Err(err) = state.buffer.add(offset, more_fragments, payload) {
                self.active.remove(&key);
                return Err(err);
            }
            state.buffer.is_complete()
        };

        if !complete {
            return Ok(None);
        }

        let state = self
            .active
            .remove(&key)
            .expect("completed UDP fragment state must exist");
        let (payload, _) = state.buffer.take_bufs();
        Ok(Some(payload))
    }
}

pub struct SplitRead {
    recv: mpsc::Receiver<Packet>,
    fragments: UdpFragmentReassembler,
}

impl SplitRead {
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

            let src_ip = packet.src_addr();
            let dst_ip = packet.dst_addr();
            let sliced = match etherparse::IpSlice::from_slice(data.data()) {
                Ok(packet) => packet,
                Err(err) => {
                    error!("invalid IP packet: {err}");
                    continue;
                }
            };
            self.fragments.prune_expired(Instant::now());
            let payload = sliced.payload();
            if payload.ip_number != etherparse::ip_number::UDP {
                error!(
                    "UDP input contained non-UDP payload: {:?}",
                    payload.ip_number
                );
                continue;
            }

            let udp_data = if payload.fragmented {
                match self.fragments.push(&sliced) {
                    Ok(Some(payload)) => Cow::Owned(payload),
                    Ok(None) => continue,
                    Err(err) => {
                        error!("invalid UDP fragment sequence: {err}");
                        continue;
                    }
                }
            } else {
                Cow::Borrowed(payload.payload)
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
            if !packet.verify_checksum(&src_ip.into(), &dst_ip.into()) {
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
    send: mpsc::Sender<Packet>,
    dropped_on_full: Arc<AtomicU64>,
}

impl SplitWrite {
    pub async fn send(&mut self, packet: UdpPacket) -> Result<(), std::io::Error> {
        let builder = match (packet.local_addr, packet.remote_addr) {
            (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
                PacketBuilder::ipv4(src.ip().octets(), dst.ip().octets(), 20)
                    .udp(src.port(), dst.port())
            }
            (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
                PacketBuilder::ipv6(src.ip().octets(), dst.ip().octets(), 20)
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

        // UDP is inherently unreliable; drop the packet if the outbound
        // channel is full rather than blocking the UDP handler task.
        match self.send.try_send(Packet::new(ip_packet_writer)) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                let dropped =
                    self.dropped_on_full.fetch_add(1, Ordering::Relaxed) + 1;
                if dropped == 1 || dropped.is_power_of_two() {
                    warn!(
                        "dropping UDP packet because outbound queue is full; total dropped on this split writer: {dropped}"
                    );
                }
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(std::io::Error::other("packet outbound channel closed"))
            }
        }
    }
}
