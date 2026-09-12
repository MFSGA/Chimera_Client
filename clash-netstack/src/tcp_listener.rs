use crate::{
    Packet, device::NetstackDevice, packet::IpPacket,
    ring_buffer::LockFreeRingBuffer, stack::IfaceEvent, tcp_stream::TcpStream,
};
use futures::task::AtomicWaker;
use log::{debug, error, trace, warn};
use smoltcp::{iface::Interface, socket::tcp, wire::TcpPacket};
use std::{
    collections::HashMap,
    net::SocketAddr,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant as StdInstant},
};
use tokio::sync::mpsc;

const DEFAULT_TCP_SEND_BUFFER_SIZE: u32 = 256 * 1024; // 256 KiB
const DEFAULT_TCP_RECV_BUFFER_SIZE: u32 = 256 * 1024; // 256 KiB

/// Time-to-live for SYN tracker entries. Duplicates within this window are
/// suppressed to prevent the same SYN from creating multiple smoltcp sockets.
const SYN_TRACK_TTL: std::time::Duration = std::time::Duration::from_secs(60);

/// Maximum tracked half-open SYN entries. Bounds memory under a SYN flood.
const SYN_TRACK_MAX: usize = 10_000;

/// Hard cap on live TUN TCP streams. Each stream currently reserves roughly
/// 1 MiB across smoltcp and application-side buffers, so this bounds that
/// portion of memory to about 512 MiB.
const ACTIVE_TCP_STREAM_MAX: usize = 512;

/// Pending streams not yet accepted by the TUN dispatcher.
const TCP_ACCEPT_QUEUE_SIZE: usize = 128;
const IFACE_EVENT_QUEUE_SIZE: usize = 4096;

/// Bound fragmented TCP state separately from active TCP streams. A single
/// reassembled IP payload is limited to 65,535 bytes by the IP format, so this
/// caps fragment buffering to roughly 4 MiB plus map overhead.
const TCP_FRAGMENT_MAX_ACTIVE: usize = 64;
const TCP_FRAGMENT_TTL: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
enum TcpFragmentKey {
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

struct TcpFragmentState {
    buffer: etherparse::defrag::IpDefragBuf,
    updated_at: StdInstant,
}

#[derive(Default)]
struct TcpFragmentReassembler {
    active: HashMap<TcpFragmentKey, TcpFragmentState>,
}

impl TcpFragmentReassembler {
    fn prune_expired(&mut self, now: StdInstant) {
        self.active.retain(|_, state| {
            now.duration_since(state.updated_at) < TCP_FRAGMENT_TTL
        });
    }

    fn evict_oldest_if_full(&mut self) {
        if self.active.len() < TCP_FRAGMENT_MAX_ACTIVE {
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
                "evicting oldest TCP fragment reassembly because active limit ({TCP_FRAGMENT_MAX_ACTIVE}) was reached"
            );
        }
    }

    fn push(
        &mut self,
        packet: &etherparse::IpSlice<'_>,
    ) -> Result<Option<Vec<u8>>, etherparse::defrag::IpDefragError> {
        let now = StdInstant::now();
        self.prune_expired(now);

        let (key, offset, more_fragments, payload) = match packet {
            etherparse::IpSlice::Ipv4(ipv4) => {
                let header = ipv4.header();
                (
                    TcpFragmentKey::Ipv4 {
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
                    TcpFragmentKey::Ipv6 {
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
                TcpFragmentState {
                    buffer: etherparse::defrag::IpDefragBuf::new(
                        etherparse::ip_number::TCP,
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
                .expect("TCP fragment state must exist after insertion");
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
            .expect("completed TCP fragment state must exist");
        let (payload, _) = state.buffer.take_bufs();
        Ok(Some(payload))
    }
}

fn rebuild_tcp_ip_packet(
    packet: &etherparse::IpSlice<'_>,
    tcp_payload: &[u8],
) -> std::io::Result<Packet> {
    match packet {
        etherparse::IpSlice::Ipv4(ipv4) => {
            let original = ipv4.header();
            let payload_len = u16::try_from(tcp_payload.len()).map_err(|_| {
                std::io::Error::other("reassembled TCP payload too large")
            })?;
            let mut header = etherparse::Ipv4Header::new(
                payload_len,
                original.ttl(),
                etherparse::ip_number::TCP,
                original.source(),
                original.destination(),
            )
            .map_err(std::io::Error::other)?;
            header.identification = original.identification();
            header.dont_fragment = true;
            header.header_checksum = header.calc_header_checksum();

            let mut out = header.to_bytes().to_vec();
            out.extend_from_slice(tcp_payload);
            Ok(Packet::new(out))
        }
        etherparse::IpSlice::Ipv6(ipv6) => {
            let payload_length = u16::try_from(tcp_payload.len()).map_err(|_| {
                std::io::Error::other("reassembled TCP payload too large")
            })?;
            let original = ipv6.header();
            let header = etherparse::Ipv6Header {
                traffic_class: original.traffic_class(),
                flow_label: original.flow_label(),
                payload_length,
                next_header: etherparse::ip_number::TCP,
                hop_limit: original.hop_limit(),
                source: original.source(),
                destination: original.destination(),
            };

            let mut out = header.to_bytes().to_vec();
            out.extend_from_slice(tcp_payload);
            Ok(Packet::new(out))
        }
    }
}

#[derive(Clone, Debug)]
struct LastTcpPacketMeta {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    seq: u32,
    ack: Option<u32>,
    syn: bool,
    ack_flag: bool,
    fin: bool,
    rst: bool,
    psh: bool,
    payload_len: usize,
    window_len: u16,
}

impl std::fmt::Display for LastTcpPacketMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} -> {} seq={} ack={:?} flags={}{}{}{}{} payload_len={} window={}",
            self.src_addr,
            self.dst_addr,
            self.seq,
            self.ack,
            if self.syn { "S" } else { "-" },
            if self.ack_flag { "A" } else { "-" },
            if self.fin { "F" } else { "-" },
            if self.rst { "R" } else { "-" },
            if self.psh { "P" } else { "-" },
            self.payload_len,
            self.window_len
        )
    }
}

fn panic_payload_to_string(payload: Box<dyn std::any::Any + Send>) -> String {
    match payload.downcast::<String>() {
        Ok(msg) => *msg,
        Err(payload) => match payload.downcast::<&'static str>() {
            Ok(msg) => (*msg).to_string(),
            Err(_) => "unknown panic payload".to_string(),
        },
    }
}

fn mark_stream_closed(socket_control: &TcpStreamHandle) {
    socket_control.socket_closed.store(true, Ordering::Release);
    socket_control.read_closed.store(true, Ordering::Release);
    socket_control.write_closed.store(true, Ordering::Release);
    socket_control.recv_waker.wake();
    socket_control.send_waker.wake();
}

fn mark_all_streams_closed(
    socket_maps: &HashMap<smoltcp::iface::SocketHandle, Arc<TcpStreamHandle>>,
) {
    for socket_control in socket_maps.values() {
        mark_stream_closed(socket_control);
    }
}

fn mark_tracked_streams_closed(streams: &Mutex<Vec<Weak<TcpStreamHandle>>>) {
    if let Ok(mut streams) = streams.lock() {
        streams.retain(|stream| {
            if let Some(stream) = stream.upgrade() {
                mark_stream_closed(&stream);
                true
            } else {
                false
            }
        });
    }
}

fn has_active_stream_capacity(
    streams: &Mutex<Vec<Weak<TcpStreamHandle>>>,
    limit: usize,
) -> std::io::Result<bool> {
    let mut streams = streams
        .lock()
        .map_err(|_| std::io::Error::other("TCP stream tracker lock poisoned"))?;
    streams.retain(|stream| stream.strong_count() > 0);
    Ok(streams.len() < limit)
}

struct StreamShutdownGuard {
    streams: Arc<Mutex<Vec<Weak<TcpStreamHandle>>>>,
}

impl Drop for StreamShutdownGuard {
    fn drop(&mut self) {
        mark_tracked_streams_closed(&self.streams);
    }
}

fn record_last_tcp_packet(
    sink: &Arc<Mutex<Option<LastTcpPacketMeta>>>,
    packet: &TcpPacket<&[u8]>,
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
) {
    if let Ok(mut guard) = sink.lock() {
        *guard = Some(LastTcpPacketMeta {
            src_addr,
            dst_addr,
            seq: packet.seq_number().0 as u32,
            ack: packet.ack().then(|| packet.ack_number().0 as u32),
            syn: packet.syn(),
            ack_flag: packet.ack(),
            fin: packet.fin(),
            rst: packet.rst(),
            psh: packet.psh(),
            payload_len: packet.payload().len(),
            window_len: packet.window_len(),
        });
    }
}

pub(crate) struct TcpStreamHandle {
    pub(crate) recv_buffer: LockFreeRingBuffer,
    pub(crate) recv_waker: AtomicWaker,
    pub(crate) send_buffer: LockFreeRingBuffer,
    pub(crate) send_waker: AtomicWaker,

    /// Set by the relay task through TcpStream::drop when the app-side stream
    /// is dropped. poll_sockets drains send_buffer, then calls socket.close()
    /// to start the FIN handshake.
    pub(crate) socket_dropped: AtomicBool,
    /// Set by poll_sockets when the smoltcp socket becomes inactive. poll_read
    /// returns EOF once recv_buffer is drained.
    pub(crate) socket_closed: AtomicBool,
    /// Set when smoltcp reports the receive side is closed, and defensively in
    /// TcpStream::drop().
    pub(crate) read_closed: AtomicBool,
    /// Set when smoltcp reports the send side is closed, and defensively in
    /// TcpStream::drop().
    pub(crate) write_closed: AtomicBool,
    /// Set by poll_shutdown(); poll_sockets closes once send_buffer is drained.
    pub(crate) write_shutdown: AtomicBool,
}

impl TcpStreamHandle {
    pub fn new() -> Self {
        Self {
            recv_buffer: LockFreeRingBuffer::new(
                DEFAULT_TCP_RECV_BUFFER_SIZE as usize,
            ),
            recv_waker: AtomicWaker::new(),
            send_buffer: LockFreeRingBuffer::new(
                DEFAULT_TCP_SEND_BUFFER_SIZE as usize,
            ),
            send_waker: AtomicWaker::new(),
            socket_dropped: AtomicBool::new(false),
            socket_closed: AtomicBool::new(false),
            read_closed: AtomicBool::new(false),
            write_closed: AtomicBool::new(false),
            write_shutdown: AtomicBool::new(false),
        }
    }
}

impl Drop for TcpStreamHandle {
    fn drop(&mut self) {
        trace!("TcpStreamHandle dropped");
    }
}

pub struct TcpListener {
    socket_stream: mpsc::Receiver<TcpStream>,
    tracked_streams: Arc<Mutex<Vec<Weak<TcpStreamHandle>>>>,

    task_handle: tokio::task::JoinHandle<()>,
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        trace!("TcpListener dropped");
        mark_tracked_streams_closed(&self.tracked_streams);
        self.task_handle.abort();
    }
}

impl TcpListener {
    fn build_interface(device: &mut NetstackDevice) -> Interface {
        let mut config =
            smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut iface = smoltcp::iface::Interface::new(
            config,
            device,
            smoltcp::time::Instant::now(),
        );
        iface.set_any_ip(true);
        iface.update_ip_addrs(|ip_addrs| {
            let _ = ip_addrs.push(smoltcp::wire::IpCidr::new(
                smoltcp::wire::Ipv4Address::new(10, 0, 0, 1).into(),
                24,
            ));
            let _ = ip_addrs.push(smoltcp::wire::IpCidr::new(
                smoltcp::wire::Ipv6Address::new(0x0, 0xfac, 0, 0, 0, 0, 0, 1).into(),
                64,
            ));
        });

        if let Err(err) = iface
            .routes_mut()
            .add_default_ipv4_route(smoltcp::wire::Ipv4Address::new(10, 0, 0, 1))
        {
            warn!("failed to add default IPv4 route to smoltcp interface: {err}");
        }
        if let Err(err) = iface.routes_mut().add_default_ipv6_route(
            smoltcp::wire::Ipv6Address::new(0x0, 0xfac, 0, 0, 0, 0, 0, 1),
        ) {
            warn!("failed to add default IPv6 route to smoltcp interface: {err}");
        }

        iface
    }

    pub fn new(
        inbound: mpsc::Receiver<Packet>,
        outbound: mpsc::Sender<Packet>,
    ) -> Self {
        // the global bus that drives the iface polling
        let (iface_notifier, iface_notifier_rx) =
            mpsc::channel(IFACE_EVENT_QUEUE_SIZE);
        let mut device = NetstackDevice::new(outbound, iface_notifier.clone());
        let mut iface = Self::build_interface(&mut device);

        let (socket_stream_emitter, socket_stream) =
            mpsc::channel::<TcpStream>(TCP_ACCEPT_QUEUE_SIZE);

        let tracked_streams = Arc::new(Mutex::new(Vec::new()));
        let last_tcp_packet = Arc::new(Mutex::new(None));

        let poll_packet_tracked_streams = tracked_streams.clone();
        let task_tracked_streams = tracked_streams.clone();
        let poll_packet_last_tcp_packet = last_tcp_packet.clone();
        let poll_socket_last_tcp_packet = last_tcp_packet;
        let task_handle = tokio::spawn(async move {
            let _shutdown_guard = StreamShutdownGuard {
                streams: task_tracked_streams,
            };
            let rv = tokio::select! {
                biased;
                rv = Self::poll_packets(inbound, device.create_injector(), iface_notifier, socket_stream_emitter, poll_packet_tracked_streams, poll_packet_last_tcp_packet) => rv,
                rv = Self::poll_sockets(&mut iface, &mut device, iface_notifier_rx, poll_socket_last_tcp_packet) => rv,
            };
            if let Err(e) = rv {
                error!("Error in TCP listener: {e}");
            }
        });

        TcpListener {
            socket_stream,
            task_handle,
            tracked_streams,
        }
    }

    async fn poll_packets(
        mut inbound: mpsc::Receiver<Packet>,
        device_injector: mpsc::Sender<Packet>,
        iface_notifier: mpsc::Sender<IfaceEvent<'static>>,
        tcp_stream_emitter: mpsc::Sender<TcpStream>,
        tracked_streams: Arc<Mutex<Vec<Weak<TcpStreamHandle>>>>,
        last_tcp_packet: Arc<Mutex<Option<LastTcpPacketMeta>>>,
    ) -> std::io::Result<()> {
        let mut packet_buf = Vec::with_capacity(32);
        let mut syn_tracker: HashMap<(SocketAddr, SocketAddr), std::time::Instant> =
            HashMap::new();
        let mut last_prune_time = std::time::Instant::now();
        let mut syn_drop_count: u64 = 0;
        let mut last_syn_drop_log = std::time::Instant::now();
        let mut tcp_fragments = TcpFragmentReassembler::default();

        while let n = inbound.recv_many(&mut packet_buf, 32).await
            && n > 0
        {
            let now = std::time::Instant::now();
            if now.duration_since(last_prune_time) > SYN_TRACK_TTL {
                syn_tracker
                    .retain(|_, time| now.duration_since(*time) < SYN_TRACK_TTL);
                last_prune_time = now;
            }

            trace!("Received {n} packets from inbound channel");
            for mut frame in packet_buf.drain(..) {
                {
                    let packet = match IpPacket::new_checked(frame.data()) {
                        Ok(packet) => packet,
                        Err(err) => {
                            warn!("Invalid packet: {err}");
                            continue;
                        }
                    };
                    if !packet.verify_checksum() {
                        warn!("Invalid IP checksum");
                        continue;
                    }
                }

                let rebuilt_frame = {
                    let ip = match etherparse::IpSlice::from_slice(frame.data()) {
                        Ok(packet) => packet,
                        Err(err) => {
                            warn!("Invalid IP packet: {err}");
                            continue;
                        }
                    };
                    let payload = ip.payload();
                    if payload.fragmented {
                        if payload.ip_number != etherparse::ip_number::TCP {
                            warn!(
                                "fragmented packet on TCP path used protocol {:?}",
                                payload.ip_number
                            );
                            continue;
                        }
                        let tcp_payload = match tcp_fragments.push(&ip) {
                            Ok(Some(payload)) => payload,
                            Ok(None) => continue,
                            Err(err) => {
                                warn!("invalid TCP fragment sequence: {err}");
                                continue;
                            }
                        };
                        match rebuild_tcp_ip_packet(&ip, &tcp_payload) {
                            Ok(packet) => Some(packet),
                            Err(err) => {
                                warn!(
                                    "failed to rebuild fragmented TCP packet: {err}"
                                );
                                continue;
                            }
                        }
                    } else {
                        None
                    }
                };
                if let Some(rebuilt_frame) = rebuilt_frame {
                    frame = rebuilt_frame;
                }

                let packet = match IpPacket::new_checked(frame.data()) {
                    Ok(packet) => packet,
                    Err(err) => {
                        warn!("Invalid rebuilt IP packet: {err}");
                        continue;
                    }
                };
                let sliced = match etherparse::SlicedPacket::from_ip(frame.data()) {
                    Ok(packet) => packet,
                    Err(err) => {
                        warn!("Invalid IP transport packet: {err}");
                        continue;
                    }
                };

                if matches!(
                    sliced.transport,
                    Some(
                        etherparse::TransportSlice::Icmpv4(_)
                            | etherparse::TransportSlice::Icmpv6(_)
                    )
                ) {
                    match device_injector.send(frame.clone()).await {
                        Ok(_) => {}
                        Err(err) => {
                            warn!("Failed to send packet to device: {err}");
                            continue;
                        }
                    };
                    match iface_notifier.send(IfaceEvent::Icmp).await {
                        Ok(_) => continue,
                        Err(err) => {
                            warn!("Failed to send ICMP event: {err}");
                            continue;
                        }
                    }
                }

                let src_ip = packet.src_addr();
                let dst_ip = packet.dst_addr();
                let tcp = match sliced.transport {
                    Some(etherparse::TransportSlice::Tcp(tcp)) => tcp,
                    _ => {
                        warn!("TCP input did not contain a complete TCP segment");
                        continue;
                    }
                };

                let packet = match TcpPacket::new_checked(tcp.slice()) {
                    Ok(p) => p,
                    Err(err) => {
                        error!(
                            "invalid TCP err: {err}, src_ip: {src_ip}, dst_ip: \
                             {dst_ip}, payload: {:?}",
                            tcp.slice()
                        );
                        continue;
                    }
                };
                if !packet.verify_checksum(&src_ip.into(), &dst_ip.into()) {
                    warn!("Invalid TCP checksum: {src_ip} -> {dst_ip}");
                    continue;
                }
                let src_port = packet.src_port();
                let dst_port = packet.dst_port();

                let src_addr = SocketAddr::new(src_ip, src_port);
                let dst_addr = SocketAddr::new(dst_ip, dst_port);
                record_last_tcp_packet(
                    &last_tcp_packet,
                    &packet,
                    src_addr,
                    dst_addr,
                );

                if packet.syn() && !packet.ack() {
                    let conn_tuple = (src_addr, dst_addr);

                    if let Some(time) = syn_tracker.get_mut(&conn_tuple)
                        && now.duration_since(*time) < SYN_TRACK_TTL
                    {
                        // Refresh timestamp so the entry doesn't expire
                        // while the connection is still retransmitting SYNs.
                        *time = now;
                        device_injector.send(frame.clone()).await.map_err(|e| {
                            error!("Failed to inject retransmitted SYN packet: {e}");
                            std::io::Error::other(
                                "Failed to inject retransmitted SYN packet",
                            )
                        })?;
                        continue;
                    }

                    // TODO: get rid of this stupid log
                    if syn_tracker.len() >= SYN_TRACK_MAX {
                        syn_drop_count += 1;
                        if syn_drop_count == 1
                            || now.duration_since(last_syn_drop_log)
                                >= Duration::from_secs(10)
                        {
                            debug!(
                                "SYN flood protection: dropping SYN from \
                                 {src_addr} ({syn_drop_count} total dropped)"
                            );
                            last_syn_drop_log = now;
                        }
                        continue;
                    }

                    if !has_active_stream_capacity(
                        &tracked_streams,
                        ACTIVE_TCP_STREAM_MAX,
                    )? {
                        syn_drop_count += 1;
                        if syn_drop_count == 1
                            || now.duration_since(last_syn_drop_log)
                                >= Duration::from_secs(10)
                        {
                            warn!(
                                "TCP active stream limit reached ({ACTIVE_TCP_STREAM_MAX}); dropping SYN from {src_addr}"
                            );
                            last_syn_drop_log = now;
                        }
                        continue;
                    }

                    let stream_permit = match tcp_stream_emitter.try_reserve() {
                        Ok(permit) => permit,
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            debug!(
                                "TCP accept queue full ({TCP_ACCEPT_QUEUE_SIZE}); dropping SYN from {src_addr}"
                            );
                            continue;
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::BrokenPipe,
                                "TCP accept queue closed",
                            ));
                        }
                    };

                    let mut socket = tcp::Socket::new(
                        tcp::SocketBuffer::new(vec![
                            0u8;
                            DEFAULT_TCP_RECV_BUFFER_SIZE
                                as usize
                        ]),
                        tcp::SocketBuffer::new(vec![
                            0u8;
                            DEFAULT_TCP_SEND_BUFFER_SIZE
                                as usize
                        ]),
                    );
                    socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(
                        28,
                    )));

                    socket.set_timeout(Some(smoltcp::time::Duration::from_secs(
                        if cfg!(target_os = "linux") { 7200 } else { 60 },
                    )));
                    // Default
                    socket.set_ack_delay(Some(Duration::from_millis(10).into()));
                    socket.set_nagle_enabled(false);
                    socket.set_congestion_control(tcp::CongestionControl::Cubic);

                    if let Err(err) = socket.listen(dst_addr) {
                        error!("listen error: {err:?}");
                        continue;
                    }

                    // Track after listen() succeeds so a failed listen
                    // doesn't block future SYNs for the same tuple.
                    syn_tracker.insert(conn_tuple, now);

                    trace!("created TCP connection for {src_addr} <-> {dst_addr}");

                    let handle = Arc::new(TcpStreamHandle::new());
                    if let Ok(mut streams) = tracked_streams.lock() {
                        streams.retain(|stream| stream.strong_count() > 0);
                        streams.push(Arc::downgrade(&handle));
                    }

                    stream_permit.send(TcpStream {
                        local_addr: src_addr,
                        remote_addr: dst_addr,
                        handle: handle.clone(),
                        stack_notifier: iface_notifier.clone(),
                    });
                    iface_notifier
                        .send(IfaceEvent::TcpStream(Box::new((socket, handle))))
                        .await
                        .map_err(|e| {
                            error!("Failed to send TCP stream event: {e}");
                            std::io::Error::other("Failed to send TCP stream event")
                        })?;
                } else {
                    // Non-SYN packet: the connection has progressed past the
                    // handshake, so remove the tracker entry to free the slot.
                    syn_tracker.remove(&(src_addr, dst_addr));
                }

                device_injector.send(frame.clone()).await.map_err(|e| {
                    error!("Failed to send packet to device: {e}");
                    std::io::Error::other("Failed to inject packet to device")
                })?;
            }

            // trigger another poll to drive the socket state machine
            iface_notifier
                .send(IfaceEvent::DeviceReady)
                .await
                .map_err(|e| {
                    error!("Failed to send device ready event: {e}");
                    std::io::Error::other("Failed to send device ready event")
                })?;
        }

        Ok(())
    }

    async fn poll_sockets(
        iface: &mut Interface,
        device: &mut NetstackDevice,
        mut notifier_rx: mpsc::Receiver<IfaceEvent<'_>>,
        last_tcp_packet: Arc<Mutex<Option<LastTcpPacketMeta>>>,
    ) -> std::io::Result<()> {
        // Create a socket set for TCP sockets
        let mut sockets = smoltcp::iface::SocketSet::new(vec![]);
        let mut socket_maps: HashMap<
            smoltcp::iface::SocketHandle,
            Arc<TcpStreamHandle>,
        > = HashMap::new();
        let mut next_poll = None;
        let mut poll_requested = false;
        let mut panic_window_start = StdInstant::now();
        let mut panic_count = 0usize;

        loop {
            trace!(
                "Polling TCP sockets, next_poll: {:?}, num of sockets: {}",
                next_poll,
                socket_maps.len()
            );

            let should_poll_now = if poll_requested {
                true
            } else {
                match (next_poll, socket_maps.len()) {
                    (None, 0) => {
                        trace!("No sockets to poll, waiting indefinitely");
                        false
                    }
                    (None, _) => {
                        trace!("Polling sockets with no delay");
                        true
                    }
                    (Some(dur), _) => {
                        trace!("Polling sockets with delay: {dur:?}");
                        false
                    }
                }
            };
            poll_requested = false;
            let now = smoltcp::time::Instant::now();

            if should_poll_now {
                trace!("Woke up to poll sockets");

                // Drain pending notifier events before polling smoltcp.
                //
                // The critical race is IfaceEvent::TcpStream: poll_packets
                // creates the listening socket and queues it here before the
                // raw SYN is injected into the device buffer. If iface.poll()
                // runs first, smoltcp can observe the SYN without a matching
                // listener and immediately reply with RST.
                //
                // During active downloads poll_delay often returns 0/None, keeping
                // should_poll_now=true and never entering the else branch below.
                // Draining here ensures sockets are always registered in time.
                loop {
                    match notifier_rx.try_recv() {
                        Ok(IfaceEvent::TcpStream(stream)) => {
                            let socket_handle = sockets.add(stream.0);
                            socket_maps.insert(socket_handle, stream.1);
                            trace!(
                                "Added pending TCP socket before iface poll: {socket_handle:?}"
                            );
                        }
                        Ok(_) => {
                            // Other events only mean "poll soon", which is
                            // already what this branch is about to do.
                        }
                        Err(_) => break,
                    }
                }

                if let Err(payload) = catch_unwind(AssertUnwindSafe(|| {
                    iface.poll(now, device, &mut sockets);
                })) {
                    let panic_message = panic_payload_to_string(payload);
                    let active_socket_count = socket_maps.len();
                    let last_packet =
                        last_tcp_packet.lock().ok().and_then(|guard| guard.clone());
                    mark_all_streams_closed(&socket_maps);
                    socket_maps.clear();
                    sockets = smoltcp::iface::SocketSet::new(vec![]);
                    *iface = Self::build_interface(device);
                    next_poll = None;

                    let now = StdInstant::now();
                    if now.duration_since(panic_window_start)
                        > Duration::from_secs(10)
                    {
                        panic_window_start = now;
                        panic_count = 0;
                    }
                    panic_count += 1;
                    let last_packet_log = last_packet
                        .as_ref()
                        .map(std::string::ToString::to_string)
                        .unwrap_or_else(|| "<none>".to_string());
                    error!(
                        "smoltcp iface.poll panicked: {panic_message}; active sockets: {}; last tcp packet: {}",
                        active_socket_count, last_packet_log
                    );
                    if panic_count >= 5 {
                        return Err(std::io::Error::other(format!(
                            "smoltcp iface.poll panicked repeatedly ({panic_count} times in 10s): {panic_message}"
                        )));
                    }
                    continue;
                }

                // Poll the sockets for new connections or data
                for (socket_handle, socket_control) in socket_maps.iter() {
                    let socket = sockets.get_mut::<tcp::Socket>(*socket_handle);
                    trace!(
                        "Polling TCP socket: {:?}, can_recv: {}, can_send: {}",
                        socket_handle,
                        socket.can_recv(),
                        socket.can_send()
                    );

                    let buf = &socket_control.recv_buffer;
                    let mut notify_read = false;
                    while socket.can_recv() && !buf.is_full() {
                        if let Ok(n) = socket.recv(|buffer| {
                            let n = buf.enqueue_slice(buffer);
                            (n, n)
                        }) {
                            trace!("Received {n} bytes from TCP socket");
                        }
                        notify_read = true;
                    }
                    if notify_read {
                        socket_control.recv_waker.wake();
                    }

                    let buf = &socket_control.send_buffer;
                    let mut notify_write = false;
                    while socket.can_send() && !buf.is_empty() {
                        if let Ok(n) = socket.send(|buffer| {
                            let n = buf.dequeue_slice(buffer);
                            (n, n)
                        }) {
                            trace!("Sent {n} bytes to TCP socket");
                        }
                        notify_write = true;
                    }

                    if notify_write {
                        socket_control.send_waker.wake();
                    }

                    // Only signal EOF/close after the socket has moved past
                    // the handshake states (Listen, SynSent, SynReceived).
                    // During the handshake may_recv()/may_send() return false
                    // but that does NOT mean the connection is closing — the
                    // flags are one-way and would permanently break the stream.
                    let past_handshake = !matches!(
                        socket.state(),
                        tcp::State::Listen
                            | tcp::State::SynSent
                            | tcp::State::SynReceived
                    );

                    if past_handshake
                        && !socket.may_recv()
                        && !socket.can_recv()
                        && !socket_control.read_closed.swap(true, Ordering::AcqRel)
                    {
                        socket_control.recv_waker.wake();
                    }

                    if socket_control.write_shutdown.load(Ordering::Acquire)
                        && buf.is_empty()
                        && socket.may_send()
                    {
                        trace!("Closing TCP socket send half after buffer drained");
                        socket.close();
                    }

                    if past_handshake
                        && !socket.may_send()
                        && !socket_control.write_closed.swap(true, Ordering::AcqRel)
                    {
                        socket_control.send_waker.wake();
                    }
                }

                socket_maps.retain(|handle, socket_control| {
                    let socket = sockets.get_mut::<tcp::Socket>(*handle);

                    if socket_control.socket_dropped.load(Ordering::Acquire) {
                        // The app-side TcpStream was dropped. Flush remaining
                        // data from send_buffer into smoltcp's TX buffer, then
                        // initiate a graceful FIN. Do not remove immediately,
                        // otherwise smoltcp may discard queued TX data.
                        let buf = &socket_control.send_buffer;
                        while socket.can_send() && !buf.is_empty() {
                            if let Ok(n) = socket.send(|buffer| {
                                let n = buf.dequeue_slice(buffer);
                                (n, n)
                            }) {
                                trace!("Flushing {n} bytes to closing TCP socket");
                            }
                        }
                        if buf.is_empty() {
                            socket.close();
                        }
                        // Keep the socket until smoltcp finishes the close
                        // handshake and reports is_active() == false.
                    }

                    if socket.is_active() {
                        true
                    } else {
                        trace!("Removing inactive TCP socket");
                        // Unblock any in-flight poll_read / poll_write on this
                        // stream. socket_closed covers RST/timeout paths where
                        // read_closed may not have been set by the data path.
                        socket_control.socket_closed.store(true, Ordering::Release);
                        socket_control.write_closed.store(true, Ordering::Release);
                        socket_control.recv_waker.wake();
                        socket_control.send_waker.wake();
                        sockets.remove(*handle);
                        false
                    }
                });

                next_poll = match iface.poll_delay(now, &sockets) {
                    Some(smoltcp::time::Duration::ZERO) => None,
                    Some(delay) => {
                        trace!("device poll delay: {delay:?}");
                        Some(delay.into())
                    }
                    None => None,
                };

                // Yield to the tokio scheduler so StackSplitStream can drain
                // outbound packets and send ACKs back. Without this, sustained
                // zero poll_delay can create a tight loop that starves readers.
                tokio::task::yield_now().await;
            } else {
                tokio::select! {
                    Some(event) = notifier_rx.recv() => {
                        trace!("Received iface event, will poll sockets");
                        next_poll = None; // reset the next poll time
                        poll_requested = true;
                        match event {
                            IfaceEvent::TcpStream(stream) => {
                                let socket_handle = sockets.add(stream.0);
                                socket_maps.insert(socket_handle, stream.1);
                                trace!("Added new TCP socket: {socket_handle:?}");
                            }
                            IfaceEvent::TcpSocketReady => {
                                trace!("TCP socket is ready to read/write");
                            }
                            IfaceEvent::TcpSocketClosed => {
                                trace!("TCP socket closed by application");
                            }
                            IfaceEvent::DeviceReady => {
                                trace!("Device generated some packets, will poll sockets");
                            }
                            IfaceEvent::Icmp => {
                                trace!("ICMP packet received, will poll sockets");
                            }
                        }
                    }
                    _ = tokio::time::sleep(next_poll.unwrap_or(Duration::MAX)) => {
                        trace!("Woke up to poll sockets after delay");
                        next_poll = None; // reset the next poll time
                    }
                }
            }
        }
    }
}

impl futures::Stream for TcpListener {
    type Item = TcpStream;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.socket_stream.poll_recv(cx)
    }
}

#[cfg(test)]
mod resource_limit_tests {
    use super::*;

    #[test]
    fn active_stream_capacity_recovers_after_drop() {
        let streams = Mutex::new(Vec::new());
        let first = Arc::new(TcpStreamHandle::new());
        let second = Arc::new(TcpStreamHandle::new());
        {
            let mut tracked = streams.lock().unwrap();
            tracked.push(Arc::downgrade(&first));
            tracked.push(Arc::downgrade(&second));
        }

        assert!(!has_active_stream_capacity(&streams, 2).unwrap());
        drop(first);
        assert!(has_active_stream_capacity(&streams, 2).unwrap());
    }
}
