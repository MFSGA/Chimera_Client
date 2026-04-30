use futures::{SinkExt, StreamExt};
use std::{
    collections::HashMap,
    fmt::{Debug, Formatter},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{io::AsyncWriteExt, sync::RwLock, task::JoinHandle};
use tracing::{Instrument, debug, error, info_span, instrument, trace, warn};

use crate::{
    app::{
        dispatcher::{
            TrackedStream, statistics_manager::StatisticsManager,
            tracked::TrackedDatagram,
        },
        dns::{ClashResolver, ThreadSafeDNSResolver},
        outbound::manager::ThreadSafeOutboundManager,
        router::ThreadSafeRouter,
    },
    common::io::{ShutdownMode, copy_bidirectional},
    config::{
        def::RunMode,
        internal::proxy::{PROXY_DIRECT, PROXY_GLOBAL},
    },
    proxy::{
        AnyInboundDatagram, ClientStream, datagram::UdpPacket, utils::ToCanonical,
    },
    session::{Session, SocksAddr},
};

// SS2022 (AEAD-2022) MAX_PACKET_SIZE is 0xFFFF (65535 bytes). A smaller
// relay buffer forces full packets into multiple encrypted chunks and increases
// encrypt/decrypt overhead.
const DEFAULT_BUFFER_SIZE: usize = 64 * 1024;

pub struct Dispatcher {
    outbound_manager: ThreadSafeOutboundManager,
    resolver: ThreadSafeDNSResolver,
    manager: Arc<StatisticsManager>,
    tcp_buffer_size: usize,
    mode: Arc<RwLock<RunMode>>,
    router: ThreadSafeRouter,
}

impl Debug for Dispatcher {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dispatcher").finish()
    }
}

impl Dispatcher {
    pub fn new(
        outbound_manager: ThreadSafeOutboundManager,
        router: ThreadSafeRouter,
        resolver: ThreadSafeDNSResolver,
        mode: RunMode,
        statistics_manager: Arc<StatisticsManager>,
        tcp_buffer_size: Option<usize>,
    ) -> Self {
        Self {
            outbound_manager,
            resolver,
            manager: statistics_manager,
            tcp_buffer_size: tcp_buffer_size.unwrap_or(DEFAULT_BUFFER_SIZE),
            mode: Arc::new(RwLock::new(mode)),
            router,
        }
    }

    pub fn tcp_buffer_size(&self) -> usize {
        self.tcp_buffer_size
    }

    pub fn resolver(&self) -> ThreadSafeDNSResolver {
        self.resolver.clone()
    }

    pub fn statistics_manager(&self) -> Arc<StatisticsManager> {
        self.manager.clone()
    }

    pub async fn get_mode(&self) -> RunMode {
        *self.mode.read().await
    }

    pub async fn set_mode(&self, mode: RunMode) {
        *self.mode.write().await = mode;
    }

    #[instrument(skip(self, sess, lhs))]
    pub async fn dispatch_stream(
        &self,
        mut sess: Session,
        mut lhs: Box<dyn ClientStream>,
    ) {
        let dest: SocksAddr =
            match reverse_lookup(&self.resolver, &sess.destination).await {
                Some(dest) => dest,
                None => {
                    warn!("failed to resolve destination {}", sess);
                    return;
                }
            };

        sess.destination = dest.clone();

        let mode = *self.mode.read().await;
        let (outbound_name, rule) = match mode {
            RunMode::Global => (PROXY_GLOBAL, None),
            RunMode::Rule => self.router.match_route(&mut sess).await,
            RunMode::Direct => (PROXY_DIRECT, None),
        };

        debug!("dispatching {} to {}[{}]", sess, outbound_name, mode);
        let rule_summary = rule_summary(rule);

        let mgr = self.outbound_manager.clone();
        let handler = match mgr.get_outbound(outbound_name).await {
            Some(h) => h,
            None => {
                debug!("unknown rule: {}, fallback to direct", outbound_name);
                mgr.get_outbound(PROXY_DIRECT).await.unwrap()
            }
        };

        match handler
            .connect_stream(&sess, self.resolver.clone())
            .instrument(info_span!("connect_stream", outbound_name = outbound_name,))
            .await
        {
            Ok(rhs) => {
                debug!(
                    outbound_name,
                    rule = %rule_summary,
                    mode = %mode,
                    source = %sess.source,
                    destination = %sess.destination,
                    "remote connection established"
                );
                let rhs = TrackedStream::new(
                    rhs,
                    self.manager.clone(),
                    sess.clone(),
                    rule,
                )
                .await;
                let shutdown_mode = if sess.typ == crate::session::Type::HttpConnect
                {
                    ShutdownMode::FlushOnly
                } else {
                    ShutdownMode::HalfClose
                };
                match copy_bidirectional(
                    lhs,
                    rhs,
                    self.tcp_buffer_size,
                    Duration::from_secs(10),
                    Duration::from_secs(10),
                    shutdown_mode,
                )
                .instrument(info_span!(
                    "copy_bidirectional",
                    outbound_name = outbound_name,
                ))
                .await
                {
                    Ok((up, down)) => {
                        debug!(
                            "connection {} closed with {} bytes up, {} bytes down",
                            sess, up, down
                        );
                    }
                    Err(err) => match err {
                        crate::common::io::CopyBidirectionalError::LeftClosed(
                            err,
                        ) => match err.kind() {
                            std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::BrokenPipe => {
                                debug!(
                                    "connection {} closed with error {} by local",
                                    sess, err
                                );
                            }
                            _ => {
                                warn!(
                                    "connection {} closed with error {} by local",
                                    sess, err
                                );
                            }
                        },
                        crate::common::io::CopyBidirectionalError::RightClosed(
                            err,
                        ) => match err.kind() {
                            std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::BrokenPipe => {
                                debug!(
                                    "connection {} closed with error {} by remote",
                                    sess, err
                                );
                            }
                            _ => {
                                warn!(
                                    "connection {} closed with error {} by remote",
                                    sess, err
                                );
                            }
                        },
                        crate::common::io::CopyBidirectionalError::Other(err) => {
                            match err.kind() {
                                std::io::ErrorKind::UnexpectedEof
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::BrokenPipe => {
                                    debug!(
                                        "connection {} closed with error {}",
                                        sess, err
                                    );
                                }
                                _ => {
                                    warn!(
                                        "connection {} closed with error {}",
                                        sess, err
                                    );
                                }
                            }
                        }
                    },
                }
            }
            Err(err) => {
                warn!(
                    outbound_name,
                    rule = %rule_summary,
                    mode = %mode,
                    source = %sess.source,
                    destination = %sess.destination,
                    error = %err,
                    "failed to establish remote connection"
                );
                if let Err(e) = lhs.shutdown().await {
                    warn!("error closing local connection {}: {}", sess, e)
                }
            }
        }
    }

    /// Dispatch a UDP packet to outbound handler
    /// returns the close sender
    #[instrument]
    #[must_use]
    pub async fn dispatch_datagram(
        &self,
        sess: Session,
        udp_inbound: AnyInboundDatagram,
    ) -> tokio::sync::oneshot::Sender<u8> {
        let outbound_handle_guard = TimeoutUdpSessionManager::new();

        let router = self.router.clone();
        let outbound_manager = self.outbound_manager.clone();
        let resolver = self.resolver.clone();
        let mode = self.mode.clone();
        let manager = self.manager.clone();

        #[rustfmt::skip]
        /*
         *  implement details
         *
         *  data structure:
         *    local_r, local_w: stream/sink pair
         *    remote_r, remote_w: stream/sink pair
         *    remote_receiver_r, remote_receiver_w: channel pair
         *    remote_sender, remote_forwarder: channel pair
         *
         *  data flow:
         *    => local_r => init packet => connect_datagram => remote_sender     => remote_forwarder         => remote_w
         *    => local_w                                    <= remote_receiver_r <= NAT + remote_receiver_w  <= remote_r
         *
         *  notice:
         *    the NAT is binded to the session in the dispatch_datagram function arg and the closure
         *    so we need not to add a global NAT table and do the translation
         */
        let (mut local_w, mut local_r) = udp_inbound.split();
        let (remote_receiver_w, mut remote_receiver_r) =
            tokio::sync::mpsc::channel(256);

        let s = sess.clone();
        let ss = sess.clone();
        let t1 = tokio::spawn(async move {
            while let Some(mut packet) = local_r.next().await {
                let mut sess = sess.clone();

                // SS2022 and dual-stack UDP inbounds can surface IPv4 targets as
                // IPv4-mapped IPv6. Keep the canonical IP before fake-IP reverse
                // lookup may replace the destination with a domain.
                if let SocksAddr::Ip(addr) = &mut packet.dst_addr {
                    *addr = addr.to_canonical();
                    sess.resolved_ip = Some(addr.ip());
                }

                let dest = match reverse_lookup(&resolver, &packet.dst_addr).await {
                    Some(dest) => dest,
                    None => {
                        warn!("failed to resolve destination {}", sess);
                        continue;
                    }
                };

                // for TUN or Tproxy, we need the original destination address
                let orig_dest = packet.dst_addr.clone();
                sess.source = packet.src_addr.clone().must_into_socket_addr();
                sess.destination = dest.clone();
                sess.inbound_user = packet.inbound_user.clone();

                let mode = *mode.read().await;

                let (outbound_name, rule) = match mode {
                    RunMode::Global => (PROXY_GLOBAL, None),
                    RunMode::Rule => router.match_route(&mut sess).await,
                    RunMode::Direct => (PROXY_DIRECT, None),
                };

                let outbound_name = outbound_name.to_string();

                let remote_receiver_w = remote_receiver_w.clone();

                let mgr = outbound_manager.clone();
                let handler = match mgr.get_outbound(&outbound_name).await {
                    Some(h) => h,
                    None => {
                        debug!(
                            "unknown rule: {}, fallback to direct",
                            outbound_name
                        );
                        mgr.get_outbound(PROXY_DIRECT).await.unwrap()
                    }
                };

                let outbound_name =
                    if let Some(group) = handler.try_as_group_handler() {
                        group
                            .get_active_proxy()
                            .await
                            .map(|x| x.name().to_owned())
                            .unwrap_or(outbound_name)
                    } else {
                        outbound_name
                    };

                let rule_summary = rule_summary(rule);
                debug!(
                    outbound_name = %outbound_name,
                    rule = %rule_summary,
                    mode = %mode,
                    source = %sess.source,
                    orig_dest = %orig_dest,
                    resolved_dest = %sess.destination,
                    "dispatching udp packet"
                );

                match outbound_handle_guard
                    .get_outbound_sender_mut(
                        &outbound_name,
                        packet.src_addr.clone().must_into_socket_addr(), /* this is only
                                                                          * expected to be
                                                                          * socket addr as it's
                                                                          * from local
                                                                          * udp */
                    )
                    .await
                {
                    None => {
                        debug!(
                            outbound_name = %outbound_name,
                            rule = %rule_summary,
                            source = %sess.source,
                            orig_dest = %orig_dest,
                            resolved_dest = %sess.destination,
                            "building outbound datagram"
                        );
                        let outbound_datagram = match handler
                            .connect_datagram(&sess, resolver.clone())
                            .await
                        {
                            Ok(v) => v,
                            Err(err) => {
                                error!(
                                    outbound_name = %outbound_name,
                                    rule = %rule_summary,
                                    source = %sess.source,
                                    orig_dest = %orig_dest,
                                    resolved_dest = %sess.destination,
                                    error = %err,
                                    "failed to connect outbound datagram"
                                );
                                continue;
                            }
                        };

                        debug!(
                            outbound_name = %outbound_name,
                            rule = %rule_summary,
                            source = %sess.source,
                            orig_dest = %orig_dest,
                            resolved_dest = %sess.destination,
                            "outbound datagram connected"
                        );

                        let outbound_datagram = TrackedDatagram::new(
                            outbound_datagram,
                            manager.clone(),
                            sess.clone(),
                            rule,
                        )
                        .await;

                        let (mut remote_w, mut remote_r) = outbound_datagram.split();
                        let (remote_sender, mut remote_forwarder) =
                            tokio::sync::mpsc::channel::<(UdpPacket, SocksAddr)>(
                                256,
                            );
                        let sess_for_rw = sess.clone();
                        let outbound_name_for_rw = outbound_name.clone();

                        let rw_handle = tokio::spawn(async move {
                            const ORIG_MAP_MAX: usize = 256;
                            let mut orig_map: HashMap<SocksAddr, SocksAddr> =
                                HashMap::new();
                            let mut last_orig_addr: Option<SocksAddr> = None;

                            loop {
                                tokio::select! {
                                    packet = remote_forwarder.recv() => {
                                        let Some((mut packet, dest)) = packet else { break };
                                        let orig = packet.dst_addr.clone();
                                        packet.dst_addr = dest;
                                        if orig != packet.dst_addr {
                                            if orig_map.len() >= ORIG_MAP_MAX
                                                && let Some(key) =
                                                    orig_map.keys().next().cloned()
                                            {
                                                orig_map.remove(&key);
                                            }
                                            orig_map.insert(packet.dst_addr.clone(), orig.clone());
                                        }
                                        last_orig_addr = Some(orig.clone());

                                        if let Err(err) = remote_w.send(packet).await {
                                            warn!(
                                                outbound_name = %outbound_name_for_rw,
                                                session = %sess_for_rw,
                                                orig_dest = %orig,
                                                error = ?err,
                                                "failed to send packet to remote"
                                            );
                                            break;
                                        }
                                    }

                                    packet = remote_r.next() => {
                                        let Some(mut packet) = packet else { break };
                                        if let Some(orig) =
                                            orig_map.get(&packet.src_addr).cloned()
                                        {
                                            packet.src_addr = orig;
                                        } else if !orig_map.is_empty()
                                            && let Some(ref fallback) = last_orig_addr
                                        {
                                            packet.src_addr = fallback.clone();
                                        }
                                        packet.dst_addr = sess.source.into();

                                        debug!(
                                            outbound_name = %outbound_name_for_rw,
                                            session = %sess_for_rw,
                                            packet = ?packet,
                                            "udp nat remote packet"
                                        );
                                        if let Err(err) = remote_receiver_w.send(packet).await {
                                            warn!(
                                                outbound_name = %outbound_name_for_rw,
                                                session = %sess_for_rw,
                                                error = %err,
                                                "failed to send packet to local"
                                            );
                                            break;
                                        }
                                    }
                                }
                            }
                        });

                        outbound_handle_guard
                            .insert(
                                &outbound_name,
                                packet.src_addr.clone().must_into_socket_addr(),
                                rw_handle,
                                remote_sender.clone(),
                            )
                            .await;

                        try_queue_outbound_packet(
                            &remote_sender,
                            packet,
                            dest,
                            &sess,
                            &outbound_name,
                            &orig_dest,
                        );
                    }
                    Some(handle) => {
                        // TODO: need to reset when GLOBAL select is changed
                        try_queue_outbound_packet(
                            &handle,
                            packet,
                            dest,
                            &sess,
                            &outbound_name,
                            &orig_dest,
                        );
                        debug!(
                            outbound_name = %outbound_name,
                            rule = %rule_summary,
                            source = %sess.source,
                            orig_dest = %orig_dest,
                            resolved_dest = %sess.destination,
                            "reusing outbound datagram"
                        );
                    }
                };
            }

            trace!("UDP session local -> remote finished for {}", ss);
        });

        let ss = s.clone();
        let t2 = tokio::spawn(async move {
            while let Some(packet) = remote_receiver_r.recv().await {
                match local_w.send(packet).await {
                    Ok(_) => {}
                    Err(err) => {
                        warn!("failed to send packet to local: {}", err);
                        break;
                    }
                }
            }
            trace!("UDP session remote -> local finished for {}", ss);
        });

        let (close_sender, close_receiver) = tokio::sync::oneshot::channel::<u8>();

        tokio::spawn(async move {
            match close_receiver.await {
                Ok(_) => {
                    trace!("UDP close signal for {} received", s);
                }
                Err(_) => {
                    trace!(
                        "UDP close sender for {} dropped before explicit close; treating as normal shutdown",
                        s
                    );
                }
            }

            t1.abort();
            t2.abort();
        });

        close_sender
    }
}

// helper function to resolve the destination address
// if the destination is an IP address, check if it's a fake IP
// or look for cached IP
// if the destination is a domain name, don't resolve
async fn reverse_lookup(
    resolver: &Arc<dyn ClashResolver>,
    dst: &SocksAddr,
) -> Option<SocksAddr> {
    let dst = match dst {
        crate::session::SocksAddr::Ip(socket_addr) => {
            if resolver.fake_ip_enabled() {
                let ip = socket_addr.ip();
                if resolver.is_fake_ip(ip).await {
                    trace!("looking up fake ip: {}", socket_addr.ip());
                    match resolver.reverse_lookup(ip).await {
                        Some(host) => (host, socket_addr.port())
                            .try_into()
                            .expect("must be valid domain"),
                        None => {
                            error!("failed to reverse lookup fake ip: {}", ip);
                            return None;
                        }
                    }
                } else {
                    (*socket_addr).into()
                }
            } else {
                trace!("looking up resolve cache ip: {}", socket_addr.ip());
                match resolver.cached_for(socket_addr.ip()).await {
                    Some(host) => (host, socket_addr.port())
                        .try_into()
                        .expect("must be valid domain"),
                    None => (*socket_addr).into(),
                }
            }
        }
        crate::session::SocksAddr::Domain(host, port) => (host.to_owned(), *port)
            .try_into()
            .expect("must be valid domain"),
    };
    Some(dst)
}

fn rule_summary(rule: Option<&Box<dyn crate::app::router::RuleMatcher>>) -> String {
    rule.map(|rule| {
        let payload = rule.payload();
        if payload.is_empty() {
            rule.type_name().to_string()
        } else {
            format!("{} {}", rule.type_name(), payload)
        }
    })
    .unwrap_or_else(|| "implicit MATCH".to_string())
}

type OutboundPacketSender = tokio::sync::mpsc::Sender<(UdpPacket, SocksAddr)>;

fn try_queue_outbound_packet(
    sender: &OutboundPacketSender,
    packet: UdpPacket,
    dest: SocksAddr,
    sess: &Session,
    outbound_name: &str,
    orig_dest: &SocksAddr,
) {
    match sender.try_send((packet, dest)) {
        Ok(()) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            warn!(
                outbound_name,
                source = %sess.source,
                orig_dest = %orig_dest,
                resolved_dest = %sess.destination,
                "dropping UDP packet because outbound session queue is full"
            );
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            warn!(
                outbound_name,
                source = %sess.source,
                orig_dest = %orig_dest,
                resolved_dest = %sess.destination,
                "failed to send packet to remote: outbound session is closed"
            );
        }
    }
}

struct TimeoutUdpSessionManager {
    map: Arc<RwLock<OutboundHandleMap>>,

    cleaner: Option<JoinHandle<()>>,
}

impl Drop for TimeoutUdpSessionManager {
    fn drop(&mut self) {
        trace!("dropping timeout udp session manager");
        if let Some(x) = self.cleaner.take() {
            x.abort()
        }
    }
}

impl TimeoutUdpSessionManager {
    fn new() -> Self {
        let map = Arc::new(RwLock::new(OutboundHandleMap::new()));
        let timeout = Duration::from_secs(10);

        let map_cloned = map.clone();

        let cleaner = tokio::spawn(async move {
            trace!("timeout udp session cleaner scanning");
            let mut interval = tokio::time::interval(timeout);

            loop {
                interval.tick().await;
                trace!("timeout udp session cleaner ticking");

                let mut g = map_cloned.write().await;
                let mut alived = 0;
                let mut expired = 0;
                g.0.retain(|k, x| {
                    let (handle, _, last) = x;
                    let now = Instant::now();
                    let alive = now.duration_since(*last) < timeout;
                    if !alive {
                        expired += 1;
                        trace!("udp session expired: {:?}", k);
                        handle.abort();
                    } else {
                        alived += 1;
                    }
                    alive
                });
                trace!(
                    "timeout udp session cleaner finished, alived: {}, expired: {}",
                    alived, expired
                );
            }
        });

        Self {
            map,

            cleaner: Some(cleaner),
        }
    }

    async fn insert(
        &self,
        outbound_name: &str,
        src_addr: SocketAddr,
        handle: JoinHandle<()>,
        sender: OutboundPacketSender,
    ) {
        let mut map = self.map.write().await;
        map.insert(outbound_name, src_addr, handle, sender);
    }

    async fn get_outbound_sender_mut(
        &self,
        outbound_name: &str,
        src_addr: SocketAddr,
    ) -> Option<OutboundPacketSender> {
        let mut map = self.map.write().await;
        map.get_outbound_sender_mut(outbound_name, src_addr)
    }
}

type OutboundHandleKey = (String, SocketAddr);
type OutboundHandleVal = (JoinHandle<()>, OutboundPacketSender, Instant);

struct OutboundHandleMap(HashMap<OutboundHandleKey, OutboundHandleVal>);

impl OutboundHandleMap {
    fn new() -> Self {
        Self(HashMap::new())
    }

    fn insert(
        &mut self,
        outbound_name: &str,
        src_addr: SocketAddr,
        handle: JoinHandle<()>,
        sender: OutboundPacketSender,
    ) {
        self.0.insert(
            (outbound_name.to_string(), src_addr),
            (handle, sender, Instant::now()),
        );
    }

    fn get_outbound_sender_mut(
        &mut self,
        outbound_name: &str,
        src_addr: SocketAddr,
    ) -> Option<OutboundPacketSender> {
        self.0.get_mut(&(outbound_name.to_owned(), src_addr)).map(
            |(_, sender, last)| {
                trace!(
                    "updating last access time for outbound {:?}",
                    (outbound_name, src_addr)
                );
                *last = Instant::now();
                sender.clone()
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{OutboundHandleMap, try_queue_outbound_packet};
    use crate::session::{Network, Session, SocksAddr, Type};
    use std::{future::pending, net::SocketAddr, str::FromStr};
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn outbound_handle_map_reuses_session_by_source_for_full_cone_nat() {
        let mut map = OutboundHandleMap::new();
        let src_addr = SocketAddr::from_str("127.0.0.1:53000").unwrap();
        let dest_a = SocksAddr::from_str("8.8.8.8:53").unwrap();
        let dest_b = SocksAddr::from_str("1.1.1.1:53").unwrap();

        let (sender_a, mut receiver_a) = mpsc::channel(1);
        let (sender_b, mut receiver_b) = mpsc::channel(1);

        map.insert("DIRECT", src_addr, tokio::spawn(pending()), sender_a);
        map.insert("DIRECT", src_addr, tokio::spawn(pending()), sender_b);

        let handle_a = map
            .get_outbound_sender_mut("DIRECT", src_addr)
            .expect("session should exist");
        let handle_b = map
            .get_outbound_sender_mut("DIRECT", src_addr)
            .expect("session should still exist");

        handle_a.send((Default::default(), dest_a)).await.unwrap();
        handle_b.send((Default::default(), dest_b)).await.unwrap();

        assert!(receiver_a.try_recv().is_err());
        assert!(receiver_b.recv().await.is_some());
        assert!(receiver_b.recv().await.is_some());
    }

    #[test]
    fn try_queue_outbound_packet_drops_when_session_queue_is_full() {
        let (sender, mut receiver) = mpsc::channel(1);
        let sess = Session {
            network: Network::Udp,
            typ: Type::Ignore,
            source: SocketAddr::from_str("127.0.0.1:53000").unwrap(),
            destination: SocksAddr::from_str("8.8.8.8:53").unwrap(),
            resolved_ip: None,
            so_mark: None,
            iface: None,
            asn: None,
            traffic_stats: None,
            inbound_user: None,
        };

        sender.try_send(Default::default()).unwrap();
        try_queue_outbound_packet(
            &sender,
            Default::default(),
            sess.destination.clone(),
            &sess,
            "DIRECT",
            &sess.destination,
        );

        assert!(receiver.try_recv().is_ok());
        assert!(receiver.try_recv().is_err());
    }
}

impl Drop for OutboundHandleMap {
    fn drop(&mut self) {
        trace!(
            "dropping inner outbound handle map that has {} sessions",
            self.0.len()
        );
        for (_, (handle, ..)) in self.0.drain() {
            handle.abort();
        }
    }
}
