use crate::{
    app::{
        dispatcher::Dispatcher,
        dns::{ThreadSafeDNSResolver, dns_error_response, exchange_with_resolver},
    },
    common::errors::new_io_error,
    config::internal::config::DnsHijackRule,
    proxy::datagram::UdpPacket,
    session::{Network, Session, Type},
};
use futures::{
    FutureExt, Sink, Stream, StreamExt, future::BoxFuture, ready,
    stream::FuturesUnordered,
};
use std::{
    collections::VecDeque,
    fmt,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    task::Poll,
};
use tracing::{debug, trace, warn};

type PendingPermitFuture = BoxFuture<
    'static,
    Result<
        tokio::sync::mpsc::OwnedPermit<UdpPacket>,
        tokio::sync::mpsc::error::SendError<()>,
    >,
>;

type DnsHijackReplySender = Arc<
    dyn Fn(Vec<u8>, SocketAddr, SocketAddr) -> BoxFuture<'static, ()> + Send + Sync,
>;

type DnsHijackReply = (Vec<u8>, SocketAddr, SocketAddr);
type DnsHijackQuery = BoxFuture<'static, Option<DnsHijackReply>>;

const MAX_CONCURRENT_TUN_DNS_QUERIES: usize = 8;
const MAX_QUEUED_TUN_DNS_QUERIES: usize = 32;

/// Flush state for a pending dispatcher-to-TUN UDP packet.
///
/// This intentionally waits for mpsc capacity instead of using try_send: TUN UDP
/// may be lossy at the network layer, but dropping locally just because the
/// small handoff queue is temporarily full causes avoidable stalls under bursty
/// DNS/UDP traffic.
enum FlushState {
    Pending,
    Ready(tokio::sync::mpsc::OwnedPermit<UdpPacket>),
    Disconnected,
}

/// Process the exact DNS payload extracted by the netstack from an IPv4 UDP
/// packet. This is shared by the real TUN path and offline packet tests.
async fn exchange_hijacked_udp_dns(
    resolver: &ThreadSafeDNSResolver,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let msg = match hickory_proto::op::Message::from_vec(payload) {
        Ok(msg) => msg,
        Err(error) => {
            warn!("dropping malformed hijacked UDP DNS message: {error}");
            return None;
        }
    };
    trace!("hijack dns request: {:?}", msg);

    let mut response = match exchange_with_resolver(resolver, &msg, true).await {
        Ok(response) => response,
        Err(error) => {
            warn!("failed to exchange UDP DNS message: {error}");
            dns_error_response(&msg, hickory_proto::op::ResponseCode::ServFail)
        }
    };
    response.metadata.id = msg.metadata.id;
    trace!("hijack dns response: {:?}", response);
    match response.to_vec() {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            warn!("failed to serialize hijacked UDP DNS response: {error}");
            None
        }
    }
}

fn should_hijack_udp_dns(
    enabled: bool,
    rules: &[DnsHijackRule],
    destination: std::net::SocketAddr,
) -> bool {
    enabled
        && if rules.is_empty() {
            destination.port() == 53
        } else {
            rules.iter().any(|rule| rule.matches_udp(destination))
        }
}

pub(crate) async fn handle_inbound_datagram(
    socket: watfaq_netstack::UdpSocket,
    dispatcher: Arc<Dispatcher>,
    resolver: ThreadSafeDNSResolver,
    so_mark: Option<u32>,
    dns_hijack: bool,
    dns_hijack_rules: Vec<DnsHijackRule>,
) {
    // tun i/o
    // lr: app packets went into tun will be accessed from lr
    // ls: packet written into ls will go back to app from tun
    let (lr, mut ls) = socket.split();
    let ls_dns = ls.clone(); // for dns hijack
    let resolver_dns = resolver.clone(); // for dns hijack

    // dispatcher <-> tun communications
    // l_tx: dispatcher write packet responded from remote proxy
    // l_rx: in fut1 items are forwarded to ls
    let (l_tx, mut l_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);

    // forward packets from tun to dispatcher
    let (d_tx, d_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);

    // for dispatcher - the dispatcher would receive packets from this channel,
    // which is from the stack and send back packets to this channel, which
    // is to the tun
    let udp_stream = TunDatagram::new(l_tx, d_rx);

    let sess = Session {
        network: Network::Udp,
        typ: Type::Tun,
        // Resolve the current default at outbound dial time. In particular,
        // never retain its read guard for the lifetime of this TUN stream.
        iface: None,
        so_mark,
        ..Default::default()
    };

    let closer = dispatcher
        .dispatch_datagram(sess, Box::new(udp_stream))
        .await;

    // dispatcher -> tun
    let fut1 = tokio::spawn(async move {
        while let Some(pkt) = l_rx.recv().await {
            trace!("tun <- dispatcher: {:?}", pkt);
            if let Err(e) = ls
                .send(
                    (
                        pkt.data,
                        pkt.src_addr.must_into_socket_addr(),
                        pkt.dst_addr.must_into_socket_addr(),
                    )
                        .into(),
                )
                .await
            {
                warn!("failed to send udp packet to netstack: {}", e);
            }
        }
    });

    let dns_reply_sender: DnsHijackReplySender = {
        let ls_dns = ls_dns.clone();
        Arc::new(move |data, source, destination| {
            let mut ls_dns = ls_dns.clone();
            Box::pin(async move {
                if let Err(error) =
                    ls_dns.send((data, source, destination).into()).await
                {
                    warn!("failed to send hijacked DNS reply to netstack: {error}");
                }
            })
        })
    };

    // tun -> dispatcher
    let fut2 = tokio::spawn(async move {
        let incoming = futures::stream::unfold(lr, |mut reader| async move {
            reader.recv().await.map(|packet| (packet, reader))
        });
        process_inbound_udp_packets(
            incoming,
            d_tx,
            resolver_dns,
            dns_reply_sender,
            dns_hijack,
            dns_hijack_rules,
        )
        .await;
        closer.send(0).ok();
    });

    debug!("tun UDP ready");

    let _ = futures::future::join(fut1, fut2).await;
}

async fn process_inbound_udp_packets<S>(
    incoming: S,
    d_tx: tokio::sync::mpsc::Sender<UdpPacket>,
    resolver_dns: ThreadSafeDNSResolver,
    dns_reply_sender: DnsHijackReplySender,
    dns_hijack: bool,
    dns_hijack_rules: Vec<DnsHijackRule>,
) where
    S: Stream<Item = watfaq_netstack::UdpPacket>,
{
    tokio::pin!(incoming);
    let mut active_dns_queries = FuturesUnordered::<DnsHijackQuery>::new();
    let mut pending_dns_queries = VecDeque::<DnsHijackQuery>::new();

    loop {
        while active_dns_queries.len() < MAX_CONCURRENT_TUN_DNS_QUERIES {
            let Some(query) = pending_dns_queries.pop_front() else {
                break;
            };
            active_dns_queries.push(query);
        }

        tokio::select! {
            completed = active_dns_queries.next(), if !active_dns_queries.is_empty() => {
                if let Some(Some((reply, source, destination))) = completed {
                    (dns_reply_sender)(reply, source, destination).await;
                }
            }
            incoming_packet = incoming.next() => {
                let Some(watfaq_netstack::UdpPacket {
                    data,
                    local_addr,
                    remote_addr,
                }) = incoming_packet else {
                    break;
                };

                if is_noise_datagram(
                    local_addr.ip(),
                    remote_addr.ip(),
                    remote_addr.port(),
                ) {
                    trace!(
                        source = %local_addr,
                        destination = %remote_addr,
                        "dropping tun UDP system noise"
                    );
                    continue;
                }
                let pkt = UdpPacket {
                    data: data.data().into(),
                    src_addr: local_addr.into(),
                    dst_addr: remote_addr.into(),
                    inbound_user: None,
                };

                trace!("tun -> dispatcher: {:?}", pkt);

                if should_hijack_udp_dns(
                    dns_hijack,
                    &dns_hijack_rules,
                    remote_addr,
                ) {
                    trace!(
                        "got dns packet: {:?}, returning from Clash DNS server",
                        pkt
                    );

                    if pending_dns_queries.len()
                        >= MAX_QUEUED_TUN_DNS_QUERIES
                    {
                        warn!(
                            "TUN DNS queue is full; returning SERVFAIL for the query"
                        );
                        if let Some(reply) = dns_queue_full_response(&pkt.data) {
                            (dns_reply_sender)(
                                reply,
                                pkt.dst_addr.must_into_socket_addr(),
                                pkt.src_addr.must_into_socket_addr(),
                            )
                            .await;
                        }
                        continue;
                    }

                    let resolver = resolver_dns.clone();
                    let source = pkt.src_addr.must_into_socket_addr();
                    let destination = pkt.dst_addr.must_into_socket_addr();
                    let payload = pkt.data;
                    pending_dns_queries.push_back(
                        async move {
                            let reply =
                                exchange_hijacked_udp_dns(&resolver, &payload)
                                    .await?;
                            Some((reply, destination, source))
                        }
                        .boxed(),
                    );
                    // DNS resolution proceeds independently while this loop
                    // continues receiving ordinary UDP packets.
                    continue;
                }

                if let Err(error) = d_tx.send(pkt).await {
                    warn!("failed to send udp packet to proxy: {}", error);
                }
            }
        }
    }
}

fn dns_queue_full_response(payload: &[u8]) -> Option<Vec<u8>> {
    let request = hickory_proto::op::Message::from_vec(payload).ok()?;
    let mut response =
        dns_error_response(&request, hickory_proto::op::ResponseCode::ServFail);
    response.metadata.id = request.metadata.id;
    response.to_vec().ok()
}

fn is_noise_datagram(src: IpAddr, dst: IpAddr, dst_port: u16) -> bool {
    if dst.is_multicast() || dst.is_unspecified() || src.is_unspecified() {
        return true;
    }

    if matches!(dst, IpAddr::V4(ip) if ip.is_broadcast()) {
        return true;
    }

    matches!(dst_port, 67 | 68 | 137 | 138 | 1900 | 3702 | 5353 | 5355)
}

pub struct TunDatagram {
    rx: tokio::sync::mpsc::Receiver<UdpPacket>,
    tx: tokio::sync::mpsc::Sender<UdpPacket>,

    pkt: Option<UdpPacket>,
    pending_permit: std::sync::Mutex<Option<PendingPermitFuture>>,
    flushed: bool,
}

impl TunDatagram {
    pub fn new(
        // send to tun
        tx: tokio::sync::mpsc::Sender<UdpPacket>,
        // receive from tun
        rx: tokio::sync::mpsc::Receiver<UdpPacket>,
    ) -> Self {
        Self {
            rx,
            tx,
            pkt: None,
            pending_permit: std::sync::Mutex::new(None),
            flushed: true,
        }
    }
}

impl fmt::Debug for TunDatagram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunDatagram")
            .field("flushed", &self.flushed)
            .finish_non_exhaustive()
    }
}

impl Stream for TunDatagram {
    type Item = UdpPacket;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

impl Sink<UdpPacket> for TunDatagram {
    type Error = std::io::Error;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(
        self: std::pin::Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        let pin = self.get_mut();
        pin.pkt = Some(item);
        pin.flushed = false;
        Ok(())
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        if self.pkt.is_none() {
            return Poll::Ready(Err(new_io_error(
                "no packet to send, call start_send first",
            )));
        }

        let flush_state = {
            let mut pending_permit = self
                .pending_permit
                .lock()
                .expect("pending_permit mutex poisoned");

            if pending_permit.is_none() {
                // Reserve capacity asynchronously and keep the same future
                // across polls so the packet is sent exactly once when capacity
                // becomes available.
                *pending_permit = Some(Box::pin(self.tx.clone().reserve_owned()));
            }

            match pending_permit
                .as_mut()
                .expect("pending_permit must exist")
                .as_mut()
                .poll(cx)
            {
                Poll::Pending => FlushState::Pending,
                Poll::Ready(Ok(permit)) => {
                    *pending_permit = None;
                    FlushState::Ready(permit)
                }
                Poll::Ready(Err(_)) => {
                    *pending_permit = None;
                    FlushState::Disconnected
                }
            }
        };

        match flush_state {
            FlushState::Pending => Poll::Pending,
            FlushState::Ready(permit) => {
                let pkt = self.pkt.take().ok_or(new_io_error(
                    "no packet to send, call start_send first",
                ))?;
                let _ = permit.send(pkt);
                self.flushed = true;
                Poll::Ready(Ok(()))
            }
            FlushState::Disconnected => {
                self.pkt = None;
                self.flushed = true;
                Poll::Ready(Err(new_io_error(
                    "could not send packet, local UDP sink disconnected",
                )))
            }
        }
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DnsHijackReplySender, MAX_CONCURRENT_TUN_DNS_QUERIES,
        MAX_QUEUED_TUN_DNS_QUERIES, TunDatagram, exchange_hijacked_udp_dns,
        is_noise_datagram, process_inbound_udp_packets, should_hijack_udp_dns,
    };
    use crate::{
        app::dns::{
            ClashResolver, MockClashResolver, ResolverKind, ThreadSafeDNSResolver,
        },
        config::internal::config::{
            DnsHijackAddress, DnsHijackProtocol, DnsHijackRule,
        },
        proxy::datagram::UdpPacket,
        session::SocksAddr,
    };
    use futures::{Sink, task::noop_waker_ref};
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query, ResponseCode},
        rr::{Name, RecordType},
    };
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
        time::Duration,
    };
    use tokio::sync::{Semaphore, mpsc};
    use watfaq_netstack::{Packet as NetPacket, UdpSocket as NetUdpSocket};

    struct GatedDnsResolver {
        entered: mpsc::UnboundedSender<()>,
        permits: Arc<Semaphore>,
    }

    #[async_trait::async_trait]
    impl ClashResolver for GatedDnsResolver {
        async fn resolve(
            &self,
            _host: &str,
            _enhanced: bool,
        ) -> anyhow::Result<Option<IpAddr>> {
            Ok(None)
        }

        async fn resolve_v4(
            &self,
            _host: &str,
            _enhanced: bool,
        ) -> anyhow::Result<Option<Ipv4Addr>> {
            Ok(None)
        }

        async fn resolve_v6(
            &self,
            _host: &str,
            _enhanced: bool,
        ) -> anyhow::Result<Option<std::net::Ipv6Addr>> {
            Ok(None)
        }

        async fn cached_for(&self, _ip: IpAddr) -> Option<String> {
            None
        }

        async fn exchange(&self, message: &Message) -> anyhow::Result<Message> {
            let _ = self.entered.send(());
            self.permits
                .acquire()
                .await
                .map_err(|_| anyhow::anyhow!("DNS release gate was closed"))?
                .forget();

            let mut response =
                Message::response(message.metadata.id, message.metadata.op_code);
            response.add_queries(message.queries.iter().cloned());
            Ok(response)
        }

        async fn reverse_lookup(&self, _ip: IpAddr) -> Option<String> {
            None
        }

        async fn is_fake_ip(&self, _ip: IpAddr) -> bool {
            false
        }

        async fn fake_ip_for_host(&self, _host: &str) -> Option<IpAddr> {
            None
        }

        fn fake_ip_enabled(&self) -> bool {
            false
        }

        fn ipv6(&self) -> bool {
            false
        }

        fn set_ipv6(&self, _enable: bool) {}

        fn kind(&self) -> ResolverKind {
            ResolverKind::Clash
        }
    }

    fn net_udp_packet(
        data: Vec<u8>,
        local_addr: &str,
        remote_addr: &str,
    ) -> watfaq_netstack::UdpPacket {
        watfaq_netstack::UdpPacket {
            data: NetPacket::new(data),
            local_addr: local_addr.parse().unwrap(),
            remote_addr: remote_addr.parse().unwrap(),
        }
    }

    fn dns_query(name: &str, typ: RecordType, id: u16) -> Message {
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(Name::from_ascii(name).unwrap(), typ));
        query.metadata.recursion_desired = true;
        query
    }

    async fn recv_wire(receiver: &mut mpsc::Receiver<NetPacket>) -> NetPacket {
        tokio::time::timeout(Duration::from_secs(2), receiver.recv())
            .await
            .expect("timed out waiting for IPv4/UDP packet")
            .expect("IPv4/UDP channel closed before response")
    }

    /// Actual IPv4/UDP packet round-trip through netstack SplitWrite and
    /// SplitRead. Only the kernel TUN device and Dispatcher are bypassed:
    /// DNS bytes go through the same handler as production TUN hijack.
    async fn udp_dns_packet_roundtrip(
        resolver: ThreadSafeDNSResolver,
        request: &Message,
    ) -> Message {
        let src: SocketAddr = "192.0.2.10:43000".parse().unwrap();
        let dst: SocketAddr = "192.0.2.53:53".parse().unwrap();
        assert!(should_hijack_udp_dns(true, &[], dst));

        let (_unused_tx, unused_rx) = mpsc::channel::<NetPacket>(2);
        let (raw_request_tx, mut raw_request_rx) = mpsc::channel::<NetPacket>(2);
        let (_, mut request_writer) =
            NetUdpSocket::new(unused_rx, raw_request_tx).split();
        request_writer
            .send((request.to_vec().unwrap(), src, dst).into())
            .await
            .unwrap();

        let (ingress_tx, ingress_rx) = mpsc::channel::<NetPacket>(2);
        let (egress_tx, mut egress_rx) = mpsc::channel::<NetPacket>(2);
        let (mut ingress_reader, mut egress_writer) =
            NetUdpSocket::new(ingress_rx, egress_tx).split();
        ingress_tx
            .send(recv_wire(&mut raw_request_rx).await)
            .await
            .unwrap();
        let received =
            tokio::time::timeout(Duration::from_secs(2), ingress_reader.recv())
                .await
                .expect("netstack failed to parse request IPv4/UDP packet")
                .expect("request reader closed");
        assert_eq!(received.local_addr, src);
        assert_eq!(received.remote_addr, dst);

        let payload = exchange_hijacked_udp_dns(&resolver, received.data())
            .await
            .expect("valid DNS request must produce a response");
        egress_writer
            .send((payload, received.remote_addr, received.local_addr).into())
            .await
            .unwrap();

        // Parse the IPv4 reply using netstack's real checksum and UDP parser.
        let (reply_tx, reply_rx) = mpsc::channel::<NetPacket>(2);
        let (unused_reply_tx, _unused_reply_rx) = mpsc::channel::<NetPacket>(2);
        let (mut reply_reader, _) =
            NetUdpSocket::new(reply_rx, unused_reply_tx).split();
        reply_tx
            .send(recv_wire(&mut egress_rx).await)
            .await
            .unwrap();
        let reply =
            tokio::time::timeout(Duration::from_secs(2), reply_reader.recv())
                .await
                .expect("netstack failed to parse response IPv4/UDP packet")
                .expect("response reader closed");
        assert_eq!(reply.local_addr, dst);
        assert_eq!(reply.remote_addr, src);
        Message::from_vec(reply.data()).unwrap()
    }

    #[tokio::test]
    async fn ipv4_tun_udp_fake_a_is_synthetic_and_preserves_dns_id() {
        let mut mock = MockClashResolver::new();
        mock.expect_ipv6().return_const(false);
        mock.expect_fake_ip_enabled().return_const(true);
        mock.expect_fake_ip_v6_enabled().return_const(false);
        mock.expect_should_fake_ip().once().return_const(true);
        mock.expect_fake_ip_ttl().return_const(1_u32);
        mock.expect_exchange().never();
        mock.expect_resolve_v4()
            .once()
            .with(
                mockall::predicate::eq("fake.example"),
                mockall::predicate::eq(true),
            )
            .returning(|_, _| Ok(Some("198.18.0.9".parse().unwrap())));
        let request = dns_query("fake.example.", RecordType::A, 0xbee1);
        let reply = udp_dns_packet_roundtrip(Arc::new(mock), &request).await;
        assert_eq!(reply.metadata.id, 0xbee1);
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert_eq!(reply.answers.len(), 1);
        assert_eq!(reply.answers[0].data.to_string(), "198.18.0.9");
    }

    #[tokio::test]
    async fn ipv4_tun_udp_non_a_privacy_and_excluded_forwarding() {
        for (blocked, typ) in [
            (true, RecordType::HTTPS),
            (false, RecordType::TXT),
            (false, RecordType::SRV),
        ] {
            let mut mock = MockClashResolver::new();
            mock.expect_ipv6().return_const(false);
            mock.expect_safe_srv_enabled().return_const(false);
            mock.expect_should_fake_ip().once().return_const(blocked);
            if blocked {
                mock.expect_exchange().never();
            } else {
                mock.expect_fake_ip_enabled().return_const(true);
                mock.expect_fake_ip_v6_enabled().return_const(false);
                mock.expect_exchange().once().returning(|message| {
                    let mut answer = Message::response(
                        message.metadata.id,
                        message.metadata.op_code,
                    );
                    answer.add_queries(message.queries.iter().cloned());
                    Ok(answer)
                });
            }
            let request = dns_query("printer.lan.", typ, 0x1001);
            let reply = udp_dns_packet_roundtrip(Arc::new(mock), &request).await;
            assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
            assert!(reply.answers.is_empty());
        }
    }

    #[tokio::test]
    async fn ipv4_tun_udp_upstream_error_becomes_servfail_on_wire() {
        let mut mock = MockClashResolver::new();
        mock.expect_ipv6().return_const(false);
        mock.expect_fake_ip_enabled().return_const(false);
        mock.expect_fake_ip_v6_enabled().return_const(false);
        mock.expect_exchange()
            .once()
            .returning(|_| Err(anyhow::anyhow!("upstream connection refused")));
        let request = dns_query("down.example.", RecordType::A, 0x1234);
        let reply = udp_dns_packet_roundtrip(Arc::new(mock), &request).await;
        assert_eq!(reply.metadata.id, 0x1234);
        assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(reply.queries.len(), 1);
    }

    #[tokio::test]
    async fn slow_hijacked_dns_does_not_block_forwarding_other_udp_packets() {
        let (entered_tx, mut entered_rx) = mpsc::unbounded_channel();
        let permits = Arc::new(Semaphore::new(0));
        let resolver: ThreadSafeDNSResolver = Arc::new(GatedDnsResolver {
            entered: entered_tx,
            permits: permits.clone(),
        });
        let (packet_tx, packet_rx) = mpsc::channel(4);
        let (dispatcher_tx, mut dispatcher_rx) = mpsc::channel(4);
        let (dns_reply_tx, mut dns_reply_rx) = mpsc::channel(4);
        let dns_reply_sender: DnsHijackReplySender =
            Arc::new(move |data, source, destination| {
                let dns_reply_tx = dns_reply_tx.clone();
                Box::pin(async move {
                    let _ = dns_reply_tx.send((data, source, destination)).await;
                })
            });
        let incoming =
            futures::stream::unfold(packet_rx, |mut receiver| async move {
                receiver.recv().await.map(|packet| (packet, receiver))
            });
        let task = tokio::spawn(process_inbound_udp_packets(
            incoming,
            dispatcher_tx,
            resolver,
            dns_reply_sender,
            true,
            vec![],
        ));

        let dns_request = dns_query("slow.example.", RecordType::A, 0x4d21);
        packet_tx
            .send(net_udp_packet(
                dns_request.to_vec().unwrap(),
                "192.0.2.10:43000",
                "192.0.2.53:53",
            ))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), entered_rx.recv())
            .await
            .expect("DNS resolver did not receive the hijacked query")
            .expect("DNS resolver entry channel closed");

        let ordinary_udp = net_udp_packet(
            b"voice packet".to_vec(),
            "192.0.2.10:43001",
            "198.51.100.8:9000",
        );
        packet_tx.send(ordinary_udp).await.unwrap();
        let forwarded =
            tokio::time::timeout(Duration::from_secs(1), dispatcher_rx.recv()).await;

        permits.add_permits(1);
        let (reply_bytes, reply_source, reply_destination) =
            tokio::time::timeout(Duration::from_secs(2), dns_reply_rx.recv())
                .await
                .expect("DNS response was not returned")
                .expect("DNS reply channel closed");
        let reply = Message::from_vec(&reply_bytes).unwrap();
        drop(packet_tx);
        task.await.unwrap();

        assert_eq!(reply.metadata.id, 0x4d21);
        assert_eq!(reply_source, "192.0.2.53:53".parse().unwrap());
        assert_eq!(reply_destination, "192.0.2.10:43000".parse().unwrap());
        let forwarded = forwarded
            .expect("slow DNS blocked the TUN UDP receive loop")
            .expect("dispatcher channel closed before forwarding ordinary UDP");
        assert_eq!(forwarded.data, b"voice packet");
        assert_eq!(
            forwarded.dst_addr,
            SocksAddr::Ip("198.51.100.8:9000".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn tun_dns_queue_is_bounded_and_returns_servfail_when_full() {
        let (entered_tx, mut entered_rx) = mpsc::unbounded_channel();
        let permits = Arc::new(Semaphore::new(0));
        let resolver: ThreadSafeDNSResolver = Arc::new(GatedDnsResolver {
            entered: entered_tx,
            permits,
        });
        let request_count =
            MAX_CONCURRENT_TUN_DNS_QUERIES + MAX_QUEUED_TUN_DNS_QUERIES + 1;
        let (packet_tx, packet_rx) = mpsc::channel(request_count);
        let (dispatcher_tx, _dispatcher_rx) = mpsc::channel(1);
        let (dns_reply_tx, mut dns_reply_rx) = mpsc::channel(1);
        let dns_reply_sender: DnsHijackReplySender =
            Arc::new(move |data, source, destination| {
                let dns_reply_tx = dns_reply_tx.clone();
                Box::pin(async move {
                    let _ = dns_reply_tx.send((data, source, destination)).await;
                })
            });
        let incoming =
            futures::stream::unfold(packet_rx, |mut receiver| async move {
                receiver.recv().await.map(|packet| (packet, receiver))
            });
        let task = tokio::spawn(process_inbound_udp_packets(
            incoming,
            dispatcher_tx,
            resolver,
            dns_reply_sender,
            true,
            vec![],
        ));

        for index in 0..request_count {
            let id = if index + 1 == request_count {
                0x7fff
            } else {
                index as u16
            };
            let request = dns_query("queued.example.", RecordType::A, id);
            packet_tx
                .send(net_udp_packet(
                    request.to_vec().unwrap(),
                    &format!("192.0.2.10:{}", 43000 + index),
                    "192.0.2.53:53",
                ))
                .await
                .unwrap();
        }

        let (reply_bytes, _, _) =
            tokio::time::timeout(Duration::from_secs(2), dns_reply_rx.recv())
                .await
                .expect("full TUN DNS queue did not respond")
                .expect("DNS reply channel closed");
        let reply = Message::from_vec(&reply_bytes).unwrap();
        assert_eq!(reply.metadata.id, 0x7fff);
        assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);

        for _ in 0..MAX_CONCURRENT_TUN_DNS_QUERIES {
            tokio::time::timeout(Duration::from_secs(2), entered_rx.recv())
                .await
                .expect("DNS worker did not start within the concurrency limit")
                .expect("DNS worker entry channel closed");
        }
        drop(packet_tx);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("TUN shutdown waited for pending DNS queries")
            .unwrap();
    }

    #[tokio::test]
    async fn ipv4_tun_udp_multi_question_returns_formerr_without_upstream() {
        let mock = MockClashResolver::new();
        let mut request = dns_query("one.example.", RecordType::A, 0x55ab);
        request.add_query(Query::query(
            Name::from_ascii("two.example.").unwrap(),
            RecordType::HTTPS,
        ));
        let reply = udp_dns_packet_roundtrip(Arc::new(mock), &request).await;
        assert_eq!(reply.metadata.id, 0x55ab);
        assert_eq!(reply.metadata.response_code, ResponseCode::FormErr);
        assert!(reply.queries.is_empty());
    }

    #[tokio::test]
    async fn malformed_hijacked_udp_dns_is_dropped_without_upstream() {
        let resolver: ThreadSafeDNSResolver = Arc::new(MockClashResolver::new());
        assert!(
            exchange_hijacked_udp_dns(&resolver, &[0x12, 0x34, 0x00])
                .await
                .is_none()
        );
    }

    fn sample_packet(port: u16) -> UdpPacket {
        UdpPacket::new(
            vec![1, 2, 3],
            SocksAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)),
            SocksAddr::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                53,
            )),
        )
    }

    #[test]
    fn udp_dns_hijack_uses_rules_and_preserves_empty_list_compatibility() {
        let destination = "1.1.1.1:53".parse().unwrap();
        let tcp_rule = DnsHijackRule {
            protocol: DnsHijackProtocol::Tcp,
            address: DnsHijackAddress::Any,
            port: 53,
        };
        let udp_rule = DnsHijackRule {
            protocol: DnsHijackProtocol::Udp,
            address: DnsHijackAddress::Ip("1.1.1.1".parse().unwrap()),
            port: 53,
        };

        assert!(!should_hijack_udp_dns(false, &[], destination));
        assert!(should_hijack_udp_dns(true, &[], destination));
        assert!(!should_hijack_udp_dns(true, &[tcp_rule], destination));
        assert!(should_hijack_udp_dns(true, &[udp_rule], destination));
        assert!(!should_hijack_udp_dns(
            true,
            &[udp_rule],
            "8.8.8.8:53".parse().unwrap()
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tun_datagram_flush_waits_for_capacity_instead_of_failing() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let (_dummy_tx, dummy_rx) = tokio::sync::mpsc::channel(1);
        tx.send(sample_packet(10000))
            .await
            .expect("failed to fill channel");

        let mut datagram = TunDatagram::new(tx, dummy_rx);
        let waker = noop_waker_ref();
        let mut cx = Context::from_waker(waker);

        assert!(matches!(
            Pin::new(&mut datagram).poll_ready(&mut cx),
            Poll::Ready(Ok(()))
        ));
        Pin::new(&mut datagram)
            .start_send(sample_packet(10001))
            .expect("start_send should succeed");

        assert!(matches!(
            Pin::new(&mut datagram).poll_flush(&mut cx),
            Poll::Pending
        ));

        let drained = rx.recv().await.expect("expected queued packet");
        assert_eq!(
            drained.src_addr,
            SocksAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 10000,))
        );

        assert!(matches!(
            Pin::new(&mut datagram).poll_flush(&mut cx),
            Poll::Ready(Ok(()))
        ));

        let forwarded = rx.recv().await.expect("expected forwarded packet");
        assert_eq!(
            forwarded.src_addr,
            SocksAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 10001,))
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tun_datagram_flush_reports_disconnected_sink() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        drop(rx);
        let (_dummy_tx, dummy_rx) = tokio::sync::mpsc::channel(1);

        let mut datagram = TunDatagram::new(tx, dummy_rx);
        let waker = noop_waker_ref();
        let mut cx = Context::from_waker(waker);

        assert!(matches!(
            Pin::new(&mut datagram).poll_ready(&mut cx),
            Poll::Ready(Ok(()))
        ));
        Pin::new(&mut datagram)
            .start_send(sample_packet(10002))
            .expect("start_send should succeed");

        let err = match Pin::new(&mut datagram).poll_flush(&mut cx) {
            Poll::Ready(Err(err)) => err,
            other => panic!("expected disconnected error, got {other:?}"),
        };
        assert!(
            err.to_string().contains("local UDP sink disconnected"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tun_datagram_poll_ready_waits_for_pending_flush_capacity() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let (_dummy_tx, dummy_rx) = tokio::sync::mpsc::channel(1);
        tx.send(sample_packet(10010))
            .await
            .expect("failed to fill channel");

        let mut datagram = TunDatagram::new(tx, dummy_rx);
        let waker = noop_waker_ref();
        let mut cx = Context::from_waker(waker);

        Pin::new(&mut datagram)
            .start_send(sample_packet(10011))
            .expect("start_send should succeed");

        assert!(matches!(
            Pin::new(&mut datagram).poll_ready(&mut cx),
            Poll::Pending
        ));

        let _ = rx.recv().await.expect("expected queued packet");

        assert!(matches!(
            Pin::new(&mut datagram).poll_ready(&mut cx),
            Poll::Ready(Ok(()))
        ));
        let forwarded = rx.recv().await.expect("expected forwarded packet");
        assert_eq!(
            forwarded.src_addr,
            SocksAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 10011,))
        );
    }

    #[test]
    fn drops_windows_udp_discovery_noise() {
        let src = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1));

        assert!(is_noise_datagram(
            src,
            IpAddr::V4(Ipv4Addr::new(198, 18, 0, 255)),
            137
        ));
        assert!(is_noise_datagram(
            src,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            137
        ));
        assert!(!is_noise_datagram(
            src,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            443
        ));
    }
}
