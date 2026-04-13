use crate::{
    app::{
        dispatcher::Dispatcher,
        dns::{ThreadSafeDNSResolver, exchange_with_resolver},
        net::DEFAULT_OUTBOUND_INTERFACE,
    },
    common::errors::new_io_error,
    proxy::datagram::UdpPacket,
    session::{Network, Session, Type},
};
use futures::{Sink, Stream, future::BoxFuture, ready};
use std::{fmt, sync::Arc, task::Poll};
use tracing::{debug, trace, warn};

type PendingPermitFuture = BoxFuture<
    'static,
    Result<
        tokio::sync::mpsc::OwnedPermit<UdpPacket>,
        tokio::sync::mpsc::error::SendError<()>,
    >,
>;

enum FlushState {
    Pending,
    Ready(tokio::sync::mpsc::OwnedPermit<UdpPacket>),
    Disconnected,
}

pub(crate) async fn handle_inbound_datagram(
    socket: watfaq_netstack::UdpSocket,
    dispatcher: Arc<Dispatcher>,
    resolver: ThreadSafeDNSResolver,
    so_mark: Option<u32>,
    dns_hijack: bool,
) {
    // tun i/o
    // lr: app packets went into tun will be accessed from lr
    // ls: packet written into ls will go back to app from tun
    let (mut lr, mut ls) = socket.split();
    let mut ls_dns = ls.clone(); // for dns hijack
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

    let default_outbound = DEFAULT_OUTBOUND_INTERFACE.read().await;
    let sess = Session {
        network: Network::Udp,
        typ: Type::Tun,
        iface: default_outbound.clone().inspect(|x| {
            debug!("selecting outbound interface: {:?} for tun UDP traffic", x);
        }),
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

    // tun -> dispatcher
    let fut2 = tokio::spawn(async move {
        'read_packet: while let Some(watfaq_netstack::UdpPacket {
            data,
            local_addr,
            remote_addr,
        }) = lr.recv().await
        {
            if remote_addr.ip().is_multicast() {
                continue;
            }
            let pkt = UdpPacket {
                data: data.data().into(),
                src_addr: local_addr.into(),
                dst_addr: remote_addr.into(),
                inbound_user: None,
            };

            trace!("tun -> dispatcher: {:?}", pkt);

            if dns_hijack && pkt.dst_addr.port() == 53 {
                trace!("got dns packet: {:?}, returning from Clash DNS server", pkt);

                match hickory_proto::op::Message::from_vec(&pkt.data) {
                    Ok(msg) => {
                        let mut send_response =
                            async |msg: hickory_proto::op::Message,
                                   pkt: &UdpPacket| {
                                match msg.to_vec() {
                                    Ok(data) => {
                                        if let Err(e) = ls_dns
                                            .send(
                                                (
                                                    data,
                                                    pkt.dst_addr
                                                        .clone()
                                                        .must_into_socket_addr(),
                                                    pkt.src_addr
                                                        .clone()
                                                        .must_into_socket_addr(),
                                                )
                                                    .into(),
                                            )
                                            .await
                                        {
                                            warn!(
                                                "failed to send udp packet to \
                                                 netstack: {}",
                                                e
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        warn!(
                                            "failed to serialize dns response: {}",
                                            e
                                        );
                                    }
                                }
                            };

                        trace!("hijack dns request: {:?}", msg);

                        let mut resp =
                            match exchange_with_resolver(&resolver_dns, &msg, true)
                                .await
                            {
                                Ok(resp) => resp,
                                Err(e) => {
                                    warn!("failed to exchange dns message: {}", e);
                                    continue 'read_packet;
                                }
                            };

                        // TODO: figure out where the message id got lost
                        resp.set_id(msg.id());
                        trace!("hijack dns response: {:?}", resp);

                        send_response(resp, &pkt).await;
                    }
                    Err(e) => {
                        warn!(
                            "failed to parse dns packet: {}, putting it back to \
                             stack",
                            e
                        );
                    }
                };

                // don't forward dns packet to dispatcher
                continue 'read_packet;
            }

            match d_tx.send(pkt).await {
                Ok(_) => {}
                Err(e) => {
                    warn!("failed to send udp packet to proxy: {}", e);
                }
            }
        }

        closer.send(0).ok();
    });

    debug!("tun UDP ready");

    let _ = futures::future::join(fut1, fut2).await;
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
    use super::TunDatagram;
    use crate::{proxy::datagram::UdpPacket, session::SocksAddr};
    use futures::{Sink, task::noop_waker_ref};
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        pin::Pin,
        task::{Context, Poll},
    };

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
}
