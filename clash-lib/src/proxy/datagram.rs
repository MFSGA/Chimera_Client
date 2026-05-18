use crate::{
    app::dns::ThreadSafeDNSResolver, common::errors::new_io_error,
    session::SocksAddr,
};
use futures::{Sink, Stream, ready};
use std::{
    collections::HashMap,
    fmt::{Debug, Display, Formatter},
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{io::ReadBuf, net::UdpSocket, task::JoinHandle};

const UDP_DOMAIN_MAP_TTL: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct UdpPacket {
    pub data: Vec<u8>,
    pub src_addr: SocksAddr,
    pub dst_addr: SocksAddr,
    /// Authenticated user name from SS2022 EIH, propagated to the dispatcher
    /// session for per-user traffic attribution. `None` for all other
    /// protocols.
    pub inbound_user: Option<String>,
}

impl Default for UdpPacket {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            src_addr: SocksAddr::any_ipv4(),
            dst_addr: SocksAddr::any_ipv4(),
            inbound_user: None,
        }
    }
}

impl Debug for UdpPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpPacket")
            .field("src_addr", &self.src_addr)
            .field("dst_addr", &self.dst_addr)
            .finish()
    }
}

impl Display for UdpPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UDP Packet from {} to {} with {} bytes",
            self.src_addr,
            self.dst_addr,
            self.data.len()
        )
    }
}

impl UdpPacket {
    pub fn new(data: Vec<u8>, src_addr: SocksAddr, dst_addr: SocksAddr) -> Self {
        Self {
            data,
            src_addr,
            dst_addr,
            inbound_user: None,
        }
    }
}

#[must_use = "sinks do nothing unless polled"]
// TODO: maybe we should use abstract datagram IO interface instead of the
// Stream + Sink trait
pub struct OutboundDatagramImpl {
    inner: UdpSocket,
    resolver: ThreadSafeDNSResolver,
    flushed: bool,
    pkt: Option<UdpPacket>,
    // Avoid allocating a full UDP packet buffer on every poll_next call.
    recv_buf: Vec<u8>,
    ip_to_logical: HashMap<SocketAddr, (SocksAddr, Instant)>,
    pending_dns: Option<JoinHandle<io::Result<SocketAddr>>>,
    resolved_dst: Option<SocketAddr>,
}

impl OutboundDatagramImpl {
    pub fn new(udp: UdpSocket, resolver: ThreadSafeDNSResolver) -> Self {
        Self {
            inner: udp,
            resolver,
            flushed: true,
            pkt: None,
            recv_buf: vec![0u8; 65535],
            ip_to_logical: HashMap::new(),
            pending_dns: None,
            resolved_dst: None,
        }
    }
}

impl Sink<UdpPacket> for OutboundDatagramImpl {
    type Error = io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let pin = self.get_mut();
        if let Some(handle) = pin.pending_dns.take() {
            handle.abort();
        }
        pin.pkt = Some(item);
        pin.flushed = false;
        pin.resolved_dst = None;
        Ok(())
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let Self {
            ref mut inner,
            ref mut pkt,
            ref resolver,
            ref mut ip_to_logical,
            ref mut pending_dns,
            ref mut resolved_dst,
            ..
        } = *self;

        let p = pkt
            .as_ref()
            .ok_or_else(|| io::Error::other("no packet to send"))?;
        let dst = match &p.dst_addr {
            SocksAddr::Ip(addr) => {
                *pending_dns = None;
                *resolved_dst = None;
                *addr
            }
            SocksAddr::Domain(domain, port) => {
                if let Some(addr) = *resolved_dst {
                    addr
                } else {
                    let is_ipv6 = inner.local_addr()?.is_ipv6();
                    let handle = pending_dns.get_or_insert_with(|| {
                        let resolver = resolver.clone();
                        let domain = domain.clone();
                        let port = *port;
                        tokio::spawn(async move {
                            let ip = if is_ipv6 {
                                resolver.resolve(&domain, false).await.map_err(
                                    |_| io::Error::other("resolve domain failed"),
                                )?
                            } else {
                                resolver
                                    .resolve_v4(&domain, false)
                                    .await
                                    .map_err(|_| {
                                        io::Error::other("resolve domain failed")
                                    })?
                                    .map(IpAddr::V4)
                            };
                            ip.map(|ip| SocketAddr::from((ip, port))).ok_or_else(
                                || {
                                    io::Error::other(format!(
                                        "resolve domain failed: {domain}"
                                    ))
                                },
                            )
                        })
                    });
                    let join_result = ready!(Pin::new(handle).poll(cx));
                    // Clear the completed task before propagating errors. If a
                    // DNS error returns early with the handle still stored, the
                    // next poll would panic by polling a completed JoinHandle.
                    *pending_dns = None;
                    let addr = match join_result {
                        Ok(result) => result?,
                        Err(err) => {
                            return Poll::Ready(Err(io::Error::other(format!(
                                "DNS task panicked: {err}"
                            ))));
                        }
                    };
                    *resolved_dst = Some(addr);
                    addr
                }
            }
        };

        let send_dst = match (inner.local_addr()?.is_ipv6(), dst) {
            (true, SocketAddr::V4(v4)) => {
                SocketAddr::V6(std::net::SocketAddrV6::new(
                    v4.ip().to_ipv6_mapped(),
                    v4.port(),
                    0,
                    0,
                ))
            }
            _ => dst,
        };

        let n = ready!(inner.poll_send_to(cx, p.data.as_slice(), send_dst))?;
        let now = Instant::now();
        ip_to_logical
            .retain(|_, (_, ts)| now.duration_since(*ts) < UDP_DOMAIN_MAP_TTL);
        ip_to_logical.insert(dst, (p.dst_addr.clone(), now));
        let data_len = p.data.len();

        *pkt = None;
        self.flushed = true;

        if n == data_len {
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Err(new_io_error(format!(
                "failed to send all data, only sent {n} bytes"
            ))))
        }
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }
}
impl Stream for OutboundDatagramImpl {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let Self {
            ref mut inner,
            ref mut recv_buf,
            ref ip_to_logical,
            ..
        } = *self;
        let mut buf = ReadBuf::new(recv_buf.as_mut_slice());
        match ready!(inner.poll_recv_from(cx, &mut buf)) {
            Ok(src) => {
                let data = buf.filled().to_vec();
                let src = match src {
                    SocketAddr::V6(v6) => {
                        if let Some(v4) = v6.ip().to_ipv4_mapped() {
                            SocketAddr::from((v4, v6.port()))
                        } else {
                            src
                        }
                    }
                    _ => src,
                };
                let src_addr = ip_to_logical
                    .get(&src)
                    .map(|(logical, _)| logical.clone())
                    .unwrap_or_else(|| src.into());
                Poll::Ready(Some(UdpPacket {
                    data,
                    src_addr,
                    dst_addr: SocksAddr::any_ipv4(),
                    inbound_user: None,
                }))
            }
            Err(_) => Poll::Ready(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::dns::MockClashResolver;
    use futures::{SinkExt, StreamExt};
    use std::{collections::HashSet, net::Ipv4Addr, sync::Arc, time::Duration};
    use tokio::net::UdpSocket;

    async fn spawn_echo_server() -> u16 {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    break;
                };
                let _ = sock.send_to(&buf[..n], peer).await;
            }
        });
        port
    }

    async fn make_datagram() -> OutboundDatagramImpl {
        let mut resolver = MockClashResolver::new();
        resolver
            .expect_resolve_v4()
            .returning(|_, _| Ok(Some(Ipv4Addr::LOCALHOST)));
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        OutboundDatagramImpl::new(udp, Arc::new(resolver))
    }

    #[tokio::test]
    async fn single_dest_domain_src_addr_restored() {
        let echo_port = spawn_echo_server().await;
        let mut datagram = make_datagram().await;

        let dst = SocksAddr::Domain("echo.test".to_owned(), echo_port);
        datagram
            .send(UdpPacket {
                data: b"hello".to_vec(),
                dst_addr: dst.clone(),
                ..Default::default()
            })
            .await
            .unwrap();

        let pkt = tokio::time::timeout(Duration::from_secs(2), datagram.next())
            .await
            .expect("timed out")
            .expect("stream ended");

        assert_eq!(pkt.src_addr, dst);
        assert_eq!(pkt.data, b"hello");
    }

    #[tokio::test]
    async fn multi_dest_1_to_n_src_addr_restored() {
        let port_a = spawn_echo_server().await;
        let port_b = spawn_echo_server().await;
        let mut datagram = make_datagram().await;

        let dst_a = SocksAddr::Domain("echo1.test".to_owned(), port_a);
        let dst_b = SocksAddr::Domain("echo2.test".to_owned(), port_b);

        datagram
            .send(UdpPacket {
                data: b"to-a".to_vec(),
                dst_addr: dst_a.clone(),
                ..Default::default()
            })
            .await
            .unwrap();
        datagram
            .send(UdpPacket {
                data: b"to-b".to_vec(),
                dst_addr: dst_b.clone(),
                ..Default::default()
            })
            .await
            .unwrap();

        let timeout = Duration::from_secs(2);
        let pkt1 = tokio::time::timeout(timeout, datagram.next())
            .await
            .expect("timed out waiting for first response")
            .expect("stream ended");
        let pkt2 = tokio::time::timeout(timeout, datagram.next())
            .await
            .expect("timed out waiting for second response")
            .expect("stream ended");

        let got: HashSet<SocksAddr> =
            [pkt1.src_addr, pkt2.src_addr].into_iter().collect();
        assert!(got.contains(&dst_a), "missing echo1.test src_addr");
        assert!(got.contains(&dst_b), "missing echo2.test src_addr");
    }

    #[tokio::test]
    async fn dns_failure_does_not_panic_on_retry() {
        let mut resolver = MockClashResolver::new();
        let mut call_count = 0u8;
        resolver.expect_resolve_v4().returning(move |_, _| {
            call_count += 1;
            if call_count == 1 {
                Err(anyhow::anyhow!("simulated DNS failure"))
            } else {
                Ok(Some(Ipv4Addr::LOCALHOST))
            }
        });
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut datagram = OutboundDatagramImpl::new(udp, Arc::new(resolver));

        let echo_port = spawn_echo_server().await;
        let dst = SocksAddr::Domain("fail.test".to_owned(), echo_port);

        let result = datagram
            .send(UdpPacket {
                data: b"hello".to_vec(),
                dst_addr: dst.clone(),
                ..Default::default()
            })
            .await;
        assert!(result.is_err(), "expected error on DNS failure");

        datagram
            .send(UdpPacket {
                data: b"hello again".to_vec(),
                dst_addr: dst,
                ..Default::default()
            })
            .await
            .expect("second send must succeed after DNS recovers");
    }
}
