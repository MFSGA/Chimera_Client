use std::{
    fmt,
    future::Future,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use futures::{SinkExt, StreamExt};
use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use tokio::sync::mpsc;

use crate::{
    proxy::{AnyOutboundDatagram, datagram::UdpPacket},
    session::SocksAddr,
};

const CHANNEL_CAPACITY: usize = 256;

pub(super) struct ConnectorUdpSocket {
    send_tx: mpsc::Sender<UdpPacket>,
    recv_rx: Mutex<mpsc::Receiver<UdpPacket>>,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
}

impl fmt::Debug for ConnectorUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectorUdpSocket")
            .field("peer_addr", &self.peer_addr)
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl ConnectorUdpSocket {
    pub(super) fn new(
        datagram: AnyOutboundDatagram,
        peer_addr: SocketAddr,
    ) -> Arc<Self> {
        let local_addr = match peer_addr {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        let (send_tx, mut send_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (recv_tx, recv_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (mut sink, mut stream) = datagram.split();

        tokio::spawn(async move {
            while let Some(packet) = send_rx.recv().await {
                if sink.send(packet).await.is_err() {
                    break;
                }
            }
            let _ = sink.close().await;
        });

        tokio::spawn(async move {
            while let Some(packet) = stream.next().await {
                if recv_tx.send(packet).await.is_err() {
                    break;
                }
            }
        });

        Arc::new(Self {
            send_tx,
            recv_rx: Mutex::new(recv_rx),
            peer_addr,
            local_addr,
        })
    }
}

impl AsyncUdpSocket for ConnectorUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(ChannelUdpPoller {
            sender: self.send_tx.clone(),
            waiter: Mutex::new(None),
        })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if transmit.segment_size.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "connector UDP socket does not support segmented transmits",
            ));
        }

        self.send_tx
            .try_send(UdpPacket::new(
                transmit.contents.to_vec(),
                self.local_addr.into(),
                transmit.destination.into(),
            ))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    io::Error::from(io::ErrorKind::WouldBlock)
                }
                mpsc::error::TrySendError::Closed(_) => io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "connector UDP send pump has stopped",
                ),
            })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let Some(buf) = bufs.first_mut() else {
            return Poll::Ready(Ok(0));
        };
        let Some(meta) = meta.first_mut() else {
            return Poll::Ready(Ok(0));
        };

        let mut recv_rx = self
            .recv_rx
            .lock()
            .map_err(|_| io::Error::other("connector UDP receive lock poisoned"))?;
        match recv_rx.poll_recv(cx) {
            Poll::Ready(Some(packet)) => {
                if packet.data.len() > buf.len() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "connector UDP packet too large for QUIC receive buffer: {} > {}",
                            packet.data.len(),
                            buf.len()
                        ),
                    )));
                }

                buf[..packet.data.len()].copy_from_slice(&packet.data);
                let addr = match packet.src_addr {
                    SocksAddr::Ip(addr) => addr,
                    SocksAddr::Domain(_, _) => self.peer_addr,
                };
                *meta = RecvMeta {
                    addr,
                    len: packet.data.len(),
                    stride: packet.data.len(),
                    ecn: None,
                    dst_ip: None,
                };
                Poll::Ready(Ok(1))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "connector UDP receive pump has stopped",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

type ReserveFuture = Pin<
    Box<
        dyn Future<
                Output = Result<
                    mpsc::OwnedPermit<UdpPacket>,
                    mpsc::error::SendError<()>,
                >,
            > + Send,
    >,
>;

struct ChannelUdpPoller {
    sender: mpsc::Sender<UdpPacket>,
    waiter: Mutex<Option<ReserveFuture>>,
}

impl fmt::Debug for ChannelUdpPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelUdpPoller").finish_non_exhaustive()
    }
}

impl UdpPoller for ChannelUdpPoller {
    fn poll_writable(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let mut waiter = self
            .waiter
            .lock()
            .map_err(|_| io::Error::other("connector UDP poller lock poisoned"))?;
        if waiter.is_none() {
            *waiter = Some(Box::pin(self.sender.clone().reserve_owned()));
        }

        let future = waiter.as_mut().expect("channel reserve waiter must exist");
        match future.as_mut().poll(cx) {
            Poll::Ready(Ok(permit)) => {
                drop(permit);
                *waiter = None;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_)) => {
                *waiter = None;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "connector UDP send pump has stopped",
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{io::IoSliceMut, sync::Arc, task::Poll, time::Duration};

    use quinn::AsyncUdpSocket;
    use tokio::net::UdpSocket;

    use super::*;
    use crate::{
        app::dns::MockClashResolver,
        proxy::utils::{DirectConnector, RemoteConnector},
    };

    #[tokio::test]
    async fn connector_udp_socket_round_trips_datagram() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            if let Ok((len, peer)) = echo.recv_from(&mut buf).await {
                let _ = echo.send_to(&buf[..len], peer).await;
            }
        });

        let resolver = Arc::new(MockClashResolver::new());
        let datagram = DirectConnector::new()
            .connect_datagram(
                resolver,
                None,
                peer_addr.into(),
                None,
                #[cfg(target_os = "linux")]
                None,
            )
            .await
            .unwrap();
        let socket = ConnectorUdpSocket::new(datagram, peer_addr);

        socket
            .try_send(&Transmit {
                destination: peer_addr,
                ecn: None,
                contents: b"hello-h3-adapter",
                segment_size: None,
                src_ip: None,
            })
            .unwrap();

        let mut bytes = [0u8; 64];
        let mut recv_meta = [RecvMeta::default(); 1];
        let received = tokio::time::timeout(
            Duration::from_secs(2),
            std::future::poll_fn(|cx| {
                let mut bufs = [IoSliceMut::new(&mut bytes)];
                match socket.poll_recv(cx, &mut bufs, &mut recv_meta) {
                    Poll::Ready(result) => Poll::Ready(result),
                    Poll::Pending => Poll::Pending,
                }
            }),
        )
        .await
        .expect("adapter receive timed out")
        .expect("adapter receive failed");

        assert_eq!(received, 1);
        assert_eq!(&bytes[..recv_meta[0].len], b"hello-h3-adapter");
        assert_eq!(recv_meta[0].addr, peer_addr);
    }
}
