use futures::{Sink, Stream};

use crate::proxy::datagram::UdpPacket;

pub const MAX_PACKET: usize = 65536;

pub struct UdpPair {
    send: tokio::sync::mpsc::Sender<UdpPacket>,
    recv: tokio::sync::mpsc::Receiver<UdpPacket>,
    pkt: Option<UdpPacket>,
    flushed: bool,
}

impl UdpPair {
    pub fn new(
        recv: tokio::sync::mpsc::Receiver<UdpPacket>,
        send: tokio::sync::mpsc::Sender<UdpPacket>,
    ) -> Self {
        Self {
            send,
            recv,
            pkt: None,
            flushed: true,
        }
    }
}

impl Stream for UdpPair {
    type Item = UdpPacket;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.get_mut().recv.poll_recv(cx)
    }
}

impl Sink<UdpPacket> for UdpPair {
    type Error = std::io::Error;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        if !self.flushed {
            self.poll_flush(cx)
        } else {
            std::task::Poll::Ready(Ok(()))
        }
    }

    fn start_send(
        self: std::pin::Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        let this = self.get_mut();
        this.pkt = Some(item);
        this.flushed = false;
        Ok(())
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        if !self.flushed {
            let this = self.get_mut();
            if let Some(pkt) = this.pkt.take() {
                match this.send.try_send(pkt) {
                    Ok(_) => {
                        this.flushed = true;
                        return std::task::Poll::Ready(Ok(()));
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(pkt)) => {
                        this.pkt = Some(pkt);
                        return std::task::Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            "closed",
                        )));
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Full(pkt)) => {
                        this.pkt = Some(pkt);
                        return std::task::Poll::Pending;
                    }
                }
            }
        }
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.poll_flush(cx)
    }
}

#[cfg(test)]
mod tests {
    use futures::{SinkExt, StreamExt};

    use super::UdpPair;
    use crate::{proxy::datagram::UdpPacket, session::SocksAddr};

    #[tokio::test]
    async fn wireguard_udp_pair_forwards_sink_and_stream_packets() {
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(4);
        let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel(4);
        let mut pair = UdpPair::new(inbound_rx, outbound_tx);

        let outgoing = UdpPacket::new(
            b"out".to_vec(),
            SocksAddr::any_ipv4(),
            SocksAddr::any_ipv4(),
        );
        pair.send(outgoing).await.unwrap();
        assert_eq!(outbound_rx.recv().await.unwrap().data, b"out");

        let incoming = UdpPacket::new(
            b"in".to_vec(),
            SocksAddr::any_ipv4(),
            SocksAddr::any_ipv4(),
        );
        inbound_tx.send(incoming).await.unwrap();
        assert_eq!(pair.next().await.unwrap().data, b"in");
    }
}
