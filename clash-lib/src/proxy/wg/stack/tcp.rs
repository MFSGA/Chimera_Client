use std::fmt::Debug;

use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc::{Receiver, Sender},
};
use tracing::trace;

#[derive(Debug)]
pub struct SocketPair {
    pub read: Receiver<Bytes>,
    pub write: Sender<Bytes>,
    read_buf: BytesMut,
}

impl SocketPair {
    pub fn new(read: Receiver<Bytes>, write: Sender<Bytes>) -> Self {
        Self {
            read,
            write,
            read_buf: BytesMut::new(),
        }
    }
}

impl AsyncRead for SocketPair {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if !self.read_buf.is_empty() {
            let len = std::cmp::min(self.read_buf.len(), buf.remaining());
            buf.put_slice(&self.read_buf.split_to(len));
            trace!(
                "reusing cached data sent {}, left {}",
                len,
                self.read_buf.len()
            );
            return std::task::Poll::Ready(Ok(()));
        }

        match self.read.poll_recv(cx) {
            std::task::Poll::Ready(Some(data)) => {
                let len = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..len]);
                self.read_buf.extend_from_slice(&data[len..]);
                trace!(
                    "socket got {} data, sent {}, left {}",
                    data.len(),
                    len,
                    self.read_buf.len()
                );
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl AsyncWrite for SocketPair {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match self.write.try_send(buf.to_owned().into()) {
            Ok(_) => std::task::Poll::Ready(Ok(buf.len())),
            Err(_) => std::task::Poll::Pending,
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::SocketPair;

    #[tokio::test]
    async fn wireguard_tcp_socket_pair_buffers_partial_reads() {
        let (read_tx, read_rx) = tokio::sync::mpsc::channel(4);
        let (write_tx, mut write_rx) = tokio::sync::mpsc::channel(4);
        let mut pair = SocketPair::new(read_rx, write_tx);

        read_tx.send(Bytes::from_static(b"abcdef")).await.unwrap();
        let mut first = [0u8; 2];
        pair.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"ab");
        let mut rest = [0u8; 4];
        pair.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"cdef");

        pair.write_all(b"xyz").await.unwrap();
        assert_eq!(write_rx.recv().await.unwrap(), Bytes::from_static(b"xyz"));
    }
}
