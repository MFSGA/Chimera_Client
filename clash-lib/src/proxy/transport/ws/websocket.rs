use std::{fmt::Debug, io, pin::Pin, task::Poll};

use bytes::{Bytes, BytesMut};
use futures::{Sink, Stream, ready};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Error as WsError, Message, error::ProtocolError},
};
use tracing::trace;

use crate::{
    common::errors::{map_io_error, new_io_error},
    proxy::AnyStream,
};

pub struct WebsocketConn {
    inner: WebSocketStream<AnyStream>,
    read_buffer: BytesMut,
    write_buffer: BytesMut,
    close_received: bool,
    close_sent: bool,
}

impl Debug for WebsocketConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebsocketConn")
            .field("read_buffer", &self.read_buffer)
            .finish()
    }
}

impl WebsocketConn {
    pub fn from_websocket(stream: WebSocketStream<AnyStream>) -> Self {
        Self {
            inner: stream,
            read_buffer: BytesMut::new(),
            write_buffer: BytesMut::with_capacity(Self::WRITE_BUFFER_CAPACITY),
            close_received: false,
            close_sent: false,
        }
    }

    const WRITE_BUFFER_CAPACITY: usize = 32 * 1024;
    const WRITE_BUFFER_LIMIT: usize = 128 * 1024;

    fn is_closing(&self) -> bool {
        self.close_received || self.close_sent
    }

    fn mark_stream_closed(&mut self) {
        self.close_received = true;
        self.close_sent = true;
    }

    fn is_terminal_ws_error(err: &WsError) -> bool {
        matches!(
            err,
            WsError::ConnectionClosed
                | WsError::AlreadyClosed
                | WsError::Protocol(ProtocolError::SendAfterClosing)
                | WsError::Protocol(ProtocolError::ReceivedAfterClosing)
        )
    }

    fn map_ws_error(err: WsError) -> io::Error {
        if Self::is_terminal_ws_error(&err) {
            return io::Error::new(
                io::ErrorKind::BrokenPipe,
                "websocket stream is closing",
            );
        }

        match err {
            WsError::Io(err) => err,
            other => map_io_error(other),
        }
    }

    fn poll_flush_inner(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.poll_send_pending_binary(cx))?;
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => {
                if Self::is_terminal_ws_error(&err) {
                    trace!("ws flush reached terminal closing state: {err:?}");
                    self.mark_stream_closed();
                }
                Poll::Ready(Err(Self::map_ws_error(err)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_send_pending_binary(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.write_buffer.is_empty() {
            return Poll::Ready(Ok(()));
        }

        if self.is_closing() {
            trace!(
                "ws flush skipped because the close handshake already started \
                 (close_received={}, close_sent={})",
                self.close_received, self.close_sent
            );
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "websocket stream is closing",
            )));
        }

        match ready!(Pin::new(&mut self.inner).poll_ready(cx)) {
            Ok(()) => {}
            Err(err) => {
                if Self::is_terminal_ws_error(&err) {
                    trace!(
                        "ws write readiness reached terminal closing state: {err:?}"
                    );
                    self.mark_stream_closed();
                }
                return Poll::Ready(Err(Self::map_ws_error(err)));
            }
        }

        let payload = Bytes::copy_from_slice(&self.write_buffer);
        if let Err(err) =
            Pin::new(&mut self.inner).start_send(Message::Binary(payload))
        {
            if Self::is_terminal_ws_error(&err) {
                trace!(
                    "ws write start_send reached terminal closing state: {err:?}"
                );
                self.mark_stream_closed();
            }
            return Poll::Ready(Err(Self::map_ws_error(err)));
        }
        self.write_buffer.clear();
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for WebsocketConn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if !self.read_buffer.is_empty() {
            let to_read = std::cmp::min(buf.remaining(), self.read_buffer.len());
            let for_read = self.read_buffer.split_to(to_read);
            buf.put_slice(&for_read[..to_read]);
            return std::task::Poll::Ready(Ok(()));
        }

        if self.close_received {
            return Poll::Ready(Ok(()));
        }

        loop {
            let item = match ready!(Pin::new(&mut self.inner).poll_next(cx)) {
                Some(item) => item,
                None => {
                    trace!("ws read stream ended without additional frames");
                    self.mark_stream_closed();
                    return Poll::Ready(Ok(()));
                }
            };

            match item {
                Ok(Message::Binary(data)) => {
                    let to_read = std::cmp::min(buf.remaining(), data.len());
                    buf.put_slice(&data[..to_read]);
                    if to_read < data.len() {
                        self.read_buffer.extend_from_slice(&data[to_read..]);
                    }
                    return Poll::Ready(Ok(()));
                }
                // Ping/Pong may still surface here depending on tungstenite's
                // internal buffering. They are control frames, not payload, so
                // the stream should keep polling instead of treating them as an
                // application-level protocol error.
                Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => continue,
                Ok(Message::Close(_)) => {
                    trace!("ws read received close frame from peer");
                    self.close_received = true;
                    return Poll::Ready(Ok(()));
                }
                Ok(_) => {
                    return Poll::Ready(Err(new_io_error(
                        "ws invalid message type",
                    )));
                }
                Err(err) if Self::is_terminal_ws_error(&err) => {
                    trace!("ws read reached terminal closing state: {err:?}");
                    self.mark_stream_closed();
                    return Poll::Ready(Ok(()));
                }
                Err(err) => return Poll::Ready(Err(Self::map_ws_error(err))),
            }
        }
    }
}

impl AsyncWrite for WebsocketConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Once either side has entered the close handshake we must stop
        // sending application data frames. Trying to push another Binary frame
        // is what triggers tungstenite's `SendAfterClosing` protocol error.
        if self.is_closing() {
            trace!(
                "ws write skipped because the close handshake already started \
                 (close_received={}, close_sent={})",
                self.close_received, self.close_sent
            );
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "websocket stream is closing",
            )));
        }

        if self.write_buffer.len() >= Self::WRITE_BUFFER_LIMIT {
            ready!(self.as_mut().poll_flush(cx))?;
            if self.write_buffer.len() >= Self::WRITE_BUFFER_LIMIT {
                return Poll::Pending;
            }
        }

        self.write_buffer.extend_from_slice(buf);
        if self.write_buffer.len() >= Self::WRITE_BUFFER_CAPACITY {
            match self.as_mut().poll_flush(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => {}
            }
        }
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.poll_flush_inner(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        if self.close_received {
            trace!("ws shutdown completed after peer close");
            return Poll::Ready(Ok(()));
        }

        // This adapter exposes a byte-stream abstraction on top of WebSocket.
        // `copy_bidirectional()` uses `poll_shutdown()` to model TCP half-close
        // when one direction reaches EOF first, but WebSocket has no half-close
        // concept: sending a Close frame would terminate the whole tunnel and
        // truncate any in-flight response body from the peer.  Treat shutdown as
        // "flush pending frames only" so the reverse direction can continue to
        // stream until the peer actually closes or the connection is dropped.
        trace!("ws shutdown flushing without sending close frame");
        self.poll_flush_inner(cx)
    }
}

#[cfg(test)]
mod tests {
    use futures::SinkExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio_tungstenite::{
        accept_async, client_async,
        tungstenite::{Message, handshake::client::generate_key},
    };

    use super::WebsocketConn;
    use crate::proxy::AnyStream;

    fn test_request() -> http::Request<()> {
        http::Request::builder()
            .method("GET")
            .uri("ws://example.com/")
            .header("Host", "example.com")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", generate_key())
            .body(())
            .expect("request must be valid")
    }

    #[tokio::test]
    async fn shutdown_does_not_emit_close_before_peer_finishes() {
        let (client_io, server_io) = duplex(4096);

        let server = tokio::spawn(async move {
            let mut ws = accept_async(server_io).await.expect("server handshake");
            ws.send(Message::Binary(b"hello".to_vec().into()))
                .await
                .expect("server send after client shutdown");
            ws
        });

        let (client_ws, _) =
            client_async(test_request(), Box::new(client_io) as AnyStream)
                .await
                .expect("client handshake");
        let mut conn = WebsocketConn::from_websocket(client_ws);

        conn.shutdown().await.expect("shutdown should only flush");

        let mut buf = [0u8; 5];
        conn.read_exact(&mut buf)
            .await
            .expect("peer data should still arrive after shutdown");
        assert_eq!(&buf, b"hello");

        let mut server_ws = server.await.expect("server task");
        server_ws.close(None).await.expect("server close");
    }
}
