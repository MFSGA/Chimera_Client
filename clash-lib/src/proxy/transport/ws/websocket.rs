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
            close_received: false,
            close_sent: false,
        }
    }

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

    fn poll_close_inner(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_close(cx) {
            Poll::Ready(Ok(())) => {
                trace!("ws close handshake finished");
                self.mark_stream_closed();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) if Self::is_terminal_ws_error(&err) => {
                trace!("ws close observed terminal state while closing: {err:?}");
                self.mark_stream_closed();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(Self::map_ws_error(err))),
            Poll::Pending => Poll::Pending,
        }
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
                    return Poll::Ready(Err(new_io_error("ws invalid message type")));
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
        let message = Message::Binary(Bytes::copy_from_slice(buf));
        if let Err(err) = Pin::new(&mut self.inner).start_send(message) {
            if Self::is_terminal_ws_error(&err) {
                trace!(
                    "ws write start_send reached terminal closing state: {err:?}"
                );
                self.mark_stream_closed();
            }
            return Poll::Ready(Err(Self::map_ws_error(err)));
        }
        ready!(self.as_mut().poll_flush(cx))?;
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
        if !self.close_sent {
            match ready!(Pin::new(&mut self.inner).poll_ready(cx)) {
                Ok(()) => {}
                Err(err) if Self::is_terminal_ws_error(&err) => {
                    trace!(
                        "ws shutdown saw terminal closing state before sending close: {err:?}"
                    );
                    self.mark_stream_closed();
                    return Poll::Ready(Ok(()));
                }
                Err(err) => return Poll::Ready(Err(Self::map_ws_error(err))),
            }

            // Emit the close frame exactly once. After this point every other
            // write path treats the stream as closing and will stop producing
            // Binary frames.
            trace!("ws shutdown sending close frame");
            if let Err(err) =
                Pin::new(&mut self.inner).start_send(Message::Close(None))
            {
                if Self::is_terminal_ws_error(&err) {
                    trace!(
                        "ws shutdown start_send close hit terminal state: {err:?}"
                    );
                    self.mark_stream_closed();
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(Self::map_ws_error(err)));
            }
            self.close_sent = true;
        }

        self.poll_close_inner(cx)
    }
}
