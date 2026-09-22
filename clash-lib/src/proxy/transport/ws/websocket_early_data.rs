use std::{
    cmp,
    fmt::Debug,
    pin::Pin,
    task::{Poll, Waker},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::{Future, ready};
use http::{HeaderValue, Request, Uri, uri::PathAndQuery};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::proxy::AnyStream;

use super::{handshake, websocket::WebsocketConn};

pub struct WebsocketEarlyDataConn {
    stream: Option<AnyStream>,
    req: Option<Request<()>>,
    stream_future: Option<
        Pin<
            Box<
                dyn std::future::Future<Output = std::io::Result<AnyStream>>
                    + Send
                    + Sync,
            >,
        >,
    >,
    early_waker: Option<Waker>,
    flush_waker: Option<Waker>,
    ws_config: Option<WebSocketConfig>,
    early_data_header_name: String,
    early_data_len: usize,
    early_data_flushed: bool,
}

impl Debug for WebsocketEarlyDataConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebsocketEarlyDataConn")
            .field("req", &self.req)
            .field("early_waker", &self.early_waker)
            .field("flush_waker", &self.flush_waker)
            .field("ws_config", &self.ws_config)
            .field("early_data_header_name", &self.early_data_header_name)
            .field("early_data_len", &self.early_data_len)
            .field("early_data_flushed", &self.early_data_flushed)
            .finish()
    }
}

impl WebsocketEarlyDataConn {
    pub fn new(
        stream: AnyStream,
        req: Request<()>,
        ws_config: Option<WebSocketConfig>,
        early_data_header_name: String,
        early_data_len: usize,
    ) -> Self {
        Self {
            stream: Some(stream),
            req: Some(req),
            stream_future: None,
            early_waker: None,
            flush_waker: None,
            ws_config,
            early_data_header_name,
            early_data_len,
            early_data_flushed: false,
        }
    }

    fn apply_early_data(
        req: &mut Request<()>,
        header_name: &str,
        buf: &[u8],
        max_early_data: usize,
    ) -> std::io::Result<usize> {
        let early_data_len = cmp::min(max_early_data, buf.len());
        let encoded = URL_SAFE_NO_PAD.encode(&buf[..early_data_len]);

        if header_name.is_empty() {
            let uri = req.uri().clone();
            let mut parts = uri.clone().into_parts();
            let path_and_query = if let Some(query) = uri.query() {
                format!("{}{}?{query}", uri.path(), encoded)
            } else {
                format!("{}{}", uri.path(), encoded)
            };
            parts.path_and_query =
                Some(path_and_query.parse::<PathAndQuery>().map_err(|err| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid websocket early-data URI: {err}"),
                    )
                })?);
            *req.uri_mut() = Uri::from_parts(parts).map_err(|err| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid websocket early-data URI: {err}"),
                )
            })?;
        } else {
            let value = HeaderValue::from_str(&encoded).map_err(|err| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid websocket early-data header value: {err}"),
                )
            })?;
            let header = req.headers_mut().get_mut(header_name).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "websocket early-data header placeholder is missing: {header_name}"
                    ),
                )
            })?;
            *header = value;
        }

        Ok(early_data_len)
    }

    fn proxy_stream(
        stream: AnyStream,
        req: Request<()>,
        config: Option<WebSocketConfig>,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = std::io::Result<AnyStream>>
                + Send
                + Sync,
        >,
    > {
        async fn run(
            stream: AnyStream,
            req: Request<()>,
            config: Option<WebSocketConfig>,
        ) -> std::io::Result<AnyStream> {
            let stream = handshake::client_upgrade(stream, req, config).await?;
            // After the handshake finishes, all read/write/close edge cases are
            // delegated to `WebsocketConn` so early-data and regular WS share
            // the same teardown behavior.
            let rv = Box::new(WebsocketConn::from_websocket(stream));
            Ok(rv)
        }

        Box::pin(run(stream, req, config))
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    fn request() -> Request<()> {
        Request::builder()
            .uri("ws://example.com:80/ws?token=1")
            .header("Sec-WebSocket-Protocol", "placeholder")
            .body(())
            .unwrap()
    }

    #[test]
    fn early_data_uses_configured_header() {
        let mut req = request();

        let consumed = WebsocketEarlyDataConn::apply_early_data(
            &mut req,
            "Sec-WebSocket-Protocol",
            b"hello-tail",
            5,
        )
        .unwrap();

        assert_eq!(consumed, 5);
        assert_eq!(
            req.headers()
                .get("Sec-WebSocket-Protocol")
                .unwrap()
                .to_str()
                .unwrap(),
            "aGVsbG8"
        );
        assert_eq!(req.uri().path_and_query().unwrap().as_str(), "/ws?token=1");
    }

    #[test]
    fn early_data_without_header_is_appended_to_path_before_query() {
        let mut req = request();

        let consumed =
            WebsocketEarlyDataConn::apply_early_data(&mut req, "", b"hello-tail", 5)
                .unwrap();

        assert_eq!(consumed, 5);
        assert_eq!(
            req.uri().path_and_query().unwrap().as_str(),
            "/wsaGVsbG8?token=1"
        );
        assert_eq!(
            req.headers()
                .get("Sec-WebSocket-Protocol")
                .unwrap()
                .to_str()
                .unwrap(),
            "placeholder"
        );
    }
}

impl AsyncRead for WebsocketEarlyDataConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if !self.early_data_flushed {
            if self.early_waker.is_none() {
                self.as_mut().early_waker = Some(cx.waker().clone());
            }
            return Poll::Pending;
        }
        let pin = self.get_mut();
        match &mut pin.stream {
            None => unreachable!("bad state"),
            Some(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for WebsocketEarlyDataConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        if !self.early_data_flushed {
            loop {
                match &mut self.as_mut().stream_future {
                    Some(fut) => {
                        let stream = ready!(Pin::new(fut).poll(cx))?;

                        self.as_mut().stream = Some(stream);
                        self.as_mut().early_data_flushed = true;

                        if let Some(w) = self.as_mut().early_waker.take() {
                            w.wake();
                        }
                        if let Some(w) = self.as_mut().flush_waker.take() {
                            w.wake();
                        }
                        return Poll::Ready(Ok(self.as_mut().early_data_len));
                    }
                    _ => {
                        let mut req =
                            self.as_mut().req.take().expect("req must be present");
                        let max_early_data = self.as_mut().early_data_len;
                        let header_name =
                            self.as_mut().early_data_header_name.clone();
                        self.as_mut().early_data_len = Self::apply_early_data(
                            &mut req,
                            &header_name,
                            buf,
                            max_early_data,
                        )?;

                        let stream =
                            self.as_mut().stream.take().expect("msg: bad state");
                        let config = self.as_mut().ws_config.take();
                        self.as_mut().stream_future =
                            Some(Self::proxy_stream(stream, req, config));
                    }
                }
            }
        }

        match &mut self.as_mut().stream {
            None => unreachable!("bad state"),
            Some(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if !self.early_data_flushed {
            if self.as_mut().flush_waker.is_none() {
                self.as_mut().flush_waker = Some(cx.waker().clone());
            }
            return Poll::Pending;
        }
        match &mut self.stream {
            None => unreachable!("bad state"),
            Some(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if !self.early_data_flushed {
            ready!(self.as_mut().poll_flush(cx))?;
        }
        let pin = self.get_mut();
        match &mut pin.stream {
            None => unreachable!("bad state"),
            Some(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
