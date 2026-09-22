use std::{
    cmp,
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll, Waker},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::{Buf, Bytes, BytesMut};
use futures::ready;
use http::{HeaderMap, HeaderName, HeaderValue, Request};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{common::errors::new_io_error, proxy::AnyStream};

use super::handshake::serialize_request;

const RESPONSE_HEADER_LIMIT: usize = 64 * 1024;

pub async fn client_upgrade(
    mut stream: AnyStream,
    request: Request<()>,
    fast_open: bool,
) -> io::Result<AnyStream> {
    let raw_request = serialize_request(&request)?;
    stream.write_all(&raw_request).await?;
    stream.flush().await?;

    if fast_open {
        return Ok(Box::new(HttpUpgradeConn::new(stream)));
    }

    let buffered = read_upgrade_response(&mut stream).await?;
    Ok(Box::new(HttpUpgradeConn::ready(stream, buffered)))
}

pub struct HttpUpgradeEarlyDataConn {
    stream: Option<AnyStream>,
    request: Option<Request<()>>,
    stream_future:
        Option<Pin<Box<dyn Future<Output = io::Result<AnyStream>> + Send + Sync>>>,
    read_waker: Option<Waker>,
    flush_waker: Option<Waker>,
    early_data_header_name: String,
    max_early_data: usize,
    early_data_len: usize,
    fast_open: bool,
    handshake_complete: bool,
}

impl HttpUpgradeEarlyDataConn {
    pub fn new(
        stream: AnyStream,
        request: Request<()>,
        fast_open: bool,
        early_data_header_name: String,
        max_early_data: usize,
    ) -> Self {
        Self {
            stream: Some(stream),
            request: Some(request),
            stream_future: None,
            read_waker: None,
            flush_waker: None,
            early_data_header_name,
            max_early_data,
            early_data_len: 0,
            fast_open,
            handshake_complete: false,
        }
    }

    fn start_handshake(&mut self, buf: &[u8]) -> io::Result<()> {
        let mut request = self.request.take().ok_or_else(|| {
            new_io_error("http upgrade early-data request is missing")
        })?;
        let header_name = HeaderName::from_bytes(
            self.early_data_header_name.as_bytes(),
        )
        .map_err(|_| new_io_error("invalid http upgrade early-data header name"))?;

        self.early_data_len = cmp::min(self.max_early_data, buf.len());
        let header_value = URL_SAFE_NO_PAD.encode(&buf[..self.early_data_len]);
        let header_value = HeaderValue::from_str(&header_value).map_err(|_| {
            new_io_error("invalid http upgrade early-data header value")
        })?;
        request.headers_mut().insert(header_name, header_value);

        let stream = self.stream.take().ok_or_else(|| {
            new_io_error("http upgrade early-data stream is missing")
        })?;
        let fast_open = self.fast_open;
        self.stream_future = Some(Box::pin(async move {
            client_upgrade(stream, request, fast_open).await
        }));
        Ok(())
    }

    fn poll_handshake(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        initial_buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            if let Some(future) = self.as_mut().stream_future.as_mut() {
                let stream = ready!(Pin::new(future).poll(cx))?;
                self.as_mut().stream = Some(stream);
                self.as_mut().stream_future = None;
                self.as_mut().handshake_complete = true;

                if let Some(waker) = self.as_mut().read_waker.take() {
                    waker.wake();
                }
                if let Some(waker) = self.as_mut().flush_waker.take() {
                    waker.wake();
                }
                return Poll::Ready(Ok(self.as_mut().early_data_len));
            }

            if let Err(err) = self.as_mut().start_handshake(initial_buf) {
                return Poll::Ready(Err(err));
            }
        }
    }
}

impl AsyncRead for HttpUpgradeEarlyDataConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.handshake_complete {
            if self.read_waker.is_none() {
                self.as_mut().read_waker = Some(cx.waker().clone());
            }
            return Poll::Pending;
        }

        match self.as_mut().stream.as_mut() {
            Some(stream) => Pin::new(stream).poll_read(cx, buf),
            None => Poll::Ready(Err(new_io_error(
                "http upgrade early-data stream is missing",
            ))),
        }
    }
}

impl AsyncWrite for HttpUpgradeEarlyDataConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.handshake_complete {
            return self.as_mut().poll_handshake(cx, buf);
        }

        match self.as_mut().stream.as_mut() {
            Some(stream) => Pin::new(stream).poll_write(cx, buf),
            None => Poll::Ready(Err(new_io_error(
                "http upgrade early-data stream is missing",
            ))),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.handshake_complete {
            if self.flush_waker.is_none() {
                self.as_mut().flush_waker = Some(cx.waker().clone());
            }
            return Poll::Pending;
        }

        match self.as_mut().stream.as_mut() {
            Some(stream) => Pin::new(stream).poll_flush(cx),
            None => Poll::Ready(Err(new_io_error(
                "http upgrade early-data stream is missing",
            ))),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.handshake_complete {
            ready!(self.as_mut().poll_flush(cx))?;
        }

        match self.as_mut().stream.as_mut() {
            Some(stream) => Pin::new(stream).poll_shutdown(cx),
            None => Poll::Ready(Err(new_io_error(
                "http upgrade early-data stream is missing",
            ))),
        }
    }
}

async fn read_upgrade_response(stream: &mut AnyStream) -> io::Result<Bytes> {
    let mut response = BytesMut::with_capacity(1024);
    loop {
        if response.len() > RESPONSE_HEADER_LIMIT {
            return Err(new_io_error("http upgrade response headers are too large"));
        }

        if let Some(header_end) = find_response_header_end(&response) {
            validate_upgrade_response(&response[..header_end])?;
            return Ok(response.split_off(header_end).freeze());
        }

        let read = stream.read_buf(&mut response).await?;
        if read == 0 {
            return Err(new_io_error(
                "http upgrade response ended before headers completed",
            ));
        }
    }
}

fn find_response_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|offset| offset + 4)
}

fn validate_upgrade_response(raw: &[u8]) -> io::Result<()> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| new_io_error("http upgrade response is not valid utf-8"))?;
    let mut lines = text.split("\r\n");
    let status = lines.next().ok_or_else(|| {
        new_io_error("http upgrade response is missing status line")
    })?;
    let mut status_parts = status.split_whitespace();
    let version = status_parts.next().ok_or_else(|| {
        new_io_error("http upgrade response is missing http version")
    })?;
    let code = status_parts.next().ok_or_else(|| {
        new_io_error("http upgrade response is missing status code")
    })?;

    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(new_io_error(
            "http upgrade response returned unexpected http version",
        ));
    }
    if code != "101" {
        return Err(new_io_error(
            "http upgrade response did not switch protocols",
        ));
    }

    let mut headers = HeaderMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').ok_or_else(|| {
            new_io_error("http upgrade response contains malformed header")
        })?;
        let name = http::header::HeaderName::from_bytes(name.trim().as_bytes())
            .map_err(|_| {
                new_io_error("http upgrade response contains invalid header name")
            })?;
        let value = http::HeaderValue::from_str(value.trim()).map_err(|_| {
            new_io_error("http upgrade response contains invalid header value")
        })?;
        headers.insert(name, value);
    }

    if !header_contains_token(&headers, "Connection", "Upgrade") {
        return Err(new_io_error(
            "http upgrade response has invalid Connection header",
        ));
    }
    let upgrade = find_header(&headers, "Upgrade")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            new_io_error("http upgrade response is missing Upgrade header")
        })?;
    if !upgrade.eq_ignore_ascii_case("websocket") {
        return Err(new_io_error(
            "http upgrade response has invalid Upgrade header",
        ));
    }

    Ok(())
}

fn find_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Option<&'a http::HeaderValue> {
    headers.iter().find_map(|(header_name, value)| {
        header_name
            .as_str()
            .eq_ignore_ascii_case(name)
            .then_some(value)
    })
}

fn header_contains_token(headers: &HeaderMap, name: &str, token: &str) -> bool {
    find_header(headers, name)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(token))
        })
        .unwrap_or(false)
}

pub struct HttpUpgradeConn {
    stream: AnyStream,
    response_checked: bool,
    response_buf: BytesMut,
    buffered: Bytes,
}

impl HttpUpgradeConn {
    fn new(stream: AnyStream) -> Self {
        Self {
            stream,
            response_checked: false,
            response_buf: BytesMut::with_capacity(1024),
            buffered: Bytes::new(),
        }
    }

    fn ready(stream: AnyStream, buffered: Bytes) -> Self {
        Self {
            stream,
            response_checked: true,
            response_buf: BytesMut::new(),
            buffered,
        }
    }

    fn poll_response(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if self.response_buf.len() > RESPONSE_HEADER_LIMIT {
                return Poll::Ready(Err(new_io_error(
                    "http upgrade response headers are too large",
                )));
            }

            if let Some(header_end) = find_response_header_end(&self.response_buf) {
                if let Err(err) =
                    validate_upgrade_response(&self.response_buf[..header_end])
                {
                    return Poll::Ready(Err(err));
                }
                self.buffered = self.response_buf.split_off(header_end).freeze();
                self.response_buf.clear();
                self.response_checked = true;
                return Poll::Ready(Ok(()));
            }

            let mut temp = [0u8; 4096];
            let mut read_buf = ReadBuf::new(&mut temp);
            match Pin::new(&mut self.stream).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {
                    let filled = read_buf.filled();
                    if filled.is_empty() {
                        return Poll::Ready(Err(new_io_error(
                            "http upgrade response ended before headers completed",
                        )));
                    }
                    self.response_buf.extend_from_slice(filled);
                }
            }
        }
    }

    fn copy_buffered(&mut self, buf: &mut ReadBuf<'_>) {
        if self.buffered.is_empty() || buf.remaining() == 0 {
            return;
        }
        let len = self.buffered.len().min(buf.remaining());
        buf.put_slice(&self.buffered[..len]);
        self.buffered.advance(len);
    }
}

impl AsyncRead for HttpUpgradeConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.response_checked {
            match self.poll_response(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {}
            }
        }

        if !self.buffered.is_empty() {
            self.copy_buffered(buf);
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for HttpUpgradeConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn request() -> Request<()> {
        Request::builder()
            .method("GET")
            .uri("ws://example.com:443/http-upgrade")
            .header("Host", "example.com")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .body(())
            .unwrap()
    }

    async fn read_headers(stream: &mut tokio::io::DuplexStream) -> Vec<u8> {
        let mut buf = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).await.unwrap();
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n\r\n") {
                return buf;
            }
        }
    }

    #[tokio::test]
    async fn normal_upgrade_waits_for_101_and_preserves_buffered_data() {
        let (client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let headers = read_headers(&mut server).await;
            let text = String::from_utf8(headers).unwrap();
            assert!(text.starts_with("GET /http-upgrade HTTP/1.1\r\n"));
            server
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nhello",
                )
                .await
                .unwrap();
        });

        let mut upgraded = client_upgrade(Box::new(client), request(), false)
            .await
            .unwrap();
        let mut hello = [0u8; 5];
        upgraded.read_exact(&mut hello).await.unwrap();
        assert_eq!(&hello, b"hello");
    }

    #[tokio::test]
    async fn early_data_is_encoded_in_header_before_tail_write() {
        let (client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let headers = read_headers(&mut server).await;
            let text = String::from_utf8(headers).unwrap();
            assert!(text.contains("sec-websocket-protocol: ZWFybHk\r\n"));

            server
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                )
                .await
                .unwrap();

            let mut tail = [0u8; 4];
            server.read_exact(&mut tail).await.unwrap();
            assert_eq!(&tail, b"tail");
            server.write_all(b"reply").await.unwrap();
        });

        let mut upgraded = HttpUpgradeEarlyDataConn::new(
            Box::new(client),
            request(),
            false,
            "Sec-WebSocket-Protocol".to_owned(),
            5,
        );
        upgraded.write_all(b"earlytail").await.unwrap();
        upgraded.flush().await.unwrap();

        let mut reply = [0u8; 5];
        upgraded.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
    }

    #[tokio::test]
    async fn early_data_fast_open_allows_tail_before_101_response() {
        let (client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let headers = read_headers(&mut server).await;
            let text = String::from_utf8(headers).unwrap();
            assert!(text.contains("sec-websocket-protocol: ZWFybHk\r\n"));

            let mut tail = [0u8; 4];
            server.read_exact(&mut tail).await.unwrap();
            assert_eq!(&tail, b"tail");

            server
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nreply",
                )
                .await
                .unwrap();
        });

        let mut upgraded = HttpUpgradeEarlyDataConn::new(
            Box::new(client),
            request(),
            true,
            "Sec-WebSocket-Protocol".to_owned(),
            5,
        );
        upgraded.write_all(b"earlytail").await.unwrap();
        upgraded.flush().await.unwrap();

        let mut reply = [0u8; 5];
        upgraded.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
    }

    #[tokio::test]
    async fn fast_open_allows_payload_before_101_response() {
        let (client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let _headers = read_headers(&mut server).await;
            let mut payload = [0u8; 5];
            server.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"early");
            server
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nreply",
                )
                .await
                .unwrap();
        });

        let mut upgraded = client_upgrade(Box::new(client), request(), true)
            .await
            .unwrap();
        upgraded.write_all(b"early").await.unwrap();
        upgraded.flush().await.unwrap();

        let mut reply = [0u8; 5];
        upgraded.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
    }

    #[test]
    fn rejects_non_switching_protocol_response() {
        let err = validate_upgrade_response(
            b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\n",
        )
        .expect_err("non-101 response must fail");
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }
}
