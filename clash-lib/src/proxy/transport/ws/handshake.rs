use std::io;

use bytes::BytesMut;
use http::{HeaderMap, HeaderValue, Request};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        handshake::derive_accept_key,
        protocol::{Role, WebSocketConfig},
    },
};

use crate::{common::errors::new_io_error, proxy::AnyStream};

const RESPONSE_HEADER_LIMIT: usize = 64 * 1024;

fn serialize_request(request: &Request<()>) -> io::Result<Vec<u8>> {
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let mut data = Vec::with_capacity(512);
    data.extend_from_slice(format!("GET {path} HTTP/1.1\r\n").as_bytes());

    for (name, value) in request.headers() {
        let value = value
            .to_str()
            .map_err(|_| new_io_error("ws request header is not valid ascii"))?;
        data.extend_from_slice(name.as_str().as_bytes());
        data.extend_from_slice(b": ");
        data.extend_from_slice(value.as_bytes());
        data.extend_from_slice(b"\r\n");
    }

    data.extend_from_slice(b"\r\n");
    Ok(data)
}

fn find_response_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|offset| offset + 4)
}

fn find_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a HeaderValue> {
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

fn validate_response_headers(
    headers: &HeaderMap,
    expected_accept_key: &str,
) -> io::Result<()> {
    let upgrade = find_header(headers, "Upgrade")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            new_io_error("ws upgrade response is missing Upgrade header")
        })?;
    if !upgrade.eq_ignore_ascii_case("websocket") {
        return Err(new_io_error(
            "ws upgrade response has invalid Upgrade header",
        ));
    }

    if !header_contains_token(headers, "Connection", "Upgrade") {
        return Err(new_io_error(
            "ws upgrade response has invalid Connection header",
        ));
    }

    let accept = find_header(headers, "Sec-WebSocket-Accept")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            new_io_error("ws upgrade response is missing Sec-WebSocket-Accept")
        })?;
    if accept != expected_accept_key {
        return Err(new_io_error(
            "ws upgrade response has mismatched Sec-WebSocket-Accept",
        ));
    }

    Ok(())
}

fn parse_response_headers(
    buf: &[u8],
    expected_accept_key: &str,
) -> io::Result<(usize, Vec<u8>)> {
    let header_end = find_response_header_end(buf)
        .ok_or_else(|| new_io_error("ws upgrade response is incomplete"))?;
    let raw_headers = std::str::from_utf8(&buf[..header_end])
        .map_err(|_| new_io_error("ws upgrade response is not valid utf-8"))?;

    let mut lines = raw_headers.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| new_io_error("ws upgrade response is missing status line"))?;
    let mut status_parts = status_line.split_whitespace();
    let http_version = status_parts.next().ok_or_else(|| {
        new_io_error("ws upgrade response is missing http version")
    })?;
    let status_code = status_parts
        .next()
        .ok_or_else(|| new_io_error("ws upgrade response is missing status code"))?;
    if http_version != "HTTP/1.1" && http_version != "HTTP/1.0" {
        return Err(new_io_error(
            "ws upgrade response returned unexpected http version",
        ));
    }
    if status_code != "101" {
        return Err(new_io_error("ws upgrade response did not switch protocols"));
    }

    let mut headers = HeaderMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').ok_or_else(|| {
            new_io_error("ws upgrade response contains malformed header")
        })?;
        let header_name =
            http::header::HeaderName::from_bytes(name.trim().as_bytes()).map_err(
                |_| new_io_error("ws upgrade response contains invalid header name"),
            )?;
        let header_value = HeaderValue::from_str(value.trim()).map_err(|_| {
            new_io_error("ws upgrade response contains invalid header value")
        })?;
        headers.insert(header_name, header_value);
    }

    validate_response_headers(&headers, expected_accept_key)?;

    Ok((header_end, buf[header_end..].to_vec()))
}

pub(super) async fn client_upgrade(
    mut stream: AnyStream,
    request: Request<()>,
    config: Option<WebSocketConfig>,
) -> io::Result<WebSocketStream<AnyStream>> {
    let request_key = request
        .headers()
        .get("Sec-WebSocket-Key")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| new_io_error("ws request is missing Sec-WebSocket-Key"))?
        .to_owned();
    let expected_accept_key = derive_accept_key(request_key.as_bytes());

    let raw_request = serialize_request(&request)?;
    stream.write_all(&raw_request).await?;
    stream.flush().await?;

    let mut response_buf = BytesMut::with_capacity(1024);
    let buffered_data = loop {
        if response_buf.len() > RESPONSE_HEADER_LIMIT {
            return Err(new_io_error("ws upgrade response headers are too large"));
        }
        if find_response_header_end(&response_buf).is_some() {
            let (_, buffered_data) =
                parse_response_headers(&response_buf, &expected_accept_key)?;
            break buffered_data;
        }

        let read = stream.read_buf(&mut response_buf).await?;
        if read == 0 {
            return Err(new_io_error("ws upgrade response ended unexpectedly"));
        }
    };

    let stream = if buffered_data.is_empty() {
        WebSocketStream::from_raw_socket(stream, Role::Client, config).await
    } else {
        WebSocketStream::from_partially_read(
            stream,
            buffered_data,
            Role::Client,
            config,
        )
        .await
    };

    Ok(stream)
}

#[cfg(test)]
mod tests {
    use http::Request;
    use tokio_tungstenite::tungstenite::handshake::client::generate_key;

    use super::{parse_response_headers, serialize_request};

    #[test]
    fn serialize_request_uses_origin_form() {
        let request = Request::builder()
            .method("GET")
            .uri("ws://example.com:443/socket?foo=bar")
            .header("Host", "example.com")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", generate_key())
            .body(())
            .expect("request");

        let text =
            String::from_utf8(serialize_request(&request).expect("serialize"))
                .expect("utf-8");
        assert!(text.starts_with("GET /socket?foo=bar HTTP/1.1\r\n"));
    }

    #[test]
    fn parse_response_headers_accepts_valid_upgrade() {
        let request_key = generate_key();
        let accept_key =
            tokio_tungstenite::tungstenite::handshake::derive_accept_key(
                request_key.as_bytes(),
            );
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Accept: {accept_key}\r\n\r\n\
             extra"
        );

        let (_, leftover) =
            parse_response_headers(response.as_bytes(), &accept_key).expect("parse");
        assert_eq!(leftover, b"extra");
    }
}
