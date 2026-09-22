use async_trait::async_trait;
use http::Request;
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use std::collections::HashMap;
use tokio_tungstenite::tungstenite::{
    handshake::client::generate_key, protocol::WebSocketConfig,
};

use super::Transport;
use crate::proxy::AnyStream;

mod handshake;
mod http_upgrade;
mod websocket;
mod websocket_early_data;

pub use websocket::WebsocketConn;
pub use websocket_early_data::WebsocketEarlyDataConn;

const PATH_AND_QUERY_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'\"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

pub struct Client {
    host: String,
    port: u16,
    path: String,
    headers: HashMap<String, String>,
    ws_config: Option<WebSocketConfig>,
    max_early_data: usize,
    early_data_header_name: String,
    v2ray_http_upgrade: bool,
    v2ray_http_upgrade_fast_open: bool,
}

impl Client {
    pub fn new(
        host: String,
        port: u16,
        path: String,
        headers: HashMap<String, String>,
        ws_config: Option<WebSocketConfig>,
        max_early_data: usize,
        early_data_header_name: String,
    ) -> Self {
        Self {
            host,
            port,
            path,
            headers,
            ws_config,
            max_early_data,
            early_data_header_name,
            v2ray_http_upgrade: false,
            v2ray_http_upgrade_fast_open: false,
        }
    }

    pub fn with_http_upgrade(mut self, enabled: bool, fast_open: bool) -> Self {
        self.v2ray_http_upgrade = enabled;
        self.v2ray_http_upgrade_fast_open = enabled && fast_open;
        self
    }

    fn req(&self) -> std::io::Result<Request<()>> {
        let path = utf8_percent_encode(&self.path, PATH_AND_QUERY_ENCODE_SET);
        let mut request = Request::builder()
            .method("GET")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", generate_key())
            .uri(format!("ws://{}:{}{}", self.host, self.port, path));
        for (k, v) in self.headers.iter() {
            request = request.header(k.as_str(), v.as_str());
        }
        if !self
            .headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("host"))
        {
            request = request.header("Host", self.host.as_str());
        }
        if self.max_early_data > 0 && !self.early_data_header_name.is_empty() {
            // The lazy early-data stream replaces this placeholder later.
            request = request.header(self.early_data_header_name.as_str(), "xxoo");
        }
        request.body(()).map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, error)
        })
    }

    fn http_upgrade_req(&self) -> std::io::Result<Request<()>> {
        let path = utf8_percent_encode(&self.path, PATH_AND_QUERY_ENCODE_SET);
        let mut request = Request::builder()
            .method("GET")
            .uri(format!("ws://{}:{}{}", self.host, self.port, path));
        for (k, v) in self.headers.iter() {
            request = request.header(k.as_str(), v.as_str());
        }
        if !self
            .headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("host"))
        {
            request = request.header("Host", self.host.as_str());
        }
        let mut request = request.body(()).map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, error)
        })?;
        request.headers_mut().insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("Upgrade"),
        );
        request.headers_mut().insert(
            http::header::UPGRADE,
            http::HeaderValue::from_static("websocket"),
        );
        Ok(request)
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use tokio::io::{AsyncWriteExt, duplex};
    use tokio_tungstenite::{
        accept_hdr_async,
        tungstenite::handshake::server::{Request as ServerRequest, Response},
    };

    use super::{Client, Transport};

    #[test]
    fn req_adds_default_host_header_when_missing() {
        let request = Client::new(
            "sni.example.com".to_owned(),
            443,
            "/ws".to_owned(),
            HashMap::new(),
            None,
            0,
            String::new(),
        )
        .req()
        .expect("request should build");

        assert_eq!(
            request
                .headers()
                .get("Host")
                .and_then(|value| value.to_str().ok()),
            Some("sni.example.com")
        );
    }

    #[test]
    fn req_preserves_explicit_host_header() {
        let headers =
            HashMap::from([("Host".to_owned(), "cdn.example.com".to_owned())]);
        let request = Client::new(
            "sni.example.com".to_owned(),
            443,
            "/ws".to_owned(),
            headers,
            None,
            0,
            String::new(),
        )
        .req()
        .expect("request should build");

        assert_eq!(
            request
                .headers()
                .get("Host")
                .and_then(|value| value.to_str().ok()),
            Some("cdn.example.com")
        );
    }

    #[test]
    fn req_percent_encodes_path_without_normalizing_it() {
        let request = Client::new(
            "example.com".to_owned(),
            443,
            "/a/./b/../already%20encoded/中文 path?name=中文%20value".to_owned(),
            HashMap::new(),
            None,
            0,
            String::new(),
        )
        .req()
        .expect("request should build");

        assert_eq!(
            request.uri().path_and_query().map(ToString::to_string),
            Some(
                concat!(
                    "/a/./b/../already%20encoded/",
                    "%E4%B8%AD%E6%96%87%20path?name=",
                    "%E4%B8%AD%E6%96%87%20value"
                )
                .to_string()
            )
        );
    }

    #[test]
    fn req_allows_path_early_data_without_header_name() {
        let request = Client::new(
            "example.com".to_owned(),
            443,
            "/ws".to_owned(),
            HashMap::new(),
            None,
            2048,
            String::new(),
        )
        .req()
        .expect("path early-data request should build");

        assert!(request.headers().get("").is_none());
        assert_eq!(
            request.uri().path_and_query().map(ToString::to_string),
            Some("/ws".to_owned())
        );
    }

    #[tokio::test]
    #[allow(clippy::result_large_err)]
    async fn path_early_data_is_sent_in_websocket_request_target() {
        let client = Client::new(
            "example.com".to_owned(),
            80,
            "/ws?token=1".to_owned(),
            HashMap::new(),
            None,
            5,
            String::new(),
        );
        let (client_stream, server_stream) = duplex(4096);
        let request_target = Arc::new(Mutex::new(None));
        let captured_target = Arc::clone(&request_target);

        let server_task = tokio::spawn(async move {
            accept_hdr_async(
                server_stream,
                move |request: &ServerRequest, response: Response| {
                    *captured_target.lock().expect("request target lock") =
                        request.uri().path_and_query().map(ToString::to_string);
                    Ok(response)
                },
            )
            .await
            .expect("WebSocket server handshake should succeed")
        });

        let mut stream = client
            .proxy_stream(Box::new(client_stream))
            .await
            .expect("lazy WebSocket early-data stream should build");
        let consumed = stream
            .write(b"hello-tail")
            .await
            .expect("first write should complete the WebSocket handshake");

        assert_eq!(consumed, 5);
        assert_eq!(
            request_target
                .lock()
                .expect("request target lock")
                .as_deref(),
            Some("/wsaGVsbG8?token=1")
        );

        drop(stream);
        server_task
            .await
            .expect("WebSocket server task should not panic");
    }

    #[test]
    fn http_upgrade_request_uses_raw_upgrade_headers_without_ws_key() {
        let request = Client::new(
            "example.com".to_owned(),
            443,
            "/upgrade".to_owned(),
            HashMap::new(),
            None,
            0,
            String::new(),
        )
        .with_http_upgrade(true, true)
        .http_upgrade_req()
        .expect("http upgrade request should build");

        assert_eq!(
            request
                .headers()
                .get("Connection")
                .and_then(|value| value.to_str().ok()),
            Some("Upgrade")
        );
        assert_eq!(
            request
                .headers()
                .get("Upgrade")
                .and_then(|value| value.to_str().ok()),
            Some("websocket")
        );
        assert!(request.headers().get("Sec-WebSocket-Key").is_none());
    }

    #[test]
    fn malformed_request_returns_invalid_input() {
        let error = Client::new(
            "bad host".to_owned(),
            443,
            "/".to_owned(),
            HashMap::new(),
            None,
            0,
            String::new(),
        )
        .req()
        .expect_err("invalid URI should fail");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> std::io::Result<AnyStream> {
        if self.v2ray_http_upgrade {
            let request = self.http_upgrade_req()?;
            if self.max_early_data > 0 {
                return Ok(Box::new(http_upgrade::HttpUpgradeEarlyDataConn::new(
                    stream,
                    request,
                    self.v2ray_http_upgrade_fast_open,
                    self.early_data_header_name.clone(),
                    self.max_early_data,
                )));
            }

            return http_upgrade::client_upgrade(
                stream,
                request,
                self.v2ray_http_upgrade_fast_open,
            )
            .await;
        }

        let req = self.req()?;
        if self.max_early_data > 0 {
            let early_data_conn = WebsocketEarlyDataConn::new(
                stream,
                req,
                self.ws_config,
                self.early_data_header_name.clone(),
                self.max_early_data,
            );
            Ok(Box::new(early_data_conn))
        } else {
            let stream =
                handshake::client_upgrade(stream, req, self.ws_config).await?;
            Ok(Box::new(WebsocketConn::from_websocket(stream)))
        }
    }
}
