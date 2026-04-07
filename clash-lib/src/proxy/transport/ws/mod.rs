use async_trait::async_trait;
use http::Request;
use std::collections::HashMap;
use tokio_tungstenite::tungstenite::{
    handshake::client::generate_key, protocol::WebSocketConfig,
};

use super::Transport;
use crate::proxy::AnyStream;

mod handshake;
mod websocket;
mod websocket_early_data;

pub use websocket::WebsocketConn;
pub use websocket_early_data::WebsocketEarlyDataConn;

pub struct Client {
    host: String,
    port: u16,
    path: String,
    headers: HashMap<String, String>,
    ws_config: Option<WebSocketConfig>,
    max_early_data: usize,
    early_data_header_name: String,
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
        }
    }

    fn req(&self) -> Request<()> {
        let mut request = Request::builder()
            .method("GET")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", generate_key())
            .uri(format!("ws://{}:{}{}", self.host, self.port, self.path));
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
        if self.max_early_data > 0 {
            // we will replace this field later
            request = request.header(self.early_data_header_name.as_str(), "xxoo");
        }
        request.body(()).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::Client;

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
        .req();

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
        .req();

        assert_eq!(
            request
                .headers()
                .get("Host")
                .and_then(|value| value.to_str().ok()),
            Some("cdn.example.com")
        );
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> std::io::Result<AnyStream> {
        let req = self.req();
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
