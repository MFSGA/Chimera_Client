#![allow(dead_code)]

use std::{collections::HashMap, io};

use async_trait::async_trait;

use crate::proxy::{
    AnyStream,
    transport::{self, TlsClient, Transport, WsClient},
};

use super::V2RayOBFSOption;

impl TryFrom<V2RayOBFSOption> for V2rayWsClient {
    type Error = std::io::Error;

    fn try_from(opt: V2RayOBFSOption) -> Result<Self, Self::Error> {
        if opt.mode != "websocket" {
            return Err(io::Error::other("v2ray plugin does not support this mode"));
        }
        Self::try_new(
            opt.host,
            opt.port,
            opt.path,
            opt.headers,
            opt.tls,
            opt.skip_cert_verify,
            opt.mux,
        )
    }
}

pub struct V2rayWsClient {
    pub tls_client: Option<Box<dyn Transport>>,
    pub ws_client: transport::WsClient,
}

// The plain WebSocket handshake is covered locally; TLS and third-party
// V2Ray plugin interoperability remain unverified.
impl V2rayWsClient {
    pub fn try_new(
        host: String,
        port: u16,
        path: String,
        mut headers: HashMap<String, String>,
        tls: bool,
        skip_cert_verify: bool,
        mux: bool,
    ) -> std::io::Result<Self> {
        if mux {
            return Err(io::Error::other("v2ray plugin does not support mux"));
        }

        let tls_client = if tls {
            Some(Box::new(TlsClient::new(
                skip_cert_verify,
                host.clone(),
                Some(vec!["http/1.1".to_owned()]),
                None,
            )) as _)
        } else {
            None
        };

        if !headers.keys().any(|name| name.eq_ignore_ascii_case("host")) {
            headers.insert("Host".to_owned(), host.clone());
        }
        let ws_client = WsClient::new(
            host,
            port,
            if path.is_empty() {
                "/".to_owned()
            } else {
                path
            },
            headers,
            None,
            0,
            "".to_owned(),
        );

        Ok(Self {
            tls_client,
            ws_client,
        })
    }

    pub async fn new_v2ray_websocket_stream(
        &self,
        s: AnyStream,
    ) -> std::io::Result<AnyStream> {
        let s = if let Some(tls_client) = self.tls_client.as_ref() {
            tls_client.proxy_stream(s).await?
        } else {
            s
        };

        self.ws_client.proxy_stream(s).await
    }
}

#[async_trait]
impl Transport for V2rayWsClient {
    async fn proxy_stream(&self, stream: AnyStream) -> std::io::Result<AnyStream> {
        self.new_v2ray_websocket_stream(stream).await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use tokio::net::{TcpListener, TcpStream};
    use tokio_tungstenite::{
        accept_hdr_async,
        tungstenite::handshake::server::{Request, Response},
    };

    use super::{Transport, V2rayWsClient};

    #[tokio::test]
    async fn lowercase_host_header_is_preserved_without_duplicate() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("WebSocket fixture should bind");
        let address = listener
            .local_addr()
            .expect("WebSocket fixture should have an address");
        let observed = Arc::new(Mutex::new(None));
        let observed_request = Arc::clone(&observed);
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("WebSocket fixture should accept");
            accept_hdr_async(stream, move |request: &Request, response: Response| {
                let host_values = request.headers().get_all("host");
                let value_count = host_values.iter().count();
                let host = host_values
                    .iter()
                    .next()
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                let path = request.uri().path_and_query().map(ToString::to_string);
                *observed_request.lock().expect("request observation lock") =
                    Some((value_count, host, path));
                Ok(response)
            })
            .await
            .expect("WebSocket upgrade should succeed")
        });

        let client = V2rayWsClient::try_new(
            "127.0.0.1".to_owned(),
            address.port(),
            "/ws?token=1".to_owned(),
            HashMap::from([("host".to_owned(), "cdn.example".to_owned())]),
            false,
            false,
            false,
        )
        .expect("V2Ray WebSocket client should be created");
        let stream = TcpStream::connect(address)
            .await
            .expect("WebSocket fixture should accept TCP");
        let client_stream = client
            .proxy_stream(Box::new(stream))
            .await
            .expect("V2Ray WebSocket handshake should succeed");

        drop(client_stream);
        drop(
            server
                .await
                .expect("WebSocket fixture task should not panic"),
        );

        assert_eq!(
            *observed.lock().expect("request observation lock"),
            Some((
                1,
                Some("cdn.example".to_owned()),
                Some("/ws?token=1".to_owned())
            ))
        );
    }
}
