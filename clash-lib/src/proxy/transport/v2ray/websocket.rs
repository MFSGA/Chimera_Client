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

// Loopback WebSocket handshakes are covered locally; third-party V2Ray plugin
// interoperability remains unverified.
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

        let host_header_count = headers
            .keys()
            .filter(|name| name.eq_ignore_ascii_case("host"))
            .count();
        if host_header_count > 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "v2ray plugin cannot send multiple Host headers",
            ));
        }
        if host_header_count == 0 {
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
        time::Duration,
    };

    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsAcceptor;
    use tokio_tungstenite::{
        accept_hdr_async,
        tungstenite::handshake::server::{Request, Response},
    };

    use super::{Transport, V2rayWsClient};

    const FIXTURE_TIMEOUT: Duration = Duration::from_secs(5);

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
            // Tungstenite requires a full HTTP Response as its rejection type.
            #[allow(clippy::result_large_err)]
            let callback = move |request: &Request, response: Response| {
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
            };
            accept_hdr_async(stream, callback)
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
        let stream =
            tokio::time::timeout(FIXTURE_TIMEOUT, TcpStream::connect(address))
                .await
                .expect("WebSocket TCP connect should finish before timeout")
                .expect("WebSocket fixture should accept TCP");
        let client_stream = tokio::time::timeout(
            FIXTURE_TIMEOUT,
            client.proxy_stream(Box::new(stream)),
        )
        .await
        .expect("WebSocket handshake should finish before timeout")
        .expect("V2Ray WebSocket handshake should succeed");

        drop(client_stream);
        drop(
            tokio::time::timeout(FIXTURE_TIMEOUT, server)
                .await
                .expect("WebSocket fixture should finish before timeout")
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

    #[tokio::test]
    async fn tls_websocket_uses_http11_and_preserves_custom_host() {
        crate::setup_default_crypto_provider();
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
                .expect("test certificate should generate");
        let cert = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
        let key =
            rustls::pki_types::PrivateKeyDer::try_from(signing_key.serialize_der())
                .expect("test private key should serialize");
        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("test TLS config should build");
        tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("TLS WebSocket fixture should bind");
        let address = listener
            .local_addr()
            .expect("TLS WebSocket fixture should have an address");
        let observed = Arc::new(Mutex::new(None));
        let observed_request = Arc::clone(&observed);
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("TLS WebSocket fixture should accept");
            let stream = acceptor
                .accept(stream)
                .await
                .expect("TLS handshake should succeed");
            let alpn = stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
            // Tungstenite requires a full HTTP Response as its rejection type.
            #[allow(clippy::result_large_err)]
            let callback = move |request: &Request, response: Response| {
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
            };
            let websocket = accept_hdr_async(stream, callback)
                .await
                .expect("TLS WebSocket upgrade should succeed");
            drop(websocket);
            alpn
        });

        let client = V2rayWsClient::try_new(
            "localhost".to_owned(),
            address.port(),
            "/secure?token=1".to_owned(),
            HashMap::from([("host".to_owned(), "cdn.example".to_owned())]),
            true,
            true,
            false,
        )
        .expect("TLS V2Ray WebSocket client should be created");
        let stream =
            tokio::time::timeout(FIXTURE_TIMEOUT, TcpStream::connect(address))
                .await
                .expect("TLS TCP connect should finish before timeout")
                .expect("TLS WebSocket fixture should accept TCP");
        let client_stream = tokio::time::timeout(
            FIXTURE_TIMEOUT,
            client.proxy_stream(Box::new(stream)),
        )
        .await
        .expect("TLS WebSocket handshake should finish before timeout")
        .expect("TLS WebSocket handshake should succeed");

        drop(client_stream);
        assert_eq!(
            tokio::time::timeout(FIXTURE_TIMEOUT, server)
                .await
                .expect("TLS fixture should finish before timeout")
                .expect("TLS fixture task should not panic"),
            Some(b"http/1.1".to_vec())
        );
        assert_eq!(
            *observed.lock().expect("request observation lock"),
            Some((
                1,
                Some("cdn.example".to_owned()),
                Some("/secure?token=1".to_owned())
            ))
        );
    }

    #[test]
    fn duplicate_host_headers_with_different_case_are_rejected() {
        let result = V2rayWsClient::try_new(
            "127.0.0.1".to_owned(),
            80,
            "/ws".to_owned(),
            HashMap::from([
                ("Host".to_owned(), "cdn.example".to_owned()),
                ("host".to_owned(), "other.example".to_owned()),
            ]),
            false,
            false,
            false,
        );

        assert!(matches!(
            result,
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput
        ));
    }
}
