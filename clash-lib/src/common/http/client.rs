use std::{collections::HashMap, io, sync::Arc};

use futures::FutureExt;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tracing::{trace, warn};

use crate::{
    app::dns::ThreadSafeDNSResolver, config::internal::proxy::PROXY_DIRECT,
    proxy::AnyOutboundHandler,
};

#[cfg(feature = "tls")]
use crate::common::tls::GLOBAL_ROOT_STORE;

#[derive(Clone, Debug)]
pub struct ClashHTTPClientExt {
    pub outbound: Option<String>,
}

/// A simple HTTP client that can be used to make HTTP requests.
/// Not performant for lack of connection pooling, but useful for simple tasks.
#[derive(Clone)]
pub struct HttpClient {
    dns_resolver: ThreadSafeDNSResolver,
    outbounds: Option<HashMap<String, AnyOutboundHandler>>,
    #[cfg(feature = "tls")]
    tls_config: Arc<rustls::ClientConfig>,
    timeout: tokio::time::Duration,
}

impl HttpClient {
    pub fn new(
        dns_resolver: ThreadSafeDNSResolver,
        bootstrap_outbounds: Option<Vec<AnyOutboundHandler>>,
        timeout: Option<tokio::time::Duration>,
    ) -> io::Result<HttpClient> {
        #[cfg(feature = "tls")]
        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(GLOBAL_ROOT_STORE.clone())
            .with_no_client_auth();
        #[cfg(feature = "tls")]
        if std::env::var("SSLKEYLOGFILE").is_ok() {
            tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
        }

        Ok(HttpClient {
            dns_resolver,
            outbounds: bootstrap_outbounds.map(|obs| {
                let mut map = HashMap::new();
                for handler in obs {
                    map.insert(handler.name().to_owned(), handler);
                }
                map
            }),
            #[cfg(feature = "tls")]
            tls_config: Arc::new(tls_config),
            timeout: timeout.unwrap_or(tokio::time::Duration::from_secs(10)),
        })
    }

    async fn connect_tcp(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        let connect = TcpStream::connect((host, port));
        tokio::time::timeout(self.timeout, connect)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tcp connect timeout"))?
    }

    pub async fn request<T>(
        &self,
        mut req: http::Request<T>,
    ) -> Result<http::Response<hyper::body::Incoming>, io::Error>
    where
        T: hyper::body::Body + Send + 'static,
        <T as hyper::body::Body>::Data: Send,
        <T as hyper::body::Body>::Error: std::error::Error + Send + Sync,
    {
        let uri = req.uri().clone();

        let host = uri
            .host()
            .ok_or(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("uri must have a host: {uri}"),
            ))?
            .to_owned();
        let port = uri.port_u16().unwrap_or(match uri.scheme_str() {
            None => 80,
            Some("http") => 80,
            Some("https") => 443,
            Some(s) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unsupported scheme: {s}"),
                ));
            }
        });

        if req.headers_mut().get(http::header::HOST).is_none() {
            req.headers_mut().insert(
                http::header::HOST,
                uri.host()
                    .ok_or(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "uri must have a host",
                    ))?
                    .parse()
                    .expect("must parse host header"),
            );
        }

        let req_ext = req.extensions().get::<ClashHTTPClientExt>();
        let outbound_name = req_ext
            .and_then(|ext| ext.outbound.as_deref())
            .unwrap_or(PROXY_DIRECT);
        if let Some(outbounds) = self.outbounds.as_ref() {
            if let Some(outbound) = outbounds.get(outbound_name) {
                trace!(outbound = %outbound.name(), "using outbound for http client");
            }
        }

        let stream = self.connect_tcp(&host, port).await?;

        #[cfg(not(feature = "tls"))]
        if uri.scheme() == Some(&http::uri::Scheme::HTTPS) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "https requires the tls feature",
            ));
        }

        let resp = match uri.scheme() {
            Some(scheme) if scheme == &http::uri::Scheme::HTTP => {
                let io = TokioIo::new(stream);
                let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
                    .await
                    .map_err(io::Error::other)?;

                tokio::task::spawn(async move {
                    if let Err(err) = conn.await {
                        warn!("HTTP connection error: {}", err);
                    }
                });

                sender.send_request(req).boxed()
            }
            #[cfg(feature = "tls")]
            Some(scheme) if scheme == &http::uri::Scheme::HTTPS => {
                let connector = tokio_rustls::TlsConnector::from(self.tls_config.clone());

                let stream = tokio::time::timeout(
                    self.timeout,
                    connector.connect(
                        host.try_into()
                            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad SNI"))?,
                        stream,
                    ),
                )
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tls connect timeout"))?
                .map_err(io::Error::other)?;

                let io = TokioIo::new(stream);
                let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
                    .await
                    .map_err(io::Error::other)?;

                tokio::task::spawn(async move {
                    if let Err(err) = conn.await {
                        warn!("HTTP connection error: {}", err);
                    }
                });

                sender.send_request(req).boxed()
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid url: {uri}: unsupported scheme"),
                ));
            }
        };

        resp.await
            .map_err(|e| io::Error::other(format!("HTTP request failed: {e}")))
    }
}

/// Creates a new HTTP client with the given DNS resolver and optional bootstrap
/// outbounds, that is used by clash to send outgoing HTTP requests.
pub fn new_http_client(
    dns_resolver: ThreadSafeDNSResolver,
    bootstrap_outbounds: Option<Vec<AnyOutboundHandler>>,
) -> io::Result<HttpClient> {
    HttpClient::new(dns_resolver, bootstrap_outbounds, None)
}
