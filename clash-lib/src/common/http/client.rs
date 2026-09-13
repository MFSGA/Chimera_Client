use std::{io, sync::Arc};

use futures::FutureExt;
use hyper_util::rt::TokioIo;
use tracing::{trace, warn};

#[cfg(feature = "tun")]
use crate::app::net::DEFAULT_OUTBOUND_INTERFACE;
use crate::{
    app::dns::ThreadSafeDNSResolver,
    config::internal::proxy::PROXY_DIRECT,
    proxy::{AnyOutboundHandler, direct, utils::OutboundHandlerRegistry},
    session::Session,
};

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
    outbounds: Option<OutboundHandlerRegistry>,
    tls_config: Arc<rustls::ClientConfig>,
    timeout: tokio::time::Duration,
}

fn make_direct_outbound() -> AnyOutboundHandler {
    Arc::new(direct::Handler::new(PROXY_DIRECT))
}

fn tls_server_name(
    host: String,
) -> io::Result<rustls::pki_types::ServerName<'static>> {
    host.clone().try_into().map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid TLS server name {host:?}: {err}"),
        )
    })
}

async fn resolve_http_outbound(
    registry: Option<&OutboundHandlerRegistry>,
    outbound_name: Option<&str>,
) -> io::Result<AnyOutboundHandler> {
    let Some(name) = outbound_name else {
        return Ok(make_direct_outbound());
    };
    if name == PROXY_DIRECT {
        return Ok(make_direct_outbound());
    }

    let registry = registry.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("HTTP outbound \"{name}\" was requested, but no outbound registry is available"),
        )
    })?;
    registry.read().await.get(name).cloned().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("configured HTTP outbound \"{name}\" was not found"),
        )
    })
}

impl HttpClient {
    pub fn new(
        dns_resolver: ThreadSafeDNSResolver,
        bootstrap_outbounds: Option<OutboundHandlerRegistry>,
        timeout: Option<tokio::time::Duration>,
    ) -> io::Result<HttpClient> {
        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(GLOBAL_ROOT_STORE.clone())
            .with_no_client_auth();
        if std::env::var("SSLKEYLOGFILE").is_ok() {
            tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
        }

        Ok(HttpClient {
            dns_resolver,
            outbounds: bootstrap_outbounds,
            tls_config: Arc::new(tls_config),
            timeout: timeout.unwrap_or(tokio::time::Duration::from_secs(10)),
        })
    }

    pub async fn request<T>(
        &self,
        mut req: http::Request<T>,
    ) -> Result<http::Response<hyper::body::Incoming>, std::io::Error>
    where
        T: hyper::body::Body + Send + 'static,
        <T as hyper::body::Body>::Data: Send,
        <T as hyper::body::Body>::Error: std::error::Error + Send + Sync,
    {
        let uri = req.uri().clone();

        let host = uri
            .host()
            .ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("uri must have a host: {uri}"),
            ))?
            .to_owned();
        let port = uri.port_u16().unwrap_or(match uri.scheme_str() {
            None => 80,
            Some(s) => match s {
                "http" => 80,
                "https" => 443,
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("unsupported scheme: {s}"),
                    ));
                }
            },
        });

        if req.headers_mut().get(http::header::HOST).is_none() {
            let host_header = uri
                .host()
                .ok_or(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "uri must have a host",
                ))?
                .parse()
                .map_err(|err| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid HTTP host header for {uri}: {err}"),
                    )
                })?;
            req.headers_mut().insert(http::header::HOST, host_header);
        }

        let outbound_name = req
            .extensions()
            .get::<ClashHTTPClientExt>()
            .and_then(|ext| ext.outbound.clone());
        let outbound =
            resolve_http_outbound(self.outbounds.as_ref(), outbound_name.as_deref())
                .await?;

        trace!(outbound = %outbound.name(), "using outbound");
        #[cfg(feature = "tun")]
        let default_outbound_interface =
            DEFAULT_OUTBOUND_INTERFACE.read().await.clone();
        #[cfg(not(feature = "tun"))]
        let default_outbound_interface = None;
        let sess = Session {
            network: crate::session::Network::Tcp,
            typ: crate::session::Type::Ignore,
            destination: crate::session::SocksAddr::Domain(host.clone(), port),
            iface: default_outbound_interface,
            ..Default::default()
        };
        let stream = tokio::time::timeout(
            self.timeout,
            outbound.connect_stream(&sess, self.dns_resolver.clone()),
        )
        .await?
        .inspect_err(|e| {
            warn!(outbound = outbound.name(), err = ?e, "download via proxy");
        })?;

        let resp = match uri.scheme() {
            Some(scheme) if scheme == &http::uri::Scheme::HTTP => {
                let io = TokioIo::new(stream);
                let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
                    .await
                    .map_err(std::io::Error::other)?;

                tokio::task::spawn(async move {
                    if let Err(err) = conn.await {
                        warn!("HTTP connection error: {}", err);
                    }
                });

                sender.send_request(req).boxed()
            }
            Some(scheme) if scheme == &http::uri::Scheme::HTTPS => {
                let connector =
                    tokio_rustls::TlsConnector::from(self.tls_config.clone());

                let server_name = tls_server_name(host.clone())?;
                let stream = tokio::time::timeout(
                    self.timeout,
                    connector.connect(server_name, stream),
                )
                .await??;

                let io = TokioIo::new(stream);

                let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
                    .await
                    .map_err(std::io::Error::other)?;

                tokio::task::spawn(async move {
                    if let Err(err) = conn.await {
                        warn!("HTTP connection error: {}", err);
                    }
                });

                sender.send_request(req).boxed()
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid url: {uri}: unsupported scheme"),
                ));
            }
        };

        resp.await
            .map_err(|e| std::io::Error::other(format!("HTTP request failed: {e}")))
    }
}

/// Creates a new HTTP client with the given DNS resolver and optional bootstrap
/// outbounds, that is used by clash to send outgoing HTTP requests.
pub fn new_http_client(
    dns_resolver: ThreadSafeDNSResolver,
    bootstrap_outbounds: Option<OutboundHandlerRegistry>,
) -> io::Result<HttpClient> {
    HttpClient::new(dns_resolver, bootstrap_outbounds, None)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn invalid_tls_server_name_returns_error() {
        let uri: http::Uri = "https://-prefixhypheninvalid.com/"
            .parse()
            .expect("URI parser should accept the authority syntax");
        let host = uri.host().expect("URI should expose a host").to_owned();

        let error = tls_server_name(host)
            .expect_err("invalid DNS name must be reported, not panic");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("-prefixhypheninvalid.com"));
    }

    #[tokio::test]
    async fn named_http_outbound_resolves_from_shared_registry() {
        let named =
            Arc::new(direct::Handler::new("PROXY-GROUP")) as AnyOutboundHandler;
        let registry = Arc::new(tokio::sync::RwLock::new(HashMap::from([(
            "PROXY-GROUP".to_owned(),
            named.clone(),
        )])));

        let selected = resolve_http_outbound(Some(&registry), Some("PROXY-GROUP"))
            .await
            .expect("registered outbound should resolve");

        assert!(Arc::ptr_eq(&selected, &named));
    }

    #[tokio::test]
    async fn missing_named_http_outbound_returns_not_found() {
        let registry = Arc::new(tokio::sync::RwLock::new(HashMap::new()));

        let error = resolve_http_outbound(Some(&registry), Some("MISSING"))
            .await
            .expect_err("missing outbound must not silently use DIRECT");

        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(error.to_string().contains("MISSING"));
    }

    #[tokio::test]
    async fn direct_http_outbound_does_not_require_registry() {
        let selected = resolve_http_outbound(None, Some(PROXY_DIRECT))
            .await
            .expect("DIRECT should always be available");

        assert_eq!(selected.name(), PROXY_DIRECT);
    }
}
