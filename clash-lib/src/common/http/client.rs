use std::{collections::HashMap, io, sync::Arc};

use crate::{
    app::dns::ThreadSafeDNSResolver, common::tls::GLOBAL_ROOT_STORE, proxy::AnyOutboundHandler,
};

/* #[derive(Clone, Debug)]
pub struct ClashHTTPClientExt {
    pub outbound: Option<String>,
}
 */

/// A simple HTTP client that can be used to make HTTP requests.
/// Not performant for lack of connection pooling, but useful for simple tasks.
#[derive(Clone)]
pub struct HttpClient {
    dns_resolver: ThreadSafeDNSResolver,
    outbounds: Option<HashMap<String, AnyOutboundHandler>>,
    tls_config: Arc<rustls::ClientConfig>,
    timeout: tokio::time::Duration,
}

impl HttpClient {
    pub fn new(
        dns_resolver: ThreadSafeDNSResolver,
        bootstrap_outbounds: Option<Vec<AnyOutboundHandler>>,
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
            outbounds: bootstrap_outbounds.map(|obs| {
                let mut map = HashMap::new();
                for handler in obs {
                    map.insert(handler.name().to_owned(), handler);
                }
                map
            }),
            tls_config: Arc::new(tls_config),
            timeout: timeout.unwrap_or(tokio::time::Duration::from_secs(10)),
        })
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
