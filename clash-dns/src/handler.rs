use crate::{
    DNSListenAddr, DnsMessageExchanger,
    utils::{
        load_cert_chain, load_default_cert, load_default_key, load_priv_key,
        new_io_error,
    },
};
use async_trait::async_trait;
use hickory_proto::{
    op::{
        Header, HeaderCounts, Message, MessageType, Metadata, OpCode, ResponseCode,
    },
    rr::RecordType,
};
use hickory_server::{
    Server,
    net::runtime::Time,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    zone_handler::MessageResponseBuilder,
};
use rustls::{server::AlwaysResolvesServerRawPublicKeys, sign::CertifiedKey};
use std::{sync::Arc, time::Duration};
use thiserror::Error;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, error, info, warn};

struct CertificateKeyPair {
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
}

impl From<CertificateKeyPair> for Arc<dyn rustls::server::ResolvesServerCert> {
    fn from(pair: CertificateKeyPair) -> Self {
        Arc::new(AlwaysResolvesServerRawPublicKeys::new(Arc::new(
            CertifiedKey::new(
                pair.certs,
                rustls::crypto::CryptoProvider::get_default()
                    .expect("no default crypto provider installed")
                    .key_provider
                    .load_private_key(pair.key)
                    .expect("unsupported private key type"),
            ),
        )))
    }
}

struct DnsListener<H: RequestHandler> {
    server: Server<H>,
}

struct DnsHandler<X> {
    exchanger: X,
}

#[derive(Error, Debug)]
pub enum DNSError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("invalid OP code: {0}")]
    InvalidOpQuery(String),
    #[error("query failed: {0}")]
    QueryFailed(String),
}

impl<X> DnsHandler<X>
where
    X: DnsMessageExchanger,
{
    async fn handle<H: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: H,
    ) -> Result<ResponseInfo, DNSError> {
        if request.metadata.op_code != OpCode::Query {
            return Err(DNSError::InvalidOpQuery(format!(
                "invalid OP code: {}",
                request.metadata.op_code
            )));
        }

        if request.metadata.message_type != MessageType::Query {
            return Err(DNSError::InvalidOpQuery(format!(
                "invalid message type: {}",
                request.metadata.message_type
            )));
        }

        let mut metadata = Metadata::response_from_request(&request.metadata);

        let query = request
            .queries
            .queries()
            .first()
            .ok_or(DNSError::QueryFailed("no query".to_string()))?;

        if query.query_type() == RecordType::AAAA && !self.exchanger.ipv6() {
            metadata.authoritative = true;

            let resp = MessageResponseBuilder::from_message_request(request)
                .build_no_records(metadata);
            return response_handle
                .send_response(resp)
                .await
                .map_err(|e| DNSError::QueryFailed(e.to_string()));
        }

        let mut m = Message::new(
            request.metadata.id,
            request.metadata.message_type,
            request.metadata.op_code,
        );
        m.metadata.recursion_desired = request.metadata.recursion_desired;
        m.metadata.checking_disabled = request.metadata.checking_disabled;
        m.add_query(query.original().clone());
        m.add_additionals(request.additionals.iter().cloned());
        m.add_authorities(request.authorities.iter().cloned());
        if let Some(edns) = &request.edns {
            m.set_edns(edns.clone());
        }

        match self.exchanger.exchange(&m).await {
            Ok(m) => {
                metadata.recursion_available = m.metadata.recursion_available;
                metadata.response_code = m.metadata.response_code;
                metadata.authoritative = m.metadata.authoritative;
                metadata.truncation = m.metadata.truncation;
                metadata.authentic_data = m.metadata.authentic_data;
                metadata.checking_disabled = m.metadata.checking_disabled;

                let resp_edns = if request.edns.is_some() {
                    m.edns.clone()
                } else {
                    None
                };

                let rv = MessageResponseBuilder::new(
                    &request.queries,
                    resp_edns.as_ref(),
                )
                .build(
                    metadata,
                    m.answers.iter(),
                    m.authorities.iter(),
                    std::iter::empty(),
                    m.additionals.iter(),
                );

                debug!(
                    "answering dns query {} with answer {:?}",
                    query.name(),
                    &m.answers,
                );

                Ok(response_handle
                    .send_response(rv)
                    .await
                    .map_err(|e| DNSError::QueryFailed(e.to_string()))?)
            }
            Err(e) => {
                debug!("dns resolve error: {}", e);
                Err(DNSError::QueryFailed(e.to_string()))
            }
        }
    }
}

#[async_trait]
impl<X> RequestHandler for DnsHandler<X>
where
    X: DnsMessageExchanger + Unpin + Send + Sync + 'static,
{
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        debug!(
            "got dns request [{}][{:?}][{:?}] from {}",
            request.protocol(),
            request.queries.queries().first().map(|x| x.query_type()),
            request.queries.queries().first().map(|x| x.name()),
            request.src()
        );

        self.handle(request, response_handle)
            .await
            .unwrap_or_else(|e| {
                debug!("dns request error: {}", e);
                let mut metadata =
                    Metadata::response_from_request(&request.metadata);
                metadata.response_code = ResponseCode::ServFail;
                Header {
                    metadata,
                    counts: HeaderCounts::default(),
                }
                .into()
            })
    }
}

static DEFAULT_DNS_SERVER_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn get_dns_listener<X>(
    listen: DNSListenAddr,
    exchanger: X,
    cwd: &std::path::Path,
) -> Option<futures::future::BoxFuture<'static, Result<(), DNSError>>>
where
    X: DnsMessageExchanger + Sync + Send + Unpin + 'static,
{
    let handler = DnsHandler { exchanger };
    let mut s = Server::new(handler);

    let mut has_server = false;

    if let Some(addr) = listen.udp {
        has_server = UdpSocket::bind(addr)
            .await
            .map(|x| {
                info!("UDP dns server listening on: {}", addr);
                s.register_socket(x);
            })
            .inspect_err(|x| {
                error!("failed to listen UDP DNS server on {}: {}", addr, x);
            })
            .is_ok();
    }
    if let Some(addr) = listen.tcp {
        has_server |= TcpListener::bind(addr)
            .await
            .map(|x| {
                info!("TCP dns server listening on: {}", addr);
                s.register_listener(x, DEFAULT_DNS_SERVER_TIMEOUT, 4096);
            })
            .inspect_err(|x| {
                error!("failed to listen TCP DNS server on {}: {}", addr, x);
            })
            .is_ok();
    }
    if let Some(c) = listen.doh {
        has_server |= TcpListener::bind(c.addr)
            .await
            .and_then(|x| {
                if let (Some(k), Some(c)) = (&c.ca_key, &c.ca_cert) {
                    debug!(
                        "using custom key and cert for DoH: {:?}/{:?}",
                        cwd.join(k),
                        cwd.join(c)
                    );
                }

                let server_key = c
                    .ca_key
                    .map(|x| load_priv_key(&cwd.join(x)))
                    .transpose()?
                    .unwrap_or(load_default_key());
                let server_cert = c
                    .ca_cert
                    .map(|x| load_cert_chain(&cwd.join(x)))
                    .transpose()?
                    .unwrap_or(load_default_cert());
                s.register_https_listener(
                    x,
                    DEFAULT_DNS_SERVER_TIMEOUT,
                    CertificateKeyPair {
                        certs: server_cert,
                        key: server_key,
                    }
                    .into(),
                    c.hostname,
                    "/dns-query".to_string(),
                )?;
                info!("DoH server listening on: {}", c.addr);
                Ok(())
            })
            .inspect_err(|x| {
                error!("failed to listen DoH server on {}: {}", c.addr, x);
            })
            .is_ok();
    }
    if let Some(c) = listen.dot {
        has_server |= TcpListener::bind(c.addr)
            .await
            .and_then(|x| {
                if let (Some(k), Some(c)) = (&c.ca_key, &c.ca_cert) {
                    debug!(
                        "using custom key and cert for DoT: {:?}/{:?}",
                        cwd.join(k),
                        cwd.join(c)
                    );
                }

                let server_key = c
                    .ca_key
                    .map(|x| load_priv_key(&cwd.join(x)))
                    .transpose()?
                    .unwrap_or(load_default_key());
                let server_cert = c
                    .ca_cert
                    .map(|x| load_cert_chain(&cwd.join(x)))
                    .transpose()?
                    .unwrap_or(load_default_cert());
                s.register_tls_listener(
                    x,
                    DEFAULT_DNS_SERVER_TIMEOUT,
                    CertificateKeyPair {
                        certs: server_cert,
                        key: server_key,
                    }
                    .into(),
                )?;
                info!("DoT dns server listening on: {}", c.addr);
                Ok(())
            })
            .inspect_err(|x| {
                error!("failed to listen DoT DNS server on {}: {}", c.addr, x);
            })
            .is_ok();
    }

    if let Some(c) = listen.doh3 {
        has_server |= UdpSocket::bind(c.addr)
            .await
            .and_then(|x| {
                if let (Some(k), Some(c)) = (&c.ca_key, &c.ca_cert) {
                    debug!(
                        "using custom key and cert for DoH3: {:?}/{:?}",
                        cwd.join(k),
                        cwd.join(c)
                    );
                }

                let server_key = c
                    .ca_key
                    .map(|x| load_priv_key(&cwd.join(x)))
                    .transpose()?
                    .unwrap_or(load_default_key());
                let server_cert = c
                    .ca_cert
                    .map(|x| load_cert_chain(&cwd.join(x)))
                    .transpose()?
                    .unwrap_or(load_default_cert());
                s.register_h3_listener(
                    x,
                    DEFAULT_DNS_SERVER_TIMEOUT,
                    CertificateKeyPair {
                        certs: server_cert,
                        key: server_key,
                    }
                    .into(),
                    c.hostname,
                )?;
                info!("DoT3 dns server listening on: {}", c.addr);
                Ok(())
            })
            .inspect_err(|x| {
                error!("failed to listen DoH3 DNS server on {}: {}", c.addr, x);
            })
            .is_ok();
    }

    if !has_server {
        return None;
    }

    let mut l = DnsListener { server: s };

    Some(Box::pin(async move {
        info!("starting DNS server");
        l.server.block_until_done().await.map_err(|x| {
            warn!("dns server error: {}", x);
            DNSError::Io(new_io_error(format!("dns server error: {x}")))
        })
    }))
}
