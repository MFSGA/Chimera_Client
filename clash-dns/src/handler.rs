#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
use crate::utils::{load_cert_chain, load_priv_key};
use crate::{DNSListenAddr, DnsMessageExchanger, utils::new_io_error};
use async_trait::async_trait;
use hickory_proto::{
    op::{
        Header, HeaderCounts, Message, MessageType, Metadata, OpCode, ResponseCode,
    },
    rr::RecordType,
    serialize::binary::BinDecoder,
};
use hickory_server::{
    Server,
    net::runtime::Time,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    zone_handler::{MessageResponseBuilder, Queries},
};
#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
use rustls::{server::AlwaysResolvesServerRawPublicKeys, sign::CertifiedKey};
#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, error, info, warn};

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
struct CertificateKeyPair {
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
}

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
impl CertificateKeyPair {
    fn into_resolver(
        self,
    ) -> std::io::Result<Arc<dyn rustls::server::ResolvesServerCert>> {
        let provider =
            rustls::crypto::CryptoProvider::get_default().ok_or_else(|| {
                std::io::Error::other("no default crypto provider installed")
            })?;
        let signing_key = provider
            .key_provider
            .load_private_key(self.key)
            .map_err(std::io::Error::other)?;
        Ok(Arc::new(AlwaysResolvesServerRawPublicKeys::new(Arc::new(
            CertifiedKey::new(self.certs, signing_key),
        ))))
    }
}

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
fn load_dns_server_cert(
    cert: Option<String>,
    key: Option<String>,
    cwd: &std::path::Path,
) -> std::io::Result<Arc<dyn rustls::server::ResolvesServerCert>> {
    let (Some(cert), Some(key)) = (cert, key) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "encrypted DNS listeners require both ca-cert and ca-key",
        ));
    };
    let cert_path = cwd.join(cert);
    let key_path = cwd.join(key);
    let certs = load_cert_chain(&cert_path)?;
    if certs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "certificate file {} contains no certificates",
                cert_path.display()
            ),
        ));
    }
    CertificateKeyPair {
        certs,
        key: load_priv_key(&key_path)?,
    }
    .into_resolver()
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
        response_handle: &mut H,
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

        if request.queries.len() > 1 {
            let mut decoder = BinDecoder::new(&[]);
            let empty_queries = Queries::read(&mut decoder, 0).map_err(|e| {
                DNSError::QueryFailed(format!(
                    "failed to build FORMERR response: {e}"
                ))
            })?;
            let response_edns = request.edns.as_ref().map(|request_edns| {
                let mut response_edns = hickory_proto::op::Edns::new();
                response_edns.set_max_payload(request_edns.max_payload());
                response_edns.set_dnssec_ok(request_edns.flags().dnssec_ok);
                response_edns
            });
            let response =
                MessageResponseBuilder::new(&empty_queries, response_edns.as_ref())
                    .error_msg(&request.metadata, ResponseCode::FormErr);
            return response_handle
                .send_response(response)
                .await
                .map_err(|e| DNSError::QueryFailed(e.to_string()));
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
        mut response_handle: R,
    ) -> ResponseInfo {
        debug!(
            "got dns request [{}][{:?}][{:?}] from {}",
            request.protocol(),
            request.queries.queries().first().map(|x| x.query_type()),
            request.queries.queries().first().map(|x| x.name()),
            request.src()
        );

        match self.handle(request, &mut response_handle).await {
            Ok(response_info) => response_info,
            Err(e) => {
                debug!("dns request error: {}", e);
                let mut metadata =
                    Metadata::response_from_request(&request.metadata);
                metadata.response_code = ResponseCode::ServFail;
                let fallback_response_info = Header {
                    metadata,
                    counts: HeaderCounts::default(),
                }
                .into();
                let response = MessageResponseBuilder::from_message_request(request)
                    .build_no_records(metadata);
                match response_handle.send_response(response).await {
                    Ok(response_info) => response_info,
                    Err(send_error) => {
                        error!("failed to send DNS SERVFAIL response: {send_error}");
                        fallback_response_info
                    }
                }
            }
        }
    }
}

static DEFAULT_DNS_SERVER_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn get_dns_listener<X>(
    listen: DNSListenAddr,
    exchanger: X,
    #[cfg_attr(
        not(any(feature = "aws-lc-rs", feature = "ring")),
        allow(unused_variables)
    )]
    cwd: &std::path::Path,
) -> Option<futures::future::BoxFuture<'static, Result<(), DNSError>>>
where
    X: DnsMessageExchanger + Sync + Send + Unpin + 'static,
{
    let handler = DnsHandler { exchanger };
    let mut s = Server::new(handler);

    let mut has_server = false;
    let mut listener_failed = false;

    if let Some(addr) = listen.udp {
        let started = UdpSocket::bind(addr)
            .await
            .map(|x| {
                info!("UDP dns server listening on: {}", addr);
                s.register_socket(x);
            })
            .inspect_err(|x| {
                error!("failed to listen UDP DNS server on {}: {}", addr, x);
            })
            .is_ok();
        has_server |= started;
        listener_failed |= !started;
    }
    if let Some(addr) = listen.tcp {
        let started = TcpListener::bind(addr)
            .await
            .map(|x| {
                info!("TCP dns server listening on: {}", addr);
                s.register_listener(x, DEFAULT_DNS_SERVER_TIMEOUT, 4096);
            })
            .inspect_err(|x| {
                error!("failed to listen TCP DNS server on {}: {}", addr, x);
            })
            .is_ok();
        has_server |= started;
        listener_failed |= !started;
    }
    if let Some(c) = listen.doh {
        #[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
        {
            let started = TcpListener::bind(c.addr)
                .await
                .and_then(|x| {
                    if let (Some(k), Some(c)) = (&c.ca_key, &c.ca_cert) {
                        debug!(
                            "using custom key and cert for DoH: {:?}/{:?}",
                            cwd.join(k),
                            cwd.join(c)
                        );
                    }

                    let server_cert =
                        load_dns_server_cert(c.ca_cert, c.ca_key, cwd)?;
                    s.register_https_listener(
                        x,
                        DEFAULT_DNS_SERVER_TIMEOUT,
                        server_cert,
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
            has_server |= started;
            listener_failed |= !started;
        }
        #[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
        {
            warn!(
                "DoH listener {} ignored because chimera-dns was built without aws-lc-rs or ring",
                c.addr
            );
            listener_failed = true;
        }
    }
    if let Some(c) = listen.dot {
        #[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
        {
            let started = TcpListener::bind(c.addr)
                .await
                .and_then(|x| {
                    if let (Some(k), Some(c)) = (&c.ca_key, &c.ca_cert) {
                        debug!(
                            "using custom key and cert for DoT: {:?}/{:?}",
                            cwd.join(k),
                            cwd.join(c)
                        );
                    }

                    let server_cert =
                        load_dns_server_cert(c.ca_cert, c.ca_key, cwd)?;
                    s.register_tls_listener(
                        x,
                        DEFAULT_DNS_SERVER_TIMEOUT,
                        server_cert,
                    )?;
                    info!("DoT dns server listening on: {}", c.addr);
                    Ok(())
                })
                .inspect_err(|x| {
                    error!("failed to listen DoT DNS server on {}: {}", c.addr, x);
                })
                .is_ok();
            has_server |= started;
            listener_failed |= !started;
        }
        #[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
        {
            warn!(
                "DoT listener {} ignored because chimera-dns was built without aws-lc-rs or ring",
                c.addr
            );
            listener_failed = true;
        }
    }

    if let Some(c) = listen.doh3 {
        #[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
        {
            let started = UdpSocket::bind(c.addr)
                .await
                .and_then(|x| {
                    if let (Some(k), Some(c)) = (&c.ca_key, &c.ca_cert) {
                        debug!(
                            "using custom key and cert for DoH3: {:?}/{:?}",
                            cwd.join(k),
                            cwd.join(c)
                        );
                    }

                    let server_cert =
                        load_dns_server_cert(c.ca_cert, c.ca_key, cwd)?;
                    s.register_h3_listener(
                        x,
                        DEFAULT_DNS_SERVER_TIMEOUT,
                        server_cert,
                        c.hostname,
                    )?;
                    info!("DoH3 dns server listening on: {}", c.addr);
                    Ok(())
                })
                .inspect_err(|x| {
                    error!("failed to listen DoH3 DNS server on {}: {}", c.addr, x);
                })
                .is_ok();
            has_server |= started;
            listener_failed |= !started;
        }
        #[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
        {
            warn!(
                "DoH3 listener {} ignored because chimera-dns was built without aws-lc-rs or ring",
                c.addr
            );
            listener_failed = true;
        }
    }

    if !has_server || listener_failed {
        error!(
            has_server,
            listener_failed,
            "DNS listener startup failed; every configured listener must start"
        );
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

#[cfg(test)]
mod plain_tests {
    use crate::{DNSListenAddr, MockDnsMessageExchanger};
    use futures::FutureExt;
    use hickory_net::{
        client::{Client, ClientHandle},
        runtime::TokioRuntimeProvider,
        tcp::TcpClientStream,
        udp::UdpClientStream,
    };
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query, ResponseCode},
        rr::{DNSClass, Name, RData, RecordType},
    };
    use std::time::Duration;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream, UdpSocket},
        task::JoinHandle,
    };

    async fn send_query(
        client: &mut Client<TokioRuntimeProvider>,
    ) -> anyhow::Result<()> {
        let name = Name::from_ascii("www.example.com.").unwrap();
        let response = client.query(name, DNSClass::IN, RecordType::A).await?;
        let answers = &response.answers;
        if let RData::A(ip) = &answers[0].data {
            assert_eq!(ip.0, std::net::Ipv4Addr::new(93, 184, 215, 14));
        } else {
            unreachable!("unexpected result")
        }
        Ok(())
    }

    #[tokio::test]
    async fn udp_and_tcp_listeners_work_without_crypto_features()
    -> anyhow::Result<()> {
        let mut mock_exchanger = MockDnsMessageExchanger::new();
        mock_exchanger.expect_ipv6().returning(|| false);
        mock_exchanger.expect_exchange().returning(|_| {
            async {
                let mut message = hickory_proto::op::Message::response(
                    0,
                    hickory_proto::op::OpCode::Query,
                );
                message.add_answer(hickory_proto::rr::Record::from_rdata(
                    "www.example.com".parse().unwrap(),
                    60,
                    hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(
                        std::net::Ipv4Addr::new(93, 184, 215, 14),
                    )),
                ));
                Ok(message)
            }
            .boxed()
        });

        let udp_sock = UdpSocket::bind("127.0.0.1:0").await?;
        let udp_addr = udp_sock.local_addr()?;
        drop(udp_sock);

        let tcp_sock = TcpListener::bind("127.0.0.1:0").await?;
        let tcp_addr = tcp_sock.local_addr()?;
        drop(tcp_sock);

        let cfg = DNSListenAddr {
            udp: Some(udp_addr),
            tcp: Some(tcp_addr),
            ..Default::default()
        };

        let listener =
            super::get_dns_listener(cfg, mock_exchanger, std::path::Path::new("."))
                .await;
        assert!(listener.is_some());
        let handle: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
            listener.unwrap().await?;
            Ok(())
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let stream =
            UdpClientStream::builder(udp_addr, TokioRuntimeProvider::new()).build();
        let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(stream);
        tokio::spawn(bg);
        send_query(&mut client).await?;

        let (stream_future, sender) =
            TcpClientStream::new(tcp_addr, None, None, TokioRuntimeProvider::new());
        let stream = stream_future.await?;
        let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
        tokio::spawn(bg);
        send_query(&mut client).await?;

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn upstream_failure_sends_servfail_over_udp_and_tcp() -> anyhow::Result<()>
    {
        let mut mock_exchanger = MockDnsMessageExchanger::new();
        mock_exchanger.expect_ipv6().returning(|| false);
        mock_exchanger.expect_exchange().times(2).returning(|_| {
            async {
                Err(crate::DNSError::QueryFailed(
                    "simulated upstream failure".to_string(),
                ))
            }
            .boxed()
        });

        let udp_sock = UdpSocket::bind("127.0.0.1:0").await?;
        let udp_addr = udp_sock.local_addr()?;
        drop(udp_sock);

        let tcp_sock = TcpListener::bind("127.0.0.1:0").await?;
        let tcp_addr = tcp_sock.local_addr()?;
        drop(tcp_sock);

        let listener = super::get_dns_listener(
            DNSListenAddr {
                udp: Some(udp_addr),
                tcp: Some(tcp_addr),
                ..Default::default()
            },
            mock_exchanger,
            std::path::Path::new("."),
        )
        .await
        .expect("at least one listener should start");
        let handle: JoinHandle<Result<(), crate::DNSError>> = tokio::spawn(listener);
        tokio::time::sleep(Duration::from_millis(100)).await;

        let request_id = 0x1234;
        let mut query = Message::new(request_id, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(
            Name::from_ascii("failure.example.")?,
            RecordType::A,
        ));
        let query = query.to_vec()?;

        let udp_client = UdpSocket::bind("127.0.0.1:0").await?;
        udp_client.send_to(&query, udp_addr).await?;
        let mut udp_response = [0; 512];
        let (udp_len, _) = tokio::time::timeout(
            Duration::from_secs(2),
            udp_client.recv_from(&mut udp_response),
        )
        .await??;
        let udp_response = Message::from_vec(&udp_response[..udp_len])?;
        assert_eq!(udp_response.metadata.id, request_id);
        assert_eq!(udp_response.metadata.response_code, ResponseCode::ServFail);

        let mut tcp_client = TcpStream::connect(tcp_addr).await?;
        tcp_client.write_u16(query.len().try_into()?).await?;
        tcp_client.write_all(&query).await?;
        let tcp_response = tokio::time::timeout(Duration::from_secs(2), async {
            let response_len = tcp_client.read_u16().await?;
            let mut response = vec![0; usize::from(response_len)];
            tcp_client.read_exact(&mut response).await?;
            Ok::<_, std::io::Error>(response)
        })
        .await??;
        let tcp_response = Message::from_vec(&tcp_response)?;
        assert_eq!(tcp_response.metadata.id, request_id);
        assert_eq!(tcp_response.metadata.response_code, ResponseCode::ServFail);

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn multi_question_queries_return_formerr_over_udp_and_tcp()
    -> anyhow::Result<()> {
        let mut mock_exchanger = MockDnsMessageExchanger::new();
        mock_exchanger.expect_exchange().never();

        let udp_sock = UdpSocket::bind("127.0.0.1:0").await?;
        let udp_addr = udp_sock.local_addr()?;
        drop(udp_sock);

        let tcp_sock = TcpListener::bind("127.0.0.1:0").await?;
        let tcp_addr = tcp_sock.local_addr()?;
        drop(tcp_sock);

        let listener = super::get_dns_listener(
            DNSListenAddr {
                udp: Some(udp_addr),
                tcp: Some(tcp_addr),
                ..Default::default()
            },
            mock_exchanger,
            std::path::Path::new("."),
        )
        .await
        .expect("at least one listener should start");
        let handle: JoinHandle<Result<(), crate::DNSError>> = tokio::spawn(listener);
        tokio::time::sleep(Duration::from_millis(100)).await;

        let request_id = 0x4321;
        let mut query = Message::new(request_id, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(
            Name::from_ascii("first.example.")?,
            RecordType::A,
        ));
        query.add_query(Query::query(
            Name::from_ascii("second.example.")?,
            RecordType::AAAA,
        ));
        let mut edns = hickory_proto::op::Edns::new();
        edns.set_max_payload(1232).set_dnssec_ok(true);
        query.set_edns(edns);
        let query = query.to_vec()?;

        let udp_client = UdpSocket::bind("127.0.0.1:0").await?;
        udp_client.send_to(&query, udp_addr).await?;
        let mut udp_response = [0; 512];
        let (udp_len, _) = tokio::time::timeout(
            Duration::from_secs(2),
            udp_client.recv_from(&mut udp_response),
        )
        .await??;
        let udp_response = Message::from_vec(&udp_response[..udp_len])?;
        assert_eq!(udp_response.metadata.id, request_id);
        assert_eq!(udp_response.metadata.response_code, ResponseCode::FormErr);
        assert!(udp_response.queries.is_empty());
        let udp_edns = udp_response.edns.as_ref().expect("EDNS should be echoed");
        assert_eq!(udp_edns.max_payload(), 1232);
        assert!(udp_edns.flags().dnssec_ok);

        let mut tcp_client = TcpStream::connect(tcp_addr).await?;
        tcp_client.write_u16(query.len().try_into()?).await?;
        tcp_client.write_all(&query).await?;
        let tcp_response = tokio::time::timeout(Duration::from_secs(2), async {
            let response_len = tcp_client.read_u16().await?;
            let mut response = vec![0; usize::from(response_len)];
            tcp_client.read_exact(&mut response).await?;
            Ok::<_, std::io::Error>(response)
        })
        .await??;
        let tcp_response = Message::from_vec(&tcp_response)?;
        assert_eq!(tcp_response.metadata.id, request_id);
        assert_eq!(tcp_response.metadata.response_code, ResponseCode::FormErr);
        assert!(tcp_response.queries.is_empty());
        let tcp_edns = tcp_response.edns.as_ref().expect("EDNS should be echoed");
        assert_eq!(tcp_edns.max_payload(), 1232);
        assert!(tcp_edns.flags().dnssec_ok);

        handle.abort();
        Ok(())
    }
}

#[cfg(all(test, any(feature = "aws-lc-rs", feature = "ring")))]
mod tests {
    use crate::{
        DNSListenAddr, DoH3Config, DoHConfig, DoTConfig, MockDnsMessageExchanger,
        tests::setup_default_crypto_provider,
        tls::{self, global_root_store},
    };
    use futures::FutureExt;
    use hickory_net::{
        client::{Client, ClientHandle},
        h2::HttpsClientStream,
        h3::H3ClientStream,
        runtime::TokioRuntimeProvider,
        tcp::TcpClientStream,
        tls::tls_client_connect,
        udp::UdpClientStream,
    };
    use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
    use rustls::{ClientConfig, pki_types::ServerName};
    use std::{sync::Arc, time::Duration};
    use tokio::net::{TcpListener, UdpSocket};

    async fn send_query(
        client: &mut Client<TokioRuntimeProvider>,
    ) -> anyhow::Result<()> {
        let name = Name::from_ascii("www.example.com.").unwrap();

        let mut retries = 3;
        let response = loop {
            match client
                .query(name.clone(), DNSClass::IN, RecordType::A)
                .await
            {
                Ok(v) => break v,
                Err(e) => {
                    retries -= 1;
                    if retries == 0 {
                        anyhow::bail!(e)
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        };

        let answers = &response.answers;
        if let RData::A(ip) = &answers[0].data {
            assert_eq!(ip.0, std::net::Ipv4Addr::new(93, 184, 215, 14));
        } else {
            unreachable!("unexpected result")
        }
        Ok(())
    }

    #[tokio::test]
    async fn encrypted_listener_without_certificate_is_rejected() {
        setup_default_crypto_provider();
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        drop(socket);

        let listener = super::get_dns_listener(
            DNSListenAddr {
                doh: Some(DoHConfig {
                    addr,
                    ca_cert: None,
                    ca_key: None,
                    hostname: Some("dns.example.com".to_owned()),
                }),
                ..Default::default()
            },
            MockDnsMessageExchanger::new(),
            std::path::Path::new("."),
        )
        .await;

        assert!(listener.is_none());
    }

    #[tokio::test]
    async fn encrypted_listener_rejects_invalid_certificate_material() {
        setup_default_crypto_provider();
        let test_resources =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/resources");
        let test_cert = test_resources
            .join("test.cert")
            .to_string_lossy()
            .to_string();
        let test_key = test_resources
            .join("test.key")
            .to_string_lossy()
            .to_string();

        for (cert, key) in [
            (test_key.as_str(), test_key.as_str()),
            (test_cert.as_str(), test_cert.as_str()),
        ] {
            let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = socket.local_addr().unwrap();
            drop(socket);

            let listener = super::get_dns_listener(
                DNSListenAddr {
                    doh: Some(DoHConfig {
                        addr,
                        ca_cert: Some(cert.to_owned()),
                        ca_key: Some(key.to_owned()),
                        hostname: Some("dns.example.com".to_owned()),
                    }),
                    ..Default::default()
                },
                MockDnsMessageExchanger::new(),
                std::path::Path::new("."),
            )
            .await;

            assert!(listener.is_none());
        }
    }

    #[tokio::test]
    async fn test_multiple_dns_server() -> anyhow::Result<()> {
        setup_default_crypto_provider();
        let _ = env_logger::try_init();

        let mut mock_exchanger = MockDnsMessageExchanger::new();
        mock_exchanger.expect_ipv6().returning(|| false);
        mock_exchanger.expect_exchange().returning(|_| {
            async {
                let mut m = hickory_proto::op::Message::response(
                    0,
                    hickory_proto::op::OpCode::Query,
                );
                m.add_answer(hickory_proto::rr::Record::from_rdata(
                    "www.example.com".parse().unwrap(),
                    60,
                    hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(
                        std::net::Ipv4Addr::new(93, 184, 215, 14),
                    )),
                ));
                Ok(m)
            }
            .boxed()
        });

        let udp_sock = UdpSocket::bind("127.0.0.1:0").await?;
        let udp_addr = udp_sock.local_addr()?;
        drop(udp_sock);

        let tcp_sock = TcpListener::bind("127.0.0.1:0").await?;
        let tcp_addr = tcp_sock.local_addr()?;
        drop(tcp_sock);

        let dot_sock = TcpListener::bind("127.0.0.1:0").await?;
        let dot_addr = dot_sock.local_addr()?;
        drop(dot_sock);

        let doh_sock = TcpListener::bind("127.0.0.1:0").await?;
        let doh_addr = doh_sock.local_addr()?;
        drop(doh_sock);

        let doh3_sock = UdpSocket::bind("127.0.0.1:0").await?;
        let doh3_addr = doh3_sock.local_addr()?;
        drop(doh3_sock);

        let test_resources =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/resources");
        let test_cert = test_resources
            .join("test.cert")
            .to_string_lossy()
            .to_string();
        let test_key = test_resources
            .join("test.key")
            .to_string_lossy()
            .to_string();

        let cfg = DNSListenAddr {
            udp: Some(udp_addr),
            tcp: Some(tcp_addr),
            dot: Some(DoTConfig {
                addr: dot_addr,
                ca_key: Some(test_key.clone()),
                ca_cert: Some(test_cert.clone()),
            }),
            doh: Some(DoHConfig {
                addr: doh_addr,
                hostname: Some("dns.example.com".to_string()),
                ca_key: Some(test_key.clone()),
                ca_cert: Some(test_cert.clone()),
            }),
            doh3: Some(DoH3Config {
                addr: doh3_addr,
                hostname: Some("dns.example.com".to_string()),
                ca_key: Some(test_key),
                ca_cert: Some(test_cert),
            }),
        };

        let listener =
            super::get_dns_listener(cfg, mock_exchanger, std::path::Path::new("."))
                .await;
        assert!(listener.is_some());
        std::mem::drop(tokio::spawn(async move {
            listener.unwrap().await?;
            Ok::<(), anyhow::Error>(())
        }));

        tokio::time::sleep(Duration::from_millis(100)).await;

        let stream =
            UdpClientStream::builder(udp_addr, TokioRuntimeProvider::new()).build();
        let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(stream);
        tokio::spawn(bg);
        send_query(&mut client).await?;

        let (stream_future, sender) =
            TcpClientStream::new(tcp_addr, None, None, TokioRuntimeProvider::new());
        let stream = stream_future.await?;
        let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
        tokio::spawn(bg);
        send_query(&mut client).await?;

        let mut tls_config = ClientConfig::builder()
            .with_root_certificates(global_root_store())
            .with_no_client_auth();
        tls_config.alpn_protocols = vec!["dot".into()];
        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(tls::DummyTlsVerifier::new()));

        let server_name = ServerName::try_from("dns.example.com").unwrap();
        let (stream_future, sender) = tls_client_connect(
            dot_addr,
            server_name,
            Arc::new(tls_config),
            TokioRuntimeProvider::new(),
        );
        let stream = stream_future.await?;
        let (mut client, bg) = Client::<TokioRuntimeProvider>::with_timeout(
            stream,
            sender,
            Duration::from_secs(5),
        );
        tokio::spawn(bg);
        send_query(&mut client).await?;

        let mut tls_config = ClientConfig::builder()
            .with_root_certificates(global_root_store())
            .with_no_client_auth();
        tls_config.alpn_protocols = vec!["h2".into()];
        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(tls::DummyTlsVerifier::new()));

        let stream = HttpsClientStream::builder(
            Arc::new(tls_config),
            TokioRuntimeProvider::new(),
        )
        .build(doh_addr, "dns.example.com".into(), "/dns-query".into())
        .await?;
        let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(stream);
        tokio::spawn(bg);
        send_query(&mut client).await?;

        let mut tls_config = ClientConfig::builder()
            .with_root_certificates(global_root_store())
            .with_no_client_auth();
        tls_config.alpn_protocols = vec!["h3".into()];
        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(tls::DummyTlsVerifier::new()));

        let stream = H3ClientStream::builder()
            .crypto_config(tls_config)
            .build(doh3_addr, "dns.example.com".into(), "/dns-query".into())
            .await?;
        let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(stream);
        tokio::spawn(bg);
        send_query(&mut client).await?;

        Ok(())
    }
}
