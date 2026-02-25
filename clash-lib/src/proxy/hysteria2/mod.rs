mod codec;
mod congestion;
mod salamander;
mod udp_hop;

use std::{
    fmt::{Debug, Formatter},
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    num::ParseIntError,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use anyhow::anyhow;
use bytes::Bytes;
use codec::Hy2TcpCodec;
use congestion::{Brutal, DynCongestion, DynController};
use futures::{SinkExt, StreamExt};
use h3::client::SendRequest;
use h3_quinn::OpenStreams;
use quinn::{
    ClientConfig, Connection, EndpointConfig, TokioRuntime, crypto::rustls::QuicClientConfig,
};
use quinn_proto::TransportConfig;
use rustls::ClientConfig as RustlsClientConfig;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Mutex,
};
use tracing::{debug, warn};

use crate::{
    app::{
        dispatcher::{BoxedChainedStream, ChainedStream, ChainedStreamWrapper},
        dns::ThreadSafeDNSResolver,
    },
    common::tls::DefaultTlsVerifier,
    proxy::{
        DialWithConnector, OutboundHandler, OutboundType, converters::hysteria2::PortGenerator,
    },
    session::{Session, SocksAddr},
};

#[derive(Clone)]
pub struct SalamanderObfs {
    pub key: Vec<u8>,
}

#[derive(Clone)]
pub enum Obfs {
    Salamander(SalamanderObfs),
}

#[derive(Clone)]
pub struct HystOption {
    pub name: String,
    pub addr: SocksAddr,
    pub ports: Option<PortGenerator>,
    pub sni: Option<String>,
    pub password: String,
    pub obfs: Option<Obfs>,
    pub skip_cert_verify: bool,
    pub alpn: Vec<String>,
    pub fingerprint: Option<String>,
    pub disable_mtu_discovery: bool,
    pub ca: Option<String>,
    pub ca_str: Option<String>,
    pub up_down: Option<(u64, u64)>,
    pub cwnd: Option<u64>,
    pub udp_mtu: Option<u32>,
}

#[derive(Debug, Copy, Clone)]
enum CcRx {
    Auto,
    Fixed(u64),
}

impl std::str::FromStr for CcRx {
    type Err = ParseIntError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.eq_ignore_ascii_case("auto") {
            Ok(Self::Auto)
        } else {
            Ok(Self::Fixed(value.parse::<u64>()?))
        }
    }
}

pub struct Handler {
    opts: HystOption,
    ep_config: EndpointConfig,
    client_config: ClientConfig,
    conn: Mutex<Option<Arc<Connection>>>,
    guard: Mutex<Option<SendRequest<OpenStreams, Bytes>>>,
}

impl Debug for Handler {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria2Handler")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    const DEFAULT_MAX_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

    pub fn new(opts: HystOption) -> Self {
        if opts.ca.is_some() || opts.ca_str.is_some() {
            warn!("hysteria2 custom CA is not implemented yet, using default root store");
        }
        if opts.cwnd.is_some() {
            warn!("hysteria2 `cwnd` option is not implemented yet");
        }
        if opts.udp_mtu.is_some() {
            warn!("hysteria2 `udp-mtu` is ignored in TCP-only implementation");
        }

        let verifier = DefaultTlsVerifier::new(opts.fingerprint.clone(), opts.skip_cert_verify);
        let mut tls_config = RustlsClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();

        tls_config.alpn_protocols = if opts.alpn.is_empty() {
            vec![b"h3".to_vec()]
        } else {
            opts.alpn
                .iter()
                .map(|item| item.as_bytes().to_vec())
                .collect()
        };

        let mut transport = TransportConfig::default();
        if opts.disable_mtu_discovery {
            transport.mtu_discovery_config(None);
        }
        transport.congestion_controller_factory(Arc::new(DynCongestion));
        transport.max_idle_timeout(Some(Self::DEFAULT_MAX_IDLE_TIMEOUT.try_into().unwrap()));
        transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));

        let quic_config: QuicClientConfig = tls_config.try_into().expect("valid quic config");
        let mut client_config = ClientConfig::new(Arc::new(quic_config));
        client_config.transport_config(Arc::new(transport));

        Self {
            opts,
            ep_config: EndpointConfig::default(),
            client_config,
            conn: Mutex::new(None),
            guard: Mutex::new(None),
        }
    }

    async fn resolve_server_addr(
        &self,
        resolver: ThreadSafeDNSResolver,
    ) -> anyhow::Result<SocketAddr> {
        match self.opts.addr.clone() {
            SocksAddr::Ip(ip) => Ok(ip),
            SocksAddr::Domain(domain, port) => {
                let ip = resolver
                    .resolve(domain.as_str(), true)
                    .await?
                    .ok_or_else(|| anyhow!("resolve domain {domain} failed"))?;
                Ok(SocketAddr::new(ip, port))
            }
        }
    }

    fn create_udp_socket(
        server_addr: SocketAddr,
        sess: &Session,
    ) -> io::Result<std::net::UdpSocket> {
        let (domain, bind_addr) = match server_addr {
            SocketAddr::V4(_) => (
                socket2::Domain::IPV4,
                SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
            ),
            SocketAddr::V6(_) => (
                socket2::Domain::IPV6,
                SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
            ),
        };
        let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, None)?;
        if sess.iface.is_some() {
            debug!("hysteria2 currently ignores `connect-via` interface binding");
        }
        #[cfg(target_os = "linux")]
        if let Some(so_mark) = sess.so_mark {
            socket.set_mark(so_mark)?;
        }
        socket.set_nonblocking(true)?;
        socket.bind(&bind_addr.into())?;
        Ok(socket.into())
    }

    fn tls_server_name(&self, server_addr: SocketAddr) -> String {
        self.opts
            .sni
            .clone()
            .unwrap_or_else(|| match &self.opts.addr {
                SocksAddr::Domain(domain, _) => domain.clone(),
                SocksAddr::Ip(_) => server_addr.ip().to_string(),
            })
    }

    fn server_label(&self) -> String {
        match &self.opts.addr {
            SocksAddr::Ip(ip) => ip.to_string(),
            SocksAddr::Domain(domain, port) => format!("{domain}:{port}"),
        }
    }

    fn client_cc_rx_header(&self) -> String {
        self.opts
            .up_down
            .map(|(_, down)| down.to_string())
            .unwrap_or_else(|| "0".to_owned())
    }

    fn select_brutal_bps(&self, cc_rx: CcRx) -> Option<u64> {
        match cc_rx {
            CcRx::Fixed(rate) if rate > 0 => Some(rate),
            _ => self.opts.up_down.map(|(up, _)| up).filter(|up| *up > 0),
        }
    }

    fn configure_brutal_cc(conn: &Connection, brutal_bps: Option<u64>) {
        let Some(brutal_bps) = brutal_bps else {
            return;
        };

        match conn
            .congestion_state()
            .into_any()
            .downcast::<DynController>()
        {
            Ok(controller) => {
                controller.set_controller(Box::new(Brutal::new(brutal_bps, conn.clone())));
                debug!(brutal_bps, "hysteria2 enabled brutal congestion control");
            }
            Err(_) => {
                warn!("hysteria2 failed to switch congestion controller to brutal");
            }
        }
    }

    async fn new_authed_connection_inner(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> anyhow::Result<(Arc<Connection>, SendRequest<OpenStreams, Bytes>)> {
        let server_addr = self.resolve_server_addr(resolver).await?;
        let socket_factory = || Self::create_udp_socket(server_addr, sess);

        let mut endpoint = if let Some(obfs) = self.opts.obfs.as_ref() {
            match obfs {
                Obfs::Salamander(salamander_obfs) => {
                    let socket = socket_factory()?;
                    let obfs_socket =
                        salamander::Salamander::new(socket, salamander_obfs.key.clone())?;
                    quinn::Endpoint::new_with_abstract_socket(
                        self.ep_config.clone(),
                        None,
                        Arc::new(obfs_socket),
                        Arc::new(TokioRuntime),
                    )?
                }
            }
        } else if let Some(port_generator) = self.opts.ports.as_ref() {
            let socket = udp_hop::UdpHop::new(server_addr.port(), port_generator.clone(), None)?;
            quinn::Endpoint::new_with_abstract_socket(
                self.ep_config.clone(),
                None,
                Arc::new(socket),
                Arc::new(TokioRuntime),
            )?
        } else {
            let socket = socket_factory()?;
            quinn::Endpoint::new(self.ep_config.clone(), None, socket, Arc::new(TokioRuntime))?
        };

        endpoint.set_default_client_config(self.client_config.clone());

        let server_name = self.tls_server_name(server_addr);
        let conn = endpoint.connect(server_addr, &server_name)?.await?;
        let cc_rx_header = self.client_cc_rx_header();
        let (guard, cc_rx, _udp_supported) =
            Self::auth(&conn, &self.opts.password, cc_rx_header.as_str()).await?;
        Self::configure_brutal_cc(&conn, self.select_brutal_bps(cc_rx));

        Ok((Arc::new(conn), guard))
    }

    async fn auth(
        conn: &Connection,
        password: &str,
        cc_rx_header: &str,
    ) -> anyhow::Result<(SendRequest<OpenStreams, Bytes>, CcRx, bool)> {
        let h3_conn = h3_quinn::Connection::new(conn.clone());
        let (_, mut sender) = h3::client::builder().build::<_, _, Bytes>(h3_conn).await?;

        let request = http::Request::post("https://hysteria/auth")
            .header("Hysteria-Auth", password)
            .header("Hysteria-CC-RX", cc_rx_header)
            .header("Hysteria-Padding", codec::padding(64..=512))
            .body(())
            .expect("request builder should be valid");

        let mut req = sender.send_request(request).await?;
        req.finish().await?;
        let response = req.recv_response().await?;

        const HYSTERIA_STATUS_OK: u16 = 233;
        if response.status() != HYSTERIA_STATUS_OK {
            return Err(anyhow!(
                "hysteria2 auth failed: unexpected status {}",
                response.status()
            ));
        }

        let cc_rx = match response.headers().get("Hysteria-CC-RX") {
            Some(header) => match header.to_str() {
                Ok(value) => match value.parse::<CcRx>() {
                    Ok(parsed) => parsed,
                    Err(err) => {
                        warn!(
                            "hysteria2 invalid Hysteria-CC-RX value `{value}`: {err}, fallback to auto"
                        );
                        CcRx::Auto
                    }
                },
                Err(err) => {
                    warn!("hysteria2 invalid Hysteria-CC-RX header: {err}, fallback to auto");
                    CcRx::Auto
                }
            },
            None => CcRx::Auto,
        };

        let udp_supported = response
            .headers()
            .get("Hysteria-UDP")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<bool>().ok())
            .unwrap_or(false);

        Ok((sender, cc_rx, udp_supported))
    }

    async fn new_authed_connection(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<Arc<Connection>> {
        let mut lock = self.conn.lock().await;
        if let Some(conn) = lock.as_ref() {
            if conn.close_reason().is_none() {
                return Ok(conn.clone());
            }
            debug!("hysteria2 cached connection closed, reconnecting");
        }

        let (conn, guard) = self
            .new_authed_connection_inner(sess, resolver)
            .await
            .map_err(|err| {
                io::Error::other(format!("connect to {} failed: {err}", self.server_label()))
            })?;

        *lock = Some(conn.clone());
        *self.guard.lock().await = Some(guard);
        Ok(conn)
    }

    async fn connect_tcp(conn: &Connection, sess: &Session) -> io::Result<HystStream> {
        let (mut send, mut recv) = conn.open_bi().await?;

        tokio_util::codec::FramedWrite::new(&mut send, Hy2TcpCodec)
            .send(&sess.destination)
            .await?;

        match tokio_util::codec::FramedRead::new(&mut recv, Hy2TcpCodec)
            .next()
            .await
        {
            Some(Ok(response)) if response.status == 0x00 => {}
            Some(Ok(response)) => {
                return Err(io::Error::other(format!(
                    "hysteria2 server rejected stream: status={}, message={}",
                    response.status, response.msg
                )));
            }
            Some(Err(err)) => return Err(err),
            None => {
                return Err(io::Error::other(
                    "hysteria2 server closed stream before response",
                ));
            }
        }

        Ok(HystStream { send, recv })
    }
}

impl DialWithConnector for Handler {}

#[async_trait::async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Hysteria2
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let conn = self.new_authed_connection(sess, resolver).await?;
        let stream = Self::connect_tcp(&conn, sess).await?;
        let chained = ChainedStreamWrapper::new(Box::new(stream));
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }
}

pub struct HystStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl Debug for HystStream {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HystStream").finish()
    }
}

impl AsyncRead for HystStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for HystStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().send)
            .poll_write(cx, buf)
            .map(|result| result.map_err(io::Error::other))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_shutdown(cx)
    }
}
