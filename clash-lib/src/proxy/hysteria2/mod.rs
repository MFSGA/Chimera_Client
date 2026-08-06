#![allow(dead_code)]

mod codec;
mod congestion;
mod salamander;
mod udp_hop;

mod datagram;

use std::{
    collections::HashMap,
    fmt::{Debug, Formatter},
    fs,
    io::{self, BufReader},
    net::SocketAddr,
    num::ParseIntError,
    path::Path,
    pin::Pin,
    sync::{Arc, RwLock, atomic::AtomicU32},
    task::{Context, Poll},
};

use anyhow::anyhow;
use bytes::{Bytes, BytesMut};
use codec::{Fragments, Hy2TcpCodec};
use congestion::{Brutal, DynController};
use futures::{SinkExt, StreamExt};
use h3::client::SendRequest;
use h3_quinn::OpenStreams;
use quinn::{
    ClientConfig, Connection, EndpointConfig, TokioRuntime,
    crypto::rustls::QuicClientConfig,
};
use quinn_proto::TransportConfig;
use rustls::{ClientConfig as RustlsClientConfig, RootCertStore};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Mutex,
};
use tracing::{debug, warn};

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::tls::{DefaultTlsVerifier, GLOBAL_ROOT_STORE},
    proxy::{
        DialWithConnector, OutboundHandler, OutboundType,
        converters::hysteria2::PortGenerator,
        datagram::UdpPacket,
        hysteria2::datagram::{HysteriaDatagramOutbound, UdpSession},
        utils::new_protected_udp_socket,
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
    conn: Mutex<Option<Arc<HysteriaConnection>>>,
    next_session_id: AtomicU32,
    /// a send request guard to keep the connection alive
    guard: Mutex<Option<SendRequest<OpenStreams, Bytes>>>,
    /// support udp is decided by server
    support_udp: RwLock<bool>,
}

impl Debug for Handler {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria2Handler")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    const DEFAULT_MAX_IDLE_TIMEOUT: std::time::Duration =
        std::time::Duration::from_secs(300);
    const MIN_INITIAL_CWND_PACKETS: u64 = 2;

    fn append_custom_ca(
        root_store: &mut RootCertStore,
        source: &str,
        bytes: &[u8],
    ) -> io::Result<usize> {
        let mut reader = BufReader::new(bytes);
        let pem_certs: io::Result<Vec<_>> =
            rustls_pemfile::certs(&mut reader).collect();
        let certs = match pem_certs {
            Ok(certs) if !certs.is_empty() => certs,
            Ok(_) => vec![rustls::pki_types::CertificateDer::from(bytes.to_vec())],
            Err(err) => {
                return Err(io::Error::other(format!(
                    "failed to parse certificate from {source}: {err}"
                )));
            }
        };

        let (added, ignored) = root_store.add_parsable_certificates(certs);
        if added == 0 {
            return Err(io::Error::other(format!(
                "no valid certificate found in {source}"
            )));
        }
        if ignored > 0 {
            warn!(
                source,
                ignored, "hysteria2 ignored invalid certificate entries"
            );
        }
        Ok(added)
    }

    fn load_custom_root_store(opts: &HystOption) -> Option<Arc<RootCertStore>> {
        if opts.ca.is_none() && opts.ca_str.is_none() {
            return None;
        }

        let mut root_store = (*GLOBAL_ROOT_STORE).as_ref().clone();
        let mut loaded = 0usize;

        if let Some(ca_path) = opts.ca.as_deref() {
            let source = format!("ca file `{}`", Path::new(ca_path).display());
            match fs::read(ca_path).and_then(|content| {
                Self::append_custom_ca(&mut root_store, &source, &content)
            }) {
                Ok(added) => {
                    debug!(source, added, "hysteria2 loaded custom CA certificates");
                    loaded += added;
                }
                Err(err) => warn!("hysteria2 failed to load {source}: {err}"),
            }
        }

        if let Some(ca_str) = opts.ca_str.as_deref() {
            let source = "inline ca_str".to_owned();
            match Self::append_custom_ca(&mut root_store, &source, ca_str.as_bytes())
            {
                Ok(added) => {
                    debug!(source, added, "hysteria2 loaded custom CA certificates");
                    loaded += added;
                }
                Err(err) => warn!("hysteria2 failed to load {source}: {err}"),
            }
        }

        if loaded == 0 {
            warn!(
                "hysteria2 custom CA configured but no valid certificates loaded, using default root store"
            );
            return None;
        }

        Some(Arc::new(root_store))
    }

    pub fn new(opts: HystOption) -> Self {
        if opts.ca.is_some() {
            warn!("hysteria2 does not support ca yet");
        }
        let verify =
            DefaultTlsVerifier::new(opts.fingerprint.clone(), opts.skip_cert_verify);
        let mut tls_config = RustlsClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verify))
            .with_no_client_auth();

        // should set alpn_protocol `h3` default
        tls_config.alpn_protocols = if opts.alpn.is_empty() {
            vec![b"h3".to_vec()]
        } else {
            opts.alpn.iter().map(|x| x.as_bytes().to_vec()).collect()
        };

        let mut transport = TransportConfig::default();
        #[cfg(target_os = "android")]
        transport.enable_segmentation_offload(false);
        if opts.disable_mtu_discovery {
            tracing::debug!("disable mtu discovery");
            transport.mtu_discovery_config(None);
        }
        // TODO
        // transport.congestion_controller_factory(DynCongestion);
        transport.max_idle_timeout(Some(
            Self::DEFAULT_MAX_IDLE_TIMEOUT.try_into().unwrap(),
        ));
        transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));

        let quic_config: QuicClientConfig = tls_config.try_into().unwrap();
        let mut client_config = ClientConfig::new(Arc::new(quic_config));
        client_config.transport_config(Arc::new(transport));
        let ep_config = quinn::EndpointConfig::default();

        Self {
            opts,
            ep_config,
            client_config,
            next_session_id: AtomicU32::new(0),
            conn: Mutex::new(None),
            guard: Mutex::new(None),
            support_udp: RwLock::new(true),
        }
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
                controller
                    .set_controller(Box::new(Brutal::new(brutal_bps, conn.clone())));
                debug!(brutal_bps, "hysteria2 enabled brutal congestion control");
            }
            Err(_) => {
                warn!("hysteria2 failed to switch congestion controller to brutal");
            }
        }
    }

    // connect and auth
    async fn new_authed_connection_inner(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> anyhow::Result<(
        Connection,
        SendRequest<OpenStreams, Bytes>,
        tokio::task::JoinHandle<()>,
    )> {
        tracing::trace!(
            "hysteria2 new_authed_connection_inner: starting connection to {:?}",
            self.opts.addr
        );
        // Everytime we enstablish a new session, we should lookup the server
        // address. maybe it changed since it use ddns
        let server_socket_addrs = match self.opts.addr.clone() {
            SocksAddr::Ip(ip) => vec![ip],
            SocksAddr::Domain(d, port) => {
                // Proxy server domains must resolve to real endpoint IPs. Using
                // enhanced DNS here may return a fake-ip address and make QUIC
                // connect to the virtual pool instead of the Hysteria2 server.
                resolver
                    .resolve_all(d.as_str(), false)
                    .await?
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, port))
                    .collect()
            }
        };
        if server_socket_addrs.is_empty() {
            return Err(anyhow!("resolve domain {} failed", self.opts.addr));
        }

        let mut last_error = None;
        for server_socket_addr in server_socket_addrs {
            match self
                .new_authed_connection_to(sess, server_socket_addr)
                .await
            {
                Ok(connection) => return Ok(connection),
                Err(error) => {
                    warn!(
                        server = %server_socket_addr,
                        error = %error,
                        "hysteria2 connection attempt failed"
                    );
                    last_error = Some(error);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            anyhow!("no address available for {}", self.opts.addr)
        }))
    }

    async fn new_authed_connection_to(
        &self,
        sess: &Session,
        server_socket_addr: SocketAddr,
    ) -> anyhow::Result<(
        Connection,
        SendRequest<OpenStreams, Bytes>,
        tokio::task::JoinHandle<()>,
    )> {
        // todo: Here maybe we should use a AsyncUdpSocket which implement salamander obfs
        // and port hopping
        let create_socket = || async {
            new_protected_udp_socket(
                None,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
                Some(server_socket_addr),
            )
            .await
        };

        let mut ep = if let Some(obfs) = self.opts.obfs.as_ref() {
            match obfs {
                Obfs::Salamander(salamander_obfs) => {
                    let socket = create_socket().await?;
                    let obfs = salamander::Salamander::new(
                        socket.into_std()?,
                        salamander_obfs.key.to_vec(),
                    )?;

                    quinn::Endpoint::new_with_abstract_socket(
                        self.ep_config.clone(),
                        None,
                        Arc::new(obfs),
                        Arc::new(TokioRuntime),
                    )?
                }
            }
        } else if let Some(port_gen) = self.opts.ports.as_ref() {
            let udp_hop = udp_hop::UdpHop::new(
                server_socket_addr,
                port_gen.clone(),
                sess.iface.clone(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
                None,
            )
            .await?;
            quinn::Endpoint::new_with_abstract_socket(
                self.ep_config.clone(),
                None,
                Arc::new(udp_hop),
                Arc::new(TokioRuntime),
            )?
        } else {
            let socket = create_socket().await?;

            quinn::Endpoint::new(
                self.ep_config.clone(),
                None,
                socket.into_std()?,
                Arc::new(TokioRuntime),
            )?
        };

        ep.set_default_client_config(self.client_config.clone());

        tracing::trace!("hysteria2 connecting to server: {:?}", server_socket_addr);
        let session = ep
            .connect(server_socket_addr, self.opts.sni.as_deref().unwrap_or(""))?
            .await?;
        tracing::trace!("hysteria2 QUIC connection established");
        let (guard, driver_task, cc_rx, udp) =
            Self::auth(&session, &self.opts.password).await?;
        tracing::trace!("hysteria2 authentication successful, udp={}", udp);
        *self.support_udp.write().unwrap() = udp;
        Self::configure_brutal_cc(&session, self.select_brutal_bps(cc_rx));

        Ok((session, guard, driver_task))
    }

    async fn auth(
        conn: &quinn::Connection,
        passwd: &str,
    ) -> anyhow::Result<(
        SendRequest<OpenStreams, Bytes>,
        tokio::task::JoinHandle<()>,
        CcRx,
        bool,
    )> {
        let h3_conn = h3_quinn::Connection::new(conn.clone());

        let (mut driver, mut sender) =
            h3::client::builder().build::<_, _, Bytes>(h3_conn).await?;
        let driver_task = tokio::spawn(async move {
            let err = driver.wait_idle().await;
            tracing::debug!("hysteria2 h3 driver ended: {err}");
        });

        let req = http::Request::post("https://hysteria/auth")
            .header("Hysteria-Auth", passwd)
            .header("Hysteria-CC-RX", "0")
            .header("Hysteria-Padding", codec::padding(64..=512))
            .body(())
            .unwrap();
        let mut r = sender.send_request(req).await?;
        r.finish().await?;

        let r = r.recv_response().await?;

        const HYSTERIA_STATUS_OK: u16 = 233;
        if r.status() != HYSTERIA_STATUS_OK {
            return Err(anyhow!("auth failed: response status code {}", r.status()));
        }

        // MUST have Hysteria-CC-RX and Hysteria-UDP headers according to hysteria2
        // document
        let cc_rx = r
            .headers()
            .get("Hysteria-CC-RX")
            .ok_or_else(|| anyhow!("auth failed: missing Hysteria-CC-RX header"))?
            .to_str()?
            .parse()?;

        let support_udp = r
            .headers()
            .get("Hysteria-UDP")
            .ok_or_else(|| anyhow!("auth failed: missing Hysteria-UDP header"))?
            .to_str()?
            .parse()?;

        Ok((sender, driver_task, cc_rx, support_udp))
    }

    async fn connect_tcp(
        conn: &Connection,
        sess: &Session,
    ) -> io::Result<HystStream> {
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

    pub async fn new_authed_connection(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<Arc<HysteriaConnection>> {
        let mut quinn_conn_lock = self.conn.lock().await;

        match (*quinn_conn_lock).as_ref().filter(|s| {
            match s.conn.close_reason() {
                // rust should have inspect method on Option and Result!
                Some(reason) => {
                    tracing::debug!("old connection closed: {:?}", reason);
                    false
                }
                None => true,
            }
        }) {
            Some(s) => Ok(s.clone()),
            None => {
                let (session, guard, driver_task) = self
                    .new_authed_connection_inner(sess, resolver)
                    .await
                    .map_err(|e| {
                        std::io::Error::other(format!(
                            "connect to {} failed: {}",
                            self.opts.addr, e
                        ))
                    })?;

                let session = Arc::new(session);
                let hyst_conn = HysteriaConnection::new_with_task_loop(
                    session,
                    self.opts.udp_mtu,
                    driver_task,
                );
                *quinn_conn_lock = Some(hyst_conn.clone());
                *self.guard.lock().await = Some(guard);
                Ok(hyst_conn)
            }
        }
    }
}

pub struct HysteriaConnection {
    pub conn: Arc<quinn::Connection>,
    pub udp_sessions: Arc<tokio::sync::Mutex<HashMap<u32, UdpSession>>>,
    h3_driver_task: Option<tokio::task::JoinHandle<()>>,

    // config
    pub udp_mtu: Option<usize>,
}

impl HysteriaConnection {
    pub fn new_with_task_loop(
        conn: Arc<quinn::Connection>,
        udp_mtu: Option<u32>,
        h3_driver_task: tokio::task::JoinHandle<()>,
    ) -> Arc<Self> {
        let s = Arc::new(Self {
            conn,
            udp_sessions: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            udp_mtu: udp_mtu.map(|x| x as usize),
            h3_driver_task: Some(h3_driver_task),
        });
        tokio::spawn(Self::spawn_tasks(s.clone()));

        s
    }

    async fn spawn_tasks(self: Arc<Self>) {
        tracing::trace!("hysteria2 spawn_tasks: starting datagram receive loop");
        let err = loop {
            tokio::select! {
                res = self.conn.read_datagram() => {
                    match res {
                        Ok(pkt) => {
                            tracing::trace!("hysteria2 received datagram: {} bytes", pkt.len());
                            self.clone().recv_packet(pkt).await
                        },
                        Err(e) => {
                            tracing::error!("hysteria2 read datagram error: {}", e);
                            break e;
                        }
                    }
                }
            }
        };
        tracing::warn!("hysteria2 connection error: {:?}", err);
    }

    pub async fn connect_udp(
        self: Arc<Self>,
        sess: &Session,
        session_id: u32,
    ) -> HysteriaDatagramOutbound {
        HysteriaDatagramOutbound::new(
            session_id,
            self.clone(),
            sess.destination.clone(),
        )
        .await
    }

    pub fn send_packet(
        &self,
        pkt: Bytes,
        addr: SocksAddr,
        session_id: u32,
        pkt_id: u16,
    ) -> io::Result<()> {
        let max_frag_size = match self.udp_mtu.or(self.conn.max_datagram_size()) {
            Some(value) => value,
            None => {
                return Err(io::Error::other(
                    "hysteria2 udp mtu not set, please check disable_mtu_discovery and udp_mtu",
                ));
            }
        };

        for frag in Fragments::new(session_id, pkt_id, addr, max_frag_size, pkt) {
            self.conn.send_datagram(frag).map_err(io::Error::other)?;
        }

        Ok(())
    }

    pub async fn recv_packet(self: Arc<Self>, pkt: Bytes) {
        tracing::trace!("hysteria2 recv_packet: {} bytes", pkt.len());
        let mut buf: BytesMut = pkt.into();
        let pkt = codec::HysUdpPacket::decode(&mut buf).unwrap();
        let session_id = pkt.session_id;
        let mut udp_sessions = self.udp_sessions.lock().await;
        match udp_sessions.get_mut(&session_id) {
            Some(session) => {
                tracing::trace!(
                    "hysteria2 found session {}, feeding packet",
                    session_id
                );
                if let Some(pkt) = session.feed(pkt) {
                    tracing::trace!(
                        "hysteria2 complete packet received for session {}: {} \
                         bytes to {:?}",
                        session_id,
                        pkt.data.len(),
                        session.local_addr
                    );
                    let _ = session
                        .incoming
                        .send(UdpPacket {
                            data: pkt.data,
                            src_addr: pkt.addr,
                            dst_addr: session.local_addr.clone(),
                            inbound_user: None,
                        })
                        .await;
                } else {
                    tracing::trace!(
                        "hysteria2 packet fragment buffered for session {}",
                        session_id
                    );
                }
            }
            _ => {
                tracing::warn!("hysteria2 udp session not found: {}", session_id);
            }
        }
    }
}

impl Drop for HysteriaConnection {
    fn drop(&mut self) {
        if let Some(driver_task) = self.h3_driver_task.take() {
            driver_task.abort();
        }
    }
}

impl DialWithConnector for Handler {}

#[async_trait::async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn server_name(&self) -> Option<&str> {
        self.opts.addr.domain()
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Hysteria2
    }

    async fn reset_connection_pool(&self) -> io::Result<u32> {
        let cached = self.conn.lock().await.take();
        self.guard.lock().await.take();

        let Some(cached) = cached else {
            return Ok(0);
        };
        cached
            .conn
            .close(quinn::VarInt::from_u32(0), b"network changed");
        cached.udp_sessions.lock().await.clear();
        Ok(1)
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let conn = self.new_authed_connection(sess, resolver).await?;
        let stream = Self::connect_tcp(&conn.conn, sess).await?;
        let chained = ChainedStreamWrapper::new(Box::new(stream));
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedDatagram> {
        let authed_conn = self.new_authed_connection(sess, resolver.clone()).await?;
        let next_session_id = self
            .next_session_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let hy_datagram = authed_conn.connect_udp(sess, next_session_id).await;
        let s = ChainedDatagramWrapper::new(hy_datagram);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
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

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_shutdown(cx)
    }
}

#[cfg(all(test, docker_test, throughput_test))]
mod e2e {
    use std::{io::Write as _, sync::Arc, time::Duration};

    use futures::{SinkExt as _, StreamExt as _};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UdpSocket,
    };

    use super::{Handler, HystOption, HysteriaConnection};
    use crate::{
        app::{dispatcher::BoxedChainedDatagram, dns::ThreadSafeDNSResolver},
        proxy::{
            OutboundHandler,
            datagram::UdpPacket,
            utils::test_utils::{
                config_helper,
                consts::*,
                docker_runner::{
                    DockerTestRunner, DockerTestRunnerBuilder,
                    MultiDockerTestRunner, RunAndCleanup,
                },
                docker_utils::{
                    alloc_port, clash_process_e2e_throughput, find_clash_rs_binary,
                },
            },
        },
        session::{Network, Session, SocksAddr},
        tests::initialize,
    };

    const CONTAINER_PORT: u16 = 10002;
    const TCP_ECHO_PORT: u16 = 10003;
    const UDP_ECHO_PORT: u16 = 10004;
    const E2E_PAYLOAD_BYTES: usize = 32 * 1024 * 1024; // 32 MB

    const HYSTERIA2_SERVER_CONFIG: &str = r#"{
    "listen": ":10002",
    "tls": {
        "cert": "/home/ubuntu/my.crt",
        "key": "/home/ubuntu/my.key"
    },
    "up_mbps": 100,
    "down_mbps": 100,
    "auth": {
        "type": "password",
        "password": "passwd"
    }
}"#;

    const HYSTERIA_SALAMANDER_SERVER_CONFIG: &str = r#"{
    "listen": ":10002",
    "tls": {
        "cert": "/home/ubuntu/my.crt",
        "key": "/home/ubuntu/my.key"
    },
    "obfs": {
        "type": "salamander",
        "salamander": {
            "password": "salamander-password"
        }
    },
    "up_mbps": 100,
    "down_mbps": 100,
    "auth": {
        "type": "password",
        "password": "passwd"
    }
}"#;

    async fn build_hysteria2_runner(
        server_config: &str,
    ) -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = config_helper::test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");

        let mut tmp = tempfile::NamedTempFile::new_in(&test_config_dir)?;
        tmp.write_all(server_config.as_bytes())?;

        let runner = DockerTestRunnerBuilder::new()
            .image(IMAGE_HYSTERIA)
            .cmd(&["server"])
            .no_port()
            .mounts(&[
                (tmp.path().to_str().unwrap(), "/config.json"),
                (cert.to_str().unwrap(), "/home/ubuntu/my.crt"),
                (key.to_str().unwrap(), "/home/ubuntu/my.key"),
            ])
            .build()
            .await?;
        drop(tmp);
        Ok(runner)
    }

    async fn build_echo_runner() -> anyhow::Result<DockerTestRunner> {
        DockerTestRunnerBuilder::new()
            .image(IMAGE_NETEM)
            .entrypoint(&["sh", "-c"])
            .cmd(&[
                "socat TCP-LISTEN:10003,reuseaddr,fork EXEC:/bin/cat & exec socat UDP-RECVFROM:10004,reuseaddr,fork EXEC:/bin/cat",
            ])
            .no_port()
            .build()
            .await
    }

    fn base_config(server: &str, socks_port: u16, extra: &str) -> String {
        let mmdb = config_helper::test_config_base_dir()
            .join("Country.mmdb")
            .to_str()
            .unwrap()
            .to_owned();
        format!(
            r#"
socks-port: {socks_port}
bind-address: 127.0.0.1
mmdb: "{mmdb}"
mode: global
log-level: error
proxies:
  - name: proxy
    type: hysteria2
    server: {server}
    port: {port}
    password: passwd
{extra}
    sni: example.org
    skip-cert-verify: true
rules:
  - MATCH,proxy
"#,
            socks_port = socks_port,
            mmdb = mmdb,
            server = server,
            port = CONTAINER_PORT,
            extra = extra,
        )
    }

    async fn connect_until_ready(
        handler: &Handler,
        session: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> anyhow::Result<Arc<HysteriaConnection>> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            match handler
                .new_authed_connection(session, resolver.clone())
                .await
            {
                Ok(connection) => return Ok(connection),
                Err(error) if tokio::time::Instant::now() < deadline => {
                    tracing::debug!(%error, "waiting for hysteria2 test server");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    async fn tcp_echo_roundtrip(
        handler: Arc<Handler>,
        resolver: ThreadSafeDNSResolver,
        target: &str,
    ) -> anyhow::Result<()> {
        let session = Session {
            destination: format!("{target}:{TCP_ECHO_PORT}").parse::<SocksAddr>()?,
            ..Default::default()
        };
        let mut stream = tokio::time::timeout(
            Duration::from_secs(5),
            handler.connect_stream(&session, resolver),
        )
        .await??;
        let payload = b"hysteria2-network-reset";
        stream.write_all(payload).await?;
        stream.flush().await?;
        let mut echoed = vec![0u8; payload.len()];
        stream.read_exact(&mut echoed).await?;
        anyhow::ensure!(echoed == payload, "unexpected hysteria2 TCP echo payload");
        Ok(())
    }

    async fn wait_udp_echo_ready(target: &str) -> anyhow::Result<()> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let target = format!("{target}:{UDP_ECHO_PORT}");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let payload = b"udp-echo-ready";
        let mut buffer = [0u8; 64];

        loop {
            socket.send_to(payload, &target).await?;
            match tokio::time::timeout(
                Duration::from_millis(250),
                socket.recv_from(&mut buffer),
            )
            .await
            {
                Ok(Ok((length, _))) if &buffer[..length] == payload => return Ok(()),
                Ok(Ok(_)) | Err(_) if tokio::time::Instant::now() < deadline => {
                    continue;
                }
                Ok(Ok((length, _))) => {
                    anyhow::bail!(
                        "UDP echo service returned unexpected readiness payload: {:?}",
                        &buffer[..length]
                    );
                }
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => {
                    anyhow::bail!("UDP echo service was not ready in 5 seconds")
                }
            }
        }
    }

    async fn connect_udp_datagram(
        handler: Arc<Handler>,
        resolver: ThreadSafeDNSResolver,
        target: &str,
    ) -> anyhow::Result<BoxedChainedDatagram> {
        let session = Session {
            network: Network::Udp,
            destination: format!("{target}:{UDP_ECHO_PORT}").parse::<SocksAddr>()?,
            ..Default::default()
        };
        Ok(tokio::time::timeout(
            Duration::from_secs(5),
            handler.connect_datagram(&session, resolver),
        )
        .await??)
    }

    async fn udp_echo_roundtrip(
        datagram: &mut BoxedChainedDatagram,
        target: &str,
        payload: &[u8],
    ) -> anyhow::Result<()> {
        let destination =
            format!("{target}:{UDP_ECHO_PORT}").parse::<SocksAddr>()?;
        datagram
            .send(UdpPacket {
                data: payload.to_vec(),
                dst_addr: destination,
                ..Default::default()
            })
            .await?;
        let echoed = tokio::time::timeout(Duration::from_secs(5), datagram.next())
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!("hysteria2 UDP datagram ended before echo")
            })?;
        anyhow::ensure!(
            echoed.data == payload,
            "unexpected hysteria2 UDP echo payload"
        );
        Ok(())
    }

    #[tokio::test]
    async fn e2e_network_reset_reauthenticates_hysteria2() -> anyhow::Result<()> {
        initialize();
        let hysteria = build_hysteria2_runner(HYSTERIA2_SERVER_CONFIG).await?;
        let server = hysteria.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
        let echo = match build_echo_runner().await {
            Ok(echo) => echo,
            Err(error) => {
                let _ = hysteria.cleanup().await;
                return Err(error);
            }
        };
        let Some(echo_ip) = echo.container_ip() else {
            let _ = hysteria.cleanup().await;
            let _ = echo.cleanup().await;
            anyhow::bail!("TCP/UDP echo container has no IP address");
        };
        let mut containers = MultiDockerTestRunner::default();
        containers.add_with_runner(hysteria);
        containers.add_with_runner(echo);

        containers
            .run_and_cleanup(async move {
                DockerTestRunner::wait_host_tcp_ready(
                    &echo_ip,
                    TCP_ECHO_PORT,
                    Duration::from_secs(5),
                )
                .await?;
                wait_udp_echo_ready(&echo_ip).await?;
                let handler = Arc::new(Handler::new(HystOption {
                    name: "hysteria2-reset-e2e".to_owned(),
                    addr: format!("{server}:{CONTAINER_PORT}").parse::<SocksAddr>()?,
                    ports: None,
                    sni: Some("example.org".to_owned()),
                    password: "passwd".to_owned(),
                    obfs: None,
                    skip_cert_verify: true,
                    alpn: Vec::new(),
                    fingerprint: None,
                    disable_mtu_discovery: false,
                    ca: None,
                    ca_str: None,
                    up_down: None,
                    cwnd: None,
                    udp_mtu: None,
                }));
                let resolver = config_helper::build_dns_resolver().await?;
                let session = Session::default();

                let first = connect_until_ready(&handler, &session, resolver.clone()).await?;
                tcp_echo_roundtrip(handler.clone(), resolver.clone(), &echo_ip)
                    .await
                    .map_err(|error| anyhow::anyhow!("pre-reset TCP roundtrip failed: {error:#}"))?;
                let mut first_udp =
                    connect_udp_datagram(handler.clone(), resolver.clone(), &echo_ip).await?;
                udp_echo_roundtrip(
                    &mut first_udp,
                    &echo_ip,
                    b"hysteria2-udp-before-reset",
                )
                .await
                .map_err(|error| anyhow::anyhow!("pre-reset UDP roundtrip failed: {error:#}"))?;
                anyhow::ensure!(
                    first.udp_sessions.lock().await.len() == 1,
                    "hysteria2 did not register the pre-reset UDP session"
                );
                let cached = handler
                    .new_authed_connection(&session, resolver.clone())
                    .await?;
                anyhow::ensure!(
                    Arc::ptr_eq(&first, &cached),
                    "hysteria2 did not reuse the authenticated connection"
                );

                anyhow::ensure!(
                    handler.reset_connection_pool().await? == 1,
                    "network reset did not invalidate the cached hysteria2 connection"
                );
                tokio::time::timeout(Duration::from_secs(2), async {
                    while first.conn.close_reason().is_none() {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await?;
                anyhow::ensure!(
                    first.udp_sessions.lock().await.is_empty(),
                    "network reset retained the old hysteria2 UDP session"
                );
                anyhow::ensure!(
                    tokio::time::timeout(Duration::from_secs(2), first_udp.next())
                        .await?
                        .is_none(),
                    "old hysteria2 UDP datagram remained readable after network reset"
                );

                let mut second_udp =
                    connect_udp_datagram(handler.clone(), resolver.clone(), &echo_ip).await?;
                udp_echo_roundtrip(
                    &mut second_udp,
                    &echo_ip,
                    b"hysteria2-udp-after-reset",
                )
                .await
                .map_err(|error| anyhow::anyhow!("post-reset UDP roundtrip failed: {error:#}"))?;
                let second = handler
                    .conn
                    .lock()
                    .await
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("hysteria2 did not cache replacement connection"))?;
                anyhow::ensure!(
                    !Arc::ptr_eq(&first, &second),
                    "hysteria2 reused the connection closed by network reset"
                );
                anyhow::ensure!(
                    second.conn.close_reason().is_none(),
                    "replacement hysteria2 connection was already closed"
                );
                anyhow::ensure!(
                    second.udp_sessions.lock().await.len() == 1,
                    "replacement hysteria2 connection did not register a new UDP session"
                );
                tcp_echo_roundtrip(handler.clone(), resolver.clone(), &echo_ip)
                    .await
                    .map_err(|error| anyhow::anyhow!("post-reset TCP roundtrip failed: {error:#}"))?;

                let second_cached = handler.new_authed_connection(&session, resolver).await?;
                anyhow::ensure!(
                    Arc::ptr_eq(&second, &second_cached),
                    "replacement hysteria2 connection was not cached"
                );
                Ok(())
            })
            .await
    }

    #[tokio::test]
    async fn e2e_throughput_hysteria2_plain() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = build_hysteria2_runner(HYSTERIA2_SERVER_CONFIG).await?;
        let server = container.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
        let gateway_ip = container.docker_gateway_ip();

        let config = base_config(&server, socks_port, "");
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "hysteria2-plain",
                    socks_port,
                    echo_port,
                    gateway_ip,
                    E2E_PAYLOAD_BYTES,
                )
                .await
                .map(|_| ())
            })
            .await
    }

    #[tokio::test]
    async fn e2e_throughput_hysteria2_plain_netem() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = build_hysteria2_runner(HYSTERIA2_SERVER_CONFIG).await?;
        container.apply_netem(50, 1.0).await?;
        let server = container.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
        let gateway_ip = container.docker_gateway_ip();

        let config = base_config(&server, socks_port, "");
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "hysteria2-plain-netem",
                    socks_port,
                    echo_port,
                    gateway_ip,
                    E2E_PAYLOAD_BYTES,
                )
                .await
                .map(|_| ())
            })
            .await
    }

    #[tokio::test]
    async fn e2e_throughput_hysteria2_salamander() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container =
            build_hysteria2_runner(HYSTERIA_SALAMANDER_SERVER_CONFIG).await?;
        let server = container.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
        let gateway_ip = container.docker_gateway_ip();

        let extra = r#"    obfs: salamander
    obfs-password: salamander-password
"#;
        let config = base_config(&server, socks_port, extra);
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "hysteria2-salamander",
                    socks_port,
                    echo_port,
                    gateway_ip,
                    E2E_PAYLOAD_BYTES,
                )
                .await
                .map(|_| ())
            })
            .await
    }
}
