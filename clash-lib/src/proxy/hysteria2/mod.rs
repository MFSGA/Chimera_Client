#![allow(dead_code)]

mod codec;
mod salamander;
mod udp_hop;

mod datagram;

#[cfg(feature = "transport-bench-api")]
use std::sync::atomic::AtomicBool;
use std::{
    collections::HashMap,
    fmt::{Debug, Formatter},
    fs,
    future::Future,
    io::{self, BufReader},
    net::SocketAddr,
    num::NonZeroUsize,
    path::Path,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU32, AtomicUsize, Ordering},
    },
};

use anyhow::anyhow;
use bytes::{Bytes, BytesMut};
use chimera_hysteria2_core::{AuthenticatedConnection, HysteriaClient};
use codec::Fragments;
use rustls::{ClientConfig as RustlsClientConfig, RootCertStore};
use tokio::sync::Mutex;
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
        ConnectorType, DialWithConnector, OutboundHandler, OutboundType,
        converters::hysteria2::PortGenerator,
        datagram::UdpPacket,
        hysteria2::datagram::{HysteriaDatagramOutbound, UdpSession},
        transport::ConnectorUdpSocket,
        utils::{
            NetworkPoolContext, RemoteConnector, UdpSocketConnectOptions,
            observe_proxy_target_datagram,
        },
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
    pub up: Option<u64>,
    pub down: Option<u64>,
    pub cwnd: Option<u64>,
    pub udp_mtu: Option<u32>,
    pub quic_connections: NonZeroUsize,
    pub udp_recv_buffer_size: Option<usize>,
}

pub struct Handler {
    opts: HystOption,
    core_client: HysteriaClient,
    conn: Mutex<Vec<Arc<HysteriaConnection>>>,
    next_connection_index: AtomicUsize,
    next_session_id: AtomicU32,
    #[cfg(feature = "transport-bench-api")]
    bench_udp_receive_task_enabled: AtomicBool,
    #[cfg(feature = "transport-bench-api")]
    bench_socket2_abstract_socket: AtomicBool,
    connector: tokio::sync::RwLock<Option<Arc<dyn RemoteConnector>>>,
    recovery_cancellation: tokio::sync::RwLock<tokio_util::sync::CancellationToken>,
    /// support udp is decided by server
    support_udp: RwLock<bool>,
}

#[cfg(feature = "transport-bench-api")]
fn validate_socket2_abstract_socket_bench_context(
    server_socket_addr: SocketAddr,
    has_interface: bool,
    has_port_hopping: bool,
    has_obfuscation: bool,
    #[cfg(target_os = "linux")] has_socket_mark: bool,
) -> anyhow::Result<()> {
    if !server_socket_addr.ip().is_loopback()
        || has_interface
        || has_port_hopping
        || has_obfuscation
    {
        anyhow::bail!(
            "benchmark socket2 override is limited to unpinned loopback HY2 endpoints without port hopping or obfuscation"
        );
    }
    #[cfg(target_os = "linux")]
    if has_socket_mark {
        anyhow::bail!("benchmark socket2 override does not support a socket mark");
    }
    Ok(())
}

impl Debug for Handler {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria2Handler")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
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
        let tls_config = RustlsClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verify))
            .with_no_client_auth();

        let core_client = HysteriaClient::new(
            tls_config,
            &opts.alpn,
            opts.password.clone(),
            opts.up,
            opts.down,
            opts.cwnd,
            opts.disable_mtu_discovery,
        )
        .expect("valid Hysteria 2 client transport configuration");

        Self {
            opts,
            core_client,
            next_session_id: AtomicU32::new(0),
            #[cfg(feature = "transport-bench-api")]
            bench_udp_receive_task_enabled: AtomicBool::new(true),
            #[cfg(feature = "transport-bench-api")]
            bench_socket2_abstract_socket: AtomicBool::new(false),
            conn: Mutex::new(Vec::new()),
            next_connection_index: AtomicUsize::new(0),
            connector: tokio::sync::RwLock::new(None),
            recovery_cancellation: tokio::sync::RwLock::new(
                tokio_util::sync::CancellationToken::new(),
            ),
            support_udp: RwLock::new(true),
        }
    }

    /// Toggle the idle HY2 UDP receive task for TCP-only benchmark ablations.
    /// Must be set before the first connection is opened.
    #[cfg(feature = "transport-bench-api")]
    pub fn set_udp_receive_task_for_bench(&self, enabled: bool) {
        self.bench_udp_receive_task_enabled
            .store(enabled, Ordering::Relaxed);
    }

    /// Use the standalone benchmark's socket2-to-Quinn setup for local HY2
    /// endpoint ablations. This is unavailable in product builds.
    #[cfg(feature = "transport-bench-api")]
    pub fn set_socket2_abstract_socket_for_bench(&self, enabled: bool) {
        self.bench_socket2_abstract_socket
            .store(enabled, Ordering::Relaxed);
    }

    fn should_spawn_udp_receive_task(&self) -> bool {
        #[cfg(feature = "transport-bench-api")]
        {
            self.bench_udp_receive_task_enabled.load(Ordering::Relaxed)
        }
        #[cfg(not(feature = "transport-bench-api"))]
        {
            true
        }
    }

    #[cfg(feature = "transport-bench-api")]
    fn should_use_socket2_abstract_socket_for_bench(&self) -> bool {
        self.bench_socket2_abstract_socket.load(Ordering::Relaxed)
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

    // connect and auth
    async fn new_authed_connection_inner(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
        hop_connector: Option<Arc<dyn RemoteConnector>>,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> anyhow::Result<(Vec<AuthenticatedConnection>, NetworkPoolContext)> {
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
                .new_authed_connection_to(
                    sess,
                    resolver.clone(),
                    connector,
                    hop_connector.clone(),
                    cancellation.clone(),
                    server_socket_addr,
                )
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

    #[cfg(feature = "transport-bench-api")]
    async fn socket2_abstract_udp_socket_for_bench(
        &self,
        sess: &Session,
        connector: &dyn RemoteConnector,
        server_socket_addr: SocketAddr,
    ) -> anyhow::Result<(Arc<dyn quinn::AsyncUdpSocket>, NetworkPoolContext)> {
        use quinn::Runtime;

        let requested_context =
            connector.connection_pool_context(sess.iface.as_ref()).await;
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(server_socket_addr),
            socket2::Type::DGRAM,
            None,
        )?;
        socket.set_broadcast(true)?;
        socket.set_nonblocking(true)?;
        let socket: std::net::UdpSocket = socket.into();
        let socket = tokio::net::UdpSocket::from_std(socket)?;
        let socket = socket.into_std()?;
        let socket = quinn::TokioRuntime.wrap_udp_socket(socket)?;
        let mut pool_context = requested_context;
        pool_context.generation_only_local_route = true;
        pool_context.direct_local_route_pooling_supported = true;
        Ok((socket, pool_context))
    }

    async fn new_authed_connection_to(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
        hop_connector: Option<Arc<dyn RemoteConnector>>,
        cancellation: tokio_util::sync::CancellationToken,
        server_socket_addr: SocketAddr,
    ) -> anyhow::Result<(Vec<AuthenticatedConnection>, NetworkPoolContext)> {
        #[cfg(feature = "transport-bench-api")]
        if self.should_use_socket2_abstract_socket_for_bench() {
            validate_socket2_abstract_socket_bench_context(
                server_socket_addr,
                sess.iface.is_some(),
                self.opts.ports.is_some(),
                self.opts.obfs.is_some(),
                #[cfg(target_os = "linux")]
                sess.so_mark.is_some(),
            )?;
        }

        let local_route_pooling_connector =
            if self.opts.obfs.is_none() && self.opts.ports.is_some() {
                hop_connector.as_deref()
            } else {
                Some(connector)
            };
        let supports_generation_only_local_route_pooling =
            local_route_pooling_connector.is_some_and(|connector| {
                connector.supports_generation_only_local_route_pooling()
            });
        let (udp_socket, mut pool_context): (
            Arc<dyn quinn::AsyncUdpSocket>,
            NetworkPoolContext,
        ) = if self.opts.obfs.is_none()
            && let Some(port_gen) = self.opts.ports.as_ref()
        {
            let hop_connector = hop_connector.clone().ok_or_else(|| {
                anyhow!("Hysteria2 port hopping requires a registered connector")
            })?;
            let requested_context = hop_connector
                .connection_pool_context(sess.iface.as_ref())
                .await;
            let (udp_hop, pool_context) =
                udp_hop::UdpHop::new(udp_hop::UdpHopOptions {
                    server_addr: server_socket_addr,
                    port_range: port_gen.clone(),
                    resolver,
                    connector: hop_connector.clone(),
                    iface: sess.iface.clone(),
                    #[cfg(target_os = "linux")]
                    so_mark: sess.so_mark,
                    udp_recv_buffer_size: self.opts.udp_recv_buffer_size,
                    requested_context,
                    connection_cancellation: cancellation,
                    interval: None,
                })
                .await?;
            (Arc::new(udp_hop), pool_context)
        } else {
            let bench_socket: Option<(
                Arc<dyn quinn::AsyncUdpSocket>,
                NetworkPoolContext,
            )> = {
                #[cfg(feature = "transport-bench-api")]
                {
                    if self.should_use_socket2_abstract_socket_for_bench() {
                        Some(
                            self.socket2_abstract_udp_socket_for_bench(
                                sess,
                                connector,
                                server_socket_addr,
                            )
                            .await?,
                        )
                    } else {
                        None
                    }
                }
                #[cfg(not(feature = "transport-bench-api"))]
                {
                    None
                }
            };
            if let Some(bench_socket) = bench_socket {
                bench_socket
            } else {
                let requested_context =
                    connector.connection_pool_context(sess.iface.as_ref()).await;
                let destination = SocksAddr::Ip(server_socket_addr);
                let native_socket = connector
                    .connect_quinn_udp_socket_with_recv_buffer_size_and_pool_context(
                        resolver.clone(),
                        None,
                        destination.clone(),
                        sess.iface.as_ref(),
                        #[cfg(target_os = "linux")]
                        sess.so_mark,
                        UdpSocketConnectOptions {
                            udp_recv_buffer_size: self.opts.udp_recv_buffer_size,
                            pool_context: requested_context.clone(),
                        },
                    )
                    .await?;
                let (socket, pool_context): (
                    Arc<dyn quinn::AsyncUdpSocket>,
                    NetworkPoolContext,
                ) = if let Some(native_socket) = native_socket {
                    native_socket
                } else {
                    let (datagram, pool_context) = connector
                        .connect_datagram_with_recv_buffer_size_and_pool_context(
                            resolver,
                            None,
                            destination,
                            sess.iface.as_ref(),
                            #[cfg(target_os = "linux")]
                            sess.so_mark,
                            UdpSocketConnectOptions {
                                udp_recv_buffer_size: self.opts.udp_recv_buffer_size,
                                pool_context: requested_context,
                            },
                        )
                        .await?;
                    (
                        ConnectorUdpSocket::new(datagram, server_socket_addr),
                        pool_context,
                    )
                };
                let socket = if let Some(Obfs::Salamander(salamander_obfs)) =
                    self.opts.obfs.as_ref()
                {
                    Arc::new(salamander::Salamander::with_inner(
                        socket,
                        salamander_obfs.key.to_vec(),
                    ))
                } else {
                    socket
                };
                (socket, pool_context)
            }
        };
        pool_context.network_generation = pool_context
            .path_id
            .as_ref()
            .map(|path| path.network_generation)
            .or(pool_context.network_generation);
        pool_context.direct_local_route_pooling_supported =
            supports_generation_only_local_route_pooling;
        tracing::trace!("hysteria2 connecting to server: {:?}", server_socket_addr);
        let authenticated = self
            .core_client
            .connect_many(
                udp_socket,
                server_socket_addr,
                self.opts.sni.as_deref().unwrap_or(""),
                self.opts.quic_connections,
            )
            .await?;
        let pool_context_connector =
            if self.opts.obfs.is_none() && self.opts.ports.is_some() {
                hop_connector.as_deref().unwrap_or(connector)
            } else {
                connector
            };
        let current_context = pool_context_connector
            .connection_pool_context(sess.iface.as_ref())
            .await;
        if !pool_context_is_current(
            &current_context,
            &pool_context,
            sess.iface.is_some(),
            supports_generation_only_local_route_pooling,
        ) {
            close_authenticated_connections(
                &authenticated,
                b"network path changed during Hysteria2 setup",
            );
            return Err(anyhow!(
                "network path changed while connecting to Hysteria2 endpoint"
            ));
        }

        let Some(first) = authenticated.first() else {
            return Err(anyhow!("Hysteria2 connection pool was empty"));
        };
        let supports_udp = first.supports_udp();
        let brutal_bps = first.brutal_bps();
        if authenticated.iter().any(|connection| {
            connection.supports_udp() != supports_udp
                || connection.brutal_bps() != brutal_bps
        }) {
            close_authenticated_connections(
                &authenticated,
                b"inconsistent Hysteria2 pool negotiation",
            );
            return Err(anyhow!(
                "Hysteria2 connections in one pool negotiated inconsistent UDP or congestion settings"
            ));
        }
        tracing::trace!("hysteria2 authentication successful, udp={}", supports_udp);
        *self.support_udp.write().unwrap() = supports_udp;

        Ok((authenticated, pool_context))
    }

    pub async fn new_authed_connection(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<Arc<HysteriaConnection>> {
        let connector =
            self.connector.read().await.clone().unwrap_or_else(|| {
                crate::proxy::utils::GLOBAL_DIRECT_CONNECTOR.clone()
            });
        self.new_authed_connection_using_connector(
            sess,
            resolver,
            connector.as_ref(),
            Some(connector.clone()),
            self.recovery_cancellation.read().await.clone(),
        )
        .await
    }

    /// Open a HY2 TCP stream without the normal chain metadata wrapper.
    ///
    /// This exists only for transport benchmarks that compare the core stream
    /// with the production `ChainedStreamWrapper` path. Product callers should
    /// use `OutboundHandler::connect_stream` so network-path metadata is kept.
    #[cfg(feature = "transport-bench-api")]
    pub async fn connect_stream_raw_for_bench(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<Box<dyn crate::proxy::ClientStream>> {
        let stream = self
            .connect_stream_concrete_for_bench(sess, resolver)
            .await?;
        Ok(Box::new(stream))
    }

    /// Open a HY2 stream as its concrete type for benchmark-only dispatch
    /// ablations. Product callers must use `OutboundHandler::connect_stream`
    /// so chain and network-path metadata are preserved.
    #[cfg(feature = "transport-bench-api")]
    pub async fn connect_stream_concrete_for_bench(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<chimera_hysteria2_core::Hy2TcpStream> {
        let conn = self.new_authed_connection(sess, resolver).await?;
        let stream = self
            .core_client
            .open_tcp_stream(&conn.authenticated, &sess.destination.to_string())
            .await?;
        Ok(stream)
    }

    async fn new_authed_connection_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> std::io::Result<Arc<HysteriaConnection>> {
        let hop_connector = self.connector.read().await.clone();
        let cancellation = self.recovery_cancellation.read().await.clone();
        self.new_authed_connection_using_connector(
            sess,
            resolver,
            connector,
            hop_connector,
            cancellation,
        )
        .await
    }

    async fn new_authed_connection_using_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
        hop_connector: Option<Arc<dyn RemoteConnector>>,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> std::io::Result<Arc<HysteriaConnection>> {
        // Acquire the per-handler pool lock *before* observing the network.
        // A waiting borrower must not authorize reuse using a snapshot taken
        // before another task finished (or retired) its QUIC connection.
        let mut quinn_conn_lock = self.conn.lock().await;
        let pool_connector = if self.opts.obfs.is_none() && self.opts.ports.is_some()
        {
            hop_connector.as_deref().unwrap_or(connector)
        } else {
            connector
        };
        let current_context = pool_connector
            .connection_pool_context(sess.iface.as_ref())
            .await;
        if cancellation.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "network changed before Hysteria2 pool checkout",
            ));
        }

        let supports_generation_only_local_route_pooling =
            pool_connector.supports_generation_only_local_route_pooling();
        let pool_is_current = quinn_conn_lock.len()
            == self.opts.quic_connections.get()
            && quinn_conn_lock.iter().all(|connection| {
                connection.conn.close_reason().is_none()
                    && pool_context_is_current(
                        &current_context,
                        &connection.pool_context,
                        sess.iface.is_some(),
                        supports_generation_only_local_route_pooling,
                    )
            });

        if pool_is_current {
            for connection in quinn_conn_lock.iter() {
                ensure_hysteria_connection_current(
                    &current_context,
                    &connection.pool_context,
                    &cancellation,
                    sess.iface.is_some(),
                    supports_generation_only_local_route_pooling,
                )?;
            }
            return Ok(select_hysteria_connection(
                &self.next_connection_index,
                &quinn_conn_lock,
            ));
        }

        for stale in std::mem::take(&mut *quinn_conn_lock) {
            stale
                .conn
                .close(quinn::VarInt::from_u32(0), b"network path retired");
            stale.udp_sessions.lock().await.clear();
        }

        let connecting = async {
            self.new_authed_connection_inner(
                sess,
                resolver,
                connector,
                hop_connector.clone(),
                cancellation.clone(),
            )
            .await
            .map_err(|error| {
                io::Error::other(format!(
                    "connect to {} failed: {error}",
                    self.opts.addr
                ))
            })
        };
        let (authenticated, pool_context) =
            cancel_on_network_change(cancellation.clone(), connecting).await?;

        // The QUIC dial (including authentication) can span a path
        // change that is observed before the cancellation signal.
        // Do not publish a stale connection into the reusable pool.
        let latest_context = pool_connector
            .connection_pool_context(sess.iface.as_ref())
            .await;
        if cancellation.is_cancelled()
            || !pool_context_is_current(
                &latest_context,
                &pool_context,
                sess.iface.is_some(),
                supports_generation_only_local_route_pooling,
            )
        {
            close_authenticated_connections(
                &authenticated,
                b"network path changed during QUIC dial",
            );
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "network path changed before Hysteria2 pool publication",
            ));
        }

        let mut connections = Vec::with_capacity(authenticated.len());
        for authenticated in authenticated {
            connections.push(
                HysteriaConnection::new_with_task_loop_and_udp_receiver(
                    Arc::new(authenticated),
                    self.opts.udp_mtu,
                    pool_context.clone(),
                    self.should_spawn_udp_receive_task(),
                ),
            );
        }
        *quinn_conn_lock = connections;
        Ok(select_hysteria_connection(
            &self.next_connection_index,
            &quinn_conn_lock,
        ))
    }
}

fn select_hysteria_connection(
    next_connection_index: &AtomicUsize,
    connections: &[Arc<HysteriaConnection>],
) -> Arc<HysteriaConnection> {
    let index =
        next_hysteria_connection_index(next_connection_index, connections.len());
    connections[index].clone()
}

fn next_hysteria_connection_index(
    next_connection_index: &AtomicUsize,
    connection_count: usize,
) -> usize {
    debug_assert!(connection_count > 0);
    next_connection_index.fetch_add(1, Ordering::Relaxed) % connection_count
}

fn close_authenticated_connections(
    connections: &[AuthenticatedConnection],
    reason: &[u8],
) {
    for connection in connections {
        connection
            .connection()
            .close(quinn::VarInt::from_u32(0), reason);
    }
}

pub struct HysteriaConnection {
    pub conn: Arc<quinn::Connection>,
    pub udp_sessions: Arc<tokio::sync::Mutex<HashMap<u32, UdpSession>>>,
    authenticated: Arc<AuthenticatedConnection>,
    pool_context: NetworkPoolContext,

    // config
    pub udp_mtu: Option<usize>,
}

impl HysteriaConnection {
    pub fn new_with_task_loop(
        authenticated: Arc<AuthenticatedConnection>,
        udp_mtu: Option<u32>,
        pool_context: NetworkPoolContext,
    ) -> Arc<Self> {
        Self::new_with_task_loop_and_udp_receiver(
            authenticated,
            udp_mtu,
            pool_context,
            true,
        )
    }

    fn new_with_task_loop_and_udp_receiver(
        authenticated: Arc<AuthenticatedConnection>,
        udp_mtu: Option<u32>,
        pool_context: NetworkPoolContext,
        spawn_udp_receiver: bool,
    ) -> Arc<Self> {
        let s = Arc::new(Self {
            conn: Arc::new(authenticated.connection().clone()),
            udp_sessions: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            udp_mtu: udp_mtu.map(|x| x as usize),
            authenticated,
            pool_context,
        });
        if spawn_udp_receiver {
            tokio::spawn(Self::spawn_tasks(s.clone()));
        }

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
        let disposition = {
            let mut udp_sessions = self.udp_sessions.lock().await;
            prepare_udp_delivery(&mut udp_sessions, pkt)
        };

        match disposition {
            UdpPacketDisposition::Delivery(delivery) => {
                tracing::trace!(
                    "hysteria2 found session {}, feeding packet",
                    session_id
                );
                tracing::trace!(
                    "hysteria2 complete packet received for session {}: {} bytes",
                    session_id,
                    delivery.packet.data.len(),
                );
                deliver_udp_packet(delivery, self.conn.closed()).await;
            }
            UdpPacketDisposition::FragmentBuffered => {
                tracing::trace!(
                    "hysteria2 packet fragment buffered for session {}",
                    session_id
                );
            }
            UdpPacketDisposition::MissingSession => {
                tracing::warn!("hysteria2 udp session not found: {}", session_id);
            }
        }
    }
}

struct PendingUdpDelivery {
    incoming: tokio::sync::mpsc::Sender<UdpPacket>,
    packet: UdpPacket,
}

enum UdpPacketDisposition {
    Delivery(PendingUdpDelivery),
    FragmentBuffered,
    MissingSession,
}

fn prepare_udp_delivery(
    udp_sessions: &mut HashMap<u32, UdpSession>,
    packet: codec::HysUdpPacket,
) -> UdpPacketDisposition {
    let Some(session) = udp_sessions.get_mut(&packet.session_id) else {
        return UdpPacketDisposition::MissingSession;
    };
    let Some(packet) = session.feed(packet) else {
        return UdpPacketDisposition::FragmentBuffered;
    };

    UdpPacketDisposition::Delivery(PendingUdpDelivery {
        incoming: session.incoming.clone(),
        packet: UdpPacket {
            data: packet.data,
            src_addr: packet.addr,
            dst_addr: session.local_addr.clone(),
            inbound_user: None,
        },
    })
}

async fn deliver_udp_packet(
    delivery: PendingUdpDelivery,
    connection_closed: impl Future,
) {
    tokio::select! {
        _ = connection_closed => {}
        result = delivery.incoming.send(delivery.packet) => {
            if result.is_err() {
                tracing::trace!("hysteria2 udp session receiver was dropped");
            }
        }
    }
}

#[cfg(test)]
mod udp_receive_tests {
    use std::{collections::HashMap, time::Duration};

    use super::{
        UdpPacketDisposition, codec, datagram::UdpSession, deliver_udp_packet,
        prepare_udp_delivery,
    };
    use crate::{proxy::datagram::UdpPacket, session::SocksAddr};

    #[tokio::test]
    async fn blocked_udp_delivery_releases_map_and_stops_after_connection_close() {
        let (incoming, _receiver) = tokio::sync::mpsc::channel(1);
        incoming
            .send(UdpPacket::default())
            .await
            .expect("fill the receive queue");

        let mut sessions = HashMap::new();
        sessions.insert(
            7,
            UdpSession {
                incoming,
                local_addr: SocksAddr::any_ipv4(),
                defragger: Default::default(),
            },
        );
        let session_map = tokio::sync::Mutex::new(sessions);
        let packet = codec::HysUdpPacket {
            session_id: 7,
            pkt_id: 1,
            frag_id: 0,
            frag_count: 1,
            addr: SocksAddr::any_ipv4(),
            data: vec![1, 2, 3],
        };
        let delivery = {
            let mut sessions = session_map.lock().await;
            match prepare_udp_delivery(&mut sessions, packet) {
                UdpPacketDisposition::Delivery(delivery) => delivery,
                UdpPacketDisposition::FragmentBuffered => {
                    panic!("single-fragment packet should be complete")
                }
                UdpPacketDisposition::MissingSession => {
                    panic!("test UDP session should exist")
                }
            }
        };

        let connection_closed = tokio_util::sync::CancellationToken::new();
        let cancel_delivery = connection_closed.clone();
        let delivery_task = tokio::spawn(async move {
            deliver_udp_packet(delivery, cancel_delivery.cancelled_owned()).await;
        });
        tokio::task::yield_now().await;
        assert!(
            !delivery_task.is_finished(),
            "delivery should wait while the receive queue is full"
        );

        tokio::time::timeout(Duration::from_secs(1), session_map.lock())
            .await
            .expect("blocked channel send must not retain the session map lock")
            .clear();
        connection_closed.cancel();
        tokio::time::timeout(Duration::from_secs(1), delivery_task)
            .await
            .expect("connection closure should release blocked UDP delivery")
            .expect("delivery task should not panic");
    }
}

fn ensure_hysteria_connection_current(
    current: &NetworkPoolContext,
    connected: &NetworkPoolContext,
    cancellation: &tokio_util::sync::CancellationToken,
    session_has_explicit_interface: bool,
    current_supports_generation_only_local_route_pooling: bool,
) -> io::Result<()> {
    if cancellation.is_cancelled()
        || !pool_context_is_current(
            current,
            connected,
            session_has_explicit_interface,
            current_supports_generation_only_local_route_pooling,
        )
    {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "network path changed before Hysteria2 pool publication",
        ));
    }
    Ok(())
}

fn pool_context_is_current(
    current: &NetworkPoolContext,
    cached: &NetworkPoolContext,
    session_has_explicit_interface: bool,
    current_supports_generation_only_local_route_pooling: bool,
) -> bool {
    if cached.generation_only_local_route {
        // Unknown connectors stay fail-closed. The current and cached contexts
        // must both explicitly identify a direct loopback-capable connector.
        return !session_has_explicit_interface
            && current_supports_generation_only_local_route_pooling
            && current.direct_local_route_pooling_supported
            && cached.direct_local_route_pooling_supported
            && cached.path_id.is_none()
            && current.network_generation == cached.network_generation;
    }
    // A missing physical path is not permission to bypass an explicit set of
    // eligible interfaces, except for a direct loopback route with no
    // physical interface identity.
    current.permits(cached.network_generation, cached.path_id.as_ref())
}

async fn cancel_on_network_change<T>(
    cancellation: tokio_util::sync::CancellationToken,
    future: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<T> {
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "network changed during Hysteria2 connection setup",
        )),
        result = future => result,
    }
}

#[async_trait::async_trait]
impl DialWithConnector for Handler {
    async fn register_connector(&self, connector: Arc<dyn RemoteConnector>) {
        *self.connector.write().await = Some(connector);
    }
}

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

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::All
    }

    async fn reset_connection_pool(&self) -> io::Result<u32> {
        let cancellation = self.recovery_cancellation.read().await.clone();
        cancellation.cancel();
        let cached = std::mem::take(&mut *self.conn.lock().await);
        let count = cached.len();
        for cached in cached {
            cached
                .conn
                .close(quinn::VarInt::from_u32(0), b"network changed");
            cached.udp_sessions.lock().await.clear();
        }
        *self.recovery_cancellation.write().await =
            tokio_util::sync::CancellationToken::new();
        u32::try_from(count)
            .map_err(|_| io::Error::other("Hysteria2 pool size exceeds reset count"))
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let conn = self.new_authed_connection(sess, resolver).await?;
        let stream = self
            .core_client
            .open_tcp_stream(&conn.authenticated, &sess.destination.to_string())
            .await?;
        let chained = ChainedStreamWrapper::new_with_network_path_id(
            Box::new(stream),
            conn.pool_context.path_id.clone(),
        );
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
        let pool_context = authed_conn.pool_context.clone();
        let hy_datagram = authed_conn.connect_udp(sess, next_session_id).await;
        let hy_datagram =
            observe_proxy_target_datagram(Box::new(hy_datagram), &pool_context);
        let s = ChainedDatagramWrapper::new_with_network_path_id(
            hy_datagram,
            pool_context.path_id.clone(),
        );
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        let conn = self
            .new_authed_connection_with_connector(sess, resolver, connector)
            .await?;
        let stream = self
            .core_client
            .open_tcp_stream(&conn.authenticated, &sess.destination.to_string())
            .await?;
        let chained = ChainedStreamWrapper::new_with_network_path_id(
            Box::new(stream),
            conn.pool_context.path_id.clone(),
        );
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedDatagram> {
        let conn = self
            .new_authed_connection_with_connector(sess, resolver, connector)
            .await?;
        let next_session_id = self
            .next_session_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let pool_context = conn.pool_context.clone();
        let datagram = conn.connect_udp(sess, next_session_id).await;
        let datagram =
            observe_proxy_target_datagram(Box::new(datagram), &pool_context);
        let chained = ChainedDatagramWrapper::new_with_network_path_id(
            datagram,
            pool_context.path_id.clone(),
        );
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }
}

#[cfg(all(test, docker_test, throughput_test))]
mod e2e {
    use std::{io::Write as _, sync::Arc, time::Duration};

    use anyhow::Context as _;
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

    async fn fill_udp_receive_queue(
        datagram: &mut BoxedChainedDatagram,
        pool: &[Arc<HysteriaConnection>],
        target: &str,
        session_id: u32,
    ) -> anyhow::Result<()> {
        let destination =
            format!("{target}:{UDP_ECHO_PORT}").parse::<SocksAddr>()?;
        for sequence in 0..40u32 {
            datagram
                .send(UdpPacket {
                    data: sequence.to_be_bytes().to_vec(),
                    dst_addr: destination.clone(),
                    ..Default::default()
                })
                .await?;
        }

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                for connection in pool {
                    let sessions = connection.udp_sessions.lock().await;
                    if let Some(session) = sessions.get(&session_id)
                        && session.incoming.capacity() == 0
                    {
                        return Ok(());
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("UDP echo did not fill the receive queue")?
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
                    up: None,
                    down: None,
                    cwnd: None,
                    udp_mtu: None,
                    quic_connections: std::num::NonZeroUsize::new(4)
                        .expect("four is non-zero"),
                    udp_recv_buffer_size: None,
                }));
                let resolver = config_helper::build_dns_resolver().await?;
                let session = Session::default();

                let _first =
                    connect_until_ready(&handler, &session, resolver.clone()).await?;
                let first_pool = handler.conn.lock().await.clone();
                anyhow::ensure!(
                    first_pool.len() == 4,
                    "hysteria2 did not establish the requested four-connection pool"
                );
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
                fill_udp_receive_queue(&mut first_udp, &first_pool, &echo_ip, 0)
                    .await?;
                let mut pre_reset_udp_sessions = 0;
                for connection in &first_pool {
                    pre_reset_udp_sessions +=
                        connection.udp_sessions.lock().await.len();
                }
                anyhow::ensure!(
                    pre_reset_udp_sessions == 1,
                    "hysteria2 did not register exactly one pre-reset UDP session"
                );
                let cached = handler
                    .new_authed_connection(&session, resolver.clone())
                    .await?;
                anyhow::ensure!(
                    first_pool.iter().any(|connection| Arc::ptr_eq(connection, &cached)),
                    "hysteria2 did not reuse a connection from the authenticated pool"
                );

                let reset_count = tokio::time::timeout(
                    Duration::from_secs(2),
                    handler.reset_connection_pool(),
                )
                .await??;
                anyhow::ensure!(
                    reset_count == 4,
                    "network reset did not invalidate all four cached hysteria2 connections"
                );
                tokio::time::timeout(Duration::from_secs(2), async {
                    while first_pool
                        .iter()
                        .any(|connection| connection.conn.close_reason().is_none())
                    {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await?;
                for connection in &first_pool {
                    anyhow::ensure!(
                        connection.udp_sessions.lock().await.is_empty(),
                        "network reset retained an old hysteria2 UDP session"
                    );
                }
                tokio::time::timeout(Duration::from_secs(2), async {
                    while first_udp.next().await.is_some() {}
                })
                .await
                .context("old Hysteria UDP session did not close after reset")?;

                let mut second_udp =
                    connect_udp_datagram(handler.clone(), resolver.clone(), &echo_ip).await?;
                udp_echo_roundtrip(
                    &mut second_udp,
                    &echo_ip,
                    b"hysteria2-udp-after-reset",
                )
                .await
                .map_err(|error| anyhow::anyhow!("post-reset UDP roundtrip failed: {error:#}"))?;
                let replacement_pool = handler.conn.lock().await.clone();
                anyhow::ensure!(
                    replacement_pool.len() == 4,
                    "hysteria2 did not recreate the four-connection pool after reset"
                );
                anyhow::ensure!(
                    replacement_pool.iter().all(|replacement| {
                        first_pool.iter().all(|old| !Arc::ptr_eq(old, replacement))
                    }),
                    "hysteria2 reused a connection closed by network reset"
                );
                anyhow::ensure!(
                    replacement_pool
                        .iter()
                        .all(|replacement| replacement.conn.close_reason().is_none()),
                    "a replacement hysteria2 connection was already closed"
                );
                anyhow::ensure!(
                    replacement_pool[0].udp_sessions.lock().await.len() == 1,
                    "replacement hysteria2 pool did not register a new UDP session"
                );
                tcp_echo_roundtrip(handler.clone(), resolver.clone(), &echo_ip)
                    .await
                    .map_err(|error| anyhow::anyhow!("post-reset TCP roundtrip failed: {error:#}"))?;

                let second_cached = handler.new_authed_connection(&session, resolver).await?;
                anyhow::ensure!(
                    replacement_pool
                        .iter()
                        .any(|connection| Arc::ptr_eq(connection, &second_cached)),
                    "replacement hysteria2 connection pool was not reused"
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

#[cfg(test)]
mod network_path_tests {
    use std::{
        net::Ipv4Addr,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };

    use super::*;
    use crate::app::flow::{AddressFamily, InterfaceId, NetworkPathId};
    use crate::config::internal::proxy::OutboundHysteria2;

    #[cfg(feature = "transport-bench-api")]
    #[test]
    fn benchmark_socket2_override_rejects_nonlocal_or_pinned_contexts() {
        let loopback = SocketAddr::from(([127, 0, 0, 1], 443));
        let public = SocketAddr::from(([192, 0, 2, 10], 443));
        let validate =
            |address, has_interface, has_port_hopping, has_obfuscation| {
                validate_socket2_abstract_socket_bench_context(
                    address,
                    has_interface,
                    has_port_hopping,
                    has_obfuscation,
                    #[cfg(target_os = "linux")]
                    false,
                )
            };

        assert!(validate(loopback, false, false, false).is_ok());
        assert!(validate(public, false, false, false).is_err());
        assert!(validate(loopback, true, false, false).is_err());
        assert!(validate(loopback, false, true, false).is_err());
        assert!(validate(loopback, false, false, true).is_err());
        #[cfg(target_os = "linux")]
        assert!(
            validate_socket2_abstract_socket_bench_context(
                loopback, false, false, false, true
            )
            .is_err()
        );
    }

    #[test]
    fn hysteria_config_preserves_independent_bandwidth_limits() {
        crate::setup_default_crypto_provider();

        for (up, down) in [
            (Some(8_000_000), None),
            (None, Some(12_000_000)),
            (Some(8_000_000), Some(12_000_000)),
            (None, None),
        ] {
            let handler: Handler = OutboundHysteria2 {
                name: "hy2-bandwidth-test".to_owned(),
                server: "127.0.0.1".to_owned(),
                port: 443,
                password: "test".to_owned(),
                up,
                down,
                ..Default::default()
            }
            .try_into()
            .expect("Hysteria2 config should convert");

            assert_eq!(handler.opts.up, up);
            assert_eq!(handler.opts.down, down);
            assert_eq!(handler.opts.quic_connections.get(), 1);
        }
    }

    #[test]
    fn hysteria_config_preserves_optional_udp_receive_buffer_size() {
        crate::setup_default_crypto_provider();

        for size in [None, Some(1024 * 1024), Some(4 * 1024 * 1024)] {
            let handler: Handler = OutboundHysteria2 {
                name: "hy2-receive-buffer-test".to_owned(),
                server: "127.0.0.1".to_owned(),
                port: 443,
                password: "test".to_owned(),
                udp_recv_buffer_size: size,
                ..Default::default()
            }
            .try_into()
            .expect("Hysteria2 receive buffer config should convert");

            assert_eq!(handler.opts.udp_recv_buffer_size, size);
        }
    }

    #[test]
    fn hysteria_connection_selection_is_round_robin() {
        let next = AtomicUsize::new(0);
        let connection_count = NonZeroUsize::new(4).expect("four is non-zero");
        let selected = (0..9)
            .map(|_| next_hysteria_connection_index(&next, connection_count.get()))
            .collect::<Vec<_>>();

        assert_eq!(selected, [0, 1, 2, 3, 0, 1, 2, 3, 0]);
    }

    fn path(name: &str, index: u32, address: Ipv4Addr) -> NetworkPathId {
        NetworkPathId {
            interface: InterfaceId {
                name: name.to_owned(),
                index,
            },
            family: AddressFamily::Ipv4,
            source_address: Some(address.into()),
            network_generation: 7,
        }
    }

    #[test]
    fn hysteria_connection_reuse_requires_a_current_eligible_path() {
        let wifi = path("wifi0", 4, Ipv4Addr::new(192, 0, 2, 10));
        let ethernet = path("eth0", 5, Ipv4Addr::new(198, 51, 100, 10));
        let current = NetworkPoolContext {
            network_generation: Some(7),
            path_id: None,
            eligible_path_ids: Some([ethernet.clone()].into_iter().collect()),
            generation_only_local_route: false,
            direct_local_route_pooling_supported: false,
            reporter: None,
        };

        assert!(!pool_context_is_current(
            &current,
            &NetworkPoolContext {
                network_generation: Some(7),
                path_id: Some(wifi),
                ..Default::default()
            },
            false,
            false,
        ));
        assert!(pool_context_is_current(
            &current,
            &NetworkPoolContext {
                network_generation: Some(7),
                path_id: Some(ethernet.clone()),
                ..Default::default()
            },
            false,
            false,
        ));
        assert!(!pool_context_is_current(
            &current,
            &NetworkPoolContext {
                network_generation: Some(6),
                path_id: Some(ethernet),
                ..Default::default()
            },
            false,
            false,
        ));
    }

    #[test]
    fn s04bq_hysteria_unreported_path_must_not_bypass_observed_candidates() {
        let reported = path("actual0", 3, Ipv4Addr::new(192, 0, 2, 10));
        let current = NetworkPoolContext {
            network_generation: Some(7),
            path_id: None,
            eligible_path_ids: Some([reported.clone()].into_iter().collect()),
            generation_only_local_route: false,
            direct_local_route_pooling_supported: false,
            reporter: None,
        };
        let unreported = NetworkPoolContext {
            network_generation: Some(7),
            path_id: None,
            ..Default::default()
        };
        assert!(!pool_context_is_current(
            &current,
            &unreported,
            false,
            false
        ));
        // Older, non-path-aware connectors remain generation-only.
        let generation_only = NetworkPoolContext::for_generation(Some(7));
        assert!(pool_context_is_current(
            &generation_only,
            &unreported,
            false,
            false,
        ));
        assert!(pool_context_is_current(
            &current,
            &NetworkPoolContext {
                network_generation: Some(7),
                path_id: Some(reported),
                ..Default::default()
            },
            false,
            false,
        ));
    }

    #[test]
    fn hysteria_loopback_route_uses_generation_scoped_pooling() {
        let physical = path("eth0", 5, Ipv4Addr::new(198, 51, 100, 10));
        let current = NetworkPoolContext {
            network_generation: Some(7),
            path_id: None,
            eligible_path_ids: Some([physical].into_iter().collect()),
            generation_only_local_route: false,
            direct_local_route_pooling_supported: true,
            reporter: None,
        };
        let loopback = NetworkPoolContext {
            network_generation: Some(7),
            generation_only_local_route: true,
            direct_local_route_pooling_supported: true,
            ..Default::default()
        };

        assert!(pool_context_is_current(&current, &loopback, false, true));
        assert!(!pool_context_is_current(&current, &loopback, true, true));
        // A third-party connector may delegate to DirectConnector and return
        // its context, but its default trait capability remains fail-closed.
        assert!(!pool_context_is_current(&current, &loopback, false, false));
        assert!(!pool_context_is_current(
            &NetworkPoolContext {
                direct_local_route_pooling_supported: false,
                ..current.clone()
            },
            &loopback,
            false,
            true,
        ));
        assert!(!pool_context_is_current(
            &NetworkPoolContext {
                network_generation: Some(8),
                ..current.clone()
            },
            &loopback,
            false,
            true,
        ));
        assert!(!pool_context_is_current(
            &current,
            &NetworkPoolContext {
                generation_only_local_route: false,
                ..loopback
            },
            false,
            true,
        ));
    }

    #[tokio::test]
    async fn s04bq_hysteria_dial_epoch_and_cancellation_checked_before_publication()
    {
        use std::sync::atomic::AtomicU64;
        let epoch = Arc::new(AtomicU64::new(7));
        let epoch_on_wire = epoch.clone();
        let token = tokio_util::sync::CancellationToken::new();
        let (started, arrived) = tokio::sync::oneshot::channel();
        let (release, go) = tokio::sync::oneshot::channel::<()>();
        let dial = tokio::spawn(async move {
            started.send(()).unwrap();
            go.await.unwrap();
            NetworkPoolContext::for_generation(Some(
                epoch_on_wire.load(Ordering::SeqCst),
            ))
        });
        arrived.await.unwrap();
        // A dial was already in flight when the network generation changed.
        epoch.store(8, Ordering::SeqCst);
        release.send(()).unwrap();
        let connected = NetworkPoolContext::for_generation(Some(7));
        let latest = dial.await.unwrap();
        let err = ensure_hysteria_connection_current(
            &latest, &connected, &token, false, false,
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
        assert!(
            ensure_hysteria_connection_current(
                &connected, &connected, &token, false, false,
            )
            .is_ok()
        );
        token.cancel();
        let err = ensure_hysteria_connection_current(
            &connected, &connected, &token, false, false,
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
    }

    #[tokio::test]
    async fn s04bq_repeated_inflight_cancellation_releases_pending_dials() {
        for _ in 0..32 {
            let cancellation = tokio_util::sync::CancellationToken::new();
            let dropped = Arc::new(AtomicBool::new(false));
            let witness = dropped.clone();
            let (entered, started) = tokio::sync::oneshot::channel::<()>();
            let dial = async move {
                struct Witness(Arc<AtomicBool>);
                impl Drop for Witness {
                    fn drop(&mut self) {
                        self.0.store(true, Ordering::SeqCst);
                    }
                }
                let _witness = Witness(witness);
                let _ = entered.send(());
                std::future::pending::<io::Result<()>>().await
            };
            let cancel = cancellation.clone();
            let task =
                tokio::spawn(
                    async move { cancel_on_network_change(cancel, dial).await },
                );
            started.await.unwrap();
            cancellation.cancel();
            let err = tokio::time::timeout(std::time::Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::Interrupted);
            assert!(dropped.load(Ordering::SeqCst));
        }
    }

    #[tokio::test]
    async fn network_reset_cancels_an_inflight_hysteria_dial() {
        struct DropFlag(Arc<AtomicBool>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let cancellation = tokio_util::sync::CancellationToken::new();
        let dropped = Arc::new(AtomicBool::new(false));
        let dial_dropped = dropped.clone();
        let dial = async move {
            let _drop_flag = DropFlag(dial_dropped);
            std::future::pending::<io::Result<()>>().await
        };
        let task =
            tokio::spawn(cancel_on_network_change(cancellation.clone(), dial));
        tokio::task::yield_now().await;
        cancellation.cancel();

        let error = task.await.unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(dropped.load(Ordering::SeqCst));
    }
}
