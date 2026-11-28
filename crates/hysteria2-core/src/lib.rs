//! Minimal Hysteria 2 client transport core.
//!
//! The crate owns QUIC/H3 authentication, congestion control and TCP stream
//! framing. Callers provide the already-configured TLS client and UDP socket;
//! DNS, socket selection, port hopping and proxy-session policy stay in the
//! calling application.

mod congestion;
mod tcp_codec;

use std::{
    io,
    net::SocketAddr,
    num::NonZeroUsize,
    pin::Pin,
    str::FromStr,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{Context as _, anyhow};
use bytes::Bytes;
use congestion::{Brutal, DynCongestion, DynController};
use futures::{SinkExt, StreamExt};
use h3::client::SendRequest;
use h3_quinn::OpenStreams;
use quinn::{
    AsyncUdpSocket, ClientConfig, Connection, EndpointConfig, TokioRuntime,
    crypto::rustls::QuicClientConfig,
};
use quinn_proto::TransportConfig;
use rustls::ClientConfig as RustlsClientConfig;
use tcp_codec::Hy2TcpCodec;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    task::JoinHandle,
};
use tracing::{debug, warn};

/// Server-selected receive congestion-control hint from the Hysteria auth reply.
#[derive(Debug, Copy, Clone)]
pub enum ServerCcRx {
    Auto,
    Fixed(u64),
}

impl FromStr for ServerCcRx {
    type Err = std::num::ParseIntError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.eq_ignore_ascii_case("auto") {
            Ok(Self::Auto)
        } else {
            Ok(Self::Fixed(value.parse::<u64>()?))
        }
    }
}

/// Protocol-level Hysteria 2 client configuration, independent of Clash.
pub struct HysteriaClient {
    endpoint_config: EndpointConfig,
    client_config: ClientConfig,
    password: String,
    up_bps: Option<u64>,
    down_bps: Option<u64>,
}

impl HysteriaClient {
    /// Build the QUIC configuration around a caller-provided TLS verifier.
    pub fn new(
        mut tls_config: RustlsClientConfig,
        alpn: &[String],
        password: String,
        up_bps: Option<u64>,
        down_bps: Option<u64>,
        cwnd_packets: Option<u64>,
        disable_mtu_discovery: bool,
    ) -> anyhow::Result<Self> {
        tls_config.alpn_protocols = if alpn.is_empty() {
            vec![b"h3".to_vec()]
        } else {
            alpn.iter().map(|value| value.as_bytes().to_vec()).collect()
        };

        let mut transport = TransportConfig::default();
        #[cfg(target_os = "android")]
        transport.enable_segmentation_offload(false);
        if disable_mtu_discovery {
            transport.mtu_discovery_config(None);
        }
        transport.congestion_controller_factory(Arc::new(DynCongestion::new(
            cwnd_packets,
        )));
        transport.max_idle_timeout(Some(
            Duration::from_secs(300)
                .try_into()
                .context("convert Hysteria idle timeout")?,
        ));
        transport.keep_alive_interval(Some(Duration::from_secs(10)));

        let quic_config: QuicClientConfig = tls_config
            .try_into()
            .context("convert rustls client config for Quinn")?;
        let mut client_config = ClientConfig::new(Arc::new(quic_config));
        client_config.transport_config(Arc::new(transport));

        Ok(Self {
            endpoint_config: EndpointConfig::default(),
            client_config,
            password,
            up_bps,
            down_bps,
        })
    }

    /// Connect and authenticate over a caller-selected Quinn UDP socket.
    pub async fn connect(
        &self,
        udp_socket: Arc<dyn AsyncUdpSocket>,
        server_addr: SocketAddr,
        server_name: &str,
    ) -> anyhow::Result<AuthenticatedConnection> {
        let mut endpoint = self.new_endpoint(udp_socket)?;
        self.connect_on_endpoint(&mut endpoint, server_addr, server_name)
            .await
    }

    /// Connect and authenticate several QUIC sessions on one Endpoint/socket.
    ///
    /// If a later session fails, earlier sessions are closed before returning
    /// the error so callers never publish a partial connection pool.
    pub async fn connect_many(
        &self,
        udp_socket: Arc<dyn AsyncUdpSocket>,
        server_addr: SocketAddr,
        server_name: &str,
        connection_count: NonZeroUsize,
    ) -> anyhow::Result<Vec<AuthenticatedConnection>> {
        let mut endpoint = self.new_endpoint(udp_socket)?;
        let mut authenticated = Vec::with_capacity(connection_count.get());

        for index in 0..connection_count.get() {
            match self
                .connect_on_endpoint(&mut endpoint, server_addr, server_name)
                .await
            {
                Ok(connection) => authenticated.push(connection),
                Err(error) => {
                    for connection in &authenticated {
                        connection.connection().close(
                            quinn::VarInt::from_u32(0),
                            b"connection pool setup failed",
                        );
                    }
                    return Err(error.context(format!(
                        "establish Hysteria 2 connection {} of {}",
                        index + 1,
                        connection_count
                    )));
                }
            }
        }

        Ok(authenticated)
    }

    /// Create a configured Quinn endpoint around a caller-selected UDP socket.
    ///
    /// Reusing one endpoint for several connections keeps its socket and packet
    /// receive driver shared while allowing each QUIC connection to retain its
    /// own protocol state.
    pub fn new_endpoint(
        &self,
        udp_socket: Arc<dyn AsyncUdpSocket>,
    ) -> anyhow::Result<quinn::Endpoint> {
        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            self.endpoint_config.clone(),
            None,
            udp_socket,
            Arc::new(TokioRuntime),
        )?;
        endpoint.set_default_client_config(self.client_config.clone());
        Ok(endpoint)
    }

    /// Connect through a native Quinn UDP socket for standalone measurements.
    /// Production adapters should use [`Self::connect`] to preserve their
    /// interface, mark, port-hopping, and socket-protection policies.
    pub async fn connect_direct(
        &self,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
        server_name: &str,
    ) -> anyhow::Result<AuthenticatedConnection> {
        let mut endpoint = self.new_direct_endpoint(local_addr)?;
        self.connect_on_endpoint(&mut endpoint, server_addr, server_name)
            .await
    }

    /// Create a configured Quinn endpoint using Quinn's native UDP socket.
    pub fn new_direct_endpoint(
        &self,
        local_addr: SocketAddr,
    ) -> io::Result<quinn::Endpoint> {
        let mut endpoint = quinn::Endpoint::client(local_addr)?;
        endpoint.set_default_client_config(self.client_config.clone());
        Ok(endpoint)
    }

    /// Connect and authenticate on an existing endpoint.
    ///
    /// This permits several independent QUIC connections to share one UDP
    /// socket and endpoint driver, which is useful for connection pools and
    /// controlled transport benchmarks.
    pub async fn connect_on_endpoint(
        &self,
        endpoint: &mut quinn::Endpoint,
        server_addr: SocketAddr,
        server_name: &str,
    ) -> anyhow::Result<AuthenticatedConnection> {
        endpoint.set_default_client_config(self.client_config.clone());

        let connection = endpoint.connect(server_addr, server_name)?.await?;
        tracing::trace!(%server_addr, "Hysteria 2 QUIC connection established");
        let pending_connection = connection.clone();
        let mut cleanup = PendingConnectionGuard::new(move || {
            pending_connection.close(
                quinn_proto::VarInt::from_u32(0),
                b"connection setup interrupted",
            );
        });

        let h3_connection = h3_quinn::Connection::new(connection.clone());
        let (mut driver, mut sender) = h3::client::builder()
            .build::<_, _, Bytes>(h3_connection)
            .await?;
        let driver_task = tokio::spawn(async move {
            let error = driver.wait_idle().await;
            tracing::debug!("Hysteria 2 H3 driver ended: {error}");
        });
        cleanup.set_driver_task(driver_task);

        let auth_result =
            authenticate(&mut sender, &self.password, self.down_bps).await;
        let (server_cc_rx, supports_udp) = match auth_result {
            Ok(result) => result,
            Err(error) => return Err(error),
        };

        let brutal_bps = select_brutal_bps(self.up_bps, server_cc_rx);
        if let Some(brutal_bps) = brutal_bps {
            match connection
                .congestion_state()
                .into_any()
                .downcast::<DynController>()
            {
                Ok(controller) => {
                    controller.set_controller(Box::new(Brutal::new(brutal_bps)));
                    debug!(
                        brutal_bps,
                        "Hysteria 2 enabled Brutal congestion control"
                    );
                }
                Err(_) => warn!(
                    "Hysteria 2 failed to switch congestion controller to Brutal"
                ),
            }
        }

        let driver_task = cleanup.disarm();
        Ok(AuthenticatedConnection {
            connection,
            h3_sender: Mutex::new(Some(sender)),
            driver_task: Mutex::new(Some(driver_task)),
            server_cc_rx,
            supports_udp,
            brutal_bps,
        })
    }

    /// Open one Hysteria TCP stream for a textual `host:port` destination.
    pub async fn open_tcp_stream(
        &self,
        connection: &AuthenticatedConnection,
        destination: &str,
    ) -> io::Result<Hy2TcpStream> {
        let (mut send, mut recv) = connection.connection.open_bi().await?;
        tokio_util::codec::FramedWrite::new(&mut send, Hy2TcpCodec)
            .send(destination)
            .await?;

        match tokio_util::codec::FramedRead::new(&mut recv, Hy2TcpCodec)
            .next()
            .await
        {
            Some(Ok(response)) if response.status == 0 => {}
            Some(Ok(response)) => {
                return Err(io::Error::other(format!(
                    "Hysteria 2 server rejected stream: status={}, message={}",
                    response.status, response.msg
                )));
            }
            Some(Err(error)) => return Err(error),
            None => {
                return Err(io::Error::other(
                    "Hysteria 2 server closed stream before response",
                ));
            }
        }

        Ok(Hy2TcpStream { send, recv })
    }
}

struct PendingConnectionGuard<F: FnOnce()> {
    cleanup: Option<F>,
    driver_task: Option<JoinHandle<()>>,
}

impl<F: FnOnce()> PendingConnectionGuard<F> {
    fn new(cleanup: F) -> Self {
        Self {
            cleanup: Some(cleanup),
            driver_task: None,
        }
    }

    fn set_driver_task(&mut self, driver_task: JoinHandle<()>) {
        self.driver_task = Some(driver_task);
    }

    fn disarm(mut self) -> JoinHandle<()> {
        self.cleanup.take();
        self.driver_task
            .take()
            .expect("authenticated Hysteria 2 connection has an H3 driver")
    }
}

impl<F: FnOnce()> Drop for PendingConnectionGuard<F> {
    fn drop(&mut self) {
        if let Some(cleanup) = self.cleanup.take() {
            cleanup();
        }
        if let Some(driver_task) = self.driver_task.take() {
            driver_task.abort();
        }
    }
}

/// An authenticated QUIC/H3 connection shared by TCP and UDP adapters.
pub struct AuthenticatedConnection {
    connection: Connection,
    // The auth sender keeps the H3 control connection alive for the QUIC
    // session. Data streams use QUIC directly after authentication.
    h3_sender: Mutex<Option<SendRequest<OpenStreams, Bytes>>>,
    driver_task: Mutex<Option<JoinHandle<()>>>,
    server_cc_rx: ServerCcRx,
    supports_udp: bool,
    brutal_bps: Option<u64>,
}

impl AuthenticatedConnection {
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub fn server_cc_rx(&self) -> ServerCcRx {
        self.server_cc_rx
    }

    pub fn supports_udp(&self) -> bool {
        self.supports_udp
    }

    pub fn brutal_bps(&self) -> Option<u64> {
        self.brutal_bps
    }
}

impl Drop for AuthenticatedConnection {
    fn drop(&mut self) {
        self.connection.close(
            quinn_proto::VarInt::from_u32(0),
            b"authenticated connection released",
        );
        if let Ok(task) = self.driver_task.get_mut()
            && let Some(task) = task.take()
        {
            task.abort();
        }
        // Keep this field explicit: dropping the H3 sender releases the auth
        // request stream after the connection has been retired.
        if let Ok(sender) = self.h3_sender.get_mut() {
            sender.take();
        }
    }
}

async fn authenticate(
    sender: &mut SendRequest<OpenStreams, Bytes>,
    password: &str,
    down_bps: Option<u64>,
) -> anyhow::Result<(ServerCcRx, bool)> {
    let request = http::Request::post("https://hysteria/auth")
        .header("Hysteria-Auth", password)
        .header("Hysteria-CC-RX", down_bps.unwrap_or_default().to_string())
        .header("Hysteria-Padding", tcp_codec::padding(64..=512))
        .body(())?;
    let mut response = sender.send_request(request).await?;
    response.finish().await?;
    let response = response.recv_response().await?;

    const HYSTERIA_STATUS_OK: u16 = 233;
    if response.status() != HYSTERIA_STATUS_OK {
        return Err(anyhow!(
            "Hysteria 2 auth failed: response status code {}",
            response.status()
        ));
    }

    let server_cc_rx = response
        .headers()
        .get("Hysteria-CC-RX")
        .context("Hysteria 2 auth reply is missing Hysteria-CC-RX")?
        .to_str()?
        .parse()?;
    let supports_udp = response
        .headers()
        .get("Hysteria-UDP")
        .context("Hysteria 2 auth reply is missing Hysteria-UDP")?
        .to_str()?
        .parse()?;
    Ok((server_cc_rx, supports_udp))
}

fn select_brutal_bps(
    max_tx_bps: Option<u64>,
    server_cc_rx: ServerCcRx,
) -> Option<u64> {
    let max_tx_bps = max_tx_bps.unwrap_or_default();
    let actual_tx_bps = match server_cc_rx {
        ServerCcRx::Auto => return None,
        ServerCcRx::Fixed(server_rx_bps)
            if server_rx_bps == 0 || server_rx_bps > max_tx_bps =>
        {
            max_tx_bps
        }
        ServerCcRx::Fixed(server_rx_bps) => server_rx_bps,
    };

    (actual_tx_bps > 0).then_some(actual_tx_bps)
}

/// Bidirectional QUIC stream returned by the Hysteria TCP stream handshake.
pub struct Hy2TcpStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl std::fmt::Debug for Hy2TcpStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Hy2TcpStream").finish()
    }
}

impl AsyncRead for Hy2TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for Hy2TcpStream {
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

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    #[cfg(feature = "aws-lc-rs")]
    use super::HysteriaClient;
    use super::{PendingConnectionGuard, ServerCcRx, select_brutal_bps};
    #[cfg(feature = "aws-lc-rs")]
    use bytes::Bytes;

    #[test]
    fn server_cc_rx_accepts_auto_and_fixed_rate() {
        assert!(matches!("auto".parse::<ServerCcRx>(), Ok(ServerCcRx::Auto)));
        assert!(matches!(
            "120000000".parse::<ServerCcRx>(),
            Ok(ServerCcRx::Fixed(120_000_000))
        ));
        assert!("invalid".parse::<ServerCcRx>().is_err());
    }

    #[test]
    fn brutal_rate_matches_peer_limits() {
        assert_eq!(select_brutal_bps(Some(10), ServerCcRx::Auto), None);
        assert_eq!(select_brutal_bps(Some(10), ServerCcRx::Fixed(8)), Some(8));
        assert_eq!(select_brutal_bps(Some(10), ServerCcRx::Fixed(12)), Some(10));
        assert_eq!(select_brutal_bps(Some(10), ServerCcRx::Fixed(0)), Some(10));
        assert_eq!(select_brutal_bps(None, ServerCcRx::Fixed(8)), None);
        assert_eq!(select_brutal_bps(None, ServerCcRx::Fixed(0)), None);
    }

    #[tokio::test]
    async fn pending_connection_guard_closes_and_aborts_on_drop() {
        let cleaned_up = Arc::new(AtomicBool::new(false));
        let cleanup_flag = cleaned_up.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let driver_task = tokio::spawn(async move {
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        started_rx.await.expect("driver task started");
        let driver_abort = driver_task.abort_handle();

        let mut guard = PendingConnectionGuard::new(move || {
            cleanup_flag.store(true, Ordering::SeqCst);
        });
        guard.set_driver_task(driver_task);
        drop(guard);

        assert!(cleaned_up.load(Ordering::SeqCst));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !driver_abort.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropping the pending connection guard aborts its H3 driver");
    }

    #[cfg(feature = "aws-lc-rs")]
    async fn run_second_auth_pool_scenario(
        cancel_second_auth: bool,
    ) -> anyhow::Result<()> {
        use std::{net::SocketAddr, sync::Arc};

        use anyhow::{Context as _, anyhow};
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let certificate = certified.cert.der().clone();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut server_tls =
            rustls::ServerConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_no_client_auth()
                .with_single_cert(
                    vec![certificate.clone()],
                    PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
                        certified.signing_key.serialize_der(),
                    )),
                )?;
        server_tls.alpn_protocols = vec![b"h3".to_vec()];
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_tls)?,
        ));
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::from(([127, 0, 0, 1], 0)),
        )?;
        let server_addr = server_endpoint.local_addr()?;
        let (first_tx, first_rx) = tokio::sync::oneshot::channel();
        let (second_tx, second_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            let first_incoming = server_endpoint
                .accept()
                .await
                .context("accept the first test QUIC connection")?;
            let first_connection = first_incoming
                .await
                .context("complete the first test QUIC handshake")?;
            let mut first_h3 = h3::server::builder()
                .build::<_, Bytes>(h3_quinn::Connection::new(
                    first_connection.clone(),
                ))
                .await?;
            let first_resolver = first_h3
                .accept()
                .await?
                .ok_or_else(|| anyhow!("test client closed before first auth"))?;
            let (_first_request, mut first_stream) =
                first_resolver.resolve_request().await?;
            let response = http::Response::builder()
                .status(233)
                .header("Hysteria-CC-RX", "auto")
                .header("Hysteria-UDP", "true")
                .body(())?;
            first_stream.send_response(response).await?;
            first_stream.finish().await?;
            first_tx
                .send(first_connection.clone())
                .map_err(|_| anyhow!("test receiver dropped before first auth"))?;

            let second_incoming = server_endpoint
                .accept()
                .await
                .context("accept the second test QUIC connection")?;
            let second_connection = second_incoming
                .await
                .context("complete the second test QUIC handshake")?;
            let mut second_h3 = h3::server::builder()
                .build::<_, Bytes>(h3_quinn::Connection::new(
                    second_connection.clone(),
                ))
                .await?;
            let second_resolver = second_h3
                .accept()
                .await?
                .ok_or_else(|| anyhow!("test client closed before second auth"))?;
            let (_second_request, mut second_stream) =
                second_resolver.resolve_request().await?;
            if !cancel_second_auth {
                let response = http::Response::builder().status(403).body(())?;
                second_stream.send_response(response).await?;
                second_stream.finish().await?;
            }
            second_tx
                .send(second_connection)
                .map_err(|_| anyhow!("test receiver dropped before second auth"))?;
            std::future::pending::<()>().await;
            anyhow::Ok(())
        });

        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate)?;
        let client_tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let client = HysteriaClient::new(
            client_tls,
            &[],
            "test-password".to_owned(),
            None,
            None,
            None,
            false,
        )?;
        use quinn::Runtime as _;
        let udp_socket =
            std::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
        udp_socket.set_nonblocking(true)?;
        let udp_socket: Arc<dyn quinn::AsyncUdpSocket> =
            quinn::TokioRuntime.wrap_udp_socket(udp_socket)?;
        let connection_count =
            std::num::NonZeroUsize::new(2).expect("two is nonzero");
        let client_task = tokio::spawn(async move {
            client
                .connect_many(udp_socket, server_addr, "localhost", connection_count)
                .await
        });

        let first_connection =
            tokio::time::timeout(Duration::from_secs(3), first_rx)
                .await
                .context("first Hysteria session was not authenticated")??;
        let second_connection =
            tokio::time::timeout(Duration::from_secs(3), second_rx)
                .await
                .context("second Hysteria auth request was not received")??;
        if cancel_second_auth {
            client_task.abort();
            let _ = client_task.await;
        } else {
            let result = tokio::time::timeout(Duration::from_secs(3), client_task)
                .await
                .context("second authentication failure was not returned")?
                .context("client task panicked")?;
            anyhow::ensure!(
                result.is_err(),
                "connection pool setup succeeded despite rejected second auth"
            );
        }

        tokio::time::timeout(Duration::from_secs(2), first_connection.closed())
            .await
            .context(
                "cancelling pool setup did not close the authenticated session",
            )?;
        tokio::time::timeout(Duration::from_secs(2), second_connection.closed())
            .await
            .context(
                "cancelling pool setup did not close the pending auth session",
            )?;
        server_task.abort();
        Ok(())
    }

    #[cfg(feature = "aws-lc-rs")]
    #[tokio::test]
    async fn cancelling_second_auth_closes_the_partial_quic_pool()
    -> anyhow::Result<()> {
        run_second_auth_pool_scenario(true).await
    }

    #[cfg(feature = "aws-lc-rs")]
    #[tokio::test]
    async fn rejecting_second_auth_closes_the_partial_quic_pool()
    -> anyhow::Result<()> {
        run_second_auth_pool_scenario(false).await
    }
}
