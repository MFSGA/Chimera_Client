use erased_serde::Serialize as ErasedSerialize;
use std::{collections::HashMap, io, sync::Arc};

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use sha2::{Digest, Sha224};
use tokio::io::AsyncWriteExt;
use tracing::debug;

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::utils,
    impl_default_connector,
    session::Session,
};

use self::datagram::OutboundDatagramTrojan;

use super::{
    AnyStream, ConnectorType, DialWithConnector, HandlerCommonOptions,
    OutboundHandler, OutboundType, PlainProxyAPIResponse,
    transport::Transport,
    utils::{GLOBAL_DIRECT_CONNECTOR, RemoteConnector},
};

mod datagram;

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub udp: bool,
    // might support shadow-tls?
    pub tls: Option<Box<dyn Transport>>,
    pub transport: Option<Box<dyn Transport>>,
}

pub struct Handler {
    opts: HandlerOptions,

    connector: tokio::sync::RwLock<Option<Arc<dyn RemoteConnector>>>,
}

impl_default_connector!(Handler);

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Trojan")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            connector: Default::default(),
        }
    }

    /// TCP: 0x01,
    /// UDP: 0x03,
    async fn inner_proxy_stream(
        &self,
        s: AnyStream,
        sess: &Session,
        udp: bool,
    ) -> io::Result<AnyStream> {
        let s = if let Some(tls_client) = self.opts.tls.as_ref() {
            tls_client.proxy_stream(s).await?
        } else {
            s
        };

        let mut s = if let Some(transport) = self.opts.transport.as_ref() {
            transport.proxy_stream(s).await?
        } else {
            s
        };

        let mut buf = BytesMut::new();
        let password = Sha224::digest(self.opts.password.as_bytes());
        let password = utils::encode_hex(&password[..]);
        buf.put_slice(password.as_bytes());
        buf.put_slice(b"\r\n");
        buf.put_u8(if udp { 0x03 } else { 0x01 });
        sess.destination.write_buf(&mut buf);
        buf.put_slice(b"\r\n");
        s.write_all(&buf).await?;

        Ok(s)
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    async fn reset_connection_pool(&self) -> io::Result<u32> {
        match &self.opts.transport {
            Some(transport) => transport.reset_connection_pool().await,
            None => Ok(0),
        }
    }

    fn name(&self) -> &str {
        &self.opts.name
    }

    fn server_name(&self) -> Option<&str> {
        Some(&self.opts.server)
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Trojan
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let dialer = self.connector.read().await;

        if let Some(dialer) = dialer.as_ref() {
            debug!("{:?} is connecting via {:?}", self, dialer);
        }

        self.connect_stream_with_connector(
            sess,
            resolver,
            dialer
                .as_ref()
                .unwrap_or(&GLOBAL_DIRECT_CONNECTOR.clone())
                .as_ref(),
        )
        .await
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let dialer = self.connector.read().await;

        if let Some(dialer) = dialer.as_ref() {
            debug!("{:?} is connecting via {:?}", self, dialer);
        }

        self.connect_datagram_with_connector(
            sess,
            resolver,
            dialer
                .as_ref()
                .unwrap_or(&GLOBAL_DIRECT_CONNECTOR.clone())
                .as_ref(),
        )
        .await
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::All
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        let pool_context =
            connector.connection_pool_context(sess.iface.as_ref()).await;
        let (stream, pool_context) = connector
            .connect_stream_with_pool_context(
                resolver,
                self.opts.server.as_str(),
                self.opts.port,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
                pool_context,
            )
            .await?;

        let s = self.inner_proxy_stream(stream, sess, false).await?;
        let s = crate::proxy::utils::observe_proxy_target_stream(
            s,
            &pool_context,
            &sess.destination,
            crate::app::runtime_state::TrafficKind::ProxyTcp,
        );
        let chained = ChainedStreamWrapper::new_with_network_path_id(
            s,
            pool_context.path_id.clone(),
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
        let pool_context =
            connector.connection_pool_context(sess.iface.as_ref()).await;
        let (stream, pool_context) = connector
            .connect_stream_with_pool_context(
                resolver,
                self.opts.server.as_str(),
                self.opts.port,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
                pool_context,
            )
            .await?;

        let stream = self.inner_proxy_stream(stream, sess, true).await?;
        let stream = crate::proxy::utils::observe_proxy_target_stream(
            stream,
            &pool_context,
            &sess.destination,
            crate::app::runtime_state::TrafficKind::ProxyUdp,
        );

        let d = OutboundDatagramTrojan::new(stream, sess.destination.clone());

        let chained = ChainedDatagramWrapper::new_with_network_path_id(
            d,
            pool_context.path_id.clone(),
        );
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> {
        Some(self as _)
    }
}

#[async_trait]
impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        let mut m = HashMap::new();
        m.insert("name".to_owned(), Box::new(self.opts.name.clone()) as _);
        m.insert("type".to_owned(), Box::new(self.proto().to_string()) as _);
        m.insert("server".to_owned(), Box::new(self.opts.server.clone()) as _);
        m.insert("port".to_owned(), Box::new(self.opts.port) as _);
        m.insert(
            "password".to_owned(),
            Box::new(self.opts.password.clone()) as _,
        );
        if self.opts.udp {
            m.insert("udp".to_owned(), Box::new(true) as _);
        }
        if self.opts.tls.is_some() {
            m.insert("tls".to_owned(), Box::new(true) as _);
        }
        m
    }
}

#[cfg(all(
    test,
    feature = "trojan",
    feature = "tun",
    any(target_os = "linux", target_os = "macos")
))]
mod path_health_tests {
    use std::{net::Ipv4Addr, sync::Arc, time::Duration};

    use sha2::{Digest, Sha224};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::mpsc,
        time::timeout,
    };
    use tokio_rustls::TlsAcceptor;

    use super::{Handler, HandlerOptions};
    use crate::{
        app::{
            dns::MockClashResolver,
            flow::{AddressFamily, InterfaceId, InterfaceKind, NetworkPathId},
            net::{OutboundInterface, get_interface_by_name},
            network::{
                BindingStatus, DefaultRouteEvidence, NetworkSnapshot, NetworkStatus,
                PathCandidateObservation,
            },
            runtime_state::Lifecycle,
        },
        proxy::{
            HandlerCommonOptions, OutboundHandler,
            transport::TlsClient,
            utils::{DirectConnector, NetworkPathSource},
        },
        session::{Session, SocksAddr},
    };

    const TEST_PASSWORD: &str = "local-trojan-test-password";

    #[tokio::test]
    async fn tls_handshake_and_target_response_keep_the_dialed_path() {
        crate::setup_default_crypto_provider();
        let loopback_name = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        let interface = get_interface_by_name(loopback_name)
            .expect("loopback interface should be discoverable");

        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
                .expect("test certificate should generate");
        let cert = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
        let key =
            rustls::pki_types::PrivateKeyDer::try_from(signing_key.serialize_der())
                .expect("test private key should serialize");
        let tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("test TLS config should build");
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("failed to bind local Trojan endpoint");
        let endpoint = listener.local_addr().unwrap();

        let mut status = NetworkStatus::default();
        status.set_automatic_supported_for_test(true);
        assert!(status.lifecycle(Lifecycle::Running, "test"));
        status.observed(&NetworkSnapshot {
            path_candidates: vec![
                path_candidate(
                    &interface.name,
                    interface.index,
                    Ipv4Addr::UNSPECIFIED,
                    DefaultRouteEvidence::PrimaryDefaultRoute,
                ),
                path_candidate(
                    &interface.name,
                    interface.index,
                    Ipv4Addr::LOCALHOST,
                    DefaultRouteEvidence::OtherInterface,
                ),
            ],
            ..Default::default()
        });
        let generation = status
            .shadow_path_snapshot()
            .expect("test status should expose observed loopback candidates")
            .0;
        let selected_path = NetworkPathId {
            interface: InterfaceId {
                name: interface.name.clone(),
                index: interface.index,
            },
            family: AddressFamily::Ipv4,
            source_address: Some(Ipv4Addr::LOCALHOST.into()),
            network_generation: generation,
        };

        let (events_tx, mut events_rx) = mpsc::channel(4);
        let reporter = status.traffic_reporter(events_tx);
        let status = Arc::new(tokio::sync::RwLock::new(status));
        let source = NetworkPathSource::default();
        source.attach(status.clone()).await;
        source.attach_traffic_reporter(reporter).await;
        let connector = DirectConnector::with_path_source(source);

        let target: SocksAddr = "203.0.113.19:443".parse().unwrap();
        let server_target = target.clone();
        let acceptor = acceptor.clone();
        let server = tokio::spawn(async move {
            let (rejected, _) = timeout(Duration::from_secs(3), listener.accept())
                .await
                .expect("timed out accepting the rejected wildcard-source attempt")
                .expect("failed to accept the first local dial attempt");
            drop(rejected);

            let (tcp, _) = timeout(Duration::from_secs(3), listener.accept())
                .await
                .expect("timed out accepting the selected-path TLS session")
                .expect("failed to accept the selected local dial");
            let mut tls = timeout(Duration::from_secs(3), acceptor.accept(tcp))
                .await
                .expect("timed out completing the TLS handshake")
                .expect("TLS handshake should succeed");

            let mut auth = [0; 56];
            tls.read_exact(&mut auth)
                .await
                .expect("read Trojan password hash");
            let expected_auth = crate::common::utils::encode_hex(&Sha224::digest(
                TEST_PASSWORD.as_bytes(),
            ));
            assert_eq!(std::str::from_utf8(&auth).unwrap(), expected_auth);
            let mut separator = [0; 2];
            tls.read_exact(&mut separator)
                .await
                .expect("read Trojan password separator");
            assert_eq!(&separator, b"\r\n");
            let command = tls.read_u8().await.expect("read Trojan command");
            assert_eq!(command, 0x01);
            let destination = SocksAddr::read_from(&mut tls)
                .await
                .expect("read Trojan destination");
            tls.read_exact(&mut separator)
                .await
                .expect("read Trojan request separator");
            assert_eq!(&separator, b"\r\n");
            let mut request = [0; 14];
            tls.read_exact(&mut request)
                .await
                .expect("read tunneled Trojan request");
            tls.write_all(b"R")
                .await
                .expect("write tunneled Trojan response");
            tls.flush().await.expect("flush tunneled response");
            (destination, request, server_target)
        });

        let session = Session {
            destination: target.clone(),
            iface: Some(OutboundInterface {
                name: interface.name,
                addr_v4: None,
                netmask_v4: None,
                broadcast_v4: None,
                addr_v6: None,
                netmask_v6: None,
                broadcast_v6: None,
                index: interface.index,
                mac_addr: None,
            }),
            ..Default::default()
        };
        let handler = Handler::new(HandlerOptions {
            name: "local-trojan".to_owned(),
            common_opts: HandlerCommonOptions::default(),
            server: endpoint.ip().to_string(),
            port: endpoint.port(),
            password: TEST_PASSWORD.to_owned(),
            udp: false,
            tls: Some(Box::new(TlsClient::new(
                true,
                "localhost".to_owned(),
                None,
                None,
            ))),
            transport: None,
        });
        let resolver = Arc::new(MockClashResolver::new());
        let mut chained = timeout(
            Duration::from_secs(5),
            handler.connect_stream_with_connector(&session, resolver, &connector),
        )
        .await
        .expect("Trojan path selection and TLS handshake exceeded the deadline")
        .expect("Trojan TLS and command handshake should complete on fallback path");
        assert_eq!(chained.network_path_ids(), vec![selected_path.clone()]);
        chained.write_all(b"target-request").await.unwrap();

        let mut response = [0; 1];
        timeout(Duration::from_secs(3), chained.read_exact(&mut response))
            .await
            .expect("timed out reading Trojan target response")
            .expect("failed to read Trojan target response");
        assert_eq!(&response, b"R");
        let (destination, request, server_target) =
            timeout(Duration::from_secs(3), server)
                .await
                .expect("local Trojan server did not finish")
                .expect("local Trojan server task failed");
        assert_eq!(destination, server_target);
        assert_eq!(&request, b"target-request");

        for _ in 0..3 {
            let event = timeout(Duration::from_secs(2), events_rx.recv())
                .await
                .expect("expected dial-failure, endpoint, and target evidence")
                .expect("traffic reporter stopped before all path results");
            status.write().await.record_traffic(event);
        }
        let snapshot = {
            let status = status.read().await;
            serde_json::to_value(&*status).unwrap()
        };
        let traffic_evidence = snapshot["trafficEvidence"].as_array().unwrap();
        let endpoint_evidence = traffic_evidence
            .iter()
            .find(|event| event["kind"] == "proxyEndpointTcp")
            .expect("TLS endpoint response should produce endpoint evidence");
        assert!(endpoint_evidence["receivedBytes"].as_u64().unwrap() > 0);
        let target_evidence = traffic_evidence
            .iter()
            .find(|event| event["kind"] == "proxyTcp")
            .expect("Trojan target response should produce proxy evidence");
        assert_eq!(target_evidence["receivedBytes"], 1);

        let selected_path_json = serde_json::to_value(&selected_path).unwrap();
        let selected_path_health = snapshot["pathHealth"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["path"] == selected_path_json)
            .expect("the successful local NIC should have path health");
        assert_eq!(selected_path_health["state"], "available");
        let selected_destination_health = snapshot["destinationPathHealth"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| entry["path"] == selected_path_json)
            .collect::<Vec<_>>();
        assert_eq!(
            selected_destination_health.len(),
            2,
            "the Trojan endpoint and tunneled target should have distinct health entries"
        );
        assert!(
            selected_destination_health
                .iter()
                .all(|entry| entry["state"] == "available")
        );
    }

    fn path_candidate(
        name: &str,
        index: u32,
        source_address: Ipv4Addr,
        default_route: DefaultRouteEvidence,
    ) -> PathCandidateObservation {
        PathCandidateObservation {
            interface: InterfaceId {
                name: name.to_owned(),
                index,
            },
            interface_kind: InterfaceKind::Unknown,
            family: AddressFamily::Ipv4,
            source_address: source_address.into(),
            scope_id: None,
            gateway: None,
            default_route,
            binding: BindingStatus::Verified,
            binding_error: None,
        }
    }
}

#[cfg(all(test, docker_test))]
mod tests {

    use std::{collections::HashMap, time::Duration};

    use super::*;
    use crate::{
        proxy::{
            transport,
            utils::test_utils::{
                Suite,
                docker_utils::{
                    config_helper::test_config_base_dir,
                    consts::*,
                    docker_runner::{
                        DockerTestRunner, DockerTestRunnerBuilder, alloc_docker_port,
                    },
                },
                run_test_suites_and_cleanup,
            },
        },
        tests::initialize,
    };
    const WS_CONTAINER_PORT: u16 = 10002;

    fn ws_server_port(host_port: u16) -> u16 {
        if crate::proxy::utils::test_utils::docker_utils::use_ci_host_network() {
            WS_CONTAINER_PORT
        } else {
            host_port
        }
    }

    async fn get_ws_runner(host_port: u16) -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let trojan_conf = test_config_dir.join("trojan-ws.json");
        let trojan_cert = test_config_dir.join("certs/example.org.pem");
        let trojan_key = test_config_dir.join("certs/example.org-key.pem");

        let mut builder = DockerTestRunnerBuilder::new().image(IMAGE_TROJAN_GO);
        builder =
            if crate::proxy::utils::test_utils::docker_utils::use_ci_host_network() {
                builder.host_network()
            } else {
                builder.host_port(host_port, WS_CONTAINER_PORT)
            };

        let runner = builder
            .mounts(&[
                (trojan_conf.to_str().unwrap(), "/etc/trojan-go/config.json"),
                (trojan_cert.to_str().unwrap(), "/fullchain.pem"),
                (trojan_key.to_str().unwrap(), "/privkey.pem"),
            ])
            .build()
            .await?;

        DockerTestRunner::wait_host_tcp_ready(
            LOCAL_ADDR,
            ws_server_port(host_port),
            Duration::from_secs(20),
        )
        .await?;
        // trojan-go may bind the port before TLS listener state is fully
        // initialized, which can produce transient `tls handshake eof` in CI.
        tokio::time::sleep(Duration::from_secs(2)).await;

        Ok(runner)
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_trojan_ws() -> anyhow::Result<()> {
        initialize();
        let span = tracing::info_span!("test_trojan_ws");
        let _enter = span.enter();
        let host_port = alloc_docker_port();
        let transport = transport::WsClient::new(
            "".to_owned(),
            10002,
            "/".to_owned(),
            [("Host".to_owned(), "example.org".to_owned())]
                .into_iter()
                .collect::<HashMap<_, _>>(),
            None,
            0,
            "".to_owned(),
        );
        let tls =
            transport::TlsClient::new(true, "example.org".to_owned(), None, None);

        let container = get_ws_runner(host_port).await?;

        let opts = HandlerOptions {
            name: "test-trojan-ws".to_owned(),
            common_opts: Default::default(),
            server: LOCAL_ADDR.to_owned(),
            port: ws_server_port(host_port),
            password: "example".to_owned(),
            udp: true,
            tls: Some(Box::new(tls)),
            transport: Some(Box::new(transport)),
        };
        let handler = Arc::new(Handler::new(opts));
        handler
            .register_connector(GLOBAL_DIRECT_CONNECTOR.clone())
            .await;
        // ignore the udp test
        run_test_suites_and_cleanup(handler, container, Suite::all()).await
    }

    #[cfg(any())]
    async fn get_grpc_runner() -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let conf = test_config_dir.join("trojan-grpc.json");
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");

        DockerTestRunnerBuilder::new()
            .image(IMAGE_XRAY)
            .mounts(&[
                (conf.to_str().unwrap(), "/etc/xray/config.json"),
                (cert.to_str().unwrap(), "/etc/ssl/v2ray/fullchain.pem"),
                (key.to_str().unwrap(), "/etc/ssl/v2ray/privkey.pem"),
            ])
            .build()
            .await
    }

    #[cfg(any())]
    #[tokio::test]
    #[serial_test::serial]
    async fn test_trojan_grpc() -> anyhow::Result<()> {
        initialize();
        let transport = transport::GrpcClient::new(
            "example.org".to_owned(),
            "example"
                .to_owned()
                .try_into()
                .expect("invalid grpc service name"),
        );
        let tls = transport::TlsClient::new(
            true,
            "example.org".to_owned(),
            Some(vec!["http/1.1".to_owned(), "h2".to_owned()]),
            None,
        );

        let runner = get_grpc_runner().await?;

        let opts = HandlerOptions {
            name: "test-trojan-grpc".to_owned(),
            common_opts: Default::default(),
            server: runner.container_ip().unwrap_or(LOCAL_ADDR.to_owned()),
            port: 10002,
            password: "example".to_owned(),
            udp: true,
            tls: Some(Box::new(tls)),
            transport: Some(Box::new(transport)),
        };
        let handler = Arc::new(Handler::new(opts));
        handler
            .register_connector(GLOBAL_DIRECT_CONNECTOR.clone())
            .await;
        run_test_suites_and_cleanup(handler, runner, Suite::all()).await
    }
}

#[cfg(all(test, docker_test, throughput_test))]
mod e2e {
    use crate::{
        proxy::utils::test_utils::{
            config_helper,
            consts::*,
            docker_runner::{
                DockerTestRunner, DockerTestRunnerBuilder, RunAndCleanup,
            },
            docker_utils::{
                alloc_port, clash_process_e2e_throughput, find_clash_rs_binary,
            },
        },
        tests::initialize,
    };

    const CONTAINER_PORT: u16 = 10002;
    const E2E_PAYLOAD_BYTES: usize = 32 * 1024 * 1024; // 32 MB

    fn base_config(server: &str, port: u16, socks_port: u16, extra: &str) -> String {
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
    type: trojan
    server: {server}
    port: {port}
    password: example
    skip-cert-verify: true
    udp: false
{extra}
rules:
  - MATCH,proxy
"#,
            socks_port = socks_port,
            mmdb = mmdb,
            server = server,
            port = port,
            extra = extra,
        )
    }

    const TROJAN_WS_SERVER_CONFIG: &str = r#"{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 10002,
    "disable_http_check": true,
    "password": ["example"],
    "websocket": {"enabled": true, "path": "/", "host": "example.org"},
    "ssl": {"verify": true, "cert": "/fullchain.pem", "key": "/privkey.pem", "sni": "example.org"}
}"#;

    const TROJAN_TCP_SERVER_CONFIG: &str = r#"{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 10002,
    "disable_http_check": true,
    "password": ["example"],
    "ssl": {
        "verify": true,
        "cert": "/fullchain.pem",
        "key": "/privkey.pem",
        "sni": "example.org"
    }
}"#;

    async fn get_tcp_runner() -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = config_helper::test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");
        let mut tmp = tempfile::NamedTempFile::new_in(&test_config_dir)?;
        use std::io::Write as _;
        tmp.write_all(TROJAN_TCP_SERVER_CONFIG.as_bytes())?;
        let result = DockerTestRunnerBuilder::new()
            .image(IMAGE_TROJAN_GO)
            .no_port()
            .mounts(&[
                (tmp.path().to_str().unwrap(), "/etc/trojan-go/config.json"),
                (cert.to_str().unwrap(), "/fullchain.pem"),
                (key.to_str().unwrap(), "/privkey.pem"),
            ])
            .build()
            .await;
        drop(tmp);
        result
    }

    async fn get_ws_runner() -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = config_helper::test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");
        let mut tmp = tempfile::NamedTempFile::new_in(&test_config_dir)?;
        use std::io::Write as _;
        tmp.write_all(TROJAN_WS_SERVER_CONFIG.as_bytes())?;
        let result = DockerTestRunnerBuilder::new()
            .image(IMAGE_TROJAN_GO)
            .no_port()
            .mounts(&[
                (tmp.path().to_str().unwrap(), "/etc/trojan-go/config.json"),
                (cert.to_str().unwrap(), "/fullchain.pem"),
                (key.to_str().unwrap(), "/privkey.pem"),
            ])
            .build()
            .await;
        drop(tmp);
        result
    }

    #[tokio::test]
    async fn e2e_throughput_trojan_tcp() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_tcp_runner().await?;
        let server = container.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
        let gateway_ip = container.docker_gateway_ip();

        let extra = r#"    tls: true"#;
        let config = base_config(&server, CONTAINER_PORT, socks_port, extra);
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "trojan-tcp",
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
    async fn e2e_throughput_trojan_tcp_netem() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_tcp_runner().await?;
        container.apply_netem(50, 1.0).await?;
        let server = container.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
        let gateway_ip = container.docker_gateway_ip();

        let extra = r#"    tls: true"#;
        let config = base_config(&server, CONTAINER_PORT, socks_port, extra);
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "trojan-tcp-netem",
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
    async fn e2e_throughput_trojan_ws() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_ws_runner().await?;
        let server = container.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
        let gateway_ip = container.docker_gateway_ip();

        let extra = r#"    tls: true
    network: ws
    ws-opts:
      path: /
      headers:
        Host: example.org"#;
        let config = base_config(&server, CONTAINER_PORT, socks_port, extra);
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "trojan-ws",
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
