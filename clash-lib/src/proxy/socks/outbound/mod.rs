mod datagram;

use std::{fmt::Debug, sync::Arc};

use async_trait::async_trait;
use tracing::{debug, trace};

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    config::internal::proxy::OutboundSocks5,
    impl_default_connector,
    proxy::{
        AnyStream, ConnectorType, DialWithConnector, HandlerCommonOptions,
        OutboundHandler, OutboundType,
        socks::socks5::{client_handshake, socks_command},
        transport::Transport,
        utils::{GLOBAL_DIRECT_CONNECTOR, RemoteConnector, new_udp_socket},
    },
    session::Session,
};

use datagram::Socks5Datagram;

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
    pub udp: bool,
    pub tls_client: Option<Box<dyn Transport>>,
}

pub struct Handler {
    opts: HandlerOptions,
    connector: tokio::sync::RwLock<Option<Arc<dyn RemoteConnector>>>,
}

impl_default_connector!(Handler);

impl Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks5")
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

    async fn inner_connect_stream(
        &self,
        stream: AnyStream,
        sess: &Session,
    ) -> std::io::Result<AnyStream> {
        let mut stream = if let Some(tls_client) = self.opts.tls_client.as_ref() {
            tls_client.proxy_stream(stream).await?
        } else {
            stream
        };

        client_handshake(
            &mut stream,
            &sess.destination,
            socks_command::CONNECT,
            self.opts.user.clone(),
            self.opts.password.clone(),
        )
        .await?;

        Ok(stream)
    }

    async fn inner_connect_datagram(
        &self,
        stream: AnyStream,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<Socks5Datagram> {
        let mut stream = if let Some(tls_client) = self.opts.tls_client.as_ref() {
            tls_client.proxy_stream(stream).await?
        } else {
            stream
        };

        let bind_addr = client_handshake(
            &mut stream,
            &sess.destination,
            socks_command::UDP_ASSOCIATE,
            self.opts.user.clone(),
            self.opts.password.clone(),
        )
        .await?;

        let bind_ip = bind_addr.ip().filter(|ip| !ip.is_unspecified());
        let bind_ip = if let Some(bind_ip) = bind_ip {
            trace!("using SOCKS5 server returned bind address {bind_ip}");
            bind_ip
        } else {
            trace!(
                "SOCKS5 server returned unspecified bind address, resolving server address"
            );
            resolver
                .resolve(&self.opts.server, false)
                .await
                .map_err(|err| std::io::Error::other(err.to_string()))?
                .ok_or_else(|| {
                    std::io::Error::other(
                        "SOCKS5 server returned no bind address and server resolution failed",
                    )
                })?
        };
        let bind_port = bind_addr.port();

        let udp_socket = new_udp_socket(
            None,
            sess.iface.as_ref(),
            #[cfg(target_os = "linux")]
            sess.so_mark,
            Some((bind_ip, bind_port).into()),
        )
        .await?;

        Ok(Socks5Datagram::new(
            stream,
            (bind_ip, bind_port).into(),
            udp_socket,
        ))
    }
}

impl TryFrom<OutboundSocks5> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundSocks5) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundSocks5> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundSocks5) -> Result<Self, Self::Error> {
        #[cfg(feature = "tls")]
        let tls_client = if s.tls {
            Some(Box::new(crate::proxy::transport::TlsClient::new(
                s.skip_cert_verify,
                s.sni
                    .clone()
                    .unwrap_or_else(|| s.common_opts.server.to_owned()),
                None,
                None,
            )) as Box<dyn Transport>)
        } else {
            None
        };
        #[cfg(not(feature = "tls"))]
        let tls_client = None;

        Ok(Self::new(HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: HandlerCommonOptions {
                connector: s.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            user: s.username.clone(),
            password: s.password.clone(),
            udp: s.udp,
            tls_client,
        }))
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn server_name(&self) -> Option<&str> {
        Some(&self.opts.server)
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Socks5
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedStream> {
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
    ) -> std::io::Result<BoxedChainedDatagram> {
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
    ) -> std::io::Result<BoxedChainedStream> {
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

        let stream = self.inner_connect_stream(stream, sess).await?;
        let stream = crate::proxy::utils::observe_proxy_target_stream(
            stream,
            &pool_context,
            &sess.destination,
            crate::app::runtime_state::TrafficKind::ProxyTcp,
        );
        let chained = ChainedStreamWrapper::new_with_network_path_id(
            stream,
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
    ) -> std::io::Result<BoxedChainedDatagram> {
        let pool_context =
            connector.connection_pool_context(sess.iface.as_ref()).await;
        let (stream, pool_context) = connector
            .connect_stream_with_pool_context(
                resolver.clone(),
                self.opts.server.as_str(),
                self.opts.port,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
                pool_context,
            )
            .await?;

        let datagram = self.inner_connect_datagram(stream, sess, resolver).await?;
        let chained = ChainedDatagramWrapper::new_with_network_path_id(
            datagram,
            pool_context.path_id,
        );
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }
}

#[cfg(all(test, feature = "tun", any(target_os = "linux", target_os = "macos")))]
mod path_health_tests {
    use std::{net::Ipv4Addr, sync::Arc, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::mpsc,
        time::timeout,
    };

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
            utils::{DirectConnector, NetworkPathSource},
        },
        session::{Session, SocksAddr},
    };

    #[tokio::test]
    async fn socks5_handshake_and_target_response_keep_the_dialed_path() {
        let loopback_name = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        let interface = get_interface_by_name(loopback_name)
            .expect("loopback interface should be discoverable");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("failed to bind local SOCKS5 endpoint");
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
        let server = tokio::spawn(async move {
            let (rejected, _) = timeout(Duration::from_secs(3), listener.accept())
                .await
                .expect("timed out accepting the rejected wildcard-source attempt")
                .expect("failed to accept the first local dial attempt");
            drop(rejected);

            let (mut stream, _) = timeout(Duration::from_secs(3), listener.accept())
                .await
                .expect("timed out accepting the selected-path SOCKS5 session")
                .expect("failed to accept the selected local dial");
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).await.unwrap();

            let mut request = [0; 10];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..4], &[5, 1, 0, 1]);
            assert_eq!(&request[4..8], &[203, 0, 113, 19]);
            assert_eq!(u16::from_be_bytes([request[8], request[9]]), 443);

            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            let mut request = [0; 14];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"target-request");
            stream.write_all(b"R").await.unwrap();
            stream.shutdown().await.unwrap();
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
            name: "local-socks5".to_owned(),
            common_opts: HandlerCommonOptions::default(),
            server: endpoint.ip().to_string(),
            port: endpoint.port(),
            user: None,
            password: None,
            udp: false,
            tls_client: None,
        });
        let resolver = Arc::new(MockClashResolver::new());
        let mut chained = timeout(
            Duration::from_secs(5),
            handler.connect_stream_with_connector(&session, resolver, &connector),
        )
        .await
        .expect("SOCKS5 endpoint path and handshake exceeded the deadline")
        .expect("SOCKS5 handshake should complete on the fallback path");
        assert_eq!(chained.network_path_ids(), vec![selected_path.clone()]);
        chained.write_all(b"target-request").await.unwrap();

        let mut response = Vec::new();
        timeout(Duration::from_secs(3), chained.read_to_end(&mut response))
            .await
            .expect("timed out reading the SOCKS5 target response")
            .expect("failed to read SOCKS5 target response");
        assert_eq!(response, b"R");
        timeout(Duration::from_secs(3), server)
            .await
            .expect("local SOCKS5 server did not finish")
            .expect("local SOCKS5 server task failed");

        let mut reported_kinds = Vec::new();
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
        reported_kinds.extend(
            traffic_evidence
                .iter()
                .map(|event| event["kind"].as_str().unwrap().to_owned()),
        );
        assert!(reported_kinds.contains(&"proxyEndpointTcp".to_owned()));
        assert!(reported_kinds.contains(&"proxyTcp".to_owned()));
        let endpoint_evidence = traffic_evidence
            .iter()
            .find(|event| event["kind"] == "proxyEndpointTcp")
            .expect("SOCKS5 endpoint handshake should produce endpoint evidence");
        assert_eq!(endpoint_evidence["receivedBytes"], 2);
        let target_evidence = traffic_evidence
            .iter()
            .find(|event| event["kind"] == "proxyTcp")
            .expect("tunneled target response should produce proxy evidence");
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
            "the SOCKS endpoint and tunneled target should have distinct health entries"
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

    const SOCKS5_NOAUTH_SERVER_CONFIG: &str = r#"{
    "log": {"loglevel": "debug"},
    "inbounds": [{
        "port": 10002,
        "listen": "0.0.0.0",
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": true, "ip": "0.0.0.0"}
    }],
    "outbounds": [{"protocol": "freedom"}]
}"#;

    async fn get_socks5_noauth_runner() -> anyhow::Result<DockerTestRunner> {
        use std::io::Write;
        let test_config_dir = config_helper::test_config_base_dir();
        let mut tmp = tempfile::NamedTempFile::new_in(&test_config_dir)?;
        tmp.write_all(SOCKS5_NOAUTH_SERVER_CONFIG.as_bytes())?;
        let runner = DockerTestRunnerBuilder::new()
            .image(IMAGE_SOCKS5)
            .no_port()
            .mounts(&[(tmp.path().to_str().unwrap(), "/etc/v2ray/config.json")])
            .build()
            .await?;
        drop(tmp);
        Ok(runner)
    }

    const SOCKS5_AUTH_SERVER_CONFIG: &str = r#"{
    "log": {"loglevel": "debug"},
    "inbounds": [{
        "port": 10002,
        "listen": "0.0.0.0",
        "protocol": "socks",
        "settings": {
            "auth": "password",
            "accounts": [{"user": "user", "pass": "password"}],
            "udp": true,
            "ip": "0.0.0.0"
        }
    }],
    "outbounds": [{"protocol": "freedom"}]
}"#;

    async fn get_socks5_auth_runner() -> anyhow::Result<DockerTestRunner> {
        use std::io::Write;
        let test_config_dir = config_helper::test_config_base_dir();
        let mut tmp = tempfile::NamedTempFile::new_in(&test_config_dir)?;
        tmp.write_all(SOCKS5_AUTH_SERVER_CONFIG.as_bytes())?;
        let runner = DockerTestRunnerBuilder::new()
            .image(IMAGE_SOCKS5)
            .no_port()
            .mounts(&[(tmp.path().to_str().unwrap(), "/etc/v2ray/config.json")])
            .build()
            .await?;
        drop(tmp);
        Ok(runner)
    }

    #[tokio::test]
    async fn e2e_throughput_socks5_noauth() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_socks5_noauth_runner().await?;
        let server = container
            .container_ip()
            .ok_or_else(|| anyhow::anyhow!("socks5 container has no IP"))?;
        let gateway_ip = container.docker_gateway_ip();

        let mmdb = config_helper::test_config_base_dir()
            .join("Country.mmdb")
            .to_str()
            .unwrap()
            .to_owned();
        let config = format!(
            r#"
socks-port: {socks_port}
bind-address: 127.0.0.1
mmdb: "{mmdb}"
mode: global
log-level: error
proxies:
  - name: proxy
    type: socks5
    server: {server}
    port: {port}
    udp: false
rules:
  - MATCH,proxy
"#,
            socks_port = socks_port,
            mmdb = mmdb,
            server = server,
            port = CONTAINER_PORT,
        );
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "socks5-noauth",
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
    async fn e2e_throughput_socks5_auth() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_socks5_auth_runner().await?;
        let server = container
            .container_ip()
            .ok_or_else(|| anyhow::anyhow!("socks5 container has no IP"))?;
        let gateway_ip = container.docker_gateway_ip();

        let mmdb = config_helper::test_config_base_dir()
            .join("Country.mmdb")
            .to_str()
            .unwrap()
            .to_owned();
        let config = format!(
            r#"
socks-port: {socks_port}
bind-address: 127.0.0.1
mmdb: "{mmdb}"
mode: global
log-level: error
proxies:
  - name: proxy
    type: socks5
    server: {server}
    port: {port}
    username: user
    password: password
    udp: false
rules:
  - MATCH,proxy
"#,
            socks_port = socks_port,
            mmdb = mmdb,
            server = server,
            port = CONTAINER_PORT,
        );
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "socks5-auth",
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
