use self::stream::VlessStream;
use super::{
    AnyStream, ConnectorType, DialWithConnector, HandlerCommonOptions,
    OutboundHandler, OutboundType,
    transport::Transport,
    utils::{GLOBAL_DIRECT_CONNECTOR, RemoteConnector},
};
use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    impl_default_connector,
    proxy::vless::{datagram::OutboundDatagramVless, vision::VisionStream},
    session::Session,
};
use async_trait::async_trait;
use std::{io, sync::Arc};
use tracing::debug;

mod datagram;
#[allow(dead_code)]
mod encryption;
mod stream;
mod tls_deframer;
mod tls_fuzzy_deframer;
mod tls_handshake_util;
mod vision;
mod vision_filter;
mod vision_pad;
mod vision_unpad;

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub udp: bool,
    pub transport: Option<Box<dyn Transport>>,
    pub tls: Option<Box<dyn Transport>>,
    pub flow: Option<String>,
}

pub struct Handler {
    opts: HandlerOptions,
    connector: tokio::sync::RwLock<Option<Arc<dyn RemoteConnector>>>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vless")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl_default_connector!(Handler);

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            connector: Default::default(),
        }
    }

    fn wrap_vless_stream(
        &self,
        s: AnyStream,
        sess: &Session,
        is_udp: bool,
        vision_opts: Option<crate::proxy::transport::VisionOptions>,
    ) -> io::Result<AnyStream> {
        let vless_stream = VlessStream::new(
            s,
            &self.opts.uuid,
            &sess.destination,
            is_udp,
            self.opts.flow.clone(),
        )?;

        if self.opts.flow.as_deref() == Some("xtls-rprx-vision") {
            Ok(Box::new(VisionStream::new(
                Box::new(vless_stream),
                self.opts.uuid.clone(),
                vision_opts,
            )?))
        } else {
            Ok(Box::new(vless_stream))
        }
    }

    async fn try_reuse_transport_stream(
        &self,
        sess: &Session,
        is_udp: bool,
    ) -> io::Result<Option<AnyStream>> {
        if self.opts.flow.as_deref() == Some("xtls-rprx-vision") {
            return Ok(None);
        }

        let Some(transport) = self.opts.transport.as_ref() else {
            return Ok(None);
        };
        let Some(stream) = transport.try_reuse_stream().await? else {
            return Ok(None);
        };

        Ok(Some(self.wrap_vless_stream(stream, sess, is_udp, None)?))
    }

    async fn try_transport_owned_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
        is_udp: bool,
    ) -> io::Result<Option<AnyStream>> {
        if self.opts.flow.as_deref() == Some("xtls-rprx-vision") {
            return Ok(None);
        }

        let Some(transport) = self.opts.transport.as_ref() else {
            return Ok(None);
        };
        let Some(stream) = transport
            .connect_stream_with_connector(sess, resolver, connector)
            .await?
        else {
            return Ok(None);
        };

        Ok(Some(self.wrap_vless_stream(stream, sess, is_udp, None)?))
    }

    async fn inner_proxy_stream(
        &self,
        s: AnyStream,
        sess: &Session,
        is_udp: bool,
    ) -> io::Result<AnyStream> {
        let wants_vision_splice =
            self.opts.flow.as_deref() == Some("xtls-rprx-vision");
        let mut vision_opts = None;

        let s = if let Some(tls) = self.opts.tls.as_ref() {
            if wants_vision_splice {
                let (stream, opts) = tls.proxy_stream_spliced(s).await?;
                vision_opts = opts;
                stream
            } else {
                tls.proxy_stream(s).await?
            }
        } else {
            s
        };

        let s = if let Some(transport) = self.opts.transport.as_ref() {
            if wants_vision_splice && vision_opts.is_none() {
                let (stream, opts) = transport.proxy_stream_spliced(s).await?;
                vision_opts = opts;
                stream
            } else {
                transport.proxy_stream(s).await?
            }
        } else {
            s
        };

        self.wrap_vless_stream(s, sess, is_udp, vision_opts)
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
        OutboundType::Vless
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
        if let Some(stream) = self.try_reuse_transport_stream(sess, false).await? {
            let chained = ChainedStreamWrapper::new(stream);
            chained.append_to_chain(self.name()).await;
            return Ok(Box::new(chained));
        }
        if let Some(stream) = self
            .try_transport_owned_stream(sess, resolver.clone(), connector, false)
            .await?
        {
            let chained = ChainedStreamWrapper::new(stream);
            chained.append_to_chain(self.name()).await;
            return Ok(Box::new(chained));
        }

        let stream = connector
            .connect_stream(
                resolver,
                self.opts.server.as_str(),
                self.opts.port,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;

        let s = self.inner_proxy_stream(stream, sess, false).await?;
        let chained = ChainedStreamWrapper::new(s);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedDatagram> {
        if let Some(stream) = self.try_reuse_transport_stream(sess, true).await? {
            let datagram =
                OutboundDatagramVless::new(stream, sess.destination.clone());
            let chained = ChainedDatagramWrapper::new(datagram);
            chained.append_to_chain(self.name()).await;
            return Ok(Box::new(chained));
        }
        if let Some(stream) = self
            .try_transport_owned_stream(sess, resolver.clone(), connector, true)
            .await?
        {
            let datagram =
                OutboundDatagramVless::new(stream, sess.destination.clone());
            let chained = ChainedDatagramWrapper::new(datagram);
            chained.append_to_chain(self.name()).await;
            return Ok(Box::new(chained));
        }

        let stream = connector
            .connect_stream(
                resolver,
                self.opts.server.as_str(),
                self.opts.port,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;

        let stream = self.inner_proxy_stream(stream, sess, true).await?;
        let d = OutboundDatagramVless::new(stream, sess.destination.clone());

        let chained = ChainedDatagramWrapper::new(d);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }
}

#[cfg(test)]
mod reuse_tests {
    use std::sync::Arc;

    use super::*;
    use crate::{app::dns::MockClashResolver, proxy::utils::DirectConnector};

    struct ReuseTransport;

    #[async_trait]
    impl Transport for ReuseTransport {
        async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
            Ok(stream)
        }

        async fn try_reuse_stream(&self) -> io::Result<Option<AnyStream>> {
            let (stream, peer) = tokio::io::duplex(1024);
            tokio::spawn(async move {
                let _peer = peer;
                std::future::pending::<()>().await;
            });
            Ok(Some(Box::new(stream)))
        }
    }

    struct OwnedDialTransport;

    #[async_trait]
    impl Transport for OwnedDialTransport {
        async fn proxy_stream(&self, _stream: AnyStream) -> io::Result<AnyStream> {
            panic!("owned-dial transport must bypass the pre-dialed TCP path");
        }

        async fn connect_stream_with_connector(
            &self,
            _sess: &Session,
            _resolver: ThreadSafeDNSResolver,
            _connector: &dyn RemoteConnector,
        ) -> io::Result<Option<AnyStream>> {
            let (stream, peer) = tokio::io::duplex(1024);
            tokio::spawn(async move {
                let _peer = peer;
                std::future::pending::<()>().await;
            });
            Ok(Some(Box::new(stream)))
        }
    }

    #[tokio::test]
    async fn vless_can_wrap_transport_owned_stream_before_tcp_dial() {
        let handler = Handler::new(HandlerOptions {
            name: "owned-dial-test".to_owned(),
            common_opts: HandlerCommonOptions::default(),
            server: "example.com".to_owned(),
            port: 443,
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            udp: true,
            transport: Some(Box::new(OwnedDialTransport)),
            tls: None,
            flow: None,
        });
        let resolver = Arc::new(MockClashResolver::new());
        let connector = DirectConnector::new();

        let stream = handler
            .try_transport_owned_stream(
                &Session::default(),
                resolver,
                &connector,
                false,
            )
            .await
            .expect("owned transport dial should succeed");

        assert!(
            stream.is_some(),
            "owned logical stream should be wrapped as VLESS before TCP dial"
        );
    }

    #[tokio::test]
    async fn vision_does_not_use_transport_owned_stream() {
        let handler = Handler::new(HandlerOptions {
            name: "vision-owned-dial-test".to_owned(),
            common_opts: HandlerCommonOptions::default(),
            server: "example.com".to_owned(),
            port: 443,
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            udp: true,
            transport: Some(Box::new(OwnedDialTransport)),
            tls: None,
            flow: Some("xtls-rprx-vision".to_owned()),
        });
        let resolver = Arc::new(MockClashResolver::new());
        let connector = DirectConnector::new();

        let stream = handler
            .try_transport_owned_stream(
                &Session::default(),
                resolver,
                &connector,
                false,
            )
            .await
            .expect("owned transport lookup should succeed");

        assert!(
            stream.is_none(),
            "Vision must preserve the existing splice-capable TCP path"
        );
    }

    #[tokio::test]
    async fn vless_can_wrap_transport_reuse_stream_before_dialing() {
        let handler = Handler::new(HandlerOptions {
            name: "reuse-test".to_owned(),
            common_opts: HandlerCommonOptions::default(),
            server: "example.com".to_owned(),
            port: 443,
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            udp: true,
            transport: Some(Box::new(ReuseTransport)),
            tls: None,
            flow: None,
        });

        let stream = handler
            .try_reuse_transport_stream(&Session::default(), false)
            .await
            .expect("reuse lookup should succeed");

        assert!(
            stream.is_some(),
            "reused logical stream should be wrapped as VLESS"
        );
    }

    #[tokio::test]
    async fn vision_does_not_bypass_fresh_security_handshake() {
        let handler = Handler::new(HandlerOptions {
            name: "vision-reuse-test".to_owned(),
            common_opts: HandlerCommonOptions::default(),
            server: "example.com".to_owned(),
            port: 443,
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            udp: true,
            transport: Some(Box::new(ReuseTransport)),
            tls: None,
            flow: Some("xtls-rprx-vision".to_owned()),
        });

        let stream = handler
            .try_reuse_transport_stream(&Session::default(), false)
            .await
            .expect("reuse lookup should succeed");

        assert!(
            stream.is_none(),
            "Vision must keep the fresh handshake path"
        );
    }
}

#[cfg(all(test, docker_test))]
mod tests {
    use std::{collections::HashMap, io::Write as _};

    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose,
    };

    use super::*;
    use crate::{
        proxy::{
            transport::{GrpcClient, TlsClient, WsClient},
            utils::test_utils::docker_utils::{
                config_helper::{build_dns_resolver, test_config_base_dir},
                consts::*,
                docker_runner::{
                    DockerTestRunner, DockerTestRunnerBuilder,
                    MultiDockerTestRunner, RunAndCleanup, alloc_docker_port,
                },
            },
        },
        session::SocksAddr,
        tests::initialize,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const WS_CONTAINER_PORT: u16 = 8443;
    const XRAY_CONTAINER_PORT: u16 = 10002;
    const ECHO_CONTAINER_PORT: u16 = 10003;
    const ECHO_IMAGE: &str = "alpine:3.20";
    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    const VLESS_GRPC_TLS_SERVER_CONFIG: &str = r#"{
  "log": {"loglevel": "debug"},
  "inbounds": [{
    "listen": "0.0.0.0",
    "port": 10002,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "grpc",
      "security": "tls",
      "tlsSettings": {
        "alpn": ["h2"],
        "certificates": [{
          "certificateFile": "/etc/ssl/v2ray/fullchain.pem",
          "keyFile": "/etc/ssl/v2ray/privkey.pem"
        }]
      },
      "grpcSettings": {"serviceName": "grpc-service"}
    }
  }],
  "outbounds": [{"protocol": "freedom"}]
}"#;

    const VLESS_MTLS_SERVER_CONFIG: &str = r#"{
  "log": {"loglevel": "debug"},
  "inbounds": [{
    "listen": "0.0.0.0",
    "port": 10002,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tlsSettings": {
        "verifyClientCertificate": true,
        "certificates": [
          {
            "certificateFile": "/etc/ssl/v2ray/fullchain.pem",
            "keyFile": "/etc/ssl/v2ray/privkey.pem",
            "usage": "encipherment"
          },
          {
            "certificateFile": "/etc/ssl/v2ray/client-ca.pem",
            "usage": "verify"
          }
        ]
      }
    }
  }],
  "outbounds": [{"protocol": "freedom"}]
}"#;

    fn ws_server_port(host_port: u16) -> u16 {
        if crate::proxy::utils::test_utils::docker_utils::use_ci_host_network() {
            WS_CONTAINER_PORT
        } else {
            host_port
        }
    }

    fn server_port(host_port: u16, container_port: u16) -> u16 {
        if crate::proxy::utils::test_utils::docker_utils::use_ci_host_network() {
            container_port
        } else {
            host_port
        }
    }

    fn tls_client(alpn: Option<Vec<String>>) -> Option<Box<dyn Transport>> {
        Some(Box::new(TlsClient::new(
            true,
            "example.org".to_owned(),
            alpn,
            None,
        )))
    }

    fn generate_client_identity() -> anyhow::Result<(String, String, String)> {
        let mut ca_params = CertificateParams::new(Vec::new())?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca_key = KeyPair::generate()?;
        let ca_cert = ca_params.self_signed(&ca_key)?;
        let issuer = Issuer::new(ca_params, ca_key);

        let mut client_params =
            CertificateParams::new(vec!["client.example.org".to_owned()])?;
        client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        client_params.extended_key_usages =
            vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_key = KeyPair::generate()?;
        let client_cert = client_params.signed_by(&client_key, &issuer)?;

        Ok((ca_cert.pem(), client_cert.pem(), client_key.serialize_pem()))
    }

    async fn get_echo_runner() -> anyhow::Result<DockerTestRunner> {
        let command = format!("exec nc -lk -p {ECHO_CONTAINER_PORT} -e cat");
        let runner = DockerTestRunnerBuilder::new()
            .image(ECHO_IMAGE)
            .no_port()
            .cmd(&["sh", "-c", &command])
            .build()
            .await?;
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        Ok(runner)
    }

    async fn tcp_echo_roundtrip(
        handler: Arc<Handler>,
        echo_ip: String,
    ) -> anyhow::Result<()> {
        let resolver = build_dns_resolver().await?;
        let destination: SocksAddr = (echo_ip, ECHO_CONTAINER_PORT).try_into()?;
        let session = Session {
            destination,
            ..Default::default()
        };

        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            handler.connect_stream(&session, resolver),
        )
        .await??;

        let payload = (0..128 * 1024)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        stream.write_all(&payload).await?;
        stream.flush().await?;

        let mut echoed = vec![0u8; payload.len()];
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            stream.read_exact(&mut echoed),
        )
        .await??;
        anyhow::ensure!(echoed == payload, "docker tcp echo payload mismatch");

        Ok(())
    }

    async fn get_ws_runner(host_port: u16) -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let conf = test_config_dir.join("vless-ws-tls.json");
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");

        let mut builder = DockerTestRunnerBuilder::new().image(IMAGE_VLESS);
        builder =
            if crate::proxy::utils::test_utils::docker_utils::use_ci_host_network() {
                builder.host_network()
            } else {
                builder.host_port(host_port, WS_CONTAINER_PORT)
            };

        let runner = builder
            .mounts(&[
                (conf.to_str().unwrap(), "/etc/v2ray/config.json"),
                (cert.to_str().unwrap(), "/etc/ssl/v2ray/fullchain.pem"),
                (key.to_str().unwrap(), "/etc/ssl/v2ray/privkey.pem"),
            ])
            .build()
            .await?;

        DockerTestRunner::wait_host_tcp_ready(
            LOCAL_ADDR,
            ws_server_port(host_port),
            std::time::Duration::from_secs(20),
        )
        .await?;
        // v2ray can accept TCP before the TLS/WebSocket stack is fully ready,
        // which can produce transient `tls handshake eof` locally and in CI.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        Ok(runner)
    }

    async fn get_grpc_runner(host_port: u16) -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");
        let mut config = tempfile::NamedTempFile::new_in(&test_config_dir)?;
        config.write_all(VLESS_GRPC_TLS_SERVER_CONFIG.as_bytes())?;

        let mut builder = DockerTestRunnerBuilder::new().image(IMAGE_XRAY);
        builder =
            if crate::proxy::utils::test_utils::docker_utils::use_ci_host_network() {
                builder.host_network()
            } else {
                builder.host_port(host_port, XRAY_CONTAINER_PORT)
            };

        let runner = builder
            .mounts(&[
                (config.path().to_str().unwrap(), "/etc/xray/config.json"),
                (cert.to_str().unwrap(), "/etc/ssl/v2ray/fullchain.pem"),
                (key.to_str().unwrap(), "/etc/ssl/v2ray/privkey.pem"),
            ])
            .build()
            .await?;

        DockerTestRunner::wait_host_tcp_ready(
            LOCAL_ADDR,
            server_port(host_port, XRAY_CONTAINER_PORT),
            std::time::Duration::from_secs(20),
        )
        .await?;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        Ok(runner)
    }

    async fn get_mtls_runner(
        host_port: u16,
        client_ca_pem: &str,
    ) -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");
        let mut config = tempfile::NamedTempFile::new_in(&test_config_dir)?;
        config.write_all(VLESS_MTLS_SERVER_CONFIG.as_bytes())?;
        let mut client_ca = tempfile::NamedTempFile::new_in(&test_config_dir)?;
        client_ca.write_all(client_ca_pem.as_bytes())?;

        let mut builder = DockerTestRunnerBuilder::new().image(IMAGE_XRAY);
        builder =
            if crate::proxy::utils::test_utils::docker_utils::use_ci_host_network() {
                builder.host_network()
            } else {
                builder.host_port(host_port, XRAY_CONTAINER_PORT)
            };

        let runner = builder
            .mounts(&[
                (config.path().to_str().unwrap(), "/etc/xray/config.json"),
                (cert.to_str().unwrap(), "/etc/ssl/v2ray/fullchain.pem"),
                (key.to_str().unwrap(), "/etc/ssl/v2ray/privkey.pem"),
                (
                    client_ca.path().to_str().unwrap(),
                    "/etc/ssl/v2ray/client-ca.pem",
                ),
            ])
            .build()
            .await?;

        DockerTestRunner::wait_host_tcp_ready(
            LOCAL_ADDR,
            server_port(host_port, XRAY_CONTAINER_PORT),
            std::time::Duration::from_secs(20),
        )
        .await?;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        Ok(runner)
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_vless_ws() -> anyhow::Result<()> {
        initialize();
        let span = tracing::info_span!("test_vless_ws");
        let _enter = span.enter();
        let host_port = alloc_docker_port();
        let ws_client = WsClient::new(
            "".to_owned(),
            8443,
            "/websocket".to_owned(),
            [("Host".to_owned(), "example.org".to_owned())]
                .into_iter()
                .collect::<HashMap<_, _>>(),
            None,
            0,
            "".to_owned(),
        );

        let echo = get_echo_runner().await?;
        let echo_ip = echo
            .container_ip()
            .ok_or_else(|| anyhow::anyhow!("echo container has no IP"))?;
        let runner = get_ws_runner(host_port).await?;
        let opts = HandlerOptions {
            name: "test-vless-ws".into(),
            common_opts: Default::default(),
            server: LOCAL_ADDR.to_owned(),
            port: ws_server_port(host_port),
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
            flow: None,
            udp: true,
            tls: tls_client(None),
            transport: Some(Box::new(ws_client)),
        };
        let handler = Arc::new(Handler::new(opts));
        let mut containers = MultiDockerTestRunner::default();
        containers.add_with_runner(runner);
        containers.add_with_runner(echo);
        containers
            .run_and_cleanup(
                async move { tcp_echo_roundtrip(handler, echo_ip).await },
            )
            .await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_vless_grpc_tls() -> anyhow::Result<()> {
        initialize();
        let host_port = alloc_docker_port();
        let echo = get_echo_runner().await?;
        let echo_ip = echo
            .container_ip()
            .ok_or_else(|| anyhow::anyhow!("echo container has no IP"))?;
        let runner = get_grpc_runner(host_port).await?;

        let grpc_client =
            GrpcClient::new("example.org".to_owned(), "/grpc-service".try_into()?)
                .with_user_agent(Some("chimera-e2e/1.0".to_owned()))
                .with_ping_interval(Some(5));

        let tls = TlsClient::new(
            true,
            "example.org".to_owned(),
            Some(vec!["h2".to_owned()]),
            Some("h2".to_owned()),
        );

        let opts = HandlerOptions {
            name: "test-vless-grpc-tls".into(),
            common_opts: Default::default(),
            server: LOCAL_ADDR.to_owned(),
            port: server_port(host_port, XRAY_CONTAINER_PORT),
            uuid: UUID.into(),
            flow: None,
            udp: false,
            tls: Some(Box::new(tls)),
            transport: Some(Box::new(grpc_client)),
        };
        let handler = Arc::new(Handler::new(opts));
        let mut containers = MultiDockerTestRunner::default();
        containers.add_with_runner(runner);
        containers.add_with_runner(echo);
        containers
            .run_and_cleanup(async move {
                tcp_echo_roundtrip(handler.clone(), echo_ip.clone()).await?;
                tcp_echo_roundtrip(handler, echo_ip).await
            })
            .await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_vless_mtls() -> anyhow::Result<()> {
        initialize();
        let host_port = alloc_docker_port();
        let echo = get_echo_runner().await?;
        let echo_ip = echo
            .container_ip()
            .ok_or_else(|| anyhow::anyhow!("echo container has no IP"))?;
        let (client_ca, client_cert, client_key) = generate_client_identity()?;
        let runner = get_mtls_runner(host_port, &client_ca).await?;

        let tls = TlsClient::new(true, "example.org".to_owned(), None, None)
            .with_client_auth(Some(client_cert), Some(client_key))?;

        let opts = HandlerOptions {
            name: "test-vless-mtls".into(),
            common_opts: Default::default(),
            server: LOCAL_ADDR.to_owned(),
            port: server_port(host_port, XRAY_CONTAINER_PORT),
            uuid: UUID.into(),
            flow: None,
            udp: false,
            tls: Some(Box::new(tls)),
            transport: None,
        };
        let handler = Arc::new(Handler::new(opts));
        let mut containers = MultiDockerTestRunner::default();
        containers.add_with_runner(runner);
        containers.add_with_runner(echo);
        containers
            .run_and_cleanup(
                async move { tcp_echo_roundtrip(handler, echo_ip).await },
            )
            .await
    }
}

#[cfg(all(test, docker_test, throughput_test))]
mod e2e {
    use crate::{
        proxy::utils::test_utils::{
            consts::*,
            docker_runner::{
                DockerTestRunner, DockerTestRunnerBuilder, RunAndCleanup,
            },
            docker_utils::{
                alloc_port, clash_process_e2e_throughput, config_helper,
                find_clash_rs_binary,
            },
        },
        tests::initialize,
    };

    const CONTAINER_PORT: u16 = 8443;
    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
    const E2E_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;

    const VLESS_WS_TLS_SERVER_CONFIG: &str = r#"{
    "inbounds": [
        {
            "port": 8443,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "level": 0}],
                "decryption": "none",
                "fallbacks": [
                    {"dest": 80},
                    {"path": "/websocket", "dest": 1234, "xver": 1}
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "alpn": ["http/1.1"],
                    "certificates": [{"certificateFile": "/etc/ssl/v2ray/fullchain.pem", "keyFile": "/etc/ssl/v2ray/privkey.pem"}]
                }
            }
        },
        {
            "port": 1234,
            "listen": "127.0.0.1",
            "protocol": "vless",
            "settings": {
                "clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "level": 0}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {"acceptProxyProtocol": true, "path": "/websocket"}
            }
        }
    ],
    "outbounds": [{"protocol": "freedom"}]
}"#;

    async fn get_ws_runner() -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = config_helper::test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");
        let mut tmp = tempfile::NamedTempFile::new_in(&test_config_dir)?;
        use std::io::Write as _;
        tmp.write_all(VLESS_WS_TLS_SERVER_CONFIG.as_bytes())?;
        let result = DockerTestRunnerBuilder::new()
            .image(IMAGE_VLESS)
            .no_port()
            .mounts(&[
                (tmp.path().to_str().unwrap(), "/etc/v2ray/config.json"),
                (cert.to_str().unwrap(), "/etc/ssl/v2ray/fullchain.pem"),
                (key.to_str().unwrap(), "/etc/ssl/v2ray/privkey.pem"),
            ])
            .build()
            .await;
        drop(tmp);
        result
    }

    #[tokio::test]
    async fn e2e_throughput_vless_ws() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_ws_runner().await?;
        let server = container
            .container_ip()
            .ok_or_else(|| anyhow::anyhow!("vless container has no IP"))?;
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
    type: vless
    server: {server}
    port: {port}
    uuid: {uuid}
    udp: false
    tls: true
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /websocket
      headers:
        Host: example.org
rules:
  - MATCH,proxy
"#,
            socks_port = socks_port,
            mmdb = mmdb,
            server = server,
            port = CONTAINER_PORT,
            uuid = UUID,
        );
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "vless-ws",
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
    async fn e2e_throughput_vless_tcp() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_ws_runner().await?;
        let server = container
            .container_ip()
            .ok_or_else(|| anyhow::anyhow!("vless container has no IP"))?;
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
    type: vless
    server: {server}
    port: {port}
    uuid: {uuid}
    udp: false
    tls: true
    skip-cert-verify: true
rules:
  - MATCH,proxy
"#,
            socks_port = socks_port,
            mmdb = mmdb,
            server = server,
            port = CONTAINER_PORT,
            uuid = UUID,
        );
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "vless-tcp",
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
