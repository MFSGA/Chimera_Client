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

        let stream = self.inner_connect_stream(stream, sess).await?;
        let chained = ChainedStreamWrapper::new(stream);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> std::io::Result<BoxedChainedDatagram> {
        let stream = connector
            .connect_stream(
                resolver.clone(),
                self.opts.server.as_str(),
                self.opts.port,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;

        let datagram = self.inner_connect_datagram(stream, sess, resolver).await?;
        let chained = ChainedDatagramWrapper::new(datagram);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
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
