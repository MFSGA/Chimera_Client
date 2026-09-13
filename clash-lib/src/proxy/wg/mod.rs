use self::{keys::KeyBytes, wireguard::Config};
use super::{
    ConnectorType, DialWithConnector, HandlerCommonOptions, OutboundHandler,
    OutboundType, PlainProxyAPIResponse, utils::RemoteConnector,
};
use crate::{
    Error,
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::errors::{map_io_error, new_io_error},
    impl_default_connector,
    session::Session,
};
use async_trait::async_trait;
use erased_serde::Serialize as ErasedSerialize;
use futures::TryFutureExt;
use ipnet::IpNet;
use rand::seq::IndexedRandom;
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};
use tokio::sync::OnceCell;

mod device;
mod events;
mod keys;
mod ports;
mod stack;
mod wireguard;

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub ip: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
    pub private_key: String,
    pub public_key: String,
    pub pre_shared_key: Option<String>,
    pub remote_dns_resolve: bool,
    pub dns: Option<Vec<String>>,
    pub mtu: Option<u16>,
    pub udp: bool,
    pub allowed_ips: Option<Vec<String>>,
    pub reserved_bits: Option<Vec<u8>>,
}

struct Inner {
    device_manager: Arc<device::DeviceManager>,
    wg_handle: tokio::task::JoinHandle<()>,
    device_manager_handle: tokio::task::JoinHandle<()>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.wg_handle.abort();
        self.device_manager_handle.abort();
    }
}

pub struct Handler {
    opts: HandlerOptions,
    inner: OnceCell<Inner>,

    connector: tokio::sync::RwLock<Option<Arc<dyn RemoteConnector>>>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuard")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl_default_connector!(Handler);

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            inner: OnceCell::new(),

            connector: Default::default(),
        }
    }

    pub fn try_new(opts: HandlerOptions) -> Result<Self, Error> {
        Self::validate_options(&opts)?;
        Ok(Self::new(opts))
    }

    fn parse_key(value: &str, kind: &str) -> Result<KeyBytes, Error> {
        value.parse::<KeyBytes>().map_err(|err| {
            Error::InvalidConfig(format!("invalid WireGuard {kind}: {err}"))
        })
    }

    fn validate_options(opts: &HandlerOptions) -> Result<(), Error> {
        Self::parse_key(&opts.private_key, "private key")?;
        Self::parse_key(&opts.public_key, "public key")?;
        if let Some(key) = opts.pre_shared_key.as_deref() {
            Self::parse_key(key, "pre-shared key")?;
        }
        if let Some(servers) = &opts.dns {
            for server in servers {
                server.parse::<IpAddr>().map_err(|err| {
                    Error::InvalidConfig(format!(
                        "invalid WireGuard DNS server {server:?}: {err}"
                    ))
                })?;
            }
        }
        Ok(())
    }

    /// this is a one time initialization, however in theory sess.so_mark
    /// and sess.iface should be all the same
    /// ideally we move the so_mark and iface to a global context
    async fn initialize_inner(
        &self,
        resolver: ThreadSafeDNSResolver,
        sess: &Session,
    ) -> Result<&Inner, Error> {
        self.inner
            .get_or_try_init(|| async {
                let recv_pair = tokio::sync::mpsc::channel(1024);
                let send_pair = tokio::sync::mpsc::channel(1024);
                let server_ip = resolver
                    .resolve(&self.opts.server, false)
                    .await
                    .map_err(map_io_error)?
                    .ok_or(new_io_error(
                        format!("invalid remote server: {}", self.opts.server)
                            .as_str(),
                    ))?;
                let allowed_ips = self
                    .opts
                    .allowed_ips
                    .as_ref()
                    .map(|ips| {
                        ips.iter()
                            .map(|ip| {
                                ip.parse::<IpNet>().map_err(|e| {
                                    new_io_error(
                                        format!("invalid allowed ip: {e}").as_str(),
                                    )
                                })
                            })
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .transpose()?
                    .unwrap_or_default();

                let wg = wireguard::WireguardTunnel::new(
                    Config {
                        private_key: Self::parse_key(
                            &self.opts.private_key,
                            "private key",
                        )?
                        .0
                        .into(),
                        endpoint_public_key: Self::parse_key(
                            &self.opts.public_key,
                            "public key",
                        )?
                        .0
                        .into(),
                        pre_shared_key: self
                            .opts
                            .pre_shared_key
                            .as_deref()
                            .map(|s| {
                                Self::parse_key(s, "pre-shared key")
                                    .map(|key| key.0.into())
                            })
                            .transpose()?,
                        remote_endpoint: (server_ip, self.opts.port).into(),
                        source_peer_ip: self.opts.ip,
                        source_peer_ipv6: self.opts.ipv6,
                        keepalive_seconds: Some(10),
                        allowed_ips,
                        reserved_bits: match &self.opts.reserved_bits {
                            Some(bits) if bits.len() >= 3 => {
                                [bits[0], bits[1], bits[2]]
                            }
                            _ => [0, 0, 0],
                        },
                    },
                    recv_pair.0,
                    send_pair.1,
                    resolver.clone(),
                    self.connector.read().await.as_ref().cloned(),
                    sess,
                )
                .await
                .map_err(map_io_error)?;

                let wg_handle = tokio::spawn(async move {
                    wg.start_polling().await;
                });

                // use to notify the device manager to poll sockets
                let packet_notifier = tokio::sync::mpsc::channel(1024);

                let device = device::VirtualIpDevice::new(
                    send_pair.0,
                    recv_pair.1,
                    packet_notifier.0,
                    self.opts.mtu.unwrap_or(1420) as usize,
                );

                let device_manager = Arc::new(device::DeviceManager::new(
                    self.opts.ip,
                    self.opts.ipv6,
                    resolver,
                    if self.opts.remote_dns_resolve {
                        self.opts
                            .dns
                            .as_ref()
                            .map(|server| {
                                server
                                    .iter()
                                    .map(|s| {
                                        s.parse::<IpAddr>()
                                            .map(|ip| (ip, 53).into())
                                            .map_err(|err| {
                                                Error::InvalidConfig(format!(
                                                    "invalid WireGuard DNS server {s:?}: {err}"
                                                ))
                                            })
                                    })
                                    .collect::<Result<Vec<_>, _>>()
                            })
                            .transpose()?
                            .unwrap_or_default()
                    } else {
                        vec![]
                    },
                    packet_notifier.1,
                ));

                let device_manager_clone = device_manager.clone();
                let device_manager_handle = tokio::spawn(async move {
                    device_manager_clone.poll_sockets(device).await;
                });

                Ok(Inner {
                    device_manager,
                    wg_handle,
                    device_manager_handle,
                })
            })
            .await
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
        OutboundType::WireGuard
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    /// connect to remote target via TCP
    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let inner = self
            .initialize_inner(resolver.clone(), sess)
            .await
            .map_err(map_io_error)?;

        let ip = if self.opts.remote_dns_resolve
            && sess.destination.is_domain()
            && self.opts.dns.as_ref().is_some_and(|x| !x.is_empty())
        {
            let server = self
                .opts
                .dns
                .as_ref()
                .unwrap()
                .choose(&mut rand::rng())
                .unwrap();

            inner
                .device_manager
                .look_up_dns(
                    &sess.destination.host(),
                    (
                        server.parse::<IpAddr>().map_err(|err| {
                            new_io_error(format!(
                                "invalid WireGuard DNS server {server:?}: {err}"
                            ))
                        })?,
                        53,
                    )
                        .into(),
                )
                .await
                .ok_or(new_io_error("invalid remote address"))?
        } else {
            resolver
                .resolve(&sess.destination.host(), false)
                .map_err(map_io_error)
                .await?
                .ok_or(new_io_error("invalid remote address"))?
        };

        let remote = (ip, sess.destination.port()).into();

        let socket = inner.device_manager.new_tcp_socket(remote).await?;
        let chained = ChainedStreamWrapper::new(socket);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let inner = self
            .initialize_inner(resolver, sess)
            .await
            .map_err(map_io_error)?;

        let socket = inner.device_manager.new_udp_socket().await?;
        let chained = ChainedDatagramWrapper::new(socket);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::None
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> {
        Some(self as _)
    }
}

#[async_trait]
impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        let mut m = HashMap::new();
        m.insert("server".to_owned(), Box::new(self.opts.server.clone()) as _);
        m.insert("port".to_owned(), Box::new(self.opts.port) as _);
        m.insert(
            "public-key".to_owned(),
            Box::new(self.opts.public_key.clone()) as _,
        );
        m
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use crate::app::dns::MockClashResolver;

    use super::*;

    struct TaskDropGuard(Arc<AtomicUsize>);

    impl Drop for TaskDropGuard {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn pending_task(dropped: Arc<AtomicUsize>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let _guard = TaskDropGuard(dropped);
            std::future::pending::<()>().await;
        })
    }

    #[tokio::test]
    async fn dropping_inner_aborts_background_tasks() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let wg_handle = pending_task(dropped.clone());
        let device_manager_handle = pending_task(dropped.clone());
        tokio::task::yield_now().await;

        let (_packet_notifier_tx, packet_notifier_rx) =
            tokio::sync::mpsc::channel(1);
        let device_manager = Arc::new(device::DeviceManager::new(
            Ipv4Addr::LOCALHOST,
            None,
            Arc::new(MockClashResolver::new()),
            vec![],
            packet_notifier_rx,
        ));

        drop(Inner {
            device_manager,
            wg_handle,
            device_manager_handle,
        });

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while dropped.load(Ordering::SeqCst) != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropping WireGuard inner state should abort both background tasks");
    }
}

#[cfg(all(test, docker_test))]
mod tests {

    use crate::proxy::utils::{
        GLOBAL_DIRECT_CONNECTOR,
        test_utils::{
            Suite,
            config_helper::test_config_base_dir,
            docker_runner::{DockerTestRunnerBuilder, alloc_docker_port},
        },
    };

    use super::{
        super::utils::test_utils::{consts::*, docker_runner::DockerTestRunner},
        *,
    };
    use crate::{
        proxy::utils::test_utils::run_test_suites_and_cleanup, tests::initialize,
    };

    // see: https://github.com/linuxserver/docker-wireguard?tab=readme-ov-file#usage
    // we shouldn't run the wireguard server with host mode, or
    // the sysctl of `net.ipv4.conf.all.src_valid_mark` will fail
    async fn get_runner(host_port: u16) -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let wg_config = test_config_dir.join("wg");
        // the following configs is in accordance with the config in `wg`
        // dir
        DockerTestRunnerBuilder::new()
            .image(IMAGE_WG)
            .env(&[
                "PUID=1000",
                "PGID=1000",
                "TZ=Etc/UTC",
                "SERVERPORT=10002",
                "SERVERURL=127.0.0.1",
                "PEERS=1",
                "PEERDNS=auto",
                "INTERNAL_SUBNET=10.13.13.0",
                "ALLOWEDIPS=0.0.0.0/0",
            ])
            .mounts(&[(wg_config.to_str().unwrap(), "/config")])
            .sysctls(&[("net.ipv4.conf.all.src_valid_mark", "1")])
            .cap_add(&["NET_ADMIN"])
            .net_mode("bridge") // the default network mode for testing is `host`
            .host_port(host_port, 10002)
            .build()
            .await
    }

    #[tokio::test]
    async fn test_wg() -> anyhow::Result<()> {
        initialize();
        let host_port = alloc_docker_port();

        let runner = get_runner(host_port).await?;

        let opts = HandlerOptions {
            name: "wg".to_owned(),
            common_opts: Default::default(),
            server: runner.container_ip().unwrap_or("127.0.0.1".to_owned()),
            port: 10002,
            ip: Ipv4Addr::new(10, 13, 13, 2),
            ipv6: None,
            private_key: "KIlDUePHyYwzjgn18przw/ZwPioJhh2aEyhxb/dtCXI=".to_owned(),
            public_key: "INBZyvB715sA5zatkiX8Jn3Dh5tZZboZ09x4pkr66ig=".to_owned(),
            pre_shared_key: Some(
                "+JmZErvtDT4ZfQequxWhZSydBV+ItqUcPMHUWY1j2yc=".to_owned(),
            ),
            remote_dns_resolve: false,
            dns: None,
            mtu: Some(1000),
            udp: true,
            allowed_ips: Some(vec!["0.0.0.0/0".to_owned()]),
            reserved_bits: None,
        };
        let handler = Arc::new(Handler::new(opts));
        handler
            .register_connector(GLOBAL_DIRECT_CONNECTOR.clone())
            .await;

        // cannot run the ping pong test, since the wireguard server is running
        // on bridge network mode and the `net.ipv4.conf.all.
        // src_valid_mark` is not supported in the host network mode the
        // latency test should be enough

        // FIXME: wait for the startup of the test runner in a more elegant way
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        run_test_suites_and_cleanup(
            handler,
            runner,
            &[Suite::LatencyTcp, Suite::DnsUdp],
        )
        .await
    }
}
