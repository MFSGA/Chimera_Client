use crate::{
    app::dns::{
        Client, EnhancedResolver, ThreadSafeDNSClient,
        dns_client::DNSNetMode,
        helper::{DnsClientNetworkOptions, make_clients},
    },
    proxy::utils::NetworkPathSource,
    proxy::utils::{direct_only_registry, new_udp_socket},
};
use async_trait::async_trait;
use dhcproto::{Decodable, Encodable};
use futures::FutureExt;
use std::{
    env,
    fmt::{Debug, Formatter},
    io,
    net::Ipv4Addr,
    ops::Add,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, sync::Mutex, task::yield_now};

use super::config::NameServer;
use crate::app::net::{OutboundInterface, get_interface_by_name};
use hickory_proto::op::Message;
use tracing::debug;

const IFACE_TTL: Duration = Duration::from_secs(20);
const DHCP_TTL: Duration = Duration::from_secs(3600);
const DHCP_TIMEOUT: Duration = Duration::from_secs(60);

struct Inner {
    clients: Vec<ThreadSafeDNSClient>,
    // Incremented on every network reset; in-flight DHCP probes must not
    // replace fresh service DNS with a result from a previous network path.
    generation: u64,
    iface_expires_at: std::time::Instant,
    dns_expires_at: std::time::Instant,
    iface_addr: ipnet::IpNet,
}

pub struct DhcpClient {
    iface: OutboundInterface,
    fw_mark: Option<u32>,
    network_path_source: Option<NetworkPathSource>,

    inner: Mutex<Inner>,
}

impl Debug for DhcpClient {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhcpClient")
            .field("iface", &self.iface)
            .finish()
    }
}

#[async_trait]
impl Client for DhcpClient {
    fn id(&self) -> String {
        format!("dhcp#{}", self.iface.name)
    }

    async fn exchange(&self, msg: &Message) -> anyhow::Result<Message> {
        let clients = self.resolve().await?;
        let mut dbg_str = vec![];
        for c in &clients {
            dbg_str.push(format!("{c:?}"));
        }
        debug!("using clients: {:?}", dbg_str);
        tokio::time::timeout(
            DHCP_TIMEOUT,
            EnhancedResolver::batch_exchange(&clients, msg),
        )
        .await?
    }

    async fn reset_transport(&self) -> anyhow::Result<u32> {
        let clients = {
            let mut inner = self.inner.lock().await;
            inner.generation = inner.generation.wrapping_add(1);
            inner.iface_expires_at = Instant::now();
            inner.dns_expires_at = Instant::now();
            inner.iface_addr = ipnet::IpNet::default();
            std::mem::take(&mut inner.clients)
        };

        // Network-path changes must invalidate *all* discovered DHCP DNS
        // transports. An error or stall in one old connection cannot prevent
        // a different connection from being reset before the outer resolver
        // recovery deadline cancels this operation.
        let results = futures::future::join_all(clients.into_iter().map(
            |client| async move {
                let id = client.id();
                let result = tokio::time::timeout(
                    Duration::from_secs(5),
                    client.reset_transport(),
                )
                .await;
                (id, result)
            },
        ))
        .await;
        let mut reset = 0_u32;
        let mut errors = Vec::new();
        for (id, result) in results {
            match result {
                Ok(Ok(count)) => reset = reset.saturating_add(count),
                Ok(Err(error)) => errors.push(format!("{id}: {error}")),
                Err(_) => {
                    errors.push(format!("{id}: DHCP DNS transport reset timed out"))
                }
            }
        }
        if !errors.is_empty() {
            anyhow::bail!(
                "DHCP DNS transport cleanup failed: {}",
                errors.join("; ")
            );
        }
        Ok(reset)
    }
}

impl DhcpClient {
    pub async fn new(
        iface: &str,
        fw_mark: Option<u32>,
        network_path_source: Option<NetworkPathSource>,
    ) -> io::Result<Self> {
        let iface = get_interface_by_name(iface).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("can not find interface: {iface}"),
            )
        })?;
        Ok(Self {
            iface,
            inner: Mutex::new(Inner {
                clients: vec![],
                generation: 0,
                iface_expires_at: Instant::now(),
                dns_expires_at: Instant::now(),
                iface_addr: ipnet::IpNet::default(),
            }),
            fw_mark,
            network_path_source,
        })
    }

    async fn resolve(&self) -> io::Result<Vec<ThreadSafeDNSClient>> {
        // Capture before checking the lease: a concurrent network reset in
        // either the lease check or DHCP discovery invalidates this attempt.
        let generation = self.inner.lock().await.generation;
        let expired = self.update_if_lease_expired().await?;
        if expired {
            let iface =
                get_interface_by_name(&self.iface.name).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "DHCP interface disappeared",
                    )
                })?;
            let dns = probe_dns_server(&iface).await?;
            let discovered_clients = make_clients(
                Self::discovered_upstreams(&iface, dns),
                None,
                None,
                direct_only_registry(),
                None,
                DnsClientNetworkOptions {
                    fw_mark: self.fw_mark,
                    network_path_source: self.network_path_source.clone(),
                    ..Default::default()
                },
            )
            .await
            .map_err(|err| io::Error::other(err.to_string()))?;
            self.install_discovered_clients(generation, discovered_clients)
                .await?;
        }

        Ok(self.inner.lock().await.clients.clone())
    }

    fn discovered_upstreams(
        iface: &OutboundInterface,
        servers: Vec<Ipv4Addr>,
    ) -> Vec<NameServer> {
        // Mihomo dhcp.go binds discovered resolver egress to the DHCP
        // interface. Keep the same physical service NIC that offered these
        // addresses instead of silently routing their DNS via the default NIC.
        servers
            .into_iter()
            .map(|address| NameServer {
                net: DNSNetMode::Udp,
                host: url::Host::Ipv4(address),
                port: 53,
                interface: Some(iface.clone()),
                proxy: None,
                doh_path: None,
            })
            .collect()
    }

    async fn install_discovered_clients(
        &self,
        generation: u64,
        discovered_clients: Vec<ThreadSafeDNSClient>,
    ) -> io::Result<()> {
        let mut inner = self.inner.lock().await;
        if inner.generation != generation {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "DHCP DNS discovery invalidated by network path reset",
            ));
        }
        inner.clients = discovered_clients;
        Ok(())
    }

    /// Check if interface updated or DHCP changed
    /// and update if necessary
    async fn update_if_lease_expired(&self) -> io::Result<bool> {
        let mut inner = self.inner.lock().await;
        if inner.clients.is_empty() {
            return Ok(true);
        }

        if Instant::now() < inner.iface_expires_at {
            return Ok(false);
        }

        inner.iface_expires_at = Instant::now().add(IFACE_TTL);

        let iface = get_interface_by_name(&self.iface.name).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "DHCP interface disappeared")
        })?;

        let addr = iface.addr_v4.ok_or(io::Error::other(format!(
            "no address on interface: {:?}",
            self.iface
        )))?;

        if Instant::now() < inner.dns_expires_at
            && inner.iface_addr.addr() == addr
            && inner.iface_addr.netmask()
                == iface.netmask_v4.ok_or(io::Error::other(format!(
                    "no netmask on iface: {:?}",
                    self.iface
                )))?
        {
            Ok(false)
        } else {
            inner.dns_expires_at = Instant::now().add(DHCP_TTL);
            inner.iface_addr = ipnet::IpNet::new(
                addr.into(),
                u32::from(iface.netmask_v4.ok_or(io::Error::other("no netmask"))?)
                    .count_ones() as _,
            )
            .map_err(|_x| {
                io::Error::other(format!(
                    "invalid netmask: {}",
                    iface.netmask_v4.expect("expect netmask parse error")
                ))
            })?;
            Ok(true)
        }
    }
}

async fn listen_dhcp_client(iface: &OutboundInterface) -> io::Result<UdpSocket> {
    let listen_addr = match env::consts::OS {
        "linux" => "255.255.255.255:68",
        _ => "0.0.0.0:68",
    };

    new_udp_socket(
        Some(listen_addr.parse().expect("must parse")),
        Some(iface),
        #[cfg(target_os = "linux")]
        None,
        false,
        None,
    )
    .await
}

async fn probe_dns_server(iface: &OutboundInterface) -> io::Result<Vec<Ipv4Addr>> {
    debug!("probing NS servers from DHCP");
    let socket = listen_dhcp_client(iface).await?;

    let mac_address = &iface
        .mac_addr
        .as_ref()
        .ok_or(io::Error::other(format!(
            "no MAC address on interface: {iface:?}"
        )))?
        .split(':')
        .map(|x| {
            u8::from_str_radix(x, 16)
                .map_err(|_x| io::Error::other("malformed MAC addr"))
        })
        .collect::<io::Result<Vec<u8>>>()?;

    let mut msg = dhcproto::v4::Message::default();
    msg.set_flags(dhcproto::v4::Flags::default().set_broadcast())
        .set_chaddr(mac_address.as_slice())
        .opts_mut()
        .insert(dhcproto::v4::DhcpOption::MessageType(
            dhcproto::v4::MessageType::Discover,
        ));

    msg.opts_mut()
        .insert(dhcproto::v4::DhcpOption::ParameterRequestList(vec![
            dhcproto::v4::OptionCode::SubnetMask,
            dhcproto::v4::OptionCode::Router,
            dhcproto::v4::OptionCode::DomainNameServer,
            dhcproto::v4::OptionCode::DomainName,
        ]));

    let (mut tx, rx) = tokio::sync::oneshot::channel::<io::Result<Vec<Ipv4Addr>>>();

    let mut rx = rx.fuse();

    let r = Arc::new(socket);
    let s = r.clone();

    let xid = msg.xid();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 576];

        let get_response = async move {
            loop {
                let (n_read, _) = r.recv_from(&mut buf).await?;

                // fucking deep if-else hell
                if let Ok(reply) = dhcproto::v4::Message::from_bytes(&buf[..n_read])
                    && let Some(op) =
                        reply.opts().get(dhcproto::v4::OptionCode::MessageType)
                {
                    match op {
                        dhcproto::v4::DhcpOption::MessageType(msg_type) => {
                            if msg_type == &dhcproto::v4::MessageType::Offer {
                                if reply.xid() == xid
                                    && let Some(op) = reply.opts().get(
                                        dhcproto::v4::OptionCode::DomainNameServer,
                                    )
                                {
                                    match op {
                                                dhcproto::v4::DhcpOption::DomainNameServer(dns) => {
                                                    debug!(
                                                        "got NS servers {:?} from DHCP",
                                                        dns
                                                    );
                                                    return Ok(dns.clone());
                                                }
                                                _ => yield_now().await,
                                            }
                                }
                                yield_now().await
                            }
                        }
                        _ => yield_now().await,
                    }
                }
            }
        };

        tokio::select! {
            _ = tx.closed() => {debug!("future cancelled, likely other clients won")},
            value = get_response => {
                if let Err(value) = tx.send(value) {
                    debug!("send error: {:?}", value);
                }
            },
        }
    });

    s.send_to(&msg.to_vec().expect("must encode"), "255.255.255.255:67")
        .await?;

    tokio::select! {
        result = &mut rx => {
            result.map_err(|_x| io::Error::other("dhcp receive task exited before returning a result"))?
        },

        _ = tokio::time::sleep(Duration::from_secs(10)) => {
            debug!("DHCP timeout after 10 secs");
            Err(io::Error::other("dhcp timeout"))
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        app::net::get_outbound_interface,
        dns::dhcp::{DhcpClient, probe_dns_server},
    };

    #[tokio::test]
    async fn missing_interface_is_reported_without_panicking() {
        let err = DhcpClient::new("__chimera_missing_interface__", None, None)
            .await
            .expect_err("missing DHCP interface should return an error");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(err.to_string().contains("__chimera_missing_interface__"));
    }

    #[tokio::test]
    #[ignore = "requires DHCP server on CI"]
    async fn test_probe_ns() {
        let ns = probe_dns_server(
            &get_outbound_interface().expect("cant find outbound interface"),
        )
        .await
        .expect("must prob");
        assert!(!ns.is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Debug)]
    struct ResetProbe {
        label: &'static str,
        invoked: Arc<AtomicBool>,
        failure: bool,
        stall: bool,
    }

    #[async_trait]
    impl Client for ResetProbe {
        fn id(&self) -> String {
            self.label.to_owned()
        }

        async fn exchange(&self, _: &Message) -> anyhow::Result<Message> {
            anyhow::bail!("offline reset probe cannot exchange DNS")
        }

        async fn reset_transport(&self) -> anyhow::Result<u32> {
            self.invoked.store(true, Ordering::SeqCst);
            if self.stall {
                std::future::pending::<()>().await;
            }
            if self.failure {
                anyhow::bail!("{} reset failed", self.label);
            }
            Ok(3)
        }
    }

    fn test_client(handlers: Vec<ThreadSafeDNSClient>) -> DhcpClient {
        // Purely synthetic adapter; no live DHCP interface lookup or sockets.
        DhcpClient {
            iface: OutboundInterface {
                name: "offline-test-only".to_owned(),
                addr_v4: None,
                netmask_v4: None,
                broadcast_v4: None,
                addr_v6: None,
                netmask_v6: None,
                broadcast_v6: None,
                index: 0,
                mac_addr: None,
            },
            fw_mark: None,
            network_path_source: None,
            inner: Mutex::new(Inner {
                clients: handlers,
                generation: 0,
                iface_expires_at: Instant::now(),
                dns_expires_at: Instant::now(),
                iface_addr: ipnet::IpNet::default(),
            }),
        }
    }

    fn probe(
        label: &'static str,
        invoked: Arc<AtomicBool>,
        failure: bool,
        stall: bool,
    ) -> ThreadSafeDNSClient {
        Arc::new(ResetProbe {
            label,
            invoked,
            failure,
            stall,
        })
    }

    #[tokio::test]
    async fn dhcp_discovery_started_before_network_reset_must_not_reinstall_stale_dns()
     {
        // Simulates the discovery completion path without issuing DHCP.
        let client = test_client(Vec::new());
        let old_generation = client.inner.lock().await.generation;
        client.reset_transport().await.unwrap();
        let attempted = Arc::new(AtomicBool::new(false));
        let stale = probe("old-network-dns", attempted, false, false);
        let error = client
            .install_discovered_clients(old_generation, vec![stale])
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(client.inner.lock().await.clients.is_empty());
    }

    #[test]
    fn dhcp_discovered_upstreams_keep_the_lease_interface() {
        // Fixed Mihomo's dhcp.go assigns ProxyName=ifaceName to discovered
        // DNS. Chimera must not silently pick the default outbound NIC.
        let client = test_client(Vec::new());
        let dns = vec![Ipv4Addr::new(192, 0, 2, 53), Ipv4Addr::new(192, 0, 2, 54)];
        let upstreams = DhcpClient::discovered_upstreams(&client.iface, dns.clone());
        assert_eq!(upstreams.len(), 2);
        for (upstream, expected) in upstreams.iter().zip(dns) {
            assert_eq!(upstream.net, DNSNetMode::Udp);
            assert_eq!(upstream.host, url::Host::<String>::Ipv4(expected));
            assert_eq!(upstream.port, 53);
            let bound_iface = upstream
                .interface
                .as_ref()
                .expect("discovered DNS must retain its DHCP NIC");
            assert_eq!(bound_iface.name, client.iface.name);
            assert_eq!(bound_iface.index, client.iface.index);
            assert!(upstream.proxy.is_none());
        }
    }

    #[tokio::test]
    async fn dhcp_discovery_on_current_network_can_commit_its_clients() {
        let client = test_client(Vec::new());
        let generation = client.inner.lock().await.generation;
        let attempted = Arc::new(AtomicBool::new(false));
        let resolved = probe("current-network-dns", attempted, false, false);
        client
            .install_discovered_clients(generation, vec![resolved])
            .await
            .unwrap();
        assert_eq!(client.inner.lock().await.clients.len(), 1);
        assert_eq!(client.reset_transport().await.unwrap(), 3);
        assert!(client.inner.lock().await.clients.is_empty());
    }

    #[tokio::test]
    async fn dhcp_reset_attempts_every_old_transport_even_when_first_fails() {
        // Mihomo resets every DHCP child. A failed first Chimera child must
        // not leave later old-path transports untouched after network change.
        let first = Arc::new(AtomicBool::new(false));
        let second = Arc::new(AtomicBool::new(false));
        let client = test_client(vec![
            probe("first", first.clone(), true, false),
            probe("second", second.clone(), false, false),
        ]);
        let error = client.reset_transport().await.unwrap_err().to_string();
        assert!(error.contains("first reset failed"), "{error}");
        assert!(first.load(Ordering::SeqCst));
        assert!(
            second.load(Ordering::SeqCst),
            "second old DHCP DNS transport was not reset"
        );
        assert!(client.inner.lock().await.clients.is_empty());
    }

    #[tokio::test]
    async fn dhcp_reset_reports_every_failure_without_claiming_success() {
        let first = Arc::new(AtomicBool::new(false));
        let second = Arc::new(AtomicBool::new(false));
        let client = test_client(vec![
            probe("first", first.clone(), true, false),
            probe("second", second.clone(), true, false),
        ]);
        let error = client.reset_transport().await.unwrap_err().to_string();
        assert!(error.contains("first reset failed"), "{error}");
        assert!(error.contains("second reset failed"), "{error}");
        assert!(first.load(Ordering::SeqCst));
        assert!(second.load(Ordering::SeqCst));
        assert!(client.inner.lock().await.clients.is_empty());
    }

    #[tokio::test]
    async fn dhcp_reset_counts_all_successful_old_transports_once() {
        let first = Arc::new(AtomicBool::new(false));
        let second = Arc::new(AtomicBool::new(false));
        let client = test_client(vec![
            probe("first", first.clone(), false, false),
            probe("second", second.clone(), false, false),
        ]);
        assert_eq!(client.reset_transport().await.unwrap(), 6);
        assert_eq!(client.reset_transport().await.unwrap(), 0);
        assert!(first.load(Ordering::SeqCst));
        assert!(second.load(Ordering::SeqCst));
        assert!(client.inner.lock().await.clients.is_empty());
    }

    #[tokio::test]
    async fn stalled_dhcp_reset_does_not_block_sibling_cleanup() {
        let first = Arc::new(AtomicBool::new(false));
        let second = Arc::new(AtomicBool::new(false));
        let client = test_client(vec![
            probe("stalled", first.clone(), false, true),
            probe("second", second.clone(), false, false),
        ]);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                client.reset_transport()
            )
            .await
            .is_err()
        );
        assert!(first.load(Ordering::SeqCst));
        assert!(
            second.load(Ordering::SeqCst),
            "stalled DHCP child prevented sibling reset"
        );
        assert!(client.inner.lock().await.clients.is_empty());
    }
}
