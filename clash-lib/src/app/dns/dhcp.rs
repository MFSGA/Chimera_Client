use std::{
    collections::HashMap,
    fmt::{Debug, Formatter},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::Add,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use dhcproto::{Decodable, Encodable};
use futures::FutureExt;
use hickory_proto::op::Message;
#[cfg(feature = "tun")]
use socket2::{Domain, Socket, Type};
#[cfg(feature = "tun")]
use tokio::net::UdpSocket;
use tokio::{sync::Mutex, task::yield_now};
use tracing::debug;

use super::{
    Client, ThreadSafeDNSClient,
    config::NameServer,
    dns_client::DNSNetMode,
    helper::make_clients,
    resolver::EnhancedResolver,
};
#[cfg(feature = "tun")]
use crate::app::net::{get_interface_by_name, get_outbound_interface};
use crate::{
    app::net::OutboundInterface,
    proxy::utils::{maybe_protect_socket, must_bind_socket_on_interface},
};

const IFACE_TTL: Duration = Duration::from_secs(20);
const DHCP_TTL: Duration = Duration::from_secs(3600);
const DHCP_TIMEOUT: Duration = Duration::from_secs(60);

struct Inner {
    clients: Vec<ThreadSafeDNSClient>,
    iface_expires_at: Instant,
    dns_expires_at: Instant,
    iface_addr: ipnet::IpNet,
}

pub struct DhcpClient {
    iface: OutboundInterface,
    fw_mark: Option<u32>,

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
        for client in &clients {
            dbg_str.push(format!("{client:?}"));
        }
        debug!(clients = ?dbg_str, "using dhcp dns clients");
        tokio::time::timeout(
            DHCP_TIMEOUT,
            EnhancedResolver::batch_exchange(&clients, msg),
        )
        .await?
    }
}

impl DhcpClient {
    pub async fn new(iface: &str, fw_mark: Option<u32>) -> Self {
        let iface = resolve_interface(iface).unwrap_or_else(|| {
            panic!("can not find interface for dhcp dns: {iface}")
        });

        Self {
            iface,
            fw_mark,
            inner: Mutex::new(Inner {
                clients: vec![],
                iface_expires_at: Instant::now(),
                dns_expires_at: Instant::now(),
                iface_addr: ipnet::IpNet::default(),
            }),
        }
    }

    async fn resolve(&self) -> io::Result<Vec<ThreadSafeDNSClient>> {
        let expired = self.update_if_lease_expired().await?;
        if expired {
            let dns = probe_dns_server(&self.iface, self.fw_mark).await?;
            let servers: Vec<NameServer> = dns
                .into_iter()
                .map(|server| NameServer {
                    net: DNSNetMode::Udp,
                    host: url::Host::Ipv4(server),
                    port: 53,
                    interface: None,
                    proxy: None,
                })
                .collect();

            let mut inner = self.inner.lock().await;
            inner.clients = make_clients(
                &servers,
                None,
                HashMap::new(),
                None,
                self.fw_mark,
                false,
            )
            .await;
        }

        Ok(self.inner.lock().await.clients.clone())
    }

    async fn update_if_lease_expired(&self) -> io::Result<bool> {
        let mut inner = self.inner.lock().await;
        if inner.clients.is_empty() {
            return Ok(true);
        }

        if Instant::now() < inner.iface_expires_at {
            return Ok(false);
        }

        inner.iface_expires_at = Instant::now().add(IFACE_TTL);

        let addr = self.iface.addr_v4.ok_or(io::Error::other(format!(
            "no address on interface: {:?}",
            self.iface
        )))?;

        let netmask = self.iface.netmask_v4.ok_or(io::Error::other(format!(
            "no netmask on interface: {:?}",
            self.iface
        )))?;

        if Instant::now() < inner.dns_expires_at
            && inner.iface_addr.addr() == IpAddr::V4(addr)
            && inner.iface_addr.netmask() == IpAddr::V4(netmask)
        {
            Ok(false)
        } else {
            inner.dns_expires_at = Instant::now().add(DHCP_TTL);
            inner.iface_addr = ipnet::IpNet::new(
                addr.into(),
                u32::from(netmask).count_ones() as _,
            )
            .map_err(|_| io::Error::other(format!("invalid netmask: {netmask}")))?;
            Ok(true)
        }
    }
}

#[cfg(feature = "tun")]
fn resolve_interface(iface: &str) -> Option<OutboundInterface> {
    match iface {
        "system" | "" => get_outbound_interface(),
        name => get_interface_by_name(name),
    }
}

#[cfg(not(feature = "tun"))]
fn resolve_interface(_iface: &str) -> Option<OutboundInterface> {
    None
}

#[cfg(feature = "tun")]
async fn listen_dhcp_client(
    iface: &OutboundInterface,
    fw_mark: Option<u32>,
) -> io::Result<UdpSocket> {
    let listen_addr: SocketAddr = match std::env::consts::OS {
        "linux" => "255.255.255.255:68".parse().expect("valid dhcp listen addr"),
        _ => "0.0.0.0:68".parse().expect("valid dhcp listen addr"),
    };

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
    socket.set_broadcast(true)?;
    socket.set_reuse_address(true)?;
    must_bind_socket_on_interface(&socket, iface, Domain::IPV4)?;
    maybe_protect_socket(&socket)?;
    #[cfg(target_os = "linux")]
    if let Some(fw_mark) = fw_mark {
        socket.set_mark(fw_mark)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&listen_addr.into())?;

    UdpSocket::from_std(socket.into())
}

#[cfg(not(feature = "tun"))]
async fn listen_dhcp_client(
    _iface: &OutboundInterface,
    _fw_mark: Option<u32>,
) -> io::Result<tokio::net::UdpSocket> {
    Err(io::Error::other("dhcp dns requires the `tun` feature"))
}

#[cfg(feature = "tun")]
async fn probe_dns_server(
    iface: &OutboundInterface,
    fw_mark: Option<u32>,
) -> io::Result<Vec<Ipv4Addr>> {
    debug!(iface = %iface.name, "probing dns servers from dhcp");
    let socket = listen_dhcp_client(iface, fw_mark).await?;

    let mac_address = iface
        .mac_addr
        .as_ref()
        .ok_or(io::Error::other(format!(
            "no MAC address on interface: {iface:?}"
        )))?
        .split(':')
        .map(|value| {
            u8::from_str_radix(value, 16)
                .map_err(|_| io::Error::other("malformed MAC addr"))
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

    let (mut tx, rx) = tokio::sync::oneshot::channel::<Vec<Ipv4Addr>>();
    let mut rx = rx.fuse();

    let recv_socket = Arc::new(socket);
    let send_socket = recv_socket.clone();
    let xid = msg.xid();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 576];
        let get_response = async move {
            loop {
                let (n_read, _) = recv_socket
                    .recv_from(&mut buf)
                    .await
                    .expect("failed to receive DHCP offer");

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
                                            debug!(dns = ?dns, "got dns servers from dhcp");
                                            return dns.clone();
                                        }
                                        _ => yield_now().await,
                                    }
                                }
                                yield_now().await;
                            }
                        }
                        _ => yield_now().await,
                    }
                }
            }
        };

        tokio::select! {
            _ = tx.closed() => {
                debug!("dhcp probe future cancelled");
            }
            value = get_response => {
                let _ = tx.send(value);
            }
        }
    });

    send_socket
        .send_to(
            &msg.to_vec().expect("must encode dhcp discover"),
            "255.255.255.255:67",
        )
        .await?;

    tokio::select! {
        result = &mut rx => result.map_err(|_| io::Error::other("channel error")),
        _ = tokio::time::sleep(Duration::from_secs(10)) => {
            debug!("dhcp timeout after 10 secs");
            Err(io::Error::other("dhcp timeout"))
        }
    }
}

#[cfg(not(feature = "tun"))]
async fn probe_dns_server(
    _iface: &OutboundInterface,
    _fw_mark: Option<u32>,
) -> io::Result<Vec<Ipv4Addr>> {
    Err(io::Error::other("dhcp dns requires the `tun` feature"))
}

#[cfg(test)]
mod test {
    #[cfg(feature = "tun")]
    use crate::{app::net::get_outbound_interface, app::dns::dhcp::probe_dns_server};

    #[cfg(feature = "tun")]
    #[tokio::test]
    #[ignore = "requires DHCP server on CI"]
    async fn test_probe_ns() {
        let ns = probe_dns_server(
            &get_outbound_interface().expect("cant find outbound interface"),
            None,
        )
        .await
        .expect("must probe");
        assert!(!ns.is_empty());
    }
}
