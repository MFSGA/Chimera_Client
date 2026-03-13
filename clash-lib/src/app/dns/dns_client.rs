use std::{
    fmt::{Debug, Display, Formatter},
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use hickory_proto::{
    op::Message,
    op::ResponseCode,
    rr::{
        RecordType,
        rdata::opt::{ClientSubnet, EdnsCode, EdnsOption},
    },
    runtime::{Time, iocompat::AsyncIoTokioAsStd},
    rustls::{client_config, tls_client_stream::tls_client_connect_with_future},
    tcp::{TcpClientStream, TcpStream},
    xfer::{
        DnsExchange, DnsHandle, DnsMultiplexer, DnsRequest, DnsRequestOptions,
        Protocol,
    },
};
use hickory_resolver::{
    TokioResolver,
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
    name_server::TokioConnectionProvider,
};
use tokio::sync::RwLock;
use tracing::warn;

use crate::{
    Error,
    app::dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
    app::dns::{
        ClashResolver, config::EdnsClientSubnet, helper::build_dns_response_message,
    },
    app::net::OutboundInterface,
    proxy::{
        OutboundHandler,
        datagram::UdpPacket,
        utils::{new_tcp_stream, new_udp_socket},
    },
    session::{Network, Session, SocksAddr, Type},
};

use super::{Client, ThreadSafeDNSClient, resolver::SystemResolver};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DNSNetMode {
    Udp,
    Tcp,
    DoT,
    DoH,
    Dhcp,
}

impl Display for DNSNetMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Udp => write!(f, "UDP"),
            Self::Tcp => write!(f, "TCP"),
            Self::DoT => write!(f, "DoT"),
            Self::DoH => write!(f, "DoH"),
            Self::Dhcp => write!(f, "DHCP"),
        }
    }
}

#[derive(Clone)]
pub struct Opts {
    pub father: Option<Arc<dyn ClashResolver>>,
    pub host: url::Host<String>,
    pub port: u16,
    pub net: DNSNetMode,
    pub iface: Option<String>,
    pub proxy: Arc<dyn OutboundHandler>,
    pub ecs: Option<EdnsClientSubnet>,
    pub fw_mark: Option<u32>,
    pub ipv6: bool,
}

enum DnsConfig {
    Udp(SocketAddr),
    Tcp(SocketAddr),
    Tls(SocketAddr, url::Host<String>),
    Https(SocketAddr, url::Host<String>),
    Dhcp(Option<String>),
}

impl Display for DnsConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsConfig::Udp(addr) => write!(f, "UDP: {}:{}", addr.ip(), addr.port()),
            DnsConfig::Tcp(addr) => write!(f, "TCP: {}:{}", addr.ip(), addr.port()),
            DnsConfig::Tls(addr, host) => {
                write!(f, "TLS: {}:{} host: {}", addr.ip(), addr.port(), host)
            }
            DnsConfig::Https(addr, host) => {
                write!(f, "HTTPS: {}:{} host: {}", addr.ip(), addr.port(), host)
            }
            DnsConfig::Dhcp(iface) => write!(f, "DHCP: {:?}", iface),
        }
    }
}

struct Inner {
    resolver: Option<TokioResolver>,
}

pub struct DnsClient {
    inner: Arc<RwLock<Inner>>,
    cfg: DnsConfig,
    proxy: Arc<dyn OutboundHandler>,
    host: url::Host<String>,
    port: u16,
    net: DNSNetMode,
    iface: Option<String>,
    ecs: Option<EdnsClientSubnet>,
    fw_mark: Option<u32>,
    ipv6: bool,
    bind_addr: Option<SocketAddr>,
}

impl DnsClient {
    pub async fn new_client(opts: Opts) -> anyhow::Result<ThreadSafeDNSClient> {
        if opts.net == DNSNetMode::Dhcp {
            let iface = match &opts.host {
                url::Host::Domain(iface)
                    if iface != "system" && !iface.is_empty() =>
                {
                    Some(iface.clone())
                }
                _ => opts.iface.clone(),
            };

            return Ok(Arc::new(Self {
                inner: Arc::new(RwLock::new(Inner { resolver: None })),
                cfg: DnsConfig::Dhcp(iface.clone()),
                proxy: opts.proxy,
                host: opts.host,
                port: opts.port,
                net: opts.net,
                iface,
                ecs: opts.ecs,
                fw_mark: opts.fw_mark,
                ipv6: opts.ipv6,
                bind_addr: None,
            }));
        }

        let resolved_ip = match &opts.host {
            url::Host::Ipv4(ip) => Some(IpAddr::V4(*ip)),
            url::Host::Ipv6(ip) => Some(IpAddr::V6(*ip)),
            url::Host::Domain(domain) => match &opts.father {
                Some(father) => father.resolve(domain, false).await?,
                None => tokio::net::lookup_host((domain.as_str(), opts.port))
                    .await?
                    .next()
                    .map(|addr| addr.ip()),
            },
        };
        let ip = resolved_ip.ok_or_else(|| {
            anyhow::anyhow!("no ip resolved for dns server {}", opts.host)
        })?;
        let socket_addr = SocketAddr::new(ip, opts.port);
        let bind_addr = resolve_bind_addr(opts.iface.as_deref(), socket_addr);

        let cfg = match opts.net {
            DNSNetMode::Udp => DnsConfig::Udp(socket_addr),
            DNSNetMode::Tcp => DnsConfig::Tcp(socket_addr),
            DNSNetMode::DoT => DnsConfig::Tls(socket_addr, opts.host.clone()),
            DNSNetMode::DoH => DnsConfig::Https(socket_addr, opts.host.clone()),
            DNSNetMode::Dhcp => unreachable!("dhcp handled before resolving host"),
        };

        Ok(Arc::new(Self {
            inner: Arc::new(RwLock::new(Inner { resolver: None })),
            cfg,
            proxy: opts.proxy,
            host: opts.host,
            port: opts.port,
            net: opts.net,
            iface: opts.iface,
            ecs: opts.ecs,
            fw_mark: opts.fw_mark,
            ipv6: opts.ipv6,
            bind_addr,
        }))
    }

    fn apply_edns_client_subnet(&self, message: &mut Message) {
        let Some(ecs) = &self.ecs else {
            return;
        };

        if ecs.ipv4.is_none() && ecs.ipv6.is_none() {
            return;
        }

        if message
            .extensions()
            .as_ref()
            .is_some_and(|edns| edns.option(EdnsCode::Subnet).is_some())
        {
            return;
        }

        let prefer_ipv6 = matches!(
            message.query().map(|q| q.query_type()),
            Some(RecordType::AAAA)
        );

        let candidate = if prefer_ipv6 {
            ecs.ipv6
                .map(|ipv6| (IpAddr::from(ipv6.network()), ipv6.prefix_len()))
                .or_else(|| {
                    ecs.ipv4.map(|ipv4| {
                        (IpAddr::from(ipv4.network()), ipv4.prefix_len())
                    })
                })
        } else {
            ecs.ipv4
                .map(|ipv4| (IpAddr::from(ipv4.network()), ipv4.prefix_len()))
                .or_else(|| {
                    ecs.ipv6.map(|ipv6| {
                        (IpAddr::from(ipv6.network()), ipv6.prefix_len())
                    })
                })
        };

        let Some((addr, prefix)) = candidate else {
            return;
        };

        let edns = message
            .extensions_mut()
            .get_or_insert_with(hickory_proto::op::Edns::new);

        let options = edns.options_mut();
        options.remove(EdnsCode::Subnet);
        options.insert(EdnsOption::Subnet(ClientSubnet::new(addr, prefix, prefix)));
    }

    async fn ensure_resolver(&self) -> anyhow::Result<TokioResolver> {
        if let Some(resolver) = self.inner.read().await.resolver.clone() {
            return Ok(resolver);
        }

        if self.proxy.name() != "DIRECT" {
            warn!(
                proxy = self.proxy.name(),
                dns = %self.id(),
                "dns upstream proxy dialing is not implemented yet, falling back to direct connect"
            );
        }

        if self.fw_mark.is_some() {
            warn!(
                fw_mark = self.fw_mark,
                dns = %self.id(),
                "dns upstream fw_mark is not implemented yet"
            );
        }

        if let DnsConfig::Dhcp(iface) = &self.cfg {
            if iface.is_some() {
                warn!(
                    iface = ?iface,
                    dns = %self.id(),
                    "dhcp dns interface selection is not implemented yet; using system dns configuration"
                );
            }

            let (config, mut resolver_opts) =
                hickory_resolver::system_conf::read_system_conf().map_err(|e| {
                    anyhow::anyhow!(
                        "failed to read system dns config for dhcp upstream: {e}"
                    )
                })?;
            resolver_opts.ip_strategy = if self.ipv6 {
                hickory_resolver::config::LookupIpStrategy::Ipv4AndIpv6
            } else {
                hickory_resolver::config::LookupIpStrategy::Ipv4Only
            };

            let resolver = TokioResolver::builder_with_config(
                config,
                TokioConnectionProvider::default(),
            )
            .with_options(resolver_opts)
            .build();

            self.inner.write().await.resolver = Some(resolver.clone());
            return Ok(resolver);
        }

        let mut config = ResolverConfig::new();
        let mut name_server = match &self.cfg {
            DnsConfig::Udp(addr) => NameServerConfig::new(*addr, Protocol::Udp),
            DnsConfig::Tcp(addr) => NameServerConfig::new(*addr, Protocol::Tcp),
            DnsConfig::Tls(addr, host) => {
                let mut ns = NameServerConfig::new(*addr, Protocol::Tls);
                ns.tls_dns_name = Some(host.to_string());
                ns
            }
            DnsConfig::Https(addr, host) => {
                let mut ns = NameServerConfig::new(*addr, Protocol::Https);
                ns.tls_dns_name = Some(host.to_string());
                ns.http_endpoint = Some("/dns-query".to_string());
                ns
            }
            DnsConfig::Dhcp(_) => unreachable!("dhcp handled above"),
        };
        name_server.bind_addr = self.bind_addr;
        config.add_name_server(name_server);

        let mut resolver_opts = ResolverOpts::default();
        resolver_opts.ip_strategy = if self.ipv6 {
            hickory_resolver::config::LookupIpStrategy::Ipv4AndIpv6
        } else {
            hickory_resolver::config::LookupIpStrategy::Ipv4Only
        };

        let resolver = TokioResolver::builder_with_config(
            config,
            TokioConnectionProvider::default(),
        )
        .with_options(resolver_opts)
        .build();

        self.inner.write().await.resolver = Some(resolver.clone());
        Ok(resolver)
    }

    async fn exchange_via_resolver(
        &self,
        message: &Message,
    ) -> anyhow::Result<Message> {
        let query = message
            .query()
            .ok_or_else(|| anyhow::anyhow!("invalid query message"))?;

        let lookup = self
            .ensure_resolver()
            .await?
            .lookup(query.name().clone(), query.query_type())
            .await?;

        let records: Vec<_> = lookup.record_iter().cloned().collect();
        let mut response = build_dns_response_message(message, true, false);

        if records.is_empty() {
            response.set_response_code(ResponseCode::NXDomain);
            return Ok(response);
        }

        response.set_response_code(ResponseCode::NoError);
        response.set_answer_count(records.len() as u16);
        response.add_answers(records);
        Ok(response)
    }

    async fn exchange_direct_with_mark(
        &self,
        message: &Message,
    ) -> anyhow::Result<Message> {
        match &self.cfg {
            DnsConfig::Udp(addr) => {
                self.exchange_via_direct_udp(*addr, message).await
            }
            DnsConfig::Tcp(addr) => {
                self.exchange_via_direct_tcp(*addr, message).await
            }
            DnsConfig::Tls(addr, host) => {
                self.exchange_via_direct_tls(*addr, host.to_string(), message)
                    .await
            }
            DnsConfig::Https(addr, host) => {
                self.exchange_via_direct_https(*addr, host.to_string(), message)
                    .await
            }
            DnsConfig::Dhcp(_) => self.exchange_via_resolver(message).await,
        }
    }

    async fn exchange_via_proxy(
        &self,
        message: &Message,
    ) -> anyhow::Result<Message> {
        match &self.cfg {
            DnsConfig::Udp(addr) => {
                self.exchange_via_proxy_udp(*addr, message).await
            }
            DnsConfig::Tcp(addr) => {
                self.exchange_via_proxy_tcp(*addr, message).await
            }
            DnsConfig::Tls(addr, host) => {
                self.exchange_via_proxy_tls(*addr, host.to_string(), message)
                    .await
            }
            DnsConfig::Https(addr, host) => {
                self.exchange_via_proxy_https(*addr, host.to_string(), message)
                    .await
            }
            DnsConfig::Dhcp(_) => self.exchange_via_resolver(message).await,
        }
    }

    async fn exchange_via_proxy_udp(
        &self,
        socket_addr: SocketAddr,
        message: &Message,
    ) -> anyhow::Result<Message> {
        let mut datagram = self.connect_proxy_datagram(socket_addr).await?;
        let request = UdpPacket::new(
            message.to_vec()?,
            SocksAddr::any_ipv4(),
            self.proxy_destination(socket_addr),
        );

        datagram.send(request).await?;
        let response =
            tokio::time::timeout(std::time::Duration::from_secs(5), datagram.next())
                .await
                .map_err(|_| anyhow::anyhow!("dns udp upstream timeout"))?
                .ok_or_else(|| {
                    anyhow::anyhow!("dns udp upstream returned no response")
                })?;

        Ok(Message::from_vec(&response.data)?)
    }

    async fn exchange_via_direct_udp(
        &self,
        socket_addr: SocketAddr,
        message: &Message,
    ) -> anyhow::Result<Message> {
        let socket = new_udp_socket(
            socket_addr,
            resolve_outbound_interface(self.iface.as_deref()).as_ref(),
            #[cfg(target_os = "linux")]
            self.fw_mark,
        )?;

        socket.send_to(&message.to_vec()?, socket_addr).await?;
        let mut buf = vec![0u8; 65535];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            socket.recv_from(&mut buf),
        )
        .await
        .map_err(|_| anyhow::anyhow!("dns udp upstream timeout"))??;

        buf.truncate(len);
        Ok(Message::from_vec(&buf)?)
    }

    async fn exchange_via_proxy_tcp(
        &self,
        socket_addr: SocketAddr,
        message: &Message,
    ) -> anyhow::Result<Message> {
        let future = self.connect_proxy_stream(socket_addr);
        let (stream, handle) = TcpStream::with_future(
            future,
            socket_addr,
            std::time::Duration::from_secs(5),
        );
        let stream = Box::pin(async move {
            let stream = stream.await?;
            Ok::<_, hickory_proto::ProtoError>(TcpClientStream::from_stream(stream))
        });

        self.run_multiplexed_exchange(stream, handle, message).await
    }

    async fn exchange_via_direct_tcp(
        &self,
        socket_addr: SocketAddr,
        message: &Message,
    ) -> anyhow::Result<Message> {
        let iface = resolve_outbound_interface(self.iface.as_deref());
        #[cfg(target_os = "linux")]
        let so_mark = self.fw_mark;
        let future = Box::pin(async move {
            Ok::<_, std::io::Error>(AsyncIoTokioAsStd(
                new_tcp_stream(
                    socket_addr,
                    iface.as_ref(),
                    #[cfg(target_os = "linux")]
                    so_mark,
                )
                .await?,
            ))
        });
        let (stream, handle) = TcpStream::with_future(
            future,
            socket_addr,
            std::time::Duration::from_secs(5),
        );
        let stream = Box::pin(async move {
            let stream = stream.await?;
            Ok::<_, hickory_proto::ProtoError>(TcpClientStream::from_stream(stream))
        });
        self.run_multiplexed_exchange(stream, handle, message).await
    }

    async fn exchange_via_direct_tls(
        &self,
        socket_addr: SocketAddr,
        dns_name: String,
        message: &Message,
    ) -> anyhow::Result<Message> {
        let iface = resolve_outbound_interface(self.iface.as_deref());
        #[cfg(target_os = "linux")]
        let so_mark = self.fw_mark;
        let mut tls_config = client_config();
        tls_config.enable_sni = false;
        let (stream, handle) = tls_client_connect_with_future(
            Box::pin(async move {
                let stream = new_tcp_stream(
                    socket_addr,
                    iface.as_ref(),
                    #[cfg(target_os = "linux")]
                    so_mark,
                )
                .await?;
                Ok(AsyncIoTokioAsStd(stream))
            }),
            socket_addr,
            dns_name,
            Arc::new(tls_config),
        );

        self.run_multiplexed_exchange(stream, handle, message).await
    }

    async fn exchange_via_direct_https(
        &self,
        socket_addr: SocketAddr,
        dns_name: String,
        message: &Message,
    ) -> anyhow::Result<Message> {
        let iface = resolve_outbound_interface(self.iface.as_deref());
        #[cfg(target_os = "linux")]
        let so_mark = self.fw_mark;
        let exchange: hickory_proto::xfer::DnsExchangeConnect<
            _,
            _,
            hickory_proto::runtime::TokioTime,
        > = DnsExchange::connect(hickory_proto::h2::HttpsClientConnect::new(
            Box::pin(async move {
                let stream = new_tcp_stream(
                    socket_addr,
                    iface.as_ref(),
                    #[cfg(target_os = "linux")]
                    so_mark,
                )
                .await?;
                Ok(AsyncIoTokioAsStd(stream))
            }),
            Arc::new(client_config()),
            socket_addr,
            dns_name,
            "/dns-query".to_string(),
        ));

        self.run_exchange_connect(exchange, message).await
    }

    async fn exchange_via_proxy_tls(
        &self,
        socket_addr: SocketAddr,
        dns_name: String,
        message: &Message,
    ) -> anyhow::Result<Message> {
        let mut tls_config = client_config();
        tls_config.enable_sni = false;

        let (stream, handle) = tls_client_connect_with_future(
            self.connect_proxy_stream(socket_addr),
            socket_addr,
            dns_name,
            Arc::new(tls_config),
        );

        self.run_multiplexed_exchange(stream, handle, message).await
    }

    async fn exchange_via_proxy_https(
        &self,
        socket_addr: SocketAddr,
        dns_name: String,
        message: &Message,
    ) -> anyhow::Result<Message> {
        let exchange: hickory_proto::xfer::DnsExchangeConnect<
            _,
            _,
            hickory_proto::runtime::TokioTime,
        > = DnsExchange::connect(hickory_proto::h2::HttpsClientConnect::new(
            self.connect_proxy_stream(socket_addr),
            Arc::new(client_config()),
            socket_addr,
            dns_name,
            "/dns-query".to_string(),
        ));

        self.run_exchange_connect(exchange, message).await
    }

    async fn run_multiplexed_exchange<F, S>(
        &self,
        stream: F,
        handle: hickory_proto::BufDnsStreamHandle,
        message: &Message,
    ) -> anyhow::Result<Message>
    where
        F: std::future::Future<Output = Result<S, hickory_proto::ProtoError>>
            + Send
            + Unpin
            + 'static,
        S: hickory_proto::xfer::DnsClientStream + Unpin + 'static,
    {
        let exchange: hickory_proto::xfer::DnsExchangeConnect<
            _,
            _,
            hickory_proto::runtime::TokioTime,
        > = DnsExchange::connect(DnsMultiplexer::with_timeout(
            stream,
            handle,
            std::time::Duration::from_secs(5),
            None,
        ));

        self.run_exchange_connect(exchange, message).await
    }

    async fn run_exchange_connect<F, S, TE>(
        &self,
        exchange: hickory_proto::xfer::DnsExchangeConnect<F, S, TE>,
        message: &Message,
    ) -> anyhow::Result<Message>
    where
        F: std::future::Future<Output = Result<S, hickory_proto::ProtoError>>
            + Send
            + Unpin
            + 'static,
        S: hickory_proto::xfer::DnsRequestSender,
        TE: Time + Unpin + Send + 'static,
    {
        let (exchange, background) = exchange.await?;
        tokio::spawn(background);

        let mut options = DnsRequestOptions::default();
        options.use_edns = true;
        options.recursion_desired = message.recursion_desired();

        let response = exchange
            .send(DnsRequest::new(message.clone(), options))
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("dns upstream returned no response"))??;

        Ok(response.into_message())
    }

    fn connect_proxy_stream(
        &self,
        socket_addr: SocketAddr,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = std::io::Result<AsyncIoTokioAsStd<BoxedChainedStream>>,
                > + Send
                + 'static,
        >,
    > {
        let proxy = self.proxy.clone();
        let resolver = Arc::new(
            SystemResolver::new(self.ipv6)
                .expect("failed to create system resolver for proxied dns upstream"),
        );
        let destination = self.proxy_destination(socket_addr);
        let iface = resolve_outbound_interface(self.iface.as_deref());
        let so_mark = self.fw_mark;

        Box::pin(async move {
            let session = Session {
                network: Network::Tcp,
                typ: Type::Ignore,
                destination,
                iface,
                #[cfg(target_os = "linux")]
                so_mark,
                ..Default::default()
            };

            let stream = proxy.connect_stream(&session, resolver).await?;
            Ok(AsyncIoTokioAsStd(stream))
        })
    }

    async fn connect_proxy_datagram(
        &self,
        socket_addr: SocketAddr,
    ) -> std::io::Result<BoxedChainedDatagram> {
        let resolver = Arc::new(
            SystemResolver::new(self.ipv6)
                .expect("failed to create system resolver for proxied dns upstream"),
        );
        let session = Session {
            network: Network::Udp,
            typ: Type::Ignore,
            destination: self.proxy_destination(socket_addr),
            iface: resolve_outbound_interface(self.iface.as_deref()),
            #[cfg(target_os = "linux")]
            so_mark: self.fw_mark,
            ..Default::default()
        };

        self.proxy.connect_datagram(&session, resolver).await
    }

    fn proxy_destination(&self, socket_addr: SocketAddr) -> SocksAddr {
        match &self.host {
            url::Host::Domain(domain) => {
                SocksAddr::Domain(domain.clone(), self.port)
            }
            url::Host::Ipv4(_) | url::Host::Ipv6(_) => SocksAddr::Ip(socket_addr),
        }
    }
}

fn interface_bind_addr(
    iface: &OutboundInterface,
    remote: SocketAddr,
) -> Option<SocketAddr> {
    match remote {
        SocketAddr::V4(_) => {
            iface.addr_v4.map(|ip| SocketAddr::new(IpAddr::V4(ip), 0))
        }
        SocketAddr::V6(_) => {
            iface.addr_v6.map(|ip| SocketAddr::new(IpAddr::V6(ip), 0))
        }
    }
}

#[cfg(feature = "tun")]
fn resolve_bind_addr(
    iface_name: Option<&str>,
    remote: SocketAddr,
) -> Option<SocketAddr> {
    let iface_name = iface_name?;
    let iface = crate::app::net::get_interface_by_name(iface_name);
    let bind_addr = iface
        .as_ref()
        .and_then(|iface| interface_bind_addr(iface, remote));

    if bind_addr.is_none() {
        warn!(
            iface = iface_name,
            remote = %remote,
            "dns upstream interface requested but no compatible address was found"
        );
    }

    bind_addr
}

#[cfg(not(feature = "tun"))]
fn resolve_bind_addr(
    iface_name: Option<&str>,
    _remote: SocketAddr,
) -> Option<SocketAddr> {
    if let Some(iface_name) = iface_name {
        warn!(
            iface = iface_name,
            "dns upstream interface binding requires the `tun` feature; ignoring interface"
        );
    }

    None
}

impl Debug for DnsClient {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsClient")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("net", &self.net)
            .field("iface", &self.iface)
            .field("proxy", &self.proxy.name())
            .finish()
    }
}

#[async_trait]
impl Client for DnsClient {
    fn id(&self) -> String {
        format!("{}#{}:{}", &self.net, &self.host, &self.port)
    }

    async fn exchange(&self, msg: &Message) -> anyhow::Result<Message> {
        let mut outbound = msg.clone();
        self.apply_edns_client_subnet(&mut outbound);

        if self.proxy.name() == "DIRECT" && self.fw_mark.is_some() {
            self.exchange_direct_with_mark(&outbound).await
        } else if self.proxy.name() == "DIRECT" {
            self.exchange_via_resolver(&outbound).await
        } else {
            self.exchange_via_proxy(&outbound).await
        }
    }
}

#[cfg(feature = "tun")]
fn resolve_outbound_interface(
    iface_name: Option<&str>,
) -> Option<OutboundInterface> {
    iface_name.and_then(crate::app::net::get_interface_by_name)
}

#[cfg(not(feature = "tun"))]
fn resolve_outbound_interface(
    _iface_name: Option<&str>,
) -> Option<OutboundInterface> {
    None
}
