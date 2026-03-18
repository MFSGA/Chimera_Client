use std::{
    fmt::{Debug, Display, Formatter},
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
};

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use hickory_proto::{
    op::Message,
    op::ResponseCode,
    rr::{
        Record,
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
use tracing::{info, instrument, trace, warn};

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

impl FromStr for DNSNetMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "UDP" => Ok(Self::Udp),
            "TCP" => Ok(Self::Tcp),
            "DoH" => Ok(Self::DoH),
            "DoT" => Ok(Self::DoT),
            "DHCP" => Ok(Self::Dhcp),
            _ => Err(Error::DNSError("unsupported protocol".into())),
        }
    }
}

#[derive(Clone)]
pub struct Opts {
    pub father: Option<Arc<dyn ClashResolver>>,
    pub host: url::Host<String>,
    pub port: u16,
    pub net: DNSNetMode,
    pub iface: Option<OutboundInterface>,
    pub proxy: Arc<dyn OutboundHandler>,
    pub ecs: Option<EdnsClientSubnet>,
    pub fw_mark: Option<u32>,
    pub ipv6: bool,
}

type FwMark = Option<u32>;

enum DnsConfig {
    Udp(
        SocketAddr,
        Option<OutboundInterface>,
        Arc<dyn OutboundHandler>,
        FwMark,
    ),
    Tcp(
        SocketAddr,
        Option<OutboundInterface>,
        Arc<dyn OutboundHandler>,
        FwMark,
    ),
    Tls(
        SocketAddr,
        url::Host<String>,
        Option<OutboundInterface>,
        Arc<dyn OutboundHandler>,
        FwMark,
    ),
    Https(
        SocketAddr,
        url::Host<String>,
        Option<OutboundInterface>,
        Arc<dyn OutboundHandler>,
        FwMark,
    ),
    Dhcp(Option<String>),
}

impl Display for DnsConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsConfig::Udp(addr, iface, proxy, _) => {
                write!(f, "UDP: {}:{} ", addr.ip(), addr.port())?;
                if let Some(iface) = iface {
                    write!(f, "bind: {} ", iface.name)?;
                }
                write!(f, "via proxy: {}", proxy.name())
            }
            DnsConfig::Tcp(addr, iface, proxy, _) => {
                write!(f, "TCP: {}:{} ", addr.ip(), addr.port())?;
                if let Some(iface) = iface {
                    write!(f, "bind: {} ", iface.name)?;
                }
                write!(f, "via proxy: {}", proxy.name())
            }
            DnsConfig::Tls(addr, host, iface, proxy, _) => {
                write!(f, "TLS: {}:{} ", addr.ip(), addr.port())?;
                if let Some(iface) = iface {
                    write!(f, "bind: {} ", iface.name)?;
                }
                write!(f, "host: {host}")?;
                write!(f, "via proxy: {}", proxy.name())
            }
            DnsConfig::Https(addr, host, iface, proxy, _) => {
                write!(f, "HTTPS: {}:{} ", addr.ip(), addr.port())?;
                if let Some(iface) = iface {
                    write!(f, "bind: {} ", iface.name)?;
                }
                write!(f, "host: {host}")?;
                write!(f, "via proxy: {}", proxy.name())
            }
            DnsConfig::Dhcp(iface) => write!(f, "DHCP: {:?}", iface),
        }
    }
}

impl DnsConfig {
    fn addr(&self) -> Option<SocketAddr> {
        match self {
            DnsConfig::Udp(addr, ..)
            | DnsConfig::Tcp(addr, ..)
            | DnsConfig::Tls(addr, ..)
            | DnsConfig::Https(addr, ..) => Some(*addr),
            DnsConfig::Dhcp(_) => None,
        }
    }

    fn iface(&self) -> Option<&OutboundInterface> {
        match self {
            DnsConfig::Udp(_, iface, ..)
            | DnsConfig::Tcp(_, iface, ..)
            | DnsConfig::Tls(_, _, iface, ..)
            | DnsConfig::Https(_, _, iface, ..) => iface.as_ref(),
            DnsConfig::Dhcp(_) => None,
        }
    }

    fn fw_mark(&self) -> Option<u32> {
        match self {
            DnsConfig::Udp(_, _, _, fw_mark)
            | DnsConfig::Tcp(_, _, _, fw_mark)
            | DnsConfig::Tls(_, _, _, _, fw_mark)
            | DnsConfig::Https(_, _, _, _, fw_mark) => *fw_mark,
            DnsConfig::Dhcp(_) => None,
        }
    }

    fn proxy(&self) -> Option<&Arc<dyn OutboundHandler>> {
        match self {
            DnsConfig::Udp(_, _, proxy, _)
            | DnsConfig::Tcp(_, _, proxy, _)
            | DnsConfig::Tls(_, _, _, proxy, _)
            | DnsConfig::Https(_, _, _, proxy, _) => Some(proxy),
            DnsConfig::Dhcp(_) => None,
        }
    }
}

#[derive(Default)]
struct Inner {
    resolver: Option<TokioResolver>,
}

pub struct DnsClient {
    inner: Arc<RwLock<Inner>>,

    cfg: DnsConfig,

    host: url::Host<String>,
    port: u16,
    net: DNSNetMode,
    ecs: Option<EdnsClientSubnet>,
    ipv6: bool,
}

impl DnsClient {
    fn upstream_timeout() -> std::time::Duration {
        std::time::Duration::from_secs(5)
    }

    fn doh_endpoint() -> String {
        "/dns-query".to_string()
    }

    pub async fn new_client(opts: Opts) -> anyhow::Result<ThreadSafeDNSClient> {
        if opts.net == DNSNetMode::Dhcp {
            let iface_name = match &opts.host {
                url::Host::Domain(iface)
                    if iface != "system" && !iface.is_empty() =>
                {
                    Some(iface.clone())
                }
                _ => opts.iface.as_ref().map(|iface| iface.name.clone()),
            };

            return Ok(Arc::new(Self {
                inner: Arc::new(RwLock::new(Inner::default())),
                cfg: DnsConfig::Dhcp(iface_name),
                host: opts.host,
                port: opts.port,
                net: opts.net,
                ecs: opts.ecs,
                ipv6: opts.ipv6,
            }));
        }

        let mut ip: Option<IpAddr> = None;
        let need_resolve = match &opts.host {
            url::Host::Domain(domain) => Some(domain),
            url::Host::Ipv4(addr) => {
                ip = Some(IpAddr::V4(*addr));
                None
            }
            url::Host::Ipv6(addr) => {
                ip = Some(IpAddr::V6(*addr));
                None
            }
        };

        let resolved_ip = match need_resolve {
            Some(domain) => match &opts.father {
                Some(father) => match father.resolve(domain, false).await? {
                    Some(ip) => Some(ip),
                    None => {
                        return Err(Error::InvalidConfig(format!(
                            "can't resolve default DNS: {}",
                            domain
                        ))
                        .into());
                    }
                },
                None => {
                    return Err(Error::DNSError(format!(
                        "unable to resolve DNS hostname {} without a default resolver",
                        domain
                    ))
                    .into());
                }
            },
            None => None,
        };
        let ip = ip.or(resolved_ip).ok_or_else(|| {
            anyhow::anyhow!(
                "invalid DNS host: {}, unable to parse as IP and no default resolver",
                opts.host
            )
        })?;
        let socket_addr = SocketAddr::new(ip, opts.port);

        let cfg = match opts.net {
            DNSNetMode::Udp => DnsConfig::Udp(
                socket_addr,
                opts.iface.clone(),
                opts.proxy.clone(),
                opts.fw_mark,
            ),
            DNSNetMode::Tcp => DnsConfig::Tcp(
                socket_addr,
                opts.iface.clone(),
                opts.proxy.clone(),
                opts.fw_mark,
            ),
            DNSNetMode::DoT => DnsConfig::Tls(
                socket_addr,
                opts.host.clone(),
                opts.iface.clone(),
                opts.proxy.clone(),
                opts.fw_mark,
            ),
            DNSNetMode::DoH => DnsConfig::Https(
                socket_addr,
                opts.host.clone(),
                opts.iface.clone(),
                opts.proxy.clone(),
                opts.fw_mark,
            ),
            DNSNetMode::Dhcp => unreachable!("dhcp handled before resolving host"),
        };

        Ok(Arc::new(Self {
            inner: Arc::new(RwLock::new(Inner::default())),
            cfg,
            host: opts.host,
            port: opts.port,
            net: opts.net,
            ecs: opts.ecs,
            ipv6: opts.ipv6,
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

    fn resolver_opts(&self) -> ResolverOpts {
        let mut resolver_opts = ResolverOpts::default();
        resolver_opts.ip_strategy = if self.ipv6 {
            hickory_resolver::config::LookupIpStrategy::Ipv4AndIpv6
        } else {
            hickory_resolver::config::LookupIpStrategy::Ipv4Only
        };
        resolver_opts
    }

    fn name_server_config(&self) -> anyhow::Result<Option<NameServerConfig>> {
        let Some(addr) = self.cfg.addr() else {
            return Ok(None);
        };

        let mut name_server = match &self.cfg {
            DnsConfig::Udp(..) => NameServerConfig::new(addr, Protocol::Udp),
            DnsConfig::Tcp(..) => NameServerConfig::new(addr, Protocol::Tcp),
            DnsConfig::Tls(_, host, ..) => {
                let mut ns = NameServerConfig::new(addr, Protocol::Tls);
                ns.tls_dns_name = Some(host.to_string());
                ns
            }
            DnsConfig::Https(_, host, ..) => {
                let mut ns = NameServerConfig::new(addr, Protocol::Https);
                ns.tls_dns_name = Some(host.to_string());
                ns.http_endpoint = Some(Self::doh_endpoint());
                ns
            }
            DnsConfig::Dhcp(_) => return Ok(None),
        };
        name_server.bind_addr =
            Some(addr).and_then(|addr| resolve_bind_addr(self.cfg.iface(), addr));

        Ok(Some(name_server))
    }

    async fn build_resolver(&self) -> anyhow::Result<TokioResolver> {
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
            resolver_opts.ip_strategy = self.resolver_opts().ip_strategy;

            return Ok(TokioResolver::builder_with_config(
                config,
                TokioConnectionProvider::default(),
            )
            .with_options(resolver_opts)
            .build());
        }

        let mut config = ResolverConfig::new();
        if let Some(name_server) = self.name_server_config()? {
            config.add_name_server(name_server);
        }

        Ok(TokioResolver::builder_with_config(
            config,
            TokioConnectionProvider::default(),
        )
        .with_options(self.resolver_opts())
        .build())
    }

    async fn ensure_resolver(&self) -> anyhow::Result<TokioResolver> {
        if let Some(resolver) = self.inner.read().await.resolver.clone() {
            trace!("dns client resolver is initialized, reusing existing resolver");
            return Ok(resolver);
        }

        info!("initializing dns client: {}", &self.cfg);

        if self.cfg.proxy().map(|proxy| proxy.name()) != Some("DIRECT") {
            warn!(
                proxy = self.cfg.proxy().map(|proxy| proxy.name()).unwrap_or("DIRECT"),
                dns = %self.id(),
                "dns upstream proxy dialing is not implemented yet, falling back to direct connect"
            );
        }

        if self.cfg.fw_mark().is_some() {
            warn!(
                fw_mark = self.cfg.fw_mark(),
                dns = %self.id(),
                "dns upstream fw_mark is not implemented yet"
            );
        }

        let resolver = self.build_resolver().await?;
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

        Ok(self.lookup_response(
            message,
            lookup.record_iter().cloned().collect(),
        ))
    }

    async fn exchange_via_direct(
        &self,
        message: &Message,
    ) -> anyhow::Result<Message> {
        match &self.cfg {
            DnsConfig::Udp(addr, ..) => {
                self.exchange_via_direct_udp(*addr, message).await
            }
            DnsConfig::Tcp(addr, ..) => {
                self.exchange_via_direct_tcp(*addr, message).await
            }
            DnsConfig::Tls(addr, host, ..) => {
                self.exchange_via_direct_tls(*addr, host.to_string(), message)
                    .await
            }
            DnsConfig::Https(addr, host, ..) => {
                self.exchange_via_direct_https(
                    *addr,
                    host.to_string(),
                    Self::doh_endpoint(),
                    message,
                )
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
            DnsConfig::Udp(addr, ..) => {
                self.exchange_via_proxy_udp(*addr, message).await
            }
            DnsConfig::Tcp(addr, ..) => {
                self.exchange_via_proxy_tcp(*addr, message).await
            }
            DnsConfig::Tls(addr, host, ..) => {
                self.exchange_via_proxy_tls(*addr, host.to_string(), message)
                    .await
            }
            DnsConfig::Https(addr, host, ..) => {
                self.exchange_via_proxy_https(
                    *addr,
                    host.to_string(),
                    Self::doh_endpoint(),
                    message,
                )
                .await
            }
            DnsConfig::Dhcp(_) => self.exchange_via_resolver(message).await,
        }
    }

    fn is_direct(&self) -> bool {
        self.cfg.proxy().map(|proxy| proxy.name()) == Some("DIRECT")
    }

    fn should_use_direct_exchange(&self) -> bool {
        self.is_direct() && (self.cfg.fw_mark().is_some() || self.ecs.is_some())
    }

    fn lookup_response(&self, message: &Message, records: Vec<Record>) -> Message {
        let mut response = build_dns_response_message(message, true, false);

        if records.is_empty() {
            response.set_response_code(ResponseCode::NXDomain);
            return response;
        }

        response.set_response_code(ResponseCode::NoError);
        response.set_answer_count(records.len() as u16);
        response.add_answers(records);
        response
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
        let response = tokio::time::timeout(Self::upstream_timeout(), datagram.next())
            .await
            .map_err(|_| anyhow::anyhow!("dns udp upstream timeout"))?
            .ok_or_else(|| anyhow::anyhow!("dns udp upstream returned no response"))?;

        Ok(Message::from_vec(&response.data)?)
    }

    async fn exchange_via_direct_udp(
        &self,
        socket_addr: SocketAddr,
        message: &Message,
    ) -> anyhow::Result<Message> {
        let socket = new_udp_socket(
            socket_addr,
            self.cfg.iface(),
            #[cfg(target_os = "linux")]
            self.cfg.fw_mark(),
        )?;

        socket.send_to(&message.to_vec()?, socket_addr).await?;
        let mut buf = vec![0u8; 65535];
        let (len, _) = tokio::time::timeout(
            Self::upstream_timeout(),
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
            Self::upstream_timeout(),
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
        let future = self.connect_direct_stream(socket_addr);
        let (stream, handle) = TcpStream::with_future(
            future,
            socket_addr,
            Self::upstream_timeout(),
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
        let mut tls_config = client_config();
        tls_config.enable_sni = false;
        let (stream, handle) = tls_client_connect_with_future(
            self.connect_direct_stream(socket_addr),
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
        endpoint: String,
        message: &Message,
    ) -> anyhow::Result<Message> {
        let exchange: hickory_proto::xfer::DnsExchangeConnect<
            _,
            _,
            hickory_proto::runtime::TokioTime,
        > = DnsExchange::connect(hickory_proto::h2::HttpsClientConnect::new(
            self.connect_direct_stream(socket_addr),
            Arc::new(client_config()),
            socket_addr,
            dns_name,
            endpoint,
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
        endpoint: String,
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
            endpoint,
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
            Self::upstream_timeout(),
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
        let proxy = self
            .cfg
            .proxy()
            .expect("proxy-backed dns config should carry outbound handler")
            .clone();
        let resolver = Arc::new(
            SystemResolver::new(self.ipv6)
                .expect("failed to create system resolver for proxied dns upstream"),
        );
        let destination = self.proxy_destination(socket_addr);
        let iface = self.cfg.iface().cloned();
        let so_mark = self.cfg.fw_mark();

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

    fn connect_direct_stream(
        &self,
        socket_addr: SocketAddr,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = std::io::Result<
                        AsyncIoTokioAsStd<tokio::net::TcpStream>,
                    >,
                > + Send
                + 'static,
        >,
    > {
        let iface = self.cfg.iface().cloned();
        #[cfg(target_os = "linux")]
        let so_mark = self.cfg.fw_mark();

        Box::pin(async move {
            let stream = new_tcp_stream(
                socket_addr,
                iface.as_ref(),
                #[cfg(target_os = "linux")]
                so_mark,
            )
            .await?;
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
            iface: self.cfg.iface().cloned(),
            #[cfg(target_os = "linux")]
            so_mark: self.cfg.fw_mark(),
            ..Default::default()
        };

        self.cfg
            .proxy()
            .expect("proxy-backed dns config should carry outbound handler")
            .connect_datagram(&session, resolver)
            .await
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
    iface: Option<&OutboundInterface>,
    remote: SocketAddr,
) -> Option<SocketAddr> {
    let iface = iface?;
    let bind_addr = interface_bind_addr(iface, remote);

    if bind_addr.is_none() {
        warn!(
            iface = %iface.name,
            remote = %remote,
            "dns upstream interface requested but no compatible address was found"
        );
    }

    bind_addr
}

#[cfg(not(feature = "tun"))]
fn resolve_bind_addr(
    iface: Option<&OutboundInterface>,
    _remote: SocketAddr,
) -> Option<SocketAddr> {
    if let Some(iface) = iface {
        warn!(
            iface = %iface.name,
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
            .field("iface", &self.cfg.iface())
            .field("proxy", &self.cfg.proxy().map(|proxy| proxy.name()))
            .finish()
    }
}

#[async_trait]
impl Client for DnsClient {
    fn id(&self) -> String {
        format!("{}#{}:{}", &self.net, &self.host, &self.port)
    }

    #[instrument(skip(msg), level = "trace")]
    async fn exchange(&self, msg: &Message) -> anyhow::Result<Message> {
        let mut outbound = msg.clone();
        self.apply_edns_client_subnet(&mut outbound);

        if self.should_use_direct_exchange() {
            self.exchange_via_direct(&outbound).await
        } else if self.is_direct() {
            self.exchange_via_resolver(&outbound).await
        } else {
            self.exchange_via_proxy(&outbound).await
        }
    }
}
