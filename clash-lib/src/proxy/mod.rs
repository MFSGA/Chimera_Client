use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    io,
    sync::Arc,
};

use async_trait::async_trait;
use erased_serde::Serialize as ErasedSerialize;
use futures::{Sink, Stream};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::error;

use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::ThreadSafeDNSResolver,
    },
    proxy::datagram::UdpPacket,
    session::Session,
};

use downcast_rs::{Downcast, impl_downcast};

pub mod direct;
pub mod reject;

#[cfg(feature = "anytls")]
pub mod anytls;
pub mod converters;
pub mod datagram;
pub mod group;
#[cfg(feature = "http_port")]
pub mod http;
#[cfg(feature = "hysteria")]
pub mod hysteria2;
pub mod inbound;
#[cfg(feature = "mixed_port")]
pub mod mixed;
#[cfg(feature = "shadowsocks")]
pub mod shadowsocks;
pub mod socks;
#[cfg(feature = "trojan")]
pub mod trojan;
#[cfg(feature = "tun")]
pub mod tun;
pub mod utils;
pub mod vless;

mod common;
mod options;
mod transport;

use self::{group::GroupProxyAPIResponse, utils::RemoteConnector};

#[allow(unused_imports)]
pub use group::{fallback, relay, selector, urltest};
pub use options::HandlerCommonOptions;

#[cfg(feature = "http_port")]
#[derive(thiserror::Error, Debug)]
pub enum ProxyError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("proxy error: {0}")]
    General(String),
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    #[allow(dead_code)]
    #[error("socks5 error: {0}")]
    Socks5(String),
}

#[async_trait]
pub trait OutboundHandler: Sync + Send + Unpin + DialWithConnector + Debug {
    /// The name of the outbound handler
    fn name(&self) -> &str;

    /// The server name of the outbound handler, used for
    /// proxy-server-nameserver resolution.
    fn server_name(&self) -> Option<&str> {
        None
    }

    /// The protocol of the outbound handler
    /// only contains Type information, do not rely on the underlying value
    fn proto(&self) -> OutboundType;

    /// whether the outbound handler supports UDP
    async fn support_udp(&self) -> bool {
        false
    }

    /// connect to remote target via TCP
    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream>;

    async fn connect_stream_with_connector(
        &self,
        _sess: &Session,
        _resolver: ThreadSafeDNSResolver,
        _connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        error!("tcp relay not supported for {}", self.proto());
        Err(io::Error::other(format!(
            "tcp relay not supported for {}",
            self.proto()
        )))
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram>;

    /// relay related
    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::None
    }

    async fn connect_datagram_with_connector(
        &self,
        _sess: &Session,
        _resolver: ThreadSafeDNSResolver,
        _connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedDatagram> {
        Err(io::Error::other(format!(
            "udp relay not supported for {}",
            self.proto()
        )))
    }

    fn try_as_group_handler(&self) -> Option<&dyn GroupProxyAPIResponse> {
        None
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> {
        None
    }
}

#[async_trait]
pub trait DialWithConnector {
    fn support_dialer(&self) -> Option<&str> {
        None
    }

    /// register a dialer for the outbound handler
    /// this must be called before the outbound handler is used
    async fn register_connector(&self, _: Arc<dyn RemoteConnector>) {}
}

pub type AnyOutboundHandler = Arc<dyn OutboundHandler>;

pub enum ConnectorType {
    Tcp,
    All,
    None,
}

pub trait ProxyStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T> ProxyStream for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
pub type AnyStream = Box<dyn ProxyStream>;

pub trait ClientStream: Downcast + AsyncRead + AsyncWrite + Send + Unpin {}
impl<T> ClientStream for T where T: Downcast + AsyncRead + AsyncWrite + Send + Unpin {}
impl_downcast!(ClientStream);

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub enum OutboundType {
    Shadowsocks,
    Vmess,
    Vless,
    Trojan,
    Anytls,
    WireGuard,
    Tor,
    Tuic,
    Socks5,
    Hysteria2,
    Ssh,
    Tailscale,
    ShadowQuic,

    #[serde(rename = "URLTest")]
    UrlTest,
    Selector,
    Relay,
    LoadBalance,
    Smart,
    Fallback,

    Direct,
    Reject,
}

impl Display for OutboundType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutboundType::Shadowsocks => write!(f, "Shadowsocks"),
            OutboundType::Vmess => write!(f, "Vmess"),
            OutboundType::Vless => write!(f, "Vless"),
            OutboundType::Trojan => write!(f, "Trojan"),
            OutboundType::Anytls => write!(f, "AnyTLS"),
            OutboundType::WireGuard => write!(f, "WireGuard"),
            OutboundType::Tor => write!(f, "Tor"),
            OutboundType::Tuic => write!(f, "Tuic"),
            OutboundType::Hysteria2 => write!(f, "Hysteria2"),
            OutboundType::Ssh => write!(f, "ssh"),
            OutboundType::Tailscale => write!(f, "Tailscale"),
            OutboundType::ShadowQuic => write!(f, "ShadowQuic"),
            OutboundType::Socks5 => write!(f, "Socks5"),

            OutboundType::UrlTest => write!(f, "URLTest"),
            OutboundType::Selector => write!(f, "Selector"),
            OutboundType::Relay => write!(f, "Relay"),
            OutboundType::LoadBalance => write!(f, "LoadBalance"),
            OutboundType::Smart => write!(f, "Smart"),
            OutboundType::Fallback => write!(f, "Fallback"),

            OutboundType::Direct => write!(f, "Direct"),
            OutboundType::Reject => write!(f, "Reject"),
        }
    }
}

pub trait InboundDatagram<Item>:
    Stream<Item = Item> + Sink<Item, Error = io::Error> + Send + Sync + Unpin + Debug
{
}

impl<T, U> InboundDatagram<U> for T where
    T: Stream<Item = U> + Sink<U, Error = io::Error> + Send + Sync + Unpin + Debug
{
}

pub type AnyInboundDatagram =
    Box<dyn InboundDatagram<UdpPacket, Error = io::Error, Item = UdpPacket>>;

pub trait OutboundDatagram<Item>:
    Stream<Item = Item> + Sink<Item, Error = io::Error> + Send + Sync + Unpin + 'static
{
}

impl<T, U> OutboundDatagram<U> for T where
    T: Stream<Item = U> + Sink<U, Error = io::Error> + Send + Sync + Unpin + 'static
{
}

pub type AnyOutboundDatagram =
    Box<dyn OutboundDatagram<UdpPacket, Item = UdpPacket, Error = io::Error>>;

/// Plain outbound implements this trait to serialize itself for rest API
/// response.
#[async_trait]
pub trait PlainProxyAPIResponse: OutboundHandler {
    /// used in the API responses.
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>>;
}
