use std::{
    fmt::{Debug, Display},
    io,
    sync::Arc,
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::error;

use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::ThreadSafeDNSResolver,
    },
    proxy::{group::GroupProxyAPIResponse, utils::RemoteConnector},
    session::Session,
};

use downcast_rs::{Downcast, impl_downcast};

pub mod datagram;
pub mod direct;

pub mod inbound;

pub mod reject;

pub mod socks;
#[cfg(feature = "tun")]
pub mod tun;

/// 9
mod common;
#[cfg(feature = "hysteria")]
pub mod hysteria2;
/// 7
mod options;
/// 8
mod transport;
/// 6
#[cfg(feature = "trojan")]
pub mod trojan;
pub mod utils;

pub mod converters;

pub mod group;

pub use options::HandlerCommonOptions;

#[cfg(feature = "http_port")]
pub mod http;
#[cfg(feature = "mixed_port")]
pub mod mixed;
pub mod vless;

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

    async fn connect_datagram(
        &self,
        _sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        Err(io::Error::other(format!(
            "udp relay not supported for {}",
            self.proto()
        )))
    }

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

#[derive(Serialize, Deserialize)]
pub enum OutboundType {
    Direct,
    Reject,
    Selector,
    Trojan,
    Hysteria2,
    Vless,

    #[serde(rename = "URLTest")]
    UrlTest,
    Fallback,
}

impl Display for OutboundType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            /* OutboundType::Shadowsocks => write!(f, "Shadowsocks"),
            OutboundType::Vmess => write!(f, "Vmess"),

            OutboundType::WireGuard => write!(f, "WireGuard"),
            OutboundType::Tor => write!(f, "Tor"),
            OutboundType::Tuic => write!(f, "Tuic"),
            OutboundType::Socks5 => write!(f, "Socks5"),
            OutboundType::Hysteria2 => write!(f, "Hysteria2"),
            OutboundType::Ssh => write!(f, "ssh"),
            OutboundType::ShadowQuic => write!(f, "ShadowQuic"),


            OutboundType::Selector => write!(f, "Selector"),
            OutboundType::Relay => write!(f, "Relay"),
            OutboundType::LoadBalance => write!(f, "LoadBalance"),
            OutboundType::Smart => write!(f, "Smart"),
             */
            OutboundType::Vless => write!(f, "Vless"),
            OutboundType::Trojan => write!(f, "Trojan"),
            OutboundType::Hysteria2 => write!(f, "Hysteria2"),
            OutboundType::Selector => write!(f, "Selector"),
            OutboundType::Direct => write!(f, "Direct"),
            OutboundType::Reject => write!(f, "Reject"),

            OutboundType::UrlTest => write!(f, "URLTest"),
            OutboundType::Fallback => write!(f, "Fallback"),
        }
    }
}
