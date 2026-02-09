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
    app::{dispatcher::BoxedChainedStream, dns::ThreadSafeDNSResolver},
    proxy::utils::RemoteConnector,
    session::Session,
};

use downcast_rs::{Downcast, impl_downcast};

pub mod direct;

pub mod inbound;

pub mod reject;

pub mod socks;
#[cfg(feature = "tun")]
pub mod tun;

/// 9
mod common;
/// 7
mod options;
/// 8
mod transport;
/// 6
#[cfg(feature = "trojan")]
pub mod trojan;
pub mod utils;

pub mod converters;

pub use options::HandlerCommonOptions;

#[async_trait]
pub trait OutboundHandler: Sync + Send + Unpin + DialWithConnector + Debug {
    /// The name of the outbound handler
    fn name(&self) -> &str;

    /// The protocol of the outbound handler
    /// only contains Type information, do not rely on the underlying value
    fn proto(&self) -> OutboundType;

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
    Trojan,
}

impl Display for OutboundType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            /* OutboundType::Shadowsocks => write!(f, "Shadowsocks"),
            OutboundType::Vmess => write!(f, "Vmess"),
            OutboundType::Vless => write!(f, "Vless"),
            OutboundType::WireGuard => write!(f, "WireGuard"),
            OutboundType::Tor => write!(f, "Tor"),
            OutboundType::Tuic => write!(f, "Tuic"),
            OutboundType::Socks5 => write!(f, "Socks5"),
            OutboundType::Hysteria2 => write!(f, "Hysteria2"),
            OutboundType::Ssh => write!(f, "ssh"),
            OutboundType::ShadowQuic => write!(f, "ShadowQuic"),

            OutboundType::UrlTest => write!(f, "URLTest"),
            OutboundType::Selector => write!(f, "Selector"),
            OutboundType::Relay => write!(f, "Relay"),
            OutboundType::LoadBalance => write!(f, "LoadBalance"),
            OutboundType::Smart => write!(f, "Smart"),
            OutboundType::Fallback => write!(f, "Fallback"), */
            OutboundType::Trojan => write!(f, "Trojan"),
            OutboundType::Direct => write!(f, "Direct"),
            OutboundType::Reject => write!(f, "Reject"),
        }
    }
}
