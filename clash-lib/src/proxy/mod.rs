use std::{fmt::Debug, sync::Arc};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

pub mod direct;

pub mod inbound;

pub mod reject;

pub mod socks;

#[async_trait]
pub trait OutboundHandler: Sync + Send + Unpin + DialWithConnector + Debug {
    /// The name of the outbound handler
    fn name(&self) -> &str;
}

#[async_trait]
pub trait DialWithConnector {}

pub type AnyOutboundHandler = Arc<dyn OutboundHandler>;

pub trait ProxyStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T> ProxyStream for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
pub type AnyStream = Box<dyn ProxyStream>;
