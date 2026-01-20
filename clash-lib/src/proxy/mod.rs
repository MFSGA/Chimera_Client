use std::{fmt::Debug, io, sync::Arc};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    app::dispatcher::BoxedChainedStream, app::dns::ThreadSafeDNSResolver, session::Session,
};

use downcast_rs::{Downcast, impl_downcast};

pub mod direct;

pub mod inbound;

pub mod reject;

pub mod socks;

pub mod utils;

#[async_trait]
pub trait OutboundHandler: Sync + Send + Unpin + DialWithConnector + Debug {
    /// The name of the outbound handler
    fn name(&self) -> &str;

    /// connect to remote target via TCP
    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream>;
}

#[async_trait]
pub trait DialWithConnector {}

pub type AnyOutboundHandler = Arc<dyn OutboundHandler>;

pub trait ProxyStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T> ProxyStream for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
pub type AnyStream = Box<dyn ProxyStream>;

pub trait ClientStream: Downcast + AsyncRead + AsyncWrite + Send + Unpin {}
impl<T> ClientStream for T where T: Downcast + AsyncRead + AsyncWrite + Send + Unpin {}
impl_downcast!(ClientStream);
