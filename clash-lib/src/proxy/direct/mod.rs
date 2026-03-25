use std::fmt::Debug;

use async_trait::async_trait;
use futures::TryFutureExt;

use crate::app::dispatcher::ChainedDatagram;
use crate::{
    Session,
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagramWrapper,
            ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::errors::map_io_error,
    config::internal::proxy::PROXY_DIRECT,
    proxy::{
        DialWithConnector, OutboundHandler, OutboundType,
        datagram::OutboundDatagramImpl,
        utils::{RemoteConnector, new_tcp_stream, new_udp_socket},
    },
};

#[derive(Clone)]
pub struct Handler {
    pub name: String,
}

impl Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Direct").field("name", &self.name).finish()
    }
}

impl Handler {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
        }
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        PROXY_DIRECT
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Direct
    }

    async fn support_udp(&self) -> bool {
        true
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedStream> {
        let remote_ip = resolver
            .resolve(sess.destination.host().as_str(), false)
            .map_err(map_io_error)
            .await?
            .ok_or_else(|| std::io::Error::other("no dns result"))?;

        let s = new_tcp_stream(
            (remote_ip, sess.destination.port()).into(),
            sess.iface.as_ref(),
            #[cfg(target_os = "linux")]
            sess.so_mark,
        )
        .await?;

        let s = ChainedStreamWrapper::new(s);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedDatagram> {
        let bind_addr: std::net::IpAddr = if sess.source.is_ipv4() {
            std::net::Ipv4Addr::UNSPECIFIED.into()
        } else {
            std::net::Ipv6Addr::UNSPECIFIED.into()
        };
        let d = new_udp_socket(
            Some((bind_addr, 0).into()),
            sess.iface.as_ref(),
            #[cfg(target_os = "linux")]
            sess.so_mark,
            sess.destination
                .ip()
                .map(|ip| std::net::SocketAddr::new(ip, sess.destination.port())),
        )
        .await
        .map(|x| OutboundDatagramImpl::new(x, resolver))?;

        let d = ChainedDatagramWrapper::new(d);
        d.append_to_chain(self.name()).await;
        Ok(Box::new(d))
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> std::io::Result<BoxedChainedDatagram> {
        let d = connector
            .connect_datagram(
                resolver,
                None,
                sess.destination.clone(),
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;
        let d = ChainedDatagramWrapper::new(d);
        d.append_to_chain(self.name()).await;
        Ok(Box::new(d))
    }
}
