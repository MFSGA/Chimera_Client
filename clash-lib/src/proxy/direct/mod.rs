use std::fmt::Debug;

use async_trait::async_trait;
use futures::TryFutureExt;

use crate::{
    Session,
    app::{
        dispatcher::{BoxedChainedStream, ChainedStream, ChainedStreamWrapper},
        dns::ThreadSafeDNSResolver,
    },
    common::errors::map_io_error,
    config::internal::proxy::PROXY_DIRECT,
    proxy::{DialWithConnector, OutboundHandler, OutboundType, utils::new_tcp_stream},
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
}
