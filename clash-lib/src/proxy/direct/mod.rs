use std::fmt::Debug;

use async_trait::async_trait;

use crate::{
    Session,
    app::{dispatcher::BoxedChainedStream, dns::ThreadSafeDNSResolver},
    config::internal::proxy::PROXY_DIRECT,
    proxy::{DialWithConnector, OutboundHandler},
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

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedStream> {
        todo!()
    }
}
