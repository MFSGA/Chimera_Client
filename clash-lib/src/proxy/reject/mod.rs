use std::io;

use async_trait::async_trait;
use serde::Serialize;

use crate::{
    Session,
    app::{dispatcher::BoxedChainedStream, dns::ThreadSafeDNSResolver},
    config::internal::proxy::PROXY_REJECT,
    proxy::{DialWithConnector, OutboundHandler, OutboundType},
};

#[derive(Serialize)]
pub struct Handler {
    pub name: String,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reject").field("name", &self.name).finish()
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
        PROXY_REJECT
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Reject
    }

    async fn connect_stream(
        &self,
        #[allow(unused_variables)] sess: &Session,
        #[allow(unused_variables)] _resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        Err(io::Error::other("REJECT"))
    }
}
