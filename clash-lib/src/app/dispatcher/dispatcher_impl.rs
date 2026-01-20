use std::{fmt, sync::Arc};

use tracing::instrument;

use crate::{
    app::{
        dispatcher::statistics_manager::Manager, dns::ThreadSafeDNSResolver,
        outbound::manager::ThreadSafeOutboundManager,
    },
    proxy::{AnyOutboundHandler, ClientStream}, session::Session,
};

const DEFAULT_BUFFER_SIZE: usize = 16 * 1024;

pub struct Dispatcher {
    outbound_manager: ThreadSafeOutboundManager,
    resolver: ThreadSafeDNSResolver,
    statistics_manager: Arc<Manager>,
    tcp_buffer_size: usize,
    // todo
    // mode: RunMode,
}

impl fmt::Debug for Dispatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dispatcher").finish()
    }
}

impl Dispatcher {
    pub fn new(
        outbound_manager: ThreadSafeOutboundManager,
        resolver: ThreadSafeDNSResolver,
        statistics_manager: Arc<Manager>,
        tcp_buffer_size: Option<usize>,
    ) -> Self {
        Self {
            outbound_manager,
            resolver,
            statistics_manager,
            tcp_buffer_size: tcp_buffer_size.unwrap_or(DEFAULT_BUFFER_SIZE),
        }
    }

    pub fn get_outbound(&self, name: &str) -> Option<AnyOutboundHandler> {
        self.outbound_manager.get_outbound(name)
    }

    pub fn tcp_buffer_size(&self) -> usize {
        self.tcp_buffer_size
    }

    pub fn resolver(&self) -> ThreadSafeDNSResolver {
        self.resolver.clone()
    }

    pub fn statistics_manager(&self) -> Arc<Manager> {
        self.statistics_manager.clone()
    }

    #[instrument(skip(self, sess, lhs))]
    pub async fn dispatch_stream(&self, mut sess: Session, mut lhs: Box<dyn ClientStream>) {
        todo!()
    }
}
