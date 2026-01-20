use std::{fmt, sync::Arc};

use tokio::{io::AsyncWriteExt, sync::RwLock};
use tracing::{debug, info_span, instrument, trace, warn};
use tracing_log::log;

use crate::{
    app::{
        dispatcher::statistics_manager::Manager,
        dns::{ClashResolver, ThreadSafeDNSResolver},
        outbound::manager::ThreadSafeOutboundManager,
    },
    config::{
        def::RunMode,
        internal::proxy::{PROXY_DIRECT, PROXY_GLOBAL},
    },
    proxy::{AnyOutboundHandler, ClientStream},
    session::{Session, SocksAddr},
};

const DEFAULT_BUFFER_SIZE: usize = 16 * 1024;

pub struct Dispatcher {
    outbound_manager: ThreadSafeOutboundManager,
    resolver: ThreadSafeDNSResolver,
    statistics_manager: Arc<Manager>,
    tcp_buffer_size: usize,
    mode: Arc<RwLock<RunMode>>,
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
        mode: RunMode,
        statistics_manager: Arc<Manager>,
        tcp_buffer_size: Option<usize>,
    ) -> Self {
        Self {
            outbound_manager,
            resolver,
            statistics_manager,
            tcp_buffer_size: tcp_buffer_size.unwrap_or(DEFAULT_BUFFER_SIZE),
            mode: Arc::new(RwLock::new(mode)),
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
        let dest: SocksAddr = match reverse_lookup(&self.resolver, &sess.destination).await {
            Some(dest) => dest,
            None => {
                warn!("failed to resolve destination {}", sess);
                return;
            }
        };

        sess.destination = dest.clone();

        let mode = *self.mode.read().await;
        // todo: fix the following code
        let (outbound_name) = match mode {
            RunMode::Global => (PROXY_GLOBAL),
            RunMode::Rule => {
                todo!();
                // self.router.match_route(&mut sess).await,
            }
            RunMode::Direct => (PROXY_DIRECT),
        };

        debug!("dispatching {} to {}[{}]", sess, outbound_name, mode);

        let mgr = self.outbound_manager.clone();
        let handler = mgr.get_outbound(outbound_name).unwrap_or_else(|| {
            debug!("unknown rule: {}, fallback to direct", outbound_name);
            mgr.get_outbound(PROXY_DIRECT).unwrap()
        });

        log::debug!(" todo: implement dispatch logic ");
    }
}

// helper function to resolve the destination address
// if the destination is an IP address, check if it's a fake IP
// or look for cached IP
// if the destination is a domain name, don't resolve
async fn reverse_lookup(resolver: &Arc<dyn ClashResolver>, dst: &SocksAddr) -> Option<SocksAddr> {
    let dst = match dst {
        crate::session::SocksAddr::Ip(socket_addr) => {
            todo!()
        }
        crate::session::SocksAddr::Domain(host, port) => (host.to_owned(), *port)
            .try_into()
            .expect("must be valid domain"),
    };
    Some(dst)
}
