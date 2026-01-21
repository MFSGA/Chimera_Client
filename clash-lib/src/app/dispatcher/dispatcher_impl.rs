use std::{fmt, sync::Arc, time::Duration};

use tokio::{io::AsyncWriteExt, sync::RwLock};
use tracing::{Instrument, debug, info_span, instrument, trace, warn};
use tracing_log::log;

use crate::{
    app::{
        dispatcher::{TrackedStream, statistics_manager::StatisticsManager},
        dns::{ClashResolver, ThreadSafeDNSResolver},
        outbound::manager::ThreadSafeOutboundManager,
    },
    common::io::copy_bidirectional,
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
    manager: Arc<StatisticsManager>,
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
        statistics_manager: Arc<StatisticsManager>,
        tcp_buffer_size: Option<usize>,
    ) -> Self {
        Self {
            outbound_manager,
            resolver,
            manager: statistics_manager,
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

    pub fn statistics_manager(&self) -> Arc<StatisticsManager> {
        self.manager.clone()
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
        let (outbound_name, rule) = match mode {
            RunMode::Global => (PROXY_GLOBAL, None),
            RunMode::Rule => {
                todo!();
                // self.router.match_route(&mut sess).await,
            }
            RunMode::Direct => (PROXY_DIRECT, None),
        };

        debug!("dispatching {} to {}[{}]", sess, outbound_name, mode);

        let mgr = self.outbound_manager.clone();
        let handler = mgr.get_outbound(outbound_name).unwrap_or_else(|| {
            debug!("unknown rule: {}, fallback to direct", outbound_name);
            mgr.get_outbound(PROXY_DIRECT).unwrap()
        });

        match handler
            .connect_stream(&sess, self.resolver.clone())
            .instrument(info_span!("connect_stream", outbound_name = outbound_name,))
            .await
        {
            Ok(rhs) => {
                debug!("remote connection established {}", sess);
                let rhs = TrackedStream::new(rhs, self.manager.clone(), sess.clone(), rule).await;
                log::debug!("todo use custom error");
                match copy_bidirectional(
                    lhs,
                    rhs,
                    self.tcp_buffer_size,
                    Duration::from_secs(10),
                    Duration::from_secs(10),
                )
                .instrument(info_span!(
                    "copy_bidirectional",
                    outbound_name = outbound_name,
                ))
                .await
                {
                    Ok((up, down)) => {
                        debug!(
                            "connection {} closed with {} bytes up, {} bytes down",
                            sess, up, down
                        );
                    }
                    Err(err) => match err {
                        crate::common::io::CopyBidirectionalError::LeftClosed(err) => match err
                            .kind()
                        {
                            std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::BrokenPipe => {
                                debug!("connection {} closed with error {} by local", sess, err);
                            }
                            _ => {
                                warn!("connection {} closed with error {} by local", sess, err);
                            }
                        },
                        crate::common::io::CopyBidirectionalError::RightClosed(err) => match err
                            .kind()
                        {
                            std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::BrokenPipe => {
                                debug!("connection {} closed with error {} by remote", sess, err);
                            }
                            _ => {
                                warn!("connection {} closed with error {} by remote", sess, err);
                            }
                        },
                        crate::common::io::CopyBidirectionalError::Other(err) => match err.kind() {
                            std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::BrokenPipe => {
                                debug!("connection {} closed with error {}", sess, err);
                            }
                            _ => {
                                warn!("connection {} closed with error {}", sess, err);
                            }
                        },
                    },
                }
            }
            Err(err) => {
                warn!(
                    "failed to establish remote connection {}, error: {}",
                    sess, err
                );
                if let Err(e) = lhs.shutdown().await {
                    warn!("error closing local connection {}: {}", sess, e)
                }
            }
        }
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
