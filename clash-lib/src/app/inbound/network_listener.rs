use std::sync::Arc;

use tracing::{debug, warn};

use crate::{
    Runner, app::dispatcher::Dispatcher, common::auth::ThreadSafeAuthenticator,
    config::internal::listener::InboundOpts, proxy::{inbound::InboundHandlerTrait, socks::inbound::SocksInbound},
};

pub(crate) fn build_network_listeners(
    inbound_opts: &InboundOpts,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
) -> Option<Vec<Runner>> {
    let handler = build_handler(inbound_opts, dispatcher, authenticator)?;
    let name = inbound_opts.common_opts().name.clone();

    let mut runners: Vec<Runner> = Vec::new();

    if handler.handle_tcp() {
        let handler = handler.clone();
        let name = name.clone();
        runners.push(Box::pin(async move {
            if let Err(err) = handler.listen_tcp().await {
                warn!("{} inbound tcp listener stopped: {}", name, err);
                return Err(err.into());
            }
            Ok(())
        }));
    }

    if handler.handle_udp() {
        let handler = handler.clone();
        let name = name.clone();
        runners.push(Box::pin(async move {
            if let Err(err) = handler.listen_udp().await {
                warn!("{} inbound udp listener stopped: {}", name, err);
                return Err(err.into());
            }
            Ok(())
        }));
    }

    Some(runners)
}

fn build_handler(
    inbound_opts: &InboundOpts,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
) -> Option<Arc<dyn InboundHandlerTrait>> {
    #[allow(unreachable_patterns)]
    match inbound_opts {
        InboundOpts::Socks { common_opts, udp } => {
            if *udp {
                warn!(
                    "{} SOCKS UDP is not implemented in this build",
                    common_opts.name
                );
            }
            Some(Arc::new(SocksInbound::new(
                common_opts.clone(),
                dispatcher,
                authenticator,
            )))
        }
        _ => {
            debug!(
                "inbound listener {} is not implemented in this build",
                inbound_opts.common_opts().name
            );
            None
        }
    }
}
