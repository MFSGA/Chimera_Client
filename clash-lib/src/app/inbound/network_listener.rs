use std::sync::Arc;

use tracing::{error, info, warn};

use crate::{
    Runner,
    app::dispatcher::Dispatcher,
    common::auth::ThreadSafeAuthenticator,
    config::internal::listener::InboundOpts,
    proxy::{inbound::InboundHandlerTrait, socks::inbound::SocksInbound},
};

pub(crate) fn build_network_listeners(
    inbound_opts: &InboundOpts,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
) -> Option<Vec<Runner>> {
    let name = &inbound_opts.common_opts().name;
    let addr = inbound_opts.common_opts().listen.0;
    let port = inbound_opts.common_opts().port;

    if let Some(handler) = build_handler(inbound_opts, dispatcher, authenticator) {
        let mut runners: Vec<Runner> = Vec::new();

        if handler.handle_tcp() {
            let tcp_listener = handler.clone();

            let name = name.clone();
            runners.push(Box::pin(async move {
                info!("{} TCP listening at: {}:{}", name, addr, port,);
                tcp_listener
                    .listen_tcp()
                    .await
                    .inspect_err(|x| {
                        error!("handler {} tcp listen failed: {x}", name);
                    })
                    .map_err(|e| e.into())
            }));
        }

        if handler.handle_udp() {
            let udp_listener = handler.clone();
            let name = name.clone();
            runners.push(Box::pin(async move {
                info!("{} UDP listening at: {}:{}", name, addr, port,);
                udp_listener
                    .listen_udp()
                    .await
                    .inspect_err(|x| {
                        error!("handler {} udp listen failed: {x}", name);
                    })
                    .map_err(|e| e.into())
            }));
        }

        if runners.is_empty() {
            warn!("no listener for {}", name);
            return None;
        }
        Some(runners)
    } else {
        None
    }
}

fn build_handler(
    listener: &InboundOpts,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
) -> Option<Arc<dyn InboundHandlerTrait>> {
    let fw_mark = listener.common_opts().fw_mark;
    match listener {
        InboundOpts::Socks { common_opts, .. } => Some(Arc::new(SocksInbound::new(
            (common_opts.listen.0, common_opts.port).into(),
            common_opts.allow_lan,
            dispatcher,
            authenticator,
            fw_mark,
        ))),
    }
}
