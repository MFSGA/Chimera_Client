use std::sync::Arc;

use futures::future::BoxFuture;
use tokio::sync::oneshot;
use tracing::{error, info};

#[cfg(feature = "anytls")]
use crate::proxy::anytls::inbound::{
    AnytlsInbound, InboundOptions as AnytlsInboundOptions,
};
#[cfg(feature = "http_port")]
use crate::proxy::http::HttpInbound;
#[cfg(feature = "mixed_port")]
use crate::proxy::mixed::MixedInbound;
#[cfg(all(feature = "redir", target_os = "linux"))]
use crate::proxy::redir::RedirInbound;
#[cfg(feature = "shadowsocks")]
use crate::proxy::shadowsocks::inbound::{
    InboundOptions as ShadowsocksInboundOptions, ShadowsocksInbound,
};
use crate::{
    app::dispatcher::Dispatcher,
    common::auth::ThreadSafeAuthenticator,
    config::internal::listener::InboundOpts,
    proxy::{inbound::InboundHandlerTrait, socks::inbound::SocksInbound},
};

pub(crate) struct NetworkListeners {
    pub futures: Vec<BoxFuture<'static, Result<(), crate::Error>>>,
    pub ready: Vec<oneshot::Receiver<Result<(), String>>>,
}

pub(crate) fn build_network_listeners(
    inbound_opts: &InboundOpts,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
) -> Result<NetworkListeners, crate::Error> {
    let name = &inbound_opts.common_opts().name;
    let addr = inbound_opts.common_opts().listen.0;
    let port = inbound_opts.common_opts().port;

    let handler = build_handler(inbound_opts, dispatcher, authenticator)?;
    let mut runners: Vec<BoxFuture<'static, Result<(), crate::Error>>> = Vec::new();
    let mut ready = Vec::new();

    if handler.handle_tcp() {
        let tcp_listener = handler.clone();
        let (ready_tx, ready_rx) = oneshot::channel();
        ready.push(ready_rx);

        let name = name.clone();
        runners.push(Box::pin(async move {
            info!("starting {} TCP listener at {}:{}", name, addr, port);
            tcp_listener
                .listen_tcp(ready_tx)
                .await
                .inspect_err(|x| {
                    error!("handler {} tcp listen failed: {x}", name);
                })
                .map_err(Into::into)
        }));
    }

    if handler.handle_udp() {
        let udp_listener = handler.clone();
        let (ready_tx, ready_rx) = oneshot::channel();
        ready.push(ready_rx);

        let name = name.clone();
        runners.push(Box::pin(async move {
            info!("starting {} UDP listener at {}:{}", name, addr, port);
            udp_listener
                .listen_udp(ready_tx)
                .await
                .inspect_err(|x| {
                    error!("handler {} udp listen failed: {x}", name);
                })
                .map_err(Into::into)
        }));
    }

    if runners.is_empty() {
        return Err(crate::Error::Operation(format!(
            "inbound {name} has no supported listeners"
        )));
    }

    Ok(NetworkListeners {
        futures: runners,
        ready,
    })
}

fn build_handler(
    listener: &InboundOpts,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
) -> Result<Arc<dyn InboundHandlerTrait>, crate::Error> {
    let fw_mark = listener.common_opts().fw_mark;
    match listener {
        InboundOpts::Socks { common_opts, .. } => Ok(Arc::new(SocksInbound::new(
            (common_opts.listen.0, common_opts.port).into(),
            common_opts.allow_lan,
            dispatcher,
            authenticator,
            fw_mark,
        ))),

        #[cfg(feature = "http_port")]
        InboundOpts::Http { common_opts, .. } => Ok(Arc::new(HttpInbound::new(
            (common_opts.listen.0, common_opts.port).into(),
            common_opts.allow_lan,
            dispatcher,
            authenticator,
            fw_mark,
        ))),
        #[cfg(feature = "mixed_port")]
        InboundOpts::Mixed { common_opts, .. } => Ok(Arc::new(MixedInbound::new(
            (common_opts.listen.0, common_opts.port).into(),
            common_opts.allow_lan,
            dispatcher,
            authenticator,
            fw_mark,
        ))),
        #[cfg(feature = "redir")]
        InboundOpts::Redir { common_opts } => {
            #[cfg(target_os = "linux")]
            {
                Some(Arc::new(RedirInbound::new(
                    (common_opts.listen.0, common_opts.port).into(),
                    common_opts.allow_lan,
                    dispatcher,
                    common_opts.fw_mark,
                )))
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (common_opts, dispatcher);
                warn!("redir inbound is only supported on Linux");
                None
            }
        }
        #[cfg(feature = "shadowsocks")]
        InboundOpts::Shadowsocks {
            common_opts,
            udp,
            cipher,
            password,
            users,
        } => {
            let (users_tx, users_rx) = tokio::sync::watch::channel(users.clone());
            Ok(Arc::new(ShadowsocksInbound::new(
                ShadowsocksInboundOptions {
                    addr: (common_opts.listen.0, common_opts.port).into(),
                    password: password.clone(),
                    cipher: cipher.clone(),
                    udp: *udp,
                    allow_lan: common_opts.allow_lan,
                    dispatcher,
                    fw_mark: common_opts.fw_mark,
                    users_rx,
                    static_users_tx: Some(users_tx),
                },
            )))
        }
        #[cfg(feature = "anytls")]
        InboundOpts::Anytls {
            common_opts,
            password,
            certificate,
            private_key,
            fallback,
            users,
        } => {
            let (_, users_rx) = tokio::sync::watch::channel(users.clone());
            AnytlsInbound::new(AnytlsInboundOptions {
                addr: (common_opts.listen.0, common_opts.port).into(),
                password: password.clone(),
                certificate: certificate.clone(),
                private_key: private_key.clone(),
                fallback: fallback.clone(),
                allow_lan: common_opts.allow_lan,
                dispatcher,
                fw_mark: common_opts.fw_mark,
                users_rx,
            })
            .map(|handler| Arc::new(handler) as Arc<dyn InboundHandlerTrait>)
            .map_err(Into::into)
        }
    }
}
