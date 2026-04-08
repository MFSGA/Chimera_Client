use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tokio::{sync::RwLock, task::JoinHandle};

use crate::{
    app::{
        dispatcher::Dispatcher, inbound::network_listener::build_network_listeners,
    },
    common::auth::ThreadSafeAuthenticator,
    config::internal::{config::BindAddress, listener::InboundOpts},
    runner::Runner,
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tracing::{debug, trace, warn};

type InboundHandlerMap = HashMap<InboundOpts, Option<JoinHandle<()>>>;
type ThreadSafeInboundHandlers = Arc<RwLock<InboundHandlerMap>>;

/// Legacy ports configuration for inbounds.
/// Newer inbounds have their own port configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Ports {
    pub port: Option<u16>,
    #[serde(rename = "socks-port")]
    pub socks_port: Option<u16>,
    #[serde(rename = "redir-port")]
    pub redir_port: Option<u16>,
    #[serde(rename = "tproxy-port")]
    pub tproxy_port: Option<u16>,
    #[serde(rename = "mixed-port")]
    pub mixed_port: Option<u16>,
}

pub struct InboundManager {
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,

    /// Inbound options for each inbound type -> listening Task
    inbound_handlers: ThreadSafeInboundHandlers,

    cancellation_token: tokio_util::sync::CancellationToken,
}

impl Runner for InboundManager {
    fn run_async(&self) {
        let inbound_handlers = self.inbound_handlers.clone();
        let dispatcher = self.dispatcher.clone();
        let authenticator = self.authenticator.clone();
        let cancellation_token = self.cancellation_token.clone();

        tokio::spawn(async move {
            Self::start_all_listeners(
                dispatcher,
                authenticator,
                inbound_handlers,
                cancellation_token,
            )
            .await;
        });
    }

    fn shutdown(&self) {
        self.cancellation_token.cancel();
    }

    fn join(&self) -> BoxFuture<'_, Result<(), crate::Error>> {
        Box::pin(async move { self.join_all_listeners().await })
    }
}

impl InboundManager {
    async fn take_all_listener_handles(
        inbound_handlers: ThreadSafeInboundHandlers,
    ) -> Vec<(String, JoinHandle<()>)> {
        inbound_handlers
            .write()
            .await
            .iter_mut()
            .filter_map(|(opt, listener)| {
                listener
                    .take()
                    .map(|handle| (opt.common_opts().name.clone(), handle))
            })
            .collect()
    }

    async fn abort_and_join_listener_handles(
        handles: Vec<(String, JoinHandle<()>)>,
    ) -> Result<(), crate::Error> {
        let mut last_join_error = None;

        for (name, handler) in handles {
            warn!("Shutting down inbound handler: {}", name);
            handler.abort();
            match handler.await {
                Ok(()) => {}
                Err(err) if err.is_cancelled() => {
                    trace!("Inbound {} listener task aborted: {}", name, err);
                }
                Err(err) => {
                    warn!("Inbound handler {} shutdown with error: {}", name, err);
                    last_join_error = Some(err);
                }
            }
        }

        last_join_error
            .map(|err| Err(std::io::Error::other(err).into()))
            .unwrap_or(Ok(()))
    }

    async fn stop_all_listener_handles(
        inbound_handlers: ThreadSafeInboundHandlers,
    ) -> Result<(), crate::Error> {
        let handles = Self::take_all_listener_handles(inbound_handlers).await;
        Self::abort_and_join_listener_handles(handles).await
    }

    pub async fn new(
        dispatcher: Arc<Dispatcher>,
        authenticator: ThreadSafeAuthenticator,
        inbounds_opt: HashSet<InboundOpts>,
        cancellation_token: Option<tokio_util::sync::CancellationToken>,
    ) -> Self {
        Self {
            inbound_handlers: Arc::new(RwLock::new(
                inbounds_opt.into_iter().map(|opts| (opts, None)).collect(),
            )),
            dispatcher,
            authenticator,
            cancellation_token: cancellation_token.unwrap_or_default(),
        }
    }

    /// Starts all inbounds listeners based on the provided options.
    /// If a listener is already running, it will be restarted.
    async fn start_all_listeners(
        dispatcher: Arc<Dispatcher>,
        authenticator: ThreadSafeAuthenticator,
        inbound_handlers: ThreadSafeInboundHandlers,
        cancellation_token: tokio_util::sync::CancellationToken,
    ) {
        if let Err(err) =
            Self::stop_all_listener_handles(inbound_handlers.clone()).await
        {
            warn!("failed to stop inbound handlers before restart: {}", err);
        }

        for (opts, handler) in inbound_handlers.write().await.iter_mut() {
            *handler = build_network_listeners(
                opts,
                dispatcher.clone(),
                authenticator.clone(),
            )
            .map(|r| {
                let listener_token = cancellation_token.clone();
                tokio::spawn(async move {
                    tokio::select! {
                        _ = listener_token.cancelled() => {
                            trace!("Inbound listener task cancelled");
                        }
                        _ = futures::future::join_all(r) => {}
                    }
                })
            });
        }
    }

    pub async fn shutdown(&self) {
        self.cancellation_token.cancel();
        if let Err(err) =
            Self::stop_all_listener_handles(self.inbound_handlers.clone()).await
        {
            warn!("failed to stop inbound handlers: {}", err);
        }
    }

    pub async fn restart(&self) -> Result<(), crate::Error> {
        self.stop_all_listeners().await;

        let inbound_handlers = self.inbound_handlers.clone();
        let dispatcher = self.dispatcher.clone();
        let authenticator = self.authenticator.clone();
        let cancellation_token = self.cancellation_token.clone();
        Self::start_all_listeners(
            dispatcher,
            authenticator,
            inbound_handlers,
            cancellation_token,
        )
        .await;
        Ok(())
    }

    // RESTFUL API handlers below
    pub async fn get_ports(&self) -> Ports {
        let mut ports = Ports::default();
        let guard = self.inbound_handlers.read().await;
        for opts in guard.keys() {
            match &opts {
                #[cfg(feature = "http_port")]
                InboundOpts::Http { common_opts } => {
                    ports.port = Some(common_opts.port)
                }
                InboundOpts::Socks { common_opts, .. } => {
                    ports.socks_port = Some(common_opts.port)
                }
                #[cfg(feature = "mixed_port")]
                InboundOpts::Mixed { common_opts, .. } => {
                    ports.mixed_port = Some(common_opts.port)
                }
            }
        }
        ports
    }

    pub async fn get_allow_lan(&self) -> bool {
        let guard = self.inbound_handlers.read().await;
        if let Some((opts, _)) = guard.iter().next() {
            opts.common_opts().allow_lan
        } else {
            false
        }
    }

    pub async fn get_bind_address(&self) -> BindAddress {
        let guard = self.inbound_handlers.read().await;
        if let Some((opts, _)) = guard.iter().next() {
            opts.common_opts().listen
        } else {
            BindAddress::default()
        }
    }

    pub async fn set_allow_lan(&self, allow_lan: bool) {
        let mut guard = self.inbound_handlers.write().await;
        let new_map = guard
            .drain()
            .map(|(mut opts, handler)| {
                opts.common_opts_mut().allow_lan = allow_lan;
                (opts, handler)
            })
            .collect::<HashMap<_, _>>();
        *guard = new_map;
    }

    pub async fn set_bind_address(&self, bind_address: BindAddress) {
        let mut guard = self.inbound_handlers.write().await;
        let new_map = guard
            .drain()
            .map(|(mut opts, handler)| {
                opts.common_opts_mut().listen = bind_address;
                (opts, handler)
            })
            .collect::<HashMap<_, _>>();
        *guard = new_map;
    }

    pub async fn change_ports(&self, ports: Ports) {
        let mut guard = self.inbound_handlers.write().await;

        let listeners: HashMap<InboundOpts, Option<_>> = guard
            .extract_if(|opts, _| match &opts {
                #[cfg(feature = "http_port")]
                InboundOpts::Http { common_opts } => {
                    ports.port.is_some() && Some(common_opts.port) == ports.port
                }
                InboundOpts::Socks { common_opts, .. } => {
                    ports.socks_port.is_some()
                        && Some(common_opts.port) == ports.socks_port
                }
                #[cfg(feature = "mixed_port")]
                InboundOpts::Mixed { common_opts, .. } => {
                    ports.mixed_port.is_some()
                        && Some(common_opts.port) == ports.mixed_port
                }
            })
            .collect();

        for (mut opts, handle) in listeners {
            opts.common_opts_mut().port = match &opts {
                #[cfg(feature = "http_port")]
                InboundOpts::Http { common_opts } => {
                    ports.port.unwrap_or(common_opts.port)
                }
                InboundOpts::Socks { common_opts, .. } => {
                    ports.socks_port.unwrap_or(common_opts.port)
                }
                #[cfg(feature = "mixed_port")]
                InboundOpts::Mixed { common_opts, .. } => {
                    ports.mixed_port.unwrap_or(common_opts.port)
                }
            };
            guard.insert(opts, handle);
        }
    }

    pub async fn get_listeners(&self) -> Vec<InboundEndpoint> {
        let guard = self.inbound_handlers.read().await;
        guard
            .iter()
            .map(|(opts, handler)| {
                let common = opts.common_opts();
                let active = handler.as_ref().is_some_and(|h| !h.is_finished());
                InboundEndpoint {
                    name: common.name.clone(),
                    inbound_type: opts.type_name().to_string(),
                    port: common.port,
                    active,
                }
            })
            .collect()
    }

    async fn stop_all_listeners(&self) {
        if let Err(err) =
            Self::stop_all_listener_handles(self.inbound_handlers.clone()).await
        {
            warn!("failed to stop inbound handlers: {}", err);
        }
        debug!("todo for provider");
        /* for handles in self.provider_handles.write().await.values_mut() {
            for (opt, handle) in handles.iter_mut() {
                if let Some(h) = handle.take() {
                    warn!(
                        "Shutting down provider inbound handler: {}",
                        opt.common_opts().name
                    );
                    h.abort();
                }
            }
        } */
    }

    #[allow(dead_code)]
    async fn join_all_listeners(&self) -> Result<(), crate::Error> {
        let handles =
            Self::take_all_listener_handles(self.inbound_handlers.clone()).await;
        Self::abort_and_join_listener_handles(handles).await?;
        debug!("todo join_all_listeners for provider");
        /* for handles in self.provider_handles.write().await.values_mut() {
            for (opt, handle) in handles.iter_mut() {
                if let Some(h) = handle.take() {
                    warn!(
                        "Shutting down provider inbound handler: {}",
                        opt.common_opts().name
                    );
                    h.await.unwrap_or_else(|e| {
                        warn!(
                            "Provider inbound handler {} shutdown with error: {}",
                            opt.common_opts().name,
                            e
                        );
                        last_join_error = Some(e);
                    });
                }
            }
        } */
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundEndpoint {
    pub name: String,
    #[serde(rename = "type")]
    pub inbound_type: String,
    pub port: u16,
    pub active: bool,
}
