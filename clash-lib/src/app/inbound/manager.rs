use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tokio::{sync::RwLock, task::JoinHandle};

use crate::{
    app::{
        dispatcher::Dispatcher,
        dns::ThreadSafeDNSResolver,
        inbound::network_listener::build_network_listeners,
        remote_content_manager::providers::{
            ThreadSafeProviderVehicle, file_vehicle, http_vehicle,
            inbound_provider::InboundSetProvider,
        },
    },
    common::auth::ThreadSafeAuthenticator,
    config::internal::{
        config::BindAddress,
        listener::{
            InboundFileProvider, InboundHttpProvider, InboundOpts,
            InboundProviderDef,
        },
    },
    runner::Runner,
};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tracing::{trace, warn};

type InboundHandlerMap = HashMap<InboundOpts, Option<JoinHandle<()>>>;
type ThreadSafeInboundHandlers = Arc<RwLock<InboundHandlerMap>>;
type ProviderInboundHandlers = Arc<RwLock<HashMap<String, InboundHandlerMap>>>;

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
    provider_handlers: ProviderInboundHandlers,
    inbound_providers: Arc<RwLock<HashMap<String, Arc<InboundSetProvider>>>>,

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

    async fn take_all_provider_listener_handles(
        provider_handlers: ProviderInboundHandlers,
    ) -> Vec<(String, JoinHandle<()>)> {
        let mut handles = Vec::new();
        for listeners in provider_handlers.write().await.values_mut() {
            for (opts, listener) in listeners.iter_mut() {
                if let Some(handle) = listener.take() {
                    handles.push((opts.common_opts().name.clone(), handle));
                }
            }
        }
        handles
    }

    fn spawn_listener(
        opts: &InboundOpts,
        dispatcher: Arc<Dispatcher>,
        authenticator: ThreadSafeAuthenticator,
        cancellation_token: tokio_util::sync::CancellationToken,
    ) -> Option<JoinHandle<()>> {
        build_network_listeners(opts, dispatcher, authenticator).map(|runners| {
            tokio::spawn(async move {
                tokio::select! {
                    _ = cancellation_token.cancelled() => {
                        trace!("Inbound listener task cancelled");
                    }
                    _ = futures::future::join_all(runners) => {}
                }
            })
        })
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

    async fn stop_all_provider_listener_handles(
        provider_handlers: ProviderInboundHandlers,
    ) -> Result<(), crate::Error> {
        let handles =
            Self::take_all_provider_listener_handles(provider_handlers).await;
        Self::abort_and_join_listener_handles(handles).await
    }

    async fn replace_provider_listeners(
        provider_name: String,
        new_opts: Vec<InboundOpts>,
        provider_handlers: ProviderInboundHandlers,
        dispatcher: Arc<Dispatcher>,
        authenticator: ThreadSafeAuthenticator,
        cancellation_token: tokio_util::sync::CancellationToken,
    ) {
        let old_handles = provider_handlers
            .write()
            .await
            .remove(&provider_name)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(opts, listener)| {
                listener.map(|handle| (opts.common_opts().name.clone(), handle))
            })
            .collect();
        if let Err(error) = Self::abort_and_join_listener_handles(old_handles).await
        {
            warn!(provider = %provider_name, "failed to stop provider listeners: {error}");
        }

        let mut listeners = HashMap::new();
        for opts in new_opts {
            let handle = Self::spawn_listener(
                &opts,
                dispatcher.clone(),
                authenticator.clone(),
                cancellation_token.clone(),
            );
            listeners.insert(opts, handle);
        }
        provider_handlers
            .write()
            .await
            .insert(provider_name, listeners);
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
            provider_handlers: Arc::new(RwLock::new(HashMap::new())),
            inbound_providers: Arc::new(RwLock::new(HashMap::new())),
            dispatcher,
            authenticator,
            cancellation_token: cancellation_token.unwrap_or_default(),
        }
    }

    pub async fn load_inbound_providers(
        &self,
        cwd: String,
        providers: HashMap<String, InboundProviderDef>,
        dns_resolver: ThreadSafeDNSResolver,
    ) -> Result<(), crate::Error> {
        for (name, provider) in providers {
            let (vehicle, interval): (ThreadSafeProviderVehicle, Duration) =
                match provider {
                    InboundProviderDef::Http(InboundHttpProvider {
                        url,
                        path,
                        interval,
                        ..
                    }) => {
                        let url = url.parse::<hyper::Uri>().map_err(|error| {
                            crate::Error::InvalidConfig(format!(
                                "invalid URL for inbound provider `{name}`: {error}"
                            ))
                        })?;
                        (
                            Arc::new(http_vehicle::Vehicle::new(
                                url,
                                path,
                                Some(cwd.clone()),
                                dns_resolver.clone(),
                            )),
                            Duration::from_secs(interval),
                        )
                    }
                    InboundProviderDef::File(InboundFileProvider {
                        path,
                        interval,
                        ..
                    }) => {
                        let path = PathBuf::from(path);
                        let path = if path.is_absolute() {
                            path
                        } else {
                            PathBuf::from(&cwd).join(path)
                        };
                        let path = path.to_string_lossy().into_owned();
                        (
                            Arc::new(file_vehicle::Vehicle::new(&path)),
                            Duration::from_secs(interval.unwrap_or_default()),
                        )
                    }
                };

            let provider_handlers = self.provider_handlers.clone();
            let dispatcher = self.dispatcher.clone();
            let authenticator = self.authenticator.clone();
            let cancellation_token = self.cancellation_token.clone();
            let provider_name = name.clone();
            let on_update = move |new_opts| {
                let provider_handlers = provider_handlers.clone();
                let dispatcher = dispatcher.clone();
                let authenticator = authenticator.clone();
                let cancellation_token = cancellation_token.clone();
                let provider_name = provider_name.clone();
                Box::pin(async move {
                    Self::replace_provider_listeners(
                        provider_name,
                        new_opts,
                        provider_handlers,
                        dispatcher,
                        authenticator,
                        cancellation_token,
                    )
                    .await;
                }) as BoxFuture<'static, ()>
            };

            let provider =
                InboundSetProvider::new(name.clone(), interval, vehicle, on_update)
                    .map_err(|error| {
                        crate::Error::InvalidConfig(format!(
                            "failed to create inbound provider `{name}`: {error}"
                        ))
                    })?;
            provider.initialize().await.map_err(|error| {
                crate::Error::InvalidConfig(format!(
                    "failed to initialize inbound provider `{name}`: {error}"
                ))
            })?;
            self.inbound_providers
                .write()
                .await
                .insert(name, Arc::new(provider));
        }
        Ok(())
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
            *handler = Self::spawn_listener(
                opts,
                dispatcher.clone(),
                authenticator.clone(),
                cancellation_token.clone(),
            );
        }
    }

    pub async fn shutdown(&self) {
        self.cancellation_token.cancel();
        if let Err(err) =
            Self::stop_all_listener_handles(self.inbound_handlers.clone()).await
        {
            warn!("failed to stop inbound handlers: {}", err);
        }
        if let Err(err) =
            Self::stop_all_provider_listener_handles(self.provider_handlers.clone())
                .await
        {
            warn!("failed to stop provider inbound handlers: {}", err);
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
                #[cfg(feature = "redir")]
                InboundOpts::Redir { common_opts } => {
                    ports.redir_port = Some(common_opts.port)
                }
                #[cfg(feature = "tproxy")]
                InboundOpts::Tproxy { common_opts } => {
                    ports.tproxy_port = Some(common_opts.port)
                }
                #[cfg(feature = "shadowsocks")]
                InboundOpts::Shadowsocks { .. } => {}
                #[cfg(feature = "anytls")]
                InboundOpts::Anytls { .. } => {}
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

    pub async fn change_ports(&self, ports: Ports) -> bool {
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
                #[cfg(feature = "redir")]
                InboundOpts::Redir { common_opts } => {
                    ports.redir_port.is_some()
                        && Some(common_opts.port) == ports.redir_port
                }
                #[cfg(feature = "tproxy")]
                InboundOpts::Tproxy { common_opts } => {
                    ports.tproxy_port.is_some()
                        && Some(common_opts.port) == ports.tproxy_port
                }
                #[cfg(feature = "shadowsocks")]
                InboundOpts::Shadowsocks { .. } => false,
                #[cfg(feature = "anytls")]
                InboundOpts::Anytls { .. } => false,
            })
            .collect();

        let changed = !listeners.is_empty();

        for (mut opts, handle) in listeners {
            let new_port = match &opts {
                #[cfg(feature = "http_port")]
                InboundOpts::Http { .. } => ports.port,
                InboundOpts::Socks { .. } => ports.socks_port,
                #[cfg(feature = "mixed_port")]
                InboundOpts::Mixed { .. } => ports.mixed_port,
                #[cfg(feature = "redir")]
                InboundOpts::Redir { .. } => ports.redir_port,
                #[cfg(feature = "tproxy")]
                InboundOpts::Tproxy { .. } => ports.tproxy_port,
                #[cfg(feature = "shadowsocks")]
                InboundOpts::Shadowsocks { .. } => None,
                #[cfg(feature = "anytls")]
                InboundOpts::Anytls { .. } => None,
            };
            let Some(port) = new_port else {
                warn!(
                    "Port for listener '{}' is not changed",
                    opts.common_opts().name
                );
                continue;
            };
            opts.common_opts_mut().port = port;
            guard.insert(opts, handle);
        }

        changed
    }

    pub async fn get_listeners(&self) -> Vec<InboundEndpoint> {
        let mut listeners = self
            .inbound_handlers
            .read()
            .await
            .iter()
            .map(|(opts, handler)| Self::listener_endpoint(opts, handler))
            .collect::<Vec<_>>();
        for provider in self.provider_handlers.read().await.values() {
            listeners.extend(
                provider
                    .iter()
                    .map(|(opts, handler)| Self::listener_endpoint(opts, handler)),
            );
        }
        listeners
    }

    fn listener_endpoint(
        opts: &InboundOpts,
        handler: &Option<JoinHandle<()>>,
    ) -> InboundEndpoint {
        let common = opts.common_opts();
        InboundEndpoint {
            name: common.name.clone(),
            inbound_type: opts.type_name().to_string(),
            port: common.port,
            active: handler.as_ref().is_some_and(|handle| !handle.is_finished()),
        }
    }

    async fn stop_all_listeners(&self) {
        if let Err(err) =
            Self::stop_all_listener_handles(self.inbound_handlers.clone()).await
        {
            warn!("failed to stop inbound handlers: {}", err);
        }
    }

    #[allow(dead_code)]
    async fn join_all_listeners(&self) -> Result<(), crate::Error> {
        let handles =
            Self::take_all_listener_handles(self.inbound_handlers.clone()).await;
        Self::abort_and_join_listener_handles(handles).await?;
        let provider_handles =
            Self::take_all_provider_listener_handles(self.provider_handlers.clone())
                .await;
        Self::abort_and_join_listener_handles(provider_handles).await
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
