use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
};

use async_trait::async_trait;
use tracing::warn;

use crate::{
    Error,
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::ThreadSafeDNSResolver,
        remote_content_manager::providers::proxy_provider::ThreadSafeProxyProvider,
    },
    proxy::{
        AnyOutboundHandler, ConnectorType, DialWithConnector, HandlerCommonOptions,
        OutboundHandler, OutboundType,
        group::GroupProxyAPIResponse,
        utils::RemoteConnector,
    },
    session::Session,
};

#[async_trait]
pub trait SelectorControl {
    async fn select(&self, name: &str) -> Result<(), Error>;
    #[cfg(test)]
    async fn current(&self) -> String;
}

pub type ThreadSafeSelectorControl = Arc<dyn SelectorControl + Send + Sync>;

#[derive(Default, Clone)]
pub struct HandlerOptions {
    pub common_opts: HandlerCommonOptions,
    pub name: String,
    pub udp: bool,
}

#[derive(Clone)]
pub struct Handler {
    opts: HandlerOptions,
    providers: Vec<ThreadSafeProxyProvider>,
    current_selected_index: Arc<AtomicU16>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Selector")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub async fn new(
        opts: HandlerOptions,
        providers: Vec<ThreadSafeProxyProvider>,
        selected: Option<String>,
    ) -> Self {
        let mut proxies = get_proxies_from_providers(&providers, false).await;
        if proxies.is_empty() {
            warn!("selector `{}` initialized with empty providers", opts.name);
        }

        let selected_index = selected
            .and_then(|s| proxies.iter().position(|p| p.name() == s))
            .unwrap_or(0) as u16;

        proxies.clear();

        Self {
            opts,
            providers,
            current_selected_index: Arc::new(AtomicU16::new(selected_index)),
        }
    }

    async fn selected_proxy(&self, touch: bool) -> io::Result<AnyOutboundHandler> {
        let proxies = get_proxies_from_providers(&self.providers, touch).await;
        if proxies.is_empty() {
            return Err(io::Error::other(format!(
                "selector `{}` has no proxies",
                self.name()
            )));
        }

        let current_index = self.current_selected_index.load(Ordering::Relaxed) as usize;
        if let Some(proxy) = proxies.get(current_index) {
            return Ok(proxy.clone());
        }

        warn!(
            "selector `{}` selected index {} out of bounds, fallback to first proxy",
            self.name(),
            current_index
        );
        Ok(proxies[0].clone())
    }
}

async fn get_proxies_from_providers(
    providers: &[ThreadSafeProxyProvider],
    touch: bool,
) -> Vec<AnyOutboundHandler> {
    let mut proxies = Vec::new();
    for provider in providers {
        let provider = provider.read().await;
        if touch {
            provider.touch().await;
        }
        proxies.extend(provider.proxies().await);
    }
    proxies
}

impl DialWithConnector for Handler {}

#[async_trait]
impl SelectorControl for Handler {
    async fn select(&self, name: &str) -> Result<(), Error> {
        let proxies = get_proxies_from_providers(&self.providers, false).await;
        if let Some(index) = proxies.iter().position(|p| p.name() == name) {
            self.current_selected_index.store(index as u16, Ordering::Relaxed);
            Ok(())
        } else {
            Err(Error::Operation(format!("proxy {name} not found")))
        }
    }

    #[cfg(test)]
    async fn current(&self) -> String {
        let proxies = get_proxies_from_providers(&self.providers, false).await;
        proxies
            .get(self.current_selected_index.load(Ordering::Relaxed) as usize)
            .map(|p| p.name().to_owned())
            .unwrap_or_default()
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Selector
    }

    async fn support_udp(&self) -> bool {
        if !self.opts.udp {
            return false;
        }
        match self.selected_proxy(false).await {
            Ok(proxy) => proxy.support_udp().await,
            Err(_) => false,
        }
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let selected = self.selected_proxy(true).await?;
        let s = selected.connect_stream(sess, resolver).await?;
        s.append_to_chain(self.name()).await;
        Ok(s)
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let selected = self.selected_proxy(true).await?;
        let d = selected.connect_datagram(sess, resolver).await?;
        d.append_to_chain(self.name()).await;
        Ok(d)
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::Tcp
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        let s = self
            .selected_proxy(true)
            .await?
            .connect_stream_with_connector(sess, resolver, connector)
            .await?;
        s.append_to_chain(self.name()).await;
        Ok(s)
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedDatagram> {
        self.selected_proxy(true)
            .await?
            .connect_datagram_with_connector(sess, resolver, connector)
            .await
    }

    fn try_as_group_handler(&self) -> Option<&dyn GroupProxyAPIResponse> {
        Some(self as _)
    }
}

#[async_trait]
impl GroupProxyAPIResponse for Handler {
    async fn get_proxies(&self) -> Vec<AnyOutboundHandler> {
        get_proxies_from_providers(&self.providers, false).await
    }

    async fn get_active_proxy(&self) -> Option<AnyOutboundHandler> {
        self.selected_proxy(false).await.ok()
    }

    fn icon(&self) -> Option<String> {
        self.opts.common_opts.icon.clone()
    }
}
