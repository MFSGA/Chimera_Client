pub mod helpers;

use std::io;

use async_trait::async_trait;

use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::ThreadSafeDNSResolver,
        remote_content_manager::providers::proxy_provider::ThreadSafeProxyProvider,
    },
    proxy::{
        AnyOutboundHandler, ConnectorType, DialWithConnector, HandlerCommonOptions,
        OutboundHandler, OutboundType,
        group::{GroupProxyAPIResponse, loadbalance::helpers::RoundRobin},
        utils::{RemoteConnector, provider_helper::get_proxies_from_providers},
    },
    session::Session,
};

#[derive(Default, Clone)]
pub struct HandlerOptions {
    pub common_opts: HandlerCommonOptions,
    pub name: String,
    pub udp: bool,
}

pub struct Handler {
    opts: HandlerOptions,
    providers: Vec<ThreadSafeProxyProvider>,
    strategy: RoundRobin,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadBalance")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub fn new(
        opts: HandlerOptions,
        providers: Vec<ThreadSafeProxyProvider>,
    ) -> Self {
        Self {
            opts,
            providers,
            strategy: RoundRobin::default(),
        }
    }

    async fn get_proxies(&self, touch: bool) -> Vec<AnyOutboundHandler> {
        get_proxies_from_providers(&self.providers, touch).await
    }

    async fn selected_proxy(&self, touch: bool) -> io::Result<AnyOutboundHandler> {
        let proxies = self.get_proxies(touch).await;
        self.strategy.select(&proxies)
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::LoadBalance
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
        session: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let proxy = self.selected_proxy(true).await?;
        let stream = proxy.connect_stream(session, resolver).await?;
        stream.append_to_chain(self.name()).await;
        Ok(stream)
    }

    async fn connect_datagram(
        &self,
        session: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let proxy = self.selected_proxy(true).await?;
        let datagram = proxy.connect_datagram(session, resolver).await?;
        datagram.append_to_chain(self.name()).await;
        Ok(datagram)
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::Tcp
    }

    async fn connect_stream_with_connector(
        &self,
        session: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        let stream = self
            .selected_proxy(true)
            .await?
            .connect_stream_with_connector(session, resolver, connector)
            .await?;
        stream.append_to_chain(self.name()).await;
        Ok(stream)
    }

    async fn connect_datagram_with_connector(
        &self,
        session: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedDatagram> {
        self.selected_proxy(true)
            .await?
            .connect_datagram_with_connector(session, resolver, connector)
            .await
    }

    fn try_as_group_handler(&self) -> Option<&dyn GroupProxyAPIResponse> {
        Some(self)
    }
}

#[async_trait]
impl GroupProxyAPIResponse for Handler {
    async fn get_proxies(&self) -> Vec<AnyOutboundHandler> {
        Handler::get_proxies(self, false).await
    }

    async fn get_active_proxy(&self) -> Option<AnyOutboundHandler> {
        None
    }

    fn get_latency_test_url(&self) -> Option<String> {
        self.opts.common_opts.url.clone()
    }

    fn icon(&self) -> Option<String> {
        self.opts.common_opts.icon.clone()
    }
}
