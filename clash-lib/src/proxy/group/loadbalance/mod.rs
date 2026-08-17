mod helpers;

use std::{io, sync::Arc};

use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::debug;

use self::helpers::{StrategyFn, strategy_consistent_hashring, strategy_rr};
use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::ThreadSafeDNSResolver,
        remote_content_manager::providers::proxy_provider::ThreadSafeProxyProvider,
    },
    config::internal::proxy::LoadBalanceStrategy,
    proxy::{
        AnyOutboundHandler, ConnectorType, DialWithConnector, HandlerCommonOptions,
        OutboundHandler, OutboundType,
        group::GroupProxyAPIResponse,
        utils::{RemoteConnector, provider_helper::get_proxies_from_providers},
    },
    session::Session,
};

#[derive(Default, Clone)]
pub struct HandlerOptions {
    pub common_opts: HandlerCommonOptions,
    pub name: String,
    pub udp: bool,
    pub strategy: LoadBalanceStrategy,
}

struct HandlerInner {
    strategy_fn: StrategyFn,
}

pub struct Handler {
    opts: HandlerOptions,
    providers: Vec<ThreadSafeProxyProvider>,
    inner: Arc<Mutex<HandlerInner>>,
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
    ) -> io::Result<Self> {
        let strategy_fn = match opts.strategy {
            LoadBalanceStrategy::ConsistentHashing => strategy_consistent_hashring(),
            LoadBalanceStrategy::RoundRobin => strategy_rr(),
            LoadBalanceStrategy::StickySession => {
                return Err(io::Error::other(
                    "sticky-session load-balance strategy is not implemented yet",
                ));
            }
        };

        Ok(Self {
            opts,
            providers,
            inner: Arc::new(Mutex::new(HandlerInner { strategy_fn })),
        })
    }

    async fn get_proxies(&self, touch: bool) -> Vec<AnyOutboundHandler> {
        get_proxies_from_providers(&self.providers, touch).await
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
        self.opts.udp
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let proxies = self.get_proxies(false).await;
        let proxy = (self.inner.lock().await.strategy_fn)(proxies, sess).await?;
        debug!("{} use proxy {}", self.name(), proxy.name());
        let stream = proxy.connect_stream(sess, resolver).await?;
        stream.append_to_chain(self.name()).await;
        Ok(stream)
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let proxies = self.get_proxies(false).await;
        let proxy = (self.inner.lock().await.strategy_fn)(proxies, sess).await?;
        debug!("{} use proxy {}", self.name(), proxy.name());
        let datagram = proxy.connect_datagram(sess, resolver).await?;
        datagram.append_to_chain(self.name()).await;
        Ok(datagram)
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
        let proxies = self.get_proxies(false).await;
        let proxy = (self.inner.lock().await.strategy_fn)(proxies, sess).await?;
        debug!("{} use proxy {}", self.name(), proxy.name());
        proxy
            .connect_stream_with_connector(sess, resolver, connector)
            .await
    }

    fn try_as_group_handler(&self) -> Option<&dyn GroupProxyAPIResponse> {
        Some(self as _)
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
