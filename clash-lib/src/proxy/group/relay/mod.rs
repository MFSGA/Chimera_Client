use std::{io, sync::Arc};

use async_trait::async_trait;
use futures::stream::{self, StreamExt};
use tracing::debug;

use crate::{
    app::dispatcher::{
        BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
        ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
    },
    app::{
        dns::ThreadSafeDNSResolver,
        remote_content_manager::providers::proxy_provider::ThreadSafeProxyProvider,
    },
    common::errors::new_io_error,
    proxy::{
        AnyOutboundHandler, ConnectorType, DialWithConnector, HandlerCommonOptions,
        OutboundHandler, OutboundType,
        group::GroupProxyAPIResponse,
        utils::{
            DirectConnector, ProxyConnector, RemoteConnector,
            provider_helper::get_proxies_from_providers,
        },
    },
    session::Session,
};

#[derive(Default)]
pub struct HandlerOptions {
    pub common_opts: HandlerCommonOptions,
    pub name: String,
}

pub struct Handler {
    opts: HandlerOptions,
    providers: Vec<ThreadSafeProxyProvider>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relay")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub fn new(
        opts: HandlerOptions,
        providers: Vec<ThreadSafeProxyProvider>,
    ) -> AnyOutboundHandler {
        Arc::new(Self { opts, providers })
    }

    async fn get_proxies(&self, touch: bool) -> Vec<AnyOutboundHandler> {
        get_proxies_from_providers(&self.providers, touch).await
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        self.opts.name.as_str()
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Relay
    }

    async fn support_udp(&self) -> bool {
        for proxy in self.get_proxies(false).await {
            match proxy.support_connector().await {
                ConnectorType::All => return true,
                ConnectorType::None | ConnectorType::Tcp => (),
            }
            if !proxy.support_udp().await {
                return false;
            }
        }
        true
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let proxies: Vec<AnyOutboundHandler> =
            stream::iter(self.get_proxies(true).await).collect().await;

        match proxies.len() {
            0 => Err(new_io_error("no proxy available")),
            1 => {
                let proxy = proxies[0].clone();
                debug!("tcp relay `{}` via proxy `{}`", self.name(), proxy.name());
                proxy.connect_stream(sess, resolver).await
            }
            _ => {
                let mut connector: Box<dyn RemoteConnector> =
                    Box::new(DirectConnector::new());
                let (proxies, last) = proxies.split_at(proxies.len() - 1);
                for proxy in proxies {
                    debug!(
                        "tcp relay `{}` via proxy `{}`",
                        self.name(),
                        proxy.name()
                    );
                    connector =
                        Box::new(ProxyConnector::new(proxy.clone(), connector));
                }

                debug!("relay `{}` via proxy `{}`", self.name(), last[0].name());
                let s = last[0]
                    .connect_stream_with_connector(
                        sess,
                        resolver,
                        connector.as_ref(),
                    )
                    .await?;

                let chained = ChainedStreamWrapper::new(s);
                chained.append_to_chain(self.name()).await;
                Ok(Box::new(chained))
            }
        }
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let proxies: Vec<AnyOutboundHandler> =
            stream::iter(self.get_proxies(true).await).collect().await;

        match proxies.len() {
            0 => Err(new_io_error("no proxy available")),
            1 => {
                let proxy = proxies[0].clone();
                debug!("udp relay `{}` via proxy `{}`", self.name(), proxy.name());
                proxy.connect_datagram(sess, resolver).await
            }
            _ => {
                let mut connector: Box<dyn RemoteConnector> =
                    Box::new(DirectConnector::new());
                let (proxies, last) = proxies.split_at(proxies.len() - 1);
                for proxy in proxies {
                    debug!(
                        "udp relay `{}` via proxy `{}`",
                        self.name(),
                        proxy.name()
                    );
                    connector =
                        Box::new(ProxyConnector::new(proxy.clone(), connector));
                }

                debug!("relay `{}` via proxy `{}`", self.name(), last[0].name());
                let d = last[0]
                    .connect_datagram_with_connector(
                        sess,
                        resolver,
                        connector.as_ref(),
                    )
                    .await?;

                let chained = ChainedDatagramWrapper::new(d);
                chained.append_to_chain(self.name()).await;
                Ok(Box::new(chained))
            }
        }
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::None
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
