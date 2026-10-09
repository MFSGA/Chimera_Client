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
        flow::{DirectPathSelection, NetworkPathId},
        remote_content_manager::providers::proxy_provider::ThreadSafeProxyProvider,
    },
    proxy::{
        AnyOutboundHandler, ConnectorType, DialWithConnector, HandlerCommonOptions,
        OutboundHandler, OutboundType, group::GroupProxyAPIResponse,
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

/// One connection's immutable dynamic-group traversal. Changes to selectors,
/// fallback health, URL-test latency, or load-balance rotation only affect
/// subsequent captures, never a connection already being planned.
pub(crate) struct PinnedOutbound {
    pub(crate) handler: AnyOutboundHandler,
    selector_chain: Vec<String>,
}

impl PinnedOutbound {
    pub(crate) async fn capture(
        mut handler: AnyOutboundHandler,
        session: &Session,
    ) -> io::Result<Self> {
        let mut selector_chain = Vec::new();
        let mut visited = Vec::<AnyOutboundHandler>::new();
        loop {
            if !matches!(
                handler.proto(),
                OutboundType::Selector
                    | OutboundType::Fallback
                    | OutboundType::UrlTest
                    | OutboundType::LoadBalance
            ) {
                return Ok(Self {
                    handler,
                    selector_chain,
                });
            }
            if visited.len() >= 16
                || visited.iter().any(|prior| Arc::ptr_eq(prior, &handler))
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "proxy group chain is cyclic or exceeds maximum depth",
                ));
            }
            let group = handler.try_as_group_handler().ok_or_else(|| {
                io::Error::other(format!(
                    "group `{}` does not expose its selected proxy",
                    handler.name()
                ))
            })?;
            let selected = group.select_proxy_for_connection(session).await?;
            selector_chain.push(handler.name().to_owned());
            visited.push(handler);
            handler = selected;
        }
    }

    pub(crate) async fn append_stream_chain(&self, stream: &BoxedChainedStream) {
        for name in self.selector_chain.iter().rev() {
            stream.append_to_chain(name).await;
        }
    }

    pub(crate) async fn append_datagram_chain(
        &self,
        datagram: &BoxedChainedDatagram,
    ) {
        for name in self.selector_chain.iter().rev() {
            datagram.append_to_chain(name).await;
        }
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

        let current_index =
            self.current_selected_index.load(Ordering::Relaxed) as usize;
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
            self.current_selected_index
                .store(index as u16, Ordering::Relaxed);
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

    async fn connect_stream_with_path_selection_result(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        selection: &DirectPathSelection,
    ) -> io::Result<(BoxedChainedStream, Option<NetworkPathId>)> {
        let selected = self.selected_proxy(true).await?;
        let (stream, path_id) = selected
            .connect_stream_with_path_selection_result(sess, resolver, selection)
            .await?;
        stream.append_to_chain(self.name()).await;
        Ok((stream, path_id))
    }

    async fn connect_datagram_with_path_selection(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        selection: &DirectPathSelection,
    ) -> io::Result<BoxedChainedDatagram> {
        let selected = self.selected_proxy(true).await?;
        let datagram = selected
            .connect_datagram_with_path_selection(sess, resolver, selection)
            .await?;
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

    async fn select_proxy_for_connection(
        &self,
        _session: &Session,
    ) -> io::Result<AnyOutboundHandler> {
        self.selected_proxy(true).await
    }

    fn get_latency_test_url(&self) -> Option<String> {
        self.opts.common_opts.url.clone()
    }

    fn icon(&self) -> Option<String> {
        self.opts.common_opts.icon.clone()
    }
}

#[cfg(test)]
mod path_selection_tests {
    use std::{
        collections::HashMap,
        io,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
        time::Duration,
    };

    use async_trait::async_trait;
    use erased_serde::Serialize;
    use futures::{Sink, Stream};
    use tokio::sync::RwLock;

    use crate::{
        app::{
            dispatcher::{
                BoxedChainedDatagram, BoxedChainedStream, ChainedDatagramWrapper,
                ChainedStreamWrapper,
            },
            dns::ThreadSafeDNSResolver,
            flow::{
                AddressFamily, DirectPathSelection, InterfaceId, InterfaceKind,
                NetworkPath, NetworkPathId,
            },
            remote_content_manager::{
                ProxyManager,
                providers::{
                    Provider, ProviderType, ProviderVehicleType,
                    proxy_provider::{ProxyProvider, ThreadSafeProxyProvider},
                },
            },
        },
        config::internal::proxy::LoadBalanceStrategy,
        proxy::{
            AnyOutboundHandler, DialWithConnector, OutboundHandler, OutboundType,
            datagram::UdpPacket, utils::test_utils::noop::NoopResolver,
        },
        session::{Session, SocksAddr},
    };

    use super::{Handler, HandlerOptions, PinnedOutbound, SelectorControl};

    struct TestProvider(Vec<AnyOutboundHandler>);

    #[async_trait]
    impl Provider for TestProvider {
        fn name(&self) -> &str {
            "test"
        }
        fn vehicle_type(&self) -> ProviderVehicleType {
            ProviderVehicleType::Compatible
        }
        fn typ(&self) -> ProviderType {
            ProviderType::Proxy
        }
        async fn initialize(&self) -> io::Result<()> {
            Ok(())
        }
        async fn update(&self) -> io::Result<()> {
            Ok(())
        }
        async fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
            HashMap::new()
        }
    }

    #[async_trait]
    impl ProxyProvider for TestProvider {
        async fn proxies(&self) -> Vec<AnyOutboundHandler> {
            self.0.clone()
        }
        async fn touch(&self) {}
        async fn healthcheck(&self) {}
    }

    struct IdleDatagram;

    impl Stream for IdleDatagram {
        type Item = UdpPacket;
        fn poll_next(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }
    }

    impl Sink<UdpPacket> for IdleDatagram {
        type Error = io::Error;
        fn poll_ready(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn start_send(self: Pin<&mut Self>, _: UdpPacket) -> io::Result<()> {
            Ok(())
        }
        fn poll_flush(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug)]
    struct PathMock {
        name: &'static str,
        reported_path: Option<NetworkPathId>,
        tcp_path_calls: AtomicUsize,
        udp_path_calls: AtomicUsize,
    }

    fn mock_node(name: &'static str) -> Arc<PathMock> {
        Arc::new(PathMock {
            name,
            reported_path: None,
            tcp_path_calls: AtomicUsize::new(0),
            udp_path_calls: AtomicUsize::new(0),
        })
    }

    fn provider_for(nodes: Vec<AnyOutboundHandler>) -> ThreadSafeProxyProvider {
        Arc::new(RwLock::new(TestProvider(nodes)))
    }

    impl DialWithConnector for PathMock {}

    #[async_trait]
    impl OutboundHandler for PathMock {
        fn name(&self) -> &str {
            self.name
        }
        fn proto(&self) -> OutboundType {
            if self.name == "DIRECT" {
                OutboundType::Direct
            } else {
                OutboundType::Vless
            }
        }
        async fn connect_stream(
            &self,
            _: &Session,
            _: ThreadSafeDNSResolver,
        ) -> io::Result<BoxedChainedStream> {
            let (stream, _other) = tokio::io::duplex(64);
            Ok(Box::new(ChainedStreamWrapper::new(stream)))
        }
        async fn connect_datagram(
            &self,
            _: &Session,
            _: ThreadSafeDNSResolver,
        ) -> io::Result<BoxedChainedDatagram> {
            Ok(Box::new(ChainedDatagramWrapper::new(IdleDatagram)))
        }
        async fn connect_stream_with_path_selection_result(
            &self,
            _: &Session,
            _: ThreadSafeDNSResolver,
            _: &DirectPathSelection,
        ) -> io::Result<(BoxedChainedStream, Option<NetworkPathId>)> {
            self.tcp_path_calls.fetch_add(1, Ordering::SeqCst);
            let (stream, _other) = tokio::io::duplex(64);
            Ok((
                Box::new(ChainedStreamWrapper::new_with_network_path_id(
                    stream,
                    self.reported_path.clone(),
                )),
                self.reported_path.clone(),
            ))
        }
        async fn connect_datagram_with_path_selection(
            &self,
            _: &Session,
            _: ThreadSafeDNSResolver,
            _: &DirectPathSelection,
        ) -> io::Result<BoxedChainedDatagram> {
            self.udp_path_calls.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(ChainedDatagramWrapper::new_with_network_path_id(
                IdleDatagram,
                self.reported_path.clone(),
            )))
        }
    }

    #[tokio::test]
    async fn selector_forwards_tcp_and_udp_path_selection_and_preserves_observed_path()
     {
        let path_id = NetworkPathId {
            interface: InterfaceId {
                name: "en0".to_owned(),
                index: 4,
            },
            family: AddressFamily::Ipv4,
            source_address: Some("192.0.2.10".parse().unwrap()),
            network_generation: 7,
        };
        let selected_path = NetworkPath {
            id: path_id.clone(),
            interface_kind: InterfaceKind::Ethernet,
            source_address: path_id.source_address,
            scope_id: None,
            gateway: None,
        };
        let selection = DirectPathSelection {
            ipv4: Some(selected_path.clone()),
            ipv4_candidates: vec![selected_path],
            network_generation: 7,
            required: true,
            ..Default::default()
        };
        let direct = Arc::new(PathMock {
            name: "DIRECT",
            reported_path: Some(path_id.clone()),
            tcp_path_calls: AtomicUsize::new(0),
            udp_path_calls: AtomicUsize::new(0),
        });
        let proxy = Arc::new(PathMock {
            name: "PROXY",
            reported_path: None,
            tcp_path_calls: AtomicUsize::new(0),
            udp_path_calls: AtomicUsize::new(0),
        });
        let provider: ThreadSafeProxyProvider =
            Arc::new(RwLock::new(TestProvider(vec![
                direct.clone(),
                proxy.clone(),
            ])));
        let selector = Handler::new(
            HandlerOptions {
                name: "SELECT".to_owned(),
                udp: true,
                ..Default::default()
            },
            vec![provider],
            Some("DIRECT".to_owned()),
        )
        .await;
        let session = Session {
            destination: SocksAddr::Ip("198.51.100.10:443".parse().unwrap()),
            ..Default::default()
        };
        let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);

        let (stream, tcp_path) = selector
            .connect_stream_with_path_selection_result(
                &session,
                resolver.clone(),
                &selection,
            )
            .await
            .unwrap();
        assert_eq!(tcp_path, Some(path_id.clone()));
        assert_eq!(stream.network_path_ids(), vec![path_id.clone()]);
        let datagram = selector
            .connect_datagram_with_path_selection(
                &session,
                resolver.clone(),
                &selection,
            )
            .await
            .unwrap();
        assert_eq!(datagram.network_path_ids(), vec![path_id]);
        assert_eq!(direct.tcp_path_calls.load(Ordering::SeqCst), 1);
        assert_eq!(direct.udp_path_calls.load(Ordering::SeqCst), 1);

        selector.select("PROXY").await.unwrap();
        let (stream, tcp_path) = selector
            .connect_stream_with_path_selection_result(
                &session,
                resolver.clone(),
                &selection,
            )
            .await
            .unwrap();
        assert!(tcp_path.is_none());
        assert!(stream.network_path_ids().is_empty());
        let datagram = selector
            .connect_datagram_with_path_selection(&session, resolver, &selection)
            .await
            .unwrap();
        assert!(datagram.network_path_ids().is_empty());
        assert_eq!(proxy.tcp_path_calls.load(Ordering::SeqCst), 1);
        assert_eq!(proxy.udp_path_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn pinned_selector_ignores_later_switch_for_tcp_and_udp() {
        let direct = Arc::new(PathMock {
            name: "DIRECT",
            reported_path: None,
            tcp_path_calls: AtomicUsize::new(0),
            udp_path_calls: AtomicUsize::new(0),
        });
        let proxy = Arc::new(PathMock {
            name: "PROXY",
            reported_path: None,
            tcp_path_calls: AtomicUsize::new(0),
            udp_path_calls: AtomicUsize::new(0),
        });
        let provider: ThreadSafeProxyProvider =
            Arc::new(RwLock::new(TestProvider(vec![
                direct.clone(),
                proxy.clone(),
            ])));
        let selector = Arc::new(
            Handler::new(
                HandlerOptions {
                    name: "SELECT".to_owned(),
                    udp: true,
                    ..Default::default()
                },
                vec![provider],
                Some("DIRECT".to_owned()),
            )
            .await,
        );
        let selected: AnyOutboundHandler = selector.clone();
        // Both connection plans capture DIRECT before an unrelated task
        // changes the selector. The actual dial must not re-read the selector.
        let pinned_tcp =
            PinnedOutbound::capture(selected.clone(), &Session::default())
                .await
                .unwrap();
        let pinned_udp =
            PinnedOutbound::capture(selected.clone(), &Session::default())
                .await
                .unwrap();
        assert_eq!(pinned_tcp.handler.name(), "DIRECT");
        assert_eq!(pinned_udp.handler.name(), "DIRECT");
        selector.select("PROXY").await.unwrap();

        let session = Session {
            destination: SocksAddr::Ip("198.51.100.10:443".parse().unwrap()),
            ..Default::default()
        };
        let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
        let selection = DirectPathSelection::default();
        let (stream, _) = pinned_tcp
            .handler
            .connect_stream_with_path_selection_result(
                &session,
                resolver.clone(),
                &selection,
            )
            .await
            .unwrap();
        pinned_tcp.append_stream_chain(&stream).await;
        assert_eq!(stream.chain().snapshot().await, ["SELECT"]);
        let datagram = pinned_udp
            .handler
            .connect_datagram_with_path_selection(
                &session,
                resolver.clone(),
                &selection,
            )
            .await
            .unwrap();
        pinned_udp.append_datagram_chain(&datagram).await;
        assert_eq!(datagram.chain().snapshot().await, ["SELECT"]);
        assert_eq!(direct.tcp_path_calls.load(Ordering::SeqCst), 1);
        assert_eq!(direct.udp_path_calls.load(Ordering::SeqCst), 1);
        assert_eq!(proxy.tcp_path_calls.load(Ordering::SeqCst), 0);
        assert_eq!(proxy.udp_path_calls.load(Ordering::SeqCst), 0);

        let next = PinnedOutbound::capture(selected, &Session::default())
            .await
            .unwrap();
        assert_eq!(next.handler.name(), "PROXY");
        let (stream, _) = next
            .handler
            .connect_stream_with_path_selection_result(
                &session, resolver, &selection,
            )
            .await
            .unwrap();
        next.append_stream_chain(&stream).await;
        assert_eq!(stream.chain().snapshot().await, ["SELECT"]);
        assert_eq!(proxy.tcp_path_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn nested_selectors_pin_leaf_and_preserve_chain_order() {
        let direct: AnyOutboundHandler = Arc::new(PathMock {
            name: "DIRECT",
            reported_path: None,
            tcp_path_calls: AtomicUsize::new(0),
            udp_path_calls: AtomicUsize::new(0),
        });
        let proxy: AnyOutboundHandler = Arc::new(PathMock {
            name: "PROXY",
            reported_path: None,
            tcp_path_calls: AtomicUsize::new(0),
            udp_path_calls: AtomicUsize::new(0),
        });
        let inner = Arc::new(
            Handler::new(
                HandlerOptions {
                    name: "INNER".to_owned(),
                    udp: true,
                    ..Default::default()
                },
                vec![Arc::new(RwLock::new(TestProvider(vec![direct, proxy])))],
                Some("DIRECT".to_owned()),
            )
            .await,
        );
        let outer: AnyOutboundHandler = Arc::new(
            Handler::new(
                HandlerOptions {
                    name: "OUTER".to_owned(),
                    udp: true,
                    ..Default::default()
                },
                vec![Arc::new(RwLock::new(TestProvider(vec![inner.clone()])))],
                None,
            )
            .await,
        );
        let pinned = PinnedOutbound::capture(outer, &Session::default())
            .await
            .unwrap();
        inner.select("PROXY").await.unwrap();
        assert_eq!(pinned.handler.name(), "DIRECT");
        let session = Session::default();
        let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
        let (stream, _) = pinned
            .handler
            .connect_stream_with_path_selection_result(
                &session,
                resolver,
                &DirectPathSelection::default(),
            )
            .await
            .unwrap();
        pinned.append_stream_chain(&stream).await;
        assert_eq!(stream.chain().snapshot().await, ["INNER", "OUTER"]);
    }

    #[tokio::test]
    async fn fallback_health_change_does_not_change_captured_tcp_or_udp() {
        let a = mock_node("A");
        let b = mock_node("B");
        let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
        let manager = ProxyManager::new(resolver.clone(), None);
        manager.report_alive("A", true).await;
        manager.report_alive("B", true).await;
        let group: AnyOutboundHandler =
            Arc::new(crate::proxy::group::fallback::Handler::new(
                crate::proxy::group::fallback::HandlerOptions {
                    name: "FALLBACK".to_owned(),
                    udp: true,
                    ..Default::default()
                },
                vec![provider_for(vec![a.clone(), b.clone()])],
                manager.clone(),
            ));
        let session = Session::default();
        let pinned_tcp = PinnedOutbound::capture(group.clone(), &session)
            .await
            .unwrap();
        let pinned_udp = PinnedOutbound::capture(group.clone(), &session)
            .await
            .unwrap();
        assert_eq!(pinned_tcp.handler.name(), "A");
        assert_eq!(pinned_udp.handler.name(), "A");
        manager.report_alive("A", false).await;
        let later = PinnedOutbound::capture(group, &session).await.unwrap();
        assert_eq!(later.handler.name(), "B");
        let (stream, _) = pinned_tcp
            .handler
            .connect_stream_with_path_selection_result(
                &session,
                resolver.clone(),
                &DirectPathSelection::default(),
            )
            .await
            .unwrap();
        pinned_tcp.append_stream_chain(&stream).await;
        assert_eq!(stream.chain().snapshot().await, ["FALLBACK"]);
        let datagram = pinned_udp
            .handler
            .connect_datagram_with_path_selection(
                &session,
                resolver.clone(),
                &DirectPathSelection::default(),
            )
            .await
            .unwrap();
        pinned_udp.append_datagram_chain(&datagram).await;
        assert_eq!(datagram.chain().snapshot().await, ["FALLBACK"]);
        assert_eq!(a.tcp_path_calls.load(Ordering::SeqCst), 1);
        assert_eq!(a.udp_path_calls.load(Ordering::SeqCst), 1);
        assert_eq!(b.tcp_path_calls.load(Ordering::SeqCst), 0);
        let (stream, _) = later
            .handler
            .connect_stream_with_path_selection_result(
                &session,
                resolver,
                &DirectPathSelection::default(),
            )
            .await
            .unwrap();
        later.append_stream_chain(&stream).await;
        assert_eq!(stream.chain().snapshot().await, ["FALLBACK"]);
        assert_eq!(b.tcp_path_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn urltest_latency_change_does_not_change_captured_outbound() {
        let a = mock_node("A");
        let b = mock_node("B");
        let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
        let manager = ProxyManager::new(resolver.clone(), None);
        manager
            .report_delay("A", true, Some(Duration::from_millis(10)))
            .await;
        manager
            .report_delay("B", true, Some(Duration::from_millis(150)))
            .await;
        let group: AnyOutboundHandler =
            Arc::new(crate::proxy::group::urltest::Handler::new(
                crate::proxy::group::urltest::HandlerOptions {
                    name: "URLTEST".to_owned(),
                    udp: true,
                    ..Default::default()
                },
                0,
                vec![provider_for(vec![a.clone(), b.clone()])],
                manager.clone(),
            ));
        let session = Session::default();
        let pinned_tcp = PinnedOutbound::capture(group.clone(), &session)
            .await
            .unwrap();
        let pinned_udp = PinnedOutbound::capture(group.clone(), &session)
            .await
            .unwrap();
        assert_eq!(pinned_tcp.handler.name(), "A");
        assert_eq!(pinned_udp.handler.name(), "A");
        manager
            .report_delay("A", true, Some(Duration::from_millis(300)))
            .await;
        manager
            .report_delay("B", true, Some(Duration::from_millis(5)))
            .await;
        let later = PinnedOutbound::capture(group, &session).await.unwrap();
        assert_eq!(later.handler.name(), "B");
        let (stream, _) = pinned_tcp
            .handler
            .connect_stream_with_path_selection_result(
                &session,
                resolver.clone(),
                &DirectPathSelection::default(),
            )
            .await
            .unwrap();
        pinned_tcp.append_stream_chain(&stream).await;
        assert_eq!(stream.chain().snapshot().await, ["URLTEST"]);
        let datagram = pinned_udp
            .handler
            .connect_datagram_with_path_selection(
                &session,
                resolver.clone(),
                &DirectPathSelection::default(),
            )
            .await
            .unwrap();
        pinned_udp.append_datagram_chain(&datagram).await;
        assert_eq!(datagram.chain().snapshot().await, ["URLTEST"]);
        assert_eq!(a.tcp_path_calls.load(Ordering::SeqCst), 1);
        assert_eq!(a.udp_path_calls.load(Ordering::SeqCst), 1);
        assert_eq!(b.tcp_path_calls.load(Ordering::SeqCst), 0);
        let (stream, _) = later
            .handler
            .connect_stream_with_path_selection_result(
                &session,
                resolver,
                &DirectPathSelection::default(),
            )
            .await
            .unwrap();
        later.append_stream_chain(&stream).await;
        assert_eq!(b.tcp_path_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn loadbalance_round_robin_selects_once_per_connection() {
        let a = mock_node("A");
        let b = mock_node("B");
        let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
        let manager = ProxyManager::new(resolver.clone(), None);
        let group: AnyOutboundHandler =
            Arc::new(crate::proxy::group::loadbalance::Handler::new(
                crate::proxy::group::loadbalance::HandlerOptions {
                    name: "BALANCE".to_owned(),
                    udp: true,
                    strategy: LoadBalanceStrategy::RoundRobin,
                    ..Default::default()
                },
                vec![provider_for(vec![a.clone(), b.clone()])],
                manager,
            ));
        let session = Session::default();
        let first = PinnedOutbound::capture(group.clone(), &session)
            .await
            .unwrap();
        let second = PinnedOutbound::capture(group.clone(), &session)
            .await
            .unwrap();
        assert_eq!(first.handler.name(), "A");
        assert_eq!(second.handler.name(), "B");
        // Planning and dialing the first selected node must not advance
        // RoundRobin a second time or silently switch to the second node.
        let (stream, _) = first
            .handler
            .connect_stream_with_path_selection_result(
                &session,
                resolver.clone(),
                &DirectPathSelection::default(),
            )
            .await
            .unwrap();
        first.append_stream_chain(&stream).await;
        assert_eq!(stream.chain().snapshot().await, ["BALANCE"]);
        let datagram = second
            .handler
            .connect_datagram_with_path_selection(
                &session,
                resolver,
                &DirectPathSelection::default(),
            )
            .await
            .unwrap();
        second.append_datagram_chain(&datagram).await;
        assert_eq!(datagram.chain().snapshot().await, ["BALANCE"]);
        assert_eq!(a.tcp_path_calls.load(Ordering::SeqCst), 1);
        assert_eq!(b.udp_path_calls.load(Ordering::SeqCst), 1);
        let third = PinnedOutbound::capture(group, &session).await.unwrap();
        assert_eq!(third.handler.name(), "A");
    }

    #[tokio::test]
    async fn selector_over_fallback_pins_direct_and_preserves_group_chain() {
        let direct = mock_node("DIRECT");
        let proxy = mock_node("PROXY");
        let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
        let manager = ProxyManager::new(resolver.clone(), None);
        manager.report_alive("DIRECT", true).await;
        manager.report_alive("PROXY", true).await;
        let fallback: AnyOutboundHandler =
            Arc::new(crate::proxy::group::fallback::Handler::new(
                crate::proxy::group::fallback::HandlerOptions {
                    name: "FALLBACK".to_owned(),
                    udp: true,
                    ..Default::default()
                },
                vec![provider_for(vec![direct.clone(), proxy.clone()])],
                manager.clone(),
            ));
        let outer: AnyOutboundHandler = Arc::new(
            Handler::new(
                HandlerOptions {
                    name: "SELECT".to_owned(),
                    udp: true,
                    ..Default::default()
                },
                vec![provider_for(vec![fallback])],
                None,
            )
            .await,
        );
        let session = Session::default();
        let pinned = PinnedOutbound::capture(outer.clone(), &session)
            .await
            .unwrap();
        assert_eq!(pinned.handler.name(), "DIRECT");
        manager.report_alive("DIRECT", false).await;
        let next = PinnedOutbound::capture(outer, &session).await.unwrap();
        assert_eq!(next.handler.name(), "PROXY");
        let datagram = pinned
            .handler
            .connect_datagram_with_path_selection(
                &session,
                resolver,
                &DirectPathSelection::default(),
            )
            .await
            .unwrap();
        pinned.append_datagram_chain(&datagram).await;
        assert_eq!(datagram.chain().snapshot().await, ["FALLBACK", "SELECT"]);
        assert_eq!(direct.udp_path_calls.load(Ordering::SeqCst), 1);
        assert_eq!(proxy.udp_path_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn empty_fallback_group_returns_error_not_panic() {
        let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
        let manager = ProxyManager::new(resolver, None);
        let group: AnyOutboundHandler =
            Arc::new(crate::proxy::group::fallback::Handler::new(
                crate::proxy::group::fallback::HandlerOptions {
                    name: "EMPTY".to_owned(),
                    udp: true,
                    ..Default::default()
                },
                vec![provider_for(Vec::new())],
                manager,
            ));
        assert!(
            PinnedOutbound::capture(group, &Session::default())
                .await
                .is_err()
        );
    }
}
