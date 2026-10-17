//! Conservative Smart proxy group: health, recent delay and hysteresis only.
//!
//! This baseline does not implement LightGBM, ASN-aware weighting, historical
//! failure tracking, traffic learning or persisted statistics. Unsupported
//! advanced configuration is rejected by `OutboundGroupSmart::validate`.
pub mod policy;

use std::{io, time::Duration};

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::ThreadSafeDNSResolver,
        remote_content_manager::{
            ProxyManager, providers::proxy_provider::ThreadSafeProxyProvider,
        },
    },
    proxy::{
        AnyOutboundHandler, ConnectorType, DialWithConnector, HandlerCommonOptions,
        OutboundHandler, OutboundType,
        group::GroupProxyAPIResponse,
        utils::{RemoteConnector, provider_helper::get_proxies_from_providers},
    },
    session::Session,
};

#[derive(Default)]
pub struct HandlerOptions {
    pub common_opts: HandlerCommonOptions,
    pub name: String,
    pub udp: bool,
}

pub struct Handler {
    opts: HandlerOptions,
    tolerance: Duration,
    providers: Vec<ThreadSafeProxyProvider>,
    proxy_manager: ProxyManager,
    selected_name: Mutex<Option<String>>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Smart")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub fn new(
        opts: HandlerOptions,
        tolerance_ms: u16,
        providers: Vec<ThreadSafeProxyProvider>,
        proxy_manager: ProxyManager,
    ) -> Self {
        Self {
            opts,
            tolerance: Duration::from_millis(tolerance_ms.into()),
            providers,
            proxy_manager,
            selected_name: Mutex::new(None),
        }
    }

    async fn get_proxies(&self, touch: bool) -> Vec<AnyOutboundHandler> {
        get_proxies_from_providers(&self.providers, touch).await
    }

    async fn select(&self, touch: bool) -> Option<AnyOutboundHandler> {
        let proxies = self.get_proxies(touch).await;
        let mut observations = Vec::with_capacity(proxies.len());
        for proxy in &proxies {
            let (alive, delay) =
                self.proxy_manager.alive_and_last_delay(proxy.name()).await;
            observations.push(policy::Candidate {
                name: proxy.name(),
                alive,
                last_delay: delay,
                // A health-check failure is currently reflected only in alive;
                // persistent per-node failure counters are not wired up yet.
                consecutive_failures: 0,
            });
        }

        let mut selected_name = self.selected_name.lock().await;
        let index =
            policy::choose(&observations, selected_name.as_deref(), self.tolerance)?;
        let selected = proxies[index].clone();
        *selected_name = Some(selected.name().to_owned());
        Some(selected)
    }

    async fn required_selection(
        &self,
        touch: bool,
    ) -> io::Result<AnyOutboundHandler> {
        self.select(touch).await.ok_or_else(|| {
            io::Error::other(format!(
                "smart group `{}` has no healthy proxies",
                self.name()
            ))
        })
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Smart
    }

    async fn support_udp(&self) -> bool {
        if !self.opts.udp {
            return false;
        }
        match self.select(false).await {
            Some(selected) => selected.support_udp().await,
            None => false,
        }
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let selected = self.required_selection(true).await?;
        let stream = selected.connect_stream(sess, resolver).await?;
        stream.append_to_chain(self.name()).await;
        Ok(stream)
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        if !self.opts.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Smart UDP disabled",
            ));
        }
        let selected = self.required_selection(true).await?;
        let datagram = selected.connect_datagram(sess, resolver).await?;
        datagram.append_to_chain(self.name()).await;
        Ok(datagram)
    }

    async fn support_connector(&self) -> ConnectorType {
        match self.select(false).await {
            Some(selected) => selected.support_connector().await,
            None => ConnectorType::Tcp,
        }
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        let selected = self.required_selection(true).await?;
        let stream = selected
            .connect_stream_with_connector(sess, resolver, connector)
            .await?;
        stream.append_to_chain(self.name()).await;
        Ok(stream)
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedDatagram> {
        if !self.opts.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Smart UDP disabled",
            ));
        }
        let selected = self.required_selection(true).await?;
        let datagram = selected
            .connect_datagram_with_connector(sess, resolver, connector)
            .await?;
        datagram.append_to_chain(self.name()).await;
        Ok(datagram)
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
        self.select(false).await
    }

    async fn select_proxy_for_connection(
        &self,
        session: &Session,
    ) -> io::Result<AnyOutboundHandler> {
        if session.network == crate::session::Network::Udp && !self.opts.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Smart UDP disabled",
            ));
        }
        let selected = self.required_selection(true).await?;
        if session.network == crate::session::Network::Udp
            && !selected.support_udp().await
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "selected Smart proxy does not support UDP",
            ));
        }
        Ok(selected)
    }

    fn get_latency_test_url(&self) -> Option<String> {
        self.opts.common_opts.url.clone()
    }

    fn icon(&self) -> Option<String> {
        self.opts.common_opts.icon.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, io, sync::Arc, time::Duration};

    use async_trait::async_trait;
    use erased_serde::Serialize;
    use tokio::sync::RwLock;

    use crate::{
        app::remote_content_manager::{
            ProxyManager,
            providers::{
                Provider, ProviderType, ProviderVehicleType,
                proxy_provider::{ProxyProvider, ThreadSafeProxyProvider},
            },
        },
        proxy::{
            AnyOutboundHandler, OutboundHandler, OutboundType,
            group::{GroupProxyAPIResponse, selector::PinnedOutbound},
            utils::test_utils::noop::{NoopOutboundHandler, NoopResolver},
        },
        session::Session,
    };

    #[derive(Debug)]
    struct TestProvider(Vec<AnyOutboundHandler>);

    #[async_trait]
    impl Provider for TestProvider {
        fn name(&self) -> &str {
            "smart-test"
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

    fn provider(names: &[&str]) -> ThreadSafeProxyProvider {
        let proxies = names
            .iter()
            .map(|name| {
                Arc::new(NoopOutboundHandler {
                    name: (*name).to_owned(),
                }) as AnyOutboundHandler
            })
            .collect();
        Arc::new(RwLock::new(TestProvider(proxies)))
    }

    #[tokio::test]
    async fn chooses_healthy_proxy_with_hysteresis_and_pins_for_flow() {
        let manager = ProxyManager::new(Arc::new(NoopResolver), None);
        manager
            .report_delay("a", true, Some(Duration::from_millis(80)))
            .await;
        manager
            .report_delay("b", true, Some(Duration::from_millis(50)))
            .await;
        let smart = Arc::new(super::Handler::new(
            super::HandlerOptions {
                name: "SMART".to_owned(),
                udp: true,
                ..Default::default()
            },
            20,
            vec![provider(&["a", "b"])],
            manager.clone(),
        ));
        assert!(matches!(smart.proto(), OutboundType::Smart));
        assert_eq!(smart.get_active_proxy().await.unwrap().name(), "b");

        manager
            .report_delay("a", true, Some(Duration::from_millis(40)))
            .await;
        assert_eq!(smart.get_active_proxy().await.unwrap().name(), "b");

        manager
            .report_delay("a", true, Some(Duration::from_millis(20)))
            .await;
        let pinned = PinnedOutbound::capture(smart.clone(), &Session::default())
            .await
            .expect("Smart group must be resolved before dialing");
        assert_eq!(pinned.handler.name(), "a");
        assert_eq!(smart.get_active_proxy().await.unwrap().name(), "a");

        manager.report_alive("a", false).await;
        assert_eq!(smart.get_active_proxy().await.unwrap().name(), "b");
    }

    #[tokio::test]
    async fn pinned_udp_flow_respects_smart_udp_opt_out() {
        let manager = ProxyManager::new(Arc::new(NoopResolver), None);
        let smart: AnyOutboundHandler = Arc::new(super::Handler::new(
            super::HandlerOptions {
                name: "no-udp".to_owned(),
                udp: false,
                ..Default::default()
            },
            10,
            vec![provider(&["healthy"])],
            manager,
        ));
        let session = Session {
            network: crate::session::Network::Udp,
            ..Session::default()
        };
        assert!(!smart.support_udp().await);
        let Err(error) = PinnedOutbound::capture(smart, &session).await else {
            panic!("nested group selection must not bypass Smart UDP opt-out");
        };
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    #[tokio::test]
    async fn rejects_empty_or_entirely_unhealthy_proxy_set_without_dialing() {
        let manager = ProxyManager::new(Arc::new(NoopResolver), None);
        let empty = super::Handler::new(
            super::HandlerOptions {
                name: "empty".to_owned(),
                ..Default::default()
            },
            10,
            vec![provider(&[])],
            manager.clone(),
        );
        assert!(empty.get_active_proxy().await.is_none());
        assert!(
            empty
                .select_proxy_for_connection(&Session::default())
                .await
                .is_err()
        );

        manager.report_alive("dead", false).await;
        let unhealthy = super::Handler::new(
            super::HandlerOptions {
                name: "unhealthy".to_owned(),
                ..Default::default()
            },
            10,
            vec![provider(&["dead"])],
            manager,
        );
        assert!(unhealthy.get_active_proxy().await.is_none());
        assert!(
            unhealthy
                .select_proxy_for_connection(&Session::default())
                .await
                .is_err()
        );
        assert!(!unhealthy.support_udp().await);
    }
}
