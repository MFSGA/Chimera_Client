use std::collections::HashMap;

use async_trait::async_trait;

use crate::proxy::{AnyOutboundHandler, OutboundHandler};
use erased_serde::Serialize;

pub mod selector;

pub mod urltest;

pub mod fallback;

pub mod relay;

/// Convenience trait for group proxy serializing API responses.
#[async_trait]
pub trait GroupProxyAPIResponse: OutboundHandler {
    /// Returns all proxies in the group, which are usually stored in a list of
    /// ProxyProviders.
    async fn get_proxies(&self) -> Vec<AnyOutboundHandler>;

    /// Returns the current effective proxy for the group.
    /// e.g. for a selector, it returns the currently selected proxy, and for
    /// urltest, it returns the fastest proxy, etc.
    async fn get_active_proxy(&self) -> Option<AnyOutboundHandler>;

    /// Returns the preferred latency test URL for the group, if configured.
    fn get_latency_test_url(&self) -> Option<String> {
        None
    }

    /// used in the API responses.
    async fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        let all = self.get_proxies().await;

        let mut m = HashMap::new();

        if let Some(active) = self.get_active_proxy().await {
            m.insert("now".to_string(), Box::new(active.name().to_owned()) as _);
        }

        m.insert(
            "icon".to_string(),
            Box::new(self.icon().unwrap_or_default()) as _,
        );
        m.insert("hidden".to_string(), Box::new(false) as _);
        m.insert(
            "testUrl".to_string(),
            Box::new(self.get_latency_test_url().unwrap_or_default()) as _,
        );

        m.insert(
            "all".to_string(),
            Box::new(all.iter().map(|x| x.name().to_owned()).collect::<Vec<_>>())
                as _,
        );
        m
    }

    fn icon(&self) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, io, sync::Arc};

    use crate::{
        app::{
            dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
            dns::ThreadSafeDNSResolver,
        },
        proxy::{
            ConnectorType, DialWithConnector, OutboundHandler, OutboundType,
            group::GroupProxyAPIResponse,
        },
        session::Session,
    };

    #[derive(Debug)]
    struct TestHandler {
        name: String,
        active_name: String,
        proxy_names: Vec<String>,
        test_url: Option<String>,
        icon: Option<String>,
    }

    impl DialWithConnector for TestHandler {}

    #[async_trait::async_trait]
    impl OutboundHandler for TestHandler {
        fn name(&self) -> &str {
            &self.name
        }

        fn proto(&self) -> OutboundType {
            OutboundType::Selector
        }

        async fn support_udp(&self) -> bool {
            true
        }

        async fn connect_stream(
            &self,
            _sess: &Session,
            _resolver: ThreadSafeDNSResolver,
        ) -> io::Result<BoxedChainedStream> {
            unreachable!()
        }

        async fn connect_datagram(
            &self,
            _sess: &Session,
            _resolver: ThreadSafeDNSResolver,
        ) -> io::Result<BoxedChainedDatagram> {
            unreachable!()
        }

        async fn support_connector(&self) -> ConnectorType {
            ConnectorType::None
        }
    }

    #[async_trait::async_trait]
    impl GroupProxyAPIResponse for TestHandler {
        async fn get_proxies(&self) -> Vec<Arc<dyn OutboundHandler>> {
            self.proxy_names
                .iter()
                .map(|n| {
                    Arc::new(TestHandler {
                        name: n.clone(),
                        active_name: String::new(),
                        proxy_names: vec![],
                        test_url: None,
                        icon: None,
                    }) as Arc<dyn OutboundHandler>
                })
                .collect()
        }

        async fn get_active_proxy(&self) -> Option<Arc<dyn OutboundHandler>> {
            Some(Arc::new(TestHandler {
                name: self.active_name.clone(),
                active_name: String::new(),
                proxy_names: vec![],
                test_url: None,
                icon: None,
            }) as Arc<dyn OutboundHandler>)
        }

        fn get_latency_test_url(&self) -> Option<String> {
            self.test_url.clone()
        }

        fn icon(&self) -> Option<String> {
            self.icon.clone()
        }
    }

    fn json(
        map: &HashMap<String, Box<dyn erased_serde::Serialize + Send>>,
    ) -> serde_json::Value {
        serde_json::to_value(map).unwrap()
    }

    #[tokio::test]
    async fn as_map_includes_expected_fields() {
        let h = TestHandler {
            name: "test-group".into(),
            active_name: "proxy-1".into(),
            proxy_names: vec!["proxy-1".into(), "proxy-2".into()],
            test_url: Some("http://example.com".into()),
            icon: Some("icon.svg".into()),
        };

        let map = h.as_map().await;
        let j = json(&map);

        assert_eq!(j["now"], "proxy-1");
        assert_eq!(j["icon"], "icon.svg");
        assert_eq!(j["hidden"], false);
        assert_eq!(j["testUrl"], "http://example.com");
        assert_eq!(j["all"], serde_json::json!(["proxy-1", "proxy-2"]));
    }

    #[tokio::test]
    async fn as_map_defaults_when_not_configured() {
        let h = TestHandler {
            name: "test-group".into(),
            active_name: "proxy-1".into(),
            proxy_names: vec!["proxy-1".into()],
            test_url: None,
            icon: None,
        };

        let map = h.as_map().await;
        let j = json(&map);

        assert_eq!(j["now"], "proxy-1");
        assert_eq!(j["icon"], "");
        assert_eq!(j["hidden"], false);
        assert_eq!(j["testUrl"], "");
        assert_eq!(j["all"], serde_json::json!(["proxy-1"]));
    }

    #[tokio::test]
    async fn as_map_does_not_include_type() {
        let h = TestHandler {
            name: "test-group".into(),
            active_name: "proxy-1".into(),
            proxy_names: vec!["proxy-1".into()],
            test_url: None,
            icon: None,
        };

        let map = h.as_map().await;
        assert!(!map.contains_key("type"), "as_map should not include type");
    }
}
