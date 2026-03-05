use async_trait::async_trait;

use crate::{
    app::remote_content_manager::providers::{
        Provider, proxy_provider::ProxyProvider,
    },
    proxy::AnyOutboundHandler,
};

/// A plain provider that holds a list of outbound handlers (proxies).
/// No vehicle no background update.
/// Used in GroupOutbounds to manage proxy health checks.
pub struct PlainProvider {
    name: String,
    proxies: Vec<AnyOutboundHandler>,
    // hc: Arc<HealthCheck>,
}

impl PlainProvider {
    pub fn new(
        name: String,
        proxies: Vec<AnyOutboundHandler>,
        // hc: HealthCheck,
    ) -> anyhow::Result<Self> {
        todo!()
    }
}

#[async_trait]
impl Provider for PlainProvider {
    fn name(&self) -> &str {
        &self.name
    }
}

#[async_trait]
impl ProxyProvider for PlainProvider {
    async fn proxies(&self) -> Vec<AnyOutboundHandler> {
        self.proxies.clone()
    }

    async fn touch(&self) {
        todo!()
        // self.hc.touch().await;
    }

    async fn healthcheck(&self) {
        todo!()
        // self.hc.check().await;
    }
}
