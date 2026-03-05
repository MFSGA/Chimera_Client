use async_trait::async_trait;
use std::sync::Arc;
use tracing::debug;

use crate::{
    Error,
    app::remote_content_manager::{
        healthcheck::HealthCheck,
        providers::{Provider, proxy_provider::ProxyProvider},
    },
    proxy::AnyOutboundHandler,
};

/// A plain provider that holds a list of outbound handlers (proxies).
/// No vehicle no background update.
/// Used in GroupOutbounds to manage proxy health checks.
pub struct PlainProvider {
    name: String,
    proxies: Vec<AnyOutboundHandler>,
    hc: Arc<HealthCheck>,
}

impl PlainProvider {
    pub fn new(
        name: String,
        proxies: Vec<AnyOutboundHandler>,
        hc: HealthCheck,
    ) -> anyhow::Result<Self> {
        let hc = Arc::new(hc);

        if proxies.is_empty() {
            return Err(
                Error::InvalidConfig(format!("{name}: proxies is empty")).into()
            );
        }

        if hc.auto() {
            debug!("kicking off healthcheck: {}", name);
            let hc = hc.clone();
            tokio::spawn(async move {
                hc.kick_off().await;
            });
        }

        Ok(Self { name, proxies, hc })
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
        self.hc.touch().await;
    }

    async fn healthcheck(&self) {
        self.hc.check().await;
    }
}
