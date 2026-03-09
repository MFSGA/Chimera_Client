use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use tracing::debug;

use crate::{
    app::{
        dns::{ClashResolver, DNSConfig},
        profile::ThreadSafeCacheFile,
    },
    common::mmdb::MmdbLookup,
    proxy::OutboundHandler,
};

use super::SystemResolver;

pub struct EnhancedResolver {
    system: SystemResolver,
    store: ThreadSafeCacheFile,
    _mmdb: Option<MmdbLookup>,
    _outbounds: HashMap<String, Arc<dyn OutboundHandler>>,
}

impl EnhancedResolver {
    pub async fn new(
        cfg: DNSConfig,
        store: ThreadSafeCacheFile,
        mmdb: Option<MmdbLookup>,
        outbounds: HashMap<String, Arc<dyn OutboundHandler>>,
    ) -> Self {
        debug!(ipv6 = cfg.ipv6, "creating enhanced resolver");
        Self {
            system: SystemResolver::new(cfg.ipv6)
                .expect("failed to create fallback system resolver"),
            store,
            _mmdb: mmdb,
            _outbounds: outbounds,
        }
    }
}

#[async_trait]
impl ClashResolver for EnhancedResolver {
    async fn exchange(
        &self,
        message: &hickory_proto::op::Message,
    ) -> anyhow::Result<hickory_proto::op::Message> {
        self.system.exchange(message).await
    }

    fn ipv6(&self) -> bool {
        self.system.ipv6()
    }

    fn set_ipv6(&self, enable: bool) {
        self.system.set_ipv6(enable);
    }

    fn kind(&self) -> crate::app::dns::ResolverKind {
        crate::app::dns::ResolverKind::Clash
    }

    fn fake_ip_enabled(&self) -> bool {
        false
    }

    async fn is_fake_ip(&self, _: std::net::IpAddr) -> bool {
        false
    }

    async fn resolve(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<std::net::IpAddr>> {
        let resolved = self.system.resolve(host, enhanced).await?;
        if let Some(ip) = resolved {
            let ip = ip.to_string();
            self.store.set_host_to_ip(host, &ip).await;
            self.store.set_ip_to_host(&ip, host).await;
        }
        Ok(resolved)
    }

    async fn reverse_lookup(&self, ip: std::net::IpAddr) -> Option<String> {
        self.store.get_fake_ip(&ip.to_string()).await
    }

    async fn cached_for(&self, ip: std::net::IpAddr) -> Option<String> {
        self.store.get_fake_ip(&ip.to_string()).await
    }
}
