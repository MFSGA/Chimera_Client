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
    _store: ThreadSafeCacheFile,
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
            _store: store,
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

    async fn resolve(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<std::net::IpAddr>> {
        self.system.resolve(host, enhanced).await
    }
}
