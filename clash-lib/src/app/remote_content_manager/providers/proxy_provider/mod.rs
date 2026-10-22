pub mod plain_provider;
pub mod proxy_set_provider;

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::{
    app::remote_content_manager::providers::Provider, proxy::AnyOutboundHandler,
};

pub type ThreadSafeProxyProvider = Arc<RwLock<dyn ProxyProvider + Send + Sync>>;

/// An atomic view of one provider's candidate objects and content revision.
/// A version is about change detection, NOT origin authentication.
#[derive(Clone)]
pub struct ProxyProviderContentSnapshot {
    pub revision: u64,
    pub proxies: Vec<AnyOutboundHandler>,
}

#[async_trait]
pub trait ProxyProvider: Provider {
    async fn proxies(&self) -> Vec<AnyOutboundHandler>;

    /// Providers without an atomic content revision fail closed when used by
    /// strict DNS bootstrap preflight. Existing provider behavior is unchanged.
    async fn strict_content_snapshot(&self) -> Option<ProxyProviderContentSnapshot> {
        None
    }
    async fn touch(&self);
    // this is a blocking call, you may want to spawn a new task to run this
    async fn healthcheck(&self);
}
