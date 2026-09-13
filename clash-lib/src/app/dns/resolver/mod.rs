mod enhanced;

#[cfg(all(target_feature = "crt-static", target_env = "gnu"))]
#[path = "system_static_crt.rs"]
mod system;

#[cfg(not(all(target_feature = "crt-static", target_env = "gnu")))]
#[path = "system.rs"]
mod system;

use std::sync::Arc;

pub use enhanced::EnhancedResolver;
pub use system::SystemResolver;

use super::{Config, ThreadSafeDNSResolver};
use crate::{
    app::profile::ThreadSafeCacheFile,
    dns::{RuleDispatch, filters::PendingMmdb},
    proxy::utils::OutboundHandlerRegistry,
};

pub async fn new(
    cfg: Config,
    store: Option<ThreadSafeCacheFile>,
    mmdb: Option<PendingMmdb>,
    outbounds: OutboundHandlerRegistry,
    rule_dispatch: Option<Arc<RuleDispatch>>,
) -> Result<ThreadSafeDNSResolver, crate::Error> {
    if cfg.enable {
        match store {
            Some(store) => Ok(Arc::new(
                EnhancedResolver::new(cfg, store, mmdb, outbounds, rule_dispatch)
                    .await?,
            )),
            _ => Err(crate::Error::InvalidConfig(
                "enhanced resolver requires cache store".to_owned(),
            )),
        }
    } else {
        Ok(Arc::new(
            SystemResolver::new(cfg.ipv6)
                .map_err(|err| crate::Error::DNSError(err.to_string()))?,
        ))
    }
}
