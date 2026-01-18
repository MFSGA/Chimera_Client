use crate::{
    app::{
        dns::{DNSConfig, ThreadSafeDNSResolver},
        profile::ThreadSafeCacheFile,
    },
    common::mmdb::MmdbLookup,
    print_and_exit,
    proxy::OutboundHandler,
};

use std::{collections::HashMap, sync::Arc};

#[cfg(not(all(target_feature = "crt-static", target_env = "gnu")))]
#[path = "system.rs"]
mod system;

pub use system::SystemResolver;

pub async fn new(
    cfg: DNSConfig,
    store: Option<ThreadSafeCacheFile>,
    mmdb: Option<MmdbLookup>,
    outbounds: HashMap<String, Arc<dyn OutboundHandler>>,
) -> ThreadSafeDNSResolver {
    if cfg.enable {
        match store {
            Some(store) => {
                /* Arc::new(EnhancedResolver::new(cfg, store, mmdb, outbounds).await) */
                todo!()
            }
            _ => print_and_exit!("enhanced resolver requires cache store"),
        }
    } else {
        Arc::new(SystemResolver::new(cfg.ipv6).expect("failed to create system resolver"))
    }
}
