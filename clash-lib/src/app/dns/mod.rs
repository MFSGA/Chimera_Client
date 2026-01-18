use async_trait::async_trait;

use std::sync::Arc;

/// 2
mod config;
/// 1
mod server;
/// 3
pub mod resolver;


pub use config::DNSConfig;
pub use server::get_dns_listener;

pub type ThreadSafeDNSResolver = Arc<dyn ClashResolver>;

/// A implementation of "anti-poisoning" Resolver
/// it can hold multiple clients in different protocols
/// each client can also hold a "default_resolver"
/// in case they need to resolve DoH in domain names etc.
/// #[cfg_attr(test, automock)]
#[async_trait]
pub trait ClashResolver: Sync + Send {}
