use async_trait::async_trait;

use hickory_proto::op;

use std::sync::Arc;

/// 2
mod config;
/// 3
pub mod resolver;
/// 1
mod server;

pub use config::DNSConfig;
pub use server::get_dns_listener;

pub use resolver::new as new_resolver;

pub type ThreadSafeDNSResolver = Arc<dyn ClashResolver>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolverKind {
    Clash,
    System,
}

/// A implementation of "anti-poisoning" Resolver
/// it can hold multiple clients in different protocols
/// each client can also hold a "default_resolver"
/// in case they need to resolve DoH in domain names etc.
/// #[cfg_attr(test, automock)]
#[async_trait]
pub trait ClashResolver: Sync + Send {
    /// Used for DNS Server
    async fn exchange(&self, message: &op::Message) -> anyhow::Result<op::Message>;

    fn ipv6(&self) -> bool;

    async fn resolve(&self, host: &str, enhanced: bool)
    -> anyhow::Result<Option<std::net::IpAddr>>;
}
