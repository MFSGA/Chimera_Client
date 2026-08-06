use async_trait::async_trait;

use std::fmt::Debug;

use hickory_proto::op;
use std::sync::Arc;

#[cfg(test)]
use mockall::automock;

pub mod config;
mod dhcp;
mod dns_client;
mod fakeip;
mod filters;
mod helper;
pub mod resolver;
mod rule_dispatch;
mod runtime;
mod server;

pub use config::{Config, EdnsClientSubnet};

pub use filters::PendingMmdb;
pub use rule_dispatch::{PendingOutboundManager, PendingRouter, RuleDispatch};

pub use resolver::{EnhancedResolver, SystemResolver, new as new_resolver};

pub use server::DnsRunner;
#[cfg(feature = "tun")]
pub use server::exchange_with_resolver;

#[async_trait]
pub trait Client: Sync + Send + Debug {
    /// used to identify the client for logging
    fn id(&self) -> String;
    async fn exchange(&self, msg: &op::Message) -> anyhow::Result<op::Message>;

    /// Drop any network-bound transport so the next query reconnects on the
    /// currently active network. Returns the number of live transports reset.
    async fn reset_transport(&self) -> anyhow::Result<u32> {
        Ok(0)
    }
}

type ThreadSafeDNSClient = Arc<dyn Client>;

pub enum ResolverKind {
    Clash,
    System,
}

pub type ThreadSafeDNSResolver = Arc<dyn ClashResolver>;

/// A implementation of "anti-poisoning" Resolver
/// it can hold multiple clients in different protocols
/// each client can also hold a "default_resolver"
/// in case they need to resolve DoH in domain names etc.
#[cfg_attr(test, automock)]
#[async_trait]
pub trait ClashResolver: Sync + Send {
    async fn resolve(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<std::net::IpAddr>>;
    async fn resolve_all(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Vec<std::net::IpAddr>> {
        Ok(self.resolve(host, enhanced).await?.into_iter().collect())
    }
    async fn resolve_v4(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<std::net::Ipv4Addr>>;
    async fn resolve_v6(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<std::net::Ipv6Addr>>;

    async fn cached_for(&self, ip: std::net::IpAddr) -> Option<String>;

    /// Used for DNS Server
    async fn exchange(&self, message: &op::Message) -> anyhow::Result<op::Message>;

    /// Only used for look up fake IP
    async fn reverse_lookup(&self, ip: std::net::IpAddr) -> Option<String>;
    async fn is_fake_ip(&self, ip: std::net::IpAddr) -> bool;
    async fn fake_ip_for_host(&self, host: &str) -> Option<std::net::IpAddr>;
    fn fake_ip_enabled(&self) -> bool;

    fn ipv6(&self) -> bool;
    fn set_ipv6(&self, enable: bool);

    /// Drop all live upstream transports owned by this resolver. The resolver
    /// remains usable and reconnects lazily on the next query.
    async fn reset_transports(&self) -> anyhow::Result<u32> {
        Ok(0)
    }

    fn kind(&self) -> ResolverKind;
}

/// Returns the IP address if `host` is a valid IP literal, otherwise `None`.
/// Used by resolvers to short-circuit DNS resolution for IP literals.
pub(crate) fn parse_ip_literal(host: &str) -> Option<std::net::IpAddr> {
    host.parse().ok()
}
