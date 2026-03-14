use async_trait::async_trait;

use hickory_proto::op;

use std::{
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

/// 2
pub mod config;
mod dns_client;
mod fakeip;
mod filters;
mod helper;
/// 3
pub mod resolver;
/// 1
mod server;

pub use config::DNSConfig;
pub use dns_client::DNSNetMode;
pub use server::get_dns_listener;

pub use resolver::new as new_resolver;

pub type ThreadSafeDNSResolver = Arc<dyn ClashResolver>;
pub type ThreadSafeDNSClient = Arc<dyn Client>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolverKind {
    Clash,
    System,
}

#[async_trait]
pub trait Client: Sync + Send + Debug {
    fn id(&self) -> String;
    async fn exchange(&self, msg: &op::Message) -> anyhow::Result<op::Message>;
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
    fn set_ipv6(&self, enable: bool);
    fn kind(&self) -> ResolverKind;
    fn fake_ip_enabled(&self) -> bool;

    async fn reverse_lookup(&self, ip: IpAddr) -> Option<String>;
    async fn is_fake_ip(&self, ip: IpAddr) -> bool;
    async fn cached_for(&self, ip: IpAddr) -> Option<String>;

    async fn resolve(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<std::net::IpAddr>>;

    async fn resolve_v4(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<Ipv4Addr>> {
        Ok(match self.resolve(host, enhanced).await? {
            Some(IpAddr::V4(ip)) => Some(ip),
            _ => None,
        })
    }

    async fn resolve_v6(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<Ipv6Addr>> {
        Ok(match self.resolve(host, enhanced).await? {
            Some(IpAddr::V6(ip)) => Some(ip),
            _ => None,
        })
    }
}
