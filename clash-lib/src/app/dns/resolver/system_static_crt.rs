use std::sync::atomic::AtomicBool;

use async_trait::async_trait;
use hickory_resolver::TokioResolver;
use rand::seq::IteratorRandom;

use crate::{
    Error,
    app::dns::{ClashResolver, ResolverKind, parse_ip_literal},
};

pub struct SystemResolver {
    inner: TokioResolver,
    ipv6: AtomicBool,
    dns_ipv6: bool,
}

/// Bug in libc, use tokio impl instead: https://sourceware.org/bugzilla/show_bug.cgi?id=10652
impl SystemResolver {
    pub fn new(ipv6: bool) -> anyhow::Result<Self> {
        Self::new_with_ipv6(ipv6, ipv6)
    }

    pub fn new_with_ipv6(global_ipv6: bool, dns_ipv6: bool) -> anyhow::Result<Self> {
        Ok(Self {
            inner: TokioResolver::builder_tokio()?.build(),
            ipv6: AtomicBool::new(global_ipv6),
            dns_ipv6,
        })
    }
}

#[async_trait]
impl ClashResolver for SystemResolver {
    async fn resolve(
        &self,
        host: &str,
        _: bool,
    ) -> anyhow::Result<Option<std::net::IpAddr>> {
        if let Some(ip) = parse_ip_literal(host) {
            if ip.is_ipv6() && !self.ipv6() {
                return Err(Error::DNSError(format!(
                    "IPv6 is disabled; cannot resolve IPv6 literal `{host}`"
                ))
                .into());
            }
            return Ok(Some(ip));
        }

        let response = self.inner.lookup_ip(host).await.map_err(|error| {
            if self.ipv6() {
                anyhow::Error::from(error)
            } else {
                Error::DNSError(format!(
                    "IPv6 is disabled; IPv4 lookup for hostname `{host}` failed: {error}"
                ))
                .into()
            }
        })?;
        let address = response
            .iter()
            .filter(|x| self.ipv6() || x.is_ipv4())
            .choose(&mut rand::rng());
        if address.is_none() && !self.ipv6() {
            return Err(Error::DNSError(format!(
                "IPv6 is disabled and hostname `{host}` has no IPv4 address"
            ))
            .into());
        }
        Ok(address)
    }

    async fn resolve_all(
        &self,
        host: &str,
        _: bool,
    ) -> anyhow::Result<Vec<std::net::IpAddr>> {
        if let Some(ip) = parse_ip_literal(host) {
            if ip.is_ipv6() && !self.ipv6() {
                return Err(Error::DNSError(format!(
                    "IPv6 is disabled; cannot resolve IPv6 literal `{host}`"
                ))
                .into());
            }
            return Ok(vec![ip]);
        }

        let response = self.inner.lookup_ip(host).await.map_err(|error| {
            if self.ipv6() {
                anyhow::Error::from(error)
            } else {
                Error::DNSError(format!(
                    "IPv6 is disabled; IPv4 lookup for hostname `{host}` failed: {error}"
                ))
                .into()
            }
        })?;
        let mut addresses = response
            .iter()
            .filter(|address| self.ipv6() || address.is_ipv4())
            .collect::<Vec<_>>();
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.is_empty() && !self.ipv6() {
            return Err(Error::DNSError(format!(
                "IPv6 is disabled and hostname `{host}` has no IPv4 address"
            ))
            .into());
        }
        Ok(addresses)
    }

    async fn resolve_v4(
        &self,
        host: &str,
        _: bool,
    ) -> anyhow::Result<Option<std::net::Ipv4Addr>> {
        if let Some(ip) = parse_ip_literal(host) {
            return match ip {
                std::net::IpAddr::V4(ip) => Ok(Some(ip)),
                std::net::IpAddr::V6(_) if !self.ipv6() => {
                    Err(Error::DNSError(format!(
                        "IPv6 is disabled; cannot resolve IPv6 literal `{host}`"
                    ))
                    .into())
                }
                std::net::IpAddr::V6(_) => Ok(None),
            };
        }
        let response = self.inner.ipv4_lookup(host).await?;
        Ok(response
            .answers()
            .iter()
            .filter_map(|r| match r.data() {
                Some(hickory_proto::rr::RData::A(a)) => Some(a.0),
                _ => None,
            })
            .choose(&mut rand::rng()))
    }

    async fn resolve_v6(
        &self,
        host: &str,
        _: bool,
    ) -> anyhow::Result<Option<std::net::Ipv6Addr>> {
        if !self.ipv6() {
            return Err(Error::DNSError("IPv6 is disabled".into()).into());
        }
        if let Some(ip) = parse_ip_literal(host) {
            return Ok(match ip {
                std::net::IpAddr::V6(ip) => Some(ip),
                std::net::IpAddr::V4(_) => None,
            });
        }
        let response = self.inner.ipv6_lookup(host).await?;
        Ok(response
            .answers()
            .iter()
            .filter_map(|r| match r.data() {
                Some(hickory_proto::rr::RData::AAAA(aaaa)) => Some(aaaa.0),
                _ => None,
            })
            .choose(&mut rand::rng()))
    }

    async fn cached_for(&self, _: std::net::IpAddr) -> Option<String> {
        None
    }

    async fn exchange(
        &self,
        _: &hickory_proto::op::Message,
    ) -> anyhow::Result<hickory_proto::op::Message> {
        Err(anyhow::anyhow!("unsupported"))
    }

    fn ipv6(&self) -> bool {
        self.ipv6.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn set_ipv6(&self, val: bool) {
        self.ipv6.store(val, std::sync::atomic::Ordering::Relaxed);
    }

    fn dns_ipv6(&self) -> bool {
        self.dns_ipv6
    }

    fn kind(&self) -> ResolverKind {
        ResolverKind::System
    }

    fn fake_ip_enabled(&self) -> bool {
        false
    }

    async fn is_fake_ip(&self, _: std::net::IpAddr) -> bool {
        false
    }

    async fn reverse_lookup(&self, _: std::net::IpAddr) -> Option<String> {
        None
    }

    async fn fake_ip_for_host(&self, _: &str) -> Option<std::net::IpAddr> {
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::app::dns::{ClashResolver, SystemResolver};

    #[tokio::test]
    async fn test_system_resolver_default_config() {
        let resolver = SystemResolver::new(false).unwrap();
        let response = resolver.resolve("www.google.com", false).await.unwrap();
        assert!(response.is_some());
    }
}
