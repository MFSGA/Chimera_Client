use std::sync::atomic::AtomicBool;

use crate::{
    Error,
    app::dns::{ClashResolver, ResolverKind, parse_ip_literal},
};
use async_trait::async_trait;
use rand::seq::IteratorRandom;
use tracing::{debug, warn};

pub struct SystemResolver {
    ipv6: AtomicBool,
    dns_ipv6: bool,
}

/// SystemResolver is a resolver that uses libc getaddrinfo to resolve
/// hostnames.
impl SystemResolver {
    pub fn new(ipv6: bool) -> anyhow::Result<Self> {
        Self::new_with_ipv6(ipv6, ipv6)
    }

    pub fn new_with_ipv6(global_ipv6: bool, dns_ipv6: bool) -> anyhow::Result<Self> {
        debug!(
            "creating system resolver with global_ipv6={} dns_ipv6={}",
            global_ipv6, dns_ipv6
        );
        Ok(Self {
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

        let response = tokio::net::lookup_host(format!("{host}:0"))
            .await
            .map_err(|error| {
                if self.ipv6() {
                    anyhow::Error::from(error)
                } else {
                    Error::DNSError(format!(
                        "IPv6 is disabled; IPv4 lookup for hostname `{host}` failed: {error}"
                    ))
                    .into()
                }
            })?
            .filter_map(|x| {
                if self.ipv6() || x.is_ipv4() {
                    Some(x.ip())
                } else {
                    warn!(
                        "resolved v6 address {} for {} but ipv6 is disabled",
                        x.ip(),
                        host
                    );
                    None
                }
            })
            .collect::<Vec<_>>();
        let address = response.into_iter().choose(&mut rand::rng());
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

        let mut addresses = tokio::net::lookup_host(format!("{host}:0"))
            .await
            .map_err(|error| {
                if self.ipv6() {
                    anyhow::Error::from(error)
                } else {
                    Error::DNSError(format!(
                        "IPv6 is disabled; IPv4 lookup for hostname `{host}` failed: {error}"
                    ))
                    .into()
                }
            })?
            .map(|address| address.ip())
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
        let response = tokio::net::lookup_host(format!("{host}:0"))
            .await?
            .filter_map(|ip| match ip.ip() {
                std::net::IpAddr::V4(ip) => Some(ip),
                _ => None,
            })
            .collect::<Vec<_>>();
        Ok(response.into_iter().choose(&mut rand::rng()))
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
        let response = tokio::net::lookup_host(format!("{host}:0"))
            .await?
            .filter_map(|x| match x.ip() {
                std::net::IpAddr::V6(ip) => Some(ip),
                _ => None,
            })
            .collect::<Vec<_>>();
        Ok(response.into_iter().choose(&mut rand::rng()))
    }

    async fn cached_for(&self, _: std::net::IpAddr) -> Option<String> {
        None
    }

    async fn exchange(
        &self,
        _: &hickory_proto::op::Message,
    ) -> anyhow::Result<hickory_proto::op::Message> {
        Err(anyhow::anyhow!(
            "system resolver does not support advanced dns features, please enable \
             the dns server in your config"
        ))
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
    use crate::app::dns::{ClashResolver, resolver::SystemResolver};

    #[tokio::test]
    async fn test_system_resolver_default_config() {
        let resolver = SystemResolver::new(false).unwrap();
        let response = resolver.resolve("localhost", false).await.unwrap();
        assert!(response.is_some_and(|ip| ip.is_ipv4()));
    }

    #[tokio::test]
    async fn ipv6_literal_is_rejected_when_disabled() {
        let resolver = SystemResolver::new(false).unwrap();
        let error = resolver
            .resolve("2001:db8::1", false)
            .await
            .expect_err("IPv6 literal must not bypass the global setting");
        assert!(error.to_string().contains("IPv6 is disabled"));
    }

    #[tokio::test]
    async fn global_ipv6_can_resolve_literals_when_dns_aaaa_is_disabled() {
        let resolver = SystemResolver::new_with_ipv6(true, false).unwrap();
        assert!(resolver.ipv6());
        assert!(!resolver.dns_ipv6());
        assert_eq!(
            resolver.resolve("2001:db8::1", false).await.unwrap(),
            Some("2001:db8::1".parse().unwrap())
        );
    }
}
