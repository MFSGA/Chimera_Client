use std::{net::IpAddr, sync::Arc};

use crate::common::{mmdb::MmdbLookup, trie::StringTrie};

pub trait FallbackIpFilter: Sync + Send {
    fn apply(&self, ip: &IpAddr) -> bool;
}
pub use FallbackIpFilter as FallbackIPFilter;

pub trait FallbackDomainFilter: Sync + Send {
    fn apply(&self, domain: &str) -> bool;
}

pub struct GeoIpFilter {
    code: String,
    mmdb: Option<MmdbLookup>,
}
pub use GeoIpFilter as GeoIPFilter;

impl GeoIpFilter {
    pub fn new(code: &str, mmdb: Option<MmdbLookup>) -> Self {
        Self {
            code: code.to_string(),
            mmdb,
        }
    }
}

impl FallbackIpFilter for GeoIpFilter {
    fn apply(&self, ip: &IpAddr) -> bool {
        !self.mmdb.as_ref().is_some_and(|mmdb| {
            mmdb.lookup_country(*ip)
                .map(|country| country.country_code == self.code)
                .unwrap_or(false)
        })
    }
}

pub struct IpNetFilter(ipnet::IpNet);

impl IpNetFilter {
    pub fn new(ipnet: ipnet::IpNet) -> Self {
        Self(ipnet)
    }
}
pub use IpNetFilter as IPNetFilter;

impl FallbackIpFilter for IpNetFilter {
    fn apply(&self, ip: &IpAddr) -> bool {
        self.0.contains(ip)
    }
}

pub struct DomainFilter(StringTrie<Option<String>>);

impl DomainFilter {
    pub fn new(domains: &[String]) -> Self {
        let mut filter = Self(StringTrie::new());

        for domain in domains {
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            filter.0.insert(&domain, Arc::new(None));
        }

        filter
    }
}

impl FallbackDomainFilter for DomainFilter {
    fn apply(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        self.0.search(&domain).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::{DomainFilter, FallbackDomainFilter};

    #[test]
    fn domain_filter_matches_trie_patterns() {
        let filter = DomainFilter::new(&[
            "*.example.com".to_string(),
            ".apple.*".to_string(),
            "+.foo.com".to_string(),
        ]);

        assert!(filter.apply("sub.example.com"));
        assert!(filter.apply("test.apple.com"));
        assert!(filter.apply("foo.com"));
        assert!(filter.apply("bar.foo.com"));

        assert!(!filter.apply("example.com"));
        assert!(!filter.apply("foo.example.net"));
    }
}
