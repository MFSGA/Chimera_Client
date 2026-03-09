use std::net::IpAddr;

use crate::common::mmdb::MmdbLookup;

pub trait FallbackIpFilter: Sync + Send {
    fn apply(&self, ip: &IpAddr) -> bool;
}

pub trait FallbackDomainFilter: Sync + Send {
    fn apply(&self, domain: &str) -> bool;
}

pub struct GeoIpFilter {
    code: String,
    mmdb: Option<MmdbLookup>,
}

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

impl FallbackIpFilter for IpNetFilter {
    fn apply(&self, ip: &IpAddr) -> bool {
        self.0.contains(ip)
    }
}

pub struct DomainFilter(Vec<String>);

impl DomainFilter {
    pub fn new(domains: &[String]) -> Self {
        Self(
            domains
                .iter()
                .map(|domain| domain.trim_end_matches('.').to_ascii_lowercase())
                .collect(),
        )
    }
}

impl FallbackDomainFilter for DomainFilter {
    fn apply(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        self.0.iter().any(|pattern| {
            domain == *pattern
                || domain
                    .strip_suffix(pattern)
                    .is_some_and(|rest| rest.ends_with('.'))
        })
    }
}
