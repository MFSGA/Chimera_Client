mod rules;

use std::sync::Arc;

pub use rules::RuleMatcher;
use tracing::{info, trace};

use crate::{
    Session,
    app::{
        dns::ThreadSafeDNSResolver,
        router::rules::{
            domain::Domain, domain_keyword::DomainKeyword,
            domain_suffix::DomainSuffix, final_::Final, ipcidr::IpCidr,
        },
    },
    common::{geodata::GeoDataLookup, mmdb::MmdbLookup},
    config::internal::rule::RuleType,
    print_and_exit,
};

const MATCH: &str = "MATCH";

pub struct Router {
    rules: Vec<Box<dyn RuleMatcher>>,
    dns_resolver: ThreadSafeDNSResolver,
    // kept aligned with clash-rs matcher flow
    asn_mmdb: Option<MmdbLookup>,
}

pub type ThreadSafeRouter = Arc<Router>;

#[derive(serde::Serialize)]
pub struct RuleSnapshot {
    #[serde(rename = "type")]
    pub type_name: String,
    pub proxy: String,
    pub payload: String,
}

impl Router {
    pub async fn new(
        rules: Vec<RuleType>,
        dns_resolver: ThreadSafeDNSResolver,
        country_mmdb: Option<MmdbLookup>,
        asn_mmdb: Option<MmdbLookup>,
        geodata: Option<GeoDataLookup>,
        cwd: String,
    ) -> Self {
        Self {
            rules: rules
                .into_iter()
                .map(|r| map_rule_type(r, country_mmdb.clone(), geodata.clone()))
                .collect(),
            dns_resolver,
            asn_mmdb,
        }
    }

    pub fn get_all_rules(&self) -> Vec<RuleSnapshot> {
        self.rules
            .iter()
            .map(|rule| RuleSnapshot {
                type_name: rule.type_name().to_string(),
                proxy: rule.target().to_string(),
                payload: rule.payload(),
            })
            .collect()
    }

    pub async fn match_route(
        &self,
        sess: &mut Session,
    ) -> (&str, Option<&Box<dyn RuleMatcher>>) {
        let mut sess_resolved = false;

        for r in self.rules.iter() {
            if sess.destination.is_domain()
                && r.should_resolve_ip()
                && !sess_resolved
            {
                if let Ok(Some(ip)) = self
                    .dns_resolver
                    .resolve(sess.destination.domain().unwrap(), false)
                    .await
                {
                    sess.resolved_ip = Some(ip);
                    sess_resolved = true;
                }
            }

            let maybe_ip = sess.resolved_ip.or(sess.destination.ip());
            if let (Some(ip), Some(asn_mmdb)) = (maybe_ip, &self.asn_mmdb) {
                let rv = asn_mmdb.lookup_country(ip);
                if let Ok(country) = rv {
                    sess.asn = Some(country.country_code);
                }
                if sess.asn.is_none() {
                    match asn_mmdb.lookup_asn(ip) {
                        Ok(asn) => {
                            trace!("asn for {} is {:?}", ip, asn);
                            sess.asn = Some(asn.asn_name);
                        }
                        Err(e) => {
                            trace!("failed to lookup ASN for {}: {}", ip, e);
                        }
                    }
                }
            }

            if r.apply(sess) {
                info!(
                    "matched {} to target {}[{}]",
                    &sess,
                    r.target(),
                    r.type_name()
                );
                return (r.target(), Some(r));
            }
        }

        (MATCH, None)
    }
}

pub fn map_rule_type(
    rule_type: RuleType,
    mmdb: Option<MmdbLookup>,
    geodata: Option<GeoDataLookup>,
) -> Box<dyn RuleMatcher> {
    match rule_type {
        RuleType::Domain { domain, target } => {
            Box::new(Domain { domain, target }) as Box<dyn RuleMatcher>
        }
        RuleType::DomainSuffix {
            domain_suffix,
            target,
        } => Box::new(DomainSuffix {
            suffix: domain_suffix,
            target,
        }),
        RuleType::DomainKeyword {
            domain_keyword,
            target,
        } => Box::new(DomainKeyword {
            keyword: domain_keyword,
            target,
        }),
        RuleType::GeoIP {
            target,
            country_code,
            no_resolve,
        } => Box::new(rules::geoip::GeoIP {
            target,
            country_code,
            no_resolve,
            mmdb: mmdb.clone(),
        }),
        RuleType::GeoSite {
            target,
            country_code,
        } => Box::new(
            rules::geodata::GeoSiteMatcher::new(
                country_code,
                target,
                geodata.as_ref(),
            )
            .unwrap_or_else(|err| {
                print_and_exit!("failed to initialize GEOSITE rule: {err}")
            }),
        ),
        RuleType::IpCidr {
            ipnet,
            target,
            no_resolve,
            ..
        } => Box::new(IpCidr {
            ipnet,
            target,
            no_resolve,
        }),

        RuleType::Match { target } => Box::new(Final { target }),
    }
}
