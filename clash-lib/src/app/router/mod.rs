mod rules;

use std::{collections::HashMap, sync::Arc};

pub use rules::RuleMatcher;
use tracing::{info, trace};

use crate::{
    Error, Session,
    app::{
        dns::ThreadSafeDNSResolver,
        router::rules::{domain::Domain, final_::Final, geodata::GeoSiteMatcher},
    },
    common::geodata::GeoDataLookup,
    common::mmdb::MmdbLookup,
    config::internal::{config::RuleProviderDef, rule::RuleType},
};

const MATCH: &str = "MATCH";

pub struct Router {
    rules: Vec<Box<dyn RuleMatcher>>,
    dns_resolver: ThreadSafeDNSResolver,
    // asn_mmdb: Option<MmdbLookup>,
}

pub type ThreadSafeRouter = Arc<Router>;

impl Router {
    pub async fn new(
        rules: Vec<RuleType>,
        // rule_providers: HashMap<String, RuleProviderDef>,
        dns_resolver: ThreadSafeDNSResolver,
        country_mmdb: Option<MmdbLookup>,
        // asn_mmdb: Option<MmdbLookup>,
        geodata: Option<GeoDataLookup>,
        cwd: String,
    ) -> Result<Self, Error> {
        let _ = (country_mmdb, cwd);
        Ok(Self {
            rules: rules
                .into_iter()
                .map(|r| {
                    map_rule_type(
                        r,
                        // country_mmdb.clone(),
                        geodata.clone(),
                        // Some(&rule_provider_registry),
                    )
                })
                .collect::<Result<Vec<_>, Error>>()?,
            dns_resolver,
            // asn_mmdb,
        })
    }

    /// this mutates the session, attaching resolved IP and ASN
    pub async fn match_route(&self, sess: &mut Session) -> (&str, Option<&Box<dyn RuleMatcher>>) {
        let mut sess_resolved = false;

        for r in self.rules.iter() {
            trace!("todo: deal with more scenario");
            /* if sess.destination.is_domain()
                && r.should_resolve_ip()
                && !sess_resolved
                && let Ok(Some(ip)) = self
                    .dns_resolver
                    .resolve(sess.destination.domain().unwrap(), false)
                    .await
            {
                sess.resolved_ip = Some(ip);
                sess_resolved = true;
            }

            let maybe_ip = sess.resolved_ip.or(sess.destination.ip());
            if let (Some(ip), Some(asn_mmdb)) = (maybe_ip, &self.asn_mmdb) {
                // try simplified mmdb first
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
            } */

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
    // mmdb: Option<MmdbLookup>,
    geodata: Option<GeoDataLookup>,
    // rule_provider_registry: Option<&HashMap<String, ThreadSafeRuleProvider>>,
) -> Result<Box<dyn RuleMatcher>, Error> {
    match rule_type {
        RuleType::Domain { domain, target } => {
            Ok(Box::new(Domain { domain, target }) as Box<dyn RuleMatcher>)
        }
        RuleType::GeoSite {
            country_code,
            target,
        } => Ok(
            Box::new(GeoSiteMatcher::new(country_code, target, geodata.as_ref())?)
                as Box<dyn RuleMatcher>,
        ),
        RuleType::Match { target } => Ok(Box::new(Final { target })),
    }
}
