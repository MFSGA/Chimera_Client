mod rules;

use std::{collections::HashMap, sync::Arc};

pub use rules::RuleMatcher;

use crate::{
    Session,
    app::dns::ThreadSafeDNSResolver,
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
        // geodata: Option<GeoDataLookup>,
        cwd: String,
    ) -> Self {
        Self {
            rules: rules
                .into_iter()
                .map(|r| {
                    map_rule_type(
                        r,
                        // country_mmdb.clone(),
                        // geodata.clone(),
                        // Some(&rule_provider_registry),
                    )
                })
                .collect(),
            dns_resolver,
            // asn_mmdb,
        }
    }

    /// this mutates the session, attaching resolved IP and ASN
    pub async fn match_route(&self, sess: &mut Session) -> (&str, Option<&Box<dyn RuleMatcher>>) {
        tracing::debug!("todo");
        (MATCH, None)
    }
}

pub fn map_rule_type(
    rule_type: RuleType,
    // mmdb: Option<MmdbLookup>,
    // geodata: Option<GeoDataLookup>,
    // rule_provider_registry: Option<&HashMap<String, ThreadSafeRuleProvider>>,
) -> Box<dyn RuleMatcher> {
    todo!()
}
