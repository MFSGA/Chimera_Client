mod rules;

use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

pub use rules::RuleMatcher;
use tracing::{error, info, trace};

use crate::{
    Session,
    app::{
        dns::ThreadSafeDNSResolver,
        remote_content_manager::providers::{
            file_vehicle, http_vehicle,
            rule_provider::{RuleProviderImpl, ThreadSafeRuleProvider},
        },
        router::rules::{
            domain::Domain, domain_keyword::DomainKeyword,
            domain_suffix::DomainSuffix, final_::Final, ipcidr::IpCidr,
            ruleset::RuleSet,
        },
    },
    common::{geodata::GeoDataLookup, mmdb::MmdbLookup},
    config::internal::{config::RuleProviderDef, rule::RuleType},
    print_and_exit,
};

const MATCH: &str = "MATCH";

pub struct Router {
    rules: Vec<Box<dyn RuleMatcher>>,
    dns_resolver: ThreadSafeDNSResolver,
    // kept aligned with clash-rs matcher flow
    country_mmdb: Option<MmdbLookup>,
    asn_mmdb: Option<MmdbLookup>,
    rule_providers: HashMap<String, ThreadSafeRuleProvider>,
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
        rule_providers: HashMap<String, RuleProviderDef>,
        dns_resolver: ThreadSafeDNSResolver,
        country_mmdb: Option<MmdbLookup>,
        asn_mmdb: Option<MmdbLookup>,
        geodata: Option<GeoDataLookup>,
        cwd: String,
    ) -> Self {
        let mut rule_provider_registry = HashMap::new();
        Self::load_rule_providers(
            rule_providers,
            &mut rule_provider_registry,
            dns_resolver.clone(),
            country_mmdb.clone(),
            geodata.clone(),
            cwd,
        )
        .await
        .ok();

        Self {
            rules: rules
                .into_iter()
                .map(|r| {
                    map_rule_type(
                        r,
                        country_mmdb.clone(),
                        geodata.clone(),
                        Some(&rule_provider_registry),
                    )
                })
                .collect(),
            dns_resolver,
            country_mmdb,
            asn_mmdb,
            rule_providers: rule_provider_registry,
        }
    }

    pub fn get_rule_providers(&self) -> &HashMap<String, ThreadSafeRuleProvider> {
        &self.rule_providers
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

            if let Some(ip) = sess.resolved_ip.or(sess.destination.ip()) {
                Self::populate_geo_for_ip(
                    ip,
                    &self.country_mmdb,
                    &self.asn_mmdb,
                    sess,
                );
            }

            if r.apply(sess) {
                let process = sess.process_name.as_deref().unwrap_or("<unknown>");
                if let Some(host) = sess.destination.domain()
                    && self.dns_resolver.fake_ip_enabled()
                {
                    match self.dns_resolver.fake_ip_for_host(host).await {
                        Some(fake_ip) => info!(
                            "matched {} process={} fake_ip={} reused=true to target {}[{}]",
                            &sess,
                            process,
                            fake_ip,
                            r.target(),
                            r.type_name()
                        ),
                        None => info!(
                            "matched {} process={} fake_ip=<none> reused=false to target {}[{}]",
                            &sess,
                            process,
                            r.target(),
                            r.type_name()
                        ),
                    }
                } else {
                    info!(
                        "matched {} process={} to target {}[{}]",
                        &sess,
                        process,
                        r.target(),
                        r.type_name()
                    );
                }
                return (r.target(), Some(r));
            }
        }

        (MATCH, None)
    }

    /// Look up country code and ASN for an IP address.
    fn populate_geo_for_ip(
        ip: std::net::IpAddr,
        country_mmdb: &Option<MmdbLookup>,
        asn_mmdb: &Option<MmdbLookup>,
        sess: &mut Session,
    ) {
        if sess.country.is_some() && sess.asn.is_some() {
            return;
        }

        if sess.country.is_none()
            && let Some(country_mmdb) = country_mmdb
        {
            match country_mmdb.lookup_country(ip) {
                Ok(country) => {
                    trace!("country for {} is {:?}", ip, country.country_code);
                    sess.country = Some(country.country_code);
                }
                Err(e) => {
                    trace!("failed to lookup country for {}: {}", ip, e);
                }
            }
        }

        if sess.asn.is_none()
            && let Some(asn_mmdb) = asn_mmdb
        {
            if let Ok(country) = asn_mmdb.lookup_country(ip) {
                sess.asn = Some(country.country_code);
                return;
            }

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

    async fn load_rule_providers(
        rule_providers: HashMap<String, RuleProviderDef>,
        rule_provider_registry: &mut HashMap<String, ThreadSafeRuleProvider>,
        resolver: ThreadSafeDNSResolver,
        mmdb: Option<MmdbLookup>,
        geodata: Option<GeoDataLookup>,
        cwd: String,
    ) -> Result<(), crate::Error> {
        for (name, provider) in rule_providers.into_iter() {
            match provider {
                RuleProviderDef::Http(http) => {
                    let vehicle = http_vehicle::Vehicle::new(
                        http.url.parse::<hyper::Uri>().unwrap_or_else(|_| {
                            print_and_exit!("invalid provider url: {}", http.url)
                        }),
                        http.path,
                        Some(cwd.clone()),
                        resolver.clone(),
                    );
                    let provider = RuleProviderImpl::new(
                        name.clone(),
                        http.behavior,
                        http.format.unwrap_or_default(),
                        Some(Duration::from_secs(http.interval)),
                        Some(Arc::new(vehicle)),
                        mmdb.clone(),
                        geodata.clone(),
                        http.inline_rules,
                    );
                    rule_provider_registry.insert(name, Arc::new(provider));
                }
                RuleProviderDef::File(file) => {
                    let vehicle = file_vehicle::Vehicle::new(
                        PathBuf::from(cwd.clone())
                            .join(&file.path)
                            .to_str()
                            .unwrap(),
                    );
                    let provider = RuleProviderImpl::new(
                        name.clone(),
                        file.behavior,
                        file.format.unwrap_or_default(),
                        Some(Duration::from_secs(file.interval.unwrap_or_default())),
                        Some(Arc::new(vehicle)),
                        mmdb.clone(),
                        geodata.clone(),
                        file.inline_rules,
                    );
                    rule_provider_registry.insert(name, Arc::new(provider));
                }
                RuleProviderDef::Inline(inline) => {
                    let provider = RuleProviderImpl::new(
                        name.clone(),
                        inline.behavior,
                        Default::default(),
                        None,
                        None,
                        mmdb.clone(),
                        geodata.clone(),
                        Some(inline.inline_rules),
                    );
                    rule_provider_registry.insert(name, Arc::new(provider));
                }
            }
        }

        for provider in rule_provider_registry.values() {
            let provider = provider.clone();
            tokio::spawn(async move {
                info!("initializing rule provider {}", provider.name());
                match provider.initialize().await {
                    Ok(()) => info!("rule provider {} initialized", provider.name()),
                    Err(err) => error!(
                        "failed to initialize rule provider {}: {}",
                        provider.name(),
                        err
                    ),
                }
            });
        }

        Ok(())
    }
}

pub fn map_rule_type(
    rule_type: RuleType,
    mmdb: Option<MmdbLookup>,
    geodata: Option<GeoDataLookup>,
    rule_provider_registry: Option<&HashMap<String, ThreadSafeRuleProvider>>,
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
        RuleType::RuleSet { rule_set, target } => match rule_provider_registry {
            Some(rule_provider_registry) => Box::new(RuleSet::new(
                rule_set.clone(),
                target,
                rule_provider_registry
                    .get(&rule_set)
                    .unwrap_or_else(|| {
                        print_and_exit!("rule provider {} not found", rule_set)
                    })
                    .clone(),
            )),
            None => {
                unreachable!("rule-set cannot be nested inside another rule-set")
            }
        },

        RuleType::Match { target } => Box::new(Final { target }),
    }
}
