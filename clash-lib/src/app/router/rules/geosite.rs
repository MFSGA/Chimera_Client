use std::fmt::{Display, Formatter};

use crate::{
    Error,
    app::router::RuleMatcher,
    common::{
        geodata::{
            GeoDataLookup,
            geodata_proto::{Domain, domain::Type},
        },
        trie,
    },
    session::{Session, SocksAddr},
};

enum DomainMatcher {
    Plain(String),
    Domain(String),
    Full(String),
    Regex(regex::Regex),
}

impl DomainMatcher {
    fn matches(&self, domain: &str) -> bool {
        match self {
            Self::Plain(pattern) => domain.contains(pattern),
            Self::Domain(pattern) => {
                if !domain.ends_with(pattern) {
                    return false;
                }

                if domain.len() == pattern.len() {
                    return true;
                }

                let boundary = domain.len() - pattern.len() - 1;
                domain.as_bytes().get(boundary) == Some(&b'.')
            }
            Self::Full(pattern) => domain == pattern,
            Self::Regex(pattern) => pattern.is_match(domain),
        }
    }
}

fn parse_geosite(raw: &str) -> Result<(bool, String, Vec<String>), Error> {
    let raw = raw.trim().to_lowercase();
    if raw.is_empty() {
        return Err(Error::InvalidConfig(
            "invalid geosite matcher, country code is empty".to_string(),
        ));
    }

    let (not, raw) = if let Some(rest) = raw.strip_prefix('!') {
        (true, rest)
    } else {
        (false, raw.as_str())
    };

    let mut parts = raw.split('@');
    let code = parts.next().unwrap_or_default().to_string();
    let attrs = parts
        .next()
        .map(|attrs| {
            attrs
                .split(',')
                .map(str::trim)
                .filter(|attr| !attr.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Ok((not, code, attrs))
}

fn matches_attributes(domain: &Domain, attrs: &[String]) -> bool {
    attrs.iter().all(|attr| {
        domain
            .attribute
            .iter()
            .any(|candidate| candidate.key.eq_ignore_ascii_case(attr))
    })
}

pub struct GeoSiteMatcher {
    country_code: String,
    target: String,
    succinct: trie::StringTrie<()>,
    other_matchers: Vec<DomainMatcher>,
    not: bool,
}

impl GeoSiteMatcher {
    pub fn new(
        country_code: String,
        target: String,
        loader: Option<&GeoDataLookup>,
    ) -> Result<Self, Error> {
        let (not, code, attrs) = parse_geosite(&country_code)?;
        let list = loader
            .ok_or_else(|| {
                Error::InvalidConfig(
                    "GeoDataLookup is not available. Maybe config.geosite is not set?"
                        .to_string(),
                )
            })?
            .get(&code)
            .ok_or_else(|| {
                Error::InvalidConfig(format!(
                    "geosite matcher, country code {code} not found"
                ))
            })?;

        let mut succinct = trie::StringTrie::new();
        let mut other_matchers = Vec::new();

        for domain in list
            .domain
            .into_iter()
            .filter(|domain| matches_attributes(domain, &attrs))
        {
            let kind = Type::try_from(domain.r#type).map_err(|error| {
                Error::InvalidConfig(format!("invalid geosite domain type: {error}"))
            })?;

            match kind {
                Type::Plain => {
                    other_matchers.push(DomainMatcher::Plain(domain.value))
                }
                Type::Regex => other_matchers.push(DomainMatcher::Regex(
                    regex::Regex::new(&domain.value).map_err(|error| {
                        Error::InvalidConfig(format!(
                            "invalid geosite regex: {error}"
                        ))
                    })?,
                )),
                Type::Domain => {
                    let trie_key = format!("+.{}", domain.value);
                    succinct.insert(&trie_key, std::sync::Arc::new(()));
                    other_matchers.push(DomainMatcher::Domain(domain.value));
                }
                Type::Full => {
                    succinct.insert(&domain.value, std::sync::Arc::new(()));
                    other_matchers.push(DomainMatcher::Full(domain.value));
                }
            }
        }

        Ok(Self {
            country_code,
            target,
            succinct,
            other_matchers,
            not,
        })
    }
}

impl Display for GeoSiteMatcher {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "GeoSite({})", self.country_code)
    }
}

impl RuleMatcher for GeoSiteMatcher {
    fn apply(&self, sess: &Session) -> bool {
        let matched = match &sess.destination {
            SocksAddr::Ip(_) => false,
            SocksAddr::Domain(domain, _) => {
                self.succinct.search(domain).is_some()
                    || self
                        .other_matchers
                        .iter()
                        .any(|matcher| matcher.matches(domain))
            }
        };

        if self.not { !matched } else { matched }
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn payload(&self) -> String {
        self.country_code.clone()
    }

    fn type_name(&self) -> &str {
        "GeoSite"
    }
}
