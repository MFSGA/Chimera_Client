use std::{
    fmt::{Display, Formatter},
    sync::Arc,
};

use crate::{
    Error,
    Session,
    app::router::RuleMatcher,
    common::{
        geodata::{
            GeoDataLookup,
            geodata_proto::{Domain, domain::Type},
        },
        trie::StringTrie,
    },
};

pub struct GeoSiteMatcher {
    country_code: String,
    target: String,
    set: StringTrie<()>,
    regexes: Vec<regex::Regex>,
    keywords: Vec<String>,
    not: bool,
}

impl GeoSiteMatcher {
    pub fn new(
        country_code: String,
        target: String,
        loader: Option<&GeoDataLookup>,
    ) -> Result<Self, Error> {
        let (not, code, attrs) = parse_country_code(&country_code)?;
        let list = loader
            .ok_or_else(|| {
                Error::InvalidConfig(
                    "config.geosite is required for GEOSITE rules".to_string(),
                )
            })?
            .get(&code)
            .ok_or_else(|| {
                Error::InvalidConfig(format!(
                    "geosite matcher, country code {code} not found"
                ))
            })?;

        let mut set = StringTrie::new();
        let mut regexes = Vec::new();
        let mut keywords = Vec::new();

        for domain in list
            .domain
            .into_iter()
            .filter(|domain| matches_attrs(domain, &attrs))
        {
            match Type::try_from(domain.r#type).map_err(|err| {
                Error::InvalidConfig(format!("invalid geosite domain type: {err}"))
            })? {
                Type::Domain => {
                    set.insert(&format!("+.{}", domain.value), Arc::new(()));
                }
                Type::Full => {
                    set.insert(&domain.value, Arc::new(()));
                }
                Type::Plain => keywords.push(domain.value),
                Type::Regex => regexes.push(
                    regex::Regex::new(&domain.value).map_err(|err| {
                        Error::InvalidConfig(format!("invalid geosite regex: {err}"))
                    })?,
                ),
            }
        }

        Ok(Self {
            country_code,
            target,
            set,
            regexes,
            keywords,
            not,
        })
    }
}

impl RuleMatcher for GeoSiteMatcher {
    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn payload(&self) -> String {
        self.country_code.clone()
    }

    fn apply(&self, sess: &Session) -> bool {
        let matched = match &sess.destination {
            crate::session::SocksAddr::Ip(_) => false,
            crate::session::SocksAddr::Domain(domain, _) => {
                self.set.search(domain).is_some()
                    || self.keywords.iter().any(|keyword| domain.contains(keyword))
                    || self.regexes.iter().any(|regex| regex.is_match(domain))
            }
        };

        if self.not { !matched } else { matched }
    }

    fn type_name(&self) -> &str {
        "GeoSite"
    }
}

impl Display for GeoSiteMatcher {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "GeoSite({})", self.country_code)
    }
}

fn parse_country_code(country_code: &str) -> Result<(bool, String, Vec<String>), Error> {
    let country_code = country_code.trim().to_lowercase();
    if country_code.is_empty() {
        return Err(Error::InvalidConfig(
            "invalid geosite matcher, country code is empty".to_string(),
        ));
    }

    let (not, body) = if let Some(rest) = country_code.strip_prefix('!') {
        (true, rest)
    } else {
        (false, country_code.as_str())
    };
    let mut parts = body.split('@');
    let code = parts.next().unwrap_or_default().to_string();
    let attrs = parts
        .next()
        .map(|attrs| {
            attrs
                .split(',')
                .map(|attr| attr.trim().to_string())
                .filter(|attr| !attr.is_empty())
                .collect()
        })
        .unwrap_or_default();

    Ok((not, code, attrs))
}

fn matches_attrs(domain: &Domain, attrs: &[String]) -> bool {
    attrs.iter().all(|attr| {
        domain
            .attribute
            .iter()
            .any(|candidate| candidate.key.eq_ignore_ascii_case(attr))
    })
}
