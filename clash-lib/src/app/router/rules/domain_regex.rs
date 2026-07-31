use crate::{
    app::router::rules::RuleMatcher,
    session::{Session, SocksAddr},
};

#[derive(Clone)]
pub struct DomainRegex {
    pub regex: regex::Regex,
    pub target: String,
}

impl std::fmt::Display for DomainRegex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} regex {}", self.target, self.regex)
    }
}

impl RuleMatcher for DomainRegex {
    fn target(&self) -> &str {
        &self.target
    }

    fn payload(&self) -> String {
        self.regex.to_string()
    }

    fn apply(&self, session: &Session) -> bool {
        match &session.destination {
            SocksAddr::Domain(domain, _) => self.regex.is_match(domain),
            SocksAddr::Ip(_) => false,
        }
    }

    fn type_name(&self) -> &str {
        "DomainRegex"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_domains_but_not_ip_destinations() {
        let rule = DomainRegex {
            regex: regex::Regex::new(r"^api\d+\.example\.com$").unwrap(),
            target: "PROXY".to_string(),
        };
        let domain = Session {
            destination: SocksAddr::Domain("api12.example.com".to_string(), 443),
            ..Default::default()
        };
        assert!(rule.apply(&domain));
        assert!(!rule.apply(&Session {
            destination: SocksAddr::Domain("www.example.com".to_string(), 443),
            ..Default::default()
        }));
        assert!(!rule.apply(&Session {
            destination: SocksAddr::Ip("127.0.0.1:443".parse().unwrap()),
            ..Default::default()
        }));
    }
}
