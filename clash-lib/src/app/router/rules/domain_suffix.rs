use crate::session;

use super::RuleMatcher;

#[derive(Clone)]
pub struct DomainSuffix {
    pub suffix: String,
    pub target: String,
}

impl std::fmt::Display for DomainSuffix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} suffix {}", self.target, self.suffix)
    }
}

impl RuleMatcher for DomainSuffix {
    fn payload(&self) -> String {
        self.suffix.clone()
    }

    fn apply(&self, sess: &session::Session) -> bool {
        match &sess.destination {
            session::SocksAddr::Ip(_) => false,
            session::SocksAddr::Domain(domain, _) => {
                domain.ends_with((String::from(".") + self.suffix.as_str()).as_str())
                    || domain == &self.suffix
            }
        }
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn type_name(&self) -> &str {
        "DomainSuffix"
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        app::router::rules::RuleMatcher,
        session::{Session, SocksAddr},
    };

    use super::DomainSuffix;

    #[test]
    fn matches_exact_domain() {
        let rule = DomainSuffix {
            suffix: "example.com".to_string(),
            target: "PROXY".to_string(),
        };
        let sess = Session {
            destination: SocksAddr::Domain("example.com".to_string(), 443),
            ..Default::default()
        };

        assert!(rule.apply(&sess));
    }

    #[test]
    fn matches_subdomain() {
        let rule = DomainSuffix {
            suffix: "example.com".to_string(),
            target: "PROXY".to_string(),
        };
        let sess = Session {
            destination: SocksAddr::Domain("a.example.com".to_string(), 443),
            ..Default::default()
        };

        assert!(rule.apply(&sess));
    }

    #[test]
    fn does_not_match_boundary_violation() {
        let rule = DomainSuffix {
            suffix: "example.com".to_string(),
            target: "PROXY".to_string(),
        };
        let sess = Session {
            destination: SocksAddr::Domain("badexample.com".to_string(), 443),
            ..Default::default()
        };

        assert!(!rule.apply(&sess));
    }

    #[test]
    fn does_not_match_ip_destination() {
        let rule = DomainSuffix {
            suffix: "example.com".to_string(),
            target: "PROXY".to_string(),
        };
        let sess = Session {
            destination: SocksAddr::Ip(([1, 1, 1, 1], 443).into()),
            ..Default::default()
        };

        assert!(!rule.apply(&sess));
    }
}
