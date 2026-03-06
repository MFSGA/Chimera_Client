use crate::session;

use super::RuleMatcher;

#[derive(Clone)]
pub struct DomainKeyword {
    pub keyword: String,
    pub target: String,
}

impl std::fmt::Display for DomainKeyword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} keyword {}", self.target, self.keyword)
    }
}

impl RuleMatcher for DomainKeyword {
    fn payload(&self) -> String {
        self.keyword.clone()
    }

    fn apply(&self, sess: &session::Session) -> bool {
        match &sess.destination {
            session::SocksAddr::Ip(_) => false,
            session::SocksAddr::Domain(domain, _) => domain.contains(&self.keyword),
        }
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn type_name(&self) -> &str {
        "DomainKeyword"
    }
}
