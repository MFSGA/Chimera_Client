use crate::session;

use super::RuleMatcher;

#[derive(Clone)]
pub struct Domain {
    pub domain: String,
    pub target: String,
}

impl std::fmt::Display for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} domain {}", self.target, self.domain)
    }
}

impl RuleMatcher for Domain {}
