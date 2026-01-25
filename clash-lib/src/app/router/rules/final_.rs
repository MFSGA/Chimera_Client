use crate::{app::router::rules::RuleMatcher, session::Session};

#[derive(Clone)]
pub struct Final {
    pub target: String,
}

impl std::fmt::Display for Final {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} final", self.target)
    }
}

impl RuleMatcher for Final {}
