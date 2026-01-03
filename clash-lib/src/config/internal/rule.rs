use std::str::FromStr;

use crate::Error;

/// todo: support more rule type
pub enum RuleType {
    Domain { domain: String, target: String },
}

impl RuleType {
    pub fn target(&self) -> &str {
        match self {
            RuleType::Domain { target, .. } => target,
        }
    }
}

impl FromStr for RuleType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        todo!() // s.to_string().try_into()
    }
}
