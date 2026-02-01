use std::fmt::Display;

use crate::Session;

pub mod domain;

pub mod final_;

pub mod geodata;

pub trait RuleMatcher: Send + Sync + Unpin + Display {
    /// check if the rule should apply to the session
    fn apply(&self, sess: &Session) -> bool;

    /// the Proxy to use
    fn target(&self) -> &str;

    /// the actual content of the rule
    fn payload(&self) -> String;

    /// the type of the rule
    fn type_name(&self) -> &str;

    fn should_resolve_ip(&self) -> bool {
        false
    }
}
