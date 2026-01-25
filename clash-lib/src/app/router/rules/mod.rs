use std::fmt::Display;

use crate::Session;

pub mod domain;

pub mod final_;

pub trait RuleMatcher: Send + Sync + Unpin + Display {
    /// the Proxy to use
    fn target(&self) -> &str;

    /// check if the rule should apply to the session
    fn apply(&self, sess: &Session) -> bool;

    /// the type of the rule
    fn type_name(&self) -> &str;
}
