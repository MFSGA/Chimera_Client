use std::fmt::Display;

pub trait RuleMatcher: Send + Sync + Unpin + Display {}
