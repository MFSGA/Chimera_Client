use std::fmt::Display;

pub mod domain;

pub mod final_;

pub trait RuleMatcher: Send + Sync + Unpin + Display {}
