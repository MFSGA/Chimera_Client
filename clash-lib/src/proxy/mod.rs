use std::{fmt::Debug, sync::Arc};

use async_trait::async_trait;

pub mod direct;

pub mod reject;

#[async_trait]
pub trait OutboundHandler: Sync + Send + Unpin + DialWithConnector + Debug {
    /// The name of the outbound handler
    fn name(&self) -> &str;
}

#[async_trait]
pub trait DialWithConnector {}

pub type AnyOutboundHandler = Arc<dyn OutboundHandler>;
