use std::sync::Arc;

use async_trait::async_trait;

use crate::Error;

#[async_trait]
pub trait SelectorControl {
    async fn select(&self, name: &str) -> Result<(), Error>;
    #[cfg(test)]
    async fn current(&self) -> String;
}

pub type ThreadSafeSelectorControl = Arc<dyn SelectorControl + Send + Sync>;
