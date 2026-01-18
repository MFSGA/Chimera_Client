use thiserror::Error;

use crate::{DNSListenAddr, DnsMessageExchanger};

#[derive(Error, Debug)]
pub enum DNSError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /* #[error("invalid OP code: {0}")]
    InvalidOpQuery(String),
    #[error("query failed: {0}")]
    QueryFailed(String), */
}

pub async fn get_dns_listener<X>(
    listen: DNSListenAddr,
    exchanger: X,
    cwd: &std::path::Path,
) -> Option<futures::future::BoxFuture<'static, Result<(), DNSError>>>
where
    X: DnsMessageExchanger + Sync + Send + Unpin + 'static,
{
    todo!()
}
