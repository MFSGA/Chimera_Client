use hickory_proto::op::Message;
use tracing::debug;

use crate::app::dns::ThreadSafeDNSResolver;

pub async fn exchange_with_resolver(
    resolver: &ThreadSafeDNSResolver,
    req: &Message,
    _enhanced: bool,
) -> Result<Message, chimera_dns::DNSError> {
    tracing::debug!("todo: enhanced dns resolve: {}", _enhanced);
    match resolver.exchange(req).await {
        Ok(m) => Ok(m),
        Err(e) => {
            debug!("dns resolve error: {}", e);
            todo!()
            // Err(chimera_dns::DNSError::QueryFailed(e.to_string()))
        }
    }
}
