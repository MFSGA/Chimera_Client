use hickory_proto::op::Message;
use tracing::debug;

use crate::app::dns::ThreadSafeDNSResolver;

pub async fn exchange_with_resolver(
    resolver: &ThreadSafeDNSResolver,
    req: &Message,
    _enhanced: bool,
) -> Result<Message, chimera_dns::DNSError> {
    tracing::debug!("dns resolve request, enhanced={}", _enhanced);
    match resolver.exchange(req).await {
        Ok(m) => Ok(m),
        Err(e) => {
            debug!("dns resolve error: {}", e);
            Err(chimera_dns::DNSError::Io(std::io::Error::other(
                e.to_string(),
            )))
        }
    }
}
