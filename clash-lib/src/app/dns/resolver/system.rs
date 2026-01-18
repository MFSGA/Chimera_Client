use std::sync::atomic::AtomicBool;

use tracing::debug;


pub struct SystemResolver {
    ipv6: AtomicBool,
}

/// SystemResolver is a resolver that uses libc getaddrinfo to resolve
/// hostnames.
impl SystemResolver {
    pub fn new(ipv6: bool) -> anyhow::Result<Self> {
        debug!("creating system resolver with ipv6={}", ipv6);
        Ok(Self {
            ipv6: AtomicBool::new(ipv6),
        })
    }
}