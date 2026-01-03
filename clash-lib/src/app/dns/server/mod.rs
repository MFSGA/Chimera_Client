use chimera_dns::DNSListenAddr;

use crate::{Runner, app::dns::ThreadSafeDNSResolver};

pub async fn get_dns_listener(
    listen: DNSListenAddr,
    // resolver: ThreadSafeDNSResolver,
    cwd: &std::path::Path,
) -> Option<Runner> {
    todo!()
}
