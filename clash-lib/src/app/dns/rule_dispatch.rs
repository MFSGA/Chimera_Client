use std::sync::{Arc, OnceLock};

use crate::app::{
    outbound::manager::ThreadSafeOutboundManager, router::ThreadSafeRouter,
};

/// Late-bound reference to `Router`. Populated after the DNS resolver is built.
pub type PendingRouter = Arc<OnceLock<ThreadSafeRouter>>;

/// Late-bound reference to `OutboundManager`. Populated after outbound manager
/// construction.
pub type PendingOutboundManager = Arc<OnceLock<ThreadSafeOutboundManager>>;

/// Handles used by `DnsRuntimeProvider` when `dns.respect-rules` is enabled.
/// They start empty and fall back to the static DNS outbound until populated.
pub struct RuleDispatch {
    pub router: PendingRouter,
    pub outbound_manager: PendingOutboundManager,
}

impl RuleDispatch {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            router: Arc::new(OnceLock::new()),
            outbound_manager: Arc::new(OnceLock::new()),
        })
    }
}
