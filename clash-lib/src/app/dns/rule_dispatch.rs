use std::sync::{Arc, OnceLock, Weak};

use crate::app::{outbound::manager::OutboundManager, router::Router};

/// Late-bound reference to `Router`. Populated by `lib.rs` after the router
/// is constructed; the DNS resolver itself is built earlier.
///
/// The reference is weak so the resolver and its DNS clients do not retain an
/// entire router across reloads. `DnsRuntimeProvider` falls back to its
/// bootstrap outbound when the router has already been dropped.
pub type PendingRouter = Arc<OnceLock<Weak<Router>>>;

/// Late-bound reference to `OutboundManager`. Populated by `lib.rs` after the
/// outbound manager is constructed.
pub type PendingOutboundManager = Arc<OnceLock<Weak<OutboundManager>>>;

/// Bundle of late-bound handles consulted by `DnsRuntimeProvider` when
/// `dns.respect-rules` is enabled, allowing upstream DNS dials to be routed
/// through the rule engine.
///
/// Both `OnceLock`s start empty and are filled exactly once during startup.
/// Until both are set, callers fall back to the static `outbound` handler;
/// this keeps early DNS lookups working before the rule engine exists.
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
