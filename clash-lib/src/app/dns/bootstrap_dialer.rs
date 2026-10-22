//! S04b-j: read-only, fail-closed proof of the *installed* dialer-proxy
//! relationship for a selected strict-DNS leaf.
//!
//! OutboundManager currently wires each named dialer as ProxyConnector(proxy,
//! DirectConnector). It does NOT recursively install the named dialer's own
//! connector, so claiming multi-hop protection would be unsafe. Reject nested
//! dialers, dynamic group hops, and unpinned hostnames until a real end-to-end
//! path-attested connector exists. Nothing in this module authorizes dialing.

use std::{collections::HashMap, io, net::IpAddr, sync::Arc};

use tokio::sync::OwnedRwLockReadGuard;

use crate::{
    app::outbound::manager::OutboundManager,
    proxy::{AnyOutboundHandler, OutboundType, utils::OutboundHandlerRegistry},
};

/// Holds an owned read lock over the *real* manager registry for exactly one
/// internal DNS exchange. A concurrent rebind waits until this lease drops;
/// unlike before/after lookups, A -> B -> A cannot occur during the lease.
/// Do not use around production I/O without an explicit contention review.
pub(crate) struct StrictDnsConnectorLease {
    entries: OwnedRwLockReadGuard<HashMap<String, AnyOutboundHandler>>,
}

#[derive(Debug)]
pub(crate) struct StrictDnsConnectorChain {
    selected: AnyOutboundHandler,
    hop: Option<(String, AnyOutboundHandler)>,
}

impl StrictDnsConnectorChain {
    fn require_literal_proxy(proxy: &AnyOutboundHandler) -> io::Result<()> {
        if matches!(
            proxy.proto(),
            OutboundType::Direct
                | OutboundType::Reject
                | OutboundType::Selector
                | OutboundType::Fallback
                | OutboundType::UrlTest
                | OutboundType::Smart
                | OutboundType::LoadBalance
                | OutboundType::Relay
        ) || proxy.try_as_group_handler().is_some()
        {
            return Err(io::Error::other(format!(
                "strict DNS connector '{}' is not a fixed proxy leaf",
                proxy.name(),
            )));
        }
        let host = proxy.server_name().ok_or_else(|| {
            io::Error::other(format!(
                "strict DNS connector '{}' has no verifiable endpoint",
                proxy.name(),
            ))
        })?;
        if host.parse::<IpAddr>().is_err() {
            return Err(io::Error::other(format!(
                "strict DNS connector '{}' needs independently trusted bootstrap for '{host}'",
                proxy.name(),
            )));
        }
        Ok(())
    }

    pub(crate) async fn capture(
        manager: &Arc<OutboundManager>,
        registry: &OutboundHandlerRegistry,
        selected: &AnyOutboundHandler,
    ) -> io::Result<Self> {
        if !manager.owns_outbound_registry(registry) {
            return Err(io::Error::other(
                "strict DNS connector registry does not belong to selected manager",
            ));
        }
        Self::require_literal_proxy(selected)?;
        let hop = if let Some(via) = selected.support_dialer() {
            if via == selected.name() {
                return Err(io::Error::other(
                    "strict DNS connector dependency cycles back to selected leaf",
                ));
            }
            let handler = manager.get_outbound(via).await.ok_or_else(|| {
                io::Error::other(format!(
                    "strict DNS connector dependency '{via}' missing from manager registry",
                ))
            })?;
            Self::require_literal_proxy(&handler)?;
            if handler.support_dialer().is_some() {
                return Err(io::Error::other(format!(
                    "strict DNS connector '{via}' has nested dialer-proxy; chain is not installed transitively",
                )));
            }
            Some((via.to_owned(), handler))
        } else {
            None
        };
        let chain = Self {
            selected: selected.clone(),
            hop,
        };
        chain.ensure_current(manager, registry, selected).await?;
        Ok(chain)
    }

    /// Acquire the actual registry's read lock, checking the saved hop under
    /// the same lock. Writers cannot swap handlers after this until drop.
    pub(crate) async fn lease_for_exchange(
        &self,
        manager: &Arc<OutboundManager>,
        registry: &OutboundHandlerRegistry,
        selected: &AnyOutboundHandler,
    ) -> io::Result<StrictDnsConnectorLease> {
        if !manager.owns_outbound_registry(registry) {
            return Err(io::Error::other(
                "strict DNS connector registry does not belong to selected manager",
            ));
        }
        let lease = StrictDnsConnectorLease {
            entries: registry.clone().read_owned().await,
        };
        self.ensure_leased(&lease, selected)?;
        Ok(lease)
    }

    /// Verification never reacquires the RwLock while a lease is held:
    /// reentrant readers can deadlock if a writer is already queued.
    pub(crate) fn ensure_leased(
        &self,
        lease: &StrictDnsConnectorLease,
        selected: &AnyOutboundHandler,
    ) -> io::Result<()> {
        self.verify_entries(&lease.entries, selected)
    }

    fn verify_entries(
        &self,
        entries: &HashMap<String, AnyOutboundHandler>,
        selected: &AnyOutboundHandler,
    ) -> io::Result<()> {
        if !Arc::ptr_eq(selected, &self.selected) {
            return Err(io::Error::other(
                "strict DNS connector owner or selected leaf identity changed",
            ));
        }
        Self::require_literal_proxy(selected)?;
        match (&self.hop, selected.support_dialer()) {
            (None, None) => Ok(()),
            (Some((name, captured)), Some(current_name)) if name == current_name => {
                Self::require_literal_proxy(captured)?;
                if captured.support_dialer().is_some() {
                    return Err(io::Error::other(
                        "strict DNS connector nested dialer-proxy is not permitted",
                    ));
                }
                let current = entries.get(name).ok_or_else(|| {
                    io::Error::other(format!(
                        "strict DNS connector dependency '{name}' disappeared",
                    ))
                })?;
                if !Arc::ptr_eq(current, captured) {
                    return Err(io::Error::other(format!(
                        "strict DNS connector dependency '{name}' identity changed",
                    )));
                }
                Ok(())
            }
            _ => Err(io::Error::other(
                "strict DNS connector dependency changed after capture",
            )),
        }
    }

    /// Compare the *actual* named dialer-handler Arc, not a config string.
    /// Caller must additionally verify provider version and network/config
    /// epochs on both sides of an I/O boundary.
    pub(crate) async fn ensure_current(
        &self,
        manager: &Arc<OutboundManager>,
        registry: &OutboundHandlerRegistry,
        selected: &AnyOutboundHandler,
    ) -> io::Result<()> {
        let lease = self.lease_for_exchange(manager, registry, selected).await?;
        self.ensure_leased(&lease, selected)
    }
}
