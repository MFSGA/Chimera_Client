//! S04b-j: read-only, fail-closed proof of the *installed* dialer-proxy
//! relationship for a selected strict-DNS leaf.
//!
//! OutboundManager currently wires each named dialer as ProxyConnector(proxy,
//! DirectConnector). It does NOT recursively install the named dialer's own
//! connector, so claiming multi-hop protection would be unsafe. Reject nested
//! dialers, dynamic group hops, and unpinned hostnames until a real end-to-end
//! path-attested connector exists. Nothing in this module authorizes dialing.

use std::{io, net::IpAddr, sync::Arc};

use crate::{
    app::outbound::manager::OutboundManager,
    proxy::{AnyOutboundHandler, OutboundType, utils::OutboundHandlerRegistry},
};

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

    /// Compare the *actual* named dialer-handler Arc, not a config string.
    /// Caller must additionally verify provider version and network/config
    /// epochs on both sides of an I/O boundary.
    pub(crate) async fn ensure_current(
        &self,
        manager: &Arc<OutboundManager>,
        registry: &OutboundHandlerRegistry,
        selected: &AnyOutboundHandler,
    ) -> io::Result<()> {
        if !manager.owns_outbound_registry(registry)
            || !Arc::ptr_eq(selected, &self.selected)
        {
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
                let current = manager.get_outbound(name).await.ok_or_else(|| {
                    io::Error::other(format!(
                        "strict DNS connector dependency '{name}' disappeared",
                    ))
                })?;
                if !Arc::ptr_eq(&current, captured) {
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
}
