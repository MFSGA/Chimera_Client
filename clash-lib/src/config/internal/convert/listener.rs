use std::collections::HashSet;
use tracing::{debug, warn};

use crate::config::{
    def::{self, Port},
    internal::{
        config::BindAddress,
        listener::{CommonInboundOpts, InboundOpts},
    },
};

/// combines the top-level config and config.listeners to a set of inbound
/// options.
pub(super) fn convert(
    raw: Option<Vec<InboundOpts>>,
    c: &def::Config,
) -> Result<HashSet<InboundOpts>, crate::Error> {
    #[cfg(feature = "http_port")]
    let http_port = c.port;
    let socks_port = c.socks_port;
    #[cfg(feature = "mixed_port")]
    let mixed_port = c.mixed_port;
    let bind_address = if c.bind_address == BindAddress::default() && c.ipv6 {
        BindAddress::dual_stack()
    } else {
        c.bind_address
    };

    let inbounds = raw.unwrap_or_default().into_iter().collect::<Vec<_>>();

    let mut all_inbounds = HashSet::new();
    for inbound in inbounds {
        if all_inbounds.contains(&inbound) {
            warn!("Duplicate inbound listener found: {:?}", inbound);
            continue;
        }
        all_inbounds.insert(inbound);
    }

    #[cfg(feature = "http_port")]
    debug!("todo HTTP Port:");
    #[cfg(feature = "http_port")]
    if let Some(Port(http_port)) = http_port
        && !all_inbounds.insert(InboundOpts::Http {
            common_opts: CommonInboundOpts {
                name: "HTTP-IN".into(),
                listen: bind_address,
                port: http_port,
                allow_lan: c.allow_lan.unwrap_or_default(),
                fw_mark: c.routing_mark,
            },
        })
    {
        warn!("Duplicate HTTP inbound listener found: {}", http_port);
    }
    #[cfg(not(feature = "http_port"))]
    if c.port.is_some() {
        warn!("ignoring top-level `port` because `http_port` feature is disabled");
    }

    if let Some(Port(socks_port)) = socks_port
        && !all_inbounds.insert(InboundOpts::Socks {
            common_opts: CommonInboundOpts {
                name: "SOCKS-IN".into(),
                listen: bind_address,
                port: socks_port,
                allow_lan: c.allow_lan.unwrap_or_default(),
                fw_mark: c.routing_mark,
            },
            udp: true,
        })
    {
        warn!("Duplicate SOCKS inbound listener found: {}", socks_port);
    }

    debug!("todo Mixed Port: ");
    #[cfg(feature = "mixed_port")]
    if let Some(Port(mixed_port)) = mixed_port
        && !all_inbounds.insert(InboundOpts::Mixed {
            common_opts: CommonInboundOpts {
                name: "MIXED-IN".into(),
                listen: bind_address,
                port: mixed_port,
                allow_lan: c.allow_lan.unwrap_or_default(),
                fw_mark: c.routing_mark,
            },
            udp: true,
        })
    {
        warn!("Duplicate MIXED inbound listener found: {}", mixed_port);
    }
    #[cfg(not(feature = "mixed_port"))]
    if c.mixed_port.is_some() {
        warn!(
            "ignoring top-level `mixed-port` because `mixed_port` feature is disabled"
        );
    }
    if c.redir_port.is_some() {
        warn!(
            "ignoring top-level `redir-port` because redir inbound is not implemented"
        );
    }
    if c.tproxy_port.is_some() {
        warn!(
            "ignoring top-level `tproxy-port` because tproxy inbound is not implemented"
        );
    }
    Ok(all_inbounds)
}
