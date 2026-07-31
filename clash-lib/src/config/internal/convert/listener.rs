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
    #[cfg(feature = "redir")]
    if let Some(Port(redir_port)) = c.redir_port
        && !all_inbounds.insert(InboundOpts::Redir {
            common_opts: CommonInboundOpts {
                name: "REDIR-IN".into(),
                listen: bind_address,
                port: redir_port,
                allow_lan: c.allow_lan.unwrap_or_default(),
                fw_mark: c.routing_mark,
            },
        })
    {
        warn!("Duplicate REDIR inbound listener found: {}", redir_port);
    }
    #[cfg(not(feature = "redir"))]
    if c.redir_port.is_some() {
        warn!("ignoring top-level `redir-port` because `redir` feature is disabled");
    }
    #[cfg(feature = "tproxy")]
    if let Some(Port(tproxy_port)) = c.tproxy_port
        && !all_inbounds.insert(InboundOpts::Tproxy {
            common_opts: CommonInboundOpts {
                name: "TPROXY-IN".into(),
                listen: bind_address,
                port: tproxy_port,
                allow_lan: c.allow_lan.unwrap_or_default(),
                fw_mark: c.routing_mark,
            },
        })
    {
        warn!("Duplicate TPROXY inbound listener found: {}", tproxy_port);
    }
    #[cfg(not(feature = "tproxy"))]
    if c.tproxy_port.is_some() {
        warn!(
            "ignoring top-level `tproxy-port` because `tproxy` feature is disabled"
        );
    }
    Ok(all_inbounds)
}

#[cfg(all(test, any(feature = "redir", feature = "tproxy")))]
mod tests {
    use super::*;

    #[cfg(feature = "redir")]
    #[test]
    fn top_level_redir_port_builds_listener() {
        let config = def::Config {
            redir_port: Some(Port(7892)),
            allow_lan: Some(true),
            routing_mark: Some(123),
            ..Default::default()
        };

        let inbounds = convert(None, &config).unwrap();
        let redir = inbounds
            .iter()
            .find(|inbound| matches!(inbound, InboundOpts::Redir { .. }))
            .expect("redir listener should be created");
        let common = redir.common_opts();
        assert_eq!(common.name, "REDIR-IN");
        assert_eq!(common.port, 7892);
        assert!(common.allow_lan);
        assert_eq!(common.fw_mark, Some(123));
    }

    #[cfg(feature = "tproxy")]
    #[test]
    fn top_level_tproxy_port_builds_listener() {
        let config = def::Config {
            tproxy_port: Some(Port(7893)),
            allow_lan: Some(true),
            routing_mark: Some(124),
            ..Default::default()
        };

        let inbounds = convert(None, &config).unwrap();
        let tproxy = inbounds
            .iter()
            .find(|inbound| matches!(inbound, InboundOpts::Tproxy { .. }))
            .expect("tproxy listener should be created");
        let common = tproxy.common_opts();
        assert_eq!(common.name, "TPROXY-IN");
        assert_eq!(common.port, 7893);
        assert!(common.allow_lan);
        assert_eq!(common.fw_mark, Some(124));
    }
}
