use std::collections::HashMap;

use tracing::warn;

use crate::{
    Error,
    common::auth,
    config::{
        def,
        internal::{
            config::{self, Profile},
            proxy::{
                OutboundDirect, OutboundProxy, OutboundProxyProtocol,
                OutboundReject, PROXY_DIRECT, PROXY_REJECT,
            },
            rule::RuleType,
        },
    },
};

mod general;
/// 3
mod listener;
mod proxy_group;
mod rule_provider;
mod tun;

impl TryFrom<def::Config> for config::Config {
    type Error = crate::Error;

    fn try_from(value: def::Config) -> Result<Self, Self::Error> {
        convert(value)
    }
}

pub(super) fn convert(mut c: def::Config) -> Result<config::Config, crate::Error> {
    let mut proxy_names =
        vec![String::from(PROXY_DIRECT), String::from(PROXY_REJECT)];

    if c.allow_lan.unwrap_or_default() && c.bind_address.is_localhost() {
        warn!(
            "allow-lan is set to true, but bind-address is set to localhost. This \
             will not allow any connections from the local network."
        );
    }
    if let Some(tun) = &mut c.tun {
        match (c.routing_mark, tun.so_mark) {
            (Some(routing_mark), None) => tun.so_mark = Some(routing_mark),
            (None, Some(tun_so_mark)) if tun.enable => {
                c.routing_mark = Some(tun_so_mark);
            }
            _ => {}
        }
    }
    let dns: crate::app::dns::Config = (&c).try_into()?;
    let mut tun = tun::convert(c.tun.take())?;
    validate_dns_tun_ipv6(&dns, &tun)?;
    configure_fake_ip_route(&dns, &mut tun)?;

    config::Config {
        proxies: c.proxy.take().unwrap_or_default().into_iter().try_fold(
            HashMap::from([
                (
                    String::from(PROXY_DIRECT),
                    OutboundProxy::ProxyServer(OutboundProxyProtocol::Direct(
                        OutboundDirect {
                            name: PROXY_DIRECT.to_string(),
                        },
                    )),
                ),
                (
                    String::from(PROXY_REJECT),
                    OutboundProxy::ProxyServer(OutboundProxyProtocol::Reject(
                        OutboundReject {
                            name: PROXY_REJECT.to_string(),
                        },
                    )),
                ),
            ]),
            |mut rv, protocol| {
                let proxy = OutboundProxy::ProxyServer(protocol);
                let name = proxy.name();
                if rv.contains_key(name.as_str()) {
                    return Err(Error::InvalidConfig(format!(
                        "duplicated proxy name: {name}"
                    )));
                }
                proxy_names.push(name.clone());
                rv.insert(name, proxy);
                Ok(rv)
            },
        )?,
        proxy_groups: proxy_group::convert(c.proxy_group.take(), &mut proxy_names)?,
        proxy_providers: HashMap::new(),
        rule_providers: rule_provider::convert(c.rule_provider.take()),
        proxy_names,
        users: c
            .authentication
            .clone()
            .into_iter()
            .map(|u| {
                let mut parts = u.splitn(2, ':');
                let username = parts.next().unwrap_or_default().to_string();
                let password = parts.next().unwrap_or_default().to_string();
                auth::User::new(username, password)
            })
            .collect(),
        listeners: listener::convert(c.listeners.take(), &c)?,
        rules: c
            .rule
            .take()
            .unwrap_or_default()
            .into_iter()
            .map(|x| {
                x.parse::<RuleType>()
                    .map_err(|x| Error::InvalidConfig(x.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?,
        general: general::convert(&c)?,
        dns,
        tun,
        experimental: c.experimental.take(),
        profile: Profile {
            store_selected: c.profile.store_selected,
            store_smart_stats: c.profile.store_smart_stats,
        },
    }
    .validate()
}

fn validate_dns_tun_ipv6(
    dns: &crate::app::dns::Config,
    tun: &config::TunConfig,
) -> Result<(), Error> {
    if tun.enable && dns.ipv6 && tun.gateway_v6.is_none() {
        return Err(Error::InvalidConfig(
            "dns IPv6 responses require tun.ipv6 when TUN is enabled".to_owned(),
        ));
    }
    Ok(())
}

fn configure_fake_ip_route(
    dns: &crate::app::dns::Config,
    tun: &mut config::TunConfig,
) -> Result<(), Error> {
    if !tun.enable || !dns.enable || dns.enhance_mode != def::DNSMode::FakeIp {
        return Ok(());
    }

    let fake_ip_range = match dns.fake_ip_range {
        ipnet::IpNet::V4(range) => range,
        ipnet::IpNet::V6(_) => {
            return Err(Error::InvalidConfig(
                "fake-ip-range must be an IPv4 subnet".to_string(),
            ));
        }
    };

    let tun_network = tun.gateway.trunc();
    if tun_network.contains(&fake_ip_range.network())
        || fake_ip_range.contains(&tun_network.network())
    {
        return Err(Error::InvalidConfig(format!(
            "tun gateway subnet `{tun_network}` overlaps fake-ip-range \
             `{fake_ip_range}`; use separate subnets"
        )));
    }

    let fake_ip_route = ipnet::IpNet::V4(fake_ip_range.trunc());
    if !tun.route_all && !tun.routes.contains(&fake_ip_route) {
        tun.routes.push(fake_ip_route);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{Error, config::def};

    use super::convert;

    fn parse_config(extra_yaml: &str) -> def::Config {
        let yaml = format!(
            r#"
bind_address: "*"
log_level: info
ipv6: false
dns: {{}}
profile: {{}}
{extra_yaml}
"#
        );
        yaml.parse::<def::Config>()
            .expect("def config should parse")
    }

    #[test]
    fn fill_tun_so_mark_from_routing_mark() {
        let cfg = parse_config(
            r#"
routing-mark: 6666
tun:
  enable: true
"#,
        );

        let converted = convert(cfg).expect("internal convert should succeed");
        assert_eq!(converted.tun.so_mark, Some(6666));
    }

    #[test]
    fn reject_dns_ipv6_with_ipv4_only_tun() {
        let mut cfg = parse_config(
            r#"
tun:
  enable: true
  ipv6: false
"#,
        );
        cfg.ipv6 = true;
        cfg.dns.ipv6 = true;

        let error = match convert(cfg) {
            Ok(_) => panic!("IPv4-only TUN must reject DNS IPv6"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            Error::InvalidConfig(message)
                if message.contains("dns IPv6 responses require tun.ipv6")
        ));
    }

    #[test]
    fn allow_dns_ipv6_with_ipv6_tun() {
        let mut cfg = parse_config(
            r#"
tun:
  enable: true
  ipv6: true
"#,
        );
        cfg.ipv6 = true;
        cfg.dns.ipv6 = true;

        let converted = convert(cfg).expect("dual-stack TUN should be valid");
        assert!(converted.dns.ipv6);
        assert!(converted.tun.gateway_v6.is_some());
    }

    #[test]
    fn keep_tun_so_mark_if_explicitly_set() {
        let cfg = parse_config(
            r#"
routing-mark: 6666
tun:
  enable: true
  so-mark: 7777
"#,
        );

        let converted = convert(cfg).expect("internal convert should succeed");
        assert_eq!(converted.tun.so_mark, Some(7777));
    }

    #[test]
    fn fill_routing_mark_from_enabled_tun_so_mark() {
        let cfg = parse_config(
            r#"
tun:
  enable: true
  so-mark: 7777
"#,
        );

        let converted = convert(cfg).expect("internal convert should succeed");
        assert_eq!(converted.general.routing_mask, Some(7777));
        assert_eq!(converted.dns.fw_mark, Some(7777));
        assert_eq!(converted.tun.so_mark, Some(7777));
    }

    #[test]
    fn parse_tun_auto_route_alias() {
        let cfg = parse_config(
            r#"
tun:
  enable: true
  auto-route: true
"#,
        );

        let converted = convert(cfg).expect("internal convert should succeed");
        assert!(converted.tun.route_all);
    }

    #[test]
    fn fake_ip_mode_adds_route_for_separate_default_pool() {
        let mut cfg = parse_config(
            r#"
tun:
  enable: true
"#,
        );
        cfg.dns.enable = true;
        cfg.dns.enhanced_mode = def::DNSMode::FakeIp;
        cfg.dns.nameserver = vec!["1.1.1.1".to_string()];

        let converted = convert(cfg).expect("internal convert should succeed");
        assert_eq!(converted.tun.gateway.to_string(), "198.18.0.1/30");
        assert!(
            converted
                .tun
                .routes
                .contains(&"198.19.0.0/16".parse().unwrap())
        );
    }

    #[test]
    fn reject_overlapping_tun_and_fake_ip_subnets() {
        let mut cfg = parse_config(
            r#"
tun:
  enable: true
  gateway: 198.18.0.1/30
"#,
        );
        cfg.dns.enable = true;
        cfg.dns.enhanced_mode = def::DNSMode::FakeIp;
        cfg.dns.fake_ip_range = "198.18.0.0/16".to_string();
        cfg.dns.nameserver = vec!["1.1.1.1".to_string()];

        match convert(cfg) {
            Err(Error::InvalidConfig(message)) => {
                assert!(message.contains("overlaps fake-ip-range"));
            }
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("overlapping subnets must be rejected"),
        }
    }

    #[test]
    fn parse_relay_group_with_proxies() {
        let cfg = parse_config(
            r#"
proxies:
  - name: "proxy-a"
    type: socks5
    server: 127.0.0.1
    port: 1080
  - name: "proxy-b"
    type: socks5
    server: 127.0.0.1
    port: 1081

proxy-groups:
  - name: "relay-chain"
    type: relay
    proxies:
      - "proxy-a"
      - "proxy-b"
    url: "http://www.gstatic.com/generate_204"
    icon: "relay.svg"
"#,
        );

        let converted = convert(cfg).expect("internal convert should succeed");
        let group = converted
            .proxy_groups
            .get("relay-chain")
            .expect("relay-chain group should exist");

        use crate::config::internal::proxy::OutboundGroupProtocol;
        match &group {
            crate::config::internal::proxy::OutboundProxy::ProxyGroup(protocol) => {
                match protocol {
                    OutboundGroupProtocol::Relay(relay) => {
                        assert_eq!(relay.name, "relay-chain");
                        assert_eq!(
                            relay.proxies,
                            Some(vec!["proxy-a".to_string(), "proxy-b".to_string()])
                        );
                        assert_eq!(
                            relay.url,
                            Some("http://www.gstatic.com/generate_204".to_string())
                        );
                        assert_eq!(relay.icon, Some("relay.svg".to_string()));
                    }
                    _ => panic!("expected Relay group, got {protocol:?}"),
                }
            }
            _ => panic!("expected ProxyGroup"),
        }
    }

    #[test]
    fn parse_relay_group_minimal() {
        let cfg = parse_config(
            r#"
proxies:
  - name: "proxy-a"
    type: socks5
    server: 127.0.0.1
    port: 1080

proxy-groups:
  - name: "minimal-relay"
    type: relay
    proxies:
      - "proxy-a"
"#,
        );

        let converted = convert(cfg).expect("internal convert should succeed");
        let group = converted
            .proxy_groups
            .get("minimal-relay")
            .expect("minimal-relay group should exist");

        use crate::config::internal::proxy::OutboundGroupProtocol;
        match &group {
            crate::config::internal::proxy::OutboundProxy::ProxyGroup(protocol) => {
                match protocol {
                    OutboundGroupProtocol::Relay(relay) => {
                        assert_eq!(relay.name, "minimal-relay");
                        assert_eq!(relay.proxies, Some(vec!["proxy-a".to_string()]));
                        assert!(relay.url.is_none());
                        assert!(relay.icon.is_none());
                    }
                    _ => panic!("expected Relay group, got {protocol:?}"),
                }
            }
            _ => panic!("expected ProxyGroup"),
        }
    }
}
