use crate::{
    Error,
    config::{
        def,
        internal::config::{
            self, DnsHijackAddress, DnsHijackProtocol, DnsHijackRule,
        },
    },
};

fn parse_dns_hijack_rule(value: &str) -> Result<DnsHijackRule, crate::Error> {
    let (protocol, address) = match value.split_once("://") {
        Some(("udp", address)) => (DnsHijackProtocol::Udp, address),
        Some(("tcp", address)) => (DnsHijackProtocol::Tcp, address),
        Some((protocol, _)) => {
            return Err(Error::InvalidConfig(format!(
                "parse tun dns-hijack: unsupported protocol {protocol}"
            )));
        }
        None => (DnsHijackProtocol::Udp, value),
    };

    let (address, port) = address.rsplit_once(':').ok_or_else(|| {
        Error::InvalidConfig(format!(
            "parse tun dns-hijack: missing port in {value}"
        ))
    })?;
    let port = port.parse::<u16>().map_err(|e| {
        Error::InvalidConfig(format!("parse tun dns-hijack port in {value}: {e}"))
    })?;
    if port == 0 {
        return Err(Error::InvalidConfig(format!(
            "parse tun dns-hijack: port must not be zero in {value}"
        )));
    }

    let address = if address == "any" {
        DnsHijackAddress::Any
    } else {
        if address.contains(':')
            && !(address.starts_with('[') && address.ends_with(']'))
        {
            return Err(Error::InvalidConfig(format!(
                "parse tun dns-hijack: IPv6 address must be bracketed in {value}"
            )));
        }
        let address = address
            .strip_prefix('[')
            .and_then(|address| address.strip_suffix(']'))
            .unwrap_or(address);
        DnsHijackAddress::Ip(address.parse().map_err(|e| {
            Error::InvalidConfig(format!(
                "parse tun dns-hijack address in {value}: {e}"
            ))
        })?)
    };

    Ok(DnsHijackRule {
        protocol,
        address,
        port,
    })
}

fn parse_dns_hijack(
    value: def::DnsHijack,
) -> Result<(bool, Vec<DnsHijackRule>), crate::Error> {
    let (enabled, values) = match value {
        def::DnsHijack::Switch(false) => return Ok((false, Vec::new())),
        def::DnsHijack::Switch(true) => {
            (true, vec!["any:53".to_string(), "tcp://any:53".to_string()])
        }
        def::DnsHijack::List(values) => (true, values),
    };

    let mut rules = Vec::with_capacity(values.len());
    for value in values {
        let rule = parse_dns_hijack_rule(&value)?;
        if !rules.contains(&rule) {
            rules.push(rule);
        }
    }
    Ok((enabled, rules))
}

pub(super) fn convert(
    before: Option<def::TunConfig>,
) -> Result<config::TunConfig, crate::Error> {
    fn parse_routes(
        routes: Option<Vec<String>>,
        field: &str,
    ) -> Result<Vec<ipnet::IpNet>, crate::Error> {
        routes
            .map(|routes| {
                routes
                    .into_iter()
                    .map(|route| route.parse())
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()
            .map_err(|e| Error::InvalidConfig(format!("parse tun {field}: {e}")))
            .map(|routes| routes.unwrap_or_default())
    }

    match before {
        Some(t) => {
            let (dns_hijack, dns_hijack_rules) = parse_dns_hijack(t.dns_hijack)?;
            if t.gateway_v6.is_some() && t.route_table == t.route_table_v6 {
                return Err(Error::InvalidConfig(
                    "tun route-table-v6 must differ from route-table when IPv6 is enabled"
                        .to_owned(),
                ));
            }
            let mut route_exclude_address =
                parse_routes(t.route_exclude_address, "route-exclude-address")?;

            let inet4_route_exclude_address = parse_routes(
                t.inet4_route_exclude_address,
                "inet4-route-exclude-address",
            )?;
            if inet4_route_exclude_address
                .iter()
                .any(|route| !route.addr().is_ipv4())
            {
                return Err(Error::InvalidConfig(
                    "parse tun inet4-route-exclude-address: IPv6 CIDR is not allowed"
                        .to_string(),
                ));
            }
            route_exclude_address.extend(inet4_route_exclude_address);

            let inet6_route_exclude_address = parse_routes(
                t.inet6_route_exclude_address,
                "inet6-route-exclude-address",
            )?;
            if inet6_route_exclude_address
                .iter()
                .any(|route| !route.addr().is_ipv6())
            {
                return Err(Error::InvalidConfig(
                    "parse tun inet6-route-exclude-address: IPv4 CIDR is not allowed"
                        .to_string(),
                ));
            }
            route_exclude_address.extend(inet6_route_exclude_address);

            Ok(config::TunConfig {
                enable: t.enable,
                device_id: t.device_id,
                route_all: t.route_all,
                routes: parse_routes(t.routes, "routes")?,
                route_exclude_address,
                gateway: t.gateway.parse().map_err(|e| {
                    Error::InvalidConfig(format!("parse tun gateway: {e}"))
                })?,
                gateway_v6: t
                    .gateway_v6
                    .map(|gateway| {
                        gateway.parse().map_err(|e| {
                            Error::InvalidConfig(format!(
                                "parse tun gateway_v6: {e}"
                            ))
                        })
                    })
                    .transpose()?,
                mtu: t.mtu,
                so_mark: t.so_mark,
                route_table: t.route_table,
                route_table_v6: t.route_table_v6,
                dns_hijack,
                dns_hijack_rules,
            })
        }
        None => Ok(config::TunConfig::default()),
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{
        def,
        internal::config::{DnsHijackAddress, DnsHijackProtocol, DnsHijackRule},
    };

    use super::convert;

    fn parse_tun(yaml: &str) -> def::TunConfig {
        serde_yaml::from_str(yaml).expect("tun config should parse")
    }

    #[test]
    fn parse_device_id_variants() {
        for value in ["dev://tun0", "fd://3", "tun0"] {
            let tun = parse_tun(&format!("enable: true\ndevice-id: \"{value}\""));
            let converted = convert(Some(tun)).expect("tun convert should succeed");
            assert_eq!(converted.device_id, value);
        }
    }

    #[test]
    fn parse_default_tun_values() {
        let tun = parse_tun("enable: true");
        let converted = convert(Some(tun)).expect("tun convert should succeed");

        assert_eq!(converted.device_id, "utun1989");
        assert_eq!(converted.route_table, 2468);
        assert_eq!(converted.route_table_v6, 2469);
        assert_eq!(converted.gateway.to_string(), "198.18.0.1/30");
        assert!(!converted.dns_hijack);
    }

    #[test]
    fn parse_separate_ipv6_route_table() {
        let tun = parse_tun("enable: true\nroute-table: 100\nroute-table-v6: 101");
        let converted = convert(Some(tun)).expect("tun convert should succeed");

        assert_eq!(converted.route_table, 100);
        assert_eq!(converted.route_table_v6, 101);
    }

    #[test]
    fn reject_shared_route_table_when_ipv6_is_enabled() {
        let tun = parse_tun(
            "enable: true\ngateway-v6: fd00:198:18::1/126\nroute-table: 100\nroute-table-v6: 100",
        );
        let error = match convert(Some(tun)) {
            Ok(_) => panic!("shared table should fail"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            crate::Error::InvalidConfig(message)
                if message.contains("route-table-v6 must differ")
        ));
    }

    #[test]
    fn parse_dns_hijack_list_as_true() {
        let tun = parse_tun(
            r#"
enable: true
dns-hijack:
  - any:53
"#,
        );
        let converted = convert(Some(tun)).expect("tun convert should succeed");
        assert!(converted.dns_hijack);
        assert_eq!(
            converted.dns_hijack_rules,
            vec![DnsHijackRule {
                protocol: DnsHijackProtocol::Udp,
                address: DnsHijackAddress::Any,
                port: 53,
            }]
        );
    }

    #[test]
    fn expand_dns_hijack_true_to_udp_and_tcp() {
        let converted = convert(Some(parse_tun("enable: true\ndns-hijack: true")))
            .expect("valid rule");

        assert_eq!(converted.dns_hijack_rules.len(), 2);
        assert_eq!(
            converted.dns_hijack_rules[0].protocol,
            DnsHijackProtocol::Udp
        );
        assert_eq!(
            converted.dns_hijack_rules[1].protocol,
            DnsHijackProtocol::Tcp
        );
    }

    #[test]
    fn preserve_empty_dns_hijack_list_as_enabled() {
        let converted = convert(Some(parse_tun("enable: true\ndns-hijack: []")))
            .expect("empty list remains compatible");

        assert!(converted.dns_hijack);
        assert!(converted.dns_hijack_rules.is_empty());
    }

    #[test]
    fn parse_dns_hijack_addresses_and_remove_duplicates() {
        let tun = parse_tun(
            r#"
enable: true
dns-hijack:
  - 1.1.1.1:53
  - tcp://[::1]:53
  - 1.1.1.1:53
"#,
        );
        let converted = convert(Some(tun)).expect("valid rules");

        assert_eq!(converted.dns_hijack_rules.len(), 2);
        assert_eq!(
            converted.dns_hijack_rules[0].address,
            DnsHijackAddress::Ip("1.1.1.1".parse().unwrap())
        );
        assert_eq!(
            converted.dns_hijack_rules[1].address,
            DnsHijackAddress::Ip("::1".parse().unwrap())
        );
    }

    #[test]
    fn reject_invalid_dns_hijack_rules() {
        for rule in [
            "quic://any:53",
            "any",
            "any:0",
            "any:65536",
            "not-an-ip:53",
            "::1:53",
        ] {
            let tun = parse_tun(&format!("enable: true\ndns-hijack: [\"{rule}\"]"));
            match convert(Some(tun)) {
                Err(crate::Error::InvalidConfig(message)) => {
                    assert!(message.contains("parse tun dns-hijack"))
                }
                Err(other) => panic!("unexpected error for {rule}: {other}"),
                Ok(_) => panic!("invalid rule should fail: {rule}"),
            }
        }
    }

    #[test]
    fn reject_invalid_routes_cidr() {
        let tun = parse_tun(
            r#"
enable: true
routes:
  - invalid-cidr
"#,
        );
        match convert(Some(tun)) {
            Err(crate::Error::InvalidConfig(msg)) => {
                assert!(msg.contains("parse tun routes"))
            }
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("invalid route cidr should fail"),
        }
    }

    #[test]
    fn parse_route_exclude_address_variants() {
        let tun = parse_tun(
            r#"
enable: true
route-exclude-address:
  - 10.0.0.0/8
inet4-route-exclude-address:
  - 192.168.0.0/16
inet6-route-exclude-address:
  - fe80::/10
"#,
        );
        let converted = convert(Some(tun)).expect("tun convert should succeed");

        assert_eq!(converted.route_exclude_address.len(), 3);
        assert_eq!(converted.route_exclude_address[0].to_string(), "10.0.0.0/8");
        assert_eq!(
            converted.route_exclude_address[1].to_string(),
            "192.168.0.0/16"
        );
        assert_eq!(converted.route_exclude_address[2].to_string(), "fe80::/10");
    }

    #[test]
    fn reject_ipv6_in_inet4_route_exclude_address() {
        let tun = parse_tun(
            r#"
enable: true
inet4-route-exclude-address:
  - fe80::/10
"#,
        );
        match convert(Some(tun)) {
            Err(crate::Error::InvalidConfig(msg)) => {
                assert!(msg.contains("inet4-route-exclude-address"))
            }
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("invalid inet4 route exclude cidr should fail"),
        }
    }

    #[test]
    fn reject_invalid_gateway_cidr() {
        let tun = parse_tun(
            r#"
enable: true
gateway: 198.18.0.1
"#,
        );
        match convert(Some(tun)) {
            Err(crate::Error::InvalidConfig(msg)) => {
                assert!(msg.contains("parse tun gateway"))
            }
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("invalid gateway cidr should fail"),
        }
    }
}
