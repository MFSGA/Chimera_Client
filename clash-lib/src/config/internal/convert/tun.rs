use crate::{
    Error,
    config::{def, internal::config},
};

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
                dns_hijack: match t.dns_hijack {
                    def::DnsHijack::Switch(v) => v,
                    def::DnsHijack::List(_) => true,
                },
            })
        }
        None => Ok(config::TunConfig::default()),
    }
}

#[cfg(test)]
mod tests {
    use crate::config::def;

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
        assert_eq!(converted.gateway.to_string(), "198.18.0.1/24");
        assert!(!converted.dns_hijack);
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
