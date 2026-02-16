use crate::{
    Error,
    config::{def, internal::config},
};

pub(super) fn convert(before: Option<def::TunConfig>) -> Result<config::TunConfig, crate::Error> {
    match before {
        Some(t) => Ok(config::TunConfig {
            enable: t.enable,
            device_id: t.device_id,
            route_all: t.route_all,
            routes: t
                .routes
                .map(|routes| {
                    routes
                        .into_iter()
                        .map(|route| route.parse())
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()
                .map_err(|e| Error::InvalidConfig(format!("parse tun routes: {e}")))?
                .unwrap_or_default(),
            gateway: t
                .gateway
                .parse()
                .map_err(|e| Error::InvalidConfig(format!("parse tun gateway: {e}")))?,
            gateway_v6: t
                .gateway_v6
                .map(|gateway| {
                    gateway
                        .parse()
                        .map_err(|e| Error::InvalidConfig(format!("parse tun gateway_v6: {e}")))
                })
                .transpose()?,
            mtu: t.mtu,
            so_mark: t.so_mark,
            route_table: t.route_table,
            dns_hijack: match t.dns_hijack {
                def::DnsHijack::Switch(v) => v,
                def::DnsHijack::List(_) => true,
            },
        }),
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
            Err(crate::Error::InvalidConfig(msg)) => assert!(msg.contains("parse tun routes")),
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("invalid route cidr should fail"),
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
            Err(crate::Error::InvalidConfig(msg)) => assert!(msg.contains("parse tun gateway")),
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("invalid gateway cidr should fail"),
        }
    }
}
