use ipnet::IpNet;

use crate::{
    Error,
    config::internal::proxy::OutboundWireguard,
    proxy::{
        HandlerCommonOptions,
        wg::{Handler, HandlerOptions},
    },
};

impl TryFrom<OutboundWireguard> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundWireguard) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundWireguard> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundWireguard) -> Result<Self, Self::Error> {
        let h = Handler::try_new(HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: HandlerCommonOptions {
                connector: s.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            ip: s
                .ip
                .parse::<IpNet>()
                .map(|x| match x.addr() {
                    std::net::IpAddr::V4(v4) => Ok(v4),
                    std::net::IpAddr::V6(_) => Err(Error::InvalidConfig(
                        "invalid ip address: put an v4 address here".to_owned(),
                    )),
                })
                .map_err(|x| {
                    Error::InvalidConfig(format!(
                        "invalid ip address: {}, {}",
                        x, s.ip
                    ))
                })??,
            ipv6: s
                .ipv6
                .as_ref()
                .map(|raw| {
                    let network = raw.parse::<IpNet>().map_err(|err| {
                        Error::InvalidConfig(format!(
                            "invalid WireGuard ipv6 address: {err}"
                        ))
                    })?;
                    match network.addr() {
                        std::net::IpAddr::V6(v6) => Ok(v6),
                        std::net::IpAddr::V4(_) => Err(Error::InvalidConfig(
                            "WireGuard ipv6 must be an IPv6 address".to_owned(),
                        )),
                    }
                })
                .transpose()?,
            private_key: s.private_key.to_owned(),
            public_key: s.public_key.to_owned(),
            pre_shared_key: s.pre_shared_key.as_ref().map(|x| x.to_owned()),
            remote_dns_resolve: s.remote_dns_resolve.unwrap_or_default(),
            dns: s.dns.as_ref().map(|x| x.to_owned()),
            mtu: s.mtu,
            udp: s.udp.unwrap_or_default(),
            allowed_ips: s.allowed_ips.as_ref().map(|x| x.to_owned()),
            reserved_bits: s.reserved_bits.as_ref().map(|x| x.to_owned()),
        })?;
        Ok(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::{OutboundHandler, OutboundType};

    #[test]
    fn converts_wireguard_config_to_handler() {
        let config: OutboundWireguard = serde_yaml::from_str(
            r#"
name: wg
server: 198.51.100.10
port: 51820
private-key: KIlDUePHyYwzjgn18przw/ZwPioJhh2aEyhxb/dtCXI=
public-key: INBZyvB715sA5zatkiX8Jn3Dh5tZZboZ09x4pkr66ig=
ip: 10.0.0.2/32
udp: true
"#,
        )
        .expect("wireguard config should parse");

        let handler =
            Handler::try_from(&config).expect("wireguard config should convert");

        assert_eq!(handler.name(), "wg");
        assert_eq!(handler.server_name(), Some("198.51.100.10"));
        assert!(matches!(handler.proto(), OutboundType::WireGuard));
    }

    #[test]
    fn rejects_invalid_wireguard_key_during_conversion() {
        let config: OutboundWireguard = serde_yaml::from_str(
            r#"
name: wg
server: 198.51.100.10
port: 51820
private-key: "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
public-key: INBZyvB715sA5zatkiX8Jn3Dh5tZZboZ09x4pkr66ig=
ip: 10.0.0.2/32
"#,
        )
        .expect("wireguard config shape should parse");

        let error = Handler::try_from(&config)
            .expect_err("invalid WireGuard key must fail conversion");

        assert!(error.to_string().contains("private key"));
    }

    #[test]
    fn rejects_invalid_ipv6_instead_of_silently_disabling_it() {
        for invalid_ipv6 in ["not-an-address", "10.0.0.3/32"] {
            let config: OutboundWireguard = serde_yaml::from_str(&format!(
                r#"
name: wg
server: 198.51.100.10
port: 51820
private-key: KIlDUePHyYwzjgn18przw/ZwPioJhh2aEyhxb/dtCXI=
public-key: INBZyvB715sA5zatkiX8Jn3Dh5tZZboZ09x4pkr66ig=
ip: 10.0.0.2/32
ipv6: {invalid_ipv6}
"#
            ))
            .expect("synthetic config should parse");

            let error = Handler::try_from(&config).expect_err(
                "invalid or non-IPv6 address must fail outbound conversion",
            );
            assert!(
                error.to_string().contains("ipv6"),
                "unexpected rejection reason: {error}"
            );
        }
    }

    #[test]
    fn accepts_valid_ipv6_allowed_ips_and_reserved_bits_offline() {
        for reserved_bits in ["[]", "[0, 0, 0]"] {
            let config: OutboundWireguard = serde_yaml::from_str(&format!(
                r#"
name: wg
server: 198.51.100.10
port: 51820
private-key: KIlDUePHyYwzjgn18przw/ZwPioJhh2aEyhxb/dtCXI=
public-key: INBZyvB715sA5zatkiX8Jn3Dh5tZZboZ09x4pkr66ig=
ip: 10.0.0.2/32
ipv6: 2001:db8::2/128
allowed-ips:
  - 0.0.0.0/0
  - ::/0
reserved-bits: {reserved_bits}
"#
            ))
            .expect("valid synthetic config should parse");

            let handler = Handler::try_from(&config)
                .expect("valid WireGuard options should construct without dialing");
            assert_eq!(handler.name(), "wg");
        }
    }

    #[test]
    fn rejects_invalid_allowed_ips_during_conversion() {
        let config: OutboundWireguard = serde_yaml::from_str(
            r#"
name: wg
server: 198.51.100.10
port: 51820
private-key: KIlDUePHyYwzjgn18przw/ZwPioJhh2aEyhxb/dtCXI=
public-key: INBZyvB715sA5zatkiX8Jn3Dh5tZZboZ09x4pkr66ig=
ip: 10.0.0.2/32
allowed-ips: [not-a-cidr]
"#,
        )
        .expect("synthetic config should parse");

        let error = Handler::try_from(&config).expect_err(
            "invalid allowed-ips must fail before tunnel initialization",
        );
        assert!(error.to_string().contains("allowed IP"));
    }

    #[test]
    fn rejects_incomplete_or_extra_reserved_bits_during_conversion() {
        for reserved in ["[0, 0]", "[0, 0, 0, 0]"] {
            let config: OutboundWireguard = serde_yaml::from_str(&format!(
                r#"
name: wg
server: 198.51.100.10
port: 51820
private-key: KIlDUePHyYwzjgn18przw/ZwPioJhh2aEyhxb/dtCXI=
public-key: INBZyvB715sA5zatkiX8Jn3Dh5tZZboZ09x4pkr66ig=
ip: 10.0.0.2/32
reserved-bits: {reserved}
"#
            ))
            .expect("synthetic config should parse");

            let error = Handler::try_from(&config)
                .expect_err("invalid reserved-bits length must fail conversion");
            assert!(error.to_string().contains("reserved-bits"));
        }
    }

    #[test]
    fn rejects_invalid_wireguard_dns_server_during_conversion() {
        let config: OutboundWireguard = serde_yaml::from_str(
            r#"
name: wg
server: 198.51.100.10
port: 51820
private-key: KIlDUePHyYwzjgn18przw/ZwPioJhh2aEyhxb/dtCXI=
public-key: INBZyvB715sA5zatkiX8Jn3Dh5tZZboZ09x4pkr66ig=
ip: 10.0.0.2/32
remote-dns-resolve: true
dns:
  - not-an-ip
"#,
        )
        .expect("wireguard config shape should parse");

        let error = Handler::try_from(&config)
            .expect_err("invalid WireGuard DNS server must fail conversion");

        assert!(error.to_string().contains("DNS server"));
    }
}
