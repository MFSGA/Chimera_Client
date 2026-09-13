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
                .and_then(|x| {
                    x.parse::<IpNet>()
                        .map(|x| match x.addr() {
                            std::net::IpAddr::V4(_) => Err(Error::InvalidConfig(
                                "invalid ip address: put an v6 address here"
                                    .to_owned(),
                            )),
                            std::net::IpAddr::V6(v6) => Ok(v6),
                        })
                        .map_err(|e| {
                            Error::InvalidConfig(format!(
                                "invalid ipv6 address: {e}, {x}"
                            ))
                        })
                        .ok()
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
