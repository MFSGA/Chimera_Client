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
        let handler = Handler::new(HandlerOptions {
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
                .map(|network| match network.addr() {
                    std::net::IpAddr::V4(v4) => Ok(v4),
                    std::net::IpAddr::V6(_) => Err(Error::InvalidConfig(
                        "invalid ip address: put an v4 address here".to_owned(),
                    )),
                })
                .map_err(|error| {
                    Error::InvalidConfig(format!(
                        "invalid ip address: {error}, {}",
                        s.ip
                    ))
                })??,
            ipv6: s
                .ipv6
                .as_ref()
                .and_then(|value| {
                    value
                        .parse::<IpNet>()
                        .map(|network| match network.addr() {
                            std::net::IpAddr::V4(_) => Err(Error::InvalidConfig(
                                "invalid ip address: put an v6 address here"
                                    .to_owned(),
                            )),
                            std::net::IpAddr::V6(v6) => Ok(v6),
                        })
                        .map_err(|error| {
                            Error::InvalidConfig(format!(
                                "invalid ipv6 address: {error}, {value}"
                            ))
                        })
                        .ok()
                })
                .transpose()?,
            private_key: s.private_key.to_owned(),
            public_key: s.public_key.to_owned(),
            pre_shared_key: s.pre_shared_key.clone(),
            remote_dns_resolve: s.remote_dns_resolve.unwrap_or_default(),
            dns: s.dns.clone(),
            mtu: s.mtu,
            udp: s.udp.unwrap_or_default(),
            allowed_ips: s.allowed_ips.clone(),
            reserved_bits: s.reserved_bits.clone(),
        });
        Ok(handler)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIVATE_KEY: &str = "KIlDUePHyYwzjgn18przw/ZwPioJhh2aEyhxb/dtCXI=";
    const PUBLIC_KEY: &str = "INBZyvB715sA5zatkiX8Jn3Dh5tZZboZ09x4pkr66ig=";

    #[test]
    fn wireguard_converter_maps_reference_options() {
        let yaml = format!(
            r#"
name: wg-convert
type: wireguard
server: wg.example.com
port: 51820
private-key: {PRIVATE_KEY}
public-key: {PUBLIC_KEY}
ip: 10.0.0.2/32
ipv6: 2001:db8::2/128
udp: true
mtu: 1380
remote-dns-resolve: true
dns:
  - 1.1.1.1
allowed-ips:
  - 0.0.0.0/0
reserved-bits: [1, 2, 3]
dialer-proxy: DIRECT
"#
        );
        let config: OutboundWireguard =
            serde_yaml::from_str(&yaml).expect("wireguard config should parse");
        let handler: Handler =
            (&config).try_into().expect("converter should succeed");
        let opts = handler.options();

        assert_eq!(opts.name, "wg-convert");
        assert_eq!(opts.server, "wg.example.com");
        assert_eq!(opts.port, 51820);
        assert_eq!(opts.ip.to_string(), "10.0.0.2");
        assert_eq!(opts.ipv6.unwrap().to_string(), "2001:db8::2");
        assert!(opts.udp);
        assert_eq!(opts.mtu, Some(1380));
        assert!(opts.remote_dns_resolve);
        assert_eq!(opts.dns.as_deref(), Some(&["1.1.1.1".to_string()][..]));
        assert_eq!(
            opts.allowed_ips.as_deref(),
            Some(&["0.0.0.0/0".to_string()][..])
        );
        assert_eq!(opts.reserved_bits.as_deref(), Some(&[1, 2, 3][..]));
        assert_eq!(opts.common_opts.connector.as_deref(), Some("DIRECT"));
    }

    #[test]
    fn wireguard_converter_rejects_ipv6_in_ipv4_field() {
        let config = OutboundWireguard {
            common_opts: crate::config::internal::proxy::CommonConfigOptions {
                name: "bad-wg".to_string(),
                server: "example.com".to_string(),
                port: 51820,
                connect_via: None,
            },
            private_key: PRIVATE_KEY.to_string(),
            public_key: PUBLIC_KEY.to_string(),
            ip: "2001:db8::2/128".to_string(),
            ..Default::default()
        };

        let result = Handler::try_from(&config);
        assert!(matches!(result, Err(Error::InvalidConfig(_))));
    }
}
