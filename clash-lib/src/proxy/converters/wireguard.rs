use ipnet::IpNet;

use crate::{
    Error,
    config::internal::proxy::OutboundWireguard,
    proxy::{HandlerCommonOptions, wg::HandlerOptions},
};

impl TryFrom<&OutboundWireguard> for HandlerOptions {
    type Error = Error;

    fn try_from(s: &OutboundWireguard) -> Result<Self, Self::Error> {
        Ok(Self {
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
            pre_shared_key: s.pre_shared_key.clone(),
            remote_dns_resolve: s.remote_dns_resolve.unwrap_or_default(),
            dns: s.dns.clone(),
            mtu: s.mtu,
            udp: s.udp.unwrap_or_default(),
            allowed_ips: s.allowed_ips.clone(),
            reserved_bits: s.reserved_bits.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_wireguard_config_to_handler_options() {
        let config: OutboundWireguard = serde_yaml::from_str(
            r#"
name: wg
server: 198.51.100.10
port: 51820
private-key: private
public-key: public
ip: 10.0.0.2/32
ipv6: fd00::2/128
udp: true
remote-dns-resolve: true
dns: [1.1.1.1]
allowed-ips: [0.0.0.0/0, "::/0"]
reserved-bits: [1, 2, 3]
"#,
        )
        .expect("wireguard config should parse");

        let opts = HandlerOptions::try_from(&config)
            .expect("wireguard config should convert");

        assert_eq!(opts.name, "wg");
        assert_eq!(opts.server, "198.51.100.10");
        assert_eq!(opts.port, 51820);
        assert_eq!(opts.ip, "10.0.0.2".parse::<std::net::Ipv4Addr>().unwrap());
        assert_eq!(
            opts.ipv6,
            Some("fd00::2".parse::<std::net::Ipv6Addr>().unwrap())
        );
        assert!(opts.udp);
        assert!(opts.remote_dns_resolve);
    }
}
