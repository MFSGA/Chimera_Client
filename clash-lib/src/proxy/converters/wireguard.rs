use ipnet::IpNet;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{
    Error,
    config::internal::proxy::OutboundWireguard,
    proxy::{
        HandlerCommonOptions,
        wg::{Handler, HandlerOptions},
    },
};

fn parse_wireguard_ipv4(value: &str) -> Result<Ipv4Addr, Error> {
    if let Ok(addr) = value.parse::<Ipv4Addr>() {
        return Ok(addr);
    }

    match value.parse::<IpNet>() {
        Ok(IpNet::V4(net)) => Ok(net.addr()),
        Ok(IpNet::V6(_)) => Err(Error::InvalidConfig(format!(
            "invalid WireGuard ip: expected IPv4 address, got {value}"
        ))),
        Err(err) => Err(Error::InvalidConfig(format!(
            "invalid WireGuard ip {value:?}: {err}"
        ))),
    }
}

fn parse_wireguard_ipv6(value: &str) -> Result<Ipv6Addr, Error> {
    if let Ok(addr) = value.parse::<Ipv6Addr>() {
        return Ok(addr);
    }

    match value.parse::<IpNet>() {
        Ok(IpNet::V6(net)) => Ok(net.addr()),
        Ok(IpNet::V4(_)) => Err(Error::InvalidConfig(format!(
            "invalid WireGuard ipv6: expected IPv6 address, got {value}"
        ))),
        Err(err) => Err(Error::InvalidConfig(format!(
            "invalid WireGuard ipv6 {value:?}: {err}"
        ))),
    }
}

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
            ip: parse_wireguard_ipv4(&s.ip)?,
            ipv6: s.ipv6.as_deref().map(parse_wireguard_ipv6).transpose()?,
            private_key: s.private_key.to_owned(),
            public_key: s.public_key.to_owned(),
            pre_shared_key: s.pre_shared_key.as_ref().map(|x| x.to_owned()),
            remote_dns_resolve: s.remote_dns_resolve.unwrap_or_default(),
            dns: s.dns.as_ref().map(|x| x.to_owned()),
            mtu: s.mtu,
            udp: s.udp.unwrap_or_default(),
            allowed_ips: s.allowed_ips.as_ref().map(|x| x.to_owned()),
            reserved_bits: s.reserved_bits.as_ref().map(|x| x.to_owned()),
            persistent_keepalive: s.persistent_keepalive,
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
ip: 10.0.0.2
ipv6: fd00::2
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
    fn wireguard_address_parser_accepts_bare_and_cidr_forms() {
        assert_eq!(
            parse_wireguard_ipv4("10.0.0.2").unwrap(),
            "10.0.0.2".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            parse_wireguard_ipv4("10.0.0.2/32").unwrap(),
            "10.0.0.2".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            parse_wireguard_ipv6("fd00::2").unwrap(),
            "fd00::2".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            parse_wireguard_ipv6("fd00::2/128").unwrap(),
            "fd00::2".parse::<Ipv6Addr>().unwrap()
        );
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
    fn rejects_invalid_wireguard_allowed_ip_during_conversion() {
        let config: OutboundWireguard = serde_yaml::from_str(
            r#"
name: wg
server: 198.51.100.10
port: 51820
private-key: KIlDUePHyYwzjgn18przw/ZwPioJhh2aEyhxb/dtCXI=
public-key: INBZyvB715sA5zatkiX8Jn3Dh5tZZboZ09x4pkr66ig=
ip: 10.0.0.2
allowed-ips:
  - not-a-cidr
"#,
        )
        .expect("wireguard config shape should parse");

        let error = Handler::try_from(&config)
            .expect_err("invalid WireGuard allowed-ip must fail conversion");
        assert!(error.to_string().contains("allowed-ip"));
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
