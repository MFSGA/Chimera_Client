use std::net::{Ipv4Addr, Ipv6Addr};

use super::HandlerCommonOptions;

#[allow(dead_code)]
mod device;
#[allow(dead_code)]
mod events;
#[allow(dead_code)]
mod keys;
#[allow(dead_code)]
mod ports;
#[allow(dead_code)]
mod stack;

// Consumed by the WireGuard handler once the runtime module is wired in.
#[allow(dead_code)]
pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub ip: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
    pub private_key: String,
    pub public_key: String,
    pub pre_shared_key: Option<String>,
    pub remote_dns_resolve: bool,
    pub dns: Option<Vec<String>>,
    pub mtu: Option<u16>,
    pub udp: bool,
    pub allowed_ips: Option<Vec<String>>,
    pub reserved_bits: Option<Vec<u8>>,
}
