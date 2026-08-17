use std::net::{Ipv4Addr, Ipv6Addr};

use crate::proxy::HandlerCommonOptions;

pub(crate) mod events;
pub(crate) mod keys;
pub(crate) mod ports;
pub(crate) mod stack;
pub(crate) mod wireguard;

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

pub struct Handler {
    opts: HandlerOptions,
}

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self { opts }
    }

    #[cfg(test)]
    pub(crate) fn options(&self) -> &HandlerOptions {
        &self.opts
    }
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuard")
            .field("name", &self.opts.name)
            .finish()
    }
}
