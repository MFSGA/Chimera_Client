use std::net::{IpAddr, Ipv4Addr};

use async_trait::async_trait;

use crate::Error;

mod file_store;
mod mem_store;

pub use file_store::FileStore;
pub use mem_store::InMemStore;

pub struct Opts {
    pub ipnet: ipnet::IpNet,
    pub skipped_hostnames: Vec<String>,
    pub store: Box<dyn Store>,
}

#[async_trait]
pub trait Store: Sync + Send {
    async fn get_by_host(&mut self, host: &str) -> Option<IpAddr>;
    async fn pub_by_host(&mut self, host: &str, ip: IpAddr);
    async fn get_by_ip(&mut self, ip: IpAddr) -> Option<String>;
    async fn put_by_ip(&mut self, ip: IpAddr, host: &str);
    async fn del_by_ip(&mut self, ip: IpAddr);
    async fn exist(&mut self, ip: IpAddr) -> bool;
}

pub struct FakeDns {
    max: u32,
    min: u32,
    offset: u32,
    skipped_hostnames: Vec<String>,
    ipnet: ipnet::IpNet,
    store: Box<dyn Store>,
}

impl FakeDns {
    pub fn new(opt: Opts) -> Result<Self, Error> {
        let ip = match opt.ipnet.network() {
            IpAddr::V4(ip) => ip,
            _ => {
                return Err(Error::InvalidConfig(
                    "fake-ip-range must be valid ipv4 subnet".to_string(),
                ));
            }
        };

        let min = Self::ip_to_uint(&ip) + 2;
        let prefix_len = opt.ipnet.prefix_len();
        let max_prefix_len = opt.ipnet.max_prefix_len();
        let total = (1 << (max_prefix_len - prefix_len)) - 2;
        let max = min + total - 1;

        Ok(Self {
            max,
            min,
            offset: 0,
            skipped_hostnames: opt.skipped_hostnames,
            ipnet: opt.ipnet,
            store: opt.store,
        })
    }

    pub async fn lookup(&mut self, host: &str) -> IpAddr {
        if let Some(ip) = self.store.get_by_host(host).await {
            return ip;
        }

        let ip = self.next_ip(host).await;
        self.store.pub_by_host(host, ip).await;
        ip
    }

    pub async fn reverse_lookup(&mut self, ip: IpAddr) -> Option<String> {
        if ip.is_ipv4() {
            self.store.get_by_ip(ip).await
        } else {
            None
        }
    }

    pub fn should_skip(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        self.skipped_hostnames.iter().any(|pattern| {
            let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
            domain == pattern
                || domain
                    .strip_suffix(&pattern)
                    .is_some_and(|rest| rest.ends_with('.'))
        })
    }

    pub async fn is_fake_ip(&mut self, ip: IpAddr) -> bool {
        ip.is_ipv4() && self.ipnet.contains(&ip)
    }

    async fn next_ip(&mut self, host: &str) -> IpAddr {
        let current = self.offset;

        loop {
            self.offset = (self.offset + 1) % (self.max - self.min);

            if self.offset == current {
                self.offset = (self.offset + 1) % (self.max - self.min);
                let ip = Ipv4Addr::from(self.min + self.offset - 1);
                self.store.del_by_ip(IpAddr::V4(ip)).await;
                break;
            }

            let ip = Ipv4Addr::from(self.min + self.offset - 1);
            if !self.store.exist(IpAddr::V4(ip)).await {
                break;
            }
        }

        let ip = Ipv4Addr::from(self.min + self.offset - 1);
        self.store.put_by_ip(IpAddr::V4(ip), host).await;
        IpAddr::V4(ip)
    }

    fn ip_to_uint(ip: &Ipv4Addr) -> u32 {
        u32::from_be_bytes(ip.octets())
    }
}
