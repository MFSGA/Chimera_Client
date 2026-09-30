use std::{net, sync::Arc};

use crate::{Error, common::trie};

use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use tokio::sync::RwLock;
use tracing::info;

mod file_store;
mod mem_store;

pub use file_store::FileStore;
pub use mem_store::InMemStore;

pub struct Opts {
    pub ipnet: ipnet::IpNet,
    pub skipped_hostnames: Option<trie::StringTrie<bool>>,
    pub store: Box<dyn Store>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpFamily {
    V4,
    V6,
}

impl IpFamily {
    fn of(ip: net::IpAddr) -> Self {
        match ip {
            net::IpAddr::V4(_) => Self::V4,
            net::IpAddr::V6(_) => Self::V6,
        }
    }
}

#[async_trait]
pub trait Store: Sync + Send {
    async fn get_by_host(
        &mut self,
        host: &str,
        family: IpFamily,
    ) -> Option<net::IpAddr>;
    async fn pub_by_host(&mut self, host: &str, family: IpFamily, ip: net::IpAddr);
    async fn get_by_ip(&mut self, ip: net::IpAddr) -> Option<String>;
    async fn put_by_ip(&mut self, ip: net::IpAddr, host: &str);
    async fn del_by_host(&mut self, host: &str, family: IpFamily);
    async fn exist(&mut self, ip: net::IpAddr) -> bool;
    async fn copy_to(&self, store: &mut Box<dyn Store>);
}

pub type ThreadSafeFakeDns = Arc<RwLock<FakeDns>>;

pub struct FakeDns {
    range: PoolRange,
    #[allow(dead_code)]
    gateway: u32,
    cursor: u32,
    skipped_hostnames: Option<trie::StringTrie<bool>>,
    ipnet: ipnet::IpNet,
    store: Box<dyn Store>,
}

#[derive(Clone, Copy)]
enum PoolRange {
    V4 { first: u32, capacity: u32 },
    V6 { first: u128, capacity: u32 },
}

impl FakeDns {
    /// Maximum supported number of fake-IP addresses in a configured range.
    /// The default /16 fits, while in-memory mappings remain bounded.
    const MAX_CAPACITY: u32 = 65_533;

    fn validated_range(
        ipnet: &ipnet::IpNet,
        expected_family: IpFamily,
    ) -> Result<(PoolRange, u32), Error> {
        match (ipnet, expected_family) {
            (ipnet::IpNet::V4(_), IpFamily::V6) => {
                return Err(Error::InvalidConfig(
                    "fake-ip-range6 must be an IPv6 subnet".to_string(),
                ));
            }
            (ipnet::IpNet::V6(_), IpFamily::V4) => {
                return Err(Error::InvalidConfig(
                    "fake-ip-range must be an IPv4 subnet".to_string(),
                ));
            }
            _ => {}
        }

        match ipnet {
            ipnet::IpNet::V4(network) => {
                if network.prefix_len() > 30 {
                    return Err(Error::InvalidConfig(
                        "fake-ip-range must contain a network address, a gateway, at \
                         least one allocatable address, and a broadcast address"
                            .to_string(),
                    ));
                }

                let network_addr = Self::ip_to_uint(&network.network());
                let broadcast = Self::ip_to_uint(&network.broadcast());
                let capacity = broadcast - (network_addr + 2);
                if capacity > Self::MAX_CAPACITY {
                    return Err(Error::InvalidConfig(format!(
                        "fake-ip-range capacity {capacity} exceeds the supported limit {}",
                        Self::MAX_CAPACITY
                    )));
                }
                Ok((
                    PoolRange::V4 {
                        first: network_addr + 2,
                        capacity,
                    },
                    network_addr + 1,
                ))
            }
            ipnet::IpNet::V6(network) => {
                let network_address = network.network();
                if network_address.is_unspecified()
                    || network_address.is_loopback()
                    || network_address.is_multicast()
                    || network_address.is_unicast_link_local()
                {
                    return Err(Error::InvalidConfig(
                        "fake-ip-range6 must be a non-reserved IPv6 subnet"
                            .to_string(),
                    ));
                }
                let host_bits = 128 - network.prefix_len();
                if host_bits == 0 {
                    return Err(Error::InvalidConfig(
                        "fake-ip-range6 must contain at least one allocatable address"
                            .to_string(),
                    ));
                }

                let address_count = if host_bits == 128 {
                    u128::MAX
                } else {
                    1_u128 << host_bits
                };
                let capacity = address_count
                    .saturating_sub(1)
                    .min(Self::MAX_CAPACITY as u128)
                    as u32;
                let first =
                    u128::from(network_address).checked_add(1).ok_or_else(|| {
                        Error::InvalidConfig(
                            "fake-ip-range6 has no allocatable addresses"
                                .to_string(),
                        )
                    })?;
                if capacity == 0 {
                    return Err(Error::InvalidConfig(
                        "fake-ip-range6 must contain at least one allocatable address"
                            .to_string(),
                    ));
                }
                Ok((PoolRange::V6 { first, capacity }, 0))
            }
        }
    }

    pub fn new(opt: Opts) -> Result<Self, Error> {
        Self::new_for_family(opt, IpFamily::V4)
    }

    #[cfg(test)]
    pub(crate) fn new_v6(opt: Opts) -> Result<Self, Error> {
        Self::new_for_family(opt, IpFamily::V6)
    }

    fn new_for_family(opt: Opts, expected_family: IpFamily) -> Result<Self, Error> {
        let (range, gateway) = Self::validated_range(&opt.ipnet, expected_family)?;

        Ok(Self {
            range,
            gateway,
            cursor: 0,
            skipped_hostnames: opt.skipped_hostnames,
            ipnet: opt.ipnet,
            store: opt.store,
        })
    }

    pub async fn lookup(&mut self, host: &str) -> Result<net::IpAddr, Error> {
        // DNS names are case-insensitive. Use one stable key even when a
        // resolver sends different casing on separate queries.
        let host = host.to_ascii_lowercase();
        if let Some(ip) = self.lookup_existing(&host).await {
            info!(
                host = %host,
                fake_ip = %ip,
                range = %self.ipnet,
                reused = true,
                "fake-ip mapping reused"
            );
            return Ok(ip);
        }

        let ip = self.get(&host).await?;
        self.store.pub_by_host(&host, IpFamily::of(ip), ip).await;
        info!(
            host = %host,
            fake_ip = %ip,
            range = %self.ipnet,
            reused = false,
            "fake-ip mapping allocated"
        );
        Ok(ip)
    }

    pub async fn lookup_existing(&mut self, host: &str) -> Option<net::IpAddr> {
        let host = host.to_ascii_lowercase();
        let family = self.family();
        let ip = self.store.get_by_host(&host, family).await?;
        if self.is_allocatable(ip)
            && self.store.get_by_ip(ip).await.as_deref() == Some(host.as_str())
        {
            return Some(ip);
        }
        self.store.del_by_host(&host, family).await;
        None
    }

    pub async fn reverse_lookup(&mut self, ip: net::IpAddr) -> Option<String> {
        if !self.is_allocatable(ip) {
            None
        } else {
            self.store
                .get_by_ip(ip)
                .await
                .map(|host| host.to_ascii_lowercase())
        }
    }

    pub fn should_skip(&self, domain: &str) -> bool {
        match &self.skipped_hostnames {
            None => false,
            Some(host) => host.search(&domain.to_ascii_lowercase()).is_some(),
        }
    }

    #[allow(dead_code)]
    pub async fn exist(&mut self, ip: net::IpAddr) -> bool {
        if !self.is_allocatable(ip) {
            false
        } else {
            self.store.exist(ip).await
        }
    }

    pub async fn is_fake_ip(&mut self, ip: net::IpAddr) -> bool {
        // Only IPs that are both within the fake-IP range *and* have actually
        // been allocated in the store should be treated as fake IPs.  This
        // prevents directed-broadcast addresses (e.g. 198.18.0.255 for the
        // /24 TUN subnet) that fall inside the wider fake-IP /16 range from
        // triggering a failed reverse-lookup in the dispatcher.
        self.is_allocatable(ip) && self.store.exist(ip).await
    }

    fn is_allocatable(&self, ip: net::IpAddr) -> bool {
        match (self.range, ip) {
            (PoolRange::V4 { first, capacity }, net::IpAddr::V4(ip)) => {
                if ip.is_broadcast() || ip.is_multicast() {
                    return false;
                }
                let ip = Self::ip_to_uint(&ip);
                ip >= first && ip < first + capacity
            }
            (PoolRange::V6 { first, capacity }, net::IpAddr::V6(ip)) => {
                if ip.is_unspecified()
                    || ip.is_loopback()
                    || ip.is_multicast()
                    || ip.is_unicast_link_local()
                {
                    return false;
                }
                let ip = u128::from(ip);
                ip >= first && ip - first < capacity as u128
            }
            _ => false,
        }
    }

    fn family(&self) -> IpFamily {
        match self.range {
            PoolRange::V4 { .. } => IpFamily::V4,
            PoolRange::V6 { .. } => IpFamily::V6,
        }
    }

    #[allow(dead_code)]
    pub fn gateway(&self) -> net::Ipv4Addr {
        net::Ipv4Addr::from(self.gateway)
    }

    #[allow(dead_code)]
    pub fn ipnet(&self) -> ipnet::IpNet {
        self.ipnet
    }

    #[allow(dead_code)]
    pub async fn copy_from(&mut self, src: &Self) {
        src.store.copy_to(&mut self.store).await;
    }

    async fn get(&mut self, host: &str) -> Result<net::IpAddr, Error> {
        let capacity = match self.range {
            PoolRange::V4 { capacity, .. } | PoolRange::V6 { capacity, .. } => {
                capacity
            }
        };
        for _ in 0..capacity {
            let ip = match self.range {
                PoolRange::V4 { first, .. } => {
                    net::IpAddr::V4(net::Ipv4Addr::from(first + self.cursor))
                }
                PoolRange::V6 { first, .. } => {
                    net::IpAddr::V6(net::Ipv6Addr::from(first + self.cursor as u128))
                }
            };
            self.cursor = (self.cursor + 1) % capacity;
            if self.is_allocatable(ip) && !self.store.exist(ip).await {
                self.store.put_by_ip(ip, host).await;
                return Ok(ip);
            }
        }

        Err(Error::DNSError(format!(
            "fake-ip pool exhausted for range {}",
            self.ipnet
        )))
    }

    fn ip_to_uint(ip: &net::Ipv4Addr) -> u32 {
        BigEndian::read_u32(&ip.octets())
    }
}

#[cfg(test)]
mod tests {
    use std::{net, sync::Arc};

    use crate::{
        app::dns::fakeip::{FileStore, mem_store::InMemStore},
        common::trie,
    };

    use super::{FakeDns, Opts};

    #[tokio::test]
    async fn test_inmem_basic() {
        let ipnet = "192.168.0.0/29".parse::<ipnet::IpNet>().unwrap();
        let store = Box::new(InMemStore::new(10));
        let mut pool = FakeDns::new(Opts {
            ipnet,
            skipped_hostnames: None,
            store,
        })
        .unwrap();

        let first = pool.lookup("foo.com").await.unwrap();
        let last = pool.lookup("bar.com").await.unwrap();

        let bar = pool.reverse_lookup(last).await;

        assert_eq!(first, net::IpAddr::from([192, 168, 0, 2]));
        assert_eq!(
            pool.lookup("foo.com").await.unwrap(),
            net::IpAddr::from([192, 168, 0, 2])
        );
        assert_eq!(last, net::IpAddr::from([192, 168, 0, 3]));
        assert!(bar.is_some());
        assert_eq!(bar, Some("bar.com".into()));
        assert_eq!(pool.gateway(), net::IpAddr::from([192, 168, 0, 1]));
        assert_eq!(pool.ipnet().to_string(), ipnet.to_string());
        assert!(pool.exist(net::IpAddr::from([192, 168, 0, 3])).await);
        assert!(!pool.exist(net::IpAddr::from([192, 168, 0, 4])).await);
        assert!(!pool.exist("::1".parse().unwrap()).await);
    }

    #[tokio::test]
    async fn fake_ip_host_mapping_is_case_insensitive() {
        let mut pool = FakeDns::new(Opts {
            ipnet: "192.168.0.0/29".parse().unwrap(),
            skipped_hostnames: None,
            store: Box::new(InMemStore::new(10)),
        })
        .unwrap();

        let ip = pool.lookup("ExAmPlE.CoM").await.unwrap();

        assert_eq!(pool.lookup("example.com").await.unwrap(), ip);
        assert_eq!(pool.lookup_existing("EXAMPLE.COM").await, Some(ip));
        assert_eq!(
            pool.reverse_lookup(ip).await.as_deref(),
            Some("example.com")
        );
    }

    #[tokio::test]
    async fn test_allocates_every_usable_address_without_gateway_or_broadcast() {
        let store = Box::new(InMemStore::new(10));
        let mut pool = FakeDns::new(Opts {
            ipnet: "192.168.0.0/29".parse().unwrap(),
            skipped_hostnames: None,
            store,
        })
        .unwrap();

        let mut allocated = Vec::new();
        for index in 0..5 {
            allocated.push(pool.lookup(&format!("{index}.example")).await.unwrap());
        }

        assert_eq!(
            allocated,
            [
                "192.168.0.2",
                "192.168.0.3",
                "192.168.0.4",
                "192.168.0.5",
                "192.168.0.6"
            ]
            .map(|ip| ip.parse::<net::IpAddr>().unwrap())
        );
    }

    #[tokio::test]
    async fn test_30_pool_allocates_its_single_usable_address() {
        let store = Box::new(InMemStore::new(10));
        let mut pool = FakeDns::new(Opts {
            ipnet: "192.168.0.0/30".parse().unwrap(),
            skipped_hostnames: None,
            store,
        })
        .unwrap();

        assert_eq!(
            pool.lookup("example.com").await.unwrap(),
            "192.168.0.2".parse::<net::IpAddr>().unwrap()
        );
    }

    #[test]
    fn test_rejects_unsupported_ranges() {
        for ipnet in [
            "192.168.0.0/31",
            "192.168.0.1/32",
            "192.168.0.0/15",
            "fd00::/128",
        ] {
            let result = FakeDns::new(Opts {
                ipnet: ipnet.parse().unwrap(),
                skipped_hostnames: None,
                store: Box::new(InMemStore::new(10)),
            });
            assert!(result.is_err(), "{ipnet} must be rejected");
        }
    }

    #[test]
    fn test_rejects_reserved_ipv6_fake_ip_ranges() {
        for ipnet in ["::/64", "::1/128", "fe80::/64", "ff00::/8"] {
            let result = FakeDns::new_v6(Opts {
                ipnet: ipnet.parse().unwrap(),
                skipped_hostnames: None,
                store: Box::new(InMemStore::new(10)),
            });
            assert!(result.is_err(), "{ipnet} must be rejected");
        }
    }

    #[tokio::test]
    async fn ipv6_pool_allocates_and_reverse_looks_up_hosts() {
        let mut pool = FakeDns::new_v6(Opts {
            ipnet: "fd00::/126".parse().unwrap(),
            skipped_hostnames: None,
            store: Box::new(InMemStore::new(10)),
        })
        .unwrap();

        let first = pool.lookup("example.com").await.unwrap();
        let second = pool.lookup("other.example").await.unwrap();

        assert_eq!(first, "fd00::1".parse::<net::IpAddr>().unwrap());
        assert_eq!(second, "fd00::2".parse::<net::IpAddr>().unwrap());
        assert_eq!(pool.lookup("example.com").await.unwrap(), first);
        assert!(pool.is_fake_ip(first).await);
        assert_eq!(
            pool.reverse_lookup(first).await.as_deref(),
            Some("example.com")
        );
        assert!(!pool.is_fake_ip("fd00::3".parse().unwrap()).await);
    }

    #[tokio::test]
    async fn file_store_keeps_ipv4_and_ipv6_mappings_for_the_same_host() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("cache.yaml");
        let cache = crate::app::profile::ThreadSafeCacheFile::new(
            path.to_str().unwrap(),
            false,
        );
        let mut ipv4 = FakeDns::new(Opts {
            ipnet: "198.18.0.0/16".parse().unwrap(),
            skipped_hostnames: None,
            store: Box::new(FileStore::new(cache.clone())),
        })
        .unwrap();
        let mut ipv6 = FakeDns::new_v6(Opts {
            ipnet: "fd00::/96".parse().unwrap(),
            skipped_hostnames: None,
            store: Box::new(FileStore::new(cache.clone())),
        })
        .unwrap();

        let ipv4_address = ipv4.lookup("example.com").await.unwrap();
        let ipv6_address = ipv6.lookup("example.com").await.unwrap();

        assert_eq!(ipv4_address, "198.18.0.2".parse::<net::IpAddr>().unwrap());
        assert_eq!(ipv6_address, "fd00::1".parse::<net::IpAddr>().unwrap());
        assert_ne!(ipv4_address, ipv6_address);
        assert_eq!(ipv4.lookup("example.com").await.unwrap(), ipv4_address);
        assert_eq!(ipv6.lookup("example.com").await.unwrap(), ipv6_address);
        assert_eq!(
            ipv4.reverse_lookup(ipv4_address).await.as_deref(),
            Some("example.com")
        );
        assert_eq!(
            ipv6.reverse_lookup(ipv6_address).await.as_deref(),
            Some("example.com")
        );

        let mut restored_ipv4 = FakeDns::new(Opts {
            ipnet: "198.18.0.0/16".parse().unwrap(),
            skipped_hostnames: None,
            store: Box::new(FileStore::new(cache.clone())),
        })
        .unwrap();
        let mut restored_ipv6 = FakeDns::new_v6(Opts {
            ipnet: "fd00::/96".parse().unwrap(),
            skipped_hostnames: None,
            store: Box::new(FileStore::new(cache.clone())),
        })
        .unwrap();

        assert_eq!(
            restored_ipv4.lookup_existing("example.com").await,
            Some(ipv4_address)
        );
        assert_eq!(
            restored_ipv6.lookup_existing("example.com").await,
            Some(ipv6_address)
        );

        let mut changed_ipv4_range = FakeDns::new(Opts {
            ipnet: "198.19.0.0/16".parse().unwrap(),
            skipped_hostnames: None,
            store: Box::new(FileStore::new(cache.clone())),
        })
        .unwrap();
        assert_eq!(
            changed_ipv4_range.lookup_existing("example.com").await,
            None
        );
        assert_eq!(
            restored_ipv6.lookup_existing("example.com").await,
            Some(ipv6_address),
            "cleaning the IPv4 cache entry must preserve its IPv6 counterpart"
        );
    }

    #[tokio::test]
    async fn exhausted_pool_keeps_existing_host_mappings_stable() {
        let store = Box::new(InMemStore::new(2));

        let ipnet = "192.168.0.0/29".parse::<ipnet::IpNet>().unwrap();
        let mut pool = FakeDns::new(Opts {
            ipnet,
            skipped_hostnames: None,
            store,
        })
        .unwrap();

        let foo = pool.lookup("foo.com").await.unwrap();
        let bar = pool.lookup("bar.com").await.unwrap();

        for i in 0..3 {
            pool.lookup(&format!("{}.com", i)).await.unwrap();
        }

        assert!(pool.lookup("baz.com").await.is_err());
        assert_eq!(pool.lookup("foo.com").await.unwrap(), foo);
        assert_eq!(pool.lookup("bar.com").await.unwrap(), bar);
    }

    #[tokio::test]
    async fn test_pool_skip() {
        let store = Box::new(InMemStore::new(10));

        let ipnet = "192.168.0.0/30".parse::<ipnet::IpNet>().unwrap();
        let mut tree = trie::StringTrie::new();
        tree.insert("example.com", Arc::new(false));

        let pool = FakeDns::new(Opts {
            ipnet,
            skipped_hostnames: Some(tree),
            store,
        })
        .unwrap();

        assert!(pool.should_skip("example.com"));
        assert!(pool.should_skip("EXAMPLE.COM"));
        assert!(!pool.should_skip("foo.com"));
    }

    #[tokio::test]
    async fn persisted_mapping_outside_current_range_is_replaced() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("cache.yaml");
        let cache = crate::app::profile::ThreadSafeCacheFile::new(
            path.to_str().unwrap(),
            false,
        );
        cache.set_host_to_ip("stale.example", "203.0.113.7").await;
        cache.set_ip_to_host("203.0.113.7", "stale.example").await;
        let mut pool = FakeDns::new(Opts {
            ipnet: "192.168.0.0/29".parse().unwrap(),
            skipped_hostnames: None,
            store: Box::new(FileStore::new(cache)),
        })
        .unwrap();

        assert_eq!(pool.lookup_existing("stale.example").await, None);
        let replacement = pool.lookup("stale.example").await.unwrap();

        assert_eq!(replacement, "192.168.0.2".parse::<net::IpAddr>().unwrap());
        assert_eq!(
            pool.reverse_lookup("203.0.113.7".parse().unwrap()).await,
            None
        );
    }

    #[tokio::test]
    #[ignore = "copy not implemented"]
    async fn test_pool_clone() {
        let store = Box::new(InMemStore::new(2));

        let ipnet = "192.168.0.0/24".parse::<ipnet::IpNet>().unwrap();
        let mut pool = FakeDns::new(Opts {
            ipnet,
            skipped_hostnames: None,
            store,
        })
        .unwrap();

        let first = pool.lookup("foo.com").await.unwrap();
        let last = pool.lookup("bar.com").await.unwrap();
        assert_eq!(first, net::IpAddr::from([192, 168, 0, 2]));
        assert_eq!(last, net::IpAddr::from([192, 168, 0, 3]));

        let store = Box::new(InMemStore::new(2));

        let mut new_pool = FakeDns::new(Opts {
            ipnet,
            skipped_hostnames: None,
            store,
        })
        .unwrap();

        new_pool.copy_from(&pool).await;

        assert!(new_pool.reverse_lookup(first).await.is_some());
        assert!(new_pool.reverse_lookup(last).await.is_some());
    }

    #[tokio::test]
    async fn test_is_fake_ip_excludes_broadcast_and_unallocated() {
        let store = Box::new(InMemStore::new(10));

        // Use 198.18.0.0/16 (the default fake-ip-range) to mirror the real
        // production setup described in the bug report, where the TUN gateway
        // is 198.18.0.1/24 and its subnet broadcast 198.18.0.255 fell inside
        // the wider /16 fake-ip range.
        let ipnet = "198.18.0.0/16".parse::<ipnet::IpNet>().unwrap();
        let mut pool = FakeDns::new(Opts {
            ipnet,
            skipped_hostnames: None,
            store,
        })
        .unwrap();

        // Allocate one real fake IP.
        let allocated = pool.lookup("foo.com").await.unwrap();
        assert!(
            pool.is_fake_ip(allocated).await,
            "allocated IP must be fake"
        );

        // Directed broadcast for the /24 TUN subnet (198.18.0.0/24) – never
        // allocated, yet it falls inside the /16 range.
        let directed_broadcast: net::IpAddr = "198.18.0.255".parse().unwrap();
        assert!(
            !pool.is_fake_ip(directed_broadcast).await,
            "directed broadcast must not be treated as a fake IP"
        );

        // Global broadcast must never be a fake IP.
        let global_broadcast: net::IpAddr = "255.255.255.255".parse().unwrap();
        assert!(
            !pool.is_fake_ip(global_broadcast).await,
            "255.255.255.255 must not be a fake IP"
        );

        // A multicast address must never be a fake IP.
        let multicast: net::IpAddr = "224.0.0.1".parse().unwrap();
        assert!(
            !pool.is_fake_ip(multicast).await,
            "multicast must not be a fake IP"
        );

        // An IP in the range that was never allocated must not be fake.
        let unallocated: net::IpAddr = "198.18.1.1".parse().unwrap();
        assert!(
            !pool.is_fake_ip(unallocated).await,
            "unallocated in-range IP must not be treated as a fake IP"
        );
    }
}
