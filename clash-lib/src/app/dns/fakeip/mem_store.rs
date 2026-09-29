use std::{collections::HashMap, net::IpAddr};

use async_trait::async_trait;

use super::{IpFamily, Store};

pub struct InMemStore {
    itoh: HashMap<IpAddr, String>,
    htoi: HashMap<(String, IpFamily), IpAddr>,
}

impl InMemStore {
    /// Creates a bidirectional mapping store with an initial allocation hint.
    /// Mappings are not evicted; `FakeDns` bounds growth by its address pool.
    pub fn new(initial_capacity: usize) -> Self {
        Self {
            itoh: HashMap::with_capacity(initial_capacity),
            htoi: HashMap::with_capacity(initial_capacity),
        }
    }

    /// Insert or update a bidirectional mapping `host <-> ip`, ensuring that
    /// any old conflicting associations for either the host or the IP are
    /// purged.
    fn insert_pair(&mut self, host: &str, family: IpFamily, ip: IpAddr) {
        if let Some(old_host) = self.itoh.remove(&ip)
            && old_host != host
        {
            self.htoi.remove(&(old_host, family));
        }
        let key = (host.to_string(), family);
        if let Some(old_ip) = self.htoi.remove(&key)
            && old_ip != ip
        {
            self.itoh.remove(&old_ip);
        }
        self.itoh.insert(ip, host.to_string());
        self.htoi.insert(key, ip);
    }
}

#[async_trait]
impl Store for InMemStore {
    async fn get_by_host(&mut self, host: &str, family: IpFamily) -> Option<IpAddr> {
        let key = (host.to_string(), family);
        let ip = *self.htoi.get(&key)?;
        // Cross-check: if itoh doesn't map this IP back to the same host,
        // the entry is stale. Treat it as a miss and clean up.
        if self.itoh.get(&ip).map(|h| h.as_str()) != Some(host)
            || IpFamily::of(ip) != family
        {
            self.htoi.remove(&key);
            return None;
        }
        Some(ip)
    }

    async fn pub_by_host(&mut self, host: &str, family: IpFamily, ip: IpAddr) {
        self.insert_pair(host, family, ip);
    }

    async fn get_by_ip(&mut self, ip: IpAddr) -> Option<String> {
        let host = self.itoh.get(&ip)?;
        // Cross-check: if htoi doesn't map this host back to the same IP,
        // the entry is stale.
        if self.htoi.get(&(host.clone(), IpFamily::of(ip))).copied() != Some(ip) {
            self.itoh.remove(&ip);
            return None;
        }
        Some(host.clone())
    }

    async fn put_by_ip(&mut self, ip: IpAddr, host: &str) {
        self.insert_pair(host, IpFamily::of(ip), ip);
    }

    async fn del_by_host(&mut self, host: &str, family: IpFamily) {
        if let Some(ip) = self.htoi.remove(&(host.to_string(), family))
            && self.itoh.get(&ip).map(String::as_str) == Some(host)
        {
            self.itoh.remove(&ip);
        }
    }

    async fn exist(&mut self, ip: IpAddr) -> bool {
        // An IP exists only if both forward and reverse mappings agree.
        self.itoh.get(&ip).is_some_and(|host| {
            self.htoi.get(&(host.clone(), IpFamily::of(ip))).copied() == Some(ip)
        })
    }

    async fn copy_to(&self, #[allow(unused)] store: &mut Box<dyn Store>) {
        // TODO: copy
        // NOTE: use file based persistence store
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{InMemStore, IpFamily, Store};

    #[tokio::test]
    async fn reassigning_host_removes_old_ip_mapping() {
        let mut store = InMemStore::new(8);
        let first: IpAddr = "198.18.0.2".parse().unwrap();
        let second: IpAddr = "198.18.0.3".parse().unwrap();

        store.put_by_ip(first, "example.com").await;
        store.put_by_ip(second, "example.com").await;

        assert_eq!(
            store.get_by_host("example.com", IpFamily::V4).await,
            Some(second)
        );
        assert_eq!(store.get_by_ip(first).await, None);
        assert_eq!(
            store.get_by_ip(second).await.as_deref(),
            Some("example.com")
        );
    }

    #[tokio::test]
    async fn reassigning_ip_removes_old_host_mapping() {
        let mut store = InMemStore::new(8);
        let ip: IpAddr = "198.18.0.2".parse().unwrap();

        store.pub_by_host("old.example", IpFamily::V4, ip).await;
        store.pub_by_host("new.example", IpFamily::V4, ip).await;

        assert_eq!(store.get_by_host("old.example", IpFamily::V4).await, None);
        assert_eq!(
            store.get_by_host("new.example", IpFamily::V4).await,
            Some(ip)
        );
        assert_eq!(store.get_by_ip(ip).await.as_deref(), Some("new.example"));
    }
}
