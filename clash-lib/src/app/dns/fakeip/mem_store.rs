use std::{collections::HashMap, net::IpAddr};

use async_trait::async_trait;

use super::Store;

pub struct InMemStore {
    itoh: HashMap<IpAddr, String>,
    htoi: HashMap<String, IpAddr>,
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
    fn insert_pair(&mut self, host: &str, ip: IpAddr) {
        if let Some(old_host) = self.itoh.remove(&ip)
            && old_host != host
        {
            self.htoi.remove(&old_host);
        }
        if let Some(old_ip) = self.htoi.remove(host)
            && old_ip != ip
        {
            self.itoh.remove(&old_ip);
        }
        self.itoh.insert(ip, host.to_string());
        self.htoi.insert(host.to_string(), ip);
    }
}

#[async_trait]
impl Store for InMemStore {
    async fn get_by_host(&mut self, host: &str) -> Option<IpAddr> {
        let ip = *self.htoi.get(host)?;
        // Cross-check: if itoh doesn't map this IP back to the same host,
        // the entry is stale. Treat it as a miss and clean up.
        if self.itoh.get(&ip).map(|h| h.as_str()) != Some(host) {
            self.htoi.remove(host);
            return None;
        }
        Some(ip)
    }

    async fn pub_by_host(&mut self, host: &str, ip: IpAddr) {
        self.insert_pair(host, ip);
    }

    async fn get_by_ip(&mut self, ip: IpAddr) -> Option<String> {
        let host = self.itoh.get(&ip)?;
        // Cross-check: if htoi doesn't map this host back to the same IP,
        // the entry is stale.
        if self.htoi.get(host).copied() != Some(ip) {
            self.itoh.remove(&ip);
            return None;
        }
        Some(host.clone())
    }

    async fn put_by_ip(&mut self, ip: IpAddr, host: &str) {
        self.insert_pair(host, ip);
    }

    async fn del_by_host(&mut self, host: &str) {
        if let Some(ip) = self.htoi.remove(host)
            && self.itoh.get(&ip).map(String::as_str) == Some(host)
        {
            self.itoh.remove(&ip);
        }
    }

    async fn exist(&mut self, ip: IpAddr) -> bool {
        // An IP exists only if both forward and reverse mappings agree.
        self.itoh
            .get(&ip)
            .is_some_and(|host| self.htoi.get(host).copied() == Some(ip))
    }

    async fn copy_to(&self, #[allow(unused)] store: &mut Box<dyn Store>) {
        // TODO: copy
        // NOTE: use file based persistence store
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{InMemStore, Store};

    #[tokio::test]
    async fn reassigning_host_removes_old_ip_mapping() {
        let mut store = InMemStore::new(8);
        let first: IpAddr = "198.18.0.2".parse().unwrap();
        let second: IpAddr = "198.18.0.3".parse().unwrap();

        store.put_by_ip(first, "example.com").await;
        store.put_by_ip(second, "example.com").await;

        assert_eq!(store.get_by_host("example.com").await, Some(second));
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

        store.pub_by_host("old.example", ip).await;
        store.pub_by_host("new.example", ip).await;

        assert_eq!(store.get_by_host("old.example").await, None);
        assert_eq!(store.get_by_host("new.example").await, Some(ip));
        assert_eq!(store.get_by_ip(ip).await.as_deref(), Some("new.example"));
    }
}
