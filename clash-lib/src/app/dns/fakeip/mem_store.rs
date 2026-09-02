use std::net::IpAddr;

use async_trait::async_trait;

use super::Store;

pub struct InMemStore {
    itoh: lru_time_cache::LruCache<IpAddr, String>,
    htoi: lru_time_cache::LruCache<String, IpAddr>,
}

impl InMemStore {
    pub fn new(size: usize) -> Self {
        Self {
            itoh: lru_time_cache::LruCache::with_capacity(size),
            htoi: lru_time_cache::LruCache::with_capacity(size),
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
        let ip = *self.htoi.get_mut(host)?;
        // Cross-check: if itoh doesn't map this IP back to the same host,
        // the entry is stale (e.g. htoi survived but itoh was evicted and
        // the IP was reassigned). Treat as a miss and clean up.
        if self.itoh.get(&ip).map(|h| h.as_str()) != Some(host) {
            self.htoi.remove(host);
            return None;
        }
        // Touch itoh LRU to keep access ordering in sync.
        self.itoh.get_mut(&ip);
        Some(ip)
    }

    async fn pub_by_host(&mut self, host: &str, ip: IpAddr) {
        self.insert_pair(host, ip);
    }

    async fn get_by_ip(&mut self, ip: IpAddr) -> Option<String> {
        let host = self.itoh.get_mut(&ip)?;
        // Cross-check: if htoi doesn't map this host back to the same IP,
        // the entry is stale.
        if self.htoi.get(host).copied() != Some(ip) {
            self.itoh.remove(&ip);
            return None;
        }
        let host = host.clone();
        // Touch htoi LRU to keep access ordering in sync.
        self.htoi.get_mut(&host);
        Some(host)
    }

    async fn put_by_ip(&mut self, ip: IpAddr, host: &str) {
        self.insert_pair(host, ip);
    }

    async fn del_by_ip(&mut self, ip: IpAddr) {
        if let Some(host) = self.itoh.remove(&ip) {
            self.htoi.remove(&host);
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
