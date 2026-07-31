use std::{
    collections::HashMap,
    io,
    sync::atomic::{AtomicUsize, Ordering},
};

use tokio::sync::Mutex;

use crate::{
    app::remote_content_manager::ProxyManager,
    proxy::AnyOutboundHandler,
    session::{Session, SocksAddr},
};

#[derive(Default)]
pub struct RoundRobin {
    next: AtomicUsize,
}

impl RoundRobin {
    pub fn select(
        &self,
        proxies: &[AnyOutboundHandler],
    ) -> io::Result<AnyOutboundHandler> {
        if proxies.is_empty() {
            return Err(io::Error::other("load-balance group has no proxies"));
        }
        let index = self.next.fetch_add(1, Ordering::Relaxed) % proxies.len();
        Ok(proxies[index].clone())
    }
}

#[derive(Default)]
pub struct ConsistentHash;

impl ConsistentHash {
    pub fn select(
        &self,
        proxies: &[AnyOutboundHandler],
        session: &Session,
    ) -> io::Result<AnyOutboundHandler> {
        if proxies.is_empty() {
            return Err(io::Error::other("load-balance group has no proxies"));
        }
        let key = destination_key(session);
        let index = jump_hash(stable_hash(key.as_bytes()), proxies.len());
        Ok(proxies[index].clone())
    }
}

pub struct StickySession {
    cache: Mutex<HashMap<u64, usize>>,
    proxy_manager: ProxyManager,
}

impl StickySession {
    pub fn new(proxy_manager: ProxyManager) -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            proxy_manager,
        }
    }

    pub async fn select(
        &self,
        proxies: &[AnyOutboundHandler],
        session: &Session,
    ) -> io::Result<AnyOutboundHandler> {
        if proxies.is_empty() {
            return Err(io::Error::other("load-balance group has no proxies"));
        }
        let key = stable_hash(
            format!("{}-{}", session.source.ip(), destination_key(session))
                .as_bytes(),
        );
        if let Some(index) = self.cache.lock().await.get(&key).copied()
            && let Some(proxy) = proxies.get(index)
            && self.proxy_manager.alive(proxy.name()).await
        {
            return Ok(proxy.clone());
        }

        let start = jump_hash(key, proxies.len());
        for offset in 0..proxies.len() {
            let index = (start + offset) % proxies.len();
            let proxy = &proxies[index];
            if self.proxy_manager.alive(proxy.name()).await {
                let mut cache = self.cache.lock().await;
                if cache.len() >= 1024 && !cache.contains_key(&key) {
                    cache.clear();
                }
                cache.insert(key, index);
                return Ok(proxy.clone());
            }
        }
        Err(io::Error::other("no healthy proxy found"))
    }
}

fn destination_key(session: &Session) -> String {
    match &session.destination {
        SocksAddr::Ip(address) => address.ip().to_string(),
        SocksAddr::Domain(domain, _) => domain.to_ascii_lowercase(),
    }
}

fn stable_hash(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}

fn jump_hash(mut key: u64, buckets: usize) -> usize {
    let mut previous = -1i64;
    let mut next = 0i64;
    while next < buckets as i64 {
        previous = next;
        key = key.wrapping_mul(2862933555777941757).wrapping_add(1);
        next = ((previous + 1) as f64 * (1u64 << 31) as f64
            / ((key >> 33) + 1) as f64) as i64;
    }
    previous as usize
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::proxy::utils::test_utils::noop::{NoopOutboundHandler, NoopResolver};

    fn proxies(names: &[&str]) -> Vec<AnyOutboundHandler> {
        names
            .iter()
            .map(|name| {
                Arc::new(NoopOutboundHandler {
                    name: (*name).to_string(),
                }) as AnyOutboundHandler
            })
            .collect()
    }

    #[test]
    fn round_robin_cycles_in_declared_order() {
        let strategy = RoundRobin::default();
        let proxies = proxies(&["a", "b", "c"]);
        let selected = (0..7)
            .map(|_| strategy.select(&proxies).unwrap().name().to_string())
            .collect::<Vec<_>>();
        assert_eq!(selected, ["a", "b", "c", "a", "b", "c", "a"]);
    }

    #[test]
    fn round_robin_rejects_empty_proxy_lists() {
        assert!(RoundRobin::default().select(&[]).is_err());
    }

    fn session(host: &str) -> Session {
        Session {
            destination: SocksAddr::Domain(host.to_string(), 443),
            ..Default::default()
        }
    }

    #[test]
    fn consistent_hash_keeps_the_same_destination_stable() {
        let strategy = ConsistentHash;
        let proxies = proxies(&["a", "b", "c"]);
        let first = strategy
            .select(&proxies, &session("api.example.com"))
            .unwrap();
        for _ in 0..20 {
            assert_eq!(
                strategy
                    .select(&proxies, &session("api.example.com"))
                    .unwrap()
                    .name(),
                first.name()
            );
        }
    }

    #[test]
    fn consistent_hash_distributes_multiple_destinations() {
        let strategy = ConsistentHash;
        let proxies = proxies(&["a", "b", "c"]);
        let selected = (0..100)
            .map(|index| {
                strategy
                    .select(&proxies, &session(&format!("host{index}.example")))
                    .unwrap()
                    .name()
                    .to_string()
            })
            .collect::<std::collections::HashSet<_>>();
        assert!(selected.len() > 1);
    }

    #[test]
    fn consistent_hash_rejects_empty_proxy_lists() {
        assert!(ConsistentHash.select(&[], &Session::default()).is_err());
    }

    #[tokio::test]
    async fn sticky_session_keeps_a_healthy_selection_and_fails_over() {
        let manager = ProxyManager::new(Arc::new(NoopResolver), None);
        let proxies = proxies(&["a", "b", "c"]);
        for proxy in &proxies {
            manager.report_alive(proxy.name(), true).await;
        }
        let strategy = StickySession::new(manager.clone());
        let mut session = session("api.example.com");
        session.source = "192.168.1.20:50000".parse().unwrap();

        let first = strategy.select(&proxies, &session).await.unwrap();
        assert_eq!(
            strategy.select(&proxies, &session).await.unwrap().name(),
            first.name()
        );

        manager.report_alive(first.name(), false).await;
        let replacement = strategy.select(&proxies, &session).await.unwrap();
        assert_ne!(replacement.name(), first.name());
        assert_eq!(
            strategy.select(&proxies, &session).await.unwrap().name(),
            replacement.name()
        );
    }

    #[tokio::test]
    async fn sticky_session_rejects_when_every_proxy_is_unhealthy() {
        let manager = ProxyManager::new(Arc::new(NoopResolver), None);
        let proxies = proxies(&["a", "b"]);
        for proxy in &proxies {
            manager.report_alive(proxy.name(), false).await;
        }
        let strategy = StickySession::new(manager);
        assert!(
            strategy
                .select(&proxies, &Session::default())
                .await
                .is_err()
        );
    }
}
