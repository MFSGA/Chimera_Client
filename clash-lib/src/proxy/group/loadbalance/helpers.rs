use std::{
    io,
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::{
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
        let key = match &session.destination {
            SocksAddr::Ip(address) => address.ip().to_string(),
            SocksAddr::Domain(domain, _) => domain.to_ascii_lowercase(),
        };
        let index = jump_hash(stable_hash(key.as_bytes()), proxies.len());
        Ok(proxies[index].clone())
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
    use crate::proxy::utils::test_utils::noop::NoopOutboundHandler;

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
}
