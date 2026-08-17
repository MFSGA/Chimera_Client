use std::{
    io::Cursor,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use futures::future::BoxFuture;
use murmur3::murmur3_32;
use public_suffix::{DEFAULT_PROVIDER, EffectiveTLDProvider};
use tokio::sync::Mutex;

use crate::{
    app::remote_content_manager::ProxyManager, proxy::AnyOutboundHandler,
    session::Session,
};

pub type StrategyFn = Box<
    dyn FnMut(
            Vec<AnyOutboundHandler>,
            &Session,
        ) -> BoxFuture<'static, std::io::Result<AnyOutboundHandler>>
        + Send
        + Sync,
>;

fn get_key(sess: &Session) -> String {
    match &sess.destination {
        crate::session::SocksAddr::Ip(addr) => addr.ip().to_string(),
        crate::session::SocksAddr::Domain(host, _) => DEFAULT_PROVIDER
            .effective_tld_plus_one(host)
            .map(|s| s.to_string())
            .unwrap_or_else(|_| host.clone()),
    }
}

fn get_key_src_and_dst(sess: &Session) -> String {
    let dst = get_key(sess);
    let src = sess.source.ip().to_string();
    format!("{src}-{dst}")
}

fn jump_hash(key: u64, buckets: i32) -> i32 {
    let mut key = key;
    let mut b = -1i64;
    let mut j = 0i64;
    while j < buckets as i64 {
        b = j;
        key = key.wrapping_mul(2862933555777941757).wrapping_add(1);
        j = ((b + 1) as f64 * (1i64 << 31) as f64 / ((key >> 33) + 1) as f64) as i64;
    }
    b as i32
}

pub fn strategy_rr() -> StrategyFn {
    let mut index = 0usize;
    Box::new(move |proxies: Vec<AnyOutboundHandler>, _: &Session| {
        if proxies.is_empty() {
            return Box::pin(futures::future::err(std::io::Error::other(
                "no proxy found",
            )));
        }
        let selected = proxies[index % proxies.len()].clone();
        index = (index + 1) % proxies.len();
        Box::pin(futures::future::ok(selected))
    })
}

pub fn strategy_consistent_hashring() -> StrategyFn {
    Box::new(move |proxies, sess| {
        if proxies.is_empty() {
            return Box::pin(futures::future::err(std::io::Error::other(
                "no proxy found",
            )));
        }
        let key = murmur3_32(&mut Cursor::new(get_key(sess)), 0).unwrap() as u64;
        let index = jump_hash(key, proxies.len() as i32);
        Box::pin(futures::future::ok(proxies[index as usize].clone()))
    })
}

pub fn strategy_sticky_session(proxy_manager: ProxyManager) -> StrategyFn {
    let max_retry = 5;
    let lru_cache: lru_time_cache::LruCache<u64, usize> =
        lru_time_cache::LruCache::with_expiry_duration_and_capacity(
            std::time::Duration::from_secs(60 * 10),
            1024,
        );
    let lru_cache = Arc::new(Mutex::new(lru_cache));

    Box::new(move |proxies, sess| {
        let key = murmur3_32(&mut Cursor::new(get_key_src_and_dst(sess)), 0).unwrap()
            as u64;
        let proxy_manager = proxy_manager.clone();
        let lru_cache = lru_cache.clone();
        let timestamp = || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64
        };

        Box::pin(async move {
            if proxies.is_empty() {
                return Err(std::io::Error::other("no proxy found"));
            }

            let buckets = proxies.len() as i32;
            let (start_index, hit) = match lru_cache.lock().await.get(&key) {
                Some(&index) => (index, true),
                None => (jump_hash(key + timestamp(), buckets) as usize, false),
            };

            let mut index = start_index;
            for _ in 0..max_retry {
                if let Some(proxy) = proxies.get(index)
                    && proxy_manager.alive(proxy.name()).await
                {
                    if index != start_index || !hit {
                        lru_cache.lock().await.insert(key, index);
                    }
                    return Ok(proxy.clone());
                }
                index = jump_hash(key + timestamp(), buckets) as usize;
            }

            lru_cache.lock().await.insert(key, 0);
            Err(std::io::Error::other("no proxy found"))
        })
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        proxy::utils::test_utils::noop::{NoopOutboundHandler, NoopResolver},
        session::SocksAddr,
    };

    fn proxies() -> Vec<AnyOutboundHandler> {
        vec![
            Arc::new(NoopOutboundHandler {
                name: "a".to_string(),
            }) as _,
            Arc::new(NoopOutboundHandler {
                name: "b".to_string(),
            }) as _,
        ]
    }

    #[tokio::test]
    async fn round_robin_cycles_proxies() {
        let mut strategy = strategy_rr();
        let session = Session::default();
        let first = strategy(proxies(), &session).await.unwrap();
        let second = strategy(proxies(), &session).await.unwrap();
        assert_eq!(first.name(), "a");
        assert_eq!(second.name(), "b");
    }

    #[tokio::test]
    async fn consistent_hashing_is_stable_for_same_domain() {
        let mut strategy = strategy_consistent_hashring();
        let mut session = Session::default();
        session.destination = SocksAddr::Domain("www.example.com".to_string(), 443);
        let first = strategy(proxies(), &session).await.unwrap();
        let second = strategy(proxies(), &session).await.unwrap();
        assert_eq!(first.name(), second.name());
    }

    #[tokio::test]
    async fn sticky_session_reuses_cached_proxy_and_checks_health() {
        let manager = ProxyManager::new(Arc::new(NoopResolver), None);
        manager.report_alive("a", false).await;
        manager.report_alive("b", false).await;

        let mut strategy = strategy_sticky_session(manager.clone());
        let mut session = Session::default();
        session.destination = SocksAddr::Domain("www.example.com".to_string(), 443);

        assert!(strategy(proxies(), &session).await.is_err());

        manager.report_alive("a", true).await;
        manager.report_alive("b", true).await;
        let first = strategy(proxies(), &session).await.unwrap();
        let second = strategy(proxies(), &session).await.unwrap();
        assert_eq!(first.name(), second.name());
    }
}
