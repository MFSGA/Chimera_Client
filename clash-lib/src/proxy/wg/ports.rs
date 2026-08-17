use std::{collections::VecDeque, ops::Range, sync::Arc};

use anyhow::Context;
use rand::seq::SliceRandom;

const MIN_PORT: u16 = 1025;
const MAX_PORT: u16 = 60000;
const PORT_RANGE: Range<u16> = MIN_PORT..MAX_PORT;

#[derive(Clone)]
pub struct PortPool {
    inner: Arc<tokio::sync::RwLock<TcpPortPoolInner>>,
}

impl Default for PortPool {
    fn default() -> Self {
        Self::new()
    }
}

impl PortPool {
    pub fn new() -> Self {
        let mut inner = TcpPortPoolInner::default();
        let mut ports: Vec<u16> = PORT_RANGE.collect();
        ports.shuffle(&mut rand::rng());
        ports
            .into_iter()
            .for_each(|port| inner.queue.push_back(port));
        Self {
            inner: Arc::new(tokio::sync::RwLock::new(inner)),
        }
    }

    pub async fn next(&self) -> anyhow::Result<u16> {
        let mut inner = self.inner.write().await;
        inner
            .queue
            .pop_front()
            .with_context(|| "virtual port pool is exhausted")
    }

    pub async fn release(&self, port: u16) {
        self.inner.write().await.queue.push_back(port);
    }
}

#[derive(Debug, Default)]
struct TcpPortPoolInner {
    queue: VecDeque<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wireguard_port_pool_releases_virtual_port() {
        let pool = PortPool {
            inner: Arc::new(tokio::sync::RwLock::new(TcpPortPoolInner {
                queue: VecDeque::from([4242]),
            })),
        };

        assert_eq!(pool.next().await.unwrap(), 4242);
        assert!(pool.next().await.is_err());
        pool.release(4242).await;
        assert_eq!(pool.next().await.unwrap(), 4242);
    }

    #[tokio::test]
    async fn wireguard_port_pool_uses_only_virtual_range() {
        let pool = PortPool::new();
        for _ in 0..32 {
            let port = pool.next().await.unwrap();
            assert!((MIN_PORT..MAX_PORT).contains(&port));
        }
    }
}
