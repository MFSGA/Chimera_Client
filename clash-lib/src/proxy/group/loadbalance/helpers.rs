use std::{
    io,
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::proxy::AnyOutboundHandler;

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
}
