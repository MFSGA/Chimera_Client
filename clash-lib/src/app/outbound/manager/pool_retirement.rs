use std::{
    collections::{HashMap, HashSet},
    io,
    sync::{Arc, Weak},
    time::Duration,
};

use futures::StreamExt;
use tokio::sync::Mutex;

use crate::proxy::{AnyOutboundHandler, utils::NetworkPathSource};

#[derive(Default)]
pub(super) struct PoolRetirementState {
    pub(super) generation: Option<u64>,
    pub(super) ready: HashMap<usize, Weak<dyn crate::proxy::OutboundHandler>>,
    pub(super) failed: HashMap<usize, String>,
}

pub(super) struct PoolResetOutcome {
    pub(super) identity: usize,
    pub(super) handler: Weak<dyn crate::proxy::OutboundHandler>,
    pub(super) result: io::Result<u32>,
}

pub(super) fn handler_identity(handler: &AnyOutboundHandler) -> usize {
    Arc::as_ptr(handler) as *const () as usize
}

pub(super) async fn reset_unique_connection_pools_detailed(
    handlers: Vec<AnyOutboundHandler>,
) -> Vec<PoolResetOutcome> {
    let mut seen = HashSet::new();
    let mut pending = futures::stream::FuturesUnordered::new();
    for handler in handlers {
        let identity = handler_identity(&handler);
        if seen.insert(identity) {
            let weak = Arc::downgrade(&handler);
            pending.push(async move {
                let result = tokio::time::timeout(
                    Duration::from_secs(5),
                    handler.reset_connection_pool(),
                )
                .await
                .unwrap_or_else(|_| {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "outbound pool reset timed out",
                    ))
                });
                PoolResetOutcome {
                    identity,
                    handler: weak,
                    result,
                }
            });
        }
    }
    let mut outcomes = Vec::new();
    while let Some(outcome) = pending.next().await {
        outcomes.push(outcome);
    }
    outcomes
}

pub(super) fn summarize_pool_resets(
    outcomes: &[PoolResetOutcome],
) -> io::Result<u32> {
    let mut reset = 0_u32;
    let mut errors = Vec::new();
    for outcome in outcomes {
        match &outcome.result {
            Ok(count) => reset = reset.saturating_add(*count),
            Err(error) => errors.push(error.to_string()),
        }
    }
    if errors.is_empty() {
        Ok(reset)
    } else {
        Err(io::Error::other(errors.join("; ")))
    }
}

impl PoolRetirementState {
    pub(super) fn record(&mut self, generation: u64, outcomes: &[PoolResetOutcome]) {
        self.generation = Some(generation);
        self.ready.clear();
        self.failed.clear();
        for outcome in outcomes {
            match &outcome.result {
                Ok(_) => {
                    self.ready.insert(outcome.identity, outcome.handler.clone());
                }
                Err(error) => {
                    self.failed.insert(outcome.identity, error.to_string());
                }
            }
        }
    }
}

#[cfg(test)]
pub(super) async fn reset_unique_connection_pools(
    handlers: Vec<AnyOutboundHandler>,
) -> io::Result<u32> {
    summarize_pool_resets(&reset_unique_connection_pools_detailed(handlers).await)
}

pub(super) async fn ensure_pool_generation_current<F, Fut>(
    network_path_source: &NetworkPathSource,
    reset_gate: &Mutex<()>,
    pool_generation: &Mutex<Option<u64>>,
    mut reset_pools: F,
) -> io::Result<bool>
where
    F: FnMut(u64) -> Fut,
    Fut: std::future::Future<Output = io::Result<()>>,
{
    let _reset_gate = reset_gate.lock().await;
    let mut pool_generation = pool_generation.lock().await;
    // A flow can wait behind manual recovery or another flow's pool reset.
    // Read the observed generation only after acquiring the reset gate.
    // If a second network change happens during retirement, retry against
    // the newest generation, but bound the work under a flapping network.
    const MAX_GENERATION_ATTEMPTS: usize = 3;
    for _ in 0..MAX_GENERATION_ATTEMPTS {
        let Some((generation, ..)) = network_path_source.snapshot().await else {
            return Ok(false);
        };
        if *pool_generation == Some(generation) {
            return Ok(false);
        }

        reset_pools(generation).await?;
        let current_generation = network_path_source
            .snapshot()
            .await
            .map(|(current, ..)| current);
        if current_generation == Some(generation) {
            *pool_generation = Some(generation);
            return Ok(true);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::Interrupted,
        "network changed repeatedly while retiring stale outbound pools",
    ))
}
