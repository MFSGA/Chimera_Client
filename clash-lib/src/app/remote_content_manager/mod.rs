use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::RwLock;

use crate::app::dns::ThreadSafeDNSResolver;
use crate::common::utils::serialize_duration;

pub mod providers;

#[derive(Default)]
struct ProxyState {
    alive: AtomicBool,
    delay_history: VecDeque<DelayHistory>,
}

#[derive(Clone, Serialize)]
pub struct DelayHistory {
    time: DateTime<Utc>,
    #[serde(serialize_with = "serialize_duration")]
    delay: Duration,
}

/// ProxyManager is the latency registry.
#[derive(Clone)]
pub struct ProxyManager {
    proxy_state: Arc<RwLock<HashMap<String, ProxyState>>>,
    dns_resolver: ThreadSafeDNSResolver,
    fw_mark: Option<u32>,
}

impl ProxyManager {
    pub fn new(dns_resolver: ThreadSafeDNSResolver, fw_mark: Option<u32>) -> Self {
        Self {
            dns_resolver,
            proxy_state: Default::default(),
            fw_mark,
        }
    }

    pub async fn alive(&self, name: &str) -> bool {
        self.proxy_state
            .read()
            .await
            .get(name)
            .map(|state| state.alive.load(Ordering::Relaxed))
            .unwrap_or(true)
    }

    pub async fn delay_history(&self, name: &str) -> Vec<DelayHistory> {
        self.proxy_state
            .read()
            .await
            .get(name)
            .map(|state| state.delay_history.clone())
            .unwrap_or_default()
            .into()
    }
}
