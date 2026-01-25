use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::RwLock;

use crate::app::dns::ThreadSafeDNSResolver;
use crate::common::utils::serialize_duration;

/// ProxyManager is the latency registry.
#[derive(Clone)]
pub struct ProxyManager {
    proxy_state: Arc<RwLock<HashMap<String, ProxyState>>>,
    dns_resolver: ThreadSafeDNSResolver,
    // todo Firewall Mark for url test
    // fw_mark: Option<u32>,
}

impl ProxyManager {
    pub fn new(dns_resolver: ThreadSafeDNSResolver) -> Self {
        Self {
            dns_resolver,
            proxy_state: Default::default(),
            // fw_mark,
        }
    }
}

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
