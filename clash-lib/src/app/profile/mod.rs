use std::{collections::HashMap, sync::Arc};
use serde::{Deserialize, Serialize};
use tracing::{error, trace, warn};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Db {
    #[serde(default)]
    selected: HashMap<String, String>,
    #[serde(default)]
    ip_to_host: HashMap<String, String>,
    #[serde(default)]
    host_to_ip: HashMap<String, String>,
    // todo: implement smart stats persistence in the future
    // #[serde(default)]
    // smart_stats: HashMap<String, crate::proxy::group::smart::state::SmartStateData>,
    #[serde(default)]
    smart_policy_priority: HashMap<String, String>,
}

#[derive(Clone)]
pub struct ThreadSafeCacheFile(Arc<tokio::sync::RwLock<CacheFile>>);

impl ThreadSafeCacheFile {
    pub fn new(path: &str, store_selected: bool) -> Self {
        let store = Arc::new(tokio::sync::RwLock::new(CacheFile::new(
            path,
            store_selected,
        )));

        let path = path.to_string();
        let store_clone = store.clone();

        if store_selected {
            tokio::spawn(async move {
                let store = store_clone;
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                    let r = store.read().await;
                    let db = r.db.clone();
                    drop(r);

                    let s = match serde_yaml::to_string(&db) {
                        Ok(s) => s,
                        Err(e) => {
                            error!("failed to serialize cache file: {}", e);
                            continue;
                        }
                    };

                    match tokio::fs::write(&path, s).await {
                        Err(e) => {
                            error!("failed to write cache file: {}", e);
                        }
                        _ => {
                            trace!("cache file flushed to {}", path);
                        }
                    }
                }
            });
        }

        Self(store)
    }
}

struct CacheFile {
    db: Db,

    store_selected: bool,
}

impl CacheFile {
    pub fn new(path: &str, store_selected: bool) -> Self {
        let db = match std::fs::read_to_string(path) {
            Ok(s) => match serde_yaml::from_str(&s) {
                Ok(db) => db,
                Err(e) => {
                    error!("failed to parse cache file: {}, initializing a new one", e);
                    Db {
                        selected: HashMap::new(),
                        ip_to_host: HashMap::new(),
                        host_to_ip: HashMap::new(),
                        // smart_stats: HashMap::new(),
                        smart_policy_priority: HashMap::new(),
                    }
                }
            },
            Err(e) => {
                warn!("failed to read cache file: {}, initializing a new one", e);
                Db {
                    selected: HashMap::new(),
                    ip_to_host: HashMap::new(),
                    host_to_ip: HashMap::new(),
                    // smart_stats: HashMap::new(),
                    smart_policy_priority: HashMap::new(),
                }
            }
        };

        Self { db, store_selected }
    }
}
