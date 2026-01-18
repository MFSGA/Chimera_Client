use std::sync::Arc;
use tracing::{error, trace};

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
                    /*  todo
                    let r = store.read().await;
                    let db = r.db.clone();
                    drop(r); */

                    /* let s = match serde_yaml::to_string(&db) {
                        Ok(s) => s,
                        Err(e) => {
                            error!("failed to serialize cache file: {}", e);
                            continue;
                        }
                    }; */
                    todo!()
                    /*  match tokio::fs::write(&path, s).await {
                        Err(e) => {
                            error!("failed to write cache file: {}", e);
                        }
                        _ => {
                            trace!("cache file flushed to {}", path);
                        }
                    } */
                }
            });
        }

        Self(store)
    }
}

struct CacheFile {
    // db: Db,

    // store_selected: bool,
}

impl CacheFile {
    pub fn new(path: &str, store_selected: bool) -> Self {
        Self {}
    }
}
