use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use dashmap::DashMap;
use tokio::time::{sleep, Duration};

use super::upload_queue::UploadQueue;

#[derive(Debug)]
pub struct Session {
    pub id: String,
    pub queue: Arc<UploadQueue>,
    pub fully_connected: AtomicBool,
}

#[derive(Clone, Debug)]
pub struct SessionStore {
    sessions: Arc<DashMap<String, Arc<Session>>>,
    ttl: Duration,
    max_buffered_posts: usize,
}

impl SessionStore {
    pub fn new(ttl: Duration, max_buffered_posts: usize) -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            ttl,
            max_buffered_posts,
        }
    }

    pub fn get_or_create(&self, id: &str) -> Arc<Session> {
        if let Some(v) = self.sessions.get(id) {
            return v.clone();
        }

        let session = Arc::new(Session {
            id: id.to_string(),
            queue: UploadQueue::new(self.max_buffered_posts),
            fully_connected: AtomicBool::new(false),
        });

        let entry = self
            .sessions
            .entry(id.to_string())
            .or_insert_with(|| session.clone());
        let sess = entry.clone();
        drop(entry);

        // TTL cleanup: remove if GET (stream-down) never arrives
        let store = self.clone();
        let sid = id.to_string();
        tokio::spawn(async move {
            sleep(store.ttl).await;
            if let Some(s) = store.sessions.get(&sid) {
                if !s.fully_connected.load(Ordering::Acquire) {
                    let _ = store.remove(&sid).await;
                }
            }
        });

        sess
    }

    pub fn mark_fully_connected(&self, id: &str) {
        if let Some(s) = self.sessions.get(id) {
            s.fully_connected.store(true, Ordering::Release);
        }
    }

    pub async fn remove(&self, id: &str) -> Option<Arc<Session>> {
        let removed = self.sessions.remove(id).map(|(_, v)| v);
        if let Some(s) = &removed {
            s.queue.close().await;
        }
        removed
    }
}
