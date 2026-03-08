use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::{Mutex, Notify};

#[derive(Debug)]
struct Inner {
    next_seq: u64,
    buffered: BTreeMap<u64, Bytes>,
    ready: VecDeque<Bytes>,
    closed: bool,
    max_buffered_posts: usize,
}

#[derive(Debug)]
pub struct UploadQueue {
    inner: Mutex<Inner>,
    notify: Notify,
}

#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    #[error("queue closed")]
    Closed,
    #[error("too many buffered posts (max {0})")]
    TooManyBuffered(usize),
}

impl UploadQueue {
    pub fn new(max_buffered_posts: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                next_seq: 0,
                buffered: BTreeMap::new(),
                ready: VecDeque::new(),
                closed: false,
                max_buffered_posts,
            }),
            notify: Notify::new(),
        })
    }

    pub async fn close(&self) {
        let mut g = self.inner.lock().await;
        g.closed = true;
        drop(g);
        self.notify.notify_waiters();
    }

    pub async fn push_packet(
        &self,
        seq: u64,
        data: Bytes,
    ) -> Result<(), QueueError> {
        let mut g = self.inner.lock().await;
        if g.closed {
            return Err(QueueError::Closed);
        }

        // Drop old packets (retries/duplicates)
        if seq < g.next_seq {
            return Ok(());
        }

        // Cap buffered map size
        if g.buffered.len() >= g.max_buffered_posts && !g.buffered.contains_key(&seq)
        {
            return Err(QueueError::TooManyBuffered(g.max_buffered_posts));
        }

        g.buffered.insert(seq, data);

        // Move contiguous sequence into ready queue
        loop {
            let next_seq = g.next_seq;
            let Some(v) = g.buffered.remove(&next_seq) else {
                break;
            };
            g.ready.push_back(v);
            g.next_seq += 1;
        }

        drop(g);
        self.notify.notify_waiters();
        Ok(())
    }

    /// Reads next available chunk in-order. Returns None when closed and drained.
    pub async fn read_chunk(&self) -> Option<Bytes> {
        loop {
            {
                let mut g = self.inner.lock().await;
                if let Some(b) = g.ready.pop_front() {
                    return Some(b);
                }
                if g.closed && g.ready.is_empty() && g.buffered.is_empty() {
                    return None;
                }
            }
            self.notify.notified().await;
        }
    }
}
