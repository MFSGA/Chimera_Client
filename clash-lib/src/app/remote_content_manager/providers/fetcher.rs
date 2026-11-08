use std::{
    fs::{self, metadata},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime},
};

use chrono::{DateTime, Utc};
use futures::future::BoxFuture;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{info, trace, warn};

use crate::common::utils;

use super::{ProviderVehicleType, ThreadSafeProviderVehicle};

/// Stage on the destination filesystem and sync bytes *before* calling an
/// updater that makes new proxy endpoints reachable. Common disk, quota and
/// parent-path errors must not publish nodes before they are detected.
fn stage_cache_write(
    path: &Path,
    content: &[u8],
) -> io::Result<tempfile::NamedTempFile> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    // An atomic rename can replace an existing regular file or symlink but
    // not a directory. Detect an already-impossible commit *before* the
    // updater publishes new proxy endpoints / node DNS ownership.
    // This is a preflight, not a cross-process rename transaction; another
    // writer can still replace the destination after the check.
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if !metadata.file_type().is_file()
                && !metadata.file_type().is_symlink() =>
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "provider cache destination is not a regular file or symlink",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    staged.write_all(content)?;
    staged.flush()?;
    staged.as_file().sync_all()?;
    Ok(staged)
}

fn persist_staged_cache(
    staged: tempfile::NamedTempFile,
    path: &Path,
) -> io::Result<()> {
    staged
        .persist(path)
        .map(|_| ())
        .map_err(|error| error.error)
}

#[cfg(test)]
fn write_cache_atomically(path: &Path, content: &[u8]) -> io::Result<()> {
    persist_staged_cache(stage_cache_write(path, content)?, path)
}

/// A failed final rename must compensate the already published proxy
/// revision and its provider-owned DNS domains. This callback runs while the
/// fetcher's update lock is held, so the next revision cannot overtake it.
pub(crate) type CacheCommitRollback =
    Arc<dyn Fn() -> BoxFuture<'static, anyhow::Result<()>> + Send + Sync>;

/// Release the previous revision retained for rollback after the cache
/// commit is durable (or when the source is a local file).
pub(crate) type CacheCommitAccepted =
    Arc<dyn Fn() -> BoxFuture<'static, ()> + Send + Sync>;

async fn persist_with_rollback(
    staged: tempfile::NamedTempFile,
    path: &Path,
    rollback: Option<&CacheCommitRollback>,
) -> anyhow::Result<()> {
    if let Err(error) = persist_staged_cache(staged, path) {
        if let Some(rollback) = rollback
            && let Err(rollback_error) = rollback().await
        {
            return Err(anyhow::anyhow!(
                "provider cache commit failed: {error}; provisional provider rollback failed: {rollback_error}"
            ));
        }
        return Err(error.into());
    }
    Ok(())
}

/// The source read and staging happen in the caller; this helper starts only
/// after the candidate is ready for DNS/provider publication. It keeps the
/// commit worker alive when the caller is cancelled and preserves an audit
/// warning if a late error would otherwise have no observer. Deliberately do
/// not log the error text: parser, provider and disk errors can contain
/// private node hostnames, filesystem locations or credentials.
async fn finish_published_transaction<R, F>(work: F) -> anyhow::Result<R>
where
    R: Send + 'static,
    F: std::future::Future<Output = anyhow::Result<R>> + Send + 'static,
{
    let (completion, observed) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let result = work.await;
        if let Err(unobserved) = completion.send(result)
            && unobserved.is_err()
        {
            warn!("abandoned provider transaction failed");
        }
    });
    observed.await?
}

fn cache_needs_immediate_update(
    now: SystemTime,
    modified: SystemTime,
    interval: Duration,
) -> bool {
    now.duration_since(modified).unwrap_or_default() > interval
}

struct Inner {
    updated_at: SystemTime,
    hash: [u8; 16],
    // A failed provider cache commit may have failed DNS compensation and
    // disabled the visible provider. Do not skip an identical last-good hash
    // until the updater has successfully re-registered its endpoints.
    force_republish: bool,
}

pub struct Fetcher<U, P> {
    name: String,
    interval: Duration,
    vehicle: ThreadSafeProviderVehicle,
    ticker_interval: Duration,
    inner: Arc<RwLock<Inner>>,
    parser: Arc<P>,
    pub on_update: Option<Arc<U>>,
    on_cache_commit_rollback: Option<CacheCommitRollback>,
    on_cache_commit_accepted: Option<CacheCommitAccepted>,
    cancel_token: CancellationToken,
    initialized: Arc<AtomicBool>,
    initial_immediate_refresh: Arc<AtomicBool>,
    polling_started: AtomicBool,
}

impl<U, P> Drop for Fetcher<U, P> {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

impl<T, U, P> Fetcher<U, P>
where
    T: Send + Sync + 'static,
    U: Fn(T) -> BoxFuture<'static, anyhow::Result<()>> + Send + Sync + 'static,
    P: Fn(&[u8]) -> anyhow::Result<T> + Send + Sync + 'static,
{
    pub fn new(
        name: String,
        interval: Duration,
        vehicle: ThreadSafeProviderVehicle,
        parser: P,
        on_update: Option<U>,
    ) -> Self {
        Self {
            name,
            interval,
            vehicle,
            ticker_interval: interval,
            inner: Arc::new(tokio::sync::RwLock::new(Inner {
                updated_at: SystemTime::UNIX_EPOCH,
                hash: [0; 16],
                force_republish: false,
            })),
            parser: Arc::new(parser),
            on_update: on_update.map(Arc::new),
            on_cache_commit_rollback: None,
            on_cache_commit_accepted: None,
            cancel_token: CancellationToken::new(),
            initialized: Arc::new(AtomicBool::new(false)),
            initial_immediate_refresh: Arc::new(AtomicBool::new(false)),
            polling_started: AtomicBool::new(false),
        }
    }

    /// Configure transactional rollback for provider updates that must keep
    /// their DNS ownership and visible revision aligned with durable cache.
    pub(crate) fn with_cache_commit_hooks(
        mut self,
        rollback: CacheCommitRollback,
        accepted: CacheCommitAccepted,
    ) -> Self {
        self.on_cache_commit_rollback = Some(rollback);
        self.on_cache_commit_accepted = Some(accepted);
        self
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn vehicle_type(&self) -> ProviderVehicleType {
        self.vehicle.typ()
    }

    pub async fn updated_at(&self) -> DateTime<Utc> {
        self.inner.read().await.updated_at.into()
    }

    /// Validate and publish the first revision before persisting a downloaded
    /// provider cache. A failed bootstrap DNS registrar must not leave a
    /// persisted provider that the next startup treats as accepted.
    pub async fn initial(&self) -> anyhow::Result<()> {
        let mut is_local = false;
        let mut recovered_invalid_cache = false;
        let mut immediately_update = false;
        let mut cached_at = None;

        let vehicle_path = self.vehicle.path().to_owned();

        let mut inner = self.inner.clone().write_owned().await;
        if self.initialized.load(Ordering::Acquire) {
            return Ok(());
        }

        let mut content = match metadata(&vehicle_path) {
            Ok(meta) => {
                let content = fs::read(&vehicle_path)?;
                is_local = true;
                let modified = meta.modified()?;
                cached_at = Some(modified);
                immediately_update = cache_needs_immediate_update(
                    SystemTime::now(),
                    modified,
                    self.interval,
                );
                content
            }
            Err(_) => self.vehicle.read().await?,
        };

        let parser_guard = &self.parser;

        let items = match (parser_guard)(&content) {
            Ok(proxies) => proxies,
            Err(e) => {
                if !is_local {
                    return Err(e);
                }
                content = self.vehicle.read().await?;
                let parsed = (parser_guard)(&content)?;
                recovered_invalid_cache = true;
                parsed
            }
        };

        let staged_cache = (self.vehicle_type() != ProviderVehicleType::File
            && (!is_local || recovered_invalid_cache))
            .then(|| stage_cache_write(Path::new(&vehicle_path), &content))
            .transpose()?;

        // Parsing, any remote recovery read and cache staging above remain
        // cancellable. Once registration begins, run the *entire* initial
        // publish/rename/compensation sequence in an owned worker. Dropping
        // the startup caller must not strand the provider's reader gate or
        // leave an unpersisted revision with registered DNS ownership.
        let on_update = self.on_update.clone();
        let rollback = self.on_cache_commit_rollback.clone();
        let accepted = self.on_cache_commit_accepted.clone();
        let immediate_refresh = self.initial_immediate_refresh.clone();
        let initialized = self.initialized.clone();
        finish_published_transaction(async move {
            if let Some(on_update) = on_update {
                // Failure must precede cache/hash mutation. In particular,
                // proxy node domains must be registered before downloaded
                // provider bytes can survive a future restart.
                on_update(items).await?;
            }

            if let Some(staged_cache) = staged_cache {
                persist_with_rollback(
                    staged_cache,
                    Path::new(&vehicle_path),
                    rollback.as_ref(),
                )
                .await?;
                inner.updated_at = SystemTime::now();
                // A recovered cache has been refreshed successfully.
                immediately_update = false;
            } else if let Some(cached_at) = cached_at {
                // Do not inspect the cache a second time after publication:
                // another process may have replaced it in the meantime.
                inner.updated_at = cached_at;
            }

            inner.hash = utils::md5(&content)[..16]
                .try_into()
                .expect("md5 must be 16 bytes");
            inner.force_republish = false;

            if let Some(accepted) = accepted {
                accepted().await;
            }
            immediate_refresh.store(immediately_update, Ordering::Release);
            initialized.store(true, Ordering::Release);
            Ok(())
        })
        .await
    }

    /// Publish an already-valid HTTP cache without reading from its remote
    /// vehicle. A missing or invalid cache is left untouched so normal
    /// initialization can fetch it after the runtime candidate is committed.
    pub async fn prepare_candidate_from_cache(&self) -> anyhow::Result<bool> {
        if self.vehicle.typ() != ProviderVehicleType::Http {
            return Ok(false);
        }

        let mut inner = self.inner.write().await;
        if self.initialized.load(Ordering::Acquire) {
            return Ok(true);
        }

        let vehicle_path = Path::new(self.vehicle.path());
        let meta = match metadata(vehicle_path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        };
        let content = fs::read(vehicle_path)?;
        let items = match (self.parser)(&content) {
            Ok(items) => items,
            Err(_) => {
                warn!(
                    provider = self.name.as_str(),
                    "provider cache is invalid; deferring remote recovery until candidate commit"
                );
                return Ok(false);
            }
        };

        if let Some(on_update) = self.on_update.as_ref() {
            on_update(items).await?;
        }

        let modified = meta.modified()?;
        inner.updated_at = modified;
        inner.hash = utils::md5(&content)[..16]
            .try_into()
            .expect("md5 must be 16 bytes");
        self.initial_immediate_refresh.store(
            cache_needs_immediate_update(SystemTime::now(), modified, self.interval),
            Ordering::Release,
        );
        self.initialized.store(true, Ordering::Release);
        Ok(true)
    }

    /// Start background refresh only after the initial updater has installed
    /// and published the first accepted revision. Otherwise the first poll
    /// could overtake the bootstrap node-DNS registration at startup.
    pub async fn start_polling(&self) {
        if self.ticker_interval.is_zero()
            || self.polling_started.swap(true, Ordering::AcqRel)
        {
            return;
        }
        self.pull_loop(
            self.initial_immediate_refresh.load(Ordering::Acquire),
            tokio::time::interval(self.ticker_interval),
        )
        .await;
    }

    /// Apply a parsed revision before committing its source hash and cache.
    /// A failed updater must remain retryable on the next refresh, including
    /// background polling. Callers must not publish provider revisions after
    /// DNS registration has failed.
    ///
    /// Only the already-staged publication/commit phase must outlive a
    /// cancelled caller. Fetching, parsing and staging remain cancellable;
    /// otherwise cancelling a slow HTTP provider download could still
    /// publish its nodes unexpectedly.
    pub async fn update(&self) -> anyhow::Result<bool> {
        Self::update_inner(
            self.inner.clone(),
            self.vehicle.clone(),
            self.parser.clone(),
            self.on_update.clone(),
            self.on_cache_commit_rollback.clone(),
            self.on_cache_commit_accepted.clone(),
        )
        .await
    }

    async fn update_inner(
        inner: Arc<RwLock<Inner>>,
        vehicle: ThreadSafeProviderVehicle,
        parser: Arc<P>,
        on_update: Option<Arc<U>>,
        on_cache_commit_rollback: Option<CacheCommitRollback>,
        on_cache_commit_accepted: Option<CacheCommitAccepted>,
    ) -> anyhow::Result<bool> {
        // Serialize source/hash changes with publication across manual,
        // watcher and periodic updates.
        let mut this = inner.write_owned().await;
        let content = vehicle.read().await?;
        let payload = parser(&content)?;

        let now = SystemTime::now();
        let hash: [u8; 16] = utils::md5(&content)[..16]
            .try_into()
            .expect("md5 must be 16 bytes");

        if hash == this.hash && !this.force_republish {
            this.updated_at = now;
            if vehicle.typ() != ProviderVehicleType::File {
                filetime::set_file_times(vehicle.path(), now.into(), now.into())?;
            }
            return Ok(true);
        }

        // Stage potential cache write failures before the updater makes
        // endpoints reachable. Only the atomic rename follows publication.
        let staged_cache = (vehicle.typ() != ProviderVehicleType::File)
            .then(|| stage_cache_write(Path::new(vehicle.path()), &content))
            .transpose()?;

        // The source is now fully fetched, parsed and staged. Only the
        // side-effecting provider publication is non-cancellable: a dropped
        // API caller (or watcher) must not abandon DNS ownership and an
        // uncommitted proxy revision with the admission lock held.
        // Moving the owned fetcher write guard into this worker also keeps
        // subsequent updates serialized until commit or rollback finishes.
        let cache_path = vehicle.path().to_owned();
        finish_published_transaction(async move {
            // A rejected revision may not advance its content hash or
            // overwrite last-good cached YAML; the same bytes must retry.
            if let Some(on_update) = on_update {
                on_update(payload).await?;
            }
            if let Some(staged_cache) = staged_cache
                && let Err(error) = persist_with_rollback(
                    staged_cache,
                    Path::new(&cache_path),
                    on_cache_commit_rollback.as_ref(),
                )
                .await
            {
                // Even a successful rollback has failed to accept this
                // candidate. A failed DNS rollback can also disable the old
                // provider, so the next identical last-good bytes must be
                // re-registered, not silently hash-skipped.
                this.force_republish = true;
                return Err(error);
            }
            this.hash = hash;
            this.updated_at = now;
            this.force_republish = false;
            if let Some(accepted) = on_cache_commit_accepted {
                accepted().await;
            }
            Ok(false)
        })
        .await
    }

    #[cfg(test)]
    pub async fn destroy(&mut self) {
        self.cancel_token.cancel();
    }

    async fn run_update(
        inner: Arc<RwLock<Inner>>,
        vehicle: ThreadSafeProviderVehicle,
        parser: Arc<P>,
        on_update: Option<Arc<U>>,
        on_cache_commit_rollback: Option<CacheCommitRollback>,
        on_cache_commit_accepted: Option<CacheCommitAccepted>,
        name: &str,
    ) {
        match Self::update_inner(
            inner,
            vehicle,
            parser,
            on_update,
            on_cache_commit_rollback,
            on_cache_commit_accepted,
        )
        .await
        {
            Ok(true) => trace!("fetcher {} no update", name),
            Ok(false) => info!("fetcher {} updated", name),
            Err(error) => warn!("{} update failed: {}", name, error),
        }
    }

    pub async fn start_watch(&self) -> anyhow::Result<()> {
        use notify::{EventKind, RecursiveMode, Watcher, recommended_watcher};

        if self.vehicle_type() != ProviderVehicleType::File {
            return Ok(());
        }

        let file_path = PathBuf::from(self.vehicle.path());
        let watch_dir = file_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| file_path.clone());
        let watch_name = file_path.file_name().map(ToOwned::to_owned);

        let inner = self.inner.clone();
        let vehicle = self.vehicle.clone();
        let parser = self.parser.clone();
        let on_update = self.on_update.clone();
        let on_cache_commit_rollback = self.on_cache_commit_rollback.clone();
        let on_cache_commit_accepted = self.on_cache_commit_accepted.clone();
        let name = self.name.clone();
        let cancel_token = self.cancel_token.clone();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);

        let mut watcher =
            recommended_watcher(move |result: notify::Result<notify::Event>| {
                let Ok(event) = result else { return };
                if matches!(event.kind, EventKind::Access(_)) {
                    return;
                }
                if let Some(want) = &watch_name
                    && !event.paths.is_empty()
                    && !event.paths.iter().any(|p| p.file_name() == Some(want))
                {
                    return;
                }
                let _ = tx.try_send(());
            })
            .map_err(|e| {
                anyhow::anyhow!(
                    "failed to create file watcher for {}: {}",
                    file_path.display(),
                    e
                )
            })?;

        watcher
            .watch(&watch_dir, RecursiveMode::NonRecursive)
            .map_err(|e| {
                anyhow::anyhow!(
                    "failed to watch directory {}: {}",
                    watch_dir.display(),
                    e
                )
            })?;

        tokio::spawn(async move {
            let _watcher = watcher;
            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => break,
                    recv = rx.recv() => {
                        if recv.is_none() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        while rx.try_recv().is_ok() {}
                        Fetcher::<U, P>::run_update(
                            inner.clone(),
                            vehicle.clone(),
                            parser.clone(),
                            on_update.clone(),
                            on_cache_commit_rollback.clone(),
                            on_cache_commit_accepted.clone(),
                            &name,
                        )
                        .await;
                    }
                }
            }
        });

        Ok(())
    }

    async fn pull_loop(
        &self,
        immediately_update: bool,
        mut ticker: tokio::time::Interval,
    ) {
        let inner = self.inner.clone();
        let vehicle = self.vehicle.clone();
        let parser = self.parser.clone();
        let on_update = self.on_update.clone();
        let on_cache_commit_rollback = self.on_cache_commit_rollback.clone();
        let on_cache_commit_accepted = self.on_cache_commit_accepted.clone();
        let name = self.name.clone();
        let cancel_token = self.cancel_token.clone();
        let fire_immediately = immediately_update;

        tokio::spawn(async move {
            let run = |()| {
                Fetcher::<U, P>::run_update(
                    inner.clone(),
                    vehicle.clone(),
                    parser.clone(),
                    on_update.clone(),
                    on_cache_commit_rollback.clone(),
                    on_cache_commit_accepted.clone(),
                    &name,
                )
            };

            if fire_immediately {
                run(()).await;
            }
            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => break,
                    _ = ticker.tick() => run(()).await,
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::Path,
        sync::Arc,
        time::{Duration, SystemTime},
    };

    use futures::future::BoxFuture;
    use tokio::time::sleep;

    use crate::app::remote_content_manager::providers::{
        MockProviderVehicle, ProviderVehicleType,
    };

    use super::{Fetcher, cache_needs_immediate_update, write_cache_atomically};

    async fn assert_unwritable_cache_is_rejected_before_provider_publication(
        initial: bool,
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let directory = tempfile::tempdir().unwrap();
        let blocked_parent = directory.path().join("parent-is-file");
        std::fs::write(&blocked_parent, b"existing user content").unwrap();
        let cache_path = blocked_parent.join("provider.yaml");
        let mut vehicle = MockProviderVehicle::new();
        vehicle
            .expect_path()
            .return_const(cache_path.to_string_lossy().into_owned());
        vehicle.expect_typ().return_const(ProviderVehicleType::Http);
        vehicle
            .expect_read()
            .times(1)
            .returning(|| Ok(b"accepted provider".to_vec()));

        let published = Arc::new(AtomicUsize::new(0));
        let hits = published.clone();
        let updater =
            move |_candidate: String| -> BoxFuture<'static, anyhow::Result<()>> {
                hits.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ok(()) })
            };
        let fetcher = Fetcher::new(
            "staged-cache-only".to_owned(),
            Duration::ZERO,
            Arc::new(vehicle),
            |content| Ok(String::from_utf8(content.to_vec())?),
            Some(updater),
        );
        let result = if initial {
            fetcher.initial().await.map(|_| ())
        } else {
            fetcher.update().await.map(|_| ())
        };
        assert!(result.is_err(), "unwritable cache must be reported");
        assert_eq!(
            published.load(Ordering::SeqCst),
            0,
            "a candidate may not become visible before its cache can be staged"
        );
        assert_eq!(
            std::fs::read(&blocked_parent).unwrap(),
            b"existing user content"
        );
    }

    struct PausedProviderVehicle {
        path: String,
        read_started: Arc<tokio::sync::Notify>,
        release_read: Arc<tokio::sync::Notify>,
        read_dropped: Arc<tokio::sync::Notify>,
    }

    struct ReadDropNotice(Arc<tokio::sync::Notify>);

    impl Drop for ReadDropNotice {
        fn drop(&mut self) {
            self.0.notify_one();
        }
    }

    #[async_trait::async_trait]
    impl crate::app::remote_content_manager::providers::ProviderVehicle
        for PausedProviderVehicle
    {
        async fn read(&self) -> std::io::Result<Vec<u8>> {
            // Prove the pending source I/O future is dropped on cancellation,
            // without relying on a scheduling sleep.
            let _drop_signal = ReadDropNotice(self.read_dropped.clone());
            self.read_started.notify_one();
            self.release_read.notified().await;
            Ok(b"remote candidate".to_vec())
        }

        fn path(&self) -> &str {
            &self.path
        }

        fn typ(&self) -> ProviderVehicleType {
            ProviderVehicleType::Http
        }
    }

    #[tokio::test]
    async fn cancelling_initial_before_source_read_finishes_does_not_publish_or_persist()
     {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("cancelled-initial-download.yaml");
        let read_started = Arc::new(tokio::sync::Notify::new());
        let release_read = Arc::new(tokio::sync::Notify::new());
        let read_dropped = Arc::new(tokio::sync::Notify::new());
        let vehicle = Arc::new(PausedProviderVehicle {
            path: cache_path.to_string_lossy().into_owned(),
            read_started: read_started.clone(),
            release_read: release_read.clone(),
            read_dropped: read_dropped.clone(),
        });
        let published = Arc::new(AtomicUsize::new(0));
        let hits = published.clone();
        let updater =
            move |_input: String| -> BoxFuture<'static, anyhow::Result<()>> {
                hits.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ok(()) })
            };
        let fetcher = Arc::new(Fetcher::new(
            "initial-download-cancel".into(),
            Duration::ZERO,
            vehicle,
            |bytes| Ok(String::from_utf8(bytes.to_vec())?),
            Some(updater),
        ));
        let initializing = fetcher.clone();
        let request = tokio::spawn(async move { initializing.initial().await });
        tokio::time::timeout(Duration::from_secs(2), read_started.notified())
            .await
            .expect("initial remote read should start");
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_millis(300), read_dropped.notified())
            .await
            .expect("cancelled caller must drop pending source I/O before response release");
        release_read.notify_one();
        assert_eq!(published.load(Ordering::SeqCst), 0);
        assert!(
            !cache_path.exists(),
            "cancelled initial download must not become accepted"
        );
    }

    #[tokio::test]
    async fn cancellation_before_source_read_finishes_does_not_publish_or_persist() {
        // Cancellation while still fetching content is different from
        // cancellation of an already-staged publication transaction.
        // No candidate exists yet, so the in-flight fetch must remain
        // cancellable; a detached worker must start only *after* staging.
        use std::sync::atomic::{AtomicUsize, Ordering};

        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("not-downloaded.yaml");
        let read_started = Arc::new(tokio::sync::Notify::new());
        let release_read = Arc::new(tokio::sync::Notify::new());
        let read_dropped = Arc::new(tokio::sync::Notify::new());
        let vehicle = Arc::new(PausedProviderVehicle {
            path: cache_path.to_string_lossy().into_owned(),
            read_started: read_started.clone(),
            release_read: release_read.clone(),
            read_dropped: read_dropped.clone(),
        });
        let accepted = Arc::new(AtomicUsize::new(0));
        let updates = accepted.clone();
        let updater =
            move |_input: String| -> BoxFuture<'static, anyhow::Result<()>> {
                updates.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ok(()) })
            };
        let fetcher = Arc::new(Fetcher::new(
            "source-cancellation".into(),
            Duration::ZERO,
            vehicle,
            |content| Ok(String::from_utf8(content.to_vec())?),
            Some(updater),
        ));

        let updating = fetcher.clone();
        let request = tokio::spawn(async move { updating.update().await });
        tokio::time::timeout(Duration::from_secs(2), read_started.notified())
            .await
            .expect("vehicle read must start before cancellation");
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_millis(300), read_dropped.notified())
            .await
            .expect("cancelled caller must drop pending source I/O before response release");
        release_read.notify_one();
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "a cancelled pre-staging fetch may not continue to DNS publication"
        );
        assert!(
            !cache_path.exists(),
            "cancelled pre-staging fetch may not create cache"
        );
    }

    struct CaptureWriter(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for CaptureWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn observed_commit_failure_returns_diagnostic_without_orphan_warning() {
        let captured = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .with_writer(move || CaptureWriter(writer.clone()))
            .finish();
        let _subscriber = tracing::subscriber::set_default(subscriber);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("failed-observed.yaml");
        let mut vehicle = MockProviderVehicle::new();
        vehicle
            .expect_path()
            .return_const(path.to_string_lossy().into_owned());
        vehicle.expect_typ().return_const(ProviderVehicleType::Http);
        vehicle
            .expect_read()
            .times(1)
            .returning(|| Ok(b"candidate".to_vec()));
        let updater = |_payload: String| -> BoxFuture<'static, anyhow::Result<()>> {
            Box::pin(async {
                anyhow::bail!("synthetic private-provider.internal rejected")
            })
        };
        let fetcher = Fetcher::new(
            "observed-failure".into(),
            Duration::ZERO,
            Arc::new(vehicle),
            |bytes| Ok(String::from_utf8(bytes.to_vec())?),
            Some(updater),
        );
        let reported = fetcher.update().await.unwrap_err().to_string();
        assert!(reported.contains("synthetic private-provider.internal"));
        let log = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
        assert!(
            !log.contains("abandoned provider transaction failed"),
            "an observed error should not produce a duplicate orphan warning"
        );
        assert!(!log.contains("private-provider.internal"));
        assert!(
            !path.exists(),
            "failed update may not leave a persisted revision"
        );
    }

    #[tokio::test]
    async fn detached_commit_failure_emits_sanitized_diagnostic_without_caller() {
        // The caller can be gone when a DNS/cache transaction fails. The
        // worker must leave a non-sensitive audit diagnostic, rather than
        // silently dropping a failed JoinHandle or logging the node secret.
        let captured = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .with_writer(move || CaptureWriter(writer.clone()))
            .finish();
        let _subscriber = tracing::subscriber::set_default(subscriber);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("failed-offline-commit.yaml");
        let mut vehicle = MockProviderVehicle::new();
        vehicle
            .expect_path()
            .return_const(path.to_string_lossy().into_owned());
        vehicle.expect_typ().return_const(ProviderVehicleType::Http);
        vehicle
            .expect_read()
            .times(1)
            .returning(|| Ok(b"new candidate".to_vec()));
        let entered = Arc::new(tokio::sync::Notify::new());
        let released = Arc::new(tokio::sync::Notify::new());
        let signal = entered.clone();
        let resume = released.clone();
        let updater =
            move |_payload: String| -> BoxFuture<'static, anyhow::Result<()>> {
                let signal = signal.clone();
                let resume = resume.clone();
                Box::pin(async move {
                    signal.notify_one();
                    resume.notified().await;
                    anyhow::bail!(
                        "synthetic secret hostname: private-provider.internal"
                    )
                })
            };
        let fetcher = Arc::new(Fetcher::new(
            "no-caller".into(),
            Duration::ZERO,
            Arc::new(vehicle),
            |bytes| Ok(String::from_utf8(bytes.to_vec())?),
            Some(updater),
        ));
        let running = fetcher.clone();
        let request = tokio::spawn(async move { running.update().await });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .expect("transaction must reach updater");
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        released.notify_one();

        let text = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let log =
                    String::from_utf8(captured.lock().unwrap().clone()).unwrap();
                if log.contains("abandoned provider transaction failed") {
                    break log;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("an unobserved failed provider transaction must be logged");
        assert!(
            !text.contains("private-provider.internal"),
            "node endpoint must be redacted"
        );
        assert!(!path.exists(), "rejected candidate must not be persisted");
    }

    #[tokio::test]
    async fn startup_staging_failure_prevents_node_registration_publication() {
        assert_unwritable_cache_is_rejected_before_provider_publication(true).await;
    }

    #[tokio::test]
    async fn refresh_staging_failure_prevents_node_registration_publication() {
        assert_unwritable_cache_is_rejected_before_provider_publication(false).await;
    }

    #[tokio::test]
    async fn directory_cache_destination_must_not_publish_new_proxy_revision() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("provider.yaml");
        std::fs::create_dir(&destination).unwrap();
        let mut vehicle = MockProviderVehicle::new();
        vehicle
            .expect_path()
            .return_const(destination.to_string_lossy().into_owned());
        vehicle.expect_typ().return_const(ProviderVehicleType::Http);
        vehicle
            .expect_read()
            .times(1)
            .returning(|| Ok(b"new node".to_vec()));

        let published = Arc::new(AtomicUsize::new(0));
        let observed = published.clone();
        let updater =
            move |_candidate: String| -> BoxFuture<'static, anyhow::Result<()>> {
                observed.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ok(()) })
            };
        let fetcher = Fetcher::new(
            "directory-target".to_owned(),
            Duration::ZERO,
            Arc::new(vehicle),
            |content| Ok(String::from_utf8(content.to_vec())?),
            Some(updater),
        );

        assert!(
            fetcher.update().await.is_err(),
            "atomic rename over a directory must be rejected"
        );
        assert_eq!(
            published.load(Ordering::SeqCst),
            0,
            "cache destination rejection must precede DNS endpoint publication"
        );
        assert!(
            destination.is_dir(),
            "existing directory must not be modified"
        );
    }

    #[test]
    fn atomic_cache_write_replaces_existing_content() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("provider.yaml");
        std::fs::write(&path, b"old provider").unwrap();

        write_cache_atomically(&path, b"new provider").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"new provider");
    }

    #[cfg(unix)]
    #[test]
    fn staged_cache_keeps_legacy_symlink_replacement_semantics() {
        // Historically NamedTempFile::persist atomically replaced the cache
        // pathname itself. Preserve that behavior rather than following a
        // symlink and modifying an unrelated file outside the cache path.
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("original-target.yaml");
        let cache_link = dir.path().join("provider.yaml");
        std::fs::write(&outside, b"owner's original content").unwrap();
        std::os::unix::fs::symlink(&outside, &cache_link).unwrap();
        assert!(
            std::fs::symlink_metadata(&cache_link)
                .unwrap()
                .file_type()
                .is_symlink()
        );

        write_cache_atomically(&cache_link, b"accepted provider").unwrap();

        assert_eq!(
            std::fs::read(&outside).unwrap(),
            b"owner's original content"
        );
        assert_eq!(std::fs::read(&cache_link).unwrap(), b"accepted provider");
        assert!(
            std::fs::symlink_metadata(&cache_link)
                .unwrap()
                .file_type()
                .is_file(),
            "cache target should be a regular file after atomic replacement"
        );
    }

    #[test]
    fn future_cache_timestamp_does_not_panic_or_force_refresh() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let future = now + Duration::from_secs(60);

        assert!(!cache_needs_immediate_update(
            now,
            future,
            Duration::from_secs(1)
        ));
    }

    #[test]
    fn stale_cache_requests_immediate_refresh() {
        let modified = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let now = modified + Duration::from_secs(60);

        assert!(cache_needs_immediate_update(
            now,
            modified,
            Duration::from_secs(30)
        ));
    }

    #[tokio::test]
    async fn invalid_cached_provider_recovers_remote_content_atomically() {
        let dir = tempfile::tempdir().expect("temporary provider directory");
        let path = dir.path().join("cached-provider.yaml");
        std::fs::write(&path, b"invalid cached content").expect("seed bad cache");
        filetime::set_file_mtime(&path, filetime::FileTime::from_unix_time(10, 0))
            .expect("set stale cache timestamp");

        let mut vehicle = MockProviderVehicle::new();
        vehicle
            .expect_path()
            .return_const(path.to_str().unwrap().to_owned());
        vehicle.expect_typ().return_const(ProviderVehicleType::Http);
        vehicle
            .expect_read()
            .times(2)
            .returning(|| Ok(b"valid remote content".to_vec()));

        let parser = |input: &[u8]| -> anyhow::Result<String> {
            if input != b"valid remote content" {
                anyhow::bail!("invalid provider content");
            }
            Ok("valid".to_owned())
        };
        let accepted = Arc::new(std::sync::Mutex::new(Vec::new()));
        let accepted_for_callback = accepted.clone();
        let updater =
            move |input: String| -> BoxFuture<'static, anyhow::Result<()>> {
                let accepted = accepted_for_callback.clone();
                Box::pin(async move {
                    accepted.lock().unwrap().push(input);
                    Ok(())
                })
            };
        let fetcher = Fetcher::new(
            "cache-recovery".to_owned(),
            Duration::ZERO,
            Arc::new(vehicle),
            parser,
            Some(updater),
        );

        fetcher.initial().await.unwrap();
        assert_eq!(*accepted.lock().unwrap(), ["valid"]);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"valid remote content",
            "a recovered provider must replace its corrupt cache"
        );
        assert!(
            fetcher.updated_at().await.timestamp() > 10,
            "recovery must replace the stale provider timestamp"
        );
        let unchanged = fetcher.update().await.unwrap();
        assert!(
            unchanged,
            "recovered cache and in-memory hash must match remote content"
        );
    }

    #[tokio::test]
    async fn failed_remote_recovery_keeps_existing_cache_untouched() {
        let dir = tempfile::tempdir().expect("temporary provider directory");
        let path = dir.path().join("cached-provider.yaml");
        std::fs::write(&path, b"invalid cached content").expect("seed bad cache");

        let mut vehicle = MockProviderVehicle::new();
        vehicle
            .expect_path()
            .return_const(path.to_str().unwrap().to_owned());
        vehicle.expect_typ().return_const(ProviderVehicleType::Http);
        vehicle
            .expect_read()
            .times(1)
            .returning(|| Ok(b"invalid remote content".to_vec()));

        let parser = |input: &[u8]| -> anyhow::Result<String> {
            if input != b"valid remote content" {
                anyhow::bail!("invalid provider content");
            }
            Ok("valid".to_owned())
        };
        let updater = |_input: String| -> BoxFuture<'static, anyhow::Result<()>> {
            Box::pin(async { Ok(()) })
        };
        let fetcher = Fetcher::new(
            "cache-recovery-failure".to_owned(),
            Duration::ZERO,
            Arc::new(vehicle),
            parser,
            Some(updater),
        );

        assert!(fetcher.initial().await.is_err());
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"invalid cached content",
            "failed validation must not overwrite existing cache"
        );
    }

    #[tokio::test]
    async fn test_fetcher() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(32);
        let tx1 = tx.clone();

        let mut mock_vehicle = MockProviderVehicle::new();
        let mock_file = std::env::temp_dir().join(format!(
            "{}-{}",
            "mock_provider_vehicle",
            uuid::Uuid::new_v4()
        ));
        if Path::new(mock_file.to_str().unwrap()).exists() {
            std::fs::remove_file(&mock_file).unwrap();
        }
        std::fs::write(&mock_file, vec![1, 2, 3]).unwrap();

        mock_vehicle
            .expect_path()
            .return_const(mock_file.to_str().unwrap().to_owned());
        mock_vehicle.expect_read().returning(|| Ok(vec![4, 5, 6]));
        mock_vehicle
            .expect_typ()
            .return_const(ProviderVehicleType::File);

        let parser = move |i: &[u8]| -> anyhow::Result<String> {
            let copy = i.to_owned();
            tx1.try_send(copy).unwrap();
            Ok("parsed".to_owned())
        };

        let updater =
            move |input: String| -> BoxFuture<'static, anyhow::Result<()>> {
                Box::pin(async move {
                    assert_eq!(input, "parsed".to_owned());
                    Ok(())
                })
            };

        let mut f = Fetcher::new(
            "test_fetcher".to_string(),
            Duration::from_secs(1),
            Arc::new(mock_vehicle),
            parser,
            Some(updater),
        );

        let _ = f.initial().await;
        f.start_polling().await;

        sleep(Duration::from_secs_f64(5.5)).await;
        f.destroy().await;

        drop(tx);
        drop(f);

        let mut parsed = vec![];

        while let Some(message) = rx.recv().await {
            parsed.push(message);
        }

        assert!(parsed.len() > 5);
        assert_eq!(parsed[0], vec![1, 2, 3]);
        assert_eq!(parsed[1], vec![4, 5, 6]);
    }
}
