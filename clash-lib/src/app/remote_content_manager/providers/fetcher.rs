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
}

pub struct Fetcher<U, P> {
    name: String,
    interval: Duration,
    vehicle: ThreadSafeProviderVehicle,
    ticker_interval: Duration,
    inner: Arc<RwLock<Inner>>,
    parser: Arc<P>,
    pub on_update: Option<Arc<U>>,
    cancel_token: CancellationToken,
    initial_immediate_refresh: AtomicBool,
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
            })),
            parser: Arc::new(parser),
            on_update: on_update.map(Arc::new),
            cancel_token: CancellationToken::new(),
            initial_immediate_refresh: AtomicBool::new(false),
            polling_started: AtomicBool::new(false),
        }
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

        let mut inner = self.inner.write().await;

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

        if let Some(on_update) = self.on_update.as_ref() {
            // Failure must precede cache/hash mutation. In particular, a
            // proxy provider's node DNS domains must be installed before a
            // downloaded provider can survive a future restart.
            on_update(items).await?;
        }

        if let Some(staged_cache) = staged_cache {
            persist_staged_cache(staged_cache, Path::new(&vehicle_path))?;
            inner.updated_at = SystemTime::now();
            // A recovered cache has just been refreshed successfully.
            immediately_update = false;
        } else if let Some(cached_at) = cached_at {
            // Do not inspect the cache a second time after publication:
            // another process may have replaced it in the meantime.
            inner.updated_at = cached_at;
        }

        inner.hash = utils::md5(&content)[..16]
            .try_into()
            .expect("md5 must be 16 bytes");

        self.initial_immediate_refresh
            .store(immediately_update, Ordering::Release);
        Ok(())
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
    pub async fn update(&self) -> anyhow::Result<bool> {
        Self::update_inner(
            self.inner.clone(),
            self.vehicle.clone(),
            self.parser.clone(),
            self.on_update.clone(),
        )
        .await
    }

    async fn update_inner(
        inner: Arc<RwLock<Inner>>,
        vehicle: ThreadSafeProviderVehicle,
        parser: Arc<P>,
        on_update: Option<Arc<U>>,
    ) -> anyhow::Result<bool> {
        // Serialize source/hash changes with publication across manual,
        // watcher and periodic updates.
        let mut this = inner.write().await;
        let content = vehicle.read().await?;
        let payload = parser(&content)?;

        let now = SystemTime::now();
        let hash: [u8; 16] = utils::md5(&content)[..16]
            .try_into()
            .expect("md5 must be 16 bytes");

        if hash == this.hash {
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

        // A protected proxy-provider registers its DNS endpoint domains here.
        // A rejected revision may not advance the content hash or overwrite
        // last-good cached YAML; a later identical refresh must retry it.
        if let Some(on_update) = on_update {
            on_update(payload).await?;
        }
        if let Some(staged_cache) = staged_cache {
            persist_staged_cache(staged_cache, Path::new(vehicle.path()))?;
        }
        this.hash = hash;
        this.updated_at = now;
        Ok(false)
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
        name: &str,
    ) {
        match Self::update_inner(inner, vehicle, parser, on_update).await {
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

    #[tokio::test]
    async fn startup_staging_failure_prevents_node_registration_publication() {
        assert_unwritable_cache_is_rejected_before_provider_publication(true).await;
    }

    #[tokio::test]
    async fn refresh_staging_failure_prevents_node_registration_publication() {
        assert_unwritable_cache_is_rejected_before_provider_publication(false).await;
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
