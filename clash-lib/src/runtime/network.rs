use tokio::sync::oneshot;

use crate::{Error, Result, app, config::internal::InternalConfig};
#[cfg(feature = "tun")]
use crate::{
    app::net::{Interface, init_net_config},
    install_default_socket_protector,
};

#[cfg(feature = "tun")]
static NETWORK_RUNTIME_STATE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(feature = "tun")]
const CONFIGURED_NETWORK_RUNTIME: usize = usize::MAX;

/// Own the process-global socket/TUN configuration for the lifetime of one
/// runtime. Runtimes without an interface, mark, or TUN can coexist because
/// they do not write these slots; a runtime that needs them is exclusive.
pub(super) struct NetworkRuntimeLease {
    #[cfg(feature = "tun")]
    configured: bool,
}

impl NetworkRuntimeLease {
    pub(super) fn acquire(required: bool) -> Result<Self> {
        #[cfg(feature = "tun")]
        {
            if required {
                return NETWORK_RUNTIME_STATE
                    .compare_exchange(
                        0,
                        CONFIGURED_NETWORK_RUNTIME,
                        std::sync::atomic::Ordering::AcqRel,
                        std::sync::atomic::Ordering::Acquire,
                    )
                    .map(|_| Self { configured: true })
                    .map_err(|_| {
                        Error::Operation(
                            "another runtime already owns the process-global network configuration"
                                .to_owned(),
                        )
                    });
            }

            loop {
                let users =
                    NETWORK_RUNTIME_STATE.load(std::sync::atomic::Ordering::Acquire);
                if users == CONFIGURED_NETWORK_RUNTIME {
                    return Err(Error::Operation(
                        "another runtime already owns the process-global network configuration"
                            .to_owned(),
                    ));
                }
                if NETWORK_RUNTIME_STATE
                    .compare_exchange(
                        users,
                        users + 1,
                        std::sync::atomic::Ordering::AcqRel,
                        std::sync::atomic::Ordering::Acquire,
                    )
                    .is_ok()
                {
                    return Ok(Self { configured: false });
                }
            }
        }

        #[cfg(not(feature = "tun"))]
        {
            let _ = required;
            Ok(Self {})
        }
    }

    #[cfg(feature = "tun")]
    pub(super) fn ensure_active(&mut self) -> Result<()> {
        if self.configured {
            return Ok(());
        }
        NETWORK_RUNTIME_STATE
            .compare_exchange(
                1,
                CONFIGURED_NETWORK_RUNTIME,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .map(|_| {
                self.configured = true;
            })
            .map_err(|_| {
                Error::Operation(
                    "another runtime already owns the process-global network configuration"
                        .to_owned(),
                )
            })
    }

    #[cfg(feature = "tun")]
    pub(super) fn deactivate_to_neutral(&mut self) {
        if self.configured {
            NETWORK_RUNTIME_STATE.store(1, std::sync::atomic::Ordering::Release);
            self.configured = false;
        }
    }

    #[cfg(feature = "tun")]
    fn release(&mut self) {
        if self.configured {
            NETWORK_RUNTIME_STATE.store(0, std::sync::atomic::Ordering::Release);
            self.configured = false;
        } else {
            NETWORK_RUNTIME_STATE.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        }
    }
}

impl Drop for NetworkRuntimeLease {
    fn drop(&mut self) {
        #[cfg(feature = "tun")]
        {
            self.release();
        }
    }
}

pub(super) fn uses_process_global_network_state(config: &InternalConfig) -> bool {
    #[cfg(feature = "tun")]
    {
        config.tun.enable
            || config.tun.so_mark.is_some()
            || config.general.interface.is_some()
    }

    #[cfg(not(feature = "tun"))]
    {
        let _ = config;
        false
    }
}

#[cfg(feature = "tun")]
#[derive(Clone)]
pub(super) struct RuntimeNetworkConfig {
    pub(super) tun_enabled: bool,
    pub(super) tun_so_mark: Option<u32>,
    pub(super) interface: Option<Interface>,
}

#[cfg(feature = "tun")]
impl RuntimeNetworkConfig {
    pub(super) fn uses_global_state(&self) -> bool {
        self.tun_enabled || self.tun_so_mark.is_some() || self.interface.is_some()
    }

    pub(super) async fn activate(&self) -> Result<()> {
        if !self.uses_global_state() {
            return Ok(());
        }
        init_net_config(self.tun_enabled, self.tun_so_mark, self.interface.as_ref())
            .await?;
        install_default_socket_protector();
        Ok(())
    }
}

pub(super) struct NetworkRecoveryRequest {
    pub(super) snapshot: Option<app::network::NetworkSnapshot>,
    pub(super) path_changed: bool,
    pub(super) cause: app::runtime_state::RecoveryCause,
    pub(super) observation_error: Option<String>,
}

pub(super) async fn recover_to_latest_environment<F, Fut>(
    observer: &mut app::network::NetworkObserver,
    status: &tokio::sync::RwLock<app::network::NetworkStatus>,
    request: NetworkRecoveryRequest,
    mut latest_samples: Option<
        &mut tokio::sync::watch::Receiver<Option<app::network::NetworkSample>>,
    >,
    mut recover: F,
) -> Result<app::network::NetworkResetResponse>
where
    F: FnMut(Option<app::network::NetworkSnapshot>, bool) -> Fut,
    Fut: std::future::Future<Output = app::runtime_state::RecoveryReport>,
{
    const MAX_RECOVERY_ATTEMPTS_PER_CHANGE: u32 = 2;
    let mut attempts = 0_u32;
    let NetworkRecoveryRequest {
        mut snapshot,
        mut path_changed,
        mut cause,
        mut observation_error,
    } = request;
    loop {
        attempts = attempts.saturating_add(1);
        let started_at = tokio::time::Instant::now();
        let token = status
            .write()
            .await
            .begin(cause, snapshot.as_ref())
            .ok_or_else(|| {
                Error::Operation(
                    "runtime cannot recover in its current lifecycle".into(),
                )
            })?;
        let mut report = recover(snapshot.clone(), path_changed).await;
        report.observation_error = observation_error.take();

        // The sampler runs independently while DNS and pool resets wait. If a
        // newer network is already known, retain this attempt as superseded and
        // recover the latest environment before reporting success.
        if let Some(samples) = latest_samples.as_deref_mut()
            && let Some(sample) =
                app::network::take_sample_after(samples, started_at)
        {
            match sample.result.clone() {
                Ok(newest) => {
                    let changed = snapshot.as_ref() != Some(&newest);
                    status.write().await.observed_sample(&sample);
                    if changed {
                        status.write().await.supersede(token, report);
                        let retry =
                            observer.observe(&newest, tokio::time::Instant::now());
                        path_changed = retry.unwrap_or(true);
                        cause = if attempts >= MAX_RECOVERY_ATTEMPTS_PER_CHANGE {
                            app::runtime_state::RecoveryCause::Retry
                        } else {
                            app::runtime_state::RecoveryCause::NetworkChanged
                        };
                        snapshot = Some(newest);
                        observation_error = None;
                        if attempts >= MAX_RECOVERY_ATTEMPTS_PER_CHANGE {
                            let message =
                                "network changed repeatedly during recovery";
                            let token = status
                                .write()
                                .await
                                .begin(cause, snapshot.as_ref())
                                .ok_or_else(|| Error::Operation(message.into()))?;
                            let report = app::runtime_state::RecoveryReport {
                                interface:
                                    app::runtime_state::ComponentResult::skipped(),
                                dns: app::runtime_state::ComponentResult::skipped(),
                                pools: app::runtime_state::ComponentResult::skipped(
                                ),
                                observation_error: Some(message.into()),
                                offline: snapshot
                                    .as_ref()
                                    .is_none_or(|value| !value.has_path()),
                            };
                            let delay = observer
                                .retry(path_changed, tokio::time::Instant::now());
                            status.write().await.complete(
                                token,
                                report.clone(),
                                Some(delay),
                            );
                            return report.into_result();
                        }
                        continue;
                    }
                }
                Err(error) => {
                    status.write().await.observation_failed_sample(&sample);
                    report.observation_error = Some(error);
                }
            }
        }

        let failed = report.error().is_some();
        let retry = failed
            .then(|| observer.retry(path_changed, tokio::time::Instant::now()));
        if !status.write().await.complete(token, report.clone(), retry) {
            return Err(Error::Operation(
                "discarded stale network recovery result".into(),
            ));
        }
        if !failed && let Some(snapshot) = snapshot {
            observer.applied(snapshot);
        }
        return report.into_result();
    }
}

pub(super) async fn finish_reload_status(
    status: &tokio::sync::RwLock<app::network::NetworkStatus>,
    done: oneshot::Sender<Result<()>>,
    result: Result<()>,
) -> std::result::Result<(), Result<()>> {
    status
        .write()
        .await
        .reload_finished(result.as_ref().err().map(ToString::to_string));
    done.send(result)
}
