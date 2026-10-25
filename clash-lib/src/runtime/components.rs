use std::sync::Arc;

use tokio::sync::{Mutex, broadcast};
use tracing::warn;

use super::network::{NetworkRecoveryRequest, recover_to_latest_environment};
#[cfg(feature = "tun")]
use super::network::{NetworkRuntimeLease, RuntimeNetworkConfig};
use crate::{
    GlobalState, Result,
    app::{
        self,
        dispatcher::{Dispatcher, StatisticsManager},
        dns::{self, ThreadSafeDNSResolver, config::DNSListenAddr},
        inbound::manager::InboundManager,
        logging::LogEvent,
        outbound::manager::OutboundManager,
        profile,
        router::Router,
    },
    config,
    runner::Runner,
};
#[cfg(feature = "tun")]
use crate::{app::net::clear_net_config, proxy::tun};

pub(super) struct RuntimeComponents {
    pub(super) cache_store: profile::ThreadSafeCacheFile,
    pub(super) dns_resolver: ThreadSafeDNSResolver,
    pub(super) outbound_manager: Arc<OutboundManager>,
    pub(super) router: Arc<Router>,
    pub(super) dispatcher: Arc<Dispatcher>,
    pub(super) statistics_manager: Arc<StatisticsManager>,

    #[cfg(feature = "tun")]
    pub(super) tun_runner: Arc<tun::TunRunner>,
    pub(super) dns_listener: Arc<dns::DnsRunner>,
    pub(super) inbound_manager: Arc<InboundManager>,
    pub(super) dns_listen: DNSListenAddr,
    pub(super) dns_enabled: bool,
    pub(super) ipv6_allowed: bool,
    #[cfg(feature = "tun")]
    pub(super) network_config: RuntimeNetworkConfig,
}

impl RuntimeComponents {
    pub(super) fn tun_candidate_exclusion(
        &self,
    ) -> app::network::TunCandidateExclusion {
        #[cfg(feature = "tun")]
        {
            if self.tun_runner.is_enabled() {
                self.tun_runner
                    .interface_name_hint()
                    .map(app::network::TunCandidateExclusion::Named)
                    .unwrap_or(app::network::TunCandidateExclusion::Unidentified)
            } else {
                app::network::TunCandidateExclusion::Disabled
            }
        }
        #[cfg(not(feature = "tun"))]
        {
            app::network::TunCandidateExclusion::Disabled
        }
    }
}

pub(super) async fn refresh_runtime_health(
    components: &RuntimeComponents,
    api_listener: &app::api::ApiRunner,
    status: &tokio::sync::RwLock<app::network::NetworkStatus>,
) {
    use app::runtime_state::{
        RuntimeComponent as Name, RuntimeComponentPhase as Phase,
    };

    let api_configured = api_listener.is_configured();
    let api_finished = api_listener.task_finished();
    let dns_configured = components.dns_listener.is_configured();
    let dns_finished = components.dns_listener.task_finished();
    let inbound_configured =
        components.inbound_manager.has_configured_listeners().await;
    let inbound_failed = components.inbound_manager.has_finished_listener().await;

    #[cfg(feature = "tun")]
    let tun_update = {
        let enabled = components.tun_runner.is_enabled();
        let failed = enabled && components.tun_runner.task_finished();
        (
            Name::Tun,
            if !enabled {
                Phase::NotConfigured
            } else if failed {
                Phase::Failed
            } else {
                Phase::Ready
            },
            failed.then(|| "TUN runner task exited unexpectedly".to_owned()),
        )
    };
    #[cfg(not(feature = "tun"))]
    let tun_update = (Name::Tun, Phase::NotConfigured, None);

    let updates = vec![
        (
            Name::Api,
            if !api_configured {
                Phase::NotConfigured
            } else if api_finished {
                Phase::Failed
            } else {
                Phase::Ready
            },
            (api_configured && api_finished)
                .then(|| "API listener task exited unexpectedly".to_owned()),
        ),
        (
            Name::Dns,
            if !dns_configured {
                Phase::NotConfigured
            } else if dns_finished {
                Phase::Failed
            } else {
                Phase::Ready
            },
            (dns_configured && dns_finished)
                .then(|| "DNS listener task exited unexpectedly".to_owned()),
        ),
        (
            Name::Inbound,
            if !inbound_configured {
                Phase::NotConfigured
            } else if inbound_failed {
                Phase::Failed
            } else {
                Phase::Ready
            },
            inbound_failed.then(|| {
                "one or more inbound listener tasks exited unexpectedly".to_owned()
            }),
        ),
        tun_update,
    ];

    let mut status = status.write().await;
    for (name, phase, error) in updates {
        if status.set_component(name, phase, error.clone()) && phase == Phase::Failed
        {
            warn!(?name, error = ?error, "runtime component failed");
        }
    }
    status.expire_health();
}

impl RuntimeComponents {
    pub(super) async fn apply_network_observation(
        &self,
        observer: &mut app::network::NetworkObserver,
        status: &tokio::sync::RwLock<app::network::NetworkStatus>,
        snapshot: app::network::NetworkSnapshot,
        latest_samples: &mut tokio::sync::watch::Receiver<
            Option<app::network::NetworkSample>,
        >,
    ) {
        status.write().await.observed(&snapshot);
        let Some(path_changed) =
            observer.observe(&snapshot, tokio::time::Instant::now())
        else {
            return;
        };
        let cause = if observer.is_applied(&snapshot) {
            app::runtime_state::RecoveryCause::Retry
        } else {
            app::runtime_state::RecoveryCause::NetworkChanged
        };
        let _ = self
            .perform_network_recovery(
                observer,
                status,
                NetworkRecoveryRequest {
                    snapshot: Some(snapshot),
                    path_changed,
                    cause,
                    observation_error: None,
                },
                Some(latest_samples),
            )
            .await;
    }

    pub(super) async fn perform_network_recovery(
        &self,
        observer: &mut app::network::NetworkObserver,
        status: &tokio::sync::RwLock<app::network::NetworkStatus>,
        request: NetworkRecoveryRequest,
        latest_samples: Option<
            &mut tokio::sync::watch::Receiver<Option<app::network::NetworkSample>>,
        >,
    ) -> Result<app::network::NetworkResetResponse> {
        recover_to_latest_environment(
            observer,
            status,
            request,
            latest_samples,
            |snapshot, path_changed| async move {
                self.recover_network(snapshot.as_ref(), path_changed).await
            },
        )
        .await
    }

    async fn recover_network(
        &self,
        snapshot: Option<&app::network::NetworkSnapshot>,
        path_changed: bool,
    ) -> app::runtime_state::RecoveryReport {
        #[cfg(feature = "tun")]
        let mut interface_result = app::runtime_state::ComponentResult::skipped();
        #[cfg(not(feature = "tun"))]
        let interface_result = app::runtime_state::ComponentResult::skipped();
        #[cfg(feature = "tun")]
        if self.network_config.uses_global_state()
            && let Some(snapshot) = snapshot
        {
            let selected = if self.network_config.interface.is_some() {
                app::net::resolve_outbound_interface(
                    self.network_config.interface.as_ref(),
                )
                .await
            } else if self.network_config.tun_enabled {
                match snapshot.ipv4.as_ref().or(snapshot.ipv6.as_ref()) {
                    Some(path) => {
                        app::net::resolve_outbound_interface(Some(
                            &app::net::Interface::Name(path.interface.clone()),
                        ))
                        .await
                    }
                    None => Ok(None),
                }
            } else {
                Ok(None)
            };
            match selected {
                Ok(interface) => {
                    interface_result =
                        app::runtime_state::ComponentResult::refreshed(0);
                    *app::net::DEFAULT_OUTBOUND_INTERFACE.write().await = interface;
                    #[cfg(target_os = "macos")]
                    {
                        let ipv6 = if self.network_config.interface.is_none()
                            && self.network_config.tun_enabled
                        {
                            snapshot.ipv6.as_ref().and_then(|path| {
                                app::net::get_interface_by_name(&path.interface)
                            })
                        } else {
                            None
                        };
                        *app::net::DEFAULT_OUTBOUND_INTERFACE_V6.write().await =
                            ipv6;
                    }
                    app::net::OUTBOUND_INTERFACE_UNAVAILABLE
                        .store(false, std::sync::atomic::Ordering::Release);
                }
                Err(error) => {
                    app::net::OUTBOUND_INTERFACE_UNAVAILABLE
                        .store(true, std::sync::atomic::Ordering::Release);
                    interface_result =
                        app::runtime_state::ComponentResult::failed(error);
                }
            }
        }
        if path_changed {
            self.dispatcher.invalidate_network_sessions();
        }
        let mut report = app::network::reset_resources_report(
            self.dns_resolver.reset_transports(),
            async {
                if path_changed {
                    self.outbound_manager.reset_connection_pools().await
                } else {
                    Ok(0)
                }
            },
        )
        .await;
        report.interface = interface_result;
        report.offline = snapshot.is_some_and(|snapshot| !snapshot.has_path());
        if !path_changed {
            report.pools = app::runtime_state::ComponentResult::skipped();
        }
        report
    }

    pub(super) fn api_listener(
        &self,
        controller_cfg: config::internal::config::Controller,
        log_tx: broadcast::Sender<LogEvent>,
        global_state: Arc<Mutex<GlobalState>>,
        cwd: &std::path::Path,
        cancellation_token: tokio_util::sync::CancellationToken,
    ) -> Arc<app::api::ApiRunner> {
        Arc::new(app::api::ApiRunner::new(
            controller_cfg,
            log_tx,
            self.inbound_manager.clone(),
            self.dispatcher.clone(),
            global_state,
            self.dns_resolver.clone(),
            self.outbound_manager.clone(),
            self.statistics_manager.clone(),
            self.cache_store.clone(),
            self.router.clone(),
            cwd.to_string_lossy().to_string(),
            Some(cancellation_token),
            self.dns_listen.clone(),
            self.dns_enabled,
            self.ipv6_allowed,
        ))
    }

    pub(super) fn start_all(&self) {
        #[cfg(all(feature = "tun", not(target_os = "macos")))]
        self.tun_runner.run_async();
        self.dns_listener.run_async();
        #[cfg(not(target_os = "macos"))]
        self.inbound_manager.run_async();
    }

    pub(super) async fn wait_initial_ready(
        &self,
        status: &tokio::sync::RwLock<app::network::NetworkStatus>,
    ) -> Result<()> {
        if let Err(error) = self.dns_listener.wait_ready().await {
            status.write().await.set_component(
                app::runtime_state::RuntimeComponent::Dns,
                app::runtime_state::RuntimeComponentPhase::Failed,
                Some(error.to_string()),
            );
            return Err(error);
        }
        status.write().await.set_component(
            app::runtime_state::RuntimeComponent::Dns,
            if self.dns_listener.is_configured() {
                app::runtime_state::RuntimeComponentPhase::Ready
            } else {
                app::runtime_state::RuntimeComponentPhase::NotConfigured
            },
            None,
        );

        #[cfg(feature = "tun")]
        {
            #[cfg(target_os = "macos")]
            self.tun_runner.run_async();
            if let Err(error) = self.tun_runner.wait_ready().await {
                status.write().await.set_component(
                    app::runtime_state::RuntimeComponent::Tun,
                    app::runtime_state::RuntimeComponentPhase::Failed,
                    Some(error.to_string()),
                );
                return Err(error);
            }
            status.write().await.set_component(
                app::runtime_state::RuntimeComponent::Tun,
                if self.tun_runner.is_enabled() {
                    app::runtime_state::RuntimeComponentPhase::Ready
                } else {
                    app::runtime_state::RuntimeComponentPhase::NotConfigured
                },
                None,
            );
        }
        #[cfg(not(feature = "tun"))]
        status.write().await.set_component(
            app::runtime_state::RuntimeComponent::Tun,
            app::runtime_state::RuntimeComponentPhase::NotConfigured,
            None,
        );

        #[cfg(target_os = "macos")]
        {
            self.inbound_manager.run_async();
        }

        #[cfg(all(target_os = "macos", not(feature = "tun")))]
        self.inbound_manager.run_async();

        if let Err(error) = self.inbound_manager.wait_ready().await {
            status.write().await.set_component(
                app::runtime_state::RuntimeComponent::Inbound,
                app::runtime_state::RuntimeComponentPhase::Failed,
                Some(error.to_string()),
            );
            return Err(error);
        }
        let inbound_configured =
            self.inbound_manager.has_configured_listeners().await;
        status.write().await.set_component(
            app::runtime_state::RuntimeComponent::Inbound,
            if inbound_configured {
                app::runtime_state::RuntimeComponentPhase::Ready
            } else {
                app::runtime_state::RuntimeComponentPhase::NotConfigured
            },
            None,
        );
        Ok(())
    }

    pub(super) async fn fresh_data_plane(&self) -> Result<Self> {
        let cancellation_token = tokio_util::sync::CancellationToken::new();
        Ok(Self {
            cache_store: self.cache_store.clone(),
            dns_resolver: self.dns_resolver.clone(),
            outbound_manager: self.outbound_manager.clone(),
            router: self.router.clone(),
            dispatcher: self.dispatcher.clone(),
            statistics_manager: self.statistics_manager.clone(),
            #[cfg(feature = "tun")]
            tun_runner: Arc::new(
                self.tun_runner.fresh(cancellation_token.child_token())?,
            ),
            dns_listener: Arc::new(
                self.dns_listener.fresh(cancellation_token.child_token()),
            ),
            inbound_manager: Arc::new(
                self.inbound_manager
                    .fresh(cancellation_token.child_token())
                    .await,
            ),
            dns_listen: self.dns_listen.clone(),
            dns_enabled: self.dns_enabled,
            ipv6_allowed: self.ipv6_allowed,
            #[cfg(feature = "tun")]
            network_config: self.network_config.clone(),
        })
    }

    pub(super) fn stop_all(&self) {
        self.dns_listener.shutdown();
        #[cfg(feature = "tun")]
        self.tun_runner.shutdown();
        Runner::shutdown(self.inbound_manager.as_ref());
    }

    #[cfg(feature = "tun")]
    pub(super) async fn activate_network_config(&self) -> Result<()> {
        self.network_config.activate().await
    }

    pub(super) async fn stop_all_and_join(&self, _clear_network: bool) {
        self.stop_all();

        tracing::debug!("todo: validate");
        if let Err(err) = self.dns_listener.join().await {
            warn!("failed waiting for dns listener shutdown: {}", err);
        }

        #[cfg(feature = "tun")]
        {
            if let Err(err) = self.tun_runner.join().await {
                warn!("failed waiting for tun runner shutdown: {}", err);
            }
            if _clear_network && self.network_config.uses_global_state() {
                clear_net_config().await;
            }
        }

        if let Err(err) = self.inbound_manager.join().await {
            warn!("failed waiting for inbound manager shutdown: {}", err);
        }
    }
}

#[cfg(feature = "tun")]
pub(super) async fn restore_network_after_failed_reload(
    active_components: &RuntimeComponents,
    new_components: &RuntimeComponents,
    network_runtime_lease: &mut NetworkRuntimeLease,
) -> Result<()> {
    if !new_components.network_config.uses_global_state() {
        return Ok(());
    }

    restore_active_network_config(active_components, network_runtime_lease).await
}

#[cfg(feature = "tun")]
pub(super) async fn restore_active_network_config(
    active_components: &RuntimeComponents,
    network_runtime_lease: &mut NetworkRuntimeLease,
) -> Result<()> {
    if active_components.network_config.uses_global_state() {
        network_runtime_lease.ensure_active()?;
        active_components.activate_network_config().await
    } else {
        clear_net_config().await;
        network_runtime_lease.deactivate_to_neutral();
        Ok(())
    }
}
