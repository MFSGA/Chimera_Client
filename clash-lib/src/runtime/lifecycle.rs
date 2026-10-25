use std::{
    path::PathBuf,
    sync::{Arc, OnceLock},
};

use futures::FutureExt;
use tokio::sync::{Mutex, broadcast, mpsc, oneshot};
use tracing::{debug, error, info, warn};

#[cfg(feature = "tun")]
use super::components::{
    restore_active_network_config, restore_network_after_failed_reload,
};
use super::{
    components::refresh_runtime_health,
    factory::create_components,
    network::{
        NetworkRecoveryRequest, NetworkRuntimeLease, finish_reload_status,
        uses_process_global_network_state,
    },
};
#[cfg(feature = "tun")]
use crate::app::net::clear_net_config;
use crate::{
    Config, Error, GlobalState, Options, Result, TokioRuntime, app,
    app::logging::LogEvent, config::internal::InternalConfig, runner::Runner,
};

pub fn start_scaffold(opts: Options) -> Result<()> {
    let rt = match opts.rt.as_ref().unwrap_or(&TokioRuntime::MultiThread) {
        TokioRuntime::MultiThread => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?,
        TokioRuntime::SingleThread => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?,
    };

    let config_path = opts.config_path.or_else(|| {
        if let Config::File(ref path) = opts.config {
            Some(path.clone())
        } else {
            None
        }
    });
    let config: InternalConfig = opts.config.try_parse()?;
    let cwd = opts.cwd.unwrap_or_else(|| ".".to_string());
    let (log_tx, _) = broadcast::channel(100);

    let log_collector = app::logging::EventCollector::new(vec![log_tx.clone()]);

    app::logging::setup_logging(
        config.general.log_level,
        log_collector,
        &cwd,
        opts.log_file,
    );

    rt.block_on(async {
        match start(config, cwd, config_path, log_tx).await {
            Err(e) => {
                eprintln!("start error: {e}");
                Err(e)
            }
            Ok(_) => Ok(()),
        }
    })
}

enum InstanceStartupEvent {
    Ready,
    Failed(Error),
}

/// Start one runtime in a background thread with an independent shutdown token.
/// This is primarily useful for integration tests that need an independently
/// controlled instance. When the `tun` feature is enabled, starts that need
/// process-global network/TUN state are rejected while another such runtime is
/// active.
pub fn start_scaffold_instance(
    opts: Options,
) -> Result<(
    std::thread::JoinHandle<()>,
    tokio_util::sync::CancellationToken,
)> {
    let config_path = opts.config_path.or_else(|| {
        if let Config::File(ref path) = opts.config {
            Some(path.clone())
        } else {
            None
        }
    });
    let config: InternalConfig = opts.config.try_parse()?;
    let cwd = opts.cwd.unwrap_or_else(|| ".".to_string());
    let rt_kind = opts.rt.unwrap_or(TokioRuntime::MultiThread);
    let log_file = opts.log_file;
    let token = tokio_util::sync::CancellationToken::new();
    let token_clone = token.clone();
    let network_runtime_lease =
        NetworkRuntimeLease::acquire(uses_process_global_network_state(&config))?;
    let (startup_tx, startup_rx) = std::sync::mpsc::channel();

    let handle = std::thread::spawn(move || {
        let rt = match match rt_kind {
            TokioRuntime::MultiThread => tokio::runtime::Builder::new_multi_thread(),
            TokioRuntime::SingleThread => {
                tokio::runtime::Builder::new_current_thread()
            }
        }
        .enable_all()
        .build()
        {
            Ok(rt) => rt,
            Err(err) => {
                let _ =
                    startup_tx.send(InstanceStartupEvent::Failed(Error::Io(err)));
                return;
            }
        };

        let (log_tx, _) = broadcast::channel(100);
        let log_collector = app::logging::EventCollector::new(vec![log_tx.clone()]);
        app::logging::setup_logging(
            config.general.log_level,
            log_collector,
            &cwd,
            log_file,
        );

        if let Err(err) = rt.block_on(start_with_shutdown_token(
            config,
            cwd,
            config_path,
            log_tx,
            token_clone,
            network_runtime_lease,
            Some(startup_tx.clone()),
        )) && let Err(send_err) =
            startup_tx.send(InstanceStartupEvent::Failed(err))
            && let InstanceStartupEvent::Failed(err) = send_err.0
        {
            eprintln!("independent runtime error: {err}");
        }
    });

    match startup_rx.recv() {
        Ok(InstanceStartupEvent::Ready) => Ok((handle, token)),
        Ok(InstanceStartupEvent::Failed(err)) => {
            token.cancel();
            let _ = handle.join();
            Err(err)
        }
        Err(err) => {
            token.cancel();
            let _ = handle.join();
            Err(Error::Operation(format!(
                "independent runtime startup channel closed: {err}"
            )))
        }
    }
}

static CRYPTO_PROVIDER_LOCK: OnceLock<()> = OnceLock::new();

pub fn setup_default_crypto_provider() {
    CRYPTO_PROVIDER_LOCK.get_or_init(|| {
        #[cfg(feature = "aws-lc-rs")]
        {
            _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        }
        #[cfg(feature = "ring")]
        {
            _ = rustls::crypto::ring::default_provider().install_default();
        }
    });
}

async fn wait_for_shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        )?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

pub(super) enum RuntimeExit<T> {
    Control(std::result::Result<T, tokio::task::JoinError>),
    Signal(std::io::Result<()>),
    Cancelled,
}

pub(super) async fn wait_for_control_or_shutdown<T, S>(
    control: &mut tokio::task::JoinHandle<T>,
    shutdown: &tokio_util::sync::CancellationToken,
    signal: S,
) -> RuntimeExit<T>
where
    S: std::future::Future<Output = std::io::Result<()>>,
{
    tokio::select! {
        biased;
        result = control => RuntimeExit::Control(result),
        _ = shutdown.cancelled() => RuntimeExit::Cancelled,
        result = signal => RuntimeExit::Signal(result),
    }
}

pub(super) async fn catch_control_panic<F>(control: F) -> Result<()>
where
    F: std::future::Future<Output = Result<()>>,
{
    match std::panic::AssertUnwindSafe(control).catch_unwind().await {
        Ok(result) => result,
        Err(_) => Err(Error::Operation("runtime control task panicked".to_owned())),
    }
}

pub async fn start(
    config: InternalConfig,
    cwd: String,
    config_path: Option<String>,
    log_tx: broadcast::Sender<LogEvent>,
) -> Result<()> {
    let config = config.validate()?;
    let network_runtime_lease =
        NetworkRuntimeLease::acquire(uses_process_global_network_state(&config))?;
    let shutdown_token = tokio_util::sync::CancellationToken::new();
    let _shutdown_registration =
        ShutdownTokenRegistration::register(shutdown_token.clone());
    start_with_shutdown_token(
        config,
        cwd,
        config_path,
        log_tx,
        shutdown_token,
        network_runtime_lease,
        None,
    )
    .await
}

async fn start_with_shutdown_token(
    config: InternalConfig,
    cwd: String,
    config_path: Option<String>,
    log_tx: broadcast::Sender<LogEvent>,
    shutdown_token: tokio_util::sync::CancellationToken,
    network_runtime_lease: NetworkRuntimeLease,
    startup_tx: Option<std::sync::mpsc::Sender<InstanceStartupEvent>>,
) -> Result<()> {
    let config = config.validate()?;
    setup_default_crypto_provider();
    let cwd = PathBuf::from(cwd);

    // things we need to clone before consuming config
    let controller_cfg = config.general.controller.clone();
    let log_level = config.general.log_level;

    let components = create_components(cwd.clone(), config, true).await?;

    let (reload_tx, mut reload_rx) = mpsc::channel(1);
    let (network_reset_tx, mut network_reset_rx) = mpsc::channel::<
        oneshot::Sender<Result<app::network::NetworkResetResponse>>,
    >(8);
    let network_status = Arc::new(tokio::sync::RwLock::new(
        app::network::NetworkStatus::default(),
    ));
    let observed_tun_exclusion = Arc::new(tokio::sync::RwLock::new(
        components.tun_candidate_exclusion(),
    ));
    let (network_samples_tx, mut network_samples) =
        tokio::sync::watch::channel(None);

    let (traffic_tx, mut traffic_rx) = mpsc::channel(128);
    let traffic_reporter = network_status.write().await.traffic_reporter(traffic_tx);
    components
        .outbound_manager
        .attach_network_status(network_status.clone())
        .await;
    components
        .outbound_manager
        .attach_traffic_reporter(traffic_reporter.clone())
        .await;
    components
        .dispatcher
        .attach_traffic_reporter(traffic_reporter.clone());
    components
        .dispatcher
        .attach_network_status(network_status.clone());
    let final_status = network_status.clone();

    let global_state = Arc::new(Mutex::new(GlobalState {
        log_level,
        #[cfg(feature = "tun")]
        tunnel_runner: components.tun_runner.clone(),
        dns_listener: components.dns_listener.clone(),
        reload_tx,
        network_reset_tx,
        network_status: network_status.clone(),
        cwd: cwd.to_string_lossy().to_string(),
        config_path,
    }));

    let api_listener = components.api_listener(
        controller_cfg.clone(),
        log_tx.clone(),
        global_state.clone(),
        &cwd,
        shutdown_token.child_token(),
    );

    // api_listener is not part of components because it requires components to be
    // initialized before it can be initialized. start it manually.
    api_listener.run_async();
    if let Err(err) = api_listener.wait_ready().await {
        network_status.write().await.set_component(
            app::runtime_state::RuntimeComponent::Api,
            app::runtime_state::RuntimeComponentPhase::Failed,
            Some(err.to_string()),
        );
        api_listener.shutdown();
        let _ = api_listener.join().await;
        components.stop_all_and_join(true).await;
        network_status.write().await.lifecycle(
            app::runtime_state::Lifecycle::Failed,
            "listenerStartupFailed",
        );
        return Err(err);
    }

    {
        let mut g = global_state.lock().await;
        #[cfg(feature = "tun")]
        {
            g.tunnel_runner = components.tun_runner.clone();
        }
        g.dns_listener = components.dns_listener.clone();
    }

    components.start_all();
    if let Err(err) = components.wait_initial_ready(&network_status).await {
        api_listener.shutdown();
        let _ = api_listener.join().await;
        components.stop_all_and_join(true).await;
        network_status.write().await.lifecycle(
            app::runtime_state::Lifecycle::Failed,
            "listenerStartupFailed",
        );
        return Err(err);
    }

    refresh_runtime_health(&components, api_listener.as_ref(), &network_status)
        .await;
    network_status
        .write()
        .await
        .lifecycle(app::runtime_state::Lifecycle::Running, "listenersReady");
    if let Some(startup_tx) = startup_tx {
        startup_tx.send(InstanceStartupEvent::Ready).map_err(|_| {
            Error::Operation(
                "independent runtime startup receiver dropped before readiness"
                    .to_owned(),
            )
        })?;
    }
    let network_sampler = app::network::AUTOMATIC_SUPPORTED.then(|| {
        let sampler_token = shutdown_token.child_token();
        let tun_exclusion = observed_tun_exclusion.clone();
        tokio::spawn(app::network::run_sampler(
            sampler_token,
            network_samples_tx,
            move || {
                let tun_exclusion = tun_exclusion.clone();
                async move {
                    let exclusion = tun_exclusion.read().await.clone();
                    app::network::snapshot_with_tun(exclusion).await
                }
            },
        ))
    });
    let sampler_started = network_sampler.is_some();

    let cwd_clone = cwd.clone();

    let reload_token = shutdown_token.clone();
    let mut reload_handle = tokio::spawn(async move {
        #[cfg(feature = "tun")]
        let mut network_runtime_lease = network_runtime_lease;
        #[cfg(not(feature = "tun"))]
        let _network_runtime_lease = network_runtime_lease;
        let mut active_components = components;
        let mut active_api_listener = api_listener;
        let mut active_controller_cfg = controller_cfg;
        let mut network_observer = app::network::NetworkObserver::default();
        let mut sampler_running = sampler_started;
        let mut health_interval =
            tokio::time::interval(std::time::Duration::from_secs(2));
        health_interval
            .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        network_status.write().await.set_component(
            app::runtime_state::RuntimeComponent::Control,
            app::runtime_state::RuntimeComponentPhase::Ready,
            None,
        );

        // Listen for config reload signal and reload config.
        let control_result = catch_control_panic(async {
            loop {
            tokio::select! {
                biased;
                _ = reload_token.cancelled() => {
                    network_status.write().await.lifecycle(app::runtime_state::Lifecycle::Stopping, "shutdownRequested");
                    info!("runtime shutdown requested");
                    break Ok(());
                }
                Some(done) = network_reset_rx.recv() => {
                    if done.is_closed() { continue; }
                    let recovery = async {
                        let (snapshot, observation_error) = if app::network::AUTOMATIC_SUPPORTED {
                            match app::network::snapshot_with_tun(
                                active_components.tun_candidate_exclusion(),
                            ).await {
                                Ok(snapshot) => (Some(snapshot), None),
                                Err(error) => (None, Some(error.to_string())),
                            }
                        } else { (None, None) };
                        active_components.perform_network_recovery(
                            &mut network_observer,
                            &network_status,
                            NetworkRecoveryRequest {
                                snapshot,
                                path_changed: true,
                                cause: app::runtime_state::RecoveryCause::ManualReset,
                                observation_error,
                            },
                            Some(&mut network_samples),
                        ).await
                    };
                    let result = tokio::select! {
                        biased;
                        _ = reload_token.cancelled() => { continue; }
                        result = recovery => result,
                    };
                    let _ = done.send(result);
                }

                maybe_reload = reload_rx.recv() => {
                    let Some((config, done)) = maybe_reload else {
                        break Err(Error::Operation(
                            "runtime reload channel closed unexpectedly".to_owned(),
                        ));
                    };

                    network_status.write().await.lifecycle(app::runtime_state::Lifecycle::Reloading, "reloadRequested");
                    info!("reloading config");
                    let config = match config.try_parse() {
                        Ok(c) => c,
                        Err(e) => {
                            error!("failed to reload config: {}", e);
                            let _ = finish_reload_status(&network_status, done, Err(e)).await;
                            continue;
                        }
                    };
                    info!("reloading get config 2");
                    let candidate_controller_cfg = config.general.controller.clone();

                    // Build the replacement runtime while the current one is still
                    // serving traffic. Construction performs all fallible config,
                    // provider, DNS, and data-file initialization without binding
                    // listeners or touching the active network configuration.
                    let new_components =
                        match create_components(cwd_clone.clone(), config, false).await {
                            Ok(components) => {
                                components.outbound_manager.attach_network_status(network_status.clone()).await;
                                components.outbound_manager.attach_traffic_reporter(traffic_reporter.clone()).await;
                                components.dispatcher.attach_traffic_reporter(traffic_reporter.clone());
                                components.dispatcher.attach_network_status(network_status.clone());
                                components
                            },
                            Err(e) => {
                                error!(
                                    "failed to prepare components during reload; keeping the active runtime: {}",
                                    e
                                );
                                let _ = finish_reload_status(&network_status, done, Err(e)).await;
                                continue;
                            }
                        };

                    // Validate and install the replacement interface/mark only after
                    // the complete candidate runtime has been prepared. A failure at
                    // this point still leaves every old listener and task running.
                    #[cfg(feature = "tun")]
                    if new_components.network_config.uses_global_state()
                        && let Err(e) = network_runtime_lease.ensure_active()
                    {
                        error!(
                            "failed to acquire network config during reload; keeping the active runtime: {}",
                            e
                        );
                        let _ = finish_reload_status(&network_status, done, Err(e)).await;
                        continue;
                    }
                    #[cfg(feature = "tun")]
                    if let Err(e) = new_components.activate_network_config().await {
                        error!(
                            "failed to activate network config during reload; keeping the active runtime: {}",
                            e
                        );
                        if let Err(restore_err) = restore_network_after_failed_reload(
                            &active_components,
                            &new_components,
                            &mut network_runtime_lease,
                        )
                        .await
                        {
                            let fatal = Error::Operation(format!(
                                "failed to restore active network configuration after reload failure: {restore_err}"
                            ));
                            let _ = finish_reload_status(&network_status, done, Err(fatal)).await;
                            reload_token.cancel();
                            break Err(Error::Operation(
                                "active network configuration could not be restored"
                                    .to_owned(),
                            ));
                        }
                        let _ = finish_reload_status(&network_status, done, Err(e)).await;
                        continue;
                    }

                    // Prepare restartable copies of the active data-plane runners
                    // before releasing any active listener. If this ever becomes
                    // fallible, the current runtime is still completely intact.
                    let rollback_components = match active_components
                        .fresh_data_plane()
                        .await
                    {
                        Ok(components) => components,
                        Err(err) => {
                            #[cfg(feature = "tun")]
                            if let Err(restore_err) = restore_network_after_failed_reload(
                                &active_components,
                                &new_components,
                                &mut network_runtime_lease,
                            )
                            .await
                            {
                                let fatal = Error::Operation(format!(
                                    "failed to restore active network configuration after rollback preparation failure: {restore_err}"
                                ));
                                let _ = finish_reload_status(&network_status, done, Err(fatal)).await;
                                reload_token.cancel();
                                break Err(Error::Operation(
                                    "active network configuration could not be restored"
                                        .to_owned(),
                                ));
                            }
                            let _ = finish_reload_status(&network_status, done, Err(Error::Operation(format!(
                                "failed to prepare active data-plane rollback: {err}"
                            )))).await;
                            continue;
                        }
                    };

                    // Validate the replacement controller before stopping the old
                    // data plane. The old controller has to release its listening
                    // socket first, but the old SOCKS/DNS/TUN runners remain alive
                    // until every replacement controller endpoint is ready.
                    let new_api_listener = new_components.api_listener(
                        candidate_controller_cfg.clone(),
                        log_tx.clone(),
                        global_state.clone(),
                        &cwd_clone,
                        reload_token.child_token(),
                    );
                    active_api_listener.shutdown();
                    if let Err(err) = active_api_listener.join().await {
                        warn!("failed waiting for api listener shutdown: {}", err);
                    }
                    new_api_listener.run_async();
                    if let Err(err) = new_api_listener.wait_ready().await {
                        network_status.write().await.set_component(
                            app::runtime_state::RuntimeComponent::Api,
                            app::runtime_state::RuntimeComponentPhase::Failed,
                            Some(err.to_string()),
                        );
                        error!(
                            "replacement API listener failed to become ready; restoring the active runtime: {}",
                            err
                        );
                        new_api_listener.shutdown();
                        let _ = new_api_listener.join().await;

                        #[cfg(feature = "tun")]
                        if let Err(restore_err) = restore_network_after_failed_reload(
                            &active_components,
                            &new_components,
                            &mut network_runtime_lease,
                        )
                        .await
                        {
                            let fatal = Error::Operation(format!(
                                "failed to restore active network configuration after controller reload failure: {restore_err}"
                            ));
                            let _ = finish_reload_status(&network_status, done, Err(fatal)).await;
                            reload_token.cancel();
                            break Err(Error::Operation(
                                "active network configuration could not be restored"
                                    .to_owned(),
                            ));
                        }

                        let restored_api_listener = active_components.api_listener(
                            active_controller_cfg.clone(),
                            log_tx.clone(),
                            global_state.clone(),
                            &cwd_clone,
                            reload_token.child_token(),
                        );
                        restored_api_listener.run_async();
                        if let Err(restore_err) = restored_api_listener.wait_ready().await {
                            network_status.write().await.set_component(
                                app::runtime_state::RuntimeComponent::Api,
                                app::runtime_state::RuntimeComponentPhase::Failed,
                                Some(restore_err.to_string()),
                            );
                            let fatal = Error::Operation(format!(
                                "failed to restore active API listener after reload failure: {restore_err}"
                            ));
                            let _ = finish_reload_status(&network_status, done, Err(fatal)).await;
                            reload_token.cancel();
                            restored_api_listener.shutdown();
                            let _ = restored_api_listener.join().await;
                            break Err(Error::Operation(
                                "active API listener could not be restored".to_owned(),
                            ));
                        }
                        active_api_listener = restored_api_listener;
                        refresh_runtime_health(
                            &active_components,
                            active_api_listener.as_ref(),
                            &network_status,
                        )
                        .await;
                        let _ = finish_reload_status(&network_status, done, Err(err)).await;
                        continue;
                    }

                    // The replacement controller is now bound successfully. Commit
                    // the data-plane switch only after that boundary has passed.
                    active_components.stop_all_and_join(false).await;
                    #[cfg(feature = "tun")]
                    if !new_components.network_config.uses_global_state() {
                        clear_net_config().await;
                        network_runtime_lease.deactivate_to_neutral();
                    }
                    new_components.start_all();
                    if let Err(err) =
                        new_components.wait_initial_ready(&network_status).await
                    {
                        error!(
                            "replacement data plane failed to become ready; restoring the active runtime: {}",
                            err
                        );
                        new_components.stop_all_and_join(false).await;
                        new_api_listener.shutdown();
                        let _ = new_api_listener.join().await;

                        #[cfg(feature = "tun")]
                        if let Err(restore_err) = restore_active_network_config(
                            &rollback_components,
                            &mut network_runtime_lease,
                        )
                        .await
                        {
                            let fatal = Error::Operation(format!(
                                "failed to restore active network configuration after data-plane reload failure: {restore_err}"
                            ));
                            let _ = finish_reload_status(&network_status, done, Err(fatal)).await;
                            reload_token.cancel();
                            break Err(Error::Operation(
                                "active network configuration could not be restored"
                                    .to_owned(),
                            ));
                        }

                        rollback_components.start_all();
                        if let Err(restore_err) =
                            rollback_components.wait_initial_ready(&network_status).await
                        {
                            let fatal = Error::Operation(format!(
                                "failed to restore active data plane after reload failure: {restore_err}"
                            ));
                            let _ = finish_reload_status(&network_status, done, Err(fatal)).await;
                            reload_token.cancel();
                            rollback_components.stop_all_and_join(true).await;
                            break Err(Error::Operation(
                                "active data plane could not be restored".to_owned(),
                            ));
                        }

                        {
                            let mut g = global_state.lock().await;
                            #[cfg(feature = "tun")]
                            {
                                g.tunnel_runner = rollback_components.tun_runner.clone();
                            }
                            g.dns_listener = rollback_components.dns_listener.clone();
                        }

                        let restored_api_listener = rollback_components.api_listener(
                            active_controller_cfg.clone(),
                            log_tx.clone(),
                            global_state.clone(),
                            &cwd_clone,
                            reload_token.child_token(),
                        );
                        restored_api_listener.run_async();
                        if let Err(restore_err) = restored_api_listener.wait_ready().await {
                            network_status.write().await.set_component(
                                app::runtime_state::RuntimeComponent::Api,
                                app::runtime_state::RuntimeComponentPhase::Failed,
                                Some(restore_err.to_string()),
                            );
                            let fatal = Error::Operation(format!(
                                "failed to restore active API listener after data-plane reload failure: {restore_err}"
                            ));
                            let _ = finish_reload_status(&network_status, done, Err(fatal)).await;
                            reload_token.cancel();
                            restored_api_listener.shutdown();
                            let _ = restored_api_listener.join().await;
                            break Err(Error::Operation(
                                "active API listener could not be restored".to_owned(),
                            ));
                        }

                        active_components = rollback_components;
                        *observed_tun_exclusion.write().await =
                            active_components.tun_candidate_exclusion();
                        active_api_listener = restored_api_listener;
                        refresh_runtime_health(
                            &active_components,
                            active_api_listener.as_ref(),
                            &network_status,
                        )
                        .await;
                        let _ = finish_reload_status(&network_status, done, Err(err)).await;
                        continue;
                    }

                    let mut g = global_state.lock().await;
                    #[cfg(feature = "tun")]
                    {
                        g.tunnel_runner = new_components.tun_runner.clone();
                    }
                    g.dns_listener = new_components.dns_listener.clone();

                    *observed_tun_exclusion.write().await =
                        new_components.tun_candidate_exclusion();
                    active_components = new_components;
                    active_api_listener = new_api_listener;
                    active_controller_cfg = candidate_controller_cfg;
                    network_observer = app::network::NetworkObserver::default();
                    refresh_runtime_health(
                        &active_components,
                        active_api_listener.as_ref(),
                        &network_status,
                    )
                    .await;

                    if finish_reload_status(&network_status, done, Ok(())).await.is_err() {
                        warn!("config reload response channel dropped before completion");
                    }
                }
                Some(proof) = traffic_rx.recv() => {
                    network_status.write().await.record_traffic(proof);
                }
                _ = health_interval.tick() => {
                    refresh_runtime_health(
                        &active_components,
                        active_api_listener.as_ref(),
                        &network_status,
                    ).await;
                }
                changed = network_samples.changed(), if sampler_running => {
                    if changed.is_err() {
                        warn!("network sampler stopped; automatic recovery is unavailable");
                        sampler_running = false;
                        network_status.write().await.observation_failed("network sampler stopped");
                        continue;
                    }
                    let sample = network_samples.borrow_and_update().clone();
                    if let Some(sample) = sample {
                        match sample.result.clone() {
                            Ok(snapshot) => {
                                network_status.write().await.observed_sample(&sample);
                                active_components.apply_network_observation(
                                    &mut network_observer,
                                    &network_status,
                                    snapshot,
                                    &mut network_samples,
                                ).await;
                            }
                            Err(error) => {
                                let mut status = network_status.write().await;
                                status.observation_failed_sample(&sample);
                                debug!(error, sample_sequence = sample.sequence, "network observation failed");
                            }
                        }
                    }
                }
            }
            }
        })
        .await;

        active_api_listener.shutdown();
        if let Err(err) = active_api_listener.join().await {
            warn!("failed waiting for API listener shutdown: {}", err);
        }
        active_components.stop_all_and_join(true).await;
        if control_result.is_ok() {
            let mut status = network_status.write().await;
            status.stop_components();
            status.lifecycle(
                app::runtime_state::Lifecycle::Stopped,
                "resourcesReleased",
            );
        } else {
            network_status.write().await.set_component(
                app::runtime_state::RuntimeComponent::Control,
                app::runtime_state::RuntimeComponentPhase::Failed,
                Some("runtime control task exited unexpectedly".to_owned()),
            );
        }
        control_result
    });

    let exit = wait_for_control_or_shutdown(
        &mut reload_handle,
        &shutdown_token,
        wait_for_shutdown_signal(),
    )
    .await;

    let result = match exit {
        RuntimeExit::Control(joined) => {
            if shutdown_token.is_cancelled() {
                joined
                    .map_err(|err| {
                        Error::Operation(format!(
                            "runtime reload task join error: {err}"
                        ))
                    })
                    .and_then(|result| result)
            } else {
                shutdown_token.cancel();
                let error = match joined {
                    Ok(Ok(())) => Error::Operation(
                        "runtime control task exited unexpectedly".to_owned(),
                    ),
                    Ok(Err(error)) => error,
                    Err(err) => Error::Operation(format!(
                        "runtime control task terminated unexpectedly: {err}"
                    )),
                };
                final_status.write().await.set_component(
                    app::runtime_state::RuntimeComponent::Control,
                    app::runtime_state::RuntimeComponentPhase::Failed,
                    Some("runtime control task exited unexpectedly".to_owned()),
                );
                Err(error)
            }
        }
        RuntimeExit::Signal(signal_result) => {
            shutdown_token.cancel();
            let joined = reload_handle
                .await
                .map_err(|err| {
                    Error::Operation(format!(
                        "runtime reload task join error: {err}"
                    ))
                })
                .and_then(|result| result);
            match signal_result {
                Ok(()) => joined,
                Err(error) => Err(Error::Io(error)),
            }
        }
        RuntimeExit::Cancelled => {
            shutdown_token.cancel();
            reload_handle
                .await
                .map_err(|err| {
                    Error::Operation(format!(
                        "runtime reload task join error: {err}"
                    ))
                })
                .and_then(|result| result)
        }
    };
    if let Some(network_sampler) = network_sampler
        && let Err(error) = network_sampler.await
    {
        warn!("network sampler task exited with error: {error}");
    }
    if result.is_err() {
        let mut status = final_status.write().await;
        status.set_component(
            app::runtime_state::RuntimeComponent::Control,
            app::runtime_state::RuntimeComponentPhase::Failed,
            Some("runtime control task or shutdown failed".to_owned()),
        );
        status.lifecycle(app::runtime_state::Lifecycle::Failed, "controlTaskFailed");
    }
    result?;

    Ok(())
}

pub(super) static SHUTDOWN_TOKEN: std::sync::Mutex<
    Vec<tokio_util::sync::CancellationToken>,
> = std::sync::Mutex::new(Vec::new());

pub(super) struct ShutdownTokenRegistration {
    token: tokio_util::sync::CancellationToken,
}

impl ShutdownTokenRegistration {
    pub(super) fn register(token: tokio_util::sync::CancellationToken) -> Self {
        SHUTDOWN_TOKEN.lock().unwrap().push(token.clone());
        Self { token }
    }
}

impl Drop for ShutdownTokenRegistration {
    fn drop(&mut self) {
        self.token.cancel();
        SHUTDOWN_TOKEN
            .lock()
            .unwrap()
            .retain(|token| !token.is_cancelled());
    }
}

pub fn shutdown() -> bool {
    let mut token_guard = SHUTDOWN_TOKEN.lock().unwrap();
    if !token_guard.is_empty() {
        for token in token_guard.drain(..) {
            token.cancel();
        }
        warn!("Shutdown signal sent, waiting for shutdown to complete...");
        true
    } else {
        warn!("Shutdown token not initialized, cannot shutdown");
        false
    }
}
