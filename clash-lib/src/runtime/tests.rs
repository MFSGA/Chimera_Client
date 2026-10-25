use std::sync::Once;

static INIT: Once = Once::new();

pub fn initialize() {
    INIT.call_once(crate::setup_default_crypto_provider);
}

#[tokio::test]
async fn control_task_completion_is_observed_without_a_shutdown_signal() {
    let token = tokio_util::sync::CancellationToken::new();
    let mut control = tokio::spawn(async { 7_u8 });
    let exit = super::wait_for_control_or_shutdown(
        &mut control,
        &token,
        std::future::pending(),
    )
    .await;

    assert!(matches!(exit, super::RuntimeExit::Control(Ok(7))));
    assert!(!token.is_cancelled());
}

#[tokio::test]
async fn panic_in_control_loop_becomes_a_cleanup_error() {
    let result = super::catch_control_panic(async {
        std::panic::panic_any("injected control task failure");
        #[allow(unreachable_code)]
        Ok(())
    })
    .await;

    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("control task panicked")
    );
}

#[tokio::test]
async fn cancellation_interrupts_control_task_supervision() {
    let token = tokio_util::sync::CancellationToken::new();
    let mut control = tokio::spawn(std::future::pending::<()>());
    token.cancel();
    let exit = super::wait_for_control_or_shutdown(
        &mut control,
        &token,
        std::future::pending(),
    )
    .await;

    assert!(matches!(exit, super::RuntimeExit::Cancelled));
    control.abort();
    let _ = control.await;
}

#[tokio::test]
async fn recovery_restarts_on_the_latest_network_sample_before_reporting_success() {
    use super::NetworkRecoveryRequest;
    use super::recover_to_latest_environment;
    use crate::app::{
        network::{NetworkPath, NetworkSample, NetworkSnapshot},
        runtime_state::{ComponentResult, Lifecycle, RecoveryCause, RecoveryReport},
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::sync::{Notify, watch};

    let path = |interface: &str, address: &str| NetworkSnapshot {
        ipv4: Some(NetworkPath {
            interface: interface.into(),
            index: if interface == "en0" { 1 } else { 2 },
            gateway: "192.0.2.1".into(),
            addresses: vec![address.into()],
        }),
        ..Default::default()
    };
    let old = path("en0", "192.0.2.2");
    let in_flight = path("en1", "192.0.2.3");
    let newest = path("en1", "192.0.2.4");
    let mut observer = crate::app::network::NetworkObserver::default();
    observer.applied(old);
    let mut state = crate::app::network::NetworkStatus::default();
    state.lifecycle(Lifecycle::Running, "testReady");
    let status = Arc::new(tokio::sync::RwLock::new(state));
    let (sample_tx, mut samples) = watch::channel(None);
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let recover = {
        let entered = entered.clone();
        let release = release.clone();
        let calls = calls.clone();
        move |_snapshot: Option<NetworkSnapshot>, _path_changed: bool| {
            let attempt = calls.fetch_add(1, Ordering::Relaxed);
            let entered = entered.clone();
            let release = release.clone();
            async move {
                if attempt == 0 {
                    entered.notify_one();
                    release.notified().await;
                }
                RecoveryReport {
                    interface: ComponentResult::refreshed(0),
                    dns: ComponentResult::refreshed(1),
                    pools: ComponentResult::refreshed(1),
                    observation_error: None,
                    offline: false,
                }
            }
        }
    };
    let worker_status = status.clone();
    let worker = tokio::spawn(async move {
        recover_to_latest_environment(
            &mut observer,
            &worker_status,
            NetworkRecoveryRequest {
                snapshot: Some(in_flight),
                path_changed: true,
                cause: RecoveryCause::NetworkChanged,
                observation_error: None,
            },
            Some(&mut samples),
            recover,
        )
        .await
    });

    tokio::time::timeout(std::time::Duration::from_secs(2), entered.notified())
        .await
        .expect("first recovery attempt did not start");
    sample_tx.send_replace(Some(NetworkSample {
        sequence: 7,
        sampled_at: tokio::time::Instant::now(),
        result: Ok(newest),
    }));
    release.notify_one();

    worker.await.unwrap().unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    let state = status.read().await;
    assert_eq!(
        state.phase(),
        crate::app::runtime_state::NetworkPhase::AwaitingTraffic
    );
    let json = serde_json::to_value(&*state).unwrap();
    assert_eq!(json["networkVersion"], 2);
    assert_eq!(json["lastSampleSequence"], 7);
    assert_eq!(json["operationHistory"][0]["outcome"], "superseded");
    assert_eq!(json["lastOperation"]["token"]["networkVersion"], 2);
}

#[tokio::test]
async fn repeated_network_changes_during_recovery_fail_with_a_bounded_retry() {
    use super::NetworkRecoveryRequest;
    use super::recover_to_latest_environment;
    use crate::app::{
        network::{NetworkPath, NetworkSample, NetworkSnapshot},
        runtime_state::{ComponentResult, Lifecycle, RecoveryCause, RecoveryReport},
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::sync::watch;

    let path = |interface: &str, index: u32, address: &str| NetworkSnapshot {
        ipv4: Some(NetworkPath {
            interface: interface.into(),
            index,
            gateway: "192.0.2.1".into(),
            addresses: vec![address.into()],
        }),
        ..Default::default()
    };
    let mut observer = crate::app::network::NetworkObserver::default();
    observer.applied(path("en0", 1, "192.0.2.2"));
    let mut state = crate::app::network::NetworkStatus::default();
    state.lifecycle(Lifecycle::Running, "testReady");
    let status = Arc::new(tokio::sync::RwLock::new(state));
    let (sample_tx, mut samples) = watch::channel(None);
    let attempts = Arc::new(AtomicUsize::new(0));
    let recover = {
        let attempts = attempts.clone();
        move |_snapshot: Option<NetworkSnapshot>, _path_changed: bool| {
            let attempt = attempts.fetch_add(1, Ordering::Relaxed);
            let tx = sample_tx.clone();
            async move {
                let next = if attempt == 0 {
                    path("en1", 2, "192.0.2.3")
                } else {
                    path("en2", 3, "192.0.2.4")
                };
                tx.send_replace(Some(NetworkSample {
                    sequence: attempt as u64 + 1,
                    sampled_at: tokio::time::Instant::now(),
                    result: Ok(next),
                }));
                RecoveryReport {
                    interface: ComponentResult::refreshed(0),
                    dns: ComponentResult::refreshed(1),
                    pools: ComponentResult::refreshed(1),
                    observation_error: None,
                    offline: false,
                }
            }
        }
    };
    let error = recover_to_latest_environment(
        &mut observer,
        &status,
        NetworkRecoveryRequest {
            snapshot: Some(path("en1", 4, "192.0.2.5")),
            path_changed: true,
            cause: RecoveryCause::NetworkChanged,
            observation_error: None,
        },
        Some(&mut samples),
        recover,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("changed repeatedly"));
    assert_eq!(attempts.load(Ordering::Relaxed), 2);
    let state = status.read().await;
    assert_eq!(
        state.phase(),
        crate::app::runtime_state::NetworkPhase::Degraded
    );
    let json = serde_json::to_value(&*state).unwrap();
    assert!(
        json["lastError"]
            .as_str()
            .unwrap()
            .contains("changed repeatedly")
    );
}

#[tokio::test]
async fn unchanged_snapshot_does_not_clear_failed_manual_recovery() {
    initialize();
    let cwd = tempfile::tempdir().unwrap();
    let config = crate::Config::Str(
        "mode: direct\nmmdb: null\ntun:\n  enable: false\n".into(),
    )
    .try_parse()
    .unwrap();
    let mut components =
        super::create_components(cwd.path().to_path_buf(), config, false)
            .await
            .unwrap();
    let mut dns = crate::app::dns::MockClashResolver::new();
    dns.expect_reset_transports()
        .returning(|| Err(anyhow::anyhow!("injected DNS recovery failure")));
    components.dns_resolver = std::sync::Arc::new(dns);
    let snapshot = crate::app::network::NetworkSnapshot {
        ipv4: Some(crate::app::network::NetworkPath {
            interface: "test".into(),
            index: 1,
            gateway: "192.0.2.1".into(),
            addresses: vec!["192.0.2.2".into()],
        }),
        ..Default::default()
    };
    let mut observer = crate::app::network::NetworkObserver::default();
    observer.applied(snapshot.clone());
    let mut status = crate::app::network::NetworkStatus::default();
    status.lifecycle(crate::app::runtime_state::Lifecycle::Running, "testReady");
    let status = tokio::sync::RwLock::new(status);
    let error = components
        .perform_network_recovery(
            &mut observer,
            &status,
            super::NetworkRecoveryRequest {
                snapshot: Some(snapshot.clone()),
                path_changed: true,
                cause: crate::app::runtime_state::RecoveryCause::ManualReset,
                observation_error: None,
            },
            None,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("injected DNS recovery failure"));
    let (_samples_tx, mut samples) = tokio::sync::watch::channel(None);
    components
        .apply_network_observation(&mut observer, &status, snapshot, &mut samples)
        .await;
    assert_eq!(
        status.read().await.phase(),
        crate::app::runtime_state::NetworkPhase::Degraded
    );
    assert!(
        serde_json::to_value(&*status.read().await).unwrap()["lastError"]
            .as_str()
            .unwrap()
            .contains("injected DNS recovery failure")
    );
}

#[tokio::test]
async fn automatic_network_observations_recover_and_deduplicate_without_reset_api() {
    initialize();
    let cwd = tempfile::tempdir().unwrap();
    let config = crate::Config::Str(
        "mode: direct\nmmdb: null\ntun:\n  enable: false\n".into(),
    )
    .try_parse()
    .unwrap();
    let mut components =
        super::create_components(cwd.path().to_path_buf(), config, false)
            .await
            .unwrap();
    let resets = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut dns = crate::app::dns::MockClashResolver::new();
    let count = resets.clone();
    dns.expect_reset_transports().returning(move || {
        count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(1)
    });
    components.dns_resolver = std::sync::Arc::new(dns);
    let mut observer = crate::app::network::NetworkObserver::default();
    let mut state = crate::app::network::NetworkStatus::default();
    state.lifecycle(crate::app::runtime_state::Lifecycle::Running, "testReady");
    let status = tokio::sync::RwLock::new(state);
    let (_samples_tx, mut samples) = tokio::sync::watch::channel(None);
    for round in 0..20 {
        let snapshot = crate::app::network::NetworkSnapshot {
            ipv4: Some(crate::app::network::NetworkPath {
                interface: format!("test{}", round % 2),
                index: round + 1,
                gateway: "192.0.2.1".into(),
                addresses: vec![format!("192.0.2.{}", round + 2)],
            }),
            ..Default::default()
        };
        components
            .apply_network_observation(
                &mut observer,
                &status,
                snapshot.clone(),
                &mut samples,
            )
            .await;
        {
            let mut status = status.write().await;
            status.observation_failed("temporary snapshot read failure");
        }
        components
            .apply_network_observation(
                &mut observer,
                &status,
                snapshot,
                &mut samples,
            )
            .await;
        assert_eq!(
            resets.load(std::sync::atomic::Ordering::Relaxed),
            round as usize + 1
        );
        assert_eq!(
            status.read().await.phase(),
            crate::app::runtime_state::NetworkPhase::AwaitingTraffic
        );
    }
    components
        .apply_network_observation(
            &mut observer,
            &status,
            Default::default(),
            &mut samples,
        )
        .await;
    assert_eq!(
        status.read().await.phase(),
        crate::app::runtime_state::NetworkPhase::WaitingForNetwork
    );
    assert!(
        !serde_json::to_value(&*status.read().await).unwrap()["lastError"].is_null()
    );
    let online = crate::app::network::NetworkSnapshot {
        ipv6: Some(crate::app::network::NetworkPath {
            interface: "test-v6".into(),
            index: 42,
            gateway: "fe80::1".into(),
            addresses: vec!["2001:db8::2".into()],
        }),
        ..Default::default()
    };
    components
        .apply_network_observation(&mut observer, &status, online, &mut samples)
        .await;
    assert_eq!(
        status.read().await.phase(),
        crate::app::runtime_state::NetworkPhase::AwaitingTraffic
    );
    assert_eq!(
        serde_json::to_value(&*status.read().await).unwrap()["failures"],
        0
    );
    assert_eq!(resets.load(std::sync::atomic::Ordering::Relaxed), 22);
}

#[test]
#[serial_test::serial]
fn shutdown_registration_is_pruned_when_runtime_exits() {
    super::SHUTDOWN_TOKEN.lock().unwrap().clear();
    let token = tokio_util::sync::CancellationToken::new();
    let registration = super::ShutdownTokenRegistration::register(token.clone());

    assert_eq!(super::SHUTDOWN_TOKEN.lock().unwrap().len(), 1);
    drop(registration);

    assert!(token.is_cancelled());
    assert!(super::SHUTDOWN_TOKEN.lock().unwrap().is_empty());
    assert!(!crate::shutdown());
}

#[cfg(feature = "tun")]
#[test]
fn network_runtime_lease_rejects_concurrent_owner() {
    let first = super::NetworkRuntimeLease::acquire(true)
        .expect("the test should acquire the first network lease");
    let second = match super::NetworkRuntimeLease::acquire(true) {
        Ok(_) => {
            panic!("a second runtime must not overwrite global network state")
        }
        Err(err) => err,
    };
    assert!(
        second
            .to_string()
            .contains("process-global network configuration")
    );
    drop(first);
    super::NetworkRuntimeLease::acquire(true)
        .expect("the lease should be reusable after the owner exits");

    let first_neutral = super::NetworkRuntimeLease::acquire(false)
        .expect("a runtime without network state should be shareable");
    let second_neutral = super::NetworkRuntimeLease::acquire(false)
        .expect("neutral runtimes should be shareable");
    assert!(super::NetworkRuntimeLease::acquire(true).is_err());
    drop(second_neutral);
    drop(first_neutral);
}
