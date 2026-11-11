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

#[cfg(all(target_os = "macos", feature = "tun"))]
#[tokio::test]
async fn protected_candidate_http_provider_must_not_fetch_before_commit() {
    // An uncommitted DNS policy must not make a provider HTTP request.
    // Using an IP-literal loopback server guarantees no OS DNS or real NIC
    // traffic is required even when this test fails in the red phase.
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    initialize();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback provider listener");
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_for_server = hits.clone();
    let provider_server = tokio::spawn(async move {
        if let Ok(Ok((mut conn, _))) = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            listener.accept(),
        )
        .await
        {
            hits_for_server.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0; 2048];
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                conn.read(&mut buf),
            )
            .await;
            let body = b"proxies: []\n";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = conn.write_all(response.as_bytes()).await;
            let _ = conn.write_all(body).await;
        }
    });

    let temp = tempfile::tempdir().unwrap();
    let config = crate::Config::Str(format!(
        r#"ipv6: false
mode: direct
mmdb: null
tun:
  enable: true
  dns-hijack: false
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  nameserver: ['udp://127.0.0.1:9']
  default-nameserver: ['udp://127.0.0.1:9']
proxy-providers:
  candidate:
    type: http
    url: http://127.0.0.1:{port}/candidate.yaml
    path: provider-cache.yaml
    interval: 3600
    health-check:
      enable: false
proxies: []
rules:
  - MATCH,DIRECT
"#
    ))
    .try_parse()
    .expect("protected candidate fixture must parse");

    // false means we are *preparing* a candidate for reload rather than
    // starting a live runtime; it must be side-effect-free.
    let result =
        super::create_components(temp.path().to_path_buf(), config, false).await;
    provider_server.abort();
    let _ = provider_server.await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "uncommitted candidate contacted its HTTP provider before publication"
    );
    let err = match result {
        Ok(_) => panic!("candidate HTTP bootstrap must be deferred or rejected"),
        Err(err) => err.to_string(),
    };
    assert!(
        err.contains("proxy-provider") && err.contains("before DNS publication"),
        "unexpected candidate provider failure: {err}"
    );
}

#[cfg(all(target_os = "macos", feature = "tun"))]
#[tokio::test]
async fn nonprotected_candidate_preserves_legacy_http_provider_bootstrap() {
    // Legacy non-TUN reloads must still fetch their HTTP provider normally.
    // This exercises only loopback HTTP, without a DNS lookup or TUN start.
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    initialize();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = hits.clone();
    let server = tokio::spawn(async move {
        if let Ok(Ok((mut conn, _))) = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            listener.accept(),
        )
        .await
        {
            seen.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0; 2048];
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                conn.read(&mut buf),
            )
            .await;
            let body = b"proxies: []\n";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = conn.write_all(response.as_bytes()).await;
            let _ = conn.write_all(body).await;
        }
    });
    let temp = tempfile::tempdir().unwrap();
    let config = crate::Config::Str(format!(
        r#"ipv6: false
mode: direct
mmdb: null
tun:
  enable: false
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  nameserver: ['udp://127.0.0.1:9']
  default-nameserver: ['udp://127.0.0.1:9']
proxy-providers:
  legacy:
    type: http
    url: http://127.0.0.1:{port}/legacy.yaml
    path: legacy-provider-cache.yaml
    interval: 3600
    health-check:
      enable: false
proxies: []
rules:
  - MATCH,DIRECT
"#
    ))
    .try_parse()
    .unwrap();
    let result =
        super::create_components(temp.path().to_path_buf(), config, false).await;
    server.abort();
    let _ = server.await;
    if let Err(err) = result {
        panic!("legacy candidate setup failed: {err}");
    }
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "nonprotected reload must preserve HTTP provider initialization"
    );
}

#[cfg(all(target_os = "macos", feature = "tun"))]
#[tokio::test]
async fn protected_candidate_http_rule_provider_must_not_start_before_commit() {
    // HTTP rule-provider initialization is spawned in Router::new, before the
    // reload coordinator can suspend the candidate DNS owner. Reject safely
    // before any asynchronous candidate fetch is scheduled.
    initialize();
    let temp = tempfile::tempdir().unwrap();
    let config = crate::Config::Str(
        r#"ipv6: false
mode: direct
mmdb: null
tun:
  enable: true
  dns-hijack: false
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  nameserver: ['udp://127.0.0.1:9']
  default-nameserver: ['udp://127.0.0.1:9']
rule-providers:
  candidate-rules:
    type: http
    url: http://127.0.0.1:9/candidate.rules
    path: candidate-rules.yaml
    interval: 3600
    behavior: domain
proxies: []
rules:
  - MATCH,DIRECT
"#
        .to_owned(),
    )
    .try_parse()
    .unwrap();
    let result =
        super::create_components(temp.path().to_path_buf(), config, false).await;
    let err = match result {
        Ok(_) => panic!("uncommitted protected HTTP rule provider was scheduled"),
        Err(err) => err.to_string(),
    };
    assert!(
        err.contains("rule-provider") && err.contains("before DNS publication"),
        "unexpected candidate rule provider failure: {err}"
    );
}

#[cfg(all(target_os = "macos", feature = "tun"))]
#[tokio::test]
async fn protected_candidate_missing_mmdb_must_not_download_before_commit() {
    // Candidate country MMDB downloads occur in create_components, before
    // the DNS owner can be paused. Observe via loopback-only HTTP; no public
    // host is used, even in the intentional red test.
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    initialize();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = hits.clone();
    let server = tokio::spawn(async move {
        if let Ok(Ok((mut conn, _))) = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            listener.accept(),
        )
        .await
        {
            seen.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0; 2048];
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                conn.read(&mut buf),
            )
            .await;
            let body = b"not an mmdb";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = conn.write_all(response.as_bytes()).await;
            let _ = conn.write_all(body).await;
        }
    });

    let temp = tempfile::tempdir().unwrap();
    let config = crate::Config::Str(format!(
        r#"ipv6: false
mode: direct
mmdb: missing.mmdb
mmdb-download-url: http://127.0.0.1:{port}/missing.mmdb
tun:
  enable: true
  dns-hijack: false
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  nameserver: ['udp://127.0.0.1:9']
  default-nameserver: ['udp://127.0.0.1:9']
proxies: []
rules:
  - MATCH,DIRECT
"#
    ))
    .try_parse()
    .unwrap();
    let result =
        super::create_components(temp.path().to_path_buf(), config, false).await;
    server.abort();
    let _ = server.await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "uncommitted candidate downloaded a country MMDB before DNS publication"
    );
    let err = match result {
        Ok(_) => panic!("protected candidate attempted missing country MMDB load"),
        Err(err) => err.to_string(),
    };
    assert!(
        err.contains("mmdb") && err.contains("before DNS publication"),
        "unexpected candidate MMDB error: {err}"
    );
}

#[cfg(all(target_os = "macos", feature = "tun"))]
fn protected_geo_candidate_config(extra: &str) -> crate::Config {
    crate::Config::Str(format!(
        r#"ipv6: false
mode: direct
{extra}
tun:
  enable: true
  dns-hijack: false
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  nameserver: ['udp://127.0.0.1:9']
  default-nameserver: ['udp://127.0.0.1:9']
proxies: []
rules:
  - MATCH,DIRECT
"#
    ))
}

#[cfg(all(target_os = "macos", feature = "tun"))]
#[tokio::test]
async fn protected_candidate_corrupt_mmdb_remains_intact_without_refetch() {
    initialize();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("corrupt.mmdb");
    let original = b"invalid mmdb; must not be deleted during candidate build";
    std::fs::write(&path, original).unwrap();
    let config = protected_geo_candidate_config(
        "mmdb: corrupt.mmdb\nmmdb-download-url: http://127.0.0.1:9/refetch.mmdb",
    )
    .try_parse()
    .unwrap();
    let outcome =
        super::create_components(temp.path().to_path_buf(), config, false).await;
    let error = match outcome {
        Ok(_) => panic!("corrupt MMDB must not be removed and refetched precommit"),
        Err(err) => err.to_string(),
    };
    assert!(
        error.contains("mmdb") && error.contains("before DNS publication"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(path).unwrap(),
        original,
        "preflight must not delete the user's local cached database"
    );
}

#[cfg(all(target_os = "macos", feature = "tun"))]
#[tokio::test]
async fn protected_candidate_geosite_download_requires_published_dns() {
    initialize();
    for existing_forced in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        if existing_forced {
            std::fs::write(temp.path().join("site.dat"), []).unwrap();
        }
        let extra = if existing_forced {
            "mmdb: null\ngeosite: site.dat\ngeosite-download-url: http://127.0.0.1:9/geo?force=true"
        } else {
            "mmdb: null\ngeosite: site.dat\ngeosite-download-url: http://127.0.0.1:9/geo"
        };
        let config = protected_geo_candidate_config(extra).try_parse().unwrap();
        let outcome =
            super::create_components(temp.path().to_path_buf(), config, false).await;
        let error = match outcome {
            Ok(_) => panic!("missing or forced geosite was initialized precommit"),
            Err(err) => err.to_string(),
        };
        assert!(
            error.contains("geosite") && error.contains("before DNS publication"),
            "geosite case {existing_forced}: {error}"
        );
    }
}

#[cfg(all(target_os = "macos", feature = "tun"))]
#[tokio::test]
async fn protected_candidate_asn_missing_or_forced_mmdb_rejected_before_download() {
    initialize();
    for (data, expected) in [
        (
            "mmdb: null\nasn-mmdb: missing-asn.mmdb\nasn-mmdb-download-url: http://127.0.0.1:9/asn",
            "asn-mmdb",
        ),
        (
            "mmdb: missing-country.mmdb\nmmdb-download-url: http://127.0.0.1:9/country?force=true",
            "mmdb",
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let config = protected_geo_candidate_config(data).try_parse().unwrap();
        let error =
            match super::create_components(temp.path().to_path_buf(), config, false)
                .await
            {
                Ok(_) => panic!("uncommitted geo-data candidate was not rejected"),
                Err(error) => error.to_string(),
            };
        assert!(
            error.contains(expected) && error.contains("before DNS publication"),
            "bad {expected} candidate failure: {error}"
        );
    }
}

#[cfg(all(target_os = "macos", feature = "tun"))]
#[tokio::test]
async fn protected_candidate_valid_cached_geosite_remains_supported() {
    initialize();
    let temp = tempfile::tempdir().unwrap();
    // A zero-length protobuf encodes an empty but valid GeoSiteList.
    std::fs::write(temp.path().join("cached.dat"), []).unwrap();
    let config = protected_geo_candidate_config(
        "mmdb: null\ngeosite: cached.dat\ngeosite-download-url: http://127.0.0.1:9/geo",
    )
    .try_parse()
    .unwrap();
    let outcome =
        super::create_components(temp.path().to_path_buf(), config, false).await;
    if let Err(error) = outcome {
        panic!(
            "cached local geosite must remain valid for protected reload: {error}"
        );
    }
}

#[cfg(all(target_os = "macos", feature = "tun"))]
#[tokio::test]
async fn protected_candidate_resolvers_are_staged_before_factory_returns() {
    // No candidate owner should be addressable in the gap between factory
    // completion and the coordinator's subsequent pause. IP literals ensure
    // this test does not perform any DNS packet or system network changes.
    initialize();
    let temp = tempfile::tempdir().unwrap();
    let config = protected_geo_candidate_config("mmdb: null")
        .try_parse()
        .unwrap();
    let components =
        super::create_components(temp.path().to_path_buf(), config, false)
            .await
            .unwrap();

    let query = "127.0.0.1";
    assert!(
        components.dns_resolver.resolve(query, false).await.is_err(),
        "factory exposed candidate primary DNS before publication"
    );
    assert!(
        components
            .control_plane_dns_resolver
            .resolve(query, false)
            .await
            .is_err(),
        "factory exposed candidate control-plane DNS before publication"
    );
    components.dns_resolver.publish();
    components.control_plane_dns_resolver.publish();
    assert_eq!(
        components.dns_resolver.resolve(query, false).await.unwrap(),
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
    );
    assert_eq!(
        components
            .control_plane_dns_resolver
            .resolve(query, false)
            .await
            .unwrap(),
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
    );
}

#[cfg(all(target_os = "macos", feature = "tun"))]
#[tokio::test]
async fn protected_candidate_file_provider_health_check_has_no_precommit_egress() {
    // File-backed proxies are local inputs, but an eager health probe can
    // issue outbound HTTP before the candidate DNS owner is committed.
    // Observe any probe using a loopback socket and a bounded join.
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    initialize();
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(
        temp.path().join("local-proxies.yaml"),
        "proxies:\n  - name: LOCAL_DIRECT\n    type: direct\n",
    )
    .unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let mut probe = tokio::spawn(async move {
        if let Ok(Ok((_conn, _))) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            listener.accept(),
        )
        .await
        {
            counter.fetch_add(1, Ordering::SeqCst);
        }
    });

    let config = protected_geo_candidate_config(&format!(
        r#"mmdb: null
proxy-providers:
  local:
    type: file
    path: local-proxies.yaml
    interval: 1
    health-check:
      enable: true
      lazy: false
      interval: 1
      url: http://127.0.0.1:{port}/health
"#
    ))
    .try_parse()
    .unwrap();
    let components =
        super::create_components(temp.path().to_path_buf(), config, false)
            .await
            .unwrap();
    assert!(
        components
            .outbound_manager
            .get_proxy_provider("local")
            .is_some(),
        "file-backed provider was unexpectedly discarded"
    );
    let precommit_probe =
        tokio::time::timeout(std::time::Duration::from_millis(350), &mut probe)
            .await;
    assert!(
        precommit_probe.is_err(),
        "candidate probe reached local HTTP listener before publication"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "candidate file-provider health check contacted an upstream before DNS publication"
    );
    // The post-commit hook must restore the initial probe that was blocked
    // while the candidate was unpublished.
    components.dns_resolver.publish();
    components.control_plane_dns_resolver.publish();
    components
        .outbound_manager
        .resume_provider_health_checks_after_commit();
    let resumed =
        tokio::time::timeout(std::time::Duration::from_secs(2), &mut probe).await;
    if resumed.is_err() {
        probe.abort();
        let _ = probe.await;
    }
    assert!(
        resumed.is_ok() && hits.load(Ordering::SeqCst) == 1,
        "committed candidate did not resume its provider health probe"
    );
}
