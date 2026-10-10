//! Static invalid routes should be rejected during config loading. Runtime
//! changes can still remove an outbound after validation, so Dispatcher also
//! needs fail-closed handling (tested by its TCP/UDP unit tests).
use std::{net::TcpListener as StdTcpListener, path::PathBuf};

use clash_lib::{Config, Options};

mod common;
use common::ClashInstance;

#[test]
fn rule_referencing_missing_outbound_is_rejected_at_startup() {
    // Reserve both listener ports simultaneously to avoid reusing the same
    // ephemeral port during test setup.
    let reservations: [StdTcpListener; 2] = std::array::from_fn(|_| {
        StdTcpListener::bind("127.0.0.1:0")
            .expect("failed to reserve test listener port")
    });
    let [api_port, socks_port] =
        reservations.map(|socket| socket.local_addr().unwrap().port());
    let config = format!(
        r#"
allow-lan: false
bind-address: 127.0.0.1
socks-port: {socks_port}
mode: rule
log-level: error
mmdb: null
external-controller: 127.0.0.1:{api_port}
secret: test-secret
tun:
  enable: false
rules:
  - MATCH,REMOVED-PROXY
"#
    );
    let cwd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let result = ClashInstance::start(
        Options {
            config: Config::Str(config),
            cwd: Some(cwd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: None,
        },
        vec![api_port, socks_port],
    );
    match result {
        Ok(_) => panic!("configuration must not accept a nonexistent proxy"),
        Err(error) => assert!(
            error.to_string().contains("REMOVED-PROXY"),
            "error should identify the missing outbound: {error}"
        ),
    }
}
