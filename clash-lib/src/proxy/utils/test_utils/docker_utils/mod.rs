#![allow(dead_code)]

pub mod config_helper;
pub mod consts;
pub mod docker_runner;

use std::sync::Arc;

use crate::proxy::OutboundHandler;

#[allow(unused_imports)]
pub use docker_runner::{RunAndCleanup, alloc_docker_port};

#[derive(Clone, Copy)]
pub enum Suite {
    PingPongTcp,
    PingPongUdp,
    LatencyTcp,
    DnsUdp,
}

impl Suite {
    pub const fn all() -> &'static [Suite] {
        &[
            Suite::PingPongTcp,
            Suite::PingPongUdp,
            Suite::LatencyTcp,
            Suite::DnsUdp,
        ]
    }

    pub const fn tcp_tests() -> &'static [Suite] {
        &[Suite::PingPongTcp, Suite::LatencyTcp]
    }
}

pub async fn run_test_suites_and_cleanup(
    _handler: Arc<dyn OutboundHandler>,
    docker_test_runner: impl RunAndCleanup,
    _suites: &[Suite],
) -> anyhow::Result<()> {
    docker_test_runner
        .run_and_cleanup(async {
            Err(anyhow::anyhow!(
                "docker test suite execution is not migrated yet"
            ))
        })
        .await
}
