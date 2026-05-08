#![allow(dead_code)]

pub mod config_helper;
pub mod consts;
pub mod docker_runner;

use std::{sync::Arc, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, split},
    net::TcpListener,
};

use crate::{
    app::dispatcher::BoxedChainedStream,
    proxy::OutboundHandler,
    session::{Session, SocksAddr},
};

#[allow(unused_imports)]
pub use docker_runner::{RunAndCleanup, alloc_docker_port};

#[derive(Clone, Copy, Debug)]
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
    handler: Arc<dyn OutboundHandler>,
    docker_test_runner: impl RunAndCleanup,
    suites: &[Suite],
) -> anyhow::Result<()> {
    let gateway_ip = docker_test_runner.docker_gateway_ip();
    let suites = suites.to_vec();

    docker_test_runner
        .run_and_cleanup(async move {
            for suite in suites {
                match suite {
                    Suite::PingPongTcp => {
                        ping_pong_tcp_test(handler.clone(), gateway_ip.clone())
                            .await?;
                    }
                    Suite::PingPongUdp | Suite::LatencyTcp | Suite::DnsUdp => {
                        tracing::warn!(
                            "docker test suite is not migrated yet: {:?}",
                            suite
                        );
                    }
                }
            }
            Ok(())
        })
        .await
}

fn destination_list(gateway_ip: Option<String>) -> Vec<String> {
    let mut destinations = vec!["host.docker.internal".to_owned()];

    if let Some(ip) = gateway_ip {
        destinations.push(ip);
    }

    if let Ok(ip) = std::env::var("CLIENT_IP") {
        destinations.insert(0, ip);
    }

    destinations
}

async fn ping_pong_tcp_test(
    handler: Arc<dyn OutboundHandler>,
    gateway_ip: Option<String>,
) -> anyhow::Result<()> {
    let resolver = config_helper::build_dns_resolver().await?;
    let listener = TcpListener::bind("0.0.0.0:0").await?;
    let port = listener.local_addr()?.port();

    async fn serve_connection<T>(incoming: T) -> anyhow::Result<()>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut read_half, mut write_half) = split(incoming);
        let mut buf = [0u8; 5];

        for _ in 0..100 {
            read_half.read_exact(&mut buf).await?;
            anyhow::ensure!(&buf == b"hello", "unexpected tcp request payload");
        }

        for _ in 0..100 {
            write_half.write_all(b"world").await?;
            write_half.flush().await?;
        }

        Ok(())
    }

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, _) = accepted?;
                    if let Err(err) = serve_connection(stream).await {
                        tracing::warn!("tcp ping-pong target connection failed: {err:?}");
                    }
                }
                _ = &mut shutdown_rx => return Ok::<_, anyhow::Error>(()),
            }
        }
    });

    async fn proxy_roundtrip(stream: BoxedChainedStream) -> anyhow::Result<()> {
        let (mut read_half, mut write_half) = split(stream);
        let mut buf = [0u8; 5];

        for _ in 0..100 {
            write_half.write_all(b"hello").await?;
        }
        write_half.flush().await?;

        for _ in 0..100 {
            read_half.read_exact(&mut buf).await?;
            anyhow::ensure!(&buf == b"world", "unexpected tcp response payload");
        }

        Ok(())
    }

    let mut first_error = None;
    for destination in destination_list(gateway_ip) {
        let dst: SocksAddr = (destination.clone(), port).try_into()?;
        let sess = Session {
            destination: dst.clone(),
            ..Default::default()
        };

        let stream = match tokio::time::timeout(
            Duration::from_secs(5),
            handler.connect_stream(&sess, resolver.clone()),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => {
                tracing::warn!("tcp ping-pong connect failed for {dst:?}: {err:?}");
                first_error.get_or_insert_with(|| anyhow::Error::new(err));
                continue;
            }
            Err(_) => {
                tracing::warn!("tcp ping-pong connect timed out for {dst:?}");
                continue;
            }
        };

        match tokio::time::timeout(Duration::from_secs(5), proxy_roundtrip(stream))
            .await
        {
            Ok(Ok(())) => {
                let _ = shutdown_tx.send(());
                let _ = server_task.await?;
                return Ok(());
            }
            Ok(Err(err)) => {
                tracing::warn!(
                    "tcp ping-pong roundtrip failed for {dst:?}: {err:?}"
                );
                first_error.get_or_insert(err);
            }
            Err(_) => {
                tracing::warn!("tcp ping-pong roundtrip timed out for {dst:?}");
            }
        }
    }

    let _ = shutdown_tx.send(());
    let _ = server_task.await?;

    Err(first_error
        .unwrap_or_else(|| anyhow::anyhow!("all tcp ping-pong destinations failed")))
}
