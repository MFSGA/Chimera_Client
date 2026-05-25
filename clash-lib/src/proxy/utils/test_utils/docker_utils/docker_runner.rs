#![allow(dead_code)]

use std::{
    collections::HashMap,
    future::Future,
    net::SocketAddr,
    sync::atomic::{AtomicU16, Ordering},
};

use bollard::{
    API_DEFAULT_VERSION, Docker,
    config::ContainerInspectResponse,
    models::{ContainerCreateBody, HostConfig, Mount, MountTypeEnum, PortBinding},
    query_parameters::{
        CreateContainerOptions, CreateImageOptionsBuilder, RemoveContainerOptions,
        StartContainerOptions,
    },
};
use futures::TryStreamExt;
use tokio::net::TcpStream;

const FIRST_DOCKER_TEST_PORT: u16 = 30001;
const PORT: u16 = 10002;
const EXPOSED_PORTS: &[&str] = &["10002/tcp", "10002/udp"];
const TIMEOUT_DURATION: u64 = 120;

static PORT_COUNTER: AtomicU16 = AtomicU16::new(FIRST_DOCKER_TEST_PORT);

pub struct DockerTestRunner {
    instance: Docker,
    id: String,
    inspect: ContainerInspectResponse,
}

impl DockerTestRunner {
    pub async fn try_new(body: ContainerCreateBody) -> anyhow::Result<Self> {
        let docker = connect_docker()?;

        if let Some(image) = body.image.as_deref() {
            docker
                .create_image(
                    Some(CreateImageOptionsBuilder::new().from_image(image).build()),
                    None,
                    None,
                )
                .try_collect::<Vec<_>>()
                .await?;
        }

        let container = docker
            .create_container(Some(CreateContainerOptions::default()), body)
            .await?;
        let id = container.id;

        if let Err(err) = docker
            .start_container(&id, Some(StartContainerOptions::default()))
            .await
        {
            let _ = docker
                .remove_container(
                    &id,
                    Some(RemoveContainerOptions {
                        force: true,
                        ..Default::default()
                    }),
                )
                .await;
            return Err(err.into());
        }

        let inspect = docker.inspect_container(&id, None).await?;
        Ok(Self {
            instance: docker,
            id,
            inspect,
        })
    }

    pub fn container_ip(&self) -> Option<String> {
        self.inspect
            .network_settings
            .as_ref()
            .and_then(|settings| settings.networks.as_ref())
            .and_then(|networks| {
                networks
                    .values()
                    .find_map(|network| network.ip_address.clone())
                    .filter(|ip| !ip.is_empty())
            })
    }

    pub fn gateway_ip(&self) -> Option<String> {
        self.inspect
            .network_settings
            .as_ref()
            .and_then(|settings| settings.networks.as_ref())
            .and_then(|networks| {
                networks
                    .values()
                    .find_map(|network| network.gateway.clone())
                    .filter(|ip| !ip.is_empty())
            })
    }

    pub async fn wait_host_tcp_ready(
        host: &str,
        port: u16,
        timeout: std::time::Duration,
    ) -> anyhow::Result<()> {
        let addr: SocketAddr = format!("{host}:{port}").parse()?;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match TcpStream::connect(addr).await {
                Ok(stream) => {
                    drop(stream);
                    return Ok(());
                }
                Err(err) => {
                    if tokio::time::Instant::now() >= deadline {
                        anyhow::bail!(
                            "host service {} was not ready in {:?}: {}",
                            addr,
                            timeout,
                            err
                        );
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    #[cfg(all(docker_test, throughput_test))]
    pub async fn apply_netem(
        &self,
        delay_ms: u32,
        loss_pct: f32,
    ) -> anyhow::Result<()> {
        use super::consts::IMAGE_NETEM;
        use bollard::query_parameters::WaitContainerOptionsBuilder;
        use futures::StreamExt as _;

        let tc_cmd = format!(
            "tc qdisc add dev eth0 root netem delay {}ms loss {}%",
            delay_ms, loss_pct
        );
        let network_mode = format!("container:{}", self.id);

        let body = ContainerCreateBody {
            image: Some(IMAGE_NETEM.to_owned()),
            cmd: Some(vec!["sh".to_owned(), "-c".to_owned(), tc_cmd]),
            host_config: Some(HostConfig {
                network_mode: Some(network_mode),
                cap_add: Some(vec!["NET_ADMIN".to_owned()]),
                auto_remove: Some(false),
                ..Default::default()
            }),
            ..Default::default()
        };

        let sidecar = self
            .instance
            .create_container(Some(CreateContainerOptions::default()), body)
            .await?;

        self.instance
            .start_container(
                &sidecar.id,
                None::<bollard::query_parameters::StartContainerOptions>,
            )
            .await?;

        let mut wait_stream = self.instance.wait_container(
            &sidecar.id,
            Some(
                WaitContainerOptionsBuilder::new()
                    .condition("not-running")
                    .build(),
            ),
        );
        while let Some(result) = wait_stream.next().await {
            match result {
                Ok(status) => {
                    if status.status_code != 0 {
                        self.instance
                            .remove_container(
                                &sidecar.id,
                                Some(RemoveContainerOptions {
                                    force: true,
                                    ..Default::default()
                                }),
                            )
                            .await
                            .ok();
                        anyhow::bail!(
                            "netem sidecar exited with code {}: {:?}",
                            status.status_code,
                            status.error
                        );
                    }
                }
                Err(err) => return Err(err.into()),
            }
        }

        self.instance
            .remove_container(
                &sidecar.id,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await
            .ok();

        Ok(())
    }

    pub async fn cleanup(self) -> anyhow::Result<()> {
        self.instance
            .remove_container(
                &self.id,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await?;
        Ok(())
    }
}

#[derive(Default)]
pub struct MultiDockerTestRunner {
    runners: Vec<DockerTestRunner>,
}

impl MultiDockerTestRunner {
    pub async fn add(
        &mut self,
        creator: impl Future<Output = anyhow::Result<DockerTestRunner>>,
    ) -> anyhow::Result<()> {
        match creator.await {
            Ok(runner) => {
                self.runners.push(runner);
                Ok(())
            }
            Err(err) => {
                tracing::warn!(
                    "cannot start container, please check the docker environment, \
                     error: {:?}",
                    err
                );
                for runner in std::mem::take(&mut self.runners) {
                    let _ = runner.cleanup().await;
                }
                Err(err)
            }
        }
    }

    pub fn add_with_runner(&mut self, runner: DockerTestRunner) {
        self.runners.push(runner);
    }
}

#[async_trait::async_trait]
pub trait RunAndCleanup {
    fn docker_gateway_ip(&self) -> Option<String>;

    async fn run_and_cleanup(
        self,
        f: impl Future<Output = anyhow::Result<()>> + Send + 'static,
    ) -> anyhow::Result<()>;
}

#[async_trait::async_trait]
impl RunAndCleanup for DockerTestRunner {
    fn docker_gateway_ip(&self) -> Option<String> {
        self.gateway_ip()
    }

    async fn run_and_cleanup(
        self,
        f: impl Future<Output = anyhow::Result<()>> + Send + 'static,
    ) -> anyhow::Result<()> {
        let result = run_with_timeout(f).await;
        self.cleanup().await?;
        result
    }
}

#[async_trait::async_trait]
impl RunAndCleanup for MultiDockerTestRunner {
    fn docker_gateway_ip(&self) -> Option<String> {
        self.runners.iter().find_map(DockerTestRunner::gateway_ip)
    }

    async fn run_and_cleanup(
        self,
        f: impl Future<Output = anyhow::Result<()>> + Send + 'static,
    ) -> anyhow::Result<()> {
        let result = run_with_timeout(f).await;
        for runner in self.runners {
            runner.cleanup().await?;
        }
        result
    }
}

async fn run_with_timeout(
    f: impl Future<Output = anyhow::Result<()>> + Send + 'static,
) -> anyhow::Result<()> {
    tokio::select! {
        result = f => result,
        _ = tokio::time::sleep(std::time::Duration::from_secs(TIMEOUT_DURATION)) => {
            tracing::warn!("docker test runner timed out");
            Err(anyhow::anyhow!("timeout"))
        }
    }
}

#[derive(Debug)]
pub struct DockerTestRunnerBuilder {
    image: String,
    host_config: HostConfig,
    exposed_ports: Vec<String>,
    cmd: Option<Vec<String>>,
    env: Option<Vec<String>>,
}

impl Default for DockerTestRunnerBuilder {
    fn default() -> Self {
        Self {
            image: "hello-world".to_owned(),
            host_config: get_host_config(PORT),
            exposed_ports: EXPOSED_PORTS
                .iter()
                .map(|port| (*port).to_owned())
                .collect(),
            cmd: None,
            env: None,
        }
    }
}

impl DockerTestRunnerBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn image(mut self, image: &str) -> Self {
        self.image = image.to_owned();
        self
    }

    pub fn env(mut self, env: &[&str]) -> Self {
        self.env = Some(env.iter().map(|value| (*value).to_owned()).collect());
        self
    }

    pub fn cmd(mut self, cmd: &[&str]) -> Self {
        self.cmd = Some(cmd.iter().map(|value| (*value).to_owned()).collect());
        self
    }

    pub fn host_port(mut self, host_port: u16, container_port: u16) -> Self {
        self.exposed_ports = vec![
            format!("{}/tcp", container_port),
            format!("{}/udp", container_port),
        ];
        self.host_config.port_bindings = Some(
            [
                (
                    format!("{}/tcp", container_port),
                    Some(vec![PortBinding {
                        host_ip: Some("0.0.0.0".to_owned()),
                        host_port: Some(host_port.to_string()),
                    }]),
                ),
                (
                    format!("{}/udp", container_port),
                    Some(vec![PortBinding {
                        host_ip: Some("0.0.0.0".to_owned()),
                        host_port: Some(host_port.to_string()),
                    }]),
                ),
            ]
            .into_iter()
            .collect(),
        );
        self
    }

    pub fn host_network(mut self) -> Self {
        self.exposed_ports = Vec::new();
        self.host_config.network_mode = Some("host".to_owned());
        self.host_config.port_bindings = None;
        self
    }

    #[allow(dead_code)]
    pub fn no_port(mut self) -> Self {
        self.exposed_ports = vec![];
        self.host_config.port_bindings = Some(HashMap::new());
        self
    }

    pub fn mounts(mut self, pairs: &[(&str, &str)]) -> Self {
        self.host_config.mounts = Some(
            pairs
                .iter()
                .map(|(source, target)| Mount {
                    target: Some((*target).to_owned()),
                    source: Some((*source).to_owned()),
                    typ: Some(MountTypeEnum::BIND),
                    read_only: Some(false),
                    ..Default::default()
                })
                .collect(),
        );
        self
    }

    pub async fn build(self) -> anyhow::Result<DockerTestRunner> {
        DockerTestRunner::try_new(ContainerCreateBody {
            image: Some(self.image),
            tty: Some(true),
            cmd: self.cmd,
            env: self.env,
            exposed_ports: Some(self.exposed_ports),
            host_config: Some(self.host_config),
            ..Default::default()
        })
        .await
    }
}

pub fn alloc_docker_port() -> u16 {
    PORT_COUNTER.fetch_add(1, Ordering::Relaxed)
}

pub fn get_host_config(port: u16) -> HostConfig {
    HostConfig {
        port_bindings: Some(
            [
                (
                    format!("{}/tcp", port),
                    Some(vec![PortBinding {
                        host_ip: Some("0.0.0.0".to_owned()),
                        host_port: Some(port.to_string()),
                    }]),
                ),
                (
                    format!("{}/udp", port),
                    Some(vec![PortBinding {
                        host_ip: Some("0.0.0.0".to_owned()),
                        host_port: Some(port.to_string()),
                    }]),
                ),
            ]
            .into_iter()
            .collect::<HashMap<_, _>>(),
        ),
        ..Default::default()
    }
}

fn connect_docker() -> anyhow::Result<Docker> {
    match std::env::var("DOCKER_HOST").ok() {
        Some(url)
            if url.starts_with("http://")
                || url.starts_with("https://")
                || url.starts_with("tcp://") =>
        {
            Ok(Docker::connect_with_http(&url, 60, API_DEFAULT_VERSION)?)
        }
        Some(url) if url.starts_with("unix://") || url.starts_with("npipe://") => {
            Ok(Docker::connect_with_socket(&url, 60, API_DEFAULT_VERSION)?)
        }
        Some(url) => anyhow::bail!("invalid DOCKER_HOST url: {}", url),
        None => Ok(Docker::connect_with_socket_defaults()?),
    }
}
