#![allow(dead_code)]

use std::{
    future::Future,
    sync::atomic::{AtomicU16, Ordering},
};

const FIRST_DOCKER_TEST_PORT: u16 = 30001;

static PORT_COUNTER: AtomicU16 = AtomicU16::new(FIRST_DOCKER_TEST_PORT);

pub struct DockerTestRunner {
    image: String,
    gateway_ip: Option<String>,
    container_ip: Option<String>,
}

impl DockerTestRunner {
    pub fn container_ip(&self) -> Option<String> {
        self.container_ip.clone()
    }

    pub fn gateway_ip(&self) -> Option<String> {
        self.gateway_ip.clone()
    }

    pub fn image(&self) -> &str {
        &self.image
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
        self.runners.push(creator.await?);
        Ok(())
    }

    pub fn add_with_runner(&mut self, runner: DockerTestRunner) {
        self.runners.push(runner);
    }
}

pub trait RunAndCleanup {
    fn docker_gateway_ip(&self) -> Option<String>;
}

impl RunAndCleanup for DockerTestRunner {
    fn docker_gateway_ip(&self) -> Option<String> {
        self.gateway_ip()
    }
}

impl RunAndCleanup for MultiDockerTestRunner {
    fn docker_gateway_ip(&self) -> Option<String> {
        self.runners.iter().find_map(DockerTestRunner::gateway_ip)
    }
}

pub struct DockerTestRunnerBuilder {
    image: String,
    env: Vec<String>,
    cmd: Vec<String>,
    mounts: Vec<(String, String)>,
}

impl Default for DockerTestRunnerBuilder {
    fn default() -> Self {
        Self {
            image: String::new(),
            env: Vec::new(),
            cmd: Vec::new(),
            mounts: Vec::new(),
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
        self.env = env.iter().map(|value| (*value).to_owned()).collect();
        self
    }

    pub fn cmd(mut self, cmd: &[&str]) -> Self {
        self.cmd = cmd.iter().map(|value| (*value).to_owned()).collect();
        self
    }

    pub fn mounts(mut self, pairs: &[(&str, &str)]) -> Self {
        self.mounts = pairs
            .iter()
            .map(|(source, target)| ((*source).to_owned(), (*target).to_owned()))
            .collect();
        self
    }

    pub async fn build(self) -> anyhow::Result<DockerTestRunner> {
        let _ = (self.env, self.cmd, self.mounts);
        Err(anyhow::anyhow!(
            "docker runner container lifecycle is not migrated yet for image {}",
            self.image
        ))
    }
}

pub fn alloc_docker_port() -> u16 {
    PORT_COUNTER.fetch_add(1, Ordering::Relaxed)
}
