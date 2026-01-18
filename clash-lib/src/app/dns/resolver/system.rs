use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::atomic::{AtomicBool, Ordering},
};

use tracing::debug;

use async_trait::async_trait;
use hickory_proto::op::Message;

use crate::app::dns::{ClashResolver, ResolverKind};

pub struct SystemResolver {
    ipv6: AtomicBool,
}

/// SystemResolver is a resolver that uses libc getaddrinfo to resolve
/// hostnames.
impl SystemResolver {
    pub fn new(ipv6: bool) -> anyhow::Result<Self> {
        debug!("creating system resolver with ipv6={}", ipv6);
        Ok(Self {
            ipv6: AtomicBool::new(ipv6),
        })
    }
}

#[async_trait]
impl ClashResolver for SystemResolver {
    async fn exchange(
        &self,
        _: &hickory_proto::op::Message,
    ) -> anyhow::Result<hickory_proto::op::Message> {
        Err(anyhow::anyhow!(
            "system resolver does not support advanced dns features, please enable \
             the dns server in your config"
        ))
    }

    fn ipv6(&self) -> bool {
        self.ipv6.load(std::sync::atomic::Ordering::Relaxed)
    }
}
