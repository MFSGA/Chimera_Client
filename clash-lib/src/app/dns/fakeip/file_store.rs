use async_trait::async_trait;

use crate::app::profile::ThreadSafeCacheFile;

use super::{IpFamily, Store};

pub struct FileStore(ThreadSafeCacheFile);

impl FileStore {
    pub fn new(store: ThreadSafeCacheFile) -> Self {
        Self(store)
    }

    fn host_key(host: &str, family: IpFamily) -> String {
        match family {
            IpFamily::V4 => host.to_owned(),
            // ':' cannot occur in a DNS hostname, so this namespace cannot
            // collide with an IPv4 fake-IP mapping from older cache files.
            IpFamily::V6 => format!("::chimera-fake-ip-v6::{host}"),
        }
    }
}

#[async_trait]
impl Store for FileStore {
    async fn get_by_host(
        &mut self,
        host: &str,
        family: IpFamily,
    ) -> Option<std::net::IpAddr> {
        self.0
            .get_fake_ip(&Self::host_key(host, family))
            .await
            .and_then(|ip| ip.parse().ok())
    }

    async fn pub_by_host(
        &mut self,
        host: &str,
        family: IpFamily,
        ip: std::net::IpAddr,
    ) {
        self.0
            .set_host_to_ip(&Self::host_key(host, family), &ip.to_string())
            .await;
    }

    async fn get_by_ip(&mut self, ip: std::net::IpAddr) -> Option<String> {
        self.0.get_fake_ip(&ip.to_string()).await
    }

    async fn put_by_ip(&mut self, ip: std::net::IpAddr, host: &str) {
        self.0.set_ip_to_host(&ip.to_string(), host).await;
    }

    async fn del_by_host(&mut self, host: &str, family: IpFamily) {
        self.0
            .delete_fake_ip_by_host_family(host, family == IpFamily::V6)
            .await;
    }

    async fn exist(&mut self, ip: std::net::IpAddr) -> bool {
        self.0.get_fake_ip(&ip.to_string()).await.is_some()
    }

    async fn copy_to(&self, #[allow(unused)] store: &mut Box<dyn Store>) {
        // NO-OP
    }
}
