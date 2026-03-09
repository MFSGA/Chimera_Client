use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use async_trait::async_trait;

use super::Store;

pub struct InMemStore {
    capacity: usize,
    ip_to_host: HashMap<IpAddr, String>,
    host_to_ip: HashMap<String, IpAddr>,
    order: VecDeque<String>,
}

impl InMemStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            ip_to_host: HashMap::new(),
            host_to_ip: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn touch(&mut self, host: &str) {
        if let Some(index) = self.order.iter().position(|item| item == host) {
            self.order.remove(index);
        }
        self.order.push_back(host.to_string());
        self.evict_if_needed();
    }

    fn evict_if_needed(&mut self) {
        while self.host_to_ip.len() > self.capacity {
            let Some(host) = self.order.pop_front() else {
                break;
            };
            if let Some(ip) = self.host_to_ip.remove(&host) {
                self.ip_to_host.remove(&ip);
            }
        }
    }
}

#[async_trait]
impl Store for InMemStore {
    async fn get_by_host(&mut self, host: &str) -> Option<IpAddr> {
        let ip = self.host_to_ip.get(host).copied();
        if ip.is_some() {
            self.touch(host);
        }
        ip
    }

    async fn pub_by_host(&mut self, host: &str, ip: IpAddr) {
        self.host_to_ip.insert(host.to_string(), ip);
        self.touch(host);
    }

    async fn get_by_ip(&mut self, ip: IpAddr) -> Option<String> {
        let host = self.ip_to_host.get(&ip).cloned();
        if let Some(host) = &host {
            self.touch(host);
        }
        host
    }

    async fn put_by_ip(&mut self, ip: IpAddr, host: &str) {
        self.ip_to_host.insert(ip, host.to_string());
        self.touch(host);
    }

    async fn del_by_ip(&mut self, ip: IpAddr) {
        if let Some(host) = self.ip_to_host.remove(&ip) {
            self.host_to_ip.remove(&host);
            if let Some(index) = self.order.iter().position(|item| item == &host) {
                self.order.remove(index);
            }
        }
    }

    async fn exist(&mut self, ip: IpAddr) -> bool {
        self.ip_to_host.contains_key(&ip)
    }
}
