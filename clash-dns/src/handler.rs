use std::time::Duration;

use crate::utils::new_io_error;
use crate::{DNSListenAddr, DnsMessageExchanger};
use async_trait::async_trait;
use hickory_server::server::Request;
use hickory_server::{
    ServerFuture,
    server::{RequestHandler, ResponseHandler, ResponseInfo},
};
use thiserror::Error;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{error, info, warn};

struct DnsListener<H: RequestHandler> {
    server: ServerFuture<H>,
}

struct DnsHandler<X> {
    exchanger: X,
}

#[derive(Error, Debug)]
pub enum DNSError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /* #[error("invalid OP code: {0}")]
    InvalidOpQuery(String),
    #[error("query failed: {0}")]
    QueryFailed(String), */
}

#[async_trait]
impl<X> RequestHandler for DnsHandler<X>
where
    X: DnsMessageExchanger + Unpin + Send + Sync + 'static,
{
    async fn handle_request<H: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: H,
    ) -> ResponseInfo {
        todo!()
    }
}

static DEFAULT_DNS_SERVER_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn get_dns_listener<X>(
    listen: DNSListenAddr,
    exchanger: X,
    cwd: &std::path::Path,
) -> Option<futures::future::BoxFuture<'static, Result<(), DNSError>>>
where
    X: DnsMessageExchanger + Sync + Send + Unpin + 'static,
{
    let handler = DnsHandler { exchanger };
    let mut s = ServerFuture::new(handler);

    let mut has_server = false;

    if let Some(addr) = listen.udp {
        has_server = UdpSocket::bind(addr)
            .await
            .map(|x| {
                info!("UDP dns server listening on: {}", addr);
                s.register_socket(x);
            })
            .inspect_err(|x| {
                error!("failed to listen UDP DNS server on {}: {}", addr, x);
            })
            .is_ok();
    }
    if let Some(addr) = listen.tcp {
        has_server |= TcpListener::bind(addr)
            .await
            .map(|x| {
                info!("TCP dns server listening on: {}", addr);
                s.register_listener(x, DEFAULT_DNS_SERVER_TIMEOUT);
            })
            .inspect_err(|x| {
                error!("failed to listen TCP DNS server on {}: {}", addr, x);
            })
            .is_ok();
    }
    if let Some(c) = listen.doh {
        todo!()
    }

    if let Some(c) = listen.dot {
        todo!()
    }

    if let Some(c) = listen.doh3 {
        todo!()
    }

    if !has_server {
        return None;
    }

    let mut l = DnsListener { server: s };

    Some(Box::pin(async move {
        info!("starting DNS server");
        l.server.block_until_done().await.map_err(|x| {
            warn!("dns server error: {}", x);
            DNSError::Io(new_io_error(format!("dns server error: {x}")))
        })
    }))
}
