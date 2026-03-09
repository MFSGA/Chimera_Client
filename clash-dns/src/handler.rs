use std::time::Duration;

use crate::utils::new_io_error;
use crate::{DNSListenAddr, DnsMessageExchanger};
use async_trait::async_trait;
use hickory_proto::op::{Header, Message, ResponseCode};
use hickory_server::server::Request;
use hickory_server::{
    ServerFuture,
    authority::MessageResponseBuilder,
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
    #[error("invalid OP query: {0}")]
    InvalidOpQuery(String),
    #[error("query failed: {0}")]
    QueryFailed(String),
}

#[async_trait]
impl<X> RequestHandler for DnsHandler<X>
where
    X: DnsMessageExchanger + Unpin + Send + Sync + 'static,
{
    async fn handle_request<H: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: H,
    ) -> ResponseInfo {
        let req = match to_dns_message(request) {
            Ok(req) => req,
            Err(err) => {
                error!("failed to parse dns request: {}", err);
                return servfail_info();
            }
        };

        let resp = match self.exchanger.exchange(&req).await {
            Ok(resp) => resp,
            Err(err) => {
                warn!("dns exchange failed: {}", err);
                build_servfail_message(&req)
            }
        };

        let mut builder = MessageResponseBuilder::from_message_request(request);
        if let Some(edns) = resp.extensions().clone() {
            builder.edns(edns);
        }

        let response = builder.build(
            resp.header().clone(),
            resp.answers(),
            resp.name_servers(),
            std::iter::empty::<&hickory_proto::rr::Record>(),
            resp.additionals(),
        );

        match response_handle.send_response(response).await {
            Ok(info) => info,
            Err(err) => {
                error!("failed to send dns response: {}", err);
                servfail_info()
            }
        }
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
        let _ = c;
        warn!("DoH listener is not implemented yet");
    }

    if let Some(c) = listen.dot {
        let _ = c;
        warn!("DoT listener is not implemented yet");
    }

    if let Some(c) = listen.doh3 {
        let _ = c;
        warn!("DoH3 listener is not implemented yet");
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

fn to_dns_message(request: &Request) -> Result<Message, DNSError> {
    let mut message = Message::new();
    message.set_id(request.id());
    message.set_op_code(request.op_code());
    message.set_message_type(request.message_type());
    message.set_authoritative(request.authoritative());
    message.set_truncated(request.truncated());
    message.set_recursion_desired(request.recursion_desired());
    message.set_recursion_available(request.recursion_available());
    message.set_authentic_data(request.authentic_data());
    message.set_checking_disabled(request.checking_disabled());
    message.set_response_code(request.response_code());
    message.add_queries(request.queries().iter().map(|q| q.original().clone()));
    message.add_answers(request.answers().iter().cloned());
    message.add_name_servers(request.name_servers().iter().cloned());
    message.add_additionals(request.additionals().iter().cloned());
    if let Some(edns) = request.edns().cloned() {
        message.set_edns(edns);
    }
    Ok(message)
}

fn build_servfail_message(req: &Message) -> Message {
    let mut header = Header::response_from_request(req.header());
    header.set_response_code(ResponseCode::ServFail);

    let mut message = Message::new();
    message.set_id(header.id());
    message.set_message_type(header.message_type());
    message.set_op_code(header.op_code());
    message.set_authoritative(header.authoritative());
    message.set_truncated(header.truncated());
    message.set_recursion_desired(header.recursion_desired());
    message.set_recursion_available(header.recursion_available());
    message.set_authentic_data(header.authentic_data());
    message.set_checking_disabled(header.checking_disabled());
    message.set_response_code(header.response_code());
    message.add_queries(req.queries().iter().cloned());
    if let Some(edns) = req.extensions().clone() {
        message.set_edns(edns);
    }
    message
}

fn servfail_info() -> ResponseInfo {
    let mut header = Header::new();
    header.set_response_code(ResponseCode::ServFail);
    header.into()
}
