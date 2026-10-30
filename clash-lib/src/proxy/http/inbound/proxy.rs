use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use bytes::Bytes;
use futures::{TryFutureExt, future::BoxFuture};

use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::{
    Method, Request, Response, Uri,
    body::Incoming,
    header::{CONNECTION, HOST, HeaderValue, UPGRADE},
    server::conn::http1,
};

use hyper_util::{
    client::legacy::Client,
    rt::{TokioExecutor, TokioIo},
};
use tower::Service;
use tracing::{instrument, warn};

use crate::{
    app::dispatcher::Dispatcher,
    common::{auth::ThreadSafeAuthenticator, errors::map_io_error},
    proxy::{AnyStream, ProxyError},
    session::{Network, Session, SocksAddr, Type},
};

use super::{auth::authenticate_req, connector::Connector};

fn requests_protocol_upgrade(req: &Request<Incoming>) -> bool {
    req.headers().contains_key(UPGRADE)
        && req.headers().get_all(CONNECTION).iter().any(|value| {
            value.to_str().is_ok_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
        })
}

async fn proxy_protocol_upgrade(
    mut req: Request<Incoming>,
    src: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<u32>,
) -> Result<Response<BoxBody<Bytes, std::io::Error>>, ProxyError> {
    let downstream_upgrade = hyper::upgrade::on(&mut req);
    let mut connector = Connector::new(src, dispatcher, fw_mark);
    let destination = req.uri().clone();
    let outbound = connector.call(destination.clone()).await?;
    if destination.scheme().is_some() {
        let request_target = destination
            .path_and_query()
            .map_or("/", |path_and_query| path_and_query.as_str());
        *req.uri_mut() =
            request_target
                .parse()
                .map_err(|error: http::uri::InvalidUri| {
                    ProxyError::General(error.to_string())
                })?;
        if !req.headers().contains_key(HOST) {
            let host = destination
                .host()
                .ok_or_else(|| ProxyError::InvalidUrl(destination.to_string()))?;
            let host = match destination.port() {
                Some(port) => format!("{host}:{}", port.as_str()),
                None => host.to_owned(),
            };
            let host = HeaderValue::from_str(&host)
                .map_err(|error| ProxyError::General(error.to_string()))?;
            req.headers_mut().insert(HOST, host);
        }
    }
    let (mut sender, connection) = hyper::client::conn::http1::handshake(outbound)
        .await
        .map_err(|error| ProxyError::General(error.to_string()))?;
    tokio::spawn(async move {
        if let Err(error) = connection.with_upgrades().await {
            warn!("HTTP upgrade upstream connection failed: {error}");
        }
    });

    let mut response = sender
        .send_request(req)
        .await
        .map_err(|error| ProxyError::General(error.to_string()))?;
    if response.status() == hyper::StatusCode::SWITCHING_PROTOCOLS {
        let upstream_upgrade = hyper::upgrade::on(&mut response);
        tokio::spawn(async move {
            let (downstream, upstream) =
                match tokio::try_join!(downstream_upgrade, upstream_upgrade) {
                    Ok(streams) => streams,
                    Err(error) => {
                        warn!("HTTP protocol upgrade failed: {error}");
                        return;
                    }
                };
            let mut downstream = TokioIo::new(downstream);
            let mut upstream = TokioIo::new(upstream);
            if let Err(error) =
                tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await
            {
                warn!("HTTP protocol upgrade tunnel failed: {error}");
            }
        });
    }

    Ok(response.map(|body| body.map_err(map_io_error).boxed()))
}

pub fn maybe_socks_addr(r: &Uri) -> Option<SocksAddr> {
    let port = r.port_u16().unwrap_or(
        match r.scheme().map(|s| s.as_str()).unwrap_or("http") {
            "http" => 80 as _,
            "https" => 443 as _,
            _ => return None,
        },
    );

    r.host().and_then(|x| {
        if let Ok(ip) = x.parse::<IpAddr>() {
            Some(SocksAddr::Ip((ip, port).into()))
        } else {
            SocksAddr::try_from((x.to_string(), port)).ok()
        }
    })
}

async fn proxy(
    req: Request<hyper::body::Incoming>,
    src: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
    fw_mark: Option<u32>,
) -> Result<Response<BoxBody<Bytes, std::io::Error>>, ProxyError> {
    if authenticator.enabled()
        && let Some(res) = authenticate_req(&req, authenticator)
    {
        return Ok(res);
    }

    let client = Client::builder(TokioExecutor::new())
        .http1_title_case_headers(true)
        .http1_preserve_header_case(true)
        .build(Connector::new(src, dispatcher.clone(), fw_mark));

    if req.method() == Method::CONNECT {
        match maybe_socks_addr(req.uri()) {
            Some(addr) => {
                tokio::task::spawn(async move {
                    match hyper::upgrade::on(req).await {
                        Ok(upgraded) => {
                            let sess = Session {
                                network: Network::Tcp,
                                typ: Type::HttpConnect,
                                source: src,
                                destination: addr,
                                so_mark: fw_mark,

                                ..Default::default()
                            };

                            dispatcher
                                .dispatch_stream(
                                    sess,
                                    Box::new(TokioIo::new(upgraded)),
                                )
                                .await
                        }
                        Err(e) => warn!("HTTP handshake failure, {}", e),
                    }
                });

                Ok(Response::new(Empty::new().map_err(map_io_error).boxed()))
            }
            _ => Ok(Response::builder()
                .status(hyper::StatusCode::BAD_REQUEST)
                .body(
                    Full::new(format!("invalid request uri: {}", req.uri()).into())
                        .map_err(map_io_error)
                        .boxed(),
                )
                .unwrap()),
        }
    } else if requests_protocol_upgrade(&req) {
        match proxy_protocol_upgrade(req, src, dispatcher, fw_mark).await {
            Ok(response) => Ok(response),
            Err(error) => {
                warn!("http proxy upgrade failed: {error}");
                Ok(Response::builder()
                    .status(hyper::StatusCode::BAD_GATEWAY)
                    .body(Empty::new().map_err(map_io_error).boxed())
                    .unwrap())
            }
        }
    } else {
        match client
            .request(req)
            .map_err(|x| ProxyError::General(x.to_string()))
            .await
        {
            Ok(res) => Ok(res.map(|b| b.map_err(map_io_error).boxed())),
            Err(e) => {
                warn!("http proxy error: {}", e);
                Ok(Response::builder()
                    .status(hyper::StatusCode::BAD_GATEWAY)
                    .body(Empty::new().map_err(map_io_error).boxed())
                    .unwrap())
            }
        }
    }
}

struct ProxyService {
    src: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
    fw_mark: Option<u32>,
}

impl hyper::service::Service<Request<hyper::body::Incoming>> for ProxyService {
    type Error = ProxyError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;
    type Response = Response<BoxBody<Bytes, std::io::Error>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        Box::pin(proxy(
            req,
            self.src,
            self.dispatcher.clone(),
            self.authenticator.clone(),
            self.fw_mark,
        ))
    }
}

#[instrument(skip(stream, dispatcher, authenticator))]
pub async fn handle(
    stream: TokioIo<AnyStream>,
    src: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
    fw_mark: Option<u32>,
) {
    let result = http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(
            stream,
            ProxyService {
                src,
                dispatcher,
                authenticator,
                fw_mark,
            },
        )
        .with_upgrades()
        .await;

    if let Err(http_err) = result {
        warn!("Error while serving HTTP connection: {}", http_err);
    }
}

#[cfg(test)]
mod tests {
    use hyper::Uri;

    use super::maybe_socks_addr;

    #[test]
    fn rejects_http_host_longer_than_socks_domain_limit() {
        let host = vec!["a".repeat(63); 5].join(".");
        assert!(host.len() > u8::MAX as usize);
        let uri: Uri = format!("http://{host}:80/")
            .parse()
            .expect("long authority should still be a valid URI");

        assert!(maybe_socks_addr(&uri).is_none());
    }
}
