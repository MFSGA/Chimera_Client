use std::{
    io,
    path::{Path, PathBuf},
};

use async_trait::async_trait;
use http::Request;
use http_body_util::BodyExt;
use hyper::Uri;

use crate::{
    app::dns::ThreadSafeDNSResolver,
    common::{
        errors::map_io_error,
        http::{DEFAULT_USER_AGENT, HttpClient, new_http_client},
    },
};

use super::{ProviderVehicle, ProviderVehicleType};

pub struct Vehicle {
    pub url: Uri,
    pub path: PathBuf,
    http_client: HttpClient,
}

impl Vehicle {
    pub fn new<T: Into<Uri>, P: AsRef<Path>>(
        url: T,
        path: P,
        cwd: Option<P>,
        dns_resolver: ThreadSafeDNSResolver,
    ) -> Self {
        let client = new_http_client(dns_resolver, None)
            .expect("failed to create http client");
        Self {
            url: url.into(),
            path: match cwd {
                Some(cwd) => cwd.as_ref().join(path),
                None => path.as_ref().to_path_buf(),
            },
            http_client: client,
        }
    }
}

#[async_trait]
impl ProviderVehicle for Vehicle {
    async fn read(&self) -> std::io::Result<Vec<u8>> {
        let mut req = Request::default();
        req.headers_mut().insert(
            http::header::USER_AGENT,
            DEFAULT_USER_AGENT.parse().expect("must parse user agent"),
        );
        *req.body_mut() = http_body_util::Empty::<bytes::Bytes>::new();
        *req.uri_mut() = self.url.clone();
        self.http_client
            .request(req)
            .await
            .map_err(|err| io::Error::other(err.to_string()))?
            .into_body()
            .collect()
            .await
            .map(|body| body.to_bytes().to_vec())
            .map_err(map_io_error)
    }

    fn path(&self) -> &str {
        self.path.to_str().unwrap()
    }

    fn typ(&self) -> ProviderVehicleType {
        ProviderVehicleType::Http
    }
}
