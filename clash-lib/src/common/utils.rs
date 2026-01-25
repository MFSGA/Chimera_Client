use std::{collections::HashMap, path::Path};

use futures::StreamExt;
use http_body_util::{BodyDataStream, Empty};
use tracing::debug;

use crate::{
    Error,
    common::{
        errors::new_io_error,
        http::{ClashHTTPClientExt, DEFAULT_USER_AGENT, HttpClient},
    },
};

pub fn default_bool_true() -> bool {
    true
}

pub async fn download<P>(url: &str, path: P, http_client: &HttpClient) -> anyhow::Result<()>
where
    P: AsRef<Path> + std::marker::Send,
{
    let ext = {
        let fragments = url.rsplit_once('#').map(|x| x.1).unwrap_or_default();
        let pairs = fragments.split('&').filter_map(|x| {
            let mut kv = x.splitn(2, '=');
            if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
                Some((k.to_owned(), v.to_owned()))
            } else {
                None
            }
        });

        let params: HashMap<String, String> = pairs.collect();
        ClashHTTPClientExt {
            outbound: params.get("_clash_outbound").cloned(),
        }
    };

    download_with_ext(url, path, http_client, ext, 10).await
}

async fn download_with_ext<P>(
    url: &str,
    path: P,
    http_client: &HttpClient,
    req_ext: ClashHTTPClientExt,
    mut max_redirects: usize,
) -> anyhow::Result<()>
where
    P: AsRef<Path> + std::marker::Send,
{
    use std::io::Write;

    let mut current = url.to_string();

    loop {
        debug!("downloading data from {current}");
        let uri = current.parse::<http::Uri>()?;
        let mut req = http::Request::builder()
            .header(http::header::USER_AGENT, DEFAULT_USER_AGENT)
            .uri(&uri)
            .method(http::Method::GET)
            .body(Empty::<bytes::Bytes>::new())?;
        req.extensions_mut().insert(req_ext.clone());

        let res = http_client.request(req).await?;

        if res.status().is_redirection() {
            let redirected = res.headers().get("Location").ok_or(new_io_error(
                format!("failed to download from {current}").as_str(),
            ))?;
            let redirected = redirected.to_str()?;
            debug!("redirected to {redirected}");
            if max_redirects == 0 {
                return Err(Error::InvalidConfig(
                    "too many redirects, max redirects reached".to_string(),
                )
                .into());
            }
            max_redirects = max_redirects.saturating_sub(1);
            current = redirected.to_string();
            continue;
        }

        if !res.status().is_success() {
            return Err(
                Error::InvalidConfig(format!("data download failed: {}", res.status())).into(),
            );
        }

        debug!("downloading data to {}", path.as_ref().to_string_lossy());
        let mut out = std::fs::File::create(&path)?;
        let mut stream = BodyDataStream::new(res.into_body());
        while let Some(chunk) = stream.next().await {
            out.write_all(&chunk?)?;
        }

        return Ok(());
    }
}

pub fn serialize_duration<S>(
    duration: &std::time::Duration,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_u128(duration.as_millis())
}
