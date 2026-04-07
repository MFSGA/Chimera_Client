use std::{path::Path, sync::Arc};

use prost::Message;
use tracing::{debug, info};

use crate::{
    Error,
    common::{http::HttpClient, utils::download},
};

pub static DEFAULT_GEOSITE_DOWNLOAD_URL: &str = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/202406182210/geosite.dat";

pub mod geodata_proto {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Domain {
        #[prost(enumeration = "domain::Type", tag = "1")]
        pub r#type: i32,
        #[prost(string, tag = "2")]
        pub value: String,
        #[prost(message, repeated, tag = "3")]
        pub attribute: ::prost::alloc::vec::Vec<domain::Attribute>,
    }

    pub mod domain {
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Attribute {
            #[prost(string, tag = "1")]
            pub key: ::prost::alloc::string::String,
        }

        #[derive(
            Clone,
            Copy,
            Debug,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            ::prost::Enumeration,
        )]
        #[repr(i32)]
        pub enum Type {
            Plain = 0,
            Regex = 1,
            Domain = 2,
            Full = 3,
        }
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct GeoSite {
        #[prost(string, tag = "1")]
        pub country_code: String,
        #[prost(message, repeated, tag = "2")]
        pub domain: ::prost::alloc::vec::Vec<Domain>,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct GeoSiteList {
        #[prost(message, repeated, tag = "1")]
        pub entry: ::prost::alloc::vec::Vec<GeoSite>,
    }
}

pub struct GeoData {
    cache: geodata_proto::GeoSiteList,
}

pub type GeoDataLookup = Arc<dyn GeoDataLookupTrait + Send + Sync>;

pub trait GeoDataLookupTrait {
    fn get(&self, list: &str) -> Option<geodata_proto::GeoSite>;
}

impl GeoDataLookupTrait for GeoData {
    fn get(&self, list: &str) -> Option<geodata_proto::GeoSite> {
        self.cache
            .entry
            .iter()
            .find(|entry| entry.country_code.eq_ignore_ascii_case(list))
            .cloned()
    }
}

impl GeoData {
    pub async fn new<P: AsRef<Path>>(
        path: P,
        download_url: String,
        http_client: HttpClient,
    ) -> Result<Self, Error> {
        debug!("geosite path: {}", path.as_ref().to_string_lossy());

        if !path.as_ref().exists() || download_url.contains("force=true") {
            info!("downloading geodata from {}", download_url);
            download(&download_url, path.as_ref(), &http_client)
                .await
                .map_err(|err| {
                    Error::InvalidConfig(format!("geosite download failed: {err}"))
                })?;
        }

        let bytes = tokio::fs::read(path).await?;
        let cache =
            geodata_proto::GeoSiteList::decode(bytes.as_slice()).map_err(|err| {
                Error::InvalidConfig(format!("geosite decode failed: {err}"))
            })?;

        Ok(Self { cache })
    }
}
