#![allow(dead_code)]

mod http;
mod tls;

pub use http::Client as SimpleObfsHttp;
pub use tls::Client as SimpleObfsTLS;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SimpleOBFSMode {
    Http,
    Tls,
}

pub struct SimpleOBFSOption {
    pub mode: SimpleOBFSMode,
    pub host: String,
}
