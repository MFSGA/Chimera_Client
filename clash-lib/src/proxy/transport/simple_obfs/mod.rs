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

#[derive(Debug)]
pub struct SimpleOBFSOption {
    /// currently only http and tls are supported
    pub mode: SimpleOBFSMode,
    pub host: String,
}
