use crate::common::utils::default_bool_true;
use serde::{Deserialize, Serialize};

use super::config::BindAddress;

#[cfg(any(feature = "anytls", feature = "shadowsocks"))]
#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
pub struct InboundUser {
    pub name: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum InboundOpts {
    #[serde(alias = "socks")]
    Socks {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        #[serde(default = "default_bool_true")]
        udp: bool,
    },
    #[cfg(feature = "http_port")]
    #[serde(alias = "http")]
    Http {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
    },
    #[cfg(feature = "mixed_port")]
    #[serde(alias = "mixed")]
    Mixed {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        #[serde(default = "default_bool_true")]
        udp: bool,
    },
    #[cfg(feature = "redir")]
    Redir {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
    },
    #[cfg(feature = "tproxy")]
    Tproxy {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
    },
    #[cfg(feature = "shadowsocks")]
    #[serde(alias = "shadowsocks")]
    Shadowsocks {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        #[serde(default = "default_bool_true")]
        udp: bool,
        cipher: String,
        password: String,
        #[serde(default)]
        users: Vec<InboundUser>,
    },
    #[cfg(feature = "anytls")]
    #[serde(alias = "anytls")]
    Anytls {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        password: String,
        #[serde(default)]
        certificate: Option<String>,
        #[serde(rename = "private-key", default)]
        private_key: Option<String>,
        #[serde(default)]
        users: Vec<InboundUser>,
        #[serde(default)]
        fallback: Option<String>,
    },
}

impl InboundOpts {
    pub fn common_opts(&self) -> &CommonInboundOpts {
        match self {
            InboundOpts::Socks { common_opts, .. } => common_opts,
            #[cfg(feature = "http_port")]
            InboundOpts::Http { common_opts, .. } => common_opts,
            #[cfg(feature = "mixed_port")]
            InboundOpts::Mixed { common_opts, .. } => common_opts,
            #[cfg(feature = "redir")]
            InboundOpts::Redir { common_opts } => common_opts,
            #[cfg(feature = "tproxy")]
            InboundOpts::Tproxy { common_opts } => common_opts,
            #[cfg(feature = "shadowsocks")]
            InboundOpts::Shadowsocks { common_opts, .. } => common_opts,
            #[cfg(feature = "anytls")]
            InboundOpts::Anytls { common_opts, .. } => common_opts,
        }
    }

    pub fn common_opts_mut(&mut self) -> &mut CommonInboundOpts {
        match self {
            InboundOpts::Socks { common_opts, .. } => common_opts,
            #[cfg(feature = "http_port")]
            InboundOpts::Http { common_opts, .. } => common_opts,
            #[cfg(feature = "mixed_port")]
            InboundOpts::Mixed { common_opts, .. } => common_opts,
            #[cfg(feature = "redir")]
            InboundOpts::Redir { common_opts } => common_opts,
            #[cfg(feature = "tproxy")]
            InboundOpts::Tproxy { common_opts } => common_opts,
            #[cfg(feature = "shadowsocks")]
            InboundOpts::Shadowsocks { common_opts, .. } => common_opts,
            #[cfg(feature = "anytls")]
            InboundOpts::Anytls { common_opts, .. } => common_opts,
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            #[cfg(feature = "http_port")]
            InboundOpts::Http { .. } => "http",
            InboundOpts::Socks { .. } => "socks",
            #[cfg(feature = "mixed_port")]
            InboundOpts::Mixed { .. } => "mixed",
            #[cfg(feature = "redir")]
            InboundOpts::Redir { .. } => "redir",
            #[cfg(feature = "tproxy")]
            InboundOpts::Tproxy { .. } => "tproxy",
            #[cfg(feature = "shadowsocks")]
            InboundOpts::Shadowsocks { .. } => "shadowsocks",
            #[cfg(feature = "anytls")]
            InboundOpts::Anytls { .. } => "anytls",
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct CommonInboundOpts {
    pub name: String,
    pub listen: BindAddress,
    #[serde(default)]
    pub allow_lan: bool,
    pub port: u16,
    /// Linux routing mark
    pub fw_mark: Option<u32>,
}

#[cfg(all(test, any(feature = "redir", feature = "tproxy")))]
mod tests {
    use super::*;

    #[cfg(feature = "redir")]
    #[test]
    fn redir_listener_deserializes() {
        let listener: InboundOpts = serde_yaml::from_str(
            "type: redir\nname: transparent\nlisten: 127.0.0.1\nport: 7892\nallow-lan: true\nfw-mark: 123\n",
        )
        .unwrap();
        assert_eq!(listener.type_name(), "redir");
        let common = listener.common_opts();
        assert_eq!(common.name, "transparent");
        assert_eq!(common.port, 7892);
        assert!(common.allow_lan);
        assert_eq!(common.fw_mark, Some(123));
    }

    #[cfg(feature = "tproxy")]
    #[test]
    fn tproxy_listener_deserializes() {
        let listener: InboundOpts = serde_yaml::from_str(
            "type: tproxy\nname: transparent-udp\nlisten: 127.0.0.1\nport: 7893\nallow-lan: true\nfw-mark: 124\n",
        )
        .unwrap();
        assert_eq!(listener.type_name(), "tproxy");
        let common = listener.common_opts();
        assert_eq!(common.name, "transparent-udp");
        assert_eq!(common.port, 7893);
        assert!(common.allow_lan);
        assert_eq!(common.fw_mark, Some(124));
    }
}
