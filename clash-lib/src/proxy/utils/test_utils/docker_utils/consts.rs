pub const LOCAL_ADDR: &str = "127.0.0.1";

pub const IMAGE_TROJAN_GO: &str = "p4gefau1t/trojan-go:latest";
pub const IMAGE_VLESS: &str = "v2fly/v2fly-core:v4.45.2";
pub const IMAGE_XRAY: &str = "teddysun/xray:26.3.27";
pub const IMAGE_SOCKS5: &str = "v2fly/v2fly-core:v4.45.2";
pub const IMAGE_HYSTERIA: &str = "tobyxdd/hysteria:latest";
pub const IMAGE_SINGBOX: &str = "ghcr.io/sagernet/sing-box:v1.13.8";

#[cfg(all(docker_test, throughput_test))]
pub const IMAGE_NETEM: &str = "nicolaka/netshoot:latest";
