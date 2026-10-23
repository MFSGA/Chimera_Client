use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    platform: Platform,
    outbound_protocols: Vec<&'static str>,
    features: Vec<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Platform {
    os: &'static str,
    architecture: &'static str,
}

pub async fn get() -> Json<Capabilities> {
    #[allow(unused_mut)]
    let mut outbound_protocols = vec!["direct", "reject", "socks5", "vless"];
    #[cfg(feature = "shadowsocks")]
    outbound_protocols.push("ss");
    #[cfg(feature = "anytls")]
    outbound_protocols.push("anytls");
    #[cfg(feature = "wireguard")]
    outbound_protocols.push("wireguard");
    #[cfg(feature = "trojan")]
    outbound_protocols.push("trojan");
    #[cfg(feature = "hysteria")]
    outbound_protocols.push("hysteria2");

    #[allow(unused_mut)]
    let mut features = Vec::new();
    macro_rules! add_feature {
        ($feature:literal, $name:literal) => {
            #[cfg(feature = $feature)]
            features.push($name);
        };
    }
    add_feature!("zero_copy", "zero_copy");
    add_feature!("tls", "tls");
    add_feature!("aws-lc-rs", "aws-lc-rs");
    add_feature!("ring", "ring");
    add_feature!("ws", "ws");
    add_feature!("anytls", "anytls");
    add_feature!("shadowsocks", "shadowsocks");
    add_feature!("wireguard", "wireguard");
    add_feature!("trojan", "trojan");
    add_feature!("hysteria", "hysteria");
    add_feature!("tun", "tun");
    #[cfg(all(feature = "tproxy", target_os = "linux"))]
    features.push("tproxy");
    #[cfg(all(feature = "redir", target_os = "linux"))]
    features.push("redir");
    add_feature!("http_port", "http_port");
    add_feature!("mixed_port", "mixed_port");
    add_feature!("port", "port");
    add_feature!("xhttp-h3", "xhttp-h3");
    add_feature!("tracing", "tracing");
    add_feature!("reality", "reality");
    add_feature!("vless-encryption", "vless-encryption");
    add_feature!("extended-health-check", "extended-health-check");
    add_feature!("dashboard", "dashboard");

    Json(Capabilities {
        platform: Platform {
            os: std::env::consts::OS,
            architecture: std::env::consts::ARCH,
        },
        outbound_protocols,
        features,
    })
}

#[cfg(test)]
mod tests {
    use super::get;

    #[tokio::test]
    async fn client_capability_reports_protocols_that_are_always_compiled() {
        let axum::Json(capabilities) = get().await;
        for protocol in ["direct", "reject", "socks5", "vless"] {
            assert!(capabilities.outbound_protocols.contains(&protocol));
        }
    }
}
