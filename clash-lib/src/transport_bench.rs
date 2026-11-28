//! Direct protocol-handler entry points used only by local performance tools.
//!
//! This module deliberately avoids `start_scaffold`, configuration conversion
//! for the full runtime, DNS initialization from user settings, routing, and
//! Controller startup. It still constructs and calls the production outbound
//! handlers, so measured proxy traffic uses the normal HY2 or VLESS transport
//! implementation.

use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::Arc,
};

use anyhow::{Context, anyhow, ensure};
use serde::de::DeserializeOwned;
use serde_yaml::Value;

use crate::{
    app::{
        dispatcher::{BoxedChainedStream, StatisticsManager, TrackedStream},
        dns::{SystemResolver, ThreadSafeDNSResolver},
    },
    common::io::{ShutdownMode, copy_bidirectional_with_report},
    proxy::OutboundHandler,
    session::{Network, Session, SocksAddr, Type},
};
use tokio::net::TcpStream;

/// A selected production outbound handler for the benchmark SOCKS bridge.
#[derive(Clone)]
pub struct Client {
    handler: Arc<dyn OutboundHandler>,
    #[cfg(feature = "hysteria")]
    hysteria2_handler: Option<Arc<crate::proxy::hysteria2::Handler>>,
    resolver: ThreadSafeDNSResolver,
    statistics: Arc<tokio::sync::OnceCell<Arc<StatisticsManager>>>,
}

impl Client {
    #[cfg(feature = "reality")]
    fn from_handler(
        handler: impl OutboundHandler + 'static,
    ) -> anyhow::Result<Self> {
        Self::from_shared_handler(Arc::new(handler))
    }

    fn from_shared_handler(
        handler: Arc<dyn OutboundHandler>,
    ) -> anyhow::Result<Self> {
        crate::setup_default_crypto_provider();
        let resolver: ThreadSafeDNSResolver =
            Arc::new(SystemResolver::new(true).context("create system resolver")?);
        Ok(Self {
            handler,
            #[cfg(feature = "hysteria")]
            hysteria2_handler: None,
            resolver,
            statistics: Arc::new(tokio::sync::OnceCell::new()),
        })
    }

    #[cfg(feature = "hysteria")]
    fn from_hysteria2_handler(
        handler: crate::proxy::hysteria2::Handler,
    ) -> anyhow::Result<Self> {
        let handler = Arc::new(handler);
        let shared: Arc<dyn OutboundHandler> = handler.clone();
        let mut client = Self::from_shared_handler(shared)?;
        client.hysteria2_handler = Some(handler);
        Ok(client)
    }

    /// Construct the production HY2 outbound from a named proxy in a YAML
    /// client configuration. The proxy server must use a numeric IP so this
    /// benchmark path does not depend on DNS.
    #[cfg(feature = "hysteria")]
    pub fn hysteria2_from_config(
        config_path: &Path,
        proxy_name: &str,
    ) -> anyhow::Result<Self> {
        use crate::{
            config::internal::proxy::OutboundHysteria2, proxy::hysteria2::Handler,
        };

        crate::setup_default_crypto_provider();
        let outbound: OutboundHysteria2 =
            load_named_proxy(config_path, proxy_name, "hysteria2")?;
        require_numeric_server(&outbound.server)?;
        let handler = Handler::try_from(outbound)
            .map_err(|_| anyhow!("could not construct HY2 benchmark handler"))?;
        Self::from_hysteria2_handler(handler)
    }

    /// Construct the production VLESS + REALITY + Vision outbound from a
    /// named YAML proxy. The profile accepts only TCP, Vision, and numeric
    /// server addresses to keep the measured setup deterministic and DNS-free.
    #[cfg(feature = "reality")]
    pub fn vless_reality_from_config(
        config_path: &Path,
        proxy_name: &str,
    ) -> anyhow::Result<Self> {
        use crate::{config::internal::proxy::OutboundVless, proxy::vless::Handler};

        crate::setup_default_crypto_provider();
        let outbound: OutboundVless =
            load_named_proxy(config_path, proxy_name, "vless")?;
        ensure!(
            outbound.network.as_deref() == Some("tcp"),
            "REALITY benchmark proxy must use network: tcp"
        );
        ensure!(
            outbound.reality_opts.is_some(),
            "REALITY benchmark proxy must include reality-opts"
        );
        ensure!(
            outbound.flow.as_deref() == Some("xtls-rprx-vision"),
            "REALITY benchmark proxy must use flow: xtls-rprx-vision"
        );
        require_numeric_server(&outbound.common_opts.server)?;
        let handler = Handler::try_from(outbound).map_err(|_| {
            anyhow!("could not construct VLESS REALITY benchmark handler")
        })?;
        Self::from_handler(handler)
    }

    /// Open one production outbound stream for a numeric TCP destination.
    pub async fn connect_tcp(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> std::io::Result<BoxedChainedStream> {
        let session = tcp_session(source, destination);
        self.handler
            .connect_stream(&session, self.resolver.clone())
            .await
    }

    /// Open a production HY2 TCP stream before `ChainedStreamWrapper` is
    /// applied. This benchmark-only path keeps the same Handler, connector,
    /// and authenticated QUIC connection while measuring wrapper overhead.
    #[cfg(feature = "hysteria")]
    pub async fn connect_tcp_raw_hysteria_for_bench(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> std::io::Result<Box<dyn crate::proxy::ClientStream>> {
        let handler = self.hysteria2_handler.as_ref().ok_or_else(|| {
            std::io::Error::other("raw HY2 benchmark path requires a HY2 client")
        })?;
        handler
            .connect_stream_raw_for_bench(
                &tcp_session(source, destination),
                self.resolver.clone(),
            )
            .await
    }

    /// Open a concrete HY2 stream before boxing or chain metadata wrapping.
    /// This benchmark-only path isolates trait-object dispatch from connector
    /// and protocol-core work.
    #[cfg(feature = "hysteria")]
    pub async fn connect_tcp_concrete_hysteria_for_bench(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> std::io::Result<chimera_hysteria2_core::Hy2TcpStream> {
        let handler = self.hysteria2_handler.as_ref().ok_or_else(|| {
            std::io::Error::other(
                "concrete HY2 benchmark path requires a HY2 client",
            )
        })?;
        handler
            .connect_stream_concrete_for_bench(
                &tcp_session(source, destination),
                self.resolver.clone(),
            )
            .await
    }

    /// Enable or disable the production HY2 UDP receive task before the
    /// benchmark opens its first stream.
    #[cfg(feature = "hysteria")]
    pub fn set_hysteria_udp_receive_task_for_bench(
        &self,
        enabled: bool,
    ) -> std::io::Result<()> {
        let handler = self.hysteria2_handler.as_ref().ok_or_else(|| {
            std::io::Error::other(
                "UDP receive-task benchmark switch requires a HY2 client",
            )
        })?;
        handler.set_udp_receive_task_for_bench(enabled);
        Ok(())
    }

    /// Select the standalone socket2-to-Quinn UDP socket path for local HY2
    /// benchmark ablations.
    #[cfg(feature = "hysteria")]
    pub fn set_hysteria_socket2_abstract_socket_for_bench(
        &self,
        enabled: bool,
    ) -> std::io::Result<()> {
        let handler = self.hysteria2_handler.as_ref().ok_or_else(|| {
            std::io::Error::other(
                "socket2 UDP benchmark switch requires a HY2 client",
            )
        })?;
        handler.set_socket2_abstract_socket_for_bench(enabled);
        Ok(())
    }

    /// Relay through the production tracked stream and bidirectional copy loop.
    ///
    /// The benchmark bridge uses this beside Tokio's copy helper to isolate
    /// production flow accounting and relay-copy overhead without starting the
    /// full Clash runtime. `outbound` must already be connected for the same
    /// source and destination represented by the accepted SOCKS stream.
    pub async fn copy_tcp_with_product_tracking(
        &self,
        inbound: TcpStream,
        outbound: BoxedChainedStream,
        source: SocketAddr,
        destination: SocketAddr,
        buffer_size: usize,
    ) -> std::io::Result<()> {
        let session = tcp_session(source, destination);
        let manager = self
            .statistics
            .get_or_init(|| async { StatisticsManager::new() })
            .await
            .clone();
        let mut tracked = TrackedStream::new(outbound, manager, session, None).await;
        let inbound = Box::new(inbound) as Box<dyn crate::proxy::ClientStream>;
        copy_bidirectional_with_report(
            inbound,
            &mut tracked,
            buffer_size,
            std::time::Duration::from_secs(10),
            std::time::Duration::from_secs(10),
            ShutdownMode::HalfClose,
        )
        .await
        .map(|_| ())
        .map_err(std::io::Error::other)
    }
}

fn tcp_session(source: SocketAddr, destination: SocketAddr) -> Session {
    Session {
        network: Network::Tcp,
        typ: Type::Socks5,
        source,
        destination: SocksAddr::Ip(destination),
        resolved_ip: Some(destination.ip()),
        so_mark: None,
        iface: None,
        country: None,
        asn: None,
        traffic_stats: None,
        process_name: None,
        inbound_user: None,
    }
}

fn load_named_proxy<T: DeserializeOwned>(
    config_path: &Path,
    proxy_name: &str,
    expected_type: &str,
) -> anyhow::Result<T> {
    let text = fs::read_to_string(config_path)
        .context("could not read benchmark config file")?;
    parse_named_proxy(&text, proxy_name, expected_type)
}

fn parse_named_proxy<T: DeserializeOwned>(
    text: &str,
    proxy_name: &str,
    expected_type: &str,
) -> anyhow::Result<T> {
    let mut root: Value = serde_yaml::from_str(text)
        .map_err(|_| anyhow!("could not parse benchmark config YAML syntax"))?;
    root.apply_merge().map_err(|_| {
        anyhow!(
            "failed to process config YAML anchors: invalid merge value (details omitted for privacy)"
        )
    })?;
    let proxies = root
        .get("proxies")
        .and_then(Value::as_sequence)
        .context("benchmark config must contain a proxies sequence")?;
    let proxy = proxies
        .iter()
        .find(|proxy| proxy.get("name").and_then(Value::as_str) == Some(proxy_name))
        .context("named benchmark proxy was not found")?;
    ensure!(
        proxy.get("type").and_then(Value::as_str) == Some(expected_type),
        "selected benchmark proxy has the wrong protocol type"
    );
    serde_yaml::from_value(proxy.clone())
        .map_err(|_| anyhow!("selected benchmark proxy fields are invalid"))
}

fn require_numeric_server(server: &str) -> anyhow::Result<IpAddr> {
    server
        .parse::<IpAddr>()
        .map_err(|_| anyhow!("benchmark proxy server must be a numeric IP address"))
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::{parse_named_proxy, require_numeric_server};

    #[derive(Debug, Deserialize)]
    struct MergedProxy {
        #[serde(rename = "type")]
        protocol_type: String,
        name: String,
        server: String,
        port: u16,
        auth: String,
    }

    #[test]
    fn named_proxy_applies_yaml_merge_keys_before_selection() {
        let yaml = r#"
proxies:
  - &shared
    type: hysteria2
    name: template
    server: 127.0.0.1
    port: 443
    auth: fixture-auth
  - <<: *shared
    name: bench
"#;

        let proxy: MergedProxy = parse_named_proxy(yaml, "bench", "hysteria2")
            .expect("merged proxy should deserialize");

        assert_eq!(proxy.protocol_type, "hysteria2");
        assert_eq!(proxy.name, "bench");
        assert_eq!(proxy.server, "127.0.0.1");
        assert_eq!(proxy.port, 443);
        assert_eq!(proxy.auth, "fixture-auth");
    }

    #[test]
    fn invalid_merge_diagnostic_does_not_echo_config_values() {
        let yaml = "secret: fixture-merge-secret-5921\nproxies:\n  <<: fixture-merge-secret-5921\n";
        let error = parse_named_proxy::<MergedProxy>(yaml, "bench", "hysteria2")
            .expect_err("scalar merge value must be rejected")
            .to_string();

        assert!(error.contains("anchors"));
        assert!(!error.contains("fixture-merge-secret-5921"));
    }

    #[test]
    fn yaml_syntax_diagnostic_does_not_echo_config_values() {
        let yaml = "secret: fixture-syntax-secret-5921\nproxies: [";
        let error = parse_named_proxy::<MergedProxy>(yaml, "bench", "hysteria2")
            .expect_err("malformed YAML should be rejected")
            .to_string();

        assert!(error.contains("YAML syntax"));
        assert!(!error.contains("fixture-syntax-secret-5921"));
    }

    #[test]
    fn proxy_deserialization_diagnostic_does_not_echo_field_values() {
        let yaml = r#"
proxies:
  - type: hysteria2
    name: bench
    server: 127.0.0.1
    port: fixture-field-secret-5921
    auth: fixture-auth
"#;
        let error = parse_named_proxy::<MergedProxy>(yaml, "bench", "hysteria2")
            .expect_err("invalid proxy field type should be rejected")
            .to_string();

        assert!(error.contains("proxy fields are invalid"));
        assert!(!error.contains("fixture-field-secret-5921"));
    }

    #[test]
    fn missing_proxy_diagnostic_does_not_echo_proxy_name() {
        let yaml = r#"
proxies:
  - type: hysteria2
    name: other
    server: 127.0.0.1
    port: 443
    auth: fixture-auth
"#;
        let error = parse_named_proxy::<MergedProxy>(
            yaml,
            "fixture-private-proxy-name-5921",
            "hysteria2",
        )
        .expect_err("unknown proxy name should be rejected")
        .to_string();

        assert!(error.contains("proxy was not found"));
        assert!(!error.contains("fixture-private-proxy-name-5921"));
    }

    #[test]
    fn non_numeric_server_diagnostic_does_not_echo_hostname() {
        let error = require_numeric_server("fixture-private-node.internal")
            .expect_err("hostname should be rejected")
            .to_string();

        assert!(error.contains("numeric IP address"));
        assert!(!error.contains("fixture-private-node.internal"));
    }
}
