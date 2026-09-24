use tracing::warn;

const DEFAULT_ALPN: [&str; 2] = ["h2", "http/1.1"];
const DEFAULT_WS_ALPN: [&str; 1] = ["http/1.1"];

use crate::{
    Error,
    config::internal::proxy::OutboundTrojan,
    proxy::{
        HandlerCommonOptions,
        transport::{GrpcClient, TlsClient},
        trojan::{Handler, HandlerOptions},
    },
};

#[cfg(feature = "ws")]
use super::utils::build_ws_client;
#[cfg(feature = "ws")]
use crate::proxy::transport::WsClient;

impl TryFrom<OutboundTrojan> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundTrojan) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundTrojan> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundTrojan) -> Result<Self, Self::Error> {
        let skip_cert_verify = s.skip_cert_verify.unwrap_or_default();
        if skip_cert_verify {
            warn!(
                "skipping TLS cert verification for {}",
                s.common_opts.server
            );
        }

        let h = Handler::new(HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: HandlerCommonOptions {
                connector: s.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            password: s.password.clone(),
            udp: s.udp.unwrap_or_default(),
            tls: {
                let client = TlsClient::new(
                    skip_cert_verify,
                    s.sni
                        .as_ref()
                        .map(|x| x.to_owned())
                        .unwrap_or(s.common_opts.server.to_owned()),
                    s.alpn.clone().or(Some({
                        let network = s.network.as_deref();
                        let alpn: &[&str] = if let Some("ws") = network {
                            &DEFAULT_WS_ALPN
                        } else {
                            &DEFAULT_ALPN
                        };

                        alpn.iter()
                            .copied()
                            .map(|x| x.to_owned())
                            .collect::<Vec<String>>()
                    })),
                    None,
                );
                Some(Box::new(client))
            },
            transport: s
                .network
                .as_ref()
                .map(|x| match x.as_str() {
                    "ws" => {
                        #[cfg(feature = "ws")]
                        {
                            s.ws_opts
                                .as_ref()
                                .map(|x| {
                                    let client: WsClient = build_ws_client(
                                        x,
                                        &s.common_opts,
                                        s.sni.as_deref(),
                                    );
                                    Box::new(client) as _
                                })
                                .ok_or(Error::InvalidConfig(
                                    "ws_opts is required for ws".to_owned(),
                                ))
                        }
                        #[cfg(not(feature = "ws"))]
                        {
                            Err(Error::InvalidConfig(
                                "trojan ws network requires ws feature".to_owned(),
                            ))
                        }
                    }
                    "grpc" => {
                        let grpc_opts = s.grpc_opts.as_ref().ok_or_else(|| {
                            Error::InvalidConfig(
                                "grpc_opts is required for trojan grpc".to_owned(),
                            )
                        })?;
                        if grpc_opts.max_streams.is_some()
                            && (grpc_opts.max_connections.is_some()
                                || grpc_opts.min_streams.is_some())
                        {
                            return Err(Error::InvalidConfig(
                                "trojan grpc max-streams conflicts with max-connections and min-streams"
                                    .to_owned(),
                            ));
                        }
                        let authority = s
                            .sni
                            .clone()
                            .unwrap_or_else(|| s.common_opts.server.clone());
                        let path = format!(
                            "/{}",
                            grpc_opts
                                .grpc_service_name
                                .as_deref()
                                .unwrap_or_default()
                        )
                        .try_into()
                        .map_err(|err| {
                            Error::InvalidConfig(format!(
                                "invalid trojan grpc service path: {err}"
                            ))
                        })?;
                        let client = GrpcClient::new(authority, path)
                            .with_user_agent(grpc_opts.grpc_user_agent.clone())
                            .with_ping_interval(grpc_opts.ping_interval)
                            .with_pool_limits(
                                grpc_opts.max_connections,
                                grpc_opts.min_streams,
                                grpc_opts.max_streams,
                            );
                        Ok(Box::new(client) as _)
                    }
                    _ => Err(Error::InvalidConfig(format!(
                        "unsupported trojan network: {x}"
                    ))),
                })
                .transpose()?,
        });
        Ok(h)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn parse(extra: &str) -> OutboundTrojan {
        serde_yaml::from_str(&format!(
            r#"
name: trojan-test
server: 198.51.100.10
port: 443
password: secret
sni: example.com
{extra}
"#
        ))
        .expect("Trojan test config should parse")
    }

    #[test]
    fn trojan_grpc_builds_with_pool_options() {
        let config = parse(
            r#"network: grpc
grpc-opts:
  grpc-service-name: grpc-service
  grpc-user-agent: test-agent
  ping-interval: 30
  max-connections: 2
  min-streams: 1"#,
        );
        Handler::try_from(&config)
            .expect("Trojan gRPC should build with modern pool options");
    }

    #[test]
    fn trojan_grpc_requires_options() {
        let config = parse("network: grpc");
        let err = Handler::try_from(&config)
            .expect_err("Trojan gRPC must require grpc-opts");
        assert!(err.to_string().contains("grpc_opts is required"));
    }

    #[test]
    fn trojan_grpc_rejects_conflicting_pool_options() {
        let config = parse(
            r#"network: grpc
grpc-opts:
  grpc-service-name: grpc-service
  max-streams: 8
  max-connections: 2"#,
        );
        let err = Handler::try_from(&config)
            .expect_err("conflicting Trojan gRPC pool options must fail");
        assert!(err.to_string().contains("max-streams conflicts"));
    }
}
