#[cfg(feature = "vless-encryption")]
use self::encryption_stream::EncryptionStream;
use self::stream::VlessStream;
use super::{
    AnyStream, ConnectorType, DialWithConnector, HandlerCommonOptions,
    OutboundHandler, OutboundType,
    transport::Transport,
    utils::{
        GLOBAL_DIRECT_CONNECTOR, NetworkPoolContext, RemoteConnector,
        observe_proxy_target_stream,
    },
};
use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    impl_default_connector,
    proxy::vless::{datagram::OutboundDatagramVless, vision::VisionStream},
    session::Session,
};
use async_trait::async_trait;
use std::{io, sync::Arc};
use tracing::debug;

mod datagram;
pub(crate) mod encryption;
#[cfg(feature = "vless-encryption")]
mod encryption_stream;
mod stream;
mod tls_deframer;
mod tls_fuzzy_deframer;
mod tls_handshake_util;
mod vision;
mod vision_filter;
mod vision_pad;
mod vision_unpad;

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub udp: bool,
    pub transport: Option<Box<dyn Transport>>,
    pub tls: Option<Box<dyn Transport>>,
    pub flow: Option<String>,
    pub encryption: Option<encryption::Config>,
}

pub struct Handler {
    opts: HandlerOptions,
    connector: tokio::sync::RwLock<Option<Arc<dyn RemoteConnector>>>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vless")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl_default_connector!(Handler);

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            connector: Default::default(),
        }
    }

    fn wrap_vless_stream(
        &self,
        s: AnyStream,
        sess: &Session,
        is_udp: bool,
        vision_opts: Option<crate::proxy::transport::VisionOptions>,
        pool_context: Option<&NetworkPoolContext>,
    ) -> io::Result<AnyStream> {
        let s = if let Some(config) = self.opts.encryption.as_ref() {
            // UDP shares the 1-RTT encrypted byte stream. The outer VLESS
            // layer selects UDP command 2 and datagram.rs preserves packet
            // boundaries across the underlying encrypted records.
            #[cfg(feature = "vless-encryption")]
            {
                let prepared = config.prepare_crypto()?;
                Box::new(EncryptionStream::new(s, prepared)?) as AnyStream
            }
            #[cfg(not(feature = "vless-encryption"))]
            {
                let _ = config;
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "VLESS encryption requires vless-encryption feature",
                ));
            }
        } else {
            s
        };

        let vless_stream = VlessStream::new(
            s,
            &self.opts.uuid,
            &sess.destination,
            is_udp,
            self.opts.flow.clone(),
        )?;

        let stream: AnyStream =
            if self.opts.flow.as_deref() == Some("xtls-rprx-vision") {
                Box::new(VisionStream::new(
                    Box::new(vless_stream),
                    self.opts.uuid.clone(),
                    vision_opts,
                )?)
            } else {
                Box::new(vless_stream)
            };
        Ok(match pool_context {
            Some(context) => observe_proxy_target_stream(
                stream,
                context,
                &sess.destination,
                if is_udp {
                    crate::app::runtime_state::TrafficKind::ProxyUdp
                } else {
                    crate::app::runtime_state::TrafficKind::ProxyTcp
                },
            ),
            None => stream,
        })
    }

    async fn try_reuse_transport_stream(
        &self,
        sess: &Session,
        is_udp: bool,
        pool_context: &NetworkPoolContext,
        connector: &dyn RemoteConnector,
    ) -> io::Result<Option<(AnyStream, Vec<crate::app::flow::NetworkPathId>)>> {
        if self.opts.flow.as_deref() == Some("xtls-rprx-vision") {
            return Ok(None);
        }

        let Some(transport) = self.opts.transport.as_ref() else {
            return Ok(None);
        };
        let Some((stream, connected_context)) = transport
            .try_reuse_stream_with_pool_metadata(pool_context.clone())
            .await?
        else {
            return Ok(None);
        };

        // The transport may await a pooled logical stream while the network
        // changes. Never deliver a stale stream or fall back to another route.
        let now = connector.connection_pool_context(sess.iface.as_ref()).await;
        now.verify_reused_path(&connected_context)?;
        let path_ids = connected_context.path_id.clone().into_iter().collect();
        Ok(Some((
            self.wrap_vless_stream(
                stream,
                sess,
                is_udp,
                None,
                Some(&connected_context),
            )?,
            path_ids,
        )))
    }

    async fn try_transport_owned_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
        is_udp: bool,
    ) -> io::Result<Option<(AnyStream, Vec<crate::app::flow::NetworkPathId>)>> {
        if self.opts.flow.as_deref() == Some("xtls-rprx-vision") {
            return Ok(None);
        }

        let Some(transport) = self.opts.transport.as_ref() else {
            return Ok(None);
        };
        let Some((stream, path_ids)) = transport
            .connect_stream_with_connector_and_path_ids(sess, resolver, connector)
            .await?
        else {
            return Ok(None);
        };

        Ok(Some((
            self.wrap_vless_stream(stream, sess, is_udp, None, None)?,
            path_ids,
        )))
    }

    async fn inner_proxy_stream(
        &self,
        s: AnyStream,
        sess: &Session,
        is_udp: bool,
        pool_context: NetworkPoolContext,
    ) -> io::Result<AnyStream> {
        let wants_vision_splice =
            self.opts.flow.as_deref() == Some("xtls-rprx-vision");
        let mut vision_opts = None;

        let s = if let Some(tls) = self.opts.tls.as_ref() {
            if wants_vision_splice {
                let (stream, opts) = tls.proxy_stream_spliced(s).await?;
                vision_opts = opts;
                stream
            } else {
                tls.proxy_stream(s).await?
            }
        } else {
            s
        };

        let s = if let Some(transport) = self.opts.transport.as_ref() {
            if wants_vision_splice && vision_opts.is_none() {
                let (stream, opts) = transport.proxy_stream_spliced(s).await?;
                vision_opts = opts;
                stream
            } else {
                transport
                    .proxy_stream_with_pool_context(s, pool_context.clone())
                    .await?
            }
        } else {
            s
        };

        self.wrap_vless_stream(s, sess, is_udp, vision_opts, Some(&pool_context))
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    async fn reset_connection_pool(&self) -> io::Result<u32> {
        match &self.opts.transport {
            Some(transport) => transport.reset_connection_pool().await,
            None => Ok(0),
        }
    }

    fn name(&self) -> &str {
        &self.opts.name
    }

    fn server_name(&self) -> Option<&str> {
        Some(&self.opts.server)
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Vless
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp
            && (self.opts.encryption.is_none() || cfg!(feature = "vless-encryption"))
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let dialer = self.connector.read().await;

        if let Some(dialer) = dialer.as_ref() {
            debug!("{:?} is connecting via {:?}", self, dialer);
        }

        self.connect_stream_with_connector(
            sess,
            resolver,
            dialer
                .as_ref()
                .unwrap_or(&GLOBAL_DIRECT_CONNECTOR.clone())
                .as_ref(),
        )
        .await
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let dialer = self.connector.read().await;

        if let Some(dialer) = dialer.as_ref() {
            debug!("{:?} is connecting via {:?}", self, dialer);
        }

        self.connect_datagram_with_connector(
            sess,
            resolver,
            dialer
                .as_ref()
                .unwrap_or(&GLOBAL_DIRECT_CONNECTOR.clone())
                .as_ref(),
        )
        .await
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::All
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        let pool_context =
            connector.connection_pool_context(sess.iface.as_ref()).await;
        if let Some((stream, path_ids)) = self
            .try_reuse_transport_stream(sess, false, &pool_context, connector)
            .await?
        {
            let chained =
                ChainedStreamWrapper::new_with_network_path_ids(stream, path_ids);
            chained.append_to_chain(self.name()).await;
            return Ok(Box::new(chained));
        }
        if let Some((stream, path_ids)) = self
            .try_transport_owned_stream(sess, resolver.clone(), connector, false)
            .await?
        {
            let chained =
                ChainedStreamWrapper::new_with_network_path_ids(stream, path_ids);
            chained.append_to_chain(self.name()).await;
            return Ok(Box::new(chained));
        }

        let (stream, connected_pool_context) = connector
            .connect_stream_with_pool_context(
                resolver,
                self.opts.server.as_str(),
                self.opts.port,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
                pool_context,
            )
            .await?;

        let network_path_id = connected_pool_context.path_id.clone();
        let s = self
            .inner_proxy_stream(stream, sess, false, connected_pool_context)
            .await?;
        let chained =
            ChainedStreamWrapper::new_with_network_path_id(s, network_path_id);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedDatagram> {
        let pool_context =
            connector.connection_pool_context(sess.iface.as_ref()).await;
        if let Some((stream, path_ids)) = self
            .try_reuse_transport_stream(sess, true, &pool_context, connector)
            .await?
        {
            let datagram =
                OutboundDatagramVless::new(stream, sess.destination.clone());
            let chained = ChainedDatagramWrapper::new_with_network_path_ids(
                datagram, path_ids,
            );
            chained.append_to_chain(self.name()).await;
            return Ok(Box::new(chained));
        }
        if let Some((stream, path_ids)) = self
            .try_transport_owned_stream(sess, resolver.clone(), connector, true)
            .await?
        {
            let datagram =
                OutboundDatagramVless::new(stream, sess.destination.clone());
            let chained = ChainedDatagramWrapper::new_with_network_path_ids(
                datagram, path_ids,
            );
            chained.append_to_chain(self.name()).await;
            return Ok(Box::new(chained));
        }

        let (stream, connected_pool_context) = connector
            .connect_stream_with_pool_context(
                resolver,
                self.opts.server.as_str(),
                self.opts.port,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
                pool_context,
            )
            .await?;

        let path_ids = connected_pool_context.path_id.clone().into_iter().collect();
        let stream = self
            .inner_proxy_stream(stream, sess, true, connected_pool_context)
            .await?;
        let d = OutboundDatagramVless::new(stream, sess.destination.clone());

        let chained = ChainedDatagramWrapper::new_with_network_path_ids(d, path_ids);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }
}

#[cfg(test)]
mod reuse_tests {
    use std::{net::SocketAddr, sync::Arc};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::{app::dns::MockClashResolver, proxy::utils::DirectConnector};

    #[tokio::test]
    async fn encrypted_vless_advertises_udp_only_with_crypto_feature() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        let key = URL_SAFE_NO_PAD.encode([0x77; 32]);
        let config = encryption::Config::parse(&format!(
            "mlkem768x25519plus.native.1rtt.{key}"
        ))
        .expect("encryption config should parse");
        let mut handler = Handler::new(HandlerOptions {
            name: "udp-encryption".to_owned(),
            common_opts: HandlerCommonOptions::default(),
            server: "example.com".to_owned(),
            port: 443,
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            udp: true,
            transport: None,
            tls: None,
            flow: None,
            encryption: Some(config),
        });

        assert_eq!(
            handler.support_udp().await,
            cfg!(feature = "vless-encryption")
        );
        handler.opts.udp = false;
        assert!(!handler.support_udp().await);
        handler.opts.udp = true;
        handler.opts.encryption = None;
        assert!(handler.support_udp().await);
    }

    struct ReuseTransport;

    #[async_trait]
    impl Transport for ReuseTransport {
        async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
            Ok(stream)
        }

        async fn try_reuse_stream(&self) -> io::Result<Option<AnyStream>> {
            let (stream, peer) = tokio::io::duplex(1024);
            tokio::spawn(async move {
                let _peer = peer;
                std::future::pending::<()>().await;
            });
            Ok(Some(Box::new(stream)))
        }
    }

    struct OwnedDialTransport;

    #[async_trait]
    impl Transport for OwnedDialTransport {
        async fn proxy_stream(&self, _stream: AnyStream) -> io::Result<AnyStream> {
            panic!("owned-dial transport must bypass the pre-dialed TCP path");
        }

        async fn connect_stream_with_connector(
            &self,
            _sess: &Session,
            _resolver: ThreadSafeDNSResolver,
            _connector: &dyn RemoteConnector,
        ) -> io::Result<Option<AnyStream>> {
            let (stream, peer) = tokio::io::duplex(1024);
            tokio::spawn(async move {
                let _peer = peer;
                std::future::pending::<()>().await;
            });
            Ok(Some(Box::new(stream)))
        }
    }

    #[tokio::test]
    async fn vless_can_wrap_transport_owned_stream_before_tcp_dial() {
        let handler = Handler::new(HandlerOptions {
            name: "owned-dial-test".to_owned(),
            common_opts: HandlerCommonOptions::default(),
            server: "example.com".to_owned(),
            port: 443,
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            udp: true,
            transport: Some(Box::new(OwnedDialTransport)),
            tls: None,
            flow: None,
            encryption: None,
        });
        let resolver = Arc::new(MockClashResolver::new());
        let connector = DirectConnector::new();

        let stream = handler
            .try_transport_owned_stream(
                &Session::default(),
                resolver,
                &connector,
                false,
            )
            .await
            .expect("owned transport dial should succeed");

        assert!(
            stream.is_some(),
            "owned logical stream should be wrapped as VLESS before TCP dial"
        );
    }

    #[tokio::test]
    async fn vision_does_not_use_transport_owned_stream() {
        let handler = Handler::new(HandlerOptions {
            name: "vision-owned-dial-test".to_owned(),
            common_opts: HandlerCommonOptions::default(),
            server: "example.com".to_owned(),
            port: 443,
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            udp: true,
            transport: Some(Box::new(OwnedDialTransport)),
            tls: None,
            flow: Some("xtls-rprx-vision".to_owned()),
            encryption: None,
        });
        let resolver = Arc::new(MockClashResolver::new());
        let connector = DirectConnector::new();

        let stream = handler
            .try_transport_owned_stream(
                &Session::default(),
                resolver,
                &connector,
                false,
            )
            .await
            .expect("owned transport lookup should succeed");

        assert!(
            stream.is_none(),
            "Vision must preserve the existing splice-capable TCP path"
        );
    }

    #[derive(Debug)]
    struct S04bpEpochConnector {
        epoch: Arc<std::sync::atomic::AtomicU64>,
        planned: Option<crate::app::flow::NetworkPathId>,
    }

    #[async_trait]
    impl RemoteConnector for S04bpEpochConnector {
        async fn network_generation(&self) -> Option<u64> {
            Some(self.epoch.load(std::sync::atomic::Ordering::SeqCst))
        }

        async fn connection_pool_context(
            &self,
            _: Option<&crate::app::net::OutboundInterface>,
        ) -> NetworkPoolContext {
            NetworkPoolContext {
                network_generation: self.network_generation().await,
                path_id: self.planned.clone(),
                ..Default::default()
            }
        }

        async fn connect_stream(
            &self,
            _: ThreadSafeDNSResolver,
            _: &str,
            _: u16,
            _: Option<&crate::app::net::OutboundInterface>,
            #[cfg(target_os = "linux")] _: Option<u32>,
        ) -> io::Result<AnyStream> {
            panic!("stale pooled VLESS must not dial another path")
        }

        async fn connect_datagram(
            &self,
            _: ThreadSafeDNSResolver,
            _: Option<std::net::SocketAddr>,
            _: crate::session::SocksAddr,
            _: Option<&crate::app::net::OutboundInterface>,
            #[cfg(target_os = "linux")] _: Option<u32>,
        ) -> io::Result<crate::proxy::AnyOutboundDatagram> {
            panic!("stale pooled VLESS must not dial another path")
        }
    }

    struct S04bpEpochReuse {
        epoch: Arc<std::sync::atomic::AtomicU64>,
        switch_epoch: bool,
    }

    #[async_trait]
    impl Transport for S04bpEpochReuse {
        async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
            Ok(stream)
        }

        async fn try_reuse_stream_with_pool_metadata(
            &self,
            requested: NetworkPoolContext,
        ) -> io::Result<Option<(AnyStream, NetworkPoolContext)>> {
            let (stream, peer) = tokio::io::duplex(1024);
            tokio::spawn(async move {
                let _peer = peer;
                std::future::pending::<()>().await;
            });
            if self.switch_epoch {
                self.epoch.store(8, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(Some((Box::new(stream), requested)))
        }
    }

    #[tokio::test]
    async fn s04bp_vless_rechecks_pool_epoch_after_borrow_for_tcp_and_udp() {
        use std::sync::atomic::{AtomicU64, Ordering};
        for udp in [false, true] {
            for switch_epoch in [false, true] {
                let epoch = Arc::new(AtomicU64::new(7));
                let connector = S04bpEpochConnector {
                    epoch: epoch.clone(),
                    planned: None,
                };
                let handler = Handler::new(HandlerOptions {
                    name: "s04bp-epoch".into(),
                    common_opts: HandlerCommonOptions::default(),
                    server: "192.0.2.42".into(),
                    port: 443,
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    udp: true,
                    transport: Some(Box::new(S04bpEpochReuse {
                        epoch: epoch.clone(),
                        switch_epoch,
                    })),
                    tls: None,
                    flow: None,
                    encryption: None,
                });
                let before = connector.connection_pool_context(None).await;
                assert_eq!(before.network_generation, Some(7));
                let outcome = handler
                    .try_reuse_transport_stream(
                        &Session::default(),
                        udp,
                        &before,
                        &connector,
                    )
                    .await;
                if switch_epoch {
                    let err = outcome
                        .err()
                        .expect("stale pooled stream must not be delivered");
                    assert_eq!(err.kind(), io::ErrorKind::Interrupted);
                    assert!(err.to_string().contains("network path changed"));
                    assert_eq!(epoch.load(Ordering::SeqCst), 8);
                } else {
                    assert!(
                        outcome.unwrap().is_some(),
                        "unchanged epoch remains reusable"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn s04bp_transport_owned_socket_does_not_inherit_planned_path_ids() {
        use crate::app::flow::{AddressFamily, InterfaceId, NetworkPathId};
        use std::sync::atomic::AtomicU64;

        let planned = NetworkPathId {
            interface: InterfaceId {
                name: "pre-dial0".into(),
                index: 11,
            },
            family: AddressFamily::Ipv4,
            source_address: Some("192.0.2.10".parse().unwrap()),
            network_generation: 7,
        };
        let connector = S04bpEpochConnector {
            epoch: Arc::new(AtomicU64::new(7)),
            planned: Some(planned),
        };
        assert!(
            connector
                .connection_pool_context(None)
                .await
                .path_id
                .is_some()
        );
        let result = OwnedDialTransport
            .connect_stream_with_connector_and_path_ids(
                &Session::default(),
                Arc::new(MockClashResolver::new()),
                &connector,
            )
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.1.is_empty(),
            "transport-owned sockets must report their own NIC path, never a pre-dial plan"
        );
    }

    #[tokio::test]
    async fn vless_can_wrap_transport_reuse_stream_before_dialing() {
        let handler = Handler::new(HandlerOptions {
            name: "reuse-test".to_owned(),
            common_opts: HandlerCommonOptions::default(),
            server: "example.com".to_owned(),
            port: 443,
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            udp: true,
            transport: Some(Box::new(ReuseTransport)),
            tls: None,
            flow: None,
            encryption: None,
        });

        let stream = handler
            .try_reuse_transport_stream(
                &Session::default(),
                false,
                &NetworkPoolContext::default(),
                &DirectConnector::new(),
            )
            .await
            .expect("reuse lookup should succeed");

        assert!(
            stream.is_some(),
            "reused logical stream should be wrapped as VLESS"
        );
    }

    #[tokio::test]
    async fn vision_does_not_bypass_fresh_security_handshake() {
        let handler = Handler::new(HandlerOptions {
            name: "vision-reuse-test".to_owned(),
            common_opts: HandlerCommonOptions::default(),
            server: "example.com".to_owned(),
            port: 443,
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            udp: true,
            transport: Some(Box::new(ReuseTransport)),
            tls: None,
            flow: Some("xtls-rprx-vision".to_owned()),
            encryption: None,
        });

        let stream = handler
            .try_reuse_transport_stream(
                &Session::default(),
                false,
                &NetworkPoolContext::default(),
                &DirectConnector::new(),
            )
            .await
            .expect("reuse lookup should succeed");

        assert!(
            stream.is_none(),
            "Vision must keep the fresh handshake path"
        );
    }

    #[tokio::test]
    async fn vless_target_response_reports_the_actual_proxy_path() {
        let mut status = crate::app::runtime_state::RuntimeStatus::default();
        status.lifecycle(crate::app::runtime_state::Lifecycle::Running, "test");
        let (tx, mut events) = tokio::sync::mpsc::channel(1);
        let reporter = status.traffic_reporter(tx);
        let path_id = crate::app::flow::NetworkPathId {
            interface: crate::app::flow::InterfaceId {
                name: "wifi0".to_owned(),
                index: 4,
            },
            family: crate::app::flow::AddressFamily::Ipv4,
            source_address: Some("192.0.2.10".parse().unwrap()),
            network_generation: 0,
        };
        let destination: SocketAddr = "203.0.113.8:443".parse().unwrap();
        let context = NetworkPoolContext {
            network_generation: Some(0),
            path_id: Some(path_id),
            eligible_path_ids: None,
            reporter: Some(reporter),
        };
        let handler = Handler::new(HandlerOptions {
            name: "target-proof-test".to_owned(),
            common_opts: HandlerCommonOptions::default(),
            server: "proxy.example.com".to_owned(),
            port: 443,
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_owned(),
            udp: false,
            transport: None,
            tls: None,
            flow: None,
            encryption: None,
        });
        let session = Session {
            destination: crate::session::SocksAddr::Ip(destination),
            ..Default::default()
        };
        let (client, mut peer) = tokio::io::duplex(64);
        let mut observed = handler
            .wrap_vless_stream(
                Box::new(client),
                &session,
                false,
                None,
                Some(&context),
            )
            .expect("VLESS stream should wrap");

        observed.write_all(b"request").await.unwrap();
        let mut request = [0u8; 128];
        let _ = peer.read(&mut request).await.unwrap();
        peer.write_all(&[0, 0]).await.unwrap();
        peer.write_all(b"target response").await.unwrap();
        let mut response = vec![0; b"target response".len()];
        observed.read_exact(&mut response).await.unwrap();
        status.record_traffic(events.recv().await.unwrap());

        let value = serde_json::to_value(status).unwrap();
        assert_eq!(value["trafficEvidence"][0]["kind"], "proxyTcp");
        assert_eq!(value["pathHealth"][0]["state"], "available");
        assert_eq!(value["pathHealth"][0]["path"]["interface"]["name"], "wifi0");
        assert_eq!(value["destinationPathHealth"][0]["family"], "ipv4");
    }
}

#[cfg(all(
    test,
    feature = "tls",
    feature = "tun",
    any(target_os = "linux", target_os = "macos")
))]
mod path_health_tests {
    use std::{net::Ipv4Addr, sync::Arc, time::Duration};

    use bytes::BytesMut;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::mpsc,
        time::timeout,
    };
    use tokio_rustls::TlsAcceptor;

    use super::{Handler, HandlerOptions};
    use crate::{
        app::{
            dns::MockClashResolver,
            flow::{AddressFamily, InterfaceId, InterfaceKind, NetworkPathId},
            net::{OutboundInterface, get_interface_by_name},
            network::{
                BindingStatus, DefaultRouteEvidence, NetworkSnapshot, NetworkStatus,
                PathCandidateObservation,
            },
            runtime_state::Lifecycle,
        },
        proxy::{
            HandlerCommonOptions, OutboundHandler,
            transport::TlsClient,
            utils::{DirectConnector, NetworkPathSource},
        },
        session::{Session, SocksAddr},
    };

    const TEST_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    #[tokio::test]
    async fn tls_handshake_and_target_response_keep_the_dialed_path() {
        crate::setup_default_crypto_provider();
        let loopback_name = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        let interface = get_interface_by_name(loopback_name)
            .expect("loopback interface should be discoverable");

        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
                .expect("test certificate should generate");
        let cert = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
        let key =
            rustls::pki_types::PrivateKeyDer::try_from(signing_key.serialize_der())
                .expect("test private key should serialize");
        let tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("test TLS config should build");
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("failed to bind local VLESS endpoint");
        let endpoint = listener.local_addr().unwrap();

        let mut status = NetworkStatus::default();
        status.set_automatic_supported_for_test(true);
        assert!(status.lifecycle(Lifecycle::Running, "test"));
        status.observed(&NetworkSnapshot {
            path_candidates: vec![
                path_candidate(
                    &interface.name,
                    interface.index,
                    Ipv4Addr::UNSPECIFIED,
                    DefaultRouteEvidence::PrimaryDefaultRoute,
                ),
                path_candidate(
                    &interface.name,
                    interface.index,
                    Ipv4Addr::LOCALHOST,
                    DefaultRouteEvidence::OtherInterface,
                ),
            ],
            ..Default::default()
        });
        let generation = status
            .shadow_path_snapshot()
            .expect("test status should expose observed loopback candidates")
            .0;
        let selected_path = NetworkPathId {
            interface: InterfaceId {
                name: interface.name.clone(),
                index: interface.index,
            },
            family: AddressFamily::Ipv4,
            source_address: Some(Ipv4Addr::LOCALHOST.into()),
            network_generation: generation,
        };

        let (events_tx, mut events_rx) = mpsc::channel(4);
        let reporter = status.traffic_reporter(events_tx);
        let status = Arc::new(tokio::sync::RwLock::new(status));
        let source = NetworkPathSource::default();
        source.attach(status.clone()).await;
        source.attach_traffic_reporter(reporter).await;
        let connector = DirectConnector::with_path_source(source);

        let target: SocksAddr = "203.0.113.39:443".parse().unwrap();
        let server_target = target.clone();
        let acceptor = acceptor.clone();
        let server = tokio::spawn(async move {
            let (rejected, _) = timeout(Duration::from_secs(3), listener.accept())
                .await
                .expect("timed out accepting the rejected wildcard-source attempt")
                .expect("failed to accept the first local dial attempt");
            drop(rejected);

            let (tcp, _) = timeout(Duration::from_secs(3), listener.accept())
                .await
                .expect("timed out accepting the selected-path TLS session")
                .expect("failed to accept the selected local dial");
            let mut tls = timeout(Duration::from_secs(3), acceptor.accept(tcp))
                .await
                .expect("timed out completing the TLS handshake")
                .expect("TLS handshake should succeed");

            let mut request_header = [0; 19];
            tls.read_exact(&mut request_header)
                .await
                .expect("read VLESS request header");
            assert_eq!(request_header[0], 0, "VLESS version must be zero");
            let expected_uuid = uuid::Uuid::parse_str(TEST_UUID).unwrap();
            assert_eq!(&request_header[1..17], expected_uuid.as_bytes());
            assert_eq!(request_header[17], 0, "request add-ons should be empty");
            assert_eq!(request_header[18], 1, "VLESS command must be TCP");

            let mut expected_target = BytesMut::new();
            server_target.write_to_buf_vmess(&mut expected_target);
            let mut encoded_target = vec![0; expected_target.len()];
            tls.read_exact(&mut encoded_target)
                .await
                .expect("read VLESS destination");
            assert_eq!(encoded_target, expected_target.as_ref());

            let mut request = [0; 14];
            timeout(Duration::from_secs(3), tls.read_exact(&mut request))
                .await
                .expect("timed out reading tunneled VLESS request")
                .expect("failed to read tunneled VLESS request");
            assert_eq!(&request, b"target-request");

            // Write the response header fields separately before the payload.
            // TLS may coalesce them for the client, so this does not assert a
            // short read; it verifies that the complete response is accepted.
            tls.write_all(&[0])
                .await
                .expect("write VLESS response version");
            tls.write_all(&[0])
                .await
                .expect("write VLESS response add-on length");
            tls.write_all(b"R")
                .await
                .expect("write tunneled VLESS target response");
            tls.flush().await.expect("flush VLESS target response");
            (server_target, request)
        });

        let session = Session {
            destination: target.clone(),
            iface: Some(OutboundInterface {
                name: interface.name,
                addr_v4: None,
                netmask_v4: None,
                broadcast_v4: None,
                addr_v6: None,
                netmask_v6: None,
                broadcast_v6: None,
                index: interface.index,
                mac_addr: None,
            }),
            ..Default::default()
        };
        let handler = Handler::new(HandlerOptions {
            name: "local-vless".to_owned(),
            common_opts: HandlerCommonOptions::default(),
            server: endpoint.ip().to_string(),
            port: endpoint.port(),
            uuid: TEST_UUID.to_owned(),
            udp: false,
            transport: None,
            tls: Some(Box::new(TlsClient::new(
                true,
                "localhost".to_owned(),
                None,
                None,
            ))),
            flow: None,
            encryption: None,
        });
        let resolver = Arc::new(MockClashResolver::new());
        let mut chained = timeout(
            Duration::from_secs(5),
            handler.connect_stream_with_connector(&session, resolver, &connector),
        )
        .await
        .expect("VLESS path selection and TLS handshake exceeded the deadline")
        .expect("VLESS TLS and request handshake should succeed on fallback path");
        assert_eq!(chained.network_path_ids(), vec![selected_path.clone()]);
        chained.write_all(b"target-request").await.unwrap();

        let mut response = [0; 1];
        timeout(Duration::from_secs(3), chained.read_exact(&mut response))
            .await
            .expect("timed out reading VLESS target response")
            .expect("failed to read VLESS target response");
        assert_eq!(&response, b"R");
        let (server_target, request) = timeout(Duration::from_secs(3), server)
            .await
            .expect("local VLESS server did not finish")
            .expect("local VLESS server task failed");
        assert_eq!(server_target, target);
        assert_eq!(&request, b"target-request");

        for _ in 0..3 {
            let event = timeout(Duration::from_secs(2), events_rx.recv())
                .await
                .expect("expected dial-failure, endpoint, and target evidence")
                .expect("traffic reporter stopped before all path results");
            status.write().await.record_traffic(event);
        }
        let snapshot = {
            let status = status.read().await;
            serde_json::to_value(&*status).unwrap()
        };
        let traffic_evidence = snapshot["trafficEvidence"].as_array().unwrap();
        let endpoint_evidence = traffic_evidence
            .iter()
            .find(|event| event["kind"] == "proxyEndpointTcp")
            .expect("TLS endpoint response should produce endpoint evidence");
        assert!(endpoint_evidence["receivedBytes"].as_u64().unwrap() > 0);
        let target_evidence = traffic_evidence
            .iter()
            .find(|event| event["kind"] == "proxyTcp")
            .expect("VLESS target response should produce proxy evidence");
        assert_eq!(target_evidence["receivedBytes"], 1);

        let selected_path_json = serde_json::to_value(&selected_path).unwrap();
        let selected_path_health = snapshot["pathHealth"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["path"] == selected_path_json)
            .expect("the successful local NIC should have path health");
        assert_eq!(selected_path_health["state"], "available");
        let selected_destination_health = snapshot["destinationPathHealth"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| entry["path"] == selected_path_json)
            .collect::<Vec<_>>();
        assert_eq!(
            selected_destination_health.len(),
            2,
            "VLESS endpoint and tunneled target should have distinct health entries"
        );
        assert!(
            selected_destination_health
                .iter()
                .all(|entry| entry["state"] == "available")
        );
    }

    fn path_candidate(
        name: &str,
        index: u32,
        source_address: Ipv4Addr,
        default_route: DefaultRouteEvidence,
    ) -> PathCandidateObservation {
        PathCandidateObservation {
            interface: InterfaceId {
                name: name.to_owned(),
                index,
            },
            interface_kind: InterfaceKind::Unknown,
            family: AddressFamily::Ipv4,
            source_address: source_address.into(),
            scope_id: None,
            gateway: None,
            default_route,
            binding: BindingStatus::Verified,
            binding_error: None,
        }
    }
}

#[cfg(all(test, docker_test))]
mod tests {
    use std::{collections::HashMap, io::Write as _};

    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose,
    };

    use super::*;
    use crate::{
        proxy::{
            transport::{GrpcClient, TlsClient, WsClient},
            utils::test_utils::docker_utils::{
                config_helper::{build_dns_resolver, test_config_base_dir},
                consts::*,
                docker_runner::{
                    DockerTestRunner, DockerTestRunnerBuilder,
                    MultiDockerTestRunner, RunAndCleanup, alloc_docker_port,
                },
            },
        },
        session::SocksAddr,
        tests::initialize,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const WS_CONTAINER_PORT: u16 = 8443;
    const XRAY_CONTAINER_PORT: u16 = 10002;
    const ECHO_CONTAINER_PORT: u16 = 10003;
    const ECHO_IMAGE: &str = "alpine:3.20";
    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    const VLESS_GRPC_TLS_SERVER_CONFIG: &str = r#"{
  "log": {"loglevel": "debug"},
  "inbounds": [{
    "listen": "0.0.0.0",
    "port": 10002,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "grpc",
      "security": "tls",
      "tlsSettings": {
        "alpn": ["h2"],
        "certificates": [{
          "certificateFile": "/etc/ssl/v2ray/fullchain.pem",
          "keyFile": "/etc/ssl/v2ray/privkey.pem"
        }]
      },
      "grpcSettings": {"serviceName": "grpc-service"}
    }
  }],
  "outbounds": [{"protocol": "freedom"}]
}"#;

    const VLESS_MTLS_SERVER_CONFIG: &str = r#"{
  "log": {"loglevel": "debug"},
  "inbounds": [{
    "listen": "0.0.0.0",
    "port": 10002,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tlsSettings": {
        "verifyClientCertificate": true,
        "certificates": [
          {
            "certificateFile": "/etc/ssl/v2ray/fullchain.pem",
            "keyFile": "/etc/ssl/v2ray/privkey.pem",
            "usage": "encipherment"
          },
          {
            "certificateFile": "/etc/ssl/v2ray/client-ca.pem",
            "usage": "verify"
          }
        ]
      }
    }
  }],
  "outbounds": [{"protocol": "freedom"}]
}"#;

    fn ws_server_port(host_port: u16) -> u16 {
        if crate::proxy::utils::test_utils::docker_utils::use_ci_host_network() {
            WS_CONTAINER_PORT
        } else {
            host_port
        }
    }

    fn server_port(host_port: u16, container_port: u16) -> u16 {
        if crate::proxy::utils::test_utils::docker_utils::use_ci_host_network() {
            container_port
        } else {
            host_port
        }
    }

    fn tls_client(alpn: Option<Vec<String>>) -> Option<Box<dyn Transport>> {
        Some(Box::new(TlsClient::new(
            true,
            "example.org".to_owned(),
            alpn,
            None,
        )))
    }

    fn generate_client_identity() -> anyhow::Result<(String, String, String)> {
        let mut ca_params = CertificateParams::new(Vec::new())?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca_key = KeyPair::generate()?;
        let ca_cert = ca_params.self_signed(&ca_key)?;
        let issuer = Issuer::new(ca_params, ca_key);

        let mut client_params =
            CertificateParams::new(vec!["client.example.org".to_owned()])?;
        client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        client_params.extended_key_usages =
            vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_key = KeyPair::generate()?;
        let client_cert = client_params.signed_by(&client_key, &issuer)?;

        Ok((ca_cert.pem(), client_cert.pem(), client_key.serialize_pem()))
    }

    async fn get_echo_runner() -> anyhow::Result<DockerTestRunner> {
        let command = format!("exec nc -lk -p {ECHO_CONTAINER_PORT} -e cat");
        let runner = DockerTestRunnerBuilder::new()
            .image(ECHO_IMAGE)
            .no_port()
            .cmd(&["sh", "-c", &command])
            .build()
            .await?;
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        Ok(runner)
    }

    async fn tcp_echo_roundtrip(
        handler: Arc<Handler>,
        echo_ip: String,
    ) -> anyhow::Result<()> {
        let resolver = build_dns_resolver().await?;
        let destination: SocksAddr = (echo_ip, ECHO_CONTAINER_PORT).try_into()?;
        let session = Session {
            destination,
            ..Default::default()
        };

        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            handler.connect_stream(&session, resolver),
        )
        .await??;

        let payload = (0..128 * 1024)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        stream.write_all(&payload).await?;
        stream.flush().await?;

        let mut echoed = vec![0u8; payload.len()];
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            stream.read_exact(&mut echoed),
        )
        .await??;
        anyhow::ensure!(echoed == payload, "docker tcp echo payload mismatch");

        Ok(())
    }

    async fn get_ws_runner(host_port: u16) -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let conf = test_config_dir.join("vless-ws-tls.json");
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");

        let mut builder = DockerTestRunnerBuilder::new().image(IMAGE_VLESS);
        builder =
            if crate::proxy::utils::test_utils::docker_utils::use_ci_host_network() {
                builder.host_network()
            } else {
                builder.host_port(host_port, WS_CONTAINER_PORT)
            };

        let runner = builder
            .mounts(&[
                (conf.to_str().unwrap(), "/etc/v2ray/config.json"),
                (cert.to_str().unwrap(), "/etc/ssl/v2ray/fullchain.pem"),
                (key.to_str().unwrap(), "/etc/ssl/v2ray/privkey.pem"),
            ])
            .build()
            .await?;

        DockerTestRunner::wait_host_tcp_ready(
            LOCAL_ADDR,
            ws_server_port(host_port),
            std::time::Duration::from_secs(20),
        )
        .await?;
        // v2ray can accept TCP before the TLS/WebSocket stack is fully ready,
        // which can produce transient `tls handshake eof` locally and in CI.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        Ok(runner)
    }

    async fn get_grpc_runner(host_port: u16) -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");
        let mut config = tempfile::NamedTempFile::new_in(&test_config_dir)?;
        config.write_all(VLESS_GRPC_TLS_SERVER_CONFIG.as_bytes())?;

        let mut builder = DockerTestRunnerBuilder::new().image(IMAGE_XRAY);
        builder =
            if crate::proxy::utils::test_utils::docker_utils::use_ci_host_network() {
                builder.host_network()
            } else {
                builder.host_port(host_port, XRAY_CONTAINER_PORT)
            };

        let runner = builder
            .mounts(&[
                (config.path().to_str().unwrap(), "/etc/xray/config.json"),
                (cert.to_str().unwrap(), "/etc/ssl/v2ray/fullchain.pem"),
                (key.to_str().unwrap(), "/etc/ssl/v2ray/privkey.pem"),
            ])
            .build()
            .await?;

        DockerTestRunner::wait_host_tcp_ready(
            LOCAL_ADDR,
            server_port(host_port, XRAY_CONTAINER_PORT),
            std::time::Duration::from_secs(20),
        )
        .await?;
        // The TCP listen socket may open before Xray's TLS/h2 stack is
        // ready. An actual TLS+ALPN probe makes the gRPC E2E deterministic
        // without retrying application data or suppressing transport errors.
        let tls_probe = TlsClient::new(
            true,
            "example.org".to_owned(),
            Some(vec!["h2".to_owned()]),
            Some("h2".to_owned()),
        );
        let start = tokio::time::Instant::now();
        loop {
            let result =
                tokio::time::timeout(std::time::Duration::from_secs(3), async {
                    let socket = tokio::net::TcpStream::connect((
                        LOCAL_ADDR,
                        server_port(host_port, XRAY_CONTAINER_PORT),
                    ))
                    .await?;
                    tls_probe.proxy_stream(Box::new(socket)).await.map(|_| ())
                })
                .await;
            if matches!(result, Ok(Ok(()))) {
                break;
            }
            if start.elapsed() >= std::time::Duration::from_secs(20) {
                anyhow::bail!(
                    "VLESS gRPC server never became TLS/h2 ready: {result:?}"
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }

        Ok(runner)
    }

    async fn get_mtls_runner(
        host_port: u16,
        client_ca_pem: &str,
    ) -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");
        let mut config = tempfile::NamedTempFile::new_in(&test_config_dir)?;
        config.write_all(VLESS_MTLS_SERVER_CONFIG.as_bytes())?;
        let mut client_ca = tempfile::NamedTempFile::new_in(&test_config_dir)?;
        client_ca.write_all(client_ca_pem.as_bytes())?;

        let mut builder = DockerTestRunnerBuilder::new().image(IMAGE_XRAY);
        builder =
            if crate::proxy::utils::test_utils::docker_utils::use_ci_host_network() {
                builder.host_network()
            } else {
                builder.host_port(host_port, XRAY_CONTAINER_PORT)
            };

        let runner = builder
            .mounts(&[
                (config.path().to_str().unwrap(), "/etc/xray/config.json"),
                (cert.to_str().unwrap(), "/etc/ssl/v2ray/fullchain.pem"),
                (key.to_str().unwrap(), "/etc/ssl/v2ray/privkey.pem"),
                (
                    client_ca.path().to_str().unwrap(),
                    "/etc/ssl/v2ray/client-ca.pem",
                ),
            ])
            .build()
            .await?;

        DockerTestRunner::wait_host_tcp_ready(
            LOCAL_ADDR,
            server_port(host_port, XRAY_CONTAINER_PORT),
            std::time::Duration::from_secs(20),
        )
        .await?;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        Ok(runner)
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_vless_ws() -> anyhow::Result<()> {
        initialize();
        let span = tracing::info_span!("test_vless_ws");
        let _enter = span.enter();
        let host_port = alloc_docker_port();
        let ws_client = WsClient::new(
            "".to_owned(),
            8443,
            "/websocket".to_owned(),
            [("Host".to_owned(), "example.org".to_owned())]
                .into_iter()
                .collect::<HashMap<_, _>>(),
            None,
            0,
            "".to_owned(),
        );

        let echo = get_echo_runner().await?;
        let echo_ip = echo
            .container_ip()
            .ok_or_else(|| anyhow::anyhow!("echo container has no IP"))?;
        let runner = get_ws_runner(host_port).await?;
        let opts = HandlerOptions {
            name: "test-vless-ws".into(),
            common_opts: Default::default(),
            server: LOCAL_ADDR.to_owned(),
            port: ws_server_port(host_port),
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
            flow: None,
            udp: true,
            tls: tls_client(None),
            transport: Some(Box::new(ws_client)),
            encryption: None,
        };
        let handler = Arc::new(Handler::new(opts));
        let mut containers = MultiDockerTestRunner::default();
        containers.add_with_runner(runner);
        containers.add_with_runner(echo);
        containers
            .run_and_cleanup(
                async move { tcp_echo_roundtrip(handler, echo_ip).await },
            )
            .await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_vless_grpc_tls() -> anyhow::Result<()> {
        initialize();
        let host_port = alloc_docker_port();
        let echo = get_echo_runner().await?;
        let echo_ip = echo
            .container_ip()
            .ok_or_else(|| anyhow::anyhow!("echo container has no IP"))?;
        let runner = get_grpc_runner(host_port).await?;

        let grpc_client =
            GrpcClient::new("example.org".to_owned(), "/grpc-service".try_into()?)
                .with_user_agent(Some("chimera-e2e/1.0".to_owned()))
                .with_ping_interval(Some(5));

        let tls = TlsClient::new(
            true,
            "example.org".to_owned(),
            Some(vec!["h2".to_owned()]),
            Some("h2".to_owned()),
        );

        let opts = HandlerOptions {
            name: "test-vless-grpc-tls".into(),
            common_opts: Default::default(),
            server: LOCAL_ADDR.to_owned(),
            port: server_port(host_port, XRAY_CONTAINER_PORT),
            uuid: UUID.into(),
            flow: None,
            udp: false,
            tls: Some(Box::new(tls)),
            transport: Some(Box::new(grpc_client)),
            encryption: None,
        };
        let handler = Arc::new(Handler::new(opts));
        let mut containers = MultiDockerTestRunner::default();
        containers.add_with_runner(runner);
        containers.add_with_runner(echo);
        containers
            .run_and_cleanup(async move {
                tcp_echo_roundtrip(handler.clone(), echo_ip.clone()).await?;
                tcp_echo_roundtrip(handler, echo_ip).await
            })
            .await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_vless_mtls() -> anyhow::Result<()> {
        initialize();
        let host_port = alloc_docker_port();
        let echo = get_echo_runner().await?;
        let echo_ip = echo
            .container_ip()
            .ok_or_else(|| anyhow::anyhow!("echo container has no IP"))?;
        let (client_ca, client_cert, client_key) = generate_client_identity()?;
        let runner = get_mtls_runner(host_port, &client_ca).await?;

        let tls = TlsClient::new(true, "example.org".to_owned(), None, None)
            .with_client_auth(Some(client_cert), Some(client_key))?;

        let opts = HandlerOptions {
            name: "test-vless-mtls".into(),
            common_opts: Default::default(),
            server: LOCAL_ADDR.to_owned(),
            port: server_port(host_port, XRAY_CONTAINER_PORT),
            uuid: UUID.into(),
            flow: None,
            udp: false,
            tls: Some(Box::new(tls)),
            transport: None,
            encryption: None,
        };
        let handler = Arc::new(Handler::new(opts));
        let mut containers = MultiDockerTestRunner::default();
        containers.add_with_runner(runner);
        containers.add_with_runner(echo);
        containers
            .run_and_cleanup(
                async move { tcp_echo_roundtrip(handler, echo_ip).await },
            )
            .await
    }
}

#[cfg(all(test, docker_test, throughput_test))]
mod e2e {
    use crate::{
        proxy::utils::test_utils::{
            consts::*,
            docker_runner::{
                DockerTestRunner, DockerTestRunnerBuilder, RunAndCleanup,
            },
            docker_utils::{
                alloc_port, clash_process_e2e_throughput, config_helper,
                find_clash_rs_binary,
            },
        },
        tests::initialize,
    };

    const CONTAINER_PORT: u16 = 8443;
    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
    const E2E_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;

    const VLESS_WS_TLS_SERVER_CONFIG: &str = r#"{
    "inbounds": [
        {
            "port": 8443,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "level": 0}],
                "decryption": "none",
                "fallbacks": [
                    {"dest": 80},
                    {"path": "/websocket", "dest": 1234, "xver": 1}
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "alpn": ["http/1.1"],
                    "certificates": [{"certificateFile": "/etc/ssl/v2ray/fullchain.pem", "keyFile": "/etc/ssl/v2ray/privkey.pem"}]
                }
            }
        },
        {
            "port": 1234,
            "listen": "127.0.0.1",
            "protocol": "vless",
            "settings": {
                "clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "level": 0}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {"acceptProxyProtocol": true, "path": "/websocket"}
            }
        }
    ],
    "outbounds": [{"protocol": "freedom"}]
}"#;

    async fn get_ws_runner() -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = config_helper::test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");
        let mut tmp = tempfile::NamedTempFile::new_in(&test_config_dir)?;
        use std::io::Write as _;
        tmp.write_all(VLESS_WS_TLS_SERVER_CONFIG.as_bytes())?;
        let result = DockerTestRunnerBuilder::new()
            .image(IMAGE_VLESS)
            .no_port()
            .mounts(&[
                (tmp.path().to_str().unwrap(), "/etc/v2ray/config.json"),
                (cert.to_str().unwrap(), "/etc/ssl/v2ray/fullchain.pem"),
                (key.to_str().unwrap(), "/etc/ssl/v2ray/privkey.pem"),
            ])
            .build()
            .await;
        drop(tmp);
        result
    }

    #[tokio::test]
    async fn e2e_throughput_vless_ws() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_ws_runner().await?;
        let server = container
            .container_ip()
            .ok_or_else(|| anyhow::anyhow!("vless container has no IP"))?;
        let gateway_ip = container.docker_gateway_ip();

        let mmdb = config_helper::test_config_base_dir()
            .join("Country.mmdb")
            .to_str()
            .unwrap()
            .to_owned();
        let config = format!(
            r#"
socks-port: {socks_port}
bind-address: 127.0.0.1
mmdb: "{mmdb}"
mode: global
log-level: error
proxies:
  - name: proxy
    type: vless
    server: {server}
    port: {port}
    uuid: {uuid}
    udp: false
    tls: true
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /websocket
      headers:
        Host: example.org
rules:
  - MATCH,proxy
"#,
            socks_port = socks_port,
            mmdb = mmdb,
            server = server,
            port = CONTAINER_PORT,
            uuid = UUID,
        );
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "vless-ws",
                    socks_port,
                    echo_port,
                    gateway_ip,
                    E2E_PAYLOAD_BYTES,
                )
                .await
                .map(|_| ())
            })
            .await
    }

    #[tokio::test]
    async fn e2e_throughput_vless_tcp() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_ws_runner().await?;
        let server = container
            .container_ip()
            .ok_or_else(|| anyhow::anyhow!("vless container has no IP"))?;
        let gateway_ip = container.docker_gateway_ip();

        let mmdb = config_helper::test_config_base_dir()
            .join("Country.mmdb")
            .to_str()
            .unwrap()
            .to_owned();
        let config = format!(
            r#"
socks-port: {socks_port}
bind-address: 127.0.0.1
mmdb: "{mmdb}"
mode: global
log-level: error
proxies:
  - name: proxy
    type: vless
    server: {server}
    port: {port}
    uuid: {uuid}
    udp: false
    tls: true
    skip-cert-verify: true
rules:
  - MATCH,proxy
"#,
            socks_port = socks_port,
            mmdb = mmdb,
            server = server,
            port = CONTAINER_PORT,
            uuid = UUID,
        );
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "vless-tcp",
                    socks_port,
                    echo_port,
                    gateway_ip,
                    E2E_PAYLOAD_BYTES,
                )
                .await
                .map(|_| ())
            })
            .await
    }
}
