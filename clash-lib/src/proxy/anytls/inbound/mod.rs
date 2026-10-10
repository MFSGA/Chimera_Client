//! AnyTLS inbound listener — thin orchestrator.

mod datagram;
mod framing;
mod handler;
mod tls;
mod user;

pub use user::build_user_map;

use crate::{
    Dispatcher,
    config::internal::listener::InboundUser,
    proxy::{
        inbound::{
            AllowLanState, InboundHandlerTrait, InboundReady, report_listener_ready,
        },
        utils::{ToCanonical, try_create_dualstack_tcplistener_after_shutdown},
    },
};
use async_trait::async_trait;
use std::{net::SocketAddr, sync::Arc};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use self::{handler::handle_connection, tls::build_tls_acceptor};

pub struct InboundOptions {
    pub addr: SocketAddr,
    /// Single-user fallback password (plaintext). Used when `users_rx` yields
    /// an empty list.
    pub password: String,
    /// File path or inline PEM certificate chain (detected by `-----BEGIN`).
    /// When `None`, an ephemeral self-signed certificate is generated.
    pub certificate: Option<String>,
    /// File path or inline PEM private key (detected by `-----BEGIN`).
    /// When `None`, an ephemeral self-signed certificate is generated.
    pub private_key: Option<String>,
    pub dispatcher: Arc<Dispatcher>,
    pub fw_mark: Option<u32>,
    /// Optional fallback address (`host:port`) for unauthenticated connections.
    pub fallback: Option<String>,
    /// Watch receiver for the live user list.
    pub users_rx: tokio::sync::watch::Receiver<Vec<InboundUser>>,
}

pub struct AnytlsInbound {
    addr: SocketAddr,
    allow_lan: AllowLanState,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<u32>,
    tls_acceptor: TlsAcceptor,
    password: String,
    fallback: Option<String>,
    users_rx: tokio::sync::watch::Receiver<Vec<InboundUser>>,
}

impl Drop for AnytlsInbound {
    fn drop(&mut self) {
        warn!("AnyTLS inbound listener on {} stopped", self.addr);
    }
}

impl AnytlsInbound {
    pub(crate) fn new(
        opts: InboundOptions,
        allow_lan: AllowLanState,
    ) -> std::io::Result<Self> {
        let tls_acceptor = build_tls_acceptor(
            opts.certificate.as_deref(),
            opts.private_key.as_deref(),
        )?;
        Ok(Self {
            addr: opts.addr,
            allow_lan,
            dispatcher: opts.dispatcher,
            fw_mark: opts.fw_mark,
            tls_acceptor,
            password: opts.password,
            fallback: opts.fallback,
            users_rx: opts.users_rx,
        })
    }
}

#[async_trait]
impl InboundHandlerTrait for AnytlsInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        false // UDP is tunnelled over TCP; no separate UDP listener needed.
    }

    async fn listen_tcp(&self, ready: InboundReady) -> std::io::Result<()> {
        let listener = report_listener_ready(
            ready,
            try_create_dualstack_tcplistener_after_shutdown(self.addr).await,
        )?;

        let mut users_rx = self.users_rx.clone();
        let mut user_map =
            build_user_map(&users_rx.borrow_and_update(), &self.password);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, src_addr) = match result {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("anytls inbound {}: accept error: {e}", self.addr);
                            continue;
                        }
                    };

                    let src_addr = src_addr.to_canonical();

                    if !self.allow_lan.permits(src_addr, stream.local_addr()?) {
                        warn!(
                            "anytls inbound {}: connection from {} rejected (not allowed)",
                            self.addr, src_addr
                        );
                        continue;
                    }

                    let acceptor = self.tls_acceptor.clone();
                    let dispatcher = self.dispatcher.clone();
                    let map = Arc::clone(&user_map);
                    let fw_mark = self.fw_mark;
                    let fallback = self.fallback.clone();

                    tokio::spawn(async move {
                        handle_connection(
                            stream, src_addr, acceptor, dispatcher, map, fw_mark,
                            fallback,
                        )
                        .await;
                    });
                }

                Ok(()) = users_rx.changed() => {
                    let users = users_rx.borrow_and_update().clone();
                    info!(
                        "anytls inbound {}: user list updated ({} users)",
                        self.addr,
                        users.len()
                    );
                    user_map = build_user_map(&users, &self.password);
                }
            }
        }
    }

    async fn listen_udp(&self, ready: InboundReady) -> std::io::Result<()> {
        // UDP is handled inside TCP connections via UoT v2; no UDP socket.
        let _ = ready.send(Ok(()));
        Ok(())
    }
}
