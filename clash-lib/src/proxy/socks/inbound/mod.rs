use std::{io, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use tracing::{info, warn};

use crate::{
    app::dispatcher::Dispatcher,
    common::{auth::ThreadSafeAuthenticator, errors::new_io_error},
    proxy::{
        inbound::{InboundHandlerTrait, is_inbound_client_allowed},
        utils::{ToCanonical, apply_tcp_options, try_create_dualstack_tcplistener},
    },
    session::{Network, Session, Type},
};

mod datagram;
mod stream;

pub use datagram::Socks5UDPCodec;
pub use stream::handle_tcp;

pub struct SocksInbound {
    addr: SocketAddr,
    allow_lan: bool,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
    fw_mark: Option<u32>,
}

impl Drop for SocksInbound {
    fn drop(&mut self) {
        warn!("SOCKS5 inbound listener on {} stopped", self.addr);
    }
}

impl SocksInbound {
    pub fn new(
        addr: SocketAddr,
        allow_lan: bool,
        dispatcher: Arc<Dispatcher>,
        authenticator: ThreadSafeAuthenticator,
        fw_mark: Option<u32>,
    ) -> Self {
        Self {
            addr,
            allow_lan,
            dispatcher,
            authenticator,
            fw_mark,
        }
    }
}

#[async_trait]
impl InboundHandlerTrait for SocksInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        false
    }

    async fn listen_tcp(&self) -> std::io::Result<()> {
        let listener = try_create_dualstack_tcplistener(self.addr)?;
        info!("SOCKS5 TCP prepared. listening on {}", self.addr);
        loop {
            let (socket, _) = match listener.accept().await {
                Ok(socket) => socket,
                Err(err) => {
                    warn!("socks accept failed: {err}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };
            let src_addr = match socket.peer_addr() {
                Ok(addr) => addr.to_canonical(),
                Err(err) => {
                    warn!("socks peer_addr failed: {err}");
                    continue;
                }
            };
            info!("SOCKS5 TCP accepted connection from {}", src_addr);

            let local_addr = match socket.local_addr() {
                Ok(addr) => addr,
                Err(err) => {
                    warn!("socks local_addr failed: {err}");
                    continue;
                }
            };
            if !is_inbound_client_allowed(self.allow_lan, src_addr, local_addr) {
                warn!("Connection from {} is not allowed", src_addr);
                continue;
            }
            if let Err(err) = apply_tcp_options(&socket) {
                warn!("socks apply_tcp_options failed: {err}");
                continue;
            }

            let mut sess = Session {
                network: Network::Tcp,
                typ: Type::Socks5,
                source: src_addr,
                so_mark: self.fw_mark,

                ..Default::default()
            };

            let dispatcher = self.dispatcher.clone();
            let authenticator = self.authenticator.clone();

            tokio::spawn(async move {
                handle_tcp(&mut sess, socket, dispatcher, authenticator).await
            });
        }
    }

    async fn listen_udp(&self) -> io::Result<()> {
        Err(new_io_error("UDP is not supported"))
    }
}
