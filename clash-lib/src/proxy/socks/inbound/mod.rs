use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, info, warn};

use crate::{
    app::dispatcher::Dispatcher,
    common::auth::ThreadSafeAuthenticator,
    config::internal::listener::CommonInboundOpts,
    proxy::{
        inbound::InboundHandlerTrait,
        socks::{SOCKS5_VERSION, inbound::stream::handle_tcp},
        utils::{ToCanonical, apply_tcp_options, try_create_dualstack_tcplistener},
    },
    session::{Network, Session, Type},
};

mod stream;

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
            let (socket, _) = listener.accept().await?;
            info!(
                "SOCKS5 TCP accepted connection from {}",
                socket.peer_addr()?
            );

            let src_addr = socket.peer_addr()?.to_canonical();
            if !self.allow_lan && src_addr.ip() != socket.local_addr()?.ip().to_canonical() {
                warn!("Connection from {} is not allowed", src_addr);
                continue;
            }
            apply_tcp_options(&socket)?;

            let mut sess = Session {
                network: Network::Tcp,
                typ: Type::Socks5,
                source: socket.peer_addr()?.to_canonical(),
                so_mark: self.fw_mark,

                ..Default::default()
            };

            let dispatcher = self.dispatcher.clone();
            let authenticator = self.authenticator.clone();

            tokio::spawn(
                async move { handle_tcp(&mut sess, socket, dispatcher, authenticator).await },
            );
        }
    }

    async fn listen_udp(&self) -> io::Result<()> {
        Ok(())
    }
}
