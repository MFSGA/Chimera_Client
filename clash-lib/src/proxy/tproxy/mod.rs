use std::{io, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use tokio::net::TcpListener;
use tracing::{trace, warn};

use crate::{
    app::dispatcher::Dispatcher,
    proxy::{
        inbound::InboundHandlerTrait,
        utils::{ToCanonical, apply_tcp_options, try_create_dualstack_socket},
    },
    session::{Network, Session, Type},
};

pub struct TproxyInbound {
    addr: SocketAddr,
    _allow_lan: bool,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<u32>,
}

impl TproxyInbound {
    pub fn new(
        addr: SocketAddr,
        allow_lan: bool,
        dispatcher: Arc<Dispatcher>,
        fw_mark: Option<u32>,
    ) -> Self {
        Self {
            addr,
            _allow_lan: allow_lan,
            dispatcher,
            fw_mark,
        }
    }
}

impl Drop for TproxyInbound {
    fn drop(&mut self) {
        warn!(address = %self.addr, "tproxy inbound listener stopped");
    }
}

#[async_trait]
impl InboundHandlerTrait for TproxyInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        false
    }

    async fn listen_tcp(&self) -> io::Result<()> {
        let (socket, dual_stack) =
            try_create_dualstack_socket(self.addr, socket2::Type::STREAM)?;
        if dual_stack || self.addr.is_ipv4() {
            socket.set_ip_transparent_v4(true)?;
        }
        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;
        socket.bind(&self.addr.into())?;
        socket.listen(1024)?;
        let listener = TcpListener::from_std(socket.into())?;

        loop {
            let (socket, _) = listener.accept().await?;
            let source = socket.peer_addr()?.to_canonical();
            let destination = socket.local_addr()?.to_canonical();
            apply_tcp_options(&socket)?;

            let session = Session {
                network: Network::Tcp,
                typ: Type::Tproxy,
                source,
                destination: destination.into(),
                so_mark: self.fw_mark,
                ..Default::default()
            };
            trace!("tproxy new TCP connection {session}");

            let dispatcher = self.dispatcher.clone();
            tokio::spawn(async move {
                dispatcher.dispatch_stream(session, Box::new(socket)).await;
            });
        }
    }

    async fn listen_udp(&self) -> io::Result<()> {
        Err(io::Error::other(
            "tproxy UDP support is not enabled in this migration batch",
        ))
    }
}
