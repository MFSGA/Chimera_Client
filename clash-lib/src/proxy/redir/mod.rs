use std::{io, net::SocketAddr, os::fd::AsRawFd, sync::Arc};

use async_trait::async_trait;
use tokio::net::TcpStream;
use tracing::{trace, warn};

use crate::{
    app::dispatcher::Dispatcher,
    proxy::{
        inbound::{InboundHandlerTrait, is_inbound_client_allowed},
        utils::{ToCanonical, apply_tcp_options, try_create_dualstack_tcplistener},
    },
    session::{Network, Session, Type},
};

pub struct RedirInbound {
    addr: SocketAddr,
    allow_lan: bool,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<u32>,
}

impl RedirInbound {
    pub fn new(
        addr: SocketAddr,
        allow_lan: bool,
        dispatcher: Arc<Dispatcher>,
        fw_mark: Option<u32>,
    ) -> Self {
        Self {
            addr,
            allow_lan,
            dispatcher,
            fw_mark,
        }
    }
}

impl Drop for RedirInbound {
    fn drop(&mut self) {
        warn!(address = %self.addr, "redir inbound listener stopped");
    }
}

#[async_trait]
impl InboundHandlerTrait for RedirInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        false
    }

    async fn listen_tcp(&self) -> io::Result<()> {
        let listener = try_create_dualstack_tcplistener(self.addr)?;

        loop {
            let (socket, _) = listener.accept().await?;
            let source = socket.peer_addr()?.to_canonical();
            let local = socket.local_addr()?.to_canonical();
            if !is_inbound_client_allowed(self.allow_lan, source, local) {
                warn!(%source, "redir connection is not allowed");
                continue;
            }
            apply_tcp_options(&socket)?;

            let destination = match get_original_destination_addr(&socket) {
                Ok(destination) => destination.to_canonical(),
                Err(err) => {
                    warn!(%source, %err, "failed to read redir original destination");
                    continue;
                }
            };
            let session = Session {
                network: Network::Tcp,
                typ: Type::Redir,
                source,
                destination: destination.into(),
                so_mark: self.fw_mark,
                ..Default::default()
            };
            trace!("redir new TCP connection {session}");

            let dispatcher = self.dispatcher.clone();
            tokio::spawn(async move {
                dispatcher.dispatch_stream(session, Box::new(socket)).await;
            });
        }
    }

    async fn listen_udp(&self) -> io::Result<()> {
        Err(io::Error::other("redir inbound does not support UDP"))
    }
}

fn get_original_destination_addr(stream: &TcpStream) -> io::Result<SocketAddr> {
    let fd = stream.as_raw_fd();
    unsafe {
        let (_, address) = socket2::SockAddr::try_init(|storage, storage_len| {
            let ipv6_result = libc::getsockopt(
                fd,
                libc::SOL_IPV6,
                libc::IP6T_SO_ORIGINAL_DST,
                storage.cast(),
                storage_len,
            );
            if ipv6_result == 0 {
                return Ok(());
            }

            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                #[allow(unreachable_patterns)]
                Some(libc::ENOPROTOOPT)
                | Some(libc::ENOENT)
                | Some(libc::EOPNOTSUPP)
                | Some(libc::ENOTSUP) => {}
                _ => return Err(err),
            }

            if libc::getsockopt(
                fd,
                libc::SOL_IP,
                libc::SO_ORIGINAL_DST,
                storage.cast(),
                storage_len,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })?;
        address
            .as_socket()
            .ok_or_else(|| io::Error::other("invalid original destination address"))
    }
}
