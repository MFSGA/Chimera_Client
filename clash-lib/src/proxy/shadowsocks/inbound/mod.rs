use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use shadowsocks::{
    config::{ServerConfig, ServerUser, ServerUserManager},
    context::Context,
    relay::{Address, tcprelay::proxy_stream::server::ProxyServerStream},
};
use tracing::{debug, info, warn};

use crate::{
    app::dispatcher::Dispatcher,
    common::errors::new_io_error,
    config::internal::listener::InboundUser,
    proxy::{
        inbound::{InboundHandlerTrait, is_inbound_client_allowed},
        shadowsocks::map_cipher,
        utils::{ToCanonical, apply_tcp_options, try_create_dualstack_tcplistener},
    },
    session::{Network, Session, SocksAddr, Type},
};

#[derive(Clone)]
pub struct ShadowsocksInbound {
    addr: SocketAddr,
    password: String,
    cipher: String,
    allow_lan: bool,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<u32>,
    users_rx: tokio::sync::watch::Receiver<Vec<InboundUser>>,
    _static_users_tx: Option<tokio::sync::watch::Sender<Vec<InboundUser>>>,
    _udp_requested: bool,
}

pub struct InboundOptions {
    pub addr: SocketAddr,
    pub password: String,
    pub cipher: String,
    pub udp: bool,
    pub allow_lan: bool,
    pub dispatcher: Arc<Dispatcher>,
    pub fw_mark: Option<u32>,
    pub users_rx: tokio::sync::watch::Receiver<Vec<InboundUser>>,
    pub static_users_tx: Option<tokio::sync::watch::Sender<Vec<InboundUser>>>,
}

impl ShadowsocksInbound {
    pub fn new(opts: InboundOptions) -> Self {
        Self {
            addr: opts.addr,
            password: opts.password,
            cipher: opts.cipher,
            allow_lan: opts.allow_lan,
            dispatcher: opts.dispatcher,
            fw_mark: opts.fw_mark,
            users_rx: opts.users_rx,
            _static_users_tx: opts.static_users_tx,
            _udp_requested: opts.udp,
        }
    }

    fn build_server_config(&self) -> std::io::Result<ServerConfig> {
        ServerConfig::new(self.addr, &self.password, map_cipher(&self.cipher)?)
            .map_err(|err| {
                new_io_error(format!(
                    "failed to create Shadowsocks server config: {err}"
                ))
            })
    }
}

impl Drop for ShadowsocksInbound {
    fn drop(&mut self) {
        warn!("Shadowsocks inbound listener on {} stopped", self.addr);
    }
}

fn build_user_manager(
    users: &[InboundUser],
    addr: SocketAddr,
) -> Option<Arc<ServerUserManager>> {
    if users.is_empty() {
        return None;
    }

    let mut manager = ServerUserManager::new();
    let mut loaded = 0usize;
    for user in users {
        match ServerUser::with_encoded_key(&user.name, &user.password) {
            Ok(user) => {
                manager.add_user(user);
                loaded += 1;
            }
            Err(err) => {
                warn!("skipping invalid Shadowsocks user '{}': {err}", user.name)
            }
        }
    }
    info!(
        "Shadowsocks inbound {addr}: loaded {loaded}/{} users",
        users.len()
    );
    Some(Arc::new(manager))
}

#[async_trait]
impl InboundHandlerTrait for ShadowsocksInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        false
    }

    async fn listen_tcp(&self) -> std::io::Result<()> {
        let context = Context::new_shared(shadowsocks::config::ServerType::Server);
        let config = self.build_server_config()?;
        let method = map_cipher(&self.cipher)?;
        let server_key = Arc::new(config.key().to_vec());
        let listener = try_create_dualstack_tcplistener(self.addr)?;
        let mut users_rx = self.users_rx.clone();
        let mut user_manager =
            build_user_manager(&users_rx.borrow_and_update(), self.addr);

        info!("Shadowsocks TCP prepared. listening on {}", self.addr);
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, source) = accepted?;
                    let source = source.to_canonical();
                    if !is_inbound_client_allowed(
                        self.allow_lan,
                        source,
                        stream.local_addr()?,
                    ) {
                        warn!("Connection from {source} is not allowed");
                        continue;
                    }

                    let dispatcher = self.dispatcher.clone();
                    let context = context.clone();
                    let key = server_key.clone();
                    let manager = user_manager.clone();
                    let fw_mark = self.fw_mark;

                    tokio::spawn(async move {
                        let mut socket = ProxyServerStream::from_stream_with_user_manager(
                            context,
                            stream,
                            method,
                            &key,
                            manager.clone(),
                        );
                        let target = match socket.handshake().await {
                            Ok(target) => target,
                            Err(err) => {
                                warn!("failed to perform Shadowsocks handshake: {err}");
                                return;
                            }
                        };
                        if let Err(err) = apply_tcp_options(socket.get_ref()) {
                            warn!("failed to apply Shadowsocks TCP options: {err}");
                            return;
                        }

                        let inbound_user = socket.user_key().and_then(|key| {
                            manager.as_ref()?.users_iter()
                                .find(|user| user.key() == key)
                                .map(|user| user.name().to_owned())
                        });
                        let destination = match target {
                            Address::SocketAddress(addr) => SocksAddr::Ip(addr),
                            Address::DomainNameAddress(domain, port) => {
                                SocksAddr::Domain(domain, port)
                            }
                        };
                        debug!("Shadowsocks TCP connection target: {destination}");

                        let session = Session {
                            network: Network::Tcp,
                            typ: Type::Shadowsocks,
                            source,
                            destination,
                            so_mark: fw_mark,
                            inbound_user,
                            ..Default::default()
                        };
                        dispatcher.dispatch_stream(session, Box::new(socket)).await;
                    });
                }
                changed = users_rx.changed() => {
                    changed.map_err(|_| {
                        new_io_error("Shadowsocks user update channel closed")
                    })?;
                    let users = users_rx.borrow_and_update().clone();
                    user_manager = build_user_manager(&users, self.addr);
                }
            }
        }
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        Err(new_io_error("Shadowsocks UDP inbound is not enabled yet"))
    }
}
