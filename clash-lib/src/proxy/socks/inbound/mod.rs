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
    proxy::inbound::InboundHandlerTrait,
};

const SOCKS5_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USER_PASS: u8 = 0x02;
const METHOD_NO_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const REP_SUCCEEDED: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;

pub struct SocksInbound {
    name: String,
    listen_addr: SocketAddr,
    allow_lan: bool,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
}

impl SocksInbound {
    pub fn new(
        common_opts: CommonInboundOpts,
        dispatcher: Arc<Dispatcher>,
        authenticator: ThreadSafeAuthenticator,
    ) -> Self {
        let listen_addr = SocketAddr::new(common_opts.listen.0, common_opts.port);
        Self {
            name: common_opts.name,
            listen_addr,
            allow_lan: common_opts.allow_lan,
            dispatcher,
            authenticator,
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

    async fn listen_tcp(&self) -> io::Result<()> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        info!(
            "{} SOCKS5 listening at: {}",
            self.name, self.listen_addr
        );

        loop {
            let (socket, peer) = listener.accept().await?;
            if !self.allow_lan && !peer.ip().is_loopback() {
                warn!("{} connection from {} is not allowed", self.name, peer);
                continue;
            }

            let authenticator = self.authenticator.clone();
            let name = self.name.clone();
            tokio::spawn(async move {
                if let Err(err) = handle_socks5_connection(socket, authenticator).await {
                    warn!("{} SOCKS5 connection failed: {}", name, err);
                }
            });
        }
    }

    async fn listen_udp(&self) -> io::Result<()> {
        Ok(())
    }
}

enum SocksTarget {
    Ip(SocketAddr),
    Domain(String, u16),
}

async fn handle_socks5_connection(
    mut stream: TcpStream,
    authenticator: ThreadSafeAuthenticator,
) -> io::Result<()> {
    negotiate_auth(&mut stream, authenticator).await?;

    let mut header = [0u8; 3];
    stream.read_exact(&mut header).await?;
    if header[0] != SOCKS5_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported SOCKS version",
        ));
    }

    let cmd = header[1];
    if cmd != CMD_CONNECT {
        send_reply(&mut stream, REP_COMMAND_NOT_SUPPORTED, None).await?;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported SOCKS command",
        ));
    }

    let target = match read_target(&mut stream).await {
        Ok(target) => target,
        Err(err) => {
            send_reply(&mut stream, REP_GENERAL_FAILURE, None).await?;
            return Err(err);
        }
    };
    let outbound_result = match target {
        SocksTarget::Ip(addr) => TcpStream::connect(addr).await,
        SocksTarget::Domain(host, port) => TcpStream::connect((host.as_str(), port)).await,
    }
    .map_err(|err| {
        debug!("failed to connect outbound: {}", err);
        err
    });
    let mut outbound = match outbound_result {
        Ok(stream) => stream,
        Err(err) => {
            send_reply(&mut stream, REP_GENERAL_FAILURE, None).await?;
            return Err(err);
        }
    };

    let bind_addr = outbound.local_addr().unwrap_or_else(|_| {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    });
    send_reply(&mut stream, REP_SUCCEEDED, Some(bind_addr)).await?;

    let _ = tokio::io::copy_bidirectional(&mut stream, &mut outbound).await?;
    Ok(())
}

async fn negotiate_auth(
    stream: &mut TcpStream,
    authenticator: ThreadSafeAuthenticator,
) -> io::Result<()> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != SOCKS5_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported SOCKS version",
        ));
    }

    let n_methods = header[1] as usize;
    if n_methods == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no auth methods provided",
        ));
    }

    let mut methods = vec![0u8; n_methods];
    stream.read_exact(&mut methods).await?;

    let mut response = [SOCKS5_VERSION, METHOD_NO_AUTH];

    if authenticator.enabled() {
        if !methods.contains(&METHOD_USER_PASS) {
            response[1] = METHOD_NO_ACCEPTABLE;
            stream.write_all(&response).await?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "auth required",
            ));
        }

        response[1] = METHOD_USER_PASS;
        stream.write_all(&response).await?;

        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        let ulen = buf[1] as usize;

        let mut uname = vec![0u8; ulen];
        stream.read_exact(&mut uname).await?;

        stream.read_exact(&mut buf[..1]).await?;
        let plen = buf[0] as usize;
        let mut pass = vec![0u8; plen];
        stream.read_exact(&mut pass).await?;

        let user = String::from_utf8_lossy(&uname);
        let pass = String::from_utf8_lossy(&pass);

        let ok = authenticator.authenticate(&user, &pass);
        let status = if ok { REP_SUCCEEDED } else { REP_GENERAL_FAILURE };
        stream.write_all(&[0x01, status]).await?;

        if !ok {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "auth failure",
            ));
        }
    } else if methods.contains(&METHOD_NO_AUTH) {
        response[1] = METHOD_NO_AUTH;
        stream.write_all(&response).await?;
    } else {
        response[1] = METHOD_NO_ACCEPTABLE;
        stream.write_all(&response).await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "no acceptable auth method",
        ));
    }

    Ok(())
}

async fn read_target(stream: &mut TcpStream) -> io::Result<SocksTarget> {
    let mut atyp = [0u8; 1];
    stream.read_exact(&mut atyp).await?;

    let target = match atyp[0] {
        0x01 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let ip = IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]));
            let port = u16::from_be_bytes(port);
            SocksTarget::Ip(SocketAddr::new(ip, port))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let port = u16::from_be_bytes(port);
            let host = String::from_utf8_lossy(&domain).to_string();
            SocksTarget::Domain(host, port)
        }
        0x04 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let ip = IpAddr::V6(Ipv6Addr::from(addr));
            let port = u16::from_be_bytes(port);
            SocksTarget::Ip(SocketAddr::new(ip, port))
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported address type",
            ));
        }
    };

    Ok(target)
}

async fn send_reply(
    stream: &mut TcpStream,
    rep: u8,
    bind_addr: Option<SocketAddr>,
) -> io::Result<()> {
    let addr = bind_addr.unwrap_or_else(|| {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    });

    let mut buf = Vec::with_capacity(22);
    buf.push(SOCKS5_VERSION);
    buf.push(rep);
    buf.push(0x00);

    match addr {
        SocketAddr::V4(addr) => {
            buf.push(0x01);
            buf.extend_from_slice(&addr.ip().octets());
            buf.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            buf.push(0x04);
            buf.extend_from_slice(&addr.ip().octets());
            buf.extend_from_slice(&addr.port().to_be_bytes());
        }
    }

    stream.write_all(&buf).await
}
