use std::net::SocketAddr;

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    common::errors::new_io_error,
    proxy::AnyStream,
    session::SocksAddr,
};

pub const SOCKS5_VERSION: u8 = 0x05;

const MAX_ADDR_LEN: usize = 1 + 1 + 255 + 2;
const MAX_AUTH_LEN: usize = 255;

pub(crate) mod auth_methods {
    pub const NO_AUTH: u8 = 0x00;
    pub const USER_PASS: u8 = 0x02;
    pub const NO_METHODS: u8 = 0xff;
}

pub(crate) mod socks_command {
    pub const CONNECT: u8 = 0x01;
    // pub const BIND: u8 = 0x02;
    pub const UDP_ASSOCIATE: u8 = 0x3;
}

pub(crate) mod response_code {
    pub const SUCCEEDED: u8 = 0x00;
    pub const FAILURE: u8 = 0x01;
    // pub const RULE_FAILURE: u8 = 0x02;
    // pub const NETWORK_UNREACHABLE: u8 = 0x03;
    // pub const HOST_UNREACHABLE: u8 = 0x04;
    // pub const CONNECTION_REFUSED: u8 = 0x05;
    // pub const TTL_EXPIRED: u8 = 0x06;
    pub const COMMAND_NOT_SUPPORTED: u8 = 0x07;
    // pub const ADDR_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

const ERROR_CODE_LOOKUP: &[&str] = &[
    "succeeded",
    "general SOCKS server failure",
    "connection not allowed by ruleset",
    "network unreachable",
    "host unreachable",
    "connection refused",
    "TTL expired",
    "command not supported",
    "address type not supported",
];

pub(crate) async fn client_handshake(
    s: &mut AnyStream,
    addr: &SocksAddr,
    command: u8,
    username: Option<String>,
    password: Option<String>,
) -> std::io::Result<SocksAddr> {
    let mut buf = BytesMut::with_capacity(MAX_AUTH_LEN);
    buf.put_u8(SOCKS5_VERSION);
    buf.put_u8(1);
    buf.put_u8(if username.is_some() && password.is_some() {
        auth_methods::USER_PASS
    } else {
        auth_methods::NO_AUTH
    });
    s.write_all(&buf).await?;

    s.read_exact(&mut buf[..2]).await?;
    if buf[0] != SOCKS5_VERSION {
        return Err(new_io_error("unsupported SOCKS version"));
    }

    match buf[1] {
        auth_methods::NO_AUTH => {}
        auth_methods::USER_PASS => {
            let username = username
                .as_ref()
                .ok_or_else(|| new_io_error("missing username"))?;
            let password = password
                .as_ref()
                .ok_or_else(|| new_io_error("missing password"))?;

            let mut auth = BytesMut::with_capacity(MAX_AUTH_LEN);
            auth.put_u8(1);
            auth.put_u8(username.len() as u8);
            auth.put_slice(username.as_bytes());
            auth.put_u8(password.len() as u8);
            auth.put_slice(password.as_bytes());
            s.write_all(&auth).await?;

            s.read_exact(&mut auth[..2]).await?;
            if auth[1] != response_code::SUCCEEDED {
                return Err(new_io_error("SOCKS5 authentication failed"));
            }
        }
        _ => return Err(new_io_error("unsupported SOCKS5 authentication method")),
    }

    let mut request = BytesMut::with_capacity(MAX_ADDR_LEN);
    request.put_u8(SOCKS5_VERSION);
    request.put_u8(command);
    request.put_u8(0x00);
    if command == socks_command::UDP_ASSOCIATE {
        match addr {
            SocksAddr::Domain(..) | SocksAddr::Ip(SocketAddr::V6(_)) => {
                SocksAddr::any_ipv6().write_buf(&mut request);
            }
            SocksAddr::Ip(SocketAddr::V4(_)) => {
                SocksAddr::any_ipv4().write_buf(&mut request);
            }
        }
    } else {
        addr.write_buf(&mut request);
    }
    s.write_all(&request).await?;

    request.resize(3, 0);
    s.read_exact(&mut request).await?;
    if request[0] != SOCKS5_VERSION {
        return Err(new_io_error("unsupported SOCKS version"));
    }
    if request[1] != response_code::SUCCEEDED {
        let message = if request[1] < ERROR_CODE_LOOKUP.len() as u8 {
            ERROR_CODE_LOOKUP[request[1] as usize]
        } else {
            "unknown error"
        };
        return Err(new_io_error(format!("SOCKS5 request failed with {message}")));
    }

    SocksAddr::read_from(s).await
}
