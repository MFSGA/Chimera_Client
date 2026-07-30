use futures::TryFutureExt;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use std::net::{Shutdown, TcpStream};

#[allow(dead_code)]
pub fn start_clash(options: clash_lib::Options) -> Result<(), clash_lib::Error> {
    clash_lib::start_scaffold(options)
}

pub fn wait_port_ready(port: u16) -> Result<(), clash_lib::Error> {
    let addr = format!("127.0.0.1:{}", port);
    let mut attempts = 0;
    while attempts < 300 {
        if let Ok(stream) = TcpStream::connect(&addr) {
            stream.shutdown(Shutdown::Both).ok();
            return Ok(());
        }
        attempts += 1;
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err(clash_lib::Error::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("Port {} is not ready after 300 attempts (30s)", port),
    )))
}

#[allow(dead_code)]
fn wait_port_closed(port: u16) -> Result<(), clash_lib::Error> {
    let addr = format!("127.0.0.1:{}", port);
    let mut attempts = 0;
    while attempts < 30 {
        if TcpStream::connect(&addr).is_err() {
            return Ok(());
        }
        attempts += 1;
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Err(clash_lib::Error::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("Port {} is still open after 15 seconds", port),
    )))
}

/// RAII guard for Clash instance that ensures proper cleanup
#[allow(dead_code)]
pub struct ClashInstance {
    ports: Vec<u16>,
    handle: Option<std::thread::JoinHandle<()>>,
    token: tokio_util::sync::CancellationToken,
}

impl ClashInstance {
    #[allow(dead_code)]
    pub fn start(
        options: clash_lib::Options,
        ports: Vec<u16>,
    ) -> Result<Self, clash_lib::Error> {
        let (handle, token) = clash_lib::start_scaffold_instance(options)?;

        if let Some(&main_port) = ports.first()
            && let Err(err) = wait_port_ready(main_port)
        {
            token.cancel();
            let _ = handle.join();
            return Err(err);
        }

        Ok(Self {
            ports,
            handle: Some(handle),
            token,
        })
    }
}

impl Drop for ClashInstance {
    fn drop(&mut self) {
        self.token.cancel();

        for &port in &self.ports {
            if let Err(e) = wait_port_closed(port) {
                eprintln!(
                    "Warning: Failed to wait for port {} to close: {}",
                    port, e
                );
            }
        }

        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Sends an HTTP request to the specified URL using a TCP connection.
/// Don't use any domain name in the URL, which will trigger DNS resolution.
/// And libnss_files will likely cause a coredump(in static crt build).
/// TODO: Use a DNS resolver to resolve the domain name in the URL.
#[allow(dead_code)]
pub async fn send_http_request<T>(
    url: hyper::Uri,
    req: hyper::Request<T>,
) -> std::io::Result<http::Response<Incoming>>
where
    T: hyper::body::Body + Send + 'static,
    <T as hyper::body::Body>::Data: Send,
    <T as hyper::body::Body>::Error: Sync + Send + std::error::Error,
{
    let host = url.host().expect("uri has no host");
    let port = url.port_u16().unwrap_or(80);
    let addr = format!("{}:{}", host, port);

    let stream = tokio::net::TcpStream::connect(addr).await?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .map_err(|e| {
            std::io::Error::other(format!("Failed to establish connection: {}", e))
        })
        .await?;

    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {:?}", err);
        }
    });

    let res = sender
        .send_request(req)
        .map_err(|e| std::io::Error::other(format!("Failed to send request: {}", e)))
        .await?;

    Ok(res)
}

/// SOCKS5 UDP relay session that keeps the TCP control connection alive.
#[allow(dead_code)]
pub struct Socks5UdpSession {
    _tcp: tokio::net::TcpStream,
    pub socket: tokio::net::UdpSocket,
    pub relay_addr: std::net::SocketAddr,
}

#[allow(dead_code)]
impl Socks5UdpSession {
    pub async fn connect(proxy_port: u16) -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
            .await
            .expect("failed to connect to SOCKS5 listener");
        tcp.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut auth = [0u8; 2];
        tcp.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, [0x05, 0x00], "SOCKS5 authentication failed");

        tcp.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut header = [0u8; 4];
        tcp.read_exact(&mut header).await.unwrap();
        assert_eq!(header[1], 0x00, "SOCKS5 UDP ASSOCIATE rejected");

        let relay_addr: std::net::SocketAddr = match header[3] {
            0x01 => {
                let mut ip = [0u8; 4];
                let mut port = [0u8; 2];
                tcp.read_exact(&mut ip).await.unwrap();
                tcp.read_exact(&mut port).await.unwrap();
                (std::net::Ipv4Addr::from(ip), u16::from_be_bytes(port)).into()
            }
            atyp => panic!("unexpected UDP relay address type {atyp}"),
        };
        let relay_addr = if relay_addr.ip().is_unspecified() {
            std::net::SocketAddr::from(([127, 0, 0, 1], relay_addr.port()))
        } else {
            relay_addr
        };

        Self {
            _tcp: tcp,
            socket: tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            relay_addr,
        }
    }

    pub async fn send_ipv4(&self, data: &[u8], dst_ip: [u8; 4], dst_port: u16) {
        let mut packet = Vec::with_capacity(10 + data.len());
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        packet.extend_from_slice(&dst_ip);
        packet.extend_from_slice(&dst_port.to_be_bytes());
        packet.extend_from_slice(data);
        self.socket.send_to(&packet, self.relay_addr).await.unwrap();
    }

    pub async fn recv(&self) -> (Vec<u8>, String) {
        let mut buf = vec![0u8; 65535];
        let (len, sender) = self.socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(sender, self.relay_addr, "unexpected UDP relay sender");
        let packet = &buf[..len];
        assert!(packet.len() >= 4, "SOCKS5 UDP response is truncated");
        let mut pos = 4usize;
        let source = match packet[3] {
            0x01 => {
                assert!(packet.len() >= pos + 6);
                let ip = std::net::Ipv4Addr::new(
                    packet[pos],
                    packet[pos + 1],
                    packet[pos + 2],
                    packet[pos + 3],
                );
                pos += 4;
                let port = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
                pos += 2;
                format!("{ip}:{port}")
            }
            0x03 => {
                let domain_len = packet[pos] as usize;
                pos += 1;
                let domain =
                    std::str::from_utf8(&packet[pos..pos + domain_len]).unwrap();
                pos += domain_len;
                let port = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
                pos += 2;
                format!("{domain}:{port}")
            }
            0x04 => {
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&packet[pos..pos + 16]);
                pos += 16;
                let port = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
                pos += 2;
                format!("[{}]:{port}", std::net::Ipv6Addr::from(ip))
            }
            atyp => panic!("unknown SOCKS5 UDP response address type {atyp}"),
        };
        (packet[pos..].to_vec(), source)
    }
}
