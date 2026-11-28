use std::{
    env,
    fs::File,
    io::{self, BufReader},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    process,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, bail};
use chimera_hysteria2_core::{AuthenticatedConnection, HysteriaClient};
use quinn::Runtime;
use rustls::{ClientConfig as RustlsClientConfig, RootCertStore};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[derive(Debug)]
struct Arguments {
    server: SocketAddr,
    server_name: String,
    listen: SocketAddr,
    local_bind: SocketAddr,
    udp_socket_mode: UdpSocketMode,
    endpoint_mode: EndpointMode,
    quic_connections: usize,
    udp_recv_buffer_bytes: Option<usize>,
    ca: PathBuf,
    up_bps: Option<u64>,
    down_bps: Option<u64>,
    cwnd_packets: Option<u64>,
    stats_interval_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum UdpSocketMode {
    #[default]
    NativeEndpoint,
    TokioAbstractSocket,
    Socket2AbstractSocket,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum EndpointMode {
    #[default]
    Shared,
    PerConnection,
}

impl Arguments {
    fn parse(args: impl IntoIterator<Item = String>) -> anyhow::Result<Self> {
        let mut server = None;
        let mut server_name = None;
        let mut listen: SocketAddr = "127.0.0.1:59901".parse()?;
        let mut local_bind: SocketAddr = "0.0.0.0:0".parse()?;
        let mut udp_socket_mode = UdpSocketMode::default();
        let mut endpoint_mode = EndpointMode::default();
        let mut quic_connections = 1usize;
        let mut udp_recv_buffer_bytes = None;
        let mut ca = None;
        let mut up_bps = None;
        let mut down_bps = None;
        let mut cwnd_packets = None;
        let mut stats_interval_ms = None;
        let mut args = args.into_iter();

        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--server" => {
                    server = Some(required_value(&mut args, &argument)?.parse()?)
                }
                "--server-name" | "--sni" => {
                    server_name = Some(required_value(&mut args, &argument)?);
                }
                "--listen" => {
                    listen = required_value(&mut args, &argument)?.parse()?
                }
                "--local-bind" => {
                    local_bind = required_value(&mut args, &argument)?.parse()?;
                }
                "--udp-socket-mode" => {
                    udp_socket_mode = match required_value(&mut args, &argument)?
                        .as_str()
                    {
                        "native" => UdpSocketMode::NativeEndpoint,
                        "tokio-abstract" => UdpSocketMode::TokioAbstractSocket,
                        "socket2-abstract" => UdpSocketMode::Socket2AbstractSocket,
                        value => bail!(
                            "unsupported UDP socket mode `{value}`; use native, tokio-abstract, or socket2-abstract"
                        ),
                    };
                }
                "--endpoint-mode" => {
                    endpoint_mode = match required_value(&mut args, &argument)?
                        .as_str()
                    {
                        "shared" => EndpointMode::Shared,
                        "per-connection" => EndpointMode::PerConnection,
                        value => bail!(
                            "unsupported endpoint mode `{value}`; use shared or per-connection"
                        ),
                    };
                }
                "--quic-connections" => {
                    quic_connections =
                        required_value(&mut args, &argument)?.parse()?;
                    if !(1..=64).contains(&quic_connections) {
                        bail!("--quic-connections must be between 1 and 64");
                    }
                }
                "--udp-recv-buffer-bytes" => {
                    let bytes: usize =
                        required_value(&mut args, &argument)?.parse()?;
                    if bytes == 0 {
                        bail!("--udp-recv-buffer-bytes must be greater than zero");
                    }
                    udp_recv_buffer_bytes = Some(bytes);
                }
                "--ca" => {
                    ca = Some(PathBuf::from(required_value(&mut args, &argument)?))
                }
                "--up-bps" => {
                    up_bps = Some(required_value(&mut args, &argument)?.parse()?);
                }
                "--down-bps" => {
                    down_bps = Some(required_value(&mut args, &argument)?.parse()?);
                }
                "--cwnd-packets" => {
                    cwnd_packets =
                        Some(required_value(&mut args, &argument)?.parse()?);
                }
                "--stats-interval-ms" => {
                    let interval_ms: u64 =
                        required_value(&mut args, &argument)?.parse()?;
                    if interval_ms == 0 {
                        bail!("--stats-interval-ms must be greater than zero");
                    }
                    stats_interval_ms = Some(interval_ms);
                }
                "--help" | "-h" => {
                    println!(
                        "HY2_PASSWORD is read from the environment; required options: --server, --server-name, --ca. Use --udp-socket-mode native|tokio-abstract|socket2-abstract to choose Quinn's native endpoint or a caller-supplied UDP socket. Use --quic-connections N to shard SOCKS streams across N authenticated QUIC connections (benchmark only), and --endpoint-mode shared|per-connection to select whether those connections share one Quinn endpoint."
                    );
                    println!(
                        "Optional: --stats-interval-ms N logs QUIC cwnd, RTT, loss, and pacing for benchmark diagnosis."
                    );
                    println!(
                        "Optional: --udp-recv-buffer-bytes N sets SO_RCVBUF on a socket2-abstract benchmark socket; it is rejected with native or tokio-abstract mode."
                    );
                    process::exit(0);
                }
                _ => bail!("unknown argument: {argument}"),
            }
        }

        if !listen.ip().is_loopback() {
            bail!(
                "--listen must use a loopback address; this benchmark SOCKS5 listener has no authentication"
            );
        }
        if endpoint_mode == EndpointMode::PerConnection
            && quic_connections > 1
            && local_bind.port() != 0
        {
            bail!(
                "--local-bind must use port 0 when --quic-connections is greater than 1"
            );
        }
        if udp_recv_buffer_bytes.is_some()
            && udp_socket_mode != UdpSocketMode::Socket2AbstractSocket
        {
            bail!(
                "--udp-recv-buffer-bytes requires --udp-socket-mode socket2-abstract"
            );
        }

        Ok(Self {
            server: server
                .context("--server is required (use a numeric IP:PORT)")?,
            server_name: server_name.context("--server-name is required")?,
            listen,
            local_bind,
            udp_socket_mode,
            endpoint_mode,
            quic_connections,
            udp_recv_buffer_bytes,
            ca: ca.context(
                "--ca is required and must contain the server trust certificate",
            )?,
            up_bps,
            down_bps,
            cwnd_packets,
            stats_interval_ms,
        })
    }
}

fn required_value(
    args: &mut impl Iterator<Item = String>,
    argument: &str,
) -> anyhow::Result<String> {
    args.next()
        .ok_or_else(|| anyhow::anyhow!("{argument} requires a value"))
}

fn tls_config(ca: &PathBuf) -> anyhow::Result<RustlsClientConfig> {
    let file = File::open(ca)
        .with_context(|| format!("open CA certificate file {}", ca.display()))?;
    let mut reader = BufReader::new(file);
    let mut roots = RootCertStore::empty();
    let mut count = 0;
    for cert in rustls_pemfile::certs(&mut reader) {
        roots.add(cert.context("parse CA certificate")?)?;
        count += 1;
    }
    if count == 0 {
        bail!(
            "CA certificate file {} contains no certificates",
            ca.display()
        );
    }

    Ok(RustlsClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let arguments = Arguments::parse(env::args().skip(1))?;
    install_crypto_provider();
    let password = env::var("HY2_PASSWORD")
        .context("HY2_PASSWORD environment variable must be set")?;
    let tls = tls_config(&arguments.ca)?;
    let client = Arc::new(HysteriaClient::new(
        tls,
        &[],
        password,
        arguments.up_bps,
        arguments.down_bps,
        arguments.cwnd_packets,
        false,
    )?);
    let mut shared_endpoint = match arguments.endpoint_mode {
        EndpointMode::Shared => Some(
            create_endpoint(
                &client,
                arguments.udp_socket_mode,
                arguments.udp_recv_buffer_bytes,
                arguments.local_bind,
                arguments.server,
            )
            .await?,
        ),
        EndpointMode::PerConnection => None,
    };
    let mut connections = Vec::with_capacity(arguments.quic_connections);
    for index in 0..arguments.quic_connections {
        let connection_result = match shared_endpoint.as_mut() {
            Some(endpoint) => {
                client
                    .connect_on_endpoint(
                        endpoint,
                        arguments.server,
                        &arguments.server_name,
                    )
                    .await
            }
            None => {
                connect(
                    &client,
                    arguments.udp_socket_mode,
                    arguments.udp_recv_buffer_bytes,
                    arguments.local_bind,
                    arguments.server,
                    &arguments.server_name,
                )
                .await
            }
        };
        let connection = connection_result.with_context(|| {
            format!(
                "connect to and authenticate with Hysteria 2 server ({}/{})",
                index + 1,
                arguments.quic_connections
            )
        })?;
        eprintln!(
            "HY2 core authenticated: server={}, udp={}, brutal_bps={:?}, endpoint_mode={:?}, connection={}/{}",
            arguments.server,
            connection.supports_udp(),
            connection.brutal_bps(),
            arguments.endpoint_mode,
            index + 1,
            arguments.quic_connections,
        );
        connections.push(Arc::new(connection));
    }
    serve(
        arguments.listen,
        client,
        connections.into(),
        arguments.stats_interval_ms,
    )
    .await
}

async fn connect(
    client: &HysteriaClient,
    udp_socket_mode: UdpSocketMode,
    udp_recv_buffer_bytes: Option<usize>,
    local_bind: SocketAddr,
    server: SocketAddr,
    server_name: &str,
) -> anyhow::Result<AuthenticatedConnection> {
    let connection = match udp_socket_mode {
        UdpSocketMode::NativeEndpoint => {
            client.connect_direct(local_bind, server, server_name).await
        }
        UdpSocketMode::TokioAbstractSocket => {
            let socket = tokio::net::UdpSocket::bind(local_bind).await?;
            let socket = socket.into_std()?;
            let socket = quinn::TokioRuntime.wrap_udp_socket(socket)?;
            client.connect(socket, server, server_name).await
        }
        UdpSocketMode::Socket2AbstractSocket => {
            let socket = socket2::Socket::new(
                socket2::Domain::for_address(server),
                socket2::Type::DGRAM,
                None,
            )?;
            configure_udp_recv_buffer(&socket, udp_recv_buffer_bytes)?;
            socket.set_broadcast(true)?;
            socket.set_nonblocking(true)?;
            let socket: std::net::UdpSocket = socket.into();
            let socket = tokio::net::UdpSocket::from_std(socket)?;
            let socket = socket.into_std()?;
            let socket = quinn::TokioRuntime.wrap_udp_socket(socket)?;
            client.connect(socket, server, server_name).await
        }
    }?;
    Ok(connection)
}

async fn create_endpoint(
    client: &HysteriaClient,
    udp_socket_mode: UdpSocketMode,
    udp_recv_buffer_bytes: Option<usize>,
    local_bind: SocketAddr,
    server: SocketAddr,
) -> anyhow::Result<quinn::Endpoint> {
    match udp_socket_mode {
        UdpSocketMode::NativeEndpoint => Ok(client.new_direct_endpoint(local_bind)?),
        UdpSocketMode::TokioAbstractSocket => {
            let socket = tokio::net::UdpSocket::bind(local_bind).await?;
            let socket = socket.into_std()?;
            let socket = quinn::TokioRuntime.wrap_udp_socket(socket)?;
            client.new_endpoint(socket)
        }
        UdpSocketMode::Socket2AbstractSocket => {
            let socket = socket2::Socket::new(
                socket2::Domain::for_address(server),
                socket2::Type::DGRAM,
                None,
            )?;
            configure_udp_recv_buffer(&socket, udp_recv_buffer_bytes)?;
            socket.set_broadcast(true)?;
            socket.set_nonblocking(true)?;
            let socket: std::net::UdpSocket = socket.into();
            let socket = tokio::net::UdpSocket::from_std(socket)?;
            let socket = socket.into_std()?;
            let socket = quinn::TokioRuntime.wrap_udp_socket(socket)?;
            client.new_endpoint(socket)
        }
    }
}

fn configure_udp_recv_buffer(
    socket: &socket2::Socket,
    requested_bytes: Option<usize>,
) -> anyhow::Result<()> {
    if let Some(requested_bytes) = requested_bytes {
        socket.set_recv_buffer_size(requested_bytes)?;
    }
    let effective_bytes = socket.recv_buffer_size()?;
    eprintln!(
        "HY2 UDP SO_RCVBUF requested_bytes={} effective_bytes={effective_bytes}",
        requested_bytes
            .map(|bytes| bytes.to_string())
            .unwrap_or_else(|| "default".to_owned())
    );
    Ok(())
}

fn install_crypto_provider() {
    #[cfg(feature = "aws-lc-rs")]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

async fn serve(
    listen: SocketAddr,
    client: Arc<HysteriaClient>,
    connections: Arc<[Arc<AuthenticatedConnection>]>,
    stats_interval_ms: Option<u64>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    eprintln!(
        "HY2 core SOCKS5 listener ready on {listen}; QUIC connections={}",
        connections.len()
    );
    if let Some(interval_ms) = stats_interval_ms {
        spawn_connection_stats_sampler(
            connections.clone(),
            Duration::from_millis(interval_ms),
        );
    }
    let mut next_connection = 0usize;
    loop {
        let (stream, _) = listener.accept().await?;
        let client = client.clone();
        let connection = connections[next_connection % connections.len()].clone();
        next_connection = next_connection.wrapping_add(1);
        tokio::spawn(async move {
            if let Err(error) = handle_socks(stream, client, connection).await {
                eprintln!("HY2 core SOCKS5 stream failed: {error}");
            }
        });
    }
}

fn spawn_connection_stats_sampler(
    connections: Arc<[Arc<AuthenticatedConnection>]>,
    interval: Duration,
) {
    tokio::spawn(async move {
        let started = tokio::time::Instant::now();
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let elapsed_ms = started.elapsed().as_millis();
            for (index, authenticated) in connections.iter().enumerate() {
                let connection = authenticated.connection();
                let stats = connection.stats();
                let metrics = connection.congestion_state().metrics();
                eprintln!(
                    "HY2_QUIC_STATS elapsed_ms={elapsed_ms} connection={} cwnd_bytes={} pacing_bps={} rtt_us={} min_rtt_us={} sent_packets={} lost_packets={} lost_bytes={}",
                    index + 1,
                    stats.path.cwnd,
                    metrics.pacing_rate.unwrap_or_default(),
                    stats.path.rtt.as_micros(),
                    stats.path.min_rtt.as_micros(),
                    stats.path.sent_packets,
                    stats.path.lost_packets,
                    stats.path.lost_bytes,
                );
            }
        }
    });
}

async fn handle_socks(
    mut inbound: TcpStream,
    client: Arc<HysteriaClient>,
    connection: Arc<AuthenticatedConnection>,
) -> io::Result<()> {
    let destination = match read_connect_request(&mut inbound).await {
        Ok(destination) => destination,
        Err(error) => {
            let _ = write_reply(&mut inbound, 1).await;
            return Err(error);
        }
    };
    let mut outbound = match client.open_tcp_stream(&connection, &destination).await
    {
        Ok(outbound) => outbound,
        Err(error) => {
            let _ = write_reply(&mut inbound, 1).await;
            return Err(error);
        }
    };
    write_reply(&mut inbound, 0).await?;
    tokio::io::copy_bidirectional_with_sizes(
        &mut inbound,
        &mut outbound,
        64 * 1024,
        64 * 1024,
    )
    .await?;
    Ok(())
}

async fn read_connect_request(stream: &mut TcpStream) -> io::Result<String> {
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SOCKS version 5 required",
        ));
    }
    let mut methods = vec![0; usize::from(greeting[1])];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        stream.write_all(&[5, 0xff]).await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS client does not offer no-authentication",
        ));
    }
    stream.write_all(&[5, 0]).await?;

    let mut request = [0; 4];
    stream.read_exact(&mut request).await?;
    if request[0] != 5 || request[1] != 1 || request[2] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SOCKS CONNECT with a valid reserved byte is required",
        ));
    }

    let host = match request[3] {
        1 => {
            let mut octets = [0; 4];
            stream.read_exact(&mut octets).await?;
            IpAddr::from(octets).to_string()
        }
        4 => {
            let mut octets = [0; 16];
            stream.read_exact(&mut octets).await?;
            format!("[{}]", IpAddr::from(octets))
        }
        3 => {
            let mut length = [0; 1];
            stream.read_exact(&mut length).await?;
            let mut domain = vec![0; usize::from(length[0])];
            stream.read_exact(&mut domain).await?;
            String::from_utf8(domain)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported SOCKS address type",
            ));
        }
    };
    let mut port = [0; 2];
    stream.read_exact(&mut port).await?;
    Ok(format!("{host}:{}", u16::from_be_bytes(port)))
}

async fn write_reply(stream: &mut TcpStream, reply: u8) -> io::Result<()> {
    stream.write_all(&[5, reply, 0, 1, 0, 0, 0, 0, 0, 0]).await
}

#[cfg(test)]
mod tests {
    use super::{Arguments, EndpointMode, UdpSocketMode};

    fn parse(extra: &[&str]) -> anyhow::Result<Arguments> {
        let mut args = vec![
            "--server",
            "127.0.0.1:443",
            "--server-name",
            "hy2.test",
            "--ca",
            "ca.pem",
        ];
        args.extend_from_slice(extra);
        Arguments::parse(args.into_iter().map(str::to_owned))
    }

    #[test]
    fn defaults_to_loopback_and_parses_transfer_limits() {
        let arguments = parse(&["--up-bps", "2000000", "--cwnd-packets", "32"])
            .expect("arguments should parse");
        assert_eq!(arguments.listen, "127.0.0.1:59901".parse().unwrap());
        assert_eq!(arguments.up_bps, Some(2_000_000));
        assert_eq!(arguments.cwnd_packets, Some(32));
        assert_eq!(arguments.udp_socket_mode, UdpSocketMode::NativeEndpoint);
        assert_eq!(arguments.endpoint_mode, EndpointMode::Shared);
        assert_eq!(arguments.stats_interval_ms, None);
    }

    #[test]
    fn parses_optional_congestion_stats_interval() {
        let arguments = parse(&["--stats-interval-ms", "1000"])
            .expect("stats interval should parse");
        assert_eq!(arguments.stats_interval_ms, Some(1000));
        assert!(parse(&["--stats-interval-ms", "0"]).is_err());
    }

    #[test]
    fn parses_explicit_tokio_abstract_udp_socket_mode() {
        let arguments = parse(&["--udp-socket-mode", "tokio-abstract"])
            .expect("socket mode should parse");
        assert_eq!(
            arguments.udp_socket_mode,
            UdpSocketMode::TokioAbstractSocket
        );
    }

    #[test]
    fn parses_explicit_socket2_abstract_udp_socket_mode() {
        let arguments = parse(&["--udp-socket-mode", "socket2-abstract"])
            .expect("socket mode should parse");
        assert_eq!(
            arguments.udp_socket_mode,
            UdpSocketMode::Socket2AbstractSocket
        );
    }

    #[test]
    fn parses_udp_receive_buffer_only_for_socket2_mode() {
        let arguments = parse(&[
            "--udp-socket-mode",
            "socket2-abstract",
            "--udp-recv-buffer-bytes",
            "1048576",
        ])
        .expect("socket2 receive buffer should parse");
        assert_eq!(arguments.udp_recv_buffer_bytes, Some(1_048_576));
        assert!(parse(&["--udp-recv-buffer-bytes", "1048576"]).is_err());
        assert!(
            parse(&[
                "--udp-socket-mode",
                "socket2-abstract",
                "--udp-recv-buffer-bytes",
                "0",
            ])
            .is_err()
        );
    }

    #[test]
    fn parses_quic_connection_sharding_and_requires_ephemeral_local_ports() {
        let arguments = parse(&["--quic-connections", "8"])
            .expect("connection sharding should parse with ephemeral local ports");
        assert_eq!(arguments.quic_connections, 8);
        assert!(
            parse(&["--quic-connections", "2", "--local-bind", "127.0.0.1:53000",])
                .is_ok()
        );
        assert!(parse(&["--quic-connections", "0"]).is_err());
        assert!(parse(&["--quic-connections", "65"]).is_err());
        assert!(
            parse(&[
                "--quic-connections",
                "2",
                "--endpoint-mode",
                "per-connection",
                "--local-bind",
                "127.0.0.1:53000",
            ])
            .is_err()
        );
        assert!(parse(&["--endpoint-mode", "unknown"]).is_err());
    }

    #[test]
    fn rejects_non_loopback_listener() {
        assert!(parse(&["--listen", "0.0.0.0:59901"]).is_err());
    }
}
