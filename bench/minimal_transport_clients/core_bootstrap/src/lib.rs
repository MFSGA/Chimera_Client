use std::{
    env,
    ffi::OsString,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    process,
};

use clash_lib::transport_bench::Client;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing_subscriber::EnvFilter;

pub type ClientFactory = fn(&Path, &str) -> anyhow::Result<Client>;

#[derive(Debug)]
struct Arguments {
    config: PathBuf,
    proxy_name: String,
    listen: SocketAddr,
    relay_mode: RelayMode,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum RelayMode {
    #[default]
    Tokio,
    ProductCopy,
    #[cfg(feature = "hysteria")]
    RawCore,
    #[cfg(feature = "hysteria")]
    RawConcrete,
    #[cfg(feature = "hysteria")]
    RawConcreteNoUdpRx,
    #[cfg(feature = "hysteria")]
    RawConcreteSocket2NoUdpRx,
}

impl Arguments {
    fn parse(
        args: impl IntoIterator<Item = OsString>,
        default_listen: SocketAddr,
    ) -> Result<Self, String> {
        let mut config = None;
        let mut proxy_name = None;
        let mut listen = default_listen;
        let mut relay_mode = RelayMode::default();
        let mut args = args.into_iter();

        while let Some(argument) = args.next() {
            match argument.to_str() {
                Some("--config" | "-c" | "-f") => {
                    config = Some(PathBuf::from(args.next().ok_or_else(|| {
                        "--config requires a file path".to_owned()
                    })?));
                }
                Some("--proxy-name") => {
                    proxy_name = Some(
                        args.next()
                            .ok_or_else(|| {
                                "--proxy-name requires a value".to_owned()
                            })?
                            .into_string()
                            .map_err(|_| "--proxy-name must be UTF-8".to_owned())?,
                    );
                }
                Some("--listen") => {
                    let address = args
                        .next()
                        .ok_or_else(|| {
                            "--listen requires a socket address".to_owned()
                        })?
                        .into_string()
                        .map_err(|_| "--listen must be UTF-8".to_owned())?;
                    listen = address.parse().map_err(|error| {
                        format!("invalid --listen address: {error}")
                    })?;
                }
                Some("--relay-mode") => {
                    let available_modes = if cfg!(feature = "hysteria") {
                        "tokio, product-copy, raw-core, raw-concrete, raw-concrete-no-udp-rx, or raw-concrete-socket2-no-udp-rx"
                    } else {
                        "tokio or product-copy"
                    };
                    let mode = args
                        .next()
                        .ok_or_else(|| {
                            format!(
                                "--relay-mode requires one of: {available_modes}"
                            )
                        })?
                        .into_string()
                        .map_err(|_| "--relay-mode must be UTF-8".to_owned())?;
                    relay_mode = match mode.as_str() {
                        "tokio" => RelayMode::Tokio,
                        "product-copy" => RelayMode::ProductCopy,
                        #[cfg(feature = "hysteria")]
                        "raw-core" => RelayMode::RawCore,
                        #[cfg(feature = "hysteria")]
                        "raw-concrete" => RelayMode::RawConcrete,
                        #[cfg(feature = "hysteria")]
                        "raw-concrete-no-udp-rx" => RelayMode::RawConcreteNoUdpRx,
                        #[cfg(feature = "hysteria")]
                        "raw-concrete-socket2-no-udp-rx" => {
                            RelayMode::RawConcreteSocket2NoUdpRx
                        }
                        _ => {
                            return Err(format!(
                                "--relay-mode must be one of: {available_modes}"
                            ));
                        }
                    };
                }
                _ => {
                    return Err(format!(
                        "unknown argument {}; expected --config, --proxy-name, --listen, or --relay-mode",
                        argument.to_string_lossy()
                    ));
                }
            }
        }

        let config = config.ok_or_else(|| "--config is required".to_owned())?;
        let proxy_name =
            proxy_name.ok_or_else(|| "--proxy-name is required".to_owned())?;
        if !listen.ip().is_loopback() {
            return Err(
                "--listen must use a loopback address for the unauthenticated benchmark SOCKS bridge"
                    .to_owned(),
            );
        }
        Ok(Self {
            config,
            proxy_name,
            listen,
            relay_mode,
        })
    }
}

/// Start the selected production handler behind a small numeric-only SOCKS5
/// listener. The bridge intentionally skips Chimera's full runtime startup.
pub fn run_or_exit(factory: ClientFactory, default_listen: SocketAddr) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("error"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();

    if let Err(error) = run(factory, default_listen) {
        eprintln!("transport benchmark client failed: {error:#}");
        process::exit(1);
    }
}

fn run(factory: ClientFactory, default_listen: SocketAddr) -> anyhow::Result<()> {
    let arguments = Arguments::parse(env::args_os().skip(1), default_listen)
        .map_err(anyhow::Error::msg)?;
    if !arguments.config.is_file() {
        anyhow::bail!(
            "configuration file does not exist: {}",
            arguments.config.display()
        );
    }

    let client = factory(&arguments.config, &arguments.proxy_name)?;
    #[cfg(feature = "hysteria")]
    if matches!(
        arguments.relay_mode,
        RelayMode::RawConcreteNoUdpRx | RelayMode::RawConcreteSocket2NoUdpRx
    ) {
        client.set_hysteria_udp_receive_task_for_bench(false)?;
    }
    #[cfg(feature = "hysteria")]
    if arguments.relay_mode == RelayMode::RawConcreteSocket2NoUdpRx {
        client.set_hysteria_socket2_abstract_socket_for_bench(true)?;
    }
    eprintln!("benchmark relay mode: {}", arguments.relay_mode);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(serve(arguments.listen, client, arguments.relay_mode))?;
    Ok(())
}

async fn serve(
    listen: SocketAddr,
    client: Client,
    relay_mode: RelayMode,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    eprintln!("minimal transport SOCKS5 listener ready on {listen}");
    loop {
        let (stream, _) = listener.accept().await?;
        let client = client.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, client, relay_mode).await {
                eprintln!("minimal transport SOCKS5 connection failed: {error}");
            }
        });
    }
}

async fn handle_connection(
    mut client_stream: TcpStream,
    client: Client,
    relay_mode: RelayMode,
) -> io::Result<()> {
    let source = client_stream.peer_addr()?;
    let destination = match read_connect_request(&mut client_stream).await {
        Ok(destination) => destination,
        Err(error) => {
            let _ = write_reply(&mut client_stream, 1).await;
            return Err(error);
        }
    };
    match relay_mode {
        RelayMode::Tokio => {
            let mut outbound = match client.connect_tcp(source, destination).await {
                Ok(outbound) => outbound,
                Err(error) => {
                    let _ = write_reply(&mut client_stream, 1).await;
                    return Err(error);
                }
            };
            write_reply(&mut client_stream, 0).await?;
            tokio::io::copy_bidirectional_with_sizes(
                &mut client_stream,
                &mut outbound,
                64 * 1024,
                64 * 1024,
            )
            .await?;
            Ok(())
        }
        RelayMode::ProductCopy => {
            let outbound = match client.connect_tcp(source, destination).await {
                Ok(outbound) => outbound,
                Err(error) => {
                    let _ = write_reply(&mut client_stream, 1).await;
                    return Err(error);
                }
            };
            write_reply(&mut client_stream, 0).await?;
            client
                .copy_tcp_with_product_tracking(
                    client_stream,
                    outbound,
                    source,
                    destination,
                    64 * 1024,
                )
                .await
        }
        #[cfg(feature = "hysteria")]
        RelayMode::RawCore => {
            let mut outbound = match client
                .connect_tcp_raw_hysteria_for_bench(source, destination)
                .await
            {
                Ok(outbound) => outbound,
                Err(error) => {
                    let _ = write_reply(&mut client_stream, 1).await;
                    return Err(error);
                }
            };
            write_reply(&mut client_stream, 0).await?;
            tokio::io::copy_bidirectional_with_sizes(
                &mut client_stream,
                &mut outbound,
                64 * 1024,
                64 * 1024,
            )
            .await?;
            Ok(())
        }
        #[cfg(feature = "hysteria")]
        RelayMode::RawConcrete => {
            let mut outbound = match client
                .connect_tcp_concrete_hysteria_for_bench(source, destination)
                .await
            {
                Ok(outbound) => outbound,
                Err(error) => {
                    let _ = write_reply(&mut client_stream, 1).await;
                    return Err(error);
                }
            };
            write_reply(&mut client_stream, 0).await?;
            tokio::io::copy_bidirectional_with_sizes(
                &mut client_stream,
                &mut outbound,
                64 * 1024,
                64 * 1024,
            )
            .await?;
            Ok(())
        }
        #[cfg(feature = "hysteria")]
        RelayMode::RawConcreteNoUdpRx | RelayMode::RawConcreteSocket2NoUdpRx => {
            let mut outbound = match client
                .connect_tcp_concrete_hysteria_for_bench(source, destination)
                .await
            {
                Ok(outbound) => outbound,
                Err(error) => {
                    let _ = write_reply(&mut client_stream, 1).await;
                    return Err(error);
                }
            };
            write_reply(&mut client_stream, 0).await?;
            tokio::io::copy_bidirectional_with_sizes(
                &mut client_stream,
                &mut outbound,
                64 * 1024,
                64 * 1024,
            )
            .await?;
            Ok(())
        }
    }
}

impl std::fmt::Display for RelayMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tokio => f.write_str("tokio"),
            Self::ProductCopy => f.write_str("product-copy"),
            #[cfg(feature = "hysteria")]
            Self::RawCore => f.write_str("raw-core"),
            #[cfg(feature = "hysteria")]
            Self::RawConcrete => f.write_str("raw-concrete"),
            #[cfg(feature = "hysteria")]
            Self::RawConcreteNoUdpRx => f.write_str("raw-concrete-no-udp-rx"),
            #[cfg(feature = "hysteria")]
            Self::RawConcreteSocket2NoUdpRx => {
                f.write_str("raw-concrete-socket2-no-udp-rx")
            }
        }
    }
}

async fn read_connect_request(stream: &mut TcpStream) -> io::Result<SocketAddr> {
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
    if request[0] != 5 || request[2] != 0 || request[1] != 1 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SOCKS CONNECT with a valid reserved byte is required",
        ));
    }

    let ip = match request[3] {
        1 => {
            let mut octets = [0; 4];
            stream.read_exact(&mut octets).await?;
            std::net::IpAddr::V4(Ipv4Addr::from(octets))
        }
        4 => {
            let mut octets = [0; 16];
            stream.read_exact(&mut octets).await?;
            std::net::IpAddr::V6(Ipv6Addr::from(octets))
        }
        3 => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "benchmark SOCKS bridge accepts numeric IP destinations only",
            ));
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
    Ok(SocketAddr::new(ip, u16::from_be_bytes(port)))
}

async fn write_reply(stream: &mut TcpStream, reply: u8) -> io::Result<()> {
    stream.write_all(&[5, reply, 0, 1, 0, 0, 0, 0, 0, 0]).await
}

#[cfg(test)]
mod tests {
    use super::{Arguments, RelayMode};
    use std::{ffi::OsString, net::SocketAddr};

    fn parse_with_listen(listen: Option<&str>) -> Result<Arguments, String> {
        let mut args = vec![
            OsString::from("--config"),
            OsString::from("benchmark.yaml"),
            OsString::from("--proxy-name"),
            OsString::from("bench"),
        ];
        if let Some(listen) = listen {
            args.push(OsString::from("--listen"));
            args.push(OsString::from(listen));
        }
        Arguments::parse(args, "127.0.0.1:1080".parse().unwrap())
    }

    #[test]
    fn relay_mode_defaults_to_tokio_and_selects_enabled_paths() {
        let default = parse_with_listen(None).expect("default args should parse");
        assert_eq!(default.relay_mode, RelayMode::Tokio);

        let args = [
            "--config",
            "benchmark.yaml",
            "--proxy-name",
            "bench",
            "--relay-mode",
            "product-copy",
        ]
        .map(OsString::from);
        let product = Arguments::parse(args, "127.0.0.1:1080".parse().unwrap())
            .expect("product-copy mode should parse");
        assert_eq!(product.relay_mode, RelayMode::ProductCopy);

        #[cfg(feature = "hysteria")]
        let raw_core = [
            "--config",
            "benchmark.yaml",
            "--proxy-name",
            "bench",
            "--relay-mode",
            "raw-core",
        ]
        .map(OsString::from);
        #[cfg(feature = "hysteria")]
        let raw_core = Arguments::parse(raw_core, "127.0.0.1:1080".parse().unwrap())
            .expect("raw-core mode should parse");
        #[cfg(feature = "hysteria")]
        assert_eq!(raw_core.relay_mode, RelayMode::RawCore);

        #[cfg(feature = "hysteria")]
        let raw_concrete = [
            "--config",
            "benchmark.yaml",
            "--proxy-name",
            "bench",
            "--relay-mode",
            "raw-concrete",
        ]
        .map(OsString::from);
        #[cfg(feature = "hysteria")]
        let raw_concrete =
            Arguments::parse(raw_concrete, "127.0.0.1:1080".parse().unwrap())
                .expect("raw-concrete mode should parse");
        #[cfg(feature = "hysteria")]
        assert_eq!(raw_concrete.relay_mode, RelayMode::RawConcrete);

        #[cfg(feature = "hysteria")]
        let raw_concrete_no_udp_rx = [
            "--config",
            "benchmark.yaml",
            "--proxy-name",
            "bench",
            "--relay-mode",
            "raw-concrete-no-udp-rx",
        ]
        .map(OsString::from);
        #[cfg(feature = "hysteria")]
        let raw_concrete_no_udp_rx = Arguments::parse(
            raw_concrete_no_udp_rx,
            "127.0.0.1:1080".parse().unwrap(),
        )
        .expect("raw-concrete-no-udp-rx mode should parse");
        #[cfg(feature = "hysteria")]
        assert_eq!(
            raw_concrete_no_udp_rx.relay_mode,
            RelayMode::RawConcreteNoUdpRx
        );

        #[cfg(feature = "hysteria")]
        let raw_concrete_socket2_no_udp_rx = [
            "--config",
            "benchmark.yaml",
            "--proxy-name",
            "bench",
            "--relay-mode",
            "raw-concrete-socket2-no-udp-rx",
        ]
        .map(OsString::from);
        #[cfg(feature = "hysteria")]
        let raw_concrete_socket2_no_udp_rx = Arguments::parse(
            raw_concrete_socket2_no_udp_rx,
            "127.0.0.1:1080".parse().unwrap(),
        )
        .expect("raw-concrete-socket2-no-udp-rx mode should parse");
        #[cfg(feature = "hysteria")]
        assert_eq!(
            raw_concrete_socket2_no_udp_rx.relay_mode,
            RelayMode::RawConcreteSocket2NoUdpRx
        );
    }

    #[cfg(not(feature = "hysteria"))]
    #[test]
    fn raw_core_error_lists_only_modes_enabled_in_this_profile() {
        let args = [
            "--config",
            "benchmark.yaml",
            "--proxy-name",
            "bench",
            "--relay-mode",
            "raw-core",
        ]
        .map(OsString::from);
        let error = Arguments::parse(args, "127.0.0.1:1080".parse().unwrap())
            .expect_err("raw-core requires the HY2 feature");
        assert_eq!(error, "--relay-mode must be one of: tokio or product-copy");
    }

    #[test]
    fn default_listener_is_loopback() {
        let arguments =
            parse_with_listen(None).expect("default listener should parse");
        assert_eq!(
            arguments.listen,
            "127.0.0.1:1080".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn accepts_ipv4_and_ipv6_loopback_listeners() {
        for listen in ["127.0.0.2:1080", "[::1]:1080"] {
            assert!(parse_with_listen(Some(listen)).is_ok(), "{listen}");
        }
    }

    #[test]
    fn rejects_non_loopback_listeners() {
        for listen in ["0.0.0.0:1080", "192.0.2.1:1080", "[::]:1080"] {
            let error = parse_with_listen(Some(listen))
                .expect_err("non-loopback listener must be rejected");
            assert!(error.contains("loopback"), "{error}");
        }
    }
}
