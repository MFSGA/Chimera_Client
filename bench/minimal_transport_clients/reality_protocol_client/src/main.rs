use std::{
    env, io,
    net::{IpAddr, SocketAddr},
    process,
    sync::Arc,
};

use anyhow::{Context, bail};
use chimera_reality_core::{
    AnyStream, RealityClient, TargetAddr, VlessStream, decode_public_key,
    decode_short_id,
};
#[cfg(feature = "vision")]
use chimera_reality_core::{SplicableTlsStream, VisionOptions, VisionStream};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[derive(Debug)]
struct Arguments {
    server: SocketAddr,
    server_name: String,
    public_key: String,
    short_id: String,
    uuid: String,
    listen: SocketAddr,
    alpn_protocols: Vec<String>,
    vision: bool,
    x25519mlkem768: bool,
    copy_buffer_size: usize,
}

impl Arguments {
    fn parse(args: impl IntoIterator<Item = String>) -> anyhow::Result<Self> {
        let mut server = None;
        let mut server_name = None;
        let mut public_key = env::var("REALITY_PUBLIC_KEY").ok();
        let mut short_id = env::var("REALITY_SHORT_ID").unwrap_or_default();
        let mut uuid = env::var("REALITY_UUID").ok();
        let mut listen: SocketAddr = "127.0.0.1:59902".parse()?;
        let mut alpn_protocols = Vec::new();
        let mut vision = cfg!(feature = "vision");
        let mut x25519mlkem768 = false;
        let mut copy_buffer_size = 64 * 1024;
        let mut args = args.into_iter();

        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--server" => {
                    server = Some(required_value(&mut args, &argument)?.parse()?);
                }
                "--server-name" | "--sni" => {
                    server_name = Some(required_value(&mut args, &argument)?);
                }
                "--public-key" | "--pubkey" => {
                    public_key = Some(required_value(&mut args, &argument)?);
                }
                "--short-id" => {
                    short_id = required_value(&mut args, &argument)?;
                }
                "--uuid" => {
                    uuid = Some(required_value(&mut args, &argument)?);
                }
                "--listen" => {
                    listen = required_value(&mut args, &argument)?.parse()?;
                }
                "--alpn" => {
                    alpn_protocols.push(required_value(&mut args, &argument)?);
                }
                "--flow" => {
                    vision = match required_value(&mut args, &argument)?.as_str() {
                        "vision" if cfg!(feature = "vision") => true,
                        "vision" => {
                            bail!(
                                "--flow vision requires building with the vision feature"
                            )
                        }
                        "none" => false,
                        value => bail!("unsupported --flow value: {value}"),
                    };
                }
                "--x25519mlkem768" => x25519mlkem768 = true,
                "--copy-buffer-size" => {
                    copy_buffer_size =
                        required_value(&mut args, &argument)?.parse()?;
                    if !(4096..=1024 * 1024).contains(&copy_buffer_size) {
                        bail!(
                            "--copy-buffer-size must be between 4096 and 1048576 bytes"
                        );
                    }
                }
                "--help" | "-h" => {
                    println!(
                        "Required: --server IP:PORT --server-name SNI. Set REALITY_PUBLIC_KEY and REALITY_UUID in the environment; optional REALITY_SHORT_ID. Other options: repeat --alpn VALUE to configure ALPN (default: h2,http/1.1), --flow vision|none, --x25519mlkem768, --copy-buffer-size BYTES (4096..1048576, default 65536), --listen LOOPBACK:PORT."
                    );
                    process::exit(0);
                }
                _ => bail!("unknown argument: {argument}"),
            }
        }

        if !listen.ip().is_loopback() {
            bail!(
                "--listen must use a loopback address; the benchmark SOCKS5 listener has no authentication"
            );
        }

        let public_key = public_key.context("--public-key is required")?;
        decode_public_key(&public_key).context("invalid REALITY public key")?;
        decode_short_id(&short_id).context("invalid REALITY short ID")?;
        let uuid = uuid.context("--uuid is required")?;
        uuid::Uuid::parse_str(&uuid).context("invalid VLESS UUID")?;

        Ok(Self {
            server: server
                .context("--server is required and must be numeric IP:PORT")?,
            server_name: server_name.context("--server-name is required")?,
            public_key,
            short_id,
            uuid,
            listen,
            alpn_protocols,
            vision,
            x25519mlkem768,
            copy_buffer_size,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let arguments = Arguments::parse(env::args().skip(1))?;
    let public_key = decode_public_key(&arguments.public_key)?;
    let short_id = decode_short_id(&arguments.short_id)?;
    let client = Arc::new(
        RealityClient::new_with_alpn(
            public_key,
            short_id,
            arguments.server_name.clone(),
            Vec::new(),
            arguments.alpn_protocols.clone(),
        )
        .with_x25519mlkem768(arguments.x25519mlkem768),
    );

    eprintln!(
        "REALITY protocol core ready: server={}, sni={}, flow={}, copy_buffer_size={}",
        arguments.server,
        arguments.server_name,
        if arguments.vision { "vision" } else { "none" },
        arguments.copy_buffer_size,
    );
    serve(arguments, client).await
}

async fn serve(
    arguments: Arguments,
    client: Arc<RealityClient>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(arguments.listen).await?;
    eprintln!("REALITY core SOCKS5 listener ready on {}", arguments.listen);
    loop {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let server = arguments.server;
        let uuid = arguments.uuid.clone();
        let vision = arguments.vision;
        let copy_buffer_size = arguments.copy_buffer_size;
        let client = client.clone();
        tokio::spawn(async move {
            if let Err(error) =
                handle_socks(stream, server, &uuid, vision, copy_buffer_size, client)
                    .await
            {
                eprintln!("REALITY core SOCKS5 stream failed: {error}");
            }
        });
    }
}

async fn handle_socks(
    mut inbound: TcpStream,
    server: SocketAddr,
    uuid: &str,
    vision: bool,
    copy_buffer_size: usize,
    client: Arc<RealityClient>,
) -> io::Result<()> {
    let destination = match read_connect_request(&mut inbound).await {
        Ok(destination) => destination,
        Err(error) => {
            let _ = write_reply(&mut inbound, 1).await;
            return Err(error);
        }
    };

    let tcp = match TcpStream::connect(server).await {
        Ok(tcp) => tcp,
        Err(error) => {
            let _ = write_reply(&mut inbound, 1).await;
            return Err(error);
        }
    };
    tcp.set_nodelay(true)?;

    #[cfg(feature = "vision")]
    let mut outbound: AnyStream = if vision {
        let read_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let write_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reality = client.handshake_stream(tcp).await?;
        let splicable = SplicableTlsStream::new(
            reality,
            Arc::clone(&read_flag),
            Arc::clone(&write_flag),
        );
        let vless = VlessStream::new(
            Box::new(splicable),
            uuid,
            &destination,
            false,
            Some("xtls-rprx-vision".to_owned()),
        )?;
        Box::new(VisionStream::new(
            Box::new(vless),
            uuid.to_owned(),
            Some(VisionOptions {
                read_flag,
                write_flag,
            }),
        )?)
    } else {
        let reality = client.handshake_stream(tcp).await?;
        let vless =
            VlessStream::new(Box::new(reality), uuid, &destination, false, None)?;
        Box::new(vless)
    };

    #[cfg(not(feature = "vision"))]
    let mut outbound: AnyStream = {
        let _ = vision;
        let reality = client.handshake_stream(tcp).await?;
        let vless =
            VlessStream::new(Box::new(reality), uuid, &destination, false, None)?;
        Box::new(vless)
    };

    write_reply(&mut inbound, 0).await?;
    tokio::io::copy_bidirectional_with_sizes(
        &mut inbound,
        &mut outbound,
        copy_buffer_size,
        copy_buffer_size,
    )
    .await?;
    Ok(())
}

async fn read_connect_request(stream: &mut TcpStream) -> io::Result<TargetAddr> {
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

    let (ip, domain) = match request[3] {
        1 => {
            let mut octets = [0; 4];
            stream.read_exact(&mut octets).await?;
            (Some(IpAddr::from(octets)), None)
        }
        4 => {
            let mut octets = [0; 16];
            stream.read_exact(&mut octets).await?;
            (Some(IpAddr::from(octets)), None)
        }
        3 => {
            let length = stream.read_u8().await? as usize;
            let mut domain = vec![0; length];
            stream.read_exact(&mut domain).await?;
            let domain = String::from_utf8(domain).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid SOCKS domain")
            })?;
            (None, Some(domain))
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported SOCKS address type",
            ));
        }
    };
    let port = stream.read_u16().await?;
    Ok(match (ip, domain) {
        (Some(ip), None) => TargetAddr::Ip(SocketAddr::new(ip, port)),
        (None, Some(domain)) => TargetAddr::Domain(domain, port),
        _ => return Err(io::Error::other("invalid SOCKS address state")),
    })
}

async fn write_reply(stream: &mut TcpStream, reply: u8) -> io::Result<()> {
    stream.write_all(&[5, reply, 0, 1, 0, 0, 0, 0, 0, 0]).await
}

#[cfg(test)]
mod tests {
    use super::Arguments;

    const REQUIRED_ARGS: [&str; 8] = [
        "--server",
        "127.0.0.1:443",
        "--server-name",
        "example.com",
        "--public-key",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "--uuid",
        "b831381d-6324-4d53-ad4f-8cda48b30811",
    ];

    fn parse(args: &[&str]) -> anyhow::Result<Arguments> {
        Arguments::parse(args.iter().map(|arg| (*arg).to_owned()))
    }

    #[test]
    fn accepts_repeated_alpn_values() {
        let args = [
            REQUIRED_ARGS.as_slice(),
            &["--alpn", "h2", "--alpn", "http/1.1"],
        ]
        .concat();
        let parsed = parse(&args).unwrap();
        assert_eq!(parsed.alpn_protocols, ["h2", "http/1.1"]);
    }

    #[test]
    fn rejects_non_loopback_listener() {
        let result = parse(
            &[REQUIRED_ARGS.as_slice(), &["--listen", "0.0.0.0:1234"]].concat(),
        );
        assert!(result.is_err());
    }
}
