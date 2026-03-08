use std::convert::Infallible;

use anyhow::Result;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::{Method, Request, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<()> {
    let addr = "127.0.0.1:3000";
    let sid = Uuid::new_v4().to_string();

    let down_uri = format!("http://127.0.0.1:3000/xhttp/{sid}");
    let base_up = format!("http://127.0.0.1:3000/xhttp/{sid}");

    let tcp = TcpStream::connect(addr).await?;
    let io = TokioIo::new(tcp);
    let exec = TokioExecutor::new();

    let (mut sender, conn) =
        hyper::client::conn::http2::handshake::<_, _, BoxBody<Bytes, Infallible>>(
            exec, io,
        )
        .await?;

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            eprintln!("h2 conn driver error: {e:?}");
        }
    });

    // 1) Open downlink GET (stream-down)
    let get_req = Request::builder()
        .method(Method::GET)
        .uri(&down_uri)
        .version(Version::HTTP_2)
        .body(Empty::<Bytes>::new().boxed())?;

    let resp = sender.send_request(get_req).await?;
    println!("split connected. sessionId={sid}");
    println!("downlink GET: {down_uri}");
    println!("uplink POST: {base_up}/<seq>\n");
    println!("type lines and press Enter; Ctrl-D to finish.\n");

    // Read downlink frames -> stdout
    let mut resp_body: Incoming = resp.into_body();
    let mut stdout = io::stdout();
    tokio::spawn(async move {
        while let Some(frame_res) = resp_body.frame().await {
            match frame_res {
                Ok(frame) => {
                    if let Some(data) = frame.data_ref() {
                        let _ = stdout.write_all(data).await;
                        let _ = stdout.flush().await;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // 2) stdin -> packet-up POSTs
    let mut stdin = io::BufReader::new(io::stdin());
    let mut line = String::new();
    let mut seq: u64 = 0;

    loop {
        line.clear();
        let n = stdin.read_line(&mut line).await?;
        if n == 0 {
            break;
        }

        let up_uri = format!("{base_up}/{seq}");
        let body: BoxBody<Bytes, Infallible> =
            Full::new(Bytes::from(line.clone())).boxed();

        let post_req = Request::builder()
            .method(Method::POST)
            .uri(&up_uri)
            .version(Version::HTTP_2)
            .header("content-type", "application/octet-stream")
            .body(body)?;

        let resp = sender.send_request(post_req).await?;
        if !resp.status().is_success() {
            eprintln!("POST seq={seq} failed: status={}", resp.status());
        }

        seq += 1;
    }

    Ok(())
}
