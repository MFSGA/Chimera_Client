use std::convert::Infallible;

use anyhow::Result;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, StreamBody};
use hyper::body::Incoming;
use hyper::{body::Frame, Request, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

#[tokio::main]
async fn main() -> Result<()> {
    let addr = "127.0.0.1:3000";
    let uri = "http://127.0.0.1:3000/xhttp/"; // stream-one

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

    let (tx, rx) =
        mpsc::channel::<std::result::Result<Frame<Bytes>, Infallible>>(32);
    let req_body: BoxBody<Bytes, Infallible> =
        StreamBody::new(ReceiverStream::new(rx)).boxed();

    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .version(Version::HTTP_2)
        .header("content-type", "application/octet-stream")
        .body(req_body)?;

    let resp = sender.send_request(req).await?;
    println!("stream-one connected. type and press Enter; Ctrl-D to finish.\n");

    let mut resp_body: Incoming = resp.into_body();
    let mut stdout = io::stdout();
    let reader_task = tokio::spawn(async move {
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

    let mut stdin = io::BufReader::new(io::stdin());
    let mut line = String::new();

    loop {
        line.clear();
        let n = stdin.read_line(&mut line).await?;
        if n == 0 {
            break;
        }
        if tx
            .send(Ok(Frame::data(Bytes::from(line.clone()))))
            .await
            .is_err()
        {
            break;
        }
    }

    drop(tx);
    let _ = reader_task.await;
    Ok(())
}
