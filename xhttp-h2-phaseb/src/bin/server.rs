use std::{convert::Infallible, sync::Arc};

use anyhow::Result;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, StreamBody};
use hyper::body::Incoming;
use hyper::{body::Frame, Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tokio_stream::wrappers::ReceiverStream;

use xhttp_h2_phaseb::proto::meta::{extract_meta_path, normalize_base_path};
use xhttp_h2_phaseb::session::store::SessionStore;

const MAX_EACH_POST_BYTES: usize = 1_000_000; // Xray default scMaxEachPostBytes
const MAX_BUFFERED_POSTS: usize = 30; // Xray default scMaxBufferedPosts
const SESSION_TTL_SECS: u64 = 30; // Xray default TTL

#[derive(Clone)]
struct State {
    base_path: String,
    sessions: SessionStore,
}

#[tokio::main]
async fn main() -> Result<()> {
    let addr = "127.0.0.1:3000";
    let state = Arc::new(State {
        base_path: normalize_base_path("/xhttp/".to_string()),
        sessions: SessionStore::new(
            Duration::from_secs(SESSION_TTL_SECS),
            MAX_BUFFERED_POSTS,
        ),
    });

    println!(
        "H2C server listening on {addr}, base_path={}, ttl={}s",
        state.base_path, SESSION_TTL_SECS
    );

    let lis = TcpListener::bind(addr).await?;
    loop {
        let (tcp, peer) = lis.accept().await?;
        let io = TokioIo::new(tcp);
        let st = state.clone();

        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req| handle(req, st.clone()));
            let builder = auto::Builder::new(TokioExecutor::new()).http2_only();

            if let Err(e) = builder.serve_connection(io, svc).await {
                eprintln!("[{peer}] serve_connection error: {e:?}");
            }
        });
    }
}

async fn handle(
    req: Request<Incoming>,
    state: Arc<State>,
) -> std::result::Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
    let path = req.uri().path().to_string();

    if !path.starts_with(&state.base_path) {
        return Ok(simple(StatusCode::NOT_FOUND));
    }

    let (sid, seq) = extract_meta_path(&path, &state.base_path);

    match *req.method() {
        Method::GET => {
            if let Some(sid) = sid {
                Ok(handle_stream_down(state, sid).await)
            } else {
                Ok(simple(StatusCode::METHOD_NOT_ALLOWED))
            }
        }
        Method::POST => {
            if sid.is_none() {
                Ok(handle_stream_one(req).await)
            } else {
                Ok(handle_packet_up(req, state, sid.unwrap(), seq).await)
            }
        }
        _ => Ok(simple(StatusCode::METHOD_NOT_ALLOWED)),
    }
}

async fn handle_stream_one(
    req: Request<Incoming>,
) -> Response<BoxBody<Bytes, Infallible>> {
    // stream-one echo: POST body frames => response body frames
    let (tx, rx) =
        mpsc::channel::<std::result::Result<Frame<Bytes>, Infallible>>(32);

    let mut body = req.into_body();
    tokio::spawn(async move {
        while let Some(frame_res) = body.frame().await {
            match frame_res {
                Ok(frame) => {
                    if let Some(data) = frame.data_ref() {
                        if tx.send(Ok(Frame::data(data.clone()))).await.is_err() {
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .header("cache-control", "no-store")
        .header("x-accel-buffering", "no")
        .header("content-type", "application/octet-stream")
        .body(StreamBody::new(ReceiverStream::new(rx)).boxed())
        .unwrap()
}

async fn handle_stream_down(
    state: Arc<State>,
    sid: String,
) -> Response<BoxBody<Bytes, Infallible>> {
    let session = state.sessions.get_or_create(&sid);
    state.sessions.mark_fully_connected(&sid);

    // Pump UploadQueue -> response stream via channel.
    // When client disconnects, send fails and we cleanup the session.
    let (tx, rx) =
        mpsc::channel::<std::result::Result<Frame<Bytes>, Infallible>>(32);
    let store = state.sessions.clone();
    let sid2 = sid.clone();
    let queue = session.queue.clone();

    tokio::spawn(async move {
        loop {
            match queue.read_chunk().await {
                Some(bytes) => {
                    if tx.send(Ok(Frame::data(bytes))).await.is_err() {
                        break;
                    }
                }
                None => break,
            }
        }
        let _ = store.remove(&sid2).await;
    });

    Response::builder()
        .status(StatusCode::OK)
        .header("cache-control", "no-store")
        .header("x-accel-buffering", "no")
        .header("content-type", "application/octet-stream")
        .body(StreamBody::new(ReceiverStream::new(rx)).boxed())
        .unwrap()
}

async fn handle_packet_up(
    req: Request<Incoming>,
    state: Arc<State>,
    sid: String,
    seq: Option<String>,
) -> Response<BoxBody<Bytes, Infallible>> {
    let session = state.sessions.get_or_create(&sid);

    let seq = match seq.and_then(|s| s.parse::<u64>().ok()) {
        Some(v) => v,
        None => return simple(StatusCode::BAD_REQUEST),
    };

    let collected = match req.into_body().collect().await {
        Ok(c) => c,
        Err(_) => return simple(StatusCode::BAD_REQUEST),
    };
    let payload = collected.to_bytes();

    if payload.len() > MAX_EACH_POST_BYTES {
        return simple(StatusCode::PAYLOAD_TOO_LARGE);
    }

    match session.queue.push_packet(seq, payload).await {
        Ok(()) => simple(StatusCode::OK),
        Err(_) => simple(StatusCode::CONFLICT),
    }
}

fn simple(code: StatusCode) -> Response<BoxBody<Bytes, Infallible>> {
    Response::builder()
        .status(code)
        .body(Empty::<Bytes>::new().boxed())
        .unwrap()
}
