use tracing::error;

#[cfg(windows)]
pub async fn serve_ipc(
    router: axum::Router,
    path: &str,
    ready_signal: super::runner::ApiReadySignal,
) -> crate::Result<()> {
    use hyper_util::rt::TokioIo;
    use tokio::net::windows::named_pipe;
    use tower::Service as _;
    use tracing::info;

    info!("Starting API server on NamedPipe {path}");

    let server = match named_pipe::ServerOptions::new()
        .first_pipe_instance(true)
        .create(path)
    {
        Ok(server) => server,
        Err(err) => {
            let err = crate::Error::Operation(format!("Cannot create pipe {err}"));
            ready_signal.fail(err.to_string());
            return Err(err);
        }
    };

    ready_signal.ready();
    let mut server = server;
    loop {
        server
            .connect()
            .await
            .map_err(|e| crate::Error::Operation(format!("NamedPipe error: {e}")))?;
        let connected_client = server;
        server = named_pipe::ServerOptions::new().create(path).map_err(|e| {
            crate::Error::Operation(format!("Cannot create NamedPipe: {e}"))
        })?;
        let router = router.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(connected_client);
            let hyper_service = hyper::service::service_fn(move |request: _| {
                router.clone().call(request)
            });

            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, hyper_service)
                .await
            {
                error!("NamedPipe error: {}", e);
            }
        });
    }
}

#[cfg(unix)]
pub async fn serve_ipc(
    router: axum::Router,
    path: &str,
    ready_signal: super::runner::ApiReadySignal,
) -> crate::Result<()> {
    use std::{path::PathBuf, sync::Arc};

    use axum::{extract::connect_info::Connected, serve::IncomingStream};
    use tokio::net::UnixListener;
    use tracing::info;

    let path = PathBuf::from(path);

    info!("Start API server on IPC address {:?}", path);

    if let Err(e) = tokio::fs::remove_file(&path).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        let err = crate::Error::Operation(format!(
            "Cannot remove existing IPC file: {e}",
        ));
        ready_signal.fail(err.to_string());
        return Err(err);
    }

    if let Some(parent) = path.parent()
        && let Err(e) = tokio::fs::create_dir_all(parent).await
    {
        let err = crate::Error::Operation(format!("Cannot create IPC dir: {e}"));
        ready_signal.fail(err.to_string());
        return Err(err);
    }

    let uds = match UnixListener::bind(&path) {
        Ok(uds) => uds,
        Err(e) => {
            let err =
                crate::Error::Operation(format!("Cannot bind on IPC address: {e}"));
            ready_signal.fail(err.to_string());
            return Err(err);
        }
    };
    ready_signal.ready();

    #[derive(Clone, Debug)]
    #[allow(dead_code)]
    struct UdsConnectInfo {
        peer_addr: Arc<tokio::net::unix::SocketAddr>,
        peer_cred: tokio::net::unix::UCred,
    }

    impl Connected<IncomingStream<'_, UnixListener>> for UdsConnectInfo {
        fn connect_info(stream: IncomingStream<'_, UnixListener>) -> Self {
            let peer_addr = stream.io().peer_addr().unwrap();
            let peer_cred = stream.io().peer_cred().unwrap();
            Self {
                peer_addr: Arc::new(peer_addr),
                peer_cred,
            }
        }
    }

    axum::serve(
        uds,
        router.into_make_service_with_connect_info::<UdsConnectInfo>(),
    )
    .await
    .map_err(|e| {
        error!("IPC API server error: {}", e);
        crate::Error::Operation(format!("IPC API server error: {e}"))
    })
}

#[cfg(all(not(unix), not(windows)))]
pub async fn serve_ipc(
    _router: axum::Router,
    _path: &str,
    ready_signal: super::runner::ApiReadySignal,
) -> crate::Result<()> {
    error!("IPC only get supported on Unix and Windows");
    let err = crate::Error::Operation(
        "IPC only get supported on Unix and Windows".to_string(),
    );
    ready_signal.fail(err.to_string());
    Err(err)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn ipc_bind_failure_reports_readiness_error() {
        let temp = tempfile::tempdir().unwrap();
        let blocking_file = temp.path().join("not-a-directory");
        std::fs::write(&blocking_file, b"x").unwrap();
        let socket_path = blocking_file.join("api.sock");
        let (ready_tx, ready_rx) = oneshot::channel();
        let ready = super::super::runner::ApiReadySignal::new(Some(ready_tx), 1);

        let result =
            serve_ipc(axum::Router::new(), socket_path.to_str().unwrap(), ready)
                .await;

        let err = result.expect_err("invalid IPC path should fail setup");
        assert_eq!(ready_rx.await.unwrap(), Err(err.to_string()));
    }
}
