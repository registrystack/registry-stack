// SPDX-License-Identifier: Apache-2.0
//! HTTP serve boundary with transport-level limits.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::Router;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use registry_notary_core::RegistryNotaryHttpConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;
use tower::ServiceExt;
use tracing::{debug, warn};

#[derive(Debug, Clone, Copy)]
pub struct ServeLimits {
    pub http1_header_read_timeout: Duration,
    pub http2_keep_alive_interval: Duration,
    pub max_connections: usize,
}

impl ServeLimits {
    #[must_use]
    pub fn from_config(config: &RegistryNotaryHttpConfig) -> Self {
        Self {
            http1_header_read_timeout: config.http1_header_read_timeout,
            http2_keep_alive_interval: config.http1_header_read_timeout,
            max_connections: config.max_connections,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::http::StatusCode;
    use axum::routing::get;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Notify;

    #[tokio::test]
    async fn serve_listener_closes_slow_http1_headers() {
        let app = Router::new().route("/healthz", get(|| async { StatusCode::NO_CONTENT }));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener binds");
        let addr = listener.local_addr().expect("listener has local address");
        let limits = ServeLimits {
            http1_header_read_timeout: Duration::from_millis(50),
            http2_keep_alive_interval: Duration::from_millis(50),
            max_connections: 8,
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(serve_listener(listener, app, limits, async move {
            let _ = shutdown_rx.await;
        }));

        let mut stream = TcpStream::connect(addr).await.expect("connects");
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n")
            .await
            .expect("partial header writes");
        tokio::time::sleep(Duration::from_millis(150)).await;

        let mut byte = [0_u8; 1];
        let read = stream.read(&mut byte).await.expect("read completes");
        assert_eq!(read, 0, "slow header connection should be closed");

        let _ = shutdown_tx.send(());
        handle
            .await
            .expect("serve task joins")
            .expect("serve exits");
    }

    #[tokio::test]
    async fn serve_listener_max_connections_holds_excess_request_work() {
        let app = Router::new().route("/healthz", get(|| async { StatusCode::NO_CONTENT }));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener binds");
        let addr = listener.local_addr().expect("listener has local address");
        let limits = ServeLimits {
            http1_header_read_timeout: Duration::from_secs(5),
            http2_keep_alive_interval: Duration::from_secs(5),
            max_connections: 1,
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(serve_listener(listener, app, limits, async move {
            let _ = shutdown_rx.await;
        }));

        let mut held = TcpStream::connect(addr).await.expect("connect held");
        held.write_all(format!("GET /healthz HTTP/1.1\r\nHost: {addr}\r\n").as_bytes())
            .await
            .expect("partial header writes");
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut queued = TcpStream::connect(addr).await.expect("connect queued");
        queued
            .write_all(
                format!("GET /healthz HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .expect("queued request writes");

        let mut first_byte = [0_u8; 1];
        let early =
            tokio::time::timeout(Duration::from_millis(200), queued.read(&mut first_byte)).await;
        assert!(
            early.is_err(),
            "queued request received response bytes while connection cap was exhausted"
        );

        drop(held);
        let mut rest = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(2), queued.read_to_end(&mut rest))
            .await
            .expect("queued request finishes after capacity frees")
            .expect("queued response reads");
        assert!(read > 0, "queued request received a response");
        let response = String::from_utf8_lossy(&rest);
        assert!(
            response.starts_with("HTTP/1.1 204"),
            "queued request should succeed after capacity frees, got: {response}"
        );

        let _ = shutdown_tx.send(());
        handle
            .await
            .expect("serve task joins")
            .expect("serve exits");
    }

    #[tokio::test]
    async fn serve_listener_graceful_shutdown_allows_inflight_request_to_finish() {
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let app = Router::new().route(
            "/slow",
            get({
                let started = Arc::clone(&started);
                let release = Arc::clone(&release);
                move || {
                    let started = Arc::clone(&started);
                    let release = Arc::clone(&release);
                    async move {
                        started.notify_one();
                        release.notified().await;
                        StatusCode::NO_CONTENT
                    }
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener binds");
        let addr = listener.local_addr().expect("listener has local address");
        let limits = ServeLimits {
            http1_header_read_timeout: Duration::from_secs(5),
            http2_keep_alive_interval: Duration::from_secs(5),
            max_connections: 8,
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(serve_listener(listener, app, limits, async move {
            let _ = shutdown_rx.await;
        }));
        let request = tokio::spawn(async move {
            reqwest::get(format!("http://{addr}/slow"))
                .await
                .expect("request completes")
        });

        tokio::time::timeout(Duration::from_secs(2), started.notified())
            .await
            .expect("handler starts");
        let _ = shutdown_tx.send(());
        release.notify_one();

        let response = request.await.expect("request task joins");
        assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
        handle
            .await
            .expect("serve task joins")
            .expect("serve exits");
    }
}

pub async fn serve_listener<F>(
    listener: TcpListener,
    app: Router,
    limits: ServeLimits,
    shutdown: F,
) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let local_addr = listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let connection_cap = Arc::new(Semaphore::new(limits.max_connections));
    let mut tasks = JoinSet::new();
    tokio::pin!(shutdown);

    loop {
        while let Some(joined) = tasks.try_join_next() {
            if let Err(error) = joined {
                warn!(error = %error, bind = %local_addr, "http connection task failed");
            }
        }

        let permit = tokio::select! {
            biased;
            _ = &mut shutdown => {
                break;
            }
            permit = Arc::clone(&connection_cap).acquire_owned() => {
                match permit {
                    Ok(permit) => permit,
                    Err(_) => break,
                }
            }
        };
        let (stream, remote_addr) = tokio::select! {
            biased;
            _ = &mut shutdown => {
                break;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok(connection) => connection,
                    Err(error) => {
                        warn!(error = %error, bind = %local_addr, "failed to accept http connection");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                }
            }
        };
        let app = app.clone();
        let close_rx = shutdown_rx.clone();
        tasks.spawn(async move {
            let _permit = permit;
            serve_connection(stream, remote_addr, app, limits, close_rx).await;
        });
    }

    drop(shutdown_tx);
    while let Some(joined) = tasks.join_next().await {
        if let Err(error) = joined {
            warn!(error = %error, bind = %local_addr, "http connection task failed during shutdown");
        }
    }
    Ok(())
}

async fn serve_connection(
    stream: TcpStream,
    remote_addr: SocketAddr,
    app: Router,
    limits: ServeLimits,
    mut close_rx: watch::Receiver<()>,
) {
    let service = service_fn(move |req: Request<Incoming>| {
        let app = app.clone();
        async move {
            let mut req = req.map(Body::new);
            req.extensions_mut().insert(ConnectInfo(remote_addr));
            match app.oneshot(req).await {
                Ok(response) => Ok::<_, Infallible>(response),
                Err(err) => match err {},
            }
        }
    });

    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.http1_header_read_timeout)
        .keep_alive(false);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(limits.http2_keep_alive_interval)
        .keep_alive_timeout(limits.http2_keep_alive_interval);

    let io = TokioIo::new(stream);
    let conn = builder.serve_connection_with_upgrades(io, service);
    tokio::pin!(conn);
    let mut shutdown_initiated = false;

    loop {
        tokio::select! {
            result = &mut conn => {
                if let Err(error) = result {
                    debug!(error = %error, peer = %remote_addr, "http connection closed with error");
                }
                break;
            }
            _ = close_rx.changed(), if !shutdown_initiated => {
                conn.as_mut().graceful_shutdown();
                shutdown_initiated = true;
            }
        }
    }
}
