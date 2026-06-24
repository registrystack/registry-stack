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
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;
use tower::ServiceExt;
use tracing::{debug, warn};

use crate::config::ServerConfig;

#[derive(Debug, Clone, Copy)]
pub struct ServeLimits {
    pub http1_header_read_timeout: Duration,
    pub http2_keep_alive_interval: Duration,
    pub max_connections: usize,
}

impl ServeLimits {
    #[must_use]
    pub fn from_config(config: &ServerConfig) -> Self {
        Self {
            http1_header_read_timeout: config.http1_header_read_timeout,
            http2_keep_alive_interval: config.http1_header_read_timeout,
            max_connections: config.max_connections,
        }
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
