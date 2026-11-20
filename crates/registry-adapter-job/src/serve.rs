// SPDX-License-Identifier: Apache-2.0

//! Serving with a bounded graceful shutdown, shared by the job host's
//! listeners.
//!
//! axum's graceful shutdown waits for every accepted connection, and a client
//! that sends a partial request head never finishes one. Each listener
//! therefore gives its connections a deadline once shutdown starts.

use std::future::Future;
use std::time::Duration;

/// Once shutdown starts, a listener gives every accepted connection ten
/// seconds to drain before it cancels the server.
pub const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// How a listener ended without a clean shutdown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServeEnd {
    /// The server failed while serving or while starting its shutdown.
    Serve,
    /// Connections were still open when the shutdown deadline passed.
    ShutdownTimeout,
}

/// Serve `router` on `listener` until `shutdown` resolves, then wait at most
/// `shutdown_timeout` for open connections to drain.
///
/// # Errors
///
/// A serving fault, or connections that outlive the deadline.
pub async fn serve_with_shutdown_timeout(
    listener: tokio::net::TcpListener,
    router: axum::Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
    shutdown_timeout: Duration,
) -> Result<(), ServeEnd> {
    let (shutdown_started, shutdown_started_rx) = tokio::sync::oneshot::channel();
    let graceful_shutdown = async move {
        shutdown.await;
        let _ = shutdown_started.send(());
    };
    let server = std::future::IntoFuture::into_future(
        axum::serve(listener, router).with_graceful_shutdown(graceful_shutdown),
    );
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => result.map_err(|_| ServeEnd::Serve),
        started = shutdown_started_rx => {
            started.map_err(|_| ServeEnd::Serve)?;
            tokio::time::timeout(shutdown_timeout, &mut server)
                .await
                .map_err(|_| ServeEnd::ShutdownTimeout)?
                .map_err(|_| ServeEnd::Serve)
        }
    }
}
