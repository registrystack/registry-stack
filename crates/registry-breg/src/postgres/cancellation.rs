// SPDX-License-Identifier: Apache-2.0

//! Cancel-on-drop ownership of one pooled session.
//!
//! A request runs its PostgreSQL work on a session it checked out of the
//! runtime pool. When the request is abandoned while a statement is in flight
//! (its deadline passes and the boundary drops its future), PostgreSQL keeps
//! executing that statement unless it is told to stop. Returning such a
//! session to the pool makes the next checkout wait behind it and then
//! replace it, so the abandoned backend keeps running beside a new one and
//! the session count climbs past the pool bound.
//!
//! [`QueryCancellationGuard`] owns the session for the request instead.
//! Disarmed, it hands the session back to the pool as usual. Dropped armed,
//! it cancels whatever the session is executing, waits for the session to
//! acknowledge, and only then discards it, so the pool slot stays occupied
//! until the abandoned backend has stopped working and no replacement starts
//! beside it.

use std::time::Duration;

use super::RuntimePool;

/// How long a guard waits for the cancel request and then for the cancelled
/// session to drain before it discards the session anyway.
const QUERY_CANCEL_TIMEOUT: Duration = Duration::from_secs(2);

/// Owns a pooled session for one request and stops its in-flight statement
/// when the request is abandoned. See the module documentation.
pub(crate) struct QueryCancellationGuard {
    pool: RuntimePool,
    client: Option<deadpool_postgres::Client>,
    cancel_token: tokio_postgres::CancelToken,
    armed: bool,
}

impl QueryCancellationGuard {
    pub(crate) fn new(pool: RuntimePool, client: deadpool_postgres::Client) -> Self {
        let cancel_token = client.cancel_token();
        Self {
            pool,
            client: Some(client),
            cancel_token,
            armed: true,
        }
    }

    pub(crate) fn client(&mut self) -> &mut deadpool_postgres::Client {
        self.client
            .as_mut()
            .expect("the guarded client is present while guarded")
    }

    /// Declare the session idle: dropping the guard now returns it to the
    /// pool without a cancellation.
    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }

    /// Cancel the in-flight statement, wait for the session to drain, and
    /// discard it before returning. The work runs on its own task, so a
    /// caller abandoned while it waits still has the session stopped.
    pub(crate) async fn cancel_and_discard(&mut self) {
        self.armed = false;
        if let Some(client) = self.client.take() {
            if let Some(stopping) =
                stop_in_background(self.pool.clone(), self.cancel_token.clone(), client)
            {
                let _ = stopping.await;
            }
        }
    }
}

impl Drop for QueryCancellationGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Some(client) = self.client.take() {
            let _ = stop_in_background(self.pool.clone(), self.cancel_token.clone(), client);
        }
    }
}

/// Stop `client` on a task of its own and return that task. Without a
/// runtime nothing can send the cancel request, so the session is discarded
/// at once; it is never returned to the pool either way.
fn stop_in_background(
    pool: RuntimePool,
    token: tokio_postgres::CancelToken,
    client: deadpool_postgres::Client,
) -> Option<tokio::task::JoinHandle<()>> {
    let session = Discarded {
        pool,
        client: Some(client),
    };
    let runtime = tokio::runtime::Handle::try_current().ok()?;
    Some(runtime.spawn(stop_and_discard(session, token)))
}

/// A session on its way out of the pool. However the task holding it ends,
/// finished, cancelled at runtime shutdown, or panicking, dropping it
/// discards the session, so its pool slot is released only then and the
/// session is never reused.
struct Discarded {
    pool: RuntimePool,
    client: Option<deadpool_postgres::Client>,
}

impl Drop for Discarded {
    fn drop(&mut self) {
        if let Some(client) = self.client.take() {
            self.pool.discard(client);
        }
    }
}

/// Ask PostgreSQL to cancel what the session is executing, then wait until
/// the session has answered everything queued on it, before it is discarded.
///
/// The session is discarded even when it drains cleanly: the cancel request
/// travels on its own connection and may land on whatever the session runs
/// next, so a cancelled session is never reused.
async fn stop_and_discard(session: Discarded, token: tokio_postgres::CancelToken) {
    let _ = tokio::time::timeout(QUERY_CANCEL_TIMEOUT, session.pool.cancel_query(token)).await;
    if let Some(client) = &session.client {
        // The empty query is answered only after every request queued before
        // it, including the cancelled statement and the rollback its dropped
        // transaction queued, so its answer means the backend is idle.
        let _ = tokio::time::timeout(QUERY_CANCEL_TIMEOUT, client.simple_query("")).await;
    }
}
