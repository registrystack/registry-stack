// SPDX-License-Identifier: Apache-2.0

//! Revoking, off the request path, the refresh tokens of sessions that end
//! without a sign-out: expiry, idle expiry, eviction, a refused renewal.
//!
//! The store and the check hand tokens to a bounded queue and never wait for
//! the issuer. A full queue or a failed revocation is logged in fixed text and
//! counted, never hidden.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use crate::grants::{Grants, RefreshToken};

/// How many ended sessions may wait for revocation.
pub const QUEUE_CAPACITY: usize = 1024;

struct Ended {
    kind: String,
    tokens: Vec<RefreshToken>,
}

#[derive(Default)]
struct Counts {
    failed: AtomicU64,
    dropped: AtomicU64,
}

/// The sending side: where the store and the check hand a session's tokens.
#[derive(Clone)]
pub struct EndedSessions {
    sender: mpsc::Sender<Ended>,
    counts: Arc<Counts>,
}

/// The receiving side: revokes what is queued.
pub struct Revoker {
    receiver: mpsc::Receiver<Ended>,
    counts: Arc<Counts>,
}

/// A queue of `capacity` ended sessions.
#[must_use]
pub fn channel(capacity: usize) -> (EndedSessions, Revoker) {
    let (sender, receiver) = mpsc::channel(capacity);
    let counts = Arc::new(Counts::default());
    (
        EndedSessions {
            sender,
            counts: counts.clone(),
        },
        Revoker { receiver, counts },
    )
}

impl EndedSessions {
    /// Queue `tokens`, issued to a client of `kind`, for revocation. Never
    /// waits: a full queue drops them and counts the drop. Returns whether
    /// they were queued.
    pub fn revoke(&self, kind: &str, tokens: Vec<RefreshToken>) -> bool {
        if tokens.is_empty() {
            return true;
        }
        let ended = Ended {
            kind: kind.to_owned(),
            tokens,
        };
        match self.sender.try_send(ended) {
            Ok(()) => true,
            Err(TrySendError::Full(_) | TrySendError::Closed(_)) => {
                self.counts.dropped.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    "an ended session's refresh tokens could not be queued for revocation"
                );
                false
            }
        }
    }

    /// How many revocations the issuer did not confirm.
    #[must_use]
    pub fn failed(&self) -> u64 {
        self.counts.failed.load(Ordering::Relaxed)
    }

    /// How many ended sessions were not queued.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.counts.dropped.load(Ordering::Relaxed)
    }
}

impl Revoker {
    /// Revoke every queued token until every sender is gone.
    pub async fn run<G: Grants>(mut self, grants: G) {
        while let Some(ended) = self.receiver.recv().await {
            for token in &ended.tokens {
                if grants.revoke(&ended.kind, token).await.is_err() {
                    self.counts.failed.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        "an ended session's refresh token could not be revoked at the issuer"
                    );
                }
            }
        }
    }
}
