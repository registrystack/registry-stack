// SPDX-License-Identifier: Apache-2.0

//! Transfer bounds: the one in-flight byte budget that uploads, downloads,
//! and content verification share, the deadline a transfer must finish
//! within, and the body a release is streamed from.
//!
//! Every document byte the process holds for a transfer is counted against
//! one budget, so the memory a deployment needs is stated by its
//! configuration rather than by how many callers arrive at once. An upload
//! or a download that would exceed it is refused with `service.unavailable`
//! before any byte moves; a verification attempt waits for room.

use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures::Stream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

use crate::config::TransfersConfig;

/// The bytes every transfer in flight may hold at once, unless the
/// deployment ceiling is larger, in which case the budget is the ceiling so
/// one document of the largest admitted size can always move.
pub const TRANSFER_BUFFER_BYTES: u64 = 256 * 1024 * 1024;

/// The budget is counted in units of this many bytes.
const UNIT_BYTES: u64 = 1024;

/// How many bytes one released chunk carries.
const RELEASE_CHUNK_BYTES: usize = 64 * 1024;

const MEBIBYTE: u64 = 1024 * 1024;

/// The in-flight byte budget of one process.
#[derive(Clone, Debug)]
pub struct TransferBudget {
    permits: Arc<Semaphore>,
    units: u32,
}

/// Room for one transfer's bytes, returned to the budget when dropped.
#[derive(Debug)]
pub struct TransferPermit {
    _permit: OwnedSemaphorePermit,
}

impl TransferBudget {
    /// The budget of a deployment whose largest admitted document is
    /// `ceiling` bytes.
    #[must_use]
    pub fn new(ceiling: u64) -> Self {
        let total = TRANSFER_BUFFER_BYTES.max(ceiling);
        let units = u32::try_from(total.div_ceil(UNIT_BYTES)).unwrap_or(u32::MAX);
        Self {
            permits: Arc::new(Semaphore::new(units as usize)),
            units,
        }
    }

    /// The bytes the budget holds when nothing is in flight.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        u64::from(self.units) * UNIT_BYTES
    }

    /// The bytes not held by a transfer now.
    #[must_use]
    pub fn available_bytes(&self) -> u64 {
        self.permits.available_permits() as u64 * UNIT_BYTES
    }

    fn units_for(&self, length: u64) -> u32 {
        u32::try_from(length.div_ceil(UNIT_BYTES).max(1))
            .unwrap_or(u32::MAX)
            .min(self.units)
    }

    /// Room for `length` bytes now, or `None` when the budget is spent.
    #[must_use]
    pub fn try_reserve(&self, length: u64) -> Option<TransferPermit> {
        Arc::clone(&self.permits)
            .try_acquire_many_owned(self.units_for(length))
            .ok()
            .map(|permit| TransferPermit { _permit: permit })
    }

    /// Room for `length` bytes, waiting until it is free.
    pub async fn reserve(&self, length: u64) -> Option<TransferPermit> {
        Arc::clone(&self.permits)
            .acquire_many_owned(self.units_for(length))
            .await
            .ok()
            .map(|permit| TransferPermit { _permit: permit })
    }
}

/// How long one transfer may take: a floor, plus an allowance for every
/// mebibyte it carries, so a large document on a slow link is not cut off
/// while a stalled caller still lets go of its bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferDeadline {
    minimum: Duration,
    per_mebibyte: Duration,
}

impl TransferDeadline {
    #[must_use]
    pub fn new(config: &TransfersConfig) -> Self {
        Self {
            minimum: Duration::from_secs(u64::from(config.minimum_deadline_seconds.get())),
            per_mebibyte: Duration::from_secs(u64::from(config.mebibyte_allowance_seconds.get())),
        }
    }

    /// The deadline of a transfer of `length` bytes.
    #[must_use]
    pub fn for_length(&self, length: u64) -> Duration {
        let mebibytes = u32::try_from(length.div_ceil(MEBIBYTE)).unwrap_or(u32::MAX);
        self.minimum
            .saturating_add(self.per_mebibyte.saturating_mul(mebibytes))
    }
}

enum Release {
    Sending {
        bytes: Vec<u8>,
        offset: usize,
        _permit: TransferPermit,
    },
    Expired,
    Done,
}

/// The body of one release: the checked bytes, handed out in copied chunks
/// so a chunk the connection still holds never pins the whole document.
///
/// When the deadline passes before the last chunk is taken, the bytes and
/// their budget are let go at once, even while the caller reads nothing,
/// and the body ends with an error so the response is cut off rather than
/// completed short.
pub struct ReleaseBody {
    state: Arc<Mutex<Release>>,
    timer: JoinHandle<()>,
}

impl ReleaseBody {
    /// Must be called within a Tokio runtime: the deadline runs as its own
    /// task.
    #[must_use]
    pub fn new(bytes: Vec<u8>, permit: TransferPermit, deadline: Duration) -> Self {
        let state = Arc::new(Mutex::new(Release::Sending {
            bytes,
            offset: 0,
            _permit: permit,
        }));
        let expiring = Arc::clone(&state);
        let timer = tokio::spawn(async move {
            tokio::time::sleep(deadline).await;
            let mut release = expiring.lock().unwrap_or_else(PoisonError::into_inner);
            if matches!(*release, Release::Sending { .. }) {
                tracing::warn!("a document release ran out of time; its bytes were let go");
                *release = Release::Expired;
            }
        });
        Self { state, timer }
    }
}

impl Drop for ReleaseBody {
    fn drop(&mut self) {
        self.timer.abort();
    }
}

impl Stream for ReleaseBody {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut release = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let next = match &mut *release {
            Release::Sending { bytes, offset, .. } => {
                let end = bytes.len().min(*offset + RELEASE_CHUNK_BYTES);
                let chunk = Bytes::copy_from_slice(&bytes[*offset..end]);
                *offset = end;
                if end == bytes.len() {
                    *release = Release::Done;
                }
                Some(Ok(chunk))
            }
            Release::Expired => {
                *release = Release::Done;
                Some(Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "the release deadline passed",
                )))
            }
            Release::Done => None,
        };
        Poll::Ready(next)
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt as _;
    use registry_platform_yaml::BoundedU32;

    use super::*;

    #[test]
    fn the_budget_is_at_least_the_ceiling() {
        assert_eq!(TransferBudget::new(1).total_bytes(), TRANSFER_BUFFER_BYTES);
        let large = 512 * MEBIBYTE;
        assert_eq!(TransferBudget::new(large).total_bytes(), large);
    }

    #[test]
    fn a_transfer_beyond_the_remaining_budget_is_refused_until_room_returns() {
        let budget = TransferBudget::new(1);
        let held = budget.try_reserve(TRANSFER_BUFFER_BYTES - UNIT_BYTES).unwrap();
        assert!(budget.try_reserve(2 * UNIT_BYTES).is_none());
        let small = budget.try_reserve(1).unwrap();
        assert_eq!(budget.available_bytes(), 0);
        drop(held);
        drop(small);
        assert_eq!(budget.available_bytes(), TRANSFER_BUFFER_BYTES);
    }

    #[test]
    fn a_transfer_larger_than_the_budget_waits_for_the_whole_budget() {
        let budget = TransferBudget::new(1);
        let permit = budget.try_reserve(u64::MAX).unwrap();
        assert_eq!(budget.available_bytes(), 0);
        drop(permit);
    }

    #[test]
    fn the_deadline_grows_with_the_length() {
        let deadline = TransferDeadline::new(&TransfersConfig {
            minimum_deadline_seconds: BoundedU32::new(60).unwrap(),
            mebibyte_allowance_seconds: BoundedU32::new(8).unwrap(),
        });
        assert_eq!(deadline.for_length(0), Duration::from_secs(60));
        assert_eq!(deadline.for_length(1), Duration::from_secs(68));
        assert_eq!(deadline.for_length(MEBIBYTE), Duration::from_secs(68));
        assert_eq!(deadline.for_length(16 * MEBIBYTE), Duration::from_secs(188));
    }

    #[tokio::test]
    async fn a_release_hands_back_every_byte_and_returns_its_budget() {
        let budget = TransferBudget::new(1);
        let content: Vec<u8> = (0..200_000u32).map(|value| value as u8).collect();
        let permit = budget.try_reserve(content.len() as u64).unwrap();
        let mut body = ReleaseBody::new(content.clone(), permit, Duration::from_secs(60));
        let mut received = Vec::new();
        while let Some(chunk) = body.next().await {
            let chunk = chunk.unwrap();
            assert!(chunk.len() <= RELEASE_CHUNK_BYTES);
            received.extend_from_slice(&chunk);
        }
        assert_eq!(received, content);
        assert_eq!(budget.available_bytes(), TRANSFER_BUFFER_BYTES);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_release_lets_go_of_its_bytes_at_the_deadline() {
        let budget = TransferBudget::new(1);
        let content = vec![7u8; 200_000];
        let permit = budget.try_reserve(content.len() as u64).unwrap();
        let mut body = ReleaseBody::new(content, permit, Duration::from_secs(30));
        assert_eq!(body.next().await.unwrap().unwrap().len(), RELEASE_CHUNK_BYTES);
        assert!(budget.available_bytes() < TRANSFER_BUFFER_BYTES);
        tokio::time::sleep(Duration::from_secs(31)).await;
        assert_eq!(
            budget.available_bytes(),
            TRANSFER_BUFFER_BYTES,
            "the budget returns while the caller still reads nothing"
        );
        let error = body.next().await.unwrap().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(body.next().await.is_none());
    }
}
