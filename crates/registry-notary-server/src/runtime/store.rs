// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use super::*;
use std::collections::HashMap;

const BATCH_IDEMPOTENCY_RETENTION: time::Duration = time::Duration::minutes(15);

enum IdempotencyRecord {
    InFlight {
        request_hash: String,
        wake: tokio::sync::watch::Sender<bool>,
    },
    Completed {
        request_hash: String,
        response: BatchEvaluateResponse,
        expires_at: OffsetDateTime,
    },
    Failed {
        request_hash: String,
        expires_at: OffsetDateTime,
    },
}

impl IdempotencyRecord {
    fn request_hash(&self) -> &str {
        match self {
            Self::InFlight { request_hash, .. }
            | Self::Completed { request_hash, .. }
            | Self::Failed { request_hash, .. } => request_hash,
        }
    }

    fn retained_at(&self, now: OffsetDateTime) -> bool {
        match self {
            Self::InFlight { .. } => true,
            Self::Completed { expires_at, .. } | Self::Failed { expires_at, .. } => {
                *expires_at > now
            }
        }
    }
}

pub struct EvidenceStore {
    evaluations: Mutex<HashMap<String, registry_notary_core::StoredEvaluation>>,
    idempotency: Mutex<HashMap<String, IdempotencyRecord>>,
}

impl Default for EvidenceStore {
    fn default() -> Self {
        Self {
            evaluations: Mutex::new(HashMap::new()),
            idempotency: Mutex::new(HashMap::new()),
        }
    }
}

impl fmt::Debug for EvidenceStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceStore")
            .finish_non_exhaustive()
    }
}

pub(super) enum BatchIdempotencyReservation<'a> {
    Owner(BatchIdempotencyOwner<'a>),
    Replay(BatchEvaluateResponse),
}

pub(super) struct BatchIdempotencyOwner<'a> {
    store: &'a EvidenceStore,
    key: String,
    request_hash: String,
    wake: tokio::sync::watch::Sender<bool>,
    completed: bool,
}

impl BatchIdempotencyOwner<'_> {
    pub(super) fn complete(
        mut self,
        response: BatchEvaluateResponse,
    ) -> Result<BatchEvaluateResponse, EvidenceError> {
        let mut records = self
            .store
            .idempotency
            .lock()
            .expect("evidence idempotency mutex is not poisoned");
        let matches_owner = matches!(
            records.get(&self.key),
            Some(IdempotencyRecord::InFlight { request_hash, wake })
                if request_hash == &self.request_hash && wake.same_channel(&self.wake)
        );
        if !matches_owner {
            return Err(EvidenceError::RuleEvaluationFailed);
        }
        records.insert(
            self.key.clone(),
            IdempotencyRecord::Completed {
                request_hash: self.request_hash.clone(),
                response: response.clone(),
                expires_at: OffsetDateTime::now_utc() + BATCH_IDEMPOTENCY_RETENTION,
            },
        );
        self.completed = true;
        drop(records);
        self.wake.send_replace(true);
        Ok(response)
    }
}

impl Drop for BatchIdempotencyOwner<'_> {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let mut records = self
            .store
            .idempotency
            .lock()
            .expect("evidence idempotency mutex is not poisoned");
        let matches_owner = matches!(
            records.get(&self.key),
            Some(IdempotencyRecord::InFlight { request_hash, wake })
                if request_hash == &self.request_hash && wake.same_channel(&self.wake)
        );
        if matches_owner {
            records.insert(
                self.key.clone(),
                IdempotencyRecord::Failed {
                    request_hash: self.request_hash.clone(),
                    expires_at: OffsetDateTime::now_utc() + BATCH_IDEMPOTENCY_RETENTION,
                },
            );
        }
        drop(records);
        self.wake.send_replace(true);
    }
}

impl EvidenceStore {
    pub fn insert(&self, evaluation: registry_notary_core::StoredEvaluation) {
        let now = OffsetDateTime::now_utc();
        let mut evaluations = self
            .evaluations
            .lock()
            .expect("evidence store mutex is not poisoned");
        evaluations.retain(|_, evaluation| {
            OffsetDateTime::parse(&evaluation.expires_at, &Rfc3339)
                .is_ok_and(|expires_at| expires_at > now)
        });
        let Some(first) = evaluation.results.first() else {
            return;
        };
        evaluations.insert(first.evaluation_id.clone(), evaluation);
    }

    pub fn get(&self, evaluation_id: &str) -> Option<registry_notary_core::StoredEvaluation> {
        let evaluation = self
            .evaluations
            .lock()
            .expect("evidence store mutex is not poisoned")
            .get(evaluation_id)
            .cloned()?;
        let expires_at = OffsetDateTime::parse(&evaluation.expires_at, &Rfc3339).ok()?;
        if expires_at <= OffsetDateTime::now_utc() {
            return None;
        }
        Some(evaluation)
    }

    pub(super) async fn reserve_idempotent_batch(
        &self,
        key: String,
        request_hash: String,
    ) -> Result<BatchIdempotencyReservation<'_>, EvidenceError> {
        loop {
            let mut notification = {
                let now = OffsetDateTime::now_utc();
                let mut records = self
                    .idempotency
                    .lock()
                    .expect("evidence idempotency mutex is not poisoned");
                records.retain(|_, record| record.retained_at(now));
                match records.get(&key) {
                    None => {
                        let (wake, _) = tokio::sync::watch::channel(false);
                        records.insert(
                            key.clone(),
                            IdempotencyRecord::InFlight {
                                request_hash: request_hash.clone(),
                                wake: wake.clone(),
                            },
                        );
                        return Ok(BatchIdempotencyReservation::Owner(BatchIdempotencyOwner {
                            store: self,
                            key,
                            request_hash,
                            wake,
                            completed: false,
                        }));
                    }
                    Some(record) if record.request_hash() != request_hash => {
                        return Err(EvidenceError::IdempotencyConflict);
                    }
                    Some(IdempotencyRecord::Completed { response, .. }) => {
                        return Ok(BatchIdempotencyReservation::Replay(response.clone()));
                    }
                    Some(IdempotencyRecord::Failed { .. }) => {
                        let (wake, _) = tokio::sync::watch::channel(false);
                        records.insert(
                            key.clone(),
                            IdempotencyRecord::InFlight {
                                request_hash: request_hash.clone(),
                                wake: wake.clone(),
                            },
                        );
                        return Ok(BatchIdempotencyReservation::Owner(BatchIdempotencyOwner {
                            store: self,
                            key,
                            request_hash,
                            wake,
                            completed: false,
                        }));
                    }
                    Some(IdempotencyRecord::InFlight { wake, .. }) => wake.subscribe(),
                }
            };
            notification
                .changed()
                .await
                .map_err(|_| EvidenceError::RuleEvaluationFailed)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(batch_id: &str) -> BatchEvaluateResponse {
        BatchEvaluateResponse {
            batch_id: batch_id.to_owned(),
            status: BatchStatus::Completed,
            claims: Vec::new(),
            items: Vec::new(),
            summary: BatchSummary {
                succeeded: 0,
                failed: 0,
            },
        }
    }

    #[tokio::test]
    async fn completion_before_first_waiter_poll_is_not_lost() {
        let store = EvidenceStore::default();
        let owner = match store
            .reserve_idempotent_batch("key".to_owned(), "hash".to_owned())
            .await
            .unwrap()
        {
            BatchIdempotencyReservation::Owner(owner) => owner,
            BatchIdempotencyReservation::Replay(_) => panic!("first request owns reservation"),
        };
        let mut receiver = {
            let records = store.idempotency.lock().unwrap();
            match records.get("key").unwrap() {
                IdempotencyRecord::InFlight { wake, .. } => wake.subscribe(),
                _ => panic!("reservation is in flight"),
            }
        };
        owner.complete(response("batch-1")).unwrap();
        receiver.changed().await.unwrap();
        assert!(*receiver.borrow());
    }

    #[tokio::test]
    async fn one_owner_wakes_all_identical_waiters_to_the_same_replay() {
        let store = Arc::new(EvidenceStore::default());
        let owner = match store
            .reserve_idempotent_batch("key".to_owned(), "hash".to_owned())
            .await
            .unwrap()
        {
            BatchIdempotencyReservation::Owner(owner) => owner,
            BatchIdempotencyReservation::Replay(_) => panic!("first request owns reservation"),
        };
        let waiters = (0..4)
            .map(|_| {
                let store = Arc::clone(&store);
                tokio::spawn(async move {
                    match store
                        .reserve_idempotent_batch("key".to_owned(), "hash".to_owned())
                        .await?
                    {
                        BatchIdempotencyReservation::Replay(replay) => Ok(replay.batch_id),
                        BatchIdempotencyReservation::Owner(_) => {
                            Err(EvidenceError::RuleEvaluationFailed)
                        }
                    }
                })
            })
            .collect::<Vec<_>>();
        tokio::task::yield_now().await;
        owner.complete(response("batch-1")).unwrap();
        for waiter in waiters {
            assert_eq!(waiter.await.unwrap().unwrap(), "batch-1");
        }
    }

    #[tokio::test]
    async fn cancelled_owner_allows_one_same_hash_takeover_and_conflicts_other_hashes() {
        let store = EvidenceStore::default();
        let owner = match store
            .reserve_idempotent_batch("key".to_owned(), "hash".to_owned())
            .await
            .unwrap()
        {
            BatchIdempotencyReservation::Owner(owner) => owner,
            BatchIdempotencyReservation::Replay(_) => panic!("first request owns reservation"),
        };
        drop(owner);
        let takeover = match store
            .reserve_idempotent_batch("key".to_owned(), "hash".to_owned())
            .await
            .unwrap()
        {
            BatchIdempotencyReservation::Owner(owner) => owner,
            BatchIdempotencyReservation::Replay(_) => panic!("failed owner is not replayable"),
        };
        assert!(matches!(
            store
                .reserve_idempotent_batch("key".to_owned(), "different".to_owned())
                .await,
            Err(EvidenceError::IdempotencyConflict)
        ));
        takeover.complete(response("batch-2")).unwrap();
    }
}
