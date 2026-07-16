// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, fmt, sync::Arc};

use sha2::{Digest, Sha256};

use super::*;
use crate::state_plane::NotaryStatePlaneHandle;

const BATCH_IDEMPOTENCY_RETENTION: time::Duration = time::Duration::minutes(15);
const BATCH_OWNER_LEASE_SECONDS: i32 = 30;
const BATCH_OWNER_HEARTBEAT_SECONDS: u64 = 10;
const BATCH_WAIT_INITIAL_MILLIS: u64 = 50;
const BATCH_WAIT_MAX_MILLIS: u64 = 1_000;
// Version 2 adopts the pre-1.0 subject-access vocabulary in persisted
// evaluation and idempotency response envelopes. Version 1 used the removed
// self-attestation field and access-mode vocabulary and is intentionally not
// accepted by the clean 1.0 storage contract.
const STORED_RECORD_VERSION: i16 = 2;

enum IdempotencyRecord {
    InFlight {
        request_hash: String,
        quota_charged: bool,
        wake: tokio::sync::watch::Sender<bool>,
    },
    Completed {
        request_hash: String,
        response: BatchEvaluateResponse,
        expires_at: OffsetDateTime,
    },
    Failed {
        request_hash: String,
        quota_charged: bool,
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
    state_plane: Option<Arc<NotaryStatePlaneHandle>>,
    evaluations: Mutex<HashMap<String, registry_notary_core::StoredEvaluation>>,
    idempotency: Mutex<HashMap<String, IdempotencyRecord>>,
}

impl Default for EvidenceStore {
    fn default() -> Self {
        Self {
            state_plane: None,
            evaluations: Mutex::new(HashMap::new()),
            idempotency: Mutex::new(HashMap::new()),
        }
    }
}

impl fmt::Debug for EvidenceStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceStore")
            .field("postgresql", &self.postgres_state_plane().is_some())
            .finish_non_exhaustive()
    }
}

pub(super) enum BatchIdempotencyReservation<'a> {
    Owner(BatchIdempotencyOwner<'a>),
    Replay(BatchEvaluateResponse),
}

enum BatchIdempotencyOwnerBackend<'a> {
    InMemory {
        store: &'a EvidenceStore,
        key: String,
        request_hash: String,
        wake: tokio::sync::watch::Sender<bool>,
    },
    Postgresql {
        state_plane: Arc<NotaryStatePlaneHandle>,
        key_hash: Vec<u8>,
        request_hash: Vec<u8>,
        owner_token: Vec<u8>,
        heartbeat: tokio::task::JoinHandle<()>,
    },
}

pub(super) struct BatchIdempotencyOwner<'a> {
    backend: Option<BatchIdempotencyOwnerBackend<'a>>,
    quota_charged: bool,
    completed: bool,
}

impl BatchIdempotencyOwner<'_> {
    pub(super) fn quota_charged(&self) -> bool {
        self.quota_charged
    }

    pub(super) fn mark_quota_charged(&mut self) -> Result<(), EvidenceError> {
        if self.quota_charged {
            return Ok(());
        }
        let Some(backend) = self.backend.as_ref() else {
            return Err(EvidenceError::RuleEvaluationFailed);
        };
        let BatchIdempotencyOwnerBackend::InMemory {
            store,
            key,
            request_hash,
            wake,
        } = backend
        else {
            return Err(EvidenceError::RuleEvaluationFailed);
        };
        let mut records = store
            .idempotency
            .lock()
            .expect("evidence idempotency mutex is not poisoned");
        match records.get_mut(key) {
            Some(IdempotencyRecord::InFlight {
                request_hash: current_hash,
                quota_charged,
                wake: current_wake,
            }) if current_hash == request_hash && current_wake.same_channel(wake) => {
                *quota_charged = true;
            }
            _ => return Err(EvidenceError::RuleEvaluationFailed),
        }
        self.quota_charged = true;
        Ok(())
    }

    pub(super) fn abandon_uncharged(mut self) -> Result<(), EvidenceError> {
        if self.quota_charged {
            return Err(EvidenceError::RuleEvaluationFailed);
        }
        let wake = {
            let Some(BatchIdempotencyOwnerBackend::InMemory {
                store,
                key,
                request_hash,
                wake,
            }) = self.backend.as_ref()
            else {
                return Err(EvidenceError::RuleEvaluationFailed);
            };
            let mut records = store
                .idempotency
                .lock()
                .expect("evidence idempotency mutex is not poisoned");
            let matches_owner = matches!(
                records.get(key),
                Some(IdempotencyRecord::InFlight {
                    request_hash: current_hash,
                    quota_charged: false,
                    wake: current_wake,
                }) if current_hash == request_hash && current_wake.same_channel(wake)
            );
            if !matches_owner {
                return Err(EvidenceError::RuleEvaluationFailed);
            }
            records.remove(key);
            wake.clone()
        };
        self.backend.take();
        self.completed = true;
        wake.send_replace(true);
        Ok(())
    }

    pub(super) async fn complete(
        mut self,
        response: BatchEvaluateResponse,
        evaluations: Vec<registry_notary_core::StoredEvaluation>,
    ) -> Result<BatchEvaluateResponse, EvidenceError> {
        let backend = self
            .backend
            .take()
            .ok_or(EvidenceError::RuleEvaluationFailed)?;
        let result = match backend {
            BatchIdempotencyOwnerBackend::InMemory {
                store,
                key,
                request_hash,
                wake,
            } => {
                let mut records = store
                    .idempotency
                    .lock()
                    .expect("evidence idempotency mutex is not poisoned");
                let matches_owner = matches!(
                    records.get(&key),
                    Some(IdempotencyRecord::InFlight {
                        request_hash: current_hash,
                        wake: current_wake,
                        ..
                    }) if current_hash == &request_hash && current_wake.same_channel(&wake)
                );
                if !matches_owner {
                    Err(EvidenceError::RuleEvaluationFailed)
                } else {
                    for evaluation in evaluations {
                        store.insert_in_memory(evaluation);
                    }
                    records.insert(
                        key,
                        IdempotencyRecord::Completed {
                            request_hash,
                            response: response.clone(),
                            expires_at: OffsetDateTime::now_utc() + BATCH_IDEMPOTENCY_RETENTION,
                        },
                    );
                    drop(records);
                    wake.send_replace(true);
                    Ok(response)
                }
            }
            BatchIdempotencyOwnerBackend::Postgresql {
                state_plane,
                key_hash,
                request_hash,
                owner_token,
                heartbeat,
            } => {
                heartbeat.abort();
                let completion = complete_postgres_batch(
                    &state_plane,
                    &key_hash,
                    &request_hash,
                    &owner_token,
                    &evaluations,
                    &response,
                )
                .await;
                if completion.is_err() {
                    spawn_postgres_batch_failure(state_plane, key_hash, request_hash, owner_token);
                }
                completion.map(|()| response)
            }
        };
        if result.is_ok() {
            self.completed = true;
        }
        result
    }
}

impl Drop for BatchIdempotencyOwner<'_> {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let Some(backend) = self.backend.take() else {
            return;
        };
        match backend {
            BatchIdempotencyOwnerBackend::InMemory {
                store,
                key,
                request_hash,
                wake,
            } => {
                let mut records = store
                    .idempotency
                    .lock()
                    .expect("evidence idempotency mutex is not poisoned");
                let matches_owner = matches!(
                    records.get(&key),
                    Some(IdempotencyRecord::InFlight {
                        request_hash: current_hash,
                        wake: current_wake,
                        ..
                    }) if current_hash == &request_hash && current_wake.same_channel(&wake)
                );
                if matches_owner {
                    records.insert(
                        key,
                        IdempotencyRecord::Failed {
                            request_hash,
                            quota_charged: self.quota_charged,
                            expires_at: OffsetDateTime::now_utc() + BATCH_IDEMPOTENCY_RETENTION,
                        },
                    );
                }
                drop(records);
                wake.send_replace(true);
            }
            BatchIdempotencyOwnerBackend::Postgresql {
                state_plane,
                key_hash,
                request_hash,
                owner_token,
                heartbeat,
            } => {
                heartbeat.abort();
                spawn_postgres_batch_failure(state_plane, key_hash, request_hash, owner_token);
            }
        }
    }
}

impl EvidenceStore {
    #[must_use]
    pub(crate) fn with_state_plane(state_plane: Arc<NotaryStatePlaneHandle>) -> Self {
        Self {
            state_plane: Some(state_plane),
            ..Self::default()
        }
    }

    pub async fn insert(
        &self,
        evaluation: registry_notary_core::StoredEvaluation,
    ) -> Result<(), EvidenceError> {
        let Some(state_plane) = self.postgres_state_plane() else {
            self.insert_in_memory(evaluation);
            return Ok(());
        };
        insert_postgres_evaluation(state_plane, &evaluation).await
    }

    pub async fn get(
        &self,
        evaluation_id: &str,
        client_id: &str,
    ) -> Result<Option<registry_notary_core::StoredEvaluation>, EvidenceError> {
        let Some(state_plane) = self.postgres_state_plane() else {
            return Ok(self.get_in_memory(evaluation_id, client_id));
        };
        get_postgres_evaluation(state_plane, evaluation_id, client_id).await
    }

    pub(super) async fn reserve_idempotent_batch(
        &self,
        key: String,
        request_hash: String,
        principal_id: &str,
        quota: Option<(&crate::MachineQuotaLimiter, u32)>,
    ) -> Result<BatchIdempotencyReservation<'_>, EvidenceError> {
        let Some(state_plane) = self.postgres_state_plane() else {
            return self.reserve_in_memory_batch(key, request_hash).await;
        };
        reserve_postgres_batch(state_plane, key, request_hash, principal_id, quota).await
    }

    pub(super) fn uses_postgresql(&self) -> bool {
        self.postgres_state_plane().is_some()
    }

    fn postgres_state_plane(&self) -> Option<&Arc<NotaryStatePlaneHandle>> {
        self.state_plane
            .as_ref()
            .filter(|state_plane| !state_plane.is_in_memory())
    }

    fn insert_in_memory(&self, evaluation: registry_notary_core::StoredEvaluation) {
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

    fn get_in_memory(
        &self,
        evaluation_id: &str,
        client_id: &str,
    ) -> Option<registry_notary_core::StoredEvaluation> {
        let evaluation = self
            .evaluations
            .lock()
            .expect("evidence store mutex is not poisoned")
            .get(evaluation_id)
            .filter(|evaluation| evaluation.client_id == client_id)
            .cloned()?;
        let expires_at = OffsetDateTime::parse(&evaluation.expires_at, &Rfc3339).ok()?;
        (expires_at > OffsetDateTime::now_utc()).then_some(evaluation)
    }

    async fn reserve_in_memory_batch(
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
                                quota_charged: false,
                                wake: wake.clone(),
                            },
                        );
                        return Ok(BatchIdempotencyReservation::Owner(BatchIdempotencyOwner {
                            backend: Some(BatchIdempotencyOwnerBackend::InMemory {
                                store: self,
                                key,
                                request_hash,
                                wake,
                            }),
                            quota_charged: false,
                            completed: false,
                        }));
                    }
                    Some(record) if record.request_hash() != request_hash => {
                        return Err(EvidenceError::IdempotencyConflict);
                    }
                    Some(IdempotencyRecord::Completed { response, .. }) => {
                        return Ok(BatchIdempotencyReservation::Replay(response.clone()));
                    }
                    Some(IdempotencyRecord::Failed { quota_charged, .. }) => {
                        let quota_charged = *quota_charged;
                        let (wake, _) = tokio::sync::watch::channel(false);
                        records.insert(
                            key.clone(),
                            IdempotencyRecord::InFlight {
                                request_hash: request_hash.clone(),
                                quota_charged,
                                wake: wake.clone(),
                            },
                        );
                        return Ok(BatchIdempotencyReservation::Owner(BatchIdempotencyOwner {
                            backend: Some(BatchIdempotencyOwnerBackend::InMemory {
                                store: self,
                                key,
                                request_hash,
                                wake,
                            }),
                            quota_charged,
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

async fn insert_postgres_evaluation(
    state_plane: &NotaryStatePlaneHandle,
    evaluation: &registry_notary_core::StoredEvaluation,
) -> Result<(), EvidenceError> {
    let evaluation_id = evaluation
        .results
        .first()
        .map(|result| result.evaluation_id.as_str())
        .ok_or(EvidenceError::RuleEvaluationFailed)?;
    let created_at = parse_stored_time(&evaluation.created_at)?;
    let expires_at = parse_stored_time(&evaluation.expires_at)?;
    let record_json = postgres_evaluation_record_json(evaluation)?;
    let client_id_hash = state_hash("evaluation-client", &evaluation.client_id);
    let request_hash = state_hash("evaluation-request", &evaluation.request_hash);
    let runtime = state_plane
        .runtime()
        .map_err(|_| EvidenceError::RuleEvaluationFailed)?;
    let session = runtime
        .open_domain_session()
        .await
        .map_err(|_| EvidenceError::RuleEvaluationFailed)?;
    let row = session
        .run_operation(session.client().query_one(
            concat!(
                "SELECT registry_notary_api.evaluation_insert_v1(",
                "$1, $2, $3, $4, $5, $6::text::jsonb, $7, $8) AS inserted"
            ),
            &[
                &evaluation_id,
                &client_id_hash,
                &request_hash,
                &evaluation.purpose,
                &STORED_RECORD_VERSION,
                &record_json,
                &created_at,
                &expires_at,
            ],
        ))
        .await
        .map_err(|_| EvidenceError::RuleEvaluationFailed)?;
    match row.try_get::<_, bool>("inserted") {
        Ok(true) => Ok(()),
        _ => Err(EvidenceError::RuleEvaluationFailed),
    }
}

async fn get_postgres_evaluation(
    state_plane: &NotaryStatePlaneHandle,
    evaluation_id: &str,
    client_id: &str,
) -> Result<Option<registry_notary_core::StoredEvaluation>, EvidenceError> {
    let client_id_hash = state_hash("evaluation-client", client_id);
    let runtime = state_plane
        .runtime()
        .map_err(|_| EvidenceError::RuleEvaluationFailed)?;
    let session = runtime
        .open_domain_session()
        .await
        .map_err(|_| EvidenceError::RuleEvaluationFailed)?;
    let row = session
        .run_operation(session.client().query_opt(
            concat!(
                "SELECT record_version, record_json::text AS record_json ",
                "FROM registry_notary_api.evaluation_get_v1($1, $2)"
            ),
            &[&evaluation_id, &client_id_hash],
        ))
        .await
        .map_err(|_| EvidenceError::RuleEvaluationFailed)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let version: i16 = row
        .try_get("record_version")
        .map_err(|_| EvidenceError::RuleEvaluationFailed)?;
    if version != STORED_RECORD_VERSION {
        return Err(EvidenceError::RuleEvaluationFailed);
    }
    let record_json: String = row
        .try_get("record_json")
        .map_err(|_| EvidenceError::RuleEvaluationFailed)?;
    let mut evaluation: registry_notary_core::StoredEvaluation =
        serde_json::from_str(&record_json).map_err(|_| EvidenceError::RuleEvaluationFailed)?;
    evaluation.client_id = client_id.to_owned();
    Ok(Some(evaluation))
}

async fn reserve_postgres_batch<'a>(
    state_plane: &Arc<NotaryStatePlaneHandle>,
    key: String,
    request_hash: String,
    principal_id: &str,
    quota: Option<(&crate::MachineQuotaLimiter, u32)>,
) -> Result<BatchIdempotencyReservation<'a>, EvidenceError> {
    let key_hash = state_hash("batch-idempotency-key", &key);
    let request_hash = state_hash("batch-idempotency-request", &request_hash);
    let owner_token = random_owner_token()?;
    let (principal_hash, quota_limit, quota_cost) =
        postgres_batch_quota_parameters(&key, principal_id, quota)?;
    let mut wait_attempt = 0_u32;

    loop {
        let runtime = state_plane
            .runtime()
            .map_err(|_| EvidenceError::RuleEvaluationFailed)?;
        let session = runtime
            .open_domain_session()
            .await
            .map_err(|_| EvidenceError::RuleEvaluationFailed)?;
        let row = session
            .run_operation(session.client().query_one(
                concat!(
                    "SELECT outcome, retry_after_seconds, response_version, ",
                    "response_json::text AS response_json ",
                    "FROM registry_notary_api.batch_reserve_v1(",
                    "$1, $2, $3, $4, $5, $6, $7)"
                ),
                &[
                    &key_hash,
                    &request_hash,
                    &principal_hash,
                    &owner_token,
                    &BATCH_OWNER_LEASE_SECONDS,
                    &quota_limit,
                    &quota_cost,
                ],
            ))
            .await
            .map_err(|_| EvidenceError::RuleEvaluationFailed)?;
        let outcome: String = row
            .try_get("outcome")
            .map_err(|_| EvidenceError::RuleEvaluationFailed)?;
        match outcome.as_str() {
            "owner" => {
                let heartbeat = spawn_postgres_batch_heartbeat(
                    Arc::clone(state_plane),
                    key_hash.clone(),
                    request_hash.clone(),
                    owner_token.clone(),
                );
                return Ok(BatchIdempotencyReservation::Owner(BatchIdempotencyOwner {
                    backend: Some(BatchIdempotencyOwnerBackend::Postgresql {
                        state_plane: Arc::clone(state_plane),
                        key_hash,
                        request_hash,
                        owner_token,
                        heartbeat,
                    }),
                    quota_charged: quota_limit.is_some(),
                    completed: false,
                }));
            }
            "replay" => {
                let response_version: Option<i16> = row
                    .try_get("response_version")
                    .map_err(|_| EvidenceError::RuleEvaluationFailed)?;
                let response_json: Option<String> = row
                    .try_get("response_json")
                    .map_err(|_| EvidenceError::RuleEvaluationFailed)?;
                if response_version != Some(STORED_RECORD_VERSION) {
                    return Err(EvidenceError::RuleEvaluationFailed);
                }
                let response = serde_json::from_str(
                    response_json
                        .as_deref()
                        .ok_or(EvidenceError::RuleEvaluationFailed)?,
                )
                .map_err(|_| EvidenceError::RuleEvaluationFailed)?;
                return Ok(BatchIdempotencyReservation::Replay(response));
            }
            "conflict" => return Err(EvidenceError::IdempotencyConflict),
            "quota_exceeded" => {
                let retry_after_seconds: i64 = row
                    .try_get("retry_after_seconds")
                    .map_err(|_| EvidenceError::RuleEvaluationFailed)?;
                return Err(EvidenceError::MachineQuotaExceeded {
                    retry_after_seconds: retry_after_seconds.max(1) as u64,
                });
            }
            "wait" => {
                wait_for_postgres_batch_retry(
                    session,
                    postgres_batch_wait_delay(wait_attempt, &owner_token),
                )
                .await;
                wait_attempt = wait_attempt.saturating_add(1);
            }
            _ => return Err(EvidenceError::RuleEvaluationFailed),
        }
    }
}

fn postgres_batch_quota_parameters(
    key: &str,
    principal_id: &str,
    quota: Option<(&crate::MachineQuotaLimiter, u32)>,
) -> Result<(Vec<u8>, Option<i32>, i32), EvidenceError> {
    let Some((limiter, cost)) = quota.filter(|(limiter, _)| limiter.is_enabled()) else {
        return Ok((
            state_hash(
                "batch-principal-fallback",
                &format!("{key}\0{principal_id}"),
            ),
            None,
            1,
        ));
    };
    limiter
        .batch_reservation_parameters(principal_id, cost)
        .map_err(|error| EvidenceError::MachineQuotaExceeded {
            retry_after_seconds: error.retry_after_seconds,
        })
}

async fn wait_for_postgres_batch_retry<Session>(session: Session, delay: std::time::Duration) {
    drop(session);
    tokio::time::sleep(delay).await;
}

fn postgres_batch_wait_delay(attempt: u32, jitter_seed: &[u8]) -> std::time::Duration {
    let mut hasher = Sha256::new();
    hasher.update(b"batch-idempotency-wait");
    hasher.update([0]);
    hasher.update(jitter_seed);
    hasher.update(attempt.to_le_bytes());
    let digest = hasher.finalize();
    let sample = u64::from_le_bytes(
        digest[..8]
            .try_into()
            .expect("SHA-256 digest prefix is eight bytes"),
    );
    postgres_batch_wait_delay_from_sample(attempt, sample)
}

fn postgres_batch_wait_delay_from_sample(attempt: u32, sample: u64) -> std::time::Duration {
    let multiplier = 1_u64 << attempt.min(63);
    let ceiling_millis = BATCH_WAIT_INITIAL_MILLIS
        .saturating_mul(multiplier)
        .min(BATCH_WAIT_MAX_MILLIS);
    let floor_millis = (ceiling_millis / 2).max(1);
    let span = ceiling_millis - floor_millis + 1;
    let jitter_millis = ((u128::from(sample) * u128::from(span)) >> 64) as u64;
    std::time::Duration::from_millis(floor_millis + jitter_millis)
}

fn spawn_postgres_batch_heartbeat(
    state_plane: Arc<NotaryStatePlaneHandle>,
    key_hash: Vec<u8>,
    request_hash: Vec<u8>,
    owner_token: Vec<u8>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(
                BATCH_OWNER_HEARTBEAT_SECONDS,
            ))
            .await;
            let Ok(runtime) = state_plane.runtime() else {
                return;
            };
            let Ok(session) = runtime.open_domain_session().await else {
                return;
            };
            let Ok(row) = session
                .run_operation(session.client().query_one(
                    concat!(
                        "SELECT registry_notary_api.batch_heartbeat_v1(",
                        "$1, $2, $3, $4) AS renewed"
                    ),
                    &[
                        &key_hash,
                        &request_hash,
                        &owner_token,
                        &BATCH_OWNER_LEASE_SECONDS,
                    ],
                ))
                .await
            else {
                return;
            };
            if !matches!(row.try_get::<_, bool>("renewed"), Ok(true)) {
                return;
            }
        }
    })
}

fn spawn_postgres_batch_failure(
    state_plane: Arc<NotaryStatePlaneHandle>,
    key_hash: Vec<u8>,
    request_hash: Vec<u8>,
    owner_token: Vec<u8>,
) {
    let Ok(runtime_handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    runtime_handle.spawn(async move {
        let Ok(runtime) = state_plane.runtime() else {
            return;
        };
        let Ok(session) = runtime.open_domain_session().await else {
            return;
        };
        let _ = session
            .run_operation(session.client().query_one(
                "SELECT registry_notary_api.batch_fail_v1($1, $2, $3) AS failed",
                &[&key_hash, &request_hash, &owner_token],
            ))
            .await;
    });
}

async fn complete_postgres_batch(
    state_plane: &NotaryStatePlaneHandle,
    key_hash: &[u8],
    request_hash: &[u8],
    owner_token: &[u8],
    evaluations: &[registry_notary_core::StoredEvaluation],
    response: &BatchEvaluateResponse,
) -> Result<(), EvidenceError> {
    let evaluation_json = postgres_batch_evaluations(evaluations)?;
    let response_json =
        serde_json::to_string(response).map_err(|_| EvidenceError::RuleEvaluationFailed)?;
    let runtime = state_plane
        .runtime()
        .map_err(|_| EvidenceError::RuleEvaluationFailed)?;
    let session = runtime
        .open_domain_session()
        .await
        .map_err(|_| EvidenceError::RuleEvaluationFailed)?;
    let row = session
        .run_operation(session.client().query_one(
            concat!(
                "SELECT registry_notary_api.batch_complete_v1(",
                "$1, $2, $3, $4::text::jsonb, $5, $6::text::jsonb) AS completed"
            ),
            &[
                &key_hash,
                &request_hash,
                &owner_token,
                &evaluation_json,
                &STORED_RECORD_VERSION,
                &response_json,
            ],
        ))
        .await
        .map_err(|_| EvidenceError::RuleEvaluationFailed)?;
    if !matches!(row.try_get::<_, bool>("completed"), Ok(true)) {
        return Err(EvidenceError::RuleEvaluationFailed);
    }
    Ok(())
}

fn postgres_batch_evaluations(
    evaluations: &[registry_notary_core::StoredEvaluation],
) -> Result<String, EvidenceError> {
    let mut records = Vec::with_capacity(evaluations.len());
    for evaluation in evaluations {
        let evaluation_id = evaluation
            .results
            .first()
            .map(|result| result.evaluation_id.as_str())
            .ok_or(EvidenceError::RuleEvaluationFailed)?;
        parse_stored_time(&evaluation.created_at)?;
        parse_stored_time(&evaluation.expires_at)?;
        let record_json = postgres_evaluation_record_json(evaluation)?;
        let record: serde_json::Value =
            serde_json::from_str(&record_json).map_err(|_| EvidenceError::RuleEvaluationFailed)?;
        records.push(serde_json::json!({
            "evaluation_id": evaluation_id,
            "client_id_hash_hex": hex_lower(&state_hash(
                "evaluation-client",
                &evaluation.client_id,
            )),
            "purpose": evaluation.purpose,
            "record_version": STORED_RECORD_VERSION,
            "record": record,
            "created_at": evaluation.created_at,
            "expires_at": evaluation.expires_at,
        }));
    }
    serde_json::to_string(&records).map_err(|_| EvidenceError::RuleEvaluationFailed)
}

fn postgres_evaluation_record_json(
    evaluation: &registry_notary_core::StoredEvaluation,
) -> Result<String, EvidenceError> {
    let mut record =
        serde_json::to_value(evaluation).map_err(|_| EvidenceError::RuleEvaluationFailed)?;
    let object = record
        .as_object_mut()
        .ok_or(EvidenceError::RuleEvaluationFailed)?;
    object.insert(
        "client_id".to_owned(),
        serde_json::Value::String(String::new()),
    );
    serde_json::to_string(&record).map_err(|_| EvidenceError::RuleEvaluationFailed)
}

fn parse_stored_time(value: &str) -> Result<OffsetDateTime, EvidenceError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| EvidenceError::RuleEvaluationFailed)
}

fn random_owner_token() -> Result<Vec<u8>, EvidenceError> {
    let mut token = [0_u8; 32];
    getrandom::fill(&mut token).map_err(|_| EvidenceError::RuleEvaluationFailed)?;
    Ok(token.to_vec())
}

fn state_hash(domain: &str, value: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(value.as_bytes());
    hasher.finalize().to_vec()
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
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

    #[test]
    fn postgres_evaluation_record_does_not_duplicate_raw_client_id() {
        let evaluation: registry_notary_core::StoredEvaluation =
            serde_json::from_value(serde_json::json!({
                "client_id": "sensitive-machine-client",
                "purpose": "test",
                "claim_ids": [],
                "disclosure": "predicate",
                "format": "application/json",
                "results": [],
                "created_at": "2026-07-14T00:00:00Z",
                "expires_at": "2026-07-14T00:15:00Z",
                "request_hash": "request-hash"
            }))
            .unwrap();

        let record = postgres_evaluation_record_json(&evaluation).unwrap();

        assert!(!record.contains("sensitive-machine-client"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&record).unwrap()["client_id"],
            ""
        );
    }

    #[test]
    fn postgres_batch_wait_backoff_is_exponential_jittered_and_bounded() {
        let ceilings = [50, 100, 200, 400, 800, 1_000, 1_000, 1_000];
        for (attempt, ceiling) in ceilings.into_iter().enumerate() {
            let minimum = postgres_batch_wait_delay_from_sample(attempt as u32, 0);
            let maximum = postgres_batch_wait_delay_from_sample(attempt as u32, u64::MAX);
            assert_eq!(minimum, std::time::Duration::from_millis(ceiling / 2));
            assert_eq!(maximum, std::time::Duration::from_millis(ceiling));
        }
    }

    #[tokio::test]
    async fn postgres_waiter_releases_pool_session_before_backoff_for_peer() {
        let pool = Arc::new(tokio::sync::Semaphore::new(1));
        let waiter_session = Arc::clone(&pool).acquire_owned().await.unwrap();
        let waiter = tokio::spawn(wait_for_postgres_batch_retry(
            waiter_session,
            std::time::Duration::from_secs(30),
        ));

        let peer_session = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            Arc::clone(&pool).acquire_owned(),
        )
        .await
        .expect("a waiting reservation must not pin the only pool session")
        .unwrap();

        drop(peer_session);
        waiter.abort();
        let _ = waiter.await;
    }

    #[test]
    fn disabled_postgres_batch_quota_skips_bounded_principal_parameters() {
        let limiter = crate::MachineQuotaLimiter::new(registry_notary_core::MachineQuotaConfig {
            enabled: false,
            subjects_per_minute: 1,
        });
        let principal_id = "unbounded-oidc-subject".repeat(32);

        let parameters =
            postgres_batch_quota_parameters("batch-key", &principal_id, Some((&limiter, u32::MAX)))
                .expect("disabled quota does not validate or hash quota principal parameters");

        assert_eq!(
            parameters,
            (
                state_hash(
                    "batch-principal-fallback",
                    &format!("batch-key\0{principal_id}"),
                ),
                None,
                1,
            )
        );
    }

    #[tokio::test]
    async fn completion_before_first_waiter_poll_is_not_lost() {
        let store = EvidenceStore::default();
        let owner = match store
            .reserve_idempotent_batch("key".to_owned(), "hash".to_owned(), "principal", None)
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
        owner
            .complete(response("batch-1"), Vec::new())
            .await
            .unwrap();
        receiver.changed().await.unwrap();
        assert!(*receiver.borrow());
    }

    #[tokio::test]
    async fn one_owner_wakes_all_identical_waiters_to_the_same_replay() {
        let store = Arc::new(EvidenceStore::default());
        let owner = match store
            .reserve_idempotent_batch("key".to_owned(), "hash".to_owned(), "principal", None)
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
                        .reserve_idempotent_batch(
                            "key".to_owned(),
                            "hash".to_owned(),
                            "principal",
                            None,
                        )
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
        owner
            .complete(response("batch-1"), Vec::new())
            .await
            .unwrap();
        for waiter in waiters {
            assert_eq!(waiter.await.unwrap().unwrap(), "batch-1");
        }
    }

    #[tokio::test]
    async fn cancelled_owner_allows_one_same_hash_takeover_and_conflicts_other_hashes() {
        let store = EvidenceStore::default();
        let owner = match store
            .reserve_idempotent_batch("key".to_owned(), "hash".to_owned(), "principal", None)
            .await
            .unwrap()
        {
            BatchIdempotencyReservation::Owner(owner) => owner,
            BatchIdempotencyReservation::Replay(_) => panic!("first request owns reservation"),
        };
        assert!(!owner.quota_charged());
        drop(owner);
        let takeover = match store
            .reserve_idempotent_batch("key".to_owned(), "hash".to_owned(), "principal", None)
            .await
            .unwrap()
        {
            BatchIdempotencyReservation::Owner(owner) => owner,
            BatchIdempotencyReservation::Replay(_) => panic!("failed owner is not replayable"),
        };
        assert!(!takeover.quota_charged());
        assert!(matches!(
            store
                .reserve_idempotent_batch(
                    "key".to_owned(),
                    "different".to_owned(),
                    "principal",
                    None,
                )
                .await,
            Err(EvidenceError::IdempotencyConflict)
        ));
        takeover
            .complete(response("batch-2"), Vec::new())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn uncharged_abandonment_removes_key_and_wakes_waiters() {
        let store = EvidenceStore::default();
        let owner = match store
            .reserve_idempotent_batch("key".to_owned(), "hash".to_owned(), "principal", None)
            .await
            .unwrap()
        {
            BatchIdempotencyReservation::Owner(owner) => owner,
            BatchIdempotencyReservation::Replay(_) => panic!("first request owns reservation"),
        };
        let mut waiter = {
            let records = store.idempotency.lock().unwrap();
            match records.get("key").unwrap() {
                IdempotencyRecord::InFlight { wake, .. } => wake.subscribe(),
                _ => panic!("reservation is in flight"),
            }
        };

        owner.abandon_uncharged().unwrap();

        waiter.changed().await.unwrap();
        assert!(*waiter.borrow());
        assert!(!store.idempotency.lock().unwrap().contains_key("key"));
        let replacement = match store
            .reserve_idempotent_batch(
                "key".to_owned(),
                "different-hash".to_owned(),
                "principal",
                None,
            )
            .await
            .unwrap()
        {
            BatchIdempotencyReservation::Owner(owner) => owner,
            BatchIdempotencyReservation::Replay(_) => {
                panic!("an abandoned reservation is not replayable")
            }
        };
        replacement
            .complete(response("batch-2"), Vec::new())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn failed_owner_preserves_quota_charge_for_takeover_completion_and_replay() {
        let store = EvidenceStore::default();
        let mut owner = match store
            .reserve_idempotent_batch("key".to_owned(), "hash".to_owned(), "principal", None)
            .await
            .unwrap()
        {
            BatchIdempotencyReservation::Owner(owner) => owner,
            BatchIdempotencyReservation::Replay(_) => panic!("first request owns reservation"),
        };
        assert!(!owner.quota_charged());
        owner.mark_quota_charged().unwrap();
        assert!(owner.quota_charged());
        drop(owner);
        assert!(matches!(
            store.idempotency.lock().unwrap().get("key"),
            Some(IdempotencyRecord::Failed {
                quota_charged: true,
                ..
            })
        ));

        let takeover = match store
            .reserve_idempotent_batch("key".to_owned(), "hash".to_owned(), "principal", None)
            .await
            .unwrap()
        {
            BatchIdempotencyReservation::Owner(owner) => owner,
            BatchIdempotencyReservation::Replay(_) => panic!("failed owner is not replayable"),
        };
        assert!(takeover.quota_charged());
        takeover
            .complete(response("batch-2"), Vec::new())
            .await
            .unwrap();
        assert!(matches!(
            store.idempotency.lock().unwrap().get("key"),
            Some(IdempotencyRecord::Completed { .. })
        ));

        match store
            .reserve_idempotent_batch("key".to_owned(), "hash".to_owned(), "principal", None)
            .await
            .unwrap()
        {
            BatchIdempotencyReservation::Replay(replay) => {
                assert_eq!(replay.batch_id, "batch-2");
            }
            BatchIdempotencyReservation::Owner(_) => panic!("completed request is replayed"),
        };
    }
}
