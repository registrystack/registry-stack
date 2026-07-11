// SPDX-License-Identifier: Apache-2.0

use super::*;

#[derive(Debug, Clone)]
pub(super) struct IdempotencyRecord {
    request_hash: String,
    response: BatchEvaluateResponse,
    expires_at: OffsetDateTime,
}

#[derive(Debug, Default)]
pub struct EvidenceStore {
    evaluations: Mutex<HashMap<String, registry_notary_core::StoredEvaluation>>,
    idempotency: Mutex<HashMap<String, IdempotencyRecord>>,
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

    pub(crate) fn idempotent_batch(
        &self,
        key: &str,
        request_hash: &str,
    ) -> Result<Option<BatchEvaluateResponse>, EvidenceError> {
        let now = OffsetDateTime::now_utc();
        let mut records = self
            .idempotency
            .lock()
            .expect("evidence idempotency mutex is not poisoned");
        records.retain(|_, record| record.expires_at > now);
        let Some(record) = records.get(key) else {
            return Ok(None);
        };
        if record.request_hash == request_hash {
            Ok(Some(record.response.clone()))
        } else {
            Err(EvidenceError::IdempotencyConflict)
        }
    }

    pub(super) fn insert_idempotent_batch(
        &self,
        key: String,
        request_hash: String,
        response: BatchEvaluateResponse,
    ) {
        let now = OffsetDateTime::now_utc();
        self.idempotency
            .lock()
            .expect("evidence idempotency mutex is not poisoned")
            .insert(
                key,
                IdempotencyRecord {
                    request_hash,
                    response,
                    expires_at: now + time::Duration::minutes(15),
                },
            );
    }
}
