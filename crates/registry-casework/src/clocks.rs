use crate::{CaseworkService, PostgresStore, ServiceError, StoreError};
use chrono::Utc;
use registry_casework_core::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio_postgres::Transaction;
use uuid::Uuid;
impl PostgresStore {
    pub async fn put_holiday_set(
        &self,
        actor: &ActorContext,
        document: &HolidaySetDocument,
        idempotency_key: &str,
    ) -> Result<(), StoreError> {
        if actor.role != CaseworkRole::Administrator {
            return Err(StoreError::Forbidden);
        }
        if document.holiday_set.is_empty()
            || document.holiday_set.len() > 64
            || document.revision == 0
            || document.dates.len() > 3_660
            || document.dates.iter().any(|date| !valid_date(date))
            || document
                .dates
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != document.dates.len()
            || idempotency_key.is_empty()
            || idempotency_key.len() > 256
        {
            return Err(StoreError::Invalid);
        }
        let value = serde_json::to_value(document)?;
        let digest = digest_json(&value)?;
        let revision = i64::try_from(document.revision).map_err(|_| StoreError::Invalid)?;
        let mut audit = self
            .begin_audit(crate::audit::request_record(
                "holiday-revision-created",
                Some(actor),
                &actor.profile_id,
                json!({}),
            ))
            .await?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let resource = format!("{}:{}", document.holiday_set, document.revision);
        let lock_binding = format!("holiday-revision:{resource}");
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                &[&lock_binding],
            )
            .await?;
        if let Some(row) = transaction.query_opt(
            "SELECT request_hash FROM casework_idempotency WHERE issuer=$1 AND subject=$2 AND profile_id=$3 AND operation='holiday.revision.create' AND resource=$4 AND idempotency_key=$5 FOR UPDATE",
            &[&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&resource,&idempotency_key],
        ).await? {
            if row.get::<_,String>(0)!=digest{return Err(StoreError::IdempotencyConflict)}
            audit.record_outcome(crate::audit::AuditOutcome::Replayed);
            audit.commit(transaction).await?;
            return Ok(())
        }
        let existing = transaction
            .query_opt(
                "SELECT digest FROM casework_holiday_sets WHERE holiday_set=$1 AND revision=$2 FOR UPDATE",
                &[&document.holiday_set, &revision],
            )
            .await?;
        if let Some(row) = existing {
            if row.get::<_, String>(0) != digest {
                return Err(StoreError::Conflict);
            }
            insert_clock_idempotency(
                &transaction,
                actor,
                "holiday.revision.create",
                &resource,
                idempotency_key,
                &digest,
                &Value::Null,
            )
            .await?;
            audit.record_outcome(crate::audit::AuditOutcome::Unchanged);
            audit.commit(transaction).await?;
            return Ok(());
        }
        transaction.execute(
            "INSERT INTO casework_holiday_sets(holiday_set,revision,document,digest,created_at,created_by_issuer,created_by_subject,created_by_profile) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
            &[&document.holiday_set,&revision,&value,&digest,&Utc::now(),&actor.principal.issuer,&actor.principal.subject,&actor.profile_id],
        ).await?;
        append_clock_audit(
            &mut audit,
            actor,
            "holiday-revision-created",
            json!({"holidaySet":document.holiday_set,"revision":document.revision,"digest":digest}),
        )
        .await?;
        insert_clock_idempotency(
            &transaction,
            actor,
            "holiday.revision.create",
            &resource,
            idempotency_key,
            &digest,
            &Value::Null,
        )
        .await?;
        audit.commit(transaction).await?;
        Ok(())
    }
    pub async fn holiday_set(
        &self,
        holiday_set: &str,
        revision: u64,
    ) -> Result<HolidaySetDocument, StoreError> {
        let revision = i64::try_from(revision).map_err(|_| StoreError::Invalid)?;
        let client = self.client().await?;
        let row = client
            .query_opt(
                "SELECT document FROM casework_holiday_sets WHERE holiday_set=$1 AND revision=$2",
                &[&holiday_set, &revision],
            )
            .await?
            .ok_or(StoreError::NotFound)?;
        serde_json::from_value(row.get(0)).map_err(StoreError::Json)
    }
}

impl CaseworkService {
    pub async fn create_holiday_revision(
        &self,
        actor: &ActorContext,
        document: &HolidaySetDocument,
        idempotency_key: &str,
    ) -> Result<(), ServiceError> {
        self.store
            .put_holiday_set(actor, document, idempotency_key)
            .await
            .map_err(ServiceError::from)
    }
    pub async fn holiday_revision(
        &self,
        actor: &ActorContext,
        holiday_set: &str,
        revision: u64,
    ) -> Result<HolidaySetDocument, ServiceError> {
        if actor.role != CaseworkRole::Administrator {
            return Err(StoreError::Forbidden.into());
        }
        self.store
            .holiday_set(holiday_set, revision)
            .await
            .map_err(ServiceError::from)
    }
}

fn valid_date(value: &str) -> bool {
    value.len() == 10
        && value.as_bytes().get(4) == Some(&b'-')
        && value.as_bytes().get(7) == Some(&b'-')
        && chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d").is_ok()
}

fn digest_json(value: &Value) -> Result<String, StoreError> {
    let canonical = registry_platform_canonical_json::canonicalize_json(value)
        .map_err(|_| StoreError::Invalid)?;
    let digest = Sha256::digest(canonical);
    Ok(format!(
        "sha256:{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}

async fn append_clock_audit(
    audit: &mut crate::audit::AuditOperation,
    actor: &ActorContext,
    kind: &str,
    detail: Value,
) -> Result<(), StoreError> {
    let event_id = Uuid::new_v4();
    audit.record(
        event_id,
        json!({"event":format!("casework.{kind}"),"eventId":event_id,"actor":{"issuer":actor.principal.issuer,"subject":actor.principal.subject},"profileId":actor.profile_id,"detail":detail}),
    )
}

async fn insert_clock_idempotency(
    transaction: &Transaction<'_>,
    actor: &ActorContext,
    operation: &str,
    resource: &str,
    key: &str,
    request_hash: &str,
    response: &Value,
) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO casework_idempotency(issuer,subject,profile_id,operation,resource,idempotency_key,request_hash,response,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        &[&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&operation,&resource,&key,&request_hash,&response,&Utc::now()],
    ).await?;
    Ok(())
}
