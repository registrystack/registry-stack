use chrono::Utc;
use registry_casework_core::{SourceRetentionReport, SourceRetentionSelector};
use tokio_postgres::Transaction;
use uuid::Uuid;

use crate::{PostgresStore, StoreError};

impl PostgresStore {
    pub async fn preview_source_retention(
        &self,
        selector: &SourceRetentionSelector,
    ) -> Result<SourceRetentionReport, StoreError> {
        validate_selector(selector)?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        lock_subject(&transaction, selector).await?;
        let report = retention_report(&transaction, selector, false).await?;
        transaction.commit().await?;
        Ok(report)
    }

    pub async fn erase_source_retention(
        &self,
        selector: &SourceRetentionSelector,
    ) -> Result<SourceRetentionReport, StoreError> {
        validate_selector(selector)?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        lock_subject(&transaction, selector).await?;
        let item_ids = lock_items(&transaction, selector).await?;
        let mut preview_ids: Vec<Uuid> = transaction
            .query(
                "SELECT p.preview_id FROM casework_clock_recompute_previews p JOIN casework_clock_occurrences o USING(clock_occurrence_id) WHERE o.source_id=$1 AND o.subject_kind=$2 AND o.subject_id=$3 ORDER BY p.preview_id FOR UPDATE OF p",
                &[&selector.source_id, &selector.request_kind, &selector.request_id],
            )
            .await?
            .into_iter()
            .map(|row| row.get(0))
            .collect();
        preview_ids.dedup();
        let preview_resources: Vec<String> = preview_ids.iter().map(Uuid::to_string).collect();
        let report = retention_report(&transaction, selector, true).await?;
        if report.blocked_live_attempts > 0 {
            return Err(StoreError::AttemptPending);
        }

        let now = Utc::now();
        transaction
            .execute(
                "UPDATE casework_subjects SET active=false,sync_pending=false,sync_lease_until=NULL,erased_at=COALESCE(erased_at,$4) WHERE source_id=$1 AND subject_kind=$2 AND subject_id=$3",
                &[&selector.source_id, &selector.request_kind, &selector.request_id, &now],
            )
            .await?;
        if !item_ids.is_empty() {
            transaction
                .execute(
                    "UPDATE casework_items SET erased_at=COALESCE(erased_at,$2) WHERE item_id=ANY($1)",
                    &[&item_ids, &now],
                )
                .await?;
            transaction
                .execute(
                    "DELETE FROM casework_drafts WHERE item_id=ANY($1)",
                    &[&item_ids],
                )
                .await?;
            transaction
                .execute(
                    "DELETE FROM casework_correction_context WHERE item_id=ANY($1)",
                    &[&item_ids],
                )
                .await?;
            transaction
                .execute(
                    "UPDATE casework_attempts SET decision_reason=NULL,flagged_fields='[]'::jsonb,displayed_binding=NULL,recovery_evidence=NULL,receipt=CASE WHEN receipt IS NULL THEN NULL ELSE jsonb_set(receipt,'{metadata}','{}'::jsonb,true) END WHERE item_id=ANY($1) AND state IN ('completed','refused')",
                    &[&item_ids],
                )
                .await?;
            transaction
                .execute(
                    "UPDATE casework_history SET detail='{}'::jsonb WHERE item_id=ANY($1)",
                    &[&item_ids],
                )
                .await?;
            transaction
                .execute(
                    "UPDATE casework_events SET detail='{}'::jsonb WHERE item_id=ANY($1)",
                    &[&item_ids],
                )
                .await?;
            transaction
                .execute(
                    "UPDATE casework_audit_outbox a SET audit_record=((a.audit_record-'detail')-'reason')-'sourceReceipt' WHERE a.event_id IN (SELECT h.event_id FROM casework_history h WHERE h.item_id=ANY($1))",
                    &[&item_ids],
                )
                .await?;
            transaction
                .execute(
                    "DELETE FROM casework_cursors WHERE last_item_id=ANY($1)",
                    &[&item_ids],
                )
                .await?;
            transaction
                .execute(
                    "DELETE FROM casework_assignment_cursors WHERE last_item_id=ANY($1)",
                    &[&item_ids],
                )
                .await?;
        }
        let item_resources: Vec<String> = item_ids.iter().map(Uuid::to_string).collect();
        transaction
            .execute(
                "UPDATE casework_idempotency SET response=NULL WHERE response IS NOT NULL AND (resource=ANY($1) OR (operation='clock.recompute.apply' AND resource=ANY($2)))",
                &[&item_resources, &preview_resources],
            )
            .await?;
        transaction
            .execute(
                "DELETE FROM casework_clock_recompute_previews WHERE preview_id=ANY($1)",
                &[&preview_ids],
            )
            .await?;
        transaction
            .execute(
                "UPDATE casework_clock_calculations c SET source_timing=NULL FROM casework_clock_occurrences o WHERE c.clock_occurrence_id=o.clock_occurrence_id AND o.source_id=$1 AND o.subject_kind=$2 AND o.subject_id=$3",
                &[&selector.source_id, &selector.request_kind, &selector.request_id],
            )
            .await?;
        transaction
            .execute(
                "UPDATE casework_clock_occurrences SET state='cancelled',next_action_at=NULL,lease_token=NULL,lease_until=NULL,updated_at=$4 WHERE source_id=$1 AND subject_kind=$2 AND subject_id=$3 AND state<>'completed'",
                &[&selector.source_id, &selector.request_kind, &selector.request_id, &now],
            )
            .await?;
        let audit_event_id = Uuid::new_v4();
        let audit_record = serde_json::json!({
            "event": "casework.source_retention_erased",
            "eventId": audit_event_id,
            "selector": &report.selector,
            "counts": {
                "items": report.items,
                "drafts": report.drafts,
                "correctionContexts": report.correction_contexts,
                "attemptPayloads": report.attempt_payloads,
                "receiptPayloads": report.receipt_payloads,
                "historyDetails": report.history_details,
                "eventDetails": report.event_details,
                "idempotencyResponses": report.idempotency_responses,
                "auditRecords": report.audit_records,
                "clockOccurrences": report.clock_occurrences,
                "clockPreviews": report.clock_previews
            }
        });
        transaction
            .execute(
                "INSERT INTO casework_audit_outbox(event_id,audit_record) VALUES($1,$2)",
                &[&audit_event_id, &audit_record],
            )
            .await?;
        transaction.commit().await?;
        Ok(report)
    }
}

fn validate_selector(selector: &SourceRetentionSelector) -> Result<(), StoreError> {
    for value in [
        selector.source_id.as_str(),
        selector.request_kind.as_str(),
        selector.request_id.as_str(),
    ] {
        if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
            return Err(StoreError::Invalid);
        }
    }
    Ok(())
}

async fn lock_subject(
    transaction: &Transaction<'_>,
    selector: &SourceRetentionSelector,
) -> Result<(), StoreError> {
    transaction
        .query_opt(
            "SELECT source_id FROM casework_subjects WHERE source_id=$1 AND subject_kind=$2 AND subject_id=$3 FOR UPDATE",
            &[&selector.source_id, &selector.request_kind, &selector.request_id],
        )
        .await?
        .ok_or(StoreError::NotFound)?;
    Ok(())
}

async fn lock_items(
    transaction: &Transaction<'_>,
    selector: &SourceRetentionSelector,
) -> Result<Vec<Uuid>, StoreError> {
    Ok(transaction
        .query(
            "SELECT item_id FROM casework_items WHERE source_id=$1 AND subject_kind=$2 AND subject_id=$3 ORDER BY item_id FOR UPDATE",
            &[&selector.source_id, &selector.request_kind, &selector.request_id],
        )
        .await?
        .into_iter()
        .map(|row| row.get(0))
        .collect())
}

async fn retention_report(
    transaction: &Transaction<'_>,
    selector: &SourceRetentionSelector,
    applied: bool,
) -> Result<SourceRetentionReport, StoreError> {
    let row = transaction
        .query_one(
            "WITH selected_items AS (SELECT item_id FROM casework_items WHERE source_id=$1 AND subject_kind=$2 AND subject_id=$3), selected_history AS (SELECT event_id FROM casework_history WHERE item_id IN (SELECT item_id FROM selected_items)), selected_previews AS (SELECT DISTINCT p.preview_id FROM casework_clock_recompute_previews p JOIN casework_clock_occurrences o USING(clock_occurrence_id) WHERE o.source_id=$1 AND o.subject_kind=$2 AND o.subject_id=$3) SELECT
                (SELECT count(*) FROM casework_attempts WHERE item_id IN (SELECT item_id FROM selected_items) AND state IN ('pending','uncertain')),
                (SELECT count(*) FROM casework_items WHERE item_id IN (SELECT item_id FROM selected_items) AND erased_at IS NULL),
                (SELECT count(*) FROM casework_drafts WHERE item_id IN (SELECT item_id FROM selected_items)),
                (SELECT count(*) FROM casework_correction_context WHERE item_id IN (SELECT item_id FROM selected_items)),
                (SELECT count(*) FROM casework_attempts WHERE item_id IN (SELECT item_id FROM selected_items) AND state IN ('completed','refused') AND (decision_reason IS NOT NULL OR flagged_fields<>'[]'::jsonb OR displayed_binding IS NOT NULL OR recovery_evidence IS NOT NULL)),
                (SELECT count(*) FROM casework_attempts WHERE item_id IN (SELECT item_id FROM selected_items) AND receipt IS NOT NULL AND COALESCE(receipt->'metadata','{}'::jsonb)<>'{}'::jsonb),
                (SELECT count(*) FROM casework_history WHERE item_id IN (SELECT item_id FROM selected_items) AND detail<>'{}'::jsonb),
                (SELECT count(*) FROM casework_events WHERE item_id IN (SELECT item_id FROM selected_items) AND detail<>'{}'::jsonb),
                (SELECT count(*) FROM casework_idempotency WHERE response IS NOT NULL AND (resource IN (SELECT item_id::text FROM selected_items) OR (operation='clock.recompute.apply' AND resource IN (SELECT preview_id::text FROM selected_previews)))),
                (SELECT count(*) FROM casework_audit_outbox WHERE event_id IN (SELECT event_id FROM selected_history) AND (audit_record ? 'detail' OR audit_record ? 'reason' OR audit_record ? 'sourceReceipt')),
                (SELECT count(*) FROM casework_clock_occurrences o WHERE o.source_id=$1 AND o.subject_kind=$2 AND o.subject_id=$3 AND (o.state NOT IN ('completed','cancelled') OR o.next_action_at IS NOT NULL OR o.lease_token IS NOT NULL OR EXISTS(SELECT 1 FROM casework_clock_calculations c WHERE c.clock_occurrence_id=o.clock_occurrence_id AND c.source_timing IS NOT NULL))),
                (SELECT count(*) FROM casework_clock_recompute_previews WHERE preview_id IN (SELECT preview_id FROM selected_previews))",
            &[&selector.source_id, &selector.request_kind, &selector.request_id],
        )
        .await?;
    Ok(SourceRetentionReport {
        selector: selector.clone(),
        applied,
        blocked_live_attempts: count(&row, 0)?,
        items: count(&row, 1)?,
        drafts: count(&row, 2)?,
        correction_contexts: count(&row, 3)?,
        attempt_payloads: count(&row, 4)?,
        receipt_payloads: count(&row, 5)?,
        history_details: count(&row, 6)?,
        event_details: count(&row, 7)?,
        idempotency_responses: count(&row, 8)?,
        audit_records: count(&row, 9)?,
        clock_occurrences: count(&row, 10)?,
        clock_previews: count(&row, 11)?,
    })
}

fn count(row: &tokio_postgres::Row, index: usize) -> Result<u64, StoreError> {
    u64::try_from(row.get::<_, i64>(index)).map_err(|_| StoreError::Corrupt)
}
