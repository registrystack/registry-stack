// SPDX-License-Identifier: Apache-2.0

use chrono::{DateTime, TimeDelta, Utc};
use registry_casework_core::{
    evaluate_activity_clock, evaluate_subject_clock, transition, ActivityClockEvaluation,
    ActorContext, CalendarPolicy, CaseworkRole, ClockNextEffect, ClockOccurrenceView, ClockPolicy,
    ClockRecomputeChange, ClockRecomputePreview, ClockRecomputeResult, ClockRuntimeState,
    HistoryKind, HolidaySetDocument, OccurrenceEvent, OccurrenceKind, OccurrenceState,
    ReminderOccurrence, SourceAdapterError, StepOccurrence, SubjectRef,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio_postgres::Transaction;
use uuid::Uuid;

use crate::{CaseworkService, PostgresStore, ServiceError, StoreError};

const CLOCK_LEASE_SECONDS: i64 = 30;
const VERIFICATION_RETRY_SECONDS: i64 = 30;
const RECOMPUTE_PREVIEW_MINUTES: i64 = 15;

#[derive(Clone, Debug)]
pub(crate) struct ResolvedClockPolicy {
    pub clock: ClockPolicy,
    pub calendar: Option<CalendarPolicy>,
}

#[derive(Clone, Debug)]
pub(crate) struct ClockTimerClaim {
    pub clock_occurrence_id: Uuid,
    pub subject: SubjectRef,
    pub lease_token: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredCalculation {
    policy: ClockPolicy,
    calendar: Option<CalendarPolicy>,
    holiday_document: Option<HolidaySetDocument>,
    source_timing: Option<registry_casework_core::ReviewTiming>,
    anchor_at: DateTime<Utc>,
    started_at: DateTime<Utc>,
    due_at: Option<DateTime<Utc>>,
    at_risk_at: Option<DateTime<Utc>>,
    reminders: Vec<ReminderOccurrence>,
    steps: Vec<StepOccurrence>,
    completed_at: Option<DateTime<Utc>>,
}

impl PostgresStore {
    /// Store one immutable holiday revision. Repeating the exact document is
    /// idempotent; changing an existing revision is refused.
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
            transaction.commit().await?;
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
            transaction.commit().await?;
            return Ok(());
        }
        transaction.execute(
            "INSERT INTO casework_holiday_sets(holiday_set,revision,document,digest,created_at,created_by_issuer,created_by_subject,created_by_profile) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
            &[&document.holiday_set,&revision,&value,&digest,&Utc::now(),&actor.principal.issuer,&actor.principal.subject,&actor.profile_id],
        ).await?;
        append_clock_audit(
            &transaction,
            actor,
            "holiday_revision_created",
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
        transaction.commit().await?;
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

    pub async fn clock_occurrences_for_item(
        &self,
        item_id: Uuid,
    ) -> Result<Vec<ClockOccurrenceView>, StoreError> {
        let client = self.client().await?;
        let rows = client.query(
            "SELECT o.clock_occurrence_id,o.source_id,o.subject_kind,o.subject_id,o.clock_id,o.state,o.policy_digest,o.current_calculation_generation,o.recompute_generation,c.anchor_at,c.started_at,c.due_at,c.at_risk_at,c.completed_at,c.reminders,c.steps,COALESCE((SELECT jsonb_agg(jsonb_build_object('kind',e.effect_kind,'id',e.effect_id) ORDER BY e.effect_kind,e.effect_id) FROM casework_clock_effects e WHERE e.clock_occurrence_id=o.clock_occurrence_id),'[]'::jsonb) FROM casework_clock_occurrences o JOIN casework_items i ON i.item_id=o.item_id AND i.erased_at IS NULL LEFT JOIN casework_clock_calculations c ON c.clock_occurrence_id=o.clock_occurrence_id AND c.generation=o.current_calculation_generation WHERE o.item_id=$1 ORDER BY o.clock_id,o.clock_occurrence_id",
            &[&item_id],
        ).await?;
        rows.into_iter()
            .map(|row| {
                let state = parse_clock_state(&row.get::<_, String>(5))?;
                let next_effect = if matches!(
                    state,
                    ClockRuntimeState::Running
                        | ClockRuntimeState::Paused
                        | ClockRuntimeState::VerificationPending
                ) {
                    let reminders: Vec<ReminderOccurrence> = row
                        .get::<_, Option<Value>>(14)
                        .map(serde_json::from_value)
                        .transpose()?
                        .ok_or(StoreError::Corrupt)?;
                    let steps: Vec<StepOccurrence> = row
                        .get::<_, Option<Value>>(15)
                        .map(serde_json::from_value)
                        .transpose()?
                        .ok_or(StoreError::Corrupt)?;
                    let applied = serde_json::from_value::<Vec<AppliedEffect>>(row.get(16))?
                        .into_iter()
                        .map(|effect| (effect.kind, effect.id))
                        .collect();
                    next_unapplied_effect(&reminders, &steps, &applied)
                } else {
                    None
                };
                Ok(ClockOccurrenceView {
                    clock_occurrence_id: row.get(0),
                    subject: SubjectRef {
                        source_id: row.get(1),
                        kind: row.get(2),
                        id: row.get(3),
                    },
                    clock_id: row.get(4),
                    state,
                    policy_digest: row.get(6),
                    calculation_generation: row.get(7),
                    recompute_generation: row.get(8),
                    anchor_at: row.get(9),
                    started_at: row.get(10),
                    due_at: row.get(11),
                    at_risk_at: row.get(12),
                    completed_at: row.get(13),
                    next_effect,
                })
            })
            .collect()
    }

    pub async fn preview_clock_recompute(
        &self,
        actor: &ActorContext,
        request: &registry_casework_core::ClockRecomputeRequest,
    ) -> Result<ClockRecomputePreview, StoreError> {
        if actor.role != CaseworkRole::Administrator {
            return Err(StoreError::Forbidden);
        }
        let revision = i64::try_from(request.holiday_revision).map_err(|_| StoreError::Invalid)?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let holiday: HolidaySetDocument = transaction
            .query_opt(
                "SELECT document FROM casework_holiday_sets WHERE holiday_set=$1 AND revision=$2",
                &[&request.holiday_set, &revision],
            )
            .await?
            .map(|row| serde_json::from_value(row.get(0)))
            .transpose()?
            .ok_or(StoreError::NotFound)?;
        let rows=transaction.query(
            "SELECT o.clock_occurrence_id,o.item_id,o.current_calculation_generation,o.source_revision,o.source_etag,c.policy_digest,c.policy,c.calendar,c.anchor_at,c.started_at,c.source_timing,c.completed_at FROM casework_clock_occurrences o JOIN casework_items i ON i.item_id=o.item_id AND i.erased_at IS NULL JOIN casework_clock_calculations c ON c.clock_occurrence_id=o.clock_occurrence_id AND c.generation=o.current_calculation_generation WHERE o.clock_id=$1 AND o.scope='activity' AND o.state IN ('running','paused','verification_pending') ORDER BY o.clock_occurrence_id FOR UPDATE OF o LIMIT 101",
            &[&request.clock_id],
        ).await?;
        if rows.is_empty() || rows.len() > 100 {
            return Err(StoreError::Invalid);
        }
        let preview_id = Uuid::new_v4();
        let expires_at = Utc::now() + TimeDelta::minutes(RECOMPUTE_PREVIEW_MINUTES);
        let mut changes = Vec::with_capacity(rows.len());
        for row in rows {
            let occurrence_id: Uuid = row.get(0);
            let item_id: Uuid = row.get::<_, Option<Uuid>>(1).ok_or(StoreError::Corrupt)?;
            let generation: i64 = row.get(2);
            let source_revision: i64 = row.get(3);
            let source_etag: String = row.get(4);
            let policy_digest: String = row.get(5);
            let policy: ClockPolicy = serde_json::from_value(row.get(6))?;
            let calendar: CalendarPolicy =
                serde_json::from_value(row.get::<_, Option<Value>>(7).ok_or(StoreError::Corrupt)?)?;
            if calendar.holiday_set != request.holiday_set {
                return Err(StoreError::Invalid);
            }
            let anchor: DateTime<Utc> = row.get(8);
            let evaluated = evaluate_activity_clock(&policy, &calendar, &holiday, anchor)
                .map_err(|_| StoreError::Invalid)?;
            let old_due:DateTime<Utc>=transaction.query_one("SELECT due_at FROM casework_clock_calculations WHERE clock_occurrence_id=$1 AND generation=$2",&[&occurrence_id,&generation]).await?.get::<_,Option<DateTime<Utc>>>(0).ok_or(StoreError::Corrupt)?;
            transaction.execute(
                "INSERT INTO casework_clock_recompute_previews(preview_id,clock_occurrence_id,actor_issuer,actor_subject,profile_id,expected_calculation_generation,expected_source_revision,expected_source_etag,proposed_policy_digest,proposed_policy,proposed_calendar,proposed_holiday_document,proposed_due_at,proposed_at_risk_at,proposed_reminders,proposed_steps,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)",
                &[&preview_id,&occurrence_id,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&generation,&source_revision,&source_etag,&policy_digest,&serde_json::to_value(&policy)?,&serde_json::to_value(&calendar)?,&serde_json::to_value(&holiday)?,&evaluated.due_at,&evaluated.at_risk_at,&serde_json::to_value(&evaluated.reminders)?,&serde_json::to_value(&evaluated.steps)?,&expires_at],
            ).await?;
            changes.push(ClockRecomputeChange {
                clock_occurrence_id: occurrence_id,
                item_id,
                expected_calculation_generation: generation,
                old_due_at: old_due,
                proposed_due_at: evaluated.due_at,
            });
        }
        transaction.commit().await?;
        Ok(ClockRecomputePreview {
            preview_id,
            clock_id: request.clock_id.clone(),
            holiday_set: request.holiday_set.clone(),
            holiday_revision: request.holiday_revision,
            expires_at,
            changes,
        })
    }

    pub async fn apply_clock_recompute(
        &self,
        actor: &ActorContext,
        preview_id: Uuid,
        idempotency_key: &str,
    ) -> Result<ClockRecomputeResult, StoreError> {
        if actor.role != CaseworkRole::Administrator {
            return Err(StoreError::Forbidden);
        }
        if idempotency_key.is_empty() || idempotency_key.len() > 256 {
            return Err(StoreError::Invalid);
        }
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let lock_binding = format!(
            "clock-recompute:{}:{}:{}:{}",
            actor.principal.issuer, actor.principal.subject, actor.profile_id, idempotency_key
        );
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                &[&lock_binding],
            )
            .await?;
        let request_hash = digest_json(&json!({"previewId":preview_id}))?;
        if let Some(row)=transaction.query_opt("SELECT request_hash,response FROM casework_idempotency WHERE issuer=$1 AND subject=$2 AND profile_id=$3 AND operation='clock.recompute.apply' AND resource=$4 AND idempotency_key=$5 FOR UPDATE",&[&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&preview_id.to_string(),&idempotency_key]).await?{
            if row.get::<_,String>(0)!=request_hash{return Err(StoreError::IdempotencyConflict)}
            return serde_json::from_value(row.get::<_,Option<Value>>(1).ok_or(StoreError::IdempotencyExpired)?).map_err(StoreError::Json)
        }
        // Match reconciliation's subject -> item -> clock order across every
        // occurrence in this all-or-nothing preview.
        transaction.query(
            "SELECT s.source_id FROM casework_clock_recompute_previews p JOIN casework_clock_occurrences o ON o.clock_occurrence_id=p.clock_occurrence_id JOIN casework_subjects s ON s.source_id=o.source_id AND s.subject_kind=o.subject_kind AND s.subject_id=o.subject_id WHERE p.preview_id=$1 AND p.actor_issuer=$2 AND p.actor_subject=$3 AND p.profile_id=$4 ORDER BY s.source_id,s.subject_kind,s.subject_id FOR UPDATE OF s",
            &[&preview_id,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id],
        ).await?;
        transaction.query(
            "SELECT i.item_id FROM casework_clock_recompute_previews p JOIN casework_clock_occurrences o ON o.clock_occurrence_id=p.clock_occurrence_id JOIN casework_items i ON i.item_id=o.item_id WHERE p.preview_id=$1 AND p.actor_issuer=$2 AND p.actor_subject=$3 AND p.profile_id=$4 ORDER BY i.item_id FOR UPDATE OF i",
            &[&preview_id,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id],
        ).await?;
        let rows=transaction.query(
            "SELECT p.clock_occurrence_id,p.expected_calculation_generation,p.expected_source_revision,p.expected_source_etag,p.proposed_policy_digest,p.proposed_policy,p.proposed_calendar,p.proposed_holiday_document,p.proposed_due_at,p.proposed_at_risk_at,p.proposed_reminders,p.proposed_steps,p.expires_at,p.applied_at,o.item_id,o.recompute_generation,c.anchor_at,c.started_at,c.source_timing,c.completed_at,o.source_revision,o.source_etag,o.state,o.source_binding_generation,s.binding_generation,s.wanted_revision,s.applied_revision,s.representation_etag FROM casework_clock_recompute_previews p JOIN casework_clock_occurrences o ON o.clock_occurrence_id=p.clock_occurrence_id JOIN casework_clock_calculations c ON c.clock_occurrence_id=o.clock_occurrence_id AND c.generation=o.current_calculation_generation JOIN casework_subjects s ON s.source_id=o.source_id AND s.subject_kind=o.subject_kind AND s.subject_id=o.subject_id WHERE p.preview_id=$1 AND p.actor_issuer=$2 AND p.actor_subject=$3 AND p.profile_id=$4 ORDER BY p.clock_occurrence_id FOR UPDATE OF p,o",
            &[&preview_id,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id],
        ).await?;
        if rows.is_empty() {
            return Err(StoreError::NotFound);
        }
        if rows
            .iter()
            .any(|row| row.get::<_, DateTime<Utc>>(12) <= Utc::now())
        {
            return Err(StoreError::CursorExpired);
        }
        if rows
            .iter()
            .any(|row| row.get::<_, Option<DateTime<Utc>>>(13).is_some())
        {
            return Err(StoreError::Conflict);
        }
        let now = Utc::now();
        let mut applied = Vec::with_capacity(rows.len());
        for row in rows {
            let id: Uuid = row.get(0);
            let expected: i64 = row.get(1);
            let current:i64=transaction.query_one("SELECT current_calculation_generation FROM casework_clock_occurrences WHERE clock_occurrence_id=$1",&[&id]).await?.get(0);
            if current != expected {
                return Err(StoreError::Conflict);
            }
            if row.get::<_, i64>(2) != row.get::<_, i64>(20)
                || row.get::<_, String>(3) != row.get::<_, String>(21)
                || !matches!(
                    row.get::<_, String>(22).as_str(),
                    "running" | "paused" | "verification_pending"
                )
                || row.get::<_, String>(23) != row.get::<_, String>(24)
                || row.get::<_, i64>(25) > row.get::<_, i64>(2)
                || row.get::<_, i64>(26) != row.get::<_, i64>(2)
                || row.get::<_, Option<String>>(27).as_deref()
                    != Some(row.get::<_, String>(3).as_str())
            {
                return Err(StoreError::Conflict);
            }
            let next = current.checked_add(1).ok_or(StoreError::Corrupt)?;
            let recompute: i64 = row
                .get::<_, i64>(15)
                .checked_add(1)
                .ok_or(StoreError::Corrupt)?;
            let value = StoredCalculation {
                policy: serde_json::from_value(row.get(5))?,
                calendar: Some(serde_json::from_value(row.get(6))?),
                holiday_document: Some(serde_json::from_value(row.get(7))?),
                source_timing: row
                    .get::<_, Option<Value>>(18)
                    .map(serde_json::from_value)
                    .transpose()?,
                anchor_at: row.get(16),
                started_at: row.get(17),
                due_at: Some(row.get(8)),
                at_risk_at: row.get(9),
                reminders: serde_json::from_value(row.get(10))?,
                steps: serde_json::from_value(row.get(11))?,
                completed_at: row.get(19),
            };
            let digest: String = row.get(4);
            insert_calculation(&transaction, id, next, recompute, &digest, &value, now).await?;
            let next_action = next_unapplied_action(&transaction, id, &value, now).await?;
            transaction.execute("UPDATE casework_clock_occurrences SET current_calculation_generation=$2,recompute_generation=$3,next_action_at=$4,updated_at=$5 WHERE clock_occurrence_id=$1",&[&id,&next,&recompute,&next_action,&now]).await?;
            let item_id: Uuid = row.get::<_, Option<Uuid>>(14).ok_or(StoreError::Corrupt)?;
            let item = locked_item(&transaction, item_id).await?;
            if !item.state.is_active() {
                return Err(StoreError::Conflict);
            }
            crate::store::append_item_event(&transaction,&item,HistoryKind::ClockRecomputed,Some(actor),&actor.profile_id,json!({"clockOccurrenceId":id,"calculationGeneration":next,"recomputeGeneration":recompute,"oldCalculationGeneration":current,"dueAt":value.due_at})).await?;
            transaction.execute("UPDATE casework_clock_recompute_previews SET applied_at=$3 WHERE preview_id=$1 AND clock_occurrence_id=$2",&[&preview_id,&id,&now]).await?;
            applied.push(id);
        }
        let result = ClockRecomputeResult {
            preview_id,
            applied_occurrences: applied,
        };
        transaction.execute("INSERT INTO casework_idempotency(issuer,subject,profile_id,operation,resource,idempotency_key,request_hash,response,created_at) VALUES($1,$2,$3,'clock.recompute.apply',$4,$5,$6,$7,$8)",&[&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&preview_id.to_string(),&idempotency_key,&request_hash,&serde_json::to_value(&result)?,&now]).await?;
        transaction.commit().await?;
        Ok(result)
    }

    pub(crate) async fn claim_due_clocks(
        &self,
        maximum: i64,
    ) -> Result<Vec<ClockTimerClaim>, StoreError> {
        let limit = maximum.clamp(1, 100);
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let rows = transaction.query(
            "SELECT o.clock_occurrence_id,o.source_id,o.subject_kind,o.subject_id FROM casework_clock_occurrences o LEFT JOIN casework_items i ON i.item_id=o.item_id JOIN casework_subjects s ON s.source_id=o.source_id AND s.subject_kind=o.subject_kind AND s.subject_id=o.subject_id AND s.erased_at IS NULL WHERE (o.item_id IS NULL OR i.erased_at IS NULL) AND o.state IN ('running','verification_pending') AND o.next_action_at<=now() AND (o.lease_until IS NULL OR o.lease_until<now()) ORDER BY o.next_action_at,o.clock_occurrence_id FOR UPDATE OF o SKIP LOCKED LIMIT $1",
            &[&limit],
        ).await?;
        let mut claims = Vec::with_capacity(rows.len());
        for row in rows {
            let id: Uuid = row.get(0);
            let token = Uuid::new_v4();
            transaction.execute(
                "UPDATE casework_clock_occurrences SET state='verification_pending',lease_token=$2,lease_until=now()+make_interval(secs=>$3::int),updated_at=now() WHERE clock_occurrence_id=$1",
                &[&id,&token,&i32::try_from(CLOCK_LEASE_SECONDS).map_err(|_| StoreError::Invalid)?],
            ).await?;
            claims.push(ClockTimerClaim {
                clock_occurrence_id: id,
                subject: SubjectRef {
                    source_id: row.get(1),
                    kind: row.get(2),
                    id: row.get(3),
                },
                lease_token: token,
            });
        }
        transaction.commit().await?;
        Ok(claims)
    }

    pub async fn erase_expired_clock_previews(&self) -> Result<usize, StoreError> {
        let client = self.client().await?;
        let affected=client.execute(
            "WITH due AS (SELECT preview_id,clock_occurrence_id FROM casework_clock_recompute_previews WHERE expires_at<=now() ORDER BY expires_at,preview_id,clock_occurrence_id LIMIT 100 FOR UPDATE SKIP LOCKED) DELETE FROM casework_clock_recompute_previews p USING due WHERE p.preview_id=due.preview_id AND p.clock_occurrence_id=due.clock_occurrence_id",
            &[],
        ).await?;
        usize::try_from(affected).map_err(|_| StoreError::Corrupt)
    }

    pub(crate) async fn defer_clock_claim(
        &self,
        claim: &ClockTimerClaim,
    ) -> Result<(), StoreError> {
        let client = self.client().await?;
        client.execute(
            "UPDATE casework_clock_occurrences SET state='verification_pending',next_action_at=now()+make_interval(secs=>$3::int),lease_token=NULL,lease_until=NULL,updated_at=now() WHERE clock_occurrence_id=$1 AND lease_token=$2",
            &[&claim.clock_occurrence_id,&claim.lease_token,&i32::try_from(VERIFICATION_RETRY_SECONDS).map_err(|_| StoreError::Invalid)?],
        ).await?;
        Ok(())
    }

    /// Commit due effects only after the service has applied this exact fresh
    /// authoritative observation to `casework_subjects`.
    pub(crate) async fn apply_clock_claim(
        &self,
        claim: &ClockTimerClaim,
        observation: &registry_casework_core::AuthoritativeObservation,
    ) -> Result<usize, StoreError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        // Reconciliation uses subject -> item -> clock. Preserve that order so
        // a timer cannot deadlock with a source transition for this subject.
        let subject = transaction.query_opt(
            "SELECT binding_generation,wanted_revision,applied_revision,representation_etag,erased_at FROM casework_subjects WHERE source_id=$1 AND subject_kind=$2 AND subject_id=$3 FOR UPDATE",
            &[&observation.subject.source_id,&observation.subject.kind,&observation.subject.id],
        ).await?.ok_or(StoreError::Conflict)?;
        if subject.get::<_, Option<DateTime<Utc>>>(4).is_some() {
            transaction.execute(
                "UPDATE casework_clock_occurrences SET state='cancelled',next_action_at=NULL,lease_token=NULL,lease_until=NULL,updated_at=now() WHERE clock_occurrence_id=$1 AND lease_token=$2",
                &[&claim.clock_occurrence_id, &claim.lease_token],
            ).await?;
            transaction.commit().await?;
            return Ok(0);
        }
        let preview_item = transaction
            .query_opt(
                "SELECT item_id FROM casework_clock_occurrences WHERE clock_occurrence_id=$1",
                &[&claim.clock_occurrence_id],
            )
            .await?
            .and_then(|row| row.get::<_, Option<Uuid>>(0));
        let Some(preview_item) = preview_item else {
            return Err(StoreError::Conflict);
        };
        let mut item = locked_item(&transaction, preview_item).await?;
        let occurrence = transaction.query_opt(
            "SELECT state,scope,scope_key,item_id,current_calculation_generation,source_binding_generation,source_revision,source_etag FROM casework_clock_occurrences WHERE clock_occurrence_id=$1 AND lease_token=$2 FOR UPDATE",
            &[&claim.clock_occurrence_id,&claim.lease_token],
        ).await?;
        let Some(occurrence) = occurrence else {
            let state=transaction.query_opt(
                "SELECT state FROM casework_clock_occurrences WHERE clock_occurrence_id=$1 FOR UPDATE",
                &[&claim.clock_occurrence_id],
            ).await?.map(|row|row.get::<_,String>(0));
            if state
                .as_deref()
                .is_some_and(|value| matches!(value, "completed" | "cancelled"))
            {
                transaction.commit().await?;
                return Ok(0);
            }
            return Err(StoreError::Conflict);
        };
        let state: String = occurrence.get(0);
        if !matches!(state.as_str(), "running" | "verification_pending") {
            transaction.commit().await?;
            return Ok(0);
        }
        let scope: String = occurrence.get(1);
        let scope_key: String = occurrence.get(2);
        let item_id: Option<Uuid> = occurrence.get(3);
        let generation: i64 = occurrence.get(4);
        let source_current = subject.get::<_, String>(0) == observation.binding.generation
            && subject.get::<_, i64>(1) <= observation.ordered_revision
            && subject.get::<_, i64>(2) == observation.ordered_revision
            && subject.get::<_, Option<String>>(3).as_deref()
                == Some(&observation.representation_etag)
            && occurrence.get::<_, String>(5) == observation.binding.generation
            && occurrence.get::<_, i64>(6) == observation.ordered_revision
            && occurrence.get::<_, String>(7) == observation.representation_etag;
        let occurrence_current = scope == "subject"
            || (scope == "activity"
                && observation.occurrence_kind == OccurrenceKind::Review
                && scope_key == observation.occurrence_key
                && observation.state.is_active());
        if !source_current || !occurrence_current {
            transaction.execute(
                "UPDATE casework_clock_occurrences SET state=CASE WHEN $3 THEN 'cancelled' ELSE 'verification_pending' END,next_action_at=CASE WHEN $3 THEN NULL ELSE now()+make_interval(secs=>$4::int) END,lease_token=NULL,lease_until=NULL,updated_at=now() WHERE clock_occurrence_id=$1 AND lease_token=$2",
                &[&claim.clock_occurrence_id,&claim.lease_token,&(!occurrence_current),&i32::try_from(VERIFICATION_RETRY_SECONDS).map_err(|_|StoreError::Invalid)?],
            ).await?;
            transaction.commit().await?;
            return Ok(0);
        }
        let item_id = item_id.ok_or(StoreError::Corrupt)?;
        if item_id != preview_item {
            return Err(StoreError::Conflict);
        }
        let attempt: bool = transaction.query_one(
            "SELECT EXISTS(SELECT 1 FROM casework_attempts WHERE item_id=$1 AND state IN ('pending','uncertain'))",
            &[&item_id],
        ).await?.get(0);
        if attempt || item.state == OccurrenceState::Synchronizing || !item.state.is_active() {
            transaction.execute(
                "UPDATE casework_clock_occurrences SET next_action_at=now()+make_interval(secs=>$3::int),lease_token=NULL,lease_until=NULL,updated_at=now() WHERE clock_occurrence_id=$1 AND lease_token=$2",
                &[&claim.clock_occurrence_id,&claim.lease_token,&i32::try_from(VERIFICATION_RETRY_SECONDS).map_err(|_|StoreError::Invalid)?],
            ).await?;
            transaction.commit().await?;
            return Ok(0);
        }
        let calculation =
            load_calculation(&transaction, claim.clock_occurrence_id, generation).await?;
        let now = Utc::now();
        let mut applied = 0usize;
        for reminder in calculation.reminders.iter().filter(|item| item.at <= now) {
            if reserve_effect(
                &transaction,
                claim.clock_occurrence_id,
                generation,
                "reminder",
                &reminder.id,
                now,
            )
            .await?
            {
                let event_id = crate::store::append_item_event(
                    &transaction,&item,HistoryKind::ClockReminder,None,"system:clock",
                    json!({"clockOccurrenceId":claim.clock_occurrence_id,"clockId":calculation.policy.id(),"effectId":reminder.id,"calculationGeneration":generation,"at":reminder.at}),
                ).await?;
                attach_effect_event(
                    &transaction,
                    claim.clock_occurrence_id,
                    "reminder",
                    &reminder.id,
                    event_id,
                )
                .await?;
                applied += 1;
            }
        }
        for step in calculation.steps.iter().filter(|item| item.at <= now) {
            let served: bool = transaction
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM casework_queue_service WHERE queue_id=$1)",
                    &[&step.reassign_queue],
                )
                .await?
                .get(0);
            if !served {
                transaction.execute(
                    "UPDATE casework_clock_occurrences SET state='verification_pending',next_action_at=now()+make_interval(secs=>$3::int),lease_token=NULL,lease_until=NULL,updated_at=now() WHERE clock_occurrence_id=$1 AND lease_token=$2",
                    &[&claim.clock_occurrence_id,&claim.lease_token,&i32::try_from(VERIFICATION_RETRY_SECONDS).map_err(|_|StoreError::Invalid)?],
                ).await?;
                transaction.commit().await?;
                return Ok(applied);
            }
            if reserve_effect(
                &transaction,
                claim.clock_occurrence_id,
                generation,
                "step",
                &step.id,
                now,
            )
            .await?
            {
                let prior_queue = item.queue_id.clone();
                let prior_holder = item.holder.clone();
                if item.state == OccurrenceState::Claimed {
                    item.state = transition(item.state, OccurrenceEvent::Release)
                        .map_err(|_| StoreError::Corrupt)?;
                }
                item.queue_id.clone_from(&step.reassign_queue);
                item.holder = None;
                item.assignment = None;
                item.revision = item.revision.checked_add(1).ok_or(StoreError::Corrupt)?;
                item.updated_at = now;
                transaction.execute(
                    "UPDATE casework_items SET queue_id=$2,state=$3,holder_issuer=NULL,holder_subject=NULL,assignment_owner_issuer=NULL,assignment_owner_subject=NULL,assigned_by_issuer=NULL,assigned_by_subject=NULL,assignment_absence_ids='{}',staffing_diagnostic=NULL,revision=$4,updated_at=$5 WHERE item_id=$1",
                    &[&item.item_id,&item.queue_id,&state_name(item.state),&item.revision,&now],
                ).await?;
                let event_id = crate::store::append_item_event(
                    &transaction,&item,HistoryKind::ClockStepApplied,None,"system:clock",
                    json!({"clockOccurrenceId":claim.clock_occurrence_id,"clockId":calculation.policy.id(),"effectId":step.id,"because":step.because,"calculationGeneration":generation,"previousQueue":prior_queue,"queue":step.reassign_queue,"previousHolder":prior_holder}),
                ).await?;
                attach_effect_event(
                    &transaction,
                    claim.clock_occurrence_id,
                    "step",
                    &step.id,
                    event_id,
                )
                .await?;
                applied += 1;
            }
        }
        let next =
            next_unapplied_action(&transaction, claim.clock_occurrence_id, &calculation, now)
                .await?;
        transaction.execute(
            "UPDATE casework_clock_occurrences SET state='running',next_action_at=$3,lease_token=NULL,lease_until=NULL,updated_at=$4 WHERE clock_occurrence_id=$1 AND lease_token=$2",
            &[&claim.clock_occurrence_id,&claim.lease_token,&next,&now],
        ).await?;
        transaction.commit().await?;
        Ok(applied)
    }
}

impl CaseworkService {
    pub async fn work_item_clocks(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        source_profile_id: &str,
        token: &str,
    ) -> Result<Vec<ClockOccurrenceView>, ServiceError> {
        Ok(self
            .caller_item(actor, item_id, source_profile_id, token)
            .await?
            .0
            .clock_occurrences)
    }

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

    pub async fn preview_clock_recompute(
        &self,
        actor: &ActorContext,
        request: &registry_casework_core::ClockRecomputeRequest,
    ) -> Result<ClockRecomputePreview, ServiceError> {
        self.store
            .preview_clock_recompute(actor, request)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn apply_clock_recompute(
        &self,
        actor: &ActorContext,
        preview_id: Uuid,
        idempotency_key: &str,
    ) -> Result<ClockRecomputeResult, ServiceError> {
        self.store
            .apply_clock_recompute(actor, preview_id, idempotency_key)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn process_due_clocks(&self, maximum: i64) -> Result<usize, ServiceError> {
        let claims = self.store.claim_due_clocks(maximum).await?;
        let mut applied = 0usize;
        for claim in claims {
            let adapter = self.adapter(&claim.subject.source_id)?;
            let observation = match adapter.read_authoritative(&claim.subject).await {
                Ok(value) => value,
                Err(SourceAdapterError::Unavailable | SourceAdapterError::Concealed) => {
                    self.store.defer_clock_claim(&claim).await?;
                    continue;
                }
                Err(error) => {
                    self.store.defer_clock_claim(&claim).await?;
                    return Err(error.into());
                }
            };
            let (routing, target) = self.routing_policy_for(&observation)?;
            let clock = self.clock_policy_for(&observation.subject)?;
            self.store
                .apply_observation_with_context(
                    &observation,
                    &routing.queue,
                    target,
                    Some(&routing),
                    clock.as_ref(),
                )
                .await?;
            applied += self.store.apply_clock_claim(&claim, &observation).await?;
        }
        Ok(applied)
    }

    pub async fn erase_expired_clock_previews(&self) -> Result<usize, ServiceError> {
        self.store
            .erase_expired_clock_previews()
            .await
            .map_err(ServiceError::from)
    }
}

pub(crate) async fn reconcile_clock_observation(
    transaction: &Transaction<'_>,
    observation: &registry_casework_core::AuthoritativeObservation,
    binding: Option<&ResolvedClockPolicy>,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let Some(binding) = binding else {
        return Ok(());
    };
    let policy_value = serde_json::to_value(&binding.clock)?;
    let policy_digest = digest_json(&policy_value)?;
    let (scope, scope_key) = match &binding.clock {
        ClockPolicy::Subject { .. } => ("subject", "subject".to_owned()),
        ClockPolicy::Activity { .. } => ("activity", observation.occurrence_key.clone()),
    };
    let existing = transaction.query_opt(
        "SELECT clock_occurrence_id,state,current_calculation_generation,policy_digest,recompute_generation FROM casework_clock_occurrences WHERE source_id=$1 AND subject_kind=$2 AND subject_id=$3 AND clock_id=$4 AND scope=$5 AND scope_key=$6 FOR UPDATE",
        &[&observation.subject.source_id,&observation.subject.kind,&observation.subject.id,&binding.clock.id(),&scope,&scope_key],
    ).await?;
    if existing
        .as_ref()
        .is_some_and(|row| row.get::<_, String>(1) == "completed")
    {
        return Ok(());
    }
    if scope == "activity" {
        transaction.execute(
            "UPDATE casework_clock_occurrences SET state='cancelled',next_action_at=NULL,lease_token=NULL,lease_until=NULL,updated_at=$6 WHERE source_id=$1 AND subject_kind=$2 AND subject_id=$3 AND clock_id=$4 AND scope='activity' AND scope_key<>$5 AND state NOT IN ('completed','cancelled')",
            &[&observation.subject.source_id,&observation.subject.kind,&observation.subject.id,&binding.clock.id(),&scope_key,&now],
        ).await?;
    }
    if scope == "activity"
        && (observation.occurrence_kind != OccurrenceKind::Review || !observation.state.is_active())
    {
        transaction.execute(
            "UPDATE casework_clock_occurrences SET state='cancelled',next_action_at=NULL,lease_token=NULL,lease_until=NULL,updated_at=$5 WHERE source_id=$1 AND subject_kind=$2 AND subject_id=$3 AND clock_id=$4 AND scope='activity' AND state NOT IN ('completed','cancelled')",
            &[&observation.subject.source_id,&observation.subject.kind,&observation.subject.id,&binding.clock.id(),&now],
        ).await?;
        return Ok(());
    }
    let item_id = transaction.query_opt(
        "SELECT item_id FROM casework_items WHERE source_id=$1 AND subject_kind=$2 AND subject_id=$3 AND occurrence_key=$4 ORDER BY updated_at DESC LIMIT 1",
        &[&observation.subject.source_id,&observation.subject.kind,&observation.subject.id,&observation.occurrence_key],
    ).await?.map(|row| row.get::<_,Uuid>(0));
    let Some(item_id) = item_id else {
        return Ok(());
    };

    let existed = existing.is_some();
    let (id, generation, recompute_generation, pinned) = if let Some(row) = existing {
        let id: Uuid = row.get(0);
        let generation: i64 = row.get(2);
        let recompute_generation: i64 = row.get(4);
        let pinned = if generation > 0 {
            Some(load_calculation(transaction, id, generation).await?)
        } else {
            None
        };
        (id, generation, recompute_generation, pinned)
    } else {
        (Uuid::new_v4(), 0, 0, None)
    };
    let calculation = calculate_observation(
        transaction,
        observation,
        pinned
            .as_ref()
            .map_or(&binding.clock, |value| &value.policy),
        pinned
            .as_ref()
            .and_then(|value| value.calendar.as_ref())
            .or(binding.calendar.as_ref()),
        pinned
            .as_ref()
            .and_then(|value| value.holiday_document.as_ref()),
        now,
    )
    .await?;
    let Some(calculation) = calculation else {
        if !existed {
            transaction.execute(
                "INSERT INTO casework_clock_occurrences(clock_occurrence_id,source_id,subject_kind,subject_id,clock_id,scope,scope_key,item_id,state,policy_digest,current_calculation_generation,recompute_generation,source_binding_generation,source_revision,source_etag,next_action_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'source_facts_missing',$9,0,0,$10,$11,$12,NULL,$13,$13) ON CONFLICT(source_id,subject_kind,subject_id,clock_id,scope,scope_key) DO NOTHING",
                &[&id,&observation.subject.source_id,&observation.subject.kind,&observation.subject.id,&binding.clock.id(),&scope,&scope_key,&item_id,&policy_digest,&observation.binding.generation,&observation.ordered_revision,&observation.representation_etag,&now],
            ).await?;
        } else {
            transaction.execute(
                "UPDATE casework_clock_occurrences SET item_id=$2,state='source_facts_missing',source_binding_generation=$3,source_revision=$4,source_etag=$5,next_action_at=NULL,lease_token=NULL,lease_until=NULL,updated_at=$6 WHERE clock_occurrence_id=$1",
                &[&id,&item_id,&observation.binding.generation,&observation.ordered_revision,&observation.representation_etag,&now],
            ).await?;
        }
        return Ok(());
    };
    let next_generation = generation.checked_add(1).ok_or(StoreError::Corrupt)?;
    let derived_state = calculation_state(&calculation);
    let next_action = if existed {
        next_unapplied_action(transaction, id, &calculation, now).await?
    } else {
        earliest_action(&calculation, now)
    };
    if generation == 0 && !existed {
        transaction.execute(
            "INSERT INTO casework_clock_occurrences(clock_occurrence_id,source_id,subject_kind,subject_id,clock_id,scope,scope_key,item_id,state,policy_digest,current_calculation_generation,recompute_generation,source_binding_generation,source_revision,source_etag,next_action_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,1,0,$11,$12,$13,$14,$15,$15) ON CONFLICT(source_id,subject_kind,subject_id,clock_id,scope,scope_key) DO NOTHING",
            &[&id,&observation.subject.source_id,&observation.subject.kind,&observation.subject.id,&binding.clock.id(),&scope,&scope_key,&item_id,&clock_state_name(derived_state),&policy_digest,&observation.binding.generation,&observation.ordered_revision,&observation.representation_etag,&next_action,&now],
        ).await?;
        insert_calculation(transaction, id, 1, 0, &policy_digest, &calculation, now).await?;
    } else if generation == 0 {
        insert_calculation(
            transaction,
            id,
            1,
            recompute_generation,
            &policy_digest,
            &calculation,
            now,
        )
        .await?;
        transaction.execute(
            "UPDATE casework_clock_occurrences SET item_id=$2,state=$3,policy_digest=$4,current_calculation_generation=1,source_binding_generation=$5,source_revision=$6,source_etag=$7,next_action_at=$8,updated_at=$9 WHERE clock_occurrence_id=$1",
            &[&id,&item_id,&clock_state_name(derived_state),&policy_digest,&observation.binding.generation,&observation.ordered_revision,&observation.representation_etag,&next_action,&now],
        ).await?;
    } else {
        let prior = pinned.ok_or(StoreError::Corrupt)?;
        let changed = prior.source_timing != calculation.source_timing
            || prior.anchor_at != calculation.anchor_at
            || prior.due_at != calculation.due_at
            || prior.completed_at != calculation.completed_at;
        let actual_generation = if changed {
            insert_calculation(
                transaction,
                id,
                next_generation,
                recompute_generation,
                &row_policy_digest(transaction, id, generation).await?,
                &calculation,
                now,
            )
            .await?;
            next_generation
        } else {
            generation
        };
        transaction.execute(
            "UPDATE casework_clock_occurrences SET item_id=$2,state=$3,current_calculation_generation=$4,source_binding_generation=$5,source_revision=$6,source_etag=$7,next_action_at=$8,updated_at=$9 WHERE clock_occurrence_id=$1",
            &[&id,&item_id,&clock_state_name(derived_state),&actual_generation,&observation.binding.generation,&observation.ordered_revision,&observation.representation_etag,&next_action,&now],
        ).await?;
    }
    Ok(())
}

async fn calculate_observation(
    transaction: &Transaction<'_>,
    observation: &registry_casework_core::AuthoritativeObservation,
    policy: &ClockPolicy,
    calendar: Option<&CalendarPolicy>,
    pinned_holiday: Option<&HolidaySetDocument>,
    now: DateTime<Utc>,
) -> Result<Option<StoredCalculation>, StoreError> {
    match policy {
        ClockPolicy::Subject { .. } => {
            let Some(timing) = observation.review_timing.as_ref() else {
                return Ok(None);
            };
            let evaluated =
                evaluate_subject_clock(policy, timing, now).map_err(|_| StoreError::Invalid)?;
            Ok(Some(StoredCalculation {
                policy: policy.clone(),
                calendar: None,
                holiday_document: None,
                source_timing: Some(timing.clone()),
                anchor_at: timing.first_submitted_at,
                started_at: timing.first_submitted_at,
                due_at: evaluated.due_at,
                at_risk_at: None,
                reminders: Vec::new(),
                steps: Vec::new(),
                completed_at: timing.completed_at,
            }))
        }
        ClockPolicy::Activity {
            calendar: calendar_id,
            ..
        } => {
            let Some(anchor) = observation.stage_entered_at else {
                return Ok(None);
            };
            let calendar = calendar.ok_or(StoreError::Invalid)?;
            let holiday = if let Some(value) = pinned_holiday {
                value.clone()
            } else {
                let Some(row) = transaction.query_opt(
                    "SELECT document FROM casework_holiday_sets WHERE holiday_set=$1 ORDER BY revision DESC LIMIT 1",
                    &[&calendar.holiday_set],
                ).await? else { return Ok(None) };
                serde_json::from_value(row.get(0))?
            };
            if calendar.id != *calendar_id {
                return Err(StoreError::Invalid);
            }
            let evaluated: ActivityClockEvaluation =
                evaluate_activity_clock(policy, calendar, &holiday, anchor)
                    .map_err(|_| StoreError::Invalid)?;
            Ok(Some(StoredCalculation {
                policy: policy.clone(),
                calendar: Some(calendar.clone()),
                holiday_document: Some(holiday),
                source_timing: None,
                anchor_at: anchor,
                started_at: anchor,
                due_at: Some(evaluated.due_at),
                at_risk_at: evaluated.at_risk_at,
                reminders: evaluated.reminders,
                steps: evaluated.steps,
                completed_at: None,
            }))
        }
    }
}

async fn insert_calculation(
    transaction: &Transaction<'_>,
    id: Uuid,
    generation: i64,
    recompute: i64,
    digest: &str,
    value: &StoredCalculation,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO casework_clock_calculations(clock_occurrence_id,generation,recompute_generation,policy_digest,policy,calendar,holiday_document,source_timing,anchor_at,started_at,due_at,at_risk_at,reminders,steps,completed_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
        &[&id,&generation,&recompute,&digest,&serde_json::to_value(&value.policy)?,&value.calendar.as_ref().map(serde_json::to_value).transpose()?,&value.holiday_document.as_ref().map(serde_json::to_value).transpose()?,&value.source_timing.as_ref().map(serde_json::to_value).transpose()?,&value.anchor_at,&value.started_at,&value.due_at,&value.at_risk_at,&serde_json::to_value(&value.reminders)?,&serde_json::to_value(&value.steps)?,&value.completed_at,&now],
    ).await?;
    Ok(())
}

async fn load_calculation(
    transaction: &Transaction<'_>,
    id: Uuid,
    generation: i64,
) -> Result<StoredCalculation, StoreError> {
    let row=transaction.query_opt("SELECT policy,calendar,holiday_document,source_timing,anchor_at,started_at,due_at,at_risk_at,reminders,steps,completed_at FROM casework_clock_calculations WHERE clock_occurrence_id=$1 AND generation=$2",&[&id,&generation]).await?.ok_or(StoreError::Corrupt)?;
    Ok(StoredCalculation {
        policy: serde_json::from_value(row.get(0))?,
        calendar: row
            .get::<_, Option<Value>>(1)
            .map(serde_json::from_value)
            .transpose()?,
        holiday_document: row
            .get::<_, Option<Value>>(2)
            .map(serde_json::from_value)
            .transpose()?,
        source_timing: row
            .get::<_, Option<Value>>(3)
            .map(serde_json::from_value)
            .transpose()?,
        anchor_at: row.get(4),
        started_at: row.get(5),
        due_at: row.get(6),
        at_risk_at: row.get(7),
        reminders: serde_json::from_value(row.get(8))?,
        steps: serde_json::from_value(row.get(9))?,
        completed_at: row.get(10),
    })
}

async fn row_policy_digest(
    transaction: &Transaction<'_>,
    id: Uuid,
    generation: i64,
) -> Result<String, StoreError> {
    Ok(transaction.query_one("SELECT policy_digest FROM casework_clock_calculations WHERE clock_occurrence_id=$1 AND generation=$2",&[&id,&generation]).await?.get(0))
}

async fn locked_item(
    transaction: &Transaction<'_>,
    item_id: Uuid,
) -> Result<registry_casework_core::WorkItem, StoreError> {
    let row = transaction
        .query_opt(
            "SELECT * FROM casework_items WHERE item_id=$1 FOR UPDATE",
            &[&item_id],
        )
        .await?
        .ok_or(StoreError::NotFound)?;
    crate::store::row_to_item(&row)
}

async fn reserve_effect(
    transaction: &Transaction<'_>,
    id: Uuid,
    generation: i64,
    kind: &str,
    effect: &str,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let placeholder = Uuid::new_v4();
    Ok(transaction.execute("INSERT INTO casework_clock_effects(clock_occurrence_id,effect_kind,effect_id,calculation_generation,event_id,applied_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(clock_occurrence_id,effect_kind,effect_id) DO NOTHING",&[&id,&kind,&effect,&generation,&placeholder,&now]).await?==1)
}

async fn attach_effect_event(
    transaction: &Transaction<'_>,
    id: Uuid,
    kind: &str,
    effect: &str,
    event: Uuid,
) -> Result<(), StoreError> {
    transaction.execute("UPDATE casework_clock_effects SET event_id=$4 WHERE clock_occurrence_id=$1 AND effect_kind=$2 AND effect_id=$3",&[&id,&kind,&effect,&event]).await?;
    Ok(())
}

async fn next_unapplied_action(
    transaction: &Transaction<'_>,
    id: Uuid,
    value: &StoredCalculation,
    _now: DateTime<Utc>,
) -> Result<Option<DateTime<Utc>>, StoreError> {
    let rows = transaction
        .query(
            "SELECT effect_kind,effect_id FROM casework_clock_effects WHERE clock_occurrence_id=$1",
            &[&id],
        )
        .await?;
    let applied = rows
        .into_iter()
        .map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)))
        .collect::<std::collections::BTreeSet<_>>();
    Ok(
        next_unapplied_effect(&value.reminders, &value.steps, &applied)
            .as_ref()
            .map(clock_effect_at),
    )
}

fn earliest_action(value: &StoredCalculation, _now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    next_unapplied_effect(
        &value.reminders,
        &value.steps,
        &std::collections::BTreeSet::new(),
    )
    .as_ref()
    .map(clock_effect_at)
}

#[derive(Deserialize)]
struct AppliedEffect {
    kind: String,
    id: String,
}

fn next_unapplied_effect(
    reminders: &[ReminderOccurrence],
    steps: &[StepOccurrence],
    applied: &std::collections::BTreeSet<(String, String)>,
) -> Option<ClockNextEffect> {
    reminders
        .iter()
        .filter(|effect| !applied.contains(&("reminder".to_owned(), effect.id.clone())))
        .map(|effect| ClockNextEffect::Reminder {
            id: effect.id.clone(),
            at: effect.at,
        })
        .chain(
            steps
                .iter()
                .filter(|effect| !applied.contains(&("step".to_owned(), effect.id.clone())))
                .map(|effect| ClockNextEffect::Reassign {
                    id: effect.id.clone(),
                    at: effect.at,
                    because: effect.because.clone(),
                    queue_id: effect.reassign_queue.clone(),
                }),
        )
        .min_by(|left, right| {
            clock_effect_at(left)
                .cmp(&clock_effect_at(right))
                .then_with(|| clock_effect_order(left).cmp(&clock_effect_order(right)))
                .then_with(|| clock_effect_id(left).cmp(clock_effect_id(right)))
        })
}

fn clock_effect_at(effect: &ClockNextEffect) -> DateTime<Utc> {
    match effect {
        ClockNextEffect::Reminder { at, .. } | ClockNextEffect::Reassign { at, .. } => *at,
    }
}

fn clock_effect_order(effect: &ClockNextEffect) -> u8 {
    match effect {
        ClockNextEffect::Reminder { .. } => 0,
        ClockNextEffect::Reassign { .. } => 1,
    }
}

fn clock_effect_id(effect: &ClockNextEffect) -> &str {
    match effect {
        ClockNextEffect::Reminder { id, .. } | ClockNextEffect::Reassign { id, .. } => id,
    }
}

fn calculation_state(value: &StoredCalculation) -> ClockRuntimeState {
    if value.completed_at.is_some() {
        ClockRuntimeState::Completed
    } else if value
        .source_timing
        .as_ref()
        .is_some_and(|timing| timing.pause_started_at.is_some())
    {
        ClockRuntimeState::Paused
    } else {
        ClockRuntimeState::Running
    }
}

fn clock_state_name(value: ClockRuntimeState) -> &'static str {
    match value {
        ClockRuntimeState::Running => "running",
        ClockRuntimeState::Paused => "paused",
        ClockRuntimeState::Completed => "completed",
        ClockRuntimeState::Cancelled => "cancelled",
        ClockRuntimeState::VerificationPending => "verification_pending",
        ClockRuntimeState::SourceFactsMissing => "source_facts_missing",
    }
}
fn parse_clock_state(value: &str) -> Result<ClockRuntimeState, StoreError> {
    match value {
        "running" => Ok(ClockRuntimeState::Running),
        "paused" => Ok(ClockRuntimeState::Paused),
        "completed" => Ok(ClockRuntimeState::Completed),
        "cancelled" => Ok(ClockRuntimeState::Cancelled),
        "verification_pending" => Ok(ClockRuntimeState::VerificationPending),
        "source_facts_missing" => Ok(ClockRuntimeState::SourceFactsMissing),
        _ => Err(StoreError::Corrupt),
    }
}
fn state_name(value: OccurrenceState) -> &'static str {
    match value {
        OccurrenceState::Open => "open",
        OccurrenceState::Claimed => "claimed",
        OccurrenceState::WaitingApplicant => "waiting_applicant",
        OccurrenceState::WaitingApplication => "waiting_application",
        OccurrenceState::Synchronizing => "synchronizing",
        OccurrenceState::Completed => "completed",
        OccurrenceState::Superseded => "superseded",
        OccurrenceState::Cancelled => "cancelled",
    }
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

fn valid_date(value: &str) -> bool {
    value.len() == 10
        && value.as_bytes().get(4) == Some(&b'-')
        && value.as_bytes().get(7) == Some(&b'-')
        && chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d").is_ok()
}

async fn append_clock_audit(
    transaction: &Transaction<'_>,
    actor: &ActorContext,
    kind: &str,
    detail: Value,
) -> Result<(), StoreError> {
    let event_id = Uuid::new_v4();
    transaction.execute("INSERT INTO casework_audit_outbox(event_id,audit_record) VALUES($1,$2)",&[&event_id,&json!({"event":format!("casework.{kind}"),"eventId":event_id,"actor":{"issuer":actor.principal.issuer,"subject":actor.principal.subject},"profileId":actor.profile_id,"detail":detail})]).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
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

#[cfg(test)]
mod next_effect_tests {
    use super::*;

    #[test]
    fn projection_advances_using_only_persisted_effect_keys() {
        let reminder_at = DateTime::parse_from_rfc3339("2026-09-10T09:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let reassign_at = DateTime::parse_from_rfc3339("2026-09-11T09:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let reminders = vec![ReminderOccurrence {
            id: "due-soon".to_owned(),
            at: reminder_at,
        }];
        let steps = vec![StepOccurrence {
            id: "deadline".to_owned(),
            because: "Deadline passed".to_owned(),
            at: reassign_at,
            reassign_queue: "overdue".to_owned(),
        }];
        let mut applied = std::collections::BTreeSet::new();

        assert_eq!(
            next_unapplied_effect(&reminders, &steps, &applied),
            Some(ClockNextEffect::Reminder {
                id: "due-soon".to_owned(),
                at: reminder_at,
            })
        );
        applied.insert(("reminder".to_owned(), "due-soon".to_owned()));
        assert_eq!(
            next_unapplied_effect(&reminders, &steps, &applied),
            Some(ClockNextEffect::Reassign {
                id: "deadline".to_owned(),
                at: reassign_at,
                because: "Deadline passed".to_owned(),
                queue_id: "overdue".to_owned(),
            })
        );
        applied.insert(("step".to_owned(), "deadline".to_owned()));
        assert_eq!(next_unapplied_effect(&reminders, &steps, &applied), None);
    }
}

#[cfg(all(test, feature = "postgres-test"))]
mod tests {
    use std::env;

    use registry_casework_core::{
        ActivityClockAnchor, BootstrapDirectoryRequest, ClockReassignment, ClockReminder,
        ClockStep, ClockStepAction, ClockStepInstant, ElapsedDuration, IssuerPrincipal,
        ReviewTiming, SourceBinding, SubjectClockAnchor, SubjectClockCompletion, SubjectClockPause,
        WorkingDaysAfter, WorkingDaysBefore, WorkingWeekday,
    };
    use registry_platform_config::{SecretProvider, SecretResolver};

    use super::*;
    use crate::DatabaseConfig;

    fn instant(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .expect("test instant")
            .with_timezone(&Utc)
    }

    fn actor(subject: &str, role: CaseworkRole, profile: &str) -> ActorContext {
        ActorContext {
            principal: IssuerPrincipal {
                issuer: "https://issuer.test".to_owned(),
                subject: subject.to_owned(),
            },
            profile_id: profile.to_owned(),
            role,
        }
    }

    fn observation(
        subject_id: &str,
        key: &str,
        revision: i64,
        kind: OccurrenceKind,
        state: OccurrenceState,
        stage_entered_at: Option<DateTime<Utc>>,
        review_timing: Option<ReviewTiming>,
    ) -> registry_casework_core::AuthoritativeObservation {
        registry_casework_core::AuthoritativeObservation {
            subject: SubjectRef {
                source_id: "source-a".to_owned(),
                kind: "request-a".to_owned(),
                id: subject_id.to_owned(),
            },
            occurrence_key: key.to_owned(),
            ordered_revision: revision,
            representation_etag: format!("\"r{revision}\""),
            binding: SourceBinding {
                source_revision: revision.to_string(),
                version: format!("proposal-{revision}"),
                integrity: Some(format!("sha256:{revision}")),
                generation: "binding-a".to_owned(),
            },
            occurrence_kind: kind,
            stage: (kind == OccurrenceKind::Review).then(|| "technical".to_owned()),
            submitted_at: stage_entered_at,
            stage_entered_at,
            review_timing,
            routing_context: None,
            state,
            remaining_actions: Vec::new(),
        }
    }

    async fn fixture() -> (PostgresStore, tokio_postgres::Client, ActorContext) {
        let url = env::var("CASEWORK_CLOCK_TEST_DATABASE_URL")
            .expect("CASEWORK_CLOCK_TEST_DATABASE_URL is required");
        let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .expect("connect clock test database");
        tokio::spawn(async move { connection.await.expect("clock test connection") });
        client
            .batch_execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
            .await
            .expect("reset dedicated schema");
        let secrets = SecretResolver::new([SecretProvider::Environment], "/private/tmp")
            .expect("test secrets");
        let config = DatabaseConfig {
            runtime_url_ref: "secret:env/CASEWORK_CLOCK_TEST_DATABASE_URL".to_owned(),
            migration_url_ref: "secret:env/CASEWORK_CLOCK_TEST_DATABASE_URL".to_owned(),
            trusted_root_certificate_ref: None,
            test_only_plaintext: true,
        };
        let store = PostgresStore::connect_migration(&config, &secrets).expect("store");
        store.migrate().await.expect("migrate clocks");
        let admin = actor("admin", CaseworkRole::Administrator, "administrator");
        store
            .bootstrap_directory(
                &admin,
                0,
                &BootstrapDirectoryRequest {
                    team_id: "team-a".to_owned(),
                    staff: vec![],
                    supervisors: vec![
                        actor("supervisor", CaseworkRole::Supervisor, "supervisor").principal,
                    ],
                    queue_id: "default".to_owned(),
                },
                "bootstrap-clock",
            )
            .await
            .expect("bootstrap");
        client.execute(
            "INSERT INTO casework_queue_service(queue_id,team_id,revision) VALUES('overdue-review','team-a',2)",
            &[],
        ).await.expect("supervisor queue");
        (store, client, admin)
    }

    fn activity_policy() -> ResolvedClockPolicy {
        ResolvedClockPolicy {
            clock: ClockPolicy::Activity {
                id: "review-deadline".to_owned(),
                anchor: ActivityClockAnchor::StageEnteredAt,
                calendar: "office".to_owned(),
                after: WorkingDaysAfter { working_days: 5 },
                due_time: "17:00".to_owned(),
                at_risk: Some(WorkingDaysBefore {
                    working_days_before: 1,
                }),
                reminders: vec![ClockReminder {
                    id: "due-soon".to_owned(),
                    working_days_before: 1,
                }],
                steps: vec![ClockStep {
                    id: "supervisor-at-deadline".to_owned(),
                    because: "Deadline passed".to_owned(),
                    at: ClockStepInstant::Due,
                    action: ClockStepAction {
                        reassign: ClockReassignment {
                            queue: "overdue-review".to_owned(),
                        },
                    },
                }],
            },
            calendar: Some(CalendarPolicy {
                id: "office".to_owned(),
                timezone: "Asia/Bangkok".to_owned(),
                working_weekdays: vec![
                    WorkingWeekday::Monday,
                    WorkingWeekday::Tuesday,
                    WorkingWeekday::Wednesday,
                    WorkingWeekday::Thursday,
                    WorkingWeekday::Friday,
                ],
                holiday_set: "office-holidays".to_owned(),
            }),
        }
    }

    #[tokio::test]
    async fn source_clocks_survive_restart_and_preserve_subject_budget() {
        let (store, client, admin) = fixture().await;
        store
            .put_holiday_set(
                &admin,
                &HolidaySetDocument {
                    holiday_set: "office-holidays".to_owned(),
                    revision: 7,
                    dates: vec!["2026-08-03".to_owned()],
                },
                "holiday-7",
            )
            .await
            .expect("holiday revision");

        let activity = observation(
            "activity-subject",
            "review:technical:1",
            1,
            OccurrenceKind::Review,
            OccurrenceState::Open,
            Some(instant("2026-08-01T15:00:00+07:00")),
            None,
        );
        let activity_item = store
            .apply_observation_with_context(
                &activity,
                "default",
                None,
                None,
                Some(&activity_policy()),
            )
            .await
            .expect("activity observation")
            .expect("activity item");
        let initial_projection = store
            .clock_occurrences_for_item(activity_item.item_id)
            .await
            .expect("initial clock projection");
        assert!(matches!(
            initial_projection[0].next_effect,
            Some(ClockNextEffect::Reminder { ref id, .. }) if id == "due-soon"
        ));
        client.execute(
            "INSERT INTO casework_clock_effects(clock_occurrence_id,effect_kind,effect_id,calculation_generation,event_id,applied_at) VALUES($1,'reminder','due-soon',1,$2,now())",
            &[&initial_projection[0].clock_occurrence_id, &Uuid::new_v4()],
        ).await.expect("persist applied reminder");
        let resumed_projection = store
            .clock_occurrences_for_item(activity_item.item_id)
            .await
            .expect("projection after persisted effect");
        assert_eq!(
            resumed_projection[0].next_effect,
            Some(ClockNextEffect::Reassign {
                id: "supervisor-at-deadline".to_owned(),
                at: instant("2026-08-10T17:00:00+07:00"),
                because: "Deadline passed".to_owned(),
                queue_id: "overdue-review".to_owned(),
            })
        );
        let claim = store
            .claim_due_clocks(10)
            .await
            .expect("claim timers")
            .into_iter()
            .next()
            .expect("overdue timer");
        store
            .apply_observation_with_context(
                &activity,
                "default",
                None,
                None,
                Some(&activity_policy()),
            )
            .await
            .expect("fresh source verification");
        assert_eq!(
            store
                .apply_clock_claim(&claim, &activity)
                .await
                .expect("apply timer"),
            1
        );
        store
            .apply_observation_with_context(
                &activity,
                "default",
                None,
                None,
                Some(&activity_policy()),
            )
            .await
            .expect("later reconciliation");
        assert!(store
            .claim_due_clocks(10)
            .await
            .expect("restart pass")
            .is_empty());
        let completed_projection = store
            .clock_occurrences_for_item(activity_item.item_id)
            .await
            .expect("projection after all effects applied");
        assert_eq!(completed_projection[0].next_effect, None);
        let item = client
            .query_one(
                "SELECT queue_id,revision FROM casework_items WHERE subject_id='activity-subject'",
                &[],
            )
            .await
            .expect("reassigned item");
        assert_eq!(item.get::<_, String>(0), "overdue-review");
        assert_eq!(item.get::<_, i64>(1), 2);
        assert_eq!(
            client
                .query_one("SELECT count(*) FROM casework_clock_effects", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            2
        );

        let mut missing_timing = observation(
            "missing-timing",
            "review:technical:missing",
            1,
            OccurrenceKind::Review,
            OccurrenceState::Open,
            Some(instant("2026-08-01T15:00:00+07:00")),
            None,
        );
        let missing_item = store
            .apply_observation_with_context(
                &missing_timing,
                "default",
                None,
                None,
                Some(&activity_policy()),
            )
            .await
            .unwrap()
            .unwrap();
        missing_timing.ordered_revision = 2;
        missing_timing.representation_etag = "\"r2\"".to_owned();
        missing_timing.submitted_at = None;
        missing_timing.stage_entered_at = None;
        store
            .apply_observation_with_context(
                &missing_timing,
                "default",
                None,
                None,
                Some(&activity_policy()),
            )
            .await
            .unwrap();
        let missing_clock = store
            .clock_occurrences_for_item(missing_item.item_id)
            .await
            .unwrap();
        assert_eq!(
            missing_clock[0].state,
            ClockRuntimeState::SourceFactsMissing
        );

        let mut hinted = observation(
            "hinted-before-commit",
            "review:technical:hinted",
            1,
            OccurrenceKind::Review,
            OccurrenceState::Open,
            Some(instant("2026-08-01T15:00:00+07:00")),
            None,
        );
        store
            .apply_observation_with_context(
                &hinted,
                "default",
                None,
                None,
                Some(&activity_policy()),
            )
            .await
            .unwrap();
        let hinted_claim = store
            .claim_due_clocks(10)
            .await
            .unwrap()
            .into_iter()
            .find(|claim| claim.subject.id == "hinted-before-commit")
            .unwrap();
        store
            .apply_observation_with_context(
                &hinted,
                "default",
                None,
                None,
                Some(&activity_policy()),
            )
            .await
            .unwrap();
        store
            .ingest_transition(
                "binding-a",
                &registry_casework_core::TransitionHint {
                    subject: hinted.subject.clone(),
                    deduplication_key: "later-source-event".to_owned(),
                    ordered_revision: 2,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .apply_clock_claim(&hinted_claim, &hinted)
                .await
                .unwrap(),
            0
        );
        assert_eq!(client.query_one("SELECT count(*) FROM casework_clock_effects e JOIN casework_clock_occurrences o USING(clock_occurrence_id) WHERE o.subject_id='hinted-before-commit'",&[]).await.unwrap().get::<_,i64>(0),0);
        hinted.ordered_revision = 2;
        hinted.representation_etag = "\"r2\"".to_owned();
        hinted.state = OccurrenceState::Completed;
        store
            .apply_observation_with_context(
                &hinted,
                "default",
                None,
                None,
                Some(&activity_policy()),
            )
            .await
            .unwrap();

        let mut completed_before_commit = observation(
            "completed-before-clock",
            "review:technical:2",
            1,
            OccurrenceKind::Review,
            OccurrenceState::Open,
            Some(instant("2026-08-01T15:00:00+07:00")),
            None,
        );
        store
            .apply_observation_with_context(
                &completed_before_commit,
                "default",
                None,
                None,
                Some(&activity_policy()),
            )
            .await
            .unwrap();
        let stale_claim = store
            .claim_due_clocks(10)
            .await
            .unwrap()
            .into_iter()
            .find(|claim| claim.subject.id == "completed-before-clock")
            .expect("claimed stale timer");
        store
            .put_holiday_set(
                &admin,
                &HolidaySetDocument {
                    holiday_set: "office-holidays".to_owned(),
                    revision: 8,
                    dates: vec![],
                },
                "holiday-8",
            )
            .await
            .unwrap();
        let source_stale_preview = store
            .preview_clock_recompute(
                &admin,
                &registry_casework_core::ClockRecomputeRequest {
                    clock_id: "review-deadline".to_owned(),
                    holiday_set: "office-holidays".to_owned(),
                    holiday_revision: 8,
                },
            )
            .await
            .unwrap();
        store
            .ingest_transition(
                "binding-a",
                &registry_casework_core::TransitionHint {
                    subject: activity.subject.clone(),
                    deduplication_key: "activity-changed-after-preview".to_owned(),
                    ordered_revision: 2,
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            store
                .apply_clock_recompute(
                    &admin,
                    source_stale_preview.preview_id,
                    "source-stale-recompute"
                )
                .await,
            Err(StoreError::Conflict)
        ));
        let mut activity_v2 = activity.clone();
        activity_v2.ordered_revision = 2;
        activity_v2.representation_etag = "\"r2\"".to_owned();
        store
            .apply_observation_with_context(
                &activity_v2,
                "overdue-review",
                None,
                None,
                Some(&activity_policy()),
            )
            .await
            .unwrap();
        let stale_preview = store
            .preview_clock_recompute(
                &admin,
                &registry_casework_core::ClockRecomputeRequest {
                    clock_id: "review-deadline".to_owned(),
                    holiday_set: "office-holidays".to_owned(),
                    holiday_revision: 8,
                },
            )
            .await
            .unwrap();
        completed_before_commit.ordered_revision = 2;
        completed_before_commit.representation_etag = "\"r2\"".to_owned();
        completed_before_commit.state = OccurrenceState::Completed;
        store
            .apply_observation_with_context(
                &completed_before_commit,
                "default",
                None,
                None,
                Some(&activity_policy()),
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .apply_clock_claim(&stale_claim, &completed_before_commit)
                .await
                .unwrap(),
            0
        );
        assert_eq!(client.query_one("SELECT count(*) FROM casework_clock_effects e JOIN casework_clock_occurrences o USING(clock_occurrence_id) WHERE o.subject_id='completed-before-clock'",&[]).await.unwrap().get::<_,i64>(0),0);
        assert!(matches!(
            store
                .apply_clock_recompute(&admin, stale_preview.preview_id, "stale-recompute")
                .await,
            Err(StoreError::Conflict)
        ));

        let preview = store
            .preview_clock_recompute(
                &admin,
                &registry_casework_core::ClockRecomputeRequest {
                    clock_id: "review-deadline".to_owned(),
                    holiday_set: "office-holidays".to_owned(),
                    holiday_revision: 8,
                },
            )
            .await
            .unwrap();
        assert_eq!(preview.changes.len(), 1);
        assert_ne!(
            preview.changes[0].old_due_at,
            preview.changes[0].proposed_due_at
        );
        let recomputed = store
            .apply_clock_recompute(&admin, preview.preview_id, "apply-recompute")
            .await
            .unwrap();
        assert_eq!(recomputed.applied_occurrences.len(), 1);
        assert_eq!(
            store
                .apply_clock_recompute(&admin, preview.preview_id, "apply-recompute")
                .await
                .unwrap(),
            recomputed
        );
        let generation=client.query_one("SELECT current_calculation_generation,recompute_generation,next_action_at FROM casework_clock_occurrences WHERE subject_id='activity-subject'",&[]).await.unwrap();
        assert_eq!(generation.get::<_, i64>(0), 2);
        assert_eq!(generation.get::<_, i64>(1), 1);
        assert_eq!(generation.get::<_, Option<DateTime<Utc>>>(2), None);
        assert_eq!(
            client
                .query_one("SELECT count(*) FROM casework_clock_effects", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            2
        );

        let subject_policy = ResolvedClockPolicy {
            clock: ClockPolicy::Subject {
                id: "response-budget".to_owned(),
                anchor: SubjectClockAnchor::FirstSubmittedAt,
                complete_on: SubjectClockCompletion::ReviewCompleted,
                after: ElapsedDuration {
                    elapsed: "PT48H".to_owned(),
                },
                pause_while: vec![SubjectClockPause::AwaitingApplicant],
            },
            calendar: None,
        };
        let first = instant("2026-08-01T09:00:00+07:00");
        let mut review = observation(
            "budget-subject",
            "review:proposal-1",
            1,
            OccurrenceKind::Review,
            OccurrenceState::Open,
            Some(first),
            Some(ReviewTiming {
                first_submitted_at: first,
                paused_milliseconds: 0,
                pause_started_at: None,
                completed_at: None,
            }),
        );
        let item1 = store
            .apply_observation_with_context(&review, "default", None, None, Some(&subject_policy))
            .await
            .unwrap()
            .unwrap();
        review.ordered_revision = 2;
        review.representation_etag = "\"r2\"".to_owned();
        review.occurrence_key = "review:proposal-2".to_owned();
        review.state = OccurrenceState::WaitingApplicant;
        review.review_timing.as_mut().unwrap().pause_started_at =
            Some(instant("2026-08-01T13:00:00+07:00"));
        store
            .apply_observation_with_context(&review, "default", None, None, Some(&subject_policy))
            .await
            .unwrap();
        review.ordered_revision = 3;
        review.representation_etag = "\"r3\"".to_owned();
        review.state = OccurrenceState::Open;
        let timing = review.review_timing.as_mut().unwrap();
        timing.pause_started_at = None;
        timing.paused_milliseconds = 24 * 60 * 60 * 1_000;
        let item3 = store
            .apply_observation_with_context(&review, "default", None, None, Some(&subject_policy))
            .await
            .unwrap()
            .unwrap();
        let clocks = store
            .clock_occurrences_for_item(item3.item_id)
            .await
            .unwrap();
        assert_eq!(clocks.len(), 1);
        assert_eq!(clocks[0].due_at, Some(instant("2026-08-04T09:00:00+07:00")));
        assert_ne!(item1.item_id, item3.item_id);
        let occurrence_id = clocks[0].clock_occurrence_id;
        review.ordered_revision = 4;
        review.representation_etag = "\"r4\"".to_owned();
        review.occurrence_key = "application:proposal-2".to_owned();
        review.occurrence_kind = OccurrenceKind::Application;
        review.stage = None;
        review.state = OccurrenceState::Open;
        review.review_timing.as_mut().unwrap().completed_at =
            Some(instant("2026-08-02T14:00:00+07:00"));
        let application = store
            .apply_observation_with_context(&review, "default", None, None, Some(&subject_policy))
            .await
            .unwrap()
            .unwrap();
        let frozen = store
            .clock_occurrences_for_item(application.item_id)
            .await
            .unwrap();
        assert_eq!(frozen[0].clock_occurrence_id, occurrence_id);
        assert_eq!(frozen[0].state, ClockRuntimeState::Completed);
    }
}
