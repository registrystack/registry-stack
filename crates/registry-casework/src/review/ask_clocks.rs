//! Ask pauses use elapsed wall time for both elapsed and working-day clocks.
use super::*;

pub(super) async fn pause(
    tx: &impl GenericClient,
    request_id: Uuid,
    ask_id: Uuid,
    now: DateTime<Utc>,
) -> Result<(), ReviewRuntimeError> {
    let rows = tx
        .query(
            "UPDATE casework_review_clock_occurrences SET paused_state=state,state='paused',
             paused_at=$2,paused_ask_id=$3,updated_at=$2
         WHERE request_id=$1 AND state IN ('running','source-facts-missing')
         RETURNING clock_occurrence_id,clock_id,task_id",
            &[&request_id, &now, &ask_id],
        )
        .await?;
    for row in rows {
        insert_history(
            tx,
            request_id,
            &row,
            "clock-paused",
            json!({"askId":ask_id}),
            now,
        )
        .await?;
    }
    refresh_review_deadlines(tx, request_id).await?;
    Ok(())
}

pub(super) async fn resume(
    tx: &impl GenericClient,
    request_id: Uuid,
    ask_id: Uuid,
    now: DateTime<Utc>,
) -> Result<(), ReviewRuntimeError> {
    let rows = tx
        .query(
            "SELECT clock_occurrence_id,clock_id,task_id,paused_at,paused_state,
                due_at,at_risk_at,next_action_at,reminders,steps,anchor_at
         FROM casework_review_clock_occurrences
         WHERE request_id=$1 AND state='paused' AND paused_ask_id=$2
         ORDER BY clock_occurrence_id FOR UPDATE",
            &[&request_id, &ask_id],
        )
        .await?;
    for row in rows {
        let occurrence: Uuid = row.get(0);
        let paused_at: DateTime<Utc> = row.get(3);
        let duration = now.signed_duration_since(paused_at).max(TimeDelta::zero());
        let state: String = row.get(4);
        let shift = |at: Option<DateTime<Utc>>| -> Result<_, ReviewRuntimeError> {
            at.map(|at| {
                at.checked_add_signed(duration)
                    .ok_or(ReviewRuntimeError::Corrupt)
            })
            .transpose()
        };
        let due = shift(row.get(5))?;
        let at_risk = shift(row.get(6))?;
        let next = shift(row.get(7))?;
        let mut reminders: Vec<ReminderOccurrence> = serde_json::from_value(row.get(8))?;
        let mut steps: Vec<StepOccurrence> = serde_json::from_value(row.get(9))?;
        // Already applied effects keep their original instants. Only pending
        // effects are delayed, and the ledger still prevents double delivery.
        let effects = tx.query("SELECT effect_kind,effect_id FROM casework_review_clock_effects WHERE clock_occurrence_id=$1", &[&occurrence]).await?;
        let applied = effects
            .iter()
            .map(|r| (r.get::<_, String>(0), r.get::<_, String>(1)))
            .collect::<std::collections::BTreeSet<_>>();
        for reminder in &mut reminders {
            if !applied.contains(&("reminder".into(), reminder.id.clone())) {
                reminder.at = shift(Some(reminder.at))?.ok_or(ReviewRuntimeError::Corrupt)?;
            }
        }
        for step in &mut steps {
            if !applied.contains(&("step".into(), step.id.clone())) {
                step.at = shift(Some(step.at))?.ok_or(ReviewRuntimeError::Corrupt)?;
            }
        }
        let anchor: DateTime<Utc> = row.get(10);
        // An unresolved working-day clock will be evaluated when its holiday
        // facts arrive. Move its anchor so that evaluation includes the pause.
        let anchor = if state == "source-facts-missing" {
            shift(Some(anchor))?.ok_or(ReviewRuntimeError::Corrupt)?
        } else {
            anchor
        };
        tx.execute(
            "UPDATE casework_review_clock_occurrences SET state=$2,paused_at=NULL,
                 paused_state=NULL,paused_ask_id=NULL,due_at=$3,at_risk_at=$4,
                 next_action_at=$5,reminders=$6,steps=$7,anchor_at=$8,updated_at=$9
             WHERE clock_occurrence_id=$1",
            &[
                &occurrence,
                &state,
                &due,
                &at_risk,
                &next,
                &serde_json::to_value(reminders)?,
                &serde_json::to_value(steps)?,
                &anchor,
                &now,
            ],
        )
        .await?;
        insert_history(tx, request_id, &row, "clock-resumed", json!({
            "askId":ask_id,"pausedSeconds": duration.num_microseconds().ok_or(ReviewRuntimeError::Corrupt)? as f64 / 1_000_000.0
        }), now).await?;
    }
    refresh_review_deadlines(tx, request_id).await?;
    Ok(())
}

async fn insert_history(
    tx: &impl GenericClient,
    request_id: Uuid,
    row: &Row,
    kind: &str,
    mut detail: Value,
    now: DateTime<Utc>,
) -> Result<(), ReviewRuntimeError> {
    detail["clockOccurrenceId"] = json!(row.get::<_, Uuid>(0));
    detail["clockId"] = json!(row.get::<_, String>(1));
    tx.execute(
        "INSERT INTO casework_review_history(event_id,request_id,task_id,kind,actor_ref,detail,occurred_at)
         VALUES($1,$2,$3,$4,NULL,$5,$6)",
        &[&Uuid::new_v4(),&request_id,&row.get::<_, Option<Uuid>>(2),&kind,&detail,&now],
    ).await?;
    Ok(())
}

/// Caller operations that close asks collect the pause history they produced
/// before committing. Creation already collects every history event it wrote.
pub(super) async fn audit_events(
    tx: &impl GenericClient,
    request_id: Uuid,
    audit: &mut crate::audit::AuditOperation,
) -> Result<(), ReviewRuntimeError> {
    for row in tx
        .query(
            "SELECT event_id,task_id,kind FROM casework_review_history
         WHERE request_id=$1 AND kind IN ('clock-paused','clock-resumed')
           AND xmin=pg_current_xact_id()::xid ORDER BY event_id",
            &[&request_id],
        )
        .await?
    {
        let mut record = json!({"event": format!("casework.review-{}", row.get::<_, String>(2)), "reviewRequestId":request_id,"profileId":"system:clocks"});
        if let Some(task) = row.get::<_, Option<Uuid>>(1) {
            record["reviewTaskId"] = json!(task);
        }
        audit.record(row.get(0), record)?;
    }
    Ok(())
}
