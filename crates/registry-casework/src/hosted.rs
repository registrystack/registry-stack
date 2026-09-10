//! PostgreSQL-backed standalone Casework items.

use chrono::{DateTime, TimeDelta, Utc};
use registry_casework_core::{
    ActorContext, AssignmentContext, CaseworkAction, CaseworkRole, HostedAccountabilityRecord,
    HostedCancelRequest, HostedCreateRequest, HostedDecisionRequest, HostedHistoryEntry,
    HostedHistoryKind, HostedHistoryPage, HostedKindPolicySnapshot, HostedNote, HostedNoteRequest,
    HostedPolicyDigest, HostedTerminalPage, HostedTerminalResult, HostedTerminalState,
    HostedValidationError, HostedValidationReason, HostedWorkItemContext, InboxView,
    IssuerPrincipal, OccurrenceKind, OccurrenceState, OpaqueActorRef, Page, PageStatus,
    RequesterHostedItem, SourceBinding, StaffingDiagnostic, SubjectRef, WorkItem, WorkItemPage,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

use crate::{CaseworkService, PostgresStore, ServiceError, StoreError};

pub const HOSTED_TERMINAL_CURSOR_CONTEXT: &str = "hosted-terminal";
pub const HOSTED_STAFF_INBOX_CURSOR_CONTEXT: &str = "hosted-staff-inbox";

const MAXIMUM_IDEMPOTENCY_KEY_BYTES: usize = 128;
const HOSTED_CURSOR_SECONDS: i64 = 15 * 60;
const RETENTION_BATCH_SIZE: i64 = 100;

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct HostedStaffCursorContext<'a> {
    feed: &'a str,
    view: InboxView,
    queue: Option<&'a str>,
    ordering: &'static str,
}

#[derive(Clone, Debug)]
struct StoredHostedItem {
    item_id: Uuid,
    requester: Option<IssuerPrincipal>,
    requester_profile_id: Option<String>,
    requester_reference: Option<String>,
    display: Option<Value>,
    kind_id: String,
    kind_version: String,
    kind_policy_digest: String,
    kind_policy: Value,
    queue_id: String,
    state: HostedState,
    holder: Option<IssuerPrincipal>,
    assignment: Option<AssignmentContext>,
    revision: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostedState {
    Open,
    Claimed,
    Completed,
    Cancelled,
}

impl HostedState {
    fn name(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Claimed => "claimed",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
        }
    }

    fn is_active(self) -> bool {
        matches!(self, Self::Open | Self::Claimed)
    }
}

fn stored_hosted_item(row: &Row) -> Result<StoredHostedItem, StoreError> {
    let requester = optional_principal(row, "requester_issuer", "requester_subject")?;
    let holder = optional_principal(row, "holder_issuer", "holder_subject")?;
    let owner = optional_principal(row, "assignment_owner_issuer", "assignment_owner_subject")?;
    let assigned_by = optional_principal(row, "assigned_by_issuer", "assigned_by_subject")?;
    let absence_ids = row.get::<_, Vec<Uuid>>("assignment_absence_ids");
    let staffing_diagnostic = match row
        .get::<_, Option<String>>("staffing_diagnostic")
        .as_deref()
    {
        Some("no_cover_available") => Some(StaffingDiagnostic::NoCoverAvailable),
        None => None,
        Some(_) => return Err(StoreError::Corrupt),
    };
    let assignment = if owner.is_none()
        && assigned_by.is_none()
        && absence_ids.is_empty()
        && staffing_diagnostic.is_none()
    {
        None
    } else {
        Some(AssignmentContext {
            owner,
            assigned_by,
            absence_ids,
            staffing_diagnostic,
        })
    };
    Ok(StoredHostedItem {
        item_id: row.get("item_id"),
        requester,
        requester_profile_id: row.get("requester_profile_id"),
        requester_reference: row.get("requester_reference"),
        display: row.get("display"),
        kind_id: row.get("kind_id"),
        kind_version: row.get("kind_version"),
        kind_policy_digest: row.get("kind_policy_digest"),
        kind_policy: row.get("kind_policy"),
        queue_id: row.get("queue_id"),
        state: match row.get::<_, String>("state").as_str() {
            "open" => HostedState::Open,
            "claimed" => HostedState::Claimed,
            "completed" => HostedState::Completed,
            "cancelled" => HostedState::Cancelled,
            _ => return Err(StoreError::Corrupt),
        },
        holder,
        assignment,
        revision: row.get("revision"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

fn optional_principal(
    row: &Row,
    issuer_column: &str,
    subject_column: &str,
) -> Result<Option<IssuerPrincipal>, StoreError> {
    match (
        row.get::<_, Option<String>>(issuer_column),
        row.get::<_, Option<String>>(subject_column),
    ) {
        (Some(issuer), Some(subject)) => Ok(Some(IssuerPrincipal { issuer, subject })),
        (None, None) => Ok(None),
        _ => Err(StoreError::Corrupt),
    }
}

fn validate_text(value: &str, maximum: usize, allow_empty: bool) -> Result<(), StoreError> {
    if (!allow_empty && value.is_empty())
        || value.len() > maximum
        || value.chars().any(char::is_control)
    {
        return Err(StoreError::Invalid);
    }
    Ok(())
}

fn hosted_request_hash<T: serde::Serialize>(value: &T) -> Result<String, StoreError> {
    let bytes = serde_json::to_vec(value)?;
    let digest = Sha256::digest(bytes);
    Ok(format!(
        "sha256:{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}

async fn lock_hosted_idempotency(
    transaction: &Transaction<'_>,
    actor: &ActorContext,
    operation: &str,
    resource: &str,
    key: &str,
) -> Result<(), StoreError> {
    validate_text(key, MAXIMUM_IDEMPOTENCY_KEY_BYTES, false)?;
    let lock_key = format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}{operation}\u{1f}{resource}\u{1f}{key}",
        actor.principal.issuer, actor.principal.subject, actor.profile_id
    );
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            &[&lock_key],
        )
        .await?;
    Ok(())
}

async fn hosted_idempotent_response(
    transaction: &Transaction<'_>,
    actor: &ActorContext,
    operation: &str,
    resource: &str,
    key: &str,
    request_hash: &str,
) -> Result<Option<Value>, StoreError> {
    lock_hosted_idempotency(transaction, actor, operation, resource, key).await?;
    let binding_digest = hosted_request_hash(&(
        &actor.principal.issuer,
        &actor.principal.subject,
        &actor.profile_id,
        operation,
        resource,
        key,
    ))?;
    if let Some(row) = transaction
        .query_opt(
            "SELECT request_hash,retained_until FROM casework_hosted_idempotency_tombstones WHERE binding_digest=$1 FOR UPDATE",
            &[&binding_digest],
        )
        .await?
    {
        if row.get::<_, DateTime<Utc>>(1) <= Utc::now() {
            transaction
                .execute(
                    "DELETE FROM casework_hosted_idempotency_tombstones WHERE binding_digest=$1",
                    &[&binding_digest],
                )
                .await?;
            return Ok(None);
        }
        return if row.get::<_, String>(0) == request_hash {
            Err(StoreError::IdempotencyExpired)
        } else {
            Err(StoreError::IdempotencyConflict)
        };
    }
    let row = transaction
        .query_opt(
            "SELECT d.request_hash,d.response,(i.terminal_retained_until IS NULL OR i.terminal_retained_until>now()) FROM casework_hosted_idempotency d JOIN casework_hosted_items i ON i.item_id=d.item_id WHERE d.issuer=$1 AND d.subject=$2 AND d.profile_id=$3 AND d.operation=$4 AND d.resource=$5 AND d.idempotency_key=$6",
            &[&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&operation,&resource,&key],
        )
        .await?;
    match row {
        Some(row) if !row.get::<_, bool>(2) && row.get::<_, String>(0) == request_hash => {
            Err(StoreError::IdempotencyExpired)
        }
        Some(row) if row.get::<_, String>(0) == request_hash => Ok(Some(row.get(1))),
        Some(_) => Err(StoreError::IdempotencyConflict),
        None => Ok(None),
    }
}

#[allow(clippy::too_many_arguments)]
async fn insert_hosted_idempotency(
    transaction: &Transaction<'_>,
    actor: &ActorContext,
    operation: &str,
    resource: &str,
    key: &str,
    request_hash: &str,
    item_id: Uuid,
    response: &Value,
) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO casework_hosted_idempotency(issuer,subject,profile_id,operation,resource,idempotency_key,request_hash,item_id,response,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        &[&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&operation,&resource,&key,&request_hash,&item_id,&response,&Utc::now()],
    ).await?;
    Ok(())
}

async fn hosted_actor_reference(
    transaction: &Transaction<'_>,
    actor: &ActorContext,
) -> Result<String, StoreError> {
    if let Some(row) = transaction
        .query_opt(
            "SELECT actor_ref FROM casework_hosted_actor_references WHERE issuer=$1 AND subject=$2",
            &[&actor.principal.issuer, &actor.principal.subject],
        )
        .await?
    {
        return Ok(row.get(0));
    }
    let actor_ref = format!("actor_{}", Uuid::new_v4().simple());
    transaction.execute(
        "INSERT INTO casework_hosted_actor_references(actor_ref,issuer,subject) VALUES($1,$2,$3) ON CONFLICT(issuer,subject) DO NOTHING",
        &[&actor_ref,&actor.principal.issuer,&actor.principal.subject],
    ).await?;
    Ok(transaction
        .query_one(
            "SELECT actor_ref FROM casework_hosted_actor_references WHERE issuer=$1 AND subject=$2",
            &[&actor.principal.issuer, &actor.principal.subject],
        )
        .await?
        .get(0))
}

pub(crate) async fn append_hosted_history(
    transaction: &Transaction<'_>,
    item_id: Uuid,
    item_revision: i64,
    kind: &str,
    actor: &ActorContext,
    detail: Value,
) -> Result<Uuid, StoreError> {
    let event_id = Uuid::new_v4();
    let now = Utc::now();
    let actor_ref = hosted_actor_reference(transaction, actor).await?;
    transaction.execute(
        "INSERT INTO casework_hosted_history(event_id,item_id,item_revision,kind,occurred_at,actor_issuer,actor_subject,profile_id,detail) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        &[&event_id,&item_id,&item_revision,&kind,&now,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&detail],
    ).await?;
    transaction.execute(
        "INSERT INTO casework_audit_outbox(event_id,audit_record) VALUES($1,$2)",
        &[&event_id,&json!({"event":format!("casework.hosted_{kind}"),"eventId":event_id,"itemId":item_id,"itemRevision":item_revision,"actorRef":actor_ref,"profileId":actor.profile_id})],
    ).await?;
    Ok(event_id)
}

fn retained_until(now: DateTime<Utc>, days: u32) -> Result<DateTime<Utc>, StoreError> {
    now.checked_add_signed(TimeDelta::days(i64::from(days)))
        .ok_or(StoreError::Invalid)
}

impl StoredHostedItem {
    fn snapshot(&self) -> Result<HostedKindPolicySnapshot, StoreError> {
        let snapshot: HostedKindPolicySnapshot = serde_json::from_value(self.kind_policy.clone())?;
        snapshot.verify().map_err(|_| StoreError::Corrupt)?;
        if snapshot.identity.kind_id != self.kind_id
            || snapshot.identity.version != self.kind_version
            || snapshot.identity.digest.as_str() != self.kind_policy_digest
            || snapshot.queue != self.queue_id
        {
            return Err(StoreError::Corrupt);
        }
        Ok(snapshot)
    }

    fn requester_projection(&self) -> Result<RequesterHostedItem, StoreError> {
        Ok(RequesterHostedItem {
            item_id: self.item_id,
            requester_reference: self
                .requester_reference
                .clone()
                .ok_or(StoreError::NotFound)?,
            kind: self.kind_id.clone(),
            version: self.kind_version.clone(),
            display: self.display.clone().ok_or(StoreError::NotFound)?,
            state: occurrence_state(self.state),
            revision: self.revision,
            kind_policy_digest: HostedPolicyDigest::parse(&self.kind_policy_digest)
                .map_err(|_| StoreError::Corrupt)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }

    fn work_item(
        &self,
        held_since: Option<DateTime<Utc>>,
        actions: Vec<CaseworkAction>,
    ) -> Result<WorkItem, StoreError> {
        let snapshot = self.snapshot()?;
        let display = self.display.clone().ok_or(StoreError::NotFound)?;
        let requester_reference = self
            .requester_reference
            .clone()
            .ok_or(StoreError::NotFound)?;
        let binding = SourceBinding {
            source_revision: self.revision.to_string(),
            version: self.kind_version.clone(),
            integrity: Some(self.kind_policy_digest.clone()),
            generation: self.kind_policy_digest.clone(),
        };
        Ok(WorkItem {
            item_id: self.item_id,
            subject: SubjectRef {
                source_id: "casework:hosted".to_owned(),
                kind: self.kind_id.clone(),
                id: self.item_id.to_string(),
            },
            occurrence_kind: OccurrenceKind::Hosted,
            stage: None,
            binding_reference: self.kind_policy_digest.clone(),
            binding,
            state: occurrence_state(self.state),
            queue_id: self.queue_id.clone(),
            holder: self.holder.clone(),
            held_since: self.holder.as_ref().and(held_since),
            assignment: self.assignment.clone(),
            revision: self.revision,
            first_observed_at: self.created_at,
            passive_due_at: None,
            updated_at: self.updated_at,
            hosted: Some(HostedWorkItemContext {
                requester_reference,
                kind: self.kind_id.clone(),
                version: self.kind_version.clone(),
                display,
                kind_policy_digest: snapshot.identity.digest,
                outcomes: snapshot.outcomes,
            }),
            routing: None,
            clock_occurrences: Vec::new(),
            actions,
            routing_copy: None,
            live_attempt: None,
        })
    }
}

fn occurrence_state(state: HostedState) -> OccurrenceState {
    match state {
        HostedState::Open => OccurrenceState::Open,
        HostedState::Claimed => OccurrenceState::Claimed,
        HostedState::Completed => OccurrenceState::Completed,
        HostedState::Cancelled => OccurrenceState::Cancelled,
    }
}

fn hosted_actions(
    actor: &ActorContext,
    item: &StoredHostedItem,
) -> Result<Vec<CaseworkAction>, StoreError> {
    let snapshot = item.snapshot()?;
    let if_match = format!("\"{}\"", item.revision);
    let mut actions = Vec::new();
    if actor.role == CaseworkRole::Supervisor {
        if !item.state.is_active() {
            return Ok(Vec::new());
        }
        actions.push(CaseworkAction {
            operation: "assign".to_owned(),
            href: format!("/v1/work-items/{}/assign", item.item_id),
            if_match: if_match.clone(),
        });
        if item.state == HostedState::Claimed && item.holder.is_some() {
            actions.push(CaseworkAction {
                operation: "release".to_owned(),
                href: format!("/v1/work-items/{}/release", item.item_id),
                if_match: if_match.clone(),
            });
        }
    }
    if !snapshot.deciding_profiles.contains(&actor.profile_id) {
        return Ok(actions);
    }
    if item.state == HostedState::Open && item.holder.is_none() {
        actions.push(CaseworkAction {
            operation: "claim".to_owned(),
            href: format!("/v1/work-items/{}/claim", item.item_id),
            if_match,
        });
        return Ok(actions);
    }
    if item.state != HostedState::Claimed || item.holder.as_ref() != Some(&actor.principal) {
        return Ok(actions);
    }
    if actor.role == CaseworkRole::Staff {
        actions.extend([
            CaseworkAction {
                operation: "release".to_owned(),
                href: format!("/v1/work-items/{}/release", item.item_id),
                if_match: if_match.clone(),
            },
            CaseworkAction {
                operation: "delegate".to_owned(),
                href: format!("/v1/work-items/{}/delegate", item.item_id),
                if_match: if_match.clone(),
            },
        ]);
    }
    actions.extend(snapshot.outcomes.into_iter().map(|outcome| CaseworkAction {
        operation: outcome.id,
        href: format!("/v1/work-items/{}/hosted-decisions", item.item_id),
        if_match: if_match.clone(),
    }));
    Ok(actions)
}

async fn hosted_holder_timings(
    transaction: &Transaction<'_>,
    item_ids: &[Uuid],
) -> Result<BTreeMap<Uuid, (i64, Option<DateTime<Utc>>)>, StoreError> {
    if item_ids.is_empty() {
        return Ok(BTreeMap::new());
    }
    Ok(transaction
        .query(
            "SELECT i.item_id,i.revision,CASE WHEN i.holder_issuer IS NULL THEN NULL ELSE (SELECT h.occurred_at FROM casework_hosted_history h WHERE h.item_id=i.item_id AND h.kind IN ('claimed','assigned','delegated','caseload_moved') ORDER BY h.item_revision DESC,h.occurred_at DESC,h.event_id DESC LIMIT 1) END FROM casework_hosted_items i WHERE i.item_id=ANY($1) AND (i.terminal_retained_until IS NULL OR i.terminal_retained_until>now())",
            &[&item_ids],
        )
        .await?
        .into_iter()
        .map(|row| (row.get(0), (row.get(1), row.get(2))))
        .collect())
}

fn hosted_held_since(
    item: &StoredHostedItem,
    timings: &BTreeMap<Uuid, (i64, Option<DateTime<Utc>>)>,
) -> Option<DateTime<Utc>> {
    item.holder.as_ref()?;
    timings
        .get(&item.item_id)
        .filter(|(revision, _)| *revision == item.revision)
        .and_then(|(_, held_since)| *held_since)
}

fn membership_kind(role: CaseworkRole) -> Result<&'static str, StoreError> {
    match role {
        CaseworkRole::Staff => Ok("staff"),
        CaseworkRole::Supervisor => Ok("supervisor"),
        CaseworkRole::Administrator | CaseworkRole::Requester => Err(StoreError::Forbidden),
    }
}

async fn has_queue_authority(
    transaction: &Transaction<'_>,
    actor: &ActorContext,
    queue_id: &str,
) -> Result<bool, StoreError> {
    let membership_kind = membership_kind(actor.role)?;
    Ok(transaction.query_opt(
        "SELECT 1 FROM casework_queue_service q JOIN casework_memberships m ON m.team_id=q.team_id WHERE q.queue_id=$1 AND m.issuer=$2 AND m.subject=$3 AND m.membership_kind=$4 FOR KEY SHARE OF q,m",
        &[&queue_id,&actor.principal.issuer,&actor.principal.subject,&membership_kind],
    ).await?.is_some())
}

impl PostgresStore {
    pub async fn create_hosted_item(
        &self,
        actor: &ActorContext,
        request: &HostedCreateRequest,
        snapshot: &HostedKindPolicySnapshot,
        idempotency_key: &str,
    ) -> Result<RequesterHostedItem, StoreError> {
        if actor.role != CaseworkRole::Requester {
            return Err(StoreError::Forbidden);
        }
        let request_hash = hosted_request_hash(&(
            &actor.principal.issuer,
            &actor.principal.subject,
            &actor.profile_id,
            request.canonical_bytes().map_err(|_| StoreError::Invalid)?,
        ))?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        if let Some(response) = hosted_idempotent_response(
            &transaction,
            actor,
            "hosted.create",
            &request.kind,
            idempotency_key,
            &request_hash,
        )
        .await?
        {
            return serde_json::from_value(response).map_err(StoreError::Json);
        }
        snapshot.verify().map_err(|_| StoreError::Invalid)?;
        snapshot
            .validate_display(&request.display)
            .map_err(|_| StoreError::Invalid)?;
        validate_text(
            &request.requester_reference,
            registry_casework_core::MAXIMUM_HOSTED_REFERENCE_BYTES,
            false,
        )?;
        if request.kind != snapshot.identity.kind_id {
            return Err(StoreError::Invalid);
        }
        let item_id = Uuid::new_v4();
        let now = Utc::now();
        let policy = serde_json::to_value(snapshot)?;
        transaction.execute(
            "INSERT INTO casework_hosted_items(item_id,requester_issuer,requester_subject,requester_profile_id,requester_reference,display,kind_id,kind_version,kind_policy_digest,kind_policy,queue_id,state,revision,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'open',1,$12,$12)",
            &[&item_id,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&request.requester_reference,&request.display,&snapshot.identity.kind_id,&snapshot.identity.version,&snapshot.identity.digest.as_str(),&policy,&snapshot.queue,&now],
        ).await?;
        append_hosted_history(
            &transaction,
            item_id,
            1,
            "created",
            actor,
            json!({"kind":request.kind,"kindPolicyDigest":snapshot.identity.digest}),
        )
        .await?;
        let result = RequesterHostedItem {
            item_id,
            requester_reference: request.requester_reference.clone(),
            kind: snapshot.identity.kind_id.clone(),
            version: snapshot.identity.version.clone(),
            display: request.display.clone(),
            state: OccurrenceState::Open,
            revision: 1,
            kind_policy_digest: snapshot.identity.digest.clone(),
            created_at: now,
            updated_at: now,
        };
        let response = serde_json::to_value(&result)?;
        insert_hosted_idempotency(
            &transaction,
            actor,
            "hosted.create",
            &request.kind,
            idempotency_key,
            &request_hash,
            item_id,
            &response,
        )
        .await?;
        transaction.commit().await?;
        Ok(result)
    }

    pub async fn replay_hosted_create(
        &self,
        actor: &ActorContext,
        request: &HostedCreateRequest,
        idempotency_key: &str,
    ) -> Result<Option<RequesterHostedItem>, StoreError> {
        if actor.role != CaseworkRole::Requester {
            return Err(StoreError::Forbidden);
        }
        let request_hash = hosted_request_hash(&(
            &actor.principal.issuer,
            &actor.principal.subject,
            &actor.profile_id,
            request.canonical_bytes().map_err(|_| StoreError::Invalid)?,
        ))?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let response = hosted_idempotent_response(
            &transaction,
            actor,
            "hosted.create",
            &request.kind,
            idempotency_key,
            &request_hash,
        )
        .await?;
        let result = response
            .map(serde_json::from_value)
            .transpose()
            .map_err(StoreError::Json)?;
        transaction.commit().await?;
        Ok(result)
    }

    pub async fn hosted_staff_inbox(
        &self,
        actor: &ActorContext,
        view: InboxView,
        limit: usize,
        queue: Option<&str>,
        cursor_context: &str,
        cursor: Option<&str>,
    ) -> Result<Page<WorkItem>, StoreError> {
        let membership_kind = membership_kind(actor.role)?;
        let limit = limit.clamp(1, 100);
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let after = resolve_hosted_cursor(&transaction, actor, cursor_context, cursor).await?;
        let has_after = after.is_some();
        let (after_at, after_id) = after.unwrap_or((Utc::now(), Uuid::nil()));
        let query_limit = i64::try_from(limit + 1).map_err(|_| StoreError::Invalid)?;
        let view = match view {
            InboxView::Mine => "mine",
            InboxView::MyTeams => "my_teams",
            InboxView::TeamHoldings => "team_holdings",
            InboxView::Overdue => "overdue",
            InboxView::CompletedByMe => "completed_by_me",
        };
        // Hosted kinds currently define neither passive targets nor clock policies. An overdue
        // hosted view is therefore truthfully empty instead of treating item age as a deadline.
        let rows = transaction.query(
            "SELECT i.* FROM casework_hosted_items i WHERE (i.terminal_retained_until IS NULL OR i.terminal_retained_until>now()) AND ($3='supervisor' OR i.kind_policy->'decidingProfiles' ? $4) AND EXISTS(SELECT 1 FROM casework_queue_service q JOIN casework_memberships m ON m.team_id=q.team_id WHERE q.queue_id=i.queue_id AND m.issuer=$1 AND m.subject=$2 AND m.membership_kind=$3) AND ($5::text IS NULL OR i.queue_id=$5) AND (($6='mine' AND i.state='claimed' AND i.holder_issuer=$1 AND i.holder_subject=$2) OR ($6='my_teams' AND i.state IN ('open','claimed')) OR ($6='team_holdings' AND i.state='claimed' AND i.holder_issuer IS NOT NULL) OR ($6='overdue' AND FALSE) OR ($6='completed_by_me' AND i.state='completed' AND EXISTS(SELECT 1 FROM casework_hosted_history h WHERE h.item_id=i.item_id AND h.kind='completed' AND h.actor_issuer=$1 AND h.actor_subject=$2))) AND (NOT $7 OR (i.created_at,i.item_id)>($8,$9)) ORDER BY i.created_at,i.item_id LIMIT $10 FOR SHARE OF i",
            &[&actor.principal.issuer,&actor.principal.subject,&membership_kind,&actor.profile_id,&queue,&view,&has_after,&after_at,&after_id,&query_limit],
        ).await?;
        let more = rows.len() > limit;
        let stored_items = rows
            .into_iter()
            .take(limit)
            .map(|row| stored_hosted_item(&row))
            .collect::<Result<Vec<_>, _>>()?;
        let item_ids = stored_items
            .iter()
            .map(|item| item.item_id)
            .collect::<Vec<_>>();
        let holder_timings = hosted_holder_timings(&transaction, &item_ids).await?;
        let mut items = Vec::with_capacity(stored_items.len());
        let mut last = None;
        for item in stored_items {
            last = Some((item.created_at, item.item_id));
            items.push(item.work_item(
                hosted_held_since(&item, &holder_timings),
                hosted_actions(actor, &item)?,
            )?);
        }
        let next_cursor = if more {
            Some(
                issue_hosted_cursor(
                    &transaction,
                    actor,
                    cursor_context,
                    last.ok_or(StoreError::Corrupt)?,
                )
                .await?,
            )
        } else {
            None
        };
        transaction.commit().await?;
        Ok(Page {
            items,
            next_cursor,
            status: PageStatus::Complete,
        })
    }

    pub async fn hosted_terminal_page(
        &self,
        actor: &ActorContext,
        allowed_kinds: &[String],
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<HostedTerminalPage, StoreError> {
        if actor.role != CaseworkRole::Requester {
            return Err(StoreError::Forbidden);
        }
        if allowed_kinds.is_empty() {
            return Err(StoreError::Forbidden);
        }
        let limit = limit.clamp(1, 100);
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let after =
            resolve_hosted_cursor(&transaction, actor, HOSTED_TERMINAL_CURSOR_CONTEXT, cursor)
                .await?;
        let has_after = after.is_some();
        let (after_at, after_id) = after.unwrap_or((Utc::now(), Uuid::nil()));
        let query_limit = i64::try_from(limit + 1).map_err(|_| StoreError::Invalid)?;
        let rows = transaction.query(
            "SELECT e.event_id,e.item_id,e.requester_reference,e.state,e.outcome,e.cancellation_reason,e.actor_ref,e.kind_policy_digest,e.terminal_at FROM casework_hosted_terminal_events e JOIN casework_hosted_items i ON i.item_id=e.item_id WHERE e.requester_issuer=$1 AND e.requester_subject=$2 AND e.requester_profile_id=$3 AND i.kind_id=ANY($4) AND e.retained_until>now() AND (NOT $5 OR (e.terminal_at,e.event_id)>($6,$7)) ORDER BY e.terminal_at,e.event_id LIMIT $8",
            &[&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&allowed_kinds,&has_after,&after_at,&after_id,&query_limit],
        ).await?;
        let more = rows.len() > limit;
        let mut items = Vec::with_capacity(rows.len().min(limit));
        let mut last = None;
        for row in rows.into_iter().take(limit) {
            let event_id: Uuid = row.get(0);
            let terminal_at: DateTime<Utc> = row.get(8);
            let terminal = match row.get::<_, String>(3).as_str() {
                "completed" => HostedTerminalState::Completed {
                    outcome: row.get::<_, Option<String>>(4).ok_or(StoreError::Corrupt)?,
                    actor_ref: OpaqueActorRef::parse(
                        &row.get::<_, Option<String>>(6).ok_or(StoreError::Corrupt)?,
                    )
                    .map_err(|_| StoreError::Corrupt)?,
                },
                "cancelled" => HostedTerminalState::Cancelled {
                    cancellation_reason: row
                        .get::<_, Option<String>>(5)
                        .ok_or(StoreError::Corrupt)?,
                },
                _ => return Err(StoreError::Corrupt),
            };
            last = Some((terminal_at, event_id));
            items.push(HostedTerminalResult {
                item_id: row.get(1),
                event_id,
                requester_reference: row.get(2),
                terminal,
                kind_policy_digest: HostedPolicyDigest::parse(&row.get::<_, String>(7))
                    .map_err(|_| StoreError::Corrupt)?,
                terminal_at,
            });
        }
        let next_cursor = if more {
            Some(
                issue_hosted_cursor(
                    &transaction,
                    actor,
                    HOSTED_TERMINAL_CURSOR_CONTEXT,
                    last.ok_or(StoreError::Corrupt)?,
                )
                .await?,
            )
        } else {
            None
        };
        transaction.commit().await?;
        Ok(Page {
            items,
            next_cursor,
            status: PageStatus::Complete,
        })
    }

    pub async fn hosted_accountability(
        &self,
        actor: &ActorContext,
        event_id: Uuid,
    ) -> Result<HostedAccountabilityRecord, StoreError> {
        if actor.role != CaseworkRole::Supervisor {
            return Err(StoreError::Forbidden);
        }
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let row = transaction.query_opt(
            "SELECT a.item_id,a.event_id,a.actor_ref,a.actor_issuer,a.actor_subject,a.profile_id,a.outcome,a.reason,a.occurred_at,a.retained_until,a.queue_id FROM casework_hosted_accountability a WHERE a.event_id=$1 AND a.retained_until>now()",
            &[&event_id],
        ).await?.ok_or(StoreError::NotFound)?;
        if !has_queue_authority(&transaction, actor, &row.get::<_, String>(10)).await? {
            return Err(StoreError::NotFound);
        }
        let record = HostedAccountabilityRecord {
            item_id: row.get(0),
            event_id: row.get(1),
            actor_ref: OpaqueActorRef::parse(&row.get::<_, String>(2))
                .map_err(|_| StoreError::Corrupt)?,
            actor: IssuerPrincipal {
                issuer: row.get(3),
                subject: row.get(4),
            },
            profile_id: row.get(5),
            outcome: row.get::<_, Option<String>>(6).ok_or(StoreError::Corrupt)?,
            reason: row.get(7),
            recorded_at: row.get(8),
            retained_until: row.get(9),
        };
        let read_event_id = Uuid::new_v4();
        transaction.execute(
            "INSERT INTO casework_audit_outbox(event_id,audit_record) VALUES($1,$2)",
            &[&read_event_id,&json!({"event":"casework.hosted_accountability_read","eventId":read_event_id,"itemId":record.item_id,"accountabilityEventId":record.event_id,"actor":{"issuer":actor.principal.issuer,"subject":actor.principal.subject},"profileId":actor.profile_id})],
        ).await?;
        transaction.commit().await?;
        Ok(record)
    }

    pub async fn requester_hosted_notes(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<Page<HostedNote>, StoreError> {
        if actor.role != CaseworkRole::Requester {
            return Err(StoreError::Forbidden);
        }
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let owned: bool = transaction.query_one(
            "SELECT EXISTS(SELECT 1 FROM casework_hosted_items WHERE item_id=$1 AND requester_issuer=$2 AND requester_subject=$3 AND requester_profile_id=$4 AND (terminal_retained_until IS NULL OR terminal_retained_until>now()))",
            &[&item_id,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id],
        ).await?.get(0);
        if !owned {
            return Err(StoreError::NotFound);
        }
        let context = format!("hosted-requester-notes:{item_id}");
        let page = hosted_notes_page(&transaction, actor, item_id, limit, &context, cursor).await?;
        transaction.commit().await?;
        Ok(page)
    }

    pub async fn staff_hosted_history(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<HostedHistoryPage, StoreError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let row = transaction.query_opt("SELECT * FROM casework_hosted_items WHERE item_id=$1 AND (terminal_retained_until IS NULL OR terminal_retained_until>now())", &[&item_id]).await?.ok_or(StoreError::NotFound)?;
        let item = stored_hosted_item(&row)?;
        if !has_queue_authority(&transaction, actor, &item.queue_id).await?
            || (actor.role == CaseworkRole::Staff
                && !item
                    .snapshot()?
                    .deciding_profiles
                    .contains(&actor.profile_id))
        {
            return Err(StoreError::NotFound);
        }
        let context = format!("hosted-staff-history:{item_id}");
        let limit = limit.clamp(1, 100);
        let after = resolve_hosted_cursor(&transaction, actor, &context, cursor).await?;
        let has_after = after.is_some();
        let (after_at, after_id) = after.unwrap_or((Utc::now(), Uuid::nil()));
        let query_limit = i64::try_from(limit + 1).map_err(|_| StoreError::Invalid)?;
        let rows = transaction.query(
            "SELECT h.event_id,h.item_id,h.item_revision,h.kind,h.occurred_at,r.actor_ref,n.note,h.detail FROM casework_hosted_history h LEFT JOIN casework_hosted_actor_references r ON r.issuer=h.actor_issuer AND r.subject=h.actor_subject LEFT JOIN casework_hosted_notes n ON n.event_id=NULLIF(h.detail->>'noteId','')::uuid WHERE h.item_id=$1 AND (NOT $2 OR (h.occurred_at,h.event_id)>($3,$4)) ORDER BY h.occurred_at,h.event_id LIMIT $5",
            &[&item_id,&has_after,&after_at,&after_id,&query_limit],
        ).await?;
        let more = rows.len() > limit;
        let mut items = Vec::with_capacity(rows.len().min(limit));
        let mut last = None;
        for row in rows.into_iter().take(limit) {
            let event_id: Uuid = row.get(0);
            let occurred_at: DateTime<Utc> = row.get(4);
            let kind = parse_hosted_history_kind(&row.get::<_, String>(3))?;
            let detail: Value = row.get(7);
            let actor_ref = match kind {
                HostedHistoryKind::Claimed
                | HostedHistoryKind::Assigned
                | HostedHistoryKind::Delegated
                | HostedHistoryKind::CaseloadMoved
                | HostedHistoryKind::Released
                | HostedHistoryKind::Completed => row
                    .get::<_, Option<String>>(5)
                    .map(|value| OpaqueActorRef::parse(&value).map_err(|_| StoreError::Corrupt))
                    .transpose()?,
                HostedHistoryKind::Created
                | HostedHistoryKind::NoteAdded
                | HostedHistoryKind::Cancelled => None,
            };
            let assignment = matches!(
                kind,
                HostedHistoryKind::Assigned
                    | HostedHistoryKind::Delegated
                    | HostedHistoryKind::CaseloadMoved
            )
            .then(|| detail.get("assignment").cloned())
            .flatten()
            .map(serde_json::from_value)
            .transpose()?
            .map(|mut assignment: AssignmentContext| {
                assignment.assigned_by = None;
                assignment
            });
            last = Some((occurred_at, event_id));
            items.push(HostedHistoryEntry {
                event_id,
                item_id: row.get(1),
                item_revision: row.get(2),
                kind,
                occurred_at,
                actor_ref,
                assignment,
                note: (kind == HostedHistoryKind::NoteAdded)
                    .then(|| row.get::<_, Option<String>>(6))
                    .flatten(),
                outcome: (kind == HostedHistoryKind::Completed)
                    .then(|| {
                        detail
                            .get("outcome")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
                    .flatten(),
                reason: matches!(
                    kind,
                    HostedHistoryKind::Completed
                        | HostedHistoryKind::Assigned
                        | HostedHistoryKind::Delegated
                        | HostedHistoryKind::CaseloadMoved
                )
                .then(|| {
                    detail
                        .get("reason")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .flatten(),
                cancellation_reason: (kind == HostedHistoryKind::Cancelled)
                    .then(|| {
                        detail
                            .get("cancellationReason")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
                    .flatten(),
            });
        }
        let next_cursor = if more {
            Some(
                issue_hosted_cursor(
                    &transaction,
                    actor,
                    &context,
                    last.ok_or(StoreError::Corrupt)?,
                )
                .await?,
            )
        } else {
            None
        };
        transaction.commit().await?;
        Ok(Page {
            items,
            next_cursor,
            status: PageStatus::Complete,
        })
    }

    pub async fn erase_expired_hosted_at(
        &self,
        now: DateTime<Utc>,
    ) -> Result<HostedRetentionResult, StoreError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        transaction.execute(
            "DELETE FROM casework_hosted_idempotency_tombstones WHERE binding_digest IN (SELECT binding_digest FROM casework_hosted_idempotency_tombstones WHERE retained_until<=$1 ORDER BY retained_until,binding_digest LIMIT $2 FOR UPDATE SKIP LOCKED)",
            &[&now,&RETENTION_BATCH_SIZE],
        ).await?;
        let accountability_records = transaction.execute(
            "DELETE FROM casework_hosted_accountability WHERE event_id IN (SELECT event_id FROM casework_hosted_accountability WHERE retained_until<=$1 ORDER BY retained_until,event_id LIMIT $2 FOR UPDATE SKIP LOCKED)",
            &[&now,&RETENTION_BATCH_SIZE],
        ).await?;
        let expired_cursors = transaction.execute(
            "DELETE FROM casework_hosted_cursors WHERE cursor_id IN (SELECT cursor_id FROM casework_hosted_cursors WHERE expires_at<=$1 ORDER BY expires_at,cursor_id LIMIT $2 FOR UPDATE SKIP LOCKED)",
            &[&now,&RETENTION_BATCH_SIZE],
        ).await?;
        let terminal_events = transaction.execute(
            "DELETE FROM casework_hosted_terminal_events WHERE event_id IN (SELECT event_id FROM casework_hosted_terminal_events WHERE retained_until<=$1 ORDER BY retained_until,event_id LIMIT $2 FOR UPDATE SKIP LOCKED)",
            &[&now,&RETENTION_BATCH_SIZE],
        ).await?;
        let rows = transaction.query(
            "SELECT item_id FROM casework_hosted_items WHERE terminal_retained_until<=$1 AND requester_issuer IS NOT NULL ORDER BY terminal_retained_until,item_id LIMIT $2 FOR UPDATE SKIP LOCKED",
            &[&now,&RETENTION_BATCH_SIZE],
        ).await?;
        let item_ids: Vec<Uuid> = rows.into_iter().map(|row| row.get(0)).collect();
        let mut item_payloads = 0_u64;
        if !item_ids.is_empty() {
            transaction.execute("DELETE FROM casework_hosted_notes WHERE event_id IN (SELECT event_id FROM casework_hosted_notes WHERE item_id=ANY($1) ORDER BY item_id,created_at,event_id LIMIT $2 FOR UPDATE SKIP LOCKED)", &[&item_ids,&RETENTION_BATCH_SIZE]).await?;
            transaction.execute("DELETE FROM casework_hosted_history WHERE event_id IN (SELECT event_id FROM casework_hosted_history WHERE item_id=ANY($1) ORDER BY item_id,occurred_at,event_id LIMIT $2 FOR UPDATE SKIP LOCKED)", &[&item_ids,&RETENTION_BATCH_SIZE]).await?;
            let idempotency_rows = transaction.query("SELECT d.issuer,d.subject,d.profile_id,d.operation,d.resource,d.idempotency_key,d.request_hash,i.terminal_retained_until,i.accountability_retained_until FROM casework_hosted_idempotency d JOIN casework_hosted_items i ON i.item_id=d.item_id WHERE d.item_id=ANY($1) ORDER BY d.created_at,d.issuer,d.subject,d.profile_id,d.operation,d.resource,d.idempotency_key LIMIT $2 FOR UPDATE OF d SKIP LOCKED", &[&item_ids,&RETENTION_BATCH_SIZE]).await?;
            for row in idempotency_rows {
                let issuer: String = row.get(0);
                let subject: String = row.get(1);
                let profile_id: String = row.get(2);
                let operation: String = row.get(3);
                let resource: String = row.get(4);
                let key: String = row.get(5);
                let request_hash: String = row.get(6);
                let expired_at: DateTime<Utc> = row
                    .get::<_, Option<DateTime<Utc>>>(7)
                    .ok_or(StoreError::Corrupt)?;
                let retained_until: DateTime<Utc> = row
                    .get::<_, Option<DateTime<Utc>>>(8)
                    .ok_or(StoreError::Corrupt)?;
                let binding_digest = hosted_request_hash(&(
                    &issuer,
                    &subject,
                    &profile_id,
                    &operation,
                    &resource,
                    &key,
                ))?;
                if retained_until > now {
                    transaction.execute("INSERT INTO casework_hosted_idempotency_tombstones(binding_digest,request_hash,expired_at,retained_until) VALUES($1,$2,$3,$4) ON CONFLICT(binding_digest) DO NOTHING", &[&binding_digest,&request_hash,&expired_at,&retained_until]).await?;
                }
                transaction.execute("DELETE FROM casework_hosted_idempotency WHERE issuer=$1 AND subject=$2 AND profile_id=$3 AND operation=$4 AND resource=$5 AND idempotency_key=$6", &[&issuer,&subject,&profile_id,&operation,&resource,&key]).await?;
            }
            item_payloads = transaction.execute(
                "UPDATE casework_hosted_items i SET requester_issuer=NULL,requester_subject=NULL,requester_profile_id=NULL,requester_reference=NULL,display=NULL WHERE i.item_id=ANY($1) AND NOT EXISTS(SELECT 1 FROM casework_hosted_notes n WHERE n.item_id=i.item_id) AND NOT EXISTS(SELECT 1 FROM casework_hosted_history h WHERE h.item_id=i.item_id) AND NOT EXISTS(SELECT 1 FROM casework_hosted_idempotency d WHERE d.item_id=i.item_id)",
                &[&item_ids],
            ).await?;
        }
        transaction.execute(
            "DELETE FROM casework_hosted_actor_references WHERE actor_ref IN (SELECT r.actor_ref FROM casework_hosted_actor_references r WHERE NOT EXISTS(SELECT 1 FROM casework_hosted_accountability a WHERE a.actor_ref=r.actor_ref) AND NOT EXISTS(SELECT 1 FROM casework_hosted_terminal_events e WHERE e.actor_ref=r.actor_ref) AND NOT EXISTS(SELECT 1 FROM casework_hosted_history h WHERE h.actor_issuer=r.issuer AND h.actor_subject=r.subject) ORDER BY r.actor_ref LIMIT $1 FOR UPDATE SKIP LOCKED)",
            &[&RETENTION_BATCH_SIZE],
        ).await?;
        transaction.commit().await?;
        Ok(HostedRetentionResult {
            terminal_events,
            item_payloads,
            accountability_records,
            expired_cursors,
        })
    }

    pub async fn erase_expired_hosted(&self) -> Result<HostedRetentionResult, StoreError> {
        self.erase_expired_hosted_at(Utc::now()).await
    }
}

async fn hosted_notes_page(
    transaction: &Transaction<'_>,
    actor: &ActorContext,
    item_id: Uuid,
    limit: usize,
    context: &str,
    cursor: Option<&str>,
) -> Result<Page<HostedNote>, StoreError> {
    let limit = limit.clamp(1, 100);
    let after = resolve_hosted_cursor(transaction, actor, context, cursor).await?;
    let has_after = after.is_some();
    let (after_at, after_id) = after.unwrap_or((Utc::now(), Uuid::nil()));
    let query_limit = i64::try_from(limit + 1).map_err(|_| StoreError::Invalid)?;
    let rows = transaction.query(
        "SELECT event_id,item_id,note,item_revision,created_at FROM casework_hosted_notes WHERE item_id=$1 AND (NOT $2 OR (created_at,event_id)>($3,$4)) ORDER BY created_at,event_id LIMIT $5",
        &[&item_id,&has_after,&after_at,&after_id,&query_limit],
    ).await?;
    let more = rows.len() > limit;
    let mut items = Vec::with_capacity(rows.len().min(limit));
    let mut last = None;
    for row in rows.into_iter().take(limit) {
        let note_id = row.get(0);
        let recorded_at = row.get(4);
        last = Some((recorded_at, note_id));
        items.push(HostedNote {
            note_id,
            item_id: row.get(1),
            note: row.get(2),
            item_revision: row.get(3),
            recorded_at,
        });
    }
    let next_cursor = if more {
        Some(
            issue_hosted_cursor(
                transaction,
                actor,
                context,
                last.ok_or(StoreError::Corrupt)?,
            )
            .await?,
        )
    } else {
        None
    };
    Ok(Page {
        items,
        next_cursor,
        status: PageStatus::Complete,
    })
}

fn parse_hosted_history_kind(value: &str) -> Result<HostedHistoryKind, StoreError> {
    match value {
        "created" => Ok(HostedHistoryKind::Created),
        "claimed" => Ok(HostedHistoryKind::Claimed),
        "assigned" => Ok(HostedHistoryKind::Assigned),
        "delegated" => Ok(HostedHistoryKind::Delegated),
        "caseload_moved" => Ok(HostedHistoryKind::CaseloadMoved),
        "released" => Ok(HostedHistoryKind::Released),
        "note_added" => Ok(HostedHistoryKind::NoteAdded),
        "completed" => Ok(HostedHistoryKind::Completed),
        "cancelled" => Ok(HostedHistoryKind::Cancelled),
        _ => Err(StoreError::Corrupt),
    }
}

async fn resolve_hosted_cursor(
    transaction: &Transaction<'_>,
    actor: &ActorContext,
    context: &str,
    cursor: Option<&str>,
) -> Result<Option<(DateTime<Utc>, Uuid)>, StoreError> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    let cursor_id = Uuid::parse_str(cursor).map_err(|_| StoreError::CursorInvalid)?;
    let row = transaction.query_opt(
        "SELECT issuer,subject,profile_id,context,last_at,last_id,expires_at FROM casework_hosted_cursors WHERE cursor_id=$1",
        &[&cursor_id],
    ).await?.ok_or(StoreError::CursorInvalid)?;
    if row.get::<_, String>(0) != actor.principal.issuer
        || row.get::<_, String>(1) != actor.principal.subject
        || row.get::<_, String>(2) != actor.profile_id
        || row.get::<_, String>(3) != context
    {
        return Err(StoreError::CursorInvalid);
    }
    if row.get::<_, DateTime<Utc>>(6) <= Utc::now() {
        return Err(StoreError::CursorExpired);
    }
    match (
        row.get::<_, Option<DateTime<Utc>>>(4),
        row.get::<_, Option<Uuid>>(5),
    ) {
        (Some(at), Some(id)) => Ok(Some((at, id))),
        (None, None) => Ok(None),
        _ => Err(StoreError::Corrupt),
    }
}

async fn issue_hosted_cursor(
    transaction: &Transaction<'_>,
    actor: &ActorContext,
    context: &str,
    last: (DateTime<Utc>, Uuid),
) -> Result<String, StoreError> {
    let cursor_id = Uuid::new_v4();
    let expires_at = Utc::now()
        .checked_add_signed(TimeDelta::seconds(HOSTED_CURSOR_SECONDS))
        .ok_or(StoreError::Corrupt)?;
    transaction.execute(
        "INSERT INTO casework_hosted_cursors(cursor_id,issuer,subject,profile_id,context,last_at,last_id,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
        &[&cursor_id,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&context,&last.0,&last.1,&expires_at],
    ).await?;
    Ok(cursor_id.to_string())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedRetentionResult {
    pub terminal_events: u64,
    pub item_payloads: u64,
    pub accountability_records: u64,
    pub expired_cursors: u64,
}

impl CaseworkService {
    fn requester_profile(
        &self,
        actor: &ActorContext,
    ) -> Result<&registry_casework_core::AccessProfile, ServiceError> {
        self.project
            .access_profiles
            .iter()
            .find(|profile| {
                profile.id == actor.profile_id
                    && profile.role == CaseworkRole::Requester
                    && actor.role == CaseworkRole::Requester
            })
            .ok_or(ServiceError::Forbidden)
    }

    async fn ensure_requester_item_kind(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
    ) -> Result<(), ServiceError> {
        let allowed = &self.requester_profile(actor)?.kinds;
        let kind = self.store.requester_hosted_kind(actor, item_id).await?;
        if allowed.contains(&kind) {
            Ok(())
        } else {
            Err(ServiceError::NotFound)
        }
    }

    async fn ensure_requester_mutation_kind(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
    ) -> Result<(), ServiceError> {
        let allowed = &self.requester_profile(actor)?.kinds;
        let kind = self.store.hosted_item_kind(item_id).await?;
        if allowed.contains(&kind) {
            Ok(())
        } else {
            Err(ServiceError::NotFound)
        }
    }

    pub async fn hosted_create(
        &self,
        actor: &ActorContext,
        request: &HostedCreateRequest,
        idempotency_key: &str,
    ) -> Result<RequesterHostedItem, ServiceError> {
        let profile = self.requester_profile(actor)?;
        if !profile.kinds.contains(&request.kind) {
            return Err(ServiceError::HostedValidation(HostedValidationError::new(
                "$.kind",
                HostedValidationReason::KindNotAllowed,
            )));
        }
        if let Some(replay) = self
            .store
            .replay_hosted_create(actor, request, idempotency_key)
            .await?
        {
            return Ok(replay);
        }
        let policy = self
            .project
            .hosted_kinds
            .iter()
            .find(|policy| policy.id == request.kind)
            .ok_or_else(|| {
                ServiceError::HostedValidation(HostedValidationError::new(
                    "$.kind",
                    HostedValidationReason::KindNotAllowed,
                ))
            })?;
        request.check(policy)?;
        let snapshot = policy.snapshot().map_err(|_| ServiceError::Configuration)?;
        self.store
            .create_hosted_item(actor, request, &snapshot, idempotency_key)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn hosted_requester_item(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
    ) -> Result<RequesterHostedItem, ServiceError> {
        self.ensure_requester_item_kind(actor, item_id).await?;
        self.store
            .requester_hosted_item(actor, item_id)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn hosted_note(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        request: &HostedNoteRequest,
        idempotency_key: &str,
    ) -> Result<RequesterHostedItem, ServiceError> {
        self.ensure_requester_mutation_kind(actor, item_id).await?;
        request.check()?;
        self.store
            .add_hosted_note(actor, item_id, expected_revision, request, idempotency_key)
            .await
            .map(|(item, _)| item)
            .map_err(ServiceError::from)
    }

    pub async fn hosted_cancel(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        request: &HostedCancelRequest,
        idempotency_key: &str,
    ) -> Result<HostedTerminalResult, ServiceError> {
        self.ensure_requester_mutation_kind(actor, item_id).await?;
        request.check()?;
        self.store
            .cancel_hosted_item(actor, item_id, expected_revision, request, idempotency_key)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn hosted_terminal_page(
        &self,
        actor: &ActorContext,
        limit: usize,
        cursor_context: &str,
        cursor: Option<&str>,
    ) -> Result<HostedTerminalPage, ServiceError> {
        if cursor_context != HOSTED_TERMINAL_CURSOR_CONTEXT {
            return Err(ServiceError::Store(StoreError::CursorInvalid));
        }
        let allowed_kinds = self.requester_profile(actor)?.kinds.clone();
        self.store
            .hosted_terminal_page(actor, &allowed_kinds, limit, cursor)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn hosted_staff_inbox(
        &self,
        actor: &ActorContext,
        view: InboxView,
        limit: usize,
        queue: Option<&str>,
        cursor_context: &str,
        cursor: Option<&str>,
    ) -> Result<WorkItemPage, ServiceError> {
        if cursor_context != HOSTED_STAFF_INBOX_CURSOR_CONTEXT {
            return Err(ServiceError::Store(StoreError::CursorInvalid));
        }
        let cursor_context = hosted_staff_cursor_context(cursor_context, view, queue)?;
        let mut page = self
            .store
            .hosted_staff_inbox(actor, view, limit, queue, &cursor_context, cursor)
            .await
            .map_err(ServiceError::from)?;
        let served_queues = self.store.served_queues(actor).await?;
        page.items
            .retain(|item| served_queues.binary_search(&item.queue_id).is_ok());
        Ok(WorkItemPage {
            items: page.items,
            next_cursor: page.next_cursor,
            status: page.status,
            served_queues,
        })
    }

    pub async fn hosted_work_item(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
    ) -> Result<WorkItem, ServiceError> {
        self.store
            .hosted_work_item(actor, item_id)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn hosted_claim(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<WorkItem, ServiceError> {
        self.store
            .claim_hosted_item(actor, item_id, expected_revision, idempotency_key)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn hosted_release(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<WorkItem, ServiceError> {
        self.store
            .release_hosted_item(actor, item_id, expected_revision, idempotency_key)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn hosted_decide(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        request: &HostedDecisionRequest,
        idempotency_key: &str,
    ) -> Result<HostedTerminalResult, ServiceError> {
        let snapshot = self.store.hosted_policy_for_actor(actor, item_id).await?;
        request.check(&snapshot)?;
        self.store
            .decide_hosted_item(actor, item_id, expected_revision, request, idempotency_key)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn hosted_accountability_record(
        &self,
        actor: &ActorContext,
        event_id: Uuid,
    ) -> Result<HostedAccountabilityRecord, ServiceError> {
        self.store
            .hosted_accountability(actor, event_id)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn hosted_requester_notes(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<Page<HostedNote>, ServiceError> {
        self.ensure_requester_item_kind(actor, item_id).await?;
        self.store
            .requester_hosted_notes(actor, item_id, limit, cursor)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn hosted_staff_history(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<HostedHistoryPage, ServiceError> {
        self.store
            .staff_hosted_history(actor, item_id, limit, cursor)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn erase_expired_hosted(&self) -> Result<HostedRetentionResult, ServiceError> {
        self.store
            .erase_expired_hosted()
            .await
            .map_err(ServiceError::from)
    }
}

fn hosted_staff_cursor_context(
    feed: &str,
    view: InboxView,
    queue: Option<&str>,
) -> Result<String, ServiceError> {
    serde_json::to_string(&HostedStaffCursorContext {
        feed,
        view,
        queue,
        ordering: "created-at-v1",
    })
    .map_err(|_| ServiceError::Configuration)
}

impl PostgresStore {
    async fn hosted_item_kind(&self, item_id: Uuid) -> Result<String, StoreError> {
        let client = self.client().await?;
        Ok(client
            .query_opt(
                "SELECT kind_id FROM casework_hosted_items WHERE item_id=$1",
                &[&item_id],
            )
            .await?
            .ok_or(StoreError::NotFound)?
            .get(0))
    }

    pub async fn requester_hosted_item(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
    ) -> Result<RequesterHostedItem, StoreError> {
        if actor.role != CaseworkRole::Requester {
            return Err(StoreError::Forbidden);
        }
        let client = self.client().await?;
        let row = client.query_opt(
            "SELECT * FROM casework_hosted_items WHERE item_id=$1 AND requester_issuer=$2 AND requester_subject=$3 AND requester_profile_id=$4 AND (terminal_retained_until IS NULL OR terminal_retained_until>now())",
            &[&item_id,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id],
        ).await?.ok_or(StoreError::NotFound)?;
        stored_hosted_item(&row)?.requester_projection()
    }

    pub async fn requester_hosted_kind(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
    ) -> Result<String, StoreError> {
        if actor.role != CaseworkRole::Requester {
            return Err(StoreError::Forbidden);
        }
        let client = self.client().await?;
        Ok(client.query_opt(
            "SELECT kind_id FROM casework_hosted_items WHERE item_id=$1 AND requester_issuer=$2 AND requester_subject=$3 AND requester_profile_id=$4 AND (terminal_retained_until IS NULL OR terminal_retained_until>now())",
            &[&item_id,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id],
        ).await?.ok_or(StoreError::NotFound)?.get(0))
    }

    pub async fn hosted_work_item(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
    ) -> Result<WorkItem, StoreError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let row = transaction.query_opt(
            "SELECT * FROM casework_hosted_items WHERE item_id=$1 AND (terminal_retained_until IS NULL OR terminal_retained_until>now())",
            &[&item_id],
        ).await?.ok_or(StoreError::NotFound)?;
        let item = stored_hosted_item(&row)?;
        if !has_queue_authority(&transaction, actor, &item.queue_id).await?
            || (actor.role == CaseworkRole::Staff
                && !item
                    .snapshot()?
                    .deciding_profiles
                    .contains(&actor.profile_id))
        {
            return Err(StoreError::NotFound);
        }
        let holder_timings = hosted_holder_timings(&transaction, &[item_id]).await?;
        item.work_item(
            hosted_held_since(&item, &holder_timings),
            hosted_actions(actor, &item)?,
        )
    }

    pub async fn add_hosted_note(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        request: &HostedNoteRequest,
        idempotency_key: &str,
    ) -> Result<(RequesterHostedItem, HostedNote), StoreError> {
        if actor.role != CaseworkRole::Requester || request.check().is_err() {
            return Err(if actor.role == CaseworkRole::Requester {
                StoreError::Invalid
            } else {
                StoreError::Forbidden
            });
        }
        let request_hash = hosted_request_hash(&(expected_revision, request))?;
        let resource = item_id.to_string();
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        if let Some(response) = hosted_idempotent_response(
            &transaction,
            actor,
            "hosted.note",
            &resource,
            idempotency_key,
            &request_hash,
        )
        .await?
        {
            return serde_json::from_value(response).map_err(StoreError::Json);
        }
        let row = transaction.query_opt(
            "SELECT * FROM casework_hosted_items WHERE item_id=$1 AND requester_issuer=$2 AND requester_subject=$3 AND requester_profile_id=$4 FOR UPDATE",
            &[&item_id,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id],
        ).await?.ok_or(StoreError::NotFound)?;
        let mut item = stored_hosted_item(&row)?;
        if item.revision != expected_revision || !item.state.is_active() {
            return Err(StoreError::Conflict);
        }
        let next = item.revision.checked_add(1).ok_or(StoreError::Corrupt)?;
        let now = Utc::now();
        let note_id = Uuid::new_v4();
        transaction.execute(
            "INSERT INTO casework_hosted_notes(event_id,item_id,item_revision,author_issuer,author_subject,author_profile_id,note,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
            &[&note_id,&item_id,&next,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&request.note,&now],
        ).await?;
        transaction
            .execute(
                "UPDATE casework_hosted_items SET revision=$2,updated_at=$3 WHERE item_id=$1",
                &[&item_id, &next, &now],
            )
            .await?;
        item.revision = next;
        item.updated_at = now;
        append_hosted_history(
            &transaction,
            item_id,
            next,
            "note_added",
            actor,
            json!({"noteId":note_id}),
        )
        .await?;
        let result = item.requester_projection()?;
        let note = HostedNote {
            note_id,
            item_id,
            note: request.note.clone(),
            item_revision: next,
            recorded_at: now,
        };
        let response = serde_json::to_value(&(result.clone(), note.clone()))?;
        insert_hosted_idempotency(
            &transaction,
            actor,
            "hosted.note",
            &resource,
            idempotency_key,
            &request_hash,
            item_id,
            &response,
        )
        .await?;
        transaction.commit().await?;
        Ok((result, note))
    }

    pub async fn cancel_hosted_item(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        request: &HostedCancelRequest,
        idempotency_key: &str,
    ) -> Result<HostedTerminalResult, StoreError> {
        if actor.role != CaseworkRole::Requester || request.check().is_err() {
            return Err(if actor.role == CaseworkRole::Requester {
                StoreError::Invalid
            } else {
                StoreError::Forbidden
            });
        }
        let request_hash = hosted_request_hash(&(expected_revision, request))?;
        let resource = item_id.to_string();
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        if let Some(response) = hosted_idempotent_response(
            &transaction,
            actor,
            "hosted.cancel",
            &resource,
            idempotency_key,
            &request_hash,
        )
        .await?
        {
            return serde_json::from_value(response).map_err(StoreError::Json);
        }
        let row = transaction.query_opt(
            "SELECT * FROM casework_hosted_items WHERE item_id=$1 AND requester_issuer=$2 AND requester_subject=$3 AND requester_profile_id=$4 FOR UPDATE",
            &[&item_id,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id],
        ).await?.ok_or(StoreError::NotFound)?;
        let item = stored_hosted_item(&row)?;
        if item.revision != expected_revision || !item.state.is_active() {
            return Err(StoreError::Conflict);
        }
        let snapshot = item.snapshot()?;
        let next = item.revision.checked_add(1).ok_or(StoreError::Corrupt)?;
        let now = Utc::now();
        let terminal_retained_until = retained_until(now, snapshot.retention.terminal_days)?;
        let accountability_retained_until =
            retained_until(now, snapshot.retention.accountability_days)?;
        let event_id = Uuid::new_v4();
        transaction.execute(
            "UPDATE casework_hosted_items SET state='cancelled',holder_issuer=NULL,holder_subject=NULL,revision=$2,updated_at=$3,terminal_at=$3,terminal_retained_until=$4,accountability_retained_until=$5 WHERE item_id=$1",
            &[&item_id,&next,&now,&terminal_retained_until,&accountability_retained_until],
        ).await?;
        let requester_reference = item.requester_reference.ok_or(StoreError::Corrupt)?;
        transaction.execute(
            "INSERT INTO casework_hosted_terminal_events(event_id,item_id,requester_issuer,requester_subject,requester_profile_id,requester_reference,state,outcome,cancellation_reason,actor_ref,kind_policy_digest,terminal_at,retained_until) VALUES($1,$2,$3,$4,$5,$6,'cancelled',NULL,$7,NULL,$8,$9,$10)",
            &[&event_id,&item_id,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&requester_reference,&request.reason,&item.kind_policy_digest,&now,&terminal_retained_until],
        ).await?;
        append_hosted_history(
            &transaction,
            item_id,
            next,
            "cancelled",
            actor,
            json!({"eventId":event_id,"cancellationReason":request.reason}),
        )
        .await?;
        let result = HostedTerminalResult {
            item_id,
            event_id,
            requester_reference,
            terminal: HostedTerminalState::Cancelled {
                cancellation_reason: request.reason.clone(),
            },
            kind_policy_digest: HostedPolicyDigest::parse(&item.kind_policy_digest)
                .map_err(|_| StoreError::Corrupt)?,
            terminal_at: now,
        };
        let response = serde_json::to_value(&result)?;
        insert_hosted_idempotency(
            &transaction,
            actor,
            "hosted.cancel",
            &resource,
            idempotency_key,
            &request_hash,
            item_id,
            &response,
        )
        .await?;
        transaction.commit().await?;
        Ok(result)
    }

    pub async fn claim_hosted_item(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<WorkItem, StoreError> {
        self.change_hosted_holder(actor, item_id, expected_revision, idempotency_key, true)
            .await
    }

    pub async fn release_hosted_item(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<WorkItem, StoreError> {
        self.change_hosted_holder(actor, item_id, expected_revision, idempotency_key, false)
            .await
    }

    async fn change_hosted_holder(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
        claim: bool,
    ) -> Result<WorkItem, StoreError> {
        let operation = if claim {
            "hosted.claim"
        } else {
            "hosted.release"
        };
        let resource = item_id.to_string();
        let request_hash = hosted_request_hash(&(expected_revision, claim))?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let row = transaction
            .query_opt(
                "SELECT * FROM casework_hosted_items WHERE item_id=$1 FOR UPDATE",
                &[&item_id],
            )
            .await?
            .ok_or(StoreError::NotFound)?;
        let mut item = stored_hosted_item(&row)?;
        let snapshot = item.snapshot()?;
        let supervisor_release = !claim && actor.role == CaseworkRole::Supervisor;
        if !has_queue_authority(&transaction, actor, &item.queue_id).await?
            || (!supervisor_release && !snapshot.deciding_profiles.contains(&actor.profile_id))
        {
            return Err(StoreError::Forbidden);
        }
        if let Some(response) = hosted_idempotent_response(
            &transaction,
            actor,
            operation,
            &resource,
            idempotency_key,
            &request_hash,
        )
        .await?
        {
            return serde_json::from_value(response).map_err(StoreError::Json);
        }
        if item.revision != expected_revision || !item.state.is_active() {
            return Err(StoreError::Conflict);
        }
        let owns = item.holder.as_ref() == Some(&actor.principal);
        if claim && item.holder.is_some() {
            return Err(StoreError::AlreadyClaimed);
        }
        if !(claim || owns || supervisor_release && item.holder.is_some()) {
            return Err(StoreError::NotHolder);
        }
        let next = item.revision.checked_add(1).ok_or(StoreError::Corrupt)?;
        let now = Utc::now();
        let previous_holder = item.holder.clone();
        let (state, holder) = if claim {
            (HostedState::Claimed, Some(actor.principal.clone()))
        } else {
            (HostedState::Open, None)
        };
        transaction.execute(
            "UPDATE casework_hosted_items SET state=$2,holder_issuer=$3,holder_subject=$4,revision=$5,updated_at=$6,assignment_owner_issuer=$7,assignment_owner_subject=$8,assigned_by_issuer=NULL,assigned_by_subject=NULL,assignment_absence_ids='{}',staffing_diagnostic=NULL WHERE item_id=$1",
            &[&item_id,&state.name(),&holder.as_ref().map(|p|&p.issuer),&holder.as_ref().map(|p|&p.subject),&next,&now,&holder.as_ref().map(|p|&p.issuer),&holder.as_ref().map(|p|&p.subject)],
        ).await?;
        item.state = state;
        item.holder = holder;
        item.assignment = item.holder.clone().map(|owner| AssignmentContext {
            owner: Some(owner),
            assigned_by: None,
            absence_ids: Vec::new(),
            staffing_diagnostic: None,
        });
        item.revision = next;
        item.updated_at = now;
        let holder_event_id = append_hosted_history(
            &transaction,
            item_id,
            next,
            if claim { "claimed" } else { "released" },
            actor,
            if claim {
                json!({})
            } else {
                json!({"previousHolder": previous_holder})
            },
        )
        .await?;
        let held_since = if claim {
            Some(
                transaction
                    .query_one(
                        "SELECT occurred_at FROM casework_hosted_history WHERE event_id=$1",
                        &[&holder_event_id],
                    )
                    .await?
                    .get(0),
            )
        } else {
            None
        };
        let result = item.work_item(held_since, hosted_actions(actor, &item)?)?;
        let response = serde_json::to_value(&result)?;
        insert_hosted_idempotency(
            &transaction,
            actor,
            operation,
            &resource,
            idempotency_key,
            &request_hash,
            item_id,
            &response,
        )
        .await?;
        transaction.commit().await?;
        Ok(result)
    }

    pub async fn hosted_policy_for_actor(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
    ) -> Result<HostedKindPolicySnapshot, StoreError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let row = transaction
            .query_opt(
                "SELECT * FROM casework_hosted_items WHERE item_id=$1",
                &[&item_id],
            )
            .await?
            .ok_or(StoreError::NotFound)?;
        let item = stored_hosted_item(&row)?;
        let snapshot = item.snapshot()?;
        if !snapshot.deciding_profiles.contains(&actor.profile_id)
            || !has_queue_authority(&transaction, actor, &item.queue_id).await?
        {
            return Err(StoreError::NotFound);
        }
        Ok(snapshot)
    }

    pub async fn decide_hosted_item(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        request: &HostedDecisionRequest,
        idempotency_key: &str,
    ) -> Result<HostedTerminalResult, StoreError> {
        let request_hash = hosted_request_hash(&(expected_revision, request))?;
        let resource = item_id.to_string();
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let row = transaction
            .query_opt(
                "SELECT * FROM casework_hosted_items WHERE item_id=$1 FOR UPDATE",
                &[&item_id],
            )
            .await?
            .ok_or(StoreError::NotFound)?;
        let item = stored_hosted_item(&row)?;
        let snapshot = item.snapshot()?;
        if request.check(&snapshot).is_err() {
            return Err(StoreError::Invalid);
        }
        if !snapshot.deciding_profiles.contains(&actor.profile_id)
            || !has_queue_authority(&transaction, actor, &item.queue_id).await?
        {
            return Err(StoreError::Forbidden);
        }
        if let Some(response) = hosted_idempotent_response(
            &transaction,
            actor,
            "hosted.decide",
            &resource,
            idempotency_key,
            &request_hash,
        )
        .await?
        {
            return serde_json::from_value(response).map_err(StoreError::Json);
        }
        if item.revision != expected_revision || item.state != HostedState::Claimed {
            return Err(StoreError::Conflict);
        }
        if item.holder.as_ref() != Some(&actor.principal) {
            return Err(StoreError::NotHolder);
        }
        let next = item.revision.checked_add(1).ok_or(StoreError::Corrupt)?;
        let now = Utc::now();
        let terminal_retained_until = retained_until(now, snapshot.retention.terminal_days)?;
        let accountability_retained_until =
            retained_until(now, snapshot.retention.accountability_days)?;
        let actor_ref = hosted_actor_reference(&transaction, actor).await?;
        let event_id = Uuid::new_v4();
        transaction.execute(
            "UPDATE casework_hosted_items SET state='completed',holder_issuer=NULL,holder_subject=NULL,revision=$2,updated_at=$3,terminal_at=$3,terminal_retained_until=$4,accountability_retained_until=$5 WHERE item_id=$1",
            &[&item_id,&next,&now,&terminal_retained_until,&accountability_retained_until],
        ).await?;
        let requester = item.requester.ok_or(StoreError::Corrupt)?;
        let requester_profile_id = item.requester_profile_id.ok_or(StoreError::Corrupt)?;
        let requester_reference = item.requester_reference.ok_or(StoreError::Corrupt)?;
        transaction.execute(
            "INSERT INTO casework_hosted_terminal_events(event_id,item_id,requester_issuer,requester_subject,requester_profile_id,requester_reference,state,outcome,cancellation_reason,actor_ref,kind_policy_digest,terminal_at,retained_until) VALUES($1,$2,$3,$4,$5,$6,'completed',$7,NULL,$8,$9,$10,$11)",
            &[&event_id,&item_id,&requester.issuer,&requester.subject,&requester_profile_id,&requester_reference,&request.outcome,&actor_ref,&item.kind_policy_digest,&now,&terminal_retained_until],
        ).await?;
        transaction.execute(
            "INSERT INTO casework_hosted_accountability(event_id,item_id,actor_ref,actor_issuer,actor_subject,profile_id,queue_id,outcome,reason,occurred_at,retained_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
            &[&event_id,&item_id,&actor_ref,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&item.queue_id,&request.outcome,&request.reason,&now,&accountability_retained_until],
        ).await?;
        append_hosted_history(&transaction,item_id,next,"completed",actor,json!({"eventId":event_id,"outcome":request.outcome,"reason":request.reason,"actorRef":actor_ref})).await?;
        let result = HostedTerminalResult {
            item_id,
            event_id,
            requester_reference,
            terminal: HostedTerminalState::Completed {
                outcome: request.outcome.clone(),
                actor_ref: OpaqueActorRef::parse(&actor_ref).map_err(|_| StoreError::Corrupt)?,
            },
            kind_policy_digest: HostedPolicyDigest::parse(&item.kind_policy_digest)
                .map_err(|_| StoreError::Corrupt)?,
            terminal_at: now,
        };
        let response = serde_json::to_value(&result)?;
        insert_hosted_idempotency(
            &transaction,
            actor,
            "hosted.decide",
            &resource,
            idempotency_key,
            &request_hash,
            item_id,
            &response,
        )
        .await?;
        transaction.commit().await?;
        Ok(result)
    }
}
