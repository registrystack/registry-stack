// SPDX-License-Identifier: Apache-2.0

//! Product-owned, relational change-request bookkeeping. Business intake stays
//! in the compiled entity table; immutable proposals and decisions live here.

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_canonical_json::canonicalize_json;
use serde_json::{Map, Value};
use tokio_postgres::error::SqlState;
use tokio_postgres::{GenericClient, Transaction};
use uuid::Uuid;

use crate::contract::Operation;
use crate::mutation::MutationError;
use crate::postgres::SqlIdentifier;
use crate::request_prepare::RequestTargetSnapshot;
use crate::request_workflow::{
    ApplicationId, ApplicationReceipt, ApplicationResultLink, EntityId, ProposalDigest,
    ProposalSnapshot, ProposalVersion, RecordId, RecordRevision, RequestKey, RequestState,
    RequestWorkflow, ReviewDecision, ReviewDecisionKind, StateRevision, TrustedActorRef,
    TrustedTimestamp, MAX_REQUEST_SNAPSHOT_BYTES, MAX_REQUEST_TARGETS,
};

pub(crate) const REQUEST_TABLES: &[(&str, &[&str])] = &[
    ("registry_request_state", &["INSERT", "SELECT", "UPDATE"]),
    (
        "registry_request_intake_presence",
        &["DELETE", "INSERT", "SELECT"],
    ),
    ("registry_request_proposals", &["INSERT", "SELECT"]),
    ("registry_request_task_authority", &["INSERT", "SELECT"]),
    ("registry_request_targets", &["INSERT", "SELECT"]),
    ("registry_request_decisions", &["INSERT", "SELECT"]),
    ("registry_request_applications", &["INSERT", "SELECT"]),
    ("registry_request_results", &["INSERT", "SELECT"]),
    ("registry_request_idempotency_links", &["INSERT", "SELECT"]),
    ("registry_request_revision_links", &["INSERT", "SELECT"]),
];

pub(crate) async fn install(
    client: &impl GenericClient,
    runtime_role: &SqlIdentifier,
) -> Result<(), MutationError> {
    client.batch_execute(
        "CREATE TABLE IF NOT EXISTS registry_internal.registry_request_state (
             request_entity_id text NOT NULL CHECK (request_entity_id <> ''),
             request_id uuid NOT NULL,
             owner_reference text NOT NULL CHECK (owner_reference <> ''),
             state text NOT NULL CHECK (state IN
                 ('draft','submitted','approved','needs_changes','rejected','canceled','applied')),
             proposal_version bigint NOT NULL CHECK (proposal_version BETWEEN 1 AND 4294967295),
             workflow_revision bigint NOT NULL CHECK (workflow_revision > 0),
             review_completed_at timestamptz,
             detail_erased_at timestamptz,
             created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
             updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
             PRIMARY KEY (request_entity_id, request_id)
         );
         ALTER TABLE registry_internal.registry_request_state
             ADD COLUMN IF NOT EXISTS detail_erased_at timestamptz,
             ADD COLUMN IF NOT EXISTS review_completed_at timestamptz;
         ALTER TABLE registry_internal.registry_request_state
             DROP CONSTRAINT IF EXISTS registry_request_state_detail_erasure_terminal;
         ALTER TABLE registry_internal.registry_request_state
             ADD CONSTRAINT registry_request_state_detail_erasure_terminal CHECK (
                 detail_erased_at IS NULL OR state IN ('rejected','canceled','applied')
             );
         CREATE TABLE IF NOT EXISTS registry_internal.registry_request_intake_presence (
             request_entity_id text NOT NULL CHECK (request_entity_id <> ''),
             request_id uuid NOT NULL,
             field_id text NOT NULL CHECK (field_id <> ''),
             PRIMARY KEY (request_entity_id, request_id, field_id),
             FOREIGN KEY (request_entity_id, request_id)
                 REFERENCES registry_internal.registry_request_state
                 ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS registry_internal.registry_request_proposals (
             request_entity_id text NOT NULL,
             request_id uuid NOT NULL,
             proposal_version bigint NOT NULL CHECK (proposal_version BETWEEN 1 AND 4294967295),
             request_record_revision bigint NOT NULL CHECK (request_record_revision > 0),
             contract_fingerprint text NOT NULL CHECK (contract_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
             effect_digest text NOT NULL CHECK (effect_digest ~ '^sha256:[0-9a-f]{64}$'),
             snapshot jsonb,
             erased_at timestamptz,
             created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
             PRIMARY KEY (request_entity_id, request_id, proposal_version),
             FOREIGN KEY (request_entity_id, request_id)
                 REFERENCES registry_internal.registry_request_state,
             CHECK ((snapshot IS NULL) = (erased_at IS NOT NULL)),
             CHECK (snapshot IS NULL OR jsonb_typeof(snapshot) = 'object')
         );
         CREATE TABLE IF NOT EXISTS registry_internal.registry_request_task_authority (
             request_entity_id text NOT NULL,
             request_id uuid NOT NULL,
             proposal_version bigint NOT NULL,
             binding jsonb NOT NULL CHECK (
                 jsonb_typeof(binding) = 'object' AND octet_length(binding::text) <= 65536
             ),
             PRIMARY KEY (request_entity_id, request_id, proposal_version),
             FOREIGN KEY (request_entity_id, request_id, proposal_version)
                 REFERENCES registry_internal.registry_request_proposals
         );
         CREATE TABLE IF NOT EXISTS registry_internal.registry_request_targets (
             request_entity_id text NOT NULL,
             request_id uuid NOT NULL,
             proposal_version bigint NOT NULL,
             target_entity_id text NOT NULL CHECK (target_entity_id <> ''),
             target_record_id uuid NOT NULL,
             operation text NOT NULL CHECK (operation IN ('create','patch')),
             expected_revision bigint CHECK (expected_revision > 0),
             base_snapshot jsonb,
             after_snapshot jsonb,
             erased_at timestamptz,
             PRIMARY KEY (request_entity_id, request_id, proposal_version,
                          target_entity_id, target_record_id),
             FOREIGN KEY (request_entity_id, request_id, proposal_version)
                 REFERENCES registry_internal.registry_request_proposals,
             CHECK ((operation = 'create' AND expected_revision IS NULL)
                    OR (operation = 'patch' AND expected_revision IS NOT NULL)),
             CHECK (base_snapshot IS NULL OR jsonb_typeof(base_snapshot) = 'object'),
             CHECK (after_snapshot IS NULL OR jsonb_typeof(after_snapshot) = 'object'),
             CHECK (erased_at IS NULL OR (base_snapshot IS NULL AND after_snapshot IS NULL))
         );
         CREATE INDEX IF NOT EXISTS registry_request_pending_targets
             ON registry_internal.registry_request_targets (target_entity_id, target_record_id);
         CREATE INDEX IF NOT EXISTS registry_request_queue
             ON registry_internal.registry_request_state (request_entity_id, state, request_id);
         CREATE TABLE IF NOT EXISTS registry_internal.registry_request_decisions (
             request_entity_id text NOT NULL,
             request_id uuid NOT NULL,
             proposal_version bigint NOT NULL,
             decision_index integer NOT NULL CHECK (decision_index >= 0),
             stage_id text NOT NULL CHECK (stage_id <> ''),
             actor_reference text NOT NULL CHECK (actor_reference <> ''),
             decision text NOT NULL CHECK (decision IN ('approve','reject','request_revision')),
             effect_digest text NOT NULL CHECK (effect_digest ~ '^sha256:[0-9a-f]{64}$'),
             decided_at timestamptz NOT NULL,
             reason text,
             reason_present boolean NOT NULL DEFAULT false,
             PRIMARY KEY (request_entity_id, request_id, proposal_version, decision_index),
             UNIQUE (request_entity_id, request_id, proposal_version, stage_id, actor_reference),
             FOREIGN KEY (request_entity_id, request_id, proposal_version)
                 REFERENCES registry_internal.registry_request_proposals
         );
         ALTER TABLE registry_internal.registry_request_decisions
             ADD COLUMN IF NOT EXISTS reason text,
             ADD COLUMN IF NOT EXISTS reason_present boolean NOT NULL DEFAULT false;
         ALTER TABLE registry_internal.registry_request_decisions
             DROP CONSTRAINT IF EXISTS registry_request_decision_reason_bound;
         ALTER TABLE registry_internal.registry_request_decisions
             ADD CONSTRAINT registry_request_decision_reason_bound CHECK (
                 (reason IS NULL OR (char_length(reason) <= 4096 AND reason_present))
                 AND (NOT reason_present OR decision IN ('reject','request_revision'))
             );
         CREATE TABLE IF NOT EXISTS registry_internal.registry_request_applications (
             request_entity_id text NOT NULL,
             request_id uuid NOT NULL,
             proposal_version bigint NOT NULL,
             application_id uuid NOT NULL UNIQUE,
             effect_digest text NOT NULL CHECK (effect_digest ~ '^sha256:[0-9a-f]{64}$'),
             applied_by text NOT NULL CHECK (applied_by <> ''),
             applied_at timestamptz NOT NULL,
             PRIMARY KEY (request_entity_id, request_id, proposal_version),
             FOREIGN KEY (request_entity_id, request_id, proposal_version)
                 REFERENCES registry_internal.registry_request_proposals
         );
         CREATE TABLE IF NOT EXISTS registry_internal.registry_request_results (
             request_entity_id text NOT NULL,
             request_id uuid NOT NULL,
             proposal_version bigint NOT NULL,
             target_entity_id text NOT NULL,
             target_record_id uuid NOT NULL,
             target_revision bigint NOT NULL CHECK (target_revision > 0),
             PRIMARY KEY (request_entity_id, request_id, proposal_version,
                          target_entity_id, target_record_id),
             FOREIGN KEY (request_entity_id, request_id, proposal_version)
                 REFERENCES registry_internal.registry_request_applications,
             FOREIGN KEY (target_entity_id, target_record_id, target_revision)
                 REFERENCES registry_internal.registry_revisions
                     (entity_id, record_id, record_revision)
         );
         CREATE TABLE IF NOT EXISTS registry_internal.registry_request_idempotency_links (
             key_reference text NOT NULL,
             request_entity_id text NOT NULL CHECK (request_entity_id <> ''),
             request_id uuid NOT NULL,
             proposal_version bigint NOT NULL CHECK (proposal_version > 0),
             created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
             PRIMARY KEY (key_reference, request_entity_id, request_id, proposal_version),
             FOREIGN KEY (key_reference)
                 REFERENCES registry_internal.registry_idempotency (key_reference),
             FOREIGN KEY (request_entity_id, request_id)
                 REFERENCES registry_internal.registry_request_state
         );
         CREATE INDEX IF NOT EXISTS registry_request_idempotency_by_request
             ON registry_internal.registry_request_idempotency_links
                 (request_entity_id, request_id, proposal_version);
         CREATE TABLE IF NOT EXISTS registry_internal.registry_request_revision_links (
             entity_id text NOT NULL CHECK (entity_id <> ''),
             record_id uuid NOT NULL,
             record_revision bigint NOT NULL CHECK (record_revision > 0),
             request_entity_id text NOT NULL CHECK (request_entity_id <> ''),
             request_id uuid NOT NULL,
             proposal_version bigint NOT NULL CHECK (proposal_version > 0),
             link_kind text NOT NULL CHECK (link_kind IN
                 ('request_create','request_patch','request_lifecycle','request_batch')),
             created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
             PRIMARY KEY (entity_id, record_id, record_revision,
                          request_entity_id, request_id, proposal_version),
             FOREIGN KEY (entity_id, record_id, record_revision)
                 REFERENCES registry_internal.registry_revisions
                     (entity_id, record_id, record_revision),
             FOREIGN KEY (request_entity_id, request_id)
                 REFERENCES registry_internal.registry_request_state
         );
         UPDATE registry_internal.registry_request_state s
            SET review_completed_at = CASE
                WHEN s.state IN ('approved', 'applied') THEN COALESCE(
                    (SELECT max(d.decided_at)
                       FROM registry_internal.registry_request_decisions d
                      WHERE d.request_entity_id = s.request_entity_id
                        AND d.request_id = s.request_id
                        AND d.proposal_version = s.proposal_version
                        AND d.decision = 'approve'),
                    (SELECT p.created_at
                       FROM registry_internal.registry_request_proposals p
                      WHERE p.request_entity_id = s.request_entity_id
                        AND p.request_id = s.request_id
                        AND p.proposal_version = s.proposal_version))
                WHEN s.state = 'rejected' THEN
                    (SELECT min(d.decided_at)
                       FROM registry_internal.registry_request_decisions d
                      WHERE d.request_entity_id = s.request_entity_id
                        AND d.request_id = s.request_id
                        AND d.decision = 'reject')
                WHEN s.state = 'canceled' THEN COALESCE(
                    (SELECT min(d.decided_at)
                       FROM registry_internal.registry_request_decisions d
                      WHERE d.request_entity_id = s.request_entity_id
                        AND d.request_id = s.request_id
                        AND d.decision = 'reject'),
                    (SELECT max(r.created_at)
                       FROM registry_internal.registry_request_revision_links l
                       JOIN registry_internal.registry_revisions r
                         ON r.entity_id = l.entity_id
                        AND r.record_id = l.record_id
                        AND r.record_revision = l.record_revision
                      WHERE l.request_entity_id = s.request_entity_id
                        AND l.request_id = s.request_id
                        AND l.link_kind = 'request_lifecycle'))
                ELSE NULL
            END
          WHERE s.review_completed_at IS NULL
            AND s.state IN ('approved', 'rejected', 'canceled', 'applied');"
    ).await.map_err(|_| MutationError::Unavailable)?;
    crate::attachment_store::install(client, runtime_role).await?;
    for (table, privileges) in REQUEST_TABLES {
        let role = runtime_role.as_str();
        client
            .batch_execute(&format!(
                "REVOKE ALL ON registry_internal.{table} FROM PUBLIC, \"{role}\";
             GRANT {} ON registry_internal.{table} TO \"{role}\";",
                privileges.join(", ")
            ))
            .await
            .map_err(|_| MutationError::Unavailable)?;
    }
    Ok(())
}

/// Retain verified submitter authority separately from all later reviewers.
/// The proposal foreign key binds these claims to its immutable effect digest.
pub(crate) async fn save_task_authority(
    transaction: &Transaction<'_>,
    entity_id: &str,
    record_id: Uuid,
    proposal_version: i64,
    binding: &crate::task_grant::TaskGrantBinding,
) -> Result<(), MutationError> {
    binding
        .validate()
        .map_err(|_| MutationError::PreconditionFailed)?;
    let value = serde_json::to_value(binding).map_err(|_| MutationError::Unavailable)?;
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_request_task_authority
             (request_entity_id, request_id, proposal_version, binding)
         VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
            &[&entity_id, &record_id, &proposal_version, &value],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    let stored = load_task_authority(transaction, entity_id, record_id, proposal_version).await?;
    if stored.as_ref() != Some(binding) {
        return Err(MutationError::IdempotencyConflict);
    }
    Ok(())
}

/// Call only after proving current visibility of the corresponding request.
pub(crate) async fn load_task_authority(
    transaction: &Transaction<'_>,
    entity_id: &str,
    record_id: Uuid,
    proposal_version: i64,
) -> Result<Option<crate::task_grant::TaskGrantBinding>, MutationError> {
    let row = transaction
        .query_opt(
            "SELECT binding FROM registry_internal.registry_request_task_authority
         WHERE request_entity_id = $1 AND request_id = $2 AND proposal_version = $3",
            &[&entity_id, &record_id, &proposal_version],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    row.map(|row| {
        let binding: crate::task_grant::TaskGrantBinding =
            serde_json::from_value(row.get::<_, Value>(0))
                .map_err(|_| MutationError::Unavailable)?;
        binding.validate().map_err(|_| MutationError::Unavailable)?;
        Ok(binding)
    })
    .transpose()
}

#[derive(Clone, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct RequestWorkflowHeader {
    pub owner_reference: String,
    pub state: String,
    pub proposal_version: i64,
    pub workflow_revision: i64,
    pub current_proposal_erased: bool,
    pub applier_reference: Option<String>,
}

impl std::fmt::Debug for RequestWorkflowHeader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RequestWorkflowHeader")
            .field("has_owner_reference", &!self.owner_reference.is_empty())
            .field("state", &self.state)
            .field("proposal_version", &self.proposal_version)
            .field("workflow_revision", &self.workflow_revision)
            .field("current_proposal_erased", &self.current_proposal_erased)
            .field("has_applier_reference", &self.applier_reference.is_some())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RequestReviewTiming {
    pub first_submitted_at: String,
    pub paused_milliseconds: i64,
    pub pause_started_at: Option<String>,
    pub completed_at: Option<String>,
}

impl RequestWorkflowHeader {
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn is_terminal(&self) -> bool {
        matches!(self.state.as_str(), "rejected" | "canceled" | "applied")
    }
}

/// Loads the bounded, request-wide clock facts retained independently from
/// proposal payload detail. Correction intervals are derived from durable
/// decision and proposal rows and stop changing after the first completion.
pub(crate) async fn load_review_timing(
    transaction: &Transaction<'_>,
    entity_id: &str,
    record_id: Uuid,
) -> Result<Option<RequestReviewTiming>, MutationError> {
    let row = transaction
        .query_one(
            "WITH request_summary AS (
                 SELECT review_completed_at
                   FROM registry_internal.registry_request_state
                  WHERE request_entity_id = $1 AND request_id = $2
             ), first_submission AS (
                 SELECT min(created_at) AS first_submitted_at
                   FROM registry_internal.registry_request_proposals
                  WHERE request_entity_id = $1 AND request_id = $2
             ), correction_pauses AS (
                 SELECT d.decided_at AS started_at,
                        (SELECT min(p.created_at)
                           FROM registry_internal.registry_request_proposals p
                          WHERE p.request_entity_id = d.request_entity_id
                            AND p.request_id = d.request_id
                            AND p.proposal_version > d.proposal_version) AS resumed_at
                   FROM registry_internal.registry_request_decisions d
                  WHERE d.request_entity_id = $1
                    AND d.request_id = $2
                    AND d.decision = 'request_revision'
             ), bounded_pauses AS (
                 SELECT started_at,
                        CASE
                            WHEN r.review_completed_at IS NOT NULL
                             AND (resumed_at IS NULL OR r.review_completed_at < resumed_at)
                                THEN r.review_completed_at
                            ELSE resumed_at
                        END AS ended_at,
                        r.review_completed_at
                   FROM correction_pauses
                   CROSS JOIN request_summary r
                  WHERE r.review_completed_at IS NULL
                     OR started_at < r.review_completed_at
             ), pause_summary AS (
                 SELECT COALESCE(sum(GREATEST(
                            0,
                            floor(extract(epoch FROM (ended_at - started_at)) * 1000)::bigint
                        )) FILTER (WHERE ended_at IS NOT NULL), 0)::bigint AS paused_milliseconds,
                        max(started_at) FILTER (
                            WHERE ended_at IS NULL AND review_completed_at IS NULL
                        ) AS pause_started_at
                   FROM bounded_pauses
             )
             SELECT to_char(f.first_submitted_at AT TIME ZONE 'UTC',
                            'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
                    p.paused_milliseconds,
                    to_char(p.pause_started_at AT TIME ZONE 'UTC',
                            'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
                    to_char(r.review_completed_at AT TIME ZONE 'UTC',
                            'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')
               FROM request_summary r
               CROSS JOIN first_submission f
               CROSS JOIN pause_summary p",
            &[&entity_id, &record_id],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    let Some(first_submitted_at) = row.get::<_, Option<String>>(0) else {
        return Ok(None);
    };
    Ok(Some(RequestReviewTiming {
        first_submitted_at,
        paused_milliseconds: row.get(1),
        pause_started_at: row.get(2),
        completed_at: row.get(3),
    }))
}

/// Called in the same transaction as the intake CREATE, including batch CREATE.
pub(crate) async fn initialize_draft(
    transaction: &Transaction<'_>,
    entity_id: &str,
    record_id: Uuid,
    owner_reference: &str,
) -> Result<(), MutationError> {
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_request_state
             (request_entity_id, request_id, owner_reference, state,
              proposal_version, workflow_revision)
         VALUES ($1, $2, $3, 'draft', 1, 1)",
            &[&entity_id, &record_id, &owner_reference],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    Ok(())
}

/// Retains only authored field identifiers, never their values. Create and
/// draft-patch callers invoke this in the same transaction as the typed row
/// mutation so planner input can preserve JSON missing separately from null.
pub(crate) async fn record_authored_intake_fields<'a>(
    transaction: &Transaction<'_>,
    entity_id: &str,
    record_id: Uuid,
    field_ids: impl IntoIterator<Item = &'a str>,
) -> Result<(), MutationError> {
    if entity_id.is_empty() {
        return Err(MutationError::InvalidRequest);
    }
    let mut unique = BTreeSet::new();
    for field_id in field_ids {
        if field_id.is_empty() || field_id.len() > 512 || field_id.chars().any(char::is_control) {
            return Err(MutationError::InvalidRequest);
        }
        unique.insert(field_id);
    }
    if unique.len() > 1024 {
        return Err(MutationError::InvalidRequest);
    }
    for field_id in unique {
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_request_intake_presence
                     (request_entity_id, request_id, field_id)
                 VALUES ($1, $2, $3)
                 ON CONFLICT DO NOTHING",
                &[&entity_id, &record_id, &field_id],
            )
            .await
            .map_err(map_store_error)?;
    }
    Ok(())
}

pub(crate) async fn load_authored_intake(
    transaction: &Transaction<'_>,
    entity_id: &str,
    record_id: Uuid,
    materialized: &Map<String, Value>,
) -> Result<Map<String, Value>, MutationError> {
    let rows = transaction
        .query(
            "SELECT field_id
               FROM registry_internal.registry_request_intake_presence
              WHERE request_entity_id = $1 AND request_id = $2
              ORDER BY field_id
              LIMIT 1025",
            &[&entity_id, &record_id],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    if rows.len() > 1024 {
        return Err(MutationError::Unavailable);
    }
    let mut authored = Map::new();
    for row in rows {
        let field_id = row.get::<_, String>(0);
        let value = materialized
            .get(&field_id)
            .ok_or(MutationError::Unavailable)?;
        authored.insert(field_id, value.clone());
    }
    Ok(authored)
}

pub(crate) async fn erase_authored_intake_fields(
    transaction: &impl GenericClient,
    entity_id: &str,
    record_id: Uuid,
) -> Result<u64, MutationError> {
    transaction
        .execute(
            "DELETE FROM registry_internal.registry_request_intake_presence
              WHERE request_entity_id = $1
                AND request_id = $2",
            &[&entity_id, &record_id],
        )
        .await
        .map_err(map_store_error)
}

/// The request row is locked before calling this guard. Sharing the guard with
/// single-record and batch mutations keeps drafts from acquiring a bypass path.
pub(crate) async fn require_owned_draft(
    transaction: &Transaction<'_>,
    entity_id: &str,
    record_id: Uuid,
    actor_reference: &str,
) -> Result<(), MutationError> {
    let row = transaction
        .query_opt(
            "SELECT state, owner_reference FROM registry_internal.registry_request_state
         WHERE request_entity_id = $1 AND request_id = $2 FOR UPDATE",
            &[&entity_id, &record_id],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
        .ok_or(MutationError::PreconditionFailed)?;
    if row.get::<_, String>(0) != "draft" || row.get::<_, String>(1) != actor_reference {
        return Err(MutationError::PreconditionFailed);
    }
    Ok(())
}

pub(crate) async fn load(
    transaction: &Transaction<'_>,
    entity_id: &str,
    record_id: Uuid,
    lock: bool,
) -> Result<RequestWorkflow, MutationError> {
    let sql = format!(
        "SELECT owner_reference, state, proposal_version, workflow_revision
         FROM registry_internal.registry_request_state
         WHERE request_entity_id = $1 AND request_id = $2{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    let row = transaction
        .query_opt(&sql, &[&entity_id, &record_id])
        .await
        .map_err(|_| MutationError::Unavailable)?
        .ok_or(MutationError::PreconditionFailed)?;
    let request = RequestKey::new(
        EntityId::new(entity_id).map_err(|_| MutationError::Unavailable)?,
        RecordId::new(record_id.to_string()).map_err(|_| MutationError::Unavailable)?,
    );
    let owner = TrustedActorRef::from_verified_context(row.get::<_, String>(0))
        .map_err(|_| MutationError::Unavailable)?;
    let current_version = proposal_version(row.get::<_, i64>(2))?;
    let revision = u64::try_from(row.get::<_, i64>(3)).map_err(|_| MutationError::Unavailable)?;
    let state = RequestState::from_storage(&row.get::<_, String>(1))
        .map_err(|_| MutationError::Unavailable)?;
    let proposals = transaction
        .query(
            "SELECT proposal_version, snapshot FROM registry_internal.registry_request_proposals
         WHERE request_entity_id = $1 AND request_id = $2 AND proposal_version = $3",
            &[&entity_id, &record_id, &i64::from(current_version.get())],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    let mut proposal_map = BTreeMap::new();
    for proposal in proposals {
        let snapshot = proposal
            .get::<_, Option<Value>>(1)
            .ok_or(MutationError::PreconditionFailed)?;
        let version = proposal_version(proposal.get::<_, i64>(0))?;
        let snapshot: ProposalSnapshot =
            serde_json::from_value(snapshot).map_err(|_| MutationError::Unavailable)?;
        proposal_map.insert(version, snapshot);
    }
    let decisions = transaction
        .query(
            "SELECT proposal_version, stage_id, actor_reference, decision, effect_digest,
                to_char(decided_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
                reason, reason_present
         FROM registry_internal.registry_request_decisions
         WHERE request_entity_id = $1 AND request_id = $2 AND proposal_version = $3
         ORDER BY decision_index LIMIT 1025",
            &[&entity_id, &record_id, &i64::from(current_version.get())],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    if decisions.len() > 1024 {
        return Err(MutationError::Unavailable);
    }
    let decisions = decisions
        .into_iter()
        .map(|decision| {
            let kind = ReviewDecisionKind::from_storage(&decision.get::<_, String>(3))
                .map_err(|_| MutationError::Unavailable)?;
            ReviewDecision::restore(
                proposal_version(decision.get::<_, i64>(0))?,
                decision.get(1),
                kind,
                TrustedActorRef::from_verified_context(decision.get::<_, String>(2))
                    .map_err(|_| MutationError::Unavailable)?,
                TrustedTimestamp::from_server_clock(decision.get::<_, String>(5))
                    .map_err(|_| MutationError::Unavailable)?,
                ProposalDigest::new(decision.get::<_, String>(4))
                    .map_err(|_| MutationError::Unavailable)?,
                decision.get(6),
                decision.get(7),
            )
            .map_err(|_| MutationError::Unavailable)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let application = if let Some(application) = transaction
        .query_opt(
            "SELECT proposal_version, application_id, effect_digest, applied_by,
                to_char(applied_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')
         FROM registry_internal.registry_request_applications
         WHERE request_entity_id = $1 AND request_id = $2",
            &[&entity_id, &record_id],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
    {
        let version = proposal_version(application.get::<_, i64>(0))?;
        let results = transaction
            .query(
                "SELECT target_entity_id, target_record_id, target_revision
             FROM registry_internal.registry_request_results
             WHERE request_entity_id = $1 AND request_id = $2 AND proposal_version = $3
             ORDER BY target_entity_id, target_record_id",
                &[&entity_id, &record_id, &i64::from(version.get())],
            )
            .await
            .map_err(map_store_error)?;
        let result_links = results
            .into_iter()
            .map(|result| {
                Ok(ApplicationResultLink::new(
                    EntityId::new(result.get::<_, String>(0))
                        .map_err(|_| MutationError::Unavailable)?,
                    RecordId::new(result.get::<_, Uuid>(1).to_string())
                        .map_err(|_| MutationError::Unavailable)?,
                    RecordRevision::new(result.get::<_, i64>(2))
                        .map_err(|_| MutationError::Unavailable)?,
                ))
            })
            .collect::<Result<Vec<_>, MutationError>>()?;
        Some(
            ApplicationReceipt::restore(
                ApplicationId::new(application.get::<_, Uuid>(1).to_string())
                    .map_err(|_| MutationError::Unavailable)?,
                version,
                ProposalDigest::new(application.get::<_, String>(2))
                    .map_err(|_| MutationError::Unavailable)?,
                TrustedActorRef::from_verified_context(application.get::<_, String>(3))
                    .map_err(|_| MutationError::Unavailable)?,
                TrustedTimestamp::from_server_clock(application.get::<_, String>(4))
                    .map_err(|_| MutationError::Unavailable)?,
                result_links,
            )
            .map_err(|_| MutationError::Unavailable)?,
        )
    } else {
        None
    };
    RequestWorkflow::restore(
        request,
        owner,
        state,
        current_version,
        StateRevision::new(revision).map_err(|_| MutationError::Unavailable)?,
        proposal_map,
        decisions,
        application,
    )
    .map_err(|_| MutationError::Unavailable)
}

#[allow(dead_code)]
pub(crate) async fn load_header(
    transaction: &Transaction<'_>,
    entity_id: &str,
    record_id: Uuid,
    lock: bool,
) -> Result<RequestWorkflowHeader, MutationError> {
    let sql = format!(
        "SELECT s.owner_reference, s.state, s.proposal_version, s.workflow_revision,
                COALESCE(s.detail_erased_at IS NOT NULL, false)
                    OR COALESCE(p.erased_at IS NOT NULL, false), a.applied_by
           FROM registry_internal.registry_request_state s
           LEFT JOIN registry_internal.registry_request_proposals p
             ON p.request_entity_id = s.request_entity_id
            AND p.request_id = s.request_id
            AND p.proposal_version = s.proposal_version
          LEFT JOIN registry_internal.registry_request_applications a
            ON a.request_entity_id = s.request_entity_id
           AND a.request_id = s.request_id
           AND a.proposal_version = s.proposal_version
          WHERE s.request_entity_id = $1 AND s.request_id = $2{}",
        if lock { " FOR UPDATE OF s" } else { "" }
    );
    let row = transaction
        .query_opt(&sql, &[&entity_id, &record_id])
        .await
        .map_err(|_| MutationError::Unavailable)?
        .ok_or(MutationError::PreconditionFailed)?;
    let state: String = row.get(1);
    if !matches!(
        state.as_str(),
        "draft" | "submitted" | "approved" | "needs_changes" | "rejected" | "canceled" | "applied"
    ) {
        return Err(MutationError::Unavailable);
    }
    let proposal_version: i64 = row.get(2);
    let workflow_revision: i64 = row.get(3);
    if proposal_version <= 0 || workflow_revision <= 0 {
        return Err(MutationError::Unavailable);
    }
    Ok(RequestWorkflowHeader {
        owner_reference: row.get(0),
        state,
        proposal_version,
        workflow_revision,
        current_proposal_erased: row.get(4),
        applier_reference: row.get(5),
    })
}

pub(crate) async fn link_idempotency_result(
    transaction: &Transaction<'_>,
    key_reference: &str,
    request_entity_id: &str,
    request_id: Uuid,
    proposal_version: i64,
) -> Result<(), MutationError> {
    if key_reference.is_empty() || request_entity_id.is_empty() || proposal_version <= 0 {
        return Err(MutationError::InvalidRequest);
    }
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_request_idempotency_links
                 (key_reference, request_entity_id, request_id, proposal_version)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT DO NOTHING",
            &[
                &key_reference,
                &request_entity_id,
                &request_id,
                &proposal_version,
            ],
        )
        .await
        .map_err(map_store_error)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn link_request_revision(
    transaction: &Transaction<'_>,
    entity_id: &str,
    record_id: Uuid,
    record_revision: i64,
    request_entity_id: &str,
    request_id: Uuid,
    proposal_version: i64,
    link_kind: &str,
) -> Result<(), MutationError> {
    if entity_id.is_empty()
        || record_revision <= 0
        || request_entity_id.is_empty()
        || proposal_version <= 0
        || !matches!(
            link_kind,
            "request_create" | "request_patch" | "request_lifecycle" | "request_batch"
        )
    {
        return Err(MutationError::InvalidRequest);
    }
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_request_revision_links
                 (entity_id, record_id, record_revision, request_entity_id, request_id,
                  proposal_version, link_kind)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT DO NOTHING",
            &[
                &entity_id,
                &record_id,
                &record_revision,
                &request_entity_id,
                &request_id,
                &proposal_version,
                &link_kind,
            ],
        )
        .await
        .map_err(map_store_error)?;
    Ok(())
}

pub(crate) async fn save_targets(
    transaction: &Transaction<'_>,
    request_entity_id: &str,
    request_id: Uuid,
    proposal_version: i64,
    targets: &[RequestTargetSnapshot],
) -> Result<(), MutationError> {
    if proposal_version < 1 || targets.len() > MAX_REQUEST_TARGETS {
        return Err(MutationError::InvalidRequest);
    }
    let mut keys = BTreeSet::new();
    for snapshot in targets {
        if !keys.insert((snapshot.entity_id.as_str(), snapshot.record_id)) {
            return Err(MutationError::Conflict);
        }
        validate_target_snapshot(snapshot)?;
    }
    for snapshot in targets {
        let operation = operation_code(snapshot.operation);
        let before = snapshot
            .before
            .as_ref()
            .map(|before| Value::Object(before.clone()));
        let after = Value::Object(snapshot.after.clone());
        let inserted = transaction
            .execute(
                "INSERT INTO registry_internal.registry_request_targets
                 (request_entity_id, request_id, proposal_version, target_entity_id,
                  target_record_id, operation, expected_revision, base_snapshot, after_snapshot)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (request_entity_id, request_id, proposal_version,
                          target_entity_id, target_record_id) DO NOTHING",
                &[
                    &request_entity_id,
                    &request_id,
                    &proposal_version,
                    &snapshot.entity_id,
                    &snapshot.record_id,
                    &operation,
                    &snapshot.expected_revision,
                    &before,
                    &after,
                ],
            )
            .await
            .map_err(map_store_error)?;
        if inserted == 0 {
            verify_existing_target(
                transaction,
                request_entity_id,
                request_id,
                proposal_version,
                snapshot,
            )
            .await?;
        }
    }
    Ok(())
}

pub(crate) async fn load_targets(
    transaction: &Transaction<'_>,
    request_entity_id: &str,
    request_id: Uuid,
    proposal_version: i64,
) -> Result<Vec<RequestTargetSnapshot>, MutationError> {
    if proposal_version < 1 {
        return Err(MutationError::InvalidRequest);
    }
    let rows = transaction
        .query(
            "SELECT target_entity_id, target_record_id, operation, expected_revision,
                    base_snapshot, after_snapshot
             FROM registry_internal.registry_request_targets
             WHERE request_entity_id = $1 AND request_id = $2 AND proposal_version = $3
             ORDER BY target_entity_id, target_record_id
             LIMIT 17",
            &[&request_entity_id, &request_id, &proposal_version],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    if rows.len() > MAX_REQUEST_TARGETS {
        return Err(MutationError::Unavailable);
    }
    let mut snapshots = Vec::with_capacity(rows.len());
    for row in rows {
        let operation = parse_operation(row.get::<_, String>(2).as_str())?;
        let before = match row.get::<_, Option<Value>>(4) {
            Some(Value::Object(object)) => Some(object),
            Some(_) => return Err(MutationError::Unavailable),
            None => None,
        };
        let after = match row
            .get::<_, Option<Value>>(5)
            .ok_or(MutationError::PreconditionFailed)?
        {
            Value::Object(object) => object,
            _ => return Err(MutationError::Unavailable),
        };
        let snapshot = RequestTargetSnapshot {
            entity_id: row.get(0),
            record_id: row.get(1),
            operation,
            expected_revision: row.get(3),
            before,
            after,
        };
        validate_target_snapshot(&snapshot)?;
        snapshots.push(snapshot);
    }
    Ok(snapshots)
}

/// Only the current proposal and newly appended decision/application are
/// inserted. Existing payloads are never overwritten by a lifecycle command.
pub(crate) async fn save(
    transaction: &Transaction<'_>,
    entity_id: &str,
    record_id: Uuid,
    previous_revision: i64,
    workflow: &RequestWorkflow,
) -> Result<(), MutationError> {
    workflow
        .clone()
        .validate_restored()
        .map_err(|_| MutationError::Unavailable)?;
    let version = i64::from(workflow.current_version().get());
    let revision = i64::try_from(workflow.workflow_revision().get())
        .map_err(|_| MutationError::Unavailable)?;
    let review_completed_at = match workflow.state() {
        RequestState::Approved | RequestState::Rejected | RequestState::Applied => workflow
            .decisions()
            .last()
            .map(|decision| decision.decided_at().as_str())
            .or_else(|| {
                workflow
                    .current_proposal()
                    .map(|proposal| proposal.submitted_at().as_str())
            }),
        RequestState::Draft | RequestState::Submitted | RequestState::NeedsChanges => None,
        RequestState::Canceled => None,
    };
    if revision
        != previous_revision
            .checked_add(1)
            .ok_or(MutationError::Unavailable)?
    {
        return Err(MutationError::Unavailable);
    }
    if let Some(proposal) = workflow.current_proposal() {
        let snapshot = serde_json::to_value(proposal).map_err(|_| MutationError::Unavailable)?;
        let inserted = transaction
            .execute(
                "INSERT INTO registry_internal.registry_request_proposals
                 (request_entity_id, request_id, proposal_version, request_record_revision,
                  contract_fingerprint, effect_digest, snapshot)
             VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
                &[
                    &entity_id,
                    &record_id,
                    &version,
                    &proposal.request_record_revision().get(),
                    &proposal.contract_fingerprint().as_str(),
                    &proposal.effect_digest().as_str(),
                    &snapshot,
                ],
            )
            .await
            .map_err(map_store_error)?;
        if inserted == 0 {
            verify_existing_proposal(
                transaction,
                entity_id,
                record_id,
                version,
                proposal.request_record_revision().get(),
                proposal.contract_fingerprint().as_str(),
                proposal.effect_digest().as_str(),
                &snapshot,
            )
            .await?;
        }
    }
    for (index, decision) in workflow.decisions().iter().enumerate() {
        let index = i32::try_from(index).map_err(|_| MutationError::Unavailable)?;
        let decision_version = i64::from(decision.version().get());
        let inserted = transaction.execute(
            "INSERT INTO registry_internal.registry_request_decisions
                 (request_entity_id, request_id, proposal_version, decision_index,
                  stage_id, actor_reference, decision, effect_digest, decided_at,
                  reason, reason_present)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::text::timestamptz, $10, $11)
             ON CONFLICT (request_entity_id, request_id, proposal_version, decision_index) DO NOTHING",
            &[&entity_id, &record_id, &decision_version, &index,
              &decision.stage_id(), &decision.actor().as_str(),
              &decision.kind().as_storage(), &decision.effect_digest().as_str(),
              &decision.decided_at().as_str(), &decision.reason(), &decision.reason_present()],
        ).await.map_err(map_store_error)?;
        if inserted == 0 {
            verify_existing_decision(transaction, entity_id, record_id, decision, index).await?;
        }
    }
    if let Some(application) = workflow.application() {
        let application_id = Uuid::parse_str(application.application_id().as_str())
            .map_err(|_| MutationError::Unavailable)?;
        let application_version = i64::from(application.version().get());
        let inserted = transaction
            .execute(
                "INSERT INTO registry_internal.registry_request_applications
                 (request_entity_id, request_id, proposal_version, application_id,
                  effect_digest, applied_by, applied_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7::text::timestamptz)
             ON CONFLICT (request_entity_id, request_id, proposal_version) DO NOTHING",
                &[
                    &entity_id,
                    &record_id,
                    &application_version,
                    &application_id,
                    &application.effect_digest().as_str(),
                    &application.applied_by().as_str(),
                    &application.applied_at().as_str(),
                ],
            )
            .await
            .map_err(map_store_error)?;
        if inserted == 0 {
            verify_existing_application(transaction, entity_id, record_id, application).await?;
        }
        for link in application.result_links() {
            let target_id = Uuid::parse_str(link.record_id().as_str())
                .map_err(|_| MutationError::Unavailable)?;
            let target_revision = link.record_revision().get();
            let inserted = transaction
                .execute(
                    "INSERT INTO registry_internal.registry_request_results
                     (request_entity_id, request_id, proposal_version, target_entity_id,
                      target_record_id, target_revision) VALUES ($1, $2, $3, $4, $5, $6)
                      ON CONFLICT (request_entity_id, request_id, proposal_version,
                                   target_entity_id, target_record_id) DO NOTHING",
                    &[
                        &entity_id,
                        &record_id,
                        &application_version,
                        &link.entity_id().as_str(),
                        &target_id,
                        &target_revision,
                    ],
                )
                .await
                .map_err(map_store_error)?;
            if inserted == 0 {
                verify_existing_result(
                    transaction,
                    entity_id,
                    record_id,
                    application_version,
                    link,
                )
                .await?;
            }
        }
    }
    let changed = transaction
        .execute(
            "UPDATE registry_internal.registry_request_state
         SET state = $3, proposal_version = $4, workflow_revision = $5,
             updated_at = transaction_timestamp(),
             review_completed_at = COALESCE(
                 review_completed_at,
                 CASE WHEN $3 IN ('approved', 'rejected', 'canceled', 'applied')
                      THEN COALESCE($7::text::timestamptz, transaction_timestamp())
                      ELSE NULL END)
         WHERE request_entity_id = $1 AND request_id = $2 AND workflow_revision = $6",
            &[
                &entity_id,
                &record_id,
                &workflow.state().as_storage(),
                &version,
                &revision,
                &previous_revision,
                &review_completed_at,
            ],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    if changed != 1 {
        return Err(MutationError::PreconditionFailed);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn verify_existing_proposal(
    transaction: &Transaction<'_>,
    entity_id: &str,
    record_id: Uuid,
    version: i64,
    request_record_revision: i64,
    contract_fingerprint: &str,
    effect_digest: &str,
    snapshot: &Value,
) -> Result<(), MutationError> {
    let row = transaction
        .query_opt(
            "SELECT request_record_revision, contract_fingerprint, effect_digest, snapshot
             FROM registry_internal.registry_request_proposals
             WHERE request_entity_id = $1 AND request_id = $2 AND proposal_version = $3",
            &[&entity_id, &record_id, &version],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
        .ok_or(MutationError::Conflict)?;
    let existing_snapshot = row
        .get::<_, Option<Value>>(3)
        .ok_or(MutationError::PreconditionFailed)?;
    if row.get::<_, i64>(0) == request_record_revision
        && row.get::<_, String>(1) == contract_fingerprint
        && row.get::<_, String>(2) == effect_digest
        && existing_snapshot == *snapshot
    {
        Ok(())
    } else {
        Err(MutationError::Conflict)
    }
}

async fn verify_existing_decision(
    transaction: &Transaction<'_>,
    entity_id: &str,
    record_id: Uuid,
    decision: &ReviewDecision,
    index: i32,
) -> Result<(), MutationError> {
    let version = i64::from(decision.version().get());
    let stage_id = decision.stage_id();
    let actor = decision.actor().as_str();
    let kind = decision.kind().as_storage();
    let effect_digest = decision.effect_digest().as_str();
    let decided_at = decision.decided_at().as_str();
    let row = transaction
        .query_opt(
            "SELECT stage_id, actor_reference, decision, effect_digest,
                    decided_at = $5::text::timestamptz AS same_time, reason, reason_present
             FROM registry_internal.registry_request_decisions
             WHERE request_entity_id = $1 AND request_id = $2
               AND proposal_version = $3 AND decision_index = $4",
            &[&entity_id, &record_id, &version, &index, &decided_at],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
        .ok_or(MutationError::Conflict)?;
    if row.get::<_, String>(0) == stage_id
        && row.get::<_, String>(1) == actor
        && row.get::<_, String>(2) == kind
        && row.get::<_, String>(3) == effect_digest
        && row.get::<_, bool>(4)
        && row.get::<_, Option<String>>(5).as_deref() == decision.reason()
        && row.get::<_, bool>(6) == decision.reason_present()
    {
        Ok(())
    } else {
        Err(MutationError::Conflict)
    }
}

async fn verify_existing_application(
    transaction: &Transaction<'_>,
    entity_id: &str,
    record_id: Uuid,
    application: &ApplicationReceipt,
) -> Result<(), MutationError> {
    let version = i64::from(application.version().get());
    let application_id = Uuid::parse_str(application.application_id().as_str())
        .map_err(|_| MutationError::Unavailable)?;
    let effect_digest = application.effect_digest().as_str();
    let applied_by = application.applied_by().as_str();
    let applied_at = application.applied_at().as_str();
    let row = transaction
        .query_opt(
            "SELECT application_id, effect_digest, applied_by,
                    applied_at = $4::text::timestamptz AS same_time
             FROM registry_internal.registry_request_applications
             WHERE request_entity_id = $1 AND request_id = $2 AND proposal_version = $3",
            &[&entity_id, &record_id, &version, &applied_at],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
        .ok_or(MutationError::Conflict)?;
    if row.get::<_, Uuid>(0) == application_id
        && row.get::<_, String>(1) == effect_digest
        && row.get::<_, String>(2) == applied_by
        && row.get::<_, bool>(3)
    {
        Ok(())
    } else {
        Err(MutationError::Conflict)
    }
}

async fn verify_existing_result(
    transaction: &Transaction<'_>,
    entity_id: &str,
    record_id: Uuid,
    version: i64,
    link: &ApplicationResultLink,
) -> Result<(), MutationError> {
    let target_entity_id = link.entity_id().as_str();
    let target_id =
        Uuid::parse_str(link.record_id().as_str()).map_err(|_| MutationError::Unavailable)?;
    let target_revision = link.record_revision().get();
    let row = transaction
        .query_opt(
            "SELECT target_revision
             FROM registry_internal.registry_request_results
             WHERE request_entity_id = $1 AND request_id = $2 AND proposal_version = $3
               AND target_entity_id = $4 AND target_record_id = $5",
            &[
                &entity_id,
                &record_id,
                &version,
                &target_entity_id,
                &target_id,
            ],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
        .ok_or(MutationError::Conflict)?;
    if row.get::<_, i64>(0) == target_revision {
        Ok(())
    } else {
        Err(MutationError::Conflict)
    }
}

async fn verify_existing_target(
    transaction: &Transaction<'_>,
    request_entity_id: &str,
    request_id: Uuid,
    proposal_version: i64,
    snapshot: &RequestTargetSnapshot,
) -> Result<(), MutationError> {
    let row = transaction
        .query_opt(
            "SELECT operation, expected_revision, base_snapshot, after_snapshot
             FROM registry_internal.registry_request_targets
             WHERE request_entity_id = $1 AND request_id = $2 AND proposal_version = $3
               AND target_entity_id = $4 AND target_record_id = $5",
            &[
                &request_entity_id,
                &request_id,
                &proposal_version,
                &snapshot.entity_id,
                &snapshot.record_id,
            ],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
        .ok_or(MutationError::Conflict)?;
    let expected_before = snapshot
        .before
        .as_ref()
        .map(|before| Value::Object(before.clone()));
    let expected_after = Value::Object(snapshot.after.clone());
    let existing_after = row
        .get::<_, Option<Value>>(3)
        .ok_or(MutationError::PreconditionFailed)?;
    if row.get::<_, String>(0) == operation_code(snapshot.operation)
        && row.get::<_, Option<i64>>(1) == snapshot.expected_revision
        && row.get::<_, Option<Value>>(2) == expected_before
        && existing_after == expected_after
    {
        Ok(())
    } else {
        Err(MutationError::Conflict)
    }
}

fn validate_target_snapshot(snapshot: &RequestTargetSnapshot) -> Result<(), MutationError> {
    if snapshot.entity_id.is_empty()
        || canonical_object_size(&snapshot.after)? > MAX_REQUEST_SNAPSHOT_BYTES
    {
        return Err(MutationError::InvalidRequest);
    }
    if let Some(before) = &snapshot.before {
        if canonical_object_size(before)? > MAX_REQUEST_SNAPSHOT_BYTES {
            return Err(MutationError::InvalidRequest);
        }
    }
    match snapshot.operation {
        Operation::Create if snapshot.expected_revision.is_none() && snapshot.before.is_none() => {
            Ok(())
        }
        Operation::Patch
            if snapshot
                .expected_revision
                .is_some_and(|revision| revision > 0)
                && snapshot.before.is_some() =>
        {
            Ok(())
        }
        _ => Err(MutationError::InvalidRequest),
    }
}

fn canonical_object_size(object: &Map<String, Value>) -> Result<usize, MutationError> {
    canonicalize_json(&Value::Object(object.clone()))
        .map(|bytes| bytes.len())
        .map_err(|_| MutationError::InvalidRequest)
}

fn operation_code(operation: Operation) -> &'static str {
    match operation {
        Operation::Create => "create",
        Operation::Patch => "patch",
        _ => "unsupported",
    }
}

fn parse_operation(operation: &str) -> Result<Operation, MutationError> {
    match operation {
        "create" => Ok(Operation::Create),
        "patch" => Ok(Operation::Patch),
        _ => Err(MutationError::Unavailable),
    }
}

fn map_store_error(error: tokio_postgres::Error) -> MutationError {
    match error.code() {
        Some(code)
            if code == &SqlState::UNIQUE_VIOLATION
                || code == &SqlState::CHECK_VIOLATION
                || code == &SqlState::FOREIGN_KEY_VIOLATION
                || code == &SqlState::EXCLUSION_VIOLATION =>
        {
            MutationError::Conflict
        }
        _ => MutationError::Unavailable,
    }
}

fn proposal_version(value: i64) -> Result<ProposalVersion, MutationError> {
    u32::try_from(value)
        .ok()
        .and_then(|value| ProposalVersion::new(value).ok())
        .ok_or(MutationError::Unavailable)
}

#[cfg(test)]
#[cfg(feature = "postgres-test")]
mod tests {
    use std::env;

    use registry_platform_canonical_json::canonicalize_json;
    use serde_json::{json, Map};
    use tokio_postgres::Client;
    use uuid::Uuid;

    use super::*;
    use crate::model::CompiledChangeRequestStage;
    use crate::mutation::install_mutation_schema;
    use crate::request_workflow::{
        ContractFingerprint, EffectId, FieldId, FieldValue, PackageFingerprint, PreparedEffect,
        PreparedFieldChange, PreparedProposal, PreparedTarget, RecordRevision, RequestState,
        ReviewDecisionKind, TrustedTimestamp, TrustedTransitionContext,
    };

    #[allow(dead_code)]
    mod postgres_harness {
        use crate as registry_breg;

        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/postgres_harness.rs"
        ));
    }

    use postgres_harness::TestDatabase;

    const REQUEST_ENTITY: &str = "placement-correction-request";
    const TARGET_ENTITY: &str = "asset-placement";

    fn load_postgres_env() {
        if env::var_os("BREG_TEST_DATABASE_URL").is_some() {
            return;
        }
        let Ok(contents) =
            std::fs::read_to_string("/private/tmp/registry-cr-plain-gqgr39oa/test.env")
        else {
            return;
        };
        for line in contents.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let line = line.strip_prefix("export ").unwrap_or(line);
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if key.trim() != "BREG_TEST_DATABASE_URL" {
                continue;
            }
            let value = value.trim();
            let value = value
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
                .or_else(|| {
                    value
                        .strip_prefix('"')
                        .and_then(|value| value.strip_suffix('"'))
                })
                .unwrap_or(value);
            env::set_var("BREG_TEST_DATABASE_URL", value);
            return;
        }
    }

    async fn install_schema() -> (TestDatabase, Client, tokio::task::JoinHandle<()>) {
        load_postgres_env();
        let database = TestDatabase::create(1).await;
        let (migration, migration_task) = database.connect_migration().await;
        for _ in 0..2 {
            install_mutation_schema(&migration, &database.runtime_role)
                .await
                .expect("request store schema installs repeatably");
        }
        (database, migration, migration_task)
    }

    fn entity(value: &str) -> EntityId {
        EntityId::new(value).expect("entity id")
    }

    fn record(value: impl Into<String>) -> RecordId {
        RecordId::new(value.into()).expect("record id")
    }

    fn actor(value: &str) -> TrustedActorRef {
        TrustedActorRef::from_verified_context(value).expect("actor")
    }

    fn state_revision(value: u64) -> StateRevision {
        StateRevision::new(value).expect("state revision")
    }

    fn record_revision(value: i64) -> RecordRevision {
        RecordRevision::new(value).expect("record revision")
    }

    fn timestamp(second: u8) -> TrustedTimestamp {
        TrustedTimestamp::from_server_clock(format!("2026-08-31T00:00:{second:02}Z"))
            .expect("timestamp")
    }

    fn context(actor_ref: &str, second: u8) -> TrustedTransitionContext {
        TrustedTransitionContext::from_verified_context(actor(actor_ref), timestamp(second))
    }

    #[test]
    fn workflow_header_debug_redacts_actor_references() {
        let header = RequestWorkflowHeader {
            owner_reference: "private-owner-reference-canary".to_owned(),
            state: "applied".to_owned(),
            proposal_version: 2,
            workflow_revision: 9,
            current_proposal_erased: false,
            applier_reference: Some("private-applier-reference-canary".to_owned()),
        };
        let debug = format!("{header:?}");
        assert!(!debug.contains("private-owner-reference-canary"));
        assert!(!debug.contains("private-applier-reference-canary"));
        assert!(debug.contains("has_owner_reference: true"));
        assert!(debug.contains("has_applier_reference: true"));
    }

    fn workflow(request_id: Uuid) -> RequestWorkflow {
        RequestWorkflow::new_draft(
            RequestKey::new(entity(REQUEST_ENTITY), record(request_id.to_string())),
            actor("submitter"),
            state_revision(1),
        )
    }

    fn stage() -> Vec<CompiledChangeRequestStage> {
        vec![CompiledChangeRequestStage {
            id: "review".to_owned(),
            approvals: 1,
            exclude_submitter: true,
            exclude_previous_reviewers: false,
        }]
    }

    fn proposal(target_id: Uuid, before_site: &str, after_site: &str) -> PreparedProposal {
        let effects = vec![PreparedEffect::new(
            EffectId::new("patch-placement").expect("effect id"),
            Operation::Patch,
            PreparedTarget::existing(
                entity(TARGET_ENTITY),
                record(target_id.to_string()),
                record_revision(3),
            ),
            vec![PreparedFieldChange::set(
                FieldId::new("site").expect("field id"),
                FieldValue::present(json!(before_site)),
                json!(after_site),
            )
            .expect("field change")],
        )
        .expect("prepared effect")];
        let bytes = canonicalize_json(&serde_json::to_value(&effects).expect("effects serialize"))
            .expect("effects canonicalize")
            .len();
        PreparedProposal::new(
            record_revision(7),
            ContractFingerprint::new(
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            )
            .expect("contract fingerprint"),
            PackageFingerprint::new(
                "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            )
            .expect("package fingerprint"),
            stage(),
            effects,
            bytes,
        )
        .expect("prepared proposal")
    }

    fn target_snapshot(
        target_id: Uuid,
        before_site: &str,
        after_site: &str,
    ) -> RequestTargetSnapshot {
        let mut before = Map::new();
        before.insert("site".to_owned(), json!(before_site));
        let mut after = before.clone();
        after.insert("site".to_owned(), json!(after_site));
        RequestTargetSnapshot {
            entity_id: TARGET_ENTITY.to_owned(),
            record_id: target_id,
            operation: Operation::Patch,
            expected_revision: Some(3),
            before: Some(before),
            after,
        }
    }

    fn request_revision(workflow: RequestWorkflow, actor_ref: &str, second: u8) -> RequestWorkflow {
        let proposal = workflow.current_proposal().expect("current proposal");
        let digest = proposal.effect_digest().clone();
        let version = workflow.current_version();
        workflow
            .decide(
                context(actor_ref, second),
                "review",
                version,
                &digest,
                ReviewDecisionKind::RequestRevision,
            )
            .expect("request revision")
            .into_workflow()
    }

    #[tokio::test]
    async fn request_schema_installs_repeatably_and_grants_declared_table_privileges() {
        let (database, migration, migration_task) = install_schema().await;
        for (table, privileges) in REQUEST_TABLES {
            let qualified = format!("registry_internal.{table}");
            let exists = migration
                .query_one("SELECT to_regclass($1)::text IS NOT NULL", &[&qualified])
                .await
                .expect("request table lookup succeeds")
                .get::<_, bool>(0);
            assert!(exists, "request table exists");
            for privilege in *privileges {
                let allowed = migration
                    .query_one(
                        "SELECT has_table_privilege($1, $2, $3)",
                        &[&database.runtime_role.as_str(), &qualified, privilege],
                    )
                    .await
                    .expect("request table privilege lookup succeeds")
                    .get::<_, bool>(0);
                assert!(allowed, "declared runtime table privilege is granted");
            }
        }
        migration_task.abort();
        database.cleanup().await;
    }

    #[tokio::test]
    async fn proposal_task_authority_is_immutable_and_separate_from_reviewer() {
        let (database, mut migration, migration_task) = install_schema().await;
        let request_id = Uuid::new_v4();
        let submitted = workflow(request_id)
            .submit(
                context("submitter", 1),
                proposal(Uuid::new_v4(), "site-a", "site-b"),
            )
            .expect("submit")
            .into_workflow();
        let grant: crate::task_grant::TaskGrantBinding = serde_json::from_value(json!({
            "grantId": Uuid::new_v4().to_string(), "authority": "casework",
            "sourceIssuer": "https://casework.test", "principal": "original-agent",
            "client": "original-client", "resource": "urn:breg:test", "purpose": "review",
            "bounds": {"type":"breg", "permissions":[{"collection":"people", "operations":["get","patch"]}]},
            "subjects": {"person_reference":"synthetic-person"},
            "expiresAt": chrono::Utc::now().timestamp() + 900,
        })).expect("binding");
        let tx = migration.transaction().await.expect("transaction");
        initialize_draft(&tx, REQUEST_ENTITY, request_id, "submitter")
            .await
            .expect("draft");
        save(&tx, REQUEST_ENTITY, request_id, 1, &submitted)
            .await
            .expect("proposal");
        save_task_authority(&tx, REQUEST_ENTITY, request_id, 1, &grant)
            .await
            .expect("bind");
        save_task_authority(&tx, REQUEST_ENTITY, request_id, 1, &grant)
            .await
            .expect("exact replay");
        let reviewed = request_revision(submitted, "human-reviewer", 2);
        save(&tx, REQUEST_ENTITY, request_id, 2, &reviewed)
            .await
            .expect("review");
        assert_eq!(
            load_task_authority(&tx, REQUEST_ENTITY, request_id, 1)
                .await
                .unwrap(),
            Some(grant.clone())
        );
        let mut changed = serde_json::to_value(&grant).unwrap();
        changed["client"] = json!("replacement-client");
        let changed = serde_json::from_value(changed).unwrap();
        assert_eq!(
            save_task_authority(&tx, REQUEST_ENTITY, request_id, 1, &changed).await,
            Err(MutationError::IdempotencyConflict)
        );
        tx.commit().await.expect("commit");
        migration_task.abort();
        database.cleanup().await;
    }

    #[tokio::test]
    async fn reviewer_reasons_upgrade_roundtrip_and_refuse_immutable_mismatch() {
        let (database, mut migration, migration_task) = install_schema().await;
        let request_id = Uuid::new_v4();
        let submitted = workflow(request_id)
            .submit(
                context("submitter", 1),
                proposal(Uuid::new_v4(), "site-a", "site-b"),
            )
            .expect("submit")
            .into_workflow();
        let legacy_decision = request_revision(submitted.clone(), "reviewer-a", 2);
        let transaction = migration.transaction().await.expect("legacy transaction");
        initialize_draft(&transaction, REQUEST_ENTITY, request_id, "submitter")
            .await
            .expect("draft initializes");
        save(&transaction, REQUEST_ENTITY, request_id, 1, &submitted)
            .await
            .expect("proposal saves");
        save(
            &transaction,
            REQUEST_ENTITY,
            request_id,
            2,
            &legacy_decision,
        )
        .await
        .expect("legacy decision saves");
        transaction.commit().await.expect("legacy commits");
        migration
            .batch_execute(
                "ALTER TABLE registry_internal.registry_request_decisions
                 DROP COLUMN reason, DROP COLUMN reason_present",
            )
            .await
            .expect("simulate pre-reason installed database");
        for _ in 0..2 {
            install_mutation_schema(&migration, &database.runtime_role)
                .await
                .expect("existing database upgrades repeatably");
        }
        let transaction = migration
            .transaction()
            .await
            .expect("read upgraded decision");
        let loaded = load(&transaction, REQUEST_ENTITY, request_id, false)
            .await
            .expect("legacy workflow still restores");
        assert!(!loaded.decisions()[0].reason_present());
        assert!(loaded.decisions()[0].reason().is_none());
        transaction.commit().await.expect("read commits");
        let privileges = migration.query_one(
            "SELECT has_table_privilege($1, 'registry_internal.registry_request_decisions', 'UPDATE'),
                    has_table_privilege($1, 'registry_internal.registry_request_decisions', 'DELETE')",
            &[&database.runtime_role.as_str()],
        ).await.expect("runtime privileges resolve");
        assert!(!privileges.get::<_, bool>(0));
        assert!(!privileges.get::<_, bool>(1));

        let reason = "界".repeat(4096);
        let reasoned = submitted
            .clone()
            .decide_with_reason(
                context("reviewer-a", 2),
                "review",
                submitted.current_version(),
                submitted.current_proposal().unwrap().effect_digest(),
                ReviewDecisionKind::RequestRevision,
                Some(reason.clone()),
            )
            .expect("bounded Unicode reason")
            .into_workflow();
        let transaction = migration.transaction().await.expect("mismatch transaction");
        assert_eq!(
            verify_existing_decision(
                &transaction,
                REQUEST_ENTITY,
                request_id,
                &reasoned.decisions()[0],
                0
            )
            .await,
            Err(MutationError::Conflict),
            "different reason cannot reuse an existing immutable decision"
        );
        let erased_reason = ReviewDecision::restore(
            legacy_decision.decisions()[0].version(),
            legacy_decision.decisions()[0].stage_id().to_owned(),
            legacy_decision.decisions()[0].kind(),
            legacy_decision.decisions()[0].actor().clone(),
            legacy_decision.decisions()[0].decided_at().clone(),
            legacy_decision.decisions()[0].effect_digest().clone(),
            None,
            true,
        )
        .expect("erased reason retains presence");
        assert_eq!(
            verify_existing_decision(&transaction, REQUEST_ENTITY, request_id, &erased_reason, 0)
                .await,
            Err(MutationError::Conflict),
            "presence differs even when both reason texts are absent"
        );
        transaction.rollback().await.expect("mismatch rollback");
        migration.execute(
            "UPDATE registry_internal.registry_request_decisions SET reason = $3, reason_present = true
              WHERE request_entity_id = $1 AND request_id = $2",
            &[&REQUEST_ENTITY, &request_id, &reason],
        ).await.expect("migration fixture stores a full Unicode reason");
        let transaction = migration
            .transaction()
            .await
            .expect("reason read transaction");
        let loaded = load(&transaction, REQUEST_ENTITY, request_id, false)
            .await
            .expect("reasoned decision restores");
        assert_eq!(loaded.decisions()[0].reason(), Some(reason.as_str()));
        assert!(loaded.decisions()[0].reason_present());
        verify_existing_decision(
            &transaction,
            REQUEST_ENTITY,
            request_id,
            &reasoned.decisions()[0],
            0,
        )
        .await
        .expect("exact reason is replayable");
        transaction.commit().await.expect("reason read commits");
        for (kind, text, present) in [
            ("request_revision", "界".repeat(4097), true),
            ("approve", "reason".to_owned(), true),
            ("reject", "reason".to_owned(), false),
        ] {
            let error = migration.execute(
                "UPDATE registry_internal.registry_request_decisions SET decision = $3, reason = $4, reason_present = $5
                  WHERE request_entity_id = $1 AND request_id = $2",
                &[&REQUEST_ENTITY, &request_id, &kind, &text, &present],
            ).await.expect_err("database refuses invalid reason state");
            assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
        }
        migration_task.abort();
        database.cleanup().await;
    }

    #[tokio::test]
    async fn authored_intake_presence_preserves_missing_separately_from_null_and_erases() {
        let (database, mut migration, migration_task) = install_schema().await;
        let request_id = Uuid::new_v4();
        let transaction = migration.transaction().await.expect("draft transaction");
        initialize_draft(&transaction, REQUEST_ENTITY, request_id, "submitter")
            .await
            .expect("draft initializes");
        record_authored_intake_fields(
            &transaction,
            REQUEST_ENTITY,
            request_id,
            ["explicit-null", "value"],
        )
        .await
        .expect("authored presence saves");
        let materialized = Map::from_iter([
            ("explicit-null".to_owned(), Value::Null),
            ("missing-default-null".to_owned(), Value::Null),
            ("value".to_owned(), json!("present")),
        ]);
        let authored =
            load_authored_intake(&transaction, REQUEST_ENTITY, request_id, &materialized)
                .await
                .expect("authored intake loads");
        assert_eq!(
            authored,
            Map::from_iter([
                ("explicit-null".to_owned(), Value::Null),
                ("value".to_owned(), json!("present")),
            ])
        );
        transaction.commit().await.expect("presence commits");

        migration
            .execute(
                "UPDATE registry_internal.registry_request_state
                    SET state = 'canceled', detail_erased_at = transaction_timestamp()
                  WHERE request_entity_id = $1 AND request_id = $2",
                &[&REQUEST_ENTITY, &request_id],
            )
            .await
            .expect("detail erases");
        erase_authored_intake_fields(&migration, REQUEST_ENTITY, request_id)
            .await
            .expect("authored intake presence erases with request detail");
        let retained = migration
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_request_intake_presence
                  WHERE request_entity_id = $1 AND request_id = $2",
                &[&REQUEST_ENTITY, &request_id],
            )
            .await
            .expect("presence count")
            .get::<_, i64>(0);
        assert_eq!(retained, 0);
        migration_task.abort();
        database.cleanup().await;
    }

    #[tokio::test]
    async fn review_timing_is_bounded_by_first_completion_and_survives_detail_erasure() {
        let (database, mut migration, migration_task) = install_schema().await;
        let request_id = Uuid::new_v4();
        let direct_cancel_id = Uuid::new_v4();
        let approved_cancel_id = Uuid::new_v4();
        let transaction = migration.transaction().await.expect("timing transaction");
        initialize_draft(&transaction, REQUEST_ENTITY, request_id, "submitter")
            .await
            .expect("draft initializes");
        for (version, created_at) in [
            (1_i64, "2026-09-10T00:00:01Z"),
            (2, "2026-09-10T00:00:06Z"),
            (3, "2026-09-10T00:00:20Z"),
        ] {
            transaction
                .execute(
                    "INSERT INTO registry_internal.registry_request_proposals
                         (request_entity_id, request_id, proposal_version,
                          request_record_revision, contract_fingerprint, effect_digest,
                          snapshot, created_at)
                     VALUES ($1, $2, $3, 1, $4, $5, '{}'::jsonb, $6::text::timestamptz)",
                    &[
                        &REQUEST_ENTITY,
                        &request_id,
                        &version,
                        &format!("sha256:{}", "a".repeat(64)),
                        &format!("sha256:{}", "b".repeat(64)),
                        &created_at,
                    ],
                )
                .await
                .expect("proposal timing row inserts");
        }
        for (version, index, decided_at) in [
            (1_i64, 0_i32, "2026-09-10T00:00:02Z"),
            (2, 0, "2026-09-10T00:00:08Z"),
            (3, 0, "2026-09-10T00:00:21Z"),
        ] {
            transaction
                .execute(
                    "INSERT INTO registry_internal.registry_request_decisions
                         (request_entity_id, request_id, proposal_version, decision_index,
                          stage_id, actor_reference, decision, effect_digest, decided_at)
                     VALUES ($1, $2, $3, $4, 'review', $5, 'request_revision', $6,
                             $7::text::timestamptz)",
                    &[
                        &REQUEST_ENTITY,
                        &request_id,
                        &version,
                        &index,
                        &format!("actor-{version}"),
                        &format!("sha256:{}", "b".repeat(64)),
                        &decided_at,
                    ],
                )
                .await
                .expect("pause boundary inserts");
        }
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_request_decisions
                     (request_entity_id, request_id, proposal_version, decision_index,
                      stage_id, actor_reference, decision, effect_digest, decided_at)
                 VALUES ($1, $2, 2, 1, 'review', 'rejecting-actor', 'reject', $3,
                         '2026-09-10T00:00:10Z'::timestamptz)",
                &[
                    &REQUEST_ENTITY,
                    &request_id,
                    &format!("sha256:{}", "b".repeat(64)),
                ],
            )
            .await
            .expect("legacy rejection before revision and cancellation inserts");
        transaction
            .execute(
                "UPDATE registry_internal.registry_request_state
                    SET state = 'canceled', proposal_version = 3, workflow_revision = 9,
                        detail_erased_at = '2026-09-10T00:00:30Z'::timestamptz,
                        updated_at = '2026-09-10T00:00:30Z'::timestamptz,
                        review_completed_at = NULL
                  WHERE request_entity_id = $1 AND request_id = $2",
                &[&REQUEST_ENTITY, &request_id],
            )
            .await
            .expect("legacy terminal row saves without a completion summary");
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_revisions
                     (entity_id, record_id, record_reference, record_revision,
                      predecessor_revision, record_lifecycle, package_revision, operation_id,
                      mutation_kind, principal_reference, request_reference, snapshot, created_at)
                 VALUES ($1, $2, 'legacy-request', 1, NULL, 'active', 'legacy-package',
                         'cancel', 'patch', 'legacy-actor', 'legacy-request',
                         '{}'::text::bytea, '2026-09-10T00:00:25Z'::timestamptz)",
                &[&REQUEST_ENTITY, &request_id],
            )
            .await
            .expect("retained cancellation revision inserts");
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_request_revision_links
                     (entity_id, record_id, record_revision, request_entity_id, request_id,
                      proposal_version, link_kind, created_at)
                 VALUES ($1, $2, 1, $1, $2, 3, 'request_lifecycle',
                         '2026-09-10T00:00:25Z'::timestamptz)",
                &[&REQUEST_ENTITY, &request_id],
            )
            .await
            .expect("retained cancellation link inserts");
        initialize_draft(
            &transaction,
            REQUEST_ENTITY,
            direct_cancel_id,
            "direct-cancel-submitter",
        )
        .await
        .expect("direct-cancel draft initializes");
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_request_proposals
                     (request_entity_id, request_id, proposal_version,
                      request_record_revision, contract_fingerprint, effect_digest,
                      snapshot, created_at)
                 VALUES ($1, $2, 1, 1, $3, $4, '{}'::jsonb,
                         '2026-09-10T00:00:01Z'::timestamptz)",
                &[
                    &REQUEST_ENTITY,
                    &direct_cancel_id,
                    &format!("sha256:{}", "a".repeat(64)),
                    &format!("sha256:{}", "b".repeat(64)),
                ],
            )
            .await
            .expect("direct-cancel proposal inserts");
        transaction
            .execute(
                "UPDATE registry_internal.registry_request_state
                    SET state = 'canceled', detail_erased_at = '2026-09-10T00:00:30Z',
                        updated_at = '2026-09-10T00:00:30Z', review_completed_at = NULL
                  WHERE request_entity_id = $1 AND request_id = $2",
                &[&REQUEST_ENTITY, &direct_cancel_id],
            )
            .await
            .expect("direct-cancel erased state saves");
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_revisions
                     (entity_id, record_id, record_reference, record_revision,
                      predecessor_revision, record_lifecycle, package_revision, operation_id,
                      mutation_kind, principal_reference, request_reference, snapshot, created_at)
                 VALUES ($1, $2, 'direct-cancel', 1, NULL, 'active', 'legacy-package',
                         'cancel', 'patch', 'legacy-actor', 'direct-cancel',
                         '{}'::text::bytea, '2026-09-10T00:00:10Z'::timestamptz)",
                &[&REQUEST_ENTITY, &direct_cancel_id],
            )
            .await
            .expect("direct cancellation revision inserts");
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_request_revision_links
                     (entity_id, record_id, record_revision, request_entity_id, request_id,
                      proposal_version, link_kind, created_at)
                 VALUES ($1, $2, 1, $1, $2, 1, 'request_lifecycle',
                         '2026-09-10T00:00:10Z'::timestamptz)",
                &[&REQUEST_ENTITY, &direct_cancel_id],
            )
            .await
            .expect("direct cancellation link inserts");
        initialize_draft(
            &transaction,
            REQUEST_ENTITY,
            approved_cancel_id,
            "approved-cancel-submitter",
        )
        .await
        .expect("approved-cancel draft initializes");
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_request_proposals
                     (request_entity_id, request_id, proposal_version,
                      request_record_revision, contract_fingerprint, effect_digest,
                      snapshot, created_at)
                 VALUES ($1, $2, 1, 1, $3, $4, '{}'::jsonb,
                         '2026-09-10T00:00:01Z'::timestamptz)",
                &[
                    &REQUEST_ENTITY,
                    &approved_cancel_id,
                    &format!("sha256:{}", "a".repeat(64)),
                    &format!("sha256:{}", "b".repeat(64)),
                ],
            )
            .await
            .expect("approved-cancel proposal inserts");
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_request_decisions
                     (request_entity_id, request_id, proposal_version, decision_index,
                      stage_id, actor_reference, decision, effect_digest, decided_at)
                 VALUES ($1, $2, 1, 0, 'review', 'approving-actor', 'approve', $3,
                         '2026-09-10T00:00:05Z'::timestamptz)",
                &[
                    &REQUEST_ENTITY,
                    &approved_cancel_id,
                    &format!("sha256:{}", "b".repeat(64)),
                ],
            )
            .await
            .expect("approved-cancel approval inserts");
        transaction
            .execute(
                "UPDATE registry_internal.registry_request_state
                    SET state = 'canceled', detail_erased_at = '2026-09-10T00:00:30Z',
                        updated_at = '2026-09-10T00:00:30Z', review_completed_at = NULL
                  WHERE request_entity_id = $1 AND request_id = $2",
                &[&REQUEST_ENTITY, &approved_cancel_id],
            )
            .await
            .expect("approved-cancel erased state saves");
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_revisions
                     (entity_id, record_id, record_reference, record_revision,
                      predecessor_revision, record_lifecycle, package_revision, operation_id,
                      mutation_kind, principal_reference, request_reference, snapshot, created_at)
                 VALUES ($1, $2, 'approved-cancel', 1, NULL, 'active', 'legacy-package',
                         'cancel', 'patch', 'legacy-actor', 'approved-cancel',
                         '{}'::text::bytea, '2026-09-10T00:00:10Z'::timestamptz)",
                &[&REQUEST_ENTITY, &approved_cancel_id],
            )
            .await
            .expect("approved-cancel cancellation revision inserts");
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_request_revision_links
                     (entity_id, record_id, record_revision, request_entity_id, request_id,
                      proposal_version, link_kind, created_at)
                 VALUES ($1, $2, 1, $1, $2, 1, 'request_lifecycle',
                         '2026-09-10T00:00:10Z'::timestamptz)",
                &[&REQUEST_ENTITY, &approved_cancel_id],
            )
            .await
            .expect("approved-cancel cancellation link inserts");
        transaction
            .commit()
            .await
            .expect("legacy timing rows commit");

        install_mutation_schema(&migration, &database.runtime_role)
            .await
            .expect("schema upgrade backfills the terminal completion boundary");
        let transaction = migration
            .transaction()
            .await
            .expect("timing read transaction");

        let before_erasure = load_review_timing(&transaction, REQUEST_ENTITY, request_id)
            .await
            .expect("review timing loads")
            .expect("submitted request has timing");
        assert_eq!(
            before_erasure.first_submitted_at,
            "2026-09-10T00:00:01.000000Z"
        );
        assert_eq!(before_erasure.paused_milliseconds, 6_000);
        assert_eq!(before_erasure.pause_started_at, None);
        assert_eq!(
            before_erasure.completed_at.as_deref(),
            Some("2026-09-10T00:00:10.000000Z")
        );
        let direct_cancel = load_review_timing(&transaction, REQUEST_ENTITY, direct_cancel_id)
            .await
            .expect("direct cancellation timing loads")
            .expect("direct cancellation was submitted");
        assert_eq!(
            direct_cancel.completed_at.as_deref(),
            Some("2026-09-10T00:00:10.000000Z")
        );
        let approved_cancel = load_review_timing(&transaction, REQUEST_ENTITY, approved_cancel_id)
            .await
            .expect("approved-cancel timing loads")
            .expect("approved-cancel request was submitted");
        assert_eq!(
            approved_cancel.completed_at.as_deref(),
            Some("2026-09-10T00:00:10.000000Z")
        );

        transaction
            .execute(
                "UPDATE registry_internal.registry_request_proposals
                    SET snapshot = NULL, erased_at = transaction_timestamp()
                  WHERE request_entity_id = $1 AND request_id = $2",
                &[&REQUEST_ENTITY, &request_id],
            )
            .await
            .expect("proposal detail erases");
        let after_erasure = load_review_timing(&transaction, REQUEST_ENTITY, request_id)
            .await
            .expect("retained timing loads")
            .expect("proposal timestamps survive erasure");
        assert_eq!(after_erasure, before_erasure);

        transaction.commit().await.expect("timing commits");
        migration_task.abort();
        database.cleanup().await;
    }

    #[tokio::test]
    async fn request_store_roundtrips_current_lifecycle_and_preserves_history() {
        let (database, mut migration, migration_task) = install_schema().await;
        let request_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();

        let transaction = migration.transaction().await.expect("draft transaction");
        initialize_draft(&transaction, REQUEST_ENTITY, request_id, "submitter")
            .await
            .expect("draft initializes");
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_revisions
                     (entity_id, record_id, record_reference, record_revision,
                      predecessor_revision, record_lifecycle, package_revision, operation_id,
                      mutation_kind, principal_reference, request_reference, snapshot)
                 VALUES ($1, $2, 'request-ref', 1, NULL, 'active', 'package-1',
                         'records.create', 'create', 'principal-ref', 'binding-ref',
                         convert_to('{}', 'UTF8'))",
                &[&REQUEST_ENTITY, &request_id],
            )
            .await
            .expect("request create revision inserts");
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_idempotency
                     (key_reference, binding_reference, result_kind, record_reference,
                      record_revision, response_status, response_body, response_headers)
                 VALUES ('request-create-key', 'binding-ref', 'record', 'request-ref', 1,
                         201, convert_to('{}', 'UTF8'), decode('0000', 'hex'))",
                &[],
            )
            .await
            .expect("request create idempotency result inserts");
        link_request_revision(
            &transaction,
            REQUEST_ENTITY,
            request_id,
            1,
            REQUEST_ENTITY,
            request_id,
            1,
            "request_create",
        )
        .await
        .expect("request create revision link inserts");
        link_idempotency_result(
            &transaction,
            "request-create-key",
            REQUEST_ENTITY,
            request_id,
            1,
        )
        .await
        .expect("request create idempotency link inserts");
        transaction.commit().await.expect("draft commits");

        let transaction = migration
            .transaction()
            .await
            .expect("load draft transaction");
        require_owned_draft(&transaction, REQUEST_ENTITY, request_id, "submitter")
            .await
            .expect("owner can keep editing draft");
        assert_eq!(
            require_owned_draft(&transaction, REQUEST_ENTITY, request_id, "intruder")
                .await
                .expect_err("non-owner cannot edit draft"),
            MutationError::PreconditionFailed
        );
        let loaded = load(&transaction, REQUEST_ENTITY, request_id, true)
            .await
            .expect("draft loads");
        assert_eq!(loaded.state(), RequestState::Draft);
        assert_eq!(loaded.owner().as_str(), "submitter");
        let header = load_header(&transaction, REQUEST_ENTITY, request_id, false)
            .await
            .expect("draft header loads without materializing a workflow");
        assert_eq!(header.owner_reference, "submitter");
        assert_eq!(header.state, "draft");
        assert_eq!(header.proposal_version, 1);
        assert_eq!(header.workflow_revision, 1);
        assert!(!header.current_proposal_erased);
        assert!(!header.is_terminal());
        transaction.commit().await.expect("load draft commits");

        let submitted = workflow(request_id)
            .submit(
                context("submitter", 1),
                proposal(target_id, "site-a", "site-b"),
            )
            .expect("submit")
            .into_workflow();
        let transaction = migration.transaction().await.expect("submit transaction");
        save(&transaction, REQUEST_ENTITY, request_id, 1, &submitted)
            .await
            .expect("submitted workflow saves");
        save_targets(
            &transaction,
            REQUEST_ENTITY,
            request_id,
            1,
            &[target_snapshot(target_id, "site-a", "site-b")],
        )
        .await
        .expect("target snapshots save");
        transaction.commit().await.expect("submit commits");

        let transaction = migration
            .transaction()
            .await
            .expect("submitted load transaction");
        let loaded = load(&transaction, REQUEST_ENTITY, request_id, true)
            .await
            .expect("submitted loads");
        assert_eq!(loaded.state(), RequestState::Submitted);
        assert_eq!(loaded.decisions().len(), 0);
        let targets = load_targets(&transaction, REQUEST_ENTITY, request_id, 1)
            .await
            .expect("target snapshots load");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].entity_id, TARGET_ENTITY);
        assert_eq!(targets[0].record_id, target_id);
        assert_eq!(targets[0].expected_revision, Some(3));
        transaction.commit().await.expect("submitted load commits");

        let needs_changes = request_revision(submitted, "reviewer-a", 2);
        let transaction = migration.transaction().await.expect("decision transaction");
        save(&transaction, REQUEST_ENTITY, request_id, 2, &needs_changes)
            .await
            .expect("revision request saves");
        transaction.commit().await.expect("decision commits");

        let draft = needs_changes
            .revise(context("submitter", 3))
            .expect("revise")
            .into_workflow();
        let transaction = migration.transaction().await.expect("revise transaction");
        save(&transaction, REQUEST_ENTITY, request_id, 3, &draft)
            .await
            .expect("draft revision saves");
        transaction.commit().await.expect("revise commits");

        let transaction = migration
            .transaction()
            .await
            .expect("final load transaction");
        let loaded = load(&transaction, REQUEST_ENTITY, request_id, true)
            .await
            .expect("draft revision loads");
        assert_eq!(loaded.state(), RequestState::Draft);
        assert_eq!(loaded.current_version().get(), 2);
        assert!(loaded.current_proposal().is_none());
        assert!(loaded.decisions().is_empty());
        transaction.commit().await.expect("final load commits");

        migration
            .execute(
                "UPDATE registry_internal.registry_request_state
                    SET state = 'canceled',
                        detail_erased_at = transaction_timestamp(),
                        workflow_revision = workflow_revision + 1
                  WHERE request_entity_id = $1 AND request_id = $2",
                &[&REQUEST_ENTITY, &request_id],
            )
            .await
            .expect("canceled draft detail erasure marker saves");
        let transaction = migration
            .transaction()
            .await
            .expect("erased header transaction");
        let header = load_header(&transaction, REQUEST_ENTITY, request_id, false)
            .await
            .expect("erased draft header loads without restored workflow");
        assert_eq!(header.state, "canceled");
        assert!(header.current_proposal_erased);
        assert!(header.is_terminal());
        transaction
            .commit()
            .await
            .expect("erased header load commits");

        let historical_proposals = migration
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_request_proposals
                 WHERE request_entity_id = $1 AND request_id = $2",
                &[&REQUEST_ENTITY, &request_id],
            )
            .await
            .expect("proposal history count succeeds")
            .get::<_, i64>(0);
        let historical_decisions = migration
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_request_decisions
                 WHERE request_entity_id = $1 AND request_id = $2",
                &[&REQUEST_ENTITY, &request_id],
            )
            .await
            .expect("decision history count succeeds")
            .get::<_, i64>(0);
        let linked_receipts = migration
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_request_idempotency_links
                 WHERE request_entity_id = $1 AND request_id = $2 AND proposal_version = 1",
                &[&REQUEST_ENTITY, &request_id],
            )
            .await
            .expect("idempotency link count succeeds")
            .get::<_, i64>(0);
        let linked_revisions = migration
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_request_revision_links
                 WHERE request_entity_id = $1 AND request_id = $2 AND proposal_version = 1",
                &[&REQUEST_ENTITY, &request_id],
            )
            .await
            .expect("revision link count succeeds")
            .get::<_, i64>(0);
        assert_eq!(historical_proposals, 1);
        assert_eq!(historical_decisions, 1);
        assert_eq!(linked_receipts, 1);
        assert_eq!(linked_revisions, 1);

        migration_task.abort();
        database.cleanup().await;
    }

    #[tokio::test]
    async fn request_store_rejects_conflicting_immutable_rows_and_erased_targets() {
        let (database, mut migration, migration_task) = install_schema().await;
        let request_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();
        let submitted = workflow(request_id)
            .submit(
                context("submitter", 1),
                proposal(target_id, "site-a", "site-b"),
            )
            .expect("submit")
            .into_workflow();

        let transaction = migration.transaction().await.expect("draft transaction");
        initialize_draft(&transaction, REQUEST_ENTITY, request_id, "submitter")
            .await
            .expect("draft initializes");
        save(&transaction, REQUEST_ENTITY, request_id, 1, &submitted)
            .await
            .expect("submitted workflow saves");
        save_targets(
            &transaction,
            REQUEST_ENTITY,
            request_id,
            1,
            &[target_snapshot(target_id, "site-a", "site-b")],
        )
        .await
        .expect("target snapshots save");
        transaction.commit().await.expect("submit commits");

        migration
            .execute(
                "UPDATE registry_internal.registry_request_proposals
                 SET effect_digest = 'sha256:0000000000000000000000000000000000000000000000000000000000000000'
                 WHERE request_entity_id = $1 AND request_id = $2 AND proposal_version = 1",
                &[&REQUEST_ENTITY, &request_id],
            )
            .await
            .expect("test corrupts immutable proposal digest");
        let transaction = migration.transaction().await.expect("conflict transaction");
        assert_eq!(
            save(&transaction, REQUEST_ENTITY, request_id, 1, &submitted)
                .await
                .expect_err("proposal mismatch is refused"),
            MutationError::Conflict
        );
        transaction.rollback().await.expect("conflict rolls back");

        migration
            .execute(
                "UPDATE registry_internal.registry_request_proposals
                 SET effect_digest = $3
                 WHERE request_entity_id = $1 AND request_id = $2 AND proposal_version = 1",
                &[
                    &REQUEST_ENTITY,
                    &request_id,
                    &submitted
                        .current_proposal()
                        .expect("proposal")
                        .effect_digest()
                        .as_str(),
                ],
            )
            .await
            .expect("test restores immutable proposal digest");
        let transaction = migration
            .transaction()
            .await
            .expect("duplicate target transaction");
        assert_eq!(
            save_targets(
                &transaction,
                REQUEST_ENTITY,
                request_id,
                1,
                &[
                    target_snapshot(target_id, "site-a", "site-b"),
                    target_snapshot(target_id, "site-a", "site-c"),
                ],
            )
            .await
            .expect_err("duplicate target key is refused"),
            MutationError::Conflict
        );
        transaction
            .rollback()
            .await
            .expect("duplicate target rolls back");

        migration
            .execute(
                "UPDATE registry_internal.registry_request_targets
                 SET base_snapshot = NULL,
                     after_snapshot = NULL,
                     erased_at = transaction_timestamp()
                 WHERE request_entity_id = $1 AND request_id = $2 AND proposal_version = 1",
                &[&REQUEST_ENTITY, &request_id],
            )
            .await
            .expect("test erases stored target snapshot");
        let transaction = migration
            .transaction()
            .await
            .expect("erased target transaction");
        let refused = load_targets(&transaction, REQUEST_ENTITY, request_id, 1).await;
        assert!(matches!(refused, Err(MutationError::PreconditionFailed)));
        transaction
            .rollback()
            .await
            .expect("erased target load rolls back");

        migration_task.abort();
        database.cleanup().await;
    }
}
