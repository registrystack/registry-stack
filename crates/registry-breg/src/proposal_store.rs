// SPDX-License-Identifier: Apache-2.0

//! Engine-owned Proposal state, inputs, immutable submissions and receipts.
//! A Proposal has no business-record table or generated record CRUD routes.

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_canonical_json::canonicalize_json;
use serde_json::{Map, Value};
use tokio_postgres::error::SqlState;
use tokio_postgres::{GenericClient, Transaction};
use uuid::Uuid;

use crate::contract::Operation;
use crate::mutation::MutationError;
use crate::postgres::SqlIdentifier;
use crate::proposal_prepare::ProposalTargetSnapshot;
use crate::proposal_workflow::{
    ApplicationId, ApplicationReceipt, ApplicationResultLink, EntityId, ProposalDigest,
    ProposalKey, ProposalSnapshot, ProposalState, ProposalWorkflow, RecordId, RecordRevision,
    StateRevision, SubmissionVersion, TrustedActorRef, TrustedTimestamp,
    MAX_PROPOSAL_SNAPSHOT_BYTES, MAX_PROPOSAL_TARGETS,
};

pub(crate) const PROPOSAL_TABLES: &[(&str, &[&str])] = &[
    ("registry_proposal_activation_compatibility", &["SELECT"]),
    ("registry_proposal_state", &["INSERT", "SELECT", "UPDATE"]),
    ("registry_proposal_submissions", &["INSERT", "SELECT"]),
    ("registry_proposal_task_authority", &["INSERT", "SELECT"]),
    ("registry_proposal_targets", &["INSERT", "SELECT"]),
    ("registry_proposal_applications", &["INSERT", "SELECT"]),
    ("registry_proposal_evidence_uses", &["INSERT"]),
    ("registry_proposal_results", &["INSERT", "SELECT"]),
    ("registry_proposal_idempotency_links", &["INSERT", "SELECT"]),
];

pub(crate) async fn install(
    client: &impl GenericClient,
    runtime_role: &SqlIdentifier,
) -> Result<(), MutationError> {
    client.batch_execute(
        "CREATE TABLE IF NOT EXISTS registry_internal.registry_proposal_state (
             action_id text NOT NULL CHECK (action_id <> ''),
             proposal_id uuid NOT NULL UNIQUE,
             owner_reference text NOT NULL CHECK (owner_reference <> ''),
            state text NOT NULL CHECK (state IN
                 ('draft','submitted','cancelled','applied','rejected')),
             submission_version bigint NOT NULL CHECK (submission_version BETWEEN 1 AND 4294967295),
             workflow_revision bigint NOT NULL CHECK (workflow_revision > 0),
             action_revision text NOT NULL DEFAULT '',
             action_title text,
             input jsonb CHECK (input IS NULL OR jsonb_typeof(input) = 'object'),
             input_targets jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(input_targets) = 'array'),
             blocked_reason text CHECK (blocked_reason IS NULL OR blocked_reason = 'package-changed'),
             detail_erased_at timestamptz,
             created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
             updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
             PRIMARY KEY (action_id, proposal_id),
             CONSTRAINT registry_proposal_state_detail_erasure_terminal CHECK (
                 detail_erased_at IS NULL OR state IN ('cancelled','applied','rejected')
             )
         );
         CREATE TABLE IF NOT EXISTS registry_internal.registry_proposal_submissions (
             action_id text NOT NULL,
             proposal_id uuid NOT NULL,
             submission_version bigint NOT NULL CHECK (submission_version BETWEEN 1 AND 4294967295),
             input_revision bigint NOT NULL CHECK (input_revision > 0),
             contract_fingerprint text NOT NULL CHECK (contract_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
             effect_digest text NOT NULL CHECK (effect_digest ~ '^sha256:[0-9a-f]{64}$'),
             snapshot jsonb,
             erased_at timestamptz,
             created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
             PRIMARY KEY (action_id, proposal_id, submission_version),
             FOREIGN KEY (action_id, proposal_id)
                 REFERENCES registry_internal.registry_proposal_state,
             CHECK ((snapshot IS NULL) = (erased_at IS NOT NULL)),
             CHECK (snapshot IS NULL OR jsonb_typeof(snapshot) = 'object')
         );
         CREATE TABLE IF NOT EXISTS registry_internal.registry_proposal_activation_compatibility (
             action_id text NOT NULL,
             proposal_id uuid NOT NULL,
             submission_version bigint NOT NULL,
             effect_digest text NOT NULL CHECK (effect_digest ~ '^sha256:[0-9a-f]{64}$'),
             frozen_action_revision text NOT NULL CHECK (frozen_action_revision ~ '^sha256:[0-9a-f]{64}$'),
             frozen_system_grant_revision text,
             current_action_revision text NOT NULL CHECK (current_action_revision ~ '^sha256:[0-9a-f]{64}$'),
             current_system_grant_revision text,
             expected_policy jsonb NOT NULL CHECK (jsonb_typeof(expected_policy) = 'object'),
             accepted_binding jsonb NOT NULL CHECK (jsonb_typeof(accepted_binding) = 'object'),
             closure_digest text NOT NULL CHECK (closure_digest ~ '^sha256:[0-9a-f]{64}$'),
             from_package_digest text NOT NULL,
             candidate_package_digest text NOT NULL,
             activation_id uuid NOT NULL,
             proof_observed_at timestamptz NOT NULL,
             proof_valid_until timestamptz NOT NULL CHECK (proof_valid_until > proof_observed_at),
             PRIMARY KEY (action_id, proposal_id, submission_version, candidate_package_digest, activation_id),
             FOREIGN KEY (action_id, proposal_id, submission_version)
                 REFERENCES registry_internal.registry_proposal_submissions
         );
         CREATE TABLE IF NOT EXISTS registry_internal.registry_proposal_task_authority (
             action_id text NOT NULL,
             proposal_id uuid NOT NULL,
             submission_version bigint NOT NULL,
             binding jsonb NOT NULL CHECK (
                 jsonb_typeof(binding) = 'object' AND octet_length(binding::text) <= 65536
             ),
             PRIMARY KEY (action_id, proposal_id, submission_version),
             FOREIGN KEY (action_id, proposal_id, submission_version)
                 REFERENCES registry_internal.registry_proposal_submissions
         );
         CREATE TABLE IF NOT EXISTS registry_internal.registry_proposal_targets (
             action_id text NOT NULL,
             proposal_id uuid NOT NULL,
             submission_version bigint NOT NULL,
             target_entity_id text NOT NULL CHECK (target_entity_id <> ''),
             target_record_id uuid NOT NULL,
             operation text NOT NULL CHECK (operation IN ('create','patch')),
             expected_revision bigint CHECK (expected_revision > 0),
             base_snapshot jsonb,
             after_snapshot jsonb,
             erased_at timestamptz,
             PRIMARY KEY (action_id, proposal_id, submission_version,
                          target_entity_id, target_record_id),
             FOREIGN KEY (action_id, proposal_id, submission_version)
                 REFERENCES registry_internal.registry_proposal_submissions,
             CHECK ((operation = 'create' AND expected_revision IS NULL)
                    OR (operation = 'patch' AND expected_revision IS NOT NULL)),
             CHECK (base_snapshot IS NULL OR jsonb_typeof(base_snapshot) = 'object'),
             CHECK (after_snapshot IS NULL OR jsonb_typeof(after_snapshot) = 'object'),
             CHECK (erased_at IS NULL OR (base_snapshot IS NULL AND after_snapshot IS NULL))
         );
         CREATE INDEX IF NOT EXISTS registry_proposal_pending_targets
             ON registry_internal.registry_proposal_targets (target_entity_id, target_record_id);
         CREATE INDEX IF NOT EXISTS registry_proposal_queue
             ON registry_internal.registry_proposal_state (action_id, state, proposal_id);
         CREATE TABLE IF NOT EXISTS registry_internal.registry_proposal_applications (
             action_id text NOT NULL,
             proposal_id uuid NOT NULL,
             submission_version bigint NOT NULL,
             application_id uuid NOT NULL UNIQUE,
             effect_digest text NOT NULL CHECK (effect_digest ~ '^sha256:[0-9a-f]{64}$'),
             applied_by text NOT NULL CHECK (applied_by <> ''),
             applied_at timestamptz NOT NULL,
             reason text,
             reason_present boolean NOT NULL DEFAULT false,
             CONSTRAINT registry_proposal_application_reason_bound CHECK (
                 reason IS NULL OR (char_length(reason) <= 4096 AND reason_present)
             ),
             PRIMARY KEY (action_id, proposal_id, submission_version),
             FOREIGN KEY (action_id, proposal_id, submission_version)
                 REFERENCES registry_internal.registry_proposal_submissions
         );
         CREATE TABLE IF NOT EXISTS registry_internal.registry_proposal_evidence_uses (
             application_id uuid NOT NULL REFERENCES
                 registry_internal.registry_proposal_applications(application_id)
                 ON DELETE CASCADE,
             ordinal smallint NOT NULL CHECK (ordinal >= 0 AND ordinal < 2),
             retained jsonb NOT NULL CHECK (octet_length(retained::text) <= 1048576),
             expires_at timestamptz NOT NULL,
             created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
             PRIMARY KEY (application_id, ordinal),
             CHECK (expires_at > created_at)
         );
         CREATE TABLE IF NOT EXISTS registry_internal.registry_proposal_results (
             action_id text NOT NULL,
             proposal_id uuid NOT NULL,
             submission_version bigint NOT NULL,
             target_entity_id text NOT NULL,
             target_record_id uuid NOT NULL,
             target_revision bigint NOT NULL CHECK (target_revision > 0),
             PRIMARY KEY (action_id, proposal_id, submission_version,
                          target_entity_id, target_record_id),
             FOREIGN KEY (action_id, proposal_id, submission_version)
                 REFERENCES registry_internal.registry_proposal_applications,
             FOREIGN KEY (target_entity_id, target_record_id, target_revision)
                 REFERENCES registry_internal.registry_revisions
                     (entity_id, record_id, record_revision)
         );
         CREATE TABLE IF NOT EXISTS registry_internal.registry_proposal_idempotency_links (
             key_reference text NOT NULL,
             action_revision text NOT NULL CHECK (action_revision ~ '^sha256:[0-9a-f]{64}$'),
             action_id text NOT NULL CHECK (action_id <> ''),
             proposal_id uuid NOT NULL,
             submission_version bigint NOT NULL CHECK (submission_version > 0),
             created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
             PRIMARY KEY (key_reference, action_id, proposal_id, submission_version),
             FOREIGN KEY (key_reference)
                 REFERENCES registry_internal.registry_idempotency (key_reference),
             FOREIGN KEY (action_id, proposal_id)
                 REFERENCES registry_internal.registry_proposal_state
         );
         CREATE INDEX IF NOT EXISTS registry_proposal_idempotency_by_request
             ON registry_internal.registry_proposal_idempotency_links
                 (action_id, proposal_id, submission_version);
"
    ).await.map_err(|_| MutationError::Unavailable)?;
    crate::attachment_store::install(client, runtime_role).await?;
    crate::review_store::install(client, runtime_role).await?;
    let revoke_grantees = crate::postgres::RuntimeRevoke::detect(client, runtime_role)
        .await
        .map_err(|_| MutationError::Unavailable)?
        .with_public();
    for (table, privileges) in PROPOSAL_TABLES {
        let role = runtime_role.as_str();
        client
            .batch_execute(&format!(
                "REVOKE ALL ON registry_internal.{table} FROM {revoke_grantees};
             GRANT {} ON registry_internal.{table} TO \"{role}\";",
                privileges.join(", ")
            ))
            .await
            .map_err(|_| MutationError::Unavailable)?;
    }
    Ok(())
}

/// Retain verified submitter authority separately from all later reviewers.
pub(crate) async fn retain_evidence(
    transaction: &Transaction<'_>,
    application_id: Uuid,
    acquisitions: &[crate::action_evidence_client::VerifiedAcquisition],
) -> Result<(), MutationError> {
    if acquisitions.len() > 2 {
        return Err(MutationError::Unavailable);
    }
    let mut bytes = 0usize;
    for (ordinal, acquisition) in acquisitions.iter().enumerate() {
        let retained = acquisition
            .retained_serialization_for("registry.breg.proposal-commit-evidence-use/v1")
            .map_err(MutationError::from)?;
        bytes = bytes
            .checked_add(
                crate::action_evidence_client::retained_jsonb_bytes(&retained)
                    .map_err(MutationError::from)?,
            )
            .ok_or(MutationError::Unavailable)?;
        if bytes > crate::action_evidence::MAXIMUM_RETAINED_EVIDENCE_BYTES {
            return Err(MutationError::Unavailable);
        }
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_proposal_evidence_uses
            (application_id,ordinal,retained,expires_at) VALUES ($1,$2,$3,$4)",
                &[
                    &application_id,
                    &(ordinal as i16),
                    &retained,
                    &acquisition.retention_expires_at(),
                ],
            )
            .await
            .map_err(map_store_error)?;
    }
    Ok(())
}

/// Retain verified submitter authority separately from all later reviewers.
/// The proposal foreign key binds these claims to its immutable effect digest.
pub(crate) async fn save_task_authority(
    transaction: &Transaction<'_>,
    entity_id: &str,
    record_id: Uuid,
    submission_version: i64,
    binding: &crate::task_grant::TaskGrantBinding,
) -> Result<(), MutationError> {
    binding
        .validate()
        .map_err(|_| MutationError::PreconditionFailed)?;
    let value = serde_json::to_value(binding).map_err(|_| MutationError::Unavailable)?;
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_proposal_task_authority
             (action_id, proposal_id, submission_version, binding)
         VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
            &[&entity_id, &record_id, &submission_version, &value],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    let stored = load_task_authority(transaction, entity_id, record_id, submission_version).await?;
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
    submission_version: i64,
) -> Result<Option<crate::task_grant::TaskGrantBinding>, MutationError> {
    let row = transaction
        .query_opt(
            "SELECT binding FROM registry_internal.registry_proposal_task_authority
         WHERE action_id = $1 AND proposal_id = $2 AND submission_version = $3",
            &[&entity_id, &record_id, &submission_version],
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
pub(crate) struct ProposalWorkflowHeader {
    pub owner_reference: String,
    pub state: String,
    pub submission_version: i64,
    pub workflow_revision: i64,
    pub current_proposal_erased: bool,
    pub applier_reference: Option<String>,
    pub application_reason_present: bool,
}

impl std::fmt::Debug for ProposalWorkflowHeader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProposalWorkflowHeader")
            .field("has_owner_reference", &!self.owner_reference.is_empty())
            .field("state", &self.state)
            .field("submission_version", &self.submission_version)
            .field("workflow_revision", &self.workflow_revision)
            .field("current_proposal_erased", &self.current_proposal_erased)
            .field("has_applier_reference", &self.applier_reference.is_some())
            .field(
                "application_reason_present",
                &self.application_reason_present,
            )
            .finish()
    }
}

impl ProposalWorkflowHeader {
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn is_terminal(&self) -> bool {
        matches!(self.state.as_str(), "cancelled" | "applied" | "rejected")
    }
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
            "INSERT INTO registry_internal.registry_proposal_state
             (action_id, proposal_id, owner_reference, state,
              submission_version, workflow_revision)
         VALUES ($1, $2, $3, 'draft', 1, 1)",
            &[&entity_id, &record_id, &owner_reference],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    Ok(())
}

/// Store the authored Action input directly, preserving missing versus null.
/// The caller owns the state lock, transition fence, and current authority.
pub(crate) async fn save_draft_input(
    transaction: &Transaction<'_>,
    action_id: &str,
    proposal_id: Uuid,
    action_revision: &str,
    action_title: Option<&str>,
    input: &Map<String, Value>,
) -> Result<(), MutationError> {
    if action_revision.is_empty()
        || canonical_object_size(input)? > MAX_PROPOSAL_SNAPSHOT_BYTES
        || action_title
            .is_some_and(|title| title.len() > 1024 || title.chars().any(char::is_control))
    {
        return Err(MutationError::InvalidRequest);
    }
    let changed = transaction
        .execute(
            "UPDATE registry_internal.registry_proposal_state
            SET action_revision=$3, action_title=$4, input=$5,
                updated_at=transaction_timestamp()
          WHERE action_id=$1 AND proposal_id=$2 AND state='draft'
            AND detail_erased_at IS NULL AND blocked_reason IS NULL",
            &[
                &action_id,
                &proposal_id,
                &action_revision,
                &action_title,
                &Value::Object(input.clone()),
            ],
        )
        .await
        .map_err(map_store_error)?;
    if changed != 1 {
        return Err(MutationError::PreconditionFailed);
    }
    Ok(())
}

/// Only an authorized Rebase may clear an activation block. The caller holds
/// the Proposal state lock and admitted the active Action's Start grant.
pub(crate) async fn clear_rebase_block(
    transaction: &Transaction<'_>,
    action_id: &str,
    proposal_id: Uuid,
) -> Result<(), MutationError> {
    let changed = transaction
        .execute(
            "UPDATE registry_internal.registry_proposal_state
        SET blocked_reason=NULL WHERE action_id=$1 AND proposal_id=$2 AND state='draft'
        AND detail_erased_at IS NULL",
            &[&action_id, &proposal_id],
        )
        .await
        .map_err(map_store_error)?;
    if changed != 1 {
        return Err(MutationError::PreconditionFailed);
    }
    Ok(())
}

pub(crate) struct ProposalDocument {
    pub action_id: String,
    pub proposal_id: Uuid,
    pub action_revision: String,
    pub action_title: Option<String>,
    pub input: Option<Map<String, Value>>,
    pub input_targets: Vec<(String, Uuid)>,
    pub blocked_reason: Option<String>,
    pub header: ProposalWorkflowHeader,
}

/// The lock order is chosen by the caller: observation precedes related reads,
/// mutation precedes effects, and exact receipt recovery retains its own order.
#[derive(Clone, Copy)]
pub(crate) enum DocumentLock {
    None,
    Share,
    Update,
}

/// The caller must establish a current per-Action Proposal grant before use.
/// Keep the lifecycle row stable while the caller projects its separate frozen
/// snapshot, review binding, application job and receipt. Writers take the
/// exclusive lock first; observations share it until their transaction ends.
pub(crate) async fn load_document(
    transaction: &Transaction<'_>,
    proposal_id: Uuid,
    lock: DocumentLock,
) -> Result<ProposalDocument, MutationError> {
    let sql = format!(
        "SELECT action_id, action_revision, action_title, input, blocked_reason, input_targets
           FROM registry_internal.registry_proposal_state WHERE proposal_id=$1{}",
        match lock {
            DocumentLock::None => "",
            DocumentLock::Share => " FOR SHARE",
            DocumentLock::Update => " FOR UPDATE",
        },
    );
    let row = transaction
        .query_opt(&sql, &[&proposal_id])
        .await
        .map_err(map_store_error)?
        .ok_or(MutationError::PreconditionFailed)?;
    let action_id: String = row.get(0);
    let input = row
        .get::<_, Option<Value>>(3)
        .map(|value| value.as_object().cloned().ok_or(MutationError::Unavailable))
        .transpose()?;
    let header = load_header(transaction, &action_id, proposal_id, false).await?;
    Ok(ProposalDocument {
        action_id,
        proposal_id,
        action_revision: row.get(1),
        action_title: row.get(2),
        input,
        blocked_reason: row.get(4),
        header,
        input_targets: serde_json::from_value(row.get(5))
            .map_err(|_| MutationError::Unavailable)?,
    })
}

pub(crate) async fn save_input_targets(
    transaction: &Transaction<'_>,
    action_id: &str,
    proposal_id: Uuid,
    targets: &[(String, Uuid)],
) -> Result<(), MutationError> {
    if targets.len() > MAX_PROPOSAL_TARGETS {
        return Err(MutationError::InvalidRequest);
    }
    let value = serde_json::to_value(targets).map_err(|_| MutationError::InvalidRequest)?;
    let changed = transaction
        .execute(
            "UPDATE registry_internal.registry_proposal_state SET input_targets=$3
          WHERE action_id=$1 AND proposal_id=$2 AND state='draft'",
            &[&action_id, &proposal_id, &value],
        )
        .await
        .map_err(map_store_error)?;
    if changed != 1 {
        return Err(MutationError::PreconditionFailed);
    }
    Ok(())
}

#[cfg(all(test, feature = "postgres-test"))]
async fn require_owned_draft(
    transaction: &Transaction<'_>,
    entity_id: &str,
    record_id: Uuid,
    actor_reference: &str,
) -> Result<(), MutationError> {
    let row = transaction
        .query_opt(
            "SELECT state, owner_reference FROM registry_internal.registry_proposal_state
         WHERE action_id = $1 AND proposal_id = $2 FOR UPDATE",
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
) -> Result<ProposalWorkflow, MutationError> {
    let sql = format!(
        "SELECT owner_reference, state, submission_version, workflow_revision
         FROM registry_internal.registry_proposal_state
         WHERE action_id = $1 AND proposal_id = $2{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    let row = transaction
        .query_opt(&sql, &[&entity_id, &record_id])
        .await
        .map_err(|_| MutationError::Unavailable)?
        .ok_or(MutationError::PreconditionFailed)?;
    let request = ProposalKey::new(
        EntityId::new(entity_id).map_err(|_| MutationError::Unavailable)?,
        RecordId::new(record_id.to_string()).map_err(|_| MutationError::Unavailable)?,
    );
    let owner = TrustedActorRef::from_verified_context(row.get::<_, String>(0))
        .map_err(|_| MutationError::Unavailable)?;
    let current_version = submission_version(row.get::<_, i64>(2))?;
    let revision = u64::try_from(row.get::<_, i64>(3)).map_err(|_| MutationError::Unavailable)?;
    let state = ProposalState::from_storage(&row.get::<_, String>(1))
        .map_err(|_| MutationError::Unavailable)?;
    let proposals = transaction
        .query(
            "SELECT submission_version, snapshot FROM registry_internal.registry_proposal_submissions
         WHERE action_id = $1 AND proposal_id = $2 AND submission_version = $3",
            &[&entity_id, &record_id, &i64::from(current_version.get())],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    let mut proposal_map = BTreeMap::new();
    for proposal in proposals {
        let snapshot = proposal
            .get::<_, Option<Value>>(1)
            .ok_or(MutationError::PreconditionFailed)?;
        let version = submission_version(proposal.get::<_, i64>(0))?;
        let snapshot: ProposalSnapshot =
            serde_json::from_value(snapshot).map_err(|_| MutationError::Unavailable)?;
        proposal_map.insert(version, snapshot);
    }
    let application = if let Some(application) = transaction
        .query_opt(
            "SELECT submission_version, application_id, effect_digest, applied_by,
                to_char(applied_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
                reason, reason_present
         FROM registry_internal.registry_proposal_applications
         WHERE action_id = $1 AND proposal_id = $2",
            &[&entity_id, &record_id],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
    {
        let version = submission_version(application.get::<_, i64>(0))?;
        let results = transaction
            .query(
                "SELECT target_entity_id, target_record_id, target_revision
             FROM registry_internal.registry_proposal_results
             WHERE action_id = $1 AND proposal_id = $2 AND submission_version = $3
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
                application.get(5),
                application.get(6),
            )
            .map_err(|_| MutationError::Unavailable)?,
        )
    } else {
        None
    };
    ProposalWorkflow::restore(
        request,
        owner,
        state,
        current_version,
        StateRevision::new(revision).map_err(|_| MutationError::Unavailable)?,
        proposal_map,
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
) -> Result<ProposalWorkflowHeader, MutationError> {
    let sql = format!(
        "SELECT s.owner_reference, s.state, s.submission_version, s.workflow_revision,
                COALESCE(s.detail_erased_at IS NOT NULL, false)
                    OR COALESCE(p.erased_at IS NOT NULL, false), a.applied_by,
                a.reason_present
           FROM registry_internal.registry_proposal_state s
           LEFT JOIN registry_internal.registry_proposal_submissions p
             ON p.action_id = s.action_id
            AND p.proposal_id = s.proposal_id
            AND p.submission_version = s.submission_version
          LEFT JOIN registry_internal.registry_proposal_applications a
            ON a.action_id = s.action_id
           AND a.proposal_id = s.proposal_id
           AND a.submission_version = s.submission_version
          WHERE s.action_id = $1 AND s.proposal_id = $2{}",
        if lock { " FOR UPDATE OF s" } else { "" }
    );
    let row = transaction
        .query_opt(&sql, &[&entity_id, &record_id])
        .await
        .map_err(|_| MutationError::Unavailable)?
        .ok_or(MutationError::PreconditionFailed)?;
    let state: String = row.get(1);
    ProposalState::from_storage(&state).map_err(|_| MutationError::Unavailable)?;
    let submission_version: i64 = row.get(2);
    let workflow_revision: i64 = row.get(3);
    if submission_version <= 0 || workflow_revision <= 0 {
        return Err(MutationError::Unavailable);
    }
    Ok(ProposalWorkflowHeader {
        owner_reference: row.get(0),
        state,
        submission_version,
        workflow_revision,
        current_proposal_erased: row.get(4),
        applier_reference: row.get(5),
        // The applications join is outer: a request without an application has
        // no reason to record.
        application_reason_present: row.get::<_, Option<bool>>(6).unwrap_or(false),
    })
}

pub(crate) async fn link_idempotency_result(
    transaction: &Transaction<'_>,
    key_reference: &str,
    action_id: &str,
    proposal_id: Uuid,
    submission_version: i64,
    action_revision: &str,
) -> Result<(), MutationError> {
    if key_reference.is_empty() || action_id.is_empty() || submission_version <= 0 {
        return Err(MutationError::InvalidRequest);
    }
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_proposal_idempotency_links
                 (key_reference, action_id, proposal_id, submission_version,action_revision)
             VALUES ($1, $2, $3, $4,$5)
             ON CONFLICT DO NOTHING",
            &[
                &key_reference,
                &action_id,
                &proposal_id,
                &submission_version,
                &action_revision,
            ],
        )
        .await
        .map_err(map_store_error)?;
    Ok(())
}

pub(crate) async fn save_targets(
    transaction: &Transaction<'_>,
    action_id: &str,
    proposal_id: Uuid,
    submission_version: i64,
    targets: &[ProposalTargetSnapshot],
) -> Result<(), MutationError> {
    if submission_version < 1 || targets.len() > MAX_PROPOSAL_TARGETS {
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
                "INSERT INTO registry_internal.registry_proposal_targets
                 (action_id, proposal_id, submission_version, target_entity_id,
                  target_record_id, operation, expected_revision, base_snapshot, after_snapshot)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (action_id, proposal_id, submission_version,
                          target_entity_id, target_record_id) DO NOTHING",
                &[
                    &action_id,
                    &proposal_id,
                    &submission_version,
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
                action_id,
                proposal_id,
                submission_version,
                snapshot,
            )
            .await?;
        }
    }
    Ok(())
}

pub(crate) async fn load_targets(
    transaction: &Transaction<'_>,
    action_id: &str,
    proposal_id: Uuid,
    submission_version: i64,
) -> Result<Vec<ProposalTargetSnapshot>, MutationError> {
    if submission_version < 1 {
        return Err(MutationError::InvalidRequest);
    }
    let rows = transaction
        .query(
            "SELECT target_entity_id, target_record_id, operation, expected_revision,
                    base_snapshot, after_snapshot
             FROM registry_internal.registry_proposal_targets
             WHERE action_id = $1 AND proposal_id = $2 AND submission_version = $3
             ORDER BY target_entity_id, target_record_id
             LIMIT 17",
            &[&action_id, &proposal_id, &submission_version],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    if rows.len() > MAX_PROPOSAL_TARGETS {
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
        let snapshot = ProposalTargetSnapshot {
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
    workflow: &ProposalWorkflow,
) -> Result<(), MutationError> {
    workflow
        .clone()
        .validate_restored()
        .map_err(|_| MutationError::Unavailable)?;
    let version = i64::from(workflow.current_version().get());
    let revision = i64::try_from(workflow.workflow_revision().get())
        .map_err(|_| MutationError::Unavailable)?;
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
                "INSERT INTO registry_internal.registry_proposal_submissions
                 (action_id, proposal_id, submission_version, input_revision,
                  contract_fingerprint, effect_digest, snapshot)
             VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
                &[
                    &entity_id,
                    &record_id,
                    &version,
                    &proposal.input_revision().get(),
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
                proposal.input_revision().get(),
                proposal.contract_fingerprint().as_str(),
                proposal.effect_digest().as_str(),
                &snapshot,
            )
            .await?;
        }
    }
    if let Some(application) = workflow.application() {
        let application_id = Uuid::parse_str(application.application_id().as_str())
            .map_err(|_| MutationError::Unavailable)?;
        let application_version = i64::from(application.version().get());
        let inserted = transaction
            .execute(
                "INSERT INTO registry_internal.registry_proposal_applications
                 (action_id, proposal_id, submission_version, application_id,
                  effect_digest, applied_by, applied_at, reason, reason_present)
             VALUES ($1, $2, $3, $4, $5, $6, $7::text::timestamptz, $8, $9)
             ON CONFLICT (action_id, proposal_id, submission_version) DO NOTHING",
                &[
                    &entity_id,
                    &record_id,
                    &application_version,
                    &application_id,
                    &application.effect_digest().as_str(),
                    &application.applied_by().as_str(),
                    &application.applied_at().as_str(),
                    &application.reason(),
                    &application.reason_present(),
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
                    "INSERT INTO registry_internal.registry_proposal_results
                     (action_id, proposal_id, submission_version, target_entity_id,
                      target_record_id, target_revision) VALUES ($1, $2, $3, $4, $5, $6)
                      ON CONFLICT (action_id, proposal_id, submission_version,
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
            "UPDATE registry_internal.registry_proposal_state
         SET state = $3, submission_version = $4, workflow_revision = $5,
             updated_at = transaction_timestamp()
         WHERE action_id = $1 AND proposal_id = $2 AND workflow_revision = $6",
            &[
                &entity_id,
                &record_id,
                &workflow.state().as_storage(),
                &version,
                &revision,
                &previous_revision,
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
    input_revision: i64,
    contract_fingerprint: &str,
    effect_digest: &str,
    snapshot: &Value,
) -> Result<(), MutationError> {
    let row = transaction
        .query_opt(
            "SELECT input_revision, contract_fingerprint, effect_digest, snapshot
             FROM registry_internal.registry_proposal_submissions
             WHERE action_id = $1 AND proposal_id = $2 AND submission_version = $3",
            &[&entity_id, &record_id, &version],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
        .ok_or(MutationError::Conflict)?;
    let existing_snapshot = row
        .get::<_, Option<Value>>(3)
        .ok_or(MutationError::PreconditionFailed)?;
    if row.get::<_, i64>(0) == input_revision
        && row.get::<_, String>(1) == contract_fingerprint
        && row.get::<_, String>(2) == effect_digest
        && existing_snapshot == *snapshot
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
                    applied_at = $4::text::timestamptz AS same_time, reason, reason_present
             FROM registry_internal.registry_proposal_applications
             WHERE action_id = $1 AND proposal_id = $2 AND submission_version = $3",
            &[&entity_id, &record_id, &version, &applied_at],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
        .ok_or(MutationError::Conflict)?;
    if row.get::<_, Uuid>(0) == application_id
        && row.get::<_, String>(1) == effect_digest
        && row.get::<_, String>(2) == applied_by
        && row.get::<_, bool>(3)
        && row.get::<_, Option<String>>(4).as_deref() == application.reason()
        && row.get::<_, bool>(5) == application.reason_present()
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
             FROM registry_internal.registry_proposal_results
             WHERE action_id = $1 AND proposal_id = $2 AND submission_version = $3
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
    action_id: &str,
    proposal_id: Uuid,
    submission_version: i64,
    snapshot: &ProposalTargetSnapshot,
) -> Result<(), MutationError> {
    let row = transaction
        .query_opt(
            "SELECT operation, expected_revision, base_snapshot, after_snapshot
             FROM registry_internal.registry_proposal_targets
             WHERE action_id = $1 AND proposal_id = $2 AND submission_version = $3
               AND target_entity_id = $4 AND target_record_id = $5",
            &[
                &action_id,
                &proposal_id,
                &submission_version,
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

fn validate_target_snapshot(snapshot: &ProposalTargetSnapshot) -> Result<(), MutationError> {
    if snapshot.entity_id.is_empty()
        || canonical_object_size(&snapshot.after)? > MAX_PROPOSAL_SNAPSHOT_BYTES
    {
        return Err(MutationError::InvalidRequest);
    }
    if let Some(before) = &snapshot.before {
        if canonical_object_size(before)? > MAX_PROPOSAL_SNAPSHOT_BYTES {
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

fn submission_version(value: i64) -> Result<SubmissionVersion, MutationError> {
    u32::try_from(value)
        .ok()
        .and_then(|value| SubmissionVersion::new(value).ok())
        .ok_or(MutationError::Unavailable)
}

#[cfg(test)]
#[cfg(feature = "postgres-test")]
mod tests {
    use registry_platform_canonical_json::canonicalize_json;
    use serde_json::{json, Map};
    use tokio_postgres::Client;
    use uuid::Uuid;

    use super::*;
    use crate::model::CompiledProposalReview;
    use crate::mutation::install_mutation_schema;
    use crate::proposal_workflow::{
        ContractFingerprint, EffectId, FieldId, FieldValue, FrozenPlannerKind,
        FrozenPlanningBinding, PackageFingerprint, PreparedEffect, PreparedFieldChange,
        PreparedProposal, PreparedTarget, ProposalState, RecordRevision, TrustedTimestamp,
        TrustedTransitionContext, WorkflowError,
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

    async fn install_schema() -> (TestDatabase, Client, tokio::task::JoinHandle<()>) {
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
        let header = ProposalWorkflowHeader {
            owner_reference: "private-owner-reference-canary".to_owned(),
            state: "applied".to_owned(),
            submission_version: 2,
            workflow_revision: 9,
            current_proposal_erased: false,
            applier_reference: Some("private-applier-reference-canary".to_owned()),
            application_reason_present: true,
        };
        let debug = format!("{header:?}");
        assert!(!debug.contains("private-owner-reference-canary"));
        assert!(!debug.contains("private-applier-reference-canary"));
        assert!(debug.contains("has_owner_reference: true"));
        assert!(debug.contains("has_applier_reference: true"));
    }

    fn workflow(proposal_id: Uuid) -> ProposalWorkflow {
        ProposalWorkflow::new_draft(
            ProposalKey::new(entity(REQUEST_ENTITY), record(proposal_id.to_string())),
            actor("submitter"),
            state_revision(1),
        )
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
        PreparedProposal::new_with_binding(
            record_revision(7),
            ContractFingerprint::new(
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            )
            .expect("contract fingerprint"),
            PackageFingerprint::new("3b0c7a52-5d1e-4f6a-8b9c-0d1e2f3a4b01")
                .expect("package fingerprint"),
            CompiledProposalReview::None,
            FrozenPlanningBinding::new(
                FrozenPlannerKind::Declarative,
                "registry.action-plan/v1",
                None,
            )
            .expect("planning binding"),
            effects,
            bytes,
        )
        .expect("prepared proposal")
    }

    fn target_snapshot(
        target_id: Uuid,
        before_site: &str,
        after_site: &str,
    ) -> ProposalTargetSnapshot {
        let mut before = Map::new();
        before.insert("site".to_owned(), json!(before_site));
        let mut after = before.clone();
        after.insert("site".to_owned(), json!(after_site));
        ProposalTargetSnapshot {
            entity_id: TARGET_ENTITY.to_owned(),
            record_id: target_id,
            operation: Operation::Patch,
            expected_revision: Some(3),
            before: Some(before),
            after,
        }
    }

    #[test]
    fn target_snapshot_store_uses_internal_envelope_expansion_bound() {
        let expanded = Map::from_iter([(
            "secret".to_owned(),
            json!({
                crate::history_schema::ENVELOPE_MEMBER_TAG:
                    "A".repeat(crate::plan::MAX_PLAN_SNAPSHOT_BYTES as usize)
            }),
        )]);
        assert!(
            canonical_object_size(&expanded).expect("expanded snapshot canonicalizes")
                > crate::plan::MAX_PLAN_SNAPSHOT_BYTES as usize
        );
        assert!(
            canonical_object_size(&expanded).expect("expanded snapshot canonicalizes")
                <= MAX_PROPOSAL_SNAPSHOT_BYTES
        );
        validate_target_snapshot(&ProposalTargetSnapshot {
            entity_id: TARGET_ENTITY.to_owned(),
            record_id: Uuid::new_v4(),
            operation: Operation::Create,
            expected_revision: None,
            before: None,
            after: expanded,
        })
        .expect("the target store admits bounded envelope expansion");

        let oversized = Map::from_iter([(
            "secret".to_owned(),
            json!({
                crate::history_schema::ENVELOPE_MEMBER_TAG:
                    "A".repeat(MAX_PROPOSAL_SNAPSHOT_BYTES)
            }),
        )]);
        assert_eq!(
            validate_target_snapshot(&ProposalTargetSnapshot {
                entity_id: TARGET_ENTITY.to_owned(),
                record_id: Uuid::new_v4(),
                operation: Operation::Create,
                expected_revision: None,
                before: None,
                after: oversized,
            }),
            Err(MutationError::InvalidRequest)
        );
    }

    #[tokio::test]
    async fn request_schema_installs_repeatably_and_grants_declared_table_privileges() {
        let (database, migration, migration_task) = install_schema().await;
        for (table, privileges) in PROPOSAL_TABLES {
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
    async fn proposal_task_authority_is_immutable_and_separate_from_later_application() {
        let (database, mut migration, migration_task) = install_schema().await;
        let proposal_id = Uuid::new_v4();
        let submitted = workflow(proposal_id)
            .submit(
                context("submitter", 1),
                proposal(Uuid::new_v4(), "site-a", "site-b"),
            )
            .expect("submit")
            .into_workflow();
        let grant: crate::task_grant::TaskGrantBinding = serde_json::from_value(json!({
            "grantId": Uuid::new_v4().to_string(),
            "sourceIssuer": "https://casework.test", "principal": "original-agent",
            "client": "original-client", "resource": "urn:breg:test", "purpose": "review",
            "bounds": {"type":"breg", "permissions":[{"collection":"people", "operations":["get","patch"]}]},
            "subjects": {"person_reference":"synthetic-person"},
            "expiresAt": chrono::Utc::now().timestamp() + 900,
        })).expect("binding");
        let tx = migration.transaction().await.expect("transaction");
        initialize_draft(&tx, REQUEST_ENTITY, proposal_id, "submitter")
            .await
            .expect("draft");
        save(&tx, REQUEST_ENTITY, proposal_id, 1, &submitted)
            .await
            .expect("proposal");
        save_task_authority(&tx, REQUEST_ENTITY, proposal_id, 1, &grant)
            .await
            .expect("bind");
        save_task_authority(&tx, REQUEST_ENTITY, proposal_id, 1, &grant)
            .await
            .expect("exact replay");
        assert_eq!(
            load_task_authority(&tx, REQUEST_ENTITY, proposal_id, 1)
                .await
                .unwrap(),
            Some(grant.clone())
        );
        let mut changed = serde_json::to_value(&grant).unwrap();
        changed["client"] = json!("replacement-client");
        let changed = serde_json::from_value(changed).unwrap();
        assert_eq!(
            save_task_authority(&tx, REQUEST_ENTITY, proposal_id, 1, &changed).await,
            Err(MutationError::IdempotencyConflict)
        );
        tx.commit().await.expect("commit");
        migration_task.abort();
        database.cleanup().await;
    }

    #[tokio::test]
    async fn request_state_storage_admits_only_the_states_a_transition_reaches() {
        let (database, mut migration, migration_task) = install_schema().await;
        let proposal_id = Uuid::new_v4();
        let transaction = migration.transaction().await.expect("draft transaction");
        initialize_draft(&transaction, REQUEST_ENTITY, proposal_id, "submitter")
            .await
            .expect("draft initializes");
        transaction.commit().await.expect("draft commits");

        let error = migration
            .execute(
                "UPDATE registry_internal.registry_proposal_state SET state = 'superseded'
                  WHERE action_id = $1 AND proposal_id = $2",
                &[&REQUEST_ENTITY, &proposal_id],
            )
            .await
            .expect_err("an unreachable state is refused by storage");
        assert_eq!(
            error.code(),
            Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION)
        );
        assert_eq!(
            ProposalState::from_storage("superseded"),
            Err(WorkflowError::InvalidRestoredState)
        );
        migration_task.abort();
        database.cleanup().await;
    }

    #[tokio::test]
    async fn proposal_inputs_preserve_missing_separately_from_null_and_erase() {
        let (database, mut migration, migration_task) = install_schema().await;
        let id = Uuid::new_v4();
        let tx = migration.transaction().await.unwrap();
        initialize_draft(&tx, REQUEST_ENTITY, id, "submitter")
            .await
            .unwrap();
        let input = Map::from_iter([
            ("explicit-null".to_owned(), Value::Null),
            ("value".to_owned(), json!("present")),
        ]);
        save_draft_input(
            &tx,
            REQUEST_ENTITY,
            id,
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            None,
            &input,
        )
        .await
        .unwrap();
        let document = load_document(&tx, id, DocumentLock::None).await.unwrap();
        assert_eq!(document.input, Some(input));
        assert!(!document.input.unwrap().contains_key("absent"));
        tx.commit().await.unwrap();
        migration
            .execute(
                "UPDATE registry_internal.registry_proposal_state SET state='cancelled',input=NULL,
            detail_erased_at=transaction_timestamp() WHERE proposal_id=$1",
                &[&id],
            )
            .await
            .unwrap();
        let tx = migration.transaction().await.unwrap();
        assert!(load_document(&tx, id, DocumentLock::None)
            .await
            .unwrap()
            .input
            .is_none());
        tx.commit().await.unwrap();
        migration_task.abort();
        database.cleanup().await;
    }

    #[tokio::test]
    async fn proposal_store_roundtrips_current_lifecycle_and_preserves_history() {
        let (database, mut migration, migration_task) = install_schema().await;
        let proposal_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();

        let transaction = migration.transaction().await.expect("draft transaction");
        initialize_draft(&transaction, REQUEST_ENTITY, proposal_id, "submitter")
            .await
            .expect("draft initializes");
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_idempotency
                     (key_reference, binding_reference, result_kind, record_reference,
                      record_revision, response_status, response_body, response_headers,
                      caller_issuer, caller_subject, key_scope, idempotency_key, receipt_expires_at)
                 VALUES ('request-create-key', 'binding-ref', 'record', 'request-ref', 1,
                         201, convert_to('{}', 'UTF8'), decode('0000', 'hex'),
                         'urn:test:issuer', 'test-subject', 'mutation', 'request-create-key', transaction_timestamp() + interval '7 days')",
                &[],
            )
            .await
            .expect("request create idempotency result inserts");
        link_idempotency_result(
            &transaction,
            "request-create-key",
            REQUEST_ENTITY,
            proposal_id,
            1,
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .await
        .expect("request create idempotency link inserts");
        transaction.commit().await.expect("draft commits");

        let transaction = migration
            .transaction()
            .await
            .expect("load draft transaction");
        require_owned_draft(&transaction, REQUEST_ENTITY, proposal_id, "submitter")
            .await
            .expect("owner can keep editing draft");
        assert_eq!(
            require_owned_draft(&transaction, REQUEST_ENTITY, proposal_id, "intruder")
                .await
                .expect_err("non-owner cannot edit draft"),
            MutationError::PreconditionFailed
        );
        let loaded = load(&transaction, REQUEST_ENTITY, proposal_id, true)
            .await
            .expect("draft loads");
        assert_eq!(loaded.state(), ProposalState::Draft);
        assert_eq!(loaded.owner().as_str(), "submitter");
        let header = load_header(&transaction, REQUEST_ENTITY, proposal_id, false)
            .await
            .expect("draft header loads without materializing a workflow");
        assert_eq!(header.owner_reference, "submitter");
        assert_eq!(header.state, "draft");
        assert_eq!(header.submission_version, 1);
        assert_eq!(header.workflow_revision, 1);
        assert!(!header.current_proposal_erased);
        assert!(!header.is_terminal());
        transaction.commit().await.expect("load draft commits");

        let submitted = workflow(proposal_id)
            .submit(
                context("submitter", 1),
                proposal(target_id, "site-a", "site-b"),
            )
            .expect("submit")
            .into_workflow();
        let transaction = migration.transaction().await.expect("submit transaction");
        save(&transaction, REQUEST_ENTITY, proposal_id, 1, &submitted)
            .await
            .expect("submitted workflow saves");
        save_targets(
            &transaction,
            REQUEST_ENTITY,
            proposal_id,
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
        let loaded = load(&transaction, REQUEST_ENTITY, proposal_id, true)
            .await
            .expect("submitted loads");
        assert_eq!(loaded.state(), ProposalState::Submitted);
        let targets = load_targets(&transaction, REQUEST_ENTITY, proposal_id, 1)
            .await
            .expect("target snapshots load");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].entity_id, TARGET_ENTITY);
        assert_eq!(targets[0].record_id, target_id);
        assert_eq!(targets[0].expected_revision, Some(3));
        transaction.commit().await.expect("submitted load commits");

        let cancelled = submitted
            .cancel(context("submitter", 2))
            .expect("owner cancels")
            .into_workflow();
        let transaction = migration.transaction().await.expect("cancel transaction");
        save(&transaction, REQUEST_ENTITY, proposal_id, 2, &cancelled)
            .await
            .expect("cancelled workflow saves");
        transaction.commit().await.expect("cancel commits");

        let transaction = migration
            .transaction()
            .await
            .expect("final load transaction");
        let loaded = load(&transaction, REQUEST_ENTITY, proposal_id, true)
            .await
            .expect("cancelled request loads");
        assert_eq!(loaded.state(), ProposalState::Cancelled);
        assert_eq!(loaded.current_version().get(), 1);
        assert!(loaded.current_proposal().is_some());
        transaction.commit().await.expect("final load commits");

        migration
            .execute(
                "UPDATE registry_internal.registry_proposal_state
                    SET detail_erased_at = transaction_timestamp()
                  WHERE action_id = $1 AND proposal_id = $2",
                &[&REQUEST_ENTITY, &proposal_id],
            )
            .await
            .expect("cancelled detail erasure marker saves");
        let transaction = migration
            .transaction()
            .await
            .expect("erased header transaction");
        let header = load_header(&transaction, REQUEST_ENTITY, proposal_id, false)
            .await
            .expect("erased draft header loads without restored workflow");
        assert_eq!(header.state, "cancelled");
        assert!(header.current_proposal_erased);
        assert!(header.is_terminal());
        transaction
            .commit()
            .await
            .expect("erased header load commits");

        let historical_proposals = migration
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_proposal_submissions
                 WHERE action_id = $1 AND proposal_id = $2",
                &[&REQUEST_ENTITY, &proposal_id],
            )
            .await
            .expect("proposal history count succeeds")
            .get::<_, i64>(0);
        let linked_receipts = migration
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_proposal_idempotency_links
                 WHERE action_id = $1 AND proposal_id = $2 AND submission_version = 1",
                &[&REQUEST_ENTITY, &proposal_id],
            )
            .await
            .expect("idempotency link count succeeds")
            .get::<_, i64>(0);
        assert_eq!(historical_proposals, 1);
        assert_eq!(linked_receipts, 1);

        migration_task.abort();
        database.cleanup().await;
    }

    #[tokio::test]
    async fn proposal_store_rejects_conflicting_immutable_rows_and_erased_targets() {
        let (database, mut migration, migration_task) = install_schema().await;
        let proposal_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();
        let submitted = workflow(proposal_id)
            .submit(
                context("submitter", 1),
                proposal(target_id, "site-a", "site-b"),
            )
            .expect("submit")
            .into_workflow();

        let transaction = migration.transaction().await.expect("draft transaction");
        initialize_draft(&transaction, REQUEST_ENTITY, proposal_id, "submitter")
            .await
            .expect("draft initializes");
        save(&transaction, REQUEST_ENTITY, proposal_id, 1, &submitted)
            .await
            .expect("submitted workflow saves");
        save_targets(
            &transaction,
            REQUEST_ENTITY,
            proposal_id,
            1,
            &[target_snapshot(target_id, "site-a", "site-b")],
        )
        .await
        .expect("target snapshots save");
        transaction.commit().await.expect("submit commits");

        migration
            .execute(
                "UPDATE registry_internal.registry_proposal_submissions
                 SET effect_digest = 'sha256:0000000000000000000000000000000000000000000000000000000000000000'
                 WHERE action_id = $1 AND proposal_id = $2 AND submission_version = 1",
                &[&REQUEST_ENTITY, &proposal_id],
            )
            .await
            .expect("test corrupts immutable proposal digest");
        let transaction = migration.transaction().await.expect("conflict transaction");
        assert_eq!(
            save(&transaction, REQUEST_ENTITY, proposal_id, 1, &submitted)
                .await
                .expect_err("proposal mismatch is refused"),
            MutationError::Conflict
        );
        transaction.rollback().await.expect("conflict rolls back");

        migration
            .execute(
                "UPDATE registry_internal.registry_proposal_submissions
                 SET effect_digest = $3
                 WHERE action_id = $1 AND proposal_id = $2 AND submission_version = 1",
                &[
                    &REQUEST_ENTITY,
                    &proposal_id,
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
                proposal_id,
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
                "UPDATE registry_internal.registry_proposal_targets
                 SET base_snapshot = NULL,
                     after_snapshot = NULL,
                     erased_at = transaction_timestamp()
                 WHERE action_id = $1 AND proposal_id = $2 AND submission_version = 1",
                &[&REQUEST_ENTITY, &proposal_id],
            )
            .await
            .expect("test erases stored target snapshot");
        let transaction = migration
            .transaction()
            .await
            .expect("erased target transaction");
        let refused = load_targets(&transaction, REQUEST_ENTITY, proposal_id, 1).await;
        assert!(matches!(refused, Err(MutationError::PreconditionFailed)));
        transaction
            .rollback()
            .await
            .expect("erased target load rolls back");

        migration_task.abort();
        database.cleanup().await;
    }
}
