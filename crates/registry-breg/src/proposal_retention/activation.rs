// SPDX-License-Identifier: Apache-2.0
//! Engine proofs for preserving the original Review closure at one activation.
use crate::model::{
    CompiledAction, CompiledActionExecution, CompiledProposalReview, CompiledRegistry,
};
use crate::mutation::MutationError;
use crate::package::{CompiledRegistryMigrationBaseline, VerifiedPackage};
use crate::postgres::{ExpectedRegistryIdentity, RuntimePool};
use chrono::{DateTime, Utc};
use registry_review_client::{
    ReviewCreateRequest, ReviewRequestAccepted, ReviewResult, SubmissionDigest,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio_postgres::GenericClient;
use uuid::Uuid;

const MAX_PROOFS: usize = 64;
const MAX_PROOF_BYTES: usize = 1_048_576;

/// Produced only by bounded authenticated closure verification. This value
/// cannot be deserialized from an operator flag or package-authored JSON.
pub struct ProposalActivationCompatibilityInventory {
    from: ExpectedRegistryIdentity,
    candidate_digest: String,
    observed: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    entries: Vec<Proof>,
}
impl ProposalActivationCompatibilityInventory {
    /// Empty inventories confer no compatibility and need not constrain an
    /// unrelated activation to the remote proof's freshness deadline.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
struct Proof {
    source: Retained,
    accepted: ReviewRequestAccepted,
    closure_digest: String,
    current_action_revision: String,
    current_system_grant_revision: Option<String>,
}
#[derive(Clone)]
struct Retained {
    action_id: String,
    id: Uuid,
    version: i64,
    digest: String,
    action_revision: String,
    system_grant_revision: Option<String>,
    authority: String,
    producer: String,
    key: String,
    request: ReviewCreateRequest,
    submission_digest: SubmissionDigest,
    policy: registry_review_client::PolicySelection,
    accepted: Option<ReviewRequestAccepted>,
    result: Option<ReviewResult>,
    proven_current_revision: Option<String>,
    frozen: crate::proposal_workflow::ProposalSnapshot,
    result_columns: Option<ResultColumns>,
}

#[derive(Clone)]
struct ResultColumns {
    authority: String,
    id: Uuid,
    status: String,
    completed: DateTime<Utc>,
    available: DateTime<Utc>,
}

/// Recheck the one immutable closure from frozen submission through queued
/// create, exact acceptance, and retained result. A valid packet digest alone
/// cannot authenticate a different Review requirement or source subject.
fn validate_retained_closure(registry_id: &str, row: &Retained) -> Result<(), MutationError> {
    let CompiledProposalReview::Required {
        authority,
        source,
        policy,
    } = row.frozen.review_requirement()
    else {
        return Err(MutationError::PreconditionFailed);
    };
    row.request
        .check()
        .map_err(|_| MutationError::PreconditionFailed)?;
    policy
        .check()
        .map_err(|_| MutationError::PreconditionFailed)?;
    let reference = format!(
        "breg:{registry_id}:{}:{}:{}",
        row.action_id, row.id, row.version
    );
    if authority != &row.authority
        || policy != &row.policy
        || row.request.policy != *policy
        || row.request.subject.source != *source
        || row.request.subject.subject_type != "proposal"
        || row.request.subject.id != row.id.to_string()
        || row.request.subject.version != row.version.to_string()
        || row.request.subject.digest.as_str() != row.digest
        || !matches!(&row.request.context,registry_review_client::ReviewContext::CurrentSource{binding} if binding.reference==reference)
    {
        return Err(MutationError::PreconditionFailed);
    }
    if let Some(accepted) = &row.accepted {
        accepted
            .subject
            .check()
            .map_err(|_| MutationError::PreconditionFailed)?;
        accepted
            .policy
            .check()
            .map_err(|_| MutationError::PreconditionFailed)?;
        if accepted.request_id.is_nil()
            || accepted.subject != row.request.subject
            || !policy.matches(&accepted.policy)
        {
            return Err(MutationError::PreconditionFailed);
        }
    }
    match (&row.result, &row.result_columns) {
        (None, None) => {}
        (Some(result), Some(columns)) => {
            let accepted = row
                .accepted
                .as_ref()
                .ok_or(MutationError::PreconditionFailed)?;
            result
                .check()
                .map_err(|_| MutationError::PreconditionFailed)?;
            let status =
                serde_json::to_value(result.status).map_err(|_| MutationError::Unavailable)?;
            if columns.authority != *authority
                || columns.id != result.result_id
                || Some(columns.status.as_str()) != status.as_str()
                || columns.completed.timestamp_micros() != result.completed_at.timestamp_micros()
                || columns.available.timestamp_micros() != result.available_until.timestamp_micros()
                || result.request_id != accepted.request_id
                || result.subject != accepted.subject
                || result.policy != accepted.policy
                || result.submission_digest != accepted.submission_digest
            {
                return Err(MutationError::PreconditionFailed);
            }
        }
        _ => return Err(MutationError::PreconditionFailed),
    }
    crate::review_store::stored_submission_digest_compatibility(
        &row.producer,
        registry_id,
        &row.request,
        &row.submission_digest,
        row.accepted.as_ref(),
    )?;
    Ok(())
}

fn grant_revision(action: &CompiledAction) -> Option<String> {
    let CompiledActionExecution::Proposal { proposal } = &action.execution else {
        return None;
    };
    let grant = proposal.system_apply_grant.as_ref()?;
    if grant.action_id != action.id || grant.action_revision != action.definition_revision {
        return None;
    }
    let bytes = registry_platform_canonical_json::canonicalize_json(&json!({"actionId":action.id,
        "actionRevision":action.definition_revision,"targets":grant.targets}))
    .ok()?;
    Some(format!(
        "sha256:{}",
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}

fn original_action(
    source: &Retained,
    baseline: &CompiledRegistryMigrationBaseline,
) -> Option<CompiledAction> {
    let mut previous = baseline
        .actions
        .actions
        .iter()
        .find(|action| action.id == source.action_id)?
        .clone();
    if previous.definition_revision != source.action_revision {
        // The exact active predecessor compatibility row authenticates the
        // retained older pin. Reconstruct only that original review binding;
        // recomputation below verifies its complete non-review closure.
        if source.proven_current_revision.as_deref() != Some(previous.definition_revision.as_str())
        {
            return None;
        }
        let CompiledActionExecution::Proposal { proposal } = &mut previous.execution else {
            return None;
        };
        let CompiledProposalReview::Required { policy, .. } = &mut proposal.review else {
            return None;
        };
        *policy = source.policy.clone();
        previous.definition_revision = source.action_revision.clone();
        if let Some(grant) = &mut proposal.system_apply_grant {
            grant.action_revision = source.action_revision.clone();
            grant.revision = source.system_grant_revision.clone()?;
        }
    }
    let CompiledActionExecution::Proposal { proposal } = &previous.execution else {
        return None;
    };
    if proposal
        .system_apply_grant
        .as_ref()
        .map(|grant| grant.revision.as_str())
        != source.system_grant_revision.as_deref()
        || grant_revision(&previous).as_deref() != source.system_grant_revision.as_deref()
        || crate::immediate_actions::definition_revision(&previous, &baseline.entities)
            != source.action_revision
    {
        return None;
    }
    Some(previous)
}

fn non_review_meaning_matches(
    previous: &CompiledAction,
    candidate: &CompiledAction,
    baseline: &CompiledRegistryMigrationBaseline,
) -> bool {
    if crate::immediate_actions::definition_revision(previous, &baseline.entities)
        != previous.definition_revision
    {
        return false;
    }
    let (
        CompiledActionExecution::Proposal { proposal: old },
        CompiledActionExecution::Proposal { proposal: new },
    ) = (&previous.execution, &candidate.execution)
    else {
        return false;
    };
    let (
        CompiledProposalReview::Required {
            authority: old_authority,
            source: old_source,
            policy: old_policy,
        },
        CompiledProposalReview::Required {
            authority: new_authority,
            source: new_source,
            policy: new_policy,
        },
    ) = (&old.review, &new.review)
    else {
        return false;
    };
    if old_authority != new_authority
        || old_source != new_source
        || old_policy == new_policy
        || old.system_apply_grant.as_ref().map(|grant| &grant.targets)
            != new.system_apply_grant.as_ref().map(|grant| &grant.targets)
    {
        return false;
    }
    let mut substituted = previous.clone();
    let CompiledActionExecution::Proposal { proposal } = &mut substituted.execution else {
        return false;
    };
    proposal.review = new.review.clone();
    // Substitute only the review policy. The predecessor record shapes remain
    // part of what was reviewed, including fields the frozen effects do not set.
    crate::immediate_actions::definition_revision(&substituted, &baseline.entities)
        == candidate.definition_revision
}

async fn retained(
    client: &impl GenericClient,
    current: &ExpectedRegistryIdentity,
    registry_id: &str,
    scope: Option<Uuid>,
) -> Result<Vec<Retained>, MutationError> {
    let activation =
        Uuid::parse_str(&current.activation_id).map_err(|_| MutationError::Unavailable)?;
    let rows=client.query("SELECT s.action_id,s.proposal_id,s.submission_version,s.action_revision,
        q.proposal_digest,q.authority,q.producer_id,q.idempotency_key,q.create_request,q.expected_submission_digest,
        q.expected_policy,q.accepted_binding,r.result,p.snapshot->>'systemGrantRevision',p.snapshot,c.current_action_revision,
        r.authority,r.result_id,r.status,r.completed_at,r.available_until,p.effect_digest,p.contract_fingerprint
        FROM registry_internal.registry_proposal_state s
        JOIN registry_internal.registry_proposal_submissions p USING(action_id,proposal_id,submission_version)
        JOIN registry_internal.registry_proposal_review_submissions q USING(action_id,proposal_id,submission_version)
        LEFT JOIN registry_internal.registry_proposal_review_results r USING(action_id,proposal_id,submission_version)
        LEFT JOIN registry_internal.registry_proposal_activation_compatibility c
          ON c.action_id=s.action_id AND c.proposal_id=s.proposal_id AND c.submission_version=s.submission_version
          AND c.effect_digest=q.proposal_digest AND c.frozen_action_revision=s.action_revision
          AND c.frozen_system_grant_revision IS NOT DISTINCT FROM p.snapshot->>'systemGrantRevision'
          AND c.expected_policy=q.expected_policy AND c.accepted_binding=q.accepted_binding
          AND c.candidate_package_digest=$1 AND c.activation_id=$2
        WHERE s.state='submitted' AND s.detail_erased_at IS NULL AND p.erased_at IS NULL AND NOT q.withdrawn AND q.state='accepted'
          AND ($3::uuid IS NULL OR s.proposal_id=$3)
        ORDER BY s.action_id,s.proposal_id LIMIT 65",&[&current.package_digest,&activation,&scope]).await.map_err(|_|MutationError::Unavailable)?;
    if rows.len() > MAX_PROOFS {
        return Err(MutationError::Unavailable);
    }
    rows.into_iter()
        .map(|row| {
            let frozen: crate::proposal_workflow::ProposalSnapshot =
                serde_json::from_value(row.get(14)).map_err(|_| MutationError::Unavailable)?;
            let key = crate::proposal_workflow::ProposalKey::new(
                crate::proposal_workflow::EntityId::new(row.get::<_, String>(0))
                    .map_err(|_| MutationError::Unavailable)?,
                crate::proposal_workflow::RecordId::new(row.get::<_, Uuid>(1).to_string())
                    .map_err(|_| MutationError::Unavailable)?,
            );
            frozen
                .verify_digest(&key)
                .map_err(|_| MutationError::PreconditionFailed)?;
            if i64::from(frozen.version().get()) != row.get::<_, i64>(2)
                || frozen.contract_fingerprint().as_str() != row.get::<_, String>(3)
                || frozen.effect_digest().as_str() != row.get::<_, String>(4)
                || frozen.system_grant_revision() != row.get::<_, Option<String>>(13).as_deref()
                || frozen.effect_digest().as_str() != row.get::<_, String>(21)
                || frozen.contract_fingerprint().as_str() != row.get::<_, String>(22)
            {
                return Err(MutationError::PreconditionFailed);
            }
            let retained = Retained {
                action_id: row.get(0),
                id: row.get(1),
                version: row.get(2),
                action_revision: row.get(3),
                digest: row.get(4),
                authority: row.get(5),
                producer: row.get(6),
                key: row.get(7),
                request: serde_json::from_value(row.get(8))
                    .map_err(|_| MutationError::Unavailable)?,
                submission_digest: SubmissionDigest::parse(&row.get::<_, String>(9))
                    .map_err(|_| MutationError::Unavailable)?,
                policy: serde_json::from_value(row.get(10))
                    .map_err(|_| MutationError::Unavailable)?,
                accepted: row
                    .get::<_, Option<Value>>(11)
                    .map(serde_json::from_value)
                    .transpose()
                    .map_err(|_| MutationError::Unavailable)?,
                result: row
                    .get::<_, Option<Value>>(12)
                    .map(serde_json::from_value)
                    .transpose()
                    .map_err(|_| MutationError::Unavailable)?,
                system_grant_revision: row.get(13),
                proven_current_revision: row.get(15),
                frozen,
                result_columns: row
                    .get::<_, Option<String>>(16)
                    .map(|authority| ResultColumns {
                        authority,
                        id: row.get(17),
                        status: row.get(18),
                        completed: row.get(19),
                        available: row.get(20),
                    }),
            };
            validate_retained_closure(registry_id, &retained)?;
            Ok(retained)
        })
        .collect()
}

/// The normal handoff worker must first settle queued work under its original
/// key. This proof sends no Proposal payload or key, and holds no database
/// connection during authenticated Request and Result reads.
pub async fn prepare_proposal_activation_compatibility(
    pool: &RuntimePool,
    current: &ExpectedRegistryIdentity,
    candidate: &VerifiedPackage,
    authorities: &crate::review_store::ReviewAuthorityRegistry,
    timeout: Duration,
) -> Result<ProposalActivationCompatibilityInventory, MutationError> {
    if timeout.is_zero() || timeout > Duration::from_secs(30) {
        return Err(MutationError::InvalidRequest);
    }
    let role_baseline;
    let baseline = if candidate.package_digest() == current.package_digest {
        role_baseline = CompiledRegistryMigrationBaseline::from_compiled(
            &current.package_digest,
            candidate.registry(),
        );
        &role_baseline
    } else {
        candidate
            .manifest()
            .migration_plan
            .prior_baseline
            .as_ref()
            .ok_or(MutationError::PreconditionFailed)?
    };
    if baseline.package_digest != current.package_digest
        || (candidate.package_digest() != current.package_digest
            && candidate
                .manifest()
                .migration_plan
                .from_package_digest
                .as_deref()
                != Some(current.package_digest.as_str()))
    {
        return Err(MutationError::PreconditionFailed);
    }
    let observed = Utc::now();
    let deadline = tokio::time::Instant::now() + timeout;
    let rows = {
        let client = tokio::time::timeout_at(deadline, pool.get())
            .await
            .map_err(|_| MutationError::Unavailable)?
            .map_err(|_| MutationError::Unavailable)?;
        let mut cancellation =
            crate::postgres::cancellation::QueryCancellationGuard::new(pool.clone(), client);
        let read = tokio::time::timeout_at(deadline, async {
            let guarded = crate::postgres::begin_registry_transaction(
                cancellation.client(),
                crate::postgres::RegistryLockKey::derive(&baseline.registry_id)
                    .map_err(|_| MutationError::Unavailable)?,
                Duration::from_secs(2),
                current,
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
            guarded
                .set_statement_budget(
                    deadline.saturating_duration_since(tokio::time::Instant::now()),
                )
                .await
                .map_err(|_| MutationError::Unavailable)?;
            let rows =
                retained(guarded.transaction(), current, &baseline.registry_id, None).await?;
            guarded
                .commit()
                .await
                .map_err(|_| MutationError::Unavailable)?;
            Ok::<_, MutationError>(rows)
        })
        .await;
        match read {
            Ok(rows) => {
                cancellation.disarm();
                rows?
            }
            Err(_) => {
                cancellation.cancel_and_discard().await;
                return Err(MutationError::Unavailable);
            }
        }
    };
    let entries = tokio::time::timeout_at(deadline, async {
        let mut entries = Vec::new();
        let mut bytes = 0usize;
        for source in rows {
            let Some(previous) = original_action(&source, baseline) else {
                continue;
            };
            let Some(active) = candidate
                .registry()
                .actions()
                .actions
                .iter()
                .find(|action| action.id == source.action_id)
            else {
                continue;
            };
            if !non_review_meaning_matches(&previous, active, baseline) {
                continue;
            }
            let CompiledActionExecution::Proposal { proposal: old } = &previous.execution else {
                continue;
            };
            let CompiledProposalReview::Required {
                authority, policy, ..
            } = &old.review
            else {
                continue;
            };
            if authority != &source.authority
                || policy != &source.policy
                || old
                    .system_apply_grant
                    .as_ref()
                    .map(|grant| grant.revision.as_str())
                    != source.system_grant_revision.as_deref()
            {
                return Err(MutationError::PreconditionFailed);
            }
            let Some(accepted) = source.accepted.clone() else {
                continue;
            };
            if !source.policy.matches(&accepted.policy)
                || accepted.subject != source.request.subject
                || accepted.submission_digest != source.submission_digest
            {
                return Err(MutationError::PreconditionFailed);
            }
            let closure = authorities
                .prove_accepted_closure(
                    &source.authority,
                    &source.producer,
                    &accepted,
                    source.result.as_ref(),
                )
                .await?;
            bytes = bytes
                .checked_add(closure.len())
                .ok_or(MutationError::Unavailable)?;
            if bytes > MAX_PROOF_BYTES {
                return Err(MutationError::Unavailable);
            }
            let CompiledActionExecution::Proposal { proposal: new } = &active.execution else {
                unreachable!();
            };
            entries.push(Proof {
                source,
                accepted,
                closure_digest: format!(
                    "sha256:{}",
                    Sha256::digest(closure)
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                ),
                current_action_revision: active.definition_revision.clone(),
                current_system_grant_revision: new
                    .system_apply_grant
                    .as_ref()
                    .map(|grant| grant.revision.clone()),
            });
        }
        Ok(entries)
    })
    .await
    .map_err(|_| MutationError::Unavailable)??;
    let valid_until = entries
        .iter()
        .filter_map(|proof| {
            proof
                .source
                .result
                .as_ref()
                .map(|result| result.available_until)
        })
        .fold(
            observed + chrono::Duration::seconds(30),
            |bound, expires| bound.min(expires),
        );
    if Utc::now() >= valid_until {
        return Err(MutationError::PreconditionFailed);
    }
    Ok(ProposalActivationCompatibilityInventory {
        from: current.clone(),
        candidate_digest: candidate.package_digest().into(),
        observed,
        valid_until,
        entries,
    })
}

pub(crate) async fn install_activation_compatibility(
    client: &impl GenericClient,
    candidate: &CompiledRegistry,
    current: &ExpectedRegistryIdentity,
    candidate_digest: &str,
    activation_id: &str,
    inventory: Option<&ProposalActivationCompatibilityInventory>,
) -> Result<(), MutationError> {
    let Some(inventory) = inventory else {
        return Ok(());
    };
    if inventory.from != *current
        || inventory.candidate_digest != candidate_digest
        || Utc::now() > inventory.valid_until
    {
        return Err(MutationError::PreconditionFailed);
    }
    let activation = Uuid::parse_str(activation_id).map_err(|_| MutationError::InvalidRequest)?;
    let now = retained(client, current, candidate.registry_id(), None).await?;
    for proof in &inventory.entries {
        let source = &proof.source;
        let Some(row) = now.iter().find(|row| {
            row.action_id == source.action_id
                && row.id == source.id
                && row.version == source.version
        }) else {
            continue;
        };
        if row.action_revision != source.action_revision
            || row.digest != source.digest
            || row.system_grant_revision != source.system_grant_revision
            || row.authority != source.authority
            || row.producer != source.producer
            || row.key != source.key
            || row.request != source.request
            || row.submission_digest != source.submission_digest
            || row.policy != source.policy
            || row.result != source.result
            || row.accepted.as_ref() != Some(&proof.accepted)
            || !candidate.actions().actions.iter().any(|action| {
                action.id == source.action_id
                    && action.definition_revision == proof.current_action_revision
            })
        {
            return Err(MutationError::PreconditionFailed);
        }
        let accepted =
            serde_json::to_value(&proof.accepted).map_err(|_| MutationError::Unavailable)?;
        // The normal durable handoff already persisted this exact acceptance.
        // Activation records compatibility without changing that work or lease.
        client.execute("INSERT INTO registry_internal.registry_proposal_activation_compatibility
            (action_id,proposal_id,submission_version,effect_digest,frozen_action_revision,frozen_system_grant_revision,
             current_action_revision,current_system_grant_revision,expected_policy,accepted_binding,closure_digest,
             from_package_digest,candidate_package_digest,activation_id,proof_observed_at,proof_valid_until)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
            &[&source.action_id,&source.id,&source.version,&source.digest,&source.action_revision,&source.system_grant_revision,
                &proof.current_action_revision,&proof.current_system_grant_revision,&json!(source.policy),&accepted,
                &proof.closure_digest,&current.package_digest,&candidate_digest,&activation,&inventory.observed,&inventory.valid_until])
            .await.map_err(|_|MutationError::Unavailable)?;
    }
    Ok(())
}

/// The successful activation transaction calls this again immediately before
/// commit, so SQL or lock waits cannot silently consume a proof's validity.
pub(crate) async fn verify_activation_compatibility_freshness(
    client: &impl GenericClient,
    inventory: Option<&ProposalActivationCompatibilityInventory>,
) -> Result<(), MutationError> {
    let Some(inventory) = inventory else {
        return Ok(());
    };
    let valid: bool = client
        .query_one("SELECT clock_timestamp() <= $1", &[&inventory.valid_until])
        .await
        .map_err(|_| MutationError::Unavailable)?
        .get(0);
    if valid {
        Ok(())
    } else {
        Err(MutationError::PreconditionFailed)
    }
}

pub(crate) async fn submission_is_compatible(
    client: &impl GenericClient,
    expected: &ExpectedRegistryIdentity,
    registry_id: &str,
    action: &CompiledAction,
    id: Uuid,
    frozen: &crate::proposal_workflow::ProposalSnapshot,
) -> Result<bool, MutationError> {
    if frozen.contract_fingerprint().as_str() == action.definition_revision {
        return Ok(true);
    }
    let rows = retained(client, expected, registry_id, Some(id)).await?;
    let Some(row) = rows
        .iter()
        .find(|row| row.action_id == action.id && row.id == id)
    else {
        return Ok(false);
    };
    if row.frozen != *frozen {
        return Err(MutationError::PreconditionFailed);
    }
    let current_grant = match &action.execution {
        CompiledActionExecution::Proposal { proposal } => proposal
            .system_apply_grant
            .as_ref()
            .map(|grant| grant.revision.as_str()),
        _ => return Ok(false),
    };
    let activation =
        Uuid::parse_str(&expected.activation_id).map_err(|_| MutationError::Unavailable)?;
    let version = i64::from(frozen.version().get());
    let row=client.query_opt("SELECT 1 FROM registry_internal.registry_proposal_activation_compatibility c
        JOIN registry_internal.registry_proposal_review_submissions q USING(action_id,proposal_id,submission_version)
        WHERE c.action_id=$1 AND c.proposal_id=$2 AND c.submission_version=$3 AND c.effect_digest=$4
          AND c.frozen_action_revision=$5 AND c.frozen_system_grant_revision IS NOT DISTINCT FROM $6
          AND c.current_action_revision=$7 AND c.current_system_grant_revision IS NOT DISTINCT FROM $8
          AND c.candidate_package_digest=$9 AND c.activation_id=$10
          AND c.expected_policy=q.expected_policy AND c.accepted_binding=q.accepted_binding AND NOT q.withdrawn",
        &[&action.id,&id,&version,&frozen.effect_digest().as_str(),&frozen.contract_fingerprint().as_str(),
            &frozen.system_grant_revision(),&action.definition_revision,&current_grant,&expected.package_digest,&activation])
        .await.map_err(|_|MutationError::Unavailable)?;
    Ok(row.is_some())
}
