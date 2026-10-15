// SPDX-License-Identifier: Apache-2.0

//! Revision-fenced durable Proposal transitions over one frozen neutral plan.
use super::*;
mod context_projection;
use crate::api::proposals::ProposalMutationInput;
use crate::model::{
    CompiledActionExecution, CompiledProposalReview, ProposalOperation, ProposalOwnership,
};
use crate::postgres::{
    begin_proposal_transaction, ProposalAuthority, ProposalAuthorityOperation, ProposalTargetPhase,
};
use crate::proposal_prepare::{self, ProposalTargetSnapshot};
use crate::proposal_store::{self, ProposalDocument};
use crate::proposal_workflow::{
    ApplicationId, ApplicationResultLink, EntityId, ObservedTarget, PreparedApplication,
    ProposalDigest, RecordId, RecordRevision, TrustedActorRef, TrustedTimestamp,
    TrustedTransitionContext,
};

// Both branches are short-lived admission results with bounded protocol data.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ProposalApplyPreflight {
    Receipt(MutationOutcome),
    Continue {
        review: Option<(
            String,
            registry_review_client::ReviewRequestAccepted,
            Option<Uuid>,
        )>,
        evidence: Vec<(
            crate::action_evidence_contracts::CompiledEvidenceCapability,
            crate::action_evidence_client::EvidenceSubjects,
        )>,
    },
}

fn check_current_proposal_grant(authority: &ProposalAuthority) -> Result<(), MutationError> {
    if authority
        .task_grant
        .as_ref()
        .is_some_and(|binding| !binding.is_current())
    {
        return Err(MutationError::PreconditionFailed);
    }
    Ok(())
}

fn validate_attachment_authority(
    action: &CompiledAction,
    authority: &ProposalAuthority,
    attachment: &crate::attachment::AttachmentMutation,
) -> Result<(), MutationError> {
    let CompiledActionExecution::Proposal { proposal } = &action.execution else {
        return Err(MutationError::InvalidRequest);
    };
    let grant = proposal
        .permissions
        .iter()
        .find(|grant| {
            grant.profile_id == authority.common.access_profile()
                && grant.operations.contains(&ProposalOperation::Edit)
        })
        .ok_or(MutationError::PreconditionFailed)?;
    let slot = proposal
        .attachments
        .get(&attachment.slot_id)
        .ok_or(MutationError::PreconditionFailed)?;
    if !grant.writable_attachments.contains(&slot.id) {
        return Err(MutationError::PreconditionFailed);
    }
    match (&attachment.content_type, &attachment.bytes) {
        (Some(content_type), Some(bytes))
            if !bytes.is_empty()
                && bytes.len() <= slot.maximum_bytes as usize
                && slot.content_types.contains(content_type) =>
        {
            Ok(())
        }
        (None, None) => Ok(()),
        _ => Err(MutationError::InvalidRequest),
    }
}

pub(crate) fn proposal_operation_name(operation: ProposalAuthorityOperation) -> &'static str {
    match operation {
        ProposalAuthorityOperation::Start => "start",
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::Get) => "get",
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::List) => "list",
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::Edit) => "edit",
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::Submit) => "submit",
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::Revise) => "revise",
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::Cancel) => "cancel",
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::Apply) => "apply",
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::Rebase) => "rebase",
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::Retry) => "retry",
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::GetReviewStatus) => {
            "get-review-status"
        }
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::GetReviewContext) => {
            "get-review-context"
        }
    }
}

pub(crate) fn proposal_http_method(input: &ProposalMutationInput<'_>) -> HttpMethod {
    match &input.attachment {
        Some(attachment) if attachment.bytes.is_some() => HttpMethod::Patch,
        Some(_) => HttpMethod::Delete,
        None => HttpMethod::Post,
    }
}

fn validate_recovery_actor(
    action: &CompiledAction,
    input: &ProposalMutationInput<'_>,
) -> Result<(), MutationError> {
    if matches!(
        input.operation,
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::Apply | ProposalOperation::Retry)
    ) && !input.authority.is_system()
    {
        let CompiledActionExecution::Proposal { proposal } = &action.execution else {
            return Err(MutationError::InvalidRequest);
        };
        if !crate::api::proposals::external_recovery_actor_allowed(
            &proposal.application,
            input.claims,
        ) {
            return Err(MutationError::PreconditionFailed);
        }
    }
    Ok(())
}

impl MutationTransaction {
    /// Carry a review result just recorded for one submission into the
    /// Proposal lifecycle, in the transaction that recorded it. A rejection
    /// of the current submission ends the Proposal in `rejected`; a
    /// changes-requested result leaves it submitted and revisable and records
    /// `review-returned`. Any other result, or a result for a submission that
    /// is no longer current, changes nothing. The caller holds the Proposal's
    /// state row lock.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn record_review_result(
        &self,
        tx: &Transaction<'_>,
        registry: &CompiledRegistry,
        authority: &str,
        action_id: &str,
        proposal_id: Uuid,
        version: i64,
        status: &str,
    ) -> Result<(), MutationError> {
        let transition = match status {
            "rejected" => "rejected",
            "changes-requested" => "review-returned",
            _ => return Ok(()),
        };
        let action = proposal_action(registry, action_id)?;
        let document =
            proposal_store::load_document(tx, proposal_id, proposal_store::DocumentLock::None)
                .await?;
        if document.header.state != "submitted" || document.header.submission_version != version {
            return Ok(());
        }
        let mut workflow = proposal_store::load(tx, action_id, proposal_id, false).await?;
        if transition == "rejected" {
            let previous = i64::try_from(workflow.workflow_revision().get())
                .map_err(|_| MutationError::Unavailable)?;
            let actor = self.proposal_actor(&format!("review-authority:{authority}"))?;
            workflow = workflow
                .reject(transition_context(&actor)?)
                .map_err(workflow_error)?
                .into_workflow();
            proposal_store::save(tx, action_id, proposal_id, previous, &workflow).await?;
        }
        let document =
            proposal_store::load_document(tx, proposal_id, proposal_store::DocumentLock::None)
                .await?;
        let reference = format!("/v1/proposals/{proposal_id}");
        let event_source = self.event_source();
        crate::proposal_events::insert_proposal_lifecycle_event(
            tx,
            registry,
            action,
            self.event_destinations.as_deref(),
            crate::proposal_events::ProposalLifecycleEvent {
                action_id,
                action_revision: &document.action_revision,
                proposal_id,
                version: workflow.current_version().get(),
                revision: workflow.workflow_revision().get(),
                from_state: "submitted",
                state: workflow.state().as_storage(),
                transition,
                effect_digest: workflow
                    .current_proposal()
                    .map(|proposal| proposal.effect_digest().as_str()),
                authority_kind: "review",
                system_grant_revision: None,
                turn: current_turn(tx, &document, workflow.current_proposal()).await?,
                reference: &reference,
                package_revision: &self.expected.activation_id,
                schema_fingerprint: &self.expected.schema_fingerprint,
                source: &event_source,
            },
        )
        .await?;
        Ok(())
    }

    pub(crate) async fn read_proposal_attachment(
        &self,
        attachment: &crate::attachment_store::StoredAttachment,
    ) -> Result<Vec<u8>, MutationError> {
        if attachment.backend_id != self.attachment_storage.binding_digest() {
            return Err(MutationError::Unavailable);
        }
        match &self.attachment_storage {
            crate::attachment_storage::AttachmentStorage::Database => {
                attachment.content.clone().ok_or(MutationError::Unavailable)
            }
            crate::attachment_storage::AttachmentStorage::S3(store) => store
                .get(&attachment.metadata.sha256, attachment.metadata.byte_size)
                .await
                .map_err(|_| MutationError::Unavailable),
        }
    }

    /// Commit staging before the configured primitive writes external bytes.
    /// Admission and exact replay are rechecked in the effect transaction.
    pub(crate) async fn stage_proposal_attachment(
        &self,
        client: &mut Client,
        registry: &CompiledRegistry,
        input: &ProposalMutationInput<'_>,
        deadline: tokio::time::Instant,
    ) -> Result<(), MutationError> {
        if matches!(
            &self.attachment_storage,
            crate::attachment_storage::AttachmentStorage::Database
        ) {
            return Ok(());
        }
        let Some(attachment) = &input.attachment else {
            return Ok(());
        };
        let Some(bytes) = &attachment.bytes else {
            return Ok(());
        };
        if input.operation != ProposalAuthorityOperation::Lifecycle(ProposalOperation::Edit) {
            return Err(MutationError::InvalidRequest);
        }
        let action = proposal_action(registry, input.action_id)?;
        validate_attachment_authority(action, input.authority, attachment)?;
        let id = input.proposal_id.ok_or(MutationError::InvalidRequest)?;
        let guarded = begin_proposal_transaction(
            client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            input.authority,
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
        guarded
            .set_statement_budget(deadline.saturating_duration_since(tokio::time::Instant::now()))
            .await
            .map_err(|_| MutationError::Unavailable)?;
        let tx = guarded.transaction();
        let document =
            proposal_store::load_document(tx, id, proposal_store::DocumentLock::Update).await?;
        self.authorize_proposal_document(tx, registry, &document, input.authority)
            .await?;
        let (binding, _) = self
            .proposal_document_binding(tx, registry, input, Some(&document))
            .await?;
        if lock_and_load(tx, &binding).await?.is_none() {
            if document.header.state != "draft"
                || document.blocked_reason.is_some()
                || document.header.current_proposal_erased
                || document.action_revision != action.definition_revision
                || input.expected_etag
                    != Some(self.proposal_etag(&document, input.authority)?.as_str())
            {
                return Err(MutationError::PreconditionFailed);
            }
            check_current_proposal_grant(input.authority)?;
            crate::attachment_store::stage_external(
                tx,
                &crate::attachment_store::content_hash(bytes),
                bytes.len() as u64,
                &self.attachment_storage.binding_digest(),
                &self.attachment_verification.binding_digest(),
            )
            .await?;
        }
        guarded
            .commit()
            .await
            .map_err(|_| MutationError::Unavailable)
    }
    pub(crate) async fn verify_proposal_attachment_binding(
        &self,
        tx: &Transaction<'_>,
    ) -> Result<(), MutationError> {
        crate::attachment_store::verify_backend_binding(
            tx,
            &self.attachment_storage.binding_digest(),
            &self.attachment_verification.binding_digest(),
        )
        .await
    }
    pub(crate) async fn begin_proposal_read_audit(
        &self,
        authority: &ProposalAuthority,
        correlation: &RequestCorrelation,
    ) -> Result<AuditRequest, MutationError> {
        let operation_id = format!(
            "proposals.{}.{}",
            authority.common.action_id(),
            proposal_operation_name(authority.operation)
        );
        Ok(crate::audit::begin_proposal_pre_io_audit(
            &self.audit,
            &self.expected,
            &authority.common,
            crate::audit::PreIoAudit {
                kind: PreIoAuditKind::Attempt,
                method: HttpMethod::Get,
                operation_id: &operation_id,
                target_record: None,
                refusal_reason: None,
                correlation,
            },
        )
        .await?)
    }

    pub(crate) async fn finish_proposal_read_audit(
        &self,
        authority: &ProposalAuthority,
        document: Option<&ProposalDocument>,
        count: usize,
        public_reason_served: bool,
        correlation: &RequestCorrelation,
    ) -> Result<(), MutationError> {
        let reference = document
            .map(|document| {
                record_reference(
                    self.audit.profile(),
                    &self.expected.database_id,
                    &document.proposal_id.to_string(),
                )
            })
            .transpose()?;
        let entry = crate::audit::terminal_entry(
            self.audit.profile(),
            TerminalAudit {
                grant: authority.common.grant_audit().cloned(),
                outcome: if count == 0 {
                    TerminalAuditOutcome::Empty
                } else {
                    TerminalAuditOutcome::Returned
                },
                method: HttpMethod::Get,
                operation_id: format!(
                    "proposals.{}.{}",
                    authority.common.action_id(),
                    proposal_operation_name(authority.operation)
                ),
                entity_id: None,
                action_id: Some(authority.common.action_id().to_owned()),
                package_revision: self.expected.activation_id.clone(),
                selected_access_profile: authority.common.access_profile().to_owned(),
                purpose_present: authority.common.purpose().is_some(),
                principal_reference: Some(self.proposal_actor(authority.common.principal())?),
                record_reference: reference,
                record_revision: document.map(|document| document.header.workflow_revision),
                result_count: Some(count),
                // A served public reason is recorded as a fixed marker; its
                // text never reaches the journal.
                field_set_reference: public_reason_served
                    .then(|| PUBLIC_REASON_REFERENCE.to_owned()),
                correlation: correlation.clone(),
            },
        )?;
        self.audit
            .append(entry)
            .await
            .map_err(|_| MutationError::Unavailable)?;
        check_current_proposal_grant(authority)
    }

    pub(crate) async fn begin_proposal_audit(
        &self,
        input: &ProposalMutationInput<'_>,
    ) -> Result<AuditRequest, MutationError> {
        let operation_id = format!(
            "proposals.{}.{}",
            input.action_id,
            proposal_operation_name(input.operation)
        );
        Ok(crate::audit::begin_proposal_pre_io_audit(
            &self.audit,
            &self.expected,
            &input.authority.common,
            crate::audit::PreIoAudit {
                kind: PreIoAuditKind::Attempt,
                method: proposal_http_method(input),
                operation_id: &operation_id,
                target_record: None,
                refusal_reason: None,
                correlation: input.correlation,
            },
        )
        .await?)
    }

    pub(crate) async fn record_proposal_refusal(
        &self,
        authority: &ProposalAuthority,
        method: HttpMethod,
        correlation: &RequestCorrelation,
    ) -> Result<(), MutationError> {
        let operation_id = format!(
            "proposals.{}.{}",
            authority.common.action_id(),
            proposal_operation_name(authority.operation)
        );
        crate::audit::record_proposal_pre_io_audit(
            &self.audit,
            &self.expected,
            &authority.common,
            crate::audit::PreIoAudit {
                kind: PreIoAuditKind::Refusal,
                method,
                operation_id: &operation_id,
                target_record: None,
                refusal_reason: None,
                correlation,
            },
        )
        .await?;
        Ok(())
    }

    fn proposal_binding(
        &self,
        registry: &CompiledRegistry,
        input: &ProposalMutationInput<'_>,
        stored_action_revision: Option<&str>,
    ) -> Result<crate::idempotency::ResolvedIdempotencyBinding, MutationError> {
        let action = proposal_action(registry, input.action_id)?;
        if input.authority.common.action_id() != action.id
            || input.operation != input.authority.operation
        {
            return Err(MutationError::InvalidRequest);
        }
        let mut route = match input.proposal_id {
            None => action.route.clone(),
            Some(id) => format!(
                "/v1/proposals/{id}/{}",
                proposal_operation_name(input.operation)
            ),
        };
        let method = if let Some(attachment) = &input.attachment {
            route = format!(
                "/v1/proposals/{}/attachments/{}",
                input.proposal_id.ok_or(MutationError::InvalidRequest)?,
                attachment.slot_id
            );
            if attachment.bytes.is_some() {
                HttpMethod::Patch
            } else {
                HttpMethod::Delete
            }
        } else {
            HttpMethod::Post
        };
        let CompiledActionExecution::Proposal { proposal: policy } = &action.execution else {
            return Err(MutationError::InvalidRequest);
        };
        let response_contract=policy.permissions.iter().find(|permission|
            permission.profile_id==input.authority.common.access_profile())
            .map(|permission|json!({"operations":permission.operations,
                "readableAttachments":permission.readable_attachments,"writableAttachments":permission.writable_attachments}));
        let digest=Sha256::digest(canonicalize_json(&json!({
            "proposalId":input.proposal_id,"operation":proposal_operation_name(input.operation),
            "ifMatch":input.expected_etag,"input":input.input,"submissionVersion":input.submission_version,
            "effectDigest":input.effect_digest,"reason":input.reason,
            "responseContract":response_contract,
            "attachment":input.attachment.as_ref().map(|attachment|json!({"slot":attachment.slot_id,
                "contentType":attachment.content_type,"sha256":attachment.sha256(),
                "byteSize":attachment.bytes.as_ref().map(Vec::len)})),
        })).map_err(|_|MutationError::InvalidRequest)?).into();
        Ok(resolve_action_binding(
            self.audit.profile(),
            &self.idempotency,
            &ActionIdempotencyBinding {
                key: input.idempotency_key,
                context: &input.authority.common,
                method,
                route: &route,
                // Unrelated activations do not change this Action's exact meaning.
                package_revision: stored_action_revision.unwrap_or(&action.definition_revision),
                action_contract_fingerprint: stored_action_revision
                    .unwrap_or(&action.definition_revision),
                target_authority: &input.authority.targets,
                result_effects: input.authority.common.result_effects(),
                canonical_request_digest: digest,
                answer_digest: None,
            },
        )?)
    }

    pub(crate) fn proposal_actor(&self, principal: &str) -> Result<String, MutationError> {
        let bytes = canonicalize_json(
            &json!({"issuer":self.idempotency.caller_issuer(),"principal":principal}),
        )
        .map_err(|_| MutationError::Unavailable)?;
        self.audit
            .profile()
            .key_hasher()
            .audit_reference_hash(
                "breg-proposal-actor-v1",
                &self.expected.database_id,
                std::str::from_utf8(&bytes).map_err(|_| MutationError::Unavailable)?,
            )
            .map_err(|_| MutationError::Unavailable)
    }

    /// Internal ownership admission survives audit-key rotation. Audit events
    /// continue to use the separately keyed, database-scoped actor reference.
    ///
    /// Never project this value in a response, event, export or log. It is
    /// an unkeyed hash of the database, issuer and subject, so anyone who
    /// knows the first two can confirm a subject by hashing guesses, and
    /// subject spaces such as national identifiers are small enough to
    /// enumerate. A projected owner commitment needs its own keyed derivation.
    pub(crate) fn proposal_owner_reference(&self, principal: &str) -> String {
        crate::idempotency::sha256_reference(
            "breg-proposal-owner-v1",
            &[
                &self.expected.database_id,
                self.idempotency.caller_issuer(),
                principal,
            ],
        )
    }

    async fn proposal_document_binding(
        &self,
        tx: &Transaction<'_>,
        registry: &CompiledRegistry,
        input: &ProposalMutationInput<'_>,
        document: Option<&ProposalDocument>,
    ) -> Result<(crate::idempotency::ResolvedIdempotencyBinding, String), MutationError> {
        let action = proposal_action(registry, input.action_id)?;
        let revision = document
            .map(|document| document.action_revision.as_str())
            .unwrap_or(&action.definition_revision);
        let initial = self.proposal_binding(registry, input, Some(revision))?;
        let Some(document) = document else {
            return Ok((initial, revision.to_owned()));
        };
        let rows=tx.query("SELECT DISTINCT action_revision FROM registry_internal.registry_proposal_idempotency_links
            WHERE key_reference=$1 AND action_id=$2 AND proposal_id=$3",
            &[&initial.key_reference,&document.action_id,&document.proposal_id]).await.map_err(map_database_error)?;
        if rows.len() > 1 {
            return Err(MutationError::Unavailable);
        }
        let revision = rows
            .first()
            .map(|row| row.get::<_, String>(0))
            .unwrap_or_else(|| revision.to_owned());
        Ok((
            self.proposal_binding(registry, input, Some(&revision))?,
            revision,
        ))
    }

    pub(crate) fn proposal_etag(
        &self,
        document: &ProposalDocument,
        authority: &ProposalAuthority,
    ) -> Result<String, MutationError> {
        let payload = json!({"action":document.action_id,"actionRevision":document.action_revision,
            "proposal":document.proposal_id,"version":document.header.submission_version,
            "revision":document.header.workflow_revision,"profile":authority.common.access_profile(),
            "principal":authority.common.principal(),"purpose":authority.common.purpose(),
            "targets":authority.targets.iter().map(|(entity,boundaries)|json!({"entity":entity,
                "boundaries":boundaries.iter().map(|b|json!({"field":b.field(),"operator":b.operator().as_str(),"values":b.values()})).collect::<Vec<_>>()
            })).collect::<Vec<_>>()});
        let canonical = canonicalize_json(&payload).map_err(|_| MutationError::Unavailable)?;
        let digest = self
            .audit
            .profile()
            .key_hasher()
            .audit_reference_hash(
                "breg-proposal-etag-v1",
                &document.action_revision,
                std::str::from_utf8(&canonical).map_err(|_| MutationError::Unavailable)?,
            )
            .map_err(|_| MutationError::Unavailable)?;
        Ok(format!("\"breg-proposal-{digest}\""))
    }

    pub(crate) async fn authorize_proposal_document(
        &self,
        tx: &Transaction<'_>,
        registry: &CompiledRegistry,
        document: &ProposalDocument,
        authority: &ProposalAuthority,
    ) -> Result<(), MutationError> {
        let action = proposal_action(registry, &document.action_id)?;
        if document.action_id != authority.common.action_id()
            || authority
                .proposal_scope
                .as_ref()
                .is_some_and(|scope| !scope.contains(&document.proposal_id))
            || (authority.ownership == Some(ProposalOwnership::Caller)
                && document.header.owner_reference
                    != self.proposal_owner_reference(authority.common.principal()))
        {
            return Err(MutationError::AuthorizationRefused);
        }
        for (entity_id, id) in &document.input_targets {
            let entity = registry
                .entities()
                .get(entity_id)
                .ok_or(MutationError::PreconditionFailed)?;
            let (phase, revision, digest) = if authority.is_system() {
                let workflow =
                    proposal_store::load(tx, &document.action_id, document.proposal_id, false)
                        .await?;
                let frozen = workflow
                    .current_proposal()
                    .ok_or(MutationError::PreconditionFailed)?;
                let revision = frozen
                    .effects()
                    .iter()
                    .filter(|effect| effect.target().entity_id().as_str() == entity_id)
                    .find(|effect| {
                        effect
                            .target()
                            .existing_record_id()
                            .is_some_and(|record| record.as_str() == id.to_string())
                    })
                    .and_then(|effect| {
                        effect
                            .target()
                            .base_revision()
                            .map(|revision| revision.get())
                    })
                    .or_else(|| {
                        frozen.application_preconditions().and_then(|guards| {
                            guards
                                .targets
                                .iter()
                                .find(|target| {
                                    target.entity_id == *entity_id
                                        && target.record_id.as_str() == id.to_string()
                                })
                                .map(|target| target.expected_revision)
                        })
                    });
                (
                    ProposalTargetPhase::Application,
                    revision,
                    authority.frozen_digest(),
                )
            } else {
                (ProposalTargetPhase::Inspection, None, None)
            };
            authority
                .install_target(
                    tx,
                    registry,
                    document.proposal_id,
                    u32::try_from(document.header.submission_version)
                        .map_err(|_| MutationError::Unavailable)?,
                    phase,
                    entity_id,
                    *id,
                    Operation::Get,
                    &proposal_read_fields(action, &entity.id),
                    revision,
                    digest,
                )
                .await
                .map_err(|_| MutationError::PreconditionFailed)?;
            let lock = !matches!(
                authority.operation,
                ProposalAuthorityOperation::Lifecycle(
                    ProposalOperation::Get
                        | ProposalOperation::List
                        | ProposalOperation::GetReviewContext
                        | ProposalOperation::GetReviewStatus
                )
            );
            let row = load_proposal_row(tx, entity, *id, lock).await?;
            if !authority
                .authorizes_snapshot(entity, *id, &row.data)
                .map_err(|_| MutationError::PreconditionFailed)?
            {
                return Err(MutationError::PreconditionFailed);
            }
        }
        if document.header.state == "submitted" && !document.header.current_proposal_erased {
            let workflow =
                proposal_store::load(tx, &document.action_id, document.proposal_id, false).await?;
            let frozen = workflow
                .current_proposal()
                .ok_or(MutationError::PreconditionFailed)?;
            let expected = frozen
                .input_targets()
                .iter()
                .map(|target| {
                    Ok((
                        target.record_type.clone(),
                        Uuid::parse_str(target.record_id.as_str())
                            .map_err(|_| MutationError::PreconditionFailed)?,
                    ))
                })
                .collect::<Result<Vec<_>, MutationError>>()?;
            if expected != document.input_targets
                || document.input.as_ref() != Some(frozen.inputs())
            {
                return Err(MutationError::PreconditionFailed);
            }
            let targets = proposal_store::load_targets(
                tx,
                &document.action_id,
                document.proposal_id,
                document.header.submission_version,
            )
            .await?;
            for target in targets
                .iter()
                .filter(|target| target.operation == Operation::Create)
            {
                let entity = registry
                    .entities()
                    .get(&target.entity_id)
                    .ok_or(MutationError::PreconditionFailed)?;
                if !authority
                    .authorizes_snapshot(entity, target.record_id, &target.after)
                    .map_err(|_| MutationError::PreconditionFailed)?
                {
                    return Err(MutationError::PreconditionFailed);
                }
            }
        }
        if document.header.state == "applied" {
            let rows=tx.query("SELECT target_entity_id,target_record_id FROM registry_internal.registry_proposal_results
                WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3 ORDER BY target_entity_id,target_record_id",
                &[&document.action_id,&document.proposal_id,&document.header.submission_version])
                .await.map_err(map_database_error)?;
            for row in rows {
                let entity_id: String = row.get(0);
                let id: Uuid = row.get(1);
                let entity = registry
                    .entities()
                    .get(&entity_id)
                    .ok_or(MutationError::PreconditionFailed)?;
                authority
                    .install_target(
                        tx,
                        registry,
                        document.proposal_id,
                        u32::try_from(document.header.submission_version)
                            .map_err(|_| MutationError::Unavailable)?,
                        ProposalTargetPhase::Inspection,
                        &entity_id,
                        id,
                        Operation::Get,
                        &BTreeSet::new(),
                        None,
                        None,
                    )
                    .await
                    .map_err(|_| MutationError::PreconditionFailed)?;
                let current = load_proposal_row(tx, entity, id, false).await?;
                if !authority
                    .authorizes_snapshot(entity, id, &current.data)
                    .map_err(|_| MutationError::PreconditionFailed)?
                {
                    return Err(MutationError::PreconditionFailed);
                }
            }
        }
        Ok(())
    }

    pub(crate) async fn preflight_proposal_apply(
        &self,
        client: &mut Client,
        registry: &CompiledRegistry,
        input: &ProposalMutationInput<'_>,
    ) -> Result<ProposalApplyPreflight, MutationError> {
        let action = proposal_action(registry, input.action_id)?;
        validate_recovery_actor(action, input)?;
        let id = input.proposal_id.ok_or(MutationError::InvalidRequest)?;
        let guarded = begin_proposal_transaction(
            client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            input.authority,
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
        let tx = guarded.transaction();
        let document =
            proposal_store::load_document(tx, id, proposal_store::DocumentLock::None).await?;
        self.authorize_proposal_document(tx, registry, &document, input.authority)
            .await?;
        let (binding, _) = self
            .proposal_document_binding(tx, registry, input, Some(&document))
            .await?;
        if let Some(stored) = lock_and_load(tx, &binding).await? {
            let StoredResultMetadata::Proposal { .. } = stored.metadata else {
                return Err(MutationError::Unavailable);
            };
            let entry = self.proposal_terminal(input, &binding, &document, true, 0)?;
            check_current_proposal_grant(input.authority)?;
            guarded
                .commit()
                .await
                .map_err(|_| MutationError::Unavailable)?;
            self.audit
                .append(entry)
                .await
                .map_err(|_| MutationError::Unavailable)?;
            check_current_proposal_grant(input.authority)?;
            return Ok(ProposalApplyPreflight::Receipt(MutationOutcome {
                response: stored.response,
                replayed: true,
            }));
        }
        let action = proposal_action(registry, input.action_id)?;
        if document.blocked_reason.is_some() || document.header.state != "submitted" {
            return Err(MutationError::PreconditionFailed);
        }
        let workflow = proposal_store::load(tx, &document.action_id, id, false).await?;
        let proposal = workflow
            .current_proposal()
            .ok_or(MutationError::PreconditionFailed)?;
        if !crate::proposal_retention::submission_is_compatible(
            tx,
            &self.expected,
            registry.registry_id(),
            action,
            id,
            proposal,
        )
        .await?
        {
            return Err(MutationError::PreconditionFailed);
        }
        verify_apply_binding(input, proposal)?;
        if !input.authority.is_system()
            && !crate::api::proposals::external_recovery_actor_allowed(
                proposal.application_policy(),
                input.claims,
            )
        {
            return Err(MutationError::PreconditionFailed);
        }
        let accepted = match proposal.review_requirement() {
            CompiledProposalReview::None => None,
            CompiledProposalReview::Required {
                authority, policy, ..
            } => {
                let (stored_authority, accepted) = crate::review_store::load_accepted_binding(
                    tx,
                    &document.action_id,
                    id,
                    document.header.submission_version,
                    proposal.effect_digest().as_str(),
                )
                .await?;
                if *authority != stored_authority || !policy.matches(&accepted.policy) {
                    return Err(MutationError::PreconditionFailed);
                }
                let result = tx
                    .query_opt(
                        "SELECT result_id FROM registry_internal.registry_proposal_review_results
                    WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3",
                        &[
                            &document.action_id,
                            &id,
                            &document.header.submission_version,
                        ],
                    )
                    .await
                    .map_err(map_database_error)?;
                Some((stored_authority, accepted, result.map(|row| row.get(0))))
            }
        };
        guarded
            .commit()
            .await
            .map_err(|_| MutationError::Unavailable)?;
        let evidence = if let Some(guards) = proposal.application_preconditions() {
            let records = guards
                .targets
                .iter()
                .map(|target| {
                    (
                        target.id.clone(),
                        target.values.clone().into_iter().collect(),
                    )
                })
                .collect();
            crate::commit_evidence::requests(&guards.evidence, proposal.inputs(), &records)?
        } else {
            vec![]
        };
        Ok(ProposalApplyPreflight::Continue {
            review: accepted,
            evidence,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn execute_proposal(
        &self,
        client: &mut Client,
        registry: &CompiledRegistry,
        input: ProposalMutationInput<'_>,
        review_evidence: Option<&crate::review_integration::AcceptedReviewEvidence>,
        commit_evidence: &[crate::action_evidence_client::VerifiedAcquisition],
        deadline: tokio::time::Instant,
    ) -> Result<MutationOutcome, MutationError> {
        let action = proposal_action(registry, input.action_id)?;
        validate_recovery_actor(action, &input)?;
        let guarded = begin_proposal_transaction(
            client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            input.authority,
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
        guarded
            .set_statement_budget(deadline.saturating_duration_since(tokio::time::Instant::now()))
            .await
            .map_err(|_| MutationError::Unavailable)?;
        let tx = guarded.transaction();
        let existing = if let Some(id) = input.proposal_id {
            let document =
                proposal_store::load_document(tx, id, proposal_store::DocumentLock::Update).await?;
            self.authorize_proposal_document(tx, registry, &document, input.authority)
                .await?;
            Some(document)
        } else {
            None
        };
        let (binding, binding_revision) = self
            .proposal_document_binding(tx, registry, &input, existing.as_ref())
            .await?;
        if let Some(stored) = lock_and_load(tx, &binding).await? {
            let StoredResultMetadata::Proposal { .. } = stored.metadata else {
                return Err(MutationError::Unavailable);
            };
            let document = if let Some(document) = existing {
                document
            } else {
                let response: Value = serde_json::from_slice(stored.response.body())
                    .map_err(|_| MutationError::Unavailable)?;
                let id = response
                    .get("id")
                    .and_then(Value::as_str)
                    .and_then(|id| Uuid::parse_str(id).ok())
                    .ok_or(MutationError::Unavailable)?;
                let document =
                    proposal_store::load_document(tx, id, proposal_store::DocumentLock::None)
                        .await?;
                self.authorize_start_inputs(tx, registry, action, &document, input.authority)
                    .await?;
                document
            };
            let entry = self.proposal_terminal(&input, &binding, &document, true, 0)?;
            check_current_proposal_grant(input.authority)?;
            guarded
                .commit()
                .await
                .map_err(|_| MutationError::Unavailable)?;
            self.audit
                .append(entry)
                .await
                .map_err(|_| MutationError::Unavailable)?;
            check_current_proposal_grant(input.authority)?;
            return Ok(MutationOutcome {
                response: stored.response,
                replayed: true,
            });
        }
        let actor = self.proposal_actor(input.authority.common.principal())?;
        let mut result_count = 0u16;
        let (id, from_state, transition) = match input.operation {
            ProposalAuthorityOperation::Start => {
                if existing.is_some() {
                    return Err(MutationError::InvalidRequest);
                }
                let values = validate_proposal_input(
                    action,
                    input.input.as_ref().ok_or(MutationError::InvalidRequest)?,
                )?;
                let id = Uuid::new_v4();
                proposal_store::initialize_draft(
                    tx,
                    &action.id,
                    id,
                    &self.proposal_owner_reference(input.authority.common.principal()),
                )
                .await?;
                proposal_store::save_draft_input(
                    tx,
                    &action.id,
                    id,
                    &action.definition_revision,
                    action.display.label.as_deref(),
                    &values,
                )
                .await?;
                let targets = input_targets(action, &values)?;
                proposal_store::save_input_targets(tx, &action.id, id, &targets).await?;
                let document =
                    proposal_store::load_document(tx, id, proposal_store::DocumentLock::None)
                        .await?;
                self.authorize_start_inputs(tx, registry, action, &document, input.authority)
                    .await?;
                (id, "none".to_owned(), "started")
            }
            ProposalAuthorityOperation::Lifecycle(operation) => {
                let document = existing.as_ref().ok_or(MutationError::InvalidRequest)?;
                let id = document.proposal_id;
                if input.expected_etag
                    != Some(self.proposal_etag(document, input.authority)?.as_str())
                {
                    return Err(MutationError::PreconditionFailed);
                }
                let workflow = proposal_store::load(tx, &action.id, id, false).await?;
                if !matches!(
                    operation,
                    ProposalOperation::Cancel | ProposalOperation::Rebase
                ) {
                    let compatible = if matches!(
                        operation,
                        ProposalOperation::Apply | ProposalOperation::Retry
                    ) {
                        if let Some(frozen) = workflow.current_proposal() {
                            crate::proposal_retention::submission_is_compatible(
                                tx,
                                &self.expected,
                                registry.registry_id(),
                                action,
                                id,
                                frozen,
                            )
                            .await?
                        } else {
                            false
                        }
                    } else {
                        document.action_revision == action.definition_revision
                    };
                    if document.blocked_reason.is_some() || !compatible {
                        return Err(MutationError::PreconditionFailed);
                    }
                }
                let previous = i64::try_from(workflow.workflow_revision().get())
                    .map_err(|_| MutationError::Unavailable)?;
                let context = transition_context(&actor)?;
                let (workflow, transition) = match operation {
                    ProposalOperation::Submit => {
                        let values = document
                            .input
                            .as_ref()
                            .ok_or(MutationError::PreconditionFailed)?;
                        let values = validate_proposal_input(action, values)?;
                        let candidate = crate::action_handler::evaluate_plan_detailed(
                            action,
                            &values,
                            deadline.into_std(),
                        )
                        .map_err(|diagnostic| {
                            MutationError::ActionHandlerFailure(diagnostic.kind)
                        })?;
                        let effects = match candidate {
                            crate::action_handler::ActionHandlerOutcome::Effects(effects) => {
                                effects
                            }
                            crate::action_handler::ActionHandlerOutcome::Refusal(mut refusal) => {
                                refusal.field = refusal.field.and_then(|id| {
                                    action
                                        .inputs
                                        .iter()
                                        .find(|input| input.id == id)
                                        .map(|input| input.api_name.clone())
                                });
                                return Err(MutationError::ActionRefusal(refusal));
                            }
                        };
                        let creates = effects
                            .iter()
                            .filter(|effect| effect.operation == Operation::Create)
                            .map(|effect| (effect.id.clone(), Uuid::new_v4()))
                            .collect();
                        let resolved = proposal_prepare::resolve_targets(
                            registry, action, &values, effects, &creates,
                        )?;
                        let (bases, guards) = self
                            .load_submission_bases(
                                tx,
                                registry,
                                action,
                                document,
                                input.authority,
                                &resolved,
                                &values,
                            )
                            .await?;
                        let mut prepared = proposal_prepare::prepare(
                            registry,
                            action,
                            &values,
                            previous,
                            &self.expected.activation_id,
                            &resolved,
                            bases,
                            guards,
                        )?;
                        let CompiledActionExecution::Proposal { proposal: policy } =
                            &action.execution
                        else {
                            return Err(MutationError::InvalidRequest);
                        };
                        self.verify_proposal_attachment_binding(tx).await?;
                        let attachments = crate::attachment_store::manifest(
                            tx,
                            &action.id,
                            id,
                            document.header.submission_version,
                        )
                        .await?;
                        if policy.attachments.iter().any(|(slot, definition)| {
                            definition.required && !attachments.contains_key(slot)
                        }) || attachments
                            .keys()
                            .any(|slot| !policy.attachments.contains_key(slot))
                        {
                            return Err(MutationError::PreconditionFailed);
                        }
                        prepared.proposal = prepared
                            .proposal
                            .with_attachments(attachments)
                            .map_err(workflow_error)?;
                        for target in &prepared.targets {
                            let entity = registry
                                .entities()
                                .get(&target.entity_id)
                                .ok_or(MutationError::InvalidRequest)?;
                            if !input
                                .authority
                                .authorizes_snapshot(entity, target.record_id, &target.after)
                                .map_err(|_| MutationError::PreconditionFailed)?
                            {
                                return Err(MutationError::PreconditionFailed);
                            }
                        }
                        let workflow = workflow
                            .submit(context, prepared.proposal)
                            .map_err(workflow_error)?
                            .into_workflow();
                        proposal_store::save(tx, &action.id, id, previous, &workflow).await?;
                        proposal_store::save_targets(
                            tx,
                            &action.id,
                            id,
                            i64::from(workflow.current_version().get()),
                            &prepared.targets,
                        )
                        .await?;
                        if let Some(binding) = &input.authority.task_grant {
                            proposal_store::save_task_authority(
                                tx,
                                &action.id,
                                id,
                                i64::from(workflow.current_version().get()),
                                binding,
                            )
                            .await?;
                        }
                        let frozen = workflow
                            .current_proposal()
                            .ok_or(MutationError::Unavailable)?;
                        if matches!(
                            frozen.review_requirement(),
                            CompiledProposalReview::Required { .. }
                        ) {
                            let authorities = self
                                .review_authorities
                                .as_ref()
                                .ok_or(MutationError::Unavailable)?;
                            crate::review_store::enqueue_submission(
                                tx,
                                registry,
                                &action.id,
                                id,
                                frozen,
                                &actor,
                                input.human_identity,
                                authorities,
                            )
                            .await?;
                        } else if frozen.application_policy().is_automatic() {
                            crate::review_store::enqueue_automatic_application(
                                tx, &action.id, id, frozen,
                            )
                            .await?;
                        }
                        (workflow, "submitted")
                    }
                    ProposalOperation::Edit
                    | ProposalOperation::Revise
                    | ProposalOperation::Rebase => {
                        if let Some(attachment) = &input.attachment {
                            if operation != ProposalOperation::Edit {
                                return Err(MutationError::InvalidRequest);
                            }
                            validate_attachment_authority(action, input.authority, attachment)?;
                        }
                        let values = validate_proposal_input(
                            action,
                            input
                                .input
                                .as_ref()
                                .or(document.input.as_ref())
                                .ok_or(MutationError::InvalidRequest)?,
                        )?;
                        let workflow = match operation {
                            ProposalOperation::Edit => workflow.edit_draft(context),
                            ProposalOperation::Revise => workflow.revise(context),
                            ProposalOperation::Rebase => workflow.rebase(context),
                            _ => unreachable!(),
                        }
                        .map_err(workflow_error)?
                        .into_workflow();
                        if document.header.state == "submitted" {
                            crate::review_store::schedule_cancellation(
                                tx,
                                &action.id,
                                id,
                                document.header.submission_version,
                            )
                            .await?;
                            crate::review_store::close_application_jobs(tx, &action.id, id).await?;
                        }
                        proposal_store::save(tx, &action.id, id, previous, &workflow).await?;
                        if operation == ProposalOperation::Rebase {
                            let start = input
                                .rebase_start_authority
                                .ok_or(MutationError::PreconditionFailed)?;
                            if start.operation != ProposalAuthorityOperation::Start
                                || start.common.action_id() != action.id
                            {
                                return Err(MutationError::PreconditionFailed);
                            }
                            check_current_proposal_grant(start)?;
                            proposal_store::clear_rebase_block(tx, &action.id, id).await?;
                        }
                        proposal_store::save_draft_input(
                            tx,
                            &action.id,
                            id,
                            &action.definition_revision,
                            action.display.label.as_deref(),
                            &values,
                        )
                        .await?;
                        proposal_store::save_input_targets(
                            tx,
                            &action.id,
                            id,
                            &input_targets(action, &values)?,
                        )
                        .await?;
                        let replacement = proposal_store::load_document(
                            tx,
                            id,
                            proposal_store::DocumentLock::None,
                        )
                        .await?;
                        self.authorize_start_inputs(
                            tx,
                            registry,
                            action,
                            &replacement,
                            input.rebase_start_authority.unwrap_or(input.authority),
                        )
                        .await?;
                        if let Some(attachment) = &input.attachment {
                            if let (Some(content_type), Some(bytes)) =
                                (&attachment.content_type, &attachment.bytes)
                            {
                                if let crate::attachment_storage::AttachmentStorage::S3(store) =
                                    &self.attachment_storage
                                {
                                    let hash = crate::attachment_store::content_hash(bytes);
                                    crate::attachment_store::lock_for_put(
                                        tx,
                                        &action.id,
                                        id,
                                        document.header.submission_version,
                                        &attachment.slot_id,
                                        &hash,
                                    )
                                    .await?;
                                    crate::attachment_store::require_backend(
                                        tx,
                                        &hash,
                                        &self.attachment_storage.binding_digest(),
                                        bytes.len() as u64,
                                    )
                                    .await?;
                                    check_current_proposal_grant(input.authority)?;
                                    store
                                        .put(&hash, bytes.clone())
                                        .await
                                        .map_err(|_| MutationError::Unavailable)?;
                                }
                                crate::attachment_store::put(
                                    tx,
                                    &action.id,
                                    id,
                                    document.header.submission_version,
                                    &attachment.slot_id,
                                    content_type,
                                    bytes,
                                    &actor,
                                    &self.attachment_storage.binding_digest(),
                                    &self.attachment_verification.binding_digest(),
                                )
                                .await?;
                            } else {
                                crate::attachment_store::remove(
                                    tx,
                                    &action.id,
                                    id,
                                    document.header.submission_version,
                                    &attachment.slot_id,
                                )
                                .await?;
                            }
                        }
                        if workflow.current_version().get()
                            != u32::try_from(document.header.submission_version)
                                .map_err(|_| MutationError::Unavailable)?
                        {
                            crate::attachment_store::carry_forward(
                                tx,
                                &action.id,
                                id,
                                document.header.submission_version,
                                i64::from(workflow.current_version().get()),
                            )
                            .await?;
                        }
                        (
                            workflow,
                            match operation {
                                ProposalOperation::Edit => "edited",
                                ProposalOperation::Rebase => "rebased",
                                _ => "revised",
                            },
                        )
                    }
                    ProposalOperation::Retry => {
                        let frozen = workflow
                            .current_proposal()
                            .ok_or(MutationError::PreconditionFailed)?;
                        if !crate::api::proposals::external_recovery_actor_allowed(
                            frozen.application_policy(),
                            input.claims,
                        ) {
                            return Err(MutationError::PreconditionFailed);
                        }
                        crate::review_store::retry_submission_work(tx, &action.id, id, frozen)
                            .await?;
                        let workflow = workflow
                            .retry(context)
                            .map_err(workflow_error)?
                            .into_workflow();
                        proposal_store::save(tx, &action.id, id, previous, &workflow).await?;
                        (workflow, "retried")
                    }
                    ProposalOperation::Cancel => {
                        let workflow = workflow
                            .cancel(context)
                            .map_err(workflow_error)?
                            .into_workflow();
                        crate::review_store::schedule_cancellation(
                            tx,
                            &action.id,
                            id,
                            document.header.submission_version,
                        )
                        .await?;
                        crate::review_store::close_application_jobs(tx, &action.id, id).await?;
                        proposal_store::save(tx, &action.id, id, previous, &workflow).await?;
                        (workflow, "cancelled")
                    }
                    ProposalOperation::Apply => {
                        let frozen = workflow
                            .current_proposal()
                            .ok_or(MutationError::PreconditionFailed)?;
                        verify_apply_binding(&input, frozen)?;
                        if !input.authority.is_system()
                            && !crate::api::proposals::external_recovery_actor_allowed(
                                frozen.application_policy(),
                                input.claims,
                            )
                        {
                            return Err(MutationError::PreconditionFailed);
                        }
                        verify_proposal_evidence(action, frozen, commit_evidence)?;
                        self.verify_proposal_attachment_binding(tx).await?;
                        let manifest = crate::attachment_store::manifest(
                            tx,
                            &action.id,
                            id,
                            document.header.submission_version,
                        )
                        .await?;
                        if &manifest != frozen.attachments() {
                            return Err(MutationError::PreconditionFailed);
                        }
                        self.verify_executor_lease(tx, &input, frozen).await?;
                        let targets = proposal_store::load_targets(
                            tx,
                            &action.id,
                            id,
                            document.header.submission_version,
                        )
                        .await?;
                        proposal_prepare::validate_frozen_targets(frozen, &targets)?;
                        self.lock_frozen_scope(
                            tx,
                            registry,
                            action,
                            document,
                            input.authority,
                            frozen,
                        )
                        .await?;
                        self.verify_frozen_guards(
                            tx,
                            registry,
                            action,
                            document,
                            input.authority,
                            frozen,
                        )
                        .await?;
                        let application_id = Uuid::new_v4();
                        let (observed, links) = self
                            .apply_frozen_proposal(
                                tx,
                                registry,
                                document,
                                input.authority,
                                frozen,
                                &targets,
                                &binding,
                                application_id,
                            )
                            .await?;
                        result_count =
                            u16::try_from(links.len()).map_err(|_| MutationError::Unavailable)?;
                        let application = PreparedApplication::new(
                            ApplicationId::new(application_id.to_string())
                                .map_err(workflow_error)?,
                            links,
                        )
                        .map_err(workflow_error)?;
                        let applied_contract = workflow
                            .current_proposal()
                            .ok_or(MutationError::PreconditionFailed)?
                            .contract_fingerprint()
                            .clone();
                        let workflow = workflow
                            .apply(
                                transition_context(&actor)?,
                                crate::proposal_workflow::SubmissionVersion::new(
                                    input
                                        .submission_version
                                        .ok_or(MutationError::InvalidRequest)?,
                                )
                                .map_err(workflow_error)?,
                                &ProposalDigest::new(
                                    input.effect_digest.ok_or(MutationError::InvalidRequest)?,
                                )
                                .map_err(workflow_error)?,
                                &applied_contract,
                                review_evidence,
                                observed,
                                application,
                                input.reason.map(str::to_owned),
                            )
                            .map_err(workflow_error)?
                            .into_workflow();
                        proposal_store::save(tx, &action.id, id, previous, &workflow).await?;
                        proposal_store::retain_evidence(tx, application_id, commit_evidence)
                            .await?;
                        (workflow, "applied")
                    }
                    _ => return Err(MutationError::InvalidRequest),
                };
                let _ = workflow;
                (id, document.header.state.clone(), transition)
            }
        };
        let document =
            proposal_store::load_document(tx, id, proposal_store::DocumentLock::None).await?;
        let workflow = proposal_store::load(tx, &action.id, id, false).await?;
        // A Proposal event names its public resource, as Scheduling names an
        // appointment; record hooks keep their hashed record reference.
        let reference = format!("/v1/proposals/{id}");
        let event_source = self.event_source();
        crate::proposal_events::insert_proposal_lifecycle_event(
            tx,
            registry,
            action,
            self.event_destinations.as_deref(),
            crate::proposal_events::ProposalLifecycleEvent {
                action_id: &action.id,
                action_revision: &document.action_revision,
                proposal_id: id,
                version: workflow.current_version().get(),
                revision: workflow.workflow_revision().get(),
                from_state: &from_state,
                state: workflow.state().as_storage(),
                transition,
                effect_digest: workflow
                    .current_proposal()
                    .map(|proposal| proposal.effect_digest().as_str()),
                authority_kind: if input.authority.is_system() {
                    "system"
                } else {
                    "caller"
                },
                system_grant_revision: input.authority.system_grant_revision(),
                turn: current_turn(tx, &document, workflow.current_proposal()).await?,
                reference: &reference,
                package_revision: &self.expected.activation_id,
                schema_fingerprint: &self.expected.schema_fingerprint,
                source: &event_source,
            },
        )
        .await?;
        let value = self
            .proposal_public_value(tx, registry, &document, input.claims, input.authority)
            .await?;
        let mut headers = BTreeMap::from([
            (
                PermittedResponseHeader::ContentType,
                b"application/json".to_vec(),
            ),
            (
                PermittedResponseHeader::Etag,
                self.proposal_etag(&document, input.authority)?.into_bytes(),
            ),
        ]);
        if input.operation == ProposalAuthorityOperation::Start {
            headers.insert(
                PermittedResponseHeader::Location,
                format!("/v1/proposals/{id}").into_bytes(),
            );
        }
        let held = HeldResponse::from_json(
            if input.operation == ProposalAuthorityOperation::Start {
                201
            } else {
                200
            },
            &value,
            headers,
        )?;
        insert_result(
            tx,
            &binding,
            &StoredResultMetadata::Proposal {
                record_reference: reference,
                record_revision: document.header.workflow_revision,
                submission_version: document.header.submission_version,
                result_count,
            },
            &held,
        )
        .await?;
        proposal_store::link_idempotency_result(
            tx,
            &binding.key_reference,
            &action.id,
            id,
            document.header.submission_version,
            &binding_revision,
        )
        .await?;
        let entry = self.proposal_terminal(&input, &binding, &document, false, result_count)?;
        if tokio::time::Instant::now() >= deadline {
            return Err(MutationError::Unavailable);
        }
        check_current_proposal_grant(input.authority)?;
        if input.operation == ProposalAuthorityOperation::Lifecycle(ProposalOperation::Apply) {
            let frozen = workflow
                .current_proposal()
                .ok_or(MutationError::PreconditionFailed)?;
            verify_proposal_evidence(action, frozen, commit_evidence)?;
            if let CompiledProposalReview::Required {
                authority,
                source,
                policy,
            } = frozen.review_requirement()
            {
                if !review_evidence.is_some_and(|evidence| {
                    evidence.matches_proposal(
                        authority,
                        source,
                        policy,
                        &id.to_string(),
                        frozen.version().get(),
                        frozen.effect_digest().as_str(),
                        &chrono::Utc::now().to_rfc3339(),
                    )
                }) {
                    return Err(MutationError::PreconditionFailed);
                }
            }
            if let Some(lease) = &input.executor_lease {
                self.verify_executor_lease(tx, &input, frozen).await?;
                let application = workflow.application().ok_or(MutationError::Unavailable)?;
                let application_id = Uuid::parse_str(application.application_id().as_str())
                    .map_err(|_| MutationError::Unavailable)?;
                let changed=tx.execute("UPDATE registry_internal.registry_proposal_application_jobs
                    SET state='applied',application_id=$6,claim_token=NULL,last_error_code=NULL,updated_at=clock_timestamp()
                    WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3
                      AND job_id=$4 AND claim_token=$5 AND state='applying' AND next_attempt_at>clock_timestamp()",
                    &[&action.id,&id,&document.header.submission_version,&lease.job_id,&lease.claim_token,&application_id])
                    .await.map_err(map_database_error)?;
                if changed != 1 {
                    return Err(MutationError::PreconditionFailed);
                }
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(MutationError::Unavailable);
        }
        guarded
            .commit()
            .await
            .map_err(|_| MutationError::CommitUnresolved)?;
        self.audit
            .append(entry)
            .await
            .map_err(|_| MutationError::CommitUnresolved)?;
        Ok(MutationOutcome {
            response: held,
            replayed: false,
        })
    }

    fn proposal_terminal(
        &self,
        input: &ProposalMutationInput<'_>,
        binding: &crate::idempotency::ResolvedIdempotencyBinding,
        document: &ProposalDocument,
        replayed: bool,
        count: u16,
    ) -> Result<AuditEntry, MutationError> {
        let entry = action_terminal_entry(
            self.audit.profile(),
            TerminalAudit {
                grant: input.authority.common.grant_audit().cloned(),
                outcome: if replayed {
                    TerminalAuditOutcome::Replayed
                } else {
                    TerminalAuditOutcome::Committed
                },
                method: HttpMethod::Post,
                operation_id: format!(
                    "proposals.{}.{}",
                    document.action_id,
                    proposal_operation_name(input.operation)
                ),
                entity_id: None,
                action_id: Some(document.action_id.clone()),
                package_revision: self.expected.activation_id.clone(),
                selected_access_profile: input.authority.common.access_profile().to_owned(),
                purpose_present: input.authority.common.purpose().is_some(),
                principal_reference: Some(binding.principal_reference.clone()),
                record_reference: None,
                record_revision: None,
                result_count: Some(usize::from(count)),
                field_set_reference: None,
                correlation: input.correlation.clone(),
            },
            &format!(
                "proposal:{}:{}",
                document.proposal_id, document.header.workflow_revision
            ),
        )?;
        let mut record = entry.record().clone();
        record["authorityKind"] = json!(if input.authority.is_system() {
            "system"
        } else {
            "caller"
        });
        if let Some(revision) = input.authority.system_grant_revision() {
            record["systemApplyGrantRevision"] = json!(revision);
        }
        Ok(registry_platform_audit::AuditEntry::response(
            crate::audit::AUDIT_SCHEMA,
            input.correlation.request_id().to_string(),
            record,
        ))
    }

    async fn authorize_start_inputs(
        &self,
        tx: &Transaction<'_>,
        registry: &CompiledRegistry,
        action: &CompiledAction,
        document: &ProposalDocument,
        authority: &ProposalAuthority,
    ) -> Result<(), MutationError> {
        for (entity_id, id) in &document.input_targets {
            let entity = registry
                .entities()
                .get(entity_id)
                .ok_or(MutationError::InvalidRequest)?;
            let phase = if matches!(
                authority.operation,
                ProposalAuthorityOperation::Start
                    | ProposalAuthorityOperation::Lifecycle(ProposalOperation::Submit)
            ) {
                ProposalTargetPhase::Preparation
            } else {
                ProposalTargetPhase::Inspection
            };
            authority
                .install_target(
                    tx,
                    registry,
                    document.proposal_id,
                    u32::try_from(document.header.submission_version)
                        .map_err(|_| MutationError::Unavailable)?,
                    phase,
                    entity_id,
                    *id,
                    Operation::Get,
                    &proposal_read_fields(action, &entity.id),
                    None,
                    None,
                )
                .await
                .map_err(|_| MutationError::PreconditionFailed)?;
            let row = load_proposal_row(tx, entity, *id, true).await?;
            if !authority
                .authorizes_snapshot(entity, *id, &row.data)
                .map_err(|_| MutationError::PreconditionFailed)?
            {
                return Err(MutationError::PreconditionFailed);
            }
        }
        let _ = action;
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    async fn load_submission_bases(
        &self,
        tx: &Transaction<'_>,
        registry: &CompiledRegistry,
        action: &CompiledAction,
        document: &ProposalDocument,
        authority: &ProposalAuthority,
        resolved: &proposal_prepare::ResolvedProposalTargets,
        input: &Map<String, Value>,
    ) -> Result<
        (
            BTreeMap<(String, Uuid), (i64, Map<String, Value>)>,
            BTreeMap<String, (Uuid, i64, Map<String, Value>)>,
        ),
        MutationError,
    > {
        let mut bases = BTreeMap::new();
        let mut guards = BTreeMap::new();
        let mut needed = resolved
            .records
            .iter()
            .filter(|(_, operation)| **operation == Operation::Patch)
            .map(|(key, _)| key.clone())
            .collect::<BTreeSet<_>>();
        needed.extend(document.input_targets.iter().cloned());
        for guard in &action.requires {
            let id = input
                .get(&guard.input)
                .and_then(Value::as_str)
                .and_then(|id| Uuid::parse_str(id).ok())
                .ok_or(MutationError::InvalidRequest)?;
            needed.insert((guard.entity_id.clone(), id));
        }
        let mut rows = BTreeMap::new();
        for (entity_id, id) in needed {
            let entity = registry
                .entities()
                .get(&entity_id)
                .ok_or(MutationError::InvalidRequest)?;
            authority
                .install_target(
                    tx,
                    registry,
                    document.proposal_id,
                    u32::try_from(document.header.submission_version)
                        .map_err(|_| MutationError::Unavailable)?,
                    ProposalTargetPhase::Preparation,
                    &entity_id,
                    id,
                    Operation::Get,
                    &proposal_read_fields(action, &entity.id),
                    None,
                    None,
                )
                .await
                .map_err(|_| MutationError::PreconditionFailed)?;
            let row = load_proposal_row(tx, entity, id, true).await?;
            if !authority
                .authorizes_snapshot(entity, id, &row.data)
                .map_err(|_| MutationError::PreconditionFailed)?
            {
                return Err(MutationError::PreconditionFailed);
            }
            rows.insert((entity_id, id), (row.record_revision, row.data));
        }
        for ((entity, id), operation) in &resolved.records {
            if *operation == Operation::Patch {
                bases.insert((entity.clone(), *id), rows[&(entity.clone(), *id)].clone());
            }
        }
        for guard in &action.requires {
            let id = input
                .get(&guard.input)
                .and_then(Value::as_str)
                .and_then(|id| Uuid::parse_str(id).ok())
                .ok_or(MutationError::InvalidRequest)?;
            let (revision, row) = rows[&(guard.entity_id.clone(), id)].clone();
            let timestamp = registry
                .entities()
                .get(&guard.entity_id)
                .and_then(|entity| entity.fields.get(&guard.field))
                .is_some_and(|field| {
                    matches!(
                        field.field_type,
                        crate::contract::FieldTypeSource::Timestamp
                    )
                });
            verify_guard(guard, input, &row, timestamp, revision, Some(revision))?;
            guards.insert(guard.input.clone(), (id, revision, row));
        }
        for input_id in crate::commit_evidence::target_fields(&action.commit_evidence).keys() {
            let entity = reference_input_entity(action, input_id)?;
            let id = input
                .get(input_id)
                .and_then(Value::as_str)
                .and_then(|id| Uuid::parse_str(id).ok())
                .ok_or(MutationError::InvalidRequest)?;
            let (revision, row) = rows
                .get(&(entity.to_owned(), id))
                .ok_or(MutationError::PreconditionFailed)?
                .clone();
            guards.insert(input_id.clone(), (id, revision, row));
        }
        Ok((bases, guards))
    }

    async fn lock_frozen_scope(
        &self,
        tx: &Transaction<'_>,
        registry: &CompiledRegistry,
        action: &CompiledAction,
        document: &ProposalDocument,
        authority: &ProposalAuthority,
        frozen: &crate::proposal_workflow::ProposalSnapshot,
    ) -> Result<(), MutationError> {
        let mut targets = BTreeMap::new();
        for target in frozen.input_targets() {
            let id = Uuid::parse_str(target.record_id.as_str())
                .map_err(|_| MutationError::PreconditionFailed)?;
            targets.insert((target.record_type.clone(), id), None);
        }
        for effect in frozen.effects() {
            if let Some(id) = effect.target().existing_record_id() {
                targets.insert(
                    (
                        effect.target().entity_id().as_str().to_owned(),
                        Uuid::parse_str(id.as_str())
                            .map_err(|_| MutationError::PreconditionFailed)?,
                    ),
                    effect
                        .target()
                        .base_revision()
                        .map(|revision| revision.get()),
                );
            }
        }
        if let Some(guards) = frozen.application_preconditions() {
            for target in &guards.targets {
                targets.insert(
                    (
                        target.entity_id.clone(),
                        Uuid::parse_str(target.record_id.as_str())
                            .map_err(|_| MutationError::PreconditionFailed)?,
                    ),
                    Some(target.expected_revision),
                );
            }
        }
        for ((entity_id, id), revision) in targets {
            let entity = registry
                .entities()
                .get(&entity_id)
                .ok_or(MutationError::PreconditionFailed)?;
            authority
                .install_target(
                    tx,
                    registry,
                    document.proposal_id,
                    frozen.version().get(),
                    ProposalTargetPhase::Application,
                    &entity_id,
                    id,
                    Operation::Get,
                    &proposal_read_fields(action, &entity_id),
                    revision,
                    Some(frozen.effect_digest().as_str()),
                )
                .await
                .map_err(|_| MutationError::PreconditionFailed)?;
            let row = load_proposal_row(tx, entity, id, true).await?;
            if !authority
                .authorizes_snapshot(entity, id, &row.data)
                .map_err(|_| MutationError::PreconditionFailed)?
            {
                return Err(MutationError::PreconditionFailed);
            }
        }
        Ok(())
    }

    async fn verify_frozen_guards(
        &self,
        tx: &Transaction<'_>,
        registry: &CompiledRegistry,
        action: &CompiledAction,
        document: &ProposalDocument,
        authority: &ProposalAuthority,
        frozen: &crate::proposal_workflow::ProposalSnapshot,
    ) -> Result<(), MutationError> {
        let Some(preconditions) = frozen.application_preconditions() else {
            return if action.requires.is_empty() {
                Ok(())
            } else {
                Err(MutationError::PreconditionFailed)
            };
        };
        if preconditions.contract != action.requires {
            return Err(MutationError::PreconditionFailed);
        }
        preconditions.validate().map_err(workflow_error)?;
        let input = preconditions.input_values.clone().into_iter().collect();
        for target in &preconditions.targets {
            let entity = registry
                .entities()
                .get(&target.entity_id)
                .ok_or(MutationError::PreconditionFailed)?;
            let id = Uuid::parse_str(target.record_id.as_str())
                .map_err(|_| MutationError::PreconditionFailed)?;
            authority
                .install_target(
                    tx,
                    registry,
                    document.proposal_id,
                    frozen.version().get(),
                    ProposalTargetPhase::Application,
                    &entity.id,
                    id,
                    Operation::Get,
                    &proposal_read_fields(action, &entity.id),
                    Some(target.expected_revision),
                    Some(frozen.effect_digest().as_str()),
                )
                .await
                .map_err(|_| MutationError::PreconditionFailed)?;
            let row = load_proposal_row(tx, entity, id, true).await?;
            if !authority
                .authorizes_snapshot(entity, id, &row.data)
                .map_err(|_| MutationError::PreconditionFailed)?
            {
                return Err(MutationError::PreconditionFailed);
            }
            for guard in preconditions
                .contract
                .iter()
                .filter(|guard| guard.input == target.id)
            {
                if guard.revision_unchanged && row.record_revision != target.expected_revision {
                    return Err(MutationError::PreconditionFailed);
                }
                let timestamp = entity.fields.get(&guard.field).is_some_and(|field| {
                    matches!(
                        field.field_type,
                        crate::contract::FieldTypeSource::Timestamp
                    )
                });
                verify_guard(
                    guard,
                    &input,
                    &row.data,
                    timestamp,
                    row.record_revision,
                    Some(target.expected_revision),
                )?;
            }
            if let Some(fields) =
                crate::commit_evidence::target_fields(&preconditions.evidence).get(&target.id)
            {
                if fields
                    .iter()
                    .any(|field| row.data.get(field) != target.values.get(field))
                {
                    return Err(MutationError::PreconditionFailed);
                }
            }
        }
        Ok(())
    }

    async fn verify_executor_lease(
        &self,
        tx: &Transaction<'_>,
        input: &ProposalMutationInput<'_>,
        frozen: &crate::proposal_workflow::ProposalSnapshot,
    ) -> Result<(), MutationError> {
        let Some(lease) = &input.executor_lease else {
            if input.authority.is_system() {
                return Err(MutationError::PreconditionFailed);
            }
            return Ok(());
        };
        if !input.authority.is_system() || !frozen.application_policy().is_automatic() {
            return Err(MutationError::PreconditionFailed);
        }
        let executor = "builtin";
        let row = tx
            .query_opt(
                "SELECT 1 FROM registry_internal.registry_proposal_application_jobs
            WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3 AND job_id=$4
              AND claim_token=$5 AND executor=$6 AND state='applying'
              AND system_grant_revision=$7
              AND next_attempt_at>clock_timestamp() FOR UPDATE",
                &[
                    &input.action_id,
                    &input.proposal_id,
                    &i64::from(frozen.version().get()),
                    &lease.job_id,
                    &lease.claim_token,
                    &executor,
                    &frozen.system_grant_revision(),
                ],
            )
            .await
            .map_err(map_database_error)?;
        if row.is_none() {
            return Err(MutationError::PreconditionFailed);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn apply_frozen_proposal(
        &self,
        tx: &Transaction<'_>,
        registry: &CompiledRegistry,
        document: &ProposalDocument,
        authority: &ProposalAuthority,
        frozen: &crate::proposal_workflow::ProposalSnapshot,
        targets: &[ProposalTargetSnapshot],
        binding: &crate::idempotency::ResolvedIdempotencyBinding,
        application_id: Uuid,
    ) -> Result<(Vec<ObservedTarget>, Vec<ApplicationResultLink>), MutationError> {
        let action = proposal_action(registry, &document.action_id)?;
        let mut observed = Vec::new();
        let mut links = Vec::new();
        let mut rows = Vec::new();
        let mut groups = Vec::<Vec<&crate::proposal_workflow::PreparedEffect>>::new();
        let mut positions = BTreeMap::<(String, Uuid), usize>::new();
        for effect in frozen.effects() {
            let target = effect.target();
            let id = target
                .existing_record_id()
                .or_else(|| target.reserved_record_id())
                .ok_or(MutationError::PreconditionFailed)?;
            let id = Uuid::parse_str(id.as_str()).map_err(|_| MutationError::PreconditionFailed)?;
            let key = (target.entity_id().as_str().to_owned(), id);
            if let Some(position) = positions.get(&key).copied() {
                groups[position].push(effect);
            } else {
                positions.insert(key, groups.len());
                groups.push(vec![effect]);
            }
        }
        let ordered = crate::plan::order_effect_groups(
            groups,
            |effect| effect.id().as_str(),
            |effect| effect.depends_on(),
        )
        .map_err(|_| MutationError::PreconditionFailed)?;
        for group in ordered {
            let identity = group[0].target();
            let id = identity
                .existing_record_id()
                .or_else(|| identity.reserved_record_id())
                .ok_or(MutationError::PreconditionFailed)?;
            let id = Uuid::parse_str(id.as_str()).map_err(|_| MutationError::PreconditionFailed)?;
            let target = targets
                .iter()
                .find(|target| {
                    target.entity_id == identity.entity_id().as_str() && target.record_id == id
                })
                .ok_or(MutationError::PreconditionFailed)?;
            let entity = registry
                .entities()
                .get(&target.entity_id)
                .ok_or(MutationError::PreconditionFailed)?;
            let fields = frozen
                .effects()
                .iter()
                .filter(|effect| {
                    effect.target().entity_id().as_str() == target.entity_id
                        && effect
                            .target()
                            .existing_record_id()
                            .or_else(|| effect.target().reserved_record_id())
                            .is_some_and(|id| id.as_str() == target.record_id.to_string())
                })
                .flat_map(|effect| {
                    effect
                        .field_changes()
                        .iter()
                        .map(|change| change.field().as_str().to_owned())
                })
                .collect();
            if let Some(revision) = target.expected_revision {
                authority
                    .install_target(
                        tx,
                        registry,
                        document.proposal_id,
                        frozen.version().get(),
                        ProposalTargetPhase::Application,
                        &entity.id,
                        target.record_id,
                        Operation::Get,
                        &proposal_read_fields(action, &entity.id),
                        Some(revision),
                        Some(frozen.effect_digest().as_str()),
                    )
                    .await
                    .map_err(|_| MutationError::PreconditionFailed)?;
                let current = load_proposal_row(tx, entity, target.record_id, true).await?;
                if current.record_revision != revision
                    || Some(&current.data) != target.before.as_ref()
                    || !authority
                        .authorizes_snapshot(entity, target.record_id, &current.data)
                        .map_err(|_| MutationError::PreconditionFailed)?
                {
                    return Err(MutationError::PreconditionFailed);
                }
                observed.push(ObservedTarget::existing(
                    EntityId::new(&entity.id).map_err(workflow_error)?,
                    RecordId::new(target.record_id.to_string()).map_err(workflow_error)?,
                    RecordRevision::new(revision).map_err(workflow_error)?,
                ));
            } else {
                observed.push(ObservedTarget::reserved_create(
                    EntityId::new(&entity.id).map_err(workflow_error)?,
                    RecordId::new(target.record_id.to_string()).map_err(workflow_error)?,
                ));
            }
            if !authority
                .authorizes_snapshot(entity, target.record_id, &target.after)
                .map_err(|_| MutationError::PreconditionFailed)?
            {
                return Err(MutationError::PreconditionFailed);
            }
            authority
                .install_target(
                    tx,
                    registry,
                    document.proposal_id,
                    frozen.version().get(),
                    ProposalTargetPhase::Application,
                    &entity.id,
                    target.record_id,
                    target.operation,
                    &fields,
                    target.expected_revision,
                    Some(frozen.effect_digest().as_str()),
                )
                .await
                .map_err(|_| MutationError::PreconditionFailed)?;
            let write_fields = if target.operation == Operation::Patch {
                fields
                    .iter()
                    .map(|field| {
                        target
                            .after
                            .get(field)
                            .cloned()
                            .map(|value| (field.clone(), value))
                            .ok_or(MutationError::PreconditionFailed)
                    })
                    .collect::<Result<Map<_, _>, _>>()?
            } else {
                target.after.clone()
            };
            let current = write_plan_row(
                tx,
                entity,
                target.record_id,
                target.expected_revision,
                write_fields,
                target.before.as_ref(),
                self.field_encryption.as_deref(),
            )
            .await?;
            let reference = record_reference(
                self.audit.profile(),
                &self.expected.activation_id,
                &current.record_id,
            )?;
            let snapshot = canonical_snapshot(&current.data)?;
            insert_revision(
                tx,
                RevisionInsert {
                    entity_id: &entity.id,
                    record_id: current.record_uuid,
                    record_reference: &reference,
                    record_revision: current.record_revision,
                    predecessor_revision: current.predecessor_revision,
                    lifecycle: &current.record_lifecycle,
                    package_revision: &self.expected.activation_id,
                    operation_id: &format!(
                        "records.{}.{}",
                        entity.id,
                        mutation_kind(target.operation)
                    ),
                    mutation_kind: mutation_kind(target.operation),
                    principal_reference: &binding.principal_reference,
                    request_reference: &binding.request_reference,
                    snapshot: &snapshot,
                },
            )
            .await?;
            let deliveries = exact_entity_event_deliveries(registry, entity)?;
            let schemas = event_data_schemas(
                registry.registry_id(),
                entity,
                mutation_trigger(target.operation),
                &deliveries,
            )?;
            let source = self.event_source();
            let application_reference = application_id.to_string();
            insert_configured_events(
                tx,
                entity,
                &deliveries,
                self.event_destinations.as_deref(),
                OutboxMutation {
                    trigger: mutation_trigger(target.operation),
                    application_reference: Some(&application_reference),
                    entity_id: &entity.id,
                    record_id: &current.record_id,
                    record_reference: &reference,
                    record_revision: current.record_revision,
                    package_revision: &self.expected.activation_id,
                    package_digest: &self.expected.package_digest,
                    schema_fingerprint: &self.expected.schema_fingerprint,
                    before: current.before_data.as_ref(),
                    after: Some(&current.data),
                    payload_retention: self
                        .event_destinations
                        .as_deref()
                        .map_or(Duration::from_secs(7 * 24 * 60 * 60), |d| {
                            d.payload_retention()
                        }),
                    envelope: EnvelopeBinding {
                        source: &source,
                        data_schemas: &schemas,
                        causation: None,
                    },
                },
            )
            .await?;
            links.push(ApplicationResultLink::new(
                EntityId::new(&entity.id).map_err(workflow_error)?,
                RecordId::new(current.record_id.clone()).map_err(workflow_error)?,
                RecordRevision::new(current.record_revision).map_err(workflow_error)?,
            ));
            rows.push((
                entity.id.clone(),
                current.record_uuid,
                current.record_revision,
            ));
        }
        let members = rows
            .iter()
            .map(|(entity, id, revision)| RevisionCommitMember {
                entity_id: entity,
                record_id: *id,
                record_revision: *revision,
            })
            .collect::<Vec<_>>();
        allocate_revision_commit(
            tx,
            CommitAllocation {
                package_revision: &self.expected.activation_id,
                origin: CommitOrigin::Mutation {
                    actor_reference: &binding.principal_reference,
                    request_reference: &binding.request_reference,
                },
                change_context: None,
                members: &members,
            },
        )
        .await?;
        Ok((observed, links))
    }

    pub(crate) async fn authorize_proposal_review_read(
        &self,
        tx: &Transaction<'_>,
        registry: &CompiledRegistry,
        document: &ProposalDocument,
        authority: &ProposalAuthority,
    ) -> Result<(), MutationError> {
        let action = proposal_action(registry, &document.action_id)?;
        let CompiledActionExecution::Proposal { proposal } = &action.execution else {
            return Err(MutationError::PreconditionFailed);
        };
        let permission = proposal
            .permissions
            .iter()
            .find(|permission| permission.profile_id == authority.common.access_profile())
            .ok_or(MutationError::PreconditionFailed)?;
        let Some(expected_authority) = &permission.review_authority else {
            return self
                .authorize_proposal_document(tx, registry, document, authority)
                .await;
        };
        if authority.operation
            != ProposalAuthorityOperation::Lifecycle(ProposalOperation::GetReviewStatus)
            || permission.actor_kind != Some(crate::contract::ActorKindSource::Service)
            || document.action_id != authority.common.action_id()
            || document.header.current_proposal_erased
            || !permission.targets.is_empty()
            || permission.ownership.is_some()
            || authority
                .proposal_scope
                .as_ref()
                .is_some_and(|scope| !scope.contains(&document.proposal_id))
        {
            return Err(MutationError::PreconditionFailed);
        }
        let workflow =
            proposal_store::load(tx, &document.action_id, document.proposal_id, false).await?;
        let frozen = workflow
            .current_proposal()
            .ok_or(MutationError::PreconditionFailed)?;
        frozen
            .verify_digest(&crate::proposal_workflow::ProposalKey::new(
                EntityId::new(&document.action_id).map_err(workflow_error)?,
                RecordId::new(document.proposal_id.to_string()).map_err(workflow_error)?,
            ))
            .map_err(workflow_error)?;
        let CompiledProposalReview::Required {
            authority: frozen_authority,
            ..
        } = frozen.review_requirement()
        else {
            return Err(MutationError::PreconditionFailed);
        };
        if expected_authority != frozen_authority
            || i64::from(frozen.version().get()) != document.header.submission_version
            || frozen.contract_fingerprint().as_str() != document.action_revision
        {
            return Err(MutationError::PreconditionFailed);
        }
        let accepted = crate::review_store::load_status_binding(
            tx,
            registry,
            &document.action_id,
            document.proposal_id,
            frozen,
        )
        .await?;
        if let Some(row) = tx
            .query_opt(
                "SELECT authority,result_id,result,status,completed_at,available_until
            FROM registry_internal.registry_proposal_review_results
            WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3",
                &[
                    &document.action_id,
                    &document.proposal_id,
                    &document.header.submission_version,
                ],
            )
            .await
            .map_err(map_database_error)?
        {
            let accepted = accepted.ok_or(MutationError::PreconditionFailed)?;
            let result: registry_review_client::ReviewResult =
                serde_json::from_value(row.get(2))
                    .map_err(|_| MutationError::PreconditionFailed)?;
            result
                .check()
                .map_err(|_| MutationError::PreconditionFailed)?;
            let status =
                serde_json::to_value(result.status).map_err(|_| MutationError::Unavailable)?;
            if row.get::<_, String>(0) != *expected_authority
                || row.get::<_, Uuid>(1) != result.result_id
                || row.get::<_, String>(3)
                    != status.as_str().ok_or(MutationError::PreconditionFailed)?
                || row
                    .get::<_, chrono::DateTime<chrono::Utc>>(4)
                    .timestamp_micros()
                    != result.completed_at.timestamp_micros()
                || row
                    .get::<_, chrono::DateTime<chrono::Utc>>(5)
                    .timestamp_micros()
                    != result.available_until.timestamp_micros()
                || result.request_id != accepted.request_id
                || result.subject != accepted.subject
                || result.policy != accepted.policy
                || result.submission_digest != accepted.submission_digest
            {
                return Err(MutationError::PreconditionFailed);
            }
        }
        Ok(())
    }

    /// One exact submission of a Proposal: its frozen effect digest, its review
    /// result and its application outcome, each reported separately. Only the
    /// current submission has application progress; an earlier one reports
    /// only a committed receipt. `None` means the submission existed but its
    /// review result window has lapsed or its detail was erased, and no
    /// application receipt remains to report.
    pub(crate) async fn proposal_submission_value(
        &self,
        tx: &Transaction<'_>,
        document: &ProposalDocument,
        version: u32,
    ) -> Result<Option<Value>, MutationError> {
        let version = i64::from(version);
        let Some(submission) = tx
            .query_opt(
                "SELECT effect_digest, erased_at IS NOT NULL
                 FROM registry_internal.registry_proposal_submissions
                 WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3",
                &[&document.action_id, &document.proposal_id, &version],
            )
            .await
            .map_err(map_database_error)?
        else {
            return Err(MutationError::PreconditionFailed);
        };
        let erased: bool = submission.get(1);
        let workflow = if document.header.current_proposal_erased {
            None
        } else {
            Some(proposal_store::load(tx, &document.action_id, document.proposal_id, false).await?)
        };
        let frozen = workflow
            .as_ref()
            .and_then(|workflow| workflow.current_proposal())
            .filter(|_| {
                document.header.state != "draft" && document.header.submission_version == version
            });
        let review = tx
            .query_opt(
                "SELECT status,result_id,
        to_char(completed_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
        to_char(available_until AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
        available_until<=transaction_timestamp()
        FROM registry_internal.registry_proposal_review_results
        WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3",
                &[&document.action_id, &document.proposal_id, &version],
            )
            .await
            .map_err(map_database_error)?;
        let review_lapsed = review.as_ref().is_some_and(|row| row.get::<_, bool>(4));
        let review = match review {
            Some(row) => json!({
                "state":if row.get::<_,bool>(4) {"expired".to_owned()} else {row.get::<_,String>(0)},
                "resultId":row.get::<_,Uuid>(1),"completedAt":row.get::<_,String>(2),
                "availableUntil":row.get::<_,String>(3)}),
            None if document.header.state == "submitted"
                && frozen.is_some_and(|frozen| {
                    matches!(
                        frozen.review_requirement(),
                        CompiledProposalReview::Required { .. }
                    )
                }) =>
            {
                json!({"state":"pending"})
            }
            None => Value::Null,
        };
        let receipt = tx
            .query_opt(
                "SELECT application_id
        FROM registry_internal.registry_proposal_applications
        WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3",
                &[&document.action_id, &document.proposal_id, &version],
            )
            .await
            .map_err(map_database_error)?;
        let application = match (receipt, frozen) {
            // Who applied and when stay with the receipt: no profile reads them.
            (Some(row), _) => json!({"state":"applied","applicationId":row.get::<_,Uuid>(0)}),
            (None, Some(frozen)) => proposal_application_status(tx, document, frozen).await?,
            (None, None) => Value::Null,
        };
        if (review_lapsed || erased) && application.is_null() {
            return Ok(None);
        }
        let mut value = json!({
            "id":document.proposal_id,"actionId":document.action_id,
            "submissionVersion":version,"current":frozen.is_some(),
            "effectDigest":submission.get::<_,String>(0),
            "review":review,"application":application
        });
        if let Some(decision) =
            review_decision(tx, &document.action_id, document.proposal_id, version).await?
        {
            value["decision"] = decision;
        }
        Ok(Some(value))
    }

    pub(crate) async fn proposal_review_value(
        &self,
        tx: &Transaction<'_>,
        registry: &CompiledRegistry,
        document: &ProposalDocument,
        authority: &ProposalAuthority,
        records: &BTreeMap<String, crate::api::proposals::ProposalRecordReadAuthority>,
    ) -> Result<Value, MutationError> {
        let action = proposal_action(registry, &document.action_id)?;
        // Current disclosure cannot reinterpret frozen work through a newer
        // Action mapping. Review document downloads use this same projection.
        if authority.operation
            == ProposalAuthorityOperation::Lifecycle(ProposalOperation::GetReviewContext)
            && action.definition_revision != document.action_revision
        {
            return Err(MutationError::PreconditionFailed);
        }
        let workflow =
            proposal_store::load(tx, &document.action_id, document.proposal_id, false).await?;
        let frozen = workflow
            .current_proposal()
            .ok_or(MutationError::PreconditionFailed)?;
        let mut value = json!({"id":document.proposal_id,"actionId":document.action_id,
            "actionRevision":document.action_revision,"submissionVersion":frozen.version().get(),
            "revision":document.header.workflow_revision,"effectDigest":frozen.effect_digest().as_str(),
            "subject":{"source":registry.registry_id(),"subjectType":"proposal","id":document.proposal_id,"version":frozen.version().get().to_string(),
                "digest":frozen.effect_digest().as_str()},
            "context":{"reference":format!("breg:{}:{}:{}:{}",registry.registry_id(),action.id,document.proposal_id,frozen.version().get())},
            "reviewable":document.header.state=="submitted"&&document.blocked_reason.is_none()});
        if let Some(contract) = crate::compiler::review_context::compile_schema(registry, action)
            .map_err(|_| MutationError::Unavailable)?
        {
            value["context"]["contract"] = json!({
                "id":contract.id,"revision":contract.revision,"schemaDigest":contract.digest
            });
        }
        if let CompiledProposalReview::Required {
            authority,
            source,
            policy,
        } = frozen.review_requirement()
        {
            value["authority"] = json!(authority);
            value["subject"]["source"] = json!(source);
            value["policy"] = json!(policy);
        }
        match authority.operation {
            ProposalAuthorityOperation::Lifecycle(ProposalOperation::GetReviewStatus) => {
                if matches!(
                    frozen.review_requirement(),
                    CompiledProposalReview::Required { .. }
                ) {
                    if let Some(accepted) = crate::review_store::load_status_binding(
                        tx,
                        registry,
                        &document.action_id,
                        document.proposal_id,
                        frozen,
                    )
                    .await?
                    {
                        value["requestId"] = json!(accepted.request_id);
                    }
                    value["result"] = proposal_review_result(tx, document).await?;
                }
            }
            ProposalAuthorityOperation::Lifecycle(ProposalOperation::GetReviewContext) => {
                if let CompiledActionExecution::Proposal { proposal } = &action.execution {
                    if proposal.review_context.as_ref().is_some_and(|context| {
                        context.fields.values().any(|source| {
                            matches!(
                                source,
                                crate::contract::ProposalContextValueSource::Document { .. }
                            )
                        })
                    }) {
                        self.verify_proposal_attachment_binding(tx).await?;
                    }
                }
                value["context"]["fields"] = Value::Object(
                    context_projection::fields(tx, registry, document, authority, records, frozen)
                        .await?,
                );
            }
            _ => return Err(MutationError::PreconditionFailed),
        }
        Ok(value)
    }

    pub(crate) async fn proposal_public_value(
        &self,
        tx: &Transaction<'_>,
        registry: &CompiledRegistry,
        document: &ProposalDocument,
        claims: Option<&crate::api::VerifiedRequestClaims>,
        current: &ProposalAuthority,
    ) -> Result<Value, MutationError> {
        let action = proposal_action(registry, &document.action_id)?;
        let mut value = json!({"id":document.proposal_id,"actionId":document.action_id,
            "actionRevision":document.action_revision,"submissionVersion":document.header.submission_version,
            "revision":document.header.workflow_revision,"state":document.header.state,"links":{}});
        if let Some(title) = &document.action_title {
            value["title"] = json!(title);
        }
        if let Some(blocked) = &document.blocked_reason {
            value["blockedReason"] = json!(blocked);
        }
        let workflow = if document.header.current_proposal_erased {
            None
        } else {
            Some(proposal_store::load(tx, &document.action_id, document.proposal_id, false).await?)
        };
        if let Some(proposal) = workflow
            .as_ref()
            .and_then(|workflow| workflow.current_proposal())
        {
            value["effectDigest"] = json!(proposal.effect_digest().as_str());
            if claims.is_some() {
                value["applicationStatus"] =
                    proposal_application_status(tx, document, proposal).await?;
            }
        }
        value["turn"] = json!(
            current_turn(
                tx,
                document,
                workflow
                    .as_ref()
                    .and_then(|workflow| workflow.current_proposal())
            )
            .await?
        );
        if let Some(application) = workflow
            .as_ref()
            .and_then(|workflow| workflow.application())
        {
            value["application"] = public_application(application);
        }
        let Some(claims) = claims else {
            return Ok(value);
        };
        // The decision is disclosed on the reads only, beside the inputs the
        // same Get authority discloses; a lifecycle command's response omits it.
        if document.header.state != "draft"
            && workflow
                .as_ref()
                .is_some_and(|workflow| workflow.current_proposal().is_some())
            && matches!(
                current.operation,
                ProposalAuthorityOperation::Lifecycle(
                    ProposalOperation::Get | ProposalOperation::List
                )
            )
        {
            if let Some(decision) = review_decision(
                tx,
                &document.action_id,
                document.proposal_id,
                document.header.submission_version,
            )
            .await?
            {
                value["decision"] = decision;
            }
        }
        let review_refusal = match workflow
            .as_ref()
            .and_then(|workflow| workflow.current_proposal())
        {
            Some(frozen) if document.header.state == "submitted" => {
                review_progress(tx, document, frozen).await?.apply_refusal()
            }
            _ => None,
        };
        let review_available = match &action.execution {
            CompiledActionExecution::Proposal { proposal } => match &proposal.review {
                CompiledProposalReview::None => true,
                CompiledProposalReview::Required { authority, .. } => self
                    .review_authorities
                    .as_ref()
                    .is_some_and(|configured| configured.contains(authority)),
            },
            _ => false,
        };
        let retry_available = document.header.state == "submitted"
            && crate::review_store::submission_work_is_retryable(
                tx,
                &document.action_id,
                document.proposal_id,
                document.header.submission_version,
            )
            .await?;
        let operations = [
            ("self", ProposalOperation::Get),
            ("edit", ProposalOperation::Edit),
            ("submit", ProposalOperation::Submit),
            ("revise", ProposalOperation::Revise),
            ("cancel", ProposalOperation::Cancel),
            ("apply", ProposalOperation::Apply),
            ("rebase", ProposalOperation::Rebase),
            ("retry", ProposalOperation::Retry),
            ("reviewStatus", ProposalOperation::GetReviewStatus),
            ("reviewContext", ProposalOperation::GetReviewContext),
        ];
        for (name, operation) in operations {
            let profiles = std::iter::once(current.common.access_profile());
            let authority = profiles
                .filter_map(|profile| {
                    crate::api::proposals::authorize(
                        registry,
                        action,
                        claims,
                        Some(profile),
                        ProposalAuthorityOperation::Lifecycle(operation),
                        Some(document.proposal_id),
                    )
                })
                .next();
            let Some(authority) = authority else {
                continue;
            };
            if operation == ProposalOperation::Rebase
                && crate::api::proposals::authorize(
                    registry,
                    action,
                    claims,
                    Some(current.common.access_profile()),
                    ProposalAuthorityOperation::Start,
                    None,
                )
                .is_none()
            {
                continue;
            }
            if self
                .authorize_proposal_document(tx, registry, document, &authority)
                .await
                .is_err()
            {
                continue;
            }
            if operation == ProposalOperation::Get
                && matches!(
                    current.operation,
                    ProposalAuthorityOperation::Lifecycle(
                        ProposalOperation::Get | ProposalOperation::List
                    )
                )
            {
                let CompiledActionExecution::Proposal { proposal } = &action.execution else {
                    return Err(MutationError::InvalidRequest);
                };
                if let Some(permission) = proposal
                    .permissions
                    .iter()
                    .find(|permission| permission.profile_id == authority.common.access_profile())
                {
                    if let Some(inputs) =
                        public_inputs(action, &permission.readable_inputs, document.input.as_ref())
                    {
                        value["input"] = Value::Object(inputs);
                    }
                }
            }
            let available = match operation {
                ProposalOperation::Get => true,
                ProposalOperation::Edit => {
                    document.header.state == "draft" && document.blocked_reason.is_none()
                }
                ProposalOperation::Submit => {
                    document.header.state == "draft"
                        && document.blocked_reason.is_none()
                        && review_available
                }
                ProposalOperation::Revise => {
                    document.header.state == "submitted"
                        && document.blocked_reason.is_none()
                        && document.action_revision == action.definition_revision
                }
                ProposalOperation::Rebase => {
                    matches!(document.header.state.as_str(), "draft" | "submitted")
                }
                ProposalOperation::Retry => {
                    document.header.state == "submitted"
                        && document.blocked_reason.is_none()
                        && retry_available
                }
                ProposalOperation::Cancel => {
                    matches!(document.header.state.as_str(), "draft" | "submitted")
                }
                ProposalOperation::Apply => {
                    document.header.state == "submitted"
                        && document.blocked_reason.is_none()
                        && review_refusal.is_none()
                        && review_available
                }
                ProposalOperation::GetReviewContext | ProposalOperation::GetReviewStatus => {
                    document.header.state == "submitted"
                }
                ProposalOperation::List => false,
            };
            if !available
                && matches!(
                    operation,
                    ProposalOperation::GetReviewContext
                        | ProposalOperation::GetReviewStatus
                        | ProposalOperation::List
                )
            {
                continue;
            }
            let path = match operation {
                ProposalOperation::Get => format!("/v1/proposals/{}", document.proposal_id),
                ProposalOperation::GetReviewContext => {
                    format!("/v1/proposals/{}/review-context", document.proposal_id)
                }
                ProposalOperation::GetReviewStatus => {
                    format!("/v1/proposals/{}/review-status", document.proposal_id)
                }
                _ => format!(
                    "/v1/proposals/{}/{}",
                    document.proposal_id,
                    proposal_operation_name(authority.operation)
                ),
            };
            let mut link = json!({"method":if matches!(operation,ProposalOperation::Get|ProposalOperation::GetReviewContext|ProposalOperation::GetReviewStatus){"GET"}else{"POST"},
                "path":path,"accessProfile":authority.common.access_profile(),"operation":proposal_operation_name(authority.operation),
                "availability":{"available":available,"observedRevision":document.header.workflow_revision}});
            if !matches!(
                operation,
                ProposalOperation::Get
                    | ProposalOperation::GetReviewContext
                    | ProposalOperation::GetReviewStatus
            ) {
                link["ifMatch"] = json!(self.proposal_etag(document, &authority)?);
            }
            if !available {
                if document.header.state == "applied" {
                    link["availability"]["reason"] = json!("already-applied");
                    link["availability"]["recovery"] = json!("receipt-only");
                } else if document.header.state == "rejected" {
                    link["availability"]["reason"] = json!("review-rejected");
                    link["availability"]["recovery"] = json!("receipt-only");
                } else if match operation {
                    ProposalOperation::Edit | ProposalOperation::Submit => {
                        document.header.state != "draft"
                    }
                    ProposalOperation::Revise
                    | ProposalOperation::Retry
                    | ProposalOperation::Apply => document.header.state != "submitted",
                    ProposalOperation::Rebase | ProposalOperation::Cancel => {
                        !matches!(document.header.state.as_str(), "draft" | "submitted")
                    }
                    _ => false,
                } {
                    link["availability"]["reason"] = json!("stale-revision");
                    link["availability"]["recovery"] = json!("receipt-only");
                } else if operation == ProposalOperation::Revise
                    && document.action_revision != action.definition_revision
                {
                    link["availability"]["reason"] = json!("contract-changed");
                    link["availability"]["recovery"] = json!("refresh");
                } else if document.blocked_reason.is_some() {
                    link["availability"]["reason"] = json!("contract-changed");
                    link["availability"]["recovery"] = json!("correct-input");
                } else if operation == ProposalOperation::Retry && !retry_available {
                    // A review that has ended leaves nothing to retry: the
                    // same review outcome Apply reports names Revise.
                    let (reason, recovery) = review_refusal
                        .filter(|(_, recovery)| *recovery == "revise")
                        .unwrap_or(("invalid-input", "correct-input"));
                    link["availability"]["reason"] = json!(reason);
                    link["availability"]["recovery"] = json!(recovery);
                } else if !review_available {
                    link["availability"]["reason"] = json!("dependency-outage");
                    link["availability"]["recovery"] = json!("retry");
                } else if let Some((reason, recovery)) = review_refusal {
                    link["availability"]["reason"] = json!(reason);
                    link["availability"]["recovery"] = json!(recovery);
                } else {
                    link["availability"]["reason"] = json!("pending-review");
                    link["availability"]["recovery"] = json!("refresh");
                }
            }
            value["links"][name] = link;
        }
        let CompiledActionExecution::Proposal { proposal: policy } = &action.execution else {
            return Err(MutationError::Unavailable);
        };
        let permission = policy
            .permissions
            .iter()
            .find(|permission| permission.profile_id == current.common.access_profile());
        if let Some(permission) = permission {
            let read = crate::api::proposals::authorize(
                registry,
                action,
                claims,
                Some(current.common.access_profile()),
                ProposalAuthorityOperation::Lifecycle(ProposalOperation::Get),
                Some(document.proposal_id),
            );
            let write = crate::api::proposals::authorize(
                registry,
                action,
                claims,
                Some(current.common.access_profile()),
                ProposalAuthorityOperation::Lifecycle(ProposalOperation::Edit),
                Some(document.proposal_id),
            );
            let metadata = if read.is_some() && !permission.readable_attachments.is_empty() {
                crate::attachment_store::metadata(
                    tx,
                    &document.action_id,
                    document.proposal_id,
                    document.header.submission_version,
                )
                .await?
            } else {
                BTreeMap::new()
            };
            let mut slots = Map::new();
            for (id, slot) in &policy.attachments {
                let readable = read.is_some() && permission.readable_attachments.contains(id);
                let writable = write.is_some() && permission.writable_attachments.contains(id);
                if !readable && !writable {
                    continue;
                }
                let path = format!("/v1/proposals/{}/attachments/{id}", document.proposal_id);
                let mut descriptor = json!({"id":id,"required":slot.required,"maximumBytes":slot.maximum_bytes,
                    "contentTypes":slot.content_types,"classification":slot.classification,"links":{}});
                if readable {
                    if let Some(metadata) = metadata.get(id) {
                        descriptor["value"] = json!({"submissionVersion":document.header.submission_version,
                            "sha256":metadata.sha256,"byteSize":metadata.byte_size,"contentType":metadata.content_type,
                            "uploadedAt":metadata.uploaded_at,"verificationStatus":metadata.verification_status});
                        if metadata.verification_status.permits_content() {
                            descriptor["links"]["download"] = json!({"method":"GET","path":format!("{path}?submissionVersion={}",document.header.submission_version),
                                "accessProfile":current.common.access_profile(),"operation":"download",
                                "availability":{"available":true,"observedRevision":document.header.workflow_revision}});
                        }
                    }
                }
                if writable && document.header.state == "draft" && document.blocked_reason.is_none()
                {
                    let write = write.as_ref().ok_or(MutationError::Unavailable)?;
                    let etag = self.proposal_etag(document, write)?;
                    for (name, method) in [("upload", "PATCH"), ("remove", "DELETE")] {
                        descriptor["links"][name] = json!({"method":method,"path":path,"accessProfile":current.common.access_profile(),
                            "ifMatch":etag,"operation":name,"availability":{"available":true,"observedRevision":document.header.workflow_revision}});
                    }
                }
                slots.insert(id.clone(), descriptor);
            }
            if !slots.is_empty() {
                value["attachments"] = Value::Object(slots);
            }
        }
        Ok(value)
    }
}

fn public_inputs(
    action: &CompiledAction,
    readable: &BTreeSet<String>,
    inputs: Option<&Map<String, Value>>,
) -> Option<Map<String, Value>> {
    let inputs = inputs?;
    if readable.is_empty() {
        return None;
    }
    Some(
        action
            .inputs
            .iter()
            .filter(|input| readable.contains(&input.id))
            .filter_map(|input| {
                inputs
                    .get(&input.id)
                    .map(|value| (input.api_name.clone(), value.clone()))
            })
            .collect(),
    )
}

/// Observe only BReg's retained state for the current frozen binding. No
/// authority polling or guard execution belongs in a Proposal observation.
async fn proposal_application_status(
    tx: &Transaction<'_>,
    document: &ProposalDocument,
    frozen: &crate::proposal_workflow::ProposalSnapshot,
) -> Result<Value, MutationError> {
    let automatic = frozen.application_policy().is_automatic();
    let mut value = json!({"mode":if automatic {"automatic"} else {"manual"}});
    match document.header.state.as_str() {
        "applied" | "cancelled" | "rejected" => {
            value["state"] = json!(document.header.state);
            return Ok(value);
        }
        "submitted" => {}
        _ => return Err(MutationError::PreconditionFailed),
    }
    if document.blocked_reason.is_some() && !automatic {
        value["state"] = json!("blocked");
        value["reason"] = json!("contract-changed");
        value["recovery"] = json!("correct-input");
        return Ok(value);
    }
    if !automatic {
        let awaiting_review = matches!(
            frozen.review_requirement(),
            CompiledProposalReview::Required { .. }
        ) && proposal_review_result(tx, document).await?["state"]
            != "approved";
        value["state"] = json!(if awaiting_review {
            "awaiting-review"
        } else {
            "pending"
        });
        return Ok(value);
    }
    let row = tx
        .query_opt(
            "SELECT state,proposal_digest,system_grant_revision,executor,
        attempt_count,maximum_attempts,last_error_code,next_attempt_at<=clock_timestamp()
        FROM registry_internal.registry_proposal_application_jobs
        WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3",
            &[
                &document.action_id,
                &document.proposal_id,
                &document.header.submission_version,
            ],
        )
        .await
        .map_err(map_database_error)?;
    let Some(row) = row else {
        let CompiledProposalReview::Required {
            authority, policy, ..
        } = frozen.review_requirement()
        else {
            return Err(MutationError::PreconditionFailed);
        };
        // Review precedes application-job creation. This is an observation of
        // the exact retained local binding, not a fetch of review authority.
        let review = tx
            .query_opt(
                "SELECT s.proposal_digest,s.authority,s.expected_policy,
            s.on_approved_mode,s.executor,r.status
            FROM registry_internal.registry_proposal_review_submissions s
            LEFT JOIN registry_internal.registry_proposal_review_results r
              USING(action_id,proposal_id,submission_version)
            WHERE s.action_id=$1 AND s.proposal_id=$2 AND s.submission_version=$3",
                &[
                    &document.action_id,
                    &document.proposal_id,
                    &document.header.submission_version,
                ],
            )
            .await
            .map_err(map_database_error)?
            .ok_or(MutationError::PreconditionFailed)?;
        if review.get::<_, String>(0) != frozen.effect_digest().as_str()
            || review.get::<_, String>(1) != *authority
            || review.get::<_, Value>(2)
                != serde_json::to_value(policy).map_err(|_| MutationError::Unavailable)?
            || review.get::<_, String>(3) != "automatic"
            || review.get::<_, Option<String>>(4).as_deref() != Some("builtin")
        {
            return Err(MutationError::PreconditionFailed);
        }
        let result: Option<String> = review.get(5);
        if result.as_deref() == Some("approved") {
            return Err(MutationError::PreconditionFailed);
        }
        // Without a job no executor has run, so nothing here is an
        // application refusal. A review outcome, a failed review submission
        // or a withdrawal is reported by the Apply, Retry and Revise links.
        let blocked = document.blocked_reason.is_some();
        value["state"] = json!(if blocked {
            "blocked"
        } else {
            "awaiting-review"
        });
        value["automaticRetry"] = json!({"scheduled":false,"attempts":0,
            "maximumAttempts":frozen.application_policy().maximum_attempts()});
        if blocked {
            value["reason"] = json!("contract-changed");
            value["recovery"] = json!("correct-input");
        }
        return Ok(value);
    };
    if row.get::<_, String>(1) != frozen.effect_digest().as_str()
        || Some(row.get::<_, String>(2).as_str()) != frozen.system_grant_revision()
        || row.get::<_, String>(3) != "builtin"
        || row.get::<_, i32>(5) != i32::from(frozen.application_policy().maximum_attempts())
    {
        return Err(MutationError::PreconditionFailed);
    }
    let state: String = row.get(0);
    let attempts: i32 = row.get(4);
    let maximum: i32 = row.get(5);
    let error: Option<String> = row.get(6);
    let lease_expired: bool = row.get(7);
    let exhausted = attempts >= maximum && (state != "applying" || lease_expired);
    value["state"] = json!(match state.as_str() {
        "queued" if !exhausted => "pending",
        "applying" if !exhausted => "applying",
        "queued" | "applying" | "blocked" => "blocked",
        _ => return Err(MutationError::PreconditionFailed),
    });
    value["automaticRetry"] = json!({
        "scheduled":!exhausted && (state=="queued" || state=="applying" && lease_expired),
        "attempts":attempts,"maximumAttempts":maximum
    });
    if document.blocked_reason.is_some() {
        value["state"] = json!("blocked");
        value["reason"] = json!("contract-changed");
        value["recovery"] = json!("correct-input");
        value["automaticRetry"]["scheduled"] = json!(false);
        return Ok(value);
    }
    if exhausted {
        value["reason"] = json!("attempts-exhausted");
        value["recovery"] = json!("correct-input");
    } else if value["state"] == "blocked" || error.is_some() {
        let (reason, recovery) = match error.as_deref() {
            Some("dependency-outage" | "source-unavailable" | "executor-unavailable") => {
                ("dependency-outage", "retry")
            }
            Some("lease-expired") => ("lease-expired", "retry"),
            _ => ("application-refused", "correct-input"),
        };
        value["reason"] = json!(reason);
        value["recovery"] = json!(recovery);
    }
    Ok(value)
}

fn public_application(application: &crate::proposal_workflow::ApplicationReceipt) -> Value {
    json!({"applicationId":application.application_id().as_str(),
        "submissionVersion":application.version().get(),
        "effectDigest":application.effect_digest().as_str(),
        "resultLinks":application.result_links()})
}

fn proposal_action<'a>(
    registry: &'a CompiledRegistry,
    id: &str,
) -> Result<&'a CompiledAction, MutationError> {
    let action = registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == id)
        .ok_or(MutationError::InvalidRequest)?;
    if !action.execution.is_proposal() {
        return Err(MutationError::InvalidRequest);
    }
    Ok(action)
}

/// How far the current submission's review has gone, read from BReg's
/// retained submission and result rows only. No authority is asked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReviewProgress {
    /// The submission's Action requires no review.
    NotRequired,
    /// The review authority holds the request, or BReg is still delivering it.
    Pending,
    /// Delivery or result lookup failed and Retry may resume it.
    Retrying,
    /// The review submission failed for good; only a later submission can
    /// be reviewed.
    Failed,
    Approved,
    /// An approval whose availability window has passed: it can no longer
    /// authorize Apply.
    ApprovalExpired,
    Rejected,
    ChangesRequested,
    /// An `answered` result, which has no meaning for a Proposal.
    Answered,
    /// A Casework `cancelled` or `superseded` the producer did not cause.
    Ended,
}

impl ReviewProgress {
    /// The Apply availability a review that has not approved this
    /// submission gives. `None` for an approval or no review.
    fn apply_refusal(self) -> Option<(&'static str, &'static str)> {
        match self {
            Self::NotRequired | Self::Approved => None,
            Self::Pending => Some(("pending-review", "refresh")),
            // Retry resumes the delivery or lookup that failed.
            Self::Retrying => Some(("dependency-outage", "retry")),
            Self::Rejected => Some(("review-rejected", "revise")),
            Self::ChangesRequested => Some(("review-changes-requested", "revise")),
            Self::Failed | Self::ApprovalExpired | Self::Answered | Self::Ended => {
                Some(("review-ended", "revise"))
            }
        }
    }
}

/// Read the current submission's review progress. A Casework `cancelled` or
/// `superseded` the producer caused by withdrawing is not an outcome of
/// review, so it reads as pending until the withdrawal settles.
async fn review_progress(
    tx: &Transaction<'_>,
    document: &ProposalDocument,
    frozen: &crate::proposal_workflow::ProposalSnapshot,
) -> Result<ReviewProgress, MutationError> {
    if !matches!(
        frozen.review_requirement(),
        CompiledProposalReview::Required { .. }
    ) {
        return Ok(ReviewProgress::NotRequired);
    }
    let row = tx
        .query_opt(
            "SELECT s.state,s.withdrawn,s.last_error_code IS NOT NULL,r.status,
        r.available_until<=transaction_timestamp()
        FROM registry_internal.registry_proposal_review_submissions s
        LEFT JOIN registry_internal.registry_proposal_review_results r
          USING(action_id,proposal_id,submission_version)
        WHERE s.action_id=$1 AND s.proposal_id=$2 AND s.submission_version=$3",
            &[
                &document.action_id,
                &document.proposal_id,
                &document.header.submission_version,
            ],
        )
        .await
        .map_err(map_database_error)?;
    let Some(row) = row else {
        return Ok(ReviewProgress::Pending);
    };
    let state: String = row.get(0);
    let withdrawn: bool = row.get(1);
    let erroring: bool = row.get(2);
    let status: Option<String> = row.get(3);
    let expired: Option<bool> = row.get(4);
    Ok(match status.as_deref() {
        Some("approved") if expired == Some(true) => ReviewProgress::ApprovalExpired,
        Some("approved") => ReviewProgress::Approved,
        Some("rejected") => ReviewProgress::Rejected,
        Some("changes-requested") => ReviewProgress::ChangesRequested,
        Some("answered") => ReviewProgress::Answered,
        Some("cancelled" | "superseded") if !withdrawn => ReviewProgress::Ended,
        Some(_) => ReviewProgress::Pending,
        None if state == "failed" => ReviewProgress::Failed,
        None if erroring && matches!(state.as_str(), "pending" | "uncertain" | "accepted") => {
            ReviewProgress::Retrying
        }
        None => ReviewProgress::Pending,
    })
}

/// The turn of a Proposal as it stands in this transaction.
pub(crate) async fn current_turn(
    tx: &Transaction<'_>,
    document: &ProposalDocument,
    frozen: Option<&crate::proposal_workflow::ProposalSnapshot>,
) -> Result<&'static str, MutationError> {
    let blocked = document.blocked_reason.is_some();
    if document.header.state != "submitted" {
        return Ok(proposal_turn(
            &document.header.state,
            blocked,
            ReviewProgress::NotRequired,
            &Value::Null,
        ));
    }
    let frozen = frozen.ok_or(MutationError::PreconditionFailed)?;
    let review = review_progress(tx, document, frozen).await?;
    let application = proposal_application_status(tx, document, frozen).await?;
    Ok(proposal_turn(
        &document.header.state,
        blocked,
        review,
        &application,
    ))
}

/// Whose move a Proposal waits on: the party that drives it, an official
/// who reviews or applies it, or nobody. Derived from the lifecycle state,
/// the current submission's review progress and its application status;
/// nothing stores it.
pub(crate) fn proposal_turn(
    state: &str,
    blocked: bool,
    review: ReviewProgress,
    application: &Value,
) -> &'static str {
    match state {
        "draft" => return "party",
        "submitted" => {}
        _ => return "nobody",
    }
    if blocked {
        return "party";
    }
    match review {
        ReviewProgress::Pending | ReviewProgress::Retrying => return "official",
        ReviewProgress::Failed
        | ReviewProgress::ApprovalExpired
        | ReviewProgress::Rejected
        | ReviewProgress::ChangesRequested
        | ReviewProgress::Answered
        | ReviewProgress::Ended => return "party",
        ReviewProgress::NotRequired | ReviewProgress::Approved => {}
    }
    if application["mode"] == "manual" {
        return "official";
    }
    match (
        application["state"].as_str(),
        application["recovery"].as_str(),
    ) {
        (Some("blocked"), Some("retry")) => "official",
        (Some("blocked"), _) => "party",
        _ => "nobody",
    }
}

/// The audit marker of a read that served a decision's public reason.
pub(crate) const PUBLIC_REASON_REFERENCE: &str = "proposal-review-public-reason";

/// The reviewer's decision on one submission, read through the protocol's
/// own result type. Only the status, its time and the public reason are
/// served: the public reason is the one reviewer text the protocol releases
/// to the subject's owner. Provider-side ends (cancelled, superseded) are not
/// decisions, and a result whose content retention erased has none.
async fn review_decision(
    tx: &Transaction<'_>,
    action_id: &str,
    proposal_id: Uuid,
    version: i64,
) -> Result<Option<Value>, MutationError> {
    let Some(row) = tx
        .query_opt(
            "SELECT result FROM registry_internal.registry_proposal_review_results
             WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3",
            &[&action_id, &proposal_id, &version],
        )
        .await
        .map_err(map_database_error)?
    else {
        return Ok(None);
    };
    let stored: Value = row.get(0);
    if stored.as_object().is_some_and(Map::is_empty) {
        return Ok(None);
    }
    let result: registry_review_protocol::ReviewResult =
        serde_json::from_value(stored).map_err(|_| MutationError::Unavailable)?;
    use registry_review_protocol::ReviewResultStatus as Status;
    if matches!(result.status, Status::Cancelled | Status::Superseded) {
        return Ok(None);
    }
    let mut decision = json!({
        "status": result.status,
        "decidedAt": result
            .completed_at
            .to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
    });
    if let Some(reason) = result.public_reason {
        decision["publicReason"] = json!(reason);
    }
    Ok(Some(decision))
}

async fn proposal_review_result(
    tx: &Transaction<'_>,
    document: &ProposalDocument,
) -> Result<Value, MutationError> {
    let row = tx
        .query_opt(
            "SELECT status,result_id,
        to_char(completed_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
        to_char(available_until AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
        available_until<=transaction_timestamp()
        FROM registry_internal.registry_proposal_review_results
        WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3",
            &[
                &document.action_id,
                &document.proposal_id,
                &document.header.submission_version,
            ],
        )
        .await
        .map_err(map_database_error)?;
    Ok(match row {
        None => json!({"state":"pending"}),
        Some(row) => {
            json!({"state":if row.get::<_,bool>(4){"expired".to_owned()}else{row.get::<_,String>(0)},
            "resultId":row.get::<_,Uuid>(1),"completedAt":row.get::<_,String>(2),"availableUntil":row.get::<_,String>(3)})
        }
    })
}

fn reference_input_entity<'a>(
    action: &'a CompiledAction,
    input: &str,
) -> Result<&'a str, MutationError> {
    action
        .inputs
        .iter()
        .find(|declared| declared.id == input)
        .and_then(|declared| match &declared.field_type {
            crate::contract::FieldTypeSource::Reference { target, .. } => Some(target.as_str()),
            _ => None,
        })
        .ok_or(MutationError::InvalidRequest)
}

fn verify_proposal_evidence(
    action: &CompiledAction,
    frozen: &crate::proposal_workflow::ProposalSnapshot,
    acquisitions: &[crate::action_evidence_client::VerifiedAcquisition],
) -> Result<(), MutationError> {
    let guards = frozen
        .application_preconditions()
        .map(|guards| guards.evidence.as_slice())
        .unwrap_or(&[]);
    if guards != action.commit_evidence.as_slice() {
        return Err(MutationError::PreconditionFailed);
    }
    crate::commit_evidence::verify(
        guards,
        frozen.inputs(),
        |input| {
            action.inputs.iter().any(|declared| {
                declared.id == input
                    && matches!(
                        declared.field_type,
                        crate::contract::FieldTypeSource::Timestamp
                    )
            })
        },
        acquisitions,
    )
}
fn validate_proposal_input(
    action: &CompiledAction,
    input: &Map<String, Value>,
) -> Result<Map<String, Value>, MutationError> {
    proposal_prepare::validate_inputs(action, input)?;
    Ok(input.clone())
}
fn input_targets(
    action: &CompiledAction,
    input: &Map<String, Value>,
) -> Result<Vec<(String, Uuid)>, MutationError> {
    proposal_prepare::input_target_bindings(action, input)?
        .into_iter()
        .map(|target| {
            Ok((
                target.record_type,
                Uuid::parse_str(target.record_id.as_str())
                    .map_err(|_| MutationError::InvalidRequest)?,
            ))
        })
        .collect()
}
fn transition_context(actor: &str) -> Result<TrustedTransitionContext, MutationError> {
    Ok(TrustedTransitionContext::from_verified_context(
        TrustedActorRef::from_verified_context(actor).map_err(workflow_error)?,
        TrustedTimestamp::from_server_clock(chrono::Utc::now().to_rfc3339())
            .map_err(workflow_error)?,
    ))
}
fn workflow_error(error: crate::proposal_workflow::WorkflowError) -> MutationError {
    match error {
        crate::proposal_workflow::WorkflowError::Rejected => MutationError::ProposalRejected,
        _ => MutationError::PreconditionFailed,
    }
}
fn verify_apply_binding(
    input: &ProposalMutationInput<'_>,
    frozen: &crate::proposal_workflow::ProposalSnapshot,
) -> Result<(), MutationError> {
    if input.submission_version != Some(frozen.version().get())
        || input.effect_digest != Some(frozen.effect_digest().as_str())
    {
        return Err(MutationError::PreconditionFailed);
    }
    Ok(())
}
fn verify_guard(
    guard: &crate::model::CompiledCommitGuard,
    input: &Map<String, Value>,
    row: &Map<String, Value>,
    timestamp: bool,
    actual_revision: i64,
    expected_revision: Option<i64>,
) -> Result<(), MutationError> {
    if guard.revision_unchanged {
        return if expected_revision == Some(actual_revision) && actual_revision > 0 {
            Ok(())
        } else {
            Err(MutationError::PreconditionFailed)
        };
    }
    if crate::commit_guard::guard_matches(
        guard,
        input,
        row,
        &chrono::Utc::now().format("%Y-%m-%d").to_string(),
        timestamp,
    ) {
        Ok(())
    } else {
        Err(MutationError::PreconditionFailed)
    }
}

fn proposal_read_fields(action: &CompiledAction, entity_id: &str) -> BTreeSet<String> {
    action
        .target_uses
        .iter()
        .filter(|target| target.entity_id == entity_id)
        .flat_map(|target| target.fields.iter().cloned())
        .chain(
            action
                .requires
                .iter()
                .filter(|guard| guard.entity_id == entity_id && !guard.field.is_empty())
                .map(|guard| guard.field.clone()),
        )
        .collect()
}
async fn load_proposal_row(
    tx: &Transaction<'_>,
    entity: &CompiledEntity,
    id: Uuid,
    lock: bool,
) -> Result<CurrentRow, MutationError> {
    let sql = format!(
        "SELECT {} FROM registry_data.{} WHERE record_id=$1 AND record_lifecycle='active'{}",
        returning_projection(entity),
        quote_identifier(&entity.physical_table),
        if lock { " FOR UPDATE" } else { "" }
    );
    let row = tx
        .query_opt(&sql, &[&id])
        .await
        .map_err(map_database_error)?
        .ok_or(MutationError::PreconditionFailed)?;
    row_to_current(entity, &row)
}

#[cfg(test)]
mod disclosure_tests {
    use super::*;
    fn coordinator(database: &str, activation: &str, key: u8, issuer: &str) -> MutationTransaction {
        let (audit, _capture) = crate::audit::test_support::capturing(
            registry_platform_audit::AuditProfile::production_from_secret_bytes(
                vec![key; 32].into(),
            )
            .unwrap(),
        );
        MutationTransaction::new(
            crate::postgres::RegistryLockKey::derive("proposal-test").unwrap(),
            std::time::Duration::from_secs(1),
            crate::postgres::ExpectedRegistryIdentity {
                package_id: "proposal-test".into(),
                database_id: database.into(),
                package_digest: "digest".into(),
                activation_id: activation.into(),
                schema_fingerprint: "schema".into(),
            },
            "instance",
            audit,
        )
        .with_idempotency_policy(crate::idempotency::IdempotencyPolicy::new(issuer, 7).unwrap())
    }
    #[test]
    fn proposal_actor_is_keyed_database_and_issuer_scoped_but_stable_across_activation() {
        let first = "00000000-0000-4000-8000-000000000001";
        let second = "00000000-0000-4000-8000-000000000002";
        let actor = coordinator("database-a", first, 1, "https://issuer.example")
            .proposal_actor("principal-canary")
            .unwrap();
        assert_eq!(
            actor,
            coordinator("database-a", second, 1, "https://issuer.example")
                .proposal_actor("principal-canary")
                .unwrap()
        );
        assert_ne!(
            actor,
            coordinator("database-b", first, 1, "https://issuer.example")
                .proposal_actor("principal-canary")
                .unwrap()
        );
        assert_ne!(
            actor,
            coordinator("database-a", first, 2, "https://issuer.example")
                .proposal_actor("principal-canary")
                .unwrap()
        );
        assert_ne!(
            actor,
            coordinator("database-a", first, 1, "https://other-issuer.example")
                .proposal_actor("principal-canary")
                .unwrap()
        );
        assert_ne!(
            actor,
            coordinator("database-a", first, 1, "https://issuer.example")
                .proposal_actor("other-principal")
                .unwrap()
        );
        assert!(!actor.contains("principal-canary"));
    }
    #[test]
    fn proposal_owner_is_database_scoped_and_survives_audit_key_rotation() {
        let activation = "00000000-0000-4000-8000-000000000001";
        let owner = coordinator("database-a", activation, 1, "https://issuer.example")
            .proposal_owner_reference("principal-canary");
        assert_eq!(
            owner,
            coordinator("database-a", activation, 2, "https://issuer.example")
                .proposal_owner_reference("principal-canary")
        );
        assert_ne!(
            owner,
            coordinator("database-b", activation, 1, "https://issuer.example")
                .proposal_owner_reference("principal-canary")
        );
        assert_ne!(
            owner,
            coordinator("database-a", activation, 1, "https://other-issuer.example")
                .proposal_owner_reference("principal-canary")
        );
        assert_ne!(
            owner,
            coordinator("database-a", activation, 1, "https://issuer.example")
                .proposal_owner_reference("other-principal")
        );
        assert!(!owner.contains("principal-canary"));
    }
    #[test]
    fn public_application_projection_never_discloses_internal_actor_reason_or_timestamps() {
        use crate::proposal_workflow::*;
        let receipt = ApplicationReceipt::restore(
            ApplicationId::new(Uuid::new_v4().to_string()).unwrap(),
            SubmissionVersion::new(1).unwrap(),
            ProposalDigest::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            TrustedActorRef::from_verified_context("actor-canary").unwrap(),
            TrustedTimestamp::from_server_clock("2026-10-14T00:00:00Z").unwrap(),
            vec![ApplicationResultLink::new(
                EntityId::new("target").unwrap(),
                RecordId::new(Uuid::new_v4().to_string()).unwrap(),
                RecordRevision::new(2).unwrap(),
            )],
            Some("reason-canary".into()),
            true,
        )
        .unwrap();
        let public = public_application(&receipt);
        assert_eq!(
            public
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(
                [
                    "applicationId",
                    "submissionVersion",
                    "effectDigest",
                    "resultLinks"
                ]
                .map(str::to_owned)
            )
        );
        let wire = serde_json::to_string(&public).unwrap();
        for forbidden in [
            "actor-canary",
            "reason-canary",
            "appliedBy",
            "appliedAt",
            "reasonPresent",
            "2026-10-14",
        ] {
            assert!(
                !wire.contains(forbidden),
                "private receipt member {forbidden}"
            );
        }
    }
}

#[cfg(test)]
mod turn_tests {
    use super::*;

    #[test]
    fn turn_follows_state_review_and_application() {
        let manual = json!({"mode":"manual","state":"pending"});
        let queued = json!({"mode":"automatic","state":"queued"});
        let retry = json!({"mode":"automatic","state":"blocked","recovery":"retry"});
        let correct = json!({"mode":"automatic","state":"blocked","recovery":"correct-input"});
        for state in ["applied", "cancelled", "rejected"] {
            assert_eq!(
                proposal_turn(state, false, ReviewProgress::NotRequired, &Value::Null),
                "nobody",
                "{state}"
            );
        }
        assert_eq!(
            proposal_turn("draft", false, ReviewProgress::NotRequired, &Value::Null),
            "party"
        );
        assert_eq!(
            proposal_turn("submitted", true, ReviewProgress::Pending, &manual),
            "party",
            "a blocked submission waits on its party"
        );
        for review in [ReviewProgress::Pending, ReviewProgress::Retrying] {
            assert_eq!(
                proposal_turn("submitted", false, review, &queued),
                "official"
            );
        }
        for review in [
            ReviewProgress::Failed,
            ReviewProgress::ApprovalExpired,
            ReviewProgress::Rejected,
            ReviewProgress::ChangesRequested,
            ReviewProgress::Answered,
            ReviewProgress::Ended,
        ] {
            assert_eq!(proposal_turn("submitted", false, review, &queued), "party");
        }
        for review in [ReviewProgress::NotRequired, ReviewProgress::Approved] {
            assert_eq!(
                proposal_turn("submitted", false, review, &manual),
                "official"
            );
            assert_eq!(proposal_turn("submitted", false, review, &queued), "nobody");
            assert_eq!(
                proposal_turn("submitted", false, review, &retry),
                "official"
            );
            assert_eq!(proposal_turn("submitted", false, review, &correct), "party");
        }
    }
}
