// SPDX-License-Identifier: Apache-2.0

//! Revision-fenced durable Proposal transitions over one frozen neutral plan.
use super::*;
use crate::api::proposals::ProposalMutationInput;
use crate::model::{CompiledActionExecution,CompiledActionTargetUseSource,CompiledProposalReview,ProposalOperation,ProposalOwnership};
use crate::postgres::{begin_proposal_transaction,ProposalAuthority,ProposalAuthorityOperation,ProposalTargetPhase};
use crate::proposal_prepare::{self,ProposalTargetSnapshot};
use crate::proposal_store::{self,ProposalDocument};
use crate::proposal_workflow::{ApplicationId,ApplicationResultLink,ContractFingerprint,EntityId,
    ObservedTarget,PreparedApplication,ProposalDigest,ProposalKey,ProposalState,ProposalWorkflow,
    RecordId,RecordRevision,StateRevision,TrustedActorRef,TrustedTimestamp,TrustedTransitionContext};

pub(crate) enum ProposalApplyPreflight {
    Receipt(MutationOutcome),
    Continue(Option<(String,registry_review_client::ReviewRequestAccepted)>),
}

pub(crate) fn proposal_operation_name(operation:ProposalAuthorityOperation)->&'static str {
    match operation {
        ProposalAuthorityOperation::Start=>"start",
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::Get)=>"get",
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::List)=>"list",
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::Submit)=>"submit",
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::Revise)=>"revise",
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::Cancel)=>"cancel",
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::Apply)=>"apply",
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::GetReviewContext)=>"get-review-context",
    }
}

impl MutationCoordinator {
    pub(crate) async fn begin_proposal_audit(&self,input:&ProposalMutationInput<'_>)->Result<AuditRequest,MutationError> {
        let operation_id=format!("proposals.{}.{}",input.action_id,proposal_operation_name(input.operation));
        self.begin_action_boundary_audit(&input.authority.common,&operation_id,input.correlation).await
    }

    fn proposal_binding(&self,registry:&CompiledRegistry,input:&ProposalMutationInput<'_>)
        ->Result<crate::idempotency::ResolvedIdempotencyBinding,MutationError> {
        let action=proposal_action(registry,input.action_id)?;
        if input.authority.common.action_id()!=action.id || input.operation!=input.authority.operation {
            return Err(MutationError::InvalidRequest);
        }
        let route=match input.proposal_id {
            None=>action.route.clone(),Some(id)=>format!("/v1/proposals/{id}/{}",proposal_operation_name(input.operation)),
        };
        let digest=Sha256::digest(canonicalize_json(&json!({
            "proposalId":input.proposal_id,"operation":proposal_operation_name(input.operation),
            "ifMatch":input.expected_etag,"input":input.input,"proposalVersion":input.proposal_version,
            "effectDigest":input.effect_digest,"reason":input.reason,
            // A replaced worker lease cannot change the body of a spent apply.
            // Recovery retains the original body and is permitted only after
            // a committed receipt is found under current local authority.
            "executorLease":input.executor_lease,
        })).map_err(|_|MutationError::InvalidRequest)?).into();
        Ok(resolve_action_binding(self.audit.profile(),&self.idempotency,&ActionIdempotencyBinding {
            key:input.idempotency_key,context:&input.authority.common,method:HttpMethod::Post,route:&route,
            // Unrelated activations do not change this Action's exact meaning.
            package_revision:&action.definition_revision,action_contract_fingerprint:&action.definition_revision,
            target_authority:&input.authority.targets,result_effects:input.authority.common.result_effects(),
            canonical_request_digest:digest,answer_digest:None,
        })?)
    }

    pub(crate) fn proposal_actor(&self,principal:&str)->Result<String,MutationError> {
        let bytes=canonicalize_json(&json!({"issuer":self.idempotency.caller_issuer(),"principal":principal}))
            .map_err(|_|MutationError::Unavailable)?;
        Ok(format!("sha256:{}",hex_bytes(&Sha256::digest(bytes))))
    }

    pub(crate) fn proposal_etag(&self,document:&ProposalDocument,authority:&ProposalAuthority)->Result<String,MutationError> {
        let payload=json!({"action":document.action_id,"actionRevision":document.action_revision,
            "proposal":document.proposal_id,"version":document.header.proposal_version,
            "revision":document.header.workflow_revision,"profile":authority.common.access_profile(),
            "principal":authority.common.principal(),"purpose":authority.common.purpose(),
            "targets":authority.targets.iter().map(|(entity,boundaries)|json!({"entity":entity,
                "boundaries":boundaries.iter().map(|b|json!({"field":b.field(),"operator":b.operator().as_str(),"values":b.values()})).collect::<Vec<_>>()
            })).collect::<Vec<_>>()});
        let canonical=canonicalize_json(&payload).map_err(|_|MutationError::Unavailable)?;
        let digest=self.audit.profile().key_hasher().audit_reference_hash("breg-proposal-etag-v1",
            &document.action_revision,std::str::from_utf8(&canonical).map_err(|_|MutationError::Unavailable)?)
            .map_err(|_|MutationError::Unavailable)?;
        Ok(format!("\"breg-proposal-{digest}\""))
    }

    pub(crate) async fn authorize_proposal_document(
        &self,tx:&Transaction<'_>,registry:&CompiledRegistry,document:&ProposalDocument,
        authority:&ProposalAuthority,
    )->Result<(),MutationError> {
        if document.action_id!=authority.common.action_id()
            || (authority.ownership==Some(ProposalOwnership::Caller)
                && document.header.owner_reference!=self.proposal_actor(authority.common.principal())?) {
            return Err(MutationError::PreconditionFailed);
        }
        for (entity_id,id) in &document.input_targets {
            let entity=registry.entities().get(entity_id).ok_or(MutationError::PreconditionFailed)?;
            authority.install_target(tx,registry,document.proposal_id,
                u32::try_from(document.header.proposal_version).map_err(|_|MutationError::Unavailable)?,
                ProposalTargetPhase::Inspection,entity_id,*id,Operation::Get,
                &entity.fields.keys().cloned().collect(),None,None)
                .await.map_err(|_|MutationError::PreconditionFailed)?;
            let row=load_proposal_row(tx,entity,*id,false).await?;
            if !authority.authorizes_snapshot(entity,*id,&row.data).map_err(|_|MutationError::PreconditionFailed)? {
                return Err(MutationError::PreconditionFailed);
            }
        }
        if document.header.state=="submitted" && !document.header.current_proposal_erased {
            let targets=proposal_store::load_targets(tx,&document.action_id,document.proposal_id,
                document.header.proposal_version).await?;
            for target in targets.iter().filter(|target|target.operation==Operation::Create) {
                let entity=registry.entities().get(&target.entity_id).ok_or(MutationError::PreconditionFailed)?;
                if !authority.authorizes_snapshot(entity,target.record_id,&target.after)
                    .map_err(|_|MutationError::PreconditionFailed)? {
                    return Err(MutationError::PreconditionFailed);
                }
            }
        }
        Ok(())
    }

    pub(crate) async fn preflight_proposal_apply(
        &self,client:&mut Client,registry:&CompiledRegistry,input:&ProposalMutationInput<'_>,
    )->Result<ProposalApplyPreflight,MutationError> {
        let id=input.proposal_id.ok_or(MutationError::InvalidRequest)?;
        let binding=self.proposal_binding(registry,input)?;
        let guarded=begin_proposal_transaction(client,self.lock_key,self.lock_timeout,&self.expected,input.authority)
            .await.map_err(|_|MutationError::Unavailable)?;
        let tx=guarded.transaction();
        let document=proposal_store::load_document(tx,id,false).await?;
        self.authorize_proposal_document(tx,registry,&document,input.authority).await?;
        if let Some(stored)=lock_and_load(tx,&binding).await? {
            let StoredResultMetadata::Proposal {..}=stored.metadata else{return Err(MutationError::Unavailable);};
            let entry=self.proposal_terminal(input,&binding,&document,true,0)?;
            guarded.commit().await.map_err(|_|MutationError::Unavailable)?;
            self.audit.append(entry).await.map_err(|_|MutationError::Unavailable)?;
            return Ok(ProposalApplyPreflight::Receipt(MutationOutcome {response:stored.response,replayed:true}));
        }
        let action=proposal_action(registry,input.action_id)?;
        if document.blocked_reason.is_some() || document.action_revision!=action.definition_revision
            || document.header.state!="submitted" {
            return Err(MutationError::PreconditionFailed);
        }
        let workflow=proposal_store::load(tx,&document.action_id,id,false).await?;
        let proposal=workflow.current_proposal().ok_or(MutationError::PreconditionFailed)?;
        verify_apply_binding(input,proposal)?;
        let accepted=match proposal.review_requirement() {
            CompiledProposalReview::None=>None,
            CompiledProposalReview::Required {authority,policy,..}=>{
                let (stored_authority,accepted)=crate::review_store::load_accepted_binding(tx,&document.action_id,id,
                    document.header.proposal_version).await?;
                if *authority!=stored_authority || *policy!=accepted.policy {
                    return Err(MutationError::PreconditionFailed);
                }
                Some((stored_authority,accepted))
            }
        };
        guarded.commit().await.map_err(|_|MutationError::Unavailable)?;
        Ok(ProposalApplyPreflight::Continue(accepted))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn execute_proposal(
        &self,client:&mut Client,registry:&CompiledRegistry,input:ProposalMutationInput<'_>,
        review_evidence:Option<&crate::review_integration::AcceptedReviewEvidence>,
        deadline:tokio::time::Instant,
    )->Result<MutationOutcome,MutationError> {
        let action=proposal_action(registry,input.action_id)?;
        let binding=self.proposal_binding(registry,&input)?;
        let guarded=begin_proposal_transaction(client,self.lock_key,self.lock_timeout,&self.expected,input.authority)
            .await.map_err(|_|MutationError::Unavailable)?;
        guarded.set_statement_budget(deadline.saturating_duration_since(tokio::time::Instant::now()))
            .await.map_err(|_|MutationError::Unavailable)?;
        let tx=guarded.transaction();
        let existing=if let Some(id)=input.proposal_id {
            let document=proposal_store::load_document(tx,id,true).await?;
            self.authorize_proposal_document(tx,registry,&document,input.authority).await?;
            Some(document)
        } else {None};
        if let Some(stored)=lock_and_load(tx,&binding).await? {
            let StoredResultMetadata::Proposal {..}=stored.metadata else{return Err(MutationError::Unavailable);};
            let document=if let Some(document)=existing {document} else {
                let response:Value=serde_json::from_slice(stored.response.body()).map_err(|_|MutationError::Unavailable)?;
                let id=response.get("id").and_then(Value::as_str).and_then(|id|Uuid::parse_str(id).ok())
                    .ok_or(MutationError::Unavailable)?;
                let document=proposal_store::load_document(tx,id,false).await?;
                self.authorize_start_inputs(tx,registry,action,&document,input.authority).await?;
                document
            };
            let entry=self.proposal_terminal(&input,&binding,&document,true,0)?;
            guarded.commit().await.map_err(|_|MutationError::Unavailable)?;
            self.audit.append(entry).await.map_err(|_|MutationError::Unavailable)?;
            return Ok(MutationOutcome {response:stored.response,replayed:true});
        }
        let actor=self.proposal_actor(input.authority.common.principal())?;
        let mut result_count=0u16;
        let (id,from_state,transition)=match input.operation {
            ProposalAuthorityOperation::Start=>{
                if existing.is_some(){return Err(MutationError::InvalidRequest);}
                let values=validate_proposal_input(action,input.input.as_ref().ok_or(MutationError::InvalidRequest)?)?;
                let id=Uuid::new_v4();
                proposal_store::initialize_draft(tx,&action.id,id,&actor).await?;
                proposal_store::save_draft_input(tx,&action.id,id,&action.definition_revision,
                    action.display.label.as_deref(),&values).await?;
                let targets=input_targets(action,&values)?;
                proposal_store::save_input_targets(tx,&action.id,id,&targets).await?;
                let document=proposal_store::load_document(tx,id,false).await?;
                self.authorize_start_inputs(tx,registry,action,&document,input.authority).await?;
                (id,"none".to_owned(),"started")
            }
            ProposalAuthorityOperation::Lifecycle(operation)=>{
                let document=existing.as_ref().ok_or(MutationError::InvalidRequest)?;
                let id=document.proposal_id;
                if input.expected_etag!=Some(self.proposal_etag(document,input.authority)?.as_str()) {
                    return Err(MutationError::PreconditionFailed);
                }
                if operation!=ProposalOperation::Cancel && (document.blocked_reason.is_some()
                    || document.action_revision!=action.definition_revision) {
                    return Err(MutationError::PreconditionFailed);
                }
                let workflow=proposal_store::load(tx,&action.id,id,false).await?;
                let previous=i64::try_from(workflow.workflow_revision().get()).map_err(|_|MutationError::Unavailable)?;
                let context=transition_context(&actor)?;
                let (workflow,transition)=match operation {
                    ProposalOperation::Submit=>{
                        let values=document.input.as_ref().ok_or(MutationError::PreconditionFailed)?;
                        let values=validate_proposal_input(action,values)?;
                        let candidate=crate::action_handler::evaluate_plan_detailed(action,&values,deadline.into_std())
                            .map_err(|diagnostic|MutationError::ActionHandlerFailure(diagnostic.kind))?;
                        let effects=match candidate {crate::action_handler::ActionHandlerOutcome::Effects(effects)=>effects,
                            crate::action_handler::ActionHandlerOutcome::Refusal(refusal)=>return Err(MutationError::ActionRefusal(refusal))};
                        let creates=effects.iter().filter(|effect|effect.operation==Operation::Create)
                            .map(|effect|(effect.id.clone(),Uuid::new_v4())).collect();
                        let resolved=proposal_prepare::resolve_targets(registry,action,&values,effects,&creates)?;
                        let (bases,guards)=self.load_submission_bases(tx,registry,action,&document,
                            input.authority,&resolved,&values).await?;
                        let prepared=proposal_prepare::prepare(registry,action,&values,previous,
                            &self.expected.package_digest,&resolved,bases,guards)?;
                        for target in &prepared.targets {
                            let entity=registry.entities().get(&target.entity_id).ok_or(MutationError::InvalidRequest)?;
                            if !input.authority.authorizes_snapshot(entity,target.record_id,&target.after)
                                .map_err(|_|MutationError::PreconditionFailed)? {return Err(MutationError::PreconditionFailed);}
                        }
                        let workflow=workflow.submit(context,prepared.proposal).map_err(workflow_error)?.into_workflow();
                        proposal_store::save(tx,&action.id,id,previous,&workflow).await?;
                        proposal_store::save_targets(tx,&action.id,id,i64::from(workflow.current_version().get()),&prepared.targets).await?;
                        let frozen=workflow.current_proposal().ok_or(MutationError::Unavailable)?;
                        if matches!(frozen.review_requirement(),CompiledProposalReview::Required {..}) {
                            let authorities=self.review_authorities.as_ref().ok_or(MutationError::Unavailable)?;
                            crate::review_store::enqueue_submission(tx,registry,&action.id,id,frozen,&actor,
                                input.human_identity,authorities).await?;
                        } else if frozen.application_policy().is_automatic() {
                            crate::review_store::enqueue_automatic_application(tx,&action.id,id,frozen).await?;
                        }
                        (workflow,"submitted")
                    }
                    ProposalOperation::Revise=>{
                        let values=validate_proposal_input(action,input.input.as_ref().ok_or(MutationError::InvalidRequest)?)?;
                        let workflow=workflow.revise(context).map_err(workflow_error)?.into_workflow();
                        crate::review_store::schedule_cancellation(tx,&action.id,id,document.header.proposal_version).await?;
                        proposal_store::save(tx,&action.id,id,previous,&workflow).await?;
                        proposal_store::save_draft_input(tx,&action.id,id,&action.definition_revision,
                            action.display.label.as_deref(),&values).await?;
                        proposal_store::save_input_targets(tx,&action.id,id,&input_targets(action,&values)?).await?;
                        let replacement=proposal_store::load_document(tx,id,false).await?;
                        self.authorize_start_inputs(tx,registry,action,&replacement,input.authority).await?;
                        (workflow,"revised")
                    }
                    ProposalOperation::Cancel=>{
                        let workflow=workflow.cancel(context).map_err(workflow_error)?.into_workflow();
                        crate::review_store::schedule_cancellation(tx,&action.id,id,document.header.proposal_version).await?;
                        proposal_store::save(tx,&action.id,id,previous,&workflow).await?;
                        (workflow,"cancelled")
                    }
                    ProposalOperation::Apply=>{
                        let frozen=workflow.current_proposal().ok_or(MutationError::PreconditionFailed)?;
                        verify_apply_binding(&input,frozen)?;
                        self.verify_executor_lease(tx,&input,frozen).await?;
                        let targets=proposal_store::load_targets(tx,&action.id,id,document.header.proposal_version).await?;
                        proposal_prepare::validate_frozen_targets(frozen,&targets)?;
                        self.verify_frozen_guards(tx,registry,action,&document,input.authority,frozen).await?;
                        let application_id=Uuid::new_v4();
                        let (observed,links)=self.apply_frozen_proposal(tx,registry,&document,input.authority,frozen,
                            &targets,&binding,application_id).await?;
                        result_count=u16::try_from(links.len()).map_err(|_|MutationError::Unavailable)?;
                        let application=PreparedApplication::new(
                            ApplicationId::new(application_id.to_string()).map_err(workflow_error)?,links)
                            .map_err(workflow_error)?;
                        let workflow=workflow.apply(transition_context(&actor)?,
                            crate::proposal_workflow::ProposalVersion::new(input.proposal_version.ok_or(MutationError::InvalidRequest)?)
                                .map_err(workflow_error)?,
                            &ProposalDigest::new(input.effect_digest.ok_or(MutationError::InvalidRequest)?).map_err(workflow_error)?,
                            &ContractFingerprint::new(&action.definition_revision).map_err(workflow_error)?,
                            review_evidence,observed,application,input.reason.map(str::to_owned))
                            .map_err(workflow_error)?.into_workflow();
                        proposal_store::save(tx,&action.id,id,previous,&workflow).await?;
                        (workflow,"applied")
                    }
                    _=>return Err(MutationError::InvalidRequest),
                };
                let _=workflow;
                (id,document.header.state.clone(),transition)
            }
        };
        let document=proposal_store::load_document(tx,id,false).await?;
        let workflow=proposal_store::load(tx,&action.id,id,false).await?;
        let reference=record_reference(self.audit.profile(),&action.definition_revision,&id.to_string())?;
        let event_source=self.event_source();
        crate::proposal_events::insert_proposal_lifecycle_event(tx,crate::proposal_events::ProposalLifecycleEvent {
            action_id:&action.id,action_revision:&document.action_revision,proposal_id:id,
            version:workflow.current_version().get(),revision:workflow.workflow_revision().get(),
            from_state:&from_state,state:workflow.state().as_storage(),transition,
            effect_digest:workflow.current_proposal().map(|proposal|proposal.effect_digest().as_str()),
            reference:&reference,package_revision:&self.expected.activation_id,
            schema_fingerprint:&self.expected.schema_fingerprint,source:&event_source,
        }).await?;
        let value=self.proposal_public_value(tx,registry,&document,input.claims,input.authority).await?;
        let mut headers=BTreeMap::from([(PermittedResponseHeader::ContentType,b"application/json".to_vec()),
            (PermittedResponseHeader::Etag,self.proposal_etag(&document,input.authority)?.into_bytes())]);
        if input.operation==ProposalAuthorityOperation::Start {
            headers.insert(PermittedResponseHeader::Location,format!("/v1/proposals/{id}").into_bytes());
        }
        let held=HeldResponse::from_json(if input.operation==ProposalAuthorityOperation::Start{201}else{200},&value,headers)?;
        insert_result(tx,&binding,&StoredResultMetadata::Proposal {record_reference:reference,
            record_revision:document.header.workflow_revision,proposal_version:document.header.proposal_version,result_count},&held).await?;
        proposal_store::link_idempotency_result(tx,&binding.key_reference,&action.id,id,document.header.proposal_version).await?;
        let entry=self.proposal_terminal(&input,&binding,&document,false,result_count)?;
        if tokio::time::Instant::now()>=deadline {return Err(MutationError::Unavailable);}
        guarded.commit().await.map_err(|_|MutationError::CommitUnresolved)?;
        self.audit.append(entry).await.map_err(|_|MutationError::CommitUnresolved)?;
        Ok(MutationOutcome {response:held,replayed:false})
    }

    fn proposal_terminal(&self,input:&ProposalMutationInput<'_>,binding:&crate::idempotency::ResolvedIdempotencyBinding,
        document:&ProposalDocument,replayed:bool,count:u16)->Result<AuditEntry,MutationError> {
        Ok(action_terminal_entry(self.audit.profile(),TerminalAudit {
            grant:input.authority.common.grant_audit().cloned(),
            outcome:if replayed{TerminalAuditOutcome::Replayed}else{TerminalAuditOutcome::Committed},
            method:HttpMethod::Post,operation_id:format!("proposals.{}.{}",document.action_id,proposal_operation_name(input.operation)),
            entity_id:None,action_id:Some(document.action_id.clone()),package_revision:self.expected.activation_id.clone(),
            selected_access_profile:input.authority.common.access_profile().to_owned(),
            purpose_present:input.authority.common.purpose().is_some(),principal_reference:Some(binding.principal_reference.clone()),
            record_reference:None,record_revision:None,result_count:Some(usize::from(count)),field_set_reference:None,
            correlation:input.correlation.clone(),
        },&format!("proposal:{}:{}",document.proposal_id,document.header.workflow_revision))?)
    }

    async fn authorize_start_inputs(&self,tx:&Transaction<'_>,registry:&CompiledRegistry,action:&CompiledAction,
        document:&ProposalDocument,authority:&ProposalAuthority)->Result<(),MutationError> {
        for (entity_id,id) in &document.input_targets {
            let entity=registry.entities().get(entity_id).ok_or(MutationError::InvalidRequest)?;
            let phase=if matches!(authority.operation,ProposalAuthorityOperation::Start|ProposalAuthorityOperation::Lifecycle(ProposalOperation::Submit)) {
                ProposalTargetPhase::Preparation
            } else {ProposalTargetPhase::Inspection};
            authority.install_target(tx,registry,document.proposal_id,u32::try_from(document.header.proposal_version)
                .map_err(|_|MutationError::Unavailable)?,phase,entity_id,*id,Operation::Get,
                &entity.fields.keys().cloned().collect(),None,None).await.map_err(|_|MutationError::PreconditionFailed)?;
            let row=load_proposal_row(tx,entity,*id,false).await?;
            if !authority.authorizes_snapshot(entity,*id,&row.data).map_err(|_|MutationError::PreconditionFailed)? {
                return Err(MutationError::PreconditionFailed);
            }
        }
        let _=action;
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    async fn load_submission_bases(&self,tx:&Transaction<'_>,registry:&CompiledRegistry,action:&CompiledAction,
        document:&ProposalDocument,authority:&ProposalAuthority,resolved:&proposal_prepare::ResolvedProposalTargets,
        input:&Map<String,Value>) ->Result<(BTreeMap<(String,Uuid),(i64,Map<String,Value>)>,BTreeMap<String,(Uuid,i64,Map<String,Value>)>),MutationError> {
        let mut bases=BTreeMap::new();
        let mut guards=BTreeMap::new();
        let mut needed=resolved.records.iter().filter(|(_,operation)|**operation==Operation::Patch)
            .map(|(key,_)|key.clone()).collect::<BTreeSet<_>>();
        for guard in &action.requires {
            let id=input.get(&guard.input).and_then(Value::as_str).and_then(|id|Uuid::parse_str(id).ok())
                .ok_or(MutationError::InvalidRequest)?;
            needed.insert((guard.entity_id.clone(),id));
        }
        let mut rows=BTreeMap::new();
        for (entity_id,id) in needed {
            let entity=registry.entities().get(&entity_id).ok_or(MutationError::InvalidRequest)?;
            authority.install_target(tx,registry,document.proposal_id,u32::try_from(document.header.proposal_version)
                .map_err(|_|MutationError::Unavailable)?,ProposalTargetPhase::Preparation,&entity_id,id,Operation::Get,
                &entity.fields.keys().cloned().collect(),None,None).await.map_err(|_|MutationError::PreconditionFailed)?;
            let row=load_proposal_row(tx,entity,id,true).await?;
            if !authority.authorizes_snapshot(entity,id,&row.data).map_err(|_|MutationError::PreconditionFailed)? {return Err(MutationError::PreconditionFailed);}
            rows.insert((entity_id,id),(row.record_revision,row.data));
        }
        for ((entity,id),operation) in &resolved.records {
            if *operation==Operation::Patch {bases.insert((entity.clone(),*id),rows[&(entity.clone(),*id)].clone());}
        }
        for guard in &action.requires {
            let id=input.get(&guard.input).and_then(Value::as_str).and_then(|id|Uuid::parse_str(id).ok()).ok_or(MutationError::InvalidRequest)?;
            let (revision,row)=rows[&(guard.entity_id.clone(),id)].clone();
            verify_guard(guard,input,&row)?;
            guards.insert(guard.input.clone(),(id,revision,row));
        }
        Ok((bases,guards))
    }

    async fn verify_frozen_guards(&self,tx:&Transaction<'_>,registry:&CompiledRegistry,action:&CompiledAction,
        document:&ProposalDocument,authority:&ProposalAuthority,frozen:&crate::proposal_workflow::ProposalSnapshot)->Result<(),MutationError> {
        let Some(preconditions)=frozen.application_preconditions() else {
            return if action.requires.is_empty(){Ok(())}else{Err(MutationError::PreconditionFailed)};
        };
        if preconditions.contract!=action.requires {return Err(MutationError::PreconditionFailed);}
        preconditions.validate().map_err(workflow_error)?;
        let input=preconditions.input_values.clone().into_iter().collect();
        for target in &preconditions.targets {
            let entity=registry.entities().get(&target.entity_id).ok_or(MutationError::PreconditionFailed)?;
            let id=Uuid::parse_str(target.record_id.as_str()).map_err(|_|MutationError::PreconditionFailed)?;
            authority.install_target(tx,registry,document.proposal_id,frozen.version().get(),ProposalTargetPhase::Application,
                &entity.id,id,Operation::Get,&entity.fields.keys().cloned().collect(),Some(target.expected_revision),
                Some(frozen.effect_digest().as_str())).await.map_err(|_|MutationError::PreconditionFailed)?;
            let row=load_proposal_row(tx,entity,id,true).await?;
            if !authority.authorizes_snapshot(entity,id,&row.data).map_err(|_|MutationError::PreconditionFailed)? {return Err(MutationError::PreconditionFailed);}
            for guard in preconditions.contract.iter().filter(|guard|guard.input==target.id) {
                if guard.revision_unchanged && row.record_revision!=target.expected_revision {return Err(MutationError::PreconditionFailed);}
                verify_guard(guard,&input,&row.data)?;
            }
        }
        Ok(())
    }

    async fn verify_executor_lease(&self,tx:&Transaction<'_>,input:&ProposalMutationInput<'_>,
        frozen:&crate::proposal_workflow::ProposalSnapshot)->Result<(),MutationError> {
        let Some(lease)=&input.executor_lease else{return Ok(());};
        let executor=frozen.application_policy().executor().ok_or(MutationError::PreconditionFailed)?;
        let row=tx.query_opt("SELECT 1 FROM registry_internal.registry_proposal_application_jobs
            WHERE action_id=$1 AND proposal_id=$2 AND proposal_version=$3 AND job_id=$4
              AND claim_token=$5 AND executor=$6 AND state='applying'
              AND next_attempt_at>transaction_timestamp() FOR UPDATE",
            &[&input.action_id,&input.proposal_id,&i64::from(frozen.version().get()),&lease.job_id,&lease.claim_token,&executor])
            .await.map_err(map_database_error)?;
        if row.is_none(){return Err(MutationError::PreconditionFailed);}
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn apply_frozen_proposal(&self,tx:&Transaction<'_>,registry:&CompiledRegistry,document:&ProposalDocument,
        authority:&ProposalAuthority,frozen:&crate::proposal_workflow::ProposalSnapshot,targets:&[ProposalTargetSnapshot],
        binding:&crate::idempotency::ResolvedIdempotencyBinding,application_id:Uuid)
        ->Result<(Vec<ObservedTarget>,Vec<ApplicationResultLink>),MutationError> {
        let mut observed=Vec::new();
        let mut links=Vec::new();
        let mut rows=Vec::new();
        let mut ordered=Vec::new();
        let mut seen=BTreeSet::new();
        for effect in frozen.effects() {
            let target=effect.target();
            let id=target.existing_record_id().or_else(||target.reserved_record_id()).ok_or(MutationError::PreconditionFailed)?;
            let id=Uuid::parse_str(id.as_str()).map_err(|_|MutationError::PreconditionFailed)?;
            if seen.insert((target.entity_id().as_str().to_owned(),id)) {
                ordered.push(targets.iter().find(|t|t.entity_id==target.entity_id().as_str()&&t.record_id==id)
                    .ok_or(MutationError::PreconditionFailed)?);
            }
        }
        for target in ordered {
            let entity=registry.entities().get(&target.entity_id).ok_or(MutationError::PreconditionFailed)?;
            let fields=frozen.effects().iter().filter(|effect|effect.target().entity_id().as_str()==target.entity_id
                && effect.target().existing_record_id().or_else(||effect.target().reserved_record_id())
                    .is_some_and(|id|id.as_str()==target.record_id.to_string()))
                .flat_map(|effect|effect.field_changes().iter().map(|change|change.field().as_str().to_owned())).collect();
            if let Some(revision)=target.expected_revision {
                authority.install_target(tx,registry,document.proposal_id,frozen.version().get(),ProposalTargetPhase::Application,
                    &entity.id,target.record_id,Operation::Get,&entity.fields.keys().cloned().collect(),Some(revision),
                    Some(frozen.effect_digest().as_str())).await.map_err(|_|MutationError::PreconditionFailed)?;
                let current=load_proposal_row(tx,entity,target.record_id,true).await?;
                if current.record_revision!=revision || Some(&current.data)!=target.before.as_ref()
                    || !authority.authorizes_snapshot(entity,target.record_id,&current.data).map_err(|_|MutationError::PreconditionFailed)? {
                    return Err(MutationError::PreconditionFailed);
                }
                observed.push(ObservedTarget::existing(EntityId::new(&entity.id).map_err(workflow_error)?,
                    RecordId::new(target.record_id.to_string()).map_err(workflow_error)?,RecordRevision::new(revision).map_err(workflow_error)?));
            } else {
                observed.push(ObservedTarget::reserved_create_absent(EntityId::new(&entity.id).map_err(workflow_error)?,
                    RecordId::new(target.record_id.to_string()).map_err(workflow_error)?));
            }
            if !authority.authorizes_snapshot(entity,target.record_id,&target.after).map_err(|_|MutationError::PreconditionFailed)? {
                return Err(MutationError::PreconditionFailed);
            }
            authority.install_target(tx,registry,document.proposal_id,frozen.version().get(),ProposalTargetPhase::Application,
                &entity.id,target.record_id,target.operation,&fields,target.expected_revision,Some(frozen.effect_digest().as_str()))
                .await.map_err(|_|MutationError::PreconditionFailed)?;
            let current=write_plan_row(tx,entity,target.record_id,target.expected_revision,target.after.clone(),
                target.before.as_ref(),self.field_encryption.as_deref()).await?;
            let reference=record_reference(self.audit.profile(),&self.expected.activation_id,&current.record_id)?;
            let snapshot=canonical_snapshot(&current.data)?;
            insert_revision(tx,RevisionInsert {entity_id:&entity.id,record_id:current.record_uuid,
                record_reference:&reference,record_revision:current.record_revision,predecessor_revision:current.predecessor_revision,
                lifecycle:&current.record_lifecycle,package_revision:&self.expected.activation_id,
                operation_id:&format!("proposals.{}.apply",document.action_id),mutation_kind:mutation_kind(target.operation),
                principal_reference:&binding.principal_reference,request_reference:&binding.request_reference,snapshot:&snapshot}).await?;
            let deliveries=exact_entity_event_deliveries(registry,entity)?;
            let schemas=event_data_schemas(registry.registry_id(),entity,mutation_trigger(target.operation),&deliveries)?;
            let source=self.event_source();
            let application_reference=application_id.to_string();
            insert_configured_events(tx,entity,&deliveries,self.event_destinations.as_deref(),OutboxMutation {
                trigger:mutation_trigger(target.operation),application_reference:Some(&application_reference),entity_id:&entity.id,
                record_id:&current.record_id,record_reference:&reference,record_revision:current.record_revision,
                package_revision:&self.expected.activation_id,package_digest:&self.expected.package_digest,
                schema_fingerprint:&self.expected.schema_fingerprint,before:current.before_data.as_ref(),after:Some(&current.data),
                payload_retention:self.event_destinations.as_deref().map_or(Duration::from_secs(7*24*60*60),|d|d.payload_retention()),
                envelope:EnvelopeBinding {source:&source,data_schemas:&schemas,causation:None},
            }).await?;
            links.push(ApplicationResultLink::new(EntityId::new(&entity.id).map_err(workflow_error)?,
                RecordId::new(current.record_id.clone()).map_err(workflow_error)?,RecordRevision::new(current.record_revision).map_err(workflow_error)?));
            rows.push((entity.id.clone(),current.record_uuid,current.record_revision));
        }
        let members=rows.iter().map(|(entity,id,revision)|RevisionCommitMember {entity_id:entity,record_id:*id,record_revision:*revision}).collect::<Vec<_>>();
        allocate_revision_commit(tx,CommitAllocation {package_revision:&self.expected.activation_id,
            origin:CommitOrigin::Mutation {actor_reference:&binding.principal_reference,request_reference:&binding.request_reference},
            change_context:None,members:&members}).await?;
        Ok((observed,links))
    }

    pub(crate) async fn proposal_public_value(&self,tx:&Transaction<'_>,registry:&CompiledRegistry,
        document:&ProposalDocument,claims:&crate::api::VerifiedRequestClaims,current:&ProposalAuthority)->Result<Value,MutationError> {
        let action=proposal_action(registry,&document.action_id)?;
        let mut value=json!({"id":document.proposal_id,"actionId":document.action_id,
            "actionRevision":document.action_revision,"version":document.header.proposal_version,
            "revision":document.header.workflow_revision,"state":document.header.state,"links":{}});
        if let Some(title)=&document.action_title {value["title"]=json!(title);}
        if let Some(blocked)=&document.blocked_reason {value["blockedReason"]=json!(blocked);}
        let workflow=if document.header.current_proposal_erased{None}else{Some(proposal_store::load(tx,&document.action_id,document.proposal_id,false).await?)};
        if let Some(proposal)=workflow.as_ref().and_then(|workflow|workflow.current_proposal()) {
            value["effectDigest"]=json!(proposal.effect_digest().as_str());
            if let Some(review)=crate::review_store::read_projection(tx,&document.action_id,document.proposal_id,
                proposal,document.header.state=="submitted").await? {value["review"]=review;}
        }
        if let Some(application)=workflow.as_ref().and_then(|workflow|workflow.application()) {
            value["application"]=serde_json::to_value(application).map_err(|_|MutationError::Unavailable)?;
        }
        let operations=[("self",ProposalOperation::Get),("submit",ProposalOperation::Submit),
            ("revise",ProposalOperation::Revise),("cancel",ProposalOperation::Cancel),("apply",ProposalOperation::Apply),
            ("reviewContext",ProposalOperation::GetReviewContext)];
        for (name,operation) in operations {
            let CompiledActionExecution::Proposal {proposal}= &action.execution else{return Err(MutationError::Unavailable);};
            let profiles=std::iter::once(current.common.access_profile()).chain(proposal.permissions.iter().map(|p|p.profile_id.as_str()));
            let authority=profiles.filter_map(|profile|crate::api::proposals::authorize(registry,action,claims,Some(profile),
                ProposalAuthorityOperation::Lifecycle(operation))).next();
            let Some(authority)=authority else{continue;};
            if self.authorize_proposal_document(tx,registry,document,&authority).await.is_err(){continue;}
            let available=match operation {
                ProposalOperation::Get=>true,ProposalOperation::Submit=>document.header.state=="draft"&&document.blocked_reason.is_none(),
                ProposalOperation::Revise=>document.header.state=="submitted"&&document.blocked_reason.is_none(),
                ProposalOperation::Cancel=>matches!(document.header.state.as_str(),"draft"|"submitted"),
                ProposalOperation::Apply=>document.header.state=="submitted"&&document.blocked_reason.is_none(),
                ProposalOperation::GetReviewContext=>document.header.state=="submitted",ProposalOperation::List=>false,
            };
            if !available && !(operation==ProposalOperation::Apply&&document.header.state=="applied"){continue;}
            let path=match operation {ProposalOperation::Get=>format!("/v1/proposals/{}",document.proposal_id),
                ProposalOperation::GetReviewContext=>format!("/v1/proposals/{}/review-context",document.proposal_id),
                _=>format!("/v1/proposals/{}/{}",document.proposal_id,proposal_operation_name(authority.operation))};
            let mut link=json!({"method":if matches!(operation,ProposalOperation::Get|ProposalOperation::GetReviewContext){"GET"}else{"POST"},
                "path":path,"accessProfile":authority.common.access_profile(),"operation":proposal_operation_name(authority.operation),
                "availability":{"available":available,"observedRevision":document.header.workflow_revision}});
            if !matches!(operation,ProposalOperation::Get|ProposalOperation::GetReviewContext) {
                link["ifMatch"]=json!(self.proposal_etag(document,&authority)?);
            }
            if !available {link["availability"]["reason"]=json!("already-applied");link["availability"]["recovery"]=json!("receipt-only");}
            value["links"][name]=link;
        }
        Ok(value)
    }
}

fn proposal_action<'a>(registry:&'a CompiledRegistry,id:&str)->Result<&'a CompiledAction,MutationError> {
    let action=registry.actions().actions.iter().find(|action|action.id==id).ok_or(MutationError::InvalidRequest)?;
    if !action.execution.is_proposal(){return Err(MutationError::InvalidRequest);}
    Ok(action)
}
fn validate_proposal_input(action:&CompiledAction,input:&Map<String,Value>)->Result<Map<String,Value>,MutationError> {
    if input.keys().any(|id|!action.inputs.iter().any(|field|field.id==*id))
        || action.inputs.iter().any(|field|field.required&&!input.contains_key(&field.id)) {
        return Err(MutationError::InvalidRequest);
    }
    for (id,value) in input {
        let field=action.inputs.iter().find(|field|field.id==*id).ok_or(MutationError::InvalidRequest)?;
        if !validate_field_value(FieldValue::Json(value),&field.field_type){return Err(MutationError::InvalidRequest);}
    }
    Ok(input.clone())
}
fn input_targets(action:&CompiledAction,input:&Map<String,Value>)->Result<Vec<(String,Uuid)>,MutationError> {
    let mut targets=BTreeSet::new();
    for target in &action.target_uses {
        if let CompiledActionTargetUseSource::Input {input:id}=&target.source {
            if let Some(value)=input.get(id) {
                let id=value.as_str().and_then(|id|Uuid::parse_str(id).ok()).ok_or(MutationError::InvalidRequest)?;
                targets.insert((target.entity_id.clone(),id));
            }
        }
    }
    Ok(targets.into_iter().collect())
}
fn transition_context(actor:&str)->Result<TrustedTransitionContext,MutationError> {
    Ok(TrustedTransitionContext::from_verified_context(TrustedActorRef::from_verified_context(actor).map_err(workflow_error)?,
        TrustedTimestamp::from_server_clock(chrono::Utc::now().to_rfc3339()).map_err(workflow_error)?))
}
fn workflow_error(_:crate::proposal_workflow::WorkflowError)->MutationError {MutationError::PreconditionFailed}
fn verify_apply_binding(input:&ProposalMutationInput<'_>,frozen:&crate::proposal_workflow::ProposalSnapshot)->Result<(),MutationError> {
    if input.proposal_version!=Some(frozen.version().get())||input.effect_digest!=Some(frozen.effect_digest().as_str()) {
        return Err(MutationError::PreconditionFailed);
    }
    Ok(())
}
fn verify_guard(guard:&crate::model::CompiledCommitGuard,input:&Map<String,Value>,row:&Map<String,Value>)->Result<(),MutationError> {
    if guard.field.is_empty(){return Ok(());}
    let actual=row.get(&guard.field).ok_or(MutationError::PreconditionFailed)?;
    let expected=guard.equals.as_ref().or_else(||guard.equals_input.as_ref().and_then(|id|input.get(id)))
        .ok_or(MutationError::PreconditionFailed)?;
    if actual!=expected{return Err(MutationError::PreconditionFailed);}
    Ok(())
}
async fn load_proposal_row(tx:&Transaction<'_>,entity:&CompiledEntity,id:Uuid,lock:bool)->Result<CurrentRow,MutationError> {
    let sql=format!("SELECT {} FROM registry_data.{} WHERE record_id=$1 AND record_lifecycle='active'{}",
        returning_projection(entity),quote_identifier(&entity.physical_table),if lock{" FOR UPDATE"}else{""});
    let row=tx.query_opt(&sql,&[&id]).await.map_err(map_database_error)?.ok_or(MutationError::PreconditionFailed)?;
    row_to_current(entity,&row)
}
