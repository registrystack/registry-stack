// SPDX-License-Identifier: Apache-2.0

//! Proposal grants are independent from Action start and record CRUD grants.

use super::*;
use crate::model::{CompiledActionExecution, ProposalOperation, ProposalOwnership};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProposalAuthorityOperation {
    Start,
    Lifecycle(ProposalOperation),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProposalTargetPhase {
    Preparation,
    Application,
    Inspection,
}

/// Constructed only after authenticated HTTP admission. The database layer
/// independently checks the selected compiled grant and finite target ceiling.
#[derive(Clone)]
pub(crate) struct ProposalAuthority {
    pub(crate) common: ActionClaimContext,
    pub(crate) operation: ProposalAuthorityOperation,
    pub(crate) ownership: Option<ProposalOwnership>,
    pub(crate) targets: BTreeMap<String, Vec<RowBoundaryContext>>,
    pub(crate) task_grant: Option<crate::task_grant::TaskGrantBinding>,
    pub(crate) proposal_scope: Option<BTreeSet<Uuid>>,
    system: Option<SystemApplyAuthority>,
}

#[derive(Clone)]
struct SystemApplyAuthority {
    grant: crate::model::CompiledSystemApplyGrant,
    frozen_action_revision: String,
    frozen_system_grant_revision: String,
    proposal_id: Uuid,
    submission_version: u32,
    digest: String,
    read_targets: BTreeSet<(String, Uuid)>,
    writes: BTreeMap<(String, Uuid), (Operation, BTreeSet<String>)>,
}

impl ProposalAuthority {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_compiled(
        registry: &CompiledRegistry,
        action_id: &str,
        operation: ProposalAuthorityOperation,
        principal: &str,
        profile: &str,
        purpose: Option<&str>,
        targets: BTreeMap<String, Vec<RowBoundaryContext>>,
    ) -> Result<Self> {
        let action = registry
            .actions()
            .actions
            .iter()
            .find(|a| a.id == action_id)
            .ok_or_else(invalid_context)?;
        let CompiledActionExecution::Proposal { proposal } = &action.execution else {
            return Err(invalid_context());
        };
        let ownership;
        let expected = match operation {
            ProposalAuthorityOperation::Start => {
                let permission = action
                    .permissions
                    .iter()
                    .find(|p| p.profile_id == profile && p.operations.contains(&Operation::Start))
                    .ok_or_else(invalid_context)?;
                ownership = None;
                permission
                    .targets
                    .iter()
                    .map(|t| (t.entity_id.as_str(), &t.row_boundaries))
                    .collect::<BTreeMap<_, _>>()
            }
            ProposalAuthorityOperation::Lifecycle(operation) => {
                let permission = proposal
                    .permissions
                    .iter()
                    .find(|p| p.profile_id == profile && p.operations.contains(&operation))
                    .ok_or_else(invalid_context)?;
                ownership = permission.ownership;
                permission
                    .targets
                    .iter()
                    .map(|t| (t.entity_id.as_str(), &t.row_boundaries))
                    .collect::<BTreeMap<_, _>>()
            }
        };
        if targets.len() != expected.len() {
            return Err(invalid_context());
        }
        for (entity_id, boundaries) in &targets {
            validate_target_boundaries(
                registry,
                entity_id,
                boundaries,
                expected
                    .get(entity_id.as_str())
                    .ok_or_else(invalid_context)?,
            )?;
        }
        Ok(Self {
            common: ActionClaimContext::new(
                action_id.to_owned(),
                principal.to_owned(),
                profile.to_owned(),
                purpose.map(str::to_owned),
                BTreeSet::new(),
            )?,
            operation,
            ownership,
            targets,
            task_grant: None,
            proposal_scope: None,
            system: None,
        })
    }

    pub(crate) async fn for_system(
        transaction: &tokio_postgres::Transaction<'_>,
        expected: &ExpectedRegistryIdentity,
        registry: &CompiledRegistry,
        action_id: &str,
        proposal_id: Uuid,
        frozen: &crate::proposal_workflow::ProposalSnapshot,
    ) -> Result<Self> {
        frozen
            .verify_digest(&crate::proposal_workflow::ProposalKey::new(
                crate::proposal_workflow::EntityId::new(action_id)
                    .map_err(|_| invalid_context())?,
                crate::proposal_workflow::RecordId::new(proposal_id.to_string())
                    .map_err(|_| invalid_context())?,
            ))
            .map_err(|_| invalid_context())?;
        let action = registry
            .actions()
            .actions
            .iter()
            .find(|action| action.id == action_id)
            .ok_or_else(invalid_context)?;
        let CompiledActionExecution::Proposal { proposal } = &action.execution else {
            return Err(invalid_context());
        };
        let grant = proposal
            .system_apply_grant
            .as_ref()
            .ok_or_else(invalid_context)?;
        if !proposal.application.is_automatic()
            || grant.action_id != action.id
            || grant.action_revision != action.definition_revision
            || !crate::proposal_retention::submission_is_compatible(
                transaction,
                expected,
                registry.registry_id(),
                action,
                proposal_id,
                frozen,
            )
            .await
            .map_err(|_| invalid_context())?
            || (frozen.contract_fingerprint().as_str() == action.definition_revision
                && frozen.system_grant_revision() != Some(grant.revision.as_str()))
        {
            return Err(invalid_context());
        }
        let mut reads = BTreeSet::new();
        let mut writes = BTreeMap::new();
        for target in frozen.input_targets() {
            reads.insert((
                target.record_type.clone(),
                Uuid::parse_str(target.record_id.as_str()).map_err(|_| invalid_context())?,
            ));
        }
        for effect in frozen.effects() {
            let target = effect.target();
            let id = target
                .existing_record_id()
                .or_else(|| target.reserved_record_id())
                .ok_or_else(invalid_context)?;
            let id = Uuid::parse_str(id.as_str()).map_err(|_| invalid_context())?;
            let fields = effect
                .field_changes()
                .iter()
                .map(|change| change.field().as_str().to_owned())
                .collect::<BTreeSet<_>>();
            if !grant.targets.iter().any(|allowed| {
                allowed.entity_id == target.entity_id().as_str()
                    && allowed.operation == effect.operation()
                    && fields.is_subset(&allowed.fields)
            }) {
                return Err(invalid_context());
            }
            let entry = writes
                .entry((target.entity_id().as_str().to_owned(), id))
                .or_insert((effect.operation(), BTreeSet::new()));
            if entry.0 != effect.operation() {
                return Err(invalid_context());
            }
            entry.1.extend(fields);
            if effect.operation() == Operation::Patch {
                reads.insert((target.entity_id().as_str().to_owned(), id));
            }
        }
        if let Some(guards) = frozen.application_preconditions() {
            for target in &guards.targets {
                reads.insert((
                    target.entity_id.clone(),
                    Uuid::parse_str(target.record_id.as_str()).map_err(|_| invalid_context())?,
                ));
            }
        }
        if reads.iter().any(|(entity, _)| {
            !grant
                .targets
                .iter()
                .any(|target| target.entity_id == *entity)
        }) {
            return Err(invalid_context());
        }
        let targets = grant
            .targets
            .iter()
            .map(|target| (target.entity_id.clone(), Vec::new()))
            .collect();
        Ok(Self {
            common: ActionClaimContext::new(
                action.id.clone(),
                "urn:registrystack:breg:system:proposal-apply".to_owned(),
                "system-proposal-apply".to_owned(),
                None,
                BTreeSet::new(),
            )?,
            operation: ProposalAuthorityOperation::Lifecycle(ProposalOperation::Apply),
            ownership: None,
            targets,
            task_grant: None,
            proposal_scope: Some(BTreeSet::from([proposal_id])),
            system: Some(SystemApplyAuthority {
                grant: grant.clone(),
                proposal_id,
                frozen_action_revision: frozen.contract_fingerprint().as_str().into(),
                frozen_system_grant_revision: frozen
                    .system_grant_revision()
                    .ok_or_else(invalid_context)?
                    .into(),
                submission_version: frozen.version().get(),
                digest: frozen.effect_digest().as_str().to_owned(),
                read_targets: reads,
                writes,
            }),
        })
    }

    pub(crate) fn is_system(&self) -> bool {
        self.system.is_some()
    }
    pub(crate) fn system_grant_revision(&self) -> Option<&str> {
        self.system
            .as_ref()
            .map(|system| system.grant.revision.as_str())
    }
    pub(crate) fn frozen_digest(&self) -> Option<&str> {
        self.system.as_ref().map(|system| system.digest.as_str())
    }

    pub(crate) fn authorizes_snapshot(
        &self,
        entity: &crate::model::CompiledEntity,
        id: Uuid,
        snapshot: &serde_json::Map<String, Value>,
    ) -> Result<bool> {
        if let Some(system) = &self.system {
            return Ok(system.read_targets.contains(&(entity.id.clone(), id))
                || system.writes.contains_key(&(entity.id.clone(), id)));
        }
        let boundaries = self.targets.get(&entity.id).ok_or_else(invalid_context)?;
        snapshot_matches_boundaries(entity, snapshot, id, boundaries)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn install_target(
        &self,
        transaction: &tokio_postgres::Transaction<'_>,
        registry: &CompiledRegistry,
        proposal_id: Uuid,
        submission_version: u32,
        phase: ProposalTargetPhase,
        target_entity_id: &str,
        target_record_id: Uuid,
        operation: Operation,
        fields: &BTreeSet<String>,
        expected_revision: Option<i64>,
        effect_digest: Option<&str>,
    ) -> Result<()> {
        self.common.validate()?;
        let action = registry
            .actions()
            .actions
            .iter()
            .find(|a| a.id == self.common.action_id())
            .ok_or_else(invalid_context)?;
        let boundaries = self
            .targets
            .get(target_entity_id)
            .ok_or_else(invalid_context)?;
        let expected = match (phase, self.operation) {
            (ProposalTargetPhase::Preparation, ProposalAuthorityOperation::Start)
            | (
                ProposalTargetPhase::Preparation,
                ProposalAuthorityOperation::Lifecycle(ProposalOperation::Submit),
            )
            | (
                ProposalTargetPhase::Preparation,
                ProposalAuthorityOperation::Lifecycle(ProposalOperation::Edit),
            )
            | (
                ProposalTargetPhase::Preparation,
                ProposalAuthorityOperation::Lifecycle(ProposalOperation::Rebase),
            )
            | (ProposalTargetPhase::Inspection, ProposalAuthorityOperation::Lifecycle(_))
                if operation == Operation::Get =>
            {
                true
            }
            (
                ProposalTargetPhase::Application,
                ProposalAuthorityOperation::Lifecycle(ProposalOperation::Apply),
            ) if matches!(
                operation,
                Operation::Create | Operation::Patch | Operation::Get
            ) =>
            {
                true
            }
            _ => false,
        };
        let entity = registry
            .entities()
            .get(target_entity_id)
            .ok_or_else(invalid_context)?;
        if let Some(system) = &self.system {
            if proposal_id != system.proposal_id
                || submission_version != system.submission_version
                || effect_digest.is_some_and(|digest| digest != system.digest)
            {
                return Err(invalid_context());
            }
            let allowed = match operation {
                Operation::Get => {
                    system
                        .read_targets
                        .contains(&(target_entity_id.to_owned(), target_record_id))
                        || system
                            .writes
                            .contains_key(&(target_entity_id.to_owned(), target_record_id))
                }
                Operation::Create | Operation::Patch => system
                    .writes
                    .get(&(target_entity_id.to_owned(), target_record_id))
                    .is_some_and(|(allowed, ceiling)| *allowed == operation && fields == ceiling),
                _ => false,
            };
            let static_allowed = if operation == Operation::Get {
                let read_fields = system
                    .grant
                    .targets
                    .iter()
                    .filter(|target| target.entity_id == target_entity_id)
                    .flat_map(|target| &target.read_fields)
                    .cloned()
                    .collect::<BTreeSet<_>>();
                fields.is_subset(&read_fields)
            } else {
                system.grant.targets.iter().any(|target| {
                    target.entity_id == target_entity_id
                        && target.operation == operation
                        && fields.is_subset(&target.fields)
                })
            };
            if !allowed || !static_allowed {
                return Err(invalid_context());
            }
        }
        if !expected
            || submission_version == 0
            || fields.len() > MAX_TARGET_FIELDS
            || fields
                .iter()
                .any(|field| !entity.fields.contains_key(field))
        {
            return Err(invalid_context());
        }
        let frozen_action_revision = if let Some(system) = &self.system {
            Some(system.frozen_action_revision.clone())
        } else if phase == ProposalTargetPhase::Application {
            transaction
                .query_opt(
                    "SELECT action_revision FROM registry_internal.registry_proposal_state
                    WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3",
                    &[&action.id, &proposal_id, &i64::from(submission_version)],
                )
                .await?
                .map(|row| row.get::<_, String>(0))
        } else {
            None
        };
        let payload = json!({
            "version": 1, "actionId": action.id, "actionRevision": action.definition_revision,
            "actorKind":if self.is_system(){"system"}else{"caller"},
            "systemGrantRevision":self.system_grant_revision(),
            "frozenActionRevision":frozen_action_revision,
            "frozenSystemGrantRevision":self.system.as_ref().map(|system|system.frozen_system_grant_revision.as_str()),
            "frozenSubmissionDigest":self.system.as_ref().map(|system|system.digest.as_str()),
            "proposalId": proposal_id, "submissionVersion": submission_version,
            "expectedRevision": expected_revision, "effectDigest": effect_digest.or_else(||self.frozen_digest()),
            "authorityOperation": match self.operation {
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
                ProposalAuthorityOperation::Lifecycle(ProposalOperation::GetReviewStatus) => "get-review-status",
                ProposalAuthorityOperation::Lifecycle(ProposalOperation::GetReviewContext) => "get-review-context",
            },
            "phase": match phase {ProposalTargetPhase::Preparation=>"preparation",ProposalTargetPhase::Application=>"application",ProposalTargetPhase::Inspection=>"inspection"},
            "targetEntityId": target_entity_id, "targetRecordId": target_record_id,
            "operation": match operation {Operation::Get=>"get",Operation::Create=>"create",Operation::Patch=>"patch",_=>return Err(invalid_context())},
            "selectedAccessProfile": self.common.access_profile(),
            "principal": self.common.principal(), "purpose": self.common.purpose(),
            "rowBoundaries": boundaries.iter().map(|b| json!({"field":b.field(),"operator":b.operator().as_str(),"values":b.values()})).collect::<Vec<_>>(),
            "fields": fields,
        });
        let canonical = canonicalize_json(&payload).map_err(|_| invalid_context())?;
        if canonical.len() > MAX_BOUNDARY_CONTEXT_BYTES {
            return Err(invalid_context());
        }
        let canonical = String::from_utf8(canonical).map_err(|_| invalid_context())?;
        transaction
            .execute(
                "SELECT set_config('registry.proposal_target_context',$1,true)",
                &[&canonical],
            )
            .await?;
        Ok(())
    }
}

impl fmt::Debug for ProposalAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProposalAuthority")
            .field("common", &self.common)
            .field("operation", &self.operation)
            .field("ownership", &self.ownership)
            .field("target_count", &self.targets.len())
            .finish()
    }
}

/// Shared lock and active-package admission installs no target grant. Every
/// Proposal target is admitted separately through `install_target` above.
pub(crate) async fn begin_proposal_transaction<'a>(
    client: &'a mut Client,
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
    expected: &ExpectedRegistryIdentity,
    authority: &ProposalAuthority,
) -> Result<GuardedTransaction<'a>> {
    begin_action_transaction(client, lock_key, lock_timeout, expected, &authority.common).await
}
