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
pub(crate) enum ProposalTargetPhase { Preparation, Application, Inspection }

/// Constructed only after authenticated HTTP admission. The database layer
/// independently checks the selected compiled grant and finite target ceiling.
#[derive(Clone)]
pub(crate) struct ProposalAuthority {
    pub(crate) common: ActionClaimContext,
    pub(crate) operation: ProposalAuthorityOperation,
    pub(crate) ownership: Option<ProposalOwnership>,
    pub(crate) targets: BTreeMap<String, Vec<RowBoundaryContext>>,
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
        let action = registry.actions().actions.iter().find(|a| a.id == action_id)
            .ok_or_else(invalid_context)?;
        let CompiledActionExecution::Proposal { proposal } = &action.execution else {
            return Err(invalid_context());
        };
        let ownership;
        let expected = match operation {
            ProposalAuthorityOperation::Start => {
                let permission = action.permissions.iter().find(|p| p.profile_id == profile
                    && p.operations.contains(&Operation::Start)).ok_or_else(invalid_context)?;
                ownership = None;
                permission.targets.iter().map(|t| (t.entity_id.as_str(), &t.row_boundaries))
                    .collect::<BTreeMap<_, _>>()
            }
            ProposalAuthorityOperation::Lifecycle(operation) => {
                let permission = proposal.permissions.iter().find(|p| p.profile_id == profile
                    && p.operations.contains(&operation)).ok_or_else(invalid_context)?;
                ownership = permission.ownership;
                permission.targets.iter().map(|t| (t.entity_id.as_str(), &t.row_boundaries))
                    .collect::<BTreeMap<_, _>>()
            }
        };
        if targets.len() != expected.len() { return Err(invalid_context()); }
        for (entity_id, boundaries) in &targets {
            validate_target_boundaries(registry, entity_id, boundaries,
                expected.get(entity_id.as_str()).ok_or_else(invalid_context)?)?;
        }
        Ok(Self {
            common: ActionClaimContext::new(action_id.to_owned(), principal.to_owned(),
                profile.to_owned(), purpose.map(str::to_owned), BTreeSet::new())?,
            operation, ownership, targets,
        })
    }

    pub(crate) fn authorizes_snapshot(
        &self, entity: &crate::model::CompiledEntity, id: Uuid,
        snapshot: &serde_json::Map<String, Value>,
    ) -> Result<bool> {
        let boundaries = self.targets.get(&entity.id).ok_or_else(invalid_context)?;
        snapshot_matches_boundaries(entity, snapshot, id, boundaries)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn install_target(
        &self,
        transaction: &tokio_postgres::Transaction<'_>,
        registry: &CompiledRegistry,
        proposal_id: Uuid,
        proposal_version: u32,
        phase: ProposalTargetPhase,
        target_entity_id: &str,
        target_record_id: Uuid,
        operation: Operation,
        fields: &BTreeSet<String>,
        expected_revision: Option<i64>,
        effect_digest: Option<&str>,
    ) -> Result<()> {
        self.common.validate()?;
        let action = registry.actions().actions.iter().find(|a| a.id == self.common.action_id())
            .ok_or_else(invalid_context)?;
        let boundaries = self.targets.get(target_entity_id).ok_or_else(invalid_context)?;
        let expected = match (phase, self.operation) {
            (ProposalTargetPhase::Preparation, ProposalAuthorityOperation::Start)
            | (ProposalTargetPhase::Preparation, ProposalAuthorityOperation::Lifecycle(ProposalOperation::Submit))
            | (ProposalTargetPhase::Inspection, ProposalAuthorityOperation::Lifecycle(_))
                if operation == Operation::Get => true,
            (ProposalTargetPhase::Application, ProposalAuthorityOperation::Lifecycle(ProposalOperation::Apply))
                if matches!(operation, Operation::Create | Operation::Patch | Operation::Get) => true,
            _ => false,
        };
        let entity = registry.entities().get(target_entity_id).ok_or_else(invalid_context)?;
        if !expected || proposal_version == 0 || fields.len() > MAX_TARGET_FIELDS
            || fields.iter().any(|field| !entity.fields.contains_key(field)) {
            return Err(invalid_context());
        }
        let payload = json!({
            "version": 1, "actionId": action.id, "actionRevision": action.definition_revision,
            "proposalId": proposal_id, "proposalVersion": proposal_version,
            "expectedRevision": expected_revision, "effectDigest": effect_digest,
            "authorityOperation": match self.operation {
                ProposalAuthorityOperation::Start => "start",
                ProposalAuthorityOperation::Lifecycle(ProposalOperation::Get) => "get",
                ProposalAuthorityOperation::Lifecycle(ProposalOperation::List) => "list",
                ProposalAuthorityOperation::Lifecycle(ProposalOperation::Submit) => "submit",
                ProposalAuthorityOperation::Lifecycle(ProposalOperation::Revise) => "revise",
                ProposalAuthorityOperation::Lifecycle(ProposalOperation::Cancel) => "cancel",
                ProposalAuthorityOperation::Lifecycle(ProposalOperation::Apply) => "apply",
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
        if canonical.len() > MAX_BOUNDARY_CONTEXT_BYTES { return Err(invalid_context()); }
        let canonical = String::from_utf8(canonical).map_err(|_| invalid_context())?;
        transaction.execute("SELECT set_config('registry.proposal_target_context',$1,true)", &[&canonical]).await?;
        Ok(())
    }
}

impl fmt::Debug for ProposalAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProposalAuthority").field("common", &self.common)
            .field("operation", &self.operation).field("ownership", &self.ownership)
            .field("target_count", &self.targets.len()).finish()
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
