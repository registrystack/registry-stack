// SPDX-License-Identifier: Apache-2.0
//! PostgreSQL policies for the engine-owned Proposal path. The same compiled
//! Action ceiling drives preparation, inspection, and frozen application.

use super::*;
use crate::model::{CompiledActionExecution, ProposalOperation};

const CONTEXT: &str =
    "NULLIF(current_setting('registry.proposal_target_context', true), '')::jsonb";

pub(super) fn target_policies(
    entity: &CompiledEntity,
    actions: &CompiledActionInventory,
) -> Vec<DdlPolicy> {
    let mut result = Vec::new();
    for action in &actions.actions {
        let CompiledActionExecution::Proposal { proposal } = &action.execution else {
            continue;
        };
        for grant in &action.permissions {
            if !grant.operations.contains(&Operation::Start) {
                continue;
            }
            let Some(target) = grant
                .targets
                .iter()
                .find(|target| target.entity_id == entity.id)
            else {
                continue;
            };
            add_read_policies(
                &mut result,
                entity,
                action,
                &grant.profile_id,
                &grant.required_purposes,
                &target.row_boundaries,
                "preparation",
                "start",
            );
        }
        for grant in &proposal.permissions {
            let Some(target) = grant
                .targets
                .iter()
                .find(|target| target.entity_id == entity.id)
            else {
                continue;
            };
            for operation in &grant.operations {
                let name = match operation {
                    ProposalOperation::Get => "get",
                    ProposalOperation::List => "list",
                    ProposalOperation::Edit => "edit",
                    ProposalOperation::Submit => "submit",
                    ProposalOperation::Revise => "revise",
                    ProposalOperation::Rebase => "rebase",
                    ProposalOperation::Retry => "retry",
                    ProposalOperation::Cancel => "cancel",
                    ProposalOperation::Apply => "apply",
                    ProposalOperation::GetReviewContext => "get-review-context",
                    ProposalOperation::GetTaskGrantContext => "get-task-grant-context",
                    ProposalOperation::GetReviewStatus => "get-review-status",
                    ProposalOperation::GetApplicationActor => continue,
                };
                add_read_policies(
                    &mut result,
                    entity,
                    action,
                    &grant.profile_id,
                    &grant.required_purposes,
                    &target.row_boundaries,
                    "inspection",
                    name,
                );
                if matches!(
                    operation,
                    ProposalOperation::Edit | ProposalOperation::Submit | ProposalOperation::Rebase
                ) {
                    add_read_policies(
                        &mut result,
                        entity,
                        action,
                        &grant.profile_id,
                        &grant.required_purposes,
                        &target.row_boundaries,
                        "preparation",
                        name,
                    );
                }
                if *operation == ProposalOperation::Apply {
                    add_application_policies(
                        &mut result,
                        entity,
                        action,
                        &grant.profile_id,
                        &grant.required_purposes,
                        &target.row_boundaries,
                    );
                }
            }
        }
        if let Some(grant) = &proposal.system_apply_grant {
            add_system_policies(&mut result, entity, action, grant);
        }
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn common(
    entity: &CompiledEntity,
    action: &CompiledAction,
    profile: &str,
    purposes: &BTreeSet<String>,
    boundaries: &[crate::contract::RowBoundarySource],
    phase: &str,
    authority_operation: &str,
) -> String {
    let mut expressions = vec![
        format!("jsonb_typeof({CONTEXT}) = 'object'"),
        format!("{CONTEXT} ->> 'version' = '1'"),
        format!("{CONTEXT} ->> 'actorKind' = 'caller'"),
        format!("{CONTEXT} ->> 'actionId' = {}", quote_literal(&action.id)),
        format!(
            "{CONTEXT} ->> 'actionRevision' = {}",
            quote_literal(&action.definition_revision)
        ),
        format!("{CONTEXT} ->> 'phase' = {}", quote_literal(phase)),
        format!(
            "{CONTEXT} ->> 'authorityOperation' = {}",
            quote_literal(authority_operation)
        ),
        format!(
            "{CONTEXT} ->> 'selectedAccessProfile' = {}",
            quote_literal(profile)
        ),
        format!(
            "{CONTEXT} ->> 'selectedAccessProfile' = NULLIF(current_setting('registry.access_profile', true), '')"
        ),
        format!(
            "{CONTEXT} ->> 'principal' = NULLIF(current_setting('registry.principal', true), '')"
        ),
        format!("NULLIF(current_setting('registry.principal', true), '') IS NOT NULL"),
        format!(
            "({CONTEXT} ->> 'purpose') IS NOT DISTINCT FROM NULLIF(current_setting('registry.purpose', true), '')"
        ),
        format!(
            "{CONTEXT} ->> 'targetEntityId' = {}",
            quote_literal(&entity.id)
        ),
        format!("{CONTEXT} ->> 'targetRecordId' = record_id::text"),
        format!(
            "({CONTEXT} ->> 'proposalId') ~* '^[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}$'"
        ),
        format!("({CONTEXT} ->> 'submissionVersion')::bigint BETWEEN 1 AND 4294967295"),
        format!("record_lifecycle = 'active'"),
        target_boundary_expression(CONTEXT, "rowBoundaries", entity, boundaries),
    ];
    if !purposes.is_empty() {
        expressions.push(format!(
            "NULLIF(current_setting('registry.purpose', true), '') IN ({})",
            purposes
                .iter()
                .map(|purpose| quote_literal(purpose))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    expressions.join(" AND ")
}

#[allow(clippy::too_many_arguments)]
fn add_read_policies(
    result: &mut Vec<DdlPolicy>,
    entity: &CompiledEntity,
    action: &CompiledAction,
    profile: &str,
    purposes: &BTreeSet<String>,
    boundaries: &[crate::contract::RowBoundarySource],
    phase: &str,
    authority_operation: &str,
) {
    let expression = format!(
        "({}) AND {CONTEXT} ->> 'operation' = 'get'",
        common(
            entity,
            action,
            profile,
            purposes,
            boundaries,
            phase,
            authority_operation
        )
    );
    result.push(DdlPolicy {
        name: policy_name(
            action,
            entity,
            profile,
            phase,
            authority_operation,
            PolicyCommand::Select,
        ),
        command: PolicyCommand::Select,
        access_profile: profile.to_owned(),
        applies_to: ordinary_policy_role(entity),
        using_expression: Some(expression.clone()),
        check_expression: None,
    });
    // PostgreSQL requires UPDATE permission for a row lock. This policy can
    // only lock the authorized row; it can never write through the read path.
    result.push(DdlPolicy {
        name: policy_name(
            action,
            entity,
            profile,
            phase,
            authority_operation,
            PolicyCommand::Update,
        ),
        command: PolicyCommand::Update,
        access_profile: profile.to_owned(),
        applies_to: ordinary_policy_role(entity),
        using_expression: Some(expression),
        check_expression: Some("false".to_owned()),
    });
}

fn add_application_policies(
    result: &mut Vec<DdlPolicy>,
    entity: &CompiledEntity,
    action: &CompiledAction,
    profile: &str,
    purposes: &BTreeSet<String>,
    boundaries: &[crate::contract::RowBoundarySource],
) {
    let base = common(
        entity,
        action,
        profile,
        purposes,
        boundaries,
        "application",
        "apply",
    );
    let read = format!(
        "({base}) AND {CONTEXT} ->> 'operation' = 'get' AND ({})",
        frozen_read_target_expression(false)
    );
    result.push(DdlPolicy {
        name: policy_name(
            action,
            entity,
            profile,
            "application",
            "get",
            PolicyCommand::Select,
        ),
        command: PolicyCommand::Select,
        access_profile: profile.to_owned(),
        applies_to: ordinary_policy_role(entity),
        using_expression: Some(read.clone()),
        check_expression: None,
    });
    result.push(DdlPolicy {
        name: policy_name(
            action,
            entity,
            profile,
            "application",
            "get",
            PolicyCommand::Update,
        ),
        command: PolicyCommand::Update,
        access_profile: profile.to_owned(),
        applies_to: ordinary_policy_role(entity),
        using_expression: Some(read),
        check_expression: Some("false".to_owned()),
    });
    for operation in [Operation::Create, Operation::Patch] {
        let mut fields = BTreeSet::new();
        let mut targets_operation = false;
        for effect in &action.effects {
            if effect.target.entity_id == entity.id && effect.operation == operation {
                targets_operation = true;
                fields.extend(effect.mutations.iter().map(|mutation| match mutation {
                    CompiledPlanMutation::Set { field, .. }
                    | CompiledPlanMutation::Clear { field } => field.clone(),
                }));
            }
        }
        if let Some(function) = &action.handler {
            for write in &function.writes {
                if write.ceiling.target_entity_id == entity.id
                    && write.ceiling.operation == operation
                {
                    targets_operation = true;
                    fields.extend(write.ceiling.fields.iter().cloned());
                }
            }
        }
        if operation == Operation::Create && targets_operation {
            fields.extend(entity.generated_fields().map(|field| field.id.clone()));
        }
        if fields.is_empty() {
            continue;
        }
        let fields_json =
            serde_json::to_string(&fields).expect("compiled field identifiers serialize");
        let frozen = frozen_target_expression(operation);
        let bounded = format!(
            "({base}) AND ({frozen}) AND {CONTEXT} ->> 'operation' = {} AND jsonb_typeof({CONTEXT} -> 'fields') = 'array' AND ({CONTEXT} -> 'fields') <@ {}::jsonb",
            quote_literal(operation_name(operation)),
            quote_literal(&fields_json)
        );
        let suffix = operation_name(operation);
        result.push(DdlPolicy {
            name: policy_name(
                action,
                entity,
                profile,
                "application",
                suffix,
                PolicyCommand::Select,
            ),
            command: PolicyCommand::Select,
            access_profile: profile.to_owned(),
            applies_to: ordinary_policy_role(entity),
            using_expression: Some(bounded.clone()),
            check_expression: None,
        });
        let command = if operation == Operation::Create {
            PolicyCommand::Insert
        } else {
            PolicyCommand::Update
        };
        result.push(DdlPolicy {
            name: policy_name(action, entity, profile, "application", suffix, command),
            command,
            access_profile: profile.to_owned(),
            applies_to: ordinary_policy_role(entity),
            using_expression: (operation == Operation::Patch).then(|| {
                format!(
                    "({bounded}) AND record_revision = ({CONTEXT} ->> 'expectedRevision')::bigint"
                )
            }),
            check_expression: Some(bounded),
        });
    }
}

fn frozen_read_target_expression(applied: bool) -> String {
    let states = if applied {
        "IN ('submitted', 'applied')"
    } else {
        "= 'submitted'"
    };
    format!("EXISTS (
        SELECT 1 FROM registry_internal.registry_proposal_state AS p_state
        JOIN registry_internal.registry_proposal_submissions AS p_frozen
          ON p_frozen.action_id=p_state.action_id AND p_frozen.proposal_id=p_state.proposal_id
         AND p_frozen.submission_version=p_state.submission_version
        WHERE p_state.action_id=({CONTEXT} ->> 'actionId')
          AND p_state.proposal_id=({CONTEXT} ->> 'proposalId')::uuid
          AND p_state.submission_version=({CONTEXT} ->> 'submissionVersion')::bigint
          AND p_state.state {states} AND p_state.blocked_reason IS NULL AND p_state.detail_erased_at IS NULL
          AND p_state.action_revision=COALESCE({CONTEXT} ->> 'frozenActionRevision', {CONTEXT} ->> 'actionRevision')
          AND p_frozen.contract_fingerprint=COALESCE({CONTEXT} ->> 'frozenActionRevision', {CONTEXT} ->> 'actionRevision')
          AND p_frozen.effect_digest=({CONTEXT} ->> 'effectDigest') AND p_frozen.erased_at IS NULL
          AND (p_state.action_revision=({CONTEXT} ->> 'actionRevision') OR EXISTS (
              SELECT 1 FROM registry_internal.registry_proposal_activation_compatibility c
              JOIN registry_internal.registry_state active ON active.singleton
              JOIN registry_internal.registry_proposal_review_submissions q
                ON q.action_id=c.action_id AND q.proposal_id=c.proposal_id
               AND q.submission_version=c.submission_version
              WHERE c.action_id=p_frozen.action_id AND c.proposal_id=p_frozen.proposal_id
                AND c.submission_version=p_frozen.submission_version AND c.effect_digest=p_frozen.effect_digest
                AND c.frozen_action_revision=p_state.action_revision
                AND c.current_action_revision=({CONTEXT} ->> 'actionRevision')
                AND c.frozen_system_grant_revision IS NOT DISTINCT FROM (p_frozen.snapshot ->> 'systemGrantRevision')
                AND ({CONTEXT} ->> 'actorKind'='caller' OR
                     c.current_system_grant_revision=({CONTEXT} ->> 'systemGrantRevision'))
                AND c.candidate_package_digest=active.active_package_digest
                AND c.activation_id=active.active_activation_id
                AND c.expected_policy=q.expected_policy AND c.accepted_binding=q.accepted_binding
                AND NOT q.withdrawn
          ))
          AND ({CONTEXT} ->> 'actorKind'='caller' OR (
              p_frozen.snapshot ->> 'systemGrantRevision'=COALESCE({CONTEXT} ->> 'frozenSystemGrantRevision', {CONTEXT} ->> 'systemGrantRevision')
              AND p_frozen.effect_digest=({CONTEXT} ->> 'frozenSubmissionDigest')
          ))
          AND (EXISTS (
              SELECT 1 FROM registry_internal.registry_proposal_targets AS p_target
              WHERE p_target.action_id=p_frozen.action_id AND p_target.proposal_id=p_frozen.proposal_id
                AND p_target.submission_version=p_frozen.submission_version
                AND p_target.target_entity_id=({CONTEXT} ->> 'targetEntityId')
                AND p_target.target_record_id=({CONTEXT} ->> 'targetRecordId')::uuid
                AND p_target.erased_at IS NULL
          ) OR EXISTS (
              SELECT 1 FROM jsonb_array_elements(p_frozen.snapshot -> 'inputTargets') AS p_input(value)
              WHERE p_input.value ->> 'recordType'=({CONTEXT} ->> 'targetEntityId')
                AND p_input.value ->> 'recordId'=({CONTEXT} ->> 'targetRecordId')
          ))
    )")
}

fn frozen_target_expression(operation: Operation) -> String {
    format!("EXISTS (
        SELECT 1 FROM registry_internal.registry_proposal_state AS p_state
        JOIN registry_internal.registry_proposal_submissions AS p_frozen
          ON p_frozen.action_id=p_state.action_id AND p_frozen.proposal_id=p_state.proposal_id
         AND p_frozen.submission_version=p_state.submission_version
        JOIN registry_internal.registry_proposal_targets AS p_target
          ON p_target.action_id=p_frozen.action_id AND p_target.proposal_id=p_frozen.proposal_id
         AND p_target.submission_version=p_frozen.submission_version
        WHERE p_state.action_id=({CONTEXT} ->> 'actionId')
          AND p_state.proposal_id=({CONTEXT} ->> 'proposalId')::uuid
          AND p_state.submission_version=({CONTEXT} ->> 'submissionVersion')::bigint
          AND p_state.state='submitted' AND p_state.blocked_reason IS NULL AND p_state.detail_erased_at IS NULL
          AND p_state.action_revision=COALESCE({CONTEXT} ->> 'frozenActionRevision', {CONTEXT} ->> 'actionRevision')
          AND p_frozen.contract_fingerprint=COALESCE({CONTEXT} ->> 'frozenActionRevision', {CONTEXT} ->> 'actionRevision')
          AND p_frozen.effect_digest=({CONTEXT} ->> 'effectDigest') AND p_frozen.erased_at IS NULL
          AND (p_state.action_revision=({CONTEXT} ->> 'actionRevision') OR EXISTS (
              SELECT 1 FROM registry_internal.registry_proposal_activation_compatibility c
              JOIN registry_internal.registry_state active ON active.singleton
              JOIN registry_internal.registry_proposal_review_submissions q
                ON q.action_id=c.action_id AND q.proposal_id=c.proposal_id
               AND q.submission_version=c.submission_version
              WHERE c.action_id=p_frozen.action_id AND c.proposal_id=p_frozen.proposal_id
                AND c.submission_version=p_frozen.submission_version AND c.effect_digest=p_frozen.effect_digest
                AND c.frozen_action_revision=p_state.action_revision
                AND c.current_action_revision=({CONTEXT} ->> 'actionRevision')
                AND c.frozen_system_grant_revision IS NOT DISTINCT FROM (p_frozen.snapshot ->> 'systemGrantRevision')
                AND ({CONTEXT} ->> 'actorKind'='caller' OR
                     c.current_system_grant_revision=({CONTEXT} ->> 'systemGrantRevision'))
                AND c.candidate_package_digest=active.active_package_digest
                AND c.activation_id=active.active_activation_id
                AND c.expected_policy=q.expected_policy AND c.accepted_binding=q.accepted_binding
                AND NOT q.withdrawn
          ))
          AND ({CONTEXT} ->> 'actorKind'='caller' OR (
              p_frozen.snapshot ->> 'systemGrantRevision'=COALESCE({CONTEXT} ->> 'frozenSystemGrantRevision', {CONTEXT} ->> 'systemGrantRevision')
              AND p_frozen.effect_digest=({CONTEXT} ->> 'frozenSubmissionDigest')
          ))
          AND p_target.target_entity_id=({CONTEXT} ->> 'targetEntityId')
          AND p_target.target_record_id=({CONTEXT} ->> 'targetRecordId')::uuid
          AND p_target.operation={} AND p_target.erased_at IS NULL
          AND p_target.expected_revision IS NOT DISTINCT FROM ({CONTEXT} ->> 'expectedRevision')::bigint
    )", quote_literal(operation_name(operation)))
}

fn add_system_policies(
    result: &mut Vec<DdlPolicy>,
    entity: &CompiledEntity,
    action: &CompiledAction,
    grant: &crate::model::CompiledSystemApplyGrant,
) {
    const PROFILE: &str = "system-proposal-apply";
    let targets = grant
        .targets
        .iter()
        .filter(|target| target.entity_id == entity.id)
        .collect::<Vec<_>>();
    if targets.is_empty() {
        return;
    }
    let base = [
        format!("jsonb_typeof({CONTEXT}) = 'object'"),
        format!("{CONTEXT} ->> 'version' = '1'"),
        format!("{CONTEXT} ->> 'actorKind' = 'system'"),
        format!("{CONTEXT} ->> 'actionId' = {}", quote_literal(&action.id)),
        format!("{CONTEXT} ->> 'actionRevision' = {}", quote_literal(&action.definition_revision)),
        format!("{CONTEXT} ->> 'systemGrantRevision' = {}", quote_literal(&grant.revision)),
        format!("{CONTEXT} ->> 'selectedAccessProfile' = '{PROFILE}'"),
        format!("NULLIF(current_setting('registry.access_profile', true), '') = '{PROFILE}'"),
        format!("{CONTEXT} ->> 'principal' = 'urn:registrystack:breg:system:proposal-apply'"),
        "NULLIF(current_setting('registry.principal', true), '') = 'urn:registrystack:breg:system:proposal-apply'".to_owned(),
        "NULLIF(current_setting('registry.purpose', true), '') IS NULL".to_owned(),
        format!("{CONTEXT} ->> 'purpose' IS NULL"),
        format!("{CONTEXT} -> 'rowBoundaries' = '[]'::jsonb"),
        format!("{CONTEXT} ->> 'authorityOperation' = 'apply'"),
        format!("{CONTEXT} ->> 'targetEntityId' = {}", quote_literal(&entity.id)),
        format!("{CONTEXT} ->> 'targetRecordId' = record_id::text"),
        "record_lifecycle = 'active'".to_owned(),
    ].join(" AND ");
    let read_fields = targets
        .iter()
        .flat_map(|target| &target.read_fields)
        .cloned()
        .collect::<BTreeSet<_>>();
    let read_fields = serde_json::to_string(&read_fields).expect("compiled fields serialize");
    for phase in ["inspection", "application"] {
        let read = format!(
            "({base}) AND {CONTEXT} ->> 'phase' = {} AND {CONTEXT} ->> 'operation' = 'get' AND jsonb_typeof({CONTEXT} -> 'fields') = 'array' AND ({CONTEXT} -> 'fields') <@ {}::jsonb AND ({})",
            quote_literal(phase),
            quote_literal(&read_fields),
            frozen_read_target_expression(true)
        );
        for command in [PolicyCommand::Select, PolicyCommand::Update] {
            result.push(DdlPolicy {
                name: policy_name(action, entity, PROFILE, phase, "get", command),
                command,
                access_profile: PROFILE.to_owned(),
                applies_to: ordinary_policy_role(entity),
                using_expression: Some(read.clone()),
                check_expression: (command == PolicyCommand::Update).then(|| "false".to_owned()),
            });
        }
    }
    for operation in [Operation::Create, Operation::Patch] {
        let fields = targets
            .iter()
            .filter(|target| target.operation == operation)
            .flat_map(|target| &target.fields)
            .cloned()
            .collect::<BTreeSet<_>>();
        if fields.is_empty() {
            continue;
        }
        let fields = serde_json::to_string(&fields).expect("compiled fields serialize");
        let bounded = format!(
            "({base}) AND {CONTEXT} ->> 'phase' = 'application' AND {CONTEXT} ->> 'operation' = {} AND jsonb_typeof({CONTEXT} -> 'fields') = 'array' AND ({CONTEXT} -> 'fields') <@ {}::jsonb AND ({})",
            quote_literal(operation_name(operation)),
            quote_literal(&fields),
            frozen_target_expression(operation)
        );
        result.push(DdlPolicy {
            name: policy_name(
                action,
                entity,
                PROFILE,
                "application",
                operation_name(operation),
                PolicyCommand::Select,
            ),
            command: PolicyCommand::Select,
            access_profile: PROFILE.to_owned(),
            applies_to: ordinary_policy_role(entity),
            using_expression: Some(bounded.clone()),
            check_expression: None,
        });
        let command = if operation == Operation::Create {
            PolicyCommand::Insert
        } else {
            PolicyCommand::Update
        };
        result.push(DdlPolicy {
            name: policy_name(
                action,
                entity,
                PROFILE,
                "application",
                operation_name(operation),
                command,
            ),
            command,
            access_profile: PROFILE.to_owned(),
            applies_to: ordinary_policy_role(entity),
            using_expression: (operation == Operation::Patch).then(|| {
                format!(
                    "({bounded}) AND record_revision = ({CONTEXT} ->> 'expectedRevision')::bigint"
                )
            }),
            check_expression: Some(bounded),
        });
    }
}

fn policy_name(
    action: &CompiledAction,
    entity: &CompiledEntity,
    profile: &str,
    phase: &str,
    operation: &str,
    command: PolicyCommand,
) -> String {
    let mut hash = Sha256::new();
    hash.update(b"breg/proposal-target-rls/v1");
    for value in [
        &action.id,
        &entity.id,
        profile,
        phase,
        operation,
        command.as_sql(),
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    // PostgreSQL truncates identifiers after 63 bytes. Keep the complete
    // generated name below that boundary so installation and verification
    // compare exactly the same policy identity.
    format!("registry_proposal_{}", hex_prefix(&hash.finalize(), 20))
}
