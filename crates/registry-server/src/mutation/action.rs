// SPDX-License-Identifier: Apache-2.0

use super::*;

use crate::api::{ActionTargetConditionsInput, HeldReadResponse, ImmediateActionInput};

type ActionInputs = Map<String, Value>;

struct ActionEffectResult {
    effect_id: String,
    entity_id: String,
    record_id: String,
    record_uuid: Uuid,
    record_revision: i64,
    record_reference: String,
    operation: Operation,
}

impl MutationCoordinator {
    pub(crate) async fn execute_immediate_action(
        &self,
        client: &mut Client,
        registry: &CompiledRegistry,
        input: ImmediateActionInput<'_>,
        claims: &ActionClaimContext,
        target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
        fault: FaultControl,
    ) -> Result<MutationOutcome, MutationError> {
        if !profile_is_keyed(&self.audit_profile) {
            return Err(MutationError::Unavailable);
        }
        let action = action_for_route(
            registry,
            input.action_id,
            input.route_id,
            ActionRouteKind::Invoke,
        )?;
        validate_action_claims(action, claims, Operation::Invoke)?;
        let normalized_input = validate_action_input(action, input.input)?;
        validate_precondition_set(action, &input.preconditions)?;
        self.record_action_boundary_audit(
            client,
            claims,
            input.route_id,
            input.correlation,
            PreIoAuditKind::Attempt,
        )
        .await?;
        let request_digest =
            canonical_action_request_digest(action, &normalized_input, &input.preconditions)?;
        let binding = resolve_action_binding(
            &self.audit_profile,
            &ActionIdempotencyBinding {
                key: input.idempotency_key,
                context: claims,
                method: HttpMethod::Post,
                route: &action.route,
                package_revision: &self.expected.package_revision,
                action_contract_fingerprint: &action.contract_fingerprint,
                target_authority,
                result_effects: claims.result_effects(),
                canonical_request_digest: request_digest,
            },
        )?;
        let reserved_creates = reserve_action_create_ids(action)?;
        let application_id = Uuid::new_v4();
        let mut retryable_attempts = 0;
        let result = loop {
            let attempt = self
                .execute_immediate_action_after_attempt(
                    client,
                    registry,
                    action,
                    claims,
                    target_authority,
                    &normalized_input,
                    &input.preconditions,
                    &binding,
                    &reserved_creates,
                    application_id,
                    input.route_id,
                    input.correlation,
                    fault,
                )
                .await;
            if matches!(attempt, Err(MutationError::RetryableConflict))
                && retryable_attempts < 2
                && !fault.is_enabled()
            {
                retryable_attempts += 1;
                continue;
            }
            break attempt;
        };
        if result.is_err() && !fault.is_enabled() {
            self.record_action_boundary_audit(
                client,
                claims,
                input.route_id,
                input.correlation,
                PreIoAuditKind::Refusal,
            )
            .await?;
        }
        result.map_err(|error| match error {
            MutationError::RetryableConflict => MutationError::Unavailable,
            other => other,
        })
    }

    pub(crate) async fn action_target_conditions(
        &self,
        client: &mut Client,
        registry: &CompiledRegistry,
        input: ActionTargetConditionsInput<'_>,
        claims: &ActionClaimContext,
        target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
    ) -> Result<HeldReadResponse, MutationError> {
        if !profile_is_keyed(&self.audit_profile) {
            return Err(MutationError::Unavailable);
        }
        let action = action_for_route(
            registry,
            input.action_id,
            input.route_id,
            ActionRouteKind::TargetConditions,
        )?;
        validate_action_claims(action, claims, Operation::Invoke)?;
        let refs = validate_condition_inputs(action, input.input)?;
        self.record_action_boundary_audit(
            client,
            claims,
            input.route_id,
            input.correlation,
            PreIoAuditKind::Attempt,
        )
        .await?;
        let result = self
            .action_target_conditions_after_attempt(
                client,
                registry,
                action,
                claims,
                target_authority,
                &refs,
                input.route_id,
                input.correlation,
            )
            .await;
        if result.is_err() {
            self.record_action_boundary_audit(
                client,
                claims,
                input.route_id,
                input.correlation,
                PreIoAuditKind::Refusal,
            )
            .await?;
        }
        result
    }

    async fn record_action_boundary_audit(
        &self,
        client: &mut Client,
        claims: &ActionClaimContext,
        operation_id: &str,
        correlation: &RequestCorrelation,
        kind: PreIoAuditKind,
    ) -> Result<(), MutationError> {
        record_action_pre_io_audit(
            client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            claims,
            &self.audit_profile,
            PreIoAudit {
                kind,
                method: HttpMethod::Post,
                operation_id,
                target_record: None,
                correlation,
            },
        )
        .await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_immediate_action_after_attempt(
        &self,
        client: &mut Client,
        registry: &CompiledRegistry,
        action: &CompiledAction,
        claims: &ActionClaimContext,
        target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
        input_values: &ActionInputs,
        preconditions: &BTreeMap<String, String>,
        binding: &crate::idempotency::ResolvedIdempotencyBinding,
        reserved_creates: &BTreeMap<String, Uuid>,
        application_id: Uuid,
        route_id: &str,
        correlation: &RequestCorrelation,
        fault: FaultControl,
    ) -> Result<MutationOutcome, MutationError> {
        let transaction = begin_action_transaction(
            client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            claims,
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;

        if let Some(stored) = lock_and_load(transaction.transaction(), binding).await? {
            let StoredResultMetadata::ImmediateAction { result_count } = stored.metadata else {
                return Err(MutationError::Unavailable);
            };
            self.authorize_stored_action_results(
                transaction.transaction(),
                registry,
                action,
                claims,
                target_authority,
                &binding.key_reference,
            )
            .await?;
            let application_reference = stored_action_application_reference(
                transaction.transaction(),
                &self.audit_profile,
                &binding.key_reference,
            )
            .await?;
            append_action_terminal_audit(
                transaction.transaction(),
                &self.audit_profile,
                TerminalAudit {
                    outcome: TerminalAuditOutcome::Replayed,
                    method: HttpMethod::Post,
                    operation_id: route_id.to_owned(),
                    entity_id: None,
                    action_id: Some(action.id.clone()),
                    package_revision: self.expected.package_revision.clone(),
                    selected_access_profile: claims.access_profile().to_owned(),
                    purpose_present: claims.purpose().is_some(),
                    principal_reference: Some(binding.principal_reference.clone()),
                    record_reference: None,
                    record_revision: None,
                    result_count: Some(usize::from(result_count)),
                    field_set_reference: None,
                    correlation: correlation.clone(),
                },
                &application_reference,
            )
            .await?;
            transaction
                .commit()
                .await
                .map_err(|_| MutationError::Unavailable)?;
            return Ok(MutationOutcome {
                response: stored.response,
                replayed: true,
            });
        }

        let application_reference = action_application_reference(
            &self.audit_profile,
            &self.expected.package_revision,
            application_id,
        )?;

        self.lock_existing_action_targets(
            transaction.transaction(),
            registry,
            action,
            claims,
            target_authority,
            input_values,
            application_id,
        )
        .await?;

        self.verify_action_link_references(
            transaction.transaction(),
            registry,
            action,
            claims,
            target_authority,
            input_values,
        )
        .await?;

        let patch_bases = self
            .lock_action_patch_targets(
                transaction.transaction(),
                registry,
                action,
                claims,
                target_authority,
                input_values,
                preconditions,
                application_id,
            )
            .await?;
        let ordered = ordered_action_effects(action)?;
        let groups = ordered_action_effect_groups(&ordered, &patch_bases, reserved_creates)?;
        let mut rows = BTreeMap::<String, CurrentRow>::new();
        let mut results = Vec::<ActionEffectResult>::new();
        for effects in groups {
            fault.fail_at(MutationFaultPoint::BeforeCurrentRow)?;
            let current = self
                .apply_action_effect_group(
                    transaction.transaction(),
                    registry,
                    action,
                    &effects,
                    claims,
                    target_authority,
                    input_values,
                    &patch_bases,
                    reserved_creates,
                    &rows,
                    application_id,
                )
                .await?;
            let effect = effects[0];
            let record_reference = record_reference(
                &self.audit_profile,
                &self.expected.package_revision,
                &current.record_id,
            )?;
            let snapshot = canonical_snapshot(&current.data)?;
            fault.fail_at(MutationFaultPoint::BeforeRevision)?;
            insert_revision(
                transaction.transaction(),
                RevisionInsert {
                    entity_id: &effect.target.entity_id,
                    record_id: current.record_uuid,
                    record_reference: &record_reference,
                    record_revision: current.record_revision,
                    predecessor_revision: current.predecessor_revision,
                    lifecycle: &current.record_lifecycle,
                    package_revision: &self.expected.package_revision,
                    operation_id: &effect.id,
                    mutation_kind: mutation_kind(effect.operation),
                    principal_reference: &binding.principal_reference,
                    request_reference: &application_reference,
                    snapshot: &snapshot,
                },
            )
            .await?;
            let entity = registry
                .entities()
                .get(&effect.target.entity_id)
                .ok_or(MutationError::InvalidRequest)?;
            fault.fail_at(MutationFaultPoint::BeforeOutbox)?;
            insert_configured_events(
                transaction.transaction(),
                &entity.events,
                &exact_entity_event_deliveries(registry, entity)?,
                self.event_destinations.as_deref(),
                OutboxMutation {
                    trigger: mutation_trigger(effect.operation),
                    application_reference: Some(&application_reference),
                    entity_id: &entity.id,
                    record_id: &current.record_id,
                    record_reference: &record_reference,
                    record_revision: current.record_revision,
                    package_revision: &self.expected.package_revision,
                    schema_fingerprint: &self.expected.schema_fingerprint,
                    before: current.before_data.as_ref(),
                    after: Some(&current.data),
                    payload_retention: self
                        .event_destinations
                        .as_deref()
                        .map_or(Duration::from_secs(7 * 24 * 60 * 60), |destinations| {
                            destinations.payload_retention()
                        }),
                },
            )
            .await?;
            for effect in effects {
                results.push(ActionEffectResult {
                    effect_id: effect.id.clone(),
                    entity_id: effect.target.entity_id.clone(),
                    record_id: current.record_id.clone(),
                    record_uuid: current.record_uuid,
                    record_revision: current.record_revision,
                    record_reference: record_reference.clone(),
                    operation: effect.operation,
                });
                rows.insert(effect.id.clone(), current.clone());
            }
        }

        let held = action_held_response(action, claims, application_id, &results)?;
        let public_result_count = u16::try_from(
            results
                .iter()
                .filter(|result| claims.result_effect_allowed(action, &result.effect_id))
                .count(),
        )
        .map_err(|_| MutationError::Unavailable)?;
        fault.fail_at(MutationFaultPoint::BeforeTerminalAudit)?;
        append_action_terminal_audit(
            transaction.transaction(),
            &self.audit_profile,
            TerminalAudit {
                outcome: TerminalAuditOutcome::Committed,
                method: HttpMethod::Post,
                operation_id: route_id.to_owned(),
                entity_id: None,
                action_id: Some(action.id.clone()),
                package_revision: self.expected.package_revision.clone(),
                selected_access_profile: claims.access_profile().to_owned(),
                purpose_present: claims.purpose().is_some(),
                principal_reference: Some(binding.principal_reference.clone()),
                record_reference: None,
                record_revision: None,
                result_count: Some(usize::from(public_result_count)),
                field_set_reference: None,
                correlation: correlation.clone(),
            },
            &application_reference,
        )
        .await?;
        fault.fail_at(MutationFaultPoint::BeforeIdempotency)?;
        insert_result(
            transaction.transaction(),
            binding,
            &StoredResultMetadata::ImmediateAction {
                result_count: public_result_count,
            },
            &held,
        )
        .await?;
        insert_action_application(
            transaction.transaction(),
            binding,
            action,
            application_id,
            &self.expected.package_revision,
            &binding.principal_reference,
            public_result_count,
        )
        .await?;
        insert_action_result_links(transaction.transaction(), binding, action, &results).await?;
        fault.fail_at(MutationFaultPoint::BeforeCommit)?;
        transaction
            .commit()
            .await
            .map_err(|_| MutationError::Unavailable)?;
        fault.fail_at(MutationFaultPoint::AfterCommitBeforeResponseRelease)?;
        Ok(MutationOutcome {
            response: held,
            replayed: false,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn apply_action_effect_group(
        &self,
        transaction: &Transaction<'_>,
        registry: &CompiledRegistry,
        action: &CompiledAction,
        effects: &[&CompiledActionEffect],
        claims: &ActionClaimContext,
        target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
        input_values: &ActionInputs,
        patch_bases: &BTreeMap<String, CurrentRow>,
        reserved_creates: &BTreeMap<String, Uuid>,
        prior_results: &BTreeMap<String, CurrentRow>,
        application_id: Uuid,
    ) -> Result<CurrentRow, MutationError> {
        let effect = *effects.first().ok_or(MutationError::InvalidRequest)?;
        let entity = registry
            .entities()
            .get(&effect.target.entity_id)
            .ok_or(MutationError::InvalidRequest)?;
        if effects.iter().any(|candidate| {
            candidate.target.entity_id != effect.target.entity_id
                || candidate.operation != effect.operation
        }) {
            return Err(MutationError::InvalidRequest);
        }
        if entity
            .change_control
            .as_ref()
            .is_some_and(|control| control.required_for.contains(&effect.operation))
            || entity.change_request.is_some()
        {
            return Err(MutationError::InvalidRequest);
        }
        let (record_uuid, expected_revision, before) = match &effect.target.binding {
            CompiledActionTargetBinding::Create => (
                *reserved_creates
                    .get(&effect.id)
                    .ok_or(MutationError::InvalidRequest)?,
                None,
                None,
            ),
            CompiledActionTargetBinding::Existing { .. } => {
                let base = patch_bases
                    .get(&effect.id)
                    .ok_or(MutationError::PreconditionFailed)?;
                (base.record_uuid, Some(base.record_revision), Some(base))
            }
        };
        let target_context = action_target_group_context(
            registry,
            action,
            effects,
            claims,
            target_authority,
            record_uuid,
            expected_revision,
            false,
            Some(application_id),
            &self.expected.package_revision,
        )?;
        transaction
            .execute(
                "SELECT set_config('registry.immediate_action_target_context', $1, true)",
                &[&target_context.canonical_context()],
            )
            .await
            .map_err(map_database_error)?;
        let mut fields = Map::new();
        for effect in effects {
            let effect_fields = action_effect_document(
                action,
                entity,
                effect,
                input_values,
                prior_results,
                before,
            )?;
            for (field, value) in effect_fields {
                if fields.insert(field, value).is_some() {
                    return Err(MutationError::InvalidRequest);
                }
            }
        }
        match effect.operation {
            Operation::Create => target_context
                .authorize_rows(entity, None, &fields, record_uuid)
                .map_err(|_| MutationError::PreconditionFailed)?,
            Operation::Patch => {
                let before = before.ok_or(MutationError::PreconditionFailed)?;
                let mut preview = before.data.clone();
                for (field, value) in &fields {
                    preview.insert(field.clone(), value.clone());
                }
                target_context
                    .authorize_rows(entity, Some(&before.data), &preview, record_uuid)
                    .map_err(|_| MutationError::PreconditionFailed)?;
            }
            _ => return Err(MutationError::InvalidRequest),
        }
        let mut current = match effect.operation {
            Operation::Create => {
                insert_action_create_row(transaction, entity, &record_uuid.to_string(), &fields)
                    .await?
            }
            Operation::Patch => {
                let before = before.ok_or(MutationError::PreconditionFailed)?;
                let mut next = apply_patch_row(
                    transaction,
                    entity,
                    &record_uuid.to_string(),
                    before.record_revision,
                    fields,
                )
                .await?;
                next.predecessor_revision = Some(before.record_revision);
                next.before_data = Some(before.data.clone());
                next
            }
            _ => return Err(MutationError::InvalidRequest),
        };
        target_context
            .authorize_rows(
                entity,
                current.before_data.as_ref(),
                &current.data,
                current.record_uuid,
            )
            .map_err(|_| MutationError::PreconditionFailed)?;
        if effect.operation == Operation::Create {
            current.predecessor_revision = None;
        }
        Ok(current)
    }

    #[allow(clippy::too_many_arguments)]
    async fn lock_existing_action_targets(
        &self,
        transaction: &Transaction<'_>,
        registry: &CompiledRegistry,
        action: &CompiledAction,
        claims: &ActionClaimContext,
        target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
        input_values: &ActionInputs,
        application_id: Uuid,
    ) -> Result<(), MutationError> {
        enum Role<'a> {
            Patch(&'a CompiledActionEffect),
            Link(&'a str),
        }

        // A row may be a patch target in one invocation and a link target in
        // another. Acquire the complete set in one order before either phase;
        // sorting each phase independently permits opposite-role deadlocks.
        let mut targets = BTreeMap::new();
        for effect in &action.effects {
            if let CompiledActionTargetBinding::Existing { input } = &effect.target.binding {
                let record_id = Uuid::parse_str(&input_record_id(input_values, input)?)
                    .map_err(|_| MutationError::InvalidRequest)?;
                targets
                    .entry((effect.target.entity_id.as_str(), record_id))
                    .or_insert(Role::Patch(effect));
            }
        }
        for target in &action.target_uses {
            if target.operation != Operation::Invoke
                || !target.fields.is_empty()
                || target.condition_required
            {
                continue;
            }
            if let crate::model::CompiledActionTargetUseSource::Input { input } = &target.source {
                let record_id = Uuid::parse_str(&input_record_id(input_values, input)?)
                    .map_err(|_| MutationError::InvalidRequest)?;
                targets
                    .entry((target.entity_id.as_str(), record_id))
                    .or_insert(Role::Link(input));
            }
        }
        for ((entity_id, record_id), role) in targets {
            let entity = registry
                .entities()
                .get(entity_id)
                .ok_or(MutationError::InvalidRequest)?;
            let (target_context, link_context) = match role {
                Role::Patch(effect) => (
                    action_target_context(
                        registry,
                        action,
                        effect,
                        claims,
                        target_authority,
                        record_id,
                        None,
                        true,
                        Some(application_id),
                        &self.expected.package_revision,
                    )?
                    .canonical_context()
                    .to_owned(),
                    String::new(),
                ),
                Role::Link(input) => (
                    String::new(),
                    action_link_context(
                        registry,
                        action,
                        input,
                        entity_id,
                        claims,
                        target_authority,
                        record_id,
                        &self.expected.package_revision,
                    )?
                    .canonical_context()
                    .to_owned(),
                ),
            };
            transaction
                .execute(
                    "SELECT set_config('registry.immediate_action_target_context', $1, true),
                            set_config('registry.immediate_action_link_context', $2, true)",
                    &[&target_context, &link_context],
                )
                .await
                .map_err(map_database_error)?;
            load_action_row(transaction, entity, &record_id.to_string(), true).await?;
        }
        transaction
            .execute(
                "SELECT set_config('registry.immediate_action_target_context', '', true),
                        set_config('registry.immediate_action_link_context', '', true)",
                &[],
            )
            .await
            .map_err(map_database_error)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn lock_action_patch_targets(
        &self,
        transaction: &Transaction<'_>,
        registry: &CompiledRegistry,
        action: &CompiledAction,
        claims: &ActionClaimContext,
        target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
        input_values: &ActionInputs,
        preconditions: &BTreeMap<String, String>,
        application_id: Uuid,
    ) -> Result<BTreeMap<String, CurrentRow>, MutationError> {
        let mut patch_effects = action
            .effects
            .iter()
            .filter_map(|effect| match &effect.target.binding {
                CompiledActionTargetBinding::Existing { input } => Some((input, effect)),
                CompiledActionTargetBinding::Create => None,
            })
            .collect::<Vec<_>>();
        patch_effects.sort_by(|left, right| {
            let left_id = input_record_id(input_values, left.0).unwrap_or_default();
            let right_id = input_record_id(input_values, right.0).unwrap_or_default();
            (&left.1.target.entity_id, left_id, &left.1.id).cmp(&(
                &right.1.target.entity_id,
                right_id,
                &right.1.id,
            ))
        });
        let mut bases = BTreeMap::new();
        for (input_id, effect) in patch_effects {
            let entity = registry
                .entities()
                .get(&effect.target.entity_id)
                .ok_or(MutationError::InvalidRequest)?;
            let record_id = input_record_id(input_values, input_id)?;
            let record_uuid =
                Uuid::parse_str(&record_id).map_err(|_| MutationError::InvalidRequest)?;
            let read_context = action_target_context(
                registry,
                action,
                effect,
                claims,
                target_authority,
                record_uuid,
                None,
                true,
                Some(application_id),
                &self.expected.package_revision,
            )?;
            transaction
                .execute(
                    "SELECT set_config('registry.immediate_action_target_context', $1, true)",
                    &[&read_context.canonical_context()],
                )
                .await
                .map_err(map_database_error)?;
            let current = load_action_row(transaction, entity, &record_id, true).await?;
            let token = action_condition_token(
                &self.audit_profile,
                registry.registry_id(),
                &action.id,
                input_id,
                &effect.target.entity_id,
                &current.record_id,
                current.record_revision,
            )?;
            let provided = preconditions
                .get(input_id)
                .ok_or(MutationError::InvalidRequest)?;
            if provided.as_bytes().ct_eq(token.as_bytes()).unwrap_u8() != 1 {
                return Err(MutationError::PreconditionFailed);
            }
            let target_context = action_target_context(
                registry,
                action,
                effect,
                claims,
                target_authority,
                current.record_uuid,
                Some(current.record_revision),
                false,
                None,
                &self.expected.package_revision,
            )?;
            target_context
                .authorize_rows(
                    entity,
                    Some(&current.data),
                    &current.data,
                    current.record_uuid,
                )
                .map_err(|_| MutationError::PreconditionFailed)?;
            bases.insert(effect.id.clone(), current);
        }
        Ok(bases)
    }

    #[allow(clippy::too_many_arguments)]
    async fn action_target_conditions_after_attempt(
        &self,
        client: &mut Client,
        registry: &CompiledRegistry,
        action: &CompiledAction,
        claims: &ActionClaimContext,
        target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
        refs: &BTreeMap<String, String>,
        route_id: &str,
        correlation: &RequestCorrelation,
    ) -> Result<HeldReadResponse, MutationError> {
        let transaction = begin_action_transaction(
            client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            claims,
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
        let mut conditions = serde_json::Map::new();
        for (input_id, record_id) in refs {
            let effect = action
                .effects
                .iter()
                .find(|effect| {
                    matches!(&effect.target.binding, CompiledActionTargetBinding::Existing { input } if input == input_id)
                })
                .ok_or(MutationError::InvalidRequest)?;
            let entity = registry
                .entities()
                .get(&effect.target.entity_id)
                .ok_or(MutationError::InvalidRequest)?;
            let record_uuid =
                Uuid::parse_str(record_id).map_err(|_| MutationError::InvalidRequest)?;
            let target_context = action_target_context(
                registry,
                action,
                effect,
                claims,
                target_authority,
                record_uuid,
                None,
                false,
                None,
                &self.expected.package_revision,
            )?;
            transaction
                .install_immediate_action_target_context(&target_context)
                .await
                .map_err(|_| MutationError::Unavailable)?;
            let current =
                load_action_row(transaction.transaction(), entity, record_id, false).await?;
            target_context
                .authorize_rows(
                    entity,
                    Some(&current.data),
                    &current.data,
                    current.record_uuid,
                )
                .map_err(|_| MutationError::PreconditionFailed)?;
            let input = action
                .inputs
                .iter()
                .find(|input| input.id == *input_id)
                .ok_or(MutationError::InvalidRequest)?;
            conditions.insert(
                input.api_name.clone(),
                json!({
                    "ifMatch": action_condition_token(
                        &self.audit_profile,
                        registry.registry_id(),
                        &action.id,
                        input_id,
                        &effect.target.entity_id,
                        &current.record_id,
                        current.record_revision,
                    )?,
                }),
            );
        }
        let held = HeldReadResponse::from_json(&json!({ "preconditions": conditions }))
            .map_err(|_| MutationError::Unavailable)?;
        append_terminal_audit(
            transaction.transaction(),
            &self.audit_profile,
            TerminalAudit {
                outcome: TerminalAuditOutcome::Returned,
                method: HttpMethod::Post,
                operation_id: route_id.to_owned(),
                entity_id: None,
                action_id: Some(action.id.clone()),
                package_revision: self.expected.package_revision.clone(),
                selected_access_profile: claims.access_profile().to_owned(),
                purpose_present: claims.purpose().is_some(),
                principal_reference: None,
                record_reference: None,
                record_revision: None,
                result_count: Some(conditions.len()),
                field_set_reference: None,
                correlation: correlation.clone(),
            },
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| MutationError::Unavailable)?;
        Ok(held)
    }

    async fn verify_action_link_references(
        &self,
        transaction: &Transaction<'_>,
        registry: &CompiledRegistry,
        action: &CompiledAction,
        claims: &ActionClaimContext,
        target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
        input_values: &ActionInputs,
    ) -> Result<(), MutationError> {
        let mut refs = Vec::new();
        for target_use in &action.target_uses {
            if target_use.operation == Operation::Invoke
                && target_use.fields.is_empty()
                && !target_use.condition_required
            {
                if let crate::model::CompiledActionTargetUseSource::Input { input } =
                    &target_use.source
                {
                    let record_id = input_record_id(input_values, input)?;
                    refs.push((target_use.entity_id.clone(), record_id, input, target_use));
                }
            }
        }
        refs.sort_by(|left, right| (&left.0, &left.1, left.2).cmp(&(&right.0, &right.1, right.2)));
        refs.dedup_by(|left, right| left.0 == right.0 && left.1 == right.1 && left.2 == right.2);
        for (entity_id, record_id, input_id, target_use) in refs {
            let entity = registry
                .entities()
                .get(&entity_id)
                .ok_or(MutationError::InvalidRequest)?;
            let record_uuid =
                Uuid::parse_str(&record_id).map_err(|_| MutationError::InvalidRequest)?;
            let link_context = action_link_context(
                registry,
                action,
                input_id,
                &target_use.entity_id,
                claims,
                target_authority,
                record_uuid,
                &self.expected.package_revision,
            )?;
            transaction
                .execute(
                    "SELECT set_config('registry.immediate_action_link_context', $1, true)",
                    &[&link_context.canonical_context()],
                )
                .await
                .map_err(map_database_error)?;
            let current = load_action_row(transaction, entity, &record_id, true).await?;
            link_context
                .authorize_row(entity, &current.data, current.record_uuid)
                .map_err(|_| MutationError::PreconditionFailed)?;
        }
        Ok(())
    }

    async fn authorize_stored_action_results(
        &self,
        transaction: &Transaction<'_>,
        registry: &CompiledRegistry,
        action: &CompiledAction,
        claims: &ActionClaimContext,
        target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
        key_reference: &str,
    ) -> Result<(), MutationError> {
        if claims.result_effects().is_empty() {
            return Ok(());
        }
        let rows = transaction
            .query(
                "SELECT effect_id, target_entity_id, target_record_id, target_record_revision
                   FROM registry_internal.registry_immediate_action_results
                  WHERE key_reference = $1
                  ORDER BY effect_id",
                &[&key_reference],
            )
            .await
            .map_err(map_database_error)?;
        for row in rows {
            let effect_id = row.get::<_, String>(0);
            let entity_id = row.get::<_, String>(1);
            let record_uuid = row.get::<_, Uuid>(2);
            let _revision = row.get::<_, i64>(3);
            if !claims.result_effect_allowed(action, &effect_id) {
                continue;
            }
            let effect = action
                .effects
                .iter()
                .find(|effect| effect.id == effect_id && effect.target.entity_id == entity_id)
                .ok_or(MutationError::Unavailable)?;
            let entity = registry
                .entities()
                .get(&entity_id)
                .ok_or(MutationError::Unavailable)?;
            let target_context = action_target_context(
                registry,
                action,
                effect,
                claims,
                target_authority,
                record_uuid,
                None,
                false,
                None,
                &self.expected.package_revision,
            )?;
            transaction
                .execute(
                    "SELECT set_config('registry.immediate_action_target_context', $1, true)",
                    &[&target_context.canonical_context()],
                )
                .await
                .map_err(map_database_error)?;
            let current =
                load_action_row(transaction, entity, &record_uuid.to_string(), false).await?;
            target_context
                .authorize_rows(
                    entity,
                    (effect.operation == Operation::Patch).then_some(&current.data),
                    &current.data,
                    current.record_uuid,
                )
                .map_err(|_| MutationError::PreconditionFailed)?;
        }
        Ok(())
    }
}

fn action_for_route<'a>(
    registry: &'a CompiledRegistry,
    action_id: &str,
    route_id: &str,
    kind: ActionRouteKind,
) -> Result<&'a CompiledAction, MutationError> {
    let route = registry
        .actions()
        .routes
        .iter()
        .find(|route| route.id == route_id && route.action_id == action_id && route.kind == kind)
        .ok_or(MutationError::InvalidRequest)?;
    if route.method != HttpMethod::Post || route.operation != Operation::Invoke {
        return Err(MutationError::InvalidRequest);
    }
    registry
        .actions()
        .actions
        .iter()
        .find(|action| {
            action.id == action_id
                && match kind {
                    ActionRouteKind::Invoke => action.route == route.path,
                    ActionRouteKind::TargetConditions => {
                        action.condition_route.as_deref() == Some(route.path.as_str())
                    }
                }
        })
        .ok_or(MutationError::InvalidRequest)
}

fn validate_action_claims(
    action: &CompiledAction,
    claims: &ActionClaimContext,
    operation: Operation,
) -> Result<(), MutationError> {
    if claims.action_id() != action.id {
        return Err(MutationError::InvalidRequest);
    }
    let grant = action
        .grants
        .iter()
        .find(|grant| grant.profile_id == claims.access_profile())
        .ok_or(MutationError::InvalidRequest)?;
    if !grant.operations.contains(&operation) {
        return Err(MutationError::InvalidRequest);
    }
    if !claims.result_effects().is_subset(&grant.results)
        || !claims.result_effects().is_subset(&action.result_effects)
    {
        return Err(MutationError::InvalidRequest);
    }
    Ok(())
}

trait ActionClaimExt {
    fn result_effect_allowed(&self, action: &CompiledAction, effect_id: &str) -> bool;
}

impl ActionClaimExt for ActionClaimContext {
    fn result_effect_allowed(&self, action: &CompiledAction, effect_id: &str) -> bool {
        action.result_effects.contains(effect_id) && self.result_effects().contains(effect_id)
    }
}

fn validate_action_input(
    action: &CompiledAction,
    input: Map<String, Value>,
) -> Result<ActionInputs, MutationError> {
    let expected = action
        .inputs
        .iter()
        .map(|input| input.id.as_str())
        .collect::<BTreeSet<_>>();
    if input.keys().any(|key| !expected.contains(key.as_str())) {
        return Err(MutationError::InvalidRequest);
    }
    for source in &action.inputs {
        match input.get(&source.id) {
            Some(value) if !validate_field_value(FieldValue::Json(value), &source.field_type) => {
                return Err(MutationError::InvalidRequest);
            }
            None if source.required => return Err(MutationError::InvalidRequest),
            Some(_) | None => {}
        }
    }
    Ok(input)
}

fn validate_condition_inputs(
    action: &CompiledAction,
    input: Map<String, Value>,
) -> Result<BTreeMap<String, String>, MutationError> {
    let expected = existing_target_inputs(action);
    if input.len() != expected.len() || input.keys().any(|key| !expected.contains(key)) {
        return Err(MutationError::InvalidRequest);
    }
    let mut refs = BTreeMap::new();
    for input_id in expected {
        let record_id = input_record_id(&input, &input_id)?;
        refs.insert(input_id, record_id);
    }
    Ok(refs)
}

fn validate_precondition_set(
    action: &CompiledAction,
    preconditions: &BTreeMap<String, String>,
) -> Result<(), MutationError> {
    let expected = existing_target_inputs(action);
    if preconditions.len() != expected.len()
        || preconditions
            .keys()
            .any(|key| !expected.contains(key) || preconditions[key].is_empty())
    {
        return Err(MutationError::InvalidRequest);
    }
    Ok(())
}

fn existing_target_inputs(action: &CompiledAction) -> BTreeSet<String> {
    action
        .effects
        .iter()
        .filter_map(|effect| match &effect.target.binding {
            CompiledActionTargetBinding::Existing { input } => Some(input.clone()),
            CompiledActionTargetBinding::Create => None,
        })
        .collect()
}

fn input_record_id(input_values: &ActionInputs, input_id: &str) -> Result<String, MutationError> {
    let value = input_values
        .get(input_id)
        .ok_or(MutationError::InvalidRequest)?;
    let id = value.as_str().ok_or(MutationError::InvalidRequest)?;
    if !valid_uuid(id) {
        return Err(MutationError::InvalidRequest);
    }
    Ok(id.to_owned())
}

#[allow(clippy::too_many_arguments)]
fn action_link_context(
    registry: &CompiledRegistry,
    action: &CompiledAction,
    input_id: &str,
    target_entity_id: &str,
    claims: &ActionClaimContext,
    target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
    record_id: Uuid,
    package_revision: &str,
) -> Result<ImmediateActionLinkContext, MutationError> {
    ImmediateActionLinkContext::for_input(
        registry,
        claims,
        target_authority
            .get(target_entity_id)
            .cloned()
            .ok_or(MutationError::InvalidRequest)?,
        ImmediateActionLinkBinding {
            action_id: action.id.clone(),
            contract_fingerprint: action.contract_fingerprint.clone(),
            active_package_revision: package_revision.to_owned(),
            input_id: input_id.to_owned(),
            target_entity_id: target_entity_id.to_owned(),
            target_record_id: record_id,
        },
    )
    .map_err(|_| MutationError::InvalidRequest)
}

#[allow(clippy::too_many_arguments)]
fn action_target_context(
    registry: &CompiledRegistry,
    action: &CompiledAction,
    effect: &CompiledActionEffect,
    claims: &ActionClaimContext,
    target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
    record_id: Uuid,
    expected_revision: Option<i64>,
    lock_only: bool,
    application_id: Option<Uuid>,
    package_revision: &str,
) -> Result<ImmediateActionTargetContext, MutationError> {
    action_target_group_context(
        registry,
        action,
        &[effect],
        claims,
        target_authority,
        record_id,
        expected_revision,
        lock_only,
        application_id,
        package_revision,
    )
}

#[allow(clippy::too_many_arguments)]
fn action_target_group_context(
    registry: &CompiledRegistry,
    action: &CompiledAction,
    effects: &[&CompiledActionEffect],
    claims: &ActionClaimContext,
    target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
    record_id: Uuid,
    expected_revision: Option<i64>,
    lock_only: bool,
    application_id: Option<Uuid>,
    package_revision: &str,
) -> Result<ImmediateActionTargetContext, MutationError> {
    let effect = effects
        .first()
        .copied()
        .ok_or(MutationError::InvalidRequest)?;
    let effect_ids = effects
        .iter()
        .map(|effect| effect.id.clone())
        .collect::<BTreeSet<_>>();
    let fields = effects
        .iter()
        .flat_map(|effect| &effect.mutations)
        .map(|mutation| match mutation {
            CompiledActionMutation::Set { field, .. } | CompiledActionMutation::Clear { field } => {
                field.clone()
            }
        })
        .collect::<BTreeSet<_>>();
    ImmediateActionTargetContext::for_effect(
        registry,
        claims,
        target_authority
            .get(&effect.target.entity_id)
            .cloned()
            .ok_or(MutationError::InvalidRequest)?,
        ImmediateActionTargetBinding {
            action_id: action.id.clone(),
            contract_fingerprint: action.contract_fingerprint.clone(),
            active_package_revision: package_revision.to_owned(),
            effect_ids,
            target_entity_id: effect.target.entity_id.clone(),
            target_record_id: record_id,
            operation: effect.operation,
            fields,
            expected_revision,
            lock_only,
            application_id,
        },
    )
    .map_err(|_| MutationError::InvalidRequest)
}

fn reserve_action_create_ids(
    action: &CompiledAction,
) -> Result<BTreeMap<String, Uuid>, MutationError> {
    let mut reserved = BTreeMap::new();
    for effect in &action.effects {
        if matches!(effect.target.binding, CompiledActionTargetBinding::Create) {
            reserved.insert(effect.id.clone(), Uuid::new_v4());
        }
    }
    Ok(reserved)
}

fn ordered_action_effects(
    action: &CompiledAction,
) -> Result<Vec<&CompiledActionEffect>, MutationError> {
    let mut remaining = action.effects.iter().collect::<Vec<_>>();
    let mut resolved = BTreeSet::new();
    let mut ordered = Vec::with_capacity(remaining.len());
    while !remaining.is_empty() {
        let before = remaining.len();
        let mut index = 0;
        while index < remaining.len() {
            if remaining[index].depends_on.is_subset(&resolved) {
                let effect = remaining.remove(index);
                resolved.insert(effect.id.clone());
                ordered.push(effect);
            } else {
                index += 1;
            }
        }
        if remaining.len() == before {
            return Err(MutationError::InvalidRequest);
        }
    }
    Ok(ordered)
}

fn ordered_action_effect_groups<'a>(
    ordered: &[&'a CompiledActionEffect],
    patch_bases: &BTreeMap<String, CurrentRow>,
    reserved_creates: &BTreeMap<String, Uuid>,
) -> Result<Vec<Vec<&'a CompiledActionEffect>>, MutationError> {
    let mut positions = BTreeMap::<(String, Uuid), usize>::new();
    let mut groups = Vec::<Vec<&CompiledActionEffect>>::new();
    for effect in ordered {
        let key = action_effect_target_key(effect, patch_bases, reserved_creates)?;
        if let Some(position) = positions.get(&key).copied() {
            groups[position].push(*effect);
        } else {
            positions.insert(key, groups.len());
            groups.push(vec![*effect]);
        }
    }
    Ok(groups)
}

fn action_effect_target_key(
    effect: &CompiledActionEffect,
    patch_bases: &BTreeMap<String, CurrentRow>,
    reserved_creates: &BTreeMap<String, Uuid>,
) -> Result<(String, Uuid), MutationError> {
    let record_uuid = match &effect.target.binding {
        CompiledActionTargetBinding::Create => *reserved_creates
            .get(&effect.id)
            .ok_or(MutationError::InvalidRequest)?,
        CompiledActionTargetBinding::Existing { .. } => {
            patch_bases
                .get(&effect.id)
                .ok_or(MutationError::PreconditionFailed)?
                .record_uuid
        }
    };
    Ok((effect.target.entity_id.clone(), record_uuid))
}

fn action_effect_document(
    action: &CompiledAction,
    entity: &CompiledEntity,
    effect: &CompiledActionEffect,
    input_values: &ActionInputs,
    prior_results: &BTreeMap<String, CurrentRow>,
    _before: Option<&CurrentRow>,
) -> Result<Map<String, Value>, MutationError> {
    let mut data = Map::new();
    for mutation in &effect.mutations {
        match mutation {
            CompiledActionMutation::Set { field, value } => {
                let field_source = entity
                    .fields
                    .get(field)
                    .ok_or(MutationError::InvalidRequest)?;
                let value = match value {
                    CompiledActionValue::FromInput { input } => input_values
                        .get(input)
                        .cloned()
                        .ok_or(MutationError::InvalidRequest)?,
                    CompiledActionValue::FromEffect {
                        effect,
                        target_entity_id,
                    } => {
                        let source = action
                            .effects
                            .iter()
                            .find(|candidate| candidate.id == *effect)
                            .ok_or(MutationError::InvalidRequest)?;
                        if target_entity_id != &source.target.entity_id {
                            return Err(MutationError::InvalidRequest);
                        }
                        let row = prior_results
                            .get(effect)
                            .ok_or(MutationError::InvalidRequest)?;
                        Value::String(row.record_id.clone())
                    }
                };
                if !validate_field_value(FieldValue::Json(&value), &field_source.field_type) {
                    return Err(MutationError::InvalidRequest);
                }
                data.insert(field.clone(), value);
            }
            CompiledActionMutation::Clear { field } => {
                if entity.fields.get(field).is_none_or(|field| field.required) {
                    return Err(MutationError::InvalidRequest);
                }
                data.insert(field.clone(), Value::Null);
            }
        }
    }
    Ok(data)
}

fn action_held_response(
    action: &CompiledAction,
    claims: &ActionClaimContext,
    application_id: Uuid,
    results: &[ActionEffectResult],
) -> Result<HeldResponse, MutationError> {
    let allowed = claims.result_effects();
    let result_body = results
        .iter()
        .filter(|result| allowed.contains(&result.effect_id))
        .map(|result| {
            (
                result.effect_id.clone(),
                json!({
                    "entity": result.entity_id,
                    "recordId": result.record_id,
                    "revision": result.record_revision,
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    HeldResponse::from_json(
        200,
        &json!({
            "applicationId": application_id.to_string(),
            "action": action.id,
            "results": result_body,
        }),
        BTreeMap::from([(
            PermittedResponseHeader::ContentType,
            b"application/json".to_vec(),
        )]),
    )
    .map_err(MutationError::from)
}

async fn load_action_row(
    transaction: &Transaction<'_>,
    entity: &CompiledEntity,
    id: &str,
    lock: bool,
) -> Result<CurrentRow, MutationError> {
    let sql = format!(
        "SELECT {} FROM registry_data.{} WHERE record_id = $1::text::uuid
         AND record_lifecycle = 'active'{}",
        returning_projection(entity),
        quote_identifier(&entity.physical_table),
        if lock { " FOR UPDATE" } else { "" }
    );
    let row = transaction
        .query_opt(&sql, &[&id])
        .await
        .map_err(map_database_error)?
        .ok_or(MutationError::PreconditionFailed)?;
    row_to_current(entity, &row)
}

async fn insert_action_create_row(
    transaction: &Transaction<'_>,
    entity: &CompiledEntity,
    record_id: &str,
    data: &Map<String, Value>,
) -> Result<CurrentRow, MutationError> {
    let submitted_fields = entity
        .fields
        .values()
        .filter(|field| data.contains_key(&field.id))
        .collect::<Vec<_>>();
    let mut values = Vec::<Option<String>>::with_capacity(submitted_fields.len() + 1);
    values.push(Some(record_id.to_owned()));
    for field in &submitted_fields {
        values.push(sql_value(&data[&field.id], &field.field_type)?);
    }
    let parameters = values
        .iter()
        .map(|value| value as &(dyn ToSql + Sync))
        .collect::<Vec<_>>();
    let table = quote_identifier(&entity.physical_table);
    let field_columns = submitted_fields
        .iter()
        .map(|field| quote_identifier(&field.physical_name))
        .collect::<Vec<_>>();
    let field_parameters = submitted_fields
        .iter()
        .enumerate()
        .map(|(index, field)| typed_parameter(index + 2, &field.field_type))
        .collect::<Vec<_>>();
    let returning = returning_projection(entity);
    let mut columns = vec![
        "record_id".to_owned(),
        "record_revision".to_owned(),
        "record_lifecycle".to_owned(),
    ];
    columns.extend(field_columns);
    let mut placeholders = vec![
        "$1::text::uuid".to_owned(),
        "1".to_owned(),
        "'active'".to_owned(),
    ];
    placeholders.extend(field_parameters);
    let sql = format!(
        "INSERT INTO registry_data.{table} ({}) VALUES ({}) RETURNING {returning}",
        columns.join(", "),
        placeholders.join(", ")
    );
    let row = transaction
        .query_one(&sql, &parameters)
        .await
        .map_err(map_database_error)?;
    row_to_current(entity, &row)
}

async fn apply_patch_row(
    transaction: &Transaction<'_>,
    entity: &CompiledEntity,
    record_id: &str,
    expected_revision: i64,
    data: Map<String, Value>,
) -> Result<CurrentRow, MutationError> {
    let submitted_fields = entity
        .fields
        .values()
        .filter(|field| data.contains_key(&field.id))
        .collect::<Vec<_>>();
    if submitted_fields.is_empty() {
        return Err(MutationError::InvalidRequest);
    }
    let mut values = Vec::<Option<String>>::with_capacity(submitted_fields.len() + 2);
    values.push(Some(record_id.to_owned()));
    for field in &submitted_fields {
        values.push(sql_value(&data[&field.id], &field.field_type)?);
    }
    values.push(Some(expected_revision.to_string()));
    let parameters = values
        .iter()
        .map(|value| value as &(dyn ToSql + Sync))
        .collect::<Vec<_>>();
    let table = quote_identifier(&entity.physical_table);
    let assignments = submitted_fields
        .iter()
        .enumerate()
        .map(|(index, field)| {
            format!(
                "{} = {}",
                quote_identifier(&field.physical_name),
                typed_parameter(index + 2, &field.field_type)
            )
        })
        .collect::<Vec<_>>();
    let expected_parameter = values.len();
    let returning = returning_projection(entity);
    let sql = format!(
        "UPDATE registry_data.{table}
         SET record_revision = record_revision + 1,
             active_package_revision = DEFAULT,
             updated_at = transaction_timestamp(),
             {}
         WHERE record_id = $1::text::uuid
           AND record_revision = ${expected_parameter}::text::bigint
           AND record_lifecycle = 'active'
         RETURNING {returning}",
        assignments.join(", ")
    );
    let row = transaction
        .query_opt(&sql, &parameters)
        .await
        .map_err(map_database_error)?
        .ok_or(MutationError::PreconditionFailed)?;
    row_to_current(entity, &row)
}

fn action_condition_token(
    profile: &AuditProfile,
    registry_id: &str,
    action_id: &str,
    input_id: &str,
    entity_id: &str,
    record_id: &str,
    record_revision: i64,
) -> Result<String, MutationError> {
    let canonical = canonicalize_json(&json!({
        "version": 1,
        "registry": registry_id,
        "action": action_id,
        "input": input_id,
        "entity": entity_id,
        "record": record_id,
        "revision": record_revision,
    }))
    .map_err(|_| MutationError::InvalidRequest)?;
    let canonical = std::str::from_utf8(&canonical).map_err(|_| MutationError::InvalidRequest)?;
    let digest = profile
        .key_hasher()
        .audit_reference_hash(
            "registry-server-action-condition-token-v1",
            registry_id,
            canonical,
        )
        .map_err(|_| MutationError::Unavailable)?;
    Ok(format!("\"rs-{digest}\""))
}

fn action_application_reference(
    profile: &AuditProfile,
    package_revision: &str,
    application_id: Uuid,
) -> Result<String, MutationError> {
    profile
        .key_hasher()
        .audit_reference_hash(
            "registry-server-immediate-action-application-v1",
            package_revision,
            &application_id.to_string(),
        )
        .map_err(|_| MutationError::Unavailable)
}

async fn stored_action_application_reference(
    transaction: &Transaction<'_>,
    profile: &AuditProfile,
    key_reference: &str,
) -> Result<String, MutationError> {
    let row = transaction
        .query_opt(
            "SELECT application_id, package_revision
               FROM registry_internal.registry_immediate_action_applications
              WHERE key_reference = $1",
            &[&key_reference],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
        .ok_or(MutationError::Unavailable)?;
    let application_id = row.get::<_, Uuid>(0);
    let package_revision = row.get::<_, String>(1);
    action_application_reference(profile, &package_revision, application_id)
}

async fn insert_action_application(
    transaction: &Transaction<'_>,
    binding: &crate::idempotency::ResolvedIdempotencyBinding,
    action: &CompiledAction,
    application_id: Uuid,
    package_revision: &str,
    principal_reference: &str,
    result_count: u16,
) -> Result<(), MutationError> {
    let changed = transaction
        .execute(
            "INSERT INTO registry_internal.registry_immediate_action_applications
                 (key_reference, binding_reference, application_id, action_id,
                  action_contract_fingerprint, package_revision, principal_reference, result_count)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &[
                &binding.key_reference,
                &binding.binding_reference,
                &application_id,
                &action.id,
                &action.contract_fingerprint,
                &package_revision,
                &principal_reference,
                &(i16::try_from(result_count).map_err(|_| MutationError::InvalidRequest)?),
            ],
        )
        .await
        .map_err(map_database_error)?;
    if changed != 1 {
        return Err(MutationError::Unavailable);
    }
    Ok(())
}

async fn insert_action_result_links(
    transaction: &Transaction<'_>,
    binding: &crate::idempotency::ResolvedIdempotencyBinding,
    action: &CompiledAction,
    results: &[ActionEffectResult],
) -> Result<(), MutationError> {
    for result in results {
        let changed = transaction
            .execute(
                "INSERT INTO registry_internal.registry_immediate_action_results
                     (key_reference, effect_id, action_id, target_entity_id, target_record_id,
                      target_record_reference, target_record_revision, mutation_kind)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                &[
                    &binding.key_reference,
                    &result.effect_id,
                    &action.id,
                    &result.entity_id,
                    &result.record_uuid,
                    &result.record_reference,
                    &result.record_revision,
                    &mutation_kind(result.operation),
                ],
            )
            .await
            .map_err(map_database_error)?;
        if changed != 1 {
            return Err(MutationError::Unavailable);
        }
    }
    Ok(())
}

fn canonical_action_request_digest(
    action: &CompiledAction,
    input_values: &ActionInputs,
    preconditions: &BTreeMap<String, String>,
) -> Result<[u8; 32], MutationError> {
    let canonical = canonicalize_json(&json!({
        "action": action.id,
        "route": action.route,
        "input": input_values,
        "preconditions": preconditions,
    }))
    .map_err(|_| MutationError::InvalidRequest)?;
    Ok(Sha256::digest(canonical).into())
}
