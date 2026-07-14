//! Cross-artifact semantics, minimization, selectors, and response-schema validation.

use super::*;

pub(in super::super) const MAX_DCI_EXACT_REQUEST_BODY_BYTES: usize = 8 * 1024;
pub(super) fn parse_pack_reference(
    reference: &ArtifactReferenceDocument,
) -> Result<IntegrationPackIdentity, SourcePlanArtifactError> {
    let id = IntegrationPackId::try_from(reference.id.as_str())
        .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
    let version = ProfileVersion::try_from(reference.version.as_str())
        .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
    let hash = IntegrationPackHash::try_from(reference.hash.as_str())
        .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
    Ok(IntegrationPackIdentity::new(id, version, hash))
}

pub(super) fn parse_integration_reference(
    reference: &IntegrationReferenceDocument,
) -> Result<(IntegrationPackId, ProfileVersion), SourcePlanArtifactError> {
    let id = IntegrationPackId::try_from(reference.id.as_str())
        .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
    let revision = ProfileVersion::try_from(reference.revision.to_string().as_str())
        .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
    Ok((id, revision))
}

pub(super) fn validate_subject(
    subject: &SubjectDocument,
) -> Result<SelectorProvenance, SourcePlanArtifactError> {
    match &subject.selector_provenance {
        SelectorProvenanceDocument::WorkloadSelected => Ok(SelectorProvenance::WorkloadSelected),
    }
}

pub(super) fn validate_inputs(
    inputs: &BTreeMap<String, InputDocument>,
) -> Result<(), SourcePlanArtifactError> {
    if !(1..=MAX_TOTAL_INPUTS).contains(&inputs.len()) {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    let selector_count = inputs
        .values()
        .filter(|input| input.role == InputRoleDocument::Selector)
        .count();
    if !(1..=MAX_SELECTOR_INPUTS).contains(&selector_count) {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    let mut selector_max_bytes = 0_usize;
    for (name, input) in inputs {
        if !crate::source_plan::valid_consultation_input_name(name) {
            return Err(SourcePlanArtifactError::InvalidIdentity);
        }
        let (input_type, nullable) = input
            .resolved_type()
            .ok_or(SourcePlanArtifactError::InvalidAcquisition)?;
        if nullable && input.role != InputRoleDocument::Parameter {
            return Err(SourcePlanArtifactError::InvalidAcquisition);
        }
        let shape_valid = match input_type {
            InputTypeDocument::String => {
                let Some(max_length) = input.max_length else {
                    return Err(SourcePlanArtifactError::InvalidLimits);
                };
                let Some(max_bytes) = input.max_bytes else {
                    return Err(SourcePlanArtifactError::InvalidLimits);
                };
                let expected_bytes = max_length.checked_mul(4);
                max_length > 0
                    && input.min_length.is_none_or(|minimum| minimum <= max_length)
                    && max_bytes > 0
                    && max_bytes <= MAX_INPUT_BYTES
                    && expected_bytes == Some(max_bytes)
                    && input.minimum.is_none()
                    && input.maximum.is_none()
                    && input.pattern.as_ref().is_none_or(|pattern| {
                        max_bytes <= MAX_PATTERNED_INPUT_BYTES
                            && validate_bounded_text(pattern, MAX_PATTERN_BYTES).is_ok()
                            && validate_input_pattern(pattern).is_ok()
                    })
            }
            InputTypeDocument::FullDate => {
                input.max_length == Some(10)
                    && input.min_length.is_none_or(|minimum| minimum <= 10)
                    && input.max_bytes == Some(10)
                    && input.pattern.is_none()
                    && input.minimum.is_none()
                    && input.maximum.is_none()
                    && input.canonicalization == CanonicalizationDocument::Identity
            }
            InputTypeDocument::Boolean => {
                input.max_length.is_none()
                    && input.min_length.is_none()
                    && input.max_bytes.is_none()
                    && input.pattern.is_none()
                    && input.minimum.is_none()
                    && input.maximum.is_none()
                    && input.canonicalization == CanonicalizationDocument::Identity
            }
            InputTypeDocument::Integer => {
                input.max_length.is_none()
                    && input.min_length.is_none()
                    && input.max_bytes.is_none()
                    && input.pattern.is_none()
                    && input.canonicalization == CanonicalizationDocument::Identity
                    && matches!((input.minimum, input.maximum), (Some(minimum), Some(maximum))
                        if minimum <= maximum
                            && minimum.unsigned_abs() <= MAX_JSON_INTEROPERABLE_INTEGER
                            && maximum.unsigned_abs() <= MAX_JSON_INTEROPERABLE_INTEGER)
            }
        };
        if !shape_valid {
            return Err(SourcePlanArtifactError::InvalidLimits);
        }
        if input.allowed_values.len() > 64
            || input
                .allowed_values
                .iter()
                .enumerate()
                .any(|(index, value)| {
                    !input_constraint_value_valid(input, input_type, nullable, value)
                        || input.allowed_values[..index].contains(value)
                })
            || input.constant.as_ref().is_some_and(|value| {
                !input_constraint_value_valid(input, input_type, nullable, value)
                    || (!input.allowed_values.is_empty() && !input.allowed_values.contains(value))
            })
        {
            return Err(SourcePlanArtifactError::InvalidAcquisition);
        }
        if input.role == InputRoleDocument::Selector {
            selector_max_bytes = selector_max_bytes
                .checked_add(
                    input
                        .canonical_max_bytes()
                        .ok_or(SourcePlanArtifactError::InvalidLimits)?
                        as usize,
                )
                .ok_or(SourcePlanArtifactError::InvalidLimits)?;
        }
    }
    if selector_max_bytes > MAX_CANONICAL_SELECTOR_BYTES {
        return Err(SourcePlanArtifactError::InvalidLimits);
    }
    Ok(())
}

fn input_constraint_value_valid(
    input: &InputDocument,
    input_type: InputTypeDocument,
    nullable: bool,
    value: &serde_json::Value,
) -> bool {
    match (input_type, value) {
        (_, serde_json::Value::Null) => nullable,
        (
            InputTypeDocument::String | InputTypeDocument::FullDate,
            serde_json::Value::String(value),
        ) => {
            let length = value.chars().count();
            input
                .min_length
                .is_none_or(|minimum| length >= minimum as usize)
                && input
                    .max_length
                    .is_some_and(|maximum| length <= maximum as usize)
                && input
                    .max_bytes
                    .is_some_and(|maximum| value.len() <= maximum as usize)
        }
        (InputTypeDocument::Boolean, serde_json::Value::Bool(_)) => true,
        (InputTypeDocument::Integer, serde_json::Value::Number(value)) => {
            value.as_i64().is_some_and(|value| {
                input.minimum.is_some_and(|minimum| value >= minimum)
                    && input.maximum.is_some_and(|maximum| value <= maximum)
            })
        }
        _ => false,
    }
}

pub(super) fn validate_acquisition(
    acquisition: &PublicAcquisitionDocument,
) -> Result<BTreeSet<AcquiredField>, SourcePlanArtifactError> {
    if acquisition.fields.is_empty() || acquisition.fields.len() > MAX_ACQUIRED_FIELDS {
        return Err(SourcePlanArtifactError::InvalidAcquisition);
    }
    acquisition
        .fields
        .iter()
        .map(|(name, schema)| {
            let field = AcquiredField::try_from(name.as_str())
                .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
            let mut nodes = 0;
            let expanded = validate_response_schema(schema, 1, &mut nodes)?;
            if expanded > MAX_RESPONSE_SCHEMA_EXPANDED_NODES {
                return Err(SourcePlanArtifactError::InvalidLimits);
            }
            Ok(field)
        })
        .collect()
}

pub(super) fn validate_source_provenance(
    provenance: &SourceProvenanceDocument,
    acquisition: AcquisitionClassDocument,
    fields: &BTreeMap<String, ResponseSchemaDocument>,
) -> Result<(), SourcePlanArtifactError> {
    if acquisition != AcquisitionClassDocument::MaterializedSnapshot
        && (!matches!(
            provenance.source_observed_at,
            SourceObservedAtDocument::Absent
        ) || !matches!(provenance.source_revision, SourceRevisionDocument::Absent))
    {
        return Err(SourcePlanArtifactError::InvalidPlan);
    }
    if let SourceObservedAtDocument::AcquiredRfc3339 { field } = &provenance.source_observed_at {
        validate_stable_text(field)?;
        if !matches!(
            fields.get(field),
            Some(ResponseSchemaDocument::String {
                nullable: false,
                max_bytes: 1..=64,
            })
        ) {
            return Err(SourcePlanArtifactError::InvalidAcquisition);
        }
    }
    if let SourceRevisionDocument::AcquiredString { field, max_bytes } = &provenance.source_revision
    {
        validate_stable_text(field)?;
        if *max_bytes == 0
            || fields.get(field).is_none_or(|schema| {
                !matches!(
                    schema,
                    ResponseSchemaDocument::String {
                        nullable: false,
                        max_bytes: schema_max,
                    } if u32::from(*max_bytes) == *schema_max
                )
            })
        {
            return Err(SourcePlanArtifactError::InvalidAcquisition);
        }
    }
    Ok(())
}

pub(super) fn cardinality_from_bounds(
    bounds: LimitsDocument,
) -> Result<SourceCardinality, SourcePlanArtifactError> {
    match bounds.max_source_matches {
        1 => Ok(SourceCardinality::Singleton),
        2 => Ok(SourceCardinality::AmbiguityProbe),
        _ => Err(SourcePlanArtifactError::InvalidAcquisition),
    }
}

pub(super) fn validate_runtime_requirements(
    spec: &PublicContractSpecDocument,
) -> Result<(), SourcePlanArtifactError> {
    const PLATFORM_PROFILE: &str = "registry-stack.consultation.v1";
    let live_acquisition = matches!(
        spec.acquisition.class,
        AcquisitionClassDocument::SourceProjectedExact
            | AcquisitionClassDocument::BoundedFullRecord
    );
    let valid = spec.runtime.platform_profile == PLATFORM_PROFILE
        && match spec.runtime.source_capability {
            SourceCapabilityDocument::Http => live_acquisition && spec.runtime.script_abi.is_none(),
            SourceCapabilityDocument::Script => {
                live_acquisition
                    && spec.runtime.script_abi.as_deref()
                        == Some(crate::rhai_worker::xw::XW_ABI_VERSION)
            }
            SourceCapabilityDocument::Snapshot => {
                spec.acquisition.class == AcquisitionClassDocument::MaterializedSnapshot
                    && spec.runtime.script_abi.is_none()
            }
        };
    valid
        .then_some(())
        .ok_or(SourcePlanArtifactError::InvalidPlan)
}

pub(super) fn validate_materialization_contract(
    spec: &mut PublicContractSpecDocument,
    acquired_fields: &BTreeSet<AcquiredField>,
) -> Result<(), SourcePlanArtifactError> {
    let is_snapshot = spec.acquisition.class == AcquisitionClassDocument::MaterializedSnapshot;
    let Some(materialization) = &mut spec.materialization else {
        return if is_snapshot {
            Err(SourcePlanArtifactError::InvalidAcquisition)
        } else {
            Ok(())
        };
    };
    if !is_snapshot {
        return Err(SourcePlanArtifactError::InvalidAcquisition);
    }
    normalize_stable_set(&mut materialization.footprint.fields)?;
    let footprint_fields = parse_acquired_fields(&materialization.footprint.fields)?;
    let valid = footprint_fields == *acquired_fields
        && (1..=MAX_SNAPSHOT_AGE_MS).contains(&materialization.max_snapshot_age_ms)
        && materialization.footprint.max_source_records > 0
        && materialization.footprint.max_source_records <= MAX_JSON_INTEROPERABLE_INTEGER
        && materialization.footprint.max_source_bytes > 0
        && materialization.footprint.max_source_bytes <= MAX_JSON_INTEROPERABLE_INTEGER
        && materialization.footprint.max_data_exchanges > 0
        && materialization.footprint.max_credential_exchanges <= 1
        && materialization.footprint.max_data_destinations == 1
        && (1..=16).contains(&materialization.snapshot_retention_generations)
        && materialization.immutable_generation
        && materialization.digest_bound_active_pointer;
    valid
        .then_some(())
        .ok_or(SourcePlanArtifactError::InvalidAcquisition)
}
pub(super) fn validate_output(
    output: &BTreeMap<String, OutputFieldDocument>,
    acquired_fields: &BTreeSet<AcquiredField>,
) -> Result<(), SourcePlanArtifactError> {
    if output.len() > MAX_ACQUIRED_FIELDS || acquired_fields.len() > MAX_ACQUIRED_FIELDS {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    for name in output.keys() {
        AcquiredField::try_from(name.as_str())
            .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
    }
    for field in output.values() {
        let valid = match field.output_type {
            OutputTypeDocument::String => {
                field
                    .max_bytes
                    .is_some_and(|bound| (1..=MAX_PUBLIC_RESPONSE_BYTES).contains(&bound))
                    && field.minimum.is_none()
                    && field.maximum.is_none()
            }
            OutputTypeDocument::Integer => {
                field.max_bytes.is_none()
                    && matches!((field.minimum, field.maximum), (Some(min), Some(max))
                        if min <= max
                            && min.unsigned_abs() <= MAX_JSON_INTEROPERABLE_INTEGER
                            && max.unsigned_abs() <= MAX_JSON_INTEROPERABLE_INTEGER)
            }
            OutputTypeDocument::Date => {
                field.max_bytes == Some(10) && field.minimum.is_none() && field.maximum.is_none()
            }
            OutputTypeDocument::Boolean => {
                field.max_bytes.is_none() && field.minimum.is_none() && field.maximum.is_none()
            }
        };
        if !valid {
            return Err(SourcePlanArtifactError::InvalidAcquisition);
        }
    }
    Ok(())
}

pub(super) fn validate_authorization(
    authorization: &mut AuthorizationDocument,
) -> Result<ValidatedAuthorization, SourcePlanArtifactError> {
    let workload_id = WorkloadId::try_from(authorization.workload.as_str())
        .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
    let required_scope = RequiredConsultationScope::try_from(authorization.required_scope.as_str())
        .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
    let legal_basis = LegalBasisId::try_from(authorization.legal_basis.as_str())
        .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
    normalize_token_set(&mut authorization.purposes, MAX_PURPOSE_BYTES)?;
    if authorization.purposes.len() > MAX_PURPOSES {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    let purposes = authorization
        .purposes
        .iter()
        .map(|purpose| {
            CanonicalPurpose::try_from(purpose.as_str())
                .map_err(|_| SourcePlanArtifactError::InvalidText)
        })
        .collect::<Result<Box<[_]>, _>>()?;
    let id = PolicyId::try_from(authorization.policy.id.as_str())
        .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
    let hash = PolicyHash::try_from(authorization.policy.hash.as_str())
        .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
    let policy_identity = PolicyIdentity::new(id, hash);
    if authorization.policy.max_decision_age_ms == 0
        || authorization.policy.max_decision_age_ms > 1_000
    {
        return Err(SourcePlanArtifactError::InvalidLimits);
    }
    let consent_verifier = validate_consent(&authorization.consent)?;
    if !authorization.mandatory_obligations.is_empty() {
        return Err(SourcePlanArtifactError::InvalidPlan);
    }
    Ok(ValidatedAuthorization {
        workload_id,
        required_scope,
        policy_identity,
        consent_verifier,
        purposes,
        legal_basis,
    })
}

pub(super) fn validate_consent(
    consent: &ConsentDocument,
) -> Result<Option<(OperationId, IntegrationPackHash)>, SourcePlanArtifactError> {
    match (
        consent.required,
        &consent.verifier,
        consent.max_age_ms,
        &consent.revocation,
        &consent.unavailable,
    ) {
        (false, None, None, None, None) => Ok(None),
        (true, Some(verifier), Some(max_age_ms), Some(_), Some(_))
            if (1..=MAX_CONSENT_AGE_MS).contains(&max_age_ms) =>
        {
            let id = OperationId::try_from(verifier.id.as_str())
                .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
            let hash = IntegrationPackHash::try_from(verifier.hash.as_str())
                .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
            Ok(Some((id, hash)))
        }
        _ => Err(SourcePlanArtifactError::InvalidPlan),
    }
}

pub(super) fn validate_public_behavior(
    behavior: &mut PublicBehaviorDocument,
    _cardinality: SourceCardinality,
) -> Result<(), SourcePlanArtifactError> {
    behavior.outcomes.sort();
    if behavior.outcomes.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    // The public v1 result union is stable across source implementations.
    // Source cardinality controls whether ambiguity is reachable, not whether
    // the public contract can represent it.
    let expected = vec![
        OutcomeDocument::Match,
        OutcomeDocument::NoMatch,
        OutcomeDocument::Ambiguous,
    ];
    let mut expected = expected;
    expected.sort();
    if behavior.outcomes != expected {
        return Err(SourcePlanArtifactError::InvalidAcquisition);
    }
    if behavior.denial_code != "consultation.denied"
        || behavior.denial_timing_profile != "measured-uniform-v1"
    {
        return Err(SourcePlanArtifactError::InvalidPlan);
    }
    validate_stable_text(&behavior.denial_code)?;
    validate_stable_text(&behavior.denial_timing_profile)
}

pub(super) fn validate_parameter_declarations(
    parameters: &mut BTreeMap<String, ParameterDeclarationDocument>,
) -> Result<(), SourcePlanArtifactError> {
    if parameters.len() > MAX_DEPLOYMENT_PARAMETERS {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    for (name, declaration) in parameters {
        validate_stable_text(name)?;
        if is_sensitive_name(name) {
            return Err(SourcePlanArtifactError::InvalidExpression);
        }
        normalize_bounded_set(&mut declaration.allowed_values, MAX_STABLE_TEXT_BYTES)?;
        if declaration.allowed_values.len() > MAX_PARAMETER_VALUES {
            return Err(SourcePlanArtifactError::InvalidSet);
        }
    }
    Ok(())
}

pub(super) fn validate_parameter_bindings(
    parameters: &BTreeMap<String, String>,
) -> Result<(), SourcePlanArtifactError> {
    if parameters.len() > MAX_DEPLOYMENT_PARAMETERS {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    for (name, value) in parameters {
        validate_stable_text(name)?;
        if is_sensitive_name(name) {
            return Err(SourcePlanArtifactError::InvalidExpression);
        }
        validate_bounded_text(value, MAX_STABLE_TEXT_BYTES)?;
    }
    Ok(())
}

pub(super) fn validate_plan(
    spec: &mut IntegrationPackSpecDocument,
    _acquired_fields: &BTreeSet<AcquiredField>,
) -> Result<(), SourcePlanArtifactError> {
    let plan = &mut spec.plan;
    let profile_cardinality = cardinality_from_bounds(spec.bounds)?;
    if let Some(slot) = &plan.data_destination_slot {
        validate_stable_text(slot)?;
    } else if plan.kind != SourcePlanKind::SnapshotExact {
        return Err(SourcePlanArtifactError::InvalidPlan);
    }
    if let Some(slot) = &plan.credential_destination_slot {
        validate_stable_text(slot)?;
        if plan.data_destination_slot.as_ref() == Some(slot) {
            return Err(SourcePlanArtifactError::InvalidPlan);
        }
    }
    if let Some(slot) = &plan.verification_destination_slot {
        validate_stable_text(slot)?;
        if plan.data_destination_slot.as_ref() == Some(slot)
            || plan.credential_destination_slot.as_ref() == Some(slot)
        {
            return Err(SourcePlanArtifactError::InvalidPlan);
        }
    }
    if plan.kind == SourcePlanKind::SnapshotExact {
        return validate_snapshot_plan(spec);
    }
    if plan.kind == SourcePlanKind::Script {
        return validate_script_plan(spec);
    }
    if plan.operations.is_empty()
        || plan.operations.len() > MAX_SOURCE_OPERATIONS
        || (plan.kind == SourcePlanKind::BoundedHttp && plan.operations.len() != 1)
        || (plan.kind == SourcePlanKind::Script) != plan.steps.is_empty()
    {
        return Err(SourcePlanArtifactError::InvalidPlan);
    }

    let mut operation_ids = BTreeSet::new();
    let mut operation_control_fields = BTreeSet::new();
    let mut mapped_output_fields = BTreeSet::new();
    let mut operation_response_fields = BTreeMap::new();
    let mut auth_modes = BTreeSet::new();
    let mut script_request_byte_limits = BTreeSet::new();
    let mut response_bytes = 0_u64;
    let mut maximum_data_response_bytes = 0_u64;
    let mut reaches_profile_cardinality = false;
    let reviewed_acquisition = spec
        .reviewed_acquisition
        .as_ref()
        .ok_or(SourcePlanArtifactError::InvalidAcquisition)?;
    let oauth_authorization_max_bytes = plan.credential_operation.as_ref().and_then(|operation| {
        usize::from(operation.response.access_token_max_bytes).checked_add(b"Bearer ".len())
    });
    if oauth_authorization_max_bytes.is_some_and(|value| value > MAX_REQUEST_HEADER_VALUE_BYTES) {
        return Err(SourcePlanArtifactError::InvalidLimits);
    }
    let prior_output_bounds = prior_output_expression_bounds(&plan.operations);
    let operation_validation = HttpOperationValidationContext {
        plan_kind: plan.kind,
        inputs: &spec.input_slots,
        parameters: &spec.deployment_parameters,
        reviewed_control_fields: &reviewed_acquisition.control_fields,
        acquisition_class: spec.acquisition.class,
        evidence: &spec.evidence,
        bounds: spec.bounds,
        oauth_authorization_max_bytes,
        output: &spec.output,
        prior_output_bounds: &prior_output_bounds,
    };
    for operation in &mut plan.operations {
        let operation_id = OperationId::try_from(operation.id.as_str())
            .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
        if !operation_ids.insert(operation_id) {
            return Err(SourcePlanArtifactError::InvalidSet);
        }
        if plan.data_destination_slot.as_deref() != Some(operation.destination_slot.as_str()) {
            return Err(SourcePlanArtifactError::InvalidPlan);
        }
        validate_http_operation(operation, &operation_validation)?;
        if plan.kind == SourcePlanKind::Script {
            script_request_byte_limits.insert(
                operation
                    .step_limits
                    .ok_or(SourcePlanArtifactError::InvalidPlan)?
                    .max_request_bytes,
            );
        }
        let record_schema = response_record_schema(
            &operation.response.schema,
            &operation.response.normalization,
            operation.response.max_records,
            operation.response.records_field.as_deref(),
        )?;
        match record_schema {
            ResponseSchemaDocument::ScriptBody if plan.kind == SourcePlanKind::Script => {}
            ResponseSchemaDocument::Object { fields, .. } => {
                for (name, field) in fields {
                    AcquiredField::try_from(name.as_str())
                        .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
                    if operation_response_fields
                        .insert(name.clone(), field.schema.as_ref().clone())
                        .is_some_and(|prior| prior != *field.schema)
                    {
                        return Err(SourcePlanArtifactError::InvalidAcquisition);
                    }
                }
            }
            _ => return Err(SourcePlanArtifactError::InvalidAcquisition),
        }
        for field in &operation.control_fields {
            let field = AcquiredField::try_from(field.as_str())
                .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
            if !operation_control_fields.insert(field) {
                return Err(SourcePlanArtifactError::InvalidAcquisition);
            }
        }
        for field in operation.response.output_mapping.keys() {
            if !mapped_output_fields.insert(field.clone()) {
                return Err(SourcePlanArtifactError::InvalidAcquisition);
            }
        }
        auth_modes.insert(operation.auth.clone());
        let operation_cardinality = match operation.response.max_records {
            1 => SourceCardinality::Singleton,
            2 => SourceCardinality::AmbiguityProbe,
            _ => return Err(SourcePlanArtifactError::InvalidAcquisition),
        };
        let normalization_matches = matches!(
            (operation_cardinality, &operation.response.normalization),
            (
                SourceCardinality::Singleton,
                ResponseNormalizationDocument::Object | ResponseNormalizationDocument::ScriptBody
            ) | (
                SourceCardinality::AmbiguityProbe,
                ResponseNormalizationDocument::ArrayProbeTwo
                    | ResponseNormalizationDocument::ObjectArrayProbeTwo
            )
        );
        if !normalization_matches {
            return Err(SourcePlanArtifactError::InvalidAcquisition);
        }
        if operation.response.max_records > profile_cardinality.max_source_matches() {
            return Err(SourcePlanArtifactError::InvalidAcquisition);
        }
        reaches_profile_cardinality |= operation.response.max_records
            == profile_cardinality.max_source_matches()
            || (profile_cardinality == SourceCardinality::AmbiguityProbe
                && !operation.response.status_outcomes.ambiguous.is_empty());
        response_bytes = response_bytes
            .checked_add(u64::from(operation.response.max_bytes))
            .ok_or(SourcePlanArtifactError::InvalidLimits)?;
        maximum_data_response_bytes =
            maximum_data_response_bytes.max(u64::from(operation.response.max_bytes));
    }
    if plan.kind == SourcePlanKind::Script && script_request_byte_limits.len() != 1 {
        return Err(SourcePlanArtifactError::InvalidPlan);
    }
    let mut verification_ids = BTreeSet::new();
    for verification in &mut plan.verification_operations {
        let operation_id = OperationId::try_from(verification.id.as_str())
            .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
        if operation_ids.contains(&operation_id)
            || !verification_ids.insert(operation_id)
            || plan.verification_destination_slot.as_deref()
                != Some(verification.destination_slot.as_str())
            || verification.method != ReadMethod::Get
            || verification.step_limits.max_request_bytes == 0
            || verification.step_limits.timeout_ms == 0
            || verification.step_limits.timeout_ms > spec.bounds.timeout_ms
            || verification.step_limits.max_in_flight != 1
            || verification.max_response_bytes == 0
            || verification.max_response_bytes > MAX_DATA_RESPONSE_BYTES
        {
            return Err(SourcePlanArtifactError::InvalidPlan);
        }
        validate_fixed_path(&verification.path)?;
        normalize_data_status_set(&mut verification.accepted_statuses)?;
        if verification.accepted_statuses != [200] {
            return Err(SourcePlanArtifactError::InvalidPlan);
        }
    }
    if plan.verification_operations.is_empty() != plan.verification_destination_slot.is_none() {
        return Err(SourcePlanArtifactError::InvalidPlan);
    }
    if !reaches_profile_cardinality {
        return Err(SourcePlanArtifactError::InvalidAcquisition);
    }
    let declared_disclosed_fields = spec.output.keys().cloned().collect::<BTreeSet<_>>();
    let declared_control_fields = spec
        .reviewed_acquisition
        .as_ref()
        .ok_or(SourcePlanArtifactError::InvalidAcquisition)?
        .control_fields
        .keys()
        .map(|field| {
            AcquiredField::try_from(field.as_str())
                .map_err(|_| SourcePlanArtifactError::InvalidIdentity)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mapped_outputs_valid = if plan.kind == SourcePlanKind::Script {
        mapped_output_fields.is_empty() || mapped_output_fields == declared_disclosed_fields
    } else {
        mapped_output_fields == declared_disclosed_fields
    };
    let operation_fields_match_acquisition = match plan.kind {
        SourcePlanKind::Script => true,
        SourcePlanKind::BoundedHttp => {
            operation_response_fields.len() == spec.acquisition.fields.len()
                && operation_response_fields.iter().all(|(name, raw)| {
                    spec.acquisition
                        .fields
                        .get(name)
                        .is_some_and(|selected| raw.matches_selected_shape(selected))
                })
        }
        SourcePlanKind::SnapshotExact => unreachable!("snapshot plans return above"),
    };
    if operation_control_fields != declared_control_fields
        || !operation_fields_match_acquisition
        || !mapped_outputs_valid
    {
        return Err(SourcePlanArtifactError::InvalidAcquisition);
    }

    let known_operations = operation_ids
        .iter()
        .map(OperationId::as_str)
        .collect::<BTreeSet<_>>();
    let mut used_operations = BTreeSet::new();
    for step in &plan.steps {
        validate_stable_text(step)?;
        if !known_operations.contains(step.as_str()) {
            return Err(SourcePlanArtifactError::InvalidPlan);
        }
        if !used_operations.insert(step.as_str()) {
            return Err(SourcePlanArtifactError::InvalidPlan);
        }
    }
    let verification_data_exchanges = plan.verification_operations.len();
    if (plan.kind == SourcePlanKind::BoundedHttp
        && (used_operations != known_operations
            || plan.steps.len() + verification_data_exchanges
                != usize::from(spec.bounds.max_data_exchanges)))
        || (plan.kind == SourcePlanKind::Script && !plan.step_conditions.is_empty())
    {
        return Err(SourcePlanArtifactError::InvalidPlan);
    }

    let credential_auth_modes = auth_modes
        .iter()
        .filter(|mode| **mode != SourceAuthDocument::None)
        .cloned()
        .collect::<BTreeSet<_>>();
    if credential_auth_modes.len() > 1 {
        return Err(SourcePlanArtifactError::InvalidPlan);
    }
    let credential_auth = credential_auth_modes.iter().next().cloned();
    validate_credential_operation(plan, spec.bounds, credential_auth)?;
    if plan.kind == SourcePlanKind::Script {
        response_bytes = maximum_data_response_bytes
            .checked_mul(u64::from(spec.bounds.max_data_exchanges))
            .ok_or(SourcePlanArtifactError::InvalidLimits)?;
    }
    if let Some(credential) = &plan.credential_operation {
        response_bytes = response_bytes
            .checked_add(u64::from(credential.response.max_bytes))
            .ok_or(SourcePlanArtifactError::InvalidLimits)?;
    }
    for verification in &plan.verification_operations {
        response_bytes = response_bytes
            .checked_add(u64::from(verification.max_response_bytes))
            .ok_or(SourcePlanArtifactError::InvalidLimits)?;
    }
    if response_bytes > spec.bounds.max_source_bytes {
        return Err(SourcePlanArtifactError::InvalidLimits);
    }
    validate_template_kind(plan, spec.acquisition.class)?;
    validate_prior_step_references(plan)?;
    validate_step_conditions(plan)?;
    validate_dci_exact_plan(spec)
}

fn validate_script_plan(
    spec: &mut IntegrationPackSpecDocument,
) -> Result<(), SourcePlanArtifactError> {
    let (auth, response_max_bytes, signed_dci_jwks) = {
        let plan = &mut spec.plan;
        let authority = plan
            .script_authority
            .as_mut()
            .ok_or(SourcePlanArtifactError::InvalidPlan)?;
        if !plan.operations.is_empty()
            || !plan.steps.is_empty()
            || !plan.step_conditions.is_empty()
            || plan.snapshot.is_some()
            || plan.rhai.is_none()
            || !(1..=MAX_SOURCE_OPERATIONS).contains(&authority.allow.len())
            || authority.request_max_bytes == 0
            || authority.request_max_bytes > MAX_REQUEST_BYTES
            || authority.response.max_bytes == 0
            || authority.response.max_bytes > MAX_DATA_RESPONSE_BYTES
        {
            return Err(SourcePlanArtifactError::InvalidPlan);
        }
        let mut allow_rules = BTreeSet::new();
        for rule in &authority.allow {
            registry_platform_httputil::destination::validate_script_destination_path_rule(
                &rule.path,
            )
            .map_err(|_| SourcePlanArtifactError::InvalidPlan)?;
            if (rule.method == ReadMethod::ReadOnlyPost)
                != (rule.semantics == Some(ScriptReadSemanticsDocument::ReadOnly))
                || (rule.method == ReadMethod::ReadOnlyPost && rule.path.contains("**"))
                || !allow_rules.insert((rule.method, rule.path.as_str()))
            {
                return Err(SourcePlanArtifactError::InvalidPlan);
            }
        }
        let mut request_headers = std::mem::take(&mut authority.request_headers);
        if request_headers.len() > MAX_STATIC_COMPONENTS {
            return Err(SourcePlanArtifactError::InvalidLimits);
        }
        for name in request_headers.drain(..) {
            let name = name.to_ascii_lowercase();
            if !registry_platform_httputil::destination::is_script_writable_request_header_name(
                &name,
            ) || authority.request_headers.contains(&name)
            {
                return Err(SourcePlanArtifactError::InvalidExpression);
            }
            authority.request_headers.push(name);
        }
        authority.request_headers.sort_unstable();
        let mut response_headers = std::mem::take(&mut authority.response_headers);
        if response_headers.len() > MAX_STATIC_COMPONENTS {
            return Err(SourcePlanArtifactError::InvalidLimits);
        }
        for name in response_headers.drain(..) {
            let name = name.to_ascii_lowercase();
            if !registry_platform_httputil::destination::is_script_visible_response_header_name(
                &name,
            ) || authority.response_headers.contains(&name)
            {
                return Err(SourcePlanArtifactError::InvalidExpression);
            }
            authority.response_headers.push(name);
        }
        authority.response_headers.sort_unstable();
        if authority.signed_dci.is_some() {
            let [rule] = authority.allow.as_slice() else {
                return Err(SourcePlanArtifactError::InvalidPlan);
            };
            if authority.auth != SourceAuthDocument::OAuthClientCredentials
                || authority.response.format != ResponseFormatDocument::Json
                || rule.method != ReadMethod::ReadOnlyPost
                || rule.semantics != Some(ScriptReadSemanticsDocument::ReadOnly)
                || rule.path.contains('*')
            {
                return Err(SourcePlanArtifactError::InvalidPlan);
            }
        }
        (
            authority.auth.clone(),
            authority.response.max_bytes,
            authority
                .signed_dci
                .as_ref()
                .map(|dci| dci.jwks_operation.clone()),
        )
    };
    let credential_auth = (auth != SourceAuthDocument::None).then_some(auth);
    validate_credential_operation(&mut spec.plan, spec.bounds, credential_auth)?;
    match (
        signed_dci_jwks.as_deref(),
        spec.plan.verification_operations.as_slice(),
    ) {
        (None, []) => {}
        (Some(expected), [verification]) if verification.id == expected => {}
        _ => return Err(SourcePlanArtifactError::InvalidPlan),
    }
    for verification in &mut spec.plan.verification_operations {
        validate_fixed_path(&verification.path)?;
        normalize_data_status_set(&mut verification.accepted_statuses)?;
        if verification.method != ReadMethod::Get
            || verification.accepted_statuses != [200]
            || verification.step_limits.max_request_bytes == 0
            || verification.step_limits.timeout_ms == 0
            || verification.step_limits.timeout_ms > spec.bounds.timeout_ms
            || verification.step_limits.max_in_flight != 1
            || verification.max_response_bytes == 0
            || verification.max_response_bytes > MAX_DATA_RESPONSE_BYTES
        {
            return Err(SourcePlanArtifactError::InvalidPlan);
        }
    }
    let verification_bytes = spec
        .plan
        .verification_operations
        .iter()
        .try_fold(0_u64, |total, operation| {
            total.checked_add(u64::from(operation.max_response_bytes))
        })
        .ok_or(SourcePlanArtifactError::InvalidLimits)?;
    let data_response_count = spec
        .bounds
        .max_data_exchanges
        .checked_sub(
            u8::try_from(spec.plan.verification_operations.len())
                .map_err(|_| SourcePlanArtifactError::InvalidLimits)?,
        )
        .ok_or(SourcePlanArtifactError::InvalidLimits)?;
    let source_bytes = u64::from(response_max_bytes)
        .checked_mul(u64::from(data_response_count))
        .and_then(|total| total.checked_add(verification_bytes))
        .and_then(|total| {
            total.checked_add(
                spec.plan
                    .credential_operation
                    .as_ref()
                    .map_or(0, |operation| u64::from(operation.response.max_bytes)),
            )
        })
        .ok_or(SourcePlanArtifactError::InvalidLimits)?;
    if source_bytes > spec.bounds.max_source_bytes {
        return Err(SourcePlanArtifactError::InvalidLimits);
    }
    validate_template_kind(&spec.plan, spec.acquisition.class)
}

fn validate_dci_exact_plan(
    spec: &IntegrationPackSpecDocument,
) -> Result<(), SourcePlanArtifactError> {
    let exact_operations = spec
        .plan
        .operations
        .iter()
        .filter(|operation| operation.request_codec == Some(RequestCodecDocument::DciExactV1))
        .collect::<Vec<_>>();
    if exact_operations.is_empty() {
        return spec
            .plan
            .verification_operations
            .is_empty()
            .then_some(())
            .ok_or(SourcePlanArtifactError::InvalidPlan);
    }
    let [operation] = exact_operations.as_slice() else {
        return Err(SourcePlanArtifactError::InvalidPlan);
    };
    let Some(dci) = &operation.dci else {
        return Err(SourcePlanArtifactError::InvalidPlan);
    };
    let selector_names = spec.input_slots.iter().filter_map(|(name, input)| {
        (input.role == InputRoleDocument::Selector).then_some(name.as_str())
    });
    let exact_and_selector = (1..=MAX_SELECTOR_INPUTS).contains(&dci.exact_and.len())
        && dci.exact_and.keys().map(String::as_str).eq(selector_names)
        && dci.exact_and.values().all(|component| {
            valid_dci_field_name(&component.field)
                && decode_pointer_tokens(&component.response_pointer).is_ok()
        })
        && dci
            .exact_and
            .values()
            .map(|component| component.field.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            == dci.exact_and.len()
        && dci
            .exact_and
            .values()
            .map(|component| component.response_pointer.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            == dci.exact_and.len();
    if !exact_and_selector {
        return Err(SourcePlanArtifactError::InvalidPlan);
    }
    crate::source_plan::codec::dci::validate_profile_constants(
        &dci.protocol_version,
        &dci.sender_id,
        dci.receiver_id.as_deref(),
        dci.registry_type.as_deref(),
        dci.registry_event_type.as_deref(),
        dci.record_type.as_deref(),
        dci.identifier_type.as_deref().unwrap_or("exact-and"),
        &dci.locale,
        dci.page_number,
    )
    .map_err(|_| SourcePlanArtifactError::InvalidPlan)?;
    let [verification] = spec.plan.verification_operations.as_slice() else {
        return Err(SourcePlanArtifactError::InvalidPlan);
    };
    let exact_topology = (spec.plan.kind == SourcePlanKind::BoundedHttp
        && spec.plan.steps == [operation.id.as_str()])
        || (spec.plan.kind == SourcePlanKind::Script && spec.plan.steps.is_empty());
    let exact = exact_topology
        && spec.plan.operations.len() == 1
        && dci.jwks_operation == verification.id
        && verification.id != operation.id
        && matches!(
            verification.primitive,
            VerificationPrimitiveDocument::JwksV1
        )
        && spec.plan.verification_destination_slot.as_deref()
            == Some(verification.destination_slot.as_str())
        && verification.destination_slot != operation.destination_slot
        && verification.method == ReadMethod::Get
        && verification.accepted_statuses == [200]
        && verification.max_response_bytes > 0
        && verification.step_limits.max_request_bytes > 0
        && verification.step_limits.timeout_ms > 0
        && verification.step_limits.max_in_flight == 1
        && !dci.protocol_version.is_empty()
        && !dci.sender_id.is_empty()
        && dci
            .registry_type
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        && dci
            .record_type
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        && exact_and_selector
        && !dci.locale.is_empty()
        && dci.page_number > 0
        && operation.method == ReadMethod::ReadOnlyPost
        && operation.query.is_empty()
        && operation.headers.is_empty()
        && operation.body.is_none()
        && operation.relation_selector.is_none()
        && operation.request_signer.is_none()
        && operation
            .step_limits
            .is_some_and(|limits| limits.max_in_flight == 1)
        && operation.auth == SourceAuthDocument::OAuthClientCredentials
        && operation.response.accepted_statuses == [200]
        && operation.response.max_records <= 2;
    if !exact {
        return Err(SourcePlanArtifactError::InvalidPlan);
    }
    Ok(())
}

fn valid_dci_field_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

pub(super) fn validate_reviewed_acquisition(
    spec: &IntegrationPackSpecDocument,
    _acquired_fields: &BTreeSet<AcquiredField>,
) -> Result<(), SourcePlanArtifactError> {
    let reviewed = spec
        .reviewed_acquisition
        .as_ref()
        .ok_or(SourcePlanArtifactError::InvalidAcquisition)?;
    if reviewed.class != spec.acquisition.class
        || reviewed.cardinality.cardinality() != cardinality_from_bounds(spec.bounds)?
        || !reviewed.reject_unknown_fields
        || reviewed.fields.len() + reviewed.control_fields.len() > MAX_ACQUIRED_FIELDS
    {
        return Err(SourcePlanArtifactError::InvalidAcquisition);
    }

    let mut reviewed_schema_nodes = 0_usize;
    let mut reviewed_expanded_nodes = 0_usize;
    for (name, schema) in &reviewed.fields {
        AcquiredField::try_from(name.as_str())
            .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
        reviewed_expanded_nodes = reviewed_expanded_nodes
            .checked_add(validate_response_schema(
                schema,
                1,
                &mut reviewed_schema_nodes,
            )?)
            .ok_or(SourcePlanArtifactError::InvalidLimits)?;
    }
    if reviewed.control_fields.len() > MAX_ACQUIRED_FIELDS {
        return Err(SourcePlanArtifactError::InvalidAcquisition);
    }
    for (name, schema) in &reviewed.control_fields {
        AcquiredField::try_from(name.as_str())
            .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
        if reviewed.fields.contains_key(name) {
            return Err(SourcePlanArtifactError::InvalidAcquisition);
        }
        reviewed_expanded_nodes = reviewed_expanded_nodes
            .checked_add(validate_response_schema(
                schema,
                1,
                &mut reviewed_schema_nodes,
            )?)
            .ok_or(SourcePlanArtifactError::InvalidLimits)?;
    }
    if reviewed_expanded_nodes > MAX_RESPONSE_SCHEMA_EXPANDED_NODES {
        return Err(SourcePlanArtifactError::InvalidLimits);
    }
    let input_name = spec
        .input_slots
        .iter()
        .find_map(|(name, input)| (input.role == InputRoleDocument::Selector).then_some(name))
        .ok_or(SourcePlanArtifactError::InvalidAcquisition)?;
    let selector_names = spec
        .input_slots
        .iter()
        .filter_map(|(name, input)| {
            (input.role == InputRoleDocument::Selector).then_some(name.as_str())
        })
        .collect::<Vec<_>>();
    match reviewed.selector.as_ref() {
        Some(ExactSelectorDocument::HttpExactAnd {
            operation,
            components,
        }) if spec.plan.kind != SourcePlanKind::SnapshotExact
            && (1..=MAX_SELECTOR_INPUTS).contains(&components.len())
            && components
                .keys()
                .map(String::as_str)
                .eq(selector_names.iter().copied())
            && (spec.plan.steps.first() == Some(operation)
                || (spec.plan.kind == SourcePlanKind::Script && spec.plan.steps.is_empty()))
            && spec.plan.operations.iter().any(|candidate| {
                candidate.id == *operation
                    && candidate.relation_selector.is_none()
                    && candidate.input_selector.is_none()
                    && (spec.plan.kind != SourcePlanKind::Script
                        || candidate.request_codec == Some(RequestCodecDocument::DciExactV1))
                    && components.iter().all(|(input, location)| {
                        selector_location_matches(candidate, location, SelectorSource::Input(input))
                    })
            }) =>
        {
            if spec.plan.kind != SourcePlanKind::Script {
                validate_transitively_anchored_steps(&spec.plan, input_name)?;
            }
        }
        Some(ExactSelectorDocument::SnapshotExactAnd { components })
            if spec.plan.kind == SourcePlanKind::SnapshotExact
                && (1..=MAX_SELECTOR_INPUTS).contains(&components.len())
                && components
                    .keys()
                    .map(String::as_str)
                    .eq(selector_names.iter().copied()) => {}
        None if spec.plan.kind == SourcePlanKind::Script => {}
        _ => return Err(SourcePlanArtifactError::InvalidAcquisition),
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum SelectorSource<'a> {
    Input(&'a str),
    Prior { step: &'a str, output: &'a str },
}

fn selector_location_matches(
    operation: &HttpOperationDocument,
    location: &RequestSelectorLocationDocument,
    source: SelectorSource<'_>,
) -> bool {
    let expression_matches = |expression: &ValueExpressionDocument| match source {
        SelectorSource::Input(input) => matches!(
            expression,
            ValueExpressionDocument::ConsultationInput { name } if name == input
        ),
        SelectorSource::Prior { step, output } => matches!(
            expression,
            ValueExpressionDocument::PriorStepOutput {
                step: candidate_step,
                output: candidate_output,
            } if candidate_step == step && candidate_output == output
        ),
    };
    match location {
        RequestSelectorLocationDocument::Query { parameter } => operation
            .query
            .get(parameter)
            .is_some_and(expression_matches),
        RequestSelectorLocationDocument::Path { parameter } => operation
            .path_parameters
            .get(parameter)
            .is_some_and(expression_matches),
        RequestSelectorLocationDocument::Body { pointer } => operation
            .body
            .as_ref()
            .and_then(|body| resolve_body_pointer(body, pointer).ok())
            .is_some_and(|template| {
                matches!(template, BodyTemplateDocument::Expression { value } if expression_matches(value))
            }),
        RequestSelectorLocationDocument::Codec {
            role: CodecSelectorRoleDocument::DciIdtypeValue,
        } => matches!(
            operation.request_codec,
            Some(RequestCodecDocument::DciExactV1)
        ),
        RequestSelectorLocationDocument::Codec {
            role: CodecSelectorRoleDocument::DciExactPredicate,
        } => operation.request_codec == Some(RequestCodecDocument::DciExactV1)
            && operation
                .dci
                .as_ref()
                .is_some_and(|dci| dci.exact_and.contains_key(match source {
                    SelectorSource::Input(input) => input,
                    SelectorSource::Prior { .. } => return false,
                })),
    }
}

pub(super) fn validate_transitively_anchored_steps(
    plan: &PlanTemplateDocument,
    input: &str,
) -> Result<(), SourcePlanArtifactError> {
    let mut anchored = BTreeSet::new();
    for (index, step) in plan.steps.iter().enumerate() {
        let operation = plan
            .operations
            .iter()
            .find(|operation| operation.id == *step)
            .ok_or(SourcePlanArtifactError::InvalidPlan)?;
        if index == 0 {
            anchored.insert(step.clone());
            continue;
        }
        if operation.input_selector.as_ref().is_some_and(|location| {
            selector_location_matches(operation, location, SelectorSource::Input(input))
        }) {
            anchored.insert(step.clone());
            continue;
        }
        let relation = operation
            .relation_selector
            .as_ref()
            .ok_or(SourcePlanArtifactError::InvalidAcquisition)?;
        let source_exists = anchored.contains(relation.step.as_str())
            && plan.operations.iter().any(|candidate| {
                candidate.id == relation.step
                    && candidate
                        .response
                        .prior_outputs
                        .contains_key(&relation.output)
            });
        if !source_exists
            || !selector_location_matches(
                operation,
                &relation.location,
                SelectorSource::Prior {
                    step: &relation.step,
                    output: &relation.output,
                },
            )
        {
            return Err(SourcePlanArtifactError::InvalidAcquisition);
        }
        anchored.insert(step.clone());
    }
    Ok(())
}

pub(super) fn operation_prior_steps(operation: &HttpOperationDocument) -> BTreeSet<String> {
    let mut steps = BTreeSet::new();
    for expression in operation.query.values().chain(operation.headers.values()) {
        collect_prior_step(expression, &mut steps);
    }
    if let Some(body) = &operation.body {
        collect_body_prior_steps(body, &mut steps);
    }
    steps
}

pub(super) fn collect_prior_step(
    expression: &ValueExpressionDocument,
    steps: &mut BTreeSet<String>,
) {
    if let ValueExpressionDocument::PriorStepOutput { step, .. } = expression {
        steps.insert(step.clone());
    }
}

pub(super) fn collect_body_prior_steps(
    template: &BodyTemplateDocument,
    steps: &mut BTreeSet<String>,
) {
    match template {
        BodyTemplateDocument::Expression { value } => collect_prior_step(value, steps),
        BodyTemplateDocument::Array { items } => {
            for item in items {
                collect_body_prior_steps(item, steps);
            }
        }
        BodyTemplateDocument::Object { fields } => {
            for value in fields.values() {
                collect_body_prior_steps(value, steps);
            }
        }
        _ => {}
    }
}

pub(super) fn operation_uses_input(operation: &HttpOperationDocument, input: &str) -> bool {
    operation
        .path_parameters
        .values()
        .chain(operation.query.values())
        .chain(operation.headers.values())
        .any(|expression| expression_uses_input(expression, input))
        || operation
            .body
            .as_ref()
            .is_some_and(|body| body_uses_input(body, input))
}

pub(super) fn expression_uses_input(expression: &ValueExpressionDocument, input: &str) -> bool {
    matches!(
        expression,
        ValueExpressionDocument::ConsultationInput { name } if name == input
    )
}

pub(super) fn body_uses_input(template: &BodyTemplateDocument, input: &str) -> bool {
    match template {
        BodyTemplateDocument::Expression { value } => expression_uses_input(value, input),
        BodyTemplateDocument::Array { items } => {
            items.iter().any(|item| body_uses_input(item, input))
        }
        BodyTemplateDocument::Object { fields } => {
            fields.values().any(|value| body_uses_input(value, input))
        }
        _ => false,
    }
}

pub(super) fn validate_snapshot_plan(
    spec: &IntegrationPackSpecDocument,
) -> Result<(), SourcePlanArtifactError> {
    let plan = &spec.plan;
    let bounds = spec.bounds;
    if !plan.operations.is_empty()
        || !plan.steps.is_empty()
        || !plan.step_conditions.is_empty()
        || plan.data_destination_slot.is_some()
        || plan.credential_operation.is_some()
        || plan.credential_destination_slot.is_some()
        || plan.verification_destination_slot.is_some()
        || !plan.verification_operations.is_empty()
        || bounds.max_data_exchanges != 0
        || bounds.max_credential_exchanges != 0
        || bounds.max_data_destinations != 0
    {
        return Err(SourcePlanArtifactError::InvalidPlan);
    }
    validate_template_kind(plan, spec.acquisition.class)?;
    plan.snapshot
        .as_ref()
        .ok_or(SourcePlanArtifactError::InvalidPlan)?;
    let reviewed = spec
        .reviewed_acquisition
        .as_ref()
        .ok_or(SourcePlanArtifactError::InvalidAcquisition)?;
    let reviewed_fields = reviewed
        .fields
        .keys()
        .chain(reviewed.control_fields.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let acquisition_fields = spec
        .acquisition
        .fields
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    if reviewed_fields != acquisition_fields {
        return Err(SourcePlanArtifactError::InvalidAcquisition);
    }
    for provenance_field in [
        match &spec.source_provenance.source_observed_at {
            SourceObservedAtDocument::Absent => None,
            SourceObservedAtDocument::AcquiredRfc3339 { field } => Some(field),
        },
        match &spec.source_provenance.source_revision {
            SourceRevisionDocument::Absent => None,
            SourceRevisionDocument::AcquiredString { field, .. } => Some(field),
        },
    ]
    .into_iter()
    .flatten()
    {
        if !reviewed.control_fields.contains_key(provenance_field) {
            return Err(SourcePlanArtifactError::InvalidAcquisition);
        }
    }
    Ok(())
}

struct HttpOperationValidationContext<'a> {
    plan_kind: SourcePlanKind,
    inputs: &'a BTreeMap<String, InputDocument>,
    parameters: &'a BTreeMap<String, ParameterDeclarationDocument>,
    reviewed_control_fields: &'a BTreeMap<String, ResponseSchemaDocument>,
    acquisition_class: AcquisitionClassDocument,
    evidence: &'a EvidenceManifestDocument,
    bounds: LimitsDocument,
    oauth_authorization_max_bytes: Option<usize>,
    output: &'a BTreeMap<String, OutputFieldDocument>,
    prior_output_bounds: &'a BTreeMap<(String, String), usize>,
}

fn validate_http_operation(
    operation: &mut HttpOperationDocument,
    context: &HttpOperationValidationContext<'_>,
) -> Result<(), SourcePlanArtifactError> {
    let HttpOperationValidationContext {
        plan_kind,
        inputs,
        parameters,
        reviewed_control_fields,
        acquisition_class,
        evidence,
        bounds,
        oauth_authorization_max_bytes,
        output,
        prior_output_bounds,
    } = context;
    if *plan_kind == SourcePlanKind::Script {
        registry_platform_httputil::destination::validate_script_destination_path_rule(
            &operation.path,
        )
        .map_err(|_| SourcePlanArtifactError::InvalidPlan)?;
    } else {
        operation_path_parts(operation)?;
    }
    if operation.response.format == ResponseFormatDocument::Text
        && context.plan_kind != SourcePlanKind::Script
    {
        return Err(SourcePlanArtifactError::InvalidPlan);
    }
    if operation.response.selected_headers.len() > MAX_STATIC_COMPONENTS {
        return Err(SourcePlanArtifactError::InvalidLimits);
    }
    let selected_headers = std::mem::take(&mut operation.response.selected_headers);
    for name in selected_headers {
        let canonical_name = name.to_ascii_lowercase();
        if !registry_platform_httputil::destination::is_script_visible_response_header_name(
            &canonical_name,
        ) || operation
            .response
            .selected_headers
            .contains(&canonical_name)
        {
            return Err(SourcePlanArtifactError::InvalidExpression);
        }
        operation.response.selected_headers.push(canonical_name);
    }
    operation.response.selected_headers.sort_unstable();
    if !operation.response.selected_headers.is_empty()
        && context.plan_kind != SourcePlanKind::Script
    {
        return Err(SourcePlanArtifactError::InvalidPlan);
    }
    let script_request_headers = std::mem::take(&mut operation.script_request_headers);
    for name in script_request_headers {
        let canonical_name = name.to_ascii_lowercase();
        if *plan_kind != SourcePlanKind::Script
            || !registry_platform_httputil::destination::is_script_writable_request_header_name(
                &canonical_name,
            )
            || operation.script_request_headers.contains(&canonical_name)
        {
            return Err(SourcePlanArtifactError::InvalidExpression);
        }
        operation.script_request_headers.push(canonical_name);
    }
    operation.script_request_headers.sort_unstable();
    if operation.script_request_headers.len() > MAX_STATIC_COMPONENTS {
        return Err(SourcePlanArtifactError::InvalidLimits);
    }
    if (operation.request_codec == Some(RequestCodecDocument::DciExactV1))
        != operation.dci.is_some()
    {
        return Err(SourcePlanArtifactError::InvalidPlan);
    }
    if operation.input_selector.is_some() && operation.relation_selector.is_some() {
        return Err(SourcePlanArtifactError::InvalidAcquisition);
    }
    let authored_headers = std::mem::take(&mut operation.headers);
    for (name, expression) in authored_headers {
        let canonical_name = name.to_ascii_lowercase();
        validate_header_name(&canonical_name)?;
        if canonical_name == "data-purpose"
            && !matches!(&expression, ValueExpressionDocument::Literal { .. })
        {
            return Err(SourcePlanArtifactError::InvalidExpression);
        }
        if operation
            .headers
            .insert(canonical_name, expression)
            .is_some()
        {
            return Err(SourcePlanArtifactError::InvalidSet);
        }
    }
    match &operation.auth {
        SourceAuthDocument::ApiKeyHeader {
            name,
            max_value_bytes,
        } if (*max_value_bytes == 0)
            || (name != "x-api-key" && validate_header_name(name).is_err())
            || operation.headers.contains_key(name) =>
        {
            return Err(SourcePlanArtifactError::InvalidPlan);
        }
        SourceAuthDocument::ApiKeyQuery {
            name,
            max_value_bytes,
        } if *max_value_bytes == 0
            || validate_query_name(name).is_err()
            || operation.query.contains_key(name) =>
        {
            return Err(SourcePlanArtifactError::InvalidPlan);
        }
        _ => {}
    }
    if operation.query.len() > MAX_STATIC_COMPONENTS
        || operation.headers.len() + usize::from(operation.auth != SourceAuthDocument::None)
            > MAX_STATIC_COMPONENTS
    {
        return Err(SourcePlanArtifactError::InvalidLimits);
    }
    validate_request_shape(
        operation,
        *plan_kind,
        inputs,
        parameters,
        *bounds,
        *oauth_authorization_max_bytes,
        prior_output_bounds,
    )?;
    for expression in operation.path_parameters.values() {
        validate_expression(expression, inputs, parameters)?;
    }
    for (name, expression) in &operation.query {
        validate_query_name(name)?;
        validate_expression(expression, inputs, parameters)?;
    }
    for (name, expression) in &operation.headers {
        validate_header_name(name)?;
        validate_expression(expression, inputs, parameters)?;
    }
    if let Some(body) = &operation.body {
        let mut node_count = 0;
        validate_body_template(body, inputs, parameters, 1, &mut node_count)?;
    }
    if operation.acquisition_fields.is_empty() {
        if !operation.response.output_mapping.is_empty() {
            return Err(SourcePlanArtifactError::InvalidSet);
        }
    } else {
        normalize_stable_set(&mut operation.acquisition_fields)?;
    }
    if operation.control_fields.is_empty() {
        if *plan_kind != SourcePlanKind::Script && !operation.response.prior_outputs.is_empty() {
            return Err(SourcePlanArtifactError::InvalidAcquisition);
        }
    } else {
        normalize_stable_set(&mut operation.control_fields)?;
    }
    let declared_operation_controls = operation
        .control_fields
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let prior_names = operation
        .response
        .prior_outputs
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if (*plan_kind == SourcePlanKind::Script
        && !declared_operation_controls.is_subset(&prior_names))
        || (*plan_kind != SourcePlanKind::Script && declared_operation_controls != prior_names)
    {
        return Err(SourcePlanArtifactError::InvalidAcquisition);
    }
    validate_projection(operation, *acquisition_class, evidence)?;
    let script_body = matches!(
        operation.response.schema,
        ResponseSchemaDocument::ScriptBody
    ) || operation.response.normalization
        == ResponseNormalizationDocument::ScriptBody
        || operation.response.cardinality == CardinalityMechanismDocument::ScriptManaged;
    if script_body
        && (*plan_kind != SourcePlanKind::Script
            || !matches!(
                operation.response.schema,
                ResponseSchemaDocument::ScriptBody
            )
            || operation.response.normalization != ResponseNormalizationDocument::ScriptBody
            || operation.response.cardinality != CardinalityMechanismDocument::ScriptManaged
            || !matches!(
                operation.request_codec,
                None | Some(RequestCodecDocument::None)
            )
            || operation.dci.is_some()
            || operation.response.max_records != 1
            || operation.response.records_field.is_some()
            || !operation.acquisition_fields.is_empty()
            || !operation.control_fields.is_empty()
            || !operation.response.output_mapping.is_empty()
            || !operation.response.prior_outputs.is_empty()
            || !operation.response.accepted_statuses.is_empty()
            || !operation.response.status_outcomes.no_match.is_empty()
            || !operation.response.status_outcomes.ambiguous.is_empty())
    {
        return Err(SourcePlanArtifactError::InvalidAcquisition);
    }
    let operation_cardinality = match operation.response.max_records {
        1 => SourceCardinality::Singleton,
        2 => SourceCardinality::AmbiguityProbe,
        _ => return Err(SourcePlanArtifactError::InvalidAcquisition),
    };
    validate_cardinality_mechanism(operation, operation_cardinality, evidence)?;
    if operation.response.max_bytes == 0 || operation.response.max_bytes > MAX_DATA_RESPONSE_BYTES {
        return Err(SourcePlanArtifactError::InvalidLimits);
    }
    if !script_body {
        normalize_data_status_set(&mut operation.response.accepted_statuses)?;
    }
    for statuses in [
        &mut operation.response.status_outcomes.no_match,
        &mut operation.response.status_outcomes.ambiguous,
    ] {
        if !statuses.is_empty() {
            normalize_data_status_set(statuses)?;
        }
    }
    let outcome_statuses = operation
        .response
        .status_outcomes
        .no_match
        .iter()
        .chain(&operation.response.status_outcomes.ambiguous)
        .copied()
        .collect::<BTreeSet<_>>();
    if !script_body
        && (outcome_statuses.len()
            != operation.response.status_outcomes.no_match.len()
                + operation.response.status_outcomes.ambiguous.len()
            || outcome_statuses.iter().any(|status| {
                operation
                    .response
                    .accepted_statuses
                    .binary_search(status)
                    .is_err()
            })
            || outcome_statuses
                .iter()
                .any(|status| (200..=299).contains(status))
            || operation
                .response
                .accepted_statuses
                .iter()
                .any(|status| !(200..=299).contains(status) && !outcome_statuses.contains(status))
            || operation
                .response
                .accepted_statuses
                .iter()
                .all(|status| outcome_statuses.contains(status)))
    {
        return Err(SourcePlanArtifactError::InvalidAcquisition);
    }
    let mut schema_nodes = 0_usize;
    let expanded_nodes = validate_operation_response_schema(
        &operation.response.schema,
        1,
        &mut schema_nodes,
        *plan_kind == SourcePlanKind::BoundedHttp,
    )?;
    if expanded_nodes > MAX_RESPONSE_SCHEMA_EXPANDED_NODES {
        return Err(SourcePlanArtifactError::InvalidLimits);
    }
    let record_schema = response_record_schema(
        &operation.response.schema,
        &operation.response.normalization,
        operation.response.max_records,
        operation.response.records_field.as_deref(),
    )?;
    if operation.response.prior_outputs.len() > MAX_STATIC_COMPONENTS {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    let mut exposed_pointers = BTreeSet::new();
    for (name, prior_output) in &operation.response.prior_outputs {
        validate_stable_text(name)?;
        let pointer_tokens = decode_pointer_tokens(&prior_output.pointer)?;
        let raw_schema = resolve_response_pointer(record_schema, &pointer_tokens)?;
        let bounds_valid = match prior_output.output_type {
            OutputTypeDocument::String => {
                prior_output
                    .max_bytes
                    .is_some_and(|value| (1..=MAX_INPUT_BYTES).contains(&u32::from(value)))
                    && prior_output.minimum.is_none()
                    && prior_output.maximum.is_none()
            }
            OutputTypeDocument::Integer => {
                prior_output.max_bytes.is_none()
                    && matches!((prior_output.minimum, prior_output.maximum), (Some(min), Some(max)) if min <= max && min.unsigned_abs() <= MAX_JSON_INTEROPERABLE_INTEGER && max.unsigned_abs() <= MAX_JSON_INTEROPERABLE_INTEGER)
            }
            OutputTypeDocument::Boolean => {
                prior_output.max_bytes.is_none()
                    && prior_output.minimum.is_none()
                    && prior_output.maximum.is_none()
            }
            OutputTypeDocument::Date => {
                prior_output.max_bytes == Some(10)
                    && prior_output.minimum.is_none()
                    && prior_output.maximum.is_none()
            }
        };
        if !bounds_valid
            || !prior_output_matches_schema(prior_output, raw_schema)
            || (reviewed_control_fields
                .get(name)
                .is_none_or(|schema| !schema.matches_response_schema(raw_schema))
                && *plan_kind != SourcePlanKind::Script)
            || !exposed_pointers.insert(pointer_tokens)
        {
            return Err(SourcePlanArtifactError::InvalidLimits);
        }
    }
    for (field, pointer) in &operation.response.output_mapping {
        AcquiredField::try_from(field.as_str())
            .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
        let pointer_tokens = decode_pointer_tokens(pointer)?;
        let raw_schema = resolve_response_pointer(record_schema, &pointer_tokens)?;
        let declared = output
            .get(field.as_str())
            .ok_or(SourcePlanArtifactError::InvalidAcquisition)?;
        let type_matches = match declared.output_type {
            OutputTypeDocument::Date => matches!(raw_schema, ResponseSchemaDocument::String {
                nullable,
                max_bytes: 10,
            } if !*nullable || declared.nullable),
            OutputTypeDocument::String => matches!(raw_schema, ResponseSchemaDocument::String {
                nullable,
                ..
            } if !*nullable || declared.nullable),
            OutputTypeDocument::Boolean => matches!(raw_schema, ResponseSchemaDocument::Boolean {
                nullable,
            } if !*nullable || declared.nullable),
            OutputTypeDocument::Integer => matches!(raw_schema, ResponseSchemaDocument::Integer {
                nullable,
                ..
            } if !*nullable || declared.nullable),
        };
        let reviewed_rhai_alias = if *plan_kind == SourcePlanKind::Script {
            operation
                .response
                .prior_outputs
                .get(field)
                .map(|prior| decode_pointer_tokens(&prior.pointer))
                .transpose()?
                .is_some_and(|prior_tokens| prior_tokens == pointer_tokens)
        } else {
            false
        };
        if !type_matches || (!exposed_pointers.insert(pointer_tokens) && !reviewed_rhai_alias) {
            return Err(SourcePlanArtifactError::InvalidAcquisition);
        }
    }
    Ok(())
}

pub(in crate::source_plan) fn validate_response_schema(
    schema: &ResponseSchemaDocument,
    depth: usize,
    nodes: &mut usize,
) -> Result<usize, SourcePlanArtifactError> {
    validate_operation_response_schema(schema, depth, nodes, false)
}

fn validate_operation_response_schema(
    schema: &ResponseSchemaDocument,
    depth: usize,
    nodes: &mut usize,
    allow_ignored_unknown_fields: bool,
) -> Result<usize, SourcePlanArtifactError> {
    *nodes = nodes
        .checked_add(1)
        .ok_or(SourcePlanArtifactError::InvalidLimits)?;
    if depth > MAX_RESPONSE_SCHEMA_DEPTH || *nodes > MAX_RESPONSE_SCHEMA_NODES {
        return Err(SourcePlanArtifactError::InvalidLimits);
    }
    match schema {
        ResponseSchemaDocument::ScriptBody => Ok(1),
        ResponseSchemaDocument::Object {
            reject_unknown_fields,
            fields,
            ..
        } => {
            if (!reject_unknown_fields && !allow_ignored_unknown_fields)
                || fields.is_empty()
                || fields.len() > MAX_STATIC_COMPONENTS
            {
                return Err(SourcePlanArtifactError::InvalidAcquisition);
            }
            let mut expanded = 1_usize;
            for (name, field) in fields {
                validate_response_field_name(name)?;
                let child = validate_operation_response_schema(
                    &field.schema,
                    depth + 1,
                    nodes,
                    allow_ignored_unknown_fields,
                )?;
                expanded = expanded
                    .checked_add(child)
                    .ok_or(SourcePlanArtifactError::InvalidLimits)?;
            }
            Ok(expanded)
        }
        ResponseSchemaDocument::Array {
            max_items, items, ..
        } => {
            if !(1..=MAX_RESPONSE_ARRAY_ITEMS).contains(max_items) {
                return Err(SourcePlanArtifactError::InvalidLimits);
            }
            let child = validate_operation_response_schema(
                items,
                depth + 1,
                nodes,
                allow_ignored_unknown_fields,
            )?;
            usize::from(*max_items)
                .checked_mul(child)
                .and_then(|expanded| expanded.checked_add(1))
                .ok_or(SourcePlanArtifactError::InvalidLimits)
        }
        ResponseSchemaDocument::String { max_bytes, .. }
            if (1..=MAX_PUBLIC_RESPONSE_BYTES).contains(max_bytes) =>
        {
            Ok(1)
        }
        ResponseSchemaDocument::Integer {
            minimum, maximum, ..
        }
        | ResponseSchemaDocument::Number {
            minimum, maximum, ..
        } if minimum <= maximum
            && minimum.unsigned_abs() <= MAX_JSON_INTEROPERABLE_INTEGER
            && maximum.unsigned_abs() <= MAX_JSON_INTEROPERABLE_INTEGER =>
        {
            Ok(1)
        }
        ResponseSchemaDocument::Boolean { .. } => Ok(1),
        _ => Err(SourcePlanArtifactError::InvalidLimits),
    }
}

pub(super) fn validate_response_field_name(name: &str) -> Result<(), SourcePlanArtifactError> {
    let valid = !name.is_empty()
        && name.len() <= 128
        && !name.chars().any(|character| character.is_control());
    valid
        .then_some(())
        .ok_or(SourcePlanArtifactError::InvalidText)
}

pub(in super::super) fn response_record_schema<'a>(
    schema: &'a ResponseSchemaDocument,
    normalization: &ResponseNormalizationDocument,
    max_records: u8,
    records_field: Option<&str>,
) -> Result<&'a ResponseSchemaDocument, SourcePlanArtifactError> {
    match (normalization, schema) {
        (ResponseNormalizationDocument::ScriptBody, ResponseSchemaDocument::ScriptBody)
            if max_records == 1 && records_field.is_none() =>
        {
            Ok(schema)
        }
        (
            ResponseNormalizationDocument::Object,
            ResponseSchemaDocument::Object {
                nullable: false, ..
            },
        ) if max_records == 1 && records_field.is_none() => Ok(schema),
        (
            ResponseNormalizationDocument::ArrayProbeTwo,
            ResponseSchemaDocument::Array {
                nullable: false,
                max_items,
                items,
            },
        ) if records_field.is_none()
            && *max_items == u16::from(max_records)
            && matches!(
                items.as_ref(),
                ResponseSchemaDocument::Object {
                    nullable: false,
                    ..
                }
            ) =>
        {
            Ok(items)
        }
        (
            ResponseNormalizationDocument::ObjectArrayProbeTwo,
            ResponseSchemaDocument::Object {
                nullable: false,
                fields,
                ..
            },
        ) if max_records == 2 => {
            let records_field = records_field.ok_or(SourcePlanArtifactError::InvalidAcquisition)?;
            validate_response_field_name(records_field)?;
            let field = fields
                .get(records_field)
                .ok_or(SourcePlanArtifactError::InvalidAcquisition)?;
            if !field.required
                || fields.iter().any(|(name, candidate)| {
                    name != records_field
                        && matches!(
                            candidate.schema.as_ref(),
                            ResponseSchemaDocument::Array { .. }
                        )
                })
            {
                return Err(SourcePlanArtifactError::InvalidAcquisition);
            }
            match field.schema.as_ref() {
                ResponseSchemaDocument::Array {
                    nullable: false,
                    max_items,
                    items,
                } if *max_items == u16::from(max_records)
                    && matches!(
                        items.as_ref(),
                        ResponseSchemaDocument::Object {
                            nullable: false,
                            ..
                        }
                    ) =>
                {
                    Ok(items)
                }
                _ => Err(SourcePlanArtifactError::InvalidAcquisition),
            }
        }
        _ => Err(SourcePlanArtifactError::InvalidAcquisition),
    }
}

pub(in super::super) fn decode_pointer_tokens(
    pointer: &str,
) -> Result<Vec<String>, SourcePlanArtifactError> {
    validate_pointer(pointer)?;
    pointer[1..]
        .split('/')
        .map(|token| {
            let mut decoded = String::with_capacity(token.len());
            let mut chars = token.chars();
            while let Some(character) = chars.next() {
                if character == '~' {
                    match chars.next() {
                        Some('0') => decoded.push('~'),
                        Some('1') => decoded.push('/'),
                        _ => return Err(SourcePlanArtifactError::InvalidText),
                    }
                } else {
                    decoded.push(character);
                }
            }
            Ok(decoded)
        })
        .collect()
}

pub(super) fn resolve_response_pointer<'a>(
    schema: &'a ResponseSchemaDocument,
    tokens: &[String],
) -> Result<&'a ResponseSchemaDocument, SourcePlanArtifactError> {
    let mut current = schema;
    for token in tokens {
        current = match current {
            ResponseSchemaDocument::Object { fields, .. } => fields
                .get(token)
                .map(|field| field.schema.as_ref())
                .ok_or(SourcePlanArtifactError::InvalidAcquisition)?,
            ResponseSchemaDocument::Array {
                max_items, items, ..
            } => {
                let index = token
                    .parse::<u16>()
                    .map_err(|_| SourcePlanArtifactError::InvalidAcquisition)?;
                if index.to_string() != *token || index >= *max_items {
                    return Err(SourcePlanArtifactError::InvalidAcquisition);
                }
                items
            }
            _ => return Err(SourcePlanArtifactError::InvalidAcquisition),
        };
    }
    match current {
        ResponseSchemaDocument::String { .. }
        | ResponseSchemaDocument::Boolean { .. }
        | ResponseSchemaDocument::Integer { .. }
        | ResponseSchemaDocument::Number { .. } => Ok(current),
        ResponseSchemaDocument::ScriptBody
        | ResponseSchemaDocument::Object { .. }
        | ResponseSchemaDocument::Array { .. } => Err(SourcePlanArtifactError::InvalidAcquisition),
    }
}

pub(super) fn prior_output_matches_schema(
    output: &PriorOutputBindingDocument,
    schema: &ResponseSchemaDocument,
) -> bool {
    match (output.output_type, schema) {
        (
            OutputTypeDocument::String,
            ResponseSchemaDocument::String {
                nullable,
                max_bytes,
            },
        ) => {
            output.nullable == *nullable
                && output.max_bytes == u16::try_from(*max_bytes).ok()
                && output.minimum.is_none()
                && output.maximum.is_none()
        }
        (
            OutputTypeDocument::Integer,
            ResponseSchemaDocument::Integer {
                nullable,
                minimum,
                maximum,
            },
        ) => {
            output.nullable == *nullable
                && output.max_bytes.is_none()
                && output.minimum == Some(*minimum)
                && output.maximum == Some(*maximum)
        }
        (OutputTypeDocument::Boolean, ResponseSchemaDocument::Boolean { nullable }) => {
            output.nullable == *nullable
                && output.max_bytes.is_none()
                && output.minimum.is_none()
                && output.maximum.is_none()
        }
        (
            OutputTypeDocument::Date,
            ResponseSchemaDocument::String {
                nullable,
                max_bytes: 10,
            },
        ) => {
            output.nullable == *nullable
                && output.max_bytes == Some(10)
                && output.minimum.is_none()
                && output.maximum.is_none()
        }
        _ => false,
    }
}

#[derive(Serialize)]
struct HashedRequestTemplate<'a> {
    method: ReadMethod,
    path: &'a str,
    query: &'a BTreeMap<String, ValueExpressionDocument>,
    headers: &'a BTreeMap<String, ValueExpressionDocument>,
    body: &'a Option<BodyTemplateDocument>,
    request_codec: Option<RequestCodecDocument>,
    dci: &'a Option<DciExactDocument>,
    request_signer: Option<RequestSignerDocument>,
    auth: SourceAuthDocument,
}

pub(super) fn request_template_hash(
    operation: &HttpOperationDocument,
) -> Result<String, SourcePlanArtifactError> {
    let template = HashedRequestTemplate {
        method: operation.method,
        path: &operation.path,
        query: &operation.query,
        headers: &operation.headers,
        body: &operation.body,
        request_codec: operation.request_codec,
        dci: &operation.dci,
        request_signer: operation.request_signer,
        auth: operation.auth.clone(),
    };
    hash_document(REQUEST_TEMPLATE_HASH_DOMAIN, &template).map(|(_, hash)| hash)
}

pub(super) fn validate_projection(
    operation: &HttpOperationDocument,
    acquisition_class: AcquisitionClassDocument,
    evidence: &EvidenceManifestDocument,
) -> Result<(), SourcePlanArtifactError> {
    match (&operation.projection, acquisition_class) {
        (
            ProjectionMechanismDocument::QueryParameterExact {
                parameter,
                delimiter,
            },
            AcquisitionClassDocument::SourceProjectedExact,
        ) => {
            validate_query_name(parameter)?;
            if !matches!(delimiter.as_str(), "," | " ") {
                return Err(SourcePlanArtifactError::InvalidExpression);
            }
            let record_schema = response_record_schema(
                &operation.response.schema,
                &operation.response.normalization,
                operation.response.max_records,
                operation.response.records_field.as_deref(),
            )?;
            let ResponseSchemaDocument::Object { fields, .. } = record_schema else {
                return Err(SourcePlanArtifactError::InvalidAcquisition);
            };
            let mut projected_fields = fields.keys().map(String::as_str).collect::<Vec<_>>();
            projected_fields.sort_unstable();
            let expected = projected_fields.join(delimiter);
            match operation.query.get(parameter) {
                Some(ValueExpressionDocument::Literal { value }) if value == &expected => Ok(()),
                _ => Err(SourcePlanArtifactError::InvalidAcquisition),
            }
        }
        (
            ProjectionMechanismDocument::ReviewedRequestTemplate {
                request_hash,
                minimization_evidence,
            },
            AcquisitionClassDocument::SourceProjectedExact,
        ) => {
            IntegrationPackHash::try_from(request_hash.as_str())
                .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
            IntegrationPackHash::try_from(minimization_evidence.as_str())
                .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
            if request_template_hash(operation)? == *request_hash
                && evidence
                    .minimization
                    .binary_search(minimization_evidence)
                    .is_ok()
            {
                Ok(())
            } else {
                Err(SourcePlanArtifactError::InvalidAcquisition)
            }
        }
        (
            ProjectionMechanismDocument::BoundedFullRecord,
            AcquisitionClassDocument::BoundedFullRecord,
        ) => Ok(()),
        _ => Err(SourcePlanArtifactError::InvalidAcquisition),
    }
}

pub(super) fn validate_cardinality_mechanism(
    operation: &HttpOperationDocument,
    cardinality: SourceCardinality,
    evidence: &EvidenceManifestDocument,
) -> Result<(), SourcePlanArtifactError> {
    match (&operation.response.cardinality, cardinality) {
        (CardinalityMechanismDocument::ScriptManaged, SourceCardinality::Singleton)
            if matches!(
                operation.response.schema,
                ResponseSchemaDocument::ScriptBody
            ) && operation.response.normalization
                == ResponseNormalizationDocument::ScriptBody =>
        {
            Ok(())
        }
        (CardinalityMechanismDocument::DciProbeTwo, SourceCardinality::AmbiguityProbe)
            if operation.request_codec == Some(RequestCodecDocument::DciExactV1) =>
        {
            Ok(())
        }
        (
            CardinalityMechanismDocument::ProbeQueryParameter { parameter },
            SourceCardinality::AmbiguityProbe,
        ) => {
            validate_query_name(parameter)?;
            match operation.query.get(parameter) {
                Some(ValueExpressionDocument::Literal { value })
                    if value == &operation.response.max_records.to_string() =>
                {
                    Ok(())
                }
                _ => Err(SourcePlanArtifactError::InvalidAcquisition),
            }
        }
        (
            CardinalityMechanismDocument::ProbeBodyInteger { pointer },
            SourceCardinality::AmbiguityProbe,
        ) => match operation
            .body
            .as_ref()
            .and_then(|body| resolve_body_pointer(body, pointer).ok())
        {
            Some(BodyTemplateDocument::Integer { value })
                if *value == i64::from(operation.response.max_records) =>
            {
                Ok(())
            }
            _ => Err(SourcePlanArtifactError::InvalidAcquisition),
        },
        (
            CardinalityMechanismDocument::ReviewedRequestTemplateProbe {
                request_hash,
                conformance_evidence,
            },
            SourceCardinality::AmbiguityProbe,
        ) => validate_reviewed_cardinality_evidence(
            operation,
            request_hash,
            conformance_evidence,
            evidence,
        ),
        (
            CardinalityMechanismDocument::SourceEnforcedSingleton {
                conformance_evidence,
            },
            SourceCardinality::Singleton,
        ) => {
            IntegrationPackHash::try_from(conformance_evidence.as_str())
                .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
            evidence
                .conformance
                .binary_search(conformance_evidence)
                .map(|_| ())
                .map_err(|_| SourcePlanArtifactError::InvalidAcquisition)
        }
        _ => Err(SourcePlanArtifactError::InvalidAcquisition),
    }
}

pub(super) fn validate_reviewed_cardinality_evidence(
    operation: &HttpOperationDocument,
    request_hash: &str,
    conformance_evidence: &str,
    evidence: &EvidenceManifestDocument,
) -> Result<(), SourcePlanArtifactError> {
    IntegrationPackHash::try_from(request_hash)
        .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
    IntegrationPackHash::try_from(conformance_evidence)
        .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
    if request_template_hash(operation)? == request_hash
        && evidence
            .conformance
            .binary_search_by(|candidate| candidate.as_str().cmp(conformance_evidence))
            .is_ok()
    {
        Ok(())
    } else {
        Err(SourcePlanArtifactError::InvalidAcquisition)
    }
}

pub(super) fn resolve_body_pointer<'a>(
    body: &'a BodyTemplateDocument,
    pointer: &str,
) -> Result<&'a BodyTemplateDocument, SourcePlanArtifactError> {
    let mut current = body;
    for token in decode_pointer_tokens(pointer)? {
        current = match current {
            BodyTemplateDocument::Object { fields } => fields
                .get(&token)
                .ok_or(SourcePlanArtifactError::InvalidExpression)?,
            BodyTemplateDocument::Array { items } => {
                let index = token
                    .parse::<usize>()
                    .map_err(|_| SourcePlanArtifactError::InvalidExpression)?;
                if index.to_string() != token {
                    return Err(SourcePlanArtifactError::InvalidExpression);
                }
                items
                    .get(index)
                    .ok_or(SourcePlanArtifactError::InvalidExpression)?
            }
            _ => return Err(SourcePlanArtifactError::InvalidExpression),
        };
    }
    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string_input(role: InputRoleDocument, max_length: u32) -> InputDocument {
        InputDocument {
            role,
            schema_type: InputSchemaTypeDocument::Scalar(InputScalarTypeDocument::String),
            format: None,
            max_length: Some(max_length),
            min_length: None,
            max_bytes: max_length.checked_mul(4),
            pattern: None,
            canonicalization: CanonicalizationDocument::Identity,
            minimum: None,
            maximum: None,
            allowed_values: Vec::new(),
            constant: None,
        }
    }

    #[test]
    fn typed_inputs_require_selectors_and_bound_their_canonical_aggregate() {
        let mut inputs = BTreeMap::from([(
            "subject_id".to_owned(),
            string_input(InputRoleDocument::Selector, 64),
        )]);
        inputs.insert(
            "include_history".to_owned(),
            InputDocument {
                role: InputRoleDocument::Parameter,
                schema_type: InputSchemaTypeDocument::Nullable(vec![
                    InputTypeMemberDocument::Boolean,
                    InputTypeMemberDocument::Null,
                ]),
                format: None,
                max_length: None,
                min_length: None,
                max_bytes: None,
                pattern: None,
                canonicalization: CanonicalizationDocument::Identity,
                minimum: None,
                maximum: None,
                allowed_values: Vec::new(),
                constant: None,
            },
        );
        assert_eq!(validate_inputs(&inputs), Ok(()));

        inputs.get_mut("subject_id").expect("selector").schema_type =
            InputSchemaTypeDocument::Nullable(vec![
                InputTypeMemberDocument::String,
                InputTypeMemberDocument::Null,
            ]);
        assert_eq!(
            validate_inputs(&inputs),
            Err(SourcePlanArtifactError::InvalidAcquisition)
        );

        let oversized = BTreeMap::from([
            (
                "first".to_owned(),
                string_input(InputRoleDocument::Selector, 513),
            ),
            (
                "second".to_owned(),
                string_input(InputRoleDocument::Selector, 512),
            ),
        ]);
        assert_eq!(
            validate_inputs(&oversized),
            Err(SourcePlanArtifactError::InvalidLimits)
        );
    }

    #[test]
    fn typed_integer_parameters_require_json_safe_closed_bounds() {
        let mut inputs = BTreeMap::from([
            (
                "subject_id".to_owned(),
                string_input(InputRoleDocument::Selector, 64),
            ),
            (
                "year".to_owned(),
                InputDocument {
                    role: InputRoleDocument::Parameter,
                    schema_type: InputSchemaTypeDocument::Scalar(InputScalarTypeDocument::Integer),
                    format: None,
                    max_length: None,
                    min_length: None,
                    max_bytes: None,
                    pattern: None,
                    canonicalization: CanonicalizationDocument::Identity,
                    minimum: Some(1900),
                    maximum: Some(2100),
                    allowed_values: Vec::new(),
                    constant: None,
                },
            ),
        ]);
        assert_eq!(validate_inputs(&inputs), Ok(()));
        inputs.get_mut("year").expect("year").maximum = Some(9_007_199_254_740_992);
        assert_eq!(
            validate_inputs(&inputs),
            Err(SourcePlanArtifactError::InvalidLimits)
        );
    }
}
