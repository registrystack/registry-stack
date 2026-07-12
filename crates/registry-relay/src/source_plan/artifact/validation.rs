//! Cross-artifact semantics, minimization, selectors, and response-schema validation.

use super::*;
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

pub(super) fn validate_subject(
    subject: &SubjectDocument,
) -> Result<SelectorProvenance, SourcePlanArtifactError> {
    match &subject.selector_provenance {
        SelectorProvenanceDocument::TrustedNotaryAssertion { assertion_contract } => {
            let id = AssertionContractId::try_from(assertion_contract.id.as_str())
                .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
            let hash = AssertionContractHash::try_from(assertion_contract.hash.as_str())
                .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
            Ok(SelectorProvenance::TrustedNotaryAssertion(
                AssertionContractIdentity::new(id, hash),
            ))
        }
        SelectorProvenanceDocument::WorkloadSelected => Ok(SelectorProvenance::WorkloadSelected),
    }
}

pub(super) fn validate_inputs(
    inputs: &BTreeMap<String, InputDocument>,
) -> Result<(), SourcePlanArtifactError> {
    if inputs.len() != 1 {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    for (name, input) in inputs {
        validate_stable_text(name)?;
        if input.max_bytes == 0 || input.max_bytes > MAX_INPUT_BYTES {
            return Err(SourcePlanArtifactError::InvalidLimits);
        }
        validate_bounded_text(&input.pattern, MAX_PATTERN_BYTES)?;
        validate_input_pattern(&input.pattern)?;
    }
    Ok(())
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
) -> Result<(), SourcePlanArtifactError> {
    match (&provenance.source_observed_at, &provenance.source_revision) {
        (SourceObservedAtDocument::Absent, SourceRevisionDocument::Absent) => Ok(()),
        // V1 has no reviewed extraction mapping for provenance fields. Keep the
        // closed document variants explicit, but fail closed until a contract
        // version binds them to exact pack response pointers.
        _ => Err(SourcePlanArtifactError::InvalidPlan),
    }
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
    mode: OutputModeDocument,
    output: &BTreeMap<String, OutputFieldDocument>,
    acquired_fields: &BTreeSet<AcquiredField>,
) -> Result<(), SourcePlanArtifactError> {
    if mode.is_projected_fields() == output.is_empty() {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    if output.len() > MAX_ACQUIRED_FIELDS || acquired_fields.len() > MAX_ACQUIRED_FIELDS {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    for name in output.keys() {
        AcquiredField::try_from(name.as_str())
            .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
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
    cardinality: SourceCardinality,
) -> Result<(), SourcePlanArtifactError> {
    behavior.outcomes.sort();
    if behavior.outcomes.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    let expected = match cardinality {
        SourceCardinality::Singleton => vec![OutcomeDocument::Match, OutcomeDocument::NoMatch],
        SourceCardinality::AmbiguityProbe => vec![
            OutcomeDocument::Match,
            OutcomeDocument::NoMatch,
            OutcomeDocument::Ambiguous,
        ],
    };
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
    if plan.kind == SourcePlanKind::SnapshotExact {
        return validate_snapshot_plan(plan, spec.acquisition.class, spec.bounds);
    }
    if plan.operations.is_empty() || plan.operations.len() > 5 || plan.steps.is_empty() {
        return Err(SourcePlanArtifactError::InvalidPlan);
    }

    let mut operation_ids = BTreeSet::new();
    let mut operation_fields = BTreeSet::new();
    let mut operation_control_fields = BTreeSet::new();
    let mut mapped_output_fields = BTreeSet::new();
    let mut operation_response_fields = BTreeMap::new();
    let mut auth_modes = BTreeSet::new();
    let mut response_bytes = 0_u64;
    let mut maximum_data_response_bytes = 0_u64;
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
    let operation_validation = HttpOperationValidationContext {
        inputs: &spec.input_slots,
        parameters: &spec.deployment_parameters,
        reviewed_fields: &reviewed_acquisition.fields,
        reviewed_control_fields: &reviewed_acquisition.control_fields,
        acquisition_class: spec.acquisition.class,
        cardinality: profile_cardinality,
        evidence: &spec.evidence,
        bounds: spec.bounds,
        oauth_authorization_max_bytes,
        output_mode: spec.output_mode,
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
        let record_schema = response_record_schema(
            &operation.response.schema,
            &operation.response.normalization,
            operation.response.max_records,
            operation.response.records_field.as_deref(),
        )?;
        let ResponseSchemaDocument::Object { fields, .. } = record_schema else {
            return Err(SourcePlanArtifactError::InvalidAcquisition);
        };
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
        for field in &operation.acquisition_fields {
            operation_fields.insert(
                AcquiredField::try_from(field.as_str())
                    .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?,
            );
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
        auth_modes.insert(operation.auth);
        let normalization_matches = matches!(
            (profile_cardinality, &operation.response.normalization),
            (
                SourceCardinality::Singleton,
                ResponseNormalizationDocument::Object
            ) | (
                SourceCardinality::AmbiguityProbe,
                ResponseNormalizationDocument::ArrayProbeTwo
                    | ResponseNormalizationDocument::ObjectArrayProbeTwo
            )
        );
        if !normalization_matches {
            return Err(SourcePlanArtifactError::InvalidAcquisition);
        }
        if operation.response.max_records != profile_cardinality.max_source_matches() {
            return Err(SourcePlanArtifactError::InvalidAcquisition);
        }
        response_bytes = response_bytes
            .checked_add(u64::from(operation.response.max_bytes))
            .ok_or(SourcePlanArtifactError::InvalidLimits)?;
        maximum_data_response_bytes =
            maximum_data_response_bytes.max(u64::from(operation.response.max_bytes));
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
    if operation_fields
        != declared_disclosed_fields
            .iter()
            .map(|field| {
                AcquiredField::try_from(field.as_str())
                    .map_err(|_| SourcePlanArtifactError::InvalidIdentity)
            })
            .collect::<Result<BTreeSet<_>, _>>()?
        || operation_control_fields != declared_control_fields
        || operation_response_fields != spec.acquisition.fields
        || mapped_output_fields != declared_disclosed_fields
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
    let embedded_data_exchanges = usize::from(plan.operations.iter().any(|operation| {
        operation.request_codec == Some(RequestCodecDocument::OpenCrvsDciExactV1)
    }));
    if used_operations != known_operations
        || (plan.kind == SourcePlanKind::BoundedHttp
            && plan.steps.len() + embedded_data_exchanges
                != usize::from(spec.bounds.max_data_exchanges))
        || (plan.kind == SourcePlanKind::SandboxedRhai && !plan.step_conditions.is_empty())
    {
        return Err(SourcePlanArtifactError::InvalidPlan);
    }

    let credential_auth_modes = auth_modes
        .iter()
        .copied()
        .filter(|mode| *mode != SourceAuthDocument::None)
        .collect::<BTreeSet<_>>();
    if credential_auth_modes.len() > 1 {
        return Err(SourcePlanArtifactError::InvalidPlan);
    }
    let credential_auth = credential_auth_modes.iter().next().copied();
    validate_credential_operation(plan, spec.bounds, credential_auth)?;
    if plan.kind == SourcePlanKind::SandboxedRhai {
        response_bytes = maximum_data_response_bytes
            .checked_mul(u64::from(spec.bounds.max_data_exchanges))
            .ok_or(SourcePlanArtifactError::InvalidLimits)?;
    }
    if let Some(credential) = &plan.credential_operation {
        response_bytes = response_bytes
            .checked_add(u64::from(credential.response.max_bytes))
            .ok_or(SourcePlanArtifactError::InvalidLimits)?;
    }
    if plan
        .operations
        .iter()
        .any(|operation| operation.request_codec == Some(RequestCodecDocument::OpenCrvsDciExactV1))
    {
        response_bytes = response_bytes
            .checked_add(OPEN_CRVS_JWKS_MAX_RESPONSE_BYTES)
            .ok_or(SourcePlanArtifactError::InvalidLimits)?;
    }
    if response_bytes > spec.bounds.max_source_bytes {
        return Err(SourcePlanArtifactError::InvalidLimits);
    }
    validate_template_kind(plan, spec.acquisition.class)?;
    validate_prior_step_references(plan)?;
    validate_step_conditions(plan)?;
    validate_open_crvs_exact_plan(spec)
}

pub(in super::super) const OPEN_CRVS_JWKS_PATH: &str = "/.well-known/jwks.json";
pub(in super::super) const OPEN_CRVS_JWKS_MAX_RESPONSE_BYTES: u64 = 64 * 1024;
pub(in super::super) const OPEN_CRVS_DCI_SEARCH_PATH: &str = "/registry/sync/search";
pub(in super::super) const OPEN_CRVS_OAUTH_TOKEN_PATH: &str = "/oauth2/client/token";
pub(in super::super) const OPEN_CRVS_DCI_REQUEST_BODY_MAX_BYTES: usize = 8 * 1024;

fn validate_open_crvs_exact_plan(
    spec: &IntegrationPackSpecDocument,
) -> Result<(), SourcePlanArtifactError> {
    let exact_operations = spec
        .plan
        .operations
        .iter()
        .filter(|operation| {
            operation.request_codec == Some(RequestCodecDocument::OpenCrvsDciExactV1)
        })
        .collect::<Vec<_>>();
    if exact_operations.is_empty() {
        return Ok(());
    }
    let [operation] = exact_operations.as_slice() else {
        return Err(SourcePlanArtifactError::InvalidPlan);
    };
    let reviewed = spec
        .reviewed_acquisition
        .as_ref()
        .ok_or(SourcePlanArtifactError::InvalidAcquisition)?;
    let credential = spec
        .plan
        .credential_operation
        .as_ref()
        .ok_or(SourcePlanArtifactError::InvalidPlan)?;
    let jwks_operation_id = format!("{}.jwks", operation.id);
    OperationId::try_from(jwks_operation_id.as_str())
        .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
    let record_schema_matches = reviewed.fields.len() == 1
        && reviewed.fields.contains_key("record")
        && reviewed.control_fields.is_empty()
        && spec.acquisition.fields.len() == 1
        && spec.acquisition.fields.get("record") == reviewed.fields.get("record");
    let response_record_matches = response_record_schema(
        &operation.response.schema,
        &operation.response.normalization,
        operation.response.max_records,
        operation.response.records_field.as_deref(),
    )
    .is_ok_and(|schema| {
        matches!(schema, ResponseSchemaDocument::Object { fields, .. }
            if fields.len() == 1 && fields.get("record").is_some_and(|field|
                field.required && Some(field.schema.as_ref()) == reviewed.fields.get("record")))
    });
    let exact = spec.plan.kind == SourcePlanKind::BoundedHttp
        && spec.acquisition.class == AcquisitionClassDocument::BoundedFullRecord
        && spec.output_mode == OutputModeDocument::PresenceOnly
        && spec.output.is_empty()
        && spec.plan.operations.len() == 1
        && spec.plan.steps == [operation.id.as_str()]
        && credential.id != jwks_operation_id
        && spec.plan.step_conditions.is_empty()
        && spec.deployment_parameters.is_empty()
        && spec.bounds.max_source_matches == 2
        && spec.bounds.max_disclosed_records == 1
        && spec.bounds.max_data_exchanges == 2
        && spec.bounds.max_credential_exchanges == 1
        && spec.bounds.max_data_destinations == 1
        && reviewed.class == AcquisitionClassDocument::BoundedFullRecord
        && reviewed.cardinality == ReviewedCardinalityDocument::ProbeTwo
        && record_schema_matches
        && operation.method == ReadMethod::ReadOnlyPost
        && operation.path == OPEN_CRVS_DCI_SEARCH_PATH
        && operation.query.is_empty()
        && operation.headers.is_empty()
        && operation.body.is_none()
        && operation.relation_selector.is_none()
        && operation.request_signer.is_none()
        && operation
            .step_limits
            .is_some_and(|limits| limits.timeout_ms == spec.bounds.timeout_ms)
        && operation.auth == SourceAuthDocument::OAuthClientCredentials
        && operation.acquisition_fields.is_empty()
        && operation.control_fields.is_empty()
        && operation.projection == ProjectionMechanismDocument::BoundedFullRecord
        && operation.response.output_mapping.is_empty()
        && operation.response.prior_outputs.is_empty()
        && operation.response.accepted_statuses == [200]
        && operation.response.max_records == 2
        && matches!(
            operation.response.cardinality,
            CardinalityMechanismDocument::OpenCrvsDciProbeTwo
        )
        && matches!(
            operation.response.normalization,
            ResponseNormalizationDocument::ArrayProbeTwo
        )
        && response_record_matches
        && credential.request.format
            == OAuth2ClientCredentialsRequestFormatDocument::JsonClientSecretBody
        && credential.path == OPEN_CRVS_OAUTH_TOKEN_PATH
        && credential.request.timeout_ms == spec.bounds.timeout_ms
        && credential.request.audience.is_none()
        && credential.request.scopes.is_empty()
        && credential.request.resource.is_none()
        && credential.response.accepted_statuses == [200]
        && credential.response.schema
            == OAuth2TokenResponseSchemaDocument::StrictAccessTokenBearerNoExpiry
        && credential.response.cache_mode == OAuth2TokenCacheModeDocument::Disabled;
    exact
        .then_some(())
        .ok_or(SourcePlanArtifactError::InvalidPlan)
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
    for (name, output) in &spec.output {
        if reviewed
            .fields
            .get(name)
            .is_none_or(|schema| !schema.validates_public_output(output))
        {
            return Err(SourcePlanArtifactError::InvalidAcquisition);
        }
    }

    let input_name = spec
        .input_slots
        .keys()
        .next()
        .ok_or(SourcePlanArtifactError::InvalidAcquisition)?;
    match &reviewed.selector {
        ExactSelectorDocument::HttpAnchor {
            input,
            operation,
            location,
        } if spec.plan.kind != SourcePlanKind::SnapshotExact
            && input == input_name
            && spec.plan.steps.first() == Some(operation)
            && spec.plan.operations.iter().any(|candidate| {
                candidate.id == *operation
                    && candidate.relation_selector.is_none()
                    && selector_location_matches(candidate, location, SelectorSource::Input(input))
            }) =>
        {
            validate_transitively_anchored_steps(&spec.plan)?;
        }
        ExactSelectorDocument::SnapshotKey { input }
            if spec.plan.kind == SourcePlanKind::SnapshotExact && input == input_name => {}
        _ => return Err(SourcePlanArtifactError::InvalidAcquisition),
    }
    Ok(())
}

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
            Some(RequestCodecDocument::DciExactV1 | RequestCodecDocument::OpenCrvsDciExactV1)
        ),
    }
}

pub(super) fn validate_transitively_anchored_steps(
    plan: &PlanTemplateDocument,
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
        .query
        .values()
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
    plan: &PlanTemplateDocument,
    acquisition: AcquisitionClassDocument,
    bounds: LimitsDocument,
) -> Result<(), SourcePlanArtifactError> {
    if !plan.operations.is_empty()
        || !plan.steps.is_empty()
        || !plan.step_conditions.is_empty()
        || plan.data_destination_slot.is_some()
        || plan.credential_operation.is_some()
        || plan.credential_destination_slot.is_some()
        || bounds.max_data_exchanges != 0
        || bounds.max_credential_exchanges != 0
        || bounds.max_data_destinations != 0
    {
        return Err(SourcePlanArtifactError::InvalidPlan);
    }
    validate_template_kind(plan, acquisition)
}

struct HttpOperationValidationContext<'a> {
    inputs: &'a BTreeMap<String, InputDocument>,
    parameters: &'a BTreeMap<String, ParameterDeclarationDocument>,
    reviewed_fields: &'a BTreeMap<String, ResponseSchemaDocument>,
    reviewed_control_fields: &'a BTreeMap<String, ResponseSchemaDocument>,
    acquisition_class: AcquisitionClassDocument,
    cardinality: SourceCardinality,
    evidence: &'a EvidenceManifestDocument,
    bounds: LimitsDocument,
    oauth_authorization_max_bytes: Option<usize>,
    output_mode: OutputModeDocument,
}

fn validate_http_operation(
    operation: &mut HttpOperationDocument,
    context: &HttpOperationValidationContext<'_>,
) -> Result<(), SourcePlanArtifactError> {
    let HttpOperationValidationContext {
        inputs,
        parameters,
        reviewed_fields,
        reviewed_control_fields,
        acquisition_class,
        cardinality,
        evidence,
        bounds,
        oauth_authorization_max_bytes,
        output_mode,
    } = context;
    validate_fixed_path(&operation.path)?;
    if operation.query.len() > MAX_STATIC_COMPONENTS
        || operation.headers.len() + usize::from(operation.auth != SourceAuthDocument::None)
            > MAX_STATIC_COMPONENTS
    {
        return Err(SourcePlanArtifactError::InvalidLimits);
    }
    validate_request_shape(
        operation,
        inputs,
        parameters,
        *bounds,
        *oauth_authorization_max_bytes,
    )?;
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
        if output_mode.is_projected_fields() {
            return Err(SourcePlanArtifactError::InvalidSet);
        }
    } else {
        normalize_stable_set(&mut operation.acquisition_fields)?;
    }
    if operation.control_fields.is_empty() {
        if !operation.response.prior_outputs.is_empty() {
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
    if declared_operation_controls
        != operation
            .response
            .prior_outputs
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
    {
        return Err(SourcePlanArtifactError::InvalidAcquisition);
    }
    validate_projection(operation, *acquisition_class, evidence)?;
    validate_cardinality_mechanism(operation, *cardinality, evidence)?;
    let fields = parse_acquired_fields(&operation.acquisition_fields)?;
    if operation.response.max_bytes == 0 || operation.response.max_bytes > MAX_DATA_RESPONSE_BYTES {
        return Err(SourcePlanArtifactError::InvalidLimits);
    }
    if output_mode.is_projected_fields() == operation.response.output_mapping.is_empty()
        || output_mode.is_projected_fields() == operation.acquisition_fields.is_empty()
    {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    normalize_status_set(&mut operation.response.accepted_statuses)?;
    let mut schema_nodes = 0_usize;
    let expanded_nodes =
        validate_response_schema(&operation.response.schema, 1, &mut schema_nodes)?;
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
    for (name, output) in &operation.response.prior_outputs {
        validate_stable_text(name)?;
        let pointer_tokens = decode_pointer_tokens(&output.pointer)?;
        let raw_schema = resolve_response_pointer(record_schema, &pointer_tokens)?;
        let bounds_valid = match output.output_type {
            OutputTypeDocument::String => {
                output
                    .max_bytes
                    .is_some_and(|value| (1..=MAX_INPUT_BYTES).contains(&value))
                    && output.minimum.is_none()
                    && output.maximum.is_none()
            }
            OutputTypeDocument::Integer => {
                output.max_bytes.is_none()
                    && matches!((output.minimum, output.maximum), (Some(min), Some(max)) if min <= max && min.unsigned_abs() <= MAX_JSON_INTEROPERABLE_INTEGER && max.unsigned_abs() <= MAX_JSON_INTEROPERABLE_INTEGER)
            }
            OutputTypeDocument::Boolean | OutputTypeDocument::Number => {
                output.max_bytes.is_none() && output.minimum.is_none() && output.maximum.is_none()
            }
        };
        if !bounds_valid
            || !prior_output_matches_schema(output, raw_schema)
            || reviewed_control_fields
                .get(name)
                .is_none_or(|schema| !schema.matches_response_schema(raw_schema))
            || !exposed_pointers.insert(pointer_tokens)
        {
            return Err(SourcePlanArtifactError::InvalidLimits);
        }
    }
    for (field, pointer) in &operation.response.output_mapping {
        let field = AcquiredField::try_from(field.as_str())
            .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
        if !fields.contains(&field) {
            return Err(SourcePlanArtifactError::InvalidAcquisition);
        }
        let pointer_tokens = decode_pointer_tokens(pointer)?;
        let raw_schema = resolve_response_pointer(record_schema, &pointer_tokens)?;
        let schema = reviewed_fields
            .get(field.as_str())
            .ok_or(SourcePlanArtifactError::InvalidAcquisition)?;
        if !schema.matches_response_schema(raw_schema) || !exposed_pointers.insert(pointer_tokens) {
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
    *nodes = nodes
        .checked_add(1)
        .ok_or(SourcePlanArtifactError::InvalidLimits)?;
    if depth > MAX_RESPONSE_SCHEMA_DEPTH || *nodes > MAX_RESPONSE_SCHEMA_NODES {
        return Err(SourcePlanArtifactError::InvalidLimits);
    }
    match schema {
        ResponseSchemaDocument::Object {
            reject_unknown_fields,
            fields,
            ..
        } => {
            if !reject_unknown_fields || fields.is_empty() || fields.len() > MAX_STATIC_COMPONENTS {
                return Err(SourcePlanArtifactError::InvalidAcquisition);
            }
            let mut expanded = 1_usize;
            for (name, field) in fields {
                validate_response_field_name(name)?;
                let child = validate_response_schema(&field.schema, depth + 1, nodes)?;
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
            let child = validate_response_schema(items, depth + 1, nodes)?;
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
        ResponseSchemaDocument::Object { .. } | ResponseSchemaDocument::Array { .. } => {
            Err(SourcePlanArtifactError::InvalidAcquisition)
        }
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
        )
        | (
            OutputTypeDocument::Number,
            ResponseSchemaDocument::Number {
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
        request_signer: operation.request_signer,
        auth: operation.auth,
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
        (CardinalityMechanismDocument::OpenCrvsDciProbeTwo, SourceCardinality::AmbiguityProbe)
            if operation.request_codec == Some(RequestCodecDocument::OpenCrvsDciExactV1) =>
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
