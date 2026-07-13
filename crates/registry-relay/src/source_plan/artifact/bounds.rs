//! Request, credential, destination, and execution-bound validation.

use super::*;

pub(in super::super) fn prior_output_expression_bounds(
    operations: &[HttpOperationDocument],
) -> BTreeMap<(String, String), usize> {
    let mut bounds = BTreeMap::new();
    for operation in operations {
        for (name, output) in &operation.response.prior_outputs {
            let scalar_bytes = match output.output_type {
                OutputTypeDocument::String => output
                    .max_bytes
                    .map_or(MAX_INPUT_BYTES as usize, |value| value as usize),
                OutputTypeDocument::Boolean => 5,
                OutputTypeDocument::Integer => output
                    .minimum
                    .into_iter()
                    .chain(output.maximum)
                    .map(|value| value.to_string().len())
                    .max()
                    .unwrap_or(MAX_INPUT_BYTES as usize),
                OutputTypeDocument::Date => 10,
            };
            bounds.insert(
                (operation.id.clone(), name.clone()),
                scalar_bytes.max(usize::from(output.nullable) * 4),
            );
        }
    }
    bounds
}
pub(in super::super) fn validate_request_shape(
    operation: &HttpOperationDocument,
    plan_kind: SourcePlanKind,
    inputs: &BTreeMap<String, InputDocument>,
    parameters: &BTreeMap<String, ParameterDeclarationDocument>,
    bounds: LimitsDocument,
    oauth_authorization_max_bytes: Option<usize>,
    prior_output_bounds: &BTreeMap<(String, String), usize>,
) -> Result<(), SourcePlanArtifactError> {
    let codec = operation
        .request_codec
        .ok_or(SourcePlanArtifactError::InvalidPlan)?;
    let limits = operation
        .step_limits
        .ok_or(SourcePlanArtifactError::InvalidLimits)?;
    let shape_matches = matches!(
        (
            operation.method,
            codec,
            operation.body.is_some(),
            operation.request_signer
        ),
        (ReadMethod::Get, RequestCodecDocument::None, false, None)
            | (
                ReadMethod::ReadOnlyPost,
                RequestCodecDocument::Json,
                true,
                None
            )
            | (
                ReadMethod::ReadOnlyPost,
                RequestCodecDocument::DciExactV1,
                true,
                Some(RequestSignerDocument::DciJwsV1)
            )
            | (
                ReadMethod::ReadOnlyPost,
                RequestCodecDocument::DciExactV1,
                false,
                None
            )
    );
    let auth_bytes = match &operation.auth {
        SourceAuthDocument::OAuthClientCredentials => {
            oauth_authorization_max_bytes.ok_or(SourcePlanArtifactError::InvalidPlan)?
        }
        _ => operation.auth.max_value_bytes(),
    };
    let auth_shape_matches = match &operation.auth {
        SourceAuthDocument::None => true,
        SourceAuthDocument::Basic { .. } => {
            (7..=MAX_REQUEST_HEADER_VALUE_BYTES).contains(&auth_bytes)
        }
        SourceAuthDocument::StaticBearer { .. } | SourceAuthDocument::OAuthClientCredentials => {
            (8..=MAX_REQUEST_HEADER_VALUE_BYTES).contains(&auth_bytes)
        }
        SourceAuthDocument::ApiKeyHeader { .. } | SourceAuthDocument::ApiKeyQuery { .. } => {
            (1..=MAX_REQUEST_HEADER_VALUE_BYTES).contains(&auth_bytes)
        }
    };
    if plan_kind == SourcePlanKind::SandboxedRhai {
        let generic_script_authority = operation.body.is_none()
            && operation.request_signer.is_none()
            && operation.dci.is_none()
            && codec == RequestCodecDocument::None
            && matches!(operation.method, ReadMethod::Get | ReadMethod::ReadOnlyPost);
        let signed_dci_helper = operation.method == ReadMethod::ReadOnlyPost
            && operation.body.is_none()
            && operation.request_signer.is_none()
            && operation.dci.is_some()
            && codec == RequestCodecDocument::DciExactV1;
        let script_shape_matches = operation.path_parameters.is_empty()
            && operation.query.is_empty()
            && operation.headers.is_empty()
            && (generic_script_authority || signed_dci_helper);
        if !script_shape_matches
            || !auth_shape_matches
            || limits.max_request_bytes == 0
            || limits.max_request_bytes > MAX_REQUEST_BYTES
            || limits.timeout_ms == 0
            || limits.timeout_ms > bounds.timeout_ms
            || limits.max_in_flight != 1
            || registry_platform_httputil::destination::validate_script_destination_path_rule(
                &operation.path,
            )
            .is_err()
        {
            return Err(SourcePlanArtifactError::InvalidPlan);
        }
        return Ok(());
    }
    if !shape_matches
        || !auth_shape_matches
        || limits.max_request_bytes == 0
        || limits.max_request_bytes > MAX_REQUEST_BYTES
        || limits.timeout_ms == 0
        || limits.timeout_ms > bounds.timeout_ms
        || limits.max_in_flight != 1
    {
        return Err(SourcePlanArtifactError::InvalidPlan);
    }

    let (fixed_path, path_parameter) = operation_path_parts(operation)?;
    let mut target_bytes = fixed_path.len();
    if let Some((_, expression)) = path_parameter {
        target_bytes = target_bytes
            .checked_add(
                expression_max_bytes(expression, inputs, parameters, prior_output_bounds)
                    .checked_mul(3)
                    .ok_or(SourcePlanArtifactError::InvalidLimits)?,
            )
            .ok_or(SourcePlanArtifactError::InvalidLimits)?;
    }
    if !operation.query.is_empty() {
        target_bytes = target_bytes
            .checked_add(1)
            .ok_or(SourcePlanArtifactError::InvalidLimits)?;
    }
    for (index, (name, expression)) in operation.query.iter().enumerate() {
        target_bytes = target_bytes
            .checked_add(usize::from(index > 0))
            .and_then(|total| {
                name.len()
                    .checked_mul(3)
                    .and_then(|name_bytes| total.checked_add(name_bytes + 1))
            })
            .and_then(|total| {
                expression_max_bytes(expression, inputs, parameters, prior_output_bounds)
                    .checked_mul(3)
                    .and_then(|value| total.checked_add(value))
            })
            .ok_or(SourcePlanArtifactError::InvalidLimits)?;
    }
    if target_bytes > MAX_REQUEST_TARGET_BYTES {
        return Err(SourcePlanArtifactError::InvalidLimits);
    }

    let mut header_bytes = if auth_bytes == 0 {
        0
    } else {
        "authorization".len() + auth_bytes
    };
    for (name, expression) in &operation.headers {
        let value_bytes = expression_max_bytes(expression, inputs, parameters, prior_output_bounds);
        if value_bytes > MAX_REQUEST_HEADER_VALUE_BYTES {
            return Err(SourcePlanArtifactError::InvalidLimits);
        }
        header_bytes = header_bytes
            .checked_add(name.len())
            .and_then(|total| total.checked_add(value_bytes))
            .ok_or(SourcePlanArtifactError::InvalidLimits)?;
    }
    if codec == RequestCodecDocument::DciExactV1 {
        header_bytes = header_bytes
            .checked_add("accept".len() + b"application/json".len())
            .and_then(|total| total.checked_add("content-type".len() + b"application/json".len()))
            .ok_or(SourcePlanArtifactError::InvalidLimits)?;
    }
    if header_bytes > MAX_REQUEST_HEADER_BYTES {
        return Err(SourcePlanArtifactError::InvalidLimits);
    }

    let body_bytes = if codec == RequestCodecDocument::DciExactV1 {
        MAX_DCI_EXACT_REQUEST_BODY_BYTES
    } else {
        operation
            .body
            .as_ref()
            .map(|body| body_template_max_bytes(body, inputs, parameters, prior_output_bounds))
            .transpose()?
            .unwrap_or(0)
    };
    let aggregate = target_bytes
        .checked_add(header_bytes)
        .and_then(|total| total.checked_add(body_bytes))
        .ok_or(SourcePlanArtifactError::InvalidLimits)?;
    if aggregate > limits.max_request_bytes as usize {
        return Err(SourcePlanArtifactError::InvalidLimits);
    }
    Ok(())
}

pub(in super::super) fn expression_max_bytes(
    expression: &ValueExpressionDocument,
    inputs: &BTreeMap<String, InputDocument>,
    parameters: &BTreeMap<String, ParameterDeclarationDocument>,
    prior_output_bounds: &BTreeMap<(String, String), usize>,
) -> usize {
    match expression {
        ValueExpressionDocument::Literal { value } => value.len(),
        ValueExpressionDocument::ConsultationInput { name } => {
            inputs.get(name).map_or(MAX_INPUT_BYTES as usize, |input| {
                input
                    .canonical_max_bytes()
                    .map_or(MAX_INPUT_BYTES as usize, |value| value as usize)
            })
        }
        ValueExpressionDocument::DeploymentParameter { name } => parameters
            .get(name)
            .and_then(|declaration| declaration.allowed_values.iter().map(String::len).max())
            .unwrap_or(MAX_STABLE_TEXT_BYTES),
        ValueExpressionDocument::PriorStepOutput { step, output } => prior_output_bounds
            .get(&(step.clone(), output.clone()))
            .copied()
            .unwrap_or(MAX_INPUT_BYTES as usize),
    }
}

pub(in super::super) fn body_template_max_bytes(
    template: &BodyTemplateDocument,
    inputs: &BTreeMap<String, InputDocument>,
    parameters: &BTreeMap<String, ParameterDeclarationDocument>,
    prior_output_bounds: &BTreeMap<(String, String), usize>,
) -> Result<usize, SourcePlanArtifactError> {
    match template {
        BodyTemplateDocument::Null => Ok(4),
        BodyTemplateDocument::Boolean { value } => Ok(if *value { 4 } else { 5 }),
        BodyTemplateDocument::Integer { value } => Ok(value.to_string().len()),
        BodyTemplateDocument::StringLiteral { value } => json_string_max_bytes(value.len()),
        BodyTemplateDocument::Expression { value } => json_string_max_bytes(expression_max_bytes(
            value,
            inputs,
            parameters,
            prior_output_bounds,
        )),
        BodyTemplateDocument::Array { items } => {
            let mut total = 2_usize;
            for (index, item) in items.iter().enumerate() {
                total = total
                    .checked_add(usize::from(index > 0))
                    .and_then(|value| {
                        body_template_max_bytes(item, inputs, parameters, prior_output_bounds)
                            .ok()
                            .and_then(|bytes| value.checked_add(bytes))
                    })
                    .ok_or(SourcePlanArtifactError::InvalidLimits)?;
            }
            Ok(total)
        }
        BodyTemplateDocument::Object { fields } => {
            let mut total = 2_usize;
            for (index, (name, value)) in fields.iter().enumerate() {
                let name_bytes = json_string_max_bytes(name.len())?
                    .checked_add(1)
                    .ok_or(SourcePlanArtifactError::InvalidLimits)?;
                let value_bytes =
                    body_template_max_bytes(value, inputs, parameters, prior_output_bounds)?;
                total = total
                    .checked_add(usize::from(index > 0))
                    .and_then(|total| total.checked_add(name_bytes))
                    .and_then(|total| total.checked_add(value_bytes))
                    .ok_or(SourcePlanArtifactError::InvalidLimits)?;
            }
            Ok(total)
        }
    }
}

pub(in super::super) fn json_string_max_bytes(
    raw_bytes: usize,
) -> Result<usize, SourcePlanArtifactError> {
    raw_bytes
        // A single JSON string byte can require the six-byte `\u00XX` form.
        .checked_mul(6)
        .and_then(|bytes| bytes.checked_add(2))
        .ok_or(SourcePlanArtifactError::InvalidLimits)
}

pub(in super::super) fn normalize_status_set(
    statuses: &mut [u16],
) -> Result<(), SourcePlanArtifactError> {
    if statuses.is_empty() || statuses.len() > 8 {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    statuses.sort_unstable();
    if statuses.windows(2).any(|pair| pair[0] == pair[1])
        || statuses.iter().any(|status| !(200..=299).contains(status))
    {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    Ok(())
}

pub(in super::super) fn normalize_data_status_set(
    statuses: &mut [u16],
) -> Result<(), SourcePlanArtifactError> {
    if statuses.is_empty() || statuses.len() > 8 {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    statuses.sort_unstable();
    if statuses.windows(2).any(|pair| pair[0] == pair[1])
        || statuses.iter().any(|status| !(100..=599).contains(status))
    {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    Ok(())
}

pub(in super::super) fn validate_body_template(
    template: &BodyTemplateDocument,
    inputs: &BTreeMap<String, InputDocument>,
    parameters: &BTreeMap<String, ParameterDeclarationDocument>,
    depth: usize,
    node_count: &mut usize,
) -> Result<(), SourcePlanArtifactError> {
    *node_count = node_count
        .checked_add(1)
        .ok_or(SourcePlanArtifactError::InvalidLimits)?;
    if depth > MAX_BODY_TEMPLATE_DEPTH || *node_count > MAX_BODY_TEMPLATE_NODES {
        return Err(SourcePlanArtifactError::InvalidLimits);
    }
    match template {
        BodyTemplateDocument::Null | BodyTemplateDocument::Boolean { .. } => Ok(()),
        BodyTemplateDocument::Integer { value }
            if value.unsigned_abs() <= MAX_JSON_INTEROPERABLE_INTEGER =>
        {
            Ok(())
        }
        BodyTemplateDocument::Integer { .. } => Err(SourcePlanArtifactError::InvalidLimits),
        BodyTemplateDocument::StringLiteral { value } => {
            let valid = !value.is_empty()
                && value.len() <= MAX_BODY_LITERAL_BYTES
                && value.chars().all(|character| {
                    !character.is_control() || matches!(character, '\n' | '\r' | '\t')
                });
            valid
                .then_some(())
                .ok_or(SourcePlanArtifactError::InvalidText)
        }
        BodyTemplateDocument::Expression { value } => {
            validate_expression(value, inputs, parameters)
        }
        BodyTemplateDocument::Array { items } => {
            if items.len() > MAX_STATIC_COMPONENTS {
                return Err(SourcePlanArtifactError::InvalidLimits);
            }
            for item in items {
                validate_body_template(item, inputs, parameters, depth + 1, node_count)?;
            }
            Ok(())
        }
        BodyTemplateDocument::Object { fields } => {
            if fields.len() > MAX_STATIC_COMPONENTS {
                return Err(SourcePlanArtifactError::InvalidLimits);
            }
            for (name, value) in fields {
                validate_bounded_text(name, 256)?;
                if is_sensitive_name(name) {
                    return Err(SourcePlanArtifactError::InvalidExpression);
                }
                validate_body_template(value, inputs, parameters, depth + 1, node_count)?;
            }
            Ok(())
        }
    }
}

pub(in super::super) fn validate_expression(
    expression: &ValueExpressionDocument,
    inputs: &BTreeMap<String, InputDocument>,
    parameters: &BTreeMap<String, ParameterDeclarationDocument>,
) -> Result<(), SourcePlanArtifactError> {
    match expression {
        ValueExpressionDocument::Literal { value } => {
            validate_bounded_text(value, MAX_STABLE_TEXT_BYTES)
        }
        ValueExpressionDocument::ConsultationInput { name } => inputs
            .contains_key(name)
            .then_some(())
            .ok_or(SourcePlanArtifactError::InvalidExpression),
        ValueExpressionDocument::DeploymentParameter { name } => parameters
            .contains_key(name)
            .then_some(())
            .ok_or(SourcePlanArtifactError::InvalidExpression),
        ValueExpressionDocument::PriorStepOutput { step, output } => {
            validate_stable_text(step)?;
            validate_stable_text(output)
        }
    }
}

pub(in super::super) fn validate_credential_operation(
    plan: &mut PlanTemplateDocument,
    bounds: LimitsDocument,
    credential_auth: Option<SourceAuthDocument>,
) -> Result<(), SourcePlanArtifactError> {
    let credential_slot = plan.credential_destination_slot.clone();
    match (
        &mut plan.credential_operation,
        &credential_slot,
        credential_auth,
    ) {
        (None, None, None | Some(SourceAuthDocument::None))
            if bounds.max_credential_exchanges == 0 =>
        {
            Ok(())
        }
        (
            None,
            None,
            Some(
                SourceAuthDocument::Basic { .. }
                | SourceAuthDocument::StaticBearer { .. }
                | SourceAuthDocument::ApiKeyHeader { .. }
                | SourceAuthDocument::ApiKeyQuery { .. },
            ),
        ) if bounds.max_credential_exchanges == 0 => Ok(()),
        (Some(operation), Some(slot), Some(SourceAuthDocument::OAuthClientCredentials))
            if bounds.max_credential_exchanges == 1 =>
        {
            OperationId::try_from(operation.id.as_str())
                .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
            if operation.destination_slot != *slot
                || operation.kind != CredentialOperationKindDocument::OAuth2ClientCredentials
                || plan
                    .operations
                    .iter()
                    .any(|data_operation| data_operation.id == operation.id)
                || operation.failure_policy
                    != CredentialFailurePolicyDocument::FailClosedSourceUnavailableNoRetryNoStaleNoDataDispatch
            {
                return Err(SourcePlanArtifactError::InvalidPlan);
            }
            validate_fixed_path(&operation.path)?;
            validate_oauth_request(&mut operation.request, &operation.path, bounds)?;
            validate_oauth_response(&mut operation.response)
        }
        _ => Err(SourcePlanArtifactError::InvalidPlan),
    }
}

pub(in super::super) fn validate_oauth_request(
    request: &mut OAuth2ClientCredentialsRequestDocument,
    path: &str,
    bounds: LimitsDocument,
) -> Result<(), SourcePlanArtifactError> {
    if request.max_client_id_bytes == 0
        || request.max_client_id_bytes > MAX_OAUTH_CLIENT_ID_BYTES
        || request.max_client_secret_bytes == 0
        || request.max_client_secret_bytes > MAX_OAUTH_CLIENT_SECRET_BYTES
        || request.max_body_bytes == 0
        || request.max_body_bytes > MAX_REQUEST_BYTES
        || request.max_request_bytes == 0
        || request.max_request_bytes > MAX_REQUEST_BYTES
        || request.timeout_ms == 0
        || request.timeout_ms > bounds.timeout_ms
    {
        return Err(SourcePlanArtifactError::InvalidLimits);
    }
    for value in request.audience.iter().chain(request.resource.iter()) {
        validate_bounded_text(value, MAX_STABLE_TEXT_BYTES)?;
    }
    if request.scopes.len() > MAX_STATIC_COMPONENTS {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    if !request.scopes.is_empty() {
        normalize_token_set(&mut request.scopes, MAX_PURPOSE_BYTES)?;
    }
    let body_bound = oauth_request_body_max_bytes(request)?;
    let content_type_bytes = match request.format {
        OAuth2ClientCredentialsRequestFormatDocument::JsonClientSecretBody => {
            b"application/json".len()
        }
        OAuth2ClientCredentialsRequestFormatDocument::FormClientSecretBody => {
            b"application/x-www-form-urlencoded".len()
        }
    };
    let header_bytes =
        "accept".len() + b"application/json".len() + "content-type".len() + content_type_bytes;
    let aggregate = path
        .len()
        .checked_add(header_bytes)
        .and_then(|value| value.checked_add(body_bound))
        .ok_or(SourcePlanArtifactError::InvalidLimits)?;
    if body_bound > request.max_body_bytes as usize
        || aggregate > request.max_request_bytes as usize
    {
        return Err(SourcePlanArtifactError::InvalidLimits);
    }
    Ok(())
}

pub(in super::super) fn oauth_request_body_max_bytes(
    request: &OAuth2ClientCredentialsRequestDocument,
) -> Result<usize, SourcePlanArtifactError> {
    let scope_bytes = request
        .scopes
        .iter()
        .map(String::len)
        .sum::<usize>()
        .checked_add(request.scopes.len().saturating_sub(1))
        .ok_or(SourcePlanArtifactError::InvalidLimits)?;
    let fields = [
        ("grant_type", "client_credentials".len()),
        ("client_id", usize::from(request.max_client_id_bytes)),
        (
            "client_secret",
            usize::from(request.max_client_secret_bytes),
        ),
        ("audience", request.audience.as_ref().map_or(0, String::len)),
        ("scope", scope_bytes),
        ("resource", request.resource.as_ref().map_or(0, String::len)),
    ];
    let fields = fields
        .into_iter()
        .filter(|(name, value_bytes)| {
            matches!(*name, "grant_type" | "client_id" | "client_secret") || *value_bytes > 0
        })
        .collect::<Vec<_>>();
    match request.format {
        OAuth2ClientCredentialsRequestFormatDocument::JsonClientSecretBody => {
            let mut total = 2_usize;
            for (index, (name, value_bytes)) in fields.iter().enumerate() {
                total = total
                    .checked_add(usize::from(index > 0))
                    .and_then(|value| value.checked_add(json_string_max_bytes(name.len()).ok()?))
                    .and_then(|value| value.checked_add(1))
                    .and_then(|value| value.checked_add(json_string_max_bytes(*value_bytes).ok()?))
                    .ok_or(SourcePlanArtifactError::InvalidLimits)?;
            }
            Ok(total)
        }
        OAuth2ClientCredentialsRequestFormatDocument::FormClientSecretBody => {
            let mut total = 0_usize;
            for (index, (name, value_bytes)) in fields.iter().enumerate() {
                total = total
                    .checked_add(usize::from(index > 0))
                    .and_then(|value| value.checked_add(name.len().checked_mul(3)?))
                    .and_then(|value| value.checked_add(1))
                    .and_then(|value| value.checked_add(value_bytes.checked_mul(3)?))
                    .ok_or(SourcePlanArtifactError::InvalidLimits)?;
            }
            Ok(total)
        }
    }
}

pub(in super::super) fn validate_oauth_response(
    response: &mut OAuth2ClientCredentialsResponseDocument,
) -> Result<(), SourcePlanArtifactError> {
    normalize_status_set(&mut response.accepted_statuses)?;
    if response.max_bytes == 0
        || response.max_bytes > MAX_DATA_RESPONSE_BYTES
        || response.access_token_max_bytes == 0
        || response.access_token_max_bytes > MAX_OAUTH_ACCESS_TOKEN_BYTES
        || response.token_type != OAuth2TokenTypeDocument::Bearer
    {
        return Err(SourcePlanArtifactError::InvalidLimits);
    }
    match (response.schema, response.cache_mode) {
        (
            OAuth2TokenResponseSchemaDocument::StrictAccessTokenBearerExpiresIn,
            OAuth2TokenCacheModeDocument::ExpiryBound,
        ) => {
            let (Some(min_seconds), Some(max_seconds), Some(max_lifetime_ms), Some(skew_ms)) = (
                response.expires_in_min_seconds,
                response.expires_in_max_seconds,
                response.max_token_lifetime_ms,
                response.expiry_safety_skew_ms,
            ) else {
                return Err(SourcePlanArtifactError::InvalidLimits);
            };
            let max_lifetime_from_response = max_seconds
                .checked_mul(1_000)
                .ok_or(SourcePlanArtifactError::InvalidLimits)?;
            let min_lifetime_from_response = min_seconds
                .checked_mul(1_000)
                .ok_or(SourcePlanArtifactError::InvalidLimits)?;
            if min_seconds == 0
                || min_seconds > max_seconds
                || max_lifetime_ms == 0
                || max_lifetime_ms > MAX_OAUTH_TOKEN_LIFETIME_MS
                || max_lifetime_from_response > max_lifetime_ms
                || skew_ms >= min_lifetime_from_response
            {
                return Err(SourcePlanArtifactError::InvalidLimits);
            }
            Ok(())
        }
        (
            OAuth2TokenResponseSchemaDocument::StrictAccessTokenBearerNoExpiry,
            OAuth2TokenCacheModeDocument::Disabled,
        ) if response.expires_in_min_seconds.is_none()
            && response.expires_in_max_seconds.is_none()
            && response.max_token_lifetime_ms.is_none()
            && response.expiry_safety_skew_ms.is_none() =>
        {
            Ok(())
        }
        _ => Err(SourcePlanArtifactError::InvalidLimits),
    }
}

pub(in super::super) fn validate_template_kind(
    plan: &PlanTemplateDocument,
    acquisition: AcquisitionClassDocument,
) -> Result<(), SourcePlanArtifactError> {
    match (plan.kind, &plan.snapshot, &plan.rhai, acquisition) {
        (
            SourcePlanKind::BoundedHttp,
            None,
            None,
            AcquisitionClassDocument::SourceProjectedExact
            | AcquisitionClassDocument::BoundedFullRecord,
        ) => Ok(()),
        (
            SourcePlanKind::SnapshotExact,
            Some(snapshot),
            None,
            AcquisitionClassDocument::MaterializedSnapshot,
        ) if snapshot.max_snapshot_age_ms > 0
            && snapshot.max_snapshot_age_ms <= MAX_SNAPSHOT_AGE_MS
            && snapshot.immutable_generation =>
        {
            Ok(())
        }
        (
            SourcePlanKind::SandboxedRhai,
            None,
            Some(rhai),
            AcquisitionClassDocument::SourceProjectedExact
            | AcquisitionClassDocument::BoundedFullRecord,
        ) => validate_rhai(rhai),
        _ => Err(SourcePlanArtifactError::InvalidPlan),
    }
}

pub(in super::super) fn validate_rhai(
    rhai: &RhaiTemplateDocument,
) -> Result<(), SourcePlanArtifactError> {
    IntegrationPackHash::try_from(rhai.script_hash.as_str())
        .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
    if rhai.script.is_empty()
        || rhai.script.len() > MAX_RHAI_SCRIPT_BYTES
        || rhai.script.contains('\0')
        || sha256_label(rhai.script.as_bytes()) != rhai.script_hash
    {
        return Err(SourcePlanArtifactError::HashMismatch);
    }
    validate_stable_text(&rhai.entrypoint)?;
    let valid = (1..=MAX_RHAI_MEMORY_BYTES).contains(&rhai.memory_bytes)
        && (1..=MAX_RHAI_CPU_MS).contains(&rhai.cpu_ms)
        && (1..=MAX_RHAI_IPC_FRAME_BYTES).contains(&rhai.ipc_frame_bytes)
        && (1..=MAX_RHAI_INSTRUCTIONS).contains(&rhai.instructions)
        && rhai
            .call_depth
            .is_some_and(|value| (1..=MAX_RHAI_CALL_DEPTH).contains(&value))
        && rhai
            .string_bytes
            .is_some_and(|value| (1..=MAX_RHAI_STRING_BYTES).contains(&value))
        && rhai
            .array_items
            .is_some_and(|value| (1..=MAX_RHAI_COLLECTION_ITEMS).contains(&value))
        && rhai
            .map_entries
            .is_some_and(|value| (1..=MAX_RHAI_COLLECTION_ITEMS).contains(&value))
        && rhai
            .output_bytes
            .is_some_and(|value| (1..=MAX_RHAI_OUTPUT_BYTES).contains(&value))
        && rhai.concurrency.is_some_and(|value| value == 1);
    valid
        .then_some(())
        .ok_or(SourcePlanArtifactError::InvalidLimits)
}

pub(in super::super) fn validate_prior_step_references(
    plan: &PlanTemplateDocument,
) -> Result<(), SourcePlanArtifactError> {
    let mut completed = BTreeMap::new();
    for step in &plan.steps {
        let operation = plan
            .operations
            .iter()
            .find(|operation| operation.id == *step)
            .ok_or(SourcePlanArtifactError::InvalidPlan)?;
        for expression in operation
            .path_parameters
            .values()
            .chain(operation.query.values())
            .chain(operation.headers.values())
        {
            validate_prior_expression(expression, &completed, true)?;
        }
        if let Some(body) = &operation.body {
            validate_body_prior_step_references(body, &completed)?;
        }
        completed.insert(step.as_str(), operation);
    }
    Ok(())
}

pub(in super::super) type OperationPathParts<'a> =
    (&'a str, Option<(&'a str, &'a ValueExpressionDocument)>);

pub(in super::super) fn operation_path_parts(
    operation: &HttpOperationDocument,
) -> Result<OperationPathParts<'_>, SourcePlanArtifactError> {
    match operation.path_parameters.len() {
        0 => {
            validate_fixed_path(&operation.path)?;
            Ok((&operation.path, None))
        }
        1 => {
            let (name, expression) = operation
                .path_parameters
                .iter()
                .next()
                .ok_or(SourcePlanArtifactError::InvalidPlan)?;
            validate_stable_text(name)?;
            let suffix = format!("{{{name}}}");
            let fixed = operation
                .path
                .strip_suffix(&suffix)
                .ok_or(SourcePlanArtifactError::InvalidPlan)?;
            if fixed.is_empty() || !fixed.ends_with('/') {
                return Err(SourcePlanArtifactError::InvalidPlan);
            }
            validate_fixed_path(fixed)?;
            Ok((fixed, Some((name, expression))))
        }
        _ => Err(SourcePlanArtifactError::InvalidPlan),
    }
}

pub(in super::super) fn validate_step_conditions(
    plan: &PlanTemplateDocument,
) -> Result<(), SourcePlanArtifactError> {
    if plan.step_conditions.len() > plan.steps.len() {
        return Err(SourcePlanArtifactError::InvalidPlan);
    }
    let mut completed = BTreeMap::new();
    for (index, step) in plan.steps.iter().enumerate() {
        let operation = plan
            .operations
            .iter()
            .find(|operation| operation.id == *step)
            .ok_or(SourcePlanArtifactError::InvalidPlan)?;
        if let Some(condition) = plan.step_conditions.get(step) {
            if index == 0 {
                return Err(SourcePlanArtifactError::InvalidPlan);
            }
            validate_step_condition(condition, &completed)?;
        }
        completed.insert(step.as_str(), operation);
    }
    if plan
        .step_conditions
        .keys()
        .any(|step| !plan.steps.iter().any(|known| known == step))
    {
        return Err(SourcePlanArtifactError::InvalidPlan);
    }
    Ok(())
}

pub(in super::super) fn validate_step_condition(
    condition: &StepConditionDocument,
    completed: &BTreeMap<&str, &HttpOperationDocument>,
) -> Result<(), SourcePlanArtifactError> {
    let (step, output) = match condition {
        StepConditionDocument::Exists { step, output }
        | StepConditionDocument::StringEquals { step, output, .. }
        | StepConditionDocument::BooleanEquals { step, output, .. }
        | StepConditionDocument::IntegerEquals { step, output, .. } => (step, output),
    };
    validate_stable_text(step)?;
    validate_stable_text(output)?;
    let source = completed
        .get(step.as_str())
        .ok_or(SourcePlanArtifactError::InvalidExpression)?;
    let presence = output == "presence";
    if presence {
        return matches!(
            condition,
            StepConditionDocument::Exists { .. } | StepConditionDocument::BooleanEquals { .. }
        )
        .then_some(())
        .ok_or(SourcePlanArtifactError::InvalidExpression);
    }
    let declaration = source
        .response
        .prior_outputs
        .get(output)
        .ok_or(SourcePlanArtifactError::InvalidExpression)?;
    let type_matches = match condition {
        StepConditionDocument::Exists { .. } => true,
        StepConditionDocument::StringEquals { value, .. } => {
            declaration.output_type == OutputTypeDocument::String
                && declaration
                    .max_bytes
                    .is_some_and(|maximum| !value.is_empty() && value.len() <= usize::from(maximum))
                && validate_bounded_text(value, MAX_INPUT_BYTES as usize).is_ok()
        }
        StepConditionDocument::BooleanEquals { .. } => {
            declaration.output_type == OutputTypeDocument::Boolean
        }
        StepConditionDocument::IntegerEquals { value, .. } => {
            declaration.output_type == OutputTypeDocument::Integer
                && declaration.minimum.is_some_and(|minimum| *value >= minimum)
                && declaration.maximum.is_some_and(|maximum| *value <= maximum)
        }
    };
    type_matches
        .then_some(())
        .ok_or(SourcePlanArtifactError::InvalidExpression)
}

pub(in super::super) fn validate_body_prior_step_references(
    template: &BodyTemplateDocument,
    completed: &BTreeMap<&str, &HttpOperationDocument>,
) -> Result<(), SourcePlanArtifactError> {
    match template {
        BodyTemplateDocument::Expression { value } => {
            validate_prior_expression(value, completed, false)
        }
        BodyTemplateDocument::Array { items } => {
            for item in items {
                validate_body_prior_step_references(item, completed)?;
            }
            Ok(())
        }
        BodyTemplateDocument::Object { fields } => {
            for value in fields.values() {
                validate_body_prior_step_references(value, completed)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub(in super::super) fn validate_prior_expression(
    expression: &ValueExpressionDocument,
    completed: &BTreeMap<&str, &HttpOperationDocument>,
    requires_string: bool,
) -> Result<(), SourcePlanArtifactError> {
    let ValueExpressionDocument::PriorStepOutput { step, output } = expression else {
        return Ok(());
    };
    let source = completed
        .get(step.as_str())
        .ok_or(SourcePlanArtifactError::InvalidExpression)?;
    let declared = source
        .response
        .prior_outputs
        .get(output)
        .ok_or(SourcePlanArtifactError::InvalidExpression)?;
    if requires_string
        && !matches!(
            declared.output_type,
            OutputTypeDocument::String | OutputTypeDocument::Date
        )
    {
        return Err(SourcePlanArtifactError::InvalidExpression);
    }
    Ok(())
}

pub(in super::super) fn validate_destination_document(
    destination: &mut DestinationDocument,
) -> Result<(), SourcePlanArtifactError> {
    validate_stable_text(&destination.id)?;
    validate_bounded_text(&destination.origin, 2_048)?;
    let origin =
        Url::parse(&destination.origin).map_err(|_| SourcePlanArtifactError::InvalidDestination)?;
    if origin.scheme() != "https"
        || origin.host().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.port_or_known_default().is_none()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return Err(SourcePlanArtifactError::InvalidDestination);
    }
    destination.origin = origin.to_string();
    validate_application_base_path(&destination.application_base_path)?;
    for cidr in &mut destination.allowed_private_cidrs {
        validate_bounded_text(cidr, 64)?;
        *cidr = canonicalize_cidr(cidr)?;
    }
    destination.allowed_private_cidrs.sort();
    if destination
        .allowed_private_cidrs
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    if destination.allowed_private_cidrs.len() > 16 {
        return Err(SourcePlanArtifactError::InvalidDestination);
    }
    if let Some(ca) = &destination.ca {
        validate_private_transport_file(&ca.file)?;
        if ca.generation == 0 {
            return Err(SourcePlanArtifactError::InvalidDestination);
        }
    }
    if let Some(mtls) = &destination.mtls {
        validate_private_transport_file(&mtls.certificate_file)?;
        validate_private_transport_secret_name(&mtls.private_key.secret)?;
        if mtls.generation == 0 {
            return Err(SourcePlanArtifactError::InvalidDestination);
        }
    }
    Ok(())
}

fn validate_private_transport_file(path: &std::path::Path) -> Result<(), SourcePlanArtifactError> {
    let value = path
        .to_str()
        .ok_or(SourcePlanArtifactError::InvalidDestination)?;
    if !path.is_absolute()
        || value.is_empty()
        || value.len() > 4_096
        || value.chars().any(char::is_control)
    {
        return Err(SourcePlanArtifactError::InvalidDestination);
    }
    Ok(())
}

fn validate_private_transport_secret_name(name: &str) -> Result<(), SourcePlanArtifactError> {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return Err(SourcePlanArtifactError::InvalidDestination);
    };
    if name.len() > 128
        || !matches!(first, b'A'..=b'Z' | b'a'..=b'z' | b'_')
        || !bytes.all(|byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_'))
    {
        return Err(SourcePlanArtifactError::InvalidDestination);
    }
    Ok(())
}

fn validate_application_base_path(path: &str) -> Result<(), SourcePlanArtifactError> {
    let canonical = path == "/"
        || (path.starts_with('/')
            && !path.ends_with('/')
            && path.len() <= MAX_PATH_BYTES
            && path.is_ascii()
            && !path.contains(['?', '#', '%', '\\'])
            && !path.chars().any(char::is_control)
            && validate_fixed_destination_path(path).is_ok());
    canonical
        .then_some(())
        .ok_or(SourcePlanArtifactError::InvalidDestination)
}

pub(in super::super) fn canonicalize_cidr(raw: &str) -> Result<String, SourcePlanArtifactError> {
    let (address, prefix) = raw
        .split_once('/')
        .ok_or(SourcePlanArtifactError::InvalidDestination)?;
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| SourcePlanArtifactError::InvalidDestination)?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| SourcePlanArtifactError::InvalidDestination)?;
    let network = match address {
        IpAddr::V4(address) if prefix <= 32 => {
            let value = u32::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            let network = Ipv4Addr::from(value & mask);
            if network != address {
                return Err(SourcePlanArtifactError::InvalidDestination);
            }
            IpAddr::V4(network)
        }
        IpAddr::V6(address) if prefix <= 128 => {
            let value = u128::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            let network = Ipv6Addr::from(value & mask);
            if network != address {
                return Err(SourcePlanArtifactError::InvalidDestination);
            }
            IpAddr::V6(network)
        }
        _ => return Err(SourcePlanArtifactError::InvalidDestination),
    };
    Ok(format!("{network}/{prefix}"))
}

pub(in super::super) fn normalize_stable_set(
    values: &mut [String],
) -> Result<(), SourcePlanArtifactError> {
    if values.is_empty() {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    for value in values.iter() {
        AcquiredField::try_from(value.as_str())
            .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
    }
    values.sort();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    Ok(())
}

pub(in super::super) fn normalize_bounded_set(
    values: &mut [String],
    max_bytes: usize,
) -> Result<(), SourcePlanArtifactError> {
    if values.is_empty() {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    for value in values.iter() {
        validate_bounded_text(value, max_bytes)?;
    }
    values.sort();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    Ok(())
}

pub(in super::super) fn normalize_token_set(
    values: &mut [String],
    max_bytes: usize,
) -> Result<(), SourcePlanArtifactError> {
    if values.is_empty() {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    for value in values.iter() {
        validate_token(value, max_bytes)?;
    }
    values.sort();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    Ok(())
}

pub(in super::super) fn normalize_hash_set(
    values: &mut [String],
) -> Result<(), SourcePlanArtifactError> {
    if values.is_empty() {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    for value in values.iter() {
        IntegrationPackHash::try_from(value.as_str())
            .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
    }
    values.sort();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    Ok(())
}

pub(in super::super) fn parse_acquired_fields(
    values: &[String],
) -> Result<BTreeSet<AcquiredField>, SourcePlanArtifactError> {
    values
        .iter()
        .map(|value| {
            AcquiredField::try_from(value.as_str())
                .map_err(|_| SourcePlanArtifactError::InvalidIdentity)
        })
        .collect()
}

pub(in super::super) fn validate_fixed_path(path: &str) -> Result<(), SourcePlanArtifactError> {
    let valid = path.starts_with('/')
        && !path.starts_with("//")
        && path.len() <= MAX_PATH_BYTES
        && path.is_ascii()
        && !path.contains(['?', '#', '{', '}', '\\'])
        && !path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
        && !path.chars().any(char::is_control)
        && validate_fixed_destination_path(path).is_ok();
    valid
        .then_some(())
        .ok_or(SourcePlanArtifactError::InvalidText)
}

pub(in super::super) fn validate_header_name(name: &str) -> Result<(), SourcePlanArtifactError> {
    let mut bytes = name.bytes();
    let syntactically_valid = matches!(bytes.next(), Some(b'a'..=b'z'))
        && name.len() <= 64
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'));
    let denied = matches!(
        name,
        "authorization"
            | "accept-encoding"
            | "connection"
            | "content-length"
            | "cookie"
            | "forwarded"
            | "host"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "x-api-key"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-proto"
            | "x-real-ip"
    );
    (syntactically_valid && !denied && !name.starts_with("x-forwarded-"))
        .then_some(())
        .ok_or(SourcePlanArtifactError::InvalidExpression)
}

pub(in super::super) fn validate_pointer(pointer: &str) -> Result<(), SourcePlanArtifactError> {
    let bytes = pointer.as_bytes();
    let mut index = 0;
    let mut escapes_valid = true;
    while index < bytes.len() {
        if bytes[index] == b'~' {
            index += 1;
            if index == bytes.len() || !matches!(bytes[index], b'0' | b'1') {
                escapes_valid = false;
                break;
            }
        }
        index += 1;
    }
    let valid = pointer.starts_with('/')
        && pointer.len() <= MAX_POINTER_BYTES
        && !pointer.chars().any(char::is_control)
        && escapes_valid;
    valid
        .then_some(())
        .ok_or(SourcePlanArtifactError::InvalidText)
}
