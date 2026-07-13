//! Data-operation descriptor and closed parser compilation.

use super::*;
use registry_platform_httputil::destination::json::{
    ClosedJsonDecoder, ClosedJsonField, ClosedJsonRecordRoot, ClosedJsonScalarProjection,
    ClosedJsonSchema, MAX_CLOSED_JSON_ENCODED_BODY_BYTES,
};

pub(super) struct OperationCompilationIndexes<'maps, 'artifacts> {
    pub(super) inputs: &'maps BTreeMap<&'artifacts str, usize>,
    pub(super) parameters: &'maps BTreeMap<&'artifacts str, usize>,
    pub(super) operations: &'maps BTreeMap<&'artifacts str, usize>,
    pub(super) prior_slots: &'maps BTreeMap<&'artifacts str, BTreeMap<&'artifacts str, usize>>,
}

fn compile_selector_binding(
    pack: &IntegrationPackArtifact,
    operation: &HttpOperationDocument,
    indexes: &OperationCompilationIndexes<'_, '_>,
) -> Result<CompiledSelectorBinding, SourcePlanCompileError> {
    let reviewed = pack
        .document
        .spec
        .reviewed_acquisition
        .as_ref()
        .ok_or(SourcePlanCompileError::CompilerInvariant)?;
    if reviewed.selector.is_none() && pack.document.spec.plan.kind == SourcePlanKind::SandboxedRhai
    {
        let input_index = indexes
            .inputs
            .values()
            .copied()
            .next()
            .ok_or(SourcePlanCompileError::CompilerInvariant)?;
        return Ok(CompiledSelectorBinding {
            source: CompiledSelectorSource::ConsultationInput { input_index },
            location: CompiledSelectorLocation::ScriptContext,
        });
    }
    let (source, location) = match reviewed
        .selector
        .as_ref()
        .ok_or(SourcePlanCompileError::CompilerInvariant)?
    {
        ExactSelectorDocument::HttpExactAnd {
            operation: root_operation,
            components,
        } if root_operation == &operation.id => {
            let (input, location) = components
                .iter()
                .next()
                .ok_or(SourcePlanCompileError::CompilerInvariant)?;
            let input_index = indexes
                .inputs
                .get(input.as_str())
                .copied()
                .ok_or(SourcePlanCompileError::CompilerInvariant)?;
            (
                CompiledSelectorSource::ConsultationInput { input_index },
                location,
            )
        }
        ExactSelectorDocument::HttpExactAnd { components, .. }
            if operation.input_selector.is_some() =>
        {
            let input = components
                .keys()
                .next()
                .ok_or(SourcePlanCompileError::CompilerInvariant)?;
            let input_index = indexes
                .inputs
                .get(input.as_str())
                .copied()
                .ok_or(SourcePlanCompileError::CompilerInvariant)?;
            (
                CompiledSelectorSource::ConsultationInput { input_index },
                operation
                    .input_selector
                    .as_ref()
                    .ok_or(SourcePlanCompileError::CompilerInvariant)?,
            )
        }
        ExactSelectorDocument::HttpExactAnd { .. } => {
            let relation = operation
                .relation_selector
                .as_ref()
                .ok_or(SourcePlanCompileError::CompilerInvariant)?;
            let operation_index = indexes
                .operations
                .get(relation.step.as_str())
                .copied()
                .ok_or(SourcePlanCompileError::CompilerInvariant)?;
            let output_slot_index = indexes
                .prior_slots
                .get(relation.step.as_str())
                .and_then(|slots| slots.get(relation.output.as_str()))
                .copied()
                .ok_or(SourcePlanCompileError::CompilerInvariant)?;
            (
                CompiledSelectorSource::PriorStepOutput {
                    operation_index,
                    output_slot_index,
                },
                &relation.location,
            )
        }
        ExactSelectorDocument::SnapshotExactAnd { .. } => {
            return Err(SourcePlanCompileError::CompilerInvariant);
        }
    };
    let location = match location {
        RequestSelectorLocationDocument::Query { parameter } => {
            let component_index = operation
                .query
                .keys()
                .position(|name| name == parameter)
                .ok_or(SourcePlanCompileError::CompilerInvariant)?;
            CompiledSelectorLocation::Query { component_index }
        }
        RequestSelectorLocationDocument::Path { parameter } => {
            if !operation.path_parameters.contains_key(parameter) {
                return Err(SourcePlanCompileError::CompilerInvariant);
            }
            CompiledSelectorLocation::PathSegment
        }
        RequestSelectorLocationDocument::Body { pointer } => CompiledSelectorLocation::Body {
            pointer: compile_json_pointer(pointer)?,
        },
        RequestSelectorLocationDocument::Codec {
            role: CodecSelectorRoleDocument::DciIdtypeValue,
        } => CompiledSelectorLocation::DciIdtypeValue,
        RequestSelectorLocationDocument::Codec {
            role: CodecSelectorRoleDocument::DciExactPredicate,
        } => CompiledSelectorLocation::DciExactPredicate,
    };
    Ok(CompiledSelectorBinding { source, location })
}

pub(super) fn compile_operation_descriptors(
    pack: &IntegrationPackArtifact,
    acquisition_class: AcquisitionClass,
    _cardinality: SourceCardinality,
    total_deadline_ms: u32,
    application_base_path: &str,
    verification_application_base_path: &str,
    indexes: &OperationCompilationIndexes<'_, '_>,
) -> Result<Vec<CompiledOperation>, SourcePlanCompileError> {
    let input_indexes = indexes.inputs;
    let parameter_indexes = indexes.parameters;
    let operation_indexes = indexes.operations;
    let prior_slot_indexes = indexes.prior_slots;
    let prior_output_bounds = prior_output_expression_bounds(&pack.document.spec.plan.operations);
    pack.document
        .spec
        .plan
        .operations
        .iter()
        .map(|operation| {
            let id = OperationId::try_from(operation.id.as_str())
                .map_err(|_| SourcePlanCompileError::CompilerInvariant)?;
            let selector = compile_selector_binding(pack, operation, indexes)?;
            let disclosed_fields = operation
                .response
                .output_mapping
                .keys()
                .map(|field| {
                    AcquiredField::try_from(field.as_str())
                        .map_err(|_| SourcePlanCompileError::CompilerInvariant)
                })
                .collect::<Result<BTreeSet<_>, _>>()?;
            let acquired_fields = match response_record_schema(
                &operation.response.schema,
                &operation.response.normalization,
                operation.response.max_records,
                operation.response.records_field.as_deref(),
            )
            .map_err(|_| SourcePlanCompileError::CompilerInvariant)?
            {
                ResponseSchemaDocument::ScriptBody
                    if pack.document.spec.plan.kind == SourcePlanKind::SandboxedRhai =>
                {
                    BTreeSet::new()
                }
                ResponseSchemaDocument::Object { fields, .. } => fields
                    .keys()
                    .map(|field| {
                        AcquiredField::try_from(field.as_str())
                            .map_err(|_| SourcePlanCompileError::CompilerInvariant)
                    })
                    .collect::<Result<BTreeSet<_>, _>>()?,
                _ => return Err(SourcePlanCompileError::CompilerInvariant),
            };
            let query = compile_named_expressions(
                &operation.query,
                input_indexes,
                parameter_indexes,
                operation_indexes,
                prior_slot_indexes,
            )?;
            let headers = compile_named_expressions(
                &operation.headers,
                input_indexes,
                parameter_indexes,
                operation_indexes,
                prior_slot_indexes,
            )?;
            let body = operation
                .body
                .as_ref()
                .map(|body| {
                    compile_body_template(
                        body,
                        input_indexes,
                        parameter_indexes,
                        operation_indexes,
                        prior_slot_indexes,
                    )
                })
                .transpose()?;
            let request_codec = match operation
                .request_codec
                .ok_or(SourcePlanCompileError::CompilerInvariant)?
            {
                RequestCodecDocument::None => CompiledRequestCodec::None,
                RequestCodecDocument::Json => CompiledRequestCodec::Json,
                RequestCodecDocument::DciExactV1 => CompiledRequestCodec::DciExactV1,
            };
            let request_signer = operation.request_signer.map(|signer| match signer {
                RequestSignerDocument::DciJwsV1 => CompiledRequestSigner::DciJwsV1,
            });
            let step_limits = operation
                .step_limits
                .ok_or(SourcePlanCompileError::CompilerInvariant)?;
            let mut query_bounds = operation
                .query
                .iter()
                .map(|(name, expression)| {
                    (
                        name.as_str(),
                        expression_max_bytes(
                            expression,
                            &pack.document.spec.input_slots,
                            &pack.document.spec.deployment_parameters,
                            &prior_output_bounds,
                        ),
                    )
                })
                .collect::<Vec<_>>();
            let mut header_bounds = operation
                .headers
                .iter()
                .map(|(name, expression)| {
                    (
                        name.as_str(),
                        expression_max_bytes(
                            expression,
                            &pack.document.spec.input_slots,
                            &pack.document.spec.deployment_parameters,
                            &prior_output_bounds,
                        ),
                    )
                })
                .collect::<Vec<_>>();
            let max_body_bytes = if request_codec == CompiledRequestCodec::DciExactV1 {
                MAX_DCI_EXACT_REQUEST_BODY_BYTES
            } else {
                operation
                    .body
                    .as_ref()
                    .map(|body| {
                        body_template_max_bytes(
                            body,
                            &pack.document.spec.input_slots,
                            &pack.document.spec.deployment_parameters,
                            &prior_output_bounds,
                        )
                    })
                    .transpose()
                    .map_err(|_| SourcePlanCompileError::CompilerInvariant)?
                    .unwrap_or(0)
            };
            let destination_method = match operation.method {
                ReadMethod::Get => DestinationMethod::Get,
                ReadMethod::ReadOnlyPost => DestinationMethod::ReviewedReadOnlyPost,
            };
            let (auth, api_key, authorization_template) = match &operation.auth {
                SourceAuthDocument::None => (
                    CompiledSourceAuth::None,
                    None,
                    DestinationAuthorizationTemplate::Forbidden,
                ),
                SourceAuthDocument::Basic { max_value_bytes } => (
                    CompiledSourceAuth::Basic,
                    None,
                    DestinationAuthorizationTemplate::Basic {
                        max_value_bytes: usize::from(*max_value_bytes),
                    },
                ),
                SourceAuthDocument::StaticBearer { max_value_bytes } => (
                    CompiledSourceAuth::StaticBearer,
                    None,
                    DestinationAuthorizationTemplate::Bearer {
                        max_value_bytes: usize::from(*max_value_bytes),
                    },
                ),
                SourceAuthDocument::ApiKeyHeader {
                    name,
                    max_value_bytes,
                } => {
                    header_bounds.push((name.as_str(), usize::from(*max_value_bytes)));
                    (
                        CompiledSourceAuth::ApiKeyHeader,
                        Some(super::CompiledApiKeyPlacement::Header {
                            name: name.as_str().into(),
                            max_value_bytes: *max_value_bytes,
                        }),
                        DestinationAuthorizationTemplate::Forbidden,
                    )
                }
                SourceAuthDocument::ApiKeyQuery {
                    name,
                    max_value_bytes,
                } => {
                    query_bounds.push((name.as_str(), usize::from(*max_value_bytes)));
                    (
                        CompiledSourceAuth::ApiKeyQuery,
                        Some(super::CompiledApiKeyPlacement::Query {
                            name: name.as_str().into(),
                            max_value_bytes: *max_value_bytes,
                        }),
                        DestinationAuthorizationTemplate::Forbidden,
                    )
                }
                SourceAuthDocument::OAuthClientCredentials => {
                    let max_value_bytes = pack
                        .document
                        .spec
                        .plan
                        .credential_operation
                        .as_ref()
                        .and_then(|credential| {
                            usize::from(credential.response.access_token_max_bytes)
                                .checked_add(b"Bearer ".len())
                        })
                        .ok_or(SourcePlanCompileError::CompilerInvariant)?;
                    (
                        CompiledSourceAuth::OAuthClientCredentials,
                        None,
                        DestinationAuthorizationTemplate::Bearer { max_value_bytes },
                    )
                }
            };
            let script_operation = pack.document.spec.plan.kind == SourcePlanKind::SandboxedRhai;
            let (operation_fixed_path, path_parameter) = if script_operation {
                (operation.path.as_str(), None)
            } else {
                operation_path_parts(operation)
                    .map_err(|_| SourcePlanCompileError::CompilerInvariant)?
            };
            let fixed_path = destination_fixed_path(application_base_path, operation_fixed_path);
            let path_segment = path_parameter
                .map(|(_, expression)| {
                    compile_value_expression(
                        expression,
                        input_indexes,
                        parameter_indexes,
                        operation_indexes,
                        prior_slot_indexes,
                    )
                })
                .transpose()?;
            let body_template =
                if operation.body.is_some() || request_codec == CompiledRequestCodec::DciExactV1 {
                    DestinationBodyTemplate::Required {
                        max_bytes: max_body_bytes,
                    }
                } else {
                    DestinationBodyTemplate::Forbidden
                };
            let transport_template = if request_codec == CompiledRequestCodec::DciExactV1 {
                DataDestinationRequestTemplate::new_with_exact_headers(
                    destination_method,
                    &fixed_path,
                    &query_bounds,
                    &[
                        ("accept", b"application/json"),
                        ("content-type", b"application/json"),
                    ],
                    authorization_template,
                    body_template,
                    step_limits.max_request_bytes as usize,
                )
            } else if script_operation {
                let (api_key_header, api_key_query) = match &api_key {
                    Some(super::CompiledApiKeyPlacement::Header {
                        name,
                        max_value_bytes,
                    }) => (Some((name.as_ref(), usize::from(*max_value_bytes))), None),
                    Some(super::CompiledApiKeyPlacement::Query {
                        name,
                        max_value_bytes,
                    }) => (None, Some((name.as_ref(), usize::from(*max_value_bytes)))),
                    None => (None, None),
                };
                DataDestinationRequestTemplate::new_script(
                    destination_method,
                    &fixed_path,
                    &operation
                        .script_request_headers
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                    authorization_template,
                    api_key_header,
                    api_key_query,
                    step_limits.max_request_bytes as usize,
                )
            } else if let Some((_, expression)) = path_parameter {
                DataDestinationRequestTemplate::new_with_path_segment(
                    destination_method,
                    &fixed_path,
                    expression_max_bytes(
                        expression,
                        &pack.document.spec.input_slots,
                        &pack.document.spec.deployment_parameters,
                        &prior_output_bounds,
                    ),
                    &query_bounds,
                    &header_bounds,
                    authorization_template,
                    body_template,
                    step_limits.max_request_bytes as usize,
                )
            } else {
                DataDestinationRequestTemplate::new(
                    destination_method,
                    &fixed_path,
                    &query_bounds,
                    &header_bounds,
                    authorization_template,
                    body_template,
                    step_limits.max_request_bytes as usize,
                )
            }
            .map_err(|_| {
                if application_base_path == "/" {
                    SourcePlanCompileError::CompilerInvariant
                } else {
                    SourcePlanCompileError::BindingWidening
                }
            })?;
            let projection = compile_projection(operation)?;
            let response = compile_response(operation)?;
            let response_decoder = (response.normalization()
                != CompiledResponseNormalization::ScriptBody)
                .then(|| compile_closed_json_decoder(&response))
                .transpose()?;
            let cardinality = match operation.response.max_records {
                1 => SourceCardinality::Singleton,
                2 => SourceCardinality::AmbiguityProbe,
                _ => return Err(SourcePlanCompileError::CompilerInvariant),
            };
            let dci = if request_codec == CompiledRequestCodec::DciExactV1 {
                let document = operation
                    .dci
                    .as_ref()
                    .ok_or(SourcePlanCompileError::CompilerInvariant)?;
                let verification = pack
                    .document
                    .spec
                    .plan
                    .verification_operations
                    .iter()
                    .find(|candidate| candidate.id == document.jwks_operation)
                    .ok_or(SourcePlanCompileError::CompilerInvariant)?;
                let verification_id = OperationId::try_from(verification.id.as_str())
                    .map_err(|_| SourcePlanCompileError::CompilerInvariant)?;
                let fixed_path: Box<str> =
                    if verification.path == "/" && verification_application_base_path != "/" {
                        verification_application_base_path.into()
                    } else {
                        destination_fixed_path(
                            verification_application_base_path,
                            verification.path.as_str(),
                        )
                    };
                let transport_template = DataDestinationRequestTemplate::new(
                    DestinationMethod::Get,
                    &fixed_path,
                    &[],
                    &[],
                    DestinationAuthorizationTemplate::Forbidden,
                    DestinationBodyTemplate::Forbidden,
                    verification.step_limits.max_request_bytes as usize,
                )
                .map_err(|_| SourcePlanCompileError::CompilerInvariant)?;
                Some(CompiledDciExact {
                    protocol_version: document.protocol_version.as_str().into(),
                    sender_id: document.sender_id.as_str().into(),
                    receiver_id: document.receiver_id.as_deref().map(Into::into),
                    registry_type: document.registry_type.as_deref().map(Into::into),
                    registry_event_type: document.registry_event_type.as_deref().map(Into::into),
                    record_type: document.record_type.as_deref().map(Into::into),
                    selector: match document.exact_and.is_empty() {
                        false => super::CompiledDciSelector::ExactAnd {
                            components: document
                                .exact_and
                                .iter()
                                .map(|(input, component)| {
                                    Ok(super::CompiledDciExactComponent {
                                        input_index: *input_indexes
                                            .get(input.as_str())
                                            .ok_or(SourcePlanCompileError::CompilerInvariant)?,
                                        field: component.field.as_str().into(),
                                        response_pointer: component
                                            .response_pointer
                                            .as_str()
                                            .into(),
                                    })
                                })
                                .collect::<Result<Box<[_]>, SourcePlanCompileError>>()?,
                            identifier_type: document.identifier_type.as_deref().map(Into::into),
                        },
                        true => return Err(SourcePlanCompileError::CompilerInvariant),
                    },
                    locale: document.locale.as_str().into(),
                    page_number: document.page_number,
                    verification: CompiledVerificationOperation {
                        id: verification_id,
                        fixed_path,
                        transport_template,
                        response_max_bytes: verification.max_response_bytes,
                        request_timeout_ms: verification.step_limits.timeout_ms,
                    },
                })
            } else {
                None
            };
            Ok(CompiledOperation {
                id,
                method: operation.method,
                fixed_path,
                path_segment,
                query,
                headers,
                body,
                request_codec,
                request_signer,
                request_max_bytes: step_limits.max_request_bytes,
                request_timeout_ms: step_limits.timeout_ms,
                request_max_in_flight: step_limits.max_in_flight,
                auth,
                api_key,
                selector,
                projection,
                transport_template,
                response,
                response_decoder,
                acquisition_class,
                cardinality,
                total_deadline_ms,
                acquired_fields,
                disclosed_fields,
                dci,
            })
        })
        .collect()
}

pub(super) fn compile_input_slots(
    pack: &IntegrationPackArtifact,
    profile_contract_hash: &ProfileContractHash,
) -> Result<Vec<CompiledInputSlot>, SourcePlanCompileError> {
    pack.document
        .spec
        .input_slots
        .iter()
        .enumerate()
        .map(|(slot_index, (name, input))| {
            let matcher = input
                .pattern
                .as_deref()
                .map(parse_input_pattern)
                .transpose()
                .map_err(|_| SourcePlanCompileError::CompilerInvariant)?
                .map(|pattern| CompiledInputMatcher { pattern });
            let canonicalization = match input.canonicalization {
                CanonicalizationDocument::Identity => CompiledInputCanonicalization::Identity,
                CanonicalizationDocument::AsciiLowercase => {
                    CompiledInputCanonicalization::AsciiLowercase
                }
            };
            let (document_type, nullable) = input
                .resolved_type()
                .ok_or(SourcePlanCompileError::CompilerInvariant)?;
            let input_type = match document_type {
                InputTypeDocument::String => CompiledInputType::String,
                InputTypeDocument::FullDate => CompiledInputType::FullDate,
                InputTypeDocument::Boolean => CompiledInputType::Boolean,
                InputTypeDocument::Integer => CompiledInputType::Integer,
            };
            let role = match input.role {
                InputRoleDocument::Selector => CompiledInputRole::Selector,
                InputRoleDocument::Parameter => CompiledInputRole::Parameter,
            };
            Ok(CompiledInputSlot {
                name: name.as_str().into(),
                profile_contract_hash: profile_contract_hash.clone(),
                slot_index: u16::try_from(slot_index)
                    .map_err(|_| SourcePlanCompileError::CompilerInvariant)?,
                max_bytes: input
                    .canonical_max_bytes()
                    .ok_or(SourcePlanCompileError::CompilerInvariant)?,
                min_length: input.min_length,
                max_length: input.max_length,
                input_type,
                role,
                nullable,
                canonicalization,
                matcher,
                minimum: input.minimum,
                maximum: input.maximum,
                allowed_values: input
                    .allowed_values
                    .iter()
                    .cloned()
                    .map(|value| canonicalize_input_constraint(value, canonicalization))
                    .collect(),
                constant: input
                    .constant
                    .clone()
                    .map(|value| canonicalize_input_constraint(value, canonicalization)),
            })
        })
        .collect()
}

fn canonicalize_input_constraint(
    value: serde_json::Value,
    canonicalization: CompiledInputCanonicalization,
) -> serde_json::Value {
    match (canonicalization, value) {
        (CompiledInputCanonicalization::AsciiLowercase, serde_json::Value::String(value)) => {
            serde_json::Value::String(value.to_ascii_lowercase())
        }
        (_, value) => value,
    }
}

fn compile_named_expressions(
    expressions: &BTreeMap<String, ValueExpressionDocument>,
    input_indexes: &BTreeMap<&str, usize>,
    parameter_indexes: &BTreeMap<&str, usize>,
    operation_indexes: &BTreeMap<&str, usize>,
    prior_slot_indexes: &BTreeMap<&str, BTreeMap<&str, usize>>,
) -> Result<Box<[CompiledNamedExpression]>, SourcePlanCompileError> {
    expressions
        .iter()
        .map(|(name, expression)| {
            Ok(CompiledNamedExpression {
                name: name.as_str().into(),
                value: compile_value_expression(
                    expression,
                    input_indexes,
                    parameter_indexes,
                    operation_indexes,
                    prior_slot_indexes,
                )?,
            })
        })
        .collect()
}

fn compile_value_expression(
    expression: &ValueExpressionDocument,
    input_indexes: &BTreeMap<&str, usize>,
    parameter_indexes: &BTreeMap<&str, usize>,
    operation_indexes: &BTreeMap<&str, usize>,
    prior_slot_indexes: &BTreeMap<&str, BTreeMap<&str, usize>>,
) -> Result<CompiledValueExpression, SourcePlanCompileError> {
    match expression {
        ValueExpressionDocument::Literal { value } => {
            Ok(CompiledValueExpression::Literal(value.as_str().into()))
        }
        ValueExpressionDocument::ConsultationInput { name } => input_indexes
            .get(name.as_str())
            .copied()
            .map(|input_index| CompiledValueExpression::ConsultationInput { input_index })
            .ok_or(SourcePlanCompileError::CompilerInvariant),
        ValueExpressionDocument::DeploymentParameter { name } => parameter_indexes
            .get(name.as_str())
            .copied()
            .map(|parameter_index| CompiledValueExpression::DeploymentParameter { parameter_index })
            .ok_or(SourcePlanCompileError::CompilerInvariant),
        ValueExpressionDocument::PriorStepOutput { step, output } => {
            let operation_index = operation_indexes
                .get(step.as_str())
                .copied()
                .ok_or(SourcePlanCompileError::CompilerInvariant)?;
            let output_slot_index = prior_slot_indexes
                .get(step.as_str())
                .and_then(|slots| slots.get(output.as_str()))
                .copied()
                .ok_or(SourcePlanCompileError::CompilerInvariant)?;
            Ok(CompiledValueExpression::PriorStepOutput {
                operation_index,
                output_slot_index,
            })
        }
    }
}

fn compile_body_template(
    template: &BodyTemplateDocument,
    input_indexes: &BTreeMap<&str, usize>,
    parameter_indexes: &BTreeMap<&str, usize>,
    operation_indexes: &BTreeMap<&str, usize>,
    prior_slot_indexes: &BTreeMap<&str, BTreeMap<&str, usize>>,
) -> Result<CompiledBodyTemplate, SourcePlanCompileError> {
    match template {
        BodyTemplateDocument::Null => Ok(CompiledBodyTemplate::Null),
        BodyTemplateDocument::Boolean { value } => Ok(CompiledBodyTemplate::Boolean(*value)),
        BodyTemplateDocument::Integer { value } => Ok(CompiledBodyTemplate::Integer(*value)),
        BodyTemplateDocument::StringLiteral { value } => {
            Ok(CompiledBodyTemplate::StringLiteral(value.as_str().into()))
        }
        BodyTemplateDocument::Expression { value } => {
            Ok(CompiledBodyTemplate::Expression(compile_value_expression(
                value,
                input_indexes,
                parameter_indexes,
                operation_indexes,
                prior_slot_indexes,
            )?))
        }
        BodyTemplateDocument::Array { items } => items
            .iter()
            .map(|item| {
                compile_body_template(
                    item,
                    input_indexes,
                    parameter_indexes,
                    operation_indexes,
                    prior_slot_indexes,
                )
            })
            .collect::<Result<Box<[_]>, _>>()
            .map(CompiledBodyTemplate::Array),
        BodyTemplateDocument::Object { fields } => fields
            .iter()
            .map(|(name, value)| {
                Ok(CompiledNamedBodyField {
                    name: name.as_str().into(),
                    value: compile_body_template(
                        value,
                        input_indexes,
                        parameter_indexes,
                        operation_indexes,
                        prior_slot_indexes,
                    )?,
                })
            })
            .collect::<Result<Box<[_]>, _>>()
            .map(CompiledBodyTemplate::Object),
    }
}

fn compile_projection(
    operation: &HttpOperationDocument,
) -> Result<CompiledProjectionMechanism, SourcePlanCompileError> {
    match &operation.projection {
        ProjectionMechanismDocument::QueryParameterExact { parameter, .. } => operation
            .query
            .keys()
            .position(|name| name == parameter)
            .map(|query_index| CompiledProjectionMechanism::QueryParameterExact { query_index })
            .ok_or(SourcePlanCompileError::CompilerInvariant),
        ProjectionMechanismDocument::ReviewedRequestTemplate {
            minimization_evidence,
            ..
        } => Ok(CompiledProjectionMechanism::ReviewedRequestTemplate {
            evidence_hash: minimization_evidence.as_str().into(),
        }),
        ProjectionMechanismDocument::BoundedFullRecord => {
            Ok(CompiledProjectionMechanism::BoundedFullRecord)
        }
    }
}

fn compile_response(
    operation: &HttpOperationDocument,
) -> Result<CompiledResponse, SourcePlanCompileError> {
    let outputs = operation
        .response
        .output_mapping
        .iter()
        .map(|(field, pointer)| {
            Ok::<_, SourcePlanCompileError>(CompiledOutputMapping {
                field: AcquiredField::try_from(field.as_str())
                    .map_err(|_| SourcePlanCompileError::CompilerInvariant)?,
                pointer: compile_json_pointer(pointer)?,
            })
        })
        .collect::<Result<Box<[_]>, _>>()?;
    let prior_outputs = operation
        .response
        .prior_outputs
        .iter()
        .map(|(name, output)| {
            Ok::<_, SourcePlanCompileError>(CompiledPriorOutputSlot {
                name: name.as_str().into(),
                pointer: compile_json_pointer(&output.pointer)?,
                shape: compile_prior_scalar_shape(output)?,
                date: output.output_type == OutputTypeDocument::Date,
            })
        })
        .collect::<Result<Box<[_]>, _>>()?;
    let cardinality = match &operation.response.cardinality {
        CardinalityMechanismDocument::ScriptManaged => CompiledCardinalityMechanism::ScriptManaged,
        CardinalityMechanismDocument::DciProbeTwo => CompiledCardinalityMechanism::DciProbeTwo,
        CardinalityMechanismDocument::ProbeQueryParameter { parameter } => operation
            .query
            .keys()
            .position(|name| name == parameter)
            .map(|query_index| CompiledCardinalityMechanism::ProbeQueryParameter { query_index })
            .ok_or(SourcePlanCompileError::CompilerInvariant)?,
        CardinalityMechanismDocument::ProbeBodyInteger { pointer } => {
            CompiledCardinalityMechanism::ProbeBodyInteger {
                pointer: compile_json_pointer(pointer)?,
            }
        }
        CardinalityMechanismDocument::ReviewedRequestTemplateProbe {
            conformance_evidence,
            ..
        } => CompiledCardinalityMechanism::ReviewedRequestTemplateProbe {
            evidence_hash: conformance_evidence.as_str().into(),
        },
        CardinalityMechanismDocument::SourceEnforcedSingleton {
            conformance_evidence,
        } => CompiledCardinalityMechanism::SourceEnforcedSingleton {
            evidence_hash: conformance_evidence.as_str().into(),
        },
    };
    let normalization = match operation.response.normalization {
        ResponseNormalizationDocument::ScriptBody => CompiledResponseNormalization::ScriptBody,
        ResponseNormalizationDocument::Object => CompiledResponseNormalization::Object,
        ResponseNormalizationDocument::ArrayProbeTwo => {
            CompiledResponseNormalization::ArrayProbeTwo
        }
        ResponseNormalizationDocument::ObjectArrayProbeTwo => {
            let records_field = operation
                .response
                .records_field
                .as_deref()
                .ok_or(SourcePlanCompileError::CompilerInvariant)?;
            let records_field_index = match &operation.response.schema {
                ResponseSchemaDocument::Object { fields, .. } => fields
                    .keys()
                    .position(|name| name == records_field)
                    .ok_or(SourcePlanCompileError::CompilerInvariant)?,
                _ => return Err(SourcePlanCompileError::CompilerInvariant),
            };
            CompiledResponseNormalization::ObjectArrayProbeTwo {
                records_field_index,
            }
        }
    };
    Ok(CompiledResponse {
        format: match operation.response.format {
            ResponseFormatDocument::Json => CompiledResponseFormat::Json,
            ResponseFormatDocument::Text => CompiledResponseFormat::Text,
        },
        selected_headers: operation
            .response
            .selected_headers
            .iter()
            .map(|name| name.as_str().into())
            .collect(),
        max_bytes: operation.response.max_bytes,
        max_records: operation.response.max_records,
        accepted_statuses: operation
            .response
            .accepted_statuses
            .clone()
            .into_boxed_slice(),
        no_match_statuses: operation
            .response
            .status_outcomes
            .no_match
            .clone()
            .into_boxed_slice(),
        ambiguous_statuses: operation
            .response
            .status_outcomes
            .ambiguous
            .clone()
            .into_boxed_slice(),
        normalization,
        schema: compile_response_schema(&operation.response.schema),
        outputs,
        prior_outputs,
        cardinality,
    })
}

pub(super) fn compile_closed_json_decoder(
    response: &CompiledResponse,
) -> Result<ClosedJsonDecoder, SourcePlanCompileError> {
    let max_bytes = usize::try_from(response.max_bytes)
        .map_err(|_| SourcePlanCompileError::CompilerInvariant)?;
    if max_bytes > MAX_CLOSED_JSON_ENCODED_BODY_BYTES {
        return Err(SourcePlanCompileError::CompilerInvariant);
    }

    let schema = compile_closed_json_schema(&response.schema)?;
    let root = match response.normalization {
        CompiledResponseNormalization::ScriptBody => {
            return Err(SourcePlanCompileError::CompilerInvariant)
        }
        CompiledResponseNormalization::Object => ClosedJsonRecordRoot::Object,
        CompiledResponseNormalization::ArrayProbeTwo => ClosedJsonRecordRoot::ArrayProbeTwo,
        CompiledResponseNormalization::ObjectArrayProbeTwo {
            records_field_index,
        } => ClosedJsonRecordRoot::ObjectArrayProbeTwo {
            field_index: records_field_index,
        },
    };
    let mut projections = response
        .outputs
        .iter()
        .map(|output| {
            ClosedJsonScalarProjection::new(output.field(), output.extraction_pointer().tokens())
                .map_err(|_| SourcePlanCompileError::CompilerInvariant)
        })
        .collect::<Result<Vec<_>, _>>()?;
    projections.extend(
        response
            .prior_outputs
            .iter()
            .enumerate()
            .map(|(index, output)| {
                ClosedJsonScalarProjection::new(
                    &format!("registry.internal.prior.{index}"),
                    output.extraction_pointer().tokens(),
                )
                .map_err(|_| SourcePlanCompileError::CompilerInvariant)
            })
            .collect::<Result<Vec<_>, _>>()?,
    );

    ClosedJsonDecoder::new(schema, root, projections)
        .map_err(|_| SourcePlanCompileError::CompilerInvariant)
}

fn compile_closed_json_schema(
    schema: &CompiledResponseSchema,
) -> Result<ClosedJsonSchema, SourcePlanCompileError> {
    match schema {
        CompiledResponseSchema::ScriptBody => Err(SourcePlanCompileError::CompilerInvariant),
        CompiledResponseSchema::Object {
            nullable,
            reject_unknown_fields,
            fields,
        } => {
            let fields = fields
                .iter()
                .map(|field| {
                    let schema = compile_closed_json_schema(&field.schema)?;
                    ClosedJsonField::new(&field.name, field.required, schema)
                        .map_err(|_| SourcePlanCompileError::CompilerInvariant)
                })
                .collect::<Result<Vec<_>, _>>()?;
            ClosedJsonSchema::object_with_unknown_field_policy(
                *nullable,
                *reject_unknown_fields,
                fields,
            )
            .map_err(|_| SourcePlanCompileError::CompilerInvariant)
        }
        CompiledResponseSchema::Array {
            nullable,
            max_items,
            items,
        } => ClosedJsonSchema::array(*nullable, *max_items, compile_closed_json_schema(items)?)
            .map_err(|_| SourcePlanCompileError::CompilerInvariant),
        CompiledResponseSchema::Scalar(CompiledScalarShape::String {
            nullable,
            max_bytes,
        }) => ClosedJsonSchema::string(*nullable, *max_bytes)
            .map_err(|_| SourcePlanCompileError::CompilerInvariant),
        CompiledResponseSchema::Scalar(CompiledScalarShape::Boolean { nullable }) => {
            Ok(ClosedJsonSchema::boolean(*nullable))
        }
        CompiledResponseSchema::Scalar(CompiledScalarShape::Integer {
            nullable,
            minimum,
            maximum,
        }) => ClosedJsonSchema::integer(*nullable, *minimum, *maximum)
            .map_err(|_| SourcePlanCompileError::CompilerInvariant),
        CompiledResponseSchema::Scalar(CompiledScalarShape::Number {
            nullable,
            minimum,
            maximum,
        }) => ClosedJsonSchema::number(*nullable, *minimum, *maximum)
            .map_err(|_| SourcePlanCompileError::CompilerInvariant),
    }
}

fn compile_json_pointer(pointer: &str) -> Result<CompiledJsonPointer, SourcePlanCompileError> {
    let tokens = decode_pointer_tokens(pointer)
        .map_err(|_| SourcePlanCompileError::CompilerInvariant)?
        .into_iter()
        .map(String::into_boxed_str)
        .collect();
    Ok(CompiledJsonPointer { tokens })
}

fn compile_prior_scalar_shape(
    output: &PriorOutputBindingDocument,
) -> Result<CompiledScalarShape, SourcePlanCompileError> {
    match output.output_type {
        OutputTypeDocument::String => Ok(CompiledScalarShape::String {
            nullable: output.nullable,
            max_bytes: u32::from(
                output
                    .max_bytes
                    .ok_or(SourcePlanCompileError::CompilerInvariant)?,
            ),
        }),
        OutputTypeDocument::Boolean => Ok(CompiledScalarShape::Boolean {
            nullable: output.nullable,
        }),
        OutputTypeDocument::Integer => Ok(CompiledScalarShape::Integer {
            nullable: output.nullable,
            minimum: output
                .minimum
                .ok_or(SourcePlanCompileError::CompilerInvariant)?,
            maximum: output
                .maximum
                .ok_or(SourcePlanCompileError::CompilerInvariant)?,
        }),
        OutputTypeDocument::Date => Ok(CompiledScalarShape::String {
            nullable: output.nullable,
            max_bytes: 10,
        }),
    }
}

pub(in crate::source_plan) fn compile_response_schema(
    schema: &ResponseSchemaDocument,
) -> CompiledResponseSchema {
    match schema {
        ResponseSchemaDocument::ScriptBody => CompiledResponseSchema::ScriptBody,
        ResponseSchemaDocument::Object {
            nullable,
            reject_unknown_fields,
            fields,
        } => CompiledResponseSchema::Object {
            nullable: *nullable,
            reject_unknown_fields: *reject_unknown_fields,
            fields: fields
                .iter()
                .map(|(name, field)| CompiledResponseField {
                    name: name.as_str().into(),
                    required: field.required,
                    schema: compile_response_schema(&field.schema),
                })
                .collect(),
        },
        ResponseSchemaDocument::Array {
            nullable,
            max_items,
            items,
        } => CompiledResponseSchema::Array {
            nullable: *nullable,
            max_items: *max_items,
            items: Box::new(compile_response_schema(items)),
        },
        ResponseSchemaDocument::String {
            nullable,
            max_bytes,
        } => CompiledResponseSchema::Scalar(CompiledScalarShape::String {
            nullable: *nullable,
            max_bytes: *max_bytes,
        }),
        ResponseSchemaDocument::Boolean { nullable } => {
            CompiledResponseSchema::Scalar(CompiledScalarShape::Boolean {
                nullable: *nullable,
            })
        }
        ResponseSchemaDocument::Integer {
            nullable,
            minimum,
            maximum,
        } => CompiledResponseSchema::Scalar(CompiledScalarShape::Integer {
            nullable: *nullable,
            minimum: *minimum,
            maximum: *maximum,
        }),
        ResponseSchemaDocument::Number {
            nullable,
            minimum,
            maximum,
        } => CompiledResponseSchema::Scalar(CompiledScalarShape::Number {
            nullable: *nullable,
            minimum: *minimum,
            maximum: *maximum,
        }),
    }
}
