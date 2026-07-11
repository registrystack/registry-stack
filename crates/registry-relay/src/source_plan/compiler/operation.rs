//! Data-operation descriptor and closed parser compilation.

use super::*;

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
    let (source, location) = match &reviewed.selector {
        ExactSelectorDocument::HttpAnchor {
            input,
            operation: root_operation,
            location,
        } if root_operation == &operation.id => {
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
        ExactSelectorDocument::HttpAnchor { .. } => {
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
        ExactSelectorDocument::SnapshotKey { .. } => {
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
        RequestSelectorLocationDocument::Body { pointer } => CompiledSelectorLocation::Body {
            pointer: compile_json_pointer(pointer)?,
        },
        RequestSelectorLocationDocument::Codec {
            role: CodecSelectorRoleDocument::DciIdtypeValue,
        } => CompiledSelectorLocation::DciIdtypeValue,
    };
    Ok(CompiledSelectorBinding { source, location })
}

pub(super) fn compile_operation_descriptors(
    pack: &IntegrationPackArtifact,
    acquisition_class: AcquisitionClass,
    cardinality: SourceCardinality,
    total_deadline_ms: u32,
    application_base_path: &str,
    indexes: &OperationCompilationIndexes<'_, '_>,
) -> Result<Vec<CompiledOperation>, SourcePlanCompileError> {
    let input_indexes = indexes.inputs;
    let parameter_indexes = indexes.parameters;
    let operation_indexes = indexes.operations;
    let prior_slot_indexes = indexes.prior_slots;
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
                .acquisition_fields
                .iter()
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
            let query_bounds = operation
                .query
                .iter()
                .map(|(name, expression)| {
                    (
                        name.as_str(),
                        expression_max_bytes(
                            expression,
                            &pack.document.spec.input_slots,
                            &pack.document.spec.deployment_parameters,
                        ),
                    )
                })
                .collect::<Vec<_>>();
            let header_bounds = operation
                .headers
                .iter()
                .map(|(name, expression)| {
                    (
                        name.as_str(),
                        expression_max_bytes(
                            expression,
                            &pack.document.spec.input_slots,
                            &pack.document.spec.deployment_parameters,
                        ),
                    )
                })
                .collect::<Vec<_>>();
            let max_body_bytes = operation
                .body
                .as_ref()
                .map(|body| {
                    body_template_max_bytes(
                        body,
                        &pack.document.spec.input_slots,
                        &pack.document.spec.deployment_parameters,
                    )
                })
                .transpose()
                .map_err(|_| SourcePlanCompileError::CompilerInvariant)?
                .unwrap_or(0);
            let destination_method = match operation.method {
                ReadMethod::Get => DestinationMethod::Get,
                ReadMethod::ReadOnlyPost => DestinationMethod::ReviewedReadOnlyPost,
            };
            let (auth, authorization_template) = match operation.auth {
                SourceAuthDocument::None => (
                    CompiledSourceAuth::None,
                    DestinationAuthorizationTemplate::Forbidden,
                ),
                SourceAuthDocument::Basic { max_value_bytes } => (
                    CompiledSourceAuth::Basic,
                    DestinationAuthorizationTemplate::Basic {
                        max_value_bytes: usize::from(max_value_bytes),
                    },
                ),
                SourceAuthDocument::StaticBearer { max_value_bytes } => (
                    CompiledSourceAuth::StaticBearer,
                    DestinationAuthorizationTemplate::Bearer {
                        max_value_bytes: usize::from(max_value_bytes),
                    },
                ),
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
                        DestinationAuthorizationTemplate::Bearer { max_value_bytes },
                    )
                }
            };
            let fixed_path = destination_fixed_path(application_base_path, &operation.path);
            let transport_template = DataDestinationRequestTemplate::new(
                destination_method,
                &fixed_path,
                &query_bounds,
                &header_bounds,
                authorization_template,
                if operation.body.is_some() {
                    DestinationBodyTemplate::Required {
                        max_bytes: max_body_bytes,
                    }
                } else {
                    DestinationBodyTemplate::Forbidden
                },
                step_limits.max_request_bytes as usize,
            )
            .map_err(|_| {
                if application_base_path == "/" {
                    SourcePlanCompileError::CompilerInvariant
                } else {
                    SourcePlanCompileError::BindingWidening
                }
            })?;
            let projection = compile_projection(operation)?;
            let response = compile_response(operation)?;
            Ok(CompiledOperation {
                id,
                method: operation.method,
                fixed_path,
                query,
                headers,
                body,
                request_codec,
                request_signer,
                request_max_bytes: step_limits.max_request_bytes,
                request_timeout_ms: step_limits.timeout_ms,
                request_max_in_flight: step_limits.max_in_flight,
                auth,
                selector,
                projection,
                transport_template,
                response,
                acquisition_class,
                cardinality,
                total_deadline_ms,
                acquired_fields,
                disclosed_fields,
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
            let pattern = parse_input_pattern(&input.pattern)
                .map_err(|_| SourcePlanCompileError::CompilerInvariant)?;
            let canonicalization = match input.canonicalization {
                CanonicalizationDocument::Identity => CompiledInputCanonicalization::Identity,
                CanonicalizationDocument::AsciiLowercase => {
                    CompiledInputCanonicalization::AsciiLowercase
                }
            };
            Ok(CompiledInputSlot {
                name: name.as_str().into(),
                profile_contract_hash: profile_contract_hash.clone(),
                slot_index: u16::try_from(slot_index)
                    .map_err(|_| SourcePlanCompileError::CompilerInvariant)?,
                max_bytes: input.max_bytes,
                canonicalization,
                matcher: CompiledInputMatcher { pattern },
            })
        })
        .collect()
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
            })
        })
        .collect::<Result<Box<[_]>, _>>()?;
    let cardinality = match &operation.response.cardinality {
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
        max_bytes: operation.response.max_bytes,
        max_records: operation.response.max_records,
        accepted_statuses: operation
            .response
            .accepted_statuses
            .clone()
            .into_boxed_slice(),
        normalization,
        schema: compile_response_schema(&operation.response.schema),
        outputs,
        prior_outputs,
        cardinality,
    })
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
        OutputTypeDocument::Number => Ok(CompiledScalarShape::Number {
            nullable: output.nullable,
            minimum: output
                .minimum
                .ok_or(SourcePlanCompileError::CompilerInvariant)?,
            maximum: output
                .maximum
                .ok_or(SourcePlanCompileError::CompilerInvariant)?,
        }),
    }
}

pub(in crate::source_plan) fn compile_response_schema(
    schema: &ResponseSchemaDocument,
) -> CompiledResponseSchema {
    match schema {
        ResponseSchemaDocument::Object {
            nullable, fields, ..
        } => CompiledResponseSchema::Object {
            nullable: *nullable,
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
