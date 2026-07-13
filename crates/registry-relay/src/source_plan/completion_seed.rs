// SPDX-License-Identifier: Apache-2.0
//! Startup-only canonical completion-seed sizing.
//!
//! The compiler renders the complete state-plane seed shape from typed
//! artifacts, measures its largest request-dependent form, and retains only
//! the resulting byte count. Runtime code never reconstructs or reparses a
//! canonical artifact to establish this bound.

use std::collections::BTreeSet;

use registry_platform_audit::{
    DurableAuditOperationId, DurableAuditPhase, DurableAuditStreamKind, DurableAuditWrite,
};
use registry_platform_crypto::canonicalize_json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::artifact::{
    IntegrationPackArtifact, PrivateBindingArtifact, PublicContractArtifact,
    SourceObservedAtDocument, SourcePlanKind, SourcePlanLimits, SourceRevisionDocument,
};
use super::compiler::{
    CompiledBodyTemplate, CompiledCardinalityMechanism, CompiledOperation,
    CompiledProjectionMechanism, CompiledScalarShape, CompiledSelectorLocation,
    CompiledSelectorSource, CompiledSnapshotBinding, CompiledStep, CompiledStepPredicate,
    CompiledValueExpression, RhaiWorkerLimits, SourcePlanCompileError,
};
use super::runtime_profile::{
    CompiledDispatchProfile, PhysicalProjectionDigest, PredicatePlanDigest, RhaiPredicateIdentity,
};

pub(super) const MAX_COMPLETION_AUDIT_CANONICAL_BYTES_V1: usize = 768 * 1024;

const PREDICATE_PLAN_DOMAIN_V1: &str = "registry.relay.consultation-predicate-plan.v1";
const PHYSICAL_PROJECTION_DOMAIN_V1: &str = "registry.relay.consultation-physical-projection.v1";

pub(super) struct CompletionSeedSizing {
    pub(super) canonical_bytes_max: usize,
    pub(super) completion_audit_canonical_bytes_max: usize,
    pub(super) template: CompiledCompletionSeedTemplate,
    #[cfg(test)]
    pub(super) canonical_value_max: Value,
}

/// Immutable, secret-free state-plane bindings needed to render one runtime
/// completion seed.
///
/// This value deliberately retains no canonical JSON, source URL, credential
/// material, request selector, predicate, or script source. Its private
/// topology identifiers belong only in the restricted completion intent and
/// audit path, so the type implements neither `Debug` nor serialization.
pub(super) struct CompiledCompletionSeedTemplate {
    credential_destination_id: Option<Box<str>>,
    data_destination_id: Option<Box<str>>,
    verification_destination_id: Option<Box<str>>,
    credential_reference: Option<Box<str>>,
    credential_generation: Option<u64>,
    permit_bindings: Box<[CompiledPermitBinding]>,
    credential_token_lifetime_ms: Option<u32>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum CompiledOperationKind {
    Credential,
    Data,
}

impl CompiledOperationKind {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Credential => "credential",
            Self::Data => "data",
        }
    }
}

pub(super) struct CompiledPermitBinding {
    kind: CompiledOperationKind,
    ordinal: u8,
}

impl CompiledPermitBinding {
    pub(super) const fn kind(&self) -> CompiledOperationKind {
        self.kind
    }

    pub(super) const fn ordinal(&self) -> u8 {
        self.ordinal
    }
}

impl CompiledCompletionSeedTemplate {
    pub(super) fn credential_destination_id(&self) -> Option<&str> {
        self.credential_destination_id.as_deref()
    }

    pub(super) fn data_destination_id(&self) -> Option<&str> {
        self.data_destination_id.as_deref()
    }

    pub(super) fn verification_destination_id(&self) -> Option<&str> {
        self.verification_destination_id.as_deref()
    }

    pub(super) fn credential_reference(&self) -> Option<&str> {
        self.credential_reference.as_deref()
    }

    pub(super) const fn credential_generation(&self) -> Option<u64> {
        self.credential_generation
    }

    pub(super) fn permit_bindings(&self) -> impl ExactSizeIterator<Item = &CompiledPermitBinding> {
        self.permit_bindings.iter()
    }

    pub(super) const fn credential_token_lifetime_ms(&self) -> Option<u32> {
        self.credential_token_lifetime_ms
    }
}

pub(super) fn compile_runtime_commitment_digests(
    kind: SourcePlanKind,
    input_names: &[&str],
    operations: &[CompiledOperation],
    steps: &[CompiledStep],
    dispatch: &CompiledDispatchProfile,
    rhai: Option<&RhaiPredicateIdentity>,
    snapshot: Option<&CompiledSnapshotBinding>,
) -> Result<(PredicatePlanDigest, PhysicalProjectionDigest), SourcePlanCompileError> {
    let predicate = compile_predicate_plan_digest(
        kind,
        input_names,
        operations,
        steps,
        dispatch,
        rhai,
        snapshot,
    )?;
    let projection = compile_physical_projection_digest(kind, operations, snapshot)?;
    Ok((predicate, projection))
}

fn compile_predicate_plan_digest(
    kind: SourcePlanKind,
    input_names: &[&str],
    operations: &[CompiledOperation],
    steps: &[CompiledStep],
    dispatch: &CompiledDispatchProfile,
    rhai: Option<&RhaiPredicateIdentity>,
    snapshot: Option<&CompiledSnapshotBinding>,
) -> Result<PredicatePlanDigest, SourcePlanCompileError> {
    let mut operation_preimages = operations
        .iter()
        .map(|operation| {
            Ok((
                operation.id().as_str(),
                predicate_operation_preimage(operation, input_names, operations)?,
            ))
        })
        .collect::<Result<Vec<_>, SourcePlanCompileError>>()?;
    operation_preimages.sort_unstable_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    let operation_preimages = operation_preimages
        .into_iter()
        .map(|(_, preimage)| preimage)
        .collect::<Vec<_>>();

    let plan = match (kind, dispatch, rhai) {
        (SourcePlanKind::SnapshotExact, CompiledDispatchProfile::SnapshotExact, None) => {
            let snapshot = snapshot.ok_or(SourcePlanCompileError::CompilerInvariant)?;
            let selectors = snapshot
                .keys()
                .map(|(input, physical)| {
                    input_names
                        .contains(&input)
                        .then(|| {
                            json!({
                                "source": {"kind": "consultation_input", "input": input},
                                "location": {
                                    "kind": "materialized_snapshot_key",
                                    "physical_field": physical,
                                    "physical_type": "utf8",
                                    "comparison": "binary_equality",
                                },
                            })
                        })
                        .ok_or(SourcePlanCompileError::CompilerInvariant)
                })
                .collect::<Result<Vec<_>, _>>()?;
            json!({
                "schema": "registry.relay.consultation-predicate-plan.v1",
                "kind": "snapshot_exact",
                "operations": operation_preimages,
                "snapshot_selectors": selectors,
            })
        }
        (SourcePlanKind::BoundedHttp, CompiledDispatchProfile::BoundedHttp { .. }, None) => {
            let ordered_steps = steps
                .iter()
                .map(|step| bounded_step_preimage(step, operations))
                .collect::<Result<Vec<_>, SourcePlanCompileError>>()?;
            json!({
                "schema": "registry.relay.consultation-predicate-plan.v1",
                "kind": "bounded_http",
                "operations": operation_preimages,
                "ordered_steps": ordered_steps,
            })
        }
        (
            SourcePlanKind::SandboxedRhai,
            CompiledDispatchProfile::SandboxedRhai {
                callable_operations,
                worker_limits,
            },
            Some(rhai),
        ) if worker_limits.max_calls() > 0 => json!({
            "schema": "registry.relay.consultation-predicate-plan.v1",
            "kind": "sandboxed_rhai",
            "operations": operation_preimages,
            "rhai": {
                "script_hash": rhai.script_hash(),
                "entrypoint": rhai.entrypoint(),
                "callable_operation_ids": callable_operations
                    .iter()
                    .map(crate::consultation::OperationId::as_str)
                    .collect::<Vec<_>>(),
                "effective_max_calls": worker_limits.max_calls(),
            },
        }),
        _ => return Err(SourcePlanCompileError::CompilerInvariant),
    };
    PredicatePlanDigest::from_compiled_label(domain_separated_digest(
        PREDICATE_PLAN_DOMAIN_V1,
        &plan,
    )?)
}

fn compile_physical_projection_digest(
    kind: SourcePlanKind,
    operations: &[CompiledOperation],
    snapshot: Option<&CompiledSnapshotBinding>,
) -> Result<PhysicalProjectionDigest, SourcePlanCompileError> {
    let mut operation_preimages = operations
        .iter()
        .map(|operation| {
            let outputs = operation
                .response()
                .outputs()
                .map(|output| {
                    json!({
                        "field": output.field(),
                        "pointer_tokens": output.extraction_pointer().tokens().collect::<Vec<_>>(),
                    })
                })
                .collect::<Vec<_>>();
            let mut preimage = json!({
                "operation_id": operation.id().as_str(),
                "projection": projection_preimage(operation)?,
                "cardinality": cardinality_preimage(operation)?,
                "output_mappings": outputs,
            });
            if let Some(dci) = operation.dci_exact() {
                let verification = dci.verification();
                preimage["request_codec"] = Value::String("dci_exact_v1".into());
                preimage["verification"] = json!({
                    "primitive": "dci_jws_v1",
                    "operation_id": verification.id().as_str(),
                    "fixed_path": verification.fixed_path(),
                    "response_max_bytes": verification.response_max_bytes(),
                    "order": "before_data_operation",
                });
            }
            Ok((operation.id().as_str(), preimage))
        })
        .collect::<Result<Vec<_>, SourcePlanCompileError>>()?;
    operation_preimages.sort_unstable_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    let snapshot_projection = snapshot.map(|snapshot| {
        json!({
            "keys": snapshot.keys().map(|(input, physical)| json!({
                "input": input,
                "physical_field": physical,
                "physical_type": "utf8",
                "comparison": "binary_equality",
            })).collect::<Vec<_>>(),
            "fields": snapshot
                .projection()
                .map(|(logical, physical)| json!({
                    "logical_field": logical,
                    "physical_field": physical,
                }))
                .collect::<Vec<_>>(),
            "source_observed_at": snapshot
                .source_observed_at_extraction()
                .map(|(logical, physical)| json!({
                    "logical_field": logical,
                    "physical_field": physical,
                    "type": "rfc3339",
                })),
            "source_revision": snapshot
                .source_revision_extraction()
                .map(|(logical, physical, max_bytes)| json!({
                    "logical_field": logical,
                    "physical_field": physical,
                    "type": "string",
                    "max_bytes": max_bytes,
                })),
        })
    });
    if (kind == SourcePlanKind::SnapshotExact) != snapshot_projection.is_some() {
        return Err(SourcePlanCompileError::CompilerInvariant);
    }
    let mut preimage = json!({
        "schema": "registry.relay.consultation-physical-projection.v1",
        "plan_kind": source_plan_kind_str(kind),
        "operations": operation_preimages
            .into_iter()
            .map(|(_, preimage)| preimage)
            .collect::<Vec<_>>(),
    });
    if let Some(snapshot_projection) = snapshot_projection {
        preimage["snapshot_projection"] = snapshot_projection;
    }
    PhysicalProjectionDigest::from_compiled_label(domain_separated_digest(
        PHYSICAL_PROJECTION_DOMAIN_V1,
        &preimage,
    )?)
}

fn predicate_operation_preimage(
    operation: &CompiledOperation,
    input_names: &[&str],
    operations: &[CompiledOperation],
) -> Result<Value, SourcePlanCompileError> {
    let prior_output_declarations = operation
        .response()
        .prior_outputs()
        .map(|output| {
            json!({
                "name": output.name(),
                "pointer_tokens": output.extraction_pointer().tokens().collect::<Vec<_>>(),
                "shape": scalar_shape_preimage(output.shape()),
            })
        })
        .collect::<Vec<_>>();
    let mut preimage = json!({
        "operation_id": operation.id().as_str(),
        "selector": selector_preimage(operation, input_names, operations)?,
        "prior_output_dependencies": prior_output_dependencies(operation, operations)?,
        "prior_output_declarations": prior_output_declarations,
        "projection": projection_preimage(operation)?,
        "cardinality": cardinality_preimage(operation)?,
    });
    if let Some(dci) = operation.dci_exact() {
        let verification = dci.verification();
        preimage["request_codec"] = Value::String("dci_exact_v1".into());
        preimage["verification"] = json!({
            "primitive": "dci_jws_v1",
            "operation_id": verification.id().as_str(),
            "fixed_path": verification.fixed_path(),
            "response_max_bytes": verification.response_max_bytes(),
            "order": "before_data_operation",
        });
    }
    Ok(preimage)
}

fn selector_preimage(
    operation: &CompiledOperation,
    input_names: &[&str],
    operations: &[CompiledOperation],
) -> Result<Value, SourcePlanCompileError> {
    let source = match operation.selector().source() {
        CompiledSelectorSource::ConsultationInput { input_index } => json!({
            "kind": "consultation_input",
            "input": input_names
                .get(input_index)
                .copied()
                .ok_or(SourcePlanCompileError::CompilerInvariant)?,
        }),
        CompiledSelectorSource::PriorStepOutput {
            operation_index,
            output_slot_index,
        } => prior_output_source_preimage(operations, operation_index, output_slot_index)?,
    };
    Ok(json!({
        "source": source,
        "location": selector_location_preimage(operation, operation.selector().location())?,
    }))
}

fn selector_location_preimage(
    operation: &CompiledOperation,
    location: &CompiledSelectorLocation,
) -> Result<Value, SourcePlanCompileError> {
    match location {
        CompiledSelectorLocation::Query { component_index } => Ok(json!({
            "kind": "query",
            "parameter": operation
                .query()
                .nth(*component_index)
                .map(|component| component.name())
                .ok_or(SourcePlanCompileError::CompilerInvariant)?,
        })),
        CompiledSelectorLocation::PathSegment => Ok(json!({
            "kind": "path_segment",
            "ordinal": 0,
        })),
        CompiledSelectorLocation::Body { pointer } => Ok(json!({
            "kind": "body",
            "pointer_tokens": pointer.tokens().collect::<Vec<_>>(),
        })),
        CompiledSelectorLocation::DciIdtypeValue => Ok(json!({
            "kind": "codec",
            "role": "dci_idtype_value",
        })),
        CompiledSelectorLocation::DciExactPredicate => Ok(json!({
            "kind": "codec",
            "role": "dci_exact_predicate",
        })),
        CompiledSelectorLocation::ScriptContext => Ok(json!({
            "kind": "script_context",
        })),
        // A future closed path-segment selector must commit only its compiled
        // fixed segment ordinal/role here. It must never place a rendered path
        // or raw selector value in this preimage.
    }
}

fn prior_output_source_preimage(
    operations: &[CompiledOperation],
    operation_index: usize,
    output_slot_index: usize,
) -> Result<Value, SourcePlanCompileError> {
    let operation = operations
        .get(operation_index)
        .ok_or(SourcePlanCompileError::CompilerInvariant)?;
    let output = operation
        .response()
        .prior_outputs()
        .nth(output_slot_index)
        .ok_or(SourcePlanCompileError::CompilerInvariant)?;
    Ok(json!({
        "kind": "prior_output",
        "operation_id": operation.id().as_str(),
        "output": output.name(),
    }))
}

fn prior_output_dependencies(
    operation: &CompiledOperation,
    operations: &[CompiledOperation],
) -> Result<Vec<Value>, SourcePlanCompileError> {
    let mut dependencies = Vec::new();
    if let CompiledSelectorSource::PriorStepOutput {
        operation_index,
        output_slot_index,
    } = operation.selector().source()
    {
        dependencies.push(json!({
            "request_location": selector_location_preimage(
                operation,
                operation.selector().location(),
            )?,
            "source": prior_output_source_preimage(
                operations,
                operation_index,
                output_slot_index,
            )?,
        }));
    }
    for component in operation.query() {
        append_expression_dependency(
            component.value(),
            json!({"kind": "query", "parameter": component.name()}),
            operations,
            &mut dependencies,
        )?;
    }
    for component in operation.headers() {
        append_expression_dependency(
            component.value(),
            json!({"kind": "header", "name": component.name()}),
            operations,
            &mut dependencies,
        )?;
    }
    if let Some(body) = operation.body() {
        collect_body_dependencies(body, &mut Vec::new(), operations, &mut dependencies)?;
    }
    Ok(dependencies)
}

fn append_expression_dependency(
    expression: &CompiledValueExpression,
    request_location: Value,
    operations: &[CompiledOperation],
    dependencies: &mut Vec<Value>,
) -> Result<(), SourcePlanCompileError> {
    if let CompiledValueExpression::PriorStepOutput {
        operation_index,
        output_slot_index,
    } = expression
    {
        dependencies.push(json!({
            "request_location": request_location,
            "source": prior_output_source_preimage(
                operations,
                *operation_index,
                *output_slot_index,
            )?,
        }));
    }
    Ok(())
}

fn collect_body_dependencies(
    body: &CompiledBodyTemplate,
    path: &mut Vec<Value>,
    operations: &[CompiledOperation],
    dependencies: &mut Vec<Value>,
) -> Result<(), SourcePlanCompileError> {
    match body {
        CompiledBodyTemplate::Expression(expression) => append_expression_dependency(
            expression,
            json!({"kind": "body_template", "path": path}),
            operations,
            dependencies,
        ),
        CompiledBodyTemplate::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                path.push(json!(index));
                collect_body_dependencies(item, path, operations, dependencies)?;
                path.pop();
            }
            Ok(())
        }
        CompiledBodyTemplate::Object(fields) => {
            for field in fields {
                path.push(json!(field.name()));
                collect_body_dependencies(field.value(), path, operations, dependencies)?;
                path.pop();
            }
            Ok(())
        }
        CompiledBodyTemplate::Null
        | CompiledBodyTemplate::Boolean(_)
        | CompiledBodyTemplate::Integer(_)
        | CompiledBodyTemplate::StringLiteral(_) => Ok(()),
    }
}

fn projection_preimage(operation: &CompiledOperation) -> Result<Value, SourcePlanCompileError> {
    match operation.projection() {
        CompiledProjectionMechanism::QueryParameterExact { query_index } => Ok(json!({
            "kind": "query_parameter_exact",
            "parameter": operation
                .query()
                .nth(*query_index)
                .map(|component| component.name())
                .ok_or(SourcePlanCompileError::CompilerInvariant)?,
        })),
        CompiledProjectionMechanism::ReviewedRequestTemplate { evidence_hash } => Ok(json!({
            "kind": "reviewed_request_template",
            "evidence_hash": evidence_hash.as_ref(),
        })),
        CompiledProjectionMechanism::BoundedFullRecord => {
            Ok(json!({"kind": "bounded_full_record"}))
        }
    }
}

fn cardinality_preimage(operation: &CompiledOperation) -> Result<Value, SourcePlanCompileError> {
    match operation.response().cardinality() {
        CompiledCardinalityMechanism::ScriptManaged => Ok(json!({"kind": "script_managed"})),
        CompiledCardinalityMechanism::DciProbeTwo => Ok(json!({"kind": "dci_probe_two"})),
        CompiledCardinalityMechanism::ProbeQueryParameter { query_index } => Ok(json!({
            "kind": "probe_query_parameter",
            "parameter": operation
                .query()
                .nth(*query_index)
                .map(|component| component.name())
                .ok_or(SourcePlanCompileError::CompilerInvariant)?,
        })),
        CompiledCardinalityMechanism::ProbeBodyInteger { pointer } => Ok(json!({
            "kind": "probe_body_integer",
            "pointer_tokens": pointer.tokens().collect::<Vec<_>>(),
        })),
        CompiledCardinalityMechanism::ReviewedRequestTemplateProbe { evidence_hash } => Ok(json!({
            "kind": "reviewed_request_template_probe",
            "evidence_hash": evidence_hash.as_ref(),
        })),
        CompiledCardinalityMechanism::SourceEnforcedSingleton { evidence_hash } => Ok(json!({
            "kind": "source_enforced_singleton",
            "evidence_hash": evidence_hash.as_ref(),
        })),
    }
}

fn bounded_step_preimage(
    step: &CompiledStep,
    operations: &[CompiledOperation],
) -> Result<Value, SourcePlanCompileError> {
    let operation = operations
        .get(step.operation_index())
        .ok_or(SourcePlanCompileError::CompilerInvariant)?;
    let condition = match (
        step.condition_source_index(),
        step.condition_output_slot_index(),
        step.condition(),
    ) {
        (None, None, None) => Value::Null,
        (Some(source_index), Some(output_index), Some(predicate)) => json!({
            "source": prior_output_source_preimage(operations, source_index, output_index)?,
            "predicate": match predicate {
                CompiledStepPredicate::Exists => json!({"kind": "exists"}),
                CompiledStepPredicate::StringEquals(value) => {
                    json!({"kind": "string_equals", "value": value.as_ref()})
                }
                CompiledStepPredicate::BooleanEquals(value) => {
                    json!({"kind": "boolean_equals", "value": value})
                }
                CompiledStepPredicate::IntegerEquals(value) => {
                    json!({"kind": "integer_equals", "value": value})
                }
            },
        }),
        (Some(source_index), None, Some(predicate)) if step.condition_uses_presence() => json!({
            "source": {
                "operation_id": operations
                    .get(source_index)
                    .ok_or(SourcePlanCompileError::CompilerInvariant)?
                    .id()
                    .as_str(),
                "output": "presence",
            },
            "predicate": match predicate {
                CompiledStepPredicate::Exists => json!({"kind": "exists"}),
                CompiledStepPredicate::BooleanEquals(value) => {
                    json!({"kind": "boolean_equals", "value": value})
                }
                _ => return Err(SourcePlanCompileError::CompilerInvariant),
            },
        }),
        _ => return Err(SourcePlanCompileError::CompilerInvariant),
    };
    Ok(json!({
        "operation_id": operation.id().as_str(),
        "condition": condition,
    }))
}

fn scalar_shape_preimage(shape: &CompiledScalarShape) -> Value {
    match shape {
        CompiledScalarShape::String {
            nullable,
            max_bytes,
        } => json!({"type": "string", "nullable": nullable, "max_bytes": max_bytes}),
        CompiledScalarShape::Boolean { nullable } => {
            json!({"type": "boolean", "nullable": nullable})
        }
        CompiledScalarShape::Integer {
            nullable,
            minimum,
            maximum,
        } => json!({
            "type": "integer",
            "nullable": nullable,
            "minimum": minimum,
            "maximum": maximum,
        }),
        CompiledScalarShape::Number {
            nullable,
            minimum,
            maximum,
        } => json!({
            "type": "number",
            "nullable": nullable,
            "minimum": minimum,
            "maximum": maximum,
        }),
    }
}

fn domain_separated_digest(
    domain: &str,
    value: &Value,
) -> Result<Box<str>, SourcePlanCompileError> {
    use std::fmt::Write as _;

    let canonical =
        canonicalize_json(value).map_err(|_| SourcePlanCompileError::CompilerInvariant)?;
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(canonical);
    let digest = hasher.finalize();
    let mut label = String::with_capacity(71);
    label.push_str("sha256:");
    for byte in digest {
        write!(label, "{byte:02x}").map_err(|_| SourcePlanCompileError::CompilerInvariant)?;
    }
    Ok(label.into())
}

const fn source_plan_kind_str(kind: SourcePlanKind) -> &'static str {
    match kind {
        SourcePlanKind::SnapshotExact => "snapshot_exact",
        SourcePlanKind::BoundedHttp => "bounded_http",
        SourcePlanKind::SandboxedRhai => "sandboxed_rhai",
    }
}

pub(super) fn measure_completion_seed(
    contract: &PublicContractArtifact,
    pack: &IntegrationPackArtifact,
    binding: &PrivateBindingArtifact,
    binding_hash: &str,
    effective_limits: SourcePlanLimits,
    effective_token_lifetime_ms: Option<u32>,
    rhai_limits: Option<RhaiWorkerLimits>,
) -> Result<CompletionSeedSizing, SourcePlanCompileError> {
    let operations = &pack.document.spec.plan.operations;
    let credential_operation = pack.document.spec.plan.credential_operation.as_ref();
    let verification_operations = &pack.document.spec.plan.verification_operations;
    let data_permit_operations = match pack.document.spec.plan.kind {
        SourcePlanKind::SnapshotExact => Vec::new(),
        SourcePlanKind::BoundedHttp => {
            if let [verification] = verification_operations.as_slice() {
                let main_operation = operations
                    .first()
                    .ok_or(SourcePlanCompileError::CompilerInvariant)?;
                vec![
                    vec![verification.id.as_str()],
                    vec![main_operation.id.as_str()],
                ]
            } else {
                let steps = pack
                    .document
                    .spec
                    .plan
                    .steps
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>();
                let conditioned = pack
                    .document
                    .spec
                    .plan
                    .step_conditions
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>();
                bounded_actual_call_permit_operations(&steps, &conditioned)
            }
        }
        SourcePlanKind::SandboxedRhai => {
            let limits = rhai_limits.ok_or(SourcePlanCompileError::CompilerInvariant)?;
            let mut callable = operations
                .iter()
                .map(|operation| operation.id.as_str())
                .collect::<Vec<_>>();
            callable.sort_unstable();
            (0..limits.max_calls)
                .map(|_| callable.clone())
                .collect::<Vec<_>>()
        }
    };
    let mut compiled_permit_bindings = Vec::new();
    let mut permit_bindings = Vec::new();
    if credential_operation.is_some() {
        compiled_permit_bindings.push(CompiledPermitBinding {
            kind: CompiledOperationKind::Credential,
            ordinal: 0,
        });
        permit_bindings.push(json!({
            "kind": "credential",
            "ordinal": 0,
        }));
    }
    for (ordinal, _) in data_permit_operations.iter().enumerate() {
        let ordinal =
            u8::try_from(ordinal).map_err(|_| SourcePlanCompileError::CompilerInvariant)?;
        compiled_permit_bindings.push(CompiledPermitBinding {
            kind: CompiledOperationKind::Data,
            ordinal,
        });
        permit_bindings.push(json!({
            "kind": "data",
            "ordinal": ordinal,
        }));
    }
    let consent = &contract.document.spec.authorization.consent;
    let consent_verifier = consent.verifier.as_ref();
    let acquisition_fields = serde_json::to_value(&contract.document.spec.acquisition.fields)
        .map_err(|_| SourcePlanCompileError::CompilerInvariant)?;
    let disclosure_fields = contract
        .document
        .spec
        .output
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let public_outcomes = contract
        .document
        .spec
        .public_behavior
        .outcomes
        .iter()
        .map(|outcome| match outcome {
            super::artifact::OutcomeDocument::Match => "match",
            super::artifact::OutcomeDocument::NoMatch => "no_match",
            super::artifact::OutcomeDocument::Ambiguous => "ambiguous",
        })
        .collect::<Vec<_>>();
    let data_destination_id = binding
        .data_destination_id
        .as_ref()
        .map(super::identifiers::SourceDestinationId::as_str);
    let credential_destination_id = binding
        .credential_destination_id
        .as_ref()
        .map(super::identifiers::SourceDestinationId::as_str);
    let verification_destination_id = binding
        .verification_destination_id
        .as_ref()
        .map(super::identifiers::SourceDestinationId::as_str);
    let credential_reference = binding
        .credential_reference
        .as_ref()
        .map(super::identifiers::CredentialReferenceId::as_str);
    let credential_generation = binding
        .document
        .credential
        .as_ref()
        .map(|credential| credential.generation);
    let template = CompiledCompletionSeedTemplate {
        credential_destination_id: credential_destination_id.map(Into::into),
        data_destination_id: data_destination_id.map(Into::into),
        verification_destination_id: verification_destination_id.map(Into::into),
        credential_reference: credential_reference.map(Into::into),
        credential_generation,
        permit_bindings: compiled_permit_bindings.into_boxed_slice(),
        credential_token_lifetime_ms: effective_token_lifetime_ms,
    };
    let operation_bounds = effective_limits.operation();
    let kind = match pack.document.spec.plan.kind {
        SourcePlanKind::SnapshotExact => "snapshot_exact",
        SourcePlanKind::BoundedHttp => "bounded_http",
        SourcePlanKind::SandboxedRhai => "sandboxed_rhai",
    };
    let acquisition_class = match contract.acquisition_class {
        crate::consultation::AcquisitionClass::SourceProjectedExact => "source_projected_exact",
        crate::consultation::AcquisitionClass::BoundedFullRecord => "bounded_full_record",
        crate::consultation::AcquisitionClass::MaterializedSnapshot => "materialized_snapshot",
    };
    let credential_count = usize::from(credential_operation.is_some());
    if data_permit_operations.len() != usize::from(operation_bounds.max_data_exchanges) {
        return Err(SourcePlanCompileError::CompilerInvariant);
    }
    let source_observed_at_contract =
        match &contract.document.spec.source_provenance.source_observed_at {
            SourceObservedAtDocument::Absent => Value::Null,
            SourceObservedAtDocument::AcquiredRfc3339 { field } => json!({
                "type": "acquired_rfc3339",
                "field": field,
            }),
        };
    let source_revision_contract = match &contract.document.spec.source_provenance.source_revision {
        SourceRevisionDocument::Absent => Value::Null,
        SourceRevisionDocument::AcquiredString { field, max_bytes } => json!({
            "type": "acquired_string",
            "field": field,
            "max_bytes": max_bytes,
        }),
    };
    let mut seed = json!({
        "schema": "registry.relay.consultation-completion-seed/v1",
        "correlation": {"notary_evaluation_id": "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"},
        "profile": {
            "id": contract.identity().id().as_str(),
            "version": contract.identity().version().to_string(),
            "contract_hash": contract.identity().contract_hash().as_str(),
        },
        "integration_pack": {
            "id": pack.identity().id().as_str(),
            "version": pack.identity().version().to_string(),
            "hash": pack.identity().hash().as_str(),
        },
        "private_binding_hash": binding_hash,
        "workload": {
            "id": contract.workload_id.as_str(),
            "tenant_id": binding.tenant.as_str(),
            "registry_id": binding.registry_instance.as_str(),
        },
        "purpose": "",
        "policy": {
            "id": contract.policy_identity.id().as_str(),
            "hash": contract.policy_identity.hash().as_str(),
            "legal_basis_id": contract.legal_basis.as_str(),
            "consent": {
                "required": consent.required,
                "verifier_id": consent_verifier.map(|verifier| verifier.id.as_str()),
                "contract_hash": consent_verifier.map(|verifier| verifier.hash.as_str()),
                "decision": if consent.required { "verified" } else { "not_required" },
            },
            "obligations_digest": format!("sha256:{}", "f".repeat(64)),
        },
        "acquisition": {
            "class": acquisition_class,
            "schema": {
                "type": "acquisition_union",
                "fields": acquisition_fields,
            },
            "disclosure_fields": disclosure_fields,
            "public_outcomes": public_outcomes,
            "provenance_contract": {
                "source_observed_at": source_observed_at_contract,
                "source_revision": source_revision_contract,
                "snapshot_generation": if pack.document.spec.plan.kind == SourcePlanKind::SnapshotExact {
                    "required"
                } else {
                    "absent"
                },
                "snapshot_published_at": if pack.document.spec.plan.kind == SourcePlanKind::SnapshotExact {
                    "required"
                } else {
                    "absent"
                },
            },
        },
        "destinations": {
            "credential_destination_id": credential_destination_id,
            "data_destination_id": data_destination_id,
            "verification_destination_id": verification_destination_id,
        },
        "credential": {
            "reference": credential_reference,
            "generation": credential_generation,
        },
        "dispatch": {
            "plan_kind": kind,
            "permit_bindings": permit_bindings,
        },
        "bounds": {
            "source_matches": operation_bounds.max_source_matches,
            "disclosed_records": operation_bounds.max_disclosed_records,
            "data_exchanges": operation_bounds.max_data_exchanges,
            "credential_exchanges": credential_count,
            "data_destinations": operation_bounds.max_data_destinations,
            "source_bytes": operation_bounds.max_source_bytes,
            "timeout_ms": operation_bounds.timeout_ms,
            "max_in_flight": effective_limits.max_in_flight(),
            "quota_rate_per_minute": effective_limits.quota_per_minute(),
            "quota_burst": effective_limits.quota_burst(),
            "public_response_bytes": effective_limits.max_public_response_bytes(),
            "credential_token_lifetime_ms": effective_token_lifetime_ms,
        },
        "request_digest": format!("sha256:{}", "f".repeat(64)),
        "authorization_context_digest": format!("sha256:{}", "f".repeat(64)),
        "execution_plan_digest": format!("sha256:{}", "f".repeat(64)),
    });

    let mut maximum_seed = None::<(usize, Value)>;
    let mut completion_audit_canonical_bytes_max = 0;
    for purpose in &contract.purposes {
        seed["purpose"] = Value::String(purpose.as_str().to_owned());
        let canonical =
            canonicalize_json(&seed).map_err(|_| SourcePlanCompileError::CompilerInvariant)?;
        if maximum_seed
            .as_ref()
            .is_none_or(|(size, _)| canonical.len() > *size)
        {
            maximum_seed = Some((canonical.len(), seed.clone()));
        }
        completion_audit_canonical_bytes_max =
            completion_audit_canonical_bytes_max.max(measure_completion_audit_payload(
                &seed,
                &data_permit_operations,
                credential_operation.map(|operation| operation.id.as_str()),
            )?);
    }
    let maximum_seed = maximum_seed.ok_or(SourcePlanCompileError::CompilerInvariant)?;
    let canonical_bytes_max = maximum_seed.0;
    #[cfg(test)]
    let canonical_value_max = maximum_seed.1;
    Ok(CompletionSeedSizing {
        canonical_bytes_max,
        completion_audit_canonical_bytes_max,
        template,
        #[cfg(test)]
        canonical_value_max,
    })
}

/// Bind Bounded HTTP permits to monotonic actual-call positions, not fixed
/// step positions. A conditioned earlier step may be skipped while a later
/// step executes, so each position carries the exact safe operation union that
/// can occupy it. The executor still proves the reviewed condition and
/// dependency before selecting one member of that union.
pub(super) fn bounded_actual_call_permit_operations<'a>(
    steps: &[&'a str],
    conditioned: &BTreeSet<&str>,
) -> Vec<Vec<&'a str>> {
    let mut permits = vec![Vec::new(); steps.len()];
    let mut required_predecessors = 0_usize;
    for (step_index, operation) in steps.iter().copied().enumerate() {
        for permit in &mut permits[required_predecessors..=step_index] {
            permit.push(operation);
        }
        if !conditioned.contains(operation) {
            required_predecessors += 1;
        }
    }
    for permit in &mut permits {
        permit.sort_unstable();
        permit.dedup();
    }
    permits
}

fn measure_completion_audit_payload(
    seed: &Value,
    data_permit_operations: &[Vec<&str>],
    credential_operation: Option<&str>,
) -> Result<usize, SourcePlanCompileError> {
    let mut permit_evidence = Vec::new();
    let mut actual_path = Vec::new();
    if let Some(operation) = credential_operation {
        permit_evidence.push(json!({
            "kind": "credential",
            "ordinal": 0,
            "operation_id": operation,
            "dispatched_at_unix_us": 9_007_199_254_740_991_i64,
        }));
        actual_path.push(json!({
            "kind": "credential",
            "ordinal": 0,
            "operation_id": operation,
        }));
    }
    for (ordinal, allowed) in data_permit_operations.iter().enumerate() {
        let operation = allowed
            .iter()
            .max_by_key(|operation| operation.len())
            .copied()
            .ok_or(SourcePlanCompileError::CompilerInvariant)?;
        permit_evidence.push(json!({
            "kind": "data",
            "ordinal": ordinal,
            "operation_id": operation,
            "dispatched_at_unix_us": 9_007_199_254_740_991_i64,
        }));
        actual_path.push(json!({
            "kind": "data",
            "ordinal": ordinal,
            "operation_id": operation,
        }));
    }
    let commitment = "x".repeat(1_024);
    let is_snapshot = seed["acquisition"]["class"] == "materialized_snapshot";
    let public_outcome = seed["acquisition"]["public_outcomes"]
        .as_array()
        .and_then(|outcomes| outcomes.last())
        .and_then(Value::as_str)
        .ok_or(SourcePlanCompileError::CompilerInvariant)?;
    let source_observed_at = seed["acquisition"]["provenance_contract"]["source_observed_at"]
        .is_object()
        .then_some(9_007_199_254_740_991_i64);
    let source_revision = seed["acquisition"]["provenance_contract"]["source_revision"]
        .get("max_bytes")
        .and_then(Value::as_u64)
        .map(|max_bytes| "x".repeat(usize::try_from(max_bytes).unwrap_or(usize::MAX)));
    let payload = json!({
        "attempt_event": {
            "envelope_id": "7ZZZZZZZZZZZZZZZZZZZZZZZZZ",
            "chain_hash": format!("registry-audit-chain-v1:{}", "f".repeat(64)),
        },
        "completion_seed": seed,
        "commitment_key_id": "k".repeat(96),
        "subject_handle": commitment,
        "input_commitment": "x".repeat(1_024),
        "predicate_commitment": "x".repeat(1_024),
        "consent_evidence_commitment": "x".repeat(1_024),
        "outcome": "known_complete",
        "permit_evidence": permit_evidence,
        "completion_facts": {
            "schema": "registry.relay.consultation-completion-facts/v1",
            "execution_result": {
                "class": "public_success",
                "outcome": public_outcome,
            },
            "provenance": {
                "relay_acquired_at_unix_ms": 9_007_199_254_740_991_i64,
                "source_observed_at_unix_ms": source_observed_at,
                "source_revision": source_revision,
                "snapshot_generation": is_snapshot.then_some("7ZZZZZZZZZZZZZZZZZZZZZZZZZ"),
                "snapshot_published_at_unix_ms": is_snapshot
                    .then_some(9_007_199_254_740_991_i64),
            },
            "actual_credential_exchanges": usize::from(credential_operation.is_some()),
            "actual_data_exchanges": data_permit_operations.len(),
            "actual_path": actual_path,
        },
    });
    validate_completion_audit_payload(payload)
}

fn validate_completion_audit_payload(payload: Value) -> Result<usize, SourcePlanCompileError> {
    let canonical_bytes = canonicalize_json(&payload)
        .map(|canonical| canonical.len())
        .map_err(|_| SourcePlanCompileError::CompilerInvariant)?;
    let operation_id = DurableAuditOperationId::parse("7ZZZZZZZZZZZZZZZZZZZZZZZZZ")
        .map_err(|_| SourcePlanCompileError::CompilerInvariant)?;
    DurableAuditWrite::new(
        DurableAuditStreamKind::Consultation,
        operation_id,
        DurableAuditPhase::Completion,
        payload,
    )
    .map_err(|_| SourcePlanCompileError::CompletionAuditTooLarge)?;
    Ok(canonical_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_seed_and_audit_caps_leave_bounded_pseudonym_overhead() {
        const {
            assert!(
                super::super::runtime_profile::MAX_COMPLETION_SEED_CANONICAL_BYTES_V1 + 8 * 1_024
                    < MAX_COMPLETION_AUDIT_CANONICAL_BYTES_V1
            );
        }
    }

    #[test]
    fn startup_audit_sizing_uses_the_authoritative_conservative_runtime_bound() {
        // `DurableAuditWrite` budgets every string for worst-case JSON escaping.
        // This payload is therefore near its authoritative bound even though
        // its all-ASCII canonical representation is much smaller.
        let maximum_ascii_bytes = (MAX_COMPLETION_AUDIT_CANONICAL_BYTES_V1 - 38) / 6;
        let accepted = json!({"value": "x".repeat(maximum_ascii_bytes)});
        let canonical_bytes = validate_completion_audit_payload(accepted)
            .expect("exact conservative maximum is accepted at startup");
        assert!(canonical_bytes < MAX_COMPLETION_AUDIT_CANONICAL_BYTES_V1);

        let rejected = json!({"value": "x".repeat(maximum_ascii_bytes + 1)});
        assert_eq!(
            validate_completion_audit_payload(rejected),
            Err(SourcePlanCompileError::CompletionAuditTooLarge)
        );
    }

    #[test]
    fn exact_canonical_and_conservative_string_winners_can_differ() {
        let canonical_winner = "\"".repeat(200);
        let conservative_winner = "a".repeat(256);
        assert!(
            canonicalize_json(&json!({"purpose": canonical_winner}))
                .expect("canonical payload")
                .len()
                > canonicalize_json(&json!({"purpose": conservative_winner}))
                    .expect("canonical payload")
                    .len()
        );

        let accepts = |padding: usize, purpose: &str| {
            validate_completion_audit_payload(json!({
                "padding": "x".repeat(padding),
                "purpose": purpose,
            }))
            .is_ok()
        };
        let mut low = 0;
        let mut high = MAX_COMPLETION_AUDIT_CANONICAL_BYTES_V1 / 6;
        while low < high {
            let midpoint = low + (high - low).div_ceil(2);
            if accepts(midpoint, &canonical_winner) {
                low = midpoint;
            } else {
                high = midpoint - 1;
            }
        }
        assert!(accepts(low, &canonical_winner));
        assert!(
            !accepts(low, &conservative_winner),
            "the longer raw purpose must win the authoritative conservative bound"
        );
    }
}
