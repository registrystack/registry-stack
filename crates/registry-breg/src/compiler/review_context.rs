// SPDX-License-Identifier: Apache-2.0
//! Acyclic schema publication for a compiled Proposal review projection.
use crate::contract::{FieldTypeSource, ProposalContextValueSource};
use crate::diagnostics::Diagnostic;
use crate::model::{
    CompiledAction, CompiledActionExecution, CompiledEntity, CompiledProposalReview,
    CompiledRegistry,
};
use registry_platform_canonical_json::canonicalize_json;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct CompiledReviewContextSchema {
    pub id: String,
    pub revision: String,
    pub digest: String,
    pub schema: Value,
    /// Exact canonical UTF-8 bytes covered by `digest`.
    pub bytes: Vec<u8>,
}

pub fn compile_schema(
    registry: &CompiledRegistry,
    action: &CompiledAction,
) -> Result<Option<CompiledReviewContextSchema>, Diagnostic> {
    compile_schema_from_parts(registry.registry_id(), registry.entities(), action)
}

pub fn compile_schema_from_parts(
    registry_id: &str,
    entities: &BTreeMap<String, CompiledEntity>,
    action: &CompiledAction,
) -> Result<Option<CompiledReviewContextSchema>, Diagnostic> {
    let CompiledActionExecution::Proposal { proposal } = &action.execution else {
        return Ok(None);
    };
    let Some(context) = &proposal.review_context else {
        return Ok(None);
    };
    let invalid = || {
        Diagnostic::error(
            "breg.proposal.context-schema-invalid",
            format!("actions[id={}].execution.proposal.reviewContext", action.id),
            "review-context fields must retain their compiled input, Record or frozen-change binding",
        )
    };
    let mut properties = Map::new();
    let mut classifications = Map::new();
    let mut bindings = Map::new();
    for (name, projection) in &context.fields {
        let (schema, classification, binding) = match projection {
            ProposalContextValueSource::Input { input } => {
                let input = action
                    .inputs
                    .iter()
                    .find(|field| &field.id == input)
                    .ok_or_else(&invalid)?;
                (
                    crate::artifacts::field_value_schema(&input.field_type, !input.required),
                    input.classification,
                    json!({"kind":"input","input":input.id,"fieldType":input.field_type,"required":input.required}),
                )
            }
            ProposalContextValueSource::Record { input, field } => {
                let input = action
                    .inputs
                    .iter()
                    .find(|field| &field.id == input)
                    .ok_or_else(&invalid)?;
                let FieldTypeSource::Reference { target, .. } = &input.field_type else {
                    return Err(invalid());
                };
                let declared = entities
                    .get(target)
                    .and_then(|record| record.fields.get(field))
                    .filter(|field| field.encryption.is_none())
                    .ok_or_else(&invalid)?;
                (
                    crate::artifacts::field_value_schema(
                        &declared.field_type,
                        !(input.required && declared.required),
                    ),
                    declared.classification.max(input.classification),
                    json!({"kind":"current-record","input":input.id,"recordType":target,"field":field,"fieldType":declared.field_type,"required":input.required && declared.required}),
                )
            }
            ProposalContextValueSource::Changes {
                record_type,
                fields,
            } => {
                let record = entities.get(record_type).ok_or_else(&invalid)?;
                let mut selected = Map::new();
                let mut meanings = Map::new();
                let mut classification = None;
                for field in fields {
                    let declared = record
                        .fields
                        .get(field)
                        .filter(|field| field.encryption.is_none())
                        .ok_or_else(&invalid)?;
                    selected.insert(
                        field.clone(),
                        crate::artifacts::field_value_schema(
                            &declared.field_type,
                            !declared.required,
                        ),
                    );
                    meanings.insert(field.clone(), json!({"fieldType":declared.field_type,"required":declared.required,"classification":declared.classification}));
                    classification = Some(classification.map_or(
                        declared.classification,
                        |prior: crate::contract::Classification| prior.max(declared.classification),
                    ));
                }
                let snapshot = json!({"type":"object","additionalProperties":false,"properties":selected,"required":fields});
                (
                    json!({"type":"array","maxItems":crate::proposal_workflow::MAX_PROPOSAL_TARGETS,
                        "items":{"type":"object","additionalProperties":false,
                            "required":["recordId","operation","before","after"],"properties":{
                                "recordId":{"type":"string","format":"uuid"},
                                "operation":{"type":"string","enum":["create","patch"]},
                                "before":{"anyOf":[snapshot.clone(),{"type":"null"}]},"after":snapshot}}}),
                    classification.ok_or_else(&invalid)?,
                    json!({"kind":"frozen-changes","recordType":record_type,"fields":meanings}),
                )
            }
        };
        properties.insert(name.clone(), schema);
        classifications.insert(name.clone(), json!(classification));
        bindings.insert(name.clone(), binding);
    }
    let id = format!(
        "urn:registry:breg:review-context:{}:{}:{}",
        registry_id, action.id, context.id
    );
    let source_namespace = match &proposal.review {
        CompiledProposalReview::Required { source, .. } => source.as_str(),
        CompiledProposalReview::None => registry_id,
    };
    // Resolve source and reference targets into the meaning revision. A UUID
    // field's JSON shape alone does not say which Record type it identifies.
    // Policy pins and the Action revision depend on this interface downstream;
    // neither participates in this schema's own revision or file digest.
    let mut schema = json!({
        "$schema":"https://json-schema.org/draft/2020-12/schema", "$id":id,
        "type":"object", "additionalProperties":false,
        "properties":properties, "required":context.fields.keys().collect::<Vec<_>>(),
        "x-registry-review-context":{"registryId":registry_id,"sourceNamespace":source_namespace,"actionId":action.id,"contextId":context.id,"projection":context.fields,"bindings":bindings,"classifications":classifications},
    });
    let revision = digest(&canonicalize_json(&schema).map_err(|_| invalid())?);
    schema["x-registry-definition-revision"] = json!(revision);
    let bytes = canonicalize_json(&schema).map_err(|_| invalid())?;
    Ok(Some(CompiledReviewContextSchema {
        id,
        revision,
        digest: digest(&bytes),
        schema,
        bytes,
    }))
}

fn digest(bytes: &[u8]) -> String {
    format!(
        "sha256:{}",
        crate::immediate_actions::hex_lower(&Sha256::digest(bytes))
    )
}
