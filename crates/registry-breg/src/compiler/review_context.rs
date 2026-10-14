// SPDX-License-Identifier: Apache-2.0
//! Acyclic schema publication for a compiled Proposal review projection.
use crate::contract::FieldTypeSource;
use crate::diagnostics::Diagnostic;
use crate::model::{CompiledAction, CompiledActionExecution, CompiledEntity, CompiledRegistry};
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
            "review-context fields must retain their compiled input or Record-field binding",
        )
    };
    let mut properties = Map::new();
    let mut classifications = Map::new();
    for (name, projection) in &context.fields {
        let (field_type, required, classification) = match (
            &projection.from_input,
            &projection.from_record,
            &projection.field,
        ) {
            (Some(input), None, None) => {
                let input = action
                    .inputs
                    .iter()
                    .find(|field| &field.id == input)
                    .ok_or_else(&invalid)?;
                (&input.field_type, input.required, input.classification)
            }
            (None, Some(input), Some(field)) => {
                let input = action
                    .inputs
                    .iter()
                    .find(|field| &field.id == input)
                    .ok_or_else(&invalid)?;
                let FieldTypeSource::Reference { target, .. } = &input.field_type else {
                    return Err(invalid());
                };
                let field = entities
                    .get(target)
                    .and_then(|record| record.fields.get(field))
                    .filter(|field| field.encryption.is_none())
                    .ok_or_else(&invalid)?;
                (
                    &field.field_type,
                    input.required && field.required,
                    field.classification.max(input.classification),
                )
            }
            _ => return Err(invalid()),
        };
        properties.insert(
            name.clone(),
            crate::artifacts::field_value_schema(field_type, !required),
        );
        classifications.insert(name.clone(), json!(classification));
    }
    let id = format!(
        "urn:registry:breg:review-context:{}:{}:{}",
        registry_id, action.id, context.id
    );
    // Policy pins and the Action revision depend on this interface downstream.
    // Neither participates in this schema's own revision or file digest.
    let mut schema = json!({
        "$schema":"https://json-schema.org/draft/2020-12/schema", "$id":id,
        "type":"object", "additionalProperties":false,
        "properties":properties, "required":context.fields.keys().collect::<Vec<_>>(),
        "x-registry-review-context":{"registryId":registry_id,"actionId":action.id,"contextId":context.id,"projection":context.fields,"classifications":classifications},
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
