// SPDX-License-Identifier: Apache-2.0

//! Fixed GovStack direct Write attachment.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use registry_adapter_core::{AdapterPack, AdapterProject, HttpMethod, SourceWriteSupport};
use serde::Serialize;
use serde_json::{json, Value};

use crate::engine::load::LoadError;
use crate::engine::target::{
    EffectiveContractOperation, SourceNativeReplayPlan, TargetOperation, TargetWriteOperation,
};

use super::super::consultation::{MAXIMUM_RECORD_ID_CHARACTERS, MOUNT_PATH};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WriteCapability {
    Create,
    Update,
}

impl WriteCapability {
    #[must_use]
    pub const fn binding_operation(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
        }
    }

    #[must_use]
    pub const fn method(self) -> HttpMethod {
        match self {
            Self::Create => HttpMethod::Post,
            Self::Update => HttpMethod::Patch,
        }
    }

    #[must_use]
    pub const fn success_status(self) -> u16 {
        match self {
            Self::Create => 201,
            Self::Update => 204,
        }
    }

    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::Create => "/v1/collections/{collectionId}/records",
            Self::Update => "/v1/collections/{collectionId}/records/{recordId}",
        }
    }

    #[must_use]
    pub fn from_binding_operation(operation: &str) -> Option<Self> {
        match operation {
            "create" => Some(Self::Create),
            "update" => Some(Self::Update),
            _ => None,
        }
    }

    #[must_use]
    pub fn operation_id(self, collection: &str) -> String {
        let mut id = self.binding_operation().to_owned();
        for part in collection.split(['-', '_']).filter(|part| !part.is_empty()) {
            let mut characters = part.chars();
            if let Some(first) = characters.next() {
                id.extend(first.to_uppercase());
                id.extend(characters);
            }
        }
        id
    }
}

pub(crate) fn attach_operations(
    project: &AdapterProject,
    pack: &AdapterPack,
    project_directory: &Path,
    operations: &mut BTreeMap<String, TargetOperation>,
) -> Result<(), LoadError> {
    let Some(write) = project.write.as_ref() else {
        return Ok(());
    };
    for binding in project.bindings.iter() {
        let Some(capability) = WriteCapability::from_binding_operation(binding.operation.as_str())
        else {
            continue;
        };
        if !crate::govstack::consultation::valid_collection_id(binding.record_type.as_str()) {
            return Err(runtime(
                "a GovStack collection id must start with a lowercase letter and contain only lowercase letters, digits, and hyphens, with at most 128 characters",
            ));
        }
        let Some(collection) = write.collections.get(binding.record_type.as_str()) else {
            continue;
        };
        let input_schema_id = match capability {
            WriteCapability::Create => collection
                .create
                .as_ref()
                .map(|operation| operation.input_schema.as_str()),
            WriteCapability::Update => collection
                .update
                .as_ref()
                .map(|operation| operation.input_schema.as_str()),
        };
        let Some(input_schema_id) = input_schema_id else {
            continue;
        };
        let declared_schema = project
            .artifacts
            .schemas
            .get(input_schema_id)
            .ok_or_else(|| runtime("a Write input schema is unavailable"))?;
        let input_schema = Arc::new(
            crate::engine::project_transform::compile_project_schema_from_directory(
                declared_schema,
                project_directory,
            )
            .map_err(|_| runtime("a Write input schema was refused"))?,
        );
        let input_transform = Arc::new(
            crate::engine::inbound_transform::CompiledProjectInputTransform::compile_from_directory(
                project,
                binding.id.as_str(),
                project_directory,
            )
            .map_err(|_| runtime("a Write input transformation was refused"))?,
        );
        let templated = project
            .templated_routes
            .get(binding.route.as_str())
            .ok_or_else(|| runtime("a Write binding must select an instantiated route template"))?;
        let template = pack
            .route_templates
            .get(templated.route_template.as_str())
            .ok_or_else(|| runtime("a Write binding names no reusable source route template"))?;
        let support = template
            .write_support
            .clone()
            .ok_or_else(|| runtime("a Write binding has no declared source write support"))?;
        let compatible = matches!(
            (capability, &support),
            (
                WriteCapability::Create,
                SourceWriteSupport::CreateOne { .. }
            ) | (
                WriteCapability::Update,
                SourceWriteSupport::ConditionalUpdateOne { .. }
            )
        );
        if !compatible {
            return Err(runtime(
                "a Write binding selects incompatible source write support",
            ));
        }
        let path = format!(
            "{}{}",
            MOUNT_PATH,
            capability
                .path()
                .replace("{collectionId}", binding.record_type.as_str())
        );
        let path_parameters = match capability {
            WriteCapability::Create => empty_path_parameters(),
            WriteCapability::Update => record_path_parameters(),
        };
        let effective_contract = EffectiveContractOperation {
            path,
            path_parameters,
            request_body: Some(request_schema(input_schema.as_value(), capability)),
            response_body: response_schema(capability),
        };
        let operation = TargetOperation::Write(TargetWriteOperation {
            project_input_schema: input_schema,
            project_input_transform: input_transform,
            write_support: support,
            native_replay: SourceNativeReplayPlan::ExactKeyedSinglePost,
            effective_contract,
        });
        if operations
            .insert(binding.id.as_str().to_owned(), operation)
            .is_some()
        {
            return Err(runtime(
                "a target binding has duplicate attachment metadata",
            ));
        }
    }
    Ok(())
}

fn runtime(message: &'static str) -> LoadError {
    LoadError::Runtime(message.to_owned())
}

fn empty_path_parameters() -> Value {
    json!({"type": "object", "properties": {}, "required": [], "additionalProperties": false})
}

fn record_path_parameters() -> Value {
    let mut record_id = crate::engine::effective_contract::path_segment_schema();
    record_id["maxLength"] = json!(MAXIMUM_RECORD_ID_CHARACTERS);
    json!({
        "type": "object",
        "properties": {"recordId": record_id},
        "required": ["recordId"],
        "additionalProperties": false
    })
}

fn request_schema(domain_schema: &Value, _capability: WriteCapability) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["data"],
        "properties": {"data": domain_schema}
    })
}

fn response_schema(capability: WriteCapability) -> Value {
    match capability {
        WriteCapability::Create => json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["collectionId", "recordId", "etag"],
            "properties": {
                "collectionId": {"type": "string", "minLength": 1, "maxLength": 128},
                "recordId": {"type": "string", "minLength": 1, "maxLength": MAXIMUM_RECORD_ID_CHARACTERS},
                "etag": {"type": "string", "minLength": 3, "maxLength": 258}
            }
        }),
        WriteCapability::Update => Value::Bool(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_create_receipt_allows_every_collection_id_the_contract_allows() {
        let schema = response_schema(WriteCapability::Create);
        assert_eq!(schema["properties"]["collectionId"]["maxLength"], 128);
        let longest = format!("a{}", "b".repeat(127));
        assert!(crate::govstack::consultation::valid_collection_id(&longest));
        assert_eq!(longest.chars().count(), 128);
    }

    #[test]
    fn write_request_schemas_wrap_only_domain_data() {
        let schema = json!({"type": "object", "properties": {"name": {"type": "string"}}});
        assert_eq!(
            request_schema(&schema, WriteCapability::Create),
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["data"],
                "properties": {"data": schema}
            })
        );
        assert_eq!(
            request_schema(&schema, WriteCapability::Update)["properties"]["data"],
            schema
        );
    }

    #[test]
    fn fixed_write_contract_is_synchronous_create_and_update_only() {
        assert_eq!(
            WriteCapability::Create.method(),
            registry_adapter_core::HttpMethod::Post
        );
        assert_eq!(WriteCapability::Create.success_status(), 201);
        assert_eq!(
            WriteCapability::Update.method(),
            registry_adapter_core::HttpMethod::Patch
        );
        assert_eq!(WriteCapability::Update.success_status(), 204);
    }
}
