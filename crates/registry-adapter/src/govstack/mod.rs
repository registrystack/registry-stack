// SPDX-License-Identifier: Apache-2.0

//! GovStack protocol targets hosted by the Adapter facade.

use std::collections::BTreeMap;
use std::path::Path;

use registry_adapter_core::{AdapterPack, AdapterProfile, AdapterProject};
use serde_json::{json, Value};

pub mod consultation;
pub(crate) mod correlation;

pub mod write;

/// Compose only the fixed operations selected by this deployment. Authored
/// generic profiles remain unchanged and never call this constructor.
#[must_use]
pub fn built_in_profile(project: &AdapterProject) -> AdapterProfile {
    let mut value = serde_json::to_value(consultation::built_in_profile())
        .expect("the maintained GovStack profile serializes");
    let operations = value["operations"]
        .as_array_mut()
        .expect("the maintained GovStack operations are an array");
    if project.consultation.is_none() {
        operations.clear();
    }
    if let Some(write) = project.write.as_ref() {
        let has_create = write
            .collections
            .iter()
            .any(|collection| collection.create.is_some());
        let has_update = write
            .collections
            .iter()
            .any(|collection| collection.update.is_some());
        if project.consultation.is_none() && has_update {
            operations.push(json!({
                "id":"writable-read","method":"GET",
                "path":"/v1/collections/{collection_id}/records/{record_id}",
                "pathParameters":["collection_id","record_id"],
                "recordTypeParameter":"collection_id","recordIdParameter":"record_id",
                "itemEnvelope":r#"{"recordId":"{{recordId}}","data":{{record}}}"#,
                "responseEnvelope":"{{record}}"
            }));
        }
        if has_create {
            operations.push(json!({
                "id":"create","method":"POST",
                "path":"/v1/collections/{collection_id}/records",
                "pathParameters":["collection_id"],
                "recordTypeParameter":"collection_id","successStatus":201,
                "requestEnvelope":r#"{"data":{{record}}}"#,
                "responseEnvelope":"{{record}}"
            }));
        }
        if has_update {
            operations.push(json!({
                "id":"update","method":"PATCH",
                "path":"/v1/collections/{collection_id}/records/{record_id}",
                "pathParameters":["collection_id","record_id"],
                "recordTypeParameter":"collection_id","recordIdParameter":"record_id",
                "successStatus":204,"requestEnvelope":r#"{"data":{{record}}}"#,
                "responseEnvelope":"{{record}}"
            }));
        }
        compose_write_problems(&mut value);
    }
    serde_json::from_value(value).expect("the maintained unified GovStack profile is valid")
}

fn compose_write_problems(profile: &mut Value) {
    let problems = profile["problems"]
        .as_array_mut()
        .expect("the maintained GovStack problem catalogue is an array");
    for problem in problems.iter_mut() {
        let Some(classes) = problem["classes"].as_array_mut() else {
            continue;
        };
        classes.retain(|class| !matches!(class.as_str(), Some("facade.idempotency-mismatch")));
    }
}

/// Attach the unified fixed GovStack target selected by Consultation, direct
/// Write, or both. Generic profiles bypass this factory in the loader.
pub fn target_attachment(
    project: &AdapterProject,
    pack: &AdapterPack,
    project_directory: &Path,
) -> Result<crate::engine::target::TargetAttachment, crate::engine::load::LoadError> {
    let mut attachment = consultation::target_attachment(project, pack, project_directory)?;
    if project.write.is_none() {
        return Ok(attachment);
    }
    for collection in project
        .write
        .as_ref()
        .expect("Write presence was checked")
        .collections
        .iter()
        .filter(|collection| collection.update.is_some())
    {
        let view = collection
            .view
            .as_deref()
            .or_else(|| {
                project
                    .consultation
                    .as_ref()
                    .and_then(|target| target.collections.get(collection.record_type.as_str()))
                    .map(|collection| collection.view.as_str())
            })
            .ok_or_else(|| {
                crate::engine::load::LoadError::Runtime(
                    "the guarded GovStack Write companion view metadata is unavailable".to_owned(),
                )
            })?;
        if !consultation::valid_view_id(view) {
            return Err(crate::engine::load::LoadError::Runtime(
                "a GovStack view id must start with a lowercase letter and contain only lowercase letters, digits, and hyphens, with at most 128 characters"
                    .to_owned(),
            ));
        }
    }
    write::attachment::attach_operations(
        project,
        pack,
        project_directory,
        &mut attachment.operations,
    )?;
    attachment.profile = built_in_profile(project);
    attachment.identity = target_identity(&attachment.profile, &attachment.operations)?;
    Ok(attachment)
}

fn target_identity(
    profile: &AdapterProfile,
    operations: &BTreeMap<String, crate::engine::target::TargetOperation>,
) -> Result<Vec<u8>, crate::engine::load::LoadError> {
    let identity_operations: Vec<Value> = operations
        .iter()
        .map(|(binding, operation)| match operation {
            crate::engine::target::TargetOperation::Read(operation) => json!({
                "binding": binding,
                "kind": "read",
                "sourceInput": operation.source_input,
                "itemProjection": operation.item_projection,
                "readSupport": operation.read_support,
                "inputSchema": operation.project_input_schema.as_ref().map(|schema| schema.as_value()),
                "outputSchema": operation.project_transform.schema().as_value(),
                "outputTransformClosure": operation.project_transform.closure_digest(),
                "effectivePath": operation.effective_contract.path,
                "effectivePathParameters": operation.effective_contract.path_parameters,
                "effectiveRequest": operation.effective_contract.request_body,
                "effectiveResponse": operation.effective_contract.response_body,
            }),
            crate::engine::target::TargetOperation::Write(operation) => json!({
                "binding": binding,
                "kind": "write",
                "inputSchema": operation.project_input_schema.as_value(),
                "inputTransformClosure": operation.project_input_transform.closure_digest(),
                "writeSupport": operation.write_support,
                "nativeReplay": "exact-keyed-single-post",
                "effectivePath": operation.effective_contract.path,
                "effectivePathParameters": operation.effective_contract.path_parameters,
                "effectiveRequest": operation.effective_contract.request_body,
                "effectiveResponse": operation.effective_contract.response_body,
            }),
        })
        .collect();
    let identity_value = json!({
        "domain": "registry-adapter:host-target:v2",
        "mount": consultation::MOUNT_PATH,
        "profile": profile,
        "operations": identity_operations,
    });
    registry_platform_canonical_json::canonicalize_json(&identity_value).map_err(|_| {
        crate::engine::load::LoadError::Runtime(
            "the fixed GovStack target identity could not be serialized".to_owned(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_only_profile_selects_fixed_create_update_and_companion_read() {
        let project: AdapterProject = serde_json::from_value(json!({
            "project": {"id": "write-only", "version": "1"},
            "write": {"contract": "https://registry.example/contracts/1/openapi.json", "collections": [{
                "recordType": "people", "registry": "https://registry.example/registries/people",
                "view": "person-public", "readDataSchema": "person-public",
                "create": {"inputSchema": "person-create"},
                "update": {"inputSchema": "person-update", "companionRead": "people-read"}
            }]},
            "pack": {"id": "source", "version": "1", "digest": "sha256:678260a56715cba21db1f0687e5a2c5e5efb2ea0b8eea687b5f3ee8723c5f6c9"},
            "recordTypes": [{"name": "people", "fields": []}]
        })).expect("write-only project");
        let profile = built_in_profile(&project);
        assert_eq!(profile.operations.len(), 3);
        assert_eq!(
            profile
                .operations
                .get("create")
                .unwrap()
                .success_status
                .get(),
            201
        );
        assert_eq!(
            profile
                .operations
                .get("update")
                .unwrap()
                .success_status
                .get(),
            204
        );
        assert!(profile.operations.get("writable-read").is_some());
    }
}
