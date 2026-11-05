// SPDX-License-Identifier: Apache-2.0

//! GovStack protocol targets hosted by the Adapter facade.

use std::collections::BTreeMap;
use std::path::Path;

use registry_adapter_core::{AdapterPack, AdapterProfile, AdapterProject, ProfileOrigin};
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
        let has_writable_companion = write.collections.iter().any(|collection| {
            collection.update.as_ref().is_some_and(|update| {
                project
                    .bindings
                    .get(update.companion_read.as_str())
                    .is_some_and(|binding| {
                        binding.record_type == collection.record_type
                            && binding.operation.as_str() == "writable-read"
                    })
            })
        });
        if has_writable_companion {
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
    let mut profile: AdapterProfile =
        serde_json::from_value(value).expect("the maintained unified GovStack profile is valid");
    profile.origin = ProfileOrigin::BuiltInGovStack;
    profile
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

pub(super) fn target_identity(
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
    fn the_composed_profile_keeps_the_built_in_marker() {
        let project: AdapterProject = serde_json::from_value(json!({
            "project": {"id": "read-only", "version": "1"},
            "pack": {"id": "source", "version": "1", "digest": "sha256:678260a56715cba21db1f0687e5a2c5e5efb2ea0b8eea687b5f3ee8723c5f6c9"},
            "recordTypes": []
        }))
        .expect("read-only project");
        assert!(built_in_profile(&project).is_govstack_consultation());
    }

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
            "recordTypes": [{"name": "people", "fields": []}],
            "bindings": [{
                "id": "people-read", "operation": "writable-read",
                "recordType": "people", "route": "read", "maximumUpstreamCalls": 1
            }]
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

    #[test]
    fn mixed_collections_select_and_compile_each_exact_companion_read() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let project_path = root.join("products/adapter/examples/breg-govstack/project.yaml");
        let pack_path = root.join("products/adapter/packs/breg-records/pack.yaml");
        let (project, _): (AdapterProject, _) = crate::engine::load::read_artifact(
            &project_path,
            registry_adapter_core::ADAPTER_PROJECT_KIND,
            registry_adapter_core::ADAPTER_PROJECT_API_VERSION,
        )
        .expect("the maintained project reads");
        let (pack, _): (AdapterPack, _) = crate::engine::load::read_artifact(
            &pack_path,
            registry_adapter_core::ADAPTER_PACK_KIND,
            registry_adapter_core::ADAPTER_PACK_API_VERSION,
        )
        .expect("the maintained pack reads");
        let mut value = serde_json::to_value(project).expect("the project serializes");
        value["write"]["collections"]
            .as_array_mut()
            .expect("Write collections")
            .push(json!({
                "recordType": "permits",
                "registry": "https://registry.example/registries/permits",
                "view": "permit-public",
                "readDataSchema": "contact-public",
                "update": {
                    "inputSchema": "contact-update",
                    "companionRead": "permits-writable-read"
                }
            }));
        value["recordTypes"]
            .as_array_mut()
            .expect("record types")
            .push(json!({"name": "permits", "fields": []}));
        value["templatedRoutes"]
            .as_array_mut()
            .expect("templated routes")
            .extend([
                json!({
                    "routeTemplate": "read-record",
                    "routeId": "breg-permit-read",
                    "parameters": {
                        "record-route": "contacts",
                        "access-profile": "directory-editor"
                    }
                }),
                json!({
                    "routeTemplate": "update-record",
                    "routeId": "breg-permit-update",
                    "parameters": {
                        "record-route": "contacts",
                        "access-profile": "directory-editor"
                    }
                }),
            ]);
        value["bindings"].as_array_mut().expect("bindings").extend([
            json!({
                "id": "permits-writable-read",
                "operation": "writable-read",
                "recordType": "permits",
                "route": "breg-permit-read",
                "maximumUpstreamCalls": 1
            }),
            json!({
                "id": "permits-update",
                "operation": "update",
                "recordType": "permits",
                "route": "breg-permit-update",
                "maximumUpstreamCalls": 1
            }),
        ]);
        value["bindingTransforms"]["permits-writable-read"] =
            json!({"script": "contact-transform", "entrypoint": "public_contact"});
        value["bindingTransforms"]["permits-update"] =
            json!({"script": "contact-transform", "entrypoint": "update_contact"});
        for access in value["accessProfiles"]
            .as_array_mut()
            .expect("access profiles")
        {
            access["recordTypes"]
                .as_array_mut()
                .expect("access record types")
                .push(json!("permits"));
            if access["id"] == "records-reader" {
                access["operations"]
                    .as_array_mut()
                    .expect("reader operations")
                    .push(json!("writable-read"));
            }
        }
        let project: AdapterProject =
            serde_json::from_value(value).expect("the mixed project parses");
        let profile = built_in_profile(&project);

        assert!(profile.operations.get("retrieve").is_some());
        assert!(profile.operations.get("writable-read").is_some());
        let findings = registry_adapter_core::check_workspace(&registry_adapter_core::Workspace {
            profile: &profile,
            pack: &pack,
            project: &project,
            runtime: None,
            fixtures: &[],
        });
        assert!(findings.is_empty(), "{findings:?}");
        target_attachment(
            &project,
            &pack,
            project_path.parent().expect("project directory"),
        )
        .expect("the mixed target attaches");

        let schemas = ["contact-public", "contact-create", "contact-update"]
            .into_iter()
            .map(|id| {
                (
                    id.to_owned(),
                    consultation::OpenApiSchema {
                        identity: format!("https://registry.example/schemas/{id}/1"),
                        component: json!({"type": "object", "additionalProperties": false}),
                    },
                )
            })
            .collect();
        let document = consultation::assemble_openapi(&project, &schemas)
            .expect("the mixed contract assembles");
        let contacts = &document["paths"]["/v1/collections/contacts/records/{recordId}"]["get"];
        let permits = &document["paths"]["/v1/collections/permits/records/{recordId}"]["get"];
        assert_eq!(contacts["operationId"], "retrieveContacts");
        assert_eq!(permits["operationId"], "retrievePermits");
        for companion in [contacts, permits] {
            assert_eq!(
                companion["responses"]["200"]["headers"]["ETag"]["required"],
                true
            );
            assert_eq!(
                companion["responses"]["200"]["headers"]["ETag"]["schema"]["pattern"],
                r#"^"[\x21\x23-\x7E]{1,256}"(?![\s\S])"#
            );
        }
        assert_eq!(
            document["paths"]
                .as_object()
                .expect("paths")
                .values()
                .filter(|path| path.get("get").is_some())
                .count(),
            3,
            "two companion reads plus capabilities"
        );
        assert_eq!(
            document["paths"]["/v1/collections/permits/records/{recordId}"]["patch"]
                ["x-govstack-digital-registries-write"]["companionRead"]["operationId"],
            permits["operationId"]
        );
    }
}
