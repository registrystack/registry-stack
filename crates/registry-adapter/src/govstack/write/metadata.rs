// SPDX-License-Identifier: Apache-2.0

//! Runtime metadata for the fixed GovStack direct Write target.

use thiserror::Error;

use crate::engine::load::{Loaded, ServedOperation};

use super::attachment::WriteCapability;

#[derive(Clone, Copy, Debug)]
pub(crate) struct CollectionMetadata<'a> {
    pub contract: &'a str,
    pub registry: &'a str,
    pub collection: &'a str,
    pub view: Option<&'a str>,
    pub read_data_schema: Option<&'a str>,
}

#[derive(Debug)]
pub(crate) struct RuntimeWriteMetadata<'a> {
    pub capability: WriteCapability,
    pub registry: &'a str,
    pub collection: &'a str,
    pub view: Option<&'a str>,
    /// Validators bind to the loaded deployment plus the exact companion
    /// read and non-secret runtime semantics, rather than trusting a source
    /// or route name as evidence of equivalence.
    pub closure: String,
    pub companion_read: Option<&'a ServedOperation>,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum MetadataError {
    #[error("the served operation is not one fixed GovStack Write operation")]
    Operation,
    #[error("the Write collection metadata is unavailable")]
    Collection,
    #[error("the guarded Write operation has no served companion read")]
    CompanionRead,
    #[error("the guarded Write operation closure could not be derived")]
    Closure,
}

pub(crate) fn collection_metadata<'a>(
    project: &'a registry_adapter_core::AdapterProject,
    record_type: &str,
) -> Result<CollectionMetadata<'a>, MetadataError> {
    let write = project.write.as_ref().ok_or(MetadataError::Collection)?;
    let collection = write
        .collections
        .get(record_type)
        .ok_or(MetadataError::Collection)?;
    let consultation = project
        .consultation
        .as_ref()
        .and_then(|target| target.collections.get(record_type));
    let registry = collection
        .registry
        .as_deref()
        .or_else(|| consultation.map(|collection| collection.registry.as_str()))
        .ok_or(MetadataError::Collection)?;
    let view = collection
        .view
        .as_ref()
        .map(|view| view.as_str())
        .or_else(|| consultation.map(|collection| collection.view.as_str()));
    if view.is_some_and(|view| !crate::govstack::consultation::valid_view_id(view)) {
        return Err(MetadataError::Collection);
    }
    let read_data_schema = collection
        .read_data_schema
        .as_ref()
        .map(|schema| schema.as_str())
        .or_else(|| consultation.map(|collection| collection.data_schema.as_str()));
    Ok(CollectionMetadata {
        contract: write.contract.as_str(),
        registry,
        collection: collection.record_type.as_str(),
        view,
        read_data_schema,
    })
}

pub(crate) fn resolve_runtime_write<'a>(
    loaded: &'a Loaded,
    operation: &'a ServedOperation,
) -> Result<RuntimeWriteMetadata<'a>, MetadataError> {
    let capability = WriteCapability::from_binding_operation(&operation.operation)
        .ok_or(MetadataError::Operation)?;
    let collection = collection_metadata(&loaded.project, &operation.record_type)?;
    let companion_read = selected_companion_read(loaded, &operation.record_type)?;
    let closure = validator_closure(loaded, &operation.record_type)?;
    Ok(RuntimeWriteMetadata {
        capability,
        registry: collection.registry,
        collection: collection.collection,
        view: collection.view,
        closure,
        companion_read,
    })
}

pub(crate) fn validator_closure(
    loaded: &Loaded,
    record_type: &str,
) -> Result<String, MetadataError> {
    let companion_read = selected_companion_read(loaded, record_type)?;
    let companion = companion_read.map(|served| {
        let target = served.target_contract.as_ref();
        serde_json::json!({
            "binding": served.binding.as_str(),
            "operation": served.operation.as_str(),
            "method": served.method,
            "methodPath": served.method_path.as_str(),
            "recordType": served.record_type.as_str(),
            "route": served.route_id.as_str(),
            "maximumUpstreamCalls": served.maximum_upstream_calls,
            "recordSchema": &served.record_schema,
            "readSupport": served.read_support.as_ref(),
            "sourceInput": served.source_input.as_ref(),
            "itemProjection": served.item_projection.as_ref(),
            "outputTransformClosure": served.project_transform.as_ref().map(|transform| transform.closure_digest()),
            "effectivePath": target.map(|contract| contract.path.as_str()),
            "effectivePathParameters": target.map(|contract| &contract.path_parameters),
            "effectiveRequest": target.and_then(|contract| contract.request_body.as_ref()),
            "effectiveResponse": target.map(|contract| &contract.response_body),
        })
    });
    let runtime = serde_json::json!({
        "id": loaded.runtime.id.as_str(),
        "endpoints": &loaded.runtime.endpoints,
        "outboundTls": &loaded.runtime.outbound_tls,
        "allowedPrivateCidrs": &loaded.runtime.allowed_private_cidrs,
        "listener": &loaded.runtime.listener,
        "oidc": &loaded.runtime.oidc,
        "allowedClients": &loaded.runtime.allowed_clients,
        "audit": &loaded.runtime.audit,
        "idempotency": &loaded.runtime.idempotency,
    });
    let value = serde_json::json!({
        "domain": "registry-adapter:govstack-validator-closure:v1",
        "deployment": loaded.deployment.as_str(),
        "recordType": record_type,
        "runtime": runtime,
        "companionRead": companion,
    });
    let canonical = registry_platform_canonical_json::canonicalize_json(&value)
        .map_err(|_| MetadataError::Closure)?;
    Ok(registry_platform_config::sha256_uri(&canonical))
}

fn selected_companion_read<'a>(
    loaded: &'a Loaded,
    record_type: &str,
) -> Result<Option<&'a ServedOperation>, MetadataError> {
    let write_collection = loaded
        .project
        .write
        .as_ref()
        .and_then(|write| write.collections.get(record_type))
        .ok_or(MetadataError::Collection)?;
    let selected_binding = write_collection
        .update
        .as_ref()
        .map(|update| update.companion_read.as_str());
    let companion = if let Some(binding) = selected_binding {
        loaded
            .served
            .iter()
            .find(|served| served.binding == binding)
    } else {
        loaded.served.iter().find(|served| {
            served.record_type == record_type
                && matches!(served.operation.as_str(), "retrieve" | "writable-read")
        })
    };
    if selected_binding.is_some() && companion.is_none() {
        return Err(MetadataError::CompanionRead);
    }
    Ok(companion)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn collection_metadata_inherits_the_matching_consultation_closure() {
        let project: registry_adapter_core::AdapterProject = serde_json::from_value(json!({
            "project": {"id": "write-metadata", "version": "1"},
            "consultation": {"contract": "https://registry.example/contracts/1/openapi.json", "collections": [{
                "recordType": "people", "registry": "https://registry.example/registries/people",
                "view": "person-public", "dataSchema": "person-public"
            }]},
            "write": {"contract": "https://registry.example/contracts/1/openapi.json", "collections": [{
                "recordType": "people", "create": {"inputSchema": "person-create"}
            }]},
            "pack": {"id": "source", "version": "1", "digest": "sha256:678260a56715cba21db1f0687e5a2c5e5efb2ea0b8eea687b5f3ee8723c5f6c9"},
            "recordTypes": [{"name": "people", "fields": []}]
        })).expect("composite project");

        let metadata = collection_metadata(&project, "people").expect("collection metadata");
        assert_eq!(
            metadata.registry,
            "https://registry.example/registries/people"
        );
        assert_eq!(metadata.view, Some("person-public"));
        assert_eq!(metadata.read_data_schema, Some("person-public"));
    }

    #[test]
    fn collection_metadata_refuses_noncanonical_companion_views() {
        let project: registry_adapter_core::AdapterProject = serde_json::from_value(json!({
            "project": {"id": "write-metadata", "version": "1"},
            "write": {"contract": "https://registry.example/contracts/1/openapi.json", "collections": [{
                "recordType": "people", "registry": "https://registry.example/registries/people",
                "view": "person_public", "readDataSchema": "person-public",
                "update": {"inputSchema": "person-update", "companionRead": "people-read"}
            }]},
            "pack": {"id": "source", "version": "1", "digest": "sha256:678260a56715cba21db1f0687e5a2c5e5efb2ea0b8eea687b5f3ee8723c5f6c9"},
            "recordTypes": [{"name": "people", "fields": []}]
        }))
        .expect("the broader authoring grammar admits the view");

        assert!(matches!(
            collection_metadata(&project, "people"),
            Err(MetadataError::Collection)
        ));
    }
}
