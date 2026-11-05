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
    /// Validators bind to the record shape the companion read serves and the
    /// configured source endpoints, rather than trusting a source or route
    /// name as evidence of equivalence.
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

/// Derive the closure a sealed validator is bound to: what shapes the
/// record a client sees and the source it came from. Access, listener,
/// audit and retention settings are left out, so admitting a client or
/// rotating OIDC configuration keeps outstanding ETags valid.
pub(crate) fn validator_closure(
    loaded: &Loaded,
    record_type: &str,
) -> Result<String, MetadataError> {
    let companion_read = selected_companion_read(loaded, record_type)?;
    let companion = companion_read.map(|served| {
        serde_json::json!({
            "recordSchema": &served.record_schema,
            "itemProjection": served.item_projection.as_ref(),
            "outputTransformClosure": served.project_transform.as_ref().map(|transform| transform.closure_digest()),
            "effectiveResponse": served.target_contract.as_ref().map(|contract| &contract.response_body),
        })
    });
    // The configured base URL of every endpoint the companion read and the
    // collection's writes reach: a sealed native validator from one source
    // is never presented to another.
    let mut sources = std::collections::BTreeMap::new();
    for served in loaded.served.iter().filter(|served| {
        companion_read.is_some_and(|read| std::ptr::eq(read, *served))
            || (served.record_type == record_type
                && WriteCapability::from_binding_operation(&served.operation).is_some())
    }) {
        sources.extend(crate::custody::source_endpoint_bases(loaded, &served.steps));
    }
    let value = serde_json::json!({
        "domain": "registry-adapter:govstack-validator-closure:v2",
        "recordType": record_type,
        "companionRead": companion,
        "sources": sources,
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
        .and_then(|update| update.companion_read.as_deref());
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
    use std::path::{Path, PathBuf};

    fn repository_path(relative: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative)
    }

    fn copy_tree(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).expect("create the project copy");
        for entry in std::fs::read_dir(from).expect("read the project tree") {
            let entry = entry.expect("a project entry");
            let target = to.join(entry.file_name());
            if entry.file_type().expect("entry type").is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), target).expect("copy a project file");
            }
        }
    }

    /// One copy of the maintained BReg GovStack example with an owner-only
    /// source token, so a test can vary the project or the runtime.
    struct Deployment {
        root: tempfile::TempDir,
    }

    impl Deployment {
        fn new() -> Self {
            use std::os::unix::fs::PermissionsExt as _;

            let root = tempfile::tempdir().expect("deployment root");
            copy_tree(
                &repository_path("products/adapter/examples/breg-govstack"),
                &root.path().join("project"),
            );
            let secrets = root.path().join("secrets");
            std::fs::create_dir(&secrets).expect("secret root");
            let token = secrets.join("breg-access-token");
            std::fs::write(&token, "synthetic-source-token").expect("source token");
            std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600))
                .expect("owner-only token");
            Self { root }
        }

        fn project(&self) -> PathBuf {
            self.root.path().join("project")
        }

        /// Rewrite one pinned project artifact and its digest pin.
        fn rewrite_artifact(&self, relative: &str, from: &str, to: &str) {
            use sha2::{Digest as _, Sha256};

            let hex = |bytes: &[u8]| -> String {
                Sha256::digest(bytes)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect()
            };
            let path = self.project().join(relative);
            let before = std::fs::read_to_string(&path).expect("read the artifact");
            assert!(before.contains(from), "{relative} contains {from}");
            let after = before.replacen(from, to, 1);
            std::fs::write(&path, &after).expect("write the artifact");
            let manifest = self.project().join("project.yaml");
            let project = std::fs::read_to_string(&manifest).expect("read the project");
            let pin = format!("sha256:{}", hex(before.as_bytes()));
            assert!(project.contains(&pin), "the project pins {relative}");
            std::fs::write(
                &manifest,
                project.replace(&pin, &format!("sha256:{}", hex(after.as_bytes()))),
            )
            .expect("re-pin the artifact");
        }

        fn closure(&self, base_url: &str, allowed_clients: &str, issuer: &str) -> String {
            let secrets = std::fs::canonicalize(self.root.path().join("secrets"))
                .expect("absolute secret root");
            let runtime = self.root.path().join("runtime.yaml");
            std::fs::write(
                &runtime,
                format!(
                    r#"apiVersion: id.registrystack.org/formats/adapter/runtime/v1alpha1
kind: AdapterRuntimeConfig
id: breg-govstack-closure-test
secretProviders:
  file:
    root: {secrets}
endpoints:
  - endpoint: registry
    baseUrl: {base_url}
    credential:
      type: static-authorization
      tokenRef: secret:file/breg-access-token
listener:
  bind: 127.0.0.1:0
database:
  runtimeUrlRef: secret:env/CLOSURE_TEST_DB_URL
  migrationUrlRef: secret:env/CLOSURE_TEST_DB_URL
oidc:
  issuer: {issuer}
  audience: breg-govstack-closure-test
allowedClients: [{allowed_clients}]
allowedPrivateCidrs: [10.0.0.0/8]
audit:
  retentionDays: 90
idempotency:
  responseRetentionSeconds: 86400
cursorKeyRef: secret:env/CLOSURE_TEST_CURSOR_KEY
"#,
                    secrets = secrets.display()
                ),
            )
            .expect("write the runtime");
            let loaded = crate::engine::load::load_with_target(
                &self.project(),
                None,
                Some(&repository_path(
                    "products/adapter/packs/breg-records/pack.yaml",
                )),
                &runtime,
                crate::govstack::target_attachment,
            )
            .expect("load the BReg GovStack deployment");
            validator_closure(&loaded, "contacts").expect("derive the validator closure")
        }
    }

    #[test]
    fn validator_closure_survives_access_changes_and_binds_the_record_and_its_source() {
        const SOURCE: &str = "https://breg.example.invalid";
        const ISSUER: &str = "https://issuer.example.invalid";
        let deployment = Deployment::new();
        let baseline = deployment.closure(SOURCE, "client-a", ISSUER);
        assert_eq!(baseline, deployment.closure(SOURCE, "client-a", ISSUER));

        assert_eq!(
            baseline,
            deployment.closure(SOURCE, "client-a, client-b", ISSUER),
            "admitting another client keeps outstanding ETags valid"
        );
        assert_eq!(
            baseline,
            deployment.closure(SOURCE, "client-a", "https://issuer-next.example.invalid"),
            "rotating the OIDC configuration keeps outstanding ETags valid"
        );
        assert_ne!(
            baseline,
            deployment.closure("https://breg-other.example.invalid", "client-a", ISSUER),
            "a validator from one source is never presented to another"
        );

        let schema_changed = Deployment::new();
        schema_changed.rewrite_artifact(
            "schemas/contact-public.schema.json",
            r#""maxLength": 160"#,
            r#""maxLength": 120"#,
        );
        assert_ne!(
            baseline,
            schema_changed.closure(SOURCE, "client-a", ISSUER),
            "a record schema change invalidates outstanding ETags"
        );

        let transform_changed = Deployment::new();
        transform_changed.rewrite_artifact(
            "scripts/contact.rhai",
            "let contact = #{name: source.name, email: source.email};",
            "let contact = #{name: source.name, email: source.email.to_lower()};",
        );
        assert_ne!(
            baseline,
            transform_changed.closure(SOURCE, "client-a", ISSUER),
            "an output transform change invalidates outstanding ETags"
        );
    }

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
