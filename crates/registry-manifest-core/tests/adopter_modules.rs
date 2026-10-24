// SPDX-License-Identifier: Apache-2.0
mod support;
use registry_manifest_core::{
    compile_manifest, render_base_dcat, render_catalog, source_manifest_digest, validate_manifest,
    MetadataManifest,
};
use serde_json::json;

fn manifest(extra: serde_json::Value) -> MetadataManifest {
    let mut value = json!({"schema_version":"registry-manifest/v1","catalog":{"id":"adopter","base_url":"https://registry.example.test","title":"Adopter catalog","publisher":{"name":"Licensing authority"}}});
    value
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    serde_json::from_value(value).expect("static adopter metadata parses")
}

#[test]
fn data_service_reuses_real_dataset_contract() {
    let source = include_str!(
        "../../../products/manifest/profiles/example-multi-dataset/fixtures/metadata.yaml"
    );
    let manifest: MetadataManifest = support::from_yaml(source).unwrap();
    let compiled = compile_manifest(&manifest).unwrap();
    assert!(!compiled
        .data_service("registry-api")
        .unwrap()
        .serves_datasets
        .is_empty());
    assert!(!render_base_dcat(&compiled)["dcat:service"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn worker_has_static_portable_description_without_a_dataset_or_network() {
    let manifest = manifest(
        json!({"modules":[{"id":"renewal-worker","title":"Renewal worker","description":"Prepares renewal reminders.","documentation_url":"https://unreachable.invalid/worker"}]}),
    );
    let compiled = compile_manifest(&manifest).unwrap();
    let catalog = render_catalog(&compiled);
    assert_eq!(catalog["modules"][0]["id"], "renewal-worker");
    assert_eq!(
        catalog["modules"][0]["documentation_url"],
        "https://unreachable.invalid/worker"
    );
    assert_eq!(compiled.datasets().count(), 0);
    assert!(render_base_dcat(&compiled)["dcat:service"]
        .as_array()
        .is_none_or(|items| items.is_empty()));
}

#[test]
fn module_validation_names_invalid_members_and_refuses_live_configuration() {
    let invalid =
        manifest(json!({"modules":[{"id":"bad id","title":"","documentation_url":"relative"}]}));
    let text = format!("{:?}", validate_manifest(&invalid).unwrap_err());
    for path in [
        "modules[0].id",
        "modules[0].title",
        "modules[0].documentation_url",
    ] {
        assert!(text.contains(path), "{text}");
    }
    let mut duplicate = manifest(json!({"modules":[{"id":"worker","title":"Worker"}]}));
    duplicate.modules.push(duplicate.modules[0].clone());
    assert!(validate_manifest(&duplicate).is_err());
    for key in ["health_url", "token", "capabilities"] {
        let value = json!({"schema_version":"registry-manifest/v1","catalog":{"id":"adopter","base_url":"https://registry.example.test","title":"Adopter","publisher":{"name":"Authority"}},"modules":[{"id":"worker","title":"Worker",key:"value"}]});
        assert!(
            serde_json::from_value::<MetadataManifest>(value).is_err(),
            "{key}"
        );
    }
}

#[test]
fn module_documentation_uses_well_formed_http_https_iris() {
    for url in [
        "https://",
        "http://",
        "https://docs.example.test/bad path",
        "https://docs.example.test/<private>",
    ] {
        let source =
            manifest(json!({"modules":[{"id":"worker","title":"Worker","documentation_url":url}]}));
        let errors = validate_manifest(&source).expect_err("malformed module documentation IRI");
        assert!(format!("{errors:?}").contains("modules[0].documentation_url"));
    }
    for url in [
        "https://docs.example.test/worker",
        "HTTP://docs.example.test/worker",
        "https://docs.example.test/é",
    ] {
        let source =
            manifest(json!({"modules":[{"id":"worker","title":"Worker","documentation_url":url}]}));
        assert!(
            validate_manifest(&source).is_ok(),
            "well-formed HTTP(S) IRI"
        );
    }
}

#[test]
fn absent_and_empty_modules_preserve_existing_digests_and_catalogs() {
    let absent = manifest(json!({}));
    let empty = manifest(json!({"modules":[]}));
    assert_eq!(
        source_manifest_digest(&absent).unwrap(),
        source_manifest_digest(&empty).unwrap()
    );
    let absent = compile_manifest(&absent).unwrap();
    let empty = compile_manifest(&empty).unwrap();
    assert_eq!(render_catalog(&absent), render_catalog(&empty));
    assert!(render_catalog(&absent).get("modules").is_none());
    assert_eq!(render_base_dcat(&absent), render_base_dcat(&empty));
}
