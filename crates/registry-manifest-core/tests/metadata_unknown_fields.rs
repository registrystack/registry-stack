// SPDX-License-Identifier: Apache-2.0
//! Ticket #249: a misspelled field name anywhere in a metadata manifest must
//! fail deserialization instead of silently falling back to the field's
//! `#[serde(default)]` empty value.
//!
//! One case per top-level `MetadataManifest` section (matching the sections
//! named in the ticket's failure scenario), one case for a section nested
//! under `catalog` (`standards`), and one case for a typo inside a doubly
//! nested item struct (`datasets[].entities[]`).

use registry_manifest_core::MetadataManifest;

fn minimal_manifest_with(extra: &str) -> String {
    format!(
        r#"
schema_version: registry-manifest/v1
catalog:
  id: unknown-key-regression
  base_url: https://registry.example.test
  title: Unknown Key Regression
  publisher:
    name: Publisher
datasets: []
codelists: []
{extra}
"#
    )
}

#[test]
fn top_level_section_key_typos_are_rejected() {
    let cases = [
        (
            "schema_version",
            "schema_versoin: registry-manifest/v1",
            "schema_versoin",
        ),
        (
            "catalog",
            "catalogg:\n  id: unknown-key-regression-dup\n  base_url: https://registry.example.test\n  title: Unknown Key Regression Dup\n  publisher:\n    name: Publisher",
            "catalogg",
        ),
        ("vocabularies", "vocabularys:\n  ex: https://example.test/", "vocabularys"),
        (
            "profiles",
            "profils:\n  - id: profile-a\n    version: \"1.0.0\"",
            "profils",
        ),
        (
            "federation",
            "federaton:\n  node_id: node-a\n  issuer: https://issuer.example.test\n  jwks_uri: https://issuer.example.test/jwks.json\n  federation_api: https://issuer.example.test/api",
            "federaton",
        ),
        (
            "evaluation_profiles",
            "evaluaton_profiles:\n  - id: eligibility\n    ruleset: eligibility-rules-v1\n    claim_id: eligibility\n    subject_id_type: national_id",
            "evaluaton_profiles",
        ),
        (
            "ecosystem_bindings",
            "ecosytem_bindings:\n  - id: binding-a\n    version: \"1.0.0\"\n    profile: governed-evidence\n    type: governed-evidence",
            "ecosytem_bindings",
        ),
        (
            "requirements",
            "requirments:\n  - id: proof-of-eligibility\n    title: Proof of eligibility",
            "requirments",
        ),
        (
            "evidence_types",
            "evidenc_types:\n  - id: eligibility-evidence\n    title: Eligibility Evidence",
            "evidenc_types",
        ),
        (
            "authorities",
            "authorties:\n  - id: authority-a\n    name: Authority A",
            "authorties",
        ),
        (
            "public_services",
            "public_service:\n  - title: Service A",
            "public_service",
        ),
        (
            "data_services",
            "data_service:\n  - id: service-a\n    title: Service A",
            "data_service",
        ),
        (
            "forms",
            "form:\n  - id: form-a\n    title: Form A\n    service: service-a",
            "form",
        ),
        (
            "datasets",
            "dataset:\n  - id: dataset-a\n    title: Dataset A",
            "dataset",
        ),
        (
            "codelists",
            "codelist:\n  - id: codelist-a\n    scheme_iri: https://example.test/codelist",
            "codelist",
        ),
    ];

    for (section, extra, typo_key) in cases {
        let raw = minimal_manifest_with(extra);
        let error = serde_yaml_ng::from_str::<MetadataManifest>(&raw)
            .expect_err(&format!("{section} typo must be rejected, got: parsed ok"));

        assert!(
            error.to_string().contains(typo_key),
            "{section} typo error should name `{typo_key}`, got: {error}"
        );
    }
}

#[test]
fn catalog_nested_section_key_typo_is_rejected() {
    let raw = r#"
schema_version: registry-manifest/v1
catalog:
  id: unknown-key-regression
  base_url: https://registry.example.test
  title: Unknown Key Regression
  publisher:
    name: Publisher
  standars:
    dcat: "1.0.0"
datasets: []
codelists: []
"#;

    let error = serde_yaml_ng::from_str::<MetadataManifest>(raw)
        .expect_err("typo of catalog.standards must be rejected, got: parsed ok");

    assert!(
        error.to_string().contains("standars"),
        "catalog nested typo error should name `standars`, got: {error}"
    );
}

#[test]
fn nested_item_struct_key_typo_is_rejected() {
    let raw = r#"
schema_version: registry-manifest/v1
catalog:
  id: unknown-key-regression
  base_url: https://registry.example.test
  title: Unknown Key Regression
  publisher:
    name: Publisher
datasets:
  - id: dataset-a
    title: Dataset A
    entities:
      - name: person
        concept_ur: https://example.test/concepts/person
codelists: []
"#;

    let error = serde_yaml_ng::from_str::<MetadataManifest>(raw)
        .expect_err("typo of entities[].concept_uri must be rejected, got: parsed ok");

    assert!(
        error.to_string().contains("concept_ur"),
        "nested item typo error should name `concept_ur`, got: {error}"
    );
}
