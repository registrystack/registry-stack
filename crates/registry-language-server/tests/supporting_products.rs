// SPDX-License-Identifier: Apache-2.0
//! Real-file and protocol coverage for product navigation without runtime dependencies.

mod support;

use registry_language_server::{ProductKind, ProjectIndex};
use serde_json::json;
use std::{fs, path::PathBuf};
use support::{
    file,
    lsp::{uri, LspSession},
    EvidenceProject as Project,
};

fn load(project: &Project, kind: ProductKind) -> ProjectIndex {
    ProjectIndex::load_product(project.root(), kind).expect("product project indexes")
}
fn fixture(relative: &str) -> String {
    fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative),
    )
    .expect("maintained product fixture reads")
}

#[test]
fn maintained_manifest_examples_resolve_their_local_references() {
    for relative in [
        "products/manifest/profiles/example-multi-dataset/fixtures/metadata.yaml",
        "products/manifest/profiles/example-social-benefits/fixtures/metadata.yaml",
        "products/manifest/profiles/example-civil-registration/fixtures/metadata.yaml",
    ] {
        let project = Project::new(&[file("metadata.yaml", &fixture(relative))]);
        let index = load(&project, ProductKind::Manifest);
        assert!(
            index.diagnostics().is_empty(),
            "{relative}: {:?}",
            index.diagnostics()
        );
        assert!(!index
            .document_symbols(&project.path("metadata.yaml"))
            .is_empty());
    }
}

const MANIFEST: &str = r#"schema_version: registry-manifest/v1
catalog: {id: example, title: Example, base_url: 'https://example.test'}
requirements:
  - id: <|requirement|>identity
    evidence_type_lists:
      - id: identity-proof
        evidence_types: [<|evidence-type-use|>identity-certificate]
evidence_types:
  - id: <|evidence-type|>identity-certificate
    proves: [<|requirement-use|>identity]
evaluation_profiles:
  - id: identity-evaluation
    ruleset: <|ruleset|>identity-rules
data_services:
  - id: <|service|>api
    serves_datasets: [<|dataset-use|>first]
distributions:
  - id: snapshot
    dataset: first
    access_service: <|service-use|>api
datasets:
  - id: <|dataset|>first
    title: First
    entities:
      - name: record
        fields:
          - name: <|first-field|>id
            type: string
          - name: status
            type: code
            codelist: <|codelist-use|>statuses
        identifiers:
          - name: <|first-field-use|>id
            kind: local
        relationships:
          - name: link
            target_entity: <|entity-use|>other
            target: ignored-legacy-alias
      - name: <|entity|>other
        fields: []
    evidence_offerings:
      - id: identity-evidence
        evidence_type: identity-certificate
        entity: record
        lookup_keys: [id]
        access:
          kind: registry-evidence
          ruleset: <|ruleset-use|>identity-rules
      - id: external-evidence
        evidence_type: identity-certificate
        entity: record
        lookup_keys: [id]
        access:
          kind: external-provider
          ruleset: <|external-ruleset|>remote-rules
  - id: second
    title: Second
    entities:
      - name: record
        fields:
          - name: <|second-field|>id
            type: string
        identifiers:
          - name: <|second-field-use|>id
            kind: local
codelists:
  - id: <|codelist|>statuses
    scheme_iri: https://example.test/status
    concepts: [{code: active}]
"#;

#[test]
fn manifest_navigation_and_completion_respect_dataset_and_entity_scope() {
    let project = Project::new(&[file("metadata.yaml", MANIFEST)]);
    let index = load(&project, ProductKind::Manifest);
    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
    let path = project.path("metadata.yaml");
    for (reference, definition) in [
        ("service-use", "service"),
        ("dataset-use", "dataset"),
        ("first-field-use", "first-field"),
        ("second-field-use", "second-field"),
        ("entity-use", "entity"),
        ("codelist-use", "codelist"),
        ("evidence-type-use", "evidence-type"),
        ("requirement-use", "requirement"),
        ("ruleset-use", "ruleset"),
    ] {
        let targets = index.definitions_at(&path, project.cursor("metadata.yaml", reference));
        assert_eq!(targets.len(), 1, "{reference}: {targets:?}");
        assert_eq!(
            targets[0].range.start,
            project.cursor("metadata.yaml", definition)
        );
        assert!(index
            .hover_at(&path, project.cursor("metadata.yaml", reference))
            .is_some());
        assert!(index
            .references_at(&path, project.cursor("metadata.yaml", definition), false)
            .iter()
            .any(|location| location.range.start == project.cursor("metadata.yaml", reference)));
    }
    let candidates =
        index.completions_at(&path, project.cursor("metadata.yaml", "second-field-use"));
    assert_eq!(
        candidates
            .iter()
            .map(|value| value.label.as_str())
            .collect::<Vec<_>>(),
        ["id"]
    );
    assert!(index
        .definitions_at(&path, project.cursor("metadata.yaml", "external-ruleset"))
        .is_empty());
    assert!(index
        .completions_at(&path, project.cursor("metadata.yaml", "external-ruleset"))
        .is_empty());
}

const RENDER: &str = r#"apiVersion: id.registrystack.org/formats/render/bundle/v1alpha1
kind: RenderBundle
bundleVersion: 1
documents:
  - id: <|document|>receipt
    version: 1
    entryFile: <|entry|>templates/receipt.typ
    schemaFile: <|schema|>schemas/receipt.json
    labels: [<|label|>en]
"#;
fn render_project() -> Project {
    Project::new(&[
        file("manifest.yaml", RENDER),
        file("templates/receipt.typ", "#text(\"Receipt\")"),
        file("schemas/receipt.json", "{\"type\":\"object\"}"),
        file("labels/en.yaml", "title: Receipt\n"),
    ])
}

#[test]
fn render_navigates_templates_schemas_and_transformed_locale_paths() {
    let project = render_project();
    let index = load(&project, ProductKind::Render);
    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
    for (cursor, target) in [
        ("entry", "templates/receipt.typ"),
        ("schema", "schemas/receipt.json"),
        ("label", "labels/en.yaml"),
    ] {
        let definitions = index.definitions_at(
            &project.path("manifest.yaml"),
            project.cursor("manifest.yaml", cursor),
        );
        assert_eq!(definitions.len(), 1, "{cursor}");
        assert_eq!(definitions[0].path, project.path(target));
        let completions = index.completions_at(
            &project.path("manifest.yaml"),
            project.cursor("manifest.yaml", cursor),
        );
        assert!(completions
            .iter()
            .any(|candidate| candidate.label == if cursor == "label" { "en" } else { target }));
    }
}

#[test]
fn discovery_indexes_mapping_symbols_without_claiming_remote_evidence_types() {
    let first = fixture("products/discovery/fixtures/project/mappings/adult-status.yaml");
    let second = first
        .replace(
            "urn:example:mapping:adult-status",
            "urn:example:mapping:other-region",
        )
        .replace(
            "jurisdiction: urn:example:jurisdiction",
            "jurisdiction: urn:example:other-region",
        );
    let project = Project::new(&[
        file(
            "origins.yaml",
            &fixture("products/discovery/fixtures/project/origins.yaml"),
        ),
        file("mappings/adult.yaml", &first),
        file("mappings/other.yml", &second),
    ]);
    let index = load(&project, ProductKind::Discovery);
    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
    assert_eq!(
        index.document_symbols(&project.path("origins.yaml")).len(),
        1
    );
    assert!(index
        .document_symbols(&project.path("mappings/adult.yaml"))
        .iter()
        .any(|symbol| symbol.name == "urn:example:mapping:adult-status"));
    assert!(index
        .document_symbols(&project.path("mappings/other.yml"))
        .iter()
        .any(|symbol| symbol.name == "urn:example:mapping:other-region"));
}

const DELIVERY: &str = r#"version: 1
credentialIssuer: https://issuer.example.test
listener: {address: 127.0.0.1, port: 8081}
evidence: {baseUrl: 'https://evidence.example.test'}
tokenClient:
  tokenEndpoint: https://identity.example.test/token
  clientId: delivery
  privateKeyFile: <|key|>private-key.yaml
offers:
  issuer: https://identity.example.test
  jwksUri: https://identity.example.test/jwks
  audiences: [delivery]
"#;
fn delivery_project() -> Project {
    Project::new(&[
        file(
            ".registry-stack-editor/project.json",
            r#"{"product":"evidence-oid4vci","document":"config/wallet.yaml"}"#,
        ),
        file("config/wallet.yaml", DELIVERY),
        // Invalid YAML exposes accidental parsing. Key bytes must never enter the index,
        // even when the key filename ends with a supported YAML extension.
        file("config/private-key.yaml", "[not: {valid: yaml"),
    ])
}

#[test]
fn wallet_delivery_uses_config_relative_paths_without_indexing_key_bytes() {
    let project = delivery_project();
    let index = load(&project, ProductKind::EvidenceOid4vci);
    let definitions = index.definitions_at(
        &project.path("config/wallet.yaml"),
        project.cursor("config/wallet.yaml", "key"),
    );
    assert_eq!(definitions.len(), 1);
    assert_eq!(definitions[0].path, project.path("config/private-key.yaml"));
    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
    assert!(index
        .document_symbols(&project.path("config/private-key.yaml"))
        .iter()
        .all(|symbol| symbol.location.range.start.line == 0));
}

#[test]
fn wallet_key_navigation_normalizes_contained_parent_paths() {
    let project = Project::new(&[
        file(
            ".registry-stack-editor/project.json",
            r#"{"product":"evidence-oid4vci","document":"config/wallet.yaml"}"#,
        ),
        file(
            "config/wallet.yaml",
            &DELIVERY.replace("private-key.yaml", "../keys/private-key.yaml"),
        ),
        file("keys/private-key.yaml", "[not: {valid: yaml"),
    ]);
    let index = load(&project, ProductKind::EvidenceOid4vci);
    let definitions = index.definitions_at(
        &project.path("config/wallet.yaml"),
        project.cursor("config/wallet.yaml", "key"),
    );
    assert_eq!(definitions.len(), 1);
    assert_eq!(definitions[0].path, project.path("keys/private-key.yaml"));
    assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());

    let escaped = Project::new(&[
        file(
            ".registry-stack-editor/project.json",
            r#"{"product":"evidence-oid4vci","document":"config/wallet.yaml"}"#,
        ),
        file(
            "config/wallet.yaml",
            &DELIVERY.replace("private-key.yaml", "../../outside-private-key.yaml"),
        ),
    ]);
    let index = load(&escaped, ProductKind::EvidenceOid4vci);
    assert!(index
        .definitions_at(
            &escaped.path("config/wallet.yaml"),
            escaped.cursor("config/wallet.yaml", "key")
        )
        .is_empty());
}

#[tokio::test]
async fn every_supporting_product_is_discovered_and_exposes_symbols_over_the_protocol() {
    let manifest = Project::new(&[file("metadata.yaml", MANIFEST)]);
    let render = render_project();
    let delivery = delivery_project();
    let discovery = Project::new(&[file(
        "origins.yaml",
        &fixture("products/discovery/fixtures/project/origins.yaml"),
    )]);
    for (project, document, expected) in [
        (&manifest, "metadata.yaml", "snapshot"),
        (&render, "manifest.yaml", "receipt"),
        (&delivery, "config/wallet.yaml", "tokenClient"),
        (&discovery, "origins.yaml", "example-evidence"),
    ] {
        let path = project.path(document);
        let mut session = LspSession::start();
        session.initialize(project.root()).await;
        session
            .open(&path, &fs::read_to_string(&path).unwrap(), 1)
            .await;
        let symbols = session
            .request(
                "textDocument/documentSymbol",
                json!({"textDocument":{"uri":uri(&path)}}),
            )
            .await;
        assert!(
            symbols
                .as_array()
                .unwrap()
                .iter()
                .any(|symbol| symbol["name"] == expected),
            "{document}: {symbols}"
        );
    }
}

#[tokio::test]
async fn render_unsaved_reference_and_external_file_changes_refresh_navigation() {
    let project = render_project();
    let path = project.path("manifest.yaml");
    let mut session = LspSession::start();
    session.initialize(project.root()).await;
    let original = fs::read_to_string(&path).unwrap();
    session.open(&path, &original, 1).await;
    let request = json!({"textDocument":{"uri":uri(&path)},"position":project.cursor("manifest.yaml", "entry")});
    let initial = session
        .request("textDocument/definition", request.clone())
        .await;
    assert_eq!(
        initial[0]["uri"],
        uri(&project.path("templates/receipt.typ"))
    );
    session.notify("textDocument/didChange", json!({"textDocument":{"uri":uri(&path),"version":2},"contentChanges":[{"text":original.replace("templates/receipt.typ", "templates/corrected.typ")}]})).await;
    let missing = session
        .request("textDocument/definition", request.clone())
        .await;
    assert!(missing.is_null() || missing.as_array().is_some_and(Vec::is_empty));
    fs::write(
        project.path("templates/corrected.typ"),
        "#text(\"Corrected\")",
    )
    .unwrap();
    session
        .notify(
            "workspace/didChangeWatchedFiles",
            json!({"changes":[{"uri":uri(&project.path("templates/corrected.typ")),"type":1}]}),
        )
        .await;
    let updated = session.request("textDocument/definition", request).await;
    assert_eq!(
        updated[0]["uri"],
        uri(&project.path("templates/corrected.typ"))
    );
}

#[cfg(unix)]
#[test]
fn navigation_never_follows_a_secret_symlink_outside_the_product_root() {
    let project = delivery_project();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("key"), "not editor content").unwrap();
    fs::remove_file(project.path("config/private-key.yaml")).unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("key"),
        project.path("config/private-key.yaml"),
    )
    .unwrap();
    let index = load(&project, ProductKind::EvidenceOid4vci);
    assert!(index
        .definitions_at(
            &project.path("config/wallet.yaml"),
            project.cursor("config/wallet.yaml", "key")
        )
        .is_empty());
}
