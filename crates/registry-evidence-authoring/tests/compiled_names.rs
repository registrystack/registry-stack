//! Stable normalized identifiers and their reference sites use one LocalId
//! grammar. Presentation labels never enter this contract.

#![allow(
    clippy::disallowed_macros,
    reason = "this test target embeds the public canonical fixture; the library performs no I/O"
)]

use registry_evidence_authoring::project;
use registry_platform_yaml::Diagnostic;
use serde_json::{json, Value};

const NORMALIZED_PROJECT: &str =
    include_str!("../../../products/evidence/examples/standalone/evidence.yaml");

fn normalized_document() -> Value {
    let project = project::read_project("evidence.yaml", NORMALIZED_PROJECT.as_bytes())
        .expect("the canonical project reads")
        .value;
    let mut value = serde_json::to_value(project).expect("the canonical project serializes");
    let object = value.as_object_mut().expect("the project is an object");
    object.insert("apiVersion".to_owned(), json!(project::PROJECT_API_VERSION));
    object.insert("kind".to_owned(), json!(project::PROJECT_KIND));
    value
}

fn read_normalized(
    document: &Value,
) -> Result<project::EvidenceProject, registry_platform_yaml::Report> {
    let text = serde_norway::to_string(document).expect("the test project renders");
    project::read_project("evidence.yaml", text.as_bytes()).map(|decoded| decoded.value)
}

fn normalized_refusal(document: &Value) -> Diagnostic {
    let report = read_normalized(document).unwrap_err();
    assert_eq!(report.diagnostics().len(), 1, "{report:?}");
    report.diagnostics()[0].clone()
}

#[test]
fn project_id_uses_the_complete_local_id_bound() {
    let mut document = normalized_document();
    document["id"] = json!("a".repeat(64));
    assert!(read_normalized(&document).is_ok());

    document["id"] = json!("a".repeat(65));
    let diagnostic = normalized_refusal(&document);
    assert_eq!(diagnostic.path, "/id");
    assert_eq!(diagnostic.code, "config.invalid-value");
}

#[test]
fn function_id_and_presentation_label_are_separate() {
    let mut document = normalized_document();
    document["functions"].as_array_mut().unwrap().push(json!({
        "id": "a".repeat(64),
        "label": "Friendly label with spaces and punctuation.",
        "interface": "source-prepare/v1",
        "source": "functions/unused-prepare.rhai"
    }));
    assert!(read_normalized(&document).is_ok());

    document["functions"]
        .as_array_mut()
        .unwrap()
        .last_mut()
        .unwrap()["id"] = json!("a".repeat(65));
    let diagnostic = normalized_refusal(&document);
    assert_eq!(diagnostic.path, "/functions/7/id");
}

#[test]
fn selector_profile_keys_use_the_same_local_id_grammar() {
    let mut document = normalized_document();
    let profile = document["selectorProfiles"]
        .as_object_mut()
        .unwrap()
        .remove("record-by-id")
        .unwrap();
    document["selectorProfiles"]
        .as_object_mut()
        .unwrap()
        .insert("record.by.id".to_owned(), profile);
    let diagnostic = normalized_refusal(&document);
    assert_eq!(diagnostic.path, "/selectorProfiles/record.by.id");
}

#[test]
fn source_keys_use_the_same_local_id_grammar() {
    let mut document = normalized_document();
    let source = document["sources"]
        .as_object_mut()
        .unwrap()
        .remove("person-record")
        .unwrap();
    document["sources"]
        .as_object_mut()
        .unwrap()
        .insert("person.record".to_owned(), source);
    let diagnostic = normalized_refusal(&document);
    assert_eq!(diagnostic.path, "/sources/person.record");
}

#[test]
fn assertion_definition_keys_use_the_same_local_id_grammar() {
    let mut document = normalized_document();
    let definition = document["assertionDefinitions"]
        .as_object_mut()
        .unwrap()
        .remove("adult-status")
        .unwrap();
    document["assertionDefinitions"]
        .as_object_mut()
        .unwrap()
        .insert("adult.status".to_owned(), definition);
    let diagnostic = normalized_refusal(&document);
    assert_eq!(diagnostic.path, "/assertionDefinitions/adult.status");
}

#[test]
fn selector_references_are_typed_local_ids_at_the_reference_site() {
    let mut document = normalized_document();
    document["assertionDefinitions"]["adult-status"]["subjects"][0]["selectors"][0] =
        json!("record.by.id");
    let diagnostic = normalized_refusal(&document);
    assert_eq!(
        diagnostic.path,
        "/assertionDefinitions/adult-status/subjects/0/selectors/0"
    );
}

#[test]
fn source_references_are_typed_local_ids_at_the_reference_site() {
    let mut document = normalized_document();
    document["assertionDefinitions"]["adult-status"]["acquisition"]["source"] =
        json!("missing-source");
    let diagnostic = normalized_refusal(&document);
    assert_eq!(
        diagnostic.path,
        "/assertionDefinitions/adult-status/acquisition/source"
    );
}

#[test]
fn definition_keys_keep_the_complete_local_id_bound() {
    let mut document = normalized_document();
    let definition = document["assertionDefinitions"]
        .as_object_mut()
        .unwrap()
        .remove("adult-status")
        .unwrap();
    document["assertionDefinitions"]
        .as_object_mut()
        .unwrap()
        .insert("a".repeat(64), definition);
    assert!(read_normalized(&document).is_ok());
}

#[test]
fn presentation_labels_do_not_rename_stable_ids_or_references() {
    let mut document = normalized_document();
    document["label"] = json!("Standalone Evidence project");
    document["selectorProfiles"]["record-by-id"]["label"] = json!("Record identifier");
    document["sources"]["person-record"]["label"] = json!("Person source");
    document["assertionDefinitions"]["adult-status"]["label"] = json!("Adult status");
    let project = read_normalized(&document).unwrap();
    assert_eq!(project.id.as_str(), "standalone-evidence");
    assert!(project
        .selector_profiles
        .keys()
        .any(|id| id.as_str() == "record-by-id"));
    assert!(project
        .sources
        .keys()
        .any(|id| id.as_str() == "person-record"));
    assert!(project
        .assertion_definitions
        .keys()
        .any(|id| id.as_str() == "adult-status"));
}
