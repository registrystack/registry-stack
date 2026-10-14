//! Authored fixture grammar and policy-bound expectations use positioned reports.
use registry_casework_core::*;
use serde_json::{json, Value};

fn fixture() -> Value {
    json!({"apiVersion":CASEWORK_FIXTURE_API_VERSION,"kind":CASEWORK_FIXTURE_KIND,"id":"synthetic-review","review":{"policy":"decision","display":{"summary":"Synthetic batch: ready for review","reference":"BATCH/2026-01"}},"expect":{"queue":"decisions","outcomes":["confirmed","rejected"]}})
}
fn project() -> CaseworkProject {
    CaseworkProject::load(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/casework/examples/standalone-decision/casework.yaml"),
    )
    .unwrap()
}
fn refused(value: &Value) -> registry_platform_yaml::Report {
    CaseworkFixture::read("fixture.yaml", &serde_json::to_vec(value).unwrap()).unwrap_err()
}
fn has_path(report: &registry_platform_yaml::Report, path: &str) {
    assert!(
        report.diagnostics().iter().any(|item| item.path == path),
        "{report:?}"
    );
    for item in report.diagnostics() {
        let source = item
            .source
            .as_ref()
            .expect("authored diagnostic has source");
        assert_eq!(source.file, "fixture.yaml");
        assert!(source.line.is_some());
        assert!(source.column.is_some());
    }
}
#[test]
fn fixture_metadata_is_closed_typed_and_positioned() {
    for (pointer, value) in [
        ("/id", json!(null)),
        ("/id", json!(7)),
        ("/id", json!(true)),
        ("/id", json!("")),
        ("/review/policy", json!(7)),
        ("/review/display", json!([])),
        ("/expect/queue", json!(false)),
        ("/expect/outcomes", json!([7])),
    ] {
        let mut document = fixture();
        *document.pointer_mut(pointer).unwrap() = value;
        let report = refused(&document);
        assert!(report.has_errors());
        let expected = if pointer == "/expect/outcomes" {
            "/expect/outcomes/0"
        } else {
            pointer
        };
        has_path(&report, expected);
    }
    let mut document = fixture();
    document["extra"] = json!("PRIVATE_VALUE_CANARY");
    document["review"]["extra"] = json!("PRIVATE_VALUE_CANARY");
    document["expect"]["extra"] = json!("PRIVATE_VALUE_CANARY");
    let report = refused(&document);
    for pointer in ["/extra", "/review/extra", "/expect/extra"] {
        has_path(&report, pointer);
    }
    assert!(!report.to_string().contains("PRIVATE_VALUE_CANARY"));
}
#[test]
fn fixture_expectations_cannot_be_empty_or_repeat_outcomes() {
    for expect in [
        json!({}),
        json!({"queue":"decisions","outcomes":[]}),
        json!({"outcomes":[]}),
    ] {
        let mut document = fixture();
        document["expect"] = expect;
        assert!(refused(&document)
            .diagnostics()
            .iter()
            .any(|item| item.code.starts_with("casework.fixture.")));
    }
    let mut document = fixture();
    document["expect"]["outcomes"] = json!(["confirmed", "confirmed"]);
    has_path(&refused(&document), "/expect/outcomes/1");
    document["expect"] = json!({"queue":"decisions"});
    CaseworkFixture::read("fixture.yaml", &serde_json::to_vec(&document).unwrap()).unwrap();
}
#[test]
fn fixture_envelope_and_substitution_use_the_shared_reader() {
    for bytes in [
        b"".as_slice(),
        b"# comment\n".as_slice(),
        b"id: example\n".as_slice(),
    ] {
        let error = CaseworkFixture::read("fixture.yaml", bytes).unwrap_err();
        assert!(error
            .diagnostics()
            .iter()
            .any(|item| item.code == "config.empty-document"
                || item.code == "config.missing-envelope"));
    }
    for (member, value, code) in [
        ("apiVersion", "other", "config.unsupported-api-version"),
        ("kind", "OtherFixture", "config.wrong-kind"),
        (
            "id",
            "${PRIVATE_FIXTURE_CANARY}",
            "config.substitution-not-allowed",
        ),
    ] {
        let mut document = fixture();
        document[member] = json!(value);
        let error = refused(&document);
        assert!(
            error.diagnostics().iter().any(|item| item.code == code),
            "{error:?}"
        );
        assert!(!error.to_string().contains("PRIVATE_FIXTURE_CANARY"));
    }
}
#[test]
fn retired_fixture_version_is_refused_with_current_migration_guidance() {
    let mut document = fixture();
    document["apiVersion"] = json!("registry.registrystack.org/casework-fixture/v1alpha1");
    let error = refused(&document);
    let diagnostic = error
        .diagnostics()
        .iter()
        .find(|item| item.code == "config.retired-api-version")
        .unwrap();
    assert_eq!(diagnostic.path, "/apiVersion");
    assert!(diagnostic
        .suggested_action
        .contains(CASEWORK_FIXTURE_API_VERSION));
}

#[test]
fn duplicate_metadata_is_not_silently_overwritten() {
    let original = serde_json::to_string(&fixture()).unwrap();
    let document = original.replacen(
        "\"id\":\"synthetic-review\"",
        "\"id\":\"synthetic-review\",\"id\":\"second\"",
        1,
    );
    let error = CaseworkFixture::read("fixture.yaml", document.as_bytes()).unwrap_err();
    assert!(error
        .diagnostics()
        .iter()
        .any(|item| item.code == "yaml.duplicate-key"));
}
#[test]
fn fixture_references_and_display_are_checked_under_the_compiled_policy() {
    let project = project();
    let original = fixture();
    let decoded = CaseworkFixture::read_against(
        "fixture.yaml",
        &serde_json::to_vec(&original).unwrap(),
        &project,
    )
    .unwrap();
    assert_eq!(decoded.value.review.display["reference"], "BATCH/2026-01");
    for (pointer, value) in [
        ("/review/policy", json!("unknown")),
        ("/expect/queue", json!("unknown")),
        ("/expect/outcomes/0", json!("unknown")),
        ("/review/display/summary", json!(7)),
    ] {
        let mut document = original.clone();
        *document.pointer_mut(pointer).unwrap() = value;
        let error = CaseworkFixture::read_against(
            "fixture.yaml",
            &serde_json::to_vec(&document).unwrap(),
            &project,
        )
        .unwrap_err();
        has_path(&error, pointer);
    }
    let mut document = original;
    document["expect"]["outcomes"] = json!(["rejected", "confirmed"]);
    let error = CaseworkFixture::read_against(
        "fixture.yaml",
        &serde_json::to_vec(&document).unwrap(),
        &project,
    )
    .unwrap_err();
    has_path(&error, "/expect/outcomes");
}
#[test]
fn maintained_submitted_fixture_and_current_source_policy_validate_offline() {
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/casework/examples");
    let submitted = root.join("standalone-decision");
    let project = CaseworkProject::load(submitted.join("casework.yaml")).unwrap();
    let path = submitted.join("fixtures/standalone-decision.yaml");
    CaseworkFixture::read_against(
        &path.display().to_string(),
        &std::fs::read(path).unwrap(),
        &project,
    )
    .unwrap();
    let project = CaseworkProject::load(root.join("canonical-review/casework.yaml")).unwrap();
    let display = json!({"currentAddressLine":"10 Harbour Road","facilityId":"00000000-0000-4000-8000-000000000001","proposedAddressLine":"12 Harbour Road","proposedCity":"Example City","proposedPostalCode":"00100"});
    let mut document = fixture();
    document["review"] = json!({"policy":"facility-address-review","display":display});
    document["expect"] = json!({"queue":"facility-addresses","outcomes":["approved","rejected"]});
    CaseworkFixture::read_against(
        "fixture.yaml",
        &serde_json::to_vec(&document).unwrap(),
        &project,
    )
    .unwrap();
}

#[cfg(feature = "schema")]
#[test]
fn generated_fixture_schema_is_closed_and_enforces_meaningful_expectations() {
    let documents = schema::offline_documents().unwrap();
    let schema: Value = serde_json::from_str(&documents[schema::FIXTURE_SCHEMA_FILE]).unwrap();
    assert_eq!(
        schema["properties"]["apiVersion"]["const"],
        CASEWORK_FIXTURE_API_VERSION
    );
    assert_eq!(schema["properties"]["kind"]["const"], CASEWORK_FIXTURE_KIND);
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    assert!(validator.is_valid(&fixture()));
    for expect in [
        json!({}),
        json!({"outcomes":[]}),
        json!({"queue":null}),
        json!({"outcomes":["confirmed","confirmed"]}),
        json!({"queue":false}),
        json!({"extra":"value"}),
    ] {
        let mut document = fixture();
        document["expect"] = expect;
        assert!(!validator.is_valid(&document), "{document}");
    }
    assert_eq!(
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../products/casework/generated")
                .join(schema::FIXTURE_SCHEMA_FILE)
        )
        .unwrap(),
        documents[schema::FIXTURE_SCHEMA_FILE]
    );
}
