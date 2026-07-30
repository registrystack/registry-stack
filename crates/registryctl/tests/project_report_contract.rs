// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

#[path = "../src/project_authoring/knowledge.rs"]
mod knowledge;
#[path = "../src/project_authoring/required_product_action.rs"]
mod required_product_action;
pub use required_product_action::RequiredProductAction;
#[path = "../src/project_authoring/report_contract.rs"]
mod report_contract;
pub use report_contract::{ProjectRelativePath, Sha256Digest};
#[path = "../src/project_authoring/fixture_coverage.rs"]
mod fixture_coverage;

use fixture_coverage::ProjectFixtureCoverageReportV1;
use report_contract::{
    ClassifierApprovedJson, DimensionOnlySemanticChange, FieldSensitivity, JsonPointer,
    ProjectArtifactManifestV1, ProjectCommandReportV1, ProjectExplanationReportV1,
    ProjectSemanticImpactReportV1, SemanticDimension,
};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

const PROJECT_COMMAND_SCHEMA_ID: &str = "https://id.registrystack.org/schemas/registryctl/project-reports/registryctl.project_command.v1.schema.json";
const PROJECT_EXPLANATION_SCHEMA_ID: &str = "https://id.registrystack.org/schemas/registryctl/project-reports/registry.project.explanation.v1.schema.json";
const PROJECT_SEMANTIC_IMPACT_SCHEMA_ID: &str = "https://id.registrystack.org/schemas/registryctl/project-reports/registry.project.semantic_impact.v1.schema.json";
const PROJECT_ARTIFACT_MANIFEST_SCHEMA_ID: &str = "https://id.registrystack.org/schemas/registryctl/project-reports/registry.project.artifact_manifest.v1.schema.json";
const PROJECT_FIXTURE_COVERAGE_SCHEMA_ID: &str = "https://id.registrystack.org/schemas/registryctl/project-reports/registry.project.fixture_coverage.v1.schema.json";

const PROJECT_COMMAND_SCHEMA: &str =
    include_str!("../schemas/project-reports/registryctl.project_command.v1.schema.json");
const PROJECT_EXPLANATION_SCHEMA: &str =
    include_str!("../schemas/project-reports/registry.project.explanation.v1.schema.json");
const PROJECT_SEMANTIC_IMPACT_SCHEMA: &str =
    include_str!("../schemas/project-reports/registry.project.semantic_impact.v1.schema.json");
const PROJECT_ARTIFACT_MANIFEST_SCHEMA: &str =
    include_str!("../schemas/project-reports/registry.project.artifact_manifest.v1.schema.json");
const PROJECT_FIXTURE_COVERAGE_SCHEMA: &str =
    include_str!("../schemas/project-reports/registry.project.fixture_coverage.v1.schema.json");

const PROJECT_COMMAND_FIXTURE: &str =
    include_str!("fixtures/project-reports/registryctl.project_command.v1.json");
const PROJECT_EXPLANATION_FIXTURE: &str =
    include_str!("fixtures/project-reports/registry.project.explanation.v1.json");
const PROJECT_SEMANTIC_IMPACT_FIXTURE: &str =
    include_str!("fixtures/project-reports/registry.project.semantic_impact.v1.json");
const PROJECT_ARTIFACT_MANIFEST_FIXTURE: &str =
    include_str!("fixtures/project-reports/registry.project.artifact_manifest.v1.json");
const PROJECT_FIXTURE_COVERAGE_FIXTURE: &str =
    include_str!("fixtures/project-reports/registry.project.fixture_coverage.v1.json");
const PROJECT_FIXTURE_COVERAGE_NO_TARGET_FIXTURE: &str =
    include_str!("fixtures/project-reports/registry.project.fixture_coverage.no-target.v1.json");

fn parse(input: &str) -> Value {
    serde_json::from_str(input).expect("JSON parses")
}

fn validator(schema: &str) -> jsonschema::JSONSchema {
    let mut options = jsonschema::JSONSchema::options();
    options
        .with_draft(jsonschema::Draft::Draft202012)
        .with_document(
            PROJECT_COMMAND_SCHEMA_ID.to_string(),
            parse(PROJECT_COMMAND_SCHEMA),
        )
        .with_document(
            PROJECT_EXPLANATION_SCHEMA_ID.to_string(),
            parse(PROJECT_EXPLANATION_SCHEMA),
        )
        .with_document(
            PROJECT_SEMANTIC_IMPACT_SCHEMA_ID.to_string(),
            parse(PROJECT_SEMANTIC_IMPACT_SCHEMA),
        )
        .with_document(
            PROJECT_ARTIFACT_MANIFEST_SCHEMA_ID.to_string(),
            parse(PROJECT_ARTIFACT_MANIFEST_SCHEMA),
        )
        .with_document(
            PROJECT_FIXTURE_COVERAGE_SCHEMA_ID.to_string(),
            parse(PROJECT_FIXTURE_COVERAGE_SCHEMA),
        );
    options
        .compile(&parse(schema))
        .expect("Draft 2020-12 schema compiles")
}

fn assert_valid(schema: &str, document: &Value) {
    if let Err(errors) = validator(schema).validate(document) {
        let details = errors.map(|error| error.to_string()).collect::<Vec<_>>();
        panic!("document should validate: {details:?}");
    }
}

fn assert_invalid(schema: &str, document: &Value) {
    assert!(
        validator(schema).validate(document).is_err(),
        "document should not validate"
    );
}

fn assert_exact_roundtrip<T>(fixture: &str)
where
    T: DeserializeOwned + serde::Serialize + PartialEq + std::fmt::Debug,
{
    let document = parse(fixture);
    let decoded: T = serde_json::from_value(document.clone()).expect("fixture decodes");
    let encoded = serde_json::to_value(&decoded).expect("fixture re-encodes");
    assert_eq!(
        encoded, document,
        "roundtrip preserves the canonical document"
    );
    let decoded_again: T = serde_json::from_value(encoded).expect("roundtrip output decodes");
    assert_eq!(decoded_again, decoded);
}

fn assert_typed_invalid<T>(document: Value)
where
    T: DeserializeOwned,
{
    assert!(
        serde_json::from_value::<T>(document).is_err(),
        "strict DTO should reject the document"
    );
}

#[test]
fn draft_2020_12_schemas_validate_all_canonical_fixtures() {
    for (schema, fixture) in [
        (PROJECT_COMMAND_SCHEMA, PROJECT_COMMAND_FIXTURE),
        (PROJECT_EXPLANATION_SCHEMA, PROJECT_EXPLANATION_FIXTURE),
        (
            PROJECT_SEMANTIC_IMPACT_SCHEMA,
            PROJECT_SEMANTIC_IMPACT_FIXTURE,
        ),
        (
            PROJECT_ARTIFACT_MANIFEST_SCHEMA,
            PROJECT_ARTIFACT_MANIFEST_FIXTURE,
        ),
        (
            PROJECT_FIXTURE_COVERAGE_SCHEMA,
            PROJECT_FIXTURE_COVERAGE_FIXTURE,
        ),
        (
            PROJECT_FIXTURE_COVERAGE_SCHEMA,
            PROJECT_FIXTURE_COVERAGE_NO_TARGET_FIXTURE,
        ),
    ] {
        assert_valid(schema, &parse(fixture));
    }
}

#[test]
fn strict_dtos_roundtrip_canonical_fixtures_without_loss() {
    assert_exact_roundtrip::<ProjectCommandReportV1>(PROJECT_COMMAND_FIXTURE);
    assert_exact_roundtrip::<ProjectExplanationReportV1>(PROJECT_EXPLANATION_FIXTURE);
    assert_exact_roundtrip::<ProjectSemanticImpactReportV1>(PROJECT_SEMANTIC_IMPACT_FIXTURE);
    assert_exact_roundtrip::<ProjectArtifactManifestV1>(PROJECT_ARTIFACT_MANIFEST_FIXTURE);
    assert_exact_roundtrip::<ProjectFixtureCoverageReportV1>(PROJECT_FIXTURE_COVERAGE_FIXTURE);
    assert_exact_roundtrip::<ProjectFixtureCoverageReportV1>(
        PROJECT_FIXTURE_COVERAGE_NO_TARGET_FIXTURE,
    );

    for (schema, fixture, expected_version) in [
        (
            PROJECT_COMMAND_SCHEMA,
            PROJECT_COMMAND_FIXTURE,
            "registryctl.project_command.v1",
        ),
        (
            PROJECT_EXPLANATION_SCHEMA,
            PROJECT_EXPLANATION_FIXTURE,
            "registry.project.explanation.v1",
        ),
        (
            PROJECT_SEMANTIC_IMPACT_SCHEMA,
            PROJECT_SEMANTIC_IMPACT_FIXTURE,
            "registry.project.semantic_impact.v1",
        ),
        (
            PROJECT_ARTIFACT_MANIFEST_SCHEMA,
            PROJECT_ARTIFACT_MANIFEST_FIXTURE,
            "registry.project.artifact_manifest.v1",
        ),
        (
            PROJECT_FIXTURE_COVERAGE_SCHEMA,
            PROJECT_FIXTURE_COVERAGE_FIXTURE,
            "registry.project.fixture_coverage.v1",
        ),
    ] {
        let mut wrong_version = parse(fixture);
        assert_eq!(wrong_version["schema_version"], expected_version);
        wrong_version["schema_version"] = json!("registry.project.future.v2");
        assert_invalid(schema, &wrong_version);
    }
}

#[test]
fn real_project_command_producers_match_the_strict_v1_contract() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("registry-project");
    registryctl::init_registry_project(&registryctl::ProjectInitOptions {
        starter: registryctl::ProjectStarter::Http,
        directory: project.clone(),
    })
    .expect("HTTP starter initializes");
    let execution_context =
        registryctl::ProjectExecutionContext::new(env!("CARGO_BIN_EXE_registryctl"))
            .expect("Cargo provides the real registryctl executable");

    let reports = [
        registryctl::test_registry_project_with_context(
            &registryctl::ProjectTestOptions {
                project_directory: project.clone(),
                environment: None,
            },
            &execution_context,
        )
        .expect("offline project test report"),
        registryctl::check_registry_project_with_context(
            &registryctl::ProjectCheckOptions {
                project_directory: project.clone(),
                environment: "local".to_owned(),
                explain: true,
                against: None,
                anchor: None,
            },
            &execution_context,
        )
        .expect("project check report"),
        registryctl::build_registry_project_with_context(
            &registryctl::ProjectBuildOptions {
                project_directory: project,
                environment: "local".to_owned(),
                against: None,
                anchor: None,
            },
            &execution_context,
        )
        .expect("project build report"),
    ];

    for report in reports {
        let document = serde_json::to_value(report).expect("real report serializes");
        assert_valid(PROJECT_COMMAND_SCHEMA, &document);
        serde_json::from_value::<ProjectCommandReportV1>(document)
            .expect("real report decodes through the strict command DTO");
    }
}

#[test]
fn project_command_rejects_root_and_nested_unknown_fields() {
    let mut root = parse(PROJECT_COMMAND_FIXTURE);
    root["future_field"] = json!(true);
    assert_invalid(PROJECT_COMMAND_SCHEMA, &root);
    assert_typed_invalid::<ProjectCommandReportV1>(root);

    let mut nested = parse(PROJECT_COMMAND_FIXTURE);
    nested["artifact_manifest"]["absolute_path"] = json!("/tmp/manifest.json");
    assert_invalid(PROJECT_COMMAND_SCHEMA, &nested);
    assert_typed_invalid::<ProjectCommandReportV1>(nested);
}

#[test]
fn explanation_rejects_root_and_deeply_nested_unknown_fields() {
    let mut root = parse(PROJECT_EXPLANATION_FIXTURE);
    root["future_field"] = json!(true);
    assert_invalid(PROJECT_EXPLANATION_SCHEMA, &root);
    assert_typed_invalid::<ProjectExplanationReportV1>(root);

    let mut nested = parse(PROJECT_EXPLANATION_FIXTURE);
    nested["fields"][0]["knowledge"]["runtime_value"] = json!("not reportable");
    assert_invalid(PROJECT_EXPLANATION_SCHEMA, &nested);
    assert_typed_invalid::<ProjectExplanationReportV1>(nested);

    let mut non_pointer_address = parse(PROJECT_EXPLANATION_FIXTURE);
    non_pointer_address["fields"][0]["address"]["path"] =
        json!("integrations/person-record/integration.yaml");
    assert_invalid(PROJECT_EXPLANATION_SCHEMA, &non_pointer_address);
    assert_typed_invalid::<ProjectExplanationReportV1>(non_pointer_address);
}

#[test]
fn semantic_impact_rejects_root_and_deeply_nested_unknown_fields() {
    let mut root = parse(PROJECT_SEMANTIC_IMPACT_FIXTURE);
    root["future_field"] = json!(true);
    assert_invalid(PROJECT_SEMANTIC_IMPACT_SCHEMA, &root);
    assert_typed_invalid::<ProjectSemanticImpactReportV1>(root);

    let mut nested = parse(PROJECT_SEMANTIC_IMPACT_FIXTURE);
    nested["changes"][0]["requirements"]["restart_reason"] = json!("changed config");
    assert_invalid(PROJECT_SEMANTIC_IMPACT_SCHEMA, &nested);
    assert_typed_invalid::<ProjectSemanticImpactReportV1>(nested);
}

#[test]
fn artifact_manifest_rejects_root_and_deeply_nested_unknown_fields() {
    let mut root = parse(PROJECT_ARTIFACT_MANIFEST_FIXTURE);
    root["future_field"] = json!(true);
    assert_invalid(PROJECT_ARTIFACT_MANIFEST_SCHEMA, &root);
    assert_typed_invalid::<ProjectArtifactManifestV1>(root);

    let mut nested = parse(PROJECT_ARTIFACT_MANIFEST_FIXTURE);
    nested["artifacts"][0]["last_deployed_at"] = json!("runtime observation");
    assert_invalid(PROJECT_ARTIFACT_MANIFEST_SCHEMA, &nested);
    assert_typed_invalid::<ProjectArtifactManifestV1>(nested);
}

#[test]
fn artifact_manifest_rejects_unknown_or_missing_input_classification() {
    let mut unknown = parse(PROJECT_ARTIFACT_MANIFEST_FIXTURE);
    unknown["inputs"][0]["classification"] = json!("source");
    assert_typed_invalid::<ProjectArtifactManifestV1>(unknown.clone());
    assert_invalid(PROJECT_ARTIFACT_MANIFEST_SCHEMA, &unknown);

    let mut missing = parse(PROJECT_ARTIFACT_MANIFEST_FIXTURE);
    missing["inputs"][0]
        .as_object_mut()
        .expect("input object")
        .remove("classification");
    assert_typed_invalid::<ProjectArtifactManifestV1>(missing.clone());
    assert_invalid(PROJECT_ARTIFACT_MANIFEST_SCHEMA, &missing);
}

#[test]
fn semantic_precision_requires_a_field_address_only_for_field_precision() {
    let mut missing_field = parse(PROJECT_SEMANTIC_IMPACT_FIXTURE);
    missing_field["changes"][0]["precision"] = json!("field");
    assert_invalid(PROJECT_SEMANTIC_IMPACT_SCHEMA, &missing_field);
    assert_typed_invalid::<ProjectSemanticImpactReportV1>(missing_field);

    let mut dimension_with_field = parse(PROJECT_SEMANTIC_IMPACT_FIXTURE);
    dimension_with_field["changes"][0]["field"] = json!({
        "document": "integration",
        "integration": "person-record",
        "path": "/http"
    });
    assert_invalid(PROJECT_SEMANTIC_IMPACT_SCHEMA, &dimension_with_field);
    assert_typed_invalid::<ProjectSemanticImpactReportV1>(dimension_with_field);

    let mut precise_field = parse(PROJECT_SEMANTIC_IMPACT_FIXTURE);
    precise_field["changes"][0]["precision"] = json!("field");
    precise_field["changes"][0]["field"] = json!({
        "document": "integration",
        "integration": "person-record",
        "path": "/http/request/timeout"
    });
    assert_valid(PROJECT_SEMANTIC_IMPACT_SCHEMA, &precise_field);
    let typed: ProjectSemanticImpactReportV1 =
        serde_json::from_value(precise_field.clone()).expect("field-precise impact decodes");
    assert_eq!(
        serde_json::to_value(typed).expect("field-precise impact re-encodes"),
        precise_field
    );
}

#[test]
fn dimension_only_projection_preserves_the_legacy_byte_shape() {
    let impact: ProjectSemanticImpactReportV1 =
        serde_json::from_str(PROJECT_SEMANTIC_IMPACT_FIXTURE).expect("impact fixture decodes");
    let projection = impact.dimension_only_changes();
    assert_eq!(
        serde_json::to_string(&projection).expect("projection serializes"),
        r#"[{"dimension":"integration"}]"#
    );

    let command: ProjectCommandReportV1 =
        serde_json::from_str(PROJECT_COMMAND_FIXTURE).expect("command fixture decodes");
    assert_eq!(command.semantic_changes, projection);
    assert_eq!(SemanticDimension::Integration, "integration");
    assert_eq!("integration", SemanticDimension::Integration);
    assert_eq!(
        serde_json::to_string(&DimensionOnlySemanticChange {
            dimension: SemanticDimension::Integration,
        })
        .expect("single compatibility record serializes"),
        r#"{"dimension":"integration"}"#
    );
}

#[test]
fn artifact_paths_fail_closed_before_the_report_can_be_constructed() {
    for path in [
        "",
        "/tmp/output.json",
        "../output.json",
        "build/../output.json",
        r"C:\output.json",
        "https://country.example/output.json",
        "build//output.json",
    ] {
        assert!(
            ProjectRelativePath::new(path).is_err(),
            "{path:?} must not be accepted as a project-relative artifact path"
        );
    }

    for path in [
        "registry-stack.yaml",
        "environments/local.yaml",
        ".registry-stack/build/local/artifact-manifest.json",
    ] {
        assert_eq!(
            ProjectRelativePath::new(path).expect("safe path").as_str(),
            path
        );
    }

    for pointer in [
        "integrations/person-record/integration.yaml",
        "#/integrations/person-record",
        "/invalid~escape",
    ] {
        assert!(
            JsonPointer::new(pointer).is_err(),
            "{pointer:?} must not be accepted as an RFC 6901 pointer"
        );
    }
    assert_eq!(
        JsonPointer::new("/integrations/person-record/~0key")
            .expect("valid pointer")
            .as_str(),
        "/integrations/person-record/~0key"
    );
}

#[test]
fn canonical_fixtures_exclude_runtime_and_country_sensitive_material() {
    assert!(
        ClassifierApprovedJson::after_classification(
            FieldSensitivity::SecretReference,
            false,
            json!("sensitive-reference-name"),
        )
        .is_none(),
        "non-public classifier output cannot cross the value-bearing boundary"
    );
    assert_eq!(
        ClassifierApprovedJson::after_classification(FieldSensitivity::Public, false, json!("5s"))
            .expect("public classified value")
            .as_value(),
        &json!("5s")
    );

    for fixture in [
        PROJECT_COMMAND_FIXTURE,
        PROJECT_EXPLANATION_FIXTURE,
        PROJECT_SEMANTIC_IMPACT_FIXTURE,
        PROJECT_ARTIFACT_MANIFEST_FIXTURE,
        PROJECT_FIXTURE_COVERAGE_FIXTURE,
    ] {
        for forbidden in [
            "http://",
            "https://",
            "-----BEGIN",
            "PRIVATE KEY",
            "\"generated_at\"",
            "\"observed_at\"",
            "\"last_deployed_at\"",
            "/Users/",
            "/home/",
            "10.0.0.0/",
            "192.168.0.0/",
        ] {
            assert!(
                !fixture.contains(forbidden),
                "canonical fixture contains forbidden material {forbidden:?}"
            );
        }
    }
}
