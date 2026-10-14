// SPDX-License-Identifier: Apache-2.0
//! Retained CLI explanation contracts over native governed projects.
use jsonschema::{Draft, JSONSchema};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const FIXTURES: &[(&str, &str)] = &[
    ("minimal", "products/breg/examples/refactor/minimal"),
    ("facility", "products/breg/examples/refactor/facility"),
    ("asset", "products/breg/acceptance/asset-site-placement"),
    (
        "membership",
        "products/breg/fixtures/organization-membership-access",
    ),
];
const ACCESS_SCENARIOS: &[(&str, &str)] = &[
    (
        "allowed",
        "crates/registry-bregctl/tests/fixtures/retained-native/access-review/allowed.json",
    ),
    (
        "missing-scope",
        "crates/registry-bregctl/tests/fixtures/retained-native/access-review/missing-scope.json",
    ),
];
fn envelope(contract: &str) -> (&'static str, &'static str) {
    match contract {
        "ModelExplanation" => (
            "id.registrystack.org/formats/breg/model-explanation/v1alpha4",
            "BRegModelExplanation",
        ),
        "AccessExplanation" => (
            "id.registrystack.org/formats/breg/access-explanation/v1alpha4",
            "BRegAccessExplanation",
        ),
        "AccessPreview" => (
            "id.registrystack.org/formats/breg/access-preview/v1alpha4",
            "BRegAccessPreview",
        ),
        "RoutesExplanation" => (
            "id.registrystack.org/formats/breg/routes-explanation/v1alpha4",
            "BRegRoutesExplanation",
        ),
        "QueriesExplanation" => (
            "id.registrystack.org/formats/breg/queries-explanation/v1alpha4",
            "BRegQueriesExplanation",
        ),
        "ActionsExplanation" => (
            "id.registrystack.org/formats/breg/actions-explanation/v1alpha4",
            "BRegActionsExplanation",
        ),
        "EventsExplanation" => (
            "id.registrystack.org/formats/breg/events-explanation/v1alpha4",
            "BRegEventsExplanation",
        ),
        "LifecycleExplanation" => (
            "id.registrystack.org/formats/breg/lifecycle-explanation/v1alpha4",
            "BRegLifecycleExplanation",
        ),
        _ => panic!("unknown contract {contract}"),
    }
}
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root resolves")
}

fn bregctl(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .args(arguments)
        .output()
        .expect("bregctl starts")
}

fn json_stdout(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("command stdout is JSON")
}

fn explain(subject: &str, project: &Path) -> Value {
    let output = bregctl(&[
        "--format",
        "json",
        "explain",
        subject,
        project.to_str().expect("fixture path is UTF-8"),
    ]);
    assert!(
        output.status.success(),
        "bregctl explain {subject} {project:?} failed: {output:?}"
    );
    let report = json_stdout(&output);
    assert_eq!(
        report["ok"],
        Value::Bool(true),
        "bregctl explain {subject} {project:?} reported ok=false: {report:#?}"
    );
    report["explanation"].clone()
}

fn explain_with_scenario(project: &Path, scenario: &Path) -> Value {
    let output = bregctl(&[
        "--format",
        "json",
        "explain",
        "access",
        project.to_str().expect("fixture path is UTF-8"),
        "--scenario",
        scenario.to_str().expect("scenario path is UTF-8"),
    ]);
    assert!(
        output.status.success(),
        "bregctl explain access {project:?} --scenario {scenario:?} failed: {output:?}"
    );
    let report = json_stdout(&output);
    assert_eq!(
        report["ok"],
        Value::Bool(true),
        "bregctl explain access {project:?} --scenario {scenario:?} reported ok=false: {report:#?}"
    );
    report["explanation"].clone()
}

fn load_schema(kind: &str) -> JSONSchema {
    let schema = load_schema_document(kind);
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema)
        .unwrap_or_else(|error| panic!("schema {kind} compiles: {error}"))
}

fn load_schema_document(kind: &str) -> Value {
    let path = repo_root()
        .join("products/breg/contracts/explain")
        .join(format!("{kind}.schema.json"));
    let bytes =
        std::fs::read(&path).unwrap_or_else(|error| panic!("schema {path:?} reads: {error}"));
    serde_json::from_slice(&bytes).unwrap_or_else(|error| panic!("schema {path:?} parses: {error}"))
}

fn assert_matches_contract(label: &str, kind: &str, explanation: &Value) {
    let (api_version, envelope_kind) = envelope(kind);
    assert_eq!(
        explanation["apiVersion"],
        Value::String(api_version.to_owned()),
        "{label}: unexpected apiVersion in {explanation:#?}"
    );
    assert_eq!(
        explanation["kind"],
        Value::String(envelope_kind.to_owned()),
        "{label}: unexpected kind in {explanation:#?}"
    );

    let schema = load_schema(kind);
    let result = schema.validate(explanation);
    if let Err(errors) = result {
        let mut report = format!("{label}: {kind} does not satisfy its schema contract:\n");
        for error in errors {
            report.push_str(&format!("  - {}: {error}\n", error.instance_path));
        }
        panic!("{report}");
    }
}

fn fixture_path(relative: &str) -> PathBuf {
    let path = repo_root().join(relative);
    assert!(path.is_dir(), "fixture directory {path:?} exists");
    path
}

fn explain_lifecycle_report() -> Value {
    let output = bregctl(&["--format", "json", "explain", "lifecycle"]);
    assert!(
        output.status.success(),
        "bregctl explain lifecycle failed: {output:?}"
    );
    let report = json_stdout(&output);
    assert_eq!(
        report["ok"],
        Value::Bool(true),
        "bregctl explain lifecycle reported ok=false: {report:#?}"
    );
    report
}

#[test]
fn explain_model_matches_contract() {
    for (name, relative) in FIXTURES {
        let explanation = explain("model", &fixture_path(relative));
        assert_matches_contract(name, "ModelExplanation", &explanation);
    }
}

#[test]
fn explain_access_matches_contract() {
    for (name, relative) in FIXTURES {
        let explanation = explain("access", &fixture_path(relative));
        assert_matches_contract(name, "AccessExplanation", &explanation);
    }
}

#[test]
fn explain_routes_matches_contract() {
    for (name, relative) in FIXTURES {
        let explanation = explain("routes", &fixture_path(relative));
        assert_matches_contract(name, "RoutesExplanation", &explanation);
    }
}

#[test]
fn explain_queries_matches_contract() {
    for (name, relative) in FIXTURES {
        let explanation = explain("queries", &fixture_path(relative));
        assert_matches_contract(name, "QueriesExplanation", &explanation);
    }
}

#[test]
fn explain_events_matches_contract() {
    for (name, relative) in FIXTURES {
        let explanation = explain("events", &fixture_path(relative));
        assert_matches_contract(name, "EventsExplanation", &explanation);
    }
}

#[test]
fn explain_lifecycle_matches_contract() {
    let report = explain_lifecycle_report();
    assert_matches_contract("lifecycle", "LifecycleExplanation", &report["explanation"]);
}

#[test]
fn queries_contract_refuses_a_bound_spelled_max() {
    let schema = load_schema("QueriesExplanation");
    let fixture = "products/breg/acceptance/asset-site-placement";
    let explanation = explain("queries", &fixture_path(fixture));
    assert_matches_contract(fixture, "QueriesExplanation", &explanation);
    let operations = explanation["operations"]
        .as_array()
        .expect("operations array");
    assert!(!operations.is_empty(), "{fixture} writes query operations");
    for (index, operation) in operations.iter().enumerate() {
        let bounds = operation["bounds"].as_object().expect("bounds object");
        assert_eq!(
            bounds.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "maximumFilterDepth",
                "maximumFilterNodes",
                "maximumFilterPayloadBytes",
                "maximumFilterPredicates",
                "maximumInValues",
                "maximumPageSize",
                "maximumSelectedFields",
                "maximumTop"
            ]
        );
        for key in bounds.keys() {
            let mut document = explanation.clone();
            let bounds = document["operations"][index]["bounds"]
                .as_object_mut()
                .expect("bounds object");
            let value = bounds.remove(key).expect("bound");
            bounds.insert(key.replacen("maximum", "max", 1), value);
            assert!(
                !schema.is_valid(&document),
                "QueriesExplanation accepts the max spelling of {key}"
            );
        }
    }
}

#[test]
fn access_claim_contract_pins_principal_claims() {
    let schema = load_schema("AccessExplanation");
    let fixture = "crates/registry-bregctl/tests/fixtures/retained-native/access-review";
    let explanation = explain("access", &fixture_path(fixture));
    assert_matches_contract(fixture, "AccessExplanation", &explanation);
    assert_eq!(
        explanation["claimContract"]["principalClaims"],
        json!(["registry_principal"])
    );
    assert!(explanation["claimContractError"].is_null());

    let mut missing = explanation.clone();
    missing["claimContract"]
        .as_object_mut()
        .unwrap()
        .remove("principalClaims");
    assert!(
        !schema.is_valid(&missing),
        "AccessExplanation accepts an inventory without principalClaims"
    );

    for malformed in [
        json!([""]),
        json!(["registry_principal", "registry_principal"]),
        json!([1]),
    ] {
        let mut document = explanation.clone();
        document["claimContract"]["principalClaims"] = malformed.clone();
        assert!(
            !schema.is_valid(&document),
            "AccessExplanation accepts malformed principalClaims {malformed}"
        );
    }

    let mut empty = explanation.clone();
    empty["claimContract"]["principalClaims"] = json!([]);
    assert!(
        schema.is_valid(&empty),
        "AccessExplanation refuses an empty successful authority inventory"
    );

    let mut passthrough = explanation.clone();
    passthrough["claimContract"]["futureInventoryMember"] = json!({"shape":"opaque"});
    assert!(
        schema.is_valid(&passthrough),
        "AccessExplanation seals authority inventory members that remain opaque"
    );
}

#[test]
fn access_claim_contract_pins_the_inventory_error_relation() {
    let schema = load_schema("AccessExplanation");
    let fixture = "crates/registry-bregctl/tests/fixtures/retained-native/access-review";
    let explanation = explain("access", &fixture_path(fixture));
    assert_matches_contract(fixture, "AccessExplanation", &explanation);

    let mut success_with_error = explanation.clone();
    success_with_error["claimContractError"] = json!("principal-claim-missing");
    assert!(
        !schema.is_valid(&success_with_error),
        "AccessExplanation accepts both an inventory and its error"
    );

    let mut failure = explanation.clone();
    failure["claimContract"] = Value::Null;
    failure["claimContractError"] = json!("principal-claim-missing");
    assert!(
        schema.is_valid(&failure),
        "AccessExplanation refuses a pinned authority inventory failure"
    );

    failure["claimContractError"] = Value::Null;
    assert!(
        !schema.is_valid(&failure),
        "AccessExplanation accepts neither an inventory nor its error"
    );
}

#[test]
fn access_contracts_refuse_a_snake_case_constant() {
    use registry_breg::authority::AuthorityInventoryError;

    let schema = load_schema("AccessExplanation");
    let fixture = "crates/registry-bregctl/tests/fixtures/retained-native/access-review";
    let explanation = explain("access", &fixture_path(fixture));
    assert_matches_contract(fixture, "AccessExplanation", &explanation);
    assert!(explanation["claimContractError"].is_null());
    let errors = [
        AuthorityInventoryError::PrincipalClaimMissing,
        AuthorityInventoryError::TargetEntityNotCompiled,
        AuthorityInventoryError::BoundaryFieldNotCompiled,
        AuthorityInventoryError::LookupSelectorNotCompiled,
        AuthorityInventoryError::LookupClaimMappingIncomplete,
        AuthorityInventoryError::LookupFieldNotCompiled,
        AuthorityInventoryError::ConflictingClaimExpectation,
    ];
    for error in errors {
        let written = serde_json::to_value(error).expect("claim contract error serializes");
        let word = written.as_str().expect("claim contract error is a string");
        assert!(
            !word.contains('_'),
            "the engine writes claimContractError {word}, which is not kebab-case"
        );
        let mut document = explanation.clone();
        document["claimContract"] = Value::Null;
        document["claimContractError"] = written.clone();
        assert!(
            schema.is_valid(&document),
            "AccessExplanation refuses claimContractError {word}"
        );
        document["claimContractError"] = json!(word.replace('-', "_"));
        assert!(
            !schema.is_valid(&document),
            "AccessExplanation accepts a snake_case claimContractError for {word}"
        );
    }

    let schema = load_schema("AccessPreview");
    let project = fixture_path(fixture);
    for (name, relative) in ACCESS_SCENARIOS {
        let preview = explain_with_scenario(&project, &repo_root().join(relative));
        assert_matches_contract(name, "AccessPreview", &preview);
        assert_eq!(preview["mode"], json!("offline-synthetic"), "{name}");
        assert_eq!(preview["recordAccess"], json!("not-evaluated"), "{name}");
        for (member, old) in [
            ("mode", "offline_synthetic"),
            ("recordAccess", "not_evaluated"),
        ] {
            let mut document = preview.clone();
            document[member] = json!(old);
            assert!(
                !schema.is_valid(&document),
                "AccessPreview accepts {member} {old}"
            );
        }
    }
}

#[test]
fn explain_lifecycle_refuses_the_production_profile() {
    let output = bregctl(&["--format", "json", "explain", "lifecycle", "--production"]);
    assert!(
        !output.status.success(),
        "bregctl explain lifecycle --production is refused: {output:?}"
    );
    let report = json_stdout(&output);
    assert_eq!(report["ok"], Value::Bool(false), "{report:#?}");
    assert_eq!(
        report["diagnostics"][0]["code"],
        Value::String("lifecycle.profile.unused".to_owned()),
        "{report:#?}"
    );
}

#[test]
fn explain_lifecycle_does_not_announce_a_compiled_inventory() {
    let output = bregctl(&["explain", "lifecycle"]);
    assert!(
        output.status.success(),
        "bregctl explain lifecycle failed: {output:?}"
    );
    let stdout = String::from_utf8(output.stdout).expect("bregctl writes UTF-8");
    assert!(
        !stdout.contains("Explained the compiled inventory."),
        "explain lifecycle compiles nothing: {stdout}"
    );
    assert!(
        stdout.contains("No project was compiled."),
        "explain lifecycle says so in its lead: {stdout}"
    );
}

#[test]
fn explain_lifecycle_refuses_a_project() {
    let project = fixture_path("products/breg/examples/refactor/minimal");
    let output = bregctl(&[
        "--format",
        "json",
        "explain",
        "lifecycle",
        project.to_str().expect("fixture path is UTF-8"),
    ]);
    assert!(
        !output.status.success(),
        "bregctl explain lifecycle <project> is refused: {output:?}"
    );
    let report = json_stdout(&output);
    assert_eq!(report["ok"], Value::Bool(false), "{report:#?}");
    assert_eq!(
        report["diagnostics"][0]["code"],
        Value::String("lifecycle.project.unused".to_owned()),
        "{report:#?}"
    );
}

#[test]
fn explain_refuses_a_missing_project_for_every_other_subject() {
    for subject in [
        "model",
        "access",
        "routes",
        "queries",
        "actions",
        "proposals",
        "events",
    ] {
        let output = bregctl(&["--format", "json", "explain", subject]);
        assert!(
            !output.status.success(),
            "bregctl explain {subject} with no project is refused: {output:?}"
        );
        let report = json_stdout(&output);
        assert_eq!(
            report["diagnostics"][0]["code"],
            Value::String("explain.project.missing".to_owned()),
            "explain {subject}: {report:#?}"
        );
    }
}

#[test]
fn explain_actions_matches_the_current_closed_contract() {
    for (label, path) in FIXTURES {
        assert_matches_contract(
            label,
            "ActionsExplanation",
            &explain("actions", &fixture_path(path)),
        );
    }
}
#[test]
fn module_and_record_identifiers_and_derived_routes_are_validated() {
    let project = fixture_path("products/breg/acceptance/asset-site-placement");
    for (subject, contract, pointer) in [
        ("model", "ModelExplanation", "/moduleClosure/0/id"),
        ("model", "ModelExplanation", "/recordTypes/0/id"),
        ("routes", "RoutesExplanation", "/routes/0/id"),
        ("queries", "QueriesExplanation", "/operations/0/id"),
    ] {
        let value = explain(subject, &project);
        let schema = load_schema(contract);
        assert!(schema.is_valid(&value));
        for invalid in ["Not An Id", "9lives", ""] {
            let mut changed = value.clone();
            *changed
                .pointer_mut(pointer)
                .expect("fixture covers identifier") = json!(invalid);
            assert!(
                !schema.is_valid(&changed),
                "{contract} accepts {invalid} at {pointer}"
            );
        }
    }
}
#[test]
fn proposal_lifecycle_pin_rejects_state_event_order_and_enforcement_drift() {
    let value = explain_lifecycle_report()["explanation"].clone();
    let lifecycle = &value["lifecycles"][0];
    assert_eq!(lifecycle["id"], "proposal");
    assert_eq!(
        lifecycle["states"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["draft", "submitted", "cancelled", "applied"]
    );
    let schema = load_schema("LifecycleExplanation");
    for pointer in [
        "/lifecycles/0/id",
        "/lifecycles/0/states/0/id",
        "/lifecycles/0/transitions/0/event",
        "/lifecycles/0/enforcement/0/id",
    ] {
        let mut changed = value.clone();
        *changed.pointer_mut(pointer).unwrap() = json!("unknown");
        assert!(!schema.is_valid(&changed), "accepts changed {pointer}");
    }
    let mut changed = value.clone();
    changed["lifecycles"][0]["states"]
        .as_array_mut()
        .unwrap()
        .swap(0, 1);
    assert!(!schema.is_valid(&changed));
    changed = value.clone();
    changed["lifecycles"][0]["enforcement"]
        .as_array_mut()
        .unwrap()
        .pop();
    assert!(!schema.is_valid(&changed));
}
#[test]
fn native_proposal_inspection_pins_review_and_system_apply_scope_without_sources() {
    let project = fixture_path("products/breg/examples/refactor/facility");
    let inspection = explain("actions", &project);
    let actions = inspection["actions"].as_array().unwrap();
    let correction = actions
        .iter()
        .find(|a| a["id"] == "correct-address")
        .unwrap();
    assert_eq!(correction["display"]["label"], "Correct facility address");
    assert_eq!(
        correction["plan"]["function"]["abi"],
        "registry.action-plan/v1"
    );
    let policy = &correction["execution"]["proposal"];
    assert_eq!(policy["review"]["type"], "required");
    assert_eq!(policy["review"]["authority"], "casework");
    assert_eq!(policy["review"]["policy"]["id"], "facility-address-review");
    assert_eq!(policy["application"]["mode"], "automatic");
    assert!(policy["application"].get("executor").is_none());
    let grant = &policy["systemApplyGrant"];
    assert_eq!(grant["actionId"], "correct-address");
    assert_eq!(grant["actionRevision"], correction["revision"]);
    assert_eq!(grant["targets"].as_array().unwrap().len(), 2);
    let patch = grant["targets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["operation"] == "patch")
        .unwrap();
    assert_eq!(patch["recordType"], "facility");
    assert_eq!(
        patch["fields"],
        json!(["address-line", "city", "postal-code"])
    );
    let reviewer = policy["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["profileId"] == "casework-review-status")
        .unwrap();
    assert_eq!(reviewer["operations"], json!(["get-review-status"]));
    assert_eq!(reviewer["reviewAuthority"], "casework");
    assert_eq!(reviewer["targets"], json!([]));
    assert_eq!(reviewer["readableInputs"], json!([]));
    let proposals = explain("proposals", &project);
    assert_eq!(proposals["actions"].as_array().unwrap().len(), 2);
    assert!(proposals["actions"]
        .as_array()
        .unwrap()
        .iter()
        .all(|a| a["execution"]["mode"] == "proposal"));
    let rendered = serde_json::to_string(&inspection).unwrap();
    for forbidden in [
        "fn plan(",
        "scriptSource",
        "registry.change-request-plan",
        "contractFingerprint",
        "secret:env/",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "inspection leaks {forbidden}"
        );
    }
}
#[test]
fn each_generic_contract_refuses_a_shared_or_unknown_header() {
    let project = fixture_path("products/breg/examples/refactor/minimal");
    for (subject, contract) in [
        ("model", "ModelExplanation"),
        ("access", "AccessExplanation"),
        ("routes", "RoutesExplanation"),
        ("queries", "QueriesExplanation"),
        ("events", "EventsExplanation"),
        ("actions", "ActionsExplanation"),
    ] {
        let value = explain(subject, &project);
        let schema = load_schema(contract);
        for (field, invalid) in [
            (
                "apiVersion",
                "id.registrystack.org/formats/breg/explanation/v1",
            ),
            ("kind", "BRegExplanation"),
        ] {
            let mut changed = value.clone();
            changed[field] = json!(invalid);
            assert!(!schema.is_valid(&changed), "{contract} accepts {field}");
        }
    }
}
