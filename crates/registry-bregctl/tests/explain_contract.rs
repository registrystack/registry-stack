// SPDX-License-Identifier: Apache-2.0
//! Retained CLI explanation contracts over native governed projects.
use jsonschema::{Draft, JSONSchema};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const FIXTURES: &[(&str, &str)] = &[
    ("minimal", "products/breg/examples/minimal"),
    ("facility", "products/breg/examples/facility"),
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
            "id.registrystack.org/formats/breg/model-explanation/v1alpha6",
            "BRegModelExplanation",
        ),
        "AccessExplanation" => (
            "id.registrystack.org/formats/breg/access-explanation/v1alpha6",
            "BRegAccessExplanation",
        ),
        "AccessPreview" => (
            "id.registrystack.org/formats/breg/access-preview/v1alpha4",
            "BRegAccessPreview",
        ),
        "RoutesExplanation" => (
            "id.registrystack.org/formats/breg/routes-explanation/v1alpha6",
            "BRegRoutesExplanation",
        ),
        "QueriesExplanation" => (
            "id.registrystack.org/formats/breg/queries-explanation/v1alpha5",
            "BRegQueriesExplanation",
        ),
        "ActionsExplanation" => (
            "id.registrystack.org/formats/breg/actions-explanation/v1alpha6",
            "BRegActionsExplanation",
        ),
        "ProposalsExplanation" => (
            "id.registrystack.org/formats/breg/proposals-explanation/v1alpha2",
            "BRegProposalsExplanation",
        ),
        "EventsExplanation" => (
            "id.registrystack.org/formats/breg/events-explanation/v1alpha6",
            "BRegEventsExplanation",
        ),
        "LifecycleExplanation" => (
            "id.registrystack.org/formats/breg/lifecycle-explanation/v1alpha7",
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

fn source_binding<'a>(explanation: &'a Value, file: &str, explanation_pointer: &str) -> &'a Value {
    let document = explanation["authoring"]["documents"]
        .as_array()
        .expect("model authoring documents")
        .iter()
        .find(|document| document["file"] == file)
        .unwrap_or_else(|| panic!("missing authoring document {file} in {explanation:#?}"));
    document["bindings"]
        .as_array()
        .expect("model authoring bindings")
        .iter()
        .find(|binding| binding["explanationPointer"] == explanation_pointer)
        .unwrap_or_else(|| {
            panic!("missing binding for {explanation_pointer} in {file}: {document:#?}")
        })
}

fn item_index(items: &Value, id: &str) -> usize {
    items
        .as_array()
        .expect("compiled inventory is an array")
        .iter()
        .position(|item| item["id"] == id)
        .unwrap_or_else(|| panic!("missing compiled item {id}: {items:#?}"))
}

#[test]
fn explain_model_matches_contract() {
    for (name, relative) in FIXTURES {
        let explanation = explain("model", &fixture_path(relative));
        assert_matches_contract(name, "ModelExplanation", &explanation);
    }
}

#[test]
fn explain_model_lists_authored_source_presence_as_exact_document_pointers() {
    let explanation = explain("model", &fixture_path("products/breg/examples/minimal"));
    let documents = explanation["authoring"]["documents"]
        .as_array()
        .expect("model explanation lists authoring documents");
    assert_eq!(documents.len(), 1);
    assert_eq!(documents[0]["kind"], "BRegProject");
    assert_eq!(documents[0]["file"], "registry.yaml");
    assert!(documents[0].get("module").is_none());
    let authored = documents[0]["authoredPaths"]
        .as_array()
        .expect("authoredPaths is an array");
    let has = |pointer: &str| authored.iter().any(|path| path == pointer);
    assert!(has(""), "the empty pointer names the source document root");
    assert!(has("/recordTypes/0/display"));
    assert!(has("/recordTypes/0/fields/0/required"));
    assert!(
        !has("/recordTypes/0/tombstone"),
        "a compiled default is absent when the source omitted its member"
    );
}

#[test]
fn model_source_bindings_survive_compiled_order_and_module_extensions() {
    let model = explain(
        "model",
        &fixture_path("products/breg/fixtures/generic-operator-workflows"),
    );
    assert_eq!(
        source_binding(&model, "registry.yaml", "")["sourcePointer"],
        "/project"
    );

    let record_index = item_index(&model["recordTypes"], "record");
    assert_ne!(
        record_index, 1,
        "the compiled model reorders the second authored Record type"
    );
    assert_eq!(
        source_binding(
            &model,
            "registry.yaml",
            &format!("/recordTypes/{record_index}")
        )["sourcePointer"],
        "/recordTypes/1"
    );

    let field_index = item_index(
        &model["recordTypes"][record_index]["fields"],
        "internal-note",
    );
    let explanation_pointer = format!("/recordTypes/{record_index}/fields/{field_index}");
    let binding = source_binding(
        &model,
        "modules/record-notes/module.yaml",
        &explanation_pointer,
    );
    assert_eq!(binding["sourcePointer"], "/extendRecordTypes/0/fields/0");
    let module = model["authoring"]["documents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|document| document["module"] == "record-notes")
        .unwrap();
    assert!(module["authoredPaths"]
        .as_array()
        .unwrap()
        .iter()
        .any(|path| path == "/extendRecordTypes/0/fields/0/id"));
    assert!(!module["authoredPaths"]
        .as_array()
        .unwrap()
        .iter()
        .any(|path| path == "/extendRecordTypes/0/fields/0/display"));
}

#[test]
fn model_source_bindings_cover_module_records_actions_inputs_and_record_hooks() {
    let model = explain(
        "model",
        &fixture_path("products/breg/fixtures/facility-registry-actions"),
    );
    let module_file = "modules/facility-registry-actions-core/module.yaml";
    let record_index = item_index(&model["recordTypes"], "facility");
    assert_eq!(
        source_binding(&model, module_file, &format!("/recordTypes/{record_index}"))
            ["sourcePointer"],
        "/recordTypes/1"
    );
    assert_eq!(
        source_binding(
            &model,
            module_file,
            &format!("/recordTypes/{record_index}/hooks/facility-registered-v1")
        )["sourcePointer"],
        "/recordTypes/1/hooks/0"
    );

    let action_index = item_index(&model["actions"], "register-facility");
    assert_eq!(
        source_binding(&model, module_file, &format!("/actions/{action_index}"))["sourcePointer"],
        "/actions/0"
    );
    let input_index = item_index(&model["actions"][action_index]["inputs"], "facility-code");
    assert_eq!(
        source_binding(
            &model,
            module_file,
            &format!("/actions/{action_index}/inputs/{input_index}")
        )["sourcePointer"],
        "/actions/0/inputs/0"
    );
}

#[test]
fn model_source_bindings_cover_proposal_hooks_and_project_inventories() {
    let project = tempfile::tempdir().unwrap();
    let source = std::fs::read_to_string(
        fixture_path("products/breg/examples/minimal").join("registry.yaml"),
    )
    .unwrap()
    .replacen(
        "        retention: {mode: retain}\n",
        "        retention: {mode: retain}\n        hooks:\n          - id: proposal-observer\n            handler: {type: url, destinationId: proposal-events}\n",
        1,
    );
    std::fs::write(project.path().join("registry.yaml"), source).unwrap();
    let model = explain("model", project.path());
    let action_index = item_index(&model["actions"], "register-contact");
    assert_eq!(
        source_binding(
            &model,
            "registry.yaml",
            &format!("/actions/{action_index}/execution/proposal/hooks/0")
        )["sourcePointer"],
        "/actions/1/execution/proposal/hooks/0"
    );
    for collection in ["datasets", "accessProfiles"] {
        for index in 0..model[collection].as_array().unwrap().len() {
            source_binding(&model, "registry.yaml", &format!("/{collection}/{index}"));
        }
    }

    let facility = explain("model", &fixture_path("products/breg/acceptance/facility"));
    for collection in ["reviewAuthorities", "statisticalDatasets"] {
        for index in 0..facility[collection].as_array().unwrap().len() {
            source_binding(
                &facility,
                "registry.yaml",
                &format!("/{collection}/{index}"),
            );
        }
    }
    let permit_index = item_index(&facility["recordTypes"], "permit");
    let derived_index = item_index(
        &facility["recordTypes"][permit_index]["fields"],
        "expiring-soon",
    );
    assert_eq!(
        source_binding(
            &facility,
            "modules/facility-core/module.yaml",
            &format!("/recordTypes/{permit_index}/fields/{derived_index}")
        )["sourcePointer"],
        "/extendRecordTypes/0/derived/0/fields/0"
    );
}

#[test]
fn model_field_types_describe_unprojected_text_without_a_query_join() {
    let project = tempfile::tempdir().unwrap();
    let source = std::fs::read_to_string(
        fixture_path("products/breg/examples/minimal").join("registry.yaml"),
    )
    .unwrap()
    .replace(
        "id: name, type: string, required: true, minimumLength: 1",
        "id: name, type: text, required: true",
    )
    .replace(
        "readableFields: [name, email, jurisdiction]",
        "readableFields: [email, jurisdiction]",
    );
    std::fs::write(project.path().join("registry.yaml"), source).unwrap();
    let model = explain("model", project.path());
    let fields = model["recordTypes"][0]["fields"].as_array().unwrap();
    let field = |id: &str| fields.iter().find(|field| field["id"] == id).unwrap();
    assert_eq!(field("name")["fieldType"]["type"], "text");
    assert_eq!(field("email")["fieldType"]["type"], "string");
    let queries = explain("queries", project.path());
    assert!(queries["operations"]
        .as_array()
        .unwrap()
        .iter()
        .all(|operation| {
            operation["apiFields"]
                .as_array()
                .unwrap()
                .iter()
                .all(|field| field["field"] != "name")
        }));
    let schema = load_schema("ModelExplanation");
    assert!(schema.is_valid(&model));
    for invalid in [Value::Null, json!("text")] {
        let mut changed = model.clone();
        changed["recordTypes"][0]["fields"][0]["fieldType"] = invalid;
        assert!(!schema.is_valid(&changed));
    }
    let mut missing = model;
    missing["recordTypes"][0]["fields"][0]
        .as_object_mut()
        .unwrap()
        .remove("fieldType");
    assert!(!schema.is_valid(&missing));
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
        if *name == "facility" {
            let availability = explanation["routes"]
                .as_array()
                .expect("routes array")
                .iter()
                .find(|route| route["id"] == "actions.register-facility.availability")
                .expect("reference-target Action availability route");
            assert_eq!(availability["actionRouteKind"], "availability");
            assert_eq!(availability["operation"], "invoke");
            assert_eq!(availability["requiresIdempotencyKey"], false);
        }
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
    let project = fixture_path("products/breg/examples/minimal");
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
        ["draft", "submitted", "cancelled", "applied", "rejected"]
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
    let project = fixture_path("products/breg/examples/facility");
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
    let project = fixture_path("products/breg/examples/minimal");
    for (subject, contract) in [
        ("model", "ModelExplanation"),
        ("access", "AccessExplanation"),
        ("routes", "RoutesExplanation"),
        ("queries", "QueriesExplanation"),
        ("events", "EventsExplanation"),
        ("actions", "ActionsExplanation"),
        ("proposals", "ProposalsExplanation"),
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

#[test]
fn explain_proposals_matches_contract_and_filters_immediate_actions() {
    for (label, relative) in FIXTURES {
        let project = fixture_path(relative);
        let proposals = explain("proposals", &project);
        assert_matches_contract(label, "ProposalsExplanation", &proposals);
        let actions = explain("actions", &project);
        let expected = actions["actions"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|action| action["execution"]["mode"] == "proposal")
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(proposals["actions"], json!(expected), "{label}");
    }
    let mut proposals = explain(
        "proposals",
        &fixture_path("products/breg/examples/facility"),
    );
    assert!(!proposals["actions"].as_array().unwrap().is_empty());
    proposals["actions"][0]["execution"]["mode"] = json!("immediate");
    assert!(!load_schema("ProposalsExplanation").is_valid(&proposals));
}

fn format_registry(root: &Path) -> Value {
    let path = root.join("products/platform/config-formats.yaml");
    registry_platform_yaml::Reader::new(path.display().to_string())
        .scan(&std::fs::read(&path).unwrap())
        .expect("format registry parses")
        .expect("format registry is not empty")
        .to_json_value()
}

#[test]
fn registered_examples_match_current_formatter_bytes_and_schemas() {
    let root = repo_root();
    let registry = format_registry(&root);
    let formats = registry["formats"].as_array().expect("registered formats");
    let project = fixture_path("products/breg/examples/facility");
    for (subject, contract, slug) in [
        ("model", "ModelExplanation", "model-explanation"),
        ("access", "AccessExplanation", "access-explanation"),
        ("actions", "ActionsExplanation", "actions-explanation"),
        ("proposals", "ProposalsExplanation", "proposals-explanation"),
        ("routes", "RoutesExplanation", "routes-explanation"),
        ("queries", "QueriesExplanation", "queries-explanation"),
        ("events", "EventsExplanation", "events-explanation"),
        ("access", "AccessPreview", "access-preview"),
        ("lifecycle", "LifecycleExplanation", "lifecycle-explanation"),
    ] {
        let id = format!("breg/{slug}");
        let registration = formats
            .iter()
            .find(|format| format["id"] == id)
            .unwrap_or_else(|| panic!("{id} is registered"));
        let path = root.join(registration["example"].as_str().expect("example path"));
        let bytes = std::fs::read(&path).unwrap_or_else(|error| panic!("{path:?}: {error}"));
        let example: Value = serde_json::from_slice(&bytes).expect("registered example parses");
        assert_matches_contract(slug, contract, &example);
        assert_eq!(example["apiVersion"], registration["current"]["apiVersion"]);
        assert_eq!(example["kind"], registration["current"]["kind"]);
        let schema = load_schema_document(contract);
        assert_eq!(schema["$id"], registration["schema"]["id"]);
        assert_eq!(
            registration["schema"]["path"],
            json!(format!(
                "products/breg/contracts/explain/{contract}.schema.json"
            ))
        );
        let current = match contract {
            "LifecycleExplanation" => explain_lifecycle_report()["explanation"].clone(),
            "AccessPreview" => explain_with_scenario(
                &fixture_path(
                    "crates/registry-bregctl/tests/fixtures/retained-native/access-review",
                ),
                &root.join(ACCESS_SCENARIOS[0].1),
            ),
            _ => explain(subject, &project),
        };
        assert_matches_contract(slug, contract, &current);
        let mut expected = serde_json::to_vec_pretty(&current).unwrap();
        expected.push(b'\n');
        assert_eq!(
            bytes, expected,
            "{path:?} differs from current formatter bytes"
        );
    }
}

#[test]
fn authored_display_examples_pin_every_presentation_surface() {
    let root = repo_root();
    let project = fixture_path("products/breg/fixtures/authoring-display");
    for (subject, contract) in [
        ("model", "ModelExplanation"),
        ("access", "AccessExplanation"),
        ("actions", "ActionsExplanation"),
        ("proposals", "ProposalsExplanation"),
    ] {
        let current = explain(subject, &project);
        assert_matches_contract("authored display", contract, &current);
        let path = root.join(format!(
            "products/breg/examples/formats/explain/authored-display-{subject}-explanation.json"
        ));
        let bytes = std::fs::read(&path).unwrap_or_else(|error| panic!("{path:?}: {error}"));
        let mut expected = serde_json::to_vec_pretty(&current).unwrap();
        expected.push(b'\n');
        assert_eq!(
            bytes, expected,
            "{path:?} differs from current formatter bytes"
        );

        if subject != "proposals" {
            assert_eq!(
                current["accessProfiles"][0]["display"]["label"],
                "Directory editor"
            );
            assert_eq!(
                current["statisticalDatasets"][0]["display"]["label"],
                "Monthly entry counts"
            );
        }
        if matches!(subject, "model" | "actions") {
            assert_eq!(
                current["datasets"][0]["display"]["label"],
                "Directory records"
            );
            let record = &current["recordTypes"][0];
            let code = &record["fields"][item_index(&record["fields"], "code")];
            assert_eq!(code["display"]["label"], "Entry code");
            assert_eq!(
                record["hooks"]["entry-created"]["display"]["label"],
                "Entry notification"
            );
        }
        let actions = if subject == "access" {
            &current["actions"]["actions"]
        } else {
            &current["actions"]
        };
        let action = &actions[0];
        let code = &action["inputs"][item_index(&action["inputs"], "code")];
        let active = &action["inputs"][item_index(&action["inputs"], "active")];
        assert_eq!(code["display"]["label"], "Entry reference");
        assert_eq!(active["label"], active["apiName"]);
        assert!(active.get("display").is_none());
        assert_eq!(
            action["execution"]["proposal"]["hooks"][0]["display"]["label"],
            "Submission notification"
        );
    }
}

#[test]
fn registered_ctl_report_example_matches_current_actions_report() {
    let root = repo_root();
    let registry = format_registry(&root);
    let registration = registry["formats"]
        .as_array()
        .unwrap()
        .iter()
        .find(|format| format["id"] == "breg/ctl-report")
        .expect("ctl report is registered");
    let path = root.join(registration["example"].as_str().unwrap());
    let bytes = std::fs::read(&path).unwrap();
    let example: Value = serde_json::from_slice(&bytes).expect("registered report parses");
    assert_eq!(example["apiVersion"], registration["current"]["apiVersion"]);
    assert_eq!(example["kind"], registration["current"]["kind"]);
    assert_eq!(example["ok"], true);
    assert_eq!(example["command"], "explain");
    assert_matches_contract("ctl-report", "ActionsExplanation", &example["explanation"]);
    let project = fixture_path("products/breg/examples/facility");
    let output = bregctl(&[
        "--format",
        "json",
        "explain",
        "actions",
        project.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "{output:?}");
    let mut current = json_stdout(&output);
    // Only the committed example uses repository-relative diagnostic filenames.
    // CLI source addresses remain unchanged, including positions and related notes.
    let normalize_file = |location: &mut Value| {
        if let Some(file) = location["file"].as_str() {
            if let Ok(relative) = Path::new(file).strip_prefix(&root) {
                location["file"] = json!(relative.to_str().expect("source path is UTF-8"));
            }
        }
    };
    for finding in current["findings"].as_array_mut().unwrap() {
        if let Some(source) = finding.get_mut("source") {
            normalize_file(source);
        }
        if let Some(related) = finding.get_mut("related").and_then(Value::as_array_mut) {
            for location in related {
                normalize_file(location);
            }
        }
    }
    let mut expected = serde_json::to_vec_pretty(&current).unwrap();
    expected.push(b'\n');
    assert_eq!(
        bytes, expected,
        "{path:?} differs from current report bytes"
    );
}
