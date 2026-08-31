// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "runtime", feature = "tooling"))]

use registry_server::compiler::{compile_project, module_digest, CompileProfile};
use registry_server::contract::{parse_module_yaml, parse_project_json, parse_project_yaml};
use registry_server::fixtures::{validate_fixture_journeys, FixtureError};

const PROJECT_TEMPLATE: &[u8] = include_bytes!("fixtures/fixture-tooling/project.yaml");
const MODULE_SOURCE: &[u8] = include_bytes!("fixtures/fixture-tooling/module.yaml");
const JOURNEY_SOURCE: &[u8] = include_bytes!("fixtures/fixture-tooling/journeys.yaml");

#[test]
fn fixture_tooling_strict_parser_refuses_unclosed_authority_and_source_shapes() {
    let registry = compiled_fixture();
    let suite = validate_fixture_journeys(JOURNEY_SOURCE, &registry).expect("strict suite");
    assert_eq!(suite.journey_ids(), ["widget-lifecycle"]);

    let unknown_key = String::from_utf8(JOURNEY_SOURCE.to_vec())
        .expect("fixture is UTF-8")
        .replacen("journeys:", "unknownFixtureKey: refused\njourneys:", 1);
    assert_eq!(
        validate_fixture_journeys(unknown_key.as_bytes(), &registry).unwrap_err(),
        FixtureError::JourneyShapeRefused
    );

    let duplicate = String::from_utf8(JOURNEY_SOURCE.to_vec())
        .expect("fixture is UTF-8")
        .replacen("id: get-widget", "id: create-widget", 1);
    assert_eq!(
        validate_fixture_journeys(duplicate.as_bytes(), &registry).unwrap_err(),
        FixtureError::DuplicateIdentifier
    );

    let source = String::from_utf8(JOURNEY_SOURCE.to_vec()).expect("fixture is UTF-8");
    let (_, first_journey) = source
        .split_once("  - id: widget-lifecycle")
        .expect("fixture contains a journey");
    let duplicated_step_ids_in_another_journey =
        format!("{source}  - id: widget-lifecycle-copy{}", first_journey);
    assert_eq!(
        validate_fixture_journeys(duplicated_step_ids_in_another_journey.as_bytes(), &registry)
            .expect("step identifiers are scoped to one journey")
            .journey_ids(),
        ["widget-lifecycle", "widget-lifecycle-copy"]
    );

    for (from, to) in [
        ("accessProfile: operator", "accessProfile: administrator"),
        ("operation: create", "operation: tombstone"),
        ("label: first", "record_id: first"),
        ("entity: widget", "entity: registry_data"),
    ] {
        let changed = String::from_utf8(JOURNEY_SOURCE.to_vec())
            .expect("fixture is UTF-8")
            .replacen(from, to, 1);
        let error = validate_fixture_journeys(changed.as_bytes(), &registry)
            .expect_err("undeclared logical or physical reference is refused");
        assert!(matches!(
            error,
            FixtureError::JourneyShapeRefused | FixtureError::LogicalReferenceRefused
        ));
        assert!(!format!("{error:?}").contains(to));
    }

    let oversized = vec![b'x'; 1024 * 1024 + 1];
    assert_eq!(
        validate_fixture_journeys(&oversized, &registry).unwrap_err(),
        FixtureError::JourneyTooLarge
    );
}

#[test]
fn fixture_tooling_request_actions_are_closed_and_get_precondition_bound() {
    let registry = compiled_request_fixture();
    let valid = br#"apiVersion: registry.registrystack.org/server-journeys/v1
journeys:
  - id: request-action-flow
    steps:
      - id: create-request
        entity: correction-request
        accessProfile: submitter
        claims: &submitter_claims {principal: submitter}
        request:
          operation: create
          data: {target: 11111111-1111-1111-1111-111111111111, value: corrected}
        expect:
          outcome: success
          status: 201
          fields: {target: 11111111-1111-1111-1111-111111111111, value: corrected}
        capture: created-request
      - id: get-before-submit
        entity: correction-request
        accessProfile: reviewer
        claims: &reviewer_claims {principal: reviewer}
        request: {operation: get, recordRef: created-request}
        expect:
          outcome: success
          status: 200
          fields: {target: 11111111-1111-1111-1111-111111111111, value: corrected}
        capture: before-submit
      - id: submit-request
        entity: correction-request
        accessProfile: submitter
        claims: *submitter_claims
        request: {operation: submit_request, recordRef: before-submit, etagRef: before-submit}
        expect: {outcome: success, status: 200}
      - id: get-before-approve
        entity: correction-request
        accessProfile: reviewer
        claims: *reviewer_claims
        request: {operation: get, recordRef: created-request}
        expect:
          outcome: success
          status: 200
          fields: {target: 11111111-1111-1111-1111-111111111111, value: corrected}
        capture: before-approve
      - id: approve-request
        entity: correction-request
        accessProfile: reviewer
        claims: *reviewer_claims
        request:
          operation: approve_request
          stage: review
          recordRef: before-approve
          etagRef: before-approve
          proposalVersionRef: before-approve
          effectDigestRef: before-approve
        expect: {outcome: success, status: 200}
      - id: revise-request
        entity: correction-request
        accessProfile: submitter
        claims: *submitter_claims
        request: {operation: revise_request, recordRef: before-approve, etagRef: before-approve, rebase: true}
        expect: {outcome: success, status: 200}
"#;
    validate_fixture_journeys(valid, &registry).expect("closed request action fixture validates");

    for (label, from, to) in [
        (
            "raw body",
            "request: {operation: submit_request, recordRef: before-submit, etagRef: before-submit}",
            "request: {operation: submit_request, recordRef: before-submit, etagRef: before-submit, body: {}}",
        ),
        (
            "missing revise rebase",
            "request: {operation: revise_request, recordRef: before-approve, etagRef: before-approve, rebase: true}",
            "request: {operation: revise_request, recordRef: before-approve, etagRef: before-approve}",
        ),
        (
            "action capture",
            "expect: {outcome: success, status: 200}\n      - id: get-before-approve",
            "expect: {outcome: success, status: 200}\n        capture: submitted-request\n      - id: get-before-approve",
        ),
        (
            "create precondition",
            "request: {operation: submit_request, recordRef: before-submit, etagRef: before-submit}",
            "request: {operation: submit_request, recordRef: created-request, etagRef: created-request}",
        ),
        (
            "uppercase digest",
            "proposalVersionRef: before-approve\n          effectDigestRef: before-approve",
            "proposalVersion: 1\n          effectDigest: sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
    ] {
        let changed = String::from_utf8(valid.to_vec())
            .expect("fixture is UTF-8")
            .replacen(from, to, 1);
        let error = match validate_fixture_journeys(changed.as_bytes(), &registry) {
            Ok(_) => panic!("{label} shape was not refused"),
            Err(error) => error,
        };
        assert!(
            matches!(
                error,
                FixtureError::JourneyShapeRefused | FixtureError::LogicalReferenceRefused
            ),
            "{label} returned {error:?}"
        );
        assert!(!format!("{error:?}").contains(to));
    }
}

#[test]
fn postgres_fixture_runner_has_no_caller_supplied_response_path() {
    let implementation = include_str!("../src/fixtures.rs");
    let runner = implementation
        .split_once("impl PostgresFixtureTestRunner {")
        .and_then(|(_, tail)| tail.split_once("/// Completed result"))
        .map(|(runner, _)| runner)
        .expect("fixture runner implementation remains structurally visible");
    for forbidden in [
        "pub fn next_request",
        "pub async fn accept_response",
        "pub async fn accept_current_response",
        "pub async fn finish",
    ] {
        assert!(
            !runner.contains(forbidden),
            "fixture execution exposed a caller-controlled completion seam"
        );
    }
    let public_methods = runner
        .match_indices("pub async fn ")
        .map(|(offset, _)| {
            runner[offset + "pub async fn ".len()..]
                .split_once('(')
                .map(|(name, _)| name)
                .expect("public async method has an argument list")
        })
        .collect::<Vec<_>>();
    assert_eq!(public_methods, ["prepare", "run_all"]);
    assert!(!runner.contains("pub fn "));
    assert!(runner.contains("prepared: &PreparedServer"));
    let prepare_signature = runner
        .split_once("pub async fn prepare(")
        .and_then(|(_, tail)| tail.split_once(") -> Result<Self, FixtureError>"))
        .map(|(signature, _)| signature)
        .expect("fixture prepare signature remains structurally visible");
    assert!(!prepare_signature.contains("pool: RuntimePool"));
    assert!(!prepare_signature.contains("Router"));
    assert!(!prepare_signature.contains("Response"));
    assert!(runner.contains(".fixture_runtime()"));
    assert!(runner.contains(".call(request)"));
}

#[test]
fn production_schema_test_executor_has_no_raw_server_source_or_receipt_seams() {
    let implementation = include_str!("../src/fixtures.rs");
    let executor = implementation
        .split_once("pub async fn execute_schema_test(")
        .and_then(|(_, tail)| tail.split_once("#[cfg(feature = \"postgres-test\")]"))
        .map(|(executor, _)| executor)
        .expect("production executor implementation remains structurally visible");
    let signature = executor
        .split_once(") -> Result<SchemaTestReceipt, FixtureError>")
        .map(|(signature, _)| signature)
        .expect("production executor signature remains structurally visible");
    for forbidden in [
        "PreparedServer",
        "Router",
        "RuntimePool",
        "Response",
        "SchemaTestSources",
    ] {
        assert!(
            !signature.contains(forbidden),
            "production executor exposed a raw fixture authority seam"
        );
    }
    assert!(signature.contains("database: PreparedSchemaTestDatabase"));
    assert!(signature.contains("package: &PreparedPackage"));
    assert!(signature.contains("credentials: SchemaTestCredentialBindings"));
    let internal_executor = implementation
        .split_once("async fn execute_schema_test_with_key_source(")
        .and_then(|(_, tail)| tail.split_once("struct SchemaTestRuntime"))
        .map(|(executor, _)| executor)
        .expect("private executor implementation remains structurally visible");
    assert!(
        internal_executor
            .find("let credential_map = credentials.into_map(suite)")
            .expect("credentials are closed")
            < internal_executor
                .find("let pool = database.pool()")
                .expect("database is first accessed"),
        "credential shape and mode must fail before database I/O"
    );
    assert!(internal_executor.contains("let final_facts = database_execution_facts(&runtime.pool)"));
    assert!(internal_executor.contains("final_facts != runtime.initial_facts"));
    assert!(internal_executor.contains("!runtime.readiness.is_ready().await"));
    assert!(!implementation.contains("pub fn build_schema_test_receipt"));
    assert!(!implementation.contains("pub struct SuccessfulFixtureJourneys"));
    assert!(implementation.contains("pub fn validate_schema_test_receipt_for_package("));
}

fn compiled_fixture() -> registry_server::CompiledRegistry {
    let module = parse_module_yaml(MODULE_SOURCE).expect("module fixture parses");
    let project_source = String::from_utf8(PROJECT_TEMPLATE.to_vec())
        .expect("project fixture is UTF-8")
        .replace("MODULE_DIGEST", &module_digest(&module))
        .into_bytes();
    let project = parse_project_yaml(&project_source).expect("project fixture parses");
    compile_project(&project, &[module], CompileProfile::Production)
        .expect("fixture project compiles in Production")
}

fn compiled_request_fixture() -> registry_server::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"fixture-request-actions","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"target","route":"targets","mutationMode":"mutable","changeControl":{"requiredFor":["patch"]},
            "fields":[{"id":"label","type":"string","required":true,"maxLength":64,"classification":"public"}]
          },{
            "id":"correction-request","route":"correction-requests","mutationMode":"mutable","classification":"public",
            "fields":[
              {"id":"target","type":"reference","target":"target","required":true,"classification":"public"},
              {"id":"value","type":"string","required":true,"maxLength":64,"classification":"public"}
            ],
            "changeRequest":{
              "effects":[{"target":{"fromField":"target"},"operation":"patch","set":{"label":{"fromField":"value"}}}],
              "review":{"stages":[{"id":"review","approvals":1,"excludeSubmitter":true}]}
            }
          }],
          "accessProfiles":[{
            "id":"submitter","default":true,"principalClaim":"registry_principal","grants":[{
              "entity":"correction-request","operations":["create","submit_request","revise_request","cancel_request"],"readableFields":["target","value"],"writableFields":["target","value"]
            }]
          },{
            "id":"reviewer","default":true,"principalClaim":"registry_principal","grants":[{
              "entity":"correction-request","operations":["get","list","approve_request","reject_request","request_revision"],"readableFields":["target","value"],
              "reviewStages":[{"stage":"review","targets":[{"entity":"target","readableFields":["label"],"rowBoundaries":[]}]}]
            }]
          },{
            "id":"applier","default":true,"principalClaim":"registry_principal","grants":[{
              "entity":"correction-request","operations":["apply_request"],"readableFields":["target"],
              "applyTargets":[{"entity":"target","rowBoundaries":[]}]
            }]
          }]
        }"#,
    )
    .expect("request fixture source parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("request fixture compiles")
}
