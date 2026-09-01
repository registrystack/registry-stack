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
    let error = validate_fixture_journeys(duplicate.as_bytes(), &registry).unwrap_err();
    assert_eq!(
        underlying_fixture_error(&error),
        &FixtureError::DuplicateIdentifier
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
            underlying_fixture_error(&error),
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
fn fixture_tooling_crud_fields_accept_public_names_without_alias_overwrite() {
    let registry = compiled_crud_alias_fixture();
    let valid = br#"apiVersion: registry.registrystack.org/server-journeys/v1
journeys:
  - id: public-field-crud-flow
    steps:
      - id: create-person
        entity: person
        accessProfile: registrar
        claims: &claims
          principal: fixture-registrar
          purpose: case-management
          directClaims: {jurisdiction: zone-a}
        request:
          operation: create
          data: {jurisdiction: zone-a, personCode: P-001, legalName: Alex Example}
        expect:
          outcome: success
          status: 201
          fields: {jurisdiction: zone-a, personCode: P-001, legalName: Alex Example}
        capture: person
      - id: query-person
        entity: person
        accessProfile: registrar
        claims: *claims
        request: {operation: query, select: [personCode, legalName], count: true}
        expect: {outcome: success, status: 200, count: 1}
      - id: patch-person
        entity: person
        accessProfile: registrar
        claims: *claims
        request:
          operation: patch
          recordRef: person
          etagRef: person
          changes:
            - {field: legalName, value: Alicia Example}
        expect:
          outcome: success
          status: 200
          fields: {jurisdiction: zone-a, personCode: P-001, legalName: Alicia Example}
"#;
    validate_fixture_journeys(valid, &registry)
        .expect("CRUD fixture accepts public API field names");

    for (label, from, to) in [
        (
            "create data duplicate alias",
            "personCode: P-001, legalName",
            "person-code: P-001, personCode: P-001, legalName",
        ),
        (
            "expectation duplicate alias",
            "fields: {jurisdiction: zone-a, personCode: P-001, legalName: Alex Example}",
            "fields: {jurisdiction: zone-a, person-code: P-001, personCode: P-001, legalName: Alex Example}",
        ),
        (
            "query duplicate alias",
            "select: [personCode, legalName]",
            "select: [person-code, personCode]",
        ),
        (
            "patch duplicate alias",
            "- {field: legalName, value: Alicia Example}",
            "- {field: legal-name, value: Alicia Example}\n            - {field: legalName, value: Alicia Example}",
        ),
        (
            "unknown public field",
            "legalName: Alex Example",
            "displayName: Alex Example",
        ),
    ] {
        let changed = String::from_utf8(valid.to_vec())
            .expect("fixture is UTF-8")
            .replacen(from, to, 1);
        let error = match validate_fixture_journeys(changed.as_bytes(), &registry) {
            Ok(_) => panic!("{label} fixture unexpectedly validated"),
            Err(error) => error,
        };
        assert!(
            matches!(
                underlying_fixture_error(&error),
                FixtureError::LogicalReferenceRefused
            ),
            "{label} returned {error:?}"
        );
        assert!(!format!("{error:?}").contains(to));
    }
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
                underlying_fixture_error(&error),
                FixtureError::JourneyShapeRefused | FixtureError::LogicalReferenceRefused
            ),
            "{label} returned {error:?}"
        );
        assert!(!format!("{error:?}").contains(to));
    }
}

#[test]
fn fixture_tooling_immediate_actions_use_action_routes_and_public_input_names() {
    let registry = compiled_action_fixture();
    let valid = br#"apiVersion: registry.registrystack.org/server-journeys/v1
journeys:
  - id: immediate-action-flow
    steps:
      - id: create-household
        entity: household
        accessProfile: household-seed
        claims: &seed_claims
          principal: fixture-seed
          purpose: case-management
          directClaims: {jurisdiction: zone-a}
        request:
          operation: create
          data: {jurisdiction: zone-a, household-code: HH-001}
        expect:
          outcome: success
          status: 201
          fields: {jurisdiction: zone-a, household-code: HH-001}
        capture: household-before-action
      - id: read-action-condition
        action: register-household-contact
        accessProfile: contact-registrar
        claims: &registrar_claims
          principal: fixture-registrar
          scopes: [registry:contact:register]
          purpose: contact-registration
          directClaims: {jurisdiction: zone-a}
        request:
          operation: target_conditions
          input:
            householdId: {recordRef: household-before-action}
        expect: {outcome: success, status: 200}
        capture: household-action-condition
      - id: invoke-contact-action
        action: register-household-contact
        accessProfile: contact-registrar
        claims: *registrar_claims
        request:
          operation: invoke
          idempotencyKey: register-contact
          input:
            householdId: {recordRef: household-before-action}
            jurisdiction: zone-a
            personCode: P-001
            legalName: Alex Example
          preconditions:
            householdId: {conditionRef: household-action-condition}
        expect: {outcome: success, status: 200}
        capture: contact-application
        captureResults:
          person: contact-person
          household: contact-household
      - id: replay-contact-action
        action: register-household-contact
        accessProfile: contact-registrar
        claims: *registrar_claims
        request:
          operation: invoke
          idempotencyKey: register-contact
          input:
            householdId: {recordRef: household-before-action}
            jurisdiction: zone-a
            personCode: P-001
            legalName: Alex Example
          preconditions:
            householdId: {conditionRef: household-action-condition}
        expect: {outcome: success, status: 200}
      - id: get-created-person
        entity: person
        accessProfile: person-reader
        claims:
          principal: fixture-reader
          purpose: case-management
          directClaims: {jurisdiction: zone-a}
        request: {operation: get, recordRef: contact-person}
        expect: {outcome: success, status: 200}
"#;
    validate_fixture_journeys(valid, &registry)
        .expect("immediate action fixture validates through compiled action routes");

    for (label, from, to) in [
        (
            "fake entity selector",
            "action: register-household-contact",
            "entity: register-household-contact",
        ),
        (
            "unknown action selector",
            "action: register-household-contact",
            "action: missing-action",
        ),
        (
            "logical input in condition read",
            "householdId: {recordRef: household-before-action}",
            "household: {recordRef: household-before-action}",
        ),
        (
            "logical precondition role",
            "householdId: {conditionRef: household-action-condition}",
            "household: {conditionRef: household-action-condition}",
        ),
        (
            "missing boundary claim",
            "directClaims: {jurisdiction: zone-a}",
            "directClaims: {}",
        ),
        (
            "ungranted result capture",
            "person: contact-person",
            "membership: contact-person",
        ),
    ] {
        let changed = String::from_utf8(valid.to_vec())
            .expect("fixture is UTF-8")
            .replacen(from, to, 1);
        let error = match validate_fixture_journeys(changed.as_bytes(), &registry) {
            Ok(_) => panic!("{label} fixture unexpectedly validated"),
            Err(error) => error,
        };
        assert!(
            matches!(
                underlying_fixture_error(&error),
                FixtureError::JourneyShapeRefused
                    | FixtureError::LogicalReferenceRefused
                    | FixtureError::AuthorityWideningRefused
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

#[test]
fn fixture_query_builder_encodes_closed_options_without_raw_query_escape() {
    let implementation = include_str!("../src/fixtures.rs");
    let request_builder = implementation
        .split_once("fn fixture_request(")
        .and_then(|(_, tail)| tail.split_once("fn fixture_query_options("))
        .map(|(builder, _)| builder)
        .expect("fixture request builder remains structurally visible");
    assert!(request_builder.contains("percent_encode_query_value(&step.access_profile"));
    assert!(request_builder.contains("percent_encode_query_value(&value"));
    assert!(!request_builder.contains("path.push_str(&value);"));
    assert!(!request_builder.contains("path.push_str(&step.access_profile);"));

    let query_builder = implementation
        .split_once("fn fixture_query_options(")
        .and_then(|(_, tail)| tail.split_once("fn json_body("))
        .map(|(builder, _)| builder)
        .expect("fixture query option builder remains structurally visible");
    assert!(query_builder.contains("parse_fixture_bbox(bbox)?.canonical_bbox_value()"));
    assert!(!query_builder.contains("bbox.query_value()"));
}

#[test]
fn fixture_query_dsl_accepts_only_compiled_bounded_bbox_authority() {
    let registry = compiled_spatial_fixture();
    let valid = br#"apiVersion: registry.registrystack.org/server-journeys/v1
journeys:
  - id: spatial-query
    steps:
      - id: declared-bbox
        entity: site
        accessProfile: map-reader
        claims: {}
        request:
          operation: query
          bbox: {west: "100.0", south: "13.0", east: "100.1", north: "13.1"}
          select: [code, location]
        expect: {outcome: success, status: 200, count: 0}
      - id: undeclared-bbox-runtime-refusal
        entity: site
        accessProfile: directory-reader
        claims: {}
        request:
          operation: query
          bbox: {west: "100.0", south: "13.0", east: "100.1", north: "13.1"}
          select: [code]
        expect: {outcome: refusal, status: 400, problemCode: request.invalid}
"#;
    validate_fixture_journeys(valid, &registry).expect("declared bbox and refusal preflight");

    let undeclared_success = String::from_utf8(valid.to_vec())
        .expect("fixture is UTF-8")
        .replace(
            "expect: {outcome: refusal, status: 400, problemCode: request.invalid}",
            "expect: {outcome: success, status: 200, count: 0}",
        );
    let error = validate_fixture_journeys(undeclared_success.as_bytes(), &registry).unwrap_err();
    assert_eq!(
        underlying_fixture_error(&error),
        &FixtureError::LogicalReferenceRefused
    );

    let malformed = String::from_utf8(valid.to_vec())
        .expect("fixture is UTF-8")
        .replace(r#"east: "100.1""#, r#"east: "bbox-sensitive-canary""#);
    let error = validate_fixture_journeys(malformed.as_bytes(), &registry).unwrap_err();
    assert_eq!(
        underlying_fixture_error(&error),
        &FixtureError::LogicalReferenceRefused
    );
    assert!(!format!("{error:?}").contains("bbox-sensitive-canary"));
}

#[test]
fn fixture_bbox_does_not_extend_list_or_read_path_shapes() {
    let registry = compiled_spatial_fixture();
    let list_with_bbox = br#"apiVersion: registry.registrystack.org/server-journeys/v1
journeys:
  - id: list-shape
    steps:
      - id: list-bbox
        entity: site
        accessProfile: map-reader
        claims: {}
        request:
          operation: list
          bbox: {west: "100.0", south: "13.0", east: "100.1", north: "13.1"}
        expect: {outcome: success, status: 200, count: 0}
"#;
    assert_eq!(
        validate_fixture_journeys(list_with_bbox, &registry).unwrap_err(),
        FixtureError::JourneyShapeRefused
    );

    let read_path_with_bbox = br#"apiVersion: registry.registrystack.org/server-journeys/v1
journeys:
  - id: path-shape
    steps:
      - id: path-bbox
        entity: site
        accessProfile: map-reader
        claims: {}
        request:
          operation: read_path
          path: children
          recordRef: created-site
          bbox: {west: "100.0", south: "13.0", east: "100.1", north: "13.1"}
        expect: {outcome: success, status: 200, count: 0}
"#;
    assert_eq!(
        validate_fixture_journeys(read_path_with_bbox, &registry).unwrap_err(),
        FixtureError::JourneyShapeRefused
    );
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
          "registry":{"id":"fixture-request-actions","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[{
            "id":"target","primaryDataset":"test-dataset","route":"targets","mutationMode":"mutable","changeControl":{"requiredFor":["patch"]},
            "fields":[{"id":"label","type":"string","required":true,"maxLength":64,"classification":"public"}]
          },{
            "id":"correction-request","primaryDataset":"test-dataset","route":"correction-requests","mutationMode":"mutable","classification":"public",
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

fn compiled_crud_alias_fixture() -> registry_server::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"fixture-crud-aliases","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[{
            "id":"person","primaryDataset":"test-dataset","route":"people","mutationMode":"mutable","classification":"restricted",
            "fields":[
              {"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"restricted"},
              {"id":"person-code","apiName":"personCode","type":"string","maxLength":64,"required":true,"classification":"restricted"},
              {"id":"legal-name","apiName":"legalName","type":"string","maxLength":160,"required":true,"classification":"restricted"}
            ],
            "constraints":[{"kind":"unique","fields":["person-code"]}]
          }],
          "accessProfiles":[{
            "id":"registrar","default":true,"principalClaim":"registry_principal","requiredPurposes":["case-management"],
            "grants":[{
              "entity":"person","operations":["create","get","list","patch"],
              "readableFields":["jurisdiction","person-code","legal-name"],
              "writableFields":["jurisdiction","person-code","legal-name"],
              "filterableFields":["jurisdiction","person-code"],
              "sortableFields":["person-code"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}],
              "allowCount":true
            }]
          }]
        }"#,
    )
    .expect("CRUD alias fixture source parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("CRUD alias fixture compiles")
}

fn compiled_action_fixture() -> registry_server::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"fixture-immediate-actions","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[{
            "id":"person","primaryDataset":"test-dataset","route":"people","mutationMode":"mutable","classification":"restricted",
            "fields":[
              {"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"restricted"},
              {"id":"person-code","apiName":"personCode","type":"string","maxLength":64,"required":true,"classification":"restricted"},
              {"id":"legal-name","apiName":"legalName","type":"string","maxLength":160,"required":true,"classification":"restricted"}
            ],
            "constraints":[{"kind":"unique","fields":["person-code"]}]
          },{
            "id":"household","primaryDataset":"test-dataset","route":"households","mutationMode":"mutable","classification":"restricted",
            "fields":[
              {"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"restricted"},
              {"id":"household-code","type":"string","maxLength":64,"required":true,"classification":"restricted"},
              {"id":"contact-person","apiName":"contactPerson","type":"reference","target":"person","classification":"restricted"}
            ]
          },{
            "id":"group-membership","primaryDataset":"test-dataset","route":"group-memberships","mutationMode":"mutable","classification":"restricted",
            "fields":[
              {"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"restricted"},
              {"id":"person","type":"reference","target":"person","required":true,"classification":"restricted"},
              {"id":"household","type":"reference","target":"household","required":true,"classification":"restricted"}
            ]
          }],
          "actions":[{
            "id":"register-household-contact",
            "inputs":[
              {"id":"household","apiName":"householdId","type":"reference","target":"household","required":true,"classification":"restricted"},
              {"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"restricted"},
              {"id":"person-code","apiName":"personCode","type":"string","maxLength":64,"required":true,"classification":"restricted"},
              {"id":"legal-name","apiName":"legalName","type":"string","maxLength":160,"required":true,"classification":"restricted"}
            ],
            "effects":[
              {"id":"person","target":{"entity":"person"},"operation":"create",
                "set":{"jurisdiction":{"fromField":"jurisdiction"},"person-code":{"fromField":"person-code"},"legal-name":{"fromField":"legal-name"}}},
              {"id":"membership","target":{"entity":"group-membership"},"operation":"create",
                "set":{"jurisdiction":{"fromField":"jurisdiction"},"person":{"fromEffect":"person"},"household":{"fromField":"household"}}},
              {"id":"household","target":{"fromField":"household"},"operation":"patch",
                "set":{"contact-person":{"fromEffect":"person"}}}
            ]
          }],
          "accessProfiles":[{
            "id":"household-seed","default":true,"principalClaim":"registry_principal","requiredPurposes":["case-management"],
            "grants":[{
              "entity":"household","operations":["create","get"],"readableFields":["jurisdiction","household-code","contact-person"],
              "writableFields":["jurisdiction","household-code"],"rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            }]
          },{
            "id":"contact-registrar","default":true,"principalClaim":"registry_principal",
            "requiredScopes":["registry:contact:register"],"requiredPurposes":["contact-registration"],
            "grants":[{
              "action":"register-household-contact","operations":["invoke"],
              "targets":[
                {"entity":"household","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]},
                {"entity":"person","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]},
                {"entity":"group-membership","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}
              ],
              "results":["person","household"]
            }]
          },{
            "id":"person-reader","default":true,"principalClaim":"registry_principal","requiredPurposes":["case-management"],
            "grants":[{
              "entity":"person","operations":["get"],"readableFields":["jurisdiction","person-code","legal-name"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            }]
          }]
        }"#,
    )
    .expect("action fixture source parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("action fixture compiles")
}

fn underlying_fixture_error(error: &FixtureError) -> &FixtureError {
    match error {
        FixtureError::StepFailed { error, .. } => error,
        other => other,
    }
}

fn compiled_spatial_fixture() -> registry_server::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"spatial-fixture","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "package":{"environment":"local","instanceId":"spatial-fixture-instance","sequence":1,"sourceRevision":"spatial-fixture-source"},
          "entities":[{
            "id":"site","primaryDataset":"test-dataset","route":"sites","mutationMode":"mutable","classification":"public",
            "fields":[
              {"id":"code","type":"string","maxLength":32,"required":true,"classification":"public"},
              {"id":"location","type":"crs84-point","precision":9,"required":false,"classification":"public"}
            ],
            "geojson":{"geometryField":"location"}
          }],
          "accessProfiles":[
            {"id":"map-reader","default":true,"anonymous":true,"grants":[{
              "entity":"site","operations":["get","list"],"readableFields":["code","location"],
              "spatialQueries":{"bbox":{"maximumLongitudeSpanDegrees":1,"maximumLatitudeSpanDegrees":1}}
            }]},
            {"id":"directory-reader","anonymous":true,"grants":[{
              "entity":"site","operations":["list"],"readableFields":["code"]
            }]}
          ]
        }"#,
    )
    .expect("spatial project parses");
    compile_project(&project, &[], CompileProfile::Production).expect("spatial fixture compiles")
}
