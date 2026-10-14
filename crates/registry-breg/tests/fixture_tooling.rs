// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "runtime", feature = "tooling"))]

use registry_breg::compiler::{CompileProfile, compile_project, module_digest};
use registry_breg::contract::{parse_module_yaml, parse_project_json, parse_project_yaml};
use registry_breg::fixtures::{FixtureError, LogicalReferenceRefusal, validate_fixture_journeys};

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
    let error = validate_fixture_journeys(unknown_key.as_bytes(), &registry).unwrap_err();
    assert_eq!(
        document_diagnostics(&error),
        [("config.unknown-key", "/unknownFixtureKey")]
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
        ("type: create", "type: tombstone"),
        ("label: first", "record_id: first"),
        ("recordType: widget", "recordType: registry_data"),
    ] {
        let changed = String::from_utf8(JOURNEY_SOURCE.to_vec())
            .expect("fixture is UTF-8")
            .replacen(from, to, 1);
        let error = validate_fixture_journeys(changed.as_bytes(), &registry)
            .expect_err("undeclared logical or physical reference is refused");
        assert!(matches!(
            underlying_fixture_error(&error),
            FixtureError::JourneyShapeRefused
                | FixtureError::JourneyDocument(_)
                | FixtureError::LogicalReferenceRefused
                | FixtureError::LogicalReference(_)
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
fn fixture_tooling_refused_logical_references_name_their_cause() {
    let registry = compiled_fixture();
    let source = String::from_utf8(JOURNEY_SOURCE.to_vec()).expect("fixture is UTF-8");

    for (label, from, to, refusal) in [
        (
            "field the entity does not declare",
            "data: {jurisdiction: zone-a, label: first, note: initial, quantity: 1}",
            "data: {jurisdiction: zone-a, label: first, canary-field: initial, quantity: 1}",
            LogicalReferenceRefusal::UnknownField,
        ),
        (
            "request body without a field",
            "data: {jurisdiction: zone-a, label: first, note: initial, quantity: 1}",
            "data: {}",
            LogicalReferenceRefusal::EmptyRequestBody,
        ),
        (
            "step identifier outside the stable subset",
            "- id: create-widget",
            "- id: create_widget_canary",
            LogicalReferenceRefusal::StepIdentifier,
        ),
        (
            "step naming an entity and an action",
            "recordType: widget\n        accessProfile: operator",
            "recordType: widget\n        action: canary-action\n        accessProfile: operator",
            LogicalReferenceRefusal::EntityOrAction,
        ),
        (
            "capture no earlier step declares",
            "recordCapture: first-widget}",
            "recordCapture: canary-widget}",
            LogicalReferenceRefusal::CaptureSource,
        ),
    ] {
        let changed = source.replacen(from, to, 1);
        assert_ne!(changed, source, "{label} mutation did not apply");
        let error = validate_fixture_journeys(changed.as_bytes(), &registry)
            .expect_err("a refused logical reference is reported");
        assert_eq!(
            underlying_fixture_error(&error),
            &FixtureError::LogicalReference(refusal),
            "{label} returned {error:?}"
        );
        assert!(
            !format!("{error:?}").contains("canary"),
            "{label} echoed an authored value: {error:?}"
        );
    }

    let concealed = compiled_fixture_without_writable_note();
    let error = validate_fixture_journeys(JOURNEY_SOURCE, &concealed)
        .expect_err("a field the grant cannot write is refused");
    assert_eq!(
        underlying_fixture_error(&error),
        &FixtureError::LogicalReference(LogicalReferenceRefusal::FieldNotWritable),
        "{error:?}"
    );
}

#[test]
fn fixture_tooling_direct_claims_accept_bounded_strings_and_sets_without_widening() {
    let registry = compiled_crud_alias_fixture();
    let journey = |value: &str| {
        format!(
            r#"apiVersion: id.registrystack.org/formats/breg/journeys/v1
kind: BRegJourneys
journeys:
  - id: claim-set-query
    steps:
      - id: query-people
        recordType: person
        accessProfile: registrar
        claims:
          principal: fixture-registrar
          purpose: case-management
          directClaims: {{jurisdiction: {value}}}
        request: {{type: query, select: [personCode]}}
        expect: {{outcome: success, status: 200, count: 0}}
"#
        )
    };
    let maximum_set = serde_json::to_string(
        &(0..64)
            .map(|index| format!("zone-{index}"))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let maximum_value = format!(r#"["{}"]"#, "a".repeat(256));
    for value in [
        "zone-a",
        "[zone-a]",
        "[zone-b, zone-a]",
        &maximum_set,
        &maximum_value,
    ] {
        validate_fixture_journeys(journey(value).as_bytes(), &registry)
            .expect("existing scalar and bounded string-set claims validate");
    }
    let oversized_set = serde_json::to_string(
        &(0..65)
            .map(|index| format!("zone-{index}"))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    for value in [
        "[]".to_owned(),
        "[zone-a, zone-a]".to_owned(),
        r#"[""]"#.to_owned(),
        r#"["zone\na"]"#.to_owned(),
        format!(r#"["{}"]"#, "a".repeat(257)),
        format!(r#"["{}"]"#, "é".repeat(129)),
        "a".repeat(257),
        oversized_set,
    ] {
        let error = validate_fixture_journeys(journey(&value).as_bytes(), &registry)
            .expect_err("invalid or oversized claim values fail before execution");
        assert_eq!(
            underlying_fixture_error(&error),
            &FixtureError::AuthorityWideningRefused
        );
    }
    for value in ["[zone-a, 7]", "[true]", "[{}]", "null", "7"] {
        assert!(matches!(
            validate_fixture_journeys(journey(value).as_bytes(), &registry).unwrap_err(),
            FixtureError::JourneyDocument(_)
        ));
    }
    for changed in [
        journey("[zone-a, zone-b]").replace(
            "directClaims: {jurisdiction:",
            "directClaims: {unknown_claim:",
        ),
        journey("[zone-a, zone-b]").replace(
            "purpose: case-management",
            "purpose: case-management\n          scopes: [registry:extra]",
        ),
    ] {
        let error = validate_fixture_journeys(changed.as_bytes(), &registry)
            .expect_err("sets do not permit undeclared names or scopes");
        assert_eq!(
            underlying_fixture_error(&error),
            &FixtureError::AuthorityWideningRefused
        );
    }
}

#[test]
fn fixture_tooling_crud_fields_accept_public_names_without_alias_overwrite() {
    let registry = compiled_crud_alias_fixture();
    let valid = br#"apiVersion: id.registrystack.org/formats/breg/journeys/v1
kind: BRegJourneys
journeys:
  - id: public-field-crud-flow
    steps:
      - id: create-person
        recordType: person
        accessProfile: registrar
        claims:
          principal: fixture-registrar
          purpose: case-management
          directClaims: {jurisdiction: zone-a}
        request:
          type: create
          data: {jurisdiction: zone-a, personCode: P-001, legalName: Alex Example}
        expect:
          outcome: success
          status: 201
          fields: {jurisdiction: zone-a, personCode: P-001, legalName: Alex Example}
        capture: person
      - id: query-person
        recordType: person
        accessProfile: registrar
        claims:
          principal: fixture-registrar
          purpose: case-management
          directClaims: {jurisdiction: zone-a}
        request: {type: query, select: [personCode, legalName], count: true}
        expect: {outcome: success, status: 200, count: 1}
      - id: patch-person
        recordType: person
        accessProfile: registrar
        claims:
          principal: fixture-registrar
          purpose: case-management
          directClaims: {jurisdiction: zone-a}
        request:
          type: patch
          recordCapture: person
          etagCapture: person
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
                FixtureError::LogicalReferenceRefused | FixtureError::LogicalReference(_)
            ),
            "{label} returned {error:?}"
        );
        assert!(!format!("{error:?}").contains(to));
    }
}

#[test]
fn fixture_tooling_immediate_actions_use_action_routes_and_public_input_names() {
    let registry = compiled_action_fixture();
    let valid = br#"apiVersion: id.registrystack.org/formats/breg/journeys/v1
kind: BRegJourneys
journeys:
  - id: immediate-action-flow
    steps:
      - id: create-household
        recordType: household
        accessProfile: household-seed
        claims:
          principal: fixture-seed
          purpose: case-management
          directClaims: {jurisdiction: zone-a}
        request:
          type: create
          data: {jurisdiction: zone-a, household-code: HH-001}
        expect:
          outcome: success
          status: 201
          fields: {jurisdiction: zone-a, household-code: HH-001}
        capture: household-before-action
      - id: read-action-condition
        action: register-household-contact
        accessProfile: contact-registrar
        claims:
          principal: fixture-registrar
          scopes: [registry:contact:register]
          purpose: contact-registration
          directClaims: {jurisdiction: zone-a}
        request:
          type: target-conditions
          input:
            householdId: {recordCapture: household-before-action}
        expect: {outcome: success, status: 200}
        capture: household-action-condition
      - id: invoke-contact-action
        action: register-household-contact
        accessProfile: contact-registrar
        claims:
          principal: fixture-registrar
          scopes: [registry:contact:register]
          purpose: contact-registration
          directClaims: {jurisdiction: zone-a}
        request:
          type: invoke
          idempotencyKey: register-contact
          input:
            householdId: {recordCapture: household-before-action}
            jurisdiction: zone-a
            personCode: P-001
            legalName: Alex Example
          preconditions:
            householdId: {conditionCapture: household-action-condition}
        expect: {outcome: success, status: 200}
        capture: contact-application
        captureResults:
          person: contact-person
          household: contact-household
      - id: replay-contact-action
        action: register-household-contact
        accessProfile: contact-registrar
        claims:
          principal: fixture-registrar
          scopes: [registry:contact:register]
          purpose: contact-registration
          directClaims: {jurisdiction: zone-a}
        request:
          type: invoke
          idempotencyKey: register-contact
          input:
            householdId: {recordCapture: household-before-action}
            jurisdiction: zone-a
            personCode: P-001
            legalName: Alex Example
          preconditions:
            householdId: {conditionCapture: household-action-condition}
        expect: {outcome: success, status: 200}
      - id: get-created-person
        recordType: person
        accessProfile: person-reader
        claims:
          principal: fixture-reader
          purpose: case-management
          directClaims: {jurisdiction: zone-a}
        request: {type: get, recordCapture: contact-person}
        expect: {outcome: success, status: 200}
"#;
    validate_fixture_journeys(valid, &registry)
        .expect("immediate action fixture validates through compiled action routes");

    let retired_marker = String::from_utf8(valid.to_vec())
        .expect("fixture is UTF-8")
        .replacen(
            "householdId: {recordCapture: household-before-action}",
            "householdId: {recordRef: household-before-action}",
            1,
        );
    let error = validate_fixture_journeys(retired_marker.as_bytes(), &registry)
        .expect_err("the retired record marker is refused");
    assert_eq!(
        underlying_fixture_error(&error),
        &FixtureError::LogicalReference(LogicalReferenceRefusal::RetiredRecordMarker)
    );
    assert!(
        error.to_string().contains("{recordCapture: <capture>}"),
        "the refusal names the replacement marker: {error}"
    );

    for (label, from, to) in [
        (
            "fake entity selector",
            "action: register-household-contact",
            "recordType: register-household-contact",
        ),
        (
            "unknown action selector",
            "action: register-household-contact",
            "action: missing-action",
        ),
        (
            "logical input in condition read",
            "householdId: {recordCapture: household-before-action}",
            "household: {recordCapture: household-before-action}",
        ),
        (
            "logical precondition role",
            "householdId: {conditionCapture: household-action-condition}",
            "household: {conditionCapture: household-action-condition}",
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
                    | FixtureError::JourneyDocument(_)
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
    assert!(
        internal_executor.contains("let final_facts = database_execution_facts(&runtime.pool)")
    );
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
    let valid = br#"apiVersion: id.registrystack.org/formats/breg/journeys/v1
kind: BRegJourneys
journeys:
  - id: spatial-query
    steps:
      - id: declared-bbox
        recordType: site
        accessProfile: map-reader
        claims: {principal: synthetic-reader, scopes: [sites.read]}
        request:
          type: query
          bbox: {west: "100.0", south: "13.0", east: "100.1", north: "13.1"}
          select: [code, location]
        expect: {outcome: success, status: 200, count: 0}
      - id: undeclared-bbox-runtime-refusal
        recordType: site
        accessProfile: directory-reader
        claims: {principal: synthetic-reader, scopes: [sites.read]}
        request:
          type: query
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
    let list_with_bbox = br#"apiVersion: id.registrystack.org/formats/breg/journeys/v1
kind: BRegJourneys
journeys:
  - id: list-shape
    steps:
      - id: list-bbox
        recordType: site
        accessProfile: map-reader
        claims: {principal: synthetic-reader, scopes: [sites.read]}
        request:
          type: list
          bbox: {west: "100.0", south: "13.0", east: "100.1", north: "13.1"}
        expect: {outcome: success, status: 200, count: 0}
"#;
    let error = validate_fixture_journeys(list_with_bbox, &registry).unwrap_err();
    assert_eq!(
        document_diagnostics(&error),
        [("config.unknown-key", "/journeys/0/steps/0/request/bbox")],
        "the refusal names the member the list shape does not accept: {error}"
    );
    assert_eq!(document_position(&error), (12, 11));

    let read_path_with_bbox = br#"apiVersion: id.registrystack.org/formats/breg/journeys/v1
kind: BRegJourneys
journeys:
  - id: path-shape
    steps:
      - id: path-bbox
        recordType: site
        accessProfile: map-reader
        claims: {principal: synthetic-reader, scopes: [sites.read]}
        request:
          type: read-path
          path: children
          recordCapture: created-site
          bbox: {west: "100.0", south: "13.0", east: "100.1", north: "13.1"}
        expect: {outcome: success, status: 200, count: 0}
"#;
    let error = validate_fixture_journeys(read_path_with_bbox, &registry).unwrap_err();
    assert_eq!(
        document_diagnostics(&error),
        [("config.unknown-key", "/journeys/0/steps/0/request/bbox")],
        "the refusal names the member the read-path shape does not accept: {error}"
    );
    assert_eq!(document_position(&error), (14, 11));
}

/// Dropping the row boundary field from `writableFields` leaves every create
/// unable to name the column the INSERT policy pins to the caller's claim, so
/// the refusal has to say that rather than report an anonymous reference.
#[test]
fn fixture_tooling_names_the_row_boundary_when_a_create_cannot_write_its_field() {
    let registry = compiled_fixture_with_project(|source| {
        source.replace(
            "writableFields: [jurisdiction, label, note, quantity]",
            "writableFields: [label, note, quantity]",
        )
    });
    let error = validate_fixture_journeys(JOURNEY_SOURCE, &registry)
        .expect_err("a create naming an unwritable row boundary field is refused");
    assert_eq!(
        underlying_fixture_error(&error),
        &FixtureError::CreateRowBoundaryNotWritable
    );
    let message = error.to_string();
    assert!(
        message.contains("row boundary") && message.contains("writableFields"),
        "the refusal names the cause and the fix: {message}"
    );
    assert!(
        message.starts_with("journeys[0].steps[0]:"),
        "the refusal keeps its step location: {message}"
    );
}

fn compiled_fixture() -> registry_breg::CompiledRegistry {
    compiled_fixture_with_project(|source| source)
}

fn compiled_fixture_with_project(
    edit: impl FnOnce(String) -> String,
) -> registry_breg::CompiledRegistry {
    let module = parse_module_yaml(MODULE_SOURCE).expect("module fixture parses");
    let project_source = edit(
        String::from_utf8(PROJECT_TEMPLATE.to_vec())
            .expect("project fixture is UTF-8")
            .replace("MODULE_DIGEST", &module_digest(&module)),
    )
    .into_bytes();
    let project = parse_project_yaml(&project_source).expect("project fixture parses");
    compile_project(&project, &[module], CompileProfile::Production)
        .expect("fixture project compiles in Production")
}

fn compiled_fixture_without_writable_note() -> registry_breg::CompiledRegistry {
    let module = parse_module_yaml(MODULE_SOURCE).expect("module fixture parses");
    let project_source = String::from_utf8(PROJECT_TEMPLATE.to_vec())
        .expect("project fixture is UTF-8")
        .replace("MODULE_DIGEST", &module_digest(&module))
        .replace(
            "writableFields: [jurisdiction, label, note, quantity]",
            "writableFields: [jurisdiction, label, quantity]",
        )
        .into_bytes();
    let project = parse_project_yaml(&project_source).expect("project fixture parses");
    compile_project(&project, &[module], CompileProfile::Production)
        .expect("fixture project without a writable note compiles in Production")
}

fn compiled_crud_alias_fixture() -> registry_breg::CompiledRegistry {
    let project = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"fixture-crud-aliases","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[{
            "id":"person","primaryDataset":"test-dataset","route":"people","mutationMode":"mutable","classification":"restricted",
            "fields":[
              {"id":"jurisdiction","type":"string","maximumLength":32,"required":true,"classification":"restricted"},
              {"id":"person-code","apiName":"personCode","type":"string","maximumLength":64,"required":true,"classification":"restricted"},
              {"id":"legal-name","apiName":"legalName","type":"string","maximumLength":160,"required":true,"classification":"restricted"}
            ],
            "constraints":[{"type":"unique","fields":["person-code"]}]
          }],
          "accessProfiles":[{
            "id":"registrar","default":true,"principalClaim":"registry_principal","requiredScopes":"unrestricted","requiredPurposes":["case-management"],
            "permissions":{"records":[{
              "recordType":"person","operations":["create","get","list","patch"],
              "readableFields":["jurisdiction","person-code","legal-name"],
              "writableFields":["jurisdiction","person-code","legal-name"],
              "filterableFields":["jurisdiction","person-code"],
              "sortableFields":["person-code"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}],
              "allowCount":true
            }]}
          }]
        }"#,
    )
    .expect("CRUD alias fixture source parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("CRUD alias fixture compiles")
}

fn compiled_action_fixture() -> registry_breg::CompiledRegistry {
    let project = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"fixture-immediate-actions","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[{
            "id":"person","primaryDataset":"test-dataset","route":"people","mutationMode":"mutable","classification":"restricted",
            "fields":[
              {"id":"jurisdiction","type":"string","maximumLength":32,"required":true,"classification":"restricted"},
              {"id":"person-code","apiName":"personCode","type":"string","maximumLength":64,"required":true,"classification":"restricted"},
              {"id":"legal-name","apiName":"legalName","type":"string","maximumLength":160,"required":true,"classification":"restricted"}
            ],
            "constraints":[{"type":"unique","fields":["person-code"]}]
          },{
            "id":"household","primaryDataset":"test-dataset","route":"households","mutationMode":"mutable","classification":"restricted",
            "fields":[
              {"id":"jurisdiction","type":"string","maximumLength":32,"required":true,"classification":"restricted"},
              {"id":"household-code","type":"string","maximumLength":64,"required":true,"classification":"restricted"},
              {"id":"contact-person","apiName":"contactPerson","type":"reference","target":"person","classification":"restricted"}
            ]
          },{
            "id":"group-membership","primaryDataset":"test-dataset","route":"group-memberships","mutationMode":"mutable","classification":"restricted",
            "fields":[
              {"id":"jurisdiction","type":"string","maximumLength":32,"required":true,"classification":"restricted"},
              {"id":"person","type":"reference","target":"person","required":true,"classification":"restricted"},
              {"id":"household","type":"reference","target":"household","required":true,"classification":"restricted"}
            ]
          }],
          "actions":[{"execution":{"mode":"immediate"},
            "id":"register-household-contact",
            "inputs":[
              {"id":"household","apiName":"householdId","type":"reference","target":"household","required":true,"classification":"restricted"},
              {"id":"jurisdiction","type":"string","maximumLength":32,"required":true,"classification":"restricted"},
              {"id":"person-code","apiName":"personCode","type":"string","maximumLength":64,"required":true,"classification":"restricted"},
              {"id":"legal-name","apiName":"legalName","type":"string","maximumLength":160,"required":true,"classification":"restricted"}
            ],
            "plan":{"type":"fixed","effects":[
              {"id":"person","target":{"recordType":"person"},"operation":"create",
                "set":{"jurisdiction":{"fromInput":"jurisdiction"},"person-code":{"fromInput":"person-code"},"legal-name":{"fromInput":"legal-name"}}},
              {"id":"membership","target":{"recordType":"group-membership"},"operation":"create",
                "set":{"jurisdiction":{"fromInput":"jurisdiction"},"person":{"fromEffect":"person"},"household":{"fromInput":"household"}}},
              {"id":"household","target":{"fromInput":"household"},"operation":"patch",
                "set":{"contact-person":{"fromEffect":"person"}}}
            ]}
          }],
          "accessProfiles":[{
            "id":"household-seed","default":true,"principalClaim":"registry_principal","requiredScopes":"unrestricted","requiredPurposes":["case-management"],
            "permissions":{"records":[{
              "recordType":"household","operations":["create","get"],"readableFields":["jurisdiction","household-code","contact-person"],
              "writableFields":["jurisdiction","household-code"],"rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            }]}
          },{
            "id":"contact-registrar","default":true,"principalClaim":"registry_principal",
            "requiredScopes":["registry:contact:register"],"requiredPurposes":["contact-registration"],
            "permissions":{"actions":[{
              "action":"register-household-contact","operations":["invoke"],
              "targets":[
                {"recordType":"household","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]},
                {"recordType":"person","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]},
                {"recordType":"group-membership","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}
              ],
              "results":["person","household"]
            }]}
          },{
            "id":"person-reader","default":true,"principalClaim":"registry_principal","requiredScopes":"unrestricted","requiredPurposes":["case-management"],
            "permissions":{"records":[{
              "recordType":"person","operations":["get"],"readableFields":["jurisdiction","person-code","legal-name"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            }]}
          }]
        }"#,
    )
    .expect("action fixture source parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("action fixture compiles")
}

/// The shared reader's `(code, path)` pairs for a refused journeys document.
fn document_diagnostics(error: &FixtureError) -> Vec<(&str, &str)> {
    let FixtureError::JourneyDocument(report) = error else {
        panic!("the shared reader refuses the journeys document: {error}");
    };
    report
        .diagnostics()
        .iter()
        .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
        .collect()
}

/// The `(line, column)` the shared reader reports for its only diagnostic.
fn document_position(error: &FixtureError) -> (usize, usize) {
    let FixtureError::JourneyDocument(report) = error else {
        panic!("the shared reader refuses the journeys document: {error}");
    };
    let [diagnostic] = report.diagnostics() else {
        panic!("one diagnostic: {error}");
    };
    let source = diagnostic
        .source
        .as_ref()
        .expect("the diagnostic has a position");
    (
        source.line.expect("the diagnostic has a line"),
        source.column.expect("the diagnostic has a column"),
    )
}

fn underlying_fixture_error(error: &FixtureError) -> &FixtureError {
    match error {
        FixtureError::StepFailed { error, .. } => error,
        other => other,
    }
}

fn compiled_spatial_fixture() -> registry_breg::CompiledRegistry {
    let project = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"spatial-fixture","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "package":{"sourceRevision":"spatial-fixture-source"},
          "recordTypes":[{
            "id":"site","primaryDataset":"test-dataset","route":"sites","mutationMode":"mutable","classification":"public",
            "fields":[
              {"id":"code","type":"string","maximumLength":32,"required":true,"classification":"public"},
              {"id":"location","type":"crs84-point","precision":9,"required":false,"classification":"public"}
            ],
            "geojson":{"geometryField":"location"}
          }],
          "accessProfiles":[
            {"id":"map-reader","default":true,"principalClaim":"sub","requiredScopes":["sites.read"],"permissions":{"records":[{
              "recordType":"site","operations":["get","list"],"readableFields":["code","location"],
              "spatialQueries":{"bbox":{"maximumLongitudeSpanDegrees":1,"maximumLatitudeSpanDegrees":1}},
              "rowBoundaries": "unrestricted"
            }]}},
            {"id":"directory-reader","principalClaim":"sub","requiredScopes":["sites.read"],"permissions":{"records":[{
              "recordType":"site","operations":["list"],"readableFields":["code"],
              "rowBoundaries": "unrestricted"
            }]}}
          ]
        }"#,
    )
    .expect("spatial project parses");
    compile_project(&project, &[], CompileProfile::Production).expect("spatial fixture compiles")
}

#[test]
fn fixture_journey_reader_reports_every_unknown_removed_and_anchored_key_with_its_position() {
    let registry = compiled_fixture();
    let source = String::from_utf8(JOURNEY_SOURCE.to_vec()).expect("fixture is UTF-8");

    let two_unknown = source
        .replacen(
            "        recordType: widget\n",
            "        recordType: widget\n        entityName: canary-one\n",
            1,
        )
        .replacen(
            "          type: create\n",
            "          type: create\n          payload: canary-two\n",
            1,
        );
    let error = validate_fixture_journeys(two_unknown.as_bytes(), &registry).unwrap_err();
    assert_eq!(
        document_diagnostics(&error),
        [
            ("config.unknown-key", "/journeys/0/steps/0/entityName"),
            ("config.unknown-key", "/journeys/0/steps/0/request/payload"),
        ]
    );
    let FixtureError::JourneyDocument(report) = &error else {
        unreachable!();
    };
    let positions = report
        .diagnostics()
        .iter()
        .map(|diagnostic| {
            let source = diagnostic.source.as_ref().expect("a position");
            (source.line, source.column)
        })
        .collect::<Vec<_>>();
    assert_eq!(positions, [(Some(8), Some(9)), (Some(16), Some(11))]);
    assert!(
        !format!("{error:?}").contains("canary"),
        "the refusal carries no authored value: {error:?}"
    );

    let removed = source.replacen(
        "request: {type: get, recordCapture: first-widget}",
        "request: {type: get, recordRef: first-widget}",
        1,
    );
    let error = validate_fixture_journeys(removed.as_bytes(), &registry).unwrap_err();
    assert_eq!(
        document_diagnostics(&error),
        [
            ("config.missing-key", "/journeys/0/steps/1/request"),
            (
                "config.removed-key",
                "/journeys/0/steps/1/request/recordRef"
            ),
        ]
    );
    assert!(
        error
            .to_string()
            .contains("Rename `recordRef` to `recordCapture`."),
        "the removed key names its replacement: {error}"
    );

    let operation = source.replacen(
        "          type: create\n",
        "          operation: create\n",
        1,
    );
    let error = validate_fixture_journeys(operation.as_bytes(), &registry).unwrap_err();
    assert_eq!(
        document_diagnostics(&error),
        [
            ("config.missing-key", "/journeys/0/steps/0/request"),
            (
                "config.removed-key",
                "/journeys/0/steps/0/request/operation"
            ),
        ]
    );
    assert!(
        error.to_string().contains("`type: submit-request`"),
        "the removed key names its replacement: {error}"
    );

    let anchored = source.replacen("        claims:\n", "        claims: &operator\n", 1);
    let error = validate_fixture_journeys(anchored.as_bytes(), &registry).unwrap_err();
    assert_eq!(document_diagnostics(&error)[0].0, "yaml.anchor");
}

#[test]
fn fixture_journey_refusals_name_the_document_path_the_journey_and_the_bound() {
    let registry = compiled_fixture();
    let source = String::from_utf8(JOURNEY_SOURCE.to_vec()).expect("fixture is UTF-8");

    let unknown_key = source.replacen("journeys:", "unknownFixtureKey: refused\njourneys:", 1);
    let error = validate_fixture_journeys(unknown_key.as_bytes(), &registry).unwrap_err();
    assert_eq!(
        document_diagnostics(&error),
        [("config.unknown-key", "/unknownFixtureKey")]
    );
    assert_eq!(document_position(&error), (3, 1));
    let human = error.to_string();
    assert!(
        human.contains("unknownFixtureKey") && human.contains("journeys"),
        "the refusal names the member and the members the grammar accepts: {human}"
    );

    let wrong_type = source.replacen("recordType: widget", "recordType: [widget]", 1);
    let error = validate_fixture_journeys(wrong_type.as_bytes(), &registry).unwrap_err();
    assert_eq!(
        document_diagnostics(&error),
        [("config.expected-string", "/journeys/0/steps/0/recordType")]
    );
    assert!(
        !format!("{error:?}").contains("widget"),
        "the refusal carries no authored value: {error:?}"
    );

    let wrong_version = source.replacen(
        "id.registrystack.org/formats/breg/journeys/v1",
        "id.registrystack.org/formats/breg/journeys/v2",
        1,
    );
    let error = validate_fixture_journeys(wrong_version.as_bytes(), &registry).unwrap_err();
    assert_eq!(
        document_diagnostics(&error),
        [("config.unsupported-api-version", "/apiVersion")]
    );
    assert!(
        error
            .to_string()
            .contains("id.registrystack.org/formats/breg/journeys/v1"),
        "the version refusal names the one version it accepts: {error}"
    );

    // A file written for the retired header has no `kind`: the reader names
    // the current header first, then the retired version names every rename.
    let retired_header = source.replacen(
        "apiVersion: id.registrystack.org/formats/breg/journeys/v1\nkind: BRegJourneys",
        "apiVersion: registry.registrystack.org/breg-journeys/v1",
        1,
    );
    assert_ne!(
        retired_header, source,
        "the retired header mutation applies"
    );
    let error = validate_fixture_journeys(retired_header.as_bytes(), &registry).unwrap_err();
    assert_eq!(
        document_diagnostics(&error),
        [("config.missing-envelope", "")]
    );
    assert!(
        error.to_string().contains("kind: BRegJourneys"),
        "the missing envelope names the current header: {error}"
    );
    let retired_version = source.replacen(
        "apiVersion: id.registrystack.org/formats/breg/journeys/v1",
        "apiVersion: registry.registrystack.org/breg-journeys/v1",
        1,
    );
    let error = validate_fixture_journeys(retired_version.as_bytes(), &registry).unwrap_err();
    assert_eq!(
        document_diagnostics(&error),
        [("config.retired-api-version", "/apiVersion")]
    );
    let human = error.to_string();
    assert!(
        human.contains("id.registrystack.org/formats/breg/journeys/v1")
            && human.contains("kind: BRegJourneys"),
        "the retired header names its replacement: {human}"
    );

    let not_local = source.replacen("- id: widget-lifecycle", "- id: Widget-Lifecycle", 1);
    let error = validate_fixture_journeys(not_local.as_bytes(), &registry).unwrap_err();
    assert_eq!(
        document_diagnostics(&error),
        [("config.invalid-value", "/journeys/0/id")]
    );
    assert!(
        !format!("{error:?}").contains("Widget-Lifecycle"),
        "the refusal carries no authored value: {error:?}"
    );

    let unstable_id = source.replacen("- id: widget-lifecycle", "- id: widget_lifecycle", 1);
    let error = validate_fixture_journeys(unstable_id.as_bytes(), &registry).unwrap_err();
    let FixtureError::JourneyRefused {
        journey_index,
        journey_id,
        message,
    } = &error
    else {
        panic!("a journey refusal names the journey it belongs to: {error}");
    };
    assert_eq!(*journey_index, 0);
    assert_eq!(journey_id, "widget_lifecycle");
    assert!(
        message.contains("stable identifier"),
        "the refusal says what an id may contain: {message}"
    );
    assert!(
        error
            .to_string()
            .starts_with("journeys[0] `widget_lifecycle`"),
        "the rendered refusal names the journey: {error}"
    );

    let (_, first_journey) = source
        .split_once("  - id: widget-lifecycle")
        .expect("fixture contains a journey");
    let duplicated_journey = format!("{source}  - id: widget-lifecycle{first_journey}");
    let error = validate_fixture_journeys(duplicated_journey.as_bytes(), &registry).unwrap_err();
    let FixtureError::JourneyRefused {
        journey_index,
        journey_id,
        message,
    } = &error
    else {
        panic!("a duplicate journey id names the journey it repeats: {error}");
    };
    assert_eq!(*journey_index, 1);
    assert_eq!(journey_id, "widget-lifecycle");
    assert!(
        message.contains("already"),
        "the refusal says the id is already declared: {message}"
    );

    let empty = br#"apiVersion: id.registrystack.org/formats/breg/journeys/v1
kind: BRegJourneys
journeys:
  - id: empty-journey
    steps: []
"#;
    let error = validate_fixture_journeys(empty, &registry).unwrap_err();
    let FixtureError::JourneyRefused {
        journey_index,
        journey_id,
        message,
    } = &error
    else {
        panic!("a journey without steps names the journey: {error}");
    };
    assert_eq!(*journey_index, 0);
    assert_eq!(journey_id, "empty-journey");
    assert!(
        message.contains("128"),
        "the refusal names the bound it enforces: {message}"
    );
}

#[test]
fn fixture_tooling_handler_refusals_and_negative_inputs_use_the_compiled_contract() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/native-models/products/breg/acceptance/person-registration-rhai");
    let mut project =
        parse_project_yaml(&std::fs::read(root.join("registry.yaml")).unwrap()).unwrap();
    project
        .entities
        .iter_mut()
        .find(|entity| entity.id == "register")
        .unwrap()
        .fields
        .iter_mut()
        .find(|field| field.id == "register-code")
        .unwrap()
        .pattern = Some(".*".to_owned());
    let assets = project
        .functions
        .iter()
        .map(|function| registry_breg::contract::ModuleAssetSource {
            module: None,
            path: function.source.clone(),
            bytes: std::fs::read(root.join(&function.source)).unwrap(),
        })
        .collect::<Vec<_>>();
    let registry = registry_breg::compiler::compile_project_with_assets(
        &project,
        &[],
        &assets,
        CompileProfile::Authoring,
    )
    .unwrap();
    let source = std::fs::read_to_string(root.join("tests/journeys.yaml")).unwrap();
    validate_fixture_journeys(source.as_bytes(), &registry)
        .expect("the complete authored handler and native-pattern suite preflights");
    for changed in [
        source.replacen("identifier: \"0123456789012\"", "identifier: null", 1),
        source.replace(
            "registerId:\n          recordCapture: active-register",
            "registerId: null",
        ),
        source.replace(
            "recordCapture: active-register",
            "recordCapture: uncaptured-register",
        ),
        source.replace("      entityId: person\n", ""),
        source.replace("      fieldId: identifier\n", ""),
        source.replace("entityId: person", "entityId: unknown"),
        source.replace("fieldId: identifier", "fieldId: unknown"),
        source.replace("fieldId: identifier", "fieldId: display-name"),
        source.replace(
            "entityId: person\n      fieldId: identifier",
            "entityId: register\n      fieldId: register-code",
        ),
        source.replace(
            "status: 409\n      problemCode: mutation.conflict\n      entityId:",
            "status: 400\n      problemCode: request.invalid\n      entityId:",
        ),
        source.replace("      refusalCode: blank-name\n", ""),
        source.replace("refusalCode: blank-name", "refusalCode: unknown"),
        source.replace("status: 422", "status: 400"),
        source.replace(
            "problemCode: action.refused",
            "problemCode: mutation.conflict",
        ),
        source.replace("givenName:", "undeclaredInput:"),
        source.replace(
            "problemCode: request.invalid",
            "problemCode: mutation.conflict",
        ),
    ] {
        assert!(validate_fixture_journeys(changed.as_bytes(), &registry).is_err());
    }
}
