// SPDX-License-Identifier: Apache-2.0

//! Live HTTP proof for the protected effective-contract readback and the
//! whole-contract execution precondition. Every test uses the real Adapter
//! binary and a real PostgreSQL journal. Absence of the database URL fails;
//! it never turns this security boundary into a skipped test.
#![cfg(feature = "postgres-test")]

#[allow(dead_code)]
#[path = "support/served/mod.rs"]
mod served_harness;

use std::process::Command;

use registry_adapter::effective_contract::{
    PIN_PROBLEM_CODE, UNAVAILABLE_PROBLEM_CODE, WELL_KNOWN_PATH,
};
use registry_platform_testing::{access_token_test_key, jwks_from_private_jwk};
use serde_json::{json, Value};
use served_harness::upstream::{Response, UpstreamDouble};
use served_harness::{
    capture, copy_example_project, copy_govstack_project, replace_pack_script,
    replace_profile_text, Served, AUDIENCE, ISSUER, PASSWORD, USERNAME,
};

const CONTRACT_HEADER: &str = "x-registry-adapter-contract";
const REQUEST_ID_HEADER: &str = "x-registry-request-id";

fn header<'a>(head: &'a str, name: &str) -> &'a str {
    head.lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
        .unwrap_or_else(|| panic!("response has no {name} header: {head}"))
}

fn assert_protocol_problem(
    status: u16,
    head: &str,
    body: &Value,
    expected_status: u16,
    code: &str,
    title: &str,
) {
    assert_eq!(status, expected_status, "{body}");
    assert_eq!(header(head, "content-type"), "application/problem+json");
    let request_id = header(head, REQUEST_ID_HEADER);
    assert!(!request_id.is_empty(), "the Adapter mints a request id");
    assert_eq!(
        body,
        &json!({
            "code": code,
            "status": expected_status,
            "title": title,
            "requestId": request_id,
        }),
        "the protocol problem is closed and carries the response request id"
    );
}

fn assert_profile_problem_request_id(head: &str, body: &Value) {
    let request_id = header(head, REQUEST_ID_HEADER);
    assert!(!request_id.is_empty(), "the Adapter mints a request id");
    if let Some(body_request_id) = body.get("requestId") {
        assert_eq!(
            body_request_id, request_id,
            "a profile problem slot and its response header share one Adapter request id"
        );
    }
}

fn offline_contract(upstream_url: &str) -> Value {
    let directory = tempfile::tempdir().expect("an offline contract scratch directory");
    let runtime = directory.path().join("runtime.yaml");
    std::fs::write(
        &runtime,
        format!(
            r#"apiVersion: id.registrystack.org/formats/adapter/runtime/v1alpha1
kind: AdapterRuntimeConfig
id: effective-contract-test
endpoints:
  - endpoint: tracker
    baseUrl: {upstream_url}
    credential:
      type: basic
      usernameRef: secret:env/CONTRACT_TEST_USERNAME
      passwordRef: secret:env/CONTRACT_TEST_PASSWORD
listener:
  bind: 127.0.0.1:1
database:
  runtimeUrlRef: secret:env/CONTRACT_TEST_DB_URL
  migrationUrlRef: secret:env/CONTRACT_TEST_DB_URL
  testOnlyPlaintext: true
oidc:
  issuer: {ISSUER}
  audience: {AUDIENCE}
  allowInsecureHttp: true
  jwksSource:
    type: static
    documentRef: secret:env/CONTRACT_TEST_JWKS
allowedClients:
  - synthetic-client
allowedPrivateCidrs:
  - 192.168.0.0/16
audit:
  retentionDays: 90
idempotency:
  responseRetentionSeconds: 86400
cursorKeyRef: secret:env/CONTRACT_TEST_CURSOR_KEY
"#
        ),
    )
    .expect("write the offline runtime config");
    let key = access_token_test_key(jsonwebtoken::Algorithm::ES256);
    let output = Command::new(env!("CARGO_BIN_EXE_adapter"))
        .args(["effective-contract", "--runtime-config"])
        .arg(&runtime)
        .arg("--project")
        .arg(Served::example_project())
        .arg("--profile")
        .arg(Served::example_profile())
        .arg("--pack")
        .arg(Served::example_pack())
        .env("CONTRACT_TEST_USERNAME", USERNAME)
        .env("CONTRACT_TEST_PASSWORD", PASSWORD)
        .env(
            "CONTRACT_TEST_DB_URL",
            "postgresql://synthetic@localhost/synthetic",
        )
        .env(
            "CONTRACT_TEST_JWKS",
            jwks_from_private_jwk(&key).to_string(),
        )
        .env(
            "CONTRACT_TEST_CURSOR_KEY",
            "synthetic-cursor-key-0123456789!",
        )
        .output()
        .expect("run the offline effective-contract command");
    assert!(
        output.status.success(),
        "offline export failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("the offline contract is JSON")
}

#[tokio::test]
async fn protected_readback_is_the_cached_offline_contract_and_checks_journal_readiness() {
    let upstream = UpstreamDouble::start();
    let served = Served::start(&upstream.url("")).await;
    let token = served.token("");

    let unauthenticated = served.get(WELL_KNOWN_PATH, None);
    assert_eq!(unauthenticated.0, 401, "{}", unauthenticated.2);
    assert_profile_problem_request_id(&unauthenticated.1, &unauthenticated.2);
    assert_ne!(
        unauthenticated.2["code"], UNAVAILABLE_PROBLEM_CODE,
        "authentication happens before journal readiness"
    );

    let first = served.get(WELL_KNOWN_PATH, Some(&token));
    let second = served.get(WELL_KNOWN_PATH, Some(&token));
    assert_eq!(first.0, 200, "{}", first.2);
    assert_eq!(second.0, 200, "{}", second.2);
    assert!(!header(&first.1, REQUEST_ID_HEADER).is_empty());
    assert!(!header(&second.1, REQUEST_ID_HEADER).is_empty());
    assert_eq!(
        first.2, second.2,
        "readback uses one immutable startup contract"
    );
    assert_eq!(
        first.2["readiness"],
        json!({"ready": true, "configuration": "ready", "journal": "ready"})
    );
    let offline = offline_contract(&upstream.url(""));
    assert_eq!(first.2["digest"], offline["digest"]);
    assert_eq!(first.2["contract"], offline["contract"]);
    assert_eq!(
        upstream.request_count(),
        0,
        "readiness never probes the source"
    );

    served
        .execute_sql(
            "DELETE FROM adapter_schema_migrations \
             WHERE version = (SELECT max(version) FROM adapter_schema_migrations)",
        )
        .await;
    let drift = served.get(WELL_KNOWN_PATH, Some(&token));
    assert_protocol_problem(
        drift.0,
        &drift.1,
        &drift.2,
        503,
        UNAVAILABLE_PROBLEM_CODE,
        "Effective contract unavailable",
    );
    assert_eq!(
        upstream.request_count(),
        0,
        "readiness still avoids the source"
    );

    served
        .execute_sql("DROP TABLE adapter_schema_migrations")
        .await;
    let unavailable = served.get(WELL_KNOWN_PATH, Some(&token));
    assert_protocol_problem(
        unavailable.0,
        &unavailable.1,
        &unavailable.2,
        503,
        UNAVAILABLE_PROBLEM_CODE,
        "Effective contract unavailable",
    );
}

#[tokio::test]
async fn authentication_and_admission_precede_the_pin_which_precedes_body_and_source() {
    let upstream = UpstreamDouble::start();
    let served = Served::start(&upstream.url("")).await;
    let read_token = served.token("records.read");
    let write_token = served.token("records.write");
    let wrong = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let partial_body = br#"{"#;

    let unauthenticated = served.request_declaring(
        "POST",
        "/v1/records/person",
        None,
        &[
            ("Content-Type", "application/json"),
            (CONTRACT_HEADER, wrong),
        ],
        1_000_000,
        partial_body,
    );
    assert_eq!(unauthenticated.0, 401, "{}", unauthenticated.2);
    assert_profile_problem_request_id(&unauthenticated.1, &unauthenticated.2);

    let forbidden = served.request_declaring(
        "POST",
        "/v1/records/person",
        Some(&read_token),
        &[
            ("Content-Type", "application/json"),
            (CONTRACT_HEADER, wrong),
        ],
        1_000_000,
        partial_body,
    );
    assert_eq!(forbidden.0, 403, "{}", forbidden.2);
    assert_profile_problem_request_id(&forbidden.1, &forbidden.2);

    let mismatch = served.request_declaring(
        "POST",
        "/v1/records/person",
        Some(&write_token),
        &[
            ("Content-Type", "application/json"),
            (CONTRACT_HEADER, wrong),
        ],
        1_000_000,
        partial_body,
    );
    assert_protocol_problem(
        mismatch.0,
        &mismatch.1,
        &mismatch.2,
        412,
        PIN_PROBLEM_CODE,
        "Effective contract precondition failed",
    );

    let contract = served.get(WELL_KNOWN_PATH, Some(&read_token));
    assert_eq!(contract.0, 200, "{}", contract.2);
    let digest = contract.2["digest"].as_str().expect("contract digest");
    let repeated = served.request(
        "GET",
        "/v1/records/person/wk4JlTuVO9o",
        Some(&read_token),
        &[(CONTRACT_HEADER, digest), (CONTRACT_HEADER, digest)],
        b"",
    );
    assert_protocol_problem(
        repeated.0,
        &repeated.1,
        &repeated.2,
        412,
        PIN_PROBLEM_CODE,
        "Effective contract precondition failed",
    );

    assert_eq!(
        upstream.request_count(),
        0,
        "no refused call reaches the source"
    );
    assert_eq!(
        served.journal_kinds().await,
        vec![
            "callRefused".to_owned(),
            "callRefused".to_owned(),
            "callRefused".to_owned(),
        ],
        "the access refusal and two admitted pin refusals are journaled, without exchanges"
    );
    let pin_refusals = served
        .journal_details("callRefused")
        .await
        .into_iter()
        .filter(|detail| detail["code"] == PIN_PROBLEM_CODE)
        .collect::<Vec<_>>();
    assert_eq!(
        pin_refusals,
        vec![
            json!({"code": PIN_PROBLEM_CODE, "status": 412}),
            json!({"code": PIN_PROBLEM_CODE, "status": 412}),
        ],
        "the durable refusal detail is protocol metadata only"
    );

    let (source_status, source_body) = capture("get-found");
    upstream.respond_with(vec![Response::json(source_status, &source_body)]);
    let pinned = served.request(
        "GET",
        "/v1/records/person/EeBJ3Sn9uLg",
        Some(&read_token),
        &[(CONTRACT_HEADER, digest)],
        b"",
    );
    assert_eq!(pinned.0, 200, "{}", pinned.2);
    assert!(!header(&pinned.1, REQUEST_ID_HEADER).is_empty());
    assert_eq!(upstream.request_count(), 1, "the exact pin admits the call");

    served
        .execute_sql("DROP TABLE adapter_journal_events")
        .await;
    let journal_failure = served.request_declaring(
        "POST",
        "/v1/records/person",
        Some(&write_token),
        &[
            ("Content-Type", "application/json"),
            (CONTRACT_HEADER, wrong),
        ],
        1_000_000,
        partial_body,
    );
    assert_protocol_problem(
        journal_failure.0,
        &journal_failure.1,
        &journal_failure.2,
        503,
        UNAVAILABLE_PROBLEM_CODE,
        "Effective contract unavailable",
    );
    assert_eq!(
        upstream.request_count(),
        1,
        "journal failure still answers before body completion or source I/O"
    );
}

#[tokio::test]
async fn a_valid_concrete_collision_is_unserved_before_router_construction() {
    let upstream = UpstreamDouble::start();
    let directory = tempfile::tempdir().expect("a copied Adapter project");
    copy_example_project(directory.path());
    replace_profile_text(
        directory.path(),
        "    path: /v1/records/{type}\n",
        "    path: /.well-known/registry-adapter/{type}\n",
    );
    replace_profile_text(
        directory.path(),
        "    path: /v1/records/{type}\n",
        "    path: /.well-known/registry-adapter/{type}\n",
    );
    let project_path = directory.path().join("project.yaml");
    let project = std::fs::read_to_string(&project_path).expect("the copied project is readable");
    std::fs::write(
        &project_path,
        project.replace("person", "effective-contract"),
    )
    .expect("write the valid concrete-collision project");

    let served = Served::start_with_project(&upstream.url(""), directory.path()).await;
    let token = served.token("");
    let readback = served.get(WELL_KNOWN_PATH, Some(&token));
    assert_eq!(readback.0, 200, "{}", readback.2);
    let unserved = readback.2["contract"]["unserved"]
        .as_array()
        .expect("the contract carries unserved operations");
    for binding in ["effective-contract-search", "effective-contract-create"] {
        let colliding = unserved
            .iter()
            .find(|entry| entry["bindingId"] == binding)
            .unwrap_or_else(|| panic!("the {binding} collision is explicitly unserved"));
        assert_eq!(
            colliding["reasonCode"],
            "adapter.operation.reserved-facade-path"
        );
        assert_eq!(
            colliding["reason"],
            "the facade path is reserved for the Adapter effective-contract route"
        );
    }
    assert_eq!(
        upstream.request_count(),
        0,
        "the built-in protected route wins without source I/O"
    );
}

fn non_paginated_filter_project() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("a copied GovStack Adapter project");
    copy_govstack_project(directory.path());
    replace_pack_script(
        directory.path(),
        "scripts/org-unit-filter.rhai",
        r#"fn org_unit_filter(exchange) {
    let filters = exchange.properties.AdapterFilters;
    if filters == () || filters.region == () {
        throw "the read carries no region filter";
    }
    filters.region
}
"#,
    );
    replace_profile_text(
        directory.path(),
        r#"    requestEnvelope: '{"selector": "byRecordId", "values": {"recordId": "{{recordId}}"}}'"#,
        r#"    requestEnvelope: '{"selector": "byRecordId", "values": {"recordId": "{{recordId}}"}, "criteria": {{filters}}}'"#,
    );
    let path = directory.path().join("project.yaml");
    let project = std::fs::read_to_string(&path).expect("the copied project is readable");
    let project = project.replace(
        "      - name: tracked_entity_type\n        type: string\n        required: true",
        "      - name: tracked_entity_type\n        type: string\n        required: true\n      - name: region\n        type: boolean\n        required: true",
    );
    let project = project.replace(
        "  - id: person-get\n    operation: records-get\n    recordType: persons\n    route: person-fetch\n    maximumUpstreamCalls: 4",
        "  - id: person-get\n    operation: records-get\n    recordType: persons\n    route: person-search\n    filters:\n      - region\n    maximumUpstreamCalls: 4",
    );
    let project = project.replace(
        "  - id: person-lookup\n    operation: records-lookup\n    recordType: persons\n    route: person-fetch\n    maximumUpstreamCalls: 4",
        "  - id: person-lookup\n    operation: records-lookup\n    recordType: persons\n    route: person-search\n    filters:\n      - region\n    maximumUpstreamCalls: 4",
    );
    std::fs::write(path, project).expect("write the filtered non-paginated project");
    directory
}

#[tokio::test]
async fn non_paginated_get_and_post_reads_require_and_install_typed_filters() {
    let upstream = UpstreamDouble::start();
    let directory = non_paginated_filter_project();
    let served = Served::start_with_project(&upstream.url(""), directory.path()).await;
    let token = served.token("records.read");
    let get_path = "/v1/collections/persons/records/EeBJ3Sn9uLg";
    let post_path = "/v1/collections/persons/lookup";

    let missing = served.get(get_path, Some(&token));
    assert_eq!(missing.0, 422, "{}", missing.2);
    let unknown = served.get(&format!("{get_path}?other=true"), Some(&token));
    assert_eq!(unknown.0, 400, "{}", unknown.2);
    let repeated = served.get(
        &format!("{get_path}?region=true&region=false"),
        Some(&token),
    );
    assert_eq!(repeated.0, 400, "{}", repeated.2);
    let invalid = served.get(&format!("{get_path}?region=not-a-boolean"), Some(&token));
    assert_eq!(invalid.0, 422, "{}", invalid.2);
    assert_eq!(
        upstream.request_count(),
        0,
        "invalid GET filters never reach the source"
    );

    let (status, body) = capture("search-page");
    upstream.respond_with(vec![Response::json(status, &body)]);
    let _get = served.get(&format!("{get_path}?region=true"), Some(&token));
    assert_eq!(upstream.request_count(), 1, "the valid GET makes one call");
    assert!(
        upstream.requests()[0].target.contains("orgUnits=true"),
        "the typed GET filter reaches AdapterFilters and the source: {}",
        upstream.requests()[0].target
    );

    let missing = served.post(
        post_path,
        Some(&token),
        &json!({"selector": "byRecordId", "values": {"recordId": "EeBJ3Sn9uLg"}, "criteria": {}}),
    );
    assert_eq!(missing.0, 422, "{}", missing.2);
    let invalid = served.post(
        post_path,
        Some(&token),
        &json!({"selector": "byRecordId", "values": {"recordId": "EeBJ3Sn9uLg"}, "criteria": {"region": "not-a-boolean"}}),
    );
    assert_eq!(invalid.0, 422, "{}", invalid.2);
    assert_eq!(
        upstream.request_count(),
        1,
        "invalid POST filters never reach the source"
    );

    upstream.respond_with(vec![Response::json(status, &body)]);
    let _post = served.post(
        post_path,
        Some(&token),
        &json!({"selector": "byRecordId", "values": {"recordId": "EeBJ3Sn9uLg"}, "criteria": {"region": true}}),
    );
    assert_eq!(upstream.request_count(), 2, "the valid POST makes one call");
    assert!(
        upstream.requests()[1].target.contains("orgUnits=true"),
        "the typed POST filter reaches AdapterFilters and the source: {}",
        upstream.requests()[1].target
    );
}
