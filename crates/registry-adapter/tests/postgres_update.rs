// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL-backed served PUT proof through the real Adapter binary and a
//! source-neutral synthetic route. Absence of `ADAPTER_TEST_DATABASE_URL` is
//! a failure, never a skip.
#![cfg(feature = "postgres-test")]

#[allow(dead_code)]
#[path = "support/served/mod.rs"]
mod served_harness;

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

use registry_adapter::effective_contract::{PIN_HEADER, WELL_KNOWN_PATH};
use registry_adapter_core::{
    derive_operation_request_schema, AdapterProfile, AdapterProject, ADAPTER_PROFILE_API_VERSION,
    ADAPTER_PROFILE_KIND, ADAPTER_PROJECT_API_VERSION, ADAPTER_PROJECT_KIND,
};
use registry_platform_yaml::{ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader};
use serde_json::{json, Value};
use served_harness::upstream::{Response, UpstreamDouble};
use served_harness::{digest_of, Served};

const UPDATE_PATH: &str = "/v1/records/person/person-1";
const PROFILE_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_PROFILE_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_PROFILE_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};
const PROJECT_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_PROJECT_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_PROJECT_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

struct RawResponse {
    status: u16,
    request_id: String,
    body: Vec<u8>,
}

fn response_header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
}

fn raw_request(
    served: &Served,
    method: &str,
    path: &str,
    token: Option<&str>,
    headers: &[(&str, &str)],
    body: &[u8],
) -> RawResponse {
    let mut stream = TcpStream::connect(("127.0.0.1", served.port)).expect("connect to facade");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("set facade timeout");
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    if let Some(token) = token {
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    stream.write_all(request.as_bytes()).expect("send head");
    stream.write_all(body).expect("send body");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("read facade reply");
    let head_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("facade reply has a header block");
    let head = std::str::from_utf8(&response[..head_end]).expect("facade headers are text");
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .expect("facade status");
    let request_id = response_header(head, "x-registry-request-id")
        .expect("facade response carries a request id")
        .to_owned();
    RawResponse {
        status,
        request_id,
        body: response[head_end + 4..].to_vec(),
    }
}

fn put(
    served: &Served,
    path: &str,
    token: Option<&str>,
    key: &str,
    pin: Option<&str>,
    body: &Value,
) -> RawResponse {
    let body = body.to_string();
    let mut headers = vec![
        ("Content-Type", "application/json"),
        ("Idempotency-Key", key),
    ];
    if let Some(pin) = pin {
        headers.push((PIN_HEADER, pin));
    }
    raw_request(served, "PUT", path, token, &headers, body.as_bytes())
}

fn post(
    served: &Served,
    path: &str,
    token: Option<&str>,
    key: &str,
    pin: Option<&str>,
    body: &Value,
) -> RawResponse {
    let body = body.to_string();
    let mut headers = vec![
        ("Content-Type", "application/json"),
        ("Idempotency-Key", key),
    ];
    if let Some(pin) = pin {
        headers.push((PIN_HEADER, pin));
    }
    raw_request(served, "POST", path, token, &headers, body.as_bytes())
}

fn request_record(id: &str, name: &str) -> Value {
    json!({
        "command": {
            "target": id,
            "record": {
                "record_identifier": "ordinary-domain-field",
                "name": name
            }
        }
    })
}

fn write_artifacts(directory: &Path, success_status: u16) {
    let source_profile =
        fs::read_to_string(Served::example_profile()).expect("read facade profile");
    let update_start = source_profile
        .find("  - id: records-update\n")
        .expect("update operation");
    let existing = r#"    responseEnvelope: '{"data": {{record}}, "meta": {"registryIdentifier": "registryIdentifier", "datasetIdentifier": "datasetIdentifier", "recordTypeIdentifier": "{{recordType}}"}}'"#;
    let relative = source_profile[update_start..]
        .find(existing)
        .expect("the update response envelope");
    let position = update_start + relative;
    let mut profile = source_profile;
    profile.replace_range(
        position..position + existing.len(),
        r#"    responseEnvelope: '{"result": {{record}}, "requestId": "{{requestId}}"}'"#,
    );
    let update_envelope = r#"    requestEnvelope: '{"data": {"recordIdentifier": "{{recordId}}", "domainData": {{record}}}}'"#;
    let relative = profile[update_start..]
        .find(update_envelope)
        .expect("the update request envelope");
    let position = update_start + relative;
    profile.replace_range(
        position..position + update_envelope.len(),
        r#"    requestEnvelope: '{"command": {"target": "{{recordId}}", "record": {{record}}}}'"#,
    );
    if success_status != 200 {
        let method = "  - id: records-update\n    method: PUT\n";
        profile = profile.replacen(
            method,
            &format!("{method}    successStatus: {success_status}\n"),
            1,
        );
    }
    let create_start = profile
        .find("  - id: records-create\n")
        .expect("create operation");
    let create_envelope = r#"    requestEnvelope: '{"data": {"recordIdentifier": "{{recordId}}", "domainData": {{record}}}}'"#;
    let relative = profile[create_start..]
        .find(create_envelope)
        .expect("the create request envelope");
    let position = create_start + relative;
    profile.replace_range(
        position..position + create_envelope.len(),
        r#"    requestEnvelope: '{"command": {"target": "{{recordId}}", "record": {{record}}}}'"#,
    );
    fs::write(directory.join("profile.yaml"), &profile).expect("write synthetic profile");

    let pack = r#"apiVersion: id.registrystack.org/formats/adapter/pack/v1alpha1
kind: AdapterPack
id: synthetic-records
version: "1"
testedVersions:
  - "test-1"
endpoints:
  - id: tracker
    component: http
    authentication:
      type: basic
    attemptTimeoutMilliseconds: 10000
    maximumResponseBytes: 1048576
    operations:
      - id: update-record
        idempotentUpstream: true
    testedVersions:
      - "test-1"
routes:
  - id: update-record
    from:
      uri: direct:update-record
    steps:
      - onException:
          exception:
            - upstream.http
          steps:
            - setBody:
                jsonpath: "$"
      - idempotentConsumer:
          expression:
            header: Idempotency-Key
          steps:
            - to:
                uri: http:tracker
                parameters:
                  httpMethod: POST
                  path: /records/{{id}}
                  pathParameters:
                    id:
                      header: recordId
                  body:
                    jsonpath: "$"
                  operation: update-record
capabilities:
  components:
    - http
  languages:
    - header
    - jsonpath
  eips:
    - idempotentConsumer
    - onException
    - setBody
    - to
"#;
    fs::write(directory.join("pack.yaml"), pack).expect("write synthetic pack");

    let project = format!(
        r#"apiVersion: id.registrystack.org/formats/adapter/project/v1alpha1
kind: AdapterProject
project:
  id: synthetic-update
  version: "1"
profile:
  id: breg-records
  version: "1"
  digest: {}
pack:
  id: synthetic-records
  version: "1"
  digest: {}
recordTypes:
  - name: person
    fields:
      - name: record_identifier
        type: string
        required: true
      - name: name
        type: string
        required: true
bindings:
  - id: person-create
    operation: records-create
    recordType: person
    route: update-record
    maximumUpstreamCalls: 1
  - id: person-update
    operation: records-update
    recordType: person
    route: update-record
    maximumUpstreamCalls: 1
accessProfiles:
  - id: records-writer
    scopes:
      - records.write
    operations:
      - records-create
      - records-update
    recordTypes:
      - person
parameterizedParts:
  registryIdentifier: synthetic-registry
  datasetIdentifier: persons
"#,
        digest_of(profile.as_bytes()),
        digest_of(pack.as_bytes())
    );
    fs::write(directory.join("project.yaml"), project).expect("write synthetic project");
}

fn project() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("synthetic update project");
    write_artifacts(directory.path(), 200);
    directory
}

fn request_schema(project: &Path) -> Value {
    let read = |path: &Path, format: &'static FormatSpec<'static>| {
        let bytes = fs::read(path).expect("read authored artifact");
        Reader::new(path.display().to_string())
            .read(&bytes, &Expect::one(format))
            .expect("read authored artifact through the shared reader")
    };
    let profile = read(&project.join("profile.yaml"), &PROFILE_FORMAT)
        .decode::<AdapterProfile>()
        .expect("decode synthetic profile");
    let project = read(&project.join("project.yaml"), &PROJECT_FORMAT)
        .decode::<AdapterProject>()
        .expect("decode synthetic project");
    let binding = project
        .bindings
        .get("person-update")
        .expect("update binding");
    derive_operation_request_schema(&profile, &project, binding)
        .expect("derive the exported request schema")
}

#[tokio::test]
async fn put_updates_once_replays_exactly_and_refuses_changed_or_inconsistent_input() {
    let upstream = UpstreamDouble::start();
    let accepted = request_record("person-1", "Ada");
    upstream.respond_with(vec![Response::json(
        200,
        &accepted["command"]["record"].to_string(),
    )]);
    let project = project();
    let request_schema = request_schema(project.path());
    let request_validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&request_schema)
        .expect("the exported request schema compiles");
    assert!(request_validator.is_valid(&accepted));
    let served = Served::start_with_project(&upstream.url(""), project.path()).await;
    let token = served.token("records.write");

    let contract = served.get(WELL_KNOWN_PATH, Some(&token));
    assert_eq!(contract.0, 200, "{}", contract.2);
    let digest = contract.2["digest"].as_str().expect("contract digest");
    let update = contract.2["contract"]["unserved"]
        .as_array()
        .expect("unserved operations")
        .iter()
        .find(|operation| operation["operationId"] == "records-update.person")
        .expect("gateway contract names the native update");
    assert_eq!(update["method"], "PUT");
    assert_eq!(
        update["reasonCode"],
        "adapter.operation.gateway-write-disabled"
    );

    let first = put(
        &served,
        UPDATE_PATH,
        Some(&token),
        "update-person-1",
        Some(digest),
        &accepted,
    );
    let replay = put(
        &served,
        UPDATE_PATH,
        Some(&token),
        "update-person-1",
        Some(digest),
        &accepted,
    );
    assert_eq!(
        first.status,
        200,
        "{}",
        String::from_utf8_lossy(&first.body)
    );
    assert_eq!(replay.status, first.status);
    assert_eq!(replay.request_id, first.request_id);
    assert_eq!(
        replay.body, first.body,
        "the complete body replays byte for byte"
    );
    let success: Value = serde_json::from_slice(&first.body).expect("success is JSON");
    assert_eq!(success["requestId"], first.request_id);
    assert_eq!(
        success["result"]["record_identifier"], "ordinary-domain-field",
        "the profile's declared domain field remains domain data"
    );

    let changed_request = request_record("person-1", "Grace");
    assert!(request_validator.is_valid(&changed_request));
    let changed = put(
        &served,
        UPDATE_PATH,
        Some(&token),
        "update-person-1",
        Some(digest),
        &changed_request,
    );
    assert_eq!(
        changed.status,
        422,
        "{}",
        String::from_utf8_lossy(&changed.body)
    );

    let mismatched_request = request_record("person-2", "Ada");
    assert!(
        request_validator.is_valid(&mismatched_request),
        "the request schema checks identity type while the router binds its path value"
    );
    let mismatched = put(
        &served,
        UPDATE_PATH,
        Some(&token),
        "update-person-mismatch",
        Some(digest),
        &mismatched_request,
    );
    assert_eq!(
        mismatched.status,
        422,
        "{}",
        String::from_utf8_lossy(&mismatched.body)
    );

    let invalid_request = json!({
        "command": {
            "target": "person-1",
            "record": {
                "record_identifier": "ordinary-domain-field",
                "name": "Ada",
                "undeclared": true
            }
        }
    });
    assert!(!request_validator.is_valid(&invalid_request));
    let invalid = put(
        &served,
        UPDATE_PATH,
        Some(&token),
        "update-person-invalid",
        Some(digest),
        &invalid_request,
    );
    assert_eq!(
        invalid.status,
        422,
        "{}",
        String::from_utf8_lossy(&invalid.body)
    );

    let non_string_identity = json!({
        "command": {
            "target": 7,
            "record": {
                "record_identifier": "ordinary-domain-field",
                "name": "Ada"
            }
        }
    });
    assert!(!request_validator.is_valid(&non_string_identity));
    let non_string = put(
        &served,
        UPDATE_PATH,
        Some(&token),
        "update-person-non-string-id",
        Some(digest),
        &non_string_identity,
    );
    assert_eq!(
        non_string.status,
        422,
        "{}",
        String::from_utf8_lossy(&non_string.body)
    );

    assert_eq!(
        upstream.request_count(),
        1,
        "only the first update reaches the source"
    );
    let sent = upstream.requests();
    assert_eq!(sent[0].method, "POST");
    assert_eq!(sent[0].target, "/records/person-1");
    assert_eq!(
        serde_json::from_slice::<Value>(&sent[0].body).unwrap(),
        accepted["command"]["record"]
    );
}

#[tokio::test]
async fn put_auth_access_and_contract_pin_precede_body_and_source() {
    let upstream = UpstreamDouble::start();
    let accepted = request_record("person-1", "Ada");
    upstream.respond_with(vec![Response::json(
        200,
        &accepted["command"]["record"].to_string(),
    )]);
    let project = project();
    let served = Served::start_with_project(&upstream.url(""), project.path()).await;
    let write_token = served.token("records.write");
    let read_token = served.token("records.read");
    let wrong_pin = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let partial = br#"{"#;
    let common = [
        ("Content-Type", "application/json"),
        ("Idempotency-Key", "update-ordering"),
        (PIN_HEADER, wrong_pin),
    ];

    let unauthenticated = raw_request(&served, "PUT", UPDATE_PATH, None, &common, partial);
    assert_eq!(unauthenticated.status, 401);
    let forbidden = raw_request(
        &served,
        "PUT",
        UPDATE_PATH,
        Some(&read_token),
        &common,
        partial,
    );
    assert_eq!(forbidden.status, 403);
    let stale = raw_request(
        &served,
        "PUT",
        UPDATE_PATH,
        Some(&write_token),
        &common,
        partial,
    );
    assert_eq!(stale.status, 412);
    assert_eq!(
        upstream.request_count(),
        0,
        "boundary refusals precede source IO"
    );

    let contract = served.get(WELL_KNOWN_PATH, Some(&write_token));
    let digest = contract.2["digest"].as_str().expect("contract digest");
    let accepted = put(
        &served,
        UPDATE_PATH,
        Some(&write_token),
        "update-ordering",
        Some(digest),
        &accepted,
    );
    assert_eq!(
        accepted.status,
        200,
        "{}",
        String::from_utf8_lossy(&accepted.body)
    );
    assert_eq!(upstream.request_count(), 1);
}

#[tokio::test]
async fn pathless_create_places_the_authored_body_identity_in_the_route_header() {
    let upstream = UpstreamDouble::start();
    let request = request_record("person-9", "Ada");
    upstream.respond_with(vec![Response::json(
        200,
        &request["command"]["record"].to_string(),
    )]);
    let project = project();
    let served = Served::start_with_project(&upstream.url(""), project.path()).await;
    let token = served.token("records.write");
    let contract = served.get(WELL_KNOWN_PATH, Some(&token));
    let digest = contract.2["digest"].as_str().expect("contract digest");

    let response = post(
        &served,
        "/v1/records/person",
        Some(&token),
        "create-person-9",
        Some(digest),
        &request,
    );

    assert_eq!(
        response.status,
        201,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    let sent = upstream.requests();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].target, "/records/person-9");
    assert_eq!(
        serde_json::from_slice::<Value>(&sent[0].body).expect("source body is JSON"),
        request["command"]["record"]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn put_post_send_uncertainty_stays_spent_after_journal_recovery() {
    let upstream = UpstreamDouble::start();
    let accepted = request_record("person-1", "Ada");
    upstream.respond_with(vec![Response::json(
        200,
        &accepted["command"]["record"].to_string(),
    )]);
    upstream.delay_answers(Duration::from_millis(700));
    let project = project();
    let served =
        std::sync::Arc::new(Served::start_with_project(&upstream.url(""), project.path()).await);
    let token = served.token("records.write");
    let contract = served.get(WELL_KNOWN_PATH, Some(&token));
    let digest = contract.2["digest"]
        .as_str()
        .expect("contract digest")
        .to_owned();

    let first = {
        let served = std::sync::Arc::clone(&served);
        let token = token.clone();
        let digest = digest.clone();
        let accepted = accepted.clone();
        tokio::task::spawn_blocking(move || {
            put(
                &served,
                UPDATE_PATH,
                Some(&token),
                "update-uncertain",
                Some(&digest),
                &accepted,
            )
        })
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while upstream.request_count() == 0 {
        assert!(
            Instant::now() < deadline,
            "the update never reached the source"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    served
        .execute_sql("ALTER TABLE adapter_journal_events RENAME TO adapter_journal_broken")
        .await;
    let first = first.await.expect("first caller completes");
    assert_eq!(
        first.status,
        500,
        "{}",
        String::from_utf8_lossy(&first.body)
    );
    served
        .execute_sql("ALTER TABLE adapter_journal_broken RENAME TO adapter_journal_events")
        .await;

    let retry = put(
        &served,
        UPDATE_PATH,
        Some(&token),
        "update-uncertain",
        Some(&digest),
        &accepted,
    );
    assert_eq!(
        retry.status,
        409,
        "{}",
        String::from_utf8_lossy(&retry.body)
    );
    assert_eq!(
        upstream.request_count(),
        1,
        "recovery cannot repeat an uncertain effect"
    );
    assert!(
        served
            .journal_kinds()
            .await
            .iter()
            .all(|kind| kind != "exchangeCompleted"),
        "a rolled-back terminal transaction leaves no false completion"
    );
}

#[tokio::test]
async fn a_write_success_status_202_is_not_served_before_async_recovery_exists() {
    let upstream = UpstreamDouble::start();
    let project = tempfile::tempdir().expect("synthetic async project");
    write_artifacts(project.path(), 202);
    let served = Served::start_with_project(&upstream.url(""), project.path()).await;
    let token = served.token("records.write");

    let contract = served.get(WELL_KNOWN_PATH, Some(&token));
    let update = contract.2["contract"]["unserved"]
        .as_array()
        .expect("unserved operations")
        .iter()
        .find(|operation| operation["operationId"] == "records-update.person")
        .expect("the asynchronous update is unserved");
    assert_eq!(
        update["reasonCode"],
        "adapter.operation.write-async-unsupported"
    );

    let response = put(
        &served,
        UPDATE_PATH,
        Some(&token),
        "async-update",
        contract.2["digest"].as_str(),
        &request_record("person-1", "Ada"),
    );
    assert_eq!(response.status, 404);
    assert_eq!(upstream.request_count(), 0);
}

#[tokio::test]
async fn an_actual_upstream_202_stays_spent_even_when_a_handler_produces_a_valid_body() {
    let upstream = UpstreamDouble::start();
    let accepted = request_record("person-1", "Ada");
    upstream.respond_with(vec![Response::json(
        202,
        &accepted["command"]["record"].to_string(),
    )]);
    let project = project();
    let served = Served::start_with_project(&upstream.url(""), project.path()).await;
    let token = served.token("records.write");
    let contract = served.get(WELL_KNOWN_PATH, Some(&token));
    let digest = contract.2["digest"].as_str().expect("contract digest");

    let first = put(
        &served,
        UPDATE_PATH,
        Some(&token),
        "actual-202",
        Some(digest),
        &accepted,
    );
    let retry = put(
        &served,
        UPDATE_PATH,
        Some(&token),
        "actual-202",
        Some(digest),
        &accepted,
    );

    assert_eq!(
        first.status,
        409,
        "{}",
        String::from_utf8_lossy(&first.body)
    );
    assert_eq!(
        retry.status,
        409,
        "{}",
        String::from_utf8_lossy(&retry.body)
    );
    assert_eq!(retry.request_id, first.request_id);
    assert_eq!(
        retry.body, first.body,
        "the bounded problem replays exactly"
    );
    assert_eq!(
        upstream.request_count(),
        1,
        "the incomplete effect is never resent"
    );
    let (client, connection) = tokio_postgres::connect(&served.database, tokio_postgres::NoTls)
        .await
        .expect("connect to idempotency custody");
    tokio::spawn(connection);
    let state: String = client
        .query_one("SELECT state FROM adapter_idempotency_entries", &[])
        .await
        .expect("read retained write state")
        .get(0);
    assert_eq!(state, "failed");
    assert!(
        served
            .journal_kinds()
            .await
            .iter()
            .all(|kind| kind != "exchangeCompleted"),
        "an incomplete write never journals false completion"
    );
}
