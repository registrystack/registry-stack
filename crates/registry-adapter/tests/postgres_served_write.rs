// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL-backed served-write proof through the real Adapter binary and
//! the maintained synchronous DHIS2 create route. Absence of
//! `ADAPTER_TEST_DATABASE_URL` is a failure, never a skip.
#![cfg(feature = "postgres-test")]

#[allow(dead_code)]
#[path = "support/served/mod.rs"]
mod served_harness;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use registry_adapter::effective_contract::WELL_KNOWN_PATH;
use serde_json::{json, Value};
use served_harness::upstream::{Response, UpstreamDouble};
use served_harness::{capture, Served};

const CREATE_RESPONSE_ENVELOPE: &str = r#"    successStatus: 201
    requestEnvelope: '{"data": {"recordIdentifier": "{{recordId}}", "domainData": {{record}}}}'
    responseEnvelope: '{"data": {{record}}, "meta": {"registryIdentifier": "registryIdentifier", "datasetIdentifier": "datasetIdentifier", "entityTypeIdentifier": "{{recordType}}"}}'"#;
const CREATE_RESPONSE_WITH_REQUEST_ID: &str = r#"    successStatus: 201
    requestEnvelope: '{"data": {"recordIdentifier": "{{recordId}}", "domainData": {{record}}}}'
    responseEnvelope: '{"data": {{record}}, "requestId": "{{requestId}}", "meta": {"registryIdentifier": "registryIdentifier", "datasetIdentifier": "datasetIdentifier", "entityTypeIdentifier": "{{recordType}}"}}'"#;
const PROBLEM_ENVELOPE: &str = r#"problemEnvelope: '{"title": "{{problemTitle}}", "status": {{status}}, "detail": "{{?problemDetail}}", "code": "{{problemCode}}", "data": {{?problemData}}}'"#;
const PROBLEM_WITH_REQUEST_ID: &str = r#"problemEnvelope: '{"title": "{{problemTitle}}", "status": {{status}}, "detail": "{{?problemDetail}}", "code": "{{problemCode}}", "data": {{?problemData}}, "requestId": "{{requestId}}"}'"#;

fn accepted_record(updated_at: &str) -> Value {
    json!({
        "data": {
            "recordIdentifier": "wk4JlTuVO9o",
            "domainData": {
                "tracked_entity_type": "cQWYtUfH6Vx",
                "org_unit": "qfg4XUDJtgS",
                "created_at": "2026-03-01T12:00:00.000",
                "updated_at": updated_at
            }
        }
    })
}

struct RawPostResponse {
    status: u16,
    request_id: String,
    body: Vec<u8>,
}

fn raw_post_response(
    served: &Served,
    token: &str,
    key: &str,
    caller_request_id: Option<&str>,
    body: &Value,
) -> RawPostResponse {
    let body = body.to_string();
    let mut stream = TcpStream::connect(("127.0.0.1", served.port)).expect("connect to facade");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("set facade timeout");
    let caller_header = caller_request_id
        .map(|id| format!("X-Registry-Request-Id: {id}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "POST /v1/records/person HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nIdempotency-Key: {key}\r\n{caller_header}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("send write");
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
    let request_id = head
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case("x-registry-request-id")
                .then(|| value.trim().to_owned())
        })
        .expect("facade response carries a request id");
    RawPostResponse {
        status,
        request_id,
        body: response[head_end + 4..].to_vec(),
    }
}

fn raw_post(served: &Served, token: &str, key: &str, body: &Value) -> (u16, Vec<u8>) {
    let response = raw_post_response(served, token, key, None, body);
    (response.status, response.body)
}

fn accepted_upstream_response() -> Response {
    let (status, body) = capture("import-accepted");
    Response::json(status, &body)
}

fn partial_upstream_response() -> Response {
    Response::json(
        200,
        &json!({
            "status": "WARNING",
            "validationReport": {
                "errorReports": [],
                "warningReports": []
            },
            "stats": {
                "created": 1,
                "updated": 2,
                "deleted": 0,
                "ignored": 1,
                "total": 4
            }
        })
        .to_string(),
    )
}

async fn journal_exchange_ids(served: &Served) -> Vec<String> {
    let (client, connection) = tokio_postgres::connect(&served.database, tokio_postgres::NoTls)
        .await
        .expect("connect to the served journal schema");
    tokio::spawn(connection);
    client
        .query(
            "SELECT DISTINCT exchange_id FROM adapter_journal_events ORDER BY exchange_id",
            &[],
        )
        .await
        .expect("read physical journal attempt ids")
        .into_iter()
        .map(|row| row.get(0))
        .collect()
}

async fn idempotency_rows(served: &Served) -> Vec<(String, bool)> {
    let (client, connection) = tokio_postgres::connect(&served.database, tokio_postgres::NoTls)
        .await
        .expect("connect to the served idempotency schema");
    tokio::spawn(connection);
    client
        .query(
            "SELECT state, response_body IS NULL FROM adapter_idempotency_entries ORDER BY state",
            &[],
        )
        .await
        .expect("read idempotency custody")
        .into_iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect()
}

async fn seed_expired_responses(served: &Served, count: u32) {
    let (client, connection) = tokio_postgres::connect(&served.database, tokio_postgres::NoTls)
        .await
        .expect("connect to the served idempotency schema");
    tokio::spawn(connection);
    client
        .execute(
            "INSERT INTO adapter_idempotency_entries \
             (scope_digest, request_digest, state, claimed_at, terminal_at, expires_at, \
              response_status, response_content_type, response_body, response_request_id) \
             SELECT decode(md5('scope-' || value::text) || md5('scope-x-' || value::text), 'hex'), \
                    decode(md5('request-' || value::text) || md5('request-x-' || value::text), 'hex'), \
                    'completed', now() - interval '2 seconds', now() - interval '2 seconds', \
                    now() - interval '1 second', 200, convert_to('application/json', 'UTF8'), \
                    convert_to('{}', 'UTF8'), md5('response-id-' || value::text) \
             FROM generate_series(1, $1) AS value",
            &[&i32::try_from(count).expect("seed count fits PostgreSQL int4")],
        )
        .await
        .expect("seed expired response custody");
}

#[tokio::test]
async fn a_completed_duplicate_replays_exact_bytes_and_a_changed_request_mismatches() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![accepted_upstream_response()]);
    let served = Served::start(&upstream.url("")).await;
    let token = served.token("records.write");
    let request = accepted_record("2026-03-01T12:00:00.000");
    let contract = served.get(WELL_KNOWN_PATH, Some(&token));
    assert_eq!(contract.0, 200, "{}", contract.2);
    let problem_schema = &contract.2["contract"]["problemSchema"];
    let problem_validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(problem_schema)
        .expect("the protected contract carries a Draft 2020-12 problem schema");

    let first = raw_post(&served, &token, "create-person-1", &request);
    let replay = raw_post(&served, &token, "create-person-1", &request);
    let mismatch = raw_post(
        &served,
        &token,
        "create-person-1",
        &accepted_record("2026-03-02T12:00:00.000"),
    );

    assert_eq!(first.0, 201, "{}", String::from_utf8_lossy(&first.1));
    assert_eq!(
        replay, first,
        "the complete facade body replays byte for byte"
    );
    assert_eq!(mismatch.0, 422, "{}", String::from_utf8_lossy(&mismatch.1));
    let mismatch_body: Value =
        serde_json::from_slice(&mismatch.1).expect("the mismatch problem is JSON");
    assert_eq!(mismatch_body["code"], "source.facade");
    assert_eq!(mismatch_body["status"], 422);
    assert!(
        mismatch_body.get("data").is_none(),
        "the facade mismatch cannot manufacture source problem data"
    );
    assert!(
        problem_validator.is_valid(&mismatch_body),
        "the served facade mismatch must satisfy the protected contract: {mismatch_body}"
    );

    let mut arbitrary_status = mismatch_body.clone();
    arbitrary_status["status"] = json!(418);
    assert!(
        !problem_validator.is_valid(&arbitrary_status),
        "the source.facade branch is closed to unassigned statuses"
    );
    let write_partial_wrong_status = json!({
        "title": "the write was only partially accepted",
        "status": 422,
        "code": "source.write-partial",
        "data": {
            "imported": 1,
            "updated": 0,
            "ignored": 0,
            "rejected": 0
        }
    });
    assert!(
        !problem_validator.is_valid(&write_partial_wrong_status),
        "one problem code cannot borrow another problem's fixed facade status"
    );

    let replay_after_mismatch = raw_post(&served, &token, "create-person-1", &request);
    assert_eq!(
        replay_after_mismatch, first,
        "a mismatched duplicate cannot alter the original response custody"
    );
    assert_eq!(
        upstream.request_count(),
        1,
        "duplicates never reach the source"
    );
}

#[tokio::test]
async fn replay_preserves_one_response_id_across_header_and_custom_body() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![
        accepted_upstream_response(),
        partial_upstream_response(),
    ]);
    let project = tempfile::tempdir().expect("a copied project directory");
    served_harness::copy_example_project(project.path());
    served_harness::replace_profile_text(
        project.path(),
        CREATE_RESPONSE_ENVELOPE,
        CREATE_RESPONSE_WITH_REQUEST_ID,
    );
    served_harness::replace_profile_text(project.path(), PROBLEM_ENVELOPE, PROBLEM_WITH_REQUEST_ID);
    let served = Served::start_with_project(&upstream.url(""), project.path()).await;
    let token = served.token("records.write");
    let request = accepted_record("2026-03-01T12:00:00.000");
    let caller_id = "caller-controlled-request-id";

    let success = raw_post_response(
        &served,
        &token,
        "response-id-success",
        Some(caller_id),
        &request,
    );
    let success_replay = raw_post_response(
        &served,
        &token,
        "response-id-success",
        Some(caller_id),
        &request,
    );
    assert_eq!(success.status, 201);
    assert_eq!(success_replay.status, 201);
    assert_eq!(success_replay.body, success.body);
    let success_body: Value = serde_json::from_slice(&success.body).expect("success body is JSON");
    assert_eq!(success.request_id, success_body["requestId"]);
    assert_eq!(success_replay.request_id, success_body["requestId"]);
    assert_ne!(success.request_id, caller_id);

    let problem = raw_post_response(
        &served,
        &token,
        "response-id-problem",
        Some(caller_id),
        &request,
    );
    let problem_replay = raw_post_response(
        &served,
        &token,
        "response-id-problem",
        Some(caller_id),
        &request,
    );
    assert_eq!(problem.status, 409);
    assert_eq!(problem_replay.status, 409);
    assert_eq!(problem_replay.body, problem.body);
    let problem_body: Value = serde_json::from_slice(&problem.body).expect("problem body is JSON");
    assert_eq!(problem.request_id, problem_body["requestId"]);
    assert_eq!(problem_replay.request_id, problem_body["requestId"]);
    assert_ne!(problem.request_id, caller_id);

    assert_eq!(
        upstream.request_count(),
        2,
        "the two replays make no additional source effects"
    );
    let journal_ids = journal_exchange_ids(&served).await;
    assert_eq!(journal_ids.len(), 4, "each physical attempt has a fresh id");
    assert!(journal_ids.contains(&success.request_id));
    assert!(journal_ids.contains(&problem.request_id));
}

#[tokio::test]
async fn two_runtime_ids_sharing_a_database_have_distinct_write_namespaces() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![
        accepted_upstream_response(),
        accepted_upstream_response(),
    ]);
    let first = Served::start_for_deployment(
        &upstream.url(""),
        &Served::example_project(),
        "tracker-east",
        None,
    )
    .await;
    let second = Served::start_for_deployment(
        &upstream.url(""),
        &Served::example_project(),
        "tracker-west",
        Some(&first.database),
    )
    .await;
    let request = accepted_record("2026-03-01T12:00:00.000");

    let first_response = raw_post(
        &first,
        &first.token("records.write"),
        "shared-key",
        &request,
    );
    let second_response = raw_post(
        &second,
        &second.token("records.write"),
        "shared-key",
        &request,
    );

    assert_eq!(
        first_response.0,
        201,
        "{}",
        String::from_utf8_lossy(&first_response.1)
    );
    assert_eq!(
        second_response.0,
        201,
        "{}",
        String::from_utf8_lossy(&second_response.1)
    );
    assert_eq!(
        upstream.request_count(),
        2,
        "logical deployments sharing PostgreSQL cannot replay each other's writes"
    );
}

#[tokio::test]
async fn changed_artifacts_under_one_runtime_id_mismatch_without_a_fresh_send() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![
        accepted_upstream_response(),
        accepted_upstream_response(),
    ]);
    let project = tempfile::tempdir().expect("a copied project directory");
    served_harness::copy_example_project(project.path());
    let first =
        Served::start_for_deployment(&upstream.url(""), project.path(), "tracker-stable", None)
            .await;
    let request = accepted_record("2026-03-01T12:00:00.000");
    let first_response = raw_post(
        &first,
        &first.token("records.write"),
        "stable-key",
        &request,
    );
    assert_eq!(
        first_response.0,
        201,
        "{}",
        String::from_utf8_lossy(&first_response.1)
    );

    let script_path = project.path().join("scripts/accepted-record.rhai");
    let mut script = std::fs::read_to_string(&script_path).expect("the pack script reads");
    script.push_str("\n// governed artifact revision\n");
    served_harness::replace_pack_script(project.path(), "scripts/accepted-record.rhai", &script);
    let second = Served::start_for_deployment(
        &upstream.url(""),
        project.path(),
        "tracker-stable",
        Some(&first.database),
    )
    .await;
    let retry = raw_post(
        &second,
        &second.token("records.write"),
        "stable-key",
        &request,
    );

    assert_eq!(retry.0, 422, "{}", String::from_utf8_lossy(&retry.1));
    assert_eq!(
        upstream.request_count(),
        1,
        "an artifact change cannot open a fresh effect namespace"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_concurrent_duplicate_conflicts_while_the_first_source_send_is_in_flight() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![accepted_upstream_response()]);
    upstream.delay_answers(Duration::from_millis(700));
    let served = std::sync::Arc::new(Served::start(&upstream.url("")).await);
    let token = served.token("records.write");
    let request = accepted_record("2026-03-01T12:00:00.000");

    let first = {
        let served = std::sync::Arc::clone(&served);
        let token = token.clone();
        let request = request.clone();
        tokio::task::spawn_blocking(move || {
            raw_post(&served, &token, "create-person-race", &request)
        })
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while upstream.request_count() == 0 {
        assert!(
            Instant::now() < deadline,
            "the first write never reached the source"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let duplicate = raw_post(&served, &token, "create-person-race", &request);
    let first = first.await.expect("first caller completes");

    assert_eq!(
        duplicate.0,
        409,
        "{}",
        String::from_utf8_lossy(&duplicate.1)
    );
    assert_eq!(first.0, 201, "{}", String::from_utf8_lossy(&first.1));
    assert_eq!(upstream.request_count(), 1);
}

#[tokio::test]
async fn a_failure_after_the_source_send_is_recorded_and_replayed_without_a_fresh_effect() {
    let upstream = UpstreamDouble::start();
    let (status, body) = capture("import-server-error");
    upstream.respond_with(vec![Response::json(status, &body)]);
    let served = Served::start(&upstream.url("")).await;
    let token = served.token("records.write");
    let request = accepted_record("2026-03-01T12:00:00.000");

    let first = raw_post(&served, &token, "create-person-failed", &request);
    let replay = raw_post(&served, &token, "create-person-failed", &request);

    assert_eq!(first.0, 502, "{}", String::from_utf8_lossy(&first.1));
    assert_eq!(replay, first, "the recorded facade problem replays exactly");
    assert_eq!(
        upstream.request_count(),
        1,
        "a retry cannot make a fresh send"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_terminal_transaction_failure_records_no_false_completion_and_never_reexecutes() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![accepted_upstream_response()]);
    upstream.delay_answers(Duration::from_millis(700));
    let served = std::sync::Arc::new(Served::start(&upstream.url("")).await);
    let token = served.token("records.write");
    let request = accepted_record("2026-03-01T12:00:00.000");

    let first = {
        let served = std::sync::Arc::clone(&served);
        let token = token.clone();
        let request = request.clone();
        tokio::task::spawn_blocking(move || {
            raw_post(&served, &token, "create-person-commit-failure", &request)
        })
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while upstream.request_count() == 0 {
        assert!(
            Instant::now() < deadline,
            "the write never reached the source"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    served
        .execute_sql("ALTER TABLE adapter_journal_events RENAME TO adapter_journal_broken")
        .await;
    let first = first.await.expect("first caller completes");
    assert_eq!(first.0, 500, "{}", String::from_utf8_lossy(&first.1));
    served
        .execute_sql("ALTER TABLE adapter_journal_broken RENAME TO adapter_journal_events")
        .await;

    let retry = raw_post(&served, &token, "create-person-commit-failure", &request);
    assert_eq!(retry.0, 409, "{}", String::from_utf8_lossy(&retry.1));
    assert_eq!(
        upstream.request_count(),
        1,
        "the uncertain effect stays spent"
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
async fn the_supervised_timer_erases_expired_response_bytes_but_keeps_the_key_spent() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![accepted_upstream_response()]);
    let served = Served::start_with_retention(&upstream.url(""), 1).await;
    let token = served.token("records.write");
    let request = accepted_record("2026-03-01T12:00:00.000");

    let first = raw_post(&served, &token, "create-person-expiring", &request);
    assert_eq!(first.0, 201, "{}", String::from_utf8_lossy(&first.1));
    seed_expired_responses(&served, 1_001).await;

    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        let rows = idempotency_rows(&served).await;
        if rows.len() == 1_002
            && rows
                .iter()
                .all(|row| row == &("completed_expired".to_owned(), true))
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the supervised sweep did not erase custody: {rows:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let retry = raw_post(&served, &token, "create-person-expiring", &request);
    assert_eq!(retry.0, 409, "{}", String::from_utf8_lossy(&retry.1));
    assert_eq!(
        upstream.request_count(),
        1,
        "an expired response never reopens the effect"
    );
}
