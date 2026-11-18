// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL-backed proof for the facade-owned asynchronous status link.
//! Absence of `ADAPTER_TEST_DATABASE_URL` is a failure, never a skip.
#![cfg(feature = "postgres-test")]

#[allow(dead_code)]
#[path = "support/served/mod.rs"]
mod served_harness;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use served_harness::upstream::{Response, ScriptedResponse, UpstreamDouble};
use served_harness::Served;

const CREATE_PROFILE: &str = r#"    successStatus: 201
    requestEnvelope: '{"data": {"recordIdentifier": "{{recordId}}", "domainData": {{record}}}}'
    responseEnvelope: '{"data": {{record}}, "meta": {"registryIdentifier": "registryIdentifier", "datasetIdentifier": "datasetIdentifier", "recordTypeIdentifier": "{{recordType}}"}}'"#;
const ASYNC_CREATE_PROFILE: &str = r#"    successStatus: 202
    requestEnvelope: '{"data": {"recordIdentifier": "{{recordId}}", "domainData": {{record}}}}'
    responseEnvelope: '{"data": {{record}}, "meta": {"registryIdentifier": "registryIdentifier", "datasetIdentifier": "datasetIdentifier", "recordTypeIdentifier": "{{recordType}}"}}'
    asyncCompletion:
      completedStatus: 201
      statusPath: /v1/write-status/{statusId}
      acceptedEnvelope: '{"status":"accepted","statusLink":"{{statusLink}}","expiresAt":"{{statusExpiresAt}}","requestId":"{{requestId}}"}'"#;
const SOURCE_OPERATION: &str = r#"      - id: tracker-import
        idempotentUpstream: true"#;
const ASYNC_SOURCE_OPERATION: &str = r#"      - id: tracker-import
        idempotentUpstream: true
        asyncCompletion:
          acceptedId:
            jsonpath: $.operationId
          statusRoute: async-status"#;
const CREATE_BINDING: &str = r#"  - id: person-create
    operation: records-create
    recordType: person
    route: person-import
    maximumUpstreamCalls: 4"#;
const ASYNC_CREATE_BINDING: &str = r#"  - id: person-create
    operation: records-create
    recordType: person
    route: person-import
    maximumUpstreamCalls: 4
    asyncCompletion:
      type: status-link"#;
const UPDATE_BINDING: &str = r#"  - id: person-update
    operation: records-update
    recordType: person
    route: person-import
    maximumUpstreamCalls: 4
"#;
const STATUS_ROUTE: &str = r#"

routes:
  - id: async-status
    from:
      uri: direct:async-status
    steps:
      - to:
          uri: http:tracker
          parameters:
            httpMethod: GET
            path: /api/tracker/jobs/{{operation_id}}
            pathParameters:
              operation_id:
                exchangeProperty: AdapterAsyncOperationId
            operation: tracker-export
"#;
const UNCERTAINTY_RECOVERY: &str = r#"          statusRoute: async-status
          uncertaintyRecovery:
            requestHeader: X-Registry-Recovery-Id
            statusRoute: async-uncertainty"#;
const UNCERTAINTY_ROUTE: &str = r#"
  - id: async-uncertainty
    from:
      uri: direct:async-uncertainty
    steps:
      - to:
          uri: http:tracker
          parameters:
            httpMethod: GET
            path: /api/tracker/recovery
            operation: tracker-export
"#;

struct RawResponse {
    status: u16,
    request_id: String,
    retry_after: Option<String>,
    body: Vec<u8>,
}

/// A response head without its `Date` header, which the server stamps from
/// the wall clock and so differs between two requests that straddle a second
/// boundary. Every other header stays in the comparison.
fn without_date(head: &str) -> String {
    head.split("\r\n")
        .filter(|line| {
            !line
                .split_once(':')
                .is_some_and(|(name, _)| name.eq_ignore_ascii_case("date"))
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

fn async_project(directory: &Path) {
    served_harness::copy_example_project(directory);
    served_harness::replace_profile_text(directory, CREATE_PROFILE, ASYNC_CREATE_PROFILE);

    let project_path = directory.join("project.yaml");
    let project = std::fs::read_to_string(&project_path).expect("the copied project is readable");
    assert!(project.contains(CREATE_BINDING));
    assert!(project.contains(UPDATE_BINDING));
    std::fs::write(
        &project_path,
        project
            .replacen(CREATE_BINDING, ASYNC_CREATE_BINDING, 1)
            .replacen(UPDATE_BINDING, "", 1),
    )
    .expect("write the asynchronous binding");

    let pack_path = directory.join("pack.yaml");
    let pack = std::fs::read_to_string(&pack_path).expect("the copied pack is readable");
    assert!(pack.contains(SOURCE_OPERATION));
    let edited = format!(
        "{}{}",
        pack.replacen(SOURCE_OPERATION, ASYNC_SOURCE_OPERATION, 1),
        STATUS_ROUTE
    );
    let project = std::fs::read_to_string(&project_path).expect("the edited project is readable");
    let old_digest = served_harness::digest_of(pack.as_bytes());
    assert!(
        project.contains(&old_digest),
        "the project pins the copied pack"
    );
    std::fs::write(&pack_path, &edited).expect("write the asynchronous pack");
    std::fs::write(
        &project_path,
        project.replace(&old_digest, &served_harness::digest_of(edited.as_bytes())),
    )
    .expect("re-pin the asynchronous pack");
}

fn bounded_wait_project(
    directory: &Path,
    wait_timeout_milliseconds: u64,
    poll_interval_milliseconds: u64,
    maximum_polls: u64,
) {
    async_project(directory);
    let project_path = directory.join("project.yaml");
    let project = std::fs::read_to_string(&project_path).expect("the project is readable");
    let status_link = "    asyncCompletion:\n      type: status-link";
    assert!(project.contains(status_link));
    let bounded_wait = format!(
        "    asyncCompletion:\n      type: bounded-wait\n      waitTimeoutMilliseconds: {wait_timeout_milliseconds}\n      pollIntervalMilliseconds: {poll_interval_milliseconds}\n      maximumPolls: {maximum_polls}"
    );
    std::fs::write(
        &project_path,
        project.replacen(status_link, &bounded_wait, 1),
    )
    .expect("write the bounded-wait binding");
}

fn uncertainty_project(directory: &Path) {
    async_project(directory);
    let pack_path = directory.join("pack.yaml");
    let pack = std::fs::read_to_string(&pack_path).expect("the asynchronous pack is readable");
    assert!(pack.contains("          statusRoute: async-status"));
    let edited = format!(
        "{}{}",
        pack.replacen(
            "          statusRoute: async-status",
            UNCERTAINTY_RECOVERY,
            1,
        ),
        UNCERTAINTY_ROUTE
    );
    let project_path = directory.join("project.yaml");
    let project = std::fs::read_to_string(&project_path).expect("the project is readable");
    let old_digest = served_harness::digest_of(pack.as_bytes());
    assert!(project.contains(&old_digest));
    std::fs::write(&pack_path, &edited).expect("write the uncertainty recovery route");
    std::fs::write(
        &project_path,
        project.replace(&old_digest, &served_harness::digest_of(edited.as_bytes())),
    )
    .expect("re-pin the uncertainty recovery pack");
}

fn linear_resume_project() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/adapter/examples/facade-recovery")
}

fn request_body() -> Value {
    json!({
        "data": {
            "recordIdentifier": "wk4JlTuVO9o",
            "domainData": {
                "tracked_entity_type": "cQWYtUfH6Vx",
                "org_unit": "qfg4XUDJtgS",
                "created_at": "2026-03-01T12:00:00.000",
                "updated_at": "2026-03-01T12:00:00.000"
            }
        }
    })
}

fn linear_request_body() -> Value {
    json!({
        "data": {
            "recordIdentifier": "person-17",
            "domainData": {"name": "Example Person"}
        }
    })
}

fn post(served: &Served, token: &str, key: &str, body: &Value) -> RawResponse {
    let body = body.to_string();
    let mut stream = TcpStream::connect(("127.0.0.1", served.port)).expect("connect to facade");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("set facade timeout");
    let request = format!(
        "POST /v1/records/person HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nIdempotency-Key: {key}\r\nContent-Length: {}\r\n\r\n{body}",
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
        .expect("facade reply has headers");
    let head = std::str::from_utf8(&response[..head_end]).expect("facade headers are text");
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("facade status");
    let request_id = head
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case("x-registry-request-id")
                .then(|| value.trim().to_owned())
        })
        .expect("facade response request id");
    let retry_after = head
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case("retry-after")
                .then(|| value.trim().to_owned())
        });
    RawResponse {
        status,
        request_id,
        retry_after,
        body: response[head_end + 4..].to_vec(),
    }
}

#[tokio::test]
async fn a_status_link_mode_returns_and_replays_202_without_repeating_the_effect() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![Response::json(
        202,
        &json!({"operationId": "source-17"}).to_string(),
    )]);
    let directory = tempfile::tempdir().expect("an asynchronous project directory");
    async_project(directory.path());
    let served = Served::start_with_project(&upstream.url(""), directory.path()).await;
    let token = served.token("records.write");
    let request = request_body();

    let first = post(&served, &token, "async-create-1", &request);
    let replay = post(&served, &token, "async-create-1", &request);

    assert_eq!(
        first.status,
        202,
        "{}",
        String::from_utf8_lossy(&first.body)
    );
    assert_eq!(replay.status, 202);
    assert_eq!(replay.request_id, first.request_id);
    assert_eq!(
        replay.body, first.body,
        "the accepted response replays exactly"
    );
    let accepted: Value = serde_json::from_slice(&first.body).expect("accepted response is JSON");
    assert_eq!(accepted["status"], "accepted");
    assert_eq!(accepted["requestId"], first.request_id);
    assert_eq!(
        accepted["statusLink"],
        format!("/v1/write-status/{}", first.request_id)
    );
    assert!(
        accepted["expiresAt"]
            .as_str()
            .is_some_and(|value| !value.is_empty()),
        "the status link carries its absolute expiry"
    );
    assert_eq!(
        upstream.request_count(),
        1,
        "the exact replay never repeats the source mutation"
    );
}

#[tokio::test]
async fn a_linear_write_restarts_at_the_first_unfinished_native_effect() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with_script(vec![
        ScriptedResponse::EffectComplete(Response::json(200, r#"{"sourceId":"source-17"}"#)),
        ScriptedResponse::Complete(Response::json(503, r#"{"error":"operator-fix-required"}"#)),
        ScriptedResponse::EffectComplete(Response::json(
            200,
            &json!({"name": "Example Person"}).to_string(),
        )),
    ]);
    let directory = linear_resume_project();
    let first = Served::start_for_deployment_endpoint(
        &upstream.url(""),
        &directory,
        "reference",
        "linear-resume",
        None,
    )
    .await;
    let token = first.token("records.write");
    let failed = post(&first, &token, "linear-resume-1", &linear_request_body());
    assert_eq!(
        failed.status,
        409,
        "{}",
        String::from_utf8_lossy(&failed.body)
    );
    assert_eq!(
        failed.retry_after.as_deref(),
        Some("5"),
        "resumable progress is retryable"
    );
    assert_eq!(
        upstream
            .requests()
            .iter()
            .map(|request| request.target.as_str())
            .collect::<Vec<_>>(),
        ["/drafts", "/finalizations?source_id=source-17"],
        "the provider refusal happens before the second logical effect"
    );

    first
        .execute_sql("UPDATE adapter_idempotency_resumes SET lease_until = CURRENT_TIMESTAMP")
        .await;
    let database = first.database.clone();
    drop(first);
    let restarted = Served::start_for_deployment_endpoint(
        &upstream.url(""),
        &directory,
        "reference",
        "linear-resume",
        Some(&database),
    )
    .await;
    let token = restarted.token("records.write");
    let recovered = post(
        &restarted,
        &token,
        "linear-resume-1",
        &linear_request_body(),
    );
    assert_eq!(
        recovered.status,
        201,
        "{}",
        String::from_utf8_lossy(&recovered.body)
    );
    let replay = post(
        &restarted,
        &token,
        "linear-resume-1",
        &linear_request_body(),
    );
    assert_eq!(replay.status, 201);
    assert_eq!(replay.request_id, recovered.request_id);
    assert_eq!(replay.body, recovered.body);
    assert_eq!(
        upstream.logical_effect_count(),
        2,
        "each provider-idempotent native step applies one logical effect"
    );
    let requests = upstream.requests();
    assert_eq!(
        requests
            .iter()
            .map(|request| request.target.as_str())
            .collect::<Vec<_>>(),
        [
            "/drafts",
            "/finalizations?source_id=source-17",
            "/finalizations?source_id=source-17"
        ],
        "restart skips the committed first step and retries only the provider-idempotent unfinished step"
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&requests[2].body).expect("the second-step body is JSON"),
        json!({"command":"finalize"}),
        "the retried body is reconstructed from governed constants, not stored source bytes"
    );
    let kinds = restarted.journal_kinds().await;
    assert_eq!(
        kinds
            .iter()
            .filter(|kind| kind.as_str() == "resumeStepStarted")
            .count(),
        3,
        "every physical step attempt is journaled without its values"
    );
    assert_eq!(
        kinds
            .iter()
            .filter(|kind| kind.as_str() == "resumeStepCheckpointed")
            .count(),
        1,
        "only the successful non-final step advances the durable ordinal"
    );
    for detail in restarted.journal_details("resumeStepCheckpointed").await {
        let encoded = detail.to_string();
        assert!(!encoded.contains("source-17"));
        assert!(!encoded.contains("Example Person"));
    }
}

#[tokio::test]
async fn a_linear_write_retries_an_uncertain_step_without_repeating_prior_effects() {
    let upstream = UpstreamDouble::start();
    let completed = Response::json(200, &json!({"name": "Example Person"}).to_string());
    upstream.respond_with_script(vec![
        ScriptedResponse::EffectComplete(Response::json(200, r#"{"sourceId":"source-18"}"#)),
        ScriptedResponse::EffectResetAfter {
            response: completed.clone(),
            body_bytes: 8,
        },
        ScriptedResponse::EffectComplete(completed),
    ]);
    let directory = linear_resume_project();
    let served = Served::start_for_deployment_endpoint(
        &upstream.url(""),
        &directory,
        "reference",
        "linear-resume-uncertain",
        None,
    )
    .await;
    let token = served.token("records.write");
    let uncertain = post(&served, &token, "linear-resume-2", &linear_request_body());
    assert_eq!(
        uncertain.status,
        409,
        "{}",
        String::from_utf8_lossy(&uncertain.body)
    );
    assert_eq!(
        uncertain.retry_after.as_deref(),
        Some("5"),
        "an unfinished resumable step is retryable"
    );
    let recovered = post(&served, &token, "linear-resume-2", &linear_request_body());
    assert_eq!(
        recovered.status,
        201,
        "{}",
        String::from_utf8_lossy(&recovered.body)
    );
    assert_eq!(
        upstream
            .requests()
            .iter()
            .map(|request| request.target.as_str())
            .collect::<Vec<_>>(),
        [
            "/drafts",
            "/finalizations?source_id=source-18",
            "/finalizations?source_id=source-18"
        ],
        "the uncertain provider-idempotent step repeats, while its committed predecessor never does"
    );
    assert_eq!(
        upstream.logical_effect_count(),
        2,
        "the provider's reviewed idempotency semantics collapse the repeated physical request"
    );
}

#[tokio::test]
async fn a_public_facade_recovery_starter_runs_the_live_retry_contract() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with_script(vec![
        ScriptedResponse::EffectComplete(Response::json(200, r#"{"sourceId":"source-21"}"#)),
        ScriptedResponse::Complete(Response::json(503, r#"{"error":"operator-fix-required"}"#)),
        ScriptedResponse::EffectComplete(Response::json(
            200,
            &json!({"name": "Example Person"}).to_string(),
        )),
    ]);
    let directory = linear_resume_project();
    let served = Served::start_for_deployment_endpoint(
        &upstream.url(""),
        &directory,
        "reference",
        "facade-recovery-starter",
        None,
    )
    .await;
    let token = served.token("records.write");
    let key = "facade-recovery-starter-1";
    let request = linear_request_body();

    let failed = post(&served, &token, key, &request);
    assert_eq!(
        failed.status,
        409,
        "{}",
        String::from_utf8_lossy(&failed.body)
    );
    assert_eq!(
        failed.retry_after.as_deref(),
        Some("5"),
        "resumable progress is retryable"
    );

    let recovered = post(&served, &token, key, &request);
    assert_eq!(
        recovered.status,
        201,
        "{}",
        String::from_utf8_lossy(&recovered.body)
    );
    let replay = post(&served, &token, key, &request);
    assert_eq!(replay.status, 201);
    assert_eq!(replay.request_id, recovered.request_id);
    assert_eq!(replay.body, recovered.body);

    let changed = json!({
        "data": {
            "recordIdentifier": "person-17",
            "domainData": {"name": "Different Person"}
        }
    });
    let mismatch = post(&served, &token, key, &changed);
    assert_eq!(
        mismatch.status,
        422,
        "{}",
        String::from_utf8_lossy(&mismatch.body)
    );
    assert_eq!(
        upstream.logical_effect_count(),
        2,
        "the retry applies only the provider-idempotent unfinished effect"
    );
    assert_eq!(
        upstream.request_count(),
        3,
        "the exact replay and changed-body refusal never reach the provider"
    );
}

#[tokio::test]
async fn a_linear_write_can_resume_after_a_malformed_final_source_result_is_repaired() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with_script(vec![
        ScriptedResponse::EffectComplete(Response::json(200, r#"{"sourceId":"source-19"}"#)),
        ScriptedResponse::EffectComplete(Response::json(200, r#"{"unexpected":"shape"}"#)),
        ScriptedResponse::EffectComplete(Response::json(
            200,
            &json!({"name": "Example Person"}).to_string(),
        )),
    ]);
    let directory = linear_resume_project();
    let served = Served::start_for_deployment_endpoint(
        &upstream.url(""),
        &directory,
        "reference",
        "linear-resume-malformed-result",
        None,
    )
    .await;
    let token = served.token("records.write");
    let malformed = post(&served, &token, "linear-resume-3", &linear_request_body());
    assert_eq!(
        malformed.status,
        409,
        "{}",
        String::from_utf8_lossy(&malformed.body)
    );
    assert_eq!(
        malformed.retry_after.as_deref(),
        Some("5"),
        "a repaired resumable write is retryable"
    );
    let recovered = post(&served, &token, "linear-resume-3", &linear_request_body());
    assert_eq!(
        recovered.status,
        201,
        "{}",
        String::from_utf8_lossy(&recovered.body)
    );
    assert_eq!(
        upstream
            .requests()
            .iter()
            .map(|request| request.target.as_str())
            .collect::<Vec<_>>(),
        [
            "/drafts",
            "/finalizations?source_id=source-19",
            "/finalizations?source_id=source-19"
        ],
        "repair retries only the provider-idempotent final step"
    );
    assert_eq!(
        upstream.logical_effect_count(),
        2,
        "the repaired reply does not create another provider logical effect"
    );
}

#[tokio::test]
async fn a_linear_write_keeps_a_source_202_at_the_same_unfinished_step() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with_script(vec![
        ScriptedResponse::EffectComplete(Response::json(202, r#"{"sourceId":"source-20"}"#)),
        ScriptedResponse::EffectComplete(Response::json(200, r#"{"sourceId":"source-20"}"#)),
        ScriptedResponse::EffectComplete(Response::json(
            200,
            &json!({"name": "Example Person"}).to_string(),
        )),
    ]);
    let directory = linear_resume_project();
    let served = Served::start_for_deployment_endpoint(
        &upstream.url(""),
        &directory,
        "reference",
        "linear-resume-source-202",
        None,
    )
    .await;
    let token = served.token("records.write");
    let accepted_upstream = post(&served, &token, "linear-resume-4", &linear_request_body());
    assert_eq!(
        accepted_upstream.status,
        409,
        "{}",
        String::from_utf8_lossy(&accepted_upstream.body)
    );
    assert_eq!(
        accepted_upstream.retry_after.as_deref(),
        Some("5"),
        "a source 202 keeps the resumable step retryable"
    );
    let recovered = post(&served, &token, "linear-resume-4", &linear_request_body());
    assert_eq!(
        recovered.status,
        201,
        "{}",
        String::from_utf8_lossy(&recovered.body)
    );
    assert_eq!(
        upstream
            .requests()
            .iter()
            .map(|request| request.target.as_str())
            .collect::<Vec<_>>(),
        ["/drafts", "/drafts", "/finalizations?source_id=source-20"],
        "a source 202 never checkpoints or advances its unfinished ordinal"
    );
    assert_eq!(
        upstream.logical_effect_count(),
        2,
        "the provider collapses the retried first step to one logical effect"
    );
}

#[tokio::test]
async fn status_get_returns_exact_pending_then_commits_and_replays_terminal_proof() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![
        Response::json(202, &json!({"operationId": "source-18"}).to_string()),
        Response::json(200, &json!({"state": "pending"}).to_string()),
        Response::json(
            200,
            &json!({
                "state": "succeeded",
                "result": {
                    "tracked_entity_type": "cQWYtUfH6Vx",
                    "org_unit": "qfg4XUDJtgS",
                    "created_at": "2026-03-01T12:00:00.000",
                    "updated_at": "2026-03-01T12:00:00.000"
                }
            })
            .to_string(),
        ),
    ]);
    let directory = tempfile::tempdir().expect("an asynchronous project directory");
    async_project(directory.path());
    let served = Served::start_with_project(&upstream.url(""), directory.path()).await;
    let token = served.token("records.write");
    let accepted = post(&served, &token, "async-create-2", &request_body());
    assert_eq!(accepted.status, 202);
    let accepted_json: Value = serde_json::from_slice(&accepted.body).expect("accepted JSON");
    let status_path = accepted_json["statusLink"].as_str().expect("status link");

    let pending = served.get(status_path, Some(&token));
    assert_eq!(pending.0, 202, "{}", pending.2);
    assert_eq!(pending.2, accepted_json);
    assert!(pending.1.contains(&accepted.request_id));

    let terminal = served.get(status_path, Some(&token));
    assert_eq!(terminal.0, 201, "{}", terminal.2);
    assert!(terminal.1.contains(&accepted.request_id));
    assert_eq!(terminal.2["data"]["tracked_entity_type"], "cQWYtUfH6Vx");

    let journal_before_replay = served.journal_kinds().await;
    let replay = served.get(status_path, Some(&token));
    assert_eq!(
        (replay.0, without_date(&replay.1), replay.2),
        (terminal.0, without_date(&terminal.1), terminal.2),
        "terminal status custody replays exactly"
    );
    let journal_after_replay = served.journal_kinds().await;
    assert_eq!(
        journal_after_replay.len(),
        journal_before_replay.len() + 2,
        "a fresh terminal lookup journals its physical exchange"
    );
    assert_eq!(
        journal_after_replay
            .iter()
            .filter(|kind| kind.as_str() == "exchangeCreated")
            .count(),
        journal_before_replay
            .iter()
            .filter(|kind| kind.as_str() == "exchangeCreated")
            .count()
            + 1
    );
    assert_eq!(
        journal_after_replay
            .iter()
            .filter(|kind| kind.as_str() == "exchangeCompleted")
            .count(),
        journal_before_replay
            .iter()
            .filter(|kind| kind.as_str() == "exchangeCompleted")
            .count()
            + 1
    );
    assert_eq!(
        upstream.request_count(),
        3,
        "one mutation and two safe status polls reach the source"
    );
}

#[tokio::test]
async fn a_status_get_that_loses_the_lease_to_a_terminal_commit_replays_the_stored_answer() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![Response::json(
        202,
        &json!({"operationId": "source-race"}).to_string(),
    )]);
    let directory = tempfile::tempdir().expect("an asynchronous project directory");
    async_project(directory.path());
    let served = Arc::new(Served::start_with_project(&upstream.url(""), directory.path()).await);
    let token = served.token("records.write");
    let accepted = post(&served, &token, "async-create-race", &request_body());
    assert_eq!(accepted.status, 202);
    let accepted_json: Value = serde_json::from_slice(&accepted.body).expect("accepted JSON");
    let status_path = accepted_json["statusLink"]
        .as_str()
        .expect("status link")
        .to_owned();

    // A concurrent poller holds the accepted row: the GET reads `accepted`
    // and then waits on the row for its lease.
    let (poller, connection) = tokio_postgres::connect(&served.database, tokio_postgres::NoTls)
        .await
        .expect("connect the concurrent poller");
    tokio::spawn(connection);
    poller
        .batch_execute(
            "BEGIN; SELECT 1 FROM adapter_idempotency_entries \
             WHERE state = 'accepted' FOR UPDATE",
        )
        .await
        .expect("the concurrent poller holds the accepted row");
    let lookup = {
        let served = Arc::clone(&served);
        let token = token.clone();
        tokio::task::spawn_blocking(move || served.get(&status_path, Some(&token)))
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        // The poller reads pg_stat_activity inside its open transaction, where
        // PostgreSQL keeps the first read's snapshot. A GET on a connection
        // opened after that read stays invisible unless each read clears it.
        poller
            .batch_execute("SELECT pg_stat_clear_snapshot()")
            .await
            .expect("clear the activity snapshot");
        let waiting: i64 = poller
            .query_one(
                "SELECT count(*) FROM pg_stat_activity \
                 WHERE pg_backend_pid() = ANY(pg_blocking_pids(pid))",
                &[],
            )
            .await
            .expect("read the lock waiters")
            .get(0);
        if waiting > 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the status GET never waited for the poll lease"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // The concurrent poller proves the outcome and commits it, releasing
    // the lease the GET was waiting for.
    let terminal = json!({"data": {"marker": "committed-by-the-other-poller"}});
    poller
        .batch_execute(&format!(
            "UPDATE adapter_idempotency_entries \
             SET state = 'completed', terminal_at = now(), \
                 expires_at = now() + interval '1 hour', response_status = 201, \
                 response_content_type = 'application/json', response_body = '{terminal}'::bytea, \
                 async_source_id = NULL, async_recovery_id = NULL, \
                 async_poll_lease_id = NULL, async_poll_lease_until = NULL \
             WHERE state = 'accepted'; COMMIT"
        ))
        .await
        .expect("the concurrent poller commits the terminal answer");

    let answer = lookup.await.expect("the status GET completes");
    assert_eq!(
        answer.0, 201,
        "a valid link whose terminal answer is stored is replayed, not hidden: {}",
        answer.2
    );
    assert_eq!(answer.2, terminal);
    assert!(answer.1.contains(&accepted.request_id));
    assert_eq!(
        upstream.request_count(),
        1,
        "the losing GET polls nothing at the source"
    );
}

#[tokio::test]
async fn status_get_reauthenticates_the_original_caller_and_current_write_scope() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![
        Response::json(202, &json!({"operationId": "source-19"}).to_string()),
        Response::json(200, &json!({"state": "pending"}).to_string()),
    ]);
    let directory = tempfile::tempdir().expect("an asynchronous project directory");
    async_project(directory.path());
    let served = Served::start_with_project(&upstream.url(""), directory.path()).await;
    let writer = served.token("records.write");
    let accepted = post(&served, &writer, "async-create-auth", &request_body());
    let accepted_json: Value = serde_json::from_slice(&accepted.body).expect("accepted JSON");
    let status_path = accepted_json["statusLink"].as_str().expect("status link");

    let wrong_caller = served.token_for("different-caller", "records.write");
    let hidden = served.get(status_path, Some(&wrong_caller));
    assert_eq!(hidden.0, 404, "{}", hidden.2);

    let revoked_scope = served.token("records.read");
    let forbidden = served.get(status_path, Some(&revoked_scope));
    assert_eq!(forbidden.0, 403, "{}", forbidden.2);

    let pending = served.get(status_path, Some(&writer));
    assert_eq!(pending.0, 202, "{}", pending.2);
    assert_eq!(pending.2, accepted_json);
    assert_eq!(
        upstream.request_count(),
        2,
        "only the admitted original caller reaches the safe status route"
    );
}

#[tokio::test]
async fn a_status_link_survives_restart_under_the_same_artifact_and_caller() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![
        Response::json(202, &json!({"operationId": "source-20"}).to_string()),
        Response::json(
            200,
            &json!({
                "state": "succeeded",
                "result": {
                    "tracked_entity_type": "cQWYtUfH6Vx",
                    "org_unit": "qfg4XUDJtgS",
                    "created_at": "2026-03-01T12:00:00.000",
                    "updated_at": "2026-03-01T12:00:00.000"
                }
            })
            .to_string(),
        ),
    ]);
    let directory = tempfile::tempdir().expect("an asynchronous project directory");
    async_project(directory.path());
    let first =
        Served::start_for_deployment(&upstream.url(""), directory.path(), "async-restart", None)
            .await;
    let accepted = post(
        &first,
        &first.token("records.write"),
        "async-create-restart",
        &request_body(),
    );
    let accepted_json: Value = serde_json::from_slice(&accepted.body).expect("accepted JSON");
    let status_path = accepted_json["statusLink"]
        .as_str()
        .expect("status link")
        .to_owned();
    let database = first.database.clone();
    drop(first);

    let restarted = Served::start_for_deployment(
        &upstream.url(""),
        directory.path(),
        "async-restart",
        Some(&database),
    )
    .await;
    let terminal = restarted.get(&status_path, Some(&restarted.token("records.write")));
    assert_eq!(terminal.0, 201, "{}", terminal.2);
    assert!(terminal.1.contains(&accepted.request_id));
    assert_eq!(
        upstream.request_count(),
        2,
        "restart never repeats the mutation"
    );
}

/// The warning a held asynchronous row writes on each lookup.
const HELD_WARNING: &str = "is not polled";

fn succeeded_status() -> Response {
    Response::json(
        200,
        &json!({
            "state": "succeeded",
            "result": {
                "tracked_entity_type": "cQWYtUfH6Vx",
                "org_unit": "qfg4XUDJtgS",
                "created_at": "2026-03-01T12:00:00.000",
                "updated_at": "2026-03-01T12:00:00.000"
            }
        })
        .to_string(),
    )
}

#[tokio::test]
async fn a_status_link_is_polled_only_at_the_receiver_its_write_reached() {
    let original = UpstreamDouble::start();
    original.respond_with(vec![
        Response::json(202, &json!({"operationId": "source-receiver"}).to_string()),
        succeeded_status(),
    ]);
    let directory = tempfile::tempdir().expect("an asynchronous project directory");
    async_project(directory.path());
    let first =
        Served::start_for_deployment(&original.url(""), directory.path(), "async-receiver", None)
            .await;
    let accepted = post(
        &first,
        &first.token("records.write"),
        "async-create-receiver",
        &request_body(),
    );
    assert_eq!(
        accepted.status,
        202,
        "{}",
        String::from_utf8_lossy(&accepted.body)
    );
    let accepted_json: Value = serde_json::from_slice(&accepted.body).expect("accepted JSON");
    let status_path = accepted_json["statusLink"]
        .as_str()
        .expect("status link")
        .to_owned();
    let database = first.database.clone();
    drop(first);

    // The same artifact under a runtime file whose endpoint names another
    // receiver: the artifact digest is unchanged, the source origin is not.
    let other = UpstreamDouble::start();
    other.respond_with(vec![succeeded_status()]);
    let rebound = Served::start_for_deployment(
        &other.url(""),
        directory.path(),
        "async-receiver",
        Some(&database),
    )
    .await;
    let held = rebound.get(&status_path, Some(&rebound.token("records.write")));
    assert_eq!(held.0, 202, "{}", held.2);
    assert_eq!(held.2, accepted_json, "a held link answers its stored 202");
    assert_eq!(
        other.request_count(),
        0,
        "a receiver configured after the write is never consulted"
    );
    assert!(
        rebound.stderr_text().contains(HELD_WARNING),
        "a held row is reported: {}",
        rebound.stderr_text()
    );
    drop(rebound);

    // Configuring the original receiver again lets the write settle there.
    let restored = Served::start_for_deployment(
        &original.url(""),
        directory.path(),
        "async-receiver",
        Some(&database),
    )
    .await;
    let terminal = restored.get(&status_path, Some(&restored.token("records.write")));
    assert_eq!(terminal.0, 201, "{}", terminal.2);
    assert!(terminal.1.contains(&accepted.request_id));
    assert_eq!(
        original.request_count(),
        2,
        "one mutation and one status check, both at the original receiver"
    );
}

#[tokio::test]
async fn an_uncertain_effect_is_checked_only_at_the_receiver_its_write_reached() {
    let original = UpstreamDouble::start();
    original.respond_with(vec![
        Response::json(500, &json!({"error": "outcome unknown"}).to_string()),
        Response::json(200, &json!({"state": "pending"}).to_string()),
    ]);
    let directory = tempfile::tempdir().expect("an uncertainty recovery project directory");
    uncertainty_project(directory.path());
    let first = Served::start_for_deployment(
        &original.url(""),
        directory.path(),
        "async-uncertain-receiver",
        None,
    )
    .await;
    let request = request_body();
    let unknown = post(
        &first,
        &first.token("records.write"),
        "async-uncertain-receiver",
        &request,
    );
    assert_eq!(
        unknown.status,
        409,
        "{}",
        String::from_utf8_lossy(&unknown.body)
    );
    assert_eq!(unknown.retry_after.as_deref(), Some("5"));
    let database = first.database.clone();
    drop(first);

    let other = UpstreamDouble::start();
    other.respond_with(vec![succeeded_status()]);
    let rebound = Served::start_for_deployment(
        &other.url(""),
        directory.path(),
        "async-uncertain-receiver",
        Some(&database),
    )
    .await;
    let held = post(
        &rebound,
        &rebound.token("records.write"),
        "async-uncertain-receiver",
        &request,
    );
    assert_eq!(held.status, 409, "{}", String::from_utf8_lossy(&held.body));
    assert_eq!(
        held.retry_after, None,
        "no check under this configuration can prove the effect"
    );
    assert_eq!(
        other.request_count(),
        0,
        "a receiver configured after the write is never consulted"
    );
    assert_eq!(
        original.request_count(),
        2,
        "the mutation plus one safe check"
    );
    assert!(
        rebound.stderr_text().contains(HELD_WARNING),
        "a held row is reported: {}",
        rebound.stderr_text()
    );
}

#[tokio::test]
async fn an_async_write_without_a_receiver_pin_is_never_polled_and_expires() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![
        Response::json(202, &json!({"operationId": "source-unpinned"}).to_string()),
        succeeded_status(),
    ]);
    let directory = tempfile::tempdir().expect("an asynchronous project directory");
    async_project(directory.path());
    let served = Served::start_with_project(&upstream.url(""), directory.path()).await;
    let writer = served.token("records.write");
    let accepted = post(&served, &writer, "async-create-unpinned", &request_body());
    assert_eq!(
        accepted.status,
        202,
        "{}",
        String::from_utf8_lossy(&accepted.body)
    );
    let accepted_json: Value = serde_json::from_slice(&accepted.body).expect("accepted JSON");
    let status_path = accepted_json["statusLink"].as_str().expect("status link");

    // A row written before receiver pins existed carries none.
    served
        .execute_sql(
            "UPDATE adapter_idempotency_entries SET async_source_digest = NULL \
             WHERE state = 'accepted'",
        )
        .await;
    let held = served.get(status_path, Some(&writer));
    assert_eq!(held.0, 202, "{}", held.2);
    assert_eq!(held.2, accepted_json, "a held link answers its stored 202");
    assert_eq!(
        upstream.request_count(),
        1,
        "an unpinned row is never polled, even at an unchanged receiver"
    );
    assert!(
        served.stderr_text().contains(HELD_WARNING),
        "a held row is reported: {}",
        served.stderr_text()
    );

    served
        .execute_sql(
            "UPDATE adapter_idempotency_entries \
             SET async_expires_at = CURRENT_TIMESTAMP - interval '1 second' \
             WHERE state = 'accepted'",
        )
        .await;
    let expired = served.get(status_path, Some(&writer));
    assert_eq!(expired.0, 404, "{}", expired.2);
    assert_eq!(
        upstream.request_count(),
        1,
        "an expired row is never polled"
    );
}

#[tokio::test]
async fn a_status_link_settles_at_an_unchanged_receiver_after_a_credential_rotation() {
    const CREDENTIAL: &str = "      type: basic
      usernameRef: secret:env/TEST_UPSTREAM_USERNAME
      passwordRef: secret:env/TEST_UPSTREAM_PASSWORD
";
    const ROTATED_CREDENTIAL: &str = "      type: basic
      usernameRef: secret:env/TEST_UPSTREAM_PASSWORD
      passwordRef: secret:env/TEST_UPSTREAM_USERNAME
";
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![
        Response::json(202, &json!({"operationId": "source-rotated"}).to_string()),
        succeeded_status(),
    ]);
    let directory = tempfile::tempdir().expect("an asynchronous project directory");
    async_project(directory.path());
    let first = Served::start_with_pack_endpoint_and_credential(
        &upstream.url(""),
        directory.path(),
        &Served::example_pack(),
        "tracker",
        CREDENTIAL,
    )
    .await;
    let accepted = post(
        &first,
        &first.token("records.write"),
        "async-create-rotated",
        &request_body(),
    );
    assert_eq!(
        accepted.status,
        202,
        "{}",
        String::from_utf8_lossy(&accepted.body)
    );
    let accepted_json: Value = serde_json::from_slice(&accepted.body).expect("accepted JSON");
    let status_path = accepted_json["statusLink"]
        .as_str()
        .expect("status link")
        .to_owned();
    let database = first.database.clone();
    drop(first);

    let rotated = Served::start_with_pack_endpoint_credential_and_database(
        &upstream.url(""),
        directory.path(),
        &Served::example_pack(),
        "tracker",
        ROTATED_CREDENTIAL,
        &database,
    )
    .await;
    let terminal = rotated.get(&status_path, Some(&rotated.token("records.write")));
    assert_eq!(terminal.0, 201, "{}", terminal.2);
    let requests = upstream.requests();
    assert_eq!(requests.len(), 2, "one mutation and one status check");
    assert_ne!(
        requests[0].header("authorization"),
        requests[1].header("authorization"),
        "the status check ran under the rotated credential"
    );
}

#[tokio::test]
async fn a_synchronous_successor_starts_and_answers_the_older_artifacts_status_link_as_unknown() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![Response::json(
        202,
        &json!({"operationId": "source-artifact-fence"}).to_string(),
    )]);
    let async_directory = tempfile::tempdir().expect("an asynchronous project directory");
    async_project(async_directory.path());
    let first = Served::start_for_deployment(
        &upstream.url(""),
        async_directory.path(),
        "async-artifact-fence",
        None,
    )
    .await;
    let accepted = post(
        &first,
        &first.token("records.write"),
        "async-artifact-fence",
        &request_body(),
    );
    assert_eq!(accepted.status, 202);
    let accepted_json: Value = serde_json::from_slice(&accepted.body).expect("accepted JSON");
    let status_path = accepted_json["statusLink"]
        .as_str()
        .expect("status link")
        .to_owned();
    let database = first.database.clone();
    drop(first);

    // A successor that declares no asynchronous or resumable write mints no
    // recovery authority, so it starts over the older artifact's live row.
    let successor_directory =
        tempfile::tempdir().expect("a synchronous successor project directory");
    served_harness::copy_example_project(successor_directory.path());
    let successor = Served::start_for_deployment(
        &upstream.url(""),
        successor_directory.path(),
        "async-artifact-fence",
        Some(&database),
    )
    .await;
    let unknown = successor.get(&status_path, Some(&successor.token("records.write")));
    assert_eq!(unknown.0, 404, "{}", unknown.2);
    assert_eq!(
        upstream.request_count(),
        1,
        "the successor never polls or repeats the older artifact's effect"
    );
}

#[tokio::test]
async fn an_asynchronous_hotfix_is_refused_while_the_older_artifacts_write_is_unfinished() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![Response::json(
        202,
        &json!({"operationId": "source-hotfix-fence"}).to_string(),
    )]);
    let directory = tempfile::tempdir().expect("an asynchronous project directory");
    async_project(directory.path());
    let first = Served::start_for_deployment(
        &upstream.url(""),
        directory.path(),
        "async-hotfix-fence",
        None,
    )
    .await;
    let accepted = post(
        &first,
        &first.token("records.write"),
        "async-hotfix-fence",
        &request_body(),
    );
    assert_eq!(accepted.status, 202);
    let database = first.database.clone();
    drop(first);

    // Any byte change makes a new artifact; the accepted row still carries
    // the older artifact's recovery authority.
    let project_path = directory.path().join("project.yaml");
    let mut project = std::fs::read_to_string(&project_path).expect("read the project");
    project.push_str("# hotfix\n");
    std::fs::write(&project_path, project).expect("write the hotfix project");
    let refusal = Served::refusal_for_deployment(
        &upstream.url(""),
        directory.path(),
        "async-hotfix-fence",
        &database,
    )
    .await;
    assert!(
        refusal.contains("asynchronous artifact custody"),
        "the hotfix must fail at the durable artifact fence: {refusal}"
    );
    assert!(
        refusal.contains("1 unfinished asynchronous or resumable write")
            && refusal.contains("redeploy the previous artifact bytes"),
        "the refusal tells the operator what blocks it and what to do: {refusal}"
    );
    assert_eq!(
        upstream.request_count(),
        1,
        "the refused hotfix starts no source effect"
    );
}

#[tokio::test]
async fn an_expired_status_link_is_hidden_and_the_write_key_stays_spent() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![Response::json(
        202,
        &json!({"operationId": "source-21"}).to_string(),
    )]);
    let directory = tempfile::tempdir().expect("an asynchronous project directory");
    async_project(directory.path());
    let served = Served::start_with_project_retention(&upstream.url(""), directory.path(), 1).await;
    let token = served.token("records.write");
    let accepted = post(&served, &token, "async-create-expiry", &request_body());
    let accepted_json: Value = serde_json::from_slice(&accepted.body).expect("accepted JSON");
    let status_path = accepted_json["statusLink"].as_str().expect("status link");
    tokio::time::sleep(Duration::from_millis(1_200)).await;

    let expired = served.get(status_path, Some(&token));
    assert_eq!(expired.0, 404, "{}", expired.2);
    let retry = post(&served, &token, "async-create-expiry", &request_body());
    assert_eq!(
        retry.status,
        409,
        "{}",
        String::from_utf8_lossy(&retry.body)
    );
    assert_eq!(retry.retry_after, None, "an expired key is spent");
    assert_eq!(
        upstream.request_count(),
        1,
        "expiry never reopens the effect"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_acceptance_journal_fault_commits_neither_202_nor_false_acceptance() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![Response::json(
        202,
        &json!({"operationId": "source-22"}).to_string(),
    )]);
    upstream.delay_answers(Duration::from_millis(700));
    let directory = tempfile::tempdir().expect("an asynchronous project directory");
    async_project(directory.path());
    let served = Arc::new(Served::start_with_project(&upstream.url(""), directory.path()).await);
    let token = served.token("records.write");
    let first = {
        let served = Arc::clone(&served);
        let token = token.clone();
        tokio::task::spawn_blocking(move || {
            post(
                &served,
                &token,
                "async-create-journal-fault",
                &request_body(),
            )
        })
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while upstream.request_count() == 0 {
        assert!(
            Instant::now() < deadline,
            "the mutation never reached the source"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    served
        .execute_sql("ALTER TABLE adapter_journal_events RENAME TO adapter_journal_broken")
        .await;
    let first = first.await.expect("the first caller completes");
    assert_eq!(
        first.status,
        500,
        "{}",
        String::from_utf8_lossy(&first.body)
    );
    served
        .execute_sql("ALTER TABLE adapter_journal_broken RENAME TO adapter_journal_events")
        .await;

    // Age the effect mark past the exchange deadline: the attempt that
    // marked it has certainly ended, so nothing can still answer the key.
    served
        .execute_sql(
            "UPDATE adapter_idempotency_entries \
             SET effect_started_at = effect_started_at - interval '61 seconds' \
             WHERE state = 'effect_started'",
        )
        .await;
    let retry = post(
        &served,
        &token,
        "async-create-journal-fault",
        &request_body(),
    );
    assert_eq!(
        retry.status,
        409,
        "{}",
        String::from_utf8_lossy(&retry.body)
    );
    assert_eq!(
        retry.retry_after, None,
        "an unproved effect without recovery is spent"
    );
    assert_eq!(
        upstream.request_count(),
        1,
        "the uncertain mutation stays spent"
    );
    assert!(
        served
            .journal_kinds()
            .await
            .iter()
            .all(|kind| kind != "exchangeAccepted"),
        "the rolled-back acceptance transaction leaves no false journal event"
    );
}

#[tokio::test]
async fn bounded_wait_commits_and_replays_a_proven_terminal_response_without_repeating_the_effect()
{
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![
        Response::json(202, &json!({"operationId": "source-wait-1"}).to_string()),
        Response::json(
            200,
            &json!({
                "state": "succeeded",
                "result": {
                    "tracked_entity_type": "cQWYtUfH6Vx",
                    "org_unit": "qfg4XUDJtgS",
                    "created_at": "2026-03-01T12:00:00.000",
                    "updated_at": "2026-03-01T12:00:00.000"
                }
            })
            .to_string(),
        ),
    ]);
    let directory = tempfile::tempdir().expect("a bounded-wait project directory");
    bounded_wait_project(directory.path(), 1_000, 10, 2);
    let served = Served::start_with_project(&upstream.url(""), directory.path()).await;
    let token = served.token("records.write");
    let request = request_body();

    let terminal = post(&served, &token, "async-wait-terminal", &request);
    assert_eq!(
        terminal.status,
        201,
        "{}",
        String::from_utf8_lossy(&terminal.body)
    );
    let terminal_body: Value = serde_json::from_slice(&terminal.body).expect("terminal JSON");
    assert_eq!(terminal_body["data"]["tracked_entity_type"], "cQWYtUfH6Vx");
    assert_eq!(
        served.journal_details("exchangeAccepted").await[0]["mode"],
        "bounded-wait",
        "the accepted milestone records the selected facade mode"
    );

    let replay = post(&served, &token, "async-wait-terminal", &request);
    assert_eq!(replay.status, terminal.status);
    assert_eq!(replay.request_id, terminal.request_id);
    assert_eq!(replay.body, terminal.body);
    let status_path = format!("/v1/write-status/{}", terminal.request_id);
    let status_replay = served.get(&status_path, Some(&token));
    assert_eq!(status_replay.0, 201, "{}", status_replay.2);
    assert!(status_replay.1.contains(&terminal.request_id));
    assert_eq!(status_replay.2, terminal_body);
    assert_eq!(
        upstream.request_count(),
        2,
        "one mutation and one safe poll prove the terminal result"
    );
}

#[tokio::test]
async fn bounded_wait_returns_the_committed_202_after_its_poll_count_is_spent() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![
        Response::json(202, &json!({"operationId": "source-wait-2"}).to_string()),
        Response::json(200, &json!({"state": "pending"}).to_string()),
        Response::json(200, &json!({"state": "pending"}).to_string()),
        Response::json(200, &json!({"state": "pending"}).to_string()),
    ]);
    let directory = tempfile::tempdir().expect("a bounded-wait project directory");
    bounded_wait_project(directory.path(), 1_000, 10, 2);
    let served = Served::start_with_project(&upstream.url(""), directory.path()).await;
    let token = served.token("records.write");
    let request = request_body();

    let accepted = post(&served, &token, "async-wait-polls", &request);
    assert_eq!(
        accepted.status,
        202,
        "{}",
        String::from_utf8_lossy(&accepted.body)
    );
    let replay = post(&served, &token, "async-wait-polls", &request);
    assert_eq!(replay.status, 202);
    assert_eq!(replay.request_id, accepted.request_id);
    assert_eq!(replay.body, accepted.body);
    assert_eq!(
        upstream.request_count(),
        3,
        "one mutation plus exactly two declared safe polls"
    );
    let accepted_body: Value =
        serde_json::from_slice(&accepted.body).expect("the committed accepted response");
    let status_path = accepted_body["statusLink"].as_str().expect("status link");
    let pending = served.get(status_path, Some(&token));
    assert_eq!(pending.0, 202, "{}", pending.2);
    assert_eq!(pending.2, accepted_body);
    assert_eq!(
        upstream.request_count(),
        4,
        "the still-live status link performs one later safe poll"
    );
}

#[tokio::test]
async fn bounded_wait_cancels_a_slow_poll_at_its_deadline_and_returns_the_committed_202() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![
        Response::json(202, &json!({"operationId": "source-wait-3"}).to_string()),
        Response::json(200, &json!({"state": "pending"}).to_string()),
    ]);
    upstream.delay_answers(Duration::from_millis(500));
    let directory = tempfile::tempdir().expect("a bounded-wait project directory");
    bounded_wait_project(directory.path(), 200, 10, 2);
    let served = Served::start_with_project(&upstream.url(""), directory.path()).await;
    let token = served.token("records.write");

    let accepted = post(&served, &token, "async-wait-deadline", &request_body());
    assert_eq!(
        accepted.status,
        202,
        "{}",
        String::from_utf8_lossy(&accepted.body)
    );
    let accepted_body: Value =
        serde_json::from_slice(&accepted.body).expect("the committed accepted response");
    assert_eq!(accepted_body["requestId"], accepted.request_id);
    assert_eq!(
        upstream.request_count(),
        2,
        "the absolute wait deadline cancels the first slow poll and starts no second poll"
    );
}

#[tokio::test]
async fn an_uncertain_effect_can_be_proved_terminal_without_repeating_the_mutation() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![
        Response::json(500, &json!({"error": "outcome unknown"}).to_string()),
        Response::json(
            200,
            &json!({
                "state": "succeeded",
                "result": {
                    "tracked_entity_type": "cQWYtUfH6Vx",
                    "org_unit": "qfg4XUDJtgS",
                    "created_at": "2026-03-01T12:00:00.000",
                    "updated_at": "2026-03-01T12:00:00.000"
                }
            })
            .to_string(),
        ),
    ]);
    let directory = tempfile::tempdir().expect("an uncertainty recovery project directory");
    uncertainty_project(directory.path());
    let served = Served::start_with_project(&upstream.url(""), directory.path()).await;
    let token = served.token("records.write");
    let request = request_body();

    let recovered = post(&served, &token, "async-uncertain-terminal", &request);
    assert_eq!(
        recovered.status,
        201,
        "{}",
        String::from_utf8_lossy(&recovered.body)
    );
    let replay = post(&served, &token, "async-uncertain-terminal", &request);
    assert_eq!(replay.status, recovered.status);
    assert_eq!(replay.request_id, recovered.request_id);
    assert_eq!(replay.body, recovered.body);
    let requests = upstream.requests();
    assert_eq!(
        requests.len(),
        2,
        "one mutation and one safe recovery check"
    );
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[1].method, "GET");
    let initial_recovery = requests[0]
        .header("x-registry-recovery-id")
        .expect("initial recovery correlation");
    assert_eq!(initial_recovery.len(), 64);
    assert!(initial_recovery
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(
        requests[1].header("x-registry-recovery-id"),
        Some(initial_recovery)
    );
}

#[tokio::test]
async fn an_uncertain_effect_stays_spent_until_a_later_safe_check_proves_it_terminal() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![
        Response::json(500, &json!({"error": "outcome unknown"}).to_string()),
        Response::json(200, &json!({"state": "pending"}).to_string()),
        Response::json(
            200,
            &json!({
                "state": "succeeded",
                "result": {
                    "tracked_entity_type": "cQWYtUfH6Vx",
                    "org_unit": "qfg4XUDJtgS",
                    "created_at": "2026-03-01T12:00:00.000",
                    "updated_at": "2026-03-01T12:00:00.000"
                }
            })
            .to_string(),
        ),
    ]);
    let directory = tempfile::tempdir().expect("an uncertainty recovery project directory");
    uncertainty_project(directory.path());
    let served = Served::start_with_project(&upstream.url(""), directory.path()).await;
    let token = served.token("records.write");
    let request = request_body();

    let unknown = post(&served, &token, "async-uncertain-retry", &request);
    assert_eq!(
        unknown.status,
        409,
        "{}",
        String::from_utf8_lossy(&unknown.body)
    );
    assert_eq!(
        unknown.retry_after.as_deref(),
        Some("5"),
        "a later safe check can still prove the uncertain effect"
    );
    assert_eq!(
        upstream.request_count(),
        2,
        "the mutation plus one safe check"
    );

    let recovered = post(&served, &token, "async-uncertain-retry", &request);
    assert_eq!(
        recovered.status,
        201,
        "{}",
        String::from_utf8_lossy(&recovered.body)
    );
    let replay = post(&served, &token, "async-uncertain-retry", &request);
    assert_eq!(replay.status, recovered.status);
    assert_eq!(replay.request_id, recovered.request_id);
    assert_eq!(replay.body, recovered.body);
    let requests = upstream.requests();
    assert_eq!(requests.len(), 3, "the original mutation is never repeated");
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method == "POST")
            .count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method == "GET")
            .count(),
        2
    );
}

#[tokio::test]
async fn an_unknown_effect_without_source_recovery_stays_spent_and_never_repeats() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![Response::json(
        500,
        &json!({"error": "outcome unknown"}).to_string(),
    )]);
    let directory = tempfile::tempdir().expect("an asynchronous project directory");
    async_project(directory.path());
    let served = Served::start_with_project(&upstream.url(""), directory.path()).await;
    let token = served.token("records.write");
    let request = request_body();

    let unknown = post(&served, &token, "async-unknown-no-recovery", &request);
    assert_eq!(
        unknown.status,
        409,
        "{}",
        String::from_utf8_lossy(&unknown.body)
    );
    assert_eq!(
        unknown.retry_after, None,
        "no recovery is declared, so the key is spent"
    );
    // Age the effect mark past the exchange deadline: the attempt that
    // marked it has certainly ended, so nothing can still answer the key.
    served
        .execute_sql(
            "UPDATE adapter_idempotency_entries \
             SET effect_started_at = effect_started_at - interval '61 seconds' \
             WHERE state = 'effect_started'",
        )
        .await;
    let retry = post(&served, &token, "async-unknown-no-recovery", &request);
    assert_eq!(
        retry.status,
        409,
        "{}",
        String::from_utf8_lossy(&retry.body)
    );
    assert_eq!(retry.retry_after, None, "the spent key stays spent");
    assert_eq!(
        upstream.request_count(),
        1,
        "uncertainty never grants authority to repeat the mutation"
    );
}
