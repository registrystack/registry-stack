// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL proofs for the fixed GovStack Write over the BReg pack: a
//! failed replay keeps exact response custody while journaling the canonical
//! Problem identity for every attempt, a redeploy never resends an
//! interrupted write, a completed Update replays ahead of its guard, a
//! bodyless Update does not negotiate `Accept`, and an Update stays a flat
//! merge patch whatever its input schema admits.
#![cfg(feature = "postgres-test")]

#[allow(dead_code)]
#[path = "support/served/mod.rs"]
mod served_harness;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};
use served_harness::upstream::{Response, UpstreamDouble};
use served_harness::Served;

const CREATE_PATH: &str = "/govstack/registries/v1/collections/contacts/records";
const INVALID_CONTENT: &str = "https://govstack.global/problems/digital-registries/invalid-content";

fn repository_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

fn post(served: &Served, token: &str, key: &str, traceparent: &str, body: &Value) -> RawResponse {
    let body = body.to_string();
    let mut stream = TcpStream::connect(("127.0.0.1", served.port)).expect("connect to facade");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("set facade timeout");
    let request = format!(
        "POST {CREATE_PATH} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Bearer {token}\r\nAccept: application/json\r\nContent-Type: application/json\r\nIdempotency-Key: {key}\r\ntraceparent: {traceparent}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("send write");
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).expect("read facade reply");
    RawResponse::parse(bytes)
}

#[derive(Debug)]
struct RawResponse {
    status: u16,
    body: Vec<u8>,
    traceparent: String,
}

impl RawResponse {
    fn parse(bytes: Vec<u8>) -> Self {
        let head_end = bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("facade reply has a header block");
        let head = std::str::from_utf8(&bytes[..head_end]).expect("facade headers are text");
        let status = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<u16>().ok())
            .expect("facade status");
        let traceparent = head
            .lines()
            .skip(1)
            .filter_map(|line| line.split_once(':'))
            .find_map(|(name, value)| {
                name.eq_ignore_ascii_case("traceparent")
                    .then(|| value.trim().to_owned())
            })
            .expect("facade response carries trace context");
        Self {
            status,
            body: bytes[head_end + 4..].to_vec(),
            traceparent,
        }
    }
}

#[tokio::test]
async fn failed_exact_replay_keeps_body_and_journals_canonical_problem_per_attempt() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![Response::json(
        422,
        &json!({"status": 422, "code": "action.refused"}).to_string(),
    )]);
    let project = repository_path("products/adapter/examples/breg-govstack");
    let pack = repository_path("products/adapter/packs/breg-records/pack.yaml");
    let served = Served::start_with_pack_endpoint_and_credential(
        &upstream.url(""),
        &project,
        &pack,
        "registry",
        "      type: static-authorization\n      tokenRef: secret:env/TEST_UPSTREAM_PASSWORD\n",
    )
    .await;
    let token = served.token("records.write");
    let key = r#""failed-create-audit""#;
    let body = json!({"data": {"name": "Ada", "email": "ada@example.test"}});

    let first = post(
        &served,
        &token,
        key,
        "00-11111111111111111111111111111111-1111111111111111-01",
        &body,
    );
    let replay = post(
        &served,
        &token,
        key,
        "00-22222222222222222222222222222222-2222222222222222-01",
        &body,
    );

    assert_eq!(
        first.status,
        422,
        "{}",
        String::from_utf8_lossy(&first.body)
    );
    assert_eq!(replay.status, first.status);
    assert_eq!(
        replay.body, first.body,
        "the stored Problem body replays exactly"
    );
    assert_ne!(
        replay.traceparent, first.traceparent,
        "each physical attempt keeps its effective trace header"
    );
    assert_eq!(
        upstream.request_count(),
        1,
        "replay performs no source send"
    );

    let failures = served.journal_details("exchangeFailed").await;
    assert_eq!(
        failures.len(),
        2,
        "the original and replay are both terminal attempts"
    );
    for failure in failures {
        assert_eq!(failure["problemCode"], INVALID_CONTENT, "{failure}");
        assert_eq!(failure["status"], 422, "{failure}");
    }
}

#[tokio::test]
async fn a_bare_idempotency_key_is_refused_with_a_hint_to_quote_it() {
    let upstream = UpstreamDouble::start();
    let project = repository_path("products/adapter/examples/breg-govstack");
    let pack = repository_path("products/adapter/packs/breg-records/pack.yaml");
    let served = Served::start_with_pack_endpoint_and_credential(
        &upstream.url(""),
        &project,
        &pack,
        "registry",
        CREDENTIAL,
    )
    .await;
    let token = served.token("records.write");
    let body = json!({"data": {"name": "Ada", "email": "ada@example.test"}});

    let refused = post(
        &served,
        &token,
        "8a6e0804-2bd0-4672-b79d-d97027f9071a",
        "00-33333333333333333333333333333333-3333333333333333-01",
        &body,
    );

    assert_eq!(
        refused.status,
        400,
        "{}",
        String::from_utf8_lossy(&refused.body)
    );
    let problem: Value = serde_json::from_slice(&refused.body).expect("problem body is JSON");
    let detail = problem["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("quoted") && !detail.contains("8a6e0804"),
        "the detail tells the caller to quote the key without echoing it: {problem}"
    );
    assert_eq!(upstream.request_count(), 0, "a refused key sends nothing");
}

const CREDENTIAL: &str =
    "      type: static-authorization\n      tokenRef: secret:env/TEST_UPSTREAM_PASSWORD\n";

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("create the project copy");
    for entry in std::fs::read_dir(from).expect("read the project tree") {
        let entry = entry.expect("a project entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("entry type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).expect("copy a project file");
        }
    }
}

#[tokio::test]
async fn a_redeploy_activates_past_an_interrupted_write_and_never_resends_it() {
    let pack = repository_path("products/adapter/packs/breg-records/pack.yaml");
    let project = repository_path("products/adapter/examples/breg-govstack");
    let first_source = UpstreamDouble::start();
    first_source.respond_with(vec![Response::json(503, "{}")]);
    let first = Served::start_with_pack_endpoint_and_credential(
        &first_source.url(""),
        &project,
        &pack,
        "registry",
        CREDENTIAL,
    )
    .await;
    let token = first.token("records.write");
    let key = r#""interrupted-create""#;
    let body = json!({"data": {"name": "Ada", "email": "ada@example.test"}});
    let interrupted = post(
        &first,
        &token,
        key,
        "00-33333333333333333333333333333333-3333333333333333-01",
        &body,
    );
    // An ambiguous source failure leaves the single write resumable.
    assert_eq!(
        interrupted.status,
        409,
        "{}",
        String::from_utf8_lossy(&interrupted.body)
    );
    assert_eq!(first_source.request_count(), 1);
    let database = first.database.clone();
    drop(first);

    // A changed project is a changed artifact, and the changed endpoint
    // base is a changed source origin the artifact digest does not cover.
    let changed = tempfile::tempdir().expect("a project copy");
    copy_tree(&project, changed.path());
    let project_path = changed.path().join("project.yaml");
    let mut changed_project = std::fs::read_to_string(&project_path).expect("read the project");
    changed_project.push_str("# a redeployed artifact\n");
    std::fs::write(&project_path, changed_project).expect("write the changed project");
    let second_source = UpstreamDouble::start();
    second_source.respond_with(vec![Response::json(
        422,
        &json!({"status": 422, "code": "action.refused"}).to_string(),
    )]);
    let second = Served::start_with_pack_endpoint_credential_and_database(
        &second_source.url(""),
        changed.path(),
        &pack,
        "registry",
        CREDENTIAL,
        &database,
    )
    .await;
    let token = second.token("records.write");
    // The database is shared with the first instance, so count only the
    // conflicts this retry adds.
    let conflicts_before = conflict_failures(&second).await;

    let retry = post(
        &second,
        &token,
        key,
        "00-44444444444444444444444444444444-4444444444444444-01",
        &body,
    );
    assert_eq!(
        retry.status,
        409,
        "{}",
        String::from_utf8_lossy(&retry.body)
    );
    assert_eq!(
        second_source.request_count(),
        0,
        "a possibly sent write is never resent across a redeploy"
    );
    let fresh = post(
        &second,
        &token,
        r#""fresh-create""#,
        "00-55555555555555555555555555555555-5555555555555555-01",
        &body,
    );
    assert_eq!(
        fresh.status,
        422,
        "{}",
        String::from_utf8_lossy(&fresh.body)
    );
    assert_eq!(second_source.request_count(), 1);
    assert_eq!(
        conflict_failures(&second).await,
        conflicts_before + 1,
        "the retry's effect-unknown answer is journaled once"
    );
}

async fn conflict_failures(served: &Served) -> usize {
    served
        .journal_details("exchangeFailed")
        .await
        .iter()
        .filter(|failure| failure["class"] == "facade.conflict")
        .count()
}

const RECORD_ID: &str = "00000000-0000-4000-8000-000000000001";

/// One successful one-item BReg batch answer for `operation`.
fn batch_receipt(operation: &str, etag: &str) -> Response {
    Response::json(
        200,
        &json!({"results": [{
            "operation": operation,
            "recordIdentifier": RECORD_ID,
            "etag": etag,
            "domainData": {"name": "Ada", "email": "ada@example.test", "jurisdiction": "zone-a"}
        }]})
        .to_string(),
    )
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (field, value) = line.split_once(':')?;
        field.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

fn record_path() -> String {
    format!("{CREATE_PATH}/{RECORD_ID}")
}

/// Create the synthetic contact and return its public ETag.
fn create_contact(served: &Served, token: &str, key: &str) -> String {
    let (status, head, body) = served.request(
        "POST",
        CREATE_PATH,
        Some(token),
        &[
            ("Content-Type", "application/json"),
            ("Idempotency-Key", key),
        ],
        json!({"data": {"name": "Ada", "email": "ada@example.test"}})
            .to_string()
            .as_bytes(),
    );
    assert_eq!(status, 201, "{body}\n{}", served.stderr_text());
    header(&head, "etag")
        .expect("a created record carries its ETag")
        .to_owned()
}

fn patch(
    served: &Served,
    token: &str,
    key: &str,
    if_match: &str,
    extra: &[(&str, &str)],
    data: &Value,
) -> (u16, String, Value) {
    let mut headers = vec![
        ("Content-Type", "application/merge-patch+json"),
        ("Idempotency-Key", key),
        ("If-Match", if_match),
    ];
    headers.extend_from_slice(extra);
    served.request(
        "PATCH",
        &record_path(),
        Some(token),
        &headers,
        json!({"data": data}).to_string().as_bytes(),
    )
}

#[tokio::test]
async fn a_completed_update_replays_after_its_validator_closure_changes() {
    let pack = repository_path("products/adapter/packs/breg-records/pack.yaml");
    let project = repository_path("products/adapter/examples/breg-govstack");
    let first_source = UpstreamDouble::start();
    first_source.respond_with(vec![
        batch_receipt("create", "\"breg-1\""),
        batch_receipt("patch", "\"breg-2\""),
    ]);
    let first = Served::start_with_pack_endpoint_and_credential(
        &first_source.url(""),
        &project,
        &pack,
        "registry",
        CREDENTIAL,
    )
    .await;
    let token = first.token("records.write");
    let created = create_contact(&first, &token, r#""closure-create""#);
    let key = r#""closure-update""#;
    let data = json!({"name": "Augusta Ada King"});
    let (status, head, body) = patch(&first, &token, key, &created, &[], &data);
    assert_eq!(status, 204, "{body}\n{}", first.stderr_text());
    let updated = header(&head, "etag")
        .expect("the update carries its new ETag")
        .to_owned();
    assert_eq!(first_source.request_count(), 2);
    let database = first.database.clone();
    drop(first);

    // The configured source origin is part of the validator closure, so the
    // redeployed facade can no longer open the guard the client sent.
    let second_source = UpstreamDouble::start();
    let second = Served::start_with_pack_endpoint_credential_and_database(
        &second_source.url(""),
        &project,
        &pack,
        "registry",
        CREDENTIAL,
        &database,
    )
    .await;
    let token = second.token("records.write");

    let (status, head, body) = patch(&second, &token, key, &created, &[], &data);
    assert_eq!(
        status,
        204,
        "the completed Update replays before its guard is evaluated: {body}\n{}",
        second.stderr_text()
    );
    assert_eq!(header(&head, "etag"), Some(updated.as_str()));
    assert_eq!(second_source.request_count(), 0, "a replay sends nothing");

    let (status, _, problem) = patch(
        &second,
        &token,
        r#""closure-update-fresh""#,
        &created,
        &[],
        &data,
    );
    assert_eq!(status, 412, "{problem}");
    assert_eq!(
        problem["type"],
        "https://govstack.global/problems/digital-registries/precondition-failed"
    );
    let (status, _, problem) = patch(
        &second,
        &token,
        key,
        &created,
        &[],
        &json!({"name": "Changed"}),
    );
    assert_eq!(
        status, 412,
        "only an identical completed request replays ahead of its guard: {problem}"
    );
    assert_eq!(second_source.request_count(), 0);
}

#[tokio::test]
async fn a_bodyless_update_does_not_negotiate_accept_but_create_still_does() {
    let pack = repository_path("products/adapter/packs/breg-records/pack.yaml");
    let project = repository_path("products/adapter/examples/breg-govstack");
    let source = UpstreamDouble::start();
    source.respond_with(vec![
        batch_receipt("create", "\"breg-1\""),
        batch_receipt("patch", "\"breg-2\""),
        batch_receipt("patch", "\"breg-3\""),
    ]);
    let served = Served::start_with_pack_endpoint_and_credential(
        &source.url(""),
        &project,
        &pack,
        "registry",
        CREDENTIAL,
    )
    .await;
    let token = served.token("records.write");

    let (status, _, body) = served.request(
        "POST",
        CREATE_PATH,
        Some(&token),
        &[
            ("Content-Type", "application/json"),
            ("Accept", "application/problem+json"),
            ("Idempotency-Key", r#""accept-create-refused""#),
        ],
        json!({"data": {"name": "Ada", "email": "ada@example.test"}})
            .to_string()
            .as_bytes(),
    );
    assert_eq!(status, 406, "a Create receipt is JSON: {body}");
    assert_eq!(source.request_count(), 0);

    let created = create_contact(&served, &token, r#""accept-create""#);
    let (status, head, body) = patch(
        &served,
        &token,
        r#""accept-update-problem""#,
        &created,
        &[("Accept", "application/problem+json")],
        &json!({"name": "Augusta Ada King"}),
    );
    assert_eq!(status, 204, "{body}\n{}", served.stderr_text());
    let updated = header(&head, "etag").expect("new ETag").to_owned();

    let (status, _, body) = patch(
        &served,
        &token,
        r#""accept-update-other""#,
        &updated,
        &[("Accept", "text/html")],
        &json!({"name": "Ada King"}),
    );
    assert_eq!(status, 204, "an Update never fails on Accept alone: {body}");
    assert_eq!(source.request_count(), 3);
}

#[tokio::test]
async fn an_update_refuses_a_nested_object_member_even_when_its_schema_admits_one() {
    let pack = repository_path("products/adapter/packs/breg-records/pack.yaml");
    let original = repository_path("products/adapter/examples/breg-govstack");
    let changed = tempfile::tempdir().expect("a project copy");
    copy_tree(&original, changed.path());
    // Widen the Update input schema to admit an object member.
    let schema_path = changed.path().join("schemas/contact-update.schema.json");
    let old_schema = std::fs::read(&schema_path).expect("read the update schema");
    let mut schema: Value = serde_json::from_slice(&old_schema).expect("schema JSON");
    schema["properties"]["address"] = json!({
        "type": "object", "additionalProperties": false,
        "properties": {"city": {"type": "string"}}
    });
    let new_schema = serde_json::to_vec_pretty(&schema).expect("schema bytes");
    std::fs::write(&schema_path, &new_schema).expect("write the widened schema");
    let project_path = changed.path().join("project.yaml");
    let project_text = std::fs::read_to_string(&project_path).expect("read the project");
    let old_pin = served_harness::digest_of(&old_schema);
    assert!(
        project_text.contains(&old_pin),
        "the project pins the schema"
    );
    std::fs::write(
        &project_path,
        project_text.replace(&old_pin, &served_harness::digest_of(&new_schema)),
    )
    .expect("re-pin the widened schema");

    let source = UpstreamDouble::start();
    source.respond_with(vec![batch_receipt("create", "\"breg-1\"")]);
    let served = Served::start_with_pack_endpoint_and_credential(
        &source.url(""),
        changed.path(),
        &pack,
        "registry",
        CREDENTIAL,
    )
    .await;
    let token = served.token("records.write");
    let created = create_contact(&served, &token, r#""nested-create""#);

    let (status, _, problem) = patch(
        &served,
        &token,
        r#""nested-update""#,
        &created,
        &[],
        &json!({"name": "Ada", "address": {"city": "London"}}),
    );
    assert_eq!(status, 422, "{problem}\n{}", served.stderr_text());
    assert_eq!(problem["type"], INVALID_CONTENT);
    assert_eq!(
        problem["errors"][0]["pointer"], "/data/address",
        "{problem}"
    );
    assert_eq!(
        problem["errors"].as_array().map(Vec::len),
        Some(1),
        "{problem}"
    );
    assert_eq!(
        source.request_count(),
        1,
        "the refused Update sends nothing"
    );
}
