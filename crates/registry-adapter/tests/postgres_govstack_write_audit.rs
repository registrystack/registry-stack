// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL proofs for the fixed GovStack Write over the BReg pack: a
//! failed replay keeps exact response custody while journaling the canonical
//! Problem identity for every attempt, and a redeploy never resends an
//! interrupted write.
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
    assert!(
        second
            .journal_details("exchangeFailed")
            .await
            .iter()
            .any(|failure| failure["class"] == "facade.conflict"),
        "the effect-unknown answer is journaled"
    );
}
