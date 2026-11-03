// SPDX-License-Identifier: Apache-2.0

//! Authored deployment proof for nondefault Idempotent Consumer modes.
//!
//! Camel checks repository membership without adding it when `eager=false`,
//! then adds the key only on successful completion. `completionEager=true`
//! runs that completion when the guarded block ends. The Adapter preserves
//! those EIP timings while its facade independently reserves the write key in
//! PostgreSQL before guarded work, so concurrent requests cannot both run.
//! The reference is Camel 4.23.0's `IdempotentConsumer` and
//! `IdempotentOnCompletion` at the commit pinned by the product concept.
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
use served_harness::upstream::{Response, UpstreamDouble};
use served_harness::{capture, copy_example_project, replace_pack_text, Served};

struct RawPostResponse {
    status: u16,
    request_id: String,
    body: Vec<u8>,
}

fn post(served: &Served, token: &str, key: &str, body: &Value) -> RawPostResponse {
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

fn accepted_upstream_response() -> Response {
    let (status, body) = capture("import-accepted");
    Response::json(status, &body)
}

fn author_nondefault_pack(directory: &Path) {
    replace_pack_text(
        directory,
        "          expression:\n            header: Idempotency-Key\n          steps:\n",
        "          expression:\n            header: Idempotency-Key\n          eager: false\n          completionEager: true\n          steps:\n            - setProperty:\n                name: nondefaultSubmittedRecord\n                value:\n                  jsonpath: \"$\"\n            - to:\n                uri: http:tracker\n                parameters:\n                  httpMethod: GET\n                  path: /api/system/info\n                  operation: tracker-export\n            - setBody:\n                exchangeProperty: nondefaultSubmittedRecord\n",
    );
}

/// The authored nondefault modes pass the artifact reader, live loader, and
/// route compiler, then execute through the authenticated facade and durable
/// PostgreSQL store. The synthetic leading GET makes a failure before the
/// non-safe write observable without changing production behavior.
#[tokio::test(flavor = "multi_thread")]
async fn authored_nondefault_modes_retry_replay_refuse_and_reserve_atomically() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![
        Response::json(500, r#"{"failure":"synthetic-safe-preflight"}"#),
        Response::json(200, "{}"),
        accepted_upstream_response(),
        Response::json(200, "{}"),
        accepted_upstream_response(),
    ]);
    let directory = tempfile::tempdir().expect("a scratch project directory");
    copy_example_project(directory.path());
    author_nondefault_pack(directory.path());

    let served = Arc::new(Served::start_with_project(&upstream.url(""), directory.path()).await);
    let token = served.token("records.write");
    let request = accepted_record("2026-03-01T12:00:00.000");

    let safe_failure = post(&served, &token, "nondefault-retry", &request);
    assert_eq!(
        safe_failure.status,
        502,
        "{}",
        String::from_utf8_lossy(&safe_failure.body)
    );
    let safe_problem: Value =
        serde_json::from_slice(&safe_failure.body).expect("safe failure is a bounded problem");
    assert_eq!(safe_problem["code"], "source.upstream-error");
    assert_eq!(safe_problem["status"], 502);
    assert_eq!(
        upstream.request_count(),
        1,
        "the safe preflight failure occurs before the non-safe POST"
    );
    assert_eq!(upstream.requests()[0].method, "GET");

    let first = post(&served, &token, "nondefault-retry", &request);
    assert_eq!(
        first.status,
        201,
        "{}",
        String::from_utf8_lossy(&first.body)
    );
    assert_eq!(
        upstream.request_count(),
        3,
        "the released safe reservation permits one successful retry"
    );

    let replay = post(&served, &token, "nondefault-retry", &request);
    assert_eq!(replay.status, first.status);
    assert_eq!(replay.request_id, first.request_id);
    assert_eq!(replay.body, first.body, "the facade body replays exactly");
    assert_eq!(
        upstream.request_count(),
        3,
        "the completed duplicate makes no source request"
    );

    let changed = post(
        &served,
        &token,
        "nondefault-retry",
        &accepted_record("2026-03-02T12:00:00.000"),
    );
    assert_eq!(
        changed.status,
        422,
        "{}",
        String::from_utf8_lossy(&changed.body)
    );
    let mismatch: Value =
        serde_json::from_slice(&changed.body).expect("changed request refusal is JSON");
    assert_eq!(mismatch["code"], "source.facade");
    assert_eq!(mismatch["status"], 422);
    assert_eq!(
        upstream.request_count(),
        3,
        "a changed request cannot reach the source"
    );

    upstream.delay_answers(Duration::from_millis(700));
    let concurrent = {
        let served = Arc::clone(&served);
        let token = token.clone();
        let request = request.clone();
        tokio::task::spawn_blocking(move || {
            post(&served, &token, "nondefault-concurrent", &request)
        })
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while upstream.request_count() == 3 {
        assert!(
            Instant::now() < deadline,
            "the first concurrent request never reached its safe preflight"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let duplicate = post(&served, &token, "nondefault-concurrent", &request);
    let concurrent = concurrent.await.expect("first concurrent caller completes");

    assert_eq!(
        duplicate.status,
        409,
        "{}",
        String::from_utf8_lossy(&duplicate.body)
    );
    let conflict: Value =
        serde_json::from_slice(&duplicate.body).expect("concurrent refusal is JSON");
    assert_eq!(conflict["code"], "source.facade");
    assert_eq!(conflict["status"], 409);
    assert_eq!(
        concurrent.status,
        201,
        "{}",
        String::from_utf8_lossy(&concurrent.body)
    );
    assert_eq!(
        upstream.request_count(),
        5,
        "the host reservation admits only the first request's GET and POST"
    );
    assert_eq!(
        upstream
            .requests()
            .iter()
            .map(|request| request.method.as_str())
            .collect::<Vec<_>>(),
        ["GET", "GET", "POST", "GET", "POST"]
    );
}
