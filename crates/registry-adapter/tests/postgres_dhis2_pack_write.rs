// SPDX-License-Identifier: Apache-2.0

//! Served-loopback proof for the maintained DHIS2 write route's pack-owned
//! summary decisions and update identity mapping. Needs
//! `ADAPTER_TEST_DATABASE_URL`; absence is a failure, never a skip.
#![cfg(feature = "postgres-test")]

#[allow(dead_code)]
#[path = "support/served/mod.rs"]
mod served_harness;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use serde_json::{json, Value};
use served_harness::upstream::{Response, UpstreamDouble};
use served_harness::Served;

fn record(id: &str) -> Value {
    json!({
        "data": {
            "recordIdentifier": id,
            "domainData": {
                "tracked_entity_type": "cQWYtUfH6Vx",
                "org_unit": "qfg4XUDJtgS",
                "created_at": "2026-03-01T12:00:00.000",
                "updated_at": "2026-03-02T12:00:00.000"
            }
        }
    })
}

fn raw_write(
    served: &Served,
    token: &str,
    method: &str,
    path: &str,
    key: &str,
    body: &Value,
) -> (u16, Vec<u8>) {
    let body = body.to_string();
    let mut stream = TcpStream::connect(("127.0.0.1", served.port)).expect("connect to facade");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("set facade timeout");
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nIdempotency-Key: {key}\r\nContent-Length: {}\r\n\r\n{body}",
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
    (status, response[head_end + 4..].to_vec())
}

fn import_summary(status: &str, created: u64, updated: u64, ignored: u64) -> String {
    json!({
        "status": status,
        "validationReport": {
            "errorReports": [],
            "warningReports": [{"message": "UPSTREAM-SENSITIVE-CANARY"}]
        },
        "stats": {
            "created": created,
            "updated": updated,
            "deleted": 0,
            "ignored": ignored,
            "total": created + updated + ignored
        }
    })
    .to_string()
}

#[tokio::test]
async fn a_synchronous_create_uses_the_supplied_uid_and_replays_without_a_second_send() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![Response::json(200, &import_summary("OK", 0, 1, 0))]);
    let served = Served::start(&upstream.url("")).await;
    let token = served.token("records.write");
    let request = record("wk4JlTuVO9o");

    let first = raw_write(
        &served,
        &token,
        "POST",
        "/v1/records/person",
        "create-person-pack-1",
        &request,
    );
    let replay = raw_write(
        &served,
        &token,
        "POST",
        "/v1/records/person",
        "create-person-pack-1",
        &request,
    );

    assert_eq!(first.0, 201, "{}", String::from_utf8_lossy(&first.1));
    assert_eq!(replay, first, "the terminal update replays exact bytes");
    let requests = upstream.requests();
    assert_eq!(requests.len(), 1, "a replay makes no second source effect");
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].target, "/api/tracker?async=false");
    let bundle: Value = serde_json::from_slice(&requests[0].body).expect("tracker bundle JSON");
    assert_eq!(bundle["trackedEntities"][0]["trackedEntity"], "wk4JlTuVO9o");
    assert_eq!(bundle["trackedEntities"][0]["attributes"], json!([]));
}

#[tokio::test]
async fn a_partial_summary_is_a_count_free_conflict_and_never_leaks_the_summary() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![Response::json(
        200,
        &import_summary("WARNING", 1, 0, 1),
    )]);
    let served = Served::start(&upstream.url("")).await;
    let token = served.token("records.write");

    let (status, body) = raw_write(
        &served,
        &token,
        "POST",
        "/v1/records/person",
        "partial-person-1",
        &record("wk4JlTuVO9o"),
    );
    let problem: Value = serde_json::from_slice(&body).expect("facade problem JSON");
    assert_eq!(status, 409, "{}", String::from_utf8_lossy(&body));
    assert_eq!(problem["code"], "source.write-partial");
    assert!(
        !String::from_utf8_lossy(&body).contains("UPSTREAM-SENSITIVE-CANARY"),
        "the raw import summary must not cross the facade"
    );
    assert_eq!(upstream.request_count(), 1);
}

#[tokio::test]
async fn an_unfinished_summary_is_explicitly_refused_until_d16_is_implemented() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![Response::json(
        200,
        &json!({
            "status": "PENDING",
            "message": "UPSTREAM-SENSITIVE-CANARY"
        })
        .to_string(),
    )]);
    let served = Served::start(&upstream.url("")).await;
    let token = served.token("records.write");

    let (status, body) = raw_write(
        &served,
        &token,
        "POST",
        "/v1/records/person",
        "unfinished-person-1",
        &record("wk4JlTuVO9o"),
    );
    let problem: Value = serde_json::from_slice(&body).expect("facade problem JSON");
    assert_eq!(status, 422, "{}", String::from_utf8_lossy(&body));
    assert_eq!(problem["code"], "source.validation");
    assert!(!String::from_utf8_lossy(&body).contains("UPSTREAM-SENSITIVE-CANARY"));
    assert_eq!(upstream.request_count(), 1);
}
