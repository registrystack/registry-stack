// SPDX-License-Identifier: Apache-2.0

//! Generated PostgreSQL-backed properties over the real served synchronous
//! write path. Absence of `ADAPTER_TEST_DATABASE_URL` is a failure, never a
//! skip.
#![cfg(feature = "postgres-test")]

#[allow(dead_code)]
#[path = "support/served/mod.rs"]
mod served_harness;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use proptest::prelude::*;
use proptest::test_runner::{FileFailurePersistence, RngSeed, TestRunner};
use serde_json::{json, Value};
use served_harness::upstream::{Response, UpstreamDouble};
use served_harness::{capture, Served};

const CASES: u32 = 24;
const RESPONSE_CAPACITY_PER_MODE: usize = 64;

#[derive(Clone, Copy, Debug)]
enum FaultMode {
    Success,
    PostSendFailure,
}

#[derive(Debug, Eq, PartialEq)]
struct FacadeResponse {
    status: u16,
    content_type: Vec<u8>,
    body: Vec<u8>,
}

fn raw_post(served: &Served, token: &str, key: &str, body: &Value) -> FacadeResponse {
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
    let content_type = head
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.trim().as_bytes().to_vec())
        .expect("facade content type");
    FacadeResponse {
        status,
        content_type,
        body: response[head_end + 4..].to_vec(),
    }
}

fn accepted_response() -> Response {
    let (status, body) = capture("import-accepted");
    Response::json(status, &body)
}

fn failed_response() -> Response {
    let (status, body) = capture("import-server-error");
    Response::json(status, &body)
}

fn generated_record(case_id: usize, entity: u32, org_unit: u32, revision: u16) -> Value {
    json!({
        "data": {
            "recordIdentifier": format!("P{case_id:04}{entity:06}"),
            "domainData": {
                "tracked_entity_type": format!("T{entity:010}"),
                "org_unit": format!("O{org_unit:010}"),
                "created_at": format!("2026-03-{:02}T12:00:00.000", revision % 28 + 1),
                "updated_at": format!("2026-04-{:02}T13:{:02}:00.000", revision % 28 + 1, revision % 60)
            }
        }
    })
}

#[tokio::test]
async fn generated_served_writes_replay_exactly_and_never_repeat_the_source_effect() {
    let success_upstream = UpstreamDouble::start();
    success_upstream.respond_with(vec![accepted_response(); RESPONSE_CAPACITY_PER_MODE]);
    let failed_upstream = UpstreamDouble::start();
    failed_upstream.respond_with(vec![failed_response(); RESPONSE_CAPACITY_PER_MODE]);

    let success_served = Served::start(&success_upstream.url("")).await;
    let failed_served = Served::start(&failed_upstream.url("")).await;
    let success_token = success_served.token("records.write");
    let failed_token = failed_served.token("records.write");

    let next_case = AtomicUsize::new(0);
    let success_cases = AtomicUsize::new(0);
    let failure_cases = AtomicUsize::new(0);
    let config = ProptestConfig {
        cases: CASES,
        rng_seed: RngSeed::Fixed(0x1de0_5015_7e11),
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            "crates/registry-adapter/proptest-regressions/postgres_generated_write.txt",
        ))),
        source_file: Some(file!()),
        ..ProptestConfig::default()
    };
    let mut runner = TestRunner::new(config);
    let model = (
        0_u32..1_000_000,
        0_u32..1_000_000,
        any::<u16>(),
        "[a-z0-9]{1,24}",
        any::<bool>(),
    );
    runner
        .run(&model, |(entity, org_unit, revision, key_suffix, fail)| {
            let case_id = next_case.fetch_add(1, Ordering::SeqCst);
            let mode = if fail {
                failure_cases.fetch_add(1, Ordering::SeqCst);
                FaultMode::PostSendFailure
            } else {
                success_cases.fetch_add(1, Ordering::SeqCst);
                FaultMode::Success
            };
            let (served, token, upstream, expected_status) = match mode {
                FaultMode::Success => (
                    &success_served,
                    success_token.as_str(),
                    &success_upstream,
                    201,
                ),
                FaultMode::PostSendFailure => {
                    (&failed_served, failed_token.as_str(), &failed_upstream, 502)
                }
            };
            let key = format!("generated-{case_id}-{key_suffix}");
            let request = generated_record(case_id, entity, org_unit, revision);
            let mut changed = request.clone();
            changed["data"]["domainData"]["updated_at"] =
                Value::String(format!("changed-{case_id}-{revision}"));
            let sends_before = upstream.request_count();

            let first = raw_post(served, token, &key, &request);
            let replay = raw_post(served, token, &key, &request);
            let mismatch = raw_post(served, token, &key, &changed);

            prop_assert_eq!(first.status, expected_status);
            prop_assert_eq!(&replay, &first);
            prop_assert_eq!(mismatch.status, 422);
            prop_assert_eq!(
                upstream.request_count(),
                sends_before + 1,
                "one generated case makes exactly one non-safe source attempt"
            );
            Ok(())
        })
        .expect("generated served-write property");

    assert!(success_cases.load(Ordering::SeqCst) > 0);
    assert!(failure_cases.load(Ordering::SeqCst) > 0);
    assert_eq!(
        success_upstream.request_count() + failed_upstream.request_count(),
        usize::try_from(CASES).expect("the generated case count fits usize")
    );
}
