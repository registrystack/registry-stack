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

use serde_json::{json, Value};
use served_harness::upstream::{Response, UpstreamDouble};
use served_harness::{capture, Served};

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

fn raw_post(served: &Served, token: &str, key: &str, body: &Value) -> (u16, Vec<u8>) {
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
    (status, response[head_end + 4..].to_vec())
}

fn accepted_upstream_response() -> Response {
    let (status, body) = capture("import-accepted");
    Response::json(status, &body)
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
              response_status, response_content_type, response_body) \
             SELECT decode(md5('scope-' || value::text) || md5('scope-x-' || value::text), 'hex'), \
                    decode(md5('request-' || value::text) || md5('request-x-' || value::text), 'hex'), \
                    'completed', now() - interval '2 seconds', now() - interval '2 seconds', \
                    now() - interval '1 second', 200, convert_to('application/json', 'UTF8'), \
                    convert_to('{}', 'UTF8') \
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
    assert_eq!(
        upstream.request_count(),
        1,
        "duplicates never reach the source"
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
