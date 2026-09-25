// SPDX-License-Identifier: Apache-2.0

//! Database-backed retention tests: a message's payload is erased
//! `retention.payloadDays` after the message reached a terminal state, its
//! record is deleted `retention.recordDays` after, a submission receipt
//! expires at the end of `retention.submissionReceiptDays`, and nothing of
//! a message still sending or in an unknown outcome is ever erased.
//!
//! A message's dispatch state and its age are set directly in the schema,
//! so each case names exactly the state and the time it proves.
//!
//! Every test runs in its own schema inside the database named by
//! `MESSAGING_TEST_DATABASE_URL`. A test binary that passes because its
//! database URL is absent is not database verification, so the variable is
//! required: without it every test in this file fails on the spot.

mod support;

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::http::StatusCode;
use registry_messaging::messages::MESSAGE_ACCEPTED_EVENT;
use registry_messaging::retention::{
    erase_expired, RetentionActor, RetentionError, RetentionSweep, RETENTION_ERASED_EVENT,
};
use serde_json::Value;
use support::{
    assert_absent, assert_logs_clean, email_submission, sender_token, Harness, ISSUER,
    SENDER_PRINCIPAL,
};
use tokio::sync::watch;
use uuid::Uuid;

const DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// Put one message's dispatch job in `state`, last changed `age_days` ago,
/// in the shape the job table's check constraint requires of that state.
async fn settle_as(harness: &Harness, message_id: Uuid, state: &str, age_days: i32) {
    let shape = match state {
        "pending" => "next_attempt_at = now()",
        "leased" => {
            "attempt = 1, next_attempt_at = NULL, attempt_started_at = now(), \
             lease_expires_at = now() + interval '1 minute', lease_token = gen_random_uuid()"
        }
        "unknown" => "attempt = 1, next_attempt_at = NULL",
        "delivered" => "attempt = 1, next_attempt_at = NULL, delivered_at = now()",
        "dead_lettered" => "attempt = 1, next_attempt_at = NULL, dead_lettered_at = now()",
        "expired" => "next_attempt_at = NULL, expired_at = now()",
        "cancelled" => "next_attempt_at = NULL",
        other => panic!("no shape for {other}"),
    };
    let changed = harness
        .execute(
            &format!(
                "UPDATE messaging_dispatch_jobs \
                    SET state = $2, {shape}, updated_at = now() - make_interval(days => $3) \
                  WHERE message_id = $1"
            ),
            &[&message_id, &state, &age_days],
        )
        .await;
    assert_eq!(changed, 1);
}

async fn payload_erased(harness: &Harness, message_id: Uuid) -> bool {
    let row = harness
        .isolated
        .admin
        .query_one(
            "SELECT erased_at IS NOT NULL, recipient IS NULL AND subject IS NULL \
                    AND text_body IS NULL AND html_body IS NULL \
               FROM messaging_message_payloads WHERE message_id = $1",
            &[&message_id],
        )
        .await
        .unwrap();
    let (stamped, nulled): (bool, bool) = (row.get(0), row.get(1));
    assert_eq!(stamped, nulled, "an erased payload is stamped and emptied");
    stamped
}

/// How many rows name `message_id` in each table that holds part of a
/// message: the message, its payload, its job, its attempts, its receipts,
/// and its idempotency record.
async fn rows_of(harness: &Harness, message_id: Uuid) -> [i64; 6] {
    let mut counts = [0; 6];
    for (count, table) in counts.iter_mut().zip([
        "messaging_messages",
        "messaging_message_payloads",
        "messaging_dispatch_jobs",
        "messaging_attempts",
        "messaging_receipts",
        "messaging_idempotency",
    ]) {
        *count = harness
            .isolated
            .admin
            .query_one(
                &format!("SELECT count(*) FROM {table} WHERE message_id = $1"),
                &[&message_id],
            )
            .await
            .unwrap()
            .get(0);
    }
    counts
}

/// Give a message one finished attempt with a provider reference and one
/// delivery receipt.
async fn attempted_and_receipted(harness: &Harness, message_id: Uuid) {
    harness
        .execute(
            "INSERT INTO messaging_attempts \
                 (message_id, generation, attempt, started_at, outcome, finished_at, \
                  provider_reference) \
             VALUES ($1, 1, 1, now(), 'accepted', now(), 'provider-reference-1')",
            &[&message_id],
        )
        .await;
    harness
        .execute(
            "INSERT INTO messaging_receipts (message_id, sequence, received_at, report, applied) \
             VALUES ($1, 1, now(), 'delivered', true)",
            &[&message_id],
        )
        .await;
}

async fn retention_records(harness: &Harness) -> Vec<Value> {
    harness
        .outbox()
        .await
        .into_iter()
        .filter(|record| record["event"] == RETENTION_ERASED_EVENT)
        .collect()
}

#[tokio::test]
async fn a_payload_is_erased_payload_days_after_a_terminal_state_and_never_while_sending_or_unknown(
) {
    let harness = Harness::start().await;
    let mut due = Vec::new();
    for state in ["delivered", "dead_lettered", "expired", "cancelled"] {
        let id = harness.accepted(&email_submission()).await;
        settle_as(&harness, id, state, 8).await;
        due.push(id);
    }
    let mut kept = Vec::new();
    for state in ["pending", "leased", "unknown"] {
        let id = harness.accepted(&email_submission()).await;
        settle_as(&harness, id, state, 30).await;
        kept.push(id);
    }
    // Accepted a month ago but terminal only six days ago: the payload
    // period runs from the terminal state, not from acceptance.
    let recent = harness.accepted(&email_submission()).await;
    harness
        .execute(
            "UPDATE messaging_messages SET accepted_at = now() - interval '30 days' \
              WHERE message_id = $1",
            &[&recent],
        )
        .await;
    settle_as(&harness, recent, "delivered", 6).await;
    kept.push(recent);

    let report = erase_expired(
        &harness.store,
        harness.config.retention,
        None,
        true,
        RetentionActor::Runtime,
    )
    .await
    .unwrap();

    assert!(report.applied);
    assert_eq!(
        (report.payloads, report.records, report.submission_receipts),
        (4, 0, 0)
    );
    for id in due {
        assert!(payload_erased(&harness, id).await, "{id} was not erased");
    }
    for id in &kept {
        assert!(!payload_erased(&harness, *id).await, "{id} was erased");
    }
    // A second run finds nothing left to erase.
    let again = erase_expired(
        &harness.store,
        harness.config.retention,
        None,
        true,
        RetentionActor::Runtime,
    )
    .await
    .unwrap();
    assert_eq!((again.payloads, again.records), (0, 0));
    assert_eq!(harness.state(kept[1]).await, "leased");
}

#[tokio::test]
async fn a_requeue_committed_while_retention_waits_keeps_the_payload() {
    let harness = Harness::start().await;
    let id = harness.accepted(&email_submission()).await;
    settle_as(&harness, id, "dead_lettered", 8).await;
    // An operator requeue holds the job's row when retention reaches it.
    harness
        .isolated
        .admin
        .batch_execute(&format!(
            "BEGIN; \
             UPDATE messaging_dispatch_jobs \
                SET state = 'pending', generation = generation + 1, next_attempt_at = now(), \
                    dead_lettered_at = NULL, updated_at = now() \
              WHERE message_id = '{id}'"
        ))
        .await
        .unwrap();
    let store = harness.store.clone();
    let retention = harness.config.retention;
    let run = tokio::spawn(async move {
        erase_expired(&store, retention, None, true, RetentionActor::Runtime).await
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!run.is_finished(), "retention waits for the requeue's lock");
    harness
        .isolated
        .admin
        .batch_execute("COMMIT")
        .await
        .unwrap();
    let report = run.await.unwrap().unwrap();
    assert_eq!(report.payloads, 0);
    assert!(!payload_erased(&harness, id).await);
    assert_eq!(harness.state(id).await, "pending");
}

#[tokio::test]
async fn a_record_is_deleted_record_days_after_a_terminal_state_with_everything_it_holds() {
    let harness = Harness::start().await;
    let key = Uuid::new_v4().to_string();
    let (status, receipt) = harness
        .submit(&sender_token(), &key, &email_submission())
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{receipt}");
    let old = Uuid::parse_str(receipt["id"].as_str().unwrap()).unwrap();
    settle_as(&harness, old, "delivered", 91).await;
    attempted_and_receipted(&harness, old).await;

    let young = harness.accepted(&email_submission()).await;
    settle_as(&harness, young, "delivered", 89).await;
    attempted_and_receipted(&harness, young).await;

    let unknown = harness.accepted(&email_submission()).await;
    settle_as(&harness, unknown, "unknown", 400).await;

    let report = erase_expired(
        &harness.store,
        harness.config.retention,
        None,
        true,
        RetentionActor::OperatorTool,
    )
    .await
    .unwrap();
    // Both delivered payloads were past their seven days; only the older
    // record was past its ninety.
    assert_eq!((report.payloads, report.records), (2, 1));
    assert_eq!(rows_of(&harness, old).await, [0; 6]);
    assert_eq!(rows_of(&harness, young).await, [1, 1, 1, 1, 1, 1]);
    assert_eq!(rows_of(&harness, unknown).await, [1, 1, 1, 0, 0, 1]);
    assert!(!payload_erased(&harness, unknown).await);

    // With its record gone, the key stays spent: the row keeps the key
    // under the caller's keyed pseudonym and nothing else, and a retry
    // under it, with the same body or another, is refused as expired and
    // sends nothing.
    let retained = harness
        .isolated
        .admin
        .query_one(
            "SELECT to_jsonb(key)::text, message_id IS NULL AND request_hash IS NULL \
                    AND status_code IS NULL AND receipt IS NULL AND erased_at IS NOT NULL \
               FROM messaging_idempotency AS key WHERE idempotency_key = $1",
            &[&key],
        )
        .await
        .unwrap();
    assert!(
        retained.get::<_, bool>(1),
        "the retained key holds no record"
    );
    let retained: String = retained.get(0);
    for value in [ISSUER, SENDER_PRINCIPAL, receipt["id"].as_str().unwrap()] {
        assert!(!retained.contains(value), "the retained key holds {value}");
    }
    let messages = harness
        .count("SELECT count(*) FROM messaging_messages")
        .await;
    let accepted = accepted_records(&harness).await;
    let mut other = email_submission();
    other["correlationId"] = serde_json::json!("another-body");
    for body in [email_submission(), other] {
        let (status, again) = harness.submit(&sender_token(), &key, &body).await;
        assert_eq!(status, StatusCode::GONE, "{again}");
        assert_eq!(again["code"], "idempotency.expired");
    }
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_messages")
            .await,
        messages
    );
    assert_eq!(accepted_records(&harness).await, accepted);
}

async fn accepted_records(harness: &Harness) -> usize {
    harness
        .outbox()
        .await
        .iter()
        .filter(|record| record["event"] == MESSAGE_ACCEPTED_EVENT)
        .count()
}

#[tokio::test]
async fn a_submission_receipt_expires_after_its_period_and_its_key_stays_spent() {
    let harness = Harness::start().await;
    let key = Uuid::new_v4().to_string();
    let (status, receipt) = harness
        .submit(&sender_token(), &key, &email_submission())
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{receipt}");
    let fresh_key = Uuid::new_v4().to_string();
    let (status, _) = harness
        .submit(&sender_token(), &fresh_key, &email_submission())
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    harness
        .execute(
            "UPDATE messaging_idempotency SET expires_at = now() - interval '1 minute' \
              WHERE idempotency_key = $1",
            &[&key],
        )
        .await;

    let report = erase_expired(
        &harness.store,
        harness.config.retention,
        None,
        true,
        RetentionActor::Runtime,
    )
    .await
    .unwrap();
    assert_eq!(report.submission_receipts, 1);
    let row = harness
        .isolated
        .admin
        .query_one(
            "SELECT status_code IS NULL AND receipt IS NULL AND erased_at IS NOT NULL \
               FROM messaging_idempotency WHERE idempotency_key = $1",
            &[&key],
        )
        .await
        .unwrap();
    assert!(row.get::<_, bool>(0));
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_idempotency WHERE erased_at IS NULL")
            .await,
        1
    );
    let (status, replay) = harness
        .submit(&sender_token(), &key, &email_submission())
        .await;
    assert_eq!(status, StatusCode::GONE, "{replay}");
    assert_eq!(replay["code"], "idempotency.expired");
}

#[tokio::test]
async fn a_preview_changes_nothing_and_a_cutoff_in_the_future_is_refused() {
    let harness = Harness::start().await;
    let id = harness.accepted(&email_submission()).await;
    settle_as(&harness, id, "delivered", 100).await;

    let preview = erase_expired(
        &harness.store,
        harness.config.retention,
        None,
        false,
        RetentionActor::OperatorTool,
    )
    .await
    .unwrap();
    assert!(!preview.applied);
    assert_eq!((preview.payloads, preview.records), (1, 1));
    assert_eq!(rows_of(&harness, id).await, [1, 1, 1, 0, 0, 1]);
    assert!(!payload_erased(&harness, id).await);

    let refused = erase_expired(
        &harness.store,
        harness.config.retention,
        Some(SystemTime::now() + Duration::from_secs(3600)),
        true,
        RetentionActor::OperatorTool,
    )
    .await
    .unwrap_err();
    assert!(matches!(refused, RetentionError::FutureCutoff), "{refused}");
    assert_eq!(rows_of(&harness, id).await, [1, 1, 1, 0, 0, 1]);

    // An earlier cutoff reaches only what had expired by then.
    let earlier = erase_expired(
        &harness.store,
        harness.config.retention,
        Some(SystemTime::now() - 20 * DAY),
        true,
        RetentionActor::OperatorTool,
    )
    .await
    .unwrap();
    assert_eq!((earlier.payloads, earlier.records), (1, 0));
    assert!(retention_records(&harness).await.len() == 1);
}

#[tokio::test]
async fn a_retention_run_is_journaled_with_its_counts_only() {
    let harness = Harness::start().await;
    // A runtime pass that erases nothing writes no record.
    erase_expired(
        &harness.store,
        harness.config.retention,
        None,
        true,
        RetentionActor::Runtime,
    )
    .await
    .unwrap();
    assert!(retention_records(&harness).await.is_empty());
    // An operator run is always journaled, even when it erases nothing.
    erase_expired(
        &harness.store,
        harness.config.retention,
        None,
        true,
        RetentionActor::OperatorTool,
    )
    .await
    .unwrap();

    let id = harness.accepted(&email_submission()).await;
    settle_as(&harness, id, "delivered", 8).await;
    erase_expired(
        &harness.store,
        harness.config.retention,
        None,
        true,
        RetentionActor::Runtime,
    )
    .await
    .unwrap();

    let records = retention_records(&harness).await;
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["actor"]["kind"], "operator-tool");
    assert_eq!(records[0]["payloads"], 0);
    assert_eq!(records[1]["actor"]["kind"], "runtime");
    assert_eq!(records[1]["payloads"], 1);
    let mut keys: Vec<&str> = records[1]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "actor",
            "before",
            "event",
            "eventId",
            "payloads",
            "records",
            "retention",
            "submissionReceipts"
        ]
    );
    assert_eq!(records[1]["retention"]["payloadDays"], 7);
    harness.publish().await;
    assert_absent("the retention journal", &Value::Array(harness.journal()));
    assert_logs_clean();
}

#[tokio::test]
async fn the_runtime_sweep_erases_on_its_interval() {
    let harness = Harness::start().await;
    let id = harness.accepted(&email_submission()).await;
    settle_as(&harness, id, "cancelled", 8).await;
    let sweep = RetentionSweep::new(
        harness.store.clone(),
        harness.config.retention,
        Arc::clone(&harness.metrics),
    );
    let (stop, stopped) = watch::channel(false);
    let running = tokio::spawn(sweep.run(Duration::from_millis(50), stopped));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !payload_erased(&harness, id).await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the sweep never erased the payload"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), running)
        .await
        .expect("the sweep stops when asked")
        .unwrap();
    // The first pass erased the payload; every later one found nothing.
    assert_eq!(
        harness
            .sample("messaging_retention_runs_total{outcome=\"erased\"}")
            .await,
        Some(1)
    );
    assert_eq!(
        harness
            .sample("messaging_retention_runs_total{outcome=\"failed\"}")
            .await,
        Some(0)
    );
}
