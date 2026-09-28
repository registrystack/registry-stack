// SPDX-License-Identifier: Apache-2.0

//! Database-backed tests of `messagingctl messages` and `messagingctl
//! retention`: the built binary lists, shows, retries, settles, and cancels
//! messages the runtime accepted, erases what retention says is due,
//! previews each action unless `--apply` is given, and never prints a
//! contact, template data, or a principal.
//!
//! Every test runs in its own schema inside the database named by
//! `MESSAGING_TEST_DATABASE_URL`. A test binary that passes because its
//! database URL is absent is not database verification, so the variable is
//! required: without it every test in this file fails on the spot.

#[path = "../../registry-messaging/tests/support/mod.rs"]
mod support;

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use registry_messaging::dispatch::{dispatcher, MessageSender, Transports};
use registry_platform_dispatch::postgres::DispatchOutcome;
use serde_json::Value;
use support::{assert_absent, email_submission, sms_submission, Harness};
use uuid::Uuid;

/// Run the built `messagingctl` against the harness's runtime
/// configuration. The secret references it names resolve from the
/// environment this process set, which the child inherits.
fn messagingctl(runtime: &Path, arguments: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_messagingctl"))
        .args(arguments)
        .arg("--runtime-config")
        .arg(runtime)
        .output()
        .expect("run messagingctl");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    for (stream, text) in [("stdout", &stdout), ("stderr", &stderr)] {
        assert_absent(
            &format!("messagingctl {stream}"),
            &Value::String(text.clone()),
        );
    }
    (output.status.code().expect("an exit code"), stdout, stderr)
}

fn json(runtime: &Path, arguments: &[&str]) -> (i32, Value) {
    let mut all = vec!["--format", "json"];
    all.extend_from_slice(arguments);
    let (code, stdout, stderr) = messagingctl(runtime, &all);
    let report =
        serde_json::from_str(&stdout).unwrap_or_else(|error| panic!("{error}: {stdout} {stderr}"));
    (code, report)
}

/// The harness's messages in three states: one failed because its
/// provider has no transport, one unknown because its worker lost the
/// lease mid-attempt, and one still queued.
async fn three_messages(harness: &Harness) -> (Uuid, Uuid, Uuid) {
    let transports = Arc::new(Transports::new());
    let dispatcher = dispatcher(
        harness.store.clone(),
        &harness.isolated.schema,
        Arc::clone(&transports),
    )
    .unwrap();
    let sender = MessageSender::new(dispatcher.clone(), transports, Arc::clone(&harness.metrics));

    let failed = harness.accepted(&sms_submission()).await;
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::DeadLettered
    );

    let unknown = harness.accepted(&email_submission()).await;
    let leased = dispatcher.claim().await.unwrap().leased().unwrap();
    assert_eq!(leased.key.id(), unknown);
    drop(leased);
    let changed = harness
        .execute(
            "UPDATE messaging_dispatch_jobs \
                SET attempt_started_at = now() - interval '2 minutes', \
                    lease_expires_at = now() - interval '1 minute' \
              WHERE message_id = $1 AND state = 'leased'",
            &[&unknown],
        )
        .await;
    assert_eq!(changed, 1);
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::Idle
    );

    let queued = harness.accepted(&email_submission()).await;
    assert_eq!(harness.state(failed).await, "dead_lettered");
    assert_eq!(harness.state(unknown).await, "unknown");
    assert_eq!(harness.state(queued).await, "pending");
    (failed, unknown, queued)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_and_show_report_messages_with_the_contact_masked() {
    let harness = Harness::start().await;
    let (failed, unknown, queued) = three_messages(&harness).await;
    let runtime = harness.runtime_path();

    let (code, report) = json(&runtime, &["messages", "list"]);
    assert_eq!(code, 0, "{report}");
    let listed: Vec<(&str, &str)> = report["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| (row["id"].as_str().unwrap(), row["status"].as_str().unwrap()))
        .collect();
    assert_eq!(
        listed,
        vec![
            (queued.to_string().as_str(), "queued"),
            (unknown.to_string().as_str(), "unknown"),
            (failed.to_string().as_str(), "failed"),
        ]
    );

    let (code, report) = json(&runtime, &["messages", "list", "--status", "failed"]);
    assert_eq!(code, 0);
    assert_eq!(report["messages"].as_array().unwrap().len(), 1);
    assert_eq!(report["messages"][0]["id"], failed.to_string());
    assert_eq!(report["messages"][0]["channel"], "sms");
    assert_eq!(report["messages"][0]["dispatch"], "failed");

    let (code, report) = json(&runtime, &["messages", "list", "--limit", "1"]);
    assert_eq!(code, 0);
    assert_eq!(report["messages"][0]["id"], queued.to_string());
    assert_eq!(report["messages"].as_array().unwrap().len(), 1);

    let (code, report) = json(&runtime, &["messages", "show", &unknown.to_string()]);
    assert_eq!(code, 0, "{report}");
    assert_eq!(report["message"]["id"], unknown.to_string());
    assert_eq!(report["message"]["status"], "unknown");
    assert_eq!(report["message"]["dispatch"], "unknown");
    // The email went through an SMTP provider, which records no receipts.
    assert_eq!(report["message"]["report"], "unavailable");
    assert_eq!(
        report["message"]["to"],
        serde_json::json!({"email": "redacted"})
    );
    assert_eq!(report["message"]["attempts"][0]["outcome"], "interrupted");
    assert_eq!(report["accessProfile"], "case-notices");
    assert_eq!(report["generation"], 1);

    let (code, stdout, _) = messagingctl(&runtime, &["messages", "list"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains(&format!("{failed} failed (dispatch failed) sms")),
        "{stdout}"
    );
    let (code, report) = json(&runtime, &["messages", "show", &failed.to_string()]);
    assert_eq!(code, 0, "{report}");
    // The SMS provider declares receipts; none arrived.
    assert_eq!(report["message"]["report"], "none");
    let (code, stdout, _) = messagingctl(&runtime, &["messages", "show", &failed.to_string()]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("status: failed (dispatch failed, report none)"),
        "{stdout}"
    );
    assert!(stdout.contains("to: phone (redacted)"), "{stdout}");
    assert!(stdout.contains("attempt 1.1: permanent"), "{stdout}");

    let absent = Uuid::new_v4().to_string();
    let (code, report) = json(&runtime, &["messages", "show", &absent]);
    assert_eq!(code, 1);
    assert_eq!(report["diagnostics"][0]["code"], "message.not-found");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actions_preview_by_default_and_change_the_message_only_with_apply() {
    let harness = Harness::start().await;
    let (failed, unknown, queued) = three_messages(&harness).await;
    let runtime = harness.runtime_path();
    let failed_id = failed.to_string();
    let unknown_id = unknown.to_string();
    let queued_id = queued.to_string();

    let (code, report) = json(&runtime, &["messages", "retry", &failed_id]);
    assert_eq!(code, 0, "{report}");
    assert_eq!(report["eligible"], true);
    assert_eq!(report["applied"], false);
    assert_eq!(report["nextStatus"], "queued");
    assert_eq!(harness.state(failed).await, "dead_lettered");
    let (_, stdout, _) = messagingctl(&runtime, &["messages", "retry", &failed_id]);
    assert!(stdout.contains("run again with --apply"), "{stdout}");

    let (code, report) = json(&runtime, &["messages", "retry", &failed_id, "--apply"]);
    assert_eq!(code, 0, "{report}");
    assert_eq!(report["applied"], true);
    assert_eq!(report["nextGeneration"], 2);
    assert_eq!(harness.state(failed).await, "pending");

    let (code, report) = json(&runtime, &["messages", "retry", &queued_id, "--apply"]);
    assert_eq!(code, 1);
    assert_eq!(report["diagnostics"][0]["code"], "message.not-eligible");
    let refusal = report["diagnostics"][0]["message"].as_str().unwrap();
    assert!(
        refusal.contains("has dispatch state queued")
            && refusal.contains("whose dispatch state is failed"),
        "{refusal}"
    );
    assert_eq!(harness.state(queued).await, "pending");

    let (code, report) = json(
        &runtime,
        &["messages", "settle", &unknown_id, "--outcome", "sent"],
    );
    assert_eq!(code, 0, "{report}");
    assert_eq!(report["outcome"], "sent");
    assert_eq!(report["nextStatus"], "submitted");
    assert_eq!(harness.state(unknown).await, "unknown");
    let (code, report) = json(
        &runtime,
        &[
            "messages",
            "settle",
            &unknown_id,
            "--outcome",
            "sent",
            "--apply",
        ],
    );
    assert_eq!(code, 0, "{report}");
    assert_eq!(report["applied"], true);
    assert_eq!(harness.state(unknown).await, "delivered");

    let (code, report) = json(&runtime, &["messages", "cancel", &queued_id]);
    assert_eq!(code, 0, "{report}");
    assert_eq!(harness.state(queued).await, "pending");
    let (code, stdout, _) = messagingctl(&runtime, &["messages", "cancel", &queued_id, "--apply"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("applied"), "{stdout}");
    assert_eq!(harness.state(queued).await, "cancelled");

    let absent = Uuid::new_v4().to_string();
    let (code, report) = json(&runtime, &["messages", "cancel", &absent, "--apply"]);
    assert_eq!(code, 1);
    assert_eq!(report["diagnostics"][0]["code"], "message.not-found");

    // Each applied action wrote one operator-tool record into the outbox,
    // which the running runtime publishes to the journal.
    harness.publish().await;
    let operator_records: Vec<Value> = harness
        .journal()
        .into_iter()
        .map(|entry| entry["record"].clone())
        .filter(|record| record["actor"]["kind"] == "operator-tool")
        .collect();
    let events: Vec<(&str, &str)> = operator_records
        .iter()
        .map(|record| {
            (
                record["event"].as_str().unwrap(),
                record["messageId"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        events,
        vec![
            ("messaging.dispatch.transition", failed_id.as_str()),
            ("messaging.message.settled", unknown_id.as_str()),
            ("messaging.dispatch.transition", queued_id.as_str()),
        ]
    );
    for record in &operator_records {
        assert_absent("an operator-tool record", record);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retention_previews_by_default_and_erases_only_expired_terminal_messages_with_apply() {
    let harness = Harness::start().await;
    let (failed, unknown, queued) = three_messages(&harness).await;
    for id in [failed, unknown, queued] {
        harness
            .execute(
                "UPDATE messaging_dispatch_jobs SET updated_at = now() - interval '8 days' \
                  WHERE message_id = $1",
                &[&id],
            )
            .await;
    }
    let runtime = harness.runtime_path();
    // A minute back, so a database clock behind this host's still accepts it.
    let before = (chrono::Utc::now() - chrono::Duration::minutes(1)).to_rfc3339();
    let erased = "SELECT count(*) FROM messaging_message_payloads WHERE erased_at IS NOT NULL";

    let (code, preview) = json(
        &runtime,
        &["retention", "erase-expired", "--before", &before],
    );
    assert_eq!(code, 0, "{preview}");
    assert_eq!(preview["applied"], false);
    assert_eq!(preview["payloads"], 1);
    assert_eq!(preview["records"], 0);
    assert_eq!(preview["retention"]["payloadDays"], 7);
    assert_eq!(harness.count(erased).await, 0);

    let (code, stdout, _) = messagingctl(
        &runtime,
        &["retention", "erase-expired", "--before", &before, "--apply"],
    );
    assert_eq!(code, 0, "{stdout}");
    assert!(stdout.contains("payloads erased: 1"), "{stdout}");
    assert_eq!(harness.count(erased).await, 1);
    let kept: bool = harness
        .isolated
        .admin
        .query_one(
            "SELECT bool_and(erased_at IS NULL) FROM messaging_message_payloads \
              WHERE message_id = ANY($1)",
            &[&vec![unknown, queued]],
        )
        .await
        .unwrap()
        .get(0);
    assert!(kept, "an unknown or queued payload was erased");
    let records: Vec<Value> = harness
        .outbox()
        .await
        .into_iter()
        .filter(|record| record["event"] == "messaging.retention.erased")
        .collect();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["actor"]["kind"], "operator-tool");
    assert_eq!(records[0]["payloads"], 1);

    let future = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    let (code, refused) = json(
        &runtime,
        &["retention", "erase-expired", "--before", &future, "--apply"],
    );
    assert_eq!(code, 1, "{refused}");
    assert_eq!(refused["diagnostics"][0]["code"], "retention.future-cutoff");
}
