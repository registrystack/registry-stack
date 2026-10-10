#![allow(
    clippy::disallowed_methods,
    reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
)]
// SPDX-License-Identifier: Apache-2.0

//! Database-backed tests of the built `messagingctl`: plan, apply, and status
//! share the activation contract; message commands list, show, retry, settle,
//! and cancel accepted messages; retention erases what is due; and no report
//! prints a contact, template data, or a principal.
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plan_apply_and_status_are_one_operator_journey() {
    let harness = Harness::start().await;
    let runtime = harness.runtime_path();
    let digest = harness.package.digest().to_owned();
    assert_eq!(
        harness
            .execute("DELETE FROM messaging_activations", &[])
            .await,
        1
    );

    let (code, plan) = json(&runtime, &["plan"]);
    assert_eq!(code, 0, "{plan}");
    assert_eq!(plan["command"], "plan");
    assert_eq!(plan["packageDigest"], digest);
    assert_eq!(plan["activeDigest"], Value::Null);
    assert_eq!(plan["change"], "activate");
    assert_eq!(plan["databaseId"], "not-recorded");

    let (code, status) = json(&runtime, &["status"]);
    assert_eq!(code, 0, "{status}");
    assert_eq!(status["active"], Value::Null);
    assert_eq!(status["history"].as_array().unwrap().len(), 0);

    let (code, applied) = json(
        &runtime,
        &[
            "apply",
            "--operator-reference",
            "change-42",
            "--backup",
            "snapshot-1",
        ],
    );
    assert_eq!(code, 0, "{applied}");
    assert_eq!(applied["command"], "apply");
    assert_eq!(applied["packageDigest"], digest);
    assert_eq!(applied["change"], "activate");
    assert_eq!(applied["applied"], true);
    assert_eq!(applied["restartRequired"], true);
    assert_eq!(
        applied["activation"]["backupReferences"],
        serde_json::json!(["snapshot-1"])
    );

    let (code, status) = json(&runtime, &["status"]);
    assert_eq!(code, 0, "{status}");
    assert_eq!(status["active"]["packageDigest"], digest);
    assert_eq!(status["history"].as_array().unwrap().len(), 1);

    let (code, plan) = json(&runtime, &["plan"]);
    assert_eq!(code, 0, "{plan}");
    assert_eq!(plan["activeDigest"], digest);
    assert_eq!(plan["change"], "none");

    let (code, unchanged) = json(&runtime, &["apply"]);
    assert_eq!(code, 0, "{unchanged}");
    assert_eq!(unchanged["activeDigest"], digest);
    assert_eq!(unchanged["change"], "none");
    assert_eq!(unchanged["applied"], false);

    let (code, refused) = json(&runtime, &["apply", "--apply"]);
    assert_eq!(code, 2, "{refused}");
    assert_eq!(refused["diagnostics"][0]["code"], "usage.invalid");
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
        Arc::clone(&harness.audit),
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
    assert_eq!(harness.state(failed).await, "dead-lettered");
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
    assert_eq!(report["command"], "messages list");
    assert_eq!(report["status"], "complete");
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
    assert_eq!(report["command"], "messages show");
    assert_eq!(report["status"], "complete");
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
    assert_eq!(report["command"], "messages retry");
    assert_eq!(report["status"], "complete");
    assert_eq!(report["messageStatus"], "failed");
    assert_eq!(report["eligible"], true);
    assert_eq!(report["applied"], false);
    assert_eq!(report["nextStatus"], "queued");
    assert_eq!(harness.state(failed).await, "dead-lettered");
    let (_, stdout, _) = messagingctl(&runtime, &["messages", "retry", &failed_id]);
    assert!(stdout.contains("run again with --apply"), "{stdout}");

    let (code, report) = json(&runtime, &["messages", "retry", &failed_id, "--apply"]);
    assert_eq!(code, 0, "{report}");
    assert_eq!(report["applied"], true);
    assert_eq!(report["nextGeneration"], 2);
    assert_eq!(harness.state(failed).await, "pending");

    let (code, report) = json(&runtime, &["messages", "retry", &queued_id, "--apply"]);
    assert_eq!(code, 1);
    assert_eq!(report["status"], "domain-refusal");
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
    assert_eq!(report["command"], "messages settle");
    assert_eq!(report["messageStatus"], "unknown");
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

    // Each applied action wrote one operator-tool record directly to the
    // configured audit destination.
    harness.publish().await;
    let operator_records: Vec<Value> = harness
        .journal()
        .into_iter()
        .filter(|entry| entry["phase"] == "response")
        .map(|entry| entry["record"].clone())
        .filter(|record| record["actor"]["kind"] == "operator-tool")
        .filter(|record| {
            matches!(
                record["event"].as_str(),
                Some("messaging.dispatch.transition" | "messaging.message.settled")
            )
        })
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

/// A queued message waiting to retry after an attempt that may have
/// reached its provider cannot be cancelled: the preview refuses it the way
/// the cancel would, with the HTTP API's `message.dispatch-started`, so the
/// preview never promises what `--apply` refuses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_refuses_a_queued_message_whose_earlier_attempt_may_have_been_sent() {
    let harness = Harness::start_with(Value::Null, |package| {
        let path = package.join("messaging.yaml");
        let source = std::fs::read_to_string(&path).unwrap();
        let mut manifest: Value = serde_norway::from_str(&source).unwrap();
        manifest["senderProfiles"][1]["onUncertain"] = Value::String("retry".to_owned());
        std::fs::write(path, serde_norway::to_string(&manifest).unwrap()).unwrap();
    })
    .await;
    let transports = Arc::new(Transports::new());
    let dispatcher = dispatcher(
        harness.store.clone(),
        &harness.isolated.schema,
        Arc::clone(&transports),
        Arc::clone(&harness.audit),
    )
    .unwrap();
    let interrupted = harness.accepted(&sms_submission()).await;
    let leased = dispatcher.claim().await.unwrap().leased().unwrap();
    assert_eq!(leased.key.id(), interrupted);
    drop(leased);
    let changed = harness
        .execute(
            "UPDATE messaging_dispatch_jobs \
                SET attempt_started_at = now() - interval '2 minutes', \
                    lease_expires_at = now() - interval '1 minute' \
              WHERE message_id = $1 AND state = 'leased'",
            &[&interrupted],
        )
        .await;
    assert_eq!(changed, 1);
    assert!(dispatcher.claim().await.unwrap().leased().is_none());
    assert_eq!(harness.state(interrupted).await, "pending");
    let runtime = harness.runtime_path();
    let id = interrupted.to_string();

    for arguments in [
        vec!["messages", "cancel", id.as_str()],
        vec!["messages", "cancel", id.as_str(), "--apply"],
    ] {
        let (code, report) = json(&runtime, &arguments);
        assert_eq!(code, 1, "{report}");
        assert_eq!(
            report["diagnostics"][0]["code"], "message.dispatch-started",
            "{report}"
        );
        let refusal = report["diagnostics"][0]["message"].as_str().unwrap();
        assert!(refusal.contains("can no longer be cancelled"), "{refusal}");
        assert_eq!(harness.state(interrupted).await, "pending");
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
    assert_eq!(preview["command"], "retention erase-expired");
    assert_eq!(preview["status"], "complete");
    assert_eq!(preview["applied"], false);
    assert_eq!(preview["payloads"], 1);
    assert_eq!(preview["records"], 0);
    assert_eq!(preview["retention"]["payloadRetentionDays"], 7);
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
        .journal()
        .into_iter()
        .map(|entry| entry["record"].clone())
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
