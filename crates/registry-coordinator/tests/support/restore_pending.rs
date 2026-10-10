// SPDX-License-Identifier: Apache-2.0
//! Real PostgreSQL recovery proofs sharing the durable Worker harness.
use super::*;

async fn pending_work(kind: &str, at: chrono::DateTime<Utc>) -> (Harness, Uuid, Arc<Fake>) {
    let mut h = invalid_following_wait(
        match kind {
            "finish" => "choose",
            "appointment" | "message" => "message",
            other => other,
        },
        "input.at",
    )
    .await;
    if matches!(kind, "finish" | "message" | "appointment") {
        let path = h.project.path().join("workflow.yaml");
        let mut document: Value = registry_coordinator::authoring::parse_project(
            &path,
            std::fs::read_to_string(&path).unwrap(),
        )
        .unwrap()
        .1
        .to_json_value();
        if kind == "finish" {
            document["start"] = json!("done");
            document["steps"] = json!({"done":{"type":"finish","outcome":"done"}});
        } else {
            document["start"] = json!("message");
            document["steps"].as_object_mut().unwrap().remove("read");
            document["steps"]["message"]["input"] =
                json!({"function":"pending_command","arguments":[{"type":"input"}]});
            if kind == "appointment" {
                document["connections"]["messages"] = json!("scheduling");
                document["steps"]["message"]["operation"] = json!("create-appointment");
            }
            let functions = h.project.path().join("functions.rhai");
            let source = std::fs::read_to_string(&functions).unwrap();
            std::fs::write(
                functions,
                format!("{source}\nfn pending_command(input) {{ #{{ synthetic: true }} }}"),
            )
            .unwrap();
        }
        std::fs::write(&path, serde_norway::to_string(&document).unwrap()).unwrap();
        h.definition = Definition::load(h.project.path()).unwrap();
    }
    let run = h
        .store
        .admit(
            &h.definition,
            input(at),
            "synthetic-producer",
            "start",
            "binding-a",
        )
        .await
        .unwrap();
    (h, run, Fake::new(vec![]))
}

#[tokio::test]
async fn restored_pre_command_pending_work_requires_explicit_retry_or_cancel() {
    for kind in ["read", "wait", "choose", "finish", "message", "appointment"] {
        for cancel in [false, true] {
            let (h, run, fake) = pending_work(kind, Utc::now() - Duration::seconds(1)).await;
            let worker = Worker::new(h.store.clone(), fake.clone());
            let original = restored_current_job(&h, run).await;
            assert_eq!(original["state"], "pending");
            assert_eq!(original["attempt"], 0);
            assert!(original["command"].is_null());
            let identity = restored_lease_identity(&h, run).await;
            let operator = actor("operator", true);
            h.store
                .set_restore_hold(&operator, "unleased-pending-restored")
                .await
                .unwrap();
            for (complete, fenced) in [(false, true), (true, false)] {
                assert_eq!(
                    h.store
                        .complete_execution_recovery(
                            &operator,
                            "incomplete-history",
                            complete,
                            fenced
                        )
                        .await
                        .unwrap_err()
                        .code,
                    "restore-review-required"
                );
                assert_eq!(restored_lease_identity(&h, run).await, identity);
                assert_eq!(restored_current_job(&h, run).await, original);
            }
            h.store
                .complete_execution_recovery(&operator, "complete-history-fenced", true, true)
                .await
                .unwrap();
            h.store
                .release_restore_hold(&operator, "complete-history-fenced")
                .await
                .unwrap();
            assert!(
                !worker.tick().await.unwrap(),
                "{kind}: attestation/release must not execute restored pre-command work"
            );
            assert!(fake.requests.lock().unwrap().is_empty());
            assert_eq!(restored_lease_identity(&h, run).await, identity);
            let held = restored_current_job(&h, run).await;
            assert_eq!(held["state"], "dead-lettered");
            assert_eq!(held["failure_code"], "restore-pre-command-held");
            let status = h.store.status(run).await.unwrap();
            assert_eq!(status.state, "failed");
            assert!(!status.restore_review_required);
            assert!(
                h.store
                    .inspect(run, "binding-a")
                    .await
                    .unwrap()
                    .recovery
                    .retry_allowed
            );
            if cancel {
                h.store
                    .cancel_owned(run, &operator, "withdraw-restored-step")
                    .await
                    .unwrap();
                assert!(!worker.tick().await.unwrap());
                assert_eq!(
                    h.store
                        .retain_terminal(Utc::now(), 100, &operator)
                        .await
                        .unwrap(),
                    1
                );
            } else {
                h.store
                    .retry_same_owned(run, "binding-a", &operator, "explicit-reviewed-retry")
                    .await
                    .unwrap();
                assert!(
                    fake.requests.lock().unwrap().is_empty(),
                    "retry itself never sends"
                );
                assert_eq!(restored_current_job(&h, run).await["state"], "pending");
                assert!(
                    worker.tick().await.unwrap(),
                    "{kind}: explicit retry reopens this original step"
                );
                assert_eq!(
                    fake.requests.lock().unwrap().len(),
                    usize::from(matches!(kind, "read" | "message" | "appointment"))
                );
                assert_eq!(
                    h.store.status(run).await.unwrap().deadline_at,
                    status.deadline_at
                );
            }
        }
    }
}

#[tokio::test]
async fn restored_future_pending_wait_keeps_its_original_schedule_through_recovery() {
    let due = Utc::now() + Duration::minutes(30);
    let (h, run, fake) = pending_work("wait", due).await;
    let operator = actor("operator", true);
    let original_due = h.store.status(run).await.unwrap().next_due_at;
    let identity = restored_lease_identity(&h, run).await;
    h.store
        .set_restore_hold(&operator, "future-wait-restored")
        .await
        .unwrap();
    h.store
        .complete_execution_recovery(&operator, "complete-history-fenced", true, true)
        .await
        .unwrap();
    h.store
        .release_restore_hold(&operator, "complete-history-fenced")
        .await
        .unwrap();
    assert_eq!(
        restored_current_job(&h, run).await["state"],
        "dead-lettered"
    );
    assert_eq!(restored_lease_identity(&h, run).await, identity);
    h.store
        .retry_same_owned(run, "binding-a", &operator, "explicit-reviewed-wait")
        .await
        .unwrap();
    let scheduled = h.store.status(run).await.unwrap();
    assert_eq!(scheduled.next_due_at, original_due);
    assert!(
        !Worker::new(h.store.clone(), fake.clone())
            .tick()
            .await
            .unwrap(),
        "retry must not skip the original future wait"
    );
    assert!(fake.requests.lock().unwrap().is_empty());
    assert_eq!(scheduled.step, "wait");
}

#[tokio::test]
async fn attested_recovery_preserves_prepared_pending_reads() {
    let h = invalid_following_wait("read", "input.at").await;
    let run = h.admit().await;
    let fake = Fake::new(vec![CallOutcome::Retryable {
        code: "transport-timeout".into(),
    }]);
    let worker = Worker::new(h.store.clone(), Arc::new(RetryableRead(fake.clone())));
    assert!(worker.tick().await.unwrap());
    h.sql("UPDATE {schema}.jobs SET next_attempt_at=clock_timestamp()-interval '1 second' WHERE state='pending'").await;
    let original = restored_current_job(&h, run).await;
    assert!(!original["command"].is_null());
    let identity = restored_lease_identity(&h, run).await;
    fake.requests.lock().unwrap().clear();
    let operator = actor("operator", true);
    h.store
        .set_restore_hold(&operator, "prepared-read-restored")
        .await
        .unwrap();
    h.store
        .complete_execution_recovery(&operator, "complete-history-fenced", true, true)
        .await
        .unwrap();
    h.store
        .release_restore_hold(&operator, "complete-history-fenced")
        .await
        .unwrap();
    assert_eq!(restored_current_job(&h, run).await, original);
    assert_eq!(restored_lease_identity(&h, run).await, identity);
    assert!(worker.tick().await.unwrap());
    assert_eq!(fake.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn wait_replay_relational_failure_rolls_back_the_entire_reset() {
    let (h, run, fake) = pending_work("wait", Utc::now() + Duration::minutes(30)).await;
    let operator = actor("operator", true);
    h.store
        .set_restore_hold(&operator, "future-wait-restored")
        .await
        .unwrap();
    h.store
        .complete_execution_recovery(&operator, "complete-history-fenced", true, true)
        .await
        .unwrap();
    h.store
        .release_restore_hold(&operator, "complete-history-fenced")
        .await
        .unwrap();
    let held = restored_current_job(&h, run).await;
    assert_eq!(held["state"], "dead-lettered");
    let identity = restored_lease_identity(&h, run).await;
    // The core's dead-letter -> Pending reset succeeds. Only the consumer's
    // subsequent scheduling write fails, proving both share one transaction.
    h.sql("CREATE FUNCTION {schema}.refuse_replay_schedule() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic replay schedule refusal'; END $$; CREATE TRIGGER refuse_replay_schedule BEFORE UPDATE OF next_attempt_at ON {schema}.jobs FOR EACH ROW WHEN (OLD.state='pending' AND NEW.state='pending' AND OLD.generation=NEW.generation) EXECUTE FUNCTION {schema}.refuse_replay_schedule()").await;
    assert!(h
        .store
        .retry_same_owned(run, "binding-a", &operator, "explicit-reviewed-wait")
        .await
        .is_err());
    assert_eq!(restored_current_job(&h, run).await, held);
    assert_eq!(restored_lease_identity(&h, run).await, identity);
    assert!(!Worker::new(h.store.clone(), fake.clone())
        .tick()
        .await
        .unwrap());
    h.sql("DROP TRIGGER refuse_replay_schedule ON {schema}.jobs; DROP FUNCTION {schema}.refuse_replay_schedule()").await;
    h.store
        .retry_same_owned(run, "binding-a", &operator, "explicit-reviewed-wait")
        .await
        .unwrap();
    assert!(!Worker::new(h.store.clone(), fake.clone())
        .tick()
        .await
        .unwrap());
    assert!(fake.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn restored_pre_command_calls_and_waits_keep_the_original_deadline() {
    for kind in ["read", "wait", "message", "appointment"] {
        let (h, run, fake) = pending_work(kind, Utc::now() - Duration::seconds(1)).await;
        h.sql("UPDATE {schema}.runs SET deadline_at=clock_timestamp()-interval '1 second'")
            .await;
        let identity = restored_lease_identity(&h, run).await;
        let operator = actor("operator", true);
        h.store
            .set_restore_hold(&operator, "past-deadline-restored")
            .await
            .unwrap();
        h.store
            .complete_execution_recovery(&operator, "complete-history-fenced", true, true)
            .await
            .unwrap();
        h.store
            .release_restore_hold(&operator, "complete-history-fenced")
            .await
            .unwrap();
        assert_eq!(
            restored_current_job(&h, run).await["state"],
            "dead-lettered"
        );
        assert_eq!(restored_lease_identity(&h, run).await, identity);
        assert!(h
            .store
            .retry_same_owned(run, "binding-a", &operator, "past-deadline-retry")
            .await
            .is_err());
        assert!(!Worker::new(h.store.clone(), fake.clone())
            .tick()
            .await
            .unwrap());
        h.store
            .cancel_owned(run, &operator, "past-original-deadline")
            .await
            .unwrap();
        assert_eq!(
            h.store
                .retain_terminal(Utc::now(), 100, &operator)
                .await
                .unwrap(),
            1
        );
        assert!(fake.requests.lock().unwrap().is_empty());
    }
}
