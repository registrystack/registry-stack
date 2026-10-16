// SPDX-License-Identifier: Apache-2.0
//! Control persisted time at both sides of a leased local timer wake.

use super::*;
use crate::definition::Definition;
use chrono::{Duration, Utc};
use registry_platform_dispatch::postgres::Claim;
use serde_json::json;
use tokio_postgres::NoTls;
use uuid::Uuid;

const WORKFLOW: &str = r#"
apiVersion: id.registrystack.org/formats/coordinator/project/v1alpha1
kind: CoordinatorProject
project:
  id: leased-timer
  version: v1
functions:
  timer:
    runtime: rhai
    source: functions.rhai
    entrypoint: timer
    inputs: {input: {type: object}}
    output: {type: string, format: date-time}
  choice:
    runtime: rhai
    source: functions.rhai
    entrypoint: choice
    inputs: {input: {type: object}}
    output: {type: string, enum: [done]}
workflow:
  input: {type: object}
  deadlineSeconds: 3600
  start: wait
  steps:
    wait:
      type: wait-until
      waitUntil: {type: function, function: timer, inputs: {input: {type: input}}}
      next: choose
    choose:
      type: choose
      choose: {type: function, function: choice, inputs: {input: {type: input}}}
      cases: {done: done}
    done: {type: finish, outcome: done}
  outcomes:
    done: {type: 'null'}
"#;

struct NoCalls;
#[async_trait]
impl AdapterSet for NoCalls {
    fn binding_digest(&self) -> &str {
        "timer-binding"
    }
    async fn call(&self, _: &CallRequest) -> CallOutcome {
        panic!("a local timer graph must never call a product")
    }
}

#[tokio::test]
async fn leased_wait_deadline_is_checked_atomically_before_advancing() {
    let url = std::env::var("COORDINATOR_TEST_DATABASE_URL")
        .expect("COORDINATOR_TEST_DATABASE_URL must name a disposable PostgreSQL database");
    let (client, connection) = tokio_postgres::connect(&url, NoTls)
        .await
        .expect("disposable connection");
    let connection_task = tokio::spawn(connection);
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("workflow.yaml"), WORKFLOW).unwrap();
    std::fs::write(
        project.path().join("functions.rhai"),
        "fn timer(args) { args.input.at }\nfn choice(args) { \"done\" }\n",
    )
    .unwrap();
    let definition = Definition::load(project.path()).expect("local timer graph");
    let mut violations = vec![];
    for expiry in ["before-send", "before-finish", "unexpired"] {
        let namespace = format!("coordinator_wait_{}", Uuid::new_v4().simple());
        let store = Arc::new(Store::connect(&url, &namespace).await.unwrap());
        store.migrate().await.unwrap();
        let run = store
            .admit(
                &definition,
                json!({"at": (Utc::now() - Duration::seconds(1)).to_rfc3339()}),
                "synthetic-timer-producer",
                "timer-start",
                "timer-binding",
            )
            .await
            .unwrap();
        let worker = Worker::new(store.clone(), Arc::new(NoCalls));
        let dispatcher = store.dispatcher().unwrap();
        let Claim::Leased(job) = dispatcher.claim().await.unwrap() else {
            panic!("due wait must be leased before its deadline")
        };
        assert_eq!(job.key.part(), "wait");
        // The owned fixture moves only the persisted workflow deadline, after
        // claim or send. It leaves the live lease/fence valid and uses no sleep.
        let expire_sql = format!(
            "UPDATE {namespace}.runs SET deadline_at=clock_timestamp()-interval '1 second' WHERE run_id=$1"
        );
        if expiry == "before-send" {
            client.execute(&expire_sql, &[&run]).await.unwrap();
        }
        let sent = worker.send(&job).await.unwrap();
        if expiry == "before-finish" {
            client.execute(&expire_sql, &[&run]).await.unwrap();
        }
        dispatcher.finish(&job, sent).await.unwrap();
        let status = store.status(run).await.unwrap();
        let row = client
            .query_one(
                &format!("SELECT (SELECT state FROM {namespace}.jobs WHERE run_id=$1 AND step='wait'), (SELECT count(*) FROM {namespace}.jobs WHERE run_id=$1 AND step<>'wait'), completed_at IS NOT NULL FROM {namespace}.runs WHERE run_id=$1"),
                &[&run],
            )
            .await
            .unwrap();
        let wake_state: String = row.get(0);
        let successor_count: i64 = row.get(1);
        let completed: bool = row.get(2);
        // Delivery checkpoints the local wake, not a successful workflow.
        let correct = if expiry == "unexpired" {
            status.state == "running" && status.step == "choose" && successor_count == 1
        } else {
            status.state == "expired"
                && status.step == "wait"
                && status.failure_code.as_deref() == Some("deadline-reached")
                && status.outcome.is_none()
                && status.output.is_none()
                && !status.uncertain
                && status.next_due_at.is_none()
                && completed
                && successor_count == 0
        };
        if wake_state != "delivered" || !correct {
            violations.push(format!(
                "{expiry}: state={}, step={}, outcome={:?}, wake={wake_state}, successors={successor_count}",
                status.state, status.step, status.outcome
            ));
        }
        // Exercise any mistakenly queued pure successors to demonstrate the
        // original false success, while the fixed expired cases stay idle.
        for _ in 0..2 {
            worker.tick().await.unwrap();
        }
        let final_status = store.status(run).await.unwrap();
        let expected = if expiry == "unexpired" {
            "finished"
        } else {
            "expired"
        };
        if final_status.state != expected {
            violations.push(format!("{expiry}: final state={}", final_status.state));
        }
        client
            .batch_execute(&format!("DROP SCHEMA {namespace} CASCADE"))
            .await
            .unwrap();
    }
    drop(client);
    connection_task.await.unwrap().unwrap();
    assert!(violations.is_empty(), "late wait advanced: {violations:?}");
}

#[tokio::test]
async fn leased_finish_preserves_outcome_under_restore_review_and_after_retention() {
    let url = std::env::var("COORDINATOR_TEST_DATABASE_URL")
        .expect("COORDINATOR_TEST_DATABASE_URL must name a disposable PostgreSQL database");
    let (client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    let connection_task = tokio::spawn(connection);
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("workflow.yaml"),
        r#"
apiVersion: id.registrystack.org/formats/coordinator/project/v1alpha1
kind: CoordinatorProject
project: {id: leased-finish, version: v1}
functions:
  keep:
    runtime: rhai
    source: functions.rhai
    entrypoint: keep
    inputs: {input: {type: object}}
    output: {type: object}
workflow:
  input: {type: object}
  deadlineSeconds: 3600
  start: done
  steps:
    done:
      type: finish
      outcome: done
      output: {type: function, function: keep, inputs: {input: {type: input}}}
  outcomes:
    done: {type: object}
"#,
    )
    .unwrap();
    std::fs::write(
        project.path().join("functions.rhai"),
        "fn keep(args) { args.input }\n",
    )
    .unwrap();
    let definition = Definition::load(project.path()).expect("pure terminal output");
    let namespace = format!("coordinator_finish_{}", Uuid::new_v4().simple());
    let store = Arc::new(Store::connect(&url, &namespace).await.unwrap());
    store.migrate().await.unwrap();
    let operator = crate::store::Actor {
        issuer: "https://issuer.example.invalid".into(),
        subject: "synthetic-operator".into(),
        client_id: "synthetic-client".into(),
        operator: true,
    };
    let output = json!({"receipt":"synthetic-finish-canary"});
    let run = store
        .admit_owned(
            &definition,
            output.clone(),
            &operator,
            "finish-start",
            "timer-binding",
        )
        .await
        .unwrap();
    let worker = Worker::new(store.clone(), Arc::new(NoCalls));
    let dispatcher = store.dispatcher().unwrap();
    let Claim::Leased(job) = dispatcher.claim().await.unwrap() else {
        panic!("pure finish must be leased before restore hold")
    };
    assert_eq!(job.key.part(), "done");
    store
        .set_restore_hold(&operator, "synthetic-restored-deployment")
        .await
        .unwrap();
    let pending = store.status_owned(run, &operator).await.unwrap();
    assert_eq!(pending.state, "attention");
    assert!(pending.restore_review_required);
    assert!(pending.outcome.is_none() && pending.output.is_none());

    // An already leased pure Finish performs no product I/O. Its real result
    // commits while restore review still controls the public progress state.
    let sent = worker.send(&job).await.unwrap();
    dispatcher.finish(&job, sent).await.unwrap();
    let held = store.status_owned(run, &operator).await.unwrap();
    assert_eq!(held.state, "attention");
    assert!(held.restore_review_required);
    assert_eq!(held.outcome.as_deref(), Some("done"));
    assert_eq!(held.output.as_ref(), Some(&output));
    let wire = serde_json::to_value(&held).unwrap();
    assert_eq!(wire["state"], "attention");
    assert_eq!(wire["restoreReviewRequired"], true);
    assert_eq!(wire["outcome"], "done");
    assert_eq!(wire["output"], output);
    println!("held finish status: {wire}");
    assert_eq!(
        store
            .release_restore_hold(&operator, "fence-without-history-review")
            .await
            .unwrap_err()
            .code,
        "restore-unresolved"
    );
    let cutoff = client
        .query_one("SELECT clock_timestamp()", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        store.retain_terminal(cutoff, 100, &operator).await.unwrap(),
        0
    );
    store
        .complete_execution_recovery(&operator, "synthetic-complete-history-fenced", true, true)
        .await
        .unwrap();
    store
        .release_restore_hold(&operator, "synthetic-complete-history-fenced")
        .await
        .unwrap();
    let released = store.status_owned(run, &operator).await.unwrap();
    assert_eq!(released.state, "finished");
    assert!(!released.restore_review_required);
    assert_eq!(released.outcome.as_deref(), Some("done"));
    assert_eq!(released.output.as_ref(), Some(&output));
    assert_eq!(
        store.retain_terminal(cutoff, 100, &operator).await.unwrap(),
        1
    );
    let retained = store.status_owned(run, &operator).await.unwrap();
    assert_eq!(retained.state, "finished");
    assert_eq!(retained.outcome.as_deref(), Some("done"));
    assert!(retained.output.is_none());
    println!(
        "retained finish status: {}",
        serde_json::to_value(retained).unwrap()
    );
    client
        .batch_execute(&format!("DROP SCHEMA {namespace} CASCADE"))
        .await
        .unwrap();
    drop(dispatcher);
    drop(worker);
    drop(store);
    drop(client);
    connection_task.await.unwrap().unwrap();
}
