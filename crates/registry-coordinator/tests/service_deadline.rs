// SPDX-License-Identifier: Apache-2.0

use registry_coordinator::definition::Definition;
use serde_json::{json, Value};
use std::fs;

fn project() -> Value {
    json!({
        "apiVersion": "id.registrystack.org/formats/coordinator/project/v1alpha1",
        "kind": "CoordinatorProject",
        "project": {"id": "service-deadline", "version": "1"},
        "workflow": {
            "input": {
                "type": "object",
                "properties": {"at": {"type": "string", "format": "date-time"}},
                "required": ["at"],
                "additionalProperties": false
            },
            "deadlineSeconds": 3600,
            "serviceDeadlineSeconds": 60,
            "onDeadline": "escalate",
            "start": "wait",
            "steps": {
                "wait": {"type": "wait-until", "waitUntil": {"type": "input", "path": "/at"}, "next": "done"},
                "done": {"type": "finish", "outcome": "done"},
                "escalate": {"type": "finish", "outcome": "late"}
            },
            "outcomes": {"done": {"type": "null"}, "late": {"type": "null"}}
        }
    })
}

fn write(root: &std::path::Path, project: &Value) {
    fs::write(root.join("workflow.yaml"), project.to_string()).unwrap();
}

#[test]
fn service_deadline_is_checked_explained_and_pinned() {
    let root = tempfile::tempdir().unwrap();
    let mut value = project();
    write(root.path(), &value);
    let definition = Definition::load(root.path()).expect("check accepts a separate deadline");
    let report = definition.explain().unwrap();
    assert_eq!(report["serviceDeadlineSeconds"], 60);
    assert_eq!(report["onDeadline"], "escalate");
    let restored = Definition::from_snapshot(&definition.snapshot().unwrap()).unwrap();
    assert_eq!(restored.digest, definition.digest);
    assert_eq!(restored.explain().unwrap()["onDeadline"], "escalate");
    let scenario_path = root.path().join("scenarios.yaml");
    fs::write(
        &scenario_path,
        json!({
            "apiVersion": registry_coordinator::scenarios::API_VERSION,
            "kind": registry_coordinator::scenarios::KIND,
            "cases": [{
                "id": "late",
                "admittedAt": "2026-11-10T00:00:00Z",
                "input": {"at": "2026-11-10T00:10:00Z"},
                "replies": {},
                "expect": {
                    "path": ["wait", "escalate"],
                    "state": "completed",
                    "outcome": {"type": "named", "value": "late"}
                }
            }]
        })
        .to_string(),
    )
    .unwrap();
    let scenarios = registry_coordinator::scenarios::load(&scenario_path).unwrap();
    let result = registry_coordinator::scenarios::run(&definition, &scenarios.cases[0]).unwrap();
    assert_eq!(result.path, ["wait", "escalate"]);
    assert_eq!(result.outcome.as_deref(), Some("late"));
    assert_eq!(result.elapsed_seconds, 60);

    for target in ["missing", "wait", "done"] {
        value["workflow"]["onDeadline"] = json!(target);
        write(root.path(), &value);
        let error = Definition::load(root.path())
            .err()
            .expect("invalid deadline edge");
        assert!(format!("{error:?}").contains("onDeadline"), "{error:?}");
    }
}

#[cfg(feature = "postgres-test")]
#[tokio::test]
async fn a_wait_crosses_the_service_deadline_once_across_restart() {
    use async_trait::async_trait;
    use chrono::{Duration, Utc};
    use registry_coordinator::{
        protocol::{AdapterSet, CallOutcome, CallRequest},
        store::Store,
        worker::Worker,
    };
    use std::sync::Arc;
    use uuid::Uuid;

    struct Local;
    #[async_trait]
    impl AdapterSet for Local {
        fn binding_digest(&self) -> &str {
            "local"
        }
        async fn call(&self, _: &CallRequest) -> CallOutcome {
            panic!("the test workflow has no external operations")
        }
    }

    let url = std::env::var("COORDINATOR_TEST_DATABASE_URL")
        .expect("use a disposable local PostgreSQL database");
    let namespace = format!("coordinator_{}", Uuid::new_v4().simple());
    let store = Arc::new(Store::connect(&url, &namespace).await.unwrap());
    store.migrate().await.unwrap();
    let root = tempfile::tempdir().unwrap();
    write(root.path(), &project());
    let definition = Definition::load(root.path()).unwrap();
    let admit = |at: chrono::DateTime<Utc>| json!({"at": at.to_rfc3339()});
    let early = store
        .admit(
            &definition,
            admit(Utc::now() - Duration::minutes(1)),
            "p",
            "early",
            "local",
        )
        .await
        .unwrap();
    let worker = Worker::new(store.clone(), Arc::new(Local));
    assert!(worker.tick().await.unwrap());
    assert!(worker.tick().await.unwrap());
    assert_eq!(
        store.status(early).await.unwrap().outcome.as_deref(),
        Some("done")
    );

    let late = store
        .admit(
            &definition,
            admit(Utc::now() + Duration::hours(1)),
            "p",
            "late",
            "local",
        )
        .await
        .unwrap();
    let status = store.status(late).await.unwrap();
    assert_eq!(
        status.next_due_at,
        Some(status.admitted_at + Duration::seconds(60))
    );
    assert!(!worker.tick().await.unwrap());
    drop(worker);

    let (db, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    let connection = tokio::spawn(connection);
    db.execute(
        &format!(
            "UPDATE {namespace}.runs SET service_deadline_at=clock_timestamp() WHERE run_id=$1"
        ),
        &[&late],
    )
    .await
    .unwrap();
    db.execute(
        &format!("UPDATE {namespace}.jobs SET next_attempt_at=clock_timestamp() WHERE run_id=$1 AND state='pending'"),
        &[&late],
    ).await.unwrap();
    let reopened = Arc::new(Store::connect(&url, &namespace).await.unwrap());
    let worker = Worker::new(reopened.clone(), Arc::new(Local));
    assert!(worker.tick().await.unwrap());
    assert_eq!(reopened.status(late).await.unwrap().step, "escalate");
    assert!(worker.tick().await.unwrap());
    assert_eq!(
        reopened.status(late).await.unwrap().outcome.as_deref(),
        Some("late")
    );
    assert!(!worker.tick().await.unwrap());
    assert_eq!(
        reopened.status(early).await.unwrap().outcome.as_deref(),
        Some("done")
    );
    drop(db);
    connection.await.unwrap().unwrap();
}
