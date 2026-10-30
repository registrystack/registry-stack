// SPDX-License-Identifier: Apache-2.0
//! A compare choose step runs through the PostgreSQL worker: it routes on
//! typed values, and a missing or wrongly typed value fails the run with
//! `choice-invalid`, never `unmatched`.
#![cfg(feature = "postgres-test")]
use async_trait::async_trait;
use registry_coordinator::{
    definition::Definition,
    protocol::{AdapterSet, CallOutcome, CallRequest},
    store::Store,
    worker::Worker,
};
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;

const CANARY: &str = "private-canary-value";
const WORKFLOW: &str = r#"apiVersion: id.registrystack.org/formats/coordinator/project/v1alpha1
kind: CoordinatorProject
project: {id: compare-worker, version: '1'}
workflow:
  input:
    type: object
    additionalProperties: false
    properties:
      hectares: {}
  deadlineSeconds: 86400
  start: size
  steps:
    size:
      type: choose
      choose:
        type: compare
        all:
          - {value: {type: input, path: /hectares}, greater: 2}
      cases: {matched: large, unmatched: small}
    large: {type: finish, outcome: large}
    small: {type: finish, outcome: small}
  outcomes:
    large: {type: 'null'}
    small: {type: 'null'}
"#;

struct NoCalls;
#[async_trait]
impl AdapterSet for NoCalls {
    fn binding_digest(&self) -> &str {
        "binding-a"
    }
    async fn call(&self, _request: &CallRequest) -> CallOutcome {
        panic!("a compare workflow makes no call")
    }
}

async fn run(input: Value) -> registry_coordinator::store::RunStatus {
    let url = std::env::var("COORDINATOR_TEST_DATABASE_URL").expect("test database");
    let namespace = format!("coordinator_{}", Uuid::new_v4().simple());
    let store = Arc::new(Store::connect(&url, &namespace).await.expect("connect"));
    store.migrate().await.expect("migrate");
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("workflow.yaml"), WORKFLOW).unwrap();
    let definition = Definition::load(project.path()).expect("valid compare workflow");
    let run = store
        .admit(&definition, input, "p", "k", "binding-a")
        .await
        .expect("admit");
    let worker = Worker::new(store.clone(), Arc::new(NoCalls));
    while worker.tick().await.expect("tick") {}
    store.status(run).await.unwrap()
}

#[tokio::test]
async fn a_compare_routes_through_the_worker() {
    let status = run(json!({"hectares": 5})).await;
    assert_eq!(status.state, "finished", "{status:?}");
    assert_eq!(status.outcome.as_deref(), Some("large"));
    let status = run(json!({"hectares": 1})).await;
    assert_eq!(status.outcome.as_deref(), Some("small"), "{status:?}");
}

#[tokio::test]
async fn a_wrongly_typed_or_missing_value_fails_the_run_with_choice_invalid() {
    for input in [
        json!({"hectares": CANARY}),
        json!({}),
        json!({"hectares": null}),
    ] {
        let status = run(input.clone()).await;
        assert_eq!(status.state, "failed", "{input} {status:?}");
        assert_eq!(
            status.failure_code.as_deref(),
            Some("choice-invalid"),
            "{input}"
        );
        assert!(status.outcome.is_none());
        assert!(!format!("{status:?}").contains(CANARY));
    }
}
