// SPDX-License-Identifier: Apache-2.0
//! `breg.read-in-force/v1` through the PostgreSQL worker path: two records in
//! force hold the run for a person, and an operator retry after the register
//! is corrected finishes it.
#![cfg(feature = "postgres-test")]

mod support;

use registry_coordinator::{
    adapters::HttpAdapters,
    definition::Definition,
    protected_state::StateKeys,
    protocol::AdapterSet,
    store::{Store, StoreSecurity},
    worker::Worker,
};
use registry_platform_audit::{AuditProfile, AuditWriter};
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::Arc};
use support::{config, issuer, TRACE};
use tokio_postgres::NoTls;
use uuid::Uuid;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

const WORKFLOW: &str = r#"
apiVersion: id.registrystack.org/formats/coordinator/project/v1alpha1
kind: CoordinatorProject
project: {id: read-in-force-hold, version: v1}
contracts:
  assignment: {type: breg, source: contract.json}
operations:
  lookup:
    uses: breg.read-in-force/v1
    connection: applications
    record: {contract: assignment}
workflow:
  input: {type: object, additionalProperties: false}
  deadlineSeconds: 3600
  start: call
  steps:
    call:
      type: call
      operation: lookup
      input:
        type: fields
        fields:
          entity: {type: literal, value: assignments}
          subject: {type: literal, value: {district: Colombo}}
          date: {type: literal, value: "2026-06-05"}
      next: found
      onDeclaredRefusal: absent
    found: {type: finish, outcome: found}
    absent: {type: finish, outcome: absent}
  outcomes:
    found: {type: 'null'}
    absent: {type: 'null'}
"#;

fn record_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:breg:record-type:assignment", "type": "object",
        "additionalProperties": false,
        "required": ["district", "officer", "startsOn"],
        "properties": {
            "district": {"type": "string"}, "officer": {"type": "string"},
            "startsOn": {"type": "string", "format": "date"},
            "endsOn": {"type": "string", "format": "date"}
        },
        "x-registry-temporal": {
            "startProperty": "startsOn", "endProperty": "endsOn",
            "valueKind": "date", "semantics": "start-inclusive-end-exclusive",
            "route": "assignments", "nonOverlapScopeProperties": [["district"]]
        }
    })
}

fn row(identifier: &str) -> Value {
    json!({
        "recordIdentifier": identifier,
        "revisionIdentifier": "1",
        "domainData": {"district": "Colombo", "officer": "synthetic-officer", "startsOn": "2026-01-01"}
    })
}

fn collection(items: Vec<Value>) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("traceparent", TRACE)
        .insert_header(
            "link",
            "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </v1/schemas/assignment>; rel=\"describedby\"",
        )
        .set_body_json(json!({
            "items": items,
            "pageInfo": {"nextCursor": null},
            "meta": {
                "registryIdentifier": "registry",
                "datasetIdentifier": "dataset",
                "recordTypeIdentifier": "assignment"
            }
        }))
}

#[tokio::test]
async fn two_records_in_force_hold_the_run_until_an_operator_retries() {
    let url = std::env::var("COORDINATOR_TEST_DATABASE_URL").expect(
        "COORDINATOR_TEST_DATABASE_URL must name a disposable synthetic PostgreSQL 17+ database",
    );
    let namespace = format!("coordinator_{}", Uuid::new_v4().simple());
    let bootstrap = Store::connect(&url, &namespace).await.expect("connect");
    bootstrap.migrate().await.expect("migrate");
    let store = Arc::new(
        Store::open(
            &url,
            &namespace,
            StoreSecurity {
                database_id: namespace.clone(),
                keys: StateKeys::new(1, BTreeMap::from([(1, [0x11; 32])]), [0x22; 32])
                    .expect("test keys"),
                audit: AuditWriter::from_line_sink(Box::new(std::io::sink())),
                audit_profile: AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(
                    vec![0x33; 32],
                ))
                .expect("audit profile"),
            },
            None,
        )
        .await
        .expect("open store"),
    );
    let project = tempfile::tempdir().expect("project");
    std::fs::write(project.path().join("workflow.yaml"), WORKFLOW).expect("workflow");
    std::fs::write(
        project.path().join("contract.json"),
        record_schema().to_string(),
    )
    .expect("contract");
    let definition = Definition::load(project.path()).expect("valid read-in-force workflow");

    let issuer = issuer().await;
    let server = MockServer::start().await;
    // The register first has two overlapping assignments, then is corrected.
    Mock::given(method("GET"))
        .and(path("/v1/records/assignments:as-of"))
        .respond_with(collection(vec![
            row("00000000-0000-4000-8000-0000000000a1"),
            row("00000000-0000-4000-8000-0000000000a2"),
        ]))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/records/assignments:as-of"))
        .respond_with(collection(vec![row(
            "00000000-0000-4000-8000-0000000000a1",
        )]))
        .with_priority(2)
        .mount(&server)
        .await;
    let root = tempfile::tempdir().unwrap();
    let adapters = Arc::new(
        HttpAdapters::new(&config(root.path(), &issuer, &server.uri(), &server.uri())).unwrap(),
    );
    let digest = adapters.binding_digest_for(&definition.workflow);
    let run = store
        .admit(
            &definition,
            json!({}),
            "synthetic-producer",
            &Uuid::new_v4().to_string(),
            &digest,
        )
        .await
        .expect("admit");
    let worker = Worker::new(store.clone(), adapters.clone());

    assert!(worker.tick().await.expect("ambiguous read"));
    // Drain anything else due; a hold must not advance or finish the run.
    while worker.tick().await.expect("tick") {}
    let held = store.status(run).await.expect("held status");
    assert_eq!(held.state, "attention", "{held:?}");
    assert_eq!(held.failure_code.as_deref(), Some("in-force-ambiguous"));
    assert_eq!(held.outcome, None);
    assert_eq!(held.step, "call");
    assert!(!held.uncertain);

    let (client, connection) = tokio_postgres::connect(&url, NoTls).await.expect("client");
    tokio::spawn(async move { connection.await.expect("connection") });
    let job: String = client
        .query_one(
            &format!("SELECT state FROM {namespace}.jobs WHERE run_id=$1 AND step='call'"),
            &[&run],
        )
        .await
        .expect("job row")
        .get(0);
    println!("held job state: {job}");

    let inspection = store.inspect(run, &digest).await.expect("inspect");
    println!(
        "recovery: {}",
        serde_json::to_string(&inspection.recovery).unwrap()
    );
    // Inspection names the two records and the date, so the operator can
    // correct the register without tracing the run's input elsewhere.
    let step = inspection
        .steps
        .iter()
        .find(|step| step.step == "call")
        .expect("the held step");
    assert_eq!(
        serde_json::to_value(step).unwrap()["holdDetail"],
        json!({
            "date": "2026-06-05",
            "recordIdentifiers": [
                "00000000-0000-4000-8000-0000000000a1",
                "00000000-0000-4000-8000-0000000000a2"
            ]
        })
    );
    // At rest the detail is sealed like other product-derived state.
    let stored: Option<String> = client
        .query_one(
            &format!(
                "SELECT hold_detail::text FROM {namespace}.jobs WHERE run_id=$1 AND step='call'"
            ),
            &[&run],
        )
        .await
        .expect("hold detail column")
        .get(0);
    let stored = stored.expect("the hold detail is stored");
    assert!(
        !stored.contains("0000000000a1") && !stored.contains("2026-06-05"),
        "the hold detail is sealed at rest"
    );
    assert!(
        inspection.recovery.retry_allowed,
        "an operator can retry a held read"
    );
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "the hold does not retry on its own"
    );

    store
        .retry_same(run, &digest)
        .await
        .expect("operator retry");
    while worker.tick().await.expect("tick after retry") {}
    let done = store.status(run).await.expect("finished status");
    assert_eq!(done.state, "finished", "{done:?}");
    assert_eq!(done.outcome.as_deref(), Some("found"));
    let cleared: Option<Value> = client
        .query_one(
            &format!("SELECT hold_detail FROM {namespace}.jobs WHERE run_id=$1 AND step='call'"),
            &[&run],
        )
        .await
        .expect("hold detail column")
        .get(0);
    assert_eq!(cleared, None, "a read that answered clears the hold detail");
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
    issuer.stop().await;
}
