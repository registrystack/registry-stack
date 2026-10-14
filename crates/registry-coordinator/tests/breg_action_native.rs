// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "postgres-test")]
#[path = "support/breg_service.rs"]
mod breg_service;
mod support;

use breg_service::{Breg, LostResponse};
use registry_breg_client::{
    BRegCreateRequest, BRegDirectWrite, BRegIdempotencyKey, BRegRecordFormat, BRegRecordOptions,
};
use registry_coordinator::{
    adapters::HttpAdapters,
    breg_action,
    breg_proposal::{self, ApplicationObservation, Transition},
    protocol::{AdapterSet, CallOutcome, CallRequest, Operation, ReconciliationOutcome},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

type DispatchedCommands = Vec<(CallRequest, Option<Vec<u8>>)>;

#[tokio::test]
#[ignore = "native BReg/Messaging prerequisites; run products/coordinator/scripts/test-breg-action.py"]
async fn native_automatic_proposal_application_gates_a_separately_authorized_notice() {
    use registry_coordinator::{
        definition::Definition,
        store::{Actor, Store},
        worker::Worker,
    };
    let issuer = support::issuer().await;
    let service = Breg::start(&issuer).await;
    let messaging = support::messaging::Messaging::start(&issuer).await;
    let client = service.client(&issuer);
    let metadata = client.registry_contract(Some("writer")).await.unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.item.create", "writer")
        .unwrap()
    else {
        panic!("Create grant")
    };
    let record = client
        .create_record(
            &create,
            &BRegCreateRequest::new(
                json!({"owner":"coordinator-reader","label":"Before"})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
            .unwrap(),
            &BRegIdempotencyKey::parse("native-workflow-proposal-seed").unwrap(),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap()
        .value
        .data
        .record_identifier;
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let mut runtime = support::config(root.path(), &issuer, &service.base_url, &messaging.base_url);
    breg_connection(&mut runtime).profile = "writer".into();
    runtime.minimum_observation_interval_seconds =
        registry_platform_yaml::BoundedU32::new(30).unwrap();
    let mut project: Value = registry_platform_yaml::Reader::new("workflow.yaml")
        .scan(include_bytes!(
            "../../../products/coordinator/examples/proposal-follow-up/workflow.yaml"
        ))
        .unwrap()
        .unwrap()
        .to_json_value();
    project["project"]["id"] = json!("native-proposal-notice");
    project["contracts"]["facilities"]["source"] = json!("breg.contract.json");
    project["operations"]["start-correction"]["action"]["id"] = json!("propose-item");
    project["operations"]["start-correction"]["connection"] = json!("applications");
    project["operations"]["submit-correction"]["connection"] = json!("applications");
    project["workflow"]["deadlineSeconds"] = json!(1100);
    project["workflow"]["steps"]["await-application"]["timeoutSeconds"] = json!(960);
    project["workflow"]["steps"]["start-draft"]
        .as_object_mut()
        .unwrap()
        .remove("onDeclaredRefusal");
    project["workflow"]["steps"]
        .as_object_mut()
        .unwrap()
        .remove("report-correction-refused");
    project["workflow"]["outcomes"]
        .as_object_mut()
        .unwrap()
        .remove("correction-refused");
    std::fs::copy(
        service
            .root
            .join("action-contracts/generated/action-contracts.json"),
        root.path().join("breg.contract.json"),
    )
    .unwrap();
    std::fs::write(
        root.path().join("workflow.yaml"),
        serde_norway::to_string(&project).unwrap(),
    )
    .unwrap();
    let definition = Definition::load(root.path()).unwrap();
    let adapters = Arc::new(HttpAdapters::new(&runtime).unwrap());
    let store = Arc::new(
        Store::connect(
            &std::env::var("COORDINATOR_TEST_DATABASE_URL").unwrap(),
            &runtime.namespace,
        )
        .await
        .unwrap(),
    );
    store.migrate().await.unwrap();
    let owner = Actor {
        issuer: "https://institution.example.invalid".into(),
        subject: "producer".into(),
        client_id: "producer-client".into(),
        operator: false,
    };
    let input = json!({"correction":{"input":{"targetId":record,"label":"Workflow applied"}},"notice":{
        "senderProfile":"transactional","to":{"email":"person@example.invalid"},"template":{"id":"application-follow-up","version":"1"},"locale":"en",
        "data":{"applicationReference":record}}});
    let run = store
        .admit_owned(
            &definition,
            input,
            &owner,
            "native-proposal-follow-up",
            &adapters.binding_digest_for(&definition.workflow),
        )
        .await
        .unwrap();
    let binding_digest = adapters.binding_digest_for(&definition.workflow);
    let mut worker = Worker::new(store.clone(), adapters);
    let mut resumed_pending_wait = false;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(80);
    loop {
        worker.tick().await.unwrap();
        let status = store.status_owned(run, &owner).await.unwrap();
        if !resumed_pending_wait && status.step == "await-application" {
            let inspection = store.inspect(run, &binding_digest).await.unwrap();
            if let Some(wait) = inspection.waits.iter().find(|wait| wait.observations > 0) {
                assert_eq!(wait.minimum_interval_seconds, 900);
                assert_eq!(wait.observations, 1);
                assert!(wait.next_observation_at.unwrap() > chrono::Utc::now());
                worker = Worker::new(
                    Arc::new(
                        Store::connect(
                            &std::env::var("COORDINATOR_TEST_DATABASE_URL").unwrap(),
                            &runtime.namespace,
                        )
                        .await
                        .unwrap(),
                    ),
                    Arc::new(HttpAdapters::new(&runtime).unwrap()),
                );
                worker.tick().await.unwrap();
                let restored = store.inspect(run, &binding_digest).await.unwrap();
                let restored = restored
                    .waits
                    .iter()
                    .find(|item| item.step == wait.step)
                    .unwrap();
                assert_eq!(restored.not_before, wait.not_before);
                assert_eq!(restored.next_observation_at, wait.next_observation_at);
                assert_eq!(restored.observations, wait.observations);
                assert_eq!(
                    messaging.count().await,
                    0,
                    "restart cannot dispatch an early notice"
                );
                let applied_deadline =
                    std::time::Instant::now() + std::time::Duration::from_secs(20);
                let options = BRegRecordOptions::default()
                    .access_profile("writer")
                    .unwrap();
                loop {
                    let current = client.get_record("items", &record, &options).await.unwrap();
                    if current.value.data.domain_data["label"] == "Workflow applied" {
                        break;
                    }
                    assert!(
                        std::time::Instant::now() < applied_deadline,
                        "native BReg automatic application remains independently scheduled"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                // Simulate elapsed fixture time while preserving the original
                // 900-second interval, timeout, deadline and read budget.
                advance_fixture_completion_time(&runtime, run).await;
                resumed_pending_wait = true;
            }
        }
        if status.state == "finished" {
            assert_eq!(
                status.outcome.as_deref(),
                Some("message-accepted"),
                "native Proposal follow-up status: {status:?}"
            );
            assert!(status.output.as_ref().unwrap()["id"].as_str().is_some());
            assert!(
                resumed_pending_wait,
                "native application wait resumes its recorded due schedule"
            );
            break;
        }
        assert!(
            !status.uncertain,
            "native automatic Proposal wait must have known progress"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "native exact application follow-up deadline"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let options = BRegRecordOptions::default()
        .access_profile("writer")
        .unwrap();
    assert_eq!(
        client
            .get_record("items", &record, &options)
            .await
            .unwrap()
            .value
            .data
            .domain_data["label"],
        "Workflow applied"
    );
    assert_eq!(messaging.count().await, 1);
    drop(worker);
    drop(store);
    drop(messaging);
    service.finish();
}

async fn advance_fixture_completion_time(
    runtime: &registry_coordinator::runtime::RuntimeConfig,
    run: uuid::Uuid,
) {
    let (mut client, connection) = tokio_postgres::connect(
        &std::env::var("COORDINATOR_TEST_DATABASE_URL").unwrap(),
        tokio_postgres::NoTls,
    )
    .await
    .unwrap();
    let connection = tokio::spawn(connection);
    let tx = client.transaction().await.unwrap();
    // Store::connect already validated this task-owned namespace as one SQL identifier.
    let schema = &runtime.namespace;
    tx.execute(&format!("UPDATE {schema}.runs SET admitted_at=admitted_at-interval '900 seconds',deadline_at=deadline_at-interval '900 seconds' WHERE run_id=$1"), &[&run]).await.unwrap();
    tx.execute(&format!("UPDATE {schema}.completion_waits SET started_at=started_at-interval '900 seconds',timeout_at=timeout_at-interval '900 seconds',not_before=not_before-interval '900 seconds',read_at=read_at-interval '900 seconds' WHERE run_id=$1"), &[&run]).await.unwrap();
    tx.execute(&format!("UPDATE {schema}.jobs SET next_attempt_at=next_attempt_at-interval '900 seconds' WHERE run_id=$1 AND state='pending'"), &[&run]).await.unwrap();
    tx.commit().await.unwrap();
    connection.abort();
}

fn breg_connection(
    runtime: &mut registry_coordinator::runtime::RuntimeConfig,
) -> &mut registry_coordinator::runtime::BregConnectionConfig {
    let registry_coordinator::runtime::ConnectionConfig::Breg(connection) =
        runtime.connections.get_mut("applications").unwrap()
    else {
        panic!("BReg connection")
    };
    connection
}

fn action_contract(metadata: &registry_breg_client::BRegMetadata) -> breg_action::ActionContract {
    let action = metadata.select_action("update-item", "writer").unwrap();
    breg_action::ActionContract {
        action_id: action.action_identifier().into(),
        action_revision: action.definition_revision().into(),
        mode: action.mode(),
    }
}

#[tokio::test]
#[ignore = "native BReg prerequisites; run products/coordinator/scripts/test-breg-action.py"]
async fn native_draft_submit_recovery_observes_exact_automatic_and_manual_application() {
    let issuer = support::issuer().await;
    let service = Breg::start(&issuer).await;
    let client = service.client(&issuer);
    let metadata = client.registry_contract(Some("writer")).await.unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.item.create", "writer")
        .unwrap()
    else {
        panic!("Create grant")
    };
    let record = client
        .create_record(
            &create,
            &BRegCreateRequest::new(
                json!({"owner":"coordinator-reader","label":"Before"})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
            .unwrap(),
            &BRegIdempotencyKey::parse("native-proposal-seed").unwrap(),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap()
        .value
        .data
        .record_identifier;
    let options = BRegRecordOptions::default()
        .access_profile("writer")
        .unwrap();
    for (action_id, label, manual) in [
        ("propose-item", "Automatic", false),
        ("manual-item", "Manual", true),
    ] {
        let before = client
            .get_record("items", &record, &options)
            .await
            .unwrap()
            .value
            .data
            .revision_identifier;
        let action = metadata.value.select_action(action_id, "writer").unwrap();
        let start = CallRequest {
            connection: "applications".into(),
            operation: Operation::InvokeBregAction,
            input: json!({"input":{"targetId":record,"label":label}}),
            idempotency_key: Some(format!("{action_id}-start")),
            operation_contract: Some(breg_action::ActionContract {
                action_id: action_id.into(),
                action_revision: action.definition_revision().into(),
                mode: action.mode(),
            }),
        };
        let prepared = breg_action::prepare(&client, "writer", &start)
            .await
            .unwrap_or_else(|_| panic!("draft prepare"));
        let draft = match breg_action::execute(&client, "writer", &start, &prepared).await {
            CallOutcome::Success(value) => value["proposal"].clone(),
            _ => panic!("draft start"),
        };
        assert_eq!(draft["state"], "draft");
        assert!(draft.get("application").is_none());
        assert_eq!(
            client
                .get_record("items", &record, &options)
                .await
                .unwrap()
                .value
                .data
                .revision_identifier,
            before
        );
        let mut proxy =
            LostResponse::submit_proposal(&service.base_url, draft["id"].as_str().unwrap());
        let submit_client = service.client_at(&issuer, &proxy.base_url);
        let submit = CallRequest {
            connection: "applications".into(),
            operation: Operation::SubmitBregProposal,
            input: draft,
            idempotency_key: Some(format!("{action_id}-submit")),
            operation_contract: None,
        };
        let prepared =
            breg_proposal::prepare(&submit_client, "writer", &submit, Transition::Submit)
                .await
                .unwrap_or_else(|_| panic!("submit prepare"));
        assert!(matches!(
            breg_proposal::execute(
                &submit_client,
                "writer",
                &submit,
                &prepared,
                Transition::Submit
            )
            .await,
            CallOutcome::Uncertain { .. }
        ));
        drop(submit_client);
        let submit_client = service.client_at(&issuer, &proxy.base_url);
        let accepted = match breg_proposal::execute(
            &submit_client,
            "writer",
            &submit,
            &prepared,
            Transition::Submit,
        )
        .await
        {
            CallOutcome::Success(value) => value,
            _ => panic!("exact original submit replay"),
        };
        assert_eq!(accepted["id"], submit.input["id"]);
        assert_eq!(accepted["actionRevision"], submit.input["actionRevision"]);
        assert_eq!(
            accepted["submissionVersion"],
            submit.input["submissionVersion"]
        );
        assert!(accepted["effectDigest"].as_str().is_some());
        if manual {
            assert!(matches!(
                breg_proposal::observe_application(&client, "writer", &accepted).await,
                ApplicationObservation::Pending { .. }
            ));
            let apply = CallRequest {
                connection: "applications".into(),
                operation: Operation::ApplyBregProposal,
                input: accepted.clone(),
                idempotency_key: Some("manual-item-apply".into()),
                operation_contract: None,
            };
            let prepared = breg_proposal::prepare(&client, "writer", &apply, Transition::Apply)
                .await
                .unwrap_or_else(|_| panic!("ordinary manual grant"));
            assert!(matches!(
                breg_proposal::execute(&client, "writer", &apply, &prepared, Transition::Apply)
                    .await,
                CallOutcome::Success(_)
            ));
        } else {
            let apply = CallRequest {
                connection: "applications".into(),
                operation: Operation::ApplyBregProposal,
                input: accepted.clone(),
                idempotency_key: Some("service-must-not-recover-automatic".into()),
                operation_contract: None,
            };
            assert!(
                breg_proposal::prepare(&client, "writer", &apply, Transition::Apply)
                    .await
                    .is_err()
            );
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            match breg_proposal::observe_application(&client, "writer", &accepted).await {
                ApplicationObservation::Complete(value) => {
                    assert_eq!(value["outcome"], "applied");
                    assert_eq!(value["proposal"]["effectDigest"], accepted["effectDigest"]);
                    assert_eq!(
                        value["proposal"]["application"]["submissionVersion"],
                        accepted["submissionVersion"]
                    );
                    assert_eq!(
                        value["proposal"]["application"]["effectDigest"],
                        accepted["effectDigest"]
                    );
                    break;
                }
                ApplicationObservation::Pending { .. }
                | ApplicationObservation::Retryable { .. } => {}
                ApplicationObservation::Hold { code } => {
                    panic!("unexpected native application hold: {code}")
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "native automatic application deadline"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let current = client
            .get_record("items", &record, &options)
            .await
            .unwrap()
            .value;
        assert_eq!(current.data.domain_data["label"], label);
        let commands = proxy.observations()["commands"].as_array().unwrap().clone();
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0]["bodyHash"], commands[1]["bodyHash"]);
        assert_eq!(commands[0]["key"], commands[1]["key"]);
        drop(proxy);
    }
    service.finish();
}

/// Passive observations around real adapters. No response is fabricated and
/// preparation, submission and receipt requests all reach maintained clients.
struct ObservedAdapters {
    native: HttpAdapters,
    dispatched: Arc<Mutex<DispatchedCommands>>,
    reconciled: Arc<Mutex<Vec<CallRequest>>>,
}

#[async_trait::async_trait]
impl AdapterSet for ObservedAdapters {
    fn binding_digest(&self) -> &str {
        self.native.binding_digest()
    }
    fn binding_digest_for(&self, workflow: &registry_coordinator::definition::Workflow) -> String {
        self.native.binding_digest_for(workflow)
    }
    async fn prepare(&self, request: &CallRequest) -> Result<Option<Vec<u8>>, CallOutcome> {
        self.native.prepare(request).await
    }
    async fn call(&self, request: &CallRequest) -> CallOutcome {
        self.native.call(request).await
    }
    async fn call_prepared(&self, request: &CallRequest, prepared: Option<&[u8]>) -> CallOutcome {
        self.dispatched
            .lock()
            .unwrap()
            .push((request.clone(), prepared.map(<[u8]>::to_vec)));
        self.native.call_prepared(request, prepared).await
    }
    async fn reconcile(
        &self,
        request: &CallRequest,
        accepted: Option<&Value>,
    ) -> ReconciliationOutcome {
        self.reconciled.lock().unwrap().push(request.clone());
        self.native.reconcile(request, accepted).await
    }
}

fn accepted(outcome: CallOutcome) -> Value {
    match outcome {
        CallOutcome::Success(value) => value,
        _ => panic!("native action must succeed"),
    }
}

fn refused(outcome: CallOutcome, expected: &str) {
    match outcome {
        CallOutcome::Refused { code } => assert_eq!(code, expected),
        _ => panic!("expected bounded refusal"),
    }
}

/// The explicit helper builds real BReg binaries before running this test.
/// Unit protocol stubs and the Coordinator durable-state matrix are separate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native BReg prerequisites; run products/coordinator/scripts/test-breg-action.py"]
async fn real_breg_action_recovers_exactly_once_and_rechecks_current_authority() {
    let issuer = support::issuer().await;
    let service = Breg::start(&issuer).await;
    let client = service.client(&issuer);
    let metadata = client.registry_contract(Some("writer")).await.unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.item.create", "writer")
        .unwrap()
    else {
        panic!("native Create binding")
    };
    let seed = client
        .create_record(
            &create,
            &BRegCreateRequest::new(
                json!({"owner":"coordinator-reader", "label":"Before"})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
            .unwrap(),
            &BRegIdempotencyKey::parse("coordinator-native-seed").unwrap(),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let record = seed.value.data.record_identifier;
    let refused_request = CallRequest {
        connection: "applications".into(),
        operation: Operation::InvokeBregAction,
        input: json!({"input":{"targetId":record, "label":"Refuse"}}),
        idempotency_key: Some("coordinator-native-refusal".into()),
        operation_contract: Some(action_contract(&metadata.value)),
    };
    let refused_prepared = breg_action::prepare(&client, "writer", &refused_request)
        .await
        .unwrap_or_else(|_| panic!("native refusal preparation"));
    let refusal =
        match breg_action::execute(&client, "writer", &refused_request, &refused_prepared).await {
            CallOutcome::DeclaredRefusal(refusal) => refusal,
            _ => panic!("native declared business refusal"),
        };
    assert_eq!(refusal.refusal_code(), "label-not-eligible");
    assert_eq!(
        serde_json::to_value(&refusal).unwrap(),
        json!({"refusalCode":"label-not-eligible"})
    );
    let read_options = BRegRecordOptions::default()
        .access_profile("writer")
        .unwrap();
    let unchanged = client
        .get_record("items", &record, &read_options)
        .await
        .unwrap();
    assert_eq!(unchanged.value.data.domain_data["label"], "Before");
    assert_eq!(unchanged.value.data.revision_identifier, "1");
    let mut proxy = LostResponse::start(&service.base_url);
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let mut runtime = support::config(root.path(), &issuer, &proxy.base_url, "http://127.0.0.1:1");
    runtime.connections.remove("notices");
    breg_connection(&mut runtime).profile = "writer".into();
    let adapters = HttpAdapters::new(&runtime).unwrap();
    let request = CallRequest {
        connection: "applications".into(),
        operation: Operation::InvokeBregAction,
        input: json!({"input":{"targetId":record, "label":"After"}}),
        idempotency_key: Some("coordinator-native-action".into()),
        operation_contract: Some(action_contract(&metadata.value)),
    };
    let prepared = adapters
        .prepare(&request)
        .await
        .unwrap_or_else(|_| panic!("native current metadata and conditions prepare"))
        .unwrap();
    let saved: Value = serde_json::from_slice(&prepared).unwrap();
    let body = saved["body"]
        .as_str()
        .expect("native prepared invocation body");
    let invocation: Value = serde_json::from_str(body).unwrap();
    assert!(
        invocation["preconditions"]["targetId"]["ifMatch"]
            .as_str()
            .is_some(),
        "native preparation includes original target condition"
    );
    assert_eq!(
        saved["idempotency_key"],
        request.idempotency_key.as_deref().unwrap()
    );
    assert!(
        proxy.observations()["commands"]
            .as_array()
            .unwrap()
            .is_empty(),
        "preparation does not mutate"
    );
    let prepared_path = root.path().join("prepared-action");
    support::private_file(&prepared_path, &prepared);
    match adapters.call_prepared(&request, Some(&prepared)).await {
        CallOutcome::Uncertain { code } => assert_eq!(code, "transport-uncertain"),
        _ => panic!("a dropped committed response stays uncertain"),
    }
    let committed = client
        .get_record("items", &record, &read_options)
        .await
        .unwrap();
    assert_eq!(committed.value.data.domain_data["label"], "After");
    assert_eq!(committed.value.data.revision_identifier, "2");
    let after_loss = proxy.observations();
    assert_eq!(
        after_loss["commands"].as_array().unwrap().len(),
        1,
        "no implicit client retry"
    );
    assert_eq!(after_loss["commands"][0]["responseStatus"], 200);
    let before_reconcile = proxy.observations();
    assert!(!request.operation.supports_read_receipt());
    assert!(matches!(
        adapters
            .reconcile(&request, Some(&json!({"action":"update-item"})))
            .await,
        ReconciliationOutcome::Unresolved { .. }
    ));
    assert_eq!(
        proxy.observations(),
        before_reconcile,
        "no fabricated receipt lookup or mutation during reconciliation"
    );
    drop(adapters);
    drop(prepared);
    let restarted = HttpAdapters::new(&runtime).unwrap();
    let recovered = std::fs::read(prepared_path).unwrap();
    let receipt = accepted(restarted.call_prepared(&request, Some(&recovered)).await);
    assert_eq!(receipt["results"]["item"]["recordId"], record);
    assert_eq!(receipt["results"]["item"]["revision"], 2);
    assert_eq!(
        accepted(restarted.call_prepared(&request, Some(&recovered)).await),
        receipt,
        "same command returns same application receipt"
    );
    let final_record = client
        .get_record("items", &record, &read_options)
        .await
        .unwrap();
    assert_eq!(
        final_record.value.data.revision_identifier, "2",
        "only one applied patch"
    );
    let observations = proxy.observations();
    let commands = observations["commands"].as_array().unwrap();
    assert_eq!(commands.len(), 3);
    for command in commands {
        assert_eq!(command["key"], "coordinator-native-action");
        assert_eq!(
            command["bodyHash"],
            hex::encode(Sha256::digest(body.as_bytes())),
            "exact native body includes unchanged target conditions"
        );
        assert_eq!(command["responseStatus"], 200);
    }
    let requests = observations["requests"].as_array().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(
                |r| r["path"] == "/v1/actions/update-item/target-conditions?accessProfile=writer"
            )
            .count(),
        1,
        "recovery never replaces original conditions"
    );
    assert_eq!(
        requests
            .iter()
            .filter(|r| r["method"] == "GET" && r["path"] == "/v1/registry?accessProfile=writer")
            .count(),
        4,
        "every execution rechecks current filtered metadata"
    );
    // A real read-only profile has current metadata but no action permission.
    // Protected preparation is evidence, not authority for another profile.
    let mut reader_runtime = runtime.clone();
    breg_connection(&mut reader_runtime).profile = "reader".into();
    let reader = HttpAdapters::new(&reader_runtime).unwrap();
    refused(
        reader.call_prepared(&request, Some(&recovered)).await,
        "action-unavailable",
    );
    let mut changed = request.clone();
    changed.input["input"]["label"] = json!("Different");
    refused(
        restarted.call_prepared(&changed, Some(&recovered)).await,
        "prepared-command-mismatch",
    );
    changed = request.clone();
    changed.idempotency_key = Some("another-key".into());
    refused(
        restarted.call_prepared(&changed, Some(&recovered)).await,
        "prepared-command-mismatch",
    );
    assert_eq!(
        proxy.observations()["commands"].as_array().unwrap().len(),
        3,
        "current authority and exact-command refusals send no mutation"
    );
    drop(client);
    drop(reader);
    drop(restarted);
    drop(proxy);
    service.finish();
    issuer.stop().await;
}

/// Real Worker checkpoints cross two separately served products. Recreating
/// Worker, Store and adapters here is object reconstruction, not a process
/// crash/restart. The existing process_restart target covers process behavior.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native BReg/Messaging prerequisites; run products/coordinator/scripts/test-breg-action.py"]
async fn worker_reconstruction_recovers_notice_after_one_real_breg_action() {
    use registry_coordinator::{
        definition::Definition,
        store::{Actor, Store},
        worker::Worker,
    };
    let issuer = support::issuer().await;
    let service = Breg::start(&issuer).await;
    let messaging = support::messaging::Messaging::start(&issuer).await;
    let client = service.client(&issuer);
    let metadata = client.registry_contract(Some("writer")).await.unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.item.create", "writer")
        .unwrap()
    else {
        panic!("native Create binding")
    };
    let record = client
        .create_record(
            &create,
            &BRegCreateRequest::new(
                json!({"owner":"coordinator-reader", "label":"Before"})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
            .unwrap(),
            &BRegIdempotencyKey::parse("coordinator-worker-seed").unwrap(),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap()
        .value
        .data
        .record_identifier;
    let mut action_proxy = LostResponse::observe_action(&service.base_url);
    let mut notice_proxy = LostResponse::start_notice(&messaging.base_url);
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let mut runtime = support::config(
        root.path(),
        &issuer,
        &action_proxy.base_url,
        &notice_proxy.base_url,
    );
    breg_connection(&mut runtime).profile = "writer".into();
    std::fs::copy(
        service
            .root
            .join("action-contracts/generated/action-contracts.json"),
        root.path().join("breg.contract.json"),
    )
    .unwrap();
    std::fs::write(root.path().join("workflow.yaml"),r#"
apiVersion: id.registrystack.org/formats/coordinator/project/v1alpha1
kind: CoordinatorProject
project: {id: native-action-notice-proof, version: "1"}
contracts:
  source: {type: breg, source: breg.contract.json}
types:
  run-input:
    type: object
    additionalProperties: false
    required: [recordId]
    properties: {recordId: {type: string, format: uuid}}
  accepted-output:
    type: object
    additionalProperties: false
    required: [actionApplicationId, messageId]
    properties:
      actionApplicationId: {type: string, format: uuid}
      messageId: {type: string, format: uuid}
operations:
  act: {uses: breg.invoke-action/v1, connection: applications, action: {contract: source, id: update-item}}
  notify: {uses: messaging.submit-message/v1, connection: notices}
functions:
  action_request:
    runtime: rhai
    source: functions.rhai
    entrypoint: action_request
    inputs: {input: {typeRef: run-input}}
    output: {operationInput: act}
  notice_request:
    runtime: rhai
    source: functions.rhai
    entrypoint: notice_request
    inputs: {action: {operationOutput: act}}
    output: {operationInput: notify}
  result:
    runtime: rhai
    source: functions.rhai
    entrypoint: result
    inputs: {action: {operationOutput: act}, notice: {operationOutput: notify}}
    output: {typeRef: accepted-output}
workflow:
  input: {typeRef: run-input}
  deadlineSeconds: 300
  start: act
  steps:
    act:
      type: call
      operation: act
      input: {type: function, function: action_request, inputs: {input: {type: input}}}
      next: notify
    notify:
      type: call
      operation: notify
      input: {type: function, function: notice_request, inputs: {action: {type: step, step: act}}}
      next: done
    done:
      type: finish
      outcome: accepted
      output: {type: function, function: result, inputs: {action: {type: step, step: act}, notice: {type: step, step: notify}}}
  outcomes:
    accepted: {typeRef: accepted-output}
"#).unwrap();
    std::fs::write(
        root.path().join("functions.rhai"),
        r#"
fn action_request(args) {
    #{input: #{targetId: args.input.recordId, label: "After"}}
}
fn notice_request(args) {
    #{senderProfile: "transactional", to: #{email: "person@example.invalid"},
      template: #{id: "application-follow-up", version: "1"}, locale: "en",
      data: #{applicationReference: args.action.applicationId}}
}
fn result(args) {
    #{actionApplicationId: args.action.applicationId, messageId: args.notice.id}
}
"#,
    )
    .unwrap();
    let definition = Definition::load(root.path()).unwrap();
    let dispatched = Arc::new(Mutex::new(Vec::new()));
    let reconciled = Arc::new(Mutex::new(Vec::new()));
    let adapters = Arc::new(ObservedAdapters {
        native: HttpAdapters::new(&runtime).unwrap(),
        dispatched: dispatched.clone(),
        reconciled: reconciled.clone(),
    });
    let binding = adapters.binding_digest_for(&definition.workflow);
    let url = std::env::var("COORDINATOR_TEST_DATABASE_URL").unwrap();
    let store = Arc::new(Store::connect(&url, &runtime.namespace).await.unwrap());
    store.migrate().await.unwrap();
    let owner = Actor {
        issuer: "https://institution.example.invalid".into(),
        subject: "producer".into(),
        client_id: "producer-client".into(),
        operator: false,
    };
    let input = json!({"recordId":record});
    let run = store
        .admit_owned(
            &definition,
            input.clone(),
            &owner,
            "worker-native-start",
            &binding,
        )
        .await
        .unwrap();
    let worker = Worker::new(store.clone(), adapters.clone());
    assert!(worker.tick().await.unwrap(), "action step executes");
    assert_eq!(
        store.status_owned(run, &owner).await.unwrap().step,
        "notify"
    );
    assert!(worker.tick().await.unwrap(), "notice step executes");
    let attention = store.inspect_owned(run, &binding, &owner).await.unwrap();
    assert_eq!(attention.run.state, "attention");
    assert_eq!(attention.run.step, "notify");
    assert!(attention.run.uncertain);
    assert!(attention.steps.iter().any(|step| step.step == "act"
        && step.state == "delivered"
        && step.command_prepared
        && !step.uncertain));
    assert!(attention
        .steps
        .iter()
        .any(|step| step.step == "notify" && step.command_prepared && step.uncertain));
    assert_eq!(
        messaging.count().await,
        1,
        "notice committed before lost response"
    );
    assert!(
        !worker.tick().await.unwrap(),
        "uncertain notice is not retried automatically"
    );
    let (action_request, prepared, notice_request) = {
        let calls = dispatched.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0.operation, Operation::InvokeBregAction);
        assert_eq!(calls[1].0.operation, Operation::SubmitMessage);
        assert!(calls[1].1.is_none());
        (
            calls[0].0.clone(),
            calls[0].1.clone().unwrap(),
            calls[1].0.clone(),
        )
    };
    assert!(action_request
        .idempotency_key
        .as_ref()
        .is_some_and(|key| !key.is_empty() && key != "worker-native-start"));
    assert_ne!(
        action_request.idempotency_key,
        notice_request.idempotency_key
    );
    let saved: Value = serde_json::from_slice(&prepared).unwrap();
    let action_body = saved["body"].as_str().unwrap();
    let body: Value = serde_json::from_str(action_body).unwrap();
    assert!(body["preconditions"]["targetId"]["ifMatch"]
        .as_str()
        .is_some());
    let actions_before_reconstruction = action_proxy.observations();
    assert_eq!(
        actions_before_reconstruction["commands"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        actions_before_reconstruction["commands"][0]["key"],
        action_request.idempotency_key.as_deref().unwrap()
    );
    assert_eq!(
        actions_before_reconstruction["commands"][0]["bodyHash"],
        hex::encode(Sha256::digest(action_body.as_bytes()))
    );
    assert_eq!(
        actions_before_reconstruction["commands"][0]["responseStatus"],
        200
    );
    let notice_before_reconstruction = notice_proxy.observations();
    assert_eq!(
        notice_before_reconstruction["commands"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        notice_before_reconstruction["commands"][0]["responseStatus"],
        202
    );
    assert_eq!(
        notice_before_reconstruction["commands"][0]["key"],
        notice_request.idempotency_key.as_deref().unwrap()
    );
    drop(worker);
    drop(store);
    drop(adapters);
    let reopened = Arc::new(Store::connect(&url, &runtime.namespace).await.unwrap());
    let adapters = Arc::new(ObservedAdapters {
        native: HttpAdapters::new(&runtime).unwrap(),
        dispatched: dispatched.clone(),
        reconciled: reconciled.clone(),
    });
    assert_eq!(adapters.binding_digest_for(&definition.workflow), binding);
    let observed = reopened
        .reconcile_owned(
            run,
            &binding,
            &owner,
            "observe-original-notice",
            adapters.as_ref(),
        )
        .await
        .unwrap();
    assert!(
        !observed.run.uncertain,
        "real receipt settles the original notice"
    );
    assert_eq!(observed.run.step, "done");
    {
        let original = reconciled.lock().unwrap();
        assert_eq!(original.len(), 1);
        assert_eq!(
            serde_json::to_value(&original[0]).unwrap(),
            serde_json::to_value(&notice_request).unwrap(),
            "reopened Store supplies the exact original input/key"
        );
    }
    let worker = Worker::new(reopened.clone(), adapters.clone());
    assert!(
        worker.tick().await.unwrap(),
        "finish after authoritative receipt"
    );
    let finished = reopened.status_owned(run, &owner).await.unwrap();
    assert_eq!(finished.state, "finished");
    assert_eq!(finished.outcome.as_deref(), Some("accepted"));
    assert_eq!(
        finished.output.as_ref().unwrap()["actionApplicationId"],
        notice_request.input["data"]["applicationReference"]
    );
    assert!(finished.output.as_ref().unwrap()["messageId"]
        .as_str()
        .is_some());
    assert_eq!(
        reopened
            .admit_owned(&definition, input, &owner, "worker-native-start", &binding)
            .await
            .unwrap(),
        run,
        "duplicate start after reconstruction returns original run"
    );
    assert!(!worker.tick().await.unwrap());
    assert_eq!(
        dispatched.lock().unwrap().len(),
        2,
        "completed action and original notice never resubmit"
    );
    assert_eq!(
        action_proxy.observations(),
        actions_before_reconstruction,
        "completed BReg step performs no further request"
    );
    let notices = notice_proxy.observations();
    assert_eq!(
        notices["commands"], notice_before_reconstruction["commands"],
        "receipt recovery sends no notice submission"
    );
    let receipt_requests: Vec<_> = notices["requests"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|request| request["path"] == "/v1/messages/receipt")
        .collect();
    assert_eq!(receipt_requests.len(), 1);
    assert_eq!(
        receipt_requests[0]["key"],
        notice_before_reconstruction["commands"][0]["key"]
    );
    assert_eq!(
        receipt_requests[0]["bodyHash"], notice_before_reconstruction["commands"][0]["bodyHash"],
        "real receipt lookup uses exact original notice body"
    );
    assert_eq!(messaging.count().await, 1);
    let record = client
        .get_record(
            "items",
            &record,
            &BRegRecordOptions::default()
                .access_profile("writer")
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        record.value.data.revision_identifier, "2",
        "one BReg patch despite notice recovery/duplicate start"
    );
    assert_eq!(record.value.data.domain_data["label"], "After");
    drop(worker);
    drop(reopened);
    drop(adapters);
    let (admin, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    let task = tokio::spawn(connection);
    admin
        .batch_execute(&format!("DROP SCHEMA {} CASCADE", runtime.namespace))
        .await
        .unwrap();
    task.abort();
    drop(notice_proxy);
    drop(action_proxy);
    drop(client);
    messaging.stop().await;
    service.finish();
    issuer.stop().await;
}
