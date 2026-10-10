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
    protocol::{AdapterSet, CallOutcome, CallRequest, Operation, ReconciliationOutcome},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

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
                json!({"owner":"poc-reader", "label":"Before"})
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
    let mut proxy = LostResponse::start(&service.base_url);
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let mut runtime = support::config(root.path(), &issuer, &proxy.base_url, "http://127.0.0.1:1");
    runtime.connections.remove("notices");
    runtime.connections.get_mut("applications").unwrap().profile = Some("writer".into());
    let adapters = HttpAdapters::new(&runtime).unwrap();
    let request = CallRequest {
        connection: "applications".into(),
        operation: Operation::InvokeBregAction,
        input: json!({"action":"update-item", "input":{"targetId":record, "label":"After"}}),
        idempotency_key: Some("coordinator-native-action".into()),
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
    let read_options = BRegRecordOptions::default()
        .access_profile("writer")
        .unwrap();
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
    reader_runtime
        .connections
        .get_mut("applications")
        .unwrap()
        .profile = Some("reader".into());
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
