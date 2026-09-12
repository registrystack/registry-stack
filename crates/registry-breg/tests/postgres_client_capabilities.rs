// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/client_http.rs"]
#[allow(dead_code)]
mod client_http;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use registry_breg::api::VerifiedRequestClaims;
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg_client::{
    BRegAsOfListRequest, BRegBatchBuilder, BRegChangeContext, BRegCreateRequest,
    BRegCurrentListRequest, BRegDirectWrite, BRegIdempotencyKey, BRegListRequest, BRegPatchRequest,
    BRegPreparedCreate, BRegProblemCode, BRegRecordFormat, BRegRecordOptions,
    BRegSnapshotListRequest,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

fn registry() -> registry_breg::CompiledRegistry {
    let project = parse_project_json(br#"{
      "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
      "registry":{"id":"client-capabilities","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://fixture.example.test"},
      "entities":[{
        "id":"entry","primaryDataset":"test-dataset","route":"entries","mutationMode":"mutable","tombstone":true,"classification":"internal",
        "batch":{"maximumItems":4,"maximumBytes":16384},
        "fields":[
          {"id":"code","type":"string","maxLength":64,"required":true,"classification":"internal"},
          {"id":"label","type":"string","maxLength":128,"required":true,"classification":"internal"},
          {"id":"valid-from","type":"date","required":true,"classification":"internal"},
          {"id":"valid-to","type":"date","classification":"internal"}
        ],
        "temporal":{"startField":"valid-from","endField":"valid-to","scopeFields":["code"]},
        "constraints":[{"kind":"temporal-non-overlap","scopeFields":["code"],"startField":"valid-from","endField":"valid-to"}]
      },{
        "id":"timestamp-entry","primaryDataset":"test-dataset","route":"timestamp-entries","mutationMode":"mutable","classification":"internal",
        "fields":[
          {"id":"code","type":"string","maxLength":64,"required":true,"classification":"internal"},
          {"id":"valid-from","type":"timestamp","required":true,"classification":"internal"},
          {"id":"valid-to","type":"timestamp","classification":"internal"}
        ],
        "temporal":{"startField":"valid-from","endField":"valid-to","scopeFields":["code"]},
        "constraints":[{"kind":"temporal-non-overlap","scopeFields":["code"],"startField":"valid-from","endField":"valid-to"}]
      }],
      "accessProfiles":[{
        "id":"operator","default":true,"principalClaim":"registry_principal",
        "requiredPurposes":["case-management"],
        "permissions":[{"entity":"entry","operations":["create","get","list","patch","batch","tombstone","revisions","snapshot"],
          "readableFields":["code","label","valid-from","valid-to"],"writableFields":["code","label","valid-from","valid-to"],
          "filterableFields":["code"],"sortableFields":["valid-from"],"allowCount":true,"revisionAccess":true,"rowBoundaries":[]
        },{"entity":"timestamp-entry","operations":["snapshot"],
          "readableFields":["code","valid-from","valid-to"],"writableFields":[],"rowBoundaries":[]
        }]
      }]
    }"#).expect("SDK fixture follows ordinary authoring contract");
    compile_project(&project, &[], CompileProfile::Authoring).expect("SDK fixture compiles")
}

fn claims() -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        "sdk-fixture-operator",
        BTreeSet::new(),
        Some("case-management".into()),
        BTreeMap::new(),
    )
    .unwrap()
}

fn key(value: &str) -> BRegIdempotencyKey {
    BRegIdempotencyKey::parse(value).unwrap()
}
fn create(value: Value) -> BRegCreateRequest {
    BRegCreateRequest::new(value.as_object().unwrap().clone()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an installed public Node package in BREG_TEST_NODE_PACKAGE"]
async fn installed_node_package_completes_real_client_journey() {
    let package =
        std::env::var("BREG_TEST_NODE_PACKAGE").expect("set installed public Node package path");
    let fixture = client_http::ClientFixture::start(registry(), claims()).await;
    let status = std::process::Command::new("node")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/client-capabilities-node.cjs"
        ))
        .env("BREG_TEST_NODE_PACKAGE", package)
        .env("BREG_TEST_CLIENT_URL", &fixture.http.base_url)
        .status()
        .expect("installed Node package journey launches");
    fixture.finish().await;
    assert!(status.success(), "installed Node package journey failed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires isolated installed public wheel in BREG_TEST_PYTHON_EXECUTABLE"]
async fn installed_python_package_completes_real_client_journey() {
    let python = std::env::var("BREG_TEST_PYTHON_EXECUTABLE")
        .expect("set isolated installed public Python interpreter");
    let fixture = client_http::ClientFixture::start(registry(), claims()).await;
    let status = std::process::Command::new(python)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/client-capabilities-python.py"
        ))
        .env("BREG_TEST_CLIENT_URL", &fixture.http.base_url)
        .status()
        .expect("installed Python package journey launches");
    fixture.finish().await;
    assert!(status.success(), "installed Python package journey failed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sdk_atomic_corrections_snapshots_revisions_tombstone_and_recovery_use_real_postgres() {
    let fixture = client_http::ClientFixture::start(registry(), claims()).await;
    let client = &fixture.http.client;
    let contract = client.registry_contract(Some("operator")).await.unwrap();
    let BRegDirectWrite::Create(create_binding) = contract
        .value
        .select_direct_write("records.entry.create", "operator")
        .unwrap()
    else {
        panic!("Create binding")
    };
    let batch_binding = contract.value.select_batch("entry", "operator").unwrap();
    let tombstone_binding = contract
        .value
        .select_tombstone("entry", "operator")
        .unwrap();

    // Admission uses the real caller-filtered batch contract before mutation I/O.
    let mut full = BRegBatchBuilder::new(&batch_binding);
    let candidate = create(json!({"code":"LIMIT","label":"bounded","validFrom":"2020-01-01"}));
    for _ in 0..4 {
        full = full.create(&candidate).unwrap();
    }
    assert!(
        full.create(&candidate).is_err(),
        "the fifth item exceeds the advertised limit"
    );
    let oversized =
        create(json!({"code":"LIMIT","label":"x".repeat(16_384),"validFrom":"2020-01-01"}));
    assert!(BRegBatchBuilder::new(&batch_binding)
        .create(&oversized)
        .unwrap()
        .build()
        .is_err());
    let missing_required = create(json!({"code":"LIMIT","validFrom":"2020-01-01"}));
    assert!(BRegBatchBuilder::new(&batch_binding)
        .create(&missing_required)
        .is_err());
    let unknown_field = create(
        json!({"code":"LIMIT","label":"bounded","validFrom":"2020-01-01","secret":"not writable"}),
    );
    assert!(BRegBatchBuilder::new(&batch_binding)
        .create(&unknown_field)
        .is_err());

    let old = client
        .create_record(
            &create_binding,
            &create(
                json!({"code":"A","label":"old","validFrom":"2020-01-01","validTo":"2021-01-01"}),
            ),
            &key("sdk-old"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let current = client
        .create_record(
            &create_binding,
            &create(json!({"code":"A","label":"current","validFrom":"2021-01-01"})),
            &key("sdk-current"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let old_id = old.value.data.record_identifier.parse().unwrap();
    let current_id = current.value.data.record_identifier.parse().unwrap();

    let effective = client
        .list_current_records("entries", &BRegCurrentListRequest::default())
        .await
        .unwrap();
    assert_eq!(effective.value.value.items.len(), 1);
    assert_eq!(
        effective.value.value.items[0].record_identifier,
        current.value.data.record_identifier
    );
    let historical = client
        .list_records_as_of(
            "entries",
            &BRegAsOfListRequest::new("2020-04-01T00:00:00Z").unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        historical.value.value.items[0].record_identifier,
        old.value.data.record_identifier
    );
    let normalized_valid_at = client
        .list_snapshot_records(
            "timestamp-entries",
            &BRegSnapshotListRequest::default()
                .valid_at("2020-04-01T00:00:00.000Z")
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        normalized_valid_at.value.valid_at.as_deref(),
        Some("2020-04-01T00:00:00Z")
    );

    let first = client
        .list_snapshot_records(
            "entries",
            &BRegSnapshotListRequest::default()
                .orderby("validFrom")
                .unwrap()
                .top(1)
                .unwrap(),
        )
        .await
        .unwrap();
    let snapshot = first.value.snapshot.clone();
    let next = first
        .value
        .continuation
        .as_ref()
        .expect("snapshot has another page");

    // Both intervals are valid only after all edits are applied. The caller
    // sends the expanding second interval first to exercise final-state checks.
    let old_patch = BRegPatchRequest::builder()
        .replace("validTo", json!("2020-06-01"))
        .unwrap()
        .build()
        .unwrap();
    let current_patch = BRegPatchRequest::builder()
        .replace("validFrom", json!("2020-06-01"))
        .unwrap()
        .build()
        .unwrap();
    let correction = BRegBatchBuilder::new(&batch_binding)
        .patch(current_id, current.metadata.etag().unwrap(), &current_patch)
        .unwrap()
        .patch(old_id, old.metadata.etag().unwrap(), &old_patch)
        .unwrap()
        .change_context(BRegChangeContext::correction("effective-date-corrected").unwrap())
        .build()
        .unwrap();
    let corrected = client
        .batch_records(&batch_binding, &correction, &key("sdk-correction"))
        .await
        .unwrap();
    assert_eq!(corrected.value.results().len(), 2);
    let replay = client
        .batch_records(&batch_binding, &correction, &key("sdk-correction"))
        .await
        .unwrap();
    assert_eq!(replay.value, corrected.value);

    let second = client.continue_snapshot_list(next).await.unwrap();
    assert_eq!(second.value.snapshot, snapshot);
    assert_eq!(
        second.value.value.items[0].domain_data["validFrom"],
        "2021-01-01"
    );
    let retained = client
        .list_snapshot_records(
            "entries",
            &BRegSnapshotListRequest::default()
                .snapshot(snapshot)
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(retained.value.value.items.len(), 2);

    // A stale second item must roll back the new first item.
    let invalid = BRegBatchBuilder::new(&batch_binding)
        .create(&create(
            json!({"code":"ROLLBACK","label":"must-not-commit","validFrom":"2020-01-01"}),
        ))
        .unwrap()
        .patch(old_id, old.metadata.etag().unwrap(), &old_patch)
        .unwrap()
        .build()
        .unwrap();
    let refused = client
        .batch_records(&batch_binding, &invalid, &key("sdk-stale-batch"))
        .await
        .unwrap_err();
    assert_eq!(
        refused.problem_code(),
        Some(BRegProblemCode::PreconditionFailed)
    );
    let live = client
        .list_records(
            "entries",
            &BRegListRequest::default()
                .filter("code eq 'ROLLBACK'")
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(live.value.value.items.is_empty());

    let constraint_failure = BRegBatchBuilder::new(&batch_binding)
        .create(&create(
            json!({"code":"ROLLBACK-CONSTRAINT","label":"must roll back","validFrom":"2020-01-01"}),
        ))
        .unwrap()
        .create(&create(
            json!({"code":"A","label":"overlapping interval","validFrom":"2020-01-01"}),
        ))
        .unwrap()
        .build()
        .unwrap();
    let refused = client
        .batch_records(
            &batch_binding,
            &constraint_failure,
            &key("sdk-constraint-batch"),
        )
        .await
        .unwrap_err();
    assert_eq!(
        refused.problem_code(),
        Some(BRegProblemCode::MutationConflict)
    );
    let live = client
        .list_records(
            "entries",
            &BRegListRequest::default()
                .filter("code eq 'ROLLBACK-CONSTRAINT'")
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        live.value.value.items.is_empty(),
        "a constraint failure rolls back every earlier item"
    );

    let revision = client
        .get_record_revision(
            "entries",
            &old.value.data.record_identifier,
            1,
            &BRegRecordOptions::default(),
        )
        .await
        .unwrap();
    let revision: Value = serde_json::from_slice(revision.value.as_bytes()).unwrap();
    assert!(revision.to_string().contains("2021-01-01"));
    let revisions = client
        .record_revisions(
            "entries",
            &old.value.data.record_identifier,
            Some("operator"),
        )
        .await
        .unwrap();
    let revisions: Value = serde_json::from_slice(revisions.value.as_bytes()).unwrap();
    assert!(revisions["pageInfo"]["nextCursor"].is_null());

    let latest = client
        .get_record(
            "entries",
            &current.value.data.record_identifier,
            &BRegRecordOptions::default(),
        )
        .await
        .unwrap();
    let deleted = client
        .tombstone_record(
            &tombstone_binding,
            current_id,
            latest.metadata.etag().unwrap(),
            &key("sdk-tombstone"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    assert_eq!(
        deleted.value.data.record_identifier,
        current.value.data.record_identifier
    );
    let live = client
        .list_records("entries", &BRegListRequest::default())
        .await
        .unwrap();
    assert_eq!(live.value.value.items.len(), 1);
    assert!(client
        .record_revisions("entries", &current.value.data.record_identifier, None)
        .await
        .is_ok());

    let request = create(json!({"code":"RECOVERY","label":"saved","validFrom":"2020-01-01"}));
    let prepared = client
        .prepare_create(
            &create_binding,
            &request,
            &key("sdk-recover"),
            BRegRecordFormat::Json,
        )
        .unwrap();
    let committed = client
        .create_record(
            &create_binding,
            &request,
            &key("sdk-recover"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let saved = BRegPreparedCreate::from_slice(prepared.as_bytes()).unwrap();
    let fresh = client.registry_contract(Some("operator")).await.unwrap();
    let BRegDirectWrite::Create(fresh_binding) = fresh
        .value
        .select_direct_write("records.entry.create", "operator")
        .unwrap()
    else {
        panic!("Create binding")
    };
    let (request, key, format) = client.recover_create(&fresh_binding, &saved).unwrap();
    let recovered = client
        .create_record(&fresh_binding, &request, &key, format)
        .await
        .unwrap();
    assert_eq!(recovered.value, committed.value);
    fixture.finish().await;
}
