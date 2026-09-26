// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "../src/history_context.rs"]
mod history_context;
#[path = "../src/history_reference.rs"]
mod history_reference;
mod history_schema {
    pub use registry_breg::history_schema::*;
}
mod model {
    pub use registry_breg::model::*;
}
mod change_request {
    pub use registry_breg::change_request::MAX_CHANGE_REQUEST_FIELD_MUTATIONS;
}
#[path = "../src/history_store.rs"]
#[allow(dead_code)]
mod history_store;
#[allow(dead_code)]
mod postgres {
    pub use registry_breg::postgres::{ClaimContext, RowBoundaryContext, SqlIdentifier};

    pub(crate) struct ActionClaimContext {
        action_id: String,
        principal: String,
        access_profile: String,
        purpose: Option<String>,
    }

    impl ActionClaimContext {
        pub(crate) fn action_id(&self) -> &str {
            &self.action_id
        }

        pub(crate) fn principal(&self) -> &str {
            &self.principal
        }

        pub(crate) fn access_profile(&self) -> &str {
            &self.access_profile
        }

        pub(crate) fn purpose(&self) -> Option<&str> {
            self.purpose.as_deref()
        }
    }
}
#[path = "support/client_http.rs"]
#[allow(dead_code)]
mod client_http;
#[path = "../src/history_commit.rs"]
#[allow(dead_code)]
mod history_commit;
#[path = "../src/idempotency.rs"]
#[allow(dead_code)]
mod idempotency;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;
#[path = "../src/stored_bytes.rs"]
#[allow(dead_code)]
mod stored_bytes;

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use registry_platform_audit::AuditProfile;
use serde_json::{json, Value};
use tracing::instrument::WithSubscriber;
use uuid::Uuid;

use history_commit::{
    allocate_revision_commit, install_empty_history_baseline, resolve_snapshot_reference,
    CommitAllocation, HistoryCommitError, RevisionCommitMember,
};
use history_context::{ChangeContext, CommitOrigin};
use history_reference::SnapshotReference;
use history_store::retain_descriptor;
use postgres_harness::TestDatabase;
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::{parse_project_json, FieldTypeSource};
use registry_breg::field_encryption_backfill::{
    erase_field_encryption_history, FieldEncryptionHistoryErasureError,
    FieldEncryptionHistoryErasureRequest, FIELD_ENCRYPTION_AUDIT_SCHEMA,
};
use registry_breg::history_erasure::{
    erase_record_history, HistoryErasureError, HistoryErasureRequest, HistoryErasureTimeouts,
    RecordHistoryErasureTarget, HISTORY_ERASURE_AUDIT_SCHEMA,
};
use registry_breg::mutation::install_mutation_schema;
use registry_breg::postgres::{
    install_compiled_schema, managed_schema_fingerprint, ExpectedManagedCatalog,
    ExpectedRegistryIdentity, RegistryLockKey,
};
use registry_breg_client::{BRegProblemCode, BRegRecordOptions, BRegSnapshotListRequest};

const ENTITY: &str = "membership";
const OLD_PACKAGE: &str = "pkg-erasure-old";
const MIDDLE_PACKAGE: &str = "pkg-erasure-middle";
const CURRENT_PACKAGE: &str = "pkg-erasure-current";
const RECORD_CANARY: &str = "018feaa0-68f9-4a45-b9e3-58436df07af7";
const REASON_CANARY: &str = "source reason must not enter maintenance audit";
const OPERATOR_CANARY: &str = "operator secret must not enter maintenance audit";

#[test]
fn history_erasure_fixture_has_an_encrypted_structured_field() {
    let registry = compiled_registry();
    let field = &registry.entities()[ENTITY].fields["details"];
    assert!(matches!(
        field.field_type,
        FieldTypeSource::Structured { .. }
    ));
    assert!(field.encryption.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audited_erasure_deletes_targeted_history_and_makes_bookmark_unavailable() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    let expected = install_ready_history_registry(&database, &mut migration, &registry).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).expect("lock key derives");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x71; 32].into())
        .expect("test owns a keyed audit profile");
    let record_id = Uuid::parse_str(RECORD_CANARY).unwrap();

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    insert_revision(&transaction, record_id, 1, OLD_PACKAGE, "create").await;
    insert_revision(&transaction, record_id, 2, CURRENT_PACKAGE, "patch").await;
    insert_outbox_payload(&transaction, record_id, 1).await;
    let first_context = ChangeContext::parse_json(&json!({
        "kind": "correction",
        "reasonCode": "effective_date_corrected",
        "reasonText": REASON_CANARY,
        "sourceReferences": ["case-document:erasure-proof"]
    }))
    .unwrap();
    let first_commit = allocate_revision_commit(
        &transaction,
        CommitAllocation {
            package_revision: OLD_PACKAGE,
            origin: CommitOrigin::Mutation {
                actor_reference: "actor:hash",
                request_reference: "request:hash",
            },
            change_context: Some(&first_context),
            members: &[RevisionCommitMember {
                entity_id: ENTITY,
                record_id,
                record_revision: 1,
            }],
        },
    )
    .await
    .expect("first commit is indexed");
    let second_commit = allocate_revision_commit(
        &transaction,
        CommitAllocation {
            package_revision: CURRENT_PACKAGE,
            origin: CommitOrigin::Mutation {
                actor_reference: "actor:hash",
                request_reference: "request:hash",
            },
            change_context: None,
            members: &[RevisionCommitMember {
                entity_id: ENTITY,
                record_id,
                record_revision: 2,
            }],
        },
    )
    .await
    .expect("second commit is indexed");
    insert_idempotency_response(
        &transaction,
        "record-key",
        "record-binding",
        "record",
        Some(&format!("{ENTITY}:{record_id}")),
        Some(1),
        None,
        json!({
            "id": record_id.to_string(),
            "revision": 1,
            "data": {"household": "cached-record-canary"}
        }),
    )
    .await;
    insert_idempotency_response(
        &transaction,
        "batch-snapshot-key",
        "batch-snapshot-binding",
        "batch",
        None,
        None,
        Some(1),
        json!({
            "snapshot": first_commit.reference.to_string(),
            "results": [{
                "id": record_id.to_string(),
                "revision": 1,
                "data": {"household": "cached-batch-snapshot-canary"}
            }]
        }),
    )
    .await;
    insert_idempotency_response(
        &transaction,
        "batch-prehistory-key",
        "batch-prehistory-binding",
        "batch",
        None,
        None,
        Some(1),
        json!({
            "results": [{
                "id": record_id.to_string(),
                "revision": 1,
                "data": {"household": "cached-batch-prehistory-canary"}
            }]
        }),
    )
    .await;
    // A sealed batch body: the data members hold tagged envelope values while
    // the snapshot and the item's id and revision stay outside them. The
    // tombstone scan must still find it through those positions, which is why
    // sealed bodies need no referenced-records sidecar.
    insert_idempotency_response(
        &transaction,
        "batch-sealed-key",
        "batch-sealed-binding",
        "batch",
        None,
        None,
        Some(1),
        json!({
            "snapshot": first_commit.reference.to_string(),
            "results": [{
                "id": record_id.to_string(),
                "revision": 1,
                "data": {"household": {"__bregEncryptedV1": "c2VhbGVkLWNhY2hlZC12YWx1ZQ"}}
            }]
        }),
    )
    .await;
    transaction.commit().await.expect("history commits");

    let outcome = erase_record_history(
        &mut migration,
        HistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit: &database.audit(audit_profile.clone()),
            operator_reference: OPERATOR_CANARY,
            reason: REASON_CANARY,
            target: RecordHistoryErasureTarget::new(ENTITY, record_id, 1),
        },
    )
    .await
    .expect("targeted erasure succeeds");

    assert!(outcome.coverage_ready);
    assert_eq!(outcome.unavailable_after_position, Some(0));
    assert_eq!(outcome.affected_commit_count, 1);
    assert_eq!(outcome.erased_revision_count, 1);
    assert_eq!(outcome.erased_commit_member_count, 1);
    assert_eq!(outcome.scrubbed_change_context_count, 1);
    assert_eq!(outcome.scrubbed_outbox_payload_count, 1);
    assert_eq!(outcome.scrubbed_cached_response_count, 4);
    assert_eq!(outcome.removed_descriptor_count, 1);

    let erased_response_body = b"{\"kind\":\"erased\"}".as_slice();
    let empty_response_headers = vec![0_u8, 0_u8];
    let state = migration
        .query_one(
            "SELECT
                 (SELECT count(*)::bigint FROM registry_internal.registry_revisions
                   WHERE entity_id = $1 AND record_id = $2 AND record_revision = 1),
                 (SELECT count(*)::bigint FROM registry_internal.registry_revision_commit_members
                   WHERE entity_id = $1 AND record_id = $2 AND record_revision = 1),
                 (SELECT change_context IS NULL AND change_context_digest IS NULL
                    FROM registry_internal.registry_revision_commits
                   WHERE commit_position = 1),
                 (SELECT payload IS NULL FROM registry_internal.registry_outbox
                   WHERE entity_id = $1 AND record_revision = 1),
                 (SELECT count(*)::bigint FROM registry_internal.registry_history_schemas
                   WHERE package_revision = $3),
                 (SELECT count(*)::bigint FROM registry_internal.registry_history_schemas
                   WHERE package_revision = $4),
                 (SELECT count(*)::bigint FROM registry_internal.registry_revisions
                   WHERE entity_id = $1 AND record_id = $2 AND record_revision = 2),
                 (SELECT count(*)::bigint FROM registry_internal.registry_idempotency
                   WHERE result_kind = 'erased'
                     AND record_reference IS NULL
                     AND record_revision IS NULL
                     AND result_count IS NULL
                     AND response_body = $5
                     AND response_headers = $6)",
            &[
                &ENTITY,
                &record_id,
                &OLD_PACKAGE,
                &CURRENT_PACKAGE,
                &erased_response_body,
                &empty_response_headers,
            ],
        )
        .await
        .expect("migration can inspect erasure result");
    assert_eq!(state.get::<_, i64>(0), 0);
    assert_eq!(state.get::<_, i64>(1), 0);
    assert!(state.get::<_, bool>(2));
    assert!(state.get::<_, bool>(3));
    assert_eq!(state.get::<_, i64>(4), 0);
    assert_eq!(state.get::<_, i64>(5), 1);
    assert_eq!(state.get::<_, i64>(6), 1);
    assert_eq!(state.get::<_, i64>(7), 4);

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    assert_eq!(
        resolve_snapshot_reference(&transaction, first_commit.reference).await,
        Err(HistoryCommitError::Unavailable),
        "the directly erased bookmark cannot resurrect deleted history"
    );
    assert_eq!(
        resolve_snapshot_reference(&transaction, second_commit.reference).await,
        Err(HistoryCommitError::Unavailable),
        "the coarse coverage cutoff refuses newer bookmarks until an exact retained boundary exists"
    );
    let baseline_uuid: Uuid = transaction
        .query_one(
            "SELECT snapshot_reference
               FROM registry_internal.registry_revision_commits
              WHERE commit_position = 0",
            &[],
        )
        .await
        .expect("baseline reference remains stored")
        .get(0);
    resolve_snapshot_reference(&transaction, SnapshotReference::for_uuid(baseline_uuid))
        .await
        .expect("baseline remains available");
    let replay = idempotency::lock_and_load(
        &transaction,
        &idempotency::ResolvedIdempotencyBinding {
            key_reference: "record-key".to_owned(),
            binding_reference: "record-binding".to_owned(),
            principal_reference: "principal".to_owned(),
            record_reference: format!("{ENTITY}:{record_id}"),
            handler_answer_digest: None,
        },
    )
    .await;
    assert!(
        matches!(replay, Err(idempotency::IdempotencyError::Conflict)),
        "erased idempotency tombstones refuse replay before releasing cached bytes"
    );
    // The refusal is permanent, so it must reach the caller as the terminal
    // 409 idempotency.conflict rather than an outage clients retry forever.
    assert!(
        matches!(
            registry_breg::mutation::MutationError::from(
                registry_breg::idempotency::IdempotencyError::Conflict
            ),
            registry_breg::mutation::MutationError::IdempotencyConflict
        ),
        "a consumed erased key answers with a terminal conflict"
    );
    transaction.commit().await.expect("resolution commits");
    assert_erasure_audit_is_minimized(&database);

    let http = snapshot_client_http(
        &database,
        &migration,
        Arc::new(registry),
        expected.clone(),
        database.audit(audit_profile.clone()),
    )
    .await;
    let request = |reference: SnapshotReference| {
        BRegSnapshotListRequest::default()
            .options(
                BRegRecordOptions::default()
                    .access_profile("writer")
                    .unwrap()
                    .select(["household"])
                    .unwrap(),
            )
            .snapshot(reference.to_string())
            .unwrap()
    };
    for erased_or_cut_off in [first_commit.reference, second_commit.reference] {
        let refusal = http
            .client
            .list_snapshot_records("memberships", &request(erased_or_cut_off))
            .await
            .expect_err("an erased or conservatively cut-off bookmark is unavailable");
        assert_eq!(refusal.status(), Some(503));
        assert_eq!(
            refusal.problem_code(),
            Some(BRegProblemCode::SourceUnavailable)
        );
    }
    let baseline = http
        .client
        .list_snapshot_records(
            "memberships",
            &request(SnapshotReference::for_uuid(baseline_uuid)),
        )
        .await
        .expect("the earlier complete baseline remains available to the SDK");
    assert!(baseline.value.value.items.is_empty());
    drop(http);

    migration_task.abort();
    database.cleanup().await;
}

/// Generic record-history erasure does not erase change-request workflow
/// records. Proposals, target snapshots, and application receipts have their
/// own retention contract even when they refer to the erased record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn erasure_preserves_change_request_target_and_proposal_payloads() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    let expected = install_ready_history_registry(&database, &mut migration, &registry).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).expect("lock key derives");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x75; 32].into())
        .expect("test owns a keyed audit profile");
    let erased_record = Uuid::from_u128(0x11);
    let kept_record = Uuid::from_u128(0x22);

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    insert_revision(&transaction, erased_record, 1, OLD_PACKAGE, "create").await;
    insert_revision(&transaction, kept_record, 1, CURRENT_PACKAGE, "create").await;
    let fingerprint = format!("sha256:{}", "7".repeat(64));
    let request_a = Uuid::from_u128(0xA1);
    let request_b = Uuid::from_u128(0xB1);
    for (request_id, target_record, canary) in [
        (request_a, erased_record, "cr-scrub-canary"),
        (request_b, kept_record, "cr-kept-canary"),
    ] {
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_request_state
                     (request_entity_id, request_id, owner_reference, state,
                      proposal_version, workflow_revision)
                 VALUES ('membership-request', $1, 'owner:hash', 'applied', 1, 1)",
                &[&request_id],
            )
            .await
            .expect("change request state inserts");
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_request_proposals
                     (request_entity_id, request_id, proposal_version, request_record_revision,
                      contract_fingerprint, effect_digest, snapshot)
                 VALUES ('membership-request', $1, 1, 1, $2, $2, $3)",
                &[
                    &request_id,
                    &fingerprint,
                    &json!({
                        "reasonText": canary,
                        "targetCount": 1
                    }),
                ],
            )
            .await
            .expect("change request proposal inserts");
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_request_targets
                     (request_entity_id, request_id, proposal_version, target_entity_id,
                      target_record_id, operation, expected_revision, base_snapshot,
                      after_snapshot)
                 VALUES ('membership-request', $1, 1, $2, $3, 'patch', 1, $4, $5)",
                &[
                    &request_id,
                    &ENTITY,
                    &target_record,
                    &json!({"household": format!("{canary}-base")}),
                    &json!({"household": format!("{canary}-after")}),
                ],
            )
            .await
            .expect("change request target inserts");
    }
    transaction
        .commit()
        .await
        .expect("change request copies commit");

    let outcome = erase_record_history(
        &mut migration,
        HistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit: &database.audit(audit_profile.clone()),
            operator_reference: OPERATOR_CANARY,
            reason: REASON_CANARY,
            target: RecordHistoryErasureTarget::new(ENTITY, erased_record, 1),
        },
    )
    .await
    .expect("targeted erasure succeeds");

    assert_eq!(outcome.erased_revision_count, 1);
    assert_eq!(outcome.scrubbed_request_target_count, 0);
    assert_eq!(outcome.scrubbed_request_proposal_count, 0);

    let state = migration
        .query_one(
            "SELECT
                 (SELECT base_snapshot ? 'household' AND after_snapshot ? 'household'
                                          AND erased_at IS NULL
                    FROM registry_internal.registry_request_targets WHERE request_id = $1),
                 (SELECT snapshot ? 'reasonText' AND erased_at IS NULL
                    FROM registry_internal.registry_request_proposals WHERE request_id = $1),
                 (SELECT base_snapshot ? 'household' AND after_snapshot ? 'household'
                                          AND erased_at IS NULL
                    FROM registry_internal.registry_request_targets WHERE request_id = $2),
                 (SELECT snapshot ? 'reasonText' AND erased_at IS NULL
                    FROM registry_internal.registry_request_proposals WHERE request_id = $2)",
            &[&request_a, &request_b],
        )
        .await
        .expect("migration can inspect the preserved copies");
    assert!(
        state.get::<_, bool>(0),
        "the erased record's target snapshots remain workflow history"
    );
    assert!(
        state.get::<_, bool>(1),
        "the erased record's proposal remains workflow history"
    );
    assert!(
        state.get::<_, bool>(2),
        "a request targeting a kept record keeps its target snapshots"
    );
    assert!(
        state.get::<_, bool>(3),
        "a request targeting a kept record keeps its proposal snapshot"
    );

    assert_erasure_audit_is_minimized(&database);
    for entry in database.audit_entries() {
        let text = entry.to_string();
        assert!(!text.contains("cr-scrub-canary"));
        assert!(!text.contains("cr-kept-canary"));
    }

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn field_encryption_erasure_scrubs_orphan_create_and_preserves_post_flip_submission() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    let expected = install_ready_history_registry(&database, &mut migration, &registry).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).expect("lock key derives");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x76; 32].into())
        .expect("test owns a keyed audit profile");
    let request_id = Uuid::from_u128(0xCA11);
    let reserved_record_id = Uuid::from_u128(0xCA12);
    let post_flip_request_id = Uuid::from_u128(0xCA13);
    let post_flip_record_id = Uuid::from_u128(0xCA14);
    let guard_request_id = Uuid::from_u128(0xCA15);
    let guard_record_id = Uuid::from_u128(0xCA16);
    let fingerprint = format!("sha256:{}", "7".repeat(64));

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_request_state
                 (request_entity_id, request_id, owner_reference, state,
                  proposal_version, workflow_revision)
             VALUES ('membership-request', $1, 'owner:hash', 'cancelled', 1, 1)",
            &[&request_id],
        )
        .await
        .expect("canceled request state inserts");
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_request_proposals
                 (request_entity_id, request_id, proposal_version, request_record_revision,
                  contract_fingerprint, effect_digest, snapshot)
             VALUES ('membership-request', $1, 1, 1, $2, $2, $3)",
            &[
                &request_id,
                &fingerprint,
                &json!({
                    "originatingPackage": OLD_PACKAGE,
                    "effects": [{
                        "id": "create-membership",
                        "operation": "create",
                        "target": {
                            "kind": "ReservedCreate",
                            "entityId": ENTITY,
                            "reservedRecordId": reserved_record_id.to_string()
                        },
                        "fieldChanges": [{
                            "field": "details",
                            "before": {"kind": "Missing"},
                            "after": {"kind": "Present", "value": {
                                "__bregEncryptedV1": "structured-plaintext-canary"
                            }}
                        }]
                    }]
                }),
            ],
        )
        .await
        .expect("orphan proposal inserts");
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_request_targets
                 (request_entity_id, request_id, proposal_version, target_entity_id,
                  target_record_id, operation, expected_revision, base_snapshot,
                  after_snapshot)
             VALUES ('membership-request', $1, 1, $2, $3, 'create', NULL, NULL, $4)",
            &[
                &request_id,
                &ENTITY,
                &reserved_record_id,
                &json!({"details": {
                    "__bregEncryptedV1": "structured-plaintext-canary"
                }}),
            ],
        )
        .await
        .expect("orphan create target inserts");
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_request_state
                 (request_entity_id, request_id, owner_reference, state,
                  proposal_version, workflow_revision)
             VALUES ('membership-request', $1, 'owner:hash', 'cancelled', 1, 1)",
            &[&guard_request_id],
        )
        .await
        .expect("guard-only request state inserts");
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_request_proposals
                 (request_entity_id, request_id, proposal_version, request_record_revision,
                  contract_fingerprint, effect_digest, snapshot)
             VALUES ('membership-request', $1, 1, 1, $2, $2, $3)",
            &[
                &guard_request_id,
                &fingerprint,
                &json!({
                    "originatingPackage": OLD_PACKAGE,
                    "effects": [],
                    "applicationPreconditions": {"targets": [{
                        "id": "guard-membership",
                        "entityId": ENTITY,
                        "recordId": guard_record_id.to_string(),
                        "expectedRevision": 1,
                        "values": {"details": "guard-plaintext-canary"}
                    }]}
                }),
            ],
        )
        .await
        .expect("guard-only proposal inserts");
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_request_state
                 (request_entity_id, request_id, owner_reference, state,
                  proposal_version, workflow_revision)
             VALUES ('membership-request', $1, 'owner:hash', 'draft', 1, 1)",
            &[&post_flip_request_id],
        )
        .await
        .expect("pre-flip draft request state inserts");
    insert_revision_snapshot(
        &transaction,
        "membership-request",
        post_flip_request_id,
        1,
        OLD_PACKAGE,
        &json!({"state": "draft"}),
    )
    .await;
    allocate_revision_commit(
        &transaction,
        CommitAllocation {
            package_revision: OLD_PACKAGE,
            origin: CommitOrigin::Mutation {
                actor_reference: "actor:hash",
                request_reference: "request:hash",
            },
            change_context: None,
            members: &[RevisionCommitMember {
                entity_id: "membership-request",
                record_id: post_flip_request_id,
                record_revision: 1,
            }],
        },
    )
    .await
    .expect("pre-flip draft revision commit allocates");
    transaction.commit().await.expect("orphan request commits");

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    insert_erase_field_flip(&transaction, "details").await;
    transaction.commit().await.expect("flip marker persists");

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    transaction
        .execute(
            "UPDATE registry_internal.registry_request_state
                SET state = 'submitted', workflow_revision = 2,
                    updated_at = transaction_timestamp()
              WHERE request_entity_id = 'membership-request' AND request_id = $1",
            &[&post_flip_request_id],
        )
        .await
        .expect("pre-flip draft submits after the flip");
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_request_proposals
                 (request_entity_id, request_id, proposal_version, request_record_revision,
                  contract_fingerprint, effect_digest, snapshot)
             VALUES ('membership-request', $1, 1, 1, $2, $2, $3)",
            &[
                &post_flip_request_id,
                &fingerprint,
                &json!({
                    "originatingPackage": CURRENT_PACKAGE,
                    "effects": [{
                        "id": "patch-membership",
                        "operation": "patch",
                        "target": {"kind": "Existing", "entityId": ENTITY,
                                   "recordId": post_flip_record_id.to_string()},
                        "fieldChanges": [{
                            "field": "household",
                            "before": {"kind": "Present", "value": "old"},
                            "after": {"kind": "Present", "value": "new"}
                        }]
                    }]
                }),
            ],
        )
        .await
        .expect("post-flip proposal inserts");
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_request_targets
                 (request_entity_id, request_id, proposal_version, target_entity_id,
                  target_record_id, operation, expected_revision, base_snapshot,
                  after_snapshot)
             VALUES ('membership-request', $1, 1, $2, $3, 'patch', 1, $4, $5)",
            &[
                &post_flip_request_id,
                &ENTITY,
                &post_flip_record_id,
                &json!({"household": "old", "details": {
                    "__bregEncryptedV1": "authenticated-post-flip-envelope"
                }}),
                &json!({"household": "new", "details": {
                    "__bregEncryptedV1": "authenticated-post-flip-envelope"
                }}),
            ],
        )
        .await
        .expect("post-flip target inserts");
    insert_revision_snapshot(
        &transaction,
        "membership-request",
        post_flip_request_id,
        2,
        CURRENT_PACKAGE,
        &json!({"state": "submitted"}),
    )
    .await;
    allocate_revision_commit(
        &transaction,
        CommitAllocation {
            package_revision: CURRENT_PACKAGE,
            origin: CommitOrigin::Mutation {
                actor_reference: "actor:hash",
                request_reference: "request:hash",
            },
            change_context: None,
            members: &[RevisionCommitMember {
                entity_id: "membership-request",
                record_id: post_flip_request_id,
                record_revision: 2,
            }],
        },
    )
    .await
    .expect("post-flip submission revision commit allocates");
    transaction
        .commit()
        .await
        .expect("post-flip request commits");
    let proposal_counts = migration
        .query_one(
            "SELECT
                 count(*) FILTER (WHERE snapshot ? 'details')::bigint,
                 count(*) FILTER (WHERE EXISTS (
                     SELECT 1
                       FROM jsonb_array_elements(
                                COALESCE(proposal.snapshot -> 'effects', '[]'::jsonb)
                            ) AS effect
                       CROSS JOIN LATERAL jsonb_array_elements(
                           COALESCE(effect -> 'fieldChanges', '[]'::jsonb)
                       ) AS field_change
                      WHERE effect -> 'target' ->> 'entityId' = $1
                        AND field_change ->> 'field' = 'details'
                 ))::bigint
               FROM registry_internal.registry_request_proposals AS proposal
              WHERE request_id = $2",
            &[&ENTITY, &request_id],
        )
        .await
        .expect("nested proposal field count resolves");
    assert_eq!(proposal_counts.get::<_, i64>(0), 0);
    assert_eq!(
        proposal_counts.get::<_, i64>(1),
        1,
        "the proposal count follows effects[].fieldChanges[], including an orphan create"
    );

    let outcome = erase_field_encryption_history(
        &mut migration,
        FieldEncryptionHistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit: &database.audit(audit_profile.clone()),
            operator_reference: "field-encryption-operator",
            reason: "destroy pre-flip request snapshots",
            registry: &registry,
        },
    )
    .await
    .expect("field-encryption erasure handles a request with no created revision");
    assert_eq!(outcome.erased_record_count, 0);
    assert_eq!(outcome.scrubbed_request_target_count, 1);
    assert_eq!(outcome.scrubbed_request_proposal_count, 2);

    let erased = migration
        .query_one(
            "SELECT
                 (SELECT snapshot IS NULL AND erased_at IS NOT NULL
                    FROM registry_internal.registry_request_proposals WHERE request_id = $1),
                 (SELECT base_snapshot IS NULL AND after_snapshot IS NULL AND erased_at IS NOT NULL
                    FROM registry_internal.registry_request_targets WHERE request_id = $1),
                 (SELECT snapshot IS NULL AND erased_at IS NOT NULL
                    FROM registry_internal.registry_request_proposals WHERE request_id = $2)",
            &[&request_id, &guard_request_id],
        )
        .await
        .expect("migration can inspect erased orphan snapshots");
    assert!(erased.get::<_, bool>(0));
    assert!(erased.get::<_, bool>(1));
    assert!(
        erased.get::<_, bool>(2),
        "a pre-flip application guard value is erased with its proposal snapshot"
    );
    let post_flip_preserved = migration
        .query_one(
            "SELECT
                 (SELECT snapshot IS NOT NULL AND erased_at IS NULL
                    FROM registry_internal.registry_request_proposals WHERE request_id = $1),
                 (SELECT base_snapshot IS NOT NULL AND after_snapshot IS NOT NULL
                         AND erased_at IS NULL
                    FROM registry_internal.registry_request_targets WHERE request_id = $1)",
            &[&post_flip_request_id],
        )
        .await
        .expect("post-flip request snapshots resolve");
    assert!(post_flip_preserved.get::<_, bool>(0));
    assert!(post_flip_preserved.get::<_, bool>(1));

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn field_encryption_erasure_uses_flip_provenance_for_structured_plaintext() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    let expected = install_ready_history_registry(&database, &mut migration, &registry).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).expect("lock key derives");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x78; 32].into())
        .expect("test owns a keyed audit profile");
    let record_id = Uuid::from_u128(0xEA51);
    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    insert_revision_snapshot(
        &transaction,
        ENTITY,
        record_id,
        1,
        OLD_PACKAGE,
        &json!({
            "person": "00000000-0000-4000-8000-000000000010",
            "household": "household-structured",
            "details": {"__bregEncryptedV1": "structured-plaintext-canary"},
            "valid-from": "2026-06-01",
            "valid-to": null
        }),
    )
    .await;
    allocate_revision_commit(
        &transaction,
        CommitAllocation {
            package_revision: OLD_PACKAGE,
            origin: CommitOrigin::Mutation {
                actor_reference: "actor:hash",
                request_reference: "request:hash",
            },
            change_context: None,
            members: &[RevisionCommitMember {
                entity_id: ENTITY,
                record_id,
                record_revision: 1,
            }],
        },
    )
    .await
    .expect("pre-flip revision commit allocates");
    transaction
        .commit()
        .await
        .expect("pre-flip history commits");

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    insert_erase_field_flip(&transaction, "details").await;
    transaction.commit().await.expect("flip marker persists");

    let outcome = erase_field_encryption_history(
        &mut migration,
        FieldEncryptionHistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit: &database.audit(audit_profile.clone()),
            operator_reference: "field-encryption-operator",
            reason: "erase structured pre-flip plaintext",
            registry: &registry,
        },
    )
    .await
    .expect("flip provenance erases a structured plaintext sentinel lookalike");
    assert_eq!(outcome.erased_record_count, 1);
    assert_eq!(outcome.erased_revision_count, 1);
    let retained: i64 = migration
        .query_one(
            "SELECT count(*)::bigint
               FROM registry_internal.registry_revisions
              WHERE entity_id = $1 AND record_id = $2",
            &[&ENTITY, &record_id],
        )
        .await
        .expect("retained revision count resolves")
        .get(0);
    assert_eq!(retained, 0);

    let unrelated_record_id = Uuid::from_u128(0xEA52);
    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    insert_revision_snapshot(
        &transaction,
        ENTITY,
        unrelated_record_id,
        1,
        CURRENT_PACKAGE,
        &json!({
            "person": "00000000-0000-4000-8000-000000000011",
            "household": "unrelated-generic-erasure",
            "valid-from": "2026-06-01",
            "valid-to": null
        }),
    )
    .await;
    allocate_revision_commit(
        &transaction,
        CommitAllocation {
            package_revision: CURRENT_PACKAGE,
            origin: CommitOrigin::Mutation {
                actor_reference: "actor:hash",
                request_reference: "request:hash",
            },
            change_context: None,
            members: &[RevisionCommitMember {
                entity_id: ENTITY,
                record_id: unrelated_record_id,
                record_revision: 1,
            }],
        },
    )
    .await
    .expect("unrelated revision commit allocates");
    transaction
        .commit()
        .await
        .expect("unrelated history commits");
    erase_record_history(
        &mut migration,
        HistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit: &database.audit(audit_profile.clone()),
            operator_reference: "generic-erasure-operator",
            reason: "unrelated generic erasure",
            target: RecordHistoryErasureTarget::new(ENTITY, unrelated_record_id, 1),
        },
    )
    .await
    .expect("unrelated generic erasure succeeds");

    let replay = erase_field_encryption_history(
        &mut migration,
        FieldEncryptionHistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit: &database.audit(audit_profile.clone()),
            operator_reference: "field-encryption-operator",
            reason: "must not repair unrelated coverage",
            registry: &registry,
        },
    )
    .await
    .expect_err("completed field lifecycle does not replay for generic coverage damage");
    assert_eq!(
        replay,
        FieldEncryptionHistoryErasureError::NoPendingPlaintextHistory
    );
    let replay_state = migration
        .query_one(
            "SELECT unavailable_after_position IS NOT NULL
               FROM registry_internal.registry_commit_head
              WHERE singleton",
            &[],
        )
        .await
        .expect("completed lifecycle replay state resolves");
    assert!(replay_state.get::<_, bool>(0));
    assert_eq!(field_encryption_terminal_entries(&database).len(), 1);

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn field_encryption_erasure_resumes_rebaseline_after_final_erase_crash() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    let expected = install_ready_history_registry(&database, &mut migration, &registry).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).expect("lock key derives");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x77; 32].into())
        .expect("test owns a keyed audit profile");
    let record_id = Uuid::from_u128(0xFA11);
    let request_id = Uuid::from_u128(0xFA12);
    let fingerprint = format!("sha256:{}", "8".repeat(64));
    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    insert_revision_snapshot(
        &transaction,
        ENTITY,
        record_id,
        1,
        OLD_PACKAGE,
        &json!({
            "person": "00000000-0000-4000-8000-000000000010",
            "household": "retry-count-plaintext",
            "valid-from": "2026-06-01",
            "valid-to": null
        }),
    )
    .await;
    allocate_revision_commit(
        &transaction,
        CommitAllocation {
            package_revision: OLD_PACKAGE,
            origin: CommitOrigin::Mutation {
                actor_reference: "actor:hash",
                request_reference: "request:hash",
            },
            change_context: None,
            members: &[RevisionCommitMember {
                entity_id: ENTITY,
                record_id,
                record_revision: 1,
            }],
        },
    )
    .await
    .expect("pre-flip record revision commit allocates");
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_request_state
                 (request_entity_id, request_id, owner_reference, state,
                  proposal_version, workflow_revision)
             VALUES ('membership-request', $1, 'owner:hash', 'cancelled', 1, 1)",
            &[&request_id],
        )
        .await
        .expect("retry request state inserts");
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_request_proposals
                 (request_entity_id, request_id, proposal_version, request_record_revision,
                  contract_fingerprint, effect_digest, snapshot)
             VALUES ('membership-request', $1, 1, 1, $2, $2, $3)",
            &[
                &request_id,
                &fingerprint,
                &json!({"originatingPackage": OLD_PACKAGE, "effects": [{
                    "id": "patch-membership",
                    "operation": "patch",
                    "target": {"kind": "Existing", "entityId": ENTITY,
                               "recordId": record_id.to_string()},
                    "fieldChanges": [{
                        "field": "household",
                        "before": {"kind": "Present", "value": "old"},
                        "after": {"kind": "Present", "value": "new"}
                    }]
                }]}),
            ],
        )
        .await
        .expect("retry proposal inserts");
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_request_targets
                 (request_entity_id, request_id, proposal_version, target_entity_id,
                  target_record_id, operation, expected_revision, base_snapshot,
                  after_snapshot)
             VALUES ('membership-request', $1, 1, $2, $3, 'patch', 1, $4, $5)",
            &[
                &request_id,
                &ENTITY,
                &record_id,
                &json!({"household": "old"}),
                &json!({"household": "new"}),
            ],
        )
        .await
        .expect("retry target inserts");
    transaction
        .execute(
            "UPDATE registry_internal.registry_commit_head
                SET coverage_ready = true,
                    unavailable_after_position = 0,
                    updated_at = transaction_timestamp()
              WHERE singleton",
            &[],
        )
        .await
        .expect("crash point leaves coverage incomplete");
    transaction.commit().await.expect("crash point persists");

    let without_flip = erase_field_encryption_history(
        &mut migration,
        FieldEncryptionHistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit: &database.audit(audit_profile.clone()),
            operator_reference: "field-encryption-operator",
            reason: "must not repair generic coverage",
            registry: &registry,
        },
    )
    .await
    .expect_err("generic incomplete coverage is not field-encryption work");
    assert_eq!(
        without_flip,
        FieldEncryptionHistoryErasureError::NoPendingPlaintextHistory
    );
    let still_incomplete: bool = migration
        .query_one(
            "SELECT unavailable_after_position IS NOT NULL
               FROM registry_internal.registry_commit_head WHERE singleton",
            &[],
        )
        .await
        .expect("coverage head remains readable")
        .get(0);
    assert!(still_incomplete);

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    insert_erase_field_flip(&transaction, "household").await;
    transaction.commit().await.expect("flip marker persists");

    // The destination refuses the lifecycle's request entry. It is appended
    // before the first scrub, so no request snapshot, record history,
    // lifecycle progress, or coverage changes.
    let entries_before_refusal = database.audit_entries().len();
    database.audit_capture().fail_after(0);
    let request_refusal = erase_field_encryption_history(
        &mut migration,
        FieldEncryptionHistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit: &database.audit(audit_profile.clone()),
            operator_reference: "field-encryption-operator",
            reason: "request audit precedes the first scrub",
            registry: &registry,
        },
    )
    .await
    .expect_err("a refused field request entry stops the lifecycle");
    database.audit_capture().restore();
    assert_eq!(
        request_refusal,
        FieldEncryptionHistoryErasureError::Unavailable
    );
    assert_eq!(database.audit_entries().len(), entries_before_refusal);
    let untouched = migration
        .query_one(
            "SELECT
                 (SELECT count(*) FROM registry_internal.registry_field_encryption_lifecycle_progress)::bigint,
                 (SELECT count(*) FROM registry_internal.registry_request_targets
                   WHERE erased_at IS NULL AND base_snapshot IS NOT NULL)::bigint,
                 (SELECT count(*) FROM registry_internal.registry_request_proposals
                   WHERE erased_at IS NULL AND snapshot IS NOT NULL)::bigint,
                 (SELECT count(*) FROM registry_internal.registry_revisions
                   WHERE erased_at IS NULL AND snapshot IS NOT NULL)::bigint,
                 (SELECT unavailable_after_position IS NOT NULL
                    FROM registry_internal.registry_commit_head WHERE singleton)",
            &[],
        )
        .await
        .expect("refused lifecycle state reads");
    assert_eq!(untouched.get::<_, i64>(0), 0);
    assert_eq!(untouched.get::<_, i64>(1), 1);
    assert_eq!(untouched.get::<_, i64>(2), 1);
    assert_eq!(untouched.get::<_, i64>(3), 1);
    assert!(untouched.get::<_, bool>(4));

    // The destination refuses the lifecycle's terminal entry. It is appended
    // after the closing commit, so the lifecycle answers an outage over
    // committed coverage: the documented crash gap, in which the closing
    // commit carries no terminal entry.
    database
        .audit_capture()
        .fail_on(FIELD_ENCRYPTION_AUDIT_SCHEMA, "terminal");
    let audit_failure = erase_field_encryption_history(
        &mut migration,
        FieldEncryptionHistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit: &database.audit(audit_profile.clone()),
            operator_reference: "field-encryption-operator",
            reason: "terminal audit follows the coverage commit",
            registry: &registry,
        },
    )
    .await
    .expect_err("a refused field terminal entry answers an outage");
    database.audit_capture().restore();
    assert_eq!(
        audit_failure,
        FieldEncryptionHistoryErasureError::Unavailable
    );
    assert!(
        field_encryption_terminal_entries(&database).is_empty(),
        "the refused terminal entry is not recorded"
    );
    let lifecycle_counts = migration
        .query_one(
            "SELECT
                 count(DISTINCT target_record_reference) FILTER (
                     WHERE progress_kind = 'record-erasure'
                 )::bigint,
                 COALESCE(sum(erased_revision_count) FILTER (
                     WHERE progress_kind = 'record-erasure'
                 ), 0)::bigint,
                 COALESCE(sum(scrubbed_request_target_count) FILTER (
                     WHERE progress_kind = 'request-scrub'
                 ), 0)::bigint,
                 COALESCE(sum(scrubbed_request_proposal_count) FILTER (
                     WHERE progress_kind = 'request-scrub'
                 ), 0)::bigint,
                 count(*) FILTER (WHERE progress_kind = 'terminal')::bigint
               FROM registry_internal.registry_field_encryption_lifecycle_progress",
            &[],
        )
        .await
        .expect("committed lifecycle progress resolves");
    assert_eq!(lifecycle_counts.get::<_, i64>(0), 1);
    assert_eq!(lifecycle_counts.get::<_, i64>(1), 1);
    assert_eq!(lifecycle_counts.get::<_, i64>(2), 1);
    assert_eq!(lifecycle_counts.get::<_, i64>(3), 1);
    assert_eq!(lifecycle_counts.get::<_, i64>(4), 1);
    let coverage_ready: bool = migration
        .query_one(
            "SELECT coverage_ready AND unavailable_after_position IS NULL
               FROM registry_internal.registry_commit_head WHERE singleton",
            &[],
        )
        .await
        .expect("coverage head remains readable")
        .get(0);
    assert!(coverage_ready);

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn erasure_uses_migration_authority_without_runtime_journal_mutation_grants() {
    let mut database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    let expected = install_ready_history_registry(&database, &mut migration, &registry).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).expect("lock key derives");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x72; 32].into())
        .expect("test owns a keyed audit profile");
    let record_id = Uuid::parse_str("018feaa0-68f9-4a45-b9e3-58436df07af8").unwrap();

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    insert_revision(&transaction, record_id, 1, CURRENT_PACKAGE, "create").await;
    allocate_revision_commit(
        &transaction,
        CommitAllocation {
            package_revision: CURRENT_PACKAGE,
            origin: CommitOrigin::Mutation {
                actor_reference: "actor:hash",
                request_reference: "request:hash",
            },
            change_context: None,
            members: &[RevisionCommitMember {
                entity_id: ENTITY,
                record_id,
                record_revision: 1,
            }],
        },
    )
    .await
    .expect("commit is indexed");
    transaction.commit().await.expect("history commits");

    let runtime_transaction = database
        .admin
        .transaction()
        .await
        .expect("admin can begin runtime-role inspection");
    runtime_transaction
        .batch_execute(&format!(
            "SET LOCAL ROLE \"{}\"",
            database.runtime_role.as_str()
        ))
        .await
        .expect("admin can inspect as runtime role");
    let runtime_privileges = runtime_transaction
        .query_one(
            "SELECT
                 has_table_privilege(current_user, 'registry_internal.registry_revisions', 'UPDATE'),
                 has_table_privilege(current_user, 'registry_internal.registry_revisions', 'DELETE'),
                 has_table_privilege(current_user, 'registry_internal.registry_revision_commits', 'UPDATE'),
                 has_table_privilege(current_user, 'registry_internal.registry_revision_commit_members', 'DELETE'),
                 has_table_privilege(current_user, 'registry_internal.registry_history_schemas', 'DELETE')",
            &[],
        )
        .await
        .expect("runtime can inspect its own privileges");
    for index in 0..5 {
        assert!(!runtime_privileges.get::<_, bool>(index));
    }
    assert!(
        runtime_transaction
            .execute(
                "DELETE FROM registry_internal.registry_revisions
                  WHERE entity_id = 'membership'",
                &[],
            )
            .await
            .is_err(),
        "runtime cannot perform the erasure journal delete"
    );
    runtime_transaction
        .rollback()
        .await
        .expect("runtime-role inspection rolls back");

    erase_record_history(
        &mut migration,
        HistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit: &database.audit(audit_profile.clone()),
            operator_reference: "operator-run-2",
            reason: "test retention request",
            target: RecordHistoryErasureTarget::new(ENTITY, record_id, 1),
        },
    )
    .await
    .expect("migration authority can run the bounded erasure");

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn erasing_baseline_member_marks_all_history_coverage_unready_and_allows_later_erasure() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    let expected = install_ready_history_registry(&database, &mut migration, &registry).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).expect("lock key derives");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x73; 32].into())
        .expect("test owns a keyed audit profile");
    let record_id = Uuid::parse_str("018feaa0-68f9-4a45-b9e3-58436df07af9").unwrap();

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    insert_revision(&transaction, record_id, 1, OLD_PACKAGE, "migration").await;
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_revision_commit_members
                 (commit_position, member_index, entity_id, record_id, record_revision)
             VALUES (0, 0, $1, $2, 1)",
            &[&ENTITY, &record_id],
        )
        .await
        .expect("baseline member inserts");
    transaction.commit().await.expect("baseline member commits");

    let outcome = erase_record_history(
        &mut migration,
        HistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit: &database.audit(audit_profile.clone()),
            operator_reference: "operator-run-3",
            reason: "baseline retention request",
            target: RecordHistoryErasureTarget::new(ENTITY, record_id, 1),
        },
    )
    .await
    .expect("baseline-member erasure succeeds");
    assert!(!outcome.coverage_ready);
    assert_eq!(outcome.unavailable_after_position, None);
    assert_eq!(outcome.affected_commit_count, 1);
    assert_eq!(outcome.erased_revision_count, 1);

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    let baseline_uuid: Uuid = transaction
        .query_one(
            "SELECT snapshot_reference
               FROM registry_internal.registry_revision_commits
              WHERE commit_position = 0",
            &[],
        )
        .await
        .expect("baseline reference remains stored")
        .get(0);
    assert_eq!(
        resolve_snapshot_reference(&transaction, SnapshotReference::for_uuid(baseline_uuid)).await,
        Err(HistoryCommitError::Unavailable),
        "coverage_ready=false refuses every exact bookmark after a baseline erasure"
    );
    insert_revision(&transaction, record_id, 2, CURRENT_PACKAGE, "patch").await;
    allocate_revision_commit(
        &transaction,
        CommitAllocation {
            package_revision: CURRENT_PACKAGE,
            origin: CommitOrigin::Mutation {
                actor_reference: "actor:hash",
                request_reference: "request:hash",
            },
            change_context: None,
            members: &[RevisionCommitMember {
                entity_id: ENTITY,
                record_id,
                record_revision: 2,
            }],
        },
    )
    .await
    .expect("future write can still allocate a commit");
    transaction.commit().await.expect("future commit persists");

    let follow_up = erase_record_history(
        &mut migration,
        HistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit: &database.audit(audit_profile.clone()),
            operator_reference: "operator-run-3",
            reason: "follow-up retention request",
            target: RecordHistoryErasureTarget::new(ENTITY, record_id, 2),
        },
    )
    .await
    .expect("further erasure succeeds while coverage is unready");
    assert!(!follow_up.coverage_ready);
    assert_eq!(follow_up.erased_revision_count, 1);

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prebaseline_unindexed_revision_is_erased_and_marks_coverage_unready() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    let expected = install_ready_history_registry(&database, &mut migration, &registry).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).expect("lock key derives");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x74; 32].into())
        .expect("test owns a keyed audit profile");
    let record_id = Uuid::parse_str("018feaa0-68f9-4a45-b9e3-58436df07afa").unwrap();

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    insert_revision(&transaction, record_id, 1, OLD_PACKAGE, "migration").await;
    transaction
        .commit()
        .await
        .expect("unindexed revision commits");

    let outcome = erase_record_history(
        &mut migration,
        HistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit: &database.audit(audit_profile.clone()),
            operator_reference: "operator-run-4",
            reason: "prebaseline retention request",
            target: RecordHistoryErasureTarget::new(ENTITY, record_id, 1),
        },
    )
    .await
    .expect("unindexed prebaseline erasure succeeds");
    assert!(!outcome.coverage_ready);
    assert_eq!(outcome.unavailable_after_position, None);
    assert_eq!(outcome.affected_commit_count, 0);
    assert_eq!(outcome.erased_revision_count, 1);

    migration_task.abort();
    database.cleanup().await;
}

/// A standalone erasure appends its request entry before its transaction
/// opens: a writer that refuses that entry answers an outage and deletes,
/// scrubs, and narrows nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn erasure_changes_nothing_when_the_audit_writer_refuses_its_request_entry() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    let expected = install_ready_history_registry(&database, &mut migration, &registry).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).expect("lock key derives");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x75; 32].into())
        .expect("test owns a keyed audit profile");
    let record_id = Uuid::parse_str("018feaa0-68f9-4a45-b9e3-58436df07afb").unwrap();

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    insert_revision(&transaction, record_id, 1, OLD_PACKAGE, "migration").await;
    transaction.commit().await.expect("revision commits");
    let coverage_before: (bool, Option<i64>) = {
        let row = migration
            .query_one(
                "SELECT coverage_ready, unavailable_after_position
                   FROM registry_internal.registry_commit_head WHERE singleton",
                &[],
            )
            .await
            .expect("coverage head reads");
        (row.get(0), row.get(1))
    };

    database.audit_capture().fail_after(0);
    let refused = erase_record_history(
        &mut migration,
        HistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit: &database.audit(audit_profile.clone()),
            operator_reference: "operator-run-refused",
            reason: "refused retention request",
            target: RecordHistoryErasureTarget::new(ENTITY, record_id, 1),
        },
    )
    .await
    .expect_err("a refused request entry refuses the erasure");
    database.audit_capture().restore();
    assert_eq!(refused, HistoryErasureError::Unavailable);

    let retained: i64 = migration
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_revisions
              WHERE entity_id = $1 AND record_id = $2",
            &[&ENTITY, &record_id],
        )
        .await
        .expect("retained revisions count")
        .get(0);
    assert_eq!(retained, 1);
    let coverage_after: (bool, Option<i64>) = {
        let row = migration
            .query_one(
                "SELECT coverage_ready, unavailable_after_position
                   FROM registry_internal.registry_commit_head WHERE singleton",
                &[],
            )
            .await
            .expect("coverage head reads");
        (row.get(0), row.get(1))
    };
    assert_eq!(coverage_after, coverage_before);
    assert!(database.audit_entries().is_empty());

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sparse_high_revision_number_erases_when_actual_target_count_is_bounded() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    let expected = install_ready_history_registry(&database, &mut migration, &registry).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).expect("lock key derives");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x75; 32].into())
        .expect("test owns a keyed audit profile");
    let record_id = Uuid::parse_str("018feaa0-68f9-4a45-b9e3-58436df07afb").unwrap();

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    insert_revision(&transaction, record_id, 10_001, OLD_PACKAGE, "migration").await;
    transaction
        .commit()
        .await
        .expect("sparse high revision commits");

    let outcome = erase_record_history(
        &mut migration,
        HistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit: &database.audit(audit_profile.clone()),
            operator_reference: "operator-run-5",
            reason: "sparse high revision request",
            target: RecordHistoryErasureTarget::new(ENTITY, record_id, 10_001),
        },
    )
    .await
    .expect("sparse high revision erasure succeeds");
    assert!(!outcome.coverage_ready);
    assert_eq!(outcome.erased_revision_count, 1);

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn erasure_refuses_more_than_ten_thousand_actual_target_revisions() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    let expected = install_ready_history_registry(&database, &mut migration, &registry).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).expect("lock key derives");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x76; 32].into())
        .expect("test owns a keyed audit profile");
    let record_id = Uuid::parse_str("018feaa0-68f9-4a45-b9e3-58436df07afc").unwrap();

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    insert_revision_range(&transaction, record_id, 10_001).await;
    transaction
        .commit()
        .await
        .expect("large retained revision set commits");

    let result = erase_record_history(
        &mut migration,
        HistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit: &database.audit(audit_profile.clone()),
            operator_reference: "operator-run-6",
            reason: "oversized actual revision request",
            target: RecordHistoryErasureTarget::new(ENTITY, record_id, 10_001),
        },
    )
    .await;
    assert_eq!(
        result,
        Err(registry_breg::history_erasure::HistoryErasureError::InvalidInput)
    );
    let remaining: i64 = migration
        .query_one(
            "SELECT count(*)::bigint
               FROM registry_internal.registry_revisions
              WHERE entity_id = $1
                AND record_id = $2",
            &[&ENTITY, &record_id],
        )
        .await
        .expect("migration can inspect retained revisions")
        .get(0);
    assert_eq!(remaining, 10_001);

    migration_task.abort();
    database.cleanup().await;
}

/// The field-encryption lifecycle composes the generic 10,000-revision
/// transaction bound instead of inheriting its refusal. The flipped member is
/// deliberately sparse at revision 10,001: choosing a chunk boundary by
/// matching revisions alone would still hand all 10,001 retained revisions to
/// the first generic erasure transaction.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn field_encryption_erasure_chunks_sparse_oversized_record_history() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    let expected = install_ready_history_registry(&database, &mut migration, &registry).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).expect("lock key derives");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x79; 32].into())
        .expect("test owns a keyed audit profile");
    let record_id = Uuid::parse_str("018feaa0-68f9-4a45-b9e3-58436df07afe").unwrap();

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    insert_revision_range(&transaction, record_id, 10_001).await;
    let final_snapshot = registry_platform_canonical_json::canonicalize_json(&json!({
        "person": "00000000-0000-4000-8000-000000000010",
        "household": "household-bulk",
        "details": "sparse-plaintext-canary",
        "valid-from": "2026-06-01",
        "valid-to": null
    }))
    .expect("sparse final snapshot canonicalizes");
    transaction
        .execute(
            "UPDATE registry_internal.registry_revisions
                SET snapshot = $1
              WHERE entity_id = $2
                AND record_id = $3
                AND record_revision = 10001",
            &[&final_snapshot, &ENTITY, &record_id],
        )
        .await
        .expect("sparse flipped member inserts");
    insert_erase_field_flip(&transaction, "details").await;
    transaction
        .commit()
        .await
        .expect("oversized sparse history commits");

    let outcome = erase_field_encryption_history(
        &mut migration,
        FieldEncryptionHistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(30), Duration::from_secs(30))
                .unwrap(),
            audit: &database.audit(audit_profile.clone()),
            operator_reference: "field-encryption-operator",
            reason: "erase oversized sparse pre-flip history",
            registry: &registry,
        },
    )
    .await
    .expect("field-encryption erasure chunks an oversized record");
    assert_eq!(outcome.erased_record_count, 1);
    assert_eq!(outcome.erased_revision_count, 10_001);

    let state = migration
        .query_one(
            "SELECT count(*)::bigint
               FROM registry_internal.registry_revisions
              WHERE entity_id = $1 AND record_id = $2",
            &[&ENTITY, &record_id],
        )
        .await
        .expect("chunked erasure state resolves");
    assert_eq!(state.get::<_, i64>(0), 0);
    assert_eq!(
        database
            .audit_entries()
            .iter()
            .filter(|entry| {
                entry["schema"] == HISTORY_ERASURE_AUDIT_SCHEMA
                    && !entry["record"]["lifecycleReference"].is_null()
            })
            .count(),
        2,
        "the lifecycle uses two bounded generic erasure transactions"
    );

    migration_task.abort();
    database.cleanup().await;
}

/// A cached batch response whose stored bytes are not readable JSON refuses
/// the erasure as the corruption it is. Reporting it as storage unavailability
/// would hide the unreadable row behind an outage an operator would retry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn erasure_reports_an_unreadable_cached_response_rather_than_an_outage() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    let expected = install_ready_history_registry(&database, &mut migration, &registry).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).expect("lock key derives");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x77; 32].into())
        .expect("test owns a keyed audit profile");
    let record_id = Uuid::parse_str("018feaa0-68f9-4a45-b9e3-58436df07afd").unwrap();

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    insert_revision(&transaction, record_id, 1, CURRENT_PACKAGE, "create").await;
    transaction.commit().await.expect("target revision commits");

    // The two ways stored bytes stop being readable: a sequence no UTF-8
    // decoder accepts, and text that decodes but is not JSON.
    for body in [
        vec![0xf0_u8, 0x28, 0x8c, 0x28],
        b"{\"unterminated\"".to_vec(),
    ] {
        let transaction = migration
            .transaction()
            .await
            .expect("migration can begin transaction");
        transaction
            .execute("DELETE FROM registry_internal.registry_idempotency", &[])
            .await
            .expect("test can replace the cached response");
        insert_idempotency_response_bytes(
            &transaction,
            "batch-unreadable-key",
            "batch-unreadable-binding",
            &body,
        )
        .await;
        transaction
            .commit()
            .await
            .expect("unreadable cached response commits");

        let logs = CapturedOperationalLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_current_span(false)
            .with_span_list(false)
            .with_writer(logs.clone())
            .finish();
        let result = erase_record_history(
            &mut migration,
            HistoryErasureRequest {
                expected: &expected,
                migration_role: &database.migration_role,
                lock_key,
                timeouts: HistoryErasureTimeouts::new(
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                )
                .unwrap(),
                audit: &database.audit(audit_profile.clone()),
                operator_reference: OPERATOR_CANARY,
                reason: REASON_CANARY,
                target: RecordHistoryErasureTarget::new(ENTITY, record_id, 1),
            },
        )
        .with_subscriber(subscriber)
        .await;
        assert_eq!(
            result,
            Err(registry_breg::history_erasure::HistoryErasureError::CachedResponseUnreadable),
            "an unreadable cached response is reported as corruption"
        );

        // The operator sees the classification, because every read surface
        // answers the refusal it always answered. The record names the reader
        // and nothing about the row it read.
        let captured = logs.text();
        let records = captured
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("operational log is JSON"))
            .collect::<Vec<_>>();
        assert_eq!(
            records.len(),
            1,
            "the classified failure logs exactly one record"
        );
        assert_eq!(records[0]["level"], "WARN");
        assert_eq!(records[0]["target"], "registry_breg::storage");
        let fields = records[0]["fields"]
            .as_object()
            .expect("operational fields are an object");
        assert_eq!(
            fields.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            BTreeSet::from(["message", "reader"])
        );
        assert_eq!(fields["message"], "stored bytes are unreadable as JSON");
        assert_eq!(fields["reader"], "idempotency_cache");
        for forbidden in [
            record_id.to_string().as_str(),
            ENTITY,
            "batch-unreadable-key",
            "batch-unreadable-binding",
            "unterminated",
            "registry_idempotency",
            "convert_from",
            OPERATOR_CANARY,
            REASON_CANARY,
        ] {
            assert!(
                !captured.contains(forbidden),
                "the classification log carries nothing about the row it read"
            );
        }
    }

    migration_task.abort();
    database.cleanup().await;
}

/// Collect the operational log a call emits, so a test can assert on the
/// rendered record instead of letting it print.
#[derive(Clone, Default)]
struct CapturedOperationalLogs(Arc<Mutex<Vec<u8>>>);

impl CapturedOperationalLogs {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("operational log buffer").clone())
            .expect("operational logs are UTF-8")
    }
}

impl io::Write for CapturedOperationalLogs {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("operational log buffer poisoned"))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for CapturedOperationalLogs {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

async fn install_ready_history_registry(
    database: &TestDatabase,
    migration: &mut tokio_postgres::Client,
    registry: &registry_breg::CompiledRegistry,
) -> ExpectedRegistryIdentity {
    install_compiled_schema(migration, registry, &database.runtime_role)
        .await
        .expect("compiled schema installs");
    retain_descriptor(migration, registry, OLD_PACKAGE)
        .await
        .expect("old descriptor is retained");
    retain_descriptor(migration, registry, CURRENT_PACKAGE)
        .await
        .expect("current descriptor is retained");
    install_mutation_schema(migration, &database.runtime_role, false)
        .await
        .expect("mutation and history commit schema are installed");
    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    install_empty_history_baseline(&transaction, CURRENT_PACKAGE)
        .await
        .expect("empty baseline installs");
    transaction.commit().await.expect("baseline commits");

    let expected_catalog = ExpectedManagedCatalog::compiled(registry);
    let schema_fingerprint =
        managed_schema_fingerprint(migration, &database.runtime_role, &expected_catalog)
            .await
            .expect("managed schema fingerprint resolves");
    let expected = ExpectedRegistryIdentity {
        package_id: registry.registry_id().to_owned(),
        environment: "local".to_owned(),
        instance_id: "history-erasure-test".to_owned(),
        database_id: "history-erasure-db".to_owned(),
        package_revision: CURRENT_PACKAGE.to_owned(),
        schema_fingerprint,
        package_sequence: 3,
    };
    migration
        .execute(
            "INSERT INTO registry_internal.registry_state (
                 singleton, package_id, environment, instance_id, database_id,
                 active_package_revision, schema_fingerprint, package_sequence,
                 maintenance_status
             ) VALUES (true, $1, $2, $3, $4, $5, $6, $7, 'ready')",
            &[
                &expected.package_id,
                &expected.environment,
                &expected.instance_id,
                &expected.database_id,
                &expected.package_revision,
                &expected.schema_fingerprint,
                &expected.package_sequence,
            ],
        )
        .await
        .expect("registry state installs");
    expected
}

async fn insert_revision(
    transaction: &tokio_postgres::Transaction<'_>,
    record_id: Uuid,
    revision: i64,
    package_revision: &str,
    mutation_kind: &str,
) {
    let snapshot = json!({
        "person": "00000000-0000-4000-8000-000000000010",
        "household": format!("household-{revision}"),
        "valid-from": "2026-06-01",
        "valid-to": null
    });
    let snapshot = registry_platform_canonical_json::canonicalize_json(&snapshot)
        .expect("snapshot canonicalizes");
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_revisions
                 (entity_id, record_id, record_reference, record_revision,
                  predecessor_revision, record_lifecycle, package_revision, operation_id,
                  mutation_kind, principal_reference, request_reference, snapshot)
             VALUES ($1, $2, $3, $4, $5, 'active', $6, 'op-1',
                     $7, 'actor:hash', 'request:hash', $8)",
            &[
                &ENTITY,
                &record_id,
                &format!("{ENTITY}:{record_id}"),
                &revision,
                &(revision > 1).then_some(revision - 1),
                &package_revision,
                &mutation_kind,
                &snapshot,
            ],
        )
        .await
        .expect("test revision inserts");
}

async fn insert_revision_snapshot(
    transaction: &tokio_postgres::Transaction<'_>,
    entity_id: &str,
    record_id: Uuid,
    revision: i64,
    package_revision: &str,
    snapshot: &Value,
) {
    let snapshot = registry_platform_canonical_json::canonicalize_json(snapshot)
        .expect("snapshot canonicalizes");
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_revisions
                 (entity_id, record_id, record_reference, record_revision,
                  predecessor_revision, record_lifecycle, package_revision, operation_id,
                  mutation_kind, principal_reference, request_reference, snapshot)
             VALUES ($1, $2, $3, $4, $5, 'active', $6, 'op-structured',
                     'create', 'actor:hash', 'request:hash', $7)",
            &[
                &entity_id,
                &record_id,
                &format!("{entity_id}:{record_id}"),
                &revision,
                &(revision > 1).then_some(revision - 1),
                &package_revision,
                &snapshot,
            ],
        )
        .await
        .expect("test revision snapshot inserts");
}

async fn insert_erase_field_flip(transaction: &tokio_postgres::Transaction<'_>, field_id: &str) {
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_migrations
                 (target_package_revision, source_package_revision, package_sequence,
                  plan_kind, statement_checksums, artifact_paths, artifact_checksums,
                  outcome, completed_at)
             VALUES ($1, $2, 1, 'metadata_only', ARRAY[]::text[], ARRAY[]::text[],
                     ARRAY[]::text[], 'applied', transaction_timestamp()),
                    ($3, $1, 3, 'metadata_only', ARRAY[]::text[], ARRAY[]::text[],
                     ARRAY[]::text[], 'applied', transaction_timestamp())
             ON CONFLICT (target_package_revision) DO NOTHING",
            &[&MIDDLE_PACKAGE, &OLD_PACKAGE, &CURRENT_PACKAGE],
        )
        .await
        .expect("field-encryption boundary ledger row inserts");
    let history_commit_position = transaction
        .query_one(
            "SELECT latest_position + 1
               FROM registry_internal.registry_commit_head
              WHERE singleton",
            &[],
        )
        .await
        .expect("history cutoff resolves")
        .get::<_, i64>(0);
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_field_encryption_flips
                 (entity_id, field_id, boundary_package_revision, history_choice,
                  history_commit_position,
                  sealed_row_count, sealed_journal_row_count,
                  accepted_plaintext_journal_row_count,
                  accepted_request_target_row_count,
                  accepted_request_proposal_row_count,
                  accepted_idempotency_row_count, accepted_outbox_row_count)
             VALUES ($1, $2, $3, 'erase-and-rebaseline', $4, 0, 0, 0, 0, 0, 0, 0)",
            &[
                &ENTITY,
                &field_id,
                &CURRENT_PACKAGE,
                &history_commit_position,
            ],
        )
        .await
        .expect("field-encryption flip inserts");
}

async fn insert_revision_range(
    transaction: &tokio_postgres::Transaction<'_>,
    record_id: Uuid,
    count: i64,
) {
    let snapshot = json!({
        "person": "00000000-0000-4000-8000-000000000010",
        "household": "household-bulk",
        "valid-from": "2026-06-01",
        "valid-to": null
    });
    let snapshot = registry_platform_canonical_json::canonicalize_json(&snapshot)
        .expect("snapshot canonicalizes");
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_revisions
                 (entity_id, record_id, record_reference, record_revision,
                  predecessor_revision, record_lifecycle, package_revision, operation_id,
                  mutation_kind, principal_reference, request_reference, snapshot)
             SELECT $1, $2, $3, revision,
                    CASE WHEN revision > 1 THEN revision - 1 ELSE NULL END,
                    'active', $4, 'op-1', 'migration', 'actor:hash',
                    'request:hash', $5
               FROM generate_series(1::bigint, $6::bigint) AS revision",
            &[
                &ENTITY,
                &record_id,
                &format!("{ENTITY}:{record_id}"),
                &OLD_PACKAGE,
                &snapshot,
                &count,
            ],
        )
        .await
        .expect("bulk revisions insert");
}

async fn insert_outbox_payload(
    transaction: &tokio_postgres::Transaction<'_>,
    record_id: Uuid,
    revision: i64,
) {
    let payload = b"payload-canary".as_slice();
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_outbox
                 (event_id, event_type, trigger, entity_id, record_reference,
                  record_revision, package_revision, schema_fingerprint, payload,
                  payload_expires_at)
             VALUES ($1, 'membership.changed', 'created', $2, $3, $4,
                     $5, 'schema:hash', $6, transaction_timestamp() + interval '7 days')",
            &[
                &Uuid::new_v4(),
                &ENTITY,
                &format!("{ENTITY}:{record_id}"),
                &revision,
                &OLD_PACKAGE,
                &payload,
            ],
        )
        .await
        .expect("test outbox payload inserts");
}

// Test fixture construction mirrors the stored row shape explicitly.
#[allow(clippy::too_many_arguments)]
async fn insert_idempotency_response(
    transaction: &tokio_postgres::Transaction<'_>,
    key_reference: &str,
    binding_reference: &str,
    result_kind: &str,
    record_reference: Option<&str>,
    record_revision: Option<i64>,
    result_count: Option<i16>,
    body: serde_json::Value,
) {
    let body =
        registry_platform_canonical_json::canonicalize_json(&body).expect("body canonicalizes");
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_idempotency
                 (key_reference, binding_reference, result_kind, record_reference,
                  record_revision, result_count, response_status, response_body,
                  response_headers)
             VALUES ($1, $2, $3, $4, $5, $6, 200, $7, $8)",
            &[
                &key_reference,
                &binding_reference,
                &result_kind,
                &record_reference,
                &record_revision,
                &result_count,
                &body,
                &vec![0_u8, 0_u8],
            ],
        )
        .await
        .expect("idempotency response inserts");
}

/// A cached response stored exactly as supplied, so a test can place bytes the
/// stored-JSON reader cannot accept.
async fn insert_idempotency_response_bytes(
    transaction: &tokio_postgres::Transaction<'_>,
    key_reference: &str,
    binding_reference: &str,
    body: &[u8],
) {
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_idempotency
                 (key_reference, binding_reference, result_kind, record_reference,
                  record_revision, result_count, response_status, response_body,
                  response_headers)
             VALUES ($1, $2, 'batch', NULL, NULL, 1, 200, $3, $4)",
            &[&key_reference, &binding_reference, &body, &vec![0_u8, 0_u8]],
        )
        .await
        .expect("idempotency response inserts");
}

fn field_encryption_terminal_entries(database: &TestDatabase) -> Vec<serde_json::Value> {
    database
        .audit_entries()
        .into_iter()
        .filter(|entry| {
            entry["schema"] == FIELD_ENCRYPTION_AUDIT_SCHEMA
                && entry["record"]["phase"] == "terminal"
        })
        .collect()
}

/// An erasure writes one request entry before its transaction and one
/// response entry after its commit, under one correlation, and neither
/// carries an erased value, reason, or operator.
fn assert_erasure_audit_is_minimized(database: &TestDatabase) {
    let entries = database.audit_entries();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["schema"], HISTORY_ERASURE_AUDIT_SCHEMA);
    assert_eq!(entries[0]["phase"], "request");
    assert_eq!(entries[0]["record"]["phase"], "attempt");
    assert_eq!(entries[1]["schema"], HISTORY_ERASURE_AUDIT_SCHEMA);
    assert_eq!(entries[1]["phase"], "response");
    assert_eq!(entries[0]["correlation"], entries[1]["correlation"]);
    assert_eq!(
        entries[0]["record"]["targetReference"],
        entries[1]["record"]["targetReference"]
    );
    let audit_text = serde_json::Value::Array(entries).to_string();
    assert!(audit_text.contains("history-erasure-maintenance"));
    assert!(audit_text.contains("saved_exports_event_consumers_and_backups"));
    assert!(!audit_text.contains(RECORD_CANARY));
    assert!(!audit_text.contains(REASON_CANARY));
    assert!(!audit_text.contains(OPERATOR_CANARY));
    assert!(!audit_text.contains("case-document:erasure-proof"));
}

async fn snapshot_client_http(
    database: &TestDatabase,
    key_store: &tokio_postgres::Client,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: ExpectedRegistryIdentity,
    audit: registry_breg::audit::RegistryAudit,
) -> client_http::ClientHttp {
    use registry_breg::api::{HttpService, ReadRuntimeIdentity};
    use registry_breg::cursor::CursorCodec;
    use registry_breg::field_encryption::{FieldEncryptionProvider, FieldEncryptionService};
    use registry_breg::postgres::{PostgresRecordReadService, PostgresSnapshotReadService};
    use registry_platform_config::{SecretProvider, SecretReference, SecretResolver};

    let pool = database
        .runtime_config
        .build_pool()
        .expect("runtime pool builds after history erasure");
    let secret_root = tempfile::tempdir().expect("field-encryption secret root creates");
    let dek_path = secret_root.path().join("field-dek");
    std::fs::write(
        &dek_path,
        base64::engine::general_purpose::STANDARD.encode([0x42_u8; 32]),
    )
    .expect("field-encryption data key writes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&dek_path, std::fs::Permissions::from_mode(0o600))
            .expect("field-encryption data key is owner-only");
    }
    let dek_ref = SecretReference::parse("secret:file/field-dek")
        .expect("field-encryption key reference parses");
    let secrets = SecretResolver::new([SecretProvider::File], secret_root.path())
        .expect("field-encryption secret resolver builds");
    let field_encryption = Arc::new(
        FieldEncryptionService::activate(
            &FieldEncryptionProvider::LocalFile { dek_ref },
            registry.registry_id(),
            &identity.package_revision,
            &secrets,
            key_store,
        )
        .await
        .expect("local field-encryption key state activates"),
    );
    let lock_key = RegistryLockKey::derive(registry.registry_id()).unwrap();
    let cursors = Arc::new(
        CursorCodec::new(
            zeroize::Zeroizing::new(vec![0x5b; 32]),
            Duration::from_secs(300),
        )
        .unwrap(),
    );
    let records = PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit.clone(),
        cursors.clone(),
    )
    .with_field_encryption(Arc::clone(&field_encryption));
    let snapshots = PostgresSnapshotReadService::new(
        pool,
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit,
        cursors.clone(),
    )
    .with_field_encryption(Arc::clone(&field_encryption));
    let service = HttpService::new(
        registry,
        ReadRuntimeIdentity {
            package_revision: identity.package_revision,
            schema_fingerprint: identity.schema_fingerprint,
        },
        Arc::new(records),
        Arc::new(SnapshotReady),
        cursors,
    )
    .with_snapshots(Arc::new(snapshots))
    .with_field_encryption(field_encryption);
    let claims = registry_breg::api::VerifiedRequestClaims::authenticated(
        "registry_principal",
        "history-erasure-sdk-reader",
        BTreeSet::new(),
        Some("operations".to_owned()),
        BTreeMap::new(),
    )
    .unwrap();
    client_http::ClientHttp::start(registry_breg::api::router(Arc::new(service)), claims).await
}

struct SnapshotReady;

impl registry_breg::api::ReadinessProbe for SnapshotReady {
    fn is_ready(&self) -> registry_breg::api::ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

fn compiled_registry() -> registry_breg::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"history-erasure-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[{
            "id":"membership",
            "primaryDataset":"test-dataset",
            "route":"memberships",
            "mutationMode":"mutable",
            "tombstone":true,
            "classification":"restricted",
            "fields":[
              {"id":"person","type":"uuid","required":true,"classification":"internal"},
              {"id":"household","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
              {"id":"details","type":"structured","maxBytes":256,"required":false,"classification":"restricted","encrypted":true,"schema":{"type":"object","additionalProperties":false,"properties":{"__bregEncryptedV1":{"type":"string"}},"required":["__bregEncryptedV1"]}},
              {"id":"valid-from","type":"date","required":true,"classification":"internal"},
              {"id":"valid-to","type":"date","required":false,"classification":"internal"}
            ],
            "temporal":{"startField":"valid-from","endField":"valid-to"}
          }],
          "accessProfiles":[{
            "id":"writer",
            "default":true,
            "principalClaim":"registry_principal",
            "requiredPurposes":["operations"],
            "permissions":[{
              "entity":"membership",
              "operations":["create","get","list","patch","snapshot"],
              "readableFields":["person","household","details","valid-from","valid-to"],
              "writableFields":["person","household","details","valid-from","valid-to"],
              "rowBoundaries": []
            }]
          }]
        }"#,
    )
    .unwrap();
    compile_project(&project, &[], CompileProfile::Authoring).expect("fixture compiles")
}
