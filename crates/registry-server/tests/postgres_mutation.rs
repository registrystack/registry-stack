// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{HeaderName, HeaderValue, Method, Request, StatusCode};
use postgres_harness::TestDatabase;
use registry_platform_audit::{verify_jsonl_lines_with_hasher, AuditEnvelope, AuditProfile};
use registry_server::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedClaimValue,
    VerifiedRequestClaims,
};
use registry_server::compiler::{compile_project, CompileProfile};
use registry_server::contract::{parse_project_json, Operation};
use registry_server::cursor::CursorCodec;
use registry_server::idempotency::PermittedResponseHeader;
use registry_server::mutation::{
    MutationBody, MutationCoordinator, MutationError, MutationFaultPoint, MutationOutcome,
    MutationPlan, MutationRequest, PatchOperation,
};
use registry_server::postgres::{
    initialize_registry_state_for_catalog_test, install_compiled_schema, ClaimContext,
    ExpectedManagedCatalog, PostgresRecordMutationService, PostgresRecordReadService,
    RegistryLockKey, RegistryStateTestIdentity, RowBoundaryContext,
};
use serde_json::{json, Map, Value};
use tower::Service as _;
use uuid::Uuid;
use zeroize::Zeroizing;

const PRINCIPAL_CANARY: &str = "principal-value-must-not-enter-journals";
const PACKAGE_ID: &str = "mutation-registry";
const INSTANCE_ID: &str = "mutation-instance";
const DATABASE_ID: &str = "mutation-database";
const RECORD_POSITIVE: &str = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAA0101";
const RECORD_PATCH: &str = "00000000-0000-0000-0000-000000000102";
const RECORD_RECOVERY: &str = "00000000-0000-0000-0000-000000000103";
const RECORD_CONCURRENT: &str = "00000000-0000-0000-0000-000000000104";
const RS_SEC_13_PRINCIPAL_CANARY: &str = "rs-sec-13-principal-canary";
const RS_SEC_13_TOKEN_CANARY: &str = "rs-sec-13-raw-token-canary";
const RS_SEC_13_CREDENTIAL_CANARY: &str = "rs-sec-13-credential-canary";
const RS_SEC_13_IDEMPOTENCY_CANARY: &str = "rs-sec-13-idempotency-key-conflict";
const RS_SEC_13_ZONE_CANARY: &str = "rs-sec-13-zone-a";
const RS_SEC_13_LABEL_CANARY: &str = "rs-sec-13-unique-label";
const RS_SEC_13_QUANTITY_CANARY: &str = "4242";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_mutation_is_audited_atomic_typed_and_exactly_replayable() {
    let database = TestDatabase::create(10).await;
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = compiled_registry();
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("migration installs the complete compiler-owned PostgreSQL schema");
    let catalog = ExpectedManagedCatalog::compiled(&compiled);
    let identity = initialize_registry_state_for_catalog_test(
        &migration,
        &database.runtime_role,
        &catalog,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            environment: "local",
            instance_id: INSTANCE_ID,
            database_id: DATABASE_ID,
            package_revision: "package-mutation-1",
            package_sequence: 1,
        },
    )
    .await
    .expect("migration initializes the active package after exact schema install");
    migration_task.abort();

    let pool = database
        .runtime_config
        .build_pool()
        .expect("bounded runtime pool builds");
    let profile = AuditProfile::production_from_secret_bytes(vec![0x5a; 32].into())
        .expect("test owns a strong keyed audit profile");
    let coordinator = MutationCoordinator::new(
        RegistryLockKey::derive("mutation-registry").expect("lock id is bounded"),
        Duration::from_secs(2),
        identity.clone(),
        profile.clone(),
    );
    let create_plan = MutationPlan::from_compiled(&compiled, "records.widget.create")
        .expect("create plan comes from the compiled inventory");
    let patch_plan = MutationPlan::from_compiled(&compiled, "records.widget.patch")
        .expect("patch plan comes from the compiled inventory");
    let claims = mutation_claims(&compiled, PRINCIPAL_CANARY, "zone-a");
    let table = &compiled.entities()["widget"].physical_table;
    let mut client = pool
        .get_for_test()
        .await
        .expect("runtime connection is available");

    let before_invalid = durable_counts(&database, table).await;
    let invalid = coordinator
        .execute(
            &mut client,
            create_request(
                &create_plan,
                "invalid-key",
                &claims,
                "not-a-uuid",
                "missing-required-fields",
                None,
            ),
        )
        .await;
    assert_eq!(invalid, Err(MutationError::InvalidRequest));
    assert_eq!(
        durable_counts(&database, table).await,
        DurableCounts {
            audit: before_invalid.audit + 1,
            ..before_invalid
        },
        "the public mutation path persists a refusal before returning validation failure"
    );

    let anonymous_claims = ClaimContext::for_compiled(
        &compiled,
        "widget",
        None,
        "anonymous-reader",
        None,
        Vec::new(),
    )
    .expect("anonymous read authority is compiler-bound");
    let before_anonymous = durable_counts(&database, table).await;
    let anonymous_mutation = coordinator
        .execute(
            &mut client,
            create_request(
                &create_plan,
                "anonymous-key",
                &anonymous_claims,
                "00000000-0000-0000-0000-000000000105",
                "anonymous-label",
                Some(1),
            ),
        )
        .await;
    assert_eq!(anonymous_mutation, Err(MutationError::InvalidRequest));
    assert_eq!(
        durable_counts(&database, table).await,
        DurableCounts {
            audit: before_anonymous.audit + 1,
            ..before_anonymous
        },
        "anonymous read authority cannot cross the mutation boundary"
    );

    for (index, fault) in [
        MutationFaultPoint::BeforeCurrentRow,
        MutationFaultPoint::BeforeRevision,
        MutationFaultPoint::BeforeOutbox,
        MutationFaultPoint::BeforeTerminalAudit,
        MutationFaultPoint::BeforeIdempotency,
        MutationFaultPoint::BeforeCommit,
    ]
    .into_iter()
    .enumerate()
    {
        let record = format!("00000000-0000-0000-0000-0000000002{index:02}");
        let key = format!("rollback-key-{index}");
        let before = durable_counts(&database, table).await;
        let failed = coordinator
            .execute_with_fault(
                &mut client,
                create_request(
                    &create_plan,
                    &key,
                    &claims,
                    &record,
                    "rollback-domain-value",
                    Some(7),
                ),
                fault,
            )
            .await;
        assert_eq!(failed, Err(MutationError::Unavailable));
        assert_eq!(
            durable_counts(&database, table).await,
            DurableCounts {
                audit: before.audit + 1,
                ..before
            },
            "fault {fault:?} retains only its unavoidable durable attempt"
        );
    }

    let before_positive = durable_counts(&database, table).await;
    let positive = coordinator
        .execute(
            &mut client,
            create_request(
                &create_plan,
                "positive-key",
                &claims,
                RECORD_POSITIVE,
                "created-label",
                Some(7),
            ),
        )
        .await
        .expect("complete typed mutation commits");
    assert!(!positive.replayed());
    let positive_id = response_id(&positive);
    assert_created_response(&positive, &positive_id, "created-label", 7);
    assert_one_complete_effect(
        before_positive,
        durable_counts(&database, table).await,
        1,
        2,
    );

    let before_replay = durable_counts(&database, table).await;
    let replay = coordinator
        .execute(
            &mut client,
            create_request(
                &create_plan,
                "positive-key",
                &claims,
                RECORD_POSITIVE,
                "created-label",
                Some(7),
            ),
        )
        .await
        .expect("same authorized request replays");
    assert!(replay.replayed());
    assert_eq!(replay.response(), positive.response());
    assert_audited_replay_only(before_replay, durable_counts(&database, table).await);

    let other_profile_claims = ClaimContext::for_compiled(
        &compiled,
        "widget",
        Some(PRINCIPAL_CANARY.to_owned()),
        "review-operator",
        Some("case-management".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: "zone-a".to_owned(),
        }],
    )
    .expect("alternate writer context is compiler-bound");
    let before_changed_profile = durable_counts(&database, table).await;
    let before_changed_profile_refusals = refusal_audit_count(&database).await;
    let changed_profile = coordinator
        .execute(
            &mut client,
            create_request(
                &create_plan,
                "positive-key",
                &other_profile_claims,
                RECORD_POSITIVE,
                "created-label",
                Some(7),
            ),
        )
        .await;
    assert_idempotency_refusal_only(
        changed_profile,
        before_changed_profile,
        before_changed_profile_refusals,
        &database,
        table,
    )
    .await;

    let other_purpose_claims = ClaimContext::for_compiled(
        &compiled,
        "widget",
        Some(PRINCIPAL_CANARY.to_owned()),
        "operator",
        Some("case-review".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: "zone-a".to_owned(),
        }],
    )
    .expect("alternate purpose context is compiler-bound");
    let before_changed_purpose = durable_counts(&database, table).await;
    let before_changed_purpose_refusals = refusal_audit_count(&database).await;
    let changed_purpose = coordinator
        .execute(
            &mut client,
            create_request(
                &create_plan,
                "positive-key",
                &other_purpose_claims,
                RECORD_POSITIVE,
                "created-label",
                Some(7),
            ),
        )
        .await;
    assert_idempotency_refusal_only(
        changed_purpose,
        before_changed_purpose,
        before_changed_purpose_refusals,
        &database,
        table,
    )
    .await;

    let before_changed_projection = durable_counts(&database, table).await;
    let before_changed_projection_refusals = refusal_audit_count(&database).await;
    let changed_projection = coordinator
        .execute(
            &mut client,
            MutationRequest {
                response_fields: BTreeSet::from(["label".to_owned()]),
                ..create_request(
                    &create_plan,
                    "positive-key",
                    &claims,
                    RECORD_POSITIVE,
                    "created-label",
                    Some(7),
                )
            },
        )
        .await;
    assert_idempotency_refusal_only(
        changed_projection,
        before_changed_projection,
        before_changed_projection_refusals,
        &database,
        table,
    )
    .await;

    let before_changed_request_context = durable_counts(&database, table).await;
    let before_changed_request_context_refusals = refusal_audit_count(&database).await;
    let changed_request_context = coordinator
        .execute(
            &mut client,
            patch_request(
                &patch_plan,
                "positive-key",
                &claims,
                &positive_id,
                &response_etag(&positive),
                "created-label",
            ),
        )
        .await;
    assert_idempotency_refusal_only(
        changed_request_context,
        before_changed_request_context,
        before_changed_request_context_refusals,
        &database,
        table,
    )
    .await;

    let before_changed_body = durable_counts(&database, table).await;
    let before_changed_body_refusals = refusal_audit_count(&database).await;
    let changed_body = coordinator
        .execute(
            &mut client,
            create_request(
                &create_plan,
                "positive-key",
                &claims,
                RECORD_POSITIVE,
                "changed-request-body",
                Some(7),
            ),
        )
        .await;
    assert_idempotency_refusal_only(
        changed_body,
        before_changed_body,
        before_changed_body_refusals,
        &database,
        table,
    )
    .await;

    let other_authority = mutation_claims(&compiled, PRINCIPAL_CANARY, "zone-b");
    let before_authority = durable_counts(&database, table).await;
    let before_authority_refusals = refusal_audit_count(&database).await;
    let changed_authority = coordinator
        .execute(
            &mut client,
            create_request(
                &create_plan,
                "positive-key",
                &other_authority,
                RECORD_POSITIVE,
                "created-label",
                Some(7),
            ),
        )
        .await;
    assert_idempotency_refusal_only(
        changed_authority,
        before_authority,
        before_authority_refusals,
        &database,
        table,
    )
    .await;

    let other_principal = mutation_claims(&compiled, "different-principal", "zone-a");
    let before_principal = durable_counts(&database, table).await;
    let before_principal_refusals = refusal_audit_count(&database).await;
    let changed_principal = coordinator
        .execute(
            &mut client,
            create_request(
                &create_plan,
                "positive-key",
                &other_principal,
                RECORD_POSITIVE,
                "created-label",
                Some(7),
            ),
        )
        .await;
    assert_idempotency_refusal_only(
        changed_principal,
        before_principal,
        before_principal_refusals,
        &database,
        table,
    )
    .await;

    let before_patch_seed = durable_counts(&database, table).await;
    let patch_seed = coordinator
        .execute(
            &mut client,
            create_request(
                &create_plan,
                "patch-seed-key",
                &claims,
                RECORD_PATCH,
                "before-patch",
                Some(41),
            ),
        )
        .await
        .expect("patch seed commits");
    let patch_id = response_id(&patch_seed);
    let patch_seed_etag = response_etag(&patch_seed);
    assert_one_complete_effect(
        before_patch_seed,
        durable_counts(&database, table).await,
        1,
        2,
    );
    let before_noncanonical_record = durable_counts(&database, table).await;
    let noncanonical_record = coordinator
        .execute(
            &mut client,
            patch_request(
                &patch_plan,
                "noncanonical-record-key",
                &claims,
                RECORD_POSITIVE,
                "\"rs-noncanonical-regression\"",
                "not-applied",
            ),
        )
        .await;
    assert_eq!(noncanonical_record, Err(MutationError::InvalidRequest));
    assert_eq!(
        durable_counts(&database, table).await,
        DurableCounts {
            audit: before_noncanonical_record.audit + 1,
            ..before_noncanonical_record
        },
        "noncanonical UUID spellings are refused before record I/O"
    );
    let before_patch = durable_counts(&database, table).await;
    let patched = coordinator
        .execute(
            &mut client,
            patch_request(
                &patch_plan,
                "patch-key",
                &claims,
                &patch_id,
                &patch_seed_etag,
                "after-patch",
            ),
        )
        .await
        .expect("nonempty authorized partial patch commits");
    assert!(!patched.replayed());
    assert_eq!(patched.response().status(), 200);
    assert!(!patched
        .response()
        .headers()
        .contains_key(&PermittedResponseHeader::Location));
    assert_eq!(
        patched.response().body(),
        format!(
            "{{\"data\":{{\"label\":\"after-patch\",\"quantity\":41}},\"id\":\"{patch_id}\",\"revision\":2}}"
        )
        .as_bytes()
    );
    let patched_etag = response_etag(&patched);
    assert_one_complete_effect(before_patch, durable_counts(&database, table).await, 0, 2);
    assert_patch_preserved_omitted_field(&database, table, &patch_id).await;

    let label_editor = ClaimContext::for_compiled(
        &compiled,
        "widget",
        Some(PRINCIPAL_CANARY.to_owned()),
        "label-editor",
        Some("case-management".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: "zone-a".to_owned(),
        }],
    )
    .expect("limited writer context is compiler-bound");
    let before_forbidden_field = durable_counts(&database, table).await;
    let forbidden_field = coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &patch_plan,
                idempotency_key: "forbidden-field-key",
                claims: &label_editor,
                record_id: Some(&patch_id),
                expected_etag: Some(&patched_etag),
                body: MutationBody::Patch(vec![PatchOperation::Replace {
                    path: "/data/quantity".to_owned(),
                    value: json!(42),
                }]),
                response_fields: BTreeSet::from(["label".to_owned()]),
            },
        )
        .await;
    assert_eq!(forbidden_field, Err(MutationError::InvalidRequest));
    assert_eq!(
        durable_counts(&database, table).await,
        DurableCounts {
            audit: before_forbidden_field.audit + 1,
            ..before_forbidden_field
        },
        "the selected profile writable-field set is enforced before record I/O"
    );

    let before_empty_patch = durable_counts(&database, table).await;
    let empty_patch = coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &patch_plan,
                idempotency_key: "empty-patch-key",
                claims: &claims,
                record_id: Some(&patch_id),
                expected_etag: Some(&patched_etag),
                body: MutationBody::Patch(Vec::new()),
                response_fields: BTreeSet::from(["label".to_owned()]),
            },
        )
        .await;
    assert_eq!(empty_patch, Err(MutationError::InvalidRequest));
    assert_eq!(
        durable_counts(&database, table).await,
        DurableCounts {
            audit: before_empty_patch.audit + 1,
            ..before_empty_patch
        },
        "an empty patch is refused without a record effect"
    );

    let before_changed_revision = durable_counts(&database, table).await;
    let changed_revision = coordinator
        .execute(
            &mut client,
            patch_request(
                &patch_plan,
                "patch-key",
                &claims,
                &patch_id,
                &patched_etag,
                "after-patch",
            ),
        )
        .await;
    assert_eq!(changed_revision, Err(MutationError::IdempotencyConflict));
    assert_audited_refusal_only(
        before_changed_revision,
        durable_counts(&database, table).await,
    );

    let before_patch_conflict = durable_counts(&database, table).await;
    let patch_conflict = coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &patch_plan,
                idempotency_key: "patch-conflict-key",
                claims: &claims,
                record_id: Some(&patch_id),
                expected_etag: Some(&patched_etag),
                body: MutationBody::Patch(vec![
                    PatchOperation::Test {
                        path: "/data/label".to_owned(),
                        value: Value::String("not-current".to_owned()),
                    },
                    PatchOperation::Replace {
                        path: "/data/label".to_owned(),
                        value: Value::String("not-applied".to_owned()),
                    },
                ]),
                response_fields: BTreeSet::from(["label".to_owned(), "quantity".to_owned()]),
            },
        )
        .await;
    assert_eq!(patch_conflict, Err(MutationError::Conflict));
    assert_eq!(
        patch_conflict.expect_err("test op refuses").to_string(),
        "mutation conflicts with current state"
    );
    assert_audited_refusal_only(
        before_patch_conflict,
        durable_counts(&database, table).await,
    );

    let mut concurrent_one = pool
        .get_for_test()
        .await
        .expect("first concurrent connection is available");
    let mut concurrent_two = pool
        .get_for_test()
        .await
        .expect("second concurrent connection is available");
    let before_concurrent = durable_counts(&database, table).await;
    let (first, second) = tokio::join!(
        coordinator.execute(
            &mut concurrent_one,
            create_request(
                &create_plan,
                "concurrent-key",
                &claims,
                RECORD_CONCURRENT,
                "concurrent-label",
                Some(5),
            ),
        ),
        coordinator.execute(
            &mut concurrent_two,
            create_request(
                &create_plan,
                "concurrent-key",
                &claims,
                RECORD_CONCURRENT,
                "concurrent-label",
                Some(5),
            ),
        ),
    );
    let first = first.expect("one concurrent request completes");
    let second = second.expect("the serialized retry completes");
    assert_ne!(first.replayed(), second.replayed());
    assert_eq!(first.response(), second.response());
    assert_one_complete_effect(
        before_concurrent,
        durable_counts(&database, table).await,
        1,
        4,
    );

    let before_recovery = durable_counts(&database, table).await;
    let lost = coordinator
        .execute_with_fault(
            &mut client,
            create_request(
                &create_plan,
                "recovery-key",
                &claims,
                RECORD_RECOVERY,
                "recovery-label",
                Some(12),
            ),
            MutationFaultPoint::AfterCommitBeforeResponseRelease,
        )
        .await;
    assert_eq!(lost, Err(MutationError::Unavailable));
    assert_one_complete_effect(
        before_recovery,
        durable_counts(&database, table).await,
        1,
        2,
    );
    let before_recovery_replay = durable_counts(&database, table).await;
    let recovered = coordinator
        .execute(
            &mut client,
            create_request(
                &create_plan,
                "recovery-key",
                &claims,
                RECORD_RECOVERY,
                "recovery-label",
                Some(12),
            ),
        )
        .await
        .expect("authorized retry recovers exact committed response");
    assert!(recovered.replayed());
    let recovery_id = response_id(&recovered);
    assert_created_response(&recovered, &recovery_id, "recovery-label", 12);
    assert_audited_replay_only(
        before_recovery_replay,
        durable_counts(&database, table).await,
    );

    let mut changed_identity = identity.clone();
    changed_identity.package_revision = "package-mutation-2".to_owned();
    changed_identity.package_sequence = 2;
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_state
             SET active_package_revision = $1, package_sequence = $2
             WHERE singleton",
            &[
                &changed_identity.package_revision,
                &changed_identity.package_sequence,
            ],
        )
        .await
        .expect("test can simulate activation of a same-schema package revision");
    let changed_package_coordinator = MutationCoordinator::new(
        RegistryLockKey::derive("mutation-registry").expect("lock id is bounded"),
        Duration::from_secs(2),
        changed_identity,
        profile.clone(),
    );
    let before_changed_package = durable_counts(&database, table).await;
    let before_changed_package_refusals = refusal_audit_count(&database).await;
    let changed_package = changed_package_coordinator
        .execute(
            &mut client,
            create_request(
                &create_plan,
                "positive-key",
                &claims,
                RECORD_POSITIVE,
                "created-label",
                Some(7),
            ),
        )
        .await;
    assert_idempotency_refusal_only(
        changed_package,
        before_changed_package,
        before_changed_package_refusals,
        &database,
        table,
    )
    .await;

    assert_journals_are_minimized_and_chained(&database, &profile).await;
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_http_mutations_are_guarded_and_exactly_replayable() {
    let database = TestDatabase::create(12).await;
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("migration installs schema");
    let catalog = ExpectedManagedCatalog::compiled(&compiled);
    let identity = initialize_registry_state_for_catalog_test(
        &migration,
        &database.runtime_role,
        &catalog,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            environment: "local",
            instance_id: INSTANCE_ID,
            database_id: DATABASE_ID,
            package_revision: "package-http-mutation-1",
            package_sequence: 1,
        },
    )
    .await
    .expect("migration initializes state");
    migration_task.abort();

    let pool = database.runtime_config.build_pool().expect("pool builds");
    let profile = AuditProfile::production_from_secret_bytes(vec![0x6b; 32].into())
        .expect("test owns keyed audit");
    let lock_key = RegistryLockKey::derive("mutation-registry").expect("lock id is bounded");
    let app = mutation_router(
        pool.clone(),
        compiled.clone(),
        identity.clone(),
        lock_key,
        profile.clone(),
        None,
    );
    let table = compiled.entities()["widget"].physical_table.clone();
    let claims = api_claims("case-management", Some("zone-a"));
    let rs_sec_13_claims = api_claims_with_principal_and_scopes(
        RS_SEC_13_PRINCIPAL_CANARY,
        "case-management",
        Some(RS_SEC_13_ZONE_CANARY),
        BTreeSet::from(["rs-sec-13-scope-canary".to_owned()]),
    );

    let openapi = body_json(
        send(
            &app,
            Method::GET,
            "/openapi.json?accessProfile=operator",
            Some(claims.clone()),
            &[],
            Vec::new(),
        )
        .await,
    )
    .await;
    assert!(openapi["paths"]["/v1/records/widgets"]
        .get("post")
        .is_some());
    assert!(openapi["paths"]["/v1/records/widgets/{record_id}"]
        .get("patch")
        .is_some());
    assert!(openapi["paths"]["/v1/records/widgets/{record_id}"]
        .get("delete")
        .is_some());
    assert!(openapi["paths"]["/v1/records/logs"].get("post").is_some());
    assert!(openapi["paths"]
        .get("/v1/records/logs/{record_id}")
        .and_then(|path| path.get("patch"))
        .is_none());
    assert!(openapi["paths"]
        .get("/v1/records/logs/{record_id}")
        .and_then(|path| path.get("delete"))
        .is_none());
    assert!(openapi["paths"]
        .get("/v1/records/archives/{record_id}")
        .and_then(|path| path.get("delete"))
        .is_none());

    let metadata = body_json(
        send(
            &app,
            Method::GET,
            "/v1/registry?accessProfile=operator",
            Some(claims.clone()),
            &[],
            Vec::new(),
        )
        .await,
    )
    .await;
    let metadata_entities = metadata["entities"].as_array().expect("metadata entities");
    let metadata_operations = |entity_id: &str| {
        metadata_entities
            .iter()
            .find(|entity| entity["id"] == entity_id)
            .and_then(|entity| entity["operations"].as_array())
            .expect("entity metadata operations")
    };
    assert!(metadata_operations("widget")
        .iter()
        .any(|operation| operation["operation"] == "tombstone"));
    assert!(!metadata_operations("log")
        .iter()
        .any(|operation| operation["operation"] == "tombstone"));
    assert!(!metadata_operations("archive")
        .iter()
        .any(|operation| operation["operation"] == "tombstone"));

    let create_body =
        br#"{"data":{"jurisdiction":"zone-a","label":"http-created","quantity":3}}"#.to_vec();
    for (label, headers, body, expected, code) in [
        (
            "missing idempotency",
            vec![("content-type", "application/json")],
            create_body.clone(),
            StatusCode::BAD_REQUEST,
            "request.invalid",
        ),
        (
            "wrong media",
            vec![
                ("content-type", "text/plain"),
                ("idempotency-key", "bad-media"),
            ],
            create_body.clone(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported.media_type",
        ),
        (
            "caller id",
            vec![
                ("content-type", "application/json"),
                ("idempotency-key", "caller-id-body"),
            ],
            br#"{"id":"00000000-0000-0000-0000-000000000001","data":{"jurisdiction":"zone-a","label":"bad","quantity":1}}"#.to_vec(),
            StatusCode::BAD_REQUEST,
            "request.invalid",
        ),
    ] {
        let before = durable_counts(&database, &table).await;
        let response = send(
            &app,
            Method::POST,
            "/v1/records/widgets",
            Some(claims.clone()),
            &headers,
            body,
        )
        .await;
        assert_eq!(response.status(), expected, "{label}");
        assert_eq!(body_json(response).await["code"], code, "{label}");
        assert_eq!(
            durable_counts(&database, &table).await.current,
            before.current
        );
        assert_eq!(
            durable_counts(&database, &table).await.audit,
            before.audit + 1,
            "{label}"
        );
    }
    let before_duplicate_key = durable_counts(&database, &table).await;
    let duplicate_key = request_with_duplicate_header(
        &app,
        DuplicateHeaderRequest {
            method: Method::POST,
            uri: "/v1/records/widgets",
            claims: Some(claims.clone()),
            duplicate: ("idempotency-key", "dup-key"),
            headers: vec![("content-type", "application/json")],
            body: create_body.clone(),
        },
    )
    .await;
    assert_eq!(duplicate_key.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        durable_counts(&database, &table).await.audit,
        before_duplicate_key.audit + 1
    );

    let created = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/records/widgets",
            Some(claims.clone()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "http-create-key"),
            ],
            create_body.clone(),
        )
        .await,
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED);
    let record_id = created.body["id"].as_str().expect("id").to_owned();
    assert!(Uuid::parse_str(&record_id).is_ok_and(|id| id.to_string() == record_id));
    assert_eq!(created.body["revision"], 1);
    assert_eq!(created.body["data"]["label"], "http-created");
    assert_eq!(created.body["data"]["note"], Value::Null);
    assert!(created.etag.starts_with("\"rs-"));
    assert_eq!(
        created.location,
        Some(format!("/v1/records/widgets/{record_id}"))
    );

    let replay = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/records/widgets",
            Some(claims.clone()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "http-create-key"),
            ],
            create_body,
        )
        .await,
    )
    .await;
    assert_eq!(replay.status, created.status);
    assert_eq!(replay.body_bytes, created.body_bytes);
    assert_eq!(replay.content_type, created.content_type);
    assert_eq!(replay.etag, created.etag);
    assert_eq!(replay.location, created.location);

    let before_rs_sec_13_seed = durable_counts(&database, &table).await;
    let rs_sec_13_seed_body = format!(
        r#"{{"data":{{"jurisdiction":"{RS_SEC_13_ZONE_CANARY}","label":"{RS_SEC_13_LABEL_CANARY}","quantity":{RS_SEC_13_QUANTITY_CANARY}}}}}"#
    )
    .into_bytes();
    let rs_sec_13_seed = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/records/widgets",
            Some(rs_sec_13_claims.clone()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "rs-sec-13-idempotency-key-seed"),
                (
                    "authorization",
                    "Bearer rs-sec-13-credential-canary.rs-sec-13-raw-token-canary",
                ),
            ],
            rs_sec_13_seed_body.clone(),
        )
        .await,
    )
    .await;
    assert_eq!(rs_sec_13_seed.status, StatusCode::CREATED);
    assert_one_complete_effect(
        before_rs_sec_13_seed,
        durable_counts(&database, &table).await,
        1,
        2,
    );

    let before_rs_sec_13_conflict = durable_counts(&database, &table).await;
    let rs_sec_13_conflict = send(
        &app,
        Method::POST,
        "/v1/records/widgets",
        Some(rs_sec_13_claims),
        &[
            ("content-type", "application/json"),
            ("idempotency-key", RS_SEC_13_IDEMPOTENCY_CANARY),
            (
                "authorization",
                "Bearer rs-sec-13-credential-canary.rs-sec-13-raw-token-canary",
            ),
        ],
        rs_sec_13_seed_body,
    )
    .await;
    assert_unique_violation_conflict_is_value_free(
        rs_sec_13_conflict,
        before_rs_sec_13_conflict,
        durable_counts(&database, &table).await,
        &compiled,
    )
    .await;

    let fetched = response_parts(
        send(
            &app,
            Method::GET,
            &format!("/v1/records/widgets/{record_id}?accessProfile=operator"),
            Some(claims.clone()),
            &[],
            Vec::new(),
        )
        .await,
    )
    .await;
    assert_eq!(fetched.body["id"], record_id);
    assert_eq!(fetched.body["revision"], 1);
    assert_eq!(fetched.body["data"]["label"], "http-created");
    assert_eq!(fetched.etag, created.etag);

    let anonymous_fetched = response_parts(
        send(
            &app,
            Method::GET,
            &format!("/v1/records/widgets/{record_id}?accessProfile=anonymous-reader"),
            None,
            &[],
            Vec::new(),
        )
        .await,
    )
    .await;
    assert_eq!(
        anonymous_fetched.body["data"],
        json!({"label": "http-created"})
    );
    assert!(anonymous_fetched.etag.starts_with("\"rs-"));
    assert_ne!(anonymous_fetched.etag, fetched.etag);

    let listed_response = send(
        &app,
        Method::GET,
        "/v1/records/widgets?accessProfile=operator",
        Some(claims.clone()),
        &[],
        Vec::new(),
    )
    .await;
    assert!(listed_response.headers().get("etag").is_none());
    let listed = body_json(listed_response).await;
    assert!(listed["items"]
        .as_array()
        .expect("items")
        .iter()
        .any(|item| item["id"] == record_id));

    let log_created = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/records/logs",
            Some(claims.clone()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "http-log-create-key"),
            ],
            br#"{"data":{"jurisdiction":"zone-a","message":"create-only-log"}}"#.to_vec(),
        )
        .await,
    )
    .await;
    assert_eq!(log_created.status, StatusCode::CREATED);
    let log_id = log_created.body["id"].as_str().expect("log id");
    let log_patch = send(
        &app,
        Method::PATCH,
        &format!("/v1/records/logs/{log_id}"),
        Some(claims.clone()),
        &[
            ("content-type", "application/json-patch+json"),
            ("idempotency-key", "log-patch-omitted"),
            ("if-match", &log_created.etag),
        ],
        br#"[{"op":"replace","path":"/data/message","value":"nope"}]"#.to_vec(),
    )
    .await;
    assert_eq!(log_patch.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_json(log_patch).await["code"], "resource.not_found");
    let log_delete = send(
        &app,
        Method::DELETE,
        &format!("/v1/records/logs/{log_id}"),
        Some(claims.clone()),
        &[
            ("idempotency-key", "log-delete-omitted"),
            ("if-match", &log_created.etag),
        ],
        Vec::new(),
    )
    .await;
    assert_eq!(log_delete.status(), StatusCode::NOT_FOUND);
    assert!(log_delete.headers().get("etag").is_none());
    let archive_delete = send(
        &app,
        Method::DELETE,
        "/v1/records/archives/00000000-0000-0000-0000-000000000001",
        Some(claims.clone()),
        &[
            ("idempotency-key", "archive-delete-omitted"),
            ("if-match", "\"rs-route-omitted\""),
        ],
        Vec::new(),
    )
    .await;
    assert_eq!(archive_delete.status(), StatusCode::NOT_FOUND);
    assert!(archive_delete.headers().get("etag").is_none());

    let before_missing_match = durable_counts(&database, &table).await;
    let missing_match = send(
        &app,
        Method::PATCH,
        &format!("/v1/records/widgets/{record_id}"),
        Some(claims.clone()),
        &[
            ("content-type", "application/json-patch+json"),
            ("idempotency-key", "missing-match"),
        ],
        br#"[{"op":"replace","path":"/data/label","value":"x"}]"#.to_vec(),
    )
    .await;
    assert_eq!(missing_match.status(), StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(
        body_json(missing_match).await["code"],
        "precondition.required"
    );
    assert_eq!(
        durable_counts(&database, &table).await.audit,
        before_missing_match.audit + 1
    );

    let before_bad_patch_body = durable_counts(&database, &table).await;
    let bad_patch_body = send(
        &app,
        Method::PATCH,
        &format!("/v1/records/widgets/{record_id}"),
        Some(claims.clone()),
        &[
            ("content-type", "application/json-patch+json"),
            ("idempotency-key", "bad-patch-body"),
            ("if-match", &created.etag),
        ],
        br#"{"op":"replace","path":"/data/label","value":"x"}"#.to_vec(),
    )
    .await;
    assert_eq!(bad_patch_body.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        durable_counts(&database, &table).await.audit,
        before_bad_patch_body.audit + 1
    );

    let patched = response_parts(
        send(
            &app,
            Method::PATCH,
            &format!("/v1/records/widgets/{record_id}"),
            Some(claims.clone()),
            &[
                ("content-type", "application/json-patch+json"),
                ("idempotency-key", "http-patch-key"),
                ("if-match", &created.etag),
            ],
            br#"[
              {"op":"test","path":"/data/label","value":"http-created"},
              {"op":"add","path":"/data/note","value":"temporary"},
              {"op":"replace","path":"/data/label","value":"http-patched"},
              {"op":"remove","path":"/data/note"}
            ]"#
            .to_vec(),
        )
        .await,
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK);
    assert_eq!(patched.body["revision"], 2);
    assert_eq!(patched.body["data"]["label"], "http-patched");
    assert_eq!(patched.body["data"]["quantity"], 3);
    assert_eq!(patched.body["data"]["note"], Value::Null);
    assert!(patched.location.is_none());

    let stale = send(
        &app,
        Method::PATCH,
        &format!("/v1/records/widgets/{record_id}"),
        Some(claims.clone()),
        &[
            ("content-type", "application/json-patch+json"),
            ("idempotency-key", "http-stale-key"),
            ("if-match", &created.etag),
        ],
        br#"[{"op":"replace","path":"/data/label","value":"stale"}]"#.to_vec(),
    )
    .await;
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(body_json(stale).await["code"], "precondition.failed");

    let wrong_context = send(
        &app,
        Method::PATCH,
        &format!("/v1/records/widgets/{record_id}"),
        Some(api_claims("case-management", Some("zone-b"))),
        &[
            ("content-type", "application/json-patch+json"),
            ("idempotency-key", "http-wrong-context"),
            ("if-match", &patched.etag),
        ],
        br#"[{"op":"replace","path":"/data/label","value":"hidden"}]"#.to_vec(),
    )
    .await;
    assert_eq!(wrong_context.status(), StatusCode::PRECONDITION_FAILED);

    let before_duplicate_match = durable_counts(&database, &table).await;
    let duplicate_match = request_with_duplicate_header(
        &app,
        DuplicateHeaderRequest {
            method: Method::PATCH,
            uri: &format!("/v1/records/widgets/{record_id}"),
            claims: Some(claims.clone()),
            duplicate: ("if-match", &patched.etag),
            headers: vec![
                ("content-type", "application/json-patch+json"),
                ("idempotency-key", "duplicate-match"),
            ],
            body: br#"[{"op":"replace","path":"/data/label","value":"x"}]"#.to_vec(),
        },
    )
    .await;
    assert_eq!(duplicate_match.status(), StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(
        durable_counts(&database, &table).await.audit,
        before_duplicate_match.audit + 1
    );

    let current = response_parts(
        send(
            &app,
            Method::GET,
            &format!("/v1/records/widgets/{record_id}?accessProfile=operator"),
            Some(claims.clone()),
            &[],
            Vec::new(),
        )
        .await,
    )
    .await;
    assert_eq!(current.body["revision"], 2);
    assert_eq!(current.etag, patched.etag);

    for (label, headers, body, expected, code) in [
        (
            "missing idempotency",
            vec![("if-match", current.etag.as_str())],
            Vec::new(),
            StatusCode::BAD_REQUEST,
            "request.invalid",
        ),
        (
            "missing if-match",
            vec![("idempotency-key", "delete-missing-match")],
            Vec::new(),
            StatusCode::PRECONDITION_REQUIRED,
            "precondition.required",
        ),
        (
            "weak if-match",
            vec![
                ("idempotency-key", "delete-weak-match"),
                ("if-match", "W/\"rs-weak\""),
            ],
            Vec::new(),
            StatusCode::PRECONDITION_FAILED,
            "precondition.failed",
        ),
        (
            "content type is forbidden",
            vec![
                ("content-type", "application/json"),
                ("idempotency-key", "delete-content-type"),
                ("if-match", current.etag.as_str()),
            ],
            Vec::new(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported.media_type",
        ),
        (
            "body is forbidden",
            vec![
                ("idempotency-key", "delete-body"),
                ("if-match", current.etag.as_str()),
            ],
            br#"{}"#.to_vec(),
            StatusCode::BAD_REQUEST,
            "request.invalid",
        ),
    ] {
        let response = send(
            &app,
            Method::DELETE,
            &format!("/v1/records/widgets/{record_id}"),
            Some(claims.clone()),
            &headers,
            body,
        )
        .await;
        assert_eq!(response.status(), expected, "{label}");
        assert!(response.headers().get("etag").is_none(), "{label}");
        assert_eq!(body_json(response).await["code"], code, "{label}");
    }

    let duplicate_delete_key = request_with_duplicate_header(
        &app,
        DuplicateHeaderRequest {
            method: Method::DELETE,
            uri: &format!("/v1/records/widgets/{record_id}"),
            claims: Some(claims.clone()),
            duplicate: ("idempotency-key", "duplicate-delete-key"),
            headers: vec![("if-match", current.etag.as_str())],
            body: Vec::new(),
        },
    )
    .await;
    assert_eq!(duplicate_delete_key.status(), StatusCode::BAD_REQUEST);
    let duplicate_delete_match = request_with_duplicate_header(
        &app,
        DuplicateHeaderRequest {
            method: Method::DELETE,
            uri: &format!("/v1/records/widgets/{record_id}"),
            claims: Some(claims.clone()),
            duplicate: ("if-match", current.etag.as_str()),
            headers: vec![("idempotency-key", "duplicate-delete-match")],
            body: Vec::new(),
        },
    )
    .await;
    assert_eq!(
        duplicate_delete_match.status(),
        StatusCode::PRECONDITION_REQUIRED
    );

    let query_authority = send(
        &app,
        Method::DELETE,
        &format!("/v1/records/widgets/{record_id}?fields=label"),
        Some(claims.clone()),
        &[
            ("idempotency-key", "delete-query-authority"),
            ("if-match", &current.etag),
        ],
        Vec::new(),
    )
    .await;
    assert_eq!(query_authority.status(), StatusCode::NOT_FOUND);
    assert!(query_authority.headers().get("etag").is_none());

    for (label, blocked_claims) in [
        ("anonymous", None),
        (
            "unauthorized",
            Some(api_claims("wrong-purpose", Some("zone-a"))),
        ),
    ] {
        let response = send(
            &app,
            Method::DELETE,
            &format!("/v1/records/widgets/{record_id}"),
            blocked_claims,
            &[
                ("idempotency-key", label),
                ("if-match", current.etag.as_str()),
            ],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{label}");
        assert!(response.headers().get("etag").is_none(), "{label}");
    }

    let stale_delete = send(
        &app,
        Method::DELETE,
        &format!("/v1/records/widgets/{record_id}"),
        Some(claims.clone()),
        &[
            ("idempotency-key", "delete-stale-etag"),
            ("if-match", &fetched.etag),
        ],
        Vec::new(),
    )
    .await;
    assert_eq!(stale_delete.status(), StatusCode::PRECONDITION_FAILED);
    let stale_bytes = response_bytes(stale_delete).await;
    assert!(!stale_bytes
        .windows(b"http-patched".len())
        .any(|window| window == b"http-patched"));

    let changed_context = send(
        &app,
        Method::DELETE,
        &format!("/v1/records/widgets/{record_id}?accessProfile=review-operator"),
        Some(claims.clone()),
        &[
            ("idempotency-key", "delete-changed-context"),
            ("if-match", &current.etag),
        ],
        Vec::new(),
    )
    .await;
    assert_eq!(changed_context.status(), StatusCode::PRECONDITION_FAILED);
    let changed_context_bytes = response_bytes(changed_context).await;
    assert!(!changed_context_bytes
        .windows(b"http-patched".len())
        .any(|window| window == b"http-patched"));

    let tombstoned = response_parts(
        send(
            &app,
            Method::DELETE,
            &format!("/v1/records/widgets/{record_id}"),
            Some(claims.clone()),
            &[
                ("idempotency-key", "http-tombstone-key"),
                ("if-match", &current.etag),
            ],
            Vec::new(),
        )
        .await,
    )
    .await;
    assert_eq!(tombstoned.status, StatusCode::OK);
    assert_eq!(tombstoned.body["id"], record_id);
    assert_eq!(tombstoned.body["revision"], 3);
    assert_eq!(tombstoned.body["data"]["label"], "http-patched");

    let tombstone_replay = response_parts(
        send(
            &app,
            Method::DELETE,
            &format!("/v1/records/widgets/{record_id}"),
            Some(claims.clone()),
            &[
                ("idempotency-key", "http-tombstone-key"),
                ("if-match", &current.etag),
            ],
            Vec::new(),
        )
        .await,
    )
    .await;
    assert_eq!(tombstone_replay.status, tombstoned.status);
    assert_eq!(tombstone_replay.body_bytes, tombstoned.body_bytes);
    assert_eq!(tombstone_replay.content_type, tombstoned.content_type);
    assert_eq!(tombstone_replay.etag, tombstoned.etag);

    let concealed_tombstone = send(
        &app,
        Method::GET,
        &format!("/v1/records/widgets/{record_id}?accessProfile=operator"),
        Some(claims.clone()),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(concealed_tombstone.status(), StatusCode::NOT_FOUND);
    assert!(concealed_tombstone.headers().get("etag").is_none());
    let concealed_tombstone_bytes = response_bytes(concealed_tombstone).await;
    assert!(!concealed_tombstone_bytes
        .windows(b"http-patched".len())
        .any(|window| window == b"http-patched"));

    let before_bad_query = durable_counts(&database, &table).await;
    let bad_query = send(
        &app,
        Method::POST,
        "/v1/records/widgets?fields=label",
        Some(claims.clone()),
        &[
            ("content-type", "application/json"),
            ("idempotency-key", "bad-query"),
        ],
        br#"{"data":{"jurisdiction":"zone-a","label":"bad-query","quantity":1}}"#.to_vec(),
    )
    .await;
    assert_eq!(bad_query.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_json(bad_query).await["code"], "resource.not_found");
    assert_eq!(
        durable_counts(&database, &table).await.audit,
        before_bad_query.audit + 1
    );

    let refusal_faulting = mutation_refusal_audit_fault_router(
        pool.clone(),
        compiled.clone(),
        identity.clone(),
        lock_key,
        profile.clone(),
    );
    let before_refusal_fault = durable_counts(&database, &table).await;
    let refusal_fault = send(
        &refusal_faulting,
        Method::DELETE,
        &format!("/v1/records/widgets/{record_id}"),
        Some(claims.clone()),
        &[
            ("content-type", "text/plain"),
            ("idempotency-key", "refusal-audit-fault"),
            ("if-match", &current.etag),
        ],
        Vec::new(),
    )
    .await;
    assert_eq!(refusal_fault.status(), StatusCode::SERVICE_UNAVAILABLE);
    let refusal_fault_body = response_bytes(refusal_fault).await;
    let refusal_fault_json: Value =
        serde_json::from_slice(&refusal_fault_body).expect("problem JSON");
    assert_eq!(refusal_fault_json["code"], "service.unavailable");
    assert!(!refusal_fault_body
        .windows(b"unsupported.media_type".len())
        .any(|window| window == b"unsupported.media_type"));
    assert_eq!(
        durable_counts(&database, &table).await,
        before_refusal_fault,
        "refusal audit failure releases no intended refusal and commits no mutation packet"
    );

    for (label, uri, blocked_claims) in [
        (
            "wrong purpose",
            "/v1/records/widgets?accessProfile=operator",
            api_claims("wrong-purpose", Some("zone-a")),
        ),
        (
            "wrong profile",
            "/v1/records/widgets?accessProfile=missing",
            api_claims("case-management", Some("zone-a")),
        ),
        (
            "missing boundary",
            "/v1/records/widgets?accessProfile=operator",
            api_claims("case-management", None),
        ),
    ] {
        let before = durable_counts(&database, &table).await;
        let response = send(
            &app,
            Method::POST,
            uri,
            Some(blocked_claims),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", label),
            ],
            br#"{"data":{"jurisdiction":"zone-a","label":"blocked","quantity":1}}"#.to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{label}");
        assert_eq!(
            durable_counts(&database, &table).await.current,
            before.current
        );
        assert_eq!(
            durable_counts(&database, &table).await.audit,
            before.audit + 1
        );
    }

    let faulting = mutation_router(
        pool,
        compiled,
        identity,
        lock_key,
        profile.clone(),
        Some(MutationFaultPoint::BeforeTerminalAudit),
    );
    let before_fault = durable_counts(&database, &table).await;
    let faulted = send(
        &faulting,
        Method::POST,
        "/v1/records/widgets",
        Some(claims),
        &[
            ("content-type", "application/json"),
            ("idempotency-key", "http-terminal-fault"),
        ],
        br#"{"data":{"jurisdiction":"zone-a","label":"not-released","quantity":9}}"#.to_vec(),
    )
    .await;
    assert_eq!(faulted.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_json(faulted).await["code"], "service.unavailable");
    assert_eq!(
        durable_counts(&database, &table).await,
        DurableCounts {
            audit: before_fault.audit + 1,
            ..before_fault
        },
        "terminal audit failure releases no success bytes and commits no mutation packet"
    );

    assert_journals_are_minimized_and_chained(&database, &profile).await;
    database.cleanup().await;
}

fn mutation_refusal_audit_fault_router(
    pool: registry_server::postgres::RuntimePool,
    registry: Arc<registry_server::CompiledRegistry>,
    identity: registry_server::postgres::ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    profile: AuditProfile,
) -> axum::Router {
    let cursors = test_cursor_codec();
    let records = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        profile.clone(),
        cursors.clone(),
    ));
    let read_identity = ReadRuntimeIdentity {
        package_revision: identity.package_revision.clone(),
        schema_fingerprint: identity.schema_fingerprint.clone(),
    };
    let mutations = PostgresRecordMutationService::new(
        pool,
        registry.clone(),
        identity,
        lock_key,
        Duration::from_secs(2),
        profile,
    )
    .with_refusal_audit_fault_for_test();
    router(Arc::new(
        HttpService::new(
            registry,
            read_identity,
            records,
            Arc::new(AlwaysReady),
            cursors,
        )
        .with_postgres_mutations(Arc::new(mutations)),
    ))
}

fn mutation_router(
    pool: registry_server::postgres::RuntimePool,
    registry: Arc<registry_server::CompiledRegistry>,
    identity: registry_server::postgres::ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    profile: AuditProfile,
    fault: Option<MutationFaultPoint>,
) -> axum::Router {
    let cursors = test_cursor_codec();
    let records = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        profile.clone(),
        cursors.clone(),
    ));
    let read_identity = ReadRuntimeIdentity {
        package_revision: identity.package_revision.clone(),
        schema_fingerprint: identity.schema_fingerprint.clone(),
    };
    let mutations = PostgresRecordMutationService::new(
        pool,
        registry.clone(),
        identity,
        lock_key,
        Duration::from_secs(2),
        profile,
    );
    let mutations = match fault {
        Some(fault) => mutations.with_fault_for_test(fault),
        None => mutations,
    };
    router(Arc::new(
        HttpService::new(
            registry,
            read_identity,
            records,
            Arc::new(AlwaysReady),
            cursors,
        )
        .with_postgres_mutations(Arc::new(mutations)),
    ))
}

fn test_cursor_codec() -> Arc<CursorCodec> {
    Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x63; 32]), Duration::from_secs(300))
            .expect("test cursor key is valid"),
    )
}

struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

async fn send(
    app: &axum::Router,
    method: Method,
    uri: &str,
    claims: Option<VerifiedRequestClaims>,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::from(body))
        .expect("request");
    for (name, value) in headers {
        request.headers_mut().append(
            HeaderName::from_bytes(name.as_bytes()).expect("test header name"),
            HeaderValue::from_str(value).expect("test header value"),
        );
    }
    if let Some(claims) = claims {
        request.extensions_mut().insert(claims);
    }
    let mut app = app.clone();
    app.call(request).await.expect("response")
}

struct DuplicateHeaderRequest<'a> {
    method: Method,
    uri: &'a str,
    claims: Option<VerifiedRequestClaims>,
    duplicate: (&'a str, &'a str),
    headers: Vec<(&'a str, &'a str)>,
    body: Vec<u8>,
}

async fn request_with_duplicate_header(
    app: &axum::Router,
    input: DuplicateHeaderRequest<'_>,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method(input.method)
        .uri(input.uri)
        .body(Body::from(input.body))
        .expect("request");
    for (name, value) in input.headers {
        request.headers_mut().append(
            HeaderName::from_bytes(name.as_bytes()).expect("test header name"),
            HeaderValue::from_str(value).expect("test header value"),
        );
    }
    for _ in 0..2 {
        request.headers_mut().append(
            HeaderName::from_bytes(input.duplicate.0.as_bytes()).expect("test header name"),
            HeaderValue::from_str(input.duplicate.1).expect("test header value"),
        );
    }
    if let Some(claims) = input.claims {
        request.extensions_mut().insert(claims);
    }
    let mut app = app.clone();
    app.call(request).await.expect("response")
}

struct ResponseParts {
    status: StatusCode,
    body: Value,
    body_bytes: Vec<u8>,
    content_type: String,
    etag: String,
    location: Option<String>,
}

async fn response_parts(response: axum::response::Response) -> ResponseParts {
    let status = response.status();
    let headers = response.headers().clone();
    let body_bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("body")
        .to_vec();
    let body = serde_json::from_slice(&body_bytes).expect("JSON body");
    ResponseParts {
        status,
        body,
        body_bytes,
        content_type: header_string(&headers, "content-type"),
        etag: header_string(&headers, "etag"),
        location: headers
            .get("location")
            .map(|value| value.to_str().expect("location").to_owned()),
    }
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = response_bytes(response).await;
    serde_json::from_slice(&bytes).expect("JSON response")
}

async fn response_bytes(response: axum::response::Response) -> Vec<u8> {
    to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body")
        .to_vec()
}

fn header_string(headers: &axum::http::HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .expect("header is present")
        .to_owned()
}

fn api_claims(purpose: &str, zone: Option<&str>) -> VerifiedRequestClaims {
    api_claims_with_principal_and_scopes(PRINCIPAL_CANARY, purpose, zone, BTreeSet::new())
}

fn api_claims_with_principal_and_scopes(
    principal: &str,
    purpose: &str,
    zone: Option<&str>,
    scopes: BTreeSet<String>,
) -> VerifiedRequestClaims {
    let mut direct_claims = std::collections::BTreeMap::new();
    if let Some(zone) = zone {
        direct_claims.insert(
            "jurisdiction".to_owned(),
            VerifiedClaimValue::direct_string(zone).expect("direct claim"),
        );
    }
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        principal,
        scopes,
        Some(purpose.to_owned()),
        direct_claims,
    )
    .expect("verified context")
}

fn compiled_registry() -> registry_server::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"mutation-registry","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"widget","route":"widgets","mutationMode":"mutable","tombstone":true,"classification":"public",
            "constraints":[{"kind":"unique","fields":["label"]}],
            "fields":[
              {"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"public"},
              {"id":"label","type":"string","maxLength":128,"required":true,"classification":"public"},
              {"id":"note","type":"string","maxLength":128,"required":false,"classification":"public"},
              {"id":"quantity","type":"int64","required":true,"classification":"public"}
            ],
            "accessProfiles":[{
              "id":"operator","default":true,"principalClaim":"registry_principal",
              "requiredPurposes":["case-management","case-review"],
              "operations":["create","get","list","patch","tombstone"],
              "readableFields":["jurisdiction","label","note","quantity"],
              "writableFields":["jurisdiction","label","note","quantity"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            },{
              "id":"review-operator","principalClaim":"registry_principal",
              "requiredPurposes":["case-management"],
              "operations":["create","get","list","patch","tombstone"],
              "readableFields":["jurisdiction","label","note","quantity"],
              "writableFields":["jurisdiction","label","note","quantity"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            },{
              "id":"anonymous-reader","anonymous":true,
              "operations":["get","list"],
              "readableFields":["label"]
            },{
              "id":"label-editor","principalClaim":"registry_principal",
              "requiredPurposes":["case-management"],
              "operations":["get","patch"],
              "readableFields":["label"],
              "writableFields":["label"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            }],
            "events":[
              {"id":"widget-created","trigger":"created","projection":["label"]},
              {"id":"widget-patched","trigger":"patched","projection":["label","quantity"]},
              {"id":"widget-tombstoned","trigger":"tombstoned","projection":["label","quantity"]}
            ]
          },{
            "id":"log","route":"logs","mutationMode":"create_only","classification":"public",
            "fields":[
              {"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"public"},
              {"id":"message","type":"string","maxLength":128,"required":true,"classification":"public"}
            ],
            "accessProfiles":[{
              "id":"operator","default":true,"principalClaim":"registry_principal",
              "requiredPurposes":["case-management"],
              "operations":["create","get","list"],
              "readableFields":["jurisdiction","message"],
              "writableFields":["jurisdiction","message"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            }]
          },{
            "id":"archive","route":"archives","mutationMode":"mutable","classification":"public",
            "fields":[
              {"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"public"},
              {"id":"name","type":"string","maxLength":128,"required":true,"classification":"public"}
            ],
            "accessProfiles":[{
              "id":"operator","default":true,"principalClaim":"registry_principal",
              "requiredPurposes":["case-management"],
              "operations":["create","get","list","patch"],
              "readableFields":["jurisdiction","name"],
              "writableFields":["jurisdiction","name"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            }]
          }]
        }"#,
    )
    .expect("mutation fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("mutation fixture compiles to trusted inventories")
}

fn mutation_claims(
    registry: &registry_server::CompiledRegistry,
    principal: &str,
    zone: &str,
) -> ClaimContext {
    ClaimContext::for_compiled(
        registry,
        "widget",
        Some(principal.to_owned()),
        "operator",
        Some("case-management".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: zone.to_owned(),
        }],
    )
    .expect("claim context is compiler-bound")
}

fn create_request<'a>(
    plan: &'a MutationPlan,
    key: &'a str,
    claims: &'a ClaimContext,
    _record_id: &'a str,
    label: &str,
    quantity: Option<i64>,
) -> MutationRequest<'a> {
    let mut data = Map::from_iter([
        (
            "jurisdiction".to_owned(),
            Value::String("zone-a".to_owned()),
        ),
        ("label".to_owned(), Value::String(label.to_owned())),
    ]);
    if let Some(quantity) = quantity {
        data.insert("quantity".to_owned(), json!(quantity));
    }
    MutationRequest {
        plan,
        idempotency_key: key,
        claims,
        record_id: None,
        expected_etag: None,
        body: MutationBody::Create(data),
        response_fields: BTreeSet::from(["label".to_owned(), "quantity".to_owned()]),
    }
}

fn patch_request<'a>(
    plan: &'a MutationPlan,
    key: &'a str,
    claims: &'a ClaimContext,
    record_id: &'a str,
    expected_etag: &'a str,
    label: &str,
) -> MutationRequest<'a> {
    MutationRequest {
        plan,
        idempotency_key: key,
        claims,
        record_id: Some(record_id),
        expected_etag: Some(expected_etag),
        body: MutationBody::Patch(vec![PatchOperation::Replace {
            path: "/data/label".to_owned(),
            value: Value::String(label.to_owned()),
        }]),
        response_fields: BTreeSet::from(["label".to_owned(), "quantity".to_owned()]),
    }
}

fn response_etag(outcome: &MutationOutcome) -> String {
    String::from_utf8(outcome.response().headers()[&PermittedResponseHeader::Etag].clone())
        .expect("mutation response etag is UTF-8")
}

fn response_id(outcome: &MutationOutcome) -> String {
    let body: Value =
        serde_json::from_slice(outcome.response().body()).expect("mutation response is JSON");
    body["id"]
        .as_str()
        .expect("mutation response includes id")
        .to_owned()
}

fn assert_created_response(outcome: &MutationOutcome, record_id: &str, label: &str, quantity: i64) {
    assert_eq!(outcome.response().status(), 201);
    assert_eq!(
        outcome.response().body(),
        format!(
            "{{\"data\":{{\"label\":\"{label}\",\"quantity\":{quantity}}},\"id\":\"{record_id}\",\"revision\":1}}"
        )
        .as_bytes()
    );
    assert_eq!(
        outcome.response().headers()[&PermittedResponseHeader::ContentType],
        b"application/json"
    );
    assert!(outcome.response().headers()[&PermittedResponseHeader::Etag].starts_with(b"\"rs-"));
    assert_eq!(
        outcome.response().headers()[&PermittedResponseHeader::Location],
        format!("/v1/records/widgets/{record_id}").as_bytes()
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DurableCounts {
    current: i64,
    revisions: i64,
    outbox: i64,
    audit: i64,
    idempotency: i64,
}

fn assert_one_complete_effect(
    before: DurableCounts,
    after: DurableCounts,
    current_delta: i64,
    audit_delta: i64,
) {
    assert_eq!(
        after,
        DurableCounts {
            current: before.current + current_delta,
            revisions: before.revisions + 1,
            outbox: before.outbox + 1,
            audit: before.audit + audit_delta,
            idempotency: before.idempotency + 1,
        },
        "one successful request creates one complete atomic packet"
    );
}

fn assert_audited_replay_only(before: DurableCounts, after: DurableCounts) {
    assert_eq!(
        after,
        DurableCounts {
            audit: before.audit + 2,
            ..before
        }
    );
}

fn assert_audited_refusal_only(before: DurableCounts, after: DurableCounts) {
    assert_eq!(
        after,
        DurableCounts {
            audit: before.audit + 2,
            ..before
        }
    );
}

async fn assert_idempotency_refusal_only(
    result: Result<MutationOutcome, MutationError>,
    before: DurableCounts,
    before_refusals: i64,
    database: &TestDatabase,
    table: &str,
) {
    assert_eq!(result, Err(MutationError::IdempotencyConflict));
    assert_audited_refusal_only(before, durable_counts(database, table).await);
    assert_eq!(
        refusal_audit_count(database).await,
        before_refusals + 1,
        "idempotency conflict records exactly one minimized refusal audit"
    );
}

async fn assert_unique_violation_conflict_is_value_free(
    response: axum::response::Response,
    before: DurableCounts,
    after: DurableCounts,
    compiled: &registry_server::CompiledRegistry,
) {
    let status = response.status();
    let headers = response.headers().clone();
    let body = response_bytes(response).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/problem+json")
    );
    assert!(headers.get("etag").is_none());
    assert!(headers.get("location").is_none());
    assert_eq!(
        body.as_slice(),
        br#"{"type":"urn:registry-server:problem:mutation.conflict","title":"Conflict","status":409,"detail":"The mutation conflicts with current state.","code":"mutation.conflict"}"#
    );
    let problem: Value = serde_json::from_slice(&body).expect("problem JSON is valid");
    assert_eq!(
        problem,
        json!({
            "type": "urn:registry-server:problem:mutation.conflict",
            "title": "Conflict",
            "status": 409,
            "detail": "The mutation conflicts with current state.",
            "code": "mutation.conflict",
        })
    );
    assert_eq!(
        after,
        DurableCounts {
            audit: before.audit + 2,
            ..before
        },
        "a PostgreSQL uniqueness refusal leaves only minimized attempt/refusal audits"
    );
    let public_error_text = format!("{} {:?}", MutationError::Conflict, MutationError::Conflict);
    assert_diagnostic_text_excludes_canaries_and_database_details(
        std::str::from_utf8(&body).expect("problem body is UTF-8"),
        compiled,
    );
    assert_diagnostic_text_excludes_canaries_and_database_details(&public_error_text, compiled);
}

fn assert_diagnostic_text_excludes_canaries_and_database_details(
    text: &str,
    compiled: &registry_server::CompiledRegistry,
) {
    let lower_text = text.to_ascii_lowercase();
    for forbidden in forbidden_diagnostic_fragments(compiled) {
        assert!(
            !text.contains(&forbidden) && !lower_text.contains(&forbidden.to_ascii_lowercase()),
            "public diagnostic text leaked forbidden fragment {forbidden:?}: {text}"
        );
    }
}

fn forbidden_diagnostic_fragments(
    compiled: &registry_server::CompiledRegistry,
) -> BTreeSet<String> {
    let mut forbidden = BTreeSet::from([
        PRINCIPAL_CANARY.to_owned(),
        RS_SEC_13_PRINCIPAL_CANARY.to_owned(),
        RS_SEC_13_TOKEN_CANARY.to_owned(),
        RS_SEC_13_CREDENTIAL_CANARY.to_owned(),
        RS_SEC_13_IDEMPOTENCY_CANARY.to_owned(),
        RS_SEC_13_ZONE_CANARY.to_owned(),
        RS_SEC_13_LABEL_CANARY.to_owned(),
        RS_SEC_13_QUANTITY_CANARY.to_owned(),
        "registry_data".to_owned(),
        "registry_internal".to_owned(),
        "insert into".to_owned(),
        "update ".to_owned(),
        "select ".to_owned(),
        "returning".to_owned(),
        "duplicate key".to_owned(),
        "violates unique constraint".to_owned(),
        "already exists".to_owned(),
        "key (".to_owned(),
        "sqlstate".to_owned(),
        "23505".to_owned(),
    ]);
    let widget = &compiled.entities()["widget"];
    forbidden.insert(widget.physical_table.clone());
    forbidden.extend(
        widget
            .fields
            .values()
            .map(|field| field.physical_name.clone()),
    );
    let widget_names = &compiled.physical_names().entities["widget"];
    forbidden.insert(widget_names.table.clone());
    forbidden.extend(widget_names.fields.values().cloned());
    forbidden.extend(widget_names.constraints.values().cloned());
    forbidden.extend(widget_names.indexes.values().cloned());
    forbidden.extend(widget_names.policies.values().cloned());
    forbidden
}

async fn durable_counts(database: &TestDatabase, table: &str) -> DurableCounts {
    let row = database
        .admin
        .query_one(
            &format!(
                "SELECT
                   (SELECT count(*) FROM registry_data.\"{table}\"),
                   (SELECT count(*) FROM registry_internal.registry_revisions),
                   (SELECT count(*) FROM registry_internal.registry_outbox),
                   (SELECT count(*) FROM registry_internal.registry_audit),
                   (SELECT count(*) FROM registry_internal.registry_idempotency)"
            ),
            &[],
        )
        .await
        .expect("administrator can inspect isolated durable state");
    DurableCounts {
        current: row.get(0),
        revisions: row.get(1),
        outbox: row.get(2),
        audit: row.get(3),
        idempotency: row.get(4),
    }
}

async fn refusal_audit_count(database: &TestDatabase) -> i64 {
    database
        .admin
        .query_one(
            "SELECT count(*)
             FROM registry_internal.registry_audit
             WHERE convert_from(envelope, 'UTF8') LIKE '%\"phase\":\"refusal\"%'",
            &[],
        )
        .await
        .expect("administrator can inspect minimized refusal audit events")
        .get(0)
}

async fn assert_patch_preserved_omitted_field(
    database: &TestDatabase,
    table: &str,
    record_id: &str,
) {
    let rows = database
        .admin
        .query(
            "SELECT snapshot FROM registry_internal.registry_revisions
             WHERE record_revision = 2",
            &[],
        )
        .await
        .expect("administrator can inspect complete post-write revision");
    assert!(rows.iter().any(|row| {
        row.get::<_, Vec<u8>>(0)
            == br#"{"jurisdiction":"zone-a","label":"after-patch","note":null,"quantity":41}"#
                .as_slice()
    }));
    let events = database
        .admin
        .query(
            "SELECT payload FROM registry_internal.registry_outbox
             WHERE event_type = 'widget-patched'",
            &[],
        )
        .await
        .expect("administrator can inspect configured post-write event");
    assert!(events.iter().any(|row| {
        row.get::<_, Vec<u8>>(0) == br#"{"label":"after-patch","quantity":41}"#.as_slice()
    }));
    let quantity_physical = compiled_registry().entities()["widget"].fields["quantity"]
        .physical_name
        .clone();
    let quantity: i64 = database
        .admin
        .query_one(
            &format!(
                "SELECT \"{quantity_physical}\" FROM registry_data.\"{table}\"
                 WHERE record_id = $1::text::uuid"
            ),
            &[&record_id],
        )
        .await
        .expect("typed current row retains omitted field")
        .get(0);
    assert_eq!(quantity, 41);
}

async fn assert_journals_are_minimized_and_chained(
    database: &TestDatabase,
    profile: &AuditProfile,
) {
    let audit_rows = database
        .admin
        .query("SELECT envelope FROM registry_internal.registry_audit", &[])
        .await
        .expect("administrator can inspect audit envelopes");
    let mut envelopes = audit_rows
        .iter()
        .map(|row| {
            serde_json::from_slice::<AuditEnvelope>(&row.get::<_, Vec<u8>>(0))
                .expect("audit envelope is canonical platform JSON")
        })
        .collect::<Vec<_>>();
    let mut ordered = Vec::with_capacity(envelopes.len());
    let mut predecessor = None;
    while !envelopes.is_empty() {
        let position = envelopes
            .iter()
            .position(|envelope| envelope.prev_hash == predecessor)
            .expect("database audit chain has one next envelope");
        let envelope = envelopes.remove(position);
        predecessor = Some(envelope.record_hash);
        ordered.push(envelope);
    }
    let audit_lines = ordered
        .iter()
        .map(|envelope| serde_json::to_string(envelope).expect("audit envelope serializes"))
        .collect::<Vec<_>>();
    verify_jsonl_lines_with_hasher(audit_lines.iter(), &profile.chain_hasher())
        .expect("database audit envelopes form one keyed platform chain");
    let audit_text = audit_lines.join("\n");
    assert!(!audit_text.contains(PRINCIPAL_CANARY));
    assert!(!audit_text.contains(RS_SEC_13_PRINCIPAL_CANARY));
    assert!(!audit_text.contains(RS_SEC_13_TOKEN_CANARY));
    assert!(!audit_text.contains(RS_SEC_13_CREDENTIAL_CANARY));
    assert!(!audit_text.contains(RS_SEC_13_IDEMPOTENCY_CANARY));
    for record in [
        RECORD_POSITIVE,
        RECORD_PATCH,
        RECORD_RECOVERY,
        RECORD_CONCURRENT,
    ] {
        assert!(!audit_text.contains(record));
    }
    assert!(audit_text.contains("\"outcome\":\"replayed\""));
    assert!(audit_text.contains("principalReference"));
    assert!(audit_text.contains("recordReference"));

    for table_and_column in [
        ("registry_revisions", "snapshot"),
        ("registry_outbox", "payload"),
    ] {
        let rows = database
            .admin
            .query(
                &format!(
                    "SELECT {column}, record_reference FROM registry_internal.{table}",
                    column = table_and_column.1,
                    table = table_and_column.0
                ),
                &[],
            )
            .await
            .expect("administrator can inspect mutation journal");
        for row in rows {
            let payload: Vec<u8> = row.get(0);
            let reference: String = row.get(1);
            let payload = String::from_utf8_lossy(&payload);
            assert!(!payload.contains(PRINCIPAL_CANARY));
            assert!(!payload.contains(RS_SEC_13_PRINCIPAL_CANARY));
            assert!(!payload.contains(RS_SEC_13_TOKEN_CANARY));
            assert!(!payload.contains(RS_SEC_13_CREDENTIAL_CANARY));
            assert!(!payload.contains(RS_SEC_13_IDEMPOTENCY_CANARY));
            assert!(!reference.contains(PRINCIPAL_CANARY));
            assert!(!reference.contains(RS_SEC_13_PRINCIPAL_CANARY));
            assert!(!reference.contains(RS_SEC_13_TOKEN_CANARY));
            assert!(!reference.contains(RS_SEC_13_CREDENTIAL_CANARY));
            assert!(!reference.contains(RS_SEC_13_IDEMPOTENCY_CANARY));
            for record in [
                RECORD_POSITIVE,
                RECORD_PATCH,
                RECORD_RECOVERY,
                RECORD_CONCURRENT,
            ] {
                assert!(!payload.contains(record));
                assert!(!reference.contains(record));
            }
        }
    }

    let references = database
        .admin
        .query(
            "SELECT key_reference, binding_reference
             FROM registry_internal.registry_idempotency",
            &[],
        )
        .await
        .expect("administrator can inspect keyed idempotency references");
    for row in references {
        let key_reference: String = row.get(0);
        let binding_reference: String = row.get(1);
        assert!(!key_reference.contains(PRINCIPAL_CANARY));
        assert!(!key_reference.contains(RS_SEC_13_PRINCIPAL_CANARY));
        assert!(!key_reference.contains(RS_SEC_13_TOKEN_CANARY));
        assert!(!key_reference.contains(RS_SEC_13_CREDENTIAL_CANARY));
        assert!(!key_reference.contains(RS_SEC_13_IDEMPOTENCY_CANARY));
        assert!(!binding_reference.contains(PRINCIPAL_CANARY));
        assert!(!binding_reference.contains(RS_SEC_13_PRINCIPAL_CANARY));
        assert!(!binding_reference.contains(RS_SEC_13_TOKEN_CANARY));
        assert!(!binding_reference.contains(RS_SEC_13_CREDENTIAL_CANARY));
        assert!(!binding_reference.contains(RS_SEC_13_IDEMPOTENCY_CANARY));
        for record in [
            RECORD_POSITIVE,
            RECORD_PATCH,
            RECORD_RECOVERY,
            RECORD_CONCURRENT,
        ] {
            assert!(!binding_reference.contains(record));
        }
    }
}

#[test]
fn mutation_error_vocabulary_is_closed_and_value_free() {
    for error in [
        MutationError::InvalidRequest,
        MutationError::PreconditionFailed,
        MutationError::Conflict,
        MutationError::IdempotencyConflict,
        MutationError::Unavailable,
    ] {
        let rendered = error.to_string();
        assert!(!rendered.contains("registry_"));
        assert!(!rendered.contains("00000000"));
        assert!(!rendered.contains(PRINCIPAL_CANARY));
    }
}

#[test]
fn compiled_fixture_exposes_create_patch_and_configured_tombstone_plans() {
    let compiled = compiled_registry();
    assert!(compiled.routes().routes.iter().any(|route| {
        route.id == "records.widget.create" && route.operation == Operation::Create
    }));
    assert!(compiled
        .routes()
        .routes
        .iter()
        .any(|route| route.id == "records.widget.patch" && route.operation == Operation::Patch));
    assert!(compiled.routes().routes.iter().any(|route| {
        route.id == "records.widget.tombstone" && route.operation == Operation::Tombstone
    }));
    assert!(!compiled
        .routes()
        .routes
        .iter()
        .any(|route| { route.entity_id == "log" && route.operation == Operation::Tombstone }));
    assert!(!compiled
        .routes()
        .routes
        .iter()
        .any(|route| { route.entity_id == "archive" && route.operation == Operation::Tombstone }));
}
