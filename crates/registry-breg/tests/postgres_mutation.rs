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
use registry_breg::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedClaimValue,
    VerifiedRequestClaims,
};
use registry_breg::audit::RegistryAudit;
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::{parse_project_json, Operation};
use registry_breg::cursor::CursorCodec;
use registry_breg::idempotency::{IdempotencyPolicy, PermittedResponseHeader};
use registry_breg::mutation::{
    install_mutation_schema, MutationBody, MutationCoordinator, MutationError, MutationFaultPoint,
    MutationOutcome, MutationPlan, MutationRequest, PatchOperation,
};
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema, test_activation_id,
    test_package_digest, ClaimContext, PostgresRecordMutationService, PostgresRecordReadService,
    RegistryLockKey, RegistryStateTestIdentity, RowBoundaryContext,
};
use registry_breg::problem_location::{PatchMember, RequestLocation};
use registry_platform_audit::AuditProfile;
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
const BREG_SEC_13_PRINCIPAL_CANARY: &str = "breg-sec-13-principal-canary";
const BREG_SEC_13_TOKEN_CANARY: &str = "breg-sec-13-raw-token-canary";
const BREG_SEC_13_CREDENTIAL_CANARY: &str = "breg-sec-13-credential-canary";
const BREG_SEC_13_IDEMPOTENCY_CANARY: &str = "breg-sec-13-idempotency-key-conflict";
const BREG_SEC_13_ZONE_CANARY: &str = "breg-sec-13-zone-a";
const BREG_SEC_13_LABEL_CANARY: &str = "breg-sec-13-unique-label";
const BREG_SEC_13_QUANTITY_CANARY: &str = "4242";
const BREG_SEC_13_PROFILE_CANARY: &str = "breg-sec-13-access-profile-canary";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_idempotency_response_bound_matches_clean_and_upgraded_schema() {
    const EXPECTED_MAX_STORED_RESPONSE_BYTES: usize = 3 * 1024 * 1024;

    let database = TestDatabase::create(1).await;
    let (migration, migration_task) = database.connect_migration().await;
    install_mutation_schema(&migration, &database.runtime_role)
        .await
        .expect("clean mutation schema installs");
    assert_idempotency_response_body_bound(&migration, "clean", EXPECTED_MAX_STORED_RESPONSE_BYTES)
        .await;

    migration
        .batch_execute(
            "ALTER TABLE registry_internal.registry_idempotency
                 DROP CONSTRAINT registry_idempotency_response_body_bounds;
             ALTER TABLE registry_internal.registry_idempotency
                 ADD CONSTRAINT registry_idempotency_response_body_bounds CHECK (
                     response_body IS NULL OR
                     (octet_length(response_body) > 0 AND octet_length(response_body) <= 2097152)
                 )",
        )
        .await
        .expect("test restores the legacy 2 MiB response constraint");
    assert!(
        insert_idempotency_response(
            &migration,
            "legacy-over-two-mib",
            &json_body_with_size(2 * 1024 * 1024 + 1),
        )
        .await
        .is_err(),
        "the legacy fixture must reject a response above 2 MiB"
    );

    install_mutation_schema(&migration, &database.runtime_role)
        .await
        .expect("mutation schema reconciles the legacy response constraint");
    assert_idempotency_response_body_bound(
        &migration,
        "upgraded",
        EXPECTED_MAX_STORED_RESPONSE_BYTES,
    )
    .await;

    migration_task.abort();
    database.cleanup().await;
}

async fn assert_idempotency_response_body_bound(
    migration: &tokio_postgres::Client,
    key_prefix: &str,
    expected_maximum: usize,
) {
    let maximum_key = format!("{key_prefix}-maximum");
    insert_idempotency_response(
        migration,
        &maximum_key,
        &json_body_with_size(expected_maximum),
    )
    .await
    .expect("the configured maximum stored response is admitted");
    assert!(
        insert_idempotency_response(
            migration,
            &format!("{key_prefix}-oversized"),
            &json_body_with_size(expected_maximum + 1),
        )
        .await
        .is_err(),
        "one byte above the configured maximum must be refused"
    );
    migration
        .execute(
            "DELETE FROM registry_internal.registry_idempotency WHERE key_reference = $1",
            &[&maximum_key],
        )
        .await
        .expect("accepted boundary fixture is removed before constraint replacement");
}

async fn insert_idempotency_response(
    migration: &tokio_postgres::Client,
    key_reference: &str,
    body: &[u8],
) -> Result<u64, tokio_postgres::Error> {
    let response_headers = Vec::<u8>::new();
    migration
        .execute(
            "INSERT INTO registry_internal.registry_idempotency (
                 key_reference, binding_reference, result_kind,
                 record_reference, record_revision, response_status,
                 response_body, response_headers, caller_issuer, caller_subject, key_scope, idempotency_key, receipt_expires_at
             ) VALUES ($1, 'binding', 'record', 'record', 1, 200, $2, $3,
                       'urn:test:issuer', 'test-subject', 'mutation', $1, transaction_timestamp() + interval '7 days')",
            &[&key_reference, &body, &response_headers],
        )
        .await
}

/// The predecessor's idempotency table admits no release receipt, and
/// `CREATE TABLE IF NOT EXISTS` leaves its constraints in place, so schema
/// install replaces the result kind and result shape constraints.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_idempotency_release_kind_installs_on_the_predecessor_schema() {
    let database = TestDatabase::create(1).await;
    let (migration, migration_task) = database.connect_migration().await;
    install_mutation_schema(&migration, &database.runtime_role)
        .await
        .expect("clean mutation schema installs");
    insert_idempotency_release(&migration, "clean-release")
        .await
        .expect("a clean schema admits a release receipt");

    migration
        .batch_execute(
            "DELETE FROM registry_internal.registry_idempotency;
             ALTER TABLE registry_internal.registry_idempotency
                 DROP CONSTRAINT registry_idempotency_result_kind_values,
                 DROP CONSTRAINT registry_idempotency_result_shape;
             ALTER TABLE registry_internal.registry_idempotency
                 ADD CONSTRAINT registry_idempotency_result_kind_values
                     CHECK (result_kind IN ('record', 'batch', 'application', 'immediate_action', 'erased')),
                 ADD CONSTRAINT registry_idempotency_result_shape CHECK (
                     (result_kind = 'record' AND record_reference IS NOT NULL
                         AND record_revision IS NOT NULL AND result_count IS NULL
                         AND proposal_version IS NULL)
                     OR
                     (result_kind = 'batch' AND record_reference IS NULL
                         AND record_revision IS NULL AND result_count IS NOT NULL
                         AND proposal_version IS NULL)
                     OR
                     (result_kind = 'application' AND record_reference IS NOT NULL
                         AND record_revision IS NOT NULL AND result_count IS NOT NULL
                         AND result_count BETWEEN 1 AND 16
                         AND proposal_version IS NOT NULL)
                     OR
                     (result_kind = 'immediate_action' AND record_reference IS NULL
                         AND record_revision IS NULL AND result_count IS NOT NULL
                         AND proposal_version IS NULL)
                     OR
                     (result_kind = 'erased' AND record_reference IS NULL
                         AND record_revision IS NULL AND result_count IS NULL
                         AND proposal_version IS NULL)
                 )",
        )
        .await
        .expect("test restores the predecessor's result kind and shape constraints");
    assert!(
        insert_idempotency_release(&migration, "predecessor-release")
            .await
            .is_err(),
        "the predecessor fixture must refuse a release receipt"
    );

    install_mutation_schema(&migration, &database.runtime_role)
        .await
        .expect("mutation schema replaces the predecessor's result constraints");
    insert_idempotency_release(&migration, "upgraded-release")
        .await
        .expect("an upgraded schema admits a release receipt");
    assert!(
        migration
            .execute(
                "INSERT INTO registry_internal.registry_idempotency (
                     key_reference, binding_reference, result_kind,
                     response_status, response_body, response_headers, caller_issuer, caller_subject, key_scope, idempotency_key, receipt_expires_at
                 ) VALUES ('upgraded-release-without-record', 'binding', 'release', 200, '{}', '',
                           'urn:test:issuer', 'test-subject', 'mutation', 'upgraded-release-without-record', transaction_timestamp() + interval '7 days')",
                &[],
            )
            .await
            .is_err(),
        "an upgraded schema still refuses a release receipt without its record reference"
    );

    migration_task.abort();
    database.cleanup().await;
}

async fn insert_idempotency_release(
    migration: &tokio_postgres::Client,
    key_reference: &str,
) -> Result<u64, tokio_postgres::Error> {
    migration
        .execute(
            "INSERT INTO registry_internal.registry_idempotency (
                 key_reference, binding_reference, result_kind,
                 record_reference, record_revision, response_status,
                 response_body, response_headers, caller_issuer, caller_subject, key_scope, idempotency_key, receipt_expires_at
             ) VALUES ($1, 'binding', 'release', 'release', 1, 200, '{}', '',
                       'urn:test:issuer', 'test-subject', 'mutation', $1, transaction_timestamp() + interval '7 days')",
            &[&key_reference],
        )
        .await
}

fn json_body_with_size(size: usize) -> Vec<u8> {
    const PREFIX: &[u8] = b"{\"value\":\"";
    const SUFFIX: &[u8] = b"\"}";
    assert!(size >= PREFIX.len() + SUFFIX.len());
    let mut body = Vec::with_capacity(size);
    body.extend_from_slice(PREFIX);
    body.resize(size - SUFFIX.len(), b'x');
    body.extend_from_slice(SUFFIX);
    assert_eq!(body.len(), size);
    body
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_mutation_is_audited_atomic_typed_and_exactly_replayable() {
    let database = TestDatabase::create(10).await;
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = compiled_registry();
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("migration installs the complete compiler-owned PostgreSQL schema");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "package-mutation-1",
        },
    )
    .await
    .expect("migration initializes the active package after exact schema install");
    migration_task.abort();

    let pool = database
        .runtime_config
        .build_pool()
        .expect("bounded runtime pool builds");
    let profile = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x5a; 32].into())
            .expect("test owns a strong keyed audit profile"),
    );
    let coordinator = MutationCoordinator::new(
        RegistryLockKey::derive("mutation-registry").expect("lock id is bounded"),
        Duration::from_secs(2),
        identity.clone(),
        INSTANCE_ID,
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
    assert_eq!(
        invalid,
        Err(MutationError::InvalidRequestAt(
            RequestLocation::data_field("quantity")
        ))
    );
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
                audit: before.audit + 2,
                ..before
            },
            "fault {fault:?} retains only its attempt and the unfinished answer to it"
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
                representation: registry_breg::record_profile::RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
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

    let before_changed_representation = durable_counts(&database, table).await;
    let before_changed_representation_refusals = refusal_audit_count(&database).await;
    let changed_representation = coordinator
        .execute(
            &mut client,
            MutationRequest {
                representation: registry_breg::record_profile::RecordRepresentation::JsonLd,
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
        changed_representation,
        before_changed_representation,
        before_changed_representation_refusals,
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

    // Keys are per caller: the same key from another principal is that
    // principal's own unspent key, so the request executes as a fresh write
    // and is refused only because the record it would create already exists.
    let other_principal = mutation_claims(&compiled, "different-principal", "zone-a");
    let before_principal = durable_counts(&database, table).await;
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
    assert_eq!(changed_principal, Err(MutationError::Conflict));
    assert_audited_refusal_only(before_principal, durable_counts(&database, table).await);

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
                "\"breg-noncanonical-regression\"",
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
    let patched_body: Value =
        serde_json::from_slice(patched.response().body()).expect("patch response is JSON");
    assert_eq!(patched_body["data"]["domainData"]["label"], "after-patch");
    assert_eq!(patched_body["data"]["domainData"]["quantity"], 41);
    assert_eq!(patched_body["data"]["recordIdentifier"], patch_id);
    assert_eq!(patched_body["data"]["revisionIdentifier"], "2");
    assert_snapshot_reference(&patched_body["data"]["snapshot"]);
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
                representation: registry_breg::record_profile::RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await;
    assert_eq!(
        forbidden_field,
        Err(MutationError::InvalidRequestAt(
            RequestLocation::patch_operation(0, Some(PatchMember::Path))
        ))
    );
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
                representation: registry_breg::record_profile::RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
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
                representation: registry_breg::record_profile::RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
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
    changed_identity.package_digest = test_package_digest("package-mutation-2");
    changed_identity.activation_id = test_activation_id("package-mutation-2");
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_state
             SET active_package_digest = $1, active_activation_id = $2::text::uuid
             WHERE singleton",
            &[
                &changed_identity.package_digest,
                &changed_identity.activation_id,
            ],
        )
        .await
        .expect("test can simulate activation of a same-schema package revision");
    let changed_package_coordinator = MutationCoordinator::new(
        RegistryLockKey::derive("mutation-registry").expect("lock id is bounded"),
        Duration::from_secs(2),
        changed_identity,
        INSTANCE_ID,
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

    assert_journals_are_minimized_and_paired(&database).await;
    database.cleanup().await;
}

async fn prepared_mutation_registry(
    database: &TestDatabase,
) -> (
    registry_breg::CompiledRegistry,
    registry_breg::postgres::ExpectedRegistryIdentity,
    registry_breg::postgres::RuntimePool,
) {
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = compiled_registry();
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("migration installs the complete compiler-owned PostgreSQL schema");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "package-mutation-1",
        },
    )
    .await
    .expect("migration initializes the active package after exact schema install");
    migration_task.abort();
    let pool = database
        .runtime_config
        .build_pool()
        .expect("bounded runtime pool builds");
    (compiled, identity, pool)
}

fn audited_coordinator(
    database: &TestDatabase,
    identity: &registry_breg::postgres::ExpectedRegistryIdentity,
) -> MutationCoordinator {
    MutationCoordinator::new(
        RegistryLockKey::derive("mutation-registry").expect("lock id is bounded"),
        Duration::from_secs(2),
        identity.clone(),
        INSTANCE_ID,
        database.audit(
            AuditProfile::production_from_secret_bytes(vec![0x5a; 32].into())
                .expect("test owns a strong keyed audit profile"),
        ),
    )
}

/// A refused request entry stops the mutation before any protected I/O. A
/// refused response entry comes after the commit, so the effect is durable
/// while the caller receives the audit-unavailable refusal; a restarted
/// process then releases that committed result only as an audited replay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_mutation_audit_refusals_fail_closed_around_the_commit() {
    let database = TestDatabase::create(4).await;
    let (compiled, identity, pool) = prepared_mutation_registry(&database).await;
    let create_plan = MutationPlan::from_compiled(&compiled, "records.widget.create")
        .expect("create plan comes from the compiled inventory");
    let claims = mutation_claims(&compiled, PRINCIPAL_CANARY, "zone-a");
    let table = &compiled.entities()["widget"].physical_table;
    let mut client = pool
        .get_for_test()
        .await
        .expect("runtime connection is available");

    let before = durable_counts(&database, table).await;
    database.audit_capture().fail_after(0);
    let refused = audited_coordinator(&database, &identity)
        .execute(
            &mut client,
            create_request(
                &create_plan,
                "refused-request-entry",
                &claims,
                RECORD_RECOVERY,
                "refused-request-label",
                Some(3),
            ),
        )
        .await;
    assert_eq!(refused, Err(MutationError::Unavailable));
    assert_eq!(
        durable_counts(&database, table).await,
        before,
        "a refused request entry leaves no record, revision, outbox, receipt, or entry"
    );
    database.audit_capture().restore();

    database
        .audit_capture()
        .fail_on(registry_breg::audit::AUDIT_SCHEMA, "terminal");
    let crash_gap = audited_coordinator(&database, &identity)
        .execute(
            &mut client,
            create_request(
                &create_plan,
                "refused-response-entry",
                &claims,
                RECORD_RECOVERY,
                "committed-label",
                Some(4),
            ),
        )
        .await;
    assert_eq!(crash_gap, Err(MutationError::Unavailable));
    let after_gap = durable_counts(&database, table).await;
    assert_eq!(
        after_gap,
        DurableCounts {
            current: before.current + 1,
            revisions: before.revisions + 1,
            outbox: before.outbox + 1,
            audit: before.audit + 1,
            idempotency: before.idempotency + 1,
            commits: before.commits + 1,
            commit_members: before.commit_members + 1,
        },
        "the effect commits before its response entry, which the destination refused"
    );
    let entries = database.audit_entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["phase"], "request");
    assert_eq!(entries[0]["record"]["phase"], "attempt");
    database.audit_capture().restore();

    let replay = audited_coordinator(&database, &identity)
        .execute(
            &mut client,
            create_request(
                &create_plan,
                "refused-response-entry",
                &claims,
                RECORD_RECOVERY,
                "committed-label",
                Some(4),
            ),
        )
        .await
        .expect("a restarted process replays the committed result");
    assert!(replay.replayed());
    assert_audited_replay_only(after_gap, durable_counts(&database, table).await);
    let entries = database.audit_entries();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[1]["phase"], "request");
    assert_eq!(entries[2]["phase"], "response");
    assert_eq!(entries[2]["record"]["outcome"], "replayed");
    assert_eq!(entries[1]["correlation"], entries[2]["correlation"]);

    drop(client);
    drop(pool);
    database.cleanup().await;
}

/// A COMMIT that fails does not prove the transaction rolled back, so the
/// attempt is answered `unfinished`, never refused: a lost acknowledgement of a
/// durable mutation must not leave a journal that says the mutation was
/// refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_mutation_commit_failure_is_answered_unfinished_not_refused() {
    let database = TestDatabase::create(4).await;
    let (compiled, identity, pool) = prepared_mutation_registry(&database).await;
    let create_plan = MutationPlan::from_compiled(&compiled, "records.widget.create")
        .expect("create plan comes from the compiled inventory");
    let claims = mutation_claims(&compiled, PRINCIPAL_CANARY, "zone-a");
    let table = &compiled.entities()["widget"].physical_table;
    let mut client = pool
        .get_for_test()
        .await
        .expect("runtime connection is available");
    database
        .admin
        .batch_execute(&format!(
            "CREATE FUNCTION public.test_refuse_mutation_commit()
               RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN RAISE EXCEPTION 'test refuses this mutation commit'; END $$;
             GRANT EXECUTE ON FUNCTION public.test_refuse_mutation_commit() TO PUBLIC;
             CREATE CONSTRAINT TRIGGER test_refuse_mutation_commit
               AFTER INSERT ON registry_data.\"{table}\"
               DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
               EXECUTE FUNCTION public.test_refuse_mutation_commit();"
        ))
        .await
        .expect("administrator installs the deferred commit refusal");

    let before = durable_counts(&database, table).await;
    let failed = audited_coordinator(&database, &identity)
        .execute(
            &mut client,
            create_request(
                &create_plan,
                "commit-refused-create",
                &claims,
                RECORD_RECOVERY,
                "commit-refused-label",
                Some(5),
            ),
        )
        .await;
    assert_eq!(failed, Err(MutationError::Unavailable));
    database
        .admin
        .batch_execute(&format!(
            "DROP TRIGGER test_refuse_mutation_commit ON registry_data.\"{table}\";
             DROP FUNCTION public.test_refuse_mutation_commit();"
        ))
        .await
        .expect("administrator removes the deferred commit refusal");

    let after = durable_counts(&database, table).await;
    assert_eq!(
        after.current, before.current,
        "the refused commit rolled back"
    );
    let journal = database
        .audit_entries()
        .iter()
        .map(|entry| {
            (
                entry["phase"].as_str().unwrap_or_default().to_owned(),
                entry["record"]["phase"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                entry["correlation"].to_string(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(journal.len(), 2, "{journal:?}");
    {
        let pair = &journal[..];
        assert_eq!(
            (pair[0].0.as_str(), pair[0].1.as_str()),
            ("request", "attempt")
        );
        assert_eq!(
            (pair[1].0.as_str(), pair[1].1.as_str()),
            ("response", "unfinished"),
            "an unproven commit is answered unfinished, never refused"
        );
        assert_eq!(pair[0].2, pair[1].2);
    }
    assert_eq!(refusal_audit_count(&database).await, 0);

    drop(client);
    drop(pool);
    database.cleanup().await;
}

/// Two runtimes over one database each own their audit writer. Their
/// concurrent mutations commit independently, and every request entry is
/// answered by exactly one response entry carrying its correlation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_runtimes_audit_concurrent_mutations_through_their_own_writers() {
    const PER_RUNTIME: usize = 6;
    let database = TestDatabase::create(8).await;
    let (compiled, identity, pool) = prepared_mutation_registry(&database).await;
    let create_plan = MutationPlan::from_compiled(&compiled, "records.widget.create")
        .expect("create plan comes from the compiled inventory");
    let claims = mutation_claims(&compiled, PRINCIPAL_CANARY, "zone-a");
    let table = &compiled.entities()["widget"].physical_table;
    let before = durable_counts(&database, table).await;

    let run = |runtime: usize, coordinator: MutationCoordinator| {
        let pool = pool.clone();
        let create_plan = &create_plan;
        let claims = &claims;
        async move {
            let mut client = pool
                .get_for_test()
                .await
                .expect("runtime connection is available");
            for index in 0..PER_RUNTIME {
                let key = format!("runtime-{runtime}-create-{index}");
                let label = format!("concurrent-label-{runtime}-{index}");
                let outcome = coordinator
                    .execute(
                        &mut client,
                        create_request(
                            create_plan,
                            &key,
                            claims,
                            RECORD_CONCURRENT,
                            &label,
                            Some(1),
                        ),
                    )
                    .await
                    .expect("each runtime commits its own mutation");
                assert!(!outcome.replayed());
            }
        }
    };
    tokio::join!(
        run(0, audited_coordinator(&database, &identity)),
        run(1, audited_coordinator(&database, &identity)),
    );

    let created = i64::try_from(2 * PER_RUNTIME).expect("count fits i64");
    let after = durable_counts(&database, table).await;
    assert_eq!(after.current, before.current + created);
    assert_eq!(after.revisions, before.revisions + created);
    assert_eq!(after.idempotency, before.idempotency + created);
    assert_eq!(after.audit, before.audit + 2 * created);
    let entries = database.audit_entries();
    let mut correlations = std::collections::BTreeMap::<String, Vec<String>>::new();
    for entry in &entries {
        correlations
            .entry(
                entry["correlation"]
                    .as_str()
                    .expect("correlation")
                    .to_owned(),
            )
            .or_default()
            .push(entry["phase"].as_str().expect("phase").to_owned());
    }
    assert_eq!(correlations.len(), 2 * PER_RUNTIME);
    for phases in correlations.values() {
        assert_eq!(phases, &["request".to_owned(), "response".to_owned()]);
    }

    drop(pool);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_row_boundary_write_refusals_are_safe_audited_and_atomic() {
    let database = TestDatabase::create(8).await;
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("migration installs schema");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "package-row-boundary-refusal",
        },
    )
    .await
    .expect("migration initializes state");
    migration_task.abort();

    let pool = database.runtime_config.build_pool().expect("pool builds");
    let profile = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x45; 32].into())
            .expect("test owns keyed audit"),
    );
    let app = mutation_router(
        pool.clone(),
        compiled.clone(),
        identity,
        RegistryLockKey::derive("boundary-refusal-registry").expect("lock id is bounded"),
        profile,
        None,
    );
    let table = compiled.entities()["widget"].physical_table.clone();
    let claims = api_claims("case-management", Some("zone-a"));

    let before_create = durable_counts(&database, &table).await;
    let before_create_refusals = refusal_audit_count(&database).await;
    let refused_create = send(
        &app,
        Method::POST,
        "/v1/records/widgets",
        Some(claims.clone()),
        &[
            ("content-type", "application/json"),
            ("idempotency-key", "boundary-create-refusal"),
        ],
        br#"{"data":{"jurisdiction":"zone-b","label":"concealed-create-value","quantity":1}}"#
            .to_vec(),
    )
    .await;
    assert_eq!(refused_create.status(), StatusCode::PRECONDITION_FAILED);
    let refused_create = body_json(refused_create).await;
    assert_eq!(refused_create["code"], "precondition.failed");
    assert_eq!(
        refused_create["detail"],
        "The mutation precondition failed."
    );
    assert!(!refused_create.to_string().contains("zone-b"));
    assert_eq!(
        durable_counts(&database, &table).await,
        DurableCounts {
            audit: before_create.audit + 2,
            ..before_create
        }
    );
    assert_eq!(
        refusal_audit_count(&database).await,
        before_create_refusals + 1
    );
    assert!(!database
        .audit_records()
        .iter()
        .any(|record| record.to_string().contains("concealed-create-value")));

    let created = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/records/widgets",
            Some(claims.clone()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "boundary-valid-seed"),
            ],
            br#"{"data":{"jurisdiction":"zone-a","label":"boundary-seed","quantity":1}}"#.to_vec(),
        )
        .await,
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED);
    let record_id = created.body["data"]["recordIdentifier"]
        .as_str()
        .expect("created record id")
        .to_owned();

    let before_patch = durable_counts(&database, &table).await;
    let before_patch_refusals = refusal_audit_count(&database).await;
    let refused_patch = send(
        &app,
        Method::PATCH,
        &format!("/v1/records/widgets/{record_id}"),
        Some(claims.clone()),
        &[
            ("content-type", "application/json-patch+json"),
            ("idempotency-key", "boundary-patch-refusal"),
            ("if-match", &created.etag),
        ],
        br#"[{"op":"replace","path":"/data/jurisdiction","value":"zone-b"}]"#.to_vec(),
    )
    .await;
    assert_eq!(refused_patch.status(), StatusCode::PRECONDITION_FAILED);
    let refused_patch = body_json(refused_patch).await;
    assert_eq!(refused_patch["code"], "precondition.failed");
    assert!(!refused_patch.to_string().contains("zone-b"));
    assert_eq!(
        durable_counts(&database, &table).await,
        DurableCounts {
            audit: before_patch.audit + 2,
            ..before_patch
        }
    );
    assert_eq!(
        refusal_audit_count(&database).await,
        before_patch_refusals + 1
    );
    assert!(!database
        .audit_records()
        .iter()
        .any(|record| record.to_string().contains("zone-b")));
    let preserved = response_parts(
        send(
            &app,
            Method::GET,
            &format!("/v1/records/widgets/{record_id}"),
            Some(claims.clone()),
            &[],
            Vec::new(),
        )
        .await,
    )
    .await;
    assert_eq!(preserved.status, StatusCode::OK);
    assert_eq!(preserved.etag, created.etag);
    assert_eq!(preserved.body["data"]["revisionIdentifier"], "1");
    assert_eq!(
        preserved.body["data"]["domainData"]["jurisdiction"],
        "zone-a"
    );
    assert_eq!(
        preserved.body["data"]["domainData"]["label"],
        "boundary-seed"
    );

    database
        .admin
        .batch_execute(&format!(
            "REVOKE UPDATE ON TABLE registry_data.\"{table}\" FROM \"{}\";",
            database.runtime_role.as_str()
        ))
        .await
        .expect("isolated runtime role loses only this table privilege");
    let before_privilege_failure = durable_counts(&database, &table).await;
    let privilege_failure = send(
        &app,
        Method::PATCH,
        &format!("/v1/records/widgets/{record_id}"),
        Some(claims),
        &[
            ("content-type", "application/json-patch+json"),
            ("idempotency-key", "ordinary-privilege-failure"),
            ("if-match", &created.etag),
        ],
        br#"[{"op":"replace","path":"/data/label","value":"still-authorized"}]"#.to_vec(),
    )
    .await;
    assert_eq!(privilege_failure.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body_json(privilege_failure).await["code"],
        "service.unavailable"
    );
    assert_eq!(
        durable_counts(&database, &table).await,
        DurableCounts {
            audit: before_privilege_failure.audit + 2,
            ..before_privilege_failure
        }
    );

    drop(app);
    drop(pool);
    database.cleanup().await;
}

/// A row-boundary refusal must not become an existence or uniqueness oracle,
/// and a batch carrying one out-of-boundary item must write nothing at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_row_boundary_refusals_reveal_no_hidden_row_and_batches_write_nothing() {
    let database = TestDatabase::create(8).await;
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = Arc::new(row_boundary_batch_registry());
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("migration installs schema");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        RegistryStateTestIdentity {
            package_id: "row-boundary-batch-registry",
            database_id: DATABASE_ID,
            label: "package-row-boundary-oracles",
        },
    )
    .await
    .expect("migration initializes state");
    migration_task.abort();
    let pool = database.runtime_config.build_pool().expect("pool builds");
    let audit = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x47; 32].into())
            .expect("test owns keyed audit"),
    );
    let app = mutation_router(
        pool.clone(),
        compiled.clone(),
        identity,
        RegistryLockKey::derive("row-boundary-oracles").expect("lock id is bounded"),
        audit,
        None,
    );
    let table = compiled.entities()["widget"].physical_table.clone();
    let zone_a = api_claims("case-management", Some("zone-a"));
    let zone_b = api_claims("case-management", Some("zone-b"));
    let json_headers = |key: &'static str| {
        vec![
            ("content-type", "application/json"),
            ("idempotency-key", key),
        ]
    };

    // A row only zone-b may see, carrying the unique label the probes reuse.
    let hidden = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/records/widgets",
            Some(zone_b.clone()),
            &json_headers("oracle-hidden-seed"),
            br#"{"data":{"jurisdiction":"zone-b","label":"hidden-unique-label","quantity":1}}"#
                .to_vec(),
        )
        .await,
    )
    .await;
    assert_eq!(hidden.status, StatusCode::CREATED);
    let hidden_id = hidden.body["data"]["recordIdentifier"]
        .as_str()
        .expect("created record id")
        .to_owned();

    // A batch with one in-boundary and one out-of-boundary create answers
    // the value-free precondition refusal and commits neither item.
    let before_batch = durable_counts(&database, &table).await;
    let before_batch_refusals = refusal_audit_count(&database).await;
    let refused_batch = problem(
        send(
            &app,
            Method::POST,
            "/v1/records/widgets:batch",
            Some(zone_a.clone()),
            &json_headers("oracle-batch-refusal"),
            serde_json::to_vec(&json!({"items":[
                {"operation":"create","data":{"jurisdiction":"zone-a","label":"batch-in-boundary","quantity":1}},
                {"operation":"create","data":{"jurisdiction":"zone-b","label":"batch-concealed-value","quantity":1}}
            ]}))
            .unwrap(),
        )
        .await,
    )
    .await;
    assert_eq!(refused_batch.0, StatusCode::PRECONDITION_FAILED);
    let refused_batch_body: Value = serde_json::from_slice(&refused_batch.1).unwrap();
    assert_eq!(refused_batch_body["code"], "precondition.failed");
    let refused_batch_text = String::from_utf8(refused_batch.1.clone()).unwrap();
    for concealed in ["zone-b", "batch-concealed-value", "batch-in-boundary"] {
        assert!(
            !refused_batch_text.contains(concealed),
            "{refused_batch_text}"
        );
    }
    assert_audited_refusal_only(before_batch, durable_counts(&database, &table).await);
    assert_eq!(
        refusal_audit_count(&database).await,
        before_batch_refusals + 1
    );
    assert!(!database
        .audit_records()
        .iter()
        .any(|record| record.to_string().contains("batch-concealed-value")));

    // A patch on a row outside the boundary is absent, byte for byte the same
    // answer as a record that does not exist, even with the row's own ETag
    // and a patch that would move it inside the caller's boundary.
    let patch = |key: &'static str, record_id: String| {
        let app = app.clone();
        let claims = zone_a.clone();
        let etag = hidden.etag.clone();
        async move {
            send(
                &app,
                Method::PATCH,
                &format!("/v1/records/widgets/{record_id}"),
                Some(claims),
                &[
                    ("content-type", "application/json-patch+json"),
                    ("idempotency-key", key),
                    ("if-match", &etag),
                ],
                br#"[{"op":"replace","path":"/data/jurisdiction","value":"zone-a"}]"#.to_vec(),
            )
            .await
        }
    };
    let before_hidden_patch = durable_counts(&database, &table).await;
    let hidden_patch = problem(patch("oracle-hidden-patch", hidden_id.clone()).await).await;
    let absent_patch =
        problem(patch("oracle-absent-patch", Uuid::new_v4().to_string()).await).await;
    // A write names its target by a guarded ETag, so a row the caller cannot
    // see answers the same precondition refusal as a row that does not exist.
    assert_eq!(hidden_patch.0, StatusCode::PRECONDITION_FAILED);
    assert_identical_problems(&hidden_patch, &absent_patch);
    assert_eq!(
        durable_counts(&database, &table).await,
        DurableCounts {
            audit: before_hidden_patch.audit + 4,
            ..before_hidden_patch
        }
    );
    let read = |record_id: String| {
        let app = app.clone();
        let claims = zone_a.clone();
        async move {
            send(
                &app,
                Method::GET,
                &format!("/v1/records/widgets/{record_id}"),
                Some(claims),
                &[],
                Vec::new(),
            )
            .await
        }
    };
    let hidden_read = problem(read(hidden_id.clone()).await).await;
    let absent_read = problem(read(Uuid::new_v4().to_string()).await).await;
    assert_eq!(hidden_read.0, StatusCode::NOT_FOUND);
    assert_identical_problems(&hidden_read, &absent_read);

    // Creating an out-of-boundary row whose unique label collides with the
    // hidden row is refused by the boundary first: it answers exactly what a
    // colliding-free out-of-boundary create answers, never a conflict.
    let create = |key: &'static str, label: &'static str| {
        let app = app.clone();
        let claims = zone_a.clone();
        async move {
            send(
                &app,
                Method::POST,
                "/v1/records/widgets",
                Some(claims),
                &[
                    ("content-type", "application/json"),
                    ("idempotency-key", key),
                ],
                serde_json::to_vec(&json!({"data":{
                    "jurisdiction":"zone-b","label":label,"quantity":1
                }}))
                .unwrap(),
            )
            .await
        }
    };
    let before_unique = durable_counts(&database, &table).await;
    let colliding = problem(create("oracle-colliding-create", "hidden-unique-label").await).await;
    let fresh = problem(create("oracle-fresh-create", "fresh-unique-label").await).await;
    assert_eq!(colliding.0, StatusCode::PRECONDITION_FAILED);
    assert_identical_problems(&colliding, &fresh);
    let colliding_batch = problem(
        send(
            &app,
            Method::POST,
            "/v1/records/widgets:batch",
            Some(zone_a.clone()),
            &json_headers("oracle-colliding-batch"),
            serde_json::to_vec(&json!({"items":[
                {"operation":"create","data":{"jurisdiction":"zone-b","label":"hidden-unique-label","quantity":1}}
            ]}))
            .unwrap(),
        )
        .await,
    )
    .await;
    assert_eq!(colliding_batch.0, StatusCode::PRECONDITION_FAILED);
    assert_eq!(
        durable_counts(&database, &table).await,
        DurableCounts {
            audit: before_unique.audit + 6,
            ..before_unique
        }
    );

    // The control: inside the boundary the same label is a real conflict, so
    // the refusals above were not answered by an absent constraint.
    let conflict = send(
        &app,
        Method::POST,
        "/v1/records/widgets",
        Some(zone_b.clone()),
        &json_headers("oracle-in-boundary-conflict"),
        br#"{"data":{"jurisdiction":"zone-b","label":"hidden-unique-label","quantity":2}}"#
            .to_vec(),
    )
    .await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);

    let listed = response_parts(
        send(
            &app,
            Method::GET,
            &format!("/v1/records/widgets/{hidden_id}"),
            Some(zone_b),
            &[],
            Vec::new(),
        )
        .await,
    )
    .await;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.etag, hidden.etag);
    assert_eq!(listed.body["data"]["domainData"]["jurisdiction"], "zone-b");

    drop(app);
    drop(pool);
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
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "package-http-mutation-1",
        },
    )
    .await
    .expect("migration initializes state");
    migration_task.abort();

    let pool = database.runtime_config.build_pool().expect("pool builds");
    let profile = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x6b; 32].into())
            .expect("test owns keyed audit"),
    );
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
    let breg_sec_13_claims = api_claims_with_principal_and_scopes(
        BREG_SEC_13_PRINCIPAL_CANARY,
        "case-management",
        Some(BREG_SEC_13_ZONE_CANARY),
        BTreeSet::from(["breg-sec-13-scope-canary".to_owned()]),
    );

    let operator_openapi = body_json(
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
    assert!(operator_openapi["paths"]["/v1/records/widgets"]
        .get("post")
        .is_some());
    assert_eq!(
        operator_openapi["paths"]["/v1/records/widgets"]["post"]["security"],
        json!([{"bearerAuth": []}])
    );
    assert_eq!(
        query_parameter_names(
            &operator_openapi["paths"]["/v1/records/widgets"]["post"]["parameters"]
        ),
        ["Accept", "Idempotency-Key", "accessProfile", "traceparent"]
    );
    assert!(
        operator_openapi["paths"]["/v1/records/widgets"]["post"]["responses"]["201"]["headers"]
            .get("Location")
            .is_some()
    );
    assert!(operator_openapi["paths"]["/v1/records/widgets/{record_id}"]
        .get("patch")
        .is_some());
    assert_eq!(
        query_parameter_names(
            &operator_openapi["paths"]["/v1/records/widgets/{record_id}"]["patch"]["parameters"]
        ),
        [
            "Accept",
            "Idempotency-Key",
            "If-Match",
            "accessProfile",
            "record_id",
            "traceparent"
        ]
    );
    assert!(
        operator_openapi["paths"]["/v1/records/widgets/{record_id}"]["patch"]["requestBody"]
            ["content"]
            .get("application/json-patch+json")
            .is_some()
    );
    assert!(
        operator_openapi["paths"]["/v1/records/widgets/{record_id}"]["patch"]["responses"]["428"]
            ["content"]["application/problem+json"]["schema"]
            .get("$ref")
            .is_some()
    );
    assert!(operator_openapi["paths"]["/v1/records/widgets/{record_id}"]
        .get("delete")
        .is_some());
    assert!(operator_openapi["paths"].get("/v1/records/logs").is_none());

    let case_openapi = body_json(
        send(
            &app,
            Method::GET,
            "/openapi.json?accessProfile=case-operator",
            Some(claims.clone()),
            &[],
            Vec::new(),
        )
        .await,
    )
    .await;
    assert!(case_openapi["paths"]["/v1/records/logs"]
        .get("post")
        .is_some());
    assert!(case_openapi["paths"]
        .get("/v1/records/logs/{record_id}")
        .and_then(|path| path.get("patch"))
        .is_none());
    assert!(case_openapi["paths"]
        .get("/v1/records/logs/{record_id}")
        .and_then(|path| path.get("delete"))
        .is_none());
    assert!(case_openapi["paths"]
        .get("/v1/records/archives/{record_id}")
        .and_then(|path| path.get("delete"))
        .is_none());
    assert!(case_openapi["paths"].get("/v1/records/widgets").is_none());

    let operator_metadata = body_json(
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
    let operator_entities = operator_metadata["entities"]
        .as_array()
        .expect("operator metadata entities");
    let operator_operations = |entity_id: &str| {
        operator_entities
            .iter()
            .find(|entity| entity["id"] == entity_id)
            .and_then(|entity| entity["operations"].as_array())
            .expect("operator entity metadata operations")
    };
    assert!(operator_operations("widget")
        .iter()
        .any(|operation| operation["operation"] == "tombstone"));
    assert!(!operator_entities.iter().any(|entity| entity["id"] == "log"));

    let case_metadata = body_json(
        send(
            &app,
            Method::GET,
            "/v1/registry?accessProfile=case-operator",
            Some(claims.clone()),
            &[],
            Vec::new(),
        )
        .await,
    )
    .await;
    let case_entities = case_metadata["entities"]
        .as_array()
        .expect("case metadata entities");
    let case_operations = |entity_id: &str| {
        case_entities
            .iter()
            .find(|entity| entity["id"] == entity_id)
            .and_then(|entity| entity["operations"].as_array())
            .expect("case entity metadata operations")
    };
    assert!(!case_operations("log")
        .iter()
        .any(|operation| operation["operation"] == "tombstone"));
    assert!(!case_operations("archive")
        .iter()
        .any(|operation| operation["operation"] == "tombstone"));

    let create_body =
        br#"{"data":{"jurisdiction":"zone-a","label":"http-created","quantity":3}}"#.to_vec();
    for (label, headers, body, expected, code, field_path) in [
        (
            "missing idempotency",
            vec![("content-type", "application/json")],
            create_body.clone(),
            StatusCode::BAD_REQUEST,
            "request.invalid",
            Some("Idempotency-Key"),
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
            None,
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
            None,
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
        let body = body_json(response).await;
        assert_eq!(body["code"], code, "{label}");
        match field_path {
            // A missing required header names itself in `fieldPath` so the fix
            // does not require reading the generated OpenAPI: the header name
            // is a fixed, known constant, never request content. The detail
            // stays the registered one, because typed clients match it exactly.
            Some(expected_field_path) => {
                assert_eq!(body["fieldPath"], expected_field_path, "{label}");
                assert_eq!(body["detail"], "The request is invalid.", "{label}");
            }
            None => {
                assert!(body.get("fieldPath").is_none(), "{label}");
            }
        }
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
    let record_id = created.body["data"]["recordIdentifier"]
        .as_str()
        .expect("id")
        .to_owned();
    assert!(Uuid::parse_str(&record_id).is_ok_and(|id| id.to_string() == record_id));
    assert_eq!(created.body["data"]["revisionIdentifier"], "1");
    assert_eq!(
        created.body["meta"]["registryIdentifier"],
        "mutation-registry"
    );
    assert_eq!(created.body["meta"]["datasetIdentifier"], "test-dataset");
    assert_eq!(created.body["meta"]["entityTypeIdentifier"], "widget");
    assert_eq!(created.body["data"]["domainData"]["label"], "http-created");
    assert_eq!(created.body["data"]["domainData"]["note"], Value::Null);
    assert!(created.etag.starts_with("\"breg-"));
    assert_eq!(
        created.location,
        Some(format!("/v1/records/widgets/{record_id}"))
    );
    assert_eq!(
        created.link,
        "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </v1/schemas/widget>; rel=\"describedby\""
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
    assert_eq!(replay.link, created.link);

    let before_breg_sec_13_seed = durable_counts(&database, &table).await;
    let breg_sec_13_seed_body = format!(
        r#"{{"data":{{"jurisdiction":"{BREG_SEC_13_ZONE_CANARY}","label":"{BREG_SEC_13_LABEL_CANARY}","quantity":{BREG_SEC_13_QUANTITY_CANARY}}}}}"#
    )
    .into_bytes();
    let breg_sec_13_seed = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/records/widgets",
            Some(breg_sec_13_claims.clone()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "breg-sec-13-idempotency-key-seed"),
                (
                    "authorization",
                    "Bearer breg-sec-13-credential-canary.breg-sec-13-raw-token-canary",
                ),
            ],
            breg_sec_13_seed_body.clone(),
        )
        .await,
    )
    .await;
    assert_eq!(breg_sec_13_seed.status, StatusCode::CREATED);
    assert_one_complete_effect(
        before_breg_sec_13_seed,
        durable_counts(&database, &table).await,
        1,
        2,
    );

    let before_breg_sec_13_conflict = durable_counts(&database, &table).await;
    let breg_sec_13_conflict = send(
        &app,
        Method::POST,
        "/v1/records/widgets",
        Some(breg_sec_13_claims),
        &[
            ("content-type", "application/json"),
            ("idempotency-key", BREG_SEC_13_IDEMPOTENCY_CANARY),
            (
                "authorization",
                "Bearer breg-sec-13-credential-canary.breg-sec-13-raw-token-canary",
            ),
        ],
        breg_sec_13_seed_body,
    )
    .await;
    assert_unique_violation_conflict_is_value_free(
        breg_sec_13_conflict,
        before_breg_sec_13_conflict,
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
    assert_eq!(fetched.body["data"]["recordIdentifier"], record_id);
    assert_eq!(fetched.body["data"]["revisionIdentifier"], "1");
    assert_eq!(fetched.body["data"]["domainData"]["label"], "http-created");
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
        anonymous_fetched.body["data"]["domainData"],
        json!({"label": "http-created"})
    );
    assert!(anonymous_fetched.etag.starts_with("\"breg-"));
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
        .any(|item| item["recordIdentifier"] == record_id));

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
    let log_id = log_created.body["data"]["recordIdentifier"]
        .as_str()
        .expect("log id");
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
            ("if-match", "\"breg-route-omitted\""),
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

    let before_missing_idempotency = durable_counts(&database, &table).await;
    let missing_idempotency = send(
        &app,
        Method::PATCH,
        &format!("/v1/records/widgets/{record_id}"),
        Some(claims.clone()),
        &[
            ("content-type", "application/json-patch+json"),
            ("if-match", &created.etag),
        ],
        br#"[{"op":"replace","path":"/data/label","value":"x"}]"#.to_vec(),
    )
    .await;
    assert_eq!(missing_idempotency.status(), StatusCode::BAD_REQUEST);
    let missing_idempotency_body = body_json(missing_idempotency).await;
    assert_eq!(missing_idempotency_body["code"], "request.invalid");
    // A missing required header names itself so the fix does not require
    // reading the generated OpenAPI: the header name is fixed, known
    // constant, never request content.
    assert_eq!(missing_idempotency_body["fieldPath"], "Idempotency-Key");
    assert_eq!(
        durable_counts(&database, &table).await.audit,
        before_missing_idempotency.audit + 1
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
    assert_eq!(patched.body["data"]["revisionIdentifier"], "2");
    assert_eq!(patched.body["data"]["domainData"]["label"], "http-patched");
    assert_eq!(patched.body["data"]["domainData"]["quantity"], 3);
    assert_eq!(patched.body["data"]["domainData"]["note"], Value::Null);
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
    assert_eq!(current.body["data"]["revisionIdentifier"], "2");
    assert_eq!(current.etag, patched.etag);

    for (label, headers, body, expected, code, field_path) in [
        (
            "missing idempotency",
            vec![("if-match", current.etag.as_str())],
            Vec::new(),
            StatusCode::BAD_REQUEST,
            "request.invalid",
            Some("Idempotency-Key"),
        ),
        (
            "missing if-match",
            vec![("idempotency-key", "delete-missing-match")],
            Vec::new(),
            StatusCode::PRECONDITION_REQUIRED,
            "precondition.required",
            None,
        ),
        (
            "weak if-match",
            vec![
                ("idempotency-key", "delete-weak-match"),
                ("if-match", "W/\"breg-weak\""),
            ],
            Vec::new(),
            StatusCode::PRECONDITION_FAILED,
            "precondition.failed",
            None,
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
            None,
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
            None,
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
        let body = body_json(response).await;
        assert_eq!(body["code"], code, "{label}");
        match field_path {
            Some(expected_field_path) => {
                assert_eq!(body["fieldPath"], expected_field_path, "{label}");
            }
            None => {
                assert!(body.get("fieldPath").is_none(), "{label}");
            }
        }
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
    assert_eq!(tombstoned.body["data"]["recordIdentifier"], record_id);
    assert_eq!(tombstoned.body["data"]["revisionIdentifier"], "3");
    assert_eq!(
        tombstoned.body["data"]["domainData"]["label"],
        "http-patched"
    );

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

    let json_ld_created = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/records/widgets",
            Some(claims.clone()),
            &[
                ("accept", "application/ld+json"),
                ("content-type", "application/json"),
                ("idempotency-key", "http-json-ld-create-key"),
                ("host", "attacker.example.invalid"),
                ("x-forwarded-host", "attacker.example.invalid"),
            ],
            br#"{"data":{"jurisdiction":"zone-a","label":"json-ld-created","quantity":5}}"#
                .to_vec(),
        )
        .await,
    )
    .await;
    assert_eq!(json_ld_created.status, StatusCode::CREATED);
    assert_eq!(json_ld_created.content_type, "application/ld+json");
    assert_eq!(
        json_ld_created.body["@context"],
        "https://id.registrystack.org/contexts/registry-record/v1"
    );
    assert_eq!(
        json_ld_created.body["data"]["domainData"]["label"],
        "json-ld-created"
    );
    assert!(!json_ld_created
        .body
        .to_string()
        .contains("attacker.example.invalid"));
    assert!(!json_ld_created.link.contains("attacker.example.invalid"));

    let json_ld_replay = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/records/widgets",
            Some(claims.clone()),
            &[
                ("accept", "application/ld+json"),
                ("content-type", "application/json"),
                ("idempotency-key", "http-json-ld-create-key"),
            ],
            br#"{"data":{"jurisdiction":"zone-a","label":"json-ld-created","quantity":5}}"#
                .to_vec(),
        )
        .await,
    )
    .await;
    assert_eq!(json_ld_replay.body_bytes, json_ld_created.body_bytes);
    assert_eq!(json_ld_replay.content_type, json_ld_created.content_type);
    assert_eq!(json_ld_replay.etag, json_ld_created.etag);
    assert_eq!(json_ld_replay.link, json_ld_created.link);

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
            audit: before_fault.audit + 2,
            ..before_fault
        },
        "a fault before the terminal audit releases no success bytes, commits no mutation \
         packet, and answers its attempt as unfinished"
    );

    assert_journals_are_minimized_and_paired(&database).await;
    database.cleanup().await;
}

/// #1442: every record and query `400` names the offending member or query
/// parameter, and never a caller-supplied name: an unknown and a withheld
/// field answer byte-identical problems.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn record_and_query_refusals_name_only_fixed_members_and_admitted_fields() {
    let database = TestDatabase::create(8).await;
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = Arc::new(located_refusal_registry());
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("migration installs schema");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        RegistryStateTestIdentity {
            package_id: "located-refusal-registry",
            database_id: DATABASE_ID,
            label: "package-located-refusal-1",
        },
    )
    .await
    .expect("migration initializes state");
    migration_task.abort();
    let pool = database.runtime_config.build_pool().expect("pool builds");
    let audit = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x6c; 32].into())
            .expect("test owns keyed audit"),
    );
    let lock_key = RegistryLockKey::derive("located-refusal-registry").expect("lock id is bounded");
    let app = mutation_router(pool, compiled, identity, lock_key, audit, None);
    let claims = api_claims("case-management", Some("zone-a"));
    let json_headers = |key: &'static str| {
        vec![
            ("content-type", "application/json"),
            ("idempotency-key", key),
        ]
    };

    let create = |key: &'static str, body: Value| {
        let app = app.clone();
        let claims = claims.clone();
        async move {
            send(
                &app,
                Method::POST,
                "/v1/records/widgets",
                Some(claims),
                &json_headers(key),
                serde_json::to_vec(&body).unwrap(),
            )
            .await
        }
    };

    // An unknown and a withheld field stop at their container.
    let unknown = problem(
        create(
            "located-unknown",
            json!({"data":{
                "jurisdiction":"zone-a","label":"A","quantity":1,"noSuchField":"x"
            }}),
        )
        .await,
    )
    .await;
    let withheld = problem(
        create(
            "located-withheld",
            json!({"data":{
                "jurisdiction":"zone-a","label":"A","quantity":1,"secret":"x"
            }}),
        )
        .await,
    )
    .await;
    assert_request_invalid_at(&unknown, Some("/data"));
    assert_identical_problems(&unknown, &withheld);
    let kebab = problem(
        create(
            "located-kebab",
            json!({"data":{
                "jurisdiction":"zone-a","label":"A","quantity":1,"is-flagged":true
            }}),
        )
        .await,
    )
    .await;
    assert_identical_problems(&unknown, &kebab);

    // A missing required and a wrongly typed admitted field are named.
    let missing = problem(
        create(
            "located-missing",
            json!({"data":{
                "jurisdiction":"zone-a","label":"A"
            }}),
        )
        .await,
    )
    .await;
    assert_request_invalid_at(&missing, Some("/data/quantity"));
    let wrong_type = problem(
        create(
            "located-type",
            json!({"data":{
                "jurisdiction":"zone-a","label":"A","quantity":"many"
            }}),
        )
        .await,
    )
    .await;
    assert_request_invalid_at(&wrong_type, Some("/data/quantity"));
    let camel = problem(
        create(
            "located-camel",
            json!({"data":{
                "jurisdiction":"zone-a","label":"A","quantity":1,"isFlagged":"yes"
            }}),
        )
        .await,
    )
    .await;
    assert_request_invalid_at(&camel, Some("/data/isFlagged"));
    let missing_data = problem(create("located-no-data", json!({"record":{}})).await).await;
    assert_request_invalid_at(&missing_data, Some("/data"));
    // No single member is at fault in an unparseable body.
    let unparseable = problem(
        send(
            &app,
            Method::POST,
            "/v1/records/widgets",
            Some(claims.clone()),
            &json_headers("located-unparseable"),
            b"{\"data\":".to_vec(),
        )
        .await,
    )
    .await;
    assert_request_invalid_at(&unparseable, None);
    let bad_key = problem(
        send(
            &app,
            Method::POST,
            "/v1/records/widgets",
            Some(claims.clone()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "bad key"),
            ],
            b"{\"data\":{}}".to_vec(),
        )
        .await,
    )
    .await;
    assert_request_invalid_at(&bad_key, Some("Idempotency-Key"));

    let created = response_parts(
        create(
            "located-created",
            json!({"data":{
                "jurisdiction":"zone-a","label":"A","quantity":1
            }}),
        )
        .await,
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    let record_id = created.body["data"]["recordIdentifier"]
        .as_str()
        .unwrap()
        .to_owned();
    let etag = created.etag.clone();
    let patch = |key: &'static str, document: Value| {
        let app = app.clone();
        let claims = claims.clone();
        let uri = format!("/v1/records/widgets/{record_id}");
        let etag = etag.clone();
        async move {
            send(
                &app,
                Method::PATCH,
                &uri,
                Some(claims),
                &[
                    ("content-type", "application/json-patch+json"),
                    ("idempotency-key", key),
                    ("if-match", &etag),
                ],
                serde_json::to_vec(&document).unwrap(),
            )
            .await
        }
    };
    let outside = problem(
        patch(
            "located-outside",
            json!([
                {"op":"replace","path":"/label","value":"B"}
            ]),
        )
        .await,
    )
    .await;
    assert_request_invalid_at(&outside, Some("/0/path"));
    // A withheld field ahead of an unknown one is located exactly like an
    // unknown one: the index never tells the caller the first field exists.
    let withheld_first = problem(
        patch(
            "located-withheld-first",
            json!([
                {"op":"replace","path":"/data/label","value":"B"},
                {"op":"replace","path":"/data/secret","value":"s"},
                {"op":"replace","path":"/data/noSuchField","value":"x"}
            ]),
        )
        .await,
    )
    .await;
    let unknown_first = problem(
        patch(
            "located-unknown-first",
            json!([
                {"op":"replace","path":"/data/label","value":"B"},
                {"op":"replace","path":"/data/otherField","value":"s"},
                {"op":"replace","path":"/data/noSuchField","value":"x"}
            ]),
        )
        .await,
    )
    .await;
    assert_request_invalid_at(&withheld_first, Some("/1/path"));
    assert_identical_problems(&withheld_first, &unknown_first);
    let withheld_test = problem(
        patch(
            "located-withheld-test",
            json!([
                {"op":"replace","path":"/data/quantity","value":"many"},
                {"op":"test","path":"/data/secret","value":"s"}
            ]),
        )
        .await,
    )
    .await;
    let unknown_test = problem(
        patch(
            "located-unknown-test",
            json!([
                {"op":"replace","path":"/data/quantity","value":"many"},
                {"op":"test","path":"/data/noSuchField","value":"s"}
            ]),
        )
        .await,
    )
    .await;
    assert_request_invalid_at(&withheld_test, Some("/1/path"));
    assert_identical_problems(&withheld_test, &unknown_test);
    let patch_type = problem(
        patch(
            "located-patch-type",
            json!([
                {"op":"test","path":"/data/label","value":"A"},
                {"op":"replace","path":"/data/quantity","value":"many"}
            ]),
        )
        .await,
    )
    .await;
    assert_request_invalid_at(&patch_type, Some("/1/value"));
    let patch_op = problem(
        patch(
            "located-patch-op",
            json!([
                {"op":"move","path":"/data/label","from":"/data/note"}
            ]),
        )
        .await,
    )
    .await;
    assert_request_invalid_at(&patch_op, Some("/0/op"));

    let batch = |key: &'static str, body: Value| {
        let app = app.clone();
        let claims = claims.clone();
        async move {
            send(
                &app,
                Method::POST,
                "/v1/records/widgets:batch",
                Some(claims),
                &json_headers(key),
                serde_json::to_vec(&body).unwrap(),
            )
            .await
        }
    };
    let item =
        json!({"operation":"create","data":{"jurisdiction":"zone-a","label":"C","quantity":2}});
    let bad_item = problem(
        batch(
            "located-batch-item",
            json!({"items":[
                item, {"operation":"create"}
            ]}),
        )
        .await,
    )
    .await;
    assert_request_invalid_at(&bad_item, Some("/items/1/data"));
    let batch_withheld = problem(batch("located-batch-withheld", json!({"items":[
        {"operation":"create","data":{"jurisdiction":"zone-a","label":"D","quantity":2,"secret":"s"}},
        {"operation":"create","data":{"jurisdiction":"zone-a","label":"E","quantity":2,"noSuchField":"x"}}
    ]})).await).await;
    let batch_unknown = problem(batch("located-batch-unknown", json!({"items":[
        {"operation":"create","data":{"jurisdiction":"zone-a","label":"D","quantity":2,"otherField":"s"}},
        {"operation":"create","data":{"jurisdiction":"zone-a","label":"E","quantity":2,"noSuchField":"x"}}
    ]})).await).await;
    assert_request_invalid_at(&batch_withheld, Some("/items/0/data"));
    assert_identical_problems(&batch_withheld, &batch_unknown);
    let batch_type = problem(batch("located-batch-type", json!({"items":[
        item, {"operation":"create","data":{"jurisdiction":"zone-a","label":"F","quantity":"many"}}
    ]})).await).await;
    assert_request_invalid_at(&batch_type, Some("/items/1/data/quantity"));
    let batch_patch = problem(
        batch(
            "located-batch-patch",
            json!({"items":[{
                "operation":"patch","recordId":record_id,"ifMatch":created.etag,
                "patch":[{"op":"replace","path":"/label","value":"G"}]
            }]}),
        )
        .await,
    )
    .await;
    assert_request_invalid_at(&batch_patch, Some("/items/0/patch/0/path"));
    let batch_operation = problem(
        batch(
            "located-batch-operation",
            json!({"items":[item, {"operation":"delete","data":{}}]}),
        )
        .await,
    )
    .await;
    assert_request_invalid_at(&batch_operation, Some("/items/1/operation"));
    let batch_context = problem(
        batch(
            "located-batch-context",
            json!({"items":[item],"changeContext":7}),
        )
        .await,
    )
    .await;
    assert_request_invalid_at(&batch_context, Some("/changeContext"));
    // A batch carries each item's precondition in its body, so an If-Match
    // header is refused and named.
    let batch_if_match = problem(
        send(
            &app,
            Method::POST,
            "/v1/records/widgets:batch",
            Some(claims.clone()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "located-batch-if-match"),
                ("if-match", &created.etag),
            ],
            serde_json::to_vec(&json!({"items":[item]})).unwrap(),
        )
        .await,
    )
    .await;
    assert_request_invalid_at(&batch_if_match, Some("If-Match"));
    for (key, body) in [
        ("located-batch-no-items", json!({})),
        ("located-batch-items-type", json!({"items":{}})),
        ("located-batch-empty", json!({"items":[]})),
        (
            "located-batch-over",
            json!({"items":[item, item, item, item, item]}),
        ),
    ] {
        let refused = problem(batch(key, body).await).await;
        assert_request_invalid_at(&refused, Some("/items"));
    }

    // A required field the grant withholds is missing from every body this
    // profile can send; naming it would disclose it, so the refusal stops at
    // `/data` like an unknown member.
    let drafter = api_claims("case-drafting", Some("zone-a"));
    let withheld_required = problem(
        send(
            &app,
            Method::POST,
            "/v1/records/widgets?accessProfile=drafter",
            Some(drafter.clone()),
            &json_headers("located-withheld-required"),
            serde_json::to_vec(&json!({"data":{"jurisdiction":"zone-a","label":"H"}})).unwrap(),
        )
        .await,
    )
    .await;
    assert_request_invalid_at(&withheld_required, Some("/data"));
    assert!(!String::from_utf8_lossy(&withheld_required.1).contains("quantity"));
    let drafter_unknown = problem(
        send(
            &app,
            Method::POST,
            "/v1/records/widgets?accessProfile=drafter",
            Some(drafter),
            &json_headers("located-drafter-unknown"),
            serde_json::to_vec(&json!({"data":{
                "jurisdiction":"zone-a","label":"H","noSuchField":"x"
            }}))
            .unwrap(),
        )
        .await,
    )
    .await;
    assert_identical_problems(&withheld_required, &drafter_unknown);

    let query = |uri: &'static str| {
        let app = app.clone();
        let claims = claims.clone();
        async move { send(&app, Method::GET, uri, Some(claims), &[], Vec::new()).await }
    };
    let select_unknown = problem(query("/v1/records/widgets?$select=noSuchField").await).await;
    let select_withheld = problem(query("/v1/records/widgets?$select=secret").await).await;
    assert_query_invalid_at(&select_unknown, Some("$select"));
    assert_identical_problems(&select_unknown, &select_withheld);
    let filter_unknown =
        problem(query("/v1/records/widgets?$filter=noSuchField%20eq%20'x'").await).await;
    let filter_withheld =
        problem(query("/v1/records/widgets?$filter=secret%20eq%20'x'").await).await;
    assert_query_invalid_at(&filter_unknown, Some("$filter"));
    assert_identical_problems(&filter_unknown, &filter_withheld);
    let filter_syntax = problem(query("/v1/records/widgets?$filter=label%20eq").await).await;
    assert_query_invalid_at(&filter_syntax, Some("$filter"));
    let top = problem(query("/v1/records/widgets?$top=0").await).await;
    assert_query_invalid_at(&top, Some("$top"));
    let orderby = problem(query("/v1/records/widgets?$orderby=secret").await).await;
    assert_query_invalid_at(&orderby, Some("$orderby"));
    let invented = problem(query("/v1/records/widgets?noSuchParameter=1").await).await;
    assert_query_invalid_at(&invented, None);
    assert!(!String::from_utf8_lossy(&invented.1).contains("noSuchParameter"));
    let get_filter = problem(
        send(
            &app,
            Method::GET,
            &format!("/v1/records/widgets/{record_id}?$filter=label%20eq%20'A'"),
            Some(claims.clone()),
            &[],
            Vec::new(),
        )
        .await,
    )
    .await;
    assert_query_invalid_at(&get_filter, Some("$filter"));

    for (_, bytes) in [
        &unknown,
        &withheld,
        &kebab,
        &withheld_first,
        &unknown_first,
        &withheld_test,
        &batch_withheld,
        &select_withheld,
        &filter_withheld,
        &orderby,
    ] {
        let text = String::from_utf8_lossy(bytes);
        assert!(!text.contains("secret"), "{text}");
        assert!(!text.contains("noSuchField"), "{text}");
        assert!(!text.contains("otherField"), "{text}");
        assert!(!text.contains("is-flagged"), "{text}");
    }
}

async fn problem(response: axum::response::Response) -> (StatusCode, Vec<u8>) {
    let status = response.status();
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/problem+json")
    );
    (status, response_bytes(response).await)
}

fn assert_request_invalid_at(problem: &(StatusCode, Vec<u8>), field_path: Option<&str>) {
    assert_problem_at(
        problem,
        "request.invalid",
        "The request is invalid.",
        field_path,
    );
}

fn assert_query_invalid_at(problem: &(StatusCode, Vec<u8>), field_path: Option<&str>) {
    assert_problem_at(
        problem,
        "query.invalid",
        "The query request is invalid.",
        field_path,
    );
}

fn assert_problem_at(
    (status, bytes): &(StatusCode, Vec<u8>),
    code: &str,
    detail: &str,
    field_path: Option<&str>,
) {
    let body: Value = serde_json::from_slice(bytes).expect("problem is JSON");
    assert_eq!(*status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], code, "{body}");
    assert_eq!(body["detail"], detail, "{body}");
    assert_eq!(body["title"], "Bad Request", "{body}");
    assert_eq!(
        body.get("fieldPath").and_then(Value::as_str),
        field_path,
        "{body}"
    );
    let mut members = vec!["type", "title", "status", "detail", "code", "traceId"];
    if field_path.is_some() {
        members.push("fieldPath");
    }
    assert_eq!(
        body.as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        members.into_iter().collect::<BTreeSet<_>>(),
        "{body}"
    );
}

/// Two problems are byte-identical apart from their trace identifiers.
fn assert_identical_problems(left: &(StatusCode, Vec<u8>), right: &(StatusCode, Vec<u8>)) {
    let strip = |(status, bytes): &(StatusCode, Vec<u8>)| {
        let mut body: Value = serde_json::from_slice(bytes).unwrap();
        let trace = body["traceId"].as_str().unwrap().to_owned();
        body.as_object_mut().unwrap().remove("traceId");
        (
            *status,
            String::from_utf8(bytes.clone())
                .unwrap()
                .replace(&trace, ""),
            body,
        )
    };
    assert_eq!(strip(left), strip(right));
}

fn row_boundary_batch_registry() -> registry_breg::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"row-boundary-batch-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[{
            "id":"widget","primaryDataset":"test-dataset","route":"widgets","mutationMode":"mutable","classification":"public",
            "batch":{"maximumItems":4,"maximumBytes":16384},
            "constraints":[{"kind":"unique","fields":["label"]}],
            "fields":[
              {"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"public"},
              {"id":"label","type":"string","maxLength":128,"required":true,"classification":"public"},
              {"id":"quantity","type":"int64","required":true,"classification":"public"}
            ]
          }],
          "accessProfiles":[{
            "id":"writer","default":true,"principalClaim":"registry_principal",
            "requiredPurposes":["case-management"],
            "permissions":[{
              "entity":"widget","operations":["create","get","list","patch","batch"],
              "readableFields":["jurisdiction","label","quantity"],
              "writableFields":["jurisdiction","label","quantity"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            }]
          }]
        }"#,
    )
    .expect("row boundary batch fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("row boundary batch fixture compiles")
}

fn located_refusal_registry() -> registry_breg::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"located-refusal-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[{
            "id":"widget","primaryDataset":"test-dataset","route":"widgets","mutationMode":"mutable","classification":"public",
            "batch":{"maximumItems":4,"maximumBytes":16384},
            "fields":[
              {"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"public"},
              {"id":"label","type":"string","maxLength":128,"required":true,"classification":"public"},
              {"id":"quantity","type":"int64","required":true,"classification":"public"},
              {"id":"is-flagged","type":"boolean","required":false,"classification":"public"},
              {"id":"secret","type":"string","maxLength":128,"required":false,"classification":"public"}
            ]
          }],
          "accessProfiles":[{
            "id":"writer","default":true,"principalClaim":"registry_principal",
            "requiredPurposes":["case-management"],
            "permissions":[{
              "entity":"widget","operations":["create","get","list","patch","batch"],
              "readableFields":["jurisdiction","label","quantity","is-flagged"],
              "writableFields":["jurisdiction","label","quantity","is-flagged"],
              "filterableFields":["label"],
              "sortableFields":["label"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            }]
          },{
            "id":"keeper","principalClaim":"registry_principal",
            "requiredPurposes":["case-review"],
            "permissions":[{
              "entity":"widget","operations":["get","list","patch"],
              "readableFields":["jurisdiction","label","secret"],
              "writableFields":["secret"],
              "filterableFields":["secret"],
              "sortableFields":["secret"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            }]
          },{
            "id":"drafter","principalClaim":"registry_principal",
            "requiredPurposes":["case-drafting"],
            "permissions":[{
              "entity":"widget","operations":["create","get"],
              "readableFields":["jurisdiction","label"],
              "writableFields":["jurisdiction","label"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            }]
          }]
        }"#,
    )
    .expect("located refusal fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("located refusal fixture compiles")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refusal_audit_records_only_compiled_access_profiles() {
    let database = TestDatabase::create(6).await;
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("migration installs schema");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "package-refusal-profile-1",
        },
    )
    .await
    .expect("migration initializes state");
    migration_task.abort();

    let pool = database.runtime_config.build_pool().expect("pool builds");
    let profile = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x6b; 32].into())
            .expect("test owns keyed audit"),
    );
    let lock_key = RegistryLockKey::derive("mutation-registry").expect("lock id is bounded");
    let app = mutation_router(
        pool.clone(),
        compiled.clone(),
        identity.clone(),
        lock_key,
        profile.clone(),
        None,
    );
    let claims = api_claims("case-management", Some("zone-a"));
    // Every refusal below names a principal, so the journal records it; a
    // refusal of a request that carries no principal is counted on the metrics
    // listener instead.
    let refused_claims = api_claims("wrong-purpose", Some("zone-a"));

    // A caller-chosen profile that no compiled route grants is refused, and the
    // audit journal records no profile rather than the caller's bytes.
    let unknown = send(
        &app,
        Method::POST,
        &format!("/v1/records/widgets?accessProfile={BREG_SEC_13_PROFILE_CANARY}"),
        Some(claims),
        &[
            ("content-type", "application/json"),
            ("idempotency-key", "refusal-profile-unknown"),
        ],
        br#"{"data":{"jurisdiction":"zone-a","label":"unreleased","quantity":1}}"#.to_vec(),
    )
    .await;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_json(unknown).await["code"], "resource.not_found");

    // A compiled profile the route grants is the profile the refusal was
    // evaluated under, so the audit keeps it.
    let compiled_profile = send(
        &app,
        Method::POST,
        "/v1/records/widgets?accessProfile=operator",
        Some(refused_claims.clone()),
        &[
            ("content-type", "application/json"),
            ("idempotency-key", "refusal-profile-compiled"),
        ],
        br#"{"data":{"jurisdiction":"zone-a","label":"unreleased","quantity":1}}"#.to_vec(),
    )
    .await;
    assert_eq!(compiled_profile.status(), StatusCode::NOT_FOUND);

    // Without a caller-supplied profile the route default is recorded.
    let defaulted = send(
        &app,
        Method::POST,
        "/v1/records/widgets",
        Some(refused_claims),
        &[
            ("content-type", "application/json"),
            ("idempotency-key", "refusal-profile-default"),
        ],
        br#"{"data":{"jurisdiction":"zone-a","label":"unreleased","quantity":1}}"#.to_vec(),
    )
    .await;
    assert_eq!(defaulted.status(), StatusCode::NOT_FOUND);

    let refusals = refusal_audit_envelopes(&database).await;
    assert_eq!(refusals.len(), 3);
    let mut selected = refusals
        .iter()
        .map(|record| record["selectedAccessProfile"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    selected.sort();
    assert_eq!(
        selected,
        [
            None,
            Some("operator".to_owned()),
            Some("operator".to_owned())
        ]
    );
    let audit_text = serde_json::to_string(&refusals).expect("refusal audit serializes");
    assert!(!audit_text.contains(BREG_SEC_13_PROFILE_CANARY));

    database.cleanup().await;
}

fn mutation_refusal_audit_fault_router(
    pool: registry_breg::postgres::RuntimePool,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    profile: RegistryAudit,
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
        package_revision: identity.activation_id.clone(),
        schema_fingerprint: identity.schema_fingerprint.clone(),
    };
    let mutations = PostgresRecordMutationService::new(
        pool,
        registry.clone(),
        identity,
        INSTANCE_ID,
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
    pool: registry_breg::postgres::RuntimePool,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    profile: RegistryAudit,
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
        package_revision: identity.activation_id.clone(),
        schema_fingerprint: identity.schema_fingerprint.clone(),
    };
    let mutations = PostgresRecordMutationService::new(
        pool,
        registry.clone(),
        identity,
        INSTANCE_ID,
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
    link: String,
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
        link: header_string(&headers, "link"),
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

fn compiled_registry() -> registry_breg::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"mutation-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[{
            "id":"widget","primaryDataset":"test-dataset","route":"widgets","mutationMode":"mutable","tombstone":true,"classification":"public",
            "constraints":[{"kind":"unique","fields":["label"]}],
            "fields":[
              {"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"public"},
              {"id":"label","type":"string","maxLength":128,"required":true,"classification":"public"},
              {"id":"note","type":"string","maxLength":128,"required":false,"classification":"public"},
              {"id":"quantity","type":"int64","required":true,"classification":"public"}
            ],
            "hooks":[
              {"phase":"after","id":"widget-created","trigger":"created","projection":["label"]},
              {"phase":"after","id":"widget-patched","trigger":"patched","projection":["label","quantity"]},
              {"phase":"after","id":"widget-tombstoned","trigger":"tombstoned","projection":["label","quantity"]}
            ]
          },{
            "id":"log","primaryDataset":"test-dataset","route":"logs","mutationMode":"create_only","classification":"public",
            "fields":[
              {"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"public"},
              {"id":"message","type":"string","maxLength":128,"required":true,"classification":"public"}
            ]
          },{
            "id":"archive","primaryDataset":"test-dataset","route":"archives","mutationMode":"mutable","classification":"public",
            "fields":[
              {"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"public"},
              {"id":"name","type":"string","maxLength":128,"required":true,"classification":"public"}
            ]
          }],
          "accessProfiles":[{
            "id":"operator","default":true,"principalClaim":"registry_principal",
            "requiredPurposes":["case-management","case-review"],
            "permissions":[{
              "entity":"widget","operations":["create","get","list","patch","tombstone"],
              "readableFields":["jurisdiction","label","note","quantity"],
              "writableFields":["jurisdiction","label","note","quantity"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            }]
          },{
            "id":"review-operator","principalClaim":"registry_principal",
            "requiredPurposes":["case-management"],
            "permissions":[{
              "entity":"widget","operations":["create","get","list","patch","tombstone"],
              "readableFields":["jurisdiction","label","note","quantity"],
              "writableFields":["jurisdiction","label","note","quantity"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            }]
          },{
            "id":"anonymous-reader","anonymous":true,
            "permissions":[{
              "entity":"widget","operations":["get","list"],
              "readableFields":["label"],
              "rowBoundaries": []
            }]
          },{
            "id":"label-editor","principalClaim":"registry_principal",
            "requiredPurposes":["case-management"],
            "permissions":[{
              "entity":"widget","operations":["get","patch"],
              "readableFields":["label"],
              "writableFields":["label"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            }]
          },{
            "id":"case-operator","default":true,"principalClaim":"registry_principal",
            "requiredPurposes":["case-management"],
            "permissions":[{
              "entity":"log","operations":["create","get","list"],
              "readableFields":["jurisdiction","message"],
              "writableFields":["jurisdiction","message"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            },{
              "entity":"archive","operations":["create","get","list","patch"],
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
    registry: &registry_breg::CompiledRegistry,
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
        representation: registry_breg::record_profile::RecordRepresentation::Json,
        correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
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
        representation: registry_breg::record_profile::RecordRepresentation::Json,
        correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
    }
}

fn response_etag(outcome: &MutationOutcome) -> String {
    String::from_utf8(outcome.response().headers()[&PermittedResponseHeader::Etag].clone())
        .expect("mutation response etag is UTF-8")
}

fn response_id(outcome: &MutationOutcome) -> String {
    let body: Value =
        serde_json::from_slice(outcome.response().body()).expect("mutation response is JSON");
    body["data"]["recordIdentifier"]
        .as_str()
        .expect("mutation response includes id")
        .to_owned()
}

fn assert_created_response(outcome: &MutationOutcome, record_id: &str, label: &str, quantity: i64) {
    assert_eq!(outcome.response().status(), 201);
    let body: Value =
        serde_json::from_slice(outcome.response().body()).expect("create response is JSON");
    assert_eq!(body["data"]["domainData"]["label"], label);
    assert_eq!(body["data"]["domainData"]["quantity"], quantity);
    assert_eq!(body["data"]["recordIdentifier"], record_id);
    assert_eq!(body["data"]["revisionIdentifier"], "1");
    assert_snapshot_reference(&body["data"]["snapshot"]);
    assert_eq!(
        outcome.response().headers()[&PermittedResponseHeader::ContentType],
        b"application/json"
    );
    assert!(outcome.response().headers()[&PermittedResponseHeader::Etag].starts_with(b"\"breg-"));
    assert_eq!(
        outcome.response().headers()[&PermittedResponseHeader::Location],
        format!("/v1/records/widgets/{record_id}").as_bytes()
    );
}

fn assert_snapshot_reference(value: &Value) {
    let snapshot = value.as_str().expect("response carries snapshot reference");
    let suffix = snapshot
        .strip_prefix("breg1_")
        .expect("snapshot reference carries the breg1_ prefix");
    assert_eq!(suffix.len(), 36);
    Uuid::parse_str(suffix).expect("snapshot suffix is a UUID");
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DurableCounts {
    current: i64,
    revisions: i64,
    outbox: i64,
    audit: i64,
    idempotency: i64,
    commits: i64,
    commit_members: i64,
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
            commits: before.commits + 1,
            commit_members: before.commit_members + 1,
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
    compiled: &registry_breg::CompiledRegistry,
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
    let traceparent = headers
        .get("traceparent")
        .and_then(|value| value.to_str().ok())
        .expect("problem response carries traceparent");
    let trace_id = traceparent
        .split('-')
        .nth(1)
        .expect("canonical traceparent carries trace ID");
    assert_eq!(trace_id.len(), 32);
    assert_ne!(trace_id, "00000000000000000000000000000000");
    let problem: Value = serde_json::from_slice(&body).expect("problem JSON is valid");
    assert_eq!(
        problem,
        json!({
            "type": "https://id.registrystack.org/problems/registry-breg/mutation/conflict",
            "title": "Conflict",
            "status": 409,
            "detail": "The mutation conflicts with current state.",
            "code": "mutation.conflict",
            "traceId": trace_id,
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
    compiled: &registry_breg::CompiledRegistry,
) {
    let lower_text = text.to_ascii_lowercase();
    for forbidden in forbidden_diagnostic_fragments(compiled) {
        assert!(
            !text.contains(&forbidden) && !lower_text.contains(&forbidden.to_ascii_lowercase()),
            "public diagnostic text leaked forbidden fragment {forbidden:?}: {text}"
        );
    }
}

fn forbidden_diagnostic_fragments(compiled: &registry_breg::CompiledRegistry) -> BTreeSet<String> {
    let mut forbidden = BTreeSet::from([
        PRINCIPAL_CANARY.to_owned(),
        BREG_SEC_13_PRINCIPAL_CANARY.to_owned(),
        BREG_SEC_13_TOKEN_CANARY.to_owned(),
        BREG_SEC_13_CREDENTIAL_CANARY.to_owned(),
        BREG_SEC_13_IDEMPOTENCY_CANARY.to_owned(),
        BREG_SEC_13_ZONE_CANARY.to_owned(),
        BREG_SEC_13_LABEL_CANARY.to_owned(),
        BREG_SEC_13_QUANTITY_CANARY.to_owned(),
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
                   (SELECT count(*) FROM registry_internal.registry_idempotency),
                   (SELECT count(*) FROM registry_internal.registry_revision_commits),
                   (SELECT count(*) FROM registry_internal.registry_revision_commit_members)"
            ),
            &[],
        )
        .await
        .expect("administrator can inspect isolated durable state");
    DurableCounts {
        current: row.get(0),
        revisions: row.get(1),
        outbox: row.get(2),
        audit: i64::try_from(database.audit_entries().len()).expect("audit count fits i64"),
        idempotency: row.get(3),
        commits: row.get(4),
        commit_members: row.get(5),
    }
}

async fn refusal_audit_envelopes(database: &TestDatabase) -> Vec<Value> {
    database
        .audit_records()
        .into_iter()
        .filter(|record| record["phase"] == "refusal")
        .collect()
}

async fn refusal_audit_count(database: &TestDatabase) -> i64 {
    i64::try_from(refusal_audit_envelopes(database).await.len()).expect("refusal count fits i64")
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
    let expected_data = json!({
        "entity": "widget",
        "recordId": record_id,
        "revision": 2,
        "trigger": "patched",
        "packageRevision": test_package_digest("package-mutation-1"),
        "values": {
            "label": "after-patch",
            "quantity": 41,
        },
    });
    assert!(events.iter().any(|row| {
        let envelope: Value = serde_json::from_slice(&row.get::<_, Vec<u8>>(0))
            .expect("captured event body is strict JSON");
        envelope.get("data") == Some(&expected_data)
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

async fn assert_journals_are_minimized_and_paired(database: &TestDatabase) {
    database.assert_every_audit_request_answered_once();
    let ordered = database.audit_entries();
    for entry in &ordered {
        let expected = if entry["record"]["phase"] == "attempt" {
            "request"
        } else {
            "response"
        };
        assert_eq!(entry["phase"], expected, "{entry}");
    }
    let audit_text = ordered
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!audit_text.contains(PRINCIPAL_CANARY));
    assert!(!audit_text.contains(BREG_SEC_13_PRINCIPAL_CANARY));
    assert!(!audit_text.contains(BREG_SEC_13_TOKEN_CANARY));
    assert!(!audit_text.contains(BREG_SEC_13_CREDENTIAL_CANARY));
    assert!(!audit_text.contains(BREG_SEC_13_IDEMPOTENCY_CANARY));
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

    for (position, entry) in ordered.iter().enumerate() {
        if entry["schema"] != registry_breg::audit::AUDIT_SCHEMA {
            continue;
        }
        let record = &entry["record"];
        let request_id = record["requestId"]
            .as_str()
            .expect("HTTP audit carries requestId");
        uuid::Uuid::parse_str(request_id).expect("requestId is a server UUID");
        let trace_id = record["traceId"]
            .as_str()
            .expect("HTTP audit carries traceId");
        assert_eq!(trace_id.len(), 32);
        if record["phase"] == "terminal" {
            let operation_id = &record["operationId"];
            assert!(
                ordered[..position].iter().any(|candidate| {
                    candidate["phase"] == "request"
                        && candidate["correlation"] == entry["correlation"]
                        && candidate["record"]["phase"] == "attempt"
                        && candidate["record"]["operationId"] == *operation_id
                        && candidate["record"]["requestId"] == request_id
                        && candidate["record"]["traceId"] == trace_id
                }),
                "a terminal response shares its attempt request's correlation"
            );
        }
    }

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
            assert!(!payload.contains(BREG_SEC_13_PRINCIPAL_CANARY));
            assert!(!payload.contains(BREG_SEC_13_TOKEN_CANARY));
            assert!(!payload.contains(BREG_SEC_13_CREDENTIAL_CANARY));
            assert!(!payload.contains(BREG_SEC_13_IDEMPOTENCY_CANARY));
            assert!(!reference.contains(PRINCIPAL_CANARY));
            assert!(!reference.contains(BREG_SEC_13_PRINCIPAL_CANARY));
            assert!(!reference.contains(BREG_SEC_13_TOKEN_CANARY));
            assert!(!reference.contains(BREG_SEC_13_CREDENTIAL_CANARY));
            assert!(!reference.contains(BREG_SEC_13_IDEMPOTENCY_CANARY));
            for record in [
                RECORD_POSITIVE,
                RECORD_PATCH,
                RECORD_RECOVERY,
                RECORD_CONCURRENT,
            ] {
                if table_and_column.0 != "registry_outbox" {
                    assert!(!payload.contains(record));
                }
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
        assert!(!key_reference.contains(BREG_SEC_13_PRINCIPAL_CANARY));
        assert!(!key_reference.contains(BREG_SEC_13_TOKEN_CANARY));
        assert!(!key_reference.contains(BREG_SEC_13_CREDENTIAL_CANARY));
        assert!(!key_reference.contains(BREG_SEC_13_IDEMPOTENCY_CANARY));
        assert!(!binding_reference.contains(PRINCIPAL_CANARY));
        assert!(!binding_reference.contains(BREG_SEC_13_PRINCIPAL_CANARY));
        assert!(!binding_reference.contains(BREG_SEC_13_TOKEN_CANARY));
        assert!(!binding_reference.contains(BREG_SEC_13_CREDENTIAL_CANARY));
        assert!(!binding_reference.contains(BREG_SEC_13_IDEMPOTENCY_CANARY));
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

fn query_parameter_names(parameters: &Value) -> Vec<String> {
    let mut names = parameters
        .as_array()
        .expect("parameters are an array")
        .iter()
        .map(|parameter| {
            parameter["name"]
                .as_str()
                .expect("parameter has a name")
                .to_owned()
        })
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn coordinator_with_audit_key(
    database: &TestDatabase,
    identity: &registry_breg::postgres::ExpectedRegistryIdentity,
    audit_key: u8,
) -> MutationCoordinator {
    MutationCoordinator::new(
        RegistryLockKey::derive("mutation-registry").expect("lock id is bounded"),
        Duration::from_secs(2),
        identity.clone(),
        INSTANCE_ID,
        database.audit(
            AuditProfile::production_from_secret_bytes(vec![audit_key; 32].into())
                .expect("test owns a strong keyed audit profile"),
        ),
    )
}

/// Every durable effect except the audit journal, which also records replays
/// and refusals.
fn effect_counts(counts: DurableCounts) -> [i64; 6] {
    [
        counts.current,
        counts.revisions,
        counts.outbox,
        counts.idempotency,
        counts.commits,
        counts.commit_members,
    ]
}

/// Rotating `audit.hashKeyRef` changes pseudonyms only. An exact retry after
/// the rotation finds the spent key by the caller and the key alone, replays
/// the held response, and never executes the mutation a second time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_exact_retry_after_audit_key_rotation_replays_and_never_reexecutes() {
    let database = TestDatabase::create(2).await;
    let (compiled, identity, pool) = prepared_mutation_registry(&database).await;
    let plan = MutationPlan::from_compiled(&compiled, "records.widget.create")
        .expect("create plan comes from the compiled inventory");
    let claims = mutation_claims(&compiled, PRINCIPAL_CANARY, "zone-a");
    let table = &compiled.entities()["widget"].physical_table;
    let mut client = pool
        .get_for_test()
        .await
        .expect("runtime connection is available");

    let first = coordinator_with_audit_key(&database, &identity, 0x5a)
        .execute(
            &mut client,
            create_request(
                &plan,
                "rotation-key",
                &claims,
                RECORD_POSITIVE,
                "rotation-label",
                Some(3),
            ),
        )
        .await
        .expect("the first attempt executes");
    assert!(!first.replayed());
    let committed = durable_counts(&database, table).await;

    let rotated = coordinator_with_audit_key(&database, &identity, 0x6b);
    let retry = rotated
        .execute(
            &mut client,
            create_request(
                &plan,
                "rotation-key",
                &claims,
                RECORD_POSITIVE,
                "rotation-label",
                Some(3),
            ),
        )
        .await
        .expect("an exact retry after rotation replays the held response");
    assert!(retry.replayed());
    assert_eq!(retry.response(), first.response());
    assert_eq!(
        effect_counts(durable_counts(&database, table).await),
        effect_counts(committed)
    );

    let changed = rotated
        .execute(
            &mut client,
            create_request(
                &plan,
                "rotation-key",
                &claims,
                RECORD_POSITIVE,
                "rotation-other-label",
                Some(3),
            ),
        )
        .await;
    assert_eq!(changed, Err(MutationError::IdempotencyConflict));
    assert_eq!(
        effect_counts(durable_counts(&database, table).await),
        effect_counts(committed)
    );

    let spent = database
        .admin
        .query_one(
            "SELECT key_reference, binding_reference, caller_subject, key_scope, idempotency_key
               FROM registry_internal.registry_idempotency",
            &[],
        )
        .await
        .expect("administrator can inspect the spent key");
    assert!(spent.get::<_, String>(0).starts_with("sha256:"));
    assert!(spent.get::<_, String>(1).starts_with("sha256:"));
    assert_eq!(spent.get::<_, String>(2), PRINCIPAL_CANARY);
    assert_eq!(spent.get::<_, String>(3), "mutation");
    assert_eq!(spent.get::<_, String>(4), "rotation-key");
    drop(client);
    database.cleanup().await;
}

/// A key is spent per caller: the verified issuer and subject scope it, so
/// another subject, or the same subject under another issuer, using the same
/// key executes its own request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_idempotency_keys_are_scoped_per_caller() {
    let database = TestDatabase::create(2).await;
    let (compiled, identity, pool) = prepared_mutation_registry(&database).await;
    let plan = MutationPlan::from_compiled(&compiled, "records.widget.create")
        .expect("create plan comes from the compiled inventory");
    let first_caller = mutation_claims(&compiled, PRINCIPAL_CANARY, "zone-a");
    let second_caller = mutation_claims(&compiled, "second-caller-subject", "zone-a");
    let table = &compiled.entities()["widget"].physical_table;
    let mut client = pool
        .get_for_test()
        .await
        .expect("runtime connection is available");
    let coordinator = audited_coordinator(&database, &identity);

    let first = coordinator
        .execute(
            &mut client,
            create_request(
                &plan,
                "shared-key",
                &first_caller,
                RECORD_POSITIVE,
                "first-caller-label",
                Some(1),
            ),
        )
        .await
        .expect("the first caller executes");
    let second = coordinator
        .execute(
            &mut client,
            create_request(
                &plan,
                "shared-key",
                &second_caller,
                RECORD_PATCH,
                "second-caller-label",
                Some(2),
            ),
        )
        .await
        .expect("another subject using the same key executes its own request");
    assert!(!first.replayed());
    assert!(!second.replayed());
    assert_ne!(first.response(), second.response());

    let other_issuer = audited_coordinator(&database, &identity).with_idempotency_policy(
        IdempotencyPolicy::new("https://other-issuer.example", 7)
            .expect("the policy is within bounds"),
    );
    let third = other_issuer
        .execute(
            &mut client,
            create_request(
                &plan,
                "shared-key",
                &first_caller,
                RECORD_RECOVERY,
                "other-issuer-label",
                Some(3),
            ),
        )
        .await
        .expect("the same subject under another issuer executes its own request");
    assert!(!third.replayed());

    let counts = durable_counts(&database, table).await;
    assert_eq!(counts.current, 3);
    assert_eq!(counts.idempotency, 3);
    let replay = coordinator
        .execute(
            &mut client,
            create_request(
                &plan,
                "shared-key",
                &second_caller,
                RECORD_PATCH,
                "second-caller-label",
                Some(2),
            ),
        )
        .await
        .expect("each caller replays only its own held response");
    assert!(replay.replayed());
    assert_eq!(replay.response(), second.response());
    drop(client);
    database.cleanup().await;
}

/// A held response is kept for the receipt horizon. A retry after it is
/// refused as expired and never executed, before and after the operator
/// sweep drops the held body and clears the raw caller and key; the key stays
/// spent throughout, by its digest. A changed retry is still a conflict,
/// another caller's identical key is that caller's own fresh key, and a row
/// inside its horizon is untouched.
#[cfg(feature = "tooling")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_retry_after_receipt_horizon_is_refused_and_the_sweep_keeps_the_key_spent() {
    use registry_breg::idempotency_retention::IdempotencyRetentionOperatorService;
    use registry_breg::postgres::ExpectedManagedCatalog;

    let database = TestDatabase::create(2).await;
    let (compiled, identity, pool) = prepared_mutation_registry(&database).await;
    let plan = MutationPlan::from_compiled(&compiled, "records.widget.create")
        .expect("create plan comes from the compiled inventory");
    let claims = mutation_claims(&compiled, PRINCIPAL_CANARY, "zone-a");
    let table = &compiled.entities()["widget"].physical_table;
    let mut client = pool
        .get_for_test()
        .await
        .expect("runtime connection is available");
    let coordinator = audited_coordinator(&database, &identity);

    for (key, label) in [
        ("horizon-key", "horizon-label"),
        ("fresh-key", "fresh-label"),
    ] {
        coordinator
            .execute(
                &mut client,
                create_request(&plan, key, &claims, RECORD_POSITIVE, label, Some(1)),
            )
            .await
            .expect("the first attempt executes");
    }
    let held = database
        .admin
        .query_one(
            "SELECT receipt_expires_at - created_at = INTERVAL '7 days'
               FROM registry_internal.registry_idempotency
              WHERE idempotency_key = 'horizon-key'",
            &[],
        )
        .await
        .expect("administrator can inspect the receipt horizon");
    assert!(held.get::<_, bool>(0), "the default horizon is seven days");
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_idempotency
                SET created_at = CURRENT_TIMESTAMP - INTERVAL '9 days',
                    receipt_expires_at = CURRENT_TIMESTAMP - INTERVAL '2 days'
              WHERE idempotency_key = 'horizon-key'",
            &[],
        )
        .await
        .expect("administrator ages one receipt past its horizon");
    let committed = durable_counts(&database, table).await;
    let spent_columns = "SELECT key_reference, binding_reference, key_scope, result_kind,
                                created_at::text, receipt_expires_at::text
                           FROM registry_internal.registry_idempotency";
    let spent =
        |row: &tokio_postgres::Row| (0..6).map(|i| row.get::<_, String>(i)).collect::<Vec<_>>();
    let horizon_spent = spent(
        &database
            .admin
            .query_one(
                &format!("{spent_columns} WHERE idempotency_key = 'horizon-key'"),
                &[],
            )
            .await
            .expect("administrator can read the aged spent key"),
    );
    let horizon_reference = horizon_spent[0].clone();

    let retry = || {
        create_request(
            &plan,
            "horizon-key",
            &claims,
            RECORD_POSITIVE,
            "horizon-label",
            Some(1),
        )
    };
    assert_eq!(
        coordinator.execute(&mut client, retry()).await,
        Err(MutationError::IdempotencyExpired)
    );
    assert_eq!(
        effect_counts(durable_counts(&database, table).await),
        effect_counts(committed)
    );

    let sweep = IdempotencyRetentionOperatorService::new_for_test(
        identity.clone(),
        ExpectedManagedCatalog::compiled(&compiled),
        RegistryLockKey::derive(PACKAGE_ID).expect("lock id is bounded"),
        database.migration_config.clone(),
        database.migration_role.clone(),
        database.runtime_role.clone(),
        database.audit(
            AuditProfile::production_from_secret_bytes(vec![0x5e; 32].into())
                .expect("test owns a strong keyed audit profile"),
        ),
    );
    assert_eq!(
        sweep
            .erase_expired(chrono::Utc::now())
            .await
            .expect("the sweep drops expired held responses"),
        1
    );
    assert_eq!(
        sweep
            .erase_expired(chrono::Utc::now())
            .await
            .expect("a repeated sweep is idempotent"),
        0
    );
    let rows = database
        .admin
        .query(
            "SELECT key_reference = $1, caller_issuer IS NOT NULL, caller_subject,
                    idempotency_key, response_body IS NULL, receipt_dropped_at IS NOT NULL
               FROM registry_internal.registry_idempotency
              ORDER BY created_at",
            &[&horizon_reference],
        )
        .await
        .expect("administrator can inspect spent keys");
    let rows = rows
        .iter()
        .map(|row| {
            (
                row.get::<_, bool>(0),
                row.get::<_, bool>(1),
                row.get::<_, Option<String>>(2),
                row.get::<_, Option<String>>(3),
                row.get::<_, bool>(4),
                row.get::<_, bool>(5),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        rows,
        vec![
            (true, false, None, None, true, true),
            (
                false,
                true,
                Some(PRINCIPAL_CANARY.to_owned()),
                Some("fresh-key".to_owned()),
                false,
                false
            ),
        ],
        "the sweep clears the raw caller and key past the horizon only"
    );
    assert_eq!(
        spent(
            &database
                .admin
                .query_one(
                    &format!("{spent_columns} WHERE key_reference = $1"),
                    &[&horizon_reference],
                )
                .await
                .expect("the spent row remains after the sweep"),
        ),
        horizon_spent,
        "the digest, binding, scope, kind, and times are kept"
    );
    assert_eq!(
        coordinator.execute(&mut client, retry()).await,
        Err(MutationError::IdempotencyExpired)
    );
    assert_eq!(
        coordinator
            .execute(
                &mut client,
                create_request(
                    &plan,
                    "horizon-key",
                    &claims,
                    RECORD_POSITIVE,
                    "changed-label",
                    Some(1),
                ),
            )
            .await,
        Err(MutationError::IdempotencyConflict),
        "a changed retry of the cleared key is still a conflict"
    );
    assert_eq!(
        effect_counts(durable_counts(&database, table).await),
        effect_counts(committed)
    );
    let other_caller = mutation_claims(&compiled, "second-caller-subject", "zone-a");
    let other = coordinator
        .execute(
            &mut client,
            create_request(
                &plan,
                "horizon-key",
                &other_caller,
                RECORD_POSITIVE,
                "other-caller-label",
                Some(1),
            ),
        )
        .await
        .expect("another caller's identical key is its own fresh key");
    assert!(!other.replayed());
    let after_other = durable_counts(&database, table).await;
    assert_eq!(after_other.current, committed.current + 1);
    assert_eq!(after_other.idempotency, committed.idempotency + 1);
    let sweep_entries = database
        .audit_entries()
        .into_iter()
        .filter(|entry| entry["schema"] == "breg-idempotency-retention-audit/v1")
        .collect::<Vec<_>>();
    assert_eq!(sweep_entries.len(), 4, "{sweep_entries:?}");
    assert_eq!(sweep_entries[1]["record"]["outcome"], "erased");
    assert_eq!(sweep_entries[1]["record"]["erased"], 1);
    drop(client);
    database.cleanup().await;
}

/// The receipt sweep clears the raw issuer, subject, and key of every spent
/// row past its horizon, including one whose held response request
/// retention already erased, and keeps its digest, binding, scope, kind, and
/// times, so neither key is freed. No raw caller outlives its horizon.
#[cfg(feature = "tooling")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_receipt_sweep_clears_the_raw_caller_of_every_expired_spent_key() {
    use registry_breg::idempotency_retention::IdempotencyRetentionOperatorService;
    use registry_breg::postgres::ExpectedManagedCatalog;

    let database = TestDatabase::create(2).await;
    let (compiled, identity, pool) = prepared_mutation_registry(&database).await;
    let plan = MutationPlan::from_compiled(&compiled, "records.widget.create")
        .expect("create plan comes from the compiled inventory");
    let claims = mutation_claims(&compiled, PRINCIPAL_CANARY, "zone-a");
    let table = &compiled.entities()["widget"].physical_table;
    let mut client = pool
        .get_for_test()
        .await
        .expect("runtime connection is available");
    let coordinator = audited_coordinator(&database, &identity);
    for (key, label) in [("held-key", "held-label"), ("erased-key", "erased-label")] {
        coordinator
            .execute(
                &mut client,
                create_request(&plan, key, &claims, RECORD_POSITIVE, label, Some(1)),
            )
            .await
            .expect("the first attempt executes");
    }
    database
        .admin
        .batch_execute(
            "UPDATE registry_internal.registry_idempotency
                SET created_at = CURRENT_TIMESTAMP - INTERVAL '9 days',
                    receipt_expires_at = CURRENT_TIMESTAMP - INTERVAL '2 days';
             UPDATE registry_internal.registry_idempotency
                SET response_body = NULL,
                    erased_at = CURRENT_TIMESTAMP
              WHERE idempotency_key = 'erased-key';",
        )
        .await
        .expect("administrator ages both receipts and erases one held response");
    let spent = |rows: Vec<tokio_postgres::Row>| {
        rows.iter()
            .map(|row| {
                (
                    (0..6).map(|i| row.get::<_, String>(i)).collect::<Vec<_>>(),
                    row.get::<_, bool>(6),
                )
            })
            .collect::<Vec<_>>()
    };
    let spent_rows = "SELECT key_reference, binding_reference, key_scope, result_kind,
                             created_at::text, receipt_expires_at::text,
                             caller_issuer IS NULL AND caller_subject IS NULL
                                 AND idempotency_key IS NULL
                        FROM registry_internal.registry_idempotency
                       ORDER BY key_reference";
    let before = spent(
        database
            .admin
            .query(spent_rows, &[])
            .await
            .expect("administrator can read the spent keys"),
    );
    assert!(before.iter().all(|(_, cleared)| !cleared));
    let committed = durable_counts(&database, table).await;

    let sweep = IdempotencyRetentionOperatorService::new_for_test(
        identity.clone(),
        ExpectedManagedCatalog::compiled(&compiled),
        RegistryLockKey::derive(PACKAGE_ID).expect("lock id is bounded"),
        database.migration_config.clone(),
        database.migration_role.clone(),
        database.runtime_role.clone(),
        database.audit(
            AuditProfile::production_from_secret_bytes(vec![0x5e; 32].into())
                .expect("test owns a strong keyed audit profile"),
        ),
    );
    assert_eq!(
        sweep
            .erase_expired(chrono::Utc::now())
            .await
            .expect("the sweep drops both expired receipts"),
        2
    );
    let after = spent(
        database
            .admin
            .query(spent_rows, &[])
            .await
            .expect("both spent rows remain after the sweep"),
    );
    assert_eq!(
        after,
        before
            .into_iter()
            .map(|(kept, _)| (kept, true))
            .collect::<Vec<_>>(),
        "the raw caller and key are cleared and everything else is kept"
    );
    assert_eq!(
        coordinator
            .execute(
                &mut client,
                create_request(
                    &plan,
                    "held-key",
                    &claims,
                    RECORD_POSITIVE,
                    "held-label",
                    Some(1),
                ),
            )
            .await,
        Err(MutationError::IdempotencyExpired)
    );
    assert_eq!(
        coordinator
            .execute(
                &mut client,
                create_request(
                    &plan,
                    "erased-key",
                    &claims,
                    RECORD_POSITIVE,
                    "erased-label",
                    Some(1),
                ),
            )
            .await,
        Err(MutationError::IdempotencyConflict),
        "a key whose held response was erased stays spent"
    );
    assert_eq!(
        effect_counts(durable_counts(&database, table).await),
        effect_counts(committed)
    );
    drop(client);
    database.cleanup().await;
}

/// Upgrading from the table shape that keyed rows by an audit-key HMAC keeps
/// every spent row as a tombstone no caller can find, since none carries the
/// caller its key belongs to, and leaves the caller-scoped shape in place for
/// the next write. One migration converts every shape the earlier engine
/// could leave: a held response of each result kind, a held response request
/// retention already erased (`erased_at` set, no body), and a key whose
/// record history erasure turned it into the `erased` kind while keeping its
/// erased body.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_upgrade_from_the_audit_keyed_idempotency_shape_tombstones_spent_rows() {
    let database = TestDatabase::create(1).await;
    let (migration, migration_task) = database.connect_migration().await;
    install_mutation_schema(&migration, &database.runtime_role)
        .await
        .expect("clean mutation schema installs");
    migration
        .batch_execute(
            "ALTER TABLE registry_internal.registry_idempotency
                 DROP CONSTRAINT registry_idempotency_caller_shape,
                 DROP CONSTRAINT registry_idempotency_erasure_shape;
             DROP INDEX registry_internal.registry_idempotency_caller_key;
             ALTER TABLE registry_internal.registry_idempotency
                 DROP COLUMN caller_issuer,
                 DROP COLUMN caller_subject,
                 DROP COLUMN key_scope,
                 DROP COLUMN idempotency_key,
                 DROP COLUMN receipt_expires_at,
                 DROP COLUMN receipt_dropped_at;
             ALTER TABLE registry_internal.registry_idempotency
                 ADD CONSTRAINT registry_idempotency_erasure_shape
                     CHECK ((response_body IS NULL) = (erased_at IS NOT NULL));
             INSERT INTO registry_internal.registry_idempotency
                 (key_reference, binding_reference, result_kind, record_reference,
                  record_revision, result_count, proposal_version, response_status,
                  response_body, response_headers, created_at, erased_at)
             VALUES
                 ('hmac-sha256:application-erased', 'hmac-sha256:application-erased-binding',
                  'application', 'sha256:request', 2, 1, 1,
                  200, NULL, '\\x0000',
                  transaction_timestamp() - interval '3 days',
                  transaction_timestamp() - interval '1 day'),
                 ('hmac-sha256:batch', 'hmac-sha256:batch-binding', 'batch', NULL,
                  NULL, 2, NULL,
                  200, '{\"results\":[]}', '\\x0000',
                  transaction_timestamp() - interval '2 days', NULL),
                 ('hmac-sha256:history-erased', 'hmac-sha256:history-erased-binding',
                  'erased', NULL, NULL, NULL, NULL,
                  200, '{\"erased\":true}', '\\x0000',
                  transaction_timestamp() - interval '30 days', NULL),
                 ('hmac-sha256:held', 'hmac-sha256:held-binding', 'immediate_action', NULL,
                  NULL, 0, NULL,
                  200, '{}', '\\x0000',
                  transaction_timestamp(), NULL),
                 ('hmac-sha256:record', 'hmac-sha256:record-binding', 'record', 'sha256:record',
                  3, NULL, NULL,
                  201, '{\"id\":\"record\"}', '\\x000101',
                  transaction_timestamp() - interval '400 days', NULL),
                 ('hmac-sha256:release', 'hmac-sha256:release-binding', 'release',
                  'sha256:release', 1, NULL, NULL,
                  201, '{\"version\":1}', '\\x0000',
                  transaction_timestamp() - interval '1 hour', NULL);",
        )
        .await
        .expect("the audit-keyed table shape is restored with every spent-row shape");

    for attempt in ["upgrade", "reinstall"] {
        install_mutation_schema(&migration, &database.runtime_role)
            .await
            .unwrap_or_else(|_| panic!("{attempt} of the caller-scoped shape succeeds"));
    }
    let remaining = database
        .admin
        .query(
            "SELECT key_reference, binding_reference, result_kind, record_reference,
                    record_revision, result_count, proposal_version, response_status,
                    caller_issuer, caller_subject, key_scope, idempotency_key,
                    response_body IS NULL, response_headers,
                    receipt_dropped_at IS NOT NULL,
                    receipt_expires_at = created_at + interval '1 microsecond',
                    erased_at IS NOT NULL
               FROM registry_internal.registry_idempotency
              ORDER BY key_reference COLLATE \"C\"",
            &[],
        )
        .await
        .expect("administrator can read spent keys");
    type Kept = (
        &'static str,
        &'static str,
        Option<&'static str>,
        Option<i64>,
        Option<i16>,
        Option<i64>,
        i16,
        bool,
    );
    // Key suffix, result kind, record reference, record revision, result
    // count, proposal version, response status, and whether request
    // retention had erased the held response: everything the earlier row
    // carried that the tombstone keeps.
    let expected: [Kept; 6] = [
        (
            "application-erased",
            "application",
            Some("sha256:request"),
            Some(2),
            Some(1),
            Some(1),
            200,
            true,
        ),
        ("batch", "batch", None, None, Some(2), None, 200, false),
        (
            "held",
            "immediate_action",
            None,
            None,
            Some(0),
            None,
            200,
            false,
        ),
        (
            "history-erased",
            "erased",
            None,
            None,
            None,
            None,
            200,
            false,
        ),
        (
            "record",
            "record",
            Some("sha256:record"),
            Some(3),
            None,
            None,
            201,
            false,
        ),
        (
            "release",
            "release",
            Some("sha256:release"),
            Some(1),
            None,
            None,
            201,
            false,
        ),
    ];
    assert_eq!(
        remaining.len(),
        expected.len(),
        "the upgrade keeps every audit-keyed spent row"
    );
    for (row, (suffix, kind, record, revision, count, proposal, status, erased)) in
        remaining.iter().zip(expected)
    {
        let key = format!("hmac-sha256:{suffix}");
        assert_eq!(row.get::<_, String>(0), key);
        assert_eq!(row.get::<_, String>(1), format!("{key}-binding"), "{key}");
        assert_eq!(row.get::<_, String>(2), kind, "{key}");
        assert_eq!(row.get::<_, Option<String>>(3).as_deref(), record, "{key}");
        assert_eq!(row.get::<_, Option<i64>>(4), revision, "{key}");
        assert_eq!(row.get::<_, Option<i16>>(5), count, "{key}");
        assert_eq!(row.get::<_, Option<i64>>(6), proposal, "{key}");
        assert_eq!(row.get::<_, i16>(7), status, "{key}");
        assert_eq!(
            row.get::<_, Option<String>>(8),
            None,
            "{key}: no issuer is kept"
        );
        assert_eq!(
            row.get::<_, Option<String>>(9),
            None,
            "{key}: no subject is kept"
        );
        assert_eq!(row.get::<_, String>(10), "mutation", "{key}");
        assert_eq!(
            row.get::<_, Option<String>>(11),
            None,
            "{key}: no key is kept"
        );
        assert!(row.get::<_, bool>(12), "{key}: no held response survives");
        assert_eq!(
            row.get::<_, Vec<u8>>(13),
            vec![0, 0],
            "{key}: no held header survives"
        );
        assert!(row.get::<_, bool>(14), "{key}: the receipt is dropped");
        assert!(
            row.get::<_, bool>(15),
            "{key}: the receipt expired at its commit"
        );
        assert_eq!(
            row.get::<_, bool>(16),
            erased,
            "{key}: the erasure time is kept"
        );
    }
    let constraints = database
        .admin
        .query(
            "SELECT conname::text, convalidated
               FROM pg_catalog.pg_constraint
              WHERE conrelid = 'registry_internal.registry_idempotency'::regclass
                AND conname IN ('registry_idempotency_caller_shape',
                                'registry_idempotency_erasure_shape',
                                'registry_idempotency_result_shape',
                                'registry_idempotency_result_kind_values')
              ORDER BY conname",
            &[],
        )
        .await
        .expect("administrator can read the spent-key constraints");
    assert_eq!(
        constraints
            .iter()
            .map(|row| (row.get::<_, String>(0), row.get::<_, bool>(1)))
            .collect::<Vec<_>>(),
        [
            "registry_idempotency_caller_shape",
            "registry_idempotency_erasure_shape",
            "registry_idempotency_result_kind_values",
            "registry_idempotency_result_shape",
        ]
        .map(|name| (name.to_owned(), true)),
        "every converted row satisfies the caller-scoped constraints"
    );
    let caller_index_is_unique = database
        .admin
        .query_one(
            "SELECT indisunique AND indisvalid
               FROM pg_catalog.pg_index
              WHERE indexrelid = 'registry_internal.registry_idempotency_caller_key'::regclass",
            &[],
        )
        .await
        .expect("administrator can read the caller index")
        .get::<_, bool>(0);
    assert!(
        caller_index_is_unique,
        "the converted rows hold the unique caller index"
    );
    let refused = migration
        .batch_execute(
            "INSERT INTO registry_internal.registry_idempotency
                 (key_reference, binding_reference, result_kind, result_count,
                  response_status, response_body, response_headers)
             VALUES ('sha256:unscoped', 'sha256:unscoped-binding', 'immediate_action', 0,
                     200, '{}', '\\x0000')",
        )
        .await;
    assert!(
        refused.is_err(),
        "a spent key without its caller scope is refused"
    );
    // The raw caller and key are present together exactly while the receipt
    // is, and absent together once it is dropped.
    for (label, issuer, subject, key, dropped, accepted) in [
        ("cleared", None, None, None::<&str>, true, true),
        ("cleared-held", None, None, None, false, false),
        (
            "dropped-with-caller",
            Some("https://issuer.example"),
            Some("subject"),
            Some("key"),
            true,
            false,
        ),
        (
            "partly-cleared",
            Some("https://issuer.example"),
            None,
            None,
            true,
            false,
        ),
        (
            "keyless",
            Some("https://issuer.example"),
            Some("subject"),
            None,
            true,
            false,
        ),
    ] {
        let body = (!dropped).then_some("{}".as_bytes());
        let inserted = migration
            .execute(
                "INSERT INTO registry_internal.registry_idempotency
                     (key_reference, binding_reference, result_kind, result_count,
                      response_status, response_body, response_headers,
                      caller_issuer, caller_subject, key_scope, idempotency_key,
                      receipt_expires_at, receipt_dropped_at)
                 VALUES ($1, 'sha256:shape-binding', 'immediate_action', 0,
                         200, $2, '\\x0000', $3, $4, 'mutation', $5,
                         transaction_timestamp() + interval '1 day',
                         CASE WHEN $6 THEN transaction_timestamp() END)",
                &[
                    &format!("sha256:{label}"),
                    &body,
                    &issuer,
                    &subject,
                    &key,
                    &dropped,
                ],
            )
            .await;
        assert_eq!(inserted.is_ok(), accepted, "{label}: {inserted:?}");
    }
    migration_task.abort();
    database.cleanup().await;
}
