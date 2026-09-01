// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, Response, StatusCode};
use postgres_harness::TestDatabase;
use registry_platform_audit::AuditProfile;
use registry_platform_canonical_json::canonicalize_json;
use registry_server::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedClaimValue,
    VerifiedRequestClaims,
};
use registry_server::compiler::{compile_project_with_assets, CompileProfile};
use registry_server::contract::{parse_project_json, ModuleAssetSource};
use registry_server::cursor::CursorCodec;
use registry_server::history_schema::{serialize_descriptor, HistorySchemaDescriptor};
use registry_server::postgres::{
    initialize_registry_state_for_catalog_test, install_compiled_schema, ExpectedManagedCatalog,
    ExpectedRegistryIdentity, PostgresRecordReadService, PostgresSnapshotReadService,
    RegistryLockKey, RegistryStateTestIdentity,
};
use serde_json::{json, Value};
use tokio_postgres::{Client, Transaction};
use tower::Service as _;
use uuid::Uuid;
use zeroize::Zeroizing;

const PACKAGE_ID: &str = "history-registry";
const INSTANCE_ID: &str = "history-instance";
const DATABASE_ID: &str = "history-database";
const PACKAGE_REVISION: &str = "package-history-1";
const PRINCIPAL_CANARY: &str = "history-principal-must-not-leak";
const HMAC_REF: &str =
    "hmac-sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const OLD_REFERENCE_UUID: &str = "10000000-0000-4000-8000-000000000001";
const LATEST_REFERENCE_UUID: &str = "10000000-0000-4000-8000-000000000002";
const LATER_REFERENCE_UUID: &str = "10000000-0000-4000-8000-000000000003";
const BULK_FIRST_REFERENCE_UUID: &str = "10000000-0000-4000-8000-000000000004";
const BULK_SECOND_REFERENCE_UUID: &str = "10000000-0000-4000-8000-000000000005";
const BULK_LATER_REFERENCE_UUID: &str = "10000000-0000-4000-8000-000000000006";
const LINEAGE_UUID: &str = "20000000-0000-4000-8000-000000000000";

const MEMBERSHIP: &str = "00000000-0000-4000-8000-000000000001";
const TOMBSTONED: &str = "00000000-0000-4000-8000-000000000002";
const LATER_VISIBLE: &str = "00000000-0000-4000-8000-000000000003";
const LATER_COMMIT: &str = "00000000-0000-4000-8000-000000000004";
const OTHER_JURISDICTION: &str = "00000000-0000-4000-8000-000000000005";
const AUTHORITY_CHANGED: &str = "00000000-0000-4000-8000-000000000006";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshot_http_reconstructs_before_filters_and_keeps_pages_pinned() {
    let mut database = prepared_database().await;
    let app = snapshot_router(
        database.pool.clone(),
        database.compiled.clone(),
        database.identity.clone(),
        database.lock_key,
        database.audit_profile.clone(),
        database.cursors.clone(),
        None,
    );

    let old = send(
        &app,
        &format!(
            "/v1/records/memberships:snapshot?snapshot={}&validAt=2026-06-05&$select=householdCode&$filter=householdCode%20eq%20'B'&$count=true",
            snapshot_ref(OLD_REFERENCE_UUID)
        ),
        Some(history_claims(["zone-a"])),
    )
    .await;
    assert_eq!(old.status(), StatusCode::OK);
    let old = body_json(old).await;
    assert_eq!(old["snapshot"], snapshot_ref(OLD_REFERENCE_UUID));
    assert_eq!(old["validAt"], "2026-06-05");
    assert_eq!(old["count"], 1);
    assert_eq!(old["items"][0]["id"], MEMBERSHIP);
    assert_eq!(old["items"][0]["revision"], 1);
    assert_eq!(old["items"][0]["data"], json!({"householdCode": "B"}));

    let corrected = send(
        &app,
        &format!(
            "/v1/records/memberships:snapshot?snapshot={}&validAt=2026-06-05&$select=householdCode&$filter=householdCode%20eq%20'A'",
            snapshot_ref(LATEST_REFERENCE_UUID)
        ),
        Some(history_claims(["zone-a"])),
    )
    .await;
    assert_eq!(corrected.status(), StatusCode::OK);
    let corrected = body_json(corrected).await;
    assert_eq!(corrected["items"].as_array().unwrap().len(), 1);
    assert_eq!(corrected["items"][0]["id"], MEMBERSHIP);
    assert_eq!(
        corrected["items"][0]["revision"], 3,
        "the highest revision in the same commit wins before filters run"
    );

    let obsolete = send(
        &app,
        &format!(
            "/v1/records/memberships:snapshot?snapshot={}&$select=householdCode&$filter=householdCode%20eq%20'OBSOLETE'",
            snapshot_ref(LATEST_REFERENCE_UUID)
        ),
        Some(history_claims(["zone-a"])),
    )
    .await;
    assert_eq!(obsolete.status(), StatusCode::OK);
    assert!(
        body_json(obsolete).await["items"]
            .as_array()
            .unwrap()
            .is_empty(),
        "a superseded revision from the selected record cannot reappear"
    );

    let tombstone = send(
        &app,
        &format!(
            "/v1/records/memberships:snapshot?snapshot={}&$select=householdCode&$filter=householdCode%20eq%20'TOMBSTONE-MATCH'",
            snapshot_ref(LATEST_REFERENCE_UUID)
        ),
        Some(history_claims(["zone-a"])),
    )
    .await;
    assert_eq!(tombstone.status(), StatusCode::OK);
    assert!(
        body_json(tombstone).await["items"]
            .as_array()
            .unwrap()
            .is_empty(),
        "a tombstoned latest version suppresses older active versions"
    );

    let other_jurisdiction = send(
        &app,
        &format!(
            "/v1/records/memberships:snapshot?snapshot={}&$select=householdCode&$filter=householdCode%20eq%20'OTHER'",
            snapshot_ref(LATEST_REFERENCE_UUID)
        ),
        Some(history_claims(["zone-b"])),
    )
    .await;
    assert_eq!(other_jurisdiction.status(), StatusCode::OK);
    let other_jurisdiction = body_json(other_jurisdiction).await;
    let ids = item_ids(&other_jurisdiction);
    assert_eq!(ids, vec![OTHER_JURISDICTION]);

    let first_page = send(
        &app,
        "/v1/records/memberships:snapshot?validAt=2026-06-05&$select=householdCode&$orderby=householdCode&$top=1&$count=true",
        Some(history_claims(["zone-a"])),
    )
    .await;
    assert_eq!(first_page.status(), StatusCode::OK);
    let first_page = body_json(first_page).await;
    assert_eq!(first_page["snapshot"], snapshot_ref(LATEST_REFERENCE_UUID));
    assert_eq!(first_page["count"], 2);
    assert_eq!(first_page["items"][0]["id"], MEMBERSHIP);
    let cursor = first_page["pageInfo"]["nextCursor"]
        .as_str()
        .expect("first page carries continuation")
        .to_owned();

    append_later_visible_commit(&mut database.migration).await;

    let second_page = send(
        &app,
        &format!("/v1/records/memberships:snapshot?$skiptoken={cursor}"),
        Some(history_claims(["zone-a"])),
    )
    .await;
    assert_eq!(second_page.status(), StatusCode::OK);
    let second_page = body_json(second_page).await;
    assert_eq!(second_page["snapshot"], snapshot_ref(LATEST_REFERENCE_UUID));
    assert_eq!(
        second_page["count"], 2,
        "continuation count remains bound to the captured snapshot"
    );
    assert_eq!(item_ids(&second_page), vec![LATER_VISIBLE]);

    let latest_after_write = send(
        &app,
        "/v1/records/memberships:snapshot?validAt=2026-06-05&$select=householdCode&$count=true",
        Some(history_claims(["zone-a"])),
    )
    .await;
    assert_eq!(latest_after_write.status(), StatusCode::OK);
    let latest_after_write = body_json(latest_after_write).await;
    assert_eq!(
        latest_after_write["snapshot"],
        snapshot_ref(LATER_REFERENCE_UUID)
    );
    assert_eq!(latest_after_write["count"], 3);

    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshot_valid_at_bounds_are_start_inclusive_end_exclusive_and_optional() {
    let database = prepared_database().await;
    let app = snapshot_router(
        database.pool.clone(),
        database.compiled.clone(),
        database.identity.clone(),
        database.lock_key,
        database.audit_profile.clone(),
        database.cursors.clone(),
        None,
    );

    let start_inclusive = send(
        &app,
        &format!(
            "/v1/records/memberships:snapshot?snapshot={}&validAt=2026-06-01&$select=householdCode&$filter=householdCode%20eq%20'B'",
            snapshot_ref(OLD_REFERENCE_UUID)
        ),
        Some(history_claims(["zone-a"])),
    )
    .await;
    assert_eq!(start_inclusive.status(), StatusCode::OK);
    let start_inclusive = body_json(start_inclusive).await;
    assert_eq!(item_ids(&start_inclusive), vec![MEMBERSHIP]);

    let before_start = send(
        &app,
        &format!(
            "/v1/records/memberships:snapshot?snapshot={}&validAt=2026-05-31&$select=householdCode&$filter=householdCode%20eq%20'B'",
            snapshot_ref(OLD_REFERENCE_UUID)
        ),
        Some(history_claims(["zone-a"])),
    )
    .await;
    assert_eq!(before_start.status(), StatusCode::OK);
    assert!(body_json(before_start).await["items"]
        .as_array()
        .unwrap()
        .is_empty());

    let before_end = send(
        &app,
        &format!(
            "/v1/records/memberships:snapshot?snapshot={}&validAt=2026-06-14&$select=householdCode&$filter=householdCode%20eq%20'A'",
            snapshot_ref(LATEST_REFERENCE_UUID)
        ),
        Some(history_claims(["zone-a"])),
    )
    .await;
    assert_eq!(before_end.status(), StatusCode::OK);
    let before_end = body_json(before_end).await;
    assert_eq!(item_ids(&before_end), vec![MEMBERSHIP]);

    let end_exclusive = send(
        &app,
        &format!(
            "/v1/records/memberships:snapshot?snapshot={}&validAt=2026-06-15&$select=householdCode&$filter=householdCode%20eq%20'A'",
            snapshot_ref(LATEST_REFERENCE_UUID)
        ),
        Some(history_claims(["zone-a"])),
    )
    .await;
    assert_eq!(end_exclusive.status(), StatusCode::OK);
    assert!(body_json(end_exclusive).await["items"]
        .as_array()
        .unwrap()
        .is_empty());

    let no_valid_at = send(
        &app,
        &format!(
            "/v1/records/memberships:snapshot?snapshot={}&$select=householdCode&$filter=householdCode%20eq%20'A'",
            snapshot_ref(LATEST_REFERENCE_UUID)
        ),
        Some(history_claims(["zone-a"])),
    )
    .await;
    assert_eq!(no_valid_at.status(), StatusCode::OK);
    let no_valid_at = body_json(no_valid_at).await;
    assert_eq!(item_ids(&no_valid_at), vec![MEMBERSHIP]);
    assert!(
        no_valid_at.get("validAt").is_none(),
        "omitting validAt must not inject a server clock into the snapshot query"
    );

    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshot_timestamp_valid_at_requires_utc_timestamp_and_filters_pg_rows() {
    let database = prepared_timestamp_database().await;
    let app = snapshot_router(
        database.pool.clone(),
        database.compiled.clone(),
        database.identity.clone(),
        database.lock_key,
        database.audit_profile.clone(),
        database.cursors.clone(),
        None,
    );

    let start = send(
        &app,
        &format!(
            "/v1/records/memberships:snapshot?snapshot={}&validAt=2026-06-05T00:00:00Z&$select=householdCode",
            snapshot_ref(OLD_REFERENCE_UUID)
        ),
        Some(history_claims(["zone-a"])),
    )
    .await;
    assert_eq!(start.status(), StatusCode::OK);
    let start = body_json(start).await;
    assert_eq!(start["validAt"], "2026-06-05T00:00:00Z");
    assert_eq!(item_ids(&start), vec![MEMBERSHIP]);

    let end = send(
        &app,
        &format!(
            "/v1/records/memberships:snapshot?snapshot={}&validAt=2026-06-05T12:00:00Z&$select=householdCode",
            snapshot_ref(OLD_REFERENCE_UUID)
        ),
        Some(history_claims(["zone-a"])),
    )
    .await;
    assert_eq!(end.status(), StatusCode::OK);
    assert!(body_json(end).await["items"].as_array().unwrap().is_empty());

    for rejected in ["2026-06-05", "2026-06-05T00:00:00%2B07:00"] {
        let response = send(
            &app,
            &format!(
                "/v1/records/memberships:snapshot?snapshot={}&validAt={rejected}&$select=householdCode",
                snapshot_ref(OLD_REFERENCE_UUID)
            ),
            Some(history_claims(["zone-a"])),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshot_row_authority_uses_selected_historical_row_values() {
    let database = prepared_database().await;
    let app = snapshot_router(
        database.pool.clone(),
        database.compiled.clone(),
        database.identity.clone(),
        database.lock_key,
        database.audit_profile.clone(),
        database.cursors.clone(),
        None,
    );

    let old_zone_a = send(
        &app,
        &format!(
            "/v1/records/memberships:snapshot?snapshot={}&$select=householdCode&$filter=householdCode%20eq%20'AUTHORITY'",
            snapshot_ref(OLD_REFERENCE_UUID)
        ),
        Some(history_claims(["zone-a"])),
    )
    .await;
    assert_eq!(old_zone_a.status(), StatusCode::OK);
    let old_zone_a = body_json(old_zone_a).await;
    assert_eq!(item_ids(&old_zone_a), vec![AUTHORITY_CHANGED]);
    assert_eq!(old_zone_a["items"][0]["revision"], 1);

    let old_zone_b = send(
        &app,
        &format!(
            "/v1/records/memberships:snapshot?snapshot={}&$select=householdCode&$filter=householdCode%20eq%20'AUTHORITY'",
            snapshot_ref(OLD_REFERENCE_UUID)
        ),
        Some(history_claims(["zone-b"])),
    )
    .await;
    assert_eq!(old_zone_b.status(), StatusCode::OK);
    assert!(body_json(old_zone_b).await["items"]
        .as_array()
        .unwrap()
        .is_empty());

    let latest_zone_a = send(
        &app,
        &format!(
            "/v1/records/memberships:snapshot?snapshot={}&$select=householdCode&$filter=householdCode%20eq%20'AUTHORITY'",
            snapshot_ref(LATEST_REFERENCE_UUID)
        ),
        Some(history_claims(["zone-a"])),
    )
    .await;
    assert_eq!(latest_zone_a.status(), StatusCode::OK);
    assert!(body_json(latest_zone_a).await["items"]
        .as_array()
        .unwrap()
        .is_empty());

    let latest_zone_b = send(
        &app,
        &format!(
            "/v1/records/memberships:snapshot?snapshot={}&$select=householdCode&$filter=householdCode%20eq%20'AUTHORITY'",
            snapshot_ref(LATEST_REFERENCE_UUID)
        ),
        Some(history_claims(["zone-b"])),
    )
    .await;
    assert_eq!(latest_zone_b.status(), StatusCode::OK);
    let latest_zone_b = body_json(latest_zone_b).await;
    assert_eq!(item_ids(&latest_zone_b), vec![AUTHORITY_CHANGED]);
    assert_eq!(latest_zone_b["items"][0]["revision"], 2);

    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshot_count_filter_probe_stays_bounded_and_pinned() {
    const BULK_RECORDS: usize = 2_000;
    let mut database = prepared_database().await;
    seed_bulk_history(&mut database.migration, BULK_RECORDS).await;
    let app = snapshot_router(
        database.pool.clone(),
        database.compiled.clone(),
        database.identity.clone(),
        database.lock_key,
        database.audit_profile.clone(),
        database.cursors.clone(),
        None,
    );

    let started = Instant::now();
    let first_page = send(
        &app,
        "/v1/records/memberships:snapshot?$select=householdCode&$filter=householdCode%20eq%20'probe-even'&$orderby=householdCode&$top=100&$count=true",
        Some(history_claims(["zone-a"])),
    )
    .await;
    assert_eq!(first_page.status(), StatusCode::OK);
    let first_page = body_json(first_page).await;
    assert_eq!(
        first_page["snapshot"],
        snapshot_ref(BULK_SECOND_REFERENCE_UUID)
    );
    assert_eq!(first_page["count"], (BULK_RECORDS / 2) as i64);
    assert_eq!(first_page["items"].as_array().unwrap().len(), 100);
    let cursor = first_page["pageInfo"]["nextCursor"]
        .as_str()
        .expect("bulk probe first page carries continuation")
        .to_owned();

    append_bulk_later_match_commit(&mut database.migration).await;

    let second_page = send(
        &app,
        &format!("/v1/records/memberships:snapshot?$skiptoken={cursor}"),
        Some(history_claims(["zone-a"])),
    )
    .await;
    assert_eq!(second_page.status(), StatusCode::OK);
    let second_page = body_json(second_page).await;
    assert_eq!(
        second_page["snapshot"],
        snapshot_ref(BULK_SECOND_REFERENCE_UUID)
    );
    assert_eq!(second_page["count"], (BULK_RECORDS / 2) as i64);
    assert_eq!(second_page["items"].as_array().unwrap().len(), 100);

    let fresh = send(
        &app,
        "/v1/records/memberships:snapshot?$select=householdCode&$filter=householdCode%20eq%20'probe-even'&$count=true",
        Some(history_claims(["zone-a"])),
    )
    .await;
    assert_eq!(fresh.status(), StatusCode::OK);
    let fresh = body_json(fresh).await;
    assert_eq!(fresh["snapshot"], snapshot_ref(BULK_LATER_REFERENCE_UUID));
    assert_eq!(fresh["count"], (BULK_RECORDS / 2 + 1) as i64);
    eprintln!(
        "snapshot bulk probe records={BULK_RECORDS} revisions={} elapsed_ms={}",
        BULK_RECORDS * 2,
        started.elapsed().as_millis()
    );

    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshot_refuses_derived_fields_missing_descriptors_and_terminal_audit_failure() {
    let database = prepared_database().await;
    let app = snapshot_router(
        database.pool.clone(),
        database.compiled.clone(),
        database.identity.clone(),
        database.lock_key,
        database.audit_profile.clone(),
        database.cursors.clone(),
        None,
    );

    let derived = send(
        &app,
        "/v1/records/memberships:snapshot?$select=memberCount",
        Some(history_claims(["zone-a"])),
    )
    .await;
    assert_eq!(derived.status(), StatusCode::BAD_REQUEST);
    let derived = body_json(derived).await;
    assert_eq!(derived["code"], "query.invalid");

    let stored_only = send(
        &app,
        &format!(
            "/v1/records/memberships:snapshot?snapshot={}&$select=householdCode",
            snapshot_ref(LATEST_REFERENCE_UUID)
        ),
        Some(history_claims(["zone-a"])),
    )
    .await;
    assert_eq!(stored_only.status(), StatusCode::OK);
    let stored_only = body_json(stored_only).await;
    for item in stored_only["items"].as_array().unwrap() {
        assert!(
            item["data"].get("memberCount").is_none(),
            "snapshot reads must not evaluate or disclose live derived fields"
        );
    }

    database
        .migration
        .execute(
            "DELETE FROM registry_internal.registry_history_schemas WHERE package_revision = $1",
            &[&PACKAGE_REVISION],
        )
        .await
        .expect("migration can remove descriptor to prove fail-closed behavior");
    let missing_descriptor = send(
        &app,
        &format!(
            "/v1/records/memberships:snapshot?snapshot={}&$select=householdCode",
            snapshot_ref(LATEST_REFERENCE_UUID)
        ),
        Some(history_claims(["zone-a"])),
    )
    .await;
    assert_eq!(missing_descriptor.status(), StatusCode::SERVICE_UNAVAILABLE);
    let missing_descriptor = body_json(missing_descriptor).await;
    assert_eq!(missing_descriptor["code"], "source.unavailable");
    assert!(!missing_descriptor.to_string().contains(PRINCIPAL_CANARY));

    retain_descriptor(&database.migration, &database.compiled).await;
    let timeout_failing = snapshot_router(
        database.pool.clone(),
        database.compiled.clone(),
        database.identity.clone(),
        database.lock_key,
        database.audit_profile.clone(),
        database.cursors.clone(),
        Some(registry_server::postgres::SnapshotReadFaultPoint::HistoricalStatementTimeout),
    );
    let timeout_failure = send(
        &timeout_failing,
        &format!(
            "/v1/records/memberships:snapshot?snapshot={}&$select=householdCode",
            snapshot_ref(LATEST_REFERENCE_UUID)
        ),
        Some(history_claims(["zone-a"])),
    )
    .await;
    assert_eq!(timeout_failure.status(), StatusCode::SERVICE_UNAVAILABLE);
    let timeout_failure = body_json(timeout_failure).await;
    assert_eq!(timeout_failure["code"], "source.unavailable");
    assert!(!timeout_failure.to_string().contains(PRINCIPAL_CANARY));
    assert!(!timeout_failure.to_string().contains("householdCode"));
    assert!(!timeout_failure.to_string().contains("A"));

    let after_timeout = send(
        &app,
        &format!(
            "/v1/records/memberships:snapshot?snapshot={}&$select=householdCode&$filter=householdCode%20eq%20'A'",
            snapshot_ref(LATEST_REFERENCE_UUID)
        ),
        Some(history_claims(["zone-a"])),
    )
    .await;
    assert_eq!(after_timeout.status(), StatusCode::OK);
    let after_timeout = body_json(after_timeout).await;
    assert_eq!(item_ids(&after_timeout), vec![MEMBERSHIP]);

    let audit_failing = snapshot_router(
        database.pool.clone(),
        database.compiled.clone(),
        database.identity.clone(),
        database.lock_key,
        database.audit_profile.clone(),
        database.cursors.clone(),
        Some(registry_server::postgres::SnapshotReadFaultPoint::BeforeTerminalAudit),
    );
    let terminal_failure = send(
        &audit_failing,
        &format!(
            "/v1/records/memberships:snapshot?snapshot={}&$select=householdCode",
            snapshot_ref(LATEST_REFERENCE_UUID)
        ),
        Some(history_claims(["zone-a"])),
    )
    .await;
    assert_eq!(terminal_failure.status(), StatusCode::SERVICE_UNAVAILABLE);
    let terminal_failure = body_json(terminal_failure).await;
    assert_eq!(terminal_failure["code"], "source.unavailable");
    assert!(!terminal_failure.to_string().contains("householdCode"));
    assert!(!terminal_failure.to_string().contains("A"));

    database.cleanup().await;
}

struct PreparedHistoryDatabase {
    database: TestDatabase,
    migration: Client,
    migration_task: tokio::task::JoinHandle<()>,
    pool: registry_server::postgres::RuntimePool,
    compiled: Arc<registry_server::CompiledRegistry>,
    identity: ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    audit_profile: AuditProfile,
    cursors: Arc<CursorCodec>,
}

impl PreparedHistoryDatabase {
    async fn cleanup(self) {
        self.migration_task.abort();
        self.database.cleanup().await;
    }
}

async fn prepared_database() -> PreparedHistoryDatabase {
    let database = TestDatabase::create(8).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let compiled = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("migration installs compiled schema and internal history tables");
    retain_descriptor(&migration, &compiled).await;
    let identity = initialize_registry_state_for_catalog_test(
        &migration,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(&compiled),
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            environment: "local",
            instance_id: INSTANCE_ID,
            database_id: DATABASE_ID,
            package_revision: PACKAGE_REVISION,
            package_sequence: 1,
        },
    )
    .await
    .expect("migration initializes ready registry state");
    seed_history(&mut migration).await;
    let pool = database
        .runtime_config
        .build_pool()
        .expect("bounded runtime pool builds");
    PreparedHistoryDatabase {
        database,
        migration,
        migration_task,
        pool,
        compiled,
        identity,
        lock_key: RegistryLockKey::derive(PACKAGE_ID).expect("lock key is bounded"),
        audit_profile: AuditProfile::production_from_secret_bytes(vec![0x73; 32].into())
            .expect("test audit profile is keyed"),
        cursors: Arc::new(
            CursorCodec::new(Zeroizing::new(vec![0x74; 32]), Duration::from_secs(300))
                .expect("test cursor key is valid"),
        ),
    }
}

async fn prepared_timestamp_database() -> PreparedHistoryDatabase {
    let database = TestDatabase::create(8).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let compiled = Arc::new(compiled_timestamp_registry());
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("migration installs compiled timestamp schema and internal history tables");
    retain_descriptor(&migration, &compiled).await;
    let identity = initialize_registry_state_for_catalog_test(
        &migration,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(&compiled),
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            environment: "local",
            instance_id: INSTANCE_ID,
            database_id: DATABASE_ID,
            package_revision: PACKAGE_REVISION,
            package_sequence: 1,
        },
    )
    .await
    .expect("migration initializes ready timestamp registry state");
    seed_timestamp_history(&mut migration).await;
    let pool = database
        .runtime_config
        .build_pool()
        .expect("bounded runtime pool builds");
    PreparedHistoryDatabase {
        database,
        migration,
        migration_task,
        pool,
        compiled,
        identity,
        lock_key: RegistryLockKey::derive(PACKAGE_ID).expect("lock key is bounded"),
        audit_profile: AuditProfile::production_from_secret_bytes(vec![0x73; 32].into())
            .expect("test audit profile is keyed"),
        cursors: Arc::new(
            CursorCodec::new(Zeroizing::new(vec![0x74; 32]), Duration::from_secs(300))
                .expect("test cursor key is valid"),
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn snapshot_router(
    pool: registry_server::postgres::RuntimePool,
    registry: Arc<registry_server::CompiledRegistry>,
    identity: ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    profile: AuditProfile,
    cursors: Arc<CursorCodec>,
    fault: Option<registry_server::postgres::SnapshotReadFaultPoint>,
) -> axum::Router {
    let http_identity = ReadRuntimeIdentity {
        package_revision: identity.package_revision.clone(),
        schema_fingerprint: identity.schema_fingerprint.clone(),
    };
    let records = PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        profile.clone(),
        cursors.clone(),
    );
    let snapshots = PostgresSnapshotReadService::new(
        pool,
        registry.clone(),
        identity,
        lock_key,
        Duration::from_secs(2),
        profile,
        cursors.clone(),
    );
    let snapshots = match fault {
        Some(fault) => snapshots.with_fault_for_test(fault),
        None => snapshots,
    };
    router(Arc::new(
        HttpService::new(
            registry,
            http_identity,
            Arc::new(records),
            Arc::new(AlwaysReady),
            cursors,
        )
        .with_snapshots(Arc::new(snapshots)),
    ))
}

fn compiled_registry() -> registry_server::CompiledRegistry {
    compiled_registry_for_temporal_type("date")
}

fn compiled_timestamp_registry() -> registry_server::CompiledRegistry {
    compiled_registry_for_temporal_type("timestamp")
}

fn compiled_registry_for_temporal_type(temporal_type: &str) -> registry_server::CompiledRegistry {
    let project = r#"{
      "apiVersion":"registry.registrystack.org/v1alpha1",
      "kind":"RegistryProject",
      "registry":{"id":"history-demo","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
      "entities":[{
        "id":"membership","primaryDataset":"test-dataset","route":"memberships","mutationMode":"mutable","classification":"internal",
        "fields":[
          {"id":"household-code","type":"string","maxLength":32,"required":true,"classification":"internal"},
          {"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"internal"},
          {"id":"valid-from","type":"date","required":true,"classification":"internal"},
          {"id":"valid-to","type":"date","classification":"internal"}
        ],
        "temporal":{"startField":"valid-from","endField":"valid-to"},
        "derived":[{
          "id":"membership-rollup","sql":"sql/membership-rollup.sql","key":"id","execution":"live",
          "fields":[{"id":"member-count","type":"int64","classification":"restricted"}]
        }]
      }],
      "accessProfiles":[{
        "id":"historian","default":true,"principalClaim":"registry_principal",
        "requiredScopes":["registry.read"],"requiredPurposes":["case-management"],
        "grants":[{
          "entity":"membership","operations":["snapshot"],"readableFields":["household-code","jurisdiction","valid-from","valid-to","member-count"],
          "filterableFields":["household-code"],"sortableFields":["household-code"],"allowCount":true,
          "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdictions","operator":"in"}]
        }]
      }]
    }"#
    .replace("\"type\":\"date\"", &format!("\"type\":\"{temporal_type}\""));
    let project = parse_project_json(project.as_bytes()).expect("history fixture parses");
    let sql = "SELECT m.id AS id, 1::bigint AS member_count FROM registry_source.membership m";
    compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "sql/membership-rollup.sql".to_owned(),
            bytes: sql.as_bytes().to_vec(),
        }],
        CompileProfile::Authoring,
    )
    .expect("history fixture compiles")
}

async fn retain_descriptor(migration: &Client, compiled: &registry_server::CompiledRegistry) {
    let descriptor = HistorySchemaDescriptor::from_compiled_registry(compiled, PACKAGE_REVISION);
    let bytes = serialize_descriptor(&descriptor).expect("descriptor serializes canonically");
    migration
        .execute(
            "INSERT INTO registry_internal.registry_history_schemas
                 (package_revision, descriptor)
             VALUES ($1, $2)
             ON CONFLICT (package_revision) DO UPDATE SET descriptor = EXCLUDED.descriptor",
            &[&PACKAGE_REVISION, &bytes],
        )
        .await
        .expect("migration retains history descriptor");
}

async fn seed_history(migration: &mut Client) {
    let transaction = migration
        .transaction()
        .await
        .expect("migration begins history seed transaction");
    let lineage = uuid(LINEAGE_UUID);
    insert_commit_head(&transaction, lineage, 2).await;
    insert_commit(
        &transaction,
        0,
        uuid("30000000-0000-4000-8000-000000000000"),
        uuid("40000000-0000-4000-8000-000000000000"),
        lineage,
        "baseline",
    )
    .await;
    insert_commit(
        &transaction,
        1,
        uuid("30000000-0000-4000-8000-000000000001"),
        uuid(OLD_REFERENCE_UUID),
        lineage,
        "mutation",
    )
    .await;
    insert_commit(
        &transaction,
        2,
        uuid("30000000-0000-4000-8000-000000000002"),
        uuid(LATEST_REFERENCE_UUID),
        lineage,
        "mutation",
    )
    .await;

    insert_revision(
        &transaction,
        MEMBERSHIP,
        1,
        None,
        "active",
        json!({
            "household-code": "B",
            "jurisdiction": "zone-a",
            "valid-from": "2026-06-01",
            "valid-to": null
        }),
        1,
    )
    .await;
    insert_revision(
        &transaction,
        TOMBSTONED,
        1,
        None,
        "active",
        json!({
            "household-code": "TOMBSTONE-MATCH",
            "jurisdiction": "zone-a",
            "valid-from": "2026-01-01",
            "valid-to": null
        }),
        1,
    )
    .await;
    insert_revision(
        &transaction,
        OTHER_JURISDICTION,
        1,
        None,
        "active",
        json!({
            "household-code": "OTHER",
            "jurisdiction": "zone-b",
            "valid-from": "2026-01-01",
            "valid-to": null
        }),
        1,
    )
    .await;
    insert_revision(
        &transaction,
        AUTHORITY_CHANGED,
        1,
        None,
        "active",
        json!({
            "household-code": "AUTHORITY",
            "jurisdiction": "zone-a",
            "valid-from": "2026-01-01",
            "valid-to": null
        }),
        1,
    )
    .await;

    insert_revision(
        &transaction,
        MEMBERSHIP,
        2,
        Some(1),
        "active",
        json!({
            "household-code": "OBSOLETE",
            "jurisdiction": "zone-a",
            "valid-from": "2026-01-01",
            "valid-to": null
        }),
        2,
    )
    .await;
    insert_revision(
        &transaction,
        MEMBERSHIP,
        3,
        Some(2),
        "active",
        json!({
            "household-code": "A",
            "jurisdiction": "zone-a",
            "valid-from": "2026-01-01",
            "valid-to": "2026-06-15"
        }),
        2,
    )
    .await;
    insert_revision(
        &transaction,
        TOMBSTONED,
        2,
        Some(1),
        "tombstoned",
        json!({
            "household-code": "TOMBSTONE-MATCH",
            "jurisdiction": "zone-a",
            "valid-from": "2026-01-01",
            "valid-to": null
        }),
        2,
    )
    .await;
    insert_revision(
        &transaction,
        LATER_VISIBLE,
        1,
        None,
        "active",
        json!({
            "household-code": "C",
            "jurisdiction": "zone-a",
            "valid-from": "2026-01-01",
            "valid-to": null
        }),
        2,
    )
    .await;
    insert_revision(
        &transaction,
        AUTHORITY_CHANGED,
        2,
        Some(1),
        "active",
        json!({
            "household-code": "AUTHORITY",
            "jurisdiction": "zone-b",
            "valid-from": "2026-01-01",
            "valid-to": null
        }),
        2,
    )
    .await;

    transaction
        .commit()
        .await
        .expect("history seed transaction commits");
}

async fn seed_timestamp_history(migration: &mut Client) {
    let transaction = migration
        .transaction()
        .await
        .expect("migration begins timestamp history seed transaction");
    let lineage = uuid(LINEAGE_UUID);
    insert_commit_head(&transaction, lineage, 1).await;
    insert_commit(
        &transaction,
        0,
        uuid("30000000-0000-4000-8000-000000000010"),
        uuid("40000000-0000-4000-8000-000000000010"),
        lineage,
        "baseline",
    )
    .await;
    insert_commit(
        &transaction,
        1,
        uuid("30000000-0000-4000-8000-000000000011"),
        uuid(OLD_REFERENCE_UUID),
        lineage,
        "mutation",
    )
    .await;
    insert_revision(
        &transaction,
        MEMBERSHIP,
        1,
        None,
        "active",
        json!({
            "household-code": "TIMESTAMP",
            "jurisdiction": "zone-a",
            "valid-from": "2026-06-05T00:00:00Z",
            "valid-to": "2026-06-05T12:00:00Z"
        }),
        1,
    )
    .await;
    transaction
        .commit()
        .await
        .expect("timestamp history seed transaction commits");
}

async fn append_later_visible_commit(migration: &mut Client) {
    let transaction = migration
        .transaction()
        .await
        .expect("migration begins later commit transaction");
    let lineage = uuid(LINEAGE_UUID);
    insert_commit(
        &transaction,
        3,
        uuid("30000000-0000-4000-8000-000000000003"),
        uuid(LATER_REFERENCE_UUID),
        lineage,
        "mutation",
    )
    .await;
    insert_revision(
        &transaction,
        LATER_COMMIT,
        1,
        None,
        "active",
        json!({
            "household-code": "D",
            "jurisdiction": "zone-a",
            "valid-from": "2026-01-01",
            "valid-to": null
        }),
        3,
    )
    .await;
    transaction
        .execute(
            "UPDATE registry_internal.registry_commit_head
                SET latest_position = 3, updated_at = transaction_timestamp()
              WHERE singleton",
            &[],
        )
        .await
        .expect("head advances to later commit");
    transaction
        .commit()
        .await
        .expect("later commit transaction commits");
}

async fn seed_bulk_history(migration: &mut Client, records: usize) {
    let transaction = migration
        .transaction()
        .await
        .expect("migration begins bulk history seed transaction");
    let lineage = uuid(LINEAGE_UUID);
    insert_commit(
        &transaction,
        3,
        uuid("30000000-0000-4000-8000-000000000004"),
        uuid(BULK_FIRST_REFERENCE_UUID),
        lineage,
        "mutation",
    )
    .await;
    insert_commit(
        &transaction,
        4,
        uuid("30000000-0000-4000-8000-000000000005"),
        uuid(BULK_SECOND_REFERENCE_UUID),
        lineage,
        "mutation",
    )
    .await;
    for index in 0..records {
        let record_id = bulk_record_id(index);
        insert_revision(
            &transaction,
            &record_id,
            1,
            None,
            "active",
            json!({
                "household-code": "probe-old",
                "jurisdiction": "zone-a",
                "valid-from": "2026-01-01",
                "valid-to": null
            }),
            3,
        )
        .await;
        let household_code = if index % 2 == 0 {
            "probe-even"
        } else {
            "probe-odd"
        };
        insert_revision(
            &transaction,
            &record_id,
            2,
            Some(1),
            "active",
            json!({
                "household-code": household_code,
                "jurisdiction": "zone-a",
                "valid-from": "2026-01-01",
                "valid-to": null
            }),
            4,
        )
        .await;
    }
    transaction
        .execute(
            "UPDATE registry_internal.registry_commit_head
                SET latest_position = 4, updated_at = transaction_timestamp()
              WHERE singleton",
            &[],
        )
        .await
        .expect("head advances to bulk second commit");
    transaction
        .commit()
        .await
        .expect("bulk history seed transaction commits");
}

async fn append_bulk_later_match_commit(migration: &mut Client) {
    let transaction = migration
        .transaction()
        .await
        .expect("migration begins later bulk commit transaction");
    let lineage = uuid(LINEAGE_UUID);
    insert_commit(
        &transaction,
        5,
        uuid("30000000-0000-4000-8000-000000000006"),
        uuid(BULK_LATER_REFERENCE_UUID),
        lineage,
        "mutation",
    )
    .await;
    insert_revision(
        &transaction,
        &bulk_record_id(2_000),
        1,
        None,
        "active",
        json!({
            "household-code": "probe-even",
            "jurisdiction": "zone-a",
            "valid-from": "2026-01-01",
            "valid-to": null
        }),
        5,
    )
    .await;
    transaction
        .execute(
            "UPDATE registry_internal.registry_commit_head
                SET latest_position = 5, updated_at = transaction_timestamp()
              WHERE singleton",
            &[],
        )
        .await
        .expect("head advances to later bulk commit");
    transaction
        .commit()
        .await
        .expect("later bulk commit transaction commits");
}

async fn insert_commit_head(transaction: &Transaction<'_>, lineage: Uuid, latest: i64) {
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_commit_head
                 (singleton, history_lineage, latest_position,
                  coverage_baseline_position, coverage_ready)
             VALUES (true, $1, $2, 0, true)",
            &[&lineage, &latest],
        )
        .await
        .expect("commit head inserts");
}

async fn insert_commit(
    transaction: &Transaction<'_>,
    position: i64,
    change_id: Uuid,
    reference: Uuid,
    lineage: Uuid,
    kind: &str,
) {
    let (system_origin, establishes_baseline, actor_reference, request_reference) = match kind {
        "baseline" => (
            Some("history-test-baseline"),
            true,
            None::<&str>,
            None::<&str>,
        ),
        "mutation" => (None, false, Some(HMAC_REF), Some(HMAC_REF)),
        _ => panic!("unsupported commit kind"),
    };
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_revision_commits
                 (commit_position, change_id, snapshot_reference, history_lineage,
                  originating_package_revision, origin_kind, actor_reference,
                  request_reference, system_origin, establishes_baseline)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            &[
                &position,
                &change_id,
                &reference,
                &lineage,
                &PACKAGE_REVISION,
                &kind,
                &actor_reference,
                &request_reference,
                &system_origin,
                &establishes_baseline,
            ],
        )
        .await
        .expect("commit inserts");
}

async fn insert_revision(
    transaction: &Transaction<'_>,
    record_id: &str,
    revision: i64,
    predecessor: Option<i64>,
    lifecycle: &str,
    snapshot: Value,
    commit_position: i64,
) {
    let record_id = uuid(record_id);
    let snapshot = canonicalize_json(&snapshot).expect("fixture snapshot canonicalizes");
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_revisions
                 (entity_id, record_id, record_reference, record_revision,
                  predecessor_revision, record_lifecycle, package_revision,
                  operation_id, mutation_kind, principal_reference,
                  request_reference, snapshot)
             VALUES ('membership', $1, $2, $3, $4, $5, $6,
                     'records.membership.patch', 'patch', $7, $8, $9)",
            &[
                &record_id,
                &HMAC_REF,
                &revision,
                &predecessor,
                &lifecycle,
                &PACKAGE_REVISION,
                &HMAC_REF,
                &HMAC_REF,
                &snapshot,
            ],
        )
        .await
        .expect("revision inserts");
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_revision_commit_members
                 (entity_id, record_id, record_revision, commit_position, member_index)
             VALUES ('membership', $1, $2, $3,
                     (SELECT count(*)::integer
                        FROM registry_internal.registry_revision_commit_members
                       WHERE commit_position = $3))",
            &[&record_id, &revision, &commit_position],
        )
        .await
        .expect("commit member inserts");
}

async fn send(
    app: &axum::Router,
    uri: &str,
    claims: Option<VerifiedRequestClaims>,
) -> Response<Body> {
    let mut request = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .expect("request builds");
    if let Some(claims) = claims {
        request.extensions_mut().insert(claims);
    }
    let mut app = app.clone();
    app.call(request).await.expect("router returns a response")
}

async fn body_json(response: Response<Body>) -> Value {
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body is bounded");
    serde_json::from_slice(&bytes).expect("response is JSON")
}

fn history_claims<const N: usize>(jurisdictions: [&str; N]) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        PRINCIPAL_CANARY,
        BTreeSet::from(["registry.read".to_owned()]),
        Some("case-management".to_owned()),
        BTreeMap::from([(
            "jurisdictions".to_owned(),
            VerifiedClaimValue::direct_string_set(jurisdictions)
                .expect("jurisdictions are verified strings"),
        )]),
    )
    .expect("history claims are verified")
}

fn item_ids(body: &Value) -> Vec<&str> {
    body["items"]
        .as_array()
        .expect("items are an array")
        .iter()
        .map(|item| item["id"].as_str().expect("item id is a string"))
        .collect()
}

fn snapshot_ref(uuid: &str) -> String {
    format!("rs1_{uuid}")
}

fn uuid(value: &str) -> Uuid {
    Uuid::parse_str(value).expect("fixture UUID is valid")
}

fn bulk_record_id(index: usize) -> String {
    format!("00000000-0000-4000-9000-{index:012x}")
}

struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}
