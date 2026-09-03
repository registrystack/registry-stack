// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, Response, StatusCode};
use postgres_harness::TestDatabase;
use registry_breg::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedClaimValue,
    VerifiedRequestClaims,
};
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::cursor::CursorCodec;
use registry_breg::postgres::{
    begin_record_transaction, initialize_registry_state_for_catalog_test, install_compiled_schema,
    ClaimContext, ExpectedManagedCatalog, PostgresRecordReadService, ReadFaultPoint,
    RegistryLockKey, RegistryStateTestIdentity, RowBoundaryContext,
};
use registry_platform_audit::{verify_jsonl_lines_with_hasher, AuditEnvelope, AuditProfile};
use serde_json::{json, Value};
use tokio_postgres::Transaction;
use tower::Service as _;
use zeroize::Zeroizing;

const PRINCIPAL_CANARY: &str = "principal-value-must-not-enter-read-audit";
const SECRET_CANARY: &str = "SECRET-CANARY-MUST-NOT-LEAVE-PROJECTION";
const PACKAGE_ID: &str = "read-registry";
const INSTANCE_ID: &str = "read-instance";
const DATABASE_ID: &str = "read-database";
const VISIBLE_RECORD: &str = "00000000-0000-4000-8000-000000000001";
const ALPHA_RECORD: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa0001";
const WILDCARD_RECORD: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbb0001";
const SORT_DUP_A_RECORD: &str = "cccccccc-cccc-4ccc-8ccc-cccccccc0001";
const SORT_DUP_B_RECORD: &str = "cccccccc-cccc-4ccc-8ccc-cccccccc0002";
const SORT_NEXT_RECORD: &str = "cccccccc-cccc-4ccc-8ccc-cccccccc0003";
const SORT_NULL_A_RECORD: &str = "cccccccc-cccc-4ccc-8ccc-cccccccc0004";
const SORT_NULL_B_RECORD: &str = "cccccccc-cccc-4ccc-8ccc-cccccccc0005";
const TEMPORAL_OLD_RECORD: &str = "11111111-1111-4111-8111-111111111111";
const TEMPORAL_OPEN_RECORD: &str = "22222222-2222-4222-8222-222222222222";
const TEMPORAL_OTHER_BOUNDARY_RECORD: &str = "33333333-3333-4333-8333-333333333333";
const MISMATCH_RECORD: &str = "ffffffff-ffff-4fff-8fff-ffffffffffff";
const TOMBSTONED_RECORD: &str = "00000000-0000-4000-8000-999999999999";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_read_is_authorized_bounded_minimized_and_audit_gated() {
    let database = TestDatabase::create(8).await;
    database
        .admin
        .execute("CREATE EXTENSION IF NOT EXISTS btree_gist", &[])
        .await
        .expect("administrator installs btree_gist for temporal exclusion constraints");
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("migration installs the complete compiled PostgreSQL schema");
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
            package_revision: "package-read-1",
            package_sequence: 1,
        },
    )
    .await
    .expect("migration initializes durable Registry identity");
    migration_task.abort();

    let pool = database
        .runtime_config
        .build_pool()
        .expect("bounded runtime pool builds");
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock identity is bounded");
    seed_records(&database, &pool, lock_key, &identity, &compiled, false).await;

    let profile = AuditProfile::production_from_secret_bytes(vec![0x7a; 32].into())
        .expect("test owns a strongly keyed audit profile");
    let app = read_router(
        pool.clone(),
        compiled.clone(),
        identity.clone(),
        lock_key,
        profile.clone(),
        None,
    );

    let get = send(
        &app,
        &format!("/v1/records/widgets/{VISIBLE_RECORD}?$select=label"),
        Some(read_claims(["zone-a"])),
    )
    .await;
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(get.headers()["content-type"], "application/json");
    assert_eq!(get.headers()["cache-control"], "no-store");
    assert_eq!(
        get.headers()["link"],
        "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </v1/schemas/widget>; rel=\"describedby\""
    );
    let ordinary_etag = get.headers()["etag"].clone();
    let get_bytes = body_bytes(get).await;
    assert_eq!(
        get_bytes,
        format!(
            "{{\"data\":{{\"domainData\":{{\"label\":\"label-001\"}},\"recordIdentifier\":\"{VISIBLE_RECORD}\",\"revisionIdentifier\":\"1\"}},\"meta\":{{\"datasetIdentifier\":\"test-dataset\",\"entityTypeIdentifier\":\"widget\",\"registryIdentifier\":\"read-registry\"}}}}"
        )
        .as_bytes()
    );
    let body = json_from_bytes(&get_bytes);
    assert_eq!(body["data"]["recordIdentifier"], VISIBLE_RECORD);
    assert_eq!(body["data"]["revisionIdentifier"], "1");
    assert_eq!(body["data"]["domainData"], json!({"label": "label-001"}));
    assert_eq!(body["meta"]["registryIdentifier"], "read-registry");
    assert_eq!(body["meta"]["datasetIdentifier"], "test-dataset");
    assert_eq!(body["meta"]["entityTypeIdentifier"], "widget");
    assert!(body.get("@context").is_none());
    assert!(body.get("@id").is_none());
    assert!(body.get("@type").is_none());
    assert!(!body.to_string().contains(SECRET_CANARY));

    let json_ld = send_representation(
        &app,
        &format!("/v1/records/widgets/{VISIBLE_RECORD}?$select=label"),
        Some(read_claims(["zone-a"])),
        "application/ld+json",
        "attacker.example.invalid",
    )
    .await;
    assert_eq!(json_ld.status(), StatusCode::OK);
    assert_eq!(json_ld.headers()["content-type"], "application/ld+json");
    assert_eq!(
        json_ld.headers()["link"],
        "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </v1/schemas/widget>; rel=\"describedby\""
    );
    assert_ne!(json_ld.headers()["etag"], ordinary_etag);
    assert!(!format!("{:?}", json_ld.headers()).contains("attacker.example.invalid"));
    let json_ld = body_json(json_ld).await;
    assert_eq!(
        json_ld["@context"],
        "https://id.registrystack.org/contexts/registry-record/v1"
    );
    assert_eq!(json_ld["data"]["recordIdentifier"], VISIBLE_RECORD);
    assert_eq!(json_ld["data"]["revisionIdentifier"], "1");
    assert_eq!(json_ld["data"]["domainData"], json!({"label": "label-001"}));
    assert_eq!(json_ld["meta"]["registryIdentifier"], "read-registry");
    assert_eq!(json_ld["meta"]["datasetIdentifier"], "test-dataset");
    assert_eq!(json_ld["meta"]["entityTypeIdentifier"], "widget");
    assert!(json_ld.get("@id").is_none());
    assert!(json_ld.get("@type").is_none());

    let lookup = send_lookup(
        &app,
        "/v1/records/widgets:lookup?$select=label",
        Some(read_claims(["zone-a"])),
        json!({"selector": "by-amount", "values": {"amount": "1.20"}}),
    )
    .await;
    assert_eq!(lookup.status(), StatusCode::OK);
    let lookup = body_json(lookup).await;
    assert_eq!(lookup["data"]["recordIdentifier"], VISIBLE_RECORD);
    assert_eq!(lookup["data"]["revisionIdentifier"], "1");
    assert_eq!(lookup["data"]["domainData"], json!({"label": "label-001"}));
    for amount in ["99.99", "2.00"] {
        let unresolved = send_lookup(
            &app,
            "/v1/records/widgets:lookup?$select=label",
            Some(read_claims(["zone-a"])),
            json!({"selector": "by-amount", "values": {"amount": amount}}),
        )
        .await;
        assert_eq!(unresolved.status(), StatusCode::NOT_FOUND);
        assert!(unresolved.headers().get("link").is_none());
        let unresolved = body_json(unresolved).await;
        assert_eq!(unresolved["code"], "lookup.unresolved");
        assert!(!unresolved.to_string().contains(amount));
        assert!(!unresolved.to_string().contains("amount"));
    }

    let governed_names = send(
        &app,
        "/v1/records/widgets/00000000-0000-4000-8000-000000000001?accessProfile=auditor",
        Some(read_claims(["zone-a"])),
    )
    .await;
    assert_eq!(governed_names.status(), StatusCode::OK);
    let governed_names = body_json(governed_names).await;
    assert_eq!(
        governed_names["data"]["domainData"]["publicCode"],
        Value::Null
    );
    assert_eq!(governed_names["data"]["domainData"]["label"], "label-001");
    assert_eq!(
        governed_names["data"]["domainData"]["jurisdiction"],
        "zone-a"
    );
    assert!(governed_names["data"]["domainData"]
        .get("internal-code")
        .is_none());

    let decimal = send(
        &app,
        &format!("/v1/records/widgets/{VISIBLE_RECORD}?$select=amount"),
        Some(read_claims(["zone-a"])),
    )
    .await;
    assert_eq!(decimal.status(), StatusCode::OK);
    let decimal_bytes = body_bytes(decimal).await;
    assert_eq!(
        decimal_bytes,
        format!(
            "{{\"data\":{{\"domainData\":{{\"amount\":\"1.20\"}},\"recordIdentifier\":\"{VISIBLE_RECORD}\",\"revisionIdentifier\":\"1\"}},\"meta\":{{\"datasetIdentifier\":\"test-dataset\",\"entityTypeIdentifier\":\"widget\",\"registryIdentifier\":\"read-registry\"}}}}"
        )
        .as_bytes(),
        "fixed-scale decimals are returned as exact strings, not JSON numbers"
    );
    assert_eq!(
        json_from_bytes(&decimal_bytes)["data"]["domainData"]["amount"],
        "1.20"
    );

    let list = send(
        &app,
        "/v1/records/widgets?$select=label",
        Some(read_claims(["zone-a"])),
    )
    .await;
    assert_eq!(list.status(), StatusCode::OK);
    assert_eq!(list.headers()["cache-control"], "no-store");
    let body = body_json(list).await;
    let items = body["items"].as_array().expect("list returns items");
    assert_eq!(
        items.len(),
        100,
        "the SQL limit is applied before materializing"
    );
    for window in items.windows(2) {
        assert!(
            window[0]["recordIdentifier"].as_str() <= window[1]["recordIdentifier"].as_str(),
            "list ordering is deterministic by record id"
        );
    }
    assert_eq!(
        items[0]["recordIdentifier"],
        "00000000-0000-4000-8000-000000000000"
    );
    assert_eq!(
        items[99]["recordIdentifier"],
        "00000000-0000-4000-8000-000000000099"
    );
    let next_cursor = body["pageInfo"]["nextCursor"]
        .as_str()
        .expect("overfetch produces a cursor")
        .to_owned();
    assert!(!body.to_string().contains(SECRET_CANARY));

    let repeated_in = send(
        &app,
        "/v1/records/widgets?$select=label&$filter=jurisdiction%20in%20('zone-b','zone-a')&$top=2",
        Some(read_claims(["zone-a"])),
    )
    .await;
    assert_eq!(repeated_in.status(), StatusCode::OK);
    let repeated_in = body_json(repeated_in).await;
    let repeated_items = repeated_in["items"]
        .as_array()
        .expect("repeated in returns items");
    assert_eq!(
        repeated_items.len(),
        2,
        "repeated in values are one finite set, not an impossible conjunction"
    );
    assert_eq!(
        repeated_items[0]["recordIdentifier"],
        "00000000-0000-4000-8000-000000000000"
    );
    assert_eq!(repeated_items[1]["recordIdentifier"], VISIBLE_RECORD);
    assert!(!repeated_in.to_string().contains("zone-b-label"));

    let prefix = send(
        &app,
        "/v1/records/widgets?$select=label&$filter=startswith(label,'literal%25_%5C')",
        Some(read_claims(["zone-a"])),
    )
    .await;
    assert_eq!(prefix.status(), StatusCode::OK);
    let prefix = body_json(prefix).await;
    let prefix_items = prefix["items"].as_array().expect("prefix returns items");
    assert_eq!(prefix_items.len(), 1);
    assert_eq!(prefix_items[0]["recordIdentifier"], WILDCARD_RECORD);
    assert_eq!(prefix_items[0]["domainData"]["label"], "literal%_\\value");

    let continuation = send(
        &app,
        &format!("/v1/records/widgets?$skiptoken={next_cursor}"),
        Some(read_claims(["zone-a"])),
    )
    .await;
    assert_eq!(continuation.status(), StatusCode::OK);
    let continuation = body_json(continuation).await;
    let continuation_items = continuation["items"]
        .as_array()
        .expect("cursor returns items");
    assert_eq!(continuation_items.len(), 3);
    assert_eq!(
        continuation_items
            .iter()
            .map(|item| item["recordIdentifier"].as_str().expect("record id"))
            .collect::<Vec<_>>(),
        vec![
            "00000000-0000-4000-8000-000000000100",
            ALPHA_RECORD,
            WILDCARD_RECORD
        ]
    );

    let mut tampered = next_cursor.into_bytes();
    let last = tampered.len() - 1;
    tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(tampered).expect("cursor remains UTF-8");
    let refused_cursor = send(
        &app,
        &format!("/v1/records/widgets?$skiptoken={tampered}"),
        Some(read_claims(["zone-a"])),
    )
    .await;
    assert_eq!(refused_cursor.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(refused_cursor).await["code"],
        "query.cursor_invalid"
    );

    let concealed = send(
        &app,
        &format!("/v1/records/widgets/{MISMATCH_RECORD}?$select=label"),
        Some(read_claims(["zone-a"])),
    )
    .await;
    assert_eq!(concealed.status(), StatusCode::NOT_FOUND);
    let concealed_body = body_json(concealed).await;
    assert_eq!(concealed_body["code"], "resource.not_found");
    assert!(!concealed_body.to_string().contains("zone-b"));
    assert!(!concealed_body.to_string().contains(SECRET_CANARY));

    let tombstoned = send(
        &app,
        &format!("/v1/records/widgets/{TOMBSTONED_RECORD}?$select=label"),
        Some(read_claims(["zone-a"])),
    )
    .await;
    assert_eq!(tombstoned.status(), StatusCode::NOT_FOUND);
    assert!(!body_json(tombstoned)
        .await
        .to_string()
        .contains("tombstoned-label"));

    let uppercase = send(
        &app,
        &format!(
            "/v1/records/widgets/{}?$select=label",
            ALPHA_RECORD.to_ascii_uppercase()
        ),
        Some(read_claims(["zone-a"])),
    )
    .await;
    assert_eq!(uppercase.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_json(uppercase).await["code"], "resource.not_found");

    let before_fault = audit_count(&database).await;
    let faulting_app = read_router(
        pool,
        compiled.clone(),
        identity,
        lock_key,
        profile.clone(),
        Some(ReadFaultPoint::BeforeTerminalAudit),
    );
    let faulted = send(
        &faulting_app,
        &format!("/v1/records/widgets/{VISIBLE_RECORD}?$select=label"),
        Some(read_claims(["zone-a"])),
    )
    .await;
    assert_eq!(faulted.status(), StatusCode::SERVICE_UNAVAILABLE);
    let faulted_body = body_json(faulted).await;
    assert_eq!(faulted_body["code"], "source.unavailable");
    assert!(!faulted_body.to_string().contains("label-001"));
    assert_eq!(
        audit_count(&database).await,
        before_fault + 1,
        "a terminal audit fault releases no protected data and commits only the prior attempt"
    );

    assert_read_audit_is_ordered_chained_and_minimized(&database, &profile, &compiled).await;
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_temporal_keyset_and_cursor_binding_edges_are_enforced() {
    let database = TestDatabase::create(8).await;
    database
        .admin
        .execute("CREATE EXTENSION IF NOT EXISTS btree_gist", &[])
        .await
        .expect("administrator installs btree_gist for temporal exclusion constraints");
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("migration installs the complete compiled PostgreSQL schema");
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
            package_revision: "package-read-1",
            package_sequence: 1,
        },
    )
    .await
    .expect("migration initializes durable Registry identity");
    migration_task.abort();

    let pool = database
        .runtime_config
        .build_pool()
        .expect("bounded runtime pool builds");
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock identity is bounded");
    seed_records(&database, &pool, lock_key, &identity, &compiled, true).await;

    let profile = AuditProfile::production_from_secret_bytes(vec![0x6b; 32].into())
        .expect("test owns a strongly keyed audit profile");
    let app = read_router(
        pool.clone(),
        compiled.clone(),
        identity.clone(),
        lock_key,
        profile.clone(),
        None,
    );

    assert_ids(
        body_json(
            send(
                &app,
                "/v1/records/assignments:as-of?$select=label&asOf=2020-05-31T23:59:59Z",
                Some(read_claims(["zone-a"])),
            )
            .await,
        )
        .await,
        &[TEMPORAL_OLD_RECORD],
    );
    assert_ids(
        body_json(
            send(
                &app,
                "/v1/records/assignments:as-of?$select=label&asOf=2020-06-01T00:00:00Z",
                Some(read_claims(["zone-a"])),
            )
            .await,
        )
        .await,
        &[TEMPORAL_OPEN_RECORD],
    );
    let current = send(
        &app,
        "/v1/records/assignments:current",
        Some(read_claims(["zone-a"])),
    )
    .await;
    assert_eq!(current.status(), StatusCode::OK);
    let current = body_json(current).await;
    assert_ids(current.clone(), &[TEMPORAL_OPEN_RECORD]);
    assert_eq!(current["items"][0]["domainData"]["label"], "lease-a");
    assert!(current["items"][0]["domainData"]["validFrom"].is_string());
    assert_eq!(current["items"][0]["domainData"]["validTo"], Value::Null);
    assert!(current["items"][0]["domainData"]
        .get("valid-from")
        .is_none());
    assert!(current["items"][0]["domainData"].get("valid-to").is_none());
    assert!(!current.to_string().contains(TEMPORAL_OTHER_BOUNDARY_RECORD));

    let sorted_first = send(
        &app,
        "/v1/records/widgets?$select=label,rank&$filter=startswith(label,'sort-key-')&$orderby=rank&$top=2",
        Some(read_claims(["zone-a"])),
    )
    .await;
    assert_eq!(sorted_first.status(), StatusCode::OK);
    let sorted_first = body_json(sorted_first).await;
    assert_ids(
        sorted_first.clone(),
        &[SORT_DUP_A_RECORD, SORT_DUP_B_RECORD],
    );
    let sorted_second_cursor = sorted_first["pageInfo"]["nextCursor"]
        .as_str()
        .expect("duplicate sort page overfetches")
        .to_owned();
    let sorted_second = send(
        &app,
        &format!("/v1/records/widgets?$skiptoken={sorted_second_cursor}"),
        Some(read_claims(["zone-a"])),
    )
    .await;
    assert_eq!(sorted_second.status(), StatusCode::OK);
    let sorted_second = body_json(sorted_second).await;
    assert_ids(
        sorted_second.clone(),
        &[SORT_NEXT_RECORD, SORT_NULL_A_RECORD],
    );
    assert_eq!(sorted_second["items"][1]["domainData"]["rank"], Value::Null);
    let sorted_third_cursor = sorted_second["pageInfo"]["nextCursor"]
        .as_str()
        .expect("null sort page overfetches")
        .to_owned();
    let sorted_third = send(
        &app,
        &format!("/v1/records/widgets?$skiptoken={sorted_third_cursor}"),
        Some(read_claims(["zone-a"])),
    )
    .await;
    assert_eq!(sorted_third.status(), StatusCode::OK);
    let sorted_third = body_json(sorted_third).await;
    assert_ids(sorted_third.clone(), &[SORT_NULL_B_RECORD]);
    assert!(sorted_third["pageInfo"]["nextCursor"].is_null());

    let counted_first = send(
        &app,
        "/v1/records/widgets?$select=label,rank&$filter=startswith(label,'sort-key-')&$orderby=rank&$top=2&$count=true",
        Some(read_claims(["zone-a"])),
    )
    .await;
    assert_eq!(counted_first.status(), StatusCode::OK);
    let counted_first = body_json(counted_first).await;
    assert_eq!(
        counted_first["count"], 5,
        "the first page counts the whole authorized result"
    );
    let counted_cursor = counted_first["pageInfo"]["nextCursor"]
        .as_str()
        .expect("counted page overfetches")
        .to_owned();
    let counted_second = send(
        &app,
        &format!("/v1/records/widgets?$skiptoken={counted_cursor}"),
        Some(read_claims(["zone-a"])),
    )
    .await;
    assert_eq!(counted_second.status(), StatusCode::OK);
    let counted_second = body_json(counted_second).await;
    assert_eq!(
        counted_second["count"], 5,
        "a continuation counts the same result, not only the rows after its boundary"
    );

    let replay_cursor = next_cursor(
        &app,
        "/v1/records/widgets?$select=label,rank&$filter=startswith(label,'sort-key-')&$orderby=rank&$top=2",
        Some(read_claims(["zone-a"])),
    )
    .await;
    for (uri, claims) in [
        (
            format!("/v1/records/widgets?$skiptoken={replay_cursor}"),
            read_claims_with(PRINCIPAL_CANARY, "audit-review", ["zone-a"]),
        ),
        (
            format!("/v1/records/widgets?$skiptoken={replay_cursor}"),
            read_claims_with("other-principal-value", "case-management", ["zone-a"]),
        ),
        (
            format!("/v1/records/widgets?$skiptoken={replay_cursor}"),
            read_claims_with(PRINCIPAL_CANARY, "case-management", ["zone-b"]),
        ),
        (
            format!("/v1/records/widgets?accessProfile=auditor&$skiptoken={replay_cursor}"),
            read_claims(["zone-a"]),
        ),
        (
            format!("/v1/records/assignments?$skiptoken={replay_cursor}"),
            read_claims(["zone-a"]),
        ),
    ] {
        assert_cursor_invalid(&app, &uri, Some(claims)).await;
    }

    let package_changed_app = read_router_with_cursor_codec(
        pool.clone(),
        compiled.clone(),
        identity.clone(),
        lock_key,
        profile.clone(),
        None,
        cursor_codec(),
        Some(ReadRuntimeIdentity {
            package_revision: "package-read-2".to_owned(),
            schema_fingerprint: identity.schema_fingerprint.clone(),
        }),
    );
    assert_cursor_invalid(
        &package_changed_app,
        &format!("/v1/records/widgets?$skiptoken={replay_cursor}"),
        Some(read_claims(["zone-a"])),
    )
    .await;

    let projection_cursor = next_cursor(
        &app,
        "/v1/records/widgets?$select=label,amount&$filter=startswith(label,'label-')&$orderby=ordinal&$top=2",
        Some(read_claims(["zone-a"])),
    )
    .await;
    let projection_changed_app = read_router_with_cursor_codec(
        pool.clone(),
        Arc::new(compiled_registry_without_amount_projection()),
        identity.clone(),
        lock_key,
        profile.clone(),
        None,
        cursor_codec(),
        None,
    );
    assert_cursor_invalid(
        &projection_changed_app,
        &format!("/v1/records/widgets?$skiptoken={projection_cursor}"),
        Some(read_claims(["zone-a"])),
    )
    .await;

    for changed_registry in [
        compiled_registry_without_label_filter(),
        compiled_registry_without_rank_sort(),
    ] {
        let changed_app = read_router_with_cursor_codec(
            pool.clone(),
            Arc::new(changed_registry),
            identity.clone(),
            lock_key,
            profile.clone(),
            None,
            cursor_codec(),
            None,
        );
        assert_cursor_invalid(
            &changed_app,
            &format!("/v1/records/widgets?$skiptoken={replay_cursor}"),
            Some(read_claims(["zone-a"])),
        )
        .await;
    }

    let expiring_app = read_router_with_cursor_codec(
        pool,
        compiled,
        identity,
        lock_key,
        profile,
        None,
        immediately_expiring_cursor_codec(),
        None,
    );
    let expired_cursor = next_cursor(
        &expiring_app,
        "/v1/records/widgets?$select=label&$orderby=ordinal&$top=1",
        Some(read_claims(["zone-a"])),
    )
    .await;
    assert_cursor_invalid(
        &expiring_app,
        &format!("/v1/records/widgets?$skiptoken={expired_cursor}"),
        Some(read_claims(["zone-a"])),
    )
    .await;

    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_reads_do_not_depend_on_the_database_time_zone() {
    let database = TestDatabase::create(4).await;
    database
        .admin
        .execute("CREATE EXTENSION IF NOT EXISTS btree_gist", &[])
        .await
        .expect("administrator installs btree_gist for temporal exclusion constraints");
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("migration installs the complete compiled PostgreSQL schema");
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
            package_revision: "package-read-1",
            package_sequence: 1,
        },
    )
    .await
    .expect("migration initializes durable Registry identity");
    let database_name: String = migration
        .query_one("SELECT current_database()", &[])
        .await
        .expect("migration reads its own database name")
        .get(0);
    migration_task.abort();
    database
        .admin
        .execute(
            &format!(
                "ALTER DATABASE {} SET timezone = 'Pacific/Kiritimati'",
                quote_identifier(&database_name)
            ),
            &[],
        )
        .await
        .expect("administrator moves the database default off UTC");

    let pool = database
        .runtime_config
        .build_pool()
        .expect("bounded runtime pool builds");
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock identity is bounded");
    seed_records(&database, &pool, lock_key, &identity, &compiled, true).await;
    let profile = AuditProfile::production_from_secret_bytes(vec![0x6d; 32].into())
        .expect("test owns a strongly keyed audit profile");
    let app = read_router(pool, compiled.clone(), identity, lock_key, profile, None);

    let current = send(
        &app,
        "/v1/records/assignments:current",
        Some(read_claims(["zone-a"])),
    )
    .await;
    assert_eq!(current.status(), StatusCode::OK);
    let current = body_json(current).await;
    assert_ids(current.clone(), &[TEMPORAL_OPEN_RECORD]);
    assert_eq!(
        current["items"][0]["domainData"]["validFrom"], "2020-06-01T00:00:00+00:00",
        "timestamps render in UTC whatever the database default time zone is"
    );

    let as_of = send(
        &app,
        "/v1/records/assignments:as-of?$select=label&asOf=2020-05-31T23:59:59Z",
        Some(read_claims(["zone-a"])),
    )
    .await;
    assert_eq!(as_of.status(), StatusCode::OK);
    assert_ids(body_json(as_of).await, &[TEMPORAL_OLD_RECORD]);

    database.cleanup().await;
}

fn read_router(
    pool: registry_breg::postgres::RuntimePool,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    profile: AuditProfile,
    fault: Option<ReadFaultPoint>,
) -> axum::Router {
    read_router_with_cursor_codec(
        pool,
        registry,
        identity,
        lock_key,
        profile,
        fault,
        cursor_codec(),
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn read_router_with_cursor_codec(
    pool: registry_breg::postgres::RuntimePool,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    profile: AuditProfile,
    fault: Option<ReadFaultPoint>,
    cursors: Arc<CursorCodec>,
    http_identity: Option<ReadRuntimeIdentity>,
) -> axum::Router {
    let read_identity = http_identity.unwrap_or_else(|| ReadRuntimeIdentity {
        package_revision: identity.package_revision.clone(),
        schema_fingerprint: identity.schema_fingerprint.clone(),
    });
    let records = PostgresRecordReadService::new(
        pool,
        registry.clone(),
        identity,
        lock_key,
        Duration::from_secs(2),
        profile,
        cursors.clone(),
    );
    let records = match fault {
        Some(fault) => records.with_fault_for_test(fault),
        None => records,
    };
    router(Arc::new(HttpService::new(
        registry,
        read_identity,
        Arc::new(records),
        Arc::new(AlwaysReady),
        cursors,
    )))
}

fn cursor_codec() -> Arc<CursorCodec> {
    Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x44; 32]), Duration::from_secs(300))
            .expect("test cursor key is valid"),
    )
}

fn immediately_expiring_cursor_codec() -> Arc<CursorCodec> {
    Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x45; 32]), Duration::from_nanos(1))
            .expect("subsecond max age creates deterministic expired test cursors"),
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

async fn send_representation(
    app: &axum::Router,
    uri: &str,
    claims: Option<VerifiedRequestClaims>,
    accept: &str,
    host: &str,
) -> Response<Body> {
    let mut request = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("accept", accept)
        .header("host", host)
        .header("x-forwarded-host", host)
        .body(Body::empty())
        .expect("request builds");
    if let Some(claims) = claims {
        request.extensions_mut().insert(claims);
    }
    let mut app = app.clone();
    app.call(request).await.expect("router returns a response")
}

async fn send_lookup(
    app: &axum::Router,
    uri: &str,
    claims: Option<VerifiedRequestClaims>,
    body: Value,
) -> Response<Body> {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&body).expect("lookup request serializes"),
        ))
        .expect("request builds");
    if let Some(claims) = claims {
        request.extensions_mut().insert(claims);
    }
    let mut app = app.clone();
    app.call(request).await.expect("router returns a response")
}

async fn body_json(response: Response<Body>) -> Value {
    let bytes = body_bytes(response).await;
    json_from_bytes(&bytes)
}

async fn body_bytes(response: Response<Body>) -> Vec<u8> {
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body is bounded");
    bytes.to_vec()
}

fn json_from_bytes(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("response is JSON")
}

async fn next_cursor(
    app: &axum::Router,
    uri: &str,
    claims: Option<VerifiedRequestClaims>,
) -> String {
    let response = send(app, uri, claims).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    body["pageInfo"]["nextCursor"]
        .as_str()
        .expect("response carries a continuation cursor")
        .to_owned()
}

async fn assert_cursor_invalid(
    app: &axum::Router,
    uri: &str,
    claims: Option<VerifiedRequestClaims>,
) {
    let response = send(app, uri, claims).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_json(response).await;
    assert_eq!(body["code"], "query.cursor_invalid");
    let text = body.to_string();
    for canary in [
        PRINCIPAL_CANARY,
        SECRET_CANARY,
        "other-principal-value",
        "audit-review",
        "zone-a",
        "zone-b",
        "sort-key",
        "package-read-2",
    ] {
        assert!(!text.contains(canary));
    }
}

fn assert_ids(body: Value, expected: &[&str]) {
    let ids = body["items"]
        .as_array()
        .expect("response carries items")
        .iter()
        .map(|item| item["recordIdentifier"].as_str().expect("item id"))
        .collect::<Vec<_>>();
    assert_eq!(ids, expected);
}

async fn seed_records(
    database: &TestDatabase,
    pool: &registry_breg::postgres::RuntimePool,
    lock_key: RegistryLockKey,
    identity: &registry_breg::postgres::ExpectedRegistryIdentity,
    registry: &registry_breg::CompiledRegistry,
    include_edge_rows: bool,
) {
    let mut client = pool
        .get_for_test()
        .await
        .expect("runtime connection is available");
    for jurisdiction in ["zone-a", "zone-b"] {
        let claims = seed_claims(registry, jurisdiction);
        let transaction = begin_record_transaction(
            &mut client,
            lock_key,
            Duration::from_secs(2),
            identity,
            &claims,
        )
        .await
        .expect("seed transaction installs RLS-safe context");
        if jurisdiction == "zone-a" {
            for index in (0..101).rev() {
                insert_seed_row(
                    transaction.transaction_for_test(),
                    registry,
                    SeedRow {
                        record_id: &format!("00000000-0000-4000-8000-{index:012}"),
                        jurisdiction,
                        label: &format!("label-{index:03}"),
                        secret: &format!("{SECRET_CANARY}-{index:03}"),
                        amount: if index == 1 { "1.20" } else { "2.00" },
                        ordinal: index,
                        rank: Some(index),
                    },
                )
                .await;
            }
            insert_seed_row(
                transaction.transaction_for_test(),
                registry,
                SeedRow {
                    record_id: TOMBSTONED_RECORD,
                    jurisdiction,
                    label: "tombstoned-label",
                    secret: &format!("{SECRET_CANARY}-tombstoned"),
                    amount: "3.00",
                    ordinal: 2000,
                    rank: Some(2000),
                },
            )
            .await;
            insert_seed_row(
                transaction.transaction_for_test(),
                registry,
                SeedRow {
                    record_id: ALPHA_RECORD,
                    jurisdiction,
                    label: "alpha-label",
                    secret: &format!("{SECRET_CANARY}-alpha"),
                    amount: "4.00",
                    ordinal: 2001,
                    rank: Some(2001),
                },
            )
            .await;
            insert_seed_row(
                transaction.transaction_for_test(),
                registry,
                SeedRow {
                    record_id: WILDCARD_RECORD,
                    jurisdiction,
                    label: "literal%_\\value",
                    secret: &format!("{SECRET_CANARY}-wildcard"),
                    amount: "6.00",
                    ordinal: 2002,
                    rank: Some(2002),
                },
            )
            .await;
            if include_edge_rows {
                for row in [
                    SeedRow {
                        record_id: SORT_DUP_A_RECORD,
                        jurisdiction,
                        label: "sort-key-duplicate-a",
                        secret: &format!("{SECRET_CANARY}-sort-a"),
                        amount: "7.00",
                        ordinal: 3001,
                        rank: Some(7),
                    },
                    SeedRow {
                        record_id: SORT_DUP_B_RECORD,
                        jurisdiction,
                        label: "sort-key-duplicate-b",
                        secret: &format!("{SECRET_CANARY}-sort-b"),
                        amount: "7.00",
                        ordinal: 3002,
                        rank: Some(7),
                    },
                    SeedRow {
                        record_id: SORT_NEXT_RECORD,
                        jurisdiction,
                        label: "sort-key-next",
                        secret: &format!("{SECRET_CANARY}-sort-next"),
                        amount: "8.00",
                        ordinal: 3003,
                        rank: Some(8),
                    },
                    SeedRow {
                        record_id: SORT_NULL_A_RECORD,
                        jurisdiction,
                        label: "sort-key-null-a",
                        secret: &format!("{SECRET_CANARY}-sort-null-a"),
                        amount: "9.00",
                        ordinal: 3004,
                        rank: None,
                    },
                    SeedRow {
                        record_id: SORT_NULL_B_RECORD,
                        jurisdiction,
                        label: "sort-key-null-b",
                        secret: &format!("{SECRET_CANARY}-sort-null-b"),
                        amount: "9.00",
                        ordinal: 3005,
                        rank: None,
                    },
                ] {
                    insert_seed_row(transaction.transaction_for_test(), registry, row).await;
                }
            }
        } else {
            insert_seed_row(
                transaction.transaction_for_test(),
                registry,
                SeedRow {
                    record_id: MISMATCH_RECORD,
                    jurisdiction,
                    label: "zone-b-label",
                    secret: &format!("{SECRET_CANARY}-zone-b"),
                    amount: "5.00",
                    ordinal: 1000,
                    rank: Some(1000),
                },
            )
            .await;
        }
        transaction
            .commit()
            .await
            .expect("seed transaction commits through the guarded context");
        if include_edge_rows {
            let claims = seed_claims_for(registry, "assignment", jurisdiction);
            let transaction = begin_record_transaction(
                &mut client,
                lock_key,
                Duration::from_secs(2),
                identity,
                &claims,
            )
            .await
            .expect("assignment seed transaction installs RLS-safe context");
            if jurisdiction == "zone-a" {
                for row in [
                    AssignmentRow {
                        record_id: TEMPORAL_OLD_RECORD,
                        jurisdiction,
                        label: "lease-a",
                        valid_from: "2020-01-01T00:00:00Z",
                        valid_to: Some("2020-06-01T00:00:00Z"),
                    },
                    AssignmentRow {
                        record_id: TEMPORAL_OPEN_RECORD,
                        jurisdiction,
                        label: "lease-a",
                        valid_from: "2020-06-01T00:00:00Z",
                        valid_to: None,
                    },
                ] {
                    insert_assignment_row(transaction.transaction_for_test(), registry, row).await;
                }
            }
            transaction
                .commit()
                .await
                .expect("assignment seed transaction commits through the guarded context");
        }
    }
    tombstone_seed_row(database, registry, TOMBSTONED_RECORD).await;
}

async fn insert_seed_row(
    transaction: &Transaction<'_>,
    registry: &registry_breg::CompiledRegistry,
    row: SeedRow<'_>,
) {
    let entity = &registry.entities()["widget"];
    let table = quote_identifier(&entity.physical_table);
    let jurisdiction = quote_identifier(&entity.fields["jurisdiction"].physical_name);
    let label = quote_identifier(&entity.fields["label"].physical_name);
    let secret = quote_identifier(&entity.fields["secret"].physical_name);
    let amount = quote_identifier(&entity.fields["amount"].physical_name);
    let ordinal = quote_identifier(&entity.fields["ordinal"].physical_name);
    let rank = quote_identifier(&entity.fields["rank"].physical_name);
    transaction
        .execute(
            &format!(
                "INSERT INTO registry_data.{table}
                     (record_id, record_revision, record_lifecycle,
                      {jurisdiction}, {label}, {secret}, {amount}, {ordinal}, {rank})
                 VALUES ($1::text::uuid, 1, 'active', $2, $3, $4, $5::text::numeric, $6, $7::bigint)"
            ),
            &[
                &row.record_id,
                &row.jurisdiction,
                &row.label,
                &row.secret,
                &row.amount,
                &row.ordinal,
                &row.rank,
            ],
        )
        .await
        .expect("RLS-safe seed row is accepted");
}

struct SeedRow<'a> {
    record_id: &'a str,
    jurisdiction: &'a str,
    label: &'a str,
    secret: &'a str,
    amount: &'a str,
    ordinal: i64,
    rank: Option<i64>,
}

async fn insert_assignment_row(
    transaction: &Transaction<'_>,
    registry: &registry_breg::CompiledRegistry,
    row: AssignmentRow<'_>,
) {
    let entity = &registry.entities()["assignment"];
    let table = quote_identifier(&entity.physical_table);
    let jurisdiction = quote_identifier(&entity.fields["jurisdiction"].physical_name);
    let label = quote_identifier(&entity.fields["label"].physical_name);
    let valid_from = quote_identifier(&entity.fields["valid-from"].physical_name);
    let valid_to = quote_identifier(&entity.fields["valid-to"].physical_name);
    transaction
        .execute(
            &format!(
                "INSERT INTO registry_data.{table}
                     (record_id, record_revision, record_lifecycle,
                      {jurisdiction}, {label}, {valid_from}, {valid_to})
                 VALUES ($1::text::uuid, 1, 'active', $2, $3, $4::text::timestamptz, $5::text::timestamptz)"
            ),
            &[
                &row.record_id,
                &row.jurisdiction,
                &row.label,
                &row.valid_from,
                &row.valid_to,
            ],
        )
        .await
        .expect("RLS-safe assignment seed row is accepted");
}

struct AssignmentRow<'a> {
    record_id: &'a str,
    jurisdiction: &'a str,
    label: &'a str,
    valid_from: &'a str,
    valid_to: Option<&'a str>,
}

async fn tombstone_seed_row(
    database: &TestDatabase,
    registry: &registry_breg::CompiledRegistry,
    record_id: &str,
) {
    let table = quote_identifier(&registry.entities()["widget"].physical_table);
    database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.{table}
                 SET record_lifecycle = 'tombstoned',
                     record_revision = record_revision + 1
                 WHERE record_id = $1::text::uuid"
            ),
            &[&record_id],
        )
        .await
        .expect("RLS-safe tombstone seed update is accepted");
}

fn seed_claims(registry: &registry_breg::CompiledRegistry, jurisdiction: &str) -> ClaimContext {
    seed_claims_for(registry, "widget", jurisdiction)
}

fn seed_claims_for(
    registry: &registry_breg::CompiledRegistry,
    entity_id: &str,
    jurisdiction: &str,
) -> ClaimContext {
    ClaimContext::for_compiled(
        registry,
        entity_id,
        Some(PRINCIPAL_CANARY.to_owned()),
        "operator",
        Some("case-management".to_owned()),
        vec![RowBoundaryContext::In {
            field: "jurisdiction".to_owned(),
            values: BTreeSet::from([jurisdiction.to_owned()]),
        }],
    )
    .expect("seed claims are compiler-bound")
}

fn read_claims<const N: usize>(jurisdictions: [&str; N]) -> VerifiedRequestClaims {
    read_claims_with(PRINCIPAL_CANARY, "case-management", jurisdictions)
}

fn read_claims_with<const N: usize>(
    principal: &str,
    purpose: &str,
    jurisdictions: [&str; N],
) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        principal,
        BTreeSet::from(["registry.read".to_owned()]),
        Some(purpose.to_owned()),
        BTreeMap::from([(
            "jurisdictions".to_owned(),
            VerifiedClaimValue::direct_string_set(jurisdictions)
                .expect("jurisdictions are direct verified strings"),
        )]),
    )
    .expect("read claims are verified")
}

async fn audit_count(database: &TestDatabase) -> i64 {
    database
        .admin
        .query_one("SELECT count(*) FROM registry_internal.registry_audit", &[])
        .await
        .expect("administrator can inspect audit count")
        .get(0)
}

async fn assert_read_audit_is_ordered_chained_and_minimized(
    database: &TestDatabase,
    profile: &AuditProfile,
    registry: &registry_breg::CompiledRegistry,
) {
    let envelopes = ordered_audit_envelopes(database, profile).await;
    let records = envelopes
        .iter()
        .map(|envelope| envelope.record.clone())
        .collect::<Vec<_>>();
    let phases = records
        .iter()
        .map(|record| {
            (
                record["phase"].as_str().expect("phase is recorded"),
                record["outcome"].as_str(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        phases,
        vec![
            ("attempt", None),
            ("terminal", Some("returned")),
            ("attempt", None),
            ("terminal", Some("returned")),
            ("attempt", None),
            ("terminal", Some("returned")),
            ("attempt", None),
            ("terminal", Some("unresolved")),
            ("attempt", None),
            ("terminal", Some("unresolved")),
            ("attempt", None),
            ("terminal", Some("returned")),
            ("attempt", None),
            ("terminal", Some("returned")),
            ("attempt", None),
            ("terminal", Some("returned")),
            ("attempt", None),
            ("terminal", Some("returned")),
            ("attempt", None),
            ("terminal", Some("returned")),
            ("attempt", None),
            ("terminal", Some("returned")),
            ("refusal", None),
            ("attempt", None),
            ("terminal", Some("empty")),
            ("attempt", None),
            ("terminal", Some("empty")),
            ("refusal", None),
            ("attempt", None),
        ],
        "durable read audit records bracket release in order"
    );
    assert_eq!(records[1]["resultCount"], 1);
    assert_eq!(records[3]["resultCount"], 1);
    assert_eq!(records[5]["resultCount"], 1);
    assert!(records[7].get("resultCount").is_none());
    assert!(records[9].get("resultCount").is_none());
    assert_eq!(records[11]["resultCount"], 1);
    assert_eq!(records[13]["resultCount"], 1);
    assert_eq!(records[15]["resultCount"], 100);
    assert_eq!(records[17]["resultCount"], 2);
    assert_eq!(records[19]["resultCount"], 1);
    assert_eq!(records[21]["resultCount"], 3);
    assert_eq!(records[24]["resultCount"], 0);
    assert_eq!(records[26]["resultCount"], 0);
    assert!(records[1].get("fieldSetReference").is_some());
    assert!(records[3].get("fieldSetReference").is_some());
    assert!(records[5].get("fieldSetReference").is_some());
    assert!(records[7].get("fieldSetReference").is_some());
    assert!(records[15].get("queryReference").is_some());
    assert!(records[15].get("rowBoundaryReference").is_some());

    let audit_text = records
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!audit_text.contains(PRINCIPAL_CANARY));
    assert!(!audit_text.contains(SECRET_CANARY));
    assert!(!audit_text.contains(VISIBLE_RECORD));
    assert!(!audit_text.contains(ALPHA_RECORD));
    assert!(!audit_text.contains(WILDCARD_RECORD));
    assert!(!audit_text.contains(MISMATCH_RECORD));
    assert!(!audit_text.contains(TOMBSTONED_RECORD));
    for field in [
        "label",
        "amount",
        "secret",
        "jurisdiction",
        "ordinal",
        "zone-a",
        "zone-b",
    ] {
        assert!(!audit_text.contains(field));
    }
    let entity = &registry.entities()["widget"];
    assert!(!audit_text.contains(&entity.physical_table));
    for field in entity.fields.values() {
        assert!(!audit_text.contains(&field.physical_name));
    }
    assert!(audit_text.contains("principalReference"));
    assert!(audit_text.contains("recordReference"));
}

async fn ordered_audit_envelopes(
    database: &TestDatabase,
    profile: &AuditProfile,
) -> Vec<AuditEnvelope> {
    let rows = database
        .admin
        .query("SELECT envelope FROM registry_internal.registry_audit", &[])
        .await
        .expect("administrator can inspect audit envelopes");
    let mut envelopes = rows
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
    ordered
}

fn quote_identifier(value: &str) -> String {
    format!("\"{value}\"")
}

fn compiled_registry() -> registry_breg::CompiledRegistry {
    compile_registry_source(&registry_source())
}

fn compiled_registry_without_amount_projection() -> registry_breg::CompiledRegistry {
    let source = registry_source()
        .replace(
            r#""readableFields":["label","secret","amount","jurisdiction","ordinal","rank"]"#,
            r#""readableFields":["label","secret","jurisdiction","ordinal","rank"]"#,
        )
        .replace(
            r#""writableFields":["label","secret","amount","jurisdiction","ordinal","rank"]"#,
            r#""writableFields":["label","secret","jurisdiction","ordinal","rank"]"#,
        );
    compile_registry_source(&source)
}

fn compiled_registry_without_label_filter() -> registry_breg::CompiledRegistry {
    compile_registry_source(&registry_source().replace(
        r#""filterableFields":["jurisdiction","label","ordinal","rank"]"#,
        r#""filterableFields":["jurisdiction","ordinal","rank"]"#,
    ))
}

fn compiled_registry_without_rank_sort() -> registry_breg::CompiledRegistry {
    compile_registry_source(&registry_source().replace(
        r#""sortableFields":["ordinal","label","rank"]"#,
        r#""sortableFields":["ordinal","label"]"#,
    ))
}

fn compile_registry_source(source: &str) -> registry_breg::CompiledRegistry {
    let project = parse_project_json(source.as_bytes()).expect("read fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("read fixture compiles to trusted inventories")
}

fn registry_source() -> String {
    r#"{
	          "apiVersion":"registry.registrystack.org/v1alpha1",
	          "kind":"RegistryProject",
	          "registry":{"id":"read-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[{
            "id":"widget",
            "primaryDataset":"test-dataset",
            "route":"widgets",
            "mutationMode":"mutable",
            "tombstone":true,
            "classification":"restricted",
            "selectorProfiles":[{"id":"by-amount","fields":["amount"]}],
            "fields":[
              {"id":"jurisdiction","type":"string","required":true,"maxLength":32,"classification":"internal"},
              {"id":"label","type":"string","required":true,"maxLength":100,"classification":"internal"},
              {"id":"secret","type":"string","required":true,"maxLength":100,"classification":"restricted"},
              {"id":"amount","type":"decimal","required":true,"precision":8,"scale":2,"classification":"internal"},
              {"id":"ordinal","type":"int64","required":true,"classification":"internal"},
              {"id":"rank","type":"int64","required":false,"classification":"internal"},
              {"id":"internal-code","apiName":"publicCode","type":"string","required":false,"maxLength":32,"classification":"internal"}
            ]
          },{
            "id":"assignment",
            "primaryDataset":"test-dataset",
            "route":"assignments",
            "mutationMode":"mutable",
            "tombstone":true,
            "classification":"restricted",
            "fields":[
              {"id":"jurisdiction","type":"string","required":true,"maxLength":32,"classification":"internal"},
              {"id":"label","type":"string","required":true,"maxLength":100,"classification":"internal"},
              {"id":"valid-from","type":"timestamp","required":true,"classification":"internal"},
              {"id":"valid-to","type":"timestamp","required":false,"classification":"internal"}
            ],
            "temporal":{
              "startField":"valid-from",
              "endField":"valid-to",
              "scopeFields":["label"]
            },
            "constraints":[{
              "kind":"temporal-non-overlap",
              "scopeFields":["label"],
              "startField":"valid-from",
              "endField":"valid-to"
            }]
	          }],
          "accessProfiles":[{
            "id":"operator",
            "default":true,
            "principalClaim":"registry_principal",
            "requiredScopes":["registry.read"],
            "requiredPurposes":["case-management","audit-review"],
            "grants":[{
              "entity":"widget",
              "operations":["create","get","lookup","list","tombstone"],
              "readableFields":["label","secret","amount","jurisdiction","ordinal","rank","internal-code"],
              "writableFields":["label","secret","amount","jurisdiction","ordinal","rank"],
              "filterableFields":["jurisdiction","label","ordinal","rank"],
              "sortableFields":["ordinal","label","rank"],
              "lookups":[{"selector":"by-amount","valueOrigin":"request"}],
              "allowCount":true,
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdictions","operator":"in"}]
            },{
              "entity":"assignment",
              "operations":["create","get","list"],
              "readableFields":["label","jurisdiction","valid-from","valid-to"],
              "writableFields":["label","jurisdiction","valid-from","valid-to"],
              "filterableFields":["label","jurisdiction"],
              "sortableFields":["label"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdictions","operator":"in"}]
            }]
          },{
            "id":"auditor",
            "principalClaim":"registry_principal",
            "requiredScopes":["registry.read"],
            "requiredPurposes":["case-management"],
            "grants":[{
              "entity":"widget",
              "operations":["get","list"],
              "readableFields":["label","jurisdiction","internal-code"],
              "filterableFields":["label"],
              "sortableFields":["label"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdictions","operator":"in"}]
            }]
          }]
	        }"#
    .to_owned()
}
