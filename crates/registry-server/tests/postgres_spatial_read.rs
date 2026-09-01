// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{header, HeaderValue, Method, Request, Response, StatusCode};
use postgres_harness::TestDatabase;
use registry_platform_audit::{verify_jsonl_lines_with_hasher, AuditEnvelope, AuditProfile};
use registry_platform_canonical_json::canonicalize_json;
use registry_server::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedClaimValue,
    VerifiedRequestClaims,
};
use registry_server::compiler::{
    compile_project, compile_project_with_assets, module_digest_with_assets, CompileProfile,
};
use registry_server::contract::{parse_module_json, parse_project_json, ModuleAssetSource};
use registry_server::cursor::CursorCodec;
use registry_server::postgres::{
    begin_record_transaction, initialize_registry_state_for_catalog_test, install_compiled_schema,
    provision_postgis_prerequisites, spatial_bbox_role, ClaimContext, ExpectedManagedCatalog,
    PostgresRecordReadService, ReadFaultPoint, RegistryLockKey, RegistryStateTestIdentity,
    RowBoundaryContext, RuntimePool,
};
use registry_server::runtime_config::PublicOrigin;
use serde_json::{json, Value};
use tokio_postgres::Transaction;
use tower::Service as _;
use zeroize::Zeroizing;

const PACKAGE_ID: &str = "spatial-read-registry";
const INSTANCE_ID: &str = "spatial-read-instance";
const DATABASE_ID: &str = "spatial-read-database";
const PRINCIPAL_CANARY: &str = "principal-value-must-not-enter-spatial-read-audit";
const SECRET_CANARY: &str = "SECRET-SPATIAL-CANARY-MUST-NOT-LEAVE";
const EDGE_WEST: &str = "00000000-0000-4000-8000-000000000001";
const INTERIOR: &str = "00000000-0000-4000-8000-000000000002";
const EDGE_NORTH_EAST: &str = "00000000-0000-4000-8000-000000000003";
const JUST_OUTSIDE: &str = "00000000-0000-4000-8000-000000000004";
const NULL_GEOMETRY: &str = "00000000-0000-4000-8000-000000000005";
const ZERO_AREA: &str = "00000000-0000-4000-8000-000000000006";
const OTHER_ROW_BOUNDARY: &str = "00000000-0000-4000-8000-000000000007";
const TOMBSTONED_INSIDE: &str = "00000000-0000-4000-8000-000000000008";
const EXACT_DECIMAL_POINT: &str = "00000000-0000-4000-8000-000000000009";
const PAGE_A: &str = "00000000-0000-4000-8000-000000000011";
const PAGE_B: &str = "00000000-0000-4000-8000-000000000012";
const PAGE_C: &str = "00000000-0000-4000-8000-000000000013";
const PAGE_D: &str = "00000000-0000-4000-8000-000000000014";
const PAGE_E: &str = "00000000-0000-4000-8000-000000000015";
const MALFORMED_ACQUIRED: &str = "00000000-0000-4000-8000-000000000016";
const BUDGET_A: &str = "00000000-0000-4000-8000-000000000021";
const BUDGET_B: &str = "00000000-0000-4000-8000-000000000022";
const SERVICE_ZONE_A: &str = "00000000-0000-4000-8000-000000000031";
const SERVICE_ZONE_B: &str = "00000000-0000-4000-8000-000000000032";
const SERVICE_REGION_A: &str = "00000000-0000-4000-8000-000000000033";
const SERVICE_REGION_B: &str = "00000000-0000-4000-8000-000000000034";
const PLAIN_POINT: &str = "10000000-0000-4000-8000-000000000001";
const LARGE_NOTE_BYTES: usize = 1_080_000;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_spatial_bbox_reads_preserve_authority_and_geojson_audit() {
    let harness = SpatialHarness::create(compiled_spatial_registry()).await;
    seed_spatial_rows(&harness).await;

    let query_plan = Arc::new(Mutex::new(Vec::new()));
    let app = harness.router_with_query_plan(None, cursor_codec(), Arc::clone(&query_plan));
    let json_bbox = send(
        &app,
        "/v1/records/service-sites?bbox=100,13,101,14&$select=code,label,location&$top=20",
        Some(claims(["zone-a"])),
        None,
    )
    .await;
    assert_eq!(json_bbox.status(), StatusCode::OK);
    let json_bbox = body_json(json_bbox).await;
    assert_ids(
        &json_bbox,
        &[
            EDGE_WEST,
            INTERIOR,
            EDGE_NORTH_EAST,
            ZERO_AREA,
            PAGE_A,
            PAGE_B,
            PAGE_C,
            PAGE_D,
            PAGE_E,
            MALFORMED_ACQUIRED,
        ],
    );
    assert_actual_spatial_plan_uses_gist(&query_plan);
    let json_text = json_bbox.to_string();
    assert!(!json_text.contains(JUST_OUTSIDE));
    assert!(!json_text.contains(NULL_GEOMETRY));
    assert!(!json_text.contains(OTHER_ROW_BOUNDARY));
    assert!(!json_text.contains(TOMBSTONED_INSIDE));
    assert!(!json_text.contains(SECRET_CANARY));

    let filtered = send(
        &app,
        "/v1/records/service-sites?bbox=100,13,101,14&$filter=code%20eq%20'zero-area'&$select=code,location",
        Some(claims(["zone-a"])),
        None,
    )
    .await;
    assert_eq!(filtered.status(), StatusCode::OK);
    assert_ids(&body_json(filtered).await, &[ZERO_AREA]);

    let derived_filtered_and_ordered = send(
        &app,
        "/v1/records/service-sites?bbox=100,13,101,14&$select=code,mapLabel,location&$filter=startswith(mapLabel,'page-')&$orderby=mapLabel&$top=5",
        Some(claims(["zone-a"])),
        None,
    )
    .await;
    assert_eq!(derived_filtered_and_ordered.status(), StatusCode::OK);
    let derived_filtered_and_ordered = body_json(derived_filtered_and_ordered).await;
    assert_ids(
        &derived_filtered_and_ordered,
        &[PAGE_A, PAGE_B, PAGE_C, PAGE_D, PAGE_E],
    );
    assert_eq!(
        derived_filtered_and_ordered["items"][0]["data"]["mapLabel"],
        "page-a"
    );

    let derived_dependencies = send(
        &app,
        "/v1/records/service-sites?bbox=100,13,101,14&$select=code,zoneSiteCount,zoneLabel,regionLabel,location&$filter=code%20eq%20'edge-west'",
        Some(claims(["zone-a"])),
        None,
    )
    .await;
    assert_eq!(derived_dependencies.status(), StatusCode::OK);
    let derived_dependencies = body_json(derived_dependencies).await;
    assert_ids(&derived_dependencies, &[EDGE_WEST]);
    let dependency_data = &derived_dependencies["items"][0]["data"];
    assert_eq!(
        dependency_data["zoneSiteCount"], 13,
        "same-entity derived aggregate includes authorized service-site rows outside the root bbox"
    );
    assert_eq!(
        dependency_data["zoneLabel"], "Authorized Zone A",
        "derived SQL can read an authorized nonspatial dependency entity"
    );
    assert_eq!(
        dependency_data["regionLabel"], "Remote Zone A Region",
        "derived SQL can read an authorized second GIS entity outside the root bbox"
    );

    let zero_area = send(
        &app,
        "/v1/records/service-sites?bbox=100.25,13.25,100.25,13.25&$select=code,location",
        Some(claims(["zone-a"])),
        None,
    )
    .await;
    assert_eq!(zero_area.status(), StatusCode::OK);
    assert_ids(&body_json(zero_area).await, &[ZERO_AREA]);

    let empty_bbox = send(
        &app,
        "/v1/records/service-sites?bbox=99,13,99.5,13.5&$select=code,location",
        Some(claims(["zone-a"])),
        None,
    )
    .await;
    assert_eq!(empty_bbox.status(), StatusCode::OK);
    assert_ids(&body_json(empty_bbox).await, &[]);

    let zero_width_line = send(
        &app,
        "/v1/records/service-sites?bbox=100,13,100,14&$select=code,location",
        Some(claims(["zone-a"])),
        None,
    )
    .await;
    assert_eq!(zero_width_line.status(), StatusCode::OK);
    assert_ids(&body_json(zero_width_line).await, &[EDGE_WEST]);

    let zero_height_line = send(
        &app,
        "/v1/records/service-sites?bbox=100,13.5,101,13.5&$select=code,location",
        Some(claims(["zone-a"])),
        None,
    )
    .await;
    assert_eq!(zero_height_line.status(), StatusCode::OK);
    assert_ids(&body_json(zero_height_line).await, &[EDGE_WEST, INTERIOR]);

    clear_query_plan(&query_plan);
    let exact_decimal_edge = send(
        &app,
        "/v1/records/service-sites?bbox=0.3,0,0.3,0&$select=code,location",
        Some(claims(["zone-a"])),
        None,
    )
    .await;
    assert_eq!(exact_decimal_edge.status(), StatusCode::OK);
    assert_ids(&body_json(exact_decimal_edge).await, &[EXACT_DECIMAL_POINT]);
    assert_actual_spatial_plan_uses_gist(&query_plan);

    let west_just_after_decimal = send(
        &app,
        "/v1/records/service-sites?bbox=0.30000000000000000001,0,0.30000000000000000001,0&$select=code,location",
        Some(claims(["zone-a"])),
        None,
    )
    .await;
    assert_eq!(west_just_after_decimal.status(), StatusCode::OK);
    assert_ids(&body_json(west_just_after_decimal).await, &[]);

    let east_just_before_decimal = send(
        &app,
        "/v1/records/service-sites?bbox=0.29999999999999999999,0,0.29999999999999999999,0&$select=code,location",
        Some(claims(["zone-a"])),
        None,
    )
    .await;
    assert_eq!(east_just_before_decimal.status(), StatusCode::OK);
    assert_ids(&body_json(east_just_before_decimal).await, &[]);

    let count_refused = send(
        &app,
        "/v1/records/service-sites?bbox=100,13,101,14&$count=true",
        Some(claims(["zone-a"])),
        None,
    )
    .await;
    assert_eq!(count_refused.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(count_refused).await["code"], "query.invalid");

    let counted = send(
        &app,
        "/v1/records/service-sites?accessProfile=count-reader&bbox=100,13,101,14&$count=true",
        Some(claims(["zone-a"])),
        None,
    )
    .await;
    assert_eq!(counted.status(), StatusCode::OK);
    let counted = body_json(counted).await;
    assert_eq!(counted["count"], 10);
    assert_ids(
        &counted,
        &[
            EDGE_WEST,
            INTERIOR,
            EDGE_NORTH_EAST,
            ZERO_AREA,
            PAGE_A,
            PAGE_B,
            PAGE_C,
            PAGE_D,
            PAGE_E,
            MALFORMED_ACQUIRED,
        ],
    );

    for uri in [
        "/v1/records/service-sites?bbox=100,13,101,14&$select=secret",
        "/v1/records/service-sites?accessProfile=no-bbox&bbox=100,13,101,14",
        "/v1/records/service-sites?accessProfile=get-only&bbox=100,13,101,14",
    ] {
        let response = send(&app, uri, Some(claims(["zone-a"])), None).await;
        assert!(
            matches!(
                response.status(),
                StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND
            ),
            "{uri} refuses without releasing a row"
        );
        let body = body_json(response).await;
        assert!(!body.to_string().contains(SECRET_CANARY));
    }

    for (uri, claims) in [
        (
            "/v1/records/service-sites?bbox=100,13,101,14",
            claims_without_scope(),
        ),
        (
            "/v1/records/service-sites?bbox=100,13,101,14",
            claims_with_purpose("export"),
        ),
        (
            "/v1/records/service-sites?bbox=100,13,101,14",
            claims_without_row_boundary(),
        ),
    ] {
        let response = send(&app, uri, Some(claims), None).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(body_json(response).await["code"], "resource.not_found");
    }

    for uri in [
        "/v1/records/service-sites?bbox=100,13,99,14",
        "/v1/records/service-sites?bbox=100,13,101,14,15,16",
        "/v1/records/service-sites?bbox=100,13,101,14&bbox=100,13,101,14",
        "/v1/records/service-sites?bbox=100,13,102.5,14",
        "/v1/records/service-sites?bbox=100,13,NaN,14",
        "/v1/records/service-sites?bbox=-181,13,101,14",
        "/v1/records/service-sites?bbox=170,13,-170,14",
        "/v1/records/service-sites?bbox=100,13,101,14&$top=1001",
        "/v1/gis/collections/service-site.map-reader/items?bbox=100,13,101,14&limit=10001&f=json",
    ] {
        let before = audit_count(&harness.database).await;
        let response = send(&app, uri, Some(claims(["zone-a"])), None).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(body_json(response).await["code"], "query.invalid");
        assert_eq!(
            audit_count(&harness.database).await,
            before + 1,
            "invalid bbox request is audited as a refusal before row access"
        );
    }
    let unsupported_historical = send(
        &app,
        "/v1/records/service-sites:as-of?bbox=100,13,101,14&asOf=2020-01-01T00:00:00Z",
        Some(claims(["zone-a"])),
        None,
    )
    .await;
    assert_eq!(unsupported_historical.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        body_json(unsupported_historical).await["code"],
        "resource.not_found"
    );

    let geojson = send(
        &app,
        "/v1/records/service-sites?bbox=100.25,13.25,100.25,13.25&$select=code,label,location",
        Some(claims(["zone-a"])),
        Some("application/geo+json"),
    )
    .await;
    assert_eq!(geojson.status(), StatusCode::OK);
    assert_eq!(
        geojson.headers()[header::CONTENT_TYPE],
        HeaderValue::from_static("application/geo+json")
    );
    let geojson_bytes = body_bytes(geojson).await;
    let expected = json!({
        "features": [
            feature(ZERO_AREA, 1, json!({"type":"Point","coordinates":[100.25,13.25]}), json!({"code":"zero-area","label":"Zero area"}))
        ],
        "numberReturned": 1,
        "registry": {"pageInfo": {"nextCursor": Value::Null}},
        "type": "FeatureCollection"
    });
    let expected_bytes = canonicalize_json(&expected).expect("expected GeoJSON canonicalizes");
    let body = json_from_bytes(&geojson_bytes);
    assert_eq!(body["features"].as_array().expect("features").len(), 1);
    assert_eq!(body["features"][0]["properties"]["code"], "zero-area");
    assert!(!body.to_string().contains("location"));
    assert!(!body.to_string().contains(SECRET_CANARY));
    assert_eq!(
        geojson_bytes, expected_bytes,
        "GeoJSON bytes are deterministic before the exact-byte audit release gate"
    );

    let adapter_geojson = send(
        &app,
        "/v1/gis/collections/service-site.map-reader/items?bbox=100.25,13.25,100.25,13.25&limit=20&f=json",
        Some(claims(["zone-a"])),
        None,
    )
    .await;
    assert_eq!(adapter_geojson.status(), StatusCode::OK);
    assert_eq!(
        adapter_geojson.headers()[header::CONTENT_TYPE],
        HeaderValue::from_static("application/geo+json")
    );
    let adapter_geojson_bytes = body_bytes(adapter_geojson).await;
    let adapter_expected = json!({
        "features": [
            feature(
                ZERO_AREA,
                1,
                json!({"type":"Point","coordinates":[100.25,13.25]}),
                json!({
                    "code":"zero-area",
                    "label":"Zero area",
                    "mapLabel":"zero-area",
                    "regionLabel":"Remote Zone A Region",
                    "zoneLabel":"Authorized Zone A",
                    "zoneSiteCount":13
                })
            )
        ],
        "numberReturned": 1,
        "registry": {"pageInfo": {"nextCursor": Value::Null}},
        "type": "FeatureCollection"
    });
    let adapter_expected_bytes =
        canonicalize_json(&adapter_expected).expect("expected adapter GeoJSON canonicalizes");
    assert_eq!(
        adapter_geojson_bytes, adapter_expected_bytes,
        "GIS adapter GeoJSON bytes are held until the exact-byte audit release gate"
    );

    let before_fault = audit_count(&harness.database).await;
    let faulting = harness.router(Some(ReadFaultPoint::BeforeTerminalAudit), cursor_codec());
    let faulted = send(
        &faulting,
        "/v1/records/service-sites?bbox=100,13,101,14&$select=code,label,location&$top=1",
        Some(claims(["zone-a"])),
        Some("application/geo+json"),
    )
    .await;
    assert_eq!(faulted.status(), StatusCode::SERVICE_UNAVAILABLE);
    let faulted = body_json(faulted).await;
    assert_eq!(faulted["code"], "source.unavailable");
    assert!(!faulted.to_string().contains("edge-west"));
    assert_eq!(
        audit_count(&harness.database).await,
        before_fault + 1,
        "terminal audit failure releases no held GeoJSON bytes and commits only the attempt"
    );

    let before_adapter_fault = audit_count(&harness.database).await;
    let adapter_faulted = send(
        &faulting,
        "/v1/gis/collections/service-site.map-reader/items?bbox=100.25,13.25,100.25,13.25&limit=20&f=json",
        Some(claims(["zone-a"])),
        None,
    )
    .await;
    assert_eq!(adapter_faulted.status(), StatusCode::SERVICE_UNAVAILABLE);
    let adapter_faulted = body_json(adapter_faulted).await;
    assert_eq!(adapter_faulted["code"], "source.unavailable");
    assert!(!adapter_faulted.to_string().contains("zero-area"));
    assert_eq!(
        audit_count(&harness.database).await,
        before_adapter_fault + 1,
        "GIS adapter terminal audit failure releases no held GeoJSON bytes"
    );

    assert_pool_context_clean(&harness.pool, &harness.database.runtime_role).await;
    assert_spatial_audit_is_minimized(&harness.database, &harness.audit_profile).await;
    harness.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_spatial_response_budget_refuses_oversized_payloads_atomically() {
    let harness = SpatialHarness::create(compiled_spatial_registry()).await;
    seed_spatial_budget_rows(&harness).await;

    let app = harness.router(None, cursor_codec());
    let small_selection = send(
        &app,
        "/v1/records/service-sites?accessProfile=notes-reader&bbox=102,20,102.1,20.1&$select=code,location&$top=2",
        Some(claims(["zone-a"])),
        None,
    )
    .await;
    assert_eq!(small_selection.status(), StatusCode::OK);
    let small_selection = body_json(small_selection).await;
    assert_ids(&small_selection, &[BUDGET_A, BUDGET_B]);
    assert!(!small_selection.to_string().contains("notes"));

    let smaller_page = send(
        &app,
        "/v1/records/service-sites?accessProfile=notes-reader&bbox=102,20,102.1,20.1&$select=code,notes,location&$top=1",
        Some(claims(["zone-a"])),
        None,
    )
    .await;
    assert_eq!(smaller_page.status(), StatusCode::OK);
    let smaller_page_bytes = body_bytes(smaller_page).await;
    assert!(
        smaller_page_bytes.len() > LARGE_NOTE_BYTES,
        "one large note remains below the spatial response cap"
    );
    let smaller_page = json_from_bytes(&smaller_page_bytes);
    assert_ids(&smaller_page, &[BUDGET_A]);
    assert_eq!(
        smaller_page["items"][0]["data"]["notes"]
            .as_str()
            .expect("notes is returned")
            .len(),
        LARGE_NOTE_BYTES
    );

    assert_spatial_budget_refusal(
        &harness,
        &app,
        "/v1/records/service-sites?accessProfile=notes-reader&bbox=102,20,102.1,20.1&$select=code,notes,location&$top=2",
        None,
    )
    .await;
    assert_spatial_budget_refusal(
        &harness,
        &app,
        "/v1/records/service-sites?accessProfile=notes-reader&bbox=102,20,102.1,20.1&$select=code,notes,location&$top=2",
        Some("application/geo+json"),
    )
    .await;
    assert_spatial_budget_refusal(
        &harness,
        &app,
        "/v1/gis/collections/service-site.notes-reader/items?bbox=102,20,102.1,20.1&limit=2&f=json",
        None,
    )
    .await;

    assert_pool_context_clean(&harness.pool, &harness.database.runtime_role).await;
    harness.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_spatial_paging_cursor_replay_and_pool_reset_are_bounded() {
    let harness = SpatialHarness::create(compiled_spatial_registry()).await;
    seed_spatial_rows(&harness).await;

    let app = harness.router(None, cursor_codec());
    let first = send(
        &app,
        "/v1/records/service-sites?bbox=100,13,101,14&$select=code,label,location&$top=2",
        Some(claims(["zone-a"])),
        Some("application/geo+json"),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    let first = body_json(first).await;
    let mut seen = feature_ids(&first);
    let mut cursor = first["registry"]["pageInfo"]["nextCursor"]
        .as_str()
        .expect("first page overfetches")
        .to_owned();

    for _ in 0..8 {
        let page = send(
            &app,
            &format!("/v1/records/service-sites?$skiptoken={cursor}"),
            Some(claims(["zone-a"])),
            Some("application/geo+json"),
        )
        .await;
        assert_eq!(page.status(), StatusCode::OK);
        let page = body_json(page).await;
        seen.extend(feature_ids(&page));
        let next = page["registry"]["pageInfo"]["nextCursor"].as_str();
        if let Some(next) = next {
            cursor = next.to_owned();
        } else {
            break;
        }
    }
    assert_eq!(
        seen,
        vec![
            EDGE_WEST,
            INTERIOR,
            EDGE_NORTH_EAST,
            ZERO_AREA,
            PAGE_A,
            PAGE_B,
            PAGE_C,
            PAGE_D,
            PAGE_E,
            MALFORMED_ACQUIRED,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>(),
        "unchanged bbox pages return every authorized row once"
    );

    let replay_cursor = next_cursor(
        &app,
        "/v1/records/service-sites?bbox=100,13,101,14&$select=code,label,location&$top=2",
        Some(claims(["zone-a"])),
        Some("application/geo+json"),
    )
    .await;
    for (uri, claims, accept, expected_code) in [
        (
            format!("/v1/records/service-sites?$skiptoken={replay_cursor}"),
            claims(["zone-a"]),
            None,
            "query.cursor_invalid",
        ),
        (
            format!(
                "/v1/records/service-sites?accessProfile=count-reader&$skiptoken={replay_cursor}"
            ),
            claims(["zone-a"]),
            Some("application/geo+json"),
            "query.cursor_invalid",
        ),
        (
            format!("/v1/records/service-sites?$skiptoken={replay_cursor}"),
            claims_with(PRINCIPAL_CANARY, "case-management", ["zone-b"]),
            Some("application/geo+json"),
            "query.cursor_invalid",
        ),
        (
            format!("/v1/records/service-sites?$skiptoken={replay_cursor}"),
            claims_with("other-principal", "case-management", ["zone-a"]),
            Some("application/geo+json"),
            "query.cursor_invalid",
        ),
        (
            format!("/v1/records/service-sites?$skiptoken={replay_cursor}&bbox=100,13,101,14"),
            claims(["zone-a"]),
            Some("application/geo+json"),
            "query.invalid",
        ),
        (
            format!("/v1/records/service-sites?$skiptoken={replay_cursor}&$top=5"),
            claims(["zone-a"]),
            Some("application/geo+json"),
            "query.invalid",
        ),
        (
            format!("/v1/records/service-sites?$skiptoken={replay_cursor}&$select=code"),
            claims(["zone-a"]),
            Some("application/geo+json"),
            "query.invalid",
        ),
    ] {
        let response = send(&app, &uri, Some(claims), accept).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        let body = body_json(response).await;
        assert_eq!(body["code"], expected_code);
        assert!(!body.to_string().contains(SECRET_CANARY));
    }

    let gis_first = send(
        &app,
        "/v1/gis/collections/service-site.map-reader/items?bbox=100,13,101,14&limit=2&f=json",
        Some(claims(["zone-a"])),
        None,
    )
    .await;
    assert_eq!(gis_first.status(), StatusCode::OK);
    let gis_first = body_json(gis_first).await;
    let gis_cursor = gis_first["registry"]["pageInfo"]["nextCursor"]
        .as_str()
        .expect("GIS first page overfetches");
    let native_replay = send(
        &app,
        &format!("/v1/records/service-sites?$skiptoken={gis_cursor}"),
        Some(claims(["zone-a"])),
        Some("application/geo+json"),
    )
    .await;
    assert_eq!(native_replay.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(native_replay).await["code"],
        "query.cursor_invalid"
    );

    let package_changed = harness.router_with_identity(
        None,
        cursor_codec(),
        ReadRuntimeIdentity {
            package_revision: "spatial-read-package-2".to_owned(),
            schema_fingerprint: harness.identity.schema_fingerprint.clone(),
        },
    );
    let package_replay = send(
        &package_changed,
        &format!("/v1/records/service-sites?$skiptoken={replay_cursor}"),
        Some(claims(["zone-a"])),
        Some("application/geo+json"),
    )
    .await;
    assert_eq!(package_replay.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(package_replay).await["code"],
        "query.cursor_invalid"
    );

    let expiring = harness.router(None, immediately_expiring_cursor_codec());
    let expired = next_cursor(
        &expiring,
        "/v1/records/service-sites?bbox=100,13,101,14&$select=code,location&$top=1",
        Some(claims(["zone-a"])),
        Some("application/geo+json"),
    )
    .await;
    let expired_replay = send(
        &expiring,
        &format!("/v1/records/service-sites?$skiptoken={expired}"),
        Some(claims(["zone-a"])),
        Some("application/geo+json"),
    )
    .await;
    assert_eq!(expired_replay.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(expired_replay).await["code"],
        "query.cursor_invalid"
    );

    assert_spatial_candidate_context_resets_after_statement_timeout(&harness).await;
    assert_pool_context_clean(&harness.pool, &harness.database.runtime_role).await;
    harness.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_acquired_geojson_fails_atomically_and_records_terminal_audit() {
    let harness = SpatialHarness::create(compiled_spatial_registry()).await;
    seed_spatial_rows(&harness).await;
    corrupt_point_after_storage_validation(&harness, MALFORMED_ACQUIRED).await;

    let app = harness.router(None, cursor_codec());
    let before = audit_count(&harness.database).await;
    let response = send(
        &app,
        "/v1/records/service-sites?bbox=100,13,101,14&$select=code,label,location&$top=20",
        Some(claims(["zone-a"])),
        Some("application/geo+json"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = body_json(response).await;
    assert_eq!(body["code"], "source.unavailable");
    let text = body.to_string();
    assert!(!text.contains("malformed"));
    assert!(!text.contains("edge-west"));
    assert!(!text.contains(SECRET_CANARY));

    let records = ordered_audit_records(&harness.database, &harness.audit_profile).await;
    let new_records = &records[usize::try_from(before).expect("audit count fits usize")..];
    assert_eq!(
        new_records
            .iter()
            .map(|record| (
                record["phase"].as_str().expect("phase"),
                record["outcome"].as_str()
            ))
            .collect::<Vec<_>>(),
        vec![("attempt", None), ("terminal", Some("refused"))],
        "malformed acquired GeoJSON is audited as one terminal refusal before release"
    );
    assert_eq!(new_records[1]["resultCount"], 0);

    assert_pool_context_clean(&harness.pool, &harness.database.runtime_role).await;
    harness.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn predicate_free_geojson_works_on_plain_postgresql_without_postgis() {
    let database = TestDatabase::create(4).await;
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = Arc::new(compiled_plain_geojson_registry());
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("plain PostgreSQL installs Point storage without PostGIS");
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
            package_revision: "plain-geojson-package-1",
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
    seed_plain_row(&database, &pool, lock_key, &identity, &compiled).await;
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x39; 32].into())
        .expect("test owns a strongly keyed audit profile");
    let app = read_router(
        pool,
        compiled,
        identity,
        lock_key,
        audit_profile,
        None,
        None,
        cursor_codec(),
        None,
    );

    let response = send(
        &app,
        "/v1/records/plain-sites?$select=code,location",
        Some(plain_claims()),
        Some("application/geo+json"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["features"][0]["id"], PLAIN_POINT);
    assert_eq!(
        body["features"][0]["geometry"],
        json!({"type":"Point","coordinates":[100.5,13.5]})
    );
    assert_eq!(body["features"][0]["properties"], json!({"code":"plain"}));

    let selected_without_geometry = send(
        &app,
        "/v1/records/plain-sites?$select=code",
        Some(plain_claims()),
        Some("application/geo+json"),
    )
    .await;
    assert_eq!(selected_without_geometry.status(), StatusCode::OK);
    let selected_without_geometry = body_json(selected_without_geometry).await;
    assert_eq!(
        selected_without_geometry["features"][0]["geometry"],
        Value::Null
    );
    assert_eq!(
        selected_without_geometry["features"][0]["properties"],
        json!({"code":"plain"})
    );

    database.cleanup().await;
}

struct SpatialHarness {
    database: TestDatabase,
    pool: RuntimePool,
    lock_key: RegistryLockKey,
    compiled: Arc<registry_server::CompiledRegistry>,
    identity: registry_server::postgres::ExpectedRegistryIdentity,
    audit_profile: AuditProfile,
}

impl SpatialHarness {
    async fn create(compiled: registry_server::CompiledRegistry) -> Self {
        let database = TestDatabase::create(8).await;
        provision_postgis_prerequisites(
            &database.admin,
            &database.migration_role,
            &database.runtime_role,
        )
        .await
        .expect("administrator installs governed PostGIS prerequisites");
        let (migration, migration_task) = database.connect_migration().await;
        let compiled = Arc::new(compiled);
        install_compiled_schema(&migration, &compiled, &database.runtime_role)
            .await
            .expect("migration installs the complete compiled spatial schema");
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
                package_revision: "spatial-read-package-1",
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
        let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x5d; 32].into())
            .expect("test owns a strongly keyed audit profile");
        Self {
            database,
            pool,
            lock_key,
            compiled,
            identity,
            audit_profile,
        }
    }

    fn router(&self, fault: Option<ReadFaultPoint>, cursors: Arc<CursorCodec>) -> axum::Router {
        self.router_with_identity(
            fault,
            cursors,
            ReadRuntimeIdentity {
                package_revision: self.identity.package_revision.clone(),
                schema_fingerprint: self.identity.schema_fingerprint.clone(),
            },
        )
    }

    fn router_with_query_plan(
        &self,
        fault: Option<ReadFaultPoint>,
        cursors: Arc<CursorCodec>,
        query_plan: Arc<Mutex<Vec<Value>>>,
    ) -> axum::Router {
        read_router(
            self.pool.clone(),
            self.compiled.clone(),
            self.identity.clone(),
            self.lock_key,
            self.audit_profile.clone(),
            fault,
            Some(query_plan),
            cursors,
            Some(ReadRuntimeIdentity {
                package_revision: self.identity.package_revision.clone(),
                schema_fingerprint: self.identity.schema_fingerprint.clone(),
            }),
        )
    }

    fn router_with_identity(
        &self,
        fault: Option<ReadFaultPoint>,
        cursors: Arc<CursorCodec>,
        http_identity: ReadRuntimeIdentity,
    ) -> axum::Router {
        read_router(
            self.pool.clone(),
            self.compiled.clone(),
            self.identity.clone(),
            self.lock_key,
            self.audit_profile.clone(),
            fault,
            None,
            cursors,
            Some(http_identity),
        )
    }

    async fn cleanup(self) {
        cleanup_spatial_role(&self.database).await;
        self.database.cleanup().await;
    }
}

#[allow(clippy::too_many_arguments)]
fn read_router(
    pool: RuntimePool,
    registry: Arc<registry_server::CompiledRegistry>,
    identity: registry_server::postgres::ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    profile: AuditProfile,
    fault: Option<ReadFaultPoint>,
    query_plan: Option<Arc<Mutex<Vec<Value>>>>,
    cursors: Arc<CursorCodec>,
    http_identity: Option<ReadRuntimeIdentity>,
) -> axum::Router {
    let read_identity = http_identity.unwrap_or_else(|| ReadRuntimeIdentity {
        package_revision: identity.package_revision.clone(),
        schema_fingerprint: identity.schema_fingerprint.clone(),
    });
    let mut records = PostgresRecordReadService::new(
        pool,
        registry.clone(),
        identity,
        lock_key,
        Duration::from_secs(2),
        profile,
        cursors.clone(),
    );
    if let Some(fault) = fault {
        records = records.with_fault_for_test(fault);
    }
    if let Some(query_plan) = query_plan {
        records = records.with_query_plan_for_test(query_plan);
    }
    let service = HttpService::new(
        registry,
        read_identity,
        Arc::new(records),
        Arc::new(AlwaysReady),
        cursors,
    )
    .with_public_origin(PublicOrigin::parse("http://127.0.0.1:18080").expect("public origin"));
    router(Arc::new(service))
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
    accept: Option<&str>,
) -> Response<Body> {
    let mut builder = Request::builder().method(Method::GET).uri(uri);
    if let Some(accept) = accept {
        builder = builder.header(header::ACCEPT, accept);
    }
    let mut request = builder.body(Body::empty()).expect("request builds");
    if let Some(claims) = claims {
        request.extensions_mut().insert(claims);
    }
    let mut app = app.clone();
    app.call(request).await.expect("router returns a response")
}

async fn next_cursor(
    app: &axum::Router,
    uri: &str,
    claims: Option<VerifiedRequestClaims>,
    accept: Option<&str>,
) -> String {
    let response = send(app, uri, claims, accept).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    body["registry"]["pageInfo"]["nextCursor"]
        .as_str()
        .or_else(|| body["pageInfo"]["nextCursor"].as_str())
        .expect("response carries a continuation cursor")
        .to_owned()
}

async fn body_json(response: Response<Body>) -> Value {
    let bytes = body_bytes(response).await;
    json_from_bytes(&bytes)
}

async fn body_bytes(response: Response<Body>) -> Vec<u8> {
    to_bytes(response.into_body(), 3 * 1024 * 1024)
        .await
        .expect("response body is bounded")
        .to_vec()
}

fn json_from_bytes(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("response is JSON")
}

fn assert_ids(body: &Value, expected: &[&str]) {
    let ids = body["items"]
        .as_array()
        .expect("response carries items")
        .iter()
        .map(|item| item["id"].as_str().expect("item id"))
        .collect::<Vec<_>>();
    assert_eq!(ids, expected);
}

fn assert_actual_spatial_plan_uses_gist(query_plan: &Arc<Mutex<Vec<Value>>>) {
    let nodes = query_plan.lock().expect("query plan probe is available");
    assert!(
        nodes.iter().any(|node| {
            node["spatialIndexCondition"] == true
                && node["indexName"]
                    .as_str()
                    .is_some_and(|name| name.contains("rs_spgix_"))
        }),
        "actual generated spatial read SQL uses the generated GiST spatial index: {nodes:?}"
    );
}

fn clear_query_plan(query_plan: &Arc<Mutex<Vec<Value>>>) {
    query_plan
        .lock()
        .expect("query plan probe is available")
        .clear();
}

async fn assert_spatial_budget_refusal(
    harness: &SpatialHarness,
    app: &axum::Router,
    uri: &str,
    accept: Option<&str>,
) {
    let before = audit_count(&harness.database).await;
    let response = send(app, uri, Some(claims(["zone-a"])), accept).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{uri}");
    let body = body_json(response).await;
    assert_eq!(body["code"], "source.unavailable");
    let text = body.to_string();
    assert!(!text.contains(BUDGET_A));
    assert!(!text.contains(BUDGET_B));
    assert!(!text.contains("budget-a"));
    assert!(!text.contains("notes"));

    let records = ordered_audit_records(&harness.database, &harness.audit_profile).await;
    let new_records = &records[usize::try_from(before).expect("audit count fits usize")..];
    assert_eq!(
        new_records
            .iter()
            .map(|record| (
                record["phase"].as_str().expect("phase"),
                record["outcome"].as_str()
            ))
            .collect::<Vec<_>>(),
        vec![("attempt", None), ("terminal", Some("refused"))],
        "oversized spatial response is audited as one terminal refusal before release"
    );
    assert_eq!(new_records[1]["resultCount"], 0);
}

fn feature_ids(body: &Value) -> Vec<String> {
    body["features"]
        .as_array()
        .expect("response carries features")
        .iter()
        .map(|feature| feature["id"].as_str().expect("feature id").to_owned())
        .collect()
}

fn feature(id: &str, revision: u64, geometry: Value, properties: Value) -> Value {
    json!({
        "geometry": geometry,
        "id": id,
        "properties": properties,
        "registry": {"revision": revision},
        "type": "Feature"
    })
}

async fn seed_spatial_rows(harness: &SpatialHarness) {
    let mut client = harness
        .pool
        .get_for_test()
        .await
        .expect("runtime connection is available");
    for jurisdiction in ["zone-a", "zone-b"] {
        let claims = seed_claims(&harness.compiled, jurisdiction);
        let transaction = begin_record_transaction(
            &mut client,
            harness.lock_key,
            Duration::from_secs(2),
            &harness.identity,
            &claims,
        )
        .await
        .expect("seed transaction installs RLS-safe context");
        if jurisdiction == "zone-a" {
            for row in [
                SpatialSeedRow {
                    record_id: EDGE_WEST,
                    jurisdiction,
                    code: "edge-west",
                    label: "Edge west",
                    location: Some(json!({"type":"Point","coordinates":[100.0,13.5]})),
                },
                SpatialSeedRow {
                    record_id: INTERIOR,
                    jurisdiction,
                    code: "interior",
                    label: "Interior",
                    location: Some(json!({"type":"Point","coordinates":[100.5,13.5]})),
                },
                SpatialSeedRow {
                    record_id: EDGE_NORTH_EAST,
                    jurisdiction,
                    code: "edge-north-east",
                    label: "Edge north east",
                    location: Some(json!({"type":"Point","coordinates":[101.0,14.0]})),
                },
                SpatialSeedRow {
                    record_id: JUST_OUTSIDE,
                    jurisdiction,
                    code: "just-outside",
                    label: "Just outside",
                    location: Some(json!({"type":"Point","coordinates":[101.000001,13.5]})),
                },
                SpatialSeedRow {
                    record_id: NULL_GEOMETRY,
                    jurisdiction,
                    code: "null-geometry",
                    label: "Null geometry",
                    location: None,
                },
                SpatialSeedRow {
                    record_id: ZERO_AREA,
                    jurisdiction,
                    code: "zero-area",
                    label: "Zero area",
                    location: Some(json!({"type":"Point","coordinates":[100.25,13.25]})),
                },
                SpatialSeedRow {
                    record_id: EXACT_DECIMAL_POINT,
                    jurisdiction,
                    code: "exact-decimal",
                    label: "Exact decimal",
                    location: Some(json!({"type":"Point","coordinates":[0.3,0.0]})),
                },
                SpatialSeedRow {
                    record_id: PAGE_A,
                    jurisdiction,
                    code: "page-a",
                    label: "Page A",
                    location: Some(json!({"type":"Point","coordinates":[100.11,13.11]})),
                },
                SpatialSeedRow {
                    record_id: PAGE_B,
                    jurisdiction,
                    code: "page-b",
                    label: "Page B",
                    location: Some(json!({"type":"Point","coordinates":[100.12,13.12]})),
                },
                SpatialSeedRow {
                    record_id: PAGE_C,
                    jurisdiction,
                    code: "page-c",
                    label: "Page C",
                    location: Some(json!({"type":"Point","coordinates":[100.13,13.13]})),
                },
                SpatialSeedRow {
                    record_id: PAGE_D,
                    jurisdiction,
                    code: "page-d",
                    label: "Page D",
                    location: Some(json!({"type":"Point","coordinates":[100.14,13.14]})),
                },
                SpatialSeedRow {
                    record_id: PAGE_E,
                    jurisdiction,
                    code: "page-e",
                    label: "Page E",
                    location: Some(json!({"type":"Point","coordinates":[100.15,13.15]})),
                },
                SpatialSeedRow {
                    record_id: MALFORMED_ACQUIRED,
                    jurisdiction,
                    code: "malformed",
                    label: "Malformed acquired",
                    location: Some(json!({"type":"Point","coordinates":[100.16,13.16]})),
                },
            ] {
                insert_spatial_row(transaction.transaction_for_test(), &harness.compiled, row)
                    .await;
            }
            insert_spatial_row(
                transaction.transaction_for_test(),
                &harness.compiled,
                SpatialSeedRow {
                    record_id: TOMBSTONED_INSIDE,
                    jurisdiction,
                    code: "tombstoned",
                    label: "Tombstoned inside bbox",
                    location: Some(json!({"type":"Point","coordinates":[100.3,13.3]})),
                },
            )
            .await;
        } else {
            insert_spatial_row(
                transaction.transaction_for_test(),
                &harness.compiled,
                SpatialSeedRow {
                    record_id: OTHER_ROW_BOUNDARY,
                    jurisdiction,
                    code: "other-row-boundary",
                    label: "Other row boundary",
                    location: Some(json!({"type":"Point","coordinates":[100.5,13.5]})),
                },
            )
            .await;
        }
        transaction
            .commit()
            .await
            .expect("seed transaction commits through the guarded context");
    }
    mark_spatial_row_tombstoned(harness, TOMBSTONED_INSIDE).await;
    seed_spatial_dependency_rows(harness).await;
}

async fn seed_spatial_budget_rows(harness: &SpatialHarness) {
    let mut client = harness
        .pool
        .get_for_test()
        .await
        .expect("runtime connection is available");
    let claims = seed_claims(&harness.compiled, "zone-a");
    let transaction = begin_record_transaction(
        &mut client,
        harness.lock_key,
        Duration::from_secs(2),
        &harness.identity,
        &claims,
    )
    .await
    .expect("budget seed transaction installs RLS-safe context");
    for row in [
        SpatialSeedRow {
            record_id: BUDGET_A,
            jurisdiction: "zone-a",
            code: "budget-a",
            label: "Budget A",
            location: Some(json!({"type":"Point","coordinates":[102.0,20.0]})),
        },
        SpatialSeedRow {
            record_id: BUDGET_B,
            jurisdiction: "zone-a",
            code: "budget-b",
            label: "Budget B",
            location: Some(json!({"type":"Point","coordinates":[102.1,20.1]})),
        },
    ] {
        insert_spatial_row(transaction.transaction_for_test(), &harness.compiled, row).await;
    }
    transaction
        .commit()
        .await
        .expect("budget seed transaction commits through the guarded context");

    set_large_spatial_notes(harness, &[BUDGET_A, BUDGET_B]).await;
}

async fn insert_spatial_row(
    transaction: &Transaction<'_>,
    registry: &registry_server::CompiledRegistry,
    row: SpatialSeedRow<'_>,
) {
    let entity = &registry.entities()["service-site"];
    let table = quote_identifier(&entity.physical_table);
    let jurisdiction = quote_identifier(&entity.fields["jurisdiction"].physical_name);
    let code = quote_identifier(&entity.fields["code"].physical_name);
    let label = quote_identifier(&entity.fields["label"].physical_name);
    let secret = quote_identifier(&entity.fields["secret"].physical_name);
    let location = quote_identifier(&entity.fields["location"].physical_name);
    transaction
        .execute(
            &format!(
                "INSERT INTO registry_data.{table}
                     (record_id, record_revision, record_lifecycle,
                      {jurisdiction}, {code}, {label}, {secret}, {location})
                 VALUES ($1::text::uuid, 1, 'active', $2, $3, $4, $5, $6::jsonb)"
            ),
            &[
                &row.record_id,
                &row.jurisdiction,
                &row.code,
                &row.label,
                &format!("{SECRET_CANARY}-{}", row.code),
                &row.location,
            ],
        )
        .await
        .expect("RLS-safe spatial row is accepted");
}

async fn seed_spatial_dependency_rows(harness: &SpatialHarness) {
    for (jurisdiction, zone_id, zone_label, region_id, region_label, region_location) in [
        (
            "zone-a",
            SERVICE_ZONE_A,
            "Authorized Zone A",
            SERVICE_REGION_A,
            "Remote Zone A Region",
            json!({"type":"Point","coordinates":[120.0,30.0]}),
        ),
        (
            "zone-b",
            SERVICE_ZONE_B,
            "Authorized Zone B",
            SERVICE_REGION_B,
            "Remote Zone B Region",
            json!({"type":"Point","coordinates":[100.5,13.5]}),
        ),
    ] {
        let mut client = harness
            .pool
            .get_for_test()
            .await
            .expect("runtime connection is available");
        let zone_claims = seed_entity_claims(
            &harness.compiled,
            "service-zone",
            "jurisdiction",
            jurisdiction,
        );
        let transaction = begin_record_transaction(
            &mut client,
            harness.lock_key,
            Duration::from_secs(2),
            &harness.identity,
            &zone_claims,
        )
        .await
        .expect("zone seed transaction installs RLS-safe context");
        insert_service_zone_row(
            transaction.transaction_for_test(),
            &harness.compiled,
            zone_id,
            jurisdiction,
            zone_label,
        )
        .await;
        transaction
            .commit()
            .await
            .expect("zone seed transaction commits through the guarded context");

        let mut client = harness
            .pool
            .get_for_test()
            .await
            .expect("runtime connection is available");
        let region_claims = seed_entity_claims(
            &harness.compiled,
            "service-region",
            "jurisdiction",
            jurisdiction,
        );
        let transaction = begin_record_transaction(
            &mut client,
            harness.lock_key,
            Duration::from_secs(2),
            &harness.identity,
            &region_claims,
        )
        .await
        .expect("region seed transaction installs RLS-safe context");
        insert_service_region_row(
            transaction.transaction_for_test(),
            &harness.compiled,
            region_id,
            jurisdiction,
            region_label,
            region_location,
        )
        .await;
        transaction
            .commit()
            .await
            .expect("region seed transaction commits through the guarded context");
    }
}

async fn insert_service_zone_row(
    transaction: &Transaction<'_>,
    registry: &registry_server::CompiledRegistry,
    record_id: &str,
    zone_code: &str,
    zone_label_value: &str,
) {
    let entity = &registry.entities()["service-zone"];
    let table = quote_identifier(&entity.physical_table);
    let jurisdiction_column = quote_identifier(&entity.fields["jurisdiction"].physical_name);
    let zone_label_column = quote_identifier(&entity.fields["zone-label"].physical_name);
    transaction
        .execute(
            &format!(
                "INSERT INTO registry_data.{table}
                     (record_id, record_revision, record_lifecycle,
                      {jurisdiction_column}, {zone_label_column})
                 VALUES ($1::text::uuid, 1, 'active', $2, $3)"
            ),
            &[&record_id, &zone_code, &zone_label_value],
        )
        .await
        .expect("RLS-safe zone row is accepted");
}

async fn insert_service_region_row(
    transaction: &Transaction<'_>,
    registry: &registry_server::CompiledRegistry,
    record_id: &str,
    jurisdiction_value: &str,
    region_label_value: &str,
    region_location_value: Value,
) {
    let entity = &registry.entities()["service-region"];
    let table = quote_identifier(&entity.physical_table);
    let jurisdiction = quote_identifier(&entity.fields["jurisdiction"].physical_name);
    let region_label = quote_identifier(&entity.fields["region-label"].physical_name);
    let region_location = quote_identifier(&entity.fields["region-location"].physical_name);
    transaction
        .execute(
            &format!(
                "INSERT INTO registry_data.{table}
                     (record_id, record_revision, record_lifecycle,
                      {jurisdiction}, {region_label}, {region_location})
                 VALUES ($1::text::uuid, 1, 'active', $2, $3, $4::jsonb)"
            ),
            &[
                &record_id,
                &jurisdiction_value,
                &region_label_value,
                &region_location_value,
            ],
        )
        .await
        .expect("RLS-safe region row is accepted");
}

async fn set_large_spatial_notes(harness: &SpatialHarness, record_ids: &[&str]) {
    let entity = &harness.compiled.entities()["service-site"];
    let table = quote_identifier(&entity.physical_table);
    let notes = quote_identifier(&entity.fields["notes"].physical_name);
    let large_note = "x".repeat(LARGE_NOTE_BYTES);
    for record_id in record_ids {
        harness
            .database
            .admin
            .execute(
                &format!(
                    "UPDATE registry_data.{table}
                        SET {notes} = $2
                      WHERE record_id = $1::text::uuid"
                ),
                &[record_id, &large_note],
            )
            .await
            .expect("test installs valid large text below the compiled field bound");
    }
}

struct SpatialSeedRow<'a> {
    record_id: &'a str,
    jurisdiction: &'a str,
    code: &'a str,
    label: &'a str,
    location: Option<Value>,
}

async fn mark_spatial_row_tombstoned(harness: &SpatialHarness, record_id: &str) {
    let entity = &harness.compiled.entities()["service-site"];
    let table = quote_identifier(&entity.physical_table);
    harness
        .database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.{table}
                    SET record_lifecycle = 'tombstoned'
                  WHERE record_id = $1::text::uuid"
            ),
            &[&record_id],
        )
        .await
        .expect("test marks one seeded row tombstoned after runtime insert validation");
}

async fn seed_plain_row(
    database: &TestDatabase,
    pool: &RuntimePool,
    lock_key: RegistryLockKey,
    identity: &registry_server::postgres::ExpectedRegistryIdentity,
    registry: &registry_server::CompiledRegistry,
) {
    let mut client = pool
        .get_for_test()
        .await
        .expect("runtime connection is available");
    let claims = ClaimContext::for_compiled(
        registry,
        "plain-site",
        Some(PRINCIPAL_CANARY.to_owned()),
        "plain-reader",
        None,
        Vec::new(),
    )
    .expect("plain seed claims compile");
    let transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(2),
        identity,
        &claims,
    )
    .await
    .expect("plain seed transaction installs context");
    let entity = &registry.entities()["plain-site"];
    let table = quote_identifier(&entity.physical_table);
    let code = quote_identifier(&entity.fields["code"].physical_name);
    let location = quote_identifier(&entity.fields["location"].physical_name);
    transaction
        .transaction_for_test()
        .execute(
            &format!(
                "INSERT INTO registry_data.{table}
                     (record_id, record_revision, record_lifecycle, {code}, {location})
                 VALUES ($1::text::uuid, 1, 'active', 'plain',
                         '{{\"type\":\"Point\",\"coordinates\":[100.5,13.5]}}'::jsonb)"
            ),
            &[&PLAIN_POINT],
        )
        .await
        .expect("plain Point row is accepted without PostGIS");
    transaction.commit().await.expect("plain seed commits");
    assert!(
        database
            .admin
            .query_opt(
                "SELECT 1 FROM pg_catalog.pg_extension WHERE extname = 'postgis'",
                &[]
            )
            .await
            .expect("admin can inspect extensions")
            .is_none(),
        "plain GeoJSON fixture did not install PostGIS"
    );
}

async fn corrupt_point_after_storage_validation(harness: &SpatialHarness, record_id: &str) {
    let entity = &harness.compiled.entities()["service-site"];
    let table = quote_identifier(&entity.physical_table);
    let location = quote_identifier(&entity.fields["location"].physical_name);
    let location_physical = &entity.fields["location"].physical_name;
    let constraints = harness
        .database
        .admin
        .query(
            "SELECT conname
               FROM pg_catalog.pg_constraint
              WHERE conrelid = to_regclass($1)
                AND contype = 'c'
                AND pg_get_constraintdef(oid) LIKE $2",
            &[
                &format!("registry_data.{table}"),
                &format!("%{location_physical}%"),
            ],
        )
        .await
        .expect("admin can inspect check constraints");
    assert!(
        !constraints.is_empty(),
        "location storage validation constraint is present before corruption"
    );
    for row in constraints {
        let name: String = row.get(0);
        harness
            .database
            .admin
            .batch_execute(&format!(
                "ALTER TABLE registry_data.{table} DROP CONSTRAINT {}",
                quote_identifier(&name)
            ))
            .await
            .expect("test corruption removes only the isolated location check");
    }
    harness
        .database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.{table}
                    SET {location} = '{{\"type\":\"Point\",\"coordinates\":[100.16,13.16],\"extra\":\"must-fail\"}}'::jsonb
                  WHERE record_id = $1::text::uuid"
            ),
            &[&record_id],
        )
        .await
        .expect("test can corrupt one acquired row after storage validation");
}

async fn assert_spatial_candidate_context_resets_after_statement_timeout(harness: &SpatialHarness) {
    assert_runtime_cannot_set_bbox_role(harness).await;
    let mut client = harness
        .pool
        .get_for_test()
        .await
        .expect("runtime connection is available");
    let claims = seed_claims(&harness.compiled, "zone-a");
    let transaction = begin_record_transaction(
        &mut client,
        harness.lock_key,
        Duration::from_secs(2),
        &harness.identity,
        &claims,
    )
    .await
    .expect("timeout transaction installs context");
    install_bbox_context_for_test(transaction.transaction_for_test(), "100", "13", "101", "14")
        .await;
    let candidate_view = spatial_candidate_view_for_test(&harness.compiled, "service-site");
    let candidate_ids = transaction
        .transaction_for_test()
        .query(
            &format!(
                "SELECT id::text
                   FROM registry_context.{candidate_view}
                  ORDER BY id
                  LIMIT 1"
            ),
            &[],
        )
        .await
        .expect("runtime can select the actual ID-only spatial candidate view");
    assert_eq!(
        candidate_ids[0].get::<_, String>(0),
        EDGE_WEST,
        "candidate view exposes only root candidate IDs before ordinary derived joins"
    );
    transaction
        .transaction_for_test()
        .batch_execute("SET LOCAL statement_timeout = '1ms'")
        .await
        .expect("test can set a local timeout");
    transaction
        .transaction_for_test()
        .query("SELECT pg_sleep(1)", &[])
        .await
        .expect_err("statement timeout cancels the in-flight transaction");
    transaction
        .rollback()
        .await
        .expect("cancelled transaction rolls back");
}

async fn install_bbox_context_for_test(
    transaction: &Transaction<'_>,
    west: &str,
    south: &str,
    east: &str,
    north: &str,
) {
    transaction
        .execute(
            "SELECT set_config('registry.bbox_west', $1, true),
                    set_config('registry.bbox_south', $2, true),
                    set_config('registry.bbox_east', $3, true),
                    set_config('registry.bbox_north', $4, true)",
            &[&west, &south, &east, &north],
        )
        .await
        .expect("test installs bbox context");
}

async fn assert_runtime_cannot_set_bbox_role(harness: &SpatialHarness) {
    let client = harness
        .pool
        .get_for_test()
        .await
        .expect("runtime connection is available");
    let role = spatial_bbox_role(&harness.database.runtime_role);
    client
        .batch_execute(&format!("SET ROLE {}", quote_identifier(role.as_str())))
        .await
        .expect_err("runtime role cannot directly assume the governed bbox role");
}

fn spatial_candidate_view_for_test(
    registry: &registry_server::CompiledRegistry,
    entity_id: &str,
) -> String {
    registry
        .ddl()
        .views
        .iter()
        .find(|view| view.id == format!("entity.{entity_id}.spatial-candidates"))
        .map(|view| quote_identifier(&view.name))
        .expect("compiled spatial fixture exposes a candidate view")
}

async fn assert_pool_context_clean(
    pool: &RuntimePool,
    runtime_role: &registry_server::postgres::SqlIdentifier,
) {
    let client = pool
        .get_for_test()
        .await
        .expect("runtime connection is available");
    let row = client
        .query_one(
            "SELECT current_user,
                    current_role,
                    NULLIF(current_setting('registry.bbox_west', true), ''),
                    NULLIF(current_setting('registry.bbox_south', true), ''),
                    NULLIF(current_setting('registry.bbox_east', true), ''),
                    NULLIF(current_setting('registry.bbox_north', true), '')",
            &[],
        )
        .await
        .expect("runtime connection can inspect local context");
    assert_eq!(row.get::<_, String>(0), runtime_role.as_str());
    assert_eq!(row.get::<_, String>(1), runtime_role.as_str());
    for index in 2..=5 {
        assert_eq!(row.get::<_, Option<String>>(index), None);
    }
}

async fn cleanup_spatial_role(database: &TestDatabase) {
    let bbox_role = spatial_bbox_role(&database.runtime_role);
    database
        .admin
        .batch_execute(&format!(
            "REVOKE {} FROM {};
             DROP OWNED BY {};
             DROP ROLE {};",
            quote_identifier(bbox_role.as_str()),
            quote_identifier(database.runtime_role.as_str()),
            quote_identifier(bbox_role.as_str()),
            quote_identifier(bbox_role.as_str())
        ))
        .await
        .expect("spatial bbox role is removed before ordinary test cleanup");
}

fn seed_claims(registry: &registry_server::CompiledRegistry, jurisdiction: &str) -> ClaimContext {
    seed_entity_claims(registry, "service-site", "jurisdiction", jurisdiction)
}

fn seed_entity_claims(
    registry: &registry_server::CompiledRegistry,
    entity_id: &str,
    boundary_field: &str,
    jurisdiction: &str,
) -> ClaimContext {
    ClaimContext::for_compiled(
        registry,
        entity_id,
        Some(PRINCIPAL_CANARY.to_owned()),
        "map-reader",
        Some("case-management".to_owned()),
        vec![RowBoundaryContext::In {
            field: boundary_field.to_owned(),
            values: BTreeSet::from([jurisdiction.to_owned()]),
        }],
    )
    .expect("seed claims are compiler-bound")
}

fn claims<const N: usize>(jurisdictions: [&str; N]) -> VerifiedRequestClaims {
    claims_with(PRINCIPAL_CANARY, "case-management", jurisdictions)
}

fn claims_with<const N: usize>(
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

fn claims_without_scope() -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        PRINCIPAL_CANARY,
        BTreeSet::new(),
        Some("case-management".to_owned()),
        BTreeMap::from([(
            "jurisdictions".to_owned(),
            VerifiedClaimValue::direct_string_set(["zone-a"])
                .expect("jurisdictions are direct verified strings"),
        )]),
    )
    .expect("read claims are verified")
}

fn claims_with_purpose(purpose: &str) -> VerifiedRequestClaims {
    claims_with(PRINCIPAL_CANARY, purpose, ["zone-a"])
}

fn claims_without_row_boundary() -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        PRINCIPAL_CANARY,
        BTreeSet::from(["registry.read".to_owned()]),
        Some("case-management".to_owned()),
        BTreeMap::new(),
    )
    .expect("read claims are verified")
}

fn plain_claims() -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        PRINCIPAL_CANARY,
        BTreeSet::from(["registry.read".to_owned()]),
        None,
        BTreeMap::new(),
    )
    .expect("plain read claims are verified")
}

fn cursor_codec() -> Arc<CursorCodec> {
    Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x64; 32]), Duration::from_secs(300))
            .expect("test cursor key is valid"),
    )
}

fn immediately_expiring_cursor_codec() -> Arc<CursorCodec> {
    Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x65; 32]), Duration::from_nanos(1))
            .expect("subsecond max age creates deterministic expired test cursors"),
    )
}

async fn audit_count(database: &TestDatabase) -> i64 {
    database
        .admin
        .query_one("SELECT count(*) FROM registry_internal.registry_audit", &[])
        .await
        .expect("administrator can inspect audit count")
        .get(0)
}

async fn assert_spatial_audit_is_minimized(database: &TestDatabase, profile: &AuditProfile) {
    let records = ordered_audit_records(database, profile).await;
    assert!(
        records.iter().any(|record| {
            record["phase"] == "attempt" && record["operationId"] == "records.service-site.list"
        }),
        "spatial reads record durable attempts"
    );
    assert!(
        records.iter().any(|record| {
            record["phase"] == "terminal"
                && record["operationId"] == "records.service-site.list"
                && record["outcome"] == "returned"
                && record["resultCount"] == 10
                && record.get("queryReference").is_some()
                && record.get("rowBoundaryReference").is_some()
                && record.get("fieldSetReference").is_some()
        }),
        "spatial terminal audit records profile, row, query, count and field references"
    );
    let text = records
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    for canary in [
        PRINCIPAL_CANARY,
        SECRET_CANARY,
        EDGE_WEST,
        INTERIOR,
        EDGE_NORTH_EAST,
        JUST_OUTSIDE,
        NULL_GEOMETRY,
        OTHER_ROW_BOUNDARY,
        TOMBSTONED_INSIDE,
        EXACT_DECIMAL_POINT,
        BUDGET_A,
        BUDGET_B,
        "zone-a",
        "zone-b",
        "edge-west",
        "location",
        "notes",
        "rs_spgeom_",
    ] {
        assert!(!text.contains(canary), "audit leaked {canary}");
    }
}

async fn ordered_audit_records(database: &TestDatabase, profile: &AuditProfile) -> Vec<Value> {
    ordered_audit_envelopes(database, profile)
        .await
        .into_iter()
        .map(|envelope| envelope.record)
        .collect()
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

fn compiled_spatial_registry() -> registry_server::CompiledRegistry {
    let module = parse_module_json(spatial_registry_module_source().as_bytes())
        .expect("spatial fixture module parses");
    let assets = vec![
        spatial_module_asset("sql/map-label.sql", spatial_map_label_sql()),
        spatial_module_asset("sql/zone-site-count.sql", spatial_zone_site_count_sql()),
        spatial_module_asset("sql/zone-label.sql", spatial_zone_label_sql()),
        spatial_module_asset("sql/region-label.sql", spatial_region_label_sql()),
    ];
    let digest = module_digest_with_assets(&module, &assets);
    let project_source = spatial_registry_project_source(&digest);
    let project = parse_project_json(project_source.as_bytes()).expect("spatial fixture parses");
    compile_project_with_assets(&project, &[module], &assets, CompileProfile::Authoring)
        .expect("spatial fixture compiles to trusted inventories")
}

fn spatial_module_asset(path: &str, sql: &str) -> ModuleAssetSource {
    ModuleAssetSource {
        module: Some("core".to_owned()),
        path: path.to_owned(),
        bytes: sql.as_bytes().to_vec(),
    }
}

fn compiled_plain_geojson_registry() -> registry_server::CompiledRegistry {
    compile_registry_source(plain_geojson_registry_source())
}

fn compile_registry_source(source: &str) -> registry_server::CompiledRegistry {
    let project = parse_project_json(source.as_bytes()).expect("spatial fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("spatial fixture compiles to trusted inventories")
}

fn spatial_registry_project_source(module_digest: &str) -> String {
    format!(
        r#"{{
      "apiVersion":"registry.registrystack.org/v1alpha1",
      "kind":"RegistryProject",
      "registry":{{"id":"spatial-read-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"}},
      "modules":[{{"id":"core","version":"1","digest":"{module_digest}"}}]
    }}"#
    )
}

fn spatial_registry_module_source() -> &'static str {
    r#"{
      "id":"core",
      "version":"1",
      "entities":[{
        "id":"service-site",
        "route":"service-sites",
        "mutationMode":"mutable",
        "tombstone":true,
        "classification":"internal",
        "fields":[
          {"id":"jurisdiction","type":"string","required":true,"maxLength":32,"classification":"internal"},
          {"id":"code","type":"string","required":true,"maxLength":64,"classification":"internal"},
          {"id":"label","type":"string","required":true,"maxLength":160,"classification":"internal"},
          {"id":"notes","type":"text","maxLength":1500000,"classification":"internal"},
          {"id":"secret","type":"string","required":true,"maxLength":160,"classification":"restricted"},
          {"id":"location","type":"crs84-point","precision":6,"classification":"internal"}
        ],
        "derived":[{
          "id":"map-label",
          "sql":"sql/map-label.sql",
          "key":"id",
          "fields":[{"id":"map-label","type":"string","maxLength":192,"classification":"internal"}]
        },{
          "id":"zone-site-count",
          "sql":"sql/zone-site-count.sql",
          "key":"id",
          "fields":[{"id":"zone-site-count","type":"int64","classification":"internal"}]
        },{
          "id":"zone-label",
          "sql":"sql/zone-label.sql",
          "key":"id",
          "fields":[{"id":"zone-label","type":"string","maxLength":96,"classification":"internal"}]
        },{
          "id":"region-label",
          "sql":"sql/region-label.sql",
          "key":"id",
          "fields":[{"id":"region-label","type":"string","maxLength":96,"classification":"internal"}]
        }],
        "geojson":{"geometryField":"location"},
        "accessProfiles":[{
          "id":"map-reader",
          "default":true,
          "principalClaim":"registry_principal",
          "requiredScopes":["registry.read"],
          "requiredPurposes":["case-management"],
          "operations":["create","get","list"],
          "readableFields":["code","label","location","map-label","zone-site-count","zone-label","region-label"],
          "writableFields":["jurisdiction","code","label","secret","location"],
          "filterableFields":["code","map-label"],
          "sortableFields":["map-label"],
          "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdictions","operator":"in"}],
          "spatialQueries":{"bbox":{"maximumLongitudeSpanDegrees":1.25,"maximumLatitudeSpanDegrees":1.25}}
        },{
          "id":"notes-reader",
          "principalClaim":"registry_principal",
          "requiredScopes":["registry.read"],
          "requiredPurposes":["case-management"],
          "operations":["list"],
          "readableFields":["code","label","location","notes"],
          "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdictions","operator":"in"}],
          "spatialQueries":{"bbox":{"maximumLongitudeSpanDegrees":1.25,"maximumLatitudeSpanDegrees":1.25}}
        },{
          "id":"count-reader",
          "principalClaim":"registry_principal",
          "requiredScopes":["registry.read"],
          "requiredPurposes":["case-management"],
          "operations":["list"],
          "readableFields":["code","label","location"],
          "filterableFields":["code"],
          "allowCount":true,
          "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdictions","operator":"in"}],
          "spatialQueries":{"bbox":{"maximumLongitudeSpanDegrees":1.25,"maximumLatitudeSpanDegrees":1.25}}
        },{
          "id":"no-bbox",
          "principalClaim":"registry_principal",
          "requiredScopes":["registry.read"],
          "requiredPurposes":["case-management"],
          "operations":["list"],
          "readableFields":["code","label","location"],
          "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdictions","operator":"in"}]
        },{
          "id":"get-only",
          "principalClaim":"registry_principal",
          "requiredScopes":["registry.read"],
          "requiredPurposes":["case-management"],
          "operations":["get"],
          "readableFields":["code","label","location"],
          "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdictions","operator":"in"}]
        }]
      },{
        "id":"service-zone",
        "route":"service-zones",
        "mutationMode":"mutable",
        "classification":"internal",
        "fields":[
          {"id":"jurisdiction","type":"string","required":true,"maxLength":32,"classification":"internal"},
          {"id":"zone-label","type":"string","required":true,"maxLength":96,"classification":"internal"}
        ],
        "accessProfiles":[{
          "id":"map-reader",
          "default":true,
          "principalClaim":"registry_principal",
          "requiredScopes":["registry.read"],
          "requiredPurposes":["case-management"],
          "operations":["create","get","list"],
          "readableFields":["jurisdiction","zone-label"],
          "writableFields":["jurisdiction","zone-label"],
          "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdictions","operator":"in"}]
        }]
      },{
        "id":"service-region",
        "route":"service-regions",
        "mutationMode":"mutable",
        "classification":"internal",
        "fields":[
          {"id":"jurisdiction","type":"string","required":true,"maxLength":32,"classification":"internal"},
          {"id":"region-label","type":"string","required":true,"maxLength":96,"classification":"internal"},
          {"id":"region-location","type":"crs84-point","precision":6,"classification":"internal"}
        ],
        "geojson":{"geometryField":"region-location"},
        "accessProfiles":[{
          "id":"map-reader",
          "default":true,
          "principalClaim":"registry_principal",
          "requiredScopes":["registry.read"],
          "requiredPurposes":["case-management"],
          "operations":["create","get","list"],
          "readableFields":["jurisdiction","region-label","region-location"],
          "writableFields":["jurisdiction","region-label","region-location"],
          "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdictions","operator":"in"}],
          "spatialQueries":{"bbox":{"maximumLongitudeSpanDegrees":1.25,"maximumLatitudeSpanDegrees":1.25}}
        }]
      }]
    }"#
}

fn spatial_map_label_sql() -> &'static str {
    "SELECT site.id AS id,
            site.code AS map_label
       FROM registry_source.service_site AS site"
}

fn spatial_zone_site_count_sql() -> &'static str {
    "WITH authorized_zone_counts AS (
         SELECT site.jurisdiction AS jurisdiction,
                count(*) AS zone_site_count
           FROM registry_source.service_site AS site
          GROUP BY site.jurisdiction
     )
     SELECT site.id AS id,
            authorized_zone_counts.zone_site_count AS zone_site_count
       FROM registry_source.service_site AS site
       JOIN authorized_zone_counts
         ON authorized_zone_counts.jurisdiction = site.jurisdiction"
}

fn spatial_zone_label_sql() -> &'static str {
    "SELECT site.id AS id,
            zone.zone_label AS zone_label
       FROM registry_source.service_site AS site
       JOIN registry_source.service_zone AS zone
         ON zone.jurisdiction = site.jurisdiction"
}

fn spatial_region_label_sql() -> &'static str {
    "SELECT site.id AS id,
            region.region_label AS region_label
       FROM registry_source.service_site AS site
       JOIN registry_source.service_region AS region
         ON region.jurisdiction = site.jurisdiction"
}

fn plain_geojson_registry_source() -> &'static str {
    r#"{
      "apiVersion":"registry.registrystack.org/v1alpha1",
      "kind":"RegistryProject",
      "registry":{"id":"plain-geojson-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
      "entities":[{
        "id":"plain-site",
        "route":"plain-sites",
        "mutationMode":"mutable",
        "classification":"internal",
        "fields":[
          {"id":"code","type":"string","required":true,"maxLength":64,"classification":"internal"},
          {"id":"location","type":"crs84-point","precision":6,"classification":"internal"}
        ],
        "geojson":{"geometryField":"location"}
      }],
      "accessProfiles":[{
        "id":"plain-reader",
        "default":true,
        "principalClaim":"registry_principal",
        "requiredScopes":["registry.read"],
        "grants":[{
          "entity":"plain-site",
          "operations":["create","get","list"],
          "readableFields":["code","location"],
          "writableFields":["code","location"]
        }]
      }]
    }"#
}
