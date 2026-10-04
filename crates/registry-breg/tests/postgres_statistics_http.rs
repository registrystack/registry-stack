// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{HeaderName, Method, Request, Response, StatusCode};
use chrono::{Datelike, Days, NaiveDate, Utc};
use postgres_harness::TestDatabase;
use registry_breg::api::{
    router, set_request_deadline_for_test, HttpService, ReadRuntimeIdentity, ReadinessProbe,
    ServiceFuture, VerifiedClaimValue, VerifiedRequestClaims,
};
use registry_breg::audit::RegistryAudit;
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::cursor::CursorCodec;
use registry_breg::mutation::install_mutation_schema;
use registry_breg::postgres::{
    begin_record_transaction, initialize_compiled_registry_state_for_test, install_compiled_schema,
    verify_catalog_identity_for_catalog, ClaimContext, ExpectedManagedCatalog,
    PostgresRecordReadService, PostgresStatisticsService, RegistryLockKey,
    RegistryStateTestIdentity, StatisticsPublishPause, StatisticsWithdrawalPause,
};
use registry_platform_audit::AuditProfile;
use serde_json::{json, Value};
use tower::Service as _;
use zeroize::Zeroizing;

const PACKAGE_ID: &str = "statistics-http-registry";
const DATABASE_ID: &str = "statistics-http-database";
const PRINCIPAL_CANARY: &str = "statistics-principal-must-not-enter-audit";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn predecessor_catalog_refuses_statistics_until_the_next_normal_schema_apply() {
    let database = TestDatabase::create(2).await;
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("compiled schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "package-statistics-upgrade-1",
        },
    )
    .await
    .expect("runtime identity initializes");
    let catalog = ExpectedManagedCatalog::compiled(&compiled);

    migration
        .batch_execute(
            "DROP FUNCTION registry_internal.withdraw_statistical_release(text, text, bigint, text);
             DROP TABLE registry_internal.registry_statistical_release_contents;
             DROP TABLE registry_internal.registry_statistical_release_withdrawals;
             DROP TABLE registry_internal.registry_statistical_release_versions;",
        )
        .await
        .expect("fixture restores the predecessor catalog without release storage");
    assert!(
        verify_catalog_identity_for_catalog(
            &migration,
            &identity,
            &catalog,
            &database.migration_role,
            &database.runtime_role,
        )
        .await
        .is_err(),
        "startup must reject an activated package whose managed release catalog is absent"
    );

    install_mutation_schema(&migration, &database.runtime_role)
        .await
        .expect("the ordinary next engine schema apply installs release storage");
    verify_catalog_identity_for_catalog(
        &migration,
        &identity,
        &catalog,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .expect("the same activated package passes exact catalog verification after apply");
    migration_task.abort();

    let pool = database.runtime_config.build_pool().expect("pool builds");
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives");
    let today = Utc::now().date_naive();
    let app = statistics_router(
        pool,
        compiled,
        identity,
        lock_key,
        database.audit(
            AuditProfile::production_from_secret_bytes(vec![0x71; 32].into())
                .expect("audit profile is keyed"),
        ),
        Arc::new(std::sync::Mutex::new(Vec::new())),
        None,
    );
    let live = send(
        &app,
        Method::GET,
        &format!(
            "/v1/statistics/records-by-category:live?accessProfile=analyst&from={0}&to={0}",
            month_code(today)
        ),
        Some(claims("analyst", true)),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(live.status(), StatusCode::OK);
    assert_eq!(total_cell(&body_json(live).await, &month_code(today)), 0);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn statistical_http_full_journey_preserves_visibility_release_and_withdrawal_rules() {
    let database = TestDatabase::create(4).await;
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("compiled schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "package-statistics-http-1",
        },
    )
    .await
    .expect("runtime identity and empty history baseline initialize");
    migration_task.abort();

    let pool = database.runtime_config.build_pool().expect("pool builds");
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives");
    let today = Utc::now().date_naive();
    let current_period = month_code(today);
    let prior_date = today
        .with_day(1)
        .expect("current month has a first day")
        .checked_sub_days(Days::new(1))
        .expect("previous month exists");
    let prior_period = month_code(prior_date);
    seed_records(&pool, lock_key, &identity, &compiled, today, prior_date).await;

    let audit = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x72; 32].into())
            .expect("audit profile is keyed"),
    );
    let trace = Arc::new(std::sync::Mutex::new(Vec::new()));
    let app = statistics_router(
        pool.clone(),
        compiled.clone(),
        identity.clone(),
        lock_key,
        audit,
        trace.clone(),
        None,
    );

    // Anonymous concealment must not depend on the authenticated refusal journal.
    let before_anonymous = database.audit_records().len();
    for faulted in [false, true] {
        if faulted {
            database
                .audit_capture()
                .fail_on(registry_breg::audit::AUDIT_SCHEMA, "refusal");
        }
        for path in [
            "/v1/statistics/records-by-category:live",
            "/v1/statistics/unknown-id-canary:live",
            "/v1/statistics/unknown/route/garbage",
        ] {
            let anonymous = send(&app, Method::GET, path, None, &[], Vec::new()).await;
            assert_eq!(anonymous.status(), StatusCode::NOT_FOUND, "{path}");
        }
        assert_eq!(database.audit_records().len(), before_anonymous);
        assert!(
            trace.lock().unwrap().is_empty(),
            "anonymous refusal performs no database work"
        );
    }
    database.audit_capture().restore();
    for (method, audited_method) in [
        (Method::POST, "POST"),
        (Method::GET, "GET"),
        (Method::PATCH, "PATCH"),
        (Method::DELETE, "DELETE"),
        (Method::PUT, "PUT"),
        (Method::OPTIONS, "OPTIONS"),
        (Method::HEAD, "HEAD"),
        (Method::from_bytes(b"METHOD-CANARY").unwrap(), "OTHER"),
    ] {
        for path in [
            "/v1/statistics/unknown-id-canary:live",
            "/v1/statistics/unknown/route/garbage",
        ] {
            let before = database.audit_records().len();
            let unknown = send(
                &app,
                method.clone(),
                path,
                Some(claims("reader", false)),
                &[],
                Vec::new(),
            )
            .await;
            assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
            let records = database.audit_records();
            assert_eq!(
                records.len(),
                before + 1,
                "authenticated unknown routes are journaled"
            );
            let refusal = records.last().unwrap();
            assert_eq!(refusal["phase"], "refusal");
            assert_eq!(refusal["method"], audited_method);
            assert_eq!(refusal["operationId"], "statistics.unknown");
            assert!(!refusal.to_string().contains("unknown-id-canary"));
            assert!(!refusal.to_string().contains("METHOD-CANARY"));
        }
    }
    let wrong_method = send(
        &app,
        Method::POST,
        "/v1/statistics/records-by-category:live",
        Some(claims("reader", false)),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(wrong_method.status(), StatusCode::NOT_FOUND);
    let records = database.audit_records();
    let refusal = records.last().unwrap();
    assert_eq!(refusal["method"], "POST");
    assert_eq!(refusal["operationId"], "statistics.unknown");

    let analyst = claims("analyst", true);
    let count = send(
        &app,
        Method::GET,
        "/v1/records/records?accessProfile=analyst&$filter=active%20eq%20true&$count=true&$top=1",
        Some(analyst.clone()),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(count.status(), StatusCode::OK);
    let count = body_json(count).await["count"]
        .as_u64()
        .expect("ordinary list returns its authorized count");
    assert_eq!(count, 8, "the row boundary excludes the other jurisdiction");

    let live = send(
        &app,
        Method::GET,
        &format!(
            "/v1/statistics/records-by-category:live?accessProfile=analyst&from={prior_period}&to={current_period}"
        ),
        Some(analyst.clone()),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(live.status(), StatusCode::OK);
    assert!(live.headers().contains_key("repr-digest"));
    let live = body_json(live).await;
    assert_eq!(
        total_cell(&live, &prior_period) + total_cell(&live, &current_period),
        count
    );
    assert_eq!(live["live"]["accessProfile"], "analyst");
    assert!(live.get("disclosure").is_none());

    let wide_live = send(
        &app,
        Method::GET,
        &format!(
            "/v1/statistics/records-by-category:live?accessProfile=analyst-wide&from={prior_period}&to={current_period}"
        ),
        Some(claims("analyst-wide", false)),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(wide_live.status(), StatusCode::OK);
    let wide_live = body_json(wide_live).await;
    assert_eq!(
        total_cell(&wide_live, &prior_period) + total_cell(&wide_live, &current_period),
        10
    );
    // These exact prior-period counts are what a release must never retain.
    assert_eq!(
        category_cells(&wide_live, &prior_period),
        json!([["a", 6, "exact"], ["b", 1, "exact"], ["_T", 7, "exact"]])
    );

    let default_live = send(
        &app,
        Method::GET,
        &format!(
            "/v1/statistics/records-by-category:live?from={current_period}&to={current_period}"
        ),
        Some(analyst.clone()),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(default_live.status(), StatusCode::OK);
    assert_eq!(
        body_json(default_live).await["live"]["accessProfile"],
        "analyst"
    );

    let authorized_bad_query = send(
        &app,
        Method::GET,
        "/v1/statistics/records-by-category:live?accessProfile=analyst&unknown=value",
        Some(analyst.clone()),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(authorized_bad_query.status(), StatusCode::BAD_REQUEST);

    let before_first = send(
        &app,
        Method::GET,
        "/v1/statistics/records-by-category:live?accessProfile=analyst&from=2024-12&to=2024-12",
        Some(analyst.clone()),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(before_first.status(), StatusCode::BAD_REQUEST);

    let reader = claims("reader", false);
    let reader_metadata = send(
        &app,
        Method::GET,
        "/v1/registry?accessProfile=reader",
        Some(reader.clone()),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(reader_metadata.status(), StatusCode::OK);
    let reader_metadata = body_json(reader_metadata).await;
    assert!(reader_metadata["entities"]
        .as_array()
        .is_some_and(Vec::is_empty));
    assert_eq!(
        reader_metadata["statisticalDatasets"][0]["id"],
        "records-by-category"
    );
    assert!(reader_metadata["statisticalDatasets"][0]["operations"]
        .as_array()
        .is_some_and(|operations| operations
            .iter()
            .all(|operation| operation != "read_live" && operation != "publish_release")));
    let reader_openapi = send(
        &app,
        Method::GET,
        "/openapi.json?accessProfile=reader",
        Some(reader.clone()),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(reader_openapi.status(), StatusCode::OK);
    let reader_openapi = body_json(reader_openapi).await;
    assert!(reader_openapi["paths"]
        .get("/v1/statistics/records-by-category:live")
        .is_none());
    assert!(reader_openapi["paths"]
        .get("/v1/statistics/records-by-category/releases")
        .is_some());
    assert!(reader_openapi["paths"]
        ["/v1/statistics/records-by-category/releases/{period}/versions"]
        .get("post")
        .is_none());
    let neither = send(
        &app,
        Method::GET,
        "/v1/registry?accessProfile=seed",
        Some(claims("seed", false)),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(neither.status(), StatusCode::NOT_FOUND);
    let reader_entity = send(
        &app,
        Method::GET,
        "/v1/records/records?accessProfile=reader",
        Some(reader.clone()),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(reader_entity.status(), StatusCode::NOT_FOUND);
    let reader_live = send(
        &app,
        Method::GET,
        "/v1/statistics/records-by-category:live?accessProfile=reader",
        Some(reader.clone()),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(reader_live.status(), StatusCode::NOT_FOUND);
    for uri in [
        "/v1/statistics/records-by-category:live?accessProfile=reader&unknown=value",
        "/v1/statistics/records-by-category:live?accessProfile=reader&from=2026-01&from=2026-02",
    ] {
        let concealed = send(
            &app,
            Method::GET,
            uri,
            Some(reader.clone()),
            &[],
            Vec::new(),
        )
        .await;
        assert_eq!(concealed.status(), StatusCode::NOT_FOUND);
    }

    let publisher = claims("publisher", false);
    let unended = publish(&app, &current_period, "unended", "final", publisher.clone()).await;
    assert_eq!(unended.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body_json(unended).await["refusalCode"], "period-not-ended");

    let before_first_publish =
        publish(&app, "2024-12", "before-first", "final", publisher.clone()).await;
    assert_eq!(
        before_first_publish.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        body_json(before_first_publish).await["refusalCode"],
        "before-first-period"
    );
    let missing_key = send(
        &app,
        Method::POST,
        &format!(
            "/v1/statistics/records-by-category/releases/{prior_period}/versions?accessProfile=publisher"
        ),
        Some(publisher.clone()),
        &[("content-type", "application/json")],
        serde_json::to_vec(&json!({"status":"final"})).expect("publish body serializes"),
    )
    .await;
    assert_eq!(missing_key.status(), StatusCode::BAD_REQUEST);

    let first = publish(
        &app,
        &prior_period,
        "release-one",
        "provisional",
        publisher.clone(),
    )
    .await;
    assert_eq!(
        first.status(),
        StatusCode::CREATED,
        "publication trace: {:?}",
        trace.lock().expect("trace lock")
    );
    assert!(first.headers().contains_key("repr-digest"));
    let first_bytes = body_bytes(first).await;
    let first_header: Value = serde_json::from_slice(&first_bytes).expect("header is JSON");
    assert_eq!(first_header["version"], 1);
    assert_eq!(first_header["status"], "provisional");
    let listing = send(
        &app,
        Method::GET,
        "/v1/statistics/records-by-category/releases?accessProfile=reader",
        Some(reader.clone()),
        &[("accept", "text/csv;q=1,application/json;q=0.5")],
        Vec::new(),
    )
    .await;
    assert_eq!(listing.status(), StatusCode::OK);
    assert_eq!(listing.headers()["content-type"], "application/json");
    assert!(body_json(listing).await["items"].is_array());
    let stored = database.admin.query_one(
        "SELECT h.content_digest, c.document FROM registry_internal.registry_statistical_release_versions h JOIN registry_internal.registry_statistical_release_contents c USING (dataset_id, period_code, release_version) WHERE h.dataset_id = 'records-by-category' AND h.period_code = $1 AND h.release_version = 1",
        &[&prior_period],
    ).await.expect("published canonical bytes are stored");
    let stored_digest: String = stored.get(0);
    let stored_bytes: Vec<u8> = stored.get(1);
    use sha2::{Digest, Sha256};
    assert_eq!(
        stored_digest,
        format!(
            "sha256:{}",
            Sha256::digest(&stored_bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
    );
    assert_eq!(first_header["contentDigest"], stored_digest);
    // The store holds the suppressed and rounded cells, never the exact counts.
    let disclosed_cells = json!([
        ["a", 5, "rounded"],
        ["b", null, "suppressed"],
        ["_T", 5, "rounded"]
    ]);
    let stored_document: Value =
        serde_json::from_slice(&stored_bytes).expect("stored release is JSON");
    assert_eq!(
        category_cells(&stored_document, &prior_period),
        disclosed_cells
    );
    assert_eq!(stored_document["cells"].as_array().map(Vec::len), Some(3));
    let stored_text = std::str::from_utf8(&stored_bytes).expect("stored release is UTF-8");
    for exact_count in [6, 1, 7] {
        assert!(
            !stored_text.contains(&format!("\"value\":{exact_count}")),
            "the stored release retains the exact count {exact_count}"
        );
    }
    let exact = send(&app, Method::GET,
        &format!("/v1/statistics/records-by-category/releases/{prior_period}/versions/1?accessProfile=reader"),
        Some(reader.clone()), &[], Vec::new()).await;
    assert_eq!(exact.status(), StatusCode::OK);
    use base64::Engine as _;
    assert_eq!(
        exact.headers()["repr-digest"],
        format!(
            "sha-256=:{}:",
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&stored_bytes))
        )
    );
    assert_eq!(body_bytes(exact).await, stored_bytes);

    let replay = publish(
        &app,
        &prior_period,
        "release-one",
        "provisional",
        publisher.clone(),
    )
    .await;
    assert_eq!(replay.status(), StatusCode::CREATED);
    assert_eq!(body_bytes(replay).await, first_bytes);
    let conflict = publish(
        &app,
        &prior_period,
        "release-one",
        "final",
        publisher.clone(),
    )
    .await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);

    for profile in ["analyst", "publisher"] {
        for uri in [
            "/v1/statistics/records-by-category/releases".to_owned(),
            format!(
                "/v1/statistics/records-by-category/releases:series?from={prior_period}&to={prior_period}"
            ),
            format!("/v1/statistics/records-by-category/releases/{prior_period}"),
            format!(
                "/v1/statistics/records-by-category/releases/{prior_period}/versions/1"
            ),
        ] {
            let visible = send(
                &app,
                Method::GET,
                &format!("{uri}{}accessProfile={profile}", if uri.contains('?') { "&" } else { "?" }),
                Some(claims(profile, profile == "analyst")),
                &[],
                Vec::new(),
            )
            .await;
            assert_eq!(visible.status(), StatusCode::OK, "{profile} {uri}");
        }
    }

    let latest = send(
        &app,
        Method::GET,
        &format!("/v1/statistics/records-by-category/releases/{prior_period}?accessProfile=reader"),
        Some(reader.clone()),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(latest.status(), StatusCode::OK);
    let latest_json = body_json(latest).await;
    assert_eq!(latest_json["release"]["version"], 1);
    assert!(latest_json.get("live").is_none());
    assert!(latest_json.get("disclosure").is_some());
    assert_eq!(category_cells(&latest_json, &prior_period), disclosed_cells);
    assert_eq!(latest_json["cells"].as_array().map(Vec::len), Some(3));

    let unmatched_accept = send(
        &app,
        Method::GET,
        &format!("/v1/statistics/records-by-category/releases/{prior_period}?accessProfile=reader"),
        Some(reader.clone()),
        &[("accept", "application/xml")],
        Vec::new(),
    )
    .await;
    assert_eq!(unmatched_accept.status(), StatusCode::OK);
    assert_eq!(
        unmatched_accept.headers()["content-type"],
        "application/json"
    );

    let csv = send(
        &app,
        Method::GET,
        &format!("/v1/statistics/records-by-category/releases/{prior_period}?accessProfile=reader"),
        Some(reader.clone()),
        &[("accept", "text/csv")],
        Vec::new(),
    )
    .await;
    assert_eq!(csv.status(), StatusCode::OK);
    assert_eq!(csv.headers()["content-type"], "text/csv; charset=utf-8");
    let csv_text = String::from_utf8(body_bytes(csv).await).expect("CSV is UTF-8");
    assert!(csv_text.starts_with("period,periodStart,periodEnd,category,value,status\r\n"));

    let unauthorized_publish = publish(
        &app,
        &prior_period,
        "reader-cannot-publish",
        "final",
        reader.clone(),
    )
    .await;
    assert_eq!(unauthorized_publish.status(), StatusCode::NOT_FOUND);

    let withdrawn = withdraw(&app, &prior_period, 1, "withdraw-one", publisher.clone()).await;
    assert_eq!(withdrawn.status(), StatusCode::OK);
    let withdrawal_header = body_json(withdrawn).await;
    assert_eq!(
        withdrawal_header["withdrawal"]["reason"],
        "source-data-error"
    );

    let explicit_withdrawn = send(
        &app,
        Method::GET,
        &format!(
            "/v1/statistics/records-by-category/releases/{prior_period}/versions/1?accessProfile=reader"
        ),
        Some(reader.clone()),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(explicit_withdrawn.status(), StatusCode::GONE);
    assert_eq!(
        body_json(explicit_withdrawn).await["reasonCode"],
        "source-data-error"
    );

    let no_latest = send(
        &app,
        Method::GET,
        &format!("/v1/statistics/records-by-category/releases/{prior_period}?accessProfile=reader"),
        Some(reader.clone()),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(no_latest.status(), StatusCode::NOT_FOUND);

    let second = publish(
        &app,
        &prior_period,
        "release-two",
        "final",
        publisher.clone(),
    )
    .await;
    assert_eq!(second.status(), StatusCode::CREATED);
    assert_eq!(body_json(second).await["version"], 2);
    insert_other_definition_release(&database, &prior_period, 2, 3).await;
    let fourth = publish(
        &app,
        &prior_period,
        "release-four",
        "final",
        publisher.clone(),
    )
    .await;
    assert_eq!(fourth.status(), StatusCode::CREATED);
    assert_eq!(body_json(fourth).await["version"], 4);
    let provisional_after_final = publish(
        &app,
        &prior_period,
        "late-provisional",
        "provisional",
        publisher.clone(),
    )
    .await;
    assert_eq!(
        provisional_after_final.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        body_json(provisional_after_final).await["refusalCode"],
        "provisional-after-final"
    );

    let series = send(
        &app,
        Method::GET,
        &format!(
            "/v1/statistics/records-by-category/releases:series?accessProfile=reader&from={prior_period}&to={prior_period}&status=final"
        ),
        Some(reader.clone()),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(series.status(), StatusCode::OK);
    let series = body_json(series).await;
    assert_eq!(series["periods"][0]["version"]["version"], 4);

    let releases = send(
        &app,
        Method::GET,
        "/v1/statistics/records-by-category/releases?accessProfile=reader&$top=1",
        Some(reader),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(releases.status(), StatusCode::OK);
    let releases = body_json(releases).await;
    assert_eq!(
        releases["items"].as_array().expect("release items").len(),
        1
    );
    assert_eq!(releases["items"][0]["version"], 4);
    assert_eq!(releases["pageInfo"]["hasMore"], true);
    let mut cursor = releases["pageInfo"]["nextCursor"]
        .as_str()
        .expect("first page has a continuation")
        .to_owned();

    let inserted_before_cursor = publish(
        &app,
        &prior_period,
        "release-after-first-page",
        "final",
        publisher.clone(),
    )
    .await;
    assert_eq!(inserted_before_cursor.status(), StatusCode::CREATED);
    assert_eq!(body_json(inserted_before_cursor).await["version"], 5);

    let mut existing_after_first_page = Vec::new();
    for expected_version in [2, 1] {
        let page = send(
            &app,
            Method::GET,
            &format!(
                "/v1/statistics/records-by-category/releases?accessProfile=reader&$top=1&$skiptoken={cursor}"
            ),
            Some(claims("reader", false)),
            &[],
            Vec::new(),
        )
        .await;
        assert_eq!(page.status(), StatusCode::OK);
        let page = body_json(page).await;
        let version = page["items"][0]["version"]
            .as_u64()
            .expect("continued page has a release version");
        assert_eq!(version, expected_version);
        existing_after_first_page.push(version);
        if expected_version == 2 {
            cursor = page["pageInfo"]["nextCursor"]
                .as_str()
                .expect("the middle page has a continuation")
                .to_owned();
        } else {
            assert_eq!(page["pageInfo"]["hasMore"], false);
            assert!(page["pageInfo"]["nextCursor"].is_null());
        }
    }
    assert_eq!(existing_after_first_page, [2, 1]);

    let all_releases = send(
        &app,
        Method::GET,
        "/v1/statistics/records-by-category/releases?accessProfile=reader&$top=10",
        Some(claims("reader", false)),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(all_releases.status(), StatusCode::OK);
    let all_releases = body_json(all_releases).await;
    let visible_versions = all_releases["items"]
        .as_array()
        .expect("release items")
        .iter()
        .map(|item| item["version"].as_u64().expect("release version"))
        .collect::<BTreeSet<_>>();
    assert_eq!(visible_versions, BTreeSet::from([1, 2, 4, 5]));

    let withdraw_inserted = withdraw(
        &app,
        &prior_period,
        5,
        "withdraw-inserted-page-release",
        publisher.clone(),
    )
    .await;
    assert_eq!(withdraw_inserted.status(), StatusCode::OK);

    let concurrent_period_date = prior_date
        .with_day(1)
        .expect("prior month has a first day")
        .checked_sub_days(Days::new(1))
        .expect("second prior month exists");
    let concurrent_period = month_code(concurrent_period_date);
    let (concurrent_a, concurrent_b) = tokio::join!(
        publish(
            &app,
            &concurrent_period,
            "concurrent-a",
            "final",
            publisher.clone()
        ),
        publish(
            &app,
            &concurrent_period,
            "concurrent-b",
            "final",
            publisher.clone()
        )
    );
    assert_eq!(concurrent_a.status(), StatusCode::CREATED);
    assert_eq!(concurrent_b.status(), StatusCode::CREATED);
    let concurrent_versions = BTreeSet::from([
        body_json(concurrent_a).await["version"]
            .as_u64()
            .expect("concurrent version"),
        body_json(concurrent_b).await["version"]
            .as_u64()
            .expect("concurrent version"),
    ]);
    assert_eq!(concurrent_versions, BTreeSet::from([1, 2]));

    let same_key_date = concurrent_period_date
        .with_day(1)
        .expect("second prior month has a first day")
        .checked_sub_days(Days::new(1))
        .expect("third prior month exists");
    let same_key_period = month_code(same_key_date);
    let (same_key_a, same_key_b) = tokio::join!(
        publish(
            &app,
            &same_key_period,
            "same-key-race",
            "final",
            publisher.clone()
        ),
        publish(
            &app,
            &same_key_period,
            "same-key-race",
            "final",
            publisher.clone()
        )
    );
    assert_eq!(same_key_a.status(), StatusCode::CREATED);
    assert_eq!(same_key_b.status(), StatusCode::CREATED);
    assert_eq!(body_bytes(same_key_a).await, body_bytes(same_key_b).await);
    let same_key_versions: i64 = database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_statistical_release_versions
              WHERE dataset_id = 'records-by-category' AND period_code = $1",
            &[&same_key_period],
        )
        .await
        .expect("same-key release count reads")
        .get(0);
    assert_eq!(same_key_versions, 1);

    let (withdraw_a, withdraw_b) = tokio::join!(
        withdraw(
            &app,
            &concurrent_period,
            2,
            "concurrent-withdraw-a",
            publisher.clone()
        ),
        withdraw(
            &app,
            &concurrent_period,
            2,
            "concurrent-withdraw-b",
            publisher.clone()
        )
    );
    let withdrawal_statuses = BTreeSet::from([withdraw_a.status(), withdraw_b.status()]);
    assert_eq!(
        withdrawal_statuses,
        BTreeSet::from([StatusCode::OK, StatusCode::UNPROCESSABLE_ENTITY])
    );

    let withdraw_current_definition = withdraw(
        &app,
        &prior_period,
        4,
        "withdraw-current-definition",
        publisher.clone(),
    )
    .await;
    assert_eq!(withdraw_current_definition.status(), StatusCode::OK);
    let previous_final = send(
        &app,
        Method::GET,
        &format!(
            "/v1/statistics/records-by-category/releases:series?accessProfile=reader&from={prior_period}&to={prior_period}&status=final"
        ),
        Some(claims("reader", false)),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(previous_final.status(), StatusCode::OK);
    assert_eq!(
        body_json(previous_final).await["periods"][0]["version"]["version"],
        2
    );

    let stored_before_erasure = send(
        &app,
        Method::GET,
        &format!(
            "/v1/statistics/records-by-category/releases/{prior_period}/versions/2?accessProfile=reader"
        ),
        Some(claims("reader", false)),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(stored_before_erasure.status(), StatusCode::OK);
    let stored_before_erasure = body_bytes(stored_before_erasure).await;
    let entity = &compiled.entities()["record"];
    database
        .admin
        .execute(
            &format!(
                "DELETE FROM registry_data.{} WHERE record_id = $1::text::uuid",
                quote_identifier(&entity.physical_table)
            ),
            &[&"00000000-0000-4000-8000-000000000001"],
        )
        .await
        .expect("fixture erases one current unit");
    let live_after_erasure = send(
        &app,
        Method::GET,
        &format!(
            "/v1/statistics/records-by-category:live?accessProfile=analyst&from={current_period}&to={current_period}"
        ),
        Some(analyst),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(live_after_erasure.status(), StatusCode::OK);
    assert_eq!(
        total_cell(&body_json(live_after_erasure).await, &current_period),
        2
    );
    let stored_after_erasure = send(
        &app,
        Method::GET,
        &format!(
            "/v1/statistics/records-by-category/releases/{prior_period}/versions/2?accessProfile=reader"
        ),
        Some(claims("reader", false)),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(stored_after_erasure.status(), StatusCode::OK);
    assert_eq!(
        body_bytes(stored_after_erasure).await,
        stored_before_erasure
    );
    let subject_access_log_entries: i64 = database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_subject_access_log",
            &[],
        )
        .await
        .expect("subject access log count reads")
        .get(0);
    assert_eq!(
        subject_access_log_entries, 1,
        "only the earlier entity row response is logged; statistics add no per-subject entries"
    );

    let audit_failure_date = same_key_date
        .with_day(1)
        .expect("third prior month has a first day")
        .checked_sub_days(Days::new(1))
        .expect("fourth prior month exists");
    let audit_failure_period = month_code(audit_failure_date);
    database.assert_every_audit_request_answered_once();
    let audit_before_failure = database.audit_records();
    let committed_release = audit_before_failure
        .iter()
        .find(|record| {
            record["operationId"] == "statistics.records-by-category.publish_release"
                && record["outcome"] == "committed"
        })
        .expect("publication writes a terminal audit record");
    assert_eq!(committed_release["resultCount"], 3);
    assert!(committed_release["contentDigest"].is_string());
    assert!(committed_release.get("cells").is_none());
    database
        .audit_capture()
        .fail_on(registry_breg::audit::AUDIT_SCHEMA, "terminal");
    let failed_terminal = publish(
        &app,
        &audit_failure_period,
        "audit-failure",
        "final",
        publisher.clone(),
    )
    .await;
    assert_eq!(failed_terminal.status(), StatusCode::SERVICE_UNAVAILABLE);
    database.audit_capture().restore();
    let recovered_audit = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x72; 32].into())
            .expect("audit profile is keyed"),
    );
    let recovered_app = statistics_router(
        pool,
        compiled,
        identity,
        lock_key,
        recovered_audit,
        trace,
        None,
    );
    let replay_after_audit_failure = publish(
        &recovered_app,
        &audit_failure_period,
        "audit-failure",
        "final",
        publisher,
    )
    .await;
    assert_eq!(replay_after_audit_failure.status(), StatusCode::CREATED);
    assert_eq!(body_json(replay_after_audit_failure).await["version"], 1);

    let audit_entries = database.audit_entries();
    assert!(audit_entries.iter().any(|entry| {
        entry["record"]["operationId"] == "statistics.records-by-category.publish_release"
            && entry["record"]["outcome"] == "replayed"
    }));
    let terminal_records = database.audit_records();
    for (operation, outcome, result_count) in [
        ("read_live", "returned", 3),
        ("read_released_series", "returned", 3),
        ("read_release_version", "returned", 3),
        ("list_releases", "returned", 0),
        ("publish_release", "committed", 3),
        ("withdraw_release", "committed", 0),
    ] {
        assert!(
            terminal_records.iter().any(|record| {
                record["operationId"] == format!("statistics.records-by-category.{operation}")
                    && record["outcome"] == outcome
                    && record["resultCount"] == result_count
                    && record.get("cells").is_none()
            }),
            "missing value-free terminal audit count for {operation}"
        );
    }
    let allowed_summary_keys = BTreeSet::from([
        "phase",
        "outcome",
        "method",
        "operationId",
        "requestId",
        "traceId",
        "packageRevision",
        "purposePresent",
        "selectedAccessProfile",
        "authorization",
        "entityId",
        "principalReference",
        "resultCount",
        "statisticalDatasetReference",
        "periodReference",
        "version",
        "status",
        "contentDigest",
        "queryReference",
        "rowBoundaryReference",
    ]);
    for record in terminal_records.iter().filter(|record| {
        record["phase"] == "terminal"
            && record["operationId"]
                .as_str()
                .is_some_and(|id| id.starts_with("statistics."))
    }) {
        assert!(
            record
                .as_object()
                .unwrap()
                .keys()
                .all(|key| allowed_summary_keys.contains(key.as_str())),
            "statistical audit summaries contain only references and lifecycle metadata: {record}"
        );
    }
    let audit_text = serde_json::to_string(&audit_entries).expect("audit serializes");
    assert!(!audit_text.contains(PRINCIPAL_CANARY));
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publication_rejects_a_snapshot_older_than_the_locked_release_head() {
    let database = TestDatabase::create(3).await;
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("compiled schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "package-statistics-stale-head-1",
        },
    )
    .await
    .expect("runtime identity and empty history baseline initialize");
    migration_task.abort();

    let pool = database.runtime_config.build_pool().expect("pool builds");
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives");
    let today = Utc::now().date_naive();
    let prior = today
        .with_day(1)
        .expect("current month has a first day")
        .checked_sub_days(Days::new(1))
        .expect("previous month exists");
    seed_records(&pool, lock_key, &identity, &compiled, today, prior).await;
    let definition_digest = compiled.statistical_datasets()["records-by-category"]
        .definition_digest
        .clone();
    let pause = StatisticsPublishPause::default();
    let app = statistics_router(
        pool,
        compiled,
        identity.clone(),
        lock_key,
        database.audit(
            AuditProfile::production_from_secret_bytes(vec![0x73; 32].into())
                .expect("audit profile is keyed"),
        ),
        Arc::new(std::sync::Mutex::new(Vec::new())),
        Some(pause.clone()),
    );
    let period = month_code(prior);
    let request_app = app.clone();
    let request_period = period.clone();
    let attempt = tokio::spawn(async move {
        publish(
            &request_app,
            &request_period,
            "stale-head",
            "final",
            claims("publisher", false),
        )
        .await
    });
    pause.wait_until_reached().await;
    let content_digest = format!("sha256:{}", "0".repeat(64));
    database
        .admin
        .execute(
            "INSERT INTO registry_internal.registry_statistical_release_versions
                 (dataset_id, period_code, release_version, release_status,
                  history_head_position, snapshot_reference, computed_at,
                  package_digest, definition_digest, content_digest)
             SELECT 'records-by-category', $1, 1, 'final', 1,
                    snapshot_reference, transaction_timestamp(), $2, $3, $4
               FROM registry_internal.registry_revision_commits
              WHERE commit_position = 0",
            &[
                &period,
                &identity.package_digest,
                &definition_digest,
                &content_digest,
            ],
        )
        .await
        .expect("fixture installs a competing release based on a newer head");
    pause.resume();
    let response = attempt.await.expect("publication task joins");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let versions: i64 = database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_statistical_release_versions
              WHERE dataset_id = 'records-by-category' AND period_code = $1",
            &[&period],
        )
        .await
        .expect("release count reads")
        .get(0);
    let idempotency: i64 = database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_idempotency",
            &[],
        )
        .await
        .expect("idempotency count reads")
        .get(0);
    assert_eq!(versions, 1);
    assert_eq!(idempotency, 0);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provisional_persisting_after_final_is_refused() {
    let database = TestDatabase::create(4).await;
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("compiled schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "package-statistics-provisional-race-1",
        },
    )
    .await
    .expect("runtime identity initializes");
    migration_task.abort();
    let pool = database.runtime_config.build_pool().expect("pool builds");
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives");
    let audit = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x74; 32].into())
            .expect("audit profile is keyed"),
    );
    let pause = StatisticsPublishPause::default();
    let paused = statistics_router(
        pool.clone(),
        compiled.clone(),
        identity.clone(),
        lock_key,
        audit.clone(),
        Arc::new(std::sync::Mutex::new(Vec::new())),
        Some(pause.clone()),
    );
    let unpaused = statistics_router(
        pool,
        compiled,
        identity,
        lock_key,
        audit,
        Arc::new(std::sync::Mutex::new(Vec::new())),
        None,
    );
    let today = Utc::now().date_naive();
    let prior = today
        .with_day(1)
        .expect("current month has a first day")
        .checked_sub_days(Days::new(1))
        .expect("previous month exists");
    let period = month_code(prior);
    let provisional_app = paused.clone();
    let provisional_period = period.clone();
    let provisional = tokio::spawn(async move {
        publish(
            &provisional_app,
            &provisional_period,
            "provisional-race",
            "provisional",
            claims("publisher", false),
        )
        .await
    });
    pause.wait_until_reached().await;
    let final_response = publish(
        &unpaused,
        &period,
        "final-race",
        "final",
        claims("publisher", false),
    )
    .await;
    assert_eq!(final_response.status(), StatusCode::CREATED);
    assert_eq!(body_json(final_response).await["version"], 1);
    pause.resume();
    let provisional_response = provisional.await.expect("provisional task joins");
    assert_eq!(
        provisional_response.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        body_json(provisional_response).await["refusalCode"],
        "provisional-after-final"
    );
    let versions = database
        .admin
        .query(
            "SELECT release_version, release_status
               FROM registry_internal.registry_statistical_release_versions
              WHERE dataset_id = 'records-by-category' AND period_code = $1",
            &[&period],
        )
        .await
        .expect("release versions read");
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].get::<_, i64>(0), 1);
    assert_eq!(versions[0].get::<_, String>(1), "final");
    let same_key_date = prior
        .with_day(1)
        .expect("prior month has a first day")
        .checked_sub_days(Days::new(1))
        .expect("second prior month exists");
    let same_key_period = month_code(same_key_date);
    let first_app = paused.clone();
    let first_period = same_key_period.clone();
    let first = tokio::spawn(async move {
        publish(
            &first_app,
            &first_period,
            "ordered-same-key",
            "final",
            claims("publisher", false),
        )
        .await
    });
    pause.wait_until_reached().await;
    let second = publish(
        &unpaused,
        &same_key_period,
        "ordered-same-key",
        "final",
        claims("publisher", false),
    )
    .await;
    assert_eq!(second.status(), StatusCode::CREATED);
    let second = body_bytes(second).await;
    pause.resume();
    let first = first.await.expect("first same-key task joins");
    assert_eq!(first.status(), StatusCode::CREATED);
    assert_eq!(body_bytes(first).await, second);
    let same_key_versions: i64 = database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_statistical_release_versions
              WHERE dataset_id = 'records-by-category' AND period_code = $1",
            &[&same_key_period],
        )
        .await
        .expect("same-key version count reads")
        .get(0);
    assert_eq!(same_key_versions, 1);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publication_replay_is_bound_to_the_active_package() {
    let database = TestDatabase::create(3).await;
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("compiled schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "package-statistics-activation-binding-1",
        },
    )
    .await
    .expect("runtime identity initializes");
    migration_task.abort();
    let pool = database.runtime_config.build_pool().expect("pool builds");
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives");
    let app = statistics_router(
        pool,
        compiled,
        identity,
        lock_key,
        database.audit(
            AuditProfile::production_from_secret_bytes(vec![0x75; 32].into())
                .expect("audit profile is keyed"),
        ),
        Arc::new(std::sync::Mutex::new(Vec::new())),
        None,
    );
    let today = Utc::now().date_naive();
    let prior = today
        .with_day(1)
        .expect("current month has a first day")
        .checked_sub_days(Days::new(1))
        .expect("previous month exists");
    let period = month_code(prior);
    let first = publish(
        &app,
        &period,
        "activation-bound-key",
        "final",
        claims("publisher", false),
    )
    .await;
    assert_eq!(first.status(), StatusCode::CREATED);

    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_state
                SET active_package_digest = $1,
                    active_activation_id = $2::text::uuid
              WHERE singleton",
            &[
                &format!("sha256:{}", "1".repeat(64)),
                &registry_breg::postgres::test_activation_id(
                    "package-statistics-activation-binding-2",
                ),
            ],
        )
        .await
        .expect("fixture activates a successor package");
    let replay = publish(
        &app,
        &period,
        "activation-bound-key",
        "final",
        claims("publisher", false),
    )
    .await;
    assert_eq!(replay.status(), StatusCode::SERVICE_UNAVAILABLE);
    let version_count: i64 = database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_statistical_release_versions",
            &[],
        )
        .await
        .expect("release count reads")
        .get(0);
    assert_eq!(version_count, 1);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn activation_between_compute_and_persist_is_a_version_conflict_without_writes() {
    let database = TestDatabase::create(3).await;
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("compiled schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "package-statistics-persist-activation-1",
        },
    )
    .await
    .expect("runtime identity initializes");
    migration_task.abort();
    let pause = StatisticsPublishPause::default();
    let app = statistics_router(
        database.runtime_config.build_pool().expect("pool builds"),
        compiled,
        identity,
        RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives"),
        database.audit(
            AuditProfile::production_from_secret_bytes(vec![0x79; 32].into())
                .expect("audit profile is keyed"),
        ),
        Arc::new(std::sync::Mutex::new(Vec::new())),
        Some(pause.clone()),
    );
    let today = Utc::now().date_naive();
    let prior = today
        .with_day(1)
        .expect("current month has a first day")
        .checked_sub_days(Days::new(1))
        .expect("previous month exists");
    let period = month_code(prior);
    let unavailable_app = app.clone();
    let unavailable_period = period.clone();
    let unavailable_task = tokio::spawn(async move {
        publish(
            &unavailable_app,
            &unavailable_period,
            "persist-maintenance",
            "final",
            claims("publisher", false),
        )
        .await
    });
    pause.wait_until_reached().await;
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_state
                SET maintenance_status = 'failed',
                    maintenance_target_package_digest = $1
              WHERE singleton",
            &[&format!("sha256:{}", "3".repeat(64))],
        )
        .await
        .expect("fixture puts the same activation into unavailable maintenance state");
    pause.resume();
    let unavailable_response = unavailable_task.await.expect("publication task joins");
    assert_eq!(
        unavailable_response.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_state
                SET maintenance_status = 'ready',
                    maintenance_target_package_digest = NULL
              WHERE singleton",
            &[],
        )
        .await
        .expect("fixture restores the active package to ready");
    let request_app = app.clone();
    let request_period = period.clone();
    let publish_task = tokio::spawn(async move {
        publish(
            &request_app,
            &request_period,
            "persist-activation",
            "final",
            claims("publisher", false),
        )
        .await
    });
    pause.wait_until_reached().await;
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_state
                SET active_package_digest = $1,
                    active_activation_id = $2::text::uuid
              WHERE singleton",
            &[
                &format!("sha256:{}", "2".repeat(64)),
                &registry_breg::postgres::test_activation_id(
                    "package-statistics-persist-activation-2",
                ),
            ],
        )
        .await
        .expect("fixture activates a successor between compute and persist");
    pause.resume();
    let response = publish_task.await.expect("publication task joins");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let stale_read = send(
        &app,
        Method::GET,
        "/v1/statistics/records-by-category/releases?accessProfile=reader",
        Some(claims("reader", false)),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(stale_read.status(), StatusCode::SERVICE_UNAVAILABLE);
    let persisted: i64 = database
        .admin
        .query_one(
            "SELECT
                (SELECT count(*) FROM registry_internal.registry_statistical_release_versions)
              + (SELECT count(*) FROM registry_internal.registry_statistical_release_contents)
              + (SELECT count(*) FROM registry_internal.registry_idempotency)",
            &[],
        )
        .await
        .expect("persisted result count reads")
        .get(0);
    assert_eq!(persisted, 0);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publication_statement_timeout_reserves_the_terminal_audit_before_outer_cancellation() {
    let database = TestDatabase::create(4).await;
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("compiled schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "package-statistics-outer-timeout-1",
        },
    )
    .await
    .expect("runtime identity initializes");
    migration_task.abort();
    let table = compiled.entities()["record"].physical_table.clone();
    let app = registry_breg::startup::with_request_timeout_for_test(
        statistics_router(
            database.runtime_config.build_pool().expect("pool builds"),
            compiled,
            identity,
            RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives"),
            database.audit(
                AuditProfile::production_from_secret_bytes(vec![0x7e; 32].into())
                    .expect("audit profile is keyed"),
            ),
            Arc::new(std::sync::Mutex::new(Vec::new())),
            None,
        ),
        Duration::from_secs(2),
    );
    let (mut blocker, blocker_task) = database.connect_migration().await;
    let blocker_transaction = blocker.transaction().await.expect("blocker begins");
    blocker_transaction
        .batch_execute(&format!(
            "LOCK TABLE registry_data.{} IN ACCESS EXCLUSIVE MODE",
            quote_identifier(&table)
        ))
        .await
        .expect("source read is deterministically blocked");
    let today = Utc::now().date_naive();
    let prior = today
        .with_day(1)
        .unwrap()
        .checked_sub_days(Days::new(1))
        .unwrap();
    let response = publish(
        &app,
        &month_code(prior),
        "outer-timeout-publish",
        "final",
        claims("publisher", false),
    )
    .await;
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    let records = database.audit_records();
    assert_eq!(records.len(), 2, "one attempt has one terminal response");
    assert_eq!(records[0]["phase"], "attempt");
    assert_eq!(records[1]["phase"], "terminal");
    assert_eq!(records[1]["outcome"], "refused");
    assert_eq!(records[0]["requestId"], records[1]["requestId"]);
    assert_eq!(
        records[1]["operationId"],
        "statistics.records-by-category.publish_release"
    );
    for table in [
        "registry_statistical_release_versions",
        "registry_statistical_release_contents",
        "registry_idempotency",
    ] {
        let count: i64 = database
            .admin
            .query_one(
                &format!("SELECT count(*) FROM registry_internal.{table}"),
                &[],
            )
            .await
            .expect("protected effects read")
            .get(0);
        assert_eq!(count, 0, "a timed-out publication creates no {table} row");
    }
    blocker_transaction
        .rollback()
        .await
        .expect("blocker releases");
    blocker_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idempotency_lock_cancellation_is_a_timeout_for_publish_and_withdrawal() {
    let database = TestDatabase::create(4).await;
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("compiled schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "package-statistics-idempotency-timeout-1",
        },
    )
    .await
    .expect("runtime identity initializes");
    migration_task.abort();
    let app = statistics_router(
        database.runtime_config.build_pool().expect("pool builds"),
        compiled,
        identity,
        RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives"),
        database.audit(
            AuditProfile::production_from_secret_bytes(vec![0x7a; 32].into())
                .expect("audit profile is keyed"),
        ),
        Arc::new(std::sync::Mutex::new(Vec::new())),
        None,
    );
    let today = Utc::now().date_naive();
    let prior = today
        .with_day(1)
        .expect("current month has a first day")
        .checked_sub_days(Days::new(1))
        .expect("previous month exists");
    let period = month_code(prior);
    let published = publish(
        &app,
        &period,
        "deadline-publish",
        "final",
        claims("publisher", false),
    )
    .await;
    assert_eq!(published.status(), StatusCode::CREATED);
    let withdrawn = withdraw(
        &app,
        &period,
        1,
        "deadline-withdraw",
        claims("publisher", false),
    )
    .await;
    assert_eq!(withdrawn.status(), StatusCode::OK);
    let rows = database
        .admin
        .query(
            "SELECT key_reference, response_status
               FROM registry_internal.registry_idempotency
              WHERE result_kind = 'release'",
            &[],
        )
        .await
        .expect("release idempotency references read");
    assert_eq!(rows.len(), 2);
    for row in rows {
        let key_reference = row.get::<_, String>(0);
        let response_status = row.get::<_, i16>(1);
        let (mut blocker, blocker_task) = database.connect_migration().await;
        let blocker_transaction = blocker
            .transaction()
            .await
            .expect("blocking transaction opens");
        blocker_transaction
            .execute(
                "SELECT pg_advisory_xact_lock(pg_catalog.hashtextextended($1, 0))",
                &[&key_reference],
            )
            .await
            .expect("exact idempotency key lock is held");
        let (uri, key, body) = if response_status == 201 {
            (
                format!(
                    "/v1/statistics/records-by-category/releases/{period}/versions?accessProfile=publisher"
                ),
                "deadline-publish",
                json!({"status":"final"}),
            )
        } else {
            assert_eq!(response_status, 200);
            (
                format!(
                    "/v1/statistics/records-by-category/releases/{period}/versions/1/withdrawal?accessProfile=publisher"
                ),
                "deadline-withdraw",
                json!({"reason":"source-data-error"}),
            )
        };
        let response = send_with_deadline(
            &app,
            Method::POST,
            &uri,
            Some(claims("publisher", false)),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", key),
            ],
            serde_json::to_vec(&body).expect("retry body serializes"),
            Some(tokio::time::Instant::now() + Duration::from_millis(50)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        blocker_transaction
            .rollback()
            .await
            .expect("blocking transaction rolls back");
        blocker_task.abort();
    }
    let versions: i64 = database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_statistical_release_versions",
            &[],
        )
        .await
        .expect("release count reads")
        .get(0);
    assert_eq!(versions, 1);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_withdrawal_commits_while_the_first_is_paused_before_the_period_lock() {
    let database = TestDatabase::create(4).await;
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("compiled schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "package-statistics-withdrawal-race-1",
        },
    )
    .await
    .expect("runtime identity initializes");
    migration_task.abort();
    let pool = database.runtime_config.build_pool().expect("pool builds");
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives");
    let audit = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x7b; 32].into())
            .expect("audit profile is keyed"),
    );
    let pause = StatisticsWithdrawalPause::default();
    let paused = statistics_router_with_pauses(
        pool.clone(),
        compiled.clone(),
        identity.clone(),
        lock_key,
        audit.clone(),
        Arc::new(std::sync::Mutex::new(Vec::new())),
        None,
        Some(pause.clone()),
    );
    let unpaused = statistics_router(
        pool,
        compiled,
        identity,
        lock_key,
        audit,
        Arc::new(std::sync::Mutex::new(Vec::new())),
        None,
    );
    let today = Utc::now().date_naive();
    let prior = today
        .with_day(1)
        .expect("current month has a first day")
        .checked_sub_days(Days::new(1))
        .expect("previous month exists");
    let period = month_code(prior);
    let release = publish(
        &unpaused,
        &period,
        "withdrawal-race-release",
        "final",
        claims("publisher", false),
    )
    .await;
    assert_eq!(release.status(), StatusCode::CREATED);
    let first_app = paused.clone();
    let first_period = period.clone();
    let first = tokio::spawn(async move {
        withdraw(
            &first_app,
            &first_period,
            1,
            "withdrawal-race-first",
            claims("publisher", false),
        )
        .await
    });
    pause.wait_until_reached().await;
    let second = withdraw(
        &unpaused,
        &period,
        1,
        "withdrawal-race-second",
        claims("publisher", false),
    )
    .await;
    assert_eq!(second.status(), StatusCode::OK);
    pause.resume();
    let first = first.await.expect("first withdrawal task joins");
    assert_eq!(first.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body_json(first).await["refusalCode"], "already-withdrawn");
    let withdrawals: i64 = database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_statistical_release_withdrawals",
            &[],
        )
        .await
        .expect("withdrawal count reads")
        .get(0);
    assert_eq!(withdrawals, 1);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn computation_statement_obeys_the_request_deadline_and_persists_nothing() {
    let database = TestDatabase::create(3).await;
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("compiled schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "package-statistics-deadline-1",
        },
    )
    .await
    .expect("runtime identity initializes");
    let pool = database.runtime_config.build_pool().expect("pool builds");
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives");
    let today = Utc::now().date_naive();
    let prior = today
        .with_day(1)
        .expect("current month has a first day")
        .checked_sub_days(Days::new(1))
        .expect("previous month exists");
    seed_records(&pool, lock_key, &identity, &compiled, today, prior).await;
    let entity = &compiled.entities()["record"];
    let source_columns = std::iter::once(format!(
        "record_id AS {}",
        quote_identifier(&entity.canonical_id.sql_name)
    ))
    .chain(entity.stored_fields.iter().map(|field| {
        format!(
            "{} AS {}",
            quote_identifier(&field.physical_name),
            quote_identifier(&field.logical.sql_name)
        )
    }))
    .collect::<Vec<_>>()
    .join(", ");
    migration
        .batch_execute(&format!(
            "CREATE FUNCTION registry_internal.statistics_test_delay()
             RETURNS boolean LANGUAGE sql VOLATILE
             SET search_path = pg_catalog
             AS 'SELECT true FROM pg_catalog.pg_sleep(1)';
             CREATE OR REPLACE VIEW registry_source.{source_view}
             WITH (security_invoker=true, security_barrier=true)
             AS SELECT {source_columns}
                  FROM registry_data.{table}
                 WHERE record_lifecycle = 'active'
                   AND registry_internal.statistics_test_delay()",
            source_view = quote_identifier(&entity.source_relation.sql_name),
            table = quote_identifier(&entity.physical_table),
        ))
        .await
        .expect("fixture makes the grouped source statement observably slow");
    migration_task.abort();
    let app = statistics_router(
        pool,
        compiled,
        identity,
        lock_key,
        database.audit(
            AuditProfile::production_from_secret_bytes(vec![0x76; 32].into())
                .expect("audit profile is keyed"),
        ),
        Arc::new(std::sync::Mutex::new(Vec::new())),
        None,
    );
    let started = std::time::Instant::now();
    let response = send_with_deadline(
        &app,
        Method::GET,
        &format!(
            "/v1/statistics/records-by-category:live?accessProfile=analyst&from={0}&to={0}",
            month_code(today)
        ),
        Some(claims("analyst", true)),
        &[],
        Vec::new(),
        Some(tokio::time::Instant::now() + Duration::from_millis(25)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the database statement exceeded the caller's absolute deadline"
    );
    let (mut blocker, blocker_task) = database.connect_migration().await;
    let blocker_transaction = blocker
        .transaction()
        .await
        .expect("blocking transaction opens");
    blocker_transaction
        .batch_execute(
            "LOCK TABLE registry_internal.registry_statistical_release_versions
             IN ACCESS EXCLUSIVE MODE",
        )
        .await
        .expect("release table is locked for the cancellation probe");
    let release_read = send_with_deadline(
        &app,
        Method::GET,
        "/v1/statistics/records-by-category/releases?accessProfile=reader",
        Some(claims("reader", false)),
        &[],
        Vec::new(),
        Some(tokio::time::Instant::now() + Duration::from_millis(25)),
    )
    .await;
    assert_eq!(release_read.status(), StatusCode::GATEWAY_TIMEOUT);
    blocker_transaction
        .rollback()
        .await
        .expect("blocking transaction rolls back");
    blocker_task.abort();
    let persisted: i64 = database
        .admin
        .query_one(
            "SELECT
                (SELECT count(*) FROM registry_internal.registry_statistical_release_versions)
              + (SELECT count(*) FROM registry_internal.registry_statistical_release_contents)
              + (SELECT count(*) FROM registry_internal.registry_idempotency)",
            &[],
        )
        .await
        .expect("persisted result count reads")
        .get(0);
    assert_eq!(persisted, 0);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn domain_violation_is_value_free_and_persists_no_release() {
    let database = TestDatabase::create(3).await;
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("compiled schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "package-statistics-domain-1",
        },
    )
    .await
    .expect("runtime identity initializes");
    migration_task.abort();
    let pool = database.runtime_config.build_pool().expect("pool builds");
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives");
    let today = Utc::now().date_naive();
    let prior = today
        .with_day(1)
        .expect("current month has a first day")
        .checked_sub_days(Days::new(1))
        .expect("previous month exists");
    seed_records(&pool, lock_key, &identity, &compiled, today, prior).await;
    let entity = &compiled.entities()["record"];
    let category = &entity.fields["category"].physical_name;
    let constraints = database
        .admin
        .query(
            "SELECT constraint_row.conname
               FROM pg_catalog.pg_constraint AS constraint_row
              WHERE constraint_row.conrelid = pg_catalog.to_regclass($1)
                AND constraint_row.contype = 'c'
                AND pg_catalog.pg_get_constraintdef(constraint_row.oid) LIKE '%' || $2 || '%'",
            &[
                &format!("registry_data.{}", quote_identifier(&entity.physical_table)),
                category,
            ],
        )
        .await
        .expect("dimension constraints resolve");
    assert!(
        !constraints.is_empty(),
        "the vocabulary has a storage check"
    );
    for constraint in constraints {
        let constraint: String = constraint.get(0);
        database
            .admin
            .batch_execute(&format!(
                "ALTER TABLE registry_data.{} DROP CONSTRAINT {}",
                quote_identifier(&entity.physical_table),
                quote_identifier(&constraint)
            ))
            .await
            .expect("fixture removes the storage check to simulate corrupt source data");
    }
    let canary = "undeclared-category-value-canary";
    database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.{} SET {} = $1 WHERE record_id = $2::text::uuid",
                quote_identifier(&entity.physical_table),
                quote_identifier(category)
            ),
            &[&canary, &"00000000-0000-4000-8000-000000000001"],
        )
        .await
        .expect("fixture inserts an out-of-domain source value");
    let app = statistics_router(
        pool,
        compiled,
        identity,
        lock_key,
        database.audit(
            AuditProfile::production_from_secret_bytes(vec![0x77; 32].into())
                .expect("audit profile is keyed"),
        ),
        Arc::new(std::sync::Mutex::new(Vec::new())),
        None,
    );
    let response = send(
        &app,
        Method::GET,
        &format!(
            "/v1/statistics/records-by-category:live?accessProfile=analyst-wide&from={0}&to={0}",
            month_code(today)
        ),
        Some(claims("analyst-wide", false)),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = body_bytes(response).await;
    let text = String::from_utf8(body).expect("problem body is UTF-8");
    assert!(text.contains("statistical_dataset.domain_violation"));
    let problem: Value = serde_json::from_str(&text).expect("domain problem is JSON");
    assert_eq!(
        problem["fieldPath"],
        "statisticalDatasets[id=records-by-category].dimensions[id=category]"
    );
    assert!(!text.contains(canary));
    let persisted: i64 = database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_statistical_release_versions",
            &[],
        )
        .await
        .expect("release count reads")
        .get(0);
    assert_eq!(persisted, 0);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_and_series_refuse_period_and_response_cell_caps() {
    let database = TestDatabase::create(2).await;
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = Arc::new(cap_registry());
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("compiled schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "package-statistics-caps-1",
        },
    )
    .await
    .expect("runtime identity initializes");
    migration_task.abort();
    let app = statistics_router(
        database.runtime_config.build_pool().expect("pool builds"),
        compiled,
        identity,
        RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives"),
        database.audit(
            AuditProfile::production_from_secret_bytes(vec![0x78; 32].into())
                .expect("audit profile is keyed"),
        ),
        Arc::new(std::sync::Mutex::new(Vec::new())),
        None,
    );
    let today = Utc::now().date_naive();
    let cell_cap_start = today
        .checked_sub_days(Days::new(200))
        .expect("cell-cap range start exists");
    let cases = [
        (
            format!(
                "/v1/statistics/daily-by-category:live?accessProfile=analyst&from=2025-01-01&to={today}"
            ),
            claims("analyst", true),
        ),
        (
            format!(
                "/v1/statistics/daily-by-category:live?accessProfile=analyst&from={cell_cap_start}&to={today}"
            ),
            claims("analyst", true),
        ),
        (
            format!(
                "/v1/statistics/daily-by-category/releases:series?accessProfile=reader&from=2025-01-01&to={today}"
            ),
            claims("reader", false),
        ),
    ];
    for (uri, claims) in cases {
        let response = send(&app, Method::GET, &uri, Some(claims), &[], Vec::new()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        let problem = body_json(response).await;
        assert_eq!(problem["code"], "query.invalid");
        assert_ne!(problem["fieldPath"], "period");
    }

    let release_day = today
        .checked_sub_days(Days::new(1))
        .expect("prior day exists");
    let release = send(
        &app,
        Method::POST,
        &format!(
            "/v1/statistics/daily-by-category/releases/{release_day}/versions?accessProfile=publisher"
        ),
        Some(claims("publisher", false)),
        &[
            ("content-type", "application/json"),
            ("idempotency-key", "series-cell-cap"),
        ],
        serde_json::to_vec(&json!({"status":"final"})).expect("publish body serializes"),
    )
    .await;
    assert_eq!(release.status(), StatusCode::CREATED);
    let stored: Vec<u8> = database
        .admin
        .query_one(
            "SELECT document
               FROM registry_internal.registry_statistical_release_contents
              WHERE dataset_id = 'daily-by-category' AND period_code = $1",
            &[&release_day.to_string()],
        )
        .await
        .expect("stored release reads")
        .get(0);
    let template: Value = serde_json::from_slice(&stored).expect("stored release is JSON");
    let series_start = release_day
        .checked_sub_days(Days::new(196))
        .expect("series cell-cap start exists");
    for offset in 1..197_u64 {
        let period = release_day
            .checked_sub_days(Days::new(offset))
            .expect("series fixture day exists");
        let end = period
            .checked_add_days(Days::new(1))
            .expect("series fixture end exists");
        let mut document = template.clone();
        document["periods"][0]["code"] = json!(period.to_string());
        document["periods"][0]["start"] = json!(period.to_string());
        document["periods"][0]["end"] = json!(end.to_string());
        document["periods"][0]["referenceDate"] = json!(period.to_string());
        document["release"]["period"] = json!(period.to_string());
        for cell in document["cells"]
            .as_array_mut()
            .expect("template cells are an array")
        {
            cell["period"] = json!(period.to_string());
        }
        let document: registry_breg::statistics::StatisticsDocument =
            serde_json::from_value(document).expect("series fixture document decodes");
        let canonical = registry_breg::statistics::canonical_document_and_digest(&document)
            .expect("series fixture document canonicalizes");
        database
            .admin
            .execute(
                "INSERT INTO registry_internal.registry_statistical_release_versions
                     (dataset_id, period_code, release_version, release_status,
                      history_head_position, snapshot_reference, computed_at,
                      package_digest, definition_digest, content_digest)
                 SELECT dataset_id, $1, release_version, release_status,
                        history_head_position, snapshot_reference, computed_at,
                        package_digest, definition_digest, $2
                   FROM registry_internal.registry_statistical_release_versions
                  WHERE dataset_id = 'daily-by-category' AND period_code = $3",
                &[
                    &period.to_string(),
                    &canonical.content_digest,
                    &release_day.to_string(),
                ],
            )
            .await
            .expect("series fixture header inserts");
        database
            .admin
            .execute(
                "INSERT INTO registry_internal.registry_statistical_release_contents
                     (dataset_id, period_code, release_version, document)
                 VALUES ('daily-by-category', $1, 1, $2)",
                &[&period.to_string(), &canonical.bytes],
            )
            .await
            .expect("series fixture content inserts");
    }
    let series_cell_cap = send(
        &app,
        Method::GET,
        &format!(
            "/v1/statistics/daily-by-category/releases:series?accessProfile=reader&from={series_start}&to={release_day}"
        ),
        Some(claims("reader", false)),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(series_cell_cap.status(), StatusCode::BAD_REQUEST);
    let problem = body_json(series_cell_cap).await;
    assert_eq!(problem["code"], "query.invalid");
    assert!(
        problem.get("fieldPath").is_none(),
        "cell caps describe the whole response"
    );
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_state
                SET maintenance_status = 'failed',
                    maintenance_target_package_digest = $1
              WHERE singleton",
            &[&format!("sha256:{}", "4".repeat(64))],
        )
        .await
        .expect("fixture makes database access unavailable");
    let preflight = send(
        &app,
        Method::GET,
        &format!(
            "/v1/statistics/daily-by-category:live?accessProfile=analyst&from={cell_cap_start}&to={today}"
        ),
        Some(claims("analyst", true)),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(preflight.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(preflight).await["code"], "query.invalid");
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn generated_openapi_validates_the_actual_statistical_http_wire_contract() {
    let database = TestDatabase::create(4).await;
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("compiled schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "package-statistics-openapi-1",
        },
    )
    .await
    .expect("runtime identity initializes");
    migration_task.abort();

    let pool = database.runtime_config.build_pool().expect("pool builds");
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives");
    let today = Utc::now().date_naive();
    let prior = today
        .with_day(1)
        .expect("current month has a first day")
        .checked_sub_days(Days::new(1))
        .expect("previous month exists");
    let current_period = month_code(today);
    let prior_period = month_code(prior);
    seed_records(&pool, lock_key, &identity, &compiled, today, prior).await;
    let audit = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x7c; 32].into())
            .expect("audit profile is keyed"),
    );
    let app = statistics_router(
        pool.clone(),
        compiled.clone(),
        identity.clone(),
        lock_key,
        audit.clone(),
        Arc::new(std::sync::Mutex::new(Vec::new())),
        None,
    );
    let publish_pause = StatisticsPublishPause::default();
    let paused_app = statistics_router(
        pool,
        compiled.clone(),
        identity.clone(),
        lock_key,
        audit,
        Arc::new(std::sync::Mutex::new(Vec::new())),
        Some(publish_pause.clone()),
    );

    let analyst_openapi = openapi_for(&app, "analyst", true).await;
    let reader_openapi = openapi_for(&app, "reader", false).await;
    let publisher_openapi = openapi_for(&app, "publisher", false).await;
    let live_path = "/v1/statistics/records-by-category:live";
    let list_path = "/v1/statistics/records-by-category/releases";
    let series_path = "/v1/statistics/records-by-category/releases:series";
    let latest_path = "/v1/statistics/records-by-category/releases/{period}";
    let publish_path = "/v1/statistics/records-by-category/releases/{period}/versions";
    let exact_path = "/v1/statistics/records-by-category/releases/{period}/versions/{version}";
    let withdrawal_path =
        "/v1/statistics/records-by-category/releases/{period}/versions/{version}/withdrawal";

    assert_operation_parameters(
        &analyst_openapi,
        live_path,
        "get",
        &[
            ("query", "accessProfile", false),
            ("query", "from", false),
            ("query", "to", false),
            ("header", "Accept", false),
            ("header", "traceparent", false),
        ],
    );
    let live_profile =
        operation_parameter(&analyst_openapi, live_path, "get", "query", "accessProfile");
    assert_eq!(live_profile["schema"]["default"], "analyst");
    assert_operation_parameters(
        &reader_openapi,
        list_path,
        "get",
        &[
            ("query", "$skiptoken", false),
            ("query", "$top", false),
            ("query", "accessProfile", true),
            ("header", "traceparent", false),
        ],
    );
    assert_operation_parameters(
        &reader_openapi,
        series_path,
        "get",
        &[
            ("query", "accessProfile", true),
            ("query", "from", true),
            ("query", "status", false),
            ("query", "to", true),
            ("header", "Accept", false),
            ("header", "traceparent", false),
        ],
    );
    assert_operation_parameters(
        &reader_openapi,
        latest_path,
        "get",
        &[
            ("path", "period", true),
            ("query", "accessProfile", true),
            ("query", "status", false),
            ("header", "Accept", false),
            ("header", "traceparent", false),
        ],
    );
    assert_operation_parameters(
        &reader_openapi,
        exact_path,
        "get",
        &[
            ("path", "period", true),
            ("path", "version", true),
            ("query", "accessProfile", true),
            ("header", "Accept", false),
            ("header", "traceparent", false),
        ],
    );
    assert_operation_parameters(
        &publisher_openapi,
        publish_path,
        "post",
        &[
            ("path", "period", true),
            ("query", "accessProfile", false),
            ("header", "Idempotency-Key", true),
            ("header", "traceparent", false),
        ],
    );
    assert_operation_parameters(
        &publisher_openapi,
        withdrawal_path,
        "post",
        &[
            ("path", "period", true),
            ("path", "version", true),
            ("query", "accessProfile", false),
            ("header", "Idempotency-Key", true),
            ("header", "traceparent", false),
        ],
    );
    assert_operation_media(
        &analyst_openapi,
        live_path,
        "get",
        "200",
        &["application/json", "text/csv"],
    );
    assert_operation_media(
        &reader_openapi,
        list_path,
        "get",
        "200",
        &["application/json"],
    );
    for path in [series_path, latest_path, exact_path] {
        assert_operation_media(
            &reader_openapi,
            path,
            "get",
            "200",
            &["application/json", "text/csv"],
        );
    }
    assert_request_media(
        &publisher_openapi,
        publish_path,
        "post",
        &["application/json"],
    );
    assert_request_media(
        &publisher_openapi,
        withdrawal_path,
        "post",
        &["application/json"],
    );
    assert_operation_media(
        &publisher_openapi,
        publish_path,
        "post",
        "201",
        &["application/json"],
    );
    assert_operation_media(
        &publisher_openapi,
        withdrawal_path,
        "post",
        "200",
        &["application/json"],
    );

    let live = send(
        &app,
        Method::GET,
        &format!("{live_path}?from={prior_period}&to={current_period}"),
        Some(claims("analyst", true)),
        &[],
        Vec::new(),
    )
    .await;
    let live = validate_openapi_json_response(&analyst_openapi, live_path, "get", live, 200).await;
    assert_eq!(live["live"]["accessProfile"], "analyst");

    let refused = publish(
        &app,
        &current_period,
        "openapi-unended-period",
        "final",
        claims("publisher", false),
    )
    .await;
    let refused =
        validate_openapi_json_response(&publisher_openapi, publish_path, "post", refused, 422)
            .await;
    assert_eq!(refused["code"], "statistical_dataset.release_refused");
    assert_eq!(refused["refusalCode"], "period-not-ended");

    let publish_body = json!({"status":"provisional"});
    validate_openapi_request(&publisher_openapi, publish_path, "post", &publish_body);
    let published = send(
        &app,
        Method::POST,
        &format!(
            "/v1/statistics/records-by-category/releases/{prior_period}/versions?accessProfile=publisher"
        ),
        Some(claims("publisher", false)),
        &[
            ("content-type", "application/json"),
            ("idempotency-key", "openapi-wire-publication"),
        ],
        serde_json::to_vec(&publish_body).expect("publication request serializes"),
    )
    .await;
    let published =
        validate_openapi_json_response(&publisher_openapi, publish_path, "post", published, 201)
            .await;
    assert_eq!(published["version"], 1);

    let conflict_date = prior
        .with_day(1)
        .expect("prior month has a first day")
        .checked_sub_days(Days::new(1))
        .expect("second prior month exists");
    let conflict_period = month_code(conflict_date);
    let conflict_app = paused_app.clone();
    let conflict_period_for_request = conflict_period.clone();
    let conflict_task = tokio::spawn(async move {
        publish(
            &conflict_app,
            &conflict_period_for_request,
            "openapi-version-conflict",
            "final",
            claims("publisher", false),
        )
        .await
    });
    publish_pause.wait_until_reached().await;
    let definition_digest =
        &compiled.statistical_datasets()["records-by-category"].definition_digest;
    database
        .admin
        .execute(
            "INSERT INTO registry_internal.registry_statistical_release_versions
                 (dataset_id, period_code, release_version, release_status,
                  history_head_position, snapshot_reference, computed_at,
                  package_digest, definition_digest, content_digest)
             SELECT 'records-by-category', $1, 1, 'final', 1,
                    snapshot_reference, transaction_timestamp(), $2, $3, $4
               FROM registry_internal.registry_revision_commits
              WHERE commit_position = 0",
            &[
                &conflict_period,
                &identity.package_digest,
                definition_digest,
                &format!("sha256:{}", "0".repeat(64)),
            ],
        )
        .await
        .expect("fixture installs a competing release based on a newer head");
    publish_pause.resume();
    let conflict = conflict_task.await.expect("conflicting publication joins");
    let conflict =
        validate_openapi_json_response(&publisher_openapi, publish_path, "post", conflict, 409)
            .await;
    assert_eq!(conflict["code"], "statistical_dataset.version_conflict");

    let list = send(
        &app,
        Method::GET,
        "/v1/statistics/records-by-category/releases?accessProfile=reader&$top=10",
        Some(claims("reader", false)),
        &[],
        Vec::new(),
    )
    .await;
    let list = validate_openapi_json_response(&reader_openapi, list_path, "get", list, 200).await;
    assert_eq!(list["items"][0]["version"], 1);

    let series = send(
        &app,
        Method::GET,
        &format!(
            "/v1/statistics/records-by-category/releases:series?accessProfile=reader&from={prior_period}&to={prior_period}"
        ),
        Some(claims("reader", false)),
        &[],
        Vec::new(),
    )
    .await;
    let series =
        validate_openapi_json_response(&reader_openapi, series_path, "get", series, 200).await;
    assert_eq!(series["periods"][0]["version"]["version"], 1);

    for (path, uri) in [
        (
            latest_path,
            format!(
                "/v1/statistics/records-by-category/releases/{prior_period}?accessProfile=reader"
            ),
        ),
        (
            exact_path,
            format!(
                "/v1/statistics/records-by-category/releases/{prior_period}/versions/1?accessProfile=reader"
            ),
        ),
    ] {
        let response = send(
            &app,
            Method::GET,
            &uri,
            Some(claims("reader", false)),
            &[],
            Vec::new(),
        )
        .await;
        let response =
            validate_openapi_json_response(&reader_openapi, path, "get", response, 200).await;
        assert_eq!(response["release"]["version"], 1);
    }

    let withdrawal_body = json!({"reason":"source-data-error"});
    validate_openapi_request(
        &publisher_openapi,
        withdrawal_path,
        "post",
        &withdrawal_body,
    );
    let withdrawn = send(
        &app,
        Method::POST,
        &format!(
            "/v1/statistics/records-by-category/releases/{prior_period}/versions/1/withdrawal?accessProfile=publisher"
        ),
        Some(claims("publisher", false)),
        &[
            ("content-type", "application/json"),
            ("idempotency-key", "openapi-wire-withdrawal"),
        ],
        serde_json::to_vec(&withdrawal_body).expect("withdrawal request serializes"),
    )
    .await;
    let withdrawn =
        validate_openapi_json_response(&publisher_openapi, withdrawal_path, "post", withdrawn, 200)
            .await;
    assert_eq!(withdrawn["withdrawal"]["reason"], "source-data-error");

    let gone = send(
        &app,
        Method::GET,
        &format!(
            "/v1/statistics/records-by-category/releases/{prior_period}/versions/1?accessProfile=reader"
        ),
        Some(claims("reader", false)),
        &[],
        Vec::new(),
    )
    .await;
    let gone = validate_openapi_json_response(&reader_openapi, exact_path, "get", gone, 410).await;
    assert_eq!(gone["code"], "statistical_dataset.version_withdrawn");
    assert_eq!(gone["reasonCode"], "source-data-error");

    corrupt_category_dimension(&database, &compiled).await;
    let domain = send(
        &app,
        Method::GET,
        &format!("{live_path}?accessProfile=analyst&from={current_period}&to={current_period}"),
        Some(claims("analyst", true)),
        &[],
        Vec::new(),
    )
    .await;
    let domain =
        validate_openapi_json_response(&analyst_openapi, live_path, "get", domain, 500).await;
    assert_eq!(domain["code"], "statistical_dataset.domain_violation");
    assert_eq!(
        domain["fieldPath"],
        "statisticalDatasets[id=records-by-category].dimensions[id=category]"
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caller_filtered_openapi_hides_an_inaccessible_statistical_default() {
    let database = TestDatabase::create(2).await;
    let (migration, migration_task) = database.connect_migration().await;
    let mut source = statistics_registry_source();
    source["accessProfiles"][0]["requiredScopes"] = json!(["statistics.narrow"]);
    let compiled = Arc::new(compile_statistics_registry(source));
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("compiled schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "package-statistics-openapi-ambiguous-1",
        },
    )
    .await
    .expect("runtime identity initializes");
    migration_task.abort();
    let app = statistics_router(
        database.runtime_config.build_pool().expect("pool builds"),
        compiled,
        identity,
        RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives"),
        database.audit(
            AuditProfile::production_from_secret_bytes(vec![0x7d; 32].into())
                .expect("audit profile is keyed"),
        ),
        Arc::new(std::sync::Mutex::new(Vec::new())),
        None,
    );
    let openapi = openapi_for(&app, "analyst-wide", true).await;
    let path = "/v1/statistics/records-by-category:live";
    let profile = operation_parameter(&openapi, path, "get", "query", "accessProfile");
    assert_eq!(profile["required"], true);
    assert!(profile["schema"].get("default").is_none());
    assert_eq!(profile["schema"]["const"], "analyst-wide");
    let operation = &openapi["paths"][path]["get"];
    assert_eq!(operation["x-registry-accessProfile"], "analyst-wide");
    assert!(operation.get("x-registry-accessProfiles").is_none());
    assert!(operation.get("x-registry-defaultAccessProfile").is_none());
    assert!(!serde_json::to_string(operation)
        .unwrap()
        .contains("\"analyst\""));
    let period = month_code(Utc::now().date_naive());

    let omitted = send(
        &app,
        Method::GET,
        &format!("{path}?from={period}&to={period}"),
        Some(claims("analyst-wide", true)),
        &[],
        Vec::new(),
    )
    .await;
    let omitted = validate_openapi_json_response(&openapi, path, "get", omitted, 404).await;
    assert_eq!(omitted["code"], "resource.not_found");

    let explicit = send(
        &app,
        Method::GET,
        &format!("{path}?accessProfile=analyst-wide&from={period}&to={period}"),
        Some(claims("analyst-wide", true)),
        &[],
        Vec::new(),
    )
    .await;
    let explicit = validate_openapi_json_response(&openapi, path, "get", explicit, 200).await;
    assert_eq!(explicit["live"]["accessProfile"], "analyst-wide");
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quarterly_ranges_reject_multibyte_malformed_periods_without_panicking() {
    let database = TestDatabase::create(2).await;
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = Arc::new(quarterly_registry());
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("compiled schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "package-statistics-quarter-period-1",
        },
    )
    .await
    .expect("runtime identity initializes");
    migration_task.abort();
    let app = statistics_router(
        database.runtime_config.build_pool().expect("pool builds"),
        compiled,
        identity,
        RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives"),
        database.audit(
            AuditProfile::production_from_secret_bytes(vec![0x7e; 32].into())
                .expect("audit profile is keyed"),
        ),
        Arc::new(std::sync::Mutex::new(Vec::new())),
        None,
    );
    let analyst_openapi = openapi_for(&app, "analyst", true).await;
    let live_path = "/v1/statistics/records-by-category:live";
    for (query, field_path) in [
        ("from=2025%E2%82%AC&to=2025-Q1", "from"),
        ("from=2025-Q1&to=2025%E2%82%AC", "to"),
    ] {
        let malformed = send(
            &app,
            Method::GET,
            &format!("{live_path}?accessProfile=analyst&{query}"),
            Some(claims("analyst", true)),
            &[],
            Vec::new(),
        )
        .await;
        let malformed =
            validate_openapi_json_response(&analyst_openapi, live_path, "get", malformed, 400)
                .await;
        assert_eq!(malformed["code"], "query.invalid");
        assert_eq!(malformed["fieldPath"], field_path);
    }

    let valid_live = send(
        &app,
        Method::GET,
        &format!("{live_path}?accessProfile=analyst&from=2025-Q1&to=2025-Q1"),
        Some(claims("analyst", true)),
        &[],
        Vec::new(),
    )
    .await;
    let valid_live =
        validate_openapi_json_response(&analyst_openapi, live_path, "get", valid_live, 200).await;
    assert_eq!(valid_live["periods"][0]["code"], "2025-Q1");

    let published = publish(
        &app,
        "2025-Q1",
        "quarter-range-release",
        "final",
        claims("publisher", false),
    )
    .await;
    assert_eq!(published.status(), StatusCode::CREATED);
    let reader_openapi = openapi_for(&app, "reader", false).await;
    let series_path = "/v1/statistics/records-by-category/releases:series";
    for (query, field_path) in [
        ("from=2025%E2%82%AC&to=2025-Q1", "from"),
        ("from=2025-Q1&to=2025%E2%82%AC", "to"),
    ] {
        let malformed = send(
            &app,
            Method::GET,
            &format!("{series_path}?accessProfile=reader&{query}"),
            Some(claims("reader", false)),
            &[],
            Vec::new(),
        )
        .await;
        let malformed =
            validate_openapi_json_response(&reader_openapi, series_path, "get", malformed, 400)
                .await;
        assert_eq!(malformed["code"], "query.invalid");
        assert_eq!(malformed["fieldPath"], field_path);
    }
    let valid_series = send(
        &app,
        Method::GET,
        &format!("{series_path}?accessProfile=reader&from=2025-Q1&to=2025-Q1&status=final"),
        Some(claims("reader", false)),
        &[],
        Vec::new(),
    )
    .await;
    let valid_series =
        validate_openapi_json_response(&reader_openapi, series_path, "get", valid_series, 200)
            .await;
    assert_eq!(valid_series["periods"][0]["code"], "2025-Q1");
    database.cleanup().await;
}

async fn openapi_for(app: &axum::Router, profile: &str, boundaries: bool) -> Value {
    let response = send(
        app,
        Method::GET,
        &format!("/openapi.json?accessProfile={profile}"),
        Some(claims(profile, boundaries)),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "{profile} OpenAPI serves"
    );
    body_json(response).await
}

fn assert_operation_parameters(
    openapi: &Value,
    path: &str,
    method: &str,
    expected: &[(&str, &str, bool)],
) {
    let actual = openapi["paths"][path][method]["parameters"]
        .as_array()
        .unwrap_or_else(|| panic!("{method} {path} declares parameters"))
        .iter()
        .map(|parameter| {
            (
                parameter["in"]
                    .as_str()
                    .expect("parameter location")
                    .to_owned(),
                parameter["name"]
                    .as_str()
                    .expect("parameter name")
                    .to_owned(),
                parameter["required"]
                    .as_bool()
                    .expect("parameter required flag"),
            )
        })
        .collect::<BTreeSet<_>>();
    let expected = expected
        .iter()
        .map(|(location, name, required)| ((*location).to_owned(), (*name).to_owned(), *required))
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected, "{method} {path} parameter contract");

    let template_parameters = path
        .split('{')
        .skip(1)
        .map(|suffix| {
            suffix
                .split_once('}')
                .unwrap_or_else(|| panic!("{path} has a closed path template"))
                .0
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    let declared_path_parameters = actual
        .iter()
        .filter(|(location, _, _)| location == "path")
        .map(|(_, name, required)| {
            assert!(
                *required,
                "{method} {path} path parameter {name} is required"
            );
            name.clone()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        declared_path_parameters, template_parameters,
        "{method} {path} declares every and only its path templates"
    );
}

fn operation_parameter<'a>(
    openapi: &'a Value,
    path: &str,
    method: &str,
    location: &str,
    name: &str,
) -> &'a Value {
    openapi["paths"][path][method]["parameters"]
        .as_array()
        .expect("operation parameters are an array")
        .iter()
        .find(|parameter| parameter["in"] == location && parameter["name"] == name)
        .unwrap_or_else(|| panic!("{method} {path} declares {location} parameter {name}"))
}

fn assert_operation_media(
    openapi: &Value,
    path: &str,
    method: &str,
    status: &str,
    expected: &[&str],
) {
    let actual = openapi["paths"][path][method]["responses"][status]["content"]
        .as_object()
        .unwrap_or_else(|| panic!("{method} {path} response {status} declares content"))
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected = expected.iter().map(|value| (*value).to_owned()).collect();
    assert_eq!(actual, expected, "{method} {path} response {status} media");
}

fn assert_request_media(openapi: &Value, path: &str, method: &str, expected: &[&str]) {
    let request = &openapi["paths"][path][method]["requestBody"];
    assert_eq!(
        request["required"], true,
        "{method} {path} request body is required"
    );
    let actual = request["content"]
        .as_object()
        .unwrap_or_else(|| panic!("{method} {path} declares request content"))
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected = expected.iter().map(|value| (*value).to_owned()).collect();
    assert_eq!(actual, expected, "{method} {path} request media");
}

fn validate_openapi_request(openapi: &Value, path: &str, method: &str, document: &Value) {
    let schema =
        &openapi["paths"][path][method]["requestBody"]["content"]["application/json"]["schema"];
    assert_openapi_schema_accepts(
        openapi,
        schema,
        document,
        &format!("{method} {path} request"),
    );
}

async fn validate_openapi_json_response(
    openapi: &Value,
    path: &str,
    method: &str,
    response: Response<Body>,
    expected_status: u16,
) -> Value {
    assert_eq!(
        response.status().as_u16(),
        expected_status,
        "{method} {path}"
    );
    let media = response
        .headers()
        .get("content-type")
        .expect("wire response declares content type")
        .to_str()
        .expect("wire content type is ASCII")
        .split(';')
        .next()
        .expect("wire content type has a media type")
        .trim()
        .to_owned();
    let status = expected_status.to_string();
    let schema = &openapi["paths"][path][method]["responses"][&status]["content"][&media]["schema"];
    assert!(
        schema.is_object(),
        "{method} {path} response {status} documents wire media {media}"
    );
    if method == "post" && expected_status < 300 {
        assert!(response.headers().contains_key("repr-digest"));
        assert!(
            openapi["paths"][path][method]["responses"][&status]["headers"]
                .get("Repr-Digest")
                .is_some()
        );
    }
    let document = body_json(response).await;
    assert_openapi_schema_accepts(
        openapi,
        schema,
        &document,
        &format!("{method} {path} response {status}"),
    );
    document
}

fn assert_openapi_schema_accepts(openapi: &Value, schema: &Value, document: &Value, label: &str) {
    let mut root = schema.clone();
    let root_object = root
        .as_object_mut()
        .unwrap_or_else(|| panic!("{label} schema is an object"));
    root_object.insert(
        "$schema".to_owned(),
        json!("https://json-schema.org/draft/2020-12/schema"),
    );
    root_object.insert("components".to_owned(), openapi["components"].clone());
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&root)
        .unwrap_or_else(|error| {
            panic!("{label} schema compiles after component resolution: {error}")
        });
    assert!(
        validator.is_valid(document),
        "{label} rejects actual wire document: {document}"
    );
}

async fn corrupt_category_dimension(
    database: &TestDatabase,
    registry: &registry_breg::CompiledRegistry,
) {
    let entity = &registry.entities()["record"];
    let category = &entity.fields["category"].physical_name;
    let constraints = database
        .admin
        .query(
            "SELECT constraint_row.conname
               FROM pg_catalog.pg_constraint AS constraint_row
              WHERE constraint_row.conrelid = pg_catalog.to_regclass($1)
                AND constraint_row.contype = 'c'
                AND pg_catalog.pg_get_constraintdef(constraint_row.oid) LIKE '%' || $2 || '%'",
            &[
                &format!("registry_data.{}", quote_identifier(&entity.physical_table)),
                category,
            ],
        )
        .await
        .expect("dimension constraints resolve");
    assert!(
        !constraints.is_empty(),
        "the vocabulary has a storage check"
    );
    for constraint in constraints {
        let constraint: String = constraint.get(0);
        database
            .admin
            .batch_execute(&format!(
                "ALTER TABLE registry_data.{} DROP CONSTRAINT {}",
                quote_identifier(&entity.physical_table),
                quote_identifier(&constraint)
            ))
            .await
            .expect("fixture removes the dimension storage check");
    }
    database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.{} SET {} = 'openapi-domain-canary'
                  WHERE record_id = '00000000-0000-4000-8000-000000000001'::uuid",
                quote_identifier(&entity.physical_table),
                quote_identifier(category)
            ),
            &[],
        )
        .await
        .expect("fixture inserts an out-of-domain source value");
}

fn statistics_router(
    pool: registry_breg::postgres::RuntimePool,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    audit: RegistryAudit,
    trace: Arc<std::sync::Mutex<Vec<String>>>,
    publish_pause: Option<StatisticsPublishPause>,
) -> axum::Router {
    statistics_router_with_pauses(
        pool,
        registry,
        identity,
        lock_key,
        audit,
        trace,
        publish_pause,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn statistics_router_with_pauses(
    pool: registry_breg::postgres::RuntimePool,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    audit: RegistryAudit,
    trace: Arc<std::sync::Mutex<Vec<String>>>,
    publish_pause: Option<StatisticsPublishPause>,
    withdrawal_pause: Option<StatisticsWithdrawalPause>,
) -> axum::Router {
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x31; 32]), Duration::from_secs(300))
            .expect("cursor key is valid"),
    );
    let records = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit.clone(),
        cursors.clone(),
    ));
    let statistics = PostgresStatisticsService::new(
        pool,
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit,
    )
    .with_trace_for_test(trace);
    let statistics = match publish_pause {
        Some(pause) => statistics.with_publish_pause_for_test(pause),
        None => statistics,
    };
    let statistics = match withdrawal_pause {
        Some(pause) => statistics.with_withdrawal_pause_for_test(pause),
        None => statistics,
    };
    let statistics = Arc::new(statistics);
    router(Arc::new(
        HttpService::new(
            registry,
            ReadRuntimeIdentity {
                package_revision: identity.activation_id,
                schema_fingerprint: identity.schema_fingerprint,
            },
            records,
            Arc::new(AlwaysReady),
            cursors,
        )
        .with_statistics(statistics),
    ))
}

async fn seed_records(
    pool: &registry_breg::postgres::RuntimePool,
    lock_key: RegistryLockKey,
    identity: &registry_breg::postgres::ExpectedRegistryIdentity,
    registry: &registry_breg::CompiledRegistry,
    today: NaiveDate,
    prior: NaiveDate,
) {
    let claims = ClaimContext::for_compiled(
        registry,
        "record",
        Some("fixture-seeder".to_owned()),
        "seed",
        None,
        Vec::new(),
    )
    .expect("seed context is compiler-bound");
    let mut client = pool.get_for_test().await.expect("runtime connection opens");
    let transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(2),
        identity,
        &claims,
    )
    .await
    .expect("seed transaction opens");
    let entity = &registry.entities()["record"];
    let table = quote_identifier(&entity.physical_table);
    let subject = quote_identifier(&entity.fields["subject"].physical_name);
    let active = quote_identifier(&entity.fields["active"].physical_name);
    let category = quote_identifier(&entity.fields["category"].physical_name);
    let event_date = quote_identifier(&entity.fields["event-date"].physical_name);
    let jurisdiction = quote_identifier(&entity.fields["jurisdiction"].physical_name);
    let sql = format!(
        "INSERT INTO registry_data.{table}
             (record_id, record_revision, record_lifecycle,
              {subject}, {active}, {category}, {event_date}, {jurisdiction})
         VALUES ($1::text::uuid, 1, 'active', $1, $2, $3, $4, $5)"
    );
    let rows = [
        (
            "00000000-0000-4000-8000-000000000001",
            true,
            "a",
            today,
            "north",
        ),
        (
            "00000000-0000-4000-8000-000000000002",
            true,
            "a",
            today,
            "north",
        ),
        (
            "00000000-0000-4000-8000-000000000003",
            true,
            "b",
            today,
            "north",
        ),
        (
            "00000000-0000-4000-8000-000000000004",
            true,
            "a",
            prior,
            "north",
        ),
        (
            "00000000-0000-4000-8000-000000000005",
            true,
            "a",
            prior,
            "north",
        ),
        (
            "00000000-0000-4000-8000-000000000006",
            true,
            "a",
            prior,
            "north",
        ),
        (
            "00000000-0000-4000-8000-000000000007",
            true,
            "a",
            prior,
            "north",
        ),
        (
            "00000000-0000-4000-8000-000000000008",
            true,
            "a",
            prior,
            "north",
        ),
        (
            "00000000-0000-4000-8000-000000000009",
            true,
            "a",
            prior,
            "south",
        ),
        (
            "00000000-0000-4000-8000-000000000010",
            true,
            "b",
            prior,
            "south",
        ),
    ];
    for (id, value, code, date, boundary) in rows {
        transaction
            .transaction_for_test()
            .execute(&sql, &[&id, &value, &code, &date, &boundary])
            .await
            .expect("seed row inserts through runtime RLS");
    }
    transaction
        .commit()
        .await
        .expect("seed transaction commits");
}

async fn insert_other_definition_release(
    database: &TestDatabase,
    period: &str,
    source_version: i64,
    old_definition_version: i64,
) {
    let old_definition_digest = format!("sha256:{}", "0".repeat(64));
    database
        .admin
        .execute(
            "INSERT INTO registry_internal.registry_statistical_release_versions
                 (dataset_id, period_code, release_version, release_status,
                  history_head_position, snapshot_reference, computed_at,
                  package_digest, definition_digest, content_digest)
             SELECT dataset_id, period_code, $3, release_status,
                    history_head_position, snapshot_reference, computed_at,
                    package_digest, $4, content_digest
               FROM registry_internal.registry_statistical_release_versions
              WHERE dataset_id = 'records-by-category' AND period_code = $1
                AND release_version = $2",
            &[
                &period,
                &source_version,
                &old_definition_version,
                &old_definition_digest,
            ],
        )
        .await
        .expect("fixture inserts an older-definition immutable header");
    database
        .admin
        .execute(
            "INSERT INTO registry_internal.registry_statistical_release_contents
                 (dataset_id, period_code, release_version, document)
             SELECT dataset_id, period_code, $3, document
               FROM registry_internal.registry_statistical_release_contents
              WHERE dataset_id = 'records-by-category' AND period_code = $1
                AND release_version = $2",
            &[&period, &source_version, &old_definition_version],
        )
        .await
        .expect("fixture inserts inaccessible older-definition content");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changing_population_through_package_apply_starts_a_new_release_series() {
    use registry_breg::migration::{
        apply_verified_package, ActivationDeployment, ApplyPrecondition, ApplyRoles, ApplyTimeouts,
        ApplyVerifiedPackageRequest,
    };
    use registry_breg::package::{
        load_package, prepare_package, PackageBuildRequest, PackageLoadContext,
        PackageMigrationPlanInput, PackageSourceFile,
    };
    use registry_breg::postgres::managed_schema_fingerprint;
    let database = TestDatabase::create(4).await;
    let mut source = statistics_registry_source();
    source["package"] = json!({"sourceRevision":"statistics-definition-test"});
    let prior = compile_statistics_registry(source.clone());
    let (mut migration, task) = database.connect_migration().await;
    let transaction = migration.transaction().await.unwrap();
    install_compiled_schema(&transaction, &prior, &database.runtime_role)
        .await
        .unwrap();
    let fingerprint = managed_schema_fingerprint(
        &transaction,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(&prior),
    )
    .await
    .unwrap();
    transaction.rollback().await.unwrap();
    task.abort();
    let make_package = |source: &Value, from: Option<&str>, plan| {
        let prepared = prepare_package(PackageBuildRequest {
            from_package_digest: from.map(str::to_owned),
            compiler_source_revision: "statistics-definition-test".to_owned(),
            schema_fingerprint: fingerprint.clone(),
            project: PackageSourceFile {
                path: "source/registry.yaml".to_owned(),
                bytes: serde_json::to_vec(source).unwrap(),
            },
            modules: Vec::new(),
            fixture_journeys: PackageSourceFile {
                path: "tests/journeys.yaml".to_owned(),
                bytes: br#"apiVersion: registry.registrystack.org/breg-journeys/v1
journeys:
  - id: population
    steps:
      - id: empty
        entity: record
        accessProfile: publisher
        claims: {principal: package-publisher}
        request: {operation: list}
        expect: {outcome: success, status: 200, count: 0}
"#
                .to_vec(),
            },
            migration_plan: plan,
        })
        .expect("statistical package prepares");
        let root = tempfile::tempdir().unwrap();
        let path = root.path().canonicalize().unwrap().join("package");
        prepared.publish_to_directory(&path).unwrap();
        load_package(
            &path,
            &PackageLoadContext {
                database_initialization_environment: "local",
            },
        )
        .unwrap()
    };
    let initial = make_package(&source, None, PackageMigrationPlanInput::InitialCompiledDdl);
    let audit = database.activation_audit();
    let request = |package, precondition| {
        ApplyVerifiedPackageRequest::new(
            &database.migration_config,
            package,
            ActivationDeployment::new("local", "statistics-definition-test", DATABASE_ID),
            precondition,
            ApplyRoles::new(&database.migration_role, &database.runtime_role),
            ApplyTimeouts::new(Duration::from_secs(5), Duration::from_secs(5)).unwrap(),
            audit.clone(),
        )
    };
    let active = apply_verified_package(request(&initial, ApplyPrecondition::InitialActivation))
        .await
        .expect("initial statistical package applies");
    let pool = database.runtime_config.build_pool().unwrap();
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).unwrap();
    let today = Utc::now().date_naive();
    let prior_date = today
        .with_day(1)
        .unwrap()
        .checked_sub_days(Days::new(1))
        .unwrap();
    let period = month_code(prior_date);
    seed_records(&pool, lock_key, &active, &prior, today, prior_date).await;
    let make_app = |registry: Arc<registry_breg::CompiledRegistry>, identity| {
        statistics_router(
            pool.clone(),
            registry,
            identity,
            lock_key,
            database
                .audit(AuditProfile::production_from_secret_bytes(vec![0x79; 32].into()).unwrap()),
            Arc::new(std::sync::Mutex::new(Vec::new())),
            None,
        )
    };
    let app = make_app(Arc::new(prior.clone()), active.clone());
    let old = publish(
        &app,
        &period,
        "definition-old",
        "final",
        claims("publisher", false),
    )
    .await;
    assert_eq!(old.status(), StatusCode::CREATED);
    let old = body_json(old).await;
    let old_bytes: Vec<u8> = database
        .admin
        .query_one(
            "SELECT document FROM registry_internal.registry_statistical_release_contents",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    source["statisticalDatasets"][0]["population"] = json!("active eq false");
    let candidate = compile_statistics_registry(source.clone());
    assert_ne!(
        prior.statistical_datasets()["records-by-category"].definition_digest,
        candidate.statistical_datasets()["records-by-category"].definition_digest
    );
    let successor = make_package(
        &source,
        Some(&active.package_digest),
        PackageMigrationPlanInput::Successor {
            prior_registry: Box::new(prior),
        },
    );
    let next = apply_verified_package(request(
        &successor,
        ApplyPrecondition::Successor { current: &active },
    ))
    .await
    .expect("definition-only successor applies through the maintained coordinator");
    assert_ne!(next.activation_id, active.activation_id);
    let app = make_app(Arc::new(candidate), next);
    let hidden = send(
        &app,
        Method::GET,
        &format!(
            "/v1/statistics/records-by-category/releases/{period}/versions/1?accessProfile=reader"
        ),
        Some(claims("reader", false)),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(hidden.status(), StatusCode::NOT_FOUND);
    let latest = send(
        &app,
        Method::GET,
        &format!("/v1/statistics/records-by-category/releases/{period}?accessProfile=reader"),
        Some(claims("reader", false)),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(latest.status(), StatusCode::NOT_FOUND);
    let new = publish(
        &app,
        &period,
        "definition-new",
        "provisional",
        claims("publisher", false),
    )
    .await;
    assert_eq!(new.status(), StatusCode::CREATED);
    let new = body_json(new).await;
    assert_eq!(new["status"], "provisional");
    // Stored version keys remain monotonic across definitions; series visibility is definition-specific.
    assert_eq!(new["version"], 2);
    assert_ne!(old["definitionDigest"], new["definitionDigest"]);
    let listing = send(
        &app,
        Method::GET,
        "/v1/statistics/records-by-category/releases?accessProfile=reader",
        Some(claims("reader", false)),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(listing.status(), StatusCode::OK);
    let listing = body_json(listing).await;
    assert_eq!(listing["items"].as_array().unwrap().len(), 1);
    assert_eq!(listing["items"][0]["version"], 2);
    let retained:Vec<u8> = database.admin.query_one("SELECT document FROM registry_internal.registry_statistical_release_contents WHERE release_version = 1",&[]).await.unwrap().get(0);
    assert_eq!(retained, old_bytes);
    drop(app);
    drop(pool);
    database.cleanup().await;
}

fn compiled_registry() -> registry_breg::CompiledRegistry {
    compile_statistics_registry(statistics_registry_source())
}

fn quarterly_registry() -> registry_breg::CompiledRegistry {
    let mut source = statistics_registry_source();
    source["statisticalDatasets"][0]["period"]["granularity"] = json!("quarter");
    source["statisticalDatasets"][0]["period"]["firstPeriod"] = json!("2025-Q1");
    compile_statistics_registry(source)
}

fn statistics_registry_source() -> Value {
    json!({
        "apiVersion":"registry.registrystack.org/v1alpha1",
        "kind":"RegistryProject",
        "registry":{"id":"statistics-http-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://statistics.example.test"},
        "entities":[{
            "id":"record","primaryDataset":"statistics-http","route":"records","mutationMode":"mutable",
            "accessLog":{"subjectField":"subject"},
            "fields":[
                {"id":"subject","type":"string","maxLength":128,"required":true,"classification":"internal"},
                {"id":"active","type":"boolean","required":true,"classification":"internal"},
                {"id":"category","type":"vocabulary-code","vocabulary":"category","required":true,"classification":"internal"},
                {"id":"event-date","type":"date","required":true,"classification":"internal"},
                {"id":"jurisdiction","type":"vocabulary-code","vocabulary":"jurisdiction","required":true,"classification":"internal"}
            ]
        }],
        "accessProfiles":[
            {"id":"analyst","default":true,"principalClaim":"principal","permissions":[{
                "entity":"record","operations":["list"],
                "readableFields":["subject","active","category","event-date","jurisdiction"],
                "filterableFields":["subject","active","category","event-date","jurisdiction"],"allowCount":true,
                "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdictions","operator":"in"}]
            }]},
            {"id":"analyst-wide","principalClaim":"principal","requiredScopes":["statistics.wide"],"permissions":[{
                "entity":"record","operations":["list"],
                "readableFields":["subject","active","category","event-date","jurisdiction"],
                "filterableFields":["subject","active","category","event-date","jurisdiction"],"allowCount":true,"rowBoundaries":[]
            }]},
            {"id":"publisher","principalClaim":"principal","requiredScopes":["statistics.publish"],"permissions":[{
                "entity":"record","operations":["list"],
                "readableFields":["subject","active","category","event-date","jurisdiction"],
                "filterableFields":["subject","active","category","event-date","jurisdiction"],"allowCount":true,"rowBoundaries":[]
            }]},
            {"id":"seed","principalClaim":"principal","permissions":[{
                "entity":"record","operations":["create"],
                "writableFields":["subject","active","category","event-date","jurisdiction"],"rowBoundaries":[]
            }]},
            {"id":"reader","principalClaim":"principal","permissions":[]}
        ],
        "vocabularies":[
            {"id":"category","values":["a","b"]},
            {"id":"jurisdiction","values":["north","south"]}
        ],
        "statisticalDatasets":[{
            "id":"records-by-category","unit":"record","population":"active eq true",
            "period":{"kind":"flow","field":"event-date","granularity":"month","firstPeriod":"2025-01"},
            "dimensions":["category"],"disclosure":{"minimumCount":5,"roundingBase":5},
            "live":["analyst","analyst-wide"],"releases":{"publisher":"publisher","readers":["reader"]}
        }]
    })
}

fn compile_statistics_registry(source: Value) -> registry_breg::CompiledRegistry {
    let bytes = serde_json::to_vec(&source).expect("fixture serializes");
    let project = parse_project_json(&bytes).expect("fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("fixture compiles")
}

fn cap_registry() -> registry_breg::CompiledRegistry {
    let codes = (0..50)
        .map(|value| format!("c{value:02}"))
        .collect::<Vec<_>>();
    let source = json!({
        "apiVersion":"registry.registrystack.org/v1alpha1",
        "kind":"RegistryProject",
        "registry":{"id":"statistics-cap-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://statistics-caps.example.test"},
        "entities":[{
            "id":"record","primaryDataset":"statistics-caps","route":"records","mutationMode":"mutable",
            "fields":[
                {"id":"active","type":"boolean","required":true,"classification":"internal"},
                {"id":"category","type":"vocabulary-code","vocabulary":"category","required":true,"classification":"internal"},
                {"id":"event-date","type":"date","required":true,"classification":"internal"}
            ]
        }],
        "accessProfiles":[
            {"id":"analyst","default":true,"principalClaim":"principal","permissions":[{
                "entity":"record","operations":["list"],"readableFields":["active","category","event-date"],
                "filterableFields":["active","category","event-date"],"allowCount":true,"rowBoundaries":[]
            }]},
            {"id":"publisher","principalClaim":"principal","requiredScopes":["statistics.publish"],"permissions":[{
                "entity":"record","operations":["list"],"readableFields":["active","category","event-date"],
                "filterableFields":["active","category","event-date"],"allowCount":true,"rowBoundaries":[]
            }]},
            {"id":"reader","principalClaim":"principal","permissions":[]}
        ],
        "vocabularies":[{"id":"category","values":codes}],
        "statisticalDatasets":[{
            "id":"daily-by-category","unit":"record","population":"active eq true",
            "period":{"kind":"flow","field":"event-date","granularity":"day","firstPeriod":"2025-01-01"},
            "dimensions":["category"],"disclosure":{"minimumCount":5,"roundingBase":5},
            "live":["analyst"],"releases":{"publisher":"publisher","readers":["reader"]}
        }]
    });
    let bytes = serde_json::to_vec(&source).expect("cap fixture serializes");
    let project = parse_project_json(&bytes).expect("cap fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("cap fixture compiles")
}

fn claims(profile: &str, boundaries: bool) -> VerifiedRequestClaims {
    let mut values = BTreeMap::new();
    if boundaries {
        values.insert(
            "jurisdictions".to_owned(),
            VerifiedClaimValue::direct_string_set(["north"])
                .expect("boundary claim is a verified string set"),
        );
    }
    VerifiedRequestClaims::authenticated(
        "principal",
        PRINCIPAL_CANARY,
        match profile {
            "publisher" => BTreeSet::from(["statistics.publish".to_owned()]),
            "analyst-wide" => BTreeSet::from(["statistics.wide".to_owned()]),
            _ => BTreeSet::new(),
        },
        None,
        values,
    )
    .unwrap_or_else(|_| panic!("{profile} claims are valid"))
}

async fn publish(
    app: &axum::Router,
    period: &str,
    key: &str,
    status: &str,
    claims: VerifiedRequestClaims,
) -> Response<Body> {
    send(
        app,
        Method::POST,
        &format!(
            "/v1/statistics/records-by-category/releases/{period}/versions?accessProfile=publisher"
        ),
        Some(claims),
        &[
            ("accept", "text/csv;q=1,application/json;q=0.5"),
            ("content-type", "application/json"),
            ("idempotency-key", key),
        ],
        serde_json::to_vec(&json!({"status":status})).expect("publish body serializes"),
    )
    .await
}

async fn withdraw(
    app: &axum::Router,
    period: &str,
    version: u64,
    key: &str,
    claims: VerifiedRequestClaims,
) -> Response<Body> {
    send(
        app,
        Method::POST,
        &format!(
            "/v1/statistics/records-by-category/releases/{period}/versions/{version}/withdrawal?accessProfile=publisher"
        ),
        Some(claims),
        &[("accept", "text/csv;q=1,application/json;q=0.5"), ("content-type", "application/json"), ("idempotency-key", key)],
        serde_json::to_vec(&json!({"reason":"source-data-error"}))
            .expect("withdrawal body serializes"),
    )
    .await
}

async fn send(
    app: &axum::Router,
    method: Method,
    uri: &str,
    claims: Option<VerifiedRequestClaims>,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> Response<Body> {
    send_with_deadline(app, method, uri, claims, headers, body, None).await
}

async fn send_with_deadline(
    app: &axum::Router,
    method: Method,
    uri: &str,
    claims: Option<VerifiedRequestClaims>,
    headers: &[(&str, &str)],
    body: Vec<u8>,
    deadline: Option<tokio::time::Instant>,
) -> Response<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(
            HeaderName::from_bytes(name.as_bytes()).expect("header name is valid"),
            *value,
        );
    }
    let mut request = builder.body(Body::from(body)).expect("request builds");
    if let Some(claims) = claims {
        request.extensions_mut().insert(claims);
    }
    if let Some(deadline) = deadline {
        set_request_deadline_for_test(&mut request, deadline);
    }
    let mut app = app.clone();
    app.call(request).await.expect("router returns a response")
}

async fn body_bytes(response: Response<Body>) -> Vec<u8> {
    to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .expect("response body reads")
        .to_vec()
}

async fn body_json(response: Response<Body>) -> Value {
    serde_json::from_slice(&body_bytes(response).await).expect("response is JSON")
}

fn total_cell(document: &Value, period: &str) -> u64 {
    document["cells"]
        .as_array()
        .expect("cells are an array")
        .iter()
        .find(|cell| cell["period"] == period && cell["dimensions"]["category"] == "_T")
        .and_then(|cell| cell["value"].as_u64())
        .expect("period total cell is present")
}

/// Each cell of one period as `[category, value, status]`, in document order.
fn category_cells(document: &Value, period: &str) -> Value {
    document["cells"]
        .as_array()
        .expect("cells are an array")
        .iter()
        .filter(|cell| cell["period"] == period)
        .map(|cell| {
            json!([
                cell["dimensions"]["category"],
                cell["value"],
                cell["status"]
            ])
        })
        .collect()
}

fn month_code(date: NaiveDate) -> String {
    format!("{:04}-{:02}", date.year(), date.month())
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}
