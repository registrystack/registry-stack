// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "postgres-test", feature = "tooling"))]

#[path = "support/pilot_acceptance_harness.rs"]
#[allow(dead_code)]
mod pilot_acceptance_harness;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, Response, StatusCode};
use chrono::{Days, Utc};
use pilot_acceptance_harness::{response_json, PilotHarness};
use registry_breg::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedRequestClaims,
};
use registry_breg::cursor::CursorCodec;
use registry_breg::history_erasure::{
    erase_record_history, HistoryErasureRequest, HistoryErasureTimeouts, RecordHistoryErasureTarget,
};
use registry_breg::history_rebaseline::{
    rebaseline_history_coverage, HistoryRebaselineRequest, HistoryRebaselineTimeouts,
};
use registry_breg::postgres::{
    ExpectedRegistryIdentity, PostgresRecordReadService, PostgresStatisticsService,
    RegistryLockKey, StatisticsPublishPause,
};
use registry_breg::statistics::{current_period, PeriodGranularity};
use registry_platform_audit::AuditProfile;
use serde_json::{json, Value};
use tower::Service as _;
use uuid::Uuid;
use zeroize::Zeroizing;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publication_uses_null_snapshot_until_erased_history_is_rebaselined() {
    let harness = PilotHarness::start("facility").await;
    let today = Utc::now().date_naive();
    let current = current_period(PeriodGranularity::Month, today).unwrap();
    let prior_date = current.start.checked_sub_days(Days::new(1)).unwrap();
    let prior = current_period(PeriodGranularity::Month, prior_date).unwrap();
    let operator = harness.token_with_scopes(
        "facility-registry",
        &[("administrative_boundaries", json!(["north-district"]))],
        &["registry:facility:operate"],
    );
    let publisher =
        harness.token_with_scopes("statistics", &[], &["registry:facility:statistics:publish"]);
    let reader =
        harness.token_with_scopes("statistics", &[], &["registry:facility:statistics:read"]);

    let facility = create(
        &harness,
        "facilities",
        &operator,
        "history-facility",
        json!({
            "facilityCode":"F-HISTORY","displayName":"history",
            "administrativeBoundary":"north-district"
        }),
    )
    .await;
    let permit = create(
        &harness,
        "permits",
        &operator,
        "history-permit",
        json!({
            "permitNumber":"P-HISTORY","facility":facility.id,
            "permitType":"water-discharge","validFrom":prior.start.to_string(),
            "validTo":today.checked_add_days(Days::new(60)).unwrap().to_string(),
            "administrativeBoundary":"north-district","importSource":"statistics-history",
            "sourceRecordId":"history-1"
        }),
    )
    .await;
    let patched = harness
        .send(
            Method::PATCH,
            &format!(
                "/v1/records/permits/{}?accessProfile=facility-operator",
                permit.id
            ),
            Some(&operator),
            &[
                ("content-type", "application/json-patch+json"),
                ("idempotency-key", "history-permit-patch"),
                ("if-match", &permit.etag),
            ],
            serde_json::to_vec(&json!([{
                "op":"replace","path":"/data/sourceRecordId","value":"history-2"
            }]))
            .unwrap(),
        )
        .await;
    let status = patched.status();
    let value = response_json(patched).await;
    assert_eq!(status, StatusCode::OK, "{value}");

    let live_path = format!(
        "/v1/statistics/monthly-valid-permits-fields:live?accessProfile=facility-operator&from={0}&to={0}",
        current.code
    );
    let live_before = get_json(&harness, &live_path, &operator).await;

    let (mut migration, migration_task) = harness.database.connect_migration().await;
    let expected = active_identity(&migration).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).unwrap();
    let audit = harness.database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x48; 32].into())
            .expect("history statistics audit profile is keyed"),
    );
    let erased = erase_record_history(
        &mut migration,
        HistoryErasureRequest {
            expected: &expected,
            migration_role: &harness.database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit: &audit,
            operator_reference: "history-statistics-operator",
            reason: "approved statistics history coverage test",
            target: RecordHistoryErasureTarget::new(
                "permit",
                Uuid::parse_str(&permit.id).unwrap(),
                1,
            ),
        },
    )
    .await
    .expect("ordinary history erasure succeeds");
    assert!(erased.coverage_ready);
    assert!(erased.unavailable_after_position.is_some());

    let live_after = get_json(&harness, &live_path, &operator).await;
    assert_eq!(live_after["cells"], live_before["cells"]);

    let publish_path = format!(
        "/v1/statistics/monthly-valid-permits-fields/releases/{}/versions?accessProfile=statistics-publisher",
        prior.code
    );
    let first = publish(&harness, &publish_path, &publisher, "history-publish-1").await;
    assert_eq!(first["version"], 1);
    assert_eq!(first["snapshot"], Value::Null);
    let persisted = migration
        .query_one(
            "SELECT version.history_head_position, version.snapshot_reference,
                    head.latest_position, content.document
               FROM registry_internal.registry_statistical_release_versions AS version
               JOIN registry_internal.registry_statistical_release_contents AS content
                 USING (dataset_id, period_code, release_version)
               JOIN registry_internal.registry_commit_head AS head ON head.singleton
              WHERE version.dataset_id = 'monthly-valid-permits-fields'
                AND version.period_code = $1 AND version.release_version = 1",
            &[&prior.code],
        )
        .await
        .expect("snapshot-less release is persisted");
    assert_eq!(persisted.get::<_, i64>(0), persisted.get::<_, i64>(2));
    assert_eq!(persisted.get::<_, Option<Uuid>>(1), None);
    let persisted_document: Value =
        serde_json::from_slice(&persisted.get::<_, Vec<u8>>(3)).unwrap();
    assert_eq!(persisted_document["release"]["snapshot"], Value::Null);

    let exact_path = format!(
        "/v1/statistics/monthly-valid-permits-fields/releases/{}/versions/1?accessProfile=statistics-reader",
        prior.code
    );
    let exact = get_json(&harness, &exact_path, &reader).await;
    assert_eq!(exact["release"]["snapshot"], Value::Null);
    let csv = harness
        .send(
            Method::GET,
            &exact_path,
            Some(&reader),
            &[("accept", "text/csv")],
            Vec::new(),
        )
        .await;
    assert_eq!(csv.status(), StatusCode::OK);
    let csv = String::from_utf8(
        to_bytes(csv.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(csv.starts_with(
        "period,periodStart,periodEnd,administrative-boundary,expiring-soon,value,status\r\n"
    ));

    let rebaseline = rebaseline_history_coverage(
        &mut migration,
        HistoryRebaselineRequest {
            expected: &expected,
            migration_role: &harness.database.migration_role,
            lock_key,
            timeouts: HistoryRebaselineTimeouts::new(
                Duration::from_secs(5),
                Duration::from_secs(5),
            )
            .unwrap(),
            audit: &audit,
            operator_reference: "history-statistics-operator",
            registry: &harness.registry,
        },
    )
    .await
    .expect("retained current revisions permit a history rebaseline");
    let second = publish(&harness, &publish_path, &publisher, "history-publish-2").await;
    assert_eq!(second["version"], 2);
    assert!(second["snapshot"].as_str().is_some());
    let second_head = migration
        .query_one(
            "SELECT history_head_position, snapshot_reference IS NOT NULL
               FROM registry_internal.registry_statistical_release_versions
              WHERE dataset_id = 'monthly-valid-permits-fields'
                AND period_code = $1 AND release_version = 2",
            &[&prior.code],
        )
        .await
        .unwrap();
    assert_eq!(second_head.get::<_, i64>(0), rebaseline.baseline_position);
    assert!(second_head.get::<_, bool>(1));

    let pause = StatisticsPublishPause::default();
    let paused_app = statistics_router(
        &harness,
        expected.clone(),
        lock_key,
        audit.clone(),
        pause.clone(),
    );
    let paused_path = publish_path.clone();
    let paused = tokio::spawn(async move {
        publish_through_router(
            &paused_app,
            &paused_path,
            "history-publish-after-compute-erasure",
        )
        .await
    });
    pause.wait_until_reached().await;
    let captured_head: i64 = migration
        .query_one(
            "SELECT latest_position
               FROM registry_internal.registry_commit_head
              WHERE singleton",
            &[],
        )
        .await
        .expect("the history head captured by computation remains readable")
        .get(0);
    assert_eq!(captured_head, rebaseline.baseline_position);

    let erased_after_compute = erase_record_history(
        &mut migration,
        HistoryErasureRequest {
            expected: &expected,
            migration_role: &harness.database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit: &audit,
            operator_reference: "history-statistics-race-operator",
            reason: "approved statistics publish coverage race test",
            target: RecordHistoryErasureTarget::new(
                "permit",
                Uuid::parse_str(&permit.id).unwrap(),
                2,
            ),
        },
    )
    .await
    .expect("history erasure between computation and persistence succeeds");
    assert!(!erased_after_compute.coverage_ready);
    let retained_head: i64 = migration
        .query_one(
            "SELECT latest_position
               FROM registry_internal.registry_commit_head
              WHERE singleton",
            &[],
        )
        .await
        .expect("history erasure retains the required commit head")
        .get(0);
    assert_eq!(retained_head, captured_head);

    pause.resume();
    let response = paused.await.expect("paused publication task joins");
    assert_eq!(response.status(), StatusCode::CREATED);
    let third = response_json(response).await;
    assert_eq!(third["version"], 3);
    assert_eq!(third["snapshot"], Value::Null);
    let persisted = migration
        .query_one(
            "SELECT version.history_head_position, version.snapshot_reference,
                    content.document
               FROM registry_internal.registry_statistical_release_versions AS version
               JOIN registry_internal.registry_statistical_release_contents AS content
                 USING (dataset_id, period_code, release_version)
              WHERE version.dataset_id = 'monthly-valid-permits-fields'
                AND version.period_code = $1 AND version.release_version = 3",
            &[&prior.code],
        )
        .await
        .expect("post-erasure publication is persisted");
    assert_eq!(persisted.get::<_, i64>(0), captured_head);
    assert_eq!(persisted.get::<_, Option<Uuid>>(1), None);
    let persisted_document: Value =
        serde_json::from_slice(&persisted.get::<_, Vec<u8>>(2)).unwrap();
    assert_eq!(persisted_document["release"]["snapshot"], Value::Null);

    drop(migration);
    migration_task.abort();
    harness.finish().await;
}

fn statistics_router(
    harness: &PilotHarness,
    expected: ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    audit: registry_breg::audit::RegistryAudit,
    pause: StatisticsPublishPause,
) -> axum::Router {
    let pool = harness
        .database
        .runtime_config
        .build_pool()
        .expect("statistics race pool builds");
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x4f; 32]), Duration::from_secs(300))
            .expect("statistics race cursor key is valid"),
    );
    let records = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        harness.registry.clone(),
        expected.clone(),
        lock_key,
        Duration::from_secs(5),
        audit.clone(),
        cursors.clone(),
    ));
    let statistics = Arc::new(
        PostgresStatisticsService::new(
            pool,
            harness.registry.clone(),
            expected.clone(),
            lock_key,
            Duration::from_secs(5),
            audit,
        )
        .with_publish_pause_for_test(pause),
    );
    router(Arc::new(
        HttpService::new(
            harness.registry.clone(),
            ReadRuntimeIdentity {
                package_revision: expected.activation_id,
                schema_fingerprint: expected.schema_fingerprint,
            },
            records,
            Arc::new(AlwaysReady),
            cursors,
        )
        .with_statistics(statistics),
    ))
}

async fn publish_through_router(app: &axum::Router, path: &str, key: &str) -> Response<Body> {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header("content-type", "application/json")
        .header("idempotency-key", key)
        .body(Body::from(r#"{"status":"final"}"#))
        .expect("paused publication request builds");
    request.extensions_mut().insert(
        VerifiedRequestClaims::authenticated(
            "registry_principal",
            "history-statistics-publisher",
            BTreeSet::from(["registry:facility:statistics:publish".to_owned()]),
            None,
            BTreeMap::new(),
        )
        .expect("publisher claims are valid"),
    );
    let mut app = app.clone();
    app.call(request).await.expect("statistics router responds")
}

struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

struct CreatedRecord {
    id: String,
    etag: String,
}

async fn create(
    harness: &PilotHarness,
    collection: &str,
    token: &str,
    key: &str,
    data: Value,
) -> CreatedRecord {
    let response = harness
        .send_json(
            Method::POST,
            &format!("/v1/records/{collection}?accessProfile=facility-operator"),
            Some(token),
            Some(key),
            json!({"data":data}),
        )
        .await;
    let status = response.status();
    let etag = response
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let value = response_json(response).await;
    assert_eq!(status, StatusCode::CREATED, "{collection}: {value}");
    CreatedRecord {
        id: value["data"]["recordIdentifier"]
            .as_str()
            .unwrap()
            .to_owned(),
        etag,
    }
}

async fn get_json(harness: &PilotHarness, path: &str, token: &str) -> Value {
    let response = harness
        .send(Method::GET, path, Some(token), &[], Vec::new())
        .await;
    let status = response.status();
    let value = response_json(response).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    value
}

async fn publish(harness: &PilotHarness, path: &str, token: &str, key: &str) -> Value {
    let response = harness
        .send_json(
            Method::POST,
            path,
            Some(token),
            Some(key),
            json!({"status":"final"}),
        )
        .await;
    let status = response.status();
    let value = response_json(response).await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    value
}

async fn active_identity(client: &tokio_postgres::Client) -> ExpectedRegistryIdentity {
    let row = client
        .query_one(
            "SELECT package_id, database_id, active_package_digest,
                    active_activation_id::text, schema_fingerprint
               FROM registry_internal.registry_state WHERE singleton",
            &[],
        )
        .await
        .unwrap();
    ExpectedRegistryIdentity {
        package_id: row.get(0),
        database_id: row.get(1),
        package_digest: row.get(2),
        activation_id: row.get(3),
        schema_fingerprint: row.get(4),
    }
}
