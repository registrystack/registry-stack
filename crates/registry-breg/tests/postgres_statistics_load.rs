// SPDX-License-Identifier: Apache-2.0
//! Explicit load measurement, separate from the correctness journeys.
#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use chrono::{Datelike, Days, Utc};
use registry_breg::{
    api::{
        router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture,
        VerifiedRequestClaims,
    },
    compiler::{compile_project, CompileProfile},
    contract::parse_project_json,
    cursor::CursorCodec,
    postgres::{
        initialize_compiled_registry_state_for_test, install_compiled_schema,
        PostgresRecordReadService, PostgresStatisticsService, RegistryLockKey,
        RegistryStateTestIdentity,
    },
    statistics::{apply_disclosure, canonical_document, DisclosureParameters, StatisticsDocument},
};
use registry_platform_audit::AuditProfile;
use serde_json::json;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tower::Service as _;
use zeroize::Zeroizing;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit one-million-unit measurement; run with --ignored --nocapture"]
async fn million_unit_three_dimension_statistics_measurement() {
    let source = json!({
        "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
        "registry":{"id":"statistics-load","version":"1","defaultLanguage":"en",
            "canonicalBaseIri":"https://load.example.test"},
        "entities":[{"id":"unit","route":"units","primaryDataset":"load","mutationMode":"mutable",
            "fields":[
                {"id":"active","type":"boolean","required":true,"classification":"internal"},
                {"id":"category","type":"vocabulary-code","vocabulary":"category","required":true,"classification":"internal"},
                {"id":"region","type":"vocabulary-code","vocabulary":"region","required":true,"classification":"internal"},
                {"id":"event-date","type":"date","required":true,"classification":"internal"}]}],
        "vocabularies":[{"id":"category","values":["a","b","c","d"]},
            {"id":"region","values":["north","south","east","west"]}],
        "accessProfiles":[{"id":"publisher","principalClaim":"principal","requiredScopes":"unrestricted","permissions":[{
            "entity":"unit","operations":["list"],"allowCount":true,"rowBoundaries":"unrestricted",
            "readableFields":["active","category","region","event-date"],
            "filterableFields":["active","category","region","event-date"]}]},
            {"id":"reader","principalClaim":"principal","requiredScopes":"unrestricted","permissions":[]}],
        "statisticalDatasets":[{"id":"units-by-category","unit":"unit","population":"active ne null",
            "period":{"type":"flow","field":"event-date","granularity":"month","firstPeriod":"2025-01"},
            "dimensions":["active","category","region"],
            "disclosure":{"minimumCount":5,"roundingBase":5},"live":["publisher"],
            "releases":{"publisher":"publisher","readers":["reader"]}}]
    });
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    let compiled = Arc::new(compile_project(&project, &[], CompileProfile::Authoring).unwrap());
    let database = postgres_harness::TestDatabase::create(4).await;
    let (migration, migration_task) = database.connect_migration().await;
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .unwrap();
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        RegistryStateTestIdentity {
            package_id: "statistics-load",
            database_id: "statistics-load-db",
            label: "load-measurement",
        },
    )
    .await
    .unwrap();
    let today = Utc::now().date_naive();
    let date = today
        .with_day(1)
        .unwrap()
        .checked_sub_days(Days::new(1))
        .unwrap();
    let period = date.format("%Y-%m").to_string();
    let entity = &compiled.entities()["unit"];
    let quoted = |name: &str| format!("\"{}\"", name.replace('"', "\"\""));
    let table = quoted(&entity.physical_table);
    let active = quoted(&entity.fields["active"].physical_name);
    let category = quoted(&entity.fields["category"].physical_name);
    let region = quoted(&entity.fields["region"].physical_name);
    let event_date = quoted(&entity.fields["event-date"].physical_name);
    // An administrator-owned synthetic seed avoids timing one million application writes.
    // The computation below still uses the ordinary runtime role and read policy.
    let seed_started = Instant::now();
    database
        .admin
        .execute(
            &format!(
                "INSERT INTO registry_data.{table}
        (record_id,record_revision,record_lifecycle,active_package_revision,{active},{category},{region},{event_date})
        SELECT md5(i::text)::uuid,1,'active',$2::text,(i%2=0),
            (ARRAY['a','b','c','d'])[(i/2)%4+1],
            (ARRAY['north','south','east','west'])[(i/8)%4+1],$1::date
        FROM generate_series(1,1000000) i"
            ),
            &[&date, &identity.activation_id],
        )
        .await
        .unwrap();
    migration
        .batch_execute(&format!("ANALYZE registry_data.{table}"))
        .await
        .unwrap();
    let seed_elapsed = seed_started.elapsed();
    let audit =
        database.audit(AuditProfile::production_from_secret_bytes(vec![0x75; 32].into()).unwrap());
    let lock_key = RegistryLockKey::derive("statistics-load").unwrap();
    let pool = database.runtime_config.build_pool().unwrap();
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x76; 32]), Duration::from_secs(300)).unwrap(),
    );
    let records = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        compiled.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit.clone(),
        cursors.clone(),
    ));
    let statistics = Arc::new(PostgresStatisticsService::new(
        pool,
        compiled.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit,
    ));
    let mut app = router(Arc::new(
        HttpService::new(
            compiled,
            ReadRuntimeIdentity {
                package_revision: identity.activation_id,
                schema_fingerprint: identity.schema_fingerprint,
            },
            records,
            Arc::new(AlwaysReady),
            cursors,
        )
        .with_statistics(statistics),
    ));
    let claims = VerifiedRequestClaims::authenticated(
        "principal",
        "load-publisher",
        Default::default(),
        None,
        Default::default(),
    )
    .unwrap();
    let mut request = Request::builder().uri(format!("/v1/statistics/units-by-category:live?accessProfile=publisher&from={period}&to={period}")).body(Body::empty()).unwrap();
    request.extensions_mut().insert(claims.clone());
    let start = Instant::now();
    let response = app.call(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let live: StatisticsDocument = serde_json::from_slice(&bytes).unwrap();
    let live_elapsed = start.elapsed();
    let total = live
        .cells
        .iter()
        .find(|cell| cell.dimensions.values().all(|code| code == "_T"))
        .unwrap();
    assert_eq!(total.value, Some(1_000_000));
    assert_eq!(live.cells.len(), 75);
    let mut disclosed = live.clone();
    let start = Instant::now();
    apply_disclosure(
        &mut disclosed.cells,
        DisclosureParameters {
            minimum_count: 5,
            rounding_base: 5,
        },
    )
    .unwrap();
    let disclosure_elapsed = start.elapsed();
    let start = Instant::now();
    let encoded = canonical_document(&disclosed).unwrap();
    let encoding_elapsed = start.elapsed();
    let start = Instant::now();
    let mut request = Request::builder()
        .method("POST")
        .uri(format!(
            "/v1/statistics/units-by-category/releases/{period}/versions?accessProfile=publisher"
        ))
        .header("content-type", "application/json")
        .header("idempotency-key", "million-units-measurement-1")
        .body(Body::from(r#"{"status":"final"}"#))
        .unwrap();
    request.extensions_mut().insert(claims);
    let response = app.call(request).await.unwrap();
    let publish_elapsed = start.elapsed();
    assert_eq!(response.status(), StatusCode::CREATED);
    println!("statistics_load units=1000000 dimensions=3 cells={} seed_ms={:.3} live_compute_ms={:.3} publication_ms={:.3} disclosure_us={:.3} canonical_encoding_us={:.3} encoded_bytes={}",
        live.cells.len(),seed_elapsed.as_secs_f64()*1000.,live_elapsed.as_secs_f64()*1000.,
        publish_elapsed.as_secs_f64()*1000.,disclosure_elapsed.as_secs_f64()*1_000_000.,
        encoding_elapsed.as_secs_f64()*1_000_000.,encoded.len());
    migration_task.abort();
    drop(app);
    database.cleanup().await;
}

struct AlwaysReady;
impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}
