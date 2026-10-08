// SPDX-License-Identifier: Apache-2.0
//! Access narrowing across an activation with an unchanged statistical definition.
#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
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
};
use registry_platform_audit::AuditProfile;
use serde_json::json;
use std::{sync::Arc, time::Duration};
use tower::Service as _;
use zeroize::Zeroizing;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn moving_first_period_forward_hides_old_releases_without_changing_the_definition() {
    let mut source = json!({
        "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
        "registry":{"id":"statistics-load","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://load.example.test"},
        "entities":[{"id":"unit","route":"units","primaryDataset":"load","mutationMode":"mutable","fields":[{"id":"active","type":"boolean","required":true,"classification":"internal"},{"id":"event-date","type":"date","required":true,"classification":"internal"}]}],
        "accessProfiles":[{"id":"publisher","principalClaim":"principal","requiredScopes":"unrestricted","permissions":[{"entity":"unit","operations":["list"],"allowCount":true,"rowBoundaries":"unrestricted","readableFields":["active","event-date"],"filterableFields":["active","event-date"]}]},{"id":"reader","principalClaim":"principal","requiredScopes":"unrestricted","permissions":[]}],
        "statisticalDatasets":[{"id":"units-by-category","unit":"unit","population":"active ne null","period":{"type":"flow","field":"event-date","granularity":"month","firstPeriod":"2025-01"},"dimensions":["active"],"disclosure":{"minimumCount":5,"roundingBase":5},"live":["publisher"],"releases":{"publisher":"publisher","readers":["reader"]}}]
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
    let make_app =
        |compiled: Arc<registry_breg::CompiledRegistry>,
         identity: registry_breg::postgres::ExpectedRegistryIdentity| {
            let audit = database
                .audit(AuditProfile::production_from_secret_bytes(vec![0x75; 32].into()).unwrap());
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
            router(Arc::new(
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
            ))
        };
    let mut app = make_app(compiled.clone(), identity.clone());
    let claims = VerifiedRequestClaims::authenticated(
        "principal",
        "load-publisher",
        Default::default(),
        None,
        Default::default(),
    )
    .unwrap();
    let response = call(
        &mut app,
        "POST",
        "/v1/statistics/units-by-category/releases/2025-01/versions?accessProfile=publisher",
        &claims,
        Some("first-period-key"),
        Some(r#"{"status":"final"}"#),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let original = call(
        &mut app,
        "GET",
        "/v1/statistics/units-by-category/releases/2025-01/versions/1?accessProfile=reader",
        &claims,
        None,
        None,
    )
    .await;
    assert_eq!(original.status(), StatusCode::OK);
    let original = to_bytes(original.into_body(), 1024 * 1024).await.unwrap();
    let response = call(
        &mut app,
        "POST",
        "/v1/statistics/units-by-category/releases/2025-02/versions?accessProfile=publisher",
        &claims,
        Some("withdraw-retry-publish"),
        Some(r#"{"status":"final"}"#),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = call(&mut app, "POST",
        "/v1/statistics/units-by-category/releases/2025-02/versions/1/withdrawal?accessProfile=publisher",
        &claims, Some("withdraw-retry-key"), Some(r#"{"reason":"computation-error"}"#)).await;
    assert_eq!(response.status(), StatusCode::OK);
    // The shared activation lock is held by the administrator to force
    // release-read admission to consume its real statement/request budget.
    database.admin.batch_execute("BEGIN").await.unwrap();
    database
        .admin
        .execute(
            "SELECT pg_advisory_xact_lock($1)",
            &[&RegistryLockKey::derive("statistics-load").unwrap().get()],
        )
        .await
        .unwrap();
    for suffix in [
        "",
        "/2025-01",
        "/2025-01/versions/1",
        ":series?from=2025-01&to=2025-01",
    ] {
        let separator = if suffix.contains('?') { "&" } else { "?" };
        let mut request = Request::builder()
            .uri(format!(
                "/v1/statistics/units-by-category/releases{suffix}{separator}accessProfile=reader"
            ))
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(claims.clone());
        registry_breg::api::set_request_deadline_for_test(
            &mut request,
            tokio::time::Instant::now() + Duration::from_millis(100),
        );
        let timed = app.call(request).await.unwrap();
        let status = timed.status();
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(timed.into_body(), 1024 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT, "{suffix}: {body}");
        assert_eq!(body["code"], "request.timeout");
    }
    database.admin.batch_execute("ROLLBACK").await.unwrap();
    source["statisticalDatasets"][0]["period"]["firstPeriod"] = json!("2025-06");
    let successor_project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    let successor =
        Arc::new(compile_project(&successor_project, &[], CompileProfile::Authoring).unwrap());
    assert_eq!(
        compiled.statistical_datasets()["units-by-category"].definition_digest,
        successor.statistical_datasets()["units-by-category"].definition_digest
    );
    let mut successor_identity = identity;
    successor_identity.activation_id =
        registry_breg::postgres::test_activation_id("first-period-successor");
    successor_identity.package_digest = format!("sha256:{}", "1".repeat(64));
    database.admin.execute("UPDATE registry_internal.registry_state SET active_package_digest = $1, active_activation_id = $2::text::uuid WHERE singleton", &[&successor_identity.package_digest, &successor_identity.activation_id]).await.unwrap();
    let mut successor_app = make_app(successor, successor_identity);
    let listed = call(
        &mut successor_app,
        "GET",
        "/v1/statistics/units-by-category/releases?accessProfile=reader",
        &claims,
        None,
        None,
    )
    .await;
    assert_eq!(listed.status(), StatusCode::OK);
    let listed: serde_json::Value =
        serde_json::from_slice(&to_bytes(listed.into_body(), 1024 * 1024).await.unwrap()).unwrap();
    assert_eq!(listed["items"], json!([]));
    for suffix in ["", "/versions/1"] {
        let response = call(
            &mut successor_app,
            "GET",
            &format!(
                "/v1/statistics/units-by-category/releases/2025-01{suffix}?accessProfile=reader"
            ),
            &claims,
            None,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    let withdrawn = call(&mut successor_app, "POST", "/v1/statistics/units-by-category/releases/2025-01/versions/1/withdrawal?accessProfile=publisher", &claims, Some("old-period-withdraw"), Some(r#"{"reason":"computation-error"}"#)).await;
    assert_eq!(withdrawn.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let withdrawn: serde_json::Value =
        serde_json::from_slice(&to_bytes(withdrawn.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(withdrawn["refusalCode"], "before-first-period");
    let retry = call(
        &mut successor_app,
        "POST",
        "/v1/statistics/units-by-category/releases/2025-01/versions?accessProfile=publisher",
        &claims,
        Some("first-period-key"),
        Some(r#"{"status":"final"}"#),
    )
    .await;
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    let retry: serde_json::Value =
        serde_json::from_slice(&to_bytes(retry.into_body(), 1024 * 1024).await.unwrap()).unwrap();
    assert_eq!(retry["code"], "idempotency.conflict");
    let retry = call(&mut successor_app, "POST",
        "/v1/statistics/units-by-category/releases/2025-02/versions/1/withdrawal?accessProfile=publisher",
        &claims, Some("withdraw-retry-key"), Some(r#"{"reason":"computation-error"}"#)).await;
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    let retry: serde_json::Value =
        serde_json::from_slice(&to_bytes(retry.into_body(), 1024 * 1024).await.unwrap()).unwrap();
    assert_eq!(retry["code"], "idempotency.conflict");
    let stored: Vec<u8> = database
        .admin
        .query_one(
            "SELECT document FROM registry_internal.registry_statistical_release_contents",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(stored, original);
    drop(successor_app);
    migration_task.abort();
    drop(app);
    database.cleanup().await;
}

async fn call(
    app: &mut axum::Router,
    method: &str,
    uri: &str,
    claims: &VerifiedRequestClaims,
    key: Option<&str>,
    body: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(key) = key {
        builder = builder.header("idempotency-key", key);
    }
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let mut request = builder
        .body(body.map_or_else(Body::empty, |body| Body::from(body.to_owned())))
        .unwrap();
    request.extensions_mut().insert(claims.clone());
    app.call(request).await.unwrap()
}

struct AlwaysReady;
impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}
