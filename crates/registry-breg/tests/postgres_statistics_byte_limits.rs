// SPDX-License-Identifier: Apache-2.0
//! Bounds for valid multi-period representations accepted by maintained clients.
#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use chrono::{Days, Utc};
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
async fn authored_multi_period_response_obeys_the_shared_document_byte_limit() {
    let dimension_ids: Vec<String> = (0..5)
        .map(|index| format!("dimension{index}{}", "x".repeat(54)))
        .collect();
    let mut fields: Vec<_> = dimension_ids.iter().map(|id| json!({"id":id,"type":"vocabulary-code","vocabulary":id,"required":true,"classification":"internal"})).collect();
    fields
        .push(json!({"id":"event-date","type":"date","required":true,"classification":"internal"}));
    let vocabularies: Vec<_> = dimension_ids
        .iter()
        .map(|id| json!({"id":id,"values":["a".repeat(128),"b".repeat(128)]}))
        .collect();
    let mut accessible = dimension_ids.clone();
    accessible.push("event-date".to_owned());
    let source = json!({
        "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
        "registry":{"id":"statistics-load","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://load.example.test"},
        "entities":[{"id":"unit","route":"units","primaryDataset":"load","mutationMode":"mutable","fields":fields}],
        "vocabularies":vocabularies,
        "accessProfiles":[{"id":"publisher","principalClaim":"principal","requiredScopes":"unrestricted","permissions":[{"entity":"unit","operations":["list"],"allowCount":true,"rowBoundaries":"unrestricted","readableFields":accessible,"filterableFields":accessible},{"dataset":"units-by-category","operations":["read-live"]}]}],
        "statisticalDatasets":[{"id":"units-by-category","unit":"unit","population":"eventDate ne null","period":{"type":"flow","field":"event-date","granularity":"day","firstPeriod":"2025-01-01"},"dimensions":dimension_ids,"disclosure":{"minimumCount":5,"roundingBase":5}}]
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
    let today = Utc::now().date_naive();
    for media in ["application/json", "text/csv"] {
        for (periods, expected) in [(40, StatusCode::OK), (41, StatusCode::BAD_REQUEST)] {
            let from = today.checked_sub_days(Days::new(periods - 1)).unwrap();
            let mut request = Request::builder()
                .uri(format!("/v1/statistics/units-by-category:live?accessProfile=publisher&from={from}&to={today}"))
                .header("accept", media).body(Body::empty()).unwrap();
            request.extensions_mut().insert(claims.clone());
            let response = app.call(request).await.unwrap();
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 9 * 1024 * 1024)
                .await
                .unwrap();
            assert_eq!(status, expected, "{periods} {media}: {} bytes", bytes.len());
            assert!(bytes.len() <= 8 * 1024 * 1024);
            if expected == StatusCode::BAD_REQUEST {
                let problem: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(problem["code"], "query.invalid");
                assert!(problem.get("fieldPath").is_none());
            }
        }
    }
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
