// SPDX-License-Identifier: Apache-2.0

//! `requiredFilters` on a list grant, against a real PostgreSQL database.

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use axum::{
    body::{to_bytes, Body},
    http::{Method, Request, StatusCode},
    Router,
};
use postgres_harness::TestDatabase;
use registry_breg::api::{
    authenticated_router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture,
};
use registry_breg::auth::{AuthorityClaimConfig, RegistryAuthenticator};
use registry_breg::cursor::CursorCodec;
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    PostgresRecordReadService, RegistryLockKey, RegistryStateTestIdentity,
};
use registry_breg::{compile_project, parse_project_json, CompileProfile, CompiledRegistry};
use registry_platform_audit::AuditProfile;
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
use registry_platform_testing::{oidc_verifier_config, MockIdp};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use tower::ServiceExt;
use zeroize::Zeroizing;

const PACKAGE: &str = "required-filters-test";
const AUDIENCE: &str = "urn:breg:required-filters-test";
const ROWS: [(&str, &str); 3] = [
    ("00000000-0000-4000-8000-000000000011", "visible"),
    ("00000000-0000-4000-8000-000000000012", "visible"),
    ("00000000-0000-4000-8000-000000000013", "other"),
];

struct Ready;
impl ReadinessProbe for Ready {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

fn compiled() -> CompiledRegistry {
    let source = json!({"datasets":{"records": {}},
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1", "kind":"BRegProject",
        "project":{"id":PACKAGE,"version":"1","defaultLanguage":"en","canonicalBaseIri":"https://registry.example.test"},
        "recordTypes":{"item": {"primaryDataset":"records","route":"items","mutationMode":"mutable","classification":"internal",
            "fields":[{"id":"label","type":"string","maximumLength":64,"required":true,"classification":"internal"}]}},
        "accessProfiles":{"reader": {"default":true,"principalClaim":"sub","requiredScopes":"unrestricted",
            "permissions":{"records":[{"recordType":"item","operations":["get","list"],"rowBoundaries":"unrestricted",
                "readableFields":["label"],"filterableFields":["label"],
                "requiredFilters":[{"fields":["label"]}]}]}}}
    });
    compile_project(
        &parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap(),
        &[],
        CompileProfile::Authoring,
    )
    .unwrap()
}

async fn setup() -> (TestDatabase, Router, MockIdp) {
    let database = TestDatabase::create(2).await;
    let registry = Arc::new(compiled());
    let (migration, task) = database.connect_migration().await;
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .unwrap();
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: PACKAGE,
            database_id: "required-filters-database",
            label: "required-filters-package-1",
        },
    )
    .await
    .unwrap();
    let entity = &registry.entities()["item"];
    for (id, label) in ROWS {
        database
            .admin
            .execute(
                &format!(
                    "INSERT INTO registry_data.\"{}\" (record_id,record_revision,record_lifecycle,active_package_revision,\"{}\")
                     VALUES ($1::text::uuid,1,'active',$3,$2)",
                    entity.physical_table, entity.fields["label"].physical_name
                ),
                &[&id, &label, &identity.activation_id],
            )
            .await
            .unwrap();
    }
    drop(migration);
    task.abort();
    let idp = MockIdp::start().await;
    let keys = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        idp.jwks_uri(),
        JwksFetcherConfig::defaults(),
        FetchUrlPolicy::dev(),
    ));
    let mut verifier = oidc_verifier_config(idp.issuer(), vec![AUDIENCE.to_owned()]);
    verifier.allowed_clients = vec!["portal".into()];
    let auth = Arc::new(
        RegistryAuthenticator::new(
            &registry,
            verifier,
            keys,
            AuthorityClaimConfig::new("sub", None),
        )
        .unwrap(),
    );
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x63; 32]), Duration::from_secs(300)).unwrap(),
    );
    let reads = PostgresRecordReadService::new(
        database.runtime_config.build_pool().unwrap(),
        registry.clone(),
        identity.clone(),
        RegistryLockKey::derive(PACKAGE).unwrap(),
        Duration::from_secs(2),
        database.audit(AuditProfile::production_from_secret_bytes(vec![0x52; 32].into()).unwrap()),
        cursors.clone(),
    );
    let service = HttpService::new(
        registry,
        ReadRuntimeIdentity {
            package_revision: identity.activation_id,
            schema_fingerprint: identity.schema_fingerprint,
        },
        Arc::new(reads),
        Arc::new(Ready),
        cursors,
    );
    (database, authenticated_router(Arc::new(service), auth), idp)
}

async fn list(app: &Router, idp: &MockIdp, query: &str) -> (StatusCode, Value) {
    let token = idp.mint_token(json!({"aud":AUDIENCE,"sub":"reader-subject","client_id":"portal","scope":"registry.read","registry_actor_kind":"service"}));
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/v1/records/items{query}"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

fn labels(body: &Value) -> Vec<String> {
    body["items"]
        .as_array()
        .unwrap_or_else(|| panic!("a page of items: {body}"))
        .iter()
        .map(|item| item["domainData"]["label"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_list_without_the_required_filter_is_refused() {
    let (database, app, idp) = setup().await;
    let (status, body) = list(&app, &idp, "").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "query.filter_required");
    assert_eq!(body["requiredFilters"], json!([["label"]]));
    let (status, body) = list(&app, &idp, "?$filter=label%20ne%20'other'").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "query.filter_required");
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_list_with_the_required_filter_returns_only_the_matching_rows() {
    let (database, app, idp) = setup().await;
    let (status, body) = list(&app, &idp, "?$filter=label%20eq%20'visible'").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(labels(&body), ["visible", "visible"]);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_continuation_cursor_keeps_the_filter_and_cannot_drop_or_swap_it() {
    let (database, app, idp) = setup().await;
    let (status, first) = list(&app, &idp, "?$filter=label%20eq%20'visible'&$top=1").await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(labels(&first), ["visible"]);
    let cursor = first["pageInfo"]["nextCursor"]
        .as_str()
        .expect("the first page continues")
        .to_owned();

    // The cursor alone carries the filter, so the next page holds only the
    // other matching row and never the row the filter excludes.
    let (status, second) = list(&app, &idp, &format!("?$skiptoken={cursor}")).await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(labels(&second), ["visible"]);
    assert!(second["pageInfo"]["nextCursor"].is_null(), "{second}");

    // A continuation request accepts no filter of its own, so a cursor cannot
    // be reused under a different one.
    let (status, swapped) = list(
        &app,
        &idp,
        &format!("?$skiptoken={cursor}&$filter=label%20eq%20'other'"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{swapped}");
    assert_eq!(swapped["code"], "query.invalid");
    database.cleanup().await;
}
