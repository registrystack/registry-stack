// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "postgres-test")]

#[path = "support/membership_fixture.rs"]
mod membership_fixture;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use registry_breg::api::{
    authenticated_router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture,
};
use registry_breg::auth::{AuthorityClaimConfig, RegistryAuthenticator};
use registry_breg::cursor::CursorCodec;
use registry_breg::postgres::{
    begin_record_transaction, initialize_compiled_registry_state_for_test, install_compiled_schema,
    verify_catalog_identity_for_catalog, ClaimContext, ExpectedManagedCatalog,
    PostgresRecordMutationService, PostgresRecordReadService, PostgresRevisionReadService,
    PostgresSnapshotReadService, RegistryLockKey, RegistryStateTestIdentity,
};
use registry_platform_audit::AuditProfile;
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
use registry_platform_testing::{oidc_verifier_config, MockIdp};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tower::Service as _;
use zeroize::Zeroizing;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_membership_reads_recheck_live_membership_and_hide_processing_inputs() {
    for root in ["facility", "document"] {
        let route = if root == "facility" {
            "facilities"
        } else {
            "documents"
        };
        let registry =
            Arc::new(membership_fixture::compile(&membership_fixture::source(root)).unwrap());
        let database = postgres_harness::TestDatabase::create(4).await;
        let (migration, migration_task) = database.connect_migration().await;
        install_compiled_schema(&migration, &registry, &database.runtime_role)
            .await
            .expect("generated membership schema installs");
        let identity = initialize_compiled_registry_state_for_test(
            &migration,
            &database.runtime_role,
            &registry,
            RegistryStateTestIdentity {
                package_id: "membership-example",
                environment: "local",
                instance_id: "membership-instance",
                database_id: "membership-database",
                package_revision: "membership-package-1",
                package_sequence: 1,
            },
        )
        .await
        .expect("membership catalog identity includes helper functions");
        migration_task.abort();
        let pool = database.runtime_config.build_pool().unwrap();
        let lock_key = RegistryLockKey::derive("membership-example").unwrap();
        let audit = AuditProfile::production_from_secret_bytes(vec![0x5e; 32].into()).unwrap();
        let cursors = Arc::new(
            CursorCodec::new(Zeroizing::new(vec![0x4e; 32]), Duration::from_secs(300)).unwrap(),
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
        let revisions = Arc::new(PostgresRevisionReadService::new(
            pool.clone(),
            registry.clone(),
            identity.clone(),
            lock_key,
            Duration::from_secs(2),
            audit.clone(),
        ));
        let snapshots = Arc::new(PostgresSnapshotReadService::new(
            pool.clone(),
            registry.clone(),
            identity.clone(),
            lock_key,
            Duration::from_secs(2),
            audit.clone(),
            cursors.clone(),
        ));
        let mutations = Arc::new(PostgresRecordMutationService::new(
            pool.clone(),
            registry.clone(),
            identity.clone(),
            lock_key,
            Duration::from_secs(2),
            audit,
        ));
        let service = Arc::new(
            HttpService::new(
                registry.clone(),
                ReadRuntimeIdentity {
                    package_revision: identity.package_revision.clone(),
                    schema_fingerprint: identity.schema_fingerprint.clone(),
                },
                records,
                Arc::new(AlwaysReady),
                cursors,
            )
            .with_postgres_revisions(revisions)
            .with_snapshots(snapshots)
            .with_postgres_mutations(mutations),
        );
        let idp = MockIdp::start().await;
        let key_source = Arc::new(JwksFetcher::new_with_fetch_url_policy(
            idp.jwks_uri(),
            JwksFetcherConfig::defaults(),
            FetchUrlPolicy::dev(),
        ));
        let authenticator = Arc::new(
            RegistryAuthenticator::new(
                &registry,
                oidc_verifier_config(idp.issuer(), vec!["urn:breg:membership".into()]),
                key_source,
                AuthorityClaimConfig::new("principal", None),
            )
            .unwrap(),
        );
        let app = authenticated_router(service, authenticator);
        let steward = claims(&idp, "steward", &["records:manage", "membership:use"]);
        // This exact signed token is reused after revocation; no refreshed claims
        // or token-derived membership list participates in authorization.
        let member = claims(&idp, "member-a", &["records:read", "membership:use"]);
        let org = create(
            &app,
            "organizations",
            json!({"name":"Organization A"}),
            "org-a",
            &steward,
        )
        .await
        .0;
        let other_org = create(
            &app,
            "organizations",
            json!({"name":"Organization B"}),
            "org-b",
            &steward,
        )
        .await
        .0;
        let (membership, membership_etag) = create(&app,"memberships",json!({"organization":org,"principal":"member-a","active":true,"privateNote":"MEMBERSHIP-PRIVATE-CANARY"}),"membership-a",&steward).await;
        let first = create(
            &app,
            route,
            json!({"organization":org,"label":"A"}),
            "facility-a",
            &steward,
        )
        .await
        .0;
        create(
            &app,
            route,
            json!({"organization":org,"label":"B"}),
            "facility-b",
            &steward,
        )
        .await;
        let hidden = create(
            &app,
            route,
            json!({"organization":other_org,"label":"HIDDEN-OTHER-ORG"}),
            "facility-c",
            &steward,
        )
        .await
        .0;
        let get_uri = format!("/v1/records/{route}/{first}?accessProfile=member");
        let (status, _, body) = send(&app, Method::GET, &get_uri, Value::Null, None, &member).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(!body.to_string().contains("organization"));
        assert!(!body.to_string().contains("MEMBERSHIP-PRIVATE-CANARY"));
        let (status, _, _) = send(
            &app,
            Method::GET,
            &format!("/v1/records/{route}/{hidden}?accessProfile=member"),
            Value::Null,
            None,
            &member,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (_, _, page) = send(
            &app,
            Method::GET,
            &format!("/v1/records/{route}?accessProfile=member&$top=1&$count=true"),
            Value::Null,
            None,
            &member,
        )
        .await;
        assert_eq!(page["count"], 2, "{page}");
        let cursor = page["pageInfo"]["nextCursor"].as_str().unwrap();
        let (_, _, snapshot) = send(
            &app,
            Method::GET,
            &format!("/v1/records/{route}:snapshot?accessProfile=member&$count=true&$top=1"),
            Value::Null,
            None,
            &member,
        )
        .await;
        assert_eq!(snapshot["count"], 2, "{snapshot}");
        let snapshot_cursor = snapshot["pageInfo"]["nextCursor"].as_str().unwrap();
        let revision_uri = format!("/v1/records/{route}/{first}/revisions?accessProfile=member");
        let (_, _, revisions) =
            send(&app, Method::GET, &revision_uri, Value::Null, None, &member).await;
        assert_eq!(
            revisions["items"].as_array().unwrap().len(),
            1,
            "{revisions}"
        );
        let lookup_uri = format!("/v1/records/{route}:lookup?accessProfile=member");
        let lookup_body = json!({"selector":"label","values":{"label":"A"}});
        let (lookup_status, _, lookup) = send(
            &app,
            Method::POST,
            &lookup_uri,
            lookup_body.clone(),
            None,
            &member,
        )
        .await;
        assert_eq!(lookup_status, StatusCode::OK, "{lookup}");

        // Calling the boolean helper may process membership facts; it must not open
        // the source view or its private columns for subsequent queries or endpoints.
        let mut client = pool.get_for_test().await.unwrap();
        let context = ClaimContext::for_compiled(
            &registry,
            root,
            Some("member-a".into()),
            "member",
            None,
            vec![],
        )
        .unwrap();
        let transaction = begin_record_transaction(
            &mut client,
            lock_key,
            Duration::from_secs(2),
            &identity,
            &context,
        )
        .await
        .unwrap();
        let root_table = &registry.entities()[root].physical_table;
        let visible: i64 = transaction
            .transaction_for_test()
            .query_one(
                &format!("SELECT count(*) FROM registry_data.\"{root_table}\""),
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(
            visible, 2,
            "root RLS executes the membership helper in this transaction"
        );
        let source_view = &registry.entities()["membership"].source_relation.sql_name;
        let rows = transaction
            .transaction_for_test()
            .query(
                &format!("SELECT * FROM registry_source.\"{source_view}\""),
                &[],
            )
            .await
            .unwrap();
        assert!(
            rows.is_empty(),
            "processing authorization must not disclose membership source records"
        );
        let marker: Option<String> = transaction
            .transaction_for_test()
            .query_one(
                "SELECT NULLIF(current_setting('registry.membership_probe', true), '')",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert!(
            marker.is_none(),
            "function-local authorization marker is restored"
        );
        transaction.commit().await.unwrap();
        drop(client);
        let (status, _, _) = send(
            &app,
            Method::GET,
            &format!("/v1/records/memberships/{membership}?accessProfile=member"),
            Value::Null,
            None,
            &member,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _, body) = send(
            &app,
            Method::PATCH,
            &format!("/v1/records/memberships/{membership}?accessProfile=steward"),
            json!([{"op":"replace","path":"/data/active","value":false}]),
            Some(("deactivate", membership_etag.as_str())),
            &steward,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            send(&app, Method::GET, &get_uri, Value::Null, None, &member)
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        for uri in [
            format!("/v1/records/{route}?accessProfile=member&$count=true"),
            format!("/v1/records/{route}?accessProfile=member&$skiptoken={cursor}"),
            format!("/v1/records/{route}:snapshot?accessProfile=member&$count=true"),
            format!(
                "/v1/records/{route}:snapshot?accessProfile=member&$skiptoken={snapshot_cursor}"
            ),
        ] {
            let (status, _, body) = send(&app, Method::GET, &uri, Value::Null, None, &member).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["count"], 0, "{body}");
            assert_eq!(body["items"].as_array().unwrap().len(), 0);
        }
        let (status, _, body) =
            send(&app, Method::GET, &revision_uri, Value::Null, None, &member).await;
        assert!(
            status == StatusCode::NOT_FOUND
                || (status == StatusCode::OK
                    && body["items"].as_array().is_some_and(Vec::is_empty)),
            "{status}: {body}"
        );
        let (status, _, body) =
            send(&app, Method::POST, &lookup_uri, lookup_body, None, &member).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        // Exact catalog verification rejects both altered authority and additional
        // plausible helper names, beyond the ambient function-shape allowlist.
        let (migration, task) = database.connect_migration().await;
        let catalog = ExpectedManagedCatalog::compiled(&registry);
        let helper = registry
            .ddl()
            .functions
            .iter()
            .find(|function| function.name.starts_with("membership_"))
            .unwrap();
        migration
            .batch_execute(&format!(
                "ALTER FUNCTION registry_context.\"{}\"(uuid) SECURITY DEFINER",
                helper.name
            ))
            .await
            .unwrap();
        assert!(verify_catalog_identity_for_catalog(
            &migration,
            &identity,
            &catalog,
            &database.migration_role,
            &database.runtime_role
        )
        .await
        .is_err());
        migration
            .batch_execute(&format!(
                "ALTER FUNCTION registry_context.\"{}\"(uuid) SECURITY INVOKER",
                helper.name
            ))
            .await
            .unwrap();
        verify_catalog_identity_for_catalog(
            &migration,
            &identity,
            &catalog,
            &database.migration_role,
            &database.runtime_role,
        )
        .await
        .expect("restored helper matches original catalog");
        migration.batch_execute("CREATE FUNCTION registry_context.membership_aaaaaaaaaaaaaaaaaaaaaaaa(uuid) RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER AS 'SELECT false'").await.unwrap();
        assert!(verify_catalog_identity_for_catalog(
            &migration,
            &identity,
            &catalog,
            &database.migration_role,
            &database.runtime_role
        )
        .await
        .is_err());
        task.abort();
        database.cleanup().await;
    }
}

fn claims(idp: &MockIdp, principal: &str, scopes: &[&str]) -> String {
    idp.mint_token(
        json!({"aud":"urn:breg:membership", "principal":principal, "scope":scopes.join(" ")}),
    )
}
struct AlwaysReady;
impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}
async fn create(
    app: &axum::Router,
    route: &str,
    data: Value,
    key: &str,
    claims: &str,
) -> (String, String) {
    let (status, etag, body) = send(
        app,
        Method::POST,
        &format!("/v1/records/{route}?accessProfile=steward"),
        json!({"data":data}),
        Some((key, "")),
        claims,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{route}: {body}");
    (
        body["data"]["recordIdentifier"]
            .as_str()
            .unwrap()
            .to_owned(),
        etag.unwrap(),
    )
}
async fn send(
    app: &axum::Router,
    method: Method,
    uri: &str,
    body: Value,
    condition: Option<(&str, &str)>,
    claims: &str,
) -> (StatusCode, Option<String>, Value) {
    let content_type = if method == Method::PATCH {
        "application/json-patch+json"
    } else {
        "application/json"
    };
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", content_type)
        .header("authorization", format!("Bearer {claims}"));
    if let Some((key, etag)) = condition {
        request = request.header("idempotency-key", key);
        if !etag.is_empty() {
            request = request.header("if-match", etag);
        }
    }
    let request = request
        .body(if body.is_null() {
            Body::empty()
        } else {
            Body::from(serde_json::to_vec(&body).unwrap())
        })
        .unwrap();
    let response = app.clone().call(request).await.unwrap();
    let status = response.status();
    let etag = response
        .headers()
        .get("etag")
        .map(|value| value.to_str().unwrap().to_owned());
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, etag, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_membership_successors_match_fresh_install_when_added_changed_and_removed() {
    use registry_breg::package::{
        change_set_to_applicable_migration_plan, compiled_registry_change_set,
    };
    use registry_breg::postgres::{
        managed_schema_fingerprint, reconcile_compiled_runtime_acl_for_test,
    };
    let mut base = membership_fixture::source("facility");
    base["accessProfiles"][0]["grants"][0]["membershipBoundaries"] = json!([]);
    let mut previous = membership_fixture::compile(&base).unwrap();
    let upgraded = postgres_harness::TestDatabase::create(1).await;
    let (migration, task) = upgraded.connect_migration().await;
    install_compiled_schema(&migration, &previous, &upgraded.runtime_role)
        .await
        .unwrap();
    let guarded = membership_fixture::source("facility");
    let mut changed = guarded.clone();
    changed["accessProfiles"][0]["grants"][0]["membershipBoundaries"][0]["principalField"] =
        json!("private-note");
    for (stage, source) in [("added", guarded), ("changed", changed), ("removed", base)] {
        let candidate = membership_fixture::compile(&source).unwrap();
        let changes =
            compiled_registry_change_set(&previous, &candidate, "prior-membership-package");
        let plan = change_set_to_applicable_migration_plan(&changes)
            .expect("membership access changes produce compiler-owned successor DDL");
        assert!(
            !plan.statements.is_empty(),
            "{stage} helper change needs successor DDL"
        );
        for statement in &plan.statements {
            migration
                .batch_execute(&statement.sql)
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "{stage} compiler successor statement {} must execute",
                        statement.id
                    )
                });
        }
        reconcile_compiled_runtime_acl_for_test(&migration, &candidate, &upgraded.runtime_role)
            .await
            .expect("successor policies and helper ACL reconcile");
        let catalog = ExpectedManagedCatalog::compiled(&candidate);
        let actual = managed_schema_fingerprint(&migration, &upgraded.runtime_role, &catalog)
            .await
            .expect("upgraded exact catalog");
        let fresh = postgres_harness::TestDatabase::create(1).await;
        let (fresh_migration, fresh_task) = fresh.connect_migration().await;
        install_compiled_schema(&fresh_migration, &candidate, &fresh.runtime_role)
            .await
            .unwrap();
        let expected = managed_schema_fingerprint(&fresh_migration, &fresh.runtime_role, &catalog)
            .await
            .unwrap();
        assert_eq!(
            actual, expected,
            "{stage} successor must have exactly the fresh candidate catalog"
        );
        fresh_task.abort();
        fresh.cleanup().await;
        previous = candidate;
    }
    task.abort();
    upgraded.cleanup().await;
}
