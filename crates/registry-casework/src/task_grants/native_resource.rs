// SPDX-License-Identifier: Apache-2.0
//! Synthetic governed-request fixture for the complete native task journey.
#[path = "../../../registry-breg/tests/support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;
use axum::{
    body::{to_bytes, Body},
    http::{Method, Request, StatusCode},
    Router,
};
pub(super) use postgres_harness::TestDatabase;
use registry_breg::api::{
    authenticated_router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture,
};
use registry_breg::auth::{AuthorityClaimConfig, RegistryAuthenticator};
use registry_breg::cursor::CursorCodec;
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema, ExpectedRegistryIdentity,
    PostgresRecordMutationService, PostgresRecordReadService, RegistryLockKey,
    RegistryStateTestIdentity,
};
use registry_breg::task_grant::TaskGrantStatusChecker;
use registry_breg::CompiledRegistry;
use registry_platform_audit::AuditProfile;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use tower::ServiceExt;
use zeroize::Zeroizing;
const PACKAGE: &str = "task-authority-http";
const AUDIENCE: &str = "urn:breg:task-test";
const REVISION: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub(super) const PROJECT: &str = r#"{
  "apiVersion":"registry.registrystack.org/v1alpha1",
  "kind":"RegistryProject",
  "registry":{"id":"task-authority-http","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
  "entities":[
    {
      "id":"asset-site",
      "primaryDataset":"test-dataset",
      "route":"sites",
      "mutationMode":"create_only",
      "classification":"internal",
      "fields":[
        {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
        {"id":"name","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"}
      ]
    },
    {
      "id":"asset-placement",
      "primaryDataset":"test-dataset",
      "route":"placements",
      "mutationMode":"mutable",
      "classification":"internal",
      "changeControl":{"requiredFor":["patch"]},
      "fields":[
        {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
        {"id":"site","type":"reference","target":"asset-site","required":true,"classification":"internal"}
      ]
    },
    {
      "id":"correction-request",
      "primaryDataset":"test-dataset",
      "route":"correction-requests",
      "mutationMode":"mutable",
      "classification":"internal",
      "fields":[
        {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
        {"id":"placement","type":"reference","target":"asset-placement","required":true,"classification":"internal"},
        {"id":"proposed-site","type":"reference","target":"asset-site","required":true,"classification":"internal"},
        {"id":"reason","type":"text","maxLength":1000,"required":true,"classification":"internal"}
      ],
      "changeRequest":{
        "effects":[{"target":{"fromField":"placement"},"operation":"patch","set":{"site":{"fromField":"proposed-site"}}}],
        "review":{"stages":[{"id":"review","approvals":1,"excludeSubmitter":true}]}
      }
    }
  ],
  "accessProfiles":[
    {
      "id":"steward",
      "default":true,
      "principalClaim":"sub",
      "permissions":[
        {
          "entity":"asset-site",
          "operations":["create","get","list"],
          "readableFields":["tenant","name"],
          "writableFields":["tenant","name"],
          "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
        },
        {
          "entity":"asset-placement",
          "operations":["create","get","list","revisions"],
          "revisionAccess":true,
          "readableFields":["tenant","site"],
          "writableFields":["tenant","site"],
          "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
          "requestPresence":[{"requestType":"correction-request","rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]}]
        }
      ]
    },
    {
      "id":"submitter",
      "default":true,
      "principalClaim":"sub",
      "permissions":[
        {
          "entity":"correction-request",
          "operations":["create","get","list","revisions","patch","submit_request","revise_request","cancel_request"],
          "revisionAccess":true,
          "readableFields":["tenant","placement","proposed-site","reason"],
          "writableFields":["tenant","placement","proposed-site","reason"],
          "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
        }
      ],
      "actorKind":"agent",
      "requesterClients":["task-agent"],
      "requiredPurposes":["review"],
      "taskGrant":{"authority":"casework","sourceIssuer":"https://casework.example"}
    },
    {
      "id":"reviewer",
      "principalClaim":"sub",
      "requiredPurposes":["review"],
      "permissions":[
        {
          "entity":"correction-request",
          "operations":["get","list","approve_request","reject_request","request_revision"],
          "readableFields":["tenant","placement","proposed-site","reason"],
          "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
          "reviewStages":[{"stage":"review","targets":[{"entity":"asset-placement","readableFields":["site"],"rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]}]}]
        }
      ]
    },
    {
      "id":"applier",
      "principalClaim":"sub",
      "requiredPurposes":["apply"],
      "permissions":[
        {
          "entity":"correction-request",
          "operations":["get","apply_request"],
          "readableFields":["tenant","placement","proposed-site","reason"],
          "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
          "applyTargets":[{"entity":"asset-placement","rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]}]
        }
      ]
    }
  ]
}"#;

struct Ready;
impl ReadinessProbe for Ready {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}
pub(super) async fn install(
    db: &TestDatabase,
    registry: &CompiledRegistry,
) -> ExpectedRegistryIdentity {
    let (migration, task) = db.connect_migration().await;
    install_compiled_schema(&migration, registry, &db.runtime_role)
        .await
        .unwrap();
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &db.runtime_role,
        registry,
        RegistryStateTestIdentity {
            package_id: PACKAGE,
            environment: "local",
            instance_id: "task-instance",
            database_id: "task-database",
            package_revision: REVISION,
            package_sequence: 1,
        },
    )
    .await
    .unwrap();
    drop(migration);
    task.abort();
    identity
}
pub(super) fn app(
    db: &TestDatabase,
    registry: Arc<CompiledRegistry>,
    identity: ExpectedRegistryIdentity,
    issuer: &str,
    jwks: serde_json::Value,
    status: Arc<dyn TaskGrantStatusChecker>,
) -> Router {
    app_with_clients(
        db,
        registry,
        identity,
        issuer,
        jwks,
        status,
        vec!["task-agent".into(), "seed-client".into()],
    )
}
/// The local-session proof admits its explicitly rendered service and human clients.
#[allow(clippy::too_many_arguments)]
pub(super) fn app_with_clients(
    db: &TestDatabase,
    registry: Arc<CompiledRegistry>,
    identity: ExpectedRegistryIdentity,
    issuer: &str,
    jwks: Value,
    status: Arc<dyn TaskGrantStatusChecker>,
    clients: Vec<String>,
) -> Router {
    let pool = db.runtime_config.build_pool().unwrap();
    let lock = RegistryLockKey::derive(PACKAGE).unwrap();
    let audit = AuditProfile::production_from_secret_bytes(vec![0x9a; 32].into()).unwrap();
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x49; 32]), Duration::from_secs(300)).unwrap(),
    );
    let reads = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock,
        Duration::from_secs(2),
        audit.clone(),
        cursors.clone(),
    ));
    let writes = Arc::new(
        PostgresRecordMutationService::new(
            pool,
            registry.clone(),
            identity.clone(),
            lock,
            Duration::from_secs(2),
            audit,
        )
        .with_task_status(status),
    );
    let keys = Arc::new(JwksFetcher::new_static(
        serde_json::from_value(jwks).unwrap(),
        JwksFetcherConfig::defaults(),
    ));
    let verifier = registry_platform_oidc::TokenVerifierConfig::access_token_profile(
        issuer,
        vec![AUDIENCE.into()],
        vec![jsonwebtoken::Algorithm::RS256],
        vec!["at+jwt".into()],
    )
    .with_scope_claim("scope")
    .with_allowed_clients(clients);
    let auth = RegistryAuthenticator::new(
        &registry,
        verifier,
        keys,
        AuthorityClaimConfig::new("sub", Some("registry_purpose".into())),
    )
    .unwrap();
    authenticated_router(
        Arc::new(
            HttpService::new(
                registry,
                ReadRuntimeIdentity {
                    package_revision: identity.package_revision,
                    schema_fingerprint: identity.schema_fingerprint,
                },
                reads,
                Arc::new(Ready),
                cursors,
            )
            .with_postgres_mutations(writes),
        ),
        Arc::new(auth),
    )
}
pub(super) struct Response {
    pub(super) status: StatusCode,
    pub(super) body: Value,
    pub(super) etag: String,
}
pub(super) async fn send(
    app: &Router,
    method: Method,
    uri: &str,
    token: &str,
    key: Option<&str>,
    etag: Option<&str>,
    body: Value,
) -> Response {
    let mut req = Request::builder()
        .method(method.clone())
        .uri(uri)
        .header("authorization", format!("Bearer {token}"));
    if let Some(key) = key {
        req = req.header("idempotency-key", key);
    }
    if let Some(etag) = etag {
        req = req.header("if-match", etag);
    }
    if method == Method::PATCH {
        req = req.header("content-type", "application/json-patch+json");
    } else {
        req = req.header("content-type", "application/json");
    }
    let raw = if method == Method::GET {
        Vec::new()
    } else {
        serde_json::to_vec(&body).unwrap()
    };
    let response = app
        .clone()
        .oneshot(req.body(Body::from(raw)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let etag = response
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
        .unwrap();
    Response { status, etag, body }
}
pub(super) async fn create(
    app: &Router,
    route: &str,
    token: &str,
    key: &str,
    data: Value,
) -> Response {
    let r = send(
        app,
        Method::POST,
        route,
        token,
        Some(key),
        None,
        json!({"data":data}),
    )
    .await;
    assert_eq!(
        r.status,
        StatusCode::CREATED,
        "fixture operation {key}: {}",
        r.body
    );
    r
}
pub(super) fn id(response: &Response) -> String {
    response.body["data"]["recordIdentifier"]
        .as_str()
        .unwrap()
        .into()
}
pub(super) async fn get(app: &Router, id: &str, profile: &str, token: &str) -> Response {
    let r = send(
        app,
        Method::GET,
        &format!("/v1/records/correction-requests/{id}?accessProfile={profile}"),
        token,
        None,
        None,
        Value::Null,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    r
}
pub(super) async fn counts(db: &TestDatabase) -> Vec<i64> {
    let mut counts = Vec::new();
    for table in [
        "registry_revisions",
        "registry_idempotency",
        "registry_request_proposals",
        "registry_request_decisions",
        "registry_request_applications",
        "registry_request_results",
        "registry_request_task_authority",
    ] {
        counts.push(
            db.admin
                .query_one(
                    &format!("SELECT count(*) FROM registry_internal.{table}"),
                    &[],
                )
                .await
                .unwrap()
                .get(0),
        );
    }
    counts
}
