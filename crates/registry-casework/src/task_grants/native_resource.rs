// SPDX-License-Identifier: Apache-2.0
//! Native BReg Action fixture for the complete task-grant exchange journey.
#[path = "../../../registry-breg/tests/support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;
use axum::{
    body::{to_bytes, Body},
    http::{Method, Request, StatusCode},
    Router,
};
pub(super) use postgres_harness::TestDatabase;
use registry_breg::package::{
    load_package, prepare_package, PackageBuildRequest, PackageLoadContext,
    PackageMigrationPlanInput, PackageSourceFile, FIXTURE_JOURNEYS_PATH,
};
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    managed_schema_fingerprint, ExpectedManagedCatalog, RegistryStateTestIdentity,
};
use registry_breg::startup::{prepare_with_connection_config_for_test, PreparedServer};
use registry_breg::CompiledRegistry;
use serde_json::{json, Value};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, sync::Arc};
use tower::ServiceExt;
const AUDIENCE: &str = "urn:breg:task-test";
const SOURCE_REVISION: &str = "native-task-grant-source";
const FIXTURE_JOURNEYS: &[u8] = br#"apiVersion: id.registrystack.org/formats/breg/journeys/v1
kind: BRegJourneys
journeys:
  - id: empty-site-list
    steps:
      - id: list-sites
        entity: asset-site
        accessProfile: steward
        claims: {sub: fixture-steward, tenant_claim: fixture}
        request: {type: list}
        expect: {outcome: success, status: 200, count: 0}
"#;
pub(super) const PROJECT: &str = r#"{
  "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
  "kind":"BRegProject",
  "project":{"id":"task-authority-http","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
  "datasets":[{"id":"test-dataset"}],
  "recordTypes":[
    {
      "id":"asset-site",
      "primaryDataset":"test-dataset",
      "route":"sites",
      "mutationMode":"create-only",
      "classification":"internal",
      "fields":[
        {"id":"tenant","type":"string","minimumLength":1,"maximumLength":64,"required":true,"classification":"internal"},
        {"id":"name","type":"string","minimumLength":1,"maximumLength":64,"required":true,"classification":"internal"}
      ]
    },
    {
      "id":"asset-placement",
      "primaryDataset":"test-dataset",
      "route":"placements",
      "mutationMode":"mutable",
      "classification":"internal",
      "fields":[
        {"id":"tenant","type":"string","minimumLength":1,"maximumLength":64,"required":true,"classification":"internal"},
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
        {"id":"tenant","type":"string","minimumLength":1,"maximumLength":64,"required":true,"classification":"internal"},
        {"id":"placement","type":"reference","target":"asset-placement","required":true,"classification":"internal"},
        {"id":"proposed-site","type":"reference","target":"asset-site","required":true,"classification":"internal"},
        {"id":"reason","type":"text","maximumLength":1000,"required":true,"classification":"internal"}
      ]
    }
  ],
  "actions":[{
    "id":"file-correction",
    "execution":{"mode":"immediate"},
    "inputs":[
      {"id":"tenant","type":"string","required":true,"minimumLength":1,"maximumLength":64,"classification":"internal"},
      {"id":"placement","type":"reference","target":"asset-placement","required":true,"classification":"internal"},
      {"id":"proposed-site","apiName":"proposedSite","type":"reference","target":"asset-site","required":true,"classification":"internal"},
      {"id":"reason","type":"text","required":true,"maximumLength":1000,"classification":"internal"}
    ],
    "plan":{"type":"fixed","effects":[{"id":"correction","target":{"recordType":"correction-request"},"operation":"create","set":{
      "tenant":{"fromInput":"tenant"},"placement":{"fromInput":"placement"},"proposed-site":{"fromInput":"proposed-site"},"reason":{"fromInput":"reason"}
    }}]}
  }],
  "accessProfiles":[
    {
      "id":"steward",
      "default":true,
      "principalClaim":"sub",
      "requiredScopes":"unrestricted",
      "permissions":{
        "records":[
          {
            "recordType":"asset-site",
            "operations":["create","get","list"],
            "readableFields":["tenant","name"],
            "writableFields":["tenant","name"],
            "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
          },
          {
            "recordType":"asset-placement",
            "operations":["create","get","list"],
            "readableFields":["tenant","site"],
            "writableFields":["tenant","site"],
            "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
          }
        ]
      }
    },
    {
      "id":"submitter",
      "default":false,
      "principalClaim":"sub",
      "requiredScopes":"unrestricted",
      "permissions":{
        "records":[
          {
            "recordType":"asset-site",
            "operations":["get"],
            "readableFields":["tenant","name"],
            "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
          },
          {
            "recordType":"correction-request",
            "operations":["get"],
            "readableFields":["tenant","placement","proposed-site","reason"],
            "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
          }
        ],
        "actions":[{
          "action":"file-correction","operations":["invoke"],
          "targets":[
            {"recordType":"correction-request","rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]},
            {"recordType":"asset-placement","rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]},
            {"recordType":"asset-site","rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]}
          ],
          "results":["correction"]
        }]
      },
      "actorKind":"agent",
      "requesterClients":["task-agent"],
      "requiredPurposes":["review"],
      "taskGrant":{"sourceIssuer":"https://casework.example"}
    },
    {
      "id":"applier",
      "principalClaim":"sub",
      "requiredScopes":"unrestricted",
      "requiredPurposes":["apply"],
      "permissions":{
        "records":[
          {
            "recordType":"correction-request",
            "operations":["get"],
            "readableFields":["tenant","placement","proposed-site","reason"],
            "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
          }
        ]
      }
    }
  ]
}"#;

pub(super) struct Deployment {
    pub(super) app: Router,
    pub(super) registry: Arc<CompiledRegistry>,
    _prepared: PreparedServer,
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

/// Build the authored Registry package, activate its exact package identity,
/// and construct the authenticated router through BReg's production startup.
/// The native journey therefore exercises the configured issuer, discovery,
/// admitted clients, authority claims, and task-status connection together.
pub(super) async fn start_from_runtime(
    db: &TestDatabase,
    root: &Path,
    issuer: &str,
    status_key: &registry_platform_crypto::PrivateJwk,
    casework_port: u16,
) -> Deployment {
    let mut authored: Value = serde_json::from_str(PROJECT).unwrap();
    authored["package"] = json!({"sourceRevision": SOURCE_REVISION});
    let project_bytes = serde_json::to_vec(&authored).unwrap();
    let project = registry_breg::parse_project_json(&project_bytes).unwrap();
    let registry = Arc::new(
        registry_breg::compile_project(&project, &[], registry_breg::CompileProfile::Production)
            .unwrap(),
    );
    let (migration, task) = db.connect_migration().await;
    install_compiled_schema(&migration, &registry, &db.runtime_role)
        .await
        .unwrap();
    let expected_catalog = ExpectedManagedCatalog::compiled(&registry);
    let schema_fingerprint =
        managed_schema_fingerprint(&migration, &db.runtime_role, &expected_catalog)
            .await
            .unwrap();
    let prepared_package = prepare_package(PackageBuildRequest {
        from_package_digest: None,
        compiler_source_revision: SOURCE_REVISION.into(),
        schema_fingerprint,
        project: PackageSourceFile {
            path: "registry.json".into(),
            bytes: project_bytes,
        },
        modules: Vec::new(),
        fixture_journeys: PackageSourceFile {
            path: FIXTURE_JOURNEYS_PATH.into(),
            bytes: FIXTURE_JOURNEYS.to_vec(),
        },
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
    })
    .unwrap();
    let package_root = root.join("breg-package");
    prepared_package
        .publish_to_directory(&package_root)
        .unwrap();
    let package = load_package(
        &package_root,
        &PackageLoadContext {
            database_initialization_environment: "test",
        },
    )
    .unwrap();
    assert_eq!(package.registry(), registry.as_ref());
    initialize_compiled_registry_state_for_test(
        &migration,
        &db.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: &package.manifest().package_id,
            database_id: "task-database",
            label: package.package_digest(),
        },
    )
    .await
    .unwrap();
    drop(migration);
    task.abort();

    let secrets = root.join("breg-runtime-secrets");
    fs::create_dir_all(&secrets).unwrap();
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700)).unwrap();
    write_private(
        &secrets.join("runtime-database-url"),
        b"unused-by-test-startup",
    );
    write_private(
        &secrets.join("migration-database-url"),
        b"unused-by-test-startup",
    );
    write_private(&secrets.join("audit-key"), &[0x9a; 32]);
    write_private(&secrets.join("cursor-key"), &[0x49; 32]);
    let status_private = json!({
        "kty": status_key.kty,
        "alg": status_key.alg,
        "kid": status_key.kid,
        "n": status_key.n,
        "e": status_key.e,
        "d": status_key.d,
        "p": status_key.p,
        "q": status_key.q,
        "dp": status_key.dp,
        "dq": status_key.dq,
        "qi": status_key.qi,
    });
    write_private(
        &secrets.join("status-client-key"),
        serde_json::to_string(&status_private).unwrap().as_bytes(),
    );
    let audit_dir = root.join("breg-audit");
    fs::create_dir_all(&audit_dir).unwrap();
    let runtime_path = root.join("breg-runtime.yaml");
    fs::write(
        &runtime_path,
        format!(
            r#"apiVersion: id.registrystack.org/formats/breg/runtime/v1alpha1
kind: BRegRuntimeConfig
listener: {{bind: 127.0.0.1:0}}
identity:
  environment: test
  instanceId: native-task-grant
  databaseId: task-database
  databaseInitializationEnvironment: test
secretProviders:
  file: {{root: {secrets}}}
database:
  runtimeUrlRef: secret:file/runtime-database-url
  migrationUrlRef: secret:file/migration-database-url
  pool:
    maximumConnections: 8
    waitTimeoutMilliseconds: 2000
    createTimeoutMilliseconds: 2000
    recycleTimeoutMilliseconds: 2000
  roles:
    migration: {migration_role}
    runtime: {runtime_role}
package: {{root: {package_root}}}
authentication:
  oidc:
    issuer: {issuer}
    audience: {AUDIENCE}
    allowedAlgorithm: RS256
    accessTokenType: at+jwt
    scopeClaim: scope
    scopeSeparator: " "
    allowedClients: [task-agent, other-agent, seed-client, other-seed-client]
    maximumTokenLifetimeSeconds: 3600
    leewayMilliseconds: 60000
    jwksSource: {{type: discovery}}
    jwksCache:
      cacheTtlSeconds: 60
      negativeCacheTtlSeconds: 1
      refreshCooldownSeconds: 1
      maximumDocumentBytes: 65536
      attemptTimeoutMilliseconds: 5000
      outageToleranceSeconds: 0
  authorityClaims: {{principal: sub, purpose: registry_purpose}}
taskGrantStatus:
  - sourceIssuer: https://casework.example
    baseUrl: http://127.0.0.1:{casework_port}
    tokenEndpoint: {issuer}/oauth2/token
    clientAssertionAudience: {issuer}
    clientId: breg-status
    privateKeyRef: secret:file/status-client-key
    statusResource: urn:casework:native-task
audit:
  hashKeyRef: secret:file/audit-key
  path: {audit_path}
cursor:
  secretRef: secret:file/cursor-key
  maximumAgeSeconds: 300
operationalTimeouts:
  httpRequestMilliseconds: 5000
  shutdownGraceMilliseconds: 1000
  recordLockMilliseconds: 2000
  migrationLockMilliseconds: 2000
  migrationStatementMilliseconds: 5000
"#,
            secrets = secrets.display(),
            migration_role = db.migration_role.as_str(),
            runtime_role = db.runtime_role.as_str(),
            package_root = package_root.display(),
            audit_path = audit_dir.join("audit.jsonl").display(),
        ),
    )
    .unwrap();
    fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o600)).unwrap();
    let prepared =
        prepare_with_connection_config_for_test(&runtime_path, db.runtime_config.clone())
            .await
            .unwrap();
    let app = prepared.app();
    Deployment {
        app,
        registry,
        _prepared: prepared,
    }
}
pub(super) struct Response {
    pub(super) status: StatusCode,
    pub(super) body: Value,
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
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
        .unwrap();
    Response { status, body }
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
pub(super) async fn counts(db: &TestDatabase, registry: &CompiledRegistry) -> (i64, i64) {
    let table = &registry.entities()["correction-request"].physical_table;
    let records = db
        .admin
        .query_one(
            &format!("SELECT count(*) FROM registry_data.\"{table}\""),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let idempotency = db
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_idempotency",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    (records, idempotency)
}
