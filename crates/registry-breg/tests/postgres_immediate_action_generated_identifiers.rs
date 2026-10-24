// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{HeaderName, HeaderValue, Method, Request, StatusCode};
use postgres_harness::TestDatabase;
use registry_breg::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedClaimValue,
    VerifiedRequestClaims,
};
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::cursor::CursorCodec;
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    PostgresRecordMutationService, PostgresRecordReadService, RegistryLockKey,
    RegistryStateTestIdentity,
};
use registry_platform_audit::AuditProfile;
use serde_json::{json, Value};
use tower::Service as _;
use zeroize::Zeroizing;

const PACKAGE_ID: &str = "generated-identifier-action-registry";
const DATABASE_ID: &str = "generated-identifier-action-database";
const INSTANCE_ID: &str = "generated-identifier-action-instance";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn immediate_action_create_reserves_generated_identifier() {
    let database = TestDatabase::create(6).await;
    let (migration, migration_task) = database.connect_migration().await;
    let registry = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("generated identifier Action schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "generated-identifier-action-package",
        },
    )
    .await
    .expect("generated identifier Action registry initializes");
    drop(migration);
    migration_task.abort();

    let app = action_router(&database, Arc::clone(&registry), identity);
    let response = response_parts(
        send(
            &app,
            Method::POST,
            "/v1/actions/register-application",
            Some(action_claims()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "generated-action-create"),
            ],
            serde_json::to_vec(&json!({
                "input": {
                    "jurisdiction": "zone-a",
                    "applicant": "Action applicant"
                }
            }))
            .expect("Action request serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    assert_eq!(response.body["action"], "register-application");
    assert!(response.body["results"].get("application").is_some());

    let entity = &registry.entities()["application"];
    let table = quote_identifier(&entity.physical_table);
    let jurisdiction = quote_identifier(&entity.fields["jurisdiction"].physical_name);
    let applicant = quote_identifier(&entity.fields["applicant"].physical_name);
    let number = quote_identifier(&entity.fields["number"].physical_name);
    let row = database
        .admin
        .query_one(
            &format!(
                "SELECT {jurisdiction}::text, {applicant}::text, {number}::text \
                   FROM registry_data.{table}"
            ),
            &[],
        )
        .await
        .expect("Action-created application is stored");
    assert_eq!(row.get::<_, String>(0), "zone-a");
    assert_eq!(row.get::<_, String>(1), "Action applicant");
    assert_eq!(row.get::<_, String>(2), "APP-0001");

    database.cleanup().await;
}

fn compiled_registry() -> registry_breg::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"generated-identifier-actions","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://identifiers.example.test"},
          "datasets":[{"id":"applications"}],
          "recordTypes":[{
            "id":"application","primaryDataset":"applications","route":"applications","mutationMode":"mutable",
            "fields":[
              {"id":"jurisdiction","type":"string","minimumLength":1,"maximumLength":40,"required":true,"classification":"internal"},
              {"id":"applicant","type":"string","minimumLength":1,"maximumLength":120,"required":true,"classification":"internal"},
              {"id":"number","type":"string","minimumLength":8,"maximumLength":32,"required":true,"classification":"internal",
               "generate":{"type":"sequence","prefix":"APP-","minimumDigits":4,"scope":["jurisdiction"]}}
            ]
          }],
          "actions":[{
            "id":"register-application",
            "inputs":[
              {"id":"jurisdiction","type":"string","minimumLength":1,"maximumLength":40,"required":true,"classification":"internal"},
              {"id":"applicant","type":"string","minimumLength":1,"maximumLength":120,"required":true,"classification":"internal"}
            ],
            "execution":{"mode":"immediate"},
            "plan":{"type":"fixed","effects":[{
              "id":"application","target":{"recordType":"application"},"operation":"create",
              "set":{"jurisdiction":{"fromInput":"jurisdiction"},"applicant":{"fromInput":"applicant"}}
            }]}
          }],
          "accessProfiles":[{
            "id":"application-registrar","default":true,"principalClaim":"registry_principal",
            "requiredScopes":["registry:applications:write"],
            "permissions":{"actions":[{
              "action":"register-application","operations":["invoke"],
              "targets":[{"recordType":"application","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}],
              "results":["application"]
            }]}
          }]
        }"#,
    )
    .expect("generated identifier Action project parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("generated identifier Action project compiles")
}

fn action_router(
    database: &TestDatabase,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
) -> axum::Router {
    let pool = database
        .runtime_config
        .build_pool()
        .expect("runtime pool builds");
    let audit = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x42; 32].into())
            .expect("test owns a keyed audit profile"),
    );
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives");
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x63; 32]), Duration::from_secs(300))
            .expect("cursor key is valid"),
    );
    let records = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        Arc::clone(&registry),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit.clone(),
        Arc::clone(&cursors),
    ));
    let read_identity = ReadRuntimeIdentity {
        package_revision: identity.activation_id.clone(),
        schema_fingerprint: identity.schema_fingerprint.clone(),
    };
    let mutations = Arc::new(PostgresRecordMutationService::new(
        pool,
        Arc::clone(&registry),
        identity,
        INSTANCE_ID,
        lock_key,
        Duration::from_secs(2),
        audit,
    ));
    router(Arc::new(
        HttpService::new(
            registry,
            read_identity,
            records,
            Arc::new(AlwaysReady),
            cursors,
        )
        .with_postgres_mutations(mutations),
    ))
}

fn action_claims() -> VerifiedRequestClaims {
    let mut direct_claims = BTreeMap::new();
    direct_claims.insert(
        "jurisdiction".to_owned(),
        VerifiedClaimValue::direct_string("zone-a").expect("direct claim is valid"),
    );
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        "registrar-principal",
        BTreeSet::from(["registry:applications:write".to_owned()]),
        None,
        direct_claims,
    )
    .expect("authenticated Action claims are valid")
}

async fn send(
    app: &axum::Router,
    method: Method,
    uri: &str,
    claims: Option<VerifiedRequestClaims>,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::from(body))
        .expect("request builds");
    for (name, value) in headers {
        request.headers_mut().append(
            HeaderName::from_bytes(name.as_bytes()).expect("header name is valid"),
            HeaderValue::from_str(value).expect("header value is valid"),
        );
    }
    if let Some(claims) = claims {
        request.extensions_mut().insert(claims);
    }
    let mut app = app.clone();
    app.call(request).await.expect("router responds")
}

struct ResponseParts {
    status: StatusCode,
    body: Value,
}

async fn response_parts(response: axum::response::Response) -> ResponseParts {
    let status = response.status();
    let body = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("response body reads");
    ResponseParts {
        status,
        body: serde_json::from_slice(&body).expect("response is JSON"),
    }
}

#[derive(Clone)]
struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}
