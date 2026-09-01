// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderName, HeaderValue, Method, Request};
use postgres_harness::TestDatabase;
use registry_platform_audit::AuditProfile;
use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
use registry_platform_testing::{oidc_verifier_config, MockIdp};
use registry_server::api::{
    authenticated_router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture,
};
use registry_server::auth::{AuthorityClaimConfig, RegistryAuthenticator};
use registry_server::compiler::{compile_project, CompileProfile};
use registry_server::contract::parse_project_json;
use registry_server::cursor::CursorCodec;
use registry_server::data::{
    execute_export_page, execute_import_chunk, DataError, DataExportCheckpoint, DataExportPlan,
    DataHttpMethod, DataHttpRequest, DataHttpResponse, DataImportCheckpoint, DataImportOperation,
    DataImportPlan,
};
use registry_server::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    PostgresRecordMutationService, PostgresRecordReadService, RegistryLockKey,
    RegistryStateTestIdentity,
};
use serde_json::{json, Value};
use tower::ServiceExt as _;
use zeroize::Zeroizing;

const AUDIENCE: &str = "urn:registry-server:data-export";
const PROFILE: &str = "data-operator";
const PACKAGE: &str = "package-data-export-1";
const PRINCIPAL_CANARY: &str = "data-export-principal-must-not-enter-output-or-audit";
const SECRET_CANARY: &str = "data-export-hidden-value-must-not-leak";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_export_is_authenticated_projected_audited_and_resumable() {
    let database = TestDatabase::create(8).await;
    let registry = Arc::new(compiled_registry());
    let (migration, migration_task) = database.connect_migration().await;
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("data export schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: "data-export-registry",
            environment: "local",
            instance_id: "data-export-instance",
            database_id: "data-export-database",
            package_revision: PACKAGE,
            package_sequence: 1,
        },
    )
    .await
    .expect("active data export identity initializes");
    drop(migration);
    migration_task.abort();

    let idp = MockIdp::start().await;
    let app = authenticated_app(&database, registry.clone(), identity.clone(), &idp);
    let token = idp.mint_token(json!({
        "aud":AUDIENCE,
        "registry_principal":PRINCIPAL_CANARY,
        "purpose":"data-export",
        "jurisdictions":["north"]
    }));
    let wrong_purpose = idp.mint_token(json!({
        "aud":AUDIENCE,
        "registry_principal":PRINCIPAL_CANARY,
        "purpose":"other-purpose",
        "jurisdictions":["north"]
    }));

    let input = (0..101)
        .map(|index| {
            serde_json::to_string(&json!({"operation":"create", "data":{
                "code":format!("ROW-{index:03}"), "jurisdiction":"north",
                "secret":SECRET_CANARY
            }}))
            .expect("seed item serializes")
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let import_plan = DataImportPlan::from_jsonl(
        &registry,
        "entry",
        DataImportOperation::Create,
        PROFILE,
        input.as_bytes(),
    )
    .expect("seed import closes against compiled batch authority");
    let before_import = durable_counts(&database, &registry).await;
    let mut import_checkpoint = DataImportCheckpoint::start(
        &import_plan,
        &identity.package_revision,
        &identity.schema_fingerprint,
    )
    .expect("seed checkpoint starts");
    let import_id = import_checkpoint.import_id().to_owned();
    while !import_checkpoint.is_complete() {
        execute_import_chunk(
            &import_plan,
            &mut import_checkpoint,
            &identity.package_revision,
            &identity.schema_fingerprint,
            &import_id,
            |request| dispatch(&app, Some(&token), request),
        )
        .await
        .expect("ordinary authenticated batch path seeds one bounded chunk")
        .expect("seed import has a remaining chunk");
    }
    let after_import = durable_counts(&database, &registry).await;
    assert_eq!(after_import.current - before_import.current, 101);
    assert_eq!(after_import.revisions - before_import.revisions, 101);
    assert_eq!(after_import.commits - before_import.commits, 2);
    assert_eq!(
        after_import.commit_members - before_import.commit_members,
        101
    );
    assert_eq!(after_import.outbox - before_import.outbox, 101);
    assert_eq!(after_import.idempotency - before_import.idempotency, 2);
    assert!(after_import.audit > before_import.audit);

    let export_plan = DataExportPlan::from_compiled(&registry, "entry", PROFILE, ["code"])
        .expect("explicit authenticated export permission compiles");
    let (mut checkpoint, initial_resume_state) = DataExportCheckpoint::start(
        &export_plan,
        &identity.package_revision,
        &identity.schema_fingerprint,
    )
    .expect("export checkpoint starts");
    let first = execute_export_page(
        &export_plan,
        &mut checkpoint,
        &identity.package_revision,
        &identity.schema_fingerprint,
        &[],
        &initial_resume_state,
        |request| dispatch(&app, Some(&token), request),
    )
    .await
    .expect("first authorized export page succeeds")
    .expect("first page exists");
    assert_eq!(first.added_record_count(), 100);
    assert!(!first.is_complete());
    let cursor = first
        .trusted_next_cursor()
        .expect("bounded first page yields a cursor")
        .to_owned();
    let (first_output, first_resume_state) = first.into_parts();
    let serialized = checkpoint.canonical_json().expect("checkpoint serializes");
    let partial = parse_json_strict(&serialized).expect("partial checkpoint is strict JSON");
    assert_eq!(partial["nextCursor"], cursor);
    for (label, next_cursor, complete) in [
        ("partial-to-complete", Value::Null, true),
        ("cursor-deletion", Value::Null, false),
        (
            "cursor-substitution",
            json!("SYNTACTICALLY-VALID-SUBSTITUTED-CURSOR"),
            false,
        ),
    ] {
        let mut forged = partial.clone();
        forged["nextCursor"] = next_cursor;
        forged["complete"] = json!(complete);
        let error = DataExportCheckpoint::from_json(
            &canonicalize_json(&forged).unwrap(),
            &export_plan,
            &identity.package_revision,
            &identity.schema_fingerprint,
            &first_output,
            &first_resume_state,
        )
        .expect_err(label);
        assert_eq!(error, DataError::CheckpointMismatch);
        assert!(!format!("{error:?} {error}").contains("SUBSTITUTED-CURSOR"));
    }
    let mut resumed = DataExportCheckpoint::from_json(
        &serialized,
        &export_plan,
        &identity.package_revision,
        &identity.schema_fingerprint,
        &first_output,
        &first_resume_state,
    )
    .expect("output and trusted cursor resume exactly");
    let second = execute_export_page(
        &export_plan,
        &mut resumed,
        &identity.package_revision,
        &identity.schema_fingerprint,
        &first_output,
        &first_resume_state,
        |request| dispatch(&app, Some(&token), request),
    )
    .await
    .expect("resumed authorized export page succeeds")
    .expect("second page exists");
    assert_eq!(second.added_record_count(), 1);
    assert!(second.is_complete());
    assert!(second.trusted_next_cursor().is_none());
    let (output, terminal_resume_state) = second.into_parts();
    let complete_json = resumed
        .canonical_json()
        .expect("complete checkpoint serializes");
    DataExportCheckpoint::from_json(
        &complete_json,
        &export_plan,
        &identity.package_revision,
        &identity.schema_fingerprint,
        &output,
        &terminal_resume_state,
    )
    .expect("the executor-observed terminal response validates once");
    let complete_reuse = execute_export_page(
        &export_plan,
        &mut resumed,
        &identity.package_revision,
        &identity.schema_fingerprint,
        &output,
        &terminal_resume_state,
        |_| async { Err::<DataHttpResponse, _>(()) },
    )
    .await
    .expect_err("a complete checkpoint cannot be reused as a second terminal success");
    assert_eq!(complete_reuse, DataError::CheckpointMismatch);
    let records = output
        .strip_suffix(b"\n")
        .expect("canonical JSONL ends with newline")
        .split(|byte| *byte == b'\n')
        .map(|line| parse_json_strict(line).expect("export line is strict JSON"))
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 101);
    let mut exported_codes = Vec::new();
    for record in &records {
        assert_eq!(record["data"].as_object().map(|data| data.len()), Some(1));
        exported_codes.push(
            record["data"]["code"]
                .as_str()
                .expect("projected code is a string")
                .to_owned(),
        );
        assert!(record["id"].is_string());
        assert_eq!(record["revision"], 1);
    }
    exported_codes.sort();
    assert_eq!(
        exported_codes,
        (0..101)
            .map(|index| format!("ROW-{index:03}"))
            .collect::<Vec<_>>()
    );
    let output_text = String::from_utf8(output).expect("canonical JSONL is UTF-8");
    assert!(!output_text.contains(SECRET_CANARY));
    assert!(!output_text.contains(PRINCIPAL_CANARY));
    assert!(!output_text.contains("jurisdiction"));

    let (mut refused_checkpoint, refused_resume_state) = DataExportCheckpoint::start(
        &export_plan,
        &identity.package_revision,
        &identity.schema_fingerprint,
    )
    .unwrap();
    let refused = execute_export_page(
        &export_plan,
        &mut refused_checkpoint,
        &identity.package_revision,
        &identity.schema_fingerprint,
        &[],
        &refused_resume_state,
        |request| dispatch(&app, Some(&wrong_purpose), request),
    )
    .await
    .expect_err("wrong verified purpose is concealed by the normal read path");
    assert_eq!(refused, DataError::OperationRefused);
    assert_eq!(refused_checkpoint.output_length(), 0);
    assert!(!format!("{refused:?} {refused}").contains(PRINCIPAL_CANARY));

    let (mut widened_checkpoint, widened_resume_state) = DataExportCheckpoint::start(
        &export_plan,
        &identity.package_revision,
        &identity.schema_fingerprint,
    )
    .unwrap();
    let widened_body = canonicalize_json(&json!({
        "items":[{"id":"00000000-0000-4000-8000-000000000001","revision":1,
                   "data":{"code":"ROW-000","secret":SECRET_CANARY}}],
        "pageInfo":{"nextCursor":null}
    }))
    .unwrap();
    let widened = execute_export_page(
        &export_plan,
        &mut widened_checkpoint,
        &identity.package_revision,
        &identity.schema_fingerprint,
        &[],
        &widened_resume_state,
        |_| async {
            Ok::<_, ()>(
                DataHttpResponse::new(
                    200,
                    Some("application/json".to_owned()),
                    widened_body.clone(),
                )
                .unwrap(),
            )
        },
    )
    .await
    .expect_err("a widened transport response is discarded before output or checkpoint advance");
    assert_eq!(widened, DataError::InvalidResponse);
    assert_eq!(widened_checkpoint.output_length(), 0);
    assert!(!format!("{widened:?} {widened}").contains(SECRET_CANARY));

    let audit: String = database
        .admin
        .query_one(
            "SELECT coalesce(string_agg(convert_from(envelope, 'UTF8'), ''), '')
               FROM registry_internal.registry_audit",
            &[],
        )
        .await
        .expect("administrator inspects minimized audit")
        .get(0);
    assert!(!audit.contains(PRINCIPAL_CANARY));
    assert!(!audit.contains(SECRET_CANARY));
    assert!(!audit.contains("ROW-000"));

    idp.stop().await;
    database.cleanup().await;
}

fn compiled_registry() -> registry_server::CompiledRegistry {
    let source = json!({
        "apiVersion":"registry.registrystack.org/v1alpha1",
        "kind":"RegistryProject",
        "registry":{"id":"data-export-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
        "entities":[{
            "id":"entry", "route":"entries", "mutationMode":"create_only",
            "batch":{"maximumItems":60,"maximumBytes":131072},
            "fields":[
                {"id":"code","type":"string","required":true,"maxLength":16,
                 "classification":"internal"},
                {"id":"jurisdiction","type":"string","required":true,"maxLength":16,
                 "classification":"internal"},
                {"id":"secret","type":"text","required":true,"maxLength":160,
                 "classification":"restricted"}
            ],
            "constraints":[{"kind":"unique","fields":["code"]}],
            "events":[{"id":"entry-created","trigger":"created","projection":["code"]}]
        }],
        "accessProfiles":[{
            "id":PROFILE, "principalClaim":"registry_principal",
                "requiredPurposes":["data-export"],
            "grants":[{
                "entity":"entry",
                "operations":["create","batch","list"],
                "readableFields":["code"],
                "writableFields":["code","jurisdiction","secret"],
                "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdictions","operator":"in"}],
                "allowDataExport":true
            }]
        }]
    });
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    compile_project(&project, &[], CompileProfile::Authoring).expect("data export project compiles")
}

fn authenticated_app(
    database: &TestDatabase,
    registry: Arc<registry_server::CompiledRegistry>,
    identity: registry_server::postgres::ExpectedRegistryIdentity,
    idp: &MockIdp,
) -> axum::Router {
    let pool = database
        .runtime_config
        .build_pool()
        .expect("runtime pool builds");
    let lock_key = RegistryLockKey::derive("data-export-registry").expect("lock key derives");
    let audit = AuditProfile::production_from_secret_bytes(vec![0x61; 32].into())
        .expect("test audit profile is keyed");
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x43; 32]), Duration::from_secs(300))
            .expect("cursor codec builds"),
    );
    let reads = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit.clone(),
        cursors.clone(),
    ));
    let mutations = Arc::new(PostgresRecordMutationService::new(
        pool,
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
                package_revision: identity.package_revision,
                schema_fingerprint: identity.schema_fingerprint,
            },
            reads,
            Arc::new(AlwaysReady),
            cursors,
        )
        .with_postgres_mutations(mutations),
    );
    let key_source = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        idp.jwks_uri(),
        JwksFetcherConfig::defaults(),
        FetchUrlPolicy::dev(),
    ));
    let authenticator = Arc::new(
        RegistryAuthenticator::new(
            &registry,
            oidc_verifier_config(idp.issuer(), vec![AUDIENCE.to_owned()]),
            key_source,
            AuthorityClaimConfig::new("registry_principal", Some("purpose".to_owned())),
        )
        .expect("OIDC authority matches the compiled Registry"),
    );
    authenticated_router(service, authenticator)
}

struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

#[derive(Clone, Copy)]
struct Counts {
    current: i64,
    revisions: i64,
    commits: i64,
    commit_members: i64,
    outbox: i64,
    audit: i64,
    idempotency: i64,
}

async fn durable_counts(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
) -> Counts {
    let table = &registry.entities()["entry"].physical_table;
    let row = database
        .admin
        .query_one(
            &format!(
                "SELECT
                   (SELECT count(*) FROM registry_data.\"{table}\"),
                   (SELECT count(*) FROM registry_internal.registry_revisions),
                   (SELECT count(*) FROM registry_internal.registry_outbox),
                   (SELECT count(*) FROM registry_internal.registry_audit),
                   (SELECT count(*) FROM registry_internal.registry_idempotency),
                   (SELECT count(*) FROM registry_internal.registry_revision_commits),
                   (SELECT count(*) FROM registry_internal.registry_revision_commit_members)"
            ),
            &[],
        )
        .await
        .expect("administrator inspects durable data-operation effects");
    Counts {
        current: row.get(0),
        revisions: row.get(1),
        outbox: row.get(2),
        audit: row.get(3),
        idempotency: row.get(4),
        commits: row.get(5),
        commit_members: row.get(6),
    }
}

async fn dispatch(
    app: &axum::Router,
    token: Option<&str>,
    request: DataHttpRequest,
) -> Result<DataHttpResponse, ()> {
    let method = match request.method() {
        DataHttpMethod::Get => Method::GET,
        DataHttpMethod::Post => Method::POST,
    };
    let mut http = Request::builder()
        .method(method)
        .uri(request.path_and_query())
        .body(Body::from(request.body().to_vec()))
        .map_err(|_| ())?;
    if let Some(token) = token {
        http.headers_mut().insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| ())?,
        );
    }
    for (name, value) in [
        ("content-type", request.content_type()),
        ("idempotency-key", request.idempotency_key()),
    ] {
        if let Some(value) = value {
            http.headers_mut().insert(
                HeaderName::from_static(name),
                HeaderValue::from_str(value).map_err(|_| ())?,
            );
        }
    }
    let response = app.clone().oneshot(http).await.map_err(|_| ())?;
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .map_err(|_| ())?
        .to_vec();
    DataHttpResponse::new(status, content_type, body).map_err(|_| ())
}
