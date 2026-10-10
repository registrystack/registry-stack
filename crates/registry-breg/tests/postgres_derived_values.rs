// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use postgres_harness::TestDatabase;
use registry_breg::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedRequestClaims,
};
use registry_breg::compiler::{compile_project_with_assets, CompileProfile};
use registry_breg::contract::{parse_project_json, ModuleAssetSource};
use registry_breg::cursor::CursorCodec;
use registry_breg::postgres::{
    begin_record_transaction, initialize_registry_state_for_catalog_test, install_compiled_schema,
    ClaimContext, ExpectedManagedCatalog, PostgresRecordReadService, RegistryLockKey,
    RegistryStateTestIdentity,
};
use registry_platform_audit::AuditProfile;
use serde_json::Value;
use tower::Service as _;
use zeroize::Zeroizing;

const PACKAGE: &str = "derived-values";
const SECRET_CANARY: &str = "derived-secret-canary-must-not-escape";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_derived_values_enforce_declared_contracts() {
    let registry = Arc::new(compiled_registry());
    let database = TestDatabase::create(4).await;
    let (migration, migration_task) = database.connect_migration().await;
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("compiled derived-value fixture installs");
    let identity = initialize_registry_state_for_catalog_test(
        &migration,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(&registry),
        RegistryStateTestIdentity {
            package_id: PACKAGE,
            database_id: "derived-values-database",
            label: "derived-values-contract",
        },
    )
    .await
    .expect("compiled catalog binds the fixture identity");
    migration_task.abort();

    let pool = database.runtime_config.build_pool().expect("bounded pool");
    let lock_key = RegistryLockKey::derive(PACKAGE).expect("bounded lock key");
    let entity = &registry.entities()["entry"];
    let scenarios = [
        "minimum-boundaries",
        "maximum-boundaries",
        "unicode-boundaries",
        "nullable",
        "string-short",
        "string-long",
        "text-long",
        "decimal-scale",
        "decimal-precision",
        "decimal-minimum",
        "decimal-maximum",
        "decimal-nan",
        "decimal-infinity",
        "decimal-invalid",
        "int64-fractional",
        "int64-underflow",
        "int64-overflow",
        "int64-nan",
        "int64-infinity",
        "int64-invalid",
        "vocabulary",
    ];
    let mut record_ids = BTreeMap::new();
    let mut seed = pool.get_for_test().await.expect("seed connection");
    let context = read_context(&registry);
    let transaction = begin_record_transaction(
        &mut seed,
        lock_key,
        Duration::from_secs(2),
        &identity,
        &context,
    )
    .await
    .expect("seed installs the runtime context");
    for (offset, scenario) in scenarios.iter().enumerate() {
        let record_id = format!("00000000-0000-4000-8000-{:012}", offset + 1);
        transaction
            .transaction_for_test()
            .execute(
                &format!(
                    "INSERT INTO registry_data.\"{}\" (record_id, \"{}\") VALUES ($1::text::uuid, $2)",
                    entity.physical_table, entity.fields["scenario"].physical_name,
                ),
                &[&record_id, scenario],
            )
            .await
            .expect("synthetic source row inserts");
        record_ids.insert(*scenario, record_id);
    }
    transaction.commit().await.expect("seed commits");
    drop(seed);

    let view = registry
        .ddl()
        .views
        .iter()
        .find(|view| view.id == "entity.entry.derived.contract")
        .expect("compiled derived view");
    let column = |field: &str| {
        registry.entities()["entry"].derived_fields[field]
            .logical
            .sql_name
            .clone()
    };
    let valid_columns = [
        column("short-code"),
        column("description"),
        column("amount"),
        column("count"),
        column("state"),
    ];
    for (scenario, expected) in [
        (
            "minimum-boundaries",
            [
                Some("ab"),
                Some(""),
                Some("-50.00"),
                Some("-9223372036854775808"),
                Some("open"),
            ],
        ),
        (
            "maximum-boundaries",
            [
                Some("abcd"),
                Some("abcde"),
                Some("50.00"),
                Some("9223372036854775807"),
                Some("closed"),
            ],
        ),
        (
            "unicode-boundaries",
            [
                Some("é猫ab"),
                Some("é猫abc"),
                Some("0.00"),
                Some("1"),
                Some("open"),
            ],
        ),
        ("nullable", [None, None, None, None, None]),
    ] {
        let mut client = pool.get_for_test().await.expect("valid-row connection");
        let transaction = begin_record_transaction(
            &mut client,
            lock_key,
            Duration::from_secs(2),
            &identity,
            &context,
        )
        .await
        .expect("valid-row context");
        let row = transaction
            .transaction_for_test()
            .query_one(
                &format!(
                    "SELECT {} FROM registry_derived.\"{}\" WHERE id = $1::text::uuid",
                    valid_columns
                        .iter()
                        .map(|column| format!("\"{column}\"::text"))
                        .collect::<Vec<_>>()
                        .join(", "),
                    view.name,
                ),
                &[&record_ids[scenario]],
            )
            .await
            .expect("valid boundary and nullable values remain readable");
        let actual: Vec<Option<String>> = (0..valid_columns.len())
            .map(|index| row.get(index))
            .collect();
        assert_eq!(
            actual,
            expected.map(|value| value.map(str::to_owned)),
            "{scenario}"
        );
        transaction.commit().await.expect("valid read commits");
    }

    for (scenario, field) in [
        ("string-short", "short-code"),
        ("string-long", "short-code"),
        ("text-long", "description"),
        ("decimal-scale", "amount"),
        ("decimal-precision", "amount"),
        ("decimal-minimum", "amount"),
        ("decimal-maximum", "amount"),
        ("decimal-nan", "amount"),
        ("decimal-infinity", "amount"),
        ("decimal-invalid", "amount"),
        ("int64-fractional", "count"),
        ("int64-underflow", "count"),
        ("int64-overflow", "count"),
        ("int64-nan", "count"),
        ("int64-infinity", "count"),
        ("int64-invalid", "count"),
        ("vocabulary", "state"),
    ] {
        let mut client = pool.get_for_test().await.expect("invalid-row connection");
        let transaction = begin_record_transaction(
            &mut client,
            lock_key,
            Duration::from_secs(2),
            &identity,
            &context,
        )
        .await
        .expect("invalid-row context");
        let error = transaction
            .transaction_for_test()
            .query_one(
                &format!(
                    "SELECT \"{}\"::text FROM registry_derived.\"{}\" WHERE id = $1::text::uuid",
                    column(field),
                    view.name,
                ),
                &[&record_ids[scenario]],
            )
            .await
            .expect_err("an invalid derived value must fail before a lossy cast");
        let message = error
            .as_db_error()
            .expect("PostgreSQL reports the contract refusal")
            .message();
        assert_eq!(
            message,
            format!(
                "invalid input syntax for type bigint: \"derived field entry.{field} violates declared type\""
            ),
            "{scenario}: the PostgreSQL error must identify only the governed field"
        );
    }

    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x51; 32]), Duration::from_secs(300))
            .expect("test cursor key"),
    );
    let reads = PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        registry_breg::audit::test_support::capturing(
            AuditProfile::production_from_secret_bytes(vec![0x52; 32].into()).expect("keyed audit"),
        )
        .0,
        cursors.clone(),
    );
    let app = router(Arc::new(HttpService::new(
        registry,
        ReadRuntimeIdentity {
            package_revision: identity.activation_id,
            schema_fingerprint: identity.schema_fingerprint,
        },
        Arc::new(reads),
        Arc::new(AlwaysReady),
        cursors,
    )));
    let mut request = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/v1/records/entries/{}?$select=shortCode",
            record_ids["string-long"]
        ))
        .body(Body::empty())
        .expect("bounded request");
    request.extensions_mut().insert(
        VerifiedRequestClaims::authenticated(
            "registry_principal",
            "test-principal",
            BTreeSet::new(),
            None,
            BTreeMap::new(),
        )
        .expect("verified claims"),
    );
    let response = app.clone().call(request).await.expect("router response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("bounded problem body");
    let problem: Value = serde_json::from_slice(&body).expect("JSON problem");
    assert_eq!(problem["code"], "source.unavailable");
    let rendered = problem.to_string();
    assert!(!rendered.contains(SECRET_CANARY));
    assert!(!rendered.contains("short-code"));

    drop(app);
    drop(pool);
    database.cleanup().await;
}

fn read_context(registry: &registry_breg::CompiledRegistry) -> ClaimContext {
    ClaimContext::for_compiled(
        registry,
        "entry",
        Some("test-principal".to_owned()),
        "reader",
        None,
        Vec::new(),
    )
    .expect("fixture context matches the compiled profile")
}

fn compiled_registry() -> registry_breg::CompiledRegistry {
    let project = parse_project_json(br#"{
        "apiVersion":"registry.registrystack.org/v1alpha1",
        "kind":"RegistryProject",
        "registry":{"id":"derived-values","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://example.test"},
        "entities":[{
            "id":"entry","primaryDataset":"test-dataset","route":"entries","mutationMode":"mutable",
            "fields":[{"id":"scenario","type":"string","required":true,"minLength":1,"maxLength":64,"classification":"internal"}],
            "derived":[{
                "id":"contract","sql":"contract.sql","key":"id","execution":"live",
                "fields":[
                    {"id":"short-code","type":"string","minLength":2,"maxLength":4,"classification":"internal"},
                    {"id":"description","type":"text","maxLength":5,"classification":"internal"},
                    {"id":"amount","type":"decimal","precision":5,"scale":2,"minimum":"-50.00","maximum":"50.00","classification":"internal"},
                    {"id":"count","type":"int64","classification":"internal"},
                    {"id":"state","type":"vocabulary-code","vocabulary":"states","values":["open","closed"],"classification":"internal"}
                ]
            }]
        }],
        "accessProfiles":[{
            "id":"reader","default":true,"principalClaim":"registry_principal","requiredScopes":"unrestricted",
            "permissions":[{
                "entity":"entry","operations":["create","get","list"],
                "readableFields":["scenario","short-code","description","amount","count","state"],
                "writableFields":["scenario"],
                "rowBoundaries":"unrestricted"
            }]
        }]
    }"#)
    .expect("derived-value fixture parses");
    let sql = format!(
        "SELECT r.id AS id,
                CASE r.scenario
                  WHEN 'nullable' THEN NULL
                  WHEN 'string-short' THEN 'x'
                  WHEN 'string-long' THEN '{SECRET_CANARY}'
                  WHEN 'unicode-boundaries' THEN 'é猫ab'
                  WHEN 'maximum-boundaries' THEN 'abcd'
                  ELSE 'ab'
                END AS short_code,
                CASE r.scenario
                  WHEN 'nullable' THEN NULL
                  WHEN 'text-long' THEN 'abcdef'
                  WHEN 'unicode-boundaries' THEN 'é猫abc'
                  WHEN 'minimum-boundaries' THEN ''
                  WHEN 'maximum-boundaries' THEN 'abcde'
                  ELSE 'abc'
                END AS description,
                CASE r.scenario
                  WHEN 'nullable' THEN NULL
                  WHEN 'decimal-scale' THEN '1.234'
                  WHEN 'decimal-precision' THEN '1000.00'
                  WHEN 'decimal-minimum' THEN '-50.01'
                  WHEN 'decimal-maximum' THEN '50.01'
                  WHEN 'decimal-nan' THEN 'NaN'
                  WHEN 'decimal-infinity' THEN 'Infinity'
                  WHEN 'decimal-invalid' THEN 'numeric-secret-canary'
                  WHEN 'minimum-boundaries' THEN '-50.00'
                  WHEN 'maximum-boundaries' THEN '50.00'
                  ELSE '0.00'
                END AS amount,
                CASE r.scenario
                  WHEN 'nullable' THEN NULL
                  WHEN 'int64-fractional' THEN '1.5'
                  WHEN 'int64-underflow' THEN '-9223372036854775809'
                  WHEN 'int64-overflow' THEN '9223372036854775808'
                  WHEN 'int64-nan' THEN 'NaN'
                  WHEN 'int64-infinity' THEN 'Infinity'
                  WHEN 'int64-invalid' THEN 'integer-secret-canary'
                  WHEN 'minimum-boundaries' THEN '-9223372036854775808'
                  WHEN 'maximum-boundaries' THEN '9223372036854775807'
                  ELSE '1'
                END AS count,
                CASE r.scenario
                  WHEN 'nullable' THEN NULL
                  WHEN 'vocabulary' THEN 'secret-vocabulary-canary'
                  WHEN 'maximum-boundaries' THEN 'closed'
                  ELSE 'open'
                END AS state
           FROM registry_source.entry r"
    );
    compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "contract.sql".to_owned(),
            bytes: sql.into_bytes(),
        }],
        CompileProfile::Authoring,
    )
    .expect("derived-value fixture compiles")
}

struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}
