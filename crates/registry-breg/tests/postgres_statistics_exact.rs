// SPDX-License-Identifier: Apache-2.0
//! Exact statistical reads of ended periods, served over HTTP to a profile that cannot read records.

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{Request, Response, StatusCode};
use chrono::NaiveDate;
use chrono::Utc;
use postgres_harness::TestDatabase;
use registry_breg::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedRequestClaims,
};
use registry_breg::compiler::{compile_project_with_assets, CompileProfile};
use registry_breg::contract::{parse_project_json, ModuleAssetSource};
use registry_breg::cursor::CursorCodec;
use registry_breg::postgres::{
    begin_record_transaction, initialize_compiled_registry_state_for_test, install_compiled_schema,
    ClaimContext, PostgresRecordReadService, PostgresStatisticsService, RegistryLockKey,
    RegistryStateTestIdentity,
};
use registry_platform_audit::AuditProfile;
use serde_json::{json, Value};
use tower::Service as _;
use zeroize::Zeroizing;

const PACKAGE_ID: &str = "statistics-exact-registry";
const DATABASE_ID: &str = "statistics-exact-database";

/// One seeded record: category code, event date, amount, quantity.
type Row = (
    &'static str,
    &'static str,
    Option<&'static str>,
    Option<&'static str>,
);

const DEPENDENT_SQL: &str = "SELECT r.id AS id, CASE WHEN r.event_date > registry_context.evaluation_date() - 20 THEN 'a' ELSE 'b' END AS evaluated_category FROM registry_source.record r";

/// A minimum-count dataset with a count, a sum and a mean and no publisher.
/// The analyst reads records and anchors exact reads; the statistician holds
/// read-exact and no record access; the live reader holds read-live only.
fn registry_source(dimension: &str) -> Value {
    let readable = json!([
        "subject",
        "active",
        "category",
        "event-date",
        "amount",
        "quantity",
        "evaluated-category"
    ]);
    json!({"datasets":[{"id": "statistics-exact"}],
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
        "kind":"BRegProject",
        "project":{"id":PACKAGE_ID,"version":"1","defaultLanguage":"en","canonicalBaseIri":"https://statistics.example.test","timezone":"UTC"},
        "recordTypes":[{
            "id":"record","primaryDataset":"statistics-exact","route":"records","mutationMode":"mutable",
            "accessLog":{"subjectField":"subject"},
            "fields":[
                {"id":"subject","type":"string","maximumLength":128,"required":true,"classification":"internal"},
                {"id":"active","type":"boolean","required":true,"classification":"internal"},
                {"id":"category","type":"vocabulary-code","vocabulary":"category","required":true,"classification":"internal"},
                {"id":"event-date","type":"date","required":true,"classification":"internal"},
                {"id":"amount","type":"decimal","precision":10,"scale":2,"classification":"internal"},
                {"id":"quantity","type":"int64","classification":"internal"}
            ],
            "derived":[{
                "id":"statistics","sql":"sql/statistics.sql","key":"id",
                "fields":[{"id":"evaluated-category","type":"vocabulary-code","vocabulary":"category","values":["a","b"],"classification":"internal"}]
            }]
        }],
        "accessProfiles":[
            {"id":"analyst","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
                "recordType":"record","operations":["list"],
                "readableFields":readable,
                "filterableFields":["subject","active","category","event-date","evaluated-category"],"allowCount":true,
                "rowBoundaries":"unrestricted"
            }],"datasets":[{"dataset":"records-by-category","operations":["read-live"]}]}},
            {"id":"statistician","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{
                "datasets":[{"dataset":"records-by-category","operations":["read-exact"]}]}},
            {"id":"live-reader","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
                "recordType":"record","operations":["list"],
                "readableFields":readable,
                "filterableFields":["subject","active","category","event-date","evaluated-category"],"allowCount":true,
                "rowBoundaries":"unrestricted"
            }],"datasets":[{"dataset":"records-by-category","operations":["read-live"]}]}},
            {"id":"seed","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
                "recordType":"record","operations":["create"],
                "writableFields":["subject","active","category","event-date","amount","quantity"],
                "rowBoundaries":"unrestricted"
            }]}}
        ],
        "vocabularies":[{"id":"category","values":["a","b","c"]}],
        "statisticalDatasets":[{
            "id":"records-by-category","unit":"record","population":"active eq true",
            "period":{"type":"flow","field":"event-date","granularity":"month","firstPeriod":"2025-01"},
            "dimensions":[dimension],
            "measures":[
                {"id":"records","type":"count"},
                {"id":"amount-sum","type":"sum","field":"amount"},
                {"id":"amount-mean","type":"mean","field":"amount","scale":2}
            ],
            "exactReads":{"accessProfile":"analyst"},
            "disclosure":{"type":"minimum-count-and-rounding","minimumCount":5,"roundingBase":5}
        }]
    })
}

fn assets() -> Vec<ModuleAssetSource> {
    vec![ModuleAssetSource {
        module: None,
        path: "sql/statistics.sql".to_owned(),
        bytes: DEPENDENT_SQL.as_bytes().to_vec(),
    }]
}

/// A GET as `subject`, who holds the access profile named by `profile`, or
/// with no verified claims at all.
async fn get(
    app: &axum::Router,
    uri: &str,
    subject: Option<&str>,
    accept: Option<&str>,
) -> Response<Body> {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(accept) = accept {
        builder = builder.header("accept", accept);
    }
    let mut request = builder.body(Body::empty()).expect("request builds");
    if let Some(subject) = subject {
        request.extensions_mut().insert(
            VerifiedRequestClaims::authenticated(
                "principal",
                subject,
                Default::default(),
                None,
                Default::default(),
            )
            .expect("claims are valid"),
        );
    }
    app.clone()
        .call(request)
        .await
        .expect("router returns a response")
}

async fn exact(app: &axum::Router, query: &str, accept: Option<&str>) -> Response<Body> {
    get(
        app,
        &format!("/v1/statistics/records-by-category:exact?accessProfile=statistician{query}"),
        Some("exact-statistician"),
        accept,
    )
    .await
}

/// The document cell of one period, dimension code and measure as `[value, status]`.
fn cell(document: &Value, period: &str, code: &str, measure: &str) -> Value {
    let found = document["cells"]
        .as_array()
        .expect("cells are an array")
        .iter()
        .find(|cell| {
            cell["period"] == period
                && cell["measure"] == measure
                && cell["dimensions"]
                    .as_object()
                    .is_some_and(|dimensions| dimensions.values().any(|value| value == code))
        })
        .unwrap_or_else(|| panic!("no cell for {period} {code} {measure}: {document}"));
    json!([found["value"], found["status"]])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_profile_without_record_access_reads_exact_values_of_an_ended_period() {
    // Category a has one record, below the release disclosure minimum of five.
    let rows: Vec<Row> = vec![
        ("a", "2025-03-10", Some("4.00"), Some("1")),
        ("b", "2025-03-11", Some("1.00"), Some("1")),
        ("b", "2025-03-12", Some("2.00"), Some("1")),
        ("b", "2025-03-13", Some("6.00"), Some("1")),
    ];
    let (database, migration_task, app) =
        fixture_for(registry_source("category"), &assets(), &rows).await;

    let response = exact(&app, "&from=2025-03&to=2025-03", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let document = body_json(response).await;
    assert_eq!(
        document["exact"],
        json!({"evaluatedAt": Utc::now().date_naive().to_string(), "accessProfile": "statistician"})
    );
    for absent in ["live", "release", "disclosure"] {
        assert!(document.get(absent).is_none(), "{absent}: {document}");
    }
    assert!(document["cells"]
        .as_array()
        .unwrap()
        .iter()
        .all(|cell| { matches!(cell["status"].as_str(), Some("exact" | "not-applicable")) }));
    for (code, measure, expected) in [
        ("a", "records", json!([1, "exact"])),
        ("a", "amount-sum", json!(["4.00", "exact"])),
        ("a", "amount-mean", json!(["4.00", "exact"])),
        ("b", "records", json!([3, "exact"])),
        ("b", "amount-sum", json!(["9.00", "exact"])),
        ("b", "amount-mean", json!(["3.00", "exact"])),
        ("c", "records", json!([0, "exact"])),
        ("c", "amount-mean", json!([Value::Null, "not-applicable"])),
        ("_T", "records", json!([4, "exact"])),
        ("_T", "amount-sum", json!(["13.00", "exact"])),
    ] {
        assert_eq!(
            cell(&document, "2025-03", code, measure),
            expected,
            "{code} {measure}"
        );
    }

    // The values are the visibility of the exactReads profile: the analyst,
    // who holds read-live, sees the same cells.
    let live = get(
        &app,
        "/v1/statistics/records-by-category:live?accessProfile=analyst&from=2025-03&to=2025-03",
        Some("exact-analyst"),
        None,
    )
    .await;
    assert_eq!(live.status(), StatusCode::OK);
    assert_eq!(body_json(live).await["cells"], document["cells"]);

    let csv = exact(&app, "&from=2025-03&to=2025-03", Some("text/csv")).await;
    assert_eq!(csv.status(), StatusCode::OK);
    assert_eq!(csv.headers()["content-type"], "text/csv; charset=utf-8");
    let csv = String::from_utf8(body_bytes(csv).await).expect("CSV is UTF-8");
    assert!(
        csv.lines().any(|line| line.ends_with(",a,records,1,exact")),
        "{csv}"
    );

    // The audit entry names the caller's profile and the requested range.
    let terminal = database
        .audit_records()
        .into_iter()
        .find(|record| {
            record["operationId"] == "statistics.records-by-category.read-exact"
                && record["phase"] == "terminal"
        })
        .expect("a terminal read-exact audit entry");
    assert_eq!(terminal["selectedAccessProfile"], "statistician");
    assert_eq!(terminal["outcome"], "returned");
    assert_eq!(terminal["periodFrom"], "2025-03");
    assert_eq!(terminal["periodTo"], "2025-03");
    let live_entry = database
        .audit_records()
        .into_iter()
        .find(|record| {
            record["operationId"] == "statistics.records-by-category.read-live"
                && record["phase"] == "terminal"
        })
        .expect("a terminal read-live audit entry");
    assert!(live_entry.get("periodFrom").is_none());

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_exact_read_refuses_what_it_does_not_serve() {
    let rows: Vec<Row> = vec![("a", "2025-03-10", Some("4.00"), Some("1"))];
    let (database, migration_task, app) =
        fixture_for(registry_source("category"), &assets(), &rows).await;
    let current = chrono::Datelike::year(&Utc::now().date_naive());
    let month = chrono::Datelike::month(&Utc::now().date_naive());
    let current_code = format!("{current}-{month:02}");

    let not_ended = exact(
        &app,
        &format!("&from={current_code}&to={current_code}"),
        None,
    )
    .await;
    assert_eq!(not_ended.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        body_json(not_ended).await["refusalCode"],
        "period-not-ended"
    );

    let spanning = exact(&app, &format!("&from=2025-03&to={current_code}"), None).await;
    assert_eq!(spanning.status(), StatusCode::UNPROCESSABLE_ENTITY);

    for query in ["", "&from=2025-03", "&to=2025-03"] {
        let response = exact(&app, query, None).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(
            body_json(response).await["code"],
            "query.invalid",
            "{query}"
        );
    }
    let reversed = exact(&app, "&from=2025-04&to=2025-03", None).await;
    assert_eq!(reversed.status(), StatusCode::BAD_REQUEST);

    let before_first = exact(&app, "&from=2024-12&to=2025-03", None).await;
    assert_eq!(before_first.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(before_first).await["code"], "query.invalid");

    // A profile that holds read-live and not read-exact sees no such route.
    let live_only = get(
        &app,
        "/v1/statistics/records-by-category:exact?accessProfile=live-reader&from=2025-03&to=2025-03",
        Some("exact-live-reader"),
        None,
    )
    .await;
    assert_eq!(live_only.status(), StatusCode::NOT_FOUND);
    let anchor = get(
        &app,
        "/v1/statistics/records-by-category:exact?accessProfile=analyst&from=2025-03&to=2025-03",
        Some("exact-analyst"),
        None,
    )
    .await;
    assert_eq!(anchor.status(), StatusCode::NOT_FOUND);

    let unauthenticated = get(
        &app,
        "/v1/statistics/records-by-category:exact?accessProfile=statistician&from=2025-03&to=2025-03",
        None,
        None,
    )
    .await;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_evaluation_date_dependent_dataset_reads_one_period_at_its_reference_date() {
    // At the March reference date (31 March), a record dated within the 19 days
    // before it is category a; an earlier record is category b. Evaluated today
    // every record is category b.
    let rows: Vec<Row> = vec![
        ("a", "2025-03-10", Some("1.00"), None),
        ("a", "2025-03-20", Some("2.00"), None),
        ("a", "2025-03-25", Some("3.00"), None),
    ];
    let (database, migration_task, app) =
        fixture_for(registry_source("evaluated-category"), &assets(), &rows).await;

    let response = exact(&app, "&from=2025-03&to=2025-03", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let document = body_json(response).await;
    assert_eq!(document["exact"]["evaluatedAt"], "2025-03-31");
    assert_eq!(
        cell(&document, "2025-03", "a", "records"),
        json!([2, "exact"])
    );
    assert_eq!(
        cell(&document, "2025-03", "b", "records"),
        json!([1, "exact"])
    );

    let range = exact(&app, "&from=2025-03&to=2025-04", None).await;
    assert_eq!(range.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(range).await["code"], "query.invalid");

    migration_task.abort();
    database.cleanup().await;
}

async fn fixture_for(
    source: Value,
    assets: &[ModuleAssetSource],
    rows: &[Row],
) -> (TestDatabase, tokio::task::JoinHandle<()>, axum::Router) {
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).expect("parses");
    let compiled = Arc::new(
        compile_project_with_assets(&project, &[], assets, CompileProfile::Authoring)
            .expect("compiles"),
    );
    let database = TestDatabase::create(4).await;
    let (migration, migration_task) = database.connect_migration().await;
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("compiled schema installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "package-statistics-exact-1",
        },
    )
    .await
    .expect("runtime identity initializes");
    let pool = database.runtime_config.build_pool().expect("pool builds");
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives");
    seed_records(&pool, lock_key, &identity, &compiled, rows).await;

    let audit = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x72; 32].into())
            .expect("audit profile is keyed"),
    );
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x31; 32]), Duration::from_secs(300))
            .expect("cursor key is valid"),
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
    let app = router(Arc::new(
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
    (database, migration_task, app)
}

async fn seed_records(
    pool: &registry_breg::postgres::RuntimePool,
    lock_key: RegistryLockKey,
    identity: &registry_breg::postgres::ExpectedRegistryIdentity,
    registry: &registry_breg::CompiledRegistry,
    rows: &[Row],
) {
    let claims = ClaimContext::for_compiled(
        registry,
        "record",
        Some("fixture-seeder".to_owned()),
        "seed",
        None,
        Vec::new(),
    )
    .expect("seed context is compiler-bound");
    let mut client = pool.get_for_test().await.expect("runtime connection opens");
    let transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(2),
        identity,
        &claims,
    )
    .await
    .expect("seed transaction opens");
    let entity = &registry.entities()["record"];
    let column = |field: &str| quote_identifier(&entity.fields[field].physical_name);
    let table = quote_identifier(&entity.physical_table);
    let (subject, active, category, event_date, amount, quantity) = (
        column("subject"),
        column("active"),
        column("category"),
        column("event-date"),
        column("amount"),
        column("quantity"),
    );
    let sql = format!(
        "INSERT INTO registry_data.{table}
             (record_id, record_revision, record_lifecycle,
              {subject}, {active}, {category}, {event_date}, {amount}, {quantity})
         VALUES ($1::text::uuid, 1, 'active', $1, true, $2, $3, $4::text::numeric, $5::text::bigint)"
    );
    for (index, (code, date, amount_text, quantity_text)) in rows.iter().enumerate() {
        let id = format!("00000000-0000-4000-8000-{:012}", index + 1);
        let date = NaiveDate::parse_from_str(date, "%Y-%m-%d").expect("seed date parses");
        transaction
            .transaction_for_test()
            .execute(&sql, &[&id, code, &date, amount_text, quantity_text])
            .await
            .expect("seed row inserts through runtime RLS");
    }
    transaction
        .commit()
        .await
        .expect("seed transaction commits");
}

async fn body_bytes(response: Response<Body>) -> Vec<u8> {
    to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .expect("response body reads")
        .to_vec()
}

async fn body_json(response: Response<Body>) -> Value {
    serde_json::from_slice(&body_bytes(response).await).expect("response is JSON")
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}
