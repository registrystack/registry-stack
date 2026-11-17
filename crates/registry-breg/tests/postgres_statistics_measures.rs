// SPDX-License-Identifier: Apache-2.0
//! Sum and mean measures over live statistical reads, computed by PostgreSQL.

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{Request, Response, StatusCode};
use chrono::NaiveDate;
use postgres_harness::TestDatabase;
use registry_breg::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedRequestClaims,
};
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
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

const PACKAGE_ID: &str = "statistics-measures-registry";
const DATABASE_ID: &str = "statistics-measures-database";

/// One seeded record: category code, event date, amount, quantity. The amount and
/// quantity are decimal and integer text, or `None` for a null field.
type Row = (
    &'static str,
    &'static str,
    Option<&'static str>,
    Option<&'static str>,
);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_total_of_a_sum_and_mean_is_computed_from_the_records_not_from_the_cells() {
    let rows: Vec<Row> = vec![
        ("a", "2025-03-10", Some("1.00"), Some("1")),
        ("a", "2025-03-11", Some("2.00"), Some("2")),
        ("a", "2025-03-12", Some("6.00"), Some("6")),
        ("a", "2025-03-13", None, None),
        ("b", "2025-03-14", Some("-1.00"), Some("-1")),
        ("b", "2025-03-15", Some("-2.00"), Some("-2")),
    ];
    let (database, migration_task, app) = fixture(
        &["category"],
        json!([
            {"id":"records","type":"count"},
            {"id":"amount-sum","type":"sum","field":"amount"},
            {"id":"quantity-sum","type":"sum","field":"quantity"},
            {"id":"amount-mean","type":"mean","field":"amount","scale":2},
            {"id":"quantity-mean","type":"mean","field":"quantity","scale":0}
        ]),
        &rows,
    )
    .await;

    let response = live(&app, "2025-03", "2025-03", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let document = body_json(response).await;

    // Hand-computed per category. A null amount or quantity is left out of both
    // the sum and the number of values the mean divides by.
    let expected: [(&str, [(&str, Value, &str); 5]); 4] = [
        (
            "a",
            [
                ("records", json!(4), "exact"),
                ("amount-sum", json!("9.00"), "exact"),
                ("quantity-sum", json!("9"), "exact"),
                ("amount-mean", json!("3.00"), "exact"),
                ("quantity-mean", json!("3"), "exact"),
            ],
        ),
        (
            "b",
            [
                ("records", json!(2), "exact"),
                ("amount-sum", json!("-3.00"), "exact"),
                ("quantity-sum", json!("-3"), "exact"),
                ("amount-mean", json!("-1.50"), "exact"),
                // -1.5 rounds away from zero to -2.
                ("quantity-mean", json!("-2"), "exact"),
            ],
        ),
        (
            // No records: counts are zero, sums are zero at scale, means do not apply.
            "c",
            [
                ("records", json!(0), "exact"),
                ("amount-sum", json!("0.00"), "exact"),
                ("quantity-sum", json!("0"), "exact"),
                ("amount-mean", Value::Null, "not-applicable"),
                ("quantity-mean", Value::Null, "not-applicable"),
            ],
        ),
        (
            // The grand total: 5 values summing to 6.00, so the mean is 1.20. The
            // mean of the category means is (3.00 + -1.50) / 2 = 0.75, which is
            // not what the total reports. At scale 0 the quantity mean 1.2 is 1.
            "_T",
            [
                ("records", json!(6), "exact"),
                ("amount-sum", json!("6.00"), "exact"),
                ("quantity-sum", json!("6"), "exact"),
                ("amount-mean", json!("1.20"), "exact"),
                ("quantity-mean", json!("1"), "exact"),
            ],
        ),
    ];
    for (category, measures) in expected {
        for (measure, value, status) in measures {
            assert_eq!(
                cell(&document, "2025-03", Some(category), measure),
                json!([value, status]),
                "{category} {measure}"
            );
        }
    }

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sum_and_mean_are_served_as_decimal_strings_in_json_and_csv() {
    let rows: Vec<Row> = vec![
        ("a", "2025-03-10", Some("1.00"), Some("1")),
        ("a", "2025-03-11", Some("2.50"), Some("2")),
        ("b", "2025-03-12", Some("-4.00"), None),
    ];
    let (database, migration_task, app) = fixture(
        &["category"],
        json!([
            {"id":"records","type":"count"},
            {"id":"amount-sum","type":"sum","field":"amount"},
            {"id":"quantity-mean","type":"mean","field":"quantity","scale":1}
        ]),
        &rows,
    )
    .await;

    let response = live(&app, "2025-03", "2025-03", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let document = body_json(response).await;
    assert_eq!(
        document["dataset"]["measures"],
        json!([
            {"id":"records","type":"count"},
            {"id":"amount-sum","type":"sum","field":"amount","scale":2},
            {"id":"quantity-mean","type":"mean","field":"quantity","scale":1}
        ])
    );
    let a_count = &document["cells"]
        .as_array()
        .unwrap()
        .iter()
        .find(|cell| cell["dimensions"]["category"] == "a" && cell["measure"] == "records")
        .unwrap()["value"];
    assert!(a_count.is_u64(), "a count is a JSON integer: {a_count}");
    assert_eq!(
        cell(&document, "2025-03", Some("a"), "amount-sum"),
        json!(["3.50", "exact"])
    );
    assert!(document["cells"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|cell| cell["measure"] != "records" && cell["value"] != Value::Null)
        .all(|cell| cell["value"].is_string()));
    // Category b has no quantity: the mean does not apply, nothing is withheld.
    assert_eq!(
        cell(&document, "2025-03", Some("b"), "quantity-mean"),
        json!([Value::Null, "not-applicable"])
    );

    let response = live(&app, "2025-03", "2025-03", Some("text/csv")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        "text/csv; charset=utf-8"
    );
    let csv = String::from_utf8(body_bytes(response).await).expect("CSV is UTF-8");
    let lines = csv.lines().collect::<Vec<_>>();
    assert_eq!(
        lines[0],
        "period,periodStart,periodEnd,category,measure,value,status"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.ends_with(",a,amount-sum,3.50,exact")),
        "{csv}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.ends_with(",b,amount-sum,-4.00,exact")),
        "{csv}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.ends_with(",b,quantity-mean,,not-applicable")),
        "{csv}"
    );

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dataset_without_dimensions_rounds_half_away_from_zero_and_stays_exact_in_int64() {
    let mut rows: Vec<Row> = vec![
        // January: quantities 1 and 2; mean 1.5.
        ("a", "2025-01-10", None, Some("1")),
        ("a", "2025-01-11", None, Some("2")),
        // February: quantities -1 and -2; mean -1.5.
        ("a", "2025-02-10", None, Some("-1")),
        ("a", "2025-02-11", None, Some("-2")),
        // March: amounts 1.00, 1.00, 0.00; sum 2.00 over 3 values, mean 0.6667.
        ("a", "2025-03-10", Some("1.00"), None),
        ("a", "2025-03-11", Some("1.00"), None),
        ("a", "2025-03-12", Some("0.00"), None),
        // July: three records at the top of the int64 range; the sum exceeds 2^63.
        ("a", "2025-07-10", None, Some("9223372036854775807")),
        ("a", "2025-07-11", None, Some("9223372036854775807")),
        ("a", "2025-07-12", None, Some("9223372036854775807")),
    ];
    // April: amount sum 1.00 over 8 values, mean 0.125.
    rows.push(("a", "2025-04-10", Some("1.00"), None));
    for day in 11..=17 {
        rows.push(("a", april(day), Some("0.00"), None));
    }
    // May: amount sum -1.00 over 8 values, mean -0.125.
    rows.push(("a", "2025-05-10", Some("-1.00"), None));
    for day in 11..=17 {
        rows.push(("a", may(day), Some("0.00"), None));
    }
    let (database, migration_task, app) = fixture(
        &[],
        json!([
            {"id":"records","type":"count"},
            {"id":"quantity-sum","type":"sum","field":"quantity"},
            {"id":"amount-sum","type":"sum","field":"amount"},
            {"id":"quantity-mean","type":"mean","field":"quantity","scale":0},
            {"id":"quantity-mean-2","type":"mean","field":"quantity","scale":2},
            {"id":"amount-mean","type":"mean","field":"amount","scale":2}
        ]),
        &rows,
    )
    .await;

    let response = live(&app, "2025-01", "2025-07", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let document = body_json(response).await;
    let na = || json!([Value::Null, "not-applicable"]);
    let exact = |value: &str| json!([value, "exact"]);
    // Period, then records, quantity-sum, amount-sum, quantity-mean,
    // quantity-mean-2, amount-mean.
    let expected: Vec<(&str, Value, [Value; 5])> = vec![
        (
            "2025-01",
            json!([2, "exact"]),
            [exact("3"), exact("0.00"), exact("2"), exact("1.50"), na()],
        ),
        (
            "2025-02",
            json!([2, "exact"]),
            [
                exact("-3"),
                exact("0.00"),
                exact("-2"),
                exact("-1.50"),
                na(),
            ],
        ),
        (
            // The 3 amounts have no quantity: that mean does not apply, and the
            // sum of 2.00 over 3 values is 0.67.
            "2025-03",
            json!([3, "exact"]),
            [exact("0"), exact("2.00"), na(), na(), exact("0.67")],
        ),
        (
            "2025-04",
            json!([8, "exact"]),
            [exact("0"), exact("1.00"), na(), na(), exact("0.13")],
        ),
        (
            "2025-05",
            json!([8, "exact"]),
            [exact("0"), exact("-1.00"), na(), na(), exact("-0.13")],
        ),
        (
            // No records at all in June.
            "2025-06",
            json!([0, "exact"]),
            [exact("0"), exact("0.00"), na(), na(), na()],
        ),
        (
            "2025-07",
            json!([3, "exact"]),
            [
                exact("27670116110564327421"),
                exact("0.00"),
                exact("9223372036854775807"),
                exact("9223372036854775807.00"),
                na(),
            ],
        ),
    ];
    let names = [
        "quantity-sum",
        "amount-sum",
        "quantity-mean",
        "quantity-mean-2",
        "amount-mean",
    ];
    for (period, records, values) in expected {
        assert_eq!(
            cell(&document, period, None, "records"),
            records,
            "{period}"
        );
        for (name, value) in names.iter().zip(values) {
            assert_eq!(
                cell(&document, period, None, name),
                value,
                "{period} {name}"
            );
        }
    }

    migration_task.abort();
    database.cleanup().await;
}

#[test]
fn a_profile_that_cannot_read_the_measure_field_is_refused_at_compile_time() {
    let mut source = registry_source(
        &["category"],
        json!([{"id":"amount-sum","type":"sum","field":"amount"}]),
    );
    source["accessProfiles"][0]["permissions"]["records"][0]["readableFields"] =
        json!(["subject", "active", "category", "event-date", "quantity"]);
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).expect("parses");
    let failure = compile_project(&project, &[], CompileProfile::Authoring)
        .expect_err("the analyst cannot read amount");
    assert!(
        failure.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == "breg.statistical-dataset.measure-field-not-readable"
                && diagnostic.message.contains("amount")
                && diagnostic.message.contains("analyst")
        }),
        "{:?}",
        failure.diagnostics()
    );
}

fn april(day: u32) -> &'static str {
    [
        "2025-04-11",
        "2025-04-12",
        "2025-04-13",
        "2025-04-14",
        "2025-04-15",
        "2025-04-16",
        "2025-04-17",
    ][(day - 11) as usize]
}

fn may(day: u32) -> &'static str {
    [
        "2025-05-11",
        "2025-05-12",
        "2025-05-13",
        "2025-05-14",
        "2025-05-15",
        "2025-05-16",
        "2025-05-17",
    ][(day - 11) as usize]
}

/// The document cell of one period, dimension code and measure as `[value, status]`.
fn cell(document: &Value, period: &str, category: Option<&str>, measure: &str) -> Value {
    let found = document["cells"]
        .as_array()
        .expect("cells are an array")
        .iter()
        .find(|cell| {
            cell["period"] == period
                && cell["measure"] == measure
                && match category {
                    Some(code) => cell["dimensions"]["category"] == code,
                    None => cell["dimensions"] == json!({}),
                }
        })
        .unwrap_or_else(|| panic!("no cell for {period} {category:?} {measure}: {document}"));
    json!([found["value"], found["status"]])
}

fn registry_source(dimensions: &[&str], measures: Value) -> Value {
    json!({"datasets":[{"id": "statistics-measures"}],
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
        "kind":"BRegProject",
        "project":{"id":PACKAGE_ID,"version":"1","defaultLanguage":"en","canonicalBaseIri":"https://statistics.example.test","timezone":"UTC"},
        "recordTypes":[{
            "id":"record","primaryDataset":"statistics-measures","route":"records","mutationMode":"mutable",
            "accessLog":{"subjectField":"subject"},
            "fields":[
                {"id":"subject","type":"string","maximumLength":128,"required":true,"classification":"internal"},
                {"id":"active","type":"boolean","required":true,"classification":"internal"},
                {"id":"category","type":"vocabulary-code","vocabulary":"category","required":true,"classification":"internal"},
                {"id":"event-date","type":"date","required":true,"classification":"internal"},
                {"id":"amount","type":"decimal","precision":10,"scale":2,"classification":"internal"},
                {"id":"quantity","type":"int64","classification":"internal"}
            ]
        }],
        "accessProfiles":[
            {"id":"analyst","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
                "recordType":"record","operations":["list"],
                "readableFields":["subject","active","category","event-date","amount","quantity"],
                "filterableFields":["subject","active","category","event-date"],"allowCount":true,
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
            "dimensions":dimensions,"measures":measures,
            "disclosure":{"minimumCount":5,"roundingBase":5}
        }]
    })
}

async fn fixture(
    dimensions: &[&str],
    measures: Value,
    rows: &[Row],
) -> (TestDatabase, tokio::task::JoinHandle<()>, axum::Router) {
    let source = registry_source(dimensions, measures);
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).expect("parses");
    let compiled =
        Arc::new(compile_project(&project, &[], CompileProfile::Authoring).expect("compiles"));
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
            label: "package-statistics-measures-1",
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

async fn live(app: &axum::Router, from: &str, to: &str, accept: Option<&str>) -> Response<Body> {
    let mut builder = Request::builder().method("GET").uri(format!(
        "/v1/statistics/records-by-category:live?accessProfile=analyst&from={from}&to={to}"
    ));
    if let Some(accept) = accept {
        builder = builder.header("accept", accept);
    }
    let mut request = builder.body(Body::empty()).expect("request builds");
    request.extensions_mut().insert(
        VerifiedRequestClaims::authenticated(
            "principal",
            "measures-analyst",
            Default::default(),
            None,
            Default::default(),
        )
        .expect("claims are valid"),
    );
    app.clone()
        .call(request)
        .await
        .expect("router returns a response")
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
