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
async fn a_mean_over_a_decimal_whose_precision_equals_its_scale_keeps_its_leading_zero() {
    let rows: Vec<Row> = vec![("a", "2025-03-10", Some("-0.50"), Some("1"))];
    let mut source = registry_source(
        &["category"],
        json!([
            {"id":"records","type":"count"},
            {"id":"amount-mean","type":"mean","field":"amount","scale":2},
            {"id":"amount-median","type":"percentile","field":"amount","percentile":50,"scale":2}
        ]),
    );
    source["recordTypes"][0]["fields"][4] = json!(
        {"id":"amount","type":"decimal","precision":2,"scale":2,"classification":"internal"}
    );
    let (database, migration_task, app) = fixture_for(source, &rows).await;

    let response = live(&app, "2025-03", "2025-03", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let document = body_json(response).await;
    for measure in ["amount-mean", "amount-median"] {
        assert_eq!(
            cell(&document, "2025-03", Some("a"), measure),
            json!(["-0.50", "exact"]),
            "{measure}"
        );
    }

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

/// A register of public facts: every record type and field is public, the
/// analyst reads it live, the publisher publishes it, and the reader reads releases.
fn public_register_source(measures: Value) -> Value {
    let mut source = registry_source(&["category"], measures);
    source["recordTypes"][0]["classification"] = json!("public");
    for field in source["recordTypes"][0]["fields"].as_array_mut().unwrap() {
        field["classification"] = json!("public");
    }
    let publisher = json!({
        "id":"publisher","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
            "recordType":"record","operations":["list"],
            "readableFields":["subject","active","category","event-date","amount","quantity"],
            "filterableFields":["subject","active","category","event-date"],"allowCount":true,
            "rowBoundaries":"unrestricted"
        }],"datasets":[{"dataset":"records-by-category","operations":["publish","read-releases"]}]}
    });
    let reader = json!({
        "id":"reader","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{
            "datasets":[{"dataset":"records-by-category","operations":["read-releases"]}]
        }
    });
    source["accessProfiles"][0]["permissions"]["datasets"][0]["operations"] =
        json!(["read-live", "read-releases"]);
    source["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .extend([publisher, reader]);
    source["statisticalDatasets"][0]["disclosure"] = json!({"type":"exact-public-values"});
    source
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_public_register_publishes_exact_counts_sums_and_means() {
    let rows: Vec<Row> = vec![
        ("a", "2025-03-10", Some("2.50"), Some("5")),
        ("b", "2025-03-11", Some("1.00"), Some("1")),
        ("b", "2025-03-12", Some("2.00"), Some("2")),
    ];
    let (database, migration_task, app) = fixture_for(
        public_register_source(json!([
            {"id":"records","type":"count"},
            {"id":"amount-sum","type":"sum","field":"amount"},
            {"id":"amount-mean","type":"mean","field":"amount","scale":2}
        ])),
        &rows,
    )
    .await;

    let publisher = release_claims("publisher");
    let published = release_request(
        &app,
        "POST",
        "/v1/statistics/records-by-category/releases/2025-03/versions?accessProfile=publisher",
        publisher,
        Some("exact-release"),
    )
    .await;
    assert_eq!(
        published.status(),
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&body_bytes(published).await)
    );

    let read = release_request(
        &app,
        "GET",
        "/v1/statistics/records-by-category/releases/2025-03/versions/1?accessProfile=reader",
        release_claims("reader"),
        None,
    )
    .await;
    assert_eq!(read.status(), StatusCode::OK);
    let document = body_json(read).await;
    assert_eq!(
        document["disclosure"],
        json!({"method":"exact-public-values"})
    );

    // One record is stated exactly, never suppressed.
    let expected: [(&str, [(&str, Value, &str); 3]); 3] = [
        (
            "a",
            [
                ("records", json!(1), "exact"),
                ("amount-sum", json!("2.50"), "exact"),
                ("amount-mean", json!("2.50"), "exact"),
            ],
        ),
        (
            "b",
            [
                ("records", json!(2), "exact"),
                ("amount-sum", json!("3.00"), "exact"),
                ("amount-mean", json!("1.50"), "exact"),
            ],
        ),
        (
            "c",
            [
                ("records", json!(0), "exact"),
                ("amount-sum", json!("0.00"), "exact"),
                ("amount-mean", Value::Null, "not-applicable"),
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
    assert_eq!(
        cell(&document, "2025-03", Some("_T"), "records"),
        json!([3, "exact"])
    );
    assert_eq!(
        cell(&document, "2025-03", Some("_T"), "amount-sum"),
        json!(["5.50", "exact"])
    );
    assert_eq!(
        cell(&document, "2025-03", Some("_T"), "amount-mean"),
        json!(["1.83", "exact"])
    );

    let stored: Vec<u8> = database
        .admin
        .query_one(
            "SELECT c.document FROM registry_internal.registry_statistical_release_contents c WHERE c.dataset_id = 'records-by-category' AND c.period_code = '2025-03' AND c.release_version = 1",
            &[],
        )
        .await
        .expect("the published release is stored")
        .get(0);
    let stored_text = std::str::from_utf8(&stored).expect("stored release is UTF-8");
    for withheld in ["suppressed", "rounded", "minimumCount"] {
        assert!(!stored_text.contains(withheld), "{withheld}");
    }

    migration_task.abort();
    database.cleanup().await;
}

fn release_claims(profile: &str) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "principal",
        &format!("measures-{profile}"),
        Default::default(),
        None,
        Default::default(),
    )
    .expect("claims are valid")
}

async fn release_request(
    app: &axum::Router,
    method: &str,
    uri: &str,
    claims: VerifiedRequestClaims,
    idempotency_key: Option<&str>,
) -> Response<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    let body = match idempotency_key {
        Some(key) => {
            builder = builder
                .header("content-type", "application/json")
                .header("idempotency-key", key);
            Body::from(serde_json::to_vec(&json!({"status":"final"})).expect("body serializes"))
        }
        None => Body::empty(),
    };
    let mut request = builder.body(body).expect("request builds");
    request.extensions_mut().insert(claims);
    app.clone()
        .call(request)
        .await
        .expect("router returns a response")
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
            "disclosure":{"type":"minimum-count-and-rounding","minimumCount":5,"roundingBase":5}
        }]
    })
}

async fn fixture(
    dimensions: &[&str],
    measures: Value,
    rows: &[Row],
) -> (TestDatabase, tokio::task::JoinHandle<()>, axum::Router) {
    fixture_for(registry_source(dimensions, measures), rows).await
}

async fn fixture_for(
    source: Value,
    rows: &[Row],
) -> (TestDatabase, tokio::task::JoinHandle<()>, axum::Router) {
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

/// A parcel: category code, event date, owner (an index into the owner list, or
/// `None` for a parcel with no owner), amount and quantity.
type Parcel = (
    &'static str,
    &'static str,
    Option<usize>,
    Option<&'static str>,
    Option<&'static str>,
);

/// `registry_source` over parcels that reference an owner. The analyst reads
/// live, a statistician reads exact values, a publisher publishes with rounding
/// and a reader reads the releases.
fn parcel_source(dimensions: &[&str], measures: Value) -> Value {
    let mut source = registry_source(dimensions, measures);
    source["recordTypes"].as_array_mut().unwrap().push(json!({
        "id":"owner","primaryDataset":"statistics-measures","route":"owners","mutationMode":"mutable",
        "fields":[{"id":"name","type":"string","maximumLength":80,"classification":"internal"}]
    }));
    source["recordTypes"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(
            json!({"id":"owner","type":"reference","target":"owner","classification":"internal"}),
        );
    let readable = json!([
        "subject",
        "active",
        "category",
        "event-date",
        "amount",
        "quantity",
        "owner"
    ]);
    source["accessProfiles"][0]["permissions"]["records"][0]["readableFields"] = readable.clone();
    source["accessProfiles"].as_array_mut().unwrap().push(
        json!({"id":"statistician","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{
            "datasets":[{"dataset":"records-by-category","operations":["read-exact"]}]}}),
    );
    source["statisticalDatasets"][0]["exactReads"] = json!({"accessProfile":"analyst"});
    source
}

/// `parcel_source` with a publisher and a reader of releases; its measures are
/// counts and distinct counts only.
fn released_parcel_source(dimensions: &[&str], measures: Value) -> Value {
    let mut source = parcel_source(dimensions, measures);
    let readable =
        source["accessProfiles"][0]["permissions"]["records"][0]["readableFields"].clone();
    source["accessProfiles"][0]["permissions"]["datasets"][0]["operations"] =
        json!(["read-live", "read-releases"]);
    source["accessProfiles"].as_array_mut().unwrap().extend([
        json!({"id":"publisher","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
            "recordType":"record","operations":["list"],"readableFields":readable,
            "filterableFields":["subject","active","category","event-date"],"allowCount":true,
            "rowBoundaries":"unrestricted"
        }],"datasets":[{"dataset":"records-by-category","operations":["publish","read-releases"]}]}}),
        json!({"id":"reader","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{
            "datasets":[{"dataset":"records-by-category","operations":["read-releases"]}]}}),
    ]);
    source
}

/// The fixture over `parcel_source`, with the owners and parcels inserted
/// through the administrative connection.
async fn parcel_fixture(
    source: Value,
    owner_count: usize,
    parcels: &[Parcel],
) -> (TestDatabase, tokio::task::JoinHandle<()>, axum::Router) {
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).expect("parses");
    let compiled = compile_project(&project, &[], CompileProfile::Authoring).expect("compiles");
    let (database, task, app) = fixture_for(source, &[]).await;
    let owner = &compiled.entities()["owner"];
    let record = &compiled.entities()["record"];
    let column = |field: &str| quote_identifier(&record.fields[field].physical_name);
    let owners_table = quote_identifier(&owner.physical_table);
    let table = quote_identifier(&record.physical_table);
    let activation: String = database
        .admin
        .query_one(
            "SELECT active_activation_id::text FROM registry_internal.registry_state WHERE singleton",
            &[],
        )
        .await
        .expect("the active activation is recorded")
        .get(0);
    let owner_id = |index: usize| format!("00000000-0000-4000-8000-{:012}", index + 1);
    for index in 0..owner_count {
        database
            .admin
            .execute(
                &format!(
                    "INSERT INTO registry_data.{owners_table} (record_id, record_revision, record_lifecycle, active_package_revision)
                     VALUES ($1::text::uuid, 1, 'active', $2)"
                ),
                &[&owner_id(index), &activation],
            )
            .await
            .expect("owner inserts");
    }
    let sql = format!(
        "INSERT INTO registry_data.{table}
             (record_id, record_revision, record_lifecycle, active_package_revision,
              {subject}, {active}, {category}, {event_date}, {amount}, {quantity}, {owner})
         VALUES ($1::text::uuid, 1, 'active', $7, $1, true, $2, $3, $4::text::numeric,
                 $5::text::bigint, $6::text::uuid)",
        subject = column("subject"),
        active = column("active"),
        category = column("category"),
        event_date = column("event-date"),
        amount = column("amount"),
        quantity = column("quantity"),
        owner = column("owner"),
    );
    for (index, (code, date, owner, amount, quantity)) in parcels.iter().enumerate() {
        let id = format!("00000000-0000-4000-9000-{:012}", index + 1);
        let date = NaiveDate::parse_from_str(date, "%Y-%m-%d").expect("seed date parses");
        let owner = owner.map(owner_id);
        database
            .admin
            .execute(
                &sql,
                &[&id, code, &date, amount, quantity, &owner, &activation],
            )
            .await
            .expect("parcel inserts");
    }
    (database, task, app)
}

fn distinct_measures() -> Value {
    json!([
        {"id":"parcels","type":"count"},
        {"id":"owners","type":"distinct-count","field":"owner"}
    ])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_distinct_count_total_is_computed_over_the_records_not_added_from_the_cells() {
    // Owner 0 holds parcels in both categories, so the national total of distinct
    // owners (3) is below the sum of the category values (2 + 2). A parcel with
    // no owner counts as a parcel and as no owner.
    let parcels: Vec<Parcel> = vec![
        ("a", "2025-03-10", Some(0), None, None),
        ("a", "2025-03-11", Some(0), None, None),
        ("a", "2025-03-12", Some(1), None, None),
        ("a", "2025-03-13", None, None, None),
        ("b", "2025-03-14", Some(0), None, None),
        ("b", "2025-03-15", Some(2), None, None),
    ];
    let (database, task, app) = parcel_fixture(
        parcel_source(&["category"], distinct_measures()),
        3,
        &parcels,
    )
    .await;
    let document = body_json(live(&app, "2025-03", "2025-03", None).await).await;
    for (category, parcels, owners) in [("a", 4, 2), ("b", 2, 2), ("c", 0, 0), ("_T", 6, 3)] {
        assert_eq!(
            cell(&document, "2025-03", Some(category), "parcels"),
            json!([parcels, "exact"]),
            "{category} parcels"
        );
        assert_eq!(
            cell(&document, "2025-03", Some(category), "owners"),
            json!([owners, "exact"]),
            "{category} owners"
        );
    }
    task.abort();
    database.cleanup().await;

    // Without dimensions the one cell is the total.
    let (database, task, app) =
        parcel_fixture(parcel_source(&[], distinct_measures()), 3, &parcels).await;
    let document = body_json(live(&app, "2025-03", "2025-03", None).await).await;
    assert_eq!(
        cell(&document, "2025-03", None, "owners"),
        json!([3, "exact"])
    );
    assert_eq!(
        cell(&document, "2025-03", None, "parcels"),
        json!([6, "exact"])
    );
    task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dataset_with_a_distinct_count_reports_the_same_sums_and_means_as_without_one() {
    let parcels: Vec<Parcel> = vec![
        ("a", "2025-03-10", Some(0), Some("1.00"), Some("1")),
        ("a", "2025-03-11", Some(1), Some("2.50"), Some("2")),
        ("a", "2025-03-12", Some(1), None, None),
        ("b", "2025-03-13", Some(0), Some("-1.25"), Some("-3")),
        ("b", "2025-03-14", None, Some("6.00"), Some("6")),
    ];
    let shared = [
        json!({"id":"parcels","type":"count"}),
        json!({"id":"amount-sum","type":"sum","field":"amount"}),
        json!({"id":"quantity-sum","type":"sum","field":"quantity"}),
        json!({"id":"amount-mean","type":"mean","field":"amount","scale":2}),
        json!({"id":"quantity-mean","type":"mean","field":"quantity","scale":0}),
    ];
    let mut with = shared.to_vec();
    with.push(json!({"id":"owners","type":"distinct-count","field":"owner"}));
    let mut documents = Vec::new();
    for measures in [shared.to_vec(), with] {
        let (database, task, app) =
            parcel_fixture(parcel_source(&["category"], json!(measures)), 2, &parcels).await;
        documents.push(body_json(live(&app, "2025-03", "2025-03", None).await).await);
        task.abort();
        database.cleanup().await;
    }
    let without_distinct: Vec<&Value> = documents[1]["cells"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|cell| cell["measure"] != "owners")
        .collect();
    let baseline: Vec<&Value> = documents[0]["cells"].as_array().unwrap().iter().collect();
    assert!(!baseline.is_empty());
    assert_eq!(baseline, without_distinct);
    assert_eq!(
        cell(&documents[1], "2025-03", Some("_T"), "owners"),
        json!([2, "exact"])
    );
}

/// Eighteen parcels in March: twelve in `a` by eight owners (four hold two
/// parcels), six in `b` by two of those owners.
fn release_parcels() -> Vec<Parcel> {
    const DAYS: [&str; 18] = [
        "2025-03-01",
        "2025-03-02",
        "2025-03-03",
        "2025-03-04",
        "2025-03-05",
        "2025-03-06",
        "2025-03-07",
        "2025-03-08",
        "2025-03-09",
        "2025-03-10",
        "2025-03-11",
        "2025-03-12",
        "2025-03-13",
        "2025-03-14",
        "2025-03-15",
        "2025-03-16",
        "2025-03-17",
        "2025-03-18",
    ];
    let a_owners = [0, 0, 1, 1, 2, 2, 3, 3, 4, 5, 6, 7];
    let b_owners = [0, 0, 0, 1, 1, 1];
    a_owners
        .iter()
        .map(|owner| ("a", *owner))
        .chain(b_owners.iter().map(|owner| ("b", *owner)))
        .zip(DAYS)
        .map(|((category, owner), day)| (category, day, Some(owner), None, None))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_distinct_count_is_read_live_exact_and_released_with_rounding_on_its_own_value() {
    let (database, task, app) = parcel_fixture(
        released_parcel_source(&["category"], distinct_measures()),
        8,
        &release_parcels(),
    )
    .await;

    // Live: exact values.
    let live_document = body_json(live(&app, "2025-03", "2025-03", None).await).await;
    for (category, parcels, owners) in [("a", 12, 8), ("b", 6, 2), ("c", 0, 0), ("_T", 18, 8)] {
        assert_eq!(
            cell(&live_document, "2025-03", Some(category), "parcels"),
            json!([parcels, "exact"])
        );
        assert_eq!(
            cell(&live_document, "2025-03", Some(category), "owners"),
            json!([owners, "exact"])
        );
    }

    // Exact: the profile without record access reads the same cells.
    let mut request = Request::builder()
        .method("GET")
        .uri("/v1/statistics/records-by-category:exact?accessProfile=statistician&from=2025-03&to=2025-03")
        .body(Body::empty())
        .expect("request builds");
    request
        .extensions_mut()
        .insert(release_claims("statistician"));
    let exact = app.clone().call(request).await.expect("router responds");
    assert_eq!(exact.status(), StatusCode::OK);
    assert_eq!(body_json(exact).await["cells"], live_document["cells"]);

    // Release: counts and distinct counts are suppressed and rounded each on
    // its own value.
    let published = release_request(
        &app,
        "POST",
        "/v1/statistics/records-by-category/releases/2025-03/versions?accessProfile=publisher",
        release_claims("publisher"),
        Some("distinct-release"),
    )
    .await;
    assert_eq!(
        published.status(),
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&body_bytes(published).await)
    );
    let read = release_request(
        &app,
        "GET",
        "/v1/statistics/records-by-category/releases/2025-03/versions/1?accessProfile=reader",
        release_claims("reader"),
        None,
    )
    .await;
    assert_eq!(read.status(), StatusCode::OK);
    let document = body_json(read).await;
    for (category, measure, expected) in [
        // 12 parcels round to 10; 8 owners round to 10.
        ("a", "parcels", json!([10, "rounded"])),
        ("a", "owners", json!([10, "rounded"])),
        // 6 parcels round to 5; 2 owners are below the minimum.
        ("b", "parcels", json!([5, "rounded"])),
        ("b", "owners", json!([Value::Null, "suppressed"])),
        ("c", "owners", json!([0, "exact"])),
        // 18 parcels round to 20; 8 distinct owners round to 10, not to 20.
        ("_T", "parcels", json!([20, "rounded"])),
        ("_T", "owners", json!([10, "rounded"])),
    ] {
        assert_eq!(
            cell(&document, "2025-03", Some(category), measure),
            expected,
            "{category} {measure}"
        );
    }
    task.abort();
    database.cleanup().await;
}

/// `registry_source` over the categories `codes`.
fn source_with_categories(dimensions: &[&str], measures: Value, codes: &[&str]) -> Value {
    let mut source = registry_source(dimensions, measures);
    source["vocabularies"][0]["values"] = json!(codes);
    source
}

fn ratio_measures() -> Value {
    json!([
        {"id":"records","type":"count"},
        {"id":"amount-sum","type":"sum","field":"amount"},
        {"id":"quantity-sum","type":"sum","field":"quantity"},
        {"id":"amount-per-record","type":"ratio","numerator":"amount-sum","denominator":"records","scale":3},
        {"id":"quantity-per-amount","type":"ratio","numerator":"quantity-sum","denominator":"amount-sum","scale":2},
        {"id":"amount-per-quantity","type":"ratio","numerator":"amount-sum","denominator":"quantity-sum","scale":2},
        {"id":"quantity-per-record","type":"ratio","numerator":"quantity-sum","denominator":"records","scale":0}
    ])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ratio_rounds_half_away_from_zero_for_every_sign_and_a_total_is_the_ratio_of_the_totals()
{
    let rows: Vec<Row> = vec![
        ("a", "2025-03-10", Some("1.00"), Some("1")),
        ("a", "2025-03-11", Some("2.00"), Some("2")),
        ("a", "2025-03-12", Some("3.00"), Some("3")),
        ("a", "2025-03-13", Some("4.00"), None),
        ("b", "2025-03-14", Some("-1.00"), Some("-1")),
        ("b", "2025-03-15", Some("-2.00"), Some("-2")),
        ("c", "2025-03-16", Some("4.00"), Some("-6")),
    ];
    let source = source_with_categories(&["category"], ratio_measures(), &["a", "b", "c", "d"]);
    let (database, migration_task, app) = fixture_for(source, &rows).await;
    let document = body_json(live(&app, "2025-03", "2025-03", None).await).await;

    let not_applicable = (Value::Null, "not-applicable");
    // Per category: amount-per-record, quantity-per-amount, amount-per-quantity,
    // quantity-per-record.
    let expected: [(&str, [(Value, &str); 4]); 5] = [
        (
            // 10.00 / 4; 6 / 10.00; 10.00 / 6 = 1.666..; 6 / 4 = 1.5 rounds up.
            "a",
            [
                (json!("2.500"), "exact"),
                (json!("0.60"), "exact"),
                (json!("1.67"), "exact"),
                (json!("2"), "exact"),
            ],
        ),
        (
            // -3.00 / 2; -3 / -3.00; -3.00 / -3; -3 / 2 = -1.5 rounds to -2.
            "b",
            [
                (json!("-1.500"), "exact"),
                (json!("1.00"), "exact"),
                (json!("1.00"), "exact"),
                (json!("-2"), "exact"),
            ],
        ),
        (
            // 4.00 / 1; -6 / 4.00; 4.00 / -6 = -0.666..; -6 / 1.
            "c",
            [
                (json!("4.000"), "exact"),
                (json!("-1.50"), "exact"),
                (json!("-0.67"), "exact"),
                (json!("-6"), "exact"),
            ],
        ),
        // No records: every denominator is zero.
        (
            "d",
            [
                not_applicable.clone(),
                not_applicable.clone(),
                not_applicable.clone(),
                not_applicable,
            ],
        ),
        (
            // Totals: 7 records, amount 11.00, quantity -3. The ratio of the
            // totals is 11.00 / 7 = 1.571.., which is not the mean of the
            // category ratios; -3 / 11.00 = -0.2727..; 11.00 / -3 = -3.666..;
            // -3 / 7 = -0.43 rounds to zero.
            "_T",
            [
                (json!("1.571"), "exact"),
                (json!("-0.27"), "exact"),
                (json!("-3.67"), "exact"),
                (json!("0"), "exact"),
            ],
        ),
    ];
    let measures = [
        "amount-per-record",
        "quantity-per-amount",
        "amount-per-quantity",
        "quantity-per-record",
    ];
    for (category, values) in expected {
        for (measure, (value, status)) in measures.iter().zip(values) {
            assert_eq!(
                cell(&document, "2025-03", Some(category), measure),
                json!([value, status]),
                "{category} {measure}"
            );
        }
    }
    migration_task.abort();
    database.cleanup().await;

    // Without dimensions the one cell is the total, from the base-cell path.
    let rows: Vec<Row> = vec![
        ("a", "2025-03-10", Some("1.00"), Some("1")),
        ("a", "2025-03-11", Some("2.00"), Some("2")),
    ];
    let (database, migration_task, app) = fixture(&[], ratio_measures(), &rows).await;
    let document = body_json(live(&app, "2025-03", "2025-03", None).await).await;
    for (measure, value) in [
        ("amount-per-record", "1.500"),
        ("quantity-per-amount", "1.00"),
        ("amount-per-quantity", "1.00"),
        ("quantity-per-record", "2"),
    ] {
        assert_eq!(
            cell(&document, "2025-03", None, measure),
            json!([value, "exact"]),
            "{measure}"
        );
    }
    // A period without records has a zero denominator.
    let document = body_json(live(&app, "2025-04", "2025-04", None).await).await;
    assert_eq!(
        cell(&document, "2025-04", None, "amount-per-record"),
        json!([Value::Null, "not-applicable"])
    );
    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ratio_over_a_distinct_count_divides_the_unrounded_values() {
    let parcels: Vec<Parcel> = vec![
        ("a", "2025-03-10", Some(0), None, None),
        ("a", "2025-03-11", Some(0), None, None),
        ("a", "2025-03-12", Some(1), None, None),
        ("b", "2025-03-14", Some(0), None, None),
        ("b", "2025-03-15", Some(2), None, None),
    ];
    let (database, task, app) = parcel_fixture(
        parcel_source(
            &["category"],
            json!([
                {"id":"parcels","type":"count"},
                {"id":"owners","type":"distinct-count","field":"owner"},
                {"id":"parcels-per-owner","type":"ratio","numerator":"parcels","denominator":"owners","scale":2}
            ]),
        ),
        3,
        &parcels,
    )
    .await;
    let document = body_json(live(&app, "2025-03", "2025-03", None).await).await;
    // a: 3 parcels over 2 owners; b: 2 over 2; the total is 5 over 3 distinct
    // owners, not over the 4 owners the categories add up to.
    for (category, value) in [
        ("a", json!(["1.50", "exact"])),
        ("b", json!(["1.00", "exact"])),
        ("c", json!([Value::Null, "not-applicable"])),
        ("_T", json!(["1.67", "exact"])),
    ] {
        assert_eq!(
            cell(&document, "2025-03", Some(category), "parcels-per-owner"),
            value,
            "{category}"
        );
    }
    task.abort();
    database.cleanup().await;
}

fn percentile_measures() -> Value {
    json!([
        {"id":"records","type":"count"},
        {"id":"median-amount","type":"percentile","field":"amount","percentile":50,"scale":2},
        {"id":"p10-amount","type":"percentile","field":"amount","percentile":10,"scale":2},
        {"id":"p25-amount","type":"percentile","field":"amount","percentile":25,"scale":2},
        {"id":"p90-amount","type":"percentile","field":"amount","percentile":90,"scale":2},
        {"id":"median-quantity","type":"percentile","field":"quantity","percentile":50,"scale":0},
        {"id":"median-quantity-2","type":"percentile","field":"quantity","percentile":50,"scale":2}
    ])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_percentile_is_the_averaged_inverse_distribution_over_the_records_of_each_cell() {
    let mut rows: Vec<Row> = Vec::new();
    // a: the amounts 1.00 to 10.00, one null amount (left out) and the
    // quantities 1, 2, 3.
    let ten = [
        "1.00", "2.00", "3.00", "4.00", "5.00", "6.00", "7.00", "8.00", "9.00", "10.00",
    ];
    for (index, amount) in ten.iter().enumerate() {
        let quantity = [Some("1"), Some("2"), Some("3")]
            .get(index)
            .copied()
            .flatten();
        rows.push(("a", "2025-03-10", Some(amount), quantity));
    }
    rows.push(("a", "2025-03-11", None, None));
    // b: the amounts 1.00 to 4.00 in any order, the quantities -1 and -2.
    for (amount, quantity) in [
        ("3.00", None),
        ("1.00", Some("-1")),
        ("4.00", None),
        ("2.00", Some("-2")),
    ] {
        rows.push(("b", "2025-03-12", Some(amount), quantity));
    }
    // c: three amounts.
    for amount in ["1.00", "2.00", "3.00"] {
        rows.push(("c", "2025-03-13", Some(amount), None));
    }
    let (database, migration_task, app) =
        fixture(&["category"], percentile_measures(), &rows).await;
    let document = body_json(live(&app, "2025-03", "2025-03", None).await).await;

    let expected: [(&str, [&str; 6]); 3] = [
        // 1..=10: the median is (5 + 6) / 2; p10 is (1 + 2) / 2, the n q = 1
        // case; p25 is x[3]; p90 is (9 + 10) / 2. The quantities 1, 2, 3 have
        // the median 2.
        ("a", ["5.50", "1.50", "3.00", "9.50", "2", "2.00"]),
        // 1, 2, 3, 4: the median is 2.5; p10 is x[1]; p25 is (1 + 2) / 2;
        // p90 is x[4]. The quantities -1, -2 have the median -1.5, which rounds
        // away from zero to -2 at scale 0.
        ("b", ["2.50", "1.00", "1.50", "4.00", "-2", "-1.50"]),
        // 1, 2, 3: the median is 2.
        ("c", ["2.00", "1.00", "1.00", "3.00", "", ""]),
    ];
    let measures = [
        "median-amount",
        "p10-amount",
        "p25-amount",
        "p90-amount",
        "median-quantity",
        "median-quantity-2",
    ];
    for (category, values) in expected {
        for (measure, value) in measures.iter().zip(values) {
            let want = if value.is_empty() {
                json!([Value::Null, "not-applicable"])
            } else {
                json!([value, "exact"])
            };
            assert_eq!(
                cell(&document, "2025-03", Some(category), measure),
                want,
                "{category} {measure}"
            );
        }
    }
    // The total is over all 17 amounts and 5 quantities, not over the
    // category percentiles: the median amount is x[9] and the median quantity
    // of -2, -1, 1, 2, 3 is 1.
    for (measure, value) in [
        ("median-amount", "3.00"),
        ("p10-amount", "1.00"),
        ("p25-amount", "2.00"),
        ("p90-amount", "9.00"),
        ("median-quantity", "1"),
        ("median-quantity-2", "1.00"),
    ] {
        assert_eq!(
            cell(&document, "2025-03", Some("_T"), measure),
            json!([value, "exact"]),
            "_T {measure}"
        );
    }
    migration_task.abort();
    database.cleanup().await;
}

/// Hyndman and Fan definition 2 over amounts in hundredths: with the n values
/// sorted, x[1..n], the value is x[ceil(n k / 100)], or the mean of x[j] and
/// x[j + 1] when n k / 100 is an integer j, rounded half away from zero. The
/// text has two fractional digits.
fn definition_two(values: &[i64], percentile: usize) -> String {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let product = sorted.len() * percentile;
    let hundredths = if product % 100 == 0 {
        let sum = sorted[product / 100 - 1] + sorted[product / 100];
        sum.signum() * ((sum.abs() + 1) / 2)
    } else {
        sorted[product.div_ceil(100) - 1]
    };
    let sign = if hundredths < 0 { "-" } else { "" };
    format!(
        "{sign}{}.{:02}",
        hundredths.abs() / 100,
        hundredths.abs() % 100
    )
}

/// The hundredths of a seeded amount: duplicates, negatives, and odd cents, so
/// that the average of two neighbours can fall on a half.
fn seeded_hundredths(category: usize, index: usize) -> i64 {
    (((index * 37 + category * 11) % 41) as i64 - 20) * 25 + ((index * 7 + category) % 5) as i64
}

fn hundredths_text(hundredths: i64) -> &'static str {
    let sign = if hundredths < 0 { "-" } else { "" };
    Box::leak(
        format!(
            "{sign}{}.{:02}",
            hundredths.abs() / 100,
            hundredths.abs() % 100
        )
        .into_boxed_str(),
    )
}

#[test]
fn the_reference_follows_the_definition_on_its_readable_cases() {
    assert_eq!(definition_two(&[100, 200, 300, 400], 50), "2.50");
    assert_eq!(definition_two(&[100, 200, 300], 50), "2.00");
    assert_eq!(
        definition_two(&(1..=10).map(|n| n * 100).collect::<Vec<_>>(), 10),
        "1.50"
    );
    assert_eq!(definition_two(&[-1, -2], 50), "-0.02");
    assert_eq!(definition_two(&[1, 2], 50), "0.02");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_percentile_matches_the_definition_for_every_cell_size_and_fraction() {
    const PERCENTILES: [usize; 11] = [1, 5, 10, 25, 33, 50, 67, 75, 90, 95, 99];
    let codes: Vec<String> = (1..=60).map(|n| format!("n{n:02}")).collect();
    let code_refs: Vec<&str> = codes.iter().map(String::as_str).collect();
    let mut measures = vec![json!({"id":"records","type":"count"})];
    for percentile in PERCENTILES {
        measures.push(json!({
            "id": format!("p{percentile}"), "type":"percentile",
            "field":"amount", "percentile": percentile, "scale": 2
        }));
    }
    let mut rows: Vec<Row> = Vec::new();
    let mut by_category: Vec<Vec<i64>> = Vec::new();
    for n in 1..=60_usize {
        let values: Vec<i64> = (0..n).map(|index| seeded_hundredths(n, index)).collect();
        for value in &values {
            let code: &'static str = Box::leak(codes[n - 1].clone().into_boxed_str());
            rows.push((code, "2025-03-10", Some(hundredths_text(*value)), None));
        }
        by_category.push(values);
    }
    let source = source_with_categories(&["category"], json!(measures), &code_refs);
    let (database, migration_task, app) = fixture_for(source, &rows).await;
    let document = body_json(live(&app, "2025-03", "2025-03", None).await).await;

    let all: Vec<i64> = by_category.iter().flatten().copied().collect();
    for percentile in PERCENTILES {
        let measure = format!("p{percentile}");
        for (index, values) in by_category.iter().enumerate() {
            assert_eq!(
                cell(&document, "2025-03", Some(&codes[index]), &measure),
                json!([definition_two(values, percentile), "exact"]),
                "n = {} percentile {percentile}",
                index + 1
            );
        }
        assert_eq!(
            cell(&document, "2025-03", Some("_T"), &measure),
            json!([definition_two(&all, percentile), "exact"]),
            "total percentile {percentile}"
        );
    }
    migration_task.abort();
    database.cleanup().await;
}

/// A public register with a statistician who reads exact values.
fn exact_register_source(measures: Value) -> Value {
    let mut source = public_register_source(measures);
    source["accessProfiles"].as_array_mut().unwrap().push(
        json!({"id":"statistician","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{
            "datasets":[{"dataset":"records-by-category","operations":["read-exact"]}]}}),
    );
    source["statisticalDatasets"][0]["exactReads"] = json!({"accessProfile":"analyst"});
    source
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ratio_and_a_percentile_are_read_live_read_exact_and_released_exactly() {
    let rows: Vec<Row> = vec![
        ("a", "2025-03-10", Some("1.00"), None),
        ("a", "2025-03-11", Some("2.00"), None),
        ("a", "2025-03-12", Some("3.00"), None),
        ("a", "2025-03-13", Some("4.00"), None),
        ("b", "2025-03-14", Some("-1.00"), None),
        ("b", "2025-03-15", Some("-2.00"), None),
    ];
    let (database, migration_task, app) = fixture_for(
        exact_register_source(json!([
            {"id":"records","type":"count"},
            {"id":"amount-sum","type":"sum","field":"amount"},
            {"id":"amount-per-record","type":"ratio","numerator":"amount-sum","denominator":"records","scale":3},
            {"id":"median-amount","type":"percentile","field":"amount","percentile":50,"scale":2}
        ])),
        &rows,
    )
    .await;

    let live_document = body_json(live(&app, "2025-03", "2025-03", None).await).await;
    let mut request = Request::builder()
        .method("GET")
        .uri("/v1/statistics/records-by-category:exact?accessProfile=statistician&from=2025-03&to=2025-03")
        .body(Body::empty())
        .expect("request builds");
    request
        .extensions_mut()
        .insert(release_claims("statistician"));
    let exact = app.clone().call(request).await.expect("router responds");
    assert_eq!(exact.status(), StatusCode::OK);
    assert_eq!(body_json(exact).await["cells"], live_document["cells"]);

    let published = release_request(
        &app,
        "POST",
        "/v1/statistics/records-by-category/releases/2025-03/versions?accessProfile=publisher",
        release_claims("publisher"),
        Some("ratio-percentile-release"),
    )
    .await;
    assert_eq!(
        published.status(),
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&body_bytes(published).await)
    );
    let read = release_request(
        &app,
        "GET",
        "/v1/statistics/records-by-category/releases/2025-03/versions/1?accessProfile=reader",
        release_claims("reader"),
        None,
    )
    .await;
    assert_eq!(read.status(), StatusCode::OK);
    let released = body_json(read).await;
    assert_eq!(
        released["disclosure"],
        json!({"method":"exact-public-values"})
    );
    assert_eq!(released["cells"], live_document["cells"]);

    // One record or two is stated exactly; a cell with no record has no ratio
    // and no percentile.
    for (category, ratio, median) in [
        ("a", json!(["2.500", "exact"]), json!(["2.50", "exact"])),
        ("b", json!(["-1.500", "exact"]), json!(["-1.50", "exact"])),
        (
            "c",
            json!([Value::Null, "not-applicable"]),
            json!([Value::Null, "not-applicable"]),
        ),
        // 7.00 / 6 is not the mean of 2.5 and -1.5; the median of -2, -1, 1, 2,
        // 3, 4 is 1.5.
        ("_T", json!(["1.167", "exact"]), json!(["1.50", "exact"])),
    ] {
        assert_eq!(
            cell(&released, "2025-03", Some(category), "amount-per-record"),
            ratio,
            "{category} ratio"
        );
        assert_eq!(
            cell(&released, "2025-03", Some(category), "median-amount"),
            median,
            "{category} median"
        );
    }
    migration_task.abort();
    database.cleanup().await;
}
