// SPDX-License-Identifier: Apache-2.0
//! The protected release of sums and the publisher's dry run, computed by
//! PostgreSQL.
//!
//! The compiler refuses a release of sums under minimum-count-and-rounding
//! (`sum-release-held`), so no such project compiles. These tests compile the
//! same project under `exact-public-values`, which the compiler accepts, and
//! then replace the compiled dataset's `disclosure` and `sumDisclosure` in test
//! code, before the schema is installed. The publish path and the dry run
//! therefore read a compiled dataset that carries the contributor and p; no
//! production code path, feature or setting skips the refusal.

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet};
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
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    PostgresRecordReadService, PostgresStatisticsService, RegistryLockKey,
    RegistryStateTestIdentity,
};
use registry_platform_audit::AuditProfile;
use serde_json::{json, Value};
use tower::Service as _;
use zeroize::Zeroizing;

const PACKAGE_ID: &str = "protected-sums-registry";
const DATABASE_ID: &str = "protected-sums-database";
const DATASET: &str = "records-by-category";

/// One parcel: district, category, owner (an index into the owner list, or
/// `None` for a parcel with no owner), area (decimal) and units (int64), each
/// empty for a parcel that leaves the field unset.
type Parcel = (
    &'static str,
    &'static str,
    Option<usize>,
    &'static str,
    &'static str,
);

/// Parcels of March 2025 chosen so that every rule of the release has a cell.
///
/// The release withholds a sum with fewer than 3 contributors, and with
/// p = 50 a sum whose two largest contributions leave under 50 per cent of
/// the largest (`100 (T - x1 - x2) < 50 x1`). Counts and int64 sums round to
/// the base 5.
fn parcels() -> Vec<Parcel> {
    let mut parcels: Vec<Parcel> = Vec::new();
    // d1/a: five owners, balanced.
    for (owner, units) in [(0, "10"), (1, "10"), (2, "10"), (3, "10"), (4, "13")] {
        parcels.push(("d1", "a", Some(owner), "10.00", units));
    }
    // d1/b: owner 0 holds 90 of 100 (dominant for the area); the units are
    // balanced.
    for (owner, area) in [(0, "90.00"), (1, "5.00"), (2, "5.00")] {
        parcels.push(("d1", "b", Some(owner), area, "10"));
    }
    // d1/c: one farmer with five parcels is one contributor.
    for _ in 0..5 {
        parcels.push(("d1", "c", Some(5), "10.00", "10"));
    }
    // d2/a: 100 (70 - 40 - 10) = 2000 = 50 * 40, exactly the boundary.
    for (owner, area) in [(0, "40.00"), (1, "10.00"), (2, "10.00"), (3, "10.00")] {
        parcels.push(("d2", "a", Some(owner), area, "10"));
    }
    // d2/b: four parcels with no owner are one contributor together.
    for _ in 0..4 {
        parcels.push(("d2", "b", None, "10.00", "10"));
    }
    parcels
}

/// `(district, category, measure, value, status, reason)` of every cell the
/// release of `parcels()` states, with the reason the dry run gives for a
/// withheld cell.
type Expected = (
    &'static str,
    &'static str,
    &'static str,
    Value,
    &'static str,
    Option<&'static str>,
);

fn expected_cells() -> Vec<Expected> {
    let mc = Some("minimum-contributors");
    let dom = Some("dominance");
    let cont = Some("contains-suppressed-sum");
    let none = Value::Null;
    vec![
        // Counts: rounded to 5; withheld only for contributors.
        ("d1", "a", "parcels", json!(5), "rounded", None),
        ("d1", "b", "parcels", json!(5), "rounded", None),
        ("d1", "c", "parcels", none.clone(), "suppressed", mc),
        ("d1", "_T", "parcels", json!(15), "rounded", None),
        ("d2", "a", "parcels", json!(5), "rounded", None),
        ("d2", "b", "parcels", none.clone(), "suppressed", mc),
        ("d2", "c", "parcels", json!(0), "exact", None),
        ("d2", "_T", "parcels", json!(10), "rounded", None),
        ("_T", "a", "parcels", json!(10), "rounded", None),
        ("_T", "b", "parcels", json!(5), "rounded", None),
        ("_T", "c", "parcels", none.clone(), "suppressed", mc),
        ("_T", "_T", "parcels", json!(20), "rounded", None),
        // The decimal sum is exact.
        ("d1", "a", "area-sum", json!("50.00"), "exact", None),
        ("d1", "b", "area-sum", none.clone(), "suppressed", dom),
        ("d1", "c", "area-sum", none.clone(), "suppressed", mc),
        ("d1", "_T", "area-sum", none.clone(), "suppressed", cont),
        ("d2", "a", "area-sum", json!("70.00"), "exact", None),
        ("d2", "b", "area-sum", none.clone(), "suppressed", mc),
        ("d2", "c", "area-sum", json!("0.00"), "exact", None),
        ("d2", "_T", "area-sum", none.clone(), "suppressed", cont),
        ("_T", "a", "area-sum", json!("120.00"), "exact", None),
        ("_T", "b", "area-sum", none.clone(), "suppressed", dom),
        ("_T", "c", "area-sum", none.clone(), "suppressed", mc),
        ("_T", "_T", "area-sum", none.clone(), "suppressed", cont),
        // The int64 sum rounds to 5. _T/b holds the suppressed d2/b, so it
        // is blank even though no contributor dominates it.
        ("d1", "a", "units-sum", json!("55"), "rounded", None),
        ("d1", "b", "units-sum", json!("30"), "rounded", None),
        ("d1", "c", "units-sum", none.clone(), "suppressed", mc),
        ("d1", "_T", "units-sum", none.clone(), "suppressed", cont),
        ("d2", "a", "units-sum", json!("40"), "rounded", None),
        ("d2", "b", "units-sum", none.clone(), "suppressed", mc),
        ("d2", "c", "units-sum", json!("0"), "exact", None),
        ("d2", "_T", "units-sum", none.clone(), "suppressed", cont),
        ("_T", "a", "units-sum", json!("95"), "rounded", None),
        ("_T", "b", "units-sum", none.clone(), "suppressed", cont),
        ("_T", "c", "units-sum", none.clone(), "suppressed", mc),
        ("_T", "_T", "units-sum", none, "suppressed", cont),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_dry_run_names_the_reason_of_every_withheld_cell_and_publish_stores_the_same_document()
{
    let (database, task, app) =
        fixture(protected(compiled(), field_contributor()), &parcels()).await;

    let dry = dry_run(&app, "publisher", "2025-03").await;
    let dry_status = dry.status();
    assert_eq!(dry.headers()["content-type"], "application/json");
    assert!(dry.headers().contains_key("repr-digest"));
    for absent in ["etag", "location", "link"] {
        assert!(!dry.headers().contains_key(absent), "{absent}");
    }
    let dry_bytes = body_bytes(dry).await;
    assert_eq!(
        dry_status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&dry_bytes)
    );
    let dry_body: Value = serde_json::from_slice(&dry_bytes).expect("dry run is JSON");
    let document = dry_body["document"].clone();
    assert_eq!(document["release"]["version"], 1);
    assert_eq!(document["release"]["status"], "final");

    // Every withheld cell has its reason, in cell order, and no other cell does.
    let suppressions = dry_body["suppressions"].as_array().expect("an array");
    let indexes: Vec<u64> = suppressions
        .iter()
        .map(|entry| entry["cell"].as_u64().expect("a cell index"))
        .collect();
    assert!(
        indexes.windows(2).all(|pair| pair[0] < pair[1]),
        "{indexes:?}"
    );
    let mut reasons: BTreeMap<(String, String, String), String> = BTreeMap::new();
    for entry in suppressions {
        let cell = &document["cells"][entry["cell"].as_u64().unwrap() as usize];
        assert_eq!(cell["status"], "suppressed");
        reasons.insert(
            (
                cell["dimensions"]["district"].as_str().unwrap().to_owned(),
                cell["dimensions"]["category"].as_str().unwrap().to_owned(),
                cell["measure"].as_str().unwrap().to_owned(),
            ),
            entry["reason"].as_str().unwrap().to_owned(),
        );
    }
    let want_reasons: BTreeMap<(String, String, String), String> = expected_cells()
        .into_iter()
        .filter_map(|(district, category, measure, _, _, reason)| {
            reason.map(|reason| {
                (
                    (district.to_owned(), category.to_owned(), measure.to_owned()),
                    reason.to_owned(),
                )
            })
        })
        .collect();
    assert_eq!(reasons, want_reasons);

    for (district, category, measure, value, status, _) in expected_cells() {
        let found = cell_of(&document, district, category, measure);
        assert_eq!(
            json!([found["value"], found["status"]]),
            json!([value, status]),
            "{district}/{category} {measure}"
        );
    }

    // The documents state the rules and never p or a per-cell input.
    assert_eq!(
        document["disclosure"],
        json!({
            "method":"minimum-count-and-rounding","minimumCount":3,"roundingBase":5,
            "roundingRule":"nearest-multiple-halves-up","totals":"rounded-independently",
            "contributor":{"type":"field","field":"owner"},
            "dominanceRule":"p-percent",
            "sumTotals":"suppressed-when-containing-a-suppressed-sum"
        })
    );
    // The suppression reasons are part of the dry run's answer by design, so
    // the search covers the document it carries.
    assert_no_protected_input(&serde_json::to_vec(&document).expect("document serializes"));
    for cell in document["cells"].as_array().unwrap() {
        let keys: BTreeSet<&str> = cell
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert!(
            keys.is_subset(&BTreeSet::from([
                "period",
                "dimensions",
                "measure",
                "value",
                "status"
            ])),
            "{keys:?}"
        );
    }

    // Nothing was stored and no version reserved: the publication that follows
    // is version 1 and stores exactly the document the dry run returned.
    assert_eq!(release_row_count(&database).await, 0);
    let published = publish(&app, "protected-release").await;
    assert_eq!(published.status(), StatusCode::CREATED);
    let read = read_version(&app, "reader", 1).await;
    assert_eq!(read.status(), StatusCode::OK);
    let read_bytes = body_bytes(read).await;
    assert_no_protected_input(&read_bytes);
    let mut stored: Value = serde_json::from_slice(&read_bytes).expect("release is JSON");
    let mut dry_document = document;
    for value in [&mut stored, &mut dry_document] {
        value["release"]
            .as_object_mut()
            .expect("release member")
            .remove("computedAt");
    }
    assert_eq!(stored, dry_document);
    assert_eq!(release_row_count(&database).await, 1);

    task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_record_as_contributor_makes_a_farmer_with_five_parcels_five_contributors() {
    let (database, task, app) = fixture(
        protected(compiled(), json!({"type":"each-record"})),
        &parcels(),
    )
    .await;
    let dry = dry_run(&app, "publisher", "2025-03").await;
    assert_eq!(dry.status(), StatusCode::OK);
    let body = body_json(dry).await;
    let document = &body["document"];
    assert_eq!(
        document["disclosure"]["contributor"],
        json!({"type":"each-record"})
    );
    // Five parcels are five contributors: d1/c and d2/b are no longer withheld
    // for contributors, and are balanced.
    for (district, category, measure, value) in [
        ("d1", "c", "area-sum", json!("50.00")),
        ("d2", "b", "area-sum", json!("40.00")),
        ("d1", "c", "parcels", json!(5)),
        ("d2", "b", "parcels", json!(5)),
    ] {
        let found = cell_of(document, district, category, measure);
        assert_eq!(found["value"], value, "{district}/{category} {measure}");
    }
    // The dominant cell stays withheld: its owner's parcel is 90 of 100.
    let dominant = cell_of(document, "d1", "b", "area-sum");
    assert_eq!(dominant["status"], "suppressed");
    assert!(body["suppressions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["reason"] == "dominance"));
    task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_negative_int64_value_refuses_the_dry_run_and_the_publication() {
    let mut rows = parcels();
    rows.push(("d1", "a", Some(0), "1.00", "-1"));
    let (database, task, app) = fixture(protected(compiled(), field_contributor()), &rows).await;
    for response in [
        dry_run(&app, "publisher", "2025-03").await,
        publish(&app, "negative-int64").await,
    ] {
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let problem = body_json(response).await;
        assert_eq!(problem["code"], "statistical_dataset.release_refused");
        assert_eq!(problem["refusalCode"], "negative-value");
    }
    assert_eq!(release_row_count(&database).await, 0);
    task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_negative_decimal_stored_under_a_zero_minimum_refuses_the_release() {
    // The declared minimum is 0.00, which the column enforces for new values.
    // A value stored before the minimum was declared may still be negative, so
    // the release checks the stored values: the test removes the column's check
    // to store one.
    let compiled = protected(compiled(), field_contributor());
    let (database, task, app) = fixture(compiled.clone(), &parcels()).await;
    let negative: Vec<Parcel> = vec![("d1", "a", Some(0), "-1.00", "1")];
    assert!(
        insert_parcels(&database, &compiled, &negative, 1000)
            .await
            .is_err(),
        "the column refuses a negative value under a minimum of zero"
    );
    drop_area_minimum(&database, &compiled).await;
    insert_parcels(&database, &compiled, &negative, 1000)
        .await
        .expect("the relaxed column stores the negative value");
    for response in [
        dry_run(&app, "publisher", "2025-03").await,
        publish(&app, "negative-decimal").await,
    ] {
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let problem = body_json(response).await;
        assert_eq!(problem["code"], "statistical_dataset.release_refused");
        assert_eq!(problem["refusalCode"], "negative-value");
    }
    assert_eq!(release_row_count(&database).await, 0);
    task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_dry_run_is_unavailable_to_a_release_reader_and_a_live_reader() {
    let (database, task, app) =
        fixture(protected(compiled(), field_contributor()), &parcels()).await;
    for profile in ["reader", "analyst"] {
        let response = dry_run(&app, profile, "2025-03").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{profile}");
    }
    assert_eq!(release_row_count(&database).await, 0);
    task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unended_period_is_refused_by_the_dry_run_as_by_publish() {
    let (database, task, app) =
        fixture(protected(compiled(), field_contributor()), &parcels()).await;
    let response = dry_run(&app, "publisher", "2999-01").await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let problem = body_json(response).await;
    assert_eq!(problem["refusalCode"], "period-not-ended");
    task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_small_cell_whose_parcels_leave_the_summed_fields_unset_is_withheld() {
    // d2/c has no parcels in the main fixture, so its sums are an exact zero.
    // Two owners' parcels with no area and no units make it a cell of two
    // contributors, none of them with a value: a zero would tell a reader
    // that this small group left both fields unset.
    let mut rows = parcels();
    rows.push(("d2", "c", Some(0), "", ""));
    rows.push(("d2", "c", Some(1), "", ""));
    let (database, task, app) = fixture(protected(compiled(), field_contributor()), &rows).await;
    let dry = dry_run(&app, "publisher", "2025-03").await;
    assert_eq!(dry.status(), StatusCode::OK);
    let body = body_json(dry).await;
    for (measure, reason) in [
        ("parcels", "minimum-count"),
        ("area-sum", "minimum-contributors"),
        ("units-sum", "minimum-contributors"),
    ] {
        let cell = cell_of(&body["document"], "d2", "c", measure);
        assert_eq!(
            json!([cell["value"], cell["status"]]),
            json!([null, "suppressed"]),
            "{measure}"
        );
        assert_eq!(
            reason_of(&body, "d2", "c", measure),
            Some(reason),
            "{measure}"
        );
    }
    task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn parcels_with_no_owner_in_two_cells_are_one_contributor_at_their_total() {
    // Owner 0 and an unowned parcel in d1/a, an unowned parcel in d2/a. The
    // total _T/a has three parcels and two contributors, not three: the
    // unowned parcels of both cells are one contributor together.
    let rows: Vec<Parcel> = vec![
        ("d1", "a", Some(0), "10.00", "10"),
        ("d1", "a", None, "10.00", "10"),
        ("d2", "a", None, "10.00", "10"),
    ];
    let (database, task, app) = fixture(protected(compiled(), field_contributor()), &rows).await;
    let dry = dry_run(&app, "publisher", "2025-03").await;
    assert_eq!(dry.status(), StatusCode::OK);
    let body = body_json(dry).await;
    for measure in ["parcels", "area-sum", "units-sum"] {
        let total = cell_of(&body["document"], "_T", "a", measure);
        assert_eq!(total["status"], "suppressed", "{measure}");
        assert_eq!(
            reason_of(&body, "_T", "a", measure),
            Some("minimum-contributors"),
            "{measure}"
        );
    }
    task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dataset_without_dimensions_releases_its_grand_total_through_the_dry_run_and_publish() {
    let mut without_dimensions = source();
    without_dimensions["statisticalDatasets"][DATASET]["dimensions"] = json!([]);
    let (database, task, app) = fixture(
        protected(compiled_from(&without_dimensions), field_contributor()),
        &parcels(),
    )
    .await;
    let dry = dry_run(&app, "publisher", "2025-03").await;
    assert_eq!(dry.status(), StatusCode::OK);
    let body = body_json(dry).await;
    assert_eq!(body["suppressions"], json!([]));
    let mut document = body["document"].clone();
    // 21 parcels of seven contributors (six owners and the unowned parcels).
    // The largest two contributions are 140.00 and 50.00 of an area of
    // 310.00, and 50 and 40 of 213 units: neither sum is dominated.
    let cells: BTreeMap<String, Value> = document["cells"]
        .as_array()
        .expect("cells are an array")
        .iter()
        .map(|cell| {
            assert_eq!(cell["dimensions"], json!({}));
            (
                cell["measure"].as_str().unwrap().to_owned(),
                json!([cell["value"], cell["status"]]),
            )
        })
        .collect();
    assert_eq!(
        cells,
        BTreeMap::from([
            ("parcels".to_owned(), json!([20, "rounded"])),
            ("area-sum".to_owned(), json!(["310.00", "exact"])),
            ("units-sum".to_owned(), json!(["215", "rounded"])),
        ])
    );
    let published = publish(&app, "grand-total").await;
    assert_eq!(published.status(), StatusCode::CREATED);
    let read = read_version(&app, "reader", 1).await;
    assert_eq!(read.status(), StatusCode::OK);
    let mut stored = body_json(read).await;
    for value in [&mut stored, &mut document] {
        value["release"]
            .as_object_mut()
            .expect("release member")
            .remove("computedAt");
    }
    assert_eq!(stored, document);
    task.abort();
    database.cleanup().await;
}

/// The reason the dry run gives for one cell, if it withheld it.
fn reason_of<'a>(
    body: &'a Value,
    district: &str,
    category: &str,
    measure: &str,
) -> Option<&'a str> {
    let target = cell_of(&body["document"], district, category, measure);
    body["suppressions"]
        .as_array()
        .expect("suppressions are an array")
        .iter()
        .find(|entry| {
            &body["document"]["cells"][entry["cell"].as_u64().unwrap() as usize] == target
        })
        .map(|entry| entry["reason"].as_str().expect("a reason"))
}

fn assert_no_protected_input(bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes).to_lowercase();
    for word in [
        "dominancepercent",
        "dominance_percent",
        "contributors",
        "dominant",
        "largest",
        "second",
        "integersums",
    ] {
        assert!(!text.contains(word), "the document names `{word}`");
    }
}

fn cell_of<'a>(document: &'a Value, district: &str, category: &str, measure: &str) -> &'a Value {
    document["cells"]
        .as_array()
        .expect("cells are an array")
        .iter()
        .find(|cell| {
            cell["measure"] == measure
                && cell["dimensions"]["district"] == district
                && cell["dimensions"]["category"] == category
        })
        .unwrap_or_else(|| panic!("no cell for {district}/{category} {measure}"))
}

fn field_contributor() -> Value {
    json!({"type":"field","field":"owner"})
}

/// The project: parcels with an owner reference, a decimal area that declares
/// a minimum of 0, an int64 count of units, every field public, and a
/// publisher, a release reader and a live analyst.
fn source() -> Value {
    json!({"datasets":{"protected-sums": {}},
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
        "kind":"BRegProject",
        "project":{"id":PACKAGE_ID,"version":"1","defaultLanguage":"en","canonicalBaseIri":"https://statistics.example.test","timezone":"UTC"},
        "recordTypes":{
            "owner": {"primaryDataset":"protected-sums","route":"owners","mutationMode":"mutable",
                "classification":"public",
                "fields":[{"id":"name","type":"string","maximumLength":80,"classification":"public"}]
            },
            "record": {"primaryDataset":"protected-sums","route":"records","mutationMode":"mutable",
                "classification":"public",
                "fields":[
                    {"id":"subject","type":"string","maximumLength":128,"required":true,"classification":"public"},
                    {"id":"active","type":"boolean","required":true,"classification":"public"},
                    {"id":"district","type":"vocabulary-code","vocabulary":"district","required":true,"classification":"public"},
                    {"id":"category","type":"vocabulary-code","vocabulary":"category","required":true,"classification":"public"},
                    {"id":"event-date","type":"date","required":true,"classification":"public"},
                    {"id":"area","type":"decimal","precision":10,"scale":2,"minimum":"0.00","classification":"public"},
                    {"id":"units","type":"int64","classification":"public"},
                    {"id":"owner","type":"reference","target":"owner","classification":"public"}
                ]
            }
        },
        "accessProfiles":{
            "analyst": {"default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
                "recordType":"record","operations":["list"],
                "readableFields":["subject","active","district","category","event-date","area","units","owner"],
                "filterableFields":["subject","active","district","category","event-date"],"allowCount":true,
                "rowBoundaries":"unrestricted"
            }],"datasets":[{"dataset":DATASET,"operations":["read-live","read-releases"]}]}},
            "publisher": {"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
                "recordType":"record","operations":["list"],
                "readableFields":["subject","active","district","category","event-date","area","units","owner"],
                "filterableFields":["subject","active","district","category","event-date"],"allowCount":true,
                "rowBoundaries":"unrestricted"
            }],"datasets":[{"dataset":DATASET,"operations":["publish","read-releases"]}]}},
            "reader": {"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{
                "datasets":[{"dataset":DATASET,"operations":["read-releases"]}]}}
        },
        "vocabularies":{"district": {"values":["d1","d2"]}, "category": {"values":["a","b","c"]}},
        "statisticalDatasets":{"DATASET": {"unit":"record","population":"active eq true",
            "period":{"type":"flow","field":"event-date","granularity":"month","firstPeriod":"2025-01"},
            "dimensions":["district","category"],
            "measures":[
                {"id":"parcels","type":"count"},
                {"id":"area-sum","type":"sum","field":"area"},
                {"id":"units-sum","type":"sum","field":"units"}
            ],
            "disclosure":{"type":"exact-public-values"}
        }}
    })
}

fn compiled() -> registry_breg::CompiledRegistry {
    compiled_from(&source())
}

fn compiled_from(source: &Value) -> registry_breg::CompiledRegistry {
    let project = parse_project_json(&serde_json::to_vec(source).unwrap()).expect("parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("compiles")
}

/// Test code only: gives the compiled dataset the minimum-count-and-rounding
/// method with a contributor and p = 50, as a project the compiler holds back
/// would compile to.
fn protected(
    compiled: registry_breg::CompiledRegistry,
    contributor: Value,
) -> registry_breg::CompiledRegistry {
    let mut value = serde_json::to_value(&compiled).expect("compiled registry serializes");
    let dataset = &mut value["statisticalDatasets"][DATASET];
    dataset["disclosure"] =
        json!({"method":"minimum-count-and-rounding","minimumCount":3,"roundingBase":5});
    dataset["sumDisclosure"] = json!({
        "contributor": contributor,
        "dominancePercent": 50,
        "integerSums": ["units-sum"]
    });
    serde_json::from_value(value).expect("the protected dataset deserializes")
}

async fn fixture(
    compiled: registry_breg::CompiledRegistry,
    parcels: &[Parcel],
) -> (TestDatabase, tokio::task::JoinHandle<()>, axum::Router) {
    let compiled = Arc::new(compiled);
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
            label: "package-protected-sums-1",
        },
    )
    .await
    .expect("runtime identity initializes");
    seed(&database, &compiled, parcels).await;
    let pool = database.runtime_config.build_pool().expect("pool builds");
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives");
    let audit = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x73; 32].into())
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
        Duration::from_secs(10),
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

/// Owners and parcels go in through the administrative connection: the sum
/// fields are inserted directly, including values the write path refuses.
async fn seed(
    database: &TestDatabase,
    compiled: &registry_breg::CompiledRegistry,
    parcels: &[Parcel],
) {
    let owner = &compiled.entities()["owner"];
    let owners_table = quote_identifier(&owner.physical_table);
    let owner_id = |index: usize| format!("00000000-0000-4000-8000-{:012}", index + 1);
    let activation = active_activation(database).await;
    let owner_count = parcels
        .iter()
        .filter_map(|parcel| parcel.2)
        .max()
        .map_or(0, |highest| highest + 1);
    for index in 0..owner_count {
        database
            .admin
            .execute(
                &format!(
                    "INSERT INTO registry_data.{owners_table}
                         (record_id, record_revision, record_lifecycle, active_package_revision)
                     VALUES ($1::text::uuid, 1, 'active', $2)"
                ),
                &[&owner_id(index), &activation],
            )
            .await
            .expect("owner inserts");
    }
    insert_parcels(database, compiled, parcels, 0)
        .await
        .expect("parcels insert");
}

async fn active_activation(database: &TestDatabase) -> String {
    database
        .admin
        .query_one(
            "SELECT active_activation_id::text FROM registry_internal.registry_state WHERE singleton",
            &[],
        )
        .await
        .expect("the active activation is recorded")
        .get(0)
}

/// Inserts parcels through the administrative connection, numbering their
/// record ids from `first`; the owners must exist.
async fn insert_parcels(
    database: &TestDatabase,
    compiled: &registry_breg::CompiledRegistry,
    parcels: &[Parcel],
    first: usize,
) -> Result<(), tokio_postgres::Error> {
    let record = &compiled.entities()["record"];
    let column = |field: &str| quote_identifier(&record.fields[field].physical_name);
    let table = quote_identifier(&record.physical_table);
    let activation = active_activation(database).await;
    let owner_id = |index: usize| format!("00000000-0000-4000-8000-{:012}", index + 1);
    let sql = format!(
        "INSERT INTO registry_data.{table}
             (record_id, record_revision, record_lifecycle, active_package_revision,
              {subject}, {active}, {district}, {category}, {event_date}, {area}, {units}, {owner})
         VALUES ($1::text::uuid, 1, 'active', $8, $1, true, $2, $3, $4,
                 NULLIF($5::text, '')::numeric, NULLIF($6::text, '')::bigint, $7::text::uuid)",
        subject = column("subject"),
        active = column("active"),
        district = column("district"),
        category = column("category"),
        event_date = column("event-date"),
        area = column("area"),
        units = column("units"),
        owner = column("owner"),
    );
    let date = NaiveDate::from_ymd_opt(2025, 3, 10).expect("date is valid");
    for (index, (district, category, owner, area, units)) in parcels.iter().enumerate() {
        let id = format!("00000000-0000-4000-9000-{:012}", first + index + 1);
        let owner = owner.map(owner_id);
        database
            .admin
            .execute(
                &sql,
                &[
                    &id,
                    district,
                    category,
                    &date,
                    area,
                    units,
                    &owner,
                    &activation,
                ],
            )
            .await?;
    }
    Ok(())
}

/// Removes the check constraints of the area column, as if the minimum of zero
/// had been declared after negative values were stored.
async fn drop_area_minimum(database: &TestDatabase, compiled: &registry_breg::CompiledRegistry) {
    let record = &compiled.entities()["record"];
    let area = &record.fields["area"].physical_name;
    let table = &record.physical_table;
    let constraints = database
        .admin
        .query(
            "SELECT c.conname
               FROM pg_constraint c
               JOIN pg_class t ON t.oid = c.conrelid
               JOIN pg_namespace n ON n.oid = t.relnamespace
              WHERE n.nspname = 'registry_data' AND t.relname = $1 AND c.contype = 'c'
                AND pg_get_constraintdef(c.oid) LIKE '%' || quote_ident($2) || '%'",
            &[table, area],
        )
        .await
        .expect("constraints list");
    assert!(!constraints.is_empty(), "the area column has a check");
    for constraint in constraints {
        let name: String = constraint.get(0);
        database
            .admin
            .batch_execute(&format!(
                "ALTER TABLE registry_data.{} DROP CONSTRAINT {}",
                quote_identifier(table),
                quote_identifier(&name)
            ))
            .await
            .expect("check constraint drops");
    }
}

async fn release_row_count(database: &TestDatabase) -> i64 {
    database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_statistical_release_versions",
            &[],
        )
        .await
        .expect("release rows count")
        .get(0)
}

fn claims(profile: &str) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "principal",
        format!("protected-sums-{profile}"),
        Default::default(),
        None,
        Default::default(),
    )
    .expect("claims are valid")
}

async fn dry_run(app: &axum::Router, profile: &str, period: &str) -> Response<Body> {
    request(
        app,
        "POST",
        &format!(
            "/v1/statistics/{DATASET}/releases/{period}/versions:dry-run?accessProfile={profile}"
        ),
        profile,
        Some(("content-type", "application/json")),
        None,
    )
    .await
}

async fn publish(app: &axum::Router, key: &str) -> Response<Body> {
    request(
        app,
        "POST",
        &format!("/v1/statistics/{DATASET}/releases/2025-03/versions?accessProfile=publisher"),
        "publisher",
        Some(("content-type", "application/json")),
        Some(key),
    )
    .await
}

async fn read_version(app: &axum::Router, profile: &str, version: u64) -> Response<Body> {
    request(
        app,
        "GET",
        &format!(
            "/v1/statistics/{DATASET}/releases/2025-03/versions/{version}?accessProfile={profile}"
        ),
        profile,
        None,
        None,
    )
    .await
}

async fn request(
    app: &axum::Router,
    method: &str,
    uri: &str,
    profile: &str,
    content_type: Option<(&str, &str)>,
    idempotency_key: Option<&str>,
) -> Response<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    let body = if let Some((name, value)) = content_type {
        builder = builder.header(name, value);
        Body::from(serde_json::to_vec(&json!({"status":"final"})).expect("body serializes"))
    } else {
        Body::empty()
    };
    if let Some(key) = idempotency_key {
        builder = builder.header("idempotency-key", key);
    }
    let mut request = builder.body(body).expect("request builds");
    request.extensions_mut().insert(claims(profile));
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
