// SPDX-License-Identifier: Apache-2.0

//! The GovStack Consultation facade, end to end: the built `adapter` binary
//! serves the dhis2-govstack example (the govstack-consultation profile over
//! the dhis2-tracker pack) against a loopback upstream that replays the
//! committed captures. Every test names a call a relying party makes and
//! the reply it gets: the record and page shapes, the problem codes, the
//! refusals before any upstream call, and what the journal holds. Needs
//! `ADAPTER_TEST_DATABASE_URL`.
#![cfg(feature = "postgres-test")]

#[allow(dead_code)]
#[path = "support/served/mod.rs"]
mod served_harness;

use serde_json::json;
use served_harness::upstream::{Response, UpstreamDouble};
use served_harness::{capture, fixture, Served};

const PROBLEMS: &str = "https://govstack.global/problems/digital-registries/";
const GET_PATH: &str = "/v1/collections/persons/records/EeBJ3Sn9uLg";
const LIST_PATH: &str = "/v1/collections/persons/records";
const LOOKUP_PATH: &str = "/v1/collections/persons/lookup";
const SEARCH_PATH: &str = "/v1/collections/persons/search";

async fn start(upstream: &UpstreamDouble) -> Served {
    Served::start_with_project(&upstream.url(""), &Served::govstack_project()).await
}

/// The capture's search reply restated as page `page` of `page_count`.
fn page_of(page: u64, page_count: u64) -> Response {
    let document = fixture("search-page");
    let mut body = document["entries"][0]["upstream"][0]["response"]["body"].clone();
    body["pager"]["page"] = json!(page);
    body["pager"]["pageCount"] = json!(page_count);
    Response::json(200, &body.to_string())
}

fn found() -> Response {
    let (status, body) = capture("get-found");
    Response::json(status, &body)
}

/// The two shapes of the Consultation contract this facade serves, as a
/// relying party reads them: a Problem with a 32-digit trace identifier, a
/// Record, and a RecordPage whose `pageInfo.nextCursor` is a string or null.
mod contract {
    use serde_json::Value;

    pub fn is_trace_id(text: &str) -> bool {
        text.len() == 32
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && text.bytes().any(|b| b != b'0')
    }

    pub fn assert_problem(body: &Value, status: u64, slug: &str) {
        let object = body.as_object().expect("a problem is an object");
        for member in ["type", "title", "status", "traceId"] {
            assert!(object.contains_key(member), "{member} is required: {body}");
        }
        assert!(
            object.keys().all(|key| ["type", "title", "status", "detail", "traceId"]
                .contains(&key.as_str())),
            "no member beyond the Problem's: {body}"
        );
        assert_eq!(body["status"], status, "{body}");
        assert_eq!(body["type"], format!("{}{slug}", super::PROBLEMS), "{body}");
        assert!(body["title"].is_string(), "{body}");
        assert!(
            is_trace_id(body["traceId"].as_str().expect("traceId")),
            "{body}"
        );
    }

    pub fn assert_record(body: &Value) {
        let object = body.as_object().expect("a record is an object");
        assert_eq!(object.len(), 2, "recordId and data only: {body}");
        assert!(
            body["recordId"].as_str().is_some_and(|id| !id.is_empty()),
            "{body}"
        );
        assert!(body["data"].is_object(), "{body}");
    }

    pub fn assert_page(body: &Value) {
        let object = body.as_object().expect("a page is an object");
        assert_eq!(object.len(), 2, "items and pageInfo only: {body}");
        for item in body["items"].as_array().expect("items is an array") {
            assert_record(item);
        }
        let page_info = body["pageInfo"].as_object().expect("pageInfo is an object");
        assert_eq!(page_info.len(), 1, "{body}");
        assert!(
            body["pageInfo"]["nextCursor"].is_string() || body["pageInfo"]["nextCursor"].is_null(),
            "{body}"
        );
    }
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

#[tokio::test]
async fn one_record_comes_back_as_a_record() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![found()]);
    let served = start(&upstream).await;
    let token = served.token("records.read");

    let (status, head, body) = served.get(GET_PATH, Some(&token));

    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body,
        json!({
            "recordId": "EeBJ3Sn9uLg",
            "data": {
                "tracked_entity_type": "cQWYtUfH6Vx",
                "org_unit": "slSrf7H9lMf",
                "created_at": "2017-01-20T10:44:02.770",
                "updated_at": "2017-05-26T11:46:22.372"
            }
        })
    );
    contract::assert_record(&body);
    assert_eq!(header(&head, "content-type"), Some("application/json"));
    assert_eq!(header(&head, "cache-control"), Some("no-store"));
    assert_eq!(
        upstream.requests()[0].target,
        "/api/tracker/trackedEntities/EeBJ3Sn9uLg"
    );
}

#[tokio::test]
async fn a_missing_record_is_the_record_not_available_problem() {
    let upstream = UpstreamDouble::start();
    let (status, body) = capture("get-missing");
    upstream.respond_with(vec![Response::json(status, &body)]);
    let served = start(&upstream).await;
    let token = served.token("records.read");

    let (status, head, body) =
        served.get("/v1/collections/persons/records/TV7SRzsjKQi", Some(&token));

    assert_eq!(status, 404, "{body}");
    contract::assert_problem(&body, 404, "record-not-available");
    assert_eq!(
        header(&head, "content-type"),
        Some("application/problem+json")
    );
    assert_eq!(header(&head, "cache-control"), Some("no-store"));
}

#[tokio::test]
async fn an_unknown_collection_is_the_collection_not_available_problem() {
    let upstream = UpstreamDouble::start();
    let served = start(&upstream).await;
    let token = served.token("records.read");

    for path in [
        "/v1/collections/animals/records/EeBJ3Sn9uLg",
        "/v1/collections/animals/records",
    ] {
        let (status, _, body) = served.get(path, Some(&token));
        assert_eq!(status, 404, "{path}: {body}");
        contract::assert_problem(&body, 404, "collection-not-available");
    }
    let (status, _, body) = served.post(
        "/v1/collections/animals/lookup",
        Some(&token),
        &json!({"selector": "byRecordId", "values": {"recordId": "x"}}),
    );
    assert_eq!(status, 404, "{body}");
    contract::assert_problem(&body, 404, "collection-not-available");
    assert_eq!(upstream.request_count(), 0);
}

#[tokio::test]
async fn an_unauthenticated_or_unscoped_call_is_refused_with_its_problem() {
    let upstream = UpstreamDouble::start();
    let served = start(&upstream).await;

    let (status, head, body) = served.get(GET_PATH, None);
    assert_eq!(status, 401, "{body}");
    contract::assert_problem(&body, 401, "unauthorized");
    assert_eq!(header(&head, "cache-control"), Some("no-store"));

    let unscoped = served.token("records.write");
    let (status, _, body) = served.get(GET_PATH, Some(&unscoped));
    assert_eq!(status, 403, "{body}");
    contract::assert_problem(&body, 403, "forbidden");
    let (status, _, body) = served.post(
        SEARCH_PATH,
        Some(&unscoped),
        &json!({"search": "byCriteria", "criteria": {"org_unit": "slSrf7H9lMf"}}),
    );
    assert_eq!(status, 403, "{body}");
    contract::assert_problem(&body, 403, "forbidden");
    assert_eq!(upstream.request_count(), 0);
}

#[tokio::test]
async fn a_list_page_carries_items_and_a_sealed_cursor_and_the_default_page_size() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![page_of(1, 3806)]);
    let served = start(&upstream).await;
    let token = served.token("records.read");

    let (status, _, body) = served.get(LIST_PATH, Some(&token));

    assert_eq!(status, 200, "{body}");
    contract::assert_page(&body);
    assert_eq!(body["items"].as_array().map(Vec::len), Some(5));
    assert_eq!(body["items"][0]["recordId"], "EeBJ3Sn9uLg");
    let cursor = body["pageInfo"]["nextCursor"].as_str().expect("a cursor");
    assert!(cursor.len() <= 4096, "the cursor fits the contract's bound");
    assert!(
        cursor
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "the cursor is URL-safe text: {cursor}"
    );
    let target = &upstream.requests()[0].target;
    assert!(
        target.contains("pageSize=20"),
        "the profile default: {target}"
    );
}

#[tokio::test]
async fn the_cursor_resumes_at_the_same_page_size_and_the_last_page_ends_with_null() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![page_of(1, 2), page_of(2, 2)]);
    let served = start(&upstream).await;
    let token = served.token("records.read");

    let (_, _, first) = served.get(&format!("{LIST_PATH}?pageSize=5"), Some(&token));
    let cursor = first["pageInfo"]["nextCursor"].as_str().expect("a cursor");

    // A resumed call may omit the page size (the cursor carries it) or repeat it.
    let (status, _, second) = served.get(&format!("{LIST_PATH}?cursor={cursor}"), Some(&token));
    assert_eq!(status, 200, "{second}");
    contract::assert_page(&second);
    assert_eq!(second["pageInfo"], json!({"nextCursor": null}));
    let requests = upstream.requests();
    assert!(
        requests[1].target.contains("page=2&"),
        "{}",
        requests[1].target
    );
    assert!(
        requests[1].target.contains("pageSize=5"),
        "{}",
        requests[1].target
    );
}

#[tokio::test]
async fn a_cursor_refuses_a_different_page_size_and_a_forged_text() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![page_of(1, 9)]);
    let served = start(&upstream).await;
    let token = served.token("records.read");
    let (_, _, first) = served.get(&format!("{LIST_PATH}?pageSize=5"), Some(&token));
    let cursor = first["pageInfo"]["nextCursor"].as_str().expect("a cursor");

    let (status, _, body) = served.get(
        &format!("{LIST_PATH}?pageSize=6&cursor={cursor}"),
        Some(&token),
    );
    assert_eq!(status, 400, "{body}");
    contract::assert_problem(&body, 400, "invalid-cursor");

    let (status, _, body) = served.get(&format!("{LIST_PATH}?cursor=forged"), Some(&token));
    assert_eq!(status, 400, "{body}");
    contract::assert_problem(&body, 400, "invalid-cursor");
    assert_eq!(
        upstream.request_count(),
        1,
        "neither refusal reached the upstream"
    );
}

#[tokio::test]
async fn a_default_page_size_cursor_resumes_without_a_size() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![page_of(1, 9), page_of(2, 9)]);
    let served = start(&upstream).await;
    let token = served.token("records.read");
    let (_, _, first) = served.get(LIST_PATH, Some(&token));
    let cursor = first["pageInfo"]["nextCursor"].as_str().expect("a cursor");

    let (status, _, second) = served.get(&format!("{LIST_PATH}?cursor={cursor}"), Some(&token));
    assert_eq!(status, 200, "{second}");
    assert!(upstream.requests()[1].target.contains("pageSize=20"));
    // The size the cursor carries is the default, so repeating it is the same size.
    let (status, _, _) = served.get(
        &format!("{LIST_PATH}?pageSize=20&cursor={cursor}"),
        Some(&token),
    );
    assert_ne!(status, 400, "the cursor's size equals the supplied size");
}

#[tokio::test]
async fn a_query_page_size_outside_the_bounds_is_a_bad_request_and_a_body_one_is_an_invalid_field()
{
    let upstream = UpstreamDouble::start();
    let served = start(&upstream).await;
    let token = served.token("records.read");

    for size in ["0", "101", "abc"] {
        let (status, _, body) = served.get(&format!("{LIST_PATH}?pageSize={size}"), Some(&token));
        assert_eq!(status, 400, "{size}: {body}");
        contract::assert_problem(&body, 400, "bad-request");
    }
    let (status, _, body) = served.post(
        SEARCH_PATH,
        Some(&token),
        &json!({"search": "byCriteria", "criteria": {"org_unit": "slSrf7H9lMf"}, "pageSize": 101}),
    );
    assert_eq!(status, 422, "{body}");
    contract::assert_problem(&body, 422, "invalid-field");
    assert_eq!(upstream.request_count(), 0);
}

#[tokio::test]
async fn an_undeclared_or_repeated_query_parameter_is_a_bad_request() {
    let upstream = UpstreamDouble::start();
    let served = start(&upstream).await;
    let token = served.token("records.read");

    for query in ["org_unit=x", "pageSize=5&pageSize=6", "fields=a"] {
        let (status, _, body) = served.get(&format!("{LIST_PATH}?{query}"), Some(&token));
        assert_eq!(status, 400, "{query}: {body}");
        contract::assert_problem(&body, 400, "bad-request");
    }
    assert_eq!(upstream.request_count(), 0);
}

#[tokio::test]
async fn a_lookup_resolves_one_record_by_its_selector() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![found()]);
    let served = start(&upstream).await;
    let token = served.token("records.read");

    let (status, head, body) = served.post(
        LOOKUP_PATH,
        Some(&token),
        &json!({"selector": "byRecordId", "values": {"recordId": "EeBJ3Sn9uLg"}}),
    );

    assert_eq!(status, 200, "{body}");
    contract::assert_record(&body);
    assert_eq!(body["recordId"], "EeBJ3Sn9uLg");
    assert_eq!(header(&head, "cache-control"), Some("no-store"));
    assert_eq!(
        upstream.requests()[0].target,
        "/api/tracker/trackedEntities/EeBJ3Sn9uLg"
    );
}

#[tokio::test]
async fn a_lookup_refuses_what_its_closed_shape_does_not_name() {
    let upstream = UpstreamDouble::start();
    let served = start(&upstream).await;
    let token = served.token("records.read");

    // A selector name the profile does not declare is a field fault.
    let (status, _, body) = served.post(
        LOOKUP_PATH,
        Some(&token),
        &json!({"selector": "byNationalId", "values": {"recordId": "x"}}),
    );
    assert_eq!(status, 422, "{body}");
    contract::assert_problem(&body, 422, "invalid-field");

    // A body that is not the declared shape is a bad request.
    for shape in [
        json!({"selector": "byRecordId"}),
        json!({"selector": "byRecordId", "values": {"recordId": "x", "extra": 1}}),
        json!({"selector": "byRecordId", "values": {"recordId": 7}}),
        json!([1]),
    ] {
        let (status, _, body) = served.post(LOOKUP_PATH, Some(&token), &shape);
        assert_eq!(status, 400, "{shape}: {body}");
        contract::assert_problem(&body, 400, "bad-request");
    }
    let (status, _, body) = served.post(
        LOOKUP_PATH,
        Some(&token),
        &json!({"selector": "byRecordId", "values": {"recordId": ""}}),
    );
    assert_eq!(status, 422, "an empty identifier: {body}");
    assert_eq!(upstream.request_count(), 0);
}

#[tokio::test]
async fn a_search_narrows_to_the_organisation_unit_and_pages() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![page_of(1, 4)]);
    let served = start(&upstream).await;
    let token = served.token("records.read");

    let (status, _, body) = served.post(
        SEARCH_PATH,
        Some(&token),
        &json!({"search": "byCriteria", "criteria": {"org_unit": "slSrf7H9lMf"}, "pageSize": 5}),
    );

    assert_eq!(status, 200, "{body}");
    contract::assert_page(&body);
    assert!(body["pageInfo"]["nextCursor"].is_string());
    let target = &upstream.requests()[0].target;
    assert!(target.contains("orgUnits=slSrf7H9lMf"), "{target}");
    assert!(target.contains("orgUnitMode=SELECTED"), "{target}");
    assert!(target.contains("pageSize=5"), "{target}");
}

#[tokio::test]
async fn a_search_resumes_from_the_cursor_in_its_body() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![page_of(1, 2), page_of(2, 2)]);
    let served = start(&upstream).await;
    let token = served.token("records.read");
    let criteria = json!({"org_unit": "slSrf7H9lMf"});
    let (_, _, first) = served.post(
        SEARCH_PATH,
        Some(&token),
        &json!({"search": "byCriteria", "criteria": criteria, "pageSize": 5}),
    );
    let cursor = first["pageInfo"]["nextCursor"].as_str().expect("a cursor");

    let (status, _, second) = served.post(
        SEARCH_PATH,
        Some(&token),
        &json!({"search": "byCriteria", "criteria": criteria, "cursor": cursor}),
    );
    assert_eq!(status, 200, "{second}");
    assert_eq!(second["pageInfo"], json!({"nextCursor": null}));

    // The cursor is bound to its criteria: other criteria refuse it.
    let (status, _, body) = served.post(
        SEARCH_PATH,
        Some(&token),
        &json!({"search": "byCriteria", "criteria": {"org_unit": "CXQG7JjTr0o"}, "cursor": cursor}),
    );
    assert_eq!(status, 400, "{body}");
    contract::assert_problem(&body, 400, "invalid-cursor");
}

#[tokio::test]
async fn a_search_refuses_undeclared_criteria_and_unknown_searches() {
    let upstream = UpstreamDouble::start();
    let served = start(&upstream).await;
    let token = served.token("records.read");

    // A value the shape names but the filters refuse is a field fault.
    for shape in [
        json!({"search": "byCriteria", "criteria": {"name": "x"}}),
        json!({"search": "byCriteria", "criteria": {"org_unit": 5}}),
        json!({"search": "byName", "criteria": {"org_unit": "x"}}),
    ] {
        let (status, _, body) = served.post(SEARCH_PATH, Some(&token), &shape);
        assert_eq!(status, 422, "{shape}: {body}");
        contract::assert_problem(&body, 422, "invalid-field");
    }
    // A body that is not the declared shape is a bad request.
    for shape in [
        json!({"criteria": {"org_unit": "x"}}),
        json!({"search": "byCriteria", "criteria": {"org_unit": "x"}, "sort": "a"}),
    ] {
        let (status, _, body) = served.post(SEARCH_PATH, Some(&token), &shape);
        assert_eq!(status, 400, "{shape}: {body}");
        contract::assert_problem(&body, 400, "bad-request");
    }
    assert_eq!(upstream.request_count(), 0);
}

#[tokio::test]
async fn a_post_read_refuses_a_wrong_media_type_a_query_string_and_a_large_body() {
    let upstream = UpstreamDouble::start();
    let served = start(&upstream).await;
    let token = served.token("records.read");
    let body = json!({"search": "byCriteria", "criteria": {"org_unit": "x"}}).to_string();

    let (status, _, reply) = served.request(
        "POST",
        SEARCH_PATH,
        Some(&token),
        &[("Content-Type", "text/plain")],
        body.as_bytes(),
    );
    assert_eq!(status, 415, "{reply}");
    contract::assert_problem(&reply, 415, "unsupported-media-type");

    let (status, _, reply) = served.request(
        "POST",
        &format!("{SEARCH_PATH}?pageSize=5"),
        Some(&token),
        &[("Content-Type", "application/json")],
        body.as_bytes(),
    );
    assert_eq!(status, 400, "{reply}");
    contract::assert_problem(&reply, 400, "bad-request");

    let (status, _, reply) = served.request(
        "POST",
        SEARCH_PATH,
        Some(&token),
        &[("Content-Type", "application/json")],
        b"{not json",
    );
    assert_eq!(status, 400, "{reply}");
    contract::assert_problem(&reply, 400, "bad-request");

    let large = format!(
        "{{\"search\":\"byCriteria\",\"criteria\":{{\"org_unit\":\"{}\"}}}}",
        "a".repeat(20_000)
    );
    let (status, _, reply) = served.request(
        "POST",
        SEARCH_PATH,
        Some(&token),
        &[("Content-Type", "application/json")],
        large.as_bytes(),
    );
    assert_eq!(status, 413, "{reply}");
    contract::assert_problem(&reply, 413, "content-too-large");
    assert_eq!(upstream.request_count(), 0);
}

#[tokio::test]
async fn a_method_the_path_does_not_serve_is_405_and_an_unacceptable_accept_is_406() {
    let upstream = UpstreamDouble::start();
    let served = start(&upstream).await;
    let token = served.token("records.read");

    let (status, head, body) = served.request("PUT", GET_PATH, Some(&token), &[], b"");
    assert_eq!(status, 405, "{body}");
    contract::assert_problem(&body, 405, "bad-request");
    assert_eq!(header(&head, "allow"), Some("GET"));
    let (status, head, _) = served.get(SEARCH_PATH, Some(&token));
    assert_eq!(status, 405);
    assert_eq!(header(&head, "allow"), Some("POST"));

    let (status, _, body) = served.request(
        "GET",
        GET_PATH,
        Some(&token),
        &[("Accept", "text/html")],
        b"",
    );
    assert_eq!(status, 406, "{body}");
    contract::assert_problem(&body, 406, "not-acceptable");
    assert_eq!(upstream.request_count(), 0);
}

#[tokio::test]
async fn a_search_body_never_reaches_the_journal_in_the_clear() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![page_of(1, 1)]);
    let served = start(&upstream).await;
    let token = served.token("records.read");
    let marker = "ZmarkerOrgUnitQ";

    let (status, _, body) = served.post(
        SEARCH_PATH,
        Some(&token),
        &json!({"search": "byCriteria", "criteria": {"org_unit": marker}}),
    );
    assert_eq!(status, 200, "{body}");
    let (status, _, _) = served.post(
        LOOKUP_PATH,
        Some(&token),
        &json!({"selector": "byRecordId", "values": {"recordId": marker}}),
    );
    assert_eq!(status, 502, "the one scripted upstream reply is spent");

    let journal = served.journal_text().await;
    assert!(!journal.is_empty(), "the exchanges were journaled");
    assert!(
        !journal.contains(marker),
        "the criteria value is not in the journal"
    );
}

/// The capture's search reply restated as a full page of `rows` entities,
/// each the captured entity under its own identifier.
fn full_page_of(rows: usize) -> Response {
    let document = fixture("search-page");
    let mut body = document["entries"][0]["upstream"][0]["response"]["body"].clone();
    let entity = body["trackedEntities"][0].clone();
    let entities: Vec<_> = (0..rows)
        .map(|row| {
            let mut entity = entity.clone();
            entity["trackedEntity"] = json!(format!("E{row:010}"));
            entity
        })
        .collect();
    body["trackedEntities"] = json!(entities);
    body["pager"]["pageSize"] = json!(rows);
    body["pager"]["pageCount"] = json!(2);
    Response::json(200, &body.to_string())
}

#[tokio::test]
async fn a_page_at_the_declared_maximum_is_shaped_within_the_script_budget() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![full_page_of(100)]);
    let served = start(&upstream).await;
    let token = served.token("records.read");

    let (status, _, body) = served.get(&format!("{LIST_PATH}?pageSize=100"), Some(&token));

    assert_eq!(status, 200, "{body}");
    contract::assert_page(&body);
    assert_eq!(body["items"].as_array().map(Vec::len), Some(100));
}

#[tokio::test]
async fn every_failed_exchange_leaves_one_value_free_warning() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![Response::json(
        500,
        r#"{"message":"UPSTREAM-DETAIL-CANARY"}"#,
    )]);
    let served = start(&upstream).await;
    let token = served.token("records.read");

    let (status, _, _) = served.get(GET_PATH, Some(&token));
    assert_eq!(status, 502);
    let (status, _, _) = served.get(&format!("{LIST_PATH}?pageSize=0"), Some(&token));
    assert_eq!(status, 400);

    let stderr = served.stop_and_read_stderr();
    let warnings: Vec<&str> = stderr
        .lines()
        .filter(|line| line.contains("an exchange failed"))
        .collect();
    assert_eq!(
        warnings.len(),
        2,
        "one warning per failed exchange: {stderr}"
    );
    assert!(warnings[0].contains("WARN"), "{stderr}");
    assert!(warnings[0].contains("\"status\":502"), "{}", warnings[0]);
    assert!(warnings[1].contains("\"status\":400"), "{}", warnings[1]);
    for warning in warnings {
        assert!(warning.contains("\"class\":\""), "{warning}");
        assert!(!warning.contains("UPSTREAM-DETAIL-CANARY"), "{warning}");
        assert!(!warning.contains("EeBJ3Sn9uLg"), "no identifier: {warning}");
    }
}
