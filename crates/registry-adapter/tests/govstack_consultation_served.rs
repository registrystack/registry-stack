// SPDX-License-Identifier: Apache-2.0

//! The GovStack Consultation facade, end to end: the built `adapter` binary
//! serves the dhis2-consultation example (the built-in GovStack Consultation
//! facade over the dhis2-tracker pack) against a loopback upstream that replays the
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
const GET_PATH: &str = "/govstack/registries/v1/collections/people/records/EeBJ3Sn9uLg";
const LIST_PATH: &str = "/govstack/registries/v1/collections/people/records";
const LOOKUP_PATH: &str = "/govstack/registries/v1/collections/people/lookup";
const SEARCH_PATH: &str = "/govstack/registries/v1/collections/people/search";

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
            object.keys().all(
                |key| ["type", "title", "status", "detail", "traceId", "errors"]
                    .contains(&key.as_str())
            ),
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
                "source": {"id": "EeBJ3Sn9uLg", "type": "cQWYtUfH6Vx"},
                "registration": {
                    "organisationUnit": "slSrf7H9lMf",
                    "createdAt": "2017-01-20T10:44:02.770",
                    "updatedAt": "2017-05-26T11:46:22.372"
                }
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

    let (status, head, body) = served.get(
        "/govstack/registries/v1/collections/people/records/TV7SRzsjKQi",
        Some(&token),
    );

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
        "/govstack/registries/v1/collections/animals/records/EeBJ3Sn9uLg",
        "/govstack/registries/v1/collections/animals/records",
    ] {
        let (status, _, body) = served.get(path, Some(&token));
        assert_eq!(status, 404, "{path}: {body}");
        contract::assert_problem(&body, 404, "collection-not-available");
    }
    let (status, _, body) = served.post(
        "/govstack/registries/v1/collections/animals/lookup",
        Some(&token),
        &json!({"selector": "by-record-id", "values": {"record-id": "x"}}),
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
        &json!({"search": "by-org-unit", "criteria": {"org-unit": "slSrf7H9lMf"}}),
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
async fn a_cursor_is_bound_to_its_client_and_survives_a_refreshed_token() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![page_of(1, 9), page_of(2, 9)]);
    let served = start(&upstream).await;
    let token = served.token("records.read");
    let (_, _, first) = served.get(&format!("{LIST_PATH}?pageSize=5"), Some(&token));
    let cursor = first["pageInfo"]["nextCursor"].as_str().expect("a cursor");

    // The same person acting through another admitted client is refused
    // with the problem any other binding mismatch gets, naming nothing.
    let other_client = served.token_with(
        served_harness::SUBJECT,
        "records.read",
        json!({"client_id": served_harness::SECOND_CLIENT}),
    );
    let (status, _, body) =
        served.get(&format!("{LIST_PATH}?cursor={cursor}"), Some(&other_client));
    assert_eq!(status, 400, "{body}");
    contract::assert_problem(&body, 400, "invalid-cursor");
    let (_, _, forged) = served.get(&format!("{LIST_PATH}?cursor=forged"), Some(&token));
    assert_eq!(body["title"], forged["title"]);
    assert_eq!(body.get("detail"), forged.get("detail"));
    assert_eq!(
        upstream.request_count(),
        1,
        "the refusal reached no upstream"
    );

    // A refreshed token for the same subject and client continues.
    let refreshed = served.token("records.read");
    assert_ne!(refreshed, token);
    let (status, _, second) = served.get(&format!("{LIST_PATH}?cursor={cursor}"), Some(&refreshed));
    assert_eq!(status, 200, "{second}");
    contract::assert_page(&second);
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
async fn a_page_size_outside_the_bounds_is_a_bad_request_from_the_query_or_the_body() {
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
        &json!({"search": "by-org-unit", "criteria": {"org-unit": "slSrf7H9lMf"}, "pageSize": 101}),
    );
    assert_eq!(status, 400, "{body}");
    contract::assert_problem(&body, 400, "bad-request");
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
        &json!({"selector": "by-record-id", "values": {"record-id": "EeBJ3Sn9uLg"}}),
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
        &json!({"selector": "by-national-id", "values": {"record-id": "x"}}),
    );
    assert_eq!(status, 422, "{body}");
    contract::assert_problem(&body, 422, "invalid-content");
    // The pointer names the refused member: the selector, not the values.
    assert_eq!(
        body["errors"],
        json!([{"pointer": "/selector", "message": body["errors"][0]["message"]}]),
        "{body}"
    );

    // Values that break the selector's closed schema are field faults.
    for shape in [
        json!({"selector": "by-record-id", "values": {"record-id": "x", "extra": 1}}),
        json!({"selector": "by-record-id", "values": {"record-id": 7}}),
    ] {
        let (status, _, body) = served.post(LOOKUP_PATH, Some(&token), &shape);
        assert_eq!(status, 422, "{shape}: {body}");
        contract::assert_problem(&body, 422, "invalid-content");
        assert_eq!(body["errors"][0]["pointer"], "/values", "{shape}: {body}");
    }

    // A body that is not the declared shape is a bad request.
    for shape in [json!({"selector": "by-record-id"}), json!([1])] {
        let (status, _, body) = served.post(LOOKUP_PATH, Some(&token), &shape);
        assert_eq!(status, 400, "{shape}: {body}");
        contract::assert_problem(&body, 400, "bad-request");
    }
    let (status, _, body) = served.post(
        LOOKUP_PATH,
        Some(&token),
        &json!({"selector": "by-record-id", "values": {"record-id": ""}}),
    );
    assert_eq!(status, 422, "an empty identifier: {body}");
    assert_eq!(upstream.request_count(), 0);
}

#[tokio::test]
async fn a_lookup_identifier_over_the_schema_bound_is_invalid_before_any_send() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![found()]);
    let served = start(&upstream).await;
    let token = served.token("records.read");

    // 2,100 ASCII bytes, and 700 bytes of non-ASCII that triple when encoded.
    for long in ["a".repeat(2_100), "\u{e9}".repeat(350)] {
        let (status, _, body) = served.post(
            LOOKUP_PATH,
            Some(&token),
            &json!({"selector": "by-record-id", "values": {"record-id": long}}),
        );
        assert_eq!(status, 422, "{body}");
        contract::assert_problem(&body, 422, "invalid-content");
    }
    assert_eq!(upstream.request_count(), 0);
    let kinds = served.journal_kinds().await;
    assert!(
        kinds.iter().all(|kind| kind != "exchangeSending"),
        "nothing was sent: {kinds:?}"
    );
}

#[tokio::test]
async fn a_retrieve_identifier_too_long_for_the_destination_url_is_not_found_before_any_send() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![found()]);
    let served = start(&upstream).await;
    let token = served.token("records.read");

    for long in ["a".repeat(2_100), "%C3%A9".repeat(350)] {
        let (status, _, body) = served.get(
            &format!("/govstack/registries/v1/collections/people/records/{long}"),
            Some(&token),
        );
        assert_eq!(status, 404, "{body}");
        contract::assert_problem(&body, 404, "record-not-available");
    }
    assert_eq!(upstream.request_count(), 0);
    let kinds = served.journal_kinds().await;
    assert!(
        kinds.iter().all(|kind| kind != "exchangeSending"),
        "nothing was sent: {kinds:?}"
    );
}

#[tokio::test]
async fn a_retrieve_identifier_that_cannot_be_one_path_segment_is_not_found_before_any_upstream_call(
) {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![found()]);
    let served = start(&upstream).await;
    let token = served.token("records.read");

    // The spellings are as a caller writes them; the router decodes each once.
    for spelling in [
        ".",
        "..",
        "%2E%2E",
        "a%2Fb",
        "a%5Cb",
        "a%3Fb",
        "a%3Bb",
        "a%3Ab",
        "a%01b",
        "a%25b",
        "a%E2%80%8Bb",
    ] {
        let (status, _, body) = served.get(&format!("{LIST_PATH}/{spelling}"), Some(&token));
        assert_eq!(status, 404, "{spelling}: {body}");
        contract::assert_problem(&body, 404, "record-not-available");
    }
    assert_eq!(upstream.request_count(), 0);
}

#[tokio::test]
async fn a_lookup_identifier_that_cannot_be_one_path_segment_is_not_found_before_any_upstream_call()
{
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![found()]);
    let served = start(&upstream).await;
    let token = served.token("records.read");

    for identifier in [".", "..", "a/b", "a\\b", "a?b", "a\u{1}b"] {
        let (status, _, body) = served.post(
            LOOKUP_PATH,
            Some(&token),
            &json!({"selector": "by-record-id", "values": {"record-id": identifier}}),
        );
        assert_eq!(status, 404, "{identifier:?}: {body}");
        contract::assert_problem(&body, 404, "record-not-available");
    }
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
        &json!({"search": "by-org-unit", "criteria": {"org-unit": "slSrf7H9lMf"}, "pageSize": 5}),
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
    let criteria = json!({"org-unit": "slSrf7H9lMf"});
    let (_, _, first) = served.post(
        SEARCH_PATH,
        Some(&token),
        &json!({"search": "by-org-unit", "criteria": criteria, "pageSize": 5}),
    );
    let cursor = first["pageInfo"]["nextCursor"].as_str().expect("a cursor");

    let (status, _, second) = served.post(
        SEARCH_PATH,
        Some(&token),
        &json!({"search": "by-org-unit", "criteria": criteria, "cursor": cursor}),
    );
    assert_eq!(status, 200, "{second}");
    assert_eq!(second["pageInfo"], json!({"nextCursor": null}));

    // The cursor is bound to its criteria: other criteria refuse it.
    let (status, _, body) = served.post(
        SEARCH_PATH,
        Some(&token),
        &json!({"search": "by-org-unit", "criteria": {"org-unit": "CXQG7JjTr0o"}, "cursor": cursor}),
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
    for (shape, pointer) in [
        (
            json!({"search": "by-org-unit", "criteria": {"name": "x"}}),
            "/criteria",
        ),
        (
            json!({"search": "by-org-unit", "criteria": {"org-unit": 5}}),
            "/criteria",
        ),
        (
            json!({"search": "by-name", "criteria": {"org-unit": "x"}}),
            "/search",
        ),
    ] {
        let (status, _, body) = served.post(SEARCH_PATH, Some(&token), &shape);
        assert_eq!(status, 422, "{shape}: {body}");
        contract::assert_problem(&body, 422, "invalid-content");
        assert_eq!(body["errors"][0]["pointer"], pointer, "{shape}: {body}");
    }

    // The 422 names where the fault is as a JSON pointer, never the value.
    let (status, _, body) = served.post(
        SEARCH_PATH,
        Some(&token),
        &json!({"search": "by-org-unit", "criteria": {"unknown-field": "SUBMITTED-VALUE-CANARY"}}),
    );
    assert_eq!(status, 422, "{body}");
    contract::assert_problem(&body, 422, "invalid-content");
    assert!(
        body["errors"][0]["pointer"]
            .as_str()
            .is_some_and(|pointer| pointer.starts_with('/')),
        "a JSON pointer: {body}"
    );
    assert!(
        !body.to_string().contains("SUBMITTED-VALUE-CANARY"),
        "the submitted value is not echoed: {body}"
    );
    // A body that is not the declared shape is a bad request.
    for shape in [
        json!({"criteria": {"org-unit": "x"}}),
        json!({"search": "by-org-unit", "criteria": {"org-unit": "x"}, "sort": "a"}),
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
    let body = json!({"search": "by-org-unit", "criteria": {"org-unit": "x"}}).to_string();

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
        "{{\"search\":\"by-org-unit\",\"criteria\":{{\"org-unit\":\"{}\"}}}}",
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
        &json!({"search": "by-org-unit", "criteria": {"org-unit": marker}}),
    );
    assert_eq!(status, 200, "{body}");
    let (status, _, _) = served.post(
        LOOKUP_PATH,
        Some(&token),
        &json!({"selector": "by-record-id", "values": {"record-id": marker}}),
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

#[tokio::test]
async fn a_search_without_its_declared_filter_is_an_invalid_field_before_any_call() {
    let upstream = UpstreamDouble::start();
    let served = start(&upstream).await;
    let token = served.token("records.read");

    let (status, _, body) = served.post(
        SEARCH_PATH,
        Some(&token),
        &json!({"search": "by-org-unit", "criteria": {}}),
    );

    assert_eq!(status, 422, "{body}");
    contract::assert_problem(&body, 422, "invalid-content");
    assert_eq!(upstream.request_count(), 0);
}

/// The upstream request targets a call sent since `before` requests.
fn targets_since(upstream: &UpstreamDouble, before: usize) -> Vec<String> {
    upstream
        .requests()
        .iter()
        .skip(before)
        .map(|request| request.target.clone())
        .collect()
}

#[tokio::test]
async fn hostile_filter_values_arrive_as_one_encoded_value_each() {
    let upstream = UpstreamDouble::start();
    let served = start(&upstream).await;
    let token = served.token("records.read");

    for value in [
        "x&orgUnitMode=ALL",
        "a\"b",
        "a\\b",
        "a\nb",
        "a\r\nX: y",
        "a/b",
        "../b",
        "a%2Fb",
        "a;b,c",
        "{{recordId}}",
        "{{??x}}",
    ] {
        upstream.respond_with(vec![page_of(1, 1)]);
        let before = upstream.request_count();

        let (status, _, body) = served.post(
            SEARCH_PATH,
            Some(&token),
            &json!({"search": "by-org-unit", "criteria": {"org-unit": value}}),
        );

        assert_eq!(status, 200, "{value:?}: {body}");
        let targets = targets_since(&upstream, before);
        assert_eq!(targets.len(), 1, "{value:?}: {targets:?}");
        let (path, query) = targets[0].split_once('?').expect("a query");
        assert_eq!(path, "/api/tracker/trackedEntities", "{value:?}");
        let pairs: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        let named = |name: &str| -> Vec<&str> {
            pairs
                .iter()
                .filter(|(key, _)| key == name)
                .map(|(_, text)| text.as_str())
                .collect()
        };
        assert_eq!(named("orgUnits"), vec![value], "one value, intact: {query}");
        assert_eq!(named("orgUnitMode"), vec!["SELECTED"], "{value:?}: {query}");
        assert!(!query.contains('\n') && !query.contains('\r'), "{query}");
    }
}

#[tokio::test]
async fn hostile_lookup_values_are_encoded_into_one_path_segment_or_refused() {
    let upstream = UpstreamDouble::start();
    let served = start(&upstream).await;
    let token = served.token("records.read");

    for (value, encoded) in [
        ("a\"b", "a%22b"),
        ("x&orgUnitMode=ALL", "x%26orgUnitMode%3DALL"),
        ("{{recordId}}", "%7B%7BrecordId%7D%7D"),
        ("a b", "a%20b"),
    ] {
        let (status, entity) = capture("get-found");
        let mut entity: serde_json::Value =
            serde_json::from_str(&entity).expect("the capture is JSON");
        entity["trackedEntity"] = json!(value);
        upstream.respond_with(vec![Response::json(status, &entity.to_string())]);
        let before = upstream.request_count();
        let (status, _, body) = served.post(
            LOOKUP_PATH,
            Some(&token),
            &json!({"selector": "by-record-id", "values": {"record-id": value}}),
        );
        assert_eq!(status, 200, "{value:?}: {body}");
        assert_eq!(
            targets_since(&upstream, before),
            vec![format!("/api/tracker/trackedEntities/{encoded}")],
            "{value:?}"
        );
    }

    // A value that would not stay in one path segment, or that no header
    // can carry, is refused before the source is called.
    for value in ["a/b", "a\\b", "a\nb", "a\r\nX: y", "a;b,c", "a%2Fb", ".."] {
        upstream.respond_with(vec![found()]);
        let before = upstream.request_count();
        let (status, _, body) = served.post(
            LOOKUP_PATH,
            Some(&token),
            &json!({"selector": "by-record-id", "values": {"record-id": value}}),
        );
        assert!(status >= 400, "{value:?}: {status} {body}");
        assert!(
            targets_since(&upstream, before).is_empty(),
            "{value:?} reached the source"
        );
    }
}

#[tokio::test]
async fn a_source_refusal_of_the_criteria_is_a_bad_gateway() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![Response::json(
        400,
        r#"{"httpStatus":"Bad Request","httpStatusCode":400,"status":"ERROR","message":"Org unit mode requires org units"}"#,
    )]);
    let served = start(&upstream).await;
    let token = served.token("records.read");

    let (status, _, body) = served.post(
        SEARCH_PATH,
        Some(&token),
        &json!({"search": "by-org-unit", "criteria": {"org-unit": "x&orgUnitMode=ALL"}}),
    );

    assert_eq!(status, 502, "{body}");
    contract::assert_problem(&body, 502, "bad-gateway");
    let target = &upstream.requests()[0].target;
    assert!(
        target.contains("orgUnits=x%26orgUnitMode%3DALL&")
            && target.contains("orgUnitMode=SELECTED"),
        "{target}"
    );
}

#[tokio::test]
async fn an_unauthenticated_post_declaring_an_oversize_body_is_refused_without_reading_it() {
    let upstream = UpstreamDouble::start();
    let served = start(&upstream).await;
    let declared = 64 * 1024 * 1024;
    let sent = b"{\"search\":\"by-org-unit\"";

    // The request promises 64 MiB and sends 23 bytes. An answer arrives
    // anyway: the refusal does not wait for, or buffer, the body.
    let (status, _, body) = served.request_declaring(
        "POST",
        SEARCH_PATH,
        None,
        &[("content-type", "application/json")],
        declared,
        sent,
    );

    assert_eq!(status, 401, "{body}");
    contract::assert_problem(&body, 401, "unauthorized");
    assert_eq!(upstream.request_count(), 0);
}

#[tokio::test]
async fn a_path_parameter_that_is_not_utf8_is_a_bad_request_problem() {
    let upstream = UpstreamDouble::start();
    let served = start(&upstream).await;
    let token = served.token("records.read");

    for path in [
        "/govstack/registries/v1/collections/people/records/%ff",
        "/govstack/registries/v1/collections/%ff/records",
    ] {
        let (status, head, body) = served.get(path, Some(&token));

        assert_eq!(status, 400, "{path}: {body}");
        contract::assert_problem(&body, 400, "bad-request");
        assert_eq!(
            header(&head, "content-type"),
            Some("application/problem+json"),
            "{path}"
        );
        assert_eq!(header(&head, "cache-control"), Some("no-store"), "{path}");
    }
    assert_eq!(upstream.request_count(), 0);
}
