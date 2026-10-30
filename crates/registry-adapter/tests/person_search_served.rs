// SPDX-License-Identifier: Apache-2.0

//! The served `records-search` slice, end to end: the built `adapter`
//! binary starts on the dhis2-tracker example, a loopback upstream
//! replays the committed search capture (and pages derived from it), and
//! a facade call comes back as a page with a sealed cursor, the next
//! page, the last page, an empty result, or a refusal before any
//! upstream call. Needs `ADAPTER_TEST_DATABASE_URL`.
#![cfg(feature = "postgres-test")]

#[allow(dead_code)]
#[path = "support/served/mod.rs"]
mod served_harness;

use serde_json::{json, Value};
use served_harness::upstream::{Response, UpstreamDouble};
use served_harness::{expected_basic, fixture, Served};

const FIRST_PAGE_QUERY: &str =
    "order=createdAt%3Adesc&orgUnitMode=ACCESSIBLE&page=1&pageSize=5&program=qyVpUaAYv2A&totalPages=true";

/// The committed capture: its upstream reply and the facade body it
/// expects.
fn search_page() -> (Value, Value) {
    let document = fixture("search-page");
    let entry = &document["entries"][0];
    (
        entry["upstream"][0]["response"]["body"].clone(),
        entry["expected"]["body"].clone(),
    )
}

/// The capture's reply restated as page `page` of `page_count`.
fn page_of(page: u64, page_count: u64) -> Response {
    let (mut body, _) = search_page();
    body["pager"]["page"] = json!(page);
    body["pager"]["pageCount"] = json!(page_count);
    Response::json(200, &body.to_string())
}

fn empty_page() -> Response {
    let (mut body, _) = search_page();
    body["pager"]["page"] = json!(1);
    body["pager"]["pageCount"] = json!(0);
    body["pager"]["total"] = json!(0);
    body["trackedEntities"] = json!([]);
    Response::json(200, &body.to_string())
}

fn cursor_of(body: &Value) -> String {
    body["pageInfo"]["nextCursor"]
        .as_str()
        .expect("a next cursor")
        .to_owned()
}

#[tokio::test]
async fn the_first_page_comes_back_shaped_with_a_sealed_cursor() {
    let upstream = UpstreamDouble::start();
    let (reply, expected) = search_page();
    upstream.respond_with(vec![Response::json(200, &reply.to_string())]);
    let served = Served::start(&upstream.url("")).await;

    let token = served.token("records.read");
    let (status, _, body) = served.get("/v1/records/person?limit=5", Some(&token));

    assert_eq!(status, 200, "{body}");
    assert_eq!(body["items"], expected["items"]);
    assert_eq!(body["meta"], expected["meta"]);
    let cursor = cursor_of(&body);
    assert!(cursor.len() > 20, "the cursor is sealed, not a page number");
    assert_ne!(cursor, "2");

    let requests = upstream.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "GET");
    assert!(
        requests[0]
            .target
            .ends_with(&format!("/api/tracker/trackedEntities?{FIRST_PAGE_QUERY}")),
        "{}",
        requests[0].target
    );
    assert_eq!(
        requests[0].header("authorization"),
        Some(expected_basic().as_str())
    );
    let kinds = served.journal_kinds().await;
    assert!(
        kinds.iter().any(|kind| kind == "exchangeCompleted"),
        "{kinds:?}"
    );
}

#[tokio::test]
async fn the_cursor_asks_the_source_for_the_next_page() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![page_of(1, 3806), page_of(2, 3806)]);
    let served = Served::start(&upstream.url("")).await;
    let token = served.token("records.read");

    let (_, _, first) = served.get("/v1/records/person?limit=5", Some(&token));
    let cursor = cursor_of(&first);
    let (status, _, second) = served.get(
        &format!("/v1/records/person?limit=5&cursor={cursor}"),
        Some(&token),
    );

    assert_eq!(status, 200, "{second}");
    assert_eq!(second["items"].as_array().map(Vec::len), Some(5));
    assert_ne!(cursor_of(&second), cursor);
    let requests = upstream.requests();
    assert_eq!(requests.len(), 2);
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
async fn the_last_page_carries_no_cursor() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![page_of(1, 2), page_of(2, 2)]);
    let served = Served::start(&upstream.url("")).await;
    let token = served.token("records.read");

    let (_, _, first) = served.get("/v1/records/person?limit=5", Some(&token));
    let cursor = cursor_of(&first);
    // Page 2 of 2 is the last page: its reply ends the paging.
    let (status, _, last) = served.get(
        &format!("/v1/records/person?limit=5&cursor={cursor}"),
        Some(&token),
    );
    assert_eq!(status, 200, "{last}");
    assert_eq!(last["items"].as_array().map(Vec::len), Some(5));
    assert_eq!(last["pageInfo"], json!({}));
    assert_eq!(last["meta"]["entityTypeIdentifier"], "person");
}

#[tokio::test]
async fn an_empty_result_is_an_empty_page_without_a_cursor() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![empty_page()]);
    let served = Served::start(&upstream.url("")).await;
    let token = served.token("records.read");

    let (status, _, body) = served.get("/v1/records/person?limit=5", Some(&token));

    assert_eq!(status, 200, "{body}");
    assert_eq!(body["items"], json!([]));
    assert_eq!(body["pageInfo"], json!({}));
}

/// A request the facade refuses answers the profile's facade problem and
/// never reaches the source.
fn assert_refused(outcome: (u16, String, Value), upstream: &UpstreamDouble, calls: usize) {
    let (status, _, body) = outcome;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["code"], "source.facade");
    assert_eq!(upstream.request_count(), calls, "no further upstream call");
}

#[tokio::test]
async fn a_tampered_cursor_is_refused_before_any_upstream_call() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![page_of(1, 3806), page_of(2, 3806)]);
    let served = Served::start(&upstream.url("")).await;
    let token = served.token("records.read");
    let (_, _, first) = served.get("/v1/records/person?limit=5", Some(&token));
    let cursor = cursor_of(&first);

    let mut bytes = cursor.clone().into_bytes();
    let last = bytes.len() - 1;
    bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(bytes).expect("ascii");
    assert_refused(
        served.get(
            &format!("/v1/records/person?limit=5&cursor={tampered}"),
            Some(&token),
        ),
        &upstream,
        1,
    );
    assert_refused(
        served.get(
            "/v1/records/person?limit=5&cursor=not-a-cursor",
            Some(&token),
        ),
        &upstream,
        1,
    );
}

#[tokio::test]
async fn a_cursor_replayed_with_another_page_size_or_caller_is_refused() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![page_of(1, 3806), page_of(2, 3806)]);
    let served = Served::start(&upstream.url("")).await;
    let token = served.token("records.read");
    let (_, _, first) = served.get("/v1/records/person?limit=5", Some(&token));
    let cursor = cursor_of(&first);

    assert_refused(
        served.get(
            &format!("/v1/records/person?limit=6&cursor={cursor}"),
            Some(&token),
        ),
        &upstream,
        1,
    );
    let other = served.token_for("another-caller", "records.read");
    assert_refused(
        served.get(
            &format!("/v1/records/person?limit=5&cursor={cursor}"),
            Some(&other),
        ),
        &upstream,
        1,
    );
    // The same caller and page size still turn the page.
    let (status, _, second) = served.get(
        &format!("/v1/records/person?limit=5&cursor={cursor}"),
        Some(&token),
    );
    assert_eq!(status, 200, "{second}");
}

#[tokio::test]
async fn an_undeclared_or_out_of_bounds_input_is_refused_before_any_upstream_call() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![page_of(1, 3806)]);
    let served = Served::start(&upstream.url("")).await;
    let token = served.token("records.read");

    for path in [
        "/v1/records/person?limit=5&name=Alice",
        "/v1/records/person",
        "/v1/records/person?limit=0",
        "/v1/records/person?limit=1001",
        "/v1/records/person?limit=five",
    ] {
        assert_refused(served.get(path, Some(&token)), &upstream, 0);
    }
}
