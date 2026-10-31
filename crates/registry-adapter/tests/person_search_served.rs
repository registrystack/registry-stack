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
use served_harness::{copy_example_project, expected_basic, fixture, replace_pack_script, Served};

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
    // The fixture records the profile's stand-in text; the deployment's
    // own values replace it.
    let mut meta = expected["meta"].clone();
    meta["registryIdentifier"] = json!("dhis2-tracker-registry");
    meta["datasetIdentifier"] = json!("persons");
    assert_eq!(body["meta"], meta);
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
    assert_eq!(last["meta"]["recordTypeIdentifier"], "person");
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

#[tokio::test]
async fn a_continuation_too_large_to_seal_answers_500_and_journals_a_failure() {
    let upstream = UpstreamDouble::start();
    let (reply, _) = search_page();
    upstream.respond_with(vec![Response::json(200, &reply.to_string())]);
    let directory = tempfile::tempdir().expect("a scratch directory");
    copy_example_project(directory.path());
    replace_pack_script(
        directory.path(),
        "scripts/next-continuation.rhai",
        &format!(
            "fn next_continuation(exchange) {{\n    \"{}\"\n}}\n",
            "x".repeat(3000)
        ),
    );
    let served = Served::start_with_project(&upstream.url(""), directory.path()).await;

    let token = served.token("records.read");
    let (status, _, body) = served.get("/v1/records/person?limit=5", Some(&token));

    assert_eq!(status, 500, "{body}");
    let kinds = served.journal_kinds().await;
    assert!(
        kinds.contains(&"exchangeFailed".to_owned())
            && !kinds.contains(&"exchangeCompleted".to_owned()),
        "{kinds:?}"
    );
}

#[tokio::test]
async fn a_part_value_with_a_quote_a_backslash_and_braces_renders_as_text() {
    let upstream = UpstreamDouble::start();
    let (reply, expected) = search_page();
    upstream.respond_with(vec![Response::json(200, &reply.to_string())]);
    let directory = tempfile::tempdir().expect("a scratch directory");
    copy_example_project(directory.path());
    let project_path = directory.path().join("project.yaml");
    let project = std::fs::read_to_string(&project_path).expect("the project is readable");
    let hostile = r#"civil "registry" \ {{record}}"#;
    let edited = project.replace(
        "registryIdentifier: dhis2-tracker-registry",
        &format!("registryIdentifier: '{hostile}'"),
    );
    assert_ne!(edited, project, "the part is where the test expects it");
    std::fs::write(&project_path, edited).expect("write the project");
    let served = Served::start_with_project(&upstream.url(""), directory.path()).await;

    let token = served.token("records.read");
    let (status, _, body) = served.get("/v1/records/person?limit=5", Some(&token));

    assert_eq!(status, 200, "{body}");
    assert_eq!(body["meta"]["registryIdentifier"], hostile);
    assert_eq!(body["meta"]["datasetIdentifier"], "persons");
    assert_eq!(body["items"], expected["items"]);
}

#[tokio::test]
async fn a_page_larger_than_the_requested_size_is_a_disclosure_violation() {
    let upstream = UpstreamDouble::start();
    let (reply, _) = search_page();
    // The source ignores the requested size and answers its full page.
    upstream.respond_with(vec![Response::json(200, &reply.to_string())]);
    let served = Served::start(&upstream.url("")).await;

    let token = served.token("records.read");
    let (status, _, body) = served.get("/v1/records/person?limit=1", Some(&token));

    assert_eq!(status, 500, "{body}");
    assert!(
        body.get("items").is_none(),
        "no record is disclosed: {body}"
    );
    let kinds = served.journal_kinds().await;
    assert!(
        kinds.contains(&"exchangeFailed".to_owned())
            && !kinds.contains(&"exchangeCompleted".to_owned()),
        "{kinds:?}"
    );
}
