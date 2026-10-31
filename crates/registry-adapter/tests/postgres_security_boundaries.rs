// SPDX-License-Identifier: Apache-2.0

//! Served security negatives from `products/adapter/CONCEPT.md` section
//! 13.7. Every case crosses the real facade router and a disposable
//! PostgreSQL journal; the source remains a loopback synthetic double.
#![cfg(feature = "postgres-test")]

use std::time::{SystemTime, UNIX_EPOCH};

#[allow(dead_code)]
#[path = "support/served/mod.rs"]
mod served_harness;

use serde_json::json;
use served_harness::upstream::{Response, UpstreamDouble};
use served_harness::{copy_example_project, fixture, replace_pack_text, Served};

const RECORD_MARKER: &str = "served-record-canary-451cc7";
const ERROR_MARKER: &str = "served-error-canary-a80e93";
const WRONG_AUDIENCE_MARKER: &str = "served-wrong-audience-canary-713f44";
const SEARCH_PATH: &str = "/v1/collections/persons/search";
const INVALID_CURSOR_PROBLEM: &str =
    "https://govstack.global/problems/digital-registries/invalid-cursor";

/// Every journal column, not only the intentionally small `detail` member.
async fn journal_rows(served: &Served) -> String {
    let (client, connection) = tokio_postgres::connect(&served.database, tokio_postgres::NoTls)
        .await
        .expect("connect the served journal schema");
    tokio::spawn(connection);
    client
        .query(
            "SELECT to_jsonb(e)::text FROM adapter_journal_events AS e \
             ORDER BY occurred_at, event_id",
            &[],
        )
        .await
        .expect("read every journal column")
        .iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>()
        .join("\n")
}

fn assert_no_markers(text: &str, surface: &str) {
    let wire_credential = served_harness::expected_basic();
    for marker in [
        served_harness::PASSWORD,
        wire_credential.as_str(),
        RECORD_MARKER,
        ERROR_MARKER,
        WRONG_AUDIENCE_MARKER,
    ] {
        assert!(
            !text.contains(marker),
            "{marker} leaked into {surface}: {text}"
        );
    }
}

async fn assert_failed_terminal(served: &Served, class: &str, problem_code: &str) -> String {
    let failures = served.journal_details("exchangeFailed").await;
    let terminal = failures.last().expect("a failed terminal journal row");
    assert_eq!(terminal["class"], class, "{terminal}");
    assert_eq!(terminal["problemCode"], problem_code, "{terminal}");
    let rows = journal_rows(served).await;
    assert_no_markers(&rows, "all journal columns");
    rows
}

/// The capture's response restated as a page that has a continuation.
fn first_search_page() -> Response {
    let document = fixture("search-page");
    let mut body = document["entries"][0]["upstream"][0]["response"]["body"].clone();
    body["pager"]["page"] = json!(1);
    body["pager"]["pageCount"] = json!(2);
    Response::json(200, &body.to_string())
}

/// Replace the maintained get send with one source-provided absolute link.
fn project_with_http_uri(link: &str) -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("a scratch project directory");
    copy_example_project(directory.path());
    replace_pack_text(
        directory.path(),
        "            path: /api/tracker/trackedEntities/{{id}}\n            pathParameters:\n              id:\n                header: recordId\n            operation: tracker-export\n",
        &format!(
            "            httpUri:\n              constant: \"{link}\"\n            operation: tracker-export\n"
        ),
    );
    directory
}

#[tokio::test]
async fn expired_and_wrong_audience_tokens_are_refused_before_source_io() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![Response::json(200, r#"{"unexpected":true}"#)]);
    let served = Served::start(&upstream.url("")).await;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the test clock follows the epoch")
        .as_secs();

    let expired = served.token_with(
        "expired-caller",
        "records.read",
        json!({"exp": now.saturating_sub(3_600)}),
    );
    let wrong_audience = served.token_with(
        "wrong-audience-caller",
        "records.read",
        json!({"aud": WRONG_AUDIENCE_MARKER}),
    );
    let rejected_tokens = [expired, wrong_audience];
    for token in &rejected_tokens {
        let (status, _, body) = served.get("/v1/records/person/served-auth-canary", Some(token));
        assert_eq!(status, 401, "{body}");
        assert_no_markers(&body.to_string(), "the authentication problem");
    }

    assert_eq!(upstream.request_count(), 0, "authentication precedes IO");
    assert!(
        journal_rows(&served).await.is_empty(),
        "an unverified caller is logged, not journaled"
    );
    let stderr = served.stop_and_read_stderr();
    assert_no_markers(&stderr, "the child diagnostics");
    for token in rejected_tokens {
        assert!(
            !stderr.contains(&token),
            "a rejected bearer reached the log"
        );
    }
}

#[tokio::test]
async fn a_redirect_is_a_value_free_failed_terminal_and_is_never_followed() {
    let upstream = UpstreamDouble::start();
    let redirect_target = UpstreamDouble::start();
    let location = redirect_target.url(&format!("/forbidden/{RECORD_MARKER}"));
    upstream.respond_with_headers(
        Response::json(302, &json!({"message": ERROR_MARKER}).to_string()),
        vec![("Location".to_owned(), location)],
    );
    let served = Served::start(&upstream.url("")).await;
    let token = served.token("records.read");

    let (status, _, body) =
        served.get(&format!("/v1/records/person/{RECORD_MARKER}"), Some(&token));

    assert_eq!(status, 502, "{body}");
    assert_eq!(body["code"], "source.upstream-error", "{body}");
    assert_no_markers(&body.to_string(), "the redirect problem");
    assert_eq!(
        upstream.request_count(),
        1,
        "the declared source was called"
    );
    assert_eq!(
        redirect_target.request_count(),
        0,
        "the Location target was not called"
    );
    assert_failed_terminal(&served, "upstream.redirect", "source.upstream-error").await;
    let stderr = served.stop_and_read_stderr();
    assert_no_markers(&stderr, "the child diagnostics");
}

#[tokio::test]
async fn off_origin_and_outside_base_links_are_refused_without_any_send() {
    for case in ["off-origin", "outside-base"] {
        let admitted = UpstreamDouble::start();
        let unauthorized = UpstreamDouble::start();
        let admitted_base = admitted.url("/base");
        let link = match case {
            "off-origin" => unauthorized.url(&format!("/base/{RECORD_MARKER}")),
            "outside-base" => admitted.url(&format!("/outside/{RECORD_MARKER}")),
            _ => unreachable!(),
        };
        let directory = project_with_http_uri(&link);
        let served = Served::start_with_project(&admitted_base, directory.path()).await;
        let token = served.token("records.read");

        let (status, _, body) =
            served.get(&format!("/v1/records/person/{RECORD_MARKER}"), Some(&token));

        assert_eq!(status, 500, "{case}: {body}");
        assert_eq!(body["code"], "source.egress", "{case}: {body}");
        assert_no_markers(&body.to_string(), "the egress problem");
        assert_eq!(admitted.request_count(), 0, "{case}: no admitted send");
        assert_eq!(
            unauthorized.request_count(),
            0,
            "{case}: no unauthorized send"
        );
        assert_failed_terminal(&served, "egress.refused", "source.egress").await;
        let stderr = served.stop_and_read_stderr();
        assert_no_markers(&stderr, "the child diagnostics");
    }
}

#[tokio::test]
async fn a_continuation_replayed_with_other_filters_never_runs_the_route() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![first_search_page()]);
    let served = Served::start_with_project(&upstream.url(""), &Served::govstack_project()).await;
    let token = served.token("records.read");
    let original_filter = json!({"org_unit": "slSrf7H9lMf"});
    let (status, _, first) = served.post(
        SEARCH_PATH,
        Some(&token),
        &json!({"search": "byCriteria", "criteria": original_filter, "pageSize": 5}),
    );
    assert_eq!(status, 200, "{first}");
    let cursor = first["pageInfo"]["nextCursor"]
        .as_str()
        .expect("the first page carries a cursor");
    let calls_before = upstream.request_count();
    let sends_before = served
        .journal_kinds()
        .await
        .iter()
        .filter(|kind| kind.as_str() == "exchangeSending")
        .count();

    let (status, _, body) = served.post(
        SEARCH_PATH,
        Some(&token),
        &json!({
            "search": "byCriteria",
            "criteria": {"org_unit": RECORD_MARKER},
            "cursor": cursor
        }),
    );

    assert_eq!(status, 400, "{body}");
    assert!(
        body["type"]
            .as_str()
            .is_some_and(|kind| kind.ends_with("/invalid-cursor")),
        "{body}"
    );
    assert_eq!(upstream.request_count(), calls_before, "no source call");
    let kinds = served.journal_kinds().await;
    assert_eq!(
        kinds
            .iter()
            .filter(|kind| kind.as_str() == "exchangeSending")
            .count(),
        sends_before,
        "cursor verification precedes the route"
    );
    assert_failed_terminal(&served, "facade.invalid-cursor", INVALID_CURSOR_PROBLEM).await;
    let stderr = served.stop_and_read_stderr();
    assert_no_markers(&stderr, "the child diagnostics");
}
