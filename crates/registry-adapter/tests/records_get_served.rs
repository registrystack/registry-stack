// SPDX-License-Identifier: Apache-2.0

//! The served `records-get` slice, end to end: the built `adapter` binary
//! starts on the dhis2-tracker example with a runtime config, a loopback
//! upstream replays the committed captures, and a facade call comes back
//! shaped, as the not-found problem, or refused before any upstream
//! call. Needs `ADAPTER_TEST_DATABASE_URL` (the journal is written before
//! every answer); without it every test fails on the spot.
#![cfg(feature = "postgres-test")]

#[allow(dead_code)]
#[path = "support/served/mod.rs"]
mod served_harness;

use serde_json::json;
use served_harness::upstream::{Response, UpstreamDouble};
use served_harness::{capture, expected_basic, Served};

#[tokio::test]
async fn a_found_record_comes_back_shaped_through_the_served_binary() {
    let upstream = UpstreamDouble::start();
    let (status, body) = capture("get-found");
    upstream.respond_with(vec![Response::json(status, &body)]);
    let served = Served::start(&upstream.url("")).await;

    let token = served.token("records.read");
    let (status, _, body) = served.get("/v1/records/person/EeBJ3Sn9uLg", Some(&token));

    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body,
        json!({
            "data": {
                "tracked_entity_type": "cQWYtUfH6Vx",
                "org_unit": "slSrf7H9lMf",
                "created_at": "2017-01-20T10:44:02.770",
                "updated_at": "2017-05-26T11:46:22.372"
            },
            "meta": {
                "registryIdentifier": "registryIdentifier",
                "datasetIdentifier": "datasetIdentifier",
                "entityTypeIdentifier": "person"
            }
        })
    );
    let requests = upstream.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(
        requests[0].target,
        "/api/tracker/trackedEntities/EeBJ3Sn9uLg"
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
async fn a_missing_record_is_the_not_found_problem() {
    let upstream = UpstreamDouble::start();
    let (status, body) = capture("get-missing");
    upstream.respond_with(vec![Response::json(status, &body)]);
    let served = Served::start(&upstream.url("")).await;

    let token = served.token("records.read");
    let (status, _, body) = served.get("/v1/records/person/TV7SRzsjKQi", Some(&token));

    assert_eq!(status, 404, "{body}");
    assert_eq!(body["code"], "source.not-found");
    assert_eq!(body["status"], 404);
    assert_eq!(
        body["detail"],
        "No tracked entity with that identifier exists at the source."
    );
    assert_eq!(upstream.request_count(), 1);
}

#[tokio::test]
async fn a_request_without_a_valid_token_is_refused_before_any_upstream_call() {
    let upstream = UpstreamDouble::start();
    let (status, body) = capture("get-found");
    upstream.respond_with(vec![Response::json(status, &body)]);
    let served = Served::start(&upstream.url("")).await;

    let (status, head, body) = served.get("/v1/records/person/EeBJ3Sn9uLg", None);
    assert_eq!(status, 401, "{body}");
    assert!(head
        .to_ascii_lowercase()
        .contains("www-authenticate: bearer"));

    let (status, _, _) = served.get("/v1/records/person/EeBJ3Sn9uLg", Some("not.a.token"));
    assert_eq!(status, 401);

    let forged = Served::forged_token();
    let (status, _, _) = served.get("/v1/records/person/EeBJ3Sn9uLg", Some(&forged));
    assert_eq!(status, 401);

    let unscoped = served.token("records.write");
    let (status, _, body) = served.get("/v1/records/person/EeBJ3Sn9uLg", Some(&unscoped));
    assert_eq!(status, 403, "{body}");

    assert_eq!(
        upstream.request_count(),
        0,
        "no refused call reached the upstream"
    );
}

#[tokio::test]
async fn a_dot_segment_record_identifier_never_reaches_the_upstream() {
    let upstream = UpstreamDouble::start();
    let (status, body) = capture("get-found");
    upstream.respond_with(vec![Response::json(status, &body)]);
    let served = Served::start(&upstream.url("")).await;
    let token = served.token("records.read");

    for spelling in ["..", "%2E%2E", "%2e%2e", ".", "%2E", ".%2e"] {
        let (status, _, body) = served.get(&format!("/v1/records/person/{spelling}"), Some(&token));
        assert_eq!(status, 400, "{spelling}: {body}");
        assert_eq!(body["code"], "facade.invalid-request", "{spelling}");
    }
    assert_eq!(
        upstream.request_count(),
        0,
        "no dot segment was sent upstream"
    );
}
