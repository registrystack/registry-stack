// SPDX-License-Identifier: Apache-2.0

//! DHIS2 exact-read error translation through the built-in Consultation host.
//! Needs `ADAPTER_TEST_DATABASE_URL`.
#![cfg(feature = "postgres-test")]

#[allow(dead_code)]
#[path = "support/served/mod.rs"]
mod served_harness;

use serde_json::{json, Value};
use served_harness::upstream::{Response, UpstreamDouble};
use served_harness::{capture, Served};
use std::path::Path;

const PROBLEMS: &str = "https://govstack.global/problems/digital-registries/";
const RECORD_ID: &str = "TV7SRzsjKQi";
const RETRIEVE_PATH: &str = "/v1/collections/people/records/TV7SRzsjKQi";
const LOOKUP_PATH: &str = "/v1/collections/people/lookup";

fn project() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/adapter/examples/dhis2-consultation")
}

fn dhis2_error(status: u16) -> Response {
    Response::json(
        status,
        &json!({
            "httpStatus": if status == 404 { "Not Found" } else { "Synthetic Error" },
            "httpStatusCode": status,
            "status": "ERROR",
            "message": "synthetic upstream detail must not cross the facade"
        })
        .to_string(),
    )
}

fn captured_not_found() -> Response {
    let (status, body) = capture("get-missing");
    Response::json(status, &body)
}

fn assert_problem(body: &Value, status: u64, slug: &str) {
    assert_eq!(body["status"], status, "{body}");
    assert_eq!(body["type"], format!("{PROBLEMS}{slug}"), "{body}");
    assert!(body["title"].is_string(), "{body}");
    assert!(body["traceId"].is_string(), "{body}");
    assert!(
        !body.to_string().contains("synthetic upstream detail"),
        "upstream detail is not disclosed: {body}"
    );
}

#[tokio::test]
async fn dhis2_not_found_is_record_not_available_for_retrieve_and_lookup() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![captured_not_found(), captured_not_found()]);
    let served = Served::start_with_project(&upstream.url(""), &project()).await;
    let token = served.token("records.read");

    let (status, _, body) = served.get(RETRIEVE_PATH, Some(&token));
    assert_eq!(status, 404, "{body}\n{}", served.stderr_text());
    assert_problem(&body, 404, "record-not-available");

    let (status, _, body) = served.post(
        LOOKUP_PATH,
        Some(&token),
        &json!({"selector": "by-record-id", "values": {"record-id": RECORD_ID}}),
    );
    assert_eq!(status, 404, "{body}\n{}", served.stderr_text());
    assert_problem(&body, 404, "record-not-available");

    let requests = upstream.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].target,
        "/api/tracker/trackedEntities/TV7SRzsjKQi"
    );
    assert_eq!(
        requests[1].target,
        "/api/tracker/trackedEntities/TV7SRzsjKQi"
    );
}

#[tokio::test]
async fn dhis2_other_http_errors_remain_bad_gateway() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![dhis2_error(400), dhis2_error(500)]);
    let served = Served::start_with_project(&upstream.url(""), &project()).await;
    let token = served.token("records.read");

    let (status, _, body) = served.get(RETRIEVE_PATH, Some(&token));
    assert_eq!(status, 502, "{body}\n{}", served.stderr_text());
    assert_problem(&body, 502, "bad-gateway");

    let (status, _, body) = served.post(
        LOOKUP_PATH,
        Some(&token),
        &json!({"selector": "by-record-id", "values": {"record-id": RECORD_ID}}),
    );
    assert_eq!(status, 502, "{body}\n{}", served.stderr_text());
    assert_problem(&body, 502, "bad-gateway");

    assert_eq!(upstream.request_count(), 2);
}
