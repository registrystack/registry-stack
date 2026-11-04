// SPDX-License-Identifier: Apache-2.0

//! Source identity validation through the built-in Consultation host.
//! Needs `ADAPTER_TEST_DATABASE_URL`.
#![cfg(feature = "postgres-test")]

#[allow(dead_code)]
#[path = "support/served/mod.rs"]
mod served_harness;

use serde_json::Value;
use served_harness::upstream::{Response, UpstreamDouble};
use served_harness::{fixture, Served};
use std::path::Path;

const LIST_PATH: &str = "/govstack/registries/v1/collections/people-summary/records?pageSize=5";

fn project() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/adapter/examples/dhis2-consultation")
}

fn source_page_with_key(key: &str) -> Value {
    let fixture = fixture("search-page");
    let mut page = fixture["entries"][0]["upstream"][0]["response"]["body"].clone();
    page["trackedEntities"][0]["trackedEntity"] = serde_json::json!(key);
    page
}

async fn assert_malformed_page_key_is_refused(key: &str) {
    let upstream = UpstreamDouble::start();
    let page = source_page_with_key(key);
    upstream.respond_with(vec![Response::json(200, &page.to_string())]);
    let served = Served::start_with_project(&upstream.url(""), &project()).await;
    let token = served.token("records.read");

    let (status, _, body) = served.get(LIST_PATH, Some(&token));

    assert_eq!(
        status,
        502,
        "a malformed source identity is a bad gateway: {body}\n{}",
        served.stderr_text()
    );
    assert_eq!(
        body["type"],
        "https://govstack.global/problems/digital-registries/bad-gateway"
    );
    assert_eq!(body["status"], 502);
    if !key.is_empty() {
        assert!(
            !body.to_string().contains(key),
            "source identity leaked: {body}"
        );
        assert!(
            !served.stderr_text().contains(key),
            "source identity leaked to logs"
        );
        assert!(
            !served.journal_text().await.contains(key),
            "source identity leaked to the journal"
        );
    }
    assert_eq!(upstream.request_count(), 1);
}

#[tokio::test]
async fn an_empty_page_key_is_refused_before_the_summary_projection_is_wrapped() {
    assert_malformed_page_key_is_refused("").await;
}

#[tokio::test]
async fn a_page_key_over_the_public_record_id_bound_is_refused_before_wrapping() {
    assert_malformed_page_key_is_refused(&"K".repeat(257)).await;
}
