// SPDX-License-Identifier: Apache-2.0

//! The served facade persists the paired breaker-refusal and fallback events.
#![cfg(feature = "postgres-test")]

#[allow(dead_code)]
#[path = "support/served/mod.rs"]
mod served_harness;

use serde_json::{json, Value};
use served_harness::upstream::{Response, UpstreamDouble};
use served_harness::{copy_example_project, digest_of, Served};

#[allow(
    clippy::disallowed_methods,
    reason = "the test reads a committed example, pack or fixture to build its input; it reads no operator configuration"
)]
fn install_one_call_breaker(directory: &std::path::Path) {
    let pack_path = directory.join("pack.yaml");
    let pack = std::fs::read_to_string(&pack_path).expect("the pack is readable");
    let mut document: Value = serde_norway::from_str(&pack).expect("the pack parses");
    let template = document["routeTemplates"]
        .as_array_mut()
        .expect("route templates")
        .iter_mut()
        .find(|template| template["id"] == "fetch-tracked-entity")
        .expect("fetch template");
    let steps = template["steps"].as_array_mut().expect("route steps");
    let guarded = steps.split_off(3);
    steps.push(json!({
        "circuitBreaker": {
            "failureRateThreshold": 1,
            "slidingWindowCalls": 1,
            "minimumNumberOfCalls": 1,
            "openStateWaitSeconds": 60,
            "maximumHalfOpenCalls": 1,
            "steps": guarded,
            "onFallback": {"steps": [{"setBody": {"constant": {
                "recordIdentifier": "EeBJ3Sn9uLg",
                "domainData": {
                    "tracked_entity_type": "fallback-type",
                    "org_unit": "fallback-unit"
                }
            }}}]}
        }
    }));

    let edited = serde_norway::to_string(&document).expect("serialize the edited pack");
    let project_path = directory.join("project.yaml");
    let project = std::fs::read_to_string(&project_path).expect("the project is readable");
    let old_pin = digest_of(pack.as_bytes());
    assert!(project.contains(&old_pin), "the project pins the pack");
    std::fs::write(&pack_path, &edited).expect("write the edited pack");
    std::fs::write(
        &project_path,
        project.replace(&old_pin, &digest_of(edited.as_bytes())),
    )
    .expect("re-pin the edited pack");
}

#[tokio::test]
async fn an_open_breaker_persists_refusal_then_fallback_through_the_facade() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![Response::json(500, r#"{"status":"ERROR"}"#)]);
    let directory = tempfile::tempdir().expect("a scratch directory");
    copy_example_project(directory.path());
    install_one_call_breaker(directory.path());
    let served = Served::start_with_project(&upstream.url(""), directory.path()).await;
    let token = served.token("records.read");

    for _ in 0..2 {
        let (status, _, body) = served.get("/v1/records/person/EeBJ3Sn9uLg", Some(&token));
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["data"]["domainData"]["org_unit"], "fallback-unit");
    }
    assert_eq!(upstream.request_count(), 1, "the refusal sends nothing");

    let kinds = served.journal_kinds().await;
    assert_eq!(
        kinds
            .iter()
            .filter(|kind| *kind == "breakerFallback")
            .count(),
        2,
        "both the recorded failure and refusal use fallback: {kinds:?}"
    );
    assert_eq!(
        kinds
            .iter()
            .filter(|kind| *kind == "breakerRefused")
            .count(),
        1,
        "the open breaker refusal is journaled: {kinds:?}"
    );
}
