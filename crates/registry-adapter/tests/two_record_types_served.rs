// SPDX-License-Identifier: Apache-2.0

//! One profile operation bound to two record types, served by the built
//! `adapter` binary: the dhis2-tracker example with a second record type
//! bound to `records-get` answers each record type through its own
//! operation, and refuses a record type no binding names only after it
//! authenticates the caller. Needs `ADAPTER_TEST_DATABASE_URL` (the journal
//! is written before every answer); without it every test fails on the
//! spot.
#![cfg(feature = "postgres-test")]

#[allow(dead_code)]
#[path = "support/served/mod.rs"]
mod served_harness;

use serde_json::json;
use served_harness::upstream::{Response, UpstreamDouble};
use served_harness::{capture, copy_example_project, Served};

/// Bind `records-get` to a `household` record type shaped like `person`,
/// over the same route, and let the reader read it.
fn add_household(directory: &std::path::Path) {
    let path = directory.join("project.yaml");
    let text = std::fs::read_to_string(&path).expect("the project is readable");
    let edits = [
        (
            "templatedRoutes:\n",
            "  - name: household\n    fields:\n      - name: org_unit\n        type: string\n        required: true\n      - name: tracked_entity_type\n        type: string\n        required: true\n      - name: created_at\n        type: string\n      - name: updated_at\n        type: string\ntemplatedRoutes:\n",
        ),
        (
            "  - id: person-create\n",
            "  - id: household-get\n    operation: records-get\n    recordType: household\n    route: person-fetch\n    maximumUpstreamCalls: 4\n  - id: person-create\n",
        ),
        (
            "      - records-get\n    recordTypes:\n      - person\n",
            "      - records-get\n    recordTypes:\n      - person\n      - household\n",
        ),
    ];
    let mut edited = text;
    for (from, to) in edits {
        assert_eq!(
            edited.matches(from).count(),
            1,
            "one {from:?} in the project"
        );
        edited = edited.replacen(from, to, 1);
    }
    std::fs::write(&path, edited).expect("write the edited project");
}

#[tokio::test]
async fn each_record_type_of_one_operation_is_answered_by_its_own_binding() {
    let upstream = UpstreamDouble::start();
    let (status, body) = capture("get-found");
    upstream.respond_with(vec![
        Response::json(status, &body),
        Response::json(status, &body),
    ]);
    let directory = tempfile::tempdir().expect("a scratch directory");
    copy_example_project(directory.path());
    add_household(directory.path());
    let served = Served::start_with_project(&upstream.url(""), directory.path()).await;
    let token = served.token("records.read");

    for record_type in ["person", "household"] {
        let (status, _, body) = served.get(
            &format!("/v1/records/{record_type}/EeBJ3Sn9uLg"),
            Some(&token),
        );
        assert_eq!(status, 200, "{record_type}: {body}");
        assert_eq!(body["meta"]["recordTypeIdentifier"], record_type, "{body}");
        assert_eq!(body["data"]["recordIdentifier"], "EeBJ3Sn9uLg", "{body}");
    }
    assert_eq!(upstream.request_count(), 2);
}

#[tokio::test]
async fn a_record_type_no_binding_names_is_refused_after_authentication() {
    let upstream = UpstreamDouble::start();
    let directory = tempfile::tempdir().expect("a scratch directory");
    copy_example_project(directory.path());
    add_household(directory.path());
    let served = Served::start_with_project(&upstream.url(""), directory.path()).await;

    let (status, _, _) = served.get("/v1/records/canary-type/EeBJ3Sn9uLg", None);
    assert_eq!(
        status, 401,
        "an unbound record type still authenticates first"
    );
    let token = served.token("records.read");
    let (status, _, _) = served.get("/v1/records/canary-type/EeBJ3Sn9uLg", Some(&token));
    assert_eq!(status, 404);

    assert_eq!(
        served.journal_details("callRefused").await,
        vec![json!({ "class": "facade.not-found", "status": 404 })],
        "only the verified caller's refusal is journaled"
    );
    assert_eq!(upstream.request_count(), 0);
}
