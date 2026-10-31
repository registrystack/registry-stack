// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "breg")]
//! Mock boundary tests for the BReg connector's read family (N1) and
//! direct mutation family (N2): prepared bytes, sends, exact-same-key
//! recovery, refusal surfacing, and authority gating, all against a
//! scripted in-process BReg. The tests run on the multi-thread flavor so
//! the scripted service keeps serving while a connector call blocks its
//! caller.

#[path = "support/mod.rs"]
mod support;

use axum::http::StatusCode;
use registry_adapter_connectors::breg::problems;
use registry_adapter_connectors::breg::read::Lookup;
use registry_adapter_connectors::operation::{
    CommandKey, ConnectorFault, Observable, Operation, OutcomeCategory, PreparedAttempt,
};
use registry_breg_client::{BRegListRequest, BRegLookupRequest, BRegProblemCode};
use serde_json::{json, Value};

use support::{
    created_record, mutated_record, problem, record_body, Mock, RECORD_ID, SERVER_ETAG, TOKEN,
};

fn key(step: &str) -> CommandKey {
    CommandKey::new(format!("adapter-unit/company/{step}")).expect("derived key")
}

fn link_header() -> (&'static str, &'static str) {
    (
        "link",
        "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </tenant/prefix/v1/schemas/company>; rel=\"describedby\"",
    )
}

fn single_record() -> support::MockResponse {
    support::MockResponse::json(StatusCode::OK, record_body())
        .with_header("etag", SERVER_ETAG)
        .with_header(link_header().0, link_header().1)
        .with_header("cache-control", "no-store")
        .with_header("vary", "authorization, accept")
}

#[tokio::test(flavor = "multi_thread")]
async fn catalog_advertises_exactly_the_bound_families() {
    let mock = Mock::start("immediate", false).await;
    let names: Vec<&str> = mock
        .connector
        .catalog()
        .iter()
        .map(|descriptor| descriptor.name)
        .collect();
    assert_eq!(
        names,
        vec![
            "breg.record.create",
            "breg.record.patch",
            "breg.action.invoke",
            "breg.batch.records",
            "breg.ingestion.create-run",
            "breg.ingestion.submit-chunk",
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn tombstone_stays_absent_until_the_host_opens_it() {
    let opened = Mock::start("immediate", true).await;
    let names: Vec<&str> = opened
        .connector
        .catalog()
        .iter()
        .map(|descriptor| descriptor.name)
        .collect();
    assert!(names.contains(&"breg.record.tombstone"));

    let closed = Mock::start("immediate", false).await;
    let names: Vec<&str> = closed
        .connector
        .catalog()
        .iter()
        .map(|descriptor| descriptor.name)
        .collect();
    assert!(!names.contains(&"breg.record.tombstone"));
    let fault = closed.connector.record_tombstone().prepare(
        &json!({"record": RECORD_ID, "etag": SERVER_ETAG}),
        key("tombstone"),
    );
    assert!(matches!(fault, Err(ConnectorFault::AuthorityAbsent)));
    assert!(closed.exchanges().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn create_prepares_without_io_and_carries_no_credential() {
    let mock = Mock::start("immediate", false).await;
    let prepared = mock
        .connector
        .record_create()
        .prepare(
            &json!({"data": {"legalName": "Prepared Ltd"}}),
            key("create"),
        )
        .expect("create prepares");
    assert_eq!(prepared.operation(), "breg.record.create");
    assert_eq!(prepared.key().as_str(), "adapter-unit/company/create");
    // The prepared bytes hold request material and the key, never the
    // bearer token the host owns.
    let bytes = String::from_utf8_lossy(prepared.as_bytes()).to_string();
    assert!(!bytes.contains(TOKEN));
    assert!(bytes.contains("legalName"));
    assert!(mock.exchanges().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn create_send_completes_on_the_committed_receipt() {
    let mock = Mock::start("immediate", false).await;
    mock.push(created_record(RECORD_ID));
    let outcome = {
        let prepared = mock
            .connector
            .record_create()
            .prepare(
                &json!({"data": {"legalName": "Created Ltd"}}),
                key("create"),
            )
            .expect("prepares");
        mock.connector.record_create().send(&prepared)
    }
    .expect("send answers");
    assert_eq!(outcome.category, OutcomeCategory::Completed);
    assert_eq!(outcome.correlation.as_deref(), Some(RECORD_ID));
    let requests = mock.exchanges();
    assert_eq!(requests.len(), 1, "one create exchange");
    assert_eq!(
        requests[0].idempotency_key.as_deref(),
        Some("adapter-unit/company/create")
    );
    assert_eq!(
        requests[0].uri,
        "/tenant/prefix/v1/records/companies?accessProfile=writer"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn create_recovery_restores_stored_bytes_under_the_same_key() {
    let mock = Mock::start("immediate", false).await;
    let stored = {
        let prepared = mock
            .connector
            .record_create()
            .prepare(
                &json!({"data": {"legalName": "Created Ltd"}}),
                key("create"),
            )
            .expect("prepares");
        prepared.as_bytes().to_vec()
    };
    mock.push(created_record(RECORD_ID));
    let outcome = {
        let prepared =
            registry_adapter_connectors::breg::mutation::PreparedCreate::from_bytes(&stored)
                .expect("stored bytes restore");
        assert_eq!(prepared.key().as_str(), "adapter-unit/company/create");
        mock.connector.record_create().recover(&prepared)
    }
    .expect("recovery answers");
    assert_eq!(outcome.category, OutcomeCategory::Completed);
    let requests = mock.exchanges();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].idempotency_key.as_deref(),
        Some("adapter-unit/company/create")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn create_refusals_surface_the_product_problem_words() {
    for (code, expected) in [
        (
            BRegProblemCode::IdempotencyConflict,
            problems::IDEMPOTENCY_KEY_REUSED,
        ),
        (
            BRegProblemCode::IdempotencyExpired,
            problems::IDEMPOTENCY_EXPIRED,
        ),
    ] {
        let mock = Mock::start("immediate", false).await;
        mock.push(problem(code));
        let outcome = {
            let prepared = mock
                .connector
                .record_create()
                .prepare(&json!({"data": {"legalName": "Created Ltd"}}), key("spent"))
                .expect("prepares");
            mock.connector.record_create().send(&prepared)
        }
        .expect("refusal is an outcome");
        assert_eq!(outcome.category, OutcomeCategory::Refused);
        assert_eq!(outcome.native_problem.as_deref(), Some(expected));
        assert_eq!(mock.exchanges().len(), 1);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn create_unknown_outcome_is_uncertain_not_an_error() {
    let mock = Mock::start("immediate", false).await;
    mock.push(support::MockResponse::json(StatusCode::CREATED, json!({})).hanging());
    let outcome = {
        let prepared = mock
            .connector
            .record_create()
            .prepare(&json!({"data": {"legalName": "Created Ltd"}}), key("lost"))
            .expect("prepares");
        mock.connector.record_create().send(&prepared)
    }
    .expect("uncertainty is an outcome");
    assert_eq!(outcome.category, OutcomeCategory::Uncertain);
    assert!(outcome.correlation.is_none());
    assert!(!mock.exchanges().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn create_input_outside_the_closed_shape_is_invalid() {
    let mock = Mock::start("immediate", false).await;
    let fault = mock
        .connector
        .record_create()
        .prepare(&json!({"values": {}}), key("create"));
    assert!(matches!(fault, Err(ConnectorFault::InvalidInput)));
    assert!(mock.exchanges().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_sends_the_precondition_and_completes() {
    let mock = Mock::start("immediate", false).await;
    mock.push(mutated_record());
    let outcome = {
        let prepared = mock
            .connector
            .record_patch()
            .prepare(
                &json!({
                    "record": RECORD_ID,
                    "etag": SERVER_ETAG,
                    "operations": [
                        {"op": "test", "field": "legalName", "value": "Example Ltd"},
                        {"op": "replace", "field": "legalName", "value": "Patched Ltd"}
                    ]
                }),
                key("patch"),
            )
            .expect("prepares");
        mock.connector.record_patch().send(&prepared)
    }
    .expect("send answers");
    assert_eq!(outcome.category, OutcomeCategory::Completed);
    assert_eq!(outcome.correlation.as_deref(), Some(RECORD_ID));
    let requests = mock.exchanges();
    assert_eq!(requests[0].method, "PATCH");
    assert_eq!(requests[0].if_match.as_deref(), Some(SERVER_ETAG));
    assert_eq!(
        requests[0].idempotency_key.as_deref(),
        Some("adapter-unit/company/patch")
    );
    let body: Value = serde_json::from_slice(&requests[0].body).expect("patch body");
    assert_eq!(body[1]["op"], "replace");
    assert_eq!(body[1]["path"], "/data/legalName");
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_recovery_rebuilds_the_identical_request_from_stored_bytes() {
    let mock = Mock::start("immediate", false).await;
    let stored = {
        let prepared = mock
            .connector
            .record_patch()
            .prepare(
                &json!({
                    "record": RECORD_ID,
                    "etag": SERVER_ETAG,
                    "operations": [{"op": "remove", "field": "legalName"}]
                }),
                key("patch"),
            )
            .expect("prepares");
        prepared.as_bytes().to_vec()
    };
    mock.push(mutated_record());
    let outcome = {
        let prepared =
            registry_adapter_connectors::breg::mutation::PreparedPatch::from_bytes(&stored)
                .expect("stored bytes restore");
        mock.connector.record_patch().recover(&prepared)
    }
    .expect("recovery answers");
    assert_eq!(outcome.category, OutcomeCategory::Completed);
    let body: Value = serde_json::from_slice(&mock.exchanges()[0].body).expect("patch body");
    assert_eq!(body[0]["op"], "remove");
    assert_eq!(body[0]["path"], "/data/legalName");
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_refusal_from_a_moved_condition_is_refused() {
    let mock = Mock::start("immediate", false).await;
    mock.push(problem(BRegProblemCode::PreconditionFailed));
    let outcome = {
        let prepared = mock
            .connector
            .record_patch()
            .prepare(
                &json!({
                    "record": RECORD_ID,
                    "etag": SERVER_ETAG,
                    "operations": [{"op": "replace", "field": "legalName", "value": "Late"}]
                }),
                key("patch"),
            )
            .expect("prepares");
        mock.connector.record_patch().send(&prepared)
    }
    .expect("refusal is an outcome");
    assert_eq!(outcome.category, OutcomeCategory::Refused);
    assert_eq!(
        outcome.native_problem.as_deref(),
        Some("precondition.failed")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn tombstone_runs_only_under_opened_authority() {
    let mock = Mock::start("immediate", true).await;
    mock.push(mutated_record());
    let outcome = {
        let prepared = mock
            .connector
            .record_tombstone()
            .prepare(
                &json!({"record": RECORD_ID, "etag": SERVER_ETAG}),
                key("tombstone"),
            )
            .expect("prepares under opened authority");
        mock.connector.record_tombstone().send(&prepared)
    }
    .expect("send answers");
    assert_eq!(outcome.category, OutcomeCategory::Completed);
    let requests = mock.exchanges();
    assert_eq!(requests[0].method, "DELETE");
    assert_eq!(requests[0].if_match.as_deref(), Some(SERVER_ETAG));
    assert!(requests[0].idempotency_key.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn get_record_reads_the_route_under_the_profile() {
    let mock = Mock::start("immediate", false).await;
    mock.push(single_record());
    let record = mock
        .connector
        .reads()
        .get_record(RECORD_ID)
        .expect("read answers");
    assert_eq!(record.value.data.record_identifier, RECORD_ID);
    assert_eq!(record.value.data.revision_identifier, "3");
    let requests = mock.exchanges();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].uri,
        "/tenant/prefix/v1/records/companies/00000000-0000-4000-8000-000000000001?accessProfile=writer"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn revisions_read_as_inert_bytes() {
    let mock = Mock::start("immediate", false).await;
    mock.push(
        support::MockResponse::json(StatusCode::OK, json!({"revisions": []}))
            .with_header(link_header().0, link_header().1),
    );
    let revisions = mock
        .connector
        .reads()
        .record_revisions(RECORD_ID)
        .expect("revisions answer");
    assert!(std::str::from_utf8(revisions.value.as_bytes())
        .expect("inert bytes")
        .contains("revisions"));
    assert_eq!(
        mock.exchanges()[0].uri,
        format!("/tenant/prefix/v1/records/companies/{RECORD_ID}/revisions?accessProfile=writer")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn lookup_resolution_passes_through_unresolved_unchanged() {
    let mock = Mock::start("immediate", false).await;
    let request = BRegLookupRequest::new("by-legal-name")
        .expect("selector")
        .value("legalName", json!("Example Ltd"))
        .expect("value");
    // A lookup answer carries no entity tag.
    mock.push(
        support::MockResponse::json(StatusCode::OK, record_body())
            .with_header(link_header().0, link_header().1),
    );
    let resolved = mock
        .connector
        .reads()
        .lookup(&request)
        .expect("lookup answers");
    assert!(matches!(resolved, Lookup::Resolved(_)));
    // The unresolved answer is the destination's own typed problem, never
    // not-found and never retried.
    mock.push(problem(BRegProblemCode::LookupUnresolved));
    let unresolved = mock
        .connector
        .reads()
        .lookup(&request)
        .expect("lookup answers");
    assert!(matches!(unresolved, Lookup::Unresolved));
    assert_eq!(mock.exchanges().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn list_page_advances_only_until_the_caller_bound() {
    let mock = Mock::start("immediate", false).await;
    let page = |cursor: Value| {
        support::MockResponse::json(
            StatusCode::OK,
            json!({
                "items": [
                    record_body()["data"].clone(),
                    record_body()["data"].clone()
                ],
                "pageInfo": {"nextCursor": cursor},
                "meta": {
                    "registryIdentifier": "business-registry",
                    "datasetIdentifier": "legal-entities",
                    "entityTypeIdentifier": "company"
                }
            }),
        )
        .with_header(link_header().0, link_header().1)
        .with_header("cache-control", "no-store")
        .with_header("vary", "authorization, accept")
    };
    mock.push(page(json!("token-1")));
    mock.push(page(Value::Null));
    let request = BRegListRequest::default().top(2).expect("page size");
    let outcome = mock
        .connector
        .reads()
        .list_page(&request, 4)
        .expect("list answers");
    assert_eq!(outcome.items.len(), 4);
    assert!(outcome.continuation.is_none());
    assert_eq!(mock.exchanges().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn observation_reads_the_record_revision_back() {
    let mock = Mock::start("immediate", false).await;
    mock.push(single_record());
    let state = mock
        .connector
        .record_create()
        .observe(RECORD_ID)
        .expect("observation answers");
    assert_eq!(state.state, "present");
    assert!(state
        .details
        .iter()
        .any(|(name, value)| name == "revision" && value == "3"));
}
