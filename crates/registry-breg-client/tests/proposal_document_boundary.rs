// SPDX-License-Identifier: Apache-2.0
use std::sync::{Arc, Mutex};

use axum::{extract::State, routing::any, Json, Router};
use registry_breg_client::{
    BRegIdempotencyKey, BRegMetadata, BRegProposal, BRegProposalQuery, BaseRegistryClient,
    BaseRegistryClientConfig,
};
use serde_json::{json, Value};

const ID: &str = "00000000-0000-4000-8000-000000000001";
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct Fixture {
    client: BaseRegistryClient,
    metadata: BRegMetadata,
    response: Arc<Mutex<Value>>,
    server: tokio::task::JoinHandle<()>,
}
impl Fixture {
    async fn start() -> Self {
        let response = Arc::new(Mutex::new(json!({"metadataVersion":"1","id":"directory",
            "version":"1","revision":DIGEST,"recordTypes":[],"operations":[],
            "proposals":{"method":"GET","path":"/v1/proposals","accessProfiles":["writer"],
                "get":{"method":"GET","path":"/v1/proposals/{proposal_id}","accessProfiles":["writer"]},
                "actions":[{"actionId":"correct","accessProfile":"writer",
                    "operations":["get-review-context","get-review-status"]}]}})));
        let router = Router::new()
            .fallback(any(|State(value): State<Arc<Mutex<Value>>>| async move {
                (
                    [
                        (
                            "traceparent",
                            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                        ),
                        ("cache-control", "no-store"),
                        ("vary", "authorization, accept"),
                    ],
                    Json(value.lock().unwrap().clone()),
                )
            }))
            .with_state(response.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = BaseRegistryClient::new(
            BaseRegistryClientConfig::new(format!("http://{address}/").parse().unwrap())
                .with_max_mutation_retries(0),
        )
        .unwrap();
        let metadata = client
            .registry_contract(Some("writer"))
            .await
            .unwrap()
            .value;
        Self {
            client,
            metadata,
            response,
            server,
        }
    }
    fn answer(&self, value: Value) {
        *self.response.lock().unwrap() = value;
    }
    async fn proposal(&self, value: Value) -> BRegProposal {
        self.answer(value);
        let binding = self.metadata.select_proposal_get("writer").unwrap();
        self.client.get_proposal(&binding, ID).await.unwrap().value
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn proposal(state: &str) -> Value {
    let mut value = json!({"id":ID,"actionId":"correct","actionRevision":DIGEST,
        "submissionVersion":1,"revision":2,"state":state,"links":{
            "self":{"method":"GET","path":format!("/v1/proposals/{ID}"),"accessProfile":"writer","operation":"get"},
            "submit":{"method":"POST","path":format!("/v1/proposals/{ID}/submit"),"accessProfile":"writer","operation":"submit","ifMatch":"\"condition\""},
            "reviewStatus":{"method":"GET","path":format!("/v1/proposals/{ID}/review-status"),"accessProfile":"writer","operation":"get-review-status"},
            "reviewContext":{"method":"GET","path":format!("/v1/proposals/{ID}/review-context"),"accessProfile":"writer","operation":"get-review-context"}}});
    if state == "submitted" {
        value["effectDigest"] = json!(DIGEST);
    }
    value
}

fn review(context: bool) -> Value {
    let mut value = json!({"id":ID,"actionId":"correct","actionRevision":DIGEST,
        "submissionVersion":1,"revision":2,"effectDigest":DIGEST,
        "subject":{"source":"directory","subjectType":"proposal","id":ID,"version":"1","digest":DIGEST},
        "context":{"reference":"breg:directory:correct:proposal:1"},"reviewable":true,
        "authority":"review-provider","policy":{"id":"review-policy"}});
    if context {
        value["context"]["contract"] = json!({"id":"urn:registry:breg:review-context:directory:correct:display",
            "revision":DIGEST,"schemaDigest":DIGEST});
        value["context"]["fields"] = json!({});
    } else {
        value["result"] = json!({"state":"pending"});
    }
    value
}
fn terminal(state: &str) -> Value {
    json!({"state":state,"resultId":ID,"completedAt":"2026-09-19T00:01:00.000001Z",
        "availableUntil":"2026-09-20T07:01:00.000001+07:00"})
}

#[tokio::test]
async fn proposal_get_list_and_promoted_reads_validate_frozen_state_and_allow_tombstones() {
    let fixture = Fixture::start().await;
    let held = fixture.proposal(proposal("submitted")).await;
    let binding = fixture.metadata.select_proposal_get("writer").unwrap();
    let collection = fixture.metadata.select_proposals("writer").unwrap();
    let mut cases = vec![];
    for state in ["draft", "submitted", "applied", "cancelled"] {
        let mut invalid = proposal(state);
        invalid["submissionVersion"] = json!(0);
        cases.push((format!("{state}:zero-version"), invalid));
    }
    let mut missing_digest = proposal("submitted");
    missing_digest
        .as_object_mut()
        .unwrap()
        .remove("effectDigest");
    cases.push(("submitted:missing-digest".to_owned(), missing_digest));
    let mut frozen_draft = proposal("draft");
    frozen_draft["effectDigest"] = json!(DIGEST);
    cases.push(("draft:frozen-digest".to_owned(), frozen_draft));
    let mut incomplete_applied = proposal("applied");
    incomplete_applied["effectDigest"] = json!(DIGEST);
    cases.push(("applied:missing-application".to_owned(), incomplete_applied));
    let mut accepted = vec![];
    for (name, invalid) in cases {
        fixture.answer(invalid.clone());
        if fixture.client.get_proposal(&binding, ID).await.is_ok() {
            accepted.push(format!("get:{name}"));
        }
        if fixture.client.read_proposal(&held).await.is_ok() {
            accepted.push(format!("read:{name}"));
        }
        fixture.answer(json!({"items":[invalid]}));
        if fixture
            .client
            .list_proposals(&collection, &BRegProposalQuery::default())
            .await
            .is_ok()
        {
            accepted.push(format!("list:{name}"));
        }
    }
    let mut full_applied = proposal("applied");
    full_applied["effectDigest"] = json!(DIGEST);
    full_applied["application"] = json!({"applicationId":ID,"submissionVersion":1,
        "effectDigest":DIGEST,"resultLinks":[]});
    let mut permitted: Vec<_> = ["draft", "submitted", "applied", "cancelled"]
        .into_iter()
        .map(|state| (state, proposal(state)))
        .collect();
    permitted.push(("applied-with-evidence", full_applied));
    for (state, valid) in permitted {
        fixture.answer(valid.clone());
        assert!(
            fixture.client.get_proposal(&binding, ID).await.is_ok(),
            "get:{state}"
        );
        assert!(
            fixture.client.read_proposal(&held).await.is_ok(),
            "read:{state}"
        );
        fixture.answer(json!({"items":[valid]}));
        assert!(
            fixture
                .client
                .list_proposals(&collection, &BRegProposalQuery::default())
                .await
                .is_ok(),
            "list:{state}"
        );
    }
    assert!(
        accepted.is_empty(),
        "accepted malformed documents: {accepted:?}"
    );
}

#[tokio::test]
async fn review_status_reads_require_complete_terminal_evidence_and_parse_instants() {
    let fixture = Fixture::start().await;
    let held = fixture.proposal(proposal("submitted")).await;
    let binding = fixture
        .metadata
        .select_proposal_review_status("writer", "correct")
        .unwrap();
    let mut cases = vec![];
    for state in [
        "approved",
        "rejected",
        "changes-requested",
        "answered",
        "cancelled",
        "superseded",
        "expired",
    ] {
        for field in ["resultId", "completedAt", "availableUntil"] {
            let mut result = terminal(state);
            result.as_object_mut().unwrap().remove(field);
            cases.push((format!("{state}:missing-{field}"), result));
        }
    }
    for field in ["resultId", "completedAt", "availableUntil"] {
        let mut pending = json!({"state":"pending"});
        pending[field] = terminal("approved")[field].clone();
        cases.push((format!("pending:{field}"), pending));
    }
    for field in ["completedAt", "availableUntil"] {
        for invalid in ["not-a-time", "2026-02-30T00:00:00Z", "2026-09-19T00:01:00"] {
            let mut result = terminal("approved");
            result[field] = json!(invalid);
            cases.push((format!("{field}:{invalid}"), result));
        }
    }
    for end in ["2026-09-19T00:01:00.000001Z", "2026-09-18T00:01:00Z"] {
        let mut result = terminal("approved");
        result["availableUntil"] = json!(end);
        cases.push((format!("availability:{end}"), result));
    }
    let mut nil = terminal("approved");
    nil["resultId"] = json!("00000000-0000-0000-0000-000000000000");
    cases.push(("nil-result".to_owned(), nil));
    let mut accepted = vec![];
    for (name, result) in cases {
        let mut invalid = review(false);
        invalid["result"] = result;
        fixture.answer(invalid);
        if fixture
            .client
            .read_proposal_review_by_id(&binding, ID)
            .await
            .is_ok()
        {
            accepted.push(format!("uuid:{name}"));
        }
        if fixture
            .client
            .read_proposal_review_status(&held)
            .await
            .is_ok()
        {
            accepted.push(format!("promoted:{name}"));
        }
    }
    for state in [
        "pending",
        "approved",
        "rejected",
        "changes-requested",
        "answered",
        "cancelled",
        "superseded",
        "expired",
    ] {
        for reviewable in [false, true] {
            let mut valid = review(false);
            valid["reviewable"] = json!(reviewable);
            if state != "pending" {
                valid["result"] = terminal(state);
            }
            fixture.answer(valid);
            assert!(
                fixture
                    .client
                    .read_proposal_review_by_id(&binding, ID)
                    .await
                    .is_ok(),
                "uuid:{state}:{reviewable}"
            );
            assert!(
                fixture
                    .client
                    .read_proposal_review_status(&held)
                    .await
                    .is_ok(),
                "promoted:{state}:{reviewable}"
            );
        }
    }
    assert!(
        accepted.is_empty(),
        "accepted malformed results: {accepted:?}"
    );
}

#[tokio::test]
async fn review_context_and_status_preserve_their_distinct_result_projections() {
    let fixture = Fixture::start().await;
    let held = fixture.proposal(proposal("submitted")).await;
    let mut accepted = vec![];
    for context in [false, true] {
        let binding = if context {
            fixture
                .metadata
                .select_proposal_review_context("writer", "correct")
        } else {
            fixture
                .metadata
                .select_proposal_review_status("writer", "correct")
        }
        .unwrap();
        for configured in [false, true] {
            let mut valid = review(context);
            if !configured {
                for key in ["authority", "policy", "result"] {
                    valid.as_object_mut().unwrap().remove(key);
                }
            }
            fixture.answer(valid.clone());
            assert!(fixture
                .client
                .read_proposal_review_by_id(&binding, ID)
                .await
                .is_ok());
            let result = if context {
                fixture.client.read_proposal_review_context(&held).await
            } else {
                fixture.client.read_proposal_review_status(&held).await
            };
            assert!(result.is_ok());
            if context || !configured {
                valid["result"] = terminal("approved");
            } else {
                valid.as_object_mut().unwrap().remove("result");
            }
            fixture.answer(valid);
            if fixture
                .client
                .read_proposal_review_by_id(&binding, ID)
                .await
                .is_ok()
            {
                accepted.push(format!("uuid:{context}:{configured}"));
            }
            let result = if context {
                fixture.client.read_proposal_review_context(&held).await
            } else {
                fixture.client.read_proposal_review_status(&held).await
            };
            if result.is_ok() {
                accepted.push(format!("promoted:{context}:{configured}"));
            }
        }
    }
    assert!(
        accepted.is_empty(),
        "accepted invalid result projections: {accepted:?}"
    );
}

#[tokio::test]
async fn submit_receipts_require_a_frozen_digest_before_recovery() {
    let fixture = Fixture::start().await;
    let held = fixture.proposal(proposal("draft")).await;
    let attempt = fixture
        .client
        .prepare_proposal(
            &held,
            "submit",
            json!({}),
            &BRegIdempotencyKey::parse("frozen-submit").unwrap(),
        )
        .unwrap();
    let mut valid = proposal("submitted");
    valid["revision"] = json!(3);
    fixture.answer(valid.clone());
    let successor = fixture
        .client
        .execute_proposal(&attempt)
        .await
        .unwrap()
        .value;
    let recovered = fixture
        .client
        .recover_proposal(&successor, &attempt)
        .unwrap();
    assert_eq!(recovered.as_bytes(), attempt.as_bytes());
    let mut invalid = valid;
    invalid.as_object_mut().unwrap().remove("effectDigest");
    fixture.answer(invalid);
    assert!(fixture.client.execute_proposal(&attempt).await.is_err());
}

#[tokio::test]
async fn readable_attachment_metadata_requires_a_valid_upload_instant() {
    let fixture = Fixture::start().await;
    let source: Value =
        serde_json::from_slice(include_bytes!("fixtures/attachments.json")).unwrap();
    let mut valid = source["proposal"].clone();
    valid["attachments"]["supporting-file"]["value"] = json!({"submissionVersion":2,
        "sha256":"a".repeat(64),"contentType":"application/pdf","byteSize":4,
        "uploadedAt":"2026-09-19T00:01:00.123456Z","verificationStatus":"approved"});
    valid["links"]["self"] = json!({"method":"GET","path":format!("/v1/proposals/{ID}"),
        "accessProfile":"writer","operation":"get"});
    let held = fixture.proposal(valid.clone()).await;
    let binding = fixture.metadata.select_proposal_get("writer").unwrap();
    let collection = fixture.metadata.select_proposals("writer").unwrap();
    let key = BRegIdempotencyKey::parse("attachment-instant").unwrap();
    let mut receipt = valid.clone();
    receipt["revision"] = json!(4);
    fixture.answer(receipt.clone());
    assert!(fixture
        .client
        .upload_proposal_attachment(&held, "supporting-file", "application/pdf", b"%PDF", &key)
        .await
        .is_ok());
    receipt["attachments"]["supporting-file"]
        .as_object_mut()
        .unwrap()
        .remove("value");
    fixture.answer(receipt);
    assert!(fixture
        .client
        .delete_proposal_attachment(&held, "supporting-file", &key)
        .await
        .is_ok());
    let mut accepted = vec![];
    for instant in [
        None,
        Some("not-a-time"),
        Some("2026-02-30T00:00:00Z"),
        Some("2026-09-19"),
    ] {
        let mut invalid = valid.clone();
        let value = invalid["attachments"]["supporting-file"]["value"]
            .as_object_mut()
            .unwrap();
        if let Some(instant) = instant {
            value.insert("uploadedAt".to_owned(), json!(instant));
        } else {
            value.remove("uploadedAt");
        }
        fixture.answer(invalid.clone());
        if fixture.client.get_proposal(&binding, ID).await.is_ok() {
            accepted.push(format!("get:{instant:?}"));
        }
        if fixture.client.read_proposal(&held).await.is_ok() {
            accepted.push(format!("read:{instant:?}"));
        }
        fixture.answer(json!({"items":[invalid.clone()]}));
        if fixture
            .client
            .list_proposals(&collection, &BRegProposalQuery::default())
            .await
            .is_ok()
        {
            accepted.push(format!("list:{instant:?}"));
        }
        invalid["revision"] = json!(4);
        fixture.answer(invalid);
        if fixture
            .client
            .upload_proposal_attachment(&held, "supporting-file", "application/pdf", b"%PDF", &key)
            .await
            .is_ok()
        {
            accepted.push(format!("upload:{instant:?}"));
        }
    }
    assert!(
        accepted.is_empty(),
        "accepted malformed upload instants: {accepted:?}"
    );
}
