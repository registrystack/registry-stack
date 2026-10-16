// SPDX-License-Identifier: Apache-2.0
use async_trait::async_trait;
use registry_platform_httputil::client::{BearerToken, TokenError, TokenProvider};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

use axum::{
    extract::{Path, State},
    routing::{any, get},
    Json, Router,
};
use registry_breg_client::{
    BRegIdempotencyKey, BRegMetadata, BRegPreparedProposal, BRegProposal, BRegProposalQuery,
    BRegRecordOptions, BaseRegistryClient, BaseRegistryClientConfig,
};
use serde_json::{json, Value};

const ID: &str = "00000000-0000-4000-8000-000000000001";
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[derive(Debug, Default)]
struct CountingToken(AtomicUsize);
#[async_trait]
impl TokenProvider for CountingToken {
    async fn bearer_token(&self) -> Result<BearerToken, TokenError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        BearerToken::new("proposal-boundary-token")
    }
}

struct Fixture {
    client: BaseRegistryClient,
    metadata: BRegMetadata,
    response: Arc<Mutex<Value>>,
    requests: Arc<AtomicUsize>,
    token: Arc<CountingToken>,
    server: tokio::task::JoinHandle<()>,
}
impl Fixture {
    async fn start() -> Self {
        let response = Arc::new(Mutex::new(json!({"metadataVersion":"2","id":"directory",
            "version":"1","revision":DIGEST,"recordTypes":[],"operations":[],
            "proposals":{"method":"GET","path":"/v1/proposals","accessProfiles":["writer"],
                "get":{"method":"GET","path":"/v1/proposals/{proposal_id}","accessProfiles":["writer"]},
                "actions":[{"actionId":"correct","accessProfile":"writer",
                    "readableInputs":[],
                    "operations":["get-review-context","get-review-status"]}]}})));
        let requests = Arc::new(AtomicUsize::new(0));
        let router = Router::new()
            .route("/v1/records/items/{id}", get(|Path(id): Path<String>, State((_, requests)): State<(Arc<Mutex<Value>>, Arc<AtomicUsize>)>| async move {
                requests.fetch_add(1, Ordering::SeqCst);
                (
                    [("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
                     ("cache-control", "no-store"), ("vary", "authorization, accept"),
                     ("etag", "\"breg-record-000000000001\""),
                     ("link", "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </v1/schemas/item>; rel=\"describedby\"")],
                    Json(json!({"meta":{"registryIdentifier":"directory", "datasetIdentifier":"items", "entityTypeIdentifier":"item"},
                        "data":{"recordIdentifier":id, "revisionIdentifier":"4", "domainData":{}}})),
                )
            }))
            .fallback(any(|State((value, requests)): State<(Arc<Mutex<Value>>, Arc<AtomicUsize>)>| async move {
                requests.fetch_add(1, Ordering::SeqCst);
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
            .with_state((response.clone(), requests.clone()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let token = Arc::new(CountingToken::default());
        let client = BaseRegistryClient::new(
            BaseRegistryClientConfig::new(format!("http://{address}/").parse().unwrap())
                .with_max_mutation_retries(0)
                .with_token_provider(token.clone()),
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
            requests,
            token,
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
async fn submission_read_refuses_an_incoherent_application() {
    let fixture = Fixture::start().await;
    let held = fixture.proposal(proposal("submitted")).await;
    let submission = |application: Value| {
        json!({"id":ID,"actionId":"correct","submissionVersion":1,"current":true,
            "effectDigest":DIGEST,"review":null,"application":application})
    };
    let retry = json!({"scheduled":true,"attempts":1,"maximumAttempts":3});
    for (name, application) in [
        ("applied", json!({"state":"applied","applicationId":ID})),
        ("pending", json!({"state":"pending","mode":"manual"})),
        (
            "blocked",
            json!({"state":"blocked","mode":"manual","reason":"contract-changed","recovery":"correct-input"}),
        ),
        (
            "automatic",
            json!({"state":"pending","mode":"automatic","automaticRetry":retry}),
        ),
        ("none", Value::Null),
    ] {
        fixture.answer(submission(application));
        assert!(
            fixture
                .client
                .read_proposal_submission(&held, 1)
                .await
                .is_ok(),
            "{name}"
        );
    }
    let mut accepted = vec![];
    for (name, application) in [
        ("applied-without-receipt", json!({"state":"applied"})),
        (
            "applied-with-mode",
            json!({"state":"applied","applicationId":ID,"mode":"manual"}),
        ),
        (
            "applied-with-retry",
            json!({"state":"applied","applicationId":ID,"automaticRetry":retry}),
        ),
        (
            "pending-with-receipt",
            json!({"state":"pending","mode":"manual","applicationId":ID}),
        ),
        ("pending-without-mode", json!({"state":"pending"})),
        (
            "blocked-without-reason",
            json!({"state":"blocked","mode":"manual"}),
        ),
        (
            "reason-without-recovery",
            json!({"state":"blocked","mode":"manual","reason":"contract-changed"}),
        ),
        (
            "automatic-without-retry",
            json!({"state":"pending","mode":"automatic"}),
        ),
        (
            "manual-with-retry",
            json!({"state":"pending","mode":"manual","automaticRetry":retry}),
        ),
    ] {
        fixture.answer(submission(application));
        if fixture
            .client
            .read_proposal_submission(&held, 1)
            .await
            .is_ok()
        {
            accepted.push(name);
        }
    }
    assert!(accepted.is_empty(), "accepted: {accepted:?}");
}

#[tokio::test]
async fn application_recovery_is_bound_to_its_reason_in_current_and_retained_reads() {
    let fixture = Fixture::start().await;
    let held = fixture.proposal(proposal("submitted")).await;
    let binding = fixture.metadata.select_proposal_get("writer").unwrap();
    let status = |reason: &str, recovery: &str| {
        json!({"state":"blocked","mode":"automatic","reason":reason,"recovery":recovery,
            "automaticRetry":{"scheduled":false,"attempts":3,"maximumAttempts":3}})
    };
    let reads = |application: Value| {
        let mut current = proposal("submitted");
        current["applicationStatus"] = application.clone();
        let submission = json!({"id":ID,"actionId":"correct","submissionVersion":1,
            "current":true,"effectDigest":DIGEST,"review":null,"application":application});
        (current, submission)
    };
    // The only pairs BReg emits: a dependency outage or an expired lease can
    // be retried; everything else needs corrected input.
    for (reason, recovery) in [
        ("contract-changed", "correct-input"),
        ("attempts-exhausted", "correct-input"),
        ("application-refused", "correct-input"),
        ("dependency-outage", "retry"),
        ("lease-expired", "retry"),
    ] {
        let (current, submission) = reads(status(reason, recovery));
        fixture.answer(current);
        assert!(
            fixture.client.get_proposal(&binding, ID).await.is_ok(),
            "current {reason}/{recovery}"
        );
        fixture.answer(submission);
        assert!(
            fixture
                .client
                .read_proposal_submission(&held, 1)
                .await
                .is_ok(),
            "retained {reason}/{recovery}"
        );
    }
    let mut accepted = vec![];
    for (reason, recovery) in [
        ("contract-changed", "retry"),
        ("attempts-exhausted", "retry"),
        ("application-refused", "retry"),
        ("dependency-outage", "correct-input"),
        ("lease-expired", "correct-input"),
    ] {
        let (current, submission) = reads(status(reason, recovery));
        fixture.answer(current);
        if fixture.client.get_proposal(&binding, ID).await.is_ok() {
            accepted.push(format!("current {reason}/{recovery}"));
        }
        fixture.answer(submission);
        if fixture
            .client
            .read_proposal_submission(&held, 1)
            .await
            .is_ok()
        {
            accepted.push(format!("retained {reason}/{recovery}"));
        }
    }
    assert!(accepted.is_empty(), "accepted: {accepted:?}");
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
async fn promoted_proposal_reads_preserve_the_held_action_revision() {
    let fixture = Fixture::start().await;
    let binding = fixture.metadata.select_proposal_get("writer").unwrap();
    let collection = fixture.metadata.select_proposals("writer").unwrap();
    for before in ["draft", "submitted"] {
        let held = fixture.proposal(proposal(before)).await;
        for (state, version, revision) in [(before, 1, 2), ("submitted", 1, 3), ("draft", 2, 5)] {
            let mut current = proposal(state);
            current["submissionVersion"] = json!(version);
            current["revision"] = json!(revision);
            fixture.answer(current.clone());
            assert!(fixture.client.read_proposal(&held).await.is_ok());

            current["actionRevision"] = json!(format!("sha256:{}", "b".repeat(64)));
            fixture.answer(current.clone());
            assert!(
                fixture.client.read_proposal(&held).await.is_err(),
                "{before}:{state}:{version}:{revision} silently rebound the Action"
            );
            // Fresh authorized discovery may deliberately observe the successor.
            assert!(fixture.client.get_proposal(&binding, ID).await.is_ok());
            fixture.answer(json!({"items":[current]}));
            assert!(fixture
                .client
                .list_proposals(&collection, &BRegProposalQuery::default())
                .await
                .is_ok());
        }
    }
}

#[tokio::test]
async fn application_result_ids_are_canonical_and_usable_for_record_reads() {
    let fixture = Fixture::start().await;
    let binding = fixture.metadata.select_proposal_get("writer").unwrap();
    let collection = fixture.metadata.select_proposals("writer").unwrap();
    let mut submitted = proposal("submitted");
    submitted["links"]["apply"] = json!({"method":"POST","path":format!("/v1/proposals/{ID}/apply"),
        "accessProfile":"writer","operation":"apply","ifMatch":"\"condition\""});
    let held = fixture.proposal(submitted).await;
    let attempt = fixture
        .client
        .prepare_proposal(
            &held,
            "apply",
            json!({"submissionVersion":1,"effectDigest":DIGEST}),
            &BRegIdempotencyKey::parse("canonical-result-id").unwrap(),
        )
        .unwrap();
    let canonical = "123e4567-e89b-42d3-a456-426614174000";
    let mut accepted = vec![];
    for (id, valid) in [
        (canonical.to_owned(), true),
        ("00000000-0000-0000-0000-000000000000".to_owned(), true),
        (canonical.to_ascii_uppercase(), false),
        (canonical.replace('-', ""), false),
    ] {
        let mut current = proposal("applied");
        current["revision"] = json!(3);
        current["effectDigest"] = json!(DIGEST);
        current["application"] = json!({"applicationId":ID,"submissionVersion":1,"effectDigest":DIGEST,
            "resultLinks":[{"recordType":"item","recordId":id,"revision":4}]});
        fixture.answer(current.clone());
        let observed = fixture.client.get_proposal(&binding, ID).await;
        if valid {
            let observed = observed.unwrap().value;
            let reference = &observed.application().unwrap().result_links[0];
            assert_eq!(reference.record_id, id);
            fixture
                .client
                .get_record("items", &reference.record_id, &BRegRecordOptions::default())
                .await
                .unwrap();
        } else {
            if let Ok(observed) = observed {
                accepted.push(format!(
                    "get:{}",
                    observed.value.application().unwrap().result_links[0].record_id
                ));
            }
            let requests = fixture.requests.load(Ordering::SeqCst);
            let tokens = fixture.token.0.load(Ordering::SeqCst);
            assert!(fixture
                .client
                .get_record("items", &id, &BRegRecordOptions::default())
                .await
                .is_err());
            assert_eq!(fixture.requests.load(Ordering::SeqCst), requests);
            assert_eq!(fixture.token.0.load(Ordering::SeqCst), tokens);
        }
        for (operation, observed) in [
            ("read", fixture.client.read_proposal(&held).await),
            ("apply", fixture.client.execute_proposal(&attempt).await),
        ] {
            if valid {
                assert!(observed.is_ok(), "{operation}:{id}");
            } else if observed.is_ok() {
                accepted.push(format!("{operation}:{id}"));
            }
        }
        fixture.answer(json!({"items":[current]}));
        let listed = fixture
            .client
            .list_proposals(&collection, &BRegProposalQuery::default())
            .await;
        if valid {
            assert!(listed.is_ok(), "list:{id}");
        } else if listed.is_ok() {
            accepted.push(format!("list:{id}"));
        }
    }
    assert!(
        accepted.is_empty(),
        "accepted unusable result record IDs: {accepted:?}"
    );
}

#[tokio::test]
async fn proposal_list_binds_only_canonical_non_nil_ids() {
    let fixture = Fixture::start().await;
    let collection = fixture.metadata.select_proposals("writer").unwrap();
    let canonical = "123e4567-e89b-42d3-a456-426614174000";
    let key = BRegIdempotencyKey::parse("canonical-proposal-id").unwrap();
    for id in [
        canonical.to_ascii_uppercase(),
        canonical.replace('-', ""),
        "00000000-0000-0000-0000-000000000000".to_owned(),
    ] {
        let item: Value =
            serde_json::from_str(&proposal("submitted").to_string().replace(ID, &id)).unwrap();
        fixture.answer(json!({"items":[item]}));
        let requests = fixture.requests.load(Ordering::SeqCst);
        let tokens = fixture.token.0.load(Ordering::SeqCst);
        let error = fixture
            .client
            .list_proposals(&collection, &BRegProposalQuery::default())
            .await
            .err()
            .expect("noncanonical Proposal must not become bound");
        assert_eq!(fixture.requests.load(Ordering::SeqCst), requests + 1);
        assert_eq!(fixture.token.0.load(Ordering::SeqCst), tokens + 1);
        let debug = format!("{error:?}");
        assert!(!debug.contains(&id));
        assert!(!debug.contains("proposal-boundary-token"));
    }

    let item: Value =
        serde_json::from_str(&proposal("draft").to_string().replace(ID, canonical)).unwrap();
    fixture.answer(json!({"items":[item]}));
    let page = fixture
        .client
        .list_proposals(&collection, &BRegProposalQuery::default())
        .await
        .unwrap()
        .value;
    let held = &page.items[0];
    assert_eq!(held.id(), canonical);
    let requests = fixture.requests.load(Ordering::SeqCst);
    let tokens = fixture.token.0.load(Ordering::SeqCst);
    fixture
        .client
        .prepare_proposal(held, "submit", json!({}), &key)
        .expect("canonical listed Proposal can prepare an advertised transition");
    assert_eq!(fixture.requests.load(Ordering::SeqCst), requests);
    assert_eq!(fixture.token.0.load(Ordering::SeqCst), tokens);
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
    let canonical_id = "123e4567-e89b-42d3-a456-426614174000";
    for id in [canonical_id.to_uppercase(), canonical_id.replace('-', "")] {
        let mut result = terminal("approved");
        result["resultId"] = json!(id);
        cases.push((format!("noncanonical-result:{id}"), result));
    }
    let mut accepted = vec![];
    for (name, result) in cases {
        let mut invalid = review(false);
        invalid["result"] = result;
        invalid["requestId"] = json!(ID);
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
    for id in [
        "123e4567-e89b-12d3-a456-426614174000",
        canonical_id,
        "0192a870-1234-7abc-8def-123456789abc",
    ] {
        let mut valid = review(false);
        valid["requestId"] = json!(id);
        valid["result"] = terminal("approved");
        valid["result"]["resultId"] = json!(id);
        fixture.answer(valid);
        for complete in [
            fixture
                .client
                .read_proposal_review_by_id(&binding, ID)
                .await
                .unwrap(),
            fixture
                .client
                .read_proposal_review_status(&held)
                .await
                .unwrap(),
        ] {
            assert_eq!(complete.value.request_id.as_deref(), Some(id));
            assert_eq!(
                complete.value.result.unwrap().result_id.as_deref(),
                Some(id)
            );
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
                valid["requestId"] = json!(ID);
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
    for state in [
        "approved",
        "rejected",
        "changes-requested",
        "answered",
        "cancelled",
        "superseded",
        "expired",
    ] {
        for request_id in [
            None,
            Some(json!("")),
            Some(json!("not-a-request")),
            Some(json!("00000000-0000-0000-0000-000000000000")),
            Some(json!("00000000-0000-4000-8000-00000000000A")),
            Some(json!(canonical_id.replace('-', ""))),
        ] {
            let mut invalid = review(false);
            invalid["result"] = terminal(state);
            if let Some(request_id) = request_id {
                invalid["requestId"] = request_id;
            }
            fixture.answer(invalid);
            assert!(
                fixture
                    .client
                    .read_proposal_review_by_id(&binding, ID)
                    .await
                    .is_err(),
                "uuid:{state}"
            );
            assert!(
                fixture
                    .client
                    .read_proposal_review_status(&held)
                    .await
                    .is_err(),
                "promoted:{state}"
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
async fn invalid_transition_states_are_refused_before_credentials_or_http() {
    let fixture = Fixture::start().await;
    for state in ["draft", "submitted", "applied", "cancelled"] {
        for operation in [
            "edit", "submit", "revise", "rebase", "retry", "cancel", "apply",
        ] {
            let legal = match state {
                "draft" => matches!(operation, "edit" | "submit" | "rebase" | "cancel"),
                "submitted" => matches!(
                    operation,
                    "revise" | "rebase" | "retry" | "cancel" | "apply"
                ),
                _ => false,
            };
            if legal {
                continue;
            }
            let mut document = proposal(state);
            // The server may still promote an unavailable receipt-recovery link in a terminal state.
            document["links"][operation] = json!({"method":"POST","path":format!("/v1/proposals/{ID}/{operation}"),
                "accessProfile":"writer","operation":operation,"ifMatch":"\"condition\""});
            let held = fixture.proposal(document).await;
            let tokens = fixture.token.0.load(Ordering::SeqCst);
            let requests = fixture.requests.load(Ordering::SeqCst);
            let body = match operation {
                "edit" | "rebase" => json!({"input":{}}),
                "apply" => json!({"submissionVersion":1,"effectDigest":DIGEST}),
                _ => json!({}),
            };
            assert!(
                fixture
                    .client
                    .prepare_proposal(
                        &held,
                        operation,
                        body,
                        &BRegIdempotencyKey::parse("invalid-state").unwrap()
                    )
                    .is_err(),
                "{state}:{operation}"
            );
            assert_eq!(fixture.token.0.load(Ordering::SeqCst), tokens);
            assert_eq!(fixture.requests.load(Ordering::SeqCst), requests);
        }
    }
    let held = fixture.proposal(proposal("draft")).await;
    let attempt = fixture
        .client
        .prepare_proposal(
            &held,
            "submit",
            json!({}),
            &BRegIdempotencyKey::parse("saved-state").unwrap(),
        )
        .unwrap();
    let mut saved: Value = serde_json::from_slice(attempt.as_bytes()).unwrap();
    saved["state"] = json!("submitted");
    assert!(BRegPreparedProposal::from_slice(&serde_json::to_vec(&saved).unwrap()).is_err());
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
    use sha2::{Digest, Sha256};
    receipt["attachments"]["supporting-file"]["value"]["sha256"] = json!(Sha256::digest(b"%PDF")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>());
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

// The preflight bounds the smallest possible canonical stored input object,
// independent of public aliases, saved-envelope escaping and response limits.
const PROPOSAL_INPUT_BYTES: usize = 3 * 1024 * 1024;

fn proposal_input_with_canonical_size(size: usize, number: f64) -> Value {
    let mut input = if number == 1e20 {
        let values = vec![json!(number); 35_746];
        json!({"a":values, "b":values, "c":values, "d":values})
    } else {
        json!({"a":"", "b":number})
    };
    let overhead = registry_platform_canonical_json::canonicalize_json(&input)
        .unwrap()
        .len();
    if number == 1e20 {
        input["d"]
            .as_array_mut()
            .unwrap()
            .push(json!("x".repeat(size - overhead - 3)));
    } else {
        input["a"] = json!("x".repeat(size - overhead));
    }
    assert_eq!(
        registry_platform_canonical_json::canonicalize_json(&input)
            .unwrap()
            .len(),
        size
    );
    input
}

#[tokio::test]
async fn proposal_input_snapshot_bound_is_checked_before_protected_io() {
    let fixture = Fixture::start().await;
    let key = BRegIdempotencyKey::parse("bounded-proposal-input").unwrap();
    for (operation, state) in [
        ("edit", "draft"),
        ("revise", "submitted"),
        ("rebase", "draft"),
        ("rebase", "submitted"),
    ] {
        let mut original = proposal(state);
        original["links"][operation] = json!({"method":"POST",
            "path":format!("/v1/proposals/{ID}/{operation}"), "accessProfile":"writer",
            "operation":operation, "ifMatch":"\"condition\""});
        let held = fixture.proposal(original.clone()).await;
        let tokens = fixture.token.0.load(Ordering::SeqCst);
        let requests = fixture.requests.load(Ordering::SeqCst);

        // JCS expands this exponent-form number, so serialized input alone
        // remains below the limit even when its canonical snapshot is too large.
        let oversized = proposal_input_with_canonical_size(PROPOSAL_INPUT_BYTES + 1, 1e20);
        assert!(
            serde_json::to_vec(&json!({"input":oversized.clone()}))
                .unwrap()
                .len()
                < 2 * 1024 * 1024
        );
        assert!(
            fixture
                .client
                .prepare_proposal(&held, operation, json!({"input":oversized.clone()}), &key)
                .is_err(),
            "{operation}:{state}:oversized canonical input"
        );

        assert_eq!(fixture.token.0.load(Ordering::SeqCst), tokens);
        assert_eq!(fixture.requests.load(Ordering::SeqCst), requests);
        for number in [1e20, 1.0] {
            let tokens = fixture.token.0.load(Ordering::SeqCst);
            let requests = fixture.requests.load(Ordering::SeqCst);
            let exact = proposal_input_with_canonical_size(PROPOSAL_INPUT_BYTES, number);
            if number == 1.0 {
                // JCS removes the fractional suffix. This client preflight
                // boundary is distinct from the runtime's smaller wire limit.
                assert!(serde_json::to_vec(&exact).unwrap().len() > PROPOSAL_INPUT_BYTES);
            }
            let attempt = fixture
                .client
                .prepare_proposal(&held, operation, json!({"input":exact}), &key)
                .expect("exact canonical boundary is permitted");
            let mut aliased = proposal_input_with_canonical_size(PROPOSAL_INPUT_BYTES, number);
            let aliased_object = aliased.as_object_mut().unwrap();
            let value = aliased_object.remove("a").unwrap();
            aliased_object.insert("a".repeat(64), value);
            assert!(
                registry_platform_canonical_json::canonicalize_json(&aliased)
                    .unwrap()
                    .len()
                    > PROPOSAL_INPUT_BYTES
            );
            fixture
                .client
                .prepare_proposal(&held, operation, json!({"input":aliased}), &key)
                .expect("public aliases do not inflate the stored-input lower bound");
            let restored = BRegPreparedProposal::from_slice(attempt.as_bytes()).unwrap();
            let recovered = fixture.client.recover_proposal(&held, &restored).unwrap();
            assert_eq!(recovered.as_bytes(), attempt.as_bytes());

            let mut saved: Value = serde_json::from_slice(attempt.as_bytes()).unwrap();
            saved["body"] = json!(json!({"input":oversized}).to_string());
            let saved = serde_json::to_vec(&saved).unwrap();
            assert!(saved.len() < registry_breg_client::DEFAULT_MAX_RESPONSE_BYTES as usize);
            assert!(
                BRegPreparedProposal::from_slice(&saved).is_err(),
                "{operation}:{state}:oversized restored input"
            );
            assert_eq!(fixture.token.0.load(Ordering::SeqCst), tokens);
            assert_eq!(fixture.requests.load(Ordering::SeqCst), requests);

            let mut successor = original.clone();
            successor["revision"] = json!(3);
            successor["state"] = json!("draft");
            successor.as_object_mut().unwrap().remove("effectDigest");
            if state == "submitted" {
                successor["submissionVersion"] = json!(2);
            }
            fixture.answer(successor);
            fixture
                .client
                .execute_proposal(&recovered)
                .await
                .expect("exact-boundary attempt is sent once");
            assert_eq!(fixture.token.0.load(Ordering::SeqCst), tokens + 1);
            assert_eq!(fixture.requests.load(Ordering::SeqCst), requests + 1);
        }
    }
}

#[tokio::test]
async fn proposal_pages_require_progress_without_interpreting_opaque_cursors() {
    let fixture = Fixture::start().await;
    let collection = fixture.metadata.select_proposals("writer").unwrap();
    for cursor in [ID.to_owned(), "x".repeat(512)] {
        for items in [json!([]), json!([proposal("draft")])] {
            fixture.answer(json!({"items":items,"nextCursor":cursor}));
            let count = fixture.requests.load(Ordering::SeqCst);
            let error = fixture
                .client
                .list_proposals(
                    &collection,
                    &BRegProposalQuery {
                        cursor: Some(cursor.clone()),
                        ..Default::default()
                    },
                )
                .await
                .err()
                .expect("an echoed cursor must not advance a traversal");
            assert_eq!(error.kind(), "invalid-request");
            assert!(!error.is_outcome_unknown());
            assert_eq!(fixture.requests.load(Ordering::SeqCst), count + 1);
        }
        fixture.answer(json!({"items":[],"nextCursor":cursor}));
        assert!(fixture
            .client
            .list_proposals(&collection, &Default::default())
            .await
            .is_err());
        // A nonempty page may carry an opaque token unrelated to its final ID.
        fixture.answer(json!({"items":[proposal("draft")],"nextCursor":cursor}));
        let page = fixture
            .client
            .list_proposals(&collection, &Default::default())
            .await
            .unwrap()
            .value;
        assert_eq!(page.next_cursor.as_deref(), Some(cursor.as_str()));
        fixture.answer(json!({"items":[]}));
        let count = fixture.requests.load(Ordering::SeqCst);
        assert!(fixture
            .client
            .list_proposals(
                &collection,
                &BRegProposalQuery {
                    cursor: page.next_cursor,
                    ..Default::default()
                }
            )
            .await
            .unwrap()
            .value
            .items
            .is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), count + 1);
    }
}

#[tokio::test]
async fn application_ids_require_canonical_non_nil_identity_and_preserve_exact_recovery() {
    let fixture = Fixture::start().await;
    let binding = fixture.metadata.select_proposal_get("writer").unwrap();
    let collection = fixture.metadata.select_proposals("writer").unwrap();
    let mut original = proposal("submitted");
    original["links"]["apply"] = json!({"method":"POST","path":format!("/v1/proposals/{ID}/apply"),
        "accessProfile":"writer","operation":"apply","ifMatch":"\"condition\""});
    let held = fixture.proposal(original.clone()).await;
    let attempt = fixture
        .client
        .prepare_proposal(
            &held,
            "apply",
            json!({"submissionVersion":1,"effectDigest":DIGEST}),
            &BRegIdempotencyKey::parse("canonical-application-id").unwrap(),
        )
        .unwrap();
    let canonical = "123e4567-e89b-42d3-a456-426614174000";
    let mut receipt = original;
    receipt["state"] = json!("applied");
    receipt["revision"] = json!(3);
    receipt["application"] = json!({"applicationId":canonical,"submissionVersion":1,
        "effectDigest":DIGEST,"resultLinks":[]});
    receipt["links"]["apply"]["availability"] = json!({"available":false,"observedRevision":3,
        "reason":"already-applied","recovery":"receipt-only"});
    for id in [
        canonical.to_uppercase(),
        canonical.replace('-', ""),
        "00000000-0000-0000-0000-000000000000".to_owned(),
    ] {
        let mut invalid = receipt.clone();
        invalid["application"]["applicationId"] = json!(id);
        fixture.answer(invalid.clone());
        for observed in [
            fixture.client.get_proposal(&binding, ID).await,
            fixture.client.read_proposal(&held).await,
        ] {
            let error = observed.expect_err("malformed application identity must be refused");
            assert_eq!(error.kind(), "invalid-request");
            assert!(!error.is_outcome_unknown());
            assert!(!format!("{error:?}").contains(&id));
        }
        let error = fixture
            .client
            .execute_proposal(&attempt)
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), "protocol");
        assert!(error.is_outcome_unknown());
        fixture.answer(json!({"items":[invalid]}));
        assert!(fixture
            .client
            .list_proposals(&collection, &Default::default())
            .await
            .is_err());
    }
    fixture.answer(receipt);
    let committed = fixture
        .client
        .execute_proposal(&attempt)
        .await
        .unwrap()
        .value;
    assert_eq!(committed.application().unwrap().application_id, canonical);
    let count = fixture.requests.load(Ordering::SeqCst);
    let tokens = fixture.token.0.load(Ordering::SeqCst);
    let restored = BRegPreparedProposal::from_slice(attempt.as_bytes()).unwrap();
    let recovered = fixture
        .client
        .recover_proposal(&committed, &restored)
        .unwrap();
    assert_eq!(recovered.as_bytes(), attempt.as_bytes());
    assert_eq!(fixture.requests.load(Ordering::SeqCst), count);
    assert_eq!(fixture.token.0.load(Ordering::SeqCst), tokens);
    assert_eq!(
        fixture
            .client
            .execute_proposal(&recovered)
            .await
            .unwrap()
            .value
            .application()
            .unwrap()
            .application_id,
        canonical
    );
}

#[tokio::test]
async fn attachment_availability_uses_the_same_complete_unavailable_contract_as_lifecycle_links() {
    let fixture = Fixture::start().await;
    let source: Value =
        serde_json::from_slice(include_bytes!("fixtures/attachments.json")).unwrap();
    let mut original = source["proposal"].clone();
    original["links"]["self"] = proposal("draft")["links"]["self"].clone();
    original["links"]["edit"] = json!({"method":"POST","path":format!("/v1/proposals/{ID}/edit"),
        "accessProfile":"writer","operation":"edit","ifMatch":"\"condition\""});
    let held = fixture.proposal(original.clone()).await;
    let binding = fixture.metadata.select_proposal_get("writer").unwrap();
    let collection = fixture.metadata.select_proposals("writer").unwrap();
    let key = BRegIdempotencyKey::parse("attachment-availability").unwrap();
    let attempt = fixture
        .client
        .prepare_proposal(&held, "edit", json!({"input":{}}), &key)
        .unwrap();
    for operation in ["download", "upload", "remove"] {
        for missing in ["reason", "recovery"] {
            let mut invalid = original.clone();
            let mut availability = json!({"available":false,"observedRevision":3,
                "reason":"stale-revision","recovery":"refresh"});
            availability.as_object_mut().unwrap().remove(missing);
            invalid["attachments"]["supporting-file"]["links"][operation]["availability"] =
                availability;
            fixture.answer(invalid.clone());
            assert_eq!(
                fixture
                    .client
                    .get_proposal(&binding, ID)
                    .await
                    .err()
                    .unwrap()
                    .kind(),
                "invalid-request"
            );
            assert_eq!(
                fixture
                    .client
                    .read_proposal(&held)
                    .await
                    .err()
                    .unwrap()
                    .kind(),
                "invalid-request"
            );
            fixture.answer(json!({"items":[invalid.clone()]}));
            assert!(fixture
                .client
                .list_proposals(&collection, &Default::default())
                .await
                .is_err());
            invalid["revision"] = json!(4);
            invalid["attachments"]["supporting-file"]["links"][operation]["availability"]
                ["observedRevision"] = json!(4);
            fixture.answer(invalid);
            let error = fixture
                .client
                .execute_proposal(&attempt)
                .await
                .err()
                .unwrap();
            assert_eq!(error.kind(), "protocol");
            assert!(error.is_outcome_unknown());
            let error = fixture
                .client
                .delete_proposal_attachment(&held, "supporting-file", &key)
                .await
                .err()
                .unwrap();
            assert_eq!(error.kind(), "protocol");
            assert!(error.is_outcome_unknown());
        }
        for availability in [
            json!({"available":true,"observedRevision":3}),
            json!({"available":false,"observedRevision":3,"reason":"stale-revision","recovery":"refresh"}),
        ] {
            let mut valid = original.clone();
            valid["attachments"]["supporting-file"]["links"][operation]["availability"] =
                availability;
            fixture.proposal(valid).await;
        }
    }
    let mut receipt = original;
    receipt["revision"] = json!(4);
    fixture.answer(receipt);
    assert!(fixture.client.execute_proposal(&attempt).await.is_ok());
}
