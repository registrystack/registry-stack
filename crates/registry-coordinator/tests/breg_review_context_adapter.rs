// SPDX-License-Identifier: Apache-2.0
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use registry_breg_client::{BaseRegistryClient, BaseRegistryClientConfig, StaticToken};
use registry_coordinator::{breg_review_context, protocol::CallOutcome};
use serde_json::{json, Value};
use wiremock::{
    matchers::{header, method, path, query_param},
    Mock, MockServer, Request, ResponseTemplate,
};

const ID: &str = "00000000-0000-4000-8000-000000000001";
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const TRACE: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

fn contract() -> Value {
    json!({"id":"urn:registry:breg:review-context:source:correct-name:assessment",
        "revision":DIGEST,"schemaDigest":DIGEST})
}

fn input() -> Value {
    json!({"actionId":"correct-name","contract":contract(),
        "subject":{"source":"source","type":"proposal","id":ID,"version":"1","digest":DIGEST}})
}

fn document() -> Value {
    json!({"id":ID,"actionId":"correct-name","actionRevision":DIGEST,
        "submissionVersion":1,"revision":1,"effectDigest":DIGEST,
        "subject":{"source":"source","subjectType":"proposal","id":ID,"version":"1","digest":DIGEST},
        "context":{"reference":"native-proposal","contract":contract(),
            "fields":{"operatorActive":true,"requestedName":"Requested name"}},"reviewable":true})
}

fn metadata(revision: &str, operation: &str) -> Value {
    json!({"metadataVersion":"1","id":"source","version":"1","revision":revision,
        "recordTypes":[],"operations":[],"proposals":{"actions":[
            {"actionId":"correct-name","accessProfile":"assessment","operations":[operation]}]}})
}

fn response(value: Value) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("traceparent", TRACE)
        .insert_header("cache-control", "no-store")
        .insert_header("vary", "authorization, accept")
        .set_body_json(value)
}

fn client(server: &MockServer) -> BaseRegistryClient {
    BaseRegistryClient::new(
        BaseRegistryClientConfig::new(server.uri().parse().unwrap())
            .with_token_provider(Arc::new(StaticToken::new("assessment-bearer").unwrap())),
    )
    .unwrap()
}

async fn source(server: &MockServer, value: Value) {
    Mock::given(method("GET"))
        .and(path("/v1/registry"))
        .and(query_param("accessProfile", "assessment"))
        .and(header("authorization", "Bearer assessment-bearer"))
        .respond_with(response(metadata(DIGEST, "get-review-context")))
        .mount(server)
        .await;
    context(server, value).await;
}

async fn context(server: &MockServer, value: Value) {
    Mock::given(method("GET"))
        .and(path(format!("/v1/proposals/{ID}/review-context")))
        .and(query_param("accessProfile", "assessment"))
        .and(header("authorization", "Bearer assessment-bearer"))
        .respond_with(response(value))
        .mount(server)
        .await;
}

#[tokio::test]
async fn assessment_reads_only_exact_frozen_requested_values_and_current_source_fields() {
    let server = MockServer::start().await;
    source(&server, document()).await;
    let CallOutcome::Success(value) =
        breg_review_context::read(&client(&server), "assessment", &input()).await
    else {
        panic!("explicit assessment context should be available");
    };
    assert_eq!(value["subject"], input()["subject"]);
    assert_eq!(value["contract"], contract());
    assert_eq!(
        value["fields"],
        json!({"operatorActive":true,"requestedName":"Requested name"})
    );
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 3);
    assert!(requests.iter().all(|request| request.method == "GET"));
    assert!(requests
        .iter()
        .all(|request| !request.url.path().ends_with("review-status")));
    assert!(!value.to_string().contains("assessment-bearer"));
}

#[tokio::test]
async fn changed_subject_contract_and_nonreviewable_source_cannot_release_assessment_fields() {
    let mut variants = Vec::new();
    for field in ["source", "subjectType", "id", "version", "digest"] {
        let mut value = document();
        value["subject"][field] = json!(match field {
            "digest" => OTHER,
            "id" => "00000000-0000-4000-8000-000000000002",
            "version" => "2",
            _ => "other",
        });
        if field == "version" {
            value["submissionVersion"] = json!(2);
        }
        if field == "digest" {
            value["effectDigest"] = json!(OTHER);
        }
        variants.push(value);
    }
    for field in ["id", "revision", "schemaDigest"] {
        let mut value = document();
        value["context"]["contract"][field] = json!(if field == "id" {
            "urn:registry:breg:review-context:source:other:assessment"
        } else {
            OTHER
        });
        variants.push(value);
    }
    let mut blocked = document();
    blocked["reviewable"] = json!(false);
    variants.push(blocked);
    for value in variants {
        let server = MockServer::start().await;
        source(&server, value).await;
        assert!(matches!(
            breg_review_context::read(&client(&server), "assessment", &input()).await,
            CallOutcome::Refused { .. }
        ));
    }
}

#[tokio::test]
async fn status_only_profile_cannot_be_promoted_to_assessment_and_no_fallback_occurs() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/registry"))
        .and(query_param("accessProfile", "assessment"))
        .respond_with(response(metadata(DIGEST, "get-review-status")))
        .mount(&server)
        .await;
    let answer = breg_review_context::read(&client(&server), "assessment", &input()).await;
    assert!(matches!(answer, CallOutcome::Refused { code } if code == "product-forbidden"));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn unrelated_registry_activation_preserves_context_but_revoked_context_grant_refuses() {
    for revoked in [false, true] {
        let server = MockServer::start().await;
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        Mock::given(method("GET"))
            .and(path("/v1/registry"))
            .and(query_param("accessProfile", "assessment"))
            .respond_with(move |_: &Request| {
                let later = observed.fetch_add(1, Ordering::SeqCst) > 0;
                response(metadata(
                    if later { OTHER } else { DIGEST },
                    if later && revoked {
                        "get-review-status"
                    } else {
                        "get-review-context"
                    },
                ))
            })
            .mount(&server)
            .await;
        context(&server, document()).await;
        let answer = breg_review_context::read(&client(&server), "assessment", &input()).await;
        assert_eq!(matches!(answer, CallOutcome::Success(_)), !revoked);
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn invalid_locator_and_unrecognized_input_fail_before_source_io() {
    let server = MockServer::start().await;
    for value in [
        {
            let mut value = input();
            value["subject"]["id"] = json!("../other");
            value
        },
        {
            let mut value = input();
            value["subject"]["type"] = json!("record");
            value
        },
        {
            let mut value = input();
            value["subject"]["version"] = json!("01");
            value
        },
        {
            let mut value = input();
            value["credential"] = json!("human-token-canary");
            value
        },
    ] {
        assert!(
            matches!(breg_review_context::read(&client(&server), "assessment", &value).await,
            CallOutcome::Refused { code } if code == "invalid-command")
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}
