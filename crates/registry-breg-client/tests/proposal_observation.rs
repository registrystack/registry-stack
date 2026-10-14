// SPDX-License-Identifier: Apache-2.0
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Response, StatusCode},
    routing::get,
    Router,
};
use registry_breg_client::{
    BRegProblemCode, BRegRetryAfter, BaseRegistryClient, BaseRegistryClientConfig, BearerToken,
    TokenError, TokenProvider,
};
use serde_json::{json, Value};

const REVISION: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PROPOSAL: &str = "00000000-0000-4000-8000-000000000001";
const TRACE: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

struct Token;
#[async_trait]
impl TokenProvider for Token {
    async fn bearer_token(&self) -> Result<BearerToken, TokenError> {
        BearerToken::new("observation-token-private-canary")
    }
}

fn response(status: StatusCode, body: Value, media: &str, hint: Option<&str>) -> Response<Body> {
    let mut response = Response::builder()
        .status(status)
        .header("traceparent", TRACE)
        .header("cache-control", "no-store")
        .header("vary", "authorization, accept")
        .header("content-type", media);
    if let Some(hint) = hint {
        response = response.header("retry-after", hint);
    }
    response.body(Body::from(body.to_string())).unwrap()
}

async fn client(
    status: StatusCode,
    body: Value,
    hint: &str,
) -> (
    BaseRegistryClient,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let hint = hint.to_owned();
    let metadata = json!({"metadataVersion":"1","id":"facilities","version":"1","revision":REVISION,"recordTypes":[],"operations":[],
        "proposals":{"get":{"method":"GET","path":"/v1/proposals/{proposal_id}","accessProfiles":["writer"]}}});
    let router = Router::new()
        .route(
            "/v1/registry",
            get(move || {
                let metadata = metadata.clone();
                async move { response(StatusCode::OK, metadata, "application/json", Some("9")) }
            }),
        )
        .route(
            "/v1/proposals/{id}",
            get(move || {
                let body = body.clone();
                let hint = hint.clone();
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    response(
                        status,
                        body,
                        if status.is_success() {
                            "application/json"
                        } else {
                            "application/problem+json"
                        },
                        Some(&hint),
                    )
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let client = BaseRegistryClient::new(
        BaseRegistryClientConfig::new(format!("http://{address}/").parse().unwrap())
            .with_token_provider(Arc::new(Token))
            .with_max_mutation_retries(0),
    )
    .unwrap();
    (client, calls, server)
}

#[tokio::test]
async fn proposal_observation_preserves_retry_after_on_unavailable_response_without_retrying() {
    let code = BRegProblemCode::ServiceUnavailable;
    let (client,calls,server)=client(StatusCode::SERVICE_UNAVAILABLE,json!({"type":format!("https://id.registrystack.org/problems/registry-breg/{}",code.code().replace('.',"/")),
        "title":"Service Unavailable","status":503,"code":code.code(),"detail":code.detail(),"traceId":"4bf92f3577b34da6a3ce929d0e0e4736"}),"17").await;
    let metadata_observation = client.registry_contract_observation(Some("writer")).await;
    assert_eq!(metadata_observation.retry_after, BRegRetryAfter::Seconds(9));
    let binding = metadata_observation
        .outcome
        .unwrap()
        .value
        .select_proposal_get("writer")
        .unwrap();
    let observation = client.get_proposal_observation(&binding, PROPOSAL).await;
    assert_eq!(observation.retry_after, BRegRetryAfter::Seconds(17));
    assert_eq!(
        observation.outcome.as_ref().unwrap_err().status(),
        Some(503)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let debug = format!("{observation:?}");
    assert!(!debug.contains("observation-token-private-canary"));
    assert!(!debug.contains(PROPOSAL));
    assert!(!debug.contains("Service Unavailable"));
    server.abort();
}

#[tokio::test]
async fn invalid_or_overflowing_retry_after_is_a_closed_unusable_hint() {
    for header in [
        "private-header-canary",
        "18446744073709551616",
        "Wed, 21 Oct 2026 07:28:00 GMT",
    ] {
        let (client,calls,server)=client(StatusCode::OK,json!({"id":PROPOSAL,"actionId":"correct-address","actionRevision":REVISION,"submissionVersion":1,"revision":1,"state":"draft","links":{}}),header).await;
        let metadata = client.registry_contract(Some("writer")).await.unwrap();
        let binding = metadata.value.select_proposal_get("writer").unwrap();
        let observation = client.get_proposal_observation(&binding, PROPOSAL).await;
        assert_eq!(observation.retry_after, BRegRetryAfter::Unusable);
        assert!(observation.outcome.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(!format!("{observation:?}").contains(header));
        server.abort();
    }
}
