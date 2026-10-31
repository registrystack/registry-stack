// SPDX-License-Identifier: Apache-2.0

//! Actual-HTTP fault and pagination transcripts from `CONCEPT.md` section
//! 13.4. The loopback double speaks TCP, so these exercise the transport and
//! route interpreter together rather than substituting a send function.

#[path = "support/upstream/mod.rs"]
#[allow(dead_code)]
mod upstream;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use registry_adapter::exchange::Exchange;
use registry_adapter::resilience::ResilienceRuntime;
use registry_adapter::route::{
    run_route_within, EndpointRuntime, RouteContext, RouteOutcome, RouteTable,
};
use registry_adapter::scripts::ScriptSet;
use registry_adapter_core::{
    Cidr, ComponentKind, Endpoint, EndpointAuthentication, EndpointBinding, ErrorClass, RuntimeCredential, Step, AdapterEndpointBindings,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_yaml::{
    BoundedU64, ExternalId, LocalId, UniqueIdList, UniqueList, Url,
};
use serde_json::{json, Value};

const PRIVATE_MARKER: &str = "partial-record-must-not-escape";

fn local(value: &str) -> LocalId {
    LocalId::new(value).expect("a local id")
}

fn external(value: &str) -> ExternalId {
    ExternalId::new(value).expect("an external id")
}

fn steps(value: Value) -> Vec<Step> {
    serde_json::from_value(value).expect("the route parses")
}

fn endpoint() -> Endpoint {
    Endpoint {
        id: local("source"),
        component: ComponentKind::Http,
        authentication: EndpointAuthentication::None {},
        attempt_timeout_milliseconds: BoundedU64::new(5_000).expect("attempt bound"),
        maximum_response_bytes: BoundedU64::new(65_536).expect("response bound"),
        response_headers: UniqueList::new(Vec::new()).expect("empty headers"),
        request_headers: UniqueList::new(Vec::new()).expect("empty headers"),
        operations: Vec::new(),
        tested_versions: vec!["test".to_owned()],
        query_file: None,
        operation_name: None,
        variables: None,
    }
}

fn runtime_config(base_url: &str) -> AdapterEndpointBindings {
    AdapterEndpointBindings {
        id: local("fault-runtime"),
        endpoints: UniqueIdList::new(vec![EndpointBinding {
            endpoint: external("source"),
            base_url: Url::new(base_url).expect("loopback base URL"),
            credential: Some(RuntimeCredential::None {}),
            anonymous_https: None,
            tls_trust_profile: None,
            mtls_identity: None,
            attempt_timeout_milliseconds: None,
            maximum_response_bytes: None,
        }])
        .expect("one endpoint"),
        allowed_private_cidrs: UniqueList::new(vec![
            Cidr::new("192.168.0.0/16").expect("private CIDR")
        ])
        .expect("one CIDR"),
        outbound_tls: None,
    }
}

async fn run(
    double: &upstream::UpstreamDouble,
    route: &[Step],
    body: Value,
    deadline: Duration,
    maximum_upstream_calls: u64,
) -> RouteOutcome {
    run_timed(double, route, body, deadline, maximum_upstream_calls)
        .await
        .0
}

async fn run_timed(
    double: &upstream::UpstreamDouble,
    route: &[Step],
    body: Value,
    deadline: Duration,
    maximum_upstream_calls: u64,
) -> (RouteOutcome, Duration) {
    let resolver =
        SecretResolver::new([SecretProvider::Environment], "").expect("the resolver builds");
    let config = runtime_config(&double.url("/"));
    let binding = config.endpoints.iter().next().expect("the binding");
    let runtime = EndpointRuntime::compile(binding, &endpoint(), &config, &resolver)
        .expect("the endpoint compiles");
    let endpoints = BTreeMap::from([("source".to_owned(), runtime)]);
    let scripts = ScriptSet::default();
    let resilience = ResilienceRuntime::compile(route);
    let routes = RouteTable::new();
    let context = RouteContext {
        endpoints: &endpoints,
        scripts: &scripts,
        resolver: &resolver,
        resilience: &resilience,
        routes: &routes,
        code_maps: Arc::new(BTreeMap::new()),
        maximum_upstream_calls,
        job: registry_adapter::job_sources::JobPageState::default(),
    };
    let mut exchange = Exchange::new("upstream-fault".to_owned());
    exchange.message.body = body;
    let started = Instant::now();
    let outcome = run_route_within(&context, route, exchange, deadline).await;
    (outcome, started.elapsed())
}

fn one_get() -> Vec<Step> {
    steps(json!([{
        "to": {
            "uri": "http:source",
            "parameters": {"httpMethod": "GET", "path": "/pages"}
        }
    }]))
}

fn pagination_route() -> Vec<Step> {
    let get = json!({
        "to": {
            "uri": "http:source",
            "parameters": {"httpMethod": "GET", "path": "/pages"}
        }
    });
    steps(json!([{
        "split": {
            "expression": {"constant": [0, 1, 2]},
            "maximumItems": 3,
            "aggregationStrategy": {
                "type": "json-array-append",
                "from": "page",
                "into": "records",
                "uniqueBy": "id"
            },
            "steps": [
                get,
                {"setProperty": {"name": "page", "value": {"jsonpath": "$.entries"}}}
            ]
        }
    }]))
}

fn assert_value_free_failure(outcome: RouteOutcome, expected: ErrorClass) {
    let failure = outcome
        .result
        .expect_err("the route must not release an exchange");
    assert_eq!(failure.class, expected);
    assert_eq!(
        failure.message, None,
        "terminal failure carries no source value"
    );
    assert_eq!(failure.auth, None, "terminal failure carries no auth value");
    let event_details = Value::Array(
        outcome
            .events
            .into_iter()
            .map(|event| event.detail)
            .collect(),
    );
    assert!(
        !event_details.to_string().contains(PRIVATE_MARKER),
        "the journal facts must not carry the partial record"
    );
}

#[tokio::test]
async fn a_mid_body_connection_reset_releases_no_partial_record() {
    let double = upstream::UpstreamDouble::start();
    let body = json!({"records": [{"id": PRIVATE_MARKER}]}).to_string();
    double.respond_with_reset(upstream::Response::json(200, &body), body.len() - 2);

    let outcome = run(&double, &one_get(), json!({}), Duration::from_secs(1), 1).await;

    assert_value_free_failure(outcome, ErrorClass::UpstreamConnection);
    assert_eq!(
        double.request_count(),
        1,
        "one bounded real HTTP send occurred"
    );
}

#[tokio::test]
async fn a_slow_trickle_spends_the_total_route_deadline() {
    let double = upstream::UpstreamDouble::start();
    double.respond_with_trickle(
        upstream::Response::json(
            200,
            &json!({"records": [{"id": PRIVATE_MARKER}]}).to_string(),
        ),
        1,
        Duration::from_millis(20),
    );
    let (outcome, elapsed) =
        run_timed(&double, &one_get(), json!({}), Duration::from_millis(60), 1).await;

    assert_value_free_failure(outcome, ErrorClass::BudgetExhausted);
    assert!(elapsed < Duration::from_millis(500));
    assert_eq!(double.request_count(), 1, "the trickle is never retried");
}

#[tokio::test]
async fn pagination_transcripts_refuse_duplicates_and_shifts_but_accept_an_empty_page() {
    let route = pagination_route();
    for (name, pages) in [
        (
            "duplicate",
            vec![
                json!({"entries": [{"id": "a"}]}),
                json!({"entries": [{"id": "a"}]}),
                json!({"entries": [{"id": "never"}]}),
            ],
        ),
        (
            "shifting",
            vec![
                json!({"entries": [{"id": "a"}, {"id": "b"}]}),
                json!({"entries": [{"id": "b"}, {"id": "c"}]}),
                json!({"entries": [{"id": "never"}]}),
            ],
        ),
    ] {
        let double = upstream::UpstreamDouble::start();
        double.respond_with(
            pages
                .iter()
                .map(|page| upstream::Response::json(200, &page.to_string()))
                .collect(),
        );
        let outcome = run(
            &double,
            &route,
            json!({"records": []}),
            Duration::from_secs(1),
            3,
        )
        .await;
        assert_value_free_failure(outcome, ErrorClass::AggregationDuplicate);
        assert_eq!(
            double.request_count(),
            2,
            "{name} transcript stops at its first repeated identifier"
        );
    }

    let empty = upstream::UpstreamDouble::start();
    empty.respond_with(vec![
        upstream::Response::json(200, r#"{"entries":[{"id":"a"}]}"#),
        upstream::Response::json(200, r#"{"entries":[]}"#),
        upstream::Response::json(200, r#"{"entries":[{"id":"b"}]}"#),
    ]);
    let outcome = run(
        &empty,
        &route,
        json!({"records": []}),
        Duration::from_secs(1),
        3,
    )
    .await;
    let exchange = outcome
        .result
        .expect("an empty middle page is well-defined");
    assert_eq!(
        exchange.message.body,
        json!({"records": [{"id": "a"}, {"id": "b"}]})
    );
    assert_eq!(
        empty.request_count(),
        3,
        "the transcript is statically bounded"
    );
}
