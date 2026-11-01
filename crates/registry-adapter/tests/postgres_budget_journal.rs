// SPDX-License-Identifier: Apache-2.0

//! Served resource-bound failures are complete, value-free journal terminals.
#![cfg(feature = "postgres-test")]

use std::{collections::BTreeMap, sync::Arc, time::Duration};

#[allow(dead_code)]
#[path = "support/served/mod.rs"]
mod served_harness;

use registry_adapter::engine::exchange::Exchange;
use registry_adapter::engine::resilience::ResilienceRuntime;
use registry_adapter::engine::route::{
    run_route_within, EndpointRuntime, RouteContext, RouteTable,
};
use registry_adapter::engine::scripts::ScriptSet;
use registry_adapter_core::{
    AdapterEndpointBindings, Cidr, ComponentKind, Endpoint, EndpointAuthentication,
    EndpointBinding, ErrorClass, RuntimeCredential, Step,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_yaml::{BoundedU64, ExternalId, LocalId, UniqueIdList, UniqueList, Url};
use serde_json::{json, Value};
use served_harness::upstream::{Response, UpstreamDouble};
use served_harness::{copy_example_project, replace_pack_text, Served};

const SOURCE_CANARY: &str = "source-private-canary-7bcb7521";

async fn assert_terminal(
    served: &Served,
    status: u16,
    body: &Value,
    class: &str,
    problem_code: &str,
) {
    assert_eq!(body["status"], status, "{body}");
    assert_eq!(body["code"], problem_code, "{body}");
    let response_text = body.to_string();
    assert!(response_text.len() < 4_096, "the problem stays bounded");
    assert!(
        !response_text.contains(SOURCE_CANARY),
        "no partial source body reaches the problem"
    );

    let failures = served.journal_details("exchangeFailed").await;
    let terminal = failures.last().expect("one terminal journal event");
    assert_eq!(terminal["class"], class, "{terminal}");
    assert_eq!(terminal["problemCode"], problem_code, "{terminal}");
    assert!(
        !served.journal_text().await.contains(SOURCE_CANARY),
        "no source body reaches any journal event"
    );
}

#[tokio::test]
async fn an_over_bound_source_body_has_one_bounded_problem_and_complete_terminal_journal() {
    let upstream = UpstreamDouble::start();
    let oversized = format!(
        r#"{{"canary":"{}{}"}}"#,
        SOURCE_CANARY,
        "x".repeat(1_100_000)
    );
    upstream.respond_with(vec![Response::json(200, &oversized)]);
    let served = Served::start(&upstream.url("")).await;
    let token = served.token("records.read");

    let (status, _, body) = served.get("/v1/records/person/EeBJ3Sn9uLg", Some(&token));
    assert_eq!(status, 502, "{body}");
    assert_terminal(
        &served,
        status,
        &body,
        "upstream.too-large",
        "source.upstream-error",
    )
    .await;
}

#[tokio::test]
async fn an_attempt_deadline_has_one_bounded_problem_and_complete_terminal_journal() {
    let upstream = UpstreamDouble::start();
    upstream.delay_answers(Duration::from_millis(100));
    let canary = format!(r#"{{"canary":"{SOURCE_CANARY}"}}"#);
    upstream.respond_with(vec![
        Response::json(200, &canary),
        Response::json(200, &canary),
    ]);
    let directory = tempfile::tempdir().expect("a scratch directory");
    copy_example_project(directory.path());
    replace_pack_text(
        directory.path(),
        "    attemptTimeoutMilliseconds: 10000\n",
        "    attemptTimeoutMilliseconds: 1\n",
    );
    let served = Served::start_with_project(&upstream.url(""), directory.path()).await;
    let token = served.token("records.read");

    let (status, _, body) = served.get("/v1/records/person/EeBJ3Sn9uLg", Some(&token));
    assert_eq!(status, 504, "{body}");
    assert_terminal(
        &served,
        status,
        &body,
        "upstream.timeout",
        "source.unavailable",
    )
    .await;
}

#[tokio::test]
async fn the_kernel_stops_before_a_send_over_the_call_budget() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![
        Response::json(200, r#"{"ok":true}"#),
        Response::json(200, r#"{"private":"must-not-send"}"#),
    ]);
    let route: Vec<Step> = serde_json::from_value(json!([
        {"to": {"uri": "http:source", "parameters": {"httpMethod": "GET", "path": "/one"}}},
        {"to": {"uri": "http:source", "parameters": {"httpMethod": "GET", "path": "/two"}}}
    ]))
    .expect("the route parses");
    let declared = Endpoint {
        id: LocalId::new("source").expect("endpoint id"),
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
    };
    let config = AdapterEndpointBindings {
        id: LocalId::new("budget-runtime").expect("runtime id"),
        endpoints: UniqueIdList::new(vec![EndpointBinding {
            endpoint: ExternalId::new("source").expect("endpoint id"),
            base_url: Url::new(upstream.url("/")).expect("loopback base URL"),
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
    };
    let resolver =
        SecretResolver::new([SecretProvider::Environment], "").expect("the resolver builds");
    let binding = config.endpoints.iter().next().expect("the binding");
    let runtime = EndpointRuntime::compile(binding, &declared, &config, &resolver)
        .expect("the endpoint compiles");
    let endpoints = BTreeMap::from([("source".to_owned(), runtime)]);
    let scripts = ScriptSet::default();
    let resilience = ResilienceRuntime::compile(&route);
    let routes = RouteTable::new();
    let context = RouteContext {
        endpoints: &endpoints,
        scripts: &scripts,
        resolver: &resolver,
        resilience: &resilience,
        routes: &routes,
        code_maps: Arc::new(BTreeMap::new()),
        maximum_upstream_calls: 1,
        job: registry_adapter::engine::job_sources::JobPageState::default(),
    };

    let outcome = run_route_within(
        &context,
        &route,
        Exchange::new("call-budget".to_owned()),
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(
        outcome
            .result
            .expect_err("the second send is refused")
            .class,
        ErrorClass::BudgetExhausted
    );
    assert_eq!(
        upstream.request_count(),
        1,
        "the over-budget send never reaches the source"
    );
}
