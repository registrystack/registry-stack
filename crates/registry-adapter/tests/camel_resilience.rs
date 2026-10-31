// SPDX-License-Identifier: Apache-2.0

//! The resilience conformance suite: `circuitBreaker` and `throttle`
//! (`products/adapter/CONCEPT.md` sections 8.6 and 8.7, port-table rows
//! 32 and 33).
//!
//! Every send goes over the loopback double, so pacing and breaking are
//! observed against real requests the double counts, and one lane holds
//! one resilience runtime across every exchange it runs, the way a
//! served operation does for the process lifetime.

use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use registry_adapter::exchange::Exchange;
use registry_adapter::resilience::ResilienceRuntime;
use registry_adapter::route::{
    check_servable, run_route, run_route_within, EndpointRuntime, RouteContext, RouteFailure,
    RouteOutcome, RouteTable,
};
use registry_adapter::scripts::ScriptSet;
use registry_adapter_core::{
    AdapterRuntimeConfig, ComponentKind, Endpoint, EndpointAuthentication, EndpointBinding,
    RuntimeCredential, Step,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_yaml::{
    BoundedU64, ExternalId, LocalId, SecretReference, UniqueIdList, UniqueList, Url,
};
use serde_json::{json, Value};

/// The empty code-map table: no test lane here converts.
fn empty_code_maps() -> registry_adapter::scripts::CodeMaps {
    std::sync::Arc::new(std::collections::BTreeMap::new())
}

#[path = "support/upstream/mod.rs"]
#[allow(dead_code)]
mod upstream;

fn steps(value: Value) -> Vec<Step> {
    serde_json::from_value(value).expect("the steps parse")
}

/// One endpoint over the loopback double: static-api-key http, the same
/// shape the error cluster suite sends through.
fn resilience_endpoints(
    base_url: &str,
    resolver: &SecretResolver,
) -> BTreeMap<String, EndpointRuntime> {
    let binding = EndpointBinding {
        endpoint: ExternalId::new("tracker").expect("endpoint id"),
        base_url: Url::new(base_url).expect("base url"),
        credential: Some(RuntimeCredential::StaticApiKey {
            value_ref: SecretReference::new("secret:env/RESILIENCE_KEY").expect("secret reference"),
        }),
        anonymous_https: None,
        tls_trust_profile: None,
        mtls_identity: None,
        attempt_timeout_milliseconds: None,
        maximum_response_bytes: None,
    };
    let endpoint = Endpoint {
        id: LocalId::new("tracker").expect("endpoint id"),
        component: ComponentKind::Http,
        authentication: EndpointAuthentication::StaticApiKey {
            header_name: "x-api-key".to_owned(),
        },
        attempt_timeout_milliseconds: BoundedU64::new(10_000).expect("attempt timeout"),
        maximum_response_bytes: BoundedU64::new(65_536).expect("response bound"),
        response_headers: UniqueList::new(Vec::new()).expect("response headers"),
        request_headers: UniqueList::new(Vec::new()).expect("request headers"),
        operations: Vec::new(),
        tested_versions: Vec::new(),
        query_file: None,
        operation_name: None,
        variables: None,
    };
    let config = AdapterRuntimeConfig {
        id: LocalId::new("resilience").expect("deployment id"),
        endpoints: UniqueIdList::new(vec![binding]).expect("bindings"),
        allowed_private_cidrs: UniqueList::new(vec![registry_adapter_core::Cidr::new(
            "192.168.0.0/16",
        )
        .expect("cidrs")])
        .expect("cidrs"),
        outbound_tls: None,
        listener: serde_json::from_str(r#"{ "bind": "127.0.0.1:8080" }"#).expect("listener"),
        database: serde_json::from_str(
            r#"{
                "runtimeUrlRef": "secret:env/RESILIENCE_DB",
                "migrationUrlRef": "secret:env/RESILIENCE_DB"
            }"#,
        )
        .expect("database"),
        oidc: serde_json::from_str(
            r#"{ "issuer": "https://issuer.example.invalid", "audience": "resilience" }"#,
        )
        .expect("oidc"),
        allowed_clients: UniqueList::new(vec![
            ExternalId::new("resilience-client").expect("client")
        ])
        .expect("clients"),
        audit: registry_adapter_core::AuditRetention {
            retention_days: registry_platform_yaml::BoundedU32::<1, 3_650>::new(90)
                .expect("retention"),
        },
        cursor_key_ref: None,
        previous_cursor_key_ref: None,
        cursor_ttl_seconds: None,
        idempotency: None,
    };
    let binding = config.endpoints.iter().next().expect("the binding");
    let runtime = EndpointRuntime::compile(binding, &endpoint, &config, resolver)
        .expect("the endpoint compiles");
    let mut endpoints = BTreeMap::new();
    endpoints.insert("tracker".to_owned(), runtime);
    endpoints
}

/// A `to` send to the double over GET.
fn get() -> Value {
    json!({"to": {"uri": "http:tracker", "parameters": {"httpMethod": "GET", "path": "/thing"}}})
}

/// A `circuitBreaker` over `body` with a small, declared configuration.
fn breaker(body: Value, members: Value) -> Value {
    let mut node = json!({
        "failureRateThreshold": 50,
        "slidingWindowCalls": 2,
        "minimumNumberOfCalls": 2,
        "openStateWaitSeconds": 60,
        "maximumHalfOpenCalls": 10
    });
    if let Value::Object(extra) = members {
        for (key, value) in extra {
            node[key] = value;
        }
    }
    node["steps"] = json!([body]);
    json!({"circuitBreaker": node})
}

/// A `throttle` over `body` with a small, declared configuration.
fn throttle(body: Value, members: Value) -> Value {
    let mut node = json!({
        "limit": {"constant": 1},
        "timePeriodMilliseconds": 60_000
    });
    if let Value::Object(extra) = members {
        for (key, value) in extra {
            node[key] = value;
        }
    }
    node["steps"] = json!([body]);
    json!({"throttle": node})
}

/// One lane: the double, the endpoints, the parsed steps, and the one
/// resilience runtime every exchange of the lane runs under, the way a
/// served operation holds its state for the process lifetime.
struct Lane {
    double: upstream::UpstreamDouble,
    endpoints: BTreeMap<String, EndpointRuntime>,
    scripts: ScriptSet,
    resolver: SecretResolver,
    resilience: ResilienceRuntime,
    steps: Vec<Step>,
}

impl Lane {
    fn over(step_list: Value) -> Self {
        let double = upstream::UpstreamDouble::start();
        std::env::set_var("RESILIENCE_KEY", "resilience-key");
        let resolver = SecretResolver::new([SecretProvider::Environment], "")
            .expect("the environment resolver builds");
        let endpoints = resilience_endpoints(&double.url("/"), &resolver);
        let steps = steps(step_list);
        let resilience = ResilienceRuntime::compile(&steps);
        Self {
            double,
            endpoints,
            scripts: ScriptSet::default(),
            resolver,
            resilience,
            steps,
        }
    }

    fn replies(&self, statuses: &[u16]) {
        self.double.respond_with(
            statuses
                .iter()
                .map(|status| upstream::Response::json(*status, r#"{"thing":"yes"}"#))
                .collect(),
        );
    }

    async fn run(&self) -> RouteOutcome {
        self.run_exchange(Exchange::new("resilience".to_owned()))
            .await
    }

    /// One run with a prepared exchange, used when an expression reads a
    /// caller-controlled test header.
    async fn run_exchange(&self, exchange: Exchange) -> RouteOutcome {
        let routes = RouteTable::new();
        let context = RouteContext {
            endpoints: &self.endpoints,
            scripts: &self.scripts,
            resolver: &self.resolver,
            resilience: &self.resilience,
            routes: &routes,
            code_maps: empty_code_maps(),
            maximum_upstream_calls: 12,
            job: registry_adapter::job_sources::JobPageState::default(),
        };
        run_route(&context, &self.steps, exchange).await
    }

    /// One run under an explicit exchange deadline, the way a caller
    /// bounds the whole exchange.
    async fn run_within(&self, deadline: Duration) -> RouteOutcome {
        let routes = RouteTable::new();
        let context = RouteContext {
            endpoints: &self.endpoints,
            scripts: &self.scripts,
            resolver: &self.resolver,
            resilience: &self.resilience,
            routes: &routes,
            code_maps: empty_code_maps(),
            maximum_upstream_calls: 12,
            job: registry_adapter::job_sources::JobPageState::default(),
        };
        run_route_within(
            &context,
            &self.steps,
            Exchange::new("resilience".to_owned()),
            deadline,
        )
        .await
    }

    fn requests(&self) -> usize {
        self.double.request_count()
    }

    /// Wait until the loopback double has recorded `expected` requests.
    /// Recording happens before its test-only answer delay, so this is an
    /// admission barrier rather than a timing assertion.
    async fn wait_for_requests(&self, expected: usize) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while self.requests() < expected {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the admitted requests reach the loopback double");
    }
}

fn failed(outcome: &RouteOutcome) -> &RouteFailure {
    outcome.result.as_ref().expect_err("the exchange fails")
}

fn failed_class(outcome: &RouteOutcome) -> &'static str {
    failed(outcome).class.class()
}

fn ok(outcome: &RouteOutcome) -> &registry_adapter::exchange::Exchange {
    outcome.result.as_ref().expect("the exchange completes")
}

fn has_event(outcome: &RouteOutcome, kind: &str) -> bool {
    outcome.events.iter().any(|event| event.kind == kind)
}

#[tokio::test]
/// Two failures fill the count window and the next call is rejected, as in
/// Camel's resilience4j EIP test
/// (`camel-4.23.0:components/camel-resilience4j/src/test/java/org/apache/camel/component/resilience4j/ResilienceOpenWithFallbackExchangePropertyTest.java#testRejectedOnlyWhenBreakerOpen`).
/// The Adapter's rejection raises `breaker.open`, its recorded divergence
/// from <https://camel.apache.org/components/4.23.x/eips/resilience4j-eip.html>.
async fn a_failure_storm_opens_the_breaker_and_refuses_without_calling() {
    let lane = Lane::over(json!([breaker(get(), json!({}))]));
    lane.replies(&[500, 500, 200]);
    let first = lane.run().await;
    assert_eq!(failed_class(&first), "upstream.http");
    assert_eq!(lane.requests(), 1);
    let second = lane.run().await;
    assert_eq!(failed_class(&second), "upstream.http");
    assert_eq!(lane.requests(), 2, "the window holds two failures now");
    // The breaker is open: the third exchange is refused before any
    // send, with the adapter's own refusal class.
    let third = lane.run().await;
    assert_eq!(failed_class(&third), "breaker.open");
    assert_eq!(
        lane.requests(),
        2,
        "a refused exchange never reaches the source"
    );
    assert!(has_event(&third, "breakerRefused"));
}

#[tokio::test]
/// Camel passes the slow-call duration and rate thresholds into resilience4j
/// (`camel-4.23.0:components/camel-resilience4j/src/main/java/org/apache/camel/component/resilience4j/ResilienceReifier.java#configureCircuitBreaker`).
/// This processor-level case records one delayed success and one fast success
/// in the same two-call window. The resulting 50 percent slow-call rate opens
/// the breaker without treating either HTTP response as a failure.
async fn successful_slow_calls_open_at_the_authored_duration_and_rate() {
    let lane = Lane::over(json!([breaker(
        get(),
        json!({
            "slowCallDurationThresholdSeconds": 1,
            "slowCallRateThreshold": 50
        }),
    )]));
    lane.replies(&[200, 200, 200]);

    lane.double.delay_answers(Duration::from_millis(1_100));
    assert!(lane.run().await.result.is_ok(), "the slow call succeeds");
    lane.double.delay_answers(Duration::ZERO);
    assert!(lane.run().await.result.is_ok(), "the fast call succeeds");
    assert_eq!(lane.requests(), 2, "both judged calls reached the source");

    let refused = lane.run().await;
    assert_eq!(failed_class(&refused), "breaker.open");
    assert_eq!(
        lane.requests(),
        2,
        "the exact 50 percent slow-call rate opened the breaker"
    );
}

#[tokio::test]
/// Camel delegates omitted breaker settings to resilience4j defaults through
/// `camel-4.23.0:components/camel-resilience4j/src/main/java/org/apache/camel/component/resilience4j/ResilienceReifier.java#configureCircuitBreaker`.
/// The Adapter authors those defaults explicitly. One lane proves the
/// 100-call minimum; a second proves the 100-call window by opening only when
/// call 101 evicts the oldest success and raises the retained failure rate to
/// the default 50 percent threshold.
async fn default_breaker_enforces_one_hundred_call_minimum_and_window() {
    let minimum_lane = Lane::over(json!([{
        "circuitBreaker": {"steps": [get()]}
    }]));
    minimum_lane.replies(&[500; 100]);

    for expected_requests in 1..=99 {
        assert_eq!(failed_class(&minimum_lane.run().await), "upstream.http");
        assert_eq!(
            minimum_lane.requests(),
            expected_requests,
            "every call below the default minimum reaches the source"
        );
    }
    assert_eq!(failed_class(&minimum_lane.run().await), "upstream.http");
    assert_eq!(minimum_lane.requests(), 100, "call 100 meets the minimum");
    let refused = minimum_lane.run().await;
    assert_eq!(failed_class(&refused), "breaker.open");
    assert_eq!(
        minimum_lane.requests(),
        100,
        "call 101 is refused after the minimum permits judgment"
    );

    let window_lane = Lane::over(json!([{
        "circuitBreaker": {"steps": [get()]}
    }]));
    let mut statuses = vec![200; 51];
    statuses.extend([500; 50]);
    window_lane.replies(&statuses);

    for _ in 0..51 {
        assert!(
            window_lane.run().await.result.is_ok(),
            "a success is admitted"
        );
    }
    for _ in 0..49 {
        assert_eq!(failed_class(&window_lane.run().await), "upstream.http");
    }
    assert_eq!(
        window_lane.requests(),
        100,
        "49 failures in the first 100 calls leave the breaker closed"
    );

    assert_eq!(failed_class(&window_lane.run().await), "upstream.http");
    assert_eq!(
        window_lane.requests(),
        101,
        "call 101 is admitted before its result updates the window"
    );
    let refused = window_lane.run().await;
    assert_eq!(failed_class(&refused), "breaker.open");
    assert_eq!(
        window_lane.requests(),
        101,
        "the retained 100 calls contain 50 failures after one success is evicted"
    );
}

#[tokio::test]
/// Camel runs `onFallback` for a guarded failure and for an open-breaker
/// rejection
/// (`camel-4.23.0:components/camel-resilience4j/src/test/java/org/apache/camel/component/resilience4j/ResilienceRouteFallbackTest.java#testResilience`,
/// `camel-4.23.0:components/camel-resilience4j/src/test/java/org/apache/camel/component/resilience4j/ResilienceOpenWithFallbackExchangePropertyTest.java#testRejectedOnlyWhenBreakerOpen`;
/// <https://camel.apache.org/components/4.23.x/eips/resilience4j-eip.html>).
async fn on_fallback_answers_on_failure_and_on_rejection() {
    let fallback = json!({"onFallback": {"steps": [
        {"setProperty": {"name": "saw", "value": {"constant": "fallback"}}}
    ]}});
    let mut node = breaker(
        get(),
        json!({"minimumNumberOfCalls": 1, "slidingWindowCalls": 1}),
    );
    node["circuitBreaker"]["onFallback"] = fallback["onFallback"].clone();
    let lane = Lane::over(json!([node]));
    lane.replies(&[500]);
    // A failing guarded call runs the fallback and completes the route.
    let first = lane.run().await;
    assert_eq!(ok(&first).property("saw"), Some(&json!("fallback")));
    assert_eq!(lane.requests(), 1);
    assert!(first.events.iter().any(|event| {
        event.kind == "breakerFallback" && event.detail["class"] == json!("upstream.http")
    }));
    // The breaker opened on that failure; the next exchange is refused
    // and answered by the same fallback, with no send.
    let second = lane.run().await;
    assert_eq!(ok(&second).property("saw"), Some(&json!("fallback")));
    assert_eq!(lane.requests(), 1, "the rejected exchange sends nothing");
    assert!(second.events.iter().any(|event| {
        event.kind == "breakerFallback" && event.detail["class"] == json!("breaker.open")
    }));
}

#[tokio::test]
/// A configured recorded parent matches its descendant while an unrelated
/// exception is not recorded, adapted from Camel's IOException and
/// FileNotFoundException cases
/// (`camel-4.23.0:components/camel-resilience4j/src/test/java/org/apache/camel/component/resilience4j/ResilienceRecordExceptionTest.java#testFile`,
/// `camel-4.23.0:components/camel-resilience4j/src/test/java/org/apache/camel/component/resilience4j/ResilienceRecordExceptionTest.java#testKaboom`;
/// <https://camel.apache.org/components/4.23.x/eips/resilience4j-eip.html>).
async fn record_exception_matches_descendants_and_only_recorded_failures_use_fallback() {
    let fallback = json!({"steps": [
        {"setProperty": {"name": "saw", "value": {"constant": "fallback"}}}
    ]});

    let mut matched = breaker(
        get(),
        json!({
            "minimumNumberOfCalls": 1,
            "slidingWindowCalls": 1,
            "recordException": ["upstream"]
        }),
    );
    matched["circuitBreaker"]["onFallback"] = fallback.clone();
    let lane = Lane::over(json!([matched]));
    lane.replies(&[500]);
    let outcome = lane.run().await;
    assert_eq!(ok(&outcome).property("saw"), Some(&json!("fallback")));
    assert!(outcome.events.iter().any(|event| {
        event.kind == "breakerFallback" && event.detail["class"] == json!("upstream.http")
    }));

    let mut missed = breaker(
        get(),
        json!({
            "minimumNumberOfCalls": 1,
            "slidingWindowCalls": 1,
            "recordException": ["upstream.timeout"]
        }),
    );
    missed["circuitBreaker"]["onFallback"] = fallback;
    let lane = Lane::over(json!([missed]));
    lane.replies(&[500, 200]);
    let first = lane.run().await;
    assert!(first.result.is_ok(), "a recordException miss continues");
    assert_eq!(ok(&first).property("saw"), None, "fallback does not run");
    assert!(first.events.iter().any(|event| {
        event.kind == "exchangeFailureHandled"
            && event.detail["source"] == json!("circuitBreaker")
            && event.detail["class"] == json!("upstream.http")
    }));
    assert!(lane.run().await.result.is_ok());
    assert_eq!(lane.requests(), 2, "the record miss counted as success");
}

#[tokio::test]
/// Camel gives `ignoreException` precedence when its subclass also matches
/// `recordException`
/// (`camel-4.23.0:components/camel-resilience4j/src/test/java/org/apache/camel/component/resilience4j/ResilienceRecordIgnoreExceptionTest.java#testFile`,
/// `camel-4.23.0:components/camel-resilience4j/src/test/java/org/apache/camel/component/resilience4j/ResilienceRecordIgnoreExceptionTest.java#testIo`;
/// <https://camel.apache.org/components/4.23.x/eips/resilience4j-eip.html>).
async fn ignore_exception_wins_overlap_and_never_uses_fallback() {
    let mut node = breaker(
        get(),
        json!({
            "minimumNumberOfCalls": 1,
            "slidingWindowCalls": 1,
            "recordException": ["upstream"],
            "ignoreException": ["upstream.http"]
        }),
    );
    node["circuitBreaker"]["onFallback"] = json!({"steps": [
        {"setProperty": {"name": "saw", "value": {"constant": "fallback"}}}
    ]});
    let lane = Lane::over(json!([node]));
    lane.replies(&[500, 500]);

    for _ in 0..2 {
        let outcome = lane.run().await;
        assert!(outcome.result.is_ok(), "an ignored exception continues");
        assert_eq!(ok(&outcome).property("saw"), None, "fallback does not run");
        assert!(outcome.events.iter().any(|event| {
            event.kind == "exchangeFailureHandled"
                && event.detail["source"] == json!("circuitBreaker")
                && event.detail["class"] == json!("upstream.http")
        }));
    }
    assert_eq!(
        lane.requests(),
        2,
        "ignored exceptions did not open the one-call breaker"
    );
}

#[tokio::test]
/// The Adapter always records an uncatchable boundary failure and lets it
/// escape filters and fallback. This is an Adapter security divergence, not a
/// Camel exception-class port
/// (<https://camel.apache.org/components/4.23.x/eips/resilience4j-eip.html>).
async fn boundary_failure_is_recorded_and_propagates_past_filters_and_fallback() {
    let mut node = breaker(
        json!({"throwException": {
            "exceptionType": "script.budget-exceeded",
            "message": "bounded"
        }}),
        json!({
            "minimumNumberOfCalls": 1,
            "slidingWindowCalls": 1,
            "recordException": ["upstream"]
        }),
    );
    node["circuitBreaker"]["onFallback"] = json!({"steps": [
        {"setProperty": {"name": "saw", "value": {"constant": "fallback"}}}
    ]});
    let lane = Lane::over(json!([node]));

    let first = lane.run().await;
    assert_eq!(failed_class(&first), "script.budget-exceeded");
    assert_eq!(
        first
            .result
            .as_ref()
            .expect_err("boundary failure propagates")
            .class
            .class(),
        "script.budget-exceeded"
    );
    let second = lane.run().await;
    assert!(
        has_event(&second, "breakerRefused"),
        "the boundary failure was recorded as failure and opened the breaker"
    );
}

#[tokio::test]
/// A successful permitted call after the open-state wait closes the breaker
/// for subsequent calls, the half-open transition documented by Camel's
/// resilience4j EIP
/// (<https://camel.apache.org/components/4.23.x/eips/resilience4j-eip.html>).
async fn an_open_breaker_recovers_through_half_open_trials() {
    let lane = Lane::over(json!([breaker(
        get(),
        json!({"openStateWaitSeconds": 1, "maximumHalfOpenCalls": 1})
    )]));
    lane.replies(&[500, 500, 200, 200]);
    assert_eq!(failed_class(&lane.run().await), "upstream.http");
    assert_eq!(failed_class(&lane.run().await), "upstream.http");
    // The wait elapses; the next exchange is the half-open trial.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let trial = lane.run().await;
    assert!(trial.result.is_ok(), "the trial succeeds");
    assert_eq!(lane.requests(), 3);
    // One trial succeeded under a maximum of one: the breaker closed,
    // and the next exchange calls through.
    let after = lane.run().await;
    assert!(after.result.is_ok(), "the closed breaker calls through");
    assert_eq!(lane.requests(), 4);
}

#[tokio::test]
/// Camel can opt into wrapping a breaker with the route error handler
/// (`camel-4.23.0:components/camel-resilience4j/src/test/java/org/apache/camel/component/resilience4j/ResilienceInheritErrorHandlerTest.java#testResilience`).
/// The Adapter deliberately fixes the opposite behavior, so guarded steps run
/// bare
/// (<https://camel.apache.org/components/4.23.x/eips/resilience4j-eip.html>).
async fn the_route_error_handler_does_not_wrap_a_breaker_block() {
    // The clause would answer the guarded failure with a second send;
    // a breaker and its steps run bare (section 8.7), so neither the
    // clause steps nor its handling ever run.
    let route = json!([
        {"onException": {"exception": ["upstream.http"], "steps": [get()]}},
        breaker(get(), json!({}))
    ]);
    let lane = Lane::over(route);
    lane.replies(&[500]);
    let outcome = lane.run().await;
    assert_eq!(failed_class(&outcome), "upstream.http");
    assert_eq!(lane.requests(), 1, "the clause's send never ran");
    assert!(
        !has_event(&outcome, "exchangeFailureHandled"),
        "no clause claimed the breaker's failure"
    );
}

#[tokio::test]
/// Total-requests mode admits only the configured count in each period,
/// adapted from Camel's constant-expression pacing case
/// (`camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/throttle/requests/ThrottlerTest.java#testConfigurationWithConstantExpression`;
/// <https://camel.apache.org/components/4.23.x/eips/throttle-eip.html>).
async fn the_throttler_paces_requests_over_the_period() {
    let lane = Lane::over(json!([throttle(
        get(),
        json!({"limit": {"constant": 2}, "timePeriodMilliseconds": 400}),
    )]));
    lane.replies(&[200, 200, 200]);
    assert!(lane.run().await.result.is_ok());
    assert!(lane.run().await.result.is_ok());
    let started = Instant::now();
    let third = lane.run().await;
    assert!(
        third.result.is_ok(),
        "the third exchange waits and completes"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(200),
        "the third exchange waited for the window to roll, waited {:?}",
        started.elapsed()
    );
    assert_eq!(lane.requests(), 3);
}

#[tokio::test]
/// Camel evaluates a header limit for each exchange and applies a changed
/// value to later exchanges
/// (`camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/throttle/requests/ThrottlerTest.java#testConfigurationWithHeaderExpression`,
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/throttle/requests/ThrottlerTest.java#testConfigurationWithChangingHeaderExpression`;
/// <https://camel.apache.org/components/4.23.x/eips/throttle-eip.html>).
async fn a_header_limit_is_re_evaluated_for_each_exchange() {
    let lane = Lane::over(json!([throttle(
        get(),
        json!({
            "limit": {"header": "lim"},
            "timePeriodMilliseconds": 60_000,
            "rejectExecution": true
        }),
    )]));
    lane.replies(&[200, 200, 200]);

    let mut first = Exchange::new("first".to_owned());
    first.message.set_header("lim", json!(1));
    assert!(lane.run_exchange(first).await.result.is_ok());

    let mut second = Exchange::new("second".to_owned());
    second.message.set_header("lim", json!(2));
    assert!(
        lane.run_exchange(second).await.result.is_ok(),
        "raising the evaluated limit admits the next exchange in the same window"
    );

    let mut third = Exchange::new("third".to_owned());
    third.message.set_header("lim", json!(2));
    let refused = lane.run_exchange(third).await;
    assert_eq!(failed_class(&refused), "throttle.rejected");
    assert_eq!(
        lane.requests(),
        2,
        "the third exchange never reaches the source"
    );
}

#[tokio::test]
/// `rejectExecution` refuses calls over the total-requests limit instead of
/// delaying them
/// (`camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/throttle/requests/ThrottlerTest.java#testSendLotsOfMessagesWithRejectExecution`;
/// <https://camel.apache.org/components/4.23.x/eips/throttle-eip.html>).
async fn reject_execution_refuses_instead_of_waiting() {
    let lane = Lane::over(json!([throttle(get(), json!({"rejectExecution": true}))]));
    lane.replies(&[200, 200]);
    assert!(lane.run().await.result.is_ok());
    let second = lane.run().await;
    assert_eq!(failed_class(&second), "throttle.rejected");
    assert_eq!(lane.requests(), 1);
}

#[tokio::test]
/// Waiting is additionally bounded by the Adapter exchange deadline. Raising
/// `throttle.rejected` at that deadline is the port-table divergence from
/// Camel's delay behavior
/// (<https://camel.apache.org/components/4.23.x/eips/throttle-eip.html>).
async fn a_wait_past_the_deadline_raises_throttle_rejected() {
    let lane = Lane::over(json!([throttle(
        get(),
        json!({"timePeriodMilliseconds": 600_000})
    )]));
    lane.replies(&[200]);
    assert!(lane.run().await.result.is_ok());
    // The next exchange would wait ten minutes for the window; its own
    // deadline ends the wait with the throttler's refusal class, not the
    // run's budget.
    let started = Instant::now();
    let second = lane.run_within(Duration::from_millis(150)).await;
    assert_eq!(failed_class(&second), "throttle.rejected");
    assert_eq!(lane.requests(), 1);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the refusal is immediate, not a burned deadline"
    );
}

#[tokio::test]
/// Concurrent-requests mode holds the configured number of in-flight calls
/// and delays the rest
/// (`camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/throttle/concurrent/ConcurrentRequestsThrottlerTest.java#testSendLotsOfMessagesSimultaneouslyButOnly3GetThrough`;
/// <https://camel.apache.org/components/4.23.x/eips/throttle-eip.html>).
async fn concurrent_requests_mode_bounds_in_flight_calls() {
    let lane = Lane::over(json!([throttle(
        get(),
        json!({"mode": "concurrent-requests", "limit": {"constant": 1}}),
    )]));
    lane.replies(&[200, 200]);
    // The first exchange holds the double's answer back, so its body is
    // still inside the throttle when the second arrives.
    lane.double.delay_answers(Duration::from_millis(150));
    let started = Instant::now();
    let (first, second) = tokio::join!(lane.run(), lane.run());
    assert!(first.result.is_ok());
    assert!(second.result.is_ok(), "the second waits for the slot");
    assert!(
        started.elapsed() >= Duration::from_millis(150),
        "the second ran after the first released its slot"
    );
    assert_eq!(lane.requests(), 2);
}

#[tokio::test]
/// Camel re-evaluates a concurrent-request header expression when its value
/// changes between exchanges
/// (`camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/throttle/concurrent/ConcurrentRequestsThrottlerTest.java#testConfigurationWithChangingHeaderExpression`).
/// The first exchange enters under limit 1, the changed limit 2 admits a
/// second body concurrently, and a third exchange at limit 2 is refused.
async fn concurrent_requests_mode_re_reads_a_changed_header_limit() {
    let lane = Lane::over(json!([throttle(
        get(),
        json!({
            "mode": "concurrent-requests",
            "limit": {"header": "lim"},
            "rejectExecution": true
        }),
    )]));
    lane.replies(&[200, 200]);
    lane.double.delay_answers(Duration::from_secs(2));

    let mut first_exchange = Exchange::new("first".to_owned());
    first_exchange.message.set_header("lim", json!(1));
    let mut first = Box::pin(lane.run_exchange(first_exchange));
    tokio::select! {
        _ = &mut first => panic!("the first body finished before admission was observed"),
        () = lane.wait_for_requests(1) => {}
    }

    let mut second_exchange = Exchange::new("second".to_owned());
    second_exchange.message.set_header("lim", json!(2));
    let mut second = Box::pin(lane.run_exchange(second_exchange));
    tokio::select! {
        _ = &mut first => panic!("the first body finished before the raised limit was exercised"),
        _ = &mut second => panic!("the second body finished before admission was observed"),
        () = lane.wait_for_requests(2) => {}
    }

    let mut third_exchange = Exchange::new("third".to_owned());
    third_exchange.message.set_header("lim", json!(2));
    let refused = lane.run_exchange(third_exchange).await;
    assert_eq!(failed_class(&refused), "throttle.rejected");
    assert_eq!(
        lane.requests(),
        2,
        "the changed limit admitted exactly two concurrent bodies"
    );

    let (first, second) = tokio::join!(first, second);
    assert!(first.result.is_ok(), "the limit-1 body completes");
    assert!(second.result.is_ok(), "the changed limit-2 body completes");
}

#[tokio::test]
/// `rejectExecution` also refuses calls over the concurrent-requests limit
/// (`camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/throttle/concurrent/ConcurrentRequestsThrottlerTest.java#testSendLotsOfMessagesWithRejectExecution`;
/// <https://camel.apache.org/components/4.23.x/eips/throttle-eip.html>).
async fn concurrent_requests_mode_rejects_over_the_limit() {
    let lane = Lane::over(json!([throttle(
        get(),
        json!({
            "mode": "concurrent-requests",
            "limit": {"constant": 1},
            "rejectExecution": true
        }),
    )]));
    lane.replies(&[200, 200]);
    lane.double.delay_answers(Duration::from_millis(150));
    let (first, second) = tokio::join!(lane.run(), lane.run());
    let refused = [&first, &second]
        .into_iter()
        .find(|outcome| outcome.result.is_err())
        .expect("one exchange is over the limit");
    assert_eq!(failed_class(refused), "throttle.rejected");
    assert_eq!(lane.requests(), 1, "the refused exchange sends nothing");
}

#[tokio::test]
/// A failed guarded processor releases its concurrent-request permit, as in
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/throttle/concurrent/ConcurrentRequestsThrottlerTest.java#testPermitReleaseOnException`
/// (<https://camel.apache.org/components/4.23.x/eips/throttle-eip.html>).
async fn concurrent_requests_mode_releases_its_permit_on_failure() {
    let body = json!({"throwException": {
        "exceptionType": "validation",
        "message": "expected failure"
    }});
    let lane = Lane::over(json!([throttle(
        body,
        json!({
            "mode": "concurrent-requests",
            "limit": {"constant": 1},
            "rejectExecution": true
        }),
    )]));

    let first = lane.run().await;
    assert_eq!(failed_class(&first), "validation");
    let second = lane.run().await;
    assert_eq!(
        failed_class(&second),
        "validation",
        "the second call entered the body instead of seeing a leaked permit"
    );
}

#[tokio::test]
/// Camel dead-letters a first missing limit but lets a later missing limit
/// continue under the established throttler
/// (`camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/throttle/ThrottlerNullEvalTest.java#testFirstNoHeaderTest`,
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/throttle/ThrottlerNullEvalTest.java#testNoHeaderTest`).
/// The Adapter deliberately requires every evaluation to be a positive integer
/// and fails closed
/// (<https://camel.apache.org/components/4.23.x/eips/throttle-eip.html>).
async fn a_non_integer_limit_fails_the_exchange() {
    let lane = Lane::over(json!([throttle(
        get(),
        json!({"limit": {"header": "lim"}, "timePeriodMilliseconds": 60_000}),
    )]));
    lane.replies(&[200]);
    // No `lim` header is set, so the limit evaluates to null.
    let outcome = lane.run().await;
    assert_eq!(failed_class(&outcome), "validation");
    assert_eq!(lane.requests(), 0, "nothing ran under no limit");
}

#[tokio::test]
/// Camel refuses a throttler with no limit expression at startup
/// (`camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/throttle/ThrottlerInvalidConfiguredTest.java#testInvalid`).
/// The Adapter adds bounded-shape checks for non-empty processor bodies and
/// positive constant limits
/// (<https://camel.apache.org/components/4.23.x/eips/throttle-eip.html>,
/// <https://camel.apache.org/components/4.23.x/eips/resilience4j-eip.html>).
async fn the_resilience_steps_refuse_their_unservable_shapes_at_load() {
    let refused =
        |step_list: Value| check_servable(&steps(step_list)).expect_err("the shape is refused");
    assert!(
        refused(json!([{"circuitBreaker": {
            "failureRateThreshold": 50,
            "slidingWindowCalls": 2,
            "minimumNumberOfCalls": 2,
            "openStateWaitSeconds": 60,
            "maximumHalfOpenCalls": 10,
            "steps": []
        }}]))
        .contains("guards no steps"),
        "a breaker over an empty body is refused"
    );
    assert!(
        refused(json!([breaker(get(), json!({"minimumNumberOfCalls": 3}))]))
            .contains("window holds"),
        "a minimum above the window is refused"
    );
    let empty_fallback = breaker(get(), json!({}));
    let mut with_fallback = empty_fallback;
    with_fallback["circuitBreaker"]["onFallback"] = json!({"steps": []});
    assert!(
        refused(json!([with_fallback])).contains("onFallback declares no steps"),
        "an empty fallback is refused"
    );
    assert!(
        refused(json!([{"throttle": {
            "limit": {"constant": 1},
            "timePeriodMilliseconds": 60_000,
            "steps": []
        }}]))
        .contains("paces no steps"),
        "a throttle over an empty body is refused"
    );
    assert!(
        refused(json!([throttle(
            get(),
            json!({"limit": {"constant": 1.5}})
        )]))
        .contains("positive integer"),
        "a fractional constant limit is refused"
    );
    assert!(
        refused(json!([throttle(get(), json!({"limit": {"constant": 0}}))]))
            .contains("positive integer"),
        "a zero constant limit is refused"
    );
    // The well-formed pair passes.
    check_servable(&steps(json!([
        breaker(get(), json!({})),
        throttle(get(), json!({}))
    ])))
    .expect("the well-formed pair is served");
}
