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
        let routes = RouteTable::new();
        let context = RouteContext {
            endpoints: &self.endpoints,
            scripts: &self.scripts,
            resolver: &self.resolver,
            resilience: &self.resilience,
            routes: &routes,
            maximum_upstream_calls: 12,
        };
        run_route(
            &context,
            &self.steps,
            Exchange::new("resilience".to_owned()),
        )
        .await
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
            maximum_upstream_calls: 12,
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
    // The breaker opened on that failure; the next exchange is refused
    // and answered by the same fallback, with no send.
    let second = lane.run().await;
    assert_eq!(ok(&second).property("saw"), Some(&json!("fallback")));
    assert_eq!(lane.requests(), 1, "the rejected exchange sends nothing");
}

#[tokio::test]
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
async fn reject_execution_refuses_instead_of_waiting() {
    let lane = Lane::over(json!([throttle(get(), json!({"rejectExecution": true}))]));
    lane.replies(&[200, 200]);
    assert!(lane.run().await.result.is_ok());
    let second = lane.run().await;
    assert_eq!(failed_class(&second), "throttle.rejected");
    assert_eq!(lane.requests(), 1);
}

#[tokio::test]
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
