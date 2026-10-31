// SPDX-License-Identifier: Apache-2.0

//! Regression coverage for failure scopes that cross more than one EIP.

use std::collections::BTreeMap;
use std::sync::Arc;

use registry_adapter::exchange::Exchange;
use registry_adapter::resilience::ResilienceRuntime;
use registry_adapter::route::{check_servable, run_route, RouteContext, RouteOutcome, RouteTable};
use registry_adapter::scripts::ScriptSet;
use registry_adapter_core::Step;
use registry_platform_config::{SecretProvider, SecretResolver};
use serde_json::{json, Value};

fn steps(value: Value) -> Vec<Step> {
    serde_json::from_value(value).expect("the steps parse")
}

fn empty_code_maps() -> registry_adapter::scripts::CodeMaps {
    Arc::new(BTreeMap::new())
}

async fn run_empty(main: Value, targets: Value) -> RouteOutcome {
    let main = steps(main);
    let mut routes = RouteTable::new();
    let mut resilience = ResilienceRuntime::empty();
    if let Value::Object(entries) = targets {
        for (id, body) in entries {
            let target = steps(body);
            resilience.absorb(&target);
            routes.insert(id, Arc::new(target));
        }
    }
    resilience.absorb(&main);
    let endpoints = BTreeMap::new();
    let scripts = ScriptSet::default();
    let resolver =
        SecretResolver::new([SecretProvider::Environment], "").expect("the resolver builds");
    let context = RouteContext {
        endpoints: &endpoints,
        scripts: &scripts,
        resolver: &resolver,
        resilience: &resilience,
        routes: &routes,
        code_maps: empty_code_maps(),
        maximum_upstream_calls: 4,
        job: registry_adapter::job_sources::JobPageState::default(),
    };
    run_route(&context, &main, Exchange::new("error-lifecycle".to_owned())).await
}

fn failed_class(outcome: &RouteOutcome) -> &'static str {
    outcome
        .result
        .as_ref()
        .expect_err("the route fails")
        .class
        .class()
}

/// A top-level `doTry` owns its complete failure scope. An error that no
/// `doCatch` claims leaves the route without entering its outer error handler
/// (`camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/DoTryEdgeCasesTest.java#testNestedDoTryKeepsTryBlock`).
#[tokio::test]
async fn a_top_level_do_try_runs_bare() {
    let outcome = run_empty(
        json!([
            {"onException": {
                "exception": ["upstream"],
                "handled": true,
                "steps": [{"setProperty": {
                    "name": "outerClauseRan", "value": {"constant": true}
                }}]
            }},
            {"doTry": {
                "steps": [{"throwException": {"exceptionType": "upstream.http"}}],
                "doFinally": {}
            }}
        ]),
        json!({}),
    )
    .await;

    assert_eq!(failed_class(&outcome), "upstream.http");
    assert!(
        !outcome
            .events
            .iter()
            .any(|event| event.kind == "exchangeFailureHandled"),
        "the route clause never claims a failure leaving doTry"
    );
}

/// A `doTry` without either `doCatch` or `doFinally` is structurally invalid
/// and is refused while the route is loaded
/// (`camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/DoTryEdgeCasesTest.java#testDoTryWithoutCatchOrFinally`).
#[test]
fn an_unanchored_do_try_is_refused_at_load() {
    let error = check_servable(&steps(json!([{"doTry": {
        "steps": [{"throwException": {"exceptionType": "upstream.http"}}]
    }}])))
    .expect_err("a doTry requires a catch or finally clause");

    assert_eq!(error, "doTry declares neither doCatch nor doFinally");
}

/// The Adapter divergence keeps a `direct:` call made by an exception clause
/// inside that clause. The callee's own handler must not recursively handle a
/// failure raised there, unlike
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/onexception/OnExceptionRecursionTest.java#testRecursionDirect`.
#[tokio::test]
async fn a_direct_call_inside_an_exception_clause_does_not_activate_callee_handlers() {
    let outcome = run_empty(
        json!([
            {"onException": {
                "exception": ["upstream"],
                "handled": true,
                "steps": [{"to": {"uri": "direct:fallback"}}]
            }},
            {"throwException": {"exceptionType": "upstream.http"}}
        ]),
        json!({
            "fallback": [
                {"onException": {
                    "exception": ["validation"],
                    "handled": true,
                    "steps": [{"setProperty": {
                        "name": "calleeClauseRan", "value": {"constant": true}
                    }}]
                }},
                {"throwException": {"exceptionType": "validation"}}
            ]
        }),
    )
    .await;

    assert_eq!(failed_class(&outcome), "validation");
    let handled: Vec<&str> = outcome
        .events
        .iter()
        .filter(|event| event.kind == "exchangeFailureHandled")
        .filter_map(|event| event.detail["source"].as_str())
        .collect();
    assert_eq!(handled, ["onException"], "only the outer clause fires");
}

/// A breaker fallback may consume an ordinary guarded failure, but it cannot
/// turn an uncatchable boundary error into success (sections 5.5 and 8.7).
#[tokio::test]
async fn a_breaker_fallback_propagates_an_uncatchable_failure() {
    let outcome = run_empty(
        json!([{"circuitBreaker": {
            "failureRateThreshold": 50,
            "slidingWindowCalls": 1,
            "minimumNumberOfCalls": 1,
            "openStateWaitSeconds": 60,
            "maximumHalfOpenCalls": 1,
            "steps": [{"throwException": {
                "exceptionType": "script.budget-exceeded"
            }}],
            "onFallback": {"steps": [{"setProperty": {
                "name": "fallbackRan", "value": {"constant": true}
            }}]}
        }}]),
        json!({}),
    )
    .await;

    assert_eq!(failed_class(&outcome), "script.budget-exceeded");
    assert!(outcome.events.iter().any(|event| {
        event.kind == "breakerFallback" && event.detail["class"] == json!("script.budget-exceeded")
    }));
}

/// `aggregateOnException` admits ordinary resource failures to the strategy,
/// never uncatchable boundary failures (sections 5.5 and 8.7).
#[tokio::test]
async fn enrich_cannot_aggregate_an_uncatchable_resource_failure() {
    let outcome = run_empty(
        json!([{"enrich": {
            "uri": "http:missing",
            "aggregateOnException": true,
            "parameters": {"httpMethod": "GET", "path": "/thing"}
        }}]),
        json!({}),
    )
    .await;

    assert_eq!(failed_class(&outcome), "egress.refused");
    assert!(
        !outcome
            .events
            .iter()
            .any(|event| event.kind == "exchangeFailureHandled"),
        "the uncatchable failure is not consumed"
    );
}

/// Redelivery is an upstream-send recovery mechanism. Even when the failing
/// step is syntactically a send, an uncatchable pre-send refusal is terminal.
#[tokio::test]
async fn the_default_handler_does_not_redeliver_an_uncatchable_send_failure() {
    let outcome = run_empty(
        json!([
            {"errorHandler": {"defaultErrorHandler": {"redeliveryPolicy": {
                "maximumRedeliveries": 1,
                "retryDelaySeconds": 1
            }}}},
            {"to": {"uri": "http:missing", "parameters": {
                "httpMethod": "GET", "path": "/thing"
            }}}
        ]),
        json!({}),
    )
    .await;

    assert_eq!(failed_class(&outcome), "egress.refused");
    assert!(
        !outcome
            .events
            .iter()
            .any(|event| event.kind == "exchangeRedelivery"),
        "a terminal refusal is never retried"
    );
}

/// Runtime served-shape checks refuse both ends of a named conversion when
/// either name belongs to the engine, matching set/remove rules.
#[test]
fn conversions_refuse_reserved_source_and_target_names() {
    for route in [
        json!([{"convertHeaderTo": {
            "type": "codeMap:states", "name": "recordId"
        }}]),
        json!([{"convertHeaderTo": {
            "type": "codeMap:states", "name": "state", "toName": "CamelState"
        }}]),
        json!([{"convertPropertyTo": {
            "type": "codeMap:states", "name": "AdapterFilters"
        }}]),
        json!([{"convertPropertyTo": {
            "type": "codeMap:states", "name": "state", "toName": "AdapterInternal"
        }}]),
    ] {
        check_servable(&steps(route)).expect_err("the reserved conversion name is refused");
    }
}
