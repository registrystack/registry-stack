// SPDX-License-Identifier: Apache-2.0

//! The error cluster conformance suite: the error handler, the redelivery
//! policy, the exception clause, and `doTry`
//! (`products/adapter/CONCEPT.md` section 8.7, port-table rows 28-31).
//!
//! Every send goes over the loopback double, so a redelivery is a real
//! second request the double counts, and the redelivery headers are read
//! off an exchange the retried send succeeded on.

use std::collections::BTreeMap;

use registry_adapter::exchange::Exchange;
use registry_adapter::route::{
    check_servable, run_route, EndpointRuntime, RouteContext, RouteOutcome, RouteTable,
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
/// shape the enrich suite sends through.
fn error_endpoints(base_url: &str, resolver: &SecretResolver) -> BTreeMap<String, EndpointRuntime> {
    let binding = EndpointBinding {
        endpoint: ExternalId::new("tracker").expect("endpoint id"),
        base_url: Url::new(base_url).expect("base url"),
        credential: Some(RuntimeCredential::StaticApiKey {
            value_ref: SecretReference::new("secret:env/ERROR_CLUSTER_KEY")
                .expect("secret reference"),
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
        id: LocalId::new("error-cluster").expect("deployment id"),
        endpoints: UniqueIdList::new(vec![binding]).expect("bindings"),
        allowed_private_cidrs: UniqueList::new(vec![registry_adapter_core::Cidr::new(
            "192.168.0.0/16",
        )
        .expect("cidr")])
        .expect("cidrs"),
        outbound_tls: None,
        listener: serde_json::from_str(r#"{ "bind": "127.0.0.1:8080" }"#).expect("listener"),
        database: serde_json::from_str(
            r#"{
                "runtimeUrlRef": "secret:env/ERROR_CLUSTER_DB",
                "migrationUrlRef": "secret:env/ERROR_CLUSTER_DB"
            }"#,
        )
        .expect("database"),
        oidc: serde_json::from_str(
            r#"{ "issuer": "https://issuer.example.invalid", "audience": "error-cluster" }"#,
        )
        .expect("oidc"),
        allowed_clients: UniqueList::new(vec![
            ExternalId::new("error-cluster-client").expect("client")
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

/// One route run over the scripted upstream: the steps as JSON, the
/// replies the double answers in order, and the number of requests the
/// run made (counted by the double).
async fn run_over(step_list: Value, replies: Vec<upstream::Response>) -> (RouteOutcome, usize) {
    let double = upstream::UpstreamDouble::start();
    double.respond_with(replies);
    std::env::set_var("ERROR_CLUSTER_KEY", "error-cluster-key");
    let resolver = SecretResolver::new([SecretProvider::Environment], "")
        .expect("the environment resolver builds");
    let endpoints = error_endpoints(&double.url("/"), &resolver);
    let resilience = registry_adapter::resilience::ResilienceRuntime::empty();
    let routes = RouteTable::new();
    let context = RouteContext {
        endpoints: &endpoints,
        scripts: &ScriptSet::default(),
        resolver: &resolver,
        resilience: &resilience,
        routes: &routes,
        code_maps: empty_code_maps(),
        maximum_upstream_calls: 12,
        job: registry_adapter::job_sources::JobPageState::default(),
    };
    let mut exchange = Exchange::new("error-cluster".to_owned());
    exchange.message.body = json!({"q": 1});
    let outcome = run_route(&context, &steps(step_list), exchange).await;
    (outcome, double.request_count())
}

/// A failing GET to the double.
fn get() -> Value {
    json!({"to": {"uri": "http:tracker", "parameters": {
        "httpMethod": "GET", "path": "/thing"
    }}})
}

/// The class a run failed with, for the assertions that care.
fn failed_class(outcome: &RouteOutcome) -> String {
    outcome
        .result
        .as_ref()
        .expect_err("the route fails")
        .class
        .class()
        .to_owned()
}

/// The default error handler without a policy makes one attempt and the
/// failure propagates to the caller; `noErrorHandler` additionally keeps
/// every clause from firing. These are the bounded counterparts of
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/DefaultErrorHandlerRedeliveryTest.java#testNoRedeliveriesTest`
/// and
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/onexception/OnExceptionRecursionTest.java#testRecursionDirectNoErrorHandler`.
#[tokio::test]
async fn the_error_handler_shapes_the_attempts_and_clause_reach() {
    let (outcome, requests) = run_over(
        json!([
            {"errorHandler": {"defaultErrorHandler": {}}},
            get(),
            {"setHeader": {"name": "x-after", "value": {"constant": 1}}}
        ]),
        vec![
            upstream::Response::json(500, r#"{"boom": true}"#),
            upstream::Response::json(500, r#"{"boom": true}"#),
        ],
    )
    .await;
    assert_eq!(failed_class(&outcome), "upstream.http");
    assert_eq!(requests, 1, "no policy, no redelivery");

    // Under noErrorHandler a clause never fires: its steps leave no mark.
    let (silent, requests) = run_over(
        json!([
            {"errorHandler": {"noErrorHandler": {}}},
            {"onException": {
                "exception": ["upstream"],
                "steps": [{"setHeader": {"name": "x-clause", "value": {"constant": 1}}}]
            }},
            get()
        ]),
        vec![upstream::Response::json(500, r#"{"boom": true}"#)],
    )
    .await;
    assert_eq!(failed_class(&silent), "upstream.http");
    assert_eq!(requests, 1);
    assert!(
        !silent
            .events
            .iter()
            .any(|event| matches!(event.kind, "exchangeFailureHandled" | "exchangeRedelivery")),
        "no clause fired, so nothing was handled"
    );
}

/// The default error handler redelivers a failed send while its policy
/// allows, carrying Camel's redelivery headers on the exchange that
/// succeeds, as exercised by
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/DefaultErrorHandlerRedeliveryTest.java#testRedeliveryTest`
/// and
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/RedeliveryPolicyPerExceptionTest.java#testUsingCustomExceptionHandlerAndOneRedelivery`.
#[tokio::test]
async fn the_default_error_handler_redelivers_under_its_policy() {
    let (outcome, requests) = run_over(
        json!([
            {"errorHandler": {"defaultErrorHandler": {"redeliveryPolicy": {
                "maximumRedeliveries": 2,
                "retryDelaySeconds": 1
            }}}},
            get()
        ]),
        vec![
            upstream::Response::json(500, r#"{"boom": true}"#),
            upstream::Response::json(500, r#"{"boom": true}"#),
            upstream::Response::json(200, r#"{"ok": true}"#),
        ],
    )
    .await;
    let exchange = outcome.result.expect("the second redelivery succeeds");
    assert_eq!(requests, 3);
    assert_eq!(exchange.message.body, json!({"ok": true}));
    assert_eq!(
        exchange.message.header("CamelRedelivered"),
        Some(&json!(true))
    );
    assert_eq!(
        exchange.message.header("CamelRedeliveryCounter"),
        Some(&json!(2))
    );
    assert_eq!(
        exchange.message.header("CamelRedeliveryMaxCounter"),
        Some(&json!(2))
    );

    // An exhausted policy leaves the failure with the caller.
    let (exhausted, requests) = run_over(
        json!([
            {"errorHandler": {"defaultErrorHandler": {"redeliveryPolicy": {
                "maximumRedeliveries": 1,
                "retryDelaySeconds": 1
            }}}},
            get()
        ]),
        vec![
            upstream::Response::json(500, r#"{"boom": true}"#),
            upstream::Response::json(500, r#"{"boom": true}"#),
            upstream::Response::json(200, r#"{"never": true}"#),
        ],
    )
    .await;
    assert_eq!(failed_class(&exhausted), "upstream.http");
    assert_eq!(requests, 2, "one attempt plus one redelivery");
    assert!(
        exhausted
            .events
            .iter()
            .any(|event| event.kind == "exchangeRedelivery"),
        "each redelivery is an event"
    );
}

/// A clause's own policy governs its classes; the handler's policy
/// governs every other failure, porting
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/RedeliveryPolicyPerExceptionTest.java#testUsingCustomExceptionHandlerAndOneRedelivery`.
#[tokio::test]
async fn the_clause_policy_governs_its_classes_and_the_handler_the_rest() {
    let (clause_class, requests) = run_over(
        json!([
            {"errorHandler": {"defaultErrorHandler": {"redeliveryPolicy": {
                "maximumRedeliveries": 3, "retryDelaySeconds": 1
            }}}},
            {"onException": {
                "exception": ["upstream.http"],
                "redeliveryPolicy": {"maximumRedeliveries": 1, "retryDelaySeconds": 1},
                "steps": [{"setHeader": {"name": "x-clause", "value": {"constant": 1}}}]
            }},
            get()
        ]),
        vec![
            upstream::Response::json(500, r#"{"boom": true}"#),
            upstream::Response::json(500, r#"{"boom": true}"#),
            upstream::Response::json(500, r#"{"boom": true}"#),
        ],
    )
    .await;
    assert_eq!(failed_class(&clause_class), "upstream.http");
    assert_eq!(
        requests, 2,
        "the clause's tighter policy wins for its class"
    );

    // A class no clause names falls to the handler's policy.
    let (unclaimed, requests) = run_over(
        json!([
            {"errorHandler": {"defaultErrorHandler": {"redeliveryPolicy": {
                "maximumRedeliveries": 1, "retryDelaySeconds": 1
            }}}},
            {"onException": {
                "exception": ["upstream.http"],
                "redeliveryPolicy": {"maximumRedeliveries": 3, "retryDelaySeconds": 1},
                "steps": [{"setHeader": {"name": "x-clause", "value": {"constant": 1}}}]
            }},
            get(),
            {"throwException": {"exceptionType": "upstream.connection"}}
        ]),
        vec![upstream::Response::json(200, r#"{"ok": true}"#)],
    )
    .await;
    assert_eq!(failed_class(&unclaimed), "upstream.connection");
    assert_eq!(
        requests, 1,
        "the thrown class matched no clause, and redelivery reaches only sends"
    );
}

/// Camel gives an output-bearing `onException` clause that declares no
/// policy zero redeliveries, even when the route handler permits them
/// (`camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/RedeliveryPolicyPerExceptionTest.java#testUsingCustomExceptionHandlerWithNoRedeliveries`).
/// An outputless clause follows Camel's separate parent-policy inheritance
/// path, which `retry_while_narrows_redelivery_without_raising_the_cap`
/// exercises below.
#[tokio::test]
async fn an_output_bearing_clause_without_policy_disables_handler_redelivery() {
    let (outcome, requests) = run_over(
        json!([
            {"errorHandler": {"defaultErrorHandler": {"redeliveryPolicy": {
                "maximumRedeliveries": 3, "retryDelaySeconds": 1
            }}}},
            {"onException": {
                "exception": ["upstream"],
                "handled": true,
                "steps": [{"setHeader": {
                    "name": "x-clause", "value": {"constant": 1}
                }}]
            }},
            get()
        ]),
        vec![
            upstream::Response::json(500, r#"{"boom": true}"#),
            upstream::Response::json(200, r#"{"unexpected": "retry"}"#),
        ],
    )
    .await;

    let exchange = outcome
        .result
        .expect("the output-bearing clause handles the first failure");
    assert_eq!(requests, 1, "the route policy is not inherited");
    assert_eq!(exchange.message.header("x-clause"), Some(&json!(1)));
}

/// `retryWhile` sits on the clause and the default handler, as in Camel,
/// never on the redelivery policy (section 8.7). It continues redelivery
/// while it holds, stops early when it does not, and a raising predicate
/// ends the redelivery; the cap stays `maximumRedeliveries`. A matched
/// clause's own predicate governs its classes, the handler's every other
/// failure. An outputless clause without its own policy redelivers under
/// the handler's. Camel's predicate behavior is exercised by
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/onexception/DefaultErrorHandlerRetryWhileTest.java#testRetryUntil`,
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/onexception/OnExceptionRetryUntilTest.java#testRetryUntil`,
/// and
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/onexception/ErrorHandlerFailurePathsTest.java#testDeadLetterChannelRetryWhileThrows`;
/// the Adapter's hard cap is the recorded divergence. Camel's
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/RedeliveryPolicyPerExceptionTest.java#testUsingCustomExceptionHandlerWithNoRedeliveries`
/// gives an output-bearing clause with no policy zero redeliveries. The
/// outputless handled clause below follows Camel's separate inheritance path.
/// The output-bearing zero-redelivery case has its own focused regression.
#[tokio::test]
async fn retry_while_narrows_redelivery_without_raising_the_cap() {
    // A predicate that does not hold stops before any redelivery.
    let (stopped, requests) = run_over(
        json!([
            {"errorHandler": {"defaultErrorHandler": {
                "retryWhile": {"constant": false},
                "redeliveryPolicy": {"maximumRedeliveries": 2, "retryDelaySeconds": 1}
            }}},
            get()
        ]),
        vec![
            upstream::Response::json(500, r#"{"boom": true}"#),
            upstream::Response::json(500, r#"{"boom": true}"#),
            upstream::Response::json(500, r#"{"boom": true}"#),
        ],
    )
    .await;
    assert_eq!(failed_class(&stopped), "upstream.http");
    assert_eq!(requests, 1, "retryWhile false stops before any redelivery");

    // A predicate that raises ends the redelivery the same way: a
    // constant that is no boolean is a raising predicate.
    let (raised, requests) = run_over(
        json!([
            {"errorHandler": {"defaultErrorHandler": {
                "retryWhile": {"constant": 1},
                "redeliveryPolicy": {"maximumRedeliveries": 2, "retryDelaySeconds": 1}
            }}},
            get()
        ]),
        vec![
            upstream::Response::json(500, r#"{"boom": true}"#),
            upstream::Response::json(500, r#"{"boom": true}"#),
        ],
    )
    .await;
    assert_eq!(failed_class(&raised), "upstream.http");
    assert_eq!(requests, 1, "a raising retryWhile ends the redelivery");

    // With the predicate held by a constant, the cap alone stops it.
    let (capped, requests) = run_over(
        json!([
            {"errorHandler": {"defaultErrorHandler": {
                "retryWhile": {"constant": true},
                "redeliveryPolicy": {"maximumRedeliveries": 2, "retryDelaySeconds": 1}
            }}},
            get()
        ]),
        vec![
            upstream::Response::json(500, r#"{"boom": true}"#),
            upstream::Response::json(500, r#"{"boom": true}"#),
            upstream::Response::json(500, r#"{"boom": true}"#),
        ],
    )
    .await;
    assert_eq!(failed_class(&capped), "upstream.http");
    assert_eq!(requests, 3, "one attempt plus the two capped redeliveries");

    // The clause's own predicate governs its classes: false stops before
    // any redelivery, whatever the handler carries.
    let (clause_stopped, requests) = run_over(
        json!([
            {"errorHandler": {"defaultErrorHandler": {
                "retryWhile": {"constant": true},
                "redeliveryPolicy": {"maximumRedeliveries": 2, "retryDelaySeconds": 1}
            }}},
            {"onException": {
                "exception": ["upstream"],
                "retryWhile": {"constant": false},
                "redeliveryPolicy": {"maximumRedeliveries": 2, "retryDelaySeconds": 1},
                "handled": true
            }},
            get()
        ]),
        vec![
            upstream::Response::json(500, r#"{"boom": true}"#),
            upstream::Response::json(500, r#"{"boom": true}"#),
        ],
    )
    .await;
    assert!(clause_stopped.result.is_ok(), "the handled clause ends it");
    assert_eq!(
        requests, 1,
        "the clause's own retryWhile governs its classes"
    );

    // A clause that carries no predicate does not inherit the handler's:
    // its redeliveries run to their own cap while the handler's held
    // predicate would have stopped them.
    let (clause_capped, requests) = run_over(
        json!([
            {"errorHandler": {"defaultErrorHandler": {
                "retryWhile": {"constant": false},
                "redeliveryPolicy": {"maximumRedeliveries": 1, "retryDelaySeconds": 1}
            }}},
            {"onException": {
                "exception": ["upstream"],
                "redeliveryPolicy": {"maximumRedeliveries": 2, "retryDelaySeconds": 1},
                "handled": true
            }},
            get()
        ]),
        vec![
            upstream::Response::json(500, r#"{"boom": true}"#),
            upstream::Response::json(500, r#"{"boom": true}"#),
            upstream::Response::json(500, r#"{"boom": true}"#),
        ],
    )
    .await;
    assert!(clause_capped.result.is_ok(), "the handled clause ends it");
    assert_eq!(
        requests, 3,
        "a clause without its own predicate does not take the handler's"
    );

    // A clause without its own policy redelivers under the handler's,
    // with its own predicate in force.
    let (inherited, requests) = run_over(
        json!([
            {"errorHandler": {"defaultErrorHandler": {
                "redeliveryPolicy": {"maximumRedeliveries": 2, "retryDelaySeconds": 1}
            }}},
            {"onException": {
                "exception": ["upstream"],
                "retryWhile": {"constant": true},
                "handled": true
            }},
            get()
        ]),
        vec![
            upstream::Response::json(500, r#"{"boom": true}"#),
            upstream::Response::json(500, r#"{"boom": true}"#),
            upstream::Response::json(500, r#"{"boom": true}"#),
        ],
    )
    .await;
    assert!(inherited.result.is_ok(), "the handled clause ends it");
    assert_eq!(
        requests, 3,
        "a clause with no policy of its own redelivers under the handler's"
    );
}

/// `handled` ends the exchange with the clause's result and `continued`
/// resumes the route after the failure point; without either the clause's
/// steps run and the failure still surfaces. The first two paths port
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/onexception/OnExceptionHandledTest.java#testHandled`
/// and
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/onexception/OnExceptionContinueTest.java#testContinued`;
/// a later independent failure follows
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/onexception/ErrorHandlerFailurePathsTest.java#testContinuedThenUnrelatedFailure`.
#[tokio::test]
async fn handled_ends_continued_resumes_and_default_propagates() {
    let (handled, _) = run_over(
        json!([
            {"onException": {
                "exception": ["upstream"],
                "handled": true,
                "steps": [
                    {"setBody": {"constant": {"records": [], "total": 0}}},
                    {"setHeader": {"name": "x-clause", "value": {"constant": 1}}}
                ]
            }},
            get(),
            {"setHeader": {"name": "x-after", "value": {"constant": 1}}}
        ]),
        vec![upstream::Response::json(500, r#"{"boom": true}"#)],
    )
    .await;
    let exchange = handled.result.expect("a handled clause succeeds");
    assert_eq!(exchange.message.body, json!({"records": [], "total": 0}));
    assert_eq!(exchange.message.header("x-clause"), Some(&json!(1)));
    assert_eq!(
        exchange.message.header("x-after"),
        None,
        "the route ends at the handled failure"
    );

    let (continued, _) = run_over(
        json!([
            {"onException": {
                "exception": ["upstream"],
                "continued": true,
                "steps": [{"setBody": {"constant": {"records": [], "total": 0}}}]
            }},
            get(),
            {"setHeader": {"name": "x-after", "value": {"constant": 1}}}
        ]),
        vec![upstream::Response::json(500, r#"{"boom": true}"#)],
    )
    .await;
    let exchange = continued.result.expect("a continued clause resumes");
    assert_eq!(exchange.message.body, json!({"records": [], "total": 0}));
    assert_eq!(
        exchange.message.header("x-after"),
        Some(&json!(1)),
        "the route resumes after the failure"
    );

    let (continued_then_failed, _) = run_over(
        json!([
            {"onException": {
                "exception": ["upstream"],
                "continued": true
            }},
            {"throwException": {"exceptionType": "upstream.http"}},
            {"throwException": {"exceptionType": "validation"}}
        ]),
        Vec::new(),
    )
    .await;
    assert_eq!(
        failed_class(&continued_then_failed),
        "validation",
        "a later independent failure replaces the continued one"
    );

    let (propagated, _) = run_over(
        json!([
            {"onException": {
                "exception": ["upstream"],
                "steps": [{"setHeader": {"name": "x-clause", "value": {"constant": 1}}}]
            }},
            get(),
            {"setHeader": {"name": "x-after", "value": {"constant": 1}}}
        ]),
        vec![upstream::Response::json(500, r#"{"boom": true}"#)],
    )
    .await;
    assert_eq!(failed_class(&propagated), "upstream.http");
}

/// The closest declared class wins over an earlier ancestor; equally close
/// clauses retain declaration order, while an `onWhen` that raises is not a
/// match. This ports
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/exceptionpolicy/DefaultExceptionPolicyStrategyTest.java#testClosetMatch3`,
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/exceptionpolicy/DefaultExceptionPolicyStrategyUsingWhenTest.java#testWithWhen`,
/// and
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/onexception/ErrorHandlerFailurePathsTest.java#testOnWhenThrowsIsNoMatch`
/// into the Adapter's single-class hierarchy.
#[tokio::test]
async fn the_closest_exception_clause_wins_and_on_when_narrows_ties() {
    let (closest, _) = run_over(
        json!([
            {"onException": {
                "exception": ["upstream"],
                "handled": true,
                "steps": [{"setHeader": {
                    "name": "x-clause", "value": {"constant": "ancestor"}
                }}]
            }},
            {"onException": {
                "exception": ["upstream.http"],
                "handled": true,
                "steps": [{"setHeader": {
                    "name": "x-clause", "value": {"constant": "closest"}
                }}]
            }},
            {"throwException": {"exceptionType": "upstream.http"}}
        ]),
        Vec::new(),
    )
    .await;
    assert_eq!(
        closest
            .result
            .expect("the closest clause handles the failure")
            .message
            .header("x-clause"),
        Some(&json!("closest"))
    );

    let (tied, _) = run_over(
        json!([
            {"onException": {
                "exception": ["upstream.http"],
                "handled": true,
                "steps": [{"setHeader": {
                    "name": "x-clause", "value": {"constant": "first"}
                }}]
            }},
            {"onException": {
                "exception": ["upstream.http"],
                "handled": true,
                "steps": [{"setHeader": {
                    "name": "x-clause", "value": {"constant": "second"}
                }}]
            }},
            {"throwException": {"exceptionType": "upstream.http"}}
        ]),
        Vec::new(),
    )
    .await;
    assert_eq!(
        tied.result
            .expect("the first equally specific clause handles the failure")
            .message
            .header("x-clause"),
        Some(&json!("first"))
    );

    // The first equally specific clause has a raising predicate (a
    // non-boolean constant), so it is no match and the next clause wins.
    let (narrowed, _) = run_over(
        json!([
            {"onException": {
                "exception": ["upstream.http"],
                "onWhen": {"constant": 1},
                "handled": true,
                "steps": [{"setHeader": {
                    "name": "x-clause", "value": {"constant": "raising"}
                }}]
            }},
            {"onException": {
                "exception": ["upstream.http"],
                "handled": true,
                "steps": [{"setHeader": {
                    "name": "x-clause", "value": {"constant": "fallback"}
                }}]
            }},
            {"throwException": {"exceptionType": "upstream.http"}}
        ]),
        Vec::new(),
    )
    .await;
    assert_eq!(
        narrowed
            .result
            .expect("the fallback clause handles the failure")
            .message
            .header("x-clause"),
        Some(&json!("fallback"))
    );
}

/// An error raised inside a clause is never handled again: it replaces
/// the failure, and the record keeps both classes. Camel recursively invokes
/// the callee's handler in
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/onexception/OnExceptionRecursionTest.java#testRecursionDirect`;
/// not doing so is the Adapter's recorded `direct:` divergence.
#[tokio::test]
async fn a_clause_error_replaces_the_failure_and_keeps_the_original() {
    let (outcome, _) = run_over(
        json!([
            {"onException": {
                "exception": ["upstream"],
                "steps": [{"throwException": {
                    "exceptionType": "outcome.not-found",
                    "message": "no such record"
                }}]
            }},
            get()
        ]),
        vec![upstream::Response::json(500, r#"{"boom": true}"#)],
    )
    .await;
    assert_eq!(failed_class(&outcome), "outcome.not-found");
    let recorded: Vec<&str> = outcome
        .events
        .iter()
        .filter(|event| event.kind == "exchangeFailureHandled")
        .map(|event| event.detail["class"].as_str().unwrap_or_default())
        .collect();
    assert!(
        recorded.contains(&"upstream.http"),
        "the original class is recorded beside the raised one: {recorded:?}"
    );
}

/// No clause matches an uncatchable class, whatever prefix the clause
/// names. This terminal class set is an Adapter addition with no Camel case.
#[tokio::test]
async fn an_uncatchable_class_matches_no_clause() {
    let (outcome, _) = run_over(
        json!([
            {"onException": {
                "exception": ["script"],
                "steps": [{"setHeader": {"name": "x-clause", "value": {"constant": 1}}}]
            }},
            {"throwException": {"exceptionType": "script.budget-exceeded"}}
        ]),
        Vec::new(),
    )
    .await;
    assert_eq!(failed_class(&outcome), "script.budget-exceeded");
    assert!(
        outcome
            .result
            .as_ref()
            .is_err_and(|_| outcome.events.is_empty()),
        "the boundary is not caught through its own causes"
    );
}

/// `doTry` catches a matching class, `instanceof`-wise, first catch
/// winning, with `CamelExceptionCaught` readable inside the clause and
/// cleared afterward; the route resumes after the `doTry`. This ports
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/TryProcessorTest.java#testTryCatchFinallyProcessor`
/// and
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/TryProcessorMultipleExceptionTest.java#testIOException`,
/// while first-catch resolution follows
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/DoTryEdgeCasesTest.java#testOnWhenNotEvaluatedWhenHandled`.
#[tokio::test]
async fn do_try_catches_its_block_and_resumes_the_route() {
    let (outcome, _) = run_over(
        json!([
            {"doTry": {"steps": [get()], "doCatch": [
                {"exception": ["upstream"], "steps": [
                    {"setProperty": {"name": "saw", "value": {
                        "header": "CamelExceptionCaught"
                    }}},
                    {"setBody": {"constant": {"records": [], "total": 0}}},
                    {"setHeader": {"name": "x-caught", "value": {"constant": "upstream"}}}
                ]},
                {"exception": ["upstream.http"], "steps": [
                    {"setHeader": {"name": "x-caught", "value": {"constant": "http"}}}
                ]}
            ]}},
            {"setHeader": {"name": "x-after", "value": {"constant": 1}}}
        ]),
        vec![upstream::Response::json(500, r#"{"boom": true}"#)],
    )
    .await;
    let exchange = outcome.result.expect("the catch handles the failure");
    assert_eq!(exchange.property("saw"), Some(&json!("upstream.http")));
    assert_eq!(
        exchange.message.header("x-caught"),
        Some(&json!("upstream")),
        "the first declared catch wins"
    );
    assert_eq!(exchange.message.body, json!({"records": [], "total": 0}));
    assert_eq!(exchange.message.header("x-after"), Some(&json!(1)));
    assert_eq!(
        exchange.message.header("CamelExceptionCaught"),
        None,
        "the caught class does not outlive the clause"
    );

    let (multi_class, _) = run_over(
        json!([
            {"doTry": {
                "steps": [{"throwException": {"exceptionType": "upstream.http"}}],
                "doCatch": [{
                    "exception": ["upstream.connection", "upstream.http"],
                    "steps": [{"setHeader": {
                        "name": "x-caught", "value": {"constant": "multi"}
                    }}]
                }]
            }}
        ]),
        Vec::new(),
    )
    .await;
    assert_eq!(
        multi_class
            .result
            .expect("one catch may name more than one class")
            .message
            .header("x-caught"),
        Some(&json!("multi"))
    );
}

/// A `doCatch` narrows with `onWhen`: a predicate that does not hold
/// leaves the catch, and one that raises fails the exchange with the
/// raising error, the original kept. This ports
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/TryProcessorOnWhenTest.java#testOtherBug`
/// and
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/DoTryEdgeCasesTest.java#testOnWhenThrowsException`.
#[tokio::test]
async fn a_do_catch_on_when_narrows_or_fails() {
    let (matched, _) = run_over(
        json!([
            {"doTry": {
                "steps": [{"throwException": {"exceptionType": "upstream.http"}}],
                "doCatch": [{
                    "exception": ["upstream"],
                    "onWhen": {"constant": true},
                    "steps": [{"setHeader": {
                        "name": "x-caught", "value": {"constant": 1}
                    }}]
                }]
            }}
        ]),
        Vec::new(),
    )
    .await;
    assert_eq!(
        matched
            .result
            .expect("the holding predicate admits the catch")
            .message
            .header("x-caught"),
        Some(&json!(1))
    );

    let (fallback, _) = run_over(
        json!([
            {"doTry": {
                "steps": [{"throwException": {"exceptionType": "upstream.http"}}],
                "doCatch": [
                    {
                        "exception": ["upstream"],
                        "onWhen": {"constant": false},
                        "steps": [{"setHeader": {
                            "name": "x-caught", "value": {"constant": "narrowed"}
                        }}]
                    },
                    {
                        "exception": ["upstream"],
                        "steps": [{"setHeader": {
                            "name": "x-caught", "value": {"constant": "fallback"}
                        }}]
                    }
                ]
            }}
        ]),
        Vec::new(),
    )
    .await;
    assert_eq!(
        fallback
            .result
            .expect("the next catch handles after the narrowed catch")
            .message
            .header("x-caught"),
        Some(&json!("fallback"))
    );

    let (skipped, _) = run_over(
        json!([
            {"doTry": {"steps": [get()], "doCatch": [
                {"exception": ["upstream"], "onWhen": {"constant": false}, "steps": [
                    {"setHeader": {"name": "x-caught", "value": {"constant": 1}}}
                ]}
            ]}}
        ]),
        vec![upstream::Response::json(500, r#"{"boom": true}"#)],
    )
    .await;
    assert_eq!(failed_class(&skipped), "upstream.http");

    let (raised, _) = run_over(
        json!([
            {"doTry": {"steps": [get()], "doCatch": [
                {"exception": ["upstream"], "onWhen": {"constant": 1}, "steps": [
                    {"setHeader": {"name": "x-caught", "value": {"constant": 1}}}
                ]}
            ]}}
        ]),
        vec![upstream::Response::json(500, r#"{"boom": true}"#)],
    )
    .await;
    assert_eq!(failed_class(&raised), "script");
    assert!(
        raised
            .events
            .iter()
            .any(|event| event.kind == "exchangeFailureSuppressed"
                && event.detail["class"] == json!("upstream.http")),
        "the original class is kept as suppressed"
    );
}

/// An error no `doCatch` matches leaves the `doTry` and fails the
/// exchange; `doFinally` runs on success, on a handled catch, and on an
/// escaping failure, and an error it raises itself wins only when no
/// failure is pending. This ports
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/TryProcessorMultipleExceptionTest.java#testOk`
/// and
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/DoTryEdgeCasesTest.java#testDoFinallyThrowsKeepsOriginal`.
#[tokio::test]
async fn do_finally_runs_on_every_path_and_yields_to_a_pending_failure() {
    let (clean, _) = run_over(
        json!([
            {"doTry": {
                "steps": [get()],
                "doCatch": [{"exception": ["upstream"], "steps": []}],
                "doFinally": {"steps": [
                    {"setHeader": {"name": "x-finally", "value": {"constant": 1}}}
                ]}
            }}
        ]),
        vec![upstream::Response::json(200, r#"{"ok": true}"#)],
    )
    .await;
    assert_eq!(
        clean
            .result
            .expect("the clean try succeeds")
            .message
            .header("x-finally"),
        Some(&json!(1)),
        "doFinally runs after a clean try"
    );

    let (caught, _) = run_over(
        json!([
            {"doTry": {
                "steps": [get()],
                "doCatch": [{"exception": ["upstream"], "steps": []}],
                "doFinally": {"steps": [
                    {"setHeader": {"name": "x-finally", "value": {"constant": 1}}}
                ]}
            }}
        ]),
        vec![upstream::Response::json(500, r#"{"boom": true}"#)],
    )
    .await;
    assert_eq!(
        caught
            .result
            .expect("the catch handles the failure")
            .message
            .header("x-finally"),
        Some(&json!(1)),
        "doFinally runs after a handled catch"
    );

    // An escaping failure with a failing finally: the original wins.
    let (suppressed, _) = run_over(
        json!([
            {"doTry": {
                "steps": [get()],
                "doFinally": {"steps": [
                    {"throwException": {"exceptionType": "validation"}}
                ]}
            }}
        ]),
        vec![upstream::Response::json(500, r#"{"boom": true}"#)],
    )
    .await;
    assert_eq!(failed_class(&suppressed), "upstream.http");

    // A clean try with a failing finally: the finally's error fails it.
    let (final_failed, _) = run_over(
        json!([
            {"doTry": {
                "steps": [get()],
                "doFinally": {"steps": [
                    {"throwException": {"exceptionType": "validation"}}
                ]}
            }}
        ]),
        vec![upstream::Response::json(200, r#"{"ok": true}"#)],
    )
    .await;
    assert_eq!(failed_class(&final_failed), "validation");
}

/// Inside a `doTry` block the route error handler is not in use: no
/// clause fires and no redelivery multiplies the send, matching
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/DoTryEdgeCasesTest.java#testNestedDoTryKeepsTryBlock`.
#[tokio::test]
async fn the_route_error_handler_does_not_wrap_a_do_try_block() {
    let (outcome, requests) = run_over(
        json!([
            {"errorHandler": {"defaultErrorHandler": {"redeliveryPolicy": {
                "maximumRedeliveries": 2, "retryDelaySeconds": 1
            }}}},
            {"onException": {
                "exception": ["upstream"],
                "steps": [{"setHeader": {"name": "x-clause", "value": {"constant": 1}}}]
            }},
            {"doTry": {"steps": [get()], "doCatch": [
                {"exception": ["upstream"], "steps": [
                    {"setHeader": {"name": "x-caught", "value": {"constant": 1}}}
                ]}
            ]}},
            {"setHeader": {"name": "x-after", "value": {"constant": 1}}}
        ]),
        vec![upstream::Response::json(500, r#"{"boom": true}"#)],
    )
    .await;
    let exchange = outcome.result.expect("the catch handles the failure");
    assert_eq!(requests, 1, "no redelivery inside the block");
    assert_eq!(exchange.message.header("x-clause"), None);
    assert_eq!(exchange.message.header("x-caught"), Some(&json!(1)));
    assert_eq!(exchange.message.header("x-after"), Some(&json!(1)));
}

/// The load refusals: a second error handler, a nested clause, a
/// `retryWhile` with no redeliveries behind it, and a doCatch naming an
/// uncatchable class. The handled/continued exclusivity exercised here is
/// the same invariant as
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/onexception/OnExceptionHandledAndContinueTest.java#testHandledAndContinued`;
/// the other refusals are Adapter bounds. Camel's `useOriginalMessage` cases
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/onexception/OnExceptionUseOriginalMessageTest.java#testOnExceptionError`
/// and
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/onexception/OnExceptionUseOriginalBodyTest.java#testUseOriginalBody`
/// are outside the port and their fields are rejected rather than ignored.
#[tokio::test]
async fn the_cluster_refuses_its_unservable_shapes_at_load() {
    serde_json::from_value::<Vec<Step>>(json!([{"onException": {
        "exception": ["upstream"], "useOriginalMessage": true
    }}]))
    .expect_err("useOriginalMessage is not in the bounded onException shape");
    serde_json::from_value::<Vec<Step>>(json!([{"onException": {
        "exception": ["upstream"], "useOriginalBody": true
    }}]))
    .expect_err("useOriginalBody is not in the bounded onException shape");

    check_servable(&steps(json!([
        {"errorHandler": {"defaultErrorHandler": {}}},
        {"errorHandler": {"noErrorHandler": {}}},
        get()
    ])))
    .expect_err("a route carries one error handler");

    check_servable(&steps(json!([
        {"onException": {
            "exception": ["upstream"],
            "steps": [{"onException": {"exception": ["script"], "steps": []}}]
        }},
        get()
    ])))
    .expect_err("a clause never nests inside a clause");

    check_servable(&steps(json!([
        {"errorHandler": {"defaultErrorHandler": {
            "retryWhile": {"constant": true},
            "redeliveryPolicy": {"maximumRedeliveries": 0}
        }}},
        get()
    ])))
    .expect_err("a retryWhile with no redeliveries behind it");

    check_servable(&steps(json!([
        {"onException": {
            "exception": ["upstream"],
            "retryWhile": {"constant": true}
        }},
        get()
    ])))
    .expect_err("a clause retryWhile with no redeliveries behind it");

    check_servable(&steps(json!([
        {"doTry": {"steps": [], "doCatch": [
            {"exception": ["budget.exhausted"], "steps": []}
        ]}}
    ])))
    .expect_err("a doCatch never names an uncatchable class");
}

/// A header the redelivery loop or a catch reads must be spelled exactly
/// as Camel spells it; the engine headers are read-only to routes
/// (section 8.11.4).
#[tokio::test]
async fn the_engine_error_headers_stay_read_only() {
    check_servable(&steps(json!([
        {"setHeader": {"name": "CamelRedeliveryCounter", "value": {"constant": 1}}}
    ])))
    .expect_err("a route cannot write the redelivery counter");
}
