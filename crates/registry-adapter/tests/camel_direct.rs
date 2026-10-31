// SPDX-License-Identifier: Apache-2.0

//! The `direct:` conformance suite, port-table row 9
//! (`products/adapter/CONCEPT.md` sections 8.8 and 8.11.7): a synchronous
//! in-process call that shares the exchange, the target's clauses handle
//! the target first, the caller's clauses see what the target did not
//! handle, and a `to: direct:` send is never redelivered.

use std::collections::BTreeMap;
use std::sync::Arc;

use registry_adapter::exchange::Exchange;
use registry_adapter::resilience::ResilienceRuntime;
use registry_adapter::route::{
    check_direct_targets, check_servable, run_route, EndpointRuntime, RouteContext, RouteFailure,
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

/// One endpoint over the loopback double, the same static-api-key shape
/// the resilience suite sends through.
fn direct_endpoints(
    base_url: &str,
    resolver: &SecretResolver,
) -> BTreeMap<String, EndpointRuntime> {
    let binding = EndpointBinding {
        endpoint: ExternalId::new("tracker").expect("endpoint id"),
        base_url: Url::new(base_url).expect("base url"),
        credential: Some(RuntimeCredential::StaticApiKey {
            value_ref: SecretReference::new("secret:env/DIRECT_KEY").expect("secret reference"),
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
        id: LocalId::new("direct").expect("deployment id"),
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
                "runtimeUrlRef": "secret:env/DIRECT_DB",
                "migrationUrlRef": "secret:env/DIRECT_DB"
            }"#,
        )
        .expect("database"),
        oidc: serde_json::from_str(
            r#"{ "issuer": "https://issuer.example.invalid", "audience": "direct" }"#,
        )
        .expect("oidc"),
        allowed_clients: UniqueList::new(vec![ExternalId::new("direct-client").expect("client")])
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

/// One lane: the double, the endpoints, the route table every direct
/// call resolves against, and the one resilience runtime shared by the
/// whole deployment, the way a served deployment holds its state for
/// the process lifetime.
struct Lane {
    double: upstream::UpstreamDouble,
    endpoints: BTreeMap<String, EndpointRuntime>,
    scripts: ScriptSet,
    resolver: SecretResolver,
    resilience: ResilienceRuntime,
    routes: RouteTable,
    steps: Vec<Step>,
}

impl Lane {
    fn over(main: Value, routes: Value) -> Self {
        let double = upstream::UpstreamDouble::start();
        std::env::set_var("DIRECT_KEY", "direct-key");
        let resolver = SecretResolver::new([SecretProvider::Environment], "")
            .expect("the environment resolver builds");
        let endpoints = direct_endpoints(&double.url("/"), &resolver);
        let mut table: RouteTable = BTreeMap::new();
        let mut resilience = ResilienceRuntime::empty();
        if let Value::Object(entries) = routes {
            for (id, body) in entries {
                let target = steps(body.clone());
                resilience.absorb(&target);
                table.insert(id.clone(), Arc::new(target));
            }
        }
        let steps = steps(main);
        resilience.absorb(&steps);
        Self {
            double,
            endpoints,
            scripts: ScriptSet::default(),
            resolver,
            resilience,
            routes: table,
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
        let context = RouteContext {
            endpoints: &self.endpoints,
            scripts: &self.scripts,
            resolver: &self.resolver,
            resilience: &self.resilience,
            routes: &self.routes,
            code_maps: empty_code_maps(),
            maximum_upstream_calls: 12,
        };
        run_route(&context, &self.steps, Exchange::new("direct".to_owned())).await
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

/// A synchronous `direct:` call exposes the target's body and property
/// changes on the caller's same exchange.
///
/// Camel cases:
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/component/direct/DirectNoToTypeTest.java#testNoToType` and
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/component/direct/DirectShouldUseSameThreadTest.java#testUseSameThread`.
#[tokio::test]
async fn a_direct_call_shares_the_exchange_and_its_changes() {
    let lane = Lane::over(
        json!([
            {"setProperty": {"name": "caller", "value": {"constant": "main"}}},
            {"to": {"uri": "direct:helper"}},
            {"setProperty": {"name": "after", "value": {"constant": "back"}}}
        ]),
        json!({"helper": [
            {"setProperty": {"name": "inside", "value": {"constant": "helper"}}},
            {"setBody": {"constant": {"deep": true}}}
        ]}),
    );
    let outcome = lane.run().await;
    let exchange = ok(&outcome);
    assert_eq!(exchange.property("inside"), Some(&json!("helper")));
    assert_eq!(exchange.message.body, json!({"deep": true}));
    assert_eq!(exchange.property("after"), Some(&json!("back")));
    // One exchange, one flow: the caller's own property survived the
    // call and the target's changes came back on the same exchange.
    assert_eq!(exchange.property("caller"), Some(&json!("main")));
}

#[tokio::test]
async fn the_targets_own_clauses_handle_the_target_first() {
    let lane = Lane::over(
        json!([
            {"to": {"uri": "direct:guarded"}},
            {"setProperty": {"name": "after", "value": {"constant": "ran"}}}
        ]),
        json!({"guarded": [
            {"onException": {
                "exception": ["validation"],
                "handled": true,
                "steps": [{"setProperty": {
                    "name": "saw",
                    "value": {"constant": "target"}
                }}]
            }},
            {"throwException": {"exceptionType": "validation"}}
        ]}),
    );
    let outcome = lane.run().await;
    let exchange = ok(&outcome);
    assert_eq!(exchange.property("saw"), Some(&json!("target")));
    assert_eq!(exchange.property("after"), Some(&json!("ran")));
}

#[tokio::test]
async fn an_unhandled_target_error_reaches_the_callers_clauses() {
    let lane = Lane::over(
        json!([
            {"onException": {
                "exception": ["validation"],
                "handled": true,
                "steps": [{"setProperty": {
                    "name": "saw",
                    "value": {"constant": "caller"}
                }}]
            }},
            {"to": {"uri": "direct:plain"}},
            {"setProperty": {"name": "after", "value": {"constant": "never"}}}
        ]),
        json!({"plain": [
            {"throwException": {"exceptionType": "validation"}}
        ]}),
    );
    let outcome = lane.run().await;
    let exchange = ok(&outcome);
    assert_eq!(
        exchange.property("saw"),
        Some(&json!("caller")),
        "the caller's clause claimed what the target left unhandled"
    );
    assert_eq!(exchange.property("after"), None);
    assert!(has_event(&outcome, "exchangeFailureHandled"));
}

/// This is a recorded divergence from Camel's route error handler, which
/// redelivers through a `direct:` subroute. The Adapter never redelivers the
/// `direct:` send itself.
///
/// Camel divergence anchor:
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/RedeliverToSubRouteRemoveHeadersDecrementTest.java#testDecrementCounterWithRemoveHeaders`.
#[tokio::test]
async fn a_direct_send_is_never_redelivered() {
    // The caller's handler would redeliver a failing endpoint send three
    // times; a direct send is never redelivered (section 8.11.7), so the
    // whole call runs once and its single send is all the double sees.
    let lane = Lane::over(
        json!([
            {"errorHandler": {"defaultErrorHandler": {"redeliveryPolicy": {
                "maximumRedeliveries": 3, "retryDelaySeconds": 1
            }}}},
            {"to": {"uri": "direct:sending"}},
            {"setProperty": {"name": "after", "value": {"constant": "never"}}}
        ]),
        json!({"sending": [get()]}),
    );
    lane.replies(&[500, 500, 500, 500]);
    let outcome = lane.run().await;
    assert_eq!(failed_class(&outcome), "upstream.http");
    assert_eq!(lane.requests(), 1, "the direct call ran once, send and all");
    assert!(
        !has_event(&outcome, "exchangeRedelivery"),
        "no policy redelivers a direct call"
    );
}

#[tokio::test]
async fn the_targets_own_sends_carry_their_redelivery() {
    // The target's own handler redelivers its endpoint send once; the
    // direct call that wraps it neither adds nor withholds that.
    let lane = Lane::over(
        json!([{"to": {"uri": "direct:sending"}}]),
        json!({"sending": [
            {"errorHandler": {"defaultErrorHandler": {"redeliveryPolicy": {
                "maximumRedeliveries": 1, "retryDelaySeconds": 1
            }}}},
            get()
        ]}),
    );
    lane.replies(&[500, 200]);
    let outcome = lane.run().await;
    assert!(outcome.result.is_ok(), "the redelivered send recovered");
    assert_eq!(lane.requests(), 2);
    assert!(has_event(&outcome, "exchangeRedelivery"));
}

#[tokio::test]
async fn a_stop_in_the_target_ends_the_whole_route() {
    let lane = Lane::over(
        json!([
            {"to": {"uri": "direct:stopping"}},
            {"setProperty": {"name": "after", "value": {"constant": "never"}}}
        ]),
        json!({"stopping": [
            {"setProperty": {"name": "saw", "value": {"constant": "target"}}},
            {"stop": {}}
        ]}),
    );
    let outcome = lane.run().await;
    let exchange = ok(&outcome);
    assert_eq!(exchange.property("saw"), Some(&json!("target")));
    assert_eq!(
        exchange.property("after"),
        None,
        "the target's stop ends the caller's route too"
    );
}

/// Camel fails an InOut `direct:` send when no consumer is available; the
/// Adapter preserves failure but uses its closed `egress.refused` class.
///
/// Camel case:
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/component/direct/DirectNoConsumerTest.java#testInOut`.
#[tokio::test]
async fn a_direct_send_to_an_undeclared_route_fails_the_exchange() {
    let lane = Lane::over(json!([{"to": {"uri": "direct:nowhere"}}]), json!({}));
    let outcome = lane.run().await;
    assert_eq!(failed_class(&outcome), "egress.refused");
    assert_eq!(lane.requests(), 0);
}

/// Unlike Camel's runtime consumer lookup, the Adapter also resolves every
/// static target before serving a route table.
///
/// Camel behavior anchor:
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/component/direct/DirectNoConsumerTest.java#testInOut`.
#[test]
fn an_undeclared_direct_target_is_refused_at_load() {
    let mut routes: RouteTable = BTreeMap::new();
    routes.insert(
        "main".to_owned(),
        Arc::new(steps(json!([{"to": {"uri": "direct:missing"}}]))),
    );
    let refusal = check_direct_targets(&routes).expect_err("the target is refused");
    assert!(
        refusal.contains("missing"),
        "the refusal names the route: {refusal}"
    );
    routes.insert(
        "missing".to_owned(),
        Arc::new(steps(
            json!([{"setProperty": {"name": "x", "value": {"constant": 1}}}]),
        )),
    );
    check_direct_targets(&routes).expect("a declared target is served");
}

#[tokio::test]
async fn a_direct_chain_past_the_bounded_depth_is_refused_at_run() {
    // The authoring checks bound the chain statically; the engine holds
    // the same bound at run, so a table that never saw those checks
    // still cannot recurse without end.
    let bound = registry_adapter_core::MAX_DIRECT_DEPTH;
    let mut chain = json!({"sink": [{"setProperty": {"name": "x", "value": {"constant": 1}}}]});
    if let Value::Object(entries) = &mut chain {
        for hop in 0..bound + 2 {
            entries.insert(
                format!("hop{hop}"),
                json!([{"to": {"uri": format!("direct:hop{}", hop + 1)}}]),
            );
        }
        // The deepest hop names the sink, not another hop.
        entries.insert(
            format!("hop{}", bound + 1),
            json!([{"to": {"uri": "direct:sink"}}]),
        );
    }
    let lane = Lane::over(json!([{"to": {"uri": "direct:hop0"}}]), chain);
    let outcome = lane.run().await;
    assert_eq!(failed_class(&outcome), "budget.exhausted");
}

/// Camel accepts endpoint options such as `failIfNoConsumers`, `block`, and
/// `timeout`; the bounded Adapter form accepts no `direct:` parameters.
///
/// Camel divergence anchors:
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/component/direct/DirectNoConsumerTest.java#testFailIfNoConsumerFalse` and
/// `camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/component/direct/DirectProducerBlockingTest.java#testProducerBlocksWithNoConsumers`.
#[test]
fn a_direct_send_with_parameters_is_not_served() {
    let refusal = check_servable(&steps(json!([{"to": {
        "uri": "direct:helper",
        "parameters": {"httpMethod": "GET", "path": "/thing"}
    }}])))
    .expect_err("a parameterized direct send is refused");
    assert!(
        refusal.contains("direct"),
        "the refusal names the direct form: {refusal}"
    );
    check_servable(&steps(json!([{"to": {"uri": "direct:helper"}}])))
        .expect("a bare direct send is served");
}
