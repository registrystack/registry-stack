// SPDX-License-Identifier: Apache-2.0

//! Engine conformance for the leaf processors of the port table
//! (`products/adapter/CONCEPT.md` sections 8.5 and 8.6): `transform`,
//! `setHeader`, `removeHeader`, `removeProperty`, `script`, `choice`,
//! `filter`, `validate`, and `stop`, with the `jsonpath` expression
//! language wired into the interpreter (section 8.11.8's result rules).

use std::collections::BTreeMap;

use registry_adapter::exchange::Exchange;
use registry_adapter::route::{check_servable, run_route, RouteContext};
use registry_adapter::scripts::ScriptSet;
use registry_adapter_core::{AdapterPack, ErrorClass, Step};
use registry_platform_config::{sha256_uri, SecretProvider, SecretResolver};
use serde_json::{json, Value};

fn steps(value: Value) -> Vec<Step> {
    serde_json::from_value(value).expect("the steps parse")
}

/// One route run over a body-bearing exchange, with no endpoint and the
/// given scripts: the leaf processors need no upstream.
async fn run(step_list: Vec<Step>, scripts: &ScriptSet) -> registry_adapter::route::RouteOutcome {
    let endpoints = BTreeMap::new();
    let resolver = SecretResolver::new([SecretProvider::Environment], "")
        .expect("the environment resolver builds");
    let resilience = registry_adapter::resilience::ResilienceRuntime::empty();
    let context = RouteContext {
        endpoints: &endpoints,
        scripts,
        resolver: &resolver,
        resilience: &resilience,
        maximum_upstream_calls: 4,
    };
    let mut exchange = Exchange::new("test".to_owned());
    exchange.message.body = json!({"items": [{"id": "a"}, {"id": "b"}]});
    exchange.message.set_header("recordType", json!("persons"));
    exchange.message.set_header("recordId", json!("a"));
    run_route(&context, &step_list, exchange).await
}

/// A script set over one in-memory script file, pinned by its digest.
fn scripts(source: &str) -> ScriptSet {
    let directory = tempfile::tempdir().expect("a scratch directory");
    std::fs::write(directory.path().join("props.rhai"), source).expect("the script is written");
    let pack: AdapterPack = serde_json::from_value(json!({
        "id": "probe",
        "version": "1",
        "testedVersions": ["1"],
        "scripts": [{"path": "props.rhai", "digest": sha256_uri(source.as_bytes())}],
    }))
    .expect("the pack parses");
    let mut set = ScriptSet::default();
    set.add(&pack, directory.path(), "props.rhai", "apply")
        .expect("the script compiles under its pinned digest");
    set
}

/// Rhai writes a returned property map as an object map literal.
fn property_script(map: &str) -> ScriptSet {
    scripts(&format!("fn apply(exchange) {{ #{{ {map} }} }}"))
}

fn body_of(outcome: &registry_adapter::route::RouteOutcome) -> &Value {
    &outcome
        .result
        .as_ref()
        .expect("the route succeeds")
        .message
        .body
}

/// `transform` replaces the body from its expression under the same rules
/// as `setBody` (manual/transform-eip.html; the port table's one row for
/// both).
#[tokio::test]
async fn transform_replaces_the_body_from_its_expression() {
    let outcome = run(
        steps(json!([
            {"setBody": {"constant": {"n": 1}}},
            {"transform": {"constant": {"m": 2}}},
        ])),
        &ScriptSet::default(),
    )
    .await;
    assert_eq!(body_of(&outcome), &json!({"m": 2}));
}

/// A `jsonpath` expression yields its one value when singular and the
/// matched nodes as a list otherwise; an absent singular result raises
/// `validation` where a value is required, while a present null node is
/// a value, exactly as section 8.11.8 fixes the shapes.
#[tokio::test]
async fn jsonpath_yields_its_singular_value_or_its_node_list() {
    let singular = run(
        steps(json!([{"transform": {"jsonpath": "$.items[0].id"}}])),
        &ScriptSet::default(),
    )
    .await;
    assert_eq!(body_of(&singular), &json!("a"));
    let list = run(
        steps(json!([{"transform": {"jsonpath": "$.items[*].id"}}])),
        &ScriptSet::default(),
    )
    .await;
    assert_eq!(body_of(&list), &json!(["a", "b"]));
    let absent = run(
        steps(json!([{"transform": {"jsonpath": "$.none.such"}}])),
        &ScriptSet::default(),
    )
    .await;
    assert_eq!(
        absent
            .result
            .expect_err("an absent result raises validation where a value is required")
            .class,
        ErrorClass::Validation
    );
    let present_null = run(
        steps(json!([
            {"setBody": {"constant": {"seen": null}}},
            {"transform": {"jsonpath": "$.seen"}}
        ])),
        &ScriptSet::default(),
    )
    .await;
    assert_eq!(body_of(&present_null), &json!(null));
    check_servable(&steps(json!([
        {"transform": {"jsonpath": format!("$.{}", "a".repeat(4096))}}
    ])))
    .expect_err("an over-long selector is refused at load");
}

/// `setHeader` sets one header from an expression, compared without case
/// after the set (manual/setHeader-eip.html, Message.java).
#[tokio::test]
async fn set_header_sets_one_header_from_its_expression() {
    let outcome = run(
        steps(json!([
            {"setHeader": {"name": "X-Total", "value": {"constant": 3}}},
            {"setHeader": {"name": "x-origin", "value": {"header": "recordType"}}},
            {"setHeader": {"name": "x-first", "value": {"jsonpath": "$.items[0].id"}}},
        ])),
        &ScriptSet::default(),
    )
    .await;
    let exchange = outcome.result.expect("the route succeeds");
    assert_eq!(exchange.message.header("X-TOTAL"), Some(&json!(3)));
    assert_eq!(exchange.message.header("x-origin"), Some(&json!("persons")));
    assert_eq!(exchange.message.header("x-first"), Some(&json!("a")));
}

/// A route writes no read-only header: the facade inputs, the credential
/// and hop-by-hop names, and the engine's `Camel` and `Adapter` prefixes
/// refuse at load, for `setHeader` and `removeHeader` alike
/// (sections 8.11.1 and 8.11.4).
#[test]
fn header_writes_refuse_the_read_only_targets_at_load() {
    for refused in [
        "recordId",
        "recordType",
        "pageSize",
        "Idempotency-Key",
        "Authorization",
        "Proxy-Authorization",
        "CamelHttpResponseCode",
        "AdapterAnything",
    ] {
        let set = steps(json!([{"setHeader": {"name": refused, "value": {"constant": 1}}}]));
        let refusal = check_servable(&set).expect_err("the set is refused");
        assert!(refusal.contains(refused), "{refused}: {refusal}");
        let remove = steps(json!([{"removeHeader": refused}]));
        assert!(check_servable(&remove).is_err(), "{refused}");
    }
    check_servable(&steps(
        json!([{"setHeader": {"name": "X-Own", "value": {"constant": 1}}}]),
    ))
    .expect("a route's own name is writable");
}

/// `removeHeader` removes a header an earlier step set
/// (manual/removeHeader-eip.html).
#[tokio::test]
async fn remove_header_removes_a_route_set_header() {
    let outcome = run(
        steps(json!([
            {"setHeader": {"name": "x-temp", "value": {"constant": 1}}},
            {"removeHeader": "x-temp"},
        ])),
        &ScriptSet::default(),
    )
    .await;
    assert_eq!(
        outcome
            .result
            .expect("the route succeeds")
            .message
            .header("x-temp"),
        None
    );
}

/// `removeProperty` removes a route property; the read-only properties
/// refuse, `AdapterNextContinuation` excepted, as for `setProperty`
/// (manual/removeProperty-eip.html, section 8.11.1).
#[tokio::test]
async fn remove_property_removes_a_route_property_and_refuses_facade_names() {
    let outcome = run(
        steps(json!([
            {"setProperty": {"name": "page", "value": {"constant": 2}}},
            {"removeProperty": "page"},
        ])),
        &ScriptSet::default(),
    )
    .await;
    assert_eq!(
        outcome.result.expect("the route succeeds").property("page"),
        None
    );
    for refused in ["AdapterFilters", "AdapterContinuation", "AdapterAnything"] {
        let remove = steps(json!([{"removeProperty": refused}]));
        let refusal = check_servable(&remove).expect_err("the removal is refused");
        assert!(refusal.contains(refused), "{refused}: {refusal}");
    }
    check_servable(&steps(json!([
        {"removeProperty": "AdapterNextContinuation"}
    ])))
    .expect("the next continuation exists to be set and removed");
}

/// The `script` EIP runs one expression for effect on properties without
/// changing the body: the entrypoint returns a map of property names to
/// values (manual/script-eip.html, section 8.11.3's slot table).
#[tokio::test]
async fn script_sets_properties_from_a_returned_map_and_leaves_the_body() {
    let set = property_script(r#""seen": true, "first": exchange.body.items[0].id"#);
    let outcome = run(
        steps(json!([{"script": {"rhai": {"file": "props.rhai", "entrypoint": "apply"}}}])),
        &set,
    )
    .await;
    let exchange = outcome.result.expect("the route succeeds");
    assert_eq!(exchange.property("seen"), Some(&json!(true)));
    assert_eq!(exchange.property("first"), Some(&json!("a")));
    assert_eq!(
        exchange.message.body["items"].as_array().map(Vec::len),
        Some(2)
    );
}

/// A script may set the one reserved property a search route hands back,
/// and no other reserved property: the `Adapter` prefix belongs to the
/// engine (section 8.11.2's set rule, one step down).
#[tokio::test]
async fn script_writes_the_next_continuation_and_no_other_reserved_property() {
    let set = property_script(r#""AdapterNextContinuation": 2"#);
    let outcome = run(
        steps(json!([{"script": {"rhai": {"file": "props.rhai", "entrypoint": "apply"}}}])),
        &set,
    )
    .await;
    assert_eq!(
        outcome
            .result
            .expect("the route succeeds")
            .property("AdapterNextContinuation"),
        Some(&json!(2))
    );
    let refused = property_script(r#""AdapterFilters": {}"#);
    let outcome = run(
        steps(json!([{"script": {"rhai": {"file": "props.rhai", "entrypoint": "apply"}}}])),
        &refused,
    )
    .await;
    assert_eq!(
        outcome.result.expect_err("the reserved write fails").class,
        ErrorClass::Script
    );
}

/// A script that returns no map of properties fails the exchange with the
/// `script` class (section 8.11.3: the slot returns a map).
#[tokio::test]
async fn script_returning_no_map_fails_the_exchange() {
    let set = scripts(r#"fn apply(exchange) { 3 }"#);
    let outcome = run(
        steps(json!([{"script": {"rhai": {"file": "props.rhai", "entrypoint": "apply"}}}])),
        &set,
    )
    .await;
    assert_eq!(
        outcome.result.expect_err("a non-map return fails").class,
        ErrorClass::Script
    );
}

/// `choice` runs the first matching `when` and `otherwise` when none
/// matches; an unmatched exchange continues the route after the choice
/// (manual/choice-eip.html).
#[tokio::test]
async fn choice_runs_the_first_matching_when_and_otherwise_when_none_matches() {
    let outcome = run(
        steps(json!([
            {"setHeader": {"name": "x-typed", "value": {"constant": true}}},
            {"choice": {
                "when": [
                    {"header": "x-typed", "steps": [{"setBody": {"constant": "typed"}}]},
                    {"constant": true, "steps": [{"setBody": {"constant": "second"}}]}
                ],
                "otherwise": {"steps": [{"setBody": {"constant": "fallback"}}]}
            }},
            {"setHeader": {"name": "x-after", "value": {"constant": 1}}}
        ])),
        &ScriptSet::default(),
    )
    .await;
    let exchange = outcome.result.expect("the route succeeds");
    assert_eq!(exchange.message.body, json!("typed"));
    assert_eq!(exchange.message.header("x-after"), Some(&json!(1)));

    let none = run(
        steps(json!([
            {"choice": {
                "when": [{"constant": false, "steps": [{"setBody": {"constant": "no"}}]}],
                "otherwise": {"steps": [{"setBody": {"constant": "fallback"}}]}
            }}
        ])),
        &ScriptSet::default(),
    )
    .await;
    assert_eq!(body_of(&none), &json!("fallback"));
}

/// A predicate that yields no boolean is an error, never a truthiness
/// guess (section 8.5), and a non-singular `jsonpath` predicate is
/// refused before the route is registered (section 8.11.8).
#[tokio::test]
async fn a_non_boolean_predicate_fails_and_a_non_singular_one_never_loads() {
    let outcome = run(
        steps(json!([
            {"choice": {"when": [{"constant": "yes", "steps": [{"setBody": {"constant": 1}}]}]}}
        ])),
        &ScriptSet::default(),
    )
    .await;
    assert_eq!(
        outcome
            .result
            .expect_err("a non-boolean predicate fails")
            .class,
        ErrorClass::Script
    );
    check_servable(&steps(json!([
        {"choice": {"when": [
            {"jsonpath": "$.items[*].id", "steps": [{"setBody": {"constant": 1}}]}
        ]}}
    ])))
    .expect_err("a non-singular predicate is refused at load");
}

/// `filter` runs its steps only on a match, the route continues after the
/// filter either way, and `statusPropertyName`, when declared, records the
/// boolean outcome on a property (manual/filter-eip.html; Camel 4 sets no
/// fixed filter property).
#[tokio::test]
async fn filter_runs_its_steps_only_on_match_and_records_the_outcome() {
    let matched = run(
        steps(json!([
            {"setBody": {"constant": {"hit": true}}},
            {"filter": {
                "jsonpath": "$.hit",
                "steps": [{"setHeader": {"name": "x-hit", "value": {"constant": 1}}}],
                "statusPropertyName": "personMatched"
            }},
            {"setHeader": {"name": "x-after", "value": {"constant": 1}}}
        ])),
        &ScriptSet::default(),
    )
    .await;
    let exchange = matched.result.expect("the route succeeds");
    assert_eq!(exchange.message.header("x-hit"), Some(&json!(1)));
    assert_eq!(exchange.message.header("x-after"), Some(&json!(1)));
    assert_eq!(exchange.property("personMatched"), Some(&json!(true)));

    let unmatched = run(
        steps(json!([
            {"filter": {
                "constant": false,
                "steps": [{"setHeader": {"name": "x-hit", "value": {"constant": 1}}}],
                "statusPropertyName": "personMatched"
            }},
            {"setHeader": {"name": "x-after", "value": {"constant": 1}}}
        ])),
        &ScriptSet::default(),
    )
    .await;
    let exchange = unmatched.result.expect("the route succeeds");
    assert_eq!(exchange.message.header("x-hit"), None);
    assert_eq!(exchange.message.header("x-after"), Some(&json!(1)));
    assert_eq!(exchange.property("personMatched"), Some(&json!(false)));

    check_servable(&steps(json!([
        {"filter": {
            "constant": false,
            "steps": [],
            "statusPropertyName": "AdapterFilters"
        }}
    ])))
    .expect_err("the outcome property may not take a reserved name");
}

/// `validate` raises the `validation` class on a failing predicate and
/// passes a holding one (manual/validate-eip.html,
/// PredicateValidationException).
#[tokio::test]
async fn validate_raises_validation_on_a_failing_predicate() {
    let failed = run(
        steps(json!([{"validate": {"expression": {"constant": false}}}])),
        &ScriptSet::default(),
    )
    .await;
    assert_eq!(
        failed
            .result
            .expect_err("the failed predicate raises")
            .class,
        ErrorClass::Validation
    );
    let held = run(
        steps(json!([
            {"setBody": {"constant": {"ok": true}}},
            {"validate": {"expression": {"jsonpath": "$.ok"}}},
            {"setBody": {"constant": "passed"}}
        ])),
        &ScriptSet::default(),
    )
    .await;
    assert_eq!(body_of(&held), &json!("passed"));
}

/// `stop` ends the route without failing the exchange, from the body and
/// from inside a nested branch (manual/stop-eip.html).
#[tokio::test]
async fn stop_ends_the_route_without_failing() {
    let direct = run(
        steps(json!([
            {"setBody": {"constant": "kept"}},
            {"stop": {}},
            {"setBody": {"constant": "dropped"}}
        ])),
        &ScriptSet::default(),
    )
    .await;
    assert_eq!(body_of(&direct), &json!("kept"));

    let nested = run(
        steps(json!([
            {"choice": {
                "when": [{"constant": true, "steps": [{"stop": {}}]}],
                "otherwise": {"steps": [{"setBody": {"constant": "fallback"}}]}
            }},
            {"setBody": {"constant": "after"}}
        ])),
        &ScriptSet::default(),
    )
    .await;
    // No step after the stop ran, and the exchange did not fail: the body
    // is the one the route started with.
    assert_eq!(
        nested.result.expect("the route succeeds").message.body,
        json!({"items": [{"id": "a"}, {"id": "b"}]})
    );
}
