// SPDX-License-Identifier: Apache-2.0

//! Engine conformance for the splitting and repeating processors of the
//! port table (`products/adapter/CONCEPT.md` sections 8.6 and 8.11.7):
//! `split`, `loop`, `enrich`, and the aggregation strategies, with the
//! engine-set exchange headers each places.

use std::collections::BTreeMap;

use registry_adapter::exchange::Exchange;
use registry_adapter::route::{
    check_direct_targets, check_servable, run_route, EndpointRuntime, RouteContext, RouteOutcome,
    RouteTable,
};
use registry_adapter::scripts::ScriptSet;
use registry_adapter_core::{
    AdapterPack, AdapterRuntimeConfig, ComponentKind, Endpoint, EndpointAuthentication,
    EndpointBinding, ErrorClass, RuntimeCredential, Step,
};
use registry_platform_config::{sha256_uri, SecretProvider, SecretResolver};
use registry_platform_yaml::{
    BoundedU64, ExternalId, LocalId, SecretReference, UniqueIdList, UniqueList, Url,
};
use serde_json::{json, Value};

/// The empty code-map table: no test lane here converts.
fn empty_code_maps() -> registry_adapter::scripts::CodeMaps {
    std::sync::Arc::new(std::collections::BTreeMap::new())
}

fn steps(value: Value) -> Vec<Step> {
    serde_json::from_value(value).expect("the steps parse")
}

/// One route run over a body-bearing exchange, with no endpoint and the
/// given scripts: the split and loop processors need no upstream.
async fn run(step_list: Vec<Step>, scripts: &ScriptSet) -> RouteOutcome {
    let endpoints = BTreeMap::new();
    let resolver = SecretResolver::new([SecretProvider::Environment], "")
        .expect("the environment resolver builds");
    let resilience = registry_adapter::resilience::ResilienceRuntime::empty();
    let routes = RouteTable::new();
    let context = RouteContext {
        endpoints: &endpoints,
        scripts,
        resolver: &resolver,
        resilience: &resilience,
        routes: &routes,
        code_maps: empty_code_maps(),
        maximum_upstream_calls: 8,
    };
    let mut exchange = Exchange::new("test".to_owned());
    exchange.message.body = json!({"records": [{"id": "a"}, {"id": "b"}, {"id": "c"}]});
    run_route(&context, &step_list, exchange).await
}

/// A script set over one in-memory script file, pinned by its digest,
/// with its entrypoint registered under the one-argument `exchange`
/// contract (section 8.11.3).
/// A script set registering every entrypoint one script file serves, the
/// way a route references several entrypoints from one pack file.
fn scripts_of(source: &str, entrypoints: &[&str]) -> ScriptSet {
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
    for entrypoint in entrypoints {
        set.add(&pack, directory.path(), "props.rhai", entrypoint)
            .expect("the script compiles under its pinned digest");
    }
    set
}

fn one_script(entrypoint: &str, source: &str) -> ScriptSet {
    scripts_of(source, &[entrypoint])
}

/// A script set with a two-argument aggregation entrypoint registered
/// under the `old`/`new` strategy contract (section 8.11.7).
fn strategy_script(entrypoint: &str, body: &str) -> ScriptSet {
    let source = format!("fn {entrypoint}(oldExchange, newExchange) {{ {body} }}");
    let directory = tempfile::tempdir().expect("a scratch directory");
    std::fs::write(directory.path().join("props.rhai"), &source).expect("the script is written");
    let pack: AdapterPack = serde_json::from_value(json!({
        "id": "probe",
        "version": "1",
        "testedVersions": ["1"],
        "scripts": [{"path": "props.rhai", "digest": sha256_uri(source.as_bytes())}],
    }))
    .expect("the pack parses");
    let mut set = ScriptSet::default();
    set.add_aggregation(&pack, directory.path(), "props.rhai", entrypoint)
        .expect("the strategy entrypoint compiles under its pinned digest");
    set
}

/// The counting script: one run of its step adds one to the `count`
/// property, so a repeated body's iteration count is observable.
fn counting_script() -> ScriptSet {
    one_script(
        "apply",
        r#"fn apply(exchange) {
    let count = exchange.properties.count;
    if count == () { count = 0; }
    #{ "count": count + 1 }
}"#,
    )
}

/// A predicate script over the piece's engine headers.
fn piece_predicate(entrypoint: &str, test: &str) -> ScriptSet {
    one_script(
        entrypoint,
        &format!("fn {entrypoint}(exchange) {{ {test} }}"),
    )
}

fn body_of(outcome: &RouteOutcome) -> &Value {
    &outcome
        .result
        .as_ref()
        .expect("the route succeeds")
        .message
        .body
}

/// A split of the route's own records with the given extra members and
/// per-piece steps.
fn split_of(extra: Value, item_steps: Value) -> Value {
    let mut split = json!({
        "split": {
            "expression": {"jsonpath": "$.records"},
            "maximumItems": 5,
            "steps": item_steps,
        }
    });
    if let Some(object) = split["split"].as_object_mut() {
        if let Some(members) = extra.as_object() {
            for (name, value) in members {
                object.insert(name.clone(), value.clone());
            }
        }
    }
    split
}

/// Each piece runs on its own exchange carrying the engine headers
/// `CamelSplitIndex` (zero-based), `CamelSplitSize`, and
/// `CamelSplitComplete` on the last piece (manual/split-eip.html), and a
/// split without a strategy returns the original message, Camel's
/// `use-original` default (section 8.6).
#[tokio::test]
async fn split_runs_each_piece_under_the_engine_headers_and_returns_the_original() {
    let second = piece_predicate(
        "piece",
        "exchange.headers.camelsplitindex == 1 && exchange.headers.camelsplitsize == 3",
    );
    let outcome = run(
        steps(json!([split_of(
            json!({"aggregationStrategy": {"type": "grouped-body"}}),
            json!([{"choice": {"when": [
                {"rhai": {"file": "props.rhai", "entrypoint": "piece"},
                 "steps": [{"setBody": {"constant": "second"}}]}
            ]}}])
        ),])),
        &second,
    )
    .await;
    assert_eq!(
        body_of(&outcome),
        &json!([{"id": "a"}, "second", {"id": "c"}])
    );

    let last = piece_predicate("last", "exchange.headers.camelsplitcomplete == true");
    let outcome = run(
        steps(json!([split_of(
            json!({"aggregationStrategy": {"type": "grouped-body"}}),
            json!([{"choice": {"when": [
                {"rhai": {"file": "props.rhai", "entrypoint": "last"},
                 "steps": [{"setBody": {"constant": "last"}}]}
            ]}}])
        ),])),
        &last,
    )
    .await;
    assert_eq!(
        body_of(&outcome),
        &json!([{"id": "a"}, {"id": "b"}, "last"])
    );

    let original = run(
        steps(json!([split_of(
            json!({}),
            json!([{"setBody": {"constant": "dropped"}}])
        )])),
        &ScriptSet::default(),
    )
    .await;
    assert_eq!(
        body_of(&original),
        &json!({"records": [{"id": "a"}, {"id": "b"}, {"id": "c"}]})
    );
}

/// A `stop` inside a piece ends the split and then the route: the
/// stopped piece still aggregates and no step after the split runs
/// (manual/stop-eip.html inside a splitter).
#[tokio::test]
async fn a_stop_inside_a_piece_ends_the_split_and_the_route() {
    let first = piece_predicate("piece", "exchange.headers.camelsplitindex == 0");
    let outcome = run(
        steps(json!([
            split_of(
                json!({"aggregationStrategy": {"type": "grouped-body"}}),
                json!([{"choice": {"when": [
                    {"rhai": {"file": "props.rhai", "entrypoint": "piece"},
                     "steps": [{"stop": {}}]}
                ], "otherwise": {"steps": [
                    {"setBody": {"constant": "ran"}}
                ]}}}
                ])
            ),
            {"setHeader": {"name": "x-after", "value": {"constant": 1}}}
        ])),
        &first,
    )
    .await;
    let exchange = outcome.result.expect("the route succeeds");
    assert_eq!(exchange.message.body, json!([{"id": "a"}]));
    assert_eq!(exchange.message.header("x-after"), None);
}

/// Without the failure accounting, every piece runs and the last item
/// failure is raised after the split completes; `stopOnException` raises
/// the first failure instead, and a declared `use-original` with
/// `propagateException: false` swallows the failures
/// (manual/split-eip.html, section 8.6).
#[tokio::test]
async fn split_item_failures_raise_after_the_split_or_sooner_or_never() {
    let failing_records = json!({"records": [{"id": "a", "fail": true}, {"id": "b"}, {"id": "c"}]});
    let failing_piece = json!([
        {"choice": {"when": [
            {"jsonpath": "$.fail", "steps": [{"validate": {"expression": {"constant": false}}}]}
        ], "otherwise": {"steps": [
            {"setBody": {"jsonpath": "$.id"}},
            {"throwException": {"exceptionType": "script", "message": "late"}}
        ]}}}
    ]);
    let last = run(
        steps(json!([
            {"setBody": {"constant": failing_records.clone()}},
            split_of(json!({}), failing_piece.clone())
        ])),
        &ScriptSet::default(),
    )
    .await;
    assert_eq!(
        last.result.expect_err("the last failure is raised").class,
        ErrorClass::Script
    );
    let consumed: Vec<_> = last
        .events
        .iter()
        .filter(|event| event.kind == "exchangeFailureHandled")
        .map(|event| event.detail.clone())
        .collect();
    assert_eq!(
        consumed,
        vec![
            json!({"source": "split", "class": "validation"}),
            json!({"source": "split", "class": "script"}),
        ]
    );

    let first = run(
        steps(json!([
            {"setBody": {"constant": failing_records.clone()}},
            split_of(json!({"stopOnException": true}), failing_piece.clone())
        ])),
        &ScriptSet::default(),
    )
    .await;
    assert_eq!(
        first
            .result
            .expect_err("the first failure stops the split")
            .class,
        ErrorClass::Validation
    );
    assert!(
        first.events.is_empty(),
        "the returned failure was not consumed"
    );

    let swallowed = run(
        steps(json!([
            {"setBody": {"constant": failing_records}},
            split_of(
                json!({"aggregationStrategy": {
                    "type": "use-original", "propagateException": false
                }}),
                failing_piece
            )
        ])),
        &ScriptSet::default(),
    )
    .await;
    let exchange = swallowed.result.expect("the failures are swallowed");
    assert_eq!(
        exchange.message.body,
        json!({"records": [{"id": "a", "fail": true}, {"id": "b"}, {"id": "c"}]})
    );
    assert_eq!(exchange.message.header("CamelSplitResult"), None);
    assert_eq!(
        swallowed
            .events
            .iter()
            .filter(|event| event.kind == "exchangeFailureHandled")
            .count(),
        3,
        "every swallowed piece failure is journaled"
    );
}

/// The failure accounting keeps the split going under its thresholds,
/// sets `CamelSplitResult` on the exchange with the counts, and stops at
/// the threshold, raising the piece's failure
/// (manual/split-eip.html, section 8.6).
#[tokio::test]
async fn split_failure_accounting_counts_stops_and_reports() {
    // The failure sits in the middle: a first-piece failure fails every
    // ratio threshold at once (one failure over one processed).
    let failing_records = json!({"records": [{"id": "a"}, {"id": "b", "fail": true}, {"id": "c"}]});
    let failing_piece = json!([
        {"choice": {"when": [
            {"jsonpath": "$.fail", "steps": [{"validate": {"expression": {"constant": false}}}]}
        ], "otherwise": {"steps": [{"setBody": {"jsonpath": "$.id"}}]}}}
    ]);
    let route = |extra: Value| {
        steps(json!([
            {"setBody": {"constant": failing_records.clone()}},
            split_of(extra, failing_piece.clone())
        ]))
    };

    let under = run(
        route(json!({
            "aggregationStrategy": {"type": "grouped-body"},
            "errorThreshold": 0.6
        })),
        &ScriptSet::default(),
    )
    .await;
    let exchange = under
        .result
        .expect("the split completes under the threshold");
    assert_eq!(exchange.message.body, json!(["a", "c"]));
    assert_eq!(
        exchange.message.header("CamelSplitResult"),
        Some(&json!({
            "totalItems": 3,
            "processedItems": 3,
            "failureCount": 1,
        }))
    );
    assert_eq!(
        under
            .events
            .iter()
            .filter(|event| event.kind == "exchangeFailureHandled")
            .map(|event| event.detail.clone())
            .collect::<Vec<_>>(),
        vec![json!({"source": "split", "class": "validation"})]
    );

    let over = run(
        route(json!({
            "aggregationStrategy": {"type": "grouped-body"},
            "errorThreshold": 0.5
        })),
        &ScriptSet::default(),
    )
    .await;
    assert_eq!(
        over.result
            .expect_err("the reached ratio stops and raises")
            .class,
        ErrorClass::Validation
    );
    assert!(
        over.events.is_empty(),
        "the returned threshold failure was not consumed"
    );

    let counted = run(
        route(json!({"maximumFailedRecords": 1})),
        &ScriptSet::default(),
    )
    .await;
    assert_eq!(
        counted
            .result
            .expect_err("the failed-records bound stops and raises")
            .class,
        ErrorClass::Validation
    );
}

/// `json-array-append` appends the array held by the named property of
/// each piece into the named body member, refuses a `uniqueBy` duplicate
/// with `aggregation.duplicate`, and a piece naming no array property
/// fails the exchange (section 8.6's additions).
#[tokio::test]
async fn split_json_array_append_merges_a_named_property_and_refuses_duplicates() {
    let carrying_records = json!({
        "records": [{"id": "z"}],
        "pieces": [
            {"entries": [{"id": "a"}]},
            {"entries": [{"id": "b"}]},
            {"entries": [{"id": "c"}]}
        ]
    });
    let strategy = json!({
        "type": "json-array-append",
        "from": "piece",
        "into": "records",
        "uniqueBy": "id"
    });
    let carries = json!([{"setProperty": {"name": "piece", "value": {"jsonpath": "$.entries"}}}]);
    let outcome = run(
        steps(json!([
            {"setBody": {"constant": carrying_records.clone()}},
            {"split": {
                "expression": {"jsonpath": "$.pieces"},
                "maximumItems": 5,
                "aggregationStrategy": strategy.clone(),
                "steps": carries.clone()
            }}
        ])),
        &ScriptSet::default(),
    )
    .await;
    assert_eq!(
        body_of(&outcome),
        &json!({"records": [{"id": "z"}, {"id": "a"}, {"id": "b"}, {"id": "c"}],
                "pieces": [{"entries": [{"id": "a"}]}, {"entries": [{"id": "b"}]}, {"entries": [{"id": "c"}]}]})
    );

    let duplicate_records = json!({
        "records": [{"id": "a"}],
        "pieces": [
            {"entries": [{"id": "a"}]},
            {"entries": [{"id": "b"}]}
        ]
    });
    let duplicate = run(
        steps(json!([
            {"setBody": {"constant": duplicate_records}},
            {"split": {
                "expression": {"jsonpath": "$.pieces"},
                "maximumItems": 5,
                "aggregationStrategy": strategy.clone(),
                "steps": carries.clone()
            }}
        ])),
        &ScriptSet::default(),
    )
    .await;
    assert_eq!(
        duplicate
            .result
            .expect_err("the repeated id is refused")
            .class,
        ErrorClass::AggregationDuplicate
    );

    let absent = run(
        steps(json!([
            {"setBody": {"constant": carrying_records}},
            {"split": {
                "expression": {"jsonpath": "$.pieces"},
                "maximumItems": 5,
                "aggregationStrategy": strategy,
                "steps": json!([])
            }}
        ])),
        &ScriptSet::default(),
    )
    .await;
    assert_eq!(
        absent
            .result
            .expect_err("a piece naming no array property fails")
            .class,
        ErrorClass::Validation
    );
}

/// The `properties` map of a JSON strategy carries named values out of
/// each piece's body onto the route exchange, and an absent selection
/// removes the property, so a pagination loop's cursor ends absent on
/// the last page (section 8.11.7).
#[tokio::test]
async fn split_strategy_properties_carry_values_and_clear_absent_ones() {
    let records = json!({
        "records": [],
        "pieces": [
            {"entries": [{"id": "a"}], "cursor": "one"},
            {"entries": [{"id": "b"}]}
        ]
    });
    let carries = json!([{"setProperty": {"name": "piece", "value": {"jsonpath": "$.entries"}}}]);
    let carried = run(
        steps(json!([
            {"setBody": {"constant": records.clone()}},
            {"split": {
                "expression": {"jsonpath": "$.pieces"},
                "maximumItems": 5,
                "aggregationStrategy": {
                    "type": "json-array-append",
                    "from": "piece",
                    "into": "records",
                    "properties": {"lastId": "$.entries[0].id"}
                },
                "steps": carries.clone()
            }}
        ])),
        &ScriptSet::default(),
    )
    .await;
    assert_eq!(
        carried
            .result
            .expect("the route succeeds")
            .property("lastId"),
        Some(&json!("b"))
    );

    let cleared = run(
        steps(json!([
            {"setBody": {"constant": records}},
            {"split": {
                "expression": {"jsonpath": "$.pieces"},
                "maximumItems": 5,
                "aggregationStrategy": {
                    "type": "json-array-append",
                    "from": "piece",
                    "into": "records",
                    "properties": {"cursor": "$.cursor"}
                },
                "steps": carries
            }}
        ])),
        &ScriptSet::default(),
    )
    .await;
    assert_eq!(
        cleared
            .result
            .expect("the route succeeds")
            .property("cursor"),
        None
    );

    // The carried names are property writes, so the engine's reserved
    // prefix is refused the same way `setProperty` refuses it.
    check_servable(&steps(json!([{"split": {
        "expression": {"jsonpath": "$.pieces"},
        "maximumItems": 5,
        "aggregationStrategy": {
            "type": "json-array-append",
            "from": "piece",
            "into": "records",
            "properties": {"AdapterContinuation": "$.cursor"}
        },
        "steps": []
    }}])))
    .expect_err("a strategy may not write a reserved property");
}

/// A split expression that yields no array fails as `validation`, a
/// piece count over the declared bound fails as `budget.exhausted`, and
/// the load refuses a split without its bound (sections 8.6 and 5.5).
#[tokio::test]
async fn split_refuses_its_shape_and_bound_faults() {
    let not_an_array = run(
        steps(json!([{"split": {
            "expression": {"constant": {"no": "array"}},
            "maximumItems": 5,
            "steps": []
        }}])),
        &ScriptSet::default(),
    )
    .await;
    assert_eq!(
        not_an_array
            .result
            .expect_err("a non-array expression fails")
            .class,
        ErrorClass::Validation
    );

    let over_bound = run(
        steps(json!([split_of(json!({"maximumItems": 2}), json!([]))])),
        &ScriptSet::default(),
    )
    .await;
    assert_eq!(
        over_bound
            .result
            .expect_err("the piece count over the bound fails")
            .class,
        ErrorClass::BudgetExhausted
    );

    check_servable(&steps(json!([{"split": {
        "expression": {"jsonpath": "$.records"},
        "steps": []
    }}])))
    .expect_err("a split without maximumItems is refused at load");
}

/// A count loop repeats its steps on the same exchange, carrying
/// `CamelLoopIndex` (zero-based) and `CamelLoopSize`, and a count of
/// zero runs nothing (manual/loop-eip.html, `LoopProcessor`).
#[tokio::test]
async fn a_count_loop_repeats_with_the_loop_headers() {
    let outcome = run(
        steps(json!([
            {"loop": {
                "constant": 3,
                "maximumIterations": 5,
                "steps": [{"script": {"rhai": {"file": "props.rhai", "entrypoint": "apply"}}}]
            }}
        ])),
        &counting_script(),
    )
    .await;
    let exchange = outcome.result.expect("the route succeeds");
    assert_eq!(exchange.property("count"), Some(&json!(3)));
    assert_eq!(exchange.message.header("CamelLoopIndex"), Some(&json!(2)));
    assert_eq!(exchange.message.header("CamelLoopSize"), Some(&json!(3)));

    let zero = run(
        steps(json!([
            {"loop": {
                "constant": 0,
                "maximumIterations": 5,
                "steps": [{"script": {"rhai": {"file": "props.rhai", "entrypoint": "apply"}}}]
            }}
        ])),
        &counting_script(),
    )
    .await;
    let exchange = zero.result.expect("the route succeeds");
    assert_eq!(exchange.property("count"), None);
    assert_eq!(exchange.message.header("CamelLoopSize"), Some(&json!(0)));
    assert_eq!(exchange.message.header("CamelLoopIndex"), None);
}

/// A `doWhile` loop tests its predicate on the current exchange before
/// every iteration, the first included, so a predicate already false
/// runs nothing and one its steps make false runs once
/// (`LoopProcessor`).
#[tokio::test]
async fn a_do_while_loop_tests_its_predicate_before_each_iteration() {
    let once = run(
        steps(json!([
            {"setBody": {"constant": {"more": true}}},
            {"loop": {
                "doWhile": true,
                "jsonpath": "$.more",
                "maximumIterations": 5,
                "steps": [
                    {"setBody": {"constant": {"more": false}}},
                    {"script": {"rhai": {"file": "props.rhai", "entrypoint": "apply"}}}
                ]
            }}
        ])),
        &counting_script(),
    )
    .await;
    assert_eq!(
        once.result.expect("the route succeeds").property("count"),
        Some(&json!(1))
    );

    let never = run(
        steps(json!([
            {"loop": {
                "doWhile": true,
                "constant": false,
                "maximumIterations": 5,
                "steps": [{"script": {"rhai": {"file": "props.rhai", "entrypoint": "apply"}}}]
            }}
        ])),
        &counting_script(),
    )
    .await;
    assert_eq!(
        never.result.expect("the route succeeds").property("count"),
        None
    );
}

/// A loop that reaches its bound still counting or still holding raises
/// the catchable `loop.maximum-iterations-reached`, while a loop that
/// lands exactly on its bound completes (section 8.6).
#[tokio::test]
async fn a_loop_at_its_bound_completes_and_one_past_it_raises() {
    let holding = run(
        steps(json!([
            {"loop": {
                "doWhile": true,
                "constant": true,
                "maximumIterations": 2,
                "steps": [{"script": {"rhai": {"file": "props.rhai", "entrypoint": "apply"}}}]
            }}
        ])),
        &counting_script(),
    )
    .await;
    assert_eq!(
        holding
            .result
            .expect_err("a predicate still holding at the bound raises")
            .class,
        ErrorClass::LoopMaximumIterationsReached
    );

    let counted = |header: Value| {
        steps(json!([
            {"setHeader": {"name": "x-iterations", "value": header}},
            {"loop": {
                "header": "x-iterations",
                "maximumIterations": 2,
                "steps": [{"script": {"rhai": {"file": "props.rhai", "entrypoint": "apply"}}}]
            }}
        ]))
    };
    let over = run(counted(json!({"constant": 5})), &counting_script()).await;
    assert_eq!(
        over.result
            .expect_err("a count above the bound raises")
            .class,
        ErrorClass::LoopMaximumIterationsReached
    );

    let at_bound = run(counted(json!({"constant": 2})), &counting_script()).await;
    assert_eq!(
        at_bound
            .result
            .expect("a count exactly at the bound completes")
            .property("count"),
        Some(&json!(2))
    );
}

/// A count that is no integer fails the exchange, and a `doWhile`
/// predicate that yields no boolean fails as a script fault
/// (section 8.5), while the load refuses the malformed loop shapes.
#[tokio::test]
async fn a_loop_count_must_be_an_integer_and_the_shape_must_be_well_formed() {
    let not_an_integer = run(
        steps(json!([
            {"setBody": {"constant": {"name": "x"}}},
            {"loop": {
                "jsonpath": "$.name",
                "maximumIterations": 5,
                "steps": []
            }}
        ])),
        &ScriptSet::default(),
    )
    .await;
    assert_eq!(
        not_an_integer
            .result
            .expect_err("a non-integer count fails")
            .class,
        ErrorClass::Validation
    );

    let not_a_boolean = run(
        steps(json!([
            {"loop": {
                "doWhile": true,
                "constant": "yes",
                "maximumIterations": 5,
                "steps": []
            }}
        ])),
        &ScriptSet::default(),
    )
    .await;
    assert_eq!(
        not_a_boolean
            .result
            .expect_err("a non-boolean predicate fails")
            .class,
        ErrorClass::Script
    );

    check_servable(&steps(json!([{"loop": {
        "constant": 1,
        "steps": []
    }}])))
    .expect_err("a loop without maximumIterations is refused at load");
    check_servable(&steps(json!([{"loop": {
        "maximumIterations": 5,
        "steps": []
    }}])))
    .expect_err("a loop without a language key is refused at load");
    check_servable(&steps(json!([{"loop": {
        "constant": 1,
        "header": "x",
        "maximumIterations": 5,
        "steps": []
    }}])))
    .expect_err("a loop with two language keys is refused at load");
    check_servable(&steps(json!([{"loop": {
        "doWhile": true,
        "jsonpath": "$.records[*]",
        "maximumIterations": 5,
        "steps": []
    }}])))
    .expect_err("a non-singular doWhile jsonpath is refused at load");
}

/// `copy` runs each iteration on a fresh copy of the original exchange,
/// so nothing accumulates between iterations and the last iteration's
/// exchange becomes the result (`LoopProcessor`'s `copy`), and a `stop`
/// inside an iteration ends the loop and the route with the exchange as
/// it stopped.
#[tokio::test]
async fn copy_mode_starts_each_iteration_from_the_original_and_keeps_the_last() {
    let outcome = run(
        steps(json!([
            {"loop": {
                "constant": 3,
                "copy": true,
                "maximumIterations": 5,
                "steps": [
                    {"script": {"rhai": {"file": "props.rhai", "entrypoint": "apply"}}},
                    {"setBody": {"constant": {"iterated": true}}}
                ]
            }}
        ])),
        &counting_script(),
    )
    .await;
    let exchange = outcome.result.expect("the route succeeds");
    assert_eq!(exchange.property("count"), Some(&json!(1)));
    assert_eq!(exchange.message.body, json!({"iterated": true}));
    assert_eq!(exchange.message.header("CamelLoopIndex"), Some(&json!(2)));

    let stopping = scripts_of(
        r#"fn apply(exchange) {
    let count = exchange.properties.count;
    if count == () { count = 0; }
    #{ "count": count + 1 }
}
fn again(exchange) { exchange.properties.count == 1 }"#,
        &["apply", "again"],
    );
    let stopped = run(
        steps(json!([
            {"loop": {
                "constant": 3,
                "maximumIterations": 5,
                "steps": [
                    {"script": {"rhai": {"file": "props.rhai", "entrypoint": "apply"}}},
                    {"choice": {"when": [
                        {"rhai": {"file": "props.rhai", "entrypoint": "again"},
                         "steps": [{"stop": {}}]}
                    ]}}
                ]
            }},
            {"setHeader": {"name": "x-after", "value": {"constant": 1}}}
        ])),
        &stopping,
    )
    .await;
    let exchange = stopped.result.expect("the route succeeds");
    assert_eq!(exchange.property("count"), Some(&json!(1)));
    assert_eq!(exchange.message.header("x-after"), None);
}

#[path = "support/upstream/mod.rs"]
#[allow(dead_code)]
mod upstream;

/// The endpoint the enrich tests send to: one static-api-key http
/// endpoint over the loopback double.
fn enrich_endpoints(
    base_url: &str,
    key_env: &str,
    resolver: &SecretResolver,
) -> BTreeMap<String, EndpointRuntime> {
    let binding = EndpointBinding {
        endpoint: ExternalId::new("tracker").expect("endpoint id"),
        base_url: Url::new(base_url).expect("base url"),
        credential: Some(RuntimeCredential::StaticApiKey {
            value_ref: SecretReference::new(format!("secret:env/{key_env}"))
                .expect("secret reference"),
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
        id: LocalId::new("split-loop").expect("deployment id"),
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
                "runtimeUrlRef": "secret:env/SPLIT_LOOP_DB",
                "migrationUrlRef": "secret:env/SPLIT_LOOP_DB"
            }"#,
        )
        .expect("database"),
        oidc: serde_json::from_str(
            r#"{ "issuer": "https://issuer.example.invalid", "audience": "split-loop" }"#,
        )
        .expect("oidc"),
        allowed_clients: UniqueList::new(vec![
            ExternalId::new("split-loop-client").expect("client")
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

/// One enrich route run against a scripted upstream.
async fn run_enrich(
    enrich: Value,
    scripts: &ScriptSet,
    replies: Vec<upstream::Response>,
) -> RouteOutcome {
    let double = upstream::UpstreamDouble::start();
    double.respond_with(replies);
    std::env::set_var("SPLIT_LOOP_KEY", "split-loop-key");
    let resolver = SecretResolver::new([SecretProvider::Environment], "")
        .expect("the environment resolver builds");
    let endpoints = enrich_endpoints(&double.url("/"), "SPLIT_LOOP_KEY", &resolver);
    let resilience = registry_adapter::resilience::ResilienceRuntime::empty();
    let routes = RouteTable::new();
    let context = RouteContext {
        endpoints: &endpoints,
        scripts,
        resolver: &resolver,
        resilience: &resilience,
        routes: &routes,
        code_maps: empty_code_maps(),
        maximum_upstream_calls: 8,
    };
    let mut exchange = Exchange::new("enrich".to_owned());
    exchange.message.body = json!({"q": 1});
    run_route(&context, &steps(json!([enrich])), exchange).await
}

/// A `direct:` resource route still sends over HTTP on its copied exchange;
/// aggregation carries only the selected body and properties back, never an
/// ordinary resource header.
#[tokio::test]
async fn direct_enrich_runs_the_resource_route_on_a_copy() {
    let double = upstream::UpstreamDouble::start();
    double.respond_with(vec![upstream::Response::json(
        200,
        r#"{"pieces":[{"id":"a"}],"next":"opaque"}"#,
    )]);
    std::env::set_var("SPLIT_LOOP_KEY", "split-loop-key");
    let resolver = SecretResolver::new([SecretProvider::Environment], "")
        .expect("the environment resolver builds");
    let endpoints = enrich_endpoints(&double.url("/"), "SPLIT_LOOP_KEY", &resolver);
    let scripts = ScriptSet::default();
    let resilience = registry_adapter::resilience::ResilienceRuntime::empty();
    let routes = RouteTable::from([(
        "fetch-page".to_owned(),
        std::sync::Arc::new(steps(json!([
            {"to": {"uri": "http:tracker", "parameters": {
                "httpMethod": "GET", "path": "/thing"
            }}},
            {"setProperty": {"name": "pages", "value": {"jsonpath": "$.pieces"}}},
            {"setHeader": {"name": "x-resource", "value": {"constant": "private"}}}
        ]))),
    )]);
    let context = RouteContext {
        endpoints: &endpoints,
        scripts: &scripts,
        resolver: &resolver,
        resilience: &resilience,
        routes: &routes,
        code_maps: empty_code_maps(),
        maximum_upstream_calls: 1,
    };
    let route = steps(json!([{
        "enrich": {
            "uri": "direct:fetch-page",
            "aggregationStrategy": {
                "type": "json-array-append",
                "from": "pages",
                "into": "records",
                "uniqueBy": "id",
                "properties": {"next": "$.next"}
            }
        }
    }]));
    check_servable(&route).expect("static direct enrichment is served");
    check_direct_targets(&routes).expect("the resource target is declared and acyclic");
    let mut exchange = Exchange::new("direct-enrich".to_owned());
    exchange.message.body = json!({"records": []});
    exchange
        .message
        .set_header("x-caller", Value::String("kept".to_owned()));

    let exchange = run_route(&context, &route, exchange)
        .await
        .result
        .expect("the direct resource route succeeds");

    assert_eq!(exchange.message.body, json!({"records": [{"id": "a"}]}));
    assert_eq!(exchange.property("next"), Some(&json!("opaque")));
    assert_eq!(exchange.message.header("x-caller"), Some(&json!("kept")));
    assert_eq!(exchange.message.header("x-resource"), None);
    assert_eq!(double.request_count(), 1);
}

/// `enrich` sends on a copy of the exchange and merges the reply through
/// its strategy: the default replaces the body with the resource reply,
/// `use-original` keeps the route's body, and a custom strategy folds
/// both bodies (manual/enrich-eip.html, section 8.11.7).
#[tokio::test]
async fn enrich_merges_the_resource_reply_through_its_strategy() {
    let reply = upstream::Response::json(200, r#"{"answer": 42}"#);
    let default = run_enrich(
        json!({"enrich": {"uri": "http:tracker", "parameters": {
            "httpMethod": "GET", "path": "/thing"
        }}}),
        &ScriptSet::default(),
        vec![reply.clone()],
    )
    .await;
    let exchange = default.result.expect("the route succeeds");
    assert_eq!(exchange.message.body, json!({"answer": 42}));
    assert_eq!(
        exchange.message.header("CamelHttpResponseCode"),
        Some(&json!(200))
    );

    let original = run_enrich(
        json!({"enrich": {
            "uri": "http:tracker",
            "aggregationStrategy": {"type": "use-original"},
            "parameters": {"httpMethod": "GET", "path": "/thing"}
        }}),
        &ScriptSet::default(),
        vec![reply.clone()],
    )
    .await;
    assert_eq!(
        original.result.expect("the route succeeds").message.body,
        json!({"q": 1})
    );

    let set = strategy_script(
        "merge",
        r#"#{ "body": #{ "kept": oldExchange.q, "answer": newExchange.answer }, "properties": #{ "saw": true } }"#,
    );
    let custom = run_enrich(
        json!({"enrich": {
            "uri": "http:tracker",
            "aggregationStrategy": {"type": "rhai", "expression": {
                "file": "props.rhai", "entrypoint": "merge"
            }},
            "parameters": {"httpMethod": "GET", "path": "/thing"}
        }}),
        &set,
        vec![reply],
    )
    .await;
    let exchange = custom.result.expect("the route succeeds");
    assert_eq!(exchange.message.body, json!({"kept": 1, "answer": 42}));
    assert_eq!(exchange.property("saw"), Some(&json!(true)));
}

/// A failed resource send propagates to the error handler unless the
/// step aggregates on exception, when the failure's own reply state
/// merges instead; and the JSON strategies, which read a named property
/// of the resource exchange, find none on an http reply
/// (section 8.6, section 8.11.7).
#[tokio::test]
async fn enrich_failure_propagates_unless_it_aggregates_on_exception() {
    let failure = vec![upstream::Response::json(500, r#"{"boom": true}"#)];
    let propagates = run_enrich(
        json!({"enrich": {"uri": "http:tracker", "parameters": {
            "httpMethod": "GET", "path": "/thing"
        }}}),
        &ScriptSet::default(),
        failure.clone(),
    )
    .await;
    assert_eq!(
        propagates
            .result
            .expect_err("the failed resource propagates")
            .class,
        ErrorClass::UpstreamHttp
    );

    let aggregates = run_enrich(
        json!({"enrich": {
            "uri": "http:tracker",
            "aggregateOnException": true,
            "parameters": {"httpMethod": "GET", "path": "/thing"}
        }}),
        &ScriptSet::default(),
        failure,
    )
    .await;
    assert_eq!(
        aggregates.result.expect("the failure merges").message.body,
        json!({"boom": true})
    );

    let json_strategy = run_enrich(
        json!({"enrich": {
            "uri": "http:tracker",
            "aggregationStrategy": {
                "type": "json-array-append", "from": "piece", "into": "records"
            },
            "parameters": {"httpMethod": "GET", "path": "/thing"}
        }}),
        &ScriptSet::default(),
        vec![upstream::Response::json(200, r#"{"answer": 42}"#)],
    )
    .await;
    assert_eq!(
        json_strategy
            .result
            .expect_err("the json strategies need a named property")
            .class,
        ErrorClass::Validation
    );
}

/// The load admits a static `direct:` resource and refuses the enrich shapes
/// this runtime does not serve: parameters on a direct resource, a non-GET
/// HTTP method, the split-only `grouped-body` strategy, and a missing HTTP
/// parameter block (sections 8.6 and 8.11.7).
#[test]
fn enrich_refuses_the_unserved_shapes_at_load() {
    check_servable(&steps(json!([{"enrich": {
        "uri": "direct:fetch-page"
    }}])))
    .expect("a static direct enrichment is served");
    check_servable(&steps(json!([{"enrich": {
        "uri": "direct:fetch-page",
        "parameters": {"httpMethod": "GET", "path": "/x"}
    }}])))
    .expect_err("a direct enrichment carries no endpoint parameters");
    check_servable(&steps(json!([{"enrich": {
        "uri": "http:tracker",
        "parameters": {"httpMethod": "POST", "path": "/x"}
    }}])))
    .expect_err("a non-GET enrichment is not served");
    check_servable(&steps(json!([{"enrich": {
        "uri": "http:tracker",
        "aggregationStrategy": {"type": "grouped-body"},
        "parameters": {"httpMethod": "GET", "path": "/x"}
    }}])))
    .expect_err("the split-only grouped-body strategy is refused");
    check_servable(&steps(json!([{"enrich": {"uri": "http:tracker"}}])))
        .expect_err("an enrichment without parameters is refused");
}

#[test]
fn direct_enrich_targets_are_resolved_and_acyclic_before_execution() {
    let missing = RouteTable::from([(
        "entry".to_owned(),
        std::sync::Arc::new(steps(json!([{"enrich": {"uri": "direct:missing"}}]))),
    )]);
    assert!(check_direct_targets(&missing)
        .expect_err("an unknown resource route is refused")
        .contains("missing"));

    let cyclic = RouteTable::from([
        (
            "first".to_owned(),
            std::sync::Arc::new(steps(json!([{"enrich": {"uri": "direct:second"}}]))),
        ),
        (
            "second".to_owned(),
            std::sync::Arc::new(steps(json!([{"enrich": {"uri": "direct:first"}}]))),
        ),
    ]);
    assert!(check_direct_targets(&cyclic)
        .expect_err("a cyclic resource graph is refused")
        .contains("cycle"));
}
