// SPDX-License-Identifier: Apache-2.0

//! Resource-bound regressions for the route engine. These cover the
//! bounded-exchange and cooperative-deadline parts of `CONCEPT.md`
//! sections 5.5, 8.2, and 13.5 without an upstream send.

use std::collections::BTreeMap;
use std::time::Duration;

use registry_adapter::exchange::Exchange;
use registry_adapter::route::{
    run_route, run_route_within, RouteContext, RouteOutcome, RouteTable,
};
use registry_adapter::scripts::ScriptSet;
use registry_adapter_core::{ErrorClass, Step};
use registry_platform_config::{SecretProvider, SecretResolver};
use serde_json::{json, Value};

fn steps(value: Value) -> Vec<Step> {
    serde_json::from_value(value).expect("the steps parse")
}

fn empty_code_maps() -> registry_adapter::scripts::CodeMaps {
    std::sync::Arc::new(BTreeMap::new())
}

async fn run_with_deadline(step_list: &[Step], deadline: Duration) -> RouteOutcome {
    let endpoints = BTreeMap::new();
    let scripts = ScriptSet::default();
    let resolver = SecretResolver::new([SecretProvider::Environment], "")
        .expect("the environment resolver builds");
    let resilience = registry_adapter::resilience::ResilienceRuntime::empty();
    let routes = RouteTable::new();
    let context = RouteContext {
        endpoints: &endpoints,
        scripts: &scripts,
        resolver: &resolver,
        resilience: &resilience,
        routes: &routes,
        code_maps: empty_code_maps(),
        maximum_upstream_calls: 1,
    };
    run_route_within(
        &context,
        step_list,
        Exchange::new("resource-bound".to_owned()),
        deadline,
    )
    .await
}

async fn run(step_list: &[Step]) -> RouteOutcome {
    let endpoints = BTreeMap::new();
    let scripts = ScriptSet::default();
    let resolver = SecretResolver::new([SecretProvider::Environment], "")
        .expect("the environment resolver builds");
    let resilience = registry_adapter::resilience::ResilienceRuntime::empty();
    let routes = RouteTable::new();
    let context = RouteContext {
        endpoints: &endpoints,
        scripts: &scripts,
        resolver: &resolver,
        resilience: &resilience,
        routes: &routes,
        code_maps: empty_code_maps(),
        maximum_upstream_calls: 1,
    };
    run_route(
        &context,
        step_list,
        Exchange::new("resource-bound".to_owned()),
    )
    .await
}

#[test]
fn exchange_bound_counts_body_headers_and_properties_together() {
    let mut exchange = Exchange::new("bounded".to_owned());
    exchange.message.body = json!({"small": true});
    exchange.message.set_header("trace", json!("synthetic"));
    exchange.set_property("cursor", json!("synthetic"));
    assert_eq!(exchange.ensure_bounded(), Ok(()));

    exchange.message.body = Value::String("x".repeat(600_000));
    exchange.set_property("retained", Value::String("y".repeat(500_000)));
    assert_eq!(exchange.ensure_bounded(), Err(ErrorClass::BudgetExhausted));
}

#[tokio::test]
async fn nested_no_send_loops_yield_to_the_exchange_deadline() {
    let repeated = steps(json!([{
        "loop": {
            "constant": 100,
            "maximumIterations": 100,
            "steps": [{
                "loop": {
                    "constant": 100_000,
                    "maximumIterations": 100_000,
                    "steps": []
                }
            }]
        }
    }]));
    let outcome = run_with_deadline(&repeated, Duration::from_millis(1)).await;
    assert_eq!(
        outcome
            .result
            .expect_err("the cooperative deadline stops nested loops")
            .class,
        ErrorClass::BudgetExhausted
    );
}

#[tokio::test]
async fn no_send_split_yields_to_the_exchange_deadline() {
    let pieces: Vec<_> = (0..100_000).map(|index| json!(index)).collect();
    let split = steps(json!([{
        "split": {
            "expression": {"constant": pieces},
            "maximumItems": 100_000,
            "steps": []
        }
    }]));
    let outcome = run_with_deadline(&split, Duration::from_millis(1)).await;
    assert_eq!(
        outcome
            .result
            .expect_err("the cooperative deadline stops a no-send split")
            .class,
        ErrorClass::BudgetExhausted
    );
}

#[tokio::test]
async fn grouped_split_refuses_an_accumulator_over_the_exchange_cap() {
    let piece = "x".repeat(24_000);
    let pieces: Vec<_> = (0..48).map(|index| json!(index)).collect();
    let route = steps(json!([{
        "split": {
            "expression": {"constant": pieces},
            "maximumItems": 48,
            "aggregationStrategy": {"type": "grouped-body"},
            "steps": [{"setBody": {"constant": piece}}]
        }
    }]));
    let outcome = run(&route).await;
    assert_eq!(
        outcome
            .result
            .expect_err("the growing accumulator is bounded")
            .class,
        ErrorClass::BudgetExhausted
    );
}

#[tokio::test]
async fn split_item_cap_is_checked_for_a_large_constant_before_processing() {
    let pieces = vec![Value::String("x".repeat(400_000)); 3];
    let route = steps(json!([{
        "split": {
            "expression": {"constant": pieces},
            "maximumItems": 2,
            "steps": [{"throwException": {"exceptionType": "validation"}}]
        }
    }]));
    let outcome = run(&route).await;
    assert_eq!(
        outcome
            .result
            .expect_err("the authored item cap refuses the split")
            .class,
        ErrorClass::BudgetExhausted
    );
}

#[tokio::test]
async fn bounded_split_replay_is_deterministic() {
    let route = steps(json!([{
        "split": {
            "expression": {"constant": [{"id": "a"}, {"id": "b"}, {"id": "c"}]},
            "maximumItems": 3,
            "aggregationStrategy": {"type": "grouped-body"},
            "steps": []
        }
    }]));
    let first = run(&route).await.result.expect("the first replay succeeds");
    let second = run(&route)
        .await
        .result
        .expect("the second replay succeeds");
    assert_eq!(first.message.body, second.message.body);
}
