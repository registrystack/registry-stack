// SPDX-License-Identifier: Apache-2.0

//! The Type Converter conformance suite, port-table row 35
//! (`products/adapter/CONCEPT.md` sections 8.6 and 8.10):
//! `convertBodyTo`, `convertHeaderTo`, and the port's `convertPropertyTo`
//! addition over one declared code map. The lookup is exact and
//! case-sensitive over a string input; a null or absent input passes
//! through unchanged whatever `mandatory` says, any other non-string
//! input or a miss raises `conversion.unmapped`, and with
//! `mandatory: false` a miss leaves the target absent. Rhai reaches the
//! same lookup through `code_map(id, key)`.

use std::collections::BTreeMap;
use std::sync::Arc;

use registry_adapter::exchange::Exchange;
use registry_adapter::route::{check_servable, run_route, RouteContext, RouteTable};
use registry_adapter::scripts::{CodeMaps, ScriptSet};
use registry_adapter_core::{AdapterPack, Step};
use registry_platform_config::{sha256_uri, SecretProvider, SecretResolver};
use registry_platform_yaml::{ExternalId, LocalId};
use serde_json::{json, Value};

fn steps(value: Value) -> Vec<Step> {
    serde_json::from_value(value).expect("the steps parse")
}

/// One declared map: the statuses a source system spells its own way.
fn status_maps() -> CodeMaps {
    let mut entries = BTreeMap::new();
    for (key, value) in [
        ("active", json!("ACTIVE")),
        ("suspended", json!("SUSPENDED")),
        ("counted", json!(3)),
        ("flagged", json!(true)),
        ("cleared", json!(null)),
    ] {
        entries.insert(ExternalId::new(key).expect("the key"), value);
    }
    let map = registry_adapter_core::CodeMap {
        id: LocalId::new("statuses").expect("map id"),
        entries,
    };
    Arc::new(BTreeMap::from([("statuses".to_owned(), map)]))
}

/// One route run over the given body and maps: a conversion needs no
/// upstream.
async fn run(step_list: Vec<Step>, body: Value) -> registry_adapter::route::RouteOutcome {
    run_over(step_list, body, status_maps(), &ScriptSet::default()).await
}

/// The same run over an explicit table and script set.
async fn run_over(
    step_list: Vec<Step>,
    body: Value,
    maps: CodeMaps,
    scripts: &ScriptSet,
) -> registry_adapter::route::RouteOutcome {
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
        code_maps: maps,
        maximum_upstream_calls: 4,
    };
    let mut exchange = Exchange::new("test".to_owned());
    exchange.message.body = body;
    run_route(&context, &step_list, exchange).await
}

fn failed_class(outcome: &registry_adapter::route::RouteOutcome) -> &'static str {
    outcome
        .result
        .as_ref()
        .expect_err("the exchange fails")
        .class
        .class()
}

fn failed_message(outcome: &registry_adapter::route::RouteOutcome) -> &str {
    outcome
        .result
        .as_ref()
        .expect_err("the exchange fails")
        .message
        .as_deref()
        .expect("the failure names its map")
}

fn ok(outcome: &registry_adapter::route::RouteOutcome) -> &Exchange {
    outcome.result.as_ref().expect("the exchange completes")
}

/// `convertBodyTo` writes the mapped scalar, every scalar kind whole.
#[tokio::test]
async fn the_body_conversion_writes_each_scalar_kind() {
    for (key, expected) in [
        ("active", json!("ACTIVE")),
        ("counted", json!(3)),
        ("flagged", json!(true)),
        ("cleared", json!(null)),
    ] {
        let outcome = run(
            steps(json!([{"convertBodyTo": {"type": "codeMap:statuses"}}])),
            json!(key),
        )
        .await;
        assert_eq!(ok(&outcome).message.body, expected, "the key {key} maps");
    }
}

/// A null body passes through unchanged whatever `mandatory` says
/// (Camel's `ConvertBodyTest.testConvertNullBody`).
#[tokio::test]
async fn a_null_body_passes_through_whatever_mandatory_says() {
    for mandatory in [None, Some(false), Some(true)] {
        let outcome = run(
            steps(json!([{"convertBodyTo": {
                "type": "codeMap:statuses",
                "mandatory": mandatory
            }}])),
            Value::Null,
        )
        .await;
        assert!(
            outcome.result.is_ok(),
            "a null body never fails, whatever mandatory: {:?}",
            mandatory
        );
        assert_eq!(ok(&outcome).message.body, Value::Null);
    }
}

/// A non-string body raises `conversion.unmapped`, naming the map and
/// never the input value.
#[tokio::test]
async fn a_non_string_body_raises_conversion_unmapped() {
    for body in [
        json!({"status": "active"}),
        json!(3),
        json!([1]),
        json!(true),
    ] {
        let outcome = run(
            steps(json!([{"convertBodyTo": {"type": "codeMap:statuses"}}])),
            body.clone(),
        )
        .await;
        assert_eq!(failed_class(&outcome), "conversion.unmapped");
        assert_eq!(
            failed_message(&outcome),
            "code map statuses takes a string key"
        );
    }
}

/// A miss raises `conversion.unmapped` under the default `mandatory`;
/// with `mandatory: false` the target keeps what it had.
#[tokio::test]
async fn a_miss_raises_unless_mandatory_is_false() {
    let outcome = run(
        steps(json!([{"convertBodyTo": {"type": "codeMap:statuses"}}])),
        json!("withdrawn"),
    )
    .await;
    assert_eq!(failed_class(&outcome), "conversion.unmapped");
    assert_eq!(
        failed_message(&outcome),
        "code map statuses has no entry for the key"
    );

    let outcome = run(
        steps(json!([{"convertBodyTo": {
            "type": "codeMap:statuses",
            "mandatory": false
        }}])),
        json!("withdrawn"),
    )
    .await;
    assert_eq!(
        ok(&outcome).message.body,
        json!("withdrawn"),
        "a miss under mandatory false leaves the body as it was"
    );
}

/// The lookup is exact and case-sensitive: the source's own spelling
/// only, never a folded variant.
#[tokio::test]
async fn the_lookup_is_exact_and_case_sensitive() {
    for key in ["Active", "ACTIVE", "activ"] {
        let outcome = run(
            steps(json!([{"convertBodyTo": {"type": "codeMap:statuses"}}])),
            json!(key),
        )
        .await;
        assert_eq!(
            failed_class(&outcome),
            "conversion.unmapped",
            "the key {key} matches nothing"
        );
    }
}

/// `convertHeaderTo` converts the named header in place; `toName`
/// redirects the result and leaves the source untouched, as Camel's
/// own option does.
#[tokio::test]
async fn the_header_conversion_replaces_in_place_and_to_name_redirects() {
    let outcome = run(
        steps(json!([
            {"setHeader": {"name": "state", "value": {"constant": "active"}}},
            {"convertHeaderTo": {"type": "codeMap:statuses", "name": "state"}}
        ])),
        json!({"id": "a"}),
    )
    .await;
    let exchange = ok(&outcome);
    assert_eq!(exchange.message.header("state"), Some(&json!("ACTIVE")));

    let outcome = run(
        steps(json!([
            {"setHeader": {"name": "state", "value": {"constant": "active"}}},
            {"convertHeaderTo": {
                "type": "codeMap:statuses",
                "name": "state",
                "toName": "stateCode"
            }}
        ])),
        json!({"id": "a"}),
    )
    .await;
    let exchange = ok(&outcome);
    assert_eq!(
        exchange.message.header("state"),
        Some(&json!("active")),
        "the source header keeps its own value"
    );
    assert_eq!(exchange.message.header("stateCode"), Some(&json!("ACTIVE")));
}

/// An absent header passes through unchanged; a miss with
/// `mandatory: false` leaves the target absent.
#[tokio::test]
async fn an_absent_header_and_a_lenient_miss_write_nothing() {
    let outcome = run(
        steps(json!([{"convertHeaderTo": {
            "type": "codeMap:statuses",
            "name": "state"
        }}])),
        json!({"id": "a"}),
    )
    .await;
    let exchange = ok(&outcome);
    assert!(
        exchange.message.header("state").is_none(),
        "an absent header writes nothing, whatever mandatory"
    );

    let outcome = run(
        steps(json!([
            {"setHeader": {"name": "state", "value": {"constant": "withdrawn"}}},
            {"convertHeaderTo": {
                "type": "codeMap:statuses",
                "name": "state",
                "mandatory": false,
                "toName": "stateCode"
            }}
        ])),
        json!({"id": "a"}),
    )
    .await;
    let exchange = ok(&outcome);
    assert_eq!(exchange.message.header("state"), Some(&json!("withdrawn")));
    assert!(
        exchange.message.header("stateCode").is_none(),
        "a lenient miss leaves the target absent"
    );
}

/// A non-string header value raises `conversion.unmapped` like the
/// body form does.
#[tokio::test]
async fn a_non_string_header_value_raises_conversion_unmapped() {
    let outcome = run(
        steps(json!([
            {"setHeader": {"name": "state", "value": {"constant": 7}}},
            {"convertHeaderTo": {"type": "codeMap:statuses", "name": "state"}}
        ])),
        json!({"id": "a"}),
    )
    .await;
    assert_eq!(failed_class(&outcome), "conversion.unmapped");
    assert_eq!(
        failed_message(&outcome),
        "code map statuses takes a string key"
    );
}

/// `convertPropertyTo` is the header form over properties: in place,
/// redirected by `toName`, absent on a lenient miss.
#[tokio::test]
async fn the_property_conversion_follows_the_header_form() {
    let outcome = run(
        steps(json!([
            {"setProperty": {"name": "state", "value": {"constant": "suspended"}}},
            {"convertPropertyTo": {"type": "codeMap:statuses", "name": "state"}}
        ])),
        json!({"id": "a"}),
    )
    .await;
    let exchange = ok(&outcome);
    assert_eq!(exchange.property("state"), Some(&json!("SUSPENDED")));

    let outcome = run(
        steps(json!([
            {"setProperty": {"name": "state", "value": {"constant": "suspended"}}},
            {"convertPropertyTo": {
                "type": "codeMap:statuses",
                "name": "state",
                "toName": "stateCode"
            }}
        ])),
        json!({"id": "a"}),
    )
    .await;
    let exchange = ok(&outcome);
    assert_eq!(exchange.property("state"), Some(&json!("suspended")));
    assert_eq!(exchange.property("stateCode"), Some(&json!("SUSPENDED")));

    let outcome = run(
        steps(json!([
            {"setProperty": {"name": "state", "value": {"constant": "withdrawn"}}},
            {"convertPropertyTo": {
                "type": "codeMap:statuses",
                "name": "state",
                "mandatory": false,
                "toName": "stateCode"
            }}
        ])),
        json!({"id": "a"}),
    )
    .await;
    let exchange = ok(&outcome);
    assert_eq!(exchange.property("state"), Some(&json!("withdrawn")));
    assert!(exchange.property("stateCode").is_none());
}

/// A conversion naming a map the table does not carry fails at the
/// exchange with the same class: the loader resolves every literal id
/// at load, so this is the table a lane assembled without it.
#[tokio::test]
async fn a_conversion_naming_no_declared_map_fails_the_exchange() {
    let empty: CodeMaps = Arc::new(BTreeMap::new());
    let outcome = run_over(
        steps(json!([{"convertBodyTo": {"type": "codeMap:statuses"}}])),
        json!("active"),
        empty,
        &ScriptSet::default(),
    )
    .await;
    assert_eq!(failed_class(&outcome), "conversion.unmapped");
    assert_eq!(
        failed_message(&outcome),
        "code map statuses is not declared"
    );
}

/// The served shape: the body form carries no `name` or `toName`, the
/// named forms require `name`, `toName` never stands alone, and `type`
/// names a code map.
#[test]
fn the_served_shape_is_refused_by_name() {
    for member in [
        json!({"type": "codeMap:statuses", "name": "state"}),
        json!({"type": "codeMap:statuses", "toName": "stateCode"}),
        json!({"type": "codeMap:statuses", "name": "state", "toName": "stateCode"}),
    ] {
        let refusal = check_servable(&steps(json!([{"convertBodyTo": member}])))
            .expect_err("the body form carries no name or toName");
        assert!(
            refusal.contains("convertBodyTo"),
            "the refusal names the step: {refusal}"
        );
    }
    for fault in [
        json!({"type": "codeMap:statuses", "toName": "stateCode"}),
        json!({"type": "codeMap:statuses"}),
        json!({"type": "string", "name": "state"}),
    ] {
        for form in ["convertHeaderTo", "convertPropertyTo"] {
            let refusal = check_servable(&steps(json!([{form: fault.clone()}])))
                .expect_err("the named form is refused");
            assert!(
                refusal.contains(form),
                "the refusal names the step: {refusal}"
            );
        }
    }
    check_servable(&steps(json!([
        {"convertHeaderTo": {"type": "codeMap:statuses", "name": "state"}}
    ])))
    .expect("the served header conversion runs");
}

/// A script set over one in-memory script file, pinned by its digest.
fn scripts(source: &str, entrypoint: &str) -> ScriptSet {
    let directory = tempfile::tempdir().expect("a scratch directory");
    std::fs::write(directory.path().join("probe.rhai"), source).expect("the script is written");
    let pack: AdapterPack = serde_json::from_value(json!({
        "id": "probe",
        "version": "1",
        "testedVersions": ["1"],
        "scripts": [{"path": "probe.rhai", "digest": sha256_uri(source.as_bytes())}],
    }))
    .expect("the pack parses");
    let mut set = ScriptSet::default();
    set.add(&pack, directory.path(), "probe.rhai", entrypoint)
        .expect("the script compiles under its pinned digest");
    set
}

/// Rhai's `code_map(id, key)` takes the same single lookup: a hit
/// returns the entry, a miss raises `conversion.unmapped`, and an id no
/// declared map carries answers the same miss naming that id.
#[tokio::test]
async fn rhai_code_map_takes_the_same_lookup() {
    let set = scripts(
        "fn apply(exchange) { code_map(\"statuses\", exchange.body) }",
        "apply",
    );
    let outcome = run_over(
        steps(json!([{"setBody": {
            "rhai": {"file": "probe.rhai", "entrypoint": "apply"}
        }}])),
        json!("active"),
        status_maps(),
        &set,
    )
    .await;
    assert_eq!(ok(&outcome).message.body, json!("ACTIVE"));

    let outcome = run_over(
        steps(json!([{"setBody": {
            "rhai": {"file": "probe.rhai", "entrypoint": "apply"}
        }}])),
        json!("withdrawn"),
        status_maps(),
        &set,
    )
    .await;
    assert_eq!(failed_class(&outcome), "conversion.unmapped");
    assert_eq!(
        failed_message(&outcome),
        "code map statuses has no entry for the key"
    );

    // An id no declared map carries: the same miss naming that id.
    let set = scripts(
        "fn apply(exchange) { code_map(\"unknown\", exchange.body) }",
        "apply",
    );
    let outcome = run_over(
        steps(json!([{"setBody": {
            "rhai": {"file": "probe.rhai", "entrypoint": "apply"}
        }}])),
        json!("active"),
        status_maps(),
        &set,
    )
    .await;
    assert_eq!(failed_class(&outcome), "conversion.unmapped");
    assert_eq!(
        failed_message(&outcome),
        "code map unknown has no entry for the key"
    );
}

/// A pack's code maps parse in the platform form, and the table the
/// engine reads is keyed by the declared id.
#[test]
fn the_declared_map_parses_from_the_pack_form() {
    let pack: AdapterPack = serde_json::from_value(json!({
        "id": "probe",
        "version": "1",
        "testedVersions": ["1"],
        "codeMaps": [{
            "id": "statuses",
            "entries": {"active": "ACTIVE", "counted": 3}
        }]
    }))
    .expect("the pack parses");
    let map = pack
        .code_maps
        .get("statuses")
        .expect("the declared map is keyed by id");
    assert_eq!(map.lookup("active"), Some(&json!("ACTIVE")));
    assert_eq!(map.lookup("counted"), Some(&json!(3)));
    assert_eq!(map.lookup("withdrawn"), None);
    assert_eq!(
        map.lookup("not an external id"),
        None,
        "a key that is not a valid external id matches no entry"
    );
}
