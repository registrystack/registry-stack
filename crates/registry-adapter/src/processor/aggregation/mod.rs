// SPDX-License-Identifier: Apache-2.0

//! Aggregation strategies for `split` and `enrich`, compiled in and
//! named after Camel's built-ins (`products/adapter/CONCEPT.md`
//! section 8.6): `useLatest`, `useOriginal`, and `groupedBody`, plus
//! the two JSON-body additions marked as such: `jsonArrayAppend`
//! (`from`, `into`, `uniqueBy`; a duplicate `uniqueBy` value raises
//! `aggregation.duplicate`, so duplicate and shifting pages fail the
//! exchange instead of merging silently) and `jsonMerge` (`from`,
//! `into`).
//!
//! A custom strategy is a `rhai` entrypoint over the old and new bodies,
//! Camel's custom `AggregationStrategy` bean in the port's form:
//! `fn(old, new)` on `split`, with `old` as `()` on the first call, and
//! `fn(original, resource)` on `enrich`, returning
//! `#{ body, properties }` (section 8.11.3).
//!
//! The strategies merge bodies; the JSON additions also carry the named
//! `properties` out of the reply, each a singular `jsonpath` on the
//! reply body, with an absent selection removing the property, which is
//! how a pagination loop's cursor ends absent on the last page
//! (section 8.11.7).

use registry_adapter_core::{AggregationStrategy, ErrorClass};
use serde_json::{Map, Value};

use crate::exchange::Exchange;
use crate::language::{compile_selector, JsonPathResult};
use crate::route::RouteFailure;
use crate::scripts::ScriptSet;

/// The merged body plus the property writes a strategy asks the route
/// exchange to take. A `None` value removes the property: the stale
/// cursor must not outlive the page that carried it.
#[derive(Debug)]
pub(crate) struct Aggregated {
    pub(crate) body: Value,
    pub(crate) properties: Vec<(String, Option<Value>)>,
}

/// The accumulator a strategy starts from over the original body: the
/// list strategies build their own, a custom strategy starts from `()`
/// on its first call, and every other strategy folds the original.
pub(crate) fn initial_body(strategy: &AggregationStrategy, original: &Value) -> Value {
    match strategy {
        AggregationStrategy::GroupedBody {} => Value::Array(Vec::new()),
        AggregationStrategy::Rhai { .. } => Value::Null,
        _ => original.clone(),
    }
}

/// Whether the split raises its recorded item failure after every piece
/// has run: a declared `use-original` may swallow it with
/// `propagateException: false`, every other strategy raises
/// (`UseOriginalAggregationStrategy`).
pub(crate) fn propagates(strategy: &AggregationStrategy) -> bool {
    match strategy {
        AggregationStrategy::UseOriginal {
            propagate_exception,
        } => *propagate_exception,
        _ => true,
    }
}

/// Fold `new` into `old` under the strategy: the body the route
/// exchange takes and the property writes it applies. `old` is the
/// accumulated body (the original for the first piece), `new` the piece
/// or resource exchange whose body and properties the strategy reads.
pub(crate) fn fold(
    scripts: &ScriptSet,
    strategy: &AggregationStrategy,
    old: &Value,
    new: &Exchange,
) -> Result<Aggregated, RouteFailure> {
    match strategy {
        AggregationStrategy::UseLatest {} => Ok(Aggregated {
            body: new.message.body.clone(),
            properties: Vec::new(),
        }),
        AggregationStrategy::UseOriginal { .. } => Ok(Aggregated {
            body: old.clone(),
            properties: Vec::new(),
        }),
        AggregationStrategy::GroupedBody {} => {
            let mut items = match old {
                Value::Array(items) => items.clone(),
                Value::Null => Vec::new(),
                _ => return Err(fault("the grouped-body strategy aggregates a list")),
            };
            // A piece whose body ended null contributed nothing; an
            // enrich reply is one value in the list.
            if !new.message.body.is_null() {
                items.push(new.message.body.clone());
            }
            Ok(Aggregated {
                body: Value::Array(items),
                properties: Vec::new(),
            })
        }
        AggregationStrategy::JsonArrayAppend {
            from,
            into,
            unique_by,
            properties,
        } => {
            let elements = named_property_array(new, from)?;
            let mut body = object_body(old)?;
            let target = body
                .entry(into.clone())
                .or_insert_with(|| Value::Array(Vec::new()));
            let Value::Array(list) = target else {
                return Err(fault("the into member must name an array"));
            };
            for element in elements {
                if let Some(member) = unique_by {
                    if let Some(value) = element.get(member) {
                        if list
                            .iter()
                            .any(|existing| existing.get(member) == Some(value))
                        {
                            return Err(RouteFailure::of(ErrorClass::AggregationDuplicate));
                        }
                    }
                }
                list.push(element);
            }
            Ok(Aggregated {
                body: Value::Object(body),
                properties: carried(properties, new)?,
            })
        }
        AggregationStrategy::JsonMerge {
            from,
            into,
            properties,
        } => {
            let members = named_property_object(new, from)?;
            let mut body = object_body(old)?;
            let target = body
                .entry(into.clone())
                .or_insert_with(|| Value::Object(Map::new()));
            let Value::Object(object) = target else {
                return Err(fault("the into member must name an object"));
            };
            for (name, value) in members {
                object.insert(name, value);
            }
            Ok(Aggregated {
                body: Value::Object(body),
                properties: carried(properties, new)?,
            })
        }
        AggregationStrategy::Rhai { expression } => {
            let merged = scripts
                .aggregate(
                    &expression.file,
                    &expression.entrypoint,
                    old,
                    &new.message.body,
                )
                .map_err(|failure| RouteFailure::of(failure.class()))?;
            let Value::Object(merged) = merged else {
                return Err(RouteFailure::of(ErrorClass::Script));
            };
            let Some(body) = merged.get("body").cloned() else {
                return Err(RouteFailure::of(ErrorClass::Script));
            };
            let properties = match merged.get("properties") {
                None | Some(Value::Null) => Vec::new(),
                Some(Value::Object(writes)) => writes
                    .iter()
                    .map(|(name, value)| (name.clone(), Some(value.clone())))
                    .collect(),
                Some(_) => return Err(RouteFailure::of(ErrorClass::Script)),
            };
            Ok(Aggregated { body, properties })
        }
    }
}

/// The named property of `new` as the elements to append; a property
/// that is absent or no array fails the exchange, never a silent skip.
fn named_property_array(new: &Exchange, from: &str) -> Result<Vec<Value>, RouteFailure> {
    match new.property(from) {
        Some(Value::Array(elements)) => Ok(elements.clone()),
        _ => Err(fault("the from property must name an array the reply set")),
    }
}

/// The named property of `new` as the members to merge.
fn named_property_object(new: &Exchange, from: &str) -> Result<Vec<(String, Value)>, RouteFailure> {
    match new.property(from) {
        Some(Value::Object(members)) => Ok(members
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect()),
        _ => Err(fault("the from property must name an object the reply set")),
    }
}

/// The accumulated body as an object, an absent body starting empty.
fn object_body(old: &Value) -> Result<Map<String, Value>, RouteFailure> {
    match old {
        Value::Object(body) => Ok(body.clone()),
        Value::Null => Ok(Map::new()),
        _ => Err(fault("the accumulated body must be an object")),
    }
}

/// The property writes the strategy's `properties` map asks for, each a
/// singular query on the reply body: a value to set, a node list to set
/// as an array, an absent singular result to remove.
fn carried(
    properties: &std::collections::BTreeMap<String, String>,
    new: &Exchange,
) -> Result<Vec<(String, Option<Value>)>, RouteFailure> {
    let mut writes = Vec::new();
    for (name, selector) in properties {
        let compiled =
            compile_selector(selector).map_err(|_| fault("the property selector is not served"))?;
        let write = match compiled.evaluate(&new.message.body) {
            Ok(JsonPathResult::Singular(Some(value))) => Some(value.clone()),
            Ok(JsonPathResult::Singular(None)) => None,
            Ok(JsonPathResult::List(nodes)) => {
                Some(Value::Array(nodes.into_iter().cloned().collect()))
            }
            Err(_) => return Err(fault("the property selector failed")),
        };
        writes.push((name.clone(), write));
    }
    Ok(writes)
}

fn fault(message: &str) -> RouteFailure {
    RouteFailure {
        class: ErrorClass::Validation,
        message: Some(message.to_owned()),
        auth: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// An exchange whose body and properties the tests set directly.
    fn exchange(body: Value, properties: &[(&str, Value)]) -> Exchange {
        let mut exchange = Exchange::new("test".to_owned());
        exchange.message.body = body;
        for (name, value) in properties {
            exchange.set_property(name, value.clone());
        }
        exchange
    }

    fn strategy(value: Value) -> AggregationStrategy {
        serde_json::from_value(value).expect("the strategy parses")
    }

    #[test]
    fn use_latest_and_use_original_pick_their_bodies() {
        let old = json!({"q": 1});
        let new = exchange(json!({"answer": 42}), &[]);
        let latest = fold(
            &ScriptSet::default(),
            &strategy(json!({"type": "use-latest"})),
            &old,
            &new,
        )
        .expect("the latest body wins");
        assert_eq!(latest.body, json!({"answer": 42}));
        let original = fold(
            &ScriptSet::default(),
            &strategy(json!({"type": "use-original"})),
            &old,
            &new,
        )
        .expect("the original body stays");
        assert_eq!(original.body, json!({"q": 1}));
    }

    #[test]
    fn grouped_body_concatenates_and_skips_null_bodies() {
        let strategy = strategy(json!({"type": "grouped-body"}));
        let mut accumulated = initial_body(&strategy, &json!({"untouched": true}));
        for body in [json!("a"), json!(null), json!("b")] {
            let merged = fold(
                &ScriptSet::default(),
                &strategy,
                &accumulated,
                &exchange(body, &[]),
            )
            .expect("the piece folds");
            accumulated = merged.body;
        }
        assert_eq!(accumulated, json!(["a", "b"]));
    }

    #[test]
    fn json_array_append_appends_into_the_named_member_and_refuses_duplicates() {
        let strategy = strategy(json!({
            "type": "json-array-append", "from": "page", "into": "records", "uniqueBy": "id"
        }));
        let mut accumulated = initial_body(&strategy, &json!({"records": [{"id": "z"}]}));
        for page in [
            vec![json!({"id": "a"}), json!({"id": "b"})],
            vec![json!({"id": "c"})],
        ] {
            let merged = fold(
                &ScriptSet::default(),
                &strategy,
                &accumulated,
                &exchange(
                    json!({"page": true}),
                    &[("page", Value::Array(page.to_vec()))],
                ),
            )
            .expect("the page appends");
            accumulated = merged.body;
        }
        assert_eq!(
            accumulated,
            json!({"records": [{"id": "z"}, {"id": "a"}, {"id": "b"}, {"id": "c"}]})
        );

        let duplicate = fold(
            &ScriptSet::default(),
            &strategy,
            &accumulated,
            &exchange(json!({}), &[("page", json!([{"id": "a"}]))]),
        )
        .expect_err("the repeated id is refused");
        assert_eq!(duplicate.class, ErrorClass::AggregationDuplicate);

        let absent = fold(
            &ScriptSet::default(),
            &strategy,
            &json!({"records": []}),
            &exchange(json!({}), &[]),
        )
        .expect_err("a reply naming no array property fails");
        assert_eq!(absent.class, ErrorClass::Validation);
    }

    #[test]
    fn json_array_append_creates_the_member_and_ignores_elements_without_the_member() {
        let strategy = strategy(json!({
            "type": "json-array-append", "from": "page", "into": "records", "uniqueBy": "id"
        }));
        let merged = fold(
            &ScriptSet::default(),
            &strategy,
            &json!({}),
            &exchange(
                json!({}),
                &[("page", json!([{"id": "a"}, {"kind": "note"}]))],
            ),
        )
        .expect("an absent member starts empty and unkeyed elements append");
        assert_eq!(
            merged.body,
            json!({"records": [{"id": "a"}, {"kind": "note"}]})
        );
    }

    #[test]
    fn json_merge_merges_member_wise_into_the_named_member() {
        let strategy = strategy(json!({
            "type": "json-merge", "from": "extra", "into": "record"
        }));
        let merged = fold(
            &ScriptSet::default(),
            &strategy,
            &json!({"record": {"a": 1, "b": 2}}),
            &exchange(json!({}), &[("extra", json!({"b": 3, "c": 4}))]),
        )
        .expect("the members merge");
        assert_eq!(merged.body, json!({"record": {"a": 1, "b": 3, "c": 4}}));
    }

    #[test]
    fn the_properties_map_sets_carries_and_clears() {
        let strategy = strategy(json!({
            "type": "json-array-append",
            "from": "page",
            "into": "records",
            "properties": {"lastId": "$.entries[0].id", "cursor": "$.cursor"}
        }));
        let new = exchange(
            json!({"entries": [{"id": "a"}], "cursor": "one"}),
            &[("page", json!([{"id": "a"}]))],
        );
        let merged = fold(
            &ScriptSet::default(),
            &strategy,
            &json!({"records": []}),
            &new,
        )
        .expect("the values carry");
        // The map's entries arrive in its own sorted order; a strategy's
        // writes carry no order a route may rely on.
        let mut carried = merged.properties;
        carried.sort_by(|(left, _), (right, _)| left.cmp(right));
        assert_eq!(
            carried,
            vec![
                ("cursor".to_owned(), Some(json!("one"))),
                ("lastId".to_owned(), Some(json!("a"))),
            ]
        );
        let cleared = fold(
            &ScriptSet::default(),
            &strategy,
            &json!({"records": []}),
            &exchange(
                json!({"entries": [{"id": "b"}]}),
                &[("page", json!([{"id": "b"}]))],
            ),
        )
        .expect("the absent selection clears");
        assert_eq!(
            cleared.properties,
            vec![
                ("cursor".to_owned(), None),
                ("lastId".to_owned(), Some(json!("b"))),
            ]
        );
    }

    #[test]
    fn a_custom_strategy_returns_its_body_and_properties() {
        let source = r#"fn merge(oldExchange, newExchange) {
    let kept = ();
    if oldExchange != () { kept = oldExchange.q; }
    #{ "body": #{ "kept": kept, "answer": newExchange.answer }, "properties": #{ "saw": true } }
}"#;
        let directory = tempfile::tempdir().expect("a scratch directory");
        std::fs::write(directory.path().join("props.rhai"), source).expect("the script is written");
        let pack: registry_adapter_core::AdapterPack = serde_json::from_value(json!({
            "id": "probe",
            "version": "1",
            "testedVersions": ["1"],
            "scripts": [{
                "path": "props.rhai",
                "digest": registry_platform_config::sha256_uri(source.as_bytes()),
            }],
        }))
        .expect("the pack parses");
        let mut scripts = ScriptSet::default();
        scripts
            .add_aggregation(&pack, directory.path(), "props.rhai", "merge")
            .expect("the strategy compiles");
        let strategy = strategy(json!({
            "type": "rhai", "expression": {"file": "props.rhai", "entrypoint": "merge"}
        }));
        let merged = fold(
            &scripts,
            &strategy,
            &json!({"q": 1}),
            &exchange(json!({"answer": 42}), &[]),
        )
        .expect("the strategy folds");
        assert_eq!(merged.body, json!({"kept": 1, "answer": 42}));
        assert_eq!(
            merged.properties,
            vec![("saw".to_owned(), Some(json!(true)))]
        );

        let first = fold(
            &scripts,
            &strategy,
            &Value::Null,
            &exchange(json!({"answer": 42}), &[]),
        )
        .expect("the first call sees () for old");
        assert_eq!(first.body, json!({"kept": null, "answer": 42}));
    }

    #[test]
    fn a_custom_strategy_without_a_body_member_fails() {
        let source = r#"fn merge(oldExchange, newExchange) { #{ "properties": #{} } }"#;
        let directory = tempfile::tempdir().expect("a scratch directory");
        std::fs::write(directory.path().join("props.rhai"), source).expect("the script is written");
        let pack: registry_adapter_core::AdapterPack = serde_json::from_value(json!({
            "id": "probe",
            "version": "1",
            "testedVersions": ["1"],
            "scripts": [{
                "path": "props.rhai",
                "digest": registry_platform_config::sha256_uri(source.as_bytes()),
            }],
        }))
        .expect("the pack parses");
        let mut scripts = ScriptSet::default();
        scripts
            .add_aggregation(&pack, directory.path(), "props.rhai", "merge")
            .expect("the strategy compiles");
        let strategy = strategy(json!({
            "type": "rhai", "expression": {"file": "props.rhai", "entrypoint": "merge"}
        }));
        let failed = fold(&scripts, &strategy, &json!({}), &exchange(json!({}), &[]))
            .expect_err("a strategy without a body member fails");
        assert_eq!(failed.class, ErrorClass::Script);
    }
}
