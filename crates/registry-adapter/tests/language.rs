// SPDX-License-Identifier: Apache-2.0

//! The `jsonpath` language's compile-time bounds, singular-query
//! classification, evaluation result rules, and matched-node budget, and
//! the code-map id resolution half of the Rhai `code_map(id, key)` seam
//! (`products/adapter/CONCEPT.md` sections 8.5, 8.6, and 8.11.8).

use std::collections::BTreeMap;

use registry_adapter::engine::language::{
    compile_selector, CodeMapIndex, JsonPathResult, LanguageError, MATCHED_NODE_MAXIMUM,
    SELECTOR_MAXIMUM_BYTES, SELECTOR_MAXIMUM_DEPTH,
};
use registry_adapter_core::CodeMap;
use registry_platform_yaml::LocalId;
use serde_json::{json, Value};

/// A filter selector whose grouping nests `groups` paren_expr levels deep
/// inside one filter. The raw-text scan counts `[` plus every `(`, so the
/// depth it reports is 2 + `groups`.
fn deep_filter(groups: usize) -> String {
    format!("$[?({}@.a{})]", "(".repeat(groups), ")".repeat(groups))
}

/// `$` followed by `segments` `.a` member segments: 2 * segments + 1 bytes.
fn chained_names(segments: usize) -> String {
    format!("$.a{}", ".a".repeat(segments - 1))
}

#[test]
fn a_selector_over_the_length_bound_is_refused() {
    let selector = chained_names(2048);
    assert_eq!(selector.len(), SELECTOR_MAXIMUM_BYTES + 1);
    assert_eq!(
        compile_selector(&selector),
        Err(LanguageError::SelectorTooLong {
            length: selector.len(),
            maximum: SELECTOR_MAXIMUM_BYTES,
        })
    );
}

#[test]
fn a_selector_at_the_length_bound_compiles() {
    // 3 + 2 * 2045 + 3 = 4096 bytes: 2046 `.a` members and one `.ab`.
    let selector = format!("$.a{}.ab", ".a".repeat(2045));
    assert_eq!(selector.len(), SELECTOR_MAXIMUM_BYTES);
    let compiled = compile_selector(&selector)
        .unwrap_or_else(|error| panic!("a selector at the byte bound compiles: {error:?}"));
    assert!(compiled.is_singular());
}

#[test]
fn a_selector_over_the_nesting_bound_is_refused() {
    let selector = deep_filter(63);
    assert_eq!(
        compile_selector(&selector),
        Err(LanguageError::SelectorTooDeep {
            depth: 65,
            maximum: SELECTOR_MAXIMUM_DEPTH,
        })
    );
}

#[test]
fn a_selector_at_the_nesting_bound_compiles() {
    let selector = deep_filter(62);
    let compiled = compile_selector(&selector)
        .unwrap_or_else(|error| panic!("a selector at the nesting bound compiles: {error:?}"));
    assert!(!compiled.is_singular(), "a filter selector is not singular");
}

#[test]
fn bounds_are_refused_before_the_parser_runs() {
    // Over both bounds and malformed: the length bound fires first, so the
    // refusal is typed, not a pest parse error.
    let selector = format!("$.a{}", ".a".repeat(4096));
    assert_eq!(
        compile_selector(&selector),
        Err(LanguageError::SelectorTooLong {
            length: selector.len(),
            maximum: SELECTOR_MAXIMUM_BYTES,
        })
    );
    // Deep but short: the nesting bound fires before the parser sees 202
    // nested groups (pest 2.8.5 carries no stack guard of its own).
    let selector = deep_filter(200);
    assert!(
        selector.len() <= SELECTOR_MAXIMUM_BYTES,
        "the deep selector stays under the length bound"
    );
    assert_eq!(
        compile_selector(&selector),
        Err(LanguageError::SelectorTooDeep {
            depth: 202,
            maximum: SELECTOR_MAXIMUM_DEPTH,
        })
    );
}

#[test]
fn an_unparseable_selector_is_a_typed_parse_failure() {
    for selector in ["", "notapath", "$.a[", "$.a[?(", "$.a]"] {
        match compile_selector(selector) {
            Err(LanguageError::SelectorInvalid(_)) => {}
            other => panic!("{selector:?} is refused as SelectorInvalid, got {other:?}"),
        }
    }
}

#[test]
fn name_and_index_selectors_are_singular() {
    for selector in ["$", "$.a", "$['a']", "$[0]", "$[-1]", "$.a.b[2]['c']"] {
        let compiled = compile_selector(selector)
            .unwrap_or_else(|error| panic!("{selector} compiles: {error:?}"));
        assert!(compiled.is_singular(), "{selector} is singular");
    }
}

#[test]
fn every_other_selector_shape_is_not_singular() {
    for selector in [
        "$.*",
        "$.a[*]",
        "$..a",
        "$..*",
        "$.a[1:2]",
        "$.a[0,1]",
        "$.a[?(@.b)]",
        deep_filter(1).as_str(),
    ] {
        let compiled = compile_selector(selector)
            .unwrap_or_else(|error| panic!("{selector} compiles: {error:?}"));
        assert!(!compiled.is_singular(), "{selector} is not singular");
    }
}

fn code_map(id: &str) -> CodeMap {
    CodeMap {
        id: LocalId::new(id).expect("a valid local id"),
        entries: BTreeMap::new(),
    }
}

#[test]
fn the_code_map_index_resolves_declared_ids() {
    let maps = vec![code_map("tracker-status"), code_map("gender-code")];
    let index = CodeMapIndex::build(&maps).expect("distinct ids build");
    assert!(index.find("tracker-status").is_some());
    assert!(index.find("gender-code").is_some());
    assert!(index.find("missing").is_none());

    let empty: Vec<CodeMap> = Vec::new();
    let index = CodeMapIndex::build(&empty).expect("an empty inventory builds");
    assert!(index.find("tracker-status").is_none());
}

#[test]
fn the_code_map_index_refuses_a_duplicate_id() {
    let maps = vec![code_map("tracker-status"), code_map("tracker-status")];
    assert_eq!(
        CodeMapIndex::build(&maps),
        Err(LanguageError::CodeMapDuplicateId(
            "tracker-status".to_owned()
        ))
    );
}

#[test]
fn a_singular_query_yields_its_one_value() {
    let body = json!({"a": {"b": 7}});
    let selector = compile_selector("$.a.b").expect("compiles");
    match selector.evaluate(&body).expect("evaluates") {
        JsonPathResult::Singular(Some(value)) => assert_eq!(value, &json!(7)),
        other => panic!("a singular query yields its one value, got {other:?}"),
    }
}

#[test]
fn a_singular_query_yields_absent_when_nothing_matches() {
    let body = json!({"a": 1});
    let selector = compile_selector("$.a.z").expect("compiles");
    match selector.evaluate(&body).expect("evaluates") {
        JsonPathResult::Singular(None) => {}
        other => panic!("a singular query with no match is absent, got {other:?}"),
    }
}

#[test]
fn any_other_query_yields_the_node_list() {
    let body = json!({"a": [1, 2]});
    let selector = compile_selector("$.a[*]").expect("compiles");
    match selector.evaluate(&body).expect("evaluates") {
        JsonPathResult::List(nodes) => assert_eq!(nodes, vec![&json!(1), &json!(2)]),
        other => panic!("a non-singular query yields the node list, got {other:?}"),
    }

    // Empty when nothing matches, never absent (CONCEPT 8.11.8).
    let selector = compile_selector("$.z[*]").expect("compiles");
    match selector.evaluate(&body).expect("evaluates") {
        JsonPathResult::List(nodes) => assert!(nodes.is_empty()),
        other => panic!("an empty node list is a list, got {other:?}"),
    }
}

#[test]
fn a_predicate_accepts_only_a_boolean() {
    for (body, selector, expected) in [
        (json!({"active": true}), "$.active", Ok(true)),
        (json!({"active": false}), "$.active", Ok(false)),
        // Absent counts as false, the one place absence has a meaning.
        (json!({}), "$.active", Ok(false)),
    ] {
        let compiled = compile_selector(selector).expect("compiles");
        assert_eq!(
            compiled.evaluate_predicate(&body),
            expected,
            "{selector} over {body}"
        );
    }

    for (body, selector, kind) in [
        (json!({"value": "x"}), "$.value", "string"),
        (json!({"value": 1}), "$.value", "number"),
        (json!({"value": []}), "$.value", "array"),
        (json!({"value": {}}), "$.value", "object"),
        (json!({"value": null}), "$.value", "null"),
    ] {
        let compiled = compile_selector(selector).expect("compiles");
        assert_eq!(
            compiled.evaluate_predicate(&body),
            Err(LanguageError::PredicateNotBoolean { kind }),
            "{selector} over {body}"
        );
    }
}

#[test]
fn a_non_singular_predicate_is_refused() {
    let body = json!({"a": 1});
    let selector = compile_selector("$..a").expect("compiles");
    assert_eq!(
        selector.evaluate_predicate(&body),
        Err(LanguageError::PredicateNotSingular)
    );
}

#[test]
fn the_matched_node_budget_is_enforced() {
    // Past the budget: 4097 id nodes under one descendant selector.
    let past: Vec<Value> = (0..(MATCHED_NODE_MAXIMUM + 1))
        .map(|i| json!({ "id": i }))
        .collect();
    let body = Value::Array(past);
    let selector = compile_selector("$..id").expect("compiles");
    assert_eq!(
        selector.evaluate(&body),
        Err(LanguageError::MatchedNodeBudgetExceeded {
            count: MATCHED_NODE_MAXIMUM + 1,
            maximum: MATCHED_NODE_MAXIMUM,
        })
    );

    // At the budget: the cap is inclusive, so this is a full node list.
    let at_cap: Vec<Value> = (0..MATCHED_NODE_MAXIMUM)
        .map(|i| json!({ "id": i }))
        .collect();
    let body = Value::Array(at_cap);
    match selector.evaluate(&body).expect("at the cap evaluates") {
        JsonPathResult::List(nodes) => assert_eq!(nodes.len(), MATCHED_NODE_MAXIMUM),
        other => panic!("a wide body at the cap yields the full list, got {other:?}"),
    }
}

#[test]
fn a_descendant_over_a_parse_limit_body_stays_within_the_budget() {
    // A body nested exactly to serde_json's default recursion limit
    // (128 container levels including the document, so 127 nested
    // objects parse) still does, and `..` over it walks a depth-bounded
    // tree inside the matched-node budget: the module never enables
    // unbounded_depth.
    let mut text = String::new();
    text.push_str(&"{\"a\":".repeat(127));
    text.push('0');
    text.push_str(&"}".repeat(127));
    let body: Value = serde_json::from_str(&text).expect("127 levels is the parse limit");
    let selector = compile_selector("$..a").expect("compiles");
    match selector.evaluate(&body).expect("within the budget") {
        JsonPathResult::List(nodes) => assert_eq!(nodes.len(), 127),
        other => panic!("a parse-limit body yields its nodes, got {other:?}"),
    }

    // One level past it the default recursion limit refuses the body
    // itself, so no deeper tree ever reaches a descendant selector here.
    let deeper = format!("{}0{}", "{\"a\":".repeat(128), "}".repeat(128));
    assert!(
        serde_json::from_str::<Value>(&deeper).is_err(),
        "128 nested objects exceeds the default parse recursion limit"
    );
}
