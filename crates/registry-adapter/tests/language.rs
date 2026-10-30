// SPDX-License-Identifier: Apache-2.0

//! The `jsonpath` language's compile-time bounds and singular-query
//! classification, and the code-map id resolution half of the Rhai
//! `code_map(id, key)` seam (`products/adapter/CONCEPT.md` sections 8.5,
//! 8.6, and 8.11.8).

use std::collections::BTreeMap;

use registry_adapter::language::{
    compile_selector, CodeMapIndex, LanguageError, SELECTOR_MAXIMUM_BYTES, SELECTOR_MAXIMUM_DEPTH,
};
use registry_adapter_core::CodeMap;
use registry_platform_yaml::LocalId;

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
