// SPDX-License-Identifier: Apache-2.0
//! The output bound the Rhai handler path applies to a handler result before
//! the result is decoded.
//!
//! Decoding a Rhai value into the neutral document recurses to build it, so
//! the depth ceiling is checked while walking the Rhai value: these cases
//! hold that a result nested past the ceiling is refused without the walk
//! descending to its bottom, and that the walk charges the same budget,
//! widths and strings the shared document bound charges.
//!
//! The deep case runs on a thread with a small stack, so a walk that
//! descended the whole value would abort the process instead of passing. It
//! takes its value apart one level at a time afterwards: dropping a value
//! thousands of levels deep recurses on its own, which is a separate
//! property from the one under test here.

use rhai::{Array, Dynamic, ImmutableString, Map};

use super::{bound_document, bound_rhai_result, rhai_document};
use crate::action_handler::ActionHandlerError;
use crate::rhai_planner::{MAXIMUM_ARRAY_ITEMS, MAXIMUM_MAP_ENTRIES, MAXIMUM_VALUE_DEPTH};

/// A stack of single-member maps `depth` levels deep, built by a loop so the
/// construction itself does not recurse.
fn nested_map(depth: usize) -> Dynamic {
    let mut value = Dynamic::from(Map::new());
    for _ in 0..depth {
        let mut map = Map::new();
        map.insert("child".into(), value);
        value = Dynamic::from(map);
    }
    value
}

/// Take a nested stack apart one level at a time, so dropping it recurses
/// through no level at all.
fn dismantle(value: Dynamic) {
    let mut current = value;
    while let Some(mut map) = current.try_cast::<Map>() {
        match map.remove("child") {
            Some(child) => current = child,
            None => break,
        }
    }
}

#[test]
fn the_bound_accepts_a_result_at_the_depth_ceiling() {
    let value = nested_map(MAXIMUM_VALUE_DEPTH);
    assert_eq!(bound_rhai_result(&value, u32::MAX), Ok(()));
    let document = rhai_document(value);
    assert_eq!(bound_document(&document, u32::MAX), Ok(()));
}

#[test]
fn the_bound_refuses_a_result_nested_past_the_depth_ceiling() {
    let value = nested_map(MAXIMUM_VALUE_DEPTH + 1);
    assert_eq!(
        bound_rhai_result(&value, u32::MAX),
        Err(ActionHandlerError::Resource)
    );
}

#[test]
fn the_bound_refuses_a_deep_result_without_walking_to_its_bottom() {
    std::thread::Builder::new()
        .stack_size(2 << 20)
        .spawn(|| {
            let value = nested_map(5000);
            assert_eq!(
                bound_rhai_result(&value, u32::MAX),
                Err(ActionHandlerError::Resource)
            );
            dismantle(value);
        })
        .expect("the deep case needs its own thread")
        .join()
        .expect("the bound refuses a deep result without descending it");
}

#[test]
fn the_bound_charges_strings_against_the_snapshot_budget() {
    let value = Dynamic::from(ImmutableString::from("twelve bytes"));
    assert_eq!(bound_rhai_result(&value, 20), Ok(()));
    assert_eq!(
        bound_rhai_result(&value, 19),
        Err(ActionHandlerError::Resource)
    );
}

#[test]
fn the_bound_refuses_a_result_wider_than_the_array_and_map_ceilings() {
    let items: Array = (0..=MAXIMUM_ARRAY_ITEMS).map(|_| Dynamic::UNIT).collect();
    assert_eq!(
        bound_rhai_result(&Dynamic::from_array(items), u32::MAX),
        Err(ActionHandlerError::Resource)
    );
    let members: Map = (0..=MAXIMUM_MAP_ENTRIES)
        .map(|index| (format!("member{index}").into(), Dynamic::UNIT))
        .collect();
    assert_eq!(
        bound_rhai_result(&Dynamic::from_map(members), u32::MAX),
        Err(ActionHandlerError::Resource)
    );
}

#[test]
fn the_rhai_bound_and_the_document_bound_decide_alike() {
    let values = [
        Dynamic::UNIT,
        Dynamic::from_bool(true),
        Dynamic::from_int(7),
        Dynamic::from_char('x'),
        Dynamic::from(ImmutableString::from("value")),
        Dynamic::from_array(vec![
            Dynamic::from_int(1),
            Dynamic::from(ImmutableString::from("two")),
        ]),
        nested_map(MAXIMUM_VALUE_DEPTH),
        nested_map(MAXIMUM_VALUE_DEPTH + 1),
    ];
    for value in values {
        for budget in [u32::MAX, 1024, 64, 8, 0] {
            assert_eq!(
                bound_rhai_result(&value, budget),
                bound_document(&rhai_document(value.clone()), budget),
                "the two bounds must decide alike at budget {budget}"
            );
        }
    }
}
