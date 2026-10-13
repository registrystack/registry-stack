// SPDX-License-Identifier: Apache-2.0
//! One bounded dependency validator for authored and evaluated action plans.
use crate::{diagnostics::Diagnostic, model::CompiledPlanEffect};
use std::collections::{BTreeMap, BTreeSet};
pub fn order_plan_effects(
    effects: Vec<CompiledPlanEffect>,
) -> Result<Vec<CompiledPlanEffect>, Vec<Diagnostic>> {
    let mut by_id = BTreeMap::new();
    let mut errors = Vec::new();
    for effect in effects {
        if by_id.insert(effect.id.clone(), effect).is_some() {
            errors.push(Diagnostic::error(
                "breg.action.effect-id-duplicate",
                "actions[].plan.effects",
                "effect identifiers must be unique",
            ));
        }
    }
    for effect in by_id.values() {
        for dependency in &effect.depends_on {
            if !by_id.contains_key(dependency) {
                errors.push(Diagnostic::error(
                    "breg.action.effect-dependency-unknown",
                    "actions[].plan.effects[].after",
                    "a dependency must name an effect in this plan",
                ));
            }
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    let mut done = BTreeSet::new();
    let mut ordered = Vec::new();
    while !by_id.is_empty() {
        let ready = by_id
            .iter()
            .filter(|(_, effect)| effect.depends_on.is_subset(&done))
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        if ready.is_empty() {
            return Err(vec![Diagnostic::error(
                "breg.action.effect-dependency-cycle",
                "actions[].plan.effects",
                "plan dependencies must form a directed acyclic graph",
            )]);
        }
        for id in ready {
            done.insert(id.clone());
            ordered.push(by_id.remove(&id).expect("ready effect exists"));
        }
    }
    Ok(ordered)
}

/// Hard ceilings bound both fixed and function-backed plans.
pub const MAX_PLAN_TARGETS: u16 = 16;
pub const MAX_PLAN_FIELD_MUTATIONS: u16 = 128;
pub const MAX_PLAN_SNAPSHOT_BYTES: u32 = 2_097_152;
pub const MAX_PLAN_SOURCE_BYTES: usize = 65_536;
pub const PLAN_RHAI_VERSION: &str = "1.26.1";
pub(crate) fn valid_function_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 256
        && path.ends_with(".rhai")
        && !path.starts_with('/')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}
