// SPDX-License-Identifier: Apache-2.0
//! One bounded dependency validator for authored and evaluated action plans.
use crate::{diagnostics::Diagnostic, model::CompiledPlanEffect};
use std::collections::{BTreeMap, BTreeSet};

pub fn condition_inputs(action: &crate::model::CompiledAction) -> BTreeSet<&str> {
    action
        .target_uses
        .iter()
        .filter(|use_| use_.condition_required)
        .filter_map(|use_| match &use_.source {
            crate::model::CompiledActionTargetUseSource::Input { input } => Some(input.as_str()),
            crate::model::CompiledActionTargetUseSource::Effect { .. } => None,
        })
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EffectGroupOrderError {
    #[error("effect identifiers must be unique across folded groups")]
    DuplicateId,
    #[error("an effect dependency is not present in the plan")]
    UnknownDependency,
    #[error("folded effect groups contain a dependency cycle")]
    Cycle,
}

/// Order atomic row groups by the union of their member dependencies. Among
/// ready groups, retain the earliest authored group. A member dependency on
/// another member of its own folded row is already satisfied by that group.
pub fn order_effect_groups<T>(
    groups: Vec<Vec<T>>,
    id: impl Fn(&T) -> &str,
    depends: impl Fn(&T) -> &BTreeSet<String>,
) -> Result<Vec<Vec<T>>, EffectGroupOrderError> {
    let mut owners = BTreeMap::new();
    for (index, group) in groups.iter().enumerate() {
        for effect in group {
            if owners.insert(id(effect).to_owned(), index).is_some() {
                return Err(EffectGroupOrderError::DuplicateId);
            }
        }
    }
    let mut dependencies = Vec::with_capacity(groups.len());
    for (index, group) in groups.iter().enumerate() {
        let mut required = BTreeSet::new();
        for effect in group {
            for dependency in depends(effect) {
                let owner = owners
                    .get(dependency)
                    .ok_or(EffectGroupOrderError::UnknownDependency)?;
                if *owner != index {
                    required.insert(*owner);
                }
            }
        }
        dependencies.push(required);
    }
    let mut remaining = groups.into_iter().map(Some).collect::<Vec<_>>();
    let mut completed = BTreeSet::new();
    let mut ordered = Vec::with_capacity(remaining.len());
    while ordered.len() < remaining.len() {
        let index = remaining
            .iter()
            .enumerate()
            .find_map(|(index, group)| {
                (group.is_some() && dependencies[index].is_subset(&completed)).then_some(index)
            })
            .ok_or(EffectGroupOrderError::Cycle)?;
        ordered.push(remaining[index].take().expect("selected a remaining group"));
        completed.insert(index);
    }
    Ok(ordered)
}

/// Validate the revised ordered Plan contract without reordering effects.
/// A dependency can only name a create whose position precedes its consumer.
pub fn order_plan_effects(
    effects: Vec<CompiledPlanEffect>,
) -> Result<Vec<CompiledPlanEffect>, Vec<Diagnostic>> {
    let mut seen = BTreeSet::new();
    let mut earlier_creates = BTreeSet::new();
    let mut errors = Vec::new();
    for effect in &effects {
        if !seen.insert(effect.id.clone()) {
            errors.push(Diagnostic::error(
                "breg.action.effect-id-duplicate",
                "actions[].plan.effects",
                "effect identifiers must be unique",
            ));
        }
        for dependency in &effect.depends_on {
            if !earlier_creates.contains(dependency) {
                errors.push(Diagnostic::error(
                    "breg.action.effect-reference-not-earlier-create",
                    "actions[].plan.effects[].set",
                    "fromEffect must name an earlier create effect in this ordered plan",
                ));
            }
        }
        if effect.operation == crate::contract::Operation::Create {
            earlier_creates.insert(effect.id.clone());
        }
    }
    if errors.is_empty() {
        Ok(effects)
    } else {
        Err(errors)
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    fn effect(id: &str, dependencies: &[&str]) -> (String, BTreeSet<String>) {
        (
            id.to_owned(),
            dependencies.iter().map(|id| (*id).to_owned()).collect(),
        )
    }
    #[test]
    fn folded_groups_wait_for_every_member_and_choose_earliest_ready() {
        let groups = vec![
            vec![effect("first", &["late"]), effect("folded", &["early"])],
            vec![effect("independent", &[])],
            vec![effect("early", &[])],
            vec![effect("late", &[])],
        ];
        let ordered =
            order_effect_groups(groups, |effect| effect.0.as_str(), |effect| &effect.1).unwrap();
        assert_eq!(
            ordered
                .iter()
                .map(|group| group[0].0.as_str())
                .collect::<Vec<_>>(),
            ["independent", "early", "late", "first"]
        );
    }
    #[test]
    fn folded_groups_ignore_internal_edges_and_refuse_invalid_graphs() {
        assert!(order_effect_groups(
            vec![vec![effect("a", &[]), effect("b", &["a"])]],
            |effect| effect.0.as_str(),
            |effect| &effect.1
        )
        .is_ok());
        for (groups, error) in [
            (
                vec![vec![effect("a", &[])], vec![effect("a", &[])]],
                EffectGroupOrderError::DuplicateId,
            ),
            (
                vec![vec![effect("a", &["missing"])]],
                EffectGroupOrderError::UnknownDependency,
            ),
            (
                vec![
                    vec![effect("a", &[]), effect("c", &["b"])],
                    vec![effect("b", &["a"])],
                ],
                EffectGroupOrderError::Cycle,
            ),
        ] {
            assert_eq!(
                order_effect_groups(groups, |effect| effect.0.as_str(), |effect| &effect.1),
                Err(error)
            );
        }
    }
}
