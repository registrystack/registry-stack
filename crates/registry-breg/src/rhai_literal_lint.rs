// SPDX-License-Identifier: Apache-2.0
//! Only direct returned ABI structures are inspected. This is not dataflow
//! analysis: variables, helper returns and dynamically assembled arrays remain
//! subject to the ordinary runtime validator and executable branch tests.

use rhai::{ASTNode, Expr, Stmt};
use std::collections::BTreeSet;

pub(crate) struct LiteralFault {
    pub code: &'static str,
    pub message: &'static str,
    pub position: rhai::Position,
}

pub(crate) fn inspect(
    script: &str,
    entrypoint: &str,
    refusals: &BTreeSet<&str>,
    effects: &BTreeSet<&str>,
) -> Vec<LiteralFault> {
    // Keep authored computed expressions computed. Optimizing first would
    // turn constant propagation into an accidental, broader lint contract.
    // The caller inspects only a source the same engine already compiled and
    // reports compile failures itself; an uncompilable source has no direct
    // literal to inspect.
    let Ok(mut ast) = crate::rhai_planner::engine(None)
        .set_optimization_level(rhai::OptimizationLevel::None)
        .compile(script)
    else {
        return Vec::new();
    };
    ast.clear_statements();
    ast.retain_functions(|_, _, name, arity| name == entrypoint && arity == 1);
    let mut returned = Vec::new();
    let mut final_statement = None;
    ast.walk(&mut |path| {
        if let Some(ASTNode::Stmt(statement)) = path.last() {
            if path.len() == 1 {
                final_statement = Some((*statement).clone());
            }
            if let Stmt::Return(Some(value), flags, _) = statement {
                if !flags.contains(rhai::ASTFlags::BREAK) {
                    returned.push((**value).clone());
                }
            }
        }
        true
    });
    if let Some(Stmt::Expr(value)) = final_statement {
        returned.push(*value);
    }
    let mut faults = Vec::new();
    for outcome in returned {
        let Some(keys) = map_keys(&outcome) else {
            continue;
        };
        if keys == ["refusal"] {
            if let Some(refusal) = member(&outcome, "refusal") {
                if let Some(code) = member(&refusal, "code") {
                    if literal_string(&code).is_some_and(|code| !refusals.contains(code.as_str())) {
                        faults.push(LiteralFault {code:"breg.action.plan-literal-refusal-undeclared", message:"Direct returned refusal.code is undeclared; correct the literal or declare it in plan.refusals.", position:code.position()});
                    }
                }
            }
        } else if keys == ["effects"] {
            if let Some(array) = member(&outcome, "effects").and_then(|array| array_items(&array)) {
                for effect in array {
                    if let Some(id) = member(&effect, "id") {
                        if literal_string(&id).is_some_and(|id| !effects.contains(id.as_str())) {
                            faults.push(LiteralFault {code:"breg.action.plan-literal-effect-undeclared", message:"Direct returned effects[].id is undeclared; correct the literal or declare the slot in plan.writes.", position:id.position()});
                        }
                    }
                }
            }
        }
    }
    faults
}

fn member(value: &Expr, key: &str) -> Option<Expr> {
    if let Expr::Map(map, _) = value {
        return map
            .0
            .iter()
            .find(|(name, _)| name.name == key)
            .map(|(_, value)| value.clone());
    }
    let mut map = value.get_literal_value(None)?.try_cast::<rhai::Map>()?;
    map.remove(key)
        .map(|member| Expr::DynamicConstant(Box::new(member), value.position()))
}

fn map_keys(value: &Expr) -> Option<Vec<String>> {
    if let Expr::Map(map, _) = value {
        return Some(
            map.0
                .iter()
                .map(|(name, _)| name.name.to_string())
                .collect(),
        );
    }
    Some(
        value
            .get_literal_value(None)?
            .try_cast::<rhai::Map>()?
            .keys()
            .map(ToString::to_string)
            .collect(),
    )
}

fn array_items(value: &Expr) -> Option<Vec<Expr>> {
    if let Expr::Array(items, _) = value {
        return Some(items.iter().cloned().collect());
    }
    Some(
        value
            .get_literal_value(None)?
            .try_cast::<rhai::Array>()?
            .into_iter()
            .map(|item| Expr::DynamicConstant(Box::new(item), value.position()))
            .collect(),
    )
}

fn literal_string(value: &Expr) -> Option<String> {
    value
        .get_literal_value(None)?
        .try_cast::<rhai::ImmutableString>()
        .map(|text| text.to_string())
}
