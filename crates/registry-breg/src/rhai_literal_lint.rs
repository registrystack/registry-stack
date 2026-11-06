// SPDX-License-Identifier: Apache-2.0
//! Only direct returned ABI structures are inspected. This is not dataflow
//! analysis: variables, helper returns and dynamically assembled arrays remain
//! subject to the ordinary runtime validator and executable branch tests.
//!
//! Calls are inspected the same way: only a call written with a literal
//! function name, directly, as a method, or through `Fn("name")`, is checked
//! against the functions the plan engine leaves out. A name computed at run
//! time still fails when the call runs.

use rhai::{ASTNode, Engine, Expr, FnPtr, Stmt};
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

/// A call, by literal name, to a function Rhai's standard engine offers but
/// the plan engine does not, so the call can only fail when it runs.
pub(crate) struct UnavailableCall {
    pub function: String,
    pub position: rhai::Position,
}

/// Every call in `script`, in any function, to a named function that Rhai's
/// standard engine provides and the plan engine leaves out, unless the script
/// defines a function of that name itself. The left-out names are derived
/// from the two engines rather than listed, so they follow the plan engine.
pub(crate) fn unavailable_calls(script: &str) -> Vec<UnavailableCall> {
    let mut engine = crate::rhai_planner::engine(None);
    // As above: inspect the calls as authored, not as the optimizer rewrote
    // them.
    engine.set_optimization_level(rhai::OptimizationLevel::None);
    let Ok(ast) = engine.compile(script) else {
        return Vec::new();
    };
    let available = function_names(&engine);
    let defined = ast
        .iter_functions()
        .map(|function| function.name.to_owned())
        .collect::<BTreeSet<_>>();
    let unavailable = function_names(&Engine::new())
        .into_iter()
        .filter(|name| is_identifier(name))
        .filter(|name| !available.contains(name) && !defined.contains(name))
        .collect::<BTreeSet<_>>();
    let mut calls = Vec::new();
    ast.walk(&mut |path| {
        let named = match path.last() {
            Some(ASTNode::Expr(Expr::FnCall(call, position))) if !call.is_qualified() => {
                if call.name == "Fn" && call.args.len() == 1 {
                    literal_string(&call.args[0]).map(|name| (name, *position))
                } else {
                    Some((call.name.to_string(), *position))
                }
            }
            Some(ASTNode::Expr(Expr::MethodCall(call, position))) => {
                Some((call.name.to_string(), *position))
            }
            Some(ASTNode::Expr(Expr::DynamicConstant(value, position))) => value
                .read_lock::<FnPtr>()
                .map(|pointer| (pointer.fn_name().to_owned(), *position)),
            _ => None,
        };
        if let Some((function, position)) = named {
            if unavailable.contains(&function) {
                calls.push(UnavailableCall { function, position });
            }
        }
        true
    });
    calls
}

fn function_names(engine: &Engine) -> BTreeSet<String> {
    engine
        .collect_fn_metadata(None, |info| Some(info.metadata.name.to_string()), true)
        .into_iter()
        .collect()
}

/// Operators and property accessors are resolved by argument type, so a
/// left-out overload of one says nothing about a call by that name.
fn is_identifier(name: &str) -> bool {
    name.chars()
        .next()
        .is_some_and(|first| first.is_alphabetic() || first == '_')
        && name.chars().all(|c| c.is_alphanumeric() || c == '_')
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
