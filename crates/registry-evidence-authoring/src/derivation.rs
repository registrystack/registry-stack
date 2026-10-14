//! The checks an authored derivation program must pass.
//!
//! Only the program text is read here. Compiling is not running: no derivation
//! is evaluated, no module is resolved, and nothing outside the string reaches
//! this code. The engine below has no resolver to reach a module with either,
//! and no way to reach a standard stream, so an authored `import` names a path
//! that nothing here will open and an authored `print` has nowhere to land.

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_yaml::LocalId;
use rhai::module_resolvers::DummyModuleResolver;

use crate::finding::{FieldPath, Finding};

/// A Rhai engine with no way to reach a module and no way to reach a standard
/// stream, whatever it is later asked to do with a program.
///
/// `Engine::new` hands out three capabilities this crate must not have. Its
/// module resolver opens the file an `import` statement names. Its print and
/// debug handlers are `println!` (rhai 1.25.1, `src/engine.rs:305-318`), so an
/// authored `print` or `debug` writes to file descriptor 1, which in the editor
/// process this crate is linked into is the JSON-RPC channel itself. Parsing
/// asks for none of the three, so the engine as built would reach nothing, but
/// that is a fact about one call site rather than about the engine, and the
/// distance between it and an editor opening whatever path an author typed, or
/// printing whatever an author wrote, is one changed call. Giving all three up
/// leaves the engine no file to open and no stream to write.
///
/// This is the crate's only engine, and the lint configuration beside this
/// crate is what keeps it the only one: `rhai::Engine` and its constructors are
/// disallowed types and methods there, resolved after name resolution rather
/// than matched as text, and this is the one site that expects them. The
/// expectation is what makes that configuration load-bearing, because a build
/// that stops applying it leaves this expectation unfulfilled and fails.
#[expect(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    reason = "the crate's one engine, disarmed on the next three lines"
)]
fn parser() -> rhai::Engine {
    let mut engine = rhai::Engine::new();
    engine.set_module_resolver(DummyModuleResolver::new());
    engine.on_print(|_| {});
    engine.on_debug(|_, _, _| {});
    engine
}

/// The validated named entry point arity, without executing its program.
pub(crate) fn function_arity(
    source: &str,
    interface: crate::project::FunctionInterface,
) -> Option<usize> {
    let ast = parser().compile(source).ok()?;
    let (entry, arities) = interface.entry_point();
    let mut functions = ast
        .iter_functions()
        .filter(|function| function.name == entry);
    let arity = functions.next()?.params.len();
    (functions.next().is_none() && arities.contains(&arity)).then_some(arity)
}

/// Validate the reviewed named Function against its one interface. The parser
/// cannot load imports, print, or execute the supplied program.
#[must_use]
pub fn validate_function(
    source: &str,
    interface: crate::project::FunctionInterface,
) -> Vec<Finding> {
    let Ok(ast) = parser().compile(source) else {
        return vec![Finding::new(
            FieldPath::root(),
            "function-compile",
            "Function does not compile as Rhai",
        )];
    };
    let (entry, arities) = interface.entry_point();
    let entries = ast
        .iter_functions()
        .filter(|function| function.name == entry)
        .collect::<Vec<_>>();
    if entries.len() != 1 || !arities.contains(&entries[0].params.len()) {
        return vec![Finding::new(
            FieldPath::root(),
            "function-signature",
            "Function must expose exactly one entry point with its declared interface signature",
        )];
    }
    if ast.iter_functions().any(|function| {
        [
            "prepare",
            "extract",
            "derive",
            "prepare_batch",
            "extract_batch",
        ]
        .contains(&function.name)
            && function.name != entry
    }) {
        return vec![Finding::new(
            FieldPath::root(),
            "function-interface",
            "Function cannot expose another interface entry point",
        )];
    }
    Vec::new()
}

/// Source-batch call sites use the existing source interface with exactly two
/// arguments. This only inspects the reviewed program; it never evaluates it.
#[must_use]
pub fn validate_batch_function(
    source: &str,
    interface: crate::project::FunctionInterface,
) -> Vec<Finding> {
    let findings = validate_function(source, interface);
    if !findings.is_empty() {
        return findings;
    }
    let ast = parser().compile(source).expect("validated Function");
    let (entry, _) = interface.entry_point();
    if ast
        .iter_functions()
        .find(|function| function.name == entry)
        .is_none_or(|function| function.params.len() != 2)
    {
        return vec![Finding::new(
            FieldPath::root(),
            "batch-function-signature",
            "source batch Functions must expose the two-argument source interface",
        )];
    }
    Vec::new()
}

/// Check named assertion Function reads against its acquired private FactSet.
#[must_use]
pub fn validate_derive_fact_reads(source: &str, declared: &BTreeSet<String>) -> Vec<Finding> {
    validate_entry_fact_reads(source, "derive", declared)
}

fn validate_entry_fact_reads(
    source: &str,
    entry: &str,
    declared: &BTreeSet<String>,
) -> Vec<Finding> {
    let Ok(ast) = parser().compile(source) else {
        return Vec::new();
    };
    let mut answers = ast
        .iter_functions()
        .filter(|function| function.name == entry && function.params.len() == 3);
    let (Some(answer), None) = (answers.next(), answers.next()) else {
        return Vec::new();
    };
    let facts = answer.params[0];
    // `retain_functions` rather than `clone_functions_only_filtered`: in the
    // pinned rhai the latter copies every function when its target module is
    // empty, which a fresh clone always is.
    let mut body = ast.clone_functions_only();
    body.retain_functions(|_, _, name, params| name == entry && params == 3);

    let mut rebound = false;
    let mut read = BTreeSet::new();
    // The reads under each outermost `??`, keyed by that node's address, which
    // is stable for the walk.
    let mut fallbacks: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
    body.walk(&mut |path| {
        match path.last() {
            Some(rhai::ASTNode::Stmt(statement)) if rebinds(statement, facts) => {
                rebound = true;
                return false;
            }
            Some(rhai::ASTNode::Expr(
                rhai::Expr::Index(chain, ..) | rhai::Expr::Dot(chain, ..),
            )) if names_variable(&chain.lhs, facts) => {
                if let Some(name) = first_key(path.last(), &chain.rhs) {
                    let fallback = path.iter().find_map(|node| match node {
                        rhai::ASTNode::Expr(expression @ rhai::Expr::Coalesce(..)) => {
                            Some(std::ptr::from_ref(*expression) as usize)
                        }
                        _ => None,
                    });
                    match fallback {
                        Some(fallback) => {
                            fallbacks.entry(fallback).or_default().insert(name);
                        }
                        None => {
                            read.insert(name);
                        }
                    }
                }
            }
            _ => {}
        }
        true
    });
    if rebound {
        return Vec::new();
    }
    for names in fallbacks.into_values() {
        if !names.iter().any(|name| declared.contains(name)) {
            read.extend(names);
        }
    }
    read.into_iter()
        .filter(|name| !declared.contains(name))
        .map(|name| {
            Finding::new(
                FieldPath::root(),
                "derivation-fact-undeclared",
                if LocalId::new(name.as_str()).is_ok() {
                    format!(
                        "authored derivation reads fact `{name}`, which the question's source does not declare"
                    )
                } else {
                    "authored derivation reads a fact the question's source does not declare"
                        .to_owned()
                },
            )
        })
        .collect()
}

/// Whether a statement binds or writes `name`: a `let` or `const`, an
/// assignment to it or to one of its keys, a `for` loop variable, or a `catch`
/// variable.
fn rebinds(statement: &rhai::Stmt, name: &str) -> bool {
    match statement {
        rhai::Stmt::Var(binding, ..) => binding.0.name == name,
        rhai::Stmt::Assignment(assignment) => {
            let mut target = &assignment.1.lhs;
            while let rhai::Expr::Index(chain, ..) | rhai::Expr::Dot(chain, ..) = target {
                target = &chain.lhs;
            }
            names_variable(target, name)
        }
        rhai::Stmt::For(binding, ..) => {
            binding.0.name == name
                || binding
                    .1
                    .as_ref()
                    .is_some_and(|counter| counter.name == name)
        }
        rhai::Stmt::TryCatch(flow, ..) => names_variable(&flow.expr, name),
        _ => false,
    }
}

/// Whether an expression is the plain, unqualified variable `name`.
fn names_variable(expression: &rhai::Expr, name: &str) -> bool {
    matches!(
        expression,
        rhai::Expr::Variable(variable, ..) if variable.1 == name && variable.2.is_empty()
    )
}

/// The key a chain reads first, when it is written literally: a string index
/// under `[` or a property under `.`. A method call, a computed index, and any
/// other link name no key this check can read.
fn first_key(link: Option<&rhai::ASTNode>, rhs: &rhai::Expr) -> Option<String> {
    let mut key = rhs;
    while let rhai::Expr::Index(chain, ..) | rhai::Expr::Dot(chain, ..) = key {
        key = &chain.lhs;
    }
    match (link, key) {
        (
            Some(rhai::ASTNode::Expr(rhai::Expr::Index(..))),
            rhai::Expr::StringConstant(name, ..),
        ) => Some(name.to_string()),
        (Some(rhai::ASTNode::Expr(rhai::Expr::Dot(..))), rhai::Expr::Property(property, ..)) => {
            Some(property.2.to_string())
        }
        _ => None,
    }
}
