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

/// Parse the authored program as Rhai and reserve `derive` exclusively for
/// the generated binding wrapper. Function discovery comes from the AST, so
/// strings, comments, and whitespace cannot masquerade as entry points.
#[must_use]
pub fn validate_authored_answer(source: &str) -> Vec<Finding> {
    let one = |code, message: &str| vec![Finding::new(FieldPath::root(), code, message)];
    let Ok(ast) = parser().compile(source) else {
        return one(
            "derivation-compile",
            "authored derivation does not compile as Rhai",
        );
    };
    let mut names = BTreeSet::new();
    let mut answers = 0;
    for function in ast.iter_functions() {
        if !names.insert(function.name) {
            return one(
                "derivation-function-unique",
                "authored derivation function names must be unique",
            );
        }
        if function.name == "derive" {
            return one(
                "derivation-reserved-entry-point",
                "the `derive` entry point is reserved for the generated concept binding",
            );
        }
        if function.name == "answer" {
            if function.params.len() != 3 {
                return one(
                    "derivation-answer-signature",
                    "authored derivation must declare answer(facts, selectors, context)",
                );
            }
            answers += 1;
        }
    }
    if answers != 1 {
        return one(
            "derivation-answer-count",
            "authored derivation must declare exactly one answer(facts, selectors, context)",
        );
    }
    Vec::new()
}

/// Name every fact the `answer` function reads that `declared` does not hold.
///
/// A fact read is an index read with a string literal key (`facts["status"]`)
/// or a property read (`facts.status`, `facts?.status`) on the first parameter
/// of `answer`, however that parameter is named. Only the first key of a chain
/// is a fact name: `facts.address.region` reads the fact `address`.
///
/// The operands of one `??` fallback are read together: when any of them reads
/// a declared fact, none of its reads is named, so `facts.new ?? facts.old`
/// stays valid while a source moves from one name to the other.
///
/// The check is deliberately partial, and never refuses a program it cannot
/// read. A computed key (`facts[key]`) is not a literal read, so it is the
/// way to read a fact the check should not see, and like a read inside another
/// function the facts are passed to, it is left to the fixtures. So is an
/// `answer` that rebinds or writes its first parameter anywhere, through
/// `let`, `const`, an assignment to it or to one of its keys, a `for` loop
/// variable, or a `catch` variable. A program the other derivation checks
/// refuse reports nothing here, because those checks already name what is
/// wrong with it.
///
/// Each undeclared fact is named once, in name order.
#[must_use]
pub fn validate_answer_fact_reads(source: &str, declared: &BTreeSet<String>) -> Vec<Finding> {
    let Ok(ast) = parser().compile(source) else {
        return Vec::new();
    };
    let mut answers = ast
        .iter_functions()
        .filter(|function| function.name == "answer" && function.params.len() == 3);
    let (Some(answer), None) = (answers.next(), answers.next()) else {
        return Vec::new();
    };
    let facts = answer.params[0];
    // `retain_functions` rather than `clone_functions_only_filtered`: in the
    // pinned rhai the latter copies every function when its target module is
    // empty, which a fresh clone always is.
    let mut body = ast.clone_functions_only();
    body.retain_functions(|_, _, name, params| name == "answer" && params == 3);

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
