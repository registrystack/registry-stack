//! The checks an authored derivation program must pass.
//!
//! Only the program text is read here. Compiling is not running: no derivation
//! is evaluated, no module is resolved, and nothing outside the string reaches
//! this code. The engine below has no resolver to reach a module with either,
//! so an authored `import` names a path that nothing here will open.

use std::collections::BTreeSet;

use rhai::module_resolvers::DummyModuleResolver;

use crate::finding::{FieldPath, Finding};

/// A Rhai engine with no way to reach a module, whatever it is later asked to
/// do with a program.
///
/// `Engine::new` installs a resolver that opens the file an `import` statement
/// names. Parsing never asks it to, so the engine as built would read nothing,
/// but that is a fact about one call site rather than about the engine, and the
/// distance between it and an editor process opening whatever path an author
/// typed is one changed call. Giving the resolver up leaves the engine no path
/// to a file to lose.
fn parser() -> rhai::Engine {
    let mut engine = rhai::Engine::new();
    engine.set_module_resolver(DummyModuleResolver::new());
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
