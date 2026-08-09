//! The checks an authored derivation program must pass.
//!
//! Only the program text is read here. Compiling is not running: no derivation
//! is evaluated, no module is resolved, and nothing outside the string reaches
//! this code. The engine below has no resolver to reach a module with either,
//! and no way to reach a standard stream, so an authored `import` names a path
//! that nothing here will open and an authored `print` has nowhere to land.

use std::collections::BTreeSet;

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
