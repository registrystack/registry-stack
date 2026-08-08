//! The checks an authored derivation program must pass.
//!
//! Only the program text is read here. Compiling is not running: no derivation
//! is evaluated, no module is resolved, and nothing outside the string reaches
//! this code.

use std::collections::BTreeSet;

use crate::finding::{FieldPath, Finding};

/// Parse the authored program as Rhai and reserve `derive` exclusively for
/// the generated binding wrapper. Function discovery comes from the AST, so
/// strings, comments, and whitespace cannot masquerade as entry points.
#[must_use]
pub fn validate_authored_answer(source: &str) -> Vec<Finding> {
    let one = |code, message: &str| vec![Finding::new(FieldPath::root(), code, message)];
    let Ok(ast) = rhai::Engine::new().compile(source) else {
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
