// SPDX-License-Identifier: Apache-2.0
//! The Rhai backend adapter: profile-described engine construction,
//! entry-point compilation, fresh-scope invocation, and bounded failure
//! classification.
//!
//! Products supply the profile values and their helper registration; this
//! module only applies them. Every verdict a product renders on a script's
//! source, inputs, results, or errors stays in the product.

use std::collections::BTreeSet;
use std::time::Instant;

use rhai::{
    module_resolvers::DummyModuleResolver, CallFnOptions, Dynamic, Engine, EvalAltResult, FuncArgs,
    Scope, AST,
};

/// The numeric limits a profile asks the engine to enforce.
///
/// Each field is applied through the corresponding engine setter;
/// `expression_depth` is applied to both the statement and function expression
/// depths.
#[derive(Clone, Copy, Debug)]
pub struct RhaiLimits {
    /// Maximum number of operations per evaluation (`set_max_operations`).
    pub operations: u64,
    /// Maximum levels of function calls (`set_max_call_levels`).
    pub call_levels: usize,
    /// Maximum expression nesting depth (`set_max_expr_depths`).
    pub expression_depth: usize,
    /// Maximum number of loaded modules (`set_max_modules`).
    pub modules: usize,
    /// Maximum size, in bytes, of a single string (`set_max_string_size`).
    pub string_bytes: usize,
    /// Maximum number of items in an array (`set_max_array_size`).
    pub array_items: usize,
    /// Maximum number of entries in an object map (`set_max_map_size`).
    pub map_entries: usize,
}

/// Which base engine spelling a profile constructs before limits are applied.
///
/// The choice is product policy. `Standard` is the full engine with its module
/// loading removed and its print and debug output silenced; `Raw` is the bare
/// engine with no packages and no resolver, for products that register every
/// callable themselves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RhaiBaseEngine {
    /// `Engine::new()` with a `DummyModuleResolver`, so every `import` fails,
    /// and silenced `on_print`/`on_debug` handlers.
    Standard,
    /// `Engine::new_raw()` with no packages, no built-ins, and no resolver.
    Raw,
}

/// Everything the adapter needs to construct and compile for one product: the
/// exact settings the engine receives, plus the source byte bound its compile
/// path enforces. Products own these values; identical values across products
/// do not make two profiles the same program, because helper registration
/// differs.
#[derive(Clone, Copy, Debug)]
pub struct RhaiProfile {
    /// Numeric engine limits, applied verbatim.
    pub limits: RhaiLimits,
    /// The base engine the limits are applied to.
    pub base: RhaiBaseEngine,
    /// Language symbols removed from the parser, in application order.
    pub disabled_symbols: &'static [&'static str],
    /// Whether anonymous functions (closures) may be compiled.
    pub allow_anonymous_fn: bool,
    /// The compile path refuses sources longer than this many bytes.
    pub maximum_source_bytes: usize,
}

/// Why compiling a source under an entry-point contract failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RhaiCompileError {
    /// The source exceeds the profile's source byte bound.
    SourceBound,
    /// The engine refused to parse or compile the source.
    Parse(rhai::Position),
    /// The entry-point contract failed: a duplicate function name, or not
    /// exactly one public entry point at a declared arity.
    Entrypoint,
}

/// The bounded category of a Rhai evaluation failure. The adapter recognizes
/// engine-level resource exhaustion and leaves every other failure to the
/// product's own closed error mapping; no script-controlled text crosses this
/// boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RhaiFailureCategory {
    /// The engine's operation, call-depth, or data-size budget was exhausted.
    ResourceExhausted,
    /// Every other engine-level failure.
    Other,
}

/// Construct a Rhai engine from `profile`.
///
/// The base engine is built first, then the limits, anonymous-function policy,
/// and disabled symbols are applied in that order, then `register` installs the
/// product's own helpers and modules, and finally an optional `deadline` is
/// wired through the engine's progress hook so a running evaluation terminates
/// once the instant passes. A product may call this once and retain the engine,
/// or once per call; nothing here mandates either lifetime.
pub fn build_engine(
    profile: &RhaiProfile,
    deadline: Option<Instant>,
    register: impl FnOnce(&mut Engine),
) -> Engine {
    let mut engine = match profile.base {
        RhaiBaseEngine::Standard => {
            let mut engine = Engine::new();
            engine.set_module_resolver(DummyModuleResolver::new());
            engine.on_print(|_| {});
            engine.on_debug(|_, _, _| {});
            engine
        }
        RhaiBaseEngine::Raw => Engine::new_raw(),
    };
    engine
        .set_max_operations(profile.limits.operations)
        .set_max_call_levels(profile.limits.call_levels)
        .set_max_expr_depths(
            profile.limits.expression_depth,
            profile.limits.expression_depth,
        )
        .set_max_modules(profile.limits.modules)
        .set_max_string_size(profile.limits.string_bytes)
        .set_max_array_size(profile.limits.array_items)
        .set_max_map_size(profile.limits.map_entries)
        .set_allow_anonymous_fn(profile.allow_anonymous_fn);
    for symbol in profile.disabled_symbols {
        engine.disable_symbol(*symbol);
    }
    register(&mut engine);
    if let Some(deadline) = deadline {
        engine.on_progress(move |_| (Instant::now() >= deadline).then_some(Dynamic::UNIT));
    }
    engine
}

/// Compile `source` under the entry-point contract `(entrypoint, arities)`.
///
/// The source is refused over the profile's byte bound, compiled with an
/// engine built from the same profile (product helper registration cannot
/// change compilation: the default optimizer folds only built-in operators),
/// and then checked for unique function names and exactly one public function
/// named `entrypoint` whose parameter count is in `arities`. Which source is
/// reviewable, and what the entry point is called, stay with the product.
pub fn compile_entrypoint(
    profile: &RhaiProfile,
    source: &str,
    entrypoint: &str,
    arities: &[usize],
) -> Result<AST, RhaiCompileError> {
    if source.len() > profile.maximum_source_bytes {
        return Err(RhaiCompileError::SourceBound);
    }
    let engine = build_engine(profile, None, |_| {});
    let ast = engine
        .compile(source)
        .map_err(|error| RhaiCompileError::Parse(error.position()))?;
    let mut names = BTreeSet::new();
    let mut entrypoints = 0usize;
    for function in ast.iter_functions() {
        if !names.insert(function.name) {
            return Err(RhaiCompileError::Entrypoint);
        }
        if function.name == entrypoint {
            if !arities.contains(&function.params.len())
                || function.access != rhai::FnAccess::Public
            {
                return Err(RhaiCompileError::Entrypoint);
            }
            entrypoints += 1;
        }
    }
    if entrypoints != 1 {
        return Err(RhaiCompileError::Entrypoint);
    }
    Ok(ast)
}

/// Invoke `entrypoint` on `ast` through `engine` with a fresh scope.
///
/// Top-level statements in `ast` are never evaluated; only the named function
/// runs, with the arguments the caller supplies. The scope is created and
/// dropped inside this call, so no state survives between invocations.
pub fn call_with_fresh_scope<A: FuncArgs>(
    engine: &Engine,
    ast: &AST,
    entrypoint: &str,
    args: A,
) -> Result<Dynamic, Box<EvalAltResult>> {
    engine.call_fn_with_options::<Dynamic>(
        CallFnOptions::new().eval_ast(false),
        &mut Scope::new(),
        ast,
        entrypoint,
        args,
    )
}

/// Classify a Rhai evaluation failure into the bounded categories.
///
/// Operation-count, call-depth, and data-size exhaustion are the engine's own
/// resource families; everything else, including script-thrown errors, is left
/// to the product's mapping.
pub fn classify_failure(error: &EvalAltResult) -> RhaiFailureCategory {
    if matches!(
        error,
        EvalAltResult::ErrorTooManyOperations(..)
            | EvalAltResult::ErrorStackOverflow(..)
            | EvalAltResult::ErrorDataTooLarge(..)
    ) {
        RhaiFailureCategory::ResourceExhausted
    } else {
        RhaiFailureCategory::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The profile shape the Base Registry Engine supplies today. The values
    /// mirror its published constants so the adapter's behavior is pinned
    /// against the values, not the symbols.
    fn breg_shaped_profile() -> RhaiProfile {
        RhaiProfile {
            limits: RhaiLimits {
                operations: 100_000,
                call_levels: 32,
                expression_depth: 64,
                modules: 0,
                string_bytes: 16_384,
                array_items: 256,
                map_entries: 256,
            },
            base: RhaiBaseEngine::Standard,
            disabled_symbols: &["import", "export", "eval", "print", "debug"],
            allow_anonymous_fn: false,
            maximum_source_bytes: 65_536,
        }
    }

    fn profile_with(overrides: impl FnOnce(&mut RhaiProfile)) -> RhaiProfile {
        let mut profile = breg_shaped_profile();
        overrides(&mut profile);
        profile
    }

    /// Compile `source` for a one-parameter `entry` function and run it with a
    /// unit argument, so limit and classification tests share one path.
    fn evaluate(
        profile: &RhaiProfile,
        source: &str,
        deadline: Option<Instant>,
    ) -> Result<Dynamic, Box<EvalAltResult>> {
        let engine = build_engine(profile, deadline, |_| {});
        let ast = compile_entrypoint(profile, source, "entry", &[1])
            .expect("test source compiles under its profile");
        call_with_fresh_scope(&engine, &ast, "entry", (Dynamic::UNIT,))
    }

    #[test]
    fn operations_budget_terminates_runaway_evaluation() {
        let profile = profile_with(|profile| profile.limits.operations = 64);
        let error = evaluate(
            &profile,
            "fn entry(ctx) { let total = 0; for i in 0..10000 { total += 1; } total }",
            None,
        )
        .expect_err("a 64-operation budget cannot run a 10000-iteration loop");
        assert!(matches!(*error, EvalAltResult::ErrorTooManyOperations(..)));
        assert_eq!(
            classify_failure(&error),
            RhaiFailureCategory::ResourceExhausted
        );
    }

    #[test]
    fn call_depth_budget_terminates_deep_recursion() {
        let error = evaluate(
            &breg_shaped_profile(),
            "fn descend(n) { if n <= 0 { 0 } else { descend(n - 1) } }
             fn entry(ctx) { descend(1000) }",
            None,
        )
        .expect_err("recursion 1000 deep exceeds a 32-level budget");
        assert!(matches!(*error, EvalAltResult::ErrorStackOverflow(..)));
        assert_eq!(
            classify_failure(&error),
            RhaiFailureCategory::ResourceExhausted
        );
    }

    #[test]
    fn data_size_budgets_terminate_oversized_values() {
        for (source, label) in [
            (
                r#"fn entry(ctx) {
                    let joined = "0123456789abcdefghij";
                    for i in 0..2000 { joined += "0123456789abcdefghij"; }
                    joined.len()
                }"#,
                "string growth past the byte bound",
            ),
            (
                "fn entry(ctx) { let items = []; for i in 0..300 { items.push(i); } items.len() }",
                "array growth past the item bound",
            ),
            (
                r#"fn entry(ctx) {
                    let entries = #{};
                    for i in 0..300 { entries[i.to_string()] = i; }
                    entries.len()
                }"#,
                "map growth past the entry bound",
            ),
        ] {
            let error = match evaluate(&breg_shaped_profile(), source, None) {
                Ok(value) => panic!("{label} must fail, returned {value:?}"),
                Err(error) => error,
            };
            assert!(
                matches!(*error, EvalAltResult::ErrorDataTooLarge(..)),
                "{label} classified as {error:?}"
            );
            assert_eq!(
                classify_failure(&error),
                RhaiFailureCategory::ResourceExhausted
            );
        }
    }

    #[test]
    fn expression_depth_budget_rejects_deeply_nested_sources_at_compile_time() {
        let profile = profile_with(|profile| profile.limits.expression_depth = 4);
        let nesting = 40;
        let source = format!(
            "fn entry(ctx) {{ {}1{} }}",
            "1+(".repeat(nesting),
            ")".repeat(nesting)
        );
        assert!(matches!(
            compile_entrypoint(&profile, &source, "entry", &[1]),
            Err(RhaiCompileError::Parse(_))
        ));
    }

    #[test]
    fn disabled_symbols_are_refused_by_the_parser() {
        for source in [
            r#"fn entry(ctx) { import "somewhere"; 42 }"#,
            r#"fn entry(ctx) { export fn f(x) { x }; 42 }"#,
            r#"fn entry(ctx) { eval("42") }"#,
        ] {
            assert!(
                matches!(
                    compile_entrypoint(&breg_shaped_profile(), source, "entry", &[1]),
                    Err(RhaiCompileError::Parse(_))
                ),
                "disabled symbol accepted in: {source}"
            );
        }
    }

    #[test]
    fn anonymous_functions_are_refused_when_the_profile_disallows_them() {
        assert!(matches!(
            compile_entrypoint(
                &breg_shaped_profile(),
                "fn entry(ctx) { let double = |x| x + 1; double(1) }",
                "entry",
                &[1]
            ),
            Err(RhaiCompileError::Parse(_))
        ));
        let allowing = profile_with(|profile| {
            profile.allow_anonymous_fn = true;
            profile.disabled_symbols = &[];
        });
        let engine = build_engine(&allowing, None, |_| {});
        let ast = compile_entrypoint(
            &allowing,
            "fn entry(ctx) { let double = |x| x + 1; double.call(41) }",
            "entry",
            &[1],
        )
        .expect("closure allowed by profile");
        assert_eq!(
            call_with_fresh_scope(&engine, &ast, "entry", (Dynamic::UNIT,))
                .unwrap()
                .cast::<i64>(),
            42
        );
    }

    #[test]
    fn registration_closure_installs_product_helpers() {
        let engine = build_engine(&breg_shaped_profile(), None, |engine| {
            engine.register_fn("double", |value: i64| value * 2);
        });
        let ast = compile_entrypoint(
            &breg_shaped_profile(),
            "fn entry(ctx) { double(21) }",
            "entry",
            &[1],
        )
        .unwrap();
        assert_eq!(
            call_with_fresh_scope(&engine, &ast, "entry", (Dynamic::UNIT,))
                .unwrap()
                .cast::<i64>(),
            42
        );
    }

    #[test]
    fn raw_base_engine_carries_no_standard_packages() {
        let raw = profile_with(|profile| profile.base = RhaiBaseEngine::Raw);
        // A string method from the standard packages: present on Standard,
        // absent on Raw.
        let standard_error = evaluate(&breg_shaped_profile(), "fn entry(ctx) { ctx.len() }", None)
            .map(|_| ())
            .unwrap_err();
        assert_eq!(
            classify_failure(&standard_error),
            RhaiFailureCategory::Other
        );
        let raw_error = evaluate(&raw, "fn entry(ctx) { ctx.len() }", None)
            .map(|_| ())
            .unwrap_err();
        assert!(matches!(
            *raw_error,
            EvalAltResult::ErrorFunctionNotFound(..)
        ));

        // A product registration still works on the raw engine.
        let engine = build_engine(&raw, None, |engine| {
            engine.register_fn("answer", || 42_i64);
        });
        let ast = compile_entrypoint(&raw, "fn entry(ctx) { answer() }", "entry", &[1]).unwrap();
        assert_eq!(
            call_with_fresh_scope(&engine, &ast, "entry", (Dynamic::UNIT,))
                .unwrap()
                .cast::<i64>(),
            42
        );
    }

    #[test]
    fn standard_base_engine_silences_print_and_debug() {
        // With print and debug left enabled as symbols, their output is still
        // swallowed by the silenced handlers, so this test's output stays clean.
        let profile = profile_with(|profile| {
            profile.disabled_symbols = &["import", "export", "eval"];
        });
        let result = evaluate(
            &profile,
            r#"fn entry(ctx) { print("printed"); debug("debugged"); 42 }"#,
            None,
        )
        .unwrap();
        assert_eq!(result.cast::<i64>(), 42);
    }

    #[test]
    fn standard_base_engine_refuses_module_imports() {
        let profile = profile_with(|profile| profile.disabled_symbols = &[]);
        let error = evaluate(
            &profile,
            r#"fn entry(ctx) { import "somewhere" as m; 42 }"#,
            None,
        )
        .map(|_| ())
        .unwrap_err();
        assert_ne!(
            classify_failure(&error),
            RhaiFailureCategory::ResourceExhausted
        );
    }

    #[test]
    fn a_passed_deadline_terminates_evaluation() {
        let error = evaluate(
            &breg_shaped_profile(),
            "fn entry(ctx) { let total = 0; for i in 0..10000 { total += 1; } total }",
            Some(Instant::now()),
        )
        .map(|_| ())
        .expect_err("an already-passed deadline stops any looping evaluation");
        assert_ne!(
            classify_failure(&error),
            RhaiFailureCategory::ResourceExhausted
        );
    }

    #[test]
    fn a_future_deadline_leaves_evaluation_running() {
        let deadline = Instant::now() + std::time::Duration::from_secs(60);
        let result = evaluate(
            &breg_shaped_profile(),
            "fn entry(ctx) { let total = 0; for i in 0..100 { total += 1; } total }",
            Some(deadline),
        )
        .unwrap();
        assert_eq!(result.cast::<i64>(), 100);
    }

    #[test]
    fn script_thrown_and_undefined_call_failures_are_not_resource_failures() {
        for source in [
            "fn entry(ctx) { throw ctx; }",
            "fn entry(ctx) { missing_function(ctx); }",
        ] {
            let error = evaluate(&breg_shaped_profile(), source, None)
                .map(|_| ())
                .unwrap_err();
            assert_eq!(
                classify_failure(&error),
                RhaiFailureCategory::Other,
                "unexpected category for {error:?}"
            );
        }
    }

    #[test]
    fn compile_accepts_one_public_entrypoint_with_private_helpers() {
        let ast = compile_entrypoint(
            &breg_shaped_profile(),
            "private fn clean(value) { value.trim(); value }
             fn entry(context) { clean(context) }",
            "entry",
            &[1],
        )
        .expect("a single public one-parameter entrypoint compiles");
        assert!(ast.iter_functions().count() >= 2);
    }

    #[test]
    fn compile_accepts_an_entrypoint_at_any_declared_arity() {
        let source = "fn entry(context, extra) { context }";
        assert!(compile_entrypoint(&breg_shaped_profile(), source, "entry", &[2]).is_ok());
        assert!(compile_entrypoint(&breg_shaped_profile(), source, "entry", &[2, 3]).is_ok());
        assert!(compile_entrypoint(&breg_shaped_profile(), source, "entry", &[1, 3]).is_err());
    }

    #[test]
    fn compile_rejects_entrypoint_contract_violations() {
        for (source, expected) in [
            ("fn other(ctx) { 42 }", RhaiCompileError::Entrypoint),
            ("fn entry() { 42 }", RhaiCompileError::Entrypoint),
            ("fn entry(ctx, extra) { 42 }", RhaiCompileError::Entrypoint),
            ("private fn entry(ctx) { 42 }", RhaiCompileError::Entrypoint),
            // The parser itself rejects a duplicate same-arity definition;
            // the entry-point walk catches what the parser allows, namely
            // overloads of a different arity, as the next row shows.
            (
                "fn entry(ctx) { 42 } fn entry(ctx) { 43 }",
                RhaiCompileError::Parse(rhai::Position::NONE),
            ),
            (
                "fn helper(x) { x } fn helper(x, y) { x } fn entry(ctx) { helper(1) }",
                RhaiCompileError::Entrypoint,
            ),
            (
                "fn entry(ctx) { let value = ; }",
                RhaiCompileError::Parse(rhai::Position::NONE),
            ),
        ] {
            let error =
                compile_entrypoint(&breg_shaped_profile(), source, "entry", &[1]).unwrap_err();
            assert_eq!(
                std::mem::discriminant(&error),
                std::mem::discriminant(&expected),
                "wrong rejection for: {source}"
            );
        }
    }

    #[test]
    fn compile_refuses_sources_over_the_profile_byte_bound() {
        let profile = profile_with(|profile| profile.maximum_source_bytes = 8);
        assert_eq!(
            compile_entrypoint(&profile, "fn entry(ctx) { 42 }", "entry", &[1]).unwrap_err(),
            RhaiCompileError::SourceBound
        );
    }

    #[test]
    fn invocation_skips_top_level_statements_and_shares_no_state() {
        let profile = breg_shaped_profile();
        let source = "top_level_call_that_would_fail();
             fn entry(ctx) { ctx }";
        let engine = build_engine(&profile, None, |_| {});
        let ast = compile_entrypoint(&profile, source, "entry", &[1])
            .expect("top-level statements still parse");
        // eval_ast(false): the failing top-level call never runs.
        assert_eq!(
            call_with_fresh_scope(&engine, &ast, "entry", (Dynamic::from(7i64),))
                .unwrap()
                .cast::<i64>(),
            7
        );
        // A second call through the same engine sees none of the first call's
        // state, only its own arguments.
        assert_eq!(
            call_with_fresh_scope(
                &engine,
                &ast,
                "entry",
                (Dynamic::from("second".to_owned()),)
            )
            .unwrap()
            .clone()
            .cast::<rhai::ImmutableString>()
            .as_str(),
            "second"
        );
    }
}
