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

use rhai::packages::{
    ArithmeticPackage, BasicArrayPackage, BasicBlobPackage, BasicFnPackage, BasicIteratorPackage,
    BasicMapPackage, BasicMathPackage, BasicStringPackage, BitFieldPackage, LogicPackage,
    MoreStringPackage, Package,
};
use rhai::{
    CallFnOptions, Dynamic, Engine, EvalAltResult, FuncArgs, FuncRegistration, ImmutableString,
    NativeCallContext, Scope, AST, INT,
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
/// The choice is product policy. A deadline wired through the progress hook
/// is checked only between operations, so neither base offers a native
/// function that reads the clock, sleeps, or never returns: such a call would
/// outlast the deadline. `Deterministic` is the standard language surface
/// without those functions; `Raw` is the bare engine with no packages, for
/// products that register every callable themselves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RhaiBaseEngine {
    /// `Engine::new_raw()` with every package Rhai's standard engine carries
    /// except two: the language-core package, which ships `sleep` beside
    /// `exit`, `take`, `tag`, `set_tag`, `parse_json`, and
    /// `get_fn_metadata_list`, and the time package (`timestamp`, `elapsed`,
    /// and instant arithmetic). String `pad` with a string is replaced by a
    /// version that refuses an empty padding string, which the package
    /// version pads with forever, and every string `replace` overload by one
    /// that refuses a result over the string bound before building it, where
    /// the package version builds the whole result first. The `curry` keyword
    /// is disabled: Rhai does not count data curried into a function pointer
    /// against the size bounds, and every copy of the pointer copies that
    /// data, so a native call such as array `pad` could multiply it past every
    /// bound inside one call. No module resolver is installed, so every
    /// `import` fails, and no print or debug handler, so output goes nowhere.
    ///
    /// The base has no clock, no sleep, and no ambient input: a script sees
    /// only its arguments and what the product registers, so the same call
    /// gives the same result on the same host. Floating-point transcendental
    /// functions (`sin`, `exp`, `ln`, and the like) use the host's maths
    /// library, so their last digits can differ across platforms.
    Deterministic,
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
    let mut engine = Engine::new_raw();
    if profile.base == RhaiBaseEngine::Deterministic {
        register_deterministic_packages(&mut engine);
        engine.disable_symbol("curry");
    }
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

/// Register the deterministic base's packages in the order Rhai's standard
/// package combines them, so a later package's overload still wins, then the
/// checked string padding and replacement over the package's own.
fn register_deterministic_packages(engine: &mut Engine) {
    ArithmeticPackage::new().register_into_engine(engine);
    BasicStringPackage::new().register_into_engine(engine);
    BasicIteratorPackage::new().register_into_engine(engine);
    BasicFnPackage::new().register_into_engine(engine);
    BitFieldPackage::new().register_into_engine(engine);
    LogicPackage::new().register_into_engine(engine);
    BasicMathPackage::new().register_into_engine(engine);
    BasicArrayPackage::new().register_into_engine(engine);
    BasicBlobPackage::new().register_into_engine(engine);
    BasicMapPackage::new().register_into_engine(engine);
    MoreStringPackage::new().register_into_engine(engine);
    // Functions registered on the engine are found before any package's, by
    // name, function pointer, and method syntax alike. They change their
    // first argument, so they are registered as non-pure, as the package's
    // are, and calling one on a constant is refused.
    FuncRegistration::new("pad")
        .with_purity(false)
        .register_into_engine(engine, pad_with_text);
    FuncRegistration::new("replace")
        .with_purity(false)
        .register_into_engine(engine, replace_text);
    FuncRegistration::new("replace")
        .with_purity(false)
        .register_into_engine(engine, replace_text_with_char);
    FuncRegistration::new("replace")
        .with_purity(false)
        .register_into_engine(engine, replace_char_with_text);
    FuncRegistration::new("replace")
        .with_purity(false)
        .register_into_engine(engine, replace_char);
}

/// `text.pad(length, padding)`: pad `text` with repetitions of `padding` up
/// to `length` characters, as the package does, except that an empty
/// `padding` is refused when padding is needed. The package version never
/// returns in that case, and the deadline cannot interrupt a native call.
fn pad_with_text(
    context: NativeCallContext,
    text: &mut ImmutableString,
    length: INT,
    padding: &str,
) -> Result<(), Box<EvalAltResult>> {
    let Ok(length) = usize::try_from(length) else {
        // A negative length asks for no padding.
        return Ok(());
    };
    let limit = context.engine().max_string_size();
    if limit > 0 && length > limit {
        return Err(EvalAltResult::ErrorDataTooLarge(
            "Length of string".to_owned(),
            context.call_position(),
        )
        .into());
    }
    let missing = length.saturating_sub(text.chars().count());
    if missing == 0 {
        return Ok(());
    }
    if padding.is_empty() {
        return Err(EvalAltResult::ErrorRuntime(
            "pad needs a padding string that is not empty".into(),
            context.call_position(),
        )
        .into());
    }
    let padded = text.make_mut();
    padded.extend(padding.chars().cycle().take(missing));
    if limit > 0 && padded.len() > limit {
        return Err(EvalAltResult::ErrorDataTooLarge(
            "Length of string".to_owned(),
            context.call_position(),
        )
        .into());
    }
    Ok(())
}

/// The byte length of `text.replace(find, with)`, worked out without building
/// it. An empty `find` matches at every character boundary, as it does when
/// replacing.
fn replaced_len(text: &str, find: &str, with: &str) -> usize {
    let matches = text.matches(find).count();
    text.len()
        .saturating_sub(matches.saturating_mul(find.len()))
        .saturating_add(matches.saturating_mul(with.len()))
}

/// Replace every `find` in `text` with `with`, as the package does, once the
/// result is known to fit the string bound. The package version builds the
/// whole result before the engine's size check sees it, and a native call
/// cannot be interrupted, so a script could make it build up to the bound
/// squared.
fn replace_checked(
    context: &NativeCallContext,
    text: &mut ImmutableString,
    find: &str,
    with: &str,
) -> Result<(), Box<EvalAltResult>> {
    // The package leaves an empty string as it is, even for an empty `find`.
    if text.is_empty() {
        return Ok(());
    }
    let limit = context.engine().max_string_size();
    if limit > 0 && replaced_len(text, find, with) > limit {
        return Err(EvalAltResult::ErrorDataTooLarge(
            "Length of string that replace would build".to_owned(),
            context.call_position(),
        )
        .into());
    }
    *text = text.replace(find, with).into();
    Ok(())
}

/// `text.replace(find, with)` with a string for each.
fn replace_text(
    context: NativeCallContext,
    text: &mut ImmutableString,
    find: &str,
    with: &str,
) -> Result<(), Box<EvalAltResult>> {
    replace_checked(&context, text, find, with)
}

/// `text.replace(find, with)` with a string to find and a character for it.
fn replace_text_with_char(
    context: NativeCallContext,
    text: &mut ImmutableString,
    find: &str,
    with: char,
) -> Result<(), Box<EvalAltResult>> {
    replace_checked(&context, text, find, with.encode_utf8(&mut [0; 4]))
}

/// `text.replace(find, with)` with a character to find and a string for it.
fn replace_char_with_text(
    context: NativeCallContext,
    text: &mut ImmutableString,
    find: char,
    with: &str,
) -> Result<(), Box<EvalAltResult>> {
    replace_checked(&context, text, find.encode_utf8(&mut [0; 4]), with)
}

/// `text.replace(find, with)` with a character for each.
fn replace_char(
    context: NativeCallContext,
    text: &mut ImmutableString,
    find: char,
    with: char,
) -> Result<(), Box<EvalAltResult>> {
    replace_checked(
        &context,
        text,
        find.encode_utf8(&mut [0; 4]),
        with.encode_utf8(&mut [0; 4]),
    )
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

/// The parameter names of the public functions named `entrypoint` in a
/// compiled AST, in declaration order. Under [`compile_entrypoint`]'s
/// contract the list holds exactly one function's parameters; a product
/// reads them to hold its entry points to their own signature ABI, which
/// stays with the product.
pub fn entrypoint_parameters<'a>(ast: &'a AST, entrypoint: &str) -> Vec<&'a str> {
    ast.iter_functions()
        .filter(|function| function.access == rhai::FnAccess::Public && function.name == entrypoint)
        .flat_map(|function| function.params)
        .collect()
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
            base: RhaiBaseEngine::Deterministic,
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
    fn the_deterministic_base_refuses_curry_in_every_call_form() {
        let raw = profile_with(|profile| profile.base = RhaiBaseEngine::Raw);
        for source in [
            r#"fn helper(x) { x } fn entry(ctx) { let f = Fn("helper").curry(1); f.call() }"#,
            r#"fn helper(x) { x } fn entry(ctx) { let f = curry(Fn("helper"), 1); f.call() }"#,
        ] {
            assert!(
                matches!(
                    compile_entrypoint(&breg_shaped_profile(), source, "entry", &[1]),
                    Err(RhaiCompileError::Parse(_))
                ),
                "curry accepted in: {source}"
            );
            assert!(
                compile_entrypoint(&raw, source, "entry", &[1]).is_ok(),
                "the Raw base leaves curry to the product: {source}"
            );
        }
        let error = evaluate(
            &breg_shaped_profile(),
            r#"fn entry(ctx) { let f = Fn("curry"); 1 }"#,
            None,
        )
        .expect_err("a function pointer cannot name the curry keyword");
        assert_eq!(classify_failure(&error), RhaiFailureCategory::Other);
    }

    #[test]
    fn checked_string_helpers_refuse_to_change_a_constant() {
        for source in [
            r#"fn entry(ctx) { const TEXT = "abc"; TEXT.pad(5, "x"); TEXT }"#,
            r#"fn entry(ctx) { const TEXT = "abc"; TEXT.replace("a", "z"); TEXT }"#,
            r#"fn entry(ctx) { const TEXT = "abc"; TEXT.replace('a', 'z'); TEXT }"#,
        ] {
            let error = evaluate(&breg_shaped_profile(), source, None)
                .expect_err("a constant cannot be changed by a method call");
            assert!(
                matches!(*error, EvalAltResult::ErrorNonPureMethodCallOnConstant(..)),
                "{source} failed as {error:?}"
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

    /// The parameter reader sees the named public entrypoint's parameters
    /// in declaration order, whatever else the same file defines.
    #[test]
    fn entrypoint_parameters_read_the_public_entrypoints_signature() {
        let ast = compile_entrypoint(
            &breg_shaped_profile(),
            "fn entry(exchange) { exchange } fn helper(paging) { paging }",
            "entry",
            &[1],
        )
        .expect("test source compiles under its profile");
        assert_eq!(entrypoint_parameters(&ast, "entry"), ["exchange"]);
        assert_eq!(entrypoint_parameters(&ast, "helper"), ["paging"]);
        assert!(entrypoint_parameters(&ast, "absent").is_empty());

        let two = compile_entrypoint(
            &breg_shaped_profile(),
            "fn merge(older, newer) { newer }",
            "merge",
            &[2],
        )
        .expect("two-parameter entrypoint compiles");
        assert_eq!(entrypoint_parameters(&two, "merge"), ["older", "newer"]);
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
    fn rhai_maps_use_compact_string_keys_and_owned_unicode_round_trips() {
        let profile = breg_shaped_profile();
        let engine = build_engine(&profile, None, |_| {});
        let ast = compile_entrypoint(
            &profile,
            "fn entry(value) { let result = #{}; result[value] = value; result }",
            "entry",
            &[1],
        )
        .unwrap();
        let owned = String::from("สวัสดี 🌍");

        let result = call_with_fresh_scope(&engine, &ast, "entry", (owned.clone(),))
            .unwrap()
            .cast::<rhai::Map>();
        let (key, value) = result.into_iter().next().unwrap();

        // This names the feature-selected backend deliberately: reverting to
        // Rhai's smartstring default restores its unsafe owned-string path.
        assert_eq!(
            std::any::type_name_of_val(&key),
            "compact_str::CompactString"
        );
        assert_eq!(key.as_str(), owned);
        assert_eq!(value.cast::<rhai::ImmutableString>().as_str(), owned);
    }

    #[test]
    fn raw_base_engine_carries_no_standard_packages() {
        let raw = profile_with(|profile| profile.base = RhaiBaseEngine::Raw);
        // A string method from the standard packages: present on
        // Deterministic, absent on Raw.
        let deterministic_error =
            evaluate(&breg_shaped_profile(), "fn entry(ctx) { ctx.len() }", None)
                .map(|_| ())
                .unwrap_err();
        assert_eq!(
            classify_failure(&deterministic_error),
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
    fn deterministic_base_engine_silences_print_and_debug() {
        // With print and debug left enabled as symbols, their output still
        // goes nowhere: the base installs no output handler, so this test's
        // output stays clean.
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
    fn deterministic_base_engine_refuses_module_imports() {
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

    /// `evaluate` on a thread of its own. A call that has not returned within
    /// a second fails the case instead of hanging the suite.
    fn evaluate_within(
        profile: &RhaiProfile,
        source: &str,
        deadline: Option<Instant>,
    ) -> Result<Dynamic, Box<EvalAltResult>> {
        let (sender, receiver) = std::sync::mpsc::channel();
        let profile = *profile;
        let owned = source.to_owned();
        std::thread::spawn(move || {
            sender
                .send(evaluate(&profile, &owned, deadline))
                .expect("the watchdog is still waiting for this call");
        });
        receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap_or_else(|_| panic!("the call did not return within a second: {source}"))
    }

    fn function_names(engine: &Engine) -> BTreeSet<String> {
        engine
            .collect_fn_metadata(None, |info| Some(info.metadata.name.to_string()), true)
            .into_iter()
            .collect()
    }

    /// Exactly what the deterministic base leaves out of Rhai's standard
    /// engine: the language-core package, which carries `sleep`, and the time
    /// package. Instant arithmetic and comparison go with the time package
    /// too; their operator names stay, overloaded for other types, except
    /// `-=`, which no other package registers.
    #[test]
    fn deterministic_base_engine_leaves_out_the_language_core_and_time_packages() {
        let standard = function_names(&Engine::new());
        let deterministic = function_names(&build_engine(&breg_shaped_profile(), None, |_| {}));
        assert_eq!(
            standard
                .difference(&deterministic)
                .map(String::as_str)
                .collect::<Vec<_>>(),
            [
                "-=",
                "elapsed",
                "exit",
                "get$elapsed",
                "get$tag",
                "get_fn_metadata_list",
                "parse_json",
                "set$tag",
                "set_tag",
                "sleep",
                "tag",
                "take",
                "timestamp",
            ]
        );
        assert!(
            deterministic.is_subset(&standard),
            "the base adds no function name: {:?}",
            deterministic.difference(&standard).collect::<Vec<_>>()
        );
    }

    /// The deadline is checked between operations, so a call that reads the
    /// clock or sleeps is refused as absent by name, by function pointer, and
    /// by method syntax alike.
    #[test]
    fn deterministic_base_engine_refuses_the_clock_and_sleep_by_every_call_form() {
        let deadline = Some(Instant::now() + std::time::Duration::from_secs(5));
        for (function, source) in [
            ("timestamp", "fn entry(ctx) { timestamp() }"),
            ("timestamp", r#"fn entry(ctx) { Fn("timestamp").call() }"#),
            ("timestamp", r#"fn entry(ctx) { call(Fn("timestamp")) }"#),
            ("sleep", "fn entry(ctx) { sleep(2); 1 }"),
            ("sleep", "fn entry(ctx) { sleep(2.0); 1 }"),
            (
                "sleep",
                "fn entry(ctx) { let seconds = 2; seconds.sleep(); 1 }",
            ),
            ("sleep", r#"fn entry(ctx) { Fn("sleep").call(2); 1 }"#),
            (
                "sleep",
                r#"fn entry(ctx) { let seconds = 2.0; seconds.call(Fn("sleep")); 1 }"#,
            ),
        ] {
            match evaluate_within(&breg_shaped_profile(), source, deadline) {
                Err(error)
                    if matches!(
                        &*error,
                        EvalAltResult::ErrorFunctionNotFound(signature, _)
                            if signature.starts_with(&format!("{function} ("))
                    ) => {}
                other => panic!("expected {function} to be absent, got {other:?}: {source}"),
            }
        }
    }

    /// String padding with a string pads exactly as the package does
    /// whenever that terminates, and refuses the empty padding string the
    /// package would loop on without end, by every call form. Character
    /// padding is the package's own.
    #[test]
    fn deterministic_base_engine_pads_like_the_package_and_refuses_empty_padding() {
        for (source, expected) in [
            (
                r#"fn entry(ctx) { let text = "a"; text.pad(5, "xy"); text }"#,
                "axyxy",
            ),
            (
                r#"fn entry(ctx) { let text = "a"; text.pad(4, "xy"); text }"#,
                "axyx",
            ),
            (
                r#"fn entry(ctx) { let text = "é"; text.pad(3, "ü"); text }"#,
                "éüü",
            ),
            (
                r#"fn entry(ctx) { let text = "a"; pad(text, 3, "-"); text }"#,
                "a--",
            ),
            (
                r#"fn entry(ctx) { let text = "a"; text.pad(3, 'z'); text }"#,
                "azz",
            ),
            (
                r#"fn entry(ctx) { let text = "abc"; text.pad(2, ""); text }"#,
                "abc",
            ),
            (
                r#"fn entry(ctx) { let text = "abc"; text.pad(-1, ""); text }"#,
                "abc",
            ),
        ] {
            let value = evaluate_within(&breg_shaped_profile(), source, None)
                .unwrap_or_else(|error| panic!("{source}: {error:?}"));
            assert_eq!(
                value.cast::<rhai::ImmutableString>().as_str(),
                expected,
                "{source}"
            );
        }
        for source in [
            r#"fn entry(ctx) { let text = "a"; text.pad(5, ""); text }"#,
            r#"fn entry(ctx) { let text = "a"; pad(text, 5, ""); text }"#,
            r#"fn entry(ctx) { let text = "a"; Fn("pad").call(text, 5, ""); text }"#,
            r#"fn entry(ctx) { let text = "a"; text.call(Fn("pad"), 5, ""); text }"#,
        ] {
            let error = evaluate_within(&breg_shaped_profile(), source, None)
                .map(|_| ())
                .unwrap_err();
            assert_eq!(
                classify_failure(&error),
                RhaiFailureCategory::Other,
                "{source}: {error:?}"
            );
        }
        let narrow = profile_with(|profile| profile.limits.string_bytes = 8);
        for source in [
            // More characters than the string bound, refused before padding.
            r#"fn entry(ctx) { let text = "a"; text.pad(9, "xy"); text }"#,
            // Within the bound in characters, over it in bytes.
            r#"fn entry(ctx) { let text = "a"; text.pad(8, "ü"); text }"#,
        ] {
            let error = evaluate_within(&narrow, source, None)
                .map(|_| ())
                .unwrap_err();
            assert!(
                matches!(*error, EvalAltResult::ErrorDataTooLarge(..)),
                "{source}: {error:?}"
            );
        }
    }

    /// String `replace` replaces exactly as the package does within the
    /// string bound. Past it, each overload the package registers works out
    /// the size of its result and refuses before building it, by every call
    /// form; the package version builds the whole result first, up to the
    /// bound squared, and only then meets the engine's size check.
    #[test]
    fn deterministic_base_engine_bounds_replace_before_it_builds_the_result() {
        for (source, expected) in [
            (
                r#"fn entry(ctx) { let text = "a-b-a"; text.replace("a", "xy"); text }"#,
                "xy-b-xy",
            ),
            (
                r#"fn entry(ctx) { let text = "a-b-a"; text.replace("a", 'z'); text }"#,
                "z-b-z",
            ),
            (
                r#"fn entry(ctx) { let text = "a-b-a"; text.replace('a', "xy"); text }"#,
                "xy-b-xy",
            ),
            (
                r#"fn entry(ctx) { let text = "a-b-a"; text.replace('a', 'é'); text }"#,
                "é-b-é",
            ),
            (
                r#"fn entry(ctx) { let text = "aaa"; text.replace("aa", "b"); text }"#,
                "ba",
            ),
            (
                r#"fn entry(ctx) { let text = "ab"; text.replace("", "-"); text }"#,
                "-a-b-",
            ),
            (
                r#"fn entry(ctx) { let text = ""; text.replace("", "x"); text }"#,
                "",
            ),
            (
                r#"fn entry(ctx) { let text = "a"; replace(text, "a", "b"); text }"#,
                "b",
            ),
        ] {
            let value = evaluate_within(&breg_shaped_profile(), source, None)
                .unwrap_or_else(|error| panic!("{source}: {error:?}"));
            assert_eq!(
                value.cast::<rhai::ImmutableString>().as_str(),
                expected,
                "{source}"
            );
        }

        let narrow = profile_with(|profile| profile.limits.string_bytes = 8);
        let at_bound = r#"fn entry(ctx) { let text = "aaaa"; text.replace("a", "bb"); text }"#;
        let value = evaluate_within(&narrow, at_bound, None).unwrap();
        assert_eq!(value.cast::<rhai::ImmutableString>().as_str(), "bbbbbbbb");

        // Five one-byte characters, each replaced by two bytes: ten bytes.
        let refused =
            |profile: &RhaiProfile, source: &str| match evaluate_within(profile, source, None) {
                Err(error)
                    if matches!(
                        &*error,
                        EvalAltResult::ErrorDataTooLarge(what, _)
                            if what == "Length of string that replace would build"
                    ) => {}
                other => {
                    panic!("expected replace to refuse before building, got {other:?}: {source}")
                }
            };
        for source in [
            r#"fn entry(ctx) { let text = "aaaaa"; text.replace("a", "bb"); text }"#,
            r#"fn entry(ctx) { let text = "aaaaa"; text.replace("a", 'ü'); text }"#,
            r#"fn entry(ctx) { let text = "aaaaa"; text.replace('a', "bb"); text }"#,
            r#"fn entry(ctx) { let text = "aaaaa"; text.replace('a', 'ü'); text }"#,
            r#"fn entry(ctx) { let text = "aaaaa"; replace(text, "a", "bb"); text }"#,
            r#"fn entry(ctx) { let text = "aaaaa"; Fn("replace").call(text, "a", "bb"); text }"#,
            r#"fn entry(ctx) { let text = "aaaaa"; call(Fn("replace"), text, 'a', 'ü'); text }"#,
            r#"fn entry(ctx) { let text = "aaaaa"; text.call(Fn("replace"), "a", 'ü'); text }"#,
        ] {
            refused(&narrow, source);
        }
        // At the BReg-shaped bound, a string replaced by itself would build
        // 16384 squared bytes.
        refused(
            &breg_shaped_profile(),
            r#"fn entry(ctx) { let text = "a"; text.pad(16384, "a"); text.replace("a", text); text }"#,
        );
    }

    /// Every other standard package stays: arithmetic, logic, bit fields,
    /// math, strings, iterators, function pointers, arrays, BLOBs, and maps.
    #[test]
    fn deterministic_base_engine_keeps_the_rest_of_the_standard_surface() {
        let source = r#"
            fn double(x) { x * 2 }
            fn entry(ctx) {
                let items = [3, 1, 2];
                items.sort();
                let total = 0;
                for i in range(0, 4) { total += i; }
                let padded = "x";
                padded.pad(3, "-");
                let words = "  Ab,cd ";
                words.trim();
                [
                    items.map(Fn("double")),
                    words.to_upper().split(","),
                    #{b: 1, a: 2}.keys(),
                    max(4, 7),
                    0b1010.get_bit(1),
                    sqrt(16.0).to_int(),
                    parse_int("42"),
                    blob(3, 0x2a).len(),
                    total,
                    padded,
                ]
            }"#;
        let value = evaluate_within(&breg_shaped_profile(), source, None).unwrap();
        assert_eq!(
            format!("{value:?}"),
            r#"[[2, 4, 6], ["AB", "CD"], ["a", "b"], 7, true, 4, 42, 3, 6, "x--"]"#
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
