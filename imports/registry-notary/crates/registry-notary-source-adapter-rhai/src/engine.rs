// SPDX-License-Identifier: Apache-2.0
//! The sandboxed script engine: policy, limits, compilation, and hardening.
//!
//! [`ScriptEngine::compile`] turns a source string + entrypoint name into a
//! compiled, ready-to-run unit, validating up front that the engine accepts the
//! configured limits and that the named entrypoint exists. The hardening
//! applied here is the security baseline every execution inherits:
//! * all Rhai resource limits set from [`RhaiLimits`];
//! * module loading disabled (`set_max_modules(0)`);
//! * `eval` disabled so scripts cannot construct code at runtime;
//! * `print`/`debug` routed to no-ops so scripts cannot emit;
//! * the `xw` pure-helper module tree registered.
//!
//! The per-execution capability (`source.get`) and the termination callback are
//! applied later, in the bridge, because they depend on per-run state.

use std::sync::Arc;
use std::time::Duration;

use rhai::{Engine, AST};
use tokio::sync::Semaphore;

use crate::counters::ExecCounters;
use crate::error::SourceScriptError;

/// Resource limits applied to the Rhai engine (the sandbox axes).
#[derive(Debug, Clone, Copy)]
pub struct RhaiLimits {
    /// Maximum number of operations (the instruction budget). Bounds runaway
    /// loops. `0` would mean unlimited and is intentionally never the default.
    pub max_operations: u64,
    /// Maximum function call nesting depth. Bounds infinite recursion.
    pub max_call_levels: usize,
    /// Maximum size, in bytes, of any single string.
    pub max_string_bytes: usize,
    /// Maximum number of items in any single array.
    pub max_array_items: usize,
    /// Maximum number of entries in any single map.
    pub max_map_entries: usize,
    /// Maximum number of modules that may be loaded. Always `0`: no loading.
    pub max_modules: usize,
}

impl Default for RhaiLimits {
    fn default() -> Self {
        Self {
            max_operations: 1_000_000,
            max_call_levels: 32,
            max_string_bytes: 64 * 1024,
            max_array_items: 4_096,
            max_map_entries: 4_096,
            max_modules: 0,
        }
    }
}

/// The complete execution policy: resource limits plus host-enforced budgets.
#[derive(Debug, Clone, Copy)]
pub struct RhaiPolicy {
    /// Rhai engine resource limits.
    pub limits: RhaiLimits,
    /// Wall-clock execution budget for a single run.
    pub timeout: Duration,
    /// Maximum number of `source.get` calls a single run may dispatch.
    pub max_http_calls: u32,
    /// Maximum size, in bytes, of the serialized script output.
    pub max_output_bytes: usize,
    /// Maximum number of concurrent executions admitted (the dedicated permit
    /// pool size). Bounds OS-thread usage independently of the shared blocking
    /// pool.
    pub max_concurrent: usize,
}

impl Default for RhaiPolicy {
    fn default() -> Self {
        Self {
            limits: RhaiLimits::default(),
            timeout: Duration::from_millis(2_000),
            max_http_calls: 8,
            max_output_bytes: 256 * 1024,
            max_concurrent: 8,
        }
    }
}

/// A compiled, hardened, ready-to-execute script unit.
///
/// Holds the compiled AST, the verified entrypoint name, the policy, and the
/// shared `xw` helper module. Each execution builds a fresh hardened engine
/// from these (cheap: the AST and the `xw` module are shared), then layers on
/// the per-run capability and termination callback.
pub struct ScriptEngine {
    pub(crate) ast: AST,
    pub(crate) entrypoint: String,
    pub(crate) policy: RhaiPolicy,
    /// Dedicated admission pool (size = `policy.max_concurrent`). Bounds the
    /// number of concurrent blocking executions independently of tokio's
    /// shared blocking pool.
    pub(crate) semaphore: Arc<Semaphore>,
    /// Outcome counters shared across executions of this unit.
    pub(crate) counters: ExecCounters,
}

impl ScriptEngine {
    /// Compile `source` and verify that `entrypoint` exists.
    ///
    /// Returns [`SourceScriptError::Compile`] on a syntax error and
    /// [`SourceScriptError::Entrypoint`] if the named function is absent.
    pub fn compile(
        source: &str,
        entrypoint: &str,
        policy: &RhaiPolicy,
    ) -> Result<Self, SourceScriptError> {
        // Build a hardened engine purely to compile + introspect. The same
        // hardening is re-applied per execution in the bridge.
        let mut engine = Engine::new();
        apply_hardening(&mut engine, &policy.limits);

        let ast = engine
            .compile(source)
            .map_err(|e| SourceScriptError::Compile {
                reason: compile_reason(&e),
            })?;

        // Verify the named entrypoint exists among the script's functions.
        let exists = ast
            .iter_functions()
            .any(|f| f.name == entrypoint && f.params.len() == 1);
        if !exists {
            return Err(SourceScriptError::Entrypoint {
                entrypoint: entrypoint.to_string(),
            });
        }

        // A `max_concurrent` of 0 would deadlock every execution; treat it as 1.
        let permits = policy.max_concurrent.max(1);

        Ok(Self {
            ast,
            entrypoint: entrypoint.to_string(),
            policy: *policy,
            semaphore: Arc::new(Semaphore::new(permits)),
            counters: ExecCounters::new(),
        })
    }

    /// The execution policy this unit was compiled with.
    pub fn policy(&self) -> &RhaiPolicy {
        &self.policy
    }

    /// The verified entrypoint name.
    pub fn entrypoint(&self) -> &str {
        &self.entrypoint
    }

    /// The outcome counters accumulated across executions of this unit.
    pub fn counters(&self) -> &ExecCounters {
        &self.counters
    }
}

/// Apply the security baseline to a fresh engine.
///
/// This is the single place the hardening rules live; both compilation and
/// execution call it so they cannot drift apart.
///
/// The engine is built with [`Engine::new`], which loads only Rhai's standard
/// (pure, non-IO) package set — no filesystem, process, or networking packages.
/// This is intentional: the sandbox's sole effect is the host `source.get`
/// capability, so the engine must never gain ambient IO. Do not switch to a
/// package set that adds IO; the `xw.*` helpers are the only additional surface.
pub(crate) fn apply_hardening(engine: &mut Engine, limits: &RhaiLimits) {
    // --- resource limits (sandbox axes) ---
    engine.set_max_operations(limits.max_operations);
    engine.set_max_call_levels(limits.max_call_levels);
    engine.set_max_string_size(limits.max_string_bytes);
    engine.set_max_array_size(limits.max_array_items);
    engine.set_max_map_size(limits.max_map_entries);
    engine.set_max_modules(limits.max_modules);

    // --- no runtime code construction ---
    engine.disable_symbol("eval");

    // --- scripts cannot emit anything ---
    engine.on_print(|_| {});
    engine.on_debug(|_, _, _| {});

    // --- pure helper namespace, dotted access: xw.text.*, xw.date.*, ... ---
    crate::xw::register(engine);
}

/// Produce a short, non-sensitive compile reason. We avoid echoing the script
/// source; Rhai's parse error already excludes the full source but may include
/// a token, which is acceptable low-cardinality detail.
fn compile_reason(err: &rhai::ParseError) -> String {
    // ParseError Display is concise (error kind + position), no full source.
    err.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Extract the error without requiring `Debug` on `ScriptEngine` (the Ok
    /// type), which would otherwise be needed by `Result::unwrap_err`.
    fn err_of(r: Result<ScriptEngine, SourceScriptError>) -> SourceScriptError {
        match r {
            Ok(_) => panic!("expected an error"),
            Err(e) => e,
        }
    }

    #[test]
    fn compiles_and_finds_entrypoint() {
        let eng = ScriptEngine::compile(
            r#"fn lookup(ctx) { [#{ ok: true }] }"#,
            "lookup",
            &RhaiPolicy::default(),
        )
        .unwrap();
        assert_eq!(eng.entrypoint(), "lookup");
    }

    #[test]
    fn missing_entrypoint_is_an_error() {
        let e = err_of(ScriptEngine::compile(
            r#"fn other(ctx) { [] }"#,
            "lookup",
            &RhaiPolicy::default(),
        ));
        assert!(matches!(e, SourceScriptError::Entrypoint { .. }));
    }

    #[test]
    fn entrypoint_must_take_one_param() {
        // `lookup` with the wrong arity does not satisfy the entrypoint contract.
        let e = err_of(ScriptEngine::compile(
            r#"fn lookup() { [] }"#,
            "lookup",
            &RhaiPolicy::default(),
        ));
        assert!(matches!(e, SourceScriptError::Entrypoint { .. }));
    }

    #[test]
    fn syntax_error_is_compile_error() {
        let e = err_of(ScriptEngine::compile(
            r#"fn lookup(ctx) { let x = ; }"#,
            "lookup",
            &RhaiPolicy::default(),
        ));
        assert!(matches!(e, SourceScriptError::Compile { .. }));
    }

    #[test]
    fn eval_is_disabled_at_compile() {
        // `disable_symbol("eval")` makes `eval(...)` a parse error.
        let e = err_of(ScriptEngine::compile(
            r#"fn lookup(ctx) { eval("1+1") }"#,
            "lookup",
            &RhaiPolicy::default(),
        ));
        assert!(matches!(e, SourceScriptError::Compile { .. }));
    }
}
