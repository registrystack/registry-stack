// SPDX-License-Identifier: Apache-2.0

//! Authored WASM action-handler admission.
//!
//! A WASM handler declares a project-local module path instead of a Rhai
//! script path. This module owns the authored-path discipline, the module
//! byte ceilings, and (in a build with the non-default `wasm` feature)
//! compile-time structural validation against the platform guest ABI, so a
//! package either carries a module the runtime could prepare, or the compiler
//! refuses it with a diagnostic naming the violation. Admission never
//! executes a guest; execution belongs to the process runtime in
//! `wasm_runtime`.

/// Structural byte ceiling for one authored WASM handler module.
///
/// This is the ceiling enforced wherever no operator configuration exists:
/// the compiler admission and the package closure. A deployment whose
/// operator raises the execution ceiling may load modules up to this size;
/// it can never admit anything the authoring admission refused.
pub const MAXIMUM_WASM_MODULE_BYTES: usize = 5 * 1024 * 1024;

/// Default byte ceiling for one WASM handler module at execution time: the
/// value both the runtime configuration section and the process executor
/// budgets start from when the operator configures nothing. Ordinary handler
/// modules compile well under it.
pub const DEFAULT_WASM_MODULE_BYTES: usize = 2 * 1024 * 1024;

/// Ceiling on WASM handler modules carried by one package.
pub const MAX_PACKAGE_WASM_MODULES: usize = 16;

/// Default byte ceiling for guest memory growth during one handler call.
/// Operator configuration may raise or lower it; this is the default both the
/// runtime configuration section and the process executor budgets start from.
pub const DEFAULT_WASM_GUEST_MEMORY_BYTES: usize = 32 * 1024 * 1024;

/// The execution backend a deployment compiles WASM handler modules for:
/// the value both the runtime configuration section and every
/// backend-resolving path start from when the operator configures nothing.
/// Pulley, the portable interpreter target, is the default because it holds
/// the deterministic, executable-memory-free execution envelope every
/// deployment can run; `native` opts a deployment into host machine code.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum WasmExecutionBackend {
    /// Cranelift lowering to Pulley bytecode, executed by the interpreter.
    #[default]
    Pulley,
    /// Cranelift lowering to host machine code.
    Native,
}

impl WasmExecutionBackend {
    /// The configured spelling of this backend (`pulley`, `native`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pulley => "pulley",
            Self::Native => "native",
        }
    }

    /// Parse the configured spelling; every other value is refused by the
    /// configuration loader as an invalid `wasmExecution` section. Compiled
    /// under the `runtime` feature, the only build whose configuration
    /// loader reads the section.
    #[cfg(feature = "runtime")]
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "pulley" => Some(Self::Pulley),
            "native" => Some(Self::Native),
            _ => None,
        }
    }
}

/// Resolve the configured execution backend onto the platform executor
/// backend. One resolution serves admission validation (under the default,
/// see `structural_violation`) and runtime execution (under the configured
/// value), so a module is never validated under one engine and executed
/// under another by configuration drift.
#[cfg(feature = "wasm")]
pub(crate) fn execution_backend(
    configured: WasmExecutionBackend,
) -> registry_platform_script::wasm::Backend {
    match configured {
        WasmExecutionBackend::Pulley => registry_platform_script::wasm::Backend::Pulley,
        WasmExecutionBackend::Native => registry_platform_script::wasm::Backend::Native,
    }
}

/// Ceiling on the authored WASM module path, matching the planner script
/// path ceiling the package source-file policy already enforces.
pub const MAXIMUM_WASM_MODULE_PATH_BYTES: usize = 256;

/// The WebAssembly binary format magic prefix. Authored modules are binaries;
/// WebAssembly text is not admitted.
const WASM_BINARY_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6D];

/// The authored-path discipline a WASM handler's module must satisfy, checked
/// only in a build that can admit WASM handlers.
#[cfg(feature = "wasm")]
pub(crate) fn valid_wasm_module_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAXIMUM_WASM_MODULE_PATH_BYTES
        && path.ends_with(".wasm")
        && !path.starts_with('/')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

/// Reject non-binary module bytes before any engine work. Admitting text that
/// happens to parse is an accident of the engine's text support, not a
/// contract.
pub(crate) fn is_wasm_binary(bytes: &[u8]) -> bool {
    bytes.starts_with(&WASM_BINARY_MAGIC)
}

/// Structurally validate a module against the platform guest byte ABI: zero
/// imports, the exact export set with wasm32 signatures, optional `init`,
/// tolerated `__data_end`/`__heap_base`.
///
/// Returns the diagnostic code and message for the first violation; the
/// caller owns the diagnostic path. Runs only in a build with the
/// `wasm` feature, the only build whose compiler can validate
/// modules; the default build refuses WASM handlers at admission instead.
#[cfg(feature = "wasm")]
pub(crate) fn structural_violation(bytes: &[u8]) -> Option<(&'static str, String)> {
    use registry_platform_script::wasm::{Budgets, Executor};

    // The same engine configuration the runtime's prepare path uses, with
    // the structural module ceiling: authoring validates anything an
    // operator could configure, and the configured ceiling is enforced again
    // when the module is loaded into the runtime. Threads, relaxed SIMD, and
    // memory64 off; NaN canonicalization on.
    //
    // LIMITATION: pure authoring compilation has no operator configuration
    // in scope, so admission validates under the same default backend the
    // configuration section resolves to when the operator configures
    // nothing; the runtime executes under the resolved configured value.
    // The ABI check is target-independent, so admission cannot accept a
    // module the configured backend rejects (or refuse one it accepts); only
    // the engine the validation compile targets can differ from execution's.
    let budgets = Budgets {
        max_module_bytes: MAXIMUM_WASM_MODULE_BYTES,
        ..Budgets::default()
    };
    let executor = match Executor::new(execution_backend(WasmExecutionBackend::default()), budgets)
    {
        Ok(executor) => executor,
        Err(error) => return Some(admission_violation(error)),
    };
    executor.prepare(bytes).err().map(admission_violation)
}

/// Map an executor refusal to its admission diagnostic code and message. An
/// engine-setup failure is a build fault, typed with the same execution
/// class the runtime's prepare and invoke paths use, never as a module
/// fault: the module bytes did not cause it.
#[cfg(feature = "wasm")]
pub(crate) fn admission_violation(
    error: registry_platform_script::wasm::InvokeError,
) -> (&'static str, String) {
    use registry_platform_script::wasm::InvokeError;

    match error {
        InvokeError::ModuleTooLarge { size, max } => (
            "action.handler.module_bound",
            format!("the handler module is {size} bytes; the ceiling is {max} bytes"),
        ),
        InvokeError::UnsupportedImport { .. } => (
            "action.handler.module_import_unsupported",
            error.to_string(),
        ),
        InvokeError::MissingExport { .. } => {
            ("action.handler.module_export_missing", error.to_string())
        }
        InvokeError::ExportTypeMismatch { .. } => {
            ("action.handler.module_export_type", error.to_string())
        }
        InvokeError::UnexpectedExport { .. } => {
            ("action.handler.module_export_unexpected", error.to_string())
        }
        InvokeError::InvalidModule { .. } => (
            "action.handler.module_invalid",
            format!("the handler module is not a valid WebAssembly binary: {error}"),
        ),
        InvokeError::EngineSetup { .. } => (
            "action.handler.execution",
            format!("this build cannot validate WASM handler modules: {error}"),
        ),
        error => (
            "action.handler.module_invalid",
            format!("the handler module was rejected: {error}"),
        ),
    }
}
