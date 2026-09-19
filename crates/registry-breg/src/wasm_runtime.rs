// SPDX-License-Identifier: Apache-2.0

//! Process-wide WASM handler execution (`wasm` feature).
//!
//! One platform [`Executor`] (one engine) and one [`EpochTicker`] serve the
//! whole server process, and a bounded cache keeps prepared modules so the
//! first use of a module identity pays compilation and later uses do not.
//! The evaluation entry points are free functions over owned compiled
//! declarations (see `mutation::action`), so the runtime is installed once at
//! server startup from the operator configuration; evaluation before that
//! install is refused rather than silently served on default budgets, and
//! replacing or clearing the runtime stops the old ticker when the last
//! evaluation holding it finishes.
//!
//! Semantics shared with the Rhai path are not re-decided here: the request
//! envelope is the same inputs document the Rhai context receives, and the
//! outcome bytes flow through the same decode layer and the same shared
//! validator (`action_outcome`), so authorization, write ceilings, receipt
//! semantics, and audit content are identical by construction.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Instant;

use registry_platform_script::wasm::{
    Backend, Budgets, EpochTicker, Executor, InvokeError, PreparedModule, TickerSpawnError,
    DEFAULT_INTERVAL,
};
use serde_json::{Map as JsonMap, Value};

use crate::action_handler::{ActionHandlerDiagnostic, ActionHandlerError, ActionHandlerOutcome};
use crate::model::{CompiledAction, CompiledActionHandler};

/// Named bound on prepared modules retained by one process. A package
/// carries at most `wasm_handler::MAX_PACKAGE_WASM_MODULES` modules, so this
/// bounds cross-package reuse, not correctness: an evicted entry only costs
/// a recompile on its next use.
pub(crate) const MAXIMUM_RETAINED_PREPARED_MODULES: usize = 32;

/// Fuel granted to one guest call. Constant this stage: only the module and
/// guest-memory ceilings are operator configuration.
const WASM_FUEL_PER_CALL: u64 = 10_000_000_000;

/// Outcome-byte ceiling for one guest call, rejected before any allocation
/// or copy. Constant this stage.
const WASM_MAXIMUM_OUTCOME_BYTES: usize = 1024 * 1024;

/// Request-byte ceiling for one guest call. Admission bounds the inputs
/// document by the action's snapshot ceiling, and the request envelope only
/// wraps that document, so the ceiling is the snapshot ceiling plus wrapper
/// margin: a request must never be refused for a document admission accepted.
const WASM_MAXIMUM_REQUEST_BYTES: usize =
    crate::change_request::MAX_CHANGE_REQUEST_SNAPSHOT_BYTES as usize + 1024;

/// The epoch-deadline tick cap. Deadlines are seconds in practice; the cap
/// keeps the engine's tick arithmetic honest if a caller ever passes a
/// far-future deadline. Fuel still bounds every call regardless.
const MAXIMUM_EPOCH_DEADLINE_TICKS: u64 = u32::MAX as u64;

/// The operator-configurable execution budgets. Defaults mirror the default
/// execution-time module ceiling and the platform guest-memory default; a
/// build that changes either default changes them in lockstep (pinned by
/// tests beside this module).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WasmExecutionBudgets {
    /// Byte ceiling for one handler module, checked again at prepare time.
    pub max_module_bytes: usize,
    /// Byte ceiling for guest memory growth during one call.
    pub max_guest_memory_bytes: usize,
}

impl WasmExecutionBudgets {
    pub(crate) const DEFAULT_MAX_MODULE_BYTES: usize =
        crate::wasm_handler::DEFAULT_WASM_MODULE_BYTES;
    pub(crate) const DEFAULT_MAX_GUEST_MEMORY_BYTES: usize =
        crate::wasm_handler::DEFAULT_WASM_GUEST_MEMORY_BYTES;
}

impl Default for WasmExecutionBudgets {
    fn default() -> Self {
        Self {
            max_module_bytes: Self::DEFAULT_MAX_MODULE_BYTES,
            max_guest_memory_bytes: Self::DEFAULT_MAX_GUEST_MEMORY_BYTES,
        }
    }
}

/// The operator configuration section maps straight onto the execution
/// budgets; the server startup path installs the configured values and every
/// other process uses the defaults.
#[cfg(feature = "runtime")]
impl From<crate::runtime_config::WasmExecutionConfig> for WasmExecutionBudgets {
    fn from(config: crate::runtime_config::WasmExecutionConfig) -> Self {
        Self {
            max_module_bytes: config.max_module_bytes() as usize,
            max_guest_memory_bytes: config.max_guest_memory_bytes() as usize,
        }
    }
}

/// Why the process runtime could not start: the engine rejected its
/// configuration, the epoch ticker's thread could not be spawned, or another
/// lifecycle already owns the process executor. Every case refuses installation
/// rather than weakening execution bounds or replacing an active lifecycle.
#[derive(Debug)]
pub enum WasmRuntimeStartError {
    EngineSetup(InvokeError),
    Ticker(TickerSpawnError),
    LifecycleActive,
}

/// One engine, one ticker, and the bounded prepared-module cache.
pub(crate) struct WasmHandlerRuntime {
    executor: Executor,
    ticker: EpochTicker,
    retained_modules: usize,
    cache: Mutex<ModuleCache>,
}

impl Drop for WasmHandlerRuntime {
    fn drop(&mut self) {
        // Stop the ticker eagerly rather than waiting for its own Drop, so a
        // replaced or cleared runtime ends its background thread at the last
        // reference even if the ticker type later outlives it another way.
        self.ticker.stop();
    }
}

struct ModuleCache {
    /// Most-recently-used first; the tail is evicted at the retained bound.
    /// The key is the module content hash paired with the backend the module
    /// was compiled for.
    entries: Vec<((String, Backend), Arc<PreparedModule>)>,
    /// Compilations performed through this cache; test-observable.
    preparations: u64,
}

impl WasmHandlerRuntime {
    /// Build the executor for `backend`, start its epoch ticker, and start
    /// with an empty cache retaining at most `retained_modules` prepared
    /// modules. A ticker that cannot start is a start failure: the runtime is
    /// not built with permanently inert deadlines.
    pub(crate) fn new(
        budgets: WasmExecutionBudgets,
        backend: Backend,
        retained_modules: usize,
    ) -> Result<Self, WasmRuntimeStartError> {
        let budgets = Budgets {
            max_module_bytes: budgets.max_module_bytes,
            max_guest_memory_bytes: budgets.max_guest_memory_bytes,
            fuel: WASM_FUEL_PER_CALL,
            max_input_bytes: WASM_MAXIMUM_REQUEST_BYTES,
            max_output_bytes: WASM_MAXIMUM_OUTCOME_BYTES,
            ..Budgets::default()
        };
        let executor =
            Executor::new(backend, budgets).map_err(WasmRuntimeStartError::EngineSetup)?;
        let ticker = EpochTicker::spawn(executor.engine().clone(), DEFAULT_INTERVAL)
            .map_err(WasmRuntimeStartError::Ticker)?;
        Ok(Self {
            executor,
            ticker,
            retained_modules: retained_modules.max(1),
            cache: Mutex::new(ModuleCache {
                entries: Vec::new(),
                preparations: 0,
            }),
        })
    }

    /// Compilations performed through this cache so far.
    #[cfg(test)]
    pub(crate) fn preparation_count(&self) -> u64 {
        self.cache
            .lock()
            .expect("wasm module cache lock")
            .preparations
    }

    /// Resolve the handler's prepared module, compiling it on first use.
    ///
    /// Identity is the module's content hash paired with the executor's
    /// backend: a prepared module is immutable, content-addressed, and
    /// compiled for exactly one engine target, so identical bytes under one
    /// backend share one preparation and a backend change re-prepares rather
    /// than cross-serving a module compiled for the other engine. Budgets
    /// are fixed at runtime construction, so a configuration change replaces
    /// the runtime and its cache together.
    fn prepared_module(
        &self,
        handler: &CompiledActionHandler,
    ) -> Result<Arc<PreparedModule>, ActionHandlerDiagnostic> {
        let module_sha256 = handler.module_sha256.as_deref().ok_or_else(|| {
            ActionHandlerDiagnostic::new(
                ActionHandlerError::Source,
                "A compiled WASM handler carries its module content hash.",
            )
        })?;
        self.prepared_module_for(module_sha256, &handler.module_bytes)
            .map_err(classify_prepare_error)
    }

    /// Resolve a prepared module by content identity, compiling it on first
    /// use. Shared by the action handler path and the hook handler path: both
    /// address a module by its content hash, and a prepared module is
    /// immutable, so one cache serves both without either learning the
    /// other's error vocabulary.
    fn prepared_module_for(
        &self,
        module_sha256: &str,
        module_bytes: &[u8],
    ) -> Result<Arc<PreparedModule>, InvokeError> {
        let identity = (module_sha256.to_owned(), self.executor.backend());
        let mut cache = self.cache.lock().expect("wasm module cache lock");
        if let Some(position) = cache.entries.iter().position(|(key, _)| *key == identity) {
            // Move-to-front keeps the eviction order least-recently-used.
            let prepared = cache.entries.remove(position);
            cache.entries.insert(0, prepared.clone());
            return Ok(prepared.1);
        }
        let prepared = Arc::new(self.executor.prepare(module_bytes)?);
        cache.preparations += 1;
        cache.entries.insert(0, (identity, prepared.clone()));
        cache
            .entries
            .truncate(MAXIMUM_RETAINED_PREPARED_MODULES.min(self.retained_modules));
        Ok(prepared)
    }
}

/// The process runtime. Server startup installs the configured runtime
/// before serving; an evaluation that arrives before any install is refused
/// rather than silently served on default budgets.
static RUNTIME: RwLock<Option<Arc<WasmHandlerRuntime>>> = RwLock::new(None);
static RUNTIME_OWNED: AtomicBool = AtomicBool::new(false);

/// Ownership of one configured process runtime installation.
///
/// Configured ownership is exclusive. The guard clears the runtime it
/// installed and releases ownership so a later server or schema-test lifecycle
/// can install its own configured executor.
#[cfg(feature = "runtime")]
pub(crate) struct ConfiguredWasmRuntime {
    runtime: Weak<WasmHandlerRuntime>,
}

#[cfg(feature = "runtime")]
impl Drop for ConfiguredWasmRuntime {
    fn drop(&mut self) {
        let mut installed = RUNTIME.write().expect("wasm runtime lock");
        let owns_installed = self
            .runtime
            .upgrade()
            .zip(installed.as_ref())
            .is_some_and(|(owned, current)| Arc::ptr_eq(&owned, current));
        if owns_installed {
            drop(installed.take());
        }
        RUNTIME_OWNED.store(false, Ordering::Release);
    }
}

fn runtime() -> Result<Arc<WasmHandlerRuntime>, ActionHandlerDiagnostic> {
    RUNTIME
        .read()
        .expect("wasm runtime lock")
        .clone()
        .ok_or_else(runtime_not_installed)
}

/// Evaluation before any install is a wiring fault, typed with the closed
/// execution vocabulary. A lazily defaulted runtime would silently discard
/// the operator budgets and backend the startup path owns.
fn runtime_not_installed() -> ActionHandlerDiagnostic {
    ActionHandlerDiagnostic::new(
        ActionHandlerError::Execution,
        "The WASM execution runtime is not installed; the server startup path installs it.",
    )
}

/// Replace the runtime for serialized unit tests that exercise executor
/// behavior under different configurations.
#[cfg(test)]
pub(crate) fn install(
    budgets: WasmExecutionBudgets,
    backend: Backend,
    retained_modules: usize,
) -> Result<(), WasmRuntimeStartError> {
    acquire_runtime_ownership()?;
    let result = replace_runtime(budgets, backend, retained_modules).map(drop);
    RUNTIME_OWNED.store(false, Ordering::Release);
    result
}

fn acquire_runtime_ownership() -> Result<(), WasmRuntimeStartError> {
    RUNTIME_OWNED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
        .map_err(|_| WasmRuntimeStartError::LifecycleActive)
}

fn replace_runtime(
    budgets: WasmExecutionBudgets,
    backend: Backend,
    retained_modules: usize,
) -> Result<Weak<WasmHandlerRuntime>, WasmRuntimeStartError> {
    let runtime = Arc::new(WasmHandlerRuntime::new(budgets, backend, retained_modules)?);
    let ownership = Arc::downgrade(&runtime);
    *RUNTIME.write().expect("wasm runtime lock") = Some(runtime);
    Ok(ownership)
}

/// Install the process runtime from the validated operator configuration and
/// return its exclusive lifecycle owner. Production serving and pre-sign
/// schema tests use this same mapping so neither path can drift on budgets,
/// backend, or cache bounds. An overlapping owner is refused before it can
/// replace the active executor.
#[cfg(feature = "runtime")]
pub(crate) fn install_configured(
    config: crate::runtime_config::WasmExecutionConfig,
) -> Result<ConfiguredWasmRuntime, WasmRuntimeStartError> {
    acquire_runtime_ownership()?;
    let runtime = match replace_runtime(
        WasmExecutionBudgets::from(config),
        crate::wasm_handler::execution_backend(config.backend()),
        MAXIMUM_RETAINED_PREPARED_MODULES,
    ) {
        Ok(runtime) => runtime,
        Err(error) => {
            RUNTIME_OWNED.store(false, Ordering::Release);
            return Err(error);
        }
    };
    Ok(ConfiguredWasmRuntime { runtime })
}

/// Clear the process runtime for unit tests that exercise uninstalled state.
/// The configured production and schema-test lifecycles use
/// [`ConfiguredWasmRuntime`] instead so ownership remains exclusive.
#[cfg(test)]
pub(crate) fn shutdown() {
    drop(RUNTIME.write().expect("wasm runtime lock").take());
    RUNTIME_OWNED.store(false, Ordering::Release);
}

fn install_persistent(
    budgets: WasmExecutionBudgets,
    backend: Backend,
    retained_modules: usize,
) -> Result<(), WasmRuntimeStartError> {
    acquire_runtime_ownership()?;
    match replace_runtime(budgets, backend, retained_modules) {
        Ok(_) => Ok(()),
        Err(error) => {
            RUNTIME_OWNED.store(false, Ordering::Release);
            Err(error)
        }
    }
}

/// Install the process runtime with the default execution budgets, default
/// backend, and default cache bound. The server startup path installs the
/// configured runtime itself; an embedder assembling the HTTP app without
/// that path calls this once before serving. That executor owns the process
/// runtime for the remainder of the process, and every evaluation before any
/// install is refused.
pub fn install_default() -> Result<(), WasmRuntimeStartError> {
    install_persistent(
        WasmExecutionBudgets::default(),
        crate::wasm_handler::execution_backend(crate::wasm_handler::WasmExecutionBackend::default()),
        MAXIMUM_RETAINED_PREPARED_MODULES,
    )
}

/// Whether a runtime is installed; observability for the startup/shutdown
/// wiring tests.
#[cfg(test)]
pub(crate) fn installed() -> bool {
    RUNTIME.read().expect("wasm runtime lock").is_some()
}

fn engine_setup_refused() -> ActionHandlerDiagnostic {
    ActionHandlerDiagnostic::new(
        ActionHandlerError::Execution,
        "This build cannot start the WASM execution engine.",
    )
}

/// Compile failures are typed the way authoring admission types them: a
/// module over the configured ceiling is a resource refusal, anything caused
/// by the module bytes is a module-source refusal, and an engine-setup
/// failure is the build fault the invoke path uses. A compiled package was
/// structurally validated at authoring time, so the non-size branches are
/// defense-in-depth for hand-built handler declarations.
fn classify_prepare_error(error: InvokeError) -> ActionHandlerDiagnostic {
    match error {
        InvokeError::ModuleTooLarge { .. } => ActionHandlerError::Resource.into(),
        InvokeError::EngineSetup { .. } => engine_setup_refused(),
        _ => ActionHandlerError::Source.into(),
    }
}

/// Map a call failure to the same closed vocabulary the Rhai path uses: the
/// epoch backstop is the action deadline, exhausted budgets are resource
/// refusals, and everything the guest did or failed to do is an execution
/// failure. Only host-generated, bounded text exists on these errors.
fn classify_invoke_error(error: InvokeError) -> ActionHandlerDiagnostic {
    match error {
        InvokeError::DeadlineExceeded => ActionHandlerError::Deadline.into(),
        InvokeError::FuelExhausted
        | InvokeError::StackLimitExceeded
        | InvokeError::MemoryLimitExceeded { .. }
        | InvokeError::TableLimitExceeded { .. }
        | InvokeError::InputTooLarge { .. }
        | InvokeError::OutputTooLarge { .. } => ActionHandlerError::Resource.into(),
        InvokeError::EngineSetup { .. } => engine_setup_refused(),
        _ => ActionHandlerError::Execution.into(),
    }
}

/// Map the action's remaining wall-clock budget to epoch ticks under the
/// process ticker's interval, rounding up so the epoch deadline never
/// outlives the caller's deadline.
fn epoch_ticks_until(deadline: Instant) -> u64 {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let millis = u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX);
    millis.saturating_add(1).min(MAXIMUM_EPOCH_DEADLINE_TICKS)
}

/// Evaluate a WASM handler: build the request envelope, resolve the
/// prepared module, run one fresh-store call under the action deadline,
/// then decode and validate the outcome through the shared layers.
pub(crate) fn evaluate_wasm_handler(
    action: &CompiledAction,
    handler: &CompiledActionHandler,
    inputs: &JsonMap<String, Value>,
    deadline: Instant,
) -> Result<ActionHandlerOutcome, ActionHandlerDiagnostic> {
    let runtime = runtime()?;
    evaluate_with_runtime(&runtime, action, handler, inputs, deadline)
}

fn evaluate_with_runtime(
    runtime: &WasmHandlerRuntime,
    action: &CompiledAction,
    handler: &CompiledActionHandler,
    inputs: &JsonMap<String, Value>,
    deadline: Instant,
) -> Result<ActionHandlerOutcome, ActionHandlerDiagnostic> {
    if Instant::now() >= deadline {
        return Err(ActionHandlerError::Deadline.into());
    }
    // The request bytes are the inputs JSON document the v1 handler
    // contract defines: the same JSON conversion the Rhai path's context
    // receives (its ctx map carries one "inputs" member built from this
    // same object), without the operation-dispatch wrapper a multi-operation
    // envelope would need.
    let mut envelope = JsonMap::new();
    envelope.insert("inputs".to_owned(), Value::Object(inputs.clone()));
    let request = serde_json::to_vec(&Value::Object(envelope))
        .map_err(|_| ActionHandlerDiagnostic::from(ActionHandlerError::Result))?;
    let prepared = runtime.prepared_module(handler)?;
    let invoked = runtime
        .executor
        .invoke_with_epoch_deadline(&prepared, &request, epoch_ticks_until(deadline))
        .map_err(classify_invoke_error)?;
    if Instant::now() >= deadline {
        return Err(ActionHandlerError::Deadline.into());
    }
    let proposed =
        crate::action_outcome::decode_wasm_outcome(&invoked.output, action.maximum_snapshot_bytes)?;
    crate::action_outcome::validate_proposed_outcome(action, handler, proposed)
}

/// Evaluate one reviewed WASM hook handler: the envelope in verbatim, the
/// guest's answer bytes out.
///
/// The hook handler contract is narrower than the action handler contract:
/// the request is the envelope itself rather than an operation wrapper, and
/// the answer is the handler message the delivery worker parses, so nothing
/// is decoded here. Only the failure vocabulary is translated, into the hook
/// error taxonomy the delivery state records.
#[cfg(feature = "runtime")]
pub(crate) fn evaluate_wasm_hook(
    module_sha256: &str,
    module_bytes: &[u8],
    envelope: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, registry_platform_hooks::ErrorCategory> {
    use registry_platform_hooks::ErrorCategory;

    let runtime = RUNTIME
        .read()
        .expect("wasm runtime lock")
        .clone()
        // Evaluation before any install is a wiring fault, not a property of
        // the reviewed module: a lazily defaulted runtime would silently
        // discard the operator budgets and backend startup owns.
        .ok_or(ErrorCategory::Execution)?;
    if Instant::now() >= deadline {
        return Err(ErrorCategory::Deadline);
    }
    let prepared = runtime
        .prepared_module_for(module_sha256, module_bytes)
        .map_err(hook_prepare_category)?;
    let invoked = runtime
        .executor
        .invoke_with_epoch_deadline(&prepared, envelope, epoch_ticks_until(deadline))
        .map_err(hook_invoke_category)?;
    if Instant::now() >= deadline {
        return Err(ErrorCategory::Deadline);
    }
    Ok(invoked.output)
}

/// A module over the configured ceiling is a resource refusal, an
/// engine-setup failure is a build fault, and anything else caused by the
/// module bytes is a source refusal. Same split the action path applies, in
/// the hook taxonomy.
#[cfg(feature = "runtime")]
fn hook_prepare_category(error: InvokeError) -> registry_platform_hooks::ErrorCategory {
    use registry_platform_hooks::ErrorCategory;
    match error {
        // The declared guest memory is checked once at preparation, so an
        // operator ceiling can be crossed before the module ever runs.
        InvokeError::ModuleTooLarge { .. }
        | InvokeError::MemoryLimitExceeded { .. }
        | InvokeError::TableLimitExceeded { .. } => ErrorCategory::Resource,
        InvokeError::EngineSetup { .. } => ErrorCategory::Execution,
        _ => ErrorCategory::Source,
    }
}

/// The epoch backstop is the attempt deadline, exhausted budgets are resource
/// refusals, and everything the guest did or failed to do is an execution
/// failure. `Unavailable` never appears: a local kind has nothing to reach.
#[cfg(feature = "runtime")]
fn hook_invoke_category(error: InvokeError) -> registry_platform_hooks::ErrorCategory {
    use registry_platform_hooks::ErrorCategory;
    match error {
        InvokeError::DeadlineExceeded => ErrorCategory::Deadline,
        InvokeError::FuelExhausted
        | InvokeError::StackLimitExceeded
        | InvokeError::MemoryLimitExceeded { .. }
        | InvokeError::TableLimitExceeded { .. }
        | InvokeError::InputTooLarge { .. }
        | InvokeError::OutputTooLarge { .. } => ErrorCategory::Resource,
        _ => ErrorCategory::Execution,
    }
}

#[cfg(test)]
#[path = "tests/wasm_runtime_tests.rs"]
mod wasm_runtime_tests;
