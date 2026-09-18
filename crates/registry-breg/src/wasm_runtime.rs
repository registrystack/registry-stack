// SPDX-License-Identifier: Apache-2.0

//! Process-wide WASM handler execution (prototype feature).
//!
//! One platform [`Executor`] (one engine) and one [`EpochTicker`] serve the
//! whole server process, and a bounded cache keeps prepared modules so the
//! first use of a module identity pays compilation and later uses do not.
//! The evaluation entry points are free functions over owned compiled
//! declarations (see `mutation::action`), so the runtime is installed once at
//! server startup from the operator configuration and otherwise
//! default-initialized on first use; replacing or clearing it stops the old
//! ticker when the last evaluation holding it finishes.
//!
//! Semantics shared with the Rhai path are not re-decided here: the request
//! envelope is the same inputs document the Rhai context receives, and the
//! outcome bytes flow through the same decode layer and the same shared
//! validator (`action_outcome`), so authorization, write ceilings, receipt
//! semantics, and audit content are identical by construction.

use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use registry_platform_script::wasm::{
    Backend, Budgets, EpochTicker, Executor, InvokeError, PreparedModule, DEFAULT_INTERVAL,
};
use serde_json::{Map as JsonMap, Value};

use crate::action_handler::{ActionHandlerDiagnostic, ActionHandlerError, ActionHandlerOutcome};
use crate::model::{CompiledAction, CompiledActionHandler};

/// The compilation backend for handler execution. Native is the default
/// deployment; Pulley is the fallback for executable-memory-restricted
/// environments and becomes configuration when that deployment lands.
const WASM_EXECUTION_BACKEND: Backend = Backend::Native;

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

/// The operator-configurable execution budgets. Defaults mirror the
/// compile-time module admission ceiling and the platform guest-memory
/// default; a build that changes either default changes them in lockstep
/// (pinned by tests beside this module).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WasmExecutionBudgets {
    /// Byte ceiling for one handler module, checked again at prepare time.
    pub max_module_bytes: usize,
    /// Byte ceiling for guest memory growth during one call.
    pub max_guest_memory_bytes: usize,
}

impl WasmExecutionBudgets {
    pub(crate) const DEFAULT_MAX_MODULE_BYTES: usize =
        crate::wasm_handler::MAXIMUM_WASM_MODULE_BYTES;
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
    entries: Vec<(String, Arc<PreparedModule>)>,
    /// Compilations performed through this cache; test-observable.
    preparations: u64,
}

impl WasmHandlerRuntime {
    /// Build the executor, start its epoch ticker, and start with an empty
    /// cache retaining at most `retained_modules` prepared modules.
    pub(crate) fn new(
        budgets: WasmExecutionBudgets,
        retained_modules: usize,
    ) -> Result<Self, InvokeError> {
        let budgets = Budgets {
            max_module_bytes: budgets.max_module_bytes,
            max_guest_memory_bytes: budgets.max_guest_memory_bytes,
            fuel: WASM_FUEL_PER_CALL,
            max_input_bytes: WASM_MAXIMUM_REQUEST_BYTES,
            max_output_bytes: WASM_MAXIMUM_OUTCOME_BYTES,
            ..Budgets::default()
        };
        let executor = Executor::new(WASM_EXECUTION_BACKEND, budgets)?;
        let ticker = EpochTicker::spawn(executor.engine().clone(), DEFAULT_INTERVAL);
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
    /// Identity is the module's content hash: a prepared module is immutable
    /// and content-addressed, so identical bytes prepare to an identical
    /// module and different package revisions carrying identical bytes share
    /// one preparation. Backend and budgets are fixed at runtime
    /// construction, so a configuration change replaces the runtime and its
    /// cache together.
    fn prepared_module(
        &self,
        handler: &CompiledActionHandler,
    ) -> Result<Arc<PreparedModule>, ActionHandlerDiagnostic> {
        let identity = handler.module_sha256.clone().ok_or_else(|| {
            ActionHandlerDiagnostic::new(
                ActionHandlerError::Source,
                "A compiled WASM handler carries its module content hash.",
            )
        })?;
        let mut cache = self.cache.lock().expect("wasm module cache lock");
        if let Some(position) = cache.entries.iter().position(|(key, _)| *key == identity) {
            // Move-to-front keeps the eviction order least-recently-used.
            let prepared = cache.entries.remove(position);
            cache.entries.insert(0, prepared.clone());
            return Ok(prepared.1);
        }
        let prepared = Arc::new(
            self.executor
                .prepare(&handler.module_bytes)
                .map_err(classify_prepare_error)?,
        );
        cache.preparations += 1;
        cache.entries.insert(0, (identity, prepared.clone()));
        cache
            .entries
            .truncate(MAXIMUM_RETAINED_PREPARED_MODULES.min(self.retained_modules));
        Ok(prepared)
    }
}

/// The process runtime. Lazily default-initialized so every evaluation entry
/// works in any process (tests, tooling); server startup installs the
/// configured runtime before serving.
static RUNTIME: RwLock<Option<Arc<WasmHandlerRuntime>>> = RwLock::new(None);

fn runtime() -> Result<Arc<WasmHandlerRuntime>, ActionHandlerDiagnostic> {
    if let Some(runtime) = RUNTIME.read().expect("wasm runtime lock").clone() {
        return Ok(runtime);
    }
    let mut guard = RUNTIME.write().expect("wasm runtime lock");
    if guard.is_none() {
        let runtime = WasmHandlerRuntime::new(WasmExecutionBudgets::default(), usize::MAX)
            .map_err(|_| engine_setup_refused())?;
        *guard = Some(Arc::new(runtime));
    }
    Ok(guard.as_ref().expect("just installed").clone())
}

/// Install the configured runtime. Called once at server startup, before
/// requests: replacing a runtime stops the previous ticker once the last
/// evaluation holding it finishes, so no evaluation loses its backstop
/// mid-call.
#[cfg(any(test, feature = "runtime"))]
pub(crate) fn install(
    budgets: WasmExecutionBudgets,
    retained_modules: usize,
) -> Result<(), InvokeError> {
    let runtime = WasmHandlerRuntime::new(budgets, retained_modules)?;
    *RUNTIME.write().expect("wasm runtime lock") = Some(Arc::new(runtime));
    Ok(())
}

/// Clear the process runtime. The server shutdown path calls this; the
/// runtime's Drop stops its ticker at the last reference, and a later
/// evaluation lazily builds a fresh default runtime.
#[cfg(any(test, feature = "runtime"))]
pub(crate) fn shutdown() {
    drop(RUNTIME.write().expect("wasm runtime lock").take());
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
/// module over the configured ceiling is a resource refusal, anything else
/// is a module-source refusal. A compiled package was structurally
/// validated at authoring time, so the non-size branches are
/// defense-in-depth for hand-built handler declarations.
fn classify_prepare_error(error: InvokeError) -> ActionHandlerDiagnostic {
    match error {
        InvokeError::ModuleTooLarge { .. } => ActionHandlerError::Resource.into(),
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
    // prototype envelope needed.
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

#[cfg(test)]
#[path = "tests/wasm_runtime_tests.rs"]
mod wasm_runtime_tests;
