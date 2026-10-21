// SPDX-License-Identifier: Apache-2.0

//! The WASM hook program engine (`wasm` feature).
//!
//! A [`WasmHookRuntime`] is hook-owned: one platform executor, one epoch
//! ticker, and one bounded prepared-module cache that serve hook programs
//! and nothing else. A product that also runs WASM for its own purposes keeps
//! that runtime separate, so neither cache nor budget is shared across the
//! two paths and neither learns the other's error vocabulary.
//!
//! The hook contract is narrow: the request is the stored envelope verbatim
//! and the answer is the handler message bytes the delivery worker parses,
//! so nothing is decoded here. Only the failure vocabulary is translated,
//! into the shared five-category taxonomy the delivery state records.

use std::sync::{Arc, Mutex};
use std::time::Instant;

pub use registry_platform_script::wasm::Backend;
use registry_platform_script::wasm::{
    Budgets, EpochTicker, Executor, InvokeError, PreparedModule, TickerSpawnError, DEFAULT_INTERVAL,
};

use crate::{ErrorCategory, MAX_ENVELOPE_BYTES, MAX_OUTPUT_BYTES};

/// Prepared modules one runtime retains. An evicted entry only costs a
/// recompile on its next use.
pub const WASM_HOOK_RETAINED_MODULES: usize = 32;

/// Fuel granted to one guest call. Fixed, not operator configuration.
pub const WASM_HOOK_FUEL_PER_CALL: u64 = 10_000_000_000;

/// The epoch-deadline tick cap. Fuel still bounds every call regardless.
const MAXIMUM_EPOCH_DEADLINE_TICKS: u64 = u32::MAX as u64;

/// The product-configured budgets a hook module runs under. The request and
/// answer ceilings are the shared envelope and handler-output ceilings and
/// are not configurable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WasmHookBudgets {
    /// Byte ceiling for one hook module, checked at prepare time.
    pub max_module_bytes: usize,
    /// Byte ceiling for guest memory, including the declared initial memory.
    pub max_guest_memory_bytes: usize,
}

/// Why a WASM hook runtime could not start. Either case refuses the runtime
/// rather than weakening its bounds.
#[derive(Debug, thiserror::Error)]
pub enum WasmHookRuntimeError {
    /// The engine rejected its configuration.
    #[error("the WASM hook engine could not start")]
    EngineSetup(#[source] InvokeError),
    /// The epoch ticker's thread could not be spawned.
    #[error("the WASM hook epoch ticker could not start")]
    Ticker(#[source] TickerSpawnError),
}

/// One hook-owned WASM engine, its epoch ticker, and its module cache.
pub struct WasmHookRuntime {
    executor: Executor,
    ticker: EpochTicker,
    cache: Mutex<ModuleCache>,
}

impl std::fmt::Debug for WasmHookRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WasmHookRuntime")
            .field("backend", &self.executor.backend())
            .finish_non_exhaustive()
    }
}

impl Drop for WasmHookRuntime {
    fn drop(&mut self) {
        // Stop the ticker at the last reference rather than leaving its
        // background thread to the ticker's own Drop.
        self.ticker.stop();
    }
}

struct ModuleCache {
    /// Most-recently-used first. The key is the module content digest paired
    /// with the backend the module was compiled for.
    entries: Vec<((String, Backend), Arc<PreparedModule>)>,
    /// Compilations performed through this cache; test-observable.
    preparations: u64,
}

impl WasmHookRuntime {
    /// Build the executor for `backend` under `budgets`, and start its epoch
    /// ticker. A ticker that cannot start is a start failure: the runtime is
    /// never built with inert deadlines.
    ///
    /// # Errors
    ///
    /// [`WasmHookRuntimeError`] when the engine or the ticker cannot start.
    pub fn new(budgets: WasmHookBudgets, backend: Backend) -> Result<Self, WasmHookRuntimeError> {
        let budgets = Budgets {
            max_module_bytes: budgets.max_module_bytes,
            max_guest_memory_bytes: budgets.max_guest_memory_bytes,
            fuel: WASM_HOOK_FUEL_PER_CALL,
            max_input_bytes: MAX_ENVELOPE_BYTES,
            max_output_bytes: MAX_OUTPUT_BYTES,
            ..Budgets::default()
        };
        let executor =
            Executor::new(backend, budgets).map_err(WasmHookRuntimeError::EngineSetup)?;
        let ticker = EpochTicker::spawn(executor.engine().clone(), DEFAULT_INTERVAL)
            .map_err(WasmHookRuntimeError::Ticker)?;
        Ok(Self {
            executor,
            ticker,
            cache: Mutex::new(ModuleCache {
                entries: Vec::new(),
                preparations: 0,
            }),
        })
    }

    /// Compilations performed through this runtime's cache so far.
    #[must_use]
    pub fn preparation_count(&self) -> u64 {
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .preparations
    }

    /// Run one reviewed hook module: the envelope in verbatim, the guest's
    /// answer bytes out.
    pub(crate) fn run(
        &self,
        module_digest: &str,
        module_bytes: &[u8],
        envelope: &[u8],
        deadline: Instant,
    ) -> Result<Vec<u8>, ErrorCategory> {
        if Instant::now() >= deadline {
            return Err(ErrorCategory::Deadline);
        }
        let prepared = self
            .prepared_module(module_digest, module_bytes)
            .map_err(prepare_category)?;
        let invoked = self
            .executor
            .invoke_with_epoch_deadline(&prepared, envelope, epoch_ticks_until(deadline))
            .map_err(invoke_category)?;
        if Instant::now() >= deadline {
            return Err(ErrorCategory::Deadline);
        }
        Ok(invoked.output)
    }

    /// Resolve a prepared module by content identity, compiling it on first
    /// use. A prepared module is immutable and compiled for exactly one
    /// backend, so identical bytes under one backend share one preparation.
    fn prepared_module(
        &self,
        module_digest: &str,
        module_bytes: &[u8],
    ) -> Result<Arc<PreparedModule>, InvokeError> {
        let identity = (module_digest.to_owned(), self.executor.backend());
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(position) = cache.entries.iter().position(|(key, _)| *key == identity) {
            // Move-to-front keeps the eviction order least-recently-used.
            let entry = cache.entries.remove(position);
            let prepared = Arc::clone(&entry.1);
            cache.entries.insert(0, entry);
            return Ok(prepared);
        }
        let prepared = Arc::new(self.executor.prepare(module_bytes)?);
        cache.preparations += 1;
        cache.entries.insert(0, (identity, Arc::clone(&prepared)));
        cache.entries.truncate(WASM_HOOK_RETAINED_MODULES);
        Ok(prepared)
    }
}

/// A module over a ceiling is a resource refusal, an engine-setup failure is
/// an execution fault, and anything else caused by the module bytes is a
/// source refusal.
fn prepare_category(error: InvokeError) -> ErrorCategory {
    match error {
        // The declared guest memory is checked once at preparation, so a
        // ceiling can be crossed before the module ever runs.
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
fn invoke_category(error: InvokeError) -> ErrorCategory {
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

/// Map the remaining wall-clock budget to epoch ticks under the ticker's
/// interval, rounding up so the epoch deadline never outlives the caller's.
fn epoch_ticks_until(deadline: Instant) -> u64 {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let millis = u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX);
    millis.saturating_add(1).min(MAXIMUM_EPOCH_DEADLINE_TICKS)
}
