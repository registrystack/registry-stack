// SPDX-License-Identifier: Apache-2.0
//! The WASM backend adapter: a deterministic Wasmtime configuration with a
//! native and a Pulley target, strict prepare-time validation of the guest
//! byte ABI, and one fresh store and instance per call under fuel, epoch,
//! memory, table, and stack budgets.
//!
//! The module is compiled only under the crate's non-default `wasm` feature.
//! It owns execution mechanics and nothing else: which bytes are a valid
//! guest, how a request crosses the memory boundary, and how a call is
//! bounded and stopped. When preparation and invocation happen, and what any
//! request or outcome means, stay with the owning product.
//!
//! Only WASM bytes are admitted. A module is prepared from bytes under the
//! host's pinned runtime configuration; precompiled native artifacts are
//! never accepted. Preparation and invocation are explicit host steps, so
//! compiling a module stays out of any request path that does not choose to
//! run it.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use wasmtime::{
    Config, Engine, ExternType, Instance, Memory, Module, ResourceLimiter, Store, Trap, TypedFunc,
    ValType,
};

/// Upper bound for guest-derived text carried in error fields. Guest-chosen
/// strings are never echoed past this length.
const NAME_LIMIT: usize = 64;
const SUMMARY_LIMIT: usize = 256;
const TRAP_LIMIT: usize = 128;

/// A host-generated, length-bounded string safe to carry in an error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundedString(String);

impl BoundedString {
    /// Bound a guest-derived name at [`NAME_LIMIT`].
    pub fn new(text: &str) -> Self {
        Self(truncate(text, NAME_LIMIT))
    }

    /// Bound host-generated text at a caller-chosen limit: the summary and
    /// trap limits, which are wider than the name limit.
    pub fn with_limit(text: &str, limit: usize) -> Self {
        Self(truncate(text, limit))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BoundedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Truncate to `limit` bytes without splitting a UTF-8 character.
fn truncate(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// The execution backend the engine compiles for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    /// Cranelift lowering to host machine code.
    Native,
    /// Cranelift lowering to Pulley bytecode, executed by the interpreter.
    Pulley,
}

/// Ceilings and metering knobs applied to every guest module and call.
///
/// These are the crate's defaults; they are not calibrated per-product
/// values. Fuel is not a cross-host invariant for identical modules, and
/// memory peaks depend on the guest, so products derive their own values
/// from measured workloads ([`CallStats`] reports what a call consumed, so
/// calibration has data, not just pass/fail).
#[derive(Clone, Copy, Debug)]
pub struct Budgets {
    /// Reject a wasm binary before compiling it if it exceeds this size.
    pub max_module_bytes: usize,
    /// Deny guest linear-memory growth (including the initial allocation at
    /// instantiation) beyond this many bytes.
    pub max_guest_memory_bytes: usize,
    /// Deny guest table growth beyond this many elements.
    pub max_table_elements: usize,
    /// wasmtime native stack budget per wasm call; 512 KiB is wasmtime's
    /// documented default, recorded here explicitly because it is part of the
    /// determinism story (stack overflow traps identically on both backends).
    pub max_wasm_stack_bytes: usize,
    /// Reject host-copied request bytes beyond this size.
    pub max_input_bytes: usize,
    /// Reject guest-reported outcome lengths beyond this size; mirrors the
    /// registry's MAX_STRUCTURED_VALUE_BYTES structured-value ceiling.
    pub max_output_bytes: usize,
    /// Fuel granted per call. Stores start at 0 fuel, so this is set before
    /// every call.
    pub fuel: u64,
    /// Epoch deadline, in engine epoch increments beyond the current epoch,
    /// set before every call.
    pub epoch_deadline_ticks: u64,
}

impl Default for Budgets {
    fn default() -> Self {
        Self {
            max_module_bytes: 2 * 1024 * 1024,
            max_guest_memory_bytes: 32 * 1024 * 1024,
            max_table_elements: 10_000,
            max_wasm_stack_bytes: 512 * 1024,
            max_input_bytes: 256 * 1024,
            max_output_bytes: 1024 * 1024,
            fuel: 10_000_000_000,
            epoch_deadline_ticks: 250,
        }
    }
}

/// Statistics about one completed guest call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallStats {
    /// Fuel spent by the call: the granted budget minus the remaining fuel.
    pub fuel_consumed: u64,
    /// Peak guest memory size granted during the call, in bytes.
    pub memory_bytes: u64,
    /// Whether a memory or table growth attempt was denied by the limiter.
    pub memory_growth_denied: bool,
}

/// A successful call: the guest's outcome bytes and the call's statistics.
#[derive(Clone, Debug)]
pub struct InvokeOk {
    pub output: Vec<u8>,
    pub stats: CallStats,
}

/// Everything that can go wrong on the host side of a call. Every Display
/// string is host-generated and bounded; guest-chosen strings never reach it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvokeError {
    /// The wasm binary exceeds `max_module_bytes`.
    ModuleTooLarge { size: usize, max: usize },
    /// The module imports an entity; the guest ABI requires zero imports.
    UnsupportedImport {
        module: BoundedString,
        name: BoundedString,
    },
    /// A required ABI export is absent.
    MissingExport { name: &'static str },
    /// An ABI export exists with the wrong kind or signature.
    ExportTypeMismatch { name: &'static str },
    /// The module exports a name outside the ABI.
    UnexpectedExport { name: BoundedString },
    /// The engine configuration was rejected by wasmtime.
    EngineSetup { detail: BoundedString },
    /// The binary failed to compile or validate, or instantiation failed
    /// without a limiter denial.
    InvalidModule { summary: BoundedString },
    /// The request bytes exceed `max_input_bytes`.
    InputTooLarge { size: usize, max: usize },
    /// Guest memory growth (including the initial allocation) was denied.
    MemoryLimitExceeded { requested: usize, max: usize },
    /// Guest table growth was denied.
    TableLimitExceeded { requested: usize, max: usize },
    /// `alloc` returned a pointer that is not a writable in-bounds range.
    AllocInvalidPointer { ptr: i32, len: usize },
    /// The guest rejected the request as malformed (status 1).
    GuestMalformedRequest,
    /// The guest reported an internal error (status 2).
    GuestInternalError,
    /// The guest returned a status outside the ABI.
    GuestStatusUnknown(i32),
    /// The reported outcome length exceeds `max_output_bytes`.
    OutputTooLarge { len: usize, max: usize },
    /// The reported outcome range lies outside guest memory.
    OutputOutOfBounds {
        ptr: usize,
        len: usize,
        memory_bytes: usize,
    },
    /// `result_len` returned a negative length.
    OutputLengthNegative(i32),
    /// `result_ptr` returned a negative pointer.
    OutputPointerNegative(i32),
    /// The epoch deadline fired before the guest returned.
    DeadlineExceeded,
    /// The fuel budget ran out before the guest returned.
    FuelExhausted,
    /// The guest exhausted its wasm stack budget.
    StackLimitExceeded,
    /// Any other trap; only the host-generated trap description is carried.
    Trap { description: BoundedString },
}

impl fmt::Display for InvokeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModuleTooLarge { size, max } => {
                write!(f, "module of {size} bytes exceeds the {max}-byte ceiling")
            }
            Self::UnsupportedImport { module, name } => write!(
                f,
                "module imports \"{module}\".\"{name}\"; the guest ABI requires zero imports"
            ),
            Self::MissingExport { name } => write!(f, "required export \"{name}\" is missing"),
            Self::ExportTypeMismatch { name } => write!(
                f,
                "export \"{name}\" has the wrong kind or signature for the guest ABI"
            ),
            Self::UnexpectedExport { name } => {
                write!(f, "export \"{name}\" is not part of the guest ABI")
            }
            Self::EngineSetup { detail } => write!(f, "engine configuration failed: {detail}"),
            Self::InvalidModule { summary } => write!(f, "module rejected: {summary}"),
            Self::InputTooLarge { size, max } => {
                write!(f, "input of {size} bytes exceeds the {max}-byte ceiling")
            }
            Self::MemoryLimitExceeded { requested, max } => write!(
                f,
                "guest memory growth to {requested} bytes exceeds the {max}-byte ceiling"
            ),
            Self::TableLimitExceeded { requested, max } => write!(
                f,
                "guest table growth to {requested} elements exceeds the {max}-element ceiling"
            ),
            Self::AllocInvalidPointer { ptr, len } => write!(
                f,
                "guest alloc returned {ptr} for {len} bytes; not a writable in-bounds pointer"
            ),
            Self::GuestMalformedRequest => {
                write!(f, "guest rejected the request as malformed (status 1)")
            }
            Self::GuestInternalError => write!(f, "guest reported an internal error (status 2)"),
            Self::GuestStatusUnknown(status) => {
                write!(f, "guest returned unknown status {status}")
            }
            Self::OutputTooLarge { len, max } => {
                write!(
                    f,
                    "guest outcome of {len} bytes exceeds the {max}-byte ceiling"
                )
            }
            Self::OutputOutOfBounds {
                ptr,
                len,
                memory_bytes,
            } => write!(
                f,
                "guest outcome range {ptr}..{} lies outside guest memory ({memory_bytes} bytes)",
                ptr.saturating_add(*len)
            ),
            Self::OutputLengthNegative(len) => write!(
                f,
                "guest result_len returned {len}; the guest ABI requires a non-negative length"
            ),
            Self::OutputPointerNegative(ptr) => write!(
                f,
                "guest result_ptr returned {ptr}; the guest ABI requires a non-negative pointer"
            ),
            Self::DeadlineExceeded => {
                write!(f, "epoch deadline reached before the guest returned")
            }
            Self::FuelExhausted => write!(f, "fuel exhausted before the guest returned"),
            Self::StackLimitExceeded => write!(f, "guest exhausted its wasm stack budget"),
            Self::Trap { description } => write!(f, "guest trapped: {description}"),
        }
    }
}

impl std::error::Error for InvokeError {}

/// An engine plus the budgets every call runs under. The engine is shareable
/// across threads; one executor serves any number of concurrent calls.
pub struct Executor {
    engine: Engine,
    budgets: Budgets,
    backend: Backend,
}

/// The required exports, in validation-reporting order.
const REQUIRED_EXPORTS: [&str; 5] = ["alloc", "handle", "result_ptr", "result_len", "memory"];

impl Executor {
    /// Build the deterministic engine configuration for a backend.
    ///
    /// Both backends share every knob so outcomes differ only in the
    /// compilation target: threads, relaxed SIMD and memory64 off (the first
    /// two default to on, so the explicit calls are load-bearing), NaN
    /// canonicalization on, and fuel plus epoch interruption armed. Pulley
    /// adds `target("pulley64")`.
    pub fn new(backend: Backend, budgets: Budgets) -> Result<Self, InvokeError> {
        let mut config = Config::new();
        // wasm_threads defaults to on with the `threads` cargo feature; the
        // guest contract is single-threaded, and shared memories are how
        // threads leak in.
        config.wasm_threads(false);
        // Relaxed SIMD admits nondeterministic lane-wise results.
        config.wasm_relaxed_simd(false);
        // memory64 is off by default; recorded explicitly as part of the
        // contract because pointer widths shape the ABI.
        config.wasm_memory64(false);
        // Canonicalize NaNs so f32/f64 results are bit-identical across
        // backends (applies under Pulley too).
        config.cranelift_nan_canonicalization(true);
        config.max_wasm_stack(budgets.max_wasm_stack_bytes);
        config.consume_fuel(true);
        config.epoch_interruption(true);
        if backend == Backend::Pulley {
            config
                .target("pulley64")
                .map_err(|err| InvokeError::EngineSetup {
                    detail: BoundedString::with_limit(&err.to_string(), SUMMARY_LIMIT),
                })?;
        }
        let engine = Engine::new(&config).map_err(|err| InvokeError::EngineSetup {
            detail: BoundedString::with_limit(&err.to_string(), SUMMARY_LIMIT),
        })?;
        Ok(Self {
            engine,
            budgets,
            backend,
        })
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }

    pub fn budgets(&self) -> &Budgets {
        &self.budgets
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Compile and strictly validate a guest module. The returned module is
    /// immutable and shareable across threads.
    ///
    /// Validation: zero imports; exactly the `alloc` / `handle` /
    /// `result_ptr` / `result_len` / `memory` exports with their wasm32
    /// signatures, the exported memory's declared minimum within the
    /// guest-memory budget, plus an optional `init` export (the
    /// pre-initialized rewrite strips it).
    pub fn prepare(&self, wasm_bytes: &[u8]) -> Result<PreparedModule, InvokeError> {
        if wasm_bytes.len() > self.budgets.max_module_bytes {
            return Err(InvokeError::ModuleTooLarge {
                size: wasm_bytes.len(),
                max: self.budgets.max_module_bytes,
            });
        }
        let module = Module::new(&self.engine, wasm_bytes).map_err(invalid_module)?;
        validate_abi(&module, self.budgets.max_guest_memory_bytes)?;
        Ok(PreparedModule { module })
    }

    /// Run one request through the guest: a fresh store and a fresh instance,
    /// always.
    pub fn invoke(&self, prepared: &PreparedModule, input: &[u8]) -> Result<InvokeOk, InvokeError> {
        self.start_call(prepared)?.invoke(input)
    }

    /// Run one request through the guest under a per-call epoch deadline that
    /// replaces [`Budgets::epoch_deadline_ticks`] for this one call. A caller
    /// mapping a wall-clock deadline onto ticks must know the ticker interval
    /// that drives the engine's epoch.
    pub fn invoke_with_epoch_deadline(
        &self,
        prepared: &PreparedModule,
        input: &[u8],
        epoch_deadline_ticks: u64,
    ) -> Result<InvokeOk, InvokeError> {
        self.start_call_with_epoch_deadline(prepared, epoch_deadline_ticks)?
            .invoke(input)
    }

    /// Open a call: build the fresh store, attach the resource limiter before
    /// instantiation, arm fuel and the epoch deadline, instantiate, and look
    /// up the ABI exports. [`CallInstance::invoke`] completes the call.
    ///
    /// Exposed separately from [`Executor::invoke`] so a caller can account
    /// for the instantiate phase separately from the invoke phase.
    pub fn start_call(&self, prepared: &PreparedModule) -> Result<CallInstance, InvokeError> {
        self.start_call_with_epoch_deadline(prepared, self.budgets.epoch_deadline_ticks)
    }

    /// Open a call with a per-call epoch deadline in ticks counted from the
    /// engine's current epoch, replacing the budget default. Everything else
    /// matches [`Executor::start_call`].
    pub fn start_call_with_epoch_deadline(
        &self,
        prepared: &PreparedModule,
        epoch_deadline_ticks: u64,
    ) -> Result<CallInstance, InvokeError> {
        let mut store = Store::new(
            &self.engine,
            CallState {
                limits: Limits {
                    max_memory_bytes: self.budgets.max_guest_memory_bytes,
                    max_table_elements: self.budgets.max_table_elements,
                    peak_memory_bytes: 0,
                    memory_denied: None,
                    table_denied: None,
                },
            },
        );
        // Attached before instantiation so the initial memory allocation is
        // limited too: a module declaring a huge initial memory fails here.
        store.limiter(|state: &mut CallState| &mut state.limits);
        store
            .set_fuel(self.budgets.fuel)
            .map_err(|err| InvokeError::EngineSetup {
                detail: BoundedString::with_limit(&err.to_string(), SUMMARY_LIMIT),
            })?;
        store.set_epoch_deadline(epoch_deadline_ticks);

        let instance = Instance::new(&mut store, prepared.module(), &[])
            .map_err(|err| state_denial(&store, err, &self.budgets))?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(InvokeError::MissingExport { name: "memory" })?;
        let alloc = typed(&mut store, &instance, "alloc")?;
        let handle = typed::<(i32, i32), i32>(&mut store, &instance, "handle")?;
        let result_ptr = typed::<(), i32>(&mut store, &instance, "result_ptr")?;
        let result_len = typed::<(), i32>(&mut store, &instance, "result_len")?;

        // Record the granted initial size even if nothing ever grows.
        let granted = memory.data_size(&store);
        store.data_mut().limits.note_granted(granted);

        Ok(CallInstance {
            store,
            memory,
            alloc,
            handle,
            result_ptr,
            result_len,
            fuel_budget: self.budgets.fuel,
            max_input_bytes: self.budgets.max_input_bytes,
            max_output_bytes: self.budgets.max_output_bytes,
        })
    }
}

fn typed<P: wasmtime::WasmParams, R: wasmtime::WasmResults>(
    store: &mut Store<CallState>,
    instance: &Instance,
    name: &'static str,
) -> Result<TypedFunc<P, R>, InvokeError> {
    instance
        .get_typed_func(store, name)
        .map_err(|_| InvokeError::ExportTypeMismatch { name })
}

/// A compiled, validated guest module. `Module` is `Send + Sync`, so one
/// prepared module can serve concurrent callers.
pub struct PreparedModule {
    module: Module,
}

impl PreparedModule {
    pub fn module(&self) -> &Module {
        &self.module
    }
}

/// A live call: one store, one instance, and the looked-up ABI handles.
pub struct CallInstance {
    store: Store<CallState>,
    memory: Memory,
    alloc: TypedFunc<i32, i32>,
    handle: TypedFunc<(i32, i32), i32>,
    result_ptr: TypedFunc<(), i32>,
    result_len: TypedFunc<(), i32>,
    fuel_budget: u64,
    max_input_bytes: usize,
    max_output_bytes: usize,
}

impl CallInstance {
    /// Complete the call: copy the request in, run `handle`, read the outcome
    /// back, and collect the call's statistics.
    pub fn invoke(mut self, input: &[u8]) -> Result<InvokeOk, InvokeError> {
        // The second bound also keeps the `as i32` length casts honest for
        // absurdly configured budgets.
        let input_cap = self.max_input_bytes.min(i32::MAX as usize);
        if input.len() > input_cap {
            return Err(InvokeError::InputTooLarge {
                size: input.len(),
                max: self.max_input_bytes,
            });
        }

        let ptr = self
            .alloc
            .call(&mut self.store, input.len() as i32)
            .map_err(map_trap)?;
        if !input.is_empty() {
            // alloc(0) legitimately returns 0; there is nothing to copy.
            let in_bounds = ptr > 0
                && (ptr as usize)
                    .checked_add(input.len())
                    .is_some_and(|end| end <= self.memory.data_size(&self.store));
            if !in_bounds {
                return Err(InvokeError::AllocInvalidPointer {
                    ptr,
                    len: input.len(),
                });
            }
            self.memory
                .write(&mut self.store, ptr as usize, input)
                .map_err(|err| InvokeError::Trap {
                    description: BoundedString::with_limit(&err.to_string(), TRAP_LIMIT),
                })?;
        }

        let status = self
            .handle
            .call(&mut self.store, (ptr, input.len() as i32))
            .map_err(map_trap)?;
        match status {
            0 => {}
            1 => return Err(InvokeError::GuestMalformedRequest),
            2 => return Err(InvokeError::GuestInternalError),
            other => return Err(InvokeError::GuestStatusUnknown(other)),
        }

        // Length first, and rejected before any host allocation or copy.
        let raw_len = self
            .result_len
            .call(&mut self.store, ())
            .map_err(map_trap)?;
        if raw_len < 0 {
            return Err(InvokeError::OutputLengthNegative(raw_len));
        }
        let len = usize::try_from(raw_len).unwrap_or(usize::MAX);
        if len > self.max_output_bytes {
            return Err(InvokeError::OutputTooLarge {
                len,
                max: self.max_output_bytes,
            });
        }
        let raw_ptr = self
            .result_ptr
            .call(&mut self.store, ())
            .map_err(map_trap)?;
        if raw_ptr < 0 {
            return Err(InvokeError::OutputPointerNegative(raw_ptr));
        }
        let memory_bytes = self.memory.data_size(&self.store);
        let result_ptr = usize::try_from(raw_ptr).unwrap_or(usize::MAX);
        let in_bounds = result_ptr
            .checked_add(len)
            .is_some_and(|end| end <= memory_bytes);
        if !in_bounds {
            return Err(InvokeError::OutputOutOfBounds {
                ptr: result_ptr,
                len,
                memory_bytes,
            });
        }
        let mut output = vec![0u8; len];
        if len > 0 {
            self.memory
                .read(&self.store, result_ptr, &mut output)
                .map_err(|_| InvokeError::OutputOutOfBounds {
                    ptr: result_ptr,
                    len,
                    memory_bytes,
                })?;
        }

        let remaining = self
            .store
            .get_fuel()
            .map_err(|err| InvokeError::EngineSetup {
                detail: BoundedString::with_limit(&err.to_string(), SUMMARY_LIMIT),
            })?;
        let limits = &self.store.data().limits;
        let stats = CallStats {
            fuel_consumed: self.fuel_budget.saturating_sub(remaining),
            memory_bytes: limits.peak_memory_bytes as u64,
            memory_growth_denied: limits.memory_denied.is_some() || limits.table_denied.is_some(),
        };
        Ok(InvokeOk { output, stats })
    }
}

/// Store data: the resource limiter plus what it recorded.
struct CallState {
    limits: Limits,
}

/// Deny-and-record limiter for one call's store. Denials return `Ok(false)`
/// (guest-visible as a `-1` growth result) while remembering the request, so
/// a failed instantiation can be attributed to a budget and the stats can
/// report the denial.
struct Limits {
    max_memory_bytes: usize,
    max_table_elements: usize,
    peak_memory_bytes: usize,
    /// Bytes requested by a denied memory growth, if any.
    memory_denied: Option<usize>,
    /// Elements requested by a denied table growth, if any.
    table_denied: Option<usize>,
}

impl Limits {
    fn note_granted(&mut self, size: usize) {
        self.peak_memory_bytes = self.peak_memory_bytes.max(size);
    }
}

impl ResourceLimiter for Limits {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired > self.max_memory_bytes {
            self.memory_denied = Some(desired);
            return Ok(false);
        }
        self.note_granted(desired);
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired > self.max_table_elements {
            self.table_denied = Some(desired);
            return Ok(false);
        }
        Ok(true)
    }

    fn instances(&self) -> usize {
        1
    }

    fn tables(&self) -> usize {
        1
    }

    fn memories(&self) -> usize {
        1
    }
}

/// Map an instantiation error, preferring a recorded limiter denial as the
/// cause of the failure.
fn state_denial(store: &Store<CallState>, err: wasmtime::Error, budgets: &Budgets) -> InvokeError {
    let limits = &store.data().limits;
    if let Some(requested) = limits.memory_denied {
        return InvokeError::MemoryLimitExceeded {
            requested,
            max: budgets.max_guest_memory_bytes,
        };
    }
    if let Some(requested) = limits.table_denied {
        return InvokeError::TableLimitExceeded {
            requested,
            max: budgets.max_table_elements,
        };
    }
    invalid_module(err)
}

/// Map a call error: recognize the three budget traps, and for anything else
/// carry only the trap's own host-generated description (never guest-chosen
/// strings from panic payloads or backtrace context).
fn map_trap(err: wasmtime::Error) -> InvokeError {
    if let Some(trap) = err.downcast_ref::<Trap>() {
        return match trap {
            Trap::Interrupt => InvokeError::DeadlineExceeded,
            Trap::OutOfFuel => InvokeError::FuelExhausted,
            Trap::StackOverflow => InvokeError::StackLimitExceeded,
            other => InvokeError::Trap {
                description: BoundedString::with_limit(&other.to_string(), TRAP_LIMIT),
            },
        };
    }
    InvokeError::Trap {
        description: BoundedString::with_limit(&err.to_string(), TRAP_LIMIT),
    }
}

fn invalid_module(err: wasmtime::Error) -> InvokeError {
    InvokeError::InvalidModule {
        summary: BoundedString::with_limit(&err.to_string(), SUMMARY_LIMIT),
    }
}

/// Whether an extern is a function with exactly the given params and results.
fn is_func_of(ty: &ExternType, params: &[ValType], results: &[ValType]) -> bool {
    let ExternType::Func(func) = ty else {
        return false;
    };
    types_match(func.params(), params) && types_match(func.results(), results)
}

/// `ValType` implements no `PartialEq`, so the comparison goes through
/// `matches!` pairs.
fn types_match(got: impl ExactSizeIterator<Item = ValType>, want: &[ValType]) -> bool {
    got.len() == want.len()
        && got.zip(want).all(|(got, want)| {
            matches!(
                (got, want),
                (ValType::I32, ValType::I32)
                    | (ValType::I64, ValType::I64)
                    | (ValType::F32, ValType::F32)
                    | (ValType::F64, ValType::F64)
            )
        })
}

/// Strict export validation of the guest ABI. On wasm32 the guest's `usize`
/// and pointer exports are `i32`, which is why every wasm-level signature
/// here is `i32`-typed.
///
/// Error priority: type mismatches, oversized declared memory minimums, and
/// unknown exports are reported while iterating (deterministically, in
/// module order); a missing required export is reported only if nothing else
/// fired.
fn validate_abi(module: &Module, max_guest_memory_bytes: usize) -> Result<(), InvokeError> {
    if let Some(import) = module.imports().next() {
        return Err(InvokeError::UnsupportedImport {
            module: BoundedString::new(import.module()),
            name: BoundedString::new(import.name()),
        });
    }

    let mut seen = [false; 7];
    for export in module.exports() {
        let slot = abi_slot(export.name(), &export.ty())?;
        if slot == MEMORY_SLOT {
            check_memory_minimum(&export.ty(), max_guest_memory_bytes)?;
        }
        seen[slot] = true;
    }
    for (name, present) in REQUIRED_EXPORTS.iter().zip(&seen[..REQUIRED_EXPORTS.len()]) {
        if !present {
            return Err(InvokeError::MissingExport { name });
        }
    }
    Ok(())
}

/// The `seen` slot of the `memory` export.
const MEMORY_SLOT: usize = 4;

/// Refuse a memory type whose declared minimum (minimum pages times the page
/// size) already exceeds the guest-memory ceiling: such a module can never
/// instantiate, so preparation reports the budget denial instead of every
/// later call failing at instantiation.
fn check_memory_minimum(ty: &ExternType, max_guest_memory_bytes: usize) -> Result<(), InvokeError> {
    let ExternType::Memory(memory) = ty else {
        return Ok(());
    };
    let minimum_bytes = memory.minimum().saturating_mul(memory.page_size());
    if minimum_bytes > max_guest_memory_bytes as u64 {
        return Err(InvokeError::MemoryLimitExceeded {
            requested: usize::try_from(minimum_bytes).unwrap_or(usize::MAX),
            max: max_guest_memory_bytes,
        });
    }
    Ok(())
}

/// Classify one export: its ABI slot when it conforms, or the ABI violation.
fn abi_slot(name: &str, ty: &ExternType) -> Result<usize, InvokeError> {
    match name {
        "alloc" if is_func_of(ty, &[ValType::I32], &[ValType::I32]) => Ok(0),
        "handle" if is_func_of(ty, &[ValType::I32, ValType::I32], &[ValType::I32]) => Ok(1),
        "result_ptr" if is_func_of(ty, &[], &[ValType::I32]) => Ok(2),
        "result_len" if is_func_of(ty, &[], &[ValType::I32]) => Ok(3),
        "memory" if matches!(ty, ExternType::Memory(_)) => Ok(4),
        // Optional: present on a module built without build-time
        // pre-initialization, stripped by the pre-initialized rewrite.
        "init" if is_func_of(ty, &[], &[]) => Ok(5),
        // The wasm32 Rust linker's immutable globals; tolerated, nothing
        // else outside the ABI is.
        "__data_end" | "__heap_base" if matches!(ty, ExternType::Global(_)) => Ok(6),
        "alloc" | "handle" | "result_ptr" | "result_len" | "memory" | "init" | "__data_end"
        | "__heap_base" => Err(InvokeError::ExportTypeMismatch {
            name: static_abi_name(name),
        }),
        other => Err(InvokeError::UnexpectedExport {
            name: BoundedString::new(other),
        }),
    }
}

/// The static spelling of an ABI export name (for error payloads).
fn static_abi_name(name: &str) -> &'static str {
    match name {
        "alloc" => "alloc",
        "handle" => "handle",
        "result_ptr" => "result_ptr",
        "result_len" => "result_len",
        "memory" => "memory",
        "init" => "init",
        "__data_end" => "__data_end",
        // The only remaining tolerated name.
        _ => "__heap_base",
    }
}

/// A managed epoch-ticker thread for epoch-deadline enforcement.
///
/// Lifecycle: spawn ONE ticker per engine (service) and stop it when the
/// engine retires. Do not spawn one per request; an epoch increment is a
/// single atomic add on the shared engine, so one thread serves all calls.
pub struct EpochTicker {
    engine: Engine,
    stop_flag: Arc<AtomicBool>,
    // The handle is taken out by stop(); a second stop finds it gone.
    handle: Mutex<Option<JoinHandle<()>>>,
}

/// The default tick interval: 1 ms.
pub const DEFAULT_INTERVAL: Duration = Duration::from_millis(1);

/// The ticker thread could not be spawned. Without the thread, epoch
/// deadlines never fire and calls stay bounded by fuel alone, so the caller
/// is told and decides; the ticker does not run degraded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TickerSpawnError;

impl fmt::Display for TickerSpawnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the epoch-ticker thread could not be spawned")
    }
}

impl std::error::Error for TickerSpawnError {}

/// The ticker thread body handed to the spawner.
type TickerBody = Box<dyn FnOnce() + Send>;

impl EpochTicker {
    /// Start ticking every `interval` (1 ms by default; see
    /// [`DEFAULT_INTERVAL`]). A ticker whose thread could not be spawned is
    /// returned as an error, never as an inert ticker with permanently dead
    /// deadlines.
    pub fn spawn(engine: Engine, interval: Duration) -> Result<Self, TickerSpawnError> {
        Self::spawn_with(engine, interval, spawn_ticker_thread)
    }

    /// Spawn through `spawner`. The seam exists so a spawn failure is
    /// testable without exhausting host threads; production code always
    /// reaches the ticker through [`EpochTicker::spawn`].
    fn spawn_with(
        engine: Engine,
        interval: Duration,
        spawner: impl FnOnce(TickerBody) -> Result<JoinHandle<()>, TickerSpawnError>,
    ) -> Result<Self, TickerSpawnError> {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let thread_flag = Arc::clone(&stop_flag);
        let tick_engine = engine.clone();
        let handle = spawner(Box::new(move || {
            while !thread_flag.load(Ordering::Relaxed) {
                thread::sleep(interval);
                tick_engine.increment_epoch();
            }
        }))?;
        Ok(EpochTicker {
            engine,
            stop_flag,
            handle: Mutex::new(Some(handle)),
        })
    }

    /// Signal the ticker to stop and join its thread. Returning proves the
    /// thread finished. Safe to call more than once; later calls find no
    /// handle and return immediately. The join blocks for at most one
    /// interval.
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        let taken = match self.handle.lock() {
            Ok(mut guard) => guard.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(handle) = taken {
            let _ = handle.join();
        }
    }

    /// The engine this ticker drives (kept alive alongside it).
    pub fn engine(&self) -> &Engine {
        &self.engine
    }
}

/// The production spawner: a named host thread.
fn spawn_ticker_thread(body: TickerBody) -> Result<JoinHandle<()>, TickerSpawnError> {
    thread::Builder::new()
        .name("epoch-ticker".to_owned())
        .spawn(body)
        .map_err(|_| TickerSpawnError)
}

impl Drop for EpochTicker {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::{truncate, BoundedString, Budgets, NAME_LIMIT, SUMMARY_LIMIT, TRAP_LIMIT};

    /// Reduced budgets for tests that need a ceiling small enough to hit.
    fn reduced() -> Budgets {
        Budgets {
            fuel: 5_000,
            epoch_deadline_ticks: 3,
            max_module_bytes: 64,
            max_input_bytes: 8,
            max_output_bytes: 16,
            ..Budgets::default()
        }
    }

    #[test]
    fn bounded_strings_carry_their_own_limit() {
        let text = "x".repeat(SUMMARY_LIMIT + 1);
        // Names stay at the 64-byte name limit.
        assert_eq!(BoundedString::new(&text).as_str().len(), NAME_LIMIT);
        // Summaries and trap descriptions are bounded by their own limits,
        // not re-truncated to the name limit.
        assert_eq!(
            BoundedString::with_limit(&text, SUMMARY_LIMIT)
                .as_str()
                .len(),
            SUMMARY_LIMIT
        );
        assert_eq!(
            BoundedString::with_limit(&text, TRAP_LIMIT).as_str().len(),
            TRAP_LIMIT
        );
    }

    #[test]
    fn truncation_never_splits_a_utf8_character() {
        // 4-byte characters: every cut lands inside one.
        let text = "\u{1F600}".repeat(100);
        for limit in [1, 2, 3, 127, 255] {
            let cut = truncate(&text, limit);
            assert!(cut.len() <= limit);
            assert!(cut.chars().all(|c| c == '\u{1F600}'));
        }
    }

    #[test]
    fn defaults_match_the_documented_budgets() {
        let budgets = Budgets::default();
        assert_eq!(budgets.max_module_bytes, 2_097_152);
        assert_eq!(budgets.max_guest_memory_bytes, 33_554_432);
        assert_eq!(budgets.max_table_elements, 10_000);
        assert_eq!(budgets.max_wasm_stack_bytes, 524_288);
        assert_eq!(budgets.max_input_bytes, 262_144);
        assert_eq!(budgets.max_output_bytes, 1_048_576);
        assert_eq!(budgets.fuel, 10_000_000_000);
        assert_eq!(budgets.epoch_deadline_ticks, 250);
    }

    #[test]
    fn reduced_budgets_shrink_every_relevant_ceiling() {
        let budgets = reduced();
        let defaults = Budgets::default();
        assert!(budgets.fuel < defaults.fuel);
        assert!(budgets.epoch_deadline_ticks < defaults.epoch_deadline_ticks);
        assert!(budgets.max_module_bytes < defaults.max_module_bytes);
        assert!(budgets.max_input_bytes < defaults.max_input_bytes);
        assert!(budgets.max_output_bytes < defaults.max_output_bytes);
    }

    #[test]
    fn a_ticker_spawn_failure_is_surfaced_not_swallowed() {
        // The spawner is injectable so the failure path is testable without
        // exhausting host threads; `spawn` delegates to the real spawner and
        // maps its failure the same way.
        let exec = super::Executor::new(super::Backend::Native, Budgets::default())
            .expect("fixed engine config is valid");
        let failure =
            super::EpochTicker::spawn_with(exec.engine().clone(), super::DEFAULT_INTERVAL, |_| {
                Err(super::TickerSpawnError)
            });
        assert!(matches!(failure, Err(super::TickerSpawnError)));
    }
}
