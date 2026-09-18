//! The byte-transfer ABI machinery behind the export macros.
//!
//! The exports are pointer-shaped because that is the platform contract: the
//! host allocates a request buffer through `alloc`, writes the envelope, and
//! calls `handle`; the guest stores the outcome bytes and exposes them
//! through `result_ptr`/`result_len`. On wasm32 the pointers and lengths are
//! i32; the same code compiles and runs on the host, where tests drive it
//! with real pointers.

use std::mem;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::sync::Mutex;

use crate::HandlerFailure;
use crate::outcome::Outcome;
use crate::request::Request;

/// Status codes returned by `handle`.
pub const STATUS_OUTCOME_READY: i32 = 0;
pub const STATUS_MALFORMED_REQUEST: i32 = 1;
pub const STATUS_INTERNAL_ERROR: i32 = 2;

// The guest is single-threaded (no threads on the WASM target); the Mutex
// only satisfies Rust's requirements for a mutable static. A failed handle
// clears the slot so a host can never mistake a stale outcome for the
// current one.
static RESULT: Mutex<Option<Vec<u8>>> = Mutex::new(None);

/// Allocate a host-writable buffer of `len` bytes and transfer ownership to
/// the caller. `len == 0`, and a reserve failure, return null.
///
/// The allocation is intentionally leaked: the host writes the request into
/// it and passes the pointer to `handle`; guest memory as a whole is owned
/// by the embedder.
pub fn alloc(len: usize) -> *mut u8 {
    if len == 0 {
        return ptr::null_mut();
    }
    let mut buffer: Vec<u8> = Vec::new();
    // try_reserve instead of with_capacity so an allocation failure returns
    // null rather than aborting inside the ABI.
    if buffer.try_reserve_exact(len).is_err() {
        return ptr::null_mut();
    }
    let pointer = buffer.as_mut_ptr();
    mem::forget(buffer);
    pointer
}

/// Parse the request envelope, run the handler, and store the serialized
/// outcome. Returns [`STATUS_OUTCOME_READY`] when the stored bytes are the
/// handler's outcome, [`STATUS_MALFORMED_REQUEST`] for an undecodable
/// envelope or a handler-reported input-contract violation, and
/// [`STATUS_INTERNAL_ERROR`] otherwise. No panic crosses the boundary.
///
/// # Safety (embedder contract)
///
/// The embedder guarantees that `pointer` addresses `len` readable bytes for
/// the duration of the call (on the WASM target: a valid offset into the
/// linear memory). That is the C-level calling convention, so the Rust-level
/// `unsafe` marker is not part of this signature.
pub fn handle<F>(pointer: *const u8, len: usize, handler: F) -> i32
where
    F: FnOnce(Request) -> Result<Outcome, HandlerFailure>,
{
    if pointer.is_null() || len == 0 {
        clear_result();
        return STATUS_MALFORMED_REQUEST;
    }
    // SAFETY: the embedder contract above holds for every caller of this
    // function, host test or platform executor alike.
    let bytes = unsafe { std::slice::from_raw_parts(pointer, len) };
    match catch_unwind(AssertUnwindSafe(|| dispatch(bytes, handler))) {
        Ok(Ok(document)) => {
            store_result(document);
            STATUS_OUTCOME_READY
        }
        Ok(Err(status)) => {
            clear_result();
            status
        }
        Err(_) => {
            clear_result();
            STATUS_INTERNAL_ERROR
        }
    }
}

/// Pointer to the stored outcome bytes, or null when no outcome is stored.
/// The pointer stays valid until the next successful `handle` replaces the
/// slot, which is the caller's read window on this single-threaded guest.
pub fn result_ptr() -> *const u8 {
    lock_slot(|stored| match stored.as_deref() {
        Some(bytes) if !bytes.is_empty() => bytes.as_ptr(),
        _ => ptr::null(),
    })
}

/// Length in bytes of the stored outcome, or 0 when no outcome is stored.
pub fn result_len() -> usize {
    lock_slot(|stored| stored.as_ref().map_or(0, Vec::len))
}

/// Decode, evaluate, and serialize: the pointer-free core of `handle`, so it
/// is testable without the embedder contract.
fn dispatch<F>(bytes: &[u8], handler: F) -> Result<Vec<u8>, i32>
where
    F: FnOnce(Request) -> Result<Outcome, HandlerFailure>,
{
    let request = Request::from_envelope(bytes).map_err(failure_status)?;
    let outcome = handler(request).map_err(failure_status)?;
    Ok(outcome.to_document())
}

fn failure_status(failure: HandlerFailure) -> i32 {
    match failure {
        HandlerFailure::MalformedRequest => STATUS_MALFORMED_REQUEST,
        HandlerFailure::InternalError => STATUS_INTERNAL_ERROR,
    }
}

/// Read the slot under the lock. A poisoned lock only means a panic raced a
/// store; the slot contents are still valid to read.
fn lock_slot<T>(read: impl FnOnce(&Option<Vec<u8>>) -> T) -> T {
    let guard = RESULT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    read(&guard)
}

fn store_result(bytes: Vec<u8>) {
    *RESULT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(bytes);
}

fn clear_result() {
    *RESULT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
}
