// SPDX-License-Identifier: Apache-2.0

//! The local hook program executor (`rhai` and `wasm` features).
//!
//! A local hook program is a reviewed Rhai script or WASM module a product's
//! compiled package carries. The product hands each one over as a
//! [`LocalHookProgram`], which admits it only when its recorded identity
//! digest covers its own bytes and it speaks the one handler ABI version one
//! defines. The product then registers the admitted programs in a
//! [`LocalHookHandlers`] set under the package revision it is running, and
//! the delivery worker resolves a delivery row against that set: the row's
//! compiled delivery id, package revision, handler kind, and handler digest
//! must all match before anything runs, so a row captured under an older
//! package is left for the deployment holding that package rather than
//! served by whatever program now carries the same id.
//!
//! A product that enables neither engine compiles neither, and a program of a
//! kind this build does not execute is refused as a source error rather than
//! read as the other engine's input.

#[cfg(feature = "rhai")]
mod rhai;
#[cfg(feature = "wasm")]
mod wasm;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

#[cfg(feature = "rhai")]
pub use self::rhai::{
    compile_rhai_hook, RHAI_HOOK_ENTRYPOINT, RHAI_HOOK_MAX_ARRAY_ITEMS, RHAI_HOOK_MAX_CALL_DEPTH,
    RHAI_HOOK_MAX_EXPRESSION_DEPTH, RHAI_HOOK_MAX_MAP_ENTRIES, RHAI_HOOK_MAX_OPERATIONS,
    RHAI_HOOK_MAX_SOURCE_BYTES, RHAI_HOOK_MAX_STRING_BYTES, RHAI_HOOK_MAX_VALUE_DEPTH,
    RHAI_HOOK_PROFILE,
};
#[cfg(feature = "wasm")]
pub use self::wasm::{
    Backend, WasmHookBudgets, WasmHookRuntime, WasmHookRuntimeError, WASM_HOOK_FUEL_PER_CALL,
    WASM_HOOK_RETAINED_MODULES,
};
use crate::{ErrorCategory, HookHandlerKind, HOOK_HANDLER_ABI_V1};

/// Why a program was not admitted as a local hook program.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LocalHookProgramRefused {
    /// `url` is the remote kind and carries no program.
    #[error("a url handler carries no local program")]
    NotLocal,
    /// The program speaks an ABI this contract version does not define.
    #[error("the program does not speak the version one hook handler ABI")]
    UnsupportedAbi,
    /// The recorded identity digest does not cover the program's own bytes.
    #[error("the recorded program digest does not cover the program bytes")]
    DigestMismatch,
}

/// One reviewed local program, with the identity and budgets its delivery
/// rows are bound to.
#[derive(Clone)]
pub struct LocalHookProgram {
    kind: HookHandlerKind,
    digest: String,
    bytes: Arc<[u8]>,
    attempt_timeout: Duration,
    maximum_attempts: u8,
}

impl std::fmt::Debug for LocalHookProgram {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalHookProgram")
            .field("kind", &self.kind)
            .field("digest", &self.digest)
            .field("bytes", &self.bytes.len())
            .field("attempt_timeout", &self.attempt_timeout)
            .field("maximum_attempts", &self.maximum_attempts)
            .finish()
    }
}

impl LocalHookProgram {
    /// Admit one program the product's compiled package carries.
    ///
    /// This is the one place the digest is recomputed. The delivery capture
    /// writes the recorded digest into the row and the worker compares the
    /// row against the program admitted here, so a substituted program
    /// cannot inherit another program's retained rows. Recomputing at
    /// admission rather than per delivery keeps a large module off the
    /// per-attempt path.
    ///
    /// # Errors
    ///
    /// [`LocalHookProgramRefused`] for a `url` kind, another ABI, or a
    /// recorded digest that is not `sha256:` over exactly `bytes`.
    pub fn new(
        kind: HookHandlerKind,
        abi: &str,
        recorded_digest: &str,
        bytes: impl Into<Arc<[u8]>>,
        attempt_timeout: Duration,
        maximum_attempts: u8,
    ) -> Result<Self, LocalHookProgramRefused> {
        if kind == HookHandlerKind::Url {
            return Err(LocalHookProgramRefused::NotLocal);
        }
        if abi != HOOK_HANDLER_ABI_V1 {
            return Err(LocalHookProgramRefused::UnsupportedAbi);
        }
        let bytes = bytes.into();
        if program_digest(&bytes) != recorded_digest {
            return Err(LocalHookProgramRefused::DigestMismatch);
        }
        Ok(Self {
            kind,
            digest: recorded_digest.to_owned(),
            bytes,
            attempt_timeout,
            maximum_attempts,
        })
    }

    /// The program's kind, never [`HookHandlerKind::Url`].
    #[must_use]
    pub const fn kind(&self) -> HookHandlerKind {
        self.kind
    }

    /// The `sha256:<hex>` identity digest of the program bytes.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Deployed per-attempt timeout.
    #[must_use]
    pub const fn attempt_timeout(&self) -> Duration {
        self.attempt_timeout
    }

    /// Deployed maximum attempt count.
    #[must_use]
    pub const fn maximum_attempts(&self) -> u8 {
        self.maximum_attempts
    }
}

/// The `sha256:<lowercase hex>` identity digest of a program's bytes, the
/// spelling a product records at compile time.
#[must_use]
pub fn program_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let hash = Sha256::digest(bytes);
    let mut digest = String::with_capacity(7 + hash.len() * 2);
    digest.push_str("sha256:");
    for byte in hash {
        let _ = write!(digest, "{byte:02x}");
    }
    digest
}

/// Every local hook program the running package holds, keyed by compiled
/// delivery id, plus the engines that run them.
#[derive(Debug)]
pub struct LocalHookHandlers {
    package_revision: String,
    programs: BTreeMap<String, Arc<LocalHookProgram>>,
    #[cfg(feature = "wasm")]
    wasm: Option<Arc<WasmHookRuntime>>,
}

impl LocalHookHandlers {
    /// An empty set for the package running under `package_revision`.
    #[must_use]
    pub fn new(package_revision: &str) -> Self {
        Self {
            package_revision: package_revision.to_owned(),
            programs: BTreeMap::new(),
            #[cfg(feature = "wasm")]
            wasm: None,
        }
    }

    /// Register the admitted program for one compiled delivery id.
    pub fn insert(&mut self, compiled_delivery_id: &str, program: LocalHookProgram) {
        self.programs
            .insert(compiled_delivery_id.to_owned(), Arc::new(program));
    }

    /// Run WASM programs on `runtime`. Without one, a WASM program's run is
    /// an execution refusal: evaluation before the product installs its
    /// runtime is a wiring fault, never served on default budgets.
    #[cfg(feature = "wasm")]
    #[must_use]
    pub fn with_wasm_runtime(mut self, runtime: Arc<WasmHookRuntime>) -> Self {
        self.wasm = Some(runtime);
        self
    }

    /// Whether no program is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.programs.is_empty()
    }

    /// The runnable handler for one delivery row's recorded binding, or
    /// `None` when the running package does not hold that exact program under
    /// that exact identity.
    #[must_use]
    pub fn resolve(
        &self,
        kind: HookHandlerKind,
        compiled_delivery_id: &str,
        package_revision: &str,
        handler_digest: &str,
    ) -> Option<LocalHookHandler> {
        if package_revision != self.package_revision {
            return None;
        }
        let program = self.programs.get(compiled_delivery_id)?;
        if program.digest != handler_digest || program.kind != kind {
            return None;
        }
        Some(LocalHookHandler {
            program: Arc::clone(program),
            #[cfg(feature = "wasm")]
            wasm: self.wasm.clone(),
        })
    }

    /// [`Self::resolve`] for the binding a delivery row recorded.
    #[cfg(feature = "postgres")]
    #[must_use]
    pub fn handler(
        &self,
        binding: crate::delivery::HookHandlerBinding<'_>,
    ) -> Option<LocalHookHandler> {
        self.resolve(
            binding.kind,
            binding.compiled_delivery_id,
            binding.package_revision,
            binding.handler_digest,
        )
    }
}

/// One local hook program bound to one delivery row.
#[derive(Clone, Debug)]
pub struct LocalHookHandler {
    program: Arc<LocalHookProgram>,
    #[cfg(feature = "wasm")]
    wasm: Option<Arc<WasmHookRuntime>>,
}

impl LocalHookHandler {
    /// The bound program.
    #[must_use]
    pub fn program(&self) -> &LocalHookProgram {
        &self.program
    }

    /// Run the program over `envelope` with `remaining` budget on the calling
    /// thread, answering with the handler message bytes it produced. An empty
    /// answer is the `none` answer.
    ///
    /// # Errors
    ///
    /// The shared failure category: the deadline, an exhausted budget, a
    /// failing program, or a program this build cannot run.
    pub fn run_blocking(
        &self,
        envelope: &[u8],
        remaining: Duration,
    ) -> Result<Vec<u8>, ErrorCategory> {
        let Some(deadline) = Instant::now().checked_add(remaining) else {
            return Err(ErrorCategory::Deadline);
        };
        match self.program.kind {
            #[cfg(feature = "rhai")]
            HookHandlerKind::Rhai => {
                self::rhai::run_rhai_hook(&self.program.bytes, envelope, deadline)
            }
            #[cfg(feature = "wasm")]
            HookHandlerKind::Wasm => self.wasm.as_ref().ok_or(ErrorCategory::Execution)?.run(
                &self.program.digest,
                &self.program.bytes,
                envelope,
                deadline,
            ),
            // A kind this build does not execute is refused rather than read
            // as the other engine's input.
            _ => {
                let _ = (envelope, deadline);
                Err(ErrorCategory::Source)
            }
        }
    }
}

#[cfg(feature = "postgres")]
#[async_trait::async_trait]
impl crate::delivery::HookHandler for LocalHookHandler {
    fn handler_digest(&self) -> &str {
        &self.program.digest
    }

    fn attempt_timeout(&self) -> Duration {
        self.program.attempt_timeout
    }

    fn maximum_attempts(&self) -> u8 {
        self.program.maximum_attempts
    }

    async fn run(
        &self,
        envelope: &[u8],
        remaining: Duration,
    ) -> Result<Vec<u8>, crate::delivery::HandlerRunFailure> {
        let handler = self.clone();
        let envelope = envelope.to_vec();
        // Both engines run to completion on the calling thread, so the call
        // goes to the blocking pool rather than holding a reactor thread for
        // the length of a run.
        tokio::task::spawn_blocking(move || handler.run_blocking(&envelope, remaining))
            .await
            .map_err(|_| ErrorCategory::Execution)?
            .map_err(crate::delivery::HandlerRunFailure::from)
    }
}

#[cfg(test)]
mod tests;
