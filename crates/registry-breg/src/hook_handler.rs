// SPDX-License-Identifier: Apache-2.0

//! Base Registry Engine's local hook handler seam.
//!
//! `registry-platform-hooks` owns the delivery worker and the handler
//! message, and deliberately holds no executor: a delivery row that binds a
//! `rhai` or `wasm` handler is run through this seam, so the reviewed
//! program, the script engine, and the module format stay on the product
//! side of the boundary.
//!
//! The registry below is built once from the running compiled package. A
//! delivery row names its compiled delivery id, the package revision it was
//! captured under, and the identity digest of the program bound to it. All
//! three must match the running package before anything runs: a row captured
//! under an older package is left for the deployment holding that package
//! rather than served by whatever program now carries the same id.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use registry_platform_hooks::delivery::{HandlerRunFailure, HookHandler, HookHandlerBinding};
use registry_platform_hooks::{ErrorCategory, HOOK_HANDLER_ABI_V1, MAX_OUTPUT_BYTES};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::immediate_actions::hex_lower;
use crate::model::{CompiledHookHandler, CompiledHookHandlerKind, CompiledRegistry};

/// One reviewed program, with the identity and budgets its delivery rows are
/// bound to.
struct HookProgram {
    kind: CompiledHookHandlerKind,
    digest: String,
    bytes: Vec<u8>,
    attempt_timeout: Duration,
    maximum_attempts: u8,
}

/// Every local hook handler the running package holds, keyed by compiled
/// delivery id.
pub struct HookHandlerRegistry {
    package_revision: String,
    programs: BTreeMap<String, Arc<HookProgram>>,
}

impl HookHandlerRegistry {
    /// Collect the local handlers in `compiled`, refusing any whose recorded
    /// identity digest does not cover its own bytes and any whose ABI is not
    /// the one handler contract version one defines.
    ///
    /// This is the one place the digest is recomputed. The delivery capture
    /// writes it into the row and the worker compares the row against the
    /// program resolved here, so a substituted program cannot inherit another
    /// program's retained rows. Recomputing here rather than per delivery
    /// keeps a multi-megabyte module off the per-attempt path.
    #[must_use]
    pub fn new(compiled: &CompiledRegistry, package_revision: &str) -> Self {
        let programs = compiled
            .event_deliveries()
            .deliveries
            .iter()
            .filter_map(|delivery| {
                let handler = delivery.handler.as_ref()?;
                let digest = verified_digest(handler)?;
                Some((
                    delivery.id.clone(),
                    Arc::new(HookProgram {
                        kind: handler.kind,
                        digest,
                        bytes: handler.bytes.clone(),
                        attempt_timeout: Duration::from_millis(u64::from(
                            delivery.attempt_timeout_ms,
                        )),
                        maximum_attempts: delivery.maximum_attempts,
                    }),
                ))
            })
            .collect();
        Self {
            package_revision: package_revision.to_owned(),
            programs,
        }
    }

    /// The runnable handler for one delivery row, or `None` when the running
    /// package does not hold that exact program under that exact identity.
    #[must_use]
    pub fn handler(&self, binding: HookHandlerBinding<'_>) -> Option<BregHookHandler> {
        if binding.package_revision != self.package_revision {
            return None;
        }
        let program = self.programs.get(binding.compiled_delivery_id)?;
        if program.digest != binding.handler_digest || program.kind.shared() != binding.kind {
            return None;
        }
        Some(BregHookHandler {
            program: Arc::clone(program),
        })
    }
}

/// The recorded identity digest of `handler`, or `None` when it does not
/// cover the program's own bytes or the program speaks an ABI this contract
/// version does not define.
fn verified_digest(handler: &CompiledHookHandler) -> Option<String> {
    if handler.abi != HOOK_HANDLER_ABI_V1 {
        return None;
    }
    let digest = format!("sha256:{}", hex_lower(&Sha256::digest(&handler.bytes)));
    (digest == handler.digest).then_some(digest)
}

/// One local hook handler bound to one delivery row.
pub struct BregHookHandler {
    program: Arc<HookProgram>,
}

#[async_trait::async_trait]
impl HookHandler for BregHookHandler {
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
    ) -> Result<Vec<u8>, HandlerRunFailure> {
        let program = Arc::clone(&self.program);
        let envelope = envelope.to_vec();
        // Both engines run to completion on the calling thread, so the call
        // goes to the blocking pool rather than holding a worker reactor
        // thread for the length of a handler run.
        tokio::task::spawn_blocking(move || run_program(&program, &envelope, remaining))
            .await
            .map_err(|_| failure(ErrorCategory::Execution))?
    }
}

const fn failure(category: ErrorCategory) -> HandlerRunFailure {
    HandlerRunFailure { category }
}

fn run_program(
    program: &HookProgram,
    envelope: &[u8],
    remaining: Duration,
) -> Result<Vec<u8>, HandlerRunFailure> {
    let Some(deadline) = Instant::now().checked_add(remaining) else {
        return Err(failure(ErrorCategory::Deadline));
    };
    match program.kind {
        CompiledHookHandlerKind::Rhai => run_rhai_hook(&program.bytes, envelope, deadline),
        #[cfg(feature = "wasm")]
        CompiledHookHandlerKind::Wasm => crate::wasm_runtime::evaluate_wasm_hook(
            &program.digest,
            &program.bytes,
            envelope,
            deadline,
        )
        .map_err(failure),
        // A module tagged with a backend this build does not execute is
        // refused rather than interpreted as the other backend's source,
        // which is the rule the action handler's admission already applies.
        #[cfg(not(feature = "wasm"))]
        CompiledHookHandlerKind::Wasm => Err(failure(ErrorCategory::Source)),
    }
}

/// Run one reviewed Rhai hook handler: the envelope in as the entry point's
/// one argument, one canonical handler message out.
fn run_rhai_hook(
    source_bytes: &[u8],
    envelope: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, HandlerRunFailure> {
    use registry_platform_script::rhai as platform;

    let source = std::str::from_utf8(source_bytes).map_err(|_| failure(ErrorCategory::Source))?;
    let ast = crate::rhai_planner::compile_entrypoint_detailed(source, "handle")
        .map_err(|_| failure(ErrorCategory::Source))?;
    let document: Value = registry_platform_canonical_json::parse_json_strict(envelope)
        .map_err(|_| failure(ErrorCategory::Source))?;
    let context = crate::rhai_planner::json_to_dynamic(&document, 0).map_err(|error| {
        if error == crate::rhai_planner::ChangeRequestPlannerError::Resource {
            failure(ErrorCategory::Resource)
        } else {
            failure(ErrorCategory::Source)
        }
    })?;
    if Instant::now() >= deadline {
        return Err(failure(ErrorCategory::Deadline));
    }
    let engine = crate::rhai_planner::engine(Some(deadline));
    let answer =
        platform::call_with_fresh_scope(&engine, &ast, "handle", (context,)).map_err(|error| {
            if Instant::now() >= deadline {
                failure(ErrorCategory::Deadline)
            } else if platform::classify_failure(&error)
                == platform::RhaiFailureCategory::ResourceExhausted
            {
                failure(ErrorCategory::Resource)
            } else {
                failure(ErrorCategory::Execution)
            }
        })?;
    encode_rhai_answer(&answer)
}

/// Turn the entry point's returned value into the canonical message bytes the
/// delivery worker parses.
///
/// A Rhai value is not JSON, so the bytes are built here rather than returned
/// by the script: the worker requires bytes that equal their own
/// canonicalization, and a script cannot be asked to order its own keys.
fn encode_rhai_answer(answer: &rhai::Dynamic) -> Result<Vec<u8>, HandlerRunFailure> {
    if answer.is_unit() {
        // A handler that returns nothing proposes nothing; the worker reads
        // an empty answer as the `none` message.
        return Ok(Vec::new());
    }
    let value: Value =
        rhai::serde::from_dynamic(answer).map_err(|_| failure(ErrorCategory::Execution))?;
    let bytes = registry_platform_canonical_json::canonicalize_json(&value)
        .map_err(|_| failure(ErrorCategory::Execution))?;
    if bytes.len() > MAX_OUTPUT_BYTES {
        return Err(failure(ErrorCategory::Resource));
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "tests/hook_handler_tests.rs"]
mod hook_handler_tests;
