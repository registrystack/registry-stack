// SPDX-License-Identifier: Apache-2.0
//! The synchronous-script / async-host bridge.
//!
//! Rhai is synchronous; the host seam is async. We run the compiled script on
//! [`tokio::task::spawn_blocking`], guarded by a dedicated [`Semaphore`] permit
//! (admission control independent of tokio's shared blocking pool). The
//! script's `source.get` does **not** touch async code: it sends a
//! [`SourceGetCommand`] over an mpsc channel to an async *dispatch loop* run by
//! [`ScriptEngine::execute`], which calls the host, deadline-bounds the call,
//! and **always** replies on a oneshot so the blocking `blocking_recv` can never
//! wedge.
//!
//! Termination is driven by [`rhai::Engine::on_progress`] checking an `Instant`
//! deadline and an `Arc<AtomicBool>` cancel flag. `max_http_calls` is enforced
//! host-side, before dispatch. Outcome counters classify the terminal state.
//!
//! # Outcome integrity
//!
//! A script must not be able to forge its own terminal classification. The code
//! that actually forces termination — the progress guard, the host-call budget
//! guard, the path gate, and the dispatcher result handling — records the
//! authoritative cause in a host-owned, out-of-band cell the script cannot
//! reach. Classification reads that cell first and only treats a script-thrown
//! value as a genuine `Runtime` error when the cell is empty. The opaque tokens
//! the guards return to Rhai exist solely to unwind the script; their contents
//! are never parsed.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rhai::{Dynamic, Engine, EvalAltResult, Position, Scope};
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};

use crate::convert::{dynamic_to_json, json_to_dynamic, ConvertCaps};
use crate::counters::ExecCounters;
use crate::ctx::ScriptCtx;
use crate::engine::{apply_hardening, ScriptEngine};
use crate::error::{BudgetKind, SourceScriptError};
use crate::host::{ScriptSourceHost, SourceResponse};
use crate::output::validate_records;
use crate::path::canonicalize_target_relative_path;

/// The authoritative terminal cause of a run, recorded by the code that
/// actually forces termination — the progress guard, the host-call budget
/// guard, the path gate, or the dispatcher result handling.
///
/// This is the integrity fix for outcome forgery: the cause is written into a
/// host-owned, out-of-band [`OutcomeCell`] the script cannot reach, and
/// classification reads it FIRST. A value the script merely `throw`s can never
/// masquerade as one of these, because the thrown string is consulted only when
/// the cell is empty. Each variant carries the full data needed to reconstruct
/// the correct [`SourceScriptError`] (e.g. the real `BudgetKind` and the real
/// HTTP status), so nothing is lost the way a stringly-typed tag would lose it.
#[derive(Debug, Clone)]
enum HostOutcome {
    /// The wall-clock deadline elapsed (progress guard).
    Deadline,
    /// The run was cancelled via the cancel flag (progress guard). Surfaced as
    /// a deadline, matching the prior contract.
    Cancelled,
    /// A budget was exhausted; carries the precise kind (fixes the old tag that
    /// collapsed every host-side budget to `HttpCalls`).
    Budget(BudgetKind),
    /// The upstream returned a non-2xx status; carries the real status code.
    HttpStatus(u16),
    /// The transport to the upstream failed.
    HttpTransport,
    /// The host denied the request (e.g. a path that failed canonicalization).
    HostDenied { reason: String },
    /// A value crossing the boundary had an unacceptable type/shape.
    Type { detail: String },
}

impl HostOutcome {
    /// Reconstruct the classified error this outcome represents.
    fn into_error(self) -> SourceScriptError {
        match self {
            HostOutcome::Deadline | HostOutcome::Cancelled => SourceScriptError::Deadline,
            HostOutcome::Budget(kind) => SourceScriptError::Budget { kind },
            HostOutcome::HttpStatus(status) => SourceScriptError::HttpStatus { status },
            HostOutcome::HttpTransport => SourceScriptError::HttpTransport,
            HostOutcome::HostDenied { reason } => SourceScriptError::HostDenied { reason },
            HostOutcome::Type { detail } => SourceScriptError::Type { detail },
        }
    }
}

/// A host-owned, single-writer cell holding the authoritative [`HostOutcome`].
///
/// The script runs single-threaded on the blocking thread, so the progress
/// guard, the capability, and the path gate never write concurrently; the
/// `Mutex` simply provides safe cross-thread visibility to `classify`, which
/// reads it on the async side after the join. The FIRST cause wins: once the
/// reason for termination is recorded, later writes (e.g. a follow-on guard
/// trip during unwind) do not overwrite it.
#[derive(Clone, Default)]
struct OutcomeCell(Arc<Mutex<Option<HostOutcome>>>);

impl OutcomeCell {
    fn new() -> Self {
        Self::default()
    }

    /// Record the cause if none is set yet (first-writer-wins).
    fn set(&self, outcome: HostOutcome) {
        let mut slot = self.0.lock().expect("outcome cell poisoned");
        if slot.is_none() {
            *slot = Some(outcome);
        }
    }

    /// Take the recorded cause, if any.
    fn take(&self) -> Option<HostOutcome> {
        self.0.lock().expect("outcome cell poisoned").take()
    }
}

/// Namespace marker for the `source` value in scope. `source.get(...)`
/// desugars to `get(SourceNs, ...)`.
#[derive(Debug, Clone, Copy)]
struct SourceNs;

/// A request from the (blocking) script thread to the async dispatch loop.
struct SourceGetCommand {
    target: String,
    /// The canonicalized, target-relative path. The capability runs
    /// [`canonicalize_target_relative_path`] before constructing this command,
    /// so a command never carries a raw (un-canonicalized) script path.
    path: String,
    query: Value,
    reply: oneshot::Sender<Result<SourceResponse, SourceScriptError>>,
}

impl ScriptEngine {
    /// Execute the compiled script against `host` with the minimized `ctx`.
    ///
    /// Returns the validated array of record objects on success. On failure
    /// returns the classified [`SourceScriptError`] and increments the matching
    /// outcome counter.
    pub async fn execute(
        &self,
        host: Arc<dyn ScriptSourceHost>,
        ctx: ScriptCtx,
    ) -> Result<Vec<Value>, SourceScriptError> {
        self.execute_inner(host, ctx, Arc::new(AtomicBool::new(false)))
            .await
    }

    /// Like [`ScriptEngine::execute`], but sets `finished` to `true` when the
    /// blocking script thread actually exits. Used by tests to prove that a
    /// timed-out script's thread really stops (and thus releases its permit),
    /// not just that the caller stopped waiting.
    #[doc(hidden)]
    pub async fn execute_observing(
        &self,
        host: Arc<dyn ScriptSourceHost>,
        ctx: ScriptCtx,
        finished: Arc<AtomicBool>,
    ) -> Result<Vec<Value>, SourceScriptError> {
        self.execute_inner(host, ctx, finished).await
    }

    async fn execute_inner(
        &self,
        host: Arc<dyn ScriptSourceHost>,
        ctx: ScriptCtx,
        finished: Arc<AtomicBool>,
    ) -> Result<Vec<Value>, SourceScriptError> {
        let policy = self.policy;
        let caps = ConvertCaps::from_limits(&policy.limits);

        // --- admission control: a dedicated permit, never tokio's shared pool ---
        let permit = match self.semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                ExecCounters::inc(&self.counters.saturated);
                return Err(SourceScriptError::Budget {
                    kind: BudgetKind::Saturated,
                });
            }
        };

        let ctx_json = ctx.build();
        let ctx_dynamic = json_to_dynamic(&ctx_json, caps)?;

        // --- per-run termination state ---
        let deadline = Instant::now() + policy.timeout;
        let cancel = Arc::new(AtomicBool::new(false));

        // --- per-run authoritative outcome cell (M1) ---
        // Written only by host-trusted code (progress guard, capability budget
        // guard, path gate, dispatcher result handling); read by `classify`.
        let outcome = OutcomeCell::new();

        // --- per-run host-call budget ---
        let http_calls = Arc::new(AtomicU32::new(0));
        let max_http_calls = policy.max_http_calls;

        // --- the bridge channel ---
        let (tx, mut rx) = mpsc::channel::<SourceGetCommand>(16);

        // --- build a fresh hardened engine and layer on the per-run pieces ---
        let mut engine = Engine::new();
        apply_hardening(&mut engine, &policy.limits);
        install_progress_guard(&mut engine, deadline, cancel.clone(), outcome.clone());
        install_source_capability(
            &mut engine,
            tx,
            http_calls.clone(),
            max_http_calls,
            caps,
            outcome.clone(),
        );

        let ast = self.ast.clone();
        let entrypoint = self.entrypoint.clone();
        let max_output_bytes = policy.max_output_bytes;

        // --- run the (synchronous) script on a dedicated blocking thread ---
        let blocking = tokio::task::spawn_blocking(move || {
            let _permit = permit; // released exactly when this closure exits
            let _finish = SetOnDrop(finished); // flips `finished` on exit
            run_script_blocking(engine, ast, entrypoint, ctx_dynamic, caps, max_output_bytes)
        });

        // --- async dispatch loop: drive host calls until the script finishes ---
        // Each call is deadline-bounded so a slow host cannot outlive the
        // caller deadline, and is ALWAYS answered so blocking_recv unblocks.
        // The loop ends naturally once the script drops `tx` (i.e. finishes).
        let dispatch = async move {
            while let Some(cmd) = rx.recv().await {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let per_call = if remaining.is_zero() {
                    Duration::from_millis(1)
                } else {
                    remaining
                };
                let result = match tokio::time::timeout(
                    per_call,
                    host.source_get(&cmd.target, &cmd.path, cmd.query.clone()),
                )
                .await
                {
                    Ok(r) => r,
                    Err(_elapsed) => Err(SourceScriptError::Deadline),
                };
                let _ = cmd.reply.send(result);
            }
        };

        // Run the dispatch loop and the blocking join together, under the
        // wall-clock budget. `join!` resolves when the script finishes (it then
        // drops `tx`, ending the dispatch loop). If the script never finishes
        // (e.g. infinite loop), the timeout fires; we then set the cancel flag
        // and the detached blocking thread unwinds via `on_progress`.
        let work = async {
            let (join, ()) = tokio::join!(blocking, dispatch);
            join
        };

        let joined = match tokio::time::timeout(policy.timeout, work).await {
            Ok(Ok(Ok(records))) => JoinOutcome::Ok(records),
            Ok(Ok(Err(e))) => JoinOutcome::ScriptErr(e),
            // Distinguish a genuine panic from a task cancellation (m1): only an
            // actual panic is reported as `Panic`; a cancelled join is treated
            // as a deadline/abort, the same class as a forced termination.
            Ok(Err(je)) if je.is_panic() => JoinOutcome::Panicked,
            Ok(Err(je)) if je.is_cancelled() => JoinOutcome::Cancelled,
            Ok(Err(_)) => JoinOutcome::Panicked,
            Err(_elapsed) => JoinOutcome::TimedOut,
        };

        // --- classify the outcome ---
        self.classify(joined, &cancel, &outcome)
    }

    /// Translate the raw join outcome into a result + counter increment.
    ///
    /// The authoritative [`OutcomeCell`] takes precedence over any error the
    /// script surfaced: if a host-trusted writer recorded a cause, that cause is
    /// the classification. Only when the cell is empty does a script-level error
    /// (a genuine `throw`, a Rhai resource limit, etc.) decide the outcome. This
    /// is what stops a script from forging its own outcome/problem-code.
    fn classify(
        &self,
        outcome: JoinOutcome,
        cancel: &Arc<AtomicBool>,
        cell: &OutcomeCell,
    ) -> Result<Vec<Value>, SourceScriptError> {
        match outcome {
            JoinOutcome::Ok(records) => {
                ExecCounters::inc(&self.counters.completed);
                Ok(records)
            }
            JoinOutcome::ScriptErr(err) => {
                // Trust the out-of-band cause first; fall back to the script
                // error only if no host-trusted writer set one.
                let err = match cell.take() {
                    Some(authoritative) => authoritative.into_error(),
                    None => err,
                };
                self.bump_counter_for(&err);
                Err(err)
            }
            JoinOutcome::TimedOut => {
                cancel.store(true, Ordering::SeqCst);
                ExecCounters::inc(&self.counters.timed_out);
                Err(SourceScriptError::Deadline)
            }
            JoinOutcome::Cancelled => {
                cancel.store(true, Ordering::SeqCst);
                ExecCounters::inc(&self.counters.timed_out);
                Err(SourceScriptError::Deadline)
            }
            JoinOutcome::Panicked => {
                ExecCounters::inc(&self.counters.budget_terminated);
                Err(SourceScriptError::Panic)
            }
        }
    }

    fn bump_counter_for(&self, err: &SourceScriptError) {
        match err {
            SourceScriptError::Deadline => ExecCounters::inc(&self.counters.timed_out),
            SourceScriptError::Budget {
                kind: BudgetKind::Saturated,
            } => ExecCounters::inc(&self.counters.saturated),
            SourceScriptError::Budget { .. } => ExecCounters::inc(&self.counters.budget_terminated),
            SourceScriptError::HttpTransport | SourceScriptError::HttpStatus { .. } => {
                ExecCounters::inc(&self.counters.transport_failed)
            }
            _ => ExecCounters::inc(&self.counters.budget_terminated),
        }
    }
}

/// The terminal state of a single execution before classification.
enum JoinOutcome {
    Ok(Vec<Value>),
    ScriptErr(SourceScriptError),
    TimedOut,
    /// The blocking join future was cancelled (distinct from a panic, m1).
    Cancelled,
    Panicked,
}

/// Install the `on_progress` termination guard: abort on cancel or deadline.
///
/// The guard records the authoritative cause in the out-of-band [`OutcomeCell`]
/// *before* returning the abort token. Rhai still needs a `Dynamic` token to
/// terminate the script (it surfaces as `ErrorTerminated`), but the token's
/// contents are no longer parsed for classification — the cell is. The token
/// text is therefore opaque and not script-meaningful.
fn install_progress_guard(
    engine: &mut Engine,
    deadline: Instant,
    cancel: Arc<AtomicBool>,
    outcome: OutcomeCell,
) {
    engine.on_progress(move |_ops: u64| {
        if cancel.load(Ordering::Relaxed) {
            outcome.set(HostOutcome::Cancelled);
            return Some(Dynamic::from("__terminated__"));
        }
        if Instant::now() >= deadline {
            outcome.set(HostOutcome::Deadline);
            return Some(Dynamic::from("__terminated__"));
        }
        None
    });
}

/// Register the script-visible `source.get(target, path, query)` capability.
///
/// `source` is a [`SourceNs`] marker pushed into scope; `source.get(...)`
/// desugars to `get(SourceNs, ...)`. The function is synchronous: it counts
/// against the HTTP budget, **canonicalizes the path** (the traversal gate),
/// sends a [`SourceGetCommand`], and blocks on the reply. The dispatcher always
/// answers, so the block cannot wedge.
///
/// Every failure path records the authoritative cause in the out-of-band
/// [`OutcomeCell`] and then unwinds with an opaque token (see [`host_abort`]);
/// the token text is never parsed, so a script cannot forge any of these
/// outcomes by throwing a lookalike string.
fn install_source_capability(
    engine: &mut Engine,
    tx: mpsc::Sender<SourceGetCommand>,
    http_calls: Arc<AtomicU32>,
    max_http_calls: u32,
    caps: ConvertCaps,
    outcome: OutcomeCell,
) {
    engine.register_type_with_name::<SourceNs>("SourceNs");
    engine.register_fn(
        "get",
        move |_ns: SourceNs,
              target: rhai::ImmutableString,
              path: rhai::ImmutableString,
              query: rhai::Map|
              -> Result<Dynamic, Box<EvalAltResult>> {
            // Host-side budget: count BEFORE dispatch; exceed -> Budget error.
            let n = http_calls.fetch_add(1, Ordering::SeqCst) + 1;
            if n > max_http_calls {
                return Err(host_abort(
                    &outcome,
                    HostOutcome::Budget(BudgetKind::HttpCalls),
                ));
            }

            // Traversal gate (B2): canonicalize the script-supplied path BEFORE
            // building the command. On rejection, do NOT dispatch — record a
            // HostDenied outcome and unwind. The host therefore only ever sees a
            // path that has passed canonicalization.
            let canonical_path = match canonicalize_target_relative_path(&path) {
                Ok(p) => p,
                Err(_) => {
                    return Err(host_abort(
                        &outcome,
                        HostOutcome::HostDenied {
                            reason: "path failed canonicalization".into(),
                        },
                    ));
                }
            };

            // The query map is converted to JSON, bounded by the caps.
            let query_dynamic = Dynamic::from_map(query);
            let query_json = match dynamic_to_json(&query_dynamic, caps) {
                Ok(j) => j,
                Err(e) => {
                    return Err(host_abort(
                        &outcome,
                        HostOutcome::Type {
                            detail: type_detail(&e),
                        },
                    ));
                }
            };

            let (reply_tx, reply_rx) = oneshot::channel();
            let cmd = SourceGetCommand {
                target: target.to_string(),
                path: canonical_path,
                query: query_json,
                reply: reply_tx,
            };
            // If the dispatcher is gone, fail cleanly rather than wedging.
            if tx.blocking_send(cmd).is_err() {
                return Err(host_abort(&outcome, HostOutcome::HttpTransport));
            }
            match reply_rx.blocking_recv() {
                Ok(Ok(resp)) => map_response_to_dynamic(resp, caps, &outcome),
                Ok(Err(host_err)) => Err(host_abort(&outcome, host_outcome_for(host_err))),
                Err(_recv) => Err(host_abort(&outcome, HostOutcome::HttpTransport)),
            }
        },
    );
}

/// Map a successful host response to the value the script receives. A non-2xx
/// status records an `HttpStatus` outcome (with the real code) and unwinds, so
/// the caller classifies it as [`SourceScriptError::HttpStatus`].
fn map_response_to_dynamic(
    resp: SourceResponse,
    caps: ConvertCaps,
    outcome: &OutcomeCell,
) -> Result<Dynamic, Box<EvalAltResult>> {
    if !(200..300).contains(&resp.status) {
        return Err(host_abort(outcome, HostOutcome::HttpStatus(resp.status)));
    }
    json_to_dynamic(&resp.body, caps).map_err(|e| {
        host_abort(
            outcome,
            HostOutcome::Type {
                detail: type_detail(&e),
            },
        )
    })
}

/// Translate a host-returned error into the authoritative [`HostOutcome`],
/// preserving the precise status / budget kind rather than flattening it.
fn host_outcome_for(err: SourceScriptError) -> HostOutcome {
    match err {
        SourceScriptError::Deadline => HostOutcome::Deadline,
        SourceScriptError::HttpTransport => HostOutcome::HttpTransport,
        SourceScriptError::HttpStatus { status } => HostOutcome::HttpStatus(status),
        SourceScriptError::Budget { kind } => HostOutcome::Budget(kind),
        SourceScriptError::HostDenied { reason } => HostOutcome::HostDenied { reason },
        SourceScriptError::Type { detail } => HostOutcome::Type { detail },
        // Any other host error class collapses to a transport failure, the
        // closest public equivalent for an unexpected host-side fault.
        _ => HostOutcome::HttpTransport,
    }
}

/// Pull the low-cardinality detail out of a `Type` error for re-wrapping.
fn type_detail(err: &SourceScriptError) -> String {
    match err {
        SourceScriptError::Type { detail } => detail.clone(),
        other => other.to_string(),
    }
}

/// Record `cause` in the out-of-band cell and return an opaque abort token.
///
/// The token exists only to make Rhai unwind the script; its contents are never
/// inspected during classification (the cell is), so it cannot be forged.
fn host_abort(outcome: &OutcomeCell, cause: HostOutcome) -> Box<EvalAltResult> {
    outcome.set(cause);
    Box::new(EvalAltResult::ErrorRuntime(
        Dynamic::from("__host_outcome__"),
        Position::NONE,
    ))
}

/// Sets the flag to `true` on drop. Covers a normal return as well as an
/// `on_progress`-driven abort, so a test can observe the blocking thread exit.
struct SetOnDrop(Arc<AtomicBool>);
impl Drop for SetOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// Run the compiled script synchronously and validate its output.
fn run_script_blocking(
    engine: Engine,
    ast: rhai::AST,
    entrypoint: String,
    ctx: Dynamic,
    caps: ConvertCaps,
    max_output_bytes: usize,
) -> Result<Vec<Value>, SourceScriptError> {
    let mut scope = Scope::new();
    // Push the namespace markers so `xw.*` and `source.get(...)` resolve.
    crate::xw::push_into_scope(&mut scope);
    scope.push_constant("source", SourceNs);
    let out: Dynamic = engine
        .call_fn(&mut scope, &ast, &entrypoint, (ctx,))
        .map_err(|e| classify_eval_error(&e))?;

    let json = dynamic_to_json(&out, caps)?;

    // Enforce the output byte cap before structural validation.
    let serialized = serde_json::to_string(&json).map_err(|e| SourceScriptError::Type {
        detail: format!("output not serializable: {e}"),
    })?;
    if serialized.len() > max_output_bytes {
        return Err(SourceScriptError::Budget {
            kind: BudgetKind::OutputBytes,
        });
    }

    validate_records(json)
}

/// Translate a Rhai evaluation error into a fallback [`SourceScriptError`].
///
/// This is consulted **only when the out-of-band [`OutcomeCell`] is empty** —
/// i.e. when the run was NOT terminated by a host-trusted writer (progress
/// guard / capability / path gate). In that case the error is genuinely
/// script-controlled.
///
/// Resource-limit outcomes are read from Rhai's typed error **variants**
/// (`ErrorTooManyOperations`, `ErrorStackOverflow`, `ErrorDataTooLarge`), never
/// from the Display string. This matters for integrity: a script can only ever
/// raise `ErrorRuntime` / `ErrorTerminated` (via `throw`), so it cannot forge a
/// resource-limit budget by throwing a lookalike string — such a throw falls
/// through to a plain `Runtime` error.
fn classify_eval_error(err: &EvalAltResult) -> SourceScriptError {
    // Unwrap the `ErrorInFunctionCall` wrapper Rhai adds around an error raised
    // inside a function, so a limit tripped in a helper is still recognized.
    let inner = unwrap_in_function_call(err);
    match inner {
        EvalAltResult::ErrorTooManyOperations(_) => {
            return SourceScriptError::Budget {
                kind: BudgetKind::Operations,
            };
        }
        EvalAltResult::ErrorStackOverflow(_) => {
            return SourceScriptError::Runtime {
                reason: "call depth exceeded".into(),
            };
        }
        EvalAltResult::ErrorDataTooLarge(what, _) => {
            return SourceScriptError::Runtime {
                reason: format!("{what} exceeds size limit"),
            };
        }
        _ => {}
    }

    SourceScriptError::Runtime {
        reason: short_runtime_reason(&inner.to_string()),
    }
}

/// Peel `ErrorInFunctionCall` wrappers to reach the underlying error.
fn unwrap_in_function_call(err: &EvalAltResult) -> &EvalAltResult {
    match err {
        EvalAltResult::ErrorInFunctionCall(_, _, inner, _) => unwrap_in_function_call(inner),
        other => other,
    }
}

/// Keep a runtime reason short and free of script source. We only retain the
/// leading error-kind phrasing Rhai produces.
fn short_runtime_reason(text: &str) -> String {
    // Rhai messages look like "Runtime error: ... (line N, position M)".
    // Trim at the position marker to avoid trailing detail.
    let trimmed = text.split(" (line ").next().unwrap_or(text);
    let trimmed = trimmed.trim();
    // Hard cap length to keep cardinality bounded.
    if trimmed.len() > 120 {
        trimmed.chars().take(120).collect()
    } else {
        trimmed.to_string()
    }
}
