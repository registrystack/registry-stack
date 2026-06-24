// SPDX-License-Identifier: Apache-2.0
//! A sandboxed Rhai scripting engine for governed source adapters.
//!
//! This crate runs small, untrusted Rhai scripts that resolve a lookup against
//! an upstream source. Every resource axis is bounded, the only effect a script
//! can perform is a single host capability, and the script's output is shape-
//! validated before it leaves the engine.
//!
//! # Architecture
//!
//! * [`host`] — the language-agnostic async seam ([`ScriptSourceHost`]). The
//!   sole boundary between a script and the outside world.
//! * [`engine`] — [`ScriptEngine`] compilation and the [`RhaiPolicy`] /
//!   [`RhaiLimits`] that harden the runtime.
//! * [`bridge`] — runs the synchronous script on a dedicated blocking thread,
//!   bridged to the async host via an mpsc/oneshot channel pair, with
//!   deadline + cancel-flag termination and admission control.
//! * [`ctx`] — the minimized [`ScriptCtx`] handed to the entrypoint.
//! * [`convert`] / [`output`] — bounded JSON conversion and return-shape
//!   validation.
//! * [`xw`] — the pure helper module tree scripts call as `xw.text.*`,
//!   `xw.date.*`, etc.
//! * [`path`] — [`canonicalize_target_relative_path`], the request-path
//!   security gate.
//! * [`harness`] — a deterministic mock host for offline testing.
//!
//! # Script-visible API
//!
//! A script defines an entrypoint `fn lookup(ctx) { ... }` and may call:
//!
//! ```text
//! // The host capability. Returns `#{ status, body }` for every observable
//! // response (2xx, or a status in the engine's `visible_statuses`); any other
//! // non-2xx status terminates the run. Read records via `r.body`, branch on
//! // `r.status`:
//! let r = source.get(target, path, query);
//! let data = if r.status == 404 { source.get(target, alt, query).body } else { r.body };
//!
//! xw.text.slug(s)                   // pure helpers (see the `xw` module)
//! xw.date.add_days(d, 3)
//! // ...
//! ```
//!
//! It must return an array of plain JSON objects.

pub mod bridge;
pub mod convert;
pub mod counters;
pub mod ctx;
pub mod engine;
pub mod error;
pub mod harness;
pub mod host;
pub mod output;
pub mod path;
pub mod xw;

pub use counters::ExecCounters;
pub use ctx::{Lookup, ScriptCtx};
pub use engine::{RhaiLimits, RhaiPolicy, ScriptEngine};
pub use error::{problem_code, BudgetKind, SourceScriptError};
pub use harness::MockScriptHost;
pub use host::{ScriptSourceHost, SourceResponse};
pub use output::{validate_records, MAX_RECORDS};
pub use path::{canonicalize_target_relative_path, PathError};
