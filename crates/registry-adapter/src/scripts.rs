// SPDX-License-Identifier: Apache-2.0

//! The pack's Rhai entrypoints, digest-verified and compiled at load, and
//! the call that runs one against an exchange
//! (`products/adapter/CONCEPT.md` section 8.11.3).
//!
//! An entrypoint takes one `exchange` argument, `#{body, headers,
//! properties}` with lowercased header names, and returns a value. Each file
//! is its own compilation unit and every call runs in a fresh scope under the
//! maintained runtime profile's limits and a wall-clock deadline.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::load::MAXIMUM_RESPONSE_BYTES;
use registry_adapter_core::{AdapterPack, CodeMap, ErrorClass};
use registry_platform_config::sha256_uri;
use registry_platform_script::rhai::{
    build_engine, call_with_fresh_scope, classify_failure, compile_entrypoint,
    entrypoint_parameters, RhaiBaseEngine, RhaiCompileError, RhaiFailureCategory, RhaiLimits,
    RhaiProfile,
};
use rhai::{EvalAltResult, AST};
use serde_json::Value;
use thiserror::Error;

/// Rhai counts string bytes, array items and map entries over the whole
/// nested value, not per container. A script holds the reply it was given,
/// at most [`MAXIMUM_RESPONSE_BYTES`], and may keep a second copy beside it,
/// so each ceiling is sized from that cap: any reply the runtime accepts can
/// be processed at the declared page maximum.
const STRING_BYTES: usize = 2 * MAXIMUM_RESPONSE_BYTES;
/// An array item needs at least two bytes of JSON (a value and a comma).
const ARRAY_ITEMS: usize = MAXIMUM_RESPONSE_BYTES / 2;
/// A map entry needs at least four bytes of JSON (a key, a colon, a value).
const MAP_ENTRIES: usize = MAXIMUM_RESPONSE_BYTES / 4;

/// The engine contract the entrypoints compile and run under. The
/// operations, depth and source ceilings are the limits every maintained
/// runtime profile publishes; the data ceilings follow the reply cap.
pub const SCRIPT_PROFILE: RhaiProfile = RhaiProfile {
    limits: RhaiLimits {
        operations: 100_000,
        call_levels: 32,
        expression_depth: 64,
        modules: 0,
        string_bytes: STRING_BYTES,
        array_items: ARRAY_ITEMS,
        map_entries: MAP_ENTRIES,
    },
    base: RhaiBaseEngine::Standard,
    disabled_symbols: &["import", "export", "eval", "print", "debug"],
    allow_anonymous_fn: false,
    maximum_source_bytes: 65_536,
};

/// How long one entrypoint call may run.
const CALL_DEADLINE: Duration = Duration::from_secs(2);

/// A deployment's declared code maps, keyed by id: the one table the
/// conversion steps and the Rhai `code_map(id, key)` helper read
/// (`products/adapter/CONCEPT.md` section 8.6). Shared because the Rhai
/// native function cannot borrow the caller's stack: each call clones
/// the handle, and the maps themselves are never copied per call.
pub type CodeMaps = Arc<BTreeMap<String, CodeMap>>;

/// The fixed marker a `code_map` miss raises through the engine: the
/// class name and the map id, so the failure classification can name
/// the map without carrying the key (section 8.6). A script that raises
/// the same text itself is classified the same way: the marker is the
/// contract, and pack scripts are reviewed content.
const UNMAPPED_MARKER: &str = "conversion.unmapped:";
/// A marker for an undeclared map id. The id may come from the current
/// exchange, so neither the marker nor the classified failure carries it.
const UNDECLARED_MAP_MARKER: &str = "conversion.undeclared-code-map";

/// Why a script could not be loaded. Every text is fixed and value-free
/// apart from the script path the pack itself names.
#[derive(Debug, Error)]
pub enum ScriptLoadError {
    #[error("script {0} is not in the pack's script inventory")]
    NotInventoried(String),
    #[error("script {0} could not be read")]
    Unreadable(String),
    #[error("script {0} is over the engine's source bound")]
    TooLarge(String),
    #[error("script {0} does not match its pinned digest")]
    DigestMismatch(String),
    #[error("script {path} entrypoint {entrypoint} does not compile as a one-parameter function named exchange")]
    Entrypoint { path: String, entrypoint: String },
    #[error("script {path} entrypoint {entrypoint} does not compile as a two-parameter function named oldExchange and newExchange")]
    EntrypointPair { path: String, entrypoint: String },
}

/// A failed entrypoint call, as the error class it raises.
#[derive(Debug, Error)]
pub enum ScriptFailure {
    #[error("the script exhausted its budget")]
    Budget,
    #[error("the script raised an error")]
    Failed,
    #[error("{0}")]
    Unmapped(String),
}

impl ScriptFailure {
    #[must_use]
    pub fn class(&self) -> ErrorClass {
        match self {
            Self::Budget => ErrorClass::ScriptBudgetExceeded,
            Self::Failed => ErrorClass::Script,
            Self::Unmapped(_) => ErrorClass::ConversionUnmapped,
        }
    }
}

/// The compiled entrypoints a deployment serves, by file and entrypoint.
#[derive(Debug, Default)]
pub struct ScriptSet {
    compiled: BTreeMap<(String, String), AST>,
}

impl ScriptSet {
    /// Compile `(file, entrypoint)` into the set, verifying the file against
    /// the pack's pinned digest first. A pair already compiled is kept.
    pub fn add(
        &mut self,
        pack: &AdapterPack,
        pack_directory: &Path,
        file: &str,
        entrypoint: &str,
    ) -> Result<(), ScriptLoadError> {
        self.compile_into(pack, pack_directory, file, entrypoint, &["exchange"], false)
    }

    /// Compile `(file, entrypoint)` as an aggregation strategy entrypoint:
    /// a two-parameter function over the old and new bodies, named for
    /// Camel's own `AggregationStrategy.aggregate(oldExchange, newExchange)`
    /// (`products/adapter/CONCEPT.md` section 8.11.7; `new` alone is a
    /// reserved word in the pinned engine, so Camel's full names it is).
    /// The same digest verification as [`ScriptSet::add`] applies.
    pub fn add_aggregation(
        &mut self,
        pack: &AdapterPack,
        pack_directory: &Path,
        file: &str,
        entrypoint: &str,
    ) -> Result<(), ScriptLoadError> {
        self.compile_into(
            pack,
            pack_directory,
            file,
            entrypoint,
            &["oldExchange", "newExchange"],
            true,
        )
    }

    /// The shared registration: read the file behind the pack's pinned
    /// digest and compile the entrypoint under the declared parameter
    /// names. A pair already compiled is kept.
    fn compile_into(
        &mut self,
        pack: &AdapterPack,
        pack_directory: &Path,
        file: &str,
        entrypoint: &str,
        parameters: &[&str],
        pair: bool,
    ) -> Result<(), ScriptLoadError> {
        let key = (file.to_owned(), entrypoint.to_owned());
        if self.compiled.contains_key(&key) {
            return Ok(());
        }
        let pinned = pack
            .scripts
            .iter()
            .find(|script| script.path == file)
            .ok_or_else(|| ScriptLoadError::NotInventoried(file.to_owned()))?;
        let bytes = match read_bounded_file(
            &pack_directory.join(file),
            SCRIPT_PROFILE.maximum_source_bytes,
        )
        .map_err(|_| ScriptLoadError::Unreadable(file.to_owned()))?
        {
            BoundedRead::Bytes(bytes) => bytes,
            BoundedRead::TooLarge => return Err(ScriptLoadError::TooLarge(file.to_owned())),
        };
        if sha256_uri(&bytes) != pinned.digest.as_str() {
            return Err(ScriptLoadError::DigestMismatch(file.to_owned()));
        }
        let entrypoint_error = || {
            if pair {
                ScriptLoadError::EntrypointPair {
                    path: file.to_owned(),
                    entrypoint: entrypoint.to_owned(),
                }
            } else {
                ScriptLoadError::Entrypoint {
                    path: file.to_owned(),
                    entrypoint: entrypoint.to_owned(),
                }
            }
        };
        let source = std::str::from_utf8(&bytes).map_err(|_| entrypoint_error())?;
        let ast = compile_entrypoint(&SCRIPT_PROFILE, source, entrypoint, &[parameters.len()])
            .map_err(|_: RhaiCompileError| entrypoint_error())?;
        if entrypoint_parameters(&ast, entrypoint).as_slice() != parameters {
            return Err(entrypoint_error());
        }
        self.compiled.insert(key, ast);
        Ok(())
    }

    /// Run one entrypoint over `exchange` and return its JSON result.
    pub fn call(
        &self,
        maps: &CodeMaps,
        file: &str,
        entrypoint: &str,
        exchange: &Value,
    ) -> Result<Value, ScriptFailure> {
        self.call_with_deadline(
            maps,
            file,
            entrypoint,
            exchange,
            Instant::now() + CALL_DEADLINE,
        )
    }

    /// Run one entrypoint without exceeding either the caller's absolute
    /// deadline or the script profile's per-call wall-clock ceiling.
    pub fn call_with_deadline(
        &self,
        maps: &CodeMaps,
        file: &str,
        entrypoint: &str,
        exchange: &Value,
        deadline: Instant,
    ) -> Result<Value, ScriptFailure> {
        let ast = self
            .compiled
            .get(&(file.to_owned(), entrypoint.to_owned()))
            .ok_or(ScriptFailure::Failed)?;
        let argument = rhai::serde::to_dynamic(exchange).map_err(|_| ScriptFailure::Failed)?;
        self.invoke(maps, ast, entrypoint, (argument,), deadline)
    }

    /// Run one aggregation strategy entrypoint over the old and new
    /// bodies (section 8.11.7). A split's first call passes a null `old`,
    /// which the entrypoint sees as `()`.
    pub fn aggregate(
        &self,
        maps: &CodeMaps,
        file: &str,
        entrypoint: &str,
        old: &Value,
        new: &Value,
    ) -> Result<Value, ScriptFailure> {
        self.aggregate_with_deadline(
            maps,
            file,
            entrypoint,
            old,
            new,
            Instant::now() + CALL_DEADLINE,
        )
    }

    /// Run one aggregation entrypoint without exceeding the caller's
    /// absolute deadline or the per-call script ceiling.
    #[allow(clippy::too_many_arguments)]
    pub fn aggregate_with_deadline(
        &self,
        maps: &CodeMaps,
        file: &str,
        entrypoint: &str,
        old: &Value,
        new: &Value,
        deadline: Instant,
    ) -> Result<Value, ScriptFailure> {
        let ast = self
            .compiled
            .get(&(file.to_owned(), entrypoint.to_owned()))
            .ok_or(ScriptFailure::Failed)?;
        let old_value = rhai::serde::to_dynamic(old).map_err(|_| ScriptFailure::Failed)?;
        let new_value = rhai::serde::to_dynamic(new).map_err(|_| ScriptFailure::Failed)?;
        self.invoke(maps, ast, entrypoint, (old_value, new_value), deadline)
    }

    /// Call a compiled entrypoint under the profile's limits and convert
    /// its result back to JSON.
    fn invoke<A: rhai::FuncArgs>(
        &self,
        maps: &CodeMaps,
        ast: &rhai::AST,
        entrypoint: &str,
        args: A,
        deadline: Instant,
    ) -> Result<Value, ScriptFailure> {
        let deadline = deadline.min(Instant::now() + CALL_DEADLINE);
        let engine = build_engine(&SCRIPT_PROFILE, Some(deadline), |engine| {
            register_code_map(engine, maps);
        });
        let result = call_with_fresh_scope(&engine, ast, entrypoint, args)
            .map_err(|error| failure(&error))?;
        rhai::serde::from_dynamic::<Value>(&result).map_err(|_| ScriptFailure::Failed)
    }

    /// Run a predicate entrypoint. A result that is not a boolean raises
    /// `script` (section 8.11.3).
    pub fn predicate(
        &self,
        maps: &CodeMaps,
        file: &str,
        entrypoint: &str,
        exchange: &Value,
    ) -> Result<bool, ScriptFailure> {
        match self.call(maps, file, entrypoint, exchange)? {
            Value::Bool(verdict) => Ok(verdict),
            _ => Err(ScriptFailure::Failed),
        }
    }
}

/// The result of reading a governed file without allocating from its
/// declared filesystem length or reading past the caller's ceiling.
pub(crate) enum BoundedRead {
    Bytes(Vec<u8>),
    TooLarge,
}

/// Read at most `limit + 1` bytes. Metadata refuses an already oversized
/// regular file before reading it, while the limited reader also holds the
/// boundary if the file grows or its reported length is not useful.
pub(crate) fn read_bounded_file(path: &Path, limit: usize) -> io::Result<BoundedRead> {
    let file = File::open(path)?;
    let length = file.metadata()?.len();
    if length > limit as u64 {
        return Ok(BoundedRead::TooLarge);
    }
    let mut bytes = Vec::with_capacity(limit.min(length as usize));
    file.take(limit.saturating_add(1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        Ok(BoundedRead::TooLarge)
    } else {
        Ok(BoundedRead::Bytes(bytes))
    }
}

/// Register `code_map(id, key)` over the declared maps: the same single
/// lookup a conversion step takes, with the miss raised as the marker
/// text (`CONCEPT.md` section 8.6; there is no second key lookup in v1).
/// An id no declared map carries answers the same miss naming that id:
/// a script's references are not statically countable, so the run time
/// is where they resolve.
fn register_code_map(engine: &mut rhai::Engine, maps: &CodeMaps) {
    let maps = Arc::clone(maps);
    engine.register_fn(
        "code_map",
        move |id: &str, key: &str| -> Result<rhai::Dynamic, Box<EvalAltResult>> {
            let map = maps.get(id).ok_or_else(undeclared_map)?;
            let value = map.lookup(key).ok_or_else(|| unmapped(id))?;
            // A JSON scalar always converts; the marker keeps the one
            // failure path if a non-scalar ever reached the table.
            rhai::serde::to_dynamic(value).map_err(|_| unmapped(id))
        },
    );
}

/// The fixed runtime error for an id no authored map declares. The id is
/// untrusted exchange-derived input and must not cross the failure boundary.
fn undeclared_map() -> Box<EvalAltResult> {
    Box::new(EvalAltResult::ErrorRuntime(
        rhai::Dynamic::from(UNDECLARED_MAP_MARKER),
        rhai::Position::NONE,
    ))
}

/// The runtime error a miss raises: the marker text in the payload the
/// classification unwraps, never the key itself.
fn unmapped(id: &str) -> Box<EvalAltResult> {
    Box::new(EvalAltResult::ErrorRuntime(
        rhai::Dynamic::from(format!("{UNMAPPED_MARKER}{id}")),
        rhai::Position::NONE,
    ))
}

fn failure(error: &EvalAltResult) -> ScriptFailure {
    if let Some(message) = unmapped_message(error) {
        return ScriptFailure::Unmapped(message);
    }
    if matches!(error, EvalAltResult::ErrorTerminated(..))
        || classify_failure(error) == RhaiFailureCategory::ResourceExhausted
    {
        ScriptFailure::Budget
    } else {
        ScriptFailure::Failed
    }
}

/// The safe failure message the marker names, if the failure carries one.
/// Rhai wraps
/// a native function's runtime error in `ErrorInFunctionCall`; the
/// marker sits in the innermost runtime payload.
fn unmapped_message(error: &EvalAltResult) -> Option<String> {
    let mut cursor = error;
    loop {
        if let EvalAltResult::ErrorRuntime(payload, _) = cursor {
            if let Ok(text) = payload.as_immutable_string_ref() {
                if text.as_str() == UNDECLARED_MAP_MARKER {
                    return Some("an undeclared code map was requested".to_owned());
                }
                if let Some(id) = text.as_str().strip_prefix(UNMAPPED_MARKER) {
                    return Some(format!("code map {id} has no entry for the key"));
                }
            }
        }
        cursor = match cursor {
            EvalAltResult::ErrorInFunctionCall(_, _, err, _) => err.as_ref(),
            _ => return None,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pack_for_script(source: &[u8]) -> AdapterPack {
        serde_json::from_value(json!({
            "id": "bounded-script",
            "version": "1",
            "testedVersions": ["1"],
            "scripts": [{"path": "probe.rhai", "digest": sha256_uri(source)}],
        }))
        .expect("the test pack parses")
    }

    #[test]
    fn an_oversized_sparse_script_is_refused_before_compilation() {
        let directory = tempfile::tempdir().expect("a scratch directory");
        let path = directory.path().join("probe.rhai");
        File::create(&path)
            .expect("the sparse file is created")
            .set_len(SCRIPT_PROFILE.maximum_source_bytes as u64 + 1)
            .expect("the sparse file length is set");
        let pack = pack_for_script(b"");
        let mut scripts = ScriptSet::default();

        assert!(matches!(
            scripts.add(&pack, directory.path(), "probe.rhai", "probe"),
            Err(ScriptLoadError::TooLarge(path)) if path == "probe.rhai"
        ));
    }

    #[test]
    fn a_caller_deadline_bounds_a_synchronous_script() {
        let source = b"fn probe(exchange) { let n = 0; for x in 0..10000 { n += x; } n }";
        let directory = tempfile::tempdir().expect("a scratch directory");
        std::fs::write(directory.path().join("probe.rhai"), source).expect("the script is written");
        let pack = pack_for_script(source);
        let mut scripts = ScriptSet::default();
        scripts
            .add(&pack, directory.path(), "probe.rhai", "probe")
            .expect("the script compiles");

        let exchange = json!({"body": null, "headers": {}, "properties": {}});
        let completed = scripts.call(&Arc::new(BTreeMap::new()), "probe.rhai", "probe", &exchange);
        assert!(
            completed.is_ok(),
            "the finite script stays inside the operation budget: {completed:?}"
        );

        let expired = scripts.call_with_deadline(
            &Arc::new(BTreeMap::new()),
            "probe.rhai",
            "probe",
            &exchange,
            Instant::now(),
        );
        assert!(matches!(expired, Err(ScriptFailure::Budget)), "{expired:?}");
    }
}
