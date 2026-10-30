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
use std::path::Path;
use std::time::{Duration, Instant};

use crate::load::MAXIMUM_RESPONSE_BYTES;
use registry_adapter_core::{AdapterPack, ErrorClass};
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

/// Why a script could not be loaded. Every text is fixed and value-free
/// apart from the script path the pack itself names.
#[derive(Debug, Error)]
pub enum ScriptLoadError {
    #[error("script {0} is not in the pack's script inventory")]
    NotInventoried(String),
    #[error("script {0} could not be read")]
    Unreadable(String),
    #[error("script {0} does not match its pinned digest")]
    DigestMismatch(String),
    #[error("script {path} entrypoint {entrypoint} does not compile as a one-parameter function named exchange")]
    Entrypoint { path: String, entrypoint: String },
}

/// A failed entrypoint call, as the error class it raises.
#[derive(Debug, Error)]
pub enum ScriptFailure {
    #[error("the script exhausted its budget")]
    Budget,
    #[error("the script raised an error")]
    Failed,
}

impl ScriptFailure {
    #[must_use]
    pub fn class(&self) -> ErrorClass {
        match self {
            Self::Budget => ErrorClass::ScriptBudgetExceeded,
            Self::Failed => ErrorClass::Script,
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
        let key = (file.to_owned(), entrypoint.to_owned());
        if self.compiled.contains_key(&key) {
            return Ok(());
        }
        let pinned = pack
            .scripts
            .iter()
            .find(|script| script.path == file)
            .ok_or_else(|| ScriptLoadError::NotInventoried(file.to_owned()))?;
        let bytes = std::fs::read(pack_directory.join(file))
            .map_err(|_| ScriptLoadError::Unreadable(file.to_owned()))?;
        if sha256_uri(&bytes) != pinned.digest.as_str() {
            return Err(ScriptLoadError::DigestMismatch(file.to_owned()));
        }
        let entrypoint_error = || ScriptLoadError::Entrypoint {
            path: file.to_owned(),
            entrypoint: entrypoint.to_owned(),
        };
        let source = std::str::from_utf8(&bytes).map_err(|_| entrypoint_error())?;
        let ast = compile_entrypoint(&SCRIPT_PROFILE, source, entrypoint, &[1])
            .map_err(|_: RhaiCompileError| entrypoint_error())?;
        if entrypoint_parameters(&ast, entrypoint) != ["exchange"] {
            return Err(entrypoint_error());
        }
        self.compiled.insert(key, ast);
        Ok(())
    }

    /// Run one entrypoint over `exchange` and return its JSON result.
    pub fn call(
        &self,
        file: &str,
        entrypoint: &str,
        exchange: &Value,
    ) -> Result<Value, ScriptFailure> {
        let ast = self
            .compiled
            .get(&(file.to_owned(), entrypoint.to_owned()))
            .ok_or(ScriptFailure::Failed)?;
        let argument = rhai::serde::to_dynamic(exchange).map_err(|_| ScriptFailure::Failed)?;
        let engine = build_engine(
            &SCRIPT_PROFILE,
            Some(Instant::now() + CALL_DEADLINE),
            |_| {},
        );
        let result = call_with_fresh_scope(&engine, ast, entrypoint, (argument,))
            .map_err(|error| failure(&error))?;
        rhai::serde::from_dynamic::<Value>(&result).map_err(|_| ScriptFailure::Failed)
    }

    /// Run a predicate entrypoint. A result that is not a boolean raises
    /// `script` (section 8.11.3).
    pub fn predicate(
        &self,
        file: &str,
        entrypoint: &str,
        exchange: &Value,
    ) -> Result<bool, ScriptFailure> {
        match self.call(file, entrypoint, exchange)? {
            Value::Bool(verdict) => Ok(verdict),
            _ => Err(ScriptFailure::Failed),
        }
    }
}

fn failure(error: &EvalAltResult) -> ScriptFailure {
    if matches!(error, EvalAltResult::ErrorTerminated(..))
        || classify_failure(error) == RhaiFailureCategory::ResourceExhausted
    {
        ScriptFailure::Budget
    } else {
        ScriptFailure::Failed
    }
}
