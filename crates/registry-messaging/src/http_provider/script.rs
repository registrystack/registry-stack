// SPDX-License-Identifier: Apache-2.0

//! The three provider scripts: compiled once at activation, run with a fresh
//! scope under bounded limits, and read back through closed output shapes.
//!
//! A script sees plain data only: the rendered message and sender profile,
//! the decoded response, or the callback's form, query, and JSON body. No
//! credential, secret reference, URL, or header value the runtime owns is
//! ever placed in its scope. Its output is size-bound in Rust before it is
//! read, since the platform script adapter bounds evaluation, not output.

use std::collections::BTreeMap;
use std::time::Instant;

use registry_platform_script::rhai::{
    build_engine, call_with_fresh_scope, classify_failure, compile_entrypoint, RhaiBaseEngine,
    RhaiCompileError, RhaiFailureCategory, RhaiLimits, RhaiProfile,
};
use rhai::{Dynamic, EvalAltResult, AST};
use serde::Deserialize;
use serde_json::Value;

use super::settings::HttpProviderError;

/// The most operations one script call may run.
pub const MAXIMUM_SCRIPT_OPERATIONS: u64 = 100_000;

/// The longest script source a package may ship.
pub const MAXIMUM_SCRIPT_SOURCE_BYTES: usize = 65_536;

/// The largest serialized prepare output: a request body up to the
/// substrate's one MiB body bound plus its target and headers.
pub const MAXIMUM_PREPARE_OUTPUT_BYTES: usize = 1_114_112;

/// The largest serialized interpret or receipt output, as Evidence bounds its
/// own script results.
pub const MAXIMUM_SCRIPT_OUTPUT_BYTES: usize = 65_536;

/// The profile every provider script runs under. The string bound admits the
/// largest rendered HTML part; nothing a script builds may exceed it.
const PROVIDER_SCRIPT_PROFILE: RhaiProfile = RhaiProfile {
    limits: RhaiLimits {
        operations: MAXIMUM_SCRIPT_OPERATIONS,
        call_levels: 32,
        expression_depth: 64,
        modules: 0,
        string_bytes: 262_144,
        array_items: 256,
        map_entries: 256,
    },
    base: RhaiBaseEngine::Standard,
    disabled_symbols: &["import", "export", "eval", "print", "debug"],
    allow_anonymous_fn: false,
    maximum_source_bytes: MAXIMUM_SCRIPT_SOURCE_BYTES,
};

pub(crate) const PREPARE_ENTRYPOINT: &str = "prepare";
pub(crate) const INTERPRET_ENTRYPOINT: &str = "interpret";
pub(crate) const RECEIPT_ENTRYPOINT: &str = "receipt";

/// Compile one provider script under its entry-point contract.
pub(crate) fn compile(
    script: &'static str,
    source: &str,
    entrypoint: &str,
    arity: usize,
) -> Result<AST, HttpProviderError> {
    compile_entrypoint(&PROVIDER_SCRIPT_PROFILE, source, entrypoint, &[arity]).map_err(|error| {
        HttpProviderError::Script {
            script,
            reason: match error {
                RhaiCompileError::SourceBound => "the source exceeds 65536 bytes",
                RhaiCompileError::Parse(_) => "the source does not compile",
                RhaiCompileError::Entrypoint => {
                    "the source must define exactly one public entry point of the expected arity and no duplicate function names"
                }
            },
        }
    })
}

/// Why a script call produced no usable output. Value-free: no script text,
/// thrown value, or input crosses this boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScriptFailure {
    /// The send deadline passed while the script ran.
    Deadline,
    /// The operation, call-depth, or data-size budget ran out.
    ResourceExhausted,
    /// The script threw, or failed at run time.
    Failed,
    /// The output exceeded its byte bound.
    OutputTooLarge,
    /// The output did not have the required shape.
    OutputInvalid,
}

impl ScriptFailure {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deadline => "deadline",
            Self::ResourceExhausted => "resource-exhausted",
            Self::Failed => "failed",
            Self::OutputTooLarge => "output-too-large",
            Self::OutputInvalid => "output-invalid",
        }
    }
}

/// Call `entrypoint` with `args` and return its output as JSON within
/// `maximum_output_bytes`.
pub(crate) fn run(
    ast: &AST,
    entrypoint: &str,
    args: Vec<Value>,
    deadline: Instant,
    maximum_output_bytes: usize,
) -> Result<Value, ScriptFailure> {
    let engine = build_engine(&PROVIDER_SCRIPT_PROFILE, Some(deadline), |_| {});
    let args = args
        .iter()
        .map(rhai::serde::to_dynamic)
        .collect::<Result<Vec<Dynamic>, _>>()
        .map_err(|_| ScriptFailure::Failed)?;
    let result = match args.len() {
        1 => call_with_fresh_scope(&engine, ast, entrypoint, (args[0].clone(),)),
        2 => call_with_fresh_scope(&engine, ast, entrypoint, (args[0].clone(), args[1].clone())),
        _ => return Err(ScriptFailure::Failed),
    };
    let output = result.map_err(|error| classify(&error, deadline))?;
    let value: Value =
        rhai::serde::from_dynamic(&output).map_err(|_| ScriptFailure::OutputInvalid)?;
    let encoded = serde_json::to_vec(&value).map_err(|_| ScriptFailure::OutputInvalid)?;
    if encoded.len() > maximum_output_bytes {
        return Err(ScriptFailure::OutputTooLarge);
    }
    Ok(value)
}

fn classify(error: &EvalAltResult, deadline: Instant) -> ScriptFailure {
    if matches!(error, EvalAltResult::ErrorTerminated(..)) && Instant::now() >= deadline {
        return ScriptFailure::Deadline;
    }
    match classify_failure(error) {
        RhaiFailureCategory::ResourceExhausted => ScriptFailure::ResourceExhausted,
        RhaiFailureCategory::Other => ScriptFailure::Failed,
    }
}

/// The closed shape a prepare script returns.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PreparedRequest {
    pub target: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body_format: Option<BodyFormat>,
    #[serde(default)]
    pub body: Option<Value>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum BodyFormat {
    Json,
    Form,
}

/// The closed shape an interpret script returns.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Interpretation {
    pub outcome: InterpretedOutcome,
    #[serde(default)]
    pub provider_reference: Option<String>,
    #[serde(default)]
    pub retry_after: Option<u64>,
    #[serde(default)]
    pub code: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum InterpretedOutcome {
    Accepted,
    Transient,
    Permanent,
    MaybeSent,
}

/// The closed shape a receipt script returns when it recognises a report.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ScriptReceipt {
    pub provider_reference: String,
    pub report: registry_messaging_core::DeliveryReport,
    #[serde(default)]
    pub code: Option<String>,
}

/// Read a script's JSON output into one of the closed shapes above.
pub(crate) fn read_output<T: for<'de> Deserialize<'de>>(value: Value) -> Result<T, ScriptFailure> {
    serde_json::from_value(value).map_err(|_| ScriptFailure::OutputInvalid)
}
