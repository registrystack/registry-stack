// SPDX-License-Identifier: Apache-2.0
//! Bounded offline scenarios over the exact workflow graph and pure mappings.

use crate::{
    authoring,
    contracts::{contract, event_contract, Violation},
    definition::{class, parse_timestamp, Definition, Step, WaitEvent},
    protocol::{CallRequest, DeclaredRefusal},
    CoordinatorError, Result,
};
use chrono::{DateTime, Utc};
use registry_platform_config::AuthoredExpressions;
use registry_platform_yaml::{
    ApiVersion, BoundedU32, Diagnostic, Document, EnvelopeRule, Expect, ForeignValue, FormatSpec,
    Identified, Invalid, LocalId, Reader, Severity, UniqueIdList, UniqueList,
};
use registry_review_protocol::{ReviewRequestAccepted, ReviewResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read as _,
    path::Path,
};

pub const API_VERSION: &str = "id.registrystack.org/formats/coordinator/scenarios/v1alpha1";
pub const KIND: &str = "CoordinatorScenarios";
pub const SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/coordinator/scenarios/scenarios.v1alpha1.schema.json";
/// The file a scenario refusal names before it is placed in a project.
const SCENARIOS_FILE: &str = "scenarios.yaml";
const FORMAT: FormatSpec<'static> = FormatSpec {
    kind: KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

// The authored format is separate from the stable offline execution types.
/// Offline cases for one workflow: each runs the workflow from a start input
/// against synthetic product replies on a virtual clock, and states where the
/// run must end. `coordinatorctl test` runs them; no product is contacted.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CoordinatorScenarios {
    /// The cases, 1 to 64, each with a unique `id`.
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 64)))]
    cases: UniqueIdList<AuthoredScenario>,
}

/// One run of the workflow, from admission to where it stops.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
struct AuthoredScenario {
    /// The case name test reports.
    id: LocalId,
    /// The RFC 3339 instant the run is admitted; the virtual clock starts
    /// here and moves only to the instants waits select.
    #[cfg_attr(feature = "schema", schemars(extend("format" = "date-time")))]
    admitted_at: String,
    /// The start input, which must satisfy the workflow input schema.
    input: ForeignValue,
    /// The synthetic replies each call step receives, by step, in the order
    /// its attempts consume them: 1 to 8 per step. A reply after the first
    /// needs a recovery for that step.
    #[cfg_attr(feature = "schema", schemars(schema_with = "replies_schema"))]
    replies: BTreeMap<LocalId, Vec<AuthoredReply>>,
    /// The operator recovery each call step receives after a retryable or
    /// uncertain reply, by step, so the step consumes its next reply.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(schema_with = "recovery_schema"))]
    recovery: BTreeMap<LocalId, Recovery>,
    /// What each wait-for step the run reaches receives, by step: the event
    /// it waits for, or its timeout.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(schema_with = "waits_schema"))]
    waits: BTreeMap<LocalId, AuthoredWait>,
    /// Where the run must stop.
    expect: AuthoredExpectation,
}

impl Identified for AuthoredScenario {
    fn id(&self) -> &str {
        self.id.as_str()
    }
}

#[derive(Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
enum AuthoredReply {
    /// The call completed and returned `value`.
    Success {
        /// The output the call returns, which must satisfy the operation's
        /// output contract.
        value: ForeignValue,
    },
    /// The call failed and may be retried; the run stops as retryable, or as
    /// uncertain after an earlier uncertain reply, unless a recovery consumes
    /// another reply.
    Retryable {
        /// The code the reply carries, such as credential-unavailable.
        code: LocalId,
    },
    /// The product refused the call; the run stops as refused, or as
    /// uncertain after an earlier uncertain reply.
    Refused {
        /// The code the reply carries, such as product-not-found.
        code: LocalId,
    },
    /// The product returned a package-declared, no-effect business refusal.
    /// A supported call takes its `onDeclaredRefusal` edge when it has one;
    /// otherwise the run stops as refused.
    DeclaredRefusal {
        /// The validated refusal code the package declares.
        refusal_code: RefusalCode,
    },
    /// The call's effect is unknown; the run stops as uncertain unless a
    /// recovery consumes another reply.
    Uncertain {
        /// The code the reply carries, such as transport-uncertain.
        code: LocalId,
    },
    /// The product's receipt for the call expired, so the original command
    /// cannot be confirmed; the run stops as uncertain and no later reply is
    /// consumed.
    ReceiptExpired {},
}
registry_platform_yaml::tagged_union!(AuthoredReply);

/// One package-declared refusal code, kept in the same bounded shape as the
/// protocol value without admitting an arbitrary product problem document.
struct RefusalCode(String);

impl std::fmt::Debug for RefusalCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RefusalCode(<undisclosed>)")
    }
}

impl<'de> Deserialize<'de> for RefusalCode {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        DeclaredRefusal::new(&text).map(|_| Self(text)).ok_or_else(|| {
            Invalid::expected(
                "a non-empty declared refusal code of at most 128 characters without control characters",
                "Write the package-declared refusal code exactly, without control characters.",
            )
            .into_error()
        })
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for RefusalCode {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "DeclaredRefusalCode".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "pattern": "^[^\\u0000-\\u001F\\u007F-\\u009F]+$",
        })
    }
}

#[derive(Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
enum AuthoredWait {
    /// The event arrives when the wait starts; the run continues at the
    /// step's `next` with `value` as the step's output.
    Event {
        /// The event, which must satisfy the step's event contract. A review
        /// result must also be one the review protocol accepts, for the
        /// request identifier, subject, policy and submission digest the
        /// request step accepted.
        value: ForeignValue,
    },
    /// No event arrives: the clock moves by the step's `timeoutSeconds`, and
    /// the run continues at its `onTimeout`, or stops as `timed-out` when the
    /// step has none. A deadline that passes first stops the run as
    /// `deadline-exceeded`.
    Timeout {},
    /// An authorized caller cancels the run while this wait is durably
    /// parked. The run continues at `onCancel`, or stops as `cancelled` when
    /// the step has none.
    Cancel {},
}
registry_platform_yaml::tagged_union!(AuthoredWait);

/// Where the run must stop. Omitted members are not checked.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
struct AuthoredExpectation {
    /// The steps the run reaches, in order.
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 64)))]
    path: UniqueList<LocalId>,
    /// The state the run stops in.
    state: ExpectedState,
    /// The outcome the run finishes with, or `{type: none}` for a run that
    /// finishes without one. Omit it to leave the outcome unchecked.
    #[serde(default)]
    outcome: Option<ExpectedOutcome>,
    /// The output the run finishes with. Omit it to leave the output
    /// unchecked.
    #[serde(default)]
    output: Option<ForeignValue>,
    /// The virtual seconds from admission to where the run stops. Omit it to
    /// leave the time unchecked.
    #[serde(default)]
    workflow_elapsed_seconds: Option<BoundedU32<0, 31_536_000>>,
}

/// A state a scenario run stops in: `completed` (a finish step ran),
/// `refused`, `retryable`, `uncertain`, `cancelled` (a waiting run was
/// cancelled), `timed-out` (a wait's timeout passed
/// and the wait has no `onTimeout`), or `deadline-exceeded` (the workflow
/// deadline passed first).
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
enum ExpectedState {
    Completed,
    Refused,
    Retryable,
    Uncertain,
    Cancelled,
    TimedOut,
    DeadlineExceeded,
}

impl ExpectedState {
    fn name(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Refused => "refused",
            Self::Retryable => "retryable",
            Self::Uncertain => "uncertain",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed-out",
            Self::DeadlineExceeded => "deadline-exceeded",
        }
    }
}

#[derive(Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
enum ExpectedOutcome {
    /// The run finishes with the outcome `value` names.
    Named {
        /// The outcome, declared under the workflow's `outcomes`.
        value: LocalId,
    },
    /// The run stops without an outcome.
    None {},
}
registry_platform_yaml::tagged_union!(ExpectedOutcome);

const MAX_SCENARIO_BYTES: u64 = 1_048_576;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScenarioDocument {
    pub cases: Vec<Scenario>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Scenario {
    pub name: String,
    pub admitted_at: DateTime<Utc>,
    pub input: Value,
    pub replies: BTreeMap<String, Vec<Reply>>,
    #[serde(default)]
    pub recovery: BTreeMap<String, Recovery>,
    #[serde(default)]
    pub waits: BTreeMap<String, Wait>,
    pub expect: Expectation,
}

/// An operator recovery: `retry-same` sends the same frozen command again
/// after a retryable reply, or after an uncertain one where the operation
/// allows it; `reconcile` reads the product's receipt for an uncertain
/// command, for operations that keep one.
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum Recovery {
    RetrySame,
    Reconcile,
}

#[derive(Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Reply {
    Success {
        success: Value,
    },
    Retryable {
        retryable: String,
    },
    Refused {
        refused: String,
    },
    DeclaredRefusal {
        #[serde(rename = "declaredRefusal")]
        declared_refusal: String,
    },
    Uncertain {
        uncertain: String,
    },
    ReceiptExpired {
        #[serde(rename = "receiptExpired")]
        receipt_expired: bool,
    },
}

/// What a wait-for step receives: the event it waits for, or its timeout.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Wait {
    Event { value: Value },
    Timeout,
    Cancel,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Expectation {
    pub path: Vec<String>,
    pub state: String,
    #[serde(default)]
    pub outcome: Option<String>,
    #[serde(skip)]
    /// Authored omission means not checked; explicit `none` checks absence.
    pub skip_outcome_check: bool,
    #[serde(default)]
    pub output: Option<Value>,
    #[serde(default)]
    pub elapsed_seconds: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScenarioReport {
    pub name: String,
    pub path: Vec<String>,
    pub state: String,
    pub outcome: Option<String>,
    pub output: Option<Value>,
    pub elapsed_seconds: i64,
    pub call_attempts: BTreeMap<String, usize>,
    pub frozen_commands: usize,
}

pub fn load(path: &Path) -> Result<ScenarioDocument> {
    load_with_document(path).map(|(scenarios, _)| scenarios)
}

/// Load a scenarios file with the document its findings are placed in.
pub(crate) fn load_with_document(path: &Path) -> Result<(ScenarioDocument, Document)> {
    let unreadable = || {
        error(
            "scenario.read",
            "",
            "the scenarios file could not be read",
            "Make the scenarios file a readable regular file, then rerun test.",
        )
        .at(path, "")
    };
    let metadata = std::fs::symlink_metadata(path).map_err(|failure| {
        if failure.kind() == std::io::ErrorKind::NotFound {
            CoordinatorError::new("scenario.missing", "the scenarios file is missing")
                .at(path, "/")
                .suggest("Add scenarios.yaml beside workflow.yaml with at least one case (coordinatorctl init writes a starter), or name another file with --scenarios.")
        } else {
            unreadable()
        }
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(error(
            "scenario.bound",
            "",
            "the scenarios path is not a regular file",
            "Replace the link or special file with a regular scenarios file.",
        )
        .at(path, ""));
    }
    let mut source = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| unreadable())?
        .take(MAX_SCENARIO_BYTES + 1)
        .read_to_end(&mut source)
        .map_err(|_| unreadable())?;
    decode_document(&source, &path.display().to_string())
}

/// Decode authored scenarios through the shared reader, keeping positioned findings.
pub fn decode(source: &str, file: &str) -> Result<ScenarioDocument> {
    decode_bytes(source.as_bytes(), file)
}

pub(crate) fn decode_bytes(source: &[u8], file: &str) -> Result<ScenarioDocument> {
    decode_document(source, file).map(|(scenarios, _)| scenarios)
}

fn decode_document(source: &[u8], file: &str) -> Result<(ScenarioDocument, Document)> {
    let mut hook = AuthoredExpressions;
    let decoded = Reader::new(file)
        .with_hook(&mut hook)
        .decode::<CoordinatorScenarios>(source, &Expect::one(&FORMAT))
        .map_err(CoordinatorError::from_report)?;
    let scenarios = decoded.value.into_document(&decoded.document)?;
    Ok((scenarios, decoded.document))
}

impl CoordinatorScenarios {
    fn into_document(self, document: &Document) -> Result<ScenarioDocument> {
        let mut findings = Vec::new();
        let mut bound = |pointer: &str, valid: bool, message: &str| {
            if !valid {
                findings.push(document.diagnostic_at_value(
                    Severity::Error,
                    "coordinator.scenarios.invalid-length",
                    pointer,
                    message,
                    "Keep the authored collection or quantity within the stated bounds.",
                ));
            }
        };
        bound(
            "/cases",
            (1..=64).contains(&self.cases.len()),
            "expected from 1 to 64 scenario cases",
        );
        for (index, case) in self.cases.iter().enumerate() {
            let path = format!("/cases/{index}");
            bound(
                &format!("{path}/replies"),
                case.replies.len() <= 64,
                "expected at most 64 reply steps",
            );
            bound(
                &format!("{path}/recovery"),
                case.recovery.len() <= 64,
                "expected at most 64 recovery steps",
            );
            bound(
                &format!("{path}/waits"),
                case.waits.len() <= 64,
                "expected at most 64 wait steps",
            );
            bound(
                &format!("{path}/expect/path"),
                (1..=64).contains(&case.expect.path.len()),
                "expected from 1 to 64 visited steps",
            );
            for (step, replies) in &case.replies {
                bound(
                    &format!("{path}/replies/{step}"),
                    (1..=8).contains(&replies.len()),
                    "expected from 1 to 8 synthetic replies",
                );
            }
        }
        let mut cases = Vec::new();
        for (index, case) in self.cases.into_iter().enumerate() {
            let path = format!("/cases/{index}");
            let admitted_at = match DateTime::parse_from_rfc3339(&case.admitted_at) {
                Ok(timestamp) => timestamp.with_timezone(&Utc),
                Err(_) => {
                    findings.push(document.diagnostic_at_value(
                        Severity::Error,
                        "coordinator.scenarios.invalid-timestamp",
                        &format!("{path}/admittedAt"),
                        "expected an RFC 3339 timestamp",
                        "Write the admission instant with an explicit offset.",
                    ));
                    continue;
                }
            };
            cases.push(Scenario {
                name: case.id.into_string(),
                admitted_at,
                input: case.input.into_value(),
                replies: case
                    .replies
                    .into_iter()
                    .map(|(step, replies)| {
                        (
                            step.into_string(),
                            replies
                                .into_iter()
                                .map(|reply| match reply {
                                    AuthoredReply::Success { value } => Reply::Success {
                                        success: value.into_value(),
                                    },
                                    AuthoredReply::Retryable { code } => Reply::Retryable {
                                        retryable: code.into_string(),
                                    },
                                    AuthoredReply::Refused { code } => Reply::Refused {
                                        refused: code.into_string(),
                                    },
                                    AuthoredReply::DeclaredRefusal { refusal_code } => {
                                        Reply::DeclaredRefusal {
                                            declared_refusal: refusal_code.0,
                                        }
                                    }
                                    AuthoredReply::Uncertain { code } => Reply::Uncertain {
                                        uncertain: code.into_string(),
                                    },
                                    AuthoredReply::ReceiptExpired {} => Reply::ReceiptExpired {
                                        receipt_expired: true,
                                    },
                                })
                                .collect(),
                        )
                    })
                    .collect(),
                recovery: case
                    .recovery
                    .into_iter()
                    .map(|(step, recovery)| (step.into_string(), recovery))
                    .collect(),
                waits: case
                    .waits
                    .into_iter()
                    .map(|(step, wait)| {
                        (
                            step.into_string(),
                            match wait {
                                AuthoredWait::Event { value } => Wait::Event {
                                    value: value.into_value(),
                                },
                                AuthoredWait::Timeout {} => Wait::Timeout,
                                AuthoredWait::Cancel {} => Wait::Cancel,
                            },
                        )
                    })
                    .collect(),
                expect: Expectation {
                    path: case
                        .expect
                        .path
                        .into_iter()
                        .map(LocalId::into_string)
                        .collect(),
                    state: case.expect.state.name().into(),
                    skip_outcome_check: case.expect.outcome.is_none(),
                    outcome: match case.expect.outcome {
                        Some(ExpectedOutcome::Named { value }) => Some(value.into_string()),
                        Some(ExpectedOutcome::None {}) | None => None,
                    },
                    output: case.expect.output.map(ForeignValue::into_value),
                    elapsed_seconds: case
                        .expect
                        .workflow_elapsed_seconds
                        .map(|seconds| i64::from(seconds.get())),
                },
            });
        }
        if !findings.is_empty() {
            return Err(CoordinatorError::from_diagnostics(&findings));
        }
        Ok(ScenarioDocument { cases })
    }
}

#[cfg(feature = "schema")]
fn replies_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "object",
        "propertyNames": generator.subschema_for::<LocalId>(),
        "maxProperties": 64,
        "additionalProperties": {
            "type": "array", "minItems": 1, "maxItems": 8,
            "items": generator.subschema_for::<AuthoredReply>(),
        },
    })
}

#[cfg(feature = "schema")]
fn recovery_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "object",
        "propertyNames": generator.subschema_for::<LocalId>(),
        "maxProperties": 64,
        "additionalProperties": generator.subschema_for::<Recovery>(),
    })
}

#[cfg(feature = "schema")]
fn waits_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "object",
        "propertyNames": generator.subschema_for::<LocalId>(),
        "maxProperties": 64,
        "additionalProperties": generator.subschema_for::<AuthoredWait>(),
    })
}

#[cfg(feature = "schema")]
pub fn scenario_schema() -> std::result::Result<String, serde_json::Error> {
    let mut schema = serde_json::to_value(schemars::schema_for!(CoordinatorScenarios))?;
    crate::schema::finish(&mut schema, API_VERSION, KIND, SCHEMA_ID);
    Ok(format!("{}\n", serde_json::to_string_pretty(&schema)?))
}

/// This runner never resolves runtime configuration or opens network/database I/O.
/// Responses, outages and recovery are synthetic scenario replies, not Dispatch
/// or downstream product proofs. Time advances to authored wait instants and
/// stated timeouts, bounded by the workflow deadline.
pub fn run(definition: &Definition, scenario: &Scenario) -> Result<ScenarioReport> {
    let report = execute(definition, scenario)?;
    match mismatches(scenario, &report).into_iter().next() {
        Some(mismatch) => Err(mismatch),
        None => Ok(report),
    }
}

/// One case run to its end, before the run is compared with its expectation.
fn execute(definition: &Definition, scenario: &Scenario) -> Result<ScenarioReport> {
    definition
        .validate_input(&scenario.input)
        .map_err(|refused| match definition.input_refusal(&scenario.input) {
            Some(detail) => CoordinatorError {
                message: format!("the workflow input schema refuses the case input{detail}"),
                ..refused
            }
            .at(SCENARIOS_FILE, "/input")
            .suggest("Correct the case input, or the workflow input schema if the input is right."),
            None => refused,
        })?;
    let call_steps = || {
        definition
            .workflow
            .steps
            .iter()
            .filter(|(_, step)| matches!(step, Step::Call { .. }))
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    for (step, replies) in &scenario.replies {
        let Some(Step::Call { call, .. }) = definition.workflow.steps.get(step) else {
            return Err(error(
                "scenario.reply-step",
                format!("/replies/{step}"),
                format!("replies name step {step}, which is not a call step"),
                format!("Give replies only to call steps: {}.", call_steps()),
            ));
        };
        // Every synthetic success is held to the operation output, whether or
        // not this run consumes it.
        let operation = call.operation.as_str();
        for (index, reply) in replies.iter().enumerate() {
            match reply {
                Reply::Success { success } => {
                    contract(call.operation)
                        .check_output(success)
                        .map_err(|violation| {
                            contract_error(
                                "scenario.reply-output",
                                format!("/replies/{step}/{index}/value{}", violation.path),
                                &violation,
                                &format!("in a success reply to step {step}, as the {operation} output declares; the synthetic value does not match"),
                                &format!("Correct the synthetic value so it satisfies the {operation} output."),
                            )
                        })?;
                }
                Reply::DeclaredRefusal { declared_refusal } => {
                    if !call.operation.descriptor().declared_refusal {
                        return Err(error(
                            "scenario.reply",
                            format!("/replies/{step}/{index}"),
                            format!("step {step} calls {operation}, which cannot return a package-declared business refusal"),
                            "Use declared-refusal only for invoke-breg-action; use refused for an operational or authority refusal.",
                        ));
                    }
                    if DeclaredRefusal::new(declared_refusal).is_none() {
                        return Err(error(
                            "scenario.reply",
                            format!("/replies/{step}/{index}/refusalCode"),
                            format!("the declared refusal code for step {step} is outside its contract"),
                            "Write a non-empty package-declared refusal code of at most 128 characters without control characters.",
                        ));
                    }
                }
                _ => {}
            }
        }
    }
    for (step, recovery) in &scenario.recovery {
        let Some(Step::Call { call, .. }) = definition.workflow.steps.get(step) else {
            return Err(error(
                "scenario.recovery",
                format!("/recovery/{step}"),
                format!("recovery names step {step}, which is not a call step"),
                format!("Give recovery only to call steps: {}.", call_steps()),
            ));
        };
        if matches!(recovery, Recovery::Reconcile) && !call.operation.supports_read_receipt() {
            return Err(error(
                "scenario.recovery",
                format!("/recovery/{step}"),
                format!(
                    "step {step} calls {}, which has no read receipt to reconcile against",
                    call.operation.as_str()
                ),
                "Use retry-same for this step, or remove its recovery.",
            ));
        }
    }
    for (step, wait) in &scenario.waits {
        let Some(Step::WaitFor { wait_for, .. }) = definition.workflow.steps.get(step) else {
            return Err(error(
                "scenario.wait-step",
                format!("/waits/{step}"),
                format!("waits name step {step}, which is not a wait-for step"),
                wait_steps_action(definition, "State waits only for wait-for steps"),
            ));
        };
        // Every stated event is held to its contract, whether or not this
        // run reaches the wait.
        if let Wait::Event { value } = wait {
            check_event(step, wait_for, value)?;
        }
    }
    let deadline = definition.deadline_at(scenario.admitted_at)?;
    let mut now = scenario.admitted_at;
    let mut step = definition.workflow.start.clone();
    let mut outputs = BTreeMap::new();
    let mut report = ScenarioReport {
        name: scenario.name.clone(),
        path: Vec::new(),
        state: "running".into(),
        outcome: None,
        output: None,
        elapsed_seconds: 0,
        call_attempts: BTreeMap::new(),
        frozen_commands: 0,
    };
    for _ in 0..=64 {
        if now >= deadline {
            report.state = "deadline-exceeded".into();
            break;
        }
        report.path.push(step.clone());
        match definition.workflow.steps.get(&step).ok_or_else(|| {
            error(
                "scenario.step",
                "",
                format!("the run reached step {step}, which the workflow does not declare"),
                "Run check on the project; a checked workflow names only declared steps.",
            )
        })? {
            Step::WaitUntil { next, .. } => {
                now = now
                    .max(parse_timestamp(&definition.evaluate_synthetic(
                        &step,
                        &scenario.input,
                        &outputs,
                    )?)?)
                    .min(deadline);
                step = next.clone();
            }
            Step::WaitFor {
                wait_for,
                timeout_seconds,
                next,
                on_timeout,
                on_cancel,
            } => {
                // A case without waits is refused at the case itself.
                let at = if scenario.waits.is_empty() {
                    ""
                } else {
                    "/waits"
                };
                let wait = scenario.waits.get(&step).ok_or_else(|| {
                    error(
                        "scenario.wait",
                        at,
                        format!("the run reached wait step {step}, which this case states no event or timeout for"),
                        format!("Add waits.{step} with the event this wait receives ({{type: event, value: ...}}) or {{type: timeout}}."),
                    )
                })?;
                match wait {
                    Wait::Event { value } => {
                        correlate(&step, wait_for, value, &outputs)?;
                        outputs.insert(step.clone(), value.clone());
                        step = next.clone();
                    }
                    Wait::Timeout => {
                        now = (now + chrono::Duration::seconds(i64::from(*timeout_seconds)))
                            .min(deadline);
                        match on_timeout {
                            Some(route) => step = route.clone(),
                            None => {
                                report.state = if now >= deadline {
                                    "deadline-exceeded"
                                } else {
                                    "timed-out"
                                }
                                .into();
                                break;
                            }
                        }
                    }
                    Wait::Cancel => match on_cancel {
                        Some(route) => step = route.clone(),
                        None => {
                            report.state = "cancelled".into();
                            break;
                        }
                    },
                }
            }
            Step::Choose { cases, .. } => {
                let choice = definition.evaluate_synthetic(&step, &scenario.input, &outputs)?;
                step = choice
                    .as_str()
                    .and_then(|label| cases.get(label))
                    .ok_or_else(|| {
                        error(
                            "scenario.branch",
                            "",
                            format!(
                                "step {step} chose a value of class {}, which is not one of its case labels",
                                class(&choice)
                            ),
                            format!("Return one of the case labels of step {step}."),
                        )
                    })?
                    .clone();
            }
            Step::Finish { finish, output } => {
                let result = match output {
                    Some(_) => definition.evaluate_synthetic(&step, &scenario.input, &outputs)?,
                    None => {
                        definition
                            .validate_outcome(finish, &Value::Null)
                            .map_err(|refused| {
                                CoordinatorError {
                                    message: format!("step {step} finishes without an output, and the {finish} outcome schema refuses null"),
                                    ..refused
                                }
                                .at("workflow.yaml", format!("steps.{step}.finish"))
                                .suggest(format!("Give step {step} an output that satisfies the {finish} outcome schema, or declare that outcome as type null."))
                            })?;
                        Value::Null
                    }
                };
                report.state = "completed".into();
                report.outcome = Some(finish.clone());
                report.output = Some(result);
                break;
            }
            Step::Call {
                call,
                next,
                on_declared_refusal,
                ..
            } => {
                let value = definition.evaluate_synthetic(&step, &scenario.input, &outputs)?;
                let operation = call.operation.as_str();
                contract(call.operation)
                    .check_input(&value)
                    .map_err(|violation| {
                        contract_error(
                            "scenario.call-input",
                            String::new(),
                            &violation,
                            &format!("in the input step {step} computes, as the {operation} input declares; the computed input does not match"),
                            &format!("Correct the steps.{step}.input mapping, or the scenario data it reads, so the computed input satisfies the {operation} input."),
                        )
                    })?;
                let command = CallRequest {
                    connection: call.connection.clone(),
                    operation: call.operation,
                    input: value,
                    idempotency_key: if call.operation.requires_key() {
                        Some(format!(
                            "scenario-{}",
                            registry_platform_config::sha256_uri(
                                format!("{}\0{}\0{}", scenario.name, step, definition.digest)
                                    .as_bytes()
                            )
                        ))
                    } else {
                        None
                    },
                };
                let replayed = || {
                    error(
                        "scenario.command",
                        "",
                        format!("the frozen command of step {step} could not be replayed unchanged"),
                        "Report this Coordinator defect with the project; a frozen command never changes between replies.",
                    )
                };
                // Keep this value for every recovery reply: mapping evaluation and
                // authority selection never run again for a prepared mutation.
                let frozen = serde_json::to_vec(&command).map_err(|_| replayed())?;
                if command.operation.has_dispatch_risk() {
                    report.frozen_commands += 1;
                }
                let replies = scenario.replies.get(&step).ok_or_else(|| {
                    error(
                        "scenario.reply",
                        "/replies",
                        format!("the run reached call step {step}, which has no synthetic replies"),
                        format!(
                            "Add replies.{step} with the replies this call receives in this case."
                        ),
                    )
                })?;
                let recovery = scenario.recovery.get(&step);
                let mut prior_unknown = false;
                let mut completion = None;
                for (index, reply) in replies.iter().enumerate() {
                    let at = format!("/replies/{step}/{index}");
                    if command.operation.is_evaluation()
                        && matches!(reply, Reply::ReceiptExpired { .. })
                    {
                        return Err(error(
                            "scenario.reply",
                            at,
                            format!("step {step} calls {operation}, an evaluation without a receipt, so it cannot reply receipt-expired"),
                            "Use an uncertain, retryable, refused or success reply for this step.",
                        ));
                    }
                    if index > 0 && recovery.is_none() {
                        return Err(error(
                            "scenario.recovery",
                            at,
                            format!("step {step} has a reply after its first, and no recovery to consume it"),
                            format!("Add recovery.{step} (retry-same or reconcile), or keep only the first reply."),
                        ));
                    }
                    if index > 0 && prior_unknown && !command.operation.can_retry_after_unknown() {
                        return Err(error(
                            "scenario.recovery",
                            at,
                            format!("step {step} calls {operation}, which holds the run after an uncertain reply, so no later reply is consumed"),
                            "End the replies at the uncertain one, as a held run would.",
                        ));
                    }
                    // Receipt observation can resolve an unknown mutation,
                    // never create success after a definite retryable rejection.
                    if index > 0
                        && matches!(recovery, Some(Recovery::Reconcile))
                        && (!command.operation.supports_read_receipt() || !prior_unknown)
                    {
                        return Err(error(
                            "scenario.recovery",
                            at,
                            format!("reconcile at step {step} observes an uncertain command, and no reply before this one was uncertain"),
                            "Use retry-same after a retryable reply, or make an earlier reply uncertain.",
                        ));
                    }
                    let same: CallRequest =
                        serde_json::from_slice(&frozen).map_err(|_| replayed())?;
                    if same.operation != command.operation
                        || same.input != command.input
                        || same.idempotency_key != command.idempotency_key
                    {
                        return Err(replayed());
                    }
                    *report.call_attempts.entry(step.clone()).or_default() += 1;
                    match reply {
                        Reply::Success { success: value } => {
                            completion = Some((next.clone(), value.clone()));
                            break;
                        }
                        Reply::DeclaredRefusal { declared_refusal } => {
                            if prior_unknown {
                                report.state = "uncertain".into();
                            } else if let Some(target) = on_declared_refusal {
                                let refusal = DeclaredRefusal::new(declared_refusal).ok_or_else(|| {
                                    error(
                                        "scenario.reply",
                                        format!("{at}/refusalCode"),
                                        format!("the declared refusal code for step {step} is outside its contract"),
                                        "Write a non-empty package-declared refusal code of at most 128 characters without control characters.",
                                    )
                                })?;
                                let output = serde_json::to_value(refusal).map_err(|_| {
                                    error(
                                        "scenario.reply",
                                        format!("{at}/refusalCode"),
                                        format!("the declared refusal code for step {step} could not be retained"),
                                        "Report this Coordinator defect with the project.",
                                    )
                                })?;
                                completion = Some((target.clone(), output));
                            } else {
                                report.state = "refused".into();
                            }
                            break;
                        }
                        Reply::Uncertain { .. } => {
                            prior_unknown = true;
                            report.state = "uncertain".into();
                        }
                        Reply::ReceiptExpired {
                            receipt_expired: true,
                        } => {
                            report.state = "uncertain".into();
                            // Supported product receipts cannot confirm an
                            // original command after expiry. Neither retry nor
                            // reconciliation may consume a later synthetic reply.
                            if index + 1 < replies.len() {
                                return Err(error(
                                    "scenario.receipt-expired",
                                    format!("/replies/{step}/{}", index + 1),
                                    format!("step {step} replies after receipt-expired, which ends its recovery"),
                                    "Remove the replies after receipt-expired: an expired receipt cannot confirm the original command, so neither retry nor reconciliation consumes another reply.",
                                ));
                            }
                            break;
                        }
                        Reply::ReceiptExpired {
                            receipt_expired: false,
                        } => {
                            return Err(error(
                                "scenario.reply",
                                at,
                                format!("a receipt-expired reply to step {step} is false"),
                                "Write receipt-expired only for a receipt that expired.",
                            ))
                        }
                        Reply::Refused { .. } => {
                            report.state = if prior_unknown {
                                "uncertain"
                            } else {
                                "refused"
                            }
                            .into();
                            break;
                        }
                        Reply::Retryable { .. } => {
                            report.state = if prior_unknown {
                                "uncertain"
                            } else {
                                "retryable"
                            }
                            .into();
                        }
                    }
                }
                if let Some((target, value)) = completion {
                    outputs.insert(step.clone(), value);
                    report.state = "running".into();
                    step = target;
                } else {
                    break;
                }
            }
        }
    }
    report.elapsed_seconds = (now - scenario.admitted_at).num_seconds();
    if report.state == "running" {
        return Err(error(
            "scenario.bound",
            "",
            "the run did not finish within the 64-step scenario bound",
            "Run check on the project; a checked workflow finishes within its steps.",
        ));
    }
    Ok(report)
}

/// The action that names the wait-for steps a case may state waits for.
fn wait_steps_action(definition: &Definition, lead: &str) -> String {
    let steps = definition
        .workflow
        .steps
        .iter()
        .filter(|(_, step)| matches!(step, Step::WaitFor { .. }))
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>();
    if steps.is_empty() {
        "Remove waits; this workflow declares no wait-for step.".into()
    } else {
        format!("{lead}: {}.", steps.join(", "))
    }
}

/// An event a case states for step `step`, held to the step's event contract
/// and, for a review result, to the review protocol's rules for a result a
/// producer may return. Refusals name pointers and expectations, never the
/// stated value.
fn check_event(step: &str, event: &WaitEvent, value: &Value) -> Result<()> {
    let pointer = format!("/waits/{step}/value");
    let kind = event.id();
    event_contract(event).check(value).map_err(|violation| {
        contract_error(
            "scenario.wait-event",
            format!("{pointer}{}", violation.path),
            &violation,
            &format!("in the event stated for step {step}, as the {kind} event declares; the stated value does not match"),
            &format!("Correct the stated value so it satisfies the {kind} event."),
        )
    })?;
    match event {
        WaitEvent::ReviewResult { .. } => {
            let broken = |rule: String| {
                error(
                    "scenario.wait-event",
                    pointer.clone(),
                    format!("the review result stated for step {step} breaks a review protocol rule: {rule}"),
                    "Correct the stated result so the review protocol accepts it; a producer returns no other result.",
                )
            };
            let result = serde_json::from_value::<ReviewResult>(value.clone())
                .map_err(|_| broken("its members do not form a review result".into()))?;
            result.check().map_err(|rule| broken(rule.to_string()))
        }
    }
}

/// A stated event belongs to the request its wait names. A review result
/// carries the request identifier, subject, policy and submission digest
/// the request step accepted, as the producer client requires of every
/// result it reads. A refusal names the member that differs, never a value.
fn correlate(
    step: &str,
    event: &WaitEvent,
    value: &Value,
    outputs: &BTreeMap<String, Value>,
) -> Result<()> {
    match event {
        WaitEvent::ReviewResult { request } => {
            let accepted = outputs.get(request).and_then(|output| {
                serde_json::from_value::<ReviewRequestAccepted>(output.clone()).ok()
            });
            let result = serde_json::from_value::<ReviewResult>(value.clone()).ok();
            let (Some(accepted), Some(result)) = (accepted, result) else {
                return Err(error(
                    "scenario.wait-event",
                    format!("/waits/{step}/value"),
                    format!("the review result stated for step {step} cannot be matched to the request step {request} accepted"),
                    format!("Give step {request} a success reply that satisfies the submit-review-request output."),
                ));
            };
            let differs = [
                ("requestId", result.request_id != accepted.request_id),
                ("subject", result.subject != accepted.subject),
                ("policy", result.policy != accepted.policy),
                (
                    "submissionDigest",
                    result.submission_digest != accepted.submission_digest,
                ),
            ]
            .into_iter()
            .find_map(|(member, differs)| differs.then_some(member));
            match differs {
                Some(member) => Err(error(
                    "scenario.wait-event",
                    format!("/waits/{step}/value/{member}"),
                    format!("the review result stated for step {step} carries a {member} other than the one step {request} accepted; the producer client refuses a result for another request"),
                    format!("Copy requestId, subject, policy and submissionDigest from the success reply to step {request}."),
                )),
                None => Ok(()),
            }
        }
    }
}

/// The differences one case lists before it counts the rest.
const MISMATCHES_LISTED: usize = 20;

const EXPECTATION_ACTION: &str = "Correct this expectation if the run is right; otherwise correct the workflow, functions or synthetic replies that produced it.";

/// Each way a finished run differs from its case's expectation, at the
/// expectation it breaks. Steps, run states and outcomes are declared
/// identifiers and accepted values, so a difference in them names both
/// sides. Any other member is named by JSON Pointer and the class of each
/// side, never by value: an expectation may hold values read from a file,
/// and a run may carry them into its result. A case lists its first
/// `MISMATCHES_LISTED` differences and counts the rest.
fn mismatches(scenario: &Scenario, report: &ScenarioReport) -> Vec<CoordinatorError> {
    let expected = &scenario.expect;
    let mut found = Vec::new();
    for index in 0..expected.path.len().max(report.path.len()) {
        let (wanted, reached) = (expected.path.get(index), report.path.get(index));
        if wanted != reached {
            let pointer = format!("/expect/path/{index}");
            // A step only the run took is placed at the path that lacks it.
            let placement = if wanted.is_some() {
                pointer.as_str()
            } else {
                "/expect/path"
            };
            found.push(named(&pointer, placement, "step", wanted, reached));
        }
    }
    if expected.state != report.state {
        found.push(named(
            "/expect/state",
            "/expect/state",
            "state",
            Some(&expected.state),
            Some(&report.state),
        ));
    }
    if !expected.skip_outcome_check && expected.outcome != report.outcome {
        // An expected absence is authored at the outcome itself.
        let pointer = if expected.outcome.is_some() {
            "/expect/outcome/value"
        } else {
            "/expect/outcome"
        };
        found.push(named(
            pointer,
            pointer,
            "outcome",
            expected.outcome.as_ref(),
            report.outcome.as_ref(),
        ));
    }
    if let Some(output) = &expected.output {
        differences(
            Some(output),
            report.output.as_ref(),
            "/expect/output".into(),
            &mut found,
        );
    }
    if let Some(seconds) = expected.elapsed_seconds {
        differences(
            Some(&Value::from(seconds)),
            Some(&Value::from(report.elapsed_seconds)),
            "/expect/workflowElapsedSeconds".into(),
            &mut found,
        );
    }
    if found.len() > MISMATCHES_LISTED {
        let more = found.len() - MISMATCHES_LISTED;
        found.truncate(MISMATCHES_LISTED);
        let noun = if more == 1 {
            "difference"
        } else {
            "differences"
        };
        found.push(error(
            "scenario.expectation",
            "/expect",
            format!("and {more} more {noun}"),
            EXPECTATION_ACTION,
        ));
    }
    found
}

/// A step, run state or outcome that differs, named on each side.
fn named(
    pointer: &str,
    placement: &str,
    kind: &str,
    expected: Option<&String>,
    observed: Option<&String>,
) -> CoordinatorError {
    let side = |value: Option<&String>| {
        value.map_or_else(|| format!("no {kind}"), |value| format!("{kind} {value}"))
    };
    error(
        "scenario.expectation",
        placement,
        format!(
            "{pointer}: expected {}, observed {}",
            side(expected),
            side(observed)
        ),
        EXPECTATION_ACTION,
    )
}

/// Every member at or below `pointer` where `observed` differs from
/// `expected`. Objects are compared member by member and arrays item by item;
/// any other pair differs as a whole.
fn differences(
    expected: Option<&Value>,
    observed: Option<&Value>,
    pointer: String,
    found: &mut Vec<CoordinatorError>,
) {
    match (expected, observed) {
        (Some(Value::Object(expected)), Some(Value::Object(observed))) => {
            let members = expected
                .keys()
                .chain(observed.keys())
                .collect::<BTreeSet<_>>();
            for member in members {
                let escaped = member.replace('~', "~0").replace('/', "~1");
                differences(
                    expected.get(member),
                    observed.get(member),
                    format!("{pointer}/{escaped}"),
                    found,
                );
            }
        }
        (Some(Value::Array(expected)), Some(Value::Array(observed))) => {
            for index in 0..expected.len().max(observed.len()) {
                differences(
                    expected.get(index),
                    observed.get(index),
                    format!("{pointer}/{index}"),
                    found,
                );
            }
        }
        (expected, observed) if expected != observed => {
            // A member only the run has is placed at the expectation that
            // lacks it.
            let placement = match expected {
                Some(_) => pointer.as_str(),
                None => pointer.rsplit_once('/').map_or("", |(parent, _)| parent),
            };
            found.push(difference(&pointer, placement, expected, observed));
        }
        _ => {}
    }
}

/// One member that differs, named by its pointer and the class of each side.
fn difference(
    pointer: &str,
    placement: &str,
    expected: Option<&Value>,
    observed: Option<&Value>,
) -> CoordinatorError {
    let classed = |side: Option<&Value>| {
        side.map_or_else(
            || "absent".to_owned(),
            |value| format!("class {}", class(value)),
        )
    };
    let cause = match (expected, observed) {
        (Some(_), None) => "the run has no value here",
        (None, _) => "the expectation has no value here",
        (Some(expected), Some(observed)) if class(expected) == class(observed) => {
            "the values differ"
        }
        _ => "the classes differ",
    };
    error(
        "scenario.expectation",
        placement,
        format!(
            "{pointer}: {cause} (expected {}, observed {})",
            classed(expected),
            classed(observed)
        ),
        EXPECTATION_ACTION,
    )
}

pub fn check(definition: &Definition, document: &ScenarioDocument) -> Result<Vec<ScenarioReport>> {
    document
        .cases
        .iter()
        .enumerate()
        .map(|(index, scenario)| {
            run(definition, scenario).map_err(|error| {
                if error.file.as_deref() == Some(Path::new(SCENARIOS_FILE)) {
                    let pointer = case_pointer(&error, index);
                    error.at(SCENARIOS_FILE, pointer)
                } else {
                    error
                }
            })
        })
        .collect()
}

/// Every case of one project's scenarios, as `check` and `test` both report
/// them. Each refusal is placed where it was authored: in the workflow when a
/// step refused the value it computed, otherwise in the case. One refusal
/// that several cases reach is reported once and names each of them.
pub(crate) fn run_project(
    definition: &Definition,
    workflow: &Document,
    document: &Document,
    scenarios: &ScenarioDocument,
) -> (Vec<Value>, Vec<Diagnostic>) {
    let mut found: Vec<(Diagnostic, Vec<&str>)> = Vec::new();
    let mut cases = Vec::new();
    for (index, scenario) in scenarios.cases.iter().enumerate() {
        let unknown = unknown_references(definition, document, index, scenario);
        let (mut value, findings) = if !unknown.is_empty() {
            (json!({"name": scenario.name}), unknown)
        } else {
            match execute(definition, scenario) {
                Ok(report) => {
                    let findings = mismatches(scenario, &report)
                        .into_iter()
                        .flat_map(|mismatch| placed(mismatch, index, workflow, document))
                        .collect();
                    // A case reports its name, its verdict and the declared
                    // steps, state and outcome its run reached; the values
                    // its run computed stay out of the report.
                    (
                        json!({
                            "name": scenario.name,
                            "path": report.path,
                            "state": report.state,
                            "outcome": report.outcome,
                        }),
                        findings,
                    )
                }
                Err(refused) => (
                    json!({"name": scenario.name}),
                    placed(refused, index, workflow, document),
                ),
            }
        };
        value["status"] = json!(if findings.is_empty() {
            "passed"
        } else {
            "failed"
        });
        for finding in findings {
            match found.iter_mut().find(|(seen, _)| *seen == finding) {
                Some((_, names)) => names.push(&scenario.name),
                None => found.push((finding, vec![&scenario.name])),
            }
        }
        cases.push(value);
    }
    let diagnostics = found
        .into_iter()
        .map(|(mut finding, names)| {
            let cases = if names.len() == 1 { "case" } else { "cases" };
            finding.message = format!("scenario {cases} {}: {}", names.join(", "), finding.message);
            finding
        })
        .collect();
    (cases, diagnostics)
}

/// Steps and outcomes a case names that the workflow does not declare.
/// Running such a case would only report them again as a later refusal.
fn unknown_references(
    definition: &Definition,
    document: &Document,
    index: usize,
    scenario: &Scenario,
) -> Vec<Diagnostic> {
    let workflow = &definition.workflow;
    let declared = |names: Vec<&str>| names.join(", ");
    let steps = || declared(workflow.steps.keys().map(String::as_str).collect());
    let calls = || {
        declared(
            workflow
                .steps
                .iter()
                .filter(|(_, step)| matches!(step, Step::Call { .. }))
                .map(|(name, _)| name.as_str())
                .collect(),
        )
    };
    let mut findings = Vec::new();
    let mut unknown = |pointer: String, message: String, action: String| {
        findings.push(document.diagnostic_at_value(
            Severity::Error,
            "coordinator.scenarios.unknown-reference",
            &format!("/cases/{index}{pointer}"),
            &message,
            &action,
        ));
    };
    for (member, step) in scenario
        .replies
        .keys()
        .map(|step| ("replies", step))
        .chain(scenario.recovery.keys().map(|step| ("recovery", step)))
    {
        if !workflow.steps.contains_key(step) {
            unknown(
                format!("/{member}/{step}"),
                format!("{member} names step {step}, which this workflow does not declare"),
                format!("Name one of the call steps: {}.", calls()),
            );
        }
    }
    for step in scenario.waits.keys() {
        if !workflow.steps.contains_key(step) {
            unknown(
                format!("/waits/{step}"),
                format!("waits name step {step}, which this workflow does not declare"),
                wait_steps_action(definition, "Name one of the wait-for steps"),
            );
        }
    }
    for (position, step) in scenario.expect.path.iter().enumerate() {
        if !workflow.steps.contains_key(step) {
            unknown(
                format!("/expect/path/{position}"),
                format!(
                    "the expected path names step {step}, which this workflow does not declare"
                ),
                format!("Name one of the declared steps: {}.", steps()),
            );
        }
    }
    if let Some(outcome) = scenario
        .expect
        .outcome
        .as_ref()
        .filter(|outcome| !workflow.outcomes.contains_key(*outcome))
    {
        unknown(
            "/expect/outcome/value".into(),
            format!("the expected outcome {outcome} is not declared by this workflow"),
            format!(
                "Name one of the declared outcomes: {}.",
                declared(workflow.outcomes.keys().map(String::as_str).collect())
            ),
        );
    }
    findings
}

/// The findings of one refusal from case `index`, placed in the workflow
/// when a step refused what it computed, and otherwise in the case.
fn placed(
    refused: CoordinatorError,
    index: usize,
    workflow: &Document,
    document: &Document,
) -> Vec<Diagnostic> {
    if refused.file.as_deref() == Some(Path::new("workflow.yaml")) {
        return authoring::positioned(workflow, refused)
            .report()
            .into_diagnostics();
    }
    if !refused.diagnostics.is_empty() {
        return refused.diagnostics.into_vec();
    }
    let pointer = case_pointer(&refused, index);
    refused
        .report()
        .into_diagnostics()
        .into_iter()
        .map(|finding| {
            document.diagnostic_at_value(
                finding.severity,
                &finding.code,
                &pointer,
                &finding.message,
                &finding.suggested_action,
            )
        })
        .collect()
}

/// Where a refusal from `run` sits in its scenario document: inside case
/// `index`, at the pointer a refusal carries relative to that case, or at the
/// case itself.
pub(crate) fn case_pointer(error: &CoordinatorError, index: usize) -> String {
    let within = error
        .field
        .as_deref()
        .filter(|field| {
            field.starts_with('/') && error.file.as_deref() == Some(Path::new(SCENARIOS_FILE))
        })
        .unwrap_or_default();
    format!("/cases/{index}{within}")
}

/// A value outside an operation contract. The message names where the value
/// leaves the contract and what the contract expects, never the value.
fn contract_error(
    code: &'static str,
    within: String,
    violation: &Violation,
    context: &str,
    action: &str,
) -> CoordinatorError {
    let at = if violation.path.is_empty() {
        String::new()
    } else {
        format!(" at {}", violation.path)
    };
    CoordinatorError::new(
        code,
        format!("expected {}{at} {context}", violation.expected),
    )
    .at(SCENARIOS_FILE, within)
    .suggest(action)
}

/// A refusal at `pointer` within the case that reached it.
fn error(
    code: &'static str,
    pointer: impl Into<String>,
    message: impl Into<String>,
    action: impl Into<String>,
) -> CoordinatorError {
    CoordinatorError::new(code, message)
        .at(SCENARIOS_FILE, pointer)
        .suggest(action)
}
