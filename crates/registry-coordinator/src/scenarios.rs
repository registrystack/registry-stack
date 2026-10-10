// SPDX-License-Identifier: Apache-2.0
//! Bounded offline scenarios over the exact workflow graph and pure mappings.

use crate::{
    definition::{parse_timestamp, Definition, Step},
    protocol::CallRequest,
    CoordinatorError, Result,
};
use chrono::{DateTime, Utc};
use registry_platform_config::AuthoredExpressions;
use registry_platform_yaml::{
    ApiVersion, BoundedU32, Document, EnvelopeRule, Expect, ForeignValue, FormatSpec, Identified,
    LocalId, Reader, Severity, UniqueIdList, UniqueList,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, io::Read as _, path::Path};

pub const API_VERSION: &str = "id.registrystack.org/formats/coordinator/scenarios/v1alpha1";
pub const KIND: &str = "CoordinatorScenarios";
pub const SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/coordinator/scenarios/scenarios.v1alpha1.schema.json";
const FORMAT: FormatSpec<'static> = FormatSpec {
    kind: KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

/// The authored format is separate from the stable offline execution types.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CoordinatorScenarios {
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 64)))]
    cases: UniqueIdList<AuthoredScenario>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
struct AuthoredScenario {
    id: LocalId,
    #[cfg_attr(feature = "schema", schemars(extend("format" = "date-time")))]
    admitted_at: String,
    input: ForeignValue,
    #[cfg_attr(feature = "schema", schemars(schema_with = "replies_schema"))]
    replies: BTreeMap<LocalId, Vec<AuthoredReply>>,
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(schema_with = "recovery_schema"))]
    recovery: BTreeMap<LocalId, Recovery>,
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
    Success { value: ForeignValue },
    Retryable { code: LocalId },
    Refused { code: LocalId },
    Uncertain { code: LocalId },
    ReceiptExpired {},
}
registry_platform_yaml::tagged_union!(AuthoredReply);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
struct AuthoredExpectation {
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 64)))]
    path: UniqueList<LocalId>,
    state: ExpectedState,
    #[serde(default)]
    outcome: Option<ExpectedOutcome>,
    #[serde(default)]
    output: Option<ForeignValue>,
    #[serde(default)]
    workflow_elapsed_seconds: Option<BoundedU32<0, 31_536_000>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
enum ExpectedState {
    Completed,
    Refused,
    Retryable,
    Uncertain,
    DeadlineExceeded,
}

impl ExpectedState {
    fn name(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Refused => "refused",
            Self::Retryable => "retryable",
            Self::Uncertain => "uncertain",
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
    Named { value: LocalId },
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
    pub expect: Expectation,
}

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
    Uncertain {
        uncertain: String,
    },
    ReceiptExpired {
        #[serde(rename = "receiptExpired")]
        receipt_expired: bool,
    },
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
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| error("coordinator.scenario.read"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(error("coordinator.scenario.bound"));
    }
    let mut source = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| error("coordinator.scenario.read"))?
        .take(MAX_SCENARIO_BYTES + 1)
        .read_to_end(&mut source)
        .map_err(|_| error("coordinator.scenario.read"))?;
    decode_bytes(&source, &path.display().to_string())
}

/// Decode authored scenarios through the shared reader, keeping positioned findings.
pub fn decode(source: &str, file: &str) -> Result<ScenarioDocument> {
    decode_bytes(source.as_bytes(), file)
}

pub(crate) fn decode_bytes(source: &[u8], file: &str) -> Result<ScenarioDocument> {
    let mut hook = AuthoredExpressions;
    let decoded = Reader::new(file)
        .with_hook(&mut hook)
        .decode::<CoordinatorScenarios>(source, &Expect::one(&FORMAT))
        .map_err(CoordinatorError::from_report)?;
    decoded.value.into_document(&decoded.document)
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
pub fn scenario_schema() -> std::result::Result<String, serde_json::Error> {
    let mut schema = serde_json::to_value(schemars::schema_for!(CoordinatorScenarios))?;
    crate::schema::finish(&mut schema, API_VERSION, KIND, SCHEMA_ID);
    Ok(format!("{}\n", serde_json::to_string_pretty(&schema)?))
}

/// This runner never resolves runtime configuration or opens network/database I/O.
/// Responses, outages and recovery are synthetic scenario replies, not Dispatch
/// or downstream product proofs. Time advances to authored wait instants,
/// bounded by the workflow deadline.
pub fn run(definition: &Definition, scenario: &Scenario) -> Result<ScenarioReport> {
    definition.validate_input(&scenario.input)?;
    for step in scenario.replies.keys() {
        if !matches!(definition.workflow.steps.get(step), Some(Step::Call { .. })) {
            return Err(error("coordinator.scenario.reply-step"));
        }
    }
    for (step, recovery) in &scenario.recovery {
        let Some(Step::Call { call, .. }) = definition.workflow.steps.get(step) else {
            return Err(error("coordinator.scenario.recovery"));
        };
        if matches!(recovery, Recovery::Reconcile) && !call.operation.supports_read_receipt() {
            return Err(error("coordinator.scenario.recovery"));
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
        match definition
            .workflow
            .steps
            .get(&step)
            .ok_or_else(|| error("coordinator.scenario.step"))?
        {
            Step::WaitUntil { next, .. } => {
                now = now
                    .max(parse_timestamp(&definition.evaluate(
                        &step,
                        &scenario.input,
                        &outputs,
                    )?)?)
                    .min(deadline);
                step = next.clone();
            }
            Step::Choose { cases, .. } => {
                let choice = definition.evaluate(&step, &scenario.input, &outputs)?;
                step = cases
                    .get(
                        choice
                            .as_str()
                            .ok_or_else(|| error("coordinator.scenario.branch"))?,
                    )
                    .ok_or_else(|| error("coordinator.scenario.branch"))?
                    .clone();
            }
            Step::Finish { finish, output } => {
                let result = match output {
                    Some(_) => definition.evaluate(&step, &scenario.input, &outputs)?,
                    None => Value::Null,
                };
                definition.validate_outcome(finish, &result)?;
                report.state = "completed".into();
                report.outcome = Some(finish.clone());
                report.output = Some(result);
                break;
            }
            Step::Call { call, next, .. } => {
                let value = definition.evaluate(&step, &scenario.input, &outputs)?;
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
                // Keep this value for every recovery reply: mapping evaluation and
                // authority selection never run again for a prepared mutation.
                let frozen = serde_json::to_vec(&command)
                    .map_err(|_| error("coordinator.scenario.command"))?;
                if command.operation.has_dispatch_risk() {
                    report.frozen_commands += 1;
                }
                let replies = scenario
                    .replies
                    .get(&step)
                    .ok_or_else(|| error("coordinator.scenario.reply"))?;
                let recovery = scenario.recovery.get(&step);
                let mut prior_unknown = false;
                let mut success = None;
                for (index, reply) in replies.iter().enumerate() {
                    if command.operation.is_evaluation()
                        && matches!(reply, Reply::ReceiptExpired { .. })
                    {
                        return Err(error("coordinator.scenario.reply"));
                    }
                    if index > 0 && recovery.is_none() {
                        return Err(error("coordinator.scenario.recovery"));
                    }
                    if index > 0 && prior_unknown && !command.operation.can_retry_after_unknown() {
                        return Err(error("coordinator.scenario.recovery"));
                    }
                    // Receipt observation can resolve an unknown mutation,
                    // never create success after a definite retryable rejection.
                    if index > 0
                        && matches!(recovery, Some(Recovery::Reconcile))
                        && (!command.operation.supports_read_receipt() || !prior_unknown)
                    {
                        return Err(error("coordinator.scenario.recovery"));
                    }
                    let same: CallRequest = serde_json::from_slice(&frozen)
                        .map_err(|_| error("coordinator.scenario.command"))?;
                    if same.operation != command.operation
                        || same.input != command.input
                        || same.idempotency_key != command.idempotency_key
                    {
                        return Err(error("coordinator.scenario.command"));
                    }
                    *report.call_attempts.entry(step.clone()).or_default() += 1;
                    match reply {
                        Reply::Success { success: value } => {
                            success = Some(value.clone());
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
                                return Err(error("coordinator.scenario.receipt-expired"));
                            }
                            break;
                        }
                        Reply::ReceiptExpired {
                            receipt_expired: false,
                        } => return Err(error("coordinator.scenario.reply")),
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
                if let Some(value) = success {
                    outputs.insert(step.clone(), value);
                    report.state = "running".into();
                    step = next.clone();
                } else {
                    break;
                }
            }
        }
    }
    report.elapsed_seconds = (now - scenario.admitted_at).num_seconds();
    if report.state == "running" {
        return Err(error("coordinator.scenario.bound"));
    }
    if report.path != scenario.expect.path
        || report.state != scenario.expect.state
        || (!scenario.expect.skip_outcome_check && report.outcome != scenario.expect.outcome)
        || scenario
            .expect
            .output
            .as_ref()
            .is_some_and(|expected| report.output.as_ref() != Some(expected))
        || scenario
            .expect
            .elapsed_seconds
            .is_some_and(|expected| report.elapsed_seconds != expected)
    {
        return Err(error("coordinator.scenario.expectation"));
    }
    Ok(report)
}

pub fn check(definition: &Definition, document: &ScenarioDocument) -> Result<Vec<ScenarioReport>> {
    document
        .cases
        .iter()
        .map(|scenario| run(definition, scenario))
        .collect()
}

fn error(code: &'static str) -> CoordinatorError {
    CoordinatorError::new(code,"the offline scenario or expected synthetic result was refused")
        .at("scenarios.yaml","cases")
        .suggest("Correct the named scenario input, bounded replies and expected graph path; no live effects were attempted.")
}
