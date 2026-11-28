// SPDX-License-Identifier: Apache-2.0
//! Bounded, explicitly initiated examples against this project's owned dev instance.
use crate::local_files as private;
use registry_rstack_dev::BregRun;

const MAX_BYTES: u64 = 1024 * 1024;
mod proposals;
use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use registry_breg::literal_text::{LiteralText, WRITE_THE_VALUE};
use registry_breg_client::*;
use registry_platform_yaml::{
    display_text, escape_pointer_segment, local_id_collision_diagnostics, ApiVersion, AuthoredId,
    Diagnostic, Document, EnvelopeRule, Expect, FormatSpec, Identified, LocalId, Reader,
    RemovedKey, Report, Severity, UniqueIdList,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Debug, Args)]
pub struct ExamplesArgs {
    #[command(subcommand)]
    action: ExamplesAction,
}
#[derive(Debug, Subcommand)]
enum ExamplesAction {
    /// Describe authored local scenarios without starting services or creating credentials.
    List {
        /// Authored project containing examples/scenarios.json.
        #[arg(default_value = ".")]
        project: PathBuf,
        /// Ready run whose retained example attempts to list.
        #[arg(long)]
        run_id: Option<String>,
    },
    /// Run or resume an example against the project's ready owned development instance.
    Run(RunArgs),
}
#[derive(Debug, Args)]
struct RunArgs {
    /// Bounded scenario identifier declared in this project's examples catalogue.
    scenario: String,
    /// Authored project whose owned local development instance is ready.
    #[arg(default_value = ".")]
    project: PathBuf,
    /// Ready run serving the exact project.
    #[arg(long)]
    run_id: String,
    /// Editable JSON input (default: the scenario's declared examples input file).
    #[arg(long)]
    input: Option<PathBuf>,
    /// Resume exactly this retained execution attempt.
    #[arg(long, conflicts_with = "new_attempt")]
    attempt: Option<uuid::Uuid>,
    /// Start a distinct attempt, with new idempotency keys and ordinary uniqueness checks.
    #[arg(long)]
    new_attempt: bool,
    /// Completed population attempt whose typed captures this scenario uses.
    #[arg(long)]
    from_attempt: Option<uuid::Uuid>,
}
pub(super) const API_VERSION: &str = "id.registrystack.org/formats/breg/example-scenarios/v1alpha1";
pub(super) const KIND: &str = "BRegExampleScenarios";
const CATALOGUE_FILE: &str = "examples/scenarios.json";

/// The example scenarios catalogue `bregctl examples` reads from a project's
/// `examples/scenarios.json`.
pub(crate) const EXAMPLE_SCENARIOS_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[
        RemovedKey {
            pointer: "/version",
            replacement: "Delete `version`; the apiVersion header names the format version.",
        },
        RemovedKey {
            pointer: "/scenarios/*/steps/*/entity",
            replacement: "Rename `entity` to `recordType`, keeping the same Record type reference.",
        },
    ],
};

/// An example scenarios catalogue the shared reader or the catalogue checks
/// refused. `bregctl examples` prints its diagnostics unchanged (CFG-DIAG-1,
/// CFG-DIAG-2).
#[derive(Debug)]
pub(crate) struct CatalogueRefused(pub Report);

impl std::fmt::Display for CatalogueRefused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0.render_human())
    }
}

impl std::error::Error for CatalogueRefused {}

/// Members that name something by a local identifier are decoded through
/// the reader's `LocalId`, so a refusal carries its code and position
/// (CFG-ID-1).
fn local_id<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    LocalId::deserialize(deserializer).map(LocalId::into_string)
}

fn optional_local_id<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    local_id(deserializer).map(Some)
}

fn local_id_map<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    let map = BTreeMap::<LocalId, LocalId>::deserialize(deserializer)?;
    Ok(map
        .into_iter()
        .map(|(key, value)| (key.into_string(), value.into_string()))
        .collect())
}

fn optional_local_id_map<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<BTreeMap<String, String>>, D::Error> {
    local_id_map(deserializer).map(Some)
}

#[cfg(feature = "schema")]
fn local_id_map_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let names = generator.subschema_for::<LocalId>();
    schemars::json_schema!({
        "type": "object",
        "minProperties": 1,
        "maxProperties": 100,
        "propertyNames": names.clone(),
        "additionalProperties": names,
    })
}

#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Catalogue {
    scenarios: UniqueIdList<Scenario>,
}

/// The JSON Schema of the catalogue members the reader decodes. The header is
/// checked and removed before decoding, so the publisher adds it.
#[cfg(feature = "schema")]
pub(crate) fn catalogue_schema() -> schemars::Schema {
    schemars::schema_for!(Catalogue)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Scenario {
    #[serde(deserialize_with = "local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "LocalId"))]
    id: String,
    #[serde(deserialize_with = "display_text")]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "scenario_description_schema")
    )]
    description: String,
    input: String,
    steps: UniqueIdList<Step>,
}

#[cfg(feature = "schema")]
fn scenario_description_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let display_text = generator.subschema_for::<registry_platform_yaml::DisplayText>();
    schemars::json_schema!({
        "allOf": [
            display_text,
            {"type": "string", "minLength": 1, "maxLength": 1024}
        ]
    })
}

impl Identified for Scenario {
    fn id(&self) -> &str {
        &self.id
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(transform = step_capture_schema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Step {
    #[serde(deserialize_with = "local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "LocalId"))]
    id: String,
    operation: Operation,
    #[serde(
        default,
        rename = "recordType",
        deserialize_with = "optional_local_id",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<LocalId>"))]
    entity: Option<String>,
    #[serde(deserialize_with = "local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "LocalId"))]
    client: String,
    #[serde(deserialize_with = "local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "LocalId"))]
    access_profile: String,
    #[serde(default, deserialize_with = "optional_local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "Option<LocalId>"))]
    input: Option<String>,
    /// Local capture alias for this step's result. For create and invoke steps,
    /// Record capture aliases must be unique throughout the scenario, including
    /// aliases in captureResults; the reader checks this semantic rule.
    #[serde(default, deserialize_with = "optional_local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "Option<LocalId>"))]
    capture: Option<String>,
    #[serde(default, deserialize_with = "optional_local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "Option<LocalId>"))]
    record: Option<String>,
    #[serde(
        default,
        deserialize_with = "optional_local_id",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<LocalId>"))]
    action: Option<String>,
    #[serde(
        default,
        deserialize_with = "optional_local_id",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<LocalId>"))]
    result: Option<String>,
    /// Maps disclosed Action result aliases to distinct local capture aliases.
    /// Record capture aliases must be unique throughout the scenario, including
    /// earlier Record captures; the reader checks this semantic rule.
    #[serde(
        default,
        deserialize_with = "optional_local_id_map",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(schema_with = "local_id_map_schema"))]
    capture_results: Option<BTreeMap<String, String>>,
    #[serde(
        default,
        deserialize_with = "optional_local_id",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<LocalId>"))]
    proposal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expect: Option<ProposalExpectation>,
}

/// A flat reader keeps source positions; these conditions mirror the record
/// and result-capture variants checked by `catalogue_problems`.
#[cfg(feature = "schema")]
fn step_capture_schema(schema: &mut schemars::Schema) {
    schema.insert(
        "allOf".to_owned(),
        json!([
            {
                "if": {"properties": {"operation": {
                    "enum": [Operation::Create, Operation::Get, Operation::History]
                }}},
                "then": {"required": ["recordType"]}
            },
            {
                "if": {"properties": {"operation": {"const": Operation::Invoke}}},
                "then": {
                    "required": ["action", "input"],
                    "oneOf": [
                        {
                            "required": ["recordType", "result", "capture"],
                            "not": {"required": ["captureResults"]}
                        },
                        {
                            "required": ["captureResults"],
                            "not": {"anyOf": [
                                {"required": ["recordType"]},
                                {"required": ["result"]},
                                {"required": ["capture"]}
                            ]}
                        }
                    ]
                },
                "else": {"not": {"required": ["captureResults"]}}
            }
        ]),
    );
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProposalExpectation {
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    status: Option<registry_platform_yaml::BoundedU32<400, 599>>,
    #[serde(default)]
    problem_code: Option<String>,
}
impl Identified for Step {
    fn id(&self) -> &str {
        &self.id
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
enum Operation {
    Create,
    Invoke,
    Get,
    History,
    Start,
    Inspect,
    Submit,
    Apply,
    Edit,
    Revise,
    Rebase,
    Retry,
    Cancel,
}
impl Operation {
    fn is_proposal(self) -> bool {
        !matches!(
            self,
            Self::Create | Self::Invoke | Self::Get | Self::History
        )
    }
    fn transition(self) -> &'static str {
        match self {
            Self::Submit => "submit",
            Self::Apply => "apply",
            Self::Edit => "edit",
            Self::Revise => "revise",
            Self::Rebase => "rebase",
            Self::Retry => "retry",
            Self::Cancel => "cancel",
            _ => "get",
        }
    }
    fn metadata_kind(self) -> BRegOperationKind {
        match self {
            Self::Create => BRegOperationKind::Create,
            Self::Invoke => BRegOperationKind::Invoke,
            Self::Get => BRegOperationKind::Get,
            Self::History => BRegOperationKind::Revisions,
            _ => BRegOperationKind::Get,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Binding {
    source: String,
    package: String,
    database: String,
    clients: String,
    scenario: String,
    input: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Capture {
    #[serde(rename = "recordType")]
    entity: String,
    id: uuid::Uuid,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Attempt {
    version: u8,
    id: uuid::Uuid,
    scenario: String,
    binding: Binding,
    from_attempt: Option<uuid::Uuid>,
    captures: BTreeMap<String, Capture>,
    #[serde(default)]
    proposals: BTreeMap<String, ProposalCapture>,
    completed: BTreeMap<String, Value>,
    pending: Option<Pending>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProposalCapture {
    action: String,
    id: uuid::Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    submission_version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    effect_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    action_revision: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Pending {
    step: String,
    capsule: Value,
}
impl Attempt {
    fn save(&self, directory: &Path) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self)?;
        if bytes.len() as u64 > MAX_BYTES {
            bail!(
                "example attempt exceeds its retained-state size bound; no further mutation was sent"
            );
        }
        private::replace(&directory.join(format!("{}.json", self.id)), &bytes)
    }
}

fn read_source(path: &Path) -> Result<Vec<u8>> {
    crate::read_bounded_source_file(path, "examples.input", "examples", 1024 * 1024)
        .map_err(|_| anyhow::anyhow!("examples require bounded ordinary files (maximum 1 MiB)"))
}
fn catalogue(project: &Path) -> Result<(Catalogue, Vec<u8>)> {
    let path = project.join(CATALOGUE_FILE);
    if !path
        .try_exists()
        .context("cannot inspect the example catalogue")?
    {
        bail!("examples/scenarios.json is absent; create a complete example project with bregctl init, or add an examples/scenarios.json catalogue before running bregctl examples list");
    }
    let bytes = read_source(&path)?;
    let decoded = Reader::new(path.display().to_string())
        .with_hook(&mut LiteralText {
            remedy: WRITE_THE_VALUE,
        })
        .decode::<Catalogue>(&bytes, &Expect::one(&EXAMPLE_SCENARIOS_FORMAT))
        .map_err(CatalogueRefused)?;
    let problems = catalogue_problems(&decoded.value, &decoded.document);
    if !problems.is_empty() {
        return Err(CatalogueRefused(decoded.document.report_with(problems)).into());
    }
    Ok((decoded.value, bytes))
}

/// Check an example scenarios document `bregctl check --file` read: the
/// checks `bregctl examples` applies before it runs a scenario.
pub(crate) fn check(document: &Document) -> std::result::Result<Vec<Diagnostic>, Report> {
    let catalogue = document.decode::<Catalogue>()?;
    Ok(catalogue_problems(&catalogue, document))
}

/// The checks the reader's types cannot express, each reported at the
/// member it concerns (CFG-DIAG-1). Messages name members, never values.
fn catalogue_problems(catalogue: &Catalogue, document: &Document) -> Vec<Diagnostic> {
    let scenario_pointers = catalogue
        .scenarios
        .iter()
        .enumerate()
        .map(|(index, scenario)| (scenario.id.as_str(), format!("/scenarios/{index}/id")))
        .collect::<Vec<_>>();
    let scenario_ids = scenario_pointers
        .iter()
        .map(|(id, pointer)| AuthoredId::at_value(id, pointer))
        .collect::<Vec<_>>();
    let mut problems = local_id_collision_diagnostics(
        document,
        "breg.examples.scenario-id-collision",
        &scenario_ids,
    );
    for (index, scenario) in catalogue.scenarios.iter().enumerate() {
        let step_pointers = scenario
            .steps
            .iter()
            .enumerate()
            .map(|(step_index, step)| {
                (
                    step.id.as_str(),
                    format!("/scenarios/{index}/steps/{step_index}/id"),
                )
            })
            .collect::<Vec<_>>();
        let step_ids = step_pointers
            .iter()
            .map(|(id, pointer)| AuthoredId::at_value(id, pointer))
            .collect::<Vec<_>>();
        problems.extend(local_id_collision_diagnostics(
            document,
            "breg.examples.step-id-collision",
            &step_ids,
        ));
        let mut capture_pointers = Vec::new();
        for (step_index, step) in scenario.steps.iter().enumerate() {
            let step_pointer = format!("/scenarios/{index}/steps/{step_index}");
            if matches!(
                step.operation,
                Operation::Create | Operation::Start | Operation::Invoke
            ) && step.capture_results.is_none()
            {
                if let Some(alias) = &step.capture {
                    capture_pointers.push((alias.as_str(), format!("{step_pointer}/capture")));
                }
            }
            if step.operation == Operation::Invoke {
                for (result, alias) in step.capture_results.iter().flatten() {
                    capture_pointers.push((
                        alias.as_str(),
                        format!(
                            "{step_pointer}/captureResults/{}",
                            escape_pointer_segment(result)
                        ),
                    ));
                }
            }
        }
        let capture_ids = capture_pointers
            .iter()
            .map(|(id, pointer)| AuthoredId::at_value(id, pointer))
            .collect::<Vec<_>>();
        problems.extend(local_id_collision_diagnostics(
            document,
            "breg.examples.capture-id-collision",
            &capture_ids,
        ));
    }
    let mut refuse = |pointer: &str, code: &str, message: &str, action: &str| {
        problems.push(document.diagnostic_at_value(
            Severity::Error,
            code,
            pointer,
            message,
            action,
        ));
    };
    if catalogue.scenarios.is_empty() || catalogue.scenarios.len() > 32 {
        refuse(
            "/scenarios",
            "breg.examples.scenario-count",
            "the catalogue must declare 1 to 32 scenarios",
            "Declare between 1 and 32 scenarios.",
        );
    }
    for (index, scenario) in catalogue.scenarios.iter().enumerate() {
        let at = format!("/scenarios/{index}");
        if scenario.description.is_empty() || scenario.description.len() > 1024 {
            refuse(
                &format!("{at}/description"),
                "breg.examples.description-length",
                "a scenario description must be 1 to 1024 bytes",
                "Write a description of 1 to 1024 bytes.",
            );
        }
        let input = Path::new(&scenario.input);
        if !scenario.input.starts_with("examples/")
            || input
                .components()
                .any(|p| !matches!(p, std::path::Component::Normal(_)))
        {
            refuse(
                &format!("{at}/input"),
                "breg.examples.input-path",
                "a scenario input must be a relative file under examples/",
                "Name a file under examples/, such as examples/inputs/starter-data.json, without `.` or `..` segments.",
            );
        }
        if scenario.steps.is_empty() || scenario.steps.len() > 100 {
            refuse(
                &format!("{at}/steps"),
                "breg.examples.step-count",
                "a scenario must declare 1 to 100 steps",
                "Declare between 1 and 100 steps.",
            );
        }
        let mut record_capture_aliases = BTreeSet::new();
        for (position, step) in scenario.steps.iter().enumerate() {
            let at = format!("{at}/steps/{position}");
            if step.operation.is_proposal() {
                proposals::validate_step(step, &at, &mut refuse);
                continue;
            }
            if step.proposal.is_some() || step.expect.is_some() {
                refuse(
                    &at,
                    "breg.examples.step-members",
                    "only Proposal steps may declare `proposal` or `expect`",
                    "Delete the Proposal-only members.",
                );
            }
            if step.operation == Operation::Invoke {
                // Both name something the registry project declares, a governed
                // action and one of its result effects, so both are held to the
                // project's identifier grammar when they are decoded.
                let singular =
                    step.result.is_some() || step.capture.is_some() || step.entity.is_some();
                let several = step.capture_results.is_some();
                if step.action.is_none()
                    || singular == several
                    || (singular
                        && (step.result.is_none()
                            || step.capture.is_none()
                            || step.entity.is_none()))
                {
                    refuse(
                        &at,
                        "breg.examples.step-members",
                        "an invoke step must declare `action` and either one `recordType`, `result`, and `capture`, or a non-empty `captureResults` mapping",
                        "Select one disclosed result with `recordType`, `result`, and `capture`, or map disclosed result aliases to capture aliases with `captureResults`.",
                    );
                }
                let mut aliases = BTreeSet::new();
                if step
                    .capture_results
                    .as_ref()
                    .is_some_and(|captures| captures.values().any(|alias| !aliases.insert(alias)))
                {
                    refuse(
                        &format!("{at}/captureResults"),
                        "breg.examples.capture-results",
                        "captureResults must assign each result a distinct capture alias",
                        "Use a distinct capture alias for each result.",
                    );
                }
                if step
                    .capture_results
                    .as_ref()
                    .is_some_and(|captures| captures.is_empty() || captures.len() > 100)
                {
                    refuse(
                        &format!("{at}/captureResults"),
                        "breg.examples.capture-results",
                        "captureResults must declare 1 to 100 result captures",
                        "Declare between 1 and 100 result-to-capture entries.",
                    );
                }
                for alias in step
                    .capture_results
                    .iter()
                    .flat_map(|captures| captures.values())
                {
                    if !record_capture_aliases.insert(alias) {
                        refuse(
                            &format!("{at}/captureResults"),
                            "breg.examples.capture-results",
                            "record capture aliases must be unique within a scenario",
                            "Use a capture alias that no earlier step declares.",
                        );
                    }
                }
                if step.capture_results.is_none() {
                    if let Some(alias) = &step.capture {
                        if !record_capture_aliases.insert(alias) {
                            refuse(
                                &format!("{at}/capture"),
                                "breg.examples.capture-results",
                                "record capture aliases must be unique within a scenario",
                                "Use a capture alias that no earlier step declares.",
                            );
                        }
                    }
                }
            } else if step.action.is_some()
                || step.result.is_some()
                || step.capture_results.is_some()
            {
                refuse(
                    &at,
                    "breg.examples.step-members",
                    "only an invoke step may declare `action`, `result`, or `captureResults`",
                    "Delete `action`, `result`, and `captureResults`, or set `operation` to invoke.",
                );
            }
            if step.operation == Operation::Create {
                if step.entity.is_none()
                    || step.input.is_none()
                    || step.capture.is_none()
                    || step.record.is_some()
                {
                    refuse(
                        &at,
                        "breg.examples.step-members",
                        "a create or invoke step must declare `input` and `capture`, and no `record`",
                        "Name the payload with `input`, the returned record with `capture`, and delete `record`.",
                    );
                }
                if let Some(alias) = &step.capture {
                    if !record_capture_aliases.insert(alias) {
                        refuse(
                            &format!("{at}/capture"),
                            "breg.examples.capture-results",
                            "record capture aliases must be unique within a scenario",
                            "Use a capture alias that no earlier step declares.",
                        );
                    }
                }
            } else if step.operation == Operation::Invoke {
                if step.input.is_none() || step.record.is_some() {
                    refuse(
                        &at,
                        "breg.examples.step-members",
                        "an invoke step must declare `input` and no `record`",
                        "Name the payload with `input` and delete `record`.",
                    );
                }
            } else if step.entity.is_none()
                || step.record.is_none()
                || step.input.is_some()
                || step.capture.is_some()
            {
                refuse(
                    &at,
                    "breg.examples.step-members",
                    "a read or lifecycle step must declare `record`, and no `input` or `capture`",
                    "Name the captured record with `record`, and delete `input` and `capture`.",
                );
            }
            if record_capture_aliases.len() > 100 {
                refuse(
                    &format!("{at}/captureResults"),
                    "breg.examples.capture-results",
                    "a scenario may declare at most 100 record captures",
                    "Keep at most 100 record capture aliases in one scenario.",
                );
            }
            if !matches!(
                step.operation,
                Operation::Create | Operation::Get | Operation::Invoke | Operation::History
            ) {
                refuse(
                    &format!("{at}/operation"),
                    "breg.examples.population-operation",
                    "a record scenario may create, invoke, get, or read history",
                    "Use the generated Proposal client for durable Action lifecycle journeys.",
                );
            }
        }
        if scenario.id == "first-record"
            && (scenario.steps.len() != 2
                || scenario.steps[0].operation != Operation::Create
                || scenario.steps[1].operation != Operation::Get)
        {
            refuse(
                &format!("{at}/steps"),
                "breg.examples.fixed-scenario",
                "first-record must create one record and then get it",
                "Declare exactly two steps: a create step, then a get step that reads its capture.",
            );
        }
    }
    problems
}

/// Captures carry their declared entity; metadata validates each reference field.
fn resolve(value: &Value, captures: &BTreeMap<String, Capture>, _depth: usize) -> Result<Value> {
    Ok(
        registry_breg::example_references::resolve_record_references(value, |alias| {
            captures.get(alias).map(|capture| capture.id.to_string())
        })?,
    )
}

fn validate_reference_fields(
    step: &Step,
    metadata: &BRegMetadata,
    input: &Value,
    captures: &BTreeMap<String, Capture>,
) -> Result<()> {
    let operation = metadata
        .operations()
        .iter()
        .find(|o| {
            Some(o.source_record_type()) == step.entity.as_deref()
                && o.access_profile() == step.access_profile
                && *o.kind() == BRegOperationKind::Create
        })
        .context("create operation missing")?;
    let data = input
        .get(step.input.as_deref().context("input key missing")?)
        .and_then(Value::as_object)
        .context("create payload must be an object")?;
    for (name, value) in data {
        if let Some(alias) = registry_breg::example_references::record_reference(value)? {
            let field = operation
                .fields()
                .iter()
                .find(|f| f.api_name() == name)
                .context("reference field is not advertised")?;
            let target = field
                .reference_target_record_type()
                .context("logical reference requires an advertised reference target entity")?;
            if captures.get(alias).is_none_or(|c| c.entity != target) {
                bail!("reference alias is missing or belongs to the wrong target entity");
            }
        } else {
            // Only direct reference fields advertise a target entity. Keep
            // ordinary structured values inert rather than resolving untyped
            // nested aliases through the shared fixture grammar.
            registry_breg::example_references::resolve_record_references(value, |_| None)
                .context("nested logical references require a direct advertised reference field")?;
        }
    }
    Ok(())
}

fn record<'a>(step: &Step, captures: &'a BTreeMap<String, Capture>) -> Result<&'a Capture> {
    let capture = captures
        .get(
            step.record
                .as_deref()
                .context("step lacks a record alias")?,
        )
        .context("record alias is missing; run its prerequisite first")?;
    if Some(capture.entity.as_str()) != step.entity.as_deref() {
        bail!("record alias belongs to another entity");
    }
    Ok(capture)
}
fn payload(
    step: &Step,
    input: &Value,
    captures: &BTreeMap<String, Capture>,
) -> Result<BRegCreateRequest> {
    let key = step
        .input
        .as_deref()
        .context("create input key is missing")?;
    let value = resolve(
        input
            .get(key)
            .context("input file is missing a declared payload key")?,
        captures,
        0,
    )?;
    Ok(BRegCreateRequest::new(
        value
            .as_object()
            .context("create payload must be a JSON object")?
            .clone(),
    )?)
}

fn action_inputs(
    step: &Step,
    action: &BRegActionBinding,
    input: &Value,
    captures: &BTreeMap<String, Capture>,
) -> Result<serde_json::Map<String, Value>> {
    let data = input
        .get(step.input.as_deref().context("action input key missing")?)
        .and_then(Value::as_object)
        .context("action payload must be an object")?;
    for (name, value) in data {
        if let Some(alias) = registry_breg::example_references::record_reference(value)? {
            let reference = action
                .reference_inputs()
                .iter()
                .find(|field| field.api_name() == name)
                .context("logical action reference requires an advertised reference input")?;
            if captures
                .get(alias)
                .is_none_or(|capture| capture.entity != reference.target_record_type())
            {
                bail!("action reference alias is missing or belongs to another entity");
            }
        } else {
            registry_breg::example_references::resolve_record_references(value, |_| None)
                .context("nested logical action references are not advertised inputs")?;
        }
    }
    let resolved = resolve(&Value::Object(data.clone()), captures, 0)?;
    let inputs = resolved
        .as_object()
        .context("action input must be an object")?
        .clone();
    BRegActionInvocationRequest::validate_inputs(action, &inputs)?;
    Ok(inputs)
}

fn action_binding(contract: &BRegMetadata, step: &Step) -> Result<BRegActionBinding> {
    let action = contract.select_action(
        step.action
            .as_deref()
            .context("action identifier missing")?,
        &step.access_profile,
    )?;
    if step.capture_results.is_none() {
        if action
            .result_effects()
            .get(step.result.as_deref().context("action result missing")?)
            != step.entity.as_ref()
        {
            bail!("action capture must select one advertised result of the declared entity");
        }
    } else if step
        .capture_results
        .iter()
        .flat_map(|captures| captures.keys())
        .any(|effect| !action.result_effects().contains_key(effect))
    {
        bail!("action captures must select advertised results disclosed to this profile");
    }
    Ok(action)
}

fn declared_action_capture_entities(
    action: &BRegActionBinding,
    step: &Step,
) -> Result<BTreeMap<String, (String, String)>> {
    let declarations: Vec<(&String, &String)> = if step.capture_results.is_none() {
        vec![(
            step.result.as_ref().context("action result missing")?,
            step.capture.as_ref().context("action capture missing")?,
        )]
    } else {
        step.capture_results
            .as_ref()
            .context("action capture results missing")?
            .iter()
            .collect()
    };
    declarations
        .into_iter()
        .map(|(effect, alias)| {
            let entity = action
                .result_effects()
                .get(effect)
                .context("action capture selects an undisclosed result")?;
            Ok((alias.clone(), (effect.clone(), entity.clone())))
        })
        .collect()
}

fn extract_invocation_captures(
    declarations: BTreeMap<String, (String, String)>,
    results: &BTreeMap<String, (String, uuid::Uuid)>,
) -> std::result::Result<BTreeMap<String, Capture>, &'static str> {
    declarations
        .into_iter()
        .map(|(alias, (effect, entity))| match results.get(&effect) {
            Some((actual_entity, id)) if actual_entity == &entity => {
                Ok((alias, Capture { entity, id: *id }))
            }
            Some(_) => Err("action receipt capture entity differs from its authored declaration"),
            None => Err("successful action did not disclose every configured capture result"),
        })
        .collect()
}
fn attempts(directory: &Path) -> Result<Vec<Attempt>> {
    let mut result = Vec::new();
    for entry in fs::read_dir(directory)? {
        if result.len() >= 1000 {
            bail!("retained example attempt limit reached (1000)");
        }
        let entry = entry?;
        if entry.path().extension().is_none_or(|v| v != "json") {
            continue;
        }
        let attempt: Attempt = serde_json::from_slice(&private::read(&entry.path(), MAX_BYTES)?)
            .context("retained example attempt is malformed")?;
        if attempt.version != 1
            || attempt.id.is_nil()
            || attempt.from_attempt.is_some_and(|id| id.is_nil())
            || !crate::dev_clients::identifier(&attempt.scenario)
            || entry.file_name().to_str() != Some(&format!("{}.json", attempt.id))
            || attempt.captures.len() > 100
            || attempt.proposals.len() > 100
            || attempt.completed.len() > 100
        {
            bail!("retained example attempt is incompatible or malformed");
        }
        if attempt.captures.iter().any(|(k, v)| {
            !crate::dev_clients::identifier(k)
                || !crate::dev_clients::identifier(&v.entity)
                || v.id.is_nil()
        }) {
            bail!("retained example capture is malformed");
        }
        if attempt.proposals.iter().any(|(alias, capture)| {
            !crate::dev_clients::identifier(alias)
                || !crate::dev_clients::identifier(&capture.action)
                || capture.id.is_nil()
        }) {
            bail!("retained Proposal capture is malformed");
        }
        result.push(attempt);
    }
    Ok(result)
}

/// Import identifiers, never credentials or authority, from a completed
/// population in the same source and database generation.
fn inherit_captures(attempt: &mut Attempt, parent: &Attempt, catalogue: &Catalogue) -> Result<()> {
    let scenario = catalogue
        .scenarios
        .iter()
        .find(|s| s.id == parent.scenario)
        .context("source attempt scenario is no longer declared")?;
    if parent.id == attempt.id
        || parent.pending.is_some()
        || parent.binding.source != attempt.binding.source
        || parent.binding.package != attempt.binding.package
        || parent.binding.database != attempt.binding.database
        || parent.binding.clients != attempt.binding.clients
        || parent.binding.scenario != attempt.binding.scenario
        || parent.completed.len() != scenario.steps.len()
        || scenario
            .steps
            .iter()
            .any(|step| !parent.completed.contains_key(&step.id))
        || scenario
            .steps
            .iter()
            .filter(|step| step.operation == Operation::Invoke)
            .any(|step| require_retained_invocation_capture(parent, step).is_err())
    {
        bail!(
            "--from-attempt requires a completed population with the same source, package, clients, catalogue and database generation"
        );
    }
    attempt.from_attempt = Some(parent.id);
    attempt.captures = parent.captures.clone();
    attempt.proposals = parent.proposals.clone();
    Ok(())
}

pub fn run(args: ExamplesArgs) -> Result<Value> {
    match args.action {
        ExamplesAction::List { project, run_id } => {
            let project = project.canonicalize()?;
            let (catalogue, _) = catalogue(&project)?;
            let retained = if let Some(run_id) = run_id {
                let run = BregRun::open(&run_id, &project)?;
                let directory = run.state.join("examples");
                let _lock = private::lock(&run.state.join("examples.lock"))?;
                if directory.exists() {
                    private::check(&directory, true)?;
                    attempts(&directory)?.iter().map(|a|json!({"attempt":a.id,"scenario":a.scenario,"completedSteps":a.completed.keys().collect::<Vec<_>>(),"pendingStep":a.pending.as_ref().map(|p|&p.step)})).collect::<Vec<_>>()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };
            Ok(
                json!({"ok":true,"command":"examples list","project":project,"scenarios":catalogue.scenarios,"attempts":retained}),
            )
        }
        ExamplesAction::Run(args) => run_example(args),
    }
}
fn run_example(args: RunArgs) -> Result<Value> {
    let run = BregRun::open(&args.run_id, &args.project)?;
    let project = &run.project;
    let _lock = private::lock(&run.state.join("examples.lock"))?;
    let package = registry_breg::package::load_package(
        &run.package,
        &registry_breg::package::PackageLoadContext {
            posture: registry_platform_config::Posture::Development,
        },
    )?;
    let compiled = crate::compile(project, crate::ProfileArg::Production, "examples")
        .map_err(|_| anyhow::anyhow!("The authored registry could not be compiled."))?;
    let revision = compiled.revision();
    if revision != package.registry().revision() {
        bail!("The authored registry differs from the active package. Start a run from the current project.");
    }
    let (catalogue, bytes) = catalogue(project)?;
    let scenario = catalogue
        .scenarios
        .iter()
        .find(|s| s.id == args.scenario)
        .context("scenario is not declared in this project")?;
    let input_path = args
        .input
        .clone()
        .unwrap_or_else(|| project.join(&scenario.input));
    let input_bytes = read_source(&input_path)?;
    let input: Value =
        serde_json::from_slice(&input_bytes).context("example input must be JSON")?;
    validate_scenario_input(scenario, &input)?;
    let directory = run.state.join("examples");
    private::directory(&directory)?;
    let retained = attempts(&directory)?;
    let binding = Binding {
        source: revision.to_owned(),
        package: package.package_digest().to_owned(),
        database: run.instance.clone(),
        clients: run.identities_digest()?,
        scenario: registry_platform_config::sha256_uri(&bytes),
        input: registry_platform_config::sha256_uri(&input_bytes),
    };
    let mut eligible: Vec<_> = retained
        .iter()
        .filter(|a| a.scenario == args.scenario && a.binding.database == binding.database)
        .collect();
    let existing = if let Some(id) = args.attempt {
        Some(
            retained
                .iter()
                .find(|a| a.id == id)
                .context("attempt does not exist in this project")?,
        )
    } else if args.new_attempt {
        None
    } else {
        if eligible.len() > 1 {
            bail!("multiple attempts exist; select --attempt ID or start --new-attempt");
        }
        eligible.pop()
    };
    let mut attempt = if let Some(existing) = existing {
        if existing.binding != binding || existing.scenario != scenario.id {
            bail!(
                "attempt source, input, client, scenario or database generation differs; unchanged input resumes, changed input requires --new-attempt"
            );
        }
        if args.from_attempt.is_some() && args.from_attempt != existing.from_attempt {
            bail!("attempt already binds another source attempt; use --new-attempt");
        }
        existing.clone()
    } else {
        if retained.len() >= 1000 {
            bail!("retained example attempt limit reached (1000); resume an existing --attempt");
        }
        let mut attempt = Attempt {
            version: 1,
            id: uuid::Uuid::new_v4(),
            scenario: scenario.id.clone(),
            binding,
            from_attempt: None,
            captures: BTreeMap::new(),
            proposals: BTreeMap::new(),
            completed: BTreeMap::new(),
            pending: None,
        };
        if let Some(id) = args.from_attempt {
            let parent = retained
                .iter()
                .find(|a| a.id == id)
                .context("source attempt does not exist in this project")?;
            inherit_captures(&mut attempt, parent, &catalogue)?;
        }
        attempt
    };
    let mut native = BTreeMap::new();
    let origin = run.origin.parse::<reqwest::Url>()?;
    for step in &scenario.steps {
        let key = (step.client.clone(), step.access_profile.clone());
        if let std::collections::btree_map::Entry::Vacant(entry) = native.entry(key) {
            let mut token = run.example_token(&step.client, &step.access_profile)?;
            let provider = StaticToken::new(std::mem::take(&mut *token))?;
            entry.insert(example_client(origin.clone(), provider)?);
        }
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(execute(
        &run,
        &native,
        scenario,
        &input,
        &directory,
        &mut attempt,
        &args,
    ));
    if let Err(error) = result {
        if directory.join(format!("{}.json", attempt.id)).exists()
            && error
                .downcast_ref::<proposals::SettledApplication>()
                .is_none()
        {
            let mut resume = format!(
                "bregctl examples run {} {} --run-id {} --attempt {}",
                scenario.id,
                shell_path(project),
                args.run_id,
                attempt.id
            );
            if args.input.is_some() {
                resume.push_str(&format!(" --input {}", shell_path(&input_path)));
            }
            return Err(error.context(format!("example {} attempt {} retained {} confirmed steps; resume the original operation with: {resume}",scenario.id,attempt.id,attempt.completed.len())));
        }
        return Err(error);
    }
    result
}

fn create_binding(metadata: &BRegMetadata, step: &Step) -> Result<BRegCreateBinding> {
    let operations: Vec<_> = metadata
        .operations()
        .iter()
        .filter(|o| {
            Some(o.source_record_type()) == step.entity.as_deref()
                && o.access_profile() == step.access_profile
                && *o.kind() == BRegOperationKind::Create
        })
        .collect();
    if operations.len() != 1 {
        bail!(
            "example create requires one advertised direct create operation for its entity and profile"
        );
    }
    match metadata.select_direct_write(operations[0].identifier(), &step.access_profile)? {
        BRegDirectWrite::Create(binding) => Ok(binding),
        _ => bail!("example operation does not advertise direct create"),
    }
}
fn route(metadata: &BRegMetadata, step: &Step) -> Result<String> {
    let operations: Vec<_> = metadata
        .operations()
        .iter()
        .filter(|o| {
            Some(o.source_record_type()) == step.entity.as_deref()
                && o.access_profile() == step.access_profile
                && *o.kind() == BRegOperationKind::Get
        })
        .collect();
    if operations.len() != 1 {
        bail!("example read requires one advertised record route for its entity and profile");
    }
    let path = operations[0].path();
    let route = path
        .strip_prefix("/v1/records/")
        .and_then(|p| p.strip_suffix("/{record_id}"))
        .context("record route is incompatible with the native client")?;
    Ok(route.into())
}
/// Record a step whose effects have committed.
///
/// Nothing that can refuse afterwards may leave the attempt holding this step
/// as pending: the run loop resumes a pending step by replaying its original
/// idempotency capsule, and a refusal that survives the replay would have no
/// way past it. A retained step is skipped instead.
fn retain(attempt: &mut Attempt, step: &Step, directory: &Path, retained: Value) -> Result<()> {
    attempt.completed.insert(step.id.clone(), retained);
    attempt.pending = None;
    attempt.save(directory)
}

/// Persist a committed invocation's receipt and any disclosed capture in one
/// replacement. A successful handler may omit an authored result, in which
/// case the completed receipt still clears the pending replay capsule.
fn retain_invocation(
    attempt: &mut Attempt,
    step: &Step,
    directory: &Path,
    retained: Value,
    captures: BTreeMap<String, Capture>,
) -> Result<()> {
    attempt.captures.extend(captures);
    retain(attempt, step, directory, retained)
}

fn require_retained_invocation_capture(attempt: &Attempt, step: &Step) -> Result<()> {
    let aliases = if step.capture_results.is_none() {
        vec![step.capture.as_ref().context("action capture missing")?]
    } else {
        step.capture_results
            .as_ref()
            .context("action capture results missing")?
            .values()
            .collect()
    };
    if aliases
        .iter()
        .all(|alias| attempt.captures.contains_key(alias.as_str()))
    {
        Ok(())
    } else {
        bail!("successful action did not disclose every configured capture result")
    }
}

fn example_client(base_url: reqwest::Url, token: StaticToken) -> Result<BaseRegistryClient> {
    Ok(BaseRegistryClient::new(
        BaseRegistryClientConfig::new(base_url, PeerPolicy::AcceptDevelopmentPeer)
            .with_token_provider(Arc::new(token)),
    )?)
}

async fn execute(
    run: &BregRun,
    native: &BTreeMap<(String, String), BaseRegistryClient>,
    scenario: &Scenario,
    input: &Value,
    directory: &Path,
    attempt: &mut Attempt,
    args: &RunArgs,
) -> Result<Value> {
    let selected = scenario.steps.iter().collect::<Vec<_>>();
    if attempt
        .pending
        .as_ref()
        .is_some_and(|p| !selected.iter().any(|s| s.id == p.step))
    {
        bail!(
            "an uncertain mutation must be resumed with its original --step before another action"
        );
    }
    let mut metadata = BTreeMap::new();
    for step in &scenario.steps {
        let key = (step.client.clone(), step.access_profile.clone());
        if let std::collections::btree_map::Entry::Vacant(entry) = metadata.entry(key.clone()) {
            entry.insert(
                native[&key]
                    .registry_contract(Some(&step.access_profile))
                    .await?
                    .value,
            );
        }
    }
    // Validate every payload and dependency before the first mutation, with
    // typed placeholder UUIDs for captures not produced yet. Native metadata
    // owns the payload schema; this runner owns only dependency interpretation.
    let mut declared = attempt.captures.clone();
    let mut declared_proposals = attempt.proposals.clone();
    for step in &scenario.steps {
        let key = (step.client.clone(), step.access_profile.clone());
        let client = &native[&key];
        let contract = &metadata[&key];
        if step.operation.is_proposal() {
            proposals::preflight(
                step,
                contract,
                input,
                &declared,
                &mut declared_proposals,
                attempt,
            )?;
            continue;
        }
        if step.operation == Operation::Invoke {
            let action = action_binding(contract, step)?;
            action_inputs(step, &action, input, &declared)?;
            for (alias, (_, entity)) in declared_action_capture_entities(&action, step)? {
                let placeholder = Capture {
                    entity,
                    id: uuid::Uuid::new_v4(),
                };
                if let Some(existing) = declared.get(&alias) {
                    if !attempt.completed.contains_key(&step.id)
                        || existing.entity != placeholder.entity
                    {
                        bail!(
                            "action capture aliases must be unique and match their declared entity"
                        );
                    }
                } else {
                    declared.insert(alias, placeholder);
                }
            }
            continue;
        }
        let kind = step.operation.metadata_kind();
        if !contract.operations().iter().any(|operation| {
            Some(operation.source_record_type()) == step.entity.as_deref()
                && operation.access_profile() == step.access_profile
                && *operation.kind() == kind
        }) {
            bail!(
                "example {} step {} requires advertised {} permission for its entity and profile",
                scenario.id,
                step.id,
                kind.as_str()
            );
        }
        if step.operation == Operation::Create {
            let binding = create_binding(contract, step)?;
            validate_reference_fields(step, contract, input, &declared).with_context(|| {
                format!(
                    "example {} step {} has an invalid reference",
                    scenario.id, step.id
                )
            })?;
            let request = payload(step, input, &declared).with_context(|| {
                format!(
                    "example {} step {} has an invalid input payload",
                    scenario.id, step.id
                )
            })?;
            let data = resolve(
                &input[step.input.as_deref().context("input key missing")?],
                &declared,
                0,
            )?;
            let schema = jsonschema::JSONSchema::options()
                .with_draft(jsonschema::Draft::Draft202012)
                .should_validate_formats(true)
                .compile(binding.request_schema())
                .map_err(|_| anyhow::anyhow!("advertised example input schema is invalid"))?;
            if !schema.is_valid(&json!({"data":data})) {
                bail!(
                    "example {} step {} input does not match its advertised create schema; inspect payload {} before running",
                    scenario.id,
                    step.id,
                    step.input.as_deref().unwrap_or_default()
                );
            }
            client.prepare_create(
                &binding,
                &request,
                &BRegIdempotencyKey::parse("example-preflight")?,
                BRegRecordFormat::Json,
            )?;
            let alias = step.capture.as_ref().context("create capture missing")?;
            if let Some(existing) = declared.get(alias) {
                if !attempt.completed.contains_key(&step.id)
                    || Some(existing.entity.as_str()) != step.entity.as_deref()
                {
                    bail!("capture aliases must be unique and match their declared entity");
                }
            } else {
                declared.insert(
                    alias.clone(),
                    Capture {
                        entity: step.entity.clone().context("create record type missing")?,
                        id: uuid::Uuid::new_v4(),
                    },
                );
            }
        } else {
            record(step, &declared)?;
            route(contract, step)?;
        }
    }
    if scenario.id == "first-record" {
        let create = &scenario.steps[0];
        let get = &scenario.steps[1];
        if get.record != create.capture || get.entity != create.entity {
            bail!("first-record must retrieve exactly the record it created");
        }
    }
    if declared.len() > 100 || declared_proposals.len() > 100 {
        bail!("scenario and inherited captures exceed the retained limit of 100");
    }
    attempt.save(directory)?;
    let mut results = BTreeMap::new();
    for step in selected {
        // Completed mutations are observations, not permission to recreate a
        // user-deleted sample. Reads intentionally inspect the current record.
        if let Some(result) = attempt.completed.get(&step.id) {
            let later_progress = step.operation == Operation::Inspect
                && scenario
                    .steps
                    .iter()
                    .skip_while(|later| later.id != step.id)
                    .skip(1)
                    .any(|later| {
                        attempt.completed.contains_key(&later.id)
                            || attempt
                                .pending
                                .as_ref()
                                .is_some_and(|pending| pending.step == later.id)
                    });
            if later_progress
                || !matches!(
                    step.operation,
                    Operation::Get | Operation::History | Operation::Inspect
                )
            {
                if step.operation == Operation::Invoke {
                    require_retained_invocation_capture(attempt, step)?;
                }
                results.insert(step.id.clone(), result.clone());
                continue;
            }
        }
        let key = (step.client.clone(), step.access_profile.clone());
        let client = &native[&key];
        let contract = &metadata[&key];
        if step.operation.is_proposal() {
            let result =
                proposals::execute(step, client, contract, input, directory, attempt).await?;
            results.insert(step.id.clone(), result);
            continue;
        }
        let mut invocation_captures = BTreeMap::new();
        let mut committed_invocation_error = None;
        let result = if step.operation == Operation::Invoke {
            let action = action_binding(contract, step)?;
            let inputs = action_inputs(step, &action, input, &attempt.captures)?;
            let key = BRegIdempotencyKey::parse(format!("examples-{}-{}", attempt.id, step.id))?;
            let prepared = if let Some(pending) = &attempt.pending {
                if pending.step != step.id {
                    bail!("resume the pending original action first");
                }
                BRegPreparedAction::from_slice(&serde_json::to_vec(&pending.capsule)?)?
            } else {
                let conditions = if action.required_condition_keys().is_empty() {
                    None
                } else {
                    let targets = action
                        .required_condition_keys()
                        .iter()
                        .map(|name| inputs.get(name).cloned().map(|value| (name.clone(), value)))
                        .collect::<Option<serde_json::Map<String, Value>>>()
                        .context("action condition input missing")?;
                    let request = BRegActionTargetConditionsRequest::new(&action, targets)?;
                    Some(
                        client
                            .action_target_conditions(&action, &request)
                            .await?
                            .value,
                    )
                };
                let request =
                    BRegActionInvocationRequest::new(&action, inputs.clone(), conditions.as_ref())?;
                let prepared = client.prepare_action(&action, &request, &key)?;
                attempt.pending = Some(Pending {
                    step: step.id.clone(),
                    capsule: serde_json::from_slice(prepared.as_bytes())?,
                });
                attempt.save(directory)?;
                prepared
            };
            let request = client.recover_action(&action, &prepared, &inputs, &key)?;
            let response = client.invoke_action(&action, &request, &key).await?;
            let receipt = serde_json::to_value(&response.value)?;
            let declarations = declared_action_capture_entities(&action, step)?;
            let disclosed = response
                .value
                .results()
                .iter()
                .map(|(effect, result)| {
                    (
                        effect.clone(),
                        (
                            result.record_type_identifier().to_owned(),
                            result.record_identifier(),
                        ),
                    )
                })
                .collect();
            match extract_invocation_captures(declarations, &disclosed) {
                Ok(captures) => invocation_captures = captures,
                Err(error) => committed_invocation_error = Some(error),
            }
            receipt
        } else if step.operation == Operation::Create {
            let binding = create_binding(contract, step)?;
            let prepared = if let Some(pending) = &attempt.pending {
                if pending.step != step.id {
                    bail!("resume the pending original step first");
                }
                BRegPreparedCreate::from_slice(&serde_json::to_vec(&pending.capsule)?)?
            } else {
                let request = payload(step, input, &attempt.captures)?;
                let key =
                    BRegIdempotencyKey::parse(format!("examples-{}-{}", attempt.id, step.id))?;
                let prepared =
                    client.prepare_create(&binding, &request, &key, BRegRecordFormat::Json)?;
                attempt.pending = Some(Pending {
                    step: step.id.clone(),
                    capsule: serde_json::from_slice(prepared.as_bytes())?,
                });
                attempt.save(directory)?;
                prepared
            };
            let expected_key =
                BRegIdempotencyKey::parse(format!("examples-{}-{}", attempt.id, step.id))?;
            let expected = client.prepare_create(
                &binding,
                &payload(step, input, &attempt.captures)?,
                &expected_key,
                BRegRecordFormat::Json,
            )?;
            if serde_json::from_slice::<Value>(prepared.as_bytes())?
                != serde_json::from_slice::<Value>(expected.as_bytes())?
            {
                bail!(
                    "pending create no longer matches its exact attempt input and captured dependencies"
                );
            }
            let (request, key, format) = client.recover_create(&binding, &prepared)?;
            let response = client
                .create_record(&binding, &request, &key, format)
                .await?;
            let capture = Capture {
                entity: step.entity.clone().context("create record type missing")?,
                id: uuid::Uuid::parse_str(&response.value.data.record_identifier)?,
            };
            attempt.captures.insert(
                step.capture.clone().context("create capture missing")?,
                capture,
            );
            serde_json::to_value(response.value)?
        } else {
            let capture = record(step, &attempt.captures)?;
            if step.operation == Operation::History {
                let response = client
                    .record_revisions(
                        &route(contract, step)?,
                        &capture.id.to_string(),
                        Some(&step.access_profile),
                    )
                    .await?;
                serde_json::from_slice(response.value.as_bytes())?
            } else {
                let response = client
                    .get_record(
                        &route(contract, step)?,
                        &capture.id.to_string(),
                        &BRegRecordOptions::default().access_profile(&step.access_profile)?,
                    )
                    .await?;
                serde_json::to_value(response.value)?
            }
        };
        #[cfg(test)]
        tests::interrupt_after_commit(step);
        let retained = if step.operation == Operation::Create {
            let capture =
                &attempt.captures[step.capture.as_deref().context("create capture missing")?];
            json!({"recordId":capture.id,"recordType":capture.entity})
        } else if matches!(step.operation, Operation::Get | Operation::History) {
            json!({"observed":true})
        } else {
            result.clone()
        };
        if step.operation == Operation::Invoke {
            retain_invocation(attempt, step, directory, retained, invocation_captures)?;
        } else {
            retain(attempt, step, directory, retained)?;
        }
        if let Some(error) = committed_invocation_error {
            bail!(error);
        }
        results.insert(step.id.clone(), result);
    }
    let next = format!(
        "bregctl examples run {} {} --run-id {} --attempt {}",
        scenario.id,
        shell_path(&run.project),
        args.run_id,
        attempt.id
    );
    let next = if scenario.id != "first-record" {
        if let Some(input) = &args.input {
            format!("{next} --input {}", shell_path(&fs::canonicalize(input)?))
        } else {
            next
        }
    } else {
        next
    };
    Ok(
        json!({"ok":true,"command":"examples run","project":run.project,"scenario":scenario.id,"attempt":attempt.id,"captures":attempt.captures,"proposals":attempt.proposals,"fromAttempt":attempt.from_attempt,"completedSteps":attempt.completed.keys().collect::<Vec<_>>(),"results":results,"nextCommand":next,"historyScope":"first-page-only","message":"Example progress retained. External review remains independent from these source-owned steps."}),
    )
}
fn validate_scenario_input(scenario: &Scenario, input: &Value) -> Result<()> {
    if !input.is_object() {
        bail!("example input must be an object of named payloads");
    }
    let declared_keys: BTreeSet<_> = scenario
        .steps
        .iter()
        .filter_map(|s| s.input.as_deref())
        .collect();
    let supplied_keys: BTreeSet<_> = input
        .as_object()
        .context("input object missing")?
        .keys()
        .map(String::as_str)
        .collect();
    if declared_keys != supplied_keys {
        bail!("example input must contain exactly the scenario's declared payload keys");
    }
    Ok(())
}
fn shell_path(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::disallowed_methods,
        reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
    )]
    use super::*;

    pub(super) fn interrupt_after_commit(step: &Step) {
        // Exists only in the Rust test harness. The released CLI has neither
        // this hook nor any environment-controlled interruption surface.
        if std::env::var("BREG_EXAMPLE_TEST_INTERRUPT").ok().as_deref() == Some(&step.id) {
            std::process::exit(79);
        }
    }
    fn copy_tree(from: &Path, to: &Path) {
        fs::create_dir_all(to).unwrap();
        for entry in fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&entry.path(), &to.join(entry.file_name()));
            } else {
                fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
            }
        }
    }

    fn assets() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/retained-native/example-catalog")
            .canonicalize()
            .unwrap()
    }
    #[tokio::test]
    async fn example_preflight_reads_metadata_from_a_development_peer() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            let body = json!({
                "id": "fixture-registry", "version": "1",
                "revision": format!("sha256:{}", "0".repeat(64)),
                "metadataVersion": "2", "recordTypes": [], "operations": [], "actions": []
            })
            .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nRegistry-Posture: development\r\nTraceparent: 00-1234567890abcdef1234567890abcdef-1234567890abcdef-01\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let client = example_client(
            origin.parse().unwrap(),
            StaticToken::new("synthetic-test-token").unwrap(),
        )
        .unwrap();
        let metadata = client.registry_contract(Some("editor")).await;
        server.await.unwrap();
        assert!(metadata.is_ok(), "{metadata:?}");
    }

    #[test]
    #[ignore = "requires a ready rstack dev BReg run of the minimal project"]
    fn live_run_examples_replay_the_same_attempt() {
        let project = PathBuf::from(std::env::var_os("BREG_EXAMPLE_PROJECT").unwrap());
        let run_id = std::env::var("BREG_EXAMPLE_RUN_ID").unwrap();
        let args = RunArgs {
            scenario: "contact".to_owned(),
            project,
            run_id,
            input: None,
            attempt: None,
            new_attempt: true,
            from_attempt: None,
        };
        let first = run_example(args).unwrap();
        let next = RunArgs {
            scenario: first["scenario"].as_str().unwrap().to_owned(),
            project: PathBuf::from(first["project"].as_str().unwrap()),
            run_id: std::env::var("BREG_EXAMPLE_RUN_ID").unwrap(),
            input: None,
            attempt: Some(first["attempt"].as_str().unwrap().parse().unwrap()),
            new_attempt: false,
            from_attempt: None,
        };
        let replay = run_example(next).unwrap();
        assert_eq!(first["attempt"], replay["attempt"]);
        assert_eq!(first["captures"], replay["captures"]);
    }

    #[test]
    fn listing_is_offline_and_does_not_create_dev_state() {
        let temp = tempfile::tempdir().unwrap();
        copy_tree(&assets(), temp.path());
        let value = run(ExamplesArgs {
            action: ExamplesAction::List {
                project: temp.path().into(),
                run_id: None,
            },
        })
        .unwrap();
        assert_eq!(value["scenarios"].as_array().unwrap().len(), 3);
        assert!(!temp.path().join(".breg").exists());
    }
    #[test]
    fn every_installed_facility_scenario_accepts_its_authored_input_keys() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("facility");
        assert!(crate::starters::run(&project, "facility-registry").is_ok());
        let project = project.canonicalize().unwrap();
        let (catalogue, _) = catalogue(&project).unwrap();
        for scenario in &catalogue.scenarios {
            let input: Value =
                serde_json::from_slice(&read_source(&project.join(&scenario.input)).unwrap())
                    .unwrap();
            validate_scenario_input(scenario, &input)
                .unwrap_or_else(|error| panic!("{}: {error}", scenario.id));
        }
    }
    #[test]
    fn typed_references_refuse_missing_and_malformed_aliases() {
        let captures = BTreeMap::from([(
            "parent".into(),
            Capture {
                entity: "entry".into(),
                id: uuid::Uuid::new_v4(),
            },
        )]);
        assert_eq!(
            resolve(&json!({"recordCapture":"parent"}), &captures, 0).unwrap(),
            json!(captures["parent"].id)
        );
        for value in [
            json!({"recordCapture":"missing"}),
            json!({"recordCapture":"parent","extra":true}),
            json!({"recordCapture":false}),
        ] {
            assert!(resolve(&value, &captures, 0).is_err());
        }
    }
    #[test]
    fn capture_dependencies_cannot_reference_later_records() {
        let (catalogue, _) = catalogue(&assets()).unwrap();
        let scenario = &catalogue.scenarios[0];
        let input: Value =
            serde_json::from_slice(&read_source(&assets().join(&scenario.input)).unwrap()).unwrap();
        let mut captures = BTreeMap::new();
        let linked = scenario.steps.last().unwrap();
        assert!(payload(linked, &input, &captures).is_err());
        for step in &scenario.steps {
            payload(step, &input, &captures).unwrap();
            captures.insert(
                step.capture.clone().unwrap(),
                Capture {
                    entity: step.entity.clone().unwrap(),
                    id: uuid::Uuid::new_v4(),
                },
            );
        }
    }
    fn attempt() -> Attempt {
        Attempt {
            version: 1,
            id: uuid::Uuid::new_v4(),
            scenario: "observe-created".into(),
            binding: Binding {
                source: "source".into(),
                package: "package".into(),
                database: "database".into(),
                clients: "clients".into(),
                scenario: "scenario".into(),
                input: "input".into(),
            },
            from_attempt: None,
            captures: BTreeMap::new(),
            proposals: BTreeMap::new(),
            completed: BTreeMap::new(),
            pending: None,
        }
    }
    #[test]
    fn attempt_files_are_private_and_generation_and_pending_operation_survive_reload() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(
            temp.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        private::directory(temp.path()).unwrap();
        let mut value = attempt();
        value.pending = Some(Pending {
            step: "submit".into(),
            capsule: json!({"exact":"original bytes"}),
        });
        value.save(temp.path()).unwrap();
        let loaded = attempts(temp.path()).unwrap().pop().unwrap();
        assert_eq!(loaded.binding, value.binding);
        assert_eq!(
            loaded.pending.unwrap().capsule,
            value.pending.as_ref().unwrap().capsule
        );
        let mut changed = value.binding.clone();
        changed.database = "replacement".into();
        assert_ne!(changed, value.binding);
        value.captures.insert(
            "bad".into(),
            Capture {
                entity: "entry".into(),
                id: uuid::Uuid::nil(),
            },
        );
        value.save(temp.path()).unwrap();
        assert!(attempts(temp.path()).is_err());
    }
    #[test]
    fn custom_population_requires_explicit_complete_same_generation_parent() {
        let (catalogue, _) = catalogue(&assets()).unwrap();
        let scenario = &catalogue.scenarios[0];
        let mut parent = attempt();
        parent.scenario = scenario.id.clone();
        parent.completed = scenario
            .steps
            .iter()
            .map(|s| (s.id.clone(), json!({})))
            .collect();
        parent.captures.insert(
            "parent".into(),
            Capture {
                entity: "entry".into(),
                id: uuid::Uuid::new_v4(),
            },
        );
        let mut child = attempt();
        child.scenario = "follow-up".into();
        child.binding.input = "different-input-is-expected".into();
        inherit_captures(&mut child, &parent, &catalogue).unwrap();
        assert_eq!(child.from_attempt, Some(parent.id));
        assert_eq!(child.captures["parent"].id, parent.captures["parent"].id);
        for field in ["source", "package", "database", "clients", "scenario"] {
            let mut changed = parent.clone();
            let mut binding = serde_json::to_value(&changed.binding).unwrap();
            binding[field] = json!("different");
            changed.binding = serde_json::from_value(binding).unwrap();
            assert!(inherit_captures(&mut child, &changed, &catalogue).is_err());
        }
        let mut pending = parent.clone();
        pending.pending = Some(Pending {
            step: scenario.steps[0].id.clone(),
            capsule: json!({}),
        });
        assert!(inherit_captures(&mut child, &pending, &catalogue).is_err());
        parent.completed.remove(&scenario.steps[0].id);
        assert!(inherit_captures(&mut child, &parent, &catalogue).is_err());

        let catalogue: Catalogue = serde_json::from_value(json!({"scenarios":[{
            "id":"population","description":"Register two records","input":"examples/input.json",
            "steps":[{"id":"register","operation":"invoke","client":"writer",
                "accessProfile":"writer","input":"register","action":"register-pair",
                "captureResults":{"first":"first","second":"second"}}]}]}))
        .unwrap();
        let mut parent = attempt();
        parent.scenario = "population".to_owned();
        parent
            .completed
            .insert("register".to_owned(), json!({"receipt":"committed"}));
        parent.captures.insert(
            "first".to_owned(),
            Capture {
                entity: "entry".to_owned(),
                id: uuid::Uuid::new_v4(),
            },
        );
        let mut child = attempt();
        assert!(inherit_captures(&mut child, &parent, &catalogue).is_err());
    }

    #[test]
    fn invoke_catalogue_requires_closed_named_disclosed_result() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("examples")).unwrap();
        let step = json!({"id":"register","operation":"invoke","recordType":"entry",
            "client":"writer","accessProfile":"writer","input":"register","capture":"entry",
            "action":"register-entry","result":"entry"});
        let valid = json!({"apiVersion":API_VERSION,"kind":KIND,"scenarios":[{"id":"register-entries",
            "description":"Register configured entries","input":"examples/inputs.json","steps":[step]}]});
        let path = temp.path().join("examples/scenarios.json");
        fs::write(&path, serde_json::to_vec(&valid).unwrap()).unwrap();
        catalogue(&temp.path().canonicalize().unwrap()).unwrap();
        let mut several = valid.clone();
        let invocation = several["scenarios"][0]["steps"][0].as_object_mut().unwrap();
        invocation.remove("recordType");
        invocation.remove("result");
        invocation.remove("capture");
        invocation.insert(
            "captureResults".to_owned(),
            json!({"entry":"entry", "audit":"audit"}),
        );
        fs::write(&path, serde_json::to_vec(&several).unwrap()).unwrap();
        catalogue(&temp.path().canonicalize().unwrap())
            .expect("an invocation can declare several result captures");

        for captures in [
            json!({}),
            json!({"entry":"same", "audit":"same"}),
            json!({"entry":"not.valid"}),
        ] {
            let mut invalid = several.clone();
            invalid["scenarios"][0]["steps"][0]["captureResults"] = captures;
            fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
            assert!(
                catalogue(&temp.path().canonicalize().unwrap()).is_err(),
                "missing, duplicate, and invalid capture declarations are refused"
            );
        }
        fs::write(&path, serde_json::to_vec(&valid).unwrap()).unwrap();
        for field in ["action", "result", "recordType", "capture"] {
            let mut invalid = valid.clone();
            invalid["scenarios"][0]["steps"][0]
                .as_object_mut()
                .unwrap()
                .remove(field);
            fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
            assert!(
                catalogue(&temp.path().canonicalize().unwrap()).is_err(),
                "{field}"
            );
        }
        for operation in ["create", "get", "history"] {
            let mut missing_record_type = json!({"apiVersion":API_VERSION,"kind":KIND,"scenarios":[{
                "id":"record-step","description":"Exercise one record step","input":"examples/inputs.json",
                "steps":[{"id":"step","operation":operation,"recordType":"entry","client":"writer",
                    "accessProfile":"writer","input":"entry","capture":"entry","record":"entry"}]}]});
            let step = missing_record_type["scenarios"][0]["steps"][0]
                .as_object_mut()
                .unwrap();
            step.remove("recordType");
            if operation == "create" {
                step.remove("record");
            } else {
                step.remove("input");
                step.remove("capture");
            }
            fs::write(&path, serde_json::to_vec(&missing_record_type).unwrap()).unwrap();
            assert!(catalogue(&temp.path().canonicalize().unwrap()).is_err());
        }

        let mut non_invoke = valid.clone();
        let step = non_invoke["scenarios"][0]["steps"][0]
            .as_object_mut()
            .unwrap();
        step.insert("operation".to_owned(), json!("get"));
        step.insert("record".to_owned(), json!("entry"));
        step.insert(
            "captureResults".to_owned(),
            json!({"entry":"another-entry"}),
        );
        for member in ["input", "capture", "action", "result"] {
            step.remove(member);
        }
        let report = catalogue_refusal(&non_invoke);
        let diagnostic = report
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "breg.examples.step-members")
            .expect("non-invoke captureResults has a focused diagnostic");
        assert!(diagnostic.message.contains("captureResults"));
        assert!(diagnostic.suggested_action.contains("captureResults"));

        let mut too_many = several.clone();
        too_many["scenarios"][0]["steps"][0]["captureResults"] = Value::Object(
            (0..101)
                .map(|index| (format!("result{index}"), json!(format!("capture{index}"))))
                .collect(),
        );
        let report = catalogue_refusal(&too_many);
        assert!(report.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == "breg.examples.capture-results"
                && diagnostic.message.contains("at most 100")
        }));
        // The action and the disclosed result name a governed action and one of
        // its declared effects, and that grammar admits an underscore. A name
        // this catalogue refuses is an authored action a scenario could never
        // invoke.
        for (action, result) in [
            ("register_entry", "entry"),
            ("register-entry", "entry_record"),
            ("r2", "e2"),
        ] {
            let mut named = valid.clone();
            named["scenarios"][0]["steps"][0]["action"] = json!(action);
            named["scenarios"][0]["steps"][0]["result"] = json!(result);
            fs::write(&path, serde_json::to_vec(&named).unwrap()).unwrap();
            catalogue(&temp.path().canonicalize().unwrap())
                .unwrap_or_else(|error| panic!("{action}/{result}: {error}"));
        }
        // The grammar stays closed in the other direction: anchored on a
        // lowercase letter, and no other byte.
        for name in ["2register", "_register", "Register", "register.entry"] {
            for field in ["action", "result"] {
                let mut named = valid.clone();
                named["scenarios"][0]["steps"][0][field] = json!(name);
                fs::write(&path, serde_json::to_vec(&named).unwrap()).unwrap();
                assert!(
                    catalogue(&temp.path().canonicalize().unwrap()).is_err(),
                    "{field}: {name}"
                );
            }
        }
        let mut invalid = valid;
        invalid["scenarios"][0]["steps"][0]["operation"] = json!("apply");
        fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
        assert!(
            catalogue(&temp.path().canonicalize().unwrap()).is_err(),
            "custom population cannot hide review application"
        );
    }

    /// The diagnostics a refused catalogue carries.
    fn catalogue_refusal(document: &Value) -> Report {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("examples")).unwrap();
        fs::write(
            temp.path().join(CATALOGUE_FILE),
            serde_json::to_vec_pretty(document).unwrap(),
        )
        .unwrap();
        match catalogue(&temp.path().canonicalize().unwrap())
            .expect_err("the catalogue is refused")
            .downcast::<CatalogueRefused>()
        {
            Ok(refused) => refused.0,
            Err(error) => panic!("not a document refusal: {error:#}"),
        }
    }

    fn assert_catalogue_accepted(document: &Value) {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("examples")).unwrap();
        fs::write(
            temp.path().join(CATALOGUE_FILE),
            serde_json::to_vec_pretty(document).unwrap(),
        )
        .unwrap();
        catalogue(&temp.path().canonicalize().unwrap())
            .unwrap_or_else(|error| panic!("the catalogue should be accepted: {error:#}"));
    }

    fn serialized_value_position(document: &Value, value: &str) -> (usize, usize) {
        let written = serde_json::to_string_pretty(document).unwrap();
        let quoted = format!("\"{value}\"");
        written
            .lines()
            .enumerate()
            .find_map(|(line, written)| written.find(&quoted).map(|column| (line + 1, column + 1)))
            .unwrap_or_else(|| panic!("missing {value:?} in {written}"))
    }

    fn located(report: &Report) -> Vec<(&str, &str, Option<usize>)> {
        report
            .diagnostics()
            .iter()
            .map(|diagnostic| {
                (
                    diagnostic.code.as_str(),
                    diagnostic.path.as_str(),
                    diagnostic.source.as_ref().and_then(|source| source.line),
                )
            })
            .collect()
    }

    #[test]
    fn the_catalogue_header_replaces_its_version_member() {
        let report = catalogue_refusal(&json!({"version":1,"scenarios":[]}));
        assert_eq!(
            located(&report),
            [
                ("config.missing-envelope", "", Some(1)),
                ("config.removed-key", "/version", Some(3))
            ],
            "{}",
            report.render_human()
        );
        let rendered = report.render_human();
        assert!(
            rendered.contains(API_VERSION) && rendered.contains(KIND),
            "{rendered}"
        );
        let report = catalogue_refusal(
            &json!({"apiVersion":API_VERSION,"kind":KIND,"version":1,"scenarios":[]}),
        );
        let [diagnostic] = report.diagnostics() else {
            panic!("{}", report.render_human());
        };
        assert_eq!(diagnostic.code, "config.removed-key");
        assert_eq!(diagnostic.path, "/version");
        assert!(diagnostic.suggested_action.contains("apiVersion"));
    }

    #[test]
    fn retired_scenario_record_type_key_has_rename_diagnostic() {
        let report = catalogue_refusal(&json!({"apiVersion": API_VERSION, "kind": KIND,
            "scenarios": [{"id": "read", "description": "Read a retained record", "input": "examples/inputs.json",
                "steps": [{"id": "read-record", "operation": "get", "entity": "record", "client": "reader",
                    "accessProfile": "reader", "record": "record"}]}]}));
        let diagnostic = report
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.path == "/scenarios/0/steps/0/entity")
            .expect("the retired Record type key has its own diagnostic");
        assert_eq!(diagnostic.code, "config.removed-key");
        assert!(diagnostic.suggested_action.contains("recordType"));
    }

    #[test]
    fn catalogue_checks_report_every_problem_at_its_member() {
        let create = json!({"id":"make","operation":"create","recordType":"entry","client":"writer",
            "accessProfile":"writer","input":"make","capture":"made"});
        let mut invoke = create.clone();
        invoke["id"] = json!("register");
        invoke["operation"] = json!("invoke");
        let mut apply = create.clone();
        apply["id"] = json!("apply");
        apply["operation"] = json!("history");
        let report = catalogue_refusal(&json!({"apiVersion":API_VERSION,"kind":KIND,"scenarios":[
            {"id":"population","description":"","input":"../outside.json",
             "steps":[create, invoke, apply]}]}));
        assert_eq!(
            located(&report),
            [
                (
                    "breg.examples.description-length",
                    "/scenarios/0/description",
                    Some(6)
                ),
                ("breg.examples.input-path", "/scenarios/0/input", Some(8)),
                (
                    "breg.examples.step-members",
                    "/scenarios/0/steps/1",
                    Some(19)
                ),
                (
                    "breg.examples.capture-results",
                    "/scenarios/0/steps/1/capture",
                    Some(21)
                ),
                (
                    "breg.examples.step-members",
                    "/scenarios/0/steps/2",
                    Some(28)
                ),
            ],
            "{}",
            report.render_human()
        );
        assert!(!report.render_human().contains("outside.json"));
        // Repeated identifiers are refused by the reader's list type, at the
        // second item's id.
        let step = json!({"id":"make","operation":"get","recordType":"entry","client":"writer",
            "accessProfile":"writer","record":"made"});
        let report = catalogue_refusal(&json!({"apiVersion":API_VERSION,"kind":KIND,"scenarios":[
            {"id":"population","description":"Read","input":"examples/in.json","steps":[step.clone(), step]}]}));
        assert_eq!(
            report
                .diagnostics()
                .iter()
                .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
                .collect::<Vec<_>>(),
            [("config.duplicate-id", "/scenarios/0/steps/1/id")],
            "{}",
            report.render_human()
        );
    }

    #[test]
    fn catalogue_descriptions_use_display_text_without_changing_length_bounds() {
        let step = json!({"id":"read","operation":"get","recordType":"entry","client":"reader",
            "accessProfile":"reader","record":"entry"});
        let catalogue_value = |description: String| {
            json!({
                "apiVersion":API_VERSION,"kind":KIND,"scenarios":[{
                    "id":"read","description":description,"input":"examples/input.json",
                    "steps":[step.clone()]
                }]
            })
        };
        for refused in ['\u{202e}', '\u{2028}', '\u{fdd0}'] {
            let report = catalogue_refusal(&catalogue_value(format!("unsafe{refused}text")));
            let diagnostic = report
                .diagnostics()
                .iter()
                .find(|diagnostic| diagnostic.path == "/scenarios/0/description")
                .unwrap_or_else(|| {
                    panic!("missing description refusal: {}", report.render_human())
                });
            assert_eq!(diagnostic.code, "config.invalid-value");
            assert!(diagnostic.source.as_ref().unwrap().line.is_some());
        }
        for refused in ["x".repeat(1025), "é".repeat(513)] {
            let report = catalogue_refusal(&catalogue_value(refused));
            assert!(report.diagnostics().iter().any(|diagnostic| {
                diagnostic.code == "breg.examples.description-length"
                    && diagnostic.path == "/scenarios/0/description"
            }));
        }
        for accepted in ["שלום\u{200f}".to_owned(), "é".repeat(512)] {
            let temp = tempfile::tempdir().unwrap();
            fs::create_dir(temp.path().join("examples")).unwrap();
            fs::write(
                temp.path().join(CATALOGUE_FILE),
                serde_json::to_vec_pretty(&catalogue_value(accepted)).unwrap(),
            )
            .unwrap();
            catalogue(&temp.path().canonicalize().unwrap())
                .expect("multilingual DisplayText at the byte limit is accepted");
        }
    }

    #[test]
    fn catalogue_ids_refuse_separator_collisions_in_each_definition_namespace() {
        let step = || {
            json!({"id":"read-record","operation":"get","recordType":"entry",
            "client":"reader","accessProfile":"reader","record":"entry"})
        };
        let scenario = |id: &str, steps: Vec<Value>| {
            json!({
                "id":id,"description":"Read a record","input":"examples/input.json","steps":steps
            })
        };

        let report = catalogue_refusal(&json!({
            "apiVersion":API_VERSION,"kind":KIND,"scenarios":[
                scenario("read-one", vec![step()]),
                scenario("read_one", vec![step()])
            ]
        }));
        let diagnostic = report
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "breg.examples.scenario-id-collision")
            .unwrap_or_else(|| panic!("missing scenario collision: {}", report.render_human()));
        assert_eq!(diagnostic.path, "/scenarios/1/id");
        assert_eq!(diagnostic.related[0].path, "/scenarios/0/id");
        assert!(diagnostic.source.as_ref().unwrap().line.is_some());
        assert!(diagnostic.related[0].line.is_some());

        let mut second_step = step();
        second_step["id"] = json!("read_record");
        let report = catalogue_refusal(&json!({
            "apiVersion":API_VERSION,"kind":KIND,"scenarios":[
                scenario("read", vec![step(), second_step])
            ]
        }));
        let diagnostic = report
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "breg.examples.step-id-collision")
            .unwrap_or_else(|| panic!("missing step collision: {}", report.render_human()));
        assert_eq!(diagnostic.path, "/scenarios/0/steps/1/id");
        assert_eq!(diagnostic.related[0].path, "/scenarios/0/steps/0/id");
        assert!(diagnostic.source.as_ref().unwrap().line.is_some());
        assert!(diagnostic.related[0].line.is_some());
    }

    #[test]
    fn catalogue_capture_aliases_share_one_positioned_scenario_namespace() {
        let create = json!({
            "id":"create","operation":"create","recordType":"entry","client":"writer",
            "accessProfile":"writer","input":"entry","capture":"case-file"
        });
        let invoke = json!({
            "id":"invoke","operation":"invoke","client":"writer","accessProfile":"writer",
            "input":"action","action":"register-entry",
            "captureResults":{"entry":"case_file"}
        });
        let singular_invoke = json!({
            "id":"invoke","operation":"invoke","recordType":"entry","client":"writer",
            "accessProfile":"writer","input":"action","action":"register-entry",
            "result":"entry","capture":"case_file"
        });
        let start = json!({
            "id":"start","operation":"start","client":"writer","accessProfile":"writer",
            "input":"proposal","action":"correct-entry","capture":"case_file"
        });
        for (second, primary) in [
            (singular_invoke, "/scenarios/0/steps/1/capture"),
            (invoke, "/scenarios/0/steps/1/captureResults/entry"),
            (start, "/scenarios/0/steps/1/capture"),
        ] {
            let catalogue = json!({
                "apiVersion":API_VERSION,"kind":KIND,"scenarios":[{
                    "id":"capture-aliases","description":"Exercise capture aliases",
                    "input":"examples/input.json","steps":[create.clone(), second]
                }]
            });
            let primary_position = serialized_value_position(&catalogue, "case_file");
            let related_position = serialized_value_position(&catalogue, "case-file");
            let report = catalogue_refusal(&catalogue);
            let diagnostic = report
                .diagnostics()
                .iter()
                .find(|diagnostic| diagnostic.code == "breg.examples.capture-id-collision")
                .unwrap_or_else(|| panic!("missing capture collision: {}", report.render_human()));
            assert_eq!(diagnostic.path, primary);
            assert_eq!(diagnostic.related[0].path, "/scenarios/0/steps/0/capture");
            let source = diagnostic.source.as_ref().expect("primary source");
            assert_eq!(
                (source.line, source.column),
                (Some(primary_position.0), Some(primary_position.1))
            );
            assert_eq!(
                (diagnostic.related[0].line, diagnostic.related[0].column),
                (Some(related_position.0), Some(related_position.1))
            );
        }

        let mut second_create = create.clone();
        second_create["capture"] = json!("case_file");
        assert_catalogue_accepted(&json!({
            "apiVersion":API_VERSION,"kind":KIND,"scenarios":[
                {"id":"first","description":"First namespace","input":"examples/input.json",
                 "steps":[create.clone()]},
                {"id":"second","description":"Second namespace","input":"examples/input.json",
                 "steps":[second_create]}
            ]
        }));

        let reference = json!({
            "id":"case_file","operation":"get","recordType":"entry","client":"reader",
            "accessProfile":"reader","record":"case_file"
        });
        assert_catalogue_accepted(&json!({
            "apiVersion":API_VERSION,"kind":KIND,"scenarios":[{
                "id":"references","description":"References stay outside the definition namespace",
                "input":"examples/input.json","steps":[create, reference]
            }]
        }));
    }

    #[test]
    fn a_committed_invocation_retains_its_receipt_and_capture_atomically() {
        // An invocation that commits and then discloses no authored capture is
        // a refusal, and the mutation behind it has already happened. Retaining
        // the step is what keeps that refusal from becoming a resume that
        // replays the same idempotency key, receives the same receipt, and
        // fails on it again; the run loop refuses a retained invocation that
        // has no capture without replaying its mutation.
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(
            temp.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        private::directory(temp.path()).unwrap();
        let step: Step = serde_json::from_value(json!({"id":"register","operation":"invoke",
            "recordType":"entry","client":"writer","accessProfile":"writer","input":"register",
            "capture":"entry","action":"register-entry","result":"entry"}))
        .unwrap();
        assert!(!serde_json::to_value(&step)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("captureResults"));
        let mut value = attempt();
        value.pending = Some(Pending {
            step: step.id.clone(),
            capsule: json!({"exact":"original bytes"}),
        });
        let capture = Capture {
            entity: step.entity.clone().unwrap(),
            id: uuid::Uuid::new_v4(),
        };
        retain_invocation(
            &mut value,
            &step,
            temp.path(),
            json!({"receipt":true}),
            BTreeMap::from([("entry".to_owned(), capture.clone())]),
        )
        .unwrap();
        assert!(value.pending.is_none());
        assert_eq!(value.completed[&step.id], json!({"receipt":true}));
        assert_eq!(value.captures["entry"].id, capture.id);
        let reloaded = attempts(temp.path()).unwrap().pop().unwrap();
        assert!(reloaded.pending.is_none());
        assert_eq!(reloaded.completed[&step.id], json!({"receipt":true}));
        assert_eq!(reloaded.captures["entry"].id, capture.id);
        assert!(require_retained_invocation_capture(&reloaded, &step).is_ok());

        // A handler is allowed to omit a declared result. That is still a
        // completed invocation whose exact idempotency capsule must not replay.
        value.id = uuid::Uuid::new_v4();
        value.completed.clear();
        value.captures.clear();
        value.pending = Some(Pending {
            step: step.id.clone(),
            capsule: json!({"exact":"original bytes"}),
        });
        retain_invocation(
            &mut value,
            &step,
            temp.path(),
            json!({"receipt":"without-result"}),
            BTreeMap::new(),
        )
        .unwrap();
        let reloaded = attempts(temp.path())
            .unwrap()
            .into_iter()
            .find(|attempt| attempt.id == value.id)
            .unwrap();
        assert!(reloaded.pending.is_none());
        assert!(reloaded.captures.is_empty());
        assert!(require_retained_invocation_capture(&reloaded, &step).is_err());
        assert_eq!(
            reloaded.completed[&step.id],
            json!({"receipt":"without-result"})
        );

        // Multi-result extraction is all-or-nothing. A valid first result must
        // not leak into retained state when another configured result is
        // absent or has the wrong Record type.
        let step: Step = serde_json::from_value(json!({"id":"register-pair","operation":"invoke",
            "client":"writer","accessProfile":"writer","input":"register",
            "action":"register-pair","captureResults":{"first":"first","second":"second"}}))
        .unwrap();
        let first_id = uuid::Uuid::new_v4();
        let declarations = BTreeMap::from([
            ("first".to_owned(), ("first".to_owned(), "entry".to_owned())),
            (
                "second".to_owned(),
                ("second".to_owned(), "assignment".to_owned()),
            ),
        ]);
        let disclosed = BTreeMap::from([("first".to_owned(), ("entry".to_owned(), first_id))]);
        assert_eq!(
            extract_invocation_captures(declarations.clone(), &disclosed).unwrap_err(),
            "successful action did not disclose every configured capture result"
        );
        let disclosed = BTreeMap::from([
            ("first".to_owned(), ("entry".to_owned(), first_id)),
            (
                "second".to_owned(),
                ("wrong-record-type".to_owned(), uuid::Uuid::new_v4()),
            ),
        ]);
        assert_eq!(
            extract_invocation_captures(declarations, &disclosed).unwrap_err(),
            "action receipt capture entity differs from its authored declaration"
        );

        value.id = uuid::Uuid::new_v4();
        value.completed.clear();
        value.captures.clear();
        value.pending = Some(Pending {
            step: step.id.clone(),
            capsule: json!({"exact":"original multi-result bytes"}),
        });
        retain_invocation(
            &mut value,
            &step,
            temp.path(),
            json!({"receipt":"missing-second-result"}),
            BTreeMap::new(),
        )
        .unwrap();
        let reloaded = attempts(temp.path())
            .unwrap()
            .into_iter()
            .find(|attempt| attempt.id == value.id)
            .unwrap();
        assert!(reloaded.pending.is_none());
        assert!(reloaded.captures.is_empty());
        assert_eq!(
            reloaded.completed[&step.id],
            json!({"receipt":"missing-second-result"})
        );
        assert!(require_retained_invocation_capture(&reloaded, &step).is_err());
    }
}
