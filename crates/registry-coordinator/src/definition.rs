// SPDX-License-Identifier: Apache-2.0
//! Closed, finite workflow authoring and immutable execution snapshots.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    io::Read as _,
    path::Path,
    sync::{Arc, Mutex, PoisonError},
};

use chrono::{DateTime, Duration, Utc};
use jsonschema::{Draft, JSONSchema, SchemaResolver, SchemaResolverError};
use registry_platform_config::sha256_uri;
use registry_platform_yaml::Document;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    functions::{check_value, Functions, INTERPRETER_ABI},
    operations::OperationIdentity,
    protocol::Operation,
    CoordinatorError, Result,
};

/// The compiled snapshot format, carried by its workflow.
pub(crate) const API_VERSION: &str =
    "id.registrystack.org/formats/coordinator/definition-snapshot/v1alpha1";
const ADAPTER_ABI: &str = "coordinator/product-operations/v1";
const SCHEMA_ABI: &str = "coordinator/jsonschema-0.18/draft202012/formats-asserted+uuid/v1";
const MAX_DOCUMENT_BYTES: usize = 1_048_576;
/// Maximum canonical snapshot size, shared by authoring, restore and packaging.
pub(crate) const MAX_SNAPSHOT_BYTES: usize = 393_216;

#[derive(Clone)]
pub struct Definition {
    pub workflow: Workflow,
    pub digest: String,
    frozen: Snapshot,
    functions: Functions,
    input_schema: Arc<JSONSchema>,
    outcome_schemas: BTreeMap<String, Arc<JSONSchema>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Workflow {
    pub api_version: String,
    pub kind: String,
    pub id: String,
    pub version: String,
    pub input: Value,
    pub connections: BTreeMap<String, String>,
    pub functions: String,
    pub deadline: String,
    pub start: String,
    pub steps: BTreeMap<String, Step>,
    pub outcomes: BTreeMap<String, Value>,
}

/// How a step computes its value: a pure function over references, an
/// object built member by member from references, or one reference.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged, deny_unknown_fields)]
pub enum Mapping {
    Function {
        function: String,
        arguments: Vec<Reference>,
    },
    Fields {
        fields: BTreeMap<String, Reference>,
    },
    Reference(Reference),
}

/// A value a mapping reads. A path is an RFC 6901 JSON Pointer into the
/// workflow input or the referenced step's output.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Reference {
    Input {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
    },
    Step {
        step: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
    },
    Literal {
        value: Value,
    },
}

/// The longest reference path accepted.
pub(crate) const MAXIMUM_PATH_CHARS: usize = 256;
/// The most members one fields mapping builds.
pub(crate) const MAXIMUM_FIELDS: usize = 64;

/// An RFC 6901 pointer below the root: `~` only as `~0` or `~1`.
pub(crate) fn valid_pointer(text: &str) -> bool {
    text.starts_with('/')
        && text.chars().count() <= MAXIMUM_PATH_CHARS
        && text
            .split('~')
            .skip(1)
            .all(|escaped| escaped.starts_with(['0', '1']))
}

/// A member name a fields mapping writes, matching the product wire names.
pub(crate) fn valid_field_name(name: &str) -> bool {
    name.len() <= 64
        && name.bytes().next().is_some_and(|c| c.is_ascii_alphabetic())
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

impl Mapping {
    /// Each reference with its member path below the mapping.
    pub(crate) fn references(&self) -> Vec<(String, &Reference)> {
        match self {
            Self::Function { arguments, .. } => arguments
                .iter()
                .enumerate()
                .map(|(index, reference)| (format!(".arguments[{index}]"), reference))
                .collect(),
            Self::Fields { fields } => fields
                .iter()
                .map(|(name, reference)| (format!(".fields.{name}"), reference))
                .collect(),
            Self::Reference(reference) => vec![(String::new(), reference)],
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Call {
    pub connection: String,
    pub operation: Operation,
}

/// The event a wait-for step waits for.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WaitEvent {
    /// The result of the review request the named call step submitted.
    ReviewResult { request: String },
}

impl WaitEvent {
    /// The event type an author writes.
    pub fn id(&self) -> &'static str {
        match self {
            Self::ReviewResult { .. } => "review-result",
        }
    }

    /// The call step whose accepted request the event correlates with.
    pub fn request(&self) -> &str {
        match self {
            Self::ReviewResult { request } => request,
        }
    }
}

/// The longest wait a wait-for step declares, in seconds: one year, the
/// longest run deadline.
pub(crate) const MAXIMUM_WAIT_SECONDS: u32 = 31_536_000;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged, deny_unknown_fields)]
pub enum Step {
    WaitUntil {
        #[serde(rename = "waitUntil")]
        wait_until: Mapping,
        next: String,
    },
    WaitFor {
        #[serde(rename = "waitFor")]
        wait_for: WaitEvent,
        #[serde(rename = "timeoutSeconds")]
        timeout_seconds: u32,
        next: String,
        #[serde(rename = "onTimeout", default, skip_serializing_if = "Option::is_none")]
        on_timeout: Option<String>,
    },
    Call {
        call: Call,
        input: Mapping,
        next: String,
    },
    Choose {
        choose: Mapping,
        cases: BTreeMap<String, String>,
    },
    Finish {
        finish: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        output: Option<Mapping>,
    },
}

impl Step {
    /// Each transition with the authored member that holds it.
    pub(crate) fn edges(&self) -> Vec<(&'static str, &str)> {
        match self {
            Self::WaitUntil { next, .. } | Self::Call { next, .. } => vec![("next", next)],
            Self::WaitFor {
                next, on_timeout, ..
            } => std::iter::once(("next", next.as_str()))
                .chain(on_timeout.iter().map(|step| ("onTimeout", step.as_str())))
                .collect(),
            Self::Choose { cases, .. } => cases
                .values()
                .map(|step| ("cases", step.as_str()))
                .collect(),
            Self::Finish { .. } => vec![],
        }
    }
    fn targets(&self) -> Vec<&str> {
        self.edges().into_iter().map(|(_, target)| target).collect()
    }
    /// The authored member that holds this step's mapping.
    pub(crate) fn role(&self) -> &'static str {
        match self {
            Self::WaitUntil { .. } => "waitUntil",
            Self::WaitFor { .. } => "waitFor",
            Self::Call { .. } => "input",
            Self::Choose { .. } => "choose",
            Self::Finish { .. } => "output",
        }
    }
    pub(crate) fn mapping(&self) -> Option<&Mapping> {
        match self {
            Self::WaitUntil { wait_until, .. } => Some(wait_until),
            Self::WaitFor { .. } => None,
            Self::Call { input, .. } => Some(input),
            Self::Choose { choose, .. } => Some(choose),
            Self::Finish { output, .. } => output.as_ref(),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Snapshot {
    workflow: Workflow,
    source: String,
    adapter_abi: String,
    interpreter_abi: String,
    schema_abi: String,
    operation_identities: Vec<OperationIdentity>,
}

fn operation_identities(workflow: &Workflow) -> Vec<OperationIdentity> {
    let mut identities: Vec<_> = workflow
        .steps
        .values()
        .filter_map(|step| match step {
            Step::Call { call, .. } => Some(call.operation.identity()),
            _ => None,
        })
        .collect();
    identities.sort_by(|a, b| a.id.cmp(&b.id));
    identities.dedup();
    identities
}

/// Compiled definitions keyed by the digest of their snapshot text, so one
/// worker serving several flows compiles each pinned or in-flight snapshot once.
///
/// The bound holds every flow a deployment serves plus the snapshots its
/// in-flight runs still carry. When it is full, the cache starts again from
/// empty rather than tracking use, and a refused snapshot is never kept.
pub struct DefinitionCache {
    limit: usize,
    entries: Mutex<HashMap<String, Arc<Definition>>>,
}

impl DefinitionCache {
    pub fn new(limit: usize) -> Self {
        Self {
            limit: limit.max(1),
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Keep an already compiled definition, such as a pinned package's.
    pub fn seed(&self, definition: Arc<Definition>) -> Result<()> {
        let key = sha256_uri(definition.snapshot()?.as_bytes());
        self.insert(key, definition);
        Ok(())
    }

    /// Return the compiled definition for this snapshot text, compiling it
    /// outside the lock when it is not cached.
    pub fn get(&self, snapshot: &str) -> Result<Arc<Definition>> {
        let key = sha256_uri(snapshot.as_bytes());
        if let Some(definition) = self.lock().get(&key) {
            return Ok(definition.clone());
        }
        let definition = Arc::new(Definition::from_snapshot(snapshot)?);
        self.insert(key, definition.clone());
        Ok(definition)
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    fn insert(&self, key: String, definition: Arc<Definition>) {
        let mut entries = self.lock();
        if !entries.contains_key(&key) && entries.len() >= self.limit {
            entries.clear();
        }
        entries.insert(key, definition);
    }

    /// A panic while the lock was held leaves only whole entries behind, so
    /// the map stays usable.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<Definition>>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Definition {
    pub fn load(project: &Path) -> Result<Self> {
        Self::load_project(project).map(|(definition, _)| definition)
    }

    /// Load an authored project with the workflow document its findings are
    /// placed in.
    pub(crate) fn load_project(project: &Path) -> Result<(Self, Document)> {
        let project = project
            .canonicalize()
            .map_err(|_| fail("definition.read").at(project, ""))?;
        let path = project.join("workflow.yaml");
        let bytes = read_bytes(&path, MAX_DOCUMENT_BYTES)?;
        let (workflow, document) = crate::authoring::parse_project(&path, &bytes)?;
        // A project deliberately has one local source file, rather than an import
        // loader or arbitrary path vocabulary.
        if workflow.functions != "functions.rhai" {
            return Err(crate::authoring::positioned(
                &document,
                fail("definition.functions_file").at(&path, "functions"),
            ));
        }
        let source = read_text(&project.join(&workflow.functions), 65_536).map_err(|error| {
            let exit = error.exit_code;
            crate::authoring::positioned(&document, error.at(&path, "functions")).with_exit(exit)
        })?;
        let definition = Self::restore_checked(Snapshot {
            operation_identities: operation_identities(&workflow),
            workflow,
            source,
            adapter_abi: ADAPTER_ABI.into(),
            interpreter_abi: INTERPRETER_ABI.into(),
            schema_abi: SCHEMA_ABI.into(),
        })
        .map_err(|findings| crate::authoring::placed(&document, findings))?;
        // Authoring holds a project to the static mapping checks; a restored
        // snapshot is not, so an admitted run never fails on a stricter check.
        let findings = crate::mapping_check::check(&definition.workflow);
        if !findings.is_empty() {
            return Err(crate::authoring::placed(&document, findings));
        }
        Ok((definition, document))
    }

    pub fn from_snapshot(snapshot: &str) -> Result<Self> {
        if snapshot.len() > MAX_SNAPSHOT_BYTES {
            return Err(fail("definition.snapshot_limit"));
        }
        let value = registry_platform_canonical_json::parse_json_strict(snapshot.as_bytes())
            .map_err(|_| fail("definition.snapshot"))?;
        let frozen = serde_json::from_value(value).map_err(|_| fail("definition.snapshot"))?;
        Self::restore(frozen)
    }

    fn restore(frozen: Snapshot) -> Result<Self> {
        Self::restore_checked(frozen).map_err(|findings| {
            findings
                .into_iter()
                .next()
                .unwrap_or_else(|| fail("definition.shape"))
        })
    }

    /// Restore a snapshot, or report every independent refusal of it.
    fn restore_checked(frozen: Snapshot) -> std::result::Result<Self, Vec<CoordinatorError>> {
        let operations_match = frozen.operation_identities
            == operation_identities(&frozen.workflow)
            && frozen
                .operation_identities
                .iter()
                .all(OperationIdentity::matches_registered);
        if !operations_match
            || frozen.adapter_abi != ADAPTER_ABI
            || frozen.interpreter_abi != INTERPRETER_ABI
            || frozen.schema_abi != SCHEMA_ABI
        {
            return Err(vec![fail("definition.abi")]);
        }
        let mut findings = workflow_findings(&frozen.workflow);
        let mappings = frozen
            .workflow
            .steps
            .iter()
            .filter_map(|(name, step)| Some((name.as_str(), step.role(), step.mapping()?)))
            .collect::<Vec<_>>();
        let functions = Functions::compile(&frozen.source, &mappings)
            .map_err(|refused| findings.extend(refused))
            .ok();
        let input_schema = compile_schema(&frozen.workflow.input)
            .map_err(|error| findings.push(error.at("workflow.yaml", "input")))
            .ok();
        let mut outcome_schemas = BTreeMap::new();
        for (id, schema) in &frozen.workflow.outcomes {
            match compile_schema(schema) {
                Ok(compiled) => {
                    outcome_schemas.insert(id.clone(), Arc::new(compiled));
                }
                Err(error) => {
                    findings.push(error.at("workflow.yaml", format!("outcomes.{id}")));
                }
            }
        }
        for (name, step) in &frozen.workflow.steps {
            if let Step::Finish {
                finish,
                output: None,
            } = step
            {
                if outcome_schemas
                    .get(finish)
                    .is_some_and(|schema| !schema.is_valid(&Value::Null))
                {
                    findings.push(authored(
                        "definition.outcome",
                        &format!("steps.{name}.finish"),
                        &format!(
                            "step {name} finishes without an output, and the {finish} outcome schema refuses null"
                        ),
                        &format!(
                            "Add an output to step {name}, or let the {finish} outcome schema accept null."
                        ),
                    ));
                }
            }
        }
        let (Some(functions), Some(input_schema), true) =
            (functions, input_schema, findings.is_empty())
        else {
            return Err(findings);
        };
        let input_schema = Arc::new(input_schema);
        let bytes = snapshot_bytes(&frozen).map_err(|error| vec![error])?;
        Ok(Self {
            workflow: frozen.workflow.clone(),
            digest: sha256_uri(&bytes),
            frozen,
            functions,
            input_schema,
            outcome_schemas,
        })
    }

    fn check_integrity(&self) -> Result<()> {
        if self.workflow != self.frozen.workflow
            || self.digest != sha256_uri(&snapshot_bytes(&self.frozen)?)
        {
            return Err(fail("definition.changed"));
        }
        Ok(())
    }

    /// Explain the authored graph and host limits without input, outputs,
    /// runtime destinations or secret material.
    pub fn explain(&self) -> Result<Value> {
        self.check_integrity()?;
        let steps = graph_order(&self.workflow)
            .into_iter()
            .map(|id| {
                let step = &self.workflow.steps[id];
                let kind = match step {
                    Step::WaitUntil { .. } => "wait-until",
                    Step::WaitFor { .. } => "wait-for",
                    Step::Call { .. } => "call",
                    Step::Choose { .. } => "choose",
                    Step::Finish { .. } => "finish",
                };
                let mut item = serde_json::json!({"id":id,"kind":kind,"next":step.targets()});
                if let Some(mapping) = step.mapping() {
                    item["mapping"] = serde_json::json!(mapping);
                    if let Mapping::Function { arguments, .. } = mapping {
                        item["mapping"]["arity"] = serde_json::json!(arguments.len());
                    }
                }
                match step {
                    Step::Call { call, .. } => {
                        item["connection"] = serde_json::json!(call.connection);
                        item["operation"] = serde_json::json!(call.operation);
                        item["product"] = serde_json::json!(call.operation.product());
                        item["mutating"] = serde_json::json!(call.operation.is_mutating());
                        item["effect"] = serde_json::json!(call.operation.descriptor().effect);
                        item["recovery"] = serde_json::json!(call.operation.recovery());
                    }
                    Step::WaitFor {
                        wait_for,
                        timeout_seconds,
                        on_timeout,
                        ..
                    } => {
                        item["event"] = serde_json::json!(wait_for.id());
                        item["request"] = serde_json::json!(wait_for.request());
                        item["timeoutSeconds"] = serde_json::json!(timeout_seconds);
                        item["onTimeout"] = serde_json::json!(on_timeout);
                    }
                    Step::Choose { cases, .. } => item["cases"] = serde_json::json!(cases),
                    Step::Finish { finish, .. } => item["outcome"] = serde_json::json!(finish),
                    _ => {}
                }
                item
            })
            .collect::<Vec<_>>();
        Ok(
            serde_json::json!({"workflow":self.workflow.id,"version":self.workflow.version,"definitionDigest":self.digest,
            "start":self.workflow.start,"deadlineSeconds":parse_duration(&self.workflow.deadline)?.num_seconds(),
            "connections":self.workflow.connections,"outcomes":self.workflow.outcomes.keys().collect::<Vec<_>>(),"steps":steps,
            "limits":crate::functions::limits(),"interpreterAbi":self.frozen.interpreter_abi,"schemaAbi":self.frozen.schema_abi,"adapterAbi":self.frozen.adapter_abi,
            "networkAccess":false,"databaseAccess":false,"secretResolution":false,
            "recovery":"A run restores this exact snapshot. retry-same preserves a frozen command and cannot adopt edited mappings or repeat an uncertain hold-after-dispatch evaluation."}),
        )
    }

    pub fn snapshot(&self) -> Result<String> {
        self.check_integrity()?;
        String::from_utf8(snapshot_bytes(&self.frozen)?).map_err(|_| fail("definition.snapshot"))
    }

    pub fn validate_input(&self, input: &Value) -> Result<()> {
        self.check_integrity()?;
        check_value(input)?;
        if let Err(errors) = self.input_schema.validate(input) {
            let field = errors
                .into_iter()
                .next()
                .map(|error| format!("input{}", error.schema_path))
                .unwrap_or_else(|| "input".into());
            return Err(fail("definition.input").at("workflow.yaml", field)
                .suggest("Correct the input JSON to satisfy the named authored schema rule; rejected values are omitted."));
        }
        Ok(())
    }

    /// The first input schema rule a synthetic input breaks, for offline
    /// scenarios only.
    pub(crate) fn input_refusal(&self, input: &Value) -> Option<String> {
        schema_refusal(&self.input_schema, input)
    }

    pub fn validate_outcome(&self, outcome: &str, output: &Value) -> Result<()> {
        self.check_integrity()?;
        check_value(output)?;
        let schema = self
            .outcome_schemas
            .get(outcome)
            .ok_or_else(|| fail("definition.outcome"))?;
        if let Err(errors) = schema.validate(output) {
            let field = errors
                .into_iter()
                .next()
                .map(|error| format!("outcomes.{outcome}{}", error.schema_path))
                .unwrap_or_else(|| format!("outcomes.{outcome}"));
            return Err(fail("definition.outcome").at("workflow.yaml", field)
                .suggest("Correct the final output mapping to satisfy its authored schema; rejected values are omitted."));
        }
        Ok(())
    }

    pub fn evaluate(
        &self,
        name: &str,
        input: &Value,
        outputs: &BTreeMap<String, Value>,
    ) -> Result<Value> {
        self.evaluate_as(name, input, outputs, false)
    }

    /// Evaluate one step over synthetic scenario values. A refusal also names
    /// the class of the value the step's contract refused, the rule it broke,
    /// or the kind and position of a function failure, never the value. Only
    /// offline scenarios call this; a run's refusals carry fixed messages.
    pub(crate) fn evaluate_synthetic(
        &self,
        name: &str,
        input: &Value,
        outputs: &BTreeMap<String, Value>,
    ) -> Result<Value> {
        self.evaluate_as(name, input, outputs, true)
    }

    fn evaluate_as(
        &self,
        name: &str,
        input: &Value,
        outputs: &BTreeMap<String, Value>,
        synthetic: bool,
    ) -> Result<Value> {
        self.check_integrity()?;
        let step = self
            .workflow
            .steps
            .get(name)
            .ok_or_else(|| fail("mapping.unknown"))?;
        let mapping = step.mapping().ok_or_else(|| fail("mapping.unknown"))?;
        let field = format!("steps.{name}.{}", step.role());
        let value = match mapping {
            Mapping::Function {
                function,
                arguments,
            } => {
                let arguments = arguments
                    .iter()
                    .enumerate()
                    .map(|(index, reference)| {
                        resolve(reference, input, outputs).map_err(|error| {
                            error.at("workflow.yaml", format!("{field}.arguments[{index}]"))
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                self.functions
                    .evaluate(function, arguments, synthetic)
                    .map_err(|error| error.at("workflow.yaml", &field))?
            }
            Mapping::Fields { fields } => {
                let members = fields
                    .iter()
                    .map(|(member, reference)| {
                        resolve(reference, input, outputs)
                            .map(|value| (member.clone(), value.clone()))
                            .map_err(|error| {
                                error.at("workflow.yaml", format!("{field}.fields.{member}"))
                            })
                    })
                    .collect::<Result<serde_json::Map<_, _>>>()?;
                let value = Value::Object(members);
                check_value(&value).map_err(|error| error.at("workflow.yaml", &field))?;
                value
            }
            Mapping::Reference(reference) => resolve(reference, input, outputs)
                .map_err(|error| error.at("workflow.yaml", &field))?
                .clone(),
        };
        // Name the class of the synthetic value, never the value, and what
        // the step expected instead.
        let refused = |error: CoordinatorError, expected: &str| {
            if synthetic {
                CoordinatorError {
                    message: format!(
                        "{} returned a value of class {}; {expected}",
                        producer(mapping),
                        class(&value)
                    ),
                    ..error
                }
            } else {
                error
            }
        };
        // One authored mapping may serve several branches or step kinds. Only
        // the executing step determines the result's contract and diagnostic.
        match step {
            Step::WaitUntil { .. } => {
                parse_timestamp(&value).map_err(|error| {
                    refused(
                        error.at("workflow.yaml", &field),
                        "expected an RFC 3339 instant with an offset, such as 2026-01-01T00:00:00Z",
                    )
                })?;
            }
            Step::Call { call, .. } if !value.is_object() => {
                return Err(refused(
                    fail("mapping.call_shape").at("workflow.yaml", &field),
                    &format!(
                        "expected a JSON object for the {} input",
                        call.operation.as_str()
                    ),
                ))
            }
            Step::Choose { cases, .. }
                if !value
                    .as_str()
                    .is_some_and(|label| cases.contains_key(label)) =>
            {
                let labels = cases.keys().map(String::as_str).collect::<Vec<_>>();
                let refusal = refused(
                    fail("mapping.branch").at("workflow.yaml", &field),
                    &format!("expected one of the case labels: {}", labels.join(", ")),
                );
                return Err(if synthetic {
                    refusal.suggest(format!(
                        "Return one of the case labels from {}, or add a case for the label it returns.",
                        producer(mapping)
                    ))
                } else {
                    refusal
                });
            }
            Step::Finish { finish, .. } => {
                self.validate_outcome(finish, &value).map_err(|error| {
                    let detail = self
                        .outcome_schemas
                        .get(finish)
                        .and_then(|schema| schema_refusal(schema, &value))
                        .unwrap_or_default();
                    refused(
                        error.at("workflow.yaml", &field),
                        &format!("the {finish} outcome schema refuses it{detail}"),
                    )
                })?
            }
            _ => {}
        }
        Ok(value)
    }

    pub fn deadline_at(&self, admitted_at: DateTime<Utc>) -> Result<DateTime<Utc>> {
        self.check_integrity()?;
        admitted_at
            .checked_add_signed(parse_duration(&self.workflow.deadline)?)
            .ok_or_else(|| fail("definition.deadline"))
    }

    pub fn initial_due(
        &self,
        input: &Value,
        admitted_at: DateTime<Utc>,
    ) -> Result<Option<DateTime<Utc>>> {
        self.validate_input(input)?;
        match self.workflow.steps.get(&self.workflow.start) {
            Some(Step::WaitUntil { .. }) => {
                let due = parse_timestamp(&self.evaluate(
                    &self.workflow.start,
                    input,
                    &BTreeMap::new(),
                )?)?;
                Ok(Some(due.max(admitted_at)))
            }
            _ => Ok(None),
        }
    }
}

/// The value a reference names. Errors carry no value.
fn resolve<'a>(
    reference: &'a Reference,
    input: &'a Value,
    outputs: &'a BTreeMap<String, Value>,
) -> Result<&'a Value> {
    let (value, path) = match reference {
        Reference::Input { path } => (input, path),
        Reference::Step { step, path } => (
            outputs
                .get(step)
                .ok_or_else(|| fail("mapping.missing_output"))?,
            path,
        ),
        Reference::Literal { value } => return Ok(value),
    };
    match path {
        None => Ok(value),
        Some(path) => value.pointer(path).ok_or_else(|| fail("mapping.path")),
    }
}

/// What computed a mapping's value, as a refusal names it.
fn producer(mapping: &Mapping) -> String {
    match mapping {
        Mapping::Function { function, .. } => format!("function {function}"),
        Mapping::Fields { .. } => "the fields mapping".into(),
        Mapping::Reference(_) => "the reference".into(),
    }
}

/// The JSON class of a value, which a finding may name where it may not
/// repeat the value.
pub(crate) fn class(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(number) if number.is_i64() || number.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// The first rule a schema refuses a synthetic value by, and where in the
/// value it applies. Neither names the value.
pub(crate) fn schema_refusal(schema: &JSONSchema, value: &Value) -> Option<String> {
    let error = schema.validate(value).err()?.next()?;
    let at = error.instance_path.to_string();
    let rule = error.schema_path.to_string();
    Some(if at.is_empty() {
        format!(" by its rule {rule}")
    } else {
        format!(" at {at} by its rule {rule}")
    })
}

fn snapshot_bytes(snapshot: &Snapshot) -> Result<Vec<u8>> {
    let value = serde_json::to_value(snapshot).map_err(|_| fail("definition.snapshot"))?;
    let bytes = registry_platform_canonical_json::canonicalize_json(&value)
        .map_err(|_| fail("definition.canonical"))?;
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(fail("definition.snapshot_limit"));
    }
    Ok(bytes)
}

pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

/// The names a diagnostic offers as alternatives, in order.
pub(crate) fn listed<'a>(names: impl IntoIterator<Item = &'a str>) -> String {
    let names = names.into_iter().collect::<Vec<_>>();
    if names.is_empty() {
        "none".into()
    } else {
        names.join(", ")
    }
}

/// The operations the catalog offers for one product.
pub(crate) fn offered(product: &str) -> String {
    listed(
        crate::operations::descriptors()
            .iter()
            .filter(|operation| operation.product == product)
            .map(|operation| operation.id),
    )
}

/// Every independent refusal of a workflow's shape, names and graph. The
/// graph is walked only once start and every transition name a declared
/// step, since reachability and cycles mean nothing across a broken edge.
fn workflow_findings(flow: &Workflow) -> Vec<CoordinatorError> {
    let mut findings = Vec::new();
    for (field, size, minimum, maximum) in [
        ("steps", flow.steps.len(), 1, 64),
        ("connections", flow.connections.len(), 0, 16),
        ("outcomes", flow.outcomes.len(), 1, 64),
    ] {
        if !(minimum..=maximum).contains(&size) {
            findings.push(authored(
                "definition.shape",
                field,
                &format!("expected {minimum} to {maximum} entries"),
                "Adjust the number of entries within the stated bound.",
            ));
        }
    }
    if !valid_name(&flow.version) {
        findings.push(authored(
            "definition.shape",
            "version",
            "expected 1 to 64 ASCII letters, digits, hyphens or underscores",
            "Use a bounded version identifier, such as v1.",
        ));
    }
    let steps = listed(flow.steps.keys().map(String::as_str));
    let mut broken = false;
    if !flow.steps.contains_key(&flow.start) {
        broken = true;
        findings.push(authored(
            "definition.shape",
            "start",
            &format!("start names step {}, which is not declared", flow.start),
            &format!("Set start to one of the declared steps: {steps}."),
        ));
    }
    if flow.api_version != API_VERSION
        || flow.kind != "Workflow"
        || !valid_name(&flow.id)
        || flow.functions != "functions.rhai"
    {
        findings.push(fail("definition.shape"));
    }
    if let Err(error) = parse_duration(&flow.deadline) {
        findings.push(error.at("workflow.yaml", "deadline"));
    }
    for (name, kind) in &flow.connections {
        if !valid_name(name)
            || !crate::operations::descriptors()
                .iter()
                .any(|operation| operation.product == kind)
        {
            findings.push(fail("definition.connection").at("workflow.yaml", "connections"));
        }
    }
    let connections = listed(flow.connections.keys().map(String::as_str));
    let declared_outcomes = listed(flow.outcomes.keys().map(String::as_str));
    let mut incoming: Incoming = flow.steps.keys().map(|k| (k.as_str(), vec![])).collect();
    let mut outcomes = BTreeSet::new();
    for (name, step) in &flow.steps {
        if !valid_name(name) || name == "input" {
            broken = true;
            findings.push(fail("definition.step"));
            continue;
        }
        for (member, target) in step.edges() {
            match incoming.get_mut(target) {
                Some(sources) => sources.push((name, member)),
                None => {
                    broken = true;
                    findings.push(authored(
                        "definition.target",
                        &format!("steps.{name}.{member}"),
                        &format!("the transition names step {target}, which is not declared"),
                        &format!("Point the transition at one of the declared steps: {steps}."),
                    ));
                }
            }
        }
        match step {
            Step::WaitFor {
                wait_for,
                timeout_seconds,
                ..
            } => findings.extend(wait_findings(flow, name, wait_for, *timeout_seconds)),
            Step::Call { call, .. } => match flow.connections.get(&call.connection) {
                None => findings.push(authored(
                    "definition.connection",
                    &format!("steps.{name}.call.connection"),
                    &format!(
                        "connection {} is not declared; the declared connections are {connections}",
                        call.connection
                    ),
                    &format!(
                        "Name one of the declared connections, or declare {} under connections.",
                        call.connection
                    ),
                )),
                Some(kind) if kind != call.operation.product() => findings.push(authored(
                    "definition.operation",
                    &format!("steps.{name}.call.operation"),
                    &format!(
                        "operation {} belongs to {}, but connection {} is a {kind} connection, which offers {}",
                        call.operation.as_str(),
                        call.operation.product(),
                        call.connection,
                        offered(kind)
                    ),
                    &format!(
                        "Name an operation {kind} offers, or call a {} connection.",
                        call.operation.product()
                    ),
                )),
                Some(_) => {}
            },
            Step::Choose { cases, .. }
                if cases.is_empty() || cases.len() > 32 || !cases.keys().all(|k| valid_name(k)) =>
            {
                findings.push(
                    fail("definition.cases").at("workflow.yaml", format!("steps.{name}.cases")),
                )
            }
            Step::Finish { finish, .. } => {
                if flow.outcomes.contains_key(finish) {
                    outcomes.insert(finish);
                } else {
                    findings.push(authored(
                        "definition.outcome",
                        &format!("steps.{name}.finish"),
                        &format!(
                            "step {name} finishes with outcome {finish}, which outcomes does not declare; the declared outcomes are {declared_outcomes}"
                        ),
                        &format!(
                            "Name one of the declared outcomes, or declare {finish} under outcomes with its schema."
                        ),
                    ));
                }
            }
            _ => {}
        }
    }
    for outcome in flow.outcomes.keys() {
        if !valid_name(outcome) {
            findings.push(fail("definition.outcome").at("workflow.yaml", "outcomes"));
        } else if !outcomes.contains(outcome) {
            findings.push(authored(
                "definition.outcome",
                &format!("outcomes.{outcome}"),
                &format!("no finish step ends with outcome {outcome}"),
                &format!("Finish a step with outcome {outcome}, or remove it from outcomes."),
            ));
        }
    }
    if !broken {
        findings.extend(graph_findings(flow, &incoming));
    }
    findings
}

/// Each step's incoming transitions: the step they leave and the authored
/// member that holds them.
type Incoming<'a> = BTreeMap<&'a str, Vec<(&'a str, &'static str)>>;

/// The steps that submit a review request a wait-for step may wait on.
fn review_requests(flow: &Workflow) -> String {
    listed(flow.steps.iter().filter_map(|(name, step)| match step {
        Step::Call { call, .. } if call.operation == Operation::SubmitReviewRequest => {
            Some(name.as_str())
        }
        _ => None,
    }))
}

/// Whether `request` is a step whose output a wait for `event` correlates
/// with.
fn correlates(flow: &Workflow, event: &WaitEvent) -> bool {
    match event {
        WaitEvent::ReviewResult { request } => matches!(
            flow.steps.get(request),
            Some(Step::Call { call, .. }) if call.operation == Operation::SubmitReviewRequest
        ),
    }
}

/// A wait-for step names the call whose accepted request it correlates with,
/// and a timeout a run can reach before its deadline. Whether the request
/// precedes the wait on every route is a graph finding.
fn wait_findings(
    flow: &Workflow,
    name: &str,
    event: &WaitEvent,
    timeout: u32,
) -> Vec<CoordinatorError> {
    let mut findings = Vec::new();
    let request = event.request();
    let field = format!("steps.{name}.waitFor.request");
    let requests = review_requests(flow);
    let action = format!(
        "Name the call step that submits the review request this step waits for; the steps that call submit-review-request are {requests}."
    );
    match flow.steps.get(request) {
        None => findings.push(authored(
            "definition.wait",
            &field,
            &format!(
                "request names step {request}, which is not declared; the steps that call submit-review-request are {requests}"
            ),
            &action,
        )),
        Some(_) if !correlates(flow, event) => findings.push(authored(
            "definition.wait",
            &field,
            &format!(
                "request names step {request}, which does not call submit-review-request; the steps that call submit-review-request are {requests}"
            ),
            &action,
        )),
        Some(_) => {}
    }
    let deadline = parse_duration(&flow.deadline)
        .ok()
        .map(|deadline| deadline.num_seconds());
    if !(1..=MAXIMUM_WAIT_SECONDS).contains(&timeout) {
        findings.push(authored(
            "definition.wait",
            &format!("steps.{name}.timeoutSeconds"),
            "expected 1 to 31536000 seconds",
            "Set timeoutSeconds to a bounded wait, at most one year.",
        ));
    } else if let Some(deadline) = deadline.filter(|deadline| i64::from(timeout) >= *deadline) {
        // A wait that starts at admission still reaches the deadline first, so
        // its run would expire rather than take the timeout route.
        findings.push(authored(
            "definition.wait",
            &format!("steps.{name}.timeoutSeconds"),
            &format!(
                "the wait times out after {timeout} seconds, which is not shorter than the {deadline}-second run deadline"
            ),
            "Set timeoutSeconds below deadlineSeconds so a run can reach its timeout, or raise deadlineSeconds.",
        ));
    }
    findings
}

/// Reachability, finiteness and reference dominance over a graph whose
/// transitions all name declared steps.
/// Steps in the order a reader follows them from start: each step after
/// every step that leads to it, and a choice's branches in case order. A
/// checked workflow reaches every step without a cycle; any other step
/// follows in name order.
fn graph_order(flow: &Workflow) -> Vec<&str> {
    let mut pending = flow
        .steps
        .keys()
        .map(|name| (name.as_str(), 0_usize))
        .collect::<BTreeMap<_, _>>();
    for next in flow.steps.values().flat_map(Step::targets) {
        if let Some(count) = pending.get_mut(next) {
            *count += 1;
        }
    }
    let mut order = Vec::with_capacity(flow.steps.len());
    let mut ready = std::collections::VecDeque::from([flow.start.as_str()]);
    while let Some(name) = ready.pop_front() {
        order.push(name);
        for next in flow.steps[name].targets() {
            if let Some(count) = pending.get_mut(next) {
                *count -= 1;
                if *count == 0 {
                    ready.push_back(next);
                }
            }
        }
    }
    for name in flow.steps.keys() {
        if !order.contains(&name.as_str()) {
            order.push(name);
        }
    }
    order
}

fn graph_findings<'a>(flow: &'a Workflow, incoming: &Incoming<'a>) -> Vec<CoordinatorError> {
    let mut findings = Vec::new();
    let mut reachable = BTreeSet::from([flow.start.as_str()]);
    let mut frontier = vec![flow.start.as_str()];
    while let Some(name) = frontier.pop() {
        for next in flow.steps[name].targets() {
            if reachable.insert(next) {
                frontier.push(next);
            }
        }
    }
    for name in flow.steps.keys() {
        if !reachable.contains(name.as_str()) {
            findings.push(authored(
                "definition.unreachable",
                &format!("steps.{name}"),
                &format!(
                    "step {name} is not reachable from start step {}",
                    flow.start
                ),
                &format!("Point a transition at {name}, or remove the step if no route needs it."),
            ));
        }
    }
    // Topological traversal proves finiteness. The outputs available at a
    // step are those every incoming transition carries: what was available at
    // its source, plus the source's own output unless the transition is a
    // wait's timeout, which leaves the wait without one. A reference therefore
    // exists on every route. Only reachable predecessors take part: no route
    // arrives from the others.
    let predecessors = |name: &str| {
        incoming[name]
            .iter()
            .copied()
            .filter(|(source, _)| reachable.contains(source))
            .collect::<Vec<_>>()
    };
    let mut pending = reachable
        .iter()
        .map(|name| (*name, predecessors(name).len()))
        .collect::<BTreeMap<_, _>>();
    let mut ready = if pending[flow.start.as_str()] == 0 {
        vec![flow.start.as_str()]
    } else {
        vec![]
    };
    let mut available: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    while let Some(name) = ready.pop() {
        let outputs = predecessors(name)
            .into_iter()
            .map(|(source, member)| {
                let mut carried = available[source].clone();
                if member != "onTimeout" {
                    carried.insert(source);
                }
                carried
            })
            .reduce(|left, right| left.intersection(&right).copied().collect())
            .unwrap_or_default();
        if let Some(mapping) = flow.steps[name].mapping() {
            if let Err(error) = validate_mapping(flow, name, mapping, &outputs) {
                findings.push(error);
            }
        }
        if let Step::WaitFor { wait_for, .. } = &flow.steps[name] {
            if correlates(flow, wait_for) && !outputs.contains(wait_for.request()) {
                findings.push(authored(
                    "definition.wait",
                    &format!("steps.{name}.waitFor.request"),
                    &format!(
                        "the review request of step {} is not submitted on every route to this step",
                        wait_for.request()
                    ),
                    "Move the submitting call before the branch, so every route to the wait submits the request it waits for.",
                ));
            }
        }
        available.insert(name, outputs);
        for next in flow.steps[name].targets() {
            if let Some(count) = pending.get_mut(next) {
                *count -= 1;
                if *count == 0 {
                    ready.push(next);
                }
            }
        }
    }
    if available.len() != reachable.len() {
        findings.push(cycle(flow));
    }
    findings
}

/// The first cycle a depth-first walk from start meets, named step by step
/// and placed at the transition that closes it.
fn cycle(flow: &Workflow) -> CoordinatorError {
    let mut route = vec![flow.start.as_str()];
    let mut finished = BTreeSet::new();
    let mut branches = vec![flow.steps[&flow.start].edges().into_iter()];
    while let Some(edges) = branches.last_mut() {
        let Some((member, next)) = edges.next() else {
            if let Some(done) = route.pop() {
                finished.insert(done);
            }
            branches.pop();
            continue;
        };
        if let Some(index) = route.iter().position(|name| *name == next) {
            let closing = route[route.len() - 1];
            let mut members = route[index..].to_vec();
            members.push(next);
            return authored(
                "definition.cycle",
                &format!("steps.{closing}.{member}"),
                &format!("the steps form a cycle: {}", members.join(" -> ")),
                "Point one transition in the cycle at a step outside it: a workflow is a finite graph that runs each step at most once.",
            );
        }
        if !finished.contains(next) {
            route.push(next);
            branches.push(flow.steps[next].edges().into_iter());
        }
    }
    fail("definition.cycle").at("workflow.yaml", "steps")
}

/// Check one mapping's form for its step, its bounds, and that each step
/// reference names a call or wait whose output every route to this step
/// carries.
fn validate_mapping(
    flow: &Workflow,
    name: &str,
    mapping: &Mapping,
    available: &BTreeSet<&str>,
) -> Result<()> {
    let step = &flow.steps[name];
    let base = format!("steps.{name}.{}", step.role());
    match (step, mapping) {
        (Step::Call { .. } | Step::Finish { .. }, Mapping::Reference(_)) => {
            return Err(authored(
                "mapping.reference",
                &base,
                "a call input or finish output is a function or fields, not a single reference",
                "Build the value with fields, or pass the reference to a function.",
            ))
        }
        (Step::WaitUntil { .. } | Step::Choose { .. }, Mapping::Fields { .. }) => {
            return Err(authored(
                "mapping.reference",
                &base,
                "waitUntil and choose take a function or a single reference, not fields",
                "Select the instant or label with one reference, or compute it in a function.",
            ))
        }
        (_, Mapping::Function { function, .. }) if !valid_name(function) => {
            return Err(fail("mapping.function").at("workflow.yaml", format!("steps.{name}")))
        }
        (_, Mapping::Fields { fields })
            if fields.len() > MAXIMUM_FIELDS || !fields.keys().all(|key| valid_field_name(key)) =>
        {
            return Err(authored(
                "mapping.reference",
                &format!("{base}.fields"),
                "expected at most 64 fields named by ASCII letters, digits, hyphens or underscores, starting with a letter",
                "Rename or remove fields, or build a larger value in a function.",
            ))
        }
        _ => {}
    }
    for (member, reference) in mapping.references() {
        let field = format!("{base}{member}");
        let (step, path) = match reference {
            Reference::Input { path } => (None, path),
            Reference::Step { step, path } => (Some(step), path),
            Reference::Literal { value } => {
                check_value(value).map_err(|_| {
                    authored(
                        "mapping.literal",
                        &format!("{field}.value"),
                        "the literal exceeds the structured value bounds",
                        "Shorten the literal or build the value in a function; literals hold at most 32 levels, 4096 nodes, 16384-byte strings, 131072 canonical bytes, and integers within 2^53 - 1.",
                    )
                })?;
                continue;
            }
        };
        if path.as_deref().is_some_and(|path| !valid_pointer(path)) {
            return Err(authored(
                "mapping.reference",
                &format!("{field}.path"),
                "expected a JSON Pointer of at most 256 characters, such as /member/0",
                "Start the path with /, write ~0 for ~ and ~1 for / inside a member name, or omit path to use the whole value.",
            ));
        }
        if let Some(prior) = step {
            if !available.contains(prior.as_str())
                || !matches!(
                    flow.steps.get(prior),
                    Some(Step::Call { .. } | Step::WaitFor { .. })
                )
            {
                return Err(authored("mapping.dominance", &field, "the referenced step output is not available on every incoming path", "Move the call or wait before the branch, read a wait's output only after it continues with next, or pass a value available on every route to this step."));
            }
        }
    }
    Ok(())
}

fn parse_duration(text: &str) -> Result<Duration> {
    let end = text
        .len()
        .checked_sub(1)
        .ok_or_else(|| fail("definition.deadline"))?;
    let digits = text.get(..end).ok_or_else(|| fail("definition.deadline"))?;
    let unit = text.get(end..).ok_or_else(|| fail("definition.deadline"))?;
    let amount = digits
        .parse::<i64>()
        .map_err(|_| fail("definition.deadline"))?;
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return Err(fail("definition.deadline")),
    };
    let seconds = amount
        .checked_mul(multiplier)
        .filter(|s| *s > 0 && *s <= 31_536_000)
        .ok_or_else(|| fail("definition.deadline"))?;
    Ok(Duration::seconds(seconds))
}

pub(crate) fn parse_timestamp(value: &Value) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value.as_str().ok_or_else(|| fail("mapping.timestamp"))?)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| fail("mapping.timestamp"))
}

struct NoRemoteSchemas;
impl SchemaResolver for NoRemoteSchemas {
    fn resolve(
        &self,
        _: &Value,
        _: &url::Url,
        _: &str,
    ) -> std::result::Result<Arc<Value>, SchemaResolverError> {
        Err(std::io::Error::other("external schema resolution is disabled").into())
    }
}

pub(crate) fn compile_schema(schema: &Value) -> Result<JSONSchema> {
    fn local(value: &Value, depth: usize) -> bool {
        if depth > 32 {
            return false;
        }
        match value {
            Value::Object(fields) => fields.iter().all(|(k, v)| {
                if matches!(k.as_str(), "$ref" | "$dynamicRef" | "$recursiveRef") {
                    v.as_str().is_some_and(|s| s.starts_with('#'))
                } else if k == "$id" {
                    false
                } else {
                    local(v, depth + 1)
                }
            }),
            Value::Array(items) => items.iter().all(|v| local(v, depth + 1)),
            _ => true,
        }
    }
    check_value(schema)?;
    if !(schema.is_object() || schema.is_boolean()) || !local(schema, 0) {
        return Err(fail("definition.schema"));
    }
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .should_ignore_unknown_formats(false)
        // jsonschema 0.18 only registers UUID natively for draft 2019-09.
        // Keep the authored 2020-12 boundary explicit and versioned.
        .with_format("uuid", |value| uuid::Uuid::parse_str(value).is_ok())
        .with_resolver(NoRemoteSchemas)
        .compile(schema)
        .map_err(|_| fail("definition.schema"))
}

fn read_text(path: &Path, maximum: usize) -> Result<String> {
    let bytes = read_bytes(path, maximum)?;
    if bytes.len() > maximum {
        return Err(fail("definition.file").at(path, ""));
    }
    String::from_utf8(bytes).map_err(|_| fail("definition.read").at(path, ""))
}

fn read_bytes(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| fail("definition.read").at(path, ""))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(fail("definition.file").at(path, ""));
    }
    let file = std::fs::File::open(path).map_err(|_| fail("definition.read").at(path, ""))?;
    let mut bytes = Vec::new();
    // Keep one lookahead byte so the owning decoder can diagnose its bound.
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| fail("definition.read").at(path, ""))?;
    Ok(bytes)
}

fn fail(code: &'static str) -> CoordinatorError {
    if code == "definition.snapshot_limit" {
        return CoordinatorError::new(code, "the workflow snapshot exceeds the 393216-byte limit")
            .suggest("Reduce workflow/schema annotations or functions.rhai source until the canonical snapshot is at most 393216 bytes, then rerun check and package. Admitted runs keep their original snapshot.");
    }
    CoordinatorError::new(code, match code {
        "definition.cycle" => "the graph contains a cycle",
        "definition.unreachable" => "a step is not reachable from start",
        "definition.deadline" => "deadline must be a positive s, m, h or d duration no longer than 365 days",
        "mapping.branch" => "the function did not return a declared branch label",
        "mapping.timestamp" => "waitUntil did not return an RFC 3339 instant",
        "mapping.missing_output" => "a declared prior call output is absent",
        "mapping.path" => "the reference path names no member of the value it reads",
        "mapping.call_shape" => "the call input function did not return an object",
        "definition.input" => "the start input does not satisfy its authored schema",
        "definition.outcome" => "the final output does not satisfy the declared outcome schema",
        "definition.schema" => "the schema is invalid or uses an unsupported format or external reference",
        _ => "the workflow definition or mapping was refused",
    }).suggest("Inspect the authored field and function, correct the definition, then rerun check. Admitted runs keep their original snapshot.")
}

pub(crate) fn authored(
    code: &'static str,
    field: &str,
    message: &str,
    action: &str,
) -> CoordinatorError {
    CoordinatorError::new(code, message)
        .at("workflow.yaml", field)
        .suggest(action)
}
