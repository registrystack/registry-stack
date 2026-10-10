// SPDX-License-Identifier: Apache-2.0
//! Closed, finite workflow authoring and immutable execution snapshots.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read as _,
    path::Path,
    sync::Arc,
};

use chrono::{DateTime, Duration, Utc};
use jsonschema::{Draft, JSONSchema, SchemaResolver, SchemaResolverError};
use registry_platform_config::sha256_uri;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    functions::{check_value, Functions, INTERPRETER_ABI},
    operations::OperationIdentity,
    protocol::Operation,
    PocError, Result,
};

pub const SNAPSHOT_API_VERSION: &str =
    "id.registrystack.org/formats/coordinator/definition-snapshot/v1alpha1";
pub const SNAPSHOT_KIND: &str = "CoordinatorDefinitionSnapshot";
const ADAPTER_ABI: &str = "coordinator/product-operations/v4";
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Mapping {
    pub function: String,
    pub arguments: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Call {
    pub connection: String,
    pub operation: Operation,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged, deny_unknown_fields)]
pub enum Step {
    WaitUntil {
        #[serde(rename = "waitUntil")]
        wait_until: Mapping,
        next: String,
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
    fn targets(&self) -> Vec<&str> {
        match self {
            Self::WaitUntil { next, .. } | Self::Call { next, .. } => vec![next],
            Self::Choose { cases, .. } => cases.values().map(String::as_str).collect(),
            Self::Finish { .. } => vec![],
        }
    }
    fn mapping(&self) -> Option<&Mapping> {
        match self {
            Self::WaitUntil { wait_until, .. } => Some(wait_until),
            Self::Call { input, .. } => Some(input),
            Self::Choose { choose, .. } => Some(choose),
            Self::Finish { output, .. } => output.as_ref(),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Snapshot {
    api_version: String,
    kind: String,
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

impl Definition {
    pub fn load(project: &Path) -> Result<Self> {
        let project = project
            .canonicalize()
            .map_err(|_| fail("coordinator.definition.read").at(project, ""))?;
        let path = project.join("workflow.yaml");
        let bytes = read_bytes(&path, MAX_DOCUMENT_BYTES)?;
        let (workflow, document) = crate::authoring::parse_project(&path, &bytes)?;
        // The PoC deliberately has one local source file, rather than an import
        // loader or arbitrary path vocabulary.
        if workflow.functions != "functions.rhai" {
            return Err(crate::authoring::positioned(
                &document,
                fail("coordinator.definition.functions-file").at(&path, "functions"),
            ));
        }
        let source = read_text(&project.join(&workflow.functions), 65_536).map_err(|error| {
            let exit = error.exit_code;
            crate::authoring::positioned(&document, error.at(&path, "functions")).with_exit(exit)
        })?;
        Self::restore(Snapshot {
            api_version: SNAPSHOT_API_VERSION.into(),
            kind: SNAPSHOT_KIND.into(),
            operation_identities: operation_identities(&workflow),
            workflow,
            source,
            adapter_abi: ADAPTER_ABI.into(),
            interpreter_abi: INTERPRETER_ABI.into(),
            schema_abi: SCHEMA_ABI.into(),
        })
        .map_err(|error| crate::authoring::positioned(&document, error))
    }

    pub fn from_snapshot(snapshot: &str) -> Result<Self> {
        if snapshot.len() > MAX_SNAPSHOT_BYTES {
            return Err(fail("coordinator.definition.snapshot-limit"));
        }
        let value = registry_platform_canonical_json::parse_json_strict(snapshot.as_bytes())
            .map_err(|_| fail("coordinator.definition.snapshot"))?;
        let frozen =
            serde_json::from_value(value).map_err(|_| fail("coordinator.definition.snapshot"))?;
        Self::restore(frozen)
    }

    fn restore(frozen: Snapshot) -> Result<Self> {
        if frozen.api_version != SNAPSHOT_API_VERSION || frozen.kind != SNAPSHOT_KIND {
            return Err(fail("coordinator.definition.snapshot"));
        }
        if frozen.adapter_abi != ADAPTER_ABI
            || frozen.operation_identities != operation_identities(&frozen.workflow)
            || !frozen
                .operation_identities
                .iter()
                .all(OperationIdentity::matches_registered)
            || frozen.interpreter_abi != INTERPRETER_ABI
            || frozen.schema_abi != SCHEMA_ABI
        {
            return Err(fail("coordinator.definition.abi"));
        }
        validate_workflow(&frozen.workflow)?;
        let mappings = frozen
            .workflow
            .steps
            .values()
            .filter_map(Step::mapping)
            .collect::<Vec<_>>();
        let functions = Functions::compile(&frozen.source, &mappings)?;
        let input_schema = Arc::new(
            compile_schema(&frozen.workflow.input)
                .map_err(|error| error.at("workflow.yaml", "input"))?,
        );
        let outcome_schemas: BTreeMap<String, Arc<JSONSchema>> = frozen
            .workflow
            .outcomes
            .iter()
            .map(|(id, schema)| {
                Ok((
                    id.clone(),
                    Arc::new(
                        compile_schema(schema)
                            .map_err(|error| error.at("workflow.yaml", format!("outcomes.{id}")))?,
                    ),
                ))
            })
            .collect::<Result<_>>()?;
        for step in frozen.workflow.steps.values() {
            if let Step::Finish {
                finish,
                output: None,
            } = step
            {
                if !outcome_schemas[finish].is_valid(&Value::Null) {
                    return Err(fail("coordinator.definition.outcome"));
                }
            }
        }
        let bytes = snapshot_bytes(&frozen)?;
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
            return Err(fail("coordinator.definition.changed"));
        }
        Ok(())
    }

    /// Explain the authored graph and host limits without input, outputs,
    /// runtime destinations or secret material.
    pub fn explain(&self) -> Result<Value> {
        self.check_integrity()?;
        let steps = self.workflow.steps.iter().map(|(id, step)| {
            let kind = match step { Step::WaitUntil {..} => "wait-until", Step::Call {..} => "call", Step::Choose {..} => "choose", Step::Finish {..} => "finish" };
            let mut item = serde_json::json!({"id":id,"kind":kind,"next":step.targets()});
            if let Some(mapping) = step.mapping() {
                let arguments = mapping.arguments.iter().map(|reference| {
                    if reference == "input" { serde_json::json!({"type":"input"}) }
                    else { serde_json::json!({"type":"step", "step":reference.strip_suffix(".output").unwrap_or(reference)}) }
                }).collect::<Vec<_>>();
                item["mapping"] = serde_json::json!({"function":mapping.function,"arguments":arguments,"arity":mapping.arguments.len()});
            }
            match step {
                Step::Call {call,..} => {item["connection"]=serde_json::json!(call.connection);item["operation"]=serde_json::json!(call.operation);item["product"]=serde_json::json!(call.operation.product());item["mutating"]=serde_json::json!(call.operation.is_mutating());item["effect"]=serde_json::json!(call.operation.descriptor().effect);item["recovery"]=serde_json::json!(call.operation.recovery());},
                Step::Choose {cases,..} => item["cases"]=serde_json::json!(cases),
                Step::Finish {finish,..} => item["outcome"]=serde_json::json!(finish),
                _ => {}
            }
            item
        }).collect::<Vec<_>>();
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
        String::from_utf8(snapshot_bytes(&self.frozen)?)
            .map_err(|_| fail("coordinator.definition.snapshot"))
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
            return Err(fail("coordinator.definition.input").at("workflow.yaml", field)
                .suggest("Correct the input JSON to satisfy the named authored schema rule; rejected values are omitted."));
        }
        Ok(())
    }

    pub fn validate_outcome(&self, outcome: &str, output: &Value) -> Result<()> {
        self.check_integrity()?;
        check_value(output)?;
        let schema = self
            .outcome_schemas
            .get(outcome)
            .ok_or_else(|| fail("coordinator.definition.outcome"))?;
        if let Err(errors) = schema.validate(output) {
            let field = errors
                .into_iter()
                .next()
                .map(|error| format!("outcomes.{outcome}{}", error.schema_path))
                .unwrap_or_else(|| format!("outcomes.{outcome}"));
            return Err(fail("coordinator.definition.outcome").at("workflow.yaml", field)
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
        self.check_integrity()?;
        let step = self
            .workflow
            .steps
            .get(name)
            .ok_or_else(|| fail("coordinator.mapping.unknown"))?;
        let mapping = step
            .mapping()
            .ok_or_else(|| fail("coordinator.mapping.unknown"))?;
        let arguments = mapping
            .arguments
            .iter()
            .map(|reference| {
                if reference == "input" {
                    return Ok(input);
                }
                let step = reference
                    .strip_suffix(".output")
                    .ok_or_else(|| fail("coordinator.mapping.reference"))?;
                outputs
                    .get(step)
                    .ok_or_else(|| fail("coordinator.mapping.missing-output"))
            })
            .collect::<Result<Vec<_>>>()?;
        let role = match step {
            Step::WaitUntil { .. } => "waitUntil",
            Step::Call { .. } => "input",
            Step::Choose { .. } => "choose",
            Step::Finish { .. } => "output",
        };
        let field = format!("steps.{name}.{role}");
        let value = self
            .functions
            .evaluate(&mapping.function, arguments)
            .map_err(|error| error.at("workflow.yaml", &field))?;
        // One authored mapping may serve several branches or step kinds. Only
        // the executing step determines the result's contract and diagnostic.
        match step {
            Step::WaitUntil { .. } => {
                parse_timestamp(&value).map_err(|error| error.at("workflow.yaml", &field))?;
            }
            Step::Call { .. } if !value.is_object() => {
                return Err(fail("coordinator.mapping.call-shape").at("workflow.yaml", &field))
            }
            Step::Choose { cases, .. }
                if !value
                    .as_str()
                    .is_some_and(|label| cases.contains_key(label)) =>
            {
                return Err(fail("coordinator.mapping.branch").at("workflow.yaml", &field))
            }
            Step::Finish { finish, .. } => self
                .validate_outcome(finish, &value)
                .map_err(|error| error.at("workflow.yaml", &field))?,
            _ => {}
        }
        Ok(value)
    }

    pub fn deadline_at(&self, admitted_at: DateTime<Utc>) -> Result<DateTime<Utc>> {
        self.check_integrity()?;
        admitted_at
            .checked_add_signed(parse_duration(&self.workflow.deadline)?)
            .ok_or_else(|| fail("coordinator.definition.deadline"))
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

fn snapshot_bytes(snapshot: &Snapshot) -> Result<Vec<u8>> {
    let value =
        serde_json::to_value(snapshot).map_err(|_| fail("coordinator.definition.snapshot"))?;
    let bytes = registry_platform_canonical_json::canonicalize_json(&value)
        .map_err(|_| fail("coordinator.definition.canonical"))?;
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(fail("coordinator.definition.snapshot-limit"));
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

fn validate_workflow(flow: &Workflow) -> Result<()> {
    for (field, size, minimum, maximum) in [
        ("steps", flow.steps.len(), 1, 64),
        ("connections", flow.connections.len(), 0, 16),
        ("outcomes", flow.outcomes.len(), 1, 64),
    ] {
        if !(minimum..=maximum).contains(&size) {
            return Err(authored(
                "coordinator.definition.shape",
                field,
                &format!("expected {minimum} to {maximum} entries"),
                "Adjust the number of entries within the stated bound.",
            ));
        }
    }
    if !valid_name(&flow.version) {
        return Err(authored(
            "coordinator.definition.shape",
            "version",
            "expected 1 to 64 ASCII letters, digits, hyphens or underscores",
            "Use a bounded version identifier, such as v1.",
        ));
    }
    if !flow.steps.contains_key(&flow.start) {
        return Err(authored(
            "coordinator.definition.shape",
            "start",
            "start does not name a declared step",
            "Set start to one declared step ID.",
        ));
    }
    if !valid_name(&flow.id)
        || flow.functions != "functions.rhai"
        || !flow.steps.contains_key(&flow.start)
    {
        return Err(fail("coordinator.definition.shape"));
    }
    parse_duration(&flow.deadline).map_err(|error| error.at("workflow.yaml", "deadline"))?;
    for (name, kind) in &flow.connections {
        if !valid_name(name)
            || !crate::operations::descriptors()
                .iter()
                .any(|operation| operation.product == kind)
        {
            return Err(
                fail("coordinator.definition.connection").at("workflow.yaml", "connections")
            );
        }
    }
    let mut incoming: BTreeMap<&str, Vec<&str>> =
        flow.steps.keys().map(|k| (k.as_str(), vec![])).collect();
    let mut outcomes = BTreeSet::new();
    for (name, step) in &flow.steps {
        if !valid_name(name) || name == "input" {
            return Err(fail("coordinator.definition.step"));
        }
        for target in step.targets() {
            incoming
                .get_mut(target)
                .ok_or_else(|| {
                    authored(
                        "coordinator.definition.target",
                        &format!(
                            "steps.{name}.{}",
                            if matches!(step, Step::Choose { .. }) {
                                "cases"
                            } else {
                                "next"
                            }
                        ),
                        "the transition does not name a declared step",
                        "Point the transition at a step declared under steps.",
                    )
                })?
                .push(name);
        }
        match step {
            Step::Call { call, .. } => {
                let kind = flow.connections.get(&call.connection).ok_or_else(|| {
                    fail("coordinator.definition.connection")
                        .at("workflow.yaml", format!("steps.{name}.call.connection"))
                })?;
                if kind != call.operation.product() {
                    return Err(fail("coordinator.definition.operation")
                        .at("workflow.yaml", format!("steps.{name}.call.operation")));
                }
            }
            Step::Choose { cases, .. }
                if cases.is_empty() || cases.len() > 32 || !cases.keys().all(|k| valid_name(k)) =>
            {
                return Err(fail("coordinator.definition.cases")
                    .at("workflow.yaml", format!("steps.{name}.cases")))
            }
            Step::Finish { finish, .. } => {
                if !flow.outcomes.contains_key(finish) {
                    return Err(fail("coordinator.definition.outcome"));
                }
                outcomes.insert(finish);
            }
            _ => {}
        }
    }
    if outcomes.len() != flow.outcomes.len() || !flow.outcomes.keys().all(|k| valid_name(k)) {
        return Err(fail("coordinator.definition.outcome"));
    }
    // Topological traversal proves finiteness. Dominators are the intersection
    // of predecessors' dominators, so a reference exists on every route.
    let mut pending = incoming
        .iter()
        .map(|(k, v)| (*k, v.len()))
        .collect::<BTreeMap<_, _>>();
    let mut ready = pending
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(k, _)| *k)
        .collect::<Vec<_>>();
    let mut dominators: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut visited = BTreeSet::new();
    while let Some(name) = ready.pop() {
        let predecessors = &incoming[name];
        let mut dominates = if let Some(first) = predecessors.first() {
            dominators[first].clone()
        } else {
            if name != flow.start {
                return Err(fail("coordinator.definition.unreachable")
                    .at("workflow.yaml", format!("steps.{name}")));
            }
            BTreeSet::new()
        };
        for predecessor in predecessors.iter().skip(1) {
            dominates = dominates
                .intersection(&dominators[predecessor])
                .copied()
                .collect();
        }
        if let Some(mapping) = flow.steps[name].mapping() {
            if !valid_name(&mapping.function) {
                return Err(fail("coordinator.mapping.function")
                    .at("workflow.yaml", format!("steps.{name}")));
            }
            for (index, reference) in mapping.arguments.iter().enumerate() {
                if reference == "input" {
                    continue;
                }
                let role = match &flow.steps[name] {
                    Step::WaitUntil { .. } => "waitUntil",
                    Step::Call { .. } => "input",
                    Step::Choose { .. } => "choose",
                    Step::Finish { .. } => "output",
                };
                let field = format!("steps.{name}.{role}.arguments[{index}]");
                let prior = reference
                    .strip_suffix(".output")
                    .ok_or_else(|| authored("coordinator.mapping.reference", &field, "the argument is not a whole-value reference", "Use input or a preceding call's step-id.output; select fields inside the Rhai function."))?;
                if !dominates.contains(prior)
                    || !matches!(flow.steps.get(prior), Some(Step::Call { .. }))
                {
                    return Err(authored("coordinator.mapping.dominance", &field, "the referenced call output is not available on every incoming path", "Move the call before the branch or pass a value available on every route to this step."));
                }
            }
        }
        dominates.insert(name);
        dominators.insert(name, dominates);
        visited.insert(name);
        for next in flow.steps[name].targets() {
            let count = pending
                .get_mut(next)
                .ok_or_else(|| fail("coordinator.definition.target"))?;
            *count -= 1;
            if *count == 0 {
                ready.push(next);
            }
        }
    }
    if visited.len() != flow.steps.len() {
        return Err(fail("coordinator.definition.cycle").at("workflow.yaml", "steps"));
    }
    Ok(())
}

fn parse_duration(text: &str) -> Result<Duration> {
    let end = text
        .len()
        .checked_sub(1)
        .ok_or_else(|| fail("coordinator.definition.deadline"))?;
    let digits = text
        .get(..end)
        .ok_or_else(|| fail("coordinator.definition.deadline"))?;
    let unit = text
        .get(end..)
        .ok_or_else(|| fail("coordinator.definition.deadline"))?;
    let amount = digits
        .parse::<i64>()
        .map_err(|_| fail("coordinator.definition.deadline"))?;
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return Err(fail("coordinator.definition.deadline")),
    };
    let seconds = amount
        .checked_mul(multiplier)
        .filter(|s| *s > 0 && *s <= 31_536_000)
        .ok_or_else(|| fail("coordinator.definition.deadline"))?;
    Ok(Duration::seconds(seconds))
}

pub(crate) fn parse_timestamp(value: &Value) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(
        value
            .as_str()
            .ok_or_else(|| fail("coordinator.mapping.timestamp"))?,
    )
    .map(|value| value.with_timezone(&Utc))
    .map_err(|_| fail("coordinator.mapping.timestamp"))
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
        return Err(fail("coordinator.definition.schema"));
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
        .map_err(|_| fail("coordinator.definition.schema"))
}

fn read_text(path: &Path, maximum: usize) -> Result<String> {
    let bytes = read_bytes(path, maximum)?;
    if bytes.len() > maximum {
        return Err(fail("coordinator.definition.file").at(path, ""));
    }
    String::from_utf8(bytes).map_err(|_| fail("coordinator.definition.read").at(path, ""))
}

fn read_bytes(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| fail("coordinator.definition.read").at(path, ""))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(fail("coordinator.definition.file").at(path, ""));
    }
    let file =
        std::fs::File::open(path).map_err(|_| fail("coordinator.definition.read").at(path, ""))?;
    let mut bytes = Vec::new();
    // Keep one lookahead byte so the owning decoder can diagnose its bound.
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| fail("coordinator.definition.read").at(path, ""))?;
    Ok(bytes)
}

fn fail(code: &'static str) -> PocError {
    if code == "coordinator.definition.snapshot-limit" {
        return PocError::new(code, "the workflow snapshot exceeds the 393216-byte limit")
            .suggest("Reduce workflow/schema annotations or functions.rhai source until the canonical snapshot is at most 393216 bytes, then rerun check and package. Admitted runs keep their original snapshot.");
    }
    PocError::new(code, match code {
        "coordinator.definition.cycle" => "the graph contains a cycle",
        "coordinator.definition.unreachable" => "a step is not reachable from start",
        "coordinator.definition.deadline" => "deadline must be a positive s, m, h or d duration no longer than 365 days",
        "coordinator.mapping.branch" => "the function did not return a declared branch label",
        "coordinator.mapping.timestamp" => "waitUntil did not return an RFC 3339 instant",
        "coordinator.mapping.missing-output" => "a declared prior call output is absent",
        "coordinator.mapping.call-shape" => "the call input function did not return an object",
        "coordinator.definition.input" => "the start input does not satisfy its authored schema",
        "coordinator.definition.outcome" => "the final output does not satisfy the declared outcome schema",
        "coordinator.definition.schema" => "the schema is invalid or uses an unsupported format or external reference",
        _ => "the workflow definition or mapping was refused",
    }).suggest("Inspect the authored field and function, correct the definition, then rerun check. Admitted runs keep their original snapshot.")
}

fn authored(code: &'static str, field: &str, message: &str, action: &str) -> PocError {
    PocError::new(code, message)
        .at("workflow.yaml", field)
        .suggest(action)
}
