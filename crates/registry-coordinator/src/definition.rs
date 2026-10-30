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
    functions::{
        check_value, Functions, INTERPRETER_ABI, MAXIMUM_FUNCTION_ARRAY_ITEMS,
        MAXIMUM_FUNCTION_CALL_LEVELS, MAXIMUM_FUNCTION_EXPRESSION_DEPTH,
        MAXIMUM_FUNCTION_MAP_ENTRIES, MAXIMUM_FUNCTION_OPERATIONS, MAXIMUM_FUNCTION_SOURCE_BYTES,
        MAXIMUM_FUNCTION_STRING_BYTES,
    },
    operations::OperationIdentity,
    protocol::Operation,
    CoordinatorError, Result,
};

/// The compiled snapshot format, carried by its workflow.
pub(crate) const API_VERSION: &str =
    "id.registrystack.org/formats/coordinator/definition-snapshot/v1alpha1";
const ADAPTER_ABI: &str = "coordinator/product-operations/v1";
const SCHEMA_ABI: &str =
    "coordinator/jsonschema-0.18/draft202012/formats-asserted+uuid+numeric-widths/v2";
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
    operation_contracts: BTreeMap<String, Arc<crate::contracts::OperationContract>>,
    completion_contracts: BTreeMap<(String, String), Arc<crate::contracts::CompletionContract>>,
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
    pub functions: BTreeMap<String, FunctionDefinition>,
    pub operations: BTreeMap<String, ResolvedOperation>,
    pub types: BTreeMap<String, Value>,
    pub contracts: BTreeMap<String, Value>,
    pub presentation: Presentation,
    pub references: BTreeMap<String, SourceReference>,
    pub deadline: String,
    pub start: String,
    pub steps: BTreeMap<String, Step>,
    pub outcomes: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub event_triggers: BTreeMap<String, crate::event_trigger::EventTrigger>,
}

/// How a step computes its value: a pure function over references, an
/// object built member by member from references and nested objects, or one
/// reference.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged, deny_unknown_fields)]
pub enum Mapping {
    Function {
        function: String,
        inputs: BTreeMap<String, Reference>,
    },
    Fields {
        fields: BTreeMap<String, Member>,
    },
    Compare {
        compare: crate::compare::Compare,
    },
    Reference(Reference),
}

/// One member of a fields mapping: a reference, or a nested object built
/// the same way. A member never calls a Function.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Member {
    Reference(Reference),
    Fields(Fields),
}

/// A nested object a fields member builds, written `{"type": "fields",
/// "fields": {...}}`. The tag is a field rather than a serde tag so that
/// unknown members stay refused.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Fields {
    #[serde(rename = "type")]
    pub kind: FieldsTag,
    pub fields: BTreeMap<String, Member>,
}

/// The `type` of a nested fields member.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum FieldsTag {
    #[default]
    #[serde(rename = "fields")]
    Fields,
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
/// The most members one fields mapping builds, counted across its levels:
/// a nested object is one member, and so is each of its own members.
pub(crate) const MAXIMUM_FIELDS: usize = 64;
/// The deepest a fields mapping nests, counting the outermost mapping as 1.
pub(crate) const MAXIMUM_FIELDS_DEPTH: usize = 4;

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
            Self::Function { inputs, .. } => inputs
                .iter()
                .map(|(name, reference)| (format!(".inputs.{name}"), reference))
                .collect(),
            Self::Fields { fields } => {
                let mut references = Vec::new();
                member_references(fields, "", &mut references);
                references
            }
            Self::Compare { compare } => compare.references(),
            Self::Reference(reference) => vec![(String::new(), reference)],
        }
    }
}

/// Each reference below a fields mapping, nested members included, with its
/// member path such as `.fields.premises.fields.district`.
fn member_references<'a>(
    fields: &'a BTreeMap<String, Member>,
    prefix: &str,
    references: &mut Vec<(String, &'a Reference)>,
) {
    for (name, member) in fields {
        let path = format!("{prefix}.fields.{name}");
        match member {
            Member::Reference(reference) => references.push((path, reference)),
            Member::Fields(nested) => member_references(&nested.fields, &path, references),
        }
    }
}

/// Refuse the first member of a fields mapping that breaks its bounds, in
/// name order depth first: a name a product cannot carry, a 65th member
/// across the levels, or a fifth level.
fn fields_bounds(
    fields: &BTreeMap<String, Member>,
    prefix: &str,
    depth: usize,
    count: &mut usize,
) -> Result<()> {
    for (name, member) in fields {
        let path = format!("{prefix}.fields.{name}");
        if !valid_field_name(name) {
            return Err(authored(
                "mapping.reference",
                &format!("{prefix}.fields"),
                "expected fields named by ASCII letters, digits, hyphens or underscores, starting with a letter",
                "Rename the fields to the members the target declares.",
            ));
        }
        *count += 1;
        if *count > MAXIMUM_FIELDS {
            return Err(authored(
                "mapping.fields-count",
                &path,
                "This fields mapping builds more than 64 members across its levels.",
                "Remove members, or build part of the value in an earlier step.",
            ));
        }
        if let Member::Fields(nested) = member {
            if depth == MAXIMUM_FIELDS_DEPTH {
                return Err(authored(
                    "mapping.fields-depth",
                    &path,
                    "This fields mapping nests deeper than 4 levels.",
                    "Flatten it, or build the inner value in an earlier step.",
                ));
            }
            fields_bounds(&nested.fields, &path, depth + 1, count)?;
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Call {
    pub alias: String,
    pub connection: String,
    pub operation: Operation,
}

/// An accepted call and the typed completion it exposes.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompletionReference {
    pub step: String,
    pub name: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Presentation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub steps: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceReference {
    pub target: String,
    pub source: registry_platform_yaml::Source,
}

/// Effective limits may narrow, never widen, the platform pure profile.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct FunctionLimits {
    pub operations: u64,
    pub call_levels: usize,
    pub expression_depth: usize,
    pub string_bytes: usize,
    pub array_items: usize,
    pub map_entries: usize,
    pub source_bytes: usize,
}

impl Default for FunctionLimits {
    fn default() -> Self {
        Self {
            operations: MAXIMUM_FUNCTION_OPERATIONS as u64,
            call_levels: MAXIMUM_FUNCTION_CALL_LEVELS as usize,
            expression_depth: MAXIMUM_FUNCTION_EXPRESSION_DEPTH as usize,
            string_bytes: MAXIMUM_FUNCTION_STRING_BYTES as usize,
            array_items: MAXIMUM_FUNCTION_ARRAY_ITEMS as usize,
            map_entries: MAXIMUM_FUNCTION_MAP_ENTRIES as usize,
            source_bytes: MAXIMUM_FUNCTION_SOURCE_BYTES as usize,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FunctionDefinition {
    pub runtime: String,
    pub profile: String,
    pub capabilities: BTreeSet<String>,
    pub abi: String,
    pub source: String,
    pub entrypoint: String,
    pub inputs: BTreeMap<String, Value>,
    pub output: Value,
    pub limits: FunctionLimits,
    pub revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResolvedOperation {
    pub uses: Operation,
    pub connection: String,
    pub input: Value,
    pub output: Value,
    pub refusal: Option<Value>,
    pub completions: BTreeMap<String, CompletionDefinition>,
    pub revision: String,
    /// The pinned pure Function that turns an external command's saved
    /// command and bounded provider response into an accepted result, a
    /// declared refusal or an uncertain outcome. Present only on
    /// `external.command/v1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interpret: Option<String>,
    /// The bounded provider response the interpretation Function reads.
    /// Present only on `external.command/v1`, whose `output` is the
    /// interpreted accepted result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<Value>,
    /// Exact imported specialization, when the owning product exports one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<crate::breg_action::ActionContract>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompletionDefinition {
    pub kind: CompletionKind,
    pub output: Value,
    pub revision: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CompletionKind {
    CaseworkResult {},
    /// The decision on a BReg Proposal the run started, submitted or read,
    /// settled only from the current Proposal Get.
    BregProposal {},
    BoundedPoll {
        interpret: String,
        interval_seconds: u32,
    },
}

/// The longest wait a wait-for step declares, in seconds: one year, the
/// longest run deadline.
pub(crate) const MAXIMUM_WAIT_SECONDS: u32 = 31_536_000;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Step {
    WaitUntil {
        #[serde(rename = "waitUntil")]
        wait_until: Mapping,
        next: String,
    },
    WaitFor {
        #[serde(rename = "completion")]
        wait_for: CompletionReference,
        #[serde(rename = "timeoutSeconds")]
        timeout_seconds: u32,
        next: String,
        #[serde(rename = "onTimeout", default, skip_serializing_if = "Option::is_none")]
        on_timeout: Option<String>,
        #[serde(rename = "onCancel", default, skip_serializing_if = "Option::is_none")]
        on_cancel: Option<String>,
    },
    Call {
        call: Call,
        input: Mapping,
        next: String,
        #[serde(
            rename = "onDeclaredRefusal",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        on_declared_refusal: Option<String>,
    },
    Choose {
        choose: Mapping,
        cases: BTreeMap<String, String>,
    },
    Finish {
        #[serde(rename = "outcome")]
        finish: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        output: Option<Mapping>,
    },
}

impl Step {
    /// Each transition with the authored member that holds it.
    pub(crate) fn edges(&self) -> Vec<(&'static str, &str)> {
        match self {
            Self::WaitUntil { next, .. } => vec![("next", next)],
            Self::Call {
                next,
                on_declared_refusal,
                ..
            } => std::iter::once(("next", next.as_str()))
                .chain(
                    on_declared_refusal
                        .iter()
                        .map(|step| ("onDeclaredRefusal", step.as_str())),
                )
                .collect(),
            Self::WaitFor {
                next,
                on_timeout,
                on_cancel,
                ..
            } => std::iter::once(("next", next.as_str()))
                .chain(on_timeout.iter().map(|step| ("onTimeout", step.as_str())))
                .chain(on_cancel.iter().map(|step| ("onCancel", step.as_str())))
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
    sources: BTreeMap<String, String>,
    adapter_abi: String,
    interpreter_abi: String,
    schema_abi: String,
    operation_identities: Vec<OperationIdentity>,
}

/// The first operation a snapshot names that the catalog no longer registers,
/// so a removed operation is refused by name instead of as a shapeless snapshot.
fn unregistered_operation(snapshot: &serde_json::Value) -> Option<&str> {
    let uses = snapshot["workflow"]["operations"]
        .as_object()
        .into_iter()
        .flat_map(|operations| operations.values())
        .filter_map(|operation| operation["uses"].as_str());
    let identities = snapshot["operationIdentities"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|identity| identity["id"].as_str());
    uses.chain(identities)
        .find(|identifier| crate::protocol::Operation::parse(identifier).is_none())
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
        let (mut workflow, mut document) = crate::authoring::parse_project(&path, &bytes)?;
        let mut sources = BTreeMap::new();
        for (name, function) in &workflow.functions {
            if !sources.contains_key(&function.source) {
                let source_path = crate::authoring::asset_path(&project, &function.source)
                    .map_err(|error| {
                        crate::authoring::positioned(
                            &document,
                            error.at(&path, format!("/functions/{name}/source")),
                        )
                    })?;
                let source = read_text(&source_path, MAXIMUM_FUNCTION_SOURCE_BYTES as usize)
                    .map_err(|error| {
                        crate::authoring::positioned(
                            &document,
                            error.at(&path, format!("/functions/{name}/source")),
                        )
                    })?;
                sources.insert(function.source.clone(), source);
            }
        }
        seal_revisions(&mut workflow, &sources)?;
        let definition = Self::restore_checked(Snapshot {
            operation_identities: operation_identities(&workflow),
            workflow,
            sources,
            adapter_abi: ADAPTER_ABI.into(),
            interpreter_abi: INTERPRETER_ABI.into(),
            schema_abi: SCHEMA_ABI.into(),
        })
        .map_err(|findings| crate::authoring::placed(&document, findings))?;
        // Authoring holds a project to the static mapping checks; a restored
        // snapshot is not, so an admitted run never fails on a stricter check.
        let mut findings = crate::mapping_check::check(&definition.workflow);
        findings.extend(crate::event_trigger::mapping_findings(&definition.workflow));
        if !findings.is_empty() {
            return Err(crate::authoring::placed(&document, findings));
        }
        for warning in crate::follow_check::warnings(&definition.workflow, &document) {
            document.push_warning(warning);
        }
        Ok((definition, document))
    }

    pub fn from_snapshot(snapshot: &str) -> Result<Self> {
        if snapshot.len() > MAX_SNAPSHOT_BYTES {
            return Err(fail("definition.snapshot_limit"));
        }
        let value = registry_platform_canonical_json::parse_json_strict(snapshot.as_bytes())
            .map_err(|_| fail("definition.snapshot"))?;
        if let Some(removed) = unregistered_operation(&value) {
            return Err(CoordinatorError::new(
                "definition.operation_removed",
                format!("the sealed workflow snapshot uses operation `{removed}`, which this Coordinator does not provide"),
            )
            .suggest(format!("Remove `{removed}` from the workflow project, rerun check, reseal it with coordinatorctl package, and apply the new package.")));
        }
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
        let source_names = frozen
            .workflow
            .functions
            .values()
            .map(|function| function.source.as_str())
            .collect::<BTreeSet<_>>();
        if source_names != frozen.sources.keys().map(String::as_str).collect() {
            return Err(vec![fail("definition.abi")]);
        }
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
        let mut resealed = frozen.workflow.clone();
        match seal_revisions(&mut resealed, &frozen.sources) {
            Ok(()) if resealed != frozen.workflow => findings.push(fail("definition.abi")),
            Err(error) => findings.push(error),
            _ => {}
        }
        let functions = Functions::compile(&frozen.sources, &frozen.workflow.functions)
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
        let mut operation_contracts = BTreeMap::new();
        let mut completion_contracts = BTreeMap::new();
        for (alias, operation) in &frozen.workflow.operations {
            match crate::contracts::OperationContract::new(
                operation.input.clone(),
                operation.output.clone(),
                operation.refusal.clone(),
                operation.action.clone(),
            )
            .and_then(|contract| contract.with_response(operation.response.as_ref()))
            {
                Ok(contract) => {
                    operation_contracts.insert(alias.clone(), Arc::new(contract));
                }
                Err(error) => {
                    findings.push(error.at("workflow.yaml", format!("/operations/{alias}")))
                }
            }
            for (name, completion) in &operation.completions {
                match crate::contracts::CompletionContract::new(&completion.output) {
                    Ok(contract) => {
                        completion_contracts
                            .insert((alias.clone(), name.clone()), Arc::new(contract));
                    }
                    Err(error) => findings.push(error.at(
                        "workflow.yaml",
                        format!("/operations/{alias}/completions/{name}"),
                    )),
                }
            }
        }
        let (Some(functions), Some(input_schema), true) =
            (functions, input_schema, findings.is_empty())
        else {
            return Err(findings);
        };
        let input_schema = Arc::new(input_schema);
        snapshot_bytes(&frozen).map_err(|error| vec![error])?;
        Ok(Self {
            workflow: frozen.workflow.clone(),
            digest: semantic_revision(&frozen).map_err(|error| vec![error])?,
            frozen,
            functions,
            input_schema,
            outcome_schemas,
            operation_contracts,
            completion_contracts,
        })
    }

    fn check_integrity(&self) -> Result<()> {
        if self.workflow != self.frozen.workflow || self.digest != semantic_revision(&self.frozen)?
        {
            return Err(fail("definition.changed"));
        }
        Ok(())
    }

    /// Explain the authored graph and host limits without input, outputs,
    /// runtime destinations or secret material.
    pub fn explain(&self) -> Result<Value> {
        self.check_integrity()?;
        let contracts = self
            .workflow
            .contracts
            .iter()
            .map(|(id, artifact)| {
                let source = self
                    .workflow
                    .references
                    .get(&format!("/contracts/{id}/source"))
                    .map(|reference| &reference.target);
                semantic_hash(artifact).map(|digest| {
                    (
                        id.clone(),
                        serde_json::json!({"digest":digest,"source":source}),
                    )
                })
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let operation_contracts = self
            .workflow
            .operations
            .values()
            .map(|operation| operation.uses.descriptor())
            .map(|descriptor| (descriptor.id, descriptor.host_contract()))
            .collect::<BTreeMap<_, _>>();
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
                    if let Mapping::Function { inputs, .. } = mapping {
                        item["mapping"]["inputs"] = serde_json::json!(inputs);
                    }
                }
                match step {
                    Step::Call {
                        call,
                        on_declared_refusal,
                        ..
                    } => {
                        item["connection"] = serde_json::json!(call.connection);
                        item["operation"] = serde_json::json!(call.alias);
                        item["uses"] = serde_json::json!(call.operation);
                        item["product"] = serde_json::json!(call.operation.product());
                        item["mutating"] = serde_json::json!(call.operation.is_mutating());
                        item["effect"] = serde_json::json!(call.operation.descriptor().effect);
                        item["recovery"] = serde_json::json!(call.operation.recovery());
                        if let Some(target) = on_declared_refusal {
                            item["onDeclaredRefusal"] = serde_json::json!(target);
                        }
                    }
                    Step::WaitFor {
                        wait_for,
                        timeout_seconds,
                        on_timeout,
                        on_cancel,
                        ..
                    } => {
                        item["completion"] = serde_json::json!(wait_for);
                        item["timeoutSeconds"] = serde_json::json!(timeout_seconds);
                        item["onTimeout"] = serde_json::json!(on_timeout);
                        item["onCancel"] = serde_json::json!(on_cancel);
                    }
                    Step::Choose { cases, .. } => item["cases"] = serde_json::json!(cases),
                    Step::Finish { finish, .. } => item["outcome"] = serde_json::json!(finish),
                    _ => {}
                }
                if let Some(presentation) = self.workflow.presentation.steps.get(id) {
                    item["presentation"] = presentation.clone();
                }
                item
            })
            .collect::<Vec<_>>();
        Ok(
            serde_json::json!({"workflow":self.workflow.id,"version":self.workflow.version,"workflowRevision":self.digest,
            "start":self.workflow.start,"deadlineSeconds":parse_duration(&self.workflow.deadline)?.num_seconds(),
            "contracts":contracts,"operations":self.workflow.operations,"operationContracts":operation_contracts,"eventTriggers":self.workflow.event_triggers,"functions":self.workflow.functions,"types":self.workflow.types,"references":self.workflow.references,"presentation":self.workflow.presentation,"connections":self.workflow.connections,"outcomes":self.workflow.outcomes.keys().collect::<Vec<_>>(),"steps":steps,
            "limits":crate::functions::limits(),"valueLimits":crate::functions::value_limits(),"interpreterAbi":self.frozen.interpreter_abi,"schemaAbi":self.frozen.schema_abi,"adapterAbi":self.frozen.adapter_abi,

            "recovery":"A run restores this exact snapshot. retry-same preserves a frozen command and cannot adopt edited mappings or repeat an uncertain hold-after-dispatch evaluation."}),
        )
    }

    pub fn snapshot(&self) -> Result<String> {
        self.check_integrity()?;
        String::from_utf8(snapshot_bytes(&self.frozen)?).map_err(|_| fail("definition.snapshot"))
    }

    pub fn operation_contract(&self, call: &Call) -> Result<&crate::contracts::OperationContract> {
        self.check_integrity()?;
        if self
            .workflow
            .operations
            .get(&call.alias)
            .is_none_or(|operation| {
                operation.uses != call.operation || operation.connection != call.connection
            })
        {
            return Err(fail("definition.operation"));
        }
        self.operation_contracts
            .get(&call.alias)
            .map(Arc::as_ref)
            .ok_or_else(|| fail("definition.operation"))
    }

    /// The terminal output validator compiled once for the named completion.
    pub fn completion_contract(
        &self,
        reference: &CompletionReference,
    ) -> Result<&crate::contracts::CompletionContract> {
        self.check_integrity()?;
        let Some(Step::Call { call, .. }) = self.workflow.steps.get(&reference.step) else {
            return Err(fail("definition.wait"));
        };
        self.completion_contracts
            .get(&(call.alias.clone(), reference.name.clone()))
            .map(Arc::as_ref)
            .ok_or_else(|| fail("definition.wait"))
    }

    pub fn completion(&self, reference: &CompletionReference) -> Result<&CompletionDefinition> {
        self.check_integrity()?;
        self.workflow
            .completion(reference)
            .ok_or_else(|| fail("definition.wait"))
    }

    pub fn evaluate_function(&self, name: &str, inputs: &Value, synthetic: bool) -> Result<Value> {
        self.check_integrity()?;
        self.functions.evaluate(name, inputs, synthetic)
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

    pub(crate) fn evaluate_mapping(
        &self,
        mapping: &Mapping,
        input: &Value,
        field: &str,
    ) -> Result<Value> {
        self.check_integrity()?;
        self.map_value(mapping, input, &BTreeMap::new(), field, false)
    }

    fn map_value(
        &self,
        mapping: &Mapping,
        input: &Value,
        outputs: &BTreeMap<String, Value>,
        field: &str,
        synthetic: bool,
    ) -> Result<Value> {
        Ok(match mapping {
            Mapping::Function { function, inputs } => {
                let arguments = inputs
                    .iter()
                    .map(|(name, reference)| {
                        resolve(reference, input, outputs)
                            .map(|value| (name.clone(), value.clone()))
                            .map_err(|error| {
                                error.at("workflow.yaml", format!("{field}.inputs.{name}"))
                            })
                    })
                    .collect::<Result<serde_json::Map<_, _>>>()?;
                self.functions
                    .evaluate(function, &Value::Object(arguments), synthetic)
                    .map_err(|error| error.at("workflow.yaml", field))?
            }
            Mapping::Fields { fields } => {
                let value = build_fields(fields, input, outputs, field)?;
                check_value(&value).map_err(|error| error.at("workflow.yaml", field))?;
                value
            }
            Mapping::Compare { compare } => {
                let matched =
                    compare.matches(field, |reference| resolve(reference, input, outputs))?;
                Value::from(if matched {
                    crate::compare::MATCHED
                } else {
                    crate::compare::UNMATCHED
                })
            }
            Mapping::Reference(reference) => resolve(reference, input, outputs)
                .map_err(|error| error.at("workflow.yaml", field))?
                .clone(),
        })
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
        let value = self.map_value(mapping, input, outputs, &field, synthetic)?;
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

impl Workflow {
    pub fn operation(&self, call: &Call) -> &ResolvedOperation {
        &self.operations[&call.alias]
    }
    pub fn completion(&self, reference: &CompletionReference) -> Option<&CompletionDefinition> {
        let Step::Call { call, .. } = self.steps.get(&reference.step)? else {
            return None;
        };
        self.operations
            .get(&call.alias)?
            .completions
            .get(&reference.name)
    }
}

fn seal_revisions(workflow: &mut Workflow, sources: &BTreeMap<String, String>) -> Result<()> {
    for function in workflow.functions.values_mut() {
        let source = sources
            .get(&function.source)
            .ok_or_else(|| fail("function.definition"))?;
        function.revision = crate::functions::revision(function, source)?;
    }
    for operation in workflow.operations.values_mut() {
        for completion in operation.completions.values_mut() {
            let function = match &completion.kind {
                CompletionKind::BoundedPoll { interpret, .. } => Some(
                    &workflow
                        .functions
                        .get(interpret)
                        .ok_or_else(|| fail("definition.abi"))?
                        .revision,
                ),
                _ => None,
            };
            completion.revision = semantic_hash(
                &serde_json::json!({"kind":completion.kind,"output":semantic_schema(&completion.output),"function":function}),
            )?;
        }
        let mut identity = serde_json::json!({"uses":operation.uses.identity(),"host":operation.uses.descriptor().host_contract(),"connection":operation.connection,
            "input":semantic_schema(&operation.input),"output":semantic_schema(&operation.output),"refusal":operation.refusal.as_ref().map(semantic_schema),
            "completions":operation.completions.iter().map(|(name,completion)| (name,&completion.revision)).collect::<BTreeMap<_,_>>(),"action":operation.action});
        // Only a command carries an interpretation, so every other
        // operation keeps its existing revision.
        if let Some(interpret) = &operation.interpret {
            let function = &workflow
                .functions
                .get(interpret)
                .ok_or_else(|| fail("definition.abi"))?
                .revision;
            identity["interpret"] = serde_json::json!(function);
        }
        if let Some(response) = &operation.response {
            identity["response"] = semantic_schema(response);
        }
        operation.revision = semantic_hash(&identity)?;
    }
    Ok(())
}

/// An external command pins one interpretation Function over its exact
/// command and response schemas, and its output and refusal are exactly what
/// that Function declares. No other operation carries an interpretation.
fn command_interpretation_valid(flow: &Workflow, operation: &ResolvedOperation) -> bool {
    if operation.uses != Operation::ExternalCommand {
        return operation.interpret.is_none() && operation.response.is_none();
    }
    let (Some(interpret), Some(response)) = (&operation.interpret, &operation.response) else {
        return false;
    };
    flow.functions.get(interpret).is_some_and(|function| {
        function.inputs.len() == 2
            && function.inputs.get("command") == Some(&operation.input)
            && function.inputs.get("response") == Some(response)
            && crate::authoring::command_interpretation(&function.output, "").is_ok_and(
                |(output, refusal)| output == operation.output && refusal == operation.refusal,
            )
    })
}

fn semantic_hash(value: &Value) -> Result<String> {
    let bytes = registry_platform_canonical_json::canonicalize_json(value)
        .map_err(|_| fail("definition.canonical"))?;
    Ok(sha256_uri(&bytes))
}

/// Remove JSON Schema presentation only in schema positions, never inside a
/// literal const/enum value whose member may itself be called title.
pub(crate) fn semantic_schema(schema: &Value) -> Value {
    let Some(object) = schema.as_object() else {
        return schema.clone();
    };
    let mut semantic = object.clone();
    for annotation in ["title", "description", "$comment", "examples"] {
        semantic.remove(annotation);
    }
    for keyword in [
        "properties",
        "patternProperties",
        "$defs",
        "definitions",
        "dependentSchemas",
    ] {
        if let Some(Value::Object(members)) = semantic.get_mut(keyword) {
            for schema in members.values_mut() {
                *schema = semantic_schema(schema);
            }
        }
    }
    for keyword in [
        "items",
        "additionalProperties",
        "unevaluatedProperties",
        "contains",
        "propertyNames",
        "not",
        "if",
        "then",
        "else",
        "additionalItems",
        "unevaluatedItems",
    ] {
        if let Some(schema) = semantic.get_mut(keyword) {
            *schema = semantic_schema(schema);
        }
    }
    for keyword in ["oneOf", "anyOf", "allOf", "prefixItems"] {
        if let Some(Value::Array(schemas)) = semantic.get_mut(keyword) {
            for schema in schemas {
                *schema = semantic_schema(schema);
            }
        }
    }
    Value::Object(semantic)
}

fn semantic_revision(snapshot: &Snapshot) -> Result<String> {
    let flow = &snapshot.workflow;
    let mut used_operations = BTreeSet::new();
    let mut used_functions = BTreeSet::new();
    for step in flow.steps.values() {
        if let Step::Call { call, .. } = step {
            used_operations.insert(call.alias.as_str());
        }
        if let Some(Mapping::Function { function, .. }) = step.mapping() {
            used_functions.insert(function.as_str());
        }
        if let Step::WaitFor { wait_for, .. } = step {
            if let Some(CompletionDefinition {
                kind: CompletionKind::BoundedPoll { interpret, .. },
                ..
            }) = flow.completion(wait_for)
            {
                used_functions.insert(interpret.as_str());
            }
        }
    }
    for trigger in flow.event_triggers.values() {
        if let Mapping::Function { function, .. } = &trigger.input {
            used_functions.insert(function.as_str());
        }
    }
    let operations = used_operations
        .into_iter()
        .map(|name| (name, &flow.operations[name].revision))
        .collect::<BTreeMap<_, _>>();
    let functions = used_functions
        .into_iter()
        .map(|name| {
            flow.functions
                .get(name)
                .map(|function| (name, &function.revision))
                .ok_or_else(|| fail("definition.abi"))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut semantic = serde_json::json!({"id":flow.id,"input":semantic_schema(&flow.input),"deadline":flow.deadline,"start":flow.start,
        "steps":flow.steps,"outcomes":flow.outcomes.iter().map(|(name,schema)| (name,semantic_schema(schema))).collect::<BTreeMap<_,_>>(),"operations":operations,"functions":functions,
        "adapterAbi":snapshot.adapter_abi,"interpreterAbi":snapshot.interpreter_abi,"schemaAbi":snapshot.schema_abi,"valueLimits":crate::functions::value_limits()});
    if !flow.event_triggers.is_empty() {
        semantic["eventTriggers"] =
            serde_json::to_value(&flow.event_triggers).map_err(|_| fail("definition.canonical"))?;
    }
    let bytes = registry_platform_canonical_json::canonicalize_json(&semantic)
        .map_err(|_| fail("definition.canonical"))?;
    Ok(sha256_uri(&bytes))
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

/// The object a fields mapping builds from its resolved references, nested
/// members built the same way. Errors name the member, never a value.
fn build_fields(
    fields: &BTreeMap<String, Member>,
    input: &Value,
    outputs: &BTreeMap<String, Value>,
    field: &str,
) -> Result<Value> {
    fields
        .iter()
        .map(|(name, member)| {
            let path = format!("{field}.fields.{name}");
            let value = match member {
                Member::Reference(reference) => resolve(reference, input, outputs)
                    .map_err(|error| error.at("workflow.yaml", &path))?
                    .clone(),
                Member::Fields(nested) => build_fields(&nested.fields, input, outputs, &path)?,
            };
            Ok((name.clone(), value))
        })
        .collect::<Result<serde_json::Map<_, _>>>()
        .map(Value::Object)
}

/// What computed a mapping's value, as a refusal names it.
fn producer(mapping: &Mapping) -> String {
    match mapping {
        Mapping::Function { function, .. } => format!("function {function}"),
        Mapping::Fields { .. } => "the fields mapping".into(),
        Mapping::Compare { .. } => "the compare".into(),
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
    let mut findings = crate::event_trigger::workflow_findings(flow);
    for (field, size, minimum, maximum) in [
        ("steps", flow.steps.len(), 1, 64),
        ("connections", flow.connections.len(), 0, 16),
        ("outcomes", flow.outcomes.len(), 1, 64),
        ("operations", flow.operations.len(), 0, 64),
        ("functions", flow.functions.len(), 0, 128),
        ("types", flow.types.len(), 0, 128),
        ("contracts", flow.contracts.len(), 0, 16),
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
    if flow.api_version != API_VERSION || flow.kind != "Workflow" || !valid_name(&flow.id) {
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
    for (alias, operation) in &flow.operations {
        for (name, completion) in &operation.completions {
            let valid = match &completion.kind {
                CompletionKind::CaseworkResult {} => {
                    operation.uses == Operation::SubmitReviewRequest
                        && completion.output == *crate::contracts::casework_completion_schema()
                }
                CompletionKind::BregProposal {} => {
                    operation.action.as_ref().is_some_and(|action| {
                        action.mode == registry_breg_client::BRegActionMode::Proposal
                    }) && crate::breg_proposal::completion_matches(
                        operation.uses,
                        &completion.output,
                    )
                }
                CompletionKind::BoundedPoll {
                    interpret,
                    interval_seconds,
                } => {
                    operation.uses == Operation::ExternalGet
                        && (1..=86_400).contains(interval_seconds)
                        && flow.functions.get(interpret).is_some_and(|function| {
                            function.inputs.len() == 2
                                && function.inputs.get("command") == Some(&operation.input)
                                && function.inputs.get("response") == Some(&operation.output)
                                && crate::authoring::terminal_schema(&function.output, "")
                                    .is_ok_and(|output| output == completion.output)
                        })
                }
            };
            if !valid {
                findings.push(authored("definition.abi", &format!("/operations/{alias}/completions/{name}"),
                "the completion does not match its host-enforced Operation contract", "Recompile the canonical project; local metadata cannot widen host completion capabilities."));
            }
        }
        if operation.refusal.is_some() && !operation.uses.descriptor().declared_refusal {
            findings.push(fail("definition.abi"));
        }
        if !command_interpretation_valid(flow, operation) {
            findings.push(authored("definition.abi", &format!("/operations/{alias}/interpret"),
                "the command interpretation does not match its host-enforced Operation contract", "Recompile the canonical project; local metadata cannot change how a provider response is interpreted."));
        }
    }
    for (name, step) in &flow.steps {
        if let Step::Call { call, .. } = step {
            if flow.operations.get(&call.alias).is_none_or(|resolved| {
                resolved.uses != call.operation || resolved.connection != call.connection
            }) {
                findings.push(authored(
                    "definition.operation",
                    &format!("steps.{name}.operation"),
                    "the compiled call does not match its resolved Operation alias",
                    "Recompile the project from its canonical Operation aliases.",
                ));
            }
        }
    }
    for (name, step) in &flow.steps {
        if !cancels_only_run_owned(flow, step) {
            findings.push(authored(
                "definition.proposal-not-run-owned",
                &format!("steps.{name}.input"),
                "Cancel only a request this run started or submitted: map proposalId from that step's output.",
                "Map proposalId from the output of the breg.start-proposal/v1 or breg.submit-proposal/v1 step that opened the request.",
            ));
        }
    }
    let mut resolved_connections = BTreeMap::new();
    for (name, step) in &flow.steps {
        let Step::Call { call, .. } = step else {
            continue;
        };
        let Some(operation) = flow.operations.get(&call.alias) else {
            continue;
        };
        if resolved_connections
            .insert(
                operation.connection.clone(),
                operation.uses.product().to_owned(),
            )
            .is_some_and(|product| product != operation.uses.product())
        {
            findings.push(authored(
                "definition.connection",
                &format!("/operations/{name}/connection"),
                "one logical connection cannot bind different Operation interfaces",
                "Use a separate logical connection for each interface.",
            ));
        }
    }
    if resolved_connections != flow.connections {
        findings.push(fail("definition.abi"));
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
        if let Some(Mapping::Function { function, inputs }) = step.mapping() {
            match flow.functions.get(function) {
                None => findings.push(authored("mapping.function", &format!("steps.{name}.{}.function", step.role()),
                    &format!("Function {function} is not declared; available Functions are {}", listed(flow.functions.keys().map(String::as_str))),
                    "Name one of the declared Functions, or add its typed signature and reviewed source asset.")),
                Some(signature) if inputs.keys().ne(signature.inputs.keys()) => findings.push(authored("mapping.function", &format!("steps.{name}.{}.inputs",step.role()),
                    "the named Function inputs must match its declared signature exactly", "Supply every declared input name once and remove undeclared names.")),
                _ => {},
            }
        }
        match step {
            Step::WaitFor {
                wait_for,
                timeout_seconds,
                ..
            } => findings.extend(wait_findings(flow, name, wait_for, *timeout_seconds)),
            Step::Call {
                call,
                on_declared_refusal,
                ..
            } => {
                match flow.connections.get(&call.connection) {
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
                }
                if on_declared_refusal.is_some()
                    && (!call.operation.descriptor().declared_refusal
                        || flow
                            .operations
                            .get(&call.alias)
                            .is_none_or(|operation| operation.refusal.is_none()))
                {
                    findings.push(authored(
                        "definition.operation",
                        &format!("steps.{name}.onDeclaredRefusal"),
                        &format!(
                            "operation {} does not declare a routable business refusal",
                            call.operation.as_str()
                        ),
                        "Remove onDeclaredRefusal, or use it on an invoke-breg-action call.",
                    ));
                }
                if call.operation == Operation::ReadInForce && on_declared_refusal.is_none() {
                    findings.push(authored(
                        "definition.operation",
                        &format!("steps.{name}.onDeclaredRefusal"),
                        "breg.read-in-force/v1 requires onDeclaredRefusal: no record in force is a routine answer that needs its own next step",
                        "Add onDeclaredRefusal naming the step that handles no record in force.",
                    ));
                }
            }
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

/// A wait may observe only a named completion on its accepted call.
fn correlates(flow: &Workflow, completion: &CompletionReference) -> bool {
    match flow.steps.get(&completion.step) {
        Some(Step::Call { call, .. }) => flow
            .operations
            .get(&call.alias)
            .is_some_and(|operation| operation.completions.contains_key(&completion.name)),
        _ => false,
    }
}

fn wait_findings(
    flow: &Workflow,
    name: &str,
    completion: &CompletionReference,
    timeout: u32,
) -> Vec<CoordinatorError> {
    let mut findings = Vec::new();
    if !correlates(flow, completion) {
        findings.push(authored("definition.wait", &format!("steps.{name}.completion"),
            "the completion must name a call step and one completion declared by that call's Operation",
            "Name an earlier accepted call under completion.step and one of its completion names."));
    }
    let deadline = parse_duration(&flow.deadline)
        .ok()
        .map(|deadline| deadline.num_seconds());
    if !(1..=MAXIMUM_WAIT_SECONDS).contains(&timeout)
        || deadline.is_some_and(|deadline| i64::from(timeout) >= deadline)
    {
        findings.push(authored(
            "definition.wait",
            &format!("steps.{name}.timeoutSeconds"),
            "expected a wait from 1 to 31536000 seconds shorter than the workflow deadline",
            "Set timeoutSeconds below workflow.deadlineSeconds.",
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutputRoute {
    CallSuccess,
    DeclaredRefusal,
    Completion,
}

pub(crate) type AvailableOutputs = BTreeMap<String, OutputRoute>;

fn reachable_steps(flow: &Workflow) -> BTreeSet<&str> {
    let mut reachable = BTreeSet::from([flow.start.as_str()]);
    let mut frontier = vec![flow.start.as_str()];
    while let Some(name) = frontier.pop() {
        for next in flow.steps[name].targets() {
            if reachable.insert(next) {
                frontier.push(next);
            }
        }
    }
    reachable
}

fn edge_output(step: &Step, member: &str) -> Option<OutputRoute> {
    match (step, member) {
        (Step::Call { .. }, "next") => Some(OutputRoute::CallSuccess),
        (Step::Call { .. }, "onDeclaredRefusal") => Some(OutputRoute::DeclaredRefusal),
        (Step::WaitFor { .. }, "next") => Some(OutputRoute::Completion),
        _ => None,
    }
}

fn propagated_outputs<'a>(
    flow: &'a Workflow,
    incoming: &Incoming<'a>,
    reachable: &BTreeSet<&'a str>,
) -> BTreeMap<&'a str, AvailableOutputs> {
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
    let mut available: BTreeMap<&str, AvailableOutputs> = BTreeMap::new();
    while let Some(name) = ready.pop() {
        let outputs = predecessors(name)
            .into_iter()
            .map(|(source, member)| {
                let mut carried = available[source].clone();
                if let Some(route) = edge_output(&flow.steps[source], member) {
                    carried.insert(source.to_owned(), route);
                }
                carried
            })
            .reduce(|mut common, incoming| {
                // A producer stays available only when every incoming route
                // carries the same output shape. Authors consume or normalize
                // success and declared-refusal values before their paths join.
                common.retain(|producer, route| incoming.get(producer) == Some(route));
                common
            })
            .unwrap_or_default();
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
    available
}

/// The output shape each producer has on every route to each consumer. The
/// workflow has already passed structural graph checks when the mapping checker
/// calls this helper.
pub(crate) fn output_routes(flow: &Workflow) -> BTreeMap<String, AvailableOutputs> {
    let mut incoming: Incoming = flow
        .steps
        .keys()
        .map(|name| (name.as_str(), vec![]))
        .collect();
    for (name, step) in &flow.steps {
        for (member, target) in step.edges() {
            if let Some(sources) = incoming.get_mut(target) {
                sources.push((name, member));
            }
        }
    }
    let reachable = reachable_steps(flow);
    propagated_outputs(flow, &incoming, &reachable)
        .into_iter()
        .map(|(name, outputs)| (name.to_owned(), outputs))
        .collect()
}

fn graph_findings<'a>(flow: &'a Workflow, incoming: &Incoming<'a>) -> Vec<CoordinatorError> {
    let mut findings = Vec::new();
    let reachable = reachable_steps(flow);
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
    let available = propagated_outputs(flow, incoming, &reachable);
    for (name, outputs) in &available {
        if let Some(mapping) = flow.steps[*name].mapping() {
            if let Err(error) = validate_mapping(flow, name, mapping, outputs) {
                findings.push(error);
            }
        }
        if let Step::WaitFor { wait_for, .. } = &flow.steps[*name] {
            if correlates(flow, wait_for)
                && outputs.get(&wait_for.step) != Some(&OutputRoute::CallSuccess)
            {
                findings.push(authored(
                    "definition.wait",
                    &format!("steps.{name}.completion.step"),
                    &format!(
                        "the review request of step {} is not submitted on every route to this step",
                        wait_for.step
                    ),
                    "Move the submitting call before the branch, so every route to the wait submits the request it waits for.",
                ));
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
pub(crate) fn validate_mapping(
    flow: &Workflow,
    name: &str,
    mapping: &Mapping,
    available: &AvailableOutputs,
) -> Result<()> {
    let step = &flow.steps[name];
    let base = format!("steps.{name}.{}", step.role());
    match (step, mapping) {
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
        (_, Mapping::Fields { fields }) => fields_bounds(fields, &base, 1, &mut 0)?,
        (_, Mapping::Compare { compare }) => compare.check(step, name)?,
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
            if !available.contains_key(prior.as_str())
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
        let Some(fields) = value.as_object() else {
            return value.is_boolean();
        };
        if fields.contains_key("$id")
            || ["$ref", "$dynamicRef", "$recursiveRef"]
                .iter()
                .any(|keyword| {
                    fields.get(*keyword).is_some_and(|reference| {
                        !reference.as_str().is_some_and(|text| text.starts_with('#'))
                    })
                })
        {
            return false;
        }
        // Walk schema positions only. A const/enum/default may contain ordinary
        // JSON members named $id or $ref without declaring schema resources.
        for keyword in [
            "properties",
            "patternProperties",
            "$defs",
            "definitions",
            "dependentSchemas",
        ] {
            if let Some(Value::Object(members)) = fields.get(keyword) {
                if !members.values().all(|schema| local(schema, depth + 1)) {
                    return false;
                }
            }
        }
        for keyword in [
            "items",
            "additionalProperties",
            "unevaluatedProperties",
            "contains",
            "propertyNames",
            "not",
            "if",
            "then",
            "else",
            "additionalItems",
            "unevaluatedItems",
        ] {
            if fields
                .get(keyword)
                .is_some_and(|schema| !local(schema, depth + 1))
            {
                return false;
            }
        }
        for keyword in ["oneOf", "anyOf", "allOf", "prefixItems"] {
            if let Some(Value::Array(schemas)) = fields.get(keyword) {
                if !schemas.iter().all(|schema| local(schema, depth + 1)) {
                    return false;
                }
            }
        }
        true
    }
    check_value(schema)?;
    if !(schema.is_object() || schema.is_boolean()) || !local(schema, 0) {
        return Err(fail("definition.schema"));
    }
    // Numeric width annotations from owner-generated contracts become explicit
    // validation bounds without changing the governed schema or its digest.
    let mut validation = schema.clone();
    crate::contracts::bound_numbers(&mut validation);
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .should_ignore_unknown_formats(false)
        // jsonschema 0.18 only registers UUID natively for draft 2019-09.
        // Keep the authored 2020-12 boundary explicit and versioned.
        .with_format("uuid", |value| uuid::Uuid::parse_str(value).is_ok())
        .with_resolver(NoRemoteSchemas)
        .compile(&validation)
        .map_err(|_| fail("definition.schema"))
}

fn read_text(path: &Path, maximum: usize) -> Result<String> {
    let bytes = read_bytes(path, maximum)?;
    if bytes.len() > maximum {
        return Err(fail("definition.file").at(path, ""));
    }
    String::from_utf8(bytes).map_err(|_| fail("definition.read").at(path, ""))
}

pub(crate) fn read_bytes(path: &Path, maximum: usize) -> Result<Vec<u8>> {
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

/// A run cancels only a Proposal it opened: the cancel's `proposalId` is
/// the `proposalId` a start or submit call step returned. Ordinary step
/// reference checks then hold that the step ran on every route here.
fn cancels_only_run_owned(flow: &Workflow, step: &Step) -> bool {
    let Step::Call { call, input, .. } = step else {
        return true;
    };
    if call.operation != Operation::CancelProposal {
        return true;
    }
    let Mapping::Fields { fields } = input else {
        return false;
    };
    let Some(Member::Reference(Reference::Step { step, path })) = fields.get("proposalId") else {
        return false;
    };
    path.as_deref() == Some("/proposalId")
        && matches!(
            flow.steps.get(step),
            Some(Step::Call { call, .. }) if matches!(
                call.operation,
                Operation::StartProposal | Operation::SubmitProposal
            )
        )
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
