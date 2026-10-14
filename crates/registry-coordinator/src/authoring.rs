// SPDX-License-Identifier: Apache-2.0
//! One canonical portable Workflow model and staged schema resolution.

use crate::{
    definition::{
        self, Call, CompletionDefinition, CompletionKind, CompletionReference, FunctionDefinition,
        FunctionLimits, Mapping, Presentation, ResolvedOperation, Step, Workflow,
    },
    functions::{
        MAXIMUM_FUNCTION_ARRAY_ITEMS, MAXIMUM_FUNCTION_CALL_LEVELS,
        MAXIMUM_FUNCTION_EXPRESSION_DEPTH, MAXIMUM_FUNCTION_MAP_ENTRIES,
        MAXIMUM_FUNCTION_OPERATIONS, MAXIMUM_FUNCTION_SOURCE_BYTES, MAXIMUM_FUNCTION_STRING_BYTES,
    },
    protocol::Operation,
    CoordinatorError, Result,
};
use registry_platform_config::AuthoredExpressions;
use registry_platform_yaml::{
    ApiVersion, BoundedU32, Document, EnvelopeRule, Expect, ForeignValue, FormatSpec, Invalid,
    LocalId, ProjectIdentity, Reader, RemovedKey, Severity,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path},
};

pub const API_VERSION: &str = "id.registrystack.org/formats/coordinator/project/v1alpha1";
pub const KIND: &str = "CoordinatorProject";
pub const SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/coordinator/project/project.v1alpha1.schema.json";
const FORMAT: FormatSpec<'static> = FormatSpec {
    kind: KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[
        RemovedKey { pointer: "/input", replacement: "Move input to workflow.input." },
        RemovedKey { pointer: "/connections", replacement: "Declare logical connections on Operation aliases under operations, then bind them in runtime.yaml." },
        RemovedKey { pointer: "/functionsFile", replacement: "Declare named typed Functions under functions, each with its source asset." },
        RemovedKey { pointer: "/deadlineSeconds", replacement: "Move deadlineSeconds to workflow.deadlineSeconds." },
        RemovedKey { pointer: "/start", replacement: "Move start to workflow.start." },
        RemovedKey { pointer: "/steps", replacement: "Move steps to workflow.steps and use Operation aliases." },
        RemovedKey { pointer: "/outcomes", replacement: "Move outcomes to workflow.outcomes." },
        RemovedKey { pointer: "/workflow/steps/*/*/arguments", replacement: "Use inputs with the Function signature's named references." },
    ],
};

/// A project contains one finite Workflow and its reusable typed assets.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CoordinatorProject {
    /// The shared identity: project.id identifies this Workflow and project.version is a human release label.
    pub project: ProjectIdentity,
    /// An optional human title; it changes neither stable identity nor behavior revision.
    #[serde(default)]
    title: Option<String>,
    /// An optional explanation for readers; it has no execution or authorization effect.
    #[serde(default)]
    description: Option<String>,
    /// Generated local public product contracts imported at compile time; no runtime discovery occurs.
    #[serde(default)]
    contracts: BTreeMap<LocalId, ImportedContract>,
    /// Reusable named JSON Schemas, referenced with typeRef in whole-schema positions.
    #[serde(default)]
    types: BTreeMap<LocalId, Schema>,
    /// Named typed bounded pure computations over one object of named inputs.
    #[serde(default)]
    functions: BTreeMap<LocalId, AuthoredFunction>,
    /// Local aliases for exact versioned host Operations and logical deployment connections.
    #[serde(default)]
    operations: BTreeMap<LocalId, AuthoredOperation>,
    /// The one finite acyclic Workflow graph this project defines.
    workflow: AuthoredWorkflow,
}

/// A whole JSON Schema or one compile-time schema reference. Schema keywords
/// retain their independently owned JSON Schema spelling.
#[derive(Debug, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
struct Schema(
    #[cfg_attr(feature = "schema", schemars(extend("x-registry-foreign" = "json-schema-2020-12")))]
    ForeignValue,
);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
struct ImportedContract {
    /// The producer of this generated public contract artifact.
    #[serde(rename = "type")]
    product: ContractProduct,
    /// A generated JSON artifact inside the project directory.
    source: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
enum ContractProduct {
    Breg,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
struct ActionReference {
    /// The local generated contract import that owns this definition.
    contract: LocalId,
    /// The exact definition ID within that generated contract.
    id: LocalId,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
struct AuthoredOperation {
    /// One exact versioned host catalog contract.
    #[cfg_attr(feature = "schema", schemars(with = "Operation"))]
    uses: String,
    /// The logical deployment connection. It grants no authority.
    connection: LocalId,
    /// An exact BReg Action specialization from one generated contract import.
    #[serde(default)]
    action: Option<ActionReference>,
    /// An optional typed response specialization for the bounded external GET Operation.
    #[serde(default)]
    response_schema: Option<Schema>,
    /// Named bounded completion contracts; the host enforces their observation semantics.
    #[serde(default)]
    completions: BTreeMap<LocalId, AuthoredCompletion>,
    /// An optional human title; it changes neither stable identity nor behavior revision.
    #[serde(default)]
    title: Option<String>,
    /// An optional explanation for readers; it has no execution or authorization effect.
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
enum AuthoredCompletion {
    /// Repeats the accepted read under host-owned transport and credentials.
    BoundedPoll {
        /// The typed pure Function that turns the saved command and response into an observation.
        interpret: LocalId,
        /// Seconds between pending observations; the host may impose a stricter minimum.
        interval_seconds: BoundedU32<1, 86_400>,
    },
}
registry_platform_yaml::tagged_union!(AuthoredCompletion);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
struct AuthoredFunction {
    /// The pinned pure runtime; rhai has no clock, network, database or credential capability.
    runtime: FunctionRuntime,
    /// A local reviewed source asset inside the project directory.
    source: String,
    /// One public source function taking exactly one named-input object.
    entrypoint: String,
    /// Named input schemas or references; every declared input is required exactly once.
    inputs: BTreeMap<LocalId, Schema>,
    /// The declared result schema or mapping; Functions and the host enforce it.
    output: Schema,
    /// Optional narrowing of the bounded pure profile; omitted limits retain the default ceiling.
    #[serde(default)]
    limits: NarrowedLimits,
    /// An optional human title; it changes neither stable identity nor behavior revision.
    #[serde(default)]
    title: Option<String>,
    /// An optional explanation for readers; it has no execution or authorization effect.
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
enum FunctionRuntime {
    Rhai,
}

/// Omitted limits use the bounded pure default; explicit values only narrow it.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
struct NarrowedLimits {
    /// Maximum interpreter operations, from 1 to the 100000-operation profile ceiling.
    #[serde(default)]
    operations: Option<BoundedU32<1, MAXIMUM_FUNCTION_OPERATIONS>>,
    /// Maximum nested calls, from 1 to the 32-level profile ceiling.
    #[serde(default)]
    call_levels: Option<BoundedU32<1, MAXIMUM_FUNCTION_CALL_LEVELS>>,
    /// Maximum expression nesting, from 1 to the 64-level profile ceiling.
    #[serde(default)]
    expression_depth: Option<BoundedU32<1, MAXIMUM_FUNCTION_EXPRESSION_DEPTH>>,
    /// Maximum string bytes, from 1 to the 16384-byte profile ceiling.
    #[serde(default)]
    string_bytes: Option<BoundedU32<1, MAXIMUM_FUNCTION_STRING_BYTES>>,
    /// Maximum array entries, from 1 to the 256-entry profile ceiling.
    #[serde(default)]
    array_items: Option<BoundedU32<1, MAXIMUM_FUNCTION_ARRAY_ITEMS>>,
    /// Maximum object entries, from 1 to the 256-entry profile ceiling.
    #[serde(default)]
    map_entries: Option<BoundedU32<1, MAXIMUM_FUNCTION_MAP_ENTRIES>>,
    /// Maximum source bytes, from 1 to the 65536-byte profile ceiling.
    #[serde(default)]
    source_bytes: Option<BoundedU32<1, MAXIMUM_FUNCTION_SOURCE_BYTES>>,
}
impl NarrowedLimits {
    fn effective(self) -> FunctionLimits {
        let defaults = FunctionLimits::default();
        FunctionLimits {
            operations: self
                .operations
                .map_or(defaults.operations, |v| u64::from(v.get())),
            call_levels: self
                .call_levels
                .map_or(defaults.call_levels, |v| v.get() as usize),
            expression_depth: self
                .expression_depth
                .map_or(defaults.expression_depth, |v| v.get() as usize),
            string_bytes: self
                .string_bytes
                .map_or(defaults.string_bytes, |v| v.get() as usize),
            array_items: self
                .array_items
                .map_or(defaults.array_items, |v| v.get() as usize),
            map_entries: self
                .map_entries
                .map_or(defaults.map_entries, |v| v.get() as usize),
            source_bytes: self
                .source_bytes
                .map_or(defaults.source_bytes, |v| v.get() as usize),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
struct AuthoredWorkflow {
    /// The typed Workflow start input, or a mapping supplying the called Operation input.
    input: Schema,
    /// Maximum seconds from Run admission to expiry, from 1 to 31536000.
    deadline_seconds: BoundedU32<1, 31_536_000>,
    /// The stable Step ID every Run begins at.
    start: LocalId,
    /// Steps keyed by stable ID; map ordering has no execution meaning.
    steps: BTreeMap<LocalId, AuthoredStep>,
    /// Named terminal result schemas used by finish Steps.
    outcomes: BTreeMap<LocalId, Schema>,
}

#[derive(Debug, Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
enum Reference {
    /// Reads the Workflow input.
    Input {
        /// An optional RFC 6901 pointer; omit it to read the entire value.
        #[serde(default)]
        path: Option<JsonPointer>,
    },
    /// Reads an earlier accepted call or completed wait on every incoming route.
    Step {
        /// The preceding accepted call or completed wait Step whose value is read.
        step: LocalId,
        /// An optional RFC 6901 pointer; omit it to read the entire value.
        #[serde(default)]
        path: Option<JsonPointer>,
    },
    /// Supplies one bounded literal JSON value.
    Literal {
        /// A literal JSON value; it remains subject to bounded value checks.
        value: ForeignValue,
    },
}
registry_platform_yaml::tagged_union!(Reference);

#[derive(Debug, Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
enum AuthoredMapping {
    /// Computes a value with a declared typed pure Function.
    Function {
        /// A declared pure Function called with an object of named inputs.
        function: LocalId,
        /// Named input schemas or references; every declared input is required exactly once.
        inputs: BTreeMap<LocalId, Reference>,
    },
    /// Builds an object from named references and literals.
    Fields {
        /// Object members built from typed references or literals.
        fields: Fields,
    },
    /// Reads the Workflow input.
    Input {
        /// An optional RFC 6901 pointer; omit it to read the entire value.
        #[serde(default)]
        path: Option<JsonPointer>,
    },
    /// Reads an earlier accepted call or completed wait on every incoming route.
    Step {
        /// The preceding accepted call or completed wait Step whose value is read.
        step: LocalId,
        /// An optional RFC 6901 pointer; omit it to read the entire value.
        #[serde(default)]
        path: Option<JsonPointer>,
    },
    /// Supplies one bounded literal JSON value.
    Literal {
        /// A literal JSON value; it remains subject to bounded value checks.
        value: ForeignValue,
    },
}
registry_platform_yaml::tagged_union!(AuthoredMapping);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
struct AuthoredCompletionReference {
    /// The preceding accepted call or completed wait Step whose value is read.
    step: LocalId,
    /// One named completion on the referenced call Operation.
    name: LocalId,
}

#[derive(Debug, Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
enum AuthoredStep {
    /// Waits until a computed RFC 3339 instant.
    WaitUntil {
        /// A mapping producing an RFC 3339 instant with an offset.
        wait_until: AuthoredMapping,
        /// The next Step on the successful completion route.
        next: LocalId,
        /// An optional human title; it changes neither stable identity nor behavior revision.
        #[serde(default)]
        title: Option<String>,
        /// An optional explanation for readers; it has no execution or authorization effect.
        #[serde(default)]
        description: Option<String>,
    },
    /// Observes one named completion of an earlier accepted call.
    WaitFor {
        /// A preceding accepted call Step and one named Operation completion.
        completion: AuthoredCompletionReference,
        /// Maximum seconds to wait; it must be shorter than the Workflow deadline.
        timeout_seconds: BoundedU32<1, 31_536_000>,
        /// The next Step on the successful completion route.
        next: LocalId,
        /// An optional Step taken when this wait expires; no completion value is available there.
        #[serde(default)]
        on_timeout: Option<LocalId>,
        /// An optional Step taken after authorized cancellation while waiting; no completion value is available there.
        #[serde(default)]
        on_cancel: Option<LocalId>,
        /// An optional human title; it changes neither stable identity nor behavior revision.
        #[serde(default)]
        title: Option<String>,
        /// An optional explanation for readers; it has no execution or authorization effect.
        #[serde(default)]
        description: Option<String>,
    },
    /// Calls one resolved Operation alias under the current connection authority.
    Call {
        /// One local Operation alias declared under operations.
        operation: LocalId,
        /// The typed Workflow start input, or a mapping supplying the called Operation input.
        input: AuthoredMapping,
        /// The next Step on the successful completion route.
        next: LocalId,
        /// A separate Step taken only for a validated package-declared business refusal.
        #[serde(default)]
        on_declared_refusal: Option<LocalId>,
        /// An optional human title; it changes neither stable identity nor behavior revision.
        #[serde(default)]
        title: Option<String>,
        /// An optional explanation for readers; it has no execution or authorization effect.
        #[serde(default)]
        description: Option<String>,
    },
    /// Selects one explicit graph edge by a typed case label.
    Choose {
        /// A typed mapping producing one of the declared case labels.
        choose: AuthoredMapping,
        /// Explicit label-to-Step edges; no implicit fall-through exists.
        cases: BTreeMap<LocalId, LocalId>,
        /// An optional human title; it changes neither stable identity nor behavior revision.
        #[serde(default)]
        title: Option<String>,
        /// An optional explanation for readers; it has no execution or authorization effect.
        #[serde(default)]
        description: Option<String>,
    },
    /// Finishes with one declared typed outcome.
    Finish {
        /// One declared terminal outcome name.
        outcome: LocalId,
        /// The declared result schema or mapping; Functions and the host enforce it.
        #[serde(default)]
        output: Option<AuthoredMapping>,
        /// An optional human title; it changes neither stable identity nor behavior revision.
        #[serde(default)]
        title: Option<String>,
        /// An optional explanation for readers; it has no execution or authorization effect.
        #[serde(default)]
        description: Option<String>,
    },
}
registry_platform_yaml::tagged_union!(AuthoredStep);

/// At most 64 members of a declarative object mapping.
#[derive(Debug)]
struct Fields(BTreeMap<FieldName, Reference>);
impl<'de> Deserialize<'de> for Fields {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let fields = BTreeMap::deserialize(deserializer)?;
        if fields.len() > definition::MAXIMUM_FIELDS {
            return Err(Invalid::expected(
                "at most 64 fields",
                "Remove fields, or build a larger value in a function.",
            )
            .into_error());
        }
        Ok(Self(fields))
    }
}
#[cfg(feature = "schema")]
impl schemars::JsonSchema for Fields {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Fields".into()
    }
    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let mut schema =
            <BTreeMap<FieldName, Reference> as schemars::JsonSchema>::json_schema(generator);
        let field = generator.subschema_for::<FieldName>();
        let external = generator.subschema_for::<registry_platform_yaml::ExternalId>();
        schema.insert("propertyNames".into(), json!({"allOf":[external,field]}));
        schema.insert("maxProperties".into(), json!(64));
        schema.insert(
            "description".into(),
            json!("Object members built from one typed reference or literal each."),
        );
        schema
    }
}

/// A member name a fields mapping writes.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FieldName(String);

impl<'de> Deserialize<'de> for FieldName {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        if crate::definition::valid_field_name(&name) {
            Ok(Self(name))
        } else {
            Err(Invalid::expected(
                "a field name of 1 to 64 ASCII letters, digits, hyphens or underscores, starting with a letter",
                "Name the member the operation input or outcome declares.",
            )
            .into_error())
        }
    }
}

/// An RFC 6901 JSON Pointer below the root of the referenced value.
#[derive(Debug)]
struct JsonPointer(String);

impl<'de> Deserialize<'de> for JsonPointer {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if crate::definition::valid_pointer(&text) {
            Ok(Self(text))
        } else {
            Err(Invalid::expected(
                "a JSON Pointer of at most 256 characters, such as /member/0",
                "Start the path with /, write ~0 for ~ and ~1 for / inside a member name, or omit path to use the whole value.",
            )
            .into_error())
        }
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for FieldName {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "FieldName".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": "^[A-Za-z][A-Za-z0-9_-]{0,63}$",
            "description": "A member name a fields mapping writes."
        })
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for JsonPointer {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "JsonPointer".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "maxLength": crate::definition::MAXIMUM_PATH_CHARS,
            "pattern": "^/([^~]|~[01])*$",
            "description": "An RFC 6901 JSON Pointer into the referenced value, such as /member/0. Omit path to use the whole value."
        })
    }
}

impl From<Reference> for definition::Reference {
    fn from(reference: Reference) -> Self {
        match reference {
            Reference::Input { path } => Self::Input {
                path: path.map(|p| p.0),
            },
            Reference::Step { step, path } => Self::Step {
                step: step.into_string(),
                path: path.map(|p| p.0),
            },
            Reference::Literal { value } => Self::Literal {
                value: value.into_value(),
            },
        }
    }
}
impl From<AuthoredMapping> for Mapping {
    fn from(mapping: AuthoredMapping) -> Self {
        let reference = match mapping {
            AuthoredMapping::Function { function, inputs } => {
                return Self::Function {
                    function: function.into_string(),
                    inputs: inputs
                        .into_iter()
                        .map(|(id, reference)| (id.into_string(), reference.into()))
                        .collect(),
                }
            }
            AuthoredMapping::Fields { fields } => {
                return Self::Fields {
                    fields: fields
                        .0
                        .into_iter()
                        .map(|(name, reference)| (name.0, reference.into()))
                        .collect(),
                }
            }
            AuthoredMapping::Input { path } => Reference::Input { path },
            AuthoredMapping::Step { step, path } => Reference::Step { step, path },
            AuthoredMapping::Literal { value } => Reference::Literal { value },
        };
        Self::Reference(reference.into())
    }
}

pub(crate) fn asset_path(root: &Path, asset: &str) -> Result<std::path::PathBuf> {
    let relative = Path::new(asset);
    if asset.is_empty()
        || relative.is_absolute()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(CoordinatorError::new(
            "definition.asset",
            "the asset must be a relative path inside this project",
        )
        .suggest(
            "Use a regular project asset with a relative path and no parent-directory segments.",
        ));
    }
    let root = root.canonicalize().map_err(|_| {
        CoordinatorError::new("definition.read", "the project root is unavailable").with_exit(3)
    })?;
    let candidate = root.join(relative).canonicalize().map_err(|_| {
        CoordinatorError::new("definition.read", "the project asset is unavailable")
            .with_exit(3)
            .suggest(
                "Restore the named generated contract or Function source asset inside the project.",
            )
    })?;
    if !candidate.starts_with(&root) || !candidate.is_file() {
        return Err(CoordinatorError::new(
            "definition.asset",
            "the asset escapes the project or is not a regular file",
        )
        .suggest("Keep the named regular asset within the project directory."));
    }
    Ok(candidate)
}

/// The shared reader preserves field paths and positions before compilation.
pub fn parse_project(path: &Path, bytes: impl AsRef<[u8]>) -> Result<(Workflow, Document)> {
    let mut expressions = AuthoredExpressions;
    let document = Reader::new(path.to_string_lossy())
        .with_hook(&mut expressions)
        .read(bytes.as_ref(), &Expect::one(&FORMAT))
        .map_err(CoordinatorError::from_report)?;
    let project: CoordinatorProject = document.decode().map_err(CoordinatorError::from_report)?;
    let mut workflow = compile(project, path).map_err(|error| positioned(&document, error))?;
    workflow.references = reference_sites(&document);
    Ok((workflow, document))
}

fn compile(project: CoordinatorProject, path: &Path) -> Result<Workflow> {
    let root = path.parent().unwrap_or_else(|| Path::new("."));
    let mut imported = BTreeMap::new();
    for (id, contract) in project.contracts {
        let _product = contract.product;
        let asset = asset_path(root, &contract.source)
            .map_err(|error| error.at("workflow.yaml", format!("/contracts/{id}/source")))?;
        let bytes = definition::read_bytes(&asset, 1_048_576)
            .map_err(|error| error.at("workflow.yaml", format!("/contracts/{id}/source")))?;
        if bytes.len() > 1_048_576 {
            return Err(schema_error(
                format!("/contracts/{id}/source"),
                "the imported contract exceeds its byte bound",
            ));
        }
        let value = registry_platform_canonical_json::parse_json_strict(&bytes).map_err(|_| {
            schema_error(
                format!("/contracts/{id}/source"),
                "the generated contract must be strict JSON",
            )
        })?;
        imported.insert(id.into_string(), value);
    }
    let raw_types = project
        .types
        .into_iter()
        .map(|(id, schema)| (id.into_string(), schema.0.into_value()))
        .collect::<BTreeMap<_, _>>();
    let mut operations = BTreeMap::new();
    let mut authored_completions = BTreeMap::new();
    for (id, operation) in project.operations {
        let id = id.into_string();
        let uses = Operation::from_catalog_id(&operation.uses).ok_or_else(|| {
            schema_error(
                format!("/operations/{id}/uses"),
                "uses must name an exact versioned host catalog Operation",
            )
        })?;
        if let Some(action) = &operation.action {
            if uses != Operation::InvokeBregAction {
                return Err(schema_error(
                    format!("/operations/{id}/action"),
                    "only BReg Action invocation accepts an Action contract selection",
                ));
            }
            let export = imported.get(action.contract.as_str()).ok_or_else(|| {
                schema_error(
                    format!("/operations/{id}/action/contract"),
                    "select a declared local contract import",
                )
            })?;
            if let Some(entries) = export.get("actions").and_then(Value::as_array) {
                if entries
                    .iter()
                    .filter(|entry| {
                        entry.get("id").and_then(Value::as_str) == Some(action.id.as_str())
                    })
                    .count()
                    != 1
                {
                    return Err(schema_error(
                        format!("/operations/{id}/action/id"),
                        "select exactly one Action ID from the imported contract",
                    ));
                }
            }
        }
        let contract_field = operation.action.as_ref().map_or_else(
            || format!("/operations/{id}/action"),
            |action| format!("/contracts/{}/source", action.contract),
        );
        let action = operation
            .action
            .map(|action| json!({"contract":action.contract.as_str(),"id":action.id.as_str()}));
        let contract = crate::contracts::resolve_operation(uses, action.as_ref(), &imported)
            .map_err(|error| error.at("workflow.yaml", contract_field))?;
        if operation.response_schema.is_some() && uses != Operation::ExternalGet {
            return Err(schema_error(
                format!("/operations/{id}/responseSchema"),
                "only the bounded external GET profile accepts a response specialization",
            ));
        }
        let mut completions = BTreeMap::new();
        if uses == Operation::SubmitReviewRequest {
            let output = crate::contracts::casework_completion_schema().clone();
            completions.insert(
                "result".into(),
                CompletionDefinition {
                    kind: CompletionKind::CaseworkResult {},
                    output,
                    revision: String::new(),
                },
            );
        }
        if uses == Operation::SubmitBregProposal {
            completions.insert(
                "application".into(),
                CompletionDefinition {
                    kind: CompletionKind::BregApplication {},
                    output: crate::contracts::breg_application_schema().clone(),
                    revision: String::new(),
                },
            );
        }
        authored_completions.insert(id.clone(), operation.completions);
        operations.insert(
            id,
            ResolvedOperation {
                uses,
                connection: operation.connection.into_string(),
                input: contract.input,
                output: operation
                    .response_schema
                    .map_or(contract.output, |schema| schema.0.into_value()),
                refusal: contract.declared_refusal,
                completions,
                revision: String::new(),
                action: contract.action,
                title: operation.title,
                description: operation.description,
            },
        );
    }
    // Base operation schemas resolve before Function signatures. No completion
    // output may take part in that graph, so a completion cannot define itself.
    let raw_operations = operations.clone();
    let resolver = Schemas {
        types: &raw_types,
        operations: &raw_operations,
        completions: false,
    };
    for (id, operation) in &mut operations {
        operation.input = resolver.resolve(&operation.input, &format!("/operations/{id}/input"))?;
        operation.output =
            resolver.resolve(&operation.output, &format!("/operations/{id}/output"))?;
        operation.refusal = operation
            .refusal
            .as_ref()
            .map(|schema| resolver.resolve(schema, &format!("/operations/{id}/refusal")))
            .transpose()?;
    }
    let base = operations.clone();
    // Interpretation Functions can see only resolved base Operation schemas
    // and host-owned completions. Downstream Functions resolve after bounded
    // completion bindings, so ordinary mappings can consume their typed output.
    let resolver = Schemas {
        types: &raw_types,
        operations: &base,
        completions: true,
    };
    let interpreters = authored_completions
        .values()
        .flat_map(|completions| completions.values())
        .map(|completion| match completion {
            AuthoredCompletion::BoundedPoll { interpret, .. } => interpret.as_str().to_owned(),
        })
        .collect::<BTreeSet<_>>();
    let mut functions = BTreeMap::new();
    let mut downstream = Vec::new();
    for (id, function) in project.functions {
        if interpreters.contains(id.as_str()) {
            functions.insert(
                id.as_str().to_owned(),
                resolve_function(id.as_str(), function, &resolver)?,
            );
        } else {
            downstream.push((id, function));
        }
    }
    for (operation_id, completions) in authored_completions {
        for (name, completion) in completions {
            let name = name.into_string();
            let operation = operations
                .get_mut(&operation_id)
                .expect("the base alias exists");
            if operation.completions.contains_key(&name) {
                return Err(schema_error(
                    format!("/operations/{operation_id}/completions/{name}"),
                    "a host-owned completion cannot be replaced",
                ));
            }
            let AuthoredCompletion::BoundedPoll {
                interpret,
                interval_seconds,
            } = completion;
            if operation.uses != Operation::ExternalGet {
                return Err(schema_error(
                    format!("/operations/{operation_id}/completions/{name}"),
                    "bounded-poll is available only on the host's read-only external GET Operation",
                ));
            }
            let function = functions.get(interpret.as_str()).ok_or_else(|| {
                schema_error(
                    format!("/operations/{operation_id}/completions/{name}/interpret"),
                    "the interpretation Function is not declared",
                )
            })?;
            if function.inputs.len() != 2
                || function.inputs.get("command") != Some(&operation.input)
                || function.inputs.get("response") != Some(&operation.output)
            {
                return Err(schema_error(format!("/operations/{operation_id}/completions/{name}/interpret"), "the interpretation Function must take command and response with the owning Operation's exact schemas"));
            }
            let output =
                terminal_schema(&function.output, &format!("/functions/{interpret}/output"))?;
            operation.completions.insert(
                name,
                CompletionDefinition {
                    kind: CompletionKind::BoundedPoll {
                        interpret: interpret.into_string(),
                        interval_seconds: interval_seconds.get(),
                    },
                    output,
                    revision: String::new(),
                },
            );
        }
    }
    let resolver = Schemas {
        types: &raw_types,
        operations: &operations,
        completions: true,
    };
    for (id, function) in downstream {
        functions.insert(
            id.as_str().to_owned(),
            resolve_function(id.as_str(), function, &resolver)?,
        );
    }
    let input = resolver.resolve(&project.workflow.input.0.into_value(), "/workflow/input")?;
    let outcomes = project
        .workflow
        .outcomes
        .into_iter()
        .map(|(id, schema)| {
            let id = id.into_string();
            resolver
                .resolve(&schema.0.into_value(), &format!("/workflow/outcomes/{id}"))
                .map(|schema| (id, schema))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let types = raw_types
        .iter()
        .map(|(id, schema)| {
            resolver
                .resolve(schema, &format!("/types/{id}"))
                .map(|schema| (id.clone(), schema))
        })
        .collect::<Result<_>>()?;
    let mut steps = BTreeMap::new();
    let mut presentation = Presentation {
        title: project.title,
        description: project.description,
        steps: BTreeMap::new(),
    };
    for (id, step) in project.workflow.steps {
        let id = id.into_string();
        let (step, title, description) = match step {
            AuthoredStep::WaitUntil {
                wait_until,
                next,
                title,
                description,
            } => (
                Step::WaitUntil {
                    wait_until: wait_until.into(),
                    next: next.into_string(),
                },
                title,
                description,
            ),
            AuthoredStep::WaitFor {
                completion,
                timeout_seconds,
                next,
                on_timeout,
                on_cancel,
                title,
                description,
            } => (
                Step::WaitFor {
                    wait_for: CompletionReference {
                        step: completion.step.into_string(),
                        name: completion.name.into_string(),
                    },
                    timeout_seconds: timeout_seconds.get(),
                    next: next.into_string(),
                    on_timeout: on_timeout.map(LocalId::into_string),
                    on_cancel: on_cancel.map(LocalId::into_string),
                },
                title,
                description,
            ),
            AuthoredStep::Call {
                operation,
                input,
                next,
                on_declared_refusal,
                title,
                description,
            } => {
                let resolved = operations.get(operation.as_str()).ok_or_else(|| {
                    CoordinatorError::new("definition.operation",format!("Operation alias {} is not declared; available aliases are {}",operation.as_str(),definition::listed(operations.keys().map(String::as_str))))
                        .at("workflow.yaml",format!("/workflow/steps/{id}/operation"))
                        .suggest("Name one of the declared Operation aliases, or define a versioned catalog binding under operations.")
                })?;
                (
                    Step::Call {
                        call: Call {
                            alias: operation.into_string(),
                            operation: resolved.uses,
                            connection: resolved.connection.clone(),
                        },
                        input: input.into(),
                        next: next.into_string(),
                        on_declared_refusal: on_declared_refusal.map(LocalId::into_string),
                    },
                    title,
                    description,
                )
            }
            AuthoredStep::Choose {
                choose,
                cases,
                title,
                description,
            } => (
                Step::Choose {
                    choose: choose.into(),
                    cases: cases
                        .into_iter()
                        .map(|(name, target)| (name.into_string(), target.into_string()))
                        .collect(),
                },
                title,
                description,
            ),
            AuthoredStep::Finish {
                outcome,
                output,
                title,
                description,
            } => (
                Step::Finish {
                    finish: outcome.into_string(),
                    output: output.map(Into::into),
                },
                title,
                description,
            ),
        };
        if title.is_some() || description.is_some() {
            presentation
                .steps
                .insert(id.clone(), json!({"title":title,"description":description}));
        }
        steps.insert(id, step);
    }
    let connections = steps
        .values()
        .filter_map(|step| match step {
            Step::Call { call, .. } => {
                Some((call.connection.clone(), call.operation.product().to_owned()))
            }
            _ => None,
        })
        .collect();
    Ok(Workflow {
        api_version: definition::API_VERSION.into(),
        kind: "Workflow".into(),
        id: project.project.id.into_string(),
        version: project.project.version,
        input,
        connections,
        functions,
        operations,
        types,
        contracts: imported,
        presentation,
        references: BTreeMap::new(),
        deadline: format!("{}s", project.workflow.deadline_seconds.get()),
        start: project.workflow.start.into_string(),
        steps,
        outcomes,
    })
}

fn resolve_function(
    id: &str,
    function: AuthoredFunction,
    resolver: &Schemas<'_>,
) -> Result<FunctionDefinition> {
    let _runtime = function.runtime;
    let inputs = function
        .inputs
        .into_iter()
        .map(|(name, schema)| {
            let name = name.into_string();
            resolver
                .resolve(
                    &schema.0.into_value(),
                    &format!("/functions/{id}/inputs/{name}"),
                )
                .map(|schema| (name, schema))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let output = resolver.resolve(
        &function.output.0.into_value(),
        &format!("/functions/{id}/output"),
    )?;
    Ok(FunctionDefinition {
        runtime: "rhai".into(),
        profile: crate::functions::PURE_PROFILE.into(),
        capabilities: BTreeSet::new(),
        abi: crate::functions::INTERPRETER_ABI.into(),
        source: function.source,
        entrypoint: function.entrypoint,
        inputs,
        output,
        limits: function.limits.effective(),
        revision: String::new(),
        title: function.title,
        description: function.description,
    })
}

fn reference_sites(document: &Document) -> BTreeMap<String, definition::SourceReference> {
    fn walk(
        document: &Document,
        value: &Value,
        path: &str,
        sites: &mut BTreeMap<String, definition::SourceReference>,
        schema: bool,
    ) {
        match value {
            Value::Object(object) => {
                for (name, value) in object {
                    let pointer = format!("{path}/{}", name.replace('~', "~0").replace('/', "~1"));
                    let target = match (name.as_str(), value.as_str()) {
                        ("typeRef", Some(id)) if schema => Some(format!("/types/{id}")),
                        ("operationInput" | "operationOutput" | "operationRefusal", Some(id))
                            if schema =>
                        {
                            Some(format!("/operations/{id}"))
                        }
                        ("operation", Some(id))
                            if !schema && path.starts_with("/workflow/steps/") =>
                        {
                            Some(format!("/operations/{id}"))
                        }
                        ("function" | "interpret", Some(id)) if !schema => {
                            Some(format!("/functions/{id}"))
                        }
                        (
                            "next" | "onTimeout" | "onCancel" | "onDeclaredRefusal" | "step",
                            Some(id),
                        ) if !schema && path.starts_with("/workflow/steps/") => {
                            Some(format!("/workflow/steps/{id}"))
                        }
                        (_, Some(id)) if !schema && path.ends_with("/cases") => {
                            Some(format!("/workflow/steps/{id}"))
                        }
                        ("start", Some(id)) if !schema && path == "/workflow" => {
                            Some(format!("/workflow/steps/{id}"))
                        }
                        ("outcome", Some(id))
                            if !schema && path.starts_with("/workflow/steps/") =>
                        {
                            Some(format!("/workflow/outcomes/{id}"))
                        }
                        ("contract", Some(id)) if !schema && path.ends_with("/action") => {
                            Some(format!("/contracts/{id}"))
                        }
                        ("source", Some(asset))
                            if !schema
                                && (path.starts_with("/functions/")
                                    || path.starts_with("/contracts/")) =>
                        {
                            Some(format!("asset:{asset}"))
                        }
                        ("completionOutput", _) if schema => value
                            .get("operation")
                            .and_then(Value::as_str)
                            .zip(value.get("name").and_then(Value::as_str))
                            .map(|(operation, name)| {
                                format!("/operations/{operation}/completions/{name}")
                            }),
                        _ => None,
                    };
                    if let Some(target) = target {
                        let mut source = document
                            .diagnostic_at_value(
                                Severity::Error,
                                "coordinator.reference",
                                &pointer,
                                "",
                                "",
                            )
                            .source
                            .expect("a document has a source");
                        source.file = "workflow.yaml".into();
                        sites.insert(
                            pointer.clone(),
                            definition::SourceReference { target, source },
                        );
                    }
                    if schema {
                        match name.as_str() {
                            "properties" | "patternProperties" | "$defs" | "definitions"
                            | "dependentSchemas" => {
                                if let Some(members) = value.as_object() {
                                    for (member, schema) in members {
                                        let member = member.replace('~', "~0").replace('/', "~1");
                                        walk(
                                            document,
                                            schema,
                                            &format!("{pointer}/{member}"),
                                            sites,
                                            true,
                                        );
                                    }
                                }
                            }
                            "items"
                            | "additionalProperties"
                            | "unevaluatedProperties"
                            | "contains"
                            | "propertyNames"
                            | "not"
                            | "if"
                            | "then"
                            | "else"
                            | "additionalItems"
                            | "unevaluatedItems"
                            | "oneOf"
                            | "anyOf"
                            | "allOf"
                            | "prefixItems" => walk(document, value, &pointer, sites, true),
                            _ => {}
                        }
                    } else if !(object.get("type").and_then(Value::as_str) == Some("literal")
                        && name == "value")
                    {
                        walk(document, value, &pointer, sites, schema_root(&pointer));
                    }
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    walk(document, item, &format!("{path}/{index}"), sites, schema);
                }
            }
            _ => {}
        }
    }
    fn schema_root(path: &str) -> bool {
        let parts = path.split('/').collect::<Vec<_>>();
        matches!(
            parts.as_slice(),
            ["", "types", _]
                | ["", "functions", _, "output"]
                | ["", "functions", _, "inputs", _]
                | ["", "operations", _, "responseSchema"]
                | ["", "workflow", "input"]
                | ["", "workflow", "outcomes", _]
        )
    }
    let mut sites = BTreeMap::new();
    let root = document.to_json_value();
    walk(document, &root, "", &mut sites, false);
    if let Some(steps) = root.pointer("/workflow/steps").and_then(Value::as_object) {
        for (id, step) in steps {
            let Some(reference) = step.get("completion") else {
                continue;
            };
            let Some(accepted) = reference.get("step").and_then(Value::as_str) else {
                continue;
            };
            let Some(name) = reference.get("name").and_then(Value::as_str) else {
                continue;
            };
            let Some(alias) = steps
                .get(accepted)
                .and_then(|step| step.get("operation"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            let pointer = format!("/workflow/steps/{id}/completion/name");
            let mut source = document
                .diagnostic_at_value(Severity::Error, "coordinator.reference", &pointer, "", "")
                .source
                .expect("a document has a source");
            source.file = "workflow.yaml".into();
            sites.insert(
                pointer,
                definition::SourceReference {
                    target: format!("/operations/{alias}/completions/{name}"),
                    source,
                },
            );
        }
    }
    sites
}

fn schema_error(field: String, message: &str) -> CoordinatorError {
    CoordinatorError::new("definition.schema-reference", message).at("workflow.yaml", field)
        .suggest("Use one declared whole-schema reference, or write one valid inline JSON Schema without reference markers.")
}

struct Schemas<'a> {
    types: &'a BTreeMap<String, Value>,
    operations: &'a BTreeMap<String, ResolvedOperation>,
    completions: bool,
}
impl Schemas<'_> {
    fn resolve(&self, schema: &Value, field: &str) -> Result<Value> {
        let resolved = self.walk(schema, field, field, &mut BTreeSet::new(), 0)?;
        definition::compile_schema(&resolved).map_err(|error| error.at("workflow.yaml", field))?;
        Ok(resolved)
    }
    fn walk(
        &self,
        schema: &Value,
        field: &str,
        root_field: &str,
        stack: &mut BTreeSet<String>,
        depth: usize,
    ) -> Result<Value> {
        if depth > 32 {
            return Err(schema_error(
                field.into(),
                "schema resolution exceeds 32 levels",
            ));
        }
        let Some(object) = schema.as_object() else {
            return if schema.is_boolean() {
                Ok(schema.clone())
            } else {
                Err(schema_error(
                    field.into(),
                    "a schema must be an object or boolean",
                ))
            };
        };
        let markers = [
            "typeRef",
            "operationInput",
            "operationOutput",
            "operationRefusal",
            "completionOutput",
        ];
        if let Some(marker) = markers.iter().find(|marker| object.contains_key(**marker)) {
            if object.len() != 1 {
                return Err(schema_error(
                    field.into(),
                    "a schema reference cannot be mixed with inline keywords or another reference",
                ));
            }
            let key = format!("{marker}:{}", object[*marker]);
            if !stack.insert(key.clone()) {
                return Err(schema_error(field.into(), "schema references form a cycle"));
            }
            let name = object[*marker].as_str();
            let target = match *marker {
                "typeRef" => name.and_then(|name| self.types.get(name)),
                "operationInput" => name
                    .and_then(|name| self.operations.get(name))
                    .map(|operation| &operation.input),
                "operationOutput" => name
                    .and_then(|name| self.operations.get(name))
                    .map(|operation| &operation.output),
                "operationRefusal" => name
                    .and_then(|name| self.operations.get(name))
                    .and_then(|operation| operation.refusal.as_ref()),
                "completionOutput" if self.completions => {
                    let reference = object[*marker].as_object();
                    if reference.is_some_and(|reference| {
                        reference.len() != 2
                            || !reference.contains_key("operation")
                            || !reference.contains_key("name")
                    }) {
                        return Err(schema_error(
                            field.into(),
                            "completionOutput requires exactly operation and name",
                        ));
                    }
                    reference
                        .and_then(|reference| {
                            self.operations.get(reference.get("operation")?.as_str()?)
                        })
                        .and_then(|operation| {
                            operation.completions.get(object[*marker]["name"].as_str()?)
                        })
                        .map(|completion| &completion.output)
                }
                _ => None,
            }
            .ok_or_else(|| {
                schema_error(
                    field.into(),
                    "the schema reference is undeclared or unavailable in this resolution stage",
                )
            })?;
            let mut resolved = self.walk(target, field, field, stack, depth + 1)?;
            let prefix = field.strip_prefix(root_field).unwrap_or("");
            rebase_schema(&mut resolved, prefix, field)?;
            stack.remove(&key);
            return Ok(resolved);
        }
        let mut resolved = object.clone();
        for keyword in [
            "properties",
            "patternProperties",
            "$defs",
            "definitions",
            "dependentSchemas",
        ] {
            if let Some(Value::Object(properties)) = object.get(keyword) {
                let members = properties
                    .iter()
                    .map(|(name, schema)| {
                        self.walk(
                            schema,
                            &format!(
                                "{field}/{keyword}/{}",
                                name.replace('~', "~0").replace('/', "~1")
                            ),
                            root_field,
                            stack,
                            depth + 1,
                        )
                        .map(|schema| (name.clone(), schema))
                    })
                    .collect::<Result<serde_json::Map<_, _>>>()?;
                resolved.insert(keyword.into(), Value::Object(members));
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
            if let Some(schema) = object.get(keyword) {
                resolved.insert(
                    keyword.into(),
                    self.walk(
                        schema,
                        &format!("{field}/{keyword}"),
                        root_field,
                        stack,
                        depth + 1,
                    )?,
                );
            }
        }
        for keyword in ["oneOf", "anyOf", "allOf", "prefixItems"] {
            if let Some(Value::Array(schemas)) = object.get(keyword) {
                let schemas = schemas
                    .iter()
                    .enumerate()
                    .map(|(index, schema)| {
                        self.walk(
                            schema,
                            &format!("{field}/{keyword}/{index}"),
                            root_field,
                            stack,
                            depth + 1,
                        )
                    })
                    .collect::<Result<Vec<_>>>()?;
                resolved.insert(keyword.into(), Value::Array(schemas));
            }
        }
        let resolved = Value::Object(resolved);
        Ok(resolved)
    }
}

pub(crate) fn embed_schema(schema: &Value, prefix: &str) -> Result<Value> {
    let mut embedded = schema.clone();
    rebase_schema(&mut embedded, prefix, "")?;
    Ok(embedded)
}

/// Keep a referenced schema's local JSON Pointers bound to its own root
/// when the whole schema is embedded below another schema's root.
fn rebase_schema(schema: &mut Value, prefix: &str, field: &str) -> Result<()> {
    if prefix.is_empty() {
        return Ok(());
    }
    let Some(object) = schema.as_object_mut() else {
        return Ok(());
    };
    for keyword in ["$ref", "$dynamicRef", "$recursiveRef"] {
        if let Some(reference) = object.get_mut(keyword) {
            let text = reference.as_str().ok_or_else(|| {
                schema_error(field.into(), "a local schema reference must be text")
            })?;
            if text == "#" || text.starts_with("#/") {
                *reference = json!(format!("#{prefix}{}", &text[1..]));
            } else if text.starts_with('#') {
                return Err(schema_error(field.into(), "named schema anchors cannot be embedded through a whole-schema reference; use a local JSON Pointer"));
            }
        }
    }
    for keyword in [
        "properties",
        "patternProperties",
        "$defs",
        "definitions",
        "dependentSchemas",
    ] {
        if let Some(Value::Object(members)) = object.get_mut(keyword) {
            for schema in members.values_mut() {
                rebase_schema(schema, prefix, field)?;
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
        if let Some(schema) = object.get_mut(keyword) {
            rebase_schema(schema, prefix, field)?;
        }
    }
    for keyword in ["oneOf", "anyOf", "allOf", "prefixItems"] {
        if let Some(Value::Array(schemas)) = object.get_mut(keyword) {
            for schema in schemas {
                rebase_schema(schema, prefix, field)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn terminal_schema(schema: &Value, field: &str) -> Result<Value> {
    let branches = schema.get("oneOf").and_then(Value::as_array).ok_or_else(|| schema_error(field.into(), "a polling interpretation declares pending, complete and refused object variants with oneOf"))?;
    let mut states = BTreeSet::new();
    let mut terminal = Vec::new();
    for branch in branches {
        let state = branch
            .pointer("/properties/state/const")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                schema_error(
                    field.into(),
                    "each polling interpretation variant has a constant state",
                )
            })?;
        if !states.insert(state)
            || branch.get("type") != Some(&json!("object"))
            || branch.get("additionalProperties") != Some(&json!(false))
            || !branch
                .get("required")
                .and_then(Value::as_array)
                .is_some_and(|required| required.contains(&json!("state")))
        {
            return Err(schema_error(
                field.into(),
                "polling interpretation states must be distinct closed objects requiring state",
            ));
        }
        match state {
            "pending" => {},
            "complete" if branch.pointer("/properties/result").is_some() && branch["required"].as_array().is_some_and(|required| required.contains(&json!("result"))) => terminal.push(branch.clone()),
            "refused" if branch.pointer("/properties/code/enum").and_then(Value::as_array).is_some_and(|codes| !codes.is_empty() && codes.iter().all(Value::is_string)) && branch["required"].as_array().is_some_and(|required| required.contains(&json!("code"))) => terminal.push(branch.clone()),
            _ => return Err(schema_error(field.into(), "complete requires result; refused requires a closed enum code; only pending, complete and refused states exist")),
        }
    }
    if states != BTreeSet::from(["pending", "complete", "refused"]) {
        return Err(schema_error(
            field.into(),
            "polling interpretation must declare pending, complete and refused exactly once",
        ));
    }
    // Removing pending changes oneOf indexes. Bind every local reference to
    // the original interpretation root so reused result schemas and recursive
    // local definitions keep the same meaning in the terminal-only union.
    let prefix = "/$defs/interpretation";
    let original = embed_schema(schema, prefix)?;
    let mut output = original
        .as_object()
        .expect("oneOf belongs to an object")
        .clone();
    output.insert("$defs".into(), json!({"interpretation":original}));
    output.insert(
        "oneOf".into(),
        Value::Array(
            terminal
                .iter()
                .map(|branch| embed_schema(branch, prefix))
                .collect::<Result<Vec<_>>>()?,
        ),
    );
    Ok(Value::Object(output))
}

/// One refusal that carries every finding, each placed in the authored
/// project.
pub(crate) fn placed(document: &Document, findings: Vec<CoordinatorError>) -> CoordinatorError {
    let diagnostics = findings
        .into_iter()
        .flat_map(|finding| positioned(document, finding).diagnostics.into_vec())
        .collect::<Vec<_>>();
    CoordinatorError::from_diagnostics(&diagnostics)
}

/// Project execution checks refer to the stable IR. Point their diagnostics
/// back at the corresponding member in the authored document.
pub(crate) fn positioned(document: &Document, error: CoordinatorError) -> CoordinatorError {
    if !error.diagnostics.is_empty() {
        return error;
    }
    // A function's own definition is placed in functions.rhai; a function
    // that fails while a step evaluates it is placed at that step.
    if error.code.starts_with("function.")
        && !matches!(
            error.code.as_str(),
            "function.value_limit" | "function.json"
        )
        && error.file.as_deref() != Some(Path::new("workflow.yaml"))
    {
        let mut error = error;
        error
            .file
            .get_or_insert_with(|| Path::new("functions.rhai").into());
        return CoordinatorError::from_report(error.report());
    }
    let exit = error.exit_code;
    let field = error.field.as_deref().unwrap_or("");
    let mut pointer = if field.starts_with('/') {
        field.to_owned()
    } else if field.is_empty() {
        String::new()
    } else {
        format!("/{}", field.replace(['.', '['], "/").replace(']', ""))
    };
    pointer = match pointer.as_str() {
        "/id" => "/project/id".into(),
        "/version" => "/project/version".into(),

        "/deadline" => "/workflow/deadlineSeconds".into(),
        _ => {
            let mut parts = pointer.split('/').map(str::to_owned).collect::<Vec<_>>();
            if parts.len() > 3 && parts[1] == "steps" {
                if parts[3] == "call" {
                    parts.remove(3);
                } else if parts[3] == "finish" {
                    parts[3] = "outcome".into();
                } else if parts[3] == "waitFor" {
                    parts[3] = "completion".into();
                }
            }
            if parts.get(1).is_some_and(|part| {
                matches!(part.as_str(), "steps" | "outcomes" | "input" | "start")
            }) {
                parts.insert(1, "workflow".into());
            }
            parts.join("/")
        }
    };
    let code = if error.code.starts_with("coordinator.") {
        error.code.replace('_', "-")
    } else {
        format!("coordinator.{}", error.code.replace('_', "-"))
    };
    CoordinatorError::from_diagnostics(&[document.diagnostic_at_value(
        Severity::Error,
        &code,
        &pointer,
        &error.message,
        error
            .suggested_action
            .as_deref()
            .unwrap_or("Correct the named project member and rerun check."),
    )])
    .with_exit(exit)
}

#[cfg(feature = "schema")]
pub fn project_schema() -> std::result::Result<String, serde_json::Error> {
    let mut schema = serde_json::to_value(schemars::schema_for!(CoordinatorProject))?;
    crate::schema::finish(&mut schema, API_VERSION, KIND, SCHEMA_ID);
    let identity = schema["properties"]["project"].take();
    schema["properties"]["project"] = json!({"description":"The shared Project identity; its version is a human release label, not the computed Workflow revision.",
        "unevaluatedProperties":false,"allOf":[identity,{"properties":{"version":{"type":"string","minLength":1,"maxLength":64,"pattern":"^[A-Za-z0-9_-]+$","description":"A bounded human release label; it does not replace the computed Workflow revision."}}}]});
    schema["$defs"]["ProjectIdentity"]["properties"]["id"]["description"] =
        json!("The stable Workflow API name, also the enclosing Project ID.");
    schema["$defs"]["ProjectIdentity"]["properties"]["version"]["description"] =
        json!("The human release label; it is distinct from the computed Workflow revision.");
    fn maps(value: &mut Value) {
        match value {
            Value::Object(object) => {
                if let Some(Value::Object(patterns)) = object.remove("patternProperties") {
                    if patterns.len() == 1 {
                        object.insert(
                            "additionalProperties".into(),
                            patterns.into_values().next().unwrap(),
                        );
                        object
                            .entry("propertyNames")
                            .or_insert_with(|| json!({"$ref":"#/$defs/LocalId"}));
                    }
                }
                object.values_mut().for_each(maps);
            }
            Value::Array(items) => items.iter_mut().for_each(maps),
            _ => {}
        }
    }
    maps(&mut schema);
    for (pointer, minimum, maximum) in [
        ("/properties/operations", 0, 64),
        ("/properties/functions", 0, 128),
        ("/properties/types", 0, 128),
        ("/$defs/AuthoredWorkflow/properties/steps", 1, 64),
        ("/$defs/AuthoredWorkflow/properties/outcomes", 1, 64),
    ] {
        if let Some(value) = schema.pointer_mut(pointer) {
            value["minProperties"] = json!(minimum);
            value["maxProperties"] = json!(maximum);
        }
    }
    if let Some(variants) = schema
        .pointer_mut("/$defs/AuthoredMapping/oneOf")
        .and_then(Value::as_array_mut)
    {
        for variant in variants {
            if variant
                .pointer("/properties/type/const")
                .and_then(Value::as_str)
                == Some("function")
            {
                variant["properties"]["inputs"]["maxProperties"] = json!(16);
            }
        }
    }
    if let Some(inputs) = schema.pointer_mut("/$defs/AuthoredFunction/properties/inputs") {
        inputs["maxProperties"] = json!(16);
    }
    let mut text = serde_json::to_string_pretty(&schema)?;
    text.push('\n');
    Ok(text)
}
