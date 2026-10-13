// SPDX-License-Identifier: Apache-2.0
//! Portable authoring types. The persisted execution representation stays stable.

use std::{collections::BTreeMap, path::Path};

use registry_platform_config::AuthoredExpressions;
use registry_platform_yaml::{
    ApiVersion, BoundedU32, Document, EnvelopeRule, Expect, ForeignValue, FormatSpec, Invalid,
    LocalId, ProjectIdentity, Reader, Severity,
};
use serde::Deserialize;

use crate::{
    definition::{self, Call, Mapping, Step, Workflow},
    protocol::Operation,
    CoordinatorError, Result,
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
    removed_keys: &[],
};

/// A Coordinator workflow: a finite graph of steps that waits, calls fixed
/// product operations through named connections and finishes with a declared
/// outcome. Its pure functions live in `functions.rhai` beside it.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CoordinatorProject {
    /// The workflow `id` a caller names as `flow` to start a run, and the
    /// `version` of this definition. Give a changed definition a new version.
    pub project: ProjectIdentity,
    /// The JSON Schema (2020-12) every start input must satisfy. Steps read
    /// the input through `{type: input}` references.
    #[cfg_attr(feature = "schema", schemars(extend("x-registry-foreign" = "json-schema-2020-12")))]
    input: ForeignValue,
    /// The logical connections call steps use, each naming the product it
    /// reaches. The runtime configuration binds each one to an endpoint and
    /// its credentials.
    connections: BTreeMap<LocalId, Product>,
    /// The file beside the workflow holding its pure Rhai functions; always
    /// `functions.rhai`.
    functions_file: String,
    /// How long a run may take, in seconds from admission, at most one year.
    /// A run that has not finished by its deadline expires.
    deadline_seconds: BoundedU32<1, 31_536_000>,
    /// The step every run begins with.
    start: LocalId,
    /// The steps of the workflow graph, by step identifier, at most 64.
    steps: BTreeMap<LocalId, AuthoredStep>,
    /// The outcomes a finish step may name, each with the JSON Schema
    /// (2020-12) its output must satisfy.
    outcomes: BTreeMap<LocalId, ForeignValue>,
}

/// The product a connection reaches: `breg` (Base Registry Engine),
/// `casework` (Registry Casework, as a review producer), `messaging`,
/// `scheduling`, `external-http` (a configured external HTTP service) or
/// `decision` (a configured typed decision service).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
enum Product {
    Breg,
    Casework,
    Messaging,
    Scheduling,
    ExternalHttp,
    Decision,
}

impl Product {
    fn name(self) -> &'static str {
        match self {
            Self::Breg => "breg",
            Self::Casework => "casework",
            Self::Messaging => "messaging",
            Self::Scheduling => "scheduling",
            Self::ExternalHttp => "external-http",
            Self::Decision => "decision",
        }
    }
}

/// A value a mapping reads: the workflow input, a preceding call's or wait's
/// output, or an authored literal. A path selects a member inside the value.
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
    /// Reads the workflow input.
    Input {
        /// The member of the input to read; omit it to read the whole input.
        #[serde(default)]
        path: Option<JsonPointer>,
    },
    /// Reads the output of a call step, or of a wait-for step that continued
    /// with `next`, that completed earlier on every route to this one.
    Step {
        /// The call or wait-for step whose output this reads.
        step: LocalId,
        /// The member of the output to read; omit it to read the whole output.
        #[serde(default)]
        path: Option<JsonPointer>,
    },
    /// Supplies an authored JSON value.
    Literal {
        /// The JSON value this reference supplies.
        value: ForeignValue,
    },
}
registry_platform_yaml::tagged_union!(Reference);

/// A call input or finish output: a pure function over references, or an
/// object built member by member from references.
#[derive(Debug, Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
enum AuthoredInput {
    /// Computes the value with a pure function from `functions.rhai`.
    Function {
        /// The function `functions.rhai` exports.
        function: LocalId,
        /// The references passed to the function, in order, at most 16.
        arguments: Vec<Reference>,
    },
    /// Builds an object member by member.
    Fields {
        /// The members to write, each from one reference, at most 64.
        fields: Fields,
    },
}
registry_platform_yaml::tagged_union!(AuthoredInput);

/// A waitUntil instant or a choose label: a pure function over references,
/// or one reference.
#[derive(Debug, Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
enum AuthoredSelector {
    /// Computes the value with a pure function from `functions.rhai`.
    Function {
        /// The function `functions.rhai` exports.
        function: LocalId,
        /// The references passed to the function, in order, at most 16.
        arguments: Vec<Reference>,
    },
    /// Reads the workflow input.
    Input {
        /// The member of the input to read; omit it to read the whole input.
        #[serde(default)]
        path: Option<JsonPointer>,
    },
    /// Reads the output of a call step, or of a wait-for step that continued
    /// with `next`, that completed earlier on every route to this one.
    Step {
        /// The call or wait-for step whose output this reads.
        step: LocalId,
        /// The member of the output to read; omit it to read the whole output.
        #[serde(default)]
        path: Option<JsonPointer>,
    },
    /// Supplies an authored JSON value.
    Literal {
        /// The JSON value this selector supplies.
        value: ForeignValue,
    },
}
registry_platform_yaml::tagged_union!(AuthoredSelector);

/// The members a fields mapping writes, each from one reference.
#[derive(Debug)]
struct Fields(BTreeMap<FieldName, Reference>);

impl<'de> Deserialize<'de> for Fields {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let fields = BTreeMap::deserialize(deserializer)?;
        if fields.len() > crate::definition::MAXIMUM_FIELDS {
            return Err(Invalid::expected(
                "at most 64 fields",
                "Remove fields, or build a larger value in a function.",
            )
            .into_error());
        }
        Ok(Self(fields))
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

/// An operation identifier, resolved against the catalog once the step's
/// connection is known, so a refusal can name what that product offers.
#[derive(Debug)]
struct OperationName(String);

impl<'de> Deserialize<'de> for OperationName {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self)
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for OperationName {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        <Operation as schemars::JsonSchema>::schema_name()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        <Operation as schemars::JsonSchema>::json_schema(generator)
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
impl schemars::JsonSchema for Fields {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Fields".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let mut schema =
            <BTreeMap<FieldName, Reference> as schemars::JsonSchema>::json_schema(generator);
        schema.insert(
            "description".into(),
            "The members a fields mapping writes, each from one reference.".into(),
        );
        schema
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

/// The event a wait-for step waits for, named by its `type`.
#[derive(Debug, Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
enum AuthoredEvent {
    /// The result of a review request: Casework's completion event wakes the
    /// run, and the run reads the result with the producer's own credential.
    ReviewResult {
        /// The call step whose `submit-review-request` the wait correlates
        /// with; it must precede the wait on every route.
        request: LocalId,
    },
}
registry_platform_yaml::tagged_union!(AuthoredEvent);

/// One step of the workflow graph, named by its `type`.
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
    /// Waits until an instant, then continues.
    WaitUntil {
        /// The RFC 3339 instant to wait for.
        wait_until: AuthoredSelector,
        /// The step that follows the wait.
        next: LocalId,
    },
    /// Waits for an event another product delivers, then continues with the
    /// event's value as its output, takes `onTimeout` when the event does not
    /// arrive in time, or takes `onCancel` when an authorized caller cancels
    /// the run while it is durably waiting.
    WaitFor {
        /// The event to wait for.
        event: AuthoredEvent,
        /// How long to wait, in seconds from the start of the wait, at most one
        /// year; it must be shorter than `deadlineSeconds`.
        timeout_seconds: BoundedU32<1, 31_536_000>,
        /// The step that follows the event, with the event's value as this
        /// step's output.
        next: LocalId,
        /// The step that follows a timeout; this step has no output on that
        /// route. Omit it to fail the run with `wait-timed-out`.
        #[serde(default)]
        on_timeout: Option<LocalId>,
        /// The step that follows an authorized cancellation while this wait
        /// is durably parked. Omit it to stop the run with the ordinary
        /// cancellation behavior.
        #[serde(default)]
        on_cancel: Option<LocalId>,
    },
    /// Calls one operation through a connection, then continues with its
    /// successful output available to later steps.
    Call {
        /// The connection the call goes through, declared under `connections`.
        connection: LocalId,
        /// The operation to call; it must belong to the connection's product.
        operation: OperationName,
        /// The operation input, which must satisfy the operation's input
        /// contract.
        input: AuthoredInput,
        /// The step that follows a completed call.
        next: LocalId,
        /// The step that follows a product-declared, no-effect business
        /// refusal. Only operations whose reference declares this capability
        /// accept the member; other refusals still stop the run.
        #[serde(default)]
        on_declared_refusal: Option<LocalId>,
    },
    /// Selects a label and continues with the step its case names.
    Choose {
        /// The label to select; it must be one of `cases`.
        choose: AuthoredSelector,
        /// The step to continue with for each label, at most 32.
        cases: BTreeMap<LocalId, LocalId>,
    },
    /// Ends the run with a declared outcome.
    Finish {
        /// The outcome, declared under `outcomes`.
        outcome: LocalId,
        /// The run output, which must satisfy the outcome's schema. Omit it
        /// when the outcome schema accepts null.
        #[serde(default)]
        output: Option<AuthoredInput>,
    },
}
registry_platform_yaml::tagged_union!(AuthoredStep);

impl From<Reference> for definition::Reference {
    fn from(value: Reference) -> Self {
        match value {
            Reference::Input { path } => Self::Input {
                path: path.map(|path| path.0),
            },
            Reference::Step { step, path } => Self::Step {
                step: step.into_string(),
                path: path.map(|path| path.0),
            },
            Reference::Literal { value } => Self::Literal {
                value: value.into_value(),
            },
        }
    }
}

fn function_mapping(function: LocalId, arguments: Vec<Reference>) -> Mapping {
    Mapping::Function {
        function: function.into_string(),
        arguments: arguments.into_iter().map(Into::into).collect(),
    }
}

impl From<AuthoredInput> for Mapping {
    fn from(value: AuthoredInput) -> Self {
        match value {
            AuthoredInput::Function {
                function,
                arguments,
            } => function_mapping(function, arguments),
            AuthoredInput::Fields { fields } => Self::Fields {
                fields: fields
                    .0
                    .into_iter()
                    .map(|(name, reference)| (name.0, reference.into()))
                    .collect(),
            },
        }
    }
}

impl From<AuthoredSelector> for Mapping {
    fn from(value: AuthoredSelector) -> Self {
        let reference = match value {
            AuthoredSelector::Function {
                function,
                arguments,
            } => return function_mapping(function, arguments),
            AuthoredSelector::Input { path } => Reference::Input { path },
            AuthoredSelector::Step { step, path } => Reference::Step { step, path },
            AuthoredSelector::Literal { value } => Reference::Literal { value },
        };
        Self::Reference(reference.into())
    }
}

impl TryFrom<AuthoredStep> for Step {
    /// The connection and the operation name the catalog does not hold.
    type Error = (String, String);

    fn try_from(value: AuthoredStep) -> std::result::Result<Self, Self::Error> {
        Ok(match value {
            AuthoredStep::WaitUntil { wait_until, next } => Self::WaitUntil {
                wait_until: wait_until.into(),
                next: next.into_string(),
            },
            AuthoredStep::WaitFor {
                event,
                timeout_seconds,
                next,
                on_timeout,
                on_cancel,
            } => Self::WaitFor {
                wait_for: match event {
                    AuthoredEvent::ReviewResult { request } => {
                        definition::WaitEvent::ReviewResult {
                            request: request.into_string(),
                        }
                    }
                },
                timeout_seconds: timeout_seconds.get(),
                next: next.into_string(),
                on_timeout: on_timeout.map(LocalId::into_string),
                on_cancel: on_cancel.map(LocalId::into_string),
            },
            AuthoredStep::Call {
                connection,
                operation,
                input,
                next,
                on_declared_refusal,
            } => Self::Call {
                call: Call {
                    operation: Operation::parse(&operation.0)
                        .ok_or_else(|| (connection.as_str().to_owned(), operation.0))?,
                    connection: connection.into_string(),
                },
                input: input.into(),
                next: next.into_string(),
                on_declared_refusal: on_declared_refusal.map(LocalId::into_string),
            },
            AuthoredStep::Choose { choose, cases } => Self::Choose {
                choose: choose.into(),
                cases: cases
                    .into_iter()
                    .map(|(key, value)| (key.into_string(), value.into_string()))
                    .collect(),
            },
            AuthoredStep::Finish { outcome, output } => Self::Finish {
                finish: outcome.into_string(),
                output: output.map(Into::into),
            },
        })
    }
}

/// The shared reader owns envelope, structural validation, and positions.
pub fn parse_project(path: &Path, bytes: impl AsRef<[u8]>) -> Result<(Workflow, Document)> {
    let mut expressions = AuthoredExpressions;
    let document = Reader::new(path.to_string_lossy())
        .with_hook(&mut expressions)
        .read(bytes.as_ref(), &Expect::one(&FORMAT))
        .map_err(CoordinatorError::from_report)?;
    let project: CoordinatorProject = document.decode().map_err(CoordinatorError::from_report)?;
    let connections = project
        .connections
        .into_iter()
        .map(|(id, product)| (id.into_string(), product.name().to_owned()))
        .collect::<BTreeMap<_, _>>();
    let mut steps = BTreeMap::new();
    let mut unknown = Vec::new();
    for (id, step) in project.steps {
        match Step::try_from(step) {
            Ok(step) => {
                steps.insert(id.into_string(), step);
            }
            Err((connection, operation)) => {
                let (offers, action) = match connections.get(&connection) {
                    Some(product) => (
                        format!(
                            "connection {connection} is a {product} connection, which offers {}",
                            definition::offered(product)
                        ),
                        format!("Name an operation {product} offers."),
                    ),
                    None => (
                        format!(
                            "the operations are {}",
                            definition::listed(
                                crate::operations::descriptors()
                                    .iter()
                                    .map(|descriptor| descriptor.id)
                            )
                        ),
                        "Name one of the listed operations.".to_owned(),
                    ),
                };
                unknown.push(document.diagnostic_at_value(
                    Severity::Error,
                    "coordinator.definition.operation",
                    &format!("/steps/{}/operation", id.as_str()),
                    &format!("operation {operation} is not a Coordinator operation; {offers}"),
                    &action,
                ));
            }
        }
    }
    if !unknown.is_empty() {
        return Err(CoordinatorError::from_diagnostics(&unknown));
    }
    let workflow = Workflow {
        api_version: crate::definition::API_VERSION.into(),
        kind: "Workflow".into(),
        id: project.project.id.into_string(),
        version: project.project.version,
        input: project.input.into_value(),
        connections,
        functions: project.functions_file,
        deadline: format!("{}s", project.deadline_seconds.get()),
        start: project.start.into_string(),
        steps,
        outcomes: project
            .outcomes
            .into_iter()
            .map(|(id, schema)| (id.into_string(), schema.into_value()))
            .collect(),
    };
    Ok((workflow, document))
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
        "/functions" => "/functionsFile".into(),
        "/deadline" => "/deadlineSeconds".into(),
        _ => {
            let mut parts = pointer.split('/').map(str::to_owned).collect::<Vec<_>>();
            if parts.len() > 3 && parts[1] == "steps" {
                if parts[3] == "call" {
                    parts.remove(3);
                } else if parts[3] == "finish" {
                    parts[3] = "outcome".into();
                } else if parts[3] == "waitFor" {
                    parts[3] = "event".into();
                }
            }
            parts.join("/")
        }
    };
    let code = format!("coordinator.{}", error.code.replace('_', "-"));
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
}

#[cfg(feature = "schema")]
pub fn project_schema() -> std::result::Result<String, serde_json::Error> {
    let mut schema = serde_json::to_value(schemars::schema_for!(CoordinatorProject))?;
    crate::schema::finish(&mut schema, API_VERSION, KIND, SCHEMA_ID);
    // Retain the execution ABI's version grammar within the shared identity.
    let mut identity = schema["properties"]["project"].take();
    let described = identity
        .as_object_mut()
        .and_then(|identity| identity.remove("description"));
    let version = "The version of this definition: 1 to 64 letters, digits, hyphens or underscores. A deployment refuses a changed definition under a version it already applied.";
    schema["properties"]["project"] = serde_json::json!({
        "description": described,
        "unevaluatedProperties": false,
        "allOf": [identity, {"properties": {"version": {
            "type": "string", "minLength": 1, "maxLength": 64,
            "pattern": "^[A-Za-z0-9_-]+$",
            "description": version
        }}}]
    });
    // The shared identity describes the block, not its members.
    if let Some(members) = schema.pointer_mut("/$defs/ProjectIdentity/properties") {
        members["id"]["description"] =
            "The workflow identifier a caller names as `flow` to start a run.".into();
        members["version"]["description"] = version.into();
    }
    for (pointer, minimum, maximum) in [
        ("/properties/connections", 0, 16),
        ("/properties/steps", 1, 64),
        ("/properties/outcomes", 1, 64),
    ] {
        if let Some(mapping) = schema.pointer_mut(pointer) {
            id_keyed_map_schema(mapping);
            mapping["minProperties"] = serde_json::json!(minimum);
            mapping["maxProperties"] = serde_json::json!(maximum);
        }
    }
    for union in [
        "/$defs/AuthoredInput/oneOf",
        "/$defs/AuthoredSelector/oneOf",
    ] {
        let forms = schema
            .pointer_mut(union)
            .and_then(serde_json::Value::as_array_mut);
        for form in forms.into_iter().flatten() {
            if let Some(arguments) = form.pointer_mut("/properties/arguments") {
                arguments["maxItems"] = serde_json::json!(16);
            }
        }
    }
    if let Some(fields) = schema.pointer_mut("/$defs/Fields") {
        keyed_map_schema(fields, "FieldName");
        // A key is a member name the operation input or outcome issues: an
        // external identifier, held to the field-name grammar.
        fields["propertyNames"] = serde_json::json!({"allOf": [
            {"$ref": "#/$defs/ExternalId"}, {"$ref": "#/$defs/FieldName"}
        ]});
        fields["maxProperties"] = serde_json::json!(crate::definition::MAXIMUM_FIELDS);
    }
    // Schemars reads a map key's schema inline, so the named key needs its
    // own definition.
    schema["$defs"]["FieldName"] = serde_json::to_value(
        <FieldName as schemars::JsonSchema>::json_schema(&mut schemars::SchemaGenerator::default()),
    )?;
    schema["$defs"]["ExternalId"] = serde_json::to_value(
        <registry_platform_yaml::ExternalId as schemars::JsonSchema>::json_schema(
            &mut schemars::SchemaGenerator::default(),
        ),
    )?;
    if let Some(variants) = schema
        .pointer_mut("/$defs/AuthoredStep/oneOf")
        .and_then(serde_json::Value::as_array_mut)
    {
        for variant in variants {
            if let Some(cases) = variant.pointer_mut("/properties/cases") {
                id_keyed_map_schema(cases);
                cases["minProperties"] = serde_json::json!(1);
                cases["maxProperties"] = serde_json::json!(32);
            }
            if variant.pointer("/properties/type/const") == Some(&serde_json::json!("call")) {
                variant["allOf"] = operation_input_members();
            }
        }
    }
    schema["properties"]["functionsFile"]["const"] = serde_json::json!("functions.rhai");
    if let Some(outcomes) = schema.pointer_mut("/properties/outcomes/additionalProperties") {
        *outcomes = serde_json::json!({"x-registry-foreign": "json-schema-2020-12"});
    }
    let mut text = serde_json::to_string_pretty(&schema)?;
    text.push('\n');
    Ok(text)
}

/// One rule per catalog operation: a `fields` mapping that feeds the operation
/// writes every member its input contract requires and, when the contract is
/// closed, no member it does not declare. A function mapping computes its
/// members, so the contract holds it when the input is computed.
#[cfg(feature = "schema")]
fn operation_input_members() -> serde_json::Value {
    crate::operations::descriptors()
        .iter()
        .map(|descriptor| {
            let operation = Operation::parse(descriptor.id).expect("the catalog names it");
            let input = &crate::contracts::contract(operation).input;
            let declared: serde_json::Map<String, serde_json::Value> = input["properties"]
                .as_object()
                .into_iter()
                .flat_map(|members| members.keys())
                .map(|name| (name.clone(), serde_json::Value::Bool(true)))
                .collect();
            let mut fields = serde_json::json!({"properties": declared});
            if input["additionalProperties"] == serde_json::json!(false) {
                fields["additionalProperties"] = serde_json::json!(false);
            }
            if let Some(required) = input.get("required") {
                fields["required"] = required.clone();
            }
            let mut rule = serde_json::json!({
                "if": {
                    "properties": {"operation": {"const": descriptor.id}},
                    "required": ["operation"]
                },
                "then": {"properties": {"input": {"properties": {"fields": fields}}}}
            });
            if !descriptor.declared_refusal {
                rule["then"]["not"] = serde_json::json!({"required": ["onDeclaredRefusal"]});
            }
            rule
        })
        .collect()
}

#[cfg(feature = "schema")]
fn id_keyed_map_schema(mapping: &mut serde_json::Value) {
    keyed_map_schema(mapping, "LocalId");
}

#[cfg(feature = "schema")]
fn keyed_map_schema(mapping: &mut serde_json::Value, key: &str) {
    // Schemars emits a closed pattern map for string newtypes. Configuration
    // conventions represent keyed data with typed keys and typed values.
    if let Some(serde_json::Value::Object(patterns)) = mapping
        .as_object_mut()
        .and_then(|map| map.remove("patternProperties"))
    {
        assert_eq!(patterns.len(), 1, "keyed maps have one item schema");
        mapping["additionalProperties"] = patterns.into_values().next().unwrap();
    }
    mapping["propertyNames"] = serde_json::json!({"$ref": format!("#/$defs/{key}")});
}
