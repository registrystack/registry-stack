// SPDX-License-Identifier: Apache-2.0
//! Portable authoring types. The persisted execution representation stays stable.

use std::{collections::BTreeMap, path::Path};

use registry_platform_config::AuthoredExpressions;
use registry_platform_yaml::{
    ApiVersion, BoundedU32, Document, EnvelopeRule, Expect, ForeignValue, FormatSpec, LocalId,
    ProjectIdentity, Reader, RetiredApiVersion, Severity,
};
use serde::Deserialize;

use crate::{
    definition::{Call, Mapping, Step, Workflow},
    protocol::Operation,
    PocError, Result,
};

pub const API_VERSION: &str = "id.registrystack.org/formats/coordinator/project/v1alpha1";
pub const KIND: &str = "CoordinatorProject";
pub const SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/coordinator/project/project.v1alpha1.schema.json";
const FORMAT: FormatSpec<'static> = FormatSpec {
    kind: KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(API_VERSION)],
        retired_api_versions: &[RetiredApiVersion {
            api_version: "registry.registrystack.org/coordinator/v1alpha1",
            replacement: "Use CoordinatorProject with project identity, deadlineSeconds, functionsFile, typed steps and explicit argument references.",
        }],
    },
    removed_keys: &[],
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CoordinatorProject {
    pub project: ProjectIdentity,
    #[cfg_attr(feature = "schema", schemars(extend("x-registry-foreign" = "json-schema-2020-12")))]
    input: ForeignValue,
    connections: BTreeMap<LocalId, Product>,
    functions_file: String,
    deadline_seconds: BoundedU32<1, 31_536_000>,
    start: LocalId,
    steps: BTreeMap<LocalId, AuthoredStep>,
    outcomes: BTreeMap<LocalId, ForeignValue>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
enum Product {
    Breg,
    Messaging,
    Scheduling,
    ExternalHttp,
    Decision,
}

impl Product {
    fn name(self) -> &'static str {
        match self {
            Self::Breg => "breg",
            Self::Messaging => "messaging",
            Self::Scheduling => "scheduling",
            Self::ExternalHttp => "external-http",
            Self::Decision => "decision",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
struct AuthoredMapping {
    function: LocalId,
    arguments: Vec<Argument>,
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
enum Argument {
    Input {},
    Step { step: LocalId },
}
registry_platform_yaml::tagged_union!(Argument);

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
    WaitUntil {
        wait_until: AuthoredMapping,
        next: LocalId,
    },
    Call {
        connection: LocalId,
        operation: Operation,
        input: AuthoredMapping,
        next: LocalId,
    },
    Choose {
        choose: AuthoredMapping,
        cases: BTreeMap<LocalId, LocalId>,
    },
    Finish {
        outcome: LocalId,
        #[serde(default)]
        output: Option<AuthoredMapping>,
    },
}
registry_platform_yaml::tagged_union!(AuthoredStep);

impl From<AuthoredMapping> for Mapping {
    fn from(value: AuthoredMapping) -> Self {
        Self {
            function: value.function.into_string(),
            arguments: value
                .arguments
                .into_iter()
                .map(|argument| match argument {
                    Argument::Input {} => "input".into(),
                    Argument::Step { step } => format!("{step}.output"),
                })
                .collect(),
        }
    }
}

impl From<AuthoredStep> for Step {
    fn from(value: AuthoredStep) -> Self {
        match value {
            AuthoredStep::WaitUntil { wait_until, next } => Self::WaitUntil {
                wait_until: wait_until.into(),
                next: next.into_string(),
            },
            AuthoredStep::Call {
                connection,
                operation,
                input,
                next,
            } => Self::Call {
                call: Call {
                    connection: connection.into_string(),
                    operation,
                },
                input: input.into(),
                next: next.into_string(),
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
        }
    }
}

/// The shared reader owns envelope, structural validation, and positions.
pub fn parse_project(path: &Path, bytes: impl AsRef<[u8]>) -> Result<(Workflow, Document)> {
    let mut expressions = AuthoredExpressions;
    let document = Reader::new(path.to_string_lossy())
        .with_hook(&mut expressions)
        .read(bytes.as_ref(), &Expect::one(&FORMAT))
        .map_err(PocError::from_report)?;
    let project: CoordinatorProject = document.decode().map_err(PocError::from_report)?;
    let workflow = Workflow {
        api_version: "registry.registrystack.org/coordinator/v1alpha1".into(),
        kind: "Workflow".into(),
        id: project.project.id.into_string(),
        version: project.project.version,
        input: project.input.into_value(),
        connections: project
            .connections
            .into_iter()
            .map(|(id, product)| (id.into_string(), product.name().into()))
            .collect(),
        functions: project.functions_file,
        deadline: format!("{}s", project.deadline_seconds.get()),
        start: project.start.into_string(),
        steps: project
            .steps
            .into_iter()
            .map(|(id, step)| (id.into_string(), step.into()))
            .collect(),
        outcomes: project
            .outcomes
            .into_iter()
            .map(|(id, schema)| (id.into_string(), schema.into_value()))
            .collect(),
    };
    Ok((workflow, document))
}

/// Project execution checks refer to the stable IR. Point their diagnostics
/// back at the corresponding member in the authored document.
pub(crate) fn positioned(document: &Document, error: PocError) -> PocError {
    if !error.diagnostics.is_empty() {
        return error;
    }
    if error.code.starts_with("function.")
        && !matches!(
            error.code.as_str(),
            "function.value_limit" | "function.json"
        )
    {
        let mut error = error;
        error
            .file
            .get_or_insert_with(|| Path::new("functions.rhai").into());
        return PocError::from_report(error.report());
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
                }
            }
            parts.join("/")
        }
    };
    let code = format!("coordinator.{}", error.code.replace('_', "-"));
    PocError::from_diagnostics(&[document.diagnostic_at_value(
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
    let identity = schema["properties"]["project"].take();
    schema["properties"]["project"] = serde_json::json!({
        "unevaluatedProperties": false,
        "allOf": [identity, {"properties": {"version": {
            "type": "string", "minLength": 1, "maxLength": 64,
            "pattern": "^[A-Za-z0-9_-]+$"
        }}}]
    });
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
    if let Some(arguments) = schema.pointer_mut("/$defs/AuthoredMapping/properties/arguments") {
        arguments["maxItems"] = serde_json::json!(16);
    }
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

#[cfg(feature = "schema")]
fn id_keyed_map_schema(mapping: &mut serde_json::Value) {
    // Schemars emits a closed pattern map for string newtypes. Configuration
    // conventions represent id-keyed data with typed keys and typed values.
    if let Some(serde_json::Value::Object(patterns)) = mapping
        .as_object_mut()
        .and_then(|map| map.remove("patternProperties"))
    {
        assert_eq!(patterns.len(), 1, "LocalId maps have one item schema");
        mapping["additionalProperties"] = patterns.into_values().next().unwrap();
    }
    mapping["propertyNames"] = serde_json::json!({"$ref":"#/$defs/LocalId"});
}
