//! Types projected from the validated project and its compiled schema assets.
use crate::{
    compile::CompiledProject,
    project::{self, EvidenceProject, Output},
};
use serde_json::{json, Map, Value};

fn object(properties: Map<String, Value>) -> Value {
    json!({"type":"object","required":properties.keys().collect::<Vec<_>>(),"properties":properties,"additionalProperties":false})
}
fn fields(properties: impl IntoIterator<Item = (String, Value)>) -> Value {
    object(properties.into_iter().collect())
}
fn array(items: Value) -> Value {
    json!({"type":"array","items":items})
}
fn literal(value: Value) -> Value {
    match value {
        Value::Object(values) => fields(
            values
                .into_iter()
                .map(|(name, value)| (name, literal(value))),
        ),
        Value::Array(values) => array(union(values.into_iter().map(literal).collect())),
        scalar => json!({"enum":[scalar]}),
    }
}
fn union(items: Vec<Value>) -> Value {
    json!({"anyOf":items})
}
fn parameter_shape(value: &Value) -> Value {
    match value {
        Value::Object(map) if map.get("type") == Some(&json!("decimal")) => {
            json!({"x-evidence-rhai-type":"RhaiDecimal"})
        }
        Value::Object(map) => fields(
            map.iter()
                .map(|(name, value)| (name.clone(), parameter_shape(value))),
        ),
        Value::Array(values) => array(union(values.iter().map(parameter_shape).collect())),
        scalar => literal(scalar.clone()),
    }
}
fn parameters(value: &std::collections::BTreeMap<String, Value>) -> Value {
    fields(
        value
            .iter()
            .map(|(name, value)| (name.clone(), parameter_shape(value))),
    )
}
fn codelist_codes(path: &str, compiled: &CompiledProject) -> Value {
    let value = crate::output::codelist_value(path, &compiled.artifacts[path])
        .expect("compiled codelist metadata");
    json!({"type":"string","enum":value.get("codes").or_else(||value.get("allowedOutputs")).expect("codelist codes")})
}
fn output_shape(output: &Output, compiled: &CompiledProject, authored: bool) -> Value {
    match output.value_type.as_str() {
        "boolean" => json!({"type":"boolean"}),
        "bounded-integer" => json!({"type":"integer"}),
        "bounded-identifier" => json!({"type":"string"}),
        "controlled-category" if !output.values.is_empty() => {
            json!({"type":"string","enum":output.values})
        }
        "controlled-category" | "controlled-code" => {
            codelist_codes(output.codelist.as_deref().expect("codelist"), compiled)
        }
        "controlled-code-list" => array(codelist_codes(
            output.codelist.as_deref().expect("codelist"),
            compiled,
        )),
        "bounded-decimal" if authored => json!({"x-evidence-rhai-type":"RhaiDecimal"}),
        "bounded-decimal" => json!({"type":"string"}),
        "audience-scoped-entity-reference" | "entity-reference-list" => {
            let shape = if authored {
                json!({"x-evidence-rhai-type":"EntityReferenceSeed"})
            } else {
                fields([
                    (
                        "form".to_owned(),
                        literal(json!("audience-scoped-entity-reference")),
                    ),
                    ("reference".to_owned(), json!({"type":"string"})),
                ])
            };
            if output.value_type == "entity-reference-list" {
                array(shape)
            } else {
                shape
            }
        }
        "date-bucket" | "time-bucket" => fields([
            ("form".to_owned(), literal(json!(output.value_type))),
            ("scheme".to_owned(), literal(json!(output.bucket_scheme))),
            (
                "bucket".to_owned(),
                codelist_codes(
                    output.codelist.as_deref().expect("bucket codelist"),
                    compiled,
                ),
            ),
        ]),
        "reviewed-structured-value" => {
            let schema: Value = serde_json::from_slice(
                &compiled.artifacts[output.schema.as_deref().expect("schema")],
            )
            .expect("compiled schema JSON");
            fields([
                (
                    "form".to_owned(),
                    literal(json!("reviewed-structured-value")),
                ),
                ("schema".to_owned(), literal(schema["$id"].clone())),
                ("fields".to_owned(), schema),
            ])
        }
        _ => unreachable!("compiled Output type is closed"),
    }
}
fn compiled_facts(compiled: &CompiledProject, source: &str) -> Value {
    compiled.source_facts[source].clone()
}

fn selector_inputs(
    project: &EvidenceProject,
    compiled: &CompiledProject,
    inputs: &[project::DeriveSelectorInput],
) -> Value {
    fields(inputs.iter().map(|input| {
        (
            input.role.to_string(),
            union(
                input
                    .alternatives
                    .iter()
                    .map(|alternative| {
                        let profile = &project.selector_profiles[&alternative.profile];
                        fields([
                            ("profile".to_owned(), literal(json!(alternative.profile))),
                            (
                                "values".to_owned(),
                                fields(alternative.fields.iter().map(|name| {
                                    let field = &profile.fields[name];
                                    let shape = field.codelist().map_or_else(
                                        || project::value_schema(&crate::selector::compiled(field)),
                                        |(path, _)| codelist_codes(path, compiled),
                                    );
                                    (name.to_string(), shape)
                                })),
                            ),
                        ])
                    })
                    .collect(),
            ),
        )
    }))
}

pub(crate) fn function_shape(
    project: &EvidenceProject,
    compiled: &CompiledProject,
    function: &project::Function,
) -> Value {
    let mut calls = Vec::new();
    for (id, definition) in &project.assertion_definitions {
        if definition.derive.function != function.id {
            continue;
        }
        let facts = compiled_facts(compiled, definition.acquisition.source.as_str());
        let context = fields([
            (
                "parameters".to_owned(),
                parameters(&definition.derive.parameters),
            ),
            (
                "observed_at".to_owned(),
                json!({"x-evidence-rhai-type":"UtcInstant"}),
            ),
            (
                "legal_local_date".to_owned(),
                json!({"x-evidence-rhai-type":"CalendarDate"}),
            ),
            (
                "legal_local_time".to_owned(),
                json!({"x-evidence-rhai-type":"LegalLocalTime"}),
            ),
            (
                "codelists".to_owned(),
                fields(
                    compiled
                        .artifacts
                        .iter()
                        .filter(|(path, _)| path.starts_with("codelists/"))
                        .filter_map(|(path, bytes)| {
                            crate::output::codelist_value(path, bytes).map(|value| {
                                (
                                    value["uri"].as_str().expect("codelist identity").to_owned(),
                                    json!({"x-evidence-rhai-type":"CodelistHandle"}),
                                )
                            })
                        }),
                ),
            ),
        ]);
        let outputs = array(union(
            definition
                .outputs
                .iter()
                .map(|(name, output)| {
                    fields([
                        ("output".to_owned(), literal(json!(name))),
                        ("value".to_owned(), output_shape(output, compiled, true)),
                    ])
                })
                .collect(),
        ));
        calls.push(fields([
            ("definition".to_owned(), literal(json!(id))),
            ("mode".to_owned(), literal(json!("derive"))),
            (
                "inputs".to_owned(),
                fields([
                    ("facts".to_owned(), facts),
                    (
                        "selectors".to_owned(),
                        selector_inputs(project, compiled, &definition.derive.selector_inputs),
                    ),
                    ("context".to_owned(), context),
                ]),
            ),
            ("outputs".to_owned(), outputs),
        ]));
    }
    fields([
        ("interface".to_owned(), literal(json!(function.interface))),
        ("calls".to_owned(), union(calls)),
    ])
}

fn ts(schema: &Value, root: &Value, depth: usize) -> String {
    if depth > 32 {
        return "unknown".to_owned();
    }
    if let Some(name) = schema["x-evidence-rhai-type"].as_str() {
        return name.to_owned();
    }
    if schema.get("$ref") == Some(&json!("#/$defs/JSONValue")) {
        return "JSONValue".to_owned();
    }
    if let Some(reference) = schema
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|x| x.strip_prefix('#'))
    {
        return root
            .pointer(reference)
            .map_or_else(|| "unknown".to_owned(), |shape| ts(shape, root, depth + 1));
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        return values
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join(" | ");
    }
    if let Some(values) = schema
        .get("anyOf")
        .or_else(|| schema.get("oneOf"))
        .and_then(Value::as_array)
    {
        return if values.is_empty() {
            "never".to_owned()
        } else {
            values
                .iter()
                .map(|shape| ts(shape, root, depth + 1))
                .collect::<Vec<_>>()
                .join(" | ")
        };
    }
    match schema["type"].as_str() {
        Some("boolean") => "boolean".to_owned(),
        Some("string") => "string".to_owned(),
        Some("integer" | "number") => "number".to_owned(),
        Some("null") => "null".to_owned(),
        Some("array") => format!("ReadonlyArray<{}>", ts(&schema["items"], root, depth + 1)),
        Some("object")
            if schema["additionalProperties"].is_object() && schema["properties"].is_null() =>
        {
            format!(
                "{{ readonly [key: string]: {} }}",
                ts(&schema["additionalProperties"], root, depth + 1)
            )
        }
        Some("object") => format!(
            "{{ {} }}",
            schema["properties"]
                .as_object()
                .map(|properties| properties
                    .iter()
                    .map(|(name, shape)| format!(
                        "{}{}: {}",
                        json!(name),
                        if schema["required"]
                            .as_array()
                            .is_some_and(|required| required.contains(&json!(name)))
                        {
                            ""
                        } else {
                            "?"
                        },
                        ts(shape, root, depth + 1)
                    ))
                    .collect::<Vec<_>>()
                    .join("; "))
                .unwrap_or_default()
        ),
        _ => "unknown".to_owned(),
    }
}
fn python_literal(value: &Value) -> String {
    match value {
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::Null => "None".to_owned(),
        _ => value.to_string(),
    }
}
struct Python {
    definitions: String,
    next: usize,
}
impl Python {
    fn shape(&mut self, schema: &Value, root: &Value, depth: usize) -> String {
        if depth > 32 {
            return "Any".to_owned();
        }
        if let Some(name) = schema["x-evidence-rhai-type"].as_str() {
            return name.to_owned();
        }
        if schema.get("$ref") == Some(&json!("#/$defs/JSONValue")) {
            return "JSONValue".to_owned();
        }
        if let Some(reference) = schema
            .get("$ref")
            .and_then(Value::as_str)
            .and_then(|x| x.strip_prefix('#'))
        {
            return root.pointer(reference).map_or_else(
                || "Any".to_owned(),
                |shape| self.shape(shape, root, depth + 1),
            );
        }
        if let Some(values) = schema.get("enum").and_then(Value::as_array) {
            return format!(
                "Literal[{}]",
                values
                    .iter()
                    .map(python_literal)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if let Some(values) = schema
            .get("anyOf")
            .or_else(|| schema.get("oneOf"))
            .and_then(Value::as_array)
        {
            return if values.is_empty() {
                "Never".to_owned()
            } else {
                values
                    .iter()
                    .map(|value| self.shape(value, root, depth + 1))
                    .collect::<Vec<_>>()
                    .join(" | ")
            };
        }
        match schema["type"].as_str() {
            Some("boolean") => "bool".to_owned(),
            Some("string") => "str".to_owned(),
            Some("integer") => "int".to_owned(),
            Some("number") => "float".to_owned(),
            Some("null") => "None".to_owned(),
            Some("array") => format!("list[{}]", self.shape(&schema["items"], root, depth + 1)),
            Some("object")
                if schema["additionalProperties"].is_object() && schema["properties"].is_null() =>
            {
                format!(
                    "dict[str, {}]",
                    self.shape(&schema["additionalProperties"], root, depth + 1)
                )
            }
            Some("object") => {
                let name = format!("EvidenceShape{}", self.next);
                self.next += 1;
                let entries = schema["properties"]
                    .as_object()
                    .map(|properties| {
                        properties
                            .iter()
                            .map(|(name, shape)| {
                                let shape = self.shape(shape, root, depth + 1);
                                format!(
                                    "    {}: {},\n",
                                    json!(name),
                                    if schema["required"]
                                        .as_array()
                                        .is_some_and(|required| required.contains(&json!(name)))
                                    {
                                        shape
                                    } else {
                                        format!("NotRequired[{shape}]")
                                    }
                                )
                            })
                            .collect::<String>()
                    })
                    .unwrap_or_default();
                self.definitions
                    .push_str(&format!("{name} = TypedDict({name:?}, {{\n{entries}}})\n"));
                name
            }
            _ => "Any".to_owned(),
        }
    }
}

/// Generate TypeScript from the compiled schema closure, with local ID anchors.
pub fn typescript(project: &EvidenceProject, compiled: &CompiledProject) -> String {
    let mut result="// Generated from the normalized EvidenceProject.\nexport type JSONValue = null | boolean | number | string | ReadonlyArray<JSONValue> | {readonly [key: string]: JSONValue};\nexport interface RhaiDecimal {readonly __evidenceRhaiType: \"Decimal\"}\nexport interface EntityReferenceSeed {readonly __evidenceRhaiType: \"EntityReferenceSeed\"}\n".to_owned();
    for name in [
        "UtcInstant",
        "CalendarDate",
        "LegalLocalTime",
        "CodelistHandle",
    ] {
        result.push_str(&format!(
            "export interface {name} {{readonly __evidenceRhaiType: \"{name}\"}}\n"
        ));
    }
    result.push_str("export interface AssertionOutputs {\n");
    for (id, definition) in &project.assertion_definitions {
        result.push_str(&format!(
            "  // evidence-definition: {id}\n  {}: {{\n",
            json!(id)
        ));
        for (name, output) in &definition.outputs {
            let shape = output_shape(output, compiled, false);
            result.push_str(&format!(
                "    {}: {};\n",
                json!(name),
                ts(&shape, &shape, 0)
            ));
        }
        result.push_str("  };\n");
    }
    result.push_str("}\n");
    for catalog in ["SourceFacts"] {
        result.push_str(&format!("export interface {catalog} {{\n"));
        for id in project.sources.keys() {
            let shape = compiled_facts(compiled, id.as_str());
            result.push_str(&format!(
                "  // evidence-source: {id}\n  {}: {};\n",
                json!(id),
                ts(&shape, &shape, 0)
            ));
        }
        result.push_str("}\n");
    }
    result.push_str("export interface FunctionBindings {\n");
    for function in &project.functions {
        let shape = function_shape(project, compiled, function);
        result.push_str(&format!(
            "  // evidence-function: {}\n  {}: {};\n",
            function.id,
            json!(function.id),
            ts(&shape, &shape, 0)
        ));
    }
    result.push_str("}\nexport const assertionDefinitions = ");
    result.push_str(
        &json!(project
            .assertion_definitions
            .iter()
            .map(|(id, definition)| (id.as_str(), &definition.semantics.requirement))
            .collect::<std::collections::BTreeMap<_, _>>())
        .to_string(),
    );
    result.push_str(" as const;\n");
    result
}
/// Generate Python TypedDict declarations from the same typed call-site projection.
pub fn python(project: &EvidenceProject, compiled: &CompiledProject) -> String {
    let mut result="# Generated from the normalized EvidenceProject.\nfrom typing import Any, Literal, Never, NotRequired, TypedDict, Union, Protocol\nclass RhaiDecimal(Protocol):\n    __evidence_rhai_type: Literal[\"Decimal\"]\nclass EntityReferenceSeed(Protocol):\n    __evidence_rhai_type: Literal[\"EntityReferenceSeed\"]\nJSONValue = Union[None, bool, int, float, str, list['JSONValue'], dict[str, 'JSONValue']]\n\n".to_owned();
    for name in [
        "UtcInstant",
        "CalendarDate",
        "LegalLocalTime",
        "CodelistHandle",
    ] {
        result.push_str(&format!(
            "class {name}(Protocol):\n    __evidence_rhai_type: Literal[\"{name}\"]\n"
        ));
    }
    let mut renderer = Python {
        definitions: String::new(),
        next: 0,
    };
    for (id, definition) in &project.assertion_definitions {
        let shape = fields(
            definition
                .outputs
                .iter()
                .map(|(name, output)| (name.to_string(), output_shape(output, compiled, false))),
        );
        let name = renderer.shape(&shape, &shape, 0);
        result.push_str(&format!("# evidence-definition: {id}\n"));
        result.push_str(&renderer.definitions);
        renderer.definitions.clear();
        result.push_str(&format!(
            "{} = {name}\n",
            id.as_str()
                .split('-')
                .map(|part| {
                    let mut chars = part.chars();
                    chars.next().map_or_else(String::new, |first| {
                        first.to_uppercase().chain(chars).collect()
                    })
                })
                .collect::<String>()
                + "Outputs"
        ));
    }
    for catalog in ["SourceFacts"] {
        let mut entries = Vec::new();
        for id in project.sources.keys() {
            let shape = compiled_facts(compiled, id.as_str());
            let name = renderer.shape(&shape, &shape, 0);
            result.push_str(&format!("# evidence-source: {id}\n"));
            result.push_str(&renderer.definitions);
            renderer.definitions.clear();
            entries.push(format!("    {}: {name},\n", json!(id)));
        }
        result.push_str(&format!(
            "{catalog} = TypedDict({catalog:?}, {{\n{}}})\n",
            entries.join("")
        ));
    }
    let mut entries = Vec::new();
    for function in &project.functions {
        let shape = function_shape(project, compiled, function);
        let name = renderer.shape(&shape, &shape, 0);
        result.push_str(&format!("# evidence-function: {}\n", function.id));
        result.push_str(&renderer.definitions);
        renderer.definitions.clear();
        entries.push(format!("    {}: {name},\n", json!(function.id)));
    }
    result.push_str(&format!(
        "FunctionBindings = TypedDict(\"FunctionBindings\", {{\n{}}})\n",
        entries.join("")
    ));
    result.push_str("ASSERTION_DEFINITIONS: dict[str, str] = {\n");
    for (id, definition) in &project.assertion_definitions {
        result.push_str(&format!(
            "    {}: {},\n",
            json!(id),
            json!(definition.semantics.requirement)
        ));
    }
    result.push_str("}\n");
    result
}
