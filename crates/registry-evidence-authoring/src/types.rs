//! Types projected from the validated project and its compiled schema assets.
use crate::{
    compile::CompiledProject,
    project::{self, EvidenceProject, Output, Source},
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
fn parameters(value: &std::collections::BTreeMap<String, Value>) -> Value {
    fields(
        value
            .iter()
            .map(|(name, value)| (name.clone(), literal(value.clone()))),
    )
}
fn output_shape(output: &Output, compiled: &CompiledProject) -> Value {
    if let Some(path) = &output.schema {
        let shape = serde_json::from_slice(&compiled.artifacts[path])
            .expect("compiled Output schema is JSON");
        return if output.value_type.ends_with("-list") {
            array(shape)
        } else {
            shape
        };
    }
    let shape = match output.value_type.trim_end_matches("-list") {
        "boolean" => json!({"type":"boolean"}),
        "bounded-integer" => json!({"type":"integer"}),
        "controlled-category" => json!({"type":"string","enum":output.values}),
        "bounded-identifier" => json!({"type":"string"}),
        _ => unreachable!("compiled Output type is closed"),
    };
    if output.value_type.ends_with("-list") {
        array(shape)
    } else {
        shape
    }
}
fn facts(source: &Source) -> Value {
    fields(
        source
            .facts
            .iter()
            .map(|(id, value)| (id.to_string(), project::value_schema(value))),
    )
}
fn selectors(
    project: &EvidenceProject,
    inputs: impl IntoIterator<Item = (String, Vec<(String, Vec<String>)>)>,
) -> Value {
    fields(inputs.into_iter().map(|(role, alternatives)| {
        (
            role,
            union(
                alternatives
                    .into_iter()
                    .map(|(profile, names)| {
                        let shape = &project
                            .selector_profiles
                            .iter()
                            .find(|(id, _)| id.as_str() == profile)
                            .expect("validated selector profile")
                            .1
                            .fields;
                        fields([
                            ("profile".to_owned(), literal(json!(profile))),
                            (
                                "values".to_owned(),
                                fields(names.into_iter().map(|name| {
                                    let value = shape
                                        .iter()
                                        .find(|(id, _)| id.as_str() == name)
                                        .expect("validated selector field")
                                        .1;
                                    (name, project::value_schema(value))
                                })),
                            ),
                        ])
                    })
                    .collect(),
            ),
        )
    }))
}
fn source_selectors(project: &EvidenceProject, source: &Source) -> Value {
    selectors(
        project,
        source.selectors.iter().map(|input| {
            (
                input.role.to_string(),
                input
                    .profiles
                    .iter()
                    .map(|id| {
                        (
                            id.to_string(),
                            project.selector_profiles[id]
                                .fields
                                .keys()
                                .map(ToString::to_string)
                                .collect(),
                        )
                    })
                    .collect(),
            )
        }),
    )
}
fn derive_selectors(project: &EvidenceProject, inputs: &[Value]) -> Value {
    selectors(
        project,
        inputs.iter().map(|input| {
            (
                input["role"].as_str().expect("validated role").to_owned(),
                input["alternatives"]
                    .as_array()
                    .expect("validated alternatives")
                    .iter()
                    .map(|alternative| {
                        (
                            alternative["profile"].as_str().expect("profile").to_owned(),
                            alternative["fields"]
                                .as_array()
                                .expect("fields")
                                .iter()
                                .map(|field| field.as_str().expect("field").to_owned())
                                .collect(),
                        )
                    })
                    .collect(),
            )
        }),
    )
}
fn lookup(source: &Source) -> Value {
    union(vec![
        fields([
            ("outcome".to_owned(), literal(json!("match"))),
            ("facts".to_owned(), facts(source)),
        ]),
        fields([(
            "outcome".to_owned(),
            json!({"enum":["no_match","ambiguous"]}),
        )]),
    ])
}
fn request_parts(source: &Source) -> Value {
    if source.source_type == project::SourceType::SqliteExtract {
        fields([(
            "parameters".to_owned(),
            json!({"type":"object","additionalProperties":{"anyOf":[{"type":"string"},{"type":"integer"},{"type":"boolean"}]}}),
        )])
    } else {
        fields([
            (
                "query".to_owned(),
                array(fields([
                    ("name".to_owned(), json!({"type":"string"})),
                    ("value".to_owned(), json!({"type":"string"})),
                ])),
            ),
            ("body".to_owned(), json!({"$ref":"#/$defs/JSONValue"})),
        ])
    }
}
pub(crate) fn function_shape(
    project: &EvidenceProject,
    compiled: &CompiledProject,
    function: &project::Function,
) -> Value {
    let mut calls = Vec::new();
    let mut prior = fields(
        project
            .sources
            .values()
            .flat_map(|source| source.facts.iter())
            .map(|(id, shape)| (id.to_string(), project::value_schema(shape))),
    );
    prior["required"] = json!([]);
    let extraction_arity = compiled
        .functions
        .iter()
        .find(|entry| entry["id"] == json!(function.id))
        .and_then(|entry| entry["arity"].as_u64())
        .unwrap_or(3);
    for (id, source) in &project.sources {
        let parameters = source
            .adapter_parameters_schema
            .clone()
            .unwrap_or_else(|| object(Map::new()));
        let context = fields([
            ("parameters".to_owned(), parameters.clone()),
            ("prior_facts".to_owned(), prior.clone()),
        ]);
        for (mode, matches, inputs, outputs) in [
            (
                "prepare",
                source
                    .prepare
                    .as_ref()
                    .is_some_and(|call| call.function == function.id),
                fields([
                    ("selectors".to_owned(), source_selectors(project, source)),
                    ("context".to_owned(), context.clone()),
                ]),
                request_parts(source),
            ),
            (
                "extract",
                source.extract.function == function.id,
                fields([
                    (
                        "response".to_owned(),
                        project::value_schema(&source.response.shape),
                    ),
                    ("selectors".to_owned(), source_selectors(project, source)),
                    ("context".to_owned(), context),
                ]),
                lookup(source),
            ),
        ] {
            if matches {
                let mut inputs = inputs;
                if mode == "extract" && extraction_arity == 2 {
                    inputs["properties"]
                        .as_object_mut()
                        .expect("input object")
                        .remove("selectors");
                    inputs["required"]
                        .as_array_mut()
                        .expect("required inputs")
                        .retain(|name| name != "selectors");
                }
                calls.push(fields([
                    ("source".to_owned(), literal(json!(id))),
                    ("mode".to_owned(), literal(json!(mode))),
                    ("inputs".to_owned(), inputs),
                    ("outputs".to_owned(), outputs),
                ]));
            }
        }
        if let Some(batch) = &source.batch {
            let items = array(fields([
                ("slot".to_owned(), json!({"type":"integer"})),
                ("selectors".to_owned(), source_selectors(project, source)),
            ]));
            let results = array(union(vec![
                fields([
                    ("slot".to_owned(), json!({"type":"integer"})),
                    ("outcome".to_owned(), literal(json!("match"))),
                    ("facts".to_owned(), facts(source)),
                ]),
                fields([
                    ("slot".to_owned(), json!({"type":"integer"})),
                    (
                        "outcome".to_owned(),
                        json!({"enum":["no_match","ambiguous"]}),
                    ),
                ]),
            ]));
            for (mode, matches, inputs, outputs) in [
                (
                    "batch-prepare",
                    batch.prepare.function == function.id,
                    fields([
                        ("items".to_owned(), items),
                        (
                            "context".to_owned(),
                            fields([("parameters".to_owned(), parameters.clone())]),
                        ),
                    ]),
                    request_parts(source),
                ),
                (
                    "batch-extract",
                    batch.extract.function == function.id,
                    fields([
                        (
                            "response".to_owned(),
                            project::value_schema(&batch.response.shape),
                        ),
                        (
                            "context".to_owned(),
                            fields([
                                ("parameters".to_owned(), parameters),
                                ("slots".to_owned(), array(json!({"type":"integer"}))),
                            ]),
                        ),
                    ]),
                    results,
                ),
            ] {
                if matches {
                    calls.push(fields([
                        ("source".to_owned(), literal(json!(id))),
                        ("mode".to_owned(), literal(json!(mode))),
                        ("inputs".to_owned(), inputs),
                        ("outputs".to_owned(), outputs),
                    ]));
                }
            }
        }
    }
    for (id, definition) in &project.assertion_definitions {
        if definition.derive.function != function.id {
            continue;
        }
        let facts = fields(
            definition
                .acquisition
                .source_ids()
                .into_iter()
                .flat_map(|id| project.sources[id].facts.iter())
                .map(|(id, shape)| (id.to_string(), project::value_schema(shape))),
        );
        let context = fields([
            (
                "parameters".to_owned(),
                parameters(&definition.derive.parameters),
            ),
            ("observed_at".to_owned(), json!({"type":"string"})),
            (
                "legal_local_date".to_owned(),
                json!({"type":"string","format":"date"}),
            ),
            ("legal_local_time".to_owned(), json!({"type":"string"})),
            ("codelists".to_owned(), object(Map::new())),
        ]);
        let outputs = array(union(
            definition
                .outputs
                .iter()
                .map(|(name, output)| {
                    fields([
                        ("output".to_owned(), literal(json!(name))),
                        ("value".to_owned(), output_shape(output, compiled)),
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
                        derive_selectors(project, &definition.derive.selector_inputs),
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
    let mut result="// Generated from the normalized EvidenceProject.\nexport type JSONValue = null | boolean | number | string | ReadonlyArray<JSONValue> | {readonly [key: string]: JSONValue};\nexport interface AssertionOutputs {\n".to_owned();
    for (id, definition) in &project.assertion_definitions {
        result.push_str(&format!(
            "  // evidence-definition: {id}\n  {}: {{\n",
            json!(id)
        ));
        for (name, output) in &definition.outputs {
            let shape = output_shape(output, compiled);
            result.push_str(&format!(
                "    {}: {};\n",
                json!(name),
                ts(&shape, &shape, 0)
            ));
        }
        result.push_str("  };\n");
    }
    result.push_str("}\n");
    for (catalog, response) in [("SourceFacts", false), ("SourceResponses", true)] {
        result.push_str(&format!("export interface {catalog} {{\n"));
        for (id, source) in &project.sources {
            let shape = if response {
                project::value_schema(&source.response.shape)
            } else {
                facts(source)
            };
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
    let mut result="# Generated from the normalized EvidenceProject.\nfrom typing import Any, Literal, Never, NotRequired, TypedDict, Union\nJSONValue = Union[None, bool, int, float, str, list['JSONValue'], dict[str, 'JSONValue']]\n\n".to_owned();
    let mut renderer = Python {
        definitions: String::new(),
        next: 0,
    };
    for (id, definition) in &project.assertion_definitions {
        let shape = fields(
            definition
                .outputs
                .iter()
                .map(|(name, output)| (name.to_string(), output_shape(output, compiled))),
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
    for (catalog, response) in [("SourceFacts", false), ("SourceResponses", true)] {
        let mut entries = Vec::new();
        for (id, source) in &project.sources {
            let shape = if response {
                project::value_schema(&source.response.shape)
            } else {
                facts(source)
            };
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
