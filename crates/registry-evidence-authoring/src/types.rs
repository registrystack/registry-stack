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
    compiled: &CompiledProject,
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
                                    (
                                        name,
                                        if let Some((path, _)) = value.codelist() {
                                            codelist_codes(path, compiled)
                                        } else {
                                            project::value_schema(&crate::selector::compiled(value))
                                        },
                                    )
                                })),
                            ),
                        ])
                    })
                    .collect(),
            ),
        )
    }))
}
fn source_selectors(
    project: &EvidenceProject,
    compiled: &CompiledProject,
    source: &Source,
) -> Value {
    selectors(
        project,
        compiled,
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
fn derive_selectors(
    project: &EvidenceProject,
    compiled: &CompiledProject,
    inputs: &[project::DeriveSelectorInput],
) -> Value {
    selectors(
        project,
        compiled,
        inputs.iter().map(|input| {
            (
                input.role.to_string(),
                input
                    .alternatives
                    .iter()
                    .map(|alternative| {
                        (
                            alternative.profile.to_string(),
                            alternative.fields.iter().map(ToString::to_string).collect(),
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
struct SourceCall<'a> {
    definition: &'a registry_platform_yaml::LocalId,
    source: &'a registry_platform_yaml::LocalId,
    stage: &'static str,
    prior_facts: Value,
}
fn source_calls(project: &EvidenceProject) -> Vec<SourceCall<'_>> {
    let mut calls = Vec::new();
    for (id, definition) in &project.assertion_definitions {
        match &definition.acquisition {
            project::Acquisition::Single { source } => calls.push(SourceCall {
                definition: id,
                source,
                stage: "single",
                prior_facts: object(Map::new()),
            }),
            project::Acquisition::SearchThenFetch { search, fetch } => {
                calls.push(SourceCall {
                    definition: id,
                    source: search,
                    stage: "search",
                    prior_facts: object(Map::new()),
                });
                calls.push(SourceCall {
                    definition: id,
                    source: fetch,
                    stage: "fetch",
                    prior_facts: facts(&project.sources[search]),
                });
            }
            project::Acquisition::SearchThenFetchSet { search, fetch, .. } => {
                calls.push(SourceCall {
                    definition: id,
                    source: search,
                    stage: "search",
                    prior_facts: object(Map::new()),
                });
                for member in fetch {
                    calls.push(SourceCall {
                        definition: id,
                        source: &member.source,
                        stage: "fetch",
                        prior_facts: fields(
                            project.sources[search]
                                .facts
                                .iter()
                                .filter(|(name, _)| {
                                    member
                                        .fact_inputs
                                        .iter()
                                        .any(|input| input == name.as_str())
                                })
                                .map(|(name, value)| {
                                    (name.to_string(), project::value_schema(value))
                                }),
                        ),
                    });
                }
            }
        }
    }
    calls
}
pub(crate) fn function_shape(
    project: &EvidenceProject,
    compiled: &CompiledProject,
    function: &project::Function,
) -> Value {
    let mut calls = Vec::new();
    let extraction_arity = compiled
        .functions
        .iter()
        .find(|entry| entry["id"] == json!(function.id))
        .and_then(|entry| entry["arity"].as_u64())
        .unwrap_or(3);
    for call in source_calls(project) {
        let id = call.source;
        let source = &project.sources[id];
        let prior = call.prior_facts;
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
                    (
                        "selectors".to_owned(),
                        source_selectors(project, compiled, source),
                    ),
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
                    (
                        "selectors".to_owned(),
                        source_selectors(project, compiled, source),
                    ),
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
                    ("definition".to_owned(), literal(json!(call.definition))),
                    ("stage".to_owned(), literal(json!(call.stage))),
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
                (
                    "selectors".to_owned(),
                    source_selectors(project, compiled, source),
                ),
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
                        ("definition".to_owned(), literal(json!(call.definition))),
                        ("stage".to_owned(), literal(json!(call.stage))),
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
                .derivation_source_ids()
                .into_iter()
                .flat_map(|id| project.sources[id].facts.iter())
                .map(|(id, shape)| (id.to_string(), project::value_schema(shape))),
        );
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
                        derive_selectors(project, compiled, &definition.derive.selector_inputs),
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
