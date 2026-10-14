//! Deterministic lowering into the retained bounded runtime bundle model.
//! Bytes are supplied by the caller. No source data or secret is accepted here.
use crate::{
    finding::{FieldPath, Finding},
    project::{self, EvidenceProject, FunctionInterface, SourceType},
};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug)]
pub struct CompiledProject {
    pub model: Value,
    pub artifacts: BTreeMap<String, Vec<u8>>,
    pub functions: Vec<Value>,
}

/// Compile one validated project and reviewed function assets. Target bindings
/// are intentionally absent: the package only names connection identifiers.
pub fn compile(
    project: &EvidenceProject,
    scripts: &BTreeMap<String, String>,
) -> Result<CompiledProject, Vec<Finding>> {
    let mut findings = project::validate_project(project);
    if !findings.is_empty() {
        return Err(findings);
    }
    let mut artifacts = BTreeMap::new();
    let mut functions = Vec::new();
    for function in &project.functions {
        let at = FieldPath::root()
            .key("functions")
            .map_key(function.id.to_string());
        let Some(script) = scripts.get(&function.source) else {
            findings.push(Finding::new(
                at.key("source"),
                "function-asset-missing",
                "the named Function asset was not supplied",
            ));
            continue;
        };
        findings.extend(
            crate::derivation::validate_function(script, function.interface)
                .into_iter()
                .map(|mut finding| {
                    finding.field = finding.field.under(&at);
                    finding
                }),
        );
        let mut sites = Vec::new();
        let mut bindings = Vec::new();
        for (id, source) in &project.sources {
            if let Some(batch) = &source.batch {
                for (field, call, interface) in [
                    ("prepare", &batch.prepare, FunctionInterface::SourcePrepare),
                    ("extract", &batch.extract, FunctionInterface::SourceExtract),
                ] {
                    if call.function == function.id {
                        sites.push(format!("/sources/{id}/batch/{field}"));
                        bindings.push(json!({"path":format!("/sources/{id}/batch/{field}"),"inputs":{"response":project::value_schema(&batch.response.shape),"items":{"type":"array","maximumItems":batch.maximum_items,"selectors":selector_types(project,source)},"parameters":source.adapter_parameters_schema},"outputs":{"slottedResults":{"outcome":{"enum":["match","no_match","ambiguous"]},"facts":source.facts}},"limits":{"maximumItems":batch.maximum_items,"source":source.limits}}));
                        findings.extend(
                            crate::derivation::validate_batch_function(script, interface)
                                .into_iter()
                                .map(|mut finding| {
                                    finding.field = finding.field.under(
                                        &FieldPath::root()
                                            .key("sources")
                                            .map_key(id.to_string())
                                            .key("batch")
                                            .key(field)
                                            .key("function"),
                                    );
                                    finding
                                }),
                        );
                    }
                }
            }
            if source.extract.function == function.id {
                sites.push(format!("/sources/{id}/extract"));
                bindings.push(json!({"path":format!("/sources/{id}/extract"),"inputs":{"response":project::value_schema(&source.response.shape),"selectors":selector_types(project, source),"parameters":source.adapter_parameters_schema},"outputs":{"outcome":{"enum":["match","no_match","ambiguous"]},"facts":source.facts.iter().map(|(name,shape)|(name.to_string(),project::value_schema(shape))).collect::<Map<_,_>>()},"limits":source.limits}));
            }
            if source
                .prepare
                .as_ref()
                .is_some_and(|call| call.function == function.id)
            {
                sites.push(format!("/sources/{id}/prepare"));
                bindings.push(json!({"path":format!("/sources/{id}/prepare"),"inputs":{"selectors":selector_types(project, source),"parameters":source.adapter_parameters_schema},"outputs":{"query":"bounded-name-value-pairs","body":"bounded-json"},"limits":source.preparation_limits.clone().unwrap_or_else(default_preparation_limits)}));
            }
        }
        for (id, definition) in &project.assertion_definitions {
            if definition.derive.function == function.id {
                sites.push(format!("/assertionDefinitions/{id}/derive"));
                bindings.push(json!({"path":format!("/assertionDefinitions/{id}/derive"),"inputs":{"facts":definition.acquisition.source_ids().into_iter().map(|source|(source.to_string(),json!(project.sources[source].facts.iter().map(|(name,shape)|(name.to_string(),project::value_schema(shape))).collect::<Map<_,_>>()))).collect::<Map<_,_>>(),"selectors":definition.derive.selector_inputs,"parameters":definition.derive.parameters},"outputs":definition.outputs}));
            }
        }
        functions.push(json!({"id": function.id, "interface": function.interface, "source": function.source, "label":function.label, "description":function.description, "capabilities": function.interface.capabilities(), "callSites": sites, "bindings":bindings}));
        let ordinary_source_call = project.sources.values().any(|source| {
            source.extract.function == function.id
                || source
                    .prepare
                    .as_ref()
                    .is_some_and(|call| call.function == function.id)
        });
        if function.interface != FunctionInterface::AssertionDerive && ordinary_source_call {
            artifacts.insert(
                format!("adapters/{}.rhai", function.id),
                format!(
                    "// Evidence Function {} interface {}\n{script}",
                    function.id,
                    serde_json::to_value(function.interface)
                        .expect("interface")
                        .as_str()
                        .expect("interface string")
                )
                .into_bytes(),
            );
        }
    }
    if !findings.is_empty() {
        return Err(findings);
    }
    let function = |id: &registry_platform_yaml::LocalId| {
        project
            .functions
            .iter()
            .find(|f| &f.id == id)
            .expect("validated Function reference")
    };
    let mut sources = Map::new();
    for (id, source) in &project.sources {
        let response_path = format!("schemas/{id}-response.schema.json");
        let facts_path = format!("schemas/{id}-facts.schema.json");
        let parameters_path = format!("schemas/{id}-parameters.schema.json");
        let facts = json!({"type":"object", "additionalProperties":false, "required":source.facts.keys().collect::<Vec<_>>(), "properties":source.facts.iter().map(|(name, shape)| (name.to_string(), project::value_schema(shape))).collect::<Map<_, _>>()});
        artifact(
            &mut artifacts,
            &response_path,
            &project::value_schema(&source.response.shape),
        );
        artifact(&mut artifacts, &facts_path, &facts);
        if source.source_type == SourceType::HttpJson || source.prepare.is_some() {
            artifact(
            &mut artifacts,
            &parameters_path,
            &source.adapter_parameters_schema.clone().unwrap_or_else(
                || json!({"type":"object", "additionalProperties":false, "properties":{}, "required":[]}),
            ),
        );
        }
        let selector_inputs = source.selectors.iter().map(|selector| json!({"role":selector.role,"alternatives":selector.profiles.iter().map(|profile| json!({"profile":profile,"fields":project.selector_profiles[profile].fields.keys().collect::<Vec<_>>()})).collect::<Vec<_>>()})).collect::<Vec<_>>();
        let mut request = source.request.clone();
        let Some(request_map) = request.as_object_mut() else {
            return Err(vec![Finding::new(
                FieldPath::root()
                    .key("sources")
                    .map_key(id.to_string())
                    .key("request"),
                "source-request",
                "Source request must be an object",
            )]);
        };
        request_map.insert("selectorInputs".to_owned(), json!(selector_inputs));
        request_map.insert("projection".to_owned(), json!(source.response.projection));
        request_map.insert(
            "attemptTimeoutMilliseconds".to_owned(),
            json!(source.limits.attempt_timeout_milliseconds),
        );
        request_map.insert(
            "maximumResponseBytes".to_owned(),
            json!(source.response.maximum_bytes),
        );
        request_map.insert(
            "maximumConcurrency".to_owned(),
            json!(source.limits.maximum_concurrency),
        );
        if source.source_type == SourceType::SqliteExtract {
            if let Some(Value::Object(bindings)) = request_map.get_mut("parameterBindings") {
                lower_bindings(
                    bindings,
                    &FieldPath::root()
                        .key("sources")
                        .map_key(id.to_string())
                        .key("request")
                        .key("parameterBindings"),
                    &["selector", "prepared"],
                )?;
            }
            if let Some(call) = &source.prepare {
                request_map.insert(
                    "prepareScript".to_owned(),
                    json!(format!("adapters/{}.rhai", function(&call.function).id)),
                );
                request_map.insert(
                    "adapterParameters".to_owned(),
                    source
                        .adapter_parameters
                        .clone()
                        .unwrap_or_else(|| json!({})),
                );
                request_map.insert("adapterParametersSchema".to_owned(), json!(parameters_path));
                if let Some(limits) = &source.preparation_limits {
                    request_map.insert("preparationLimits".to_owned(), limits.clone());
                }
            }
            if let Some(path) = request_map.get("statement").and_then(Value::as_str) {
                let Some(sql) = scripts.get(path) else {
                    return Err(vec![Finding::new(
                        FieldPath::root()
                            .key("sources")
                            .map_key(id.to_string())
                            .key("request")
                            .key("statement"),
                        "source-statement",
                        "the reviewed SQL statement asset was not supplied",
                    )]);
                };
                artifacts.insert(path.to_owned(), sql.as_bytes().to_vec());
            }
        }
        if source.source_type == SourceType::HttpJson {
            let prepare_path = match &source.prepare {
                Some(call) => format!("adapters/{}.rhai", function(&call.function).id),
                None => {
                    let path = format!("adapters/{id}-prepare.rhai");
                    artifacts.insert(
                        path.clone(),
                        b"fn prepare(selectors, context) { #{query: [], body: ()} }\n".to_vec(),
                    );
                    path
                }
            };
            request_map.insert("prepareScript".to_owned(), json!(prepare_path));
            request_map.insert(
                "adapterParameters".to_owned(),
                source
                    .adapter_parameters
                    .clone()
                    .unwrap_or_else(|| json!({})),
            );
            request_map.insert("adapterParametersSchema".to_owned(), json!(parameters_path));
            request_map.insert(
                "preparationLimits".to_owned(),
                source
                    .preparation_limits
                    .clone()
                    .unwrap_or_else(default_preparation_limits),
            );
            request_map.insert("projection".to_owned(), json!(source.response.projection));
            request_map.insert("redirects".to_owned(), json!("deny"));
            request_map.insert(
                "attemptTimeoutMilliseconds".to_owned(),
                json!(source.limits.attempt_timeout_milliseconds),
            );
            request_map.insert(
                "maximumResponseBytes".to_owned(),
                json!(source.response.maximum_bytes),
            );
            request_map.insert(
                "maximumConcurrency".to_owned(),
                json!(source.limits.maximum_concurrency),
            );
            if let Some(Value::Object(bindings)) = request_map.get_mut("pathBindings") {
                lower_bindings(
                    bindings,
                    &FieldPath::root()
                        .key("sources")
                        .map_key(id.to_string())
                        .key("request")
                        .key("pathBindings"),
                    &["selector", "fact"],
                )?;
            }
        }
        let mut compiled = json!({"type":source.source_type,"posture":source.acquisition_posture,"request":request,"responseSchema":response_path,"extractScript":format!("adapters/{}.rhai", function(&source.extract.function).id),"factSchema":facts_path});
        if let Some(connection) = &source.connection {
            compiled["connection"] = json!(connection);
        }
        if let Some(profile) = &source.extract_profile {
            compiled["extractProfile"] = json!(profile);
        }
        if let Some(age) = &source.maximum_extract_age_seconds {
            compiled["maximumExtractAgeSeconds"] = json!(age);
        }
        if let Some(batch) = &source.batch {
            let response_path = format!("schemas/{id}-batch-response.schema.json");
            artifact(
                &mut artifacts,
                &response_path,
                &project::value_schema(&batch.response.shape),
            );
            let prepare = function(&batch.prepare.function);
            let extract = function(&batch.extract.function);
            let prepare_path = format!("adapters/{id}-batch-prepare.rhai");
            let extract_path = format!("adapters/{id}-batch-extract.rhai");
            artifacts.insert(
                prepare_path.clone(),
                format!(
                    "// Evidence Function {} interface source-prepare/v1 batch\n{}",
                    prepare.id,
                    rename_entry(&scripts[&prepare.source], "prepare", "prepare_batch")
                )
                .into_bytes(),
            );
            artifacts.insert(
                extract_path.clone(),
                format!(
                    "// Evidence Function {} interface source-extract/v1 batch\n{}",
                    extract.id,
                    rename_entry(&scripts[&extract.source], "extract", "extract_batch")
                )
                .into_bytes(),
            );
            compiled["batch"] = json!({"maximumItems":batch.maximum_items,"prepareScript":prepare_path,"extractScript":extract_path,"responseSchema":response_path,"projection":batch.response.projection});
        }
        if let Some(evidence) = &source.evidence {
            compiled["evidence"] = evidence.clone();
        }
        if let Some(problem) = &source.unresolved_problem {
            compiled["unresolvedProblem"] = problem.clone();
        }
        if let Some(revision) = &source.behavior_revision {
            compiled["behaviorRevision"] = json!(revision);
        }
        if source.forward_access_attribution {
            compiled["forwardAccessAttribution"] = json!(true);
        }
        sources.insert(id.to_string(), compiled);
    }
    let mut requirements = Vec::new();
    for (id, definition) in &project.assertion_definitions {
        let mut concepts = Vec::new();
        for (name, output) in &definition.outputs {
            let mut constraints = serde_json::to_value(output).expect("Output serializes");
            let map = constraints.as_object_mut().expect("Output is object");
            for field in ["concept", "type", "sdJwtVc", "label", "description"] {
                map.remove(field);
            }
            if output.value_type == "controlled-category"
                || output.value_type == "controlled-category-list"
            {
                map.remove("values");
                let path = format!("codelists/{id}-{name}.yaml");
                artifact(
                    &mut artifacts,
                    &path,
                    &json!({"apiVersion":"id.registrystack.org/formats/evidence/codelist/v1alpha1","kind":"EvidenceCodelist","uri":format!("{}:values",output.concept),"version":"1","type":"code-list","codes":output.values}),
                );
                map.insert("codelist".to_owned(), json!(path));
                map.insert(
                    "categoryScheme".to_owned(),
                    json!(format!("{}:values", output.concept)),
                );
                map.insert("schemeVersion".to_owned(), json!("1"));
                map.insert(
                    "maximumBytes".to_owned(),
                    json!(output.values.iter().map(String::len).max().unwrap_or(1)),
                );
            }
            if let Some(path) = &output.schema {
                let Some(text) = scripts.get(path) else {
                    return Err(vec![Finding::new(
                        FieldPath::root()
                            .key("assertionDefinitions")
                            .map_key(id.to_string())
                            .key("outputs")
                            .map_key(name.to_string())
                            .key("schema"),
                        "output-schema",
                        "the reviewed Output schema asset was not supplied",
                    )]);
                };
                let schema = crate::formats::scan_authored(path, text.as_bytes())
                    .ok()
                    .flatten()
                    .map(|node| node.to_json_value());
                let Some(schema) = schema else {
                    return Err(vec![Finding::new(
                        FieldPath::root(),
                        "output-schema",
                        "the reviewed Output schema is invalid",
                    )]);
                };
                let findings = crate::validate::validate_output_schema_document(&schema);
                if !findings.is_empty() {
                    return Err(findings);
                }
                let Some(uri) = schema
                    .get("$id")
                    .and_then(Value::as_str)
                    .filter(|uri| url::Url::parse(uri).is_ok())
                else {
                    return Err(vec![Finding::new(
                        FieldPath::root(),
                        "output-schema",
                        "the reviewed Output schema requires an absolute $id",
                    )]);
                };
                map.insert("schema".to_owned(), json!(uri));
                artifact(&mut artifacts, path, &schema);
            }
            let mut concept = json!({"handle":name,"uri":output.concept,"type":output.value_type,"required":true,"constraints":constraints});
            if let Some(projection) = &output.sd_jwt_vc {
                concept["sdJwtVc"] = projection.clone();
            }
            concepts.push(concept);
        }
        let derive = function(&definition.derive.function);
        let script = &scripts[&derive.source];
        let declared = definition
            .acquisition
            .source_ids()
            .into_iter()
            .flat_map(|source| {
                project.sources[source]
                    .facts
                    .keys()
                    .map(ToString::to_string)
            })
            .collect::<BTreeSet<_>>();
        let findings = crate::derivation::validate_derive_fact_reads(script, &declared);
        if !findings.is_empty() {
            return Err(findings
                .into_iter()
                .map(|mut finding| {
                    finding.field = finding.field.under(
                        &FieldPath::root()
                            .key("assertionDefinitions")
                            .map_key(id.to_string())
                            .key("derive"),
                    );
                    finding
                })
                .collect());
        }
        let derive_path = format!("derivations/{id}.rhai");
        let compiled_script = wrap_derivation(
            script,
            &definition
                .outputs
                .iter()
                .map(|(name, output)| (name.to_string(), output.concept.clone()))
                .collect(),
        );
        let compiled_script = format!(
            "// Evidence Function {} interface assertion-derive/v1\n{compiled_script}",
            derive.id
        );
        artifacts.insert(derive_path.clone(), compiled_script.into_bytes());
        let mut requirement = json!({"handle":id,"uri":definition.semantics.requirement,"question":definition.question,"kind":definition.semantics.kind,"grantCeiling":definition.grant_ceiling,"representations":definition.representations,"acquisition":definition.acquisition,"purposes":[definition.purpose],"subjectRoles":definition.subjects.iter().map(|subject| json!({"role":subject.role,"cardinality":"one","selectorProfiles":subject.selectors})).collect::<Vec<_>>(),"referenceFrameworks":definition.semantics.reference_frameworks,"evidenceType":definition.semantics.evidence_type,"observationTimezone":definition.observation_timezone,"validitySeconds":definition.validity_seconds,"subjectBinding":definition.subject_binding,"derivation":{"script":derive_path,"parameters":definition.derive.parameters},"concepts":concepts,"disclosureGuard":definition.disclosure_guard.clone().unwrap_or_else(|| json!({"families":[definition.semantics.requirement]})),"existenceDisclosure":definition.existence_disclosure});
        if !definition.derive.selector_inputs.is_empty() {
            requirement["derivation"]["selectorInputs"] = json!(definition.derive.selector_inputs);
        }
        if let Some(fixtures) = &definition.fixtures {
            requirement["fixtures"] = json!(fixtures);
        }
        requirements.push(requirement);
    }
    let mut model = json!({"project":project.id,"acquisitionCapabilities":project.acquisition_capabilities,"maximumHolderBoundBatchSize":project.maximum_holder_bound_batch_size,"selectorProfiles":project.selector_profiles.iter().map(|(id,profile)|(id.to_string(),json!({"fields":profile.fields,"maximumAggregateBytes":profile.maximum_aggregate_bytes}))).collect::<Map<_,_>>(),"sources":sources,"requirements":requirements});
    if project.maximum_holder_bound_batch_size.is_none() {
        model
            .as_object_mut()
            .expect("model")
            .remove("maximumHolderBoundBatchSize");
    }
    Ok(CompiledProject {
        model,
        artifacts,
        functions,
    })
}
fn artifact(artifacts: &mut BTreeMap<String, Vec<u8>>, path: &str, value: &Value) {
    artifacts.insert(
        path.to_owned(),
        serde_json::to_vec_pretty(value).expect("JSON value serializes"),
    );
}

/// The wrapper translates only declared public Output names. Unknown, duplicate,
/// missing and malformed entries still reach the runtime's exact-set validator.
fn wrap_derivation(source: &str, outputs: &BTreeMap<String, String>) -> String {
    let renamed = rename_entry(source, "derive", "authored_derive");
    let mut result =
        format!("{renamed}\nfn derive(facts, selectors, context) {{\n    let declared = #{{\n");
    for (name, concept) in outputs {
        result.push_str(&format!("        {}: {},\n", json!(name), json!(concept)));
    }
    result.push_str("    };\n    let values = authored_derive(facts, selectors, context);\n    let result = [];\n    for value in values {\n        if type_of(value) != \"map\" || !value.contains(\"output\") || !value.contains(\"value\") || value.len() != 2 || !declared.contains(value.output) { throw(\"undeclared_output\"); }\n        result.push(#{concept_id: declared[value.output], value: value.value});\n    }\n    result\n}\n");
    result
}

// Tokenize only enough to locate a declared function name, ignoring comments
// and quoted text. The Rhai parser has already validated the whole program.
fn rename_entry(source: &str, from: &str, to: &str) -> String {
    let bytes = source.as_bytes();
    let mut i = 0;
    let mut previous = "";
    while i < bytes.len() {
        if bytes[i..].starts_with(b"//") {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if bytes[i..].starts_with(b"/*") {
            i += 2;
            let mut depth = 1;
            while i < bytes.len() && depth > 0 {
                if bytes[i..].starts_with(b"/*") {
                    depth += 1;
                    i += 2;
                } else if bytes[i..].starts_with(b"*/") {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            continue;
        }
        if matches!(bytes[i], b'"' | b'\'' | b'`') {
            let quote = bytes[i];
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i = (i + 2).min(bytes.len());
                } else if bytes[i] == quote {
                    i += 1;
                    break;
                } else {
                    i += 1;
                }
            }
            continue;
        }
        if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' {
            let start = i;
            i += 1;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let token = &source[start..i];
            if previous == "fn" && token == from {
                return format!("{}{}{}", &source[..start], to, &source[i..]);
            }
            previous = token;
        } else {
            if !bytes[i].is_ascii_whitespace() {
                previous = "";
            }
            i += 1;
        }
    }
    source.to_owned()
}

/// Source dependencies used for revision and inspection, never source values.
pub fn definition_dependencies(project: &EvidenceProject, id: &str) -> Option<Value> {
    let definition = project
        .assertion_definitions
        .iter()
        .find_map(|(key, value)| (key.as_str() == id).then_some(value))?;
    let source_ids = definition.acquisition.source_ids();
    let mut function_ids = BTreeSet::from([&definition.derive.function]);
    for id in &source_ids {
        let source = &project.sources[*id];
        function_ids.insert(&source.extract.function);
        if let Some(batch) = &source.batch {
            function_ids.insert(&batch.prepare.function);
            function_ids.insert(&batch.extract.function);
        }
        if let Some(prepare) = &source.prepare {
            function_ids.insert(&prepare.function);
        }
    }
    let mut behavior = serde_json::to_value(definition).ok()?;
    behavior.as_object_mut()?.remove("question");
    Some(behavior_value(
        json!({"definition":behavior,"sources":source_ids.into_iter().map(|id| (id.as_str(), &project.sources[id])).collect::<BTreeMap<_, _>>(),"selectors":definition.subjects.iter().flat_map(|subject| subject.selectors.iter()).map(|id| (id.as_str(), &project.selector_profiles[id])).collect::<BTreeMap<_, _>>(),"functions":project.functions.iter().filter(|function| function_ids.contains(&function.id)).collect::<Vec<_>>()}),
    ))
}

fn default_preparation_limits() -> Value {
    json!({"query":"allowed", "jsonBody":"forbidden", "maximumNormalizedBytes":4096})
}
fn selector_types(project: &EvidenceProject, source: &project::Source) -> Value {
    json!(source.selectors.iter().map(|selector| json!({"role":selector.role,"profiles":selector.profiles.iter().map(|id|(id.to_string(),json!(project.selector_profiles[id].fields.iter().map(|(name,shape)|(name.to_string(),project::value_schema(shape))).collect::<Map<_,_>>()))).collect::<Map<_,_>>()})).collect::<Vec<_>>())
}

fn behavior_value(mut value: Value) -> Value {
    match &mut value {
        Value::Object(object) => {
            object.remove("label");
            object.remove("description");
            for child in object.values_mut() {
                *child = behavior_value(child.take());
            }
        }
        Value::Array(values) => {
            for child in values {
                *child = behavior_value(child.take());
            }
        }
        _ => {}
    }
    value
}

fn lower_bindings(
    bindings: &mut Map<String, Value>,
    path: &FieldPath,
    allowed: &[&str],
) -> Result<(), Vec<Finding>> {
    for (name, binding) in bindings {
        let Some(object) = binding.as_object().filter(|object| object.len() == 1) else {
            return Err(vec![Finding::new(
                path.clone().map_key(name.clone()),
                "source-binding",
                "declare exactly one named binding origin",
            )]);
        };
        let (origin, body) = object.iter().next().expect("one origin");
        if !allowed.contains(&origin.as_str()) || !body.is_object() {
            return Err(vec![Finding::new(
                path.clone().map_key(name.clone()),
                "source-binding",
                "declare a supported named binding origin with its typed fields",
            )]);
        }
        let mut lowered = body.clone();
        lowered["type"] = json!(origin);
        *binding = lowered;
    }
    Ok(())
}
