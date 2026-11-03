//! Deterministic lowering into the retained bounded runtime bundle model.
//! Bytes are supplied by the caller. No source data or secret is accepted here.
use crate::{
    finding::{FieldPath, Finding},
    project::{self, AcquisitionPosture, EvidenceProject, PackReference},
};
use registry_platform_yaml::{ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const ADAPTER_PACK_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: "AdapterPack",
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(
            "id.registrystack.org/formats/adapter/pack/v1alpha1",
        )],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

#[derive(Debug)]
pub struct CompiledProject {
    pub model: Value,
    pub artifacts: BTreeMap<String, Vec<u8>>,
    pub functions: Vec<Value>,
    /// The checked route result contracts used by derivation/type projection.
    pub source_facts: BTreeMap<String, Value>,
}

/// Exact, already-checked pack closure supplied by tooling or an in-memory
/// editor host. This crate performs no pack loading and no I/O.
#[derive(Clone, Debug)]
pub struct CheckedPackRoute {
    pub pack: PackReference,
    pub route: registry_platform_yaml::LocalId,
    pub digest: String,
    pub inputs_schema: Value,
    pub facts_schema: Value,
    pub acquisition_posture: AcquisitionPosture,
    pub pack_bytes: Vec<u8>,
    pub artifacts: BTreeMap<String, Vec<u8>>,
}

/// Compile one validated project and reviewed function assets. Target bindings
/// are intentionally absent: the package only names connection identifiers.
pub fn compile(
    project: &EvidenceProject,
    scripts: &BTreeMap<String, String>,
) -> Result<CompiledProject, Vec<Finding>> {
    compile_with_pack_routes(project, scripts, &[])
}

/// Compile against explicit checked pack/route closures. A Source without an
/// exact closure is refused instead of being lowered to the retired executor.
pub fn compile_with_pack_routes(
    project: &EvidenceProject,
    scripts: &BTreeMap<String, String>,
    pack_routes: &[CheckedPackRoute],
) -> Result<CompiledProject, Vec<Finding>> {
    let mut findings = project::validate_project(project);
    if !findings.is_empty() {
        return Err(findings);
    }
    let mut artifacts = BTreeMap::new();
    let mut functions = Vec::new();
    for (function_index, function) in project.functions.iter().enumerate() {
        let at = FieldPath::root().key("functions").index(function_index);
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
        for (id, definition) in &project.assertion_definitions {
            if definition.derive.function == function.id {
                sites.push(format!("/assertionDefinitions/{id}/derive"));
            }
        }
        functions.push(json!({"id": function.id, "interface": function.interface, "arity": crate::derivation::function_arity(script,function.interface), "source": function.source, "label":function.label, "description":function.description, "capabilities": function.interface.capabilities(), "callSites": sites}));
    }
    if !findings.is_empty() {
        return Err(findings);
    }
    let function = |id: &registry_platform_yaml::LocalId| {
        project
            .functions
            .iter()
            .find(|function| &function.id == id)
            .expect("validated Function reference")
    };
    let mut sources = Map::new();
    let mut source_facts = BTreeMap::new();
    for (id, source) in &project.sources {
        let source_at = FieldPath::root().key("sources").map_key(id.to_string());
        let matches = pack_routes
            .iter()
            .filter(|route| route.pack == source.pack && route.route == source.route)
            .collect::<Vec<_>>();
        let Some(route) = matches.first().copied() else {
            findings.push(Finding::new(
                source_at.clone().key("pack"),
                "source-pack-closure-missing",
                "supply the checked closure for this exact pack version and route",
            ));
            continue;
        };
        if matches.len() != 1 {
            findings.push(Finding::new(
                source_at.clone().key("pack"),
                "source-pack-closure-ambiguous",
                "supply exactly one checked closure for this pack version and route",
            ));
            continue;
        }
        findings.extend(verify_pack_closure(route, source_at.clone()));
        let Some(route_inputs) = closed_schema_properties(&route.inputs_schema) else {
            findings.push(Finding::new(
                source_at.clone().key("route"),
                "source-route-input-schema",
                "the checked route input schema must be a closed object",
            ));
            continue;
        };
        let Some(route_facts) = closed_schema_properties(&route.facts_schema) else {
            findings.push(Finding::new(
                source_at.clone().key("route"),
                "source-route-facts",
                "the checked route facts schema must be a closed object",
            ));
            continue;
        };
        if route_facts.is_empty() || route_facts.len() > 64 {
            findings.push(Finding::new(
                source_at.clone().key("route"),
                "source-route-facts",
                "the checked route must declare between one and 64 typed final facts",
            ));
        }
        if posture_rank(source.acquisition_posture) < posture_rank(route.acquisition_posture) {
            findings.push(Finding::new(
                source_at.clone().key("acquisitionPosture"),
                "source-acquisition-posture",
                "the binding cannot claim a stronger posture than the checked route contract",
            ));
        }
        for required in route.inputs_schema["required"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if !source.inputs.keys().any(|input| input.as_str() == required) {
                findings.push(Finding::new(
                    source_at.clone().key("inputs"),
                    "source-route-input-required",
                    format!("map required route input {required}"),
                ));
            }
        }
        for (input_name, binding) in &source.inputs {
            let input_at = source_at
                .clone()
                .key("inputs")
                .map_key(input_name.to_string());
            let Some(contract) = route_inputs.get(input_name.as_str()) else {
                findings.push(Finding::new(
                    input_at,
                    "source-route-input-unknown",
                    "map only inputs declared by the checked route contract",
                ));
                continue;
            };
            if let Some(field) = project
                .selector_profiles
                .get(&binding.selector.profile)
                .and_then(|profile| profile.fields.get(&binding.selector.field))
            {
                let selector_schema = project::value_schema(&crate::selector::compiled(field));
                if !input_schema_accepts(contract, &selector_schema) {
                    findings.push(Finding::new(
                        input_at.key("selector"),
                        "source-route-input-type",
                        "the authorized selector field does not fit the checked route input schema",
                    ));
                }
            }
        }
        let facts_path = format!("schemas/source-facts/{id}.schema.json");
        insert_json_artifact(
            &mut artifacts,
            &facts_path,
            &route.facts_schema,
            source_at.clone().key("route"),
        )?;
        let digest_path = route
            .digest
            .strip_prefix("sha256:")
            .unwrap_or(&route.digest);
        let artifact_prefix = format!("adapter-packs/{}/{digest_path}", source.pack.id);
        if !route.pack_bytes.is_empty() {
            insert_artifact(
                &mut artifacts,
                &format!("{artifact_prefix}/pack.yaml"),
                route.pack_bytes.clone(),
                source_at.clone().key("pack"),
            )?;
        }
        for (path, bytes) in &route.artifacts {
            if !valid_pack_artifact_path(path) {
                findings.push(Finding::new(
                    source_at.clone().key("pack"),
                    "source-pack-artifact-path",
                    "checked pack artifact paths must be relative and traversal-free",
                ));
                continue;
            }
            insert_artifact(
                &mut artifacts,
                &format!("{artifact_prefix}/{path}"),
                bytes.clone(),
                source_at.clone().key("pack"),
            )?;
        }
        let compiled = json!({
            "pack": {"id":source.pack.id,"version":source.pack.version,"digest":route.digest,"artifactPrefix":artifact_prefix},
            "route": source.route,
            "connection": source.connection,
            "inputs": source.inputs,
            "posture": source.acquisition_posture,
            "factSchema": facts_path
        });
        source_facts.insert(id.to_string(), route.facts_schema.clone());
        sources.insert(id.to_string(), compiled);
    }
    if !findings.is_empty() {
        return Err(findings);
    }
    for (id, profile) in &project.selector_profiles {
        for (name, field) in &profile.fields {
            if let Some((path, version)) = field.codelist() {
                let at = FieldPath::root()
                    .key("selectorProfiles")
                    .map_key(id.to_string())
                    .key("fields")
                    .map_key(name.to_string())
                    .key("codelist");
                let bytes = scripts.get(path).ok_or_else(|| {
                    vec![Finding::new(
                        at.clone(),
                        "codelist-asset",
                        "the reviewed selector codelist asset was not supplied",
                    )]
                })?;
                let value =
                    crate::output::codelist_value(path, bytes.as_bytes()).ok_or_else(|| {
                        vec![Finding::new(
                            at.clone(),
                            "codelist-asset",
                            "the reviewed selector codelist asset is invalid",
                        )]
                    })?;
                if value["version"] != version {
                    return Err(vec![Finding::new(
                        at,
                        "codelist-identity",
                        "selector codelist version must match the reviewed asset",
                    )]);
                }
                insert_artifact(&mut artifacts, path, bytes.as_bytes().to_vec(), at)?;
            }
        }
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
            if output.value_type == "controlled-category" && !output.values.is_empty() {
                map.remove("values");
                let path = inline_codelist_path(id.as_str(), name.as_str());
                insert_json_artifact(
                    &mut artifacts,
                    &path,
                    &json!({"apiVersion":"id.registrystack.org/formats/evidence/codelist/v1alpha1","kind":"EvidenceCodelist","uri":format!("{}:values",output.concept),"version":"1","type":"code-list","codes":output.values}),
                    FieldPath::root()
                        .key("assertionDefinitions")
                        .map_key(id.to_string())
                        .key("outputs")
                        .map_key(name.to_string())
                        .key("values"),
                )?;
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
            if let Some(path) = &output.codelist {
                let bytes = scripts.get(path).ok_or_else(|| {
                    vec![Finding::new(
                        FieldPath::root()
                            .key("assertionDefinitions")
                            .map_key(id.to_string())
                            .key("outputs")
                            .map_key(name.to_string())
                            .key("codelist"),
                        "codelist-asset",
                        "the reviewed codelist asset was not supplied",
                    )]
                })?;
                let value =
                    crate::output::codelist_value(path, bytes.as_bytes()).ok_or_else(|| {
                        vec![Finding::new(
                            FieldPath::root()
                                .key("assertionDefinitions")
                                .map_key(id.to_string())
                                .key("outputs")
                                .map_key(name.to_string())
                                .key("codelist"),
                            "codelist-asset",
                            "the reviewed codelist asset must declare a bounded EvidenceCodelist",
                        )]
                    })?;
                let expected_version = output
                    .codelist_version
                    .as_ref()
                    .or(output.scheme_version.as_ref());
                if expected_version.is_some_and(|version| value["version"] != json!(version))
                    || output
                        .category_scheme
                        .as_ref()
                        .or(output.bucket_scheme.as_ref())
                        .is_some_and(|uri| value["uri"] != json!(uri))
                {
                    return Err(vec![Finding::new(
                        FieldPath::root()
                            .key("assertionDefinitions")
                            .map_key(id.to_string())
                            .key("outputs")
                            .map_key(name.to_string())
                            .key("codelist"),
                        "codelist-identity",
                        "codelist URI and version must match this Output",
                    )]);
                }
                insert_artifact(
                    &mut artifacts,
                    path,
                    bytes.as_bytes().to_vec(),
                    FieldPath::root()
                        .key("assertionDefinitions")
                        .map_key(id.to_string())
                        .key("outputs")
                        .map_key(name.to_string())
                        .key("codelist"),
                )?;
                if matches!(output.value_type.as_str(), "date-bucket" | "time-bucket") {
                    map.remove("codelist");
                }
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
                insert_json_artifact(
                    &mut artifacts,
                    path,
                    &schema,
                    FieldPath::root()
                        .key("assertionDefinitions")
                        .map_key(id.to_string())
                        .key("outputs")
                        .map_key(name.to_string())
                        .key("schema"),
                )?;
            }
            let mut concept = json!({"handle":name,"uri":output.concept,"type":output.value_type,"required":true,"constraints":constraints});
            if let Some(projection) = &output.sd_jwt_vc {
                concept["sdJwtVc"] = json!(projection);
            }
            concepts.push(concept);
        }
        let derive = function(&definition.derive.function);
        let script = &scripts[&derive.source];
        let declared = definition
            .acquisition
            .derivation_source_ids()
            .into_iter()
            .flat_map(|source| {
                source_facts[source.as_str()]["properties"]
                    .as_object()
                    .expect("checked facts schema properties")
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
        insert_artifact(
            &mut artifacts,
            &derive_path,
            compiled_script.into_bytes(),
            FieldPath::root()
                .key("assertionDefinitions")
                .map_key(id.to_string())
                .key("derive")
                .key("function"),
        )?;
        let mut requirement = json!({"handle":id,"uri":definition.semantics.requirement,"question":definition.question,"kind":definition.semantics.kind,"grantCeiling":definition.grant_ceiling,"representations":definition.representations,"acquisition":definition.acquisition,"purposes":[definition.purpose],"subjectRoles":definition.subjects.iter().map(|subject| json!({"role":subject.role,"cardinality":"one","selectorProfiles":subject.selectors})).collect::<Vec<_>>(),"referenceFrameworks":definition.semantics.reference_frameworks,"evidenceType":definition.semantics.evidence_type,"observationTimezone":definition.observation_timezone,"validitySeconds":definition.validity_seconds,"subjectBinding":definition.subject_binding,"derivation":{"script":derive_path,"parameters":definition.derive.parameters},"concepts":concepts,"disclosureGuard":definition.disclosure_guard.clone().unwrap_or_else(|| json!({"families":[definition.semantics.requirement]})),"existenceDisclosure":definition.existence_disclosure});
        if !definition.derive.selector_inputs.is_empty() {
            requirement["derivation"]["selectorInputs"] = json!(definition.derive.selector_inputs);
        }
        if let Some(fixtures) = &definition.fixtures {
            requirement["fixtures"] = json!(fixtures);
        }
        requirements.push(requirement);
    }
    let mut model = json!({"project":project.id,"maximumHolderBoundBatchSize":project.maximum_holder_bound_batch_size,"selectorProfiles":project.selector_profiles.iter().map(|(id,profile)|(id.to_string(),json!({"fields":profile.fields.iter().map(|(name,value)|(name.to_string(),crate::selector::compiled(value))).collect::<Map<_,_>>(),"maximumAggregateBytes":profile.maximum_aggregate_bytes}))).collect::<Map<_,_>>(),"sources":sources,"requirements":requirements});
    if project.maximum_holder_bound_batch_size.is_none() {
        model
            .as_object_mut()
            .expect("model")
            .remove("maximumHolderBoundBatchSize");
    }
    let mut compiled = CompiledProject {
        model,
        artifacts,
        functions,
        source_facts,
    };
    // Inspection and declaration generation share the same typed ABI projection.
    // The authored program returns local Output names; wrappers alone lower URIs.
    let interfaces = project
        .functions
        .iter()
        .map(|function| crate::types::function_shape(project, &compiled, function))
        .collect::<Vec<_>>();
    for (function, interface) in compiled.functions.iter_mut().zip(interfaces) {
        let calls = interface["properties"]["calls"]["anyOf"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        function["bindings"] = json!(calls
            .iter()
            .map(|call| {
                let properties = &call["properties"];
                json!({
                    "definition": properties["definition"]["enum"][0],
                    "mode": properties["mode"]["enum"][0],
                    "inputs": properties["inputs"]["properties"],
                    "outputs": properties["outputs"]
                })
            })
            .collect::<Vec<_>>());
        function["abi"] = interface;
    }
    Ok(compiled)
}
fn insert_json_artifact(
    artifacts: &mut BTreeMap<String, Vec<u8>>,
    path: &str,
    value: &Value,
    at: FieldPath,
) -> Result<(), Vec<Finding>> {
    insert_artifact(
        artifacts,
        path,
        serde_json::to_vec_pretty(value).expect("JSON value serializes"),
        at,
    )
}

fn insert_artifact(
    artifacts: &mut BTreeMap<String, Vec<u8>>,
    path: &str,
    bytes: Vec<u8>,
    at: FieldPath,
) -> Result<(), Vec<Finding>> {
    if artifacts
        .get(path)
        .is_some_and(|existing| existing != &bytes)
    {
        return Err(vec![Finding::new(
            at,
            "artifact-path-collision",
            "the compiled artifact path is already used for different content",
        )]);
    }
    artifacts.entry(path.to_owned()).or_insert(bytes);
    Ok(())
}

fn posture_rank(posture: AcquisitionPosture) -> u8 {
    match posture {
        AcquisitionPosture::SourceDerived => 0,
        AcquisitionPosture::FieldProjected => 1,
        AcquisitionPosture::RecordTransformed => 2,
    }
}

fn posture_wire(posture: AcquisitionPosture) -> &'static str {
    match posture {
        AcquisitionPosture::SourceDerived => "source-derived",
        AcquisitionPosture::FieldProjected => "field-projected",
        AcquisitionPosture::RecordTransformed => "record-transformed",
    }
}

fn closed_schema_properties(schema: &Value) -> Option<&Map<String, Value>> {
    (schema.get("type") == Some(&json!("object"))
        && schema.get("additionalProperties") == Some(&json!(false)))
    .then(|| schema.get("properties")?.as_object())?
}

fn input_schema_accepts(contract: &Value, selector: &Value) -> bool {
    if contract.get("type") != selector.get("type") {
        return false;
    }
    if let Some(allowed) = contract.get("enum").and_then(Value::as_array) {
        let Some(values) = selector.get("enum").and_then(Value::as_array) else {
            return false;
        };
        if values.iter().any(|value| !allowed.contains(value)) {
            return false;
        }
    }
    for (minimum, maximum) in [("minimum", "maximum"), ("minLength", "maxLength")] {
        if contract
            .get(minimum)
            .and_then(Value::as_i64)
            .is_some_and(|bound| {
                selector
                    .get(minimum)
                    .and_then(Value::as_i64)
                    .is_none_or(|value| value < bound)
            })
        {
            return false;
        }
        if contract
            .get(maximum)
            .and_then(Value::as_i64)
            .is_some_and(|bound| {
                selector
                    .get(maximum)
                    .and_then(Value::as_i64)
                    .is_none_or(|value| value > bound)
            })
        {
            return false;
        }
    }
    true
}

fn valid_pack_artifact_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

#[derive(Clone, Debug)]
struct PackArtifactReference {
    path: String,
    digest: String,
}

fn verify_pack_closure(route: &CheckedPackRoute, at: FieldPath) -> Vec<Finding> {
    let mut findings = Vec::new();
    if route.pack_bytes.is_empty() {
        findings.push(Finding::new(
            at.key("pack"),
            "source-pack-bytes-missing",
            "the checked closure must include the exact pack document bytes",
        ));
        return findings;
    }

    if !valid_sha256_uri(&route.digest) || sha256_uri(&route.pack_bytes) != route.digest {
        findings.push(Finding::new(
            at.clone().key("pack"),
            "source-pack-digest",
            "the declared pack digest must equal the SHA-256 digest of the supplied pack bytes",
        ));
    }

    let Ok(document) = Reader::new("pack.yaml")
        .decode::<Value>(&route.pack_bytes, &Expect::one(&ADAPTER_PACK_FORMAT))
        .map(|decoded| decoded.value)
    else {
        findings.push(Finding::new(
            at.key("pack"),
            "source-pack-document",
            "the supplied bytes must satisfy the current AdapterPack contract",
        ));
        return findings;
    };

    if document.get("id").and_then(Value::as_str) != Some(route.pack.id.as_str())
        || document.get("version").and_then(Value::as_str) != Some(route.pack.version.as_str())
    {
        findings.push(Finding::new(
            at.clone().key("pack"),
            "source-pack-identity",
            "the supplied pack document id and version must match the Source pack reference",
        ));
    }

    let mut references = BTreeMap::<String, String>::new();
    collect_pack_references(&document, &mut references, &mut findings, &at);

    let mut selected_routes = 0_usize;
    let mut selected_evidence = Vec::new();
    let Some(source_routes) = document.get("sourceRoutes").and_then(Value::as_array) else {
        findings.push(Finding::new(
            at.clone().key("route"),
            "source-pack-route-contract",
            "the supplied pack must declare the selected Evidence source route",
        ));
        return findings;
    };
    for source_route in source_routes {
        if source_route.get("id").and_then(Value::as_str) == Some(route.route.as_str()) {
            selected_routes += 1;
            if let Some(evidence) = source_route.get("evidence") {
                selected_evidence.push(evidence);
            }
        }
    }
    if selected_routes != 1 || selected_evidence.len() != 1 {
        findings.push(Finding::new(
            at.clone().key("route"),
            "source-pack-route-contract",
            "the supplied pack must declare exactly one selected route with an Evidence contract",
        ));
        return findings;
    }

    for (path, digest) in &references {
        if !valid_pack_artifact_path(path) || !valid_sha256_uri(digest) {
            findings.push(invalid_pack_reference(at.clone()));
            continue;
        }
        let Some(bytes) = route.artifacts.get(path) else {
            findings.push(Finding::new(
                at.clone().key("pack"),
                "source-pack-artifact-missing",
                "supply every artifact referenced by the pack document",
            ));
            continue;
        };
        if sha256_uri(bytes) != *digest {
            findings.push(Finding::new(
                at.clone().key("pack"),
                "source-pack-artifact-digest",
                "every supplied pack artifact must match its digest-pinned reference",
            ));
        }
    }
    if route
        .artifacts
        .keys()
        .any(|path| !references.contains_key(path))
    {
        findings.push(Finding::new(
            at.clone().key("pack"),
            "source-pack-artifact-unreferenced",
            "the checked closure may contain only artifacts pinned by the supplied pack document",
        ));
    }

    let evidence = selected_evidence[0];
    let pinned_posture = evidence
        .get("acquisitionPosture")
        .map(Value::as_str)
        .unwrap_or(Some("record-transformed"));
    if pinned_posture != Some(posture_wire(route.acquisition_posture)) {
        findings.push(Finding::new(
            at.clone().key("route"),
            "source-pack-posture-mismatch",
            "the supplied checked posture must equal the posture pinned by the selected route",
        ));
    }
    for (name, supplied) in [
        ("inputsSchema", &route.inputs_schema),
        ("factsSchema", &route.facts_schema),
    ] {
        let Some(reference) = evidence.get(name).and_then(pack_reference) else {
            findings.push(invalid_pack_reference(at.clone()));
            continue;
        };
        let artifact = route
            .artifacts
            .get(&reference.path)
            .and_then(|bytes| serde_json::from_slice::<Value>(bytes).ok());
        if artifact.as_ref() != Some(supplied) {
            findings.push(Finding::new(
                at.clone().key("route"),
                "source-pack-schema-mismatch",
                "the supplied checked schema must equal the schema artifact pinned by the selected route",
            ));
        }
    }

    findings
}

// The authoring library verifies supplied bytes without linking runtime
// capabilities. File-based hosts additionally parse the owning Adapter DTO.
fn collect_pack_references(
    document: &Value,
    references: &mut BTreeMap<String, String>,
    findings: &mut Vec<Finding>,
    at: &FieldPath,
) {
    for inventory in ["scripts", "queryFiles"] {
        if let Some(values) = document.get(inventory) {
            if let Some(values) = values.as_array() {
                for reference in values {
                    add_pack_reference(reference, references, findings, at.clone());
                }
            } else {
                findings.push(invalid_pack_reference(at.clone()));
            }
        }
    }
    if let Some(reference) = document.get("openApi") {
        add_pack_reference(reference, references, findings, at.clone());
    }
    if let Some(endpoints) = document.get("endpoints") {
        if let Some(endpoints) = endpoints.as_array() {
            for endpoint in endpoints {
                for (member, artifact) in
                    [("sqliteExtract", "statement"), ("hostProtocol", "config")]
                {
                    if let Some(declaration) = endpoint.get(member) {
                        if let Some(reference) = declaration.get(artifact) {
                            add_pack_reference(reference, references, findings, at.clone());
                        } else {
                            findings.push(invalid_pack_reference(at.clone()));
                        }
                    }
                }
            }
        } else {
            findings.push(invalid_pack_reference(at.clone()));
        }
    }
    for collection in ["sourceRoutes", "routes", "routeTemplates"] {
        if let Some(routes) = document.get(collection).and_then(Value::as_array) {
            for route in routes {
                if let Some(evidence) = route.get("evidence") {
                    for name in ["inputsSchema", "factsSchema"] {
                        if let Some(reference) = evidence.get(name) {
                            add_pack_reference(reference, references, findings, at.clone());
                        } else {
                            findings.push(invalid_pack_reference(at.clone()));
                        }
                    }
                }
                if let Some(steps) = route.get("steps") {
                    collect_step_schema_references(steps, references, findings, at);
                }
            }
        }
    }
}

fn collect_step_schema_references(
    steps: &Value,
    references: &mut BTreeMap<String, String>,
    findings: &mut Vec<Finding>,
    at: &FieldPath,
) {
    let Some(steps) = steps.as_array() else {
        findings.push(invalid_pack_reference(at.clone()));
        return;
    };
    for step in steps {
        if let Some(reference) = step.get("validateSchema") {
            add_pack_reference(reference, references, findings, at.clone());
        }
        // These are route control bodies. Literal request bodies, expressions
        // and constants are data and never acquire pin authority by key name.
        for kind in [
            "choice",
            "filter",
            "split",
            "loop",
            "circuitBreaker",
            "throttle",
            "idempotentConsumer",
            "doTry",
            "onException",
        ] {
            if let Some(body) = step.get(kind) {
                collect_control_schema_references(body, references, findings, at);
            }
        }
    }
}

fn collect_control_schema_references(
    body: &Value,
    references: &mut BTreeMap<String, String>,
    findings: &mut Vec<Finding>,
    at: &FieldPath,
) {
    if let Some(steps) = body.get("steps") {
        collect_step_schema_references(steps, references, findings, at);
    }
    for member in ["when", "otherwise", "doCatch", "doFinally", "onFallback"] {
        if let Some(clauses) = body.get(member) {
            if let Some(clauses) = clauses.as_array() {
                for clause in clauses {
                    collect_control_schema_references(clause, references, findings, at);
                }
            } else {
                collect_control_schema_references(clauses, references, findings, at);
            }
        }
    }
}

fn add_pack_reference(
    value: &Value,
    references: &mut BTreeMap<String, String>,
    findings: &mut Vec<Finding>,
    at: FieldPath,
) {
    let Some(reference) = pack_reference(value) else {
        findings.push(invalid_pack_reference(at));
        return;
    };
    if references
        .insert(reference.path.clone(), reference.digest.clone())
        .is_some_and(|existing| existing != reference.digest)
    {
        findings.push(invalid_pack_reference(at));
    }
}

fn pack_reference(value: &Value) -> Option<PackArtifactReference> {
    let object = value.as_object()?;
    (object.len() == 2).then_some(())?;
    Some(PackArtifactReference {
        path: object.get("path")?.as_str()?.to_owned(),
        digest: object.get("digest")?.as_str()?.to_owned(),
    })
}

fn invalid_pack_reference(at: FieldPath) -> Finding {
    Finding::new(
        at.key("pack"),
        "source-pack-artifact-reference",
        "pack artifact references must contain only a safe relative path and lowercase SHA-256 digest",
    )
}

fn valid_sha256_uri(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn sha256_uri(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    format!("sha256:{hex}")
}

fn inline_codelist_path(definition: &str, output: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(
        u64::try_from(definition.len())
            .expect("local identifier length fits u64")
            .to_be_bytes(),
    );
    digest.update(definition.as_bytes());
    digest.update(
        u64::try_from(output.len())
            .expect("local identifier length fits u64")
            .to_be_bytes(),
    );
    digest.update(output.as_bytes());
    let digest = digest.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    format!("codelists/inline/{hex}.yaml")
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
    let function_ids = BTreeSet::from([&definition.derive.function]);
    let mut behavior = serde_json::to_value(definition).ok()?;
    behavior.as_object_mut()?.remove("question");
    let mut functions = project
        .functions
        .iter()
        .filter(|function| function_ids.contains(&function.id))
        .collect::<Vec<_>>();
    // Declaration order does not change a Function dependency. Source imports
    // may recompose owned declarations around authored Functions, so compare
    // the consumed declarations in their stable identifier order.
    functions.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
    Some(behavior_value(
        json!({"definition":behavior,"sources":source_ids.into_iter().map(|id| (id.as_str(), &project.sources[id])).collect::<BTreeMap<_, _>>(),"selectors":definition.subjects.iter().flat_map(|subject| subject.selectors.iter()).map(|id| (id.as_str(), &project.selector_profiles[id])).collect::<BTreeMap<_, _>>(),"functions":functions}),
    ))
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
