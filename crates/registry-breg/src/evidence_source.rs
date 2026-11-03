// SPDX-License-Identifier: Apache-2.0
//! Offline export of one explicitly granted lookup as ordinary Evidence files.
//!
//! This renderer consumes the compiled registry. It neither grants access nor
//! discovers credentials, and Evidence requires no BReg runtime dependency.

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_canonical_json::canonicalize_json;
use serde::Serialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::{
    contract::{FieldTypeSource, LookupValueOrigin, Operation},
    diagnostics::Diagnostic,
    model::{CompiledEntity, CompiledLogicalField, CompiledRegistry},
    GeneratedArtifact,
};

/// The `apiVersion` of an export's `source-export.json`. `evidencectl source
/// import` reads the same value.
pub const EVIDENCE_SOURCE_EXPORT_API_VERSION: &str =
    "id.registrystack.org/formats/breg/evidence-source-export/v1alpha1";
pub const EVIDENCE_SOURCE_EXPORT_KIND: &str = "BRegEvidenceSourceExport";

/// The header of an exported `sources/<id>.yaml`. `evidencectl` reads the same
/// values under its source format.
const SOURCE_HEADER: [(&str, &str); 2] = [
    (
        "apiVersion",
        "id.registrystack.org/formats/evidence/source/v1alpha1",
    ),
    ("kind", "EvidenceSource"),
];

/// The header of an exported `selectors/<profile>.yaml`. `evidencectl` reads
/// the same values under its selector format.
const SELECTOR_HEADER: [(&str, &str); 2] = [
    (
        "apiVersion",
        "id.registrystack.org/formats/evidence/selector/v1alpha1",
    ),
    ("kind", "EvidenceSelector"),
];

/// `source-export.json`, written with its header first. Every member has a
/// fixed order, so the same inputs write the same bytes.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportManifest<'a> {
    api_version: &'static str,
    kind: &'static str,
    source_id: &'a str,
    provenance: BTreeMap<&'static str, &'a str>,
    artifacts: Vec<ExportManifestArtifact<'a>>,
}

#[derive(Serialize)]
struct ExportManifestArtifact<'a> {
    path: &'a str,
    digest: &'a str,
}

/// Technical choices only. Questions, permissions, targets and credentials stay with
/// the Evidence project and its operator.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EvidenceSourceAuthentication {
    #[default]
    StaticAuthorization,
    Oauth2PrivateKeyJwt,
}

impl EvidenceSourceAuthentication {
    fn as_str(self) -> &'static str {
        match self {
            Self::StaticAuthorization => "static-authorization",
            Self::Oauth2PrivateKeyJwt => "oauth2-private-key-jwt",
        }
    }
}

pub struct EvidenceSourceOptions {
    pub access_profile: String,
    pub entity: String,
    pub selectors: Vec<String>,
    pub fields: Vec<String>,
    pub source_id: String,
    pub connection: String,
    pub authentication: EvidenceSourceAuthentication,
}

pub struct EvidenceSourceExport {
    pub artifacts: Vec<GeneratedArtifact>,
    pub behavior_revision: String,
    pub selector_profiles: BTreeMap<String, String>,
    /// Additional readable fields needed to verify each selected identity.
    pub identity_fields: BTreeMap<String, Vec<String>>,
}

fn refusal(path: &str, message: &str) -> Diagnostic {
    Diagnostic::error("breg.evidence-source.refused", path, message)
}

fn local_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    matches!(bytes.first(), Some(b'a'..=b'z'))
        && bytes.len() <= 64
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn canonical(value: &Value) -> Result<Vec<u8>, Diagnostic> {
    canonicalize_json(value)
        .map_err(|_| refusal("export", "could not encode the selected technical contract"))
}

fn artifact(path: String, media_type: &str, bytes: Vec<u8>) -> GeneratedArtifact {
    GeneratedArtifact {
        path,
        media_type: media_type.to_owned(),
        sha256: format!("sha256:{}", digest(&bytes)),
        bytes,
    }
}

fn file_bytes<'a>(artifacts: &'a [GeneratedArtifact], path: &str) -> &'a [u8] {
    &artifacts
        .iter()
        .find(|artifact| artifact.path == path)
        .expect("the generated pack artifact was inserted before it was pinned")
        .bytes
}

/// A source or selector document: the flat body under its envelope header.
fn enveloped_document(
    path: String,
    header: [(&str, &str); 2],
    body: &Value,
) -> Result<GeneratedArtifact, Diagnostic> {
    let mut value = body.clone();
    let members = value
        .as_object_mut()
        .expect("an exported source or selector body is an object");
    for (name, text) in header {
        members.insert(name.to_owned(), Value::String(text.to_owned()));
    }
    document(path, &value)
}

fn document(path: String, value: &Value) -> Result<GeneratedArtifact, Diagnostic> {
    // JSON is a YAML mapping. Sort every object for repeatability while retaining
    // exact int64 schema bounds, which deliberately exceed JCS's binary64 range.
    let mut value = value.clone();
    value.sort_all_objects();
    let bytes = serde_json::to_vec_pretty(&value)
        .map_err(|_| refusal("export", "could not encode the selected source artifact"))?;
    Ok(artifact(path, "application/yaml", bytes))
}

fn field<'a>(entity: &'a CompiledEntity, id: &str) -> Result<&'a CompiledLogicalField, Diagnostic> {
    entity
        .stored_fields
        .iter()
        .find(|field| field.logical.id == id)
        .map(|field| &field.logical)
        .or_else(|| entity.derived_fields.get(id).map(|field| &field.logical))
        .ok_or_else(|| {
            refusal(
                "fields",
                "select declared stored or derived fields; record metadata is not a fact",
            )
        })
}

fn scalar_schema(kind: &FieldTypeSource) -> Result<Value, Diagnostic> {
    match kind {
        FieldTypeSource::String { max_length, .. } | FieldTypeSource::Text { max_length }
            if *max_length == 0 || *max_length > 65_536 =>
        {
            return Err(refusal(
                "fields",
                "the scalar string bound exceeds Evidence's schema ceiling of 65536 characters; use a smaller fact or a custom adapter",
            ));
        }
        FieldTypeSource::VocabularyCode { values, .. }
            if values.len() > 256 || values.iter().any(|value| value.chars().count() > 65_536) =>
        {
            return Err(refusal(
                "fields",
                "the vocabulary exceeds Evidence's bounded schema subset; use a reviewed custom adapter",
            ));
        }
        _ => {}
    }
    Ok(match kind {
        FieldTypeSource::Boolean => json!({"type":"boolean"}),
        FieldTypeSource::String {
            min_length,
            max_length,
        } => json!({"type":"string","minLength":min_length,"maxLength":max_length}),
        FieldTypeSource::Text { max_length } => json!({"type":"string","maxLength":max_length}),
        FieldTypeSource::Int64 => json!({"type":"integer","minimum":i64::MIN,"maximum":i64::MAX}),
        FieldTypeSource::Decimal {
            precision, scale, ..
        } => {
            json!({"type":"string","minLength":1,"maxLength":u32::from(*precision) + u32::from(*scale > 0) + 2})
        }
        FieldTypeSource::Date => {
            json!({"type":"string","format":"date","minLength":10,"maxLength":10})
        }
        FieldTypeSource::Timestamp => json!({"type":"string","format":"date-time","maxLength":64}),
        FieldTypeSource::Uuid | FieldTypeSource::Reference { .. } => {
            json!({"type":"string","format":"uuid","minLength":36,"maxLength":36})
        }
        FieldTypeSource::VocabularyCode { values, .. } if !values.is_empty() => {
            json!({"type":"string","enum":values,"maxLength":values.iter().map(|value|value.chars().count()).max().unwrap_or(1)})
        }
        _ => {
            return Err(refusal(
                "fields",
                "this field type needs a reviewed custom Evidence adapter; the exporter supports bounded scalar facts",
            ));
        }
    })
}

fn selector_schema(kind: &FieldTypeSource) -> Result<(Value, u64), Diagnostic> {
    let string = |maximum: u64| -> Result<(Value, u64), Diagnostic> {
        if maximum == 0 || maximum > 8192 {
            return Err(refusal(
                "selectors",
                "selector exceeds Evidence's 8192-byte bound; use a smaller bounded registry selector or a custom adapter",
            ));
        }
        Ok((
            json!({"type":"string","minimumBytes":1,"maximumBytes":maximum}),
            maximum,
        ))
    };
    match kind {
        FieldTypeSource::String { min_length: 0, .. } => Err(refusal(
            "selectors",
            "the selector field accepts an empty value that Evidence's selector profile cannot express; declare minimumLength of at least 1 on the field or use a custom adapter",
        )),
        FieldTypeSource::String { max_length, .. } => string(u64::from(*max_length) * 4),
        FieldTypeSource::Date => Ok((json!({"type":"date"}), 10)),
        FieldTypeSource::Boolean => Ok((json!({"type":"boolean"}), 5)),
        FieldTypeSource::Uuid | FieldTypeSource::Reference { .. } => Ok((json!({"type":"uuid"}), 36)),
        FieldTypeSource::VocabularyCode { .. } => Err(refusal(
            "selectors",
            "a vocabulary selector requires a reviewed Evidence codelist artifact; use a custom adapter with a controlled-code selector",
        )),
        FieldTypeSource::Int64 => Err(refusal(
            "selectors",
            "BReg int64 spans values outside Evidence's exact safe-integer selector range; use a bounded string selector or a reviewed custom adapter",
        )),
        _ => Err(refusal(
            "selectors",
            "selector cannot be represented losslessly by an Evidence selector profile; use a supported exact scalar selector or a custom adapter",
        )),
    }
}

/// Whether a compiled field type fits the canonical Evidence fact schema.
/// Authoring tools use this to offer choices before exporting an exact source.
pub fn supports_scalar_fact(kind: &FieldTypeSource) -> bool {
    scalar_schema(kind).is_ok()
}

/// Whether a compiled field type fits the canonical Evidence selector schema.
/// Exact source export still validates identity permissions, names and total bounds.
pub fn supports_selector_field(kind: &FieldTypeSource) -> bool {
    selector_schema(kind).is_ok()
}

fn object(properties: Map<String, Value>, required: Vec<String>) -> Value {
    json!({"type":"object","additionalProperties":false,"required":required,"properties":properties})
}

fn route_input_name(selector: &str, field: &str) -> String {
    let framed = format!("{}:{selector}{}:{field}", selector.len(), field.len());
    format!("input-{}", digest(framed.as_bytes()))
}

fn route_input_schema(selector: &Value) -> Value {
    let mut schema = selector.clone();
    let object = schema
        .as_object_mut()
        .expect("selector schemas are objects");
    if let Some(value) = object.remove("minimumBytes") {
        object.insert("minLength".to_owned(), value);
    }
    if let Some(value) = object.remove("maximumBytes") {
        object.insert("maxLength".to_owned(), value);
    }
    if object.get("type") == Some(&json!("uuid")) {
        object.insert("type".to_owned(), json!("string"));
        object.insert("format".to_owned(), json!("uuid"));
    }
    schema
}

/// Export multiple alternatives in one source. Each invocation replaces no
/// files; the caller publishes this inventory to a new output directory.
pub fn export_evidence_source(
    registry: &CompiledRegistry,
    options: &EvidenceSourceOptions,
) -> Result<EvidenceSourceExport, Diagnostic> {
    for (path, name) in [
        ("source-id", &options.source_id),
        ("connection", &options.connection),
    ] {
        if !local_name(name) {
            return Err(refusal(
                path,
                "use a lowercase local identifier of at most 64 bytes",
            ));
        }
    }
    let entity = registry
        .entities()
        .get(&options.entity)
        .ok_or_else(|| refusal("entity", "select an entity in the compiled registry"))?;
    let access = entity
        .access_profiles
        .get(&options.access_profile)
        .ok_or_else(|| {
            refusal(
                "access-profile",
                "select an existing access profile for this entity",
            )
        })?;
    if !access.operations.contains(&Operation::Lookup) {
        return Err(refusal(
            "access-profile",
            "the selected profile does not grant lookup; declare and review that authority in BReg first",
        ));
    }
    // An Evidence runtime is one client answering for many relying parties,
    // so a subject's consent to one recipient cannot follow its assertions.
    if entity
        .consent_requirements
        .contains_key(&options.access_profile)
    {
        return Err(Diagnostic::error(
            "breg.consent.require-evidence-source-unsupported",
            "access-profile",
            "a consent-checked profile cannot back an Evidence source; the Evidence runtime is not the recipient the subject consented to",
        ));
    }
    let route = registry
        .routes()
        .routes
        .iter()
        .find(|route| {
            route.entity_id == entity.id
                && route.operation == Operation::Lookup
                && route.access_profiles.contains(&options.access_profile)
        })
        .ok_or_else(|| refusal("access-profile", "the compiled profile has no lookup route"))?;
    let fields = options.fields.iter().cloned().collect::<BTreeSet<_>>();
    let selectors = options.selectors.iter().cloned().collect::<BTreeSet<_>>();
    if fields.is_empty() || fields.len() > 16 || fields.len() != options.fields.len() {
        return Err(refusal("fields", "select 1 to 16 distinct fact fields"));
    }
    if selectors.is_empty() || selectors.len() > 16 || selectors.len() != options.selectors.len() {
        return Err(refusal(
            "selectors",
            "select 1 to 16 distinct existing selector profiles",
        ));
    }
    let mut artifacts = Vec::new();
    let mut fact_properties = Map::new();
    for id in &fields {
        if !local_name(id) || !access.readable_fields.contains(id) {
            return Err(refusal(
                "fields",
                "every exported fact must already be readable under the selected profile and have an Evidence-compatible field name",
            ));
        }
        fact_properties.insert(id.clone(), scalar_schema(&field(entity, id)?.field_type)?);
    }
    let mut all_fields = fields.clone();
    let mut selector_profiles = BTreeMap::new();
    let mut identity_fields = BTreeMap::new();
    let mut route_input_properties = Map::new();
    let mut route_input_alternatives = Vec::new();
    let mut source_inputs = Map::new();
    let mut select_fields = String::from(
        "// Generated from the compiled registry. Review before changing.\nfn select_fields(exchange) {\n    let inputs = exchange.body;\n",
    );
    let mut prepare =
        String::from("fn prepare_request(exchange) {\n    let inputs = exchange.body;\n");
    let mut extract = String::from(
        "// Identity is checked once, before facts can feed any question.\nfn lookup(exchange) {\n    let inputs = exchange.properties[\"bregEvidenceInputs\"];\n    let record = exchange.body[\"data\"][\"domainData\"];\n",
    );
    let mut profile_dependencies = Vec::new();
    for selector_id in selectors {
        let selector = entity
            .selector_profiles
            .get(&selector_id)
            .ok_or_else(|| refusal("selectors", "select an existing compiled selector profile"))?;
        let grant = access
            .lookups
            .iter()
            .find(|grant| grant.selector == selector_id)
            .ok_or_else(|| {
                refusal(
                    "selectors",
                    "this lookup selector is not granted to the selected access profile",
                )
            })?;
        if grant.value_origin != LookupValueOrigin::Request {
            return Err(refusal(
                "selectors",
                "verified-claim lookup values describe the source workload identity, not the Evidence caller; export a request-origin lookup",
            ));
        }
        if !selector
            .fields
            .iter()
            .all(|id| access.readable_fields.contains(id))
        {
            return Err(refusal(
                "selectors",
                "exact identity verification requires the selector fields to be readable under the existing profile; review its explicit read grant first",
            ));
        }
        let profile = format!(
            "breg-{}-{}-{}-{}-{}-{}",
            options.connection.len(),
            options.connection,
            entity.id.len(),
            entity.id,
            selector_id.len(),
            selector_id
        );
        if !profile.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        }) {
            return Err(refusal(
                "selectors",
                "selector profile names require lowercase technical identifiers",
            ));
        }
        // The existing length-framed spelling is an unambiguous digest input.
        // Keep short published names stable and bound only oversized names.
        let profile = if profile.len() > 64 {
            format!("breg-{}", &digest(profile.as_bytes())[..59])
        } else {
            profile
        };
        let mut selector_fields = Map::new();
        let mut maximum = 0_u64;
        let mut body_fields = Vec::new();
        let mut required_inputs = Vec::new();
        let mut selected = fields.clone();
        let mut checks = String::new();
        for id in &selector.fields {
            if !local_name(id) {
                return Err(refusal(
                    "selectors",
                    "selector field names must be Evidence-compatible lowercase local identifiers",
                ));
            }
            let logical = field(entity, id)?;
            let (schema, bound) = selector_schema(&logical.field_type)?;
            maximum += bound;
            selector_fields.insert(id.clone(), schema.clone());
            let input = route_input_name(&selector_id, id);
            if route_input_properties
                .insert(input.clone(), route_input_schema(&schema))
                .is_some()
            {
                return Err(refusal(
                    "selectors",
                    "selector inputs did not produce distinct bounded route names",
                ));
            }
            required_inputs.push(input.clone());
            source_inputs.insert(
                input.clone(),
                json!({"selector":{"role":"subject","profile":profile,"field":id}}),
            );
            body_fields.push(format!(
                "{}: inputs[{}]",
                json!(logical.api_name),
                json!(input)
            ));
            selected.insert(id.clone());
            all_fields.insert(id.clone());
            checks.push_str(&format!("        if record[{api}] == () || type_of(record[{api}]) != type_of(inputs[{input}]) || record[{api}] != inputs[{input}] {{ throw \"source_protocol_error\"; }}\n",api=json!(logical.api_name),input=json!(input)));
        }
        if maximum > 8192 {
            return Err(refusal(
                "selectors",
                "the complete composite selector exceeds Evidence's 8192-byte bound",
            ));
        }
        let projection = selected
            .iter()
            .map(|id| field(entity, id).map(|field| field.api_name.clone()))
            .collect::<Result<Vec<_>, _>>()?
            .join(",");
        let condition = required_inputs
            .iter()
            .map(|input| format!("inputs.contains({})", json!(input)))
            .collect::<Vec<_>>()
            .join(" && ");
        select_fields.push_str(&format!(
            "    if {condition} {{ return {projection}; }}\n",
            projection = json!(projection)
        ));
        prepare.push_str(&format!(
            "    if {condition} {{ return #{{selector: {selector}, values: #{{{values}}}}}; }}\n",
            selector = json!(selector_id),
            values = body_fields.join(", ")
        ));
        extract.push_str(&format!(
            "    {}if {condition} {{\n{}    }}",
            if selector_profiles.is_empty() {
                ""
            } else {
                "else "
            },
            checks
        ));
        route_input_alternatives.push(json!({"required":required_inputs}));
        artifacts.push(enveloped_document(
            format!("selectors/{profile}.yaml"),
            SELECTOR_HEADER,
            &json!({"maximumAggregateBytes":maximum,"fields":selector_fields}),
        )?);
        identity_fields.insert(
            selector_id.clone(),
            selected.difference(&fields).cloned().collect(),
        );
        profile_dependencies.push(json!({"selector":selector,"grant":grant}));
        selector_profiles.insert(selector_id, profile);
    }
    select_fields.push_str("    throw \"unsupported source selector profile\";\n}\n");
    prepare.push_str("    throw \"unsupported source selector profile\";\n}\n");
    if all_fields.len() > 64 {
        return Err(refusal(
            "selectors",
            "the union of selected identity and fact fields exceeds Evidence's 64 projected properties; split the alternatives into separate sources",
        ));
    }
    let mut project_response = String::from(
        "fn project_response(exchange) {\n    let record = exchange.body[\"data\"][\"domainData\"];\n    let projected = #{};\n",
    );
    for id in &all_fields {
        let api_name = json!(field(entity, id)?.api_name);
        project_response.push_str(&format!(
            "    if record.contains({api_name}) {{ projected[{api_name}] = record[{api_name}]; }}\n"
        ));
    }
    project_response.push_str("    #{data: #{domainData: projected}}\n}\n");
    extract.push_str(" else { throw \"unsupported source selector profile\"; }\n");
    for id in &fields {
        extract.push_str(&format!(
            "    if record[{}] == () {{ return #{{lookup: \"no-match\"}}; }}\n",
            json!(field(entity, id)?.api_name)
        ));
    }
    let facts = fields
        .iter()
        .map(|id| {
            field(entity, id)
                .map(|logical| format!("{}: record[{}]", json!(id), json!(logical.api_name)))
        })
        .collect::<Result<Vec<_>, _>>()?;
    extract.push_str(&format!(
        "    #{{lookup: \"matched\", facts: #{{{}}}}}\n}}\n",
        facts.join(", ")
    ));
    extract.push_str(
        "fn is_unresolved(exchange) {\n    exchange.headers[\"camelhttpresponsecode\"] == 404\n}\n",
    );
    let script = format!("{select_fields}\n{prepare}\n{project_response}\n{extract}");
    let mut response_fields = Map::new();
    let mut dependencies = Map::new();
    for id in &all_fields {
        let logical = field(entity, id)?;
        let mut schema = scalar_schema(&logical.field_type)?;
        schema["type"] = json!([schema["type"], "null"]);
        // A null vocabulary value is absent data, not a protocol mismatch.
        // The fixed fact schema still enforces the vocabulary after extraction.
        schema
            .as_object_mut()
            .expect("scalar schema object")
            .remove("enum");
        response_fields.insert(logical.api_name.clone(), schema);
        dependencies.insert(
            id.clone(),
            serde_json::to_value(logical)
                .map_err(|_| refusal("fields", "could not encode field contract"))?,
        );
    }
    let behavior = selected_behavior(
        registry,
        entity,
        options,
        &all_fields,
        profile_dependencies,
        dependencies,
    )?;
    let behavior_revision = format!("sha256:{}", digest(&canonical(&behavior)?));
    let prefix = &options.source_id;
    let response = object(
        Map::from_iter([(
            "data".into(),
            object(
                Map::from_iter([("domainData".into(), object(response_fields, vec![]))]),
                vec!["domainData".into()],
            ),
        )]),
        vec!["data".into()],
    );
    let pack_root = format!("adapter-packs/{prefix}");
    let inputs_path = "schemas/inputs.json";
    let facts_path = "schemas/facts.json";
    let response_path = "schemas/response.json";
    let script_path = "scripts/lookup.rhai";
    let protocol_path = "protocols/registry-lookup.json";
    let inputs = json!({
        "type":"object",
        "additionalProperties":false,
        "properties":route_input_properties,
        "oneOf":route_input_alternatives
    });
    let facts_schema = object(fact_properties, fields.into_iter().collect());
    let inputs_bytes = serde_json::to_vec_pretty(&inputs)
        .map_err(|_| refusal("export", "could not encode the route input schema"))?;
    let facts_bytes = serde_json::to_vec_pretty(&facts_schema)
        .map_err(|_| refusal("export", "could not encode the route fact schema"))?;
    let response_bytes = serde_json::to_vec_pretty(&response)
        .map_err(|_| refusal("export", "could not encode the provider response schema"))?;
    let script_bytes = script.into_bytes();
    let protocol_bytes = serde_json::to_vec(&json!({
        "unresolvedProblem":{
            "status":404,
            "type":crate::problem::ProblemCode::LookupUnresolved.type_uri(),
            "code":"lookup.unresolved"
        },
        "forwardAccessAttribution":entity.access_log.is_some()
    }))
    .map_err(|_| refusal("export", "could not encode the registry lookup protocol"))?;
    for (path, media_type, bytes) in [
        (inputs_path, "application/schema+json", inputs_bytes),
        (facts_path, "application/schema+json", facts_bytes),
        (response_path, "application/schema+json", response_bytes),
        (script_path, "text/plain", script_bytes),
    ] {
        artifacts.push(artifact(format!("{pack_root}/{path}"), media_type, bytes));
    }
    artifacts.push(artifact(
        format!("{pack_root}/{protocol_path}"),
        "application/json",
        protocol_bytes.clone(),
    ));
    let pin =
        |path: &str, bytes: &[u8]| json!({"path":path,"digest":format!("sha256:{}",digest(bytes))});
    let script_reference = pin(
        script_path,
        file_bytes(&artifacts, &format!("{pack_root}/{script_path}")),
    );
    let response_reference = pin(
        response_path,
        file_bytes(&artifacts, &format!("{pack_root}/{response_path}")),
    );
    let endpoint = json!({
        "id":"registry",
        "component":"http",
        "authentication":{"type":options.authentication.as_str()},
        "attemptTimeoutMilliseconds":5000,
        "maximumResponseBytes":65536,
        "requestHeaders":["accept"],
        "operations":[{"id":"lookup","safeUpstream":true}],
        "hostProtocol":{"id":"registry-lookup-v1","config":pin(protocol_path,&protocol_bytes)},
        "testedVersions":["breg-evidence-lookup-v2"]
    });
    let pack = json!({
        "apiVersion":"id.registrystack.org/formats/adapter/pack/v1alpha1",
        "kind":"AdapterPack",
        "id":prefix,
        "version":behavior_revision,
        "testedVersions":["breg-evidence-lookup-v2"],
        "endpoints":[endpoint],
        "sourceRoutes":[{
            "id":"lookup",
            "evidence":{
                "inputsSchema":pin(inputs_path,file_bytes(&artifacts,&format!("{pack_root}/{inputs_path}"))),
                "factsSchema":pin(facts_path,file_bytes(&artifacts,&format!("{pack_root}/{facts_path}"))),
                "acquisitionPosture":"field-projected"
            },
            "steps":[
                {"setProperty":{"name":"bregEvidenceInputs","value":{"jsonpath":"$"}}},
                {"setProperty":{"name":"bregSelect","value":{"rhai":{"file":script_path,"entrypoint":"select_fields"}}}},
                {"setBody":{"rhai":{"file":script_path,"entrypoint":"prepare_request"}}},
                {"setHeader":{"name":"Accept","value":{"constant":"application/json"}}},
                {"to":{"uri":"http:registry","parameters":{"httpMethod":"POST","path":route.path,"operation":"lookup","throwExceptionOnFailure":false,"query":{"accessProfile":{"constant":options.access_profile},"$select":{"exchangeProperty":"bregSelect"}},"body":{"jsonpath":"$"}}}},
                {"choice":{"when":[{"rhai":{"file":script_path,"entrypoint":"is_unresolved"},"steps":[{"stop":{}}]}]}},
                {"setBody":{"rhai":{"file":script_path,"entrypoint":"project_response"}}},
                {"validateSchema":response_reference},
                {"setBody":{"rhai":{"file":script_path,"entrypoint":"lookup"}}}
            ]
        }],
        "scripts":[script_reference],
        "capabilities":{"components":["http"],"languages":["constant","exchangeProperty","jsonpath","rhai"],"eips":["choice","setBody","setHeader","setProperty","stop","to"]}
    });
    artifacts.push(document(format!("{pack_root}/pack.yaml"), &pack)?);
    artifacts.push(enveloped_document(
        format!("sources/{prefix}.yaml"),
        SOURCE_HEADER,
        &json!({
            "pack":{"id":prefix,"version":behavior_revision},
            "route":"lookup",
            "connection":options.connection,
            "inputs":source_inputs,
            "acquisitionPosture":"field-projected"
        }),
    )?);
    artifacts.sort_by(|a, b| a.path.cmp(&b.path));
    let manifest = serde_json::to_vec(&ExportManifest {
        api_version: EVIDENCE_SOURCE_EXPORT_API_VERSION,
        kind: EVIDENCE_SOURCE_EXPORT_KIND,
        source_id: prefix,
        provenance: BTreeMap::from([
            ("producer", "bregctl"),
            ("registryId", registry.registry_id()),
            ("registryRevision", registry.revision()),
            ("entity", entity.id.as_str()),
            ("accessProfile", options.access_profile.as_str()),
            ("behaviorRevision", behavior_revision.as_str()),
        ]),
        artifacts: artifacts
            .iter()
            .map(|artifact| ExportManifestArtifact {
                path: &artifact.path,
                digest: &artifact.sha256,
            })
            .collect(),
    })
    .map_err(|_| refusal("export", "could not encode the export manifest"))?;
    artifacts.push(artifact(
        "source-export.json".into(),
        "application/json",
        manifest,
    ));
    Ok(EvidenceSourceExport {
        artifacts,
        behavior_revision,
        selector_profiles,
        identity_fields,
    })
}

fn selected_behavior(
    registry: &CompiledRegistry,
    entity: &CompiledEntity,
    options: &EvidenceSourceOptions,
    fields: &BTreeSet<String>,
    selectors: Vec<Value>,
    logical_fields: Map<String, Value>,
) -> Result<Value, Diagnostic> {
    let access = &entity.access_profiles[&options.access_profile];
    let reached = fields
        .iter()
        .filter_map(|id| {
            entity
                .derived_fields
                .get(id)
                .map(|field| field.derivation_id.clone())
        })
        .collect::<BTreeSet<_>>();
    let mut derived = BTreeMap::new();
    let mut sources = BTreeMap::new();
    for id in reached {
        let relation = &entity.derived_relations[&id];
        // SQL assets are indivisible reviewed implementations. Inspect the
        // compiled AST only to find source relations, never guess SQL behavior.
        let sql = std::str::from_utf8(&relation.sql_bytes)
            .map_err(|_| refusal("derived", "compiled SQL is not UTF-8"))?;
        let parsed = pg_query::parse(sql)
            .map_err(|_| refusal("derived", "compiled SQL could not be read"))?;
        for (node, _, _, _) in parsed.protobuf.nodes() {
            if let pg_query::NodeRef::RangeVar(range) = node {
                if range.schemaname != "registry_source" {
                    continue;
                }
                let source = registry
                    .entities()
                    .values()
                    .find(|entity| entity.source_relation.sql_name == range.relname)
                    .ok_or_else(|| refusal("derived", "compiled SQL source relation is absent"))?;
                let source_access = source.access_profiles.get(&options.access_profile);
                let mut behavior = json!({"relation":source.source_relation,"canonicalId":source.canonical_id,"fields":source.stored_fields,"tombstone":source.tombstone,"accessRequirements":source.access_requirements,"rowBoundaries":source_access.map(|access|&access.row_boundaries),"selectPolicies":select_policies(registry,source,&options.access_profile)});
                let membership = membership_behavior(registry, source, &options.access_profile)?;
                if !membership.is_empty() {
                    behavior["membershipBoundaries"] = json!(membership);
                }
                sources.insert(source.id.clone(), behavior);
            }
        }
        derived.insert(id,json!({"sha256":relation.sql_sha256,"key":relation.key_field,"execution":relation.execution,"fields":relation.fields.iter().map(|id|&entity.derived_fields[id]).collect::<Vec<_>>() }));
    }
    let boundary_fields = access
        .row_boundaries
        .iter()
        .map(|boundary| &boundary.field)
        .map(|id| field(entity, id).map(|field| json!(field)))
        .collect::<Result<Vec<_>, _>>()?;
    let mut behavior = json!({"protocol":"breg-evidence-lookup-v2","readSemantics":"collection-dependencies-v1/evaluation-date-transaction-v1/access-attribution-v1","missingFactOutcome":"no-match","authentication":options.authentication.as_str(),"entity":entity.id,"route":entity.route,"canonicalId":entity.canonical_id,"tombstone":entity.tombstone,"fields":logical_fields,"selectors":selectors,"access":{"profile":access.id,"principalClaim":access.principal_claim,"requiredScopes":access.required_scopes,"requiredPurposes":access.required_purposes,"rowBoundaries":access.row_boundaries,"boundaryFields":boundary_fields,"requirements":entity.access_requirements,"accessLog":entity.access_log,"selectPolicies":select_policies(registry,entity,&options.access_profile)},"derived":derived,"sources":sources});
    let membership = membership_behavior(registry, entity, &options.access_profile)?;
    if !membership.is_empty() {
        behavior["access"]["membershipBoundaries"] = json!(membership);
    }
    Ok(behavior)
}

fn membership_behavior(
    registry: &CompiledRegistry,
    entity: &CompiledEntity,
    profile: &str,
) -> Result<Vec<Value>, Diagnostic> {
    crate::membership::boundaries(entity, profile)
        .iter()
        .enumerate()
        .map(|(index, boundary)| {
            let root_field = entity
                .fields
                .get(&boundary.field)
                .ok_or_else(|| refusal("access", "compiled membership root field is absent"))?;
            let source = registry
                .entities()
                .get(&boundary.membership_entity)
                .ok_or_else(|| refusal("access", "compiled membership source is absent"))?;
            let function_id = format!(
                "registry_context.{}",
                crate::membership::function_name(&entity.id, profile, index)
            );
            let function = registry
                .ddl()
                .statements
                .iter()
                .find(|statement| statement.id == function_id)
                .ok_or_else(|| refusal("access", "compiled membership function is absent"))?;
            let source_fields = [
                &boundary.membership_key_column,
                &boundary.principal_column,
                &boundary.active_column,
            ]
            .into_iter()
            .map(|column| {
                source
                    .fields
                    .values()
                    .find(|field| &field.physical_name == column)
                    .ok_or_else(|| refusal("access", "compiled membership source field is absent"))
            })
            .collect::<Result<Vec<_>, _>>()?;
            // Names stay stable across membership changes. Consume the actual
            // helper and the leaf source's effective SELECT rules and fields.
            // These dependencies affect identity only; none are exported facts.
            Ok(json!({
                "boundary": boundary,
                "field": root_field,
                "function": function,
                "source": {
                    "table": source.physical_table,
                    "canonicalId": source.canonical_id,
                    "fields": source_fields,
                    "tombstone": source.tombstone,
                    "accessRequirements": source.access_requirements,
                    "selectPolicies": select_policies(registry, source, profile),
                }
            }))
        })
        .collect()
}

fn select_policies<'a>(
    registry: &'a CompiledRegistry,
    entity: &CompiledEntity,
    profile: &str,
) -> Vec<&'a crate::generated_ddl::DdlPolicy> {
    // Fingerprint the compiler's effective SELECT rules, including their
    // absence and lifecycle guards. Do not reimplement operation-to-RLS rules.
    registry
        .ddl()
        .tables
        .iter()
        .filter(|table| table.entity_id == entity.id)
        .flat_map(|table| table.policies.iter())
        .filter(|policy| {
            policy.access_profile == profile
                && policy.command == crate::generated_ddl::PolicyCommand::Select
        })
        .collect()
}

#[cfg(test)]
mod tests;
