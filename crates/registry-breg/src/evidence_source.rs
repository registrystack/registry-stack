// SPDX-License-Identifier: Apache-2.0
//! Offline export of one explicitly granted lookup as ordinary Evidence files.
//!
//! This renderer consumes the compiled registry. It neither grants access nor
//! discovers credentials, and Evidence requires no BReg runtime dependency.

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_canonical_json::canonicalize_json;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::{
    contract::{FieldTypeSource, LookupValueOrigin, Operation},
    diagnostics::Diagnostic,
    model::{CompiledEntity, CompiledLogicalField, CompiledRegistry},
    GeneratedArtifact,
};

/// Technical choices only. Questions, grants, targets and credentials stay with
/// the Evidence project and its operator.
pub struct EvidenceSourceOptions {
    pub access_profile: String,
    pub entity: String,
    pub selectors: Vec<String>,
    pub fields: Vec<String>,
    pub source_id: String,
    pub connection: String,
}

pub struct EvidenceSourceExport {
    pub artifacts: Vec<GeneratedArtifact>,
    pub behavior_revision: String,
    pub selector_profiles: BTreeMap<String, String>,
    /// Additional readable fields needed to verify each selected identity.
    pub identity_fields: BTreeMap<String, Vec<String>>,
}

fn refusal(path: &str, message: &str) -> Diagnostic {
    Diagnostic::error("evidence_source.refused", path, message)
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
        FieldTypeSource::String {max_length,..} | FieldTypeSource::Text {max_length}
            if *max_length == 0 || *max_length > 65_536 => return Err(refusal("fields","the scalar string bound exceeds Evidence's schema ceiling of 65536 characters; use a smaller fact or a custom adapter")),
        FieldTypeSource::VocabularyCode {values,..}
            if values.len() > 256 || values.iter().any(|value| value.chars().count() > 65_536) => return Err(refusal("fields","the vocabulary exceeds Evidence's bounded schema subset; use a reviewed custom adapter")),
        _ => {},
    }
    Ok(match kind {
        FieldTypeSource::Boolean => json!({"type":"boolean"}),
        FieldTypeSource::String { min_length, max_length } => json!({"type":"string","minLength":min_length,"maxLength":max_length}),
        FieldTypeSource::Text { max_length } => json!({"type":"string","maxLength":max_length}),
        FieldTypeSource::Int64 => json!({"type":"integer","minimum":i64::MIN,"maximum":i64::MAX}),
        FieldTypeSource::Decimal { precision, scale, .. } => json!({"type":"string","minLength":1,"maxLength":u32::from(*precision) + u32::from(*scale > 0) + 2}),
        FieldTypeSource::Date => json!({"type":"string","format":"date","minLength":10,"maxLength":10}),
        FieldTypeSource::Timestamp => json!({"type":"string","format":"date-time","maxLength":64}),
        FieldTypeSource::Uuid | FieldTypeSource::Reference { .. } => json!({"type":"string","minLength":36,"maxLength":36}),
        FieldTypeSource::VocabularyCode { values, .. } if !values.is_empty() => json!({"type":"string","enum":values,"maxLength":values.iter().map(|value|value.chars().count()).max().unwrap_or(1)}),
        _ => return Err(refusal("fields", "this field type needs a reviewed custom Evidence adapter; the exporter supports bounded scalar facts")),
    })
}

fn selector_schema(kind: &FieldTypeSource) -> Result<(Value, u64), Diagnostic> {
    let string = |maximum: u64| -> Result<(Value, u64), Diagnostic> {
        if maximum == 0 || maximum > 8192 {
            return Err(refusal("selectors", "selector exceeds Evidence's 8192-byte bound; use a smaller bounded registry selector or a custom adapter"));
        }
        Ok((
            json!({"type":"string","minimumBytes":1,"maximumBytes":maximum}),
            maximum,
        ))
    };
    match kind {
        FieldTypeSource::String { min_length: 0, .. } => Err(refusal("selectors", "the selector field accepts an empty value that Evidence's selector profile cannot express; declare minLength of at least 1 on the field or use a custom adapter")),
        FieldTypeSource::String { max_length, .. } => string(u64::from(*max_length) * 4),
        FieldTypeSource::Date => Ok((json!({"type":"date"}),10)),
        FieldTypeSource::Boolean => Ok((json!({"type":"boolean"}),5)),
        FieldTypeSource::Uuid | FieldTypeSource::Reference { .. } => string(36),
        FieldTypeSource::VocabularyCode { values, .. } if !values.is_empty() => string(values.iter().map(|value|value.len() as u64).max().unwrap_or(1)),
        FieldTypeSource::Int64 => Err(refusal("selectors", "BReg int64 spans values outside Evidence's exact safe-integer selector range; use a bounded string selector or a reviewed custom adapter")),
        _ => Err(refusal("selectors", "selector cannot be represented losslessly by an Evidence selector profile; use a supported exact scalar selector or a custom adapter")),
    }
}

/// Whether a compiled field type fits the canonical Evidence fact schema.
/// Authoring tools use this to offer choices before exporting an exact source.
pub fn supports_scalar_fact(kind: &FieldTypeSource) -> bool {
    scalar_schema(kind).is_ok()
}

/// Whether a compiled field type fits the canonical Evidence selector schema.
/// Exact source export still validates identity grants, names and total bounds.
pub fn supports_selector_field(kind: &FieldTypeSource) -> bool {
    selector_schema(kind).is_ok()
}

fn object(properties: Map<String, Value>, required: Vec<String>) -> Value {
    json!({"type":"object","additionalProperties":false,"required":required,"properties":properties})
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
    if entity.change_request.is_some() {
        return Err(refusal(
            "entity",
            "change-request lifecycle records require a reviewed custom Evidence adapter",
        ));
    }
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
        return Err(refusal("access-profile","the selected profile does not grant lookup; declare and review that authority in BReg first"));
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
            return Err(refusal("fields","every exported fact must already be readable under the selected profile and have an Evidence-compatible field name"));
        }
        fact_properties.insert(id.clone(), scalar_schema(&field(entity, id)?.field_type)?);
    }
    let mut all_fields = fields.clone();
    let mut selector_profiles = BTreeMap::new();
    let mut identity_fields = BTreeMap::new();
    let mut alternatives = Vec::new();
    let mut prepare = String::from("// Generated from the compiled registry. Review before changing.\nfn prepare(selectors, context) {\n    let subject = selectors[\"subject\"];\n");
    let mut extract = String::from("// Identity is checked once, before facts can feed any question.\nfn extract(response, selectors, context) {\n    let subject = selectors[\"subject\"];\n    let record = response[\"data\"][\"domainData\"];\n");
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
            return Err(refusal("selectors","verified-claim lookup values describe the source workload identity, not the Evidence caller; export a request-origin lookup"));
        }
        if !selector
            .fields
            .iter()
            .all(|id| access.readable_fields.contains(id))
        {
            return Err(refusal("selectors","exact identity verification requires the selector fields to be readable under the existing profile; review its explicit read grant first"));
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
            selector_fields.insert(id.clone(), schema);
            body_fields.push(format!(
                "{}: subject[\"values\"][{}]",
                json!(logical.api_name),
                json!(id)
            ));
            selected.insert(id.clone());
            all_fields.insert(id.clone());
            checks.push_str(&format!("        if is_missing(record[{api}]) || type_of(record[{api}]) != type_of(subject[\"values\"][{id}]) || record[{api}] != subject[\"values\"][{id}] {{ throw \"source_protocol_error\"; }}\n",api=json!(logical.api_name),id=json!(id)));
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
        prepare.push_str(&format!("    if subject[\"profile\"] == {profile} {{\n        return #{{query: [#{{name: \"accessProfile\", value: {access}}}, #{{name: \"$select\", value: {projection}}}], body: #{{selector: {selector}, values: #{{{values}}}}}}};\n    }}\n",profile=json!(profile),access=json!(options.access_profile),projection=json!(projection),selector=json!(selector_id),values=body_fields.join(", ")));
        extract.push_str(&format!(
            "    {}if subject[\"profile\"] == {} {{\n{}    }}",
            if selector_profiles.is_empty() {
                ""
            } else {
                "else "
            },
            json!(profile),
            checks
        ));
        alternatives.push(json!({"profile":profile,"fields":selector.fields}));
        artifacts.push(document(
            format!("selectors/{profile}.yaml"),
            &json!({"maximumAggregateBytes":maximum,"fields":selector_fields}),
        )?);
        identity_fields.insert(
            selector_id.clone(),
            selected.difference(&fields).cloned().collect(),
        );
        profile_dependencies.push(json!({"selector":selector,"grant":grant}));
        selector_profiles.insert(selector_id, profile);
    }
    prepare.push_str("    throw \"unsupported source selector profile\";\n}\n");
    if all_fields.len() > 64 {
        return Err(refusal("selectors", "the union of selected identity and fact fields exceeds Evidence's 64 projected properties; split the alternatives into separate sources"));
    }
    extract.push_str(" else { throw \"unsupported source selector profile\"; }\n");
    for id in &fields {
        extract.push_str(&format!(
            "    if is_missing(record[{}]) {{ return #{{outcome: \"no_match\"}}; }}\n",
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
        "    #{{outcome: \"match\", facts: #{{{}}}}}\n}}\n",
        facts.join(", ")
    ));
    let mut response_fields = Map::new();
    let mut projection = Vec::new();
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
        projection.push(format!("/data/domainData/{}", logical.api_name));
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
    artifacts.push(document(
        format!("schemas/{prefix}-response.yaml"),
        &response,
    )?);
    artifacts.push(document(
        format!("schemas/{prefix}-facts.yaml"),
        &object(fact_properties, fields.into_iter().collect()),
    )?);
    artifacts.push(document(
        format!("schemas/{prefix}-parameters.yaml"),
        &object(Map::new(), vec![]),
    )?);
    artifacts.push(artifact(
        format!("adapters/{prefix}-prepare.rhai"),
        "text/plain",
        prepare.into_bytes(),
    ));
    artifacts.push(artifact(
        format!("adapters/{prefix}-extract.rhai"),
        "text/plain",
        extract.into_bytes(),
    ));
    artifacts.push(document(format!("sources/{prefix}.yaml"),&json!({
        "transport":"http-json","connection":options.connection,"behaviorRevision":behavior_revision,"posture":"field-projected",
        "unresolvedProblem":{"status":404,"type":crate::problem::ProblemCode::LookupUnresolved.type_uri(),"code":"lookup.unresolved"},
        "request":{"method":"POST","path":route.path,"fixedHeaders":[{"name":"Accept","value":"application/json"}],
            "selectorInputs":[{"role":"subject","alternatives":alternatives}],"prepareScript":format!("adapters/{prefix}-prepare.rhai"),
            "adapterParameters":{},"adapterParametersSchema":format!("schemas/{prefix}-parameters.yaml"),
            "preparationLimits":{"query":"required","jsonBody":"required","maximumJsonDepth":8,"maximumCollectionItems":128,"maximumStringBytes":8192,"maximumNormalizedBytes":16384},
            "projection":projection,"redirects":"deny","timeoutMilliseconds":5000,"maximumResponseBytes":65536},
        "responseSchema":format!("schemas/{prefix}-response.yaml"),"extractScript":format!("adapters/{prefix}-extract.rhai"),"factSchema":format!("schemas/{prefix}-facts.yaml")
    }))?);
    artifacts.sort_by(|a, b| a.path.cmp(&b.path));
    let manifest = json!({"formatVersion":1,"sourceId":prefix,"provenance":{"producer":"bregctl","registryId":registry.registry_id(),"packageRevision":registry.revision(),"entity":entity.id,"accessProfile":options.access_profile,"behaviorRevision":behavior_revision},"artifacts":artifacts.iter().map(|artifact|json!({"path":artifact.path,"sha256":digest(&artifact.bytes)})).collect::<Vec<_>>()});
    artifacts.push(artifact(
        "source-export.json".into(),
        "application/json",
        canonical(&manifest)?,
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
                let mut behavior = json!({"relation":source.source_relation,"canonicalId":source.canonical_id,"fields":source.stored_fields,"tombstone":source.tombstone,"accessRequirements":source.access_requirements,"rowBoundaries":source_access.map(|access|&access.row_boundaries),"requestVisibility":source_access.and_then(|access|access.request_visibility.as_ref()),"selectPolicies":select_policies(registry,source,&options.access_profile)});
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
    let mut behavior = json!({"protocol":"breg-evidence-lookup-v1","readSemantics":"collection-dependencies-v1/evaluation-date-transaction-v1","entity":entity.id,"route":entity.route,"canonicalId":entity.canonical_id,"tombstone":entity.tombstone,"fields":logical_fields,"selectors":selectors,"access":{"profile":access.id,"anonymous":access.anonymous,"principalClaim":access.principal_claim,"requiredScopes":access.required_scopes,"requiredPurposes":access.required_purposes,"rowBoundaries":access.row_boundaries,"boundaryFields":boundary_fields,"requestVisibility":access.request_visibility,"requirements":entity.access_requirements,"selectPolicies":select_policies(registry,entity,&options.access_profile)},"derived":derived,"sources":sources});
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
