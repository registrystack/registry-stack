// SPDX-License-Identifier: Apache-2.0
//! Renders a plan into the files of a registry project.
//!
//! The files are the same six a plain `init` writes, minus the module and
//! plus the echoed selection, and every value in them comes from the plan:
//! this module decides layout and wording only. The YAML is written by hand
//! rather than serialized, so the project carries the comments a reader
//! needs and keeps the key order a reader expects.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde_json::{json, Map, Value};

use super::resolve::{Classification, FieldKind, Plan, PlannedEntity, PlannedField, Text};
use super::selection::Selection;
use crate::{FIXTURE_JOURNEYS_PATH, INIT_RUNTIME_EXAMPLE};

/// Where the project keeps the selection it was derived from.
pub(crate) const SELECTION_PATH: &str = "model/selection.yaml";

/// The registry-wide operator profile the project grants everything to.
pub(crate) const OPERATOR_PROFILE: &str = "operator";
/// The read-only profile the project grants the non-restricted entities to.
pub(crate) const READER_PROFILE: &str = "reader";

/// The placeholder identity the plain `init` runtime example carries, which
/// the derived project replaces with its own registry identifier.
const RUNTIME_EXAMPLE_PLACEHOLDER: &str = "generic-registry";

/// Every file of the project, keyed by its path inside the destination.
pub(crate) fn render(plan: &Plan, selection: &Selection) -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([
        ("README.md".to_owned(), readme(plan).into_bytes()),
        ("registry.yaml".to_owned(), registry(plan).into_bytes()),
        (
            "runtime.example.yaml".to_owned(),
            runtime_example(plan).into_bytes(),
        ),
        (
            "dev-clients.yaml".to_owned(),
            dev_clients(plan).into_bytes(),
        ),
        (
            FIXTURE_JOURNEYS_PATH.to_owned(),
            journeys(plan).into_bytes(),
        ),
        (
            SELECTION_PATH.to_owned(),
            selection_echo(selection).into_bytes(),
        ),
    ])
}

/// The entities the reader profile may read: those not classified
/// `restricted`.
pub(crate) fn reader_entities(plan: &Plan) -> Vec<&PlannedEntity> {
    plan.entities
        .iter()
        .filter(|entity| entity.classification != Classification::Restricted)
        .collect()
}

/// The fields classified above their entity: the ones the model marks
/// sensitive inside an entity that is not, which `check` reports as
/// `access.profile.higher_classification` for every profile reading them.
pub(crate) fn elevated_fields(plan: &Plan) -> Vec<(&PlannedEntity, &PlannedField)> {
    plan.entities
        .iter()
        .flat_map(|entity| {
            entity
                .all_fields()
                .filter(move |field| field.classification > entity.classification)
                .map(move |field| (entity, field))
        })
        .collect()
}

fn base_iri(plan: &Plan) -> String {
    format!("https://{}.example.invalid", plan.registry_id)
}

fn operate_scope(plan: &Plan) -> String {
    format!("registry:{}:operate", plan.registry_id)
}

fn read_scope(plan: &Plan) -> String {
    format!("registry:{}:read", plan.registry_id)
}

fn operator_principal(plan: &Plan) -> String {
    format!("{}-operator", plan.registry_id)
}

fn reader_principal(plan: &Plan) -> String {
    format!("{}-reader", plan.registry_id)
}

fn registry(plan: &Plan) -> String {
    let mut yaml = Yaml::default();
    let base = base_iri(plan);
    let id = &plan.registry_id;
    let title = &plan.registry_title;
    yaml.comment(
        0,
        &format!(
            "{title}: a registry project derived from {} {} by `bregctl init --from publicschema`. \
             The selection it was derived from is echoed in {SELECTION_PATH}, and README.md \
             explains each rule the derivation applied. Everything below is ordinary project \
             source: edit it as you would a project written by hand, and run `bregctl check` \
             after each change.",
            plan.model.display_name, plan.model.version
        ),
    );
    yaml.line(0, "apiVersion: registry.registrystack.org/v1alpha1");
    yaml.line(0, "kind: RegistryProject");
    yaml.blank();
    yaml.comment(
        0,
        "Registry identity. `canonicalBaseIri` is the stable base of the IRIs this registry \
         publishes, so point it at a hostname you control before a production package. Names \
         under `.example.invalid` never resolve.",
    );
    yaml.line(0, "registry:");
    yaml.entry(1, "id", id);
    yaml.line(1, "version: 0.1.0");
    yaml.line(1, "defaultLanguage: en");
    yaml.entry(1, "canonicalBaseIri", &base);
    yaml.blank();
    yaml.comment(
        0,
        "Package identity binds a compiled package to one environment, one instance, and one \
         reviewed source revision. `local` is the unsigned environment that `bregctl dev` runs \
         on your machine; a package for any other environment must be signed. Raise `sequence` \
         by one for each package you build.",
    );
    yaml.line(0, "package:");
    yaml.line(1, "environment: local");
    yaml.entry(1, "instanceId", &format!("{id}-1"));
    yaml.line(1, "sequence: 1");
    yaml.entry(1, "sourceRevision", &format!("{id}-0.1.0"));
    yaml.blank();
    yaml.comment(
        0,
        &format!(
            "The Registry Manifest projection is the catalogue description this registry \
             publishes about itself. Every entity and field below carries the {} concept it \
             was derived from, so a catalogue reader can tell what a field means without \
             reading this file. `accessProfile` and `classificationCeiling` bound what the \
             projection may describe; they never grant access to a caller.",
            plan.model.display_name
        ),
    );
    yaml.line(0, "manifestProjection:");
    yaml.entry(1, "accessProfile", OPERATOR_PROFILE);
    yaml.entry(
        1,
        "classificationCeiling",
        plan.classification_ceiling.as_str(),
    );
    yaml.line(1, "catalog:");
    yaml.entry(2, "baseUrl", &base);
    yaml.entry(2, "title", &format!("{title} Catalogue"));
    yaml.entry(
        2,
        "description",
        &format!("Portable metadata for the records of {title}; replace it with your own."),
    );
    yaml.line(2, "publisher:");
    yaml.entry(3, "id", &format!("{id}-authority"));
    yaml.entry(3, "name", &format!("{title} Authority"));
    yaml.entry(3, "iri", &format!("{base}/authority"));
    yaml.line(1, "datasets:");
    yaml.entry(2, "- id", id);
    yaml.entry(3, "title", title);
    yaml.entry(
        3,
        "description",
        &format!(
            "The records of {title}, derived from {} {}; replace it with your own.",
            plan.model.display_name, plan.model.version
        ),
    );
    yaml.entry(3, "owner", &format!("{title} Authority"));
    yaml.line(3, "status: under_development");
    yaml.line(1, "dataServices:");
    yaml.entry(2, "- id", &format!("{id}-api"));
    yaml.entry(3, "title", &format!("{title} API"));
    yaml.entry(3, "endpointUrl", &base);
    yaml.line(3, &format!("servesDatasets: [{}]", scalar(id)));
    yaml.line(1, "entities:");
    for entity in &plan.entities {
        yaml.entry(2, "- id", &entity.id);
        yaml.text(3, "title", &entity.title);
        if !entity.description.is_empty() {
            yaml.text(3, "description", &entity.description);
        }
        yaml.entry(3, "conceptUri", &entity.concept_uri);
        yaml.line(3, "identifiers:");
        yaml.line(
            4,
            &format!(
                "- {{field: {}, kind: local}}",
                scalar(&entity.identifier.id)
            ),
        );
        yaml.line(3, "fields:");
        for field in entity.all_fields() {
            match (&field.kind, &field.concept_uri) {
                (FieldKind::Reference { .. }, Some(uri)) => {
                    yaml.entry(4, "- id", &field.id);
                    yaml.entry(5, "relationshipRole", &field.property);
                    yaml.entry(5, "relationshipConceptUri", uri);
                }
                (kind, Some(uri)) if kind.manifest_scalar() => {
                    yaml.line(
                        4,
                        &format!(
                            "- {{id: {}, concepts: [{}]}}",
                            scalar(&field.id),
                            scalar(uri)
                        ),
                    );
                }
                _ => {}
            }
        }
    }
    if !plan.vocabularies.is_empty() {
        yaml.line(1, "vocabularies:");
        for vocabulary in &plan.vocabularies {
            yaml.entry(2, "- id", &vocabulary.id);
            yaml.entry(3, "schemeIri", &vocabulary.scheme_iri);
            yaml.entry(3, "version", &plan.model.version);
            yaml.entry(3, "externalRef", &vocabulary.scheme_iri);
            yaml.line(3, "concepts:");
            for code in &vocabulary.values {
                let mut concept = format!("- {{code: {}", scalar(&code.code));
                if let Some(iri) = &code.iri {
                    let _ = write!(concept, ", iri: {}", scalar(iri));
                }
                if !code.label.is_empty() {
                    let _ = write!(concept, ", label: {}", flow_text(&code.label));
                }
                concept.push('}');
                yaml.line(4, &concept);
            }
        }
    }
    yaml.line(1, "publicService:");
    yaml.entry(2, "id", &format!("{id}-service"));
    yaml.entry(2, "title", &format!("{title} Service"));
    yaml.blank();

    if !plan.vocabularies.is_empty() {
        yaml.comment(
            0,
            &format!(
                "A vocabulary is a closed code list: a `vocabulary-code` field accepts only these \
                 values, and the compiler refuses any other value at authoring time. Each list \
                 below carries the values of one {} enumeration, in the model's order; the \
                 catalogue entry above carries their labels.",
                plan.model.display_name
            ),
        );
        yaml.line(0, "vocabularies:");
        for vocabulary in &plan.vocabularies {
            yaml.entry(1, "- id", &vocabulary.id);
            yaml.line(
                2,
                &format!(
                    "values: [{}]",
                    vocabulary
                        .values
                        .iter()
                        .map(|code| scalar(&code.code))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            );
        }
        yaml.blank();
    }

    yaml.comment(
        0,
        "One entity per selected concept. The first field of each is its identifier: the model \
         has no identifying property of its own, so the derivation adds one, required and \
         unique, that the registry assigns. Every other field is a selected property, under \
         the model's name in kebab case.",
    );
    yaml.line(0, "entities:");
    for entity in &plan.entities {
        yaml.comment(1, &format!("{} ({})", entity.concept, entity.concept_uri));
        yaml.entry(1, "- id", &entity.id);
        yaml.entry(2, "primaryDataset", id);
        yaml.entry(2, "route", &entity.route);
        yaml.line(2, "mutationMode: mutable");
        yaml.entry(2, "classification", entity.classification.as_str());
        yaml.line(2, "fields:");
        for field in entity.all_fields() {
            field_source(&mut yaml, 3, field);
        }
        yaml.line(2, "constraints:");
        yaml.line(
            3,
            &format!(
                "- {{kind: unique, fields: [{}]}}",
                scalar(&entity.identifier.id)
            ),
        );
    }
    yaml.blank();

    yaml.comment(
        0,
        "A token selects one profile per request, and that profile decides everything the \
         request may touch. `operator` may create, read, list, and patch every entity; it is \
         the profile `bregctl dev` and the journeys use first. `check` reports \
         `access.profile.unrestricted_collection` for it: it can list every record, and a \
         caller-supplied filter is not authorization. That is intended for a single \
         operations team; close it with a `rowBoundaries` entry or by removing `list`.",
    );
    let elevated = elevated_fields(plan);
    if !elevated.is_empty() {
        yaml.comment(
            0,
            &format!(
                "`check` also reports `access.profile.higher_classification` for {}: the \
                 model marks {} sensitive, so the derivation classified {} `restricted` \
                 inside an entity that is not, and `operator` reads {} anyway. Keep the \
                 finding as a reminder of which fields a profile discloses, or raise the \
                 entity's classification in {SELECTION_PATH} and derive again.",
                names_of(&elevated),
                if elevated.len() == 1 {
                    "that property"
                } else {
                    "those properties"
                },
                if elevated.len() == 1 {
                    "the field"
                } else {
                    "the fields"
                },
                if elevated.len() == 1 { "it" } else { "them" },
            ),
        );
    }
    yaml.line(0, "accessProfiles:");
    yaml.entry(1, "- id", OPERATOR_PROFILE);
    yaml.line(2, "default: true");
    yaml.line(2, "principalClaim: registry_principal");
    yaml.line(
        2,
        &format!("requiredScopes: [{}]", scalar(&operate_scope(plan))),
    );
    yaml.line(2, "requiredPurposes: [registry-operations]");
    yaml.line(2, "grants:");
    for entity in &plan.entities {
        let all: Vec<&str> = entity.all_fields().map(|field| field.id.as_str()).collect();
        let filterable: Vec<&str> = entity
            .all_fields()
            .filter(|field| field.kind.filterable())
            .map(|field| field.id.as_str())
            .collect();
        yaml.entry(3, "- entity", &entity.id);
        yaml.line(4, "rowBoundaries: []");
        yaml.line(4, "operations: [create, get, list, patch]");
        yaml.line(4, &format!("readableFields: {}", flow_list(&all)));
        yaml.line(4, &format!("writableFields: {}", flow_list(&all)));
        yaml.line(4, &format!("filterableFields: {}", flow_list(&filterable)));
    }
    let readers = reader_entities(plan);
    if !readers.is_empty() {
        yaml.blank();
        yaml.comment(
            1,
            "A read-only profile over the entities that are not classified `restricted`, \
             reading only their fields that are not either. It lists whole collections too, so \
             `check` reports the same finding for it; bind a `rowBoundaries` entry to whatever \
             field carries your registry's tenancy to close it.",
        );
        yaml.entry(1, "- id", READER_PROFILE);
        yaml.line(2, "principalClaim: registry_principal");
        yaml.line(
            2,
            &format!("requiredScopes: [{}]", scalar(&read_scope(plan))),
        );
        yaml.line(2, "requiredPurposes: [registry-reporting]");
        yaml.line(2, "grants:");
        for entity in readers {
            let readable: Vec<&str> = entity
                .all_fields()
                .filter(|field| field.classification != Classification::Restricted)
                .map(|field| field.id.as_str())
                .collect();
            yaml.entry(3, "- entity", &entity.id);
            yaml.line(4, "rowBoundaries: []");
            yaml.line(4, "operations: [get, list]");
            yaml.line(4, &format!("readableFields: {}", flow_list(&readable)));
            yaml.line(
                4,
                &format!(
                    "filterableFields: {}",
                    flow_list(&[entity.identifier.id.as_str()])
                ),
            );
        }
    }
    yaml.finish()
}

fn field_source(yaml: &mut Yaml, indent: usize, field: &PlannedField) {
    let classification = field.classification.as_str();
    let required = if field.required {
        ", required: true"
    } else {
        ""
    };
    let id = scalar(&field.id);
    let inline = match &field.kind {
        FieldKind::Boolean => format!("type: boolean{required}"),
        FieldKind::String {
            min_length,
            max_length,
        } => {
            if *min_length > 0 {
                format!("type: string{required}, minLength: {min_length}, maxLength: {max_length}")
            } else {
                format!("type: string{required}, maxLength: {max_length}")
            }
        }
        FieldKind::Int64 => format!("type: int64{required}"),
        FieldKind::Decimal { precision, scale } => {
            format!("type: decimal{required}, precision: {precision}, scale: {scale}")
        }
        FieldKind::Date => format!("type: date{required}"),
        FieldKind::Timestamp => format!("type: timestamp{required}"),
        FieldKind::VocabularyCode { vocabulary } => {
            format!(
                "type: vocabulary-code{required}, vocabulary: {}",
                scalar(vocabulary)
            )
        }
        FieldKind::Reference { target } => {
            format!("type: reference{required}, target: {}", scalar(target))
        }
        FieldKind::Structured { max_bytes, schema } => {
            yaml.line(indent, &format!("- id: {id}"));
            yaml.line(indent + 1, "type: structured");
            if field.required {
                yaml.line(indent + 1, "required: true");
            }
            yaml.line(indent + 1, &format!("classification: {classification}"));
            yaml.line(indent + 1, &format!("maxBytes: {max_bytes}"));
            yaml.line(indent + 1, "schema:");
            for line in schema_lines(schema) {
                yaml.line(indent + 2, &line);
            }
            return;
        }
    };
    yaml.line(
        indent,
        &format!("- {{id: {id}, {inline}, classification: {classification}}}"),
    );
}

/// The width a schema line stays within, so a code list wraps instead of
/// running past the edge of an editor or filling a page with one code per
/// line.
const SCHEMA_LINE_WIDTH: usize = 88;

/// A JSON Schema as indented JSON, which YAML reads as a flow mapping: one
/// key per line, and a list of scalars wrapped across lines instead of one
/// scalar per line.
fn schema_lines(schema: &Value) -> Vec<String> {
    let mut lines = Vec::new();
    write_schema(&mut lines, "", schema, 0, "");
    lines
}

fn write_schema(lines: &mut Vec<String>, prefix: &str, value: &Value, depth: usize, suffix: &str) {
    let margin = "  ".repeat(depth);
    match value {
        Value::Object(members) if !members.is_empty() => {
            lines.push(format!("{margin}{prefix}{{"));
            let last = members.len() - 1;
            for (position, (key, member)) in members.iter().enumerate() {
                let key = serde_json::to_string(key).expect("a key serializes");
                let suffix = if position == last { "" } else { "," };
                write_schema(lines, &format!("{key}: "), member, depth + 1, suffix);
            }
            lines.push(format!("{margin}}}{suffix}"));
        }
        Value::Array(items) if !items.is_empty() && items.iter().any(Value::is_object) => {
            lines.push(format!("{margin}{prefix}["));
            let last = items.len() - 1;
            for (position, item) in items.iter().enumerate() {
                let suffix = if position == last { "" } else { "," };
                write_schema(lines, "", item, depth + 1, suffix);
            }
            lines.push(format!("{margin}]{suffix}"));
        }
        Value::Array(items) if !items.is_empty() => {
            let mut line = format!("{margin}{prefix}[");
            let last = items.len() - 1;
            for (position, item) in items.iter().enumerate() {
                let mut text = serde_json::to_string(item).expect("an item serializes");
                if position != last {
                    text.push(',');
                }
                if line.len() + 1 + text.len() > SCHEMA_LINE_WIDTH && !line.ends_with('[') {
                    lines.push(line);
                    line = format!("{margin}  ");
                } else if !line.ends_with('[') {
                    line.push(' ');
                }
                line.push_str(&text);
            }
            line.push(']');
            line.push_str(suffix);
            lines.push(line);
        }
        _ => {
            let text = serde_json::to_string(value).expect("a value serializes");
            lines.push(format!("{margin}{prefix}{text}{suffix}"));
        }
    }
}

fn runtime_example(plan: &Plan) -> String {
    String::from_utf8(INIT_RUNTIME_EXAMPLE.to_vec())
        .expect("the runtime example is UTF-8")
        .replace(RUNTIME_EXAMPLE_PLACEHOLDER, &plan.registry_id)
}

fn dev_clients(plan: &Plan) -> String {
    let mut yaml = Yaml::default();
    yaml.comment(
        0,
        "Local callers for `bregctl dev`. Registry Mint, the local token issuer that `dev` \
         starts beside the registry, registers each client below and issues it short-lived \
         tokens carrying these claims. One client binds each access profile that \
         tests/journeys.yaml uses, with the claims those journeys expect, so a first start \
         runs the journeys and serves the package without another file. `dev` generates a \
         fresh private key per client under `.breg/dev/credentials/`; nothing here is a \
         credential, and none of it belongs in a deployment.",
    );
    yaml.line(0, "version: 1");
    yaml.line(0, "clients:");
    yaml.entry(1, "- id", OPERATOR_PROFILE);
    yaml.line(2, &format!("accessProfiles: [{OPERATOR_PROFILE}]"));
    yaml.line(2, &format!("scopes: [{}]", scalar(&operate_scope(plan))));
    yaml.line(2, "claims:");
    yaml.entry(3, "registry_principal", &operator_principal(plan));
    yaml.line(3, "registry_purpose: registry-operations");
    if !reader_entities(plan).is_empty() {
        yaml.entry(1, "- id", READER_PROFILE);
        yaml.line(2, &format!("accessProfiles: [{READER_PROFILE}]"));
        yaml.line(2, &format!("scopes: [{}]", scalar(&read_scope(plan))));
        yaml.line(2, "claims:");
        yaml.entry(3, "registry_principal", &reader_principal(plan));
        yaml.line(3, "registry_purpose: registry-reporting");
    }
    yaml.finish()
}

/// The journeys `bregctl test` and `bregctl dev` replay: one record per
/// entity created by the operator, read back, and listed, then each
/// non-restricted collection listed by the reader.
fn journeys(plan: &Plan) -> String {
    let mut yaml = Yaml::default();
    yaml.comment(
        0,
        "Project journeys: the requests `bregctl test` replays over real HTTP, with real \
         credentials, against a throwaway database before a package is built. Every entity, \
         profile, field, and claim below is resolved against the compiled project first, so a \
         journey can never reach past what a profile already allows. The claims below are \
         synthetic; credentials never belong here.",
    );
    yaml.comment(
        0,
        "The operator creates one record per entity, in an order that lets each reference \
         point at a record created before it, then reads and lists each one. A reference \
         whose target has no record yet is left out of the create, so the journey stays valid \
         for a cycle of references too.",
    );
    yaml.line(0, "apiVersion: registry.registrystack.org/breg-journeys/v1");
    yaml.line(0, "journeys:");
    yaml.line(1, "- id: first-records");
    yaml.line(2, "steps:");
    let mut operator_claims_declared = false;
    let mut created: BTreeSet<&str> = BTreeSet::new();
    for entity in creation_order(plan) {
        let capture = format!("example-{}", entity.id);
        let identifier_value = format!("{}-1", entity.id);
        yaml.line(3, &format!("- id: create-{}", entity.id));
        yaml.entry(4, "entity", &entity.id);
        yaml.entry(4, "accessProfile", OPERATOR_PROFILE);
        operator_claims(&mut yaml, plan, &mut operator_claims_declared);
        yaml.line(4, "request:");
        yaml.line(5, "operation: create");
        yaml.line(5, "data:");
        for field in entity.all_fields() {
            let Some(value) = example_value(plan, field, &identifier_value, &created) else {
                continue;
            };
            yaml.line(6, &format!("{}: {value}", scalar(&field.id)));
        }
        yaml.line(4, "expect:");
        yaml.line(5, "outcome: success");
        yaml.line(5, "status: 201");
        yaml.line(
            5,
            &format!(
                "fields: {{{}: {}}}",
                scalar(&entity.identifier.id),
                scalar(&identifier_value)
            ),
        );
        yaml.entry(4, "capture", &capture);
        yaml.line(3, &format!("- id: get-{}", entity.id));
        yaml.entry(4, "entity", &entity.id);
        yaml.entry(4, "accessProfile", OPERATOR_PROFILE);
        yaml.line(4, "claims: *operator_claims");
        yaml.line(
            4,
            &format!(
                "request: {{operation: get, recordRef: {}}}",
                scalar(&capture)
            ),
        );
        yaml.line(
            4,
            &format!(
                "expect: {{outcome: success, status: 200, fields: {{{}: {}}}}}",
                scalar(&entity.identifier.id),
                scalar(&identifier_value)
            ),
        );
        yaml.line(3, &format!("- id: list-{}", entity.route));
        yaml.entry(4, "entity", &entity.id);
        yaml.entry(4, "accessProfile", OPERATOR_PROFILE);
        yaml.line(4, "claims: *operator_claims");
        yaml.line(4, "request: {operation: list}");
        yaml.line(4, "expect: {outcome: success, status: 200, count: 1}");
        created.insert(entity.id.as_str());
    }
    let mut reader_claims_declared = false;
    for entity in reader_entities(plan) {
        yaml.line(
            3,
            &format!("- id: read-{}-as-{READER_PROFILE}", entity.route),
        );
        yaml.entry(4, "entity", &entity.id);
        yaml.entry(4, "accessProfile", READER_PROFILE);
        if reader_claims_declared {
            yaml.line(4, "claims: *reader_claims");
        } else {
            yaml.line(4, "claims: &reader_claims");
            yaml.entry(5, "principal", &reader_principal(plan));
            yaml.line(5, &format!("scopes: [{}]", scalar(&read_scope(plan))));
            yaml.line(5, "purpose: registry-reporting");
            reader_claims_declared = true;
        }
        yaml.line(4, "request: {operation: list}");
        yaml.line(4, "expect: {outcome: success, status: 200, count: 1}");
    }
    yaml.finish()
}

fn operator_claims(yaml: &mut Yaml, plan: &Plan, declared: &mut bool) {
    if *declared {
        yaml.line(4, "claims: *operator_claims");
        return;
    }
    yaml.line(4, "claims: &operator_claims");
    yaml.entry(5, "principal", &operator_principal(plan));
    yaml.line(5, &format!("scopes: [{}]", scalar(&operate_scope(plan))));
    yaml.line(5, "purpose: registry-operations");
    *declared = true;
}

/// The entities in an order that places a reference's target before the
/// entity carrying it, wherever the references allow one; a cycle is broken
/// at the first entity still waiting.
fn creation_order(plan: &Plan) -> Vec<&PlannedEntity> {
    let mut ordered: Vec<&PlannedEntity> = Vec::new();
    let mut placed: BTreeSet<&str> = BTreeSet::new();
    let mut waiting: Vec<&PlannedEntity> = plan.entities.iter().collect();
    while !waiting.is_empty() {
        let position = waiting
            .iter()
            .position(|entity| {
                entity.fields.iter().all(|field| match &field.kind {
                    FieldKind::Reference { target } => {
                        target == &entity.id || placed.contains(target.as_str())
                    }
                    _ => true,
                })
            })
            .unwrap_or(0);
        let entity = waiting.remove(position);
        placed.insert(entity.id.as_str());
        ordered.push(entity);
    }
    ordered
}

/// The YAML of an example value for `field` in a create request, or `None`
/// when the field is a reference whose target has no record yet.
fn example_value(
    plan: &Plan,
    field: &PlannedField,
    identifier_value: &str,
    created: &BTreeSet<&str>,
) -> Option<String> {
    Some(match &field.kind {
        FieldKind::Boolean => "true".to_owned(),
        FieldKind::String { max_length, .. } => {
            let value = if field.required {
                identifier_value.to_owned()
            } else {
                "example".to_owned()
            };
            scalar(&value.chars().take(*max_length as usize).collect::<String>())
        }
        FieldKind::Int64 => "1".to_owned(),
        FieldKind::Decimal { .. } => scalar("1.5"),
        FieldKind::Date => scalar("2024-01-01"),
        FieldKind::Timestamp => scalar("2024-01-01T00:00:00Z"),
        FieldKind::VocabularyCode { vocabulary } => {
            let first = plan
                .vocabularies
                .iter()
                .find(|candidate| &candidate.id == vocabulary)
                .and_then(|vocabulary| vocabulary.values.first())?;
            scalar(&first.code)
        }
        FieldKind::Reference { target } => {
            if !created.contains(target.as_str()) {
                return None;
            }
            format!("{{recordRef: {}}}", scalar(&format!("example-{target}")))
        }
        FieldKind::Structured { schema, .. } => {
            serde_json::to_string(&example_structured(schema)).expect("a value serializes")
        }
    })
}

/// A value the schema accepts: every required property with a value of its
/// declared type, and otherwise the first free-text property carrying a word.
fn example_structured(schema: &Value) -> Value {
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let required: Vec<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|names| names.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut object = Map::new();
    for name in &required {
        let Some(property) = properties.get(*name) else {
            continue;
        };
        object.insert((*name).to_owned(), example_of_schema(property));
    }
    if required.is_empty() {
        if let Some((name, property)) = properties.iter().find(|(_, property)| {
            property.get("type") == Some(&json!("string")) && property.get("enum").is_none()
        }) {
            object.insert(name.clone(), example_of_schema(property));
        }
    }
    Value::Object(object)
}

fn example_of_schema(property: &Value) -> Value {
    if let Some(first) = property
        .get("enum")
        .and_then(Value::as_array)
        .and_then(|values| values.first())
    {
        return first.clone();
    }
    match property.get("type").and_then(Value::as_str) {
        Some("string") => json!("example"),
        Some("integer") => json!(1),
        Some("number") => json!(1.5),
        Some("boolean") => json!(true),
        Some("array") => {
            if property.get("items").is_some() {
                json!([])
            } else {
                json!([0, 0])
            }
        }
        _ => Value::Object(Map::new()),
    }
}

fn selection_echo(selection: &Selection) -> String {
    let mut yaml = Yaml::default();
    yaml.comment(
        0,
        "The selection this project was derived from. It is not read by any command: keep it \
         beside the project so a reader can tell which concepts and properties were chosen, or \
         pass it to `bregctl init <new-directory> --from publicschema --selection <this file>` \
         to derive a fresh project from it after editing.",
    );
    yaml.raw(&selection.to_yaml());
    yaml.finish()
}

fn readme(plan: &Plan) -> String {
    let mut out = String::new();
    let model = plan.model.display_name;
    let version = &plan.model.version;
    let _ = writeln!(out, "# {}", plan.registry_title);
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "A registry project derived from {model} {version} by `bregctl init --from publicschema`. \
         Everything in it is ordinary project source: edit the files as you would a project \
         written by hand, and run `bregctl check .` after each change."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Attribution");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "The concepts, properties, and code lists in this project are derived from {model} \
         {version} ({}), licensed under {}. Keep this notice with the project and with any \
         package built from it.",
        plan.model.repository, plan.model.license
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Entities");
    let _ = writeln!(out);
    for entity in &plan.entities {
        let _ = writeln!(
            out,
            "### `{}` from {} `{}`",
            entity.id, model, entity.concept
        );
        let _ = writeln!(out);
        if let Some(description) = entity.description.get("en") {
            let _ = writeln!(out, "{description}");
            let _ = writeln!(out);
        }
        let _ = writeln!(
            out,
            "Route `/v1/records/{}`, classified `{}`, identified by `{}`.",
            entity.route,
            entity.classification.as_str(),
            entity.identifier.id
        );
        let _ = writeln!(out);
        let _ = writeln!(out, "| Field | Property | Type | Classification |");
        let _ = writeln!(out, "|---|---|---|---|");
        for field in entity.all_fields() {
            let _ = writeln!(
                out,
                "| `{}` | `{}` | {} | `{}` |",
                field.id,
                field.property,
                describe(&field.kind),
                field.classification.as_str()
            );
        }
        let _ = writeln!(out);
    }
    let _ = writeln!(out, "## How the project was derived");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "- Each selected concept became an entity, named by the concept in kebab case and \
         routed under its plural. The identifier field is added by the derivation, because \
         the model has no identifying property: it is required, unique, and assigned by the \
         registry."
    );
    let _ = writeln!(
        out,
        "- Each selected property became a field of the same name in kebab case. A text \
         property is a bounded `string`; a number is `int64` or `decimal`; a date, a \
         timestamp, and a boolean keep their type."
    );
    let _ = writeln!(
        out,
        "- A property whose values come from an enumeration became a `vocabulary-code` field \
         over a closed vocabulary listing every value, when the enumeration has at most {} \
         values. A larger enumeration became a bounded `string` carrying the code alone. The \
         selection's `vocabularies` list overrides either choice per enumeration.",
        super::resolve::INLINE_VOCABULARY_THRESHOLD
    );
    let _ = writeln!(
        out,
        "- A property whose value is another selected concept became a `reference` to that \
         entity. One whose value is a concept that was not selected, and that the model \
         treats as a value rather than a record, became a `structured` field carrying that \
         value inline under a closed schema. A property with many values became a \
         `structured` field carrying a bounded list."
    );
    let _ = writeln!(
        out,
        "- A property {model} marks as sensitive or restricted is classified `restricted`; \
         every other field, and every entity, is `internal`. The Registry Manifest projection's \
         ceiling is the highest classification present."
    );
    let _ = writeln!(
        out,
        "- Every entity and field carries its {model} concept IRI in the Registry Manifest \
         projection, and each vocabulary carries the enumeration's IRI and labels, so a \
         catalogue reader can tell what a field means without reading `registry.yaml`."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Access profiles");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "- `{OPERATOR_PROFILE}` may create, read, list, and patch every entity and every \
         field. It is the default profile, the one `bregctl dev` and `tests/journeys.yaml` \
         use first."
    );
    if reader_entities(plan).is_empty() {
        let _ = writeln!(
            out,
            "- Every entity is classified `restricted`, so the project declares no read-only \
             profile. Add one when you decide which fields a reader may see."
        );
    } else {
        let _ = writeln!(
            out,
            "- `{READER_PROFILE}` may read and list the entities that are not classified \
             `restricted`, and only their fields that are not either."
        );
    }
    let _ = writeln!(
        out,
        "\n`bregctl check .` reports `access.profile.unrestricted_collection` for each \
         profile: it can list a whole collection, and a caller-supplied filter is not \
         authorization. Leave the findings while you explore; before a production package, \
         bind a `rowBoundaries` entry to whatever field carries your registry's tenancy, or \
         remove `list`."
    );
    let elevated = elevated_fields(plan);
    if !elevated.is_empty() {
        let _ = writeln!(
            out,
            "\nIt also reports `access.profile.higher_classification` for {}. {model} marks \
             {} sensitive, so the derivation classified {} `restricted` inside an entity \
             that is not, and `{OPERATOR_PROFILE}` reads {} anyway. Keep the finding as a \
             reminder of what that profile discloses, or raise the entity's classification \
             in `{SELECTION_PATH}` and derive again.",
            names_of(&elevated),
            if elevated.len() == 1 {
                "that property"
            } else {
                "those properties"
            },
            if elevated.len() == 1 {
                "the field"
            } else {
                "the fields"
            },
            if elevated.len() == 1 { "it" } else { "them" },
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Files");
    let _ = writeln!(out);
    let _ = writeln!(out, "| File | Purpose |");
    let _ = writeln!(out, "|---|---|");
    let _ = writeln!(
        out,
        "| `registry.yaml` | The registry project: identity, catalogue projection, \
         vocabularies, entities, and access profiles. |"
    );
    let _ = writeln!(
        out,
        "| `tests/journeys.yaml` | The requests `bregctl test` and `bregctl dev` replay: one \
         record per entity created, read, and listed. |"
    );
    let _ = writeln!(
        out,
        "| `dev-clients.yaml` | The local callers `bregctl dev` registers with its token \
         issuer, one per access profile the journeys use. |"
    );
    let _ = writeln!(
        out,
        "| `runtime.example.yaml` | An example runtime configuration for a deployment; not \
         read by any command. |"
    );
    let _ = writeln!(
        out,
        "| `{SELECTION_PATH}` | The selection this project was derived from; edit and pass \
         it back with `--selection` to derive a fresh project. |"
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Next steps");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "1. Run `bregctl check .` and read the findings; the ones named above are expected."
    );
    let _ = writeln!(
        out,
        "2. Run `bregctl dev .` to start the registry in Docker, replay the journeys, and \
         serve the API locally."
    );
    let _ = writeln!(
        out,
        "3. Adjust the fields: tighten a length, add `required: true` where a record cannot \
         do without a value, and add a `selectorProfiles` entry for each exact-match question \
         a caller may ask."
    );
    let _ = writeln!(
        out,
        "4. Replace `canonicalBaseIri` in `registry.yaml` before you build a production \
         package; the reserved `.example.invalid` name never resolves."
    );
    out
}

/// A sentence describing a field type, for the README.
fn describe(kind: &FieldKind) -> String {
    match kind {
        FieldKind::Boolean => "boolean".to_owned(),
        FieldKind::String {
            min_length,
            max_length,
        } => {
            if *min_length > 0 {
                format!("string, {min_length} to {max_length} characters")
            } else {
                format!("string, up to {max_length} characters")
            }
        }
        FieldKind::Int64 => "int64".to_owned(),
        FieldKind::Decimal { precision, scale } => {
            format!("decimal, precision {precision}, scale {scale}")
        }
        FieldKind::Date => "date".to_owned(),
        FieldKind::Timestamp => "timestamp".to_owned(),
        FieldKind::VocabularyCode { vocabulary } => {
            format!("vocabulary-code from `{vocabulary}`")
        }
        FieldKind::Reference { target } => format!("reference to `{target}`"),
        FieldKind::Structured { max_bytes, schema } => {
            let shape = if schema
                .get("required")
                .and_then(Value::as_array)
                .is_some_and(|required| required.iter().any(|name| name == "values"))
            {
                "a list"
            } else if schema
                .get("required")
                .and_then(Value::as_array)
                .is_some_and(|required| required.iter().any(|name| name == "coordinates"))
            {
                "a geometry"
            } else {
                "an object"
            };
            format!("structured, {shape} of up to {max_bytes} bytes")
        }
    }
}

/// A block-YAML writer: two-space indentation, wrapped comments, and scalars
/// quoted only when YAML would read them as something else.
#[derive(Default)]
struct Yaml {
    out: String,
}

impl Yaml {
    fn line(&mut self, indent: usize, text: &str) {
        for _ in 0..indent {
            self.out.push_str("  ");
        }
        self.out.push_str(text);
        self.out.push('\n');
    }

    fn blank(&mut self) {
        self.out.push('\n');
    }

    fn entry(&mut self, indent: usize, key: &str, value: &str) {
        self.line(indent, &format!("{key}: {}", scalar(value)));
    }

    /// A localized text as a block mapping under `key`.
    fn text(&mut self, indent: usize, key: &str, text: &Text) {
        self.line(indent, &format!("{key}:"));
        for (language, value) in text {
            self.entry(indent + 1, language, value);
        }
    }

    /// A comment wrapped at about eighty columns.
    fn comment(&mut self, indent: usize, text: &str) {
        let width = 78usize.saturating_sub(indent * 2 + 2);
        let mut line = String::new();
        for word in text.split_whitespace() {
            if !line.is_empty() && line.len() + 1 + word.len() > width {
                self.line(indent, &format!("# {line}"));
                line.clear();
            }
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
        }
        if !line.is_empty() {
            self.line(indent, &format!("# {line}"));
        }
    }

    /// Text already in YAML, appended as it is.
    fn raw(&mut self, text: &str) {
        self.out.push_str(text);
        if !text.ends_with('\n') {
            self.out.push('\n');
        }
    }

    fn finish(self) -> String {
        self.out
    }
}

/// A localized text as a flow mapping, for one-line entries.
fn flow_text(text: &Text) -> String {
    let entries: Vec<String> = text
        .iter()
        .map(|(language, value)| format!("{language}: {}", scalar(value)))
        .collect();
    format!("{{{}}}", entries.join(", "))
}

/// `entity.field` pairs, comma-joined, for a sentence naming elevated fields.
fn names_of(fields: &[(&PlannedEntity, &PlannedField)]) -> String {
    fields
        .iter()
        .map(|(entity, field)| format!("`{}.{}`", entity.id, field.id))
        .collect::<Vec<_>>()
        .join(", ")
}

fn flow_list(values: &[&str]) -> String {
    let entries: Vec<String> = values.iter().map(|value| scalar(value)).collect();
    format!("[{}]", entries.join(", "))
}

/// Words YAML reads as a boolean or null rather than a string.
const RESERVED_WORDS: &[&str] = &[
    "true", "false", "null", "yes", "no", "on", "off", "y", "n", "~",
];

/// `value` as a YAML scalar: plain when every YAML reader agrees it is that
/// string, JSON-quoted otherwise. A plain scalar here starts with a letter,
/// carries only letters, digits, spaces, and `_ . / : -`, never a `:` before a
/// space or at the end, and is not a word YAML reads as something else.
pub(crate) fn scalar(value: &str) -> String {
    let plain = value
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(character, ' ' | '_' | '.' | '/' | ':' | '-')
        })
        && !value.ends_with(' ')
        && !value.ends_with(':')
        && !value.contains(": ")
        && !RESERVED_WORDS.contains(&value.to_ascii_lowercase().as_str());
    if plain {
        value.to_owned()
    } else {
        serde_json::to_string(value).expect("a string serializes")
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use registry_breg::fixtures::validate_fixture_journeys;
    use registry_linkml::publicschema;

    use super::super::resolve::resolve;
    use super::*;
    use crate::{compile, ProfileArg};

    fn starter_plan(name: &str) -> (Plan, Selection) {
        let starter = publicschema::starters()
            .iter()
            .find(|starter| starter.name == name)
            .expect("the starter ships");
        let selection = Selection::parse(name, starter.contents.as_bytes()).expect("parses");
        let model = publicschema::model().expect("the snapshot reads");
        let plan = resolve(&selection, &model).expect("the starter resolves");
        (plan, selection)
    }

    /// The files written under a fresh directory, returned with the directory's
    /// canonical path: the compiler refuses a symbolic link on the way to a
    /// project, and a platform's temporary root may be one.
    fn write_project(files: &BTreeMap<String, Vec<u8>>) -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().expect("a temporary directory");
        let path = root.path().canonicalize().expect("a canonical path");
        for (relative, bytes) in files {
            let target = path.join(relative);
            std::fs::create_dir_all(target.parent().expect("a parent")).expect("directories");
            std::fs::write(target, bytes).expect("a file");
        }
        (root, path)
    }

    fn yaml(files: &BTreeMap<String, Vec<u8>>, path: &str) -> Value {
        serde_norway::from_slice(&files[path]).expect("valid YAML")
    }

    #[test]
    fn scalars_are_plain_only_when_yaml_reads_them_back_unchanged() {
        assert_eq!(scalar("given-name"), "given-name");
        assert_eq!(scalar("Head of unit"), "Head of unit");
        assert_eq!(
            scalar("https://publicschema.org/Sex"),
            "https://publicschema.org/Sex"
        );
        assert_eq!(scalar("0.3.0"), "\"0.3.0\"");
        assert_eq!(scalar("2024-01-01"), "\"2024-01-01\"");
        assert_eq!(scalar("yes"), "\"yes\"");
        assert_eq!(scalar("No"), "\"No\"");
        assert_eq!(scalar("a: b"), "\"a: b\"");
        assert_eq!(scalar("trailing:"), "\"trailing:\"");
        assert_eq!(scalar("Ménage"), "\"Ménage\"");
        assert_eq!(scalar("with, comma"), "\"with, comma\"");
        assert_eq!(scalar("#hash"), "\"#hash\"");
        assert_eq!(scalar(""), "\"\"");
        for value in [
            "given-name",
            "Head of unit",
            "0.3.0",
            "yes",
            "a: b",
            "Ménage",
            "with, comma",
            "https://publicschema.org/Sex",
            "[bracket]",
            "{brace}",
            "quote \" inside",
        ] {
            let document = format!(
                "key: {}\nflow: {{inner: {}}}\n",
                scalar(value),
                scalar(value)
            );
            let read: Value = serde_norway::from_str(&document).expect("parses");
            assert_eq!(read["key"], value, "{document}");
            assert_eq!(read["flow"]["inner"], value, "{document}");
        }
    }

    #[test]
    fn a_schema_prints_as_json_that_yaml_reads_back_with_code_lists_wrapped() {
        let schema = json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["values"],
            "properties": {
                "values": {
                    "type": "array",
                    "maxItems": 50,
                    "items": {"type": "string", "enum": (0..60).map(|n| format!("code-{n}")).collect::<Vec<_>>()}
                },
                "empty": {},
                "nested": {"type": "array", "items": [{"type": "string"}, {"type": "integer"}]}
            }
        });
        let lines = schema_lines(&schema);
        assert!(
            lines.iter().all(|line| line.len() <= SCHEMA_LINE_WIDTH + 2),
            "{lines:#?}"
        );
        assert!(lines
            .iter()
            .any(|line| line.contains("\"code-0\", \"code-1\"")));
        assert!(
            lines.contains(&"    \"empty\": {},".to_owned()),
            "{lines:#?}"
        );
        let document = format!(
            "schema:\n{}",
            lines
                .iter()
                .map(|line| format!("  {line}\n"))
                .collect::<String>()
        );
        let read: Value = serde_norway::from_str(&document).expect("parses");
        assert_eq!(read["schema"], schema);
    }

    #[test]
    fn the_starter_project_compiles_in_both_profiles_and_its_journeys_validate() {
        let (plan, selection) = starter_plan("household");
        let files = render(&plan, &selection);
        assert_eq!(
            files.keys().collect::<Vec<_>>(),
            vec![
                "README.md",
                "dev-clients.yaml",
                SELECTION_PATH,
                "registry.yaml",
                "runtime.example.yaml",
                FIXTURE_JOURNEYS_PATH,
            ]
        );
        let (_root, path) = write_project(&files);
        let authoring = compile(&path, ProfileArg::Authoring, "init").unwrap_or_else(|failure| {
            panic!("{}", serde_json::to_string_pretty(&failure).unwrap())
        });
        compile(&path, ProfileArg::Production, "init").unwrap_or_else(|failure| {
            panic!("{}", serde_json::to_string_pretty(&failure).unwrap())
        });
        let findings: Vec<String> = authoring
            .findings()
            .iter()
            .map(|finding| finding.code.clone())
            .collect();
        assert!(
            findings.iter().all(|code| {
                code == "access.profile.unrestricted_collection"
                    || code == "access.profile.higher_classification"
            }),
            "{findings:?}"
        );
        let elevated = elevated_fields(&plan);
        assert_eq!(
            findings
                .iter()
                .filter(|code| *code == "access.profile.higher_classification")
                .count(),
            elevated.len(),
            "{findings:?}"
        );
        assert!(elevated
            .iter()
            .any(|(entity, field)| entity.id == "person" && field.id == "marital-status"));
        validate_fixture_journeys(&files[FIXTURE_JOURNEYS_PATH], &authoring)
            .unwrap_or_else(|error| panic!("{error}"));
    }

    #[test]
    fn the_registry_carries_the_plan() {
        let (plan, selection) = starter_plan("household");
        let files = render(&plan, &selection);
        let registry = yaml(&files, "registry.yaml");
        assert_eq!(registry["registry"]["id"], "household-registry");
        assert_eq!(registry["package"]["instanceId"], "household-registry-1");
        assert_eq!(
            registry["manifestProjection"]["classificationCeiling"],
            "restricted"
        );
        let entities = registry["entities"].as_array().expect("entities");
        assert_eq!(entities.len(), 3);
        let person = &entities[0];
        assert_eq!(person["id"], "person");
        assert_eq!(person["route"], "persons");
        let fields = person["fields"].as_array().expect("fields");
        assert_eq!(fields[0]["id"], "person-code");
        assert_eq!(fields[0]["required"], true);
        assert_eq!(fields[0]["minLength"], 1);
        let marital = fields
            .iter()
            .find(|field| field["id"] == "marital-status")
            .expect("marital-status");
        assert_eq!(marital["type"], "vocabulary-code");
        assert_eq!(marital["classification"], "restricted");
        let household = &entities[1];
        let address = household["fields"]
            .as_array()
            .expect("fields")
            .iter()
            .find(|field| field["id"] == "address")
            .expect("address")
            .clone();
        assert_eq!(address["type"], "structured");
        assert_eq!(address["schema"]["additionalProperties"], false);
        assert_eq!(address["schema"]["properties"]["city"]["type"], "string");
        let membership = &entities[2];
        let person_ref = membership["fields"]
            .as_array()
            .expect("fields")
            .iter()
            .find(|field| field["id"] == "person")
            .expect("person")
            .clone();
        assert_eq!(person_ref["type"], "reference");
        assert_eq!(person_ref["target"], "person");
        let manifest_entities = registry["manifestProjection"]["entities"]
            .as_array()
            .expect("manifest entities");
        assert_eq!(
            manifest_entities[0]["conceptUri"],
            "https://publicschema.org/Person"
        );
        assert_eq!(manifest_entities[0]["title"]["fr"], "Personne");
        let manifest_vocabularies = registry["manifestProjection"]["vocabularies"]
            .as_array()
            .expect("manifest vocabularies");
        let sex = manifest_vocabularies
            .iter()
            .find(|vocabulary| vocabulary["id"] == "sex")
            .expect("sex");
        assert_eq!(sex["schemeIri"], "https://publicschema.org/Sex");
        let first_sex = &plan
            .vocabularies
            .iter()
            .find(|vocabulary| vocabulary.id == "sex")
            .expect("sex")
            .values[0];
        assert_eq!(sex["concepts"][0]["code"], first_sex.code);
        assert_eq!(
            sex["concepts"][0]["iri"],
            format!("https://publicschema.org/Sex/{}", first_sex.code)
        );
        let profiles = registry["accessProfiles"].as_array().expect("profiles");
        assert_eq!(profiles[0]["id"], OPERATOR_PROFILE);
        assert_eq!(profiles[1]["id"], READER_PROFILE);
        let reader_person = &profiles[1]["grants"][0];
        assert_eq!(reader_person["entity"], "person");
        let readable = reader_person["readableFields"]
            .as_array()
            .expect("readable");
        assert!(!readable.iter().any(|field| field == "marital-status"));
    }

    #[test]
    fn the_dev_clients_bind_the_profiles_the_journeys_use() {
        let (plan, selection) = starter_plan("household");
        let files = render(&plan, &selection);
        let clients = yaml(&files, "dev-clients.yaml");
        assert_eq!(clients["version"], 1);
        let clients = clients["clients"].as_array().expect("clients");
        assert_eq!(clients.len(), 2);
        assert_eq!(clients[0]["accessProfiles"][0], OPERATOR_PROFILE);
        assert_eq!(
            clients[0]["scopes"][0],
            "registry:household-registry:operate"
        );
        assert_eq!(
            clients[0]["claims"]["registry_principal"],
            "household-registry-operator"
        );
        assert_eq!(clients[1]["accessProfiles"][0], READER_PROFILE);
        let journeys = yaml(&files, FIXTURE_JOURNEYS_PATH);
        let steps = journeys["journeys"][0]["steps"].as_array().expect("steps");
        assert_eq!(steps[0]["id"], "create-person");
        assert_eq!(
            steps[0]["claims"]["principal"],
            "household-registry-operator"
        );
        assert_eq!(steps[0]["request"]["data"]["person-code"], "person-1");
        let first_sex = &plan
            .vocabularies
            .iter()
            .find(|vocabulary| vocabulary.id == "sex")
            .expect("sex")
            .values[0]
            .code;
        assert_eq!(&steps[0]["request"]["data"]["sex"], first_sex);
        let membership = steps
            .iter()
            .find(|step| step["id"] == "create-group-membership")
            .expect("membership create");
        assert_eq!(
            membership["request"]["data"]["person"]["recordRef"],
            "example-person"
        );
        assert!(steps
            .iter()
            .any(|step| step["id"] == "read-persons-as-reader"));
        let runtime = String::from_utf8(files["runtime.example.yaml"].clone()).expect("UTF-8");
        assert!(runtime.contains("instanceId: household-registry-1"));
        assert!(!runtime.contains(RUNTIME_EXAMPLE_PLACEHOLDER));
        let echoed = Selection::parse(SELECTION_PATH, &files[SELECTION_PATH]).expect("parses");
        assert_eq!(echoed, selection);
        let readme = String::from_utf8(files["README.md"].clone()).expect("UTF-8");
        assert!(readme.contains("## Attribution"));
        assert!(readme.contains(&plan.model.repository));
    }

    #[test]
    fn creation_order_places_targets_before_their_references() {
        let (plan, _) = starter_plan("household");
        let order: Vec<&str> = creation_order(&plan)
            .iter()
            .map(|entity| entity.id.as_str())
            .collect();
        assert_eq!(order, vec!["person", "household", "group-membership"]);
    }

    #[test]
    fn a_directory_of_files_is_written_where_the_paths_say() {
        let (plan, selection) = starter_plan("household");
        let (_root, path) = write_project(&render(&plan, &selection));
        assert!(path.join(SELECTION_PATH).is_file());
        assert!(path.join(FIXTURE_JOURNEYS_PATH).is_file());
    }
}
