// SPDX-License-Identifier: Apache-2.0
//! Resolves a selection against the model it names into the plan a project is
//! rendered from.
//!
//! Every policy of the derivation lives here: how a concept becomes an entity,
//! how a property's range becomes a field type, which classification a
//! property's sensitivity earns, and when an enumeration is carried as a
//! closed vocabulary rather than a bounded code. The renderer only writes what
//! the plan says, and the wizard only asks about what this module can accept,
//! so the three ways of running the command agree by construction.

use std::collections::{BTreeMap, BTreeSet};

use registry_breg::Diagnostic;
use registry_linkml::publicschema::{self, Sensitivity, LANGUAGES};
use registry_linkml::{ClassDef, EnumDef, Model, Range, SlotDef};
use serde_json::{json, Value};

use super::selection::{EntitySelection, PropertySelection, Selection, VocabularyMode};
use crate::diagnostic;

/// An enumeration with more values than this is carried as a bounded code
/// rather than a closed vocabulary, unless the selection says otherwise: a
/// project that lists every language of the world inline is unreadable and
/// changes with every revision of the list.
pub(crate) const INLINE_VOCABULARY_THRESHOLD: usize = 300;

const STRING_MAX_LENGTH: u32 = 255;
const CODE_MAX_LENGTH: u32 = 64;
const URI_MAX_LENGTH: u32 = 2048;
const IDENTIFIER_MAX_LENGTH: u32 = 64;
const LIST_MAX_ITEMS: u32 = 50;
const LIST_MAX_BYTES: u32 = 4096;
const OBJECT_MAX_BYTES: u32 = 16384;
const GEOMETRY_MAX_BYTES: u32 = 65536;
const DECIMAL_PRECISION: u8 = 18;
const DECIMAL_SCALE: u8 = 6;

/// Logical field identifiers the compiler reserves, in the kebab form the
/// derivation produces. A property carrying one of these names is prefixed so
/// the field keeps its concept without shadowing a system column.
const RESERVED_FIELD_IDS: &[&str] = &[
    "id",
    "record-id",
    "revision",
    "created-at",
    "updated-at",
    "deleted-at",
];

/// Text in one or more of the model's languages, keyed by language.
pub(crate) type Text = BTreeMap<String, String>;

/// A classification the project can assign, ordered from least to most
/// protected.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum Classification {
    Public,
    Internal,
    Restricted,
}

impl Classification {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "public" => Some(Self::Public),
            "internal" => Some(Self::Internal),
            "restricted" => Some(Self::Restricted),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Restricted => "restricted",
        }
    }
}

/// Facts about the model a project is derived from, carried into the
/// project's attribution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ModelFacts {
    pub display_name: &'static str,
    pub version: String,
    pub repository: String,
    pub license: String,
}

/// Everything the renderer writes, resolved and validated.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Plan {
    pub registry_id: String,
    pub registry_title: String,
    pub model: ModelFacts,
    pub entities: Vec<PlannedEntity>,
    /// The closed vocabularies at least one field draws from, in identifier
    /// order.
    pub vocabularies: Vec<PlannedVocabulary>,
    /// The highest classification any entity or field carries, which is what
    /// the Registry Manifest projection must be allowed to describe.
    pub classification_ceiling: Classification,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct PlannedEntity {
    pub id: String,
    pub route: String,
    pub concept: String,
    pub concept_uri: String,
    pub title: Text,
    pub description: Text,
    pub classification: Classification,
    /// The field that identifies a record: always generated, always required,
    /// always unique, because the model has no identifying property of its
    /// own and a registry needs one before its first record.
    pub identifier: PlannedField,
    pub fields: Vec<PlannedField>,
}

impl PlannedEntity {
    /// The identifier first, then the selected properties in selection order.
    pub(crate) fn all_fields(&self) -> impl Iterator<Item = &PlannedField> {
        std::iter::once(&self.identifier).chain(self.fields.iter())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct PlannedField {
    pub id: String,
    /// The property's name in the model, or the identifier's own name.
    pub property: String,
    pub concept_uri: Option<String>,
    pub title: Text,
    pub description: Text,
    pub classification: Classification,
    pub required: bool,
    pub kind: FieldKind,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum FieldKind {
    Boolean,
    String { min_length: u32, max_length: u32 },
    Int64,
    Decimal { precision: u8, scale: u8 },
    Date,
    Timestamp,
    VocabularyCode { vocabulary: String },
    Reference { target: String },
    Structured { max_bytes: u32, schema: Value },
}

impl FieldKind {
    /// True for the field types a listing may be filtered by in the generated
    /// grants.
    pub(crate) fn filterable(&self) -> bool {
        matches!(
            self,
            Self::VocabularyCode { .. } | Self::Reference { .. } | Self::String { .. }
        )
    }

    /// True for the field types the Registry Manifest describes with concept
    /// metadata; a reference carries relationship metadata instead, and a
    /// structured value is not representable there at all.
    pub(crate) fn manifest_scalar(&self) -> bool {
        !matches!(self, Self::Reference { .. } | Self::Structured { .. })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PlannedVocabulary {
    pub id: String,
    pub r#enum: String,
    pub scheme_iri: String,
    pub values: Vec<PlannedCode>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PlannedCode {
    pub code: String,
    pub iri: Option<String>,
    pub label: Text,
}

/// Resolves `selection` against `model`.
///
/// Every refusal names the selection path it concerns, so a reader editing a
/// selection file finds the line, and the wizard can turn the same sentence
/// into a prompt.
pub(crate) fn resolve(selection: &Selection, model: &Model) -> Result<Plan, Diagnostic> {
    let facts = model_facts(model)?;
    if let Some(version) = &selection.model_version {
        if version != &facts.version {
            return Err(diagnostic(
                "init.selection.model_version",
                "selection.modelVersion",
                &format!(
                    "the selection was written against {} {version}, and this bregctl embeds {} {}",
                    facts.display_name, facts.display_name, facts.version
                ),
            ));
        }
    }
    validate_identifier(
        &selection.registry.id,
        "selection.registry.id",
        "the registry identifier",
    )?;
    if selection.registry.title.trim().is_empty() {
        return Err(diagnostic(
            "init.selection.registry_title",
            "selection.registry.title",
            "the registry title must not be empty",
        ));
    }
    if selection.entities.is_empty() {
        return Err(diagnostic(
            "init.selection.entities",
            "selection.entities",
            "a selection names at least one concept",
        ));
    }

    let mut index = Vec::new();
    let mut ids = BTreeSet::new();
    let mut routes = BTreeSet::new();
    for entity in &selection.entities {
        let path = format!("selection.entities[{}]", entity.concept);
        let class = model.classes.get(&entity.concept).ok_or_else(|| {
            diagnostic(
                "init.selection.concept_unknown",
                &path,
                &format!(
                    "`{}` is not a concept of {} {}",
                    entity.concept, facts.display_name, facts.version
                ),
            )
        })?;
        if class.is_abstract {
            let concrete = model
                .concrete_descendants(&class.name)
                .map_err(|error| model_error(&path, &error))?;
            return Err(diagnostic(
                "init.selection.concept_abstract",
                &path,
                &format!(
                    "`{}` is abstract; select one of its concrete concepts instead: {}",
                    class.name,
                    names(concrete.iter().map(|class| class.name.as_str()))
                ),
            ));
        }
        let id = entity.id.clone().unwrap_or_else(|| kebab_case(&class.name));
        validate_identifier(&id, &format!("{path}.id"), "an entity identifier")?;
        if !ids.insert(id.clone()) {
            return Err(diagnostic(
                "init.selection.entity_duplicate",
                &format!("{path}.id"),
                &format!("entity identifier `{id}` is selected twice"),
            ));
        }
        let route = entity.route.clone().unwrap_or_else(|| pluralize(&id));
        validate_identifier(&route, &format!("{path}.route"), "a route")?;
        if !routes.insert(route.clone()) {
            return Err(diagnostic(
                "init.selection.route_duplicate",
                &format!("{path}.route"),
                &format!("route `{route}` is used by two entities"),
            ));
        }
        index.push(EntityIndex {
            id,
            route,
            class: class.name.clone(),
        });
    }

    let mut vocabulary_modes = BTreeMap::new();
    for vocabulary in &selection.vocabularies {
        let path = format!("selection.vocabularies[{}]", vocabulary.r#enum);
        if !model.enums.contains_key(&vocabulary.r#enum) {
            return Err(diagnostic(
                "init.selection.vocabulary_unknown",
                &path,
                &format!(
                    "`{}` is not an enumeration of {} {}",
                    vocabulary.r#enum, facts.display_name, facts.version
                ),
            ));
        }
        if vocabulary_modes
            .insert(vocabulary.r#enum.clone(), vocabulary.mode)
            .is_some()
        {
            return Err(diagnostic(
                "init.selection.vocabulary_duplicate",
                &path,
                &format!("enumeration `{}` is listed twice", vocabulary.r#enum),
            ));
        }
    }

    let mut entities = Vec::new();
    let mut enums = EnumUse::default();
    for (entity, entry) in selection.entities.iter().zip(&index) {
        entities.push(resolve_entity(
            entity,
            entry,
            model,
            &index,
            &vocabulary_modes,
            &mut enums,
        )?);
    }
    for name in vocabulary_modes.keys() {
        if !enums.drawn.contains(name) {
            return Err(diagnostic(
                "init.selection.vocabulary_unused",
                &format!("selection.vocabularies[{name}]"),
                &format!("no selected property draws from enumeration `{name}`"),
            ));
        }
    }

    let mut vocabularies = Vec::new();
    for name in &enums.inline {
        vocabularies.push(resolve_vocabulary(&model.enums[name])?);
    }
    vocabularies.sort_by(|left, right| left.id.cmp(&right.id));
    let mut seen = BTreeSet::new();
    for vocabulary in &vocabularies {
        if !seen.insert(vocabulary.id.as_str()) {
            return Err(diagnostic(
                "init.selection.vocabulary_collision",
                "selection.entities",
                &format!(
                    "two enumerations derive the same vocabulary identifier `{}`",
                    vocabulary.id
                ),
            ));
        }
    }

    let classification_ceiling = entities
        .iter()
        .flat_map(|entity| {
            std::iter::once(entity.classification)
                .chain(entity.all_fields().map(|field| field.classification))
        })
        .max()
        .unwrap_or(Classification::Internal);

    Ok(Plan {
        registry_id: selection.registry.id.clone(),
        registry_title: selection.registry.title.trim().to_owned(),
        model: facts,
        entities,
        vocabularies,
        classification_ceiling,
    })
}

/// The enumerations the selected properties draw from, by model name: every
/// one, and the ones carried as a closed vocabulary in the project.
#[derive(Default)]
struct EnumUse {
    drawn: BTreeSet<String>,
    inline: BTreeSet<String>,
}

/// The concept of every selected entity, which is what a reference resolves
/// against.
#[derive(Clone, Debug)]
struct EntityIndex {
    id: String,
    route: String,
    class: String,
}

fn resolve_entity(
    entity: &EntitySelection,
    entry: &EntityIndex,
    model: &Model,
    index: &[EntityIndex],
    vocabulary_modes: &BTreeMap<String, VocabularyMode>,
    enums: &mut EnumUse,
) -> Result<PlannedEntity, Diagnostic> {
    let path = format!("selection.entities[{}]", entity.concept);
    let class = &model.classes[&entry.class];
    let classification = match &entity.classification {
        None => Classification::Internal,
        Some(value) => Classification::parse(value).ok_or_else(|| {
            diagnostic(
                "init.selection.classification",
                &format!("{path}.classification"),
                &format!("`{value}` is not one of public, internal, restricted"),
            )
        })?,
    };
    let identifier_id = entity
        .identifier_field
        .clone()
        .unwrap_or_else(|| format!("{}-code", entry.id));
    validate_identifier(
        &identifier_id,
        &format!("{path}.identifierField"),
        "a field identifier",
    )?;
    let identifier = PlannedField {
        id: identifier_id.clone(),
        property: "identifier".to_owned(),
        concept_uri: model.slots.get("identifier").map(|slot| slot.uri.clone()),
        title: Text::from([("en".to_owned(), "Identifier".to_owned())]),
        description: Text::from([(
            "en".to_owned(),
            "The code that identifies a record in this registry; assigned by the registry, unique within the entity.".to_owned(),
        )]),
        classification: Classification::Internal,
        required: true,
        kind: FieldKind::String {
            min_length: 1,
            max_length: IDENTIFIER_MAX_LENGTH,
        },
    };

    let offered = model
        .induced_slots(&class.name)
        .map_err(|error| model_error(&path, &error))?;
    let mut fields = Vec::new();
    let mut field_ids = BTreeSet::from([identifier_id]);
    let mut properties = BTreeSet::new();
    for property in &entity.properties {
        let property_path = format!("{path}.properties[{}]", property.name);
        if !properties.insert(property.name.as_str()) {
            return Err(diagnostic(
                "init.selection.property_duplicate",
                &property_path,
                &format!("property `{}` is selected twice", property.name),
            ));
        }
        let slot = offered
            .iter()
            .copied()
            .find(|slot| slot.name == property.name)
            .ok_or_else(|| {
                diagnostic(
                    "init.selection.property_unknown",
                    &property_path,
                    &format!(
                        "`{}` is not a property of `{}`; it carries: {}",
                        property.name,
                        class.name,
                        names(offered.iter().map(|slot| slot.name.as_str()))
                    ),
                )
            })?;
        let kind =
            field_kind(model, slot, property, index, vocabulary_modes).map_err(|reason| {
                diagnostic(
                    "init.selection.property_unsupported",
                    &property_path,
                    &format!("`{}` cannot become a field: {reason}", slot.name),
                )
            })?;
        if let Range::Enum(name) = &slot.range {
            enums.drawn.insert(name.clone());
            if matches!(kind, FieldKind::VocabularyCode { .. }) {
                enums.inline.insert(name.clone());
            }
        }
        let id = field_id(&slot.name);
        if !field_ids.insert(id.clone()) {
            return Err(diagnostic(
                "init.selection.field_duplicate",
                &property_path,
                &format!("two fields of this entity would share the identifier `{id}`"),
            ));
        }
        let classification = match publicschema::sensitivity(slot)
            .map_err(|error| convention_error(&property_path, &error))?
        {
            Some(Sensitivity::Sensitive | Sensitivity::Restricted) => Classification::Restricted,
            None => Classification::Internal,
        };
        fields.push(PlannedField {
            id,
            property: slot.name.clone(),
            concept_uri: Some(slot.uri.clone()),
            title: labels(slot),
            description: descriptions(slot.description.as_deref(), &slot.annotations),
            classification,
            required: false,
            kind,
        });
    }

    let mut title = labels(class);
    if title.is_empty() {
        title.insert("en".to_owned(), class.name.clone());
    }
    Ok(PlannedEntity {
        id: entry.id.clone(),
        route: entry.route.clone(),
        concept: class.name.clone(),
        concept_uri: class.uri.clone(),
        title,
        description: descriptions(class.description.as_deref(), &class.annotations),
        classification,
        identifier,
        fields,
    })
}

/// The field type a property becomes, or the sentence saying why it cannot.
///
/// The sentence is the whole of the wizard's explanation too, so it says what
/// to do instead rather than only what was refused.
fn field_kind(
    model: &Model,
    slot: &SlotDef,
    property: &PropertySelection,
    index: &[EntityIndex],
    vocabulary_modes: &BTreeMap<String, VocabularyMode>,
) -> Result<FieldKind, String> {
    match &slot.range {
        Range::Type(name) => {
            if let Some(bespoke) = publicschema::bespoke_type(slot) {
                return bespoke_kind(bespoke, slot.multivalued);
            }
            let scalar = scalar_kind(name)?;
            if slot.multivalued {
                Ok(list_of(scalar_schema(name)?))
            } else {
                Ok(scalar)
            }
        }
        Range::Enum(name) => {
            let definition = &model.enums[name];
            if slot.multivalued {
                return Ok(list_of(enum_schema(definition)));
            }
            let inline = match vocabulary_modes.get(name) {
                Some(VocabularyMode::Inline) => true,
                Some(VocabularyMode::Code) => false,
                None => definition.values.len() <= INLINE_VOCABULARY_THRESHOLD,
            };
            if inline {
                Ok(FieldKind::VocabularyCode {
                    vocabulary: kebab_case(name),
                })
            } else {
                Ok(FieldKind::String {
                    min_length: 0,
                    max_length: CODE_MAX_LENGTH,
                })
            }
        }
        Range::Class(name) => {
            if slot.multivalued {
                return Err(format!(
                    "it holds many `{name}` values; model that relationship as its own entity carrying a reference back to this one"
                ));
            }
            let candidates: Vec<&EntityIndex> = index
                .iter()
                .filter(|entry| fits_range(model, &entry.class, name))
                .collect();
            if let Some(target) = &property.target {
                return candidates
                    .iter()
                    .find(|entry| &entry.id == target)
                    .map(|entry| FieldKind::Reference {
                        target: entry.id.clone(),
                    })
                    .ok_or_else(|| {
                        format!(
                            "target `{target}` is not a selected entity whose concept is `{name}` or one of its kinds"
                        )
                    });
            }
            match candidates.as_slice() {
                [] => {
                    let class = &model.classes[name];
                    object_schema(model, class)
                        .map(|schema| FieldKind::Structured {
                            max_bytes: OBJECT_MAX_BYTES,
                            schema,
                        })
                        .ok_or_else(|| {
                            format!(
                                "it refers to `{name}`, which is not selected and has no property that can be carried inline; select `{name}` as an entity to make this a reference"
                            )
                        })
                }
                [only] => Ok(FieldKind::Reference {
                    target: only.id.clone(),
                }),
                several => Err(format!(
                    "more than one selected entity fits `{name}`; name one with `target`: {}",
                    names(several.iter().map(|entry| entry.id.as_str()))
                )),
            }
        }
    }
}

/// True when a selected concept fits a property whose range is `range`: the
/// concept itself, or one of its kinds. A concept may refer to itself (a
/// location within a location), so the owning concept is a candidate like any
/// other.
pub(crate) fn fits_range(model: &Model, concept: &str, range: &str) -> bool {
    concept == range || model.is_subclass_of(concept, range).unwrap_or(false)
}

/// Whether a property can become a field of a project that selects
/// `concepts`, or the sentence saying why it cannot.
///
/// This is [`field_kind`] asked one property at a time, so the wizard offers
/// exactly what the resolver accepts. A reference that fits several selected
/// concepts is a question rather than a refusal: the answer becomes the
/// property's `target`.
pub(crate) fn property_support(
    model: &Model,
    slot: &SlotDef,
    concepts: &[String],
) -> Result<(), String> {
    let index: Vec<EntityIndex> = concepts
        .iter()
        .map(|concept| {
            let id = kebab_case(concept);
            EntityIndex {
                route: pluralize(&id),
                id,
                class: concept.clone(),
            }
        })
        .collect();
    if let Range::Class(range) = &slot.range {
        if !slot.multivalued
            && index
                .iter()
                .filter(|entry| fits_range(model, &entry.class, range))
                .count()
                > 1
        {
            return Ok(());
        }
    }
    let property = PropertySelection {
        name: slot.name.clone(),
        target: None,
    };
    field_kind(model, slot, &property, &index, &BTreeMap::new()).map(|_| ())
}

fn bespoke_kind(bespoke: &str, multivalued: bool) -> Result<FieldKind, String> {
    match bespoke {
        "geojson_geometry" if !multivalued => Ok(FieldKind::Structured {
            max_bytes: GEOMETRY_MAX_BYTES,
            schema: geometry_schema(),
        }),
        other => Err(format!("its value type `{other}` has no field type")),
    }
}

fn scalar_kind(name: &str) -> Result<FieldKind, String> {
    Ok(match name {
        "string" | "ncname" => FieldKind::String {
            min_length: 0,
            max_length: STRING_MAX_LENGTH,
        },
        "uri" | "uriorcurie" | "curie" => FieldKind::String {
            min_length: 0,
            max_length: URI_MAX_LENGTH,
        },
        "integer" => FieldKind::Int64,
        "boolean" => FieldKind::Boolean,
        "float" | "double" | "decimal" => FieldKind::Decimal {
            precision: DECIMAL_PRECISION,
            scale: DECIMAL_SCALE,
        },
        "date" => FieldKind::Date,
        "datetime" | "date_or_datetime" => FieldKind::Timestamp,
        other => return Err(format!("its value type `{other}` has no field type")),
    })
}

/// The JSON Schema of one scalar value inside a structured field.
fn scalar_schema(name: &str) -> Result<Value, String> {
    Ok(match name {
        "string" | "ncname" => json!({"type": "string", "maxLength": STRING_MAX_LENGTH}),
        "uri" | "uriorcurie" | "curie" => json!({"type": "string", "maxLength": URI_MAX_LENGTH}),
        "integer" => json!({"type": "integer"}),
        "boolean" => json!({"type": "boolean"}),
        "float" | "double" | "decimal" => json!({"type": "number"}),
        "date" | "datetime" | "date_or_datetime" | "time" => {
            json!({"type": "string", "maxLength": 64})
        }
        other => return Err(format!("its value type `{other}` has no field type")),
    })
}

fn enum_schema(definition: &EnumDef) -> Value {
    if definition.values.len() <= INLINE_VOCABULARY_THRESHOLD {
        let codes: Vec<&str> = definition
            .values
            .iter()
            .map(|value| value.text.as_str())
            .collect();
        json!({"type": "string", "enum": codes})
    } else {
        json!({"type": "string", "maxLength": CODE_MAX_LENGTH})
    }
}

fn list_of(items: Value) -> FieldKind {
    FieldKind::Structured {
        max_bytes: LIST_MAX_BYTES,
        schema: json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["values"],
            "properties": {
                "values": {"type": "array", "maxItems": LIST_MAX_ITEMS, "items": items}
            }
        }),
    }
}

/// The closed object schema carrying a concept inline: its scalar and
/// enumerated properties under the model's own names, nested concepts left
/// out. `None` when the concept has nothing scalar to carry.
fn object_schema(model: &Model, class: &ClassDef) -> Option<Value> {
    let slots = model.induced_slots(&class.name).ok()?;
    let mut properties = serde_json::Map::new();
    for slot in slots {
        let item = match &slot.range {
            Range::Type(name) => {
                if publicschema::bespoke_type(slot) == Some("geojson_geometry") {
                    geometry_schema()
                } else {
                    scalar_schema(name).ok()?
                }
            }
            Range::Enum(name) => enum_schema(&model.enums[name]),
            Range::Class(_) => continue,
        };
        let schema = if slot.multivalued {
            json!({"type": "array", "maxItems": LIST_MAX_ITEMS, "items": item})
        } else {
            item
        };
        properties.insert(slot.name.clone(), schema);
    }
    if properties.is_empty() {
        return None;
    }
    Some(json!({
        "type": "object",
        "additionalProperties": false,
        "properties": properties
    }))
}

fn geometry_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["type", "coordinates"],
        "properties": {
            "type": {
                "type": "string",
                "enum": ["Point", "LineString", "Polygon", "MultiPoint", "MultiLineString", "MultiPolygon"]
            },
            "coordinates": {"type": "array"}
        }
    })
}

fn resolve_vocabulary(definition: &EnumDef) -> Result<PlannedVocabulary, Diagnostic> {
    let path = format!("selection.vocabularies[{}]", definition.name);
    let mut values = Vec::new();
    for value in &definition.values {
        if value.text.is_empty()
            || value.text.len() > 128
            || value.text.chars().any(char::is_control)
        {
            return Err(diagnostic(
                "init.selection.vocabulary_value",
                &path,
                &format!(
                    "value `{}` of enumeration `{}` is not a code the compiler accepts",
                    value.text.escape_default(),
                    definition.name
                ),
            ));
        }
        values.push(PlannedCode {
            code: value.text.clone(),
            iri: value.meaning.clone(),
            label: labels(value),
        });
    }
    Ok(PlannedVocabulary {
        id: kebab_case(&definition.name),
        r#enum: definition.name.clone(),
        scheme_iri: definition.uri.clone(),
        values,
    })
}

pub(crate) fn model_facts(model: &Model) -> Result<ModelFacts, Diagnostic> {
    let pin = publicschema::pin().map_err(|error| {
        diagnostic(
            "init.model.pin",
            "model",
            &format!("the embedded model's pin record does not parse: {error}"),
        )
    })?;
    Ok(ModelFacts {
        display_name: "PublicSchema",
        version: model.version.clone().unwrap_or(pin.version),
        repository: pin.repository,
        license: pin.license,
    })
}

/// The labels of `item` in every language the model carries one for.
fn labels(item: &impl publicschema::Labeled) -> Text {
    LANGUAGES
        .iter()
        .filter_map(|language| {
            publicschema::label(item, language)
                .map(collapse_whitespace)
                .filter(|text| !text.is_empty())
                .map(|text| ((*language).to_owned(), text))
        })
        .collect()
}

/// The descriptions of a definition: `description` in English, the
/// `description_<lang>` annotations otherwise.
fn descriptions(english: Option<&str>, annotations: &BTreeMap<String, String>) -> Text {
    LANGUAGES
        .iter()
        .filter_map(|language| {
            let text = if *language == "en" {
                english
            } else {
                annotations
                    .get(&format!("description_{language}"))
                    .map(String::as_str)
            };
            text.map(collapse_whitespace)
                .filter(|text| !text.is_empty())
                .map(|text| ((*language).to_owned(), text))
        })
        .collect()
}

fn collapse_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A property name as a field identifier: the model's snake case in kebab
/// case, prefixed when it would shadow a name the compiler reserves.
pub(crate) fn field_id(property: &str) -> String {
    let id = kebab_case(property);
    if RESERVED_FIELD_IDS.contains(&id.as_str()) {
        format!("declared-{id}")
    } else {
        id
    }
}

/// `ServicePoint` to `service-point`, `given_name` to `given-name`,
/// `IDDocument` to `id-document`.
pub(crate) fn kebab_case(name: &str) -> String {
    let characters: Vec<char> = name.chars().collect();
    let mut result = String::new();
    for (position, character) in characters.iter().enumerate() {
        if *character == '_' || *character == '-' || character.is_whitespace() {
            if !result.ends_with('-') && !result.is_empty() {
                result.push('-');
            }
            continue;
        }
        if character.is_uppercase() && position > 0 {
            let previous = characters[position - 1];
            let next_is_lower = characters
                .get(position + 1)
                .is_some_and(|next| next.is_lowercase());
            let boundary = previous.is_lowercase()
                || previous.is_ascii_digit()
                || (previous.is_uppercase() && next_is_lower);
            if boundary && !result.ends_with('-') {
                result.push('-');
            }
        }
        result.extend(character.to_lowercase());
    }
    result
}

/// A collection route from an entity identifier.
pub(crate) fn pluralize(id: &str) -> String {
    if id.ends_with('s')
        || id.ends_with('x')
        || id.ends_with('z')
        || id.ends_with("ch")
        || id.ends_with("sh")
    {
        format!("{id}es")
    } else if let Some(stem) = id.strip_suffix('y') {
        let vowel_before = stem
            .chars()
            .last()
            .is_some_and(|character| "aeiou".contains(character));
        if vowel_before {
            format!("{id}s")
        } else {
            format!("{stem}ies")
        }
    } else {
        format!("{id}s")
    }
}

/// The identifier grammar the compiler applies to registry, entity, field,
/// and route identifiers alike.
fn validate_identifier(value: &str, path: &str, what: &str) -> Result<(), Diagnostic> {
    match identifier_refusal(value, what) {
        None => Ok(()),
        Some(message) => Err(diagnostic("init.selection.identifier", path, &message)),
    }
}

/// The sentence refusing `value` as an identifier, or `None` when the grammar
/// accepts it. The wizard shows the same sentence inline, so a typed answer
/// is corrected at the prompt rather than after the project is derived.
pub(crate) fn identifier_refusal(value: &str, what: &str) -> Option<String> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        });
    if valid {
        None
    } else {
        Some(format!(
            "`{value}` is not valid as {what}: use 1 to 64 characters, starting with a lowercase letter, from a-z, 0-9, `-`, and `_`"
        ))
    }
}

fn names<'a>(items: impl Iterator<Item = &'a str>) -> String {
    let mut names: Vec<&str> = items.collect();
    names.sort_unstable();
    names.join(", ")
}

pub(crate) fn model_error(path: &str, error: &registry_linkml::ModelError) -> Diagnostic {
    diagnostic(
        "init.model.invalid",
        path,
        &format!("the embedded model is not usable: {error}"),
    )
}

pub(crate) fn convention_error(path: &str, error: &publicschema::ConventionError) -> Diagnostic {
    diagnostic(
        "init.model.invalid",
        path,
        &format!("the embedded model is not usable: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::*;

    fn model() -> &'static Model {
        static MODEL: OnceLock<Model> = OnceLock::new();
        MODEL.get_or_init(|| publicschema::model().expect("the snapshot reads"))
    }

    fn selection(body: &str) -> Selection {
        let document = format!(
            "apiVersion: registry.registrystack.org/breg-model-selection/v1alpha1\n\
             kind: ModelSelection\n\
             model: publicschema\n\
             registry:\n  id: example\n  title: Example\n\
             {body}"
        );
        Selection::parse("test", document.as_bytes()).expect("the selection parses")
    }

    fn resolved(body: &str) -> Plan {
        resolve(&selection(body), model()).expect("the selection resolves")
    }

    fn refused(body: &str) -> Diagnostic {
        resolve(&selection(body), model()).expect_err("the selection is refused")
    }

    fn field<'a>(plan: &'a Plan, entity: &str, id: &str) -> &'a PlannedField {
        plan.entities
            .iter()
            .find(|candidate| candidate.id == entity)
            .unwrap_or_else(|| panic!("entity {entity}"))
            .all_fields()
            .find(|candidate| candidate.id == id)
            .unwrap_or_else(|| panic!("field {entity}.{id}"))
    }

    #[test]
    fn the_household_starter_resolves_to_three_entities() {
        let starter = publicschema::starters()
            .iter()
            .find(|starter| starter.name == "household")
            .expect("ships");
        let selection = Selection::parse("starter", starter.contents.as_bytes()).expect("parses");
        let plan = resolve(&selection, model()).expect("resolves");
        assert_eq!(plan.registry_id, "household-registry");
        assert_eq!(plan.model.display_name, "PublicSchema");
        assert_eq!(plan.model.version, "0.3.0");
        assert!(!plan.model.repository.is_empty());
        assert!(!plan.model.license.is_empty());
        let ids: Vec<&str> = plan
            .entities
            .iter()
            .map(|entity| entity.id.as_str())
            .collect();
        assert_eq!(ids, ["person", "household", "group-membership"]);
        let routes: Vec<&str> = plan
            .entities
            .iter()
            .map(|entity| entity.route.as_str())
            .collect();
        assert_eq!(routes, ["persons", "households", "group-memberships"]);
        assert_eq!(plan.entities[0].identifier.id, "person-code");
        assert_eq!(plan.entities[0].identifier.property, "identifier");
        assert_eq!(
            plan.entities[0].identifier.concept_uri.as_deref(),
            Some("https://publicschema.org/identifier")
        );
        assert_eq!(plan.entities[0].title["fr"], "Personne");
        assert_eq!(
            plan.entities[0].concept_uri,
            "https://publicschema.org/Person"
        );
        assert_eq!(
            field(&plan, "group-membership", "person").kind,
            FieldKind::Reference {
                target: "person".to_owned()
            }
        );
        assert_eq!(
            field(&plan, "group-membership", "group").kind,
            FieldKind::Reference {
                target: "household".to_owned()
            }
        );
        let vocabularies: Vec<&str> = plan
            .vocabularies
            .iter()
            .map(|vocabulary| vocabulary.id.as_str())
            .collect();
        assert_eq!(
            vocabularies,
            [
                "food-security-level",
                "group-role",
                "group-type",
                "marital-status",
                "sex"
            ]
        );
        assert_eq!(plan.classification_ceiling, Classification::Restricted);
    }

    #[test]
    fn a_large_enumeration_becomes_a_bounded_code_unless_the_selection_inlines_it() {
        let plan = resolved(
            "entities:\n  - concept: Person\n    properties:\n      - name: preferred_language\n",
        );
        assert_eq!(
            field(&plan, "person", "preferred-language").kind,
            FieldKind::String {
                min_length: 0,
                max_length: CODE_MAX_LENGTH
            }
        );
        assert!(plan.vocabularies.is_empty());
        let plan = resolved(
            "entities:\n  - concept: Person\n    properties:\n      - name: preferred_language\n\
             vocabularies:\n  - enum: Language\n    mode: inline\n",
        );
        assert_eq!(
            field(&plan, "person", "preferred-language").kind,
            FieldKind::VocabularyCode {
                vocabulary: "language".to_owned()
            }
        );
        assert!(plan.vocabularies[0].values.len() > INLINE_VOCABULARY_THRESHOLD);
    }

    #[test]
    fn a_small_enumeration_becomes_a_code_when_the_selection_says_so() {
        let plan = resolved(
            "entities:\n  - concept: Person\n    properties:\n      - name: sex\n\
             vocabularies:\n  - enum: Sex\n    mode: code\n",
        );
        assert_eq!(
            field(&plan, "person", "sex").kind,
            FieldKind::String {
                min_length: 0,
                max_length: CODE_MAX_LENGTH
            }
        );
        assert!(plan.vocabularies.is_empty());
    }

    #[test]
    fn a_vocabulary_override_no_property_draws_from_is_refused() {
        let error = refused(
            "entities:\n  - concept: Person\n    properties:\n      - name: sex\n\
             vocabularies:\n  - enum: Language\n    mode: inline\n",
        );
        assert_eq!(error.code, "init.selection.vocabulary_unused");
        let error = refused(
            "entities:\n  - concept: Person\n    properties:\n      - name: sex\n\
             vocabularies:\n  - enum: Colour\n    mode: inline\n",
        );
        assert_eq!(error.code, "init.selection.vocabulary_unknown");
    }

    #[test]
    fn sensitivity_becomes_a_restricted_field_and_the_ceiling_follows() {
        let plan = resolved(
            "entities:\n  - concept: Person\n    properties:\n      - name: given_name\n      - name: marital_status\n",
        );
        assert_eq!(
            field(&plan, "person", "given-name").classification,
            Classification::Internal
        );
        assert_eq!(
            field(&plan, "person", "marital-status").classification,
            Classification::Restricted
        );
        assert_eq!(plan.classification_ceiling, Classification::Restricted);
        let plan =
            resolved("entities:\n  - concept: Person\n    properties:\n      - name: given_name\n");
        assert_eq!(plan.classification_ceiling, Classification::Internal);
    }

    #[test]
    fn an_entity_classification_is_taken_from_the_selection_and_checked() {
        let plan = resolved(
            "entities:\n  - concept: Person\n    classification: restricted\n    properties:\n      - name: given_name\n",
        );
        assert_eq!(plan.entities[0].classification, Classification::Restricted);
        let error = refused(
            "entities:\n  - concept: Person\n    classification: secret\n    properties:\n      - name: given_name\n",
        );
        assert_eq!(error.code, "init.selection.classification");
    }

    #[test]
    fn an_unselected_value_concept_becomes_a_closed_structured_object() {
        let plan =
            resolved("entities:\n  - concept: Household\n    properties:\n      - name: address\n");
        let FieldKind::Structured { max_bytes, schema } =
            &field(&plan, "household", "address").kind
        else {
            panic!("address is structured");
        };
        assert_eq!(*max_bytes, OBJECT_MAX_BYTES);
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["properties"]["city"]["type"], "string");
        assert!(
            schema["properties"]["location"].is_null(),
            "nested concepts are left out"
        );
        assert!(schema["properties"]["country"]["enum"].is_array());
    }

    #[test]
    fn a_concept_valued_property_becomes_a_reference_once_the_concept_is_selected() {
        let plan = resolved(
            "entities:\n  - concept: Household\n    properties:\n      - name: address\n  - concept: Address\n    properties:\n      - name: city\n",
        );
        assert_eq!(
            field(&plan, "household", "address").kind,
            FieldKind::Reference {
                target: "address".to_owned()
            }
        );
    }

    #[test]
    fn a_reference_with_several_fitting_entities_needs_a_target() {
        let body = "entities:\n  - concept: Person\n    id: adult\n    properties:\n      - name: given_name\n  - concept: Person\n    id: child\n    properties:\n      - name: given_name\n  - concept: GroupMembership\n    properties:\n      - name: person";
        let error = refused(&format!("{body}\n"));
        assert_eq!(error.code, "init.selection.property_unsupported");
        assert!(error.message.contains("adult, child"), "{}", error.message);
        let plan = resolved(&format!("{body}\n        target: child\n"));
        assert_eq!(
            field(&plan, "group-membership", "person").kind,
            FieldKind::Reference {
                target: "child".to_owned()
            }
        );
        let error = refused(&format!("{body}\n        target: household\n"));
        assert_eq!(error.code, "init.selection.property_unsupported");
    }

    #[test]
    fn a_property_holding_many_concepts_is_refused_with_the_way_out() {
        let error =
            refused("entities:\n  - concept: Location\n    properties:\n      - name: geocodes\n");
        assert_eq!(error.code, "init.selection.property_unsupported");
        assert!(
            error.message.contains("as its own entity"),
            "{}",
            error.message
        );
    }

    #[test]
    fn a_geometry_becomes_a_structured_field_and_a_coordinate_a_decimal() {
        let plan = resolved(
            "entities:\n  - concept: Location\n    properties:\n      - name: geometry\n      - name: latitude\n      - name: administrative_level\n",
        );
        let FieldKind::Structured { max_bytes, schema } =
            &field(&plan, "location", "geometry").kind
        else {
            panic!("geometry is structured");
        };
        assert_eq!(*max_bytes, GEOMETRY_MAX_BYTES);
        assert_eq!(schema["required"], json!(["type", "coordinates"]));
        assert_eq!(
            field(&plan, "location", "latitude").kind,
            FieldKind::Decimal {
                precision: DECIMAL_PRECISION,
                scale: DECIMAL_SCALE
            }
        );
        assert_eq!(
            field(&plan, "location", "administrative-level").kind,
            FieldKind::Int64
        );
    }

    #[test]
    fn an_unknown_property_names_what_the_concept_carries() {
        let error =
            refused("entities:\n  - concept: Person\n    properties:\n      - name: shoe_size\n");
        assert_eq!(error.code, "init.selection.property_unknown");
        assert!(error.message.contains("given_name"), "{}", error.message);
    }

    #[test]
    fn an_abstract_concept_is_refused_with_its_concrete_descendants() {
        let error = refused("entities:\n  - concept: Group\n    properties:\n      - name: name\n");
        assert_eq!(error.code, "init.selection.concept_abstract");
        assert!(error.message.contains("Household"), "{}", error.message);
        let error = refused("entities:\n  - concept: Widget\n");
        assert_eq!(error.code, "init.selection.concept_unknown");
    }

    #[test]
    fn identifiers_and_routes_are_validated_and_unique() {
        assert_eq!(
            refused("entities:\n  - concept: Person\n    id: Person\n").code,
            "init.selection.identifier"
        );
        assert_eq!(
            refused("entities:\n  - concept: Person\n  - concept: Person\n").code,
            "init.selection.entity_duplicate"
        );
        assert_eq!(
            refused("entities:\n  - concept: Person\n    route: people\n  - concept: Household\n    route: people\n").code,
            "init.selection.route_duplicate"
        );
        assert_eq!(
            refused("entities:\n  - concept: Person\n    properties:\n      - name: sex\n      - name: sex\n").code,
            "init.selection.property_duplicate"
        );
        assert_eq!(refused("entities: []\n").code, "init.selection.entities");
        let plan = resolved(
            "entities:\n  - concept: Person\n    id: citizen\n    route: citizenry\n    identifierField: national-number\n",
        );
        assert_eq!(plan.entities[0].id, "citizen");
        assert_eq!(plan.entities[0].route, "citizenry");
        assert_eq!(plan.entities[0].identifier.id, "national-number");
    }

    #[test]
    fn a_model_version_pin_must_match_the_snapshot() {
        let mut selection = selection("entities:\n  - concept: Person\n");
        selection.model_version = Some("0.0.1".to_owned());
        let error = resolve(&selection, model()).expect_err("refused");
        assert_eq!(error.code, "init.selection.model_version");
        selection.model_version = Some(model().version.clone().expect("the snapshot is versioned"));
        assert!(resolve(&selection, model()).is_ok());
    }

    #[test]
    fn names_are_derived_in_kebab_case_and_pluralized() {
        assert_eq!(kebab_case("ServicePoint"), "service-point");
        assert_eq!(kebab_case("given_name"), "given-name");
        assert_eq!(kebab_case("IDDocument"), "id-document");
        assert_eq!(kebab_case("CRVSPerson"), "crvs-person");
        assert_eq!(kebab_case("Level 2 Area"), "level-2-area");
        assert_eq!(pluralize("person"), "persons");
        assert_eq!(pluralize("address"), "addresses");
        assert_eq!(pluralize("facility"), "facilities");
        assert_eq!(pluralize("survey"), "surveys");
        assert_eq!(pluralize("match"), "matches");
        assert_eq!(field_id("id"), "declared-id");
        assert_eq!(field_id("created_at"), "declared-created-at");
        assert_eq!(field_id("family_name"), "family-name");
    }
}
