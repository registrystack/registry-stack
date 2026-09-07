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

use registry_breg::logical_names::{default_api_name, default_sql_name, reserved_logical_name};
use registry_breg::Diagnostic;
use registry_linkml::publicschema::{self, Sensitivity, LANGUAGES};
use registry_linkml::{ClassDef, EnumDef, Model, Range, SlotDef};
use registry_manifest_core::MAX_CODELIST_CONCEPTS;
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
/// The longest code a closed vocabulary accepts, which is the compiler's bound.
const VOCABULARY_CODE_MAX_LENGTH: u32 = 128;
const URI_MAX_LENGTH: u32 = 2048;
const IDENTIFIER_MAX_LENGTH: u32 = 64;
const LIST_MAX_ITEMS: u32 = 50;
const LIST_MAX_BYTES: u32 = 4096;
const OBJECT_MAX_BYTES: u32 = 16384;
const GEOMETRY_MAX_BYTES: u32 = 65536;
const TEMPORAL_MAX_LENGTH: u32 = 64;
/// A calendar date, as the compiler's own date type accepts it.
const DATE_PATTERN: &str = r"^\d{4}-\d{2}-\d{2}$";
/// A date and time with an offset, as the compiler's timestamp type accepts
/// it.
const TIMESTAMP_PATTERN: &str =
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$";
/// A time of day, with an optional offset.
const TIME_PATTERN: &str = r"^\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})?$";
const DECIMAL_PRECISION: u8 = 18;
const DECIMAL_SCALE: u8 = 6;

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
    pub license_url: String,
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
    /// The concepts of the model that were not selected and would connect
    /// the selected ones, for the README to name beside an entity nothing
    /// links.
    pub connectors: Vec<Connector>,
}

impl Plan {
    /// The entities no reference field connects to another entity, in plan
    /// order. Empty when the plan has one entity, since there is nothing to
    /// link it to.
    pub(crate) fn unlinked_entities(&self) -> Vec<&str> {
        if self.entities.len() < 2 {
            return Vec::new();
        }
        let targeted: BTreeSet<&str> = self
            .entities
            .iter()
            .flat_map(|entity| {
                entity
                    .fields
                    .iter()
                    .filter_map(move |field| outward_target(entity, field))
            })
            .collect();
        self.entities
            .iter()
            .filter(|entity| {
                !targeted.contains(entity.id.as_str())
                    && !entity
                        .fields
                        .iter()
                        .any(|field| outward_target(entity, field).is_some())
            })
            .map(|entity| entity.id.as_str())
            .collect()
    }
}

/// The entity a reference field points at, unless it points back at the
/// entity carrying it. A self-reference joins two records of one entity, so
/// it neither links that entity to another nor makes another reachable.
fn outward_target<'a>(entity: &'a PlannedEntity, field: &'a PlannedField) -> Option<&'a str> {
    match &field.kind {
        FieldKind::Reference { target } if target != &entity.id => Some(target.as_str()),
        _ => None,
    }
}

/// A concept that was not selected and refers, through single-valued
/// properties, to two of the selected concepts, so that selecting it too
/// would connect them: a membership between a person and a group, say. When
/// one concept is selected, two references to it connect two of its records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Connector {
    pub concept: String,
    /// The referring properties, in name order.
    pub links: Vec<ConnectorLink>,
}

impl Connector {
    /// True when every reference fits exactly one selected concept, so the
    /// links need no further answer.
    pub(crate) fn settled(&self) -> bool {
        self.links.iter().all(|link| link.fits.len() == 1)
    }
}

/// One reference a connector carries, and the selected concepts it fits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConnectorLink {
    pub property: String,
    /// In selection order, each concept once.
    pub fits: Vec<String>,
}

/// The connectors of `concepts` among the concepts not in it: the settled
/// ones first, then by name.
pub(crate) fn connectors(model: &Model, concepts: &[String]) -> Result<Vec<Connector>, Diagnostic> {
    let selected: BTreeSet<&str> = concepts.iter().map(String::as_str).collect();
    let mut found = Vec::new();
    for class in model.classes.values() {
        if class.is_abstract || concepts.contains(&class.name) {
            continue;
        }
        let slots = model
            .induced_slots(&class.name)
            .map_err(|error| model_error("model", &error))?;
        let mut links = Vec::new();
        for slot in slots {
            let Range::Class(range) = &slot.range else {
                continue;
            };
            if slot.multivalued {
                continue;
            }
            let mut fits: Vec<String> = Vec::new();
            for concept in concepts {
                if fits_range(model, concept, range) && !fits.contains(concept) {
                    fits.push(concept.clone());
                }
            }
            if !fits.is_empty() {
                links.push(ConnectorLink {
                    property: slot.name.clone(),
                    fits,
                });
            }
        }
        // Counting references is not enough: two references that fit the
        // same one concept leave the others as far apart as before.
        let reached: BTreeSet<&str> = links
            .iter()
            .flat_map(|link| link.fits.iter().map(String::as_str))
            .collect();
        if links.len() < 2 || reached.len() < selected.len().min(2) {
            continue;
        }
        links.sort_by(|left, right| left.property.cmp(&right.property));
        found.push(Connector {
            concept: class.name.clone(),
            links,
        });
    }
    found.sort_by(|left, right| {
        (!left.settled(), &left.concept).cmp(&(!right.settled(), &right.concept))
    });
    Ok(found)
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
    if let Some(message) = registry_identifier_refusal(&selection.registry.id) {
        return Err(diagnostic(
            "init.selection.identifier",
            "selection.registry.id",
            &message,
        ));
    }
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
    for (name, mode) in &vocabulary_modes {
        if !enums.drawn.contains(name) {
            return Err(diagnostic(
                "init.selection.vocabulary_unused",
                &format!("selection.vocabularies[{name}]"),
                &format!("no selected property draws from enumeration `{name}`"),
            ));
        }
        let values = model.enums[name].values.len();
        if *mode == VocabularyMode::Inline && values > MAX_CODELIST_CONCEPTS {
            return Err(diagnostic(
                "init.selection.vocabulary_size",
                &format!("selection.vocabularies[{name}]"),
                &format!(
                    "enumeration `{name}` has {values} values, and a project carries at most \
                     {MAX_CODELIST_CONCEPTS} of them; drop the `inline` override to carry the \
                     code without listing the values"
                ),
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

    let concepts: Vec<String> = selection
        .entities
        .iter()
        .map(|entity| entity.concept.clone())
        .collect();
    let connectors = connectors(model, &concepts)?;

    Ok(Plan {
        registry_id: selection.registry.id.clone(),
        registry_title: selection.registry.title.trim().to_owned(),
        model: facts,
        entities,
        vocabularies,
        classification_ceiling,
        connectors,
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
    if reserved_field_id(&identifier_id) {
        return Err(diagnostic(
            "init.selection.field_reserved",
            &format!("{path}.identifierField"),
            &format!(
                "`{identifier_id}` is a name the compiler keeps for a system column of every \
                 record; name the identifying field something else"
            ),
        ));
    }
    let identifier = PlannedField {
        id: identifier_id.clone(),
        property: "identifier".to_owned(),
        concept_uri: model.slots.get("identifier").map(|slot| slot.uri.clone()),
        title: Text::from([("en".to_owned(), "Identifier".to_owned())]),
        description: Text::from([(
            "en".to_owned(),
            "The code that identifies a record in this registry; supplied by the caller when the record is created, unique within the entity.".to_owned(),
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
    let mut field_ids = BTreeSet::from([identifier_id.clone()]);
    let mut api_names = BTreeSet::from([default_api_name(&identifier_id)]);
    let mut sql_names = BTreeSet::from([default_sql_name(&identifier_id)]);
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
        if property.target.is_some() && !matches!(slot.range, Range::Class(_)) {
            return Err(diagnostic(
                "init.selection.property_target",
                &property_path,
                &format!(
                    "`target` names the selected entity a reference points at, and `{}` does not \
                     hold records of a concept",
                    slot.name
                ),
            ));
        }
        let ResolvedKind {
            kind,
            classification: floor,
        } = field_kind(model, slot, property, index, vocabulary_modes).map_err(|reason| {
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
        // The compiler derives an API name and a SQL name from every field
        // identifier and holds each to be unique within the entity, so two
        // identifiers that differ only in their separators collide there.
        let api_name = default_api_name(&id);
        if !api_names.insert(api_name.clone()) || !sql_names.insert(default_sql_name(&id)) {
            return Err(diagnostic(
                "init.selection.field_name_collision",
                &property_path,
                &format!(
                    "two fields of this entity would derive the same API name `{api_name}` from \
                     their identifiers"
                ),
            ));
        }
        let classification = slot_classification(slot)
            .map_err(|error| convention_error(&property_path, &error))?
            .max(floor);
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
) -> Result<ResolvedKind, String> {
    let kind = match &slot.range {
        Range::Type(name) => {
            if let Some(bespoke) = publicschema::bespoke_type(slot) {
                return bespoke_kind(bespoke, slot.multivalued).map(ResolvedKind::internal);
            }
            let scalar = scalar_kind(name)?;
            if slot.multivalued {
                list_of(scalar_schema(name)?)
            } else {
                scalar
            }
        }
        Range::Enum(name) => {
            let definition = &model.enums[name];
            let inline = match vocabulary_modes.get(name) {
                Some(VocabularyMode::Inline) => true,
                Some(VocabularyMode::Code) => false,
                None => definition.values.len() <= INLINE_VOCABULARY_THRESHOLD,
            };
            if slot.multivalued {
                list_of(enum_schema(definition, inline))
            } else if inline {
                FieldKind::VocabularyCode {
                    vocabulary: kebab_case(name),
                }
            } else {
                FieldKind::String {
                    min_length: 0,
                    max_length: code_max_length(definition),
                }
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
                    .map(|entry| {
                        ResolvedKind::internal(FieldKind::Reference {
                            target: entry.id.clone(),
                        })
                    })
                    .ok_or_else(|| {
                        format!(
                            "target `{target}` is not a selected entity whose concept is `{name}` or one of its kinds"
                        )
                    });
            }
            match candidates.as_slice() {
                [] => {
                    // The concept is carried inline, so the field holds every
                    // scalar property of it, including the ones the model
                    // protects, and is classified for the most protected.
                    let class = &model.classes[name];
                    return object_schema(model, class)
                        .map(|object| ResolvedKind {
                            kind: FieldKind::Structured {
                                max_bytes: OBJECT_MAX_BYTES,
                                schema: object.schema,
                            },
                            classification: object.classification,
                        })
                        .ok_or_else(|| {
                            format!(
                                "it refers to `{name}`, which is not selected and has no property that can be carried inline; select `{name}` as an entity to make this a reference"
                            )
                        });
                }
                [only] => FieldKind::Reference {
                    target: only.id.clone(),
                },
                several => {
                    return Err(format!(
                        "more than one selected entity fits `{name}`; name one with `target`: {}",
                        names(several.iter().map(|entry| entry.id.as_str()))
                    ))
                }
            }
        }
    };
    Ok(ResolvedKind::internal(kind))
}

/// A field type together with the lowest classification the field may carry
/// on account of what it holds, which the property's own annotation may only
/// raise.
struct ResolvedKind {
    kind: FieldKind,
    classification: Classification,
}

impl ResolvedKind {
    /// A field whose classification is left to its own annotation.
    fn internal(kind: FieldKind) -> Self {
        Self {
            kind,
            classification: Classification::Internal,
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
        "date" => temporal_schema(DATE_PATTERN),
        "datetime" => temporal_schema(TIMESTAMP_PATTERN),
        "date_or_datetime" => temporal_schema(&format!("{DATE_PATTERN}|{TIMESTAMP_PATTERN}")),
        "time" => temporal_schema(TIME_PATTERN),
        other => return Err(format!("its value type `{other}` has no field type")),
    })
}

/// The schema of one temporal value inside a structured field. The compiler
/// checks a structured value against its schema without asserting `format`,
/// so the shape a value type carries is written as a pattern instead.
fn temporal_schema(pattern: &str) -> Value {
    json!({"type": "string", "maxLength": TEMPORAL_MAX_LENGTH, "pattern": pattern})
}

/// The schema of one value of `definition`: every code listed, or a bounded
/// code alone.
fn enum_schema(definition: &EnumDef, inline: bool) -> Value {
    if inline {
        let codes: Vec<&str> = definition
            .values
            .iter()
            .map(|value| value.text.as_str())
            .collect();
        json!({"type": "string", "enum": codes})
    } else {
        json!({"type": "string", "maxLength": code_max_length(definition)})
    }
}

/// The bound of a field carrying a code of `definition` alone: at least
/// [`CODE_MAX_LENGTH`], and long enough for the enumeration's longest code,
/// within the bound a closed vocabulary's codes are held to.
fn code_max_length(definition: &EnumDef) -> u32 {
    definition
        .values
        .iter()
        .map(|value| value.text.len() as u32)
        .max()
        .unwrap_or(0)
        .clamp(CODE_MAX_LENGTH, VOCABULARY_CODE_MAX_LENGTH)
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

/// A concept carried inline: the closed object schema of its scalar and
/// enumerated properties under the model's own names, nested concepts left
/// out, and the classification the most protected of those properties earns.
struct InlineObject {
    schema: Value,
    classification: Classification,
}

/// `None` when the concept has nothing scalar to carry.
fn object_schema(model: &Model, class: &ClassDef) -> Option<InlineObject> {
    let slots = model.induced_slots(&class.name).ok()?;
    let mut properties = serde_json::Map::new();
    let mut classification = Classification::Internal;
    for slot in slots {
        let item = match &slot.range {
            Range::Type(name) => {
                if publicschema::bespoke_type(slot) == Some("geojson_geometry") {
                    geometry_schema()
                } else {
                    scalar_schema(name).ok()?
                }
            }
            Range::Enum(name) => {
                let definition = &model.enums[name];
                enum_schema(
                    definition,
                    definition.values.len() <= INLINE_VOCABULARY_THRESHOLD,
                )
            }
            Range::Class(_) => continue,
        };
        classification = classification.max(slot_classification(slot).ok()?);
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
    Some(InlineObject {
        schema: json!({
            "type": "object",
            "additionalProperties": false,
            "properties": properties
        }),
        classification,
    })
}

/// The classification a property's own sensitivity earns.
fn slot_classification(slot: &SlotDef) -> Result<Classification, publicschema::ConventionError> {
    Ok(match publicschema::sensitivity(slot)? {
        Some(Sensitivity::Sensitive | Sensitivity::Restricted) => Classification::Restricted,
        None => Classification::Internal,
    })
}

/// The schema of a GeoJSON geometry: the object shape every geometry shares,
/// and one branch per geometry type carrying the coordinate nesting that type
/// requires, so a well-formed object holding coordinates of the wrong shape is
/// refused with the rest.
fn geometry_schema() -> Value {
    let position = json!({
        "type": "array",
        "minItems": 2,
        "maxItems": 3,
        "items": {"type": "number"}
    });
    let line = json!({"type": "array", "minItems": 2, "items": position.clone()});
    let ring = json!({"type": "array", "minItems": 4, "items": position.clone()});
    let polygon = json!({"type": "array", "minItems": 1, "items": ring});
    let shapes = [
        ("Point", position.clone()),
        ("MultiPoint", json!({"type": "array", "items": position})),
        ("LineString", line.clone()),
        ("MultiLineString", json!({"type": "array", "items": line})),
        ("Polygon", polygon.clone()),
        ("MultiPolygon", json!({"type": "array", "items": polygon})),
    ];
    let types: Vec<&str> = shapes.iter().map(|(name, _)| *name).collect();
    let branches: Vec<Value> = shapes
        .iter()
        .map(|(name, coordinates)| {
            json!({
                "additionalProperties": false,
                "properties": {
                    "type": {"const": name},
                    "coordinates": coordinates
                }
            })
        })
        .collect();
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["type", "coordinates"],
        "properties": {
            "type": {"type": "string", "enum": types},
            "coordinates": {"type": "array"}
        },
        "oneOf": branches
    })
}

fn resolve_vocabulary(definition: &EnumDef) -> Result<PlannedVocabulary, Diagnostic> {
    let path = format!("selection.vocabularies[{}]", definition.name);
    let mut values = Vec::new();
    for value in &definition.values {
        if value.text.is_empty()
            || value.text.len() > VOCABULARY_CODE_MAX_LENGTH as usize
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
        license_url: pin.license_url,
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
    if reserved_field_id(&id) {
        format!("declared-{id}")
    } else {
        id
    }
}

/// True when the compiler reserves one of the logical names it derives from
/// `id`, so a field carrying it would shadow a system column.
fn reserved_field_id(id: &str) -> bool {
    reserved_logical_name(&default_api_name(id)) || reserved_logical_name(&default_sql_name(id))
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

/// The suffixes the renderer appends to the registry identifier to name the
/// publisher, the data service, the public service, and the two principals,
/// each of which the compiler holds to the same grammar as the identifier
/// itself.
const DERIVED_REGISTRY_SUFFIXES: &[(&str, &str)] = &[
    ("-authority", "the publisher identifier"),
    ("-api", "the data service identifier"),
    ("-service", "the public service identifier"),
    ("-operator", "the operator principal"),
    ("-reader", "the reader principal"),
];

/// The sentence refusing `value` as the registry identifier, or `None` when
/// it and every name derived from it fit the grammar. Checked before anything
/// is written, because the derived names are only otherwise checked by the
/// compiler, after the destination exists.
pub(crate) fn registry_identifier_refusal(value: &str) -> Option<String> {
    if let Some(message) = identifier_refusal(value, "the registry identifier") {
        return Some(message);
    }
    DERIVED_REGISTRY_SUFFIXES.iter().find_map(|(suffix, what)| {
        identifier_refusal(&format!("{value}{suffix}"), what).map(|message| {
            format!("{message}; the project derives it from the registry identifier")
        })
    })
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

    /// Whether `schema` accepts `value` under the options the compiler
    /// checks a structured value with, which do not assert `format`.
    fn accepts(schema: &Value, value: Value) -> bool {
        jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(schema)
            .expect("the schema compiles")
            .is_valid(&value)
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
            "entities:\n  - concept: Person\n    properties:\n      - name: occupation\n\
             vocabularies:\n  - enum: Occupation\n    mode: inline\n",
        );
        assert_eq!(
            field(&plan, "person", "occupation").kind,
            FieldKind::VocabularyCode {
                vocabulary: "occupation".to_owned()
            }
        );
        assert!(plan.vocabularies[0].values.len() > INLINE_VOCABULARY_THRESHOLD);
    }

    #[test]
    fn an_inline_override_above_the_code_list_bound_is_refused() {
        let error = refused(
            "entities:\n  - concept: Person\n    properties:\n      - name: preferred_language\n\
             vocabularies:\n  - enum: Language\n    mode: inline\n",
        );
        assert_eq!(error.code, "init.selection.vocabulary_size");
        assert_eq!(error.path, "selection.vocabularies[Language]");
        assert!(
            error.message.contains(&MAX_CODELIST_CONCEPTS.to_string()),
            "{}",
            error.message
        );
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
    fn a_structured_field_takes_the_highest_classification_it_carries_inline() {
        // `FunctioningProfile.respondent` refers to `Person`, whose scalar
        // properties include ones the model marks sensitive and restricted;
        // with `Person` unselected they are carried inline, and the field
        // holding them must be classified for the most protected of them.
        let plan = resolved(
            "entities:\n  - concept: FunctioningProfile\n    properties:\n      - name: respondent\n",
        );
        let respondent = field(&plan, "functioning-profile", "respondent");
        let FieldKind::Structured { schema, .. } = &respondent.kind else {
            panic!("respondent is structured");
        };
        assert!(schema["properties"]["religion"].is_object());
        assert_eq!(respondent.classification, Classification::Restricted);
        assert_eq!(plan.classification_ceiling, Classification::Restricted);
        // `Address` carries nothing sensitive, so `household.address` stays
        // where its own annotation puts it.
        let plan =
            resolved("entities:\n  - concept: Household\n    properties:\n      - name: address\n");
        assert_eq!(
            field(&plan, "household", "address").classification,
            Classification::Internal
        );
        assert_eq!(plan.classification_ceiling, Classification::Internal);
    }

    #[test]
    fn a_vocabulary_override_applies_to_a_property_holding_many_values() {
        fn items<'a>(plan: &'a Plan, entity: &str, id: &str) -> &'a Value {
            let FieldKind::Structured { schema, .. } = &field(plan, entity, id).kind else {
                panic!("{entity}.{id} is a list");
            };
            &schema["properties"]["values"]["items"]
        }
        let body = "entities:\n  - concept: FunctioningProfile\n    properties:\n      - name: mobility_aid_types\n";
        let plan = resolved(body);
        assert!(items(&plan, "functioning-profile", "mobility-aid-types")["enum"].is_array());
        let plan = resolved(&format!(
            "{body}vocabularies:\n  - enum: MobilityAidType\n    mode: code\n"
        ));
        let item = items(&plan, "functioning-profile", "mobility-aid-types");
        assert!(item["enum"].is_null(), "{item}");
        assert_eq!(item["maxLength"], CODE_MAX_LENGTH);
        let body = "entities:\n  - concept: Instrument\n    properties:\n      - name: language_of_administration\n";
        let plan = resolved(body);
        let item = items(&plan, "instrument", "language-of-administration");
        assert!(item["enum"].is_null(), "{item}");
        let error = refused(&format!(
            "{body}vocabularies:\n  - enum: Language\n    mode: inline\n"
        ));
        assert_eq!(error.code, "init.selection.vocabulary_size");
    }

    #[test]
    fn a_bounded_code_is_sized_for_the_longest_code_of_its_enumeration() {
        let plan =
            resolved("entities:\n  - concept: Person\n    properties:\n      - name: occupation\n");
        let longest = model().enums["Occupation"]
            .values
            .iter()
            .map(|value| value.text.len())
            .max()
            .expect("values") as u32;
        assert!(longest > CODE_MAX_LENGTH, "{longest}");
        assert_eq!(
            field(&plan, "person", "occupation").kind,
            FieldKind::String {
                min_length: 0,
                max_length: longest
            }
        );
        let plan = resolved(
            "entities:\n  - concept: Instrument\n    properties:\n      - name: language_of_administration\n",
        );
        let FieldKind::Structured { schema, .. } =
            &field(&plan, "instrument", "language-of-administration").kind
        else {
            panic!("a list");
        };
        assert_eq!(
            schema["properties"]["values"]["items"]["maxLength"],
            CODE_MAX_LENGTH
        );
    }

    #[test]
    fn a_registry_identifier_leaves_room_for_the_names_derived_from_it() {
        let mut selection = selection("entities:\n  - concept: Person\n");
        selection.registry.id = "a".repeat(55);
        let error = resolve(&selection, model()).expect_err("refused");
        assert_eq!(error.code, "init.selection.identifier");
        assert_eq!(error.path, "selection.registry.id");
        assert!(error.message.contains("-authority"), "{}", error.message);
        selection.registry.id = "a".repeat(54);
        assert!(resolve(&selection, model()).is_ok());
        assert!(registry_identifier_refusal(&"a".repeat(55)).is_some());
        assert!(registry_identifier_refusal("example").is_none());
    }

    #[test]
    fn a_concept_that_refers_to_the_chosen_concepts_twice_connects_them() {
        let chosen = ["Household".to_owned(), "Person".to_owned()];
        let found = connectors(model(), &chosen).expect("computed");
        let membership = found
            .iter()
            .find(|connector| connector.concept == "GroupMembership")
            .expect("the membership concept connects a person to a group");
        assert_eq!(
            membership.links,
            vec![
                ConnectorLink {
                    property: "group".to_owned(),
                    fits: vec!["Household".to_owned()],
                },
                ConnectorLink {
                    property: "person".to_owned(),
                    fits: vec!["Person".to_owned()],
                },
            ]
        );
        // A connector with one reference fitting several chosen concepts
        // says so, and is offered after the ones whose references are
        // settled.
        let profile = found
            .iter()
            .find(|connector| connector.concept == "FunctioningProfile")
            .expect("a profile has a subject and a respondent");
        assert_eq!(
            profile.links[1].fits,
            vec!["Household".to_owned(), "Person".to_owned()]
        );
        let names: Vec<&str> = found
            .iter()
            .map(|connector| connector.concept.as_str())
            .collect();
        // A concept whose references all fit one chosen concept is absent:
        // a relationship between two people leaves the household apart.
        assert_eq!(
            names,
            [
                "GroupMembership",
                "ConsentRecord",
                "FunctioningProfile",
                "SocioEconomicProfile",
                "Voucher",
            ]
        );
        // A chosen concept is never its own connector, and a concept nothing
        // refers to twice has none.
        let with_membership = [
            "Household".to_owned(),
            "Person".to_owned(),
            "GroupMembership".to_owned(),
        ];
        assert!(connectors(model(), &with_membership)
            .expect("computed")
            .iter()
            .all(|connector| connector.concept != "GroupMembership"));
        assert!(connectors(model(), &["School".to_owned()])
            .expect("computed")
            .is_empty());
    }

    #[test]
    fn an_entity_no_field_connects_to_another_is_reported_with_what_would() {
        let plan = resolved(
            "entities:\n  - concept: Household\n    properties:\n      - name: address\n  - concept: Person\n    properties:\n      - name: given_name\n  - concept: School\n    properties:\n      - name: name\n",
        );
        assert_eq!(plan.unlinked_entities(), ["household", "person", "school"]);
        let membership = plan
            .connectors
            .iter()
            .find(|connector| connector.concept == "GroupMembership")
            .expect("suggested");
        assert_eq!(membership.links[0].fits, ["Household"]);

        let linked = resolved(
            "entities:\n  - concept: Household\n    properties:\n      - name: address\n  - concept: Person\n    properties:\n      - name: given_name\n  - concept: GroupMembership\n    properties:\n      - name: person\n      - name: group\n  - concept: School\n    properties:\n      - name: name\n",
        );
        assert_eq!(linked.unlinked_entities(), ["school"]);

        let alone =
            resolved("entities:\n  - concept: School\n    properties:\n      - name: name\n");
        assert!(
            alone.unlinked_entities().is_empty(),
            "one entity has nothing to link to"
        );
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
    fn an_identifier_field_the_compiler_keeps_for_itself_is_refused() {
        for name in ["id", "revision", "created_at", "record-id", "deleted-at"] {
            let error = refused(&format!(
                "entities:\n  - concept: Person\n    identifierField: {name}\n"
            ));
            assert_eq!(error.code, "init.selection.field_reserved", "{name}");
            assert_eq!(error.path, "selection.entities[Person].identifierField");
        }
        let plan = resolved("entities:\n  - concept: Person\n    identifierField: person-number\n");
        assert_eq!(plan.entities[0].identifier.id, "person-number");
    }

    #[test]
    fn field_identifiers_deriving_one_api_name_are_refused() {
        let error = refused(
            "entities:\n  - concept: Person\n    identifierField: given_name\n    properties:\n      - name: given_name\n",
        );
        assert_eq!(error.code, "init.selection.field_name_collision");
        assert_eq!(
            error.path,
            "selection.entities[Person].properties[given_name]"
        );
        assert!(error.message.contains("givenName"), "{}", error.message);
        assert!(resolve(
            &selection(
                "entities:\n  - concept: Person\n    identifierField: person-number\n    properties:\n      - name: given_name\n",
            ),
            model()
        )
        .is_ok());
    }

    #[test]
    fn a_target_on_a_property_that_holds_no_records_is_refused() {
        let others = "  - concept: Household\n    properties:\n      - name: name\n";
        for property in ["given_name", "sex"] {
            let error = refused(&format!(
                "entities:\n  - concept: Person\n    properties:\n      - name: {property}\n        target: household\n{others}"
            ));
            assert_eq!(error.code, "init.selection.property_target", "{property}");
            assert_eq!(
                error.path,
                format!("selection.entities[Person].properties[{property}]")
            );
        }
    }

    #[test]
    fn an_entity_only_its_own_records_link_is_reported_as_unlinked() {
        let plan = resolved(
            "entities:\n  - concept: Location\n    properties:\n      - name: parent_location\n  - concept: School\n    properties:\n      - name: name\n",
        );
        assert_eq!(
            field(&plan, "location", "parent-location").kind,
            FieldKind::Reference {
                target: "location".to_owned()
            }
        );
        assert_eq!(plan.unlinked_entities(), ["location", "school"]);
    }

    #[test]
    fn a_connector_reaches_two_of_the_selected_concepts() {
        // Both of the references a registered event carries fit the same one
        // selected concept, so selecting it would leave the other apart.
        let chosen = ["Location".to_owned(), "ServicePoint".to_owned()];
        let names: Vec<String> = connectors(model(), &chosen)
            .expect("computed")
            .into_iter()
            .map(|connector| connector.concept)
            .collect();
        assert!(!names.iter().any(|name| name == "Birth"), "{names:?}");
        // With one concept selected, two references to it connect two of its
        // records, which is all there is to connect.
        let alone = ["Location".to_owned()];
        assert!(connectors(model(), &alone)
            .expect("computed")
            .iter()
            .any(|connector| connector.concept == "Birth"));
    }

    #[test]
    fn a_geometry_refuses_coordinates_its_type_does_not_carry() {
        let plan =
            resolved("entities:\n  - concept: Location\n    properties:\n      - name: geometry\n");
        let FieldKind::Structured { schema, .. } = &field(&plan, "location", "geometry").kind
        else {
            panic!("geometry is structured");
        };
        assert!(accepts(
            schema,
            json!({"type": "Point", "coordinates": [12.5, -1.25]})
        ));
        assert!(accepts(
            schema,
            json!({"type": "Polygon", "coordinates": [[[0, 0], [1, 0], [1, 1], [0, 0]]]})
        ));
        assert!(!accepts(
            schema,
            json!({"type": "Point", "coordinates": []})
        ));
        assert!(!accepts(
            schema,
            json!({"type": "Point", "coordinates": [[12.5, -1.25]]})
        ));
        assert!(!accepts(
            schema,
            json!({"type": "Polygon", "coordinates": [[0, 0], [1, 1]]})
        ));
        assert!(!accepts(
            schema,
            json!({"type": "Circle", "coordinates": [12.5, -1.25]})
        ));
    }

    #[test]
    fn an_inlined_concept_keeps_the_shape_of_its_temporal_values() {
        let plan = resolved(
            "entities:\n  - concept: FunctioningProfile\n    properties:\n      - name: respondent\n",
        );
        let FieldKind::Structured { schema, .. } =
            &field(&plan, "functioning-profile", "respondent").kind
        else {
            panic!("respondent is structured");
        };
        let born = &schema["properties"]["date_of_birth"];
        assert_eq!(born["type"], "string");
        assert_eq!(born["maxLength"], TEMPORAL_MAX_LENGTH);
        assert!(accepts(born, json!("2019-04-01")));
        assert!(!accepts(born, json!("not-a-date")));
        assert!(!accepts(born, json!("2019-04-01T09:30:00Z")));
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
