//! Reads a bundle of LinkML schema files into one resolved [`Model`].
//!
//! The reader takes the files it is given and nothing else: it does not
//! follow `imports`, fetch anything, or consult the file system. The first
//! file is the root schema whose `id`, `name`, `version`, and `license` the
//! model carries; every file contributes its prefixes and definitions.
//!
//! The subset it understands is deliberately small. Classes carry `is_a`,
//! `mixins`, `abstract`, and `slots`; slots carry `range`, `multivalued`,
//! `required`, and `identifier`; enums carry `permissible_values`. Keys that
//! would change a class's shape if ignored, such as `attributes` and
//! `slot_usage`, are refused rather than dropped, so a bundle that relies on
//! them fails to read instead of reading wrong.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::model::{ClassDef, EnumDef, Model, PermissibleValue, Range, SlotDef};

/// The built-in types of `linkml:types`, which a bundle may name as a range
/// without importing them.
const LINKML_TYPES: &[&str] = &[
    "string",
    "integer",
    "boolean",
    "float",
    "double",
    "decimal",
    "time",
    "date",
    "datetime",
    "date_or_datetime",
    "uriorcurie",
    "curie",
    "uri",
    "ncname",
    "objectidentifier",
    "nodeidentifier",
    "jsonpointer",
    "jsonpath",
    "sparqlpath",
];

/// Schemes that identify an absolute URI even without a declared prefix,
/// because none of them use a hierarchical `scheme://` form and none of
/// them are ever declared as LinkML CURIE prefixes.
const ABSOLUTE_URI_SCHEMES: &[&str] = &["urn", "did", "mailto", "tag", "data", "doi"];

/// Class keys the reader refuses because ignoring them would change the
/// class's induced shape.
const UNSUPPORTED_CLASS_KEYS: &[&str] = &["attributes", "slot_usage", "union_of"];

/// Slot keys the reader refuses because ignoring them would change the
/// slot's range.
const UNSUPPORTED_SLOT_KEYS: &[&str] = &["any_of", "exactly_one_of", "all_of", "none_of"];

/// Enum keys the reader refuses because ignoring them would change the
/// value set.
const UNSUPPORTED_ENUM_KEYS: &[&str] = &["inherits", "include", "minus", "reachable_from"];

/// Why a bundle could not be read.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error("the bundle has no files")]
    EmptyBundle,
    #[error("{file}: not a LinkML schema: {source}")]
    Yaml {
        file: String,
        #[source]
        source: serde_norway::Error,
    },
    #[error("{file}: the schema has no `name`")]
    MissingName { file: String },
    #[error("{file}: the schema has no `default_prefix`, so `{owner}` has no URI")]
    MissingDefaultPrefix { file: String, owner: String },
    #[error("prefix `{prefix}` is `{first}` in one file and `{second}` in another")]
    PrefixConflict {
        prefix: String,
        first: String,
        second: String,
    },
    #[error("{kind} `{name}` is defined in both `{first}` and `{second}`")]
    DuplicateDefinition {
        kind: &'static str,
        name: String,
        first: String,
        second: String,
    },
    #[error("{file}: {kind} `{owner}` uses `{key}`, which this reader does not support")]
    Unsupported {
        file: String,
        kind: &'static str,
        owner: String,
        key: String,
    },
    #[error("{file}: {kind} `{owner}`: annotation `{key}` is not a scalar")]
    AnnotationNotScalar {
        file: String,
        kind: &'static str,
        owner: String,
        key: String,
    },
    #[error("{file}: {kind} `{owner}` names {target_kind} `{target}`, which no file defines")]
    UnknownReference {
        file: String,
        kind: &'static str,
        owner: String,
        target_kind: &'static str,
        target: String,
    },
    #[error("{file}: slot `{slot}` has range `{range}`, which is not a type, enum, or class in the bundle")]
    UnknownRange {
        file: String,
        slot: String,
        range: String,
    },
    #[error("{file}: `{curie}` uses a prefix no file declares")]
    UnknownPrefix { file: String, curie: String },
    #[error("{file}: enum `{owner}` has a permissible value whose key is not text: {value}")]
    ValueNotText {
        file: String,
        owner: String,
        value: String,
    },
}

/// Reads `files`, each a `(label, yaml)` pair, into one model. The label
/// names the file in errors; the first file is the root schema.
pub fn read_bundle(files: &[(&str, &str)]) -> Result<Model, ReadError> {
    let (root_label, _) = files.first().ok_or(ReadError::EmptyBundle)?;
    let mut schemas = Vec::with_capacity(files.len());
    for (label, yaml) in files {
        let schema: RawSchema = serde_norway::from_str(yaml).map_err(|source| ReadError::Yaml {
            file: (*label).to_owned(),
            source,
        })?;
        if schema.name.is_none() {
            return Err(ReadError::MissingName {
                file: (*label).to_owned(),
            });
        }
        schemas.push(((*label).to_owned(), schema));
    }

    let prefixes = merge_prefixes(&schemas)?;
    let root = &schemas[0].1;
    let mut model = Model {
        id: root.id.clone().unwrap_or_else(|| (*root_label).to_owned()),
        name: root.name.clone().expect("checked above"),
        version: root.version.clone(),
        license: root.license.clone(),
        prefixes,
        classes: BTreeMap::new(),
        slots: BTreeMap::new(),
        enums: BTreeMap::new(),
    };
    // Pass one: collect every definition so references can be checked
    // against the whole bundle in pass two.
    let mut raw_slots = Vec::new();
    for (file, schema) in &schemas {
        let schema_name = schema.name.clone().expect("checked above");
        // `default_range` applies per schema: a slot with no stated range
        // takes the default of the file that defines it, not the root's.
        let schema_default_range = schema
            .default_range
            .clone()
            .unwrap_or_else(|| "string".to_owned());
        for (name, class) in &schema.classes {
            refuse_unsupported(file, "class", name, &class.rest, UNSUPPORTED_CLASS_KEYS)?;
            let definition = ClassDef {
                name: name.clone(),
                uri: definition_uri(
                    &model.prefixes,
                    file,
                    schema,
                    name,
                    class.class_uri.as_deref(),
                )?,
                title: class.title.clone(),
                description: class.description.clone(),
                is_a: class.is_a.clone(),
                mixins: class.mixins.clone(),
                is_abstract: class.is_abstract,
                slots: class.slots.clone(),
                annotations: scalar_annotations(file, "class", name, &class.annotations)?,
                schema: schema_name.clone(),
            };
            insert_unique(&mut model.classes, "class", definition, file)?;
        }
        for (name, slot) in &schema.slots {
            refuse_unsupported(file, "slot", name, &slot.rest, UNSUPPORTED_SLOT_KEYS)?;
            raw_slots.push((
                file.clone(),
                name.clone(),
                slot.range.clone(),
                schema_default_range.clone(),
            ));
            let definition = SlotDef {
                name: name.clone(),
                uri: definition_uri(
                    &model.prefixes,
                    file,
                    schema,
                    name,
                    slot.slot_uri.as_deref(),
                )?,
                title: slot.title.clone(),
                description: slot.description.clone(),
                // Resolved in pass two once every enum and class is known.
                range: Range::Type(
                    slot.range
                        .clone()
                        .unwrap_or_else(|| schema_default_range.clone()),
                ),
                multivalued: slot.multivalued,
                required: slot.required,
                identifier: slot.identifier,
                annotations: scalar_annotations(file, "slot", name, &slot.annotations)?,
                schema: schema_name.clone(),
            };
            insert_unique(&mut model.slots, "slot", definition, file)?;
        }
        for (name, enum_) in &schema.enums {
            refuse_unsupported(file, "enum", name, &enum_.rest, UNSUPPORTED_ENUM_KEYS)?;
            let mut values = Vec::with_capacity(enum_.permissible_values.len());
            for (text, value) in &enum_.permissible_values {
                let text = match text {
                    serde_norway::Value::String(text) => text.clone(),
                    other => {
                        return Err(ReadError::ValueNotText {
                            file: file.clone(),
                            owner: name.clone(),
                            value: format!("{other:?}"),
                        })
                    }
                };
                let value: RawPermissibleValue =
                    serde_norway::from_value(value.clone()).map_err(|source| ReadError::Yaml {
                        file: file.clone(),
                        source,
                    })?;
                let owner = format!("{name}.{text}");
                values.push(PermissibleValue {
                    text,
                    meaning: value
                        .meaning
                        .as_deref()
                        .map(|meaning| expand_curie(&model.prefixes, file, meaning))
                        .transpose()?,
                    title: value.title.clone(),
                    description: value.description.clone(),
                    annotations: scalar_annotations(
                        file,
                        "enum value",
                        &owner,
                        &value.annotations,
                    )?,
                });
            }
            let definition = EnumDef {
                name: name.clone(),
                uri: definition_uri(
                    &model.prefixes,
                    file,
                    schema,
                    name,
                    enum_.enum_uri.as_deref(),
                )?,
                title: enum_.title.clone(),
                description: enum_.description.clone(),
                values,
                annotations: scalar_annotations(file, "enum", name, &enum_.annotations)?,
                schema: schema_name.clone(),
            };
            insert_unique(&mut model.enums, "enum", definition, file)?;
        }
    }

    // Pass two: resolve ranges and check every class reference.
    for (file, name, range, schema_default_range) in raw_slots {
        let range_name = range.unwrap_or(schema_default_range);
        let resolved = if model.enums.contains_key(&range_name) {
            Range::Enum(range_name)
        } else if model.classes.contains_key(&range_name) {
            Range::Class(range_name)
        } else if LINKML_TYPES.contains(&range_name.as_str()) {
            Range::Type(range_name)
        } else {
            return Err(ReadError::UnknownRange {
                file,
                slot: name,
                range: range_name,
            });
        };
        model
            .slots
            .get_mut(&name)
            .expect("inserted in pass one")
            .range = resolved;
    }
    for (file, schema) in &schemas {
        for (name, class) in &schema.classes {
            let check_class = |target: &String| -> Result<(), ReadError> {
                if model.classes.contains_key(target) {
                    Ok(())
                } else {
                    Err(ReadError::UnknownReference {
                        file: file.clone(),
                        kind: "class",
                        owner: name.clone(),
                        target_kind: "class",
                        target: target.clone(),
                    })
                }
            };
            class.is_a.iter().try_for_each(check_class)?;
            class.mixins.iter().try_for_each(check_class)?;
            for slot in &class.slots {
                if !model.slots.contains_key(slot) {
                    return Err(ReadError::UnknownReference {
                        file: file.clone(),
                        kind: "class",
                        owner: name.clone(),
                        target_kind: "slot",
                        target: slot.clone(),
                    });
                }
            }
        }
    }
    Ok(model)
}

fn merge_prefixes(schemas: &[(String, RawSchema)]) -> Result<BTreeMap<String, String>, ReadError> {
    let mut prefixes: BTreeMap<String, String> = BTreeMap::new();
    for (_, schema) in schemas {
        for (prefix, expansion) in &schema.prefixes {
            let expansion = expansion.expansion();
            match prefixes.get(prefix) {
                Some(existing) if existing != &expansion => {
                    return Err(ReadError::PrefixConflict {
                        prefix: prefix.clone(),
                        first: existing.clone(),
                        second: expansion,
                    });
                }
                Some(_) => {}
                None => {
                    prefixes.insert(prefix.clone(), expansion);
                }
            }
        }
    }
    Ok(prefixes)
}

fn insert_unique<T>(
    table: &mut BTreeMap<String, T>,
    kind: &'static str,
    definition: T,
    file: &str,
) -> Result<(), ReadError>
where
    T: HasSchema,
{
    let name = definition.name().to_owned();
    if let Some(existing) = table.get(&name) {
        return Err(ReadError::DuplicateDefinition {
            kind,
            name,
            first: existing.schema().to_owned(),
            second: file.to_owned(),
        });
    }
    table.insert(name, definition);
    Ok(())
}

trait HasSchema {
    fn name(&self) -> &str;
    fn schema(&self) -> &str;
}

impl HasSchema for ClassDef {
    fn name(&self) -> &str {
        &self.name
    }
    fn schema(&self) -> &str {
        &self.schema
    }
}

impl HasSchema for SlotDef {
    fn name(&self) -> &str {
        &self.name
    }
    fn schema(&self) -> &str {
        &self.schema
    }
}

impl HasSchema for EnumDef {
    fn name(&self) -> &str {
        &self.name
    }
    fn schema(&self) -> &str {
        &self.schema
    }
}

fn refuse_unsupported(
    file: &str,
    kind: &'static str,
    owner: &str,
    rest: &BTreeMap<String, serde_norway::Value>,
    unsupported: &[&str],
) -> Result<(), ReadError> {
    for key in unsupported {
        if rest.contains_key(*key) {
            return Err(ReadError::Unsupported {
                file: file.to_owned(),
                kind,
                owner: owner.to_owned(),
                key: (*key).to_owned(),
            });
        }
    }
    Ok(())
}

/// The URI of a definition: the one it states, expanded, or else
/// `default_prefix:name` from its own file.
fn definition_uri(
    prefixes: &BTreeMap<String, String>,
    file: &str,
    schema: &RawSchema,
    name: &str,
    stated: Option<&str>,
) -> Result<String, ReadError> {
    match stated {
        Some(uri) => expand_curie(prefixes, file, uri),
        None => {
            let prefix = schema.default_prefix.as_deref().ok_or_else(|| {
                ReadError::MissingDefaultPrefix {
                    file: file.to_owned(),
                    owner: name.to_owned(),
                }
            })?;
            expand_curie(prefixes, file, &format!("{prefix}:{name}"))
        }
    }
}

/// Expands `prefix:local` through the bundle's prefixes.
///
/// A declared prefix always wins: if `value` splits into `prefix:local` and
/// some file declares `prefix`, the value is a CURIE and expands normally,
/// even if it would otherwise match one of the cases below. Otherwise the
/// value is an absolute URI, returned unchanged, when it contains `://` or
/// its scheme (the text before the first `:`) is one of the well-known
/// non-hierarchical schemes that never serve as CURIE prefixes: `urn`,
/// `did`, `mailto`, `tag`, `data`, `doi`. Any other undeclared prefix is
/// refused.
fn expand_curie(
    prefixes: &BTreeMap<String, String>,
    file: &str,
    value: &str,
) -> Result<String, ReadError> {
    let unknown = || ReadError::UnknownPrefix {
        file: file.to_owned(),
        curie: value.to_owned(),
    };
    let (prefix, local) = value.split_once(':').ok_or_else(unknown)?;
    if let Some(expansion) = prefixes.get(prefix) {
        return Ok(format!("{expansion}{local}"));
    }
    if value.contains("://") || ABSOLUTE_URI_SCHEMES.contains(&prefix) {
        return Ok(value.to_owned());
    }
    Err(unknown())
}

fn scalar_annotations(
    file: &str,
    kind: &'static str,
    owner: &str,
    annotations: &BTreeMap<String, serde_norway::Value>,
) -> Result<BTreeMap<String, String>, ReadError> {
    let mut scalars = BTreeMap::new();
    for (key, value) in annotations {
        let text = match value {
            serde_norway::Value::String(text) => text.clone(),
            serde_norway::Value::Bool(flag) => flag.to_string(),
            serde_norway::Value::Number(number) => number.to_string(),
            _ => {
                return Err(ReadError::AnnotationNotScalar {
                    file: file.to_owned(),
                    kind,
                    owner: owner.to_owned(),
                    key: key.clone(),
                })
            }
        };
        scalars.insert(key.clone(), text);
    }
    Ok(scalars)
}

#[derive(Debug, Deserialize)]
struct RawSchema {
    id: Option<String>,
    name: Option<String>,
    version: Option<String>,
    license: Option<String>,
    default_prefix: Option<String>,
    default_range: Option<String>,
    #[serde(default)]
    prefixes: BTreeMap<String, RawPrefix>,
    #[serde(default)]
    classes: BTreeMap<String, RawClass>,
    #[serde(default)]
    slots: BTreeMap<String, RawSlot>,
    #[serde(default)]
    enums: BTreeMap<String, RawEnum>,
}

/// A prefix is either the expansion itself or a `{prefix_reference: ...}`
/// object; LinkML allows both.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawPrefix {
    Expansion(String),
    Object { prefix_reference: String },
}

impl RawPrefix {
    fn expansion(&self) -> String {
        match self {
            RawPrefix::Expansion(expansion) => expansion.clone(),
            RawPrefix::Object { prefix_reference } => prefix_reference.clone(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct RawClass {
    class_uri: Option<String>,
    title: Option<String>,
    description: Option<String>,
    is_a: Option<String>,
    #[serde(default)]
    mixins: Vec<String>,
    #[serde(default, rename = "abstract")]
    is_abstract: bool,
    #[serde(default)]
    slots: Vec<String>,
    #[serde(default)]
    annotations: BTreeMap<String, serde_norway::Value>,
    #[serde(flatten)]
    rest: BTreeMap<String, serde_norway::Value>,
}

#[derive(Debug, Deserialize)]
struct RawSlot {
    slot_uri: Option<String>,
    title: Option<String>,
    description: Option<String>,
    range: Option<String>,
    #[serde(default)]
    multivalued: bool,
    #[serde(default)]
    required: bool,
    #[serde(default)]
    identifier: bool,
    #[serde(default)]
    annotations: BTreeMap<String, serde_norway::Value>,
    #[serde(flatten)]
    rest: BTreeMap<String, serde_norway::Value>,
}

#[derive(Debug, Deserialize)]
struct RawEnum {
    enum_uri: Option<String>,
    title: Option<String>,
    description: Option<String>,
    /// Kept as a mapping so declaration order survives into the model.
    #[serde(default)]
    permissible_values: serde_norway::Mapping,
    #[serde(default)]
    annotations: BTreeMap<String, serde_norway::Value>,
    #[serde(flatten)]
    rest: BTreeMap<String, serde_norway::Value>,
}

/// A permissible value is either a body or a bare key with a null body.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct RawPermissibleValue {
    meaning: Option<String>,
    title: Option<String>,
    description: Option<String>,
    #[serde(default)]
    annotations: BTreeMap<String, serde_norway::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = r#"
id: https://example.org/linkml/root
name: root
version: 1.2.3
license: CC-BY-4.0
default_prefix: ex
default_range: string
prefixes:
  ex: https://example.org/
  skos: http://www.w3.org/2004/02/skos/core#
imports:
  - linkml:types
  - parts
"#;

    const PARTS: &str = r#"
id: https://example.org/linkml/parts
name: parts
default_prefix: ex
prefixes:
  ex: https://example.org/
classes:
  Party:
    class_uri: ex:Party
    abstract: true
    slots: [name, identifiers]
    annotations:
      featured: false
  Agent:
    abstract: true
    slots: [name, agent_kind]
  Person:
    class_uri: ex:Person
    title: Person
    is_a: Party
    mixins: [Agent]
    slots: [name, date_of_birth, sex, memberships]
    annotations:
      featured: true
      label_fr: Personne
      weight: 3
  Group:
    is_a: Party
    abstract: true
    slots: [members]
  Household:
    is_a: Group
slots:
  name:
    slot_uri: ex:name
    range: string
    multivalued: false
  identifiers:
    range: Identifier
    multivalued: true
  agent_kind:
    range: string
  date_of_birth:
    range: date
    annotations:
      sensitivity: sensitive
  sex:
    range: Sex
  memberships:
    range: Group
    multivalued: true
  members:
    range: Person
    multivalued: true
  record_id:
    identifier: true
    required: true
enums:
  Sex:
    enum_uri: ex:Sex
    permissible_values:
      not_known:
        meaning: ex:Sex/not_known
        title: Not known
      male:
        meaning: ex:Sex/male
      female:
        meaning: http://absolute.example/female
      other:
"#;

    const IDENTIFIER: &str = r#"
name: identifier
default_prefix: ex
classes:
  Identifier:
    slots: [name]
"#;

    fn bundle() -> Model {
        read_bundle(&[
            ("root.yaml", ROOT),
            ("parts.yaml", PARTS),
            ("identifier.yaml", IDENTIFIER),
        ])
        .expect("the fixture bundle reads")
    }

    #[test]
    fn root_metadata_and_merged_prefixes_come_from_the_bundle() {
        let model = bundle();
        assert_eq!(model.id, "https://example.org/linkml/root");
        assert_eq!(model.name, "root");
        assert_eq!(model.version.as_deref(), Some("1.2.3"));
        assert_eq!(model.license.as_deref(), Some("CC-BY-4.0"));
        assert_eq!(model.prefixes["ex"], "https://example.org/");
        assert_eq!(
            model.prefixes["skos"],
            "http://www.w3.org/2004/02/skos/core#"
        );
    }

    #[test]
    fn stated_and_derived_uris_are_absolute() {
        let model = bundle();
        assert_eq!(model.classes["Person"].uri, "https://example.org/Person");
        assert_eq!(model.classes["Agent"].uri, "https://example.org/Agent");
        assert_eq!(model.slots["name"].uri, "https://example.org/name");
        assert_eq!(model.slots["sex"].uri, "https://example.org/sex");
        assert_eq!(model.enums["Sex"].uri, "https://example.org/Sex");
        assert_eq!(model.classes["Identifier"].schema, "identifier");
    }

    #[test]
    fn ranges_resolve_to_types_enums_and_classes() {
        let model = bundle();
        assert_eq!(model.slots["name"].range, Range::Type("string".into()));
        assert_eq!(
            model.slots["date_of_birth"].range,
            Range::Type("date".into())
        );
        assert_eq!(model.slots["sex"].range, Range::Enum("Sex".into()));
        assert_eq!(
            model.slots["identifiers"].range,
            Range::Class("Identifier".into())
        );
        assert!(model.slots["identifiers"].multivalued);
        assert!(!model.slots["name"].multivalued);
        // A slot without a range takes its own file's default range; parts.yaml
        // states none, so it falls back to the reader's "string" default.
        assert_eq!(model.slots["record_id"].range, Range::Type("string".into()));
        assert!(model.slots["record_id"].identifier);
        assert!(model.slots["record_id"].required);
        assert!(!model.slots["name"].identifier);
    }

    #[test]
    fn an_imported_files_own_default_range_applies_to_its_slots() {
        let other = r#"
name: other_default_range
default_prefix: ex
prefixes:
  ex: https://example.org/
default_range: integer
slots:
  count: {}
"#;
        let model = read_bundle(&[("root.yaml", ROOT), ("other.yaml", other)])
            .expect("the fixture bundle reads");
        assert_eq!(model.slots["count"].range, Range::Type("integer".into()));
    }

    #[test]
    fn enum_values_keep_declaration_order_and_expand_meanings() {
        let model = bundle();
        let sex = &model.enums["Sex"];
        let texts: Vec<&str> = sex.values.iter().map(|value| value.text.as_str()).collect();
        assert_eq!(texts, ["not_known", "male", "female", "other"]);
        assert_eq!(
            sex.values[0].meaning.as_deref(),
            Some("https://example.org/Sex/not_known")
        );
        assert_eq!(sex.values[0].title.as_deref(), Some("Not known"));
        assert_eq!(
            sex.values[2].meaning.as_deref(),
            Some("http://absolute.example/female")
        );
        assert_eq!(sex.values[3].meaning, None);
    }

    #[test]
    fn scalar_annotations_are_kept_as_text() {
        let model = bundle();
        let person = &model.classes["Person"];
        assert_eq!(person.annotations["featured"], "true");
        assert_eq!(person.annotations["label_fr"], "Personne");
        assert_eq!(person.annotations["weight"], "3");
        assert_eq!(model.classes["Party"].annotations["featured"], "false");
        assert_eq!(
            model.slots["date_of_birth"].annotations["sensitivity"],
            "sensitive"
        );
        assert!(model.classes["Party"].is_abstract);
        assert!(!person.is_abstract);
    }

    #[test]
    fn induced_slots_walk_ancestors_then_mixins_then_own() {
        let model = bundle();
        let names: Vec<&str> = model
            .induced_slots("Person")
            .expect("Person resolves")
            .iter()
            .map(|slot| slot.name.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "name",
                "identifiers",
                "agent_kind",
                "date_of_birth",
                "sex",
                "memberships"
            ]
        );
        let household: Vec<&str> = model
            .induced_slots("Household")
            .expect("Household resolves")
            .iter()
            .map(|slot| slot.name.as_str())
            .collect();
        assert_eq!(household, ["name", "identifiers", "members"]);
        assert_eq!(
            model.induced_slots("Nobody").unwrap_err(),
            crate::model::ModelError::UnknownClass("Nobody".into())
        );
    }

    #[test]
    fn subclass_checks_follow_is_a_only() {
        let model = bundle();
        assert!(model.is_subclass_of("Household", "Party").unwrap());
        assert!(model.is_subclass_of("Household", "Household").unwrap());
        assert!(!model.is_subclass_of("Household", "Person").unwrap());
        // Agent is a mixin of Person, not a superclass.
        assert!(!model.is_subclass_of("Person", "Agent").unwrap());
        let names: Vec<&str> = model
            .concrete_descendants("Party")
            .unwrap()
            .iter()
            .map(|class| class.name.as_str())
            .collect();
        assert_eq!(names, ["Household", "Person"]);
        assert_eq!(
            model.concrete_descendants("Group").unwrap()[0].name,
            "Household"
        );
    }

    #[test]
    fn an_empty_bundle_is_refused() {
        assert!(matches!(read_bundle(&[]), Err(ReadError::EmptyBundle)));
    }

    #[test]
    fn a_file_without_a_name_is_refused() {
        let error = read_bundle(&[("root.yaml", "id: x\n")]).unwrap_err();
        assert_eq!(error.to_string(), "root.yaml: the schema has no `name`");
    }

    #[test]
    fn a_definition_defined_twice_is_refused() {
        let twice = "name: again\ndefault_prefix: ex\nclasses:\n  Person: {}\n";
        let error = read_bundle(&[
            ("root.yaml", ROOT),
            ("parts.yaml", PARTS),
            ("again.yaml", twice),
        ])
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "class `Person` is defined in both `parts` and `again.yaml`"
        );
    }

    #[test]
    fn conflicting_prefixes_are_refused() {
        let other =
            "name: other\ndefault_prefix: ex\nprefixes:\n  ex: https://elsewhere.example/\n";
        let error = read_bundle(&[("root.yaml", ROOT), ("other.yaml", other)]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "prefix `ex` is `https://example.org/` in one file and `https://elsewhere.example/` in another"
        );
    }

    #[test]
    fn unknown_ranges_and_references_are_refused() {
        let bad_range = "name: r\ndefault_prefix: ex\nprefixes: {ex: https://example.org/}\nslots:\n  age:\n    range: Years\n";
        let error = read_bundle(&[("r.yaml", bad_range)]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "r.yaml: slot `age` has range `Years`, which is not a type, enum, or class in the bundle"
        );

        let bad_parent = "name: r\ndefault_prefix: ex\nprefixes: {ex: https://example.org/}\nclasses:\n  Child:\n    is_a: Missing\n";
        let error = read_bundle(&[("r.yaml", bad_parent)]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "r.yaml: class `Child` names class `Missing`, which no file defines"
        );

        let bad_slot = "name: r\ndefault_prefix: ex\nprefixes: {ex: https://example.org/}\nclasses:\n  Child:\n    slots: [missing]\n";
        let error = read_bundle(&[("r.yaml", bad_slot)]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "r.yaml: class `Child` names slot `missing`, which no file defines"
        );
    }

    #[test]
    fn unknown_prefixes_are_refused() {
        let unknown = "name: r\ndefault_prefix: ex\nprefixes: {ex: https://example.org/}\nclasses:\n  Thing:\n    class_uri: nope:Thing\n";
        let error = read_bundle(&[("r.yaml", unknown)]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "r.yaml: `nope:Thing` uses a prefix no file declares"
        );

        let no_default = "name: r\nclasses:\n  Thing: {}\n";
        let error = read_bundle(&[("r.yaml", no_default)]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "r.yaml: the schema has no `default_prefix`, so `Thing` has no URI"
        );
    }

    #[test]
    fn absolute_uris_without_a_hierarchical_separator_pass_through() {
        let prefixes = BTreeMap::new();
        assert_eq!(
            expand_curie(
                &prefixes,
                "r.yaml",
                "urn:uuid:11111111-1111-1111-1111-111111111111"
            )
            .unwrap(),
            "urn:uuid:11111111-1111-1111-1111-111111111111"
        );
        assert_eq!(
            expand_curie(&prefixes, "r.yaml", "did:example:123").unwrap(),
            "did:example:123"
        );
        assert_eq!(
            expand_curie(&prefixes, "r.yaml", "mailto:jane@example.org").unwrap(),
            "mailto:jane@example.org"
        );
    }

    #[test]
    fn an_undeclared_prefix_without_a_known_absolute_scheme_is_refused() {
        let prefixes = BTreeMap::new();
        let error = expand_curie(&prefixes, "r.yaml", "foo:bar").unwrap_err();
        assert_eq!(
            error.to_string(),
            "r.yaml: `foo:bar` uses a prefix no file declares"
        );
    }

    #[test]
    fn a_declared_prefix_wins_over_a_well_known_absolute_scheme() {
        let mut prefixes = BTreeMap::new();
        prefixes.insert("urn".to_owned(), "https://example.org/urn/".to_owned());
        assert_eq!(
            expand_curie(&prefixes, "r.yaml", "urn:uuid-123").unwrap(),
            "https://example.org/urn/uuid-123"
        );
    }

    #[test]
    fn a_bundle_may_use_absolute_uris_with_non_hierarchical_schemes() {
        let schema = "name: r\ndefault_prefix: ex\nprefixes: {ex: https://example.org/}\nenums:\n  Kind:\n    permissible_values:\n      widget:\n        meaning: \"urn:uuid:11111111-1111-1111-1111-111111111111\"\n";
        let model = read_bundle(&[("r.yaml", schema)]).expect("urn meanings read");
        assert_eq!(
            model.enums["Kind"].values[0].meaning.as_deref(),
            Some("urn:uuid:11111111-1111-1111-1111-111111111111")
        );
    }

    #[test]
    fn shape_changing_keys_are_refused_rather_than_dropped() {
        let attributes = "name: r\ndefault_prefix: ex\nprefixes: {ex: https://example.org/}\nclasses:\n  Thing:\n    attributes:\n      colour:\n        range: string\n";
        let error = read_bundle(&[("r.yaml", attributes)]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "r.yaml: class `Thing` uses `attributes`, which this reader does not support"
        );

        let any_of = "name: r\ndefault_prefix: ex\nprefixes: {ex: https://example.org/}\nslots:\n  value:\n    any_of:\n      - range: string\n";
        let error = read_bundle(&[("r.yaml", any_of)]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "r.yaml: slot `value` uses `any_of`, which this reader does not support"
        );

        let inherits = "name: r\ndefault_prefix: ex\nprefixes: {ex: https://example.org/}\nenums:\n  Colours:\n    inherits: [Base]\n";
        let error = read_bundle(&[("r.yaml", inherits)]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "r.yaml: enum `Colours` uses `inherits`, which this reader does not support"
        );
    }

    #[test]
    fn structured_annotations_are_refused() {
        let nested = "name: r\ndefault_prefix: ex\nprefixes: {ex: https://example.org/}\nclasses:\n  Thing:\n    annotations:\n      tags: [a, b]\n";
        let error = read_bundle(&[("r.yaml", nested)]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "r.yaml: class `Thing`: annotation `tags` is not a scalar"
        );
    }

    #[test]
    fn prefixes_may_be_objects() {
        let objects = "name: r\ndefault_prefix: ex\nprefixes:\n  ex:\n    prefix_prefix: ex\n    prefix_reference: https://example.org/\nclasses:\n  Thing: {}\n";
        let model = read_bundle(&[("r.yaml", objects)]).expect("object prefixes read");
        assert_eq!(model.classes["Thing"].uri, "https://example.org/Thing");
    }

    #[test]
    fn inheritance_cycles_are_reported() {
        let cycle = "name: r\ndefault_prefix: ex\nprefixes: {ex: https://example.org/}\nclasses:\n  A:\n    is_a: B\n  B:\n    is_a: A\n";
        let model = read_bundle(&[("r.yaml", cycle)]).expect("the cycle reads; walking it fails");
        assert_eq!(
            model.induced_slots("A").unwrap_err(),
            crate::model::ModelError::InheritanceCycle("A".into())
        );
        assert_eq!(
            model.is_subclass_of("A", "Z").unwrap_err(),
            crate::model::ModelError::InheritanceCycle("A".into())
        );
    }
}
