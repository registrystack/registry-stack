//! The embedded PublicSchema reference model and its annotation conventions.
//!
//! PublicSchema (<https://publicschema.org>) is a reference data model for
//! social protection and civil registration systems, published as a LinkML
//! composite under CC BY 4.0. This module embeds the domain files of one
//! pinned snapshot, recorded in `publicschema/PIN.yaml`, so tooling can list
//! its concepts and properties offline. `publicschema/sync-snapshot.sh`
//! refreshes the snapshot from a checkout.
//!
//! The conventions below read PublicSchema's own annotations: the languages
//! it labels in, the convergence evidence behind a property, the sensitivity
//! it assigns, and the property groups it presents a class by. They are
//! observations about the published model, not registry semantics.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::model::{ClassDef, EnumDef, Model, PermissibleValue, SlotDef};
use crate::reader::{read_bundle, ReadError};

/// The embedded files, root first, as `(path under publicschema/, contents)`.
const FILES: &[(&str, &str)] = &[
    (
        "schema/publicschema.yaml",
        include_str!("../publicschema/schema/publicschema.yaml"),
    ),
    (
        "schema/assessment.yaml",
        include_str!("../publicschema/schema/assessment.yaml"),
    ),
    (
        "schema/biometric.yaml",
        include_str!("../publicschema/schema/biometric.yaml"),
    ),
    (
        "schema/categories.yaml",
        include_str!("../publicschema/schema/categories.yaml"),
    ),
    (
        "schema/civil_status.yaml",
        include_str!("../publicschema/schema/civil_status.yaml"),
    ),
    (
        "schema/common.yaml",
        include_str!("../publicschema/schema/common.yaml"),
    ),
    (
        "schema/consent.yaml",
        include_str!("../publicschema/schema/consent.yaml"),
    ),
    (
        "schema/core.yaml",
        include_str!("../publicschema/schema/core.yaml"),
    ),
    (
        "schema/credentials.yaml",
        include_str!("../publicschema/schema/credentials.yaml"),
    ),
    (
        "schema/document.yaml",
        include_str!("../publicschema/schema/document.yaml"),
    ),
    (
        "schema/identity.yaml",
        include_str!("../publicschema/schema/identity.yaml"),
    ),
    (
        "schema/misc.yaml",
        include_str!("../publicschema/schema/misc.yaml"),
    ),
    (
        "schema/payment.yaml",
        include_str!("../publicschema/schema/payment.yaml"),
    ),
    (
        "schema/program.yaml",
        include_str!("../publicschema/schema/program.yaml"),
    ),
    (
        "schema/vocabularies.yaml",
        include_str!("../publicschema/schema/vocabularies.yaml"),
    ),
];

const PIN_YAML: &str = include_str!("../publicschema/PIN.yaml");

/// The attribution notice the vocabulary licence asks for.
pub const LICENSE_NOTICE: &str = include_str!("../publicschema/LICENSE-VOCABULARY");

/// The languages PublicSchema labels its definitions in, `en` first because
/// English is the language of `title` itself.
pub const LANGUAGES: [&str; 3] = ["en", "fr", "es"];

/// Which upstream commit the embedded snapshot was copied from.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Pin {
    pub repository: String,
    pub commit: String,
    pub commit_date: String,
    pub version: String,
    pub license: String,
    pub files: Vec<String>,
}

/// Reads the pin record written beside the snapshot.
pub fn pin() -> Result<Pin, serde_norway::Error> {
    serde_norway::from_str(PIN_YAML)
}

/// Reads the embedded snapshot into a model. The snapshot is fixed at build
/// time, so a failure here is a defect in the crate, not in the caller.
pub fn model() -> Result<Model, ReadError> {
    read_bundle(FILES)
}

/// A property's convergence evidence: how many of the systems PublicSchema
/// mapped carry it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Convergence {
    pub system_count: u32,
    pub total_systems: u32,
    #[serde(default)]
    pub notes: Option<String>,
}

impl Convergence {
    /// The share of mapped systems that carry the property, zero when none
    /// were mapped.
    pub fn share(&self) -> f64 {
        if self.total_systems == 0 {
            0.0
        } else {
            f64::from(self.system_count) / f64::from(self.total_systems)
        }
    }
}

/// One of the groups a class presents its properties under.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PropertyGroup {
    pub category: String,
    pub properties: Vec<String>,
}

/// How PublicSchema rates a property's sensitivity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sensitivity {
    Sensitive,
    Restricted,
}

/// An annotation that is present but not in the shape the convention
/// describes.
#[derive(Debug, thiserror::Error)]
pub enum ConventionError {
    #[error("`{owner}`: annotation `{key}` is not the JSON the convention expects: {source}")]
    Json {
        owner: String,
        key: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error("`{owner}`: annotation `sensitivity` is `{value}`, not `sensitive` or `restricted`")]
    Sensitivity { owner: String, value: String },
}

/// Something with a title and annotations, which is every definition in the
/// model.
pub trait Labeled {
    fn name(&self) -> &str;
    fn title(&self) -> Option<&str>;
    fn annotations(&self) -> &BTreeMap<String, String>;
}

impl Labeled for ClassDef {
    fn name(&self) -> &str {
        &self.name
    }
    fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }
    fn annotations(&self) -> &BTreeMap<String, String> {
        &self.annotations
    }
}

impl Labeled for SlotDef {
    fn name(&self) -> &str {
        &self.name
    }
    fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }
    fn annotations(&self) -> &BTreeMap<String, String> {
        &self.annotations
    }
}

impl Labeled for EnumDef {
    fn name(&self) -> &str {
        &self.name
    }
    fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }
    fn annotations(&self) -> &BTreeMap<String, String> {
        &self.annotations
    }
}

impl Labeled for PermissibleValue {
    fn name(&self) -> &str {
        &self.text
    }
    fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }
    fn annotations(&self) -> &BTreeMap<String, String> {
        &self.annotations
    }
}

/// The label of `item` in `language`: `title` for English, the `label_<lang>`
/// annotation otherwise.
pub fn label<'a>(item: &'a impl Labeled, language: &str) -> Option<&'a str> {
    if language == "en" {
        item.title()
    } else {
        item.annotations()
            .get(&format!("label_{language}"))
            .map(String::as_str)
    }
}

/// True when PublicSchema marks the class as featured on its site.
pub fn featured(class: &ClassDef) -> bool {
    class.annotations.get("featured").map(String::as_str) == Some("true")
}

/// The convergence evidence behind `item`, when PublicSchema records any.
pub fn convergence(item: &impl Labeled) -> Result<Option<Convergence>, ConventionError> {
    json_annotation(item, "convergence_json")
}

/// The property groups a class presents itself by, when it declares any.
pub fn property_groups(class: &ClassDef) -> Result<Vec<PropertyGroup>, ConventionError> {
    Ok(json_annotation(class, "property_groups_json")?.unwrap_or_default())
}

/// The sensitivity PublicSchema assigns to a property, when it assigns one.
pub fn sensitivity(slot: &SlotDef) -> Result<Option<Sensitivity>, ConventionError> {
    match slot.annotations.get("sensitivity").map(String::as_str) {
        None => Ok(None),
        Some("sensitive") => Ok(Some(Sensitivity::Sensitive)),
        Some("restricted") => Ok(Some(Sensitivity::Restricted)),
        Some(value) => Err(ConventionError::Sensitivity {
            owner: slot.name.clone(),
            value: value.to_owned(),
        }),
    }
}

/// The bespoke type PublicSchema gives a string-ranged property whose text
/// has more structure than a string, such as `geojson_geometry`.
pub fn bespoke_type(slot: &SlotDef) -> Option<&str> {
    slot.annotations.get("bespoke_type").map(String::as_str)
}

fn json_annotation<T: serde::de::DeserializeOwned>(
    item: &impl Labeled,
    key: &'static str,
) -> Result<Option<T>, ConventionError> {
    item.annotations()
        .get(key)
        .map(|json| {
            serde_json::from_str(json).map_err(|source| ConventionError::Json {
                owner: item.name().to_owned(),
                key,
                source,
            })
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(annotations: &[(&str, &str)]) -> ClassDef {
        ClassDef {
            name: "Thing".into(),
            uri: "https://example.org/Thing".into(),
            title: Some("Thing".into()),
            description: None,
            is_a: None,
            mixins: Vec::new(),
            is_abstract: false,
            slots: Vec::new(),
            annotations: annotations
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect(),
            schema: "test".into(),
        }
    }

    fn slot(annotations: &[(&str, &str)]) -> SlotDef {
        SlotDef {
            name: "thing".into(),
            uri: "https://example.org/thing".into(),
            title: Some("Thing".into()),
            description: None,
            range: crate::model::Range::Type("string".into()),
            multivalued: false,
            required: false,
            identifier: false,
            annotations: annotations
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect(),
            schema: "test".into(),
        }
    }

    #[test]
    fn labels_come_from_title_or_language_annotations() {
        let class = class(&[("label_fr", "Chose")]);
        assert_eq!(label(&class, "en"), Some("Thing"));
        assert_eq!(label(&class, "fr"), Some("Chose"));
        assert_eq!(label(&class, "es"), None);
    }

    #[test]
    fn featured_is_the_literal_true() {
        assert!(featured(&class(&[("featured", "true")])));
        assert!(!featured(&class(&[("featured", "false")])));
        assert!(!featured(&class(&[])));
    }

    #[test]
    fn convergence_parses_the_json_annotation() {
        let slot = slot(&[(
            "convergence_json",
            r#"{"notes": "Present in 5 of 6.", "system_count": 5, "total_systems": 6}"#,
        )]);
        let convergence = convergence(&slot).unwrap().unwrap();
        assert_eq!(convergence.system_count, 5);
        assert_eq!(convergence.total_systems, 6);
        assert_eq!(convergence.notes.as_deref(), Some("Present in 5 of 6."));
        assert!((convergence.share() - 5.0 / 6.0).abs() < 1e-9);
        assert_eq!(super::convergence(&super::tests::slot(&[])).unwrap(), None);
        assert_eq!(
            Convergence {
                system_count: 0,
                total_systems: 0,
                notes: None
            }
            .share(),
            0.0
        );
    }

    #[test]
    fn malformed_convention_json_is_an_error() {
        let slot = slot(&[("convergence_json", "{not json")]);
        let error = convergence(&slot).unwrap_err();
        assert!(error.to_string().starts_with(
            "`thing`: annotation `convergence_json` is not the JSON the convention expects"
        ));
    }

    #[test]
    fn property_groups_parse_or_default_to_none() {
        let class = class(&[(
            "property_groups_json",
            r#"[{"category": "identity", "properties": ["name", "identifiers"]}]"#,
        )]);
        let groups = property_groups(&class).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].category, "identity");
        assert_eq!(groups[0].properties, ["name", "identifiers"]);
        assert!(property_groups(&super::tests::class(&[]))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn sensitivity_recognises_the_two_levels() {
        assert_eq!(
            sensitivity(&slot(&[("sensitivity", "sensitive")])).unwrap(),
            Some(Sensitivity::Sensitive)
        );
        assert_eq!(
            sensitivity(&slot(&[("sensitivity", "restricted")])).unwrap(),
            Some(Sensitivity::Restricted)
        );
        assert_eq!(sensitivity(&slot(&[])).unwrap(), None);
        assert_eq!(
            sensitivity(&slot(&[("sensitivity", "public")]))
                .unwrap_err()
                .to_string(),
            "`thing`: annotation `sensitivity` is `public`, not `sensitive` or `restricted`"
        );
    }

    #[test]
    fn bespoke_type_is_passed_through() {
        assert_eq!(
            bespoke_type(&slot(&[("bespoke_type", "geojson_geometry")])),
            Some("geojson_geometry")
        );
        assert_eq!(bespoke_type(&slot(&[])), None);
    }
}
