//! The retained, closed selector field vocabulary and its authoring bounds.
use crate::{
    finding::{FieldPath, Finding},
    project::{self, SelectorProfile},
};
use registry_platform_yaml::BoundedU64;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(feature="schema",schemars(!remote,tag="type"))]
pub enum Field {
    String {
        minimum_bytes: BoundedU64<1, 8192>,
        maximum_bytes: BoundedU64<1, 8192>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    Date {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    Integer {
        #[cfg_attr(feature="schema",schemars(range(min = -9_007_199_254_740_991_i64,max = 9_007_199_254_740_991_i64)))]
        minimum: i64,
        #[cfg_attr(feature="schema",schemars(range(min = -9_007_199_254_740_991_i64,max = 9_007_199_254_740_991_i64)))]
        maximum: i64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    Boolean {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    ControlledCode {
        codelist: String,
        codelist_version: String,
        maximum_bytes: BoundedU64<1, 8192>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
}
registry_platform_yaml::tagged_union!(Field, tag = "type");
impl Serialize for Field {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let external = Self::serialize(self, serde_json::value::Serializer)
            .map_err(serde::ser::Error::custom)?;
        let Value::Object(variants) = external else {
            return Err(serde::ser::Error::custom(
                "selector variant must be a mapping",
            ));
        };
        let Some((tag, Value::Object(mut body))) = variants.into_iter().next() else {
            return Err(serde::ser::Error::custom("selector body must be a mapping"));
        };
        body.insert("type".to_owned(), Value::String(tag));
        body.serialize(serializer)
    }
}
impl Field {
    pub fn codelist(&self) -> Option<(&str, &str)> {
        match self {
            Self::ControlledCode {
                codelist,
                codelist_version,
                ..
            } => Some((codelist, codelist_version)),
            _ => None,
        }
    }

    fn valid(&self, maximum: u64) -> bool {
        match self {
            Self::String {
                minimum_bytes,
                maximum_bytes,
                ..
            } => minimum_bytes <= maximum_bytes && maximum_bytes.get() <= maximum,
            Self::Integer {
                minimum, maximum, ..
            } => {
                minimum <= maximum
                    && *minimum >= -9_007_199_254_740_991
                    && *maximum <= 9_007_199_254_740_991
            }
            Self::ControlledCode {
                codelist,
                codelist_version,
                maximum_bytes,
                ..
            } => {
                codelist.starts_with("codelists/")
                    && (project::valid_asset(codelist, "yaml")
                        || project::valid_asset(codelist, "json"))
                    && !codelist_version.is_empty()
                    && codelist_version.len() <= 128
                    && !codelist_version.chars().any(char::is_control)
                    && maximum_bytes.get() <= maximum
            }
            Self::Date { .. } | Self::Boolean { .. } => true,
        }
    }
}
pub fn validate(profile: &SelectorProfile, at: &FieldPath) -> Vec<Finding> {
    let mut findings = Vec::new();
    if profile.fields.is_empty() || profile.fields.len() > 16 {
        findings.push(Finding::new(
            at.clone().key("fields"),
            "selector-field-count",
            "declare between one and 16 bounded selector fields",
        ));
    }
    for (id, field) in &profile.fields {
        if !field.valid(profile.maximum_aggregate_bytes.get()) {
            findings.push(Finding::new(
                at.clone().key("fields").map_key(id.to_string()),
                "selector-field-bounds",
                "declare bounded selector constraints within the profile aggregate and reviewed codelist contract",
            ));
        }
    }
    findings
}
/// Presentation is inspected but does not enter the retained runtime field contract.
pub fn compiled(field: &Field) -> Value {
    let mut value = serde_json::to_value(field).expect("selector field serializes");
    if let Some(object) = value.as_object_mut() {
        object.remove("label");
        object.remove("description");
    }
    value
}
