//! The retained, closed selector field vocabulary and its authoring bounds.
use crate::{
    finding::{FieldPath, Finding},
    project::{self, SelectorProfile},
};
use registry_platform_yaml::BoundedU64;
use serde::Deserialize;
use serde_json::Value;

#[derive(Clone, Debug, Deserialize)]
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
        label: Option<String>,
        description: Option<String>,
    },
    Date {
        label: Option<String>,
        description: Option<String>,
    },
    Integer {
        #[cfg_attr(feature="schema",schemars(range(min = -9_007_199_254_740_991_i64,max = 9_007_199_254_740_991_i64)))]
        minimum: i64,
        #[cfg_attr(feature="schema",schemars(range(min = -9_007_199_254_740_991_i64,max = 9_007_199_254_740_991_i64)))]
        maximum: i64,
        label: Option<String>,
        description: Option<String>,
    },
    Boolean {
        label: Option<String>,
        description: Option<String>,
    },
    ControlledCode {
        codelist: String,
        codelist_version: String,
        maximum_bytes: BoundedU64<1, 8192>,
        label: Option<String>,
        description: Option<String>,
    },
}
registry_platform_yaml::tagged_union!(Field, tag = "type");
impl Field {
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
    for (id, value) in &profile.fields {
        let at = at.clone().key("fields").map_key(id.to_string());
        let required: &[&str] = match value["type"].as_str() {
            Some("string") => &["minimumBytes", "maximumBytes"],
            Some("integer") => &["minimum", "maximum"],
            Some("controlled-code") => &["codelist", "codelistVersion", "maximumBytes"],
            Some("date" | "boolean") => &[],
            _ => {
                findings.push(Finding::new(at.clone().key("type"),"selector-field-type","declare a retained string, date, integer, boolean or controlled-code selector field"));
                continue;
            }
        };
        for key in required {
            if value.get(*key).is_none() {
                findings.push(Finding::new(
                    at.clone().map_key((*key).to_owned()),
                    "selector-field-required",
                    "declare every constraint required by this selector field type",
                ));
            }
        }
        let decoded = serde_json::from_value::<Field>(value.clone());
        if decoded.as_ref().is_err()
            || decoded.is_ok_and(|field| !field.valid(profile.maximum_aggregate_bytes.get()))
        {
            findings.push(Finding::new(
                at,
                "selector-field-bounds",
                "declare exactly the bounded constraints required by this selector field type",
            ));
        }
    }
    findings
}
/// Presentation is inspected but does not enter the retained runtime field contract.
pub fn compiled(value: &Value) -> Value {
    let mut value = value.clone();
    if let Some(object) = value.as_object_mut() {
        object.remove("label");
        object.remove("description");
    }
    value
}
