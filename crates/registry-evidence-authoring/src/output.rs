//! Closed retained Output constraints and exact numeric bounds.
use crate::project::{self, Output};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Bound {
    Integer(i64),
    Decimal(String),
}
impl Serialize for Bound {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Integer(value) => serializer.serialize_i64(*value),
            Self::Decimal(value) => serializer.serialize_str(value),
        }
    }
}
impl<'de> Deserialize<'de> for Bound {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match Value::deserialize(deserializer)? {
            Value::Number(value) => value
                .as_i64()
                .filter(|value| (-9_007_199_254_740_991..=9_007_199_254_740_991).contains(value))
                .map(Self::Integer),
            Value::String(value) if decimal_coefficient(&value).is_some() => {
                Some(Self::Decimal(value))
            }
            _ => None,
        }
        .ok_or_else(|| {
            serde::de::Error::custom(
                "expected a JSON-safe integer or quoted canonical decimal text",
            )
        })
    }
}
#[cfg(feature = "schema")]
impl schemars::JsonSchema for Bound {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "OutputNumericBound".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({"anyOf":[{"type":"integer","minimum":-9007199254740991_i64,"maximum":9007199254740991_i64},{"type":"string","minLength":1,"maxLength":30,"pattern":"^-?(0|[1-9][0-9]*)(\\.[0-9]*[1-9])?$"}]})
    }
}
fn decimal_coefficient(text: &str) -> Option<i128> {
    if text.is_empty() || text.starts_with('+') || text == "-0" || text.starts_with("-0.") {
        return None;
    }
    let unsigned = text.strip_prefix('-').unwrap_or(text);
    let (integer, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    if integer.is_empty()
        || !integer.bytes().all(|b| b.is_ascii_digit())
        || (integer.len() > 1 && integer.starts_with('0'))
        || (text.contains('.') && (fraction.is_empty() || fraction.ends_with('0')))
        || !fraction.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 9
        || integer.len() + fraction.len() > 28
    {
        return None;
    }
    let magnitude = format!("{integer}{fraction:0<9}").parse::<i128>().ok()?;
    Some(if text.starts_with('-') {
        -magnitude
    } else {
        magnitude
    })
}
pub const TYPES: &[&str] = &[
    "boolean",
    "controlled-code",
    "controlled-category",
    "bounded-identifier",
    "bounded-integer",
    "bounded-decimal",
    "date-bucket",
    "time-bucket",
    "audience-scoped-entity-reference",
    "controlled-code-list",
    "entity-reference-list",
    "reviewed-structured-value",
];
fn version(text: &Option<String>) -> bool {
    text.as_ref().is_some_and(|text| {
        !text.is_empty() && text.chars().count() <= 128 && !text.chars().any(char::is_control)
    })
}
fn uri(text: &Option<String>) -> bool {
    text.as_ref().is_some_and(|text| {
        text.len() <= 512
            && !text.chars().any(|c| c.is_control() || c.is_whitespace())
            && url::Url::parse(text).is_ok()
    })
}
fn codelist(text: &Option<String>) -> bool {
    text.as_ref().is_some_and(|path| {
        path.starts_with("codelists/")
            && (project::valid_asset(path, "yaml") || project::valid_asset(path, "json"))
    })
}
fn collection(output: &Output) -> bool {
    output
        .minimum_items
        .zip(output.maximum_items)
        .is_some_and(|(min, max)| min <= max)
        && output.unique == Some(true)
}
/// Each tag permits exactly its retained constraint fields, with one inline category expansion.
pub fn valid(output: &Output) -> bool {
    let expected: &[&str] = match output.value_type.as_str() {
        "boolean" => &[],
        "controlled-code" => &["codelist", "codelistVersion", "maximumBytes"],
        "controlled-category" if !output.values.is_empty() => &["values"],
        "controlled-category" => &[
            "codelist",
            "categoryScheme",
            "schemeVersion",
            "maximumBytes",
        ],
        "bounded-identifier" => &["prefix", "minimumBytes", "maximumBytes"],
        "bounded-integer" => &["minimum", "maximum"],
        "bounded-decimal" => &["minimum", "maximum", "maximumScale"],
        "date-bucket" | "time-bucket" => &["bucketScheme", "schemeVersion", "codelist"],
        "audience-scoped-entity-reference" => &["maximumBytes"],
        "controlled-code-list" => &[
            "codelist",
            "codelistVersion",
            "minimumItems",
            "maximumItems",
            "unique",
        ],
        "entity-reference-list" => &["minimumItems", "maximumItems", "unique"],
        "reviewed-structured-value" => &["schema", "maximumSerializedBytes"],
        _ => return false,
    };
    let mut value = serde_json::to_value(output).expect("Output serializes");
    let fields = value.as_object_mut().expect("Output object");
    for field in ["concept", "type", "label", "description", "sdJwtVc"] {
        fields.remove(field);
    }
    if fields.len() != expected.len() || !expected.iter().all(|field| fields.contains_key(*field)) {
        return false;
    }
    match output.value_type.as_str() {
        "boolean" => true,
        "controlled-code" => codelist(&output.codelist) && version(&output.codelist_version),
        "controlled-category" if !output.values.is_empty() => {
            output.values.len() <= 32
                && output.values.iter().all(|v| valid_code(v) && v.len() <= 64)
                && output
                    .values
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    == output.values.len()
        }
        "controlled-category" => {
            codelist(&output.codelist)
                && uri(&output.category_scheme)
                && version(&output.scheme_version)
        }
        "bounded-identifier" => {
            output.prefix.as_ref().is_some_and(|prefix| {
                !prefix.is_empty()
                    && prefix.len() <= 512
                    && prefix
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-:/#".contains(&b))
                    && prefix
                        .as_bytes()
                        .last()
                        .is_some_and(|b| b"._-:/#".contains(b))
            }) && output
                .minimum_bytes
                .zip(output.maximum_bytes)
                .is_some_and(|(min, max)| {
                    min.get() <= max.get()
                        && max.get() <= 1024
                        && max.get() > output.prefix.as_ref().map_or(0, |p| p.len() as u64)
                })
        }
        "bounded-integer" => {
            matches!((&output.minimum,&output.maximum),(Some(Bound::Integer(min)),Some(Bound::Integer(max))) if min<=max)
        }
        "bounded-decimal" => {
            matches!((&output.minimum,&output.maximum),(Some(Bound::Decimal(min)),Some(Bound::Decimal(max))) if decimal_coefficient(min).zip(decimal_coefficient(max)).is_some_and(|(min,max)|min<=max))
                && output.maximum_scale.is_some()
        }
        "date-bucket" | "time-bucket" => {
            uri(&output.bucket_scheme)
                && version(&output.scheme_version)
                && codelist(&output.codelist)
        }
        "audience-scoped-entity-reference" => true,
        "controlled-code-list" => {
            codelist(&output.codelist) && version(&output.codelist_version) && collection(output)
        }
        "entity-reference-list" => collection(output),
        "reviewed-structured-value" => output.schema.as_ref().is_some_and(|path| {
            project::valid_asset(path, "yaml") || project::valid_asset(path, "json")
        }),
        _ => false,
    }
}
pub fn valid_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 128
        && code.as_bytes()[0].is_ascii_alphanumeric()
        && code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}
/// Project supplied codelist metadata through the shared YAML reader, preserving owned bytes.
pub fn codelist_value(path: &str, bytes: &[u8]) -> Option<Value> {
    let root = crate::formats::scan_authored(path, bytes)
        .ok()??
        .to_json_value();
    if root["apiVersion"] != "id.registrystack.org/formats/evidence/codelist/v1alpha1"
        || root["kind"] != "EvidenceCodelist"
        || !uri(&root["uri"].as_str().map(str::to_owned))
        || !version(&root["version"].as_str().map(str::to_owned))
    {
        return None;
    }
    let expected: &[&str] = match root["type"].as_str() {
        Some("code-list") => &["apiVersion", "kind", "uri", "version", "type", "codes"],
        Some("mapping") => &[
            "apiVersion",
            "kind",
            "uri",
            "version",
            "type",
            "entries",
            "allowedOutputs",
        ],
        _ => return None,
    };
    let object = root.as_object()?;
    if object.len() != expected.len() || !expected.iter().all(|name| object.contains_key(*name)) {
        return None;
    }
    let codes = match root["type"].as_str() {
        Some("code-list") => root["codes"].as_array()?,
        Some("mapping") => root["allowedOutputs"].as_array()?,
        _ => return None,
    };
    if codes.is_empty()
        || codes.len() > 4096
        || codes
            .iter()
            .any(|value| !value.as_str().is_some_and(valid_code))
        || codes
            .iter()
            .map(Value::to_string)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != codes.len()
    {
        return None;
    }
    if root["type"] == "mapping" {
        let entries = root["entries"].as_object()?;
        if entries.is_empty()
            || entries.len() > 4096
            || entries.iter().any(|(input, output)| {
                !valid_code(input)
                    || !output.as_str().is_some_and(valid_code)
                    || !codes.contains(output)
            })
        {
            return None;
        }
    }
    Some(root)
}
