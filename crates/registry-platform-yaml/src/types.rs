// SPDX-License-Identifier: Apache-2.0
//! Shared value types (CFG-SCHEMA-5) and the reader types CFG-ID-6,
//! CFG-QTY-4, and CFG-EMPTY-1 call for.
//!
//! Each type refuses a bad value through [`Invalid`], so the reader reports
//! it at the node, in its own words, without repeating the value.

use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;
use std::ops::Deref;

use serde::de::{self, Deserialize, Deserializer, Visitor};
use serde::{Serialize, Serializer};

use crate::de::{Invalid, BOUNDED, BOUNDED_EXPECTING, DATA_LITERAL};
use crate::messages::{
    TypeRule, EXPECT_DATA_LITERAL, EXPECT_DIGEST, EXPECT_EXTERNAL_ID, EXPECT_LOCAL_ID, EXPECT_URL,
    TYPE_RULES,
};

pub(crate) const DATA_LITERAL_EXPECTED: &str = EXPECT_DATA_LITERAL;

/// The longest external identifier accepted (CFG-ID-2).
pub const MAXIMUM_EXTERNAL_ID_CHARS: usize = 512;
/// The longest URL accepted (CFG-VAL-7).
pub const MAXIMUM_URL_CHARS: usize = 2048;

fn rule(expected: &'static str) -> Invalid {
    let rule: &TypeRule = TYPE_RULES
        .iter()
        .find(|rule| rule.expected == expected)
        .expect("every shared type has a rule");
    Invalid::expected(rule.expected, rule.action)
}

/// Deserialize text and check it with `parse`.
fn text_type<'de, D, T>(
    deserializer: D,
    parse: fn(String) -> Result<T, Invalid>,
) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
{
    let text = String::deserialize(deserializer)?;
    parse(text).map_err(de::Error::custom)
}

macro_rules! text_newtype {
    ($name:ident) => {
        impl $name {
            /// The value as written.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl Deref for $name {
            type Target = str;

            fn deref(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl std::str::FromStr for $name {
            type Err = Invalid;

            fn from_str(text: &str) -> Result<$name, Invalid> {
                $name::new(text)
            }
        }

        impl TryFrom<String> for $name {
            type Error = Invalid;

            fn try_from(text: String) -> Result<$name, Invalid> {
                $name::new(text)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> String {
                value.0
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<$name, D::Error> {
                text_type(deserializer, $name::new)
            }
        }
    };
}

/// A local identifier: `^[a-z][a-z0-9_-]{0,63}$` (CFG-ID-1). Schema name
/// `LocalId`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LocalId(String);

impl LocalId {
    pub fn new(text: impl Into<String>) -> Result<LocalId, Invalid> {
        let text = text.into();
        let bytes = text.as_bytes();
        let valid = matches!(bytes.first(), Some(b'a'..=b'z'))
            && bytes.len() <= 64
            && bytes
                .iter()
                .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'));
        if valid {
            Ok(LocalId(text))
        } else {
            Err(rule(EXPECT_LOCAL_ID))
        }
    }
}

text_newtype!(LocalId);

/// An identifier another system issues (a client id, a claim name, a scope,
/// a URN), kept exactly as written: 1 to 512 characters, no control
/// characters (CFG-ID-2). Schema name `ExternalId`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExternalId(String);

impl ExternalId {
    pub fn new(text: impl Into<String>) -> Result<ExternalId, Invalid> {
        let text = text.into();
        let count = text.chars().count();
        if count == 0 || count > MAXIMUM_EXTERNAL_ID_CHARS || text.chars().any(char::is_control) {
            return Err(rule(EXPECT_EXTERNAL_ID));
        }
        Ok(ExternalId(text))
    }
}

text_newtype!(ExternalId);

/// A SHA-256 digest written `sha256:` followed by 64 lowercase hex digits
/// (CFG-VAL-6). Schema name `Digest`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest(String);

impl Digest {
    pub fn new(text: impl Into<String>) -> Result<Digest, Invalid> {
        let text = text.into();
        let valid = text.strip_prefix("sha256:").is_some_and(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        });
        if valid {
            Ok(Digest(text))
        } else {
            Err(rule(EXPECT_DIGEST))
        }
    }

    /// The 64 hex digits after `sha256:`.
    pub fn hex(&self) -> &str {
        &self.0["sha256:".len()..]
    }
}

text_newtype!(Digest);

/// An absolute `http` or `https` URL with a host, no user information, no
/// backslash, whitespace or control character, and at most 2048 characters (CFG-VAL-7),
/// kept as written. Whether a position also refuses `http` is the owning
/// product's decision: it checks [`Url::is_https`] and says so in the
/// member's schema description. Schema name `Url`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Url(String);

impl Url {
    pub fn new(text: impl Into<String>) -> Result<Url, Invalid> {
        let text = text.into();
        if text.chars().count() > MAXIMUM_URL_CHARS {
            return Err(rule(EXPECT_URL));
        }
        // The parser trims a space or control character at either end and
        // drops a tab or line break anywhere, without an error. Refusing
        // them here keeps the text as written and the URL as parsed the same
        // URL.
        if text.contains('\\')
            || text
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
        {
            return Err(rule(EXPECT_URL));
        }
        let Ok(parsed) = url::Url::parse(&text) else {
            return Err(rule(EXPECT_URL));
        };
        let scheme_written = text
            .get(..parsed.scheme().len() + 3)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(&format!("{}://", parsed.scheme())));
        // The authority as written, up to the first `/`, `?`, or `#`, as the
        // schema's pattern reads it: the parser reports no user information
        // for an empty one, and the pattern refuses any `@` there.
        let authority = text.get(parsed.scheme().len() + 3..).map(|rest| {
            let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
            &rest[..end]
        });
        let host_matches = authority.is_some_and(|authority| {
            // DNS case is immaterial; every other parser rewrite, including
            // IDNA conversion and percent decoding, changes the written host.
            // IPv6 has several ordinary spellings of the same numeric address.
            let written = if authority.starts_with('[') {
                authority.find(']').map(|end| &authority[..=end])
            } else {
                authority.split(':').next()
            };
            match (written, parsed.host()) {
                (Some(written), Some(url::Host::Domain(host))) => {
                    written.eq_ignore_ascii_case(host)
                }
                (Some(written), Some(url::Host::Ipv4(host))) => written == host.to_string(),
                (Some(written), Some(url::Host::Ipv6(host))) => written
                    .strip_prefix('[')
                    .and_then(|text| text.strip_suffix(']'))
                    .and_then(|text| text.parse::<std::net::Ipv6Addr>().ok())
                    .is_some_and(|written| written == host),
                _ => false,
            }
        });
        let valid = matches!(parsed.scheme(), "http" | "https")
            && scheme_written
            && parsed.host_str().is_some_and(|host| !host.is_empty())
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && authority.is_some_and(|authority| !authority.contains('@'))
            && host_matches;
        if valid {
            Ok(Url(text))
        } else {
            Err(rule(EXPECT_URL))
        }
    }

    pub fn is_https(&self) -> bool {
        self.0
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
    }

    /// The parsed URL.
    pub fn to_url(&self) -> url::Url {
        url::Url::parse(&self.0).expect("a Url was parsed when it was made")
    }
}

text_newtype!(Url);

/// The members that name a project (CFG-ENV-6): a project's `project` block
/// holds these, and may add project-wide members of the product's own.
/// Schema name `ProjectIdentity`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ProjectIdentity {
    pub id: LocalId,
    pub version: String,
}

/// A record value a format compares: the one position where `null` is a
/// value (CFG-EMPTY-1). Lists and mappings are refused.
#[derive(Clone, Debug, PartialEq)]
pub enum DataLiteral {
    Null,
    Boolean(bool),
    Number(serde_json::Number),
    String(String),
}

impl Serialize for DataLiteral {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            DataLiteral::Null => serializer.serialize_unit(),
            DataLiteral::Boolean(value) => serializer.serialize_bool(*value),
            DataLiteral::Number(value) => value.serialize(serializer),
            DataLiteral::String(value) => serializer.serialize_str(value),
        }
    }
}

impl<'de> Deserialize<'de> for DataLiteral {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<DataLiteral, D::Error> {
        struct Outer;

        impl<'de> Visitor<'de> for Outer {
            type Value = DataLiteral;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(EXPECT_DATA_LITERAL)
            }

            fn visit_newtype_struct<D: Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<DataLiteral, D::Error> {
                deserializer.deserialize_any(Literal)
            }
        }

        struct Literal;

        impl<'de> Visitor<'de> for Literal {
            type Value = DataLiteral;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(EXPECT_DATA_LITERAL)
            }

            fn visit_unit<E: de::Error>(self) -> Result<DataLiteral, E> {
                Ok(DataLiteral::Null)
            }

            fn visit_none<E: de::Error>(self) -> Result<DataLiteral, E> {
                Ok(DataLiteral::Null)
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> Result<DataLiteral, E> {
                Ok(DataLiteral::Boolean(value))
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<DataLiteral, E> {
                Ok(DataLiteral::Number(value.into()))
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<DataLiteral, E> {
                Ok(DataLiteral::Number(value.into()))
            }

            fn visit_f64<E: de::Error>(self, value: f64) -> Result<DataLiteral, E> {
                serde_json::Number::from_f64(value)
                    .map(DataLiteral::Number)
                    .ok_or_else(|| Invalid::expected(EXPECT_DATA_LITERAL, "").into_error())
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<DataLiteral, E> {
                Ok(DataLiteral::String(value.to_string()))
            }

            fn visit_string<E: de::Error>(self, value: String) -> Result<DataLiteral, E> {
                Ok(DataLiteral::String(value))
            }
        }

        deserializer.deserialize_newtype_struct(DATA_LITERAL, Outer)
    }
}

macro_rules! bounded {
    ($name:ident, $int:ty, $format:literal) => {
        /// An integer from `MIN` to `MAX` inclusive (CFG-QTY-4). Both bounds
        /// are in the schema, and the reader refuses a value outside them
        /// with `config.out-of-range`, naming the bounds and the unit the
        /// member's key carries.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name<const MIN: $int, const MAX: $int>($int);

        impl<const MIN: $int, const MAX: $int> $name<MIN, MAX> {
            pub const MINIMUM: $int = MIN;
            pub const MAXIMUM: $int = MAX;

            pub fn new(value: $int) -> Result<Self, Invalid> {
                if (MIN..=MAX).contains(&value) {
                    Ok($name(value))
                } else {
                    Err(Invalid::out_of_range(MIN, MAX))
                }
            }

            pub const fn get(self) -> $int {
                self.0
            }
        }

        impl<const MIN: $int, const MAX: $int> From<$name<MIN, MAX>> for $int {
            fn from(value: $name<MIN, MAX>) -> $int {
                value.0
            }
        }

        impl<const MIN: $int, const MAX: $int> TryFrom<$int> for $name<MIN, MAX> {
            type Error = Invalid;

            fn try_from(value: $int) -> Result<Self, Invalid> {
                $name::new(value)
            }
        }

        impl<const MIN: $int, const MAX: $int> fmt::Display for $name<MIN, MAX> {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, formatter)
            }
        }

        impl<const MIN: $int, const MAX: $int> Serialize for $name<MIN, MAX> {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                self.0.serialize(serializer)
            }
        }

        impl<'de, const MIN: $int, const MAX: $int> Deserialize<'de> for $name<MIN, MAX> {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct Bounded<const MIN: $int, const MAX: $int>;

                impl<'de, const MIN: $int, const MAX: $int> Visitor<'de> for Bounded<MIN, MAX> {
                    type Value = $name<MIN, MAX>;

                    // The reader reads the bounds from this text.
                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        write!(formatter, "{BOUNDED_EXPECTING}{MIN} to {MAX}")
                    }

                    fn visit_newtype_struct<D: Deserializer<'de>>(
                        self,
                        deserializer: D,
                    ) -> Result<Self::Value, D::Error> {
                        let value = <$int>::deserialize(deserializer)?;
                        $name::new(value).map_err(de::Error::custom)
                    }
                }

                deserializer.deserialize_newtype_struct(BOUNDED, Bounded::<MIN, MAX>)
            }
        }

        #[cfg(feature = "schema")]
        impl<const MIN: $int, const MAX: $int> schemars::JsonSchema for $name<MIN, MAX> {
            fn inline_schema() -> bool {
                true
            }

            fn schema_name() -> std::borrow::Cow<'static, str> {
                std::borrow::Cow::Owned(format!("{}_{}_{}", stringify!($name), MIN, MAX))
            }

            fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
                schemars::json_schema!({
                    "type": "integer",
                    "format": $format,
                    "minimum": MIN,
                    "maximum": MAX,
                })
            }
        }
    };
}

bounded!(BoundedU32, u32, "uint32");
bounded!(BoundedU64, u64, "uint64");

/// A list that is a set: a repeated item is refused with
/// `config.duplicate-item` instead of being collapsed (CFG-ID-6). Its schema
/// declares `uniqueItems: true`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UniqueList<T>(Vec<T>);

impl<T: Eq + Hash> UniqueList<T> {
    pub fn new(items: Vec<T>) -> Result<UniqueList<T>, Invalid> {
        let mut seen: HashMap<&T, usize> = HashMap::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            if let Some(first) = seen.insert(item, index) {
                return Err(Invalid::duplicate_item(first, index));
            }
        }
        Ok(UniqueList(items))
    }
}

impl<T> UniqueList<T> {
    pub fn into_vec(self) -> Vec<T> {
        self.0
    }
}

impl<T> Default for UniqueList<T> {
    fn default() -> UniqueList<T> {
        UniqueList(Vec::new())
    }
}

impl<T> Deref for UniqueList<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.0
    }
}

impl<'l, T> IntoIterator for &'l UniqueList<T> {
    type Item = &'l T;
    type IntoIter = std::slice::Iter<'l, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T> IntoIterator for UniqueList<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T: Serialize> Serialize for UniqueList<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de> + Eq + Hash> Deserialize<'de> for UniqueList<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let items = Vec::<T>::deserialize(deserializer)?;
        UniqueList::new(items).map_err(de::Error::custom)
    }
}

/// An item of a [`UniqueIdList`]: a mapping with an `id` member.
pub trait Identified {
    fn id(&self) -> &str;
}

/// Named items whose order carries meaning: a list of mappings, each with an
/// `id` member, unique in the list (CFG-ID-5). A repeated id is refused with
/// `config.duplicate-id` at the second item's `id`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UniqueIdList<T>(Vec<T>);

impl<T: Identified> UniqueIdList<T> {
    pub fn new(items: Vec<T>) -> Result<UniqueIdList<T>, Invalid> {
        let mut seen: HashMap<&str, usize> = HashMap::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            if let Some(first) = seen.insert(item.id(), index) {
                return Err(Invalid::duplicate_id(first, index));
            }
        }
        Ok(UniqueIdList(items))
    }

    /// The item with this id.
    pub fn get(&self, id: &str) -> Option<&T> {
        self.0.iter().find(|item| item.id() == id)
    }
}

impl<T> UniqueIdList<T> {
    pub fn into_vec(self) -> Vec<T> {
        self.0
    }
}

impl<T> Default for UniqueIdList<T> {
    fn default() -> UniqueIdList<T> {
        UniqueIdList(Vec::new())
    }
}

impl<T> Deref for UniqueIdList<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.0
    }
}

impl<'l, T> IntoIterator for &'l UniqueIdList<T> {
    type Item = &'l T;
    type IntoIter = std::slice::Iter<'l, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T> IntoIterator for UniqueIdList<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T: Serialize> Serialize for UniqueIdList<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de> + Identified> Deserialize<'de> for UniqueIdList<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let items = Vec::<T>::deserialize(deserializer)?;
        UniqueIdList::new(items).map_err(de::Error::custom)
    }
}

#[cfg(feature = "schema")]
mod schema {
    use std::borrow::Cow;

    use schemars::{json_schema, JsonSchema, Schema, SchemaGenerator};

    use super::*;

    impl JsonSchema for LocalId {
        fn schema_name() -> Cow<'static, str> {
            Cow::Borrowed("LocalId")
        }

        fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
            json_schema!({
                "type": "string",
                "pattern": "^[a-z][a-z0-9_-]{0,63}$",
                "description": "A local identifier: a lowercase letter, then up to 63 lowercase letters, digits, `_`, or `-`.",
            })
        }
    }

    impl JsonSchema for ExternalId {
        fn schema_name() -> Cow<'static, str> {
            Cow::Borrowed("ExternalId")
        }

        fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
            json_schema!({
                "type": "string",
                "minLength": 1,
                "maxLength": MAXIMUM_EXTERNAL_ID_CHARS,
                "pattern": "^[^\\u0000-\\u001F\\u007F-\\u009F]+$",
                "description": "An identifier another system issues, written exactly as its issuer gives it.",
            })
        }
    }

    impl JsonSchema for Digest {
        fn schema_name() -> Cow<'static, str> {
            Cow::Borrowed("Digest")
        }

        fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
            json_schema!({
                "type": "string",
                "pattern": "^sha256:[0-9a-f]{64}$",
                "description": "A SHA-256 digest: `sha256:` followed by 64 lowercase hex digits.",
            })
        }
    }

    /// The class in [`URL_PATTERN`] lists every character that
    /// `char::is_whitespace` or `char::is_control` accepts, by code point, so
    /// that every regular expression engine reads the same set.
    // Keep this definition identical to the frozen Version 1 contracts.
    // The reader additionally refuses backslashes and rewritten hosts.
    const URL_PATTERN: &str = "^[Hh][Tt][Tt][Pp][Ss]?://[^/?#@\\u0000-\\u0020\\u007F-\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000]+([/?#][^\\u0000-\\u0020\\u007F-\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000]*)?$";

    impl JsonSchema for Url {
        fn schema_name() -> Cow<'static, str> {
            Cow::Borrowed("Url")
        }

        fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
            json_schema!({
                "type": "string",
                "format": "uri",
                "maxLength": MAXIMUM_URL_CHARS,
                "pattern": URL_PATTERN,
                "description": "An absolute http or https URL with a host, no user information, and no whitespace or control character.",
            })
        }
    }

    impl JsonSchema for DataLiteral {
        fn schema_name() -> Cow<'static, str> {
            Cow::Borrowed("DataLiteral")
        }

        fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
            json_schema!({
                "type": ["null", "boolean", "number", "string"],
                "description": "A record value: null, a boolean, a number, or text.",
            })
        }
    }

    impl<T: JsonSchema> JsonSchema for UniqueList<T> {
        fn inline_schema() -> bool {
            true
        }

        fn schema_name() -> Cow<'static, str> {
            Cow::Owned(format!("UniqueList_{}", T::schema_name()))
        }

        fn json_schema(generator: &mut SchemaGenerator) -> Schema {
            json_schema!({
                "type": "array",
                "items": generator.subschema_for::<T>(),
                "uniqueItems": true,
            })
        }
    }

    impl<T: JsonSchema> JsonSchema for UniqueIdList<T> {
        fn inline_schema() -> bool {
            true
        }

        fn schema_name() -> Cow<'static, str> {
            Cow::Owned(format!("UniqueIdList_{}", T::schema_name()))
        }

        fn json_schema(generator: &mut SchemaGenerator) -> Schema {
            json_schema!({
                "type": "array",
                "items": generator.subschema_for::<T>(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cfg_id_1_local_id_grammar() {
        for good in [
            "a",
            "person",
            "date-of-birth",
            "date_of_birth",
            "a1",
            &"a".repeat(64),
        ] {
            assert!(LocalId::new(good).is_ok(), "{good}");
        }
        for bad in ["", "A", "1a", "-a", "a.b", "a b", "é", &"a".repeat(65)] {
            assert!(LocalId::new(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn cfg_id_2_external_id_is_kept_as_written() {
        for good in [
            "client.example",
            "urn:x:y",
            "Scope With Spaces",
            &"x".repeat(512),
        ] {
            assert_eq!(ExternalId::new(good).unwrap().as_str(), good);
        }
        for bad in ["", "a\u{7}b", "a\nb", "a\u{85}b", &"x".repeat(513)] {
            assert!(ExternalId::new(bad).is_err());
        }
    }

    #[test]
    fn cfg_val_6_digest_grammar() {
        let hex = "0123456789abcdef".repeat(4);
        assert_eq!(Digest::new(format!("sha256:{hex}")).unwrap().hex(), hex);
        assert!(Digest::new(format!("sha256:{}", hex.to_uppercase())).is_err());
        assert!(Digest::new(format!("sha512:{hex}")).is_err());
        assert!(Digest::new(format!("sha256:{}", &hex[1..])).is_err());
    }

    #[test]
    fn cfg_val_7_url_rule() {
        for good in [
            "https://issuer.example",
            "http://127.0.0.1:8080/path?q=1",
            "HTTPS://Issuer.Example/",
            "https://issuer.example/users/a@b?c=d@e#f@g",
        ] {
            assert_eq!(Url::new(good).unwrap().as_str(), good);
        }
        for bad in [
            "issuer.example",
            "/relative",
            "ftp://issuer.example",
            "https://user:pass@issuer.example",
            "https://user@issuer.example",
            "https://@issuer.example",
            "https://:@issuer.example",
            "https://@issuer.example/path",
            "file:///etc/passwd",
            "https:issuer.example",
        ] {
            assert!(Url::new(bad).is_err(), "{bad}");
        }
        let long = format!("https://issuer.example/{}", "a".repeat(2048));
        assert!(Url::new(long).is_err());
        assert!(Url::new("https://issuer.example").unwrap().is_https());
        assert!(!Url::new("http://issuer.example").unwrap().is_https());
    }

    #[test]
    fn cfg_val_7_url_refuses_backslashes() {
        for text in [
            "https://issuer.example\\other",
            "https://issuer.example/a\\b",
            "https://issuer.example?x=\\y",
            "https://issuer.example#\\fragment",
        ] {
            assert!(Url::new(text).is_err(), "{text}");
        }
        assert!(Url::new("https://issuer.example/a%5Cb").is_ok());
    }

    #[test]
    fn cfg_val_7_url_refuses_a_host_the_parser_rewrites() {
        for text in [
            "https://iss\u{200b}uer.example",
            "https://iss\u{ad}uer.example",
            "https://iss\u{feff}uer.example",
            "https://issuer\u{3002}example",
            "https://caf\u{e9}.example",
            "https://%69ssuer.example",
            "https://127.1",
        ] {
            assert!(Url::new(text).is_err(), "{text}");
        }
        for text in [
            "https://issuer.example/path",
            "HTTPS://Issuer.Example/path",
            "https://xn--caf-dma.example/path",
            "http://127.0.0.1:8080/path",
            "https://[::1]:8443/path",
            "https://[2001:0DB8:0:0:0:0:0:1]/path",
        ] {
            assert_eq!(Url::new(text).expect("unchanged host").as_str(), text);
        }
    }

    #[test]
    fn cfg_val_7_url_holds_no_whitespace_and_no_control_character() {
        // The parser drops each of these without an error, so the text kept
        // would name a different URL than the one parsed.
        for (case, bad) in [
            ("leading space", " https://issuer.example"),
            ("trailing space", "https://issuer.example "),
            ("trailing control character", "https://issuer.example\u{1}"),
            ("leading control character", "\u{1f}https://issuer.example"),
            ("trailing NUL", "https://issuer.example\0"),
            ("inner tab", "https://issuer.example/a\tb"),
            ("tab in the host", "https://issuer\t.example"),
            ("inner line feed", "https://issuer.example/a\nb"),
            ("trailing line feed", "https://issuer.example\n"),
            ("inner carriage return", "https://issuer.example/a\rb"),
            ("tab in the scheme", "ht\ttps://issuer.example"),
            // The parser keeps or percent-encodes these; one rule covers
            // every whitespace and control character.
            ("inner space", "https://issuer.example/a b"),
            ("space in the query", "https://issuer.example/?a= b"),
            ("inner delete", "https://issuer.example/a\u{7f}b"),
            ("inner C1 control", "https://issuer.example/a\u{85}b"),
            ("no-break space", "https://issuer.example/a\u{a0}b"),
            ("line separator", "https://issuer.example/a\u{2028}b"),
            ("ideographic space", "https://issuer.example/a\u{3000}b"),
        ] {
            assert!(Url::new(bad).is_err(), "{case}");
        }
        for good in [
            "https://issuer.example/a%20b",
            "https://issuer.example/a%09b",
            "https://issuer.example/caf\u{e9}",
        ] {
            assert_eq!(Url::new(good).unwrap().as_str(), good);
        }
    }

    #[test]
    fn cfg_qty_4_bounded_new_checks_both_bounds() {
        assert!(BoundedU32::<1, 10>::new(0).is_err());
        assert_eq!(BoundedU32::<1, 10>::new(1).unwrap().get(), 1);
        assert_eq!(BoundedU32::<1, 10>::new(10).unwrap().get(), 10);
        assert!(BoundedU32::<1, 10>::new(11).is_err());
        assert!(BoundedU64::<0, { u64::MAX }>::new(u64::MAX).is_ok());
    }

    #[test]
    fn cfg_id_6_unique_list_refuses_a_repeat() {
        assert_eq!(UniqueList::new(vec![1, 2, 3]).unwrap().len(), 3);
        assert_eq!(
            UniqueList::new(vec![1, 2, 1]).unwrap_err(),
            Invalid::duplicate_item(0, 2)
        );
    }

    #[test]
    fn cfg_val_6_invalid_text_never_repeats_the_value() {
        let error = Digest::new("sha256:MARKER-7f3a9c").unwrap_err().to_string();
        assert!(!error.contains("MARKER-7f3a9c"));
    }

    #[test]
    fn data_literal_reads_from_a_foreign_deserializer() {
        let values: Vec<DataLiteral> =
            serde_json::from_str(r#"[null, true, 3, 2.5, "text"]"#).unwrap();
        assert_eq!(
            values,
            vec![
                DataLiteral::Null,
                DataLiteral::Boolean(true),
                DataLiteral::Number(3.into()),
                DataLiteral::Number(serde_json::Number::from_f64(2.5).unwrap()),
                DataLiteral::String("text".to_string()),
            ]
        );
        assert!(serde_json::from_str::<DataLiteral>("[1]").is_err());
    }
}
