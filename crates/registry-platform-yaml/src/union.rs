// SPDX-License-Identifier: Apache-2.0
//! Union helpers that keep source positions inside variants (CFG-ID-7,
//! CFG-SCHEMA-8).
//!
//! serde's derived internally tagged and untagged enums buffer the whole
//! mapping without positions before choosing a variant. These helpers let
//! the reader choose the variant from the node itself, so every error inside
//! a variant keeps its path, line, and column. Other deserializers still
//! work: the helpers buffer their input and decode it the same way.

/// Decode an enum as an internally tagged union: a `type` member (or the
/// member named by `tag = "..."`) names the variant, and the variant's
/// members sit beside it.
///
/// The enum derives `Deserialize` with `#[serde(remote = "Self")]`, so the
/// derived code becomes an inherent function this macro calls. Every variant
/// is a struct variant, including one with no members (`Variant {}`). The
/// variant names are the tag's values, so the enum usually carries
/// `#[serde(rename_all = "kebab-case", rename_all_fields = "camelCase")]`.
///
/// ```
/// use registry_platform_yaml::tagged_union;
/// use serde::Deserialize;
///
/// #[derive(Debug, Deserialize)]
/// #[serde(remote = "Self", rename_all = "kebab-case", rename_all_fields = "camelCase")]
/// enum Source {
///     Http { base_url: String },
///     None {},
/// }
/// tagged_union!(Source);
///
/// let source: Source = serde_json::from_str(r#"{"type": "http", "baseUrl": "x"}"#).unwrap();
/// assert!(matches!(source, Source::Http { .. }));
/// ```
///
/// For a schema, derive `JsonSchema` with
/// `#[schemars(!remote, tag = "type")]`, so the schema describes the tagged
/// form rather than serde's remote derive.
#[macro_export]
macro_rules! tagged_union {
    ($type:ty) => {
        $crate::tagged_union!($type, tag = "type");
    };
    ($type:ty, tag = $tag:literal) => {
        impl<'de> ::serde::Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> ::core::result::Result<Self, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                struct TaggedVisitor;

                impl<'de> ::serde::de::Visitor<'de> for TaggedVisitor {
                    type Value = $type;

                    fn expecting(
                        &self,
                        formatter: &mut ::core::fmt::Formatter<'_>,
                    ) -> ::core::fmt::Result {
                        formatter.write_str(::core::concat!(
                            "a mapping whose `",
                            $tag,
                            "` member names its form"
                        ))
                    }

                    fn visit_enum<A>(self, data: A) -> ::core::result::Result<$type, A::Error>
                    where
                        A: ::serde::de::EnumAccess<'de>,
                    {
                        <$type>::deserialize(::serde::de::value::EnumAccessDeserializer::new(data))
                    }

                    fn visit_newtype_struct<E>(
                        self,
                        deserializer: E,
                    ) -> ::core::result::Result<$type, E::Error>
                    where
                        E: ::serde::Deserializer<'de>,
                    {
                        let value =
                            <$crate::__private::Value as ::serde::Deserialize>::deserialize(
                                deserializer,
                            )?;
                        let external = $crate::__private::tagged_to_external(value, $tag)?;
                        <$type>::deserialize(external).map_err(::serde::de::Error::custom)
                    }
                }

                deserializer.deserialize_newtype_struct(
                    ::core::concat!("\0registry-platform-yaml/tagged/", $tag),
                    TaggedVisitor,
                )
            }
        }
    };
}

/// Decode an enum whose variants differ by node kind: `scalar`, `list`, or
/// `mapping` (CFG-SCHEMA-8). Each variant holds one value, and each node
/// kind maps to at most one variant. The enum does not derive
/// `Deserialize`; this macro writes it.
///
/// ```
/// use registry_platform_yaml::shape_union;
///
/// #[derive(Debug)]
/// enum Scopes {
///     One(String),
///     Many(Vec<String>),
/// }
/// shape_union!(Scopes { scalar => One, list => Many });
///
/// let scopes: Scopes = serde_json::from_str(r#"["a", "b"]"#).unwrap();
/// assert!(matches!(scopes, Scopes::Many(_)));
/// ```
///
/// For a schema, derive `JsonSchema` with `#[schemars(untagged)]`; serde
/// never reads that attribute, so decoding still goes through this macro.
#[macro_export]
macro_rules! shape_union {
    ($type:ident { $($shape:ident => $variant:ident),+ $(,)? }) => {
        const _: () = {
            $( $crate::__private::assert_shape(::core::stringify!($shape)); )+
        };

        impl<'de> ::serde::Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> ::core::result::Result<Self, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                struct ShapeVisitor;

                impl<'de> ::serde::de::Visitor<'de> for ShapeVisitor {
                    type Value = $type;

                    fn expecting(
                        &self,
                        formatter: &mut ::core::fmt::Formatter<'_>,
                    ) -> ::core::fmt::Result {
                        formatter.write_str(::core::concat!(
                            "one of"
                            $(, " ", ::core::stringify!($shape))+
                        ))
                    }

                    fn visit_enum<A>(self, data: A) -> ::core::result::Result<$type, A::Error>
                    where
                        A: ::serde::de::EnumAccess<'de>,
                    {
                        let (shape, variant): (::std::string::String, A::Variant) =
                            ::serde::de::EnumAccess::variant(data)?;
                        $(
                            if shape == ::core::stringify!($shape) {
                                return ::serde::de::VariantAccess::newtype_variant(variant)
                                    .map($type::$variant);
                            }
                        )+
                        ::core::result::Result::Err(::serde::de::Error::custom(
                            $crate::__private::unmatched_shape(),
                        ))
                    }

                    fn visit_newtype_struct<E>(
                        self,
                        deserializer: E,
                    ) -> ::core::result::Result<$type, E::Error>
                    where
                        E: ::serde::Deserializer<'de>,
                    {
                        let value = <$crate::__private::Value as ::serde::Deserialize>::deserialize(
                            deserializer,
                        )?;
                        let shape = $crate::__private::shape_of(&value);
                        $(
                            if shape == ::core::stringify!($shape) {
                                return $crate::__private::from_value(value)
                                    .map($type::$variant)
                                    .map_err(::serde::de::Error::custom);
                            }
                        )+
                        ::core::result::Result::Err(::serde::de::Error::custom(
                            $crate::__private::unmatched_shape(),
                        ))
                    }
                }

                deserializer.deserialize_newtype_struct(
                    ::core::concat!(
                        "\0registry-platform-yaml/shape/"
                        $(, ::core::stringify!($shape), ",")+
                    ),
                    ShapeVisitor,
                )
            }
        }
    };
}

#[doc(hidden)]
pub mod __private {
    use serde::de::{self, DeserializeOwned};
    pub use serde_json::Value;

    use crate::de::Invalid;

    pub const fn assert_shape(shape: &str) {
        let known = matches!(shape.as_bytes(), b"scalar" | b"list" | b"mapping");
        assert!(known, "a shape union names scalar, list, or mapping");
    }

    pub fn unmatched_shape() -> Invalid {
        Invalid::expected("a value of a shape this union accepts", "")
    }

    pub fn shape_of(value: &Value) -> &'static str {
        match value {
            Value::Array(_) => "list",
            Value::Object(_) => "mapping",
            Value::Null => "null",
            _ => "scalar",
        }
    }

    pub fn from_value<T: DeserializeOwned>(value: Value) -> Result<T, serde_json::Error> {
        T::deserialize(value)
    }

    /// An internally tagged mapping, rewritten as the externally tagged one
    /// serde's derived enum reads.
    pub fn tagged_to_external<E: de::Error>(value: Value, tag: &'static str) -> Result<Value, E> {
        let Value::Object(mut members) = value else {
            return Err(Invalid::expected("a mapping", "").into_error());
        };
        let Some(name) = members.remove(tag) else {
            return Err(E::missing_field(tag));
        };
        let Value::String(name) = name else {
            return Err(Invalid::expected("text naming the form", "").into_error());
        };
        let mut external = serde_json::Map::new();
        external.insert(name, Value::Object(members));
        Ok(Value::Object(external))
    }
}
