// SPDX-License-Identifier: Apache-2.0
//! Members a Casework file reads through a `registry-platform-yaml` type
//! while the model keeps the plain value: the reader refuses what the shared
//! type refuses, with its code and position, and the schema states the same
//! rule through `schemars(with = ...)` on the member. The project and the
//! runtime configuration both read through these.

use std::{collections::BTreeMap, hash::Hash};

use registry_platform_yaml::{
    BoundedU32, BoundedU64, Digest, ExternalId, Identified, LocalId, UniqueIdList, UniqueList, Url,
};
use serde::{Deserialize, Deserializer};

/// A whole number from `MIN` to `MAX` (CFG-QTY-4).
pub fn bounded_u32<'de, D, const MIN: u32, const MAX: u32>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    BoundedU32::<MIN, MAX>::deserialize(deserializer).map(BoundedU32::get)
}

/// An optional member holding a whole number from `MIN` to `MAX`
/// (CFG-QTY-4); absent reads as `None` through `serde(default)`.
pub fn optional_bounded_u32<'de, D, const MIN: u32, const MAX: u32>(
    deserializer: D,
) -> Result<Option<u32>, D::Error>
where
    D: Deserializer<'de>,
{
    bounded_u32::<D, MIN, MAX>(deserializer).map(Some)
}

/// A whole number from `MIN` to `MAX` (CFG-QTY-4), kept as `u16`.
pub fn bounded_u16<'de, D, const MIN: u32, const MAX: u32>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    const { assert!(MAX <= u16::MAX as u32) };
    let value = BoundedU32::<MIN, MAX>::deserialize(deserializer)?.get();
    Ok(value as u16)
}

/// A whole number from `MIN` to `MAX` (CFG-QTY-4), kept as `usize`.
pub fn bounded_usize<'de, D, const MIN: u32, const MAX: u32>(
    deserializer: D,
) -> Result<usize, D::Error>
where
    D: Deserializer<'de>,
{
    BoundedU32::<MIN, MAX>::deserialize(deserializer).map(|value| value.get() as usize)
}

/// A whole number from `MIN` to `MAX` (CFG-QTY-4).
pub fn bounded_u64<'de, D, const MIN: u64, const MAX: u64>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    BoundedU64::<MIN, MAX>::deserialize(deserializer).map(BoundedU64::get)
}

/// An optional member holding a whole number from `MIN` to `MAX`
/// (CFG-QTY-4); absent reads as `None` through `serde(default)`.
pub fn optional_bounded_u64<'de, D, const MIN: u64, const MAX: u64>(
    deserializer: D,
) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    bounded_u64::<D, MIN, MAX>(deserializer).map(Some)
}

/// A list that is a set: a repeated item is refused (CFG-ID-6).
pub fn unique_list<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Eq + Hash,
{
    UniqueList::<T>::deserialize(deserializer).map(UniqueList::into_vec)
}

/// Named items, unique by `id` (CFG-ID-5): a repeated id is refused at the
/// second item's `id`.
pub fn unique_id_list<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Identified,
{
    UniqueIdList::<T>::deserialize(deserializer).map(UniqueIdList::into_vec)
}

/// An absolute `http` or `https` URL (CFG-VAL-7), kept as written.
pub fn url<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    Url::deserialize(deserializer).map(Url::into_string)
}

/// An optional member holding an absolute `http` or `https` URL
/// (CFG-VAL-7); absent reads as `None` through `serde(default)`.
pub fn optional_url<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    url(deserializer).map(Some)
}

/// An optional member holding a `sha256:` digest (CFG-VAL-6), kept as
/// written; absent reads as `None` through `serde(default)`.
pub fn optional_digest<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Digest::deserialize(deserializer)
        .map(Digest::into_string)
        .map(Some)
}

/// A local identifier (CFG-ID-1), kept as written.
pub fn local_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    LocalId::deserialize(deserializer).map(LocalId::into_string)
}

/// Whether `value` follows the local identifier grammar (CFG-ID-1), for a
/// project built in memory rather than read.
pub(crate) fn valid_local_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_lowercase()
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(*byte, b'-' | b'_')
        })
}

/// A mapping keyed by local identifiers (CFG-ID-1), keys kept as written.
pub fn local_id_keys<'de, D, V>(deserializer: D) -> Result<BTreeMap<String, V>, D::Error>
where
    D: Deserializer<'de>,
    V: Deserialize<'de>,
{
    BTreeMap::<LocalId, V>::deserialize(deserializer).map(|map| {
        map.into_iter()
            .map(|(key, value)| (key.into_string(), value))
            .collect()
    })
}

/// A mapping keyed by external identifiers (CFG-ID-2), such as claim names,
/// keys kept as written.
pub fn external_id_keys<'de, D, V>(deserializer: D) -> Result<BTreeMap<String, V>, D::Error>
where
    D: Deserializer<'de>,
    V: Deserialize<'de>,
{
    BTreeMap::<ExternalId, V>::deserialize(deserializer).map(|map| {
        map.into_iter()
            .map(|(key, value)| (key.into_string(), value))
            .collect()
    })
}

/// Named items written as a mapping from each item's id to the rest of the
/// item (CFG-ID-5), kept as a list sorted by id. The key is read as the
/// item's `id` member, so it is checked as the item checks its id, and a
/// mapping cannot repeat a key. The order the file writes them in is not
/// kept: every later reading, and the served form, lists them by id.
pub fn id_keyed<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Identified,
{
    deserializer.deserialize_map(keyed::KeyedVisitor::<T>::map_only())
}

/// Named items that configuration writes as an id-keyed mapping, read as
/// [`id_keyed`] does, and that the served form lists by id, each item
/// carrying its `id`. Both are read; a configuration file refuses the list
/// through its format's removed keys.
pub fn id_keyed_or_list<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Identified,
{
    deserializer.deserialize_any(keyed::KeyedVisitor::<T>::map_or_list())
}

/// Write named items as the mapping [`id_keyed`] reads: each item's id as
/// the key and the rest of the item as the value.
pub fn serialize_id_keyed<S, T>(items: &[T], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: serde::Serialize + Identified,
{
    use serde::ser::{Error, SerializeMap};
    let mut map = serializer.serialize_map(Some(items.len()))?;
    for item in items {
        let mut value = serde_json::to_value(item).map_err(S::Error::custom)?;
        if let serde_json::Value::Object(members) = &mut value {
            members.remove("id");
        }
        map.serialize_entry(item.id(), &value)?;
    }
    map.end()
}

/// The schema of an [`id_keyed`] member: an object whose property names are
/// the item's id and whose values are the item without its `id`.
#[cfg(feature = "schema")]
pub fn id_keyed_schema<T: schemars::JsonSchema>(
    generator: &mut schemars::SchemaGenerator,
) -> schemars::Schema {
    let mut item = T::json_schema(generator).to_value();
    let names = keyed::take_id(&mut item).unwrap_or_else(|| {
        generator
            .subschema_for::<registry_platform_yaml::LocalId>()
            .to_value()
    });
    schemars::json_schema!({
        "type": "object",
        "propertyNames": names,
        "additionalProperties": item,
    })
}

/// The schema of an [`id_keyed_or_list`] member: the mapping configuration
/// writes, or, for the served form, the list of items by id.
#[cfg(feature = "schema")]
pub fn id_keyed_or_list_schema<T: schemars::JsonSchema>(
    generator: &mut schemars::SchemaGenerator,
) -> schemars::Schema {
    if generator.contract().is_serialize() {
        generator.subschema_for::<Vec<T>>()
    } else {
        id_keyed_schema::<T>(generator)
    }
}

mod keyed {
    use std::{fmt, marker::PhantomData};

    use registry_platform_yaml::Identified;
    use serde::de::{
        value::{SeqAccessDeserializer, StrDeserializer, StringDeserializer},
        DeserializeSeed, Deserializer, EnumAccess, Error, IntoDeserializer, MapAccess, SeqAccess,
        VariantAccess, Visitor,
    };
    use serde::Deserialize;

    pub(super) struct KeyedVisitor<T> {
        list: bool,
        item: PhantomData<T>,
    }

    impl<T> KeyedVisitor<T> {
        pub(super) fn map_only() -> Self {
            Self {
                list: false,
                item: PhantomData,
            }
        }

        pub(super) fn map_or_list() -> Self {
            Self {
                list: true,
                item: PhantomData,
            }
        }
    }

    impl<'de, T> Visitor<'de> for KeyedVisitor<T>
    where
        T: Deserialize<'de> + Identified,
    {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            if self.list {
                formatter.write_str("a mapping from each id to its item, or a list of items")
            } else {
                formatter.write_str("a mapping from each id to its item")
            }
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Vec<T>, A::Error> {
            let mut items = Vec::with_capacity(map.size_hint().unwrap_or(0));
            while let Some(id) = map.next_key::<String>()? {
                items.push(map.next_value_seed(ItemSeed {
                    id,
                    item: PhantomData,
                })?);
            }
            items.sort_by(|left: &T, right: &T| left.id().cmp(right.id()));
            Ok(items)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Vec<T>, A::Error> {
            if !self.list {
                return Err(A::Error::invalid_type(
                    serde::de::Unexpected::Seq,
                    &"a mapping from each id to its item",
                ));
            }
            Vec::<T>::deserialize(SeqAccessDeserializer::new(seq))
        }
    }

    /// One mapping value, read as an item whose `id` is the mapping key.
    struct ItemSeed<T> {
        id: String,
        item: PhantomData<T>,
    }

    impl<'de, T: Deserialize<'de>> DeserializeSeed<'de> for ItemSeed<T> {
        type Value = T;

        fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<T, D::Error> {
            T::deserialize(WithId {
                inner: deserializer,
                id: self.id,
            })
        }
    }

    /// A deserializer that reads a mapping as if it began with `id: <id>`.
    /// Every request is forwarded; only the visitor is wrapped, so a struct,
    /// a tagged union, or a newtype around either reads the id member.
    struct WithId<D> {
        inner: D,
        id: String,
    }

    macro_rules! forward {
        ($($method:ident),* $(,)?) => {$(
            fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
                self.inner.$method(IdVisitor { inner: visitor, id: self.id })
            }
        )*};
    }

    impl<'de, D: Deserializer<'de>> Deserializer<'de> for WithId<D> {
        type Error = D::Error;

        forward!(
            deserialize_any,
            deserialize_bool,
            deserialize_i8,
            deserialize_i16,
            deserialize_i32,
            deserialize_i64,
            deserialize_u8,
            deserialize_u16,
            deserialize_u32,
            deserialize_u64,
            deserialize_f32,
            deserialize_f64,
            deserialize_char,
            deserialize_str,
            deserialize_string,
            deserialize_bytes,
            deserialize_byte_buf,
            deserialize_option,
            deserialize_unit,
            deserialize_seq,
            deserialize_map,
            deserialize_identifier,
            deserialize_ignored_any,
        );

        fn deserialize_unit_struct<V: Visitor<'de>>(
            self,
            name: &'static str,
            visitor: V,
        ) -> Result<V::Value, D::Error> {
            let visitor = IdVisitor {
                inner: visitor,
                id: self.id,
            };
            self.inner.deserialize_unit_struct(name, visitor)
        }

        fn deserialize_newtype_struct<V: Visitor<'de>>(
            self,
            name: &'static str,
            visitor: V,
        ) -> Result<V::Value, D::Error> {
            let visitor = IdVisitor {
                inner: visitor,
                id: self.id,
            };
            self.inner.deserialize_newtype_struct(name, visitor)
        }

        fn deserialize_tuple<V: Visitor<'de>>(
            self,
            len: usize,
            visitor: V,
        ) -> Result<V::Value, D::Error> {
            let visitor = IdVisitor {
                inner: visitor,
                id: self.id,
            };
            self.inner.deserialize_tuple(len, visitor)
        }

        fn deserialize_tuple_struct<V: Visitor<'de>>(
            self,
            name: &'static str,
            len: usize,
            visitor: V,
        ) -> Result<V::Value, D::Error> {
            let visitor = IdVisitor {
                inner: visitor,
                id: self.id,
            };
            self.inner.deserialize_tuple_struct(name, len, visitor)
        }

        fn deserialize_struct<V: Visitor<'de>>(
            self,
            name: &'static str,
            fields: &'static [&'static str],
            visitor: V,
        ) -> Result<V::Value, D::Error> {
            let visitor = IdVisitor {
                inner: visitor,
                id: self.id,
            };
            self.inner.deserialize_struct(name, fields, visitor)
        }

        fn deserialize_enum<V: Visitor<'de>>(
            self,
            name: &'static str,
            variants: &'static [&'static str],
            visitor: V,
        ) -> Result<V::Value, D::Error> {
            let visitor = IdVisitor {
                inner: visitor,
                id: self.id,
            };
            self.inner.deserialize_enum(name, variants, visitor)
        }

        fn is_human_readable(&self) -> bool {
            self.inner.is_human_readable()
        }
    }

    struct IdVisitor<V> {
        inner: V,
        id: String,
    }

    macro_rules! pass {
        ($($method:ident($type:ty)),* $(,)?) => {$(
            fn $method<E: Error>(self, value: $type) -> Result<V::Value, E> {
                self.inner.$method(value)
            }
        )*};
    }

    impl<'de, V: Visitor<'de>> Visitor<'de> for IdVisitor<V> {
        type Value = V::Value;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.inner.expecting(formatter)
        }

        pass!(
            visit_bool(bool),
            visit_i64(i64),
            visit_i128(i128),
            visit_u64(u64),
            visit_u128(u128),
            visit_f64(f64),
            visit_str(&str),
            visit_borrowed_str(&'de str),
            visit_string(String),
            visit_bytes(&[u8]),
            visit_borrowed_bytes(&'de [u8]),
            visit_byte_buf(Vec<u8>),
        );

        fn visit_none<E: Error>(self) -> Result<V::Value, E> {
            self.inner.visit_none()
        }

        fn visit_unit<E: Error>(self) -> Result<V::Value, E> {
            self.inner.visit_unit()
        }

        fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<V::Value, D::Error> {
            self.inner.visit_some(deserializer)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<V::Value, A::Error> {
            self.inner.visit_seq(seq)
        }

        fn visit_newtype_struct<D: Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> Result<V::Value, D::Error> {
            self.inner.visit_newtype_struct(WithId {
                inner: deserializer,
                id: self.id,
            })
        }

        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<V::Value, A::Error> {
            self.inner.visit_map(PrependId {
                inner: map,
                id: Some(self.id),
                pending: None,
            })
        }

        fn visit_enum<A: EnumAccess<'de>>(self, data: A) -> Result<V::Value, A::Error> {
            self.inner.visit_enum(IdEnum {
                inner: data,
                id: self.id,
            })
        }
    }

    /// A mapping that yields `id: <id>` before its own members.
    struct PrependId<A> {
        inner: A,
        id: Option<String>,
        pending: Option<String>,
    }

    impl<'de, A: MapAccess<'de>> MapAccess<'de> for PrependId<A> {
        type Error = A::Error;

        fn next_key_seed<K: DeserializeSeed<'de>>(
            &mut self,
            seed: K,
        ) -> Result<Option<K::Value>, A::Error> {
            match self.id.take() {
                Some(id) => {
                    self.pending = Some(id);
                    let key: StrDeserializer<'_, A::Error> = "id".into_deserializer();
                    seed.deserialize(key).map(Some)
                }
                None => self.inner.next_key_seed(seed),
            }
        }

        fn next_value_seed<S: DeserializeSeed<'de>>(
            &mut self,
            seed: S,
        ) -> Result<S::Value, A::Error> {
            match self.pending.take() {
                Some(id) => {
                    let value: StringDeserializer<A::Error> = id.into_deserializer();
                    seed.deserialize(value)
                }
                None => self.inner.next_value_seed(seed),
            }
        }

        fn size_hint(&self) -> Option<usize> {
            self.inner
                .size_hint()
                .map(|size| size + usize::from(self.id.is_some()))
        }
    }

    struct IdEnum<A> {
        inner: A,
        id: String,
    }

    impl<'de, A: EnumAccess<'de>> EnumAccess<'de> for IdEnum<A> {
        type Error = A::Error;
        type Variant = IdVariant<A::Variant>;

        fn variant_seed<S: DeserializeSeed<'de>>(
            self,
            seed: S,
        ) -> Result<(S::Value, Self::Variant), A::Error> {
            let (value, variant) = self.inner.variant_seed(seed)?;
            Ok((
                value,
                IdVariant {
                    inner: variant,
                    id: self.id,
                },
            ))
        }
    }

    struct IdVariant<A> {
        inner: A,
        id: String,
    }

    impl<'de, A: VariantAccess<'de>> VariantAccess<'de> for IdVariant<A> {
        type Error = A::Error;

        fn unit_variant(self) -> Result<(), A::Error> {
            self.inner.unit_variant()
        }

        fn newtype_variant_seed<S: DeserializeSeed<'de>>(
            self,
            seed: S,
        ) -> Result<S::Value, A::Error> {
            self.inner.newtype_variant_seed(IdSeed {
                inner: seed,
                id: self.id,
            })
        }

        fn tuple_variant<V: Visitor<'de>>(
            self,
            len: usize,
            visitor: V,
        ) -> Result<V::Value, A::Error> {
            self.inner.tuple_variant(len, visitor)
        }

        fn struct_variant<V: Visitor<'de>>(
            self,
            fields: &'static [&'static str],
            visitor: V,
        ) -> Result<V::Value, A::Error> {
            self.inner.struct_variant(
                fields,
                IdVisitor {
                    inner: visitor,
                    id: self.id,
                },
            )
        }
    }

    struct IdSeed<S> {
        inner: S,
        id: String,
    }

    impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for IdSeed<S> {
        type Value = S::Value;

        fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<S::Value, D::Error> {
            self.inner.deserialize(WithId {
                inner: deserializer,
                id: self.id,
            })
        }
    }

    /// Remove `id` from an item schema, from each branch of a union, and
    /// return the schema the id had, which a mapping's keys then follow.
    #[cfg(feature = "schema")]
    pub(super) fn take_id(schema: &mut serde_json::Value) -> Option<serde_json::Value> {
        use serde_json::Value;
        let Value::Object(object) = schema else {
            return None;
        };
        let mut taken = None;
        if let Some(Value::Object(properties)) = object.get_mut("properties") {
            taken = properties.remove("id");
        }
        if let Some(Value::Array(required)) = object.get_mut("required") {
            required.retain(|member| member != "id");
        }
        for union in ["oneOf", "anyOf"] {
            if let Some(Value::Array(branches)) = object.get_mut(union) {
                for branch in branches {
                    let branch_id = take_id(branch);
                    taken = taken.or(branch_id);
                }
            }
        }
        taken
    }
}
