// SPDX-License-Identifier: Apache-2.0
//! Members a Casework file reads through a `registry-platform-yaml` type
//! while the model keeps the plain value: the reader refuses what the shared
//! type refuses, with its code and position, and the schema states the same
//! rule through `schemars(with = ...)` on the member. The project and the
//! runtime configuration both read through these.

use std::hash::Hash;

use registry_platform_yaml::{BoundedU32, BoundedU64, Digest, UniqueList, Url};
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
