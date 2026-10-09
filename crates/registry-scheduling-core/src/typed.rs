// SPDX-License-Identifier: Apache-2.0

//! Members a Scheduling file reads through a `registry-platform-yaml` type
//! while the model keeps the plain value: the reader refuses what the shared
//! type refuses, with its code and position, and the schema states the same
//! rule through `schemars(with = ...)` on the member. The project, the
//! records document, and the fixture all read through these.

use std::hash::Hash;

use registry_platform_yaml::{
    BoundedU32, BoundedU64, Identified, Invalid, LocalId, UniqueIdList, UniqueList, Url,
};
use serde::{de, Deserialize, Deserializer};

/// Minutes in one day: the bound of an appointment, a buffer, and a grid.
pub const MINUTES_PER_DAY: u32 = 1_440;

/// The furthest ahead, in days, an offering may open booking.
pub const MAXIMUM_HORIZON_DAYS: u32 = 3_650;

/// The longest lead time, cancellation cutoff, or reminder offset in minutes:
/// the whole of the longest horizon.
pub const MAXIMUM_HORIZON_MINUTES: u32 = MAXIMUM_HORIZON_DAYS * MINUTES_PER_DAY;

/// The most recipient units one window, subquota, band, or claim may count.
/// The ledger stores units as a signed 32-bit integer.
pub const MAXIMUM_UNITS: u32 = i32::MAX as u32;

/// The highest revision of a published record. The ledger stores revisions
/// as a signed 64-bit integer.
pub const MAXIMUM_REVISION: u64 = i64::MAX as u64;

/// The most members one pool may list, and so the most a window's staffing
/// may reserve.
pub const MAXIMUM_POOL_MEMBERS: u32 = 256;

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

/// A local identifier (CFG-ID-1), kept as written.
pub fn local_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    LocalId::deserialize(deserializer).map(LocalId::into_string)
}

/// An optional member holding a local identifier (CFG-ID-1); absent reads
/// as `None` through `serde(default)`.
pub fn optional_local_id<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    local_id(deserializer).map(Some)
}

/// An absolute `http` or `https` URL with a host and no user information
/// (CFG-VAL-7), kept as written. The member's own rules decide whether it
/// also refuses `http`.
pub fn url<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    Url::deserialize(deserializer).map(Url::into_string)
}

/// A list that is a set: a repeated item is refused (CFG-ID-6).
pub fn unique_list<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Eq + Hash,
{
    UniqueList::<T>::deserialize(deserializer).map(UniqueList::into_vec)
}

/// Named items in a list, each with an `id` unique in the list (CFG-ID-5):
/// a repeated id is refused at the second item's `id`.
pub fn unique_id_list<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Identified,
{
    UniqueIdList::<T>::deserialize(deserializer).map(UniqueIdList::into_vec)
}

/// A set of local identifiers (CFG-ID-1, CFG-ID-6), kept as written.
pub fn unique_local_ids<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    UniqueList::<LocalId>::deserialize(deserializer).map(|ids| {
        ids.into_vec()
            .into_iter()
            .map(LocalId::into_string)
            .collect()
    })
}

/// The refusal of an empty list where an empty list would read as "no
/// restriction" (CFG-EMPTY-2).
const EMPTY_LIST: Invalid = Invalid::expected(
    "a list with at least one item",
    "List at least one item, or omit the member when there is nothing to list.",
);

/// An optional restricting list: when written it is a set of at least one
/// item (CFG-EMPTY-2, CFG-ID-6). Absent reads as empty through
/// `serde(default)`.
pub fn non_empty_unique_list<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Eq + Hash,
{
    let items = unique_list(deserializer)?;
    if items.is_empty() {
        return Err(de::Error::custom(EMPTY_LIST));
    }
    Ok(items)
}

/// An optional restricting set of local identifiers: when written it holds
/// at least one (CFG-EMPTY-2, CFG-ID-1, CFG-ID-6). Absent reads as empty
/// through `serde(default)`.
pub fn non_empty_unique_local_ids<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let ids = unique_local_ids(deserializer)?;
    if ids.is_empty() {
        return Err(de::Error::custom(EMPTY_LIST));
    }
    Ok(ids)
}

/// An optional restricting list whose items carry their own identity: when
/// written it holds at least one item (CFG-EMPTY-2). Absent reads as empty
/// through `serde(default)`.
pub fn non_empty_list<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let items = Vec::<T>::deserialize(deserializer)?;
    if items.is_empty() {
        return Err(de::Error::custom(EMPTY_LIST));
    }
    Ok(items)
}

/// Test support: decode a YAML fragment through the shared reader, without
/// an envelope, and keep the codes of a refusal.
#[cfg(test)]
pub(crate) fn decode_fragment<T: serde::de::DeserializeOwned>(
    yaml: &str,
) -> Result<T, Vec<String>> {
    use registry_platform_yaml::{EnvelopeRule, Expect, FormatSpec};
    const FRAGMENT: FormatSpec<'static> = FormatSpec {
        kind: "Fragment",
        envelope: EnvelopeRule::Exempt {
            reason: "a test fragment",
        },
        removed_keys: &[],
    };
    registry_platform_yaml::decode_document::<T>(
        "fragment.yaml",
        yaml.as_bytes(),
        &Expect::one(&FRAGMENT),
    )
    .map(|decoded| decoded.value)
    .map_err(|report| {
        report
            .diagnostics()
            .iter()
            .map(|diagnostic| format!("{} {}", diagnostic.path, diagnostic.code))
            .collect()
    })
}
