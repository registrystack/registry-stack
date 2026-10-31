// SPDX-License-Identifier: Apache-2.0

//! Members a file reads through a `registry-platform-yaml` type while the
//! model keeps the plain value: the reader refuses what the shared type
//! refuses, with its code and position, and the schema states the same
//! rule through `schemars(with = ...)` on the member.

use registry_platform_yaml::LocalId;
use serde::{Deserialize, Deserializer};
use std::collections::BTreeMap;

/// A mapping keyed by local identifiers (CFG-ID-1): each key is refused at
/// its own position unless it is a `LocalId`, and the model keeps the keys
/// as text.
pub fn local_id_map<'de, D, V>(deserializer: D) -> Result<BTreeMap<String, V>, D::Error>
where
    D: Deserializer<'de>,
    V: Deserialize<'de>,
{
    let map = BTreeMap::<LocalId, V>::deserialize(deserializer)?;
    Ok(map
        .into_iter()
        .map(|(key, value)| (key.into_string(), value))
        .collect())
}

/// The schema of a [`local_id_map`] member: an object whose property names
/// are `LocalId` and whose values are `V`.
#[cfg(feature = "schema")]
pub fn local_id_map_schema<V: schemars::JsonSchema>(
    generator: &mut schemars::SchemaGenerator,
) -> schemars::Schema {
    let names = generator.subschema_for::<LocalId>();
    schemars::json_schema!({
        "type": "object",
        "propertyNames": names,
        "additionalProperties": generator.subschema_for::<V>(),
    })
}
