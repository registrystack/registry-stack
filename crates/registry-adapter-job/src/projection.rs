// SPDX-License-Identifier: Apache-2.0

//! The pass-time projection and the plain digest
//! (`products/adapter/CONCEPT.md` section 17.2). The item value is the
//! route's projection of the destination's fields, and the job declares
//! the dotted fields the destination needs; the pass enforces that list,
//! picking exactly those fields from each item value at hand-off time, so
//! the destination never sees a field the job did not declare. The item
//! row's digest covers what [`ProjectionDecl::digest_of`] declares: the
//! projected fields by default, or the item value as the route shaped
//! it together with the declared field list. The digest is plain, with no keyed construction and no secret:
//! the item table holds identity, not confidential material, and a dump
//! of it exposes no answers.

use registry_adapter_core::{ProjectionDecl, ProjectionDigestOf};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

/// One field the projection could not resolve in the item value. A
/// missing field projects as `null` and never aborts the pass: the
/// destination sees the null and answers for itself.
const MISSING_FIELD: serde_json::Value = serde_json::Value::Null;

/// The projected form of one item value: one object member per declared
/// field, in declaration order, with a missing field carried as `null`.
/// A path walks objects only; a segment that lands on an array, a
/// scalar, or nothing projects as `null`, because the declared paths are
/// dotted identifiers and name no array element.
#[must_use]
pub fn project(declaration: &ProjectionDecl, value: &serde_json::Value) -> serde_json::Value {
    let mut projected = serde_json::Map::new();
    for field in &declaration.fields {
        projected.insert(field.clone(), lookup(value, field));
    }
    serde_json::Value::Object(projected)
}

/// Walk one dotted path through an object value, `null` on every miss.
fn lookup(value: &serde_json::Value, path: &str) -> serde_json::Value {
    let mut current = value;
    for segment in path.split('.') {
        match current.get(segment) {
            Some(next) => current = next,
            None => return MISSING_FIELD,
        }
    }
    current.clone()
}

/// The bytes the item digest covers, per the job's `digestOf`
/// declaration: the canonical serialization of the projected fields by
/// default, or of the item value as the route shaped it together with the
/// sorted declared field list. The field list decides what the
/// destination receives, so editing it re-flags every item even under a
/// value digest. Canonical means compact, UTF-8, and every object's
/// members sorted by key, so the same logical value always digests to the
/// same bytes across runs and processes.
#[must_use]
pub fn digest_input(
    declaration: &ProjectionDecl,
    value: &serde_json::Value,
    projected: &serde_json::Value,
) -> Vec<u8> {
    match declaration.digest_of {
        ProjectionDigestOf::Projection => canonical_bytes(projected),
        ProjectionDigestOf::Value => {
            let mut fields: Vec<&str> = declaration.fields.iter().map(String::as_str).collect();
            fields.sort_unstable();
            canonical_bytes(&serde_json::json!({"projection": fields, "value": value}))
        }
    }
}

/// The plain item digest, stored and handed off as `sha256:` followed by
/// 64 lowercase hex digits. No keyed construction and no digest secret:
/// the digest says only whether the bytes the job covers changed.
#[must_use]
pub fn item_digest(declaration: &ProjectionDecl, value: &serde_json::Value) -> String {
    let projected = project(declaration, value);
    let digest = Sha256::digest(digest_input(declaration, value, &projected).as_slice());
    format!("sha256:{}", hex_lower(&digest))
}

/// The canonical serialization of one JSON value: compact, and every
/// object's members sorted by key at every depth. The projection
/// functions build their own members in a fixed order, but an item value
/// digested under `digestOf: value` arrives with the source's own member
/// order, so the canonical form, not the arriving form, defines the
/// digest.
#[must_use]
pub fn canonical_bytes(value: &serde_json::Value) -> Vec<u8> {
    canonicalize(value).to_string().into_bytes()
}

fn canonicalize(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(members) => {
            let sorted: BTreeMap<&str, &serde_json::Value> = members
                .iter()
                .map(|(key, value)| (key.as_str(), value))
                .collect();
            let members = sorted
                .into_iter()
                .map(|(key, value)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("a string key renders"),
                        canonicalize(value)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{members}}}")
        }
        serde_json::Value::Array(items) => {
            let items = items.iter().map(canonicalize).collect::<Vec<_>>().join(",");
            format!("[{items}]")
        }
        other => other.to_string(),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_adapter_core::ProjectionDecl;

    fn declaration(fields: &[&str]) -> ProjectionDecl {
        ProjectionDecl {
            fields: fields.iter().map(|field| (*field).to_string()).collect(),
            digest_of: ProjectionDigestOf::default(),
        }
    }

    #[test]
    fn a_projection_carries_declared_fields_and_null_for_missing_ones() {
        let declaration = declaration(&["id", "answers.age", "answers.name"]);
        let value = serde_json::json!({"id": "a", "answers": {"age": "045"}});
        let projected = project(&declaration, &value);
        assert_eq!(
            projected,
            serde_json::json!({"id": "a", "answers.age": "045", "answers.name": null}),
            "a missing field projects as null, never aborts"
        );
    }

    #[test]
    fn a_path_that_leaves_the_objects_projects_as_null() {
        let declaration = declaration(&["answers.age.years", "answers"]);
        let value = serde_json::json!({"answers": {"age": "045"}});
        let projected = project(&declaration, &value);
        assert_eq!(
            projected,
            serde_json::json!({"answers.age.years": null, "answers": {"age": "045"}}),
            "a segment landing on a scalar projects as null"
        );
    }

    #[test]
    fn the_digest_is_plain_sha256_over_the_canonical_projection() {
        let declaration = declaration(&["id", "answers.age"]);
        let value = serde_json::json!({"answers": {"age": "045"}, "id": "a"});
        let digest = item_digest(&declaration, &value);
        assert!(
            digest.starts_with("sha256:"),
            "the digest carries the sha256 label"
        );
        let hex = digest.trim_start_matches("sha256:");
        assert_eq!(hex.len(), 64, "the digest carries 64 hex digits");
        assert!(
            hex.bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "the hex is lowercase"
        );
        // The digest covers the canonical projection, so member order in
        // the source value cannot move it.
        let reordered = serde_json::json!({"id": "a", "answers": {"age": "045"}});
        assert_eq!(item_digest(&declaration, &reordered), digest);
        // A changed projected field changes the digest.
        let changed = serde_json::json!({"id": "a", "answers": {"age": "046"}});
        assert_ne!(item_digest(&declaration, &changed), digest);
    }

    #[test]
    fn a_value_digest_covers_the_item_and_the_declared_fields_and_ignores_key_order() {
        let mut decl = declaration(&["id"]);
        decl.digest_of = ProjectionDigestOf::Value;
        let value = serde_json::json!({"id": "a", "nested": {"b": 1, "a": 2}});
        let digest = item_digest(&decl, &value);
        let reordered = serde_json::json!({"nested": {"a": 2, "b": 1}, "id": "a"});
        assert_eq!(
            item_digest(&decl, &reordered),
            digest,
            "the canonical form, not the arriving member order, defines the digest"
        );
        // The declared fields decide what the destination receives, so a
        // field-list edit re-flags every item even when the value is
        // unchanged; the order the fields are listed in does not.
        let mut other_projection = declaration(&["answers.age"]);
        other_projection.digest_of = ProjectionDigestOf::Value;
        assert_ne!(
            item_digest(&other_projection, &value),
            digest,
            "a changed field list changes a value digest"
        );
        let mut two = declaration(&["id", "nested.a"]);
        two.digest_of = ProjectionDigestOf::Value;
        let mut swapped = declaration(&["nested.a", "id"]);
        swapped.digest_of = ProjectionDigestOf::Value;
        assert_eq!(
            item_digest(&two, &value),
            item_digest(&swapped, &value),
            "the field list's order plays no part"
        );
    }

    #[test]
    fn canonical_bytes_are_compact_sorted_json() {
        let value = serde_json::json!({"b": [1, {"y": 2, "x": 3}], "a": "s"});
        let bytes = canonical_bytes(&value);
        assert_eq!(
            String::from_utf8(bytes).as_deref(),
            Ok(r#"{"a":"s","b":[1,{"x":3,"y":2}]}"#)
        );
    }
}
