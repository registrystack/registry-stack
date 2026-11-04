// SPDX-License-Identifier: Apache-2.0

//! Source-neutral direct-write guarantees and normalized source results for
//! the built-in GovStack Write target.

use registry_platform_yaml::{BoundedU64, ExternalId};
use serde::{Deserialize, Serialize};

/// The source-owned identity behavior a direct Create route guarantees.
/// The first supported shape is intentionally singular: the source assigns
/// the durable key returned in [`SourceWriteReceipt`].
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceWriteIdentity {
    SourceAssigned,
}

/// The source-owned replay behavior a direct write guarantees.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceWriteReplayKind {
    ExactKeyed,
}

/// Exact source replay semantics and their finite provider-owned window.
/// The host keeps its own idempotency custody within, never beyond, this
/// declared source guarantee.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceWriteReplay {
    #[serde(rename = "type")]
    pub kind: SourceWriteReplayKind,
    /// Seconds for which the source guarantees an exact same-key replay.
    pub replay_window_seconds: BoundedU64<1, 31_536_000>,
}

/// The source-owned concurrency behavior an Update route guarantees.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceWritePrecondition {
    /// The source compares and commits the supplied native validator in the
    /// same atomic mutation boundary.
    StrongAtomicSource,
}

/// Source-neutral direct-write semantics explicitly promised by one reusable
/// pack route template. A host never infers these guarantees from an HTTP
/// method, provider brand, route id, or successful fixture.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SourceWriteSupport {
    /// Create exactly one source record and return its source-assigned key.
    CreateOne {
        identity: SourceWriteIdentity,
        replay: SourceWriteReplay,
    },
    /// Update exactly one source record under an atomic source precondition.
    ConditionalUpdateOne {
        replay: SourceWriteReplay,
        precondition: SourceWritePrecondition,
    },
}

registry_platform_yaml::tagged_union!(SourceWriteSupport, tag = "type");
crate::model::serialize_tagged_union!(SourceWriteSupport, tag = "type");

/// The normalized result of one successful source mutation. The route maps
/// its native response into this fixed generic object; no adopter-authored
/// native-output schema is needed. The host validates the selected public
/// data schema separately before it releases a response.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceWriteReceipt {
    /// The source-assigned opaque record key.
    pub key: ExternalId,
    /// The source-native strong validator used for later conditional writes.
    pub native_validator: ExternalId,
    /// The source's current generic data object after the mutation.
    pub data: serde_json::Map<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_write_support_requires_closed_explicit_guarantees() {
        let create: SourceWriteSupport = serde_json::from_value(serde_json::json!({
            "type": "create-one",
            "identity": "source-assigned",
            "replay": {"type": "exact-keyed", "replayWindowSeconds": 604800}
        }))
        .expect("create support");
        assert!(matches!(
            create,
            SourceWriteSupport::CreateOne {
                identity: SourceWriteIdentity::SourceAssigned,
                replay: SourceWriteReplay {
                    kind: SourceWriteReplayKind::ExactKeyed,
                    ..
                }
            }
        ));

        let update: SourceWriteSupport = serde_json::from_value(serde_json::json!({
            "type": "conditional-update-one",
            "replay": {"type": "exact-keyed", "replayWindowSeconds": 604800},
            "precondition": "strong-atomic-source"
        }))
        .expect("update support");
        assert!(matches!(
            update,
            SourceWriteSupport::ConditionalUpdateOne {
                precondition: SourceWritePrecondition::StrongAtomicSource,
                ..
            }
        ));

        for refused in [
            serde_json::json!({"type": "create-one", "identity": "caller-assigned", "replay": {"type": "exact-keyed", "replayWindowSeconds": 60}}),
            serde_json::json!({"type": "create-one", "identity": "source-assigned", "replay": {"type": "best-effort", "replayWindowSeconds": 60}}),
            serde_json::json!({"type": "create-one", "identity": "source-assigned", "replay": {"type": "exact-keyed", "replayWindowSeconds": 0}}),
            serde_json::json!({"type": "conditional-update-one", "replay": {"type": "exact-keyed", "replayWindowSeconds": 60}}),
            serde_json::json!({"type": "conditional-update-one", "replay": {"type": "exact-keyed", "replayWindowSeconds": 60}, "precondition": "if-match-header"}),
            serde_json::json!({"type": "transition"}),
        ] {
            assert!(serde_json::from_value::<SourceWriteSupport>(refused).is_err());
        }
    }

    #[test]
    fn source_write_receipt_is_one_closed_object_with_native_identity() {
        let receipt: SourceWriteReceipt = serde_json::from_value(serde_json::json!({
            "key": "source-1",
            "nativeValidator": "revision-17",
            "data": {"name": "Ada"}
        }))
        .expect("receipt");
        assert_eq!(receipt.data["name"], "Ada");

        for refused in [
            serde_json::json!({"key": "", "nativeValidator": "revision-17", "data": {}}),
            serde_json::json!({"key": "source-1", "nativeValidator": "", "data": {}}),
            serde_json::json!({"key": "source-1", "nativeValidator": "revision-17", "data": []}),
            serde_json::json!({"key": "source-1", "nativeValidator": "revision-17", "data": {}, "extra": true}),
        ] {
            assert!(serde_json::from_value::<SourceWriteReceipt>(refused).is_err());
        }
    }
}
