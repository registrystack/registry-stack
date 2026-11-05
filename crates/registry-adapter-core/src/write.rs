// SPDX-License-Identifier: Apache-2.0

//! Source-neutral direct-write guarantees and normalized source results for
//! the built-in GovStack Write target.

use registry_platform_yaml::{BoundedU64, ExternalId};
use serde::{Deserialize, Serialize};

/// Source-neutral direct-write semantics explicitly promised by one reusable
/// pack route template. A host never infers these guarantees from an HTTP
/// method, provider brand, route id, or successful fixture.
///
/// Each variant names one fixed guarantee set; the only value a pack chooses
/// is the finite provider-owned window in which the source guarantees an
/// exact same-key replay. The host keeps its own idempotency custody within,
/// never beyond, that declared window.
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
    /// Create exactly one source record, replay an exact same-key retry, and
    /// return the durable key the source assigns in [`SourceWriteReceipt`].
    CreateOne {
        /// Seconds for which the source guarantees an exact same-key replay.
        replay_window_seconds: BoundedU64<1, 31_536_000>,
    },
    /// Update exactly one source record, replay an exact same-key retry, and
    /// compare and commit the supplied native validator in the same atomic
    /// mutation boundary.
    ConditionalUpdateOne {
        /// Seconds for which the source guarantees an exact same-key replay.
        replay_window_seconds: BoundedU64<1, 31_536_000>,
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
    fn source_write_support_names_only_the_variant_and_its_replay_window() {
        let create: SourceWriteSupport = serde_json::from_value(serde_json::json!({
            "type": "create-one",
            "replayWindowSeconds": 604800
        }))
        .expect("create support");
        assert!(matches!(
            create,
            SourceWriteSupport::CreateOne { replay_window_seconds } if replay_window_seconds.get() == 604800
        ));

        let update: SourceWriteSupport = serde_json::from_value(serde_json::json!({
            "type": "conditional-update-one",
            "replayWindowSeconds": 600
        }))
        .expect("update support");
        assert!(matches!(
            update,
            SourceWriteSupport::ConditionalUpdateOne { replay_window_seconds } if replay_window_seconds.get() == 600
        ));

        for refused in [
            // The single-value members are gone; the closed schema refuses them.
            serde_json::json!({"type": "create-one", "identity": "source-assigned", "replayWindowSeconds": 60}),
            serde_json::json!({"type": "create-one", "replay": {"type": "exact-keyed", "replayWindowSeconds": 60}}),
            serde_json::json!({"type": "conditional-update-one", "replayWindowSeconds": 60, "precondition": "strong-atomic-source"}),
            serde_json::json!({"type": "create-one", "replayWindowSeconds": 0}),
            serde_json::json!({"type": "create-one"}),
            serde_json::json!({"type": "conditional-update-one"}),
            serde_json::json!({"type": "transition"}),
        ] {
            assert!(
                serde_json::from_value::<SourceWriteSupport>(refused.clone()).is_err(),
                "{refused}"
            );
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
