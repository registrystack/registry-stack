// SPDX-License-Identifier: Apache-2.0

//! Vocabulary shared by the Adapter artifacts: facade operations, envelope
//! names, HTTP methods, script seams, field maps, and detection rules.

use registry_platform_yaml::Digest;
use serde::{Deserialize, Serialize};

/// A facade operation, the closed set the `breg-records` v1 profile serves
/// (`products/adapter/CONCEPT.md` section 7). `records.update` covers the
/// full and the partial update; the profile's method and path distinguish
/// them.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum FacadeOperation {
    RecordsSearch,
    RecordsGet,
    RecordsCreate,
    RecordsUpdate,
}

impl FacadeOperation {
    /// The complete closed set, in id order.
    pub const ALL: &'static [Self] = &[
        Self::RecordsSearch,
        Self::RecordsGet,
        Self::RecordsCreate,
        Self::RecordsUpdate,
    ];

    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::RecordsSearch => "records.search",
            Self::RecordsGet => "records.get",
            Self::RecordsCreate => "records.create",
            Self::RecordsUpdate => "records.update",
        }
    }

    /// Resolve an operation id back to its variant, or `None` for any string
    /// outside the closed set.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.id() == id)
    }

    /// Whether the operation changes the upstream system. Writes carry the
    /// plan restrictions of `products/adapter/CONCEPT.md` section 9.
    #[must_use]
    pub const fn is_write(self) -> bool {
        matches!(self, Self::RecordsCreate | Self::RecordsUpdate)
    }
}

impl serde::Serialize for FacadeOperation {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.id())
    }
}

impl<'de> serde::Deserialize<'de> for FacadeOperation {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let id = String::deserialize(deserializer)?;
        Self::from_id(&id).ok_or_else(|| {
            serde::de::Error::custom(registry_platform_yaml::Invalid::expected(
                "one of: records.search, records.get, records.create, records.update",
                "Write one facade operation id from the closed set.",
            ))
        })
    }
}

/// The wire envelope an artifact speaks: the closed set of envelope
/// executors compiled into the engine (`products/adapter/CONCEPT.md`
/// section 8.4). Executors are named for mechanisms, never products.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Envelope {
    #[default]
    RestJson,
    GraphQl,
}

impl Envelope {
    /// The complete closed set, in name order.
    pub const ALL: &'static [Self] = &[Self::GraphQl, Self::RestJson];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RestJson => "rest-json",
            Self::GraphQl => "graphql",
        }
    }

    /// Resolve an envelope name back to its variant, or `None` for any
    /// string outside the closed set.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.name() == name)
    }
}

/// An HTTP method a facade operation or upstream template may declare.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
}

/// A script seam: code in its own file beside the pack, referenced by a
/// relative path and pinned by digest (CFG-EMBED-1). Scripts never carry
/// credentials and never construct URLs; they fill declared placeholders and
/// transform values at the seams the pack declares.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScriptReference {
    /// The script file, relative to the pack document.
    pub path: String,
    /// The `sha256:` digest the file must hash to.
    pub digest: Digest,
}

/// One declarative field mapping: an upstream field path, the declared field
/// it fills, and an optional script seam that transforms the value. The
/// target is a declared field id; the source is a path into the upstream
/// response, kept exactly as the source system writes it.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FieldMapping {
    /// Path into the upstream response this mapping reads.
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = crate::naming::MAX_FIELD_PATH_CHARACTERS)))]
    pub from: String,
    /// The declared field this mapping fills.
    pub to: registry_platform_yaml::LocalId,
    /// Optional script seam that transforms the value before it binds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<ScriptReference>,
}

/// A declarative field map: the ordered mappings one `map` step or normalize
/// branch applies. Declarative first; the script seams are the escape hatch
/// (`products/adapter/CONCEPT.md` section 8.5, rung 2).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FieldMap {
    pub mappings: Vec<FieldMapping>,
}

/// How the engine decides an upstream exchange succeeded or which declared
/// error class it hit. Status ranges are the declarative rung; a script seam
/// covers body-level detection, which source systems such as DHIS2 need
/// because a 200 may still carry import errors.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum DetectionRule {
    /// The exchange succeeded, or the class applies, when the upstream
    /// status is in the inclusive range.
    StatusRange { minimum: u16, maximum: u16 },
    /// The script answers the yes-or-no detection question.
    Script { seam: ScriptReference },
}

impl DetectionRule {
    /// The status range this rule declares, or `None` for a script rule.
    #[must_use]
    pub const fn status_range(&self) -> Option<(u16, u16)> {
        match self {
            Self::StatusRange { minimum, maximum } => Some((*minimum, *maximum)),
            Self::Script { .. } => None,
        }
    }

    /// The script seam this rule carries, if any.
    #[must_use]
    pub const fn script(&self) -> Option<&ScriptReference> {
        match self {
            Self::StatusRange { .. } => None,
            Self::Script { seam } => Some(seam),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operations_round_trip() {
        for operation in FacadeOperation::ALL {
            assert_eq!(FacadeOperation::from_id(operation.id()), Some(*operation));
            let json = serde_json::to_string(operation).expect("serialize");
            assert_eq!(
                serde_json::from_str::<FacadeOperation>(&json).ok(),
                Some(*operation)
            );
        }
        assert_eq!(FacadeOperation::from_id("records.delete"), None);
    }

    #[test]
    fn writes_are_create_and_update_only() {
        assert!(!FacadeOperation::RecordsSearch.is_write());
        assert!(!FacadeOperation::RecordsGet.is_write());
        assert!(FacadeOperation::RecordsCreate.is_write());
        assert!(FacadeOperation::RecordsUpdate.is_write());
    }

    #[test]
    fn envelopes_round_trip_and_refuse_outside_names() {
        for envelope in Envelope::ALL {
            assert_eq!(Envelope::from_name(envelope.name()), Some(*envelope));
            let json = serde_json::to_string(envelope).expect("serialize");
            assert_eq!(
                serde_json::from_str::<Envelope>(&json).ok(),
                Some(*envelope)
            );
        }
        assert_eq!(Envelope::from_name("soap-xml"), None);
        assert!(serde_json::from_str::<Envelope>("\"soap-xml\"").is_err());
    }

    #[test]
    fn detection_rules_round_trip() {
        let range = DetectionRule::StatusRange {
            minimum: 200,
            maximum: 299,
        };
        let json = serde_json::to_string(&range).expect("serialize");
        assert!(json.contains("\"kind\":\"status-range\""));
        assert_eq!(
            serde_json::from_str::<DetectionRule>(&json).ok(),
            Some(range)
        );
        let script = DetectionRule::Script {
            seam: ScriptReference {
                path: "seams/summary.rhai".to_string(),
                digest: Digest::new(SHA256_EXAMPLE).expect("digest"),
            },
        };
        assert_eq!(script.status_range(), None);
        assert!(script.script().is_some());
    }

    const SHA256_EXAMPLE: &str =
        "sha256:678260a56715cba21db1f0687e5a2c5e5efb2ea0b8eea687b5f3ee8723c5f6c9";
}
