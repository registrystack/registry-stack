// SPDX-License-Identifier: Apache-2.0

//! The adapter project: the deployment artifact that binds a profile to a
//! pack over a declared record model (`products/adapter/CONCEPT.md`
//! sections 6, 7, and 10.1).

use registry_platform_yaml::{Digest, ExternalId, LocalId, UniqueIdList};
use serde::{Deserialize, Serialize};

/// A pinned reference to a profile or pack: plain identifier plus the
/// version and digest `adapterctl check` verifies (CFG-ID-4,
/// `products/adapter/CONCEPT.md` section 6).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PinnedRef {
    /// The referenced artifact's identifier.
    pub id: ExternalId,
    /// The referenced artifact's version.
    pub version: String,
    /// The digest the artifact's bytes must hash to.
    pub digest: Digest,
}

/// One declared record field, typed under CFG-VAL-9 so fixture values and
/// route outputs are checked against it.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordField {
    /// The field name.
    pub name: LocalId,
    /// The field's value type.
    pub r#type: RecordFieldType,
    /// Whether every record of the type carries the field.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub required: bool,
}

/// A record field's value type (CFG-VAL-9).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum RecordFieldType {
    String,
    Integer,
    Decimal,
    Boolean,
    Date,
    DateTime,
}

/// One declared record type and its fields
/// (`products/adapter/CONCEPT.md` section 6).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordType {
    /// The record type name, the `{type}` of concrete operations.
    pub name: LocalId,
    /// The declared fields, unique by whole item.
    pub fields: registry_platform_yaml::UniqueList<RecordField>,
}

impl registry_platform_yaml::Identified for RecordType {
    fn id(&self) -> &str {
        self.name.as_str()
    }
}

/// One binding of a concrete contract operation to a route
/// (`products/adapter/CONCEPT.md` section 7): one concrete operation per
/// (profile operation, record type) pair, with the static worst-case
/// upstream-call budget the checks hold the route to.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Binding {
    /// The binding identifier.
    pub id: ExternalId,
    /// The profile operation this binding serves.
    pub operation: ExternalId,
    /// The record type the concrete operation serves.
    pub record_type: LocalId,
    /// The route the operation dispatches to.
    pub route: ExternalId,
    /// The declared budget of upstream sends per exchange; the static
    /// worst-case count must stay within it.
    pub maximum_upstream_calls: registry_platform_yaml::BoundedU64<1, 100_000>,
}

impl registry_platform_yaml::Identified for Binding {
    fn id(&self) -> &str {
        self.id.as_str()
    }
}

/// One access profile: a named binding of scopes to concrete facade
/// operations and record types, reviewed deployment policy
/// (`products/adapter/CONCEPT.md` section 10.1).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessProfile {
    /// The access profile name a caller identity is granted.
    pub id: ExternalId,
    /// The OIDC scopes the profile admits.
    pub scopes: Vec<ExternalId>,
    /// The profile operation ids the profile may call.
    pub operations: Vec<ExternalId>,
    /// The record types the profile may touch.
    pub record_types: Vec<LocalId>,
}

impl registry_platform_yaml::Identified for AccessProfile {
    fn id(&self) -> &str {
        self.id.as_str()
    }
}

/// The project identity block: the deployment's own name and version
/// (`products/adapter/CONCEPT.md` section 10.1). The id is a local
/// identifier (CFG-ID-1); the version is text, the same version-as-text
/// rule as profiles and packs.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectIdentity {
    /// The project identifier.
    pub id: LocalId,
    /// The project version.
    pub version: String,
}

/// The adapter project artifact (`AdapterProject`): the declared record
/// model, the pinned profile and pack references, the template
/// instantiations, the bindings, and the access profiles.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdapterProject {
    /// The deployment's identity.
    pub project: ProjectIdentity,
    /// The pinned facade profile.
    pub profile: PinnedRef,
    /// The pinned adapter pack.
    pub pack: PinnedRef,
    /// The declared record types and fields.
    pub record_types: UniqueIdList<RecordType>,
    /// The pack template instantiations, Camel's `templatedRoute`.
    #[serde(default)]
    pub templated_routes: UniqueIdList<crate::route::TemplatedRoute>,
    /// The bindings of contract operations to routes.
    #[serde(default)]
    pub bindings: UniqueIdList<Binding>,
    /// The access profiles.
    #[serde(default)]
    pub access_profiles: UniqueIdList<AccessProfile>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin(id: &str) -> PinnedRef {
        PinnedRef {
            id: ExternalId::new(id).expect("id"),
            version: "1.0.0".to_string(),
            digest: Digest::new(
                "sha256:678260a56715cba21db1f0687e5a2c5e5efb2ea0b8eea687b5f3ee8723c5f6c9",
            )
            .expect("digest"),
        }
    }

    fn record_type() -> RecordType {
        RecordType {
            name: LocalId::new("case").expect("name"),
            fields: registry_platform_yaml::UniqueList::new(vec![
                RecordField {
                    name: LocalId::new("national_id").expect("field"),
                    r#type: RecordFieldType::String,
                    required: true,
                },
                RecordField {
                    name: LocalId::new("opened_on").expect("field"),
                    r#type: RecordFieldType::Date,
                    required: false,
                },
            ])
            .expect("unique"),
        }
    }

    /// The project artifact round-trips: pinned refs, record model,
    /// instantiations, bindings with budgets, access profiles.
    #[test]
    fn project_round_trips() {
        let project = AdapterProject {
            project: ProjectIdentity {
                id: LocalId::new("case-deployment").expect("id"),
                version: "1.0.0".to_string(),
            },
            profile: pin("case-api"),
            pack: pin("case-api-pack"),
            record_types: UniqueIdList::new(vec![record_type()]).expect("unique"),
            templated_routes: UniqueIdList::new(vec![crate::route::TemplatedRoute {
                route_template: ExternalId::new("pagedFetch").expect("id"),
                route_id: ExternalId::new("fetchCases").expect("id"),
                parameters: std::collections::BTreeMap::from([(
                    "program".to_string(),
                    serde_json::json!("salsa"),
                )]),
            }])
            .expect("unique"),
            bindings: UniqueIdList::new(vec![Binding {
                id: ExternalId::new("find-cases").expect("id"),
                operation: ExternalId::new("cases.find").expect("op"),
                record_type: LocalId::new("case").expect("type"),
                route: ExternalId::new("fetchCases").expect("route"),
                maximum_upstream_calls: registry_platform_yaml::BoundedU64::<1, 100_000>::new(30)
                    .expect("budget"),
            }])
            .expect("unique"),
            access_profiles: UniqueIdList::new(vec![AccessProfile {
                id: ExternalId::new("registry-clerk").expect("id"),
                scopes: vec![ExternalId::new("records:read").expect("scope")],
                operations: vec![ExternalId::new("cases.find").expect("op")],
                record_types: vec![LocalId::new("case").expect("type")],
            }])
            .expect("unique"),
        };
        let json = serde_json::to_string(&project).expect("serialize");
        assert!(json.contains("maximumUpstreamCalls"));
        assert_eq!(
            serde_json::from_str::<AdapterProject>(&json).ok(),
            Some(project)
        );
    }

    /// The project identity block is required: a missing `project` block
    /// and a bare top-level `id` are both refused, and the block's id is a
    /// local identifier (addendum c).
    #[test]
    fn the_project_identity_block_is_required() {
        let project = AdapterProject {
            project: ProjectIdentity {
                id: LocalId::new("case-deployment").expect("id"),
                version: "1.0.0".to_string(),
            },
            profile: pin("case-api"),
            pack: pin("case-api-pack"),
            record_types: UniqueIdList::new(vec![record_type()]).expect("unique"),
            templated_routes: UniqueIdList::new(Vec::new()).expect("empty"),
            bindings: UniqueIdList::new(Vec::new()).expect("empty"),
            access_profiles: UniqueIdList::new(Vec::new()).expect("empty"),
        };
        let json = serde_json::to_value(&project).expect("serialize");

        let mut missing = json.clone();
        missing.as_object_mut().expect("object").remove("project");
        assert!(
            serde_json::from_value::<AdapterProject>(missing).is_err(),
            "a project without its identity block is refused"
        );

        let mut bare = json;
        let object = bare.as_object_mut().expect("object");
        object.remove("project");
        object.insert("id".to_string(), serde_json::json!("case-deployment"));
        assert!(
            serde_json::from_value::<AdapterProject>(bare).is_err(),
            "a bare top-level id is refused"
        );
    }

    /// Repeated record types, bindings, and access profiles are refused at
    /// the reader (CFG-ID-5); repeated fields are refused as duplicate
    /// items (CFG-ID-6).
    #[test]
    fn duplicates_are_refused() {
        assert!(UniqueIdList::new(vec![record_type(), record_type()]).is_err());
        let fields = registry_platform_yaml::UniqueList::new(vec![
            RecordField {
                name: LocalId::new("national_id").expect("field"),
                r#type: RecordFieldType::String,
                required: true,
            },
            RecordField {
                name: LocalId::new("national_id").expect("field"),
                r#type: RecordFieldType::String,
                required: true,
            },
        ]);
        // UniqueList dedups identical items (CFG-ID-6): the same field
        // twice is refused; same name with different shape is not.
        assert!(fields.is_err());
    }
}
