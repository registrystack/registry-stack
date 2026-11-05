// SPDX-License-Identifier: Apache-2.0

//! The adapter project: the deployment artifact that binds a profile to a
//! pack over a declared record model (`products/adapter/CONCEPT.md`
//! sections 6, 7, and 10.1).

use registry_platform_yaml::{Digest, ExternalId, LocalId, UniqueIdList, UniqueList};
use serde::{Deserialize, Serialize};

/// One project-owned Rhai source. The deployment project, rather than the
/// reusable source pack, owns programme and public-view transformations.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectScript {
    /// The local name transformations use.
    pub id: LocalId,
    /// A clean path relative to the project document.
    pub file: String,
    /// The exact sha256 digest of the Rhai source bytes.
    pub digest: Digest,
}

impl registry_platform_yaml::Identified for ProjectScript {
    fn id(&self) -> &str {
        self.id.as_str()
    }
}

/// One project-owned public data schema. The schema bytes carry their stable,
/// versioned HTTPS `$id`; this inventory binds those bytes into the project
/// closure without duplicating that public identity in YAML.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectSchema {
    /// The local name a Consultation collection uses as `dataSchema`.
    pub id: LocalId,
    /// A clean path relative to the project document.
    pub file: String,
    /// The exact sha256 digest of the JSON Schema bytes.
    pub digest: Digest,
}

impl registry_platform_yaml::Identified for ProjectSchema {
    fn id(&self) -> &str {
        self.id.as_str()
    }
}

/// The project-owned artifact inventory. Empty inventories preserve existing
/// generic profile deployments, which keep all route behavior in their pack.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectArtifacts {
    /// Programme and public-view transformation scripts.
    #[serde(default)]
    pub scripts: UniqueIdList<ProjectScript>,
    /// Versioned public JSON Schemas.
    #[serde(default)]
    pub schemas: UniqueIdList<ProjectSchema>,
}

impl ProjectArtifacts {
    fn is_empty(&self) -> bool {
        self.scripts.is_empty() && self.schemas.is_empty()
    }
}

/// One binding's project-owned transformation. Its output schema is not
/// repeated here: the binding's record type selects one Consultation
/// collection/view, and that collection owns the single `dataSchema`
/// reference.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BindingTransform {
    /// A [`ProjectScript`] id.
    pub script: LocalId,
    /// The one-argument Rhai function invoked as `entrypoint(source)`.
    pub entrypoint: String,
}

/// One deployment of the built-in GovStack direct Write target. Protocol
/// paths, envelopes, error shapes, and Create/Update wrappers remain
/// maintained Rust; the project selects collections and domain schemas.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WriteFacade {
    /// Version-specific HTTPS OpenAPI contract published for this deployment.
    pub contract: String,
    /// Collection metadata, unique by the record type that also supplies the
    /// public collection identifier.
    pub collections: UniqueIdList<WriteCollection>,
}

/// Deployment metadata for direct Create of one record.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WriteCreate {
    /// Project-owned domain schema for `CreateInput.data`.
    pub input_schema: LocalId,
}

/// Deployment metadata for conditional Update of one record.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WriteUpdate {
    /// Project-owned domain merge-patch schema for `UpdateInput.data`.
    pub input_schema: LocalId,
    /// Existing same-collection read binding used by the one supporting GET.
    /// When omitted, the one `retrieve` or `writable-read` binding of the
    /// record type fills it; a record type with more than one such binding
    /// must name it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub companion_read: Option<LocalId>,
}

/// Direct-write selection for one project record type. At least one of
/// Create and Update is required. Registry, view, and readable data-schema
/// metadata may be inherited from a matching Consultation collection; a
/// Write-only Update supplies them explicitly.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WriteCollection {
    /// Project record type and literal Write collection identifier.
    pub record_type: LocalId,
    /// Stable identifier of the Registry that owns the Records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
    /// Public writable view, required for a Write-only Update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view: Option<LocalId>,
    /// Project schema for the companion read's public `data`, required for a
    /// Write-only Update and separate by selection from each input schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_data_schema: Option<LocalId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub create: Option<WriteCreate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update: Option<WriteUpdate>,
}

impl<'de> Deserialize<'de> for WriteCollection {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            record_type: LocalId,
            #[serde(default)]
            registry: Option<String>,
            #[serde(default)]
            view: Option<LocalId>,
            #[serde(default)]
            read_data_schema: Option<LocalId>,
            #[serde(default)]
            create: Option<WriteCreate>,
            #[serde(default)]
            update: Option<WriteUpdate>,
        }

        let wire = Wire::deserialize(deserializer)?;
        if wire.create.is_none() && wire.update.is_none() {
            return Err(registry_platform_yaml::Invalid::expected(
                "at least one direct write operation: create or update",
                "Add create, update, or both.",
            )
            .into_error());
        }
        Ok(Self {
            record_type: wire.record_type,
            registry: wire.registry,
            view: wire.view,
            read_data_schema: wire.read_data_schema,
            create: wire.create,
            update: wire.update,
        })
    }
}

impl registry_platform_yaml::Identified for WriteCollection {
    fn id(&self) -> &str {
        self.record_type.as_str()
    }
}

/// A pinned reference to a profile or pack: plain identifier plus the
/// version and digest `adapterctl check` verifies (CFG-ID-4,
/// `products/adapter/CONCEPT.md` section 6).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PinnedRef {
    /// The referenced artifact's identifier.
    pub id: LocalId,
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

/// How one asynchronous binding answers while the source operation remains
/// pending. Both modes use the same profile-owned status link; bounded wait
/// spends only the declared finite interval and poll count first.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum BindingAsyncCompletion {
    /// Return the committed accepted response immediately.
    StatusLink {},
    /// Poll within all three authored bounds, then return either a proven
    /// terminal response or the same committed accepted response.
    BoundedWait {
        wait_timeout_milliseconds: registry_platform_yaml::BoundedU64<1, 30_000>,
        poll_interval_milliseconds: registry_platform_yaml::BoundedU64<10, 10_000>,
        maximum_polls: registry_platform_yaml::BoundedU64<1, 100>,
    },
}

registry_platform_yaml::tagged_union!(BindingAsyncCompletion, tag = "type");
crate::model::serialize_tagged_union!(BindingAsyncCompletion, tag = "type");

/// The project keys a later format renamed, each with what replaced it
/// (CFG-CHANGE-2), so an older `project.yaml` is refused at the key with
/// the fix.
pub const ADAPTER_PROJECT_REMOVED_KEYS: &[registry_platform_yaml::RemovedKey<'static>] =
    &[registry_platform_yaml::RemovedKey {
        pointer: "/bindings/*/asyncCompletion/mode",
        replacement: "Write type: status-link or bounded-wait in its place.",
    }];

/// One binding of a concrete contract operation to a route
/// (`products/adapter/CONCEPT.md` section 7): one concrete operation per
/// (profile operation, record type) pair, with the static worst-case
/// upstream-call budget the checks hold the route to.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Binding {
    /// The binding identifier.
    pub id: LocalId,
    /// The profile operation this binding serves.
    pub operation: ExternalId,
    /// The record type the concrete operation serves.
    pub record_type: LocalId,
    /// The route the operation dispatches to.
    pub route: ExternalId,
    /// The declared fields of the bound record type a search binding
    /// filters on (`products/adapter/CONCEPT.md` section 8.11.1); the
    /// facade offers exactly these as typed equality query parameters.
    /// Every declared filter is required: a call that leaves one out is
    /// refused as an invalid field before any script runs or source is
    /// called.
    /// Every entry must name a declared field, checked at the project
    /// checks; the list is unique (CFG-ID-6).
    #[serde(default, skip_serializing_if = "filters_empty")]
    pub filters: registry_platform_yaml::UniqueList<LocalId>,
    /// The declared budget of upstream sends per exchange; the static
    /// worst-case count must stay within it. Defaults to 4.
    #[serde(default = "default_maximum_upstream_calls")]
    pub maximum_upstream_calls: registry_platform_yaml::BoundedU64<1, 100_000>,
    /// The asynchronous response policy, absent for every synchronous
    /// binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub async_completion: Option<BindingAsyncCompletion>,
}

/// The upstream-call budget of a binding that declares none; the value the
/// Binding schema documents as its default.
pub const DEFAULT_MAXIMUM_UPSTREAM_CALLS: u64 = 4;

fn default_maximum_upstream_calls() -> registry_platform_yaml::BoundedU64<1, 100_000> {
    registry_platform_yaml::BoundedU64::new(DEFAULT_MAXIMUM_UPSTREAM_CALLS)
        .expect("the default budget is within its bounds")
}

/// A filter list is omitted from the wire when empty, the shape `Vec`'s
/// `skip_serializing_if = "Vec::is_empty"` gave.
fn filters_empty(filters: &registry_platform_yaml::UniqueList<LocalId>) -> bool {
    filters.is_empty()
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
    pub id: LocalId,
    /// The OIDC scopes the profile admits, unique (CFG-ID-6).
    pub scopes: UniqueList<ExternalId>,
    /// The profile operation ids the profile may call, unique (CFG-ID-6).
    pub operations: UniqueList<ExternalId>,
    /// The record types the profile may touch, unique (CFG-ID-6).
    pub record_types: UniqueList<LocalId>,
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
/// instantiations, the bindings, and the access profiles. Reading a project
/// derives the members its short form leaves out; an explicit member always
/// wins.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(remote = "Self", rename_all = "camelCase", deny_unknown_fields)]
pub struct AdapterProject {
    /// The deployment's identity.
    pub project: ProjectIdentity,
    /// The pinned authored facade profile. Exactly one of this member and
    /// `consultation` selects the deployment's caller-facing protocol.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<PinnedRef>,
    /// The project metadata for the built-in Consultation facade. Its paths,
    /// envelopes, problems, and protocol schemas remain maintained Rust.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consultation: Option<crate::ConsultationFacade>,
    /// The project metadata for the built-in synchronous GovStack direct
    /// Write target. It may coexist with Consultation, but never with an
    /// authored generic profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write: Option<WriteFacade>,
    /// The pinned adapter pack.
    pub pack: PinnedRef,
    /// The declared record types and fields. A Consultation or Write
    /// record type left out is declared with no fields.
    #[serde(default)]
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
    /// Digest-pinned deployment-owned scripts and public schemas.
    #[serde(default, skip_serializing_if = "ProjectArtifacts::is_empty")]
    pub artifacts: ProjectArtifacts,
    /// Project-owned transformations keyed by the binding id they follow.
    /// The map form avoids duplicating the binding or source-route identity.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "crate::model::local_id_map_schema::<BindingTransform>")
    )]
    pub binding_transforms: std::collections::BTreeMap<LocalId, BindingTransform>,
    /// The deployment's value for each of the profile's parameterized
    /// parts, keyed by part name. The engine writes each value over the
    /// response-envelope members of that name; every declared part needs
    /// a value and no value names an undeclared part.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "crate::model::external_id_map_schema::<String>")
    )]
    pub parameterized_parts: std::collections::BTreeMap<ExternalId, String>,
}

impl<'de> Deserialize<'de> for AdapterProject {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut project = AdapterProject::deserialize(deserializer)?;
        project.derive_defaults();
        Ok(project)
    }
}

impl Serialize for AdapterProject {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        AdapterProject::serialize(self, serializer)
    }
}

impl AdapterProject {
    /// Fill what the short project form derives from the rest of the
    /// document; an explicit member always wins:
    ///
    /// - a Consultation or Write record type with no `recordTypes` entry is
    ///   declared with no fields;
    /// - a Consultation collection's `transform` follows every
    ///   `retrieve`, `lookup`, `list`, and `search` binding of its record
    ///   type that `bindingTransforms` leaves out;
    /// - an Update without `companionRead` takes the one `retrieve` or
    ///   `writable-read` binding of its record type. With none or more
    ///   than one it stays empty, and the project checks refuse it naming
    ///   the collection.
    fn derive_defaults(&mut self) {
        let consultation = self
            .consultation
            .iter()
            .flat_map(|consultation| consultation.collections.iter());
        let written = self
            .write
            .iter()
            .flat_map(|write| write.collections.iter())
            .map(|collection| &collection.record_type);
        let mut record_types = std::mem::take(&mut self.record_types).into_vec();
        for name in consultation
            .clone()
            .map(|collection| &collection.record_type)
            .chain(written)
        {
            if !record_types.iter().any(|declared| &declared.name == name) {
                record_types.push(RecordType {
                    name: name.clone(),
                    fields: UniqueList::new(Vec::new()).expect("an empty list is unique"),
                });
            }
        }
        self.record_types =
            UniqueIdList::new(record_types).expect("a derived record type is not yet declared");

        for collection in consultation {
            let Some(transform) = &collection.transform else {
                continue;
            };
            for binding in self.bindings.iter().filter(|binding| {
                binding.record_type == collection.record_type
                    && matches!(
                        binding.operation.as_str(),
                        "retrieve" | "lookup" | "list" | "search"
                    )
            }) {
                self.binding_transforms
                    .entry(binding.id.clone())
                    .or_insert_with(|| transform.clone());
            }
        }

        let Some(write) = &mut self.write else {
            return;
        };
        let mut collections = std::mem::take(&mut write.collections).into_vec();
        for collection in &mut collections {
            let Some(update) = &mut collection.update else {
                continue;
            };
            if update.companion_read.is_some() {
                continue;
            }
            let mut reads = self.bindings.iter().filter(|binding| {
                binding.record_type == collection.record_type
                    && matches!(binding.operation.as_str(), "retrieve" | "writable-read")
            });
            if let (Some(only), None) = (reads.next(), reads.next()) {
                update.companion_read = Some(only.id.clone());
            }
        }
        write.collections =
            UniqueIdList::new(collections).expect("filling a member keeps ids unique");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin(id: &str) -> PinnedRef {
        PinnedRef {
            id: LocalId::new(id).expect("id"),
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
            profile: Some(pin("case-api")),
            consultation: None,
            write: None,
            pack: pin("case-api-pack"),
            record_types: UniqueIdList::new(vec![record_type()]).expect("unique"),
            templated_routes: UniqueIdList::new(vec![crate::route::TemplatedRoute {
                route_template: ExternalId::new("paged-fetch").expect("id"),
                route_id: ExternalId::new("fetch-cases").expect("id"),
                parameters: std::collections::BTreeMap::from([(
                    "program".to_string(),
                    serde_json::json!("salsa"),
                )]),
            }])
            .expect("unique"),
            bindings: UniqueIdList::new(vec![Binding {
                id: LocalId::new("find-cases").expect("id"),
                operation: ExternalId::new("cases-find").expect("op"),
                record_type: LocalId::new("case").expect("type"),
                route: ExternalId::new("fetch-cases").expect("route"),
                filters: registry_platform_yaml::UniqueList::new(Vec::new()).expect("unique"),
                maximum_upstream_calls: registry_platform_yaml::BoundedU64::<1, 100_000>::new(30)
                    .expect("budget"),
                async_completion: None,
            }])
            .expect("unique"),
            access_profiles: UniqueIdList::new(vec![AccessProfile {
                id: LocalId::new("registry-clerk").expect("id"),
                scopes: UniqueList::new(vec![ExternalId::new("records:read").expect("scope")])
                    .expect("unique"),
                operations: UniqueList::new(vec![ExternalId::new("cases-find").expect("op")])
                    .expect("unique"),
                record_types: UniqueList::new(vec![LocalId::new("case").expect("type")])
                    .expect("unique"),
            }])
            .expect("unique"),
            artifacts: ProjectArtifacts::default(),
            binding_transforms: Default::default(),
            parameterized_parts: Default::default(),
        };
        let json = serde_json::to_string(&project).expect("serialize");
        assert!(json.contains("maximumUpstreamCalls"));
        assert_eq!(
            serde_json::from_str::<AdapterProject>(&json).ok(),
            Some(project)
        );
    }

    #[test]
    fn project_owned_transform_artifacts_round_trip_without_a_second_schema_reference() {
        let source = b"fn public_person(source) { #{ name: source.name } }";
        let schema = br#"{"$id":"https://example.test/schemas/person-public/1.0.0","type":"object","additionalProperties":false,"required":["name"],"properties":{"name":{"type":"string"}}}"#;
        let mut project = serde_json::from_value::<AdapterProject>(serde_json::json!({
            "project": {"id": "case-deployment", "version": "1.0.0"},
            "profile": {"id": "case-api", "version": "1.0.0", "digest": "sha256:678260a56715cba21db1f0687e5a2c5e5efb2ea0b8eea687b5f3ee8723c5f6c9"},
            "pack": {"id": "case-pack", "version": "1.0.0", "digest": "sha256:678260a56715cba21db1f0687e5a2c5e5efb2ea0b8eea687b5f3ee8723c5f6c9"},
            "recordTypes": [],
            "artifacts": {
                "scripts": [{"id": "person-public", "file": "transform/person-public.rhai", "digest": registry_platform_config::sha256_uri(source)}],
                "schemas": [{"id": "person-public", "file": "schemas/person-public.schema.json", "digest": registry_platform_config::sha256_uri(schema)}]
            },
            "bindingTransforms": {
                "find-person": {"script": "person-public", "entrypoint": "public_person"}
            }
        }))
        .expect("project reads");

        assert_eq!(project.artifacts.scripts.len(), 1);
        assert_eq!(project.artifacts.schemas.len(), 1);
        let transform = project
            .binding_transforms
            .remove(&LocalId::new("find-person").expect("id"))
            .expect("binding transform");
        assert_eq!(transform.script.as_str(), "person-public");
        assert_eq!(transform.entrypoint, "public_person");
        let wire = serde_json::to_value(project).expect("serialize");
        assert!(wire.get("recordSchemas").is_none());
        assert!(wire["bindingTransforms"]["find-person"]
            .get("outputSchema")
            .is_none());
    }

    /// One GovStack read/write deployment in its explicit and its short
    /// form. The short form omits the view that equals `dataSchema`, the
    /// stub record type, the default upstream budget, the companion read
    /// that only one binding can fill, and the read transform repeated on
    /// every binding of the collection.
    fn govstack_project(short: bool) -> serde_json::Value {
        let digest = "sha256:678260a56715cba21db1f0687e5a2c5e5efb2ea0b8eea687b5f3ee8723c5f6c9";
        let budget = |binding: serde_json::Value| {
            let mut binding = binding;
            if !short {
                binding["maximumUpstreamCalls"] = serde_json::json!(4);
            }
            binding
        };
        let mut collection = serde_json::json!({
            "recordType": "people",
            "registry": "https://registry.example/registries/people",
            "dataSchema": "person-public"
        });
        let mut update = serde_json::json!({"inputSchema": "person-update"});
        let mut transforms = serde_json::json!({
            "people-create": {"script": "person", "entrypoint": "create_person"},
            "people-update": {"script": "person", "entrypoint": "update_person"}
        });
        if short {
            collection["transform"] =
                serde_json::json!({"script": "person", "entrypoint": "public_person"});
        } else {
            collection["view"] = serde_json::json!("person-public");
            update["companionRead"] = serde_json::json!("people-retrieve");
            for binding in ["people-retrieve", "people-list"] {
                transforms[binding] =
                    serde_json::json!({"script": "person", "entrypoint": "public_person"});
            }
        }
        let mut project = serde_json::json!({
            "project": {"id": "people-deployment", "version": "1.0.0"},
            "consultation": {
                "contract": "https://registry.example/contracts/1.0.0-draft/openapi.yaml",
                "collections": [collection]
            },
            "write": {
                "contract": "https://registry.example/contracts/1.0.0-draft/openapi.yaml",
                "collections": [{
                    "recordType": "people",
                    "create": {"inputSchema": "person-create"},
                    "update": update
                }]
            },
            "pack": {"id": "people-pack", "version": "1", "digest": digest},
            "bindings": [
                budget(serde_json::json!({"id": "people-retrieve", "operation": "retrieve", "recordType": "people", "route": "read"})),
                budget(serde_json::json!({"id": "people-list", "operation": "list", "recordType": "people", "route": "page"})),
                budget(serde_json::json!({"id": "people-create", "operation": "create", "recordType": "people", "route": "create"})),
                budget(serde_json::json!({"id": "people-update", "operation": "update", "recordType": "people", "route": "update"}))
            ],
            "bindingTransforms": transforms
        });
        if !short {
            project["recordTypes"] = serde_json::json!([{"name": "people", "fields": []}]);
        }
        project
    }

    #[test]
    fn the_short_project_form_reads_as_its_explicit_form() {
        let explicit: AdapterProject =
            serde_json::from_value(govstack_project(false)).expect("explicit project");
        let short: AdapterProject =
            serde_json::from_value(govstack_project(true)).expect("short project");

        assert_eq!(short.record_types, explicit.record_types);
        assert_eq!(short.bindings, explicit.bindings);
        assert_eq!(short.binding_transforms, explicit.binding_transforms);
        assert_eq!(short.write, explicit.write);
        let view = |project: &AdapterProject| {
            project
                .consultation
                .as_ref()
                .and_then(|consultation| consultation.collections.get("people"))
                .map(|collection| collection.view.clone())
        };
        assert_eq!(view(&short), view(&explicit));
        assert_eq!(
            short.bindings[0].maximum_upstream_calls.get(),
            DEFAULT_MAXIMUM_UPSTREAM_CALLS
        );
    }

    #[test]
    fn an_explicit_member_overrides_its_short_form_default() {
        let mut value = govstack_project(true);
        value["consultation"]["collections"][0]["view"] = serde_json::json!("person-summary");
        value["bindings"][0]["maximumUpstreamCalls"] = serde_json::json!(1);
        value["bindingTransforms"]["people-list"] =
            serde_json::json!({"script": "person", "entrypoint": "list_person"});
        value["recordTypes"] = serde_json::json!([{
            "name": "people",
            "fields": [{"name": "region", "type": "string"}]
        }]);
        let project: AdapterProject = serde_json::from_value(value).expect("project");

        let collection = project
            .consultation
            .as_ref()
            .and_then(|consultation| consultation.collections.get("people"))
            .expect("collection");
        assert_eq!(collection.view.as_str(), "person-summary");
        assert_eq!(project.bindings[0].maximum_upstream_calls.get(), 1);
        let entrypoint = |binding: &str| {
            project
                .binding_transforms
                .get(&LocalId::new(binding).expect("id"))
                .map(|transform| transform.entrypoint.as_str())
        };
        assert_eq!(entrypoint("people-list"), Some("list_person"));
        assert_eq!(entrypoint("people-retrieve"), Some("public_person"));
        assert_eq!(project.record_types.len(), 1);
        assert_eq!(project.record_types[0].fields.len(), 1);
    }

    #[test]
    fn an_ambiguous_companion_read_is_left_for_the_named_check() {
        let mut value = govstack_project(true);
        value["bindings"]
            .as_array_mut()
            .expect("bindings")
            .push(serde_json::json!({
                "id": "people-writable-read", "operation": "writable-read",
                "recordType": "people", "route": "read"
            }));
        let project: AdapterProject = serde_json::from_value(value).expect("project");
        let update = project
            .write
            .as_ref()
            .and_then(|write| write.collections.get("people"))
            .and_then(|collection| collection.update.as_ref())
            .expect("update");
        assert_eq!(update.companion_read, None);
    }

    #[test]
    fn direct_write_metadata_round_trips_without_authored_protocol_envelopes() {
        let write: WriteFacade = serde_json::from_value(serde_json::json!({
            "contract": "https://registry.example/contracts/write/1.0.0-draft/openapi.yaml",
            "collections": [{
                "recordType": "people",
                "registry": "https://registry.example/registries/people",
                "view": "person-writable",
                "readDataSchema": "person-readable",
                "create": {"inputSchema": "person-create"},
                "update": {"inputSchema": "person-update", "companionRead": "people-writable-read"}
            }]
        }))
        .expect("write metadata");

        let collection = write.collections.get("people").expect("collection");
        assert_eq!(collection.record_type.as_str(), "people");
        assert_eq!(
            collection
                .update
                .as_ref()
                .expect("update")
                .companion_read
                .as_ref()
                .map(LocalId::as_str),
            Some("people-writable-read")
        );
        let encoded = serde_json::to_value(write).expect("serialize");
        assert!(encoded.get("paths").is_none());
        assert!(encoded["collections"][0]["create"]
            .get("sourceSchema")
            .is_none());
    }

    #[test]
    fn direct_write_metadata_is_closed_and_each_collection_selects_an_operation() {
        let collection =
            |members: serde_json::Value| serde_json::from_value::<WriteCollection>(members);
        assert!(collection(serde_json::json!({
            "recordType": "people",
            "create": {"inputSchema": "person-create"}
        }))
        .is_ok());
        assert!(collection(serde_json::json!({
            "recordType": "people",
            "update": {"inputSchema": "person-update", "companionRead": "people-writable-read"}
        }))
        .is_ok());
        assert!(collection(serde_json::json!({"recordType": "people"})).is_err());
        assert!(collection(serde_json::json!({
            "recordType": "people",
            "transition": {"inputSchema": "transition"}
        }))
        .is_err());
        assert!(collection(serde_json::json!({
            "recordType": "people",
            "create": {"inputSchema": "person-create", "sourceReference": true}
        }))
        .is_err());
    }

    /// A binding's filter list is unique (CFG-ID-6): a repeated field
    /// name refuses at the reader, a declared list reads back in order,
    /// and an omitted list reads as empty and serializes omitted.
    #[test]
    fn a_binding_refuses_duplicate_filters() {
        let binding_json = |filters: &str| {
            format!(
                r#"{{"id":"find-cases","operation":"cases-find","recordType":"case","route":"fetch-cases"{filters},"maximumUpstreamCalls":30}}"#
            )
        };
        let duplicate = binding_json(r#","filters":["region","region"]"#);
        assert!(
            serde_json::from_str::<Binding>(&duplicate).is_err(),
            "a repeated filter field refuses"
        );
        let declared = binding_json(r#","filters":["region","opened-on"]"#);
        let parsed = serde_json::from_str::<Binding>(&declared).expect("parse");
        let names: Vec<&str> = parsed
            .filters
            .iter()
            .map(|filter| filter.as_str())
            .collect();
        assert_eq!(names, vec!["region", "opened-on"]);
        let omitted = serde_json::from_str::<Binding>(&binding_json("")).expect("parse");
        assert!(omitted.filters.is_empty());
        assert!(
            !serde_json::to_string(&omitted)
                .expect("serialize")
                .contains("filters"),
            "an empty filter list stays off the wire"
        );
    }

    /// The project identity block is required: a missing `project` block
    /// and a bare top-level `id` are both refused, and the block's id is a
    /// local identifier (addendum c).
    #[test]
    fn the_project_identity_block_is_required() {
        let project = AdapterProject {
            consultation: None,
            write: None,
            artifacts: Default::default(),
            binding_transforms: Default::default(),
            project: ProjectIdentity {
                id: LocalId::new("case-deployment").expect("id"),
                version: "1.0.0".to_string(),
            },
            profile: Some(pin("case-api")),
            pack: pin("case-api-pack"),
            record_types: UniqueIdList::new(vec![record_type()]).expect("unique"),
            templated_routes: UniqueIdList::new(Vec::new()).expect("empty"),
            bindings: UniqueIdList::new(Vec::new()).expect("empty"),
            access_profiles: UniqueIdList::new(Vec::new()).expect("empty"),
            parameterized_parts: Default::default(),
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

    /// An access profile's scopes, operations, and record types are
    /// unique at the reader (CFG-ID-6): a repeated member is refused.
    #[test]
    fn access_profile_members_are_unique() {
        let read = |scopes: &[&str], operations: &[&str], record_types: &[&str]| {
            serde_json::from_value::<AccessProfile>(serde_json::json!({
                "id": "registry-clerk",
                "scopes": scopes,
                "operations": operations,
                "recordTypes": record_types,
            }))
        };
        assert!(read(&["cases:read"], &["cases-find"], &["case"]).is_ok());
        assert!(
            read(&["cases:read", "cases:read"], &["cases-find"], &["case"]).is_err(),
            "a repeated scope is refused"
        );
        assert!(
            read(&["cases:read"], &["cases-find", "cases-find"], &["case"]).is_err(),
            "a repeated operation is refused"
        );
        assert!(
            read(&["cases:read"], &["cases-find"], &["case", "case"]).is_err(),
            "a repeated record type is refused"
        );
    }

    #[test]
    fn binding_async_completion_modes_are_closed_and_bounded() {
        let binding = |completion: &str| {
            format!(
                r#"{{"id":"create-case","operation":"cases-create","recordType":"case","route":"create-case","maximumUpstreamCalls":30{completion}}}"#
            )
        };
        let sync = serde_json::from_str::<Binding>(&binding("")).expect("sync binding");
        assert!(sync.async_completion.is_none());
        assert!(!serde_json::to_string(&sync)
            .expect("serialize")
            .contains("asyncCompletion"));

        let linked = serde_json::from_str::<Binding>(&binding(
            r#", "asyncCompletion":{"type":"status-link"}"#,
        ))
        .expect("status link");
        assert!(matches!(
            linked.async_completion,
            Some(BindingAsyncCompletion::StatusLink {})
        ));
        assert_eq!(
            serde_json::to_value(linked.async_completion.expect("completion"))
                .expect("serialize completion"),
            serde_json::json!({"type": "status-link"})
        );

        let waited = serde_json::from_str::<Binding>(&binding(
            r#", "asyncCompletion":{"type":"bounded-wait","waitTimeoutMilliseconds":30000,"pollIntervalMilliseconds":10,"maximumPolls":100}"#,
        ))
        .expect("bounded wait");
        assert!(matches!(
            waited.async_completion,
            Some(BindingAsyncCompletion::BoundedWait {
                wait_timeout_milliseconds,
                poll_interval_milliseconds,
                maximum_polls,
            }) if wait_timeout_milliseconds.get() == 30_000
                && poll_interval_milliseconds.get() == 10
                && maximum_polls.get() == 100
        ));

        for refused in [
            r#", "asyncCompletion":{"mode":"status-link"}"#,
            r#", "asyncCompletion":{"type":"status-link","maximumPolls":1}"#,
            r#", "asyncCompletion":{"type":"bounded-wait","waitTimeoutMilliseconds":1,"pollIntervalMilliseconds":10}"#,
            r#", "asyncCompletion":{"type":"bounded-wait","waitTimeoutMilliseconds":0,"pollIntervalMilliseconds":10,"maximumPolls":1}"#,
            r#", "asyncCompletion":{"type":"bounded-wait","waitTimeoutMilliseconds":30001,"pollIntervalMilliseconds":10,"maximumPolls":1}"#,
            r#", "asyncCompletion":{"type":"bounded-wait","waitTimeoutMilliseconds":1,"pollIntervalMilliseconds":9,"maximumPolls":1}"#,
            r#", "asyncCompletion":{"type":"bounded-wait","waitTimeoutMilliseconds":1,"pollIntervalMilliseconds":10001,"maximumPolls":1}"#,
            r#", "asyncCompletion":{"type":"bounded-wait","waitTimeoutMilliseconds":1,"pollIntervalMilliseconds":10,"maximumPolls":0}"#,
            r#", "asyncCompletion":{"type":"bounded-wait","waitTimeoutMilliseconds":1,"pollIntervalMilliseconds":10,"maximumPolls":101}"#,
            r#", "asyncCompletion":{"type":"bounded-wait","waitTimeoutMilliseconds":1,"pollIntervalMilliseconds":10,"maximumPolls":1,"bogus":true}"#,
            r#", "asyncCompletion":{"type":"forever"}"#,
        ] {
            assert!(serde_json::from_str::<Binding>(&binding(refused)).is_err());
        }
    }
}
