// SPDX-License-Identifier: Apache-2.0

//! How an authored access member writes "no restriction" (CFG-EMPTY-2).
//!
//! A member that grants reach takes the keyword `unrestricted` or a list of at
//! least one item. A member that only narrows is omitted when it narrows
//! nothing. An empty list is refused in both places, because it reads as both
//! "none" and "any".
//!
//! Everything here is the authored form only. Each member is read into, and
//! written from, the plain collection the compiler holds, where empty means
//! no restriction, so the compiled model and every digest over it keep their
//! shape.

use std::convert::Infallible;
use std::marker::PhantomData;

use registry_platform_yaml::{shape_union, Invalid};
use serde::{de::IgnoredAny, Deserialize, Deserializer, Serialize, Serializer};

use super::{
    AccessProfileSource, AccessRequirementsSource, ActorKindSource, ApplyTargetPermissionSource,
    CompiledTaskGrantSource, ConsentRequirementSource, LookupPermissionSource,
    MembershipBoundarySource, Operation, ProvenanceFieldSource, ReadPathPermissionSource,
    RequestMetadataFieldSource, RequestPresencePermissionSource, RequestVisibilitySource,
    RowBoundarySource, SpatialQueryPermissionSource, UniqueSet,
};

const UNRESTRICTED: &str = "unrestricted";

/// What one member expects, and how its author fixes a value it refuses.
pub(super) trait Member {
    const EXPECTED: &'static str;
    const ACTION: &'static str;
}

fn refused<M: Member, E: serde::de::Error>() -> E {
    Invalid::expected(M::EXPECTED, M::ACTION).into_error()
}

/// A collection that can hold nothing.
pub(super) trait Items {
    fn holds_nothing(&self) -> bool;
}

impl Items for UniqueSet<String> {
    fn holds_nothing(&self) -> bool {
        self.is_empty()
    }
}

impl Items for Vec<RowBoundarySource> {
    fn holds_nothing(&self) -> bool {
        self.is_empty()
    }
}

#[cfg(feature = "runtime")]
impl Items for Vec<String> {
    fn holds_nothing(&self) -> bool {
        self.is_empty()
    }
}

/// The keyword `unrestricted`.
pub(crate) struct Unrestricted<M>(PhantomData<M>);

impl<'de, M: Member> Deserialize<'de> for Unrestricted<M> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if String::deserialize(deserializer)? == UNRESTRICTED {
            Ok(Self(PhantomData))
        } else {
            Err(refused::<M, _>())
        }
    }
}

#[cfg(feature = "schema")]
impl<M> schemars::JsonSchema for Unrestricted<M> {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Unrestricted".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({"type": "string", "const": UNRESTRICTED})
    }
}

/// A scalar written where a member takes only a list. It is never accepted.
pub(super) struct NotAList<M>(Infallible, PhantomData<M>);

impl<'de, M: Member> Deserialize<'de> for NotAList<M> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        IgnoredAny::deserialize(deserializer)?;
        Err(refused::<M, _>())
    }
}

/// A list of at least one item.
pub(crate) struct Listed<L, M>(L, PhantomData<M>);

impl<'de, L: Deserialize<'de> + Items, M: Member> Deserialize<'de> for Listed<L, M> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let items = L::deserialize(deserializer)?;
        if items.holds_nothing() {
            return Err(refused::<M, _>());
        }
        Ok(Self(items, PhantomData))
    }
}

#[cfg(feature = "schema")]
impl<L: schemars::JsonSchema, M> schemars::JsonSchema for Listed<L, M> {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        format!("Listed_{}", L::schema_name()).into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let mut schema = generator.subschema_for::<L>();
        schema.insert("minItems".to_owned(), 1.into());
        schema
    }
}

/// The scopes a profile requires.
pub(super) enum Scopes {}

impl Member for Scopes {
    const EXPECTED: &'static str = "unrestricted, or a list of at least one scope";
    const ACTION: &'static str =
        "List the scopes a token must carry, or write unrestricted to require none.";
}

/// The rows a permission reaches.
pub(super) enum Rows {}

impl Member for Rows {
    const EXPECTED: &'static str = "unrestricted, or a list of at least one row boundary";
    const ACTION: &'static str =
        "List the row boundaries that bind rows to the caller's claims, or write unrestricted to reach every row.";
}

/// The scopes a token must carry to select a profile: the keyword
/// `unrestricted`, or a list of at least one scope.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(untagged))]
pub(super) enum RequiredScopes {
    /// Require no scope.
    Unrestricted(Unrestricted<Scopes>),
    /// Require every listed scope.
    Listed(Listed<UniqueSet<String>, Scopes>),
}

shape_union!(RequiredScopes { scalar => Unrestricted, list => Listed });

/// The rows a permission reaches: the keyword `unrestricted`, or a list of at
/// least one row boundary.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(untagged))]
pub(super) enum RowBoundaries {
    /// Reach every row.
    Unrestricted(Unrestricted<Rows>),
    /// Reach the rows every listed boundary binds to the caller's claims.
    Listed(Listed<Vec<RowBoundarySource>, Rows>),
}

shape_union!(RowBoundaries { scalar => Unrestricted, list => Listed });

/// The OAuth clients a runtime accepts tokens from.
#[cfg(feature = "runtime")]
pub(crate) enum Clients {}

#[cfg(feature = "runtime")]
impl Member for Clients {
    const EXPECTED: &'static str = "unrestricted, or a list of at least one OAuth client";
    const ACTION: &'static str =
        "List the OAuth clients whose tokens this registry accepts, or write unrestricted to accept every client.";
}

/// The OAuth clients whose tokens a runtime accepts: the keyword
/// `unrestricted`, or a list of at least one client.
#[cfg(feature = "runtime")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(untagged))]
pub(crate) enum AllowedClients {
    /// Accept a token from every client.
    Unrestricted(Unrestricted<Clients>),
    /// Accept a token only from a listed client.
    Listed(Listed<Vec<String>, Clients>),
}

#[cfg(feature = "runtime")]
shape_union!(AllowedClients { scalar => Unrestricted, list => Listed });

/// Reads the runtime's accepted clients into the list the token verifier
/// holds, where empty means every client.
#[cfg(feature = "runtime")]
pub(crate) fn allowed_clients<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<String>, D::Error> {
    Ok(match AllowedClients::deserialize(deserializer)? {
        AllowedClients::Unrestricted(_) => Vec::new(),
        AllowedClients::Listed(Listed(clients, _)) => clients,
    })
}

pub(super) fn required_scopes<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<UniqueSet<String>, D::Error> {
    Ok(match RequiredScopes::deserialize(deserializer)? {
        RequiredScopes::Unrestricted(_) => UniqueSet::new(),
        RequiredScopes::Listed(Listed(scopes, _)) => scopes,
    })
}

pub(super) fn serialize_required_scopes<S: Serializer>(
    scopes: &UniqueSet<String>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    if scopes.is_empty() {
        serializer.serialize_str(UNRESTRICTED)
    } else {
        scopes.serialize(serializer)
    }
}

pub(super) fn row_boundaries<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<RowBoundarySource>, D::Error> {
    Ok(match RowBoundaries::deserialize(deserializer)? {
        RowBoundaries::Unrestricted(_) => Vec::new(),
        RowBoundaries::Listed(Listed(boundaries, _)) => boundaries,
    })
}

/// The row reach of a permission that may be written without one.
pub(super) fn written_row_boundaries<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<RowBoundarySource>>, D::Error> {
    row_boundaries(deserializer).map(Some)
}

pub(super) fn serialize_row_boundaries<S: Serializer>(
    boundaries: &[RowBoundarySource],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    if boundaries.is_empty() {
        serializer.serialize_str(UNRESTRICTED)
    } else {
        boundaries.serialize(serializer)
    }
}

/// Declares a member that only narrows: a list of at least one item, omitted
/// when it narrows nothing. A scalar is refused with the same fix as an empty
/// list, so an author who writes `unrestricted` here is told to omit the
/// member.
macro_rules! narrowing_member {
    ($member:ident, $shapes:ident, $read:ident, $list:ty, $expected:literal, $action:literal) => {
        pub(super) enum $member {}

        impl Member for $member {
            const EXPECTED: &'static str = $expected;
            const ACTION: &'static str = $action;
        }

        enum $shapes {
            Scalar(NotAList<$member>),
            Listed(Listed<$list, $member>),
        }

        shape_union!($shapes { scalar => Scalar, list => Listed });

        pub(super) fn $read<'de, D: Deserializer<'de>>(deserializer: D) -> Result<$list, D::Error> {
            Ok(match $shapes::deserialize(deserializer)? {
                $shapes::Scalar(NotAList(never, _)) => match never {},
                $shapes::Listed(Listed(items, _)) => items,
            })
        }
    };
}

narrowing_member!(
    ProfilePurposes,
    ProfilePurposesShapes,
    profile_purposes,
    UniqueSet<String>,
    "a list of at least one purpose",
    "Omit requiredPurposes to accept every purpose, or list the purposes this profile accepts."
);

narrowing_member!(
    ProfileClients,
    ProfileClientsShapes,
    profile_clients,
    UniqueSet<String>,
    "a list of at least one OAuth client",
    "Omit requesterClients to accept every client, or list the OAuth clients whose tokens may select this profile."
);

narrowing_member!(
    RequirementScopes,
    RequirementScopesShapes,
    requirement_scopes,
    UniqueSet<String>,
    "a list of at least one scope",
    "Omit requiredScopes when the entity demands no scope of its profiles; an access requirement only narrows what a profile may grant."
);

narrowing_member!(
    RequirementPurposes,
    RequirementPurposesShapes,
    requirement_purposes,
    UniqueSet<String>,
    "a list of at least one purpose",
    "Omit allowedPurposes when the entity demands no purpose of its profiles; an access requirement only narrows what a profile may grant."
);

narrowing_member!(
    RequirementRows,
    RequirementRowsShapes,
    requirement_rows,
    Vec<RowBoundarySource>,
    "a list of at least one row boundary",
    "Omit rowBoundaries when the entity demands no row boundary of its profiles; an access requirement only narrows what a profile may grant."
);

// The authored form of `AccessRequirementsSource`.
/// Compile-time requirements, not grants. Profiles must explicitly satisfy them.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "AccessRequirementsSource"))]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct AuthoredAccessRequirements {
    /// Every profile must require all these scopes. Requirements never grant access. Omit to demand no scope.
    #[serde(
        default,
        deserialize_with = "requirement_scopes",
        skip_serializing_if = "UniqueSet::is_empty"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Listed<UniqueSet<String>, RequirementScopes>")
    )]
    required_scopes: UniqueSet<String>,
    /// Every profile must restrict purpose to a subset of these values. Omit to demand no purpose.
    #[serde(
        default,
        deserialize_with = "requirement_purposes",
        skip_serializing_if = "UniqueSet::is_empty"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Listed<UniqueSet<String>, RequirementPurposes>")
    )]
    allowed_purposes: UniqueSet<String>,
    /// Every profile must include these exact field, verified-claim, and operator bindings. Omit to demand no row boundary.
    #[serde(
        default,
        deserialize_with = "requirement_rows",
        skip_serializing_if = "Vec::is_empty"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Listed<Vec<RowBoundarySource>, RequirementRows>")
    )]
    row_boundaries: Vec<RowBoundarySource>,
}

pub(super) fn access_requirements<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<AccessRequirementsSource>, D::Error> {
    Ok(
        Option::<AuthoredAccessRequirements>::deserialize(deserializer)?.map(|authored| {
            AccessRequirementsSource {
                required_scopes: authored.required_scopes,
                allowed_purposes: authored.allowed_purposes,
                row_boundaries: authored.row_boundaries,
            }
        }),
    )
}

pub(super) fn serialize_access_requirements<S: Serializer>(
    requirements: &Option<AccessRequirementsSource>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    requirements
        .clone()
        .map(|requirements| AuthoredAccessRequirements {
            required_scopes: requirements.required_scopes,
            allowed_purposes: requirements.allowed_purposes,
            row_boundaries: requirements.row_boundaries,
        })
        .serialize(serializer)
}

// The authored form of `AccessProfileSource`, as a module writes it onto an
// entity. It reads the same sentinels a project profile does.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "AccessProfileSource"))]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct AuthoredModuleProfile {
    id: String,
    #[serde(default)]
    default: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    actor_kind: Option<ActorKindSource>,
    /// The OAuth clients whose tokens may select this profile. Omit to accept every client.
    #[serde(
        default,
        deserialize_with = "profile_clients",
        skip_serializing_if = "UniqueSet::is_empty"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Listed<UniqueSet<String>, ProfileClients>")
    )]
    requester_clients: UniqueSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    task_grant: Option<CompiledTaskGrantSource>,
    #[serde(default)]
    principal_claim: Option<String>,
    /// The scopes the verified token must carry: `unrestricted`, or a list of at least one scope, all of which must be present.
    #[serde(
        deserialize_with = "required_scopes",
        serialize_with = "serialize_required_scopes"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "RequiredScopes"))]
    required_scopes: UniqueSet<String>,
    /// The verified token's purpose must match one listed value. Omit to accept every purpose.
    #[serde(
        default,
        deserialize_with = "profile_purposes",
        skip_serializing_if = "UniqueSet::is_empty"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Listed<UniqueSet<String>, ProfilePurposes>")
    )]
    required_purposes: UniqueSet<String>,
    operations: UniqueSet<Operation>,
    #[serde(default)]
    readable_fields: UniqueSet<String>,
    /// Readable change-request decision detail.
    #[serde(
        default = "super::default_readable_request_fields",
        skip_serializing_if = "super::is_default_readable_request_fields"
    )]
    readable_request_fields: UniqueSet<RequestMetadataFieldSource>,
    #[serde(default)]
    writable_fields: UniqueSet<String>,
    #[serde(default)]
    filterable_fields: UniqueSet<String>,
    #[serde(default)]
    sortable_fields: UniqueSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    spatial_queries: Option<SpatialQueryPermissionSource>,
    /// Row reach: `unrestricted`, or a list of at least one row boundary.
    #[serde(
        deserialize_with = "row_boundaries",
        serialize_with = "serialize_row_boundaries"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "RowBoundaries"))]
    row_boundaries: Vec<RowBoundarySource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    membership_boundaries: Vec<MembershipBoundarySource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    require_consent: Vec<ConsentRequirementSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request_visibility: Option<RequestVisibilitySource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    lookups: Vec<LookupPermissionSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    read_paths: Vec<ReadPathPermissionSource>,
    #[serde(
        default,
        deserialize_with = "apply_targets",
        serialize_with = "serialize_apply_targets",
        skip_serializing_if = "Vec::is_empty"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Vec<AuthoredApplyTarget>"))]
    apply_targets: Vec<ApplyTargetPermissionSource>,
    #[serde(default, skip_serializing_if = "UniqueSet::is_empty")]
    submitter_targets: UniqueSet<String>,
    #[serde(
        default,
        deserialize_with = "request_presence",
        serialize_with = "serialize_request_presence",
        skip_serializing_if = "Vec::is_empty"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Vec<AuthoredRequestPresence>"))]
    request_presence: Vec<RequestPresencePermissionSource>,
    #[serde(default, skip_serializing_if = "super::is_false")]
    allow_count: bool,
    #[serde(default)]
    revision_access: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    provenance_fields: Vec<ProvenanceFieldSource>,
    #[serde(default)]
    allow_data_export: bool,
}

impl From<AuthoredModuleProfile> for AccessProfileSource {
    fn from(authored: AuthoredModuleProfile) -> Self {
        Self {
            id: authored.id,
            default: authored.default,
            actor_kind: authored.actor_kind,
            requester_clients: authored.requester_clients,
            task_grant: authored.task_grant,
            principal_claim: authored.principal_claim,
            required_scopes: authored.required_scopes,
            required_purposes: authored.required_purposes,
            operations: authored.operations,
            readable_fields: authored.readable_fields,
            readable_request_fields: authored.readable_request_fields,
            writable_fields: authored.writable_fields,
            filterable_fields: authored.filterable_fields,
            sortable_fields: authored.sortable_fields,
            spatial_queries: authored.spatial_queries,
            row_boundaries: authored.row_boundaries,
            membership_boundaries: authored.membership_boundaries,
            require_consent: authored.require_consent,
            request_visibility: authored.request_visibility,
            lookups: authored.lookups,
            read_paths: authored.read_paths,
            apply_targets: authored.apply_targets,
            submitter_targets: authored.submitter_targets,
            request_presence: authored.request_presence,
            allow_count: authored.allow_count,
            revision_access: authored.revision_access,
            provenance_fields: authored.provenance_fields,
            allow_data_export: authored.allow_data_export,
        }
    }
}

impl From<AccessProfileSource> for AuthoredModuleProfile {
    fn from(profile: AccessProfileSource) -> Self {
        Self {
            id: profile.id,
            default: profile.default,
            actor_kind: profile.actor_kind,
            requester_clients: profile.requester_clients,
            task_grant: profile.task_grant,
            principal_claim: profile.principal_claim,
            required_scopes: profile.required_scopes,
            required_purposes: profile.required_purposes,
            operations: profile.operations,
            readable_fields: profile.readable_fields,
            readable_request_fields: profile.readable_request_fields,
            writable_fields: profile.writable_fields,
            filterable_fields: profile.filterable_fields,
            sortable_fields: profile.sortable_fields,
            spatial_queries: profile.spatial_queries,
            row_boundaries: profile.row_boundaries,
            membership_boundaries: profile.membership_boundaries,
            require_consent: profile.require_consent,
            request_visibility: profile.request_visibility,
            lookups: profile.lookups,
            read_paths: profile.read_paths,
            apply_targets: profile.apply_targets,
            submitter_targets: profile.submitter_targets,
            request_presence: profile.request_presence,
            allow_count: profile.allow_count,
            revision_access: profile.revision_access,
            provenance_fields: profile.provenance_fields,
            allow_data_export: profile.allow_data_export,
        }
    }
}

pub(super) fn module_access_profiles<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<AccessProfileSource>, D::Error> {
    Ok(Vec::<AuthoredModuleProfile>::deserialize(deserializer)?
        .into_iter()
        .map(AccessProfileSource::from)
        .collect())
}

pub(super) fn serialize_module_access_profiles<S: Serializer>(
    profiles: &[AccessProfileSource],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(profiles.iter().cloned().map(AuthoredModuleProfile::from))
}

// The authored form of `ApplyTargetPermissionSource`.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "ApplyTargetPermissionSource"))]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct AuthoredApplyTarget {
    entity: String,
    /// Row reach: `unrestricted`, or a list of at least one row boundary.
    #[serde(
        deserialize_with = "row_boundaries",
        serialize_with = "serialize_row_boundaries"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "RowBoundaries"))]
    row_boundaries: Vec<RowBoundarySource>,
}

pub(super) fn apply_targets<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<ApplyTargetPermissionSource>, D::Error> {
    Ok(Vec::<AuthoredApplyTarget>::deserialize(deserializer)?
        .into_iter()
        .map(|target| ApplyTargetPermissionSource {
            entity: target.entity,
            row_boundaries: target.row_boundaries,
        })
        .collect())
}

pub(super) fn serialize_apply_targets<S: Serializer>(
    targets: &[ApplyTargetPermissionSource],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(targets.iter().map(|target| AuthoredApplyTarget {
        entity: target.entity.clone(),
        row_boundaries: target.row_boundaries.clone(),
    }))
}

// The authored form of `RequestPresencePermissionSource`.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "schema",
    schemars(rename = "RequestPresencePermissionSource")
)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct AuthoredRequestPresence {
    request_type: String,
    /// Row reach: `unrestricted`, or a list of at least one row boundary.
    #[serde(
        deserialize_with = "row_boundaries",
        serialize_with = "serialize_row_boundaries"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "RowBoundaries"))]
    row_boundaries: Vec<RowBoundarySource>,
}

pub(super) fn request_presence<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<RequestPresencePermissionSource>, D::Error> {
    Ok(Vec::<AuthoredRequestPresence>::deserialize(deserializer)?
        .into_iter()
        .map(|presence| RequestPresencePermissionSource {
            request_type: presence.request_type,
            row_boundaries: presence.row_boundaries,
        })
        .collect())
}

pub(super) fn serialize_request_presence<S: Serializer>(
    presence: &[RequestPresencePermissionSource],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(presence.iter().map(|presence| AuthoredRequestPresence {
        request_type: presence.request_type.clone(),
        row_boundaries: presence.row_boundaries.clone(),
    }))
}
