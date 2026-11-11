// SPDX-License-Identifier: Apache-2.0
//! Governed configuration for read views over external source projections.

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_yaml::{BoundedU32, ExternalId, LocalId};
use serde::{Deserialize, Serialize};

use crate::contract::{
    ActorKindSource, Classification, DisplaySource, FieldTypeSource, Operation, RegistryProject,
    UniqueSet,
};
use crate::diagnostics::Diagnostic;
use crate::model::CompiledEntity;

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExternalRecordTypeSource {
    pub id: LocalId,
    pub authority: ExternalId,
    pub identifier_scheme: ExternalId,
    #[serde(default)]
    pub display: DisplaySource,
    pub fields: Vec<ExternalFieldSource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExternalFieldSource {
    pub id: LocalId,
    #[serde(rename = "type")]
    pub value_type: ExternalFieldType,
    pub classification: Classification,
    #[serde(default)]
    pub nullable: bool,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExternalFieldType {
    String,
    Integer,
    Boolean,
    Decimal,
    Date,
    Uuid,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExternalProjectionMode {
    Live,
    Indexed,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExternalCardinality {
    One,
    Many,
}

/// The longest cache lifetime, in seconds, of an indexed projection: one year.
/// The deployment binding and the stored scope hold the same bound.
pub const MAXIMUM_CACHE_TTL_SECONDS: u32 = 31_536_000;

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExternalProjectionSource {
    pub id: LocalId,
    pub record_type: LocalId,
    pub operation: LocalId,
    pub operation_version: ExternalId,
    pub purpose: ExternalId,
    pub scope: ExternalId,
    pub selector_scheme: ExternalId,
    pub mode: ExternalProjectionMode,
    pub cardinality: ExternalCardinality,
    pub fields: UniqueSet<LocalId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_ttl_seconds: Option<BoundedU32<1, MAXIMUM_CACHE_TTL_SECONDS>>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExternalViewSource {
    pub id: LocalId,
    pub record_type: LocalId,
    pub links: Vec<ExternalLinkSource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExternalLinkSource {
    pub id: LocalId,
    pub projection: LocalId,
    pub from_field: LocalId,
    pub identifier_scheme: ExternalId,
    pub fields: UniqueSet<LocalId>,
    /// An optional to-one label on a row of an indexed related collection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<ExternalLabelSource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExternalLabelSource {
    pub projection: LocalId,
    pub from_field: LocalId,
    pub identifier_scheme: ExternalId,
    pub fields: UniqueSet<LocalId>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExternalViewPermissionSource {
    pub view: LocalId,
    pub links: Vec<ExternalLinkPermissionSource>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExternalLinkPermissionSource {
    pub link: LocalId,
    pub readable_fields: UniqueSet<LocalId>,
    #[serde(default, skip_serializing_if = "UniqueSet::is_empty")]
    pub filterable_fields: UniqueSet<LocalId>,
    #[serde(default, skip_serializing_if = "UniqueSet::is_empty")]
    pub sortable_fields: UniqueSet<LocalId>,
    #[serde(default)]
    pub allow_count: bool,
    /// A separate grant for label fields reached through the related row.
    #[serde(default, skip_serializing_if = "UniqueSet::is_empty")]
    pub label_fields: UniqueSet<LocalId>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledExternalViews {
    pub record_types: BTreeMap<String, ExternalRecordTypeSource>,
    pub projections: BTreeMap<String, ExternalProjectionSource>,
    pub views: BTreeMap<String, ExternalViewSource>,
    /// A named local access profile grants a particular view and link.
    pub grants: BTreeMap<String, BTreeMap<String, ExternalViewPermissionSource>>,
    pub refresh: BTreeMap<String, UniqueSet<LocalId>>,
}

impl CompiledExternalViews {
    pub fn is_empty(&self) -> bool {
        self.record_types.is_empty()
            && self.projections.is_empty()
            && self.views.is_empty()
            && self.grants.is_empty()
            && self.refresh.is_empty()
    }
}

/// Record, on each root entity, the stored fields its views link from, so a
/// write path can check a link key without the view definitions.
pub(crate) fn mark_link_fields(
    views: &CompiledExternalViews,
    entities: &mut BTreeMap<String, crate::model::CompiledEntity>,
    physical_names: &mut crate::physical_names::PhysicalNameInventory,
) {
    for view in views.views.values() {
        let Some(entity) = entities.get_mut(view.record_type.as_str()) else {
            continue;
        };
        for link in &view.links {
            entity
                .external_link_fields
                .insert(link.from_field.as_str().to_owned());
            for (profile_id, projections) in &views.refresh {
                if !projections.contains(&link.projection) {
                    continue;
                }
                let Some(profile) = entity.access_profiles.get(profile_id) else {
                    continue;
                };
                let mut fields = vec![link.from_field.as_str().to_owned()];
                for boundary in &profile.row_boundaries {
                    if boundary.field.as_str() != entity.canonical_id.id.as_str()
                        && !fields.contains(&boundary.field)
                    {
                        fields.push(boundary.field.clone());
                    }
                }
                let unique_link = entity.constraints.values().any(|constraint| {
                    matches!(
                        constraint,
                        crate::contract::ConstraintSource::Unique {
                            fields,
                            when: None,
                            ..
                        } if fields.len() == 1 && fields[0] == link.from_field.as_str()
                    )
                });
                if unique_link
                    || entity
                        .indexes
                        .values()
                        .any(|index| index.starts_with(fields.as_slice()))
                {
                    continue;
                }
                let id = format!(
                    "{}{}:{}:{}",
                    crate::model::EXTERNAL_LINK_INDEX_PREFIX,
                    view.id,
                    link.id,
                    profile_id
                );
                entity.indexes.insert(id.clone(), fields);
                physical_names
                    .entities
                    .get_mut(&entity.id)
                    .expect("compiled entity has physical names")
                    .indexes
                    .insert(
                        id,
                        crate::physical_names::external_link_index_name(
                            &entity.id,
                            view.id.as_str(),
                            link.id.as_str(),
                            profile_id,
                        ),
                    );
            }
        }
    }
}

/// The longest key the source contract accepts for a selector.
#[cfg(feature = "runtime")]
const MAXIMUM_LINK_KEY_BYTES: usize = 512;

/// Whether `key` is a link key BReg accepts: the form the source contract
/// accepts for a selector. The write path refuses any other key on a field an
/// external view links from, and every read treats one that is already stored
/// as no outside value. An empty key is not a key; it names no outside
/// subject and is accepted.
#[cfg(feature = "runtime")]
pub(crate) fn link_key_acceptable(key: &str) -> bool {
    key.is_empty()
        || (key.len() <= MAXIMUM_LINK_KEY_BYTES
            && key.trim() == key
            && !key.chars().any(char::is_control))
}

/// The SQL form of [`link_key_acceptable`] over the column or expression
/// `key`: the key itself when it is NULL, empty or acceptable, otherwise
/// NULL. The character classes are the explicit code point sets of Rust's
/// `char::is_control` and `str::trim`, so both forms agree on every string.
#[cfg(feature = "runtime")]
pub(crate) fn acceptable_link_key_sql(key: &str) -> String {
    const WHITESPACE: &str =
        r"\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000";
    const CONTROL: &str = r"\u0001-\u001f\u007f-\u009f";
    format!(
        "CASE WHEN {key} IS NULL OR {key}='' OR (octet_length({key})<=512 \
         AND {key} !~ '^[{WHITESPACE}]' AND {key} !~ '[{WHITESPACE}]$' \
         AND {key} !~ '[{CONTROL}]') THEN {key} END"
    )
}

pub(crate) fn compile(
    project: &RegistryProject,
    entities: &BTreeMap<String, CompiledEntity>,
) -> Result<CompiledExternalViews, Vec<Diagnostic>> {
    let mut diagnostics = Vec::new();
    let record_types = index(
        &project.external_record_types,
        |source| &source.id,
        "/externalRecordTypes",
        &mut diagnostics,
    );
    let projections = index(
        &project.external_projections,
        |source| &source.id,
        "/externalProjections",
        &mut diagnostics,
    );
    let views = index(
        &project.external_views,
        |source| &source.id,
        "/externalViews",
        &mut diagnostics,
    );

    for (index, record_type) in project.external_record_types.iter().enumerate() {
        let path = format!("/externalRecordTypes/{index}");
        validate_uri(
            &record_type.authority,
            &format!("{path}/authority"),
            &mut diagnostics,
        );
        validate_uri(
            &record_type.identifier_scheme,
            &format!("{path}/identifierScheme"),
            &mut diagnostics,
        );
        let mut ids = BTreeSet::new();
        if record_type.fields.is_empty()
            || !record_type.fields.iter().all(|field| ids.insert(&field.id))
        {
            error(
                &mut diagnostics,
                "field-set",
                format!("{path}/fields"),
                "Declare a nonempty set of external field identifiers without duplicates.",
            );
        }
    }

    for (index, projection) in project.external_projections.iter().enumerate() {
        let path = format!("/externalProjections/{index}");
        validate_uri(
            &projection.selector_scheme,
            &format!("{path}/selectorScheme"),
            &mut diagnostics,
        );
        let Some(record_type) = record_types.get(projection.record_type.as_str()) else {
            error(
                &mut diagnostics,
                "unknown-type",
                format!("{path}/recordType"),
                "Select a declared external record type.",
            );
            continue;
        };
        let field_ids = record_type
            .fields
            .iter()
            .map(|field| &field.id)
            .collect::<BTreeSet<_>>();
        if projection.fields.is_empty()
            || !projection
                .fields
                .iter()
                .all(|field| field_ids.contains(field))
        {
            error(
                &mut diagnostics,
                "field-set",
                format!("{path}/fields"),
                "Select at least one field declared by the external record type.",
            );
        }
        if projection.cardinality == ExternalCardinality::One
            && projection.selector_scheme != record_type.identifier_scheme
        {
            error(
                &mut diagnostics,
                "identifier-scheme-mismatch",
                format!("{path}/selectorScheme"),
                "An exact operation selects the external record by its declared identifier scheme.",
            );
        }
        match (projection.mode, projection.cache_ttl_seconds) {
            (ExternalProjectionMode::Live, Some(_)) => error(
                &mut diagnostics,
                "live-cache",
                format!("{path}/cacheTtlSeconds"),
                "Remove the cache lifetime for a live projection.",
            ),
            (ExternalProjectionMode::Indexed, None) => error(
                &mut diagnostics,
                "indexed-cache",
                format!("{path}/cacheTtlSeconds"),
                "Set a positive cache lifetime for an indexed projection.",
            ),
            _ => {}
        }
    }

    let mut local_schemes = BTreeMap::new();
    for (index, view) in project.external_views.iter().enumerate() {
        let path = format!("/externalViews/{index}");
        let Some(root) = entities.get(view.record_type.as_str()) else {
            error(
                &mut diagnostics,
                "unknown-root",
                format!("{path}/recordType"),
                "Select a local record type to root the view.",
            );
            continue;
        };
        if view.links.is_empty() {
            error(
                &mut diagnostics,
                "empty-links",
                format!("{path}/links"),
                "Declare at least one external link on the view.",
            );
        }
        let mut link_ids = BTreeSet::new();
        for (link_index, link) in view.links.iter().enumerate() {
            let path = format!("{path}/links/{link_index}");
            if !link_ids.insert(&link.id) {
                error(
                    &mut diagnostics,
                    "duplicate-id",
                    format!("{path}/id"),
                    "Give each link on the view a distinct identifier.",
                );
            }
            let Some(projection) = projections.get(link.projection.as_str()) else {
                error(
                    &mut diagnostics,
                    "unknown-projection",
                    format!("{path}/projection"),
                    "Select a declared external projection.",
                );
                continue;
            };
            if link.identifier_scheme != projection.selector_scheme
                || local_schemes
                    .insert(
                        (&view.record_type, &link.from_field),
                        &link.identifier_scheme,
                    )
                    .is_some_and(|scheme| scheme != &link.identifier_scheme)
            {
                error(&mut diagnostics, "identifier-scheme-mismatch", format!("{path}/identifierScheme"),
                    "Use one consistent local identifier scheme that matches the approved source selector.");
            }
            if !root.stored_fields.iter().any(|field| {
                field.logical.id == link.from_field.as_str()
                    && field.logical.encryption.is_none()
                    && matches!(
                        field.logical.field_type,
                        FieldTypeSource::Uuid
                            | FieldTypeSource::String {
                                max_length: 1..=512,
                                ..
                            }
                    )
            }) {
                error(&mut diagnostics, "invalid-root-key", format!("{path}/fromField"),
                    "Select a stored UUID or bounded string identifier supported by direct binding.");
            }
            if link.fields.is_empty() || !link.fields.is_subset(&projection.fields) {
                error(
                    &mut diagnostics,
                    "field-set",
                    format!("{path}/fields"),
                    "Select at least one field from the approved projection.",
                );
            }
            if let Some(label) = &link.label {
                validate_label(
                    label,
                    projection,
                    &record_types,
                    &projections,
                    &path,
                    &mut diagnostics,
                );
            }
        }
    }

    let mut grants = BTreeMap::new();
    let mut refresh = BTreeMap::new();
    for (profile_index, profile) in project.access_profiles.iter().enumerate() {
        let path = format!("/accessProfiles/{profile_index}/permissions");
        let mut view_grants = BTreeMap::new();
        for (grant_index, permission) in profile.permissions.external_views.iter().enumerate() {
            let path = format!("{path}/externalViews/{grant_index}");
            let Some(view) = views.get(permission.view.as_str()) else {
                error(
                    &mut diagnostics,
                    "unknown-view",
                    format!("{path}/view"),
                    "Select a declared external view.",
                );
                continue;
            };
            let root = profile
                .permissions
                .entities
                .iter()
                .find(|grant| grant.entity == view.record_type.as_str());
            if !root.is_some_and(|root| root.operations.contains(&Operation::Get)) {
                error(
                    &mut diagnostics,
                    "root-read-missing",
                    format!("{path}/view"),
                    "Grant get on the local root record type in this same profile.",
                );
            }
            if view_grants
                .insert(permission.view.as_str().to_owned(), permission.clone())
                .is_some()
            {
                error(
                    &mut diagnostics,
                    "duplicate-view-grant",
                    format!("{path}/view"),
                    "Grant each external view once per access profile.",
                );
            }
            let mut link_grants = BTreeSet::new();
            for (link_index, grant) in permission.links.iter().enumerate() {
                let path = format!("{path}/links/{link_index}");
                if !link_grants.insert(&grant.link) {
                    error(
                        &mut diagnostics,
                        "duplicate-link-grant",
                        format!("{path}/link"),
                        "Grant each link once per view permission.",
                    );
                }
                let Some(link) = view.links.iter().find(|link| link.id == grant.link) else {
                    error(
                        &mut diagnostics,
                        "unknown-link",
                        format!("{path}/link"),
                        "Grant a link declared on the selected view.",
                    );
                    continue;
                };
                if grant.readable_fields.is_empty()
                    || !grant.readable_fields.is_subset(&link.fields)
                    || (!grant.label_fields.is_empty()
                        && !link
                            .label
                            .as_ref()
                            .is_some_and(|label| grant.label_fields.is_subset(&label.fields)))
                {
                    error(&mut diagnostics, "invalid-read-grant", path.clone(),
                        "Grant only declared link fields, with an explicit separate grant for labels.");
                }
                if !grant.filterable_fields.is_subset(&grant.readable_fields)
                    || !grant.sortable_fields.is_subset(&grant.readable_fields)
                {
                    error(
                        &mut diagnostics,
                        "processing-wider-than-read",
                        path.clone(),
                        "Grant reading a field before permitting it for filtering or sorting.",
                    );
                }
                let uses_query = !grant.filterable_fields.is_empty()
                    || !grant.sortable_fields.is_empty()
                    || grant.allow_count;
                if let Some(projection) = projections.get(link.projection.as_str()) {
                    if !profile
                        .required_purposes
                        .contains(projection.purpose.as_str())
                    {
                        error(
                            &mut diagnostics,
                            "purpose-not-granted",
                            path.clone(),
                            "Name the projection purpose in this profile's required purposes.",
                        );
                    }
                    if uses_query && projection.mode != ExternalProjectionMode::Indexed {
                        error(
                            &mut diagnostics,
                            "live-query",
                            path.clone(),
                            "Grant filtering, sorting, or counts only for an indexed projection.",
                        );
                    }
                }
                if uses_query
                    && !root.is_some_and(|root| root.operations.contains(&Operation::List))
                    || grant.allow_count && !root.is_some_and(|root| root.allow_count)
                {
                    error(
                        &mut diagnostics,
                        "root-query-missing",
                        path,
                        "Grant list and, for a count, allowCount on the local record type.",
                    );
                }
            }
        }
        if !view_grants.is_empty() {
            grants.insert(profile.id.clone(), view_grants);
        }
        if !profile.permissions.refresh_external_projections.is_empty() {
            let path = format!("{path}/refreshExternalProjections");
            let scoped_service = profile.actor_kind == Some(ActorKindSource::Service)
                && !profile.requester_clients.is_empty()
                && !profile.required_scopes.is_empty()
                && !profile.required_purposes.is_empty();
            if !scoped_service {
                error(&mut diagnostics, "refresh-service-profile", path.clone(),
                    "Grant refresh only to a service profile with explicit clients, scopes, and purposes.");
            }
            for id in &profile.permissions.refresh_external_projections {
                let may_refresh = projections.get(id.as_str()).is_some_and(|projection| {
                    projection.mode == ExternalProjectionMode::Indexed
                        && profile
                            .required_purposes
                            .contains(projection.purpose.as_str())
                        && views.values().any(|view| {
                            view.links.iter().any(|link| {
                                link.projection == *id
                                    || link.label.as_ref().is_some_and(|label| {
                                        label.projection == *id
                                            && profile
                                                .permissions
                                                .refresh_external_projections
                                                .contains(&link.projection)
                                    })
                            }) && profile.permissions.entities.iter().any(|root| {
                                root.entity == view.record_type.as_str()
                                    && root.operations.contains(&Operation::List)
                            })
                        })
                });
                if !may_refresh {
                    error(&mut diagnostics, "invalid-refresh-grant", path.clone(),
                        "Grant refresh under the projection purpose and a permitted root list. Refreshing labels also requires a refresh grant for the related collection.");
                }
            }
            refresh.insert(
                profile.id.clone(),
                profile.permissions.refresh_external_projections.clone(),
            );
        }
    }
    if !diagnostics.is_empty() {
        return Err(diagnostics);
    }
    Ok(CompiledExternalViews {
        record_types,
        projections,
        views,
        grants,
        refresh,
    })
}

fn validate_label(
    label: &ExternalLabelSource,
    parent: &ExternalProjectionSource,
    record_types: &BTreeMap<String, ExternalRecordTypeSource>,
    projections: &BTreeMap<String, ExternalProjectionSource>,
    path: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let valid = parent.cardinality == ExternalCardinality::Many
        && parent.mode == ExternalProjectionMode::Indexed
        && parent.fields.contains(&label.from_field)
        && record_types
            .get(parent.record_type.as_str())
            .is_some_and(|record_type| {
                record_type.fields.iter().any(|field| {
                    field.id == label.from_field
                        && matches!(
                            field.value_type,
                            ExternalFieldType::String | ExternalFieldType::Uuid
                        )
                })
            })
        && projections
            .get(label.projection.as_str())
            .is_some_and(|projection| {
                projection.mode == ExternalProjectionMode::Indexed
                    && projection.cardinality == ExternalCardinality::One
                    && projection.purpose == parent.purpose
                    && projection.selector_scheme == label.identifier_scheme
                    && !label.fields.is_empty()
                    && label.fields.is_subset(&projection.fields)
            });
    if !valid {
        error(diagnostics, "invalid-label", format!("{path}/label"),
            "Link an indexed related row to an indexed exact label with compatible identifiers, fields, and purpose.");
    }
}

fn validate_uri(value: &ExternalId, path: &str, diagnostics: &mut Vec<Diagnostic>) {
    let value = value.as_str();
    if value.chars().any(char::is_whitespace)
        || !url::Url::parse(value).is_ok_and(|uri| {
            uri.username().is_empty() && uri.password().is_none() && !uri.path().is_empty()
        })
    {
        error(
            diagnostics,
            "invalid-identifier-uri",
            path,
            "Use an absolute identifier URI without embedded credentials.",
        );
    }
}

fn index<T: Clone>(
    items: &[T],
    id: impl Fn(&T) -> &LocalId,
    path: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> BTreeMap<String, T> {
    let mut by_id = BTreeMap::new();
    for (index, item) in items.iter().enumerate() {
        if by_id
            .insert(id(item).as_str().to_owned(), item.clone())
            .is_some()
        {
            error(
                diagnostics,
                "duplicate-id",
                format!("{path}/{index}/id"),
                "Give each declaration in this group a distinct identifier.",
            );
        }
    }
    by_id
}

fn error(diagnostics: &mut Vec<Diagnostic>, code: &str, path: impl Into<String>, message: &str) {
    diagnostics.push(Diagnostic::error(
        &format!("breg.external-view.{code}"),
        path,
        message,
    ));
}
