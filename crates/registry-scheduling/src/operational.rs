// SPDX-License-Identifier: Apache-2.0

//! Bounded authority for cross-owner operational appointment reads.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, TimeDelta, Utc};
use registry_platform_canonical_json::canonicalize_json;
use registry_scheduling_core::{
    valid_identifier, valid_reference, AppointmentStateDocument, ExternalReference,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::audit::{with_event_id, SchedulingAudit};
use crate::store::{OperationalScopeCoverage, PostgresStore, StoreError};

/// The most separately selectable operational roles one deployment may bind.
pub const MAX_OPERATIONAL_READ_PROFILES: usize = 64;
/// The most service/location pairs one role may cover.
pub const MAX_OPERATIONAL_READ_PERMISSIONS: usize = 64;
/// The most named resources one service/location permission may cover.
pub const MAX_OPERATIONAL_READ_RESOURCES: usize = 256;
/// The most source products whose references one role may return or filter.
pub const MAX_OPERATIONAL_REFERENCE_PRODUCTS: usize = 64;
/// The longest query span. This is the existing availability span bound.
pub const MAX_OPERATIONAL_READ_SPAN_DAYS: u32 = 62;
/// The furthest a profile may reach from the observed instant.
pub const MAX_OPERATIONAL_READ_HORIZON_DAYS: u32 = registry_scheduling_core::MAXIMUM_HORIZON_DAYS;

/// One opt-in operational role. No profile is synthesized when the map is
/// absent: an empty map grants no appointment read authority.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationalReadProfileConfig {
    /// The OAuth scope that selects this role after token verification.
    pub scope: String,
    /// How far behind the observed instant a query may begin.
    #[serde(
        deserialize_with = "registry_scheduling_core::bounded_u32::<_, 0, MAX_OPERATIONAL_READ_HORIZON_DAYS>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "registry_platform_yaml::BoundedU32<0, MAX_OPERATIONAL_READ_HORIZON_DAYS>"
        )
    )]
    pub maximum_past_days: u32,
    /// How far ahead of the observed instant a query may end.
    #[serde(
        deserialize_with = "registry_scheduling_core::bounded_u32::<_, 0, MAX_OPERATIONAL_READ_HORIZON_DAYS>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "registry_platform_yaml::BoundedU32<0, MAX_OPERATIONAL_READ_HORIZON_DAYS>"
        )
    )]
    pub maximum_future_days: u32,
    /// The maximum duration of one request's half-open interval.
    #[serde(
        deserialize_with = "registry_scheduling_core::bounded_u32::<_, 1, MAX_OPERATIONAL_READ_SPAN_DAYS>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, MAX_OPERATIONAL_READ_SPAN_DAYS>")
    )]
    pub maximum_span_days: u32,
    pub permissions: Vec<OperationalReadPermissionConfig>,
    pub projection: OperationalProjectionConfig,
}

/// One exact service/location authority within a profile.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationalReadPermissionConfig {
    pub service: String,
    pub location: String,
    pub resources: OperationalResourceScope,
}

/// The resource authority at one service/location pair. `Unrestricted` is an
/// explicit operator statement, never an omitted default.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum OperationalResourceScope {
    Unrestricted {},
    Exact {
        #[serde(deserialize_with = "registry_scheduling_core::unique_local_ids")]
        #[cfg_attr(
            feature = "schema",
            schemars(with = "registry_platform_yaml::UniqueList<registry_platform_yaml::LocalId>")
        )]
        ids: Vec<String>,
    },
}
// The shared tagged-union reader keeps the position of a refused member
// inside either variant.
registry_platform_yaml::tagged_union!(OperationalResourceScope);

// `Serialize` cannot be derived next to the reader above: the reader needs the
// externally tagged derive, while the wire form is internally tagged by `type`.
impl Serialize for OperationalResourceScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap as _;
        match self {
            Self::Unrestricted {} => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("type", "unrestricted")?;
                map.end()
            }
            Self::Exact { ids } => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("type", "exact")?;
                map.serialize_entry("ids", ids)?;
                map.end()
            }
        }
    }
}

/// Fields an operational response may contain. Identity, contact, manager,
/// Party references and actor fields are deliberately absent from this vocabulary.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationalProjectionField {
    OccupiedInterval,
    Resource,
    Units,
    PartyCounts,
    Allocations,
    Attendance,
}

/// The explicit projection allowed for one role.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationalProjectionConfig {
    #[serde(deserialize_with = "registry_scheduling_core::unique_list")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::UniqueList<OperationalProjectionField>")
    )]
    pub fields: Vec<OperationalProjectionField>,
    /// Source products whose exact references may be filtered and returned.
    #[serde(
        default,
        deserialize_with = "registry_scheduling_core::unique_local_ids",
        skip_serializing_if = "Vec::is_empty"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::UniqueList<registry_platform_yaml::LocalId>")
    )]
    pub external_reference_products: Vec<String>,
}

impl OperationalProjectionConfig {
    #[must_use]
    pub fn allows(&self, field: OperationalProjectionField) -> bool {
        self.fields.contains(&field)
    }

    #[must_use]
    pub fn allows_external_reference_product(&self, product: &str) -> bool {
        self.external_reference_products
            .iter()
            .any(|allowed| allowed == product)
    }
}

pub use registry_scheduling_core::OperationalTimeBasis;

/// A fully normalized request filter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationalReadFilter {
    service: String,
    location: String,
    resource: Option<String>,
    offering: Option<String>,
    state: Option<AppointmentStateDocument>,
    external_reference: Option<ExternalReference>,
    time_basis: OperationalTimeBasis,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
}

impl OperationalReadFilter {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        service: String,
        location: String,
        resource: Option<String>,
        time_basis: OperationalTimeBasis,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Self, OperationalFilterError> {
        Self::with_optional_filters(
            service, location, resource, None, None, None, time_basis, start, end,
        )
    }

    /// Construct a normalized filter including every supported optional
    /// narrowing member.
    #[allow(clippy::too_many_arguments)]
    pub fn with_optional_filters(
        service: String,
        location: String,
        resource: Option<String>,
        offering: Option<String>,
        state: Option<AppointmentStateDocument>,
        external_reference: Option<ExternalReference>,
        time_basis: OperationalTimeBasis,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Self, OperationalFilterError> {
        if !valid_identifier(&service)
            || !valid_identifier(&location)
            || resource.as_deref().is_some_and(|id| !valid_identifier(id))
            || offering.as_deref().is_some_and(|id| !valid_identifier(id))
            || start >= end
            || external_reference.as_ref().is_some_and(|reference| {
                !valid_identifier(&reference.product)
                    || !valid_identifier(&reference.record_type)
                    || !valid_reference(&reference.identifier)
            })
        {
            return Err(OperationalFilterError::Invalid);
        }
        Ok(Self {
            service,
            location,
            resource,
            offering,
            state,
            external_reference,
            time_basis,
            start,
            end,
        })
    }

    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    #[must_use]
    pub fn location(&self) -> &str {
        &self.location
    }

    #[must_use]
    pub fn resource(&self) -> Option<&str> {
        self.resource.as_deref()
    }

    #[must_use]
    pub fn offering(&self) -> Option<&str> {
        self.offering.as_deref()
    }

    #[must_use]
    pub fn state(&self) -> Option<AppointmentStateDocument> {
        self.state
    }

    #[must_use]
    pub fn external_reference(&self) -> Option<&ExternalReference> {
        self.external_reference.as_ref()
    }

    #[must_use]
    pub fn time_basis(&self) -> OperationalTimeBasis {
        self.time_basis
    }

    #[must_use]
    pub fn start(&self) -> DateTime<Utc> {
        self.start
    }

    #[must_use]
    pub fn end(&self) -> DateTime<Utc> {
        self.end
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum OperationalFilterError {
    #[error("the operational appointment filter is invalid")]
    Invalid,
}

/// The three verified token identities that bind an operational read.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationalIdentity {
    issuer: String,
    subject: String,
    client: String,
}

impl OperationalIdentity {
    pub fn new(
        issuer: String,
        subject: String,
        client: String,
    ) -> Result<Self, OperationalAuthorizationError> {
        if [&issuer, &subject, &client]
            .into_iter()
            .any(|value| value.is_empty())
        {
            return Err(OperationalAuthorizationError::Profile);
        }
        Ok(Self {
            issuer,
            subject,
            client,
        })
    }
}

impl std::fmt::Debug for OperationalIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OperationalIdentity")
            .field("issuer", &"<redacted>")
            .field("subject", &"<redacted>")
            .field("client", &"<redacted>")
            .finish()
    }
}

/// The resource predicate the store must apply. A named-resource profile
/// with no narrower request filter yields the whole bounded list, so the
/// store can serve a work list without widening it to every resource.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum AuthorizedResourceScope {
    Unrestricted,
    Exact { ids: Vec<String> },
}

/// Immutable evidence that one verified token, one configured profile and
/// one normalized filter authorized this operation. It contains no task
/// grant and cannot combine profiles.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizedOperationalRead {
    identity: OperationalIdentity,
    profile_id: String,
    profile_digest: String,
    filter: OperationalReadFilter,
    resources: AuthorizedResourceScope,
    projection: OperationalProjectionConfig,
    context_digest: String,
}

impl AuthorizedOperationalRead {
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    #[must_use]
    pub fn profile_digest(&self) -> &str {
        &self.profile_digest
    }

    #[must_use]
    pub fn filter(&self) -> &OperationalReadFilter {
        &self.filter
    }

    #[must_use]
    pub fn resources(&self) -> &AuthorizedResourceScope {
        &self.resources
    }

    #[must_use]
    pub fn projection(&self) -> &OperationalProjectionConfig {
        &self.projection
    }

    /// Bind a cursor or cached result to the verified identity, configured
    /// authority and normalized filter without exposing their raw values.
    #[must_use]
    pub fn context_digest(&self) -> &str {
        &self.context_digest
    }
}

impl std::fmt::Debug for AuthorizedOperationalRead {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizedOperationalRead")
            .field("identity", &"<redacted>")
            .field("profile_id", &self.profile_id)
            .field("profile_digest", &self.profile_digest)
            .field("filter", &"<redacted>")
            .field("resources", &self.resources)
            .field("projection", &self.projection)
            .field("context_digest", &self.context_digest)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum OperationalAuthorizationError {
    #[error("the caller's operational appointment profile is not authorized for this request")]
    Profile,
}

/// A value-free configuration refusal located at one profile member.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("{path} {reason}")]
pub struct OperationalProfileConfigError {
    path: String,
    reason: &'static str,
}

impl OperationalProfileConfigError {
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

impl OperationalReadProfileConfig {
    pub fn validate(
        &self,
        profile_id: &str,
        reads_scope: &str,
        explain_scope: &str,
    ) -> Result<(), OperationalProfileConfigError> {
        let root = format!("authentication.oidc.appointmentReadProfiles.{profile_id}");
        let invalid = |member: &str, reason| OperationalProfileConfigError {
            path: format!("{root}.{member}"),
            reason,
        };
        if !valid_identifier(profile_id) {
            return Err(OperationalProfileConfigError {
                path: "authentication.oidc.appointmentReadProfiles".to_owned(),
                reason: "contains an invalid profile identifier",
            });
        }
        if !valid_scope_token(&self.scope) {
            return Err(invalid("scope", "must be one OAuth scope token"));
        }
        if self.scope == reads_scope || self.scope == explain_scope {
            return Err(invalid(
                "scope",
                "must differ from the catalogue and explain scopes",
            ));
        }
        if self.maximum_past_days > MAX_OPERATIONAL_READ_HORIZON_DAYS {
            return Err(invalid(
                "maximumPastDays",
                "must not exceed the scheduling horizon bound",
            ));
        }
        if self.maximum_future_days > MAX_OPERATIONAL_READ_HORIZON_DAYS {
            return Err(invalid(
                "maximumFutureDays",
                "must not exceed the scheduling horizon bound",
            ));
        }
        if self.maximum_span_days == 0 || self.maximum_span_days > MAX_OPERATIONAL_READ_SPAN_DAYS {
            return Err(invalid(
                "maximumSpanDays",
                "must use the bounded operational time limits",
            ));
        }
        if self.permissions.is_empty() || self.permissions.len() > MAX_OPERATIONAL_READ_PERMISSIONS
        {
            return Err(invalid(
                "permissions",
                "must contain between 1 and 64 exact service/location permissions",
            ));
        }
        let mut pairs = BTreeSet::new();
        for permission in &self.permissions {
            if !valid_identifier(&permission.service) || !valid_identifier(&permission.location) {
                return Err(invalid(
                    "permissions",
                    "contains an invalid service or location identifier",
                ));
            }
            if !pairs.insert((&permission.service, &permission.location)) {
                return Err(invalid(
                    "permissions",
                    "contains a repeated service/location pair",
                ));
            }
            if let OperationalResourceScope::Exact { ids } = &permission.resources {
                if ids.is_empty() || ids.len() > MAX_OPERATIONAL_READ_RESOURCES {
                    return Err(invalid(
                        "permissions",
                        "contains an exact resource list outside the 1 to 256 bound",
                    ));
                }
                let mut seen = BTreeSet::new();
                if ids
                    .iter()
                    .any(|id| !valid_identifier(id) || !seen.insert(id))
                {
                    return Err(invalid(
                        "permissions",
                        "contains an invalid or repeated resource identifier",
                    ));
                }
            }
        }
        let fields: BTreeSet<_> = self.projection.fields.iter().copied().collect();
        if fields.len() != self.projection.fields.len() {
            return Err(invalid(
                "projection.fields",
                "must not repeat a projected field",
            ));
        }
        if self.projection.external_reference_products.len() > MAX_OPERATIONAL_REFERENCE_PRODUCTS {
            return Err(invalid(
                "projection.externalReferenceProducts",
                "must contain at most 64 source products",
            ));
        }
        let mut products = BTreeSet::new();
        if self
            .projection
            .external_reference_products
            .iter()
            .any(|product| !valid_identifier(product) || !products.insert(product))
        {
            return Err(invalid(
                "projection.externalReferenceProducts",
                "contains an invalid or repeated source product",
            ));
        }
        Ok(())
    }
}

/// Validate the complete map, including rules that span profiles.
#[must_use]
pub fn validate_operational_read_profiles(
    profiles: &BTreeMap<String, OperationalReadProfileConfig>,
    reads_scope: &str,
    explain_scope: &str,
) -> Vec<OperationalProfileConfigError> {
    if profiles.len() > MAX_OPERATIONAL_READ_PROFILES {
        return vec![OperationalProfileConfigError {
            path: "authentication.oidc.appointmentReadProfiles".to_owned(),
            reason: "must contain at most 64 profiles",
        }];
    }
    if !registry_platform_yaml::lookalike_local_id_pairs(profiles.keys().map(String::as_str))
        .is_empty()
    {
        return vec![OperationalProfileConfigError {
            path: "authentication.oidc.appointmentReadProfiles".to_owned(),
            reason: "contains profile identifiers that differ only by hyphen versus underscore",
        }];
    }
    let mut findings = Vec::new();
    let mut scopes = BTreeSet::new();
    for (id, profile) in profiles {
        if let Err(error) = profile.validate(id, reads_scope, explain_scope) {
            findings.push(error);
        }
        if !scopes.insert(profile.scope.as_str()) {
            findings.push(OperationalProfileConfigError {
                path: format!("authentication.oidc.appointmentReadProfiles.{id}.scope"),
                reason: "must not repeat another operational profile scope",
            });
        }
    }
    findings
}

/// Authorize exactly one selected profile and return the effective predicates
/// the store must apply. Catalogue scope and task grants are not inputs.
pub fn authorize_operational_read(
    profiles: &BTreeMap<String, OperationalReadProfileConfig>,
    scopes: &[String],
    selector: Option<&str>,
    identity: OperationalIdentity,
    filter: OperationalReadFilter,
    now: DateTime<Utc>,
) -> Result<AuthorizedOperationalRead, OperationalAuthorizationError> {
    let authorized: Vec<_> = profiles
        .iter()
        .filter(|(_, profile)| scopes.iter().any(|scope| scope == &profile.scope))
        .collect();
    let (profile_id, profile) = match selector {
        Some(selected) => authorized
            .into_iter()
            .find(|(id, _)| id.as_str() == selected)
            .ok_or(OperationalAuthorizationError::Profile)?,
        None => match authorized.as_slice() {
            [only] => *only,
            _ => return Err(OperationalAuthorizationError::Profile),
        },
    };

    let earliest = now
        .checked_sub_signed(TimeDelta::days(i64::from(profile.maximum_past_days)))
        .ok_or(OperationalAuthorizationError::Profile)?;
    let latest = now
        .checked_add_signed(TimeDelta::days(i64::from(profile.maximum_future_days)))
        .ok_or(OperationalAuthorizationError::Profile)?;
    let maximum_span = TimeDelta::days(i64::from(profile.maximum_span_days));
    if filter.start < earliest || filter.end > latest || filter.end - filter.start > maximum_span {
        return Err(OperationalAuthorizationError::Profile);
    }
    if filter.external_reference.as_ref().is_some_and(|reference| {
        !profile
            .projection
            .allows_external_reference_product(&reference.product)
    }) {
        return Err(OperationalAuthorizationError::Profile);
    }

    let permission = profile
        .permissions
        .iter()
        .find(|permission| {
            permission.service == filter.service && permission.location == filter.location
        })
        .ok_or(OperationalAuthorizationError::Profile)?;
    let resources = match (&permission.resources, filter.resource.as_deref()) {
        (OperationalResourceScope::Unrestricted {}, None) => AuthorizedResourceScope::Unrestricted,
        (OperationalResourceScope::Unrestricted {}, Some(id)) => AuthorizedResourceScope::Exact {
            ids: vec![id.to_owned()],
        },
        (OperationalResourceScope::Exact { ids }, None) => {
            AuthorizedResourceScope::Exact { ids: ids.clone() }
        }
        (OperationalResourceScope::Exact { ids }, Some(requested))
            if ids.iter().any(|allowed| allowed == requested) =>
        {
            AuthorizedResourceScope::Exact {
                ids: vec![requested.to_owned()],
            }
        }
        (OperationalResourceScope::Exact { .. }, Some(_)) => {
            return Err(OperationalAuthorizationError::Profile)
        }
    };

    let profile_digest = canonical_digest(&json!({
        "id": profile_id,
        "profile": profile,
    }))?;
    let context_digest = canonical_digest(&json!({
        "identity": &identity,
        "profileId": profile_id,
        "profileDigest": &profile_digest,
        "filter": &filter,
        "authorizedResources": &resources,
    }))?;
    Ok(AuthorizedOperationalRead {
        identity,
        profile_id: profile_id.clone(),
        profile_digest,
        filter,
        resources,
        projection: profile.projection.clone(),
        context_digest,
    })
}

fn valid_scope_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte == b'!' || (b'#'..=b'[').contains(&byte) || (b']'..=b'~').contains(&byte)
        })
}

fn canonical_digest(value: &serde_json::Value) -> Result<String, OperationalAuthorizationError> {
    let canonical = canonicalize_json(value).map_err(|_| OperationalAuthorizationError::Profile)?;
    let digest = Sha256::digest(canonical);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut rendered = String::with_capacity(71);
    rendered.push_str("sha256:");
    for byte in digest {
        rendered.push(HEX[(byte >> 4) as usize] as char);
        rendered.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(rendered)
}

/// A failure of the attributable operator workflow that retries immutable
/// operational-read label materialization.
#[derive(Debug, Error)]
pub enum OperationalRematerializationError {
    #[error("reading operational appointment label coverage failed")]
    Coverage(#[source] StoreError),
    #[error(
        "the operational-scopes.rematerialize request audit entry was not accepted; no labels were changed"
    )]
    AuditRequest(#[source] registry_platform_audit::AuditUnavailable),
    #[error("rematerializing operational appointment labels failed")]
    Store(#[source] StoreError),
    #[error(
        "rematerializing operational appointment labels failed, and its response audit entry could not be written: {audit}"
    )]
    StoreAndAudit {
        #[source]
        store: StoreError,
        audit: registry_platform_audit::AuditUnavailable,
    },
    #[error(
        "operational appointment labels were rematerialized, but the operational-scopes.rematerialize response audit entry could not be written; the label changes stand"
    )]
    AppliedUnaudited(#[source] registry_platform_audit::AuditUnavailable),
}

/// Retry immutable operational-read label materialization through the
/// operator audit boundary. The request entry must be accepted before the
/// database transaction starts; response records contain aggregate coverage
/// only, never claim, party, owner or reference identifiers.
pub async fn rematerialize_operational_scopes(
    store: &PostgresStore,
    audit: &SchedulingAudit,
) -> Result<OperationalScopeCoverage, OperationalRematerializationError> {
    let before = store
        .operational_scope_coverage()
        .await
        .map_err(OperationalRematerializationError::Coverage)?;
    let event_id = Uuid::new_v4();
    let request = json!({
        "actorKind": "operator",
        "operation": "operational-scopes.rematerialize",
        "before": coverage_record(before),
    });
    audit
        .operational_scopes_request(event_id, request.clone())
        .await
        .map_err(OperationalRematerializationError::AuditRequest)?;

    let after = match store.rematerialize_operational_scopes().await {
        Ok(coverage) => coverage,
        Err(store) => {
            let response = rematerialization_response(
                event_id,
                request,
                json!({
                    "outcome": "failed",
                    "reason": "operational-scopes.rematerialize-failed",
                }),
            );
            return match audit.operational_scopes_response(event_id, response).await {
                Ok(()) => Err(OperationalRematerializationError::Store(store)),
                Err(audit) => {
                    Err(OperationalRematerializationError::StoreAndAudit { store, audit })
                }
            };
        }
    };
    let response = rematerialization_response(
        event_id,
        request,
        json!({
            "outcome": "allowed",
            "reason": "authorization.allowed",
            "after": coverage_record(after),
            "effects": {
                "rematerializedBookings": before.unresolved_bookings.saturating_sub(after.unresolved_bookings),
                "rematerializedActiveBookings": before.unresolved_active_bookings.saturating_sub(after.unresolved_active_bookings),
            },
        }),
    );
    audit
        .operational_scopes_response(event_id, response)
        .await
        .map_err(OperationalRematerializationError::AppliedUnaudited)?;
    Ok(after)
}

fn coverage_record(coverage: OperationalScopeCoverage) -> serde_json::Value {
    json!({
        "unresolvedBookings": coverage.unresolved_bookings,
        "unresolvedActiveBookings": coverage.unresolved_active_bookings,
    })
}

fn rematerialization_response(
    event_id: Uuid,
    mut request: serde_json::Value,
    outcome: serde_json::Value,
) -> serde_json::Value {
    let request_fields = request
        .as_object_mut()
        .expect("the closed rematerialization request is an object");
    let outcome_fields = outcome
        .as_object()
        .expect("the closed rematerialization outcome is an object");
    request_fields.extend(outcome_fields.clone());
    with_event_id(event_id, request)
        .expect("the closed rematerialization response has no competing event identity")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use std::collections::BTreeMap;

    #[test]
    fn resource_scope_wire_form_is_tagged_by_type_and_closed() {
        let exact = OperationalResourceScope::Exact {
            ids: vec!["station-1".to_owned()],
        };
        let exact_wire = json!({ "type": "exact", "ids": ["station-1"] });
        assert_eq!(serde_json::to_value(&exact).unwrap(), exact_wire);
        assert_eq!(
            serde_json::from_value::<OperationalResourceScope>(exact_wire).unwrap(),
            exact
        );

        let unrestricted = OperationalResourceScope::Unrestricted {};
        let unrestricted_wire = json!({ "type": "unrestricted" });
        assert_eq!(
            serde_json::to_value(&unrestricted).unwrap(),
            unrestricted_wire
        );
        assert_eq!(
            serde_json::from_value::<OperationalResourceScope>(unrestricted_wire).unwrap(),
            unrestricted
        );

        for refused in [
            json!({ "type": "unrestricted", "ids": ["station-1"] }),
            json!({ "type": "exact" }),
            json!({ "type": "exact", "ids": ["a", "a"] }),
            json!({ "type": "exact", "ids": ["a"], "extra": 1 }),
            json!({ "type": "other" }),
            json!({ "ids": ["a"] }),
        ] {
            assert!(
                serde_json::from_value::<OperationalResourceScope>(refused.clone()).is_err(),
                "{refused} must be refused"
            );
        }
    }

    fn profile(scope: &str, resources: OperationalResourceScope) -> OperationalReadProfileConfig {
        OperationalReadProfileConfig {
            scope: scope.to_owned(),
            maximum_past_days: 7,
            maximum_future_days: 31,
            maximum_span_days: 1,
            permissions: vec![OperationalReadPermissionConfig {
                service: "registry-update".to_owned(),
                location: "north-counter".to_owned(),
                resources,
            }],
            projection: OperationalProjectionConfig {
                fields: vec![OperationalProjectionField::Resource],
                external_reference_products: vec!["casework".to_owned()],
            },
        }
    }

    fn filter(resource: Option<&str>) -> OperationalReadFilter {
        OperationalReadFilter::new(
            "registry-update".to_owned(),
            "north-counter".to_owned(),
            resource.map(str::to_owned),
            OperationalTimeBasis::Displayed,
            Utc.with_ymd_and_hms(2026, 10, 23, 9, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 10, 23, 17, 0, 0).unwrap(),
        )
        .expect("a bounded work-list filter")
    }

    #[test]
    fn a_profile_authorizes_one_exact_operation_without_union() {
        let profiles = BTreeMap::from([
            (
                "north-stations".to_owned(),
                profile(
                    "scheduling:appointments:north",
                    OperationalResourceScope::Exact {
                        ids: vec!["station-1".to_owned()],
                    },
                ),
            ),
            (
                "south-stations".to_owned(),
                OperationalReadProfileConfig {
                    permissions: vec![OperationalReadPermissionConfig {
                        service: "registry-update".to_owned(),
                        location: "south-counter".to_owned(),
                        resources: OperationalResourceScope::Exact {
                            ids: vec!["station-2".to_owned()],
                        },
                    }],
                    ..profile(
                        "scheduling:appointments:south",
                        OperationalResourceScope::Unrestricted {},
                    )
                },
            ),
        ]);
        let identity = OperationalIdentity::new(
            "https://identity.example.test".to_owned(),
            "staff-1".to_owned(),
            "operations-client".to_owned(),
        )
        .unwrap();
        let now = Utc.with_ymd_and_hms(2026, 10, 23, 12, 0, 0).unwrap();

        let allowed = authorize_operational_read(
            &profiles,
            &["scheduling:appointments:north".to_owned()],
            None,
            identity.clone(),
            filter(Some("station-1")),
            now,
        )
        .expect("one profile covers the operation");
        assert_eq!(allowed.profile_id(), "north-stations");
        assert!(allowed
            .projection()
            .allows(OperationalProjectionField::Resource));
        assert!(allowed
            .projection()
            .allows_external_reference_product("casework"));

        assert_eq!(
            authorize_operational_read(
                &profiles,
                &[
                    "scheduling:appointments:north".to_owned(),
                    "scheduling:appointments:south".to_owned(),
                ],
                Some("north-stations"),
                identity.clone(),
                filter(Some("station-1")),
                now,
            )
            .expect("an authorized selector resolves ambiguity")
            .profile_id(),
            "north-stations"
        );
        assert_eq!(
            authorize_operational_read(
                &profiles,
                &[
                    "scheduling:appointments:north".to_owned(),
                    "scheduling:appointments:south".to_owned(),
                ],
                None,
                identity.clone(),
                filter(Some("station-1")),
                now,
            ),
            Err(OperationalAuthorizationError::Profile)
        );
        assert_eq!(
            authorize_operational_read(
                &profiles,
                &["scheduling:appointments:north".to_owned()],
                Some("south-stations"),
                identity,
                filter(Some("station-2")),
                now,
            ),
            Err(OperationalAuthorizationError::Profile)
        );
    }

    #[test]
    fn exact_resource_and_time_bounds_fail_closed() {
        let profiles = BTreeMap::from([(
            "north-stations".to_owned(),
            profile(
                "scheduling:appointments:north",
                OperationalResourceScope::Exact {
                    ids: vec!["station-1".to_owned()],
                },
            ),
        )]);
        let identity = OperationalIdentity::new(
            "https://identity.example.test".to_owned(),
            "staff-1".to_owned(),
            "operations-client".to_owned(),
        )
        .unwrap();
        let now = Utc.with_ymd_and_hms(2026, 10, 23, 12, 0, 0).unwrap();
        let bounded_work_list = authorize_operational_read(
            &profiles,
            &["scheduling:appointments:north".to_owned()],
            None,
            identity.clone(),
            filter(None),
            now,
        )
        .expect("the store can intersect a work list with the profile's named resources");
        assert_eq!(
            bounded_work_list.resources(),
            &AuthorizedResourceScope::Exact {
                ids: vec!["station-1".to_owned()]
            }
        );
        assert_eq!(
            authorize_operational_read(
                &profiles,
                &["scheduling:appointments:north".to_owned()],
                None,
                identity.clone(),
                filter(Some("station-2")),
                now,
            ),
            Err(OperationalAuthorizationError::Profile)
        );

        let two_days = OperationalReadFilter::new(
            "registry-update".to_owned(),
            "north-counter".to_owned(),
            Some("station-1".to_owned()),
            OperationalTimeBasis::Occupied,
            Utc.with_ymd_and_hms(2026, 10, 23, 0, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 10, 25, 0, 0, 0).unwrap(),
        )
        .unwrap();
        assert_eq!(
            authorize_operational_read(
                &profiles,
                &["scheduling:appointments:north".to_owned()],
                None,
                identity,
                two_days,
                now,
            ),
            Err(OperationalAuthorizationError::Profile)
        );
    }

    #[test]
    fn profile_validation_accepts_counts_but_rejects_catalogue_scope_and_ambiguity() {
        let duplicate = profile(
            "scheduling:read",
            OperationalResourceScope::Exact {
                ids: vec!["station-1".to_owned(), "station-1".to_owned()],
            },
        );
        assert!(duplicate
            .validate("north-stations", "scheduling:read", "scheduling:explain")
            .is_err());
        let mut with_counts = profile(
            "scheduling:appointments:north",
            OperationalResourceScope::Unrestricted {},
        );
        with_counts
            .projection
            .fields
            .push(OperationalProjectionField::PartyCounts);
        with_counts
            .validate("north-stations", "scheduling:read", "scheduling:explain")
            .expect("persisted counts are an explicit projection choice");

        let profiles = BTreeMap::from([
            (
                "north-stations".to_owned(),
                profile(
                    "scheduling:appointments:staff",
                    OperationalResourceScope::Unrestricted {},
                ),
            ),
            (
                "south-stations".to_owned(),
                profile(
                    "scheduling:appointments:staff",
                    OperationalResourceScope::Unrestricted {},
                ),
            ),
        ]);
        assert!(validate_operational_read_profiles(
            &profiles,
            "scheduling:read",
            "scheduling:explain"
        )
        .iter()
        .any(|error| error.reason().contains("repeat")));
    }

    #[test]
    fn every_optional_filter_and_time_basis_is_bound_into_the_context() {
        let profiles = BTreeMap::from([(
            "north-stations".to_owned(),
            profile(
                "scheduling:appointments:north",
                OperationalResourceScope::Unrestricted {},
            ),
        )]);
        let identity = OperationalIdentity::new(
            "https://identity.example.test".to_owned(),
            "staff-1".to_owned(),
            "operations-client".to_owned(),
        )
        .unwrap();
        let now = Utc.with_ymd_and_hms(2026, 10, 23, 12, 0, 0).unwrap();
        let filtered = OperationalReadFilter::with_optional_filters(
            "registry-update".to_owned(),
            "north-counter".to_owned(),
            None,
            Some("in-person".to_owned()),
            Some(AppointmentStateDocument::Confirmed),
            Some(ExternalReference {
                product: "casework".to_owned(),
                record_type: "application".to_owned(),
                identifier: "case:1234".to_owned(),
            }),
            OperationalTimeBasis::Displayed,
            Utc.with_ymd_and_hms(2026, 10, 23, 9, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 10, 23, 17, 0, 0).unwrap(),
        )
        .unwrap();
        let displayed = authorize_operational_read(
            &profiles,
            &["scheduling:appointments:north".to_owned()],
            None,
            identity.clone(),
            filtered.clone(),
            now,
        )
        .unwrap();
        let occupied = authorize_operational_read(
            &profiles,
            &["scheduling:appointments:north".to_owned()],
            None,
            identity,
            OperationalReadFilter {
                time_basis: OperationalTimeBasis::Occupied,
                ..filtered
            },
            now,
        )
        .unwrap();
        assert_ne!(displayed.context_digest(), occupied.context_digest());

        let unapproved_reference = OperationalReadFilter::with_optional_filters(
            "registry-update".to_owned(),
            "north-counter".to_owned(),
            None,
            None,
            None,
            Some(ExternalReference {
                product: "evidence".to_owned(),
                record_type: "assertion".to_owned(),
                identifier: "assertion:1234".to_owned(),
            }),
            OperationalTimeBasis::Displayed,
            Utc.with_ymd_and_hms(2026, 10, 23, 9, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 10, 23, 17, 0, 0).unwrap(),
        )
        .unwrap();
        assert_eq!(
            authorize_operational_read(
                &profiles,
                &["scheduling:appointments:north".to_owned()],
                None,
                OperationalIdentity::new(
                    "https://identity.example.test".to_owned(),
                    "staff-1".to_owned(),
                    "operations-client".to_owned(),
                )
                .unwrap(),
                unapproved_reference,
                now,
            ),
            Err(OperationalAuthorizationError::Profile)
        );
    }
}
