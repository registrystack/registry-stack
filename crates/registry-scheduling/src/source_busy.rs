// SPDX-License-Identifier: Apache-2.0

//! Bounded authority and public documents for source-owned resource busy facts.
//!
//! A busy source contributes availability facts. It never receives booking
//! authority, never replaces operator supply, and never edits another source's
//! rows. The operator binds a verified OAuth scope to one stable source id and
//! an explicit resource set. Reconciliation requests carry their bounded
//! coverage interval so an empty, stale, or unavailable feed cannot be
//! mistaken for available capacity.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, TimeDelta, Utc};
use registry_platform_audit::AuditKeyHasher;
use registry_platform_canonical_json::canonicalize_json;
use registry_scheduling_core::{valid_identifier, MAXIMUM_HORIZON_DAYS};
pub use registry_scheduling_core::{
    BusyApplyOutcome, BusyApplyOutcomeKind, BusyCommitmentImpact, BusyCoverage, BusyImpactSummary,
    BusyIntervalInput, BusyReconciliationPreview, BusyReconciliationRequest,
    BusyRequestValidationError, BusySourceStatus, BUSY_SOURCE_APPLY_PATH, BUSY_SOURCE_PREVIEW_PATH,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub const MAX_BUSY_IMPORT_PROFILES: usize = 64;
pub const MAX_BUSY_IMPORT_RESOURCES: usize = registry_scheduling_core::MAX_BUSY_IMPORT_RESOURCES;
pub const MAX_BUSY_IMPORT_IMPACTS: usize = 256;
pub const MAX_BUSY_IMPORT_SPAN_DAYS: u32 = registry_scheduling_core::MAX_BUSY_IMPORT_SPAN_DAYS;
pub const MAX_BUSY_IMPORT_FRESHNESS_MINUTES: u32 =
    registry_scheduling_core::MAX_BUSY_IMPORT_FRESHNESS_MINUTES;
const MAX_SCOPE_BYTES: usize = 256;
const BUSY_SOURCE_AUDIT_CLASS: &str = "scheduling-busy-source-v1";

/// One operator-authorized source and its current resource ceiling.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BusyImportProfileConfig {
    pub scope: String,
    pub source_id: String,
    #[serde(deserialize_with = "registry_scheduling_core::unique_local_ids")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::UniqueList<registry_platform_yaml::LocalId>")
    )]
    pub resources: Vec<String>,
    #[serde(
        deserialize_with = "registry_scheduling_core::bounded_u32::<_, 0, MAXIMUM_HORIZON_DAYS>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<0, MAXIMUM_HORIZON_DAYS>")
    )]
    pub maximum_past_days: u32,
    #[serde(
        deserialize_with = "registry_scheduling_core::bounded_u32::<_, 0, MAXIMUM_HORIZON_DAYS>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<0, MAXIMUM_HORIZON_DAYS>")
    )]
    pub maximum_future_days: u32,
    #[serde(
        deserialize_with = "registry_scheduling_core::bounded_u32::<_, 1, MAX_BUSY_IMPORT_SPAN_DAYS>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, MAX_BUSY_IMPORT_SPAN_DAYS>")
    )]
    pub maximum_span_days: u32,
    #[serde(
        deserialize_with = "registry_scheduling_core::bounded_u32::<_, 1, MAX_BUSY_IMPORT_FRESHNESS_MINUTES>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "registry_platform_yaml::BoundedU32<1, MAX_BUSY_IMPORT_FRESHNESS_MINUTES>"
        )
    )]
    pub maximum_freshness_minutes: u32,
    #[serde(default)]
    pub impact_projection: BusyImpactProjection,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BusyImpactProjection {
    #[default]
    CountOnly,
    CommitmentIntervals,
}

/// The verified token identity used to select a source profile.
#[derive(Clone, Eq, PartialEq)]
pub struct BusySourceIdentity {
    issuer: String,
    subject: String,
    client: String,
}

impl BusySourceIdentity {
    pub fn new(
        issuer: String,
        subject: String,
        client: String,
    ) -> Result<Self, BusyAuthorizationError> {
        if [&issuer, &subject, &client]
            .into_iter()
            .any(|value| value.is_empty())
        {
            return Err(BusyAuthorizationError::Profile);
        }
        Ok(Self {
            issuer,
            subject,
            client,
        })
    }
}

impl std::fmt::Debug for BusySourceIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BusySourceIdentity")
            .field("issuer", &"<redacted>")
            .field("subject", &"<redacted>")
            .field("client", &"<redacted>")
            .finish()
    }
}

/// Immutable evidence that one verified credential selected one configured
/// source authority. Request bodies cannot add a source or resource to it.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizedBusySource {
    identity: BusySourceIdentity,
    profile_id: String,
    source_id: String,
    resources: BTreeSet<String>,
    maximum_past_days: u32,
    maximum_future_days: u32,
    maximum_span_days: u32,
    maximum_freshness_minutes: u32,
    impact_projection: BusyImpactProjection,
    profile_digest: String,
}

impl AuthorizedBusySource {
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    #[must_use]
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    #[must_use]
    pub fn resources(&self) -> &BTreeSet<String> {
        &self.resources
    }

    #[must_use]
    pub fn profile_digest(&self) -> &str {
        &self.profile_digest
    }

    #[must_use]
    pub fn includes_impact_details(&self) -> bool {
        self.impact_projection == BusyImpactProjection::CommitmentIntervals
    }

    pub(crate) fn actor_pseudonym(
        &self,
        hasher: &AuditKeyHasher,
        scope: &str,
    ) -> Result<String, BusyAuthorizationError> {
        let canonical = serde_json::to_string(&(
            &self.identity.issuer,
            &self.identity.subject,
            &self.identity.client,
        ))
        .map_err(|_| BusyAuthorizationError::Profile)?;
        hasher
            .audit_reference_hash(BUSY_SOURCE_AUDIT_CLASS, scope, &canonical)
            .map_err(|_| BusyAuthorizationError::Profile)
    }
}

impl std::fmt::Debug for AuthorizedBusySource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizedBusySource")
            .field("identity", &self.identity)
            .field("profile_id", &self.profile_id)
            .field("source_id", &self.source_id)
            .field("resource_count", &self.resources.len())
            .field("profile_digest", &self.profile_digest)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum BusyAuthorizationError {
    #[error("the busy import profile is invalid or not authorized")]
    Profile,
}

/// Validate all source profiles together. Source ids are unique. Profiles may
/// deliberately share a write scope, but the caller must select exactly one
/// profile and no write scope may be reused from a read profile.
pub fn validate_busy_import_profiles(
    profiles: &BTreeMap<String, BusyImportProfileConfig>,
    reserved_scopes: impl IntoIterator<Item = String>,
) -> Result<(), BusyAuthorizationError> {
    if profiles.len() > MAX_BUSY_IMPORT_PROFILES {
        return Err(BusyAuthorizationError::Profile);
    }
    let mut source_ids = BTreeSet::new();
    let reserved_scopes = reserved_scopes.into_iter().collect::<BTreeSet<_>>();
    for (profile_id, profile) in profiles {
        let resources = profile.resources.iter().collect::<BTreeSet<_>>();
        if !valid_identifier(profile_id)
            || !valid_identifier(&profile.source_id)
            || profile.scope.is_empty()
            || profile.scope.len() > MAX_SCOPE_BYTES
            || profile.scope.chars().any(char::is_control)
            || profile.resources.is_empty()
            || profile.resources.len() > MAX_BUSY_IMPORT_RESOURCES
            || resources.len() != profile.resources.len()
            || profile
                .resources
                .iter()
                .any(|resource| !valid_identifier(resource))
            || profile.maximum_span_days == 0
            || profile.maximum_span_days > MAX_BUSY_IMPORT_SPAN_DAYS
            || profile.maximum_freshness_minutes == 0
            || profile.maximum_freshness_minutes > MAX_BUSY_IMPORT_FRESHNESS_MINUTES
            || profile.maximum_past_days > registry_scheduling_core::MAXIMUM_HORIZON_DAYS
            || profile.maximum_future_days > registry_scheduling_core::MAXIMUM_HORIZON_DAYS
            || !source_ids.insert(profile.source_id.clone())
            || reserved_scopes.contains(&profile.scope)
        {
            return Err(BusyAuthorizationError::Profile);
        }
    }
    Ok(())
}

pub fn authorize_busy_source(
    profiles: &BTreeMap<String, BusyImportProfileConfig>,
    scopes: &[String],
    profile_selector: Option<&str>,
    identity: BusySourceIdentity,
) -> Result<AuthorizedBusySource, BusyAuthorizationError> {
    let (profile_id, profile) = match profile_selector {
        Some(profile_id) => profiles
            .get_key_value(profile_id)
            .ok_or(BusyAuthorizationError::Profile)?,
        None => return Err(BusyAuthorizationError::Profile),
    };
    if !scopes.iter().any(|scope| scope == &profile.scope) {
        return Err(BusyAuthorizationError::Profile);
    }
    let profile_value =
        serde_json::to_value((profile_id, profile)).map_err(|_| BusyAuthorizationError::Profile)?;
    let canonical =
        canonicalize_json(&profile_value).map_err(|_| BusyAuthorizationError::Profile)?;
    Ok(AuthorizedBusySource {
        identity,
        profile_id: profile_id.clone(),
        source_id: profile.source_id.clone(),
        resources: profile.resources.iter().cloned().collect(),
        maximum_past_days: profile.maximum_past_days,
        maximum_future_days: profile.maximum_future_days,
        maximum_span_days: profile.maximum_span_days,
        maximum_freshness_minutes: profile.maximum_freshness_minutes,
        impact_projection: profile.impact_projection,
        profile_digest: sha256_digest(&canonical),
    })
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum BusyRequestError {
    #[error("the busy reconciliation request is invalid")]
    Invalid,
    #[error("the busy reconciliation request exceeds its bound")]
    Bound,
    #[error("the busy reconciliation request exceeds its configured authority")]
    Authority,
}

impl From<BusyRequestValidationError> for BusyRequestError {
    fn from(error: BusyRequestValidationError) -> Self {
        match error {
            BusyRequestValidationError::Invalid => Self::Invalid,
            BusyRequestValidationError::Bound => Self::Bound,
        }
    }
}

pub fn validate_busy_reconciliation_request(
    request: &BusyReconciliationRequest,
    authority: &AuthorizedBusySource,
    now: DateTime<Utc>,
) -> Result<(), BusyRequestError> {
    request.validate_wire()?;
    let span = request.coverage.end - request.coverage.start;
    let maximum_span = TimeDelta::days(i64::from(authority.maximum_span_days));
    if span > maximum_span
        || request.coverage.start < now - TimeDelta::days(i64::from(authority.maximum_past_days))
        || request.coverage.end > now + TimeDelta::days(i64::from(authority.maximum_future_days))
    {
        return Err(BusyRequestError::Bound);
    }
    let covered = request.coverage.resources.iter().collect::<BTreeSet<_>>();
    if covered
        .iter()
        .any(|resource| !authority.resources.contains(*resource))
    {
        return Err(BusyRequestError::Authority);
    }
    if let BusySourceStatus::Fresh = request.status {
        let maximum_freshness = TimeDelta::minutes(i64::from(authority.maximum_freshness_minutes));
        if !request.fresh_until.is_some_and(|fresh_until| {
            fresh_until <= request.observed_at + maximum_freshness
                && fresh_until <= now + maximum_freshness
        }) {
            return Err(BusyRequestError::Invalid);
        }
    }
    if request.observed_at > now + TimeDelta::minutes(5)
        || request.observed_at
            < now - TimeDelta::minutes(i64::from(authority.maximum_freshness_minutes))
    {
        return Err(BusyRequestError::Invalid);
    }
    if request
        .records
        .iter()
        .any(|record| !authority.resources.contains(&record.resource))
    {
        return Err(BusyRequestError::Authority);
    }
    Ok(())
}

pub fn busy_reconciliation_request_digest(
    request: &BusyReconciliationRequest,
    authority: &AuthorizedBusySource,
) -> Result<String, BusyRequestError> {
    let value = json!({
        "sourceId": authority.source_id,
        "profileDigest": authority.profile_digest,
        "request": request,
    });
    let canonical = canonicalize_json(&value).map_err(|_| BusyRequestError::Invalid)?;
    Ok(sha256_digest(&canonical))
}

fn sha256_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut rendered = String::with_capacity(71);
    rendered.push_str("sha256:");
    for byte in digest {
        rendered.push(HEX[(byte >> 4) as usize] as char);
        rendered.push(HEX[(byte & 0x0f) as usize] as char);
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profiles() -> BTreeMap<String, BusyImportProfileConfig> {
        BTreeMap::from([(
            "staff-calendar".to_owned(),
            BusyImportProfileConfig {
                scope: "scheduling:busy:staff".to_owned(),
                source_id: "staff-calendar".to_owned(),
                resources: vec!["staff-a".to_owned(), "staff-b".to_owned()],
                maximum_past_days: 7,
                maximum_future_days: 62,
                maximum_span_days: 31,
                maximum_freshness_minutes: 240,
                impact_projection: BusyImpactProjection::CountOnly,
            },
        )])
    }

    fn authority() -> AuthorizedBusySource {
        authorize_busy_source(
            &profiles(),
            &["scheduling:busy:staff".to_owned()],
            Some("staff-calendar"),
            BusySourceIdentity::new(
                "https://issuer.example".to_owned(),
                "calendar-agent".to_owned(),
                "calendar-client".to_owned(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn request(now: DateTime<Utc>) -> BusyReconciliationRequest {
        BusyReconciliationRequest {
            expected_revision: 3,
            observed_at: now,
            fresh_until: Some(now + TimeDelta::hours(2)),
            coverage: BusyCoverage {
                start: now - TimeDelta::days(1),
                end: now + TimeDelta::days(14),
                resources: vec!["staff-a".to_owned()],
            },
            status: BusySourceStatus::Fresh,
            records: vec![BusyIntervalInput {
                external_uid: "meeting-42/2026-10-23T08:00:00Z".to_owned(),
                external_revision: "7".to_owned(),
                resource: "staff-a".to_owned(),
                start: now + TimeDelta::hours(1),
                end: now + TimeDelta::hours(2),
            }],
        }
    }

    #[test]
    fn profile_selection_never_combines_sources_or_resources() {
        let mut values = profiles();
        values.insert(
            "rooms".to_owned(),
            BusyImportProfileConfig {
                scope: "scheduling:busy:rooms".to_owned(),
                source_id: "room-calendar".to_owned(),
                resources: vec!["room-a".to_owned()],
                maximum_past_days: 1,
                maximum_future_days: 31,
                maximum_span_days: 31,
                maximum_freshness_minutes: 240,
                impact_projection: BusyImpactProjection::CountOnly,
            },
        );
        validate_busy_import_profiles(
            &values,
            [
                "scheduling:read".to_owned(),
                "scheduling:explain".to_owned(),
            ],
        )
        .unwrap();
        let authorized = authorize_busy_source(
            &values,
            &[
                "scheduling:busy:staff".to_owned(),
                "scheduling:busy:rooms".to_owned(),
            ],
            Some("rooms"),
            BusySourceIdentity::new("issuer".into(), "subject".into(), "client".into()).unwrap(),
        )
        .unwrap();
        assert_eq!(authorized.source_id(), "room-calendar");
        assert_eq!(
            authorized.resources(),
            &BTreeSet::from(["room-a".to_owned()])
        );
    }

    #[test]
    fn duplicate_source_bindings_are_refused_even_when_scopes_may_be_shared() {
        let mut values = profiles();
        values.insert(
            "second".to_owned(),
            BusyImportProfileConfig {
                scope: "scheduling:busy:staff".to_owned(),
                source_id: "staff-calendar".to_owned(),
                resources: vec!["staff-b".to_owned()],
                maximum_past_days: 1,
                maximum_future_days: 1,
                maximum_span_days: 1,
                maximum_freshness_minutes: 60,
                impact_projection: BusyImpactProjection::CountOnly,
            },
        );
        assert_eq!(
            validate_busy_import_profiles(&values, std::iter::empty()),
            Err(BusyAuthorizationError::Profile)
        );
    }

    #[test]
    fn an_explicit_profile_is_required_and_shared_write_scopes_do_not_union() {
        let mut values = profiles();
        values.insert(
            "second".to_owned(),
            BusyImportProfileConfig {
                scope: "scheduling:busy:staff".to_owned(),
                source_id: "second-calendar".to_owned(),
                resources: vec!["staff-b".to_owned()],
                maximum_past_days: 1,
                maximum_future_days: 1,
                maximum_span_days: 1,
                maximum_freshness_minutes: 60,
                impact_projection: BusyImpactProjection::CountOnly,
            },
        );
        validate_busy_import_profiles(&values, std::iter::empty()).unwrap();
        let identity =
            || BusySourceIdentity::new("issuer".into(), "subject".into(), "client".into()).unwrap();
        assert_eq!(
            authorize_busy_source(
                &values,
                &["scheduling:busy:staff".to_owned()],
                None,
                identity(),
            ),
            Err(BusyAuthorizationError::Profile)
        );
        let authorized = authorize_busy_source(
            &values,
            &["scheduling:busy:staff".to_owned()],
            Some("second"),
            identity(),
        )
        .unwrap();
        assert_eq!(authorized.source_id(), "second-calendar");
        assert_eq!(
            authorized.resources(),
            &BTreeSet::from(["staff-b".to_owned()])
        );
    }

    #[test]
    fn a_request_cannot_name_an_unbound_resource() {
        let now = DateTime::parse_from_rfc3339("2026-10-23T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut value = request(now);
        value.coverage.resources = vec!["staff-c".to_owned()];
        value.records[0].resource = "staff-c".to_owned();
        assert_eq!(
            validate_busy_reconciliation_request(&value, &authority(), now),
            Err(BusyRequestError::Authority)
        );
    }

    #[test]
    fn unavailable_is_explicit_and_cannot_look_like_an_empty_fresh_snapshot() {
        let now = DateTime::parse_from_rfc3339("2026-10-23T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut value = request(now);
        value.status = BusySourceStatus::Unavailable;
        assert_eq!(
            validate_busy_reconciliation_request(&value, &authority(), now),
            Err(BusyRequestError::Invalid)
        );
        value.records.clear();
        value.fresh_until = None;
        validate_busy_reconciliation_request(&value, &authority(), now).unwrap();
    }

    #[test]
    fn coverage_bounds_and_duplicate_external_identity_are_refused() {
        let now = DateTime::parse_from_rfc3339("2026-10-23T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut value = request(now);
        value.records.push(value.records[0].clone());
        assert_eq!(
            validate_busy_reconciliation_request(&value, &authority(), now),
            Err(BusyRequestError::Invalid)
        );
        value.records.pop();
        value.coverage.end = now + TimeDelta::days(32);
        assert_eq!(
            validate_busy_reconciliation_request(&value, &authority(), now),
            Err(BusyRequestError::Bound)
        );
    }

    #[test]
    fn request_digest_binds_source_profile_and_exact_body() {
        let now = DateTime::parse_from_rfc3339("2026-10-23T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let value = request(now);
        let first = busy_reconciliation_request_digest(&value, &authority()).unwrap();
        let second = busy_reconciliation_request_digest(&value, &authority()).unwrap();
        assert_eq!(first, second);
        let mut changed = value;
        changed.records[0].external_revision = "8".to_owned();
        assert_ne!(
            first,
            busy_reconciliation_request_digest(&changed, &authority()).unwrap()
        );
    }

    #[test]
    fn impact_details_require_an_explicit_profile_projection() {
        assert!(!authority().includes_impact_details());
        let summary = BusyImpactSummary {
            total: 2,
            details_available: false,
            truncated: true,
            items: Vec::new(),
        };
        let encoded = serde_json::to_value(summary).unwrap();
        assert_eq!(encoded["total"], 2);
        assert_eq!(encoded["detailsAvailable"], false);
        assert_eq!(encoded["truncated"], true);
        assert!(encoded.get("items").is_none());

        let mut values = profiles();
        values.get_mut("staff-calendar").unwrap().impact_projection =
            BusyImpactProjection::CommitmentIntervals;
        let projected = authorize_busy_source(
            &values,
            &["scheduling:busy:staff".to_owned()],
            Some("staff-calendar"),
            BusySourceIdentity::new("issuer".into(), "subject".into(), "client".into()).unwrap(),
        )
        .unwrap();
        assert!(projected.includes_impact_details());
    }

    #[test]
    fn source_audit_identity_is_pseudonymized_over_the_verified_client() {
        let first = authority()
            .actor_pseudonym(&AuditKeyHasher::unkeyed_dev_only(), "deployment-a")
            .unwrap();
        let second = authority()
            .actor_pseudonym(&AuditKeyHasher::unkeyed_dev_only(), "deployment-a")
            .unwrap();
        assert_eq!(first, second);
        assert!(!first.contains("calendar-agent"));
        assert!(!first.contains("calendar-client"));
    }
}
