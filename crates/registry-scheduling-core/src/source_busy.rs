// SPDX-License-Identifier: Apache-2.0

//! Public wire documents for bounded, source-owned busy reconciliation.
//!
//! These documents carry only source correlation, version, resource, and time
//! facts. Calendar descriptions, attendees, organizers, absence reasons,
//! booking parties, and source references are deliberately outside the
//! contract.

use std::collections::BTreeSet;

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::valid_identifier;

pub const BUSY_SOURCE_PREVIEW_PATH: &str = "/v1/source-busy/preview";
pub const BUSY_SOURCE_APPLY_PATH: &str = "/v1/source-busy/apply";
pub const MAX_BUSY_IMPORT_RESOURCES: usize = 256;
pub const MAX_BUSY_IMPORT_RECORDS: usize = 4_096;
pub const MAX_BUSY_IMPORT_SPAN_DAYS: u32 = 62;
pub const MAX_BUSY_IMPORT_FRESHNESS_MINUTES: u32 = 10_080;
const MAX_SOURCE_UID_BYTES: usize = 512;
const MAX_SOURCE_REVISION_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum BusySourceStatus {
    Fresh,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BusyCoverage {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub resources: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BusyIntervalInput {
    pub external_uid: String,
    pub external_revision: String,
    pub resource: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BusyReconciliationRequest {
    pub expected_revision: u64,
    pub observed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fresh_until: Option<DateTime<Utc>>,
    pub coverage: BusyCoverage,
    pub status: BusySourceStatus,
    pub records: Vec<BusyIntervalInput>,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum BusyRequestValidationError {
    #[error("the source-busy request is structurally invalid")]
    Invalid,
    #[error("the source-busy request exceeds a public bound")]
    Bound,
}

impl BusyReconciliationRequest {
    /// Validate every source-independent wire invariant before network or
    /// database I/O. Runtime authorization applies the selected profile's
    /// narrower resources, horizon, freshness, and observed-clock bounds.
    pub fn validate_wire(&self) -> Result<(), BusyRequestValidationError> {
        if self.coverage.start >= self.coverage.end
            || self.coverage.end - self.coverage.start
                > TimeDelta::days(i64::from(MAX_BUSY_IMPORT_SPAN_DAYS))
            || self.coverage.resources.is_empty()
            || self.coverage.resources.len() > MAX_BUSY_IMPORT_RESOURCES
            || self.records.len() > MAX_BUSY_IMPORT_RECORDS
        {
            return Err(BusyRequestValidationError::Bound);
        }
        let covered = self.coverage.resources.iter().collect::<BTreeSet<_>>();
        if covered.len() != self.coverage.resources.len()
            || covered.iter().any(|resource| !valid_identifier(resource))
        {
            return Err(BusyRequestValidationError::Invalid);
        }
        match self.status {
            BusySourceStatus::Fresh => {
                if !self.fresh_until.is_some_and(|fresh_until| {
                    fresh_until > self.observed_at
                        && fresh_until
                            <= self.observed_at
                                + TimeDelta::minutes(i64::from(MAX_BUSY_IMPORT_FRESHNESS_MINUTES))
                }) {
                    return Err(BusyRequestValidationError::Invalid);
                }
            }
            BusySourceStatus::Unavailable => {
                if self.fresh_until.is_some() || !self.records.is_empty() {
                    return Err(BusyRequestValidationError::Invalid);
                }
            }
        }
        let mut identities = BTreeSet::new();
        for record in &self.records {
            if record.external_uid.is_empty()
                || record.external_uid.len() > MAX_SOURCE_UID_BYTES
                || record.external_uid.chars().any(char::is_control)
                || record.external_revision.is_empty()
                || record.external_revision.len() > MAX_SOURCE_REVISION_BYTES
                || record.external_revision.chars().any(char::is_control)
                || !valid_identifier(&record.resource)
                || record.start >= record.end
                || record.start < self.coverage.start
                || record.end > self.coverage.end
                || !covered.contains(&record.resource)
                || !identities.insert((&record.resource, &record.external_uid))
            {
                return Err(BusyRequestValidationError::Invalid);
            }
        }
        Ok(())
    }
}

/// One affected commitment interval. Identifiers, parties, references, and
/// free text are never present, even when this projection is enabled.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct BusyCommitmentImpact {
    pub kind: String,
    pub resource: String,
    pub occupied_start: DateTime<Utc>,
    pub occupied_end: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct BusyImpactSummary {
    pub total: u64,
    pub details_available: bool,
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<BusyCommitmentImpact>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct BusyReconciliationPreview {
    pub source_id: String,
    pub expected_revision: u64,
    pub current_revision: u64,
    pub request_digest: String,
    pub added: u64,
    pub changed: u64,
    pub deleted: u64,
    pub retained_outside_authority: u64,
    pub retained_across_coverage_boundary: u64,
    pub impacts: BusyImpactSummary,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum BusyApplyOutcomeKind {
    Applied,
    AlreadyApplied,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct BusyApplyOutcome {
    pub kind: BusyApplyOutcomeKind,
    pub source_id: String,
    pub revision: u64,
    pub request_digest: String,
    pub added: u64,
    pub changed: u64,
    pub deleted: u64,
    pub retained_outside_authority: u64,
    pub retained_across_coverage_boundary: u64,
    pub impacts: BusyImpactSummary,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instant(value: &str) -> DateTime<Utc> {
        value.parse().unwrap()
    }

    fn request() -> BusyReconciliationRequest {
        BusyReconciliationRequest {
            expected_revision: 4,
            observed_at: instant("2026-10-23T00:00:00Z"),
            fresh_until: Some(instant("2026-10-23T01:00:00Z")),
            coverage: BusyCoverage {
                start: instant("2026-10-23T00:00:00Z"),
                end: instant("2026-10-24T00:00:00Z"),
                resources: vec!["staff-a".to_owned()],
            },
            status: BusySourceStatus::Fresh,
            records: vec![BusyIntervalInput {
                external_uid: "event-1/2026-10-23T09:00:00Z".to_owned(),
                external_revision: "sequence:2".to_owned(),
                resource: "staff-a".to_owned(),
                start: instant("2026-10-23T09:00:00Z"),
                end: instant("2026-10-23T10:00:00Z"),
            }],
        }
    }

    #[test]
    fn bounded_wire_request_is_valid_before_io() {
        request().validate_wire().unwrap();
    }

    #[test]
    fn duplicate_identity_and_out_of_coverage_records_are_rejected() {
        let mut value = request();
        value.records.push(value.records[0].clone());
        assert_eq!(
            value.validate_wire(),
            Err(BusyRequestValidationError::Invalid)
        );
        value.records.pop();
        value.records[0].end = value.coverage.end + TimeDelta::seconds(1);
        assert_eq!(
            value.validate_wire(),
            Err(BusyRequestValidationError::Invalid)
        );
    }

    #[test]
    fn unavailable_is_distinct_from_an_empty_fresh_snapshot() {
        let mut value = request();
        value.status = BusySourceStatus::Unavailable;
        assert_eq!(
            value.validate_wire(),
            Err(BusyRequestValidationError::Invalid)
        );
        value.records.clear();
        value.fresh_until = None;
        value.validate_wire().unwrap();
    }
}
