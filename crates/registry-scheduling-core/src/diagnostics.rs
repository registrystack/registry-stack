// SPDX-License-Identifier: Apache-2.0

//! Field-addressed diagnostics for scheduling policy checks.
//!
//! A diagnostic names the exact policy path that failed and a closed reason,
//! so an authoring tool can point at the offending line and a report consumer
//! can never mistake one failure family for another.

use std::fmt;

/// A closed reason a policy path failed its check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyCheckReason {
    /// The envelope apiVersion is not the scheduling policy apiVersion.
    UnsupportedApiVersion,
    /// The envelope kind is not the scheduling policy kind.
    UnsupportedKind,
    /// An identifier is empty or outside the identifier grammar.
    InvalidIdentifier,
    /// The same identifier appears twice in one collection.
    DuplicateIdentifier,
    /// A required `because` is missing, blank, or longer than 256 bytes.
    InvalidBecause,
    /// A collection that must carry at least one entry is empty.
    EmptyCollection,
    /// A referenced service does not exist.
    UnknownService,
    /// A referenced offering does not exist.
    UnknownOffering,
    /// A referenced window does not exist.
    UnknownWindow,
    /// A referenced holiday set does not exist.
    UnknownHolidaySet,
    /// A field required by the offering's scheduling mode is absent.
    MissingModeField,
    /// A field that belongs to the other scheduling mode is present.
    WrongModeField,
    /// A numeric bound is zero, negative, or inverted.
    InvalidBound,
    /// The banded table is empty, non-increasing, or carries non-positive
    /// units.
    InvalidBands,
    /// Channel subquotas overlap or sum above the window's published units.
    SubquotaOverdrawn,
    /// Two declarations draw on the same supply without an attributable
    /// partition of it.
    SharedSupplyUnpartitioned,
    /// A hook declares an ABI other than the one reserved scheduling ABI.
    UnsupportedHookAbi,
    /// This version has no hook engine, so a declared hook can never run.
    HooksUnsupported,
}

impl PolicyCheckReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedApiVersion => "unsupported-api-version",
            Self::UnsupportedKind => "unsupported-kind",
            Self::InvalidIdentifier => "invalid-identifier",
            Self::DuplicateIdentifier => "duplicate-identifier",
            Self::InvalidBecause => "invalid-because",
            Self::EmptyCollection => "empty-collection",
            Self::UnknownService => "unknown-service",
            Self::UnknownOffering => "unknown-offering",
            Self::UnknownWindow => "unknown-window",
            Self::UnknownHolidaySet => "unknown-holiday-set",
            Self::MissingModeField => "missing-mode-field",
            Self::WrongModeField => "wrong-mode-field",
            Self::InvalidBound => "invalid-bound",
            Self::InvalidBands => "invalid-bands",
            Self::SubquotaOverdrawn => "subquota-overdrawn",
            Self::SharedSupplyUnpartitioned => "shared-supply-unpartitioned",
            Self::UnsupportedHookAbi => "unsupported-hook-abi",
            Self::HooksUnsupported => "hooks-unsupported",
        }
    }
}

impl fmt::Display for PolicyCheckReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One policy check finding: the path that failed, and why.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchedulingDiagnostic {
    pub path: String,
    pub reason: PolicyCheckReason,
}

impl SchedulingDiagnostic {
    pub fn new(path: impl Into<String>, reason: PolicyCheckReason) -> Self {
        Self {
            path: path.into(),
            reason,
        }
    }
}

impl fmt::Display for SchedulingDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.path, self.reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reasons_render_as_closed_slugs() {
        assert_eq!(
            PolicyCheckReason::SharedSupplyUnpartitioned.as_str(),
            "shared-supply-unpartitioned"
        );
        assert_eq!(
            SchedulingDiagnostic::new("windows[0].offering", PolicyCheckReason::UnknownOffering)
                .to_string(),
            "windows[0].offering: unknown-offering"
        );
    }
}
