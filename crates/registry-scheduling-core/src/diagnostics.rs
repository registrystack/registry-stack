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
    /// A subquota names a channel outside the package's declared channel
    /// set.
    UnknownChannel,
    /// A field required by the offering's scheduling mode is absent.
    MissingModeField,
    /// A field that belongs to the other scheduling mode is present.
    WrongModeField,
    /// A value's text is outside the grammar its field requires: a clock that
    /// is not `HH:MM`, a date that is not `YYYY-MM-DD`.
    MalformedValue,
    /// A numeric bound is zero, negative, or inverted.
    InvalidBound,
    /// An opening's effective range spans more days than the weekly calendar
    /// expansion can serve.
    PatternSpanTooLarge,
    /// The banded table is empty, non-increasing, or carries non-positive
    /// units.
    InvalidBands,
    /// Channel subquotas overlap or sum above the window's published units.
    SubquotaOverdrawn,
    /// Two declarations draw on the same supply without an attributable
    /// partition of it.
    SharedSupplyUnpartitioned,
    /// A local hook omits or changes the shared handler ABI.
    UnsupportedHookAbi,
    /// A hook phase and handler kind cannot run together.
    UnsupportedHookPhase,
    /// A hook trigger is outside Scheduling's closed lifecycle vocabulary.
    UnsupportedHookTrigger,
    /// Scheduling's observer slice does not evaluate hook conditions.
    UnsupportedHookCondition,
    /// Scheduling observer hooks cannot carry proposal authority.
    UnsupportedHookPrincipal,
    /// A projected field is unavailable for the selected Scheduling trigger.
    UnsupportedHookProjection,
    /// A URL hook names no valid deployment-owned logical destination.
    InvalidHookDestination,
    /// A shared hook declaration violates a rule unknown to this product.
    InvalidHookDeclaration,
    /// This version reads no leftover policy, so a declared one never
    /// applies.
    LeftoverUnsupported,
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
            Self::UnknownChannel => "unknown-channel",
            Self::MissingModeField => "missing-mode-field",
            Self::WrongModeField => "wrong-mode-field",
            Self::MalformedValue => "malformed-value",
            Self::InvalidBound => "invalid-bound",
            Self::PatternSpanTooLarge => "pattern-span-too-large",
            Self::InvalidBands => "invalid-bands",
            Self::SubquotaOverdrawn => "subquota-overdrawn",
            Self::SharedSupplyUnpartitioned => "shared-supply-unpartitioned",
            Self::UnsupportedHookAbi => "unsupported-hook-abi",
            Self::UnsupportedHookPhase => "unsupported-hook-phase",
            Self::UnsupportedHookTrigger => "unsupported-hook-trigger",
            Self::UnsupportedHookCondition => "unsupported-hook-condition",
            Self::UnsupportedHookPrincipal => "unsupported-hook-principal",
            Self::UnsupportedHookProjection => "unsupported-hook-projection",
            Self::InvalidHookDestination => "invalid-hook-destination",
            Self::InvalidHookDeclaration => "invalid-hook-declaration",
            Self::LeftoverUnsupported => "leftover-unsupported",
        }
    }

    /// Whether the reason describes a value whose text is outside the grammar
    /// its field requires.
    ///
    /// Such a value is not an unfinished project: no addition makes it valid,
    /// only a correction. Adopter tooling refuses a document carrying one
    /// rather than reporting it as incomplete authoring.
    #[must_use]
    pub const fn is_malformed_value(self) -> bool {
        matches!(self, Self::MalformedValue)
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

    #[test]
    fn only_a_malformed_value_says_the_text_is_wrong() {
        assert!(PolicyCheckReason::MalformedValue.is_malformed_value());
        assert_eq!(
            PolicyCheckReason::MalformedValue.as_str(),
            "malformed-value"
        );
        for reason in [
            PolicyCheckReason::InvalidBound,
            PolicyCheckReason::InvalidIdentifier,
            PolicyCheckReason::InvalidBecause,
            PolicyCheckReason::EmptyCollection,
        ] {
            assert!(!reason.is_malformed_value(), "{reason}");
        }
    }
}
