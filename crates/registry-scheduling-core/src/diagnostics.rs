// SPDX-License-Identifier: Apache-2.0

//! Field-addressed diagnostics for scheduling policy checks.
//!
//! A diagnostic names the exact place that failed, as an RFC 6901 pointer
//! into the document it is about, and a closed reason, so an authoring tool
//! can point at the offending line and a report consumer can never mistake
//! one failure family for another. The message and the action a reason
//! carries name keys, accepted forms, and bounds, and never repeat a value
//! read from the file (CFG-SEC-3).

use std::fmt;

use registry_platform_yaml::{Diagnostic, Document, Report, Severity};

/// The authored document a finding points into. It is the middle segment of
/// the finding's `scheduling.<area>.<condition>` code (CFG-DIAG-3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FindingArea {
    /// The project file, `scheduling.yaml`.
    Project,
    /// The environment records document, or the `facts` block of a fixture.
    Records,
    /// A replay fixture.
    Fixture,
}

impl FindingArea {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::Records => "records",
            Self::Fixture => "fixture",
        }
    }

    /// The `kind` of the document this area names.
    #[must_use]
    pub const fn kind(self) -> &'static str {
        match self {
            Self::Project => crate::naming::SCHEDULING_POLICY_KIND,
            Self::Records => crate::naming::SCHEDULING_RECORDS_KIND,
            Self::Fixture => crate::naming::SCHEDULING_FIXTURE_KIND,
        }
    }
}

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
    /// A required text member, such as the project version, is blank.
    EmptyText,
    /// A label is blank or longer than 128 bytes.
    InvalidLabel,
    /// A collection that must carry at least one entry is empty.
    EmptyCollection,
    /// A collection carries more entries than its bound.
    TooManyEntries,
    /// A referenced service does not exist.
    UnknownService,
    /// A referenced offering does not exist.
    UnknownOffering,
    /// A referenced window does not exist.
    UnknownWindow,
    /// A referenced location does not exist.
    UnknownLocation,
    /// A referenced resource pool does not exist.
    UnknownPool,
    /// A location names a timezone outside the IANA database.
    UnknownTimezone,
    /// A resource is a member of more than one pool.
    ResourceInManyPools,
    /// A reference resolves to a record owned by another declaration.
    MismatchedReference,
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
    /// A number is zero where at least one is required.
    InvalidBound,
    /// The end of a range does not come after its start.
    InvertedRange,
    /// A lead time is longer than the booking horizon it sits in.
    LeadTimeBeyondHorizon,
    /// An opening's effective range spans more days than the weekly calendar
    /// expansion can serve.
    PatternSpanTooLarge,
    /// The calendar cannot expand a location's openings with its dated
    /// exceptions.
    CalendarRefused,
    /// The banded table is empty, non-increasing, or carries non-positive
    /// units.
    InvalidBands,
    /// Channel subquotas overlap or sum above the window's published units.
    SubquotaOverdrawn,
    /// Two declarations draw on the same supply without a partition the
    /// ledger can enforce.
    SharedSupplyUnpartitioned,
    /// A resource pool and a published window claim the same identifier.
    /// Both anchor their capacity transactions on one row keyed by that
    /// identifier, so the two kinds of supply must not share one.
    SupplyIdentifierCollision,
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
            Self::EmptyText => "empty-text",
            Self::InvalidLabel => "invalid-label",
            Self::EmptyCollection => "empty-collection",
            Self::TooManyEntries => "too-many-entries",
            Self::UnknownService => "unknown-service",
            Self::UnknownOffering => "unknown-offering",
            Self::UnknownWindow => "unknown-window",
            Self::UnknownLocation => "unknown-location",
            Self::UnknownPool => "unknown-pool",
            Self::UnknownTimezone => "unknown-timezone",
            Self::ResourceInManyPools => "resource-in-many-pools",
            Self::MismatchedReference => "mismatched-reference",
            Self::UnknownHolidaySet => "unknown-holiday-set",
            Self::UnknownChannel => "unknown-channel",
            Self::MissingModeField => "missing-mode-field",
            Self::WrongModeField => "wrong-mode-field",
            Self::MalformedValue => "malformed-value",
            Self::InvalidBound => "invalid-bound",
            Self::InvertedRange => "inverted-range",
            Self::LeadTimeBeyondHorizon => "lead-time-beyond-horizon",
            Self::PatternSpanTooLarge => "pattern-span-too-large",
            Self::CalendarRefused => "calendar-refused",
            Self::InvalidBands => "invalid-bands",
            Self::SubquotaOverdrawn => "subquota-overdrawn",
            Self::SharedSupplyUnpartitioned => "shared-supply-unpartitioned",
            Self::SupplyIdentifierCollision => "supply-identifier-collision",
            Self::UnsupportedHookProjection => "unsupported-hook-projection",
            Self::InvalidHookDestination => "invalid-hook-destination",
            Self::InvalidHookDeclaration => "invalid-hook-declaration",
            Self::LeftoverUnsupported => "leftover-unsupported",
        }
    }

    /// What is wrong, in words that name keys, forms, and bounds and never
    /// repeat a value (CFG-SEC-3).
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::UnsupportedApiVersion => "this is not the apiVersion this document reads",
            Self::UnsupportedKind => "this is not the kind this document reads",
            Self::InvalidIdentifier => {
                "expected 1 to 64 characters: a lowercase letter, then lowercase letters, \
                 digits, '-', or '_'"
            }
            Self::DuplicateIdentifier => "this repeats an entry already listed",
            Self::InvalidBecause => "a because must be 1 to 256 bytes and not blank",
            Self::EmptyText => "this text is blank",
            Self::InvalidLabel => "a label must be 1 to 128 bytes and not blank",
            Self::EmptyCollection => "this list must carry at least one entry",
            Self::TooManyEntries => "this list carries more than 256 entries",
            Self::UnknownService => "no service under services has this id",
            Self::UnknownOffering => "no offering under offerings has this id",
            Self::UnknownWindow => "no window under windows has this id",
            Self::UnknownLocation => "no location under locations has this id",
            Self::UnknownPool => "no resource pool under pools has this id",
            Self::UnknownTimezone => "this is not an IANA timezone name",
            Self::ResourceInManyPools => "this resource is already a member of another pool",
            Self::MismatchedReference => {
                "the window this names belongs to another offering or location"
            }
            Self::UnknownHolidaySet => "no holiday set under holidaySets has this id",
            Self::UnknownChannel => "this channel is not listed under channels",
            Self::MissingModeField => "the offering's mode needs this block",
            Self::WrongModeField => {
                "this belongs to the other scheduling mode, or to an offering that does not \
                 name it"
            }
            Self::MalformedValue => "expected a clock as HH:MM or a date as YYYY-MM-DD",
            Self::InvalidBound => "expected a whole number of at least 1",
            Self::InvertedRange => "the end does not come after the start",
            Self::LeadTimeBeyondHorizon => "the lead time is longer than the booking horizon",
            Self::PatternSpanTooLarge => {
                "the effective range spans more days than a weekly opening may cover"
            }
            Self::CalendarRefused => {
                "the calendar cannot expand this location's openings with its exceptions"
            }
            Self::InvalidBands => {
                "bands must rise strictly by upTo and each band must cost at least one unit"
            }
            Self::SubquotaOverdrawn => "the subquotas together exceed the window's units",
            Self::SharedSupplyUnpartitioned => {
                "this pool also backs an exact-time offering or an overlapping window"
            }
            Self::SupplyIdentifierCollision => "a resource pool and a window share this id",
            Self::UnsupportedHookProjection => {
                "this projection names a field the trigger does not publish"
            }
            Self::InvalidHookDestination => {
                "expected a destination id: a lowercase letter, then lowercase letters, \
                 digits, '-', or '_'"
            }
            Self::InvalidHookDeclaration => "the hook declarations break a shared hook rule",
            Self::LeftoverUnsupported => "this version reads no leftover policy",
        }
    }

    /// The change that fixes the finding (CFG-DIAG-2).
    #[must_use]
    pub const fn suggested_action(self) -> &'static str {
        match self {
            Self::UnsupportedApiVersion => "Write the apiVersion the format documents.",
            Self::UnsupportedKind => "Write the kind the format documents.",
            Self::InvalidIdentifier => "Write a lowercase identifier, such as front-desk.",
            Self::DuplicateIdentifier => "Remove the repeated entry, or give it its own id.",
            Self::InvalidBecause => "Write why this rule exists in at most 256 bytes.",
            Self::EmptyText => "Write the text, such as 2026.1.",
            Self::InvalidLabel => "Write a label of at most 128 bytes.",
            Self::EmptyCollection => "Add at least one entry.",
            Self::TooManyEntries => "Keep the list to at most 256 entries.",
            Self::UnknownService => "Name a service declared under services, or declare it.",
            Self::UnknownOffering => {
                "Name an offering declared under offerings in scheduling.yaml, or declare it."
            }
            Self::UnknownWindow => {
                "Publish a window with this id under windows in the records, or name one that \
                 exists."
            }
            Self::UnknownLocation => {
                "Name a location declared under locations in the records, or declare it."
            }
            Self::UnknownPool => {
                "Name a resource pool declared under pools in the records, or declare it."
            }
            Self::UnknownTimezone => "Write an IANA timezone name, such as Europe/Paris.",
            Self::ResourceInManyPools => {
                "List each resource in one pool only; give a second resource its own id."
            }
            Self::MismatchedReference => {
                "Make the window's offering and location match the offering that names it."
            }
            Self::UnknownHolidaySet => {
                "Name a holiday set declared under holidaySets, or declare it."
            }
            Self::UnknownChannel => "Add the channel to channels, or use a channel listed there.",
            Self::MissingModeField => {
                "Add exactTime for an exact-time offering, or arrival for an arrival-window \
                 offering."
            }
            Self::WrongModeField => {
                "Remove the block, or change the offering's mode to the one it belongs to."
            }
            Self::MalformedValue => {
                "Write the clock as HH:MM, such as 09:30, or the date as YYYY-MM-DD, such as \
                 2026-03-02."
            }
            Self::InvalidBound => "Write a whole number of at least 1.",
            Self::InvertedRange => "Make the end later than the start.",
            Self::LeadTimeBeyondHorizon => "Shorten leadTimeMinutes or lengthen horizonDays.",
            Self::PatternSpanTooLarge => {
                "Split the opening into consecutive openings with shorter effective ranges."
            }
            Self::CalendarRefused => {
                "Check the location's openings and the times of its dated exceptions."
            }
            Self::InvalidBands => {
                "List the bands in increasing upTo order, each with units of at least 1."
            }
            Self::SubquotaOverdrawn => "Lower the subquota units, or raise the window's units.",
            Self::SharedSupplyUnpartitioned => {
                "Back the window with a pool of its own, or move the overlapping windows apart."
            }
            Self::SupplyIdentifierCollision => "Rename the window or the pool so the ids differ.",
            Self::UnsupportedHookProjection => {
                "Project only the fields the trigger's observer projection documents."
            }
            Self::InvalidHookDestination => {
                "Name a destination the runtime configuration declares under \
                 destinations.hooks."
            }
            Self::InvalidHookDeclaration => "Give each hook its own id and a supported handler.",
            Self::LeftoverUnsupported => "Remove leftover; nothing reads it in this version.",
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

/// One policy check finding: the place that failed, and why.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchedulingDiagnostic {
    /// The document `path` points into.
    pub area: FindingArea,
    /// RFC 6901 pointer into the document as written; `""` is the root.
    pub path: String,
    pub reason: PolicyCheckReason,
}

impl SchedulingDiagnostic {
    /// A finding in the project file.
    pub fn new(path: impl Into<String>, reason: PolicyCheckReason) -> Self {
        Self::in_area(FindingArea::Project, path, reason)
    }

    /// A finding in the environment records.
    pub fn records(path: impl Into<String>, reason: PolicyCheckReason) -> Self {
        Self::in_area(FindingArea::Records, path, reason)
    }

    pub fn in_area(area: FindingArea, path: impl Into<String>, reason: PolicyCheckReason) -> Self {
        Self {
            area,
            path: path.into(),
            reason,
        }
    }

    /// The `scheduling.<area>.<condition>` code (CFG-DIAG-3).
    #[must_use]
    pub fn code(&self) -> String {
        format!("scheduling.{}.{}", self.area.as_str(), self.reason.as_str())
    }

    /// The same finding placed in the document of `area`, as when a window
    /// check runs over the environment records rather than the project.
    #[must_use]
    pub fn with_area(mut self, area: FindingArea) -> Self {
        self.area = area;
        self
    }

    /// The same finding with its pointer placed below `prefix`, as when the
    /// records are the `facts` block of a fixture.
    #[must_use]
    pub fn under(mut self, prefix: &str) -> Self {
        self.path = format!("{prefix}{}", self.path);
        self
    }

    /// This finding as a CFG-DIAG-1 error placed in `document`: at the value
    /// the pointer names or, for a member the file does not write, at the
    /// key of the nearest enclosing member it does write.
    #[must_use]
    pub fn to_diagnostic(&self, document: &Document) -> Diagnostic {
        let code = self.code();
        let message = self.reason.message();
        let action = self.reason.suggested_action();
        if document.span_of(&self.path).is_some() {
            return document.diagnostic_at_value(
                Severity::Error,
                &code,
                &self.path,
                message,
                action,
            );
        }
        let mut ancestor = self.path.as_str();
        while let Some(index) = ancestor.rfind('/') {
            ancestor = &ancestor[..index];
            if document.span_of(ancestor).is_some() {
                let mut diagnostic =
                    document.diagnostic_at_key(Severity::Error, &code, ancestor, message, action);
                diagnostic.path.clone_from(&self.path);
                return diagnostic;
            }
        }
        document.diagnostic_at_value(Severity::Error, &code, &self.path, message, action)
    }
}

impl SchedulingDiagnostic {
    /// This finding as a CFG-DIAG-1 error with no position, naming the kind
    /// of the document it points into: a finding about a document the
    /// caller holds no reading of, such as a project offering's reference
    /// found while checking the records alone.
    #[must_use]
    pub fn to_unplaced_diagnostic(&self) -> Diagnostic {
        let mut diagnostic = Diagnostic::error(
            self.code(),
            self.path.clone(),
            self.reason.message(),
            self.reason.suggested_action(),
        );
        diagnostic.artifact = Some(self.area.kind().to_owned());
        diagnostic
    }
}

impl fmt::Display for SchedulingDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.path, self.code())
    }
}

/// Every finding about one document, after the document's own warnings, as
/// the report a check command prints.
#[must_use]
pub fn findings_report(document: &Document, findings: &[SchedulingDiagnostic]) -> Report {
    let mut report = document.warnings();
    for finding in findings {
        report.push(finding.to_diagnostic(document));
    }
    report
}

#[cfg(test)]
mod tests {
    use registry_platform_yaml::{EnvelopeRule, Expect, FormatSpec};

    use super::*;

    const ALL_REASONS: [PolicyCheckReason; 35] = [
        PolicyCheckReason::UnsupportedApiVersion,
        PolicyCheckReason::UnsupportedKind,
        PolicyCheckReason::InvalidIdentifier,
        PolicyCheckReason::DuplicateIdentifier,
        PolicyCheckReason::InvalidBecause,
        PolicyCheckReason::EmptyText,
        PolicyCheckReason::InvalidLabel,
        PolicyCheckReason::EmptyCollection,
        PolicyCheckReason::TooManyEntries,
        PolicyCheckReason::UnknownService,
        PolicyCheckReason::UnknownOffering,
        PolicyCheckReason::UnknownWindow,
        PolicyCheckReason::UnknownLocation,
        PolicyCheckReason::UnknownPool,
        PolicyCheckReason::UnknownTimezone,
        PolicyCheckReason::ResourceInManyPools,
        PolicyCheckReason::MismatchedReference,
        PolicyCheckReason::UnknownHolidaySet,
        PolicyCheckReason::UnknownChannel,
        PolicyCheckReason::MissingModeField,
        PolicyCheckReason::WrongModeField,
        PolicyCheckReason::MalformedValue,
        PolicyCheckReason::InvalidBound,
        PolicyCheckReason::InvertedRange,
        PolicyCheckReason::LeadTimeBeyondHorizon,
        PolicyCheckReason::PatternSpanTooLarge,
        PolicyCheckReason::CalendarRefused,
        PolicyCheckReason::InvalidBands,
        PolicyCheckReason::SubquotaOverdrawn,
        PolicyCheckReason::SharedSupplyUnpartitioned,
        PolicyCheckReason::SupplyIdentifierCollision,
        PolicyCheckReason::UnsupportedHookProjection,
        PolicyCheckReason::InvalidHookDestination,
        PolicyCheckReason::InvalidHookDeclaration,
        PolicyCheckReason::LeftoverUnsupported,
    ];

    #[test]
    fn reasons_render_as_closed_slugs() {
        assert_eq!(
            PolicyCheckReason::SharedSupplyUnpartitioned.as_str(),
            "shared-supply-unpartitioned"
        );
        assert_eq!(
            SchedulingDiagnostic::records(
                "/windows/0/offering",
                PolicyCheckReason::UnknownOffering
            )
            .to_string(),
            "/windows/0/offering: scheduling.records.unknown-offering"
        );
        assert_eq!(
            SchedulingDiagnostic::new("/services/0/id", PolicyCheckReason::InvalidIdentifier)
                .code(),
            "scheduling.project.invalid-identifier"
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

    #[test]
    fn every_reason_names_its_fix() {
        let mut slugs = std::collections::BTreeSet::new();
        for reason in ALL_REASONS {
            assert!(slugs.insert(reason.as_str()), "{reason}");
            assert!(!reason.message().is_empty(), "{reason}");
            let action = reason.suggested_action();
            assert!(
                action.ends_with('.') && action.starts_with(char::is_uppercase),
                "{reason}"
            );
        }
    }

    #[test]
    fn a_finding_on_an_absent_member_is_placed_at_its_nearest_written_parent() {
        const FORMAT: FormatSpec<'static> = FormatSpec {
            kind: "Test",
            envelope: EnvelopeRule::Exempt { reason: "test" },
            removed_keys: &[],
        };
        let document = registry_platform_yaml::read_document(
            "scheduling.yaml",
            b"offerings:\n  - id: one\n",
            &Expect::one(&FORMAT),
        )
        .expect("the document reads");
        let diagnostic = SchedulingDiagnostic::new(
            "/offerings/0/exactTime",
            PolicyCheckReason::MissingModeField,
        )
        .to_diagnostic(&document);
        assert_eq!(diagnostic.code, "scheduling.project.missing-mode-field");
        assert_eq!(diagnostic.path, "/offerings/0/exactTime");
        let source = diagnostic.source.expect("the finding is placed");
        assert_eq!(source.line, Some(2));
    }
}
