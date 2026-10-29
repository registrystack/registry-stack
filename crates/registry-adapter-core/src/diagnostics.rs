// SPDX-License-Identifier: Apache-2.0

//! The closed configuration-diagnostic vocabulary of the Adapter
//! (`adapter.*` codes, CFG-DIAG-3).
//!
//! Every authoring check in this crate reports one of these codes, in the one
//! diagnostic shape (`registry-platform-yaml`'s [`Diagnostic`]). The codes
//! are value-free: a message built beside a code names keys, accepted forms,
//! and bounds, and never repeats a value read from a document (CFG-SEC-3).
//! The middle segment names the artifact the finding points into, following
//! the same `<product>.<area>.<condition>` grammar Scheduling uses.

use registry_platform_yaml::Diagnostic;

/// Every configuration diagnostic code the Adapter can report, in
/// code-string order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum CheckCode {
    // adapter.auth.*
    AuthKindMismatch,
    AuthNoneNotLoopback,
    // adapter.envelope.*
    EnvelopeInvalidPlaceholder,
    // adapter.fixture.*
    FixtureUnknownEndpoint,
    FixtureUnknownIntercept,
    // adapter.pack.*
    PackDigestPinRequired,
    PackEndpointComponentInvalid,
    PackGraphQlQueryRequired,
    PackReservedHeaderName,
    PackUnknownScript,
    // adapter.profile.*
    ProfileProblemEnvelopeMissingCodeSlot,
    ProfileRequestEnvelopeMissingRecordSlot,
    ProfileResponseEnvelopeMissingResultSlot,
    ProfileUnknownSlot,
    // adapter.project.*
    ProjectDuplicateRouteId,
    ProjectUnknownOperation,
    ProjectUnknownRecordType,
    ProjectUnknownRoute,
    ProjectUnknownTemplate,
    ProjectUpstreamBudgetExceeded,
    // adapter.route.*
    RouteDirectCycle,
    RouteDirectDepthExceeded,
    RouteFromNotDirect,
    RouteMaximumItemsRequired,
    RouteMaximumIterationsRequired,
    RouteMultipleNonSafeSends,
    RouteNonSafeSendInSplit,
    RoutePredicateAmbiguous,
    RoutePredicateLanguageRequired,
    RouteRedeliveryOverNonSafeSend,
    RouteRetryWhileWithoutRedeliveries,
    RouteUncatchableClause,
    RouteUnknownDirectTarget,
    RouteUnknownEndpoint,
    RouteWriteWithoutIdempotency,
    // adapter.runtime.*
    RuntimeInsecureOrigin,
    RuntimeMissingEndpoint,
    RuntimeUnknownEndpoint,
}

impl CheckCode {
    /// The complete closed vocabulary, in code-string order.
    pub const ALL: &'static [Self] = &[
        Self::AuthKindMismatch,
        Self::AuthNoneNotLoopback,
        Self::EnvelopeInvalidPlaceholder,
        Self::FixtureUnknownEndpoint,
        Self::FixtureUnknownIntercept,
        Self::PackDigestPinRequired,
        Self::PackEndpointComponentInvalid,
        Self::PackGraphQlQueryRequired,
        Self::PackReservedHeaderName,
        Self::PackUnknownScript,
        Self::ProfileProblemEnvelopeMissingCodeSlot,
        Self::ProfileRequestEnvelopeMissingRecordSlot,
        Self::ProfileResponseEnvelopeMissingResultSlot,
        Self::ProfileUnknownSlot,
        Self::ProjectDuplicateRouteId,
        Self::ProjectUnknownOperation,
        Self::ProjectUnknownRecordType,
        Self::ProjectUnknownRoute,
        Self::ProjectUnknownTemplate,
        Self::ProjectUpstreamBudgetExceeded,
        Self::RouteDirectCycle,
        Self::RouteDirectDepthExceeded,
        Self::RouteFromNotDirect,
        Self::RouteMaximumItemsRequired,
        Self::RouteMaximumIterationsRequired,
        Self::RouteMultipleNonSafeSends,
        Self::RouteNonSafeSendInSplit,
        Self::RoutePredicateAmbiguous,
        Self::RoutePredicateLanguageRequired,
        Self::RouteRedeliveryOverNonSafeSend,
        Self::RouteRetryWhileWithoutRedeliveries,
        Self::RouteUncatchableClause,
        Self::RouteUnknownDirectTarget,
        Self::RouteUnknownEndpoint,
        Self::RouteWriteWithoutIdempotency,
        Self::RuntimeInsecureOrigin,
        Self::RuntimeMissingEndpoint,
        Self::RuntimeUnknownEndpoint,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::AuthKindMismatch => "adapter.auth.kind-mismatch",
            Self::AuthNoneNotLoopback => "adapter.auth.none-not-loopback",
            Self::EnvelopeInvalidPlaceholder => "adapter.envelope.invalid-placeholder",
            Self::FixtureUnknownEndpoint => "adapter.fixture.unknown-endpoint",
            Self::FixtureUnknownIntercept => "adapter.fixture.unknown-intercept",
            Self::PackDigestPinRequired => "adapter.pack.digest-pin-required",
            Self::PackEndpointComponentInvalid => "adapter.pack.endpoint-component-invalid",
            Self::PackGraphQlQueryRequired => "adapter.pack.graphql-query-required",
            Self::PackReservedHeaderName => "adapter.pack.reserved-header-name",
            Self::PackUnknownScript => "adapter.pack.unknown-script",
            Self::ProfileProblemEnvelopeMissingCodeSlot => {
                "adapter.profile.problem-envelope-missing-code-slot"
            }
            Self::ProfileRequestEnvelopeMissingRecordSlot => {
                "adapter.profile.request-envelope-missing-record-slot"
            }
            Self::ProfileResponseEnvelopeMissingResultSlot => {
                "adapter.profile.response-envelope-missing-result-slot"
            }
            Self::ProfileUnknownSlot => "adapter.profile.unknown-slot",
            Self::ProjectDuplicateRouteId => "adapter.project.duplicate-route-id",
            Self::ProjectUnknownOperation => "adapter.project.unknown-operation",
            Self::ProjectUnknownRecordType => "adapter.project.unknown-record-type",
            Self::ProjectUnknownRoute => "adapter.project.unknown-route",
            Self::ProjectUnknownTemplate => "adapter.project.unknown-template",
            Self::ProjectUpstreamBudgetExceeded => "adapter.project.upstream-budget-exceeded",
            Self::RouteDirectCycle => "adapter.route.direct-cycle",
            Self::RouteDirectDepthExceeded => "adapter.route.direct-depth-exceeded",
            Self::RouteFromNotDirect => "adapter.route.from-not-direct",
            Self::RouteMaximumItemsRequired => "adapter.route.maximum-items-required",
            Self::RouteMaximumIterationsRequired => "adapter.route.maximum-iterations-required",
            Self::RouteMultipleNonSafeSends => "adapter.route.multiple-non-safe-sends",
            Self::RouteNonSafeSendInSplit => "adapter.route.non-safe-send-in-split",
            Self::RoutePredicateAmbiguous => "adapter.route.predicate-ambiguous",
            Self::RoutePredicateLanguageRequired => "adapter.route.predicate-language-required",
            Self::RouteRedeliveryOverNonSafeSend => "adapter.route.redelivery-over-non-safe-send",
            Self::RouteRetryWhileWithoutRedeliveries => {
                "adapter.route.retry-while-without-redeliveries"
            }
            Self::RouteUncatchableClause => "adapter.route.uncatchable-clause",
            Self::RouteUnknownDirectTarget => "adapter.route.unknown-direct-target",
            Self::RouteUnknownEndpoint => "adapter.route.unknown-endpoint",
            Self::RouteWriteWithoutIdempotency => "adapter.route.write-without-idempotency",
            Self::RuntimeInsecureOrigin => "adapter.runtime.insecure-origin",
            Self::RuntimeMissingEndpoint => "adapter.runtime.missing-endpoint",
            Self::RuntimeUnknownEndpoint => "adapter.runtime.unknown-endpoint",
        }
    }

    /// The artifact kind whose document this finding points into; the middle
    /// segment of the code names it.
    #[must_use]
    pub const fn artifact(self) -> &'static str {
        match self {
            Self::AuthKindMismatch
            | Self::AuthNoneNotLoopback
            | Self::RuntimeInsecureOrigin
            | Self::RuntimeMissingEndpoint
            | Self::RuntimeUnknownEndpoint => crate::naming::ADAPTER_RUNTIME_KIND,
            Self::EnvelopeInvalidPlaceholder
            | Self::ProfileProblemEnvelopeMissingCodeSlot
            | Self::ProfileRequestEnvelopeMissingRecordSlot
            | Self::ProfileResponseEnvelopeMissingResultSlot
            | Self::ProfileUnknownSlot => crate::naming::ADAPTER_PROFILE_KIND,
            Self::FixtureUnknownEndpoint | Self::FixtureUnknownIntercept => {
                crate::naming::ADAPTER_FIXTURE_KIND
            }
            Self::PackDigestPinRequired
            | Self::PackEndpointComponentInvalid
            | Self::PackGraphQlQueryRequired
            | Self::PackReservedHeaderName
            | Self::PackUnknownScript
            | Self::RouteDirectCycle
            | Self::RouteDirectDepthExceeded
            | Self::RouteFromNotDirect
            | Self::RouteMaximumItemsRequired
            | Self::RouteMaximumIterationsRequired
            | Self::RouteMultipleNonSafeSends
            | Self::RouteNonSafeSendInSplit
            | Self::RoutePredicateAmbiguous
            | Self::RoutePredicateLanguageRequired
            | Self::RouteRedeliveryOverNonSafeSend
            | Self::RouteRetryWhileWithoutRedeliveries
            | Self::RouteUncatchableClause
            | Self::RouteUnknownDirectTarget
            | Self::RouteUnknownEndpoint
            | Self::RouteWriteWithoutIdempotency => crate::naming::ADAPTER_PACK_KIND,
            Self::ProjectDuplicateRouteId
            | Self::ProjectUnknownOperation
            | Self::ProjectUnknownRecordType
            | Self::ProjectUnknownRoute
            | Self::ProjectUnknownTemplate
            | Self::ProjectUpstreamBudgetExceeded => crate::naming::ADAPTER_PROJECT_KIND,
        }
    }

    /// Resolve a code string back to its variant, or `None` for any string
    /// outside the closed vocabulary.
    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.code() == code)
    }
}

/// One authoring-check finding: an error diagnostic carrying a closed
/// `adapter.*` code, its artifact kind, an RFC 6901 pointer, and a value-free
/// message with a suggested action.
#[must_use]
pub fn finding(code: CheckCode, path: &str, message: &str, action: &str) -> Diagnostic {
    let mut diagnostic = Diagnostic::error(code.code(), path, message, action);
    diagnostic.artifact = Some(code.artifact().to_string());
    diagnostic
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip() {
        for code in CheckCode::ALL {
            assert_eq!(CheckCode::from_code(code.code()), Some(*code));
        }
        assert_eq!(CheckCode::from_code("adapter.route.invented"), None);
    }

    #[test]
    fn vocabulary_is_sorted_and_complete() {
        let mut codes: Vec<&str> = CheckCode::ALL.iter().map(|c| c.code()).collect();
        let expected = codes.clone();
        codes.sort_unstable();
        assert_eq!(codes, expected, "ALL must stay in code-string order");
        assert_eq!(
            codes.len(),
            codes
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
        );
    }

    #[test]
    fn every_code_carries_the_adapter_prefix_and_three_segments() {
        for code in CheckCode::ALL {
            let mut segments = code.code().split('.');
            assert_eq!(segments.next(), Some("adapter"));
            assert!(segments.next().is_some(), "{} needs an area", code.code());
            assert!(
                segments.next().is_some(),
                "{} needs a condition",
                code.code()
            );
            assert_eq!(segments.next(), None);
        }
    }

    #[test]
    fn findings_are_value_free_errors_with_an_artifact() {
        let diagnostic = finding(
            CheckCode::RouteMaximumItemsRequired,
            "/routeTemplates/0/steps/1",
            "the split declares no maximumItems bound",
            "Declare maximumItems on every split step.",
        );
        assert_eq!(diagnostic.severity, registry_platform_yaml::Severity::Error);
        assert_eq!(diagnostic.artifact.as_deref(), Some("AdapterPack"));
        assert!(diagnostic.message.contains("maximumItems"));
    }
}
