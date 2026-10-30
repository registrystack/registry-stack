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
    FixtureCredentialRecorded,
    FixtureEmptyUpstream,
    FixtureResponseSchema,
    FixtureUncoveredExchange,
    FixtureUnknownEndpoint,
    FixtureUnknownIntercept,
    FixtureUnknownOperation,
    FixtureUnknownProblemCode,
    // adapter.pack.*
    PackCodeMapEntryNotScalar,
    PackCodeMapUnreferenced,
    PackDigestPinRequired,
    PackDuplicateHeaderName,
    PackEndpointComponentInvalid,
    PackEntrypointParameter,
    PackGraphQlOperationUnknown,
    PackGraphQlQueryInvalid,
    PackGraphQlQueryRequired,
    PackInvalidHeaderName,
    PackMapParameterMisplaced,
    PackReservedHeaderName,
    PackScriptUncompilable,
    PackTooManyHeaders,
    PackTransportRefusedHeader,
    PackUnknownScript,
    PackUnknownTemplateParameter,
    // adapter.profile.*
    ProfileInvalidPath,
    ProfilePageSizeDefaultOutOfBounds,
    ProfileProblemClassDuplicate,
    ProfileProblemClassUnresolved,
    ProfileProblemEnvelopeMissingCodeSlot,
    ProfileProblemEnvelopeUncompilable,
    ProfileReadOnlyMethod,
    ProfileRecordIdParameterMissing,
    ProfileRequestEnvelopeMissingRecordSlot,
    ProfileResponseEnvelopeMissingResultSlot,
    ProfileResponseEnvelopeUncompilable,
    ProfileUnknownRecordIdParameter,
    ProfileUnknownRecordTypeParameter,
    ProfileUnknownSlot,
    ProfileUnresolvedPathParameter,
    // adapter.project.*
    ProjectAccessProfileScopesEmpty,
    ProjectDuplicateRouteId,
    ProjectFilterParameterCollision,
    ProjectParameterTypeMismatch,
    ProjectParameterizedPartUnbound,
    ProjectPinDigestMismatch,
    ProjectPinVersionMismatch,
    ProjectRequiredParameterUnbound,
    ProjectTemplateNotInstantiated,
    ProjectUnknownFilterField,
    ProjectUnknownOperation,
    ProjectUnknownRecordType,
    ProjectUnknownRoute,
    ProjectUnknownTemplate,
    ProjectUnknownTemplateParameter,
    ProjectUpstreamBudgetExceeded,
    // adapter.route.*
    RouteCodeMapUnknown,
    RouteConvertShape,
    RouteDirectCycle,
    RouteDirectDepthExceeded,
    RouteEmptyExceptionList,
    RouteErrorHandlerShape,
    RouteFromNotDirect,
    RouteGraphQlSendMembers,
    RouteHandledAndContinued,
    RouteHttpUriMembers,
    RouteInvalidHeaderName,
    RouteInvalidPath,
    RouteInvalidQueryKey,
    RouteInvalidStatusCodeRange,
    RouteLoopCountAboveBound,
    RouteMaximumItemsRequired,
    RouteMaximumIterationsRequired,
    RouteMultipleNonSafeSends,
    RouteNestingDepthExceeded,
    RouteNonSafeSendInSplit,
    RouteOkRangeCoversUnauthorized,
    RoutePathParameterMismatch,
    RoutePredicateAmbiguous,
    RoutePredicateLanguageRequired,
    RouteReadUnsafeSend,
    RouteRedeliveryOverNonSafeSend,
    RouteRedeliveryWithoutUpstreamSend,
    RouteReservedHeaderName,
    RouteRetryWhileWithoutRedeliveries,
    RouteStopOnExceptionExclusive,
    RouteThrowExceptionClass,
    RouteThrowExceptionMessage,
    RouteUncatchableClause,
    RouteUnknownDirectTarget,
    RouteUnknownEndpoint,
    RouteUnknownHeader,
    RouteUnknownOperation,
    RouteWriteWithoutIdempotency,
    // adapter.runtime.*
    RuntimeInsecureOrigin,
    RuntimeInvalidOrigin,
    RuntimeInvalidOutboundTls,
    RuntimeMissingEndpoint,
    RuntimeUnknownEndpoint,
    RuntimeUnknownTrustProfile,
}

impl CheckCode {
    /// The complete closed vocabulary, in code-string order.
    pub const ALL: &'static [Self] = &[
        Self::AuthKindMismatch,
        Self::AuthNoneNotLoopback,
        Self::EnvelopeInvalidPlaceholder,
        Self::FixtureCredentialRecorded,
        Self::FixtureEmptyUpstream,
        Self::FixtureResponseSchema,
        Self::FixtureUncoveredExchange,
        Self::FixtureUnknownEndpoint,
        Self::FixtureUnknownIntercept,
        Self::FixtureUnknownOperation,
        Self::FixtureUnknownProblemCode,
        Self::PackCodeMapEntryNotScalar,
        Self::PackCodeMapUnreferenced,
        Self::PackDigestPinRequired,
        Self::PackDuplicateHeaderName,
        Self::PackEndpointComponentInvalid,
        Self::PackEntrypointParameter,
        Self::PackGraphQlOperationUnknown,
        Self::PackGraphQlQueryInvalid,
        Self::PackGraphQlQueryRequired,
        Self::PackInvalidHeaderName,
        Self::PackMapParameterMisplaced,
        Self::PackReservedHeaderName,
        Self::PackScriptUncompilable,
        Self::PackTooManyHeaders,
        Self::PackTransportRefusedHeader,
        Self::PackUnknownScript,
        Self::PackUnknownTemplateParameter,
        Self::ProfileInvalidPath,
        Self::ProfilePageSizeDefaultOutOfBounds,
        Self::ProfileProblemClassDuplicate,
        Self::ProfileProblemClassUnresolved,
        Self::ProfileProblemEnvelopeMissingCodeSlot,
        Self::ProfileProblemEnvelopeUncompilable,
        Self::ProfileReadOnlyMethod,
        Self::ProfileRecordIdParameterMissing,
        Self::ProfileRequestEnvelopeMissingRecordSlot,
        Self::ProfileResponseEnvelopeMissingResultSlot,
        Self::ProfileResponseEnvelopeUncompilable,
        Self::ProfileUnknownRecordIdParameter,
        Self::ProfileUnknownRecordTypeParameter,
        Self::ProfileUnknownSlot,
        Self::ProfileUnresolvedPathParameter,
        Self::ProjectAccessProfileScopesEmpty,
        Self::ProjectDuplicateRouteId,
        Self::ProjectFilterParameterCollision,
        Self::ProjectParameterTypeMismatch,
        Self::ProjectParameterizedPartUnbound,
        Self::ProjectPinDigestMismatch,
        Self::ProjectPinVersionMismatch,
        Self::ProjectRequiredParameterUnbound,
        Self::ProjectTemplateNotInstantiated,
        Self::ProjectUnknownFilterField,
        Self::ProjectUnknownOperation,
        Self::ProjectUnknownRecordType,
        Self::ProjectUnknownRoute,
        Self::ProjectUnknownTemplate,
        Self::ProjectUnknownTemplateParameter,
        Self::ProjectUpstreamBudgetExceeded,
        Self::RouteCodeMapUnknown,
        Self::RouteConvertShape,
        Self::RouteDirectCycle,
        Self::RouteDirectDepthExceeded,
        Self::RouteEmptyExceptionList,
        Self::RouteErrorHandlerShape,
        Self::RouteFromNotDirect,
        Self::RouteGraphQlSendMembers,
        Self::RouteHandledAndContinued,
        Self::RouteHttpUriMembers,
        Self::RouteInvalidHeaderName,
        Self::RouteInvalidPath,
        Self::RouteInvalidQueryKey,
        Self::RouteInvalidStatusCodeRange,
        Self::RouteLoopCountAboveBound,
        Self::RouteMaximumItemsRequired,
        Self::RouteMaximumIterationsRequired,
        Self::RouteMultipleNonSafeSends,
        Self::RouteNestingDepthExceeded,
        Self::RouteNonSafeSendInSplit,
        Self::RouteOkRangeCoversUnauthorized,
        Self::RoutePathParameterMismatch,
        Self::RoutePredicateAmbiguous,
        Self::RoutePredicateLanguageRequired,
        Self::RouteReadUnsafeSend,
        Self::RouteRedeliveryOverNonSafeSend,
        Self::RouteRedeliveryWithoutUpstreamSend,
        Self::RouteReservedHeaderName,
        Self::RouteRetryWhileWithoutRedeliveries,
        Self::RouteStopOnExceptionExclusive,
        Self::RouteThrowExceptionClass,
        Self::RouteThrowExceptionMessage,
        Self::RouteUncatchableClause,
        Self::RouteUnknownDirectTarget,
        Self::RouteUnknownEndpoint,
        Self::RouteUnknownHeader,
        Self::RouteUnknownOperation,
        Self::RouteWriteWithoutIdempotency,
        Self::RuntimeInsecureOrigin,
        Self::RuntimeInvalidOrigin,
        Self::RuntimeInvalidOutboundTls,
        Self::RuntimeMissingEndpoint,
        Self::RuntimeUnknownEndpoint,
        Self::RuntimeUnknownTrustProfile,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::AuthKindMismatch => "adapter.auth.kind-mismatch",
            Self::AuthNoneNotLoopback => "adapter.auth.none-not-loopback",
            Self::EnvelopeInvalidPlaceholder => "adapter.envelope.invalid-placeholder",
            Self::FixtureCredentialRecorded => "adapter.fixture.credential-recorded",
            Self::FixtureEmptyUpstream => "adapter.fixture.empty-upstream",
            Self::FixtureResponseSchema => "adapter.fixture.response-schema",
            Self::FixtureUncoveredExchange => "adapter.fixture.uncovered-exchange",
            Self::FixtureUnknownEndpoint => "adapter.fixture.unknown-endpoint",
            Self::FixtureUnknownIntercept => "adapter.fixture.unknown-intercept",
            Self::FixtureUnknownOperation => "adapter.fixture.unknown-operation",
            Self::FixtureUnknownProblemCode => "adapter.fixture.unknown-problem-code",
            Self::PackCodeMapEntryNotScalar => "adapter.pack.code-map-entry-not-scalar",
            Self::PackCodeMapUnreferenced => "adapter.pack.code-map-unreferenced",
            Self::PackDigestPinRequired => "adapter.pack.digest-pin-required",
            Self::PackDuplicateHeaderName => "adapter.pack.duplicate-header-name",
            Self::PackEndpointComponentInvalid => "adapter.pack.endpoint-component-invalid",
            Self::PackEntrypointParameter => "adapter.pack.entrypoint-parameter",
            Self::PackGraphQlOperationUnknown => "adapter.pack.graphql-operation-unknown",
            Self::PackGraphQlQueryInvalid => "adapter.pack.graphql-query-invalid",
            Self::PackGraphQlQueryRequired => "adapter.pack.graphql-query-required",
            Self::PackInvalidHeaderName => "adapter.pack.invalid-header-name",
            Self::PackMapParameterMisplaced => "adapter.pack.map-parameter-misplaced",
            Self::PackReservedHeaderName => "adapter.pack.reserved-header-name",
            Self::PackScriptUncompilable => "adapter.pack.script-uncompilable",
            Self::PackTooManyHeaders => "adapter.pack.too-many-headers",
            Self::PackTransportRefusedHeader => "adapter.pack.transport-refused-header",
            Self::PackUnknownScript => "adapter.pack.unknown-script",
            Self::PackUnknownTemplateParameter => "adapter.pack.unknown-template-parameter",
            Self::ProfileInvalidPath => "adapter.profile.invalid-path",
            Self::ProfilePageSizeDefaultOutOfBounds => {
                "adapter.profile.page-size-default-out-of-bounds"
            }
            Self::ProfileProblemClassDuplicate => "adapter.profile.problem-class-duplicate",
            Self::ProfileProblemClassUnresolved => "adapter.profile.problem-class-unresolved",
            Self::ProfileProblemEnvelopeMissingCodeSlot => {
                "adapter.profile.problem-envelope-missing-code-slot"
            }
            Self::ProfileProblemEnvelopeUncompilable => {
                "adapter.profile.problem-envelope-uncompilable"
            }
            Self::ProfileReadOnlyMethod => "adapter.profile.read-only-method",
            Self::ProfileRecordIdParameterMissing => "adapter.profile.record-id-parameter-missing",
            Self::ProfileRequestEnvelopeMissingRecordSlot => {
                "adapter.profile.request-envelope-missing-record-slot"
            }
            Self::ProfileResponseEnvelopeMissingResultSlot => {
                "adapter.profile.response-envelope-missing-result-slot"
            }
            Self::ProfileResponseEnvelopeUncompilable => {
                "adapter.profile.response-envelope-uncompilable"
            }
            Self::ProfileUnknownRecordIdParameter => "adapter.profile.unknown-record-id-parameter",
            Self::ProfileUnknownRecordTypeParameter => {
                "adapter.profile.unknown-record-type-parameter"
            }
            Self::ProfileUnknownSlot => "adapter.profile.unknown-slot",
            Self::ProfileUnresolvedPathParameter => "adapter.profile.unresolved-path-parameter",
            Self::ProjectAccessProfileScopesEmpty => "adapter.project.access-profile-scopes-empty",
            Self::ProjectDuplicateRouteId => "adapter.project.duplicate-route-id",
            Self::ProjectFilterParameterCollision => "adapter.project.filter-parameter-collision",
            Self::ProjectParameterTypeMismatch => "adapter.project.parameter-type-mismatch",
            Self::ProjectParameterizedPartUnbound => "adapter.project.parameterized-part-unbound",
            Self::ProjectPinDigestMismatch => "adapter.project.pin-digest-mismatch",
            Self::ProjectPinVersionMismatch => "adapter.project.pin-version-mismatch",
            Self::ProjectRequiredParameterUnbound => "adapter.project.required-parameter-unbound",
            Self::ProjectTemplateNotInstantiated => "adapter.project.template-not-instantiated",
            Self::ProjectUnknownFilterField => "adapter.project.unknown-filter-field",
            Self::ProjectUnknownOperation => "adapter.project.unknown-operation",
            Self::ProjectUnknownRecordType => "adapter.project.unknown-record-type",
            Self::ProjectUnknownRoute => "adapter.project.unknown-route",
            Self::ProjectUnknownTemplate => "adapter.project.unknown-template",
            Self::ProjectUnknownTemplateParameter => "adapter.project.unknown-template-parameter",
            Self::ProjectUpstreamBudgetExceeded => "adapter.project.upstream-budget-exceeded",
            Self::RouteCodeMapUnknown => "adapter.route.code-map-unknown",
            Self::RouteConvertShape => "adapter.route.convert-shape",
            Self::RouteDirectCycle => "adapter.route.direct-cycle",
            Self::RouteDirectDepthExceeded => "adapter.route.direct-depth-exceeded",
            Self::RouteEmptyExceptionList => "adapter.route.empty-exception-list",
            Self::RouteErrorHandlerShape => "adapter.route.error-handler-shape",
            Self::RoutePathParameterMismatch => "adapter.route.path-parameter-mismatch",
            Self::RouteFromNotDirect => "adapter.route.from-not-direct",
            Self::RouteGraphQlSendMembers => "adapter.route.graphql-send-members",
            Self::RouteHandledAndContinued => "adapter.route.handled-and-continued",
            Self::RouteHttpUriMembers => "adapter.route.http-uri-members",
            Self::RouteInvalidHeaderName => "adapter.route.invalid-header-name",
            Self::RouteInvalidPath => "adapter.route.invalid-path",
            Self::RouteInvalidQueryKey => "adapter.route.invalid-query-key",
            Self::RouteInvalidStatusCodeRange => "adapter.route.invalid-status-code-range",
            Self::RouteLoopCountAboveBound => "adapter.route.loop-count-above-bound",
            Self::RouteMaximumItemsRequired => "adapter.route.maximum-items-required",
            Self::RouteMaximumIterationsRequired => "adapter.route.maximum-iterations-required",
            Self::RouteMultipleNonSafeSends => "adapter.route.multiple-non-safe-sends",
            Self::RouteNestingDepthExceeded => "adapter.route.nesting-depth-exceeded",
            Self::RouteNonSafeSendInSplit => "adapter.route.non-safe-send-in-split",
            Self::RouteOkRangeCoversUnauthorized => "adapter.route.ok-range-covers-unauthorized",
            Self::RoutePredicateAmbiguous => "adapter.route.predicate-ambiguous",
            Self::RoutePredicateLanguageRequired => "adapter.route.predicate-language-required",
            Self::RouteReadUnsafeSend => "adapter.route.read-unsafe-send",
            Self::RouteRedeliveryOverNonSafeSend => "adapter.route.redelivery-over-non-safe-send",
            Self::RouteRedeliveryWithoutUpstreamSend => {
                "adapter.route.redelivery-without-upstream-send"
            }
            Self::RouteReservedHeaderName => "adapter.route.reserved-header-name",
            Self::RouteRetryWhileWithoutRedeliveries => {
                "adapter.route.retry-while-without-redeliveries"
            }
            Self::RouteStopOnExceptionExclusive => "adapter.route.stop-on-exception-exclusive",
            Self::RouteThrowExceptionClass => "adapter.route.throw-exception-class",
            Self::RouteThrowExceptionMessage => "adapter.route.throw-exception-message",
            Self::RouteUncatchableClause => "adapter.route.uncatchable-clause",
            Self::RouteUnknownDirectTarget => "adapter.route.unknown-direct-target",
            Self::RouteUnknownEndpoint => "adapter.route.unknown-endpoint",
            Self::RouteUnknownHeader => "adapter.route.unknown-header",
            Self::RouteUnknownOperation => "adapter.route.unknown-operation",
            Self::RouteWriteWithoutIdempotency => "adapter.route.write-without-idempotency",
            Self::RuntimeInsecureOrigin => "adapter.runtime.insecure-origin",
            Self::RuntimeInvalidOrigin => "adapter.runtime.invalid-origin",
            Self::RuntimeInvalidOutboundTls => "adapter.runtime.invalid-outbound-tls",
            Self::RuntimeMissingEndpoint => "adapter.runtime.missing-endpoint",
            Self::RuntimeUnknownEndpoint => "adapter.runtime.unknown-endpoint",
            Self::RuntimeUnknownTrustProfile => "adapter.runtime.unknown-trust-profile",
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
            | Self::RuntimeInvalidOrigin
            | Self::RuntimeInvalidOutboundTls
            | Self::RuntimeMissingEndpoint
            | Self::RuntimeUnknownEndpoint
            | Self::RuntimeUnknownTrustProfile => crate::naming::ADAPTER_RUNTIME_KIND,
            Self::EnvelopeInvalidPlaceholder
            | Self::ProfileInvalidPath
            | Self::ProfilePageSizeDefaultOutOfBounds
            | Self::ProfileProblemClassDuplicate
            | Self::ProfileProblemClassUnresolved
            | Self::ProfileProblemEnvelopeMissingCodeSlot
            | Self::ProfileProblemEnvelopeUncompilable
            | Self::ProfileReadOnlyMethod
            | Self::ProfileRecordIdParameterMissing
            | Self::ProfileRequestEnvelopeMissingRecordSlot
            | Self::ProfileResponseEnvelopeMissingResultSlot
            | Self::ProfileResponseEnvelopeUncompilable
            | Self::ProfileUnknownRecordIdParameter
            | Self::ProfileUnknownRecordTypeParameter
            | Self::ProfileUnknownSlot
            | Self::ProfileUnresolvedPathParameter => crate::naming::ADAPTER_PROFILE_KIND,
            Self::FixtureCredentialRecorded
            | Self::FixtureEmptyUpstream
            | Self::FixtureResponseSchema
            | Self::FixtureUncoveredExchange
            | Self::FixtureUnknownEndpoint
            | Self::FixtureUnknownIntercept
            | Self::FixtureUnknownOperation
            | Self::FixtureUnknownProblemCode => crate::naming::ADAPTER_FIXTURE_KIND,
            Self::PackCodeMapEntryNotScalar
            | Self::PackCodeMapUnreferenced
            | Self::PackDigestPinRequired
            | Self::PackDuplicateHeaderName
            | Self::PackEndpointComponentInvalid
            | Self::PackEntrypointParameter
            | Self::PackGraphQlOperationUnknown
            | Self::PackGraphQlQueryInvalid
            | Self::PackGraphQlQueryRequired
            | Self::PackInvalidHeaderName
            | Self::PackMapParameterMisplaced
            | Self::PackReservedHeaderName
            | Self::PackScriptUncompilable
            | Self::PackTooManyHeaders
            | Self::PackTransportRefusedHeader
            | Self::PackUnknownScript
            | Self::PackUnknownTemplateParameter
            | Self::RouteCodeMapUnknown
            | Self::RouteConvertShape
            | Self::RouteDirectCycle
            | Self::RouteDirectDepthExceeded
            | Self::RouteEmptyExceptionList
            | Self::RouteErrorHandlerShape
            | Self::RouteFromNotDirect
            | Self::RouteGraphQlSendMembers
            | Self::RouteInvalidHeaderName
            | Self::RouteInvalidQueryKey
            | Self::RoutePathParameterMismatch
            | Self::RouteHandledAndContinued
            | Self::RouteHttpUriMembers
            | Self::RouteInvalidPath
            | Self::RouteInvalidStatusCodeRange
            | Self::RouteLoopCountAboveBound
            | Self::RouteMaximumItemsRequired
            | Self::RouteMaximumIterationsRequired
            | Self::RouteMultipleNonSafeSends
            | Self::RouteNestingDepthExceeded
            | Self::RouteNonSafeSendInSplit
            | Self::RouteOkRangeCoversUnauthorized
            | Self::RoutePredicateAmbiguous
            | Self::RoutePredicateLanguageRequired
            | Self::RouteReadUnsafeSend
            | Self::RouteRedeliveryOverNonSafeSend
            | Self::RouteRedeliveryWithoutUpstreamSend
            | Self::RouteReservedHeaderName
            | Self::RouteRetryWhileWithoutRedeliveries
            | Self::RouteStopOnExceptionExclusive
            | Self::RouteThrowExceptionClass
            | Self::RouteThrowExceptionMessage
            | Self::RouteUncatchableClause
            | Self::RouteUnknownDirectTarget
            | Self::RouteUnknownEndpoint
            | Self::RouteUnknownHeader
            | Self::RouteUnknownOperation
            | Self::RouteWriteWithoutIdempotency => crate::naming::ADAPTER_PACK_KIND,
            Self::ProjectAccessProfileScopesEmpty
            | Self::ProjectDuplicateRouteId
            | Self::ProjectFilterParameterCollision
            | Self::ProjectParameterTypeMismatch
            | Self::ProjectParameterizedPartUnbound
            | Self::ProjectPinDigestMismatch
            | Self::ProjectPinVersionMismatch
            | Self::ProjectRequiredParameterUnbound
            | Self::ProjectTemplateNotInstantiated
            | Self::ProjectUnknownFilterField
            | Self::ProjectUnknownOperation
            | Self::ProjectUnknownRecordType
            | Self::ProjectUnknownRoute
            | Self::ProjectUnknownTemplate
            | Self::ProjectUnknownTemplateParameter
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
        // The graphql pack codes, spellings fixed for adopter tooling.
        assert_eq!(
            CheckCode::from_code("adapter.pack.graphql-query-invalid"),
            Some(CheckCode::PackGraphQlQueryInvalid)
        );
        assert_eq!(
            CheckCode::from_code("adapter.pack.graphql-operation-unknown"),
            Some(CheckCode::PackGraphQlOperationUnknown)
        );
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
