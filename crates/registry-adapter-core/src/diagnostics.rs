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
    // adapter.fixture.*
    FixtureDigestMismatch,
    FixtureEmptyTranscript,
    FixtureExpectationRequired,
    FixtureInvalidStatus,
    FixturePackMismatch,
    FixtureUnknownTemplate,
    FixtureUntestedVersion,
    // adapter.pack.*
    PackCodeMapTargetInvalid,
    PackDuplicateCodeMap,
    PackInvalidDetectionRange,
    PackInvalidPaginateBound,
    PackInvalidRetryPolicy,
    PackInvalidScriptDigest,
    PackInvalidScriptPath,
    PackOverlappingDetection,
    PackPaginateBoundsRequired,
    PackUnboundOperation,
    PackUnknownCodeValue,
    PackUnknownCursorShape,
    PackDuplicateErrorClass,
    PackUnknownEnvelope,
    PackUnknownErrorClass,
    PackUnknownField,
    PackUnknownPlaceholder,
    // adapter.plan.*
    PlanBudgetRequired,
    PlanDuplicateBinding,
    PlanEmptyFieldMap,
    PlanForwardBinding,
    PlanInvalidBudget,
    PlanIteratePolicyRequired,
    PlanNormalizeBranchRequired,
    PlanNormalizeBranchTotality,
    PlanUnknownBinding,
    PlanUnknownJoinField,
    PlanUnknownPaginationPlan,
    PlanUnknownTemplate,
    PlanWriteIteratePolicy,
    // adapter.profile.*
    ProfilePartMismatch,
    // adapter.project.*
    ProjectInvalidReference,
    ProjectUnknownOperation,
    // adapter.runtime.*
    RuntimeInvalidBaseUrl,
    RuntimeInvalidCidr,
    RuntimeInvalidRetention,
    RuntimeInvalidUpstreamAuth,
    RuntimePrivateCidrLimit,
}

impl CheckCode {
    /// The complete closed vocabulary, in code-string order.
    pub const ALL: &'static [Self] = &[
        Self::FixtureDigestMismatch,
        Self::FixtureEmptyTranscript,
        Self::FixtureExpectationRequired,
        Self::FixtureInvalidStatus,
        Self::FixturePackMismatch,
        Self::FixtureUnknownTemplate,
        Self::FixtureUntestedVersion,
        Self::PackCodeMapTargetInvalid,
        Self::PackDuplicateCodeMap,
        Self::PackDuplicateErrorClass,
        Self::PackInvalidDetectionRange,
        Self::PackInvalidPaginateBound,
        Self::PackInvalidRetryPolicy,
        Self::PackInvalidScriptDigest,
        Self::PackInvalidScriptPath,
        Self::PackOverlappingDetection,
        Self::PackPaginateBoundsRequired,
        Self::PackUnboundOperation,
        Self::PackUnknownCodeValue,
        Self::PackUnknownCursorShape,
        Self::PackUnknownEnvelope,
        Self::PackUnknownErrorClass,
        Self::PackUnknownField,
        Self::PackUnknownPlaceholder,
        Self::PlanBudgetRequired,
        Self::PlanDuplicateBinding,
        Self::PlanEmptyFieldMap,
        Self::PlanForwardBinding,
        Self::PlanInvalidBudget,
        Self::PlanIteratePolicyRequired,
        Self::PlanNormalizeBranchRequired,
        Self::PlanNormalizeBranchTotality,
        Self::PlanUnknownBinding,
        Self::PlanUnknownJoinField,
        Self::PlanUnknownPaginationPlan,
        Self::PlanUnknownTemplate,
        Self::PlanWriteIteratePolicy,
        Self::ProfilePartMismatch,
        Self::ProjectInvalidReference,
        Self::ProjectUnknownOperation,
        Self::RuntimeInvalidBaseUrl,
        Self::RuntimeInvalidCidr,
        Self::RuntimeInvalidRetention,
        Self::RuntimeInvalidUpstreamAuth,
        Self::RuntimePrivateCidrLimit,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::FixtureDigestMismatch => "adapter.fixture.digest-mismatch",
            Self::FixtureEmptyTranscript => "adapter.fixture.empty-transcript",
            Self::FixtureExpectationRequired => "adapter.fixture.expectation-required",
            Self::FixtureInvalidStatus => "adapter.fixture.invalid-status",
            Self::FixturePackMismatch => "adapter.fixture.pack-mismatch",
            Self::FixtureUnknownTemplate => "adapter.fixture.unknown-template",
            Self::FixtureUntestedVersion => "adapter.fixture.untested-version",
            Self::PackCodeMapTargetInvalid => "adapter.pack.code-map-target-invalid",
            Self::PackDuplicateCodeMap => "adapter.pack.duplicate-code-map",
            Self::PackInvalidDetectionRange => "adapter.pack.invalid-detection-range",
            Self::PackInvalidPaginateBound => "adapter.pack.invalid-paginate-bound",
            Self::PackInvalidRetryPolicy => "adapter.pack.invalid-retry-policy",
            Self::PackInvalidScriptDigest => "adapter.pack.invalid-script-digest",
            Self::PackInvalidScriptPath => "adapter.pack.invalid-script-path",
            Self::PackOverlappingDetection => "adapter.pack.overlapping-detection",
            Self::PackPaginateBoundsRequired => "adapter.pack.paginate-bounds-required",
            Self::PackUnboundOperation => "adapter.pack.unbound-operation",
            Self::PackUnknownCodeValue => "adapter.pack.unknown-code-value",
            Self::PackUnknownCursorShape => "adapter.pack.unknown-cursor-shape",
            Self::PackDuplicateErrorClass => "adapter.pack.duplicate-error-class",
            Self::PackUnknownEnvelope => "adapter.pack.unknown-envelope",
            Self::PackUnknownErrorClass => "adapter.pack.unknown-error-class",
            Self::PackUnknownField => "adapter.pack.unknown-field",
            Self::PackUnknownPlaceholder => "adapter.pack.unknown-placeholder",
            Self::PlanBudgetRequired => "adapter.plan.budget-required",
            Self::PlanDuplicateBinding => "adapter.plan.duplicate-binding",
            Self::PlanEmptyFieldMap => "adapter.plan.empty-field-map",
            Self::PlanForwardBinding => "adapter.plan.forward-binding",
            Self::PlanInvalidBudget => "adapter.plan.invalid-budget",
            Self::PlanIteratePolicyRequired => "adapter.plan.iterate-policy-required",
            Self::PlanNormalizeBranchRequired => "adapter.plan.normalize-branch-required",
            Self::PlanNormalizeBranchTotality => "adapter.plan.normalize-branch-totality",
            Self::PlanUnknownBinding => "adapter.plan.unknown-binding",
            Self::PlanUnknownJoinField => "adapter.plan.unknown-join-field",
            Self::PlanUnknownPaginationPlan => "adapter.plan.unknown-pagination-plan",
            Self::PlanUnknownTemplate => "adapter.plan.unknown-template",
            Self::PlanWriteIteratePolicy => "adapter.plan.write-iterate-policy",
            Self::ProfilePartMismatch => "adapter.profile.part-mismatch",
            Self::ProjectInvalidReference => "adapter.project.invalid-reference",
            Self::ProjectUnknownOperation => "adapter.project.unknown-operation",
            Self::RuntimeInvalidBaseUrl => "adapter.runtime.invalid-base-url",
            Self::RuntimeInvalidCidr => "adapter.runtime.invalid-cidr",
            Self::RuntimeInvalidRetention => "adapter.runtime.invalid-retention",
            Self::RuntimeInvalidUpstreamAuth => "adapter.runtime.invalid-upstream-auth",
            Self::RuntimePrivateCidrLimit => "adapter.runtime.private-cidr-limit",
        }
    }

    /// The artifact kind whose document this finding points into; the middle
    /// segment of the code names it.
    #[must_use]
    pub const fn artifact(self) -> &'static str {
        match self {
            Self::FixtureDigestMismatch
            | Self::FixtureEmptyTranscript
            | Self::FixtureExpectationRequired
            | Self::FixtureInvalidStatus
            | Self::FixturePackMismatch
            | Self::FixtureUnknownTemplate
            | Self::FixtureUntestedVersion => crate::naming::ADAPTER_FIXTURE_KIND,
            Self::PackCodeMapTargetInvalid
            | Self::PackDuplicateCodeMap
            | Self::PackInvalidDetectionRange
            | Self::PackInvalidPaginateBound
            | Self::PackInvalidRetryPolicy
            | Self::PackInvalidScriptDigest
            | Self::PackInvalidScriptPath
            | Self::PackOverlappingDetection
            | Self::PackPaginateBoundsRequired
            | Self::PackUnboundOperation
            | Self::PackUnknownCodeValue
            | Self::PackUnknownCursorShape
            | Self::PackDuplicateErrorClass
            | Self::PackUnknownEnvelope
            | Self::PackUnknownErrorClass
            | Self::PackUnknownField
            | Self::PackUnknownPlaceholder => crate::naming::ADAPTER_PACK_KIND,
            Self::PlanBudgetRequired
            | Self::PlanDuplicateBinding
            | Self::PlanEmptyFieldMap
            | Self::PlanForwardBinding
            | Self::PlanInvalidBudget
            | Self::PlanIteratePolicyRequired
            | Self::PlanNormalizeBranchRequired
            | Self::PlanNormalizeBranchTotality
            | Self::PlanUnknownBinding
            | Self::PlanUnknownJoinField
            | Self::PlanUnknownPaginationPlan
            | Self::PlanUnknownTemplate
            | Self::PlanWriteIteratePolicy => crate::naming::ADAPTER_PACK_KIND,
            Self::ProfilePartMismatch => crate::naming::ADAPTER_PROFILE_KIND,
            Self::ProjectInvalidReference | Self::ProjectUnknownOperation => {
                crate::naming::ADAPTER_PROJECT_KIND
            }
            Self::RuntimeInvalidBaseUrl
            | Self::RuntimeInvalidCidr
            | Self::RuntimeInvalidRetention
            | Self::RuntimeInvalidUpstreamAuth
            | Self::RuntimePrivateCidrLimit => crate::naming::ADAPTER_RUNTIME_KIND,
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
        assert_eq!(CheckCode::from_code("adapter.pack.invented"), None);
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
            CheckCode::PlanBudgetRequired,
            "/operations/records.search/plan",
            "the plan declares no budgets",
            "Declare the plan's budgets.",
        );
        assert_eq!(diagnostic.severity, registry_platform_yaml::Severity::Error);
        assert_eq!(diagnostic.artifact.as_deref(), Some("AdapterPack"));
        assert!(diagnostic.message.contains("budgets"));
    }
}
