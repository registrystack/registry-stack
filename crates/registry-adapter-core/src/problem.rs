// SPDX-License-Identifier: Apache-2.0

//! The closed problem vocabulary of the Adapter facade.
//!
//! The vocabulary is closed on purpose: a caller can enumerate every problem
//! the facade can ever return, and a problem code outside this list is a
//! defect, not a compatibility event. The vocabulary carries only what the
//! engine itself raises (`products/adapter/CONCEPT.md` sections 7 to 9):
//! the request-edge rejections under the `request.*` family, the
//! authorization pair of section 10.1, the three write outcomes the
//! idempotency store constructs, the five uncatchable boundary classes of
//! section 8.7 surfaced as problems, and the fixed catch-all
//! `adapter.upstream.unmapped` (502) an unhandled upstream error surfaces
//! as. Everything a route translates on purpose travels in the profile's
//! own problem-code list, never here.

use crate::naming::ADAPTER_PROBLEM_TYPE_BASE;

pub const AUTHENTICATION_REFUSED_PROBLEM: &str = "authentication.refused";
pub const BUDGET_EXHAUSTED_PROBLEM: &str = "budget.exhausted";
pub const CREDENTIAL_REJECTED_PROBLEM: &str = "credential.rejected";
pub const DISCLOSURE_VIOLATION_PROBLEM: &str = "disclosure.violation";
pub const EGRESS_REFUSED_PROBLEM: &str = "egress.refused";
pub const OPERATION_NOT_AUTHORIZED_PROBLEM: &str = "operation.not-authorized";
pub const REQUEST_BODY_TOO_LARGE_PROBLEM: &str = "request.body-too-large";
pub const REQUEST_INVALID_PROBLEM: &str = "request.invalid";
pub const REQUEST_METHOD_NOT_ALLOWED_PROBLEM: &str = "request.method-not-allowed";
pub const REQUEST_NOT_FOUND_PROBLEM: &str = "request.not-found";
pub const REQUEST_UNSUPPORTED_MEDIA_TYPE_PROBLEM: &str = "request.unsupported-media-type";
pub const SCRIPT_BUDGET_EXCEEDED_PROBLEM: &str = "script.budget-exceeded";
pub const UPSTREAM_UNMAPPED_PROBLEM: &str = "upstream.unmapped";
pub const WRITE_IDEMPOTENCY_MISMATCH_PROBLEM: &str = "write.idempotency-mismatch";
pub const WRITE_IN_PROGRESS_PROBLEM: &str = "write.in-progress";
pub const WRITE_PARTIAL_ACCEPTANCE_PROBLEM: &str = "write.partial-acceptance";

/// Every problem code the Adapter facade can return, in code-string order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ProblemCode {
    AuthenticationRefused,
    BudgetExhausted,
    CredentialRejected,
    DisclosureViolation,
    EgressRefused,
    OperationNotAuthorized,
    RequestBodyTooLarge,
    RequestInvalid,
    RequestMethodNotAllowed,
    RequestNotFound,
    RequestUnsupportedMediaType,
    ScriptBudgetExceeded,
    UpstreamUnmapped,
    WriteIdempotencyMismatch,
    WriteInProgress,
    WritePartialAcceptance,
}

impl ProblemCode {
    /// The complete closed vocabulary, in code-string order.
    pub const ALL: &'static [Self] = &[
        Self::AuthenticationRefused,
        Self::BudgetExhausted,
        Self::CredentialRejected,
        Self::DisclosureViolation,
        Self::EgressRefused,
        Self::OperationNotAuthorized,
        Self::RequestBodyTooLarge,
        Self::RequestInvalid,
        Self::RequestMethodNotAllowed,
        Self::RequestNotFound,
        Self::RequestUnsupportedMediaType,
        Self::ScriptBudgetExceeded,
        Self::UpstreamUnmapped,
        Self::WriteIdempotencyMismatch,
        Self::WriteInProgress,
        Self::WritePartialAcceptance,
    ];

    /// The `type` URI this problem carries, under the Adapter problem base.
    #[must_use]
    pub fn type_uri(self) -> String {
        format!("{ADAPTER_PROBLEM_TYPE_BASE}{}", self.code())
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::AuthenticationRefused => AUTHENTICATION_REFUSED_PROBLEM,
            Self::BudgetExhausted => BUDGET_EXHAUSTED_PROBLEM,
            Self::CredentialRejected => CREDENTIAL_REJECTED_PROBLEM,
            Self::DisclosureViolation => DISCLOSURE_VIOLATION_PROBLEM,
            Self::EgressRefused => EGRESS_REFUSED_PROBLEM,
            Self::OperationNotAuthorized => OPERATION_NOT_AUTHORIZED_PROBLEM,
            Self::RequestBodyTooLarge => REQUEST_BODY_TOO_LARGE_PROBLEM,
            Self::RequestInvalid => REQUEST_INVALID_PROBLEM,
            Self::RequestMethodNotAllowed => REQUEST_METHOD_NOT_ALLOWED_PROBLEM,
            Self::RequestNotFound => REQUEST_NOT_FOUND_PROBLEM,
            Self::RequestUnsupportedMediaType => REQUEST_UNSUPPORTED_MEDIA_TYPE_PROBLEM,
            Self::ScriptBudgetExceeded => SCRIPT_BUDGET_EXCEEDED_PROBLEM,
            Self::UpstreamUnmapped => UPSTREAM_UNMAPPED_PROBLEM,
            Self::WriteIdempotencyMismatch => WRITE_IDEMPOTENCY_MISMATCH_PROBLEM,
            Self::WriteInProgress => WRITE_IN_PROGRESS_PROBLEM,
            Self::WritePartialAcceptance => WRITE_PARTIAL_ACCEPTANCE_PROBLEM,
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

    /// The HTTP status this problem answers with. The map lives here, beside
    /// the vocabulary it belongs to, so the runtime emits and every client
    /// validates one pinned status per code.
    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::RequestInvalid => 400,
            Self::AuthenticationRefused => 401,
            Self::OperationNotAuthorized => 403,
            Self::RequestNotFound => 404,
            Self::RequestMethodNotAllowed => 405,
            Self::WriteInProgress | Self::WritePartialAcceptance => 409,
            Self::RequestBodyTooLarge => 413,
            Self::RequestUnsupportedMediaType => 415,
            Self::WriteIdempotencyMismatch => 422,
            Self::DisclosureViolation | Self::ScriptBudgetExceeded => 500,
            Self::CredentialRejected | Self::EgressRefused | Self::UpstreamUnmapped => 502,
            Self::BudgetExhausted => 429,
        }
    }
}

impl serde::Serialize for ProblemCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.code())
    }
}

impl<'de> serde::Deserialize<'de> for ProblemCode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let code = String::deserialize(deserializer)?;
        Self::from_code(&code).ok_or_else(|| {
            serde::de::Error::custom(registry_platform_yaml::Invalid::expected(
                "a problem code this adapter can return",
                "Write one problem code from the closed Adapter vocabulary.",
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip() {
        for problem in ProblemCode::ALL {
            assert_eq!(ProblemCode::from_code(problem.code()), Some(*problem));
        }
        assert_eq!(ProblemCode::from_code("cases-find"), None);
    }

    #[test]
    fn vocabulary_is_sorted_and_complete() {
        let mut codes: Vec<&str> = ProblemCode::ALL.iter().map(|p| p.code()).collect();
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

    /// The uncatchable boundary classes surface as problems with the same
    /// trailing name (`products/adapter/CONCEPT.md` section 8.7).
    #[test]
    fn uncatchable_classes_surface_as_problems() {
        assert_eq!(
            ProblemCode::from_code("budget.exhausted").map(|p| p.http_status()),
            Some(429)
        );
        assert_eq!(
            ProblemCode::from_code("credential.rejected").map(|p| p.http_status()),
            Some(502)
        );
        assert_eq!(
            ProblemCode::from_code("disclosure.violation").map(|p| p.http_status()),
            Some(500)
        );
        assert_eq!(
            ProblemCode::from_code("egress.refused").map(|p| p.http_status()),
            Some(502)
        );
        assert_eq!(
            ProblemCode::from_code("script.budget-exceeded").map(|p| p.http_status()),
            Some(500)
        );
    }

    /// The fixed unmapped catch-all keeps the exact code and status
    /// CONCEPT 8.7 and 9 pin (`adapter.upstream.unmapped`, 502).
    #[test]
    fn unmapped_is_pinned() {
        assert_eq!(ProblemCode::UpstreamUnmapped.code(), "upstream.unmapped");
        assert_eq!(ProblemCode::UpstreamUnmapped.http_status(), 502);
    }

    /// The write outcomes the idempotency store constructs keep the
    /// statuses CONCEPT 9 pins.
    #[test]
    fn write_semantics_are_pinned() {
        assert_eq!(ProblemCode::WriteInProgress.http_status(), 409);
        assert_eq!(ProblemCode::WriteIdempotencyMismatch.http_status(), 422);
        assert_eq!(ProblemCode::WritePartialAcceptance.http_status(), 409);
    }

    #[test]
    fn statuses_are_pinned() {
        assert_eq!(ProblemCode::AuthenticationRefused.http_status(), 401);
        assert_eq!(ProblemCode::OperationNotAuthorized.http_status(), 403);
        assert_eq!(ProblemCode::RequestInvalid.http_status(), 400);
        assert_eq!(ProblemCode::RequestBodyTooLarge.http_status(), 413);
    }

    #[test]
    fn deserializing_an_unknown_code_is_refused() {
        let error = serde_json::from_str::<ProblemCode>("\"upstream.exploded\"")
            .expect_err("an unknown code must be refused");
        assert!(error.to_string().contains("problem code"));
    }
}
