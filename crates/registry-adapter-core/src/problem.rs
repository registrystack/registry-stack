// SPDX-License-Identifier: Apache-2.0

//! The closed problem vocabulary of the Adapter facade.
//!
//! The vocabulary is closed on purpose: a caller can enumerate every problem
//! the facade can ever return, and a problem code outside this list is a
//! defect, not a compatibility event. The `request.*` family carries the
//! request-edge rejections under this product's own prefix, exactly as
//! Casework and Scheduling do. The `upstream.*` family carries what the
//! source system produced; its members never carry upstream detail, only the
//! bounded class (`products/adapter/CONCEPT.md` section 9). The `write.*`
//! family carries write acceptance and conflict outcomes; the partial
//! acceptance and conflict problems are the bounded 409s of section 9 and
//! carry counts and translated detail only, never a raw upstream body.

use crate::naming::ADAPTER_PROBLEM_TYPE_BASE;

pub const AUTHENTICATION_REFUSED_PROBLEM: &str = "authentication.refused";
pub const OPERATION_NOT_AUTHORIZED_PROBLEM: &str = "operation.not-authorized";
pub const PLAN_BUDGET_EXHAUSTED_PROBLEM: &str = "plan.budget-exhausted";
pub const PROFILE_NOT_AUTHORIZED_PROBLEM: &str = "profile.not-authorized";
pub const REQUEST_BODY_TOO_LARGE_PROBLEM: &str = "request.body-too-large";
pub const REQUEST_INVALID_PROBLEM: &str = "request.invalid";
pub const REQUEST_METHOD_NOT_ALLOWED_PROBLEM: &str = "request.method-not-allowed";
pub const REQUEST_NOT_FOUND_PROBLEM: &str = "request.not-found";
pub const REQUEST_UNPROCESSABLE_PROBLEM: &str = "request.unprocessable";
pub const REQUEST_UNSUPPORTED_MEDIA_TYPE_PROBLEM: &str = "request.unsupported-media-type";
pub const UPSTREAM_BREAKER_OPEN_PROBLEM: &str = "upstream.breaker-open";
pub const UPSTREAM_PAGINATION_DRIFT_PROBLEM: &str = "upstream.pagination-drift";
pub const UPSTREAM_RESPONSE_INVALID_PROBLEM: &str = "upstream.response-invalid";
pub const UPSTREAM_UNAVAILABLE_PROBLEM: &str = "upstream.unavailable";
pub const UPSTREAM_UNMAPPED_PROBLEM: &str = "upstream.unmapped";
pub const WRITE_CONFLICT_PROBLEM: &str = "write.conflict";
pub const WRITE_PARTIAL_ACCEPTANCE_PROBLEM: &str = "write.partial-acceptance";
pub const WRITE_REJECTED_PROBLEM: &str = "write.rejected";

/// Every problem code the Adapter facade can return, in code-string order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ProblemCode {
    AuthenticationRefused,
    OperationNotAuthorized,
    PlanBudgetExhausted,
    ProfileNotAuthorized,
    RequestBodyTooLarge,
    RequestInvalid,
    RequestMethodNotAllowed,
    RequestNotFound,
    RequestUnprocessable,
    RequestUnsupportedMediaType,
    UpstreamBreakerOpen,
    UpstreamPaginationDrift,
    UpstreamResponseInvalid,
    UpstreamUnavailable,
    UpstreamUnmapped,
    WriteConflict,
    WritePartialAcceptance,
    WriteRejected,
}

impl ProblemCode {
    /// The complete closed vocabulary, in code-string order.
    pub const ALL: &'static [Self] = &[
        Self::AuthenticationRefused,
        Self::OperationNotAuthorized,
        Self::PlanBudgetExhausted,
        Self::ProfileNotAuthorized,
        Self::RequestBodyTooLarge,
        Self::RequestInvalid,
        Self::RequestMethodNotAllowed,
        Self::RequestNotFound,
        Self::RequestUnprocessable,
        Self::RequestUnsupportedMediaType,
        Self::UpstreamBreakerOpen,
        Self::UpstreamPaginationDrift,
        Self::UpstreamResponseInvalid,
        Self::UpstreamUnavailable,
        Self::UpstreamUnmapped,
        Self::WriteConflict,
        Self::WritePartialAcceptance,
        Self::WriteRejected,
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
            Self::OperationNotAuthorized => OPERATION_NOT_AUTHORIZED_PROBLEM,
            Self::PlanBudgetExhausted => PLAN_BUDGET_EXHAUSTED_PROBLEM,
            Self::ProfileNotAuthorized => PROFILE_NOT_AUTHORIZED_PROBLEM,
            Self::RequestBodyTooLarge => REQUEST_BODY_TOO_LARGE_PROBLEM,
            Self::RequestInvalid => REQUEST_INVALID_PROBLEM,
            Self::RequestMethodNotAllowed => REQUEST_METHOD_NOT_ALLOWED_PROBLEM,
            Self::RequestNotFound => REQUEST_NOT_FOUND_PROBLEM,
            Self::RequestUnprocessable => REQUEST_UNPROCESSABLE_PROBLEM,
            Self::RequestUnsupportedMediaType => REQUEST_UNSUPPORTED_MEDIA_TYPE_PROBLEM,
            Self::UpstreamBreakerOpen => UPSTREAM_BREAKER_OPEN_PROBLEM,
            Self::UpstreamPaginationDrift => UPSTREAM_PAGINATION_DRIFT_PROBLEM,
            Self::UpstreamResponseInvalid => UPSTREAM_RESPONSE_INVALID_PROBLEM,
            Self::UpstreamUnavailable => UPSTREAM_UNAVAILABLE_PROBLEM,
            Self::UpstreamUnmapped => UPSTREAM_UNMAPPED_PROBLEM,
            Self::WriteConflict => WRITE_CONFLICT_PROBLEM,
            Self::WritePartialAcceptance => WRITE_PARTIAL_ACCEPTANCE_PROBLEM,
            Self::WriteRejected => WRITE_REJECTED_PROBLEM,
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
            Self::OperationNotAuthorized | Self::ProfileNotAuthorized => 403,
            Self::RequestNotFound => 404,
            Self::RequestMethodNotAllowed => 405,
            Self::WriteConflict | Self::WritePartialAcceptance => 409,
            Self::RequestBodyTooLarge => 413,
            Self::RequestUnsupportedMediaType => 415,
            Self::RequestUnprocessable | Self::WriteRejected => 422,
            Self::PlanBudgetExhausted | Self::UpstreamBreakerOpen => 503,
            Self::UpstreamPaginationDrift
            | Self::UpstreamResponseInvalid
            | Self::UpstreamUnavailable
            | Self::UpstreamUnmapped => 502,
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
        assert_eq!(ProblemCode::from_code("records.search"), None);
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

    #[test]
    fn statuses_are_pinned() {
        assert_eq!(ProblemCode::WritePartialAcceptance.http_status(), 409);
        assert_eq!(ProblemCode::WriteConflict.http_status(), 409);
        assert_eq!(ProblemCode::UpstreamUnmapped.http_status(), 502);
        assert_eq!(ProblemCode::PlanBudgetExhausted.http_status(), 503);
    }

    #[test]
    fn deserializing_an_unknown_code_is_refused() {
        let error = serde_json::from_str::<ProblemCode>("\"upstream.exploded\"")
            .expect_err("an unknown code must be refused");
        assert!(error.to_string().contains("problem code"));
    }
}
