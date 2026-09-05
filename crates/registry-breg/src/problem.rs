// SPDX-License-Identifier: Apache-2.0

//! The closed set of public problem types Base Registry Engine emits.
//!
//! Every refusal names its type on the shared Registry Stack identifier host,
//! the convention Registry Discovery, Evidence Gateway, and Registry Relay
//! already share, so an adopter can resolve the type it was handed. A dot in a
//! code separates path segments under the product prefix.

/// The prefix every Base Registry Engine problem type resolves under.
pub const PROBLEM_TYPE_BASE: &str = "https://id.registrystack.org/problems/registry-breg/";

/// Resolve one public problem code to its type URI.
#[must_use]
pub fn type_uri(code: &str) -> String {
    format!("{PROBLEM_TYPE_BASE}{}", code.replace('.', "/"))
}

/// One public problem code, its status, and the value-free text that describes
/// it. The runtime emits the code and the status; the title and description are
/// what a reader of the published catalog is given.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[non_exhaustive]
pub enum ProblemCode {
    AuthenticationRefused,
    IdempotencyConflict,
    LookupUnresolved,
    MutationConflict,
    PreconditionFailed,
    PreconditionRequired,
    QueryCursorInvalid,
    QueryInvalid,
    RequestInvalid,
    RequestPlanRefused,
    RequestTimeout,
    ResourceNotFound,
    RuntimeNotReady,
    ServiceUnavailable,
    SourceUnavailable,
    UnsupportedMediaType,
}

impl ProblemCode {
    /// Every registered code, ordered by its code string.
    pub const ALL: &'static [Self] = &[
        Self::AuthenticationRefused,
        Self::IdempotencyConflict,
        Self::LookupUnresolved,
        Self::MutationConflict,
        Self::PreconditionFailed,
        Self::PreconditionRequired,
        Self::QueryCursorInvalid,
        Self::QueryInvalid,
        Self::RequestInvalid,
        Self::RequestPlanRefused,
        Self::RequestTimeout,
        Self::ResourceNotFound,
        Self::RuntimeNotReady,
        Self::ServiceUnavailable,
        Self::SourceUnavailable,
        Self::UnsupportedMediaType,
    ];

    /// The codes a documented HTTP operation can answer with. The readiness
    /// probe is an operational route with no documented operation, so its code
    /// is registered and published but never listed in a generated document.
    pub const DOCUMENTED: &'static [Self] = &[
        Self::AuthenticationRefused,
        Self::IdempotencyConflict,
        Self::LookupUnresolved,
        Self::MutationConflict,
        Self::PreconditionFailed,
        Self::PreconditionRequired,
        Self::QueryCursorInvalid,
        Self::QueryInvalid,
        Self::RequestInvalid,
        Self::RequestPlanRefused,
        Self::RequestTimeout,
        Self::ResourceNotFound,
        Self::ServiceUnavailable,
        Self::SourceUnavailable,
        Self::UnsupportedMediaType,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::AuthenticationRefused => "authentication.refused",
            Self::IdempotencyConflict => "idempotency.conflict",
            Self::LookupUnresolved => "lookup.unresolved",
            Self::MutationConflict => "mutation.conflict",
            Self::PreconditionFailed => "precondition.failed",
            Self::PreconditionRequired => "precondition.required",
            Self::QueryCursorInvalid => "query.cursor_invalid",
            Self::QueryInvalid => "query.invalid",
            Self::RequestInvalid => "request.invalid",
            Self::RequestPlanRefused => "request.plan_refused",
            Self::RequestTimeout => "request.timeout",
            Self::ResourceNotFound => "resource.not_found",
            Self::RuntimeNotReady => "runtime.not_ready",
            Self::ServiceUnavailable => "service.unavailable",
            Self::SourceUnavailable => "source.unavailable",
            Self::UnsupportedMediaType => "unsupported.media_type",
        }
    }

    /// The one HTTP status this code is answered under.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::QueryCursorInvalid
            | Self::QueryInvalid
            | Self::RequestInvalid
            | Self::RequestPlanRefused => 400,
            Self::AuthenticationRefused => 401,
            Self::LookupUnresolved | Self::ResourceNotFound => 404,
            Self::IdempotencyConflict | Self::MutationConflict => 409,
            Self::PreconditionFailed => 412,
            Self::UnsupportedMediaType => 415,
            Self::PreconditionRequired => 428,
            Self::RuntimeNotReady | Self::ServiceUnavailable | Self::SourceUnavailable => 503,
            Self::RequestTimeout => 504,
        }
    }

    /// The problem title, which is the reason phrase of the code's status.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self.status() {
            400 => "Bad Request",
            401 => "Unauthorized",
            404 => "Not Found",
            409 => "Conflict",
            412 => "Precondition Failed",
            415 => "Unsupported Media Type",
            428 => "Precondition Required",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            _ => "Request failed",
        }
    }

    /// The value-free sentence published for this code. A refusal carries the
    /// same sentence on the wire, except a refused plan, which names the
    /// planner failure kind from its own closed vocabulary.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::AuthenticationRefused => "The bearer credential is missing or refused.",
            Self::IdempotencyConflict => "The idempotency key is bound to another request.",
            Self::LookupUnresolved => "The lookup did not resolve exactly one record.",
            Self::MutationConflict => "The mutation conflicts with current state.",
            Self::PreconditionFailed => "The mutation precondition failed.",
            Self::PreconditionRequired => "The mutation precondition is required.",
            Self::QueryCursorInvalid => "The query cursor is invalid.",
            Self::QueryInvalid => "The query request is invalid.",
            Self::RequestInvalid => "The request is invalid.",
            Self::RequestPlanRefused => {
                "The change-request planner refused the submission, naming the failure kind."
            }
            Self::RequestTimeout => "The request timed out.",
            Self::ResourceNotFound => "The requested resource was not found.",
            Self::RuntimeNotReady => "Registry runtime is not ready.",
            Self::ServiceUnavailable => "The Registry mutation service is unavailable.",
            Self::SourceUnavailable => "The Registry data service is unavailable.",
            Self::UnsupportedMediaType => "The request media type is not supported.",
        }
    }

    /// The resolvable type URI for this code.
    #[must_use]
    pub fn type_uri(self) -> String {
        type_uri(self.code())
    }
}

impl std::fmt::Display for ProblemCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

#[cfg(test)]
mod tests {
    use super::{type_uri, ProblemCode, PROBLEM_TYPE_BASE};

    #[test]
    fn every_type_resolves_under_the_shared_product_prefix() {
        for problem in ProblemCode::ALL {
            let uri = problem.type_uri();
            assert_eq!(uri, type_uri(problem.code()), "{problem}");
            let path = uri
                .strip_prefix(PROBLEM_TYPE_BASE)
                .unwrap_or_else(|| panic!("{problem} resolves under the product prefix"));
            assert!(!path.is_empty(), "{problem}");
            assert!(!path.contains('.'), "{problem}");
            assert_eq!(path, problem.code().replace('.', "/"), "{problem}");
        }
    }

    #[test]
    fn codes_are_unique_and_ordered() {
        let codes: Vec<_> = ProblemCode::ALL.iter().map(|code| code.code()).collect();
        let mut sorted = codes.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(codes, sorted);
    }

    #[test]
    fn the_readiness_probe_is_the_only_undocumented_code() {
        let undocumented: Vec<_> = ProblemCode::ALL
            .iter()
            .filter(|code| !ProblemCode::DOCUMENTED.contains(code))
            .copied()
            .collect();
        assert_eq!(undocumented, vec![ProblemCode::RuntimeNotReady]);
    }

    #[test]
    fn every_code_carries_a_refusal_status_and_its_own_description() {
        for problem in ProblemCode::ALL {
            assert!((400..600).contains(&problem.status()), "{problem}");
            assert_ne!(problem.title(), "Request failed", "{problem}");
            let sharing = ProblemCode::ALL
                .iter()
                .filter(|candidate| candidate.description() == problem.description())
                .count();
            assert_eq!(sharing, 1, "{problem} shares its description");
        }
    }
}
