// SPDX-License-Identifier: Apache-2.0
//! Stable HTTP wire-contract identifiers shared by Registry Relay V2 and its clients.
//!
//! This crate intentionally has no runtime or HTTP-framework dependency. Response
//! serialization, headers, and trace context remain owned by the Relay runtime.

/// RFC 9457 media type emitted for Relay problem responses.
pub const PROBLEM_MEDIA_TYPE: &str = "application/problem+json";

/// Fixed Relay V2 HTTP route templates.
pub mod routes {
    /// Process liveness probe.
    pub const HEALTH: &str = "/health";
    /// Compiled Registry readiness probe.
    pub const READY: &str = "/ready";
    /// Public OpenAPI projection.
    pub const OPENAPI: &str = "/openapi.json";
    /// Registry service metadata.
    pub const SERVICE: &str = "/v2";
    /// Registry resource collection.
    pub const RESOURCES: &str = "/v2/resources";
    /// Registry resource metadata.
    pub const RESOURCE: &str = "/v2/resources/{resource}";
    /// Consultation List operation.
    pub const RECORDS: &str = "/v2/resources/{resource}/records";
    /// Consultation Retrieve operation.
    pub const RECORD: &str = "/v2/resources/{resource}/records/{record_identifier}";
    /// Consultation Lookup operation.
    pub const LOOKUP: &str = "/v2/resources/{resource}/lookups/{lookup}";
    /// Consultation Search operation.
    pub const SEARCH: &str = "/v2/resources/{resource}/searches/{search}";
    /// Generated artifact retrieval.
    pub const ARTIFACT: &str = "/v2/artifacts/{artifact_identifier}";
    /// SDMX Aggregate Data with an explicit key.
    pub const SDMX_DATA_KEY: &str = "/sdmx/v2/data/{context}/{agency}/{resource}/{version}/{key}";
    /// SDMX Aggregate Data with an omitted key.
    pub const SDMX_DATA: &str = "/sdmx/v2/data/{context}/{agency}/{resource}/{version}";
    /// SDMX structure retrieval.
    pub const SDMX_STRUCTURE: &str =
        "/sdmx/v2/structure/{artefact_type}/{agency}/{resource}/{version}";

    /// Complete fixed Relay V2 route inventory, in router registration order.
    pub const ALL: &[&str] = &[
        HEALTH,
        READY,
        OPENAPI,
        SERVICE,
        RESOURCES,
        RESOURCE,
        RECORDS,
        RECORD,
        LOOKUP,
        SEARCH,
        ARTIFACT,
        SDMX_DATA_KEY,
        SDMX_DATA,
        SDMX_STRUCTURE,
    ];
}

macro_rules! define_problem_codes {
    ($(
        $variant:ident => {
            code: $code:literal,
            title: $title:literal,
            status: $status:literal,
            detail: $detail:literal,
            type_uri: $type_uri:literal
        }
    ),+ $(,)?) => {
        /// Closed public failure classes for the Relay V2 HTTP boundary.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum ProblemCode {
            $($variant),+
        }

        impl ProblemCode {
            /// Complete public problem inventory in stable catalog order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            #[must_use]
            pub const fn code(self) -> &'static str {
                match self {
                    $(Self::$variant => $code),+
                }
            }

            #[must_use]
            pub const fn title(self) -> &'static str {
                match self {
                    $(Self::$variant => $title),+
                }
            }

            #[must_use]
            pub const fn status(self) -> u16 {
                match self {
                    $(Self::$variant => $status),+
                }
            }

            #[must_use]
            pub const fn detail(self) -> &'static str {
                match self {
                    $(Self::$variant => $detail),+
                }
            }

            #[must_use]
            pub const fn type_uri(self) -> &'static str {
                match self {
                    $(Self::$variant => $type_uri),+
                }
            }
        }
    };
}

define_problem_codes! {
    ConsultationInvalidRequest => { code: "consultation.invalid_request", title: "Consultation request is invalid", status: 400, detail: "the consultation request is invalid", type_uri: "https://id.registrystack.org/problems/registry-relay/consultation/invalid_request" },
    AggregateDataInvalidRequest => { code: "aggregate-data.invalid_request", title: "Aggregate data request is invalid", status: 400, detail: "the aggregate data request is invalid", type_uri: "https://id.registrystack.org/problems/registry-relay/aggregate-data/invalid_request" },
    FieldsInvalid => { code: "request.fields_invalid", title: "Field selection is invalid", status: 400, detail: "field selection is invalid", type_uri: "https://id.registrystack.org/problems/registry-relay/request/fields_invalid" },
    UnknownFilter => { code: "filter.unknown_field", title: "Filter is not declared", status: 400, detail: "filter is not declared for this operation", type_uri: "https://id.registrystack.org/problems/registry-relay/filter/unknown_field" },
    InvalidFilter => { code: "filter.invalid_value", title: "Filter value is invalid", status: 400, detail: "filter value is invalid", type_uri: "https://id.registrystack.org/problems/registry-relay/filter/invalid_value" },
    CursorInvalid => { code: "query.cursor_invalid", title: "Cursor is invalid", status: 400, detail: "cursor is invalid for this query", type_uri: "https://id.registrystack.org/problems/registry-relay/query/cursor_invalid" },
    AccessProfileInvalid => { code: "request.access_profile_invalid", title: "Access profile selection is invalid", status: 400, detail: "access profile selection is invalid", type_uri: "https://id.registrystack.org/problems/registry-relay/request/access_profile_invalid" },
    MissingCredential => { code: "auth.missing_credential", title: "Bearer access token is required", status: 401, detail: "a bearer access token is required", type_uri: "https://id.registrystack.org/problems/registry-relay/auth/missing_credential" },
    InvalidCredential => { code: "auth.invalid_credential", title: "Bearer access token is invalid", status: 401, detail: "bearer access token validation failed", type_uri: "https://id.registrystack.org/problems/registry-relay/auth/invalid_credential" },
    ConsultationDenied => { code: "consultation.denied", title: "Consultation is not permitted", status: 403, detail: "the consultation is not permitted", type_uri: "https://id.registrystack.org/problems/registry-relay/consultation/denied" },
    AggregateDataDenied => { code: "aggregate-data.denied", title: "Aggregate data access is not permitted", status: 403, detail: "aggregate data access is not permitted", type_uri: "https://id.registrystack.org/problems/registry-relay/aggregate-data/denied" },
    ResourceNotFound => { code: "resource.not_found", title: "Requested resource was not found", status: 404, detail: "the requested resource was not found", type_uri: "https://id.registrystack.org/problems/registry-relay/resource/not_found" },
    ConsultationUnresolved => { code: "consultation.unresolved", title: "Requested record was not resolved", status: 404, detail: "the requested record was not resolved", type_uri: "https://id.registrystack.org/problems/registry-relay/consultation/unresolved" },
    UnsupportedFormat => { code: "format.unsupported", title: "Requested format is not supported", status: 406, detail: "the requested format is not supported", type_uri: "https://id.registrystack.org/problems/registry-relay/format/unsupported" },
    BodyTooLarge => { code: "internal.payload_too_large", title: "Request body is too large", status: 413, detail: "request body exceeds the configured limit", type_uri: "https://id.registrystack.org/problems/registry-relay/internal/payload_too_large" },
    ConsultationResponseTooLarge => { code: "consultation.response_too_large", title: "Consultation response is too large", status: 413, detail: "the consultation response exceeds the configured limit", type_uri: "https://id.registrystack.org/problems/registry-relay/consultation/response_too_large" },
    AggregateDataTooLarge => { code: "aggregate-data.too_large", title: "Aggregate data request is too broad", status: 413, detail: "the aggregate data request exceeds its observation limit", type_uri: "https://id.registrystack.org/problems/registry-relay/aggregate-data/too_large" },
    UriTooLong => { code: "internal.uri_too_long", title: "Request URI is too long", status: 414, detail: "request URI exceeds the configured limit", type_uri: "https://id.registrystack.org/problems/registry-relay/internal/uri_too_long" },
    UnsupportedMediaType => { code: "request.media_type_unsupported", title: "Request media type is not supported", status: 415, detail: "request body must use application/json", type_uri: "https://id.registrystack.org/problems/registry-relay/request/media_type_unsupported" },
    RateLimited => { code: "consultation.rate_limited", title: "Consultation quota is exhausted", status: 429, detail: "the consultation quota is exhausted", type_uri: "https://id.registrystack.org/problems/registry-relay/consultation/rate_limited" },
    AggregateDataRateLimited => { code: "aggregate-data.rate_limited", title: "Aggregate data quota is exhausted", status: 429, detail: "the aggregate data quota is exhausted", type_uri: "https://id.registrystack.org/problems/registry-relay/aggregate-data/rate_limited" },
    Internal => { code: "internal.unhandled", title: "Request could not be served", status: 500, detail: "the request could not be served", type_uri: "https://id.registrystack.org/problems/registry-relay/internal/unhandled" },
    SourceUnavailable => { code: "source.unavailable", title: "Authoritative source is unavailable", status: 503, detail: "the authoritative source is unavailable", type_uri: "https://id.registrystack.org/problems/registry-relay/source/unavailable" },
    AuditUnavailable => { code: "audit.unavailable", title: "Required audit is unavailable", status: 503, detail: "required audit is unavailable", type_uri: "https://id.registrystack.org/problems/registry-relay/audit/unavailable" },
    ServiceNotReady => { code: "service.not_ready", title: "Service is not ready", status: 503, detail: "the service is not ready", type_uri: "https://id.registrystack.org/problems/registry-relay/service/not_ready" },
    Timeout => { code: "internal.timeout", title: "Request timed out", status: 504, detail: "request exceeded the configured timeout", type_uri: "https://id.registrystack.org/problems/registry-relay/internal/timeout" },
}

impl std::fmt::Display for ProblemCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

#[cfg(test)]
mod tests {
    use super::{routes, ProblemCode, PROBLEM_MEDIA_TYPE};

    #[test]
    fn fixed_route_inventory_is_exact() {
        assert_eq!(
            routes::ALL,
            [
                "/health",
                "/ready",
                "/openapi.json",
                "/v2",
                "/v2/resources",
                "/v2/resources/{resource}",
                "/v2/resources/{resource}/records",
                "/v2/resources/{resource}/records/{record_identifier}",
                "/v2/resources/{resource}/lookups/{lookup}",
                "/v2/resources/{resource}/searches/{search}",
                "/v2/artifacts/{artifact_identifier}",
                "/sdmx/v2/data/{context}/{agency}/{resource}/{version}/{key}",
                "/sdmx/v2/data/{context}/{agency}/{resource}/{version}",
                "/sdmx/v2/structure/{artefact_type}/{agency}/{resource}/{version}",
            ]
        );
    }

    #[test]
    fn problem_catalog_uses_the_exact_stable_identifier_uris() {
        assert_eq!(PROBLEM_MEDIA_TYPE, "application/problem+json");
        assert_eq!(
            ProblemCode::ALL
                .iter()
                .copied()
                .map(|problem| (problem.code(), problem.type_uri()))
                .collect::<Vec<_>>(),
            vec![
                ("consultation.invalid_request", "https://id.registrystack.org/problems/registry-relay/consultation/invalid_request"),
                ("aggregate-data.invalid_request", "https://id.registrystack.org/problems/registry-relay/aggregate-data/invalid_request"),
                ("request.fields_invalid", "https://id.registrystack.org/problems/registry-relay/request/fields_invalid"),
                ("filter.unknown_field", "https://id.registrystack.org/problems/registry-relay/filter/unknown_field"),
                ("filter.invalid_value", "https://id.registrystack.org/problems/registry-relay/filter/invalid_value"),
                ("query.cursor_invalid", "https://id.registrystack.org/problems/registry-relay/query/cursor_invalid"),
                ("request.access_profile_invalid", "https://id.registrystack.org/problems/registry-relay/request/access_profile_invalid"),
                ("auth.missing_credential", "https://id.registrystack.org/problems/registry-relay/auth/missing_credential"),
                ("auth.invalid_credential", "https://id.registrystack.org/problems/registry-relay/auth/invalid_credential"),
                ("consultation.denied", "https://id.registrystack.org/problems/registry-relay/consultation/denied"),
                ("aggregate-data.denied", "https://id.registrystack.org/problems/registry-relay/aggregate-data/denied"),
                ("resource.not_found", "https://id.registrystack.org/problems/registry-relay/resource/not_found"),
                ("consultation.unresolved", "https://id.registrystack.org/problems/registry-relay/consultation/unresolved"),
                ("format.unsupported", "https://id.registrystack.org/problems/registry-relay/format/unsupported"),
                ("internal.payload_too_large", "https://id.registrystack.org/problems/registry-relay/internal/payload_too_large"),
                ("consultation.response_too_large", "https://id.registrystack.org/problems/registry-relay/consultation/response_too_large"),
                ("aggregate-data.too_large", "https://id.registrystack.org/problems/registry-relay/aggregate-data/too_large"),
                ("internal.uri_too_long", "https://id.registrystack.org/problems/registry-relay/internal/uri_too_long"),
                ("request.media_type_unsupported", "https://id.registrystack.org/problems/registry-relay/request/media_type_unsupported"),
                ("consultation.rate_limited", "https://id.registrystack.org/problems/registry-relay/consultation/rate_limited"),
                ("aggregate-data.rate_limited", "https://id.registrystack.org/problems/registry-relay/aggregate-data/rate_limited"),
                ("internal.unhandled", "https://id.registrystack.org/problems/registry-relay/internal/unhandled"),
                ("source.unavailable", "https://id.registrystack.org/problems/registry-relay/source/unavailable"),
                ("audit.unavailable", "https://id.registrystack.org/problems/registry-relay/audit/unavailable"),
                ("service.not_ready", "https://id.registrystack.org/problems/registry-relay/service/not_ready"),
                ("internal.timeout", "https://id.registrystack.org/problems/registry-relay/internal/timeout"),
            ]
        );
    }

    #[test]
    fn problem_catalog_metadata_is_complete_and_value_free() {
        for problem in ProblemCode::ALL {
            assert!(!problem.title().is_empty());
            assert!((400..=599).contains(&problem.status()));
            assert!(!problem.detail().is_empty());
            assert!(problem
                .type_uri()
                .starts_with("https://id.registrystack.org/problems/registry-relay/"));
        }
    }
}
