// SPDX-License-Identifier: Apache-2.0
//! Integration tests for the error taxonomy.
//!
//! These tests pin every code's string, HTTP status, RFC 9457 rendering,
//! and response-extension behavior. They also assert that response
//! payloads never leak internal paths, secrets, or stack traces.

use axum::body::to_bytes;
use axum::http::{self, StatusCode};
use axum::response::IntoResponse;
use registry_relay::audit::ErrorCodeExt;
use registry_relay::error::{
    AdminError, AggregateError, AuthError, ConfigError, Error, FilterError, IngestError,
    InternalError, MetadataError, OgcError, PdpError, QueryError, ReleaseError,
    RuntimeBindingError, SchemaError, SpatialError,
};
use serde_json::Value;

const PROBLEM_JSON: &str = "application/problem+json";
const BASE_TYPE_URL: &str = "https://id.registrystack.org/problems/registry-relay/";

/// Every variant the taxonomy defines. Order is deliberate: keep
/// variants grouped by namespace for reviewability.
fn all_variants() -> Vec<Error> {
    vec![
        // auth.*
        Error::Auth(AuthError::MissingCredential),
        Error::Auth(AuthError::InvalidCredential),
        Error::Auth(AuthError::MalformedCredential),
        Error::Auth(AuthError::ScopeDenied {
            required: "social_registry:rows".to_string(),
        }),
        Error::Auth(AuthError::PurposeRequired),
        Error::Auth(AuthError::PurposeDenied),
        Error::Auth(AuthError::AdminRequired),
        Error::Auth(AuthError::TokenExpired),
        Error::Auth(AuthError::TokenNotYetValid),
        Error::Auth(AuthError::TokenSignatureInvalid),
        Error::Auth(AuthError::IssuerMismatch),
        Error::Auth(AuthError::AudienceMismatch),
        Error::Auth(AuthError::KidUnknown),
        Error::Auth(AuthError::AlgorithmNotAllowed),
        Error::Auth(AuthError::ClientNotAllowed),
        Error::Auth(AuthError::JwksUnavailable),
        Error::Auth(AuthError::RateLimited {
            retry_after_seconds: 30,
        }),
        // pdp.*
        Error::Pdp(PdpError::PurposeNotPermitted),
        Error::Pdp(PdpError::AssuranceInsufficient),
        Error::Pdp(PdpError::EvidenceStale),
        Error::Pdp(PdpError::LegalBasisRequired),
        Error::Pdp(PdpError::ConsentRequired),
        Error::Pdp(PdpError::JurisdictionNotPermitted),
        Error::Pdp(PdpError::UnsupportedPolicyTerm),
        Error::Pdp(PdpError::PolicyIdRequired),
        Error::Pdp(PdpError::PolicyHashInvalid),
        // filter.*
        Error::Filter(FilterError::UnknownField),
        Error::Filter(FilterError::NotAllowed),
        Error::Filter(FilterError::UnsupportedOp),
        Error::Filter(FilterError::InvalidValue),
        Error::Filter(FilterError::TooManyValues),
        Error::Filter(FilterError::TooManyFilters),
        Error::Filter(FilterError::InvalidRange),
        Error::Filter(FilterError::LimitOutOfRange),
        // schema.*
        Error::Schema(SchemaError::UnknownDataset),
        Error::Schema(SchemaError::UnknownResource),
        Error::Schema(SchemaError::UnknownAggregate),
        Error::Schema(SchemaError::ResourceUnavailable),
        // ingest.*
        Error::Ingest(IngestError::SourceNotFound),
        Error::Ingest(IngestError::SourceUnreadable),
        Error::Ingest(IngestError::SchemaMismatch),
        Error::Ingest(IngestError::StrictExtraColumn),
        Error::Ingest(IngestError::CacheWriteFailed),
        Error::Ingest(IngestError::RegistrationFailed),
        // aggregate.*
        Error::Aggregate(AggregateError::ExecutionFailed),
        Error::Aggregate(AggregateError::FormatUnsupported),
        Error::Aggregate(AggregateError::MeasureUnsupported),
        Error::Aggregate(AggregateError::DisclosureViolation),
        Error::Aggregate(AggregateError::FilterRequired {
            required: vec!["municipality".to_string()],
        }),
        // admin.*
        Error::Admin(AdminError::ReloadFailed),
        Error::Admin(AdminError::UnknownResource),
        // config.*
        Error::Config(ConfigError::ParseError),
        Error::Config(ConfigError::ValidationError),
        Error::Config(ConfigError::MissingSecret),
        Error::Config(ConfigError::DuplicateId),
        // metadata.manifest.*
        Error::Metadata(MetadataError::ManifestFileNotFound),
        Error::Metadata(MetadataError::ManifestParseFailed),
        Error::Metadata(MetadataError::ManifestVersionUnsupported),
        Error::Metadata(MetadataError::ManifestValidationFailed),
        // runtime.binding.*
        Error::RuntimeBinding(RuntimeBindingError::DatasetMissing),
        Error::RuntimeBinding(RuntimeBindingError::EntityMissing),
        Error::RuntimeBinding(RuntimeBindingError::TableMissing),
        Error::RuntimeBinding(RuntimeBindingError::FieldMissing),
        Error::RuntimeBinding(RuntimeBindingError::FilterMissing),
        Error::RuntimeBinding(RuntimeBindingError::ScopeMissing),
        Error::RuntimeBinding(RuntimeBindingError::RelationshipMissing),
        Error::RuntimeBinding(RuntimeBindingError::UnsupportedEvidenceOffering),
        // ogc.*
        Error::Ogc(OgcError::CollectionNotFound),
        Error::Ogc(OgcError::FeatureNotFound),
        Error::Ogc(OgcError::RecordNotFound),
        // spatial.*
        Error::Spatial(SpatialError::GeometryInvalid),
        Error::Spatial(SpatialError::GeometryTooLarge),
        Error::Spatial(SpatialError::BboxInvalid),
        Error::Spatial(SpatialError::BboxAntimeridianUnsupported),
        Error::Spatial(SpatialError::FilterUnsupported {
            parameter: "bbox".to_string(),
        }),
        Error::Spatial(SpatialError::CrsUnsupported),
        // query.*
        Error::Query(QueryError::CursorInvalid),
        // release.*
        Error::Release(ReleaseError::ProfileNotFound),
        Error::Release(ReleaseError::SubjectInvalid),
        Error::Release(ReleaseError::SubjectNotFound),
        Error::Release(ReleaseError::SubjectAmbiguous),
        Error::Release(ReleaseError::SubjectReleaseDenied),
        Error::Release(ReleaseError::ClaimUnavailable),
        Error::Release(ReleaseError::SourceUnavailable),
        // internal.*
        Error::Internal(InternalError::Timeout),
        Error::Internal(InternalError::PayloadTooLarge),
        Error::Internal(InternalError::UriTooLong),
        Error::Internal(InternalError::Unhandled),
    ]
}

/// Expected (code, HTTP status) pairs. HTTP status comes from the
/// taxonomy table; for the n/a (startup-only or non-client-facing)
/// codes we expect 500 per the module's documented fallback.
fn expected_table() -> Vec<(&'static str, StatusCode)> {
    vec![
        ("auth.missing_credential", StatusCode::UNAUTHORIZED),
        ("auth.invalid_credential", StatusCode::UNAUTHORIZED),
        ("auth.malformed_credential", StatusCode::UNAUTHORIZED),
        ("auth.scope_denied", StatusCode::FORBIDDEN),
        ("auth.purpose_required", StatusCode::BAD_REQUEST),
        ("auth.purpose_denied", StatusCode::FORBIDDEN),
        ("auth.admin_required", StatusCode::FORBIDDEN),
        ("auth.token_expired", StatusCode::UNAUTHORIZED),
        ("auth.token_not_yet_valid", StatusCode::UNAUTHORIZED),
        ("auth.token_signature_invalid", StatusCode::UNAUTHORIZED),
        ("auth.issuer_mismatch", StatusCode::UNAUTHORIZED),
        ("auth.audience_mismatch", StatusCode::UNAUTHORIZED),
        ("auth.kid_unknown", StatusCode::UNAUTHORIZED),
        ("auth.algorithm_not_allowed", StatusCode::UNAUTHORIZED),
        ("auth.client_not_allowed", StatusCode::FORBIDDEN),
        ("auth.jwks_unavailable", StatusCode::SERVICE_UNAVAILABLE),
        ("auth.rate_limited", StatusCode::TOO_MANY_REQUESTS),
        ("pdp.purpose_not_permitted", StatusCode::FORBIDDEN),
        ("pdp.assurance_insufficient", StatusCode::FORBIDDEN),
        ("pdp.evidence_stale", StatusCode::FORBIDDEN),
        ("pdp.legal_basis_required", StatusCode::FORBIDDEN),
        ("pdp.consent_required", StatusCode::FORBIDDEN),
        ("pdp.jurisdiction_not_permitted", StatusCode::FORBIDDEN),
        ("pdp.unsupported_policy_term", StatusCode::FORBIDDEN),
        ("pdp.policy_id_required", StatusCode::FORBIDDEN),
        ("pdp.policy_hash_invalid", StatusCode::FORBIDDEN),
        ("filter.unknown_field", StatusCode::BAD_REQUEST),
        ("filter.not_allowed", StatusCode::BAD_REQUEST),
        ("filter.unsupported_op", StatusCode::BAD_REQUEST),
        ("filter.invalid_value", StatusCode::BAD_REQUEST),
        // Spec §7.bis.5: filter value list exceeds the configured cap is 413.
        ("filter.too_many_values", StatusCode::PAYLOAD_TOO_LARGE),
        ("filter.too_many_filters", StatusCode::BAD_REQUEST),
        ("filter.invalid_range", StatusCode::BAD_REQUEST),
        ("filter.limit_out_of_range", StatusCode::BAD_REQUEST),
        ("schema.unknown_dataset", StatusCode::NOT_FOUND),
        ("schema.unknown_resource", StatusCode::NOT_FOUND),
        ("schema.unknown_aggregate", StatusCode::NOT_FOUND),
        (
            "schema.resource_unavailable",
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        ("ingest.source_not_found", StatusCode::INTERNAL_SERVER_ERROR),
        (
            "ingest.source_unreadable",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        ("ingest.schema_mismatch", StatusCode::INTERNAL_SERVER_ERROR),
        (
            "ingest.strict_extra_column",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (
            "ingest.cache_write_failed",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (
            "ingest.registration_failed",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (
            "aggregate.execution_failed",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        ("aggregate.format_unsupported", StatusCode::BAD_REQUEST),
        (
            "aggregate.measure_unsupported",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (
            "aggregate.disclosure_violation",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        ("aggregate.filter_required", StatusCode::BAD_REQUEST),
        ("admin.reload_failed", StatusCode::INTERNAL_SERVER_ERROR),
        ("admin.unknown_resource", StatusCode::NOT_FOUND),
        ("config.parse_error", StatusCode::INTERNAL_SERVER_ERROR),
        ("config.validation_error", StatusCode::INTERNAL_SERVER_ERROR),
        ("config.missing_secret", StatusCode::INTERNAL_SERVER_ERROR),
        ("config.duplicate_id", StatusCode::INTERNAL_SERVER_ERROR),
        (
            "metadata.manifest.file_not_found",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (
            "metadata.manifest.parse_failed",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (
            "metadata.manifest.version_unsupported",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (
            "metadata.manifest.validation_failed",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (
            "runtime.binding.dataset_missing",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (
            "runtime.binding.entity_missing",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (
            "runtime.binding.table_missing",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (
            "runtime.binding.field_missing",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (
            "runtime.binding.filter_missing",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (
            "runtime.binding.scope_missing",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (
            "runtime.binding.relationship_missing",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (
            "runtime.binding.unsupported_evidence_offering",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        ("ogc.collection_not_found", StatusCode::NOT_FOUND),
        ("ogc.feature_not_found", StatusCode::NOT_FOUND),
        ("ogc.record_not_found", StatusCode::NOT_FOUND),
        (
            "spatial.geometry_invalid",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        ("spatial.geometry_too_large", StatusCode::PAYLOAD_TOO_LARGE),
        // BboxInvalid and BboxAntimeridianUnsupported intentionally share
        // the stable public code while rendering different details.
        ("spatial.bbox_invalid", StatusCode::BAD_REQUEST),
        ("spatial.bbox_invalid", StatusCode::BAD_REQUEST),
        ("spatial.filter_unsupported", StatusCode::BAD_REQUEST),
        ("spatial.crs_unsupported", StatusCode::BAD_REQUEST),
        ("query.cursor_invalid", StatusCode::BAD_REQUEST),
        // release.*
        ("release.profile_not_found", StatusCode::NOT_FOUND),
        ("release.subject_invalid", StatusCode::BAD_REQUEST),
        // SubjectNotFound, SubjectAmbiguous, SubjectReleaseDenied, ClaimUnavailable
        // all collapse to the same public code and 403.
        ("release.subject_denied", StatusCode::FORBIDDEN),
        ("release.subject_denied", StatusCode::FORBIDDEN),
        ("release.subject_denied", StatusCode::FORBIDDEN),
        ("release.subject_denied", StatusCode::FORBIDDEN),
        (
            "release.source_unavailable",
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        ("internal.timeout", StatusCode::GATEWAY_TIMEOUT),
        ("internal.payload_too_large", StatusCode::PAYLOAD_TOO_LARGE),
        ("internal.uri_too_long", StatusCode::URI_TOO_LONG),
        ("internal.unhandled", StatusCode::INTERNAL_SERVER_ERROR),
    ]
}

/// `code()` and `http_status()` match the public taxonomy for every
/// variant.
#[test]
fn every_variant_matches_taxonomy_table() {
    let variants = all_variants();
    let table = expected_table();
    assert_eq!(
        variants.len(),
        table.len(),
        "variant list and expectation table out of sync"
    );
    for (variant, (code, status)) in variants.iter().zip(table.iter()) {
        assert_eq!(variant.code(), *code, "wrong code() for {variant:?}");
        assert_eq!(
            variant.http_status(),
            *status,
            "wrong http_status() for {variant:?}"
        );
    }
}

/// Convert an `Error` into an axum `Response`, read its body to JSON.
async fn render(err: Error) -> (StatusCode, String, Value) {
    let response = err.into_response();
    let status = response.status();
    let content_type = response
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body read");
    let json: Value = serde_json::from_slice(&body).expect("body is JSON");
    (status, content_type, json)
}

/// Every variant renders as a well-formed RFC 9457 Problem Details
/// response with the expected status, content type, and required
/// fields (`type`, `title`, `status`, `detail`, `code`).
#[tokio::test]
async fn every_variant_renders_as_problem_details() {
    for variant in all_variants() {
        let expected_code = variant.code().to_string();
        let expected_status = variant.http_status();
        let expected_title = variant.title().to_string();
        let expected_detail = variant.detail();
        let (status, content_type, json) = render(variant).await;

        assert_eq!(
            status, expected_status,
            "status mismatch for {expected_code}"
        );
        assert_eq!(
            content_type, PROBLEM_JSON,
            "content-type mismatch for {expected_code}"
        );

        let obj = json.as_object().expect("JSON object");
        assert_eq!(
            obj.get("code").and_then(Value::as_str),
            Some(expected_code.as_str()),
            "code field missing or wrong for {expected_code}"
        );
        assert_eq!(
            obj.get("title").and_then(Value::as_str),
            Some(expected_title.as_str()),
            "title field wrong for {expected_code}"
        );
        assert_eq!(
            obj.get("detail").and_then(Value::as_str),
            Some(expected_detail.as_str()),
            "detail field wrong for {expected_code}"
        );
        assert_eq!(
            obj.get("status").and_then(Value::as_u64),
            Some(u64::from(expected_status.as_u16())),
            "status field wrong for {expected_code}"
        );
        let type_url = obj
            .get("type")
            .and_then(Value::as_str)
            .expect("type field present");
        let expected_type_path = expected_code.replace('.', "/");
        assert_eq!(
            type_url,
            format!("{BASE_TYPE_URL}{expected_type_path}"),
            "type URI wrong for {expected_code}"
        );

        // Defense in depth: no forbidden fields.
        for forbidden in ["stack", "file", "line", "cause", "backtrace"] {
            assert!(
                obj.get(forbidden).is_none(),
                "forbidden field {forbidden} present for {expected_code}"
            );
        }
    }
}

/// `auth.rate_limited` carries a `Retry-After` header so well-behaved
/// clients back off instead of retrying immediately; no other variant
/// sets it.
#[tokio::test]
async fn rate_limited_sets_retry_after_header_and_no_other_variant_does() {
    let response = Error::Auth(AuthError::RateLimited {
        retry_after_seconds: 42,
    })
    .into_response();
    assert_eq!(
        response
            .headers()
            .get(http::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok()),
        Some("42"),
        "Retry-After should carry the configured retry delay"
    );

    for variant in all_variants() {
        if matches!(variant, Error::Auth(AuthError::RateLimited { .. })) {
            continue;
        }
        let response = variant.into_response();
        assert!(
            response.headers().get(http::header::RETRY_AFTER).is_none(),
            "unexpected Retry-After header on a non-rate-limited variant"
        );
    }
}

/// Snapshot one representative variant per namespace so the JSON
/// envelope is reviewed once per family.
#[tokio::test]
async fn snapshot_one_variant_per_namespace() {
    let samples: Vec<(&str, Error)> = vec![
        (
            "auth",
            Error::Auth(AuthError::ScopeDenied {
                required: "social_registry:rows".into(),
            }),
        ),
        ("filter", Error::Filter(FilterError::UnknownField)),
        ("schema", Error::Schema(SchemaError::UnknownDataset)),
        ("ingest", Error::Ingest(IngestError::SchemaMismatch)),
        (
            "aggregate",
            Error::Aggregate(AggregateError::ExecutionFailed),
        ),
        ("admin", Error::Admin(AdminError::ReloadFailed)),
        ("config", Error::Config(ConfigError::MissingSecret)),
        (
            "metadata",
            Error::Metadata(MetadataError::ManifestValidationFailed),
        ),
        (
            "runtime_binding",
            Error::RuntimeBinding(RuntimeBindingError::FieldMissing),
        ),
        ("ogc", Error::Ogc(OgcError::CollectionNotFound)),
        (
            "spatial",
            Error::Spatial(SpatialError::FilterUnsupported {
                parameter: "bbox".into(),
            }),
        ),
        ("query", Error::Query(QueryError::CursorInvalid)),
        ("release", Error::Release(ReleaseError::SubjectNotFound)),
        ("internal", Error::Internal(InternalError::Timeout)),
    ];
    for (namespace, err) in samples {
        let (_status, _ct, json) = render(err).await;
        insta::with_settings!({ snapshot_suffix => namespace }, {
            insta::assert_json_snapshot!(json);
        });
    }
}

/// `Error::into_response` must attach `ErrorCodeExt` to the response so
/// the audit middleware can record the stable taxonomy code on every
/// 4xx/5xx, including the auth short-circuit path that routes through
/// `Error::into_response`. One representative variant per namespace.
#[tokio::test]
async fn error_into_response_attaches_error_code_extension() {
    let samples: Vec<(&str, Error)> = vec![
        (
            "auth.invalid_credential",
            Error::Auth(AuthError::InvalidCredential),
        ),
        (
            "filter.unknown_field",
            Error::Filter(FilterError::UnknownField),
        ),
        (
            "schema.unknown_dataset",
            Error::Schema(SchemaError::UnknownDataset),
        ),
        (
            "ingest.schema_mismatch",
            Error::Ingest(IngestError::SchemaMismatch),
        ),
        (
            "aggregate.execution_failed",
            Error::Aggregate(AggregateError::ExecutionFailed),
        ),
        (
            "admin.reload_failed",
            Error::Admin(AdminError::ReloadFailed),
        ),
        (
            "config.missing_secret",
            Error::Config(ConfigError::MissingSecret),
        ),
        (
            "metadata.manifest.validation_failed",
            Error::Metadata(MetadataError::ManifestValidationFailed),
        ),
        (
            "runtime.binding.field_missing",
            Error::RuntimeBinding(RuntimeBindingError::FieldMissing),
        ),
        (
            "ogc.collection_not_found",
            Error::Ogc(OgcError::CollectionNotFound),
        ),
        (
            "spatial.filter_unsupported",
            Error::Spatial(SpatialError::FilterUnsupported {
                parameter: "bbox".into(),
            }),
        ),
        (
            "query.cursor_invalid",
            Error::Query(QueryError::CursorInvalid),
        ),
        ("internal.timeout", Error::Internal(InternalError::Timeout)),
        // release.*: non-collapsed variants carry their own public code.
        (
            "release.profile_not_found",
            Error::Release(ReleaseError::ProfileNotFound),
        ),
        (
            "release.subject_invalid",
            Error::Release(ReleaseError::SubjectInvalid),
        ),
        // The four collapsed variants must all attach the public code, not
        // their internal audit label.
        (
            "release.subject_denied",
            Error::Release(ReleaseError::SubjectNotFound),
        ),
        (
            "release.subject_denied",
            Error::Release(ReleaseError::SubjectAmbiguous),
        ),
        (
            "release.subject_denied",
            Error::Release(ReleaseError::SubjectReleaseDenied),
        ),
        (
            "release.subject_denied",
            Error::Release(ReleaseError::ClaimUnavailable),
        ),
        (
            "release.source_unavailable",
            Error::Release(ReleaseError::SourceUnavailable),
        ),
    ];
    for (expected, err) in samples {
        let response = err.into_response();
        let ext = response
            .extensions()
            .get::<ErrorCodeExt>()
            .expect("ErrorCodeExt attached to response");
        assert_eq!(ext.0, expected, "wrong error code for {expected}");
    }
}

#[tokio::test]
async fn spatial_filter_unsupported_renders_parameter_extension() {
    let (_, _, body) = render(Error::Spatial(SpatialError::FilterUnsupported {
        parameter: "bbox".to_string(),
    }))
    .await;

    assert_eq!(body["code"], "spatial.filter_unsupported");
    assert_eq!(body["parameter"], "bbox");
}

/// The four denial variants (`SubjectNotFound`, `SubjectAmbiguous`,
/// `SubjectReleaseDenied`, `ClaimUnavailable`) must render byte-identical
/// HTTP responses: same status, same JSON body including `code`, `title`,
/// `detail`, and `type` URI. This is the public collapse required by the
/// spec to prevent subject-existence oracles.
#[tokio::test]
async fn collapsed_subject_denied_variants_render_identically() {
    let collapsed = [
        Error::Release(ReleaseError::SubjectNotFound),
        Error::Release(ReleaseError::SubjectAmbiguous),
        Error::Release(ReleaseError::SubjectReleaseDenied),
        Error::Release(ReleaseError::ClaimUnavailable),
    ];

    let mut rendered: Vec<(StatusCode, Value)> = Vec::new();
    for variant in collapsed {
        let (status, _ct, json) = render(variant).await;
        rendered.push((status, json));
    }

    // All four must be identical.
    let (first_status, ref first_json) = rendered[0];
    for (i, (status, json)) in rendered.iter().enumerate() {
        assert_eq!(
            *status, first_status,
            "status differs at index {i}: {status} vs {first_status}"
        );
        assert_eq!(json, first_json, "JSON body differs at index {i}");
    }

    // Verify the specific expected values.
    assert_eq!(first_status, StatusCode::FORBIDDEN);
    assert_eq!(first_json["code"], "release.subject_denied");
    assert_eq!(first_json["status"], 403u16);
}

/// For the four collapsed denial variants, `audit_code()` must return a
/// distinct internal label (not `"release.subject_denied"`), while
/// `code()` — the public wire value — remains `"release.subject_denied"`.
#[test]
fn audit_code_differs_from_public_code_for_collapsed_variants() {
    let cases = [
        (ReleaseError::SubjectNotFound, "release.subject_not_found"),
        (ReleaseError::SubjectAmbiguous, "release.subject_ambiguous"),
        (
            ReleaseError::SubjectReleaseDenied,
            "release.subject_release_denied",
        ),
        (ReleaseError::ClaimUnavailable, "release.claim_unavailable"),
    ];
    for (variant, expected_audit) in cases {
        let public_code = Error::Release(variant.clone()).code();
        assert_eq!(
            public_code, "release.subject_denied",
            "public code() must be release.subject_denied for {variant:?}"
        );
        assert_eq!(
            variant.audit_code(),
            expected_audit,
            "audit_code() mismatch for {variant:?}"
        );
        assert_ne!(
            variant.audit_code(),
            public_code,
            "audit_code() must differ from public code() for {variant:?}"
        );
    }

    // Non-collapsed variants: audit_code() == code().
    let non_collapsed = [
        ReleaseError::ProfileNotFound,
        ReleaseError::SubjectInvalid,
        ReleaseError::SourceUnavailable,
    ];
    for variant in non_collapsed {
        let public_code = Error::Release(variant.clone()).code();
        assert_eq!(
            variant.audit_code(),
            public_code,
            "non-collapsed audit_code() should equal public code() for {variant:?}"
        );
    }
}

/// `SubjectInvalid` is a 400 Bad Request — it fires before any registry
/// lookup, so it is not subject to the denial collapse.
#[tokio::test]
async fn subject_invalid_is_bad_request_not_forbidden() {
    let (status, _ct, json) = render(Error::Release(ReleaseError::SubjectInvalid)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["code"], "release.subject_invalid");
    assert_eq!(json["status"], 400u16);
}

/// `ProfileNotFound` must return a generic 404 whose `detail` does not
/// mention "profile" by name, preventing profile enumeration.
#[tokio::test]
async fn release_profile_not_found_is_generic_404() {
    let err = Error::Release(ReleaseError::ProfileNotFound);
    // detail() must not contain "profile" (case-insensitive).
    let detail = err.detail();
    assert!(
        !detail.to_lowercase().contains("profile"),
        "detail must not mention 'profile' to prevent enumeration: {detail:?}"
    );
    let (status, _ct, json) = render(err).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(json["code"], "release.profile_not_found");
    assert_eq!(json["status"], 404u16);
    // Verify the body detail also does not mention profile.
    let body_detail = json["detail"].as_str().unwrap_or("");
    assert!(
        !body_detail.to_lowercase().contains("profile"),
        "response detail must not mention 'profile': {body_detail:?}"
    );
}

proptest::proptest! {
    /// Operator-supplied scope names must never escape into the detail
    /// field unscrubbed. Newlines could break the JSONL audit pipeline;
    /// extremely long names are truncated.
    #[test]
    fn scope_denied_detail_is_safe(scope in ".{0,500}") {
        let err = Error::Auth(AuthError::ScopeDenied { required: scope });
        let detail = err.detail();
        proptest::prop_assert!(!detail.contains('\n'), "newline in detail: {detail:?}");
        proptest::prop_assert!(!detail.contains('\r'), "carriage return in detail: {detail:?}");
        proptest::prop_assert!(!detail.contains('\0'), "null byte in detail: {detail:?}");
        proptest::prop_assert!(
            detail.chars().count() <= 200,
            "detail too long: {} chars",
            detail.chars().count()
        );
    }
}

/// Belt-and-suspenders: rendered payloads must not contain substrings
/// that would indicate a leaked secret, path, or stack trace. The
/// stable taxonomy strings (`code` and the `type` URI derived from it)
/// are excluded from the substring check because they are intentional
/// public identifiers. The substring filter targets leaked values
/// (paths, header content, stack traces), not the stable identifier
/// vocabulary.
#[tokio::test]
async fn no_variant_leaks_forbidden_substrings() {
    let forbidden = [
        "password", "secret", "Bearer ", "Argon", "panicked", "/Users/", "/home/", "src/",
    ];
    for variant in all_variants() {
        let code = variant.code().to_string();
        let (_status, _ct, json) = render(variant).await;
        let mut filtered = json.as_object().expect("JSON object").clone();
        filtered.remove("code");
        filtered.remove("type");
        let body = serde_json::to_string(&filtered).expect("serialize back");
        for needle in forbidden {
            assert!(
                !body.contains(needle),
                "variant {code} payload contains forbidden substring {needle:?}: {body}"
            );
        }
    }
}
