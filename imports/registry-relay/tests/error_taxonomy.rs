// SPDX-License-Identifier: Apache-2.0
//! Integration tests for the error taxonomy.
//!
//! These tests pin the stable wire contract from `decisions/wave-0.md`
//! Section 4: every code's string, HTTP status, RFC 9457 rendering, and
//! the bi-directional invariant that the documentation table and the
//! enum variants stay in lock-step. They also assert that response
//! payloads never leak internal paths, secrets, or stack traces.

use std::collections::BTreeSet;

use axum::body::to_bytes;
use axum::http::{self, StatusCode};
use axum::response::IntoResponse;
use data_gate::audit::ErrorCodeExt;
use data_gate::error::{
    AdminError, AggregateError, AuthError, ConfigError, Error, FilterError, IngestError,
    InternalError, SchemaError,
};
use serde_json::Value;

const PROBLEM_JSON: &str = "application/problem+json";
const BASE_TYPE_URL: &str = "https://data.example.gov/problems/";

/// Every variant the taxonomy defines. Order is deliberate: matches the
/// taxonomy table in `decisions/wave-0.md` Section 4 top-to-bottom.
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
        Error::Auth(AuthError::AdminRequired),
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
        Error::Aggregate(AggregateError::MeasureUnsupported),
        Error::Aggregate(AggregateError::DisclosureViolation),
        // admin.*
        Error::Admin(AdminError::ReloadFailed),
        Error::Admin(AdminError::UnknownResource),
        // config.*
        Error::Config(ConfigError::ParseError),
        Error::Config(ConfigError::ValidationError),
        Error::Config(ConfigError::MissingSecret),
        Error::Config(ConfigError::DuplicateId),
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
        ("auth.admin_required", StatusCode::FORBIDDEN),
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
        (
            "aggregate.measure_unsupported",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (
            "aggregate.disclosure_violation",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        ("admin.reload_failed", StatusCode::INTERNAL_SERVER_ERROR),
        ("admin.unknown_resource", StatusCode::NOT_FOUND),
        ("config.parse_error", StatusCode::INTERNAL_SERVER_ERROR),
        ("config.validation_error", StatusCode::INTERNAL_SERVER_ERROR),
        ("config.missing_secret", StatusCode::INTERNAL_SERVER_ERROR),
        ("config.duplicate_id", StatusCode::INTERNAL_SERVER_ERROR),
        ("internal.timeout", StatusCode::GATEWAY_TIMEOUT),
        ("internal.payload_too_large", StatusCode::PAYLOAD_TOO_LARGE),
        ("internal.uri_too_long", StatusCode::URI_TOO_LONG),
        ("internal.unhandled", StatusCode::INTERNAL_SERVER_ERROR),
    ]
}

/// `code()` and `http_status()` match the architect taxonomy for every
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
        ("internal", Error::Internal(InternalError::Timeout)),
    ];
    for (namespace, err) in samples {
        let (_status, _ct, json) = render(err).await;
        insta::with_settings!({ snapshot_suffix => namespace }, {
            insta::assert_json_snapshot!(json);
        });
    }
}

/// Parse `decisions/wave-0.md` Section 4 and extract every code in
/// backticked table cells matching `[a-z_.]+`. Assert that the set of
/// codes in the doc equals the set of `code()` strings on every
/// variant.
#[test]
fn code_set_matches_decisions_doc() {
    let doc = include_str!("../decisions/wave-0.md");
    let section_start = doc
        .find("## 4. Error Taxonomy")
        .expect("Section 4 heading present");
    let section_end = doc[section_start..]
        .find("\n## 5.")
        .map(|i| section_start + i)
        .expect("Section 5 heading present");
    let section = &doc[section_start..section_end];

    let doc_codes: BTreeSet<String> = section
        .lines()
        .filter_map(extract_code_from_table_row)
        .collect();

    let variant_codes: BTreeSet<String> = all_variants()
        .iter()
        .map(|v| v.code().to_string())
        .collect();

    let only_in_doc: Vec<_> = doc_codes.difference(&variant_codes).collect();
    let only_in_code: Vec<_> = variant_codes.difference(&doc_codes).collect();
    assert!(
        only_in_doc.is_empty() && only_in_code.is_empty(),
        "taxonomy drift: doc-only={only_in_doc:?}, code-only={only_in_code:?}"
    );
}

/// Pull the first backticked token out of a markdown table row whose
/// first cell looks like `| \`auth.foo\` | 401 | ... |`.
fn extract_code_from_table_row(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let rest = trimmed.strip_prefix("| `")?;
    let end = rest.find('`')?;
    let candidate = &rest[..end];
    if candidate.is_empty() {
        return None;
    }
    if !candidate
        .chars()
        .all(|c| c.is_ascii_lowercase() || c == '.' || c == '_')
    {
        return None;
    }
    if !candidate.contains('.') {
        return None;
    }
    Some(candidate.to_string())
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
        ("internal.timeout", Error::Internal(InternalError::Timeout)),
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
/// stable taxonomy strings (`code` and the `type` URI derived from
/// it) are excluded from the substring check because they are pinned
/// by `decisions/wave-0.md` Section 4: e.g. `config.missing_secret`
/// is the taxonomy-mandated name and is verified in
/// `code_set_matches_decisions_doc`. The substring filter targets
/// leaked VALUES (paths, header content, stack traces), not the
/// stable identifier vocabulary.
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
