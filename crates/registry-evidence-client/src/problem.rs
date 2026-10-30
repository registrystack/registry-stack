//! The bounded public problem body and its mapping onto client failures.
//!
//! Evidence problems require the six RFC 9457-style members `type`, `title`,
//! `status`, `detail`, `code`, and `traceId`, and may gain additive members.
//! Their trace identifier must agree with the response's `traceparent`;
//! otherwise neither correlation nor the problem classification is trustworthy.

use registry_platform_httpsec::ProblemDocument;

use crate::error::EvidenceClientError;

pub(crate) const PROBLEM_MEDIA_TYPE: &str = "application/problem+json";
#[cfg(test)]
pub(crate) const TRACEPARENT_HEADER: &str = "traceparent";
const PROBLEM_TYPE_PREFIX: &str = "https://id.registrystack.org/problems/registry-evidence/";
const EVIDENCE_NOT_AVAILABLE: &str = "evidence.unavailable";

/// Longest accepted problem body. The closed contract is far smaller.
pub(crate) const MAXIMUM_PROBLEM_BYTES: usize = 4 * 1024;

const REGISTERED_PROBLEMS: [(u16, &str, &str, &str); 10] = [
    (
        400,
        "evidence.invalid-request",
        "Evidence request is invalid",
        "the Evidence request is invalid",
    ),
    (
        400,
        "request.selector-invalid",
        "Selector is invalid",
        "selector does not match an available request profile",
    ),
    (
        401,
        "auth.invalid-credential",
        "Bearer access token is invalid",
        "bearer access token validation failed",
    ),
    (
        403,
        "evidence.denied",
        "Evidence request is not permitted",
        "the Evidence request is not permitted",
    ),
    (
        406,
        "format.unsupported",
        "Requested format is not supported",
        "the requested format is not supported",
    ),
    (
        422,
        EVIDENCE_NOT_AVAILABLE,
        "Evidence could not be produced",
        "evidence could not be produced for this request",
    ),
    (
        429,
        "evidence.rate-limited",
        "Evidence request rate is exhausted",
        "the Evidence request rate is exhausted",
    ),
    (
        503,
        "source.unavailable",
        "Authoritative source is unavailable",
        "the authoritative source is unavailable",
    ),
    (
        503,
        "service.unavailable",
        "Service is unavailable",
        "the request could not be served",
    ),
    (
        404,
        "resource.not-found",
        "Requested resource was not found",
        "the requested resource was not found",
    ),
];

/// Map a refused or failed exchange onto one coarse client failure.
///
/// `Retry-After` is actionable only for a registered 429 response. The caller
/// passes the trace ID extracted from an exact v0 `traceparent`, never a
/// caller-controlled outbound context.
pub(crate) fn map_problem(
    status: u16,
    media_type: Option<&str>,
    body: &[u8],
    retry_after_seconds: Option<u64>,
    header_trace_id: Option<&str>,
) -> EvidenceClientError {
    let Some(problem) = parse_problem(media_type, body) else {
        return protocol(status, header_trace_id, None);
    };
    if problem.status != status || header_trace_id != Some(problem.trace_id.as_str()) {
        return protocol(status, header_trace_id, None);
    }
    if !(400..=599).contains(&status)
        || !valid_problem_code(&problem.code)
        || problem.type_uri != expected_type_uri(&problem.code)
    {
        return protocol(status, header_trace_id, None);
    }
    let registered = REGISTERED_PROBLEMS
        .iter()
        .find(|(_, registered_code, _, _)| *registered_code == problem.code);
    if registered.is_some_and(|(registered_status, _, _, _)| *registered_status != status) {
        return protocol(status, header_trace_id, None);
    }
    match (status, registered.map(|(_, code, _, _)| *code)) {
        (401 | 403 | 429, code) => EvidenceClientError::Denied {
            status,
            code: code.unwrap_or(problem.code.as_str()).to_owned(),
            trace_id: Some(problem.trace_id.as_str().to_owned()),
            retry_after_seconds: retry_after_seconds.filter(|_| status == 429),
        },
        (422, Some(EVIDENCE_NOT_AVAILABLE)) => EvidenceClientError::NotAvailable {
            trace_id: Some(problem.trace_id.as_str().to_owned()),
        },
        (422, None) => EvidenceClientError::NotAvailable {
            trace_id: Some(problem.trace_id.as_str().to_owned()),
        },
        (400..=499, code) => EvidenceClientError::InvalidRequest {
            status,
            code: code.unwrap_or(problem.code.as_str()).to_owned(),
            trace_id: Some(problem.trace_id.as_str().to_owned()),
        },
        (500..=599, code) => EvidenceClientError::Unavailable {
            status,
            code: code.unwrap_or(problem.code.as_str()).to_owned(),
            trace_id: Some(problem.trace_id.as_str().to_owned()),
        },
        _ => protocol(status, header_trace_id, None),
    }
}

fn protocol(status: u16, trace_id: Option<&str>, code: Option<String>) -> EvidenceClientError {
    EvidenceClientError::Protocol {
        status,
        code,
        trace_id: trace_id.map(str::to_owned),
        retry_after_seconds: None,
    }
}

/// Parse the required common problem members under the response-size bound.
fn parse_problem(media_type: Option<&str>, body: &[u8]) -> Option<ProblemDocument> {
    if !media_type.is_some_and(|value| essence(value).eq_ignore_ascii_case(PROBLEM_MEDIA_TYPE))
        || body.is_empty()
        || body.len() > MAXIMUM_PROBLEM_BYTES
    {
        return None;
    }
    ProblemDocument::parse_exact(body, MAXIMUM_PROBLEM_BYTES).ok()
}

fn expected_type_uri(code: &str) -> String {
    format!("{}{}", PROBLEM_TYPE_PREFIX, code.replace('.', "/"))
}

fn valid_problem_code(code: &str) -> bool {
    if code.is_empty() || code.len() > 128 {
        return false;
    }
    let mut segments = code.split('.');
    let Some(family) = segments.next() else {
        return false;
    };
    let Some(reason) = segments.next() else {
        return false;
    };
    segments.next().is_none()
        && valid_problem_code_segment(family)
        && valid_problem_code_segment(reason)
}

fn valid_problem_code_segment(segment: &str) -> bool {
    segment
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_lowercase())
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// The media type without its parameters.
pub(crate) fn essence(value: &str) -> &str {
    value.split(';').next().unwrap_or_default().trim()
}

/// Parse one exact lower-case W3C Trace Context version 0 header and return
/// its canonical 32-character trace ID.
#[cfg(test)]
fn trace_id_from_traceparent(value: &str) -> Option<String> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        "traceparent",
        reqwest::header::HeaderValue::from_str(value).ok()?,
    );
    registry_platform_httpsec::response_trace_id(&headers)
        .ok()
        .map(|trace_id| trace_id.as_str().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
    const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    fn problem_json(status: u16, code: &str, trace_id: &str) -> Vec<u8> {
        let (_, _, title, detail) = REGISTERED_PROBLEMS
            .iter()
            .find(|(registered_status, registered_code, _, _)| {
                *registered_status == status && *registered_code == code
            })
            .expect("the fixture names a registered problem");
        serde_json::to_vec(&serde_json::json!({
            "type": expected_type_uri(code),
            "title": title,
            "status": status,
            "detail": detail,
            "code": code,
            "traceId": trace_id,
        }))
        .expect("the fixture serializes")
    }

    #[test]
    fn strict_v0_traceparent_extracts_only_a_canonical_trace_id() {
        assert_eq!(
            trace_id_from_traceparent(TRACEPARENT),
            Some(TRACE_ID.to_owned())
        );
        for invalid in [
            "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
        ] {
            assert_eq!(trace_id_from_traceparent(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn exact_registered_problems_preserve_the_typed_mapping() {
        for (status, code, kind) in [
            (401, "auth.invalid-credential", "denied"),
            (403, "evidence.denied", "denied"),
            (429, "evidence.rate-limited", "denied"),
            (422, EVIDENCE_NOT_AVAILABLE, "not-available"),
            (400, "evidence.invalid-request", "invalid-request"),
            (400, "request.selector-invalid", "invalid-request"),
            (406, "format.unsupported", "invalid-request"),
            (404, "resource.not-found", "invalid-request"),
            (503, "source.unavailable", "unavailable"),
            (503, "service.unavailable", "unavailable"),
        ] {
            let mapped = map_problem(
                status,
                Some(PROBLEM_MEDIA_TYPE),
                &problem_json(status, code, TRACE_ID),
                Some(1),
                Some(TRACE_ID),
            );
            assert_eq!(mapped.kind(), kind, "{status} {code}");
            assert_eq!(mapped.trace_id(), Some(TRACE_ID));
            assert_eq!(
                matches!(
                    mapped,
                    EvidenceClientError::Denied {
                        retry_after_seconds: Some(1),
                        ..
                    }
                ),
                status == 429
            );
        }
    }

    #[test]
    fn unknown_valid_codes_fall_back_by_http_status() {
        for (status, code, kind) in [
            (400, "request.future-invalid", "invalid-request"),
            (403, "evidence.future-denial", "denied"),
            (422, "evidence.future-unavailable", "not-available"),
            (503, "service.future-unavailable", "unavailable"),
        ] {
            let body = serde_json::to_vec(&serde_json::json!({
                "type": expected_type_uri(code),
                "title": "Future problem prose",
                "status": status,
                "detail": "Future detail prose.",
                "code": code,
                "traceId": TRACE_ID,
            }))
            .expect("the fixture serializes");
            let mapped = map_problem(
                status,
                Some(PROBLEM_MEDIA_TYPE),
                &body,
                Some(1),
                Some(TRACE_ID),
            );
            assert_eq!(mapped.kind(), kind, "{status} {code}");
            assert_eq!(mapped.trace_id(), Some(TRACE_ID));
        }
    }

    #[test]
    fn invalid_code_spelling_remains_a_protocol_failure() {
        for (status, registered, underscored) in [
            (401, "auth.invalid-credential", "auth.invalid_credential"),
            (429, "evidence.rate-limited", "evidence.rate_limited"),
            (400, "evidence.invalid-request", "evidence.invalid_request"),
            (400, "request.selector-invalid", "request.selector_invalid"),
            (404, "resource.not-found", "resource.not_found"),
        ] {
            let mut body: serde_json::Value =
                serde_json::from_slice(&problem_json(status, registered, TRACE_ID))
                    .expect("the fixture is JSON");
            body["code"] = serde_json::json!(underscored);
            body["type"] = serde_json::json!(expected_type_uri(underscored));
            let mapped = map_problem(
                status,
                Some(PROBLEM_MEDIA_TYPE),
                &serde_json::to_vec(&body).expect("the fixture serializes"),
                Some(1),
                Some(TRACE_ID),
            );
            assert!(
                matches!(mapped, EvidenceClientError::Protocol { code: None, .. }),
                "{status} {underscored}"
            );
        }
    }

    #[test]
    fn problem_prose_and_additive_members_do_not_change_classification() {
        let good = problem_json(403, "evidence.denied", TRACE_ID);
        let mut changed: serde_json::Value =
            serde_json::from_slice(&good).expect("the fixture is JSON");
        changed["title"] = serde_json::json!("Example problem");
        changed["detail"] = serde_json::json!("The request could not be completed.");
        changed["futureMember"] = serde_json::json!({"nested": true});
        let mapped = map_problem(
            403,
            Some(PROBLEM_MEDIA_TYPE),
            &serde_json::to_vec(&changed).expect("the fixture serializes"),
            Some(1),
            Some(TRACE_ID),
        );
        assert!(matches!(
            mapped,
            EvidenceClientError::Denied { ref code, .. } if code == "evidence.denied"
        ));
    }

    #[test]
    fn malformed_or_mismatched_problems_are_protocol() {
        let good = problem_json(403, "evidence.denied", TRACE_ID);
        for (body, header) in [
            (good.clone(), Some("0123456789abcdef0123456789abcdef")),
            (br#"{"type":"about:blank"}"#.to_vec(), Some(TRACE_ID)),
            (
                problem_json(403, "evidence.denied", "4bf92f3577b34da6a3ce929d0e0e4736"),
                None,
            ),
        ] {
            let mapped = map_problem(403, Some(PROBLEM_MEDIA_TYPE), &body, Some(1), header);
            assert!(matches!(mapped, EvidenceClientError::Protocol { .. }));
        }
    }
}
