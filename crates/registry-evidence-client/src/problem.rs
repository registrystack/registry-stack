//! The closed public problem body and its mapping onto client failures.
//!
//! Evidence problems have exactly the six RFC 9457-style members `type`,
//! `title`, `status`, `detail`, `code`, and `traceId`. Their trace identifier
//! must agree with the response's `traceparent`; otherwise neither correlation
//! nor the problem classification is trustworthy.

use serde::Deserialize;

use crate::error::EvidenceClientError;

pub(crate) const PROBLEM_MEDIA_TYPE: &str = "application/problem+json";
pub(crate) const TRACEPARENT_HEADER: &str = "traceparent";
const PROBLEM_TYPE_PREFIX: &str = "https://id.registrystack.org/problems/registry-evidence/";
const EVIDENCE_NOT_AVAILABLE: &str = "evidence.unavailable";

/// Longest accepted problem body. The closed contract is far smaller.
pub(crate) const MAXIMUM_PROBLEM_BYTES: usize = 4 * 1024;

const REGISTERED_PROBLEMS: [(u16, &str, &str, &str); 10] = [
    (
        400,
        "evidence.invalid_request",
        "Evidence request is invalid",
        "the Evidence request is invalid",
    ),
    (
        400,
        "request.selector_invalid",
        "Selector is invalid",
        "selector does not match an available request profile",
    ),
    (
        401,
        "auth.invalid_credential",
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
        "evidence.rate_limited",
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
        "resource.not_found",
        "Requested resource was not found",
        "the requested resource was not found",
    ),
];

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ProblemBody {
    #[serde(rename = "type")]
    type_uri: String,
    title: String,
    status: u16,
    detail: String,
    code: String,
    #[serde(rename = "traceId")]
    trace_id: String,
}

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
    let code = REGISTERED_PROBLEMS
        .iter()
        .find(|(registered_status, registered_code, _, _)| {
            *registered_status == status && *registered_code == problem.code
        })
        .map(|(_, registered_code, _, _)| *registered_code);
    match (status, code) {
        (401 | 403 | 429, Some(code)) => EvidenceClientError::Denied {
            status,
            code: code.to_owned(),
            trace_id: Some(problem.trace_id),
            retry_after_seconds: retry_after_seconds.filter(|_| status == 429),
        },
        (422, Some(EVIDENCE_NOT_AVAILABLE)) => EvidenceClientError::NotAvailable {
            trace_id: Some(problem.trace_id),
        },
        (_, code) => protocol(status, header_trace_id, code.map(str::to_owned)),
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

/// Parse an exact six-member problem body, including its registered type URI.
fn parse_problem(media_type: Option<&str>, body: &[u8]) -> Option<ProblemBody> {
    if !media_type.is_some_and(|value| essence(value).eq_ignore_ascii_case(PROBLEM_MEDIA_TYPE))
        || body.is_empty()
        || body.len() > MAXIMUM_PROBLEM_BYTES
    {
        return None;
    }
    let problem: ProblemBody = serde_json::from_slice(body).ok()?;
    if !is_canonical_trace_id(&problem.trace_id)
        || !REGISTERED_PROBLEMS
            .iter()
            .any(|(status, code, title, detail)| {
                *status == problem.status
                    && *code == problem.code
                    && *title == problem.title
                    && *detail == problem.detail
            })
        || problem.type_uri != expected_type_uri(&problem.code)
    {
        return None;
    }
    Some(problem)
}

fn expected_type_uri(code: &str) -> String {
    format!("{}{}", PROBLEM_TYPE_PREFIX, code.replace('.', "/"))
}

/// The media type without its parameters.
pub(crate) fn essence(value: &str) -> &str {
    value.split(';').next().unwrap_or_default().trim()
}

/// Parse one exact lower-case W3C Trace Context version 0 header and return
/// its canonical 32-character trace ID.
pub(crate) fn trace_id_from_traceparent(value: &str) -> Option<String> {
    let mut parts = value.split('-');
    let [version, trace_id, parent_id, flags] =
        [parts.next()?, parts.next()?, parts.next()?, parts.next()?];
    if parts.next().is_some()
        || version != "00"
        || !is_canonical_trace_id(trace_id)
        || !is_nonzero_lower_hex(parent_id, 16)
        || !is_lower_hex(flags, 2)
    {
        return None;
    }
    Some(trace_id.to_owned())
}

pub(crate) fn is_canonical_trace_id(value: &str) -> bool {
    is_nonzero_lower_hex(value, 32)
}

fn is_nonzero_lower_hex(value: &str, length: usize) -> bool {
    is_lower_hex(value, length) && value.bytes().any(|byte| byte != b'0')
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
            (401, "auth.invalid_credential", "denied"),
            (403, "evidence.denied", "denied"),
            (429, "evidence.rate_limited", "denied"),
            (422, EVIDENCE_NOT_AVAILABLE, "not_available"),
            (400, "evidence.invalid_request", "protocol"),
            (404, "resource.not_found", "protocol"),
            (503, "source.unavailable", "protocol"),
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
    fn malformed_unknown_or_mismatched_problems_are_protocol() {
        let good = problem_json(403, "evidence.denied", TRACE_ID);
        let mut wrong_title: serde_json::Value =
            serde_json::from_slice(&good).expect("the fixture is JSON");
        wrong_title["title"] = serde_json::json!("Example problem");
        let mut wrong_detail = wrong_title.clone();
        wrong_detail["title"] = serde_json::json!("Evidence request is not permitted");
        wrong_detail["detail"] = serde_json::json!("The request could not be completed.");
        for (body, header) in [
            (good.clone(), Some("0123456789abcdef0123456789abcdef")),
            (br#"{"type":"about:blank"}"#.to_vec(), Some(TRACE_ID)),
            (
                serde_json::to_vec(&wrong_title).expect("the fixture serializes"),
                Some(TRACE_ID),
            ),
            (
                serde_json::to_vec(&wrong_detail).expect("the fixture serializes"),
                Some(TRACE_ID),
            ),
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
