//! The closed public problem body and its mapping onto client failures.
//!
//! The Evidence problem contract is frozen: exactly the members `type`,
//! `title`, `status`, `code`, and `operation`, and nothing that could describe
//! the request, the principal, the source, or the subject. This module parses
//! that body strictly and refuses anything else, so a body a deployment did
//! not promise cannot become a confident diagnostic.

use serde::Deserialize;

use crate::error::EvidenceClientError;

pub(crate) const PROBLEM_MEDIA_TYPE: &str = "application/problem+json";

/// The public code for a request that produced no evidence. It deliberately
/// covers several internal outcomes.
const EVIDENCE_NOT_AVAILABLE: &str = "evidence_not_available";

/// Longest accepted problem body. The closed contract is far smaller.
pub(crate) const MAXIMUM_PROBLEM_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProblemBody {
    #[serde(rename = "type")]
    pub(crate) type_uri: String,
    pub(crate) title: String,
    pub(crate) status: u16,
    pub(crate) code: String,
    pub(crate) operation: String,
}

/// Map a refused or failed exchange onto one coarse client failure.
///
/// `retry_after_seconds` is read from the response header and honored only for
/// the two answers the contract permits a bounded wait on: the rate-limited
/// refusal, and a transient dependency or service failure.
///
/// `header_operation` is the identifier the response header carried, already put
/// through [`sanitized_operation`] by the caller that read the header. It is the
/// fallback for every failure that can name one, because the case where the body
/// cannot be read is exactly the case where the deployment's own identifier for
/// the exchange is all a relying party can take to support. A readable body's own
/// identifier wins when it satisfies the same rule.
pub(crate) fn map_problem(
    status: u16,
    media_type: Option<&str>,
    body: &[u8],
    retry_after_seconds: Option<u64>,
    header_operation: Option<&str>,
) -> EvidenceClientError {
    let Some(problem) = parse_problem(media_type, body) else {
        return EvidenceClientError::Protocol {
            status,
            code: None,
            operation: header_operation.map(str::to_owned),
            retry_after_seconds: None,
        };
    };
    let operation =
        sanitized_operation(&problem.operation).or_else(|| header_operation.map(str::to_owned));
    match (status, problem.code.as_str()) {
        (401 | 403 | 429, code) => EvidenceClientError::Denied {
            status,
            code: code.to_owned(),
            operation,
            retry_after_seconds: retry_after_seconds.filter(|_| status == 429),
        },
        (422, EVIDENCE_NOT_AVAILABLE) => EvidenceClientError::NotAvailable { operation },
        (_, code) => EvidenceClientError::Protocol {
            status,
            code: Some(code.to_owned()),
            operation,
            retry_after_seconds: retry_after_seconds.filter(|_| status == 503),
        },
    }
}

/// Parse a problem body that satisfies the closed contract exactly.
///
/// A wrong media type, an oversized body, an unknown member, a missing member,
/// or a code outside the contract's own shape all yield `None`, which the
/// caller reports as a protocol failure rather than as a refusal it can
/// explain.
fn parse_problem(media_type: Option<&str>, body: &[u8]) -> Option<ProblemBody> {
    if !media_type.is_some_and(|value| essence(value).eq_ignore_ascii_case(PROBLEM_MEDIA_TYPE))
        || body.is_empty()
        || body.len() > MAXIMUM_PROBLEM_BYTES
    {
        return None;
    }
    let problem: ProblemBody = serde_json::from_slice(body).ok()?;
    if !is_contract_code(&problem.code) {
        return None;
    }
    Some(problem)
}

/// The media type without its parameters. Callers compare it case-insensitively,
/// as the media type grammar requires.
pub(crate) fn essence(value: &str) -> &str {
    value.split(';').next().unwrap_or_default().trim()
}

/// The contract's codes are lowercase snake case. Anything else is refused
/// before it can reach a diagnostic or a caller's own log line.
fn is_contract_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 64
        && code.starts_with(|character: char| character.is_ascii_lowercase())
        && code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
}

/// The operation identifier is an opaque support-correlation value. Only a
/// bounded alphanumeric value is kept, so a hostile deployment cannot use it to
/// inject text into a relying party's records.
///
/// This is the one rule, applied to both places the identifier can arrive from:
/// the problem body's own member, and the response header the client reads. The
/// value is judged exactly as received, with no trimming. HTTP field parsing has
/// already removed the optional whitespace the field grammar permits around a
/// header value, and a body member is exact data, so trimming here would only
/// rewrite a value the deployment chose rather than refuse it.
pub(crate) fn sanitized_operation(operation: &str) -> Option<String> {
    let acceptable = !operation.is_empty()
        && operation.len() <= 64
        && operation.bytes().all(|byte| byte.is_ascii_alphanumeric());
    acceptable.then(|| operation.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn problem_json(status: u16, code: &str) -> Vec<u8> {
        format!(
            r#"{{"type":"https://registrystack.org/problems/evidence","title":"Request is not authorized","status":{status},"code":"{code}","operation":"01JQ0QZ8YHZ0000000000000AB"}}"#
        )
        .into_bytes()
    }

    const OPERATION: &str = "01JQ0QZ8YHZ0000000000000AB";

    #[test]
    fn refusals_map_to_the_denied_failure() {
        for (status, code) in [
            (401_u16, "authentication_failed"),
            (403, "not_authorized"),
            (429, "rate_limited"),
        ] {
            let mapped = map_problem(
                status,
                Some(PROBLEM_MEDIA_TYPE),
                &problem_json(status, code),
                Some(1),
                None,
            );
            assert_eq!(
                mapped,
                EvidenceClientError::Denied {
                    status,
                    code: code.to_owned(),
                    operation: Some(OPERATION.to_owned()),
                    // Only the rate-limited answer may carry a wait.
                    retry_after_seconds: (status == 429).then_some(1),
                }
            );
        }
    }

    #[test]
    fn the_unavailable_answer_maps_to_its_own_failure() {
        let mapped = map_problem(
            422,
            Some(PROBLEM_MEDIA_TYPE),
            &problem_json(422, "evidence_not_available"),
            None,
            None,
        );
        assert_eq!(
            mapped,
            EvidenceClientError::NotAvailable {
                operation: Some(OPERATION.to_owned()),
            }
        );
    }

    #[test]
    fn other_contract_codes_map_to_a_protocol_failure() {
        for (status, code) in [
            (400_u16, "malformed_request"),
            (400, "invalid_selector"),
            (406, "response_format_not_acceptable"),
            (503, "dependency_unavailable"),
            (503, "service_unavailable"),
            // A 422 that is not the collapsed answer is not something this
            // client can interpret.
            (422, "malformed_request"),
        ] {
            let mapped = map_problem(
                status,
                Some(PROBLEM_MEDIA_TYPE),
                &problem_json(status, code),
                None,
                None,
            );
            assert_eq!(
                mapped,
                EvidenceClientError::Protocol {
                    status,
                    code: Some(code.to_owned()),
                    operation: Some(OPERATION.to_owned()),
                    retry_after_seconds: None,
                }
            );
        }
    }

    /// The contract permits a bounded wait on a transient failure, which is the
    /// answer a relying party can politely back off from.
    #[test]
    fn a_transient_failure_may_carry_a_bounded_wait() {
        for (status, code, expected_wait) in [
            (503_u16, "dependency_unavailable", Some(30)),
            (503, "service_unavailable", Some(30)),
            // Nothing else in the coarse mapping surfaces a wait.
            (400, "malformed_request", None),
            (406, "response_format_not_acceptable", None),
            (422, "malformed_request", None),
        ] {
            let mapped = map_problem(
                status,
                Some(PROBLEM_MEDIA_TYPE),
                &problem_json(status, code),
                Some(30),
                None,
            );
            assert_eq!(
                mapped,
                EvidenceClientError::Protocol {
                    status,
                    code: Some(code.to_owned()),
                    operation: Some(OPERATION.to_owned()),
                    retry_after_seconds: expected_wait,
                }
            );
        }
    }

    /// The response header is the fallback identifier. The body's own value wins
    /// whenever the body is readable, and both are held to the same rule.
    #[test]
    fn the_response_header_supplies_the_identifier_the_body_does_not() {
        // An unreadable body, so the header is all there is.
        assert_eq!(
            map_problem(400, Some("text/html"), b"<html/>", None, Some(OPERATION)),
            EvidenceClientError::Protocol {
                status: 400,
                code: None,
                operation: Some(OPERATION.to_owned()),
                retry_after_seconds: None,
            }
        );

        // A readable body, whose own identifier is the one to quote.
        assert_eq!(
            map_problem(
                403,
                Some(PROBLEM_MEDIA_TYPE),
                &problem_json(403, "not_authorized"),
                None,
                Some("01HEADERONLY"),
            ),
            EvidenceClientError::Denied {
                status: 403,
                code: "not_authorized".to_owned(),
                operation: Some(OPERATION.to_owned()),
                retry_after_seconds: None,
            }
        );

        // A readable body whose identifier is unusable falls back to the header.
        let hostile = br#"{"type":"about:blank","title":"t","status":403,"code":"not_authorized","operation":"01AB\nrole=subject"}"#;
        assert_eq!(
            map_problem(
                403,
                Some(PROBLEM_MEDIA_TYPE),
                hostile,
                None,
                Some("01HEADERONLY"),
            ),
            EvidenceClientError::Denied {
                status: 403,
                code: "not_authorized".to_owned(),
                operation: Some("01HEADERONLY".to_owned()),
                retry_after_seconds: None,
            }
        );
    }

    /// One rule, for the body's own member and for the header the client reads.
    /// A hostile deployment must not be able to write text of its choosing into a
    /// relying party's records through either.
    #[test]
    fn only_a_bounded_alphanumeric_identifier_is_kept() {
        assert_eq!(
            sanitized_operation(OPERATION),
            Some(OPERATION.to_owned()),
            "the deployment's own identifier shape is kept"
        );
        for hostile in [
            "",
            "01AB\nrole=subject",
            "01AB role=subject",
            "01AB\trole=subject",
            // Surrounding whitespace is not trimmed away, so a value carrying it
            // is refused rather than rewritten.
            " 01AB",
            "01AB ",
            "01AB;binding=urn:evidence:subject:v1_AAA",
            "01AB\u{00e9}",
            &"A".repeat(65),
        ] {
            assert_eq!(
                sanitized_operation(hostile),
                None,
                "{hostile:?} was kept as an identifier"
            );
        }
        assert_eq!(
            sanitized_operation(&"A".repeat(64)),
            Some("A".repeat(64)),
            "the bound itself is acceptable"
        );
    }

    #[test]
    fn a_body_outside_the_closed_contract_is_never_read_as_a_refusal() {
        let unknown_member = br#"{"type":"about:blank","title":"t","status":403,"code":"not_authorized","operation":"01AB","hint":"subject not found"}"#;
        let missing_member =
            br#"{"type":"about:blank","title":"t","status":403,"code":"not_authorized"}"#;
        let wrong_code_shape = br#"{"type":"about:blank","title":"t","status":403,"code":"Not Authorized: subject 42","operation":"01AB"}"#;
        for body in [
            unknown_member.as_slice(),
            missing_member.as_slice(),
            wrong_code_shape.as_slice(),
            b"not json".as_slice(),
            b"".as_slice(),
        ] {
            assert_eq!(
                map_problem(403, Some(PROBLEM_MEDIA_TYPE), body, None, None),
                EvidenceClientError::Protocol {
                    status: 403,
                    code: None,
                    operation: None,
                    retry_after_seconds: None,
                }
            );
        }

        // A body that does not announce itself as a problem document is not
        // parsed at all, whatever it contains.
        assert_eq!(
            map_problem(
                403,
                Some("application/json"),
                &problem_json(403, "not_authorized"),
                None,
                None,
            ),
            EvidenceClientError::Protocol {
                status: 403,
                code: None,
                operation: None,
                retry_after_seconds: None,
            }
        );
        assert_eq!(
            map_problem(403, None, &problem_json(403, "not_authorized"), None, None),
            EvidenceClientError::Protocol {
                status: 403,
                code: None,
                operation: None,
                retry_after_seconds: None,
            }
        );
    }

    #[test]
    fn an_oversized_problem_body_is_refused() {
        let padded = format!(
            r#"{{"type":"{}","title":"t","status":403,"code":"not_authorized","operation":"01AB"}}"#,
            "a".repeat(MAXIMUM_PROBLEM_BYTES)
        );
        assert_eq!(
            map_problem(403, Some(PROBLEM_MEDIA_TYPE), padded.as_bytes(), None, None),
            EvidenceClientError::Protocol {
                status: 403,
                code: None,
                operation: None,
                retry_after_seconds: None,
            }
        );
    }

    #[test]
    fn an_unusable_operation_identifier_is_dropped_not_copied() {
        let hostile = br#"{"type":"about:blank","title":"t","status":403,"code":"not_authorized","operation":"01AB\nrole=subject"}"#;
        assert_eq!(
            map_problem(403, Some(PROBLEM_MEDIA_TYPE), hostile, None, None),
            EvidenceClientError::Denied {
                status: 403,
                code: "not_authorized".to_owned(),
                operation: None,
                retry_after_seconds: None,
            }
        );
    }

    #[test]
    fn the_media_type_is_compared_without_its_parameters() {
        // The grammar makes the type itself case-insensitive, and a parameter is
        // not part of it, so both of these are the contract's media type.
        for media_type in [
            "application/problem+json; charset=utf-8",
            "Application/Problem+JSON",
        ] {
            let mapped = map_problem(
                403,
                Some(media_type),
                &problem_json(403, "not_authorized"),
                None,
                None,
            );
            assert!(
                matches!(mapped, EvidenceClientError::Denied { .. }),
                "{media_type}"
            );
        }
    }
}
