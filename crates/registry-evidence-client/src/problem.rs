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
/// the rate-limited answer, which is the one case the contract permits it for.
pub(crate) fn map_problem(
    status: u16,
    media_type: Option<&str>,
    body: &[u8],
    retry_after_seconds: Option<u64>,
) -> EvidenceClientError {
    let Some(problem) = parse_problem(media_type, body) else {
        return EvidenceClientError::Protocol {
            status,
            code: None,
            operation: None,
        };
    };
    let operation = sanitized_operation(&problem.operation);
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
    if media_type.map(essence) != Some(PROBLEM_MEDIA_TYPE.to_owned())
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

/// The lowercase media type without parameters.
pub(crate) fn essence(value: &str) -> String {
    value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
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
fn sanitized_operation(operation: &str) -> Option<String> {
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
            );
            assert_eq!(
                mapped,
                EvidenceClientError::Denied {
                    status,
                    code: code.to_owned(),
                    operation: Some("01JQ0QZ8YHZ0000000000000AB".to_owned()),
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
        );
        assert_eq!(
            mapped,
            EvidenceClientError::NotAvailable {
                operation: Some("01JQ0QZ8YHZ0000000000000AB".to_owned()),
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
            );
            assert_eq!(
                mapped,
                EvidenceClientError::Protocol {
                    status,
                    code: Some(code.to_owned()),
                    operation: Some("01JQ0QZ8YHZ0000000000000AB".to_owned()),
                }
            );
        }
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
                map_problem(403, Some(PROBLEM_MEDIA_TYPE), body, None),
                EvidenceClientError::Protocol {
                    status: 403,
                    code: None,
                    operation: None,
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
                None
            ),
            EvidenceClientError::Protocol {
                status: 403,
                code: None,
                operation: None,
            }
        );
        assert_eq!(
            map_problem(403, None, &problem_json(403, "not_authorized"), None),
            EvidenceClientError::Protocol {
                status: 403,
                code: None,
                operation: None,
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
            map_problem(403, Some(PROBLEM_MEDIA_TYPE), padded.as_bytes(), None),
            EvidenceClientError::Protocol {
                status: 403,
                code: None,
                operation: None,
            }
        );
    }

    #[test]
    fn an_unusable_operation_identifier_is_dropped_not_copied() {
        let hostile = br#"{"type":"about:blank","title":"t","status":403,"code":"not_authorized","operation":"01AB\nsubject=Amina"}"#;
        assert_eq!(
            map_problem(403, Some(PROBLEM_MEDIA_TYPE), hostile, None),
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
        let mapped = map_problem(
            403,
            Some("application/problem+json; charset=utf-8"),
            &problem_json(403, "not_authorized"),
            None,
        );
        assert!(matches!(mapped, EvidenceClientError::Denied { .. }));
    }
}
