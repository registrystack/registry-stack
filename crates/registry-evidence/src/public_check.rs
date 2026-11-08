// SPDX-License-Identifier: Apache-2.0
//! The public certificate check: request shape, check-code comparison and
//! answer for `POST /v1/public-check`.
//!
//! The route takes no credential and reads registry data. A
//! caller presents a document number and the check code printed on the
//! document; Evidence reads the record with its own source credentials,
//! compares the stored code in constant time, and answers with the status
//! and printed fields of the one activated definition. Every miss collapses
//! into one answer so the route reveals nothing beyond what the presented
//! pair proves.

use std::{collections::BTreeMap, fmt};

use chrono::{DateTime, SecondsFormat, Utc};
use registry_platform_crypto::{constant_time_eq, parse_json_strict};
use serde::Serialize;
use serde_json::Value;

use crate::{
    model::{PublicValue, SupportedValue},
    problem::ProblemCode,
};

/// The route path. It is registered only when the target authority
/// activates a public check.
pub const PUBLIC_CHECK_ROUTE: &str = "/v1/public-check";

/// The `schema` member of every successful answer.
pub const PUBLIC_CHECK_ANSWER_SCHEMA: &str = "registry.evidence.public-check/v1alpha1";

/// The only statuses a public check answer may carry.
pub const PUBLIC_CHECK_STATUSES: [&str; 4] = ["valid", "suspended", "revoked", "expired"];

/// RFC 4648 base32 characters in a check code: 15 random bytes, no padding.
pub const CHECK_CODE_LENGTH: usize = 24;

const DOCUMENT_NUMBER_MEMBER: &str = "documentNumber";
const CHECK_CODE_MEMBER: &str = "checkCode";

/// A stored code that is absent or malformed is compared against this value.
/// It lies outside the base32 alphabet, so no presented code can equal it,
/// and every miss performs the same comparison.
const UNMATCHABLE_CODE: [u8; CHECK_CODE_LENGTH] = [0; CHECK_CODE_LENGTH];

/// A check code in its canonical form: 24 characters of `[A-Z2-7]`.
#[derive(Clone, PartialEq, Eq)]
pub struct CheckCode([u8; CHECK_CODE_LENGTH]);

impl CheckCode {
    /// Accept a presented code. ASCII letters are uppercased first; nothing
    /// is stripped, so a code with spaces, hyphens or padding is refused.
    pub fn parse(text: &str) -> Option<Self> {
        Self::from_canonical_bytes(text.as_bytes(), true)
    }

    /// Accept a stored code only in its canonical form. The registry owns
    /// the stored value, so a lowercase or otherwise altered code is a miss.
    fn parse_stored(text: &str) -> Option<Self> {
        Self::from_canonical_bytes(text.as_bytes(), false)
    }

    fn from_canonical_bytes(bytes: &[u8], uppercase: bool) -> Option<Self> {
        let bytes: &[u8; CHECK_CODE_LENGTH] = bytes.try_into().ok()?;
        let mut code = [0; CHECK_CODE_LENGTH];
        for (slot, byte) in code.iter_mut().zip(bytes) {
            let byte = if uppercase {
                byte.to_ascii_uppercase()
            } else {
                *byte
            };
            if !matches!(byte, b'A'..=b'Z' | b'2'..=b'7') {
                return None;
            }
            *slot = byte;
        }
        Some(Self(code))
    }
}

impl fmt::Debug for CheckCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CheckCode(<redacted>)")
    }
}

/// A well-shaped public-check request. The document number is still
/// unvalidated against the activated subject's selector profile.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicCheckRequest {
    pub document_number: String,
    pub check_code: CheckCode,
}

impl fmt::Debug for PublicCheckRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicCheckRequest")
            .field("document_number", &"<redacted>")
            .field("check_code", &self.check_code)
            .finish()
    }
}

/// Parse a request body: one strict JSON object with exactly the two string
/// members and a well-formed check code.
pub fn parse_request(bytes: &[u8]) -> Result<PublicCheckRequest, ProblemCode> {
    let value = parse_json_strict(bytes).map_err(|_| ProblemCode::MalformedRequest)?;
    let Value::Object(members) = value else {
        return Err(ProblemCode::MalformedRequest);
    };
    if members.len() != 2 {
        return Err(ProblemCode::MalformedRequest);
    }
    let text = |name: &str| members.get(name).and_then(Value::as_str);
    let (Some(document_number), Some(check_code)) =
        (text(DOCUMENT_NUMBER_MEMBER), text(CHECK_CODE_MEMBER))
    else {
        return Err(ProblemCode::MalformedRequest);
    };
    let check_code = CheckCode::parse(check_code).ok_or(ProblemCode::MalformedRequest)?;
    Ok(PublicCheckRequest {
        document_number: document_number.to_owned(),
        check_code,
    })
}

/// Compare the presented code with the stored code fact in constant time.
/// An absent, non-string or malformed stored code is a miss and costs the
/// same comparison as a mismatch.
#[must_use]
pub fn stored_code_matches(presented: &CheckCode, stored: Option<&Value>) -> bool {
    let stored = stored
        .and_then(Value::as_str)
        .and_then(CheckCode::parse_stored);
    let stored_bytes = stored.as_ref().map_or(&UNMATCHABLE_CODE, |code| &code.0);
    constant_time_eq(&presented.0, stored_bytes)
}

/// Why validated outputs cannot form a public answer. Each is an evaluation
/// failure, never a miss: the presented code already matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicCheckAnswerError {
    StatusMissing,
    StatusNotText,
    /// The status is text but not one of [`PUBLIC_CHECK_STATUSES`].
    StatusOutsidePublicCheckStatuses,
    FieldsMissing,
    FieldsNotStructured,
}

/// The successful answer body.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicCheckAnswer {
    schema: &'static str,
    status: String,
    fields: BTreeMap<String, Value>,
    observed_at: String,
}

impl PublicCheckAnswer {
    /// Build the answer from the two named outputs only. Any other output on
    /// the definition stays on the relying path.
    pub fn from_values(
        values: &[SupportedValue],
        status_concept: &str,
        fields_concept: &str,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, PublicCheckAnswerError> {
        let value_for = |concept: &str| {
            values
                .iter()
                .find(|value| value.provides_value_for == concept)
                .map(|value| &value.value)
        };
        let status = match value_for(status_concept) {
            Some(PublicValue::String(status)) => status.clone(),
            Some(_) => return Err(PublicCheckAnswerError::StatusNotText),
            None => return Err(PublicCheckAnswerError::StatusMissing),
        };
        if !PUBLIC_CHECK_STATUSES.contains(&status.as_str()) {
            return Err(PublicCheckAnswerError::StatusOutsidePublicCheckStatuses);
        }
        let fields = match value_for(fields_concept) {
            Some(PublicValue::Structured(structured)) => structured.fields.clone(),
            Some(_) => return Err(PublicCheckAnswerError::FieldsNotStructured),
            None => return Err(PublicCheckAnswerError::FieldsMissing),
        };
        Ok(Self {
            schema: PUBLIC_CHECK_ANSWER_SCHEMA,
            status,
            fields,
            observed_at: observed_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        })
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;
    use serde_json::json;

    use super::*;
    use crate::model::{StructuredValue, StructuredValueForm};

    const CODE: &str = "K7QWM4XRT5PZ3NB6VHJYDC2A";

    fn body(value: Value) -> Vec<u8> {
        serde_json::to_vec(&value).expect("test body serializes")
    }

    #[test]
    fn request_with_exactly_two_string_members_parses() {
        let request = parse_request(&body(json!({
            "documentNumber": "RN-2026-004217",
            "checkCode": CODE,
        })))
        .expect("well-shaped request");
        assert_eq!(request.document_number, "RN-2026-004217");
        assert_eq!(
            request.check_code,
            CheckCode::parse(CODE).expect("canonical code")
        );
    }

    #[test]
    fn request_shape_errors_are_malformed_requests() {
        let refused: Vec<Vec<u8>> = vec![
            Vec::new(),
            b"not json".to_vec(),
            body(json!([])),
            body(json!("RN-2026-004217")),
            body(Value::Null),
            body(json!({"documentNumber": "RN-2026-004217"})),
            body(json!({"checkCode": CODE})),
            body(json!({
                "documentNumber": "RN-2026-004217",
                "checkCode": CODE,
                "extra": "member",
            })),
            body(json!({"documentNumber": 4217, "checkCode": CODE})),
            body(json!({"documentNumber": null, "checkCode": CODE})),
            body(json!({"documentNumber": "RN-2026-004217", "checkCode": [CODE]})),
            body(json!({"documentNumber": "RN-2026-004217", "checkCode": {"code": CODE}})),
            format!(
                r#"{{"documentNumber":"RN-2026-004217","checkCode":"{CODE}","checkCode":"{CODE}"}}"#
            )
            .into_bytes(),
            format!(
                r#"{{"documentNumber":"A","documentNumber":"RN-2026-004217","checkCode":"{CODE}"}}"#
            )
            .into_bytes(),
            format!(r#"{{"documentNumber":"RN-2026-004217","checkCode":"{CODE}"}} {{}}"#)
                .into_bytes(),
            body(json!({"documentNumber": "RN-2026-004217", "checkCode": "SHORT"})),
        ];
        for bytes in refused {
            assert_eq!(
                parse_request(&bytes),
                Err(ProblemCode::MalformedRequest),
                "{}",
                String::from_utf8_lossy(&bytes)
            );
        }
    }

    #[test]
    fn check_code_is_uppercased_and_never_stripped() {
        let canonical = CheckCode::parse(CODE).expect("canonical code");
        assert_eq!(
            CheckCode::parse(&CODE.to_ascii_lowercase()),
            Some(canonical.clone())
        );
        assert_eq!(
            CheckCode::parse("k7qwM4XRT5pz3NB6vhjydc2a"),
            Some(canonical)
        );
        assert!(CheckCode::parse("ABCDEFGHIJKLMNOPQRSTUVWXYZ").is_none());
        assert!(CheckCode::parse("234567ABCDEFGHIJKLMNOPQ").is_none());
        assert!(CheckCode::parse("234567ABCDEFGHIJKLMNOPQRS").is_none());
        for refused in ['0', '1', '8', '9', '=', ' ', '-', '\u{e9}', '\u{ff21}'] {
            let mut text: String = CODE.chars().take(CHECK_CODE_LENGTH - 1).collect();
            text.push(refused);
            assert!(CheckCode::parse(&text).is_none(), "{refused:?} refuses");
        }
        assert!(CheckCode::parse("K7QW M4XR T5PZ 3NB6 VHJY DC2A").is_none());
        assert!(CheckCode::parse(" K7QWM4XRT5PZ3NB6VHJYDC2A").is_none());
        assert!(CheckCode::parse("K7QWM4XRT5PZ3NB6VHJYDC2A\n").is_none());
        assert!(CheckCode::parse("").is_none());
    }

    #[test]
    fn debug_output_redacts_the_code_and_number() {
        let request = parse_request(&body(json!({
            "documentNumber": "RN-2026-004217",
            "checkCode": CODE,
        })))
        .expect("well-shaped request");
        let debug = format!("{request:?}");
        assert!(!debug.contains("RN-2026-004217"), "{debug}");
        assert!(!debug.contains(CODE), "{debug}");
    }

    #[test]
    fn only_an_exactly_stored_code_matches() {
        let presented = CheckCode::parse(&CODE.to_ascii_lowercase()).expect("code");
        assert!(stored_code_matches(&presented, Some(&json!(CODE))));
    }

    #[test]
    fn mismatch_absent_and_malformed_stored_codes_are_one_miss() {
        let presented = CheckCode::parse(CODE).expect("code");
        let misses = [
            None,
            Some(json!("AAAAAAAAAAAAAAAAAAAAAAAA")),
            Some(json!(CODE.to_ascii_lowercase())),
            Some(json!(&CODE[..CHECK_CODE_LENGTH - 1])),
            Some(json!(format!("{CODE}A"))),
            Some(json!(format!(" {}", &CODE[1..]))),
            Some(json!("")),
            Some(json!(4217)),
            Some(Value::Null),
            Some(json!([CODE])),
            Some(json!({"code": CODE})),
        ];
        for stored in misses {
            assert!(
                !stored_code_matches(&presented, stored.as_ref()),
                "{stored:?} is a miss"
            );
        }
    }

    fn status(value: &str) -> SupportedValue {
        SupportedValue {
            provides_value_for: "urn:example:concept:certificate-status:v1".to_owned(),
            value: PublicValue::String(value.to_owned()),
        }
    }

    fn printed() -> SupportedValue {
        SupportedValue {
            provides_value_for: "urn:example:concept:certificate-printed:v1".to_owned(),
            value: PublicValue::Structured(StructuredValue {
                form: StructuredValueForm::ReviewedStructuredValue,
                schema: "https://example.org/schemas/printed.json".to_owned(),
                fields: BTreeMap::from([
                    ("holderName".to_owned(), json!("Jordan Sample")),
                    ("expiresOn".to_owned(), json!("2028-02-29")),
                ]),
            }),
        }
    }

    fn extra() -> SupportedValue {
        SupportedValue {
            provides_value_for: "urn:example:concept:certificate-extra:v1".to_owned(),
            value: PublicValue::String("relying-path-only".to_owned()),
        }
    }

    fn observed() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 8, 9, 14, 3)
            .single()
            .expect("valid instant")
            + chrono::Duration::milliseconds(750)
    }

    #[test]
    fn answer_carries_status_inner_fields_and_second_precision_time() {
        let answer = PublicCheckAnswer::from_values(
            &[extra(), printed(), status("valid")],
            "urn:example:concept:certificate-status:v1",
            "urn:example:concept:certificate-printed:v1",
            observed(),
        )
        .expect("answer");
        assert_eq!(
            serde_json::to_value(&answer).expect("answer serializes"),
            json!({
                "schema": "registry.evidence.public-check/v1alpha1",
                "status": "valid",
                "fields": {"holderName": "Jordan Sample", "expiresOn": "2028-02-29"},
                "observedAt": "2026-11-08T09:14:03Z",
            })
        );
    }

    #[test]
    fn answer_refuses_missing_or_mistyped_outputs() {
        let status_concept = "urn:example:concept:certificate-status:v1";
        let fields_concept = "urn:example:concept:certificate-printed:v1";
        let build = |values: &[SupportedValue]| {
            PublicCheckAnswer::from_values(values, status_concept, fields_concept, observed())
        };
        assert_eq!(
            build(&[printed()]),
            Err(PublicCheckAnswerError::StatusMissing)
        );
        assert_eq!(
            build(&[status("valid")]),
            Err(PublicCheckAnswerError::FieldsMissing)
        );
        let mut boolean_status = status("valid");
        boolean_status.value = PublicValue::Boolean(true);
        assert_eq!(
            build(&[boolean_status, printed()]),
            Err(PublicCheckAnswerError::StatusNotText)
        );
        let mut text_fields = printed();
        text_fields.value = PublicValue::String("Jordan Sample".to_owned());
        assert_eq!(
            build(&[status("valid"), text_fields]),
            Err(PublicCheckAnswerError::FieldsNotStructured)
        );
    }

    #[test]
    fn public_check_answer_refuses_a_status_outside_the_four_statuses() {
        let build = |value: &str| {
            PublicCheckAnswer::from_values(
                &[status(value), printed()],
                "urn:example:concept:certificate-status:v1",
                "urn:example:concept:certificate-printed:v1",
                observed(),
            )
        };
        for value in ["valid", "suspended", "revoked", "expired"] {
            assert!(build(value).is_ok(), "{value} is one of the four statuses");
        }
        for value in ["pending", "Valid", "valid ", "", "unknown"] {
            assert_eq!(
                build(value),
                Err(PublicCheckAnswerError::StatusOutsidePublicCheckStatuses),
                "{value:?} is refused"
            );
        }
    }

    #[test]
    fn runtime_and_authoring_agree_on_the_four_statuses() {
        assert_eq!(
            PUBLIC_CHECK_STATUSES,
            registry_evidence_authoring::project::PUBLIC_CHECK_STATUSES
        );
    }
}
