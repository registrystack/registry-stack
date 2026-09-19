// SPDX-License-Identifier: Apache-2.0

//! The handler message: what a handler returns for one envelope.
//!
//! Exactly one of three answers. A `proposal` is a product-typed document; the
//! library validates only its size and that it is canonical JSON, and the
//! product validates its meaning. `none` is the notification answer: the
//! handler observed and proposes nothing. A `refusal` carries a bounded code
//! and a bounded summary; in phase `before` it refuses the triggering change,
//! in phase `after` it is recorded and the hook completes.
//!
//! Every named bound here is enforced, never truncated, on both the
//! construction and the deserialization path. A bound that a second truncation
//! silently shadows is a bound that is not enforced.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use registry_platform_canonical_json::{canonicalize_json, parse_json_strict, JcsError};

use crate::error::{bounded_token, redacted_message, ErrorCategory};

/// The handler output ceiling, in bytes.
///
/// Mirrors `registry-platform-script`'s `Budgets::default().max_output_bytes`
/// (1 MiB). An executor run may carry a tighter per-run ceiling; it can only
/// tighten this, never widen it.
pub const MAX_OUTPUT_BYTES: usize = 1_048_576;

/// The refusal code ceiling, in bytes.
pub const MAX_REFUSAL_CODE_BYTES: usize = 128;

/// The refusal summary ceiling, in bytes.
pub const MAX_REFUSAL_SUMMARY_BYTES: usize = 1_024;

/// Ceilings for one handler message.
///
/// The default is [`MAX_OUTPUT_BYTES`]. An executor run may carry a
/// tighter per-run ceiling; tightening is the only direction available, so the
/// ceiling is not a public field and [`HandlerOutputLimits::tightened_to`]
/// clamps a wider request back to [`MAX_OUTPUT_BYTES`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandlerOutputLimits {
    max_output_bytes: usize,
}

impl HandlerOutputLimits {
    /// Tighten the output ceiling to `bytes`.
    ///
    /// A request above [`MAX_OUTPUT_BYTES`] is clamped to it rather
    /// than refused: a per-run ceiling is a tightening, and a caller that asks
    /// for more gets the library's ceiling, never more than it.
    #[must_use]
    pub const fn tightened_to(bytes: usize) -> Self {
        Self {
            max_output_bytes: if bytes < MAX_OUTPUT_BYTES {
                bytes
            } else {
                MAX_OUTPUT_BYTES
            },
        }
    }

    /// The effective ceiling in bytes.
    #[must_use]
    pub const fn max_output_bytes(&self) -> usize {
        self.max_output_bytes
    }
}

impl Default for HandlerOutputLimits {
    fn default() -> Self {
        Self {
            max_output_bytes: MAX_OUTPUT_BYTES,
        }
    }
}

/// A product-typed request for a follow-up change.
///
/// The library never opens this document: it checks only that the message
/// carrying it is within the output ceiling and is canonical JSON. Validating
/// and applying the proposal is the product's job, through its existing
/// validator, authorization, and audit path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HookProposal(pub Value);

/// A text value with a hard byte ceiling, enforced everywhere.
///
/// Both directions are enforced: constructing one from an over-bound string is
/// refused, and deserializing one from over-bound JSON is refused, never
/// truncated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct BoundedText<const MAX_BYTES: usize>(String);

impl<const MAX_BYTES: usize> BoundedText<MAX_BYTES> {
    /// Construct from a string, enforcing the ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedTextError`] for empty text or text over the ceiling.
    pub fn new(text: String) -> Result<Self, BoundedTextError> {
        if text.is_empty() {
            return Err(BoundedTextError::Empty);
        }
        if text.len() > MAX_BYTES {
            return Err(BoundedTextError::TooLong {
                size: text.len(),
                max: MAX_BYTES,
            });
        }
        Ok(Self(text))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<const MAX_BYTES: usize> TryFrom<String> for BoundedText<MAX_BYTES> {
    type Error = BoundedTextError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::new(text)
    }
}

impl<const MAX_BYTES: usize> TryFrom<&str> for BoundedText<MAX_BYTES> {
    type Error = BoundedTextError;

    fn try_from(text: &str) -> Result<Self, Self::Error> {
        Self::new(text.to_owned())
    }
}

impl<const MAX_BYTES: usize> std::fmt::Display for BoundedText<MAX_BYTES> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de, const MAX_BYTES: usize> Deserialize<'de> for BoundedText<MAX_BYTES> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(serde::de::Error::custom)
    }
}

/// A bounded-text refusal.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum BoundedTextError {
    /// The text is empty.
    #[error("bounded text must not be empty")]
    Empty,
    /// The text exceeds its ceiling.
    #[error("text of {size} bytes exceeds the {max}-byte ceiling")]
    TooLong { size: usize, max: usize },
}

/// What a handler returns for one envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    tag = "answer",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum HookMessage {
    /// A product-typed proposal for a follow-up change.
    Proposal {
        /// The proposal document.
        document: HookProposal,
    },
    /// The handler observed and proposes nothing. This is the notification
    /// answer.
    #[serde(rename = "none")]
    Nothing,
    /// The handler refuses. In phase `before` this refuses the triggering
    /// change; in phase `after` it is recorded and the hook completes.
    Refusal {
        /// A bounded, stable refusal code the product defines.
        code: BoundedText<MAX_REFUSAL_CODE_BYTES>,
        /// A bounded, human-readable summary.
        summary: BoundedText<MAX_REFUSAL_SUMMARY_BYTES>,
    },
}

impl<'de> Deserialize<'de> for HookMessage {
    // Deserialization is manual because a derived internally tagged enum
    // silently ignores fields it does not know on the contentless `none`
    // answer, and the contract requires each answer to carry exactly its own
    // fields and nothing else.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use std::collections::BTreeMap;

        use serde::de::Error as _;

        let fields = BTreeMap::<String, Value>::deserialize(deserializer)?;
        let answer = fields
            .get("answer")
            .ok_or_else(|| D::Error::missing_field("answer"))?
            .as_str()
            .ok_or_else(|| D::Error::custom("`answer` must be a string"))?;
        match answer {
            "proposal" => {
                refuse_extra_fields::<D>(&fields, &["answer", "document"])?;
                let document = fields
                    .get("document")
                    .cloned()
                    .ok_or_else(|| D::Error::missing_field("document"))?;
                Ok(Self::Proposal {
                    document: HookProposal::deserialize(document).map_err(D::Error::custom)?,
                })
            }
            "none" => {
                refuse_extra_fields::<D>(&fields, &["answer"])?;
                Ok(Self::Nothing)
            }
            "refusal" => {
                refuse_extra_fields::<D>(&fields, &["answer", "code", "summary"])?;
                let code = fields
                    .get("code")
                    .cloned()
                    .ok_or_else(|| D::Error::missing_field("code"))?;
                let summary = fields
                    .get("summary")
                    .cloned()
                    .ok_or_else(|| D::Error::missing_field("summary"))?;
                Ok(Self::Refusal {
                    code: BoundedText::deserialize(code).map_err(D::Error::custom)?,
                    summary: BoundedText::deserialize(summary).map_err(D::Error::custom)?,
                })
            }
            unknown => Err(D::Error::unknown_variant(
                &bounded_token(unknown),
                &["proposal", "none", "refusal"],
            )),
        }
    }
}

fn refuse_extra_fields<'de, D>(
    fields: &std::collections::BTreeMap<String, Value>,
    allowed: &'static [&'static str],
) -> Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;

    fields
        .keys()
        .find(|key| !allowed.contains(&key.as_str()))
        .map_or(Ok(()), |key| {
            Err(D::Error::unknown_field(&bounded_token(key), allowed))
        })
}

impl HookMessage {
    /// Decode one handler message from untrusted bytes.
    ///
    /// The ceiling is checked before anything is parsed. The bytes must be
    /// canonical JSON (RFC 8785): the shared strict parser rejects duplicate
    /// members and integer tokens that are not exactly representable as
    /// binary64, and the bytes must equal their own canonicalization.
    ///
    /// # Errors
    ///
    /// Returns [`HookMessageError`] when the message is over the ceiling, is
    /// not strict or canonical JSON, violates the message shape, or carries a
    /// refusal outside its bounds.
    pub fn from_canonical_json(
        bytes: &[u8],
        limits: &HandlerOutputLimits,
    ) -> Result<Self, HookMessageError> {
        if bytes.len() > limits.max_output_bytes {
            return Err(HookMessageError::OutputTooLarge {
                size: bytes.len(),
                max: limits.max_output_bytes,
            });
        }
        let value = parse_json_strict(bytes)?;
        let canonical = canonicalize_json(&value).map_err(HookMessageError::Canonical)?;
        if canonical.as_slice() != bytes {
            return Err(HookMessageError::NotCanonical);
        }
        serde_json::from_value(value)
            .map_err(|error| HookMessageError::Shape(redacted_message(&error.to_string())))
    }

    /// Encode one handler message as canonical JSON (RFC 8785).
    ///
    /// The same output ceiling the decode path enforces applies here, so a
    /// message a caller builds in memory can never exceed a bound a message
    /// arriving from a handler would have been refused for.
    ///
    /// # Errors
    ///
    /// Returns [`HookMessageError`] when the message carries a proposal that
    /// cannot be canonicalized, or when the encoded bytes exceed the ceiling.
    pub fn to_canonical_json(
        &self,
        limits: &HandlerOutputLimits,
    ) -> Result<Vec<u8>, HookMessageError> {
        let value = serde_json::to_value(self)
            .map_err(|error| HookMessageError::Shape(redacted_message(&error.to_string())))?;
        let bytes = canonicalize_json(&value).map_err(HookMessageError::Canonical)?;
        if bytes.len() > limits.max_output_bytes {
            return Err(HookMessageError::OutputTooLarge {
                size: bytes.len(),
                max: limits.max_output_bytes,
            });
        }
        Ok(bytes)
    }
}

/// Failure to decode one handler message.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HookMessageError {
    /// The message exceeds the configured output ceiling.
    #[error("handler message of {size} bytes exceeds the {max}-byte output ceiling")]
    OutputTooLarge { size: usize, max: usize },
    /// The message is not strict JSON.
    #[error("handler message is not strict JSON: {0}")]
    Json(#[from] registry_platform_canonical_json::StrictJsonError),
    /// The message is valid JSON but not canonical.
    #[error("handler message is not canonical JSON")]
    NotCanonical,
    /// The message violates the message shape. The deserializer's own
    /// wording, with the untrusted values it repeats redacted and bounded.
    #[error("handler message violates the hook message shape: {0}")]
    Shape(String),
    /// The message carries a number that cannot be canonicalized.
    #[error("handler message is not canonicalizable: {0}")]
    Canonical(#[from] JcsError),
}

impl HookMessageError {
    /// The stable diagnostic code for this failure.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::OutputTooLarge { .. } => "hook.message.output_too_large",
            Self::Json(_) => "hook.message.not_strict_json",
            Self::NotCanonical => "hook.message.not_canonical",
            Self::Shape(_) => "hook.message.bad_shape",
            Self::Canonical(_) => "hook.message.not_canonicalizable",
        }
    }

    /// The run-time failure category, per the taxonomy's mapping: a body over
    /// the ceiling is `Resource`; a malformed or non-canonical body is
    /// `Source`. The same categories hold for both local kinds (an output
    /// ceiling, a malformed outcome document) and the `url` kind (a response
    /// body over the ceiling, a malformed response body).
    #[must_use]
    pub const fn category(&self) -> ErrorCategory {
        match self {
            Self::OutputTooLarge { .. } => ErrorCategory::Resource,
            Self::Json(_) | Self::NotCanonical | Self::Shape(_) | Self::Canonical(_) => {
                ErrorCategory::Source
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::error::MAX_DISPLAYED_TOKEN_BYTES;
    use serde_json::json;

    fn canonical_bytes(value: &Value) -> Vec<u8> {
        canonicalize_json(value).expect("test fixture canonicalizes")
    }

    fn proposal_message() -> Value {
        json!({
            "answer": "proposal",
            "document": {
                "kind": "action-outcome",
                "writes": [{"field": "familyName", "value": "Kalanni"}],
            },
        })
    }

    /// The three byte strings below are the handler ABI: a handler writes them
    /// and the library reads them. Changing any of them changes what an already
    /// deployed handler must emit, so it is a new handler ABI version, never a
    /// fix inside `registry.hook-handler/v1`.
    #[test]
    fn the_handler_message_wire_shape_is_pinned() {
        let limits = HandlerOutputLimits::default();
        for (message, pinned) in [
            (
                HookMessage::Proposal {
                    document: HookProposal(json!({"kind": "action-outcome"})),
                },
                r#"{"answer":"proposal","document":{"kind":"action-outcome"}}"#,
            ),
            (HookMessage::Nothing, r#"{"answer":"none"}"#),
            (
                HookMessage::Refusal {
                    code: BoundedText::try_from("eligibility.missing_evidence")
                        .expect("within the code bound"),
                    summary: BoundedText::try_from("no verified evidence for the requirement")
                        .expect("within the summary bound"),
                },
                concat!(
                    r#"{"answer":"refusal","code":"eligibility.missing_evidence","#,
                    r#""summary":"no verified evidence for the requirement"}"#,
                ),
            ),
        ] {
            let bytes = message.to_canonical_json(&limits).expect("encodes");
            assert_eq!(String::from_utf8(bytes.clone()).expect("UTF-8"), pinned);
            assert_eq!(
                HookMessage::from_canonical_json(&bytes, &limits).expect("decodes"),
                message,
                "the pinned bytes decode to the answer they were written from"
            );
        }
    }

    #[test]
    fn decodes_and_round_trips_a_proposal() {
        let limits = HandlerOutputLimits::default();
        let bytes = canonical_bytes(&proposal_message());
        let message = HookMessage::from_canonical_json(&bytes, &limits).expect("decodes");
        let HookMessage::Proposal { document } = &message else {
            panic!("expected a proposal, got {message:?}");
        };
        assert_eq!(
            document.0,
            json!({
                "kind": "action-outcome",
                "writes": [{"field": "familyName", "value": "Kalanni"}],
            })
        );

        assert_eq!(
            message.to_canonical_json(&limits).expect("encodes"),
            bytes,
            "the encoder reproduces the bytes it decoded"
        );
    }

    #[test]
    fn none_is_the_notification_answer() {
        let limits = HandlerOutputLimits::default();
        let bytes = canonical_bytes(&json!({"answer": "none"}));
        let message = HookMessage::from_canonical_json(&bytes, &limits).expect("decodes");
        assert_eq!(message, HookMessage::Nothing);
        assert_eq!(
            message.to_canonical_json(&limits).expect("encodes"),
            bytes,
            "the encoder reproduces the bytes it decoded"
        );
    }

    #[test]
    fn decodes_a_refusal_within_its_bounds() {
        let limits = HandlerOutputLimits::default();
        let bytes = canonical_bytes(&json!({
            "answer": "refusal",
            "code": "eligibility.missing_evidence",
            "summary": "no verified evidence for the residence requirement",
        }));
        let message = HookMessage::from_canonical_json(&bytes, &limits).expect("decodes");
        let HookMessage::Refusal { code, summary } = &message else {
            panic!("expected a refusal, got {message:?}");
        };
        assert_eq!(code.as_str(), "eligibility.missing_evidence");
        assert_eq!(
            summary.as_str(),
            "no verified evidence for the residence requirement"
        );

        assert_eq!(
            message.to_canonical_json(&limits).expect("encodes"),
            bytes,
            "the encoder reproduces the bytes it decoded"
        );
    }

    #[test]
    fn constructs_bounded_refusal_text_and_enforces_the_bound() {
        let code = "x".repeat(MAX_REFUSAL_CODE_BYTES);
        let at_bound = BoundedText::<MAX_REFUSAL_CODE_BYTES>::new(code.clone())
            .expect("exactly at the bound is accepted");
        assert_eq!(at_bound.as_str().len(), MAX_REFUSAL_CODE_BYTES);

        let error = BoundedText::<MAX_REFUSAL_CODE_BYTES>::new(format!("{code}x"))
            .expect_err("one byte over the bound is refused");
        assert_eq!(
            error,
            BoundedTextError::TooLong {
                size: MAX_REFUSAL_CODE_BYTES + 1,
                max: MAX_REFUSAL_CODE_BYTES,
            }
        );

        let error = BoundedText::<MAX_REFUSAL_CODE_BYTES>::new(String::new())
            .expect_err("an empty code is refused");
        assert_eq!(error, BoundedTextError::Empty);

        let summary = "y".repeat(MAX_REFUSAL_SUMMARY_BYTES);
        assert!(BoundedText::<MAX_REFUSAL_SUMMARY_BYTES>::new(summary).is_ok());
        assert!(BoundedText::<MAX_REFUSAL_SUMMARY_BYTES>::new(
            "z".repeat(MAX_REFUSAL_SUMMARY_BYTES + 1)
        )
        .is_err());
    }

    #[test]
    fn the_deserialize_path_enforces_the_bounds_and_never_truncates() {
        let limits = HandlerOutputLimits::default();
        // One byte over the code bound: refused, not truncated to the bound.
        let over_bound_code = "x".repeat(MAX_REFUSAL_CODE_BYTES + 1);
        let bytes = canonical_bytes(&json!({
            "answer": "refusal",
            "code": over_bound_code,
            "summary": "ok",
        }));
        let error = HookMessage::from_canonical_json(&bytes, &limits)
            .expect_err("an over-bound code must not pass through");
        assert!(error.to_string().contains("128-byte ceiling"), "{error}");

        let over_bound_summary = "y".repeat(MAX_REFUSAL_SUMMARY_BYTES + 1);
        let bytes = canonical_bytes(&json!({
            "answer": "refusal",
            "code": "ok",
            "summary": over_bound_summary,
        }));
        let error = HookMessage::from_canonical_json(&bytes, &limits)
            .expect_err("an over-bound summary must not pass through");
        assert!(error.to_string().contains("1024-byte ceiling"), "{error}");

        // Exactly at each bound: accepted.
        let bytes = canonical_bytes(&json!({
            "answer": "refusal",
            "code": "x".repeat(MAX_REFUSAL_CODE_BYTES),
            "summary": "y".repeat(MAX_REFUSAL_SUMMARY_BYTES),
        }));
        assert!(HookMessage::from_canonical_json(&bytes, &limits).is_ok());
    }

    #[test]
    fn flips_the_output_ceiling_at_a_non_default_value() {
        let bytes = canonical_bytes(&proposal_message());

        let tight = HandlerOutputLimits::tightened_to(bytes.len() - 1);
        let error = HookMessage::from_canonical_json(&bytes, &tight)
            .expect_err("refused above the non-default ceiling");
        assert_eq!(error.code(), "hook.message.output_too_large");
        assert_eq!(error.category(), ErrorCategory::Resource);
        assert!(
            error.to_string().contains("byte output ceiling"),
            "the ceiling is named: {error}"
        );

        let generous = HandlerOutputLimits::tightened_to(bytes.len());
        assert!(
            HookMessage::from_canonical_json(&bytes, &generous).is_ok(),
            "accepted below (at) the non-default ceiling"
        );
    }

    #[test]
    fn the_encode_path_flips_the_output_ceiling_at_a_non_default_value() {
        let bytes = canonical_bytes(&proposal_message());
        let limits = HandlerOutputLimits::default();
        let message = HookMessage::from_canonical_json(&bytes, &limits).expect("decodes");

        let tight = HandlerOutputLimits::tightened_to(bytes.len() - 1);
        let error = message
            .to_canonical_json(&tight)
            .expect_err("refused above the non-default ceiling");
        assert_eq!(error.code(), "hook.message.output_too_large");
        assert_eq!(error.category(), ErrorCategory::Resource);

        let generous = HandlerOutputLimits::tightened_to(bytes.len());
        assert_eq!(
            message.to_canonical_json(&generous).expect("encodes"),
            bytes,
            "accepted below (at) the non-default ceiling"
        );
    }

    #[test]
    fn the_size_check_runs_before_parsing() {
        let limits = HandlerOutputLimits::tightened_to(8);
        let error = HookMessage::from_canonical_json(b"not json at all", &limits)
            .expect_err("size wins before shape");
        assert!(matches!(
            error,
            HookMessageError::OutputTooLarge { size: 15, max: 8 }
        ));
    }

    #[test]
    fn refuses_a_message_that_is_valid_json_but_not_canonical() {
        let limits = HandlerOutputLimits::default();
        for raw in [
            br#"{"answer": "none"}"#.as_slice(),
            br#" { "answer":"none"} "#.as_slice(),
            br#"{"document":{"b":2,"a":1},"answer":"proposal"}"#.as_slice(),
        ] {
            let error = HookMessage::from_canonical_json(raw, &limits)
                .expect_err("handler output must arrive canonical");
            assert_eq!(error.code(), "hook.message.not_canonical");
            assert_eq!(error.category(), ErrorCategory::Source);
        }
    }

    #[test]
    fn refuses_duplicate_members_anywhere_in_the_message() {
        let limits = HandlerOutputLimits::default();
        let raw = br#"{"answer":"refusal","code":"a","code":"b","summary":"s"}"#;
        let error = HookMessage::from_canonical_json(raw, &limits).expect_err("duplicate refused");
        assert_eq!(error.code(), "hook.message.not_strict_json");
    }

    #[test]
    fn refuses_integer_tokens_that_collapse_in_binary64() {
        let limits = HandlerOutputLimits::default();
        let raw = br#"{"answer":"proposal","document":{"count":9007199254740993}}"#;
        let error = HookMessage::from_canonical_json(raw, &limits)
            .expect_err("lossy integers must be strings");
        assert_eq!(error.code(), "hook.message.not_strict_json");
    }

    #[test]
    fn refuses_unknown_answers_and_extra_fields() {
        let limits = HandlerOutputLimits::default();
        let unknown = canonical_bytes(&json!({"answer": "maybe"}));
        let error = HookMessage::from_canonical_json(&unknown, &limits)
            .expect_err("the answer set is closed");
        assert_eq!(error.code(), "hook.message.bad_shape");

        let extra = canonical_bytes(&json!({"answer": "none", "extra": true}));
        let error = HookMessage::from_canonical_json(&extra, &limits).expect_err("no extra fields");
        assert_eq!(error.code(), "hook.message.bad_shape");

        let extra_on_refusal = canonical_bytes(&json!({
            "answer": "refusal",
            "code": "c",
            "summary": "s",
            "detail": "d",
        }));
        let error = HookMessage::from_canonical_json(&extra_on_refusal, &limits)
            .expect_err("no extra fields on a refusal either");
        assert_eq!(error.code(), "hook.message.bad_shape");
    }

    #[test]
    fn the_default_output_ceiling_mirrors_the_script_budget() {
        assert_eq!(MAX_OUTPUT_BYTES, 1_048_576);
        assert_eq!(
            HandlerOutputLimits::default().max_output_bytes(),
            MAX_OUTPUT_BYTES
        );
        assert_eq!(MAX_REFUSAL_CODE_BYTES, 128);
        assert_eq!(MAX_REFUSAL_SUMMARY_BYTES, 1_024);
    }

    #[test]
    fn the_output_ceiling_can_only_be_tightened() {
        assert_eq!(
            HandlerOutputLimits::tightened_to(MAX_OUTPUT_BYTES + 1).max_output_bytes(),
            MAX_OUTPUT_BYTES,
            "a widened request is clamped to the library ceiling"
        );
        assert_eq!(
            HandlerOutputLimits::tightened_to(usize::MAX).max_output_bytes(),
            MAX_OUTPUT_BYTES
        );
        assert_eq!(
            HandlerOutputLimits::tightened_to(4_096).max_output_bytes(),
            4_096,
            "a tightened request is honored"
        );

        // The clamp is enforced, not just reported: bytes over the library
        // ceiling are still refused after asking for a wider ceiling.
        let widened = HandlerOutputLimits::tightened_to(MAX_OUTPUT_BYTES * 2);
        let oversized = vec![b' '; MAX_OUTPUT_BYTES + 1];
        let error = HookMessage::from_canonical_json(&oversized, &widened)
            .expect_err("the clamp holds on the decode path");
        assert_eq!(error.code(), "hook.message.output_too_large");
    }

    #[test]
    fn the_text_ceiling_flips_at_a_non_default_value() {
        // The two named bounds are the refusal code and summary; a third,
        // arbitrary ceiling proves the bound is the parameter and not a
        // constant the type happens to agree with.
        let at_bound = BoundedText::<4>::new("abcd".to_owned()).expect("exactly at the bound");
        assert_eq!(at_bound.as_str(), "abcd");
        assert_eq!(
            BoundedText::<4>::new("abcde".to_owned()).expect_err("one byte over"),
            BoundedTextError::TooLong { size: 5, max: 4 }
        );
        let error = serde_json::from_value::<BoundedText<4>>(json!("abcde"))
            .expect_err("the decode path enforces the same bound");
        assert!(error.to_string().contains("4-byte ceiling"), "{error}");
    }

    #[test]
    fn an_untrusted_answer_never_reaches_display_unbounded() {
        let limits = HandlerOutputLimits::default();
        // Under the output ceiling, so the shape check is the one that
        // reports, and far over the token ceiling a diagnostic may repeat.
        let huge = "x".repeat(64 * 1024);
        let bytes = canonical_bytes(&json!({"answer": huge}));
        let rendered = HookMessage::from_canonical_json(&bytes, &limits)
            .expect_err("the answer set is closed")
            .to_string();
        assert!(rendered.len() < 1_024, "{} bytes rendered", rendered.len());
        assert!(
            !rendered.contains(&"x".repeat(MAX_DISPLAYED_TOKEN_BYTES + 1)),
            "no run of the input longer than the token ceiling survives"
        );
    }

    #[test]
    fn an_untrusted_member_name_never_reaches_display_unbounded() {
        let limits = HandlerOutputLimits::default();
        let huge = "x".repeat(64 * 1024);
        let bytes = canonical_bytes(&json!({"answer": "none", huge.clone(): true}));
        let rendered = HookMessage::from_canonical_json(&bytes, &limits)
            .expect_err("no extra fields")
            .to_string();
        assert!(rendered.len() < 1_024, "{} bytes rendered", rendered.len());
        assert!(
            !rendered.contains(&"x".repeat(MAX_DISPLAYED_TOKEN_BYTES + 1)),
            "no run of the input longer than the token ceiling survives"
        );
    }

    #[test]
    fn an_untrusted_refusal_code_never_reaches_display_unbounded() {
        let limits = HandlerOutputLimits::default();
        let huge = "x".repeat(64 * 1024);
        let bytes = canonical_bytes(&json!({
            "answer": "refusal",
            "code": huge,
            "summary": "s",
        }));
        let rendered = HookMessage::from_canonical_json(&bytes, &limits)
            .expect_err("an over-bound code is refused")
            .to_string();
        assert!(rendered.len() < 1_024, "{} bytes rendered", rendered.len());
        assert!(
            !rendered.contains(&"x".repeat(MAX_DISPLAYED_TOKEN_BYTES + 1)),
            "no run of the input longer than the token ceiling survives"
        );
    }

    #[test]
    fn every_message_code_is_distinct_and_in_its_namespace() {
        let variants = [
            HookMessageError::OutputTooLarge { size: 1, max: 0 },
            HookMessageError::Json(
                parse_json_strict(b"{").expect_err("a truncated object is not strict JSON"),
            ),
            HookMessageError::NotCanonical,
            HookMessageError::Shape(String::new()),
            HookMessageError::Canonical(
                canonicalize_json(&json!({"count": 9007199254740993_u64}))
                    .expect_err("a lossy integer is not canonicalizable"),
            ),
        ];
        let codes: Vec<&str> = variants.iter().map(HookMessageError::code).collect();
        assert_eq!(
            codes.iter().collect::<BTreeSet<_>>().len(),
            codes.len(),
            "codes are distinct: {codes:?}"
        );
        for code in codes {
            assert!(
                code.starts_with("hook.message."),
                "{code} is outside the namespace"
            );
        }
    }

    #[test]
    fn diagnostic_codes_are_pinned() {
        let limits = HandlerOutputLimits::default();
        assert_eq!(
            HookMessage::from_canonical_json(b"{}", &limits)
                .expect_err("empty object has no answer")
                .code(),
            "hook.message.bad_shape"
        );
    }
}
