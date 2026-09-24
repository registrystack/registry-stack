// SPDX-License-Identifier: Apache-2.0

//! Provider delivery callback verification (spec 7.4).
//!
//! A deployment names one verifier for each provider's inbound delivery
//! callback, from a closed set of algorithms, not vendors. `none` is
//! deliberately not a member of [`CallbackVerifierConfig`]: an operator
//! cannot configure an unauthenticated callback. A credential never appears
//! here as a literal value, only as the `secret:` reference the runtime
//! resolves; the pure functions in this module verify over the resolved
//! bytes a [`ResolvedCallbackVerifier`] carries, never over a reference.
//!
//! Verification is over a narrow, product-neutral request view
//! ([`CallbackRequest`]): method, the full external URL the operator
//! configured for the callback, the request's form parameters, the raw body,
//! the headers, and the path token segment the route extracted. This crate
//! has no HTTP framework dependency, so the runtime's callback route builds
//! this view from the request it received.
//!
//! This module stops at verification. Resolving a `secretRef` or `tokenRef`
//! to bytes, the callback route, and applying a verified receipt to a stored
//! message are runtime concerns that land with the route in a later change.

use aws_lc_rs::hmac;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

/// The longest header name a verifier configuration accepts.
pub const MAXIMUM_CALLBACK_HEADER_BYTES: usize = 128;

/// How an `hmac-sha256-body` tag is encoded in its header.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CallbackBodyEncoding {
    Hex,
    Base64,
}

/// How the runtime authenticates one provider's inbound delivery callbacks,
/// closed and tagged in kebab-case like Evidence's authentication kinds.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CallbackVerifierConfig {
    /// HMAC-SHA1 over the full external callback URL with the request's form
    /// parameters sorted by key and appended as `key` then `value` with no
    /// delimiter, base64 in `header`. The `form-sms-gateway` example provider
    /// package documents the provider scheme this matches.
    HmacSha1UrlForm {
        header: String,
        #[serde(rename = "secretRef")]
        secret_ref: String,
    },
    /// HMAC-SHA256 over the raw request body, encoded in `header` as
    /// `encoding`.
    HmacSha256Body {
        header: String,
        encoding: CallbackBodyEncoding,
        #[serde(rename = "secretRef")]
        secret_ref: String,
    },
    /// A secret random token carried in the callback path, for gateways that
    /// can only be given a URL.
    PathToken {
        #[serde(rename = "tokenRef")]
        token_ref: String,
    },
}

/// Why a callback verifier configuration cannot be used. Configured header
/// names are deployment configuration, not secrets, so they are safe to
/// name; the reference itself never is.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CallbackVerifierConfigError {
    #[error(
        "callback verifier header must be 1 to {MAXIMUM_CALLBACK_HEADER_BYTES} HTTP token characters"
    )]
    InvalidHeader,
    #[error("callback verifier secretRef must not be empty")]
    EmptySecretRef,
    #[error("callback verifier tokenRef must not be empty")]
    EmptyTokenRef,
}

impl CallbackVerifierConfig {
    /// Check the shape of this configuration. The `secret:` grammar of a
    /// `secretRef` or `tokenRef`, and whether its provider is enabled, are
    /// checked by the runtime the way every other `*Ref` field is.
    pub fn validate(&self) -> Result<(), CallbackVerifierConfigError> {
        match self {
            Self::HmacSha1UrlForm { header, secret_ref }
            | Self::HmacSha256Body {
                header, secret_ref, ..
            } => {
                if !valid_header_name(header) {
                    return Err(CallbackVerifierConfigError::InvalidHeader);
                }
                if secret_ref.is_empty() {
                    return Err(CallbackVerifierConfigError::EmptySecretRef);
                }
            }
            Self::PathToken { token_ref } => {
                if token_ref.is_empty() {
                    return Err(CallbackVerifierConfigError::EmptyTokenRef);
                }
            }
        }
        Ok(())
    }
}

/// Whether `value` is a valid HTTP header field name: one to
/// [`MAXIMUM_CALLBACK_HEADER_BYTES`] RFC 7230 `tchar` bytes.
#[must_use]
pub fn valid_header_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_CALLBACK_HEADER_BYTES
        && value.bytes().all(is_header_token_byte)
}

const fn is_header_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// A callback verifier with its secret material resolved to bytes. The
/// runtime builds one of these from a [`CallbackVerifierConfig`] and the
/// secret its `secretRef` or `tokenRef` names; this crate never reads a
/// reference or a secret store itself.
#[derive(Clone, Copy, Debug)]
pub enum ResolvedCallbackVerifier<'a> {
    HmacSha1UrlForm {
        header: &'a str,
        secret: &'a [u8],
    },
    HmacSha256Body {
        header: &'a str,
        encoding: CallbackBodyEncoding,
        secret: &'a [u8],
    },
    PathToken {
        token: &'a [u8],
    },
}

/// The narrow view of an inbound callback request a verifier decides over.
///
/// `url` is the full external URL the operator configured for this
/// callback (scheme, host, path, and any query string), taken as one literal
/// string; `hmac-sha1-url-form` does not reorder it. `form_parameters` are
/// the request's `application/x-www-form-urlencoded` fields in the order the
/// request carried them: `hmac-sha1-url-form` sorts them itself, by key, so
/// their order in this list never changes the outcome. `path_token` is the
/// token segment the route extracted from the callback path, when the route
/// is configured for `path-token`.
#[derive(Clone, Copy, Debug)]
pub struct CallbackRequest<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub form_parameters: &'a [(&'a str, &'a str)],
    pub body: &'a [u8],
    pub headers: &'a [(&'a str, &'a str)],
    pub path_token: Option<&'a str>,
}

/// Why a callback request did not verify. Bounded and value-free: none of
/// these carry the header value, the body, or the secret.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum CallbackVerificationRefusal {
    #[error("the configured header is missing from the callback request")]
    MissingHeader,
    #[error("the header value is not validly encoded for this verifier")]
    MalformedSignature,
    #[error("the callback signature does not match")]
    SignatureMismatch,
    #[error("the callback path carries no token")]
    MissingPathToken,
    #[error("the callback path token does not match")]
    TokenMismatch,
}

/// Verify `request` against `verifier`, in constant time over the secret and
/// the presented value.
pub fn verify_callback(
    verifier: &ResolvedCallbackVerifier<'_>,
    request: &CallbackRequest<'_>,
) -> Result<(), CallbackVerificationRefusal> {
    match verifier {
        ResolvedCallbackVerifier::HmacSha1UrlForm { header, secret } => {
            verify_hmac_sha1_url_form(header, secret, request)
        }
        ResolvedCallbackVerifier::HmacSha256Body {
            header,
            encoding,
            secret,
        } => verify_hmac_sha256_body(header, *encoding, secret, request),
        ResolvedCallbackVerifier::PathToken { token } => verify_path_token(token, request),
    }
}

fn verify_hmac_sha1_url_form(
    header: &str,
    secret: &[u8],
    request: &CallbackRequest<'_>,
) -> Result<(), CallbackVerificationRefusal> {
    let provided =
        header_value(request.headers, header).ok_or(CallbackVerificationRefusal::MissingHeader)?;
    let tag = BASE64_STANDARD
        .decode(provided)
        .map_err(|_| CallbackVerificationRefusal::MalformedSignature)?;
    let mut signed = String::from(request.url);
    let mut sorted: Vec<&(&str, &str)> = request.form_parameters.iter().collect();
    sorted.sort_by(|left, right| left.0.cmp(right.0));
    for (key, value) in sorted {
        signed.push_str(key);
        signed.push_str(value);
    }
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    hmac::verify(&key, signed.as_bytes(), &tag)
        .map_err(|_| CallbackVerificationRefusal::SignatureMismatch)
}

fn verify_hmac_sha256_body(
    header: &str,
    encoding: CallbackBodyEncoding,
    secret: &[u8],
    request: &CallbackRequest<'_>,
) -> Result<(), CallbackVerificationRefusal> {
    let provided =
        header_value(request.headers, header).ok_or(CallbackVerificationRefusal::MissingHeader)?;
    let tag = match encoding {
        CallbackBodyEncoding::Hex => hex::decode(provided),
        CallbackBodyEncoding::Base64 => BASE64_STANDARD
            .decode(provided)
            .map_err(|_| hex::FromHexError::InvalidStringLength),
    }
    .map_err(|_| CallbackVerificationRefusal::MalformedSignature)?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    hmac::verify(&key, request.body, &tag)
        .map_err(|_| CallbackVerificationRefusal::SignatureMismatch)
}

fn verify_path_token(
    token: &[u8],
    request: &CallbackRequest<'_>,
) -> Result<(), CallbackVerificationRefusal> {
    let provided = request
        .path_token
        .ok_or(CallbackVerificationRefusal::MissingPathToken)?;
    if bool::from(token.ct_eq(provided.as_bytes())) {
        Ok(())
    } else {
        Err(CallbackVerificationRefusal::TokenMismatch)
    }
}

fn header_value<'a>(headers: &[(&'a str, &'a str)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| *value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn hmac_sha1_url_form_verifier<'a>(secret: &'a [u8]) -> ResolvedCallbackVerifier<'a> {
        ResolvedCallbackVerifier::HmacSha1UrlForm {
            header: "X-Callback-Signature",
            secret,
        }
    }

    /// The worked example a provider publishes for this scheme, cited in the
    /// `form-sms-gateway` example provider package: secret `12345`, this URL
    /// and these form parameters sign to exactly this base64 tag.
    #[test]
    fn the_published_url_form_vector_verifies() {
        let request = CallbackRequest {
            method: "POST",
            url: "https://example.com/myapp.php?foo=1&bar=2",
            form_parameters: &[
                ("CallSid", "CA1234567890ABCDE"),
                ("Caller", "+14158675310"),
                ("Digits", "1234"),
                ("From", "+14158675310"),
                ("To", "+18005551212"),
            ],
            body: b"",
            headers: &[("X-Callback-Signature", "L/OH5YylLD5NRKLltdqwSvS0BnU=")],
            path_token: None,
        };
        assert_eq!(
            verify_callback(&hmac_sha1_url_form_verifier(b"12345"), &request),
            Ok(())
        );
    }

    #[test]
    fn the_published_url_form_vector_is_order_independent_over_the_form_parameters_given() {
        let mut request = CallbackRequest {
            method: "POST",
            url: "https://example.com/myapp.php?foo=1&bar=2",
            form_parameters: &[
                ("To", "+18005551212"),
                ("From", "+14158675310"),
                ("Digits", "1234"),
                ("Caller", "+14158675310"),
                ("CallSid", "CA1234567890ABCDE"),
            ],
            body: b"",
            headers: &[("X-Callback-Signature", "L/OH5YylLD5NRKLltdqwSvS0BnU=")],
            path_token: None,
        };
        assert_eq!(
            verify_callback(&hmac_sha1_url_form_verifier(b"12345"), &request),
            Ok(())
        );
        // The header lookup is case-insensitive, as HTTP header names are.
        request.headers = &[("x-callback-signature", "L/OH5YylLD5NRKLltdqwSvS0BnU=")];
        assert_eq!(
            verify_callback(&hmac_sha1_url_form_verifier(b"12345"), &request),
            Ok(())
        );
    }

    #[test]
    fn hmac_sha1_url_form_refuses_every_forgery() {
        let valid = CallbackRequest {
            method: "POST",
            url: "https://example.com/myapp.php?foo=1&bar=2",
            form_parameters: &[
                ("CallSid", "CA1234567890ABCDE"),
                ("Caller", "+14158675310"),
                ("Digits", "1234"),
                ("From", "+14158675310"),
                ("To", "+18005551212"),
            ],
            body: b"",
            headers: &[("X-Callback-Signature", "L/OH5YylLD5NRKLltdqwSvS0BnU=")],
            path_token: None,
        };
        let verifier = hmac_sha1_url_form_verifier(b"12345");
        assert_eq!(verify_callback(&verifier, &valid), Ok(()));

        // Wrong secret.
        assert_eq!(
            verify_callback(&hmac_sha1_url_form_verifier(b"wrong-secret"), &valid),
            Err(CallbackVerificationRefusal::SignatureMismatch)
        );

        // The URL is signed as one literal string: reordering its query
        // string changes the input and must be refused, even though the
        // form parameters below are order-independent.
        let mut reordered_url = valid;
        reordered_url.url = "https://example.com/myapp.php?bar=2&foo=1";
        assert_eq!(
            verify_callback(&verifier, &reordered_url),
            Err(CallbackVerificationRefusal::SignatureMismatch)
        );

        // An extra form parameter the signer never saw.
        let mut extra_parameter = valid;
        let mut extended: Vec<(&str, &str)> = valid.form_parameters.to_vec();
        extended.push(("Extra", "1"));
        extra_parameter.form_parameters = &extended;
        assert_eq!(
            verify_callback(&verifier, &extra_parameter),
            Err(CallbackVerificationRefusal::SignatureMismatch)
        );

        // Missing header.
        let mut missing_header = valid;
        missing_header.headers = &[];
        assert_eq!(
            verify_callback(&verifier, &missing_header),
            Err(CallbackVerificationRefusal::MissingHeader)
        );

        // A header value that is not base64 at all.
        let mut malformed = valid;
        malformed.headers = &[("X-Callback-Signature", "not base64!!")];
        assert_eq!(
            verify_callback(&verifier, &malformed),
            Err(CallbackVerificationRefusal::MalformedSignature)
        );
    }

    fn body_secret() -> &'static [u8] {
        b"hmac-sha256-body-shared-secret"
    }

    fn signed_body_tag(encoding: CallbackBodyEncoding, body: &[u8]) -> String {
        let key = hmac::Key::new(hmac::HMAC_SHA256, body_secret());
        let tag = hmac::sign(&key, body);
        match encoding {
            CallbackBodyEncoding::Hex => hex::encode(tag.as_ref()),
            CallbackBodyEncoding::Base64 => BASE64_STANDARD.encode(tag.as_ref()),
        }
    }

    #[test]
    fn hmac_sha256_body_accepts_a_valid_request_in_either_encoding() {
        let body = br#"{"status":"delivered","messageId":"msg-1"}"#;
        for encoding in [CallbackBodyEncoding::Hex, CallbackBodyEncoding::Base64] {
            let tag = signed_body_tag(encoding, body);
            let verifier = ResolvedCallbackVerifier::HmacSha256Body {
                header: "X-Signature",
                encoding,
                secret: body_secret(),
            };
            let request = CallbackRequest {
                method: "POST",
                url: "https://example.com/callbacks/sms",
                form_parameters: &[],
                body,
                headers: &[("X-Signature", &tag)],
                path_token: None,
            };
            assert_eq!(verify_callback(&verifier, &request), Ok(()));
        }
    }

    #[test]
    fn hmac_sha256_body_refuses_every_forgery() {
        let body = br#"{"status":"delivered","messageId":"msg-1"}"#;
        let tag = signed_body_tag(CallbackBodyEncoding::Hex, body);
        let verifier = ResolvedCallbackVerifier::HmacSha256Body {
            header: "X-Signature",
            encoding: CallbackBodyEncoding::Hex,
            secret: body_secret(),
        };
        let valid = CallbackRequest {
            method: "POST",
            url: "https://example.com/callbacks/sms",
            form_parameters: &[],
            body,
            headers: &[("X-Signature", &tag)],
            path_token: None,
        };
        assert_eq!(verify_callback(&verifier, &valid), Ok(()));

        // Tampered body.
        let mut tampered = valid;
        tampered.body = br#"{"status":"delivered","messageId":"msg-2"}"#;
        assert_eq!(
            verify_callback(&verifier, &tampered),
            Err(CallbackVerificationRefusal::SignatureMismatch)
        );

        // Wrong secret.
        let wrong_secret = ResolvedCallbackVerifier::HmacSha256Body {
            header: "X-Signature",
            encoding: CallbackBodyEncoding::Hex,
            secret: b"a-different-secret",
        };
        assert_eq!(
            verify_callback(&wrong_secret, &valid),
            Err(CallbackVerificationRefusal::SignatureMismatch)
        );

        // Missing header.
        let mut missing_header = valid;
        missing_header.headers = &[];
        assert_eq!(
            verify_callback(&verifier, &missing_header),
            Err(CallbackVerificationRefusal::MissingHeader)
        );

        // A hex alphabet is a subset of the base64 alphabet, so a hex tag
        // fed to a base64 verifier still decodes, just to the wrong bytes:
        // the mismatch is caught by the signature comparison, not decoding.
        let base64_verifier = ResolvedCallbackVerifier::HmacSha256Body {
            header: "X-Signature",
            encoding: CallbackBodyEncoding::Base64,
            secret: body_secret(),
        };
        assert_eq!(
            verify_callback(&base64_verifier, &valid),
            Err(CallbackVerificationRefusal::SignatureMismatch)
        );

        // A header value that cannot be decoded at all is refused as
        // malformed, in either encoding.
        let mut undecodable = valid;
        undecodable.headers = &[("X-Signature", "not valid hex or base64 !!")];
        assert_eq!(
            verify_callback(&verifier, &undecodable),
            Err(CallbackVerificationRefusal::MalformedSignature)
        );
        assert_eq!(
            verify_callback(&base64_verifier, &undecodable),
            Err(CallbackVerificationRefusal::MalformedSignature)
        );
    }

    #[test]
    fn path_token_accepts_only_the_exact_token() {
        let verifier = ResolvedCallbackVerifier::PathToken {
            token: b"a-long-random-callback-token",
        };
        let valid = CallbackRequest {
            method: "POST",
            url: "https://example.com/callbacks/email/a-long-random-callback-token",
            form_parameters: &[],
            body: b"{}",
            headers: &[],
            path_token: Some("a-long-random-callback-token"),
        };
        assert_eq!(verify_callback(&verifier, &valid), Ok(()));

        let mut wrong_token = valid;
        wrong_token.path_token = Some("a-different-token-of-equal-length");
        assert_eq!(
            verify_callback(&verifier, &wrong_token),
            Err(CallbackVerificationRefusal::TokenMismatch)
        );

        let mut missing_token = valid;
        missing_token.path_token = None;
        assert_eq!(
            verify_callback(&verifier, &missing_token),
            Err(CallbackVerificationRefusal::MissingPathToken)
        );
    }

    #[test]
    fn a_verifier_configuration_document_refuses_none_and_unknown_keys() {
        // `none` is not a member of the closed set: it fails to parse as any
        // known `kind`, exactly like an operator typo would.
        let none_kind = serde_json::from_value::<CallbackVerifierConfig>(json!({"kind": "none"}));
        assert!(none_kind.is_err());

        let unknown_field = serde_json::from_value::<CallbackVerifierConfig>(json!({
            "kind": "hmac-sha1-url-form",
            "header": "X-Callback-Signature",
            "secretRef": "secret:env/SMS_CALLBACK_TOKEN",
            "endpoint": "https://elsewhere.test"
        }));
        assert!(unknown_field.is_err());

        let parsed: CallbackVerifierConfig = serde_json::from_value(json!({
            "kind": "hmac-sha256-body",
            "header": "X-Signature",
            "encoding": "hex",
            "secretRef": "secret:env/PROVIDER_SIGNING_KEY"
        }))
        .unwrap();
        assert!(parsed.validate().is_ok());
        assert!(matches!(
            parsed,
            CallbackVerifierConfig::HmacSha256Body {
                encoding: CallbackBodyEncoding::Hex,
                ..
            }
        ));

        let path_token: CallbackVerifierConfig = serde_json::from_value(json!({
            "kind": "path-token",
            "tokenRef": "secret:env/CALLBACK_TOKEN"
        }))
        .unwrap();
        assert!(path_token.validate().is_ok());
    }

    #[test]
    fn a_verifier_configuration_is_checked_for_shape() {
        assert_eq!(
            CallbackVerifierConfig::HmacSha1UrlForm {
                header: String::new(),
                secret_ref: "secret:env/TOKEN".to_owned(),
            }
            .validate(),
            Err(CallbackVerifierConfigError::InvalidHeader)
        );
        assert_eq!(
            CallbackVerifierConfig::HmacSha1UrlForm {
                header: "X-Signature\r\n".to_owned(),
                secret_ref: "secret:env/TOKEN".to_owned(),
            }
            .validate(),
            Err(CallbackVerifierConfigError::InvalidHeader)
        );
        assert_eq!(
            CallbackVerifierConfig::HmacSha1UrlForm {
                header: "X-Signature".to_owned(),
                secret_ref: String::new(),
            }
            .validate(),
            Err(CallbackVerifierConfigError::EmptySecretRef)
        );
        assert_eq!(
            CallbackVerifierConfig::PathToken {
                token_ref: String::new(),
            }
            .validate(),
            Err(CallbackVerifierConfigError::EmptyTokenRef)
        );
    }
}
