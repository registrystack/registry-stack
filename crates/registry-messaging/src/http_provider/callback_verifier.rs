// SPDX-License-Identifier: Apache-2.0

//! The runtime configuration of one provider's delivery callback verifier.
//!
//! A deployment names one verifier for each provider's inbound delivery
//! callback, from a closed set of algorithms, not vendors, tagged by `type`.
//! `none` is deliberately not a member of [`CallbackVerifierConfig`]: an
//! operator cannot configure an unauthenticated callback. A credential never
//! appears here as a literal value, only as the `secret:` reference the
//! runtime resolves into a
//! [`registry_messaging_core::ResolvedCallbackVerifier`]. Reading the file
//! refuses a header name or callback URL outside its shape, at the member.

use registry_messaging_core::{
    valid_callback_url, valid_header_name, CallbackBodyEncoding, MAXIMUM_CALLBACK_HEADER_BYTES,
    MAXIMUM_CALLBACK_URL_BYTES,
};
use registry_platform_yaml::Invalid;
use serde::{Deserialize, Deserializer};

use crate::config::secret_reference;

/// The header grammar a callback verifier names: an HTTP token.
#[cfg(feature = "schema")]
const HEADER_NAME_PATTERN: &str = "^[!#$%&'*+.^_`|~0-9A-Za-z-]+$";

/// How the runtime authenticates one provider's inbound delivery callbacks,
/// closed and tagged by `type` in kebab-case.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CallbackVerifierConfig {
    /// HMAC-SHA1 over the full external callback URL with the request's form
    /// parameters sorted by key and appended as `key` then `value` with no
    /// delimiter, base64 in `header`. The `form-sms-gateway` example provider
    /// package documents the provider scheme this matches.
    HmacSha1UrlForm {
        /// The external callback URL the provider was given and signs, as it
        /// was given: scheme, host, any port, and path, without a query or
        /// fragment. The route appends the request's own query string. A
        /// proxy may rewrite what the runtime receives, so the runtime never
        /// reconstructs this URL from the request.
        #[serde(deserialize_with = "callback_url")]
        #[cfg_attr(
            feature = "schema",
            schemars(
                with = "registry_platform_yaml::Url",
                extend("pattern" = "^https?://[^/?#]+/[^?#]*$")
            )
        )]
        url: String,
        /// The header carrying the signature.
        #[serde(deserialize_with = "header_name")]
        #[cfg_attr(
            feature = "schema",
            schemars(
                length(min = 1, max = MAXIMUM_CALLBACK_HEADER_BYTES),
                regex(pattern = HEADER_NAME_PATTERN)
            )
        )]
        header: String,
        #[serde(deserialize_with = "secret_reference")]
        #[cfg_attr(
            feature = "schema",
            schemars(with = "registry_platform_config::SecretReference")
        )]
        secret_ref: String,
    },
    /// HMAC-SHA256 over the raw request body, encoded in `header` as
    /// `encoding`.
    HmacSha256Body {
        /// The header carrying the signature.
        #[serde(deserialize_with = "header_name")]
        #[cfg_attr(
            feature = "schema",
            schemars(
                length(min = 1, max = MAXIMUM_CALLBACK_HEADER_BYTES),
                regex(pattern = HEADER_NAME_PATTERN)
            )
        )]
        header: String,
        encoding: CallbackBodyEncoding,
        #[serde(deserialize_with = "secret_reference")]
        #[cfg_attr(
            feature = "schema",
            schemars(with = "registry_platform_config::SecretReference")
        )]
        secret_ref: String,
    },
    /// A secret random token carried in the callback path, for gateways that
    /// can only be given a URL.
    PathToken {
        #[serde(deserialize_with = "secret_reference")]
        #[cfg_attr(
            feature = "schema",
            schemars(with = "registry_platform_config::SecretReference")
        )]
        token_ref: String,
    },
}
registry_platform_yaml::tagged_union!(CallbackVerifierConfig);

/// The secret references are left out, so the verifier is safe to log.
impl std::fmt::Debug for CallbackVerifierConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HmacSha1UrlForm { url, header, .. } => formatter
                .debug_struct("HmacSha1UrlForm")
                .field("url", url)
                .field("header", header)
                .field("secret_ref", &"<redacted>")
                .finish(),
            Self::HmacSha256Body {
                header, encoding, ..
            } => formatter
                .debug_struct("HmacSha256Body")
                .field("header", header)
                .field("encoding", encoding)
                .field("secret_ref", &"<redacted>")
                .finish(),
            Self::PathToken { .. } => formatter
                .debug_struct("PathToken")
                .field("token_ref", &"<redacted>")
                .finish(),
        }
    }
}

// The refusals below state these bounds in static text.
const _: () = assert!(MAXIMUM_CALLBACK_HEADER_BYTES == 128);
const _: () = assert!(MAXIMUM_CALLBACK_URL_BYTES == 2048);

/// The external callback URL an `hmac-sha1-url-form` verifier signs over:
/// an absolute URL the shared URL type accepts, in the narrower callback
/// shape.
fn callback_url<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let url = registry_messaging_core::typed::url(deserializer)?;
    if valid_callback_url(&url) {
        Ok(url)
    } else {
        Err(Invalid::expected(
            "an http or https URL of at most 2048 bytes with a host and a path, and no \
             credentials, query, or fragment",
            "Write the callback URL the provider was given, without its query string or \
             fragment.",
        )
        .into_error())
    }
}

/// The header a callback verifier reads its signature from: an HTTP token.
fn header_name<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let header = String::deserialize(deserializer)?;
    if valid_header_name(&header) {
        Ok(header)
    } else {
        Err(Invalid::expected(
            "an HTTP header name of 1 to 128 token characters",
            "Write the name of the header the provider carries the signature in, such as \
             X-Signature.",
        )
        .into_error())
    }
}

impl CallbackVerifierConfig {
    /// The member naming this verifier's secret, and the reference.
    #[must_use]
    pub fn secret_reference(&self) -> (&'static str, &str) {
        match self {
            Self::HmacSha1UrlForm { secret_ref, .. } | Self::HmacSha256Body { secret_ref, .. } => {
                ("callbackVerifier.secretRef", secret_ref)
            }
            Self::PathToken { token_ref } => ("callbackVerifier.tokenRef", token_ref),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const CALLBACK_URL: &str = "https://messaging.example.org/v1/provider-callbacks/sms";

    fn read(document: serde_json::Value) -> Result<CallbackVerifierConfig, serde_json::Error> {
        serde_json::from_value(document)
    }

    #[test]
    fn a_verifier_configuration_document_refuses_none_and_unknown_keys() {
        // `none` is not a member of the closed set: it fails to parse as any
        // known `type`, exactly like an operator typo would.
        assert!(read(json!({"type": "none"})).is_err());

        let unknown_field = read(json!({
            "type": "hmac-sha1-url-form",
            "url": CALLBACK_URL,
            "header": "X-Callback-Signature",
            "secretRef": "secret:env/SMS_CALLBACK_TOKEN",
            "endpoint": "https://elsewhere.test"
        }));
        assert!(unknown_field.is_err());

        let parsed = read(json!({
            "type": "hmac-sha256-body",
            "header": "X-Signature",
            "encoding": "hex",
            "secretRef": "secret:env/PROVIDER_SIGNING_KEY"
        }))
        .unwrap();
        assert!(matches!(
            parsed,
            CallbackVerifierConfig::HmacSha256Body {
                encoding: CallbackBodyEncoding::Hex,
                ..
            }
        ));

        let path_token = read(json!({
            "type": "path-token",
            "tokenRef": "secret:env/CALLBACK_TOKEN"
        }))
        .unwrap();
        assert_eq!(
            path_token.secret_reference(),
            ("callbackVerifier.tokenRef", "secret:env/CALLBACK_TOKEN")
        );

        // The retired tag spelling is refused, not read as a variant.
        let retired_tag = read(json!({
            "kind": "path-token",
            "tokenRef": "secret:env/CALLBACK_TOKEN"
        }));
        assert!(retired_tag.is_err());
    }

    #[test]
    fn a_verifier_configuration_is_checked_for_shape() {
        let long = "X".repeat(MAXIMUM_CALLBACK_HEADER_BYTES + 1);
        for header in ["", "X-Signature\r\n", "X-Sig nature", long.as_str()] {
            let refused = read(json!({
                "type": "hmac-sha1-url-form",
                "url": CALLBACK_URL,
                "header": header,
                "secretRef": "secret:env/TOKEN"
            }))
            .unwrap_err()
            .to_string();
            // The refusal names the expected shape and never repeats the
            // value.
            assert!(refused.contains("HTTP header name"), "{refused}");
            assert!(header.is_empty() || !refused.contains(header), "{refused}");
        }
        // A reference that is not a `secret:` reference is refused when the
        // file is read.
        for refused in [
            json!({"type": "path-token", "tokenRef": ""}),
            json!({
                "type": "hmac-sha256-body",
                "header": "X-Signature",
                "encoding": "hex",
                "secretRef": "plain-text-credential"
            }),
        ] {
            assert!(read(refused).is_err());
        }
    }

    /// The URL an `hmac-sha1-url-form` provider signs is configuration: the
    /// route cannot reconstruct it behind a proxy. It is required, absolute,
    /// and carries no query or fragment, which the request supplies.
    #[test]
    fn a_url_form_verifier_names_the_external_url_it_verifies_over() {
        let with_url = |url: &str| {
            read(json!({
                "type": "hmac-sha1-url-form",
                "url": url,
                "header": "X-Callback-Signature",
                "secretRef": "secret:env/TOKEN"
            }))
        };
        assert!(read(json!({
            "type": "hmac-sha1-url-form",
            "header": "X-Callback-Signature",
            "secretRef": "secret:env/TOKEN"
        }))
        .is_err());
        assert!(with_url(CALLBACK_URL).is_ok());
        assert!(with_url("http://127.0.0.1:8080/v1/provider-callbacks/sms").is_ok());
        let long = format!(
            "https://messaging.example.org/{}",
            "a".repeat(MAXIMUM_CALLBACK_URL_BYTES)
        );
        for refused in [
            "",
            "/v1/provider-callbacks/sms",
            "ftp://messaging.example.org/callbacks",
            "https://messaging.example.org/callbacks?secret=1",
            "https://messaging.example.org/callbacks#part",
            "https://user:pass@messaging.example.org/callbacks",
            "https:///callbacks",
            "https://messaging.example.org/call backs",
            long.as_str(),
        ] {
            let error = with_url(refused).expect_err(refused).to_string();
            if refused.len() > 8 {
                assert!(!error.contains(refused), "{error}");
            }
        }
    }
}
