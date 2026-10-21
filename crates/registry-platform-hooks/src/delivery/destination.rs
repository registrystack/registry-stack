// SPDX-License-Identifier: Apache-2.0

//! The `url` handler kind's destination: one activated logical destination,
//! its signing key, and the bounded send that reads the answer back.
//!
//! The product builds the outbound policy (its network profile, DNS family,
//! private ranges, and TLS material are deployment configuration it owns) and
//! hands it here with the rest of the binding. From then on every product
//! signs, renders, sends, and reads an answer the same way: the Version 1
//! delivery signature over `POST` and `application/json`, the closed event
//! request template, and a 2xx body read under the handler output ceiling.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use registry_platform_config::{ProtectedSecret, MAX_SECRET_BYTES};
use registry_platform_crypto::delivery_signature::{sign_v1, SignatureFields};
use registry_platform_httputil::destination::{
    DestinationProfile, DestinationRequestError, DestinationResponseError, DestinationSendError,
    EventDeliveryHeaders, EventDestinationPolicy, EventDestinationRequest,
    EventDestinationRequestTemplate, MAX_DESTINATION_REQUEST_HEADER_BYTES,
    MAX_DESTINATION_TARGET_BYTES,
};
use url::Url;

use super::seams::{
    DeliverySignatureFields, DeliverySignatureRefused, DestinationAnswer, HandlerRunFailure,
    HookDestination,
};
use crate::{ErrorCategory, MAX_OUTPUT_BYTES};

/// The shortest HMAC-SHA256 delivery key a destination accepts.
pub const MIN_HMAC_SHA256_KEY_BYTES: usize = 32;

/// Value-free refusal while building a [`UrlDestination`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum UrlDestinationError {
    /// The request target or payload ceiling cannot form the closed event
    /// request template.
    #[error("the hook destination binding is invalid")]
    InvalidBinding,
    /// The resolved HMAC-SHA256 key is shorter than
    /// [`MIN_HMAC_SHA256_KEY_BYTES`] or longer than the secret ceiling.
    #[error("the hook destination signing material is invalid")]
    InvalidSigningMaterial,
}

/// Everything one activated `url` destination is built from.
pub struct UrlDestinationParts {
    /// The product's digest of this destination's non-secret binding.
    pub binding_digest: String,
    /// The exact request target the template sends to and the signature
    /// covers.
    pub request_target: String,
    /// The only outbound authority for this logical destination.
    pub policy: EventDestinationPolicy,
    /// The largest envelope this destination is sent.
    pub maximum_payload_bytes: usize,
    /// The resolved HMAC-SHA256 delivery key.
    pub hmac_sha256_key: ProtectedSecret,
    /// The deployed per-attempt timeout.
    pub attempt_timeout: Duration,
    /// The deployed attempt ceiling.
    pub maximum_attempts: u8,
}

/// One activated `url` destination.
pub struct UrlDestination {
    binding_digest: String,
    request_target: String,
    policy: Arc<EventDestinationPolicy>,
    request_template: EventDestinationRequestTemplate,
    hmac_sha256_key: ProtectedSecret,
    attempt_timeout: Duration,
    maximum_attempts: u8,
}

impl UrlDestination {
    /// Build the destination, refusing a request target or payload ceiling
    /// the closed template refuses, then a key outside its length bounds.
    ///
    /// # Errors
    ///
    /// [`UrlDestinationError`] names which part was refused, never a value.
    pub fn new(parts: UrlDestinationParts) -> Result<Self, UrlDestinationError> {
        let request_template = EventDestinationRequestTemplate::event_delivery(
            &parts.request_target,
            parts.maximum_payload_bytes,
            MAX_DESTINATION_TARGET_BYTES
                + MAX_DESTINATION_REQUEST_HEADER_BYTES
                + parts.maximum_payload_bytes,
        )
        .map_err(|_| UrlDestinationError::InvalidBinding)?;
        if !(MIN_HMAC_SHA256_KEY_BYTES..=MAX_SECRET_BYTES).contains(&parts.hmac_sha256_key.len()) {
            return Err(UrlDestinationError::InvalidSigningMaterial);
        }
        Ok(Self {
            binding_digest: parts.binding_digest,
            request_target: parts.request_target,
            policy: Arc::new(parts.policy),
            request_template,
            hmac_sha256_key: parts.hmac_sha256_key,
            attempt_timeout: parts.attempt_timeout,
            maximum_attempts: parts.maximum_attempts,
        })
    }

    /// Digest of this destination's non-secret deployment binding.
    #[must_use]
    pub fn binding_digest(&self) -> &str {
        &self.binding_digest
    }

    /// Share the only outbound authority for this logical destination.
    #[must_use]
    pub fn policy(&self) -> Arc<EventDestinationPolicy> {
        Arc::clone(&self.policy)
    }

    /// Borrow the closed event request template.
    #[must_use]
    pub fn request_template(&self) -> &EventDestinationRequestTemplate {
        &self.request_template
    }

    /// Borrow the exact request target the template and the signature share,
    /// so signing and transport cannot disagree about the path.
    #[must_use]
    pub fn request_target(&self) -> &str {
        &self.request_target
    }

    /// Borrow signing bytes only for the duration of the supplied operation.
    pub fn with_hmac_sha256_key<T>(&self, use_key: impl FnOnce(&[u8]) -> T) -> T {
        use_key(self.hmac_sha256_key.expose_secret())
    }

    /// Deployed per-attempt timeout.
    #[must_use]
    pub fn attempt_timeout(&self) -> Duration {
        self.attempt_timeout
    }

    /// Deployed attempt ceiling.
    #[must_use]
    pub fn maximum_attempts(&self) -> u8 {
        self.maximum_attempts
    }
}

impl fmt::Debug for UrlDestination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UrlDestination")
            .field("binding_digest", &self.binding_digest)
            .field("request_target", &"[REDACTED]")
            .field("policy", &self.policy)
            .field("request_template", &self.request_template)
            .field("hmac_sha256_key", &"[REDACTED]")
            .field("attempt_timeout", &self.attempt_timeout)
            .field("maximum_attempts", &self.maximum_attempts)
            .finish()
    }
}

/// One activated destination shared with the delivery worker as its
/// destination seam.
#[derive(Clone, Debug)]
pub struct SharedUrlDestination(pub Arc<UrlDestination>);

#[async_trait::async_trait]
impl HookDestination for SharedUrlDestination {
    fn binding_digest(&self) -> &str {
        self.0.binding_digest()
    }

    fn attempt_timeout(&self) -> Duration {
        self.0.attempt_timeout()
    }

    fn maximum_attempts(&self) -> u8 {
        self.0.maximum_attempts()
    }

    fn sign_delivery(
        &self,
        fields: DeliverySignatureFields<'_>,
    ) -> Result<String, DeliverySignatureRefused> {
        let DeliverySignatureFields {
            id,
            source,
            event_type,
            time,
            data_schema,
            generation,
            attempt,
            delivery_time,
            idempotency_key,
            body,
        } = fields;
        self.0
            .with_hmac_sha256_key(|key| {
                sign_v1(
                    key,
                    SignatureFields {
                        id,
                        source,
                        event_type,
                        time,
                        data_schema,
                        generation,
                        attempt,
                        delivery_time,
                        method: "POST",
                        request_target: self.0.request_target(),
                        content_type: "application/json",
                        idempotency_key,
                        body,
                    },
                )
            })
            .map_err(|_| DeliverySignatureRefused)
    }

    fn render_delivery(
        &self,
        headers: EventDeliveryHeaders<'_>,
        body: Vec<u8>,
    ) -> Result<EventDestinationRequest, DestinationRequestError> {
        self.0.request_template().render_event(headers, body)
    }

    async fn send_delivery(
        &self,
        request: EventDestinationRequest,
        remaining: Duration,
    ) -> Result<DestinationAnswer, DestinationSendError> {
        let response = self.0.policy.send(request, remaining).await?;
        let status = response.status().as_u16();
        if !response.status().is_success() {
            return Ok(DestinationAnswer::NonSuccess { status });
        }
        // A remote hook handler answers in its response body, so the body is
        // read under the handler output ceiling rather than discarded. A body
        // that cannot be taken is classified with the same table a local run
        // is classified by, never reported as a successful delivery.
        match response.read_bounded(MAX_OUTPUT_BYTES).await {
            Ok(body) => Ok(DestinationAnswer::Delivered {
                body: body.to_event_answer(),
            }),
            Err(error) => Ok(DestinationAnswer::AnswerRefused(HandlerRunFailure::new(
                answer_read_category(error),
            ))),
        }
    }
}

/// Why a 2xx response body could not be taken as the handler's answer, in the
/// shared hook taxonomy: over the ceiling is a resource refusal, past the
/// attempt deadline is a deadline, and a read that broke mid-body is the
/// destination becoming unreachable part-way.
#[must_use]
pub const fn answer_read_category(error: DestinationResponseError) -> ErrorCategory {
    match error {
        DestinationResponseError::BodyTooLarge | DestinationResponseError::BodyLimitTooHigh => {
            ErrorCategory::Resource
        }
        DestinationResponseError::DeadlineExceeded => ErrorCategory::Deadline,
        DestinationResponseError::BodyReadFailed => ErrorCategory::Unavailable,
    }
}

/// One configured hook URL split into the origin the outbound policy pins,
/// the request target the template sends to, and the network profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UrlDestinationAddress {
    /// The scheme, host, and port, with no path.
    pub origin: String,
    /// The path, `/` when the URL names none.
    pub request_target: String,
    /// `https` is production; plain `http` is accepted only for a loopback
    /// host, as local development.
    pub profile: DestinationProfile,
}

/// Split a configured hook URL. The URL must carry a host and no user
/// information, query, or fragment; it must be `https`, or `http` to
/// `127.0.0.1`, `localhost`, or `[::1]`.
///
/// # Errors
///
/// [`UrlDestinationError::InvalidBinding`] for any refused URL.
pub fn url_destination_address(
    configured: &str,
) -> Result<UrlDestinationAddress, UrlDestinationError> {
    let parsed = Url::parse(configured).map_err(|_| UrlDestinationError::InvalidBinding)?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.host().is_none()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(UrlDestinationError::InvalidBinding);
    }
    let profile = match parsed.scheme() {
        "https" => DestinationProfile::ProductionHttps,
        "http"
            if matches!(
                parsed.host_str(),
                Some("127.0.0.1") | Some("localhost") | Some("[::1]")
            ) =>
        {
            DestinationProfile::LoopbackDevelopmentHttp
        }
        _ => return Err(UrlDestinationError::InvalidBinding),
    };
    let request_target = if parsed.path().is_empty() {
        "/".to_owned()
    } else {
        parsed.path().to_owned()
    };
    let mut origin = parsed;
    origin.set_path("");
    origin.set_query(None);
    origin.set_fragment(None);
    Ok(UrlDestinationAddress {
        origin: origin.to_string(),
        request_target,
        profile,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> EventDestinationPolicy {
        EventDestinationPolicy::new(
            "audit-sink",
            "https://hooks.example",
            DestinationProfile::ProductionHttps,
            &[],
        )
        .expect("policy")
    }

    /// Resolve `length` key bytes through the real secret path, under an
    /// environment name unique to the length so parallel tests never race.
    fn key(length: usize) -> ProtectedSecret {
        let name = format!("REGISTRY_PLATFORM_HOOKS_DESTINATION_TEST_KEY_{length}");
        std::env::set_var(&name, "k".repeat(length));
        registry_platform_config::SecretResolver::new(
            [registry_platform_config::SecretProvider::Environment],
            "/",
        )
        .expect("resolver")
        .resolve(&format!("secret:env/{name}"))
        .expect("key")
    }

    fn parts(key: ProtectedSecret) -> UrlDestinationParts {
        UrlDestinationParts {
            binding_digest: "sha256:binding".to_owned(),
            request_target: "/hooks".to_owned(),
            policy: policy(),
            maximum_payload_bytes: 16 * 1024,
            hmac_sha256_key: key,
            attempt_timeout: Duration::from_secs(5),
            maximum_attempts: 3,
        }
    }

    #[test]
    fn destination_refuses_signing_keys_outside_their_bounds() {
        assert_eq!(
            UrlDestination::new(parts(key(MIN_HMAC_SHA256_KEY_BYTES - 1))).unwrap_err(),
            UrlDestinationError::InvalidSigningMaterial
        );
        let destination =
            UrlDestination::new(parts(key(MIN_HMAC_SHA256_KEY_BYTES))).expect("destination");
        assert_eq!(destination.request_target(), "/hooks");
        assert_eq!(destination.maximum_attempts(), 3);
    }

    #[test]
    fn destination_debug_redacts_the_key_and_target() {
        let destination = UrlDestination::new(parts(key(33))).expect("destination");
        let rendered = format!("{destination:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("/hooks"));
    }

    #[test]
    fn destination_signature_covers_post_and_json_over_the_request_target() {
        let destination = SharedUrlDestination(Arc::new(
            UrlDestination::new(parts(key(33))).expect("destination"),
        ));
        let fields = || DeliverySignatureFields {
            id: "event",
            source: "urn:source",
            event_type: "record.created",
            time: "2026-01-01T00:00:00Z",
            data_schema: "urn:schema",
            generation: "1",
            attempt: "1",
            delivery_time: "2026-01-01T00:00:01Z",
            idempotency_key: "key",
            body: b"{}",
        };
        let signed = destination.sign_delivery(fields()).expect("signed");
        let expected = sign_v1(
            "k".repeat(33).as_bytes(),
            SignatureFields {
                id: "event",
                source: "urn:source",
                event_type: "record.created",
                time: "2026-01-01T00:00:00Z",
                data_schema: "urn:schema",
                generation: "1",
                attempt: "1",
                delivery_time: "2026-01-01T00:00:01Z",
                method: "POST",
                request_target: "/hooks",
                content_type: "application/json",
                idempotency_key: "key",
                body: b"{}",
            },
        )
        .expect("expected");
        assert_eq!(signed, expected);
    }

    #[test]
    fn answer_read_failures_use_the_handler_taxonomy() {
        assert_eq!(
            answer_read_category(DestinationResponseError::BodyTooLarge),
            ErrorCategory::Resource
        );
        assert_eq!(
            answer_read_category(DestinationResponseError::BodyLimitTooHigh),
            ErrorCategory::Resource
        );
        assert_eq!(
            answer_read_category(DestinationResponseError::DeadlineExceeded),
            ErrorCategory::Deadline
        );
        assert_eq!(
            answer_read_category(DestinationResponseError::BodyReadFailed),
            ErrorCategory::Unavailable
        );
    }

    #[test]
    fn url_address_accepts_https_and_loopback_http_only() {
        let address = url_destination_address("https://hooks.example:8443").expect("https");
        assert_eq!(address.origin, "https://hooks.example:8443/");
        assert_eq!(address.request_target, "/");
        assert_eq!(address.profile, DestinationProfile::ProductionHttps);
        let address = url_destination_address("http://127.0.0.1:9000/in").expect("loopback");
        assert_eq!(address.request_target, "/in");
        assert_eq!(address.profile, DestinationProfile::LoopbackDevelopmentHttp);
        for refused in [
            "http://hooks.example/in",
            "https://user@hooks.example/in",
            "https://hooks.example/in?x=1",
            "https://hooks.example/in#x",
            "ftp://hooks.example/in",
            "not a url",
        ] {
            assert_eq!(
                url_destination_address(refused),
                Err(UrlDestinationError::InvalidBinding),
                "{refused}"
            );
        }
    }
}
