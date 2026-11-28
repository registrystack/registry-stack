// SPDX-License-Identifier: Apache-2.0

//! The `url` handler kind's destination: one activated logical destination,
//! its signing keys, and the bounded send that reads the answer back.
//!
//! The product builds the outbound policy (its network profile, DNS family,
//! private ranges, and TLS material are deployment configuration it owns) and
//! hands it here with the rest of the binding. From then on every product
//! signs and renders the canonical event with Standard Webhooks, then reads
//! a 2xx response body under the handler output ceiling.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use registry_platform_crypto::delivery_signature::{sign, DeliveryKeys};
use registry_platform_httputil::destination::{
    DestinationProfile, DestinationRequestError, DestinationResponseError, DestinationSendError,
    EventDestinationPolicy, EventDestinationRequest, EventDestinationRequestTemplate,
    SignedEventHeaders, MAX_DESTINATION_REQUEST_HEADER_BYTES, MAX_DESTINATION_TARGET_BYTES,
};
use registry_platform_httputil::loopback::PrivateRange;
use registry_platform_httputil::select::{
    select_destination, DestinationSelectionError, SelectedDestination, TransportClass,
};
use url::Url;

use super::seams::{
    DeliverySignatureFields, DeliverySignatureRefused, DestinationAnswer, HandlerRunFailure,
    HookDestination,
};
use crate::{ErrorCategory, MAX_OUTPUT_BYTES};

/// The shortest HMAC-SHA256 delivery key a destination accepts.
pub use registry_platform_crypto::delivery_signature::MIN_HMAC_SHA256_KEY_BYTES;

/// Value-free refusal while building a [`UrlDestination`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum UrlDestinationError {
    /// The request target or payload ceiling cannot form the closed event
    /// request template.
    #[error("the hook destination binding is invalid")]
    InvalidBinding,
    /// The shared destination selector refused the URL, its transport, or
    /// its private ranges.
    #[error("the hook destination is refused: {0}")]
    Refused(DestinationSelectionError),
}

impl UrlDestinationError {
    /// The selector's stable code for a [`Self::Refused`] destination, or
    /// `None` for a binding refused outside the selector.
    #[must_use]
    pub fn code(&self) -> Option<&'static str> {
        match self {
            Self::InvalidBinding => None,
            Self::Refused(error) => Some(error.code()),
        }
    }
}

/// Everything one activated `url` destination is built from.
pub struct UrlDestinationParts {
    /// The product's digest of this destination's non-secret binding.
    pub binding_digest: String,
    /// The exact request target the template sends to.
    pub request_target: String,
    /// The only outbound authority for this logical destination.
    pub policy: EventDestinationPolicy,
    /// The largest envelope this destination is sent.
    pub maximum_payload_bytes: usize,
    /// The validated delivery keys, in signing order.
    pub keys: DeliveryKeys,
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
    keys: DeliveryKeys,
    attempt_timeout: Duration,
    maximum_attempts: u8,
}

impl UrlDestination {
    /// Build the destination with a closed signed event template.
    ///
    /// # Errors
    ///
    /// [`UrlDestinationError`] names which part was refused, never a value.
    pub fn new(parts: UrlDestinationParts) -> Result<Self, UrlDestinationError> {
        let request_template = EventDestinationRequestTemplate::signed_event_delivery(
            &parts.request_target,
            parts.maximum_payload_bytes,
            MAX_DESTINATION_TARGET_BYTES
                + MAX_DESTINATION_REQUEST_HEADER_BYTES
                + parts.maximum_payload_bytes,
        )
        .map_err(|_| UrlDestinationError::InvalidBinding)?;
        Ok(Self {
            binding_digest: parts.binding_digest,
            request_target: parts.request_target,
            policy: Arc::new(parts.policy),
            request_template,
            keys: parts.keys,
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

    /// Borrow the exact request target the template sends to.
    #[must_use]
    pub fn request_target(&self) -> &str {
        &self.request_target
    }

    /// Signing keys for comparison across destinations, with their bytes kept private.
    pub fn keys(&self) -> &DeliveryKeys {
        &self.keys
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
            .field("keys", &"[REDACTED]")
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
        sign(self.0.keys(), fields.id, fields.timestamp, fields.body)
            .map_err(|_| DeliverySignatureRefused)
    }

    fn render_delivery(
        &self,
        headers: SignedEventHeaders<'_>,
        body: Vec<u8>,
    ) -> Result<EventDestinationRequest, DestinationRequestError> {
        self.0.request_template().render_signed_event(headers, body)
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
const fn answer_read_category(error: DestinationResponseError) -> ErrorCategory {
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
    /// `https` is production; plain `http` is accepted for a loopback host,
    /// and for any other host only under a declared private plain-text
    /// transport. A copy of `selected.profile()`.
    pub profile: DestinationProfile,
    /// The selection the outbound policy is frozen from: the profile, the
    /// transport, and the private ranges.
    pub selected: SelectedDestination,
}

/// Split a configured hook URL. The URL must carry a host and no user
/// information, query, or fragment; it must be `https`, or `http` to
/// `127.0.0.1`, `localhost`, or `[::1]`.
///
/// This is [`url_destination_address_selected`] with no declared transport
/// and no private range.
///
/// # Errors
///
/// [`UrlDestinationError::Refused`] with the selector's refusal, or
/// [`UrlDestinationError::InvalidBinding`] for a URL that does not parse or
/// carries user information, a query, or a fragment.
pub fn url_destination_address(
    configured: &str,
) -> Result<UrlDestinationAddress, UrlDestinationError> {
    url_destination_address_selected(configured, None, &[])
}

/// Split a configured hook URL under its declared transport and private
/// ranges, through the shared destination selector. The URL must carry a
/// host and no user information, query, or fragment.
///
/// # Errors
///
/// [`UrlDestinationError::Refused`] with the selector's refusal of the URL,
/// transport, or range list, or [`UrlDestinationError::InvalidBinding`] for
/// a URL that does not parse or carries user information, a query, or a
/// fragment.
pub fn url_destination_address_selected(
    configured: &str,
    declared: Option<TransportClass>,
    allowed_private_cidrs: &[PrivateRange],
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
    let selected = select_destination(&parsed, declared, allowed_private_cidrs)
        .map_err(UrlDestinationError::Refused)?;
    let profile = selected.profile();
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
        selected,
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

    fn keys(length: usize) -> DeliveryKeys {
        use registry_platform_crypto::delivery_signature::DeliveryKey;
        DeliveryKeys::new(DeliveryKey::new(&vec![b'k'; length]).unwrap(), None).unwrap()
    }

    fn parts(keys: DeliveryKeys) -> UrlDestinationParts {
        UrlDestinationParts {
            binding_digest: "sha256:binding".to_owned(),
            request_target: "/hooks".to_owned(),
            policy: policy(),
            maximum_payload_bytes: 16 * 1024,
            keys,
            attempt_timeout: Duration::from_secs(5),
            maximum_attempts: 3,
        }
    }

    #[test]
    fn destination_debug_redacts_the_key_and_target() {
        let destination = UrlDestination::new(parts(keys(33))).expect("destination");
        let rendered = format!("{destination:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("/hooks"));
    }

    #[test]
    fn a_hook_delivery_signs_id_timestamp_and_the_exact_body() {
        use registry_platform_crypto::delivery_signature::{
            verify, DeliveryKey, SignedContent, DELIVERY_TOLERANCE,
        };
        let destination = SharedUrlDestination(Arc::new(
            UrlDestination::new(parts(keys(33))).expect("destination"),
        ));
        let signed = destination
            .sign_delivery(DeliverySignatureFields {
                id: "event",
                timestamp: 1000,
                body: br#"{"ok":true}"#,
            })
            .unwrap();
        let keys = DeliveryKeys::new(DeliveryKey::new(&[b'k'; 33]).unwrap(), None).unwrap();
        let now = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let content = SignedContent {
            id: "event",
            timestamp: "1000",
            signature: &signed,
            body: br#"{"ok":true}"#,
        };
        assert_eq!(verify(&keys, content, now, DELIVERY_TOLERANCE), Ok(1000));
        for changed in [
            SignedContent {
                id: "other",
                ..content
            },
            SignedContent {
                timestamp: "1001",
                ..content
            },
            SignedContent {
                body: br#"{ "ok":true }"#,
                ..content
            },
        ] {
            assert!(verify(&keys, changed, now, DELIVERY_TOLERANCE).is_err());
        }
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
        assert_eq!(address.profile, DestinationProfile::LoopbackHttp);
        for (refused, expected) in [
            (
                "http://hooks.example/in",
                UrlDestinationError::Refused(DestinationSelectionError::PrivateNetworkNotDeclared),
            ),
            (
                "ftp://hooks.example/in",
                UrlDestinationError::Refused(DestinationSelectionError::UnsupportedScheme),
            ),
            (
                "https://user@hooks.example/in",
                UrlDestinationError::InvalidBinding,
            ),
            (
                "https://hooks.example/in?x=1",
                UrlDestinationError::InvalidBinding,
            ),
            (
                "https://hooks.example/in#x",
                UrlDestinationError::InvalidBinding,
            ),
            ("not a url", UrlDestinationError::InvalidBinding),
        ] {
            assert_eq!(url_destination_address(refused), Err(expected), "{refused}");
        }
    }

    #[test]
    fn url_address_follows_the_shared_loopback_definition() {
        for admitted in [
            "http://127.0.0.1:9000/in",
            "http://127.0.0.2:9000/in",
            "http://[::1]:9000/in",
            "http://[::ffff:127.0.0.1]:9000/in",
            "http://localhost:9000/in",
            "http://LOCALHOST:9000/in",
        ] {
            let address = url_destination_address(admitted).expect(admitted);
            assert_eq!(
                address.profile,
                DestinationProfile::LoopbackHttp,
                "{admitted}"
            );
        }
        for refused in [
            "http://localhost.:9000/in",
            "http://hooks.localhost:9000/in",
            "http://127.0.0.1.example:9000/in",
            "http://0.0.0.0:9000/in",
            "http://[::]:9000/in",
            "http://10.0.0.1:9000/in",
            "http://[::ffff:10.0.0.1]:9000/in",
        ] {
            assert_eq!(
                url_destination_address(refused),
                Err(UrlDestinationError::Refused(
                    DestinationSelectionError::PrivateNetworkNotDeclared
                )),
                "{refused}"
            );
        }
    }

    fn ranges(texts: &[&str]) -> Vec<PrivateRange> {
        texts.iter().map(|text| text.parse().expect(text)).collect()
    }

    fn refused(
        error: DestinationSelectionError,
    ) -> Result<DestinationProfile, UrlDestinationError> {
        Err(UrlDestinationError::Refused(error))
    }

    /// The load rows of the M8 test table, through the hook seam. A refusal
    /// of the shared selector keeps its code.
    #[test]
    fn url_address_selects_the_declared_transport_and_ranges() {
        const PRIVATE: Option<TransportClass> = Some(TransportClass::PrivateNetworkPlaintext);
        const LOOPBACK: Option<TransportClass> = Some(TransportClass::LoopbackPlaintext);
        const TLS: Option<TransportClass> = Some(TransportClass::VerifiedTls);
        let seventeen: Vec<String> = (0..17).map(|n| format!("10.{n}.0.0/16")).collect();
        let seventeen: Vec<&str> = seventeen.iter().map(String::as_str).collect();
        for (row, url, declared, listed, expected) in [
            (
                "T1",
                "https://hooks.example.org/x",
                None,
                &[][..],
                Ok(DestinationProfile::ProductionHttps),
            ),
            (
                "T2",
                "https://registry.internal/",
                None,
                &["10.0.0.0/8"][..],
                Ok(DestinationProfile::ProductionHttps),
            ),
            (
                "T4",
                "http://localhost:8080/",
                None,
                &[][..],
                Ok(DestinationProfile::LoopbackHttp),
            ),
            (
                "T5",
                "http://127.0.0.1:8080/",
                LOOPBACK,
                &[][..],
                Ok(DestinationProfile::LoopbackHttp),
            ),
            (
                "T6",
                "http://hooks:8080/",
                None,
                &["10.0.0.0/8"][..],
                refused(DestinationSelectionError::PrivateNetworkNotDeclared),
            ),
            (
                "T7",
                "http://hooks:8080/",
                PRIVATE,
                &[][..],
                refused(DestinationSelectionError::PrivateNetworkRequiresRanges),
            ),
            (
                "T8",
                "http://hooks:8080/",
                PRIVATE,
                &["172.16.0.0/12"][..],
                Ok(DestinationProfile::PrivateServiceHttp),
            ),
            (
                "T15",
                "http://hooks:8080/",
                PRIVATE,
                &seventeen[..],
                refused(DestinationSelectionError::TooManyRanges),
            ),
            (
                "T16",
                "https://hooks:8443/",
                PRIVATE,
                &["10.0.0.0/8"][..],
                refused(DestinationSelectionError::TransportSchemeMismatch),
            ),
            (
                "T17",
                "http://hooks:8080/",
                TLS,
                &[][..],
                refused(DestinationSelectionError::TransportSchemeMismatch),
            ),
            (
                "T18",
                "http://localhost:8080/",
                PRIVATE,
                &["10.0.0.0/8"][..],
                refused(DestinationSelectionError::TransportHostMismatch),
            ),
            (
                "T19",
                "http://hooks:8080/",
                LOOPBACK,
                &[][..],
                refused(DestinationSelectionError::TransportHostMismatch),
            ),
            (
                "T20",
                "http://10.1.2.3:8080/",
                PRIVATE,
                &["172.16.0.0/12"][..],
                refused(DestinationSelectionError::LiteralOutsideRanges),
            ),
            (
                "T25",
                "ftp://hooks/",
                None,
                &[][..],
                refused(DestinationSelectionError::UnsupportedScheme),
            ),
            (
                "userinfo",
                "http://user@hooks:8080/",
                PRIVATE,
                &["10.0.0.0/8"][..],
                Err(UrlDestinationError::InvalidBinding),
            ),
            (
                "query",
                "http://hooks:8080/in?x=1",
                PRIVATE,
                &["10.0.0.0/8"][..],
                Err(UrlDestinationError::InvalidBinding),
            ),
            (
                "fragment",
                "http://hooks:8080/in#x",
                PRIVATE,
                &["10.0.0.0/8"][..],
                Err(UrlDestinationError::InvalidBinding),
            ),
        ] {
            let selected = url_destination_address_selected(url, declared, &ranges(listed));
            match expected {
                Ok(profile) => {
                    let address = selected.unwrap_or_else(|error| panic!("{row}: {error:?}"));
                    assert_eq!(address.profile, profile, "{row}");
                    assert_eq!(address.selected.profile(), profile, "{row}");
                    assert_eq!(
                        address.selected.allowed_private_cidrs().len(),
                        listed.len(),
                        "{row}"
                    );
                }
                Err(refusal) => {
                    assert_eq!(selected.map(drop), Err(refusal), "{row}");
                    if let UrlDestinationError::Refused(error) = refusal {
                        assert_eq!(refusal.code(), Some(error.code()), "{row}");
                    } else {
                        assert_eq!(refusal.code(), None, "{row}");
                    }
                }
            }
        }
    }

    #[test]
    fn a_private_plain_text_address_keeps_its_origin_target_and_ranges() {
        let address = url_destination_address_selected(
            "http://receiver:9000/hooks/events",
            Some(TransportClass::PrivateNetworkPlaintext),
            &ranges(&["172.16.0.0/12", "10.42.0.0/16"]),
        )
        .expect("a declared private plain-text destination");
        assert_eq!(address.origin, "http://receiver:9000/");
        assert_eq!(address.request_target, "/hooks/events");
        assert_eq!(address.profile, DestinationProfile::PrivateServiceHttp);
        assert!(address.selected.is_private_plaintext());
        let policy = EventDestinationPolicy::from_selected("receiver", &address.selected)
            .expect("the selection freezes");
        let printed = format!("{policy:?}");
        assert!(printed.contains("PrivateServiceHttp"), "{printed}");
        assert!(printed.contains("private_cidr_count: 2"), "{printed}");
    }

    /// The one-argument form declares no transport and no range: https,
    /// or http to loopback, and nothing else.
    #[test]
    fn the_one_argument_address_admits_https_and_loopback_only() {
        let not_declared =
            UrlDestinationError::Refused(DestinationSelectionError::PrivateNetworkNotDeclared);
        for (url, expected) in [
            (
                "https://hooks.example:8443",
                Ok(DestinationProfile::ProductionHttps),
            ),
            (
                "https://hooks.example/in",
                Ok(DestinationProfile::ProductionHttps),
            ),
            (
                "http://127.0.0.1:9000/in",
                Ok(DestinationProfile::LoopbackHttp),
            ),
            (
                "http://localhost:9000/in",
                Ok(DestinationProfile::LoopbackHttp),
            ),
            ("http://[::1]:9000/in", Ok(DestinationProfile::LoopbackHttp)),
            ("http://hooks.example/in", Err(not_declared)),
            ("http://10.0.0.1:9000/in", Err(not_declared)),
            ("http://hooks.localhost:9000/in", Err(not_declared)),
            (
                "ftp://hooks.example/in",
                Err(UrlDestinationError::Refused(
                    DestinationSelectionError::UnsupportedScheme,
                )),
            ),
            (
                "https://user@hooks.example/in",
                Err(UrlDestinationError::InvalidBinding),
            ),
            (
                "https://hooks.example/in?x=1",
                Err(UrlDestinationError::InvalidBinding),
            ),
            ("not a url", Err(UrlDestinationError::InvalidBinding)),
        ] {
            let address = url_destination_address(url);
            assert_eq!(
                address.as_ref().map(|address| address.profile),
                expected.as_ref().copied(),
                "{url}"
            );
            if let Ok(address) = address {
                assert_eq!(address.selected.profile(), address.profile, "{url}");
                assert!(address.selected.allowed_private_cidrs().is_empty(), "{url}");
            }
        }
    }
}
