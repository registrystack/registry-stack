//! The caller's half of the protocol: building a client assertion.
//!
//! This is what a client does, not what Mint does. It holds no server state,
//! reads no server configuration, and touches no signing key of Mint's. It
//! signs with the *caller's* own private key, exactly as an adopter's client
//! library would, and produces an assertion that the token endpoint then
//! verifies on its own terms.
//!
//! That separation is deliberate and worth stating plainly, because the obvious
//! alternative is a subcommand that signs an access token directly with Mint's
//! signing key. That would be a way to obtain authority without authenticating,
//! inside the binary whose entire purpose is to make authority depend on
//! authentication. There is no such path here and there should never be one.
//!
//! Getting an assertion right by hand is fiddly (exact claims, a fresh `jti`, a
//! lifetime inside the configured bound) and getting it wrong yields an opaque
//! `invalid_client`. A first-party builder removes that guesswork and doubles as
//! executable documentation of the format.

use std::collections::BTreeMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_crypto::PrivateJwk;
use serde_json::{json, Map, Value};

use crate::ON_BEHALF_OF_CLAIM;

/// Refusals that happen before anything is signed.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum AssertionError {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("the assertion could not be signed: {0}")]
    Signing(String),
}

/// What a caller is asking for.
///
/// `actor` and `subject` are the delegation request. Mint requires them
/// together or not at all, and refuses a registered delegated client that omits
/// them, so this refuses the halfway states here rather than spending a network
/// round trip to be told.
#[derive(Debug)]
pub struct AssertionRequest<'a> {
    pub client_id: &'a str,
    /// The token endpoint's configured `clientAssertion.audience`.
    pub audience: &'a str,
    pub lifetime_seconds: i64,
    pub actor: Option<&'a str>,
    pub subject: Option<BTreeMap<String, Value>>,
}

/// Build and sign one client assertion.
///
/// `now` is a Unix timestamp, passed in rather than read so that the claim
/// arithmetic is testable.
pub fn sign_client_assertion(
    key: &PrivateJwk,
    request: &AssertionRequest<'_>,
    now: i64,
) -> Result<String, AssertionError> {
    if request.client_id.trim().is_empty() {
        return Err(AssertionError::Invalid("a client id is required"));
    }
    if request.audience.trim().is_empty() {
        return Err(AssertionError::Invalid("an assertion audience is required"));
    }
    // Mint bounds the assertion lifetime and applies 30 seconds of clock skew
    // either way; anything outside this is a caller error, not a policy choice.
    if !(1..=300).contains(&request.lifetime_seconds) {
        return Err(AssertionError::Invalid(
            "the assertion lifetime must be 1..=300 seconds",
        ));
    }

    let mut claims = Map::new();
    claims.insert("iss".to_owned(), json!(request.client_id));
    claims.insert("sub".to_owned(), json!(request.client_id));
    claims.insert("aud".to_owned(), json!(request.audience));
    claims.insert("iat".to_owned(), json!(now));
    claims.insert("exp".to_owned(), json!(now + request.lifetime_seconds));
    // Every assertion is single use. A caller-chosen `jti` would make a repeat
    // an accident waiting to happen, so it is generated here and never reused.
    claims.insert("jti".to_owned(), json!(ulid::Ulid::new().to_string()));

    match (request.actor, &request.subject) {
        (None, None) => {}
        (Some(actor), Some(subject)) => {
            if actor.trim().is_empty() {
                return Err(AssertionError::Invalid("the actor must not be empty"));
            }
            if subject.is_empty() {
                return Err(AssertionError::Invalid(
                    "the subject must name at least one selector field",
                ));
            }
            claims.insert(
                ON_BEHALF_OF_CLAIM.to_owned(),
                json!({"actor": actor, "subject": subject}),
            );
        }
        _ => {
            return Err(AssertionError::Invalid(
                "a delegation needs both an actor and a subject",
            ))
        }
    }

    let algorithm = key
        .algorithm()
        .map_err(|error| AssertionError::Signing(error.to_string()))?
        .jwa_name();
    let header = json!({
        "alg": algorithm,
        "typ": "JWT",
        "kid": key
            .kid
            .as_deref()
            .ok_or(AssertionError::Invalid("the signing key needs a kid"))?,
    });

    let encode = |value: &Value| -> Result<String, AssertionError> {
        serde_json::to_vec(value)
            .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
            .map_err(|error| AssertionError::Signing(error.to_string()))
    };
    let signing_input = format!("{}.{}", encode(&header)?, encode(&Value::Object(claims))?);
    let signature = registry_platform_crypto::sign(signing_input.as_bytes(), key)
        .map_err(|error| AssertionError::Signing(error.to_string()))?;
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn key() -> PrivateJwk {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        PrivateJwk::parse(
            &json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "caller-key-1",
                "alg": "EdDSA",
                "x": URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes()),
                "d": URL_SAFE_NO_PAD.encode(signing.to_bytes()),
            })
            .to_string(),
        )
        .expect("the test key parses")
    }

    fn request<'a>(client_id: &'a str, audience: &'a str) -> AssertionRequest<'a> {
        AssertionRequest {
            client_id,
            audience,
            lifetime_seconds: 120,
            actor: None,
            subject: None,
        }
    }

    fn claims_of(assertion: &str) -> Value {
        let payload = assertion.split('.').nth(1).expect("a payload segment");
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url"))
            .expect("claims parse")
    }

    #[test]
    fn an_assertion_carries_exactly_what_the_token_endpoint_requires() {
        let assertion = sign_client_assertion(
            &key(),
            &request("scheduler", "https://mint.example.org/token"),
            NOW,
        )
        .expect("the assertion signs");

        let claims = claims_of(&assertion);
        assert_eq!(claims["iss"], json!("scheduler"));
        assert_eq!(claims["sub"], json!("scheduler"));
        assert_eq!(claims["aud"], json!("https://mint.example.org/token"));
        assert_eq!(claims["iat"], json!(NOW));
        assert_eq!(claims["exp"], json!(NOW + 120));
        assert!(claims.get(ON_BEHALF_OF_CLAIM).is_none());

        let header: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(assertion.split('.').next().expect("a header segment"))
                .expect("base64url"),
        )
        .expect("header parses");
        assert_eq!(header["alg"], json!("EdDSA"));
        assert_eq!(header["typ"], json!("JWT"));
        assert_eq!(header["kid"], json!("caller-key-1"));
    }

    /// Reusing a `jti` is refused by Mint as a replay, so the builder must never
    /// produce the same one twice even when called with an identical request.
    #[test]
    fn every_assertion_gets_its_own_jti() {
        let key = key();
        let request = request("scheduler", "https://mint.example.org/token");
        let first = claims_of(&sign_client_assertion(&key, &request, NOW).expect("signs"));
        let second = claims_of(&sign_client_assertion(&key, &request, NOW).expect("signs"));

        assert_ne!(first["jti"], second["jti"]);
        assert!(first["jti"].as_str().is_some_and(|jti| !jti.is_empty()));
    }

    #[test]
    fn a_delegation_request_rides_inside_the_signed_claims() {
        let subject = BTreeMap::from([
            ("given_name".to_owned(), json!("Amara")),
            ("birth_date".to_owned(), json!("1998-04-02")),
        ]);
        let assertion = sign_client_assertion(
            &key(),
            &AssertionRequest {
                actor: Some("urn:example:agent:scheduler"),
                subject: Some(subject),
                ..request("scheduler", "https://mint.example.org/token")
            },
            NOW,
        )
        .expect("the assertion signs");

        let claims = claims_of(&assertion);
        assert_eq!(
            claims[ON_BEHALF_OF_CLAIM],
            json!({
                "actor": "urn:example:agent:scheduler",
                "subject": {"given_name": "Amara", "birth_date": "1998-04-02"},
            })
        );
    }

    /// Mint requires the actor and subject together, and refuses a registered
    /// delegated client that sends neither. Answering here saves a round trip
    /// that could only ever return an opaque `invalid_client`.
    #[test]
    fn half_a_delegation_is_refused_before_anything_is_signed() {
        let audience = "https://mint.example.org/token";
        let expected = || AssertionError::Invalid("a delegation needs both an actor and a subject");

        assert_eq!(
            sign_client_assertion(
                &key(),
                &AssertionRequest {
                    actor: Some("urn:example:agent:scheduler"),
                    ..request("scheduler", audience)
                },
                NOW,
            ),
            Err(expected())
        );
        assert_eq!(
            sign_client_assertion(
                &key(),
                &AssertionRequest {
                    subject: Some(BTreeMap::from([("given_name".to_owned(), json!("Amara"))])),
                    ..request("scheduler", audience)
                },
                NOW,
            ),
            Err(expected())
        );
    }

    #[test]
    fn empty_and_out_of_range_inputs_are_refused() {
        let audience = "https://mint.example.org/token";
        assert_eq!(
            sign_client_assertion(&key(), &request("  ", audience), NOW),
            Err(AssertionError::Invalid("a client id is required"))
        );
        assert_eq!(
            sign_client_assertion(&key(), &request("scheduler", ""), NOW),
            Err(AssertionError::Invalid("an assertion audience is required"))
        );
        for lifetime in [0, -1, 301] {
            assert_eq!(
                sign_client_assertion(
                    &key(),
                    &AssertionRequest {
                        lifetime_seconds: lifetime,
                        ..request("scheduler", audience)
                    },
                    NOW,
                ),
                Err(AssertionError::Invalid(
                    "the assertion lifetime must be 1..=300 seconds"
                )),
                "lifetime {lifetime} must be refused"
            );
        }
        assert_eq!(
            sign_client_assertion(
                &key(),
                &AssertionRequest {
                    actor: Some(" "),
                    subject: Some(BTreeMap::from([("given_name".to_owned(), json!("Amara"))])),
                    ..request("scheduler", audience)
                },
                NOW,
            ),
            Err(AssertionError::Invalid("the actor must not be empty"))
        );
        assert_eq!(
            sign_client_assertion(
                &key(),
                &AssertionRequest {
                    actor: Some("urn:example:agent:scheduler"),
                    subject: Some(BTreeMap::new()),
                    ..request("scheduler", audience)
                },
                NOW,
            ),
            Err(AssertionError::Invalid(
                "the subject must name at least one selector field"
            ))
        );
    }
}
