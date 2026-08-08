//! One signed client assertion, for the RFC 7523 section 2.2 `private_key_jwt`
//! client authentication method.
//!
//! The client proves who it is by signing a short-lived assertion with a key
//! only it holds, so no shared secret ever leaves the process or sits in a
//! deployment's configuration.
//!
//! This module is the whole of what such an assertion is, and nothing else. It
//! performs no request, caches nothing, and knows no authorization server:
//! whoever calls it owns the token request the assertion is presented on and
//! whatever is issued in return. That boundary is what lets a service
//! authenticating to a source and a relying-party client library share one
//! assertion format rather than one of them depending on the other.
//!
//! It is plain OAuth, and carries no claim, route, or vocabulary belonging to
//! any particular issuer. A server that also requires a scope, a resource
//! indicator, or claims of its own needs those from the caller that builds its
//! token request; they are not part of the assertion signed here.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_crypto::{PrivateJwk, SigningAlgorithm};
use serde_json::{json, Value};
use thiserror::Error;
use ulid::Ulid;
use zeroize::Zeroizing;

/// Lifetime of one client assertion, when the caller states none.
///
/// The assertion is presented once, immediately, to one endpoint. Seconds are
/// enough, and a short window is what limits what a captured assertion is worth.
pub const DEFAULT_ASSERTION_LIFETIME_SECONDS: i64 = 60;

/// Longest assertion lifetime this builder will sign.
///
/// Authorization servers bound what they accept, and a request signed outside
/// that bound is refused with a code that says nothing about the reason.
pub const MAXIMUM_ASSERTION_LIFETIME_SECONDS: i64 = 300;

/// Why an assertion was not signed.
///
/// Deliberately not `#[non_exhaustive]`: a caller renders each of these as its
/// own refusal, and a new one must be a decision made wherever assertions are
/// consumed rather than something that silently lands in a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ClientAssertionError {
    /// `iss` and `sub` name the client, so there is nothing to sign without it.
    #[error("the client identifier must not be empty")]
    EmptyClientId,
    /// An assertion no server will recognize itself in is not worth signing.
    #[error("the assertion audience must not be empty")]
    EmptyAudience,
    /// The server selects the registered public key by this identifier.
    #[error("the signing key must carry a key identifier")]
    MissingKeyId,
    /// The key states an algorithm this stack does not sign with.
    #[error("the signing key must state a supported signing algorithm")]
    UnsupportedAlgorithm,
    /// The requested lifetime is outside `1..=MAXIMUM_ASSERTION_LIFETIME_SECONDS`.
    #[error("the assertion lifetime must be within 1..=300 seconds")]
    LifetimeOutOfRange,
    /// The header or the claim set could not be serialized.
    #[error("the client assertion cannot be serialized")]
    NotSerializable,
    /// The key parsed and named an algorithm, yet cannot sign with it.
    #[error("the signing key cannot sign a client assertion")]
    CannotSign,
}

/// What one assertion asserts.
#[derive(Debug, Clone, Copy)]
pub struct ClientAssertionRequest<'a> {
    /// The registered client identifier. RFC 7523 section 2.2 puts it in both
    /// `iss` and `sub`.
    pub client_id: &'a str,
    /// What the authorization server expects in `aud`. RFC 7523 section 3
    /// recommends the token endpoint URL, and a server that published something
    /// else refuses an assertion carrying anything but that value.
    pub audience: &'a str,
    /// Seconds from `issued_at` until the assertion expires. Must be within
    /// `1..=MAXIMUM_ASSERTION_LIFETIME_SECONDS`.
    pub lifetime_seconds: i64,
    /// The Unix time the assertion is dated from. It is passed in rather than
    /// read here, because the caller owns which clock the claims are built on:
    /// `iat` and `exp` are wall-clock times an authorization server checks
    /// against its own clock, so nothing else will do.
    pub issued_at: i64,
}

/// Build and sign one client assertion, and return its compact serialization.
///
/// The result is a credential, so it is returned in a buffer that is wiped when
/// the caller drops it.
///
/// # Errors
///
/// Returns [`ClientAssertionError`] when the request names no client or
/// audience, when the key carries no identifier or states an algorithm this
/// stack does not sign with, when the lifetime is outside the bound, or when
/// the key cannot actually sign.
pub fn sign_client_assertion(
    key: &PrivateJwk,
    request: &ClientAssertionRequest<'_>,
) -> Result<Zeroizing<String>, ClientAssertionError> {
    if request.client_id.trim().is_empty() {
        return Err(ClientAssertionError::EmptyClientId);
    }
    if request.audience.trim().is_empty() {
        return Err(ClientAssertionError::EmptyAudience);
    }
    // Ties the refusal's message to the constant, so the two cannot drift apart.
    const _: () = assert!(MAXIMUM_ASSERTION_LIFETIME_SECONDS == 300);
    if !(1..=MAXIMUM_ASSERTION_LIFETIME_SECONDS).contains(&request.lifetime_seconds) {
        return Err(ClientAssertionError::LifetimeOutOfRange);
    }
    let key_id = key
        .kid
        .as_deref()
        .filter(|kid| !kid.trim().is_empty())
        .ok_or(ClientAssertionError::MissingKeyId)?;
    // The header names the algorithm so the server can verify without guessing,
    // which means it must state what this key actually signs with rather than
    // one fixed name.
    let algorithm = key
        .algorithm()
        .map_err(|_| ClientAssertionError::UnsupportedAlgorithm)?;

    let header = json!({
        "alg": header_algorithm(algorithm),
        "typ": "JWT",
        // The server selects the registered public key by this identifier.
        "kid": key_id,
    });
    let claims = json!({
        "iss": request.client_id,
        "sub": request.client_id,
        "aud": request.audience,
        "iat": request.issued_at,
        "exp": request.issued_at.saturating_add(request.lifetime_seconds),
        // Every assertion is single use. A server that caches identifiers to
        // refuse a replay needs each request to bring its own, so one is
        // generated per assertion and never reused.
        "jti": Ulid::new().to_string(),
    });

    let signing_input = format!("{}.{}", encode(&header)?, encode(&claims)?);
    // Stating an algorithm is not the same as being able to sign with it: a
    // P-256 scalar of zero and an RSA key whose components disagree both parse.
    // Those are refused only where the key is imported, which is here.
    let signature = registry_platform_crypto::sign(signing_input.as_bytes(), key)
        .map_err(|_| ClientAssertionError::CannotSign)?;
    Ok(Zeroizing::new(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    )))
}

/// The JOSE `alg` header value naming `algorithm`.
///
/// The name itself comes from the crypto crate, so there is one spelling of it
/// in the workspace. The match exists to enumerate the variants with no
/// wildcard arm: a signing algorithm added there has to be considered here,
/// as a compile error rather than as an assertion no server can verify.
const fn header_algorithm(algorithm: SigningAlgorithm) -> &'static str {
    match algorithm {
        SigningAlgorithm::EdDsa
        | SigningAlgorithm::Es256
        | SigningAlgorithm::Rs256
        | SigningAlgorithm::Es384
        | SigningAlgorithm::Rs384 => algorithm.jwa_name(),
    }
}

/// One JWS segment: the compact JSON of `value`, base64url encoded without
/// padding.
fn encode(value: &Value) -> Result<String, ClientAssertionError> {
    serde_json::to_vec(value)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|_| ClientAssertionError::NotSerializable)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use registry_platform_crypto::verify;
    use serde_json::json;

    use super::*;

    /// The instant the assertions in this module are dated from.
    const NOW: i64 = 1_785_000_000;
    const CLIENT_ID: &str = "urn:example:client:relying-party";
    const AUDIENCE: &str = "https://tokens.example.org/token";
    const KEY_ID: &str = "client-key-2026-01";

    /// One test-only signing key per algorithm the crypto crate registers.
    ///
    /// They are the same pinned documents `registry-platform-crypto` uses for
    /// its own signing tests, so this module puts no new key material in the
    /// tree. They authenticate nothing.
    const ED25519_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.test#key-1"}"#;
    const P256_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"did:web:issuer.test#p256-key-1"}"#;
    const P384_JWK: &str = r#"{"kty":"EC","crv":"P-384","d":"Cp2oq8BnIF6oQ2KWV-1yiR7Mf0rFOuDZ5nvS9E_9HGEODI76izZiDEFQ5kfSwCAg","x":"TH-XDvwYtzdc43QDOiBjfdQZTCx1k9Rz5ELDu_2NS8JWcCv8HlfK0T9rYijDIcAY","y":"eLx0gh3VmCC2DeubmC0CdDgno7aEBYEkz5Legyg-2GoLlFohSIop3zKCGSjhg7Ta","alg":"ES384","kid":"did:web:issuer.test#p384-key-1"}"#;
    const RSA_JWK: &str = r#"{"kty":"RSA","kid":"registry-platform-rs256-test","alg":"RS256","n":"yIgEn3IXWI3CRyUY0gvZ-kJ55EC36MRFvj-ICsitN1-50phRS4CKMBRwbHwjgeTkbMDndOCmVfIbyKhJjOMIPxAzIHeMn9oWj5i-s8nlSgjHZpvCTnRbwZhbq6mEVoHJliX36IfV_iUopcwSL5lPd2wZmJ-msUmZFs6CTRExu0JGUJScOwFO5dqxBwiKyh7yGEPXI3u4tc3_47SZYxyde7fb-o3wl2RBJ28upa2jVRP9r-WjOGjE6tbZ35HnVUY4ECdYWzsiotg_XA9QVWa-pAKXV2Flr-gocCQ9E2qrSYjEbNXuFjPtMnuL6AHi0o5PiwT1dllcl925hpKd7Xt60w","e":"AQAB","d":"ATDtMhpe_z1-GTUV7NLO3V_Z0kb8W1YXkC7JbJTAdcE-FdKJrtu84Q87WpxG0tPcutFPLqW12QAQp2fbmxhZ6VrfVYneeOlEjO14ukqM_g35Z-eRDmYhwoFYrEWGqlH9XrZysHhKFZyKHW_G0lJV-Ks8Na_RFNNIXeVedVMQiytAFXibTHvdAdIrBGtt0M4tlQOCeRwnuoAQU-a5VB7rKGpxnJtUA7F_jjeX6jQPnUhkOXs20pPRey-i-jxwBbsF4XijHgTnGwAo5uOoY9b0kOmOb3Hs5TVqZCb3a4JoYAqZBbWrkKxccJTGMqLHCe0MBgQzKqP5KyrHRgQdzlmTnQ","p":"5xhkHe5lD7tUYJAFffHiRpy4unHfKDvTEASu8RBgWvHP2Hu5XLQU5n6DvI47LsW42swTcT6Ce1pWB2LK3SjKcw9FPEEGg8m5-tmfixaRq4DBaK0hj17763HmnYR0eQC0n_5y-My8WSC1y80T-AhKHJ_3xTtLXQd5Z9bf9MEiKS8","q":"3iRoiwbnn8oRJMjZUZhqKB-GVa7AJV0SUqXiUsBAJnqtbhuIESbkJKpt5eULeUQgdNkoG65KD-jXFUipWX1zlentc1FliCaB46jntqtxUsui8LNwKw_eb3nujQO7H1He4NJ5pfaLfRcmBOLwB-u2Z1cxrRDWhIgiHtGaAdQ7F50","dp":"j4h9vn1wNbozaRpq3tPap-L1dY_-e93UdPGDuuRiBHqGjr4h3itXg-X2aqmopp9V9kekl8SshHMSVdoNiBmqzJYieY8lvbsQkXaTem8VIQGCn0JRQtxK-eyvwQwgz3sZtPn0bQW0wmLnp2KD0Z1McsUEvnLalzhqNo2mYj2Guy8","dq":"0T6ySuLCIz2PUHrwWW-b7xdizirBS3CT5c3jldcJljVQT7sXPDDKDc-LnVVWrW-Csw4qPYi6sqm8j4vWGTmWOswSouE1Jj4_c1aSjPqI0FiIrvoW2jkkaRUNoz60cBgKPPOFKtNFKRs48LljJ9LcChOT81U8-7HPkgAVdUuYLfE","qi":"PnMeCE0dvWDLp2Dn1wsxtl-a0qjpkT9cp8EkvHYjCvVqqWqrVv84CoEo-1wA9j_VDvCG6T4n0UO9K0jfBf5yvPnahSQCLJk2nw-2uZ9YzBZKwkm21wU6hTknPst5Vk5ZbYJmzqXsCqEB5T2Bn5vqeXMe3SOB5hD2CbTFFfp3TC4"}"#;

    /// A test key under this module's own key identifier, so the header
    /// assertions do not depend on whichever one the pinned document carries.
    fn signing_key(document: &str) -> PrivateJwk {
        let mut key = PrivateJwk::parse(document).expect("the test key parses");
        key.kid = Some(KEY_ID.to_owned());
        key
    }

    /// The pinned RSA key restated under `alg`, which is the only difference
    /// between an RS256 and an RS384 RSA JWK.
    fn rsa_signing_key(alg: &str) -> PrivateJwk {
        let mut key = signing_key(RSA_JWK);
        key.alg = Some(alg.to_owned());
        key
    }

    fn request(lifetime_seconds: i64) -> ClientAssertionRequest<'static> {
        ClientAssertionRequest {
            client_id: CLIENT_ID,
            audience: AUDIENCE,
            lifetime_seconds,
            issued_at: NOW,
        }
    }

    fn parts(assertion: &str) -> (Value, Value, Vec<u8>) {
        let segments: Vec<&str> = assertion.split('.').collect();
        assert_eq!(segments.len(), 3, "an assertion carries three segments");
        let decode = |segment: &str| {
            let bytes = URL_SAFE_NO_PAD
                .decode(segment)
                .expect("the segment is base64url");
            serde_json::from_slice::<Value>(&bytes).expect("the segment carries JSON")
        };
        let signature = URL_SAFE_NO_PAD
            .decode(segments[2])
            .expect("the signature is base64url");
        (decode(segments[0]), decode(segments[1]), signature)
    }

    fn signing_input(assertion: &str) -> &str {
        let boundary = assertion
            .rfind('.')
            .expect("an assertion carries three segments");
        &assertion[..boundary]
    }

    /// RFC 7523 section 2.2 fixes the claim set the token endpoint reads. The
    /// header names the key so the server can select it without guessing.
    #[test]
    fn an_assertion_carries_the_claims_the_token_endpoint_requires() {
        let key = signing_key(ED25519_JWK);

        let assertion = sign_client_assertion(&key, &request(DEFAULT_ASSERTION_LIFETIME_SECONDS))
            .expect("the assertion is signed");

        let (header, claims, signature) = parts(&assertion);
        assert_eq!(header, json!({"alg": "EdDSA", "typ": "JWT", "kid": KEY_ID}));
        assert_eq!(claims["iss"], json!(CLIENT_ID));
        assert_eq!(claims["sub"], json!(CLIENT_ID));
        assert_eq!(claims["iss"], claims["sub"]);
        assert_eq!(claims["aud"], json!(AUDIENCE));
        assert_eq!(claims["iat"], json!(NOW));
        assert_eq!(
            claims["exp"],
            json!(NOW + DEFAULT_ASSERTION_LIFETIME_SECONDS)
        );
        assert_eq!(
            claims["jti"]
                .as_str()
                .expect("the assertion carries a jti")
                .len(),
            26,
            "the jti is a ULID"
        );
        let members: BTreeSet<&str> = claims
            .as_object()
            .expect("the claims are an object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            members,
            ["aud", "exp", "iat", "iss", "jti", "sub"]
                .into_iter()
                .collect(),
            "the assertion carries exactly the claims the profile fixes"
        );
        verify(
            signing_input(&assertion).as_bytes(),
            &signature,
            &key.public(),
        )
        .expect("the assertion verifies under the signing key");
        let secret = key
            .d
            .clone()
            .expect("the test key carries private material");
        assert!(
            !assertion.contains(&secret),
            "the assertion carries the private key"
        );
    }

    /// A caller states how long its assertion is good for, and `exp` says so.
    #[test]
    fn an_assertion_expires_after_the_requested_lifetime() {
        for lifetime_seconds in [1, 30, MAXIMUM_ASSERTION_LIFETIME_SECONDS] {
            let assertion =
                sign_client_assertion(&signing_key(ED25519_JWK), &request(lifetime_seconds))
                    .expect("the assertion is signed");

            let (_, claims, _) = parts(&assertion);
            assert_eq!(claims["exp"], json!(NOW + lifetime_seconds));
        }
    }

    /// The header must name the algorithm the key actually signs with, for
    /// every algorithm the stack registers, and what it names must be what
    /// verifies. A server selects the verification algorithm from this header,
    /// so a fixed `alg` would either refuse the key outright or present a
    /// signature under a name that does not describe it.
    #[test]
    fn an_assertion_verifies_under_every_algorithm_the_stack_signs_with() {
        let keys = [
            ("EdDSA", signing_key(ED25519_JWK)),
            ("ES256", signing_key(P256_JWK)),
            ("ES384", signing_key(P384_JWK)),
            ("RS256", rsa_signing_key("RS256")),
            ("RS384", rsa_signing_key("RS384")),
        ];

        for (expected_alg, key) in keys {
            let assertion =
                sign_client_assertion(&key, &request(DEFAULT_ASSERTION_LIFETIME_SECONDS))
                    .unwrap_or_else(|error| {
                        panic!("the {expected_alg} assertion is signed: {error}")
                    });

            let (header, _, signature) = parts(&assertion);
            assert_eq!(
                header,
                json!({"alg": expected_alg, "typ": "JWT", "kid": KEY_ID})
            );
            verify(
                signing_input(&assertion).as_bytes(),
                &signature,
                &key.public(),
            )
            .unwrap_or_else(|error| {
                panic!("the {expected_alg} assertion verifies under the signing key: {error}")
            });
        }
    }

    /// A replay-checking token endpoint refuses a repeated `jti`, so a fresh one
    /// per assertion is what makes a second token request possible at all.
    #[test]
    fn every_assertion_gets_its_own_jti() {
        let key = signing_key(ED25519_JWK);

        let first = sign_client_assertion(&key, &request(DEFAULT_ASSERTION_LIFETIME_SECONDS))
            .expect("the assertion is signed");
        let second = sign_client_assertion(&key, &request(DEFAULT_ASSERTION_LIFETIME_SECONDS))
            .expect("the assertion is signed");

        let (_, first_claims, _) = parts(&first);
        let (_, second_claims, _) = parts(&second);
        assert_ne!(first_claims["jti"], second_claims["jti"]);
        assert_eq!(first_claims["iat"], second_claims["iat"]);
    }

    /// The bound is what keeps a captured assertion worth little, so it is
    /// enforced at both ends rather than trusted to the caller.
    #[test]
    fn an_assertion_lifetime_outside_the_bound_is_refused() {
        let key = signing_key(ED25519_JWK);

        for lifetime_seconds in [
            i64::MIN,
            -1,
            0,
            MAXIMUM_ASSERTION_LIFETIME_SECONDS + 1,
            i64::MAX,
        ] {
            assert_eq!(
                sign_client_assertion(&key, &request(lifetime_seconds)),
                Err(ClientAssertionError::LifetimeOutOfRange),
                "lifetime {lifetime_seconds}"
            );
        }

        for lifetime_seconds in [1, MAXIMUM_ASSERTION_LIFETIME_SECONDS] {
            assert!(
                sign_client_assertion(&key, &request(lifetime_seconds)).is_ok(),
                "lifetime {lifetime_seconds}"
            );
        }
    }

    /// Stating an algorithm is not the same as being able to sign with it. A
    /// P-256 scalar of zero and an RSA key whose components disagree are both
    /// well-formed enough to parse, and are rejected only where the key is
    /// imported. Each must be reported, not panicked on.
    ///
    /// There is no EdDSA counterpart, because every 32-byte string is a valid
    /// Ed25519 seed. That asymmetry is why signing with EdDSA alone would never
    /// exercise this at all.
    #[test]
    fn a_key_that_states_an_algorithm_it_cannot_sign_with_is_refused() {
        let unsignable_es256 = {
            let mut key = signing_key(P256_JWK);
            key.d = Some(URL_SAFE_NO_PAD.encode([0u8; 32]));
            key
        };
        let unsignable_rs256 = {
            let mut key = rsa_signing_key("RS256");
            key.p = key.q.clone();
            key
        };

        for (label, key) in [("ES256", unsignable_es256), ("RS256", unsignable_rs256)] {
            assert_eq!(
                sign_client_assertion(&key, &request(DEFAULT_ASSERTION_LIFETIME_SECONDS)),
                Err(ClientAssertionError::CannotSign),
                "{label}"
            );
        }
    }

    /// A key stating an algorithm the crypto crate does not sign with produces
    /// a refusal rather than an assertion under some other name. Parsing a JWK
    /// already refuses one, so this is a floor rather than a path a caller
    /// reaches by parsing a document.
    #[test]
    fn a_key_stating_an_unsupported_algorithm_is_refused() {
        let mut key = signing_key(ED25519_JWK);
        key.alg = Some("HS256".to_owned());

        assert_eq!(
            sign_client_assertion(&key, &request(DEFAULT_ASSERTION_LIFETIME_SECONDS)),
            Err(ClientAssertionError::UnsupportedAlgorithm)
        );
    }

    /// Each of these produces an assertion no server can act on, so each is
    /// refused before anything is signed.
    #[test]
    fn an_assertion_needs_a_client_an_audience_and_a_key_identifier() {
        let key = signing_key(ED25519_JWK);
        let base = request(DEFAULT_ASSERTION_LIFETIME_SECONDS);

        for client_id in ["", "   "] {
            assert_eq!(
                sign_client_assertion(&key, &ClientAssertionRequest { client_id, ..base }),
                Err(ClientAssertionError::EmptyClientId)
            );
        }
        for audience in ["", "   "] {
            assert_eq!(
                sign_client_assertion(&key, &ClientAssertionRequest { audience, ..base }),
                Err(ClientAssertionError::EmptyAudience)
            );
        }
        for key_id in [None, Some(String::new()), Some("   ".to_owned())] {
            let mut without_key_id = signing_key(ED25519_JWK);
            without_key_id.kid = key_id.clone();
            assert_eq!(
                sign_client_assertion(&without_key_id, &base),
                Err(ClientAssertionError::MissingKeyId),
                "kid {key_id:?}"
            );
        }
    }
}
