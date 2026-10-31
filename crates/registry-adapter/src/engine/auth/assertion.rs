// SPDX-License-Identifier: Apache-2.0

//! The concrete RFC 7523 client-assertion signer of section 10.2: the
//! platform's signing routine, not one of this crate's.
//!
//! [`ClientAssertionSigner`] is the seam the token machinery signs
//! through; this module is the engine's implementation of that seam and
//! holds no signing logic of its own. The key document arrives already
//! resolved by the token plan, inside this layer's zeroizing buffer,
//! from the deployment's secret references; this module parses it with
//! the platform crypto crate's untrusted-input entry point, proves its
//! two halves pair, and hands it to
//! `registry-platform-authcommon`'s `sign_client_assertion`, the same
//! routine Evidence signs its own assertions with. Keyed and bounded as
//! Evidence keys and bounds its own: the same
//! `ClientAssertionRequest` shape, the same `1..=300` second lifetime
//! bound with the call site supplying the platform's 60-second default,
//! and the caller's issuance instant rather than a clock read here.
//!
//! No key material crosses this module in any direction except the
//! assertion itself. The document is read out of one zeroizing buffer,
//! the assertion is moved into another without an intermediate copy,
//! and every refusal is one value-free [`AuthError::Credential`]:
//! fixed text that names no member of the key document, no byte of the
//! signature, and no endpoint.

use crate::engine::auth::{AuthError, ClientAssertion, ClientAssertionSigner, ProtectedText};
use registry_platform_authcommon::client_assertion::{
    sign_client_assertion, ClientAssertionRequest,
};
use registry_platform_crypto::PrivateJwk;
use zeroize::Zeroizing;

/// What the signer proves the key with before it signs an assertion.
///
/// It carries a space and no `.`, so it cannot be read as the
/// `base64url(header).base64url(claims)` a client assertion is signed
/// over. The signature is discarded, and could not stand in for one
/// even if it were not.
const CLIENT_KEY_PROBE: &[u8] = b"registry-adapter auth client key usability probe";

/// The engine's client-assertion signer: the platform's RFC 7523
/// routine over the key document the token plan resolved.
///
/// The signer is stateless and holds no key material, because the key
/// arrives with each request and never outlives it: one instance serves
/// every endpoint of every exchange, and nothing it signs is cached
/// here. What it adds around the platform routine is the key's
/// untrusted-input parse, the pairing proof below, and the refusal
/// mapping into this layer's value-free credential error.
///
/// Every fault is [`AuthError::Credential`]: an unusable key document,
/// a key whose halves do not pair, and a lifetime outside the bound the
/// platform enforces are all one fixed-text refusal, so no diagnostic
/// this layer renders can name what was in the key.
#[derive(Debug)]
pub struct PlatformAssertionSigner;

impl ClientAssertionSigner for PlatformAssertionSigner {
    fn sign_client_assertion(
        &self,
        request: ClientAssertion<'_>,
    ) -> Result<ProtectedText, AuthError> {
        let document = str::from_utf8(request.key.as_bytes()).map_err(|_| AuthError::Credential)?;
        // `PrivateJwk::parse` is the crate's own entry point for
        // untrusted key material: it bounds the document size, rejects
        // duplicate JSON members, refuses unsupported private members,
        // and validates that the private half is present and well
        // formed. Deserializing straight into the type skips all four,
        // so a key this layer cannot actually sign with would only fail
        // later, at the signing call.
        let key = PrivateJwk::parse(document).map_err(|_| AuthError::Credential)?;
        // Parsing each half does not make the two belong together:
        // EdDSA derives the public key from the seed and never reads
        // `x`, and RSA imports the private half alone, so a document
        // pairing one pair's private half with another's public half
        // signs a valid assertion that verifies under nothing the
        // authorization server holds, because what an adopter registers
        // is the public half. Signing a probe and verifying it against
        // this key's own public half is what proves the two belong
        // together, and it costs one operation per token request
        // instead of a round trip to an authorization server that can
        // only refuse the assertion.
        //
        // The probe is deliberately not shaped like a JWS signing input,
        // so the signature discarded here could not be presented as an
        // assertion.
        let probe = registry_platform_crypto::sign(CLIENT_KEY_PROBE, &key)
            .map_err(|_| AuthError::Credential)?;
        registry_platform_crypto::verify(CLIENT_KEY_PROBE, &probe, &key.public())
            .map_err(|_| AuthError::Credential)?;
        let mut assertion = sign_client_assertion(
            &key,
            &ClientAssertionRequest {
                client_id: request.client_id,
                audience: request.audience,
                lifetime_seconds: request.lifetime_seconds,
                issued_at: request.issued_at_unix,
            },
        )
        .map_err(|_| AuthError::Credential)?;
        // The signed assertion is a credential. It leaves the platform's
        // zeroizing buffer for this layer's without an intermediate
        // copy: the buffer moves, and both wrappers erase what they are
        // left holding.
        Ok(ProtectedText::from_owned(Zeroizing::new(
            std::mem::take(&mut *assertion).into_bytes(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use registry_platform_crypto::verify;
    use serde_json::Value;

    /// The instant the assertions in this module are dated from; the
    /// caller owns the clock, so the tests date them the same way.
    const NOW: i64 = 1_785_000_000;
    const CLIENT_ID: &str = "urn:example:client:adapter";
    const TOKEN_ENDPOINT: &str = "https://tokens.example.invalid/token";
    /// The platform's default, what the token plan passes the signer.
    const LIFETIME_SECONDS: i64 = 60;

    /// One test-only signing key per key kind this seam parses, the same
    /// pinned documents the platform's own signing tests use, so this
    /// crate puts no new key material in the tree. They authenticate
    /// nothing.
    const ED25519_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.test#key-1"}"#;
    const P256_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"did:web:issuer.test#p256-key-1"}"#;
    /// The private member of the pinned Ed25519 document, what the
    /// absence assertions hunt for.
    const ED25519_PRIVATE_MEMBER: &str = "2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw";
    /// A recognizable value no deployment has ever used, carried inside
    /// key documents the signer must refuse.
    const KEY_CANARY: &str = "C4C-KEY-CANARY-7b3a1e9f5d2c4a06b8e7f1a3d5c9b2e8";

    fn sign(document: &str, audience: &str, lifetime_seconds: i64) -> Result<String, AuthError> {
        PlatformAssertionSigner
            .sign_client_assertion(ClientAssertion {
                client_id: CLIENT_ID,
                audience,
                key: &ProtectedText::from_str_value(document),
                issued_at_unix: NOW,
                lifetime_seconds,
            })
            .map(|assertion| {
                String::from_utf8(assertion.as_bytes().to_vec()).expect("the assertion is text")
            })
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

    /// What the signer produces is a client assertion the authorization
    /// server can verify: the header names the key and the algorithm the
    /// document states, the claims are the RFC 7523 section 2.2 set, and
    /// the signature verifies under the key's own public half, for every
    /// key kind this seam accepts.
    #[test]
    fn an_assertion_from_this_signer_verifies_under_its_key() {
        for document in [ED25519_JWK, P256_JWK] {
            let key = PrivateJwk::parse(document).expect("the pinned test key parses");
            let assertion =
                sign(document, TOKEN_ENDPOINT, LIFETIME_SECONDS).expect("the assertion is signed");

            let (header, claims, signature) = parts(&assertion);
            assert_eq!(
                header["alg"],
                key.alg.as_deref().expect("the key states an algorithm")
            );
            assert_eq!(header["typ"], "JWT");
            assert_eq!(
                header["kid"],
                key.kid.as_deref().expect("the key names itself")
            );
            assert_eq!(
                claims["iss"], CLIENT_ID,
                "the client names itself as issuer"
            );
            assert_eq!(
                claims["sub"], CLIENT_ID,
                "the client names itself as subject"
            );
            assert_eq!(
                claims["iat"], NOW,
                "the caller's instant dates the assertion"
            );
            assert_eq!(claims["exp"], NOW + LIFETIME_SECONDS);
            verify(
                signing_input(&assertion).as_bytes(),
                &signature,
                &key.public(),
            )
            .unwrap_or_else(|error| panic!("the assertion verifies under its key: {error}"));
        }
    }

    /// The audience is signed byte for byte as configured, never parsed
    /// back or normalized here: RFC 7523 section 3 has the authorization
    /// server compare it by Simple String Comparison, so the value the
    /// token endpoint receives is the value the operator wrote.
    #[test]
    fn the_audience_is_signed_exactly_as_configured() {
        for audience in [
            TOKEN_ENDPOINT,
            "HTTPS://tokens.example.invalid/token",
            "https://other.example.invalid/v2/oauth/token",
        ] {
            let assertion =
                sign(ED25519_JWK, audience, LIFETIME_SECONDS).expect("the assertion is signed");
            let (_, claims, _) = parts(&assertion);
            assert_eq!(claims["aud"], audience, "the audience is signed as written");
        }
    }

    /// The marker-secret rule extends to the signing key: no rendering
    /// this seam produces carries the key document or any private member
    /// of it. The assertion is a signature, not a copy, and every
    /// refusal is the fixed-text credential error with no payload to
    /// ride along.
    #[test]
    fn key_material_appears_in_no_rendering_the_seam_produces() {
        let assertion =
            sign(ED25519_JWK, TOKEN_ENDPOINT, LIFETIME_SECONDS).expect("the assertion is signed");
        assert!(
            !assertion.contains(ED25519_PRIVATE_MEMBER),
            "the assertion carries the private member"
        );
        assert!(
            !assertion.contains(ED25519_JWK),
            "the assertion carries the document"
        );

        // A document that cannot parse, with a recognizable value inside
        // it: the refusal names nothing that was in it.
        let unusable = format!(
            r#"{{"kty":"OKP","crv":"Ed25519","d":"{KEY_CANARY}","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc"}}"#
        );
        let error = sign(&unusable, TOKEN_ENDPOINT, LIFETIME_SECONDS)
            .expect_err("an unusable document refuses");
        assert_eq!(error, AuthError::Credential);
        for rendered in [
            error.to_string(),
            format!("{error:?}"),
            format!("{PlatformAssertionSigner:?}"),
        ] {
            assert!(!rendered.contains(KEY_CANARY), "{rendered}");
            assert!(!rendered.contains(ED25519_PRIVATE_MEMBER), "{rendered}");
        }
    }

    /// A document pairing one pair's private half with another's public
    /// half signs an assertion that verifies under nothing the
    /// authorization server holds, so the probe refuses it before any
    /// assertion is signed, value-free.
    #[test]
    fn a_key_whose_halves_do_not_pair_refuses() {
        let unpaired = ED25519_JWK.replacen(
            "\"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc\"",
            "\"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4\"",
            1,
        );
        let error = sign(&unpaired, TOKEN_ENDPOINT, LIFETIME_SECONDS)
            .expect_err("a key that proves nothing refuses");
        assert_eq!(error, AuthError::Credential);
        assert!(
            !error
                .to_string()
                .contains("3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4"),
            "{}",
            error
        );
    }

    /// The caller states how long the assertion is good for, and the
    /// platform's bound holds through this seam: a lifetime outside
    /// `1..=300` seconds refuses rather than signs.
    #[test]
    fn the_lifetime_the_caller_states_bounds_the_assertion() {
        let assertion = sign(ED25519_JWK, TOKEN_ENDPOINT, 120).expect("the assertion is signed");
        let (_, claims, _) = parts(&assertion);
        assert_eq!(claims["exp"], NOW + 120);

        for lifetime_seconds in [0, 301, i64::MIN, i64::MAX] {
            assert_eq!(
                sign(ED25519_JWK, TOKEN_ENDPOINT, lifetime_seconds),
                Err(AuthError::Credential),
                "lifetime {lifetime_seconds}"
            );
        }
    }
}
