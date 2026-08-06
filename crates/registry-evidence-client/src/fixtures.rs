//! Test-only issuer fixtures for this crate's own verification tests.
//!
//! The verifier crate has fixtures of its own, but they are private to it, so
//! this module signs its own inputs. It mirrors only what verification reads:
//! the protected header bytes, the signing input, and a payload that satisfies
//! the published Version 1 contract.
//!
//! What it deliberately omits: the runtime's issuer-side configuration guards
//! (key identifier validation, the check that the published key repeats the
//! provider's algorithm and identifier, and the startup sign-and-verify
//! self-test), and the published-key bound the verifier enforces. That bound is
//! private to the verifier, so a fixture here cannot assert against it; instead
//! each fixture publishes exactly one key, which is far below any bound either
//! side could impose. The runtime signer is proven against the verifier by the
//! runtime's own suite, and this crate's integration suite drives that runtime.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};
use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
use registry_evidence_verifier::{
    model::JwksDocument, EVIDENCE_JWS_CTY, EVIDENCE_JWS_TYP, EVIDENCE_SCHEMA_V1,
};
use registry_platform_crypto::{sign, PrivateJwk};
use serde_json::{json, Value};

/// Vocabulary the fixtures assert about. It is deliberately abstract: this
/// crate carries no source product and no requirement domain.
pub(crate) const REQUIREMENT: &str = "urn:example:client:requirement:status:v1";
pub(crate) const EVIDENCE_TYPE: &str = "urn:example:client:evidence-type:status:v1";
pub(crate) const ISSUED_BY: &str = "urn:example:client:issuer";
pub(crate) const PROVIDED_BY: &str = "urn:example:client:provider";
pub(crate) const AUDIENCE: &str = "urn:example:client:audience:relying-party";
pub(crate) const PURPOSE: &str = "example-decision";
pub(crate) const CONCEPT: &str = "urn:example:client:concept:status-holds";
pub(crate) const CONFIGURATION_REVISION: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
/// A binding as the runtime publishes it: the versioned prefix followed by the
/// unpadded base64url encoding of 32 bytes.
pub(crate) const SUBJECT_BINDING: &str =
    "urn:evidence:subject:v1_QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU";
/// The instant every fixture assertion is centered on.
pub(crate) const FIXTURE_INSTANT: &str = "2026-08-05T12:00:00Z";
/// Longest lifetime the fixture assertions stay within.
pub(crate) const MAXIMUM_LIFETIME_SECONDS: u64 = 300;

/// One issuer with one published key, and the assertions it will sign.
pub(crate) struct SignedEvidenceFixture {
    signing_key: PrivateJwk,
    key_id: String,
    pub(crate) trusted_jwks: JwksDocument,
    pub(crate) subject_binding: String,
    pub(crate) now: DateTime<Utc>,
}

/// A fresh issuer. Two fixtures never share a key or a key identifier, so a
/// response from one is a response signed by a key the other never pinned.
pub(crate) fn signed_evidence() -> SignedEvidenceFixture {
    let signing_key = SigningKey::random(&mut OsRng);
    let public = signing_key.verifying_key().to_encoded_point(false);
    let mut signing_key = PrivateJwk {
        kty: "EC".to_owned(),
        kid: None,
        alg: Some("ES256".to_owned()),
        crv: Some("P-256".to_owned()),
        d: Some(URL_SAFE_NO_PAD.encode(signing_key.to_bytes())),
        x: public.x().map(|value| URL_SAFE_NO_PAD.encode(value)),
        y: public.y().map(|value| URL_SAFE_NO_PAD.encode(value)),
        n: None,
        e: None,
        p: None,
        q: None,
        dp: None,
        dq: None,
        qi: None,
    };
    let key_id = signing_key.public().jkt().expect("the thumbprint computes");
    signing_key.kid = Some(key_id.clone());
    let trusted_jwks = JwksDocument {
        keys: vec![
            serde_json::to_value(signing_key.public()).expect("the published key serializes")
        ],
    };

    SignedEvidenceFixture {
        signing_key,
        key_id,
        trusted_jwks,
        subject_binding: SUBJECT_BINDING.to_owned(),
        now: FIXTURE_INSTANT
            .parse::<DateTime<Utc>>()
            .expect("the fixture instant parses"),
    }
}

impl SignedEvidenceFixture {
    /// A signed assertion answering the request that carried this nonce.
    pub(crate) fn sign(&self, request_nonce: &str) -> Vec<u8> {
        self.sign_payload(&self.payload(request_nonce, PURPOSE))
    }

    /// A signed assertion whose stated purpose is not the one the relying party
    /// asked for.
    pub(crate) fn sign_with_purpose(&self, request_nonce: &str, purpose: &str) -> Vec<u8> {
        self.sign_payload(&self.payload(request_nonce, purpose))
    }

    /// A signed assertion about a different subject, with everything else the
    /// same.
    pub(crate) fn sign_with_subject_binding(&self, request_nonce: &str, binding: &str) -> Vec<u8> {
        self.sign_with_subjects(
            request_nonce,
            json!([{"role": "subject", "binding": binding}]),
        )
    }

    /// A signed assertion carrying an arbitrary subject set, so a test can state
    /// a role the request never asked for.
    pub(crate) fn sign_with_subjects(&self, request_nonce: &str, subjects: Value) -> Vec<u8> {
        let mut payload = self.payload(request_nonce, PURPOSE);
        payload["subjects"] = subjects;
        self.sign_payload(&payload)
    }

    fn payload(&self, request_nonce: &str, purpose: &str) -> Value {
        let issued_at = self.now;
        let observed_at = issued_at - TimeDelta::try_seconds(60).expect("the offset is valid");
        let lifetime = i64::try_from(MAXIMUM_LIFETIME_SECONDS).expect("the lifetime fits");
        let valid_until =
            issued_at + TimeDelta::try_seconds(lifetime).expect("the offset is valid");
        json!({
            "schema": EVIDENCE_SCHEMA_V1,
            "assuranceProfile": "local",
            "requestNonce": request_nonce,
            "id": "urn:example:client:evidence:00000000-0000-4000-8000-000000000001",
            "type": "Evidence",
            "supportsRequirement": REQUIREMENT,
            "isConformantTo": EVIDENCE_TYPE,
            "issuedBy": ISSUED_BY,
            "providedBy": PROVIDED_BY,
            "issuedAt": rfc3339(issued_at),
            "observedAt": rfc3339(observed_at),
            "validUntil": rfc3339(valid_until),
            "purpose": purpose,
            "audience": AUDIENCE,
            "configurationRevision": CONFIGURATION_REVISION,
            "subjects": [{"role": "subject", "binding": self.subject_binding}],
            "supportedValues": [{"providesValueFor": CONCEPT, "value": true}],
        })
    }

    /// The flattened JWS serialization, as the response body carries it.
    fn sign_payload(&self, payload: &Value) -> Vec<u8> {
        let protected = URL_SAFE_NO_PAD.encode(
            json!({
                "alg": "ES256",
                "kid": self.key_id,
                "typ": EVIDENCE_JWS_TYP,
                "cty": EVIDENCE_JWS_CTY,
            })
            .to_string(),
        );
        let payload = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(payload).expect("the fixture payload serializes"));
        let signing_input = [protected.as_bytes(), b".", payload.as_bytes()].concat();
        let signature = sign(&signing_input, &self.signing_key).expect("the fixture key signs");
        serde_json::to_vec(&json!({
            "protected": protected,
            "payload": payload,
            "signature": URL_SAFE_NO_PAD.encode(signature),
        }))
        .expect("the flattened JWS serializes")
    }
}

fn rfc3339(instant: DateTime<Utc>) -> String {
    instant.to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_evidence_verifier::contracts::evidence_contract_accepts;

    /// The fixture payload is the shape the published contract accepts, so a
    /// test that fails does so for the reason it names and not because the
    /// fixture was malformed.
    #[test]
    fn the_fixture_payload_satisfies_the_published_contract() {
        let fixture = signed_evidence();
        let payload = fixture.payload("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", PURPOSE);
        assert!(
            evidence_contract_accepts(&payload).expect("the contract validator initializes"),
            "{payload}"
        );
    }

    #[test]
    fn two_fixtures_publish_different_keys() {
        let first = signed_evidence();
        let second = signed_evidence();
        assert_ne!(first.key_id, second.key_id);
        assert_ne!(first.trusted_jwks, second.trusted_jwks);
    }
}
