// SPDX-License-Identifier: Apache-2.0
//! Presentations produced by the OpenWallet Foundation `sd-jwt` Python
//! reference (tests/vectors/generate.py), verified here. Neither the issuer nor
//! the holder side of these vectors is code from this repository.

use registry_evidence_presentation::{
    verify_sd_jwt_vc, ChannelPolicy, IssuerTrust, KeySource, PresentationRefusal, SessionContext,
    TrustEntry,
};
use registry_platform_crypto::PublicJwk;
use registry_platform_x509::{ChainPolicy, TrustAnchors};
use serde_json::Value;

struct Vector(Value);

impl Vector {
    fn load(text: &str) -> Self {
        Self(serde_json::from_str(text).expect("vector json"))
    }

    fn str(&self, name: &str) -> &str {
        self.0[name].as_str().unwrap_or_else(|| panic!("{name}"))
    }

    fn int(&self, name: &str) -> i64 {
        self.0[name].as_i64().unwrap_or_else(|| panic!("{name}"))
    }

    fn key_source(&self) -> KeySource {
        if let Some(key) = self.0.get("issuerKey") {
            return KeySource::Jwks(vec![PublicJwk::parse(&key.to_string()).expect("issuer key")]);
        }
        KeySource::X5c {
            anchors: TrustAnchors::from_pem(self.str("anchorPem").as_bytes()).expect("anchor"),
            policy: ChainPolicy::default(),
        }
    }

    fn trust(&self) -> IssuerTrust {
        IssuerTrust::new(vec![TrustEntry {
            id: "vectors".into(),
            issuer: self.str("issuer").into(),
            vct: vec![self.str("vct").into()],
            key_source: self.key_source(),
        }])
        .expect("trust")
    }

    fn ctx(&self) -> SessionContext {
        SessionContext {
            nonce: self.str("nonce").into(),
            client_id: self.str("clientId").into(),
            received_at: self.int("receivedAt"),
        }
    }

    fn policy(&self) -> ChannelPolicy {
        ChannelPolicy::new(
            vec![self.str("vct").into()],
            self.0["keyBindingRequired"].as_bool().expect("flag"),
        )
    }

    fn verify(
        &self,
    ) -> Result<registry_evidence_presentation::VerifiedCredential, PresentationRefusal> {
        verify_sd_jwt_vc(
            self.str("presentation"),
            &self.ctx(),
            &self.trust(),
            &self.policy(),
            self.int("now"),
        )
    }

    fn assert_accepted(&self, key_bound: bool) {
        let credential = self.verify().expect("reference vector verifies");
        assert_eq!(credential.issuer, self.str("issuer"));
        assert_eq!(credential.vct, self.str("vct"));
        assert_eq!(credential.issued_at, self.int("issuedAt"));
        assert_eq!(credential.expires_at, Some(self.int("expiresAt")));
        assert_eq!(credential.key_bound, key_bound);
        // Everything the holder disclosed, and nothing it withheld.
        for (name, expected) in self.0["expectedClaims"].as_object().unwrap() {
            assert_eq!(&credential.claims[name], expected, "{name}");
        }
        for name in self.0["withheldClaims"].as_array().unwrap() {
            assert!(!credential.claims.contains_key(name.as_str().unwrap()));
        }
    }
}

fn es256_vector() -> Vector {
    Vector::load(include_str!("vectors/es256-pinned-key.json"))
}

fn x5c_vector() -> Vector {
    Vector::load(include_str!("vectors/eddsa-x5c-no-key-binding.json"))
}

#[test]
fn reference_es256_presentation_with_key_binding_and_nested_disclosures_verifies() {
    es256_vector().assert_accepted(true);
}

#[test]
fn reference_eddsa_x5c_presentation_verifies() {
    x5c_vector().assert_accepted(false);
}

#[test]
fn reference_vectors_are_refused_when_the_session_does_not_match() {
    let vector = es256_vector();
    let mut ctx = vector.ctx();
    ctx.nonce = "another-session".into();
    let result = verify_sd_jwt_vc(
        vector.str("presentation"),
        &ctx,
        &vector.trust(),
        &vector.policy(),
        vector.int("now"),
    );
    assert_eq!(result.unwrap_err(), PresentationRefusal::KeyBindingInvalid);

    let mut ctx = vector.ctx();
    ctx.client_id = "verifier.example".into();
    let result = verify_sd_jwt_vc(
        vector.str("presentation"),
        &ctx,
        &vector.trust(),
        &vector.policy(),
        vector.int("now"),
    );
    assert_eq!(result.unwrap_err(), PresentationRefusal::KeyBindingInvalid);
}

#[test]
fn reference_vector_without_key_binding_is_refused_when_policy_requires_it() {
    let vector = x5c_vector();
    let mut policy = vector.policy();
    policy.key_binding_required = true;
    let result = verify_sd_jwt_vc(
        vector.str("presentation"),
        &vector.ctx(),
        &vector.trust(),
        &policy,
        vector.int("now"),
    );
    assert_eq!(result.unwrap_err(), PresentationRefusal::KeyBindingRequired);
}

#[test]
fn reference_vectors_respect_the_injected_clock() {
    let vector = es256_vector();
    let expired = vector.int("expiresAt") + 61;
    let result = verify_sd_jwt_vc(
        vector.str("presentation"),
        &vector.ctx(),
        &vector.trust(),
        &vector.policy(),
        expired,
    );
    assert_eq!(result.unwrap_err(), PresentationRefusal::CredentialExpired);
    let early = vector.int("issuedAt") - 61;
    let result = verify_sd_jwt_vc(
        vector.str("presentation"),
        &vector.ctx(),
        &vector.trust(),
        &vector.policy(),
        early,
    );
    assert_eq!(
        result.unwrap_err(),
        PresentationRefusal::CredentialNotYetValid
    );
}
