//! Test-only issuer fixtures for this crate's own verification tests.
//!
//! The Evidence runtime owns signing and depends on this crate, so a test here
//! cannot reach the runtime signer: a development dependency back onto the
//! runtime would link a second instance of this crate and its wire types would
//! not unify. These fixtures produce authentic signed inputs instead, and
//! mirror the parts of issuance that verification reads: the protected header
//! bytes, the signing input, the SD-JWT VC issuance shape, and the bound on the
//! number of published keys.
//!
//! They deliberately omit the runtime's provider-readiness and startup
//! sign-and-verify probes. A fixture signer is built in-process from a known
//! good test key, so their absence cannot weaken what these tests prove. The
//! runtime signer is verified against this crate by the runtime's own suite.

use std::{collections::BTreeSet, sync::Arc};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_crypto::{PublicJwk, SigningAlgorithm, SigningProvider};
use registry_platform_sdjwt::{SdJwtIssuanceInput, SdJwtIssuer};
use serde::Serialize;

use crate::{
    model::{FlattenedJws, JwksDocument},
    EVIDENCE_JWS_CTY, EVIDENCE_JWS_TYP,
};

/// Deterministic canonical nonce for offline fixture evaluation. Real callers
/// generate a fresh random value for every request.
pub const OFFLINE_EVALUATION_REQUEST_NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

const MAX_PUBLISHED_KEYS: usize = 33;

// Two invariants meet at this number: the fixtures mirror the runtime signer's
// published-key bound, and a fixture must never build a key set the verifier
// would refuse. Divergence has to be a deliberate decision, not a drift.
const _: () = assert!(MAX_PUBLISHED_KEYS == crate::verifier::MAX_TRUSTED_KEYS);

#[derive(Debug)]
pub enum FixtureSigningError {
    Algorithm,
    ActiveKeyId,
    Provider,
    PublishedKey,
    Serialization,
    SdJwtVc,
}

#[derive(Serialize)]
struct ProtectedHeader<'a> {
    alg: &'static str,
    kid: &'a str,
    typ: &'static str,
    cty: &'static str,
}

pub struct EvidenceSigner {
    provider: Arc<dyn SigningProvider>,
}

impl EvidenceSigner {
    pub async fn initialize(
        provider: Arc<dyn SigningProvider>,
        configured_active_key_id: &str,
    ) -> Result<Self, FixtureSigningError> {
        if provider.algorithm() != SigningAlgorithm::Es256 {
            return Err(FixtureSigningError::Algorithm);
        }
        let public = provider.public_jwk();
        if provider.key_id() != configured_active_key_id
            || public.algorithm().ok() != Some(SigningAlgorithm::Es256)
            || public.kid.as_deref() != Some(provider.key_id())
            || public.jkt().ok().as_deref() != Some(provider.key_id())
        {
            return Err(FixtureSigningError::ActiveKeyId);
        }
        Ok(Self { provider })
    }

    pub fn public_jwk(&self) -> PublicJwk {
        self.provider.public_jwk()
    }

    pub async fn sign_json<T: Serialize>(
        &self,
        evidence: &T,
    ) -> Result<FlattenedJws, FixtureSigningError> {
        let payload =
            serde_json::to_vec(evidence).map_err(|_| FixtureSigningError::Serialization)?;
        let protected = serde_json::to_vec(&ProtectedHeader {
            alg: "ES256",
            kid: self.provider.key_id(),
            typ: EVIDENCE_JWS_TYP,
            cty: EVIDENCE_JWS_CTY,
        })
        .map_err(|_| FixtureSigningError::Serialization)?;

        let protected = URL_SAFE_NO_PAD.encode(protected);
        let payload = URL_SAFE_NO_PAD.encode(payload);
        let signing_input = [protected.as_bytes(), b".", payload.as_bytes()].concat();
        let signature = self
            .provider
            .sign(&signing_input)
            .await
            .map_err(|_| FixtureSigningError::Provider)?;

        Ok(FlattenedJws {
            protected,
            payload,
            signature: URL_SAFE_NO_PAD.encode(signature),
        })
    }

    pub async fn sign_sd_jwt_vc(
        &self,
        input: SdJwtIssuanceInput,
    ) -> Result<String, FixtureSigningError> {
        SdJwtIssuer::from_signing_provider(Arc::clone(&self.provider))
            .issue(input)
            .await
            .map(|signed| signed.jwt)
            .map_err(|_| FixtureSigningError::SdJwtVc)
    }
}

/// Publish an active key and its retired predecessors as the trusted key set.
pub fn jwks_document(
    active: PublicJwk,
    retired: impl IntoIterator<Item = PublicJwk>,
) -> Result<JwksDocument, FixtureSigningError> {
    let mut seen = BTreeSet::new();
    let mut keys = Vec::new();
    for key in std::iter::once(active).chain(retired) {
        if keys.len() == MAX_PUBLISHED_KEYS {
            return Err(FixtureSigningError::PublishedKey);
        }
        if key.algorithm().ok() != Some(SigningAlgorithm::Es256) {
            return Err(FixtureSigningError::Algorithm);
        }
        let key_id = key
            .kid
            .as_deref()
            .ok_or(FixtureSigningError::PublishedKey)?;
        if key.jkt().ok().as_deref() != Some(key_id) || !seen.insert(key_id.to_owned()) {
            return Err(FixtureSigningError::PublishedKey);
        }
        keys.push(serde_json::to_value(key).map_err(|_| FixtureSigningError::Serialization)?);
    }
    Ok(JwksDocument { keys })
}

#[cfg(test)]
mod tests {
    use p256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};

    use super::*;

    fn public_jwk(index: u8) -> PublicJwk {
        let mut scalar = [0_u8; 32];
        scalar[31] = index
            .checked_add(1)
            .expect("test key index remains bounded");
        let secret = SecretKey::from_slice(&scalar).expect("test scalar is valid");
        let encoded = secret.public_key().to_encoded_point(false);
        let mut key = PublicJwk {
            kty: "EC".to_owned(),
            kid: None,
            alg: Some("ES256".to_owned()),
            crv: Some("P-256".to_owned()),
            x: Some(URL_SAFE_NO_PAD.encode(encoded.x().expect("x coordinate"))),
            y: Some(URL_SAFE_NO_PAD.encode(encoded.y().expect("y coordinate"))),
            n: None,
            e: None,
        };
        key.kid = Some(key.jkt().expect("thumbprint computes"));
        key
    }

    /// The fixture key set publishes the same maximum number of keys as the
    /// runtime, so a trusted set built here cannot exceed what a deployment can
    /// serve.
    #[test]
    fn published_key_set_stops_at_the_runtime_bound() {
        let active = public_jwk(0);
        let retired = (1..MAX_PUBLISHED_KEYS as u8).map(public_jwk);
        let boundary = jwks_document(active.clone(), retired).expect("the bound itself is allowed");
        assert_eq!(boundary.keys.len(), MAX_PUBLISHED_KEYS);

        let too_many = (1..=MAX_PUBLISHED_KEYS as u8).map(public_jwk);
        assert!(matches!(
            jwks_document(active.clone(), too_many),
            Err(FixtureSigningError::PublishedKey)
        ));
    }
}
