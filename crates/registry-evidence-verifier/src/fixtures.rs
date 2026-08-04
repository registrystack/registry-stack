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
//! They deliberately omit the runtime's issuer-side configuration guards: key
//! identifier validation, the check that the published key repeats the
//! provider's algorithm and key identifier, and the startup sign-and-verify
//! self-test. Each of those refuses a misconfigured deployment before it signs
//! anything, and a fixture signer is built in-process from a known good test
//! key, so their absence cannot weaken what these tests prove. The runtime
//! signer is verified against this crate by the runtime's own suite.

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
        if provider.algorithm() != SigningAlgorithm::EdDsa {
            return Err(FixtureSigningError::Algorithm);
        }
        if provider.key_id() != configured_active_key_id {
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
            alg: "EdDSA",
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
        if key.algorithm().ok() != Some(SigningAlgorithm::EdDsa) {
            return Err(FixtureSigningError::Algorithm);
        }
        let key_id = key
            .kid
            .as_deref()
            .ok_or(FixtureSigningError::PublishedKey)?;
        if !seen.insert(key_id.to_owned()) {
            return Err(FixtureSigningError::PublishedKey);
        }
        keys.push(serde_json::to_value(key).map_err(|_| FixtureSigningError::Serialization)?);
    }
    Ok(JwksDocument { keys })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLIC_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"evidence-key-1"}"#;

    /// The fixture key set publishes the same maximum number of keys as the
    /// runtime, so a trusted set built here cannot exceed what a deployment can
    /// serve.
    #[test]
    fn published_key_set_stops_at_the_runtime_bound() {
        let active: PublicJwk = serde_json::from_str(PUBLIC_JWK).expect("test key parses");

        let retired = (0..MAX_PUBLISHED_KEYS - 1).map(|index| {
            let mut key = active.clone();
            key.kid = Some(format!("retired-evidence-key-{index:02}"));
            key
        });
        let boundary = jwks_document(active.clone(), retired).expect("the bound itself is allowed");
        assert_eq!(boundary.keys.len(), MAX_PUBLISHED_KEYS);

        let too_many = (0..MAX_PUBLISHED_KEYS).map(|index| {
            let mut key = active.clone();
            key.kid = Some(format!("excess-evidence-key-{index:02}"));
            key
        });
        assert!(matches!(
            jwks_document(active.clone(), too_many),
            Err(FixtureSigningError::PublishedKey)
        ));
    }
}
