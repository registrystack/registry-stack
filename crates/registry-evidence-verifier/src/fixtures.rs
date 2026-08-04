//! Test-only issuer fixtures for this crate's own verification tests.
//!
//! The Evidence runtime owns signing and depends on this crate, so a test here
//! cannot reach the runtime signer: a development dependency back onto the
//! runtime would link a second instance of this crate and its wire types would
//! not unify. These fixtures produce authentic signed inputs from the same
//! protected header, key set, and SD-JWT VC issuance rules instead. The runtime
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
