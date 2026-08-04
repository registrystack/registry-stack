//! Evidence-owned flattened JWS construction and key publication.

use std::{collections::BTreeSet, sync::Arc};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_crypto::{
    verify, KeyReadiness, PublicJwk, SigningAlgorithm, SigningError as ProviderSigningError,
    SigningProvider,
};
use registry_platform_sdjwt::{SdJwtError, SdJwtIssuanceInput, SdJwtIssuer};
use serde::Serialize;
use thiserror::Error;

use crate::{
    model::{FlattenedJws, JwksDocument},
    EVIDENCE_JWS_CTY, EVIDENCE_JWS_TYP,
};

const MAX_KEY_ID_BYTES: usize = 256;
const MAX_PUBLISHED_KEYS: usize = 33;

#[derive(Debug, Error)]
pub enum EvidenceSigningError {
    #[error("the configured signing algorithm is not allowed")]
    Algorithm,
    #[error("the configured signing key identifier is invalid")]
    KeyId,
    #[error("the signing key identifier does not match the configured active key")]
    ActiveKeyId,
    #[error("the signing provider is unavailable")]
    Provider(#[from] ProviderSigningError),
    #[error("the signing provider failed its startup self-test")]
    SelfTest,
    #[error("the protected header could not be serialized")]
    HeaderSerialization(#[source] serde_json::Error),
    #[error("the evidence payload could not be serialized")]
    PayloadSerialization(#[source] serde_json::Error),
    #[error("the published key set contains an invalid or duplicate key identifier")]
    PublishedKey,
    #[error("the published key set could not be serialized")]
    KeySerialization(#[source] serde_json::Error),
    #[error("the SD-JWT VC serialization could not be produced")]
    SdJwtVc(#[source] SdJwtError),
}

#[derive(Debug, Serialize)]
struct ProtectedHeader<'a> {
    alg: &'static str,
    kid: &'a str,
    typ: &'static str,
    cty: &'static str,
}

/// Evidence's single active Ed25519 signer.
pub struct EvidenceSigner {
    provider: Arc<dyn SigningProvider>,
}

impl std::fmt::Debug for EvidenceSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvidenceSigner")
            .field("algorithm", &self.provider.algorithm())
            .field("key_id", &self.provider.key_id())
            .finish_non_exhaustive()
    }
}

impl EvidenceSigner {
    pub async fn initialize(
        provider: Arc<dyn SigningProvider>,
        configured_active_key_id: &str,
    ) -> Result<Self, EvidenceSigningError> {
        validate_provider(provider.as_ref(), configured_active_key_id)?;

        let self_test_message = b"registry-evidence-signing-readiness-v1";
        let signature = provider.sign(self_test_message).await?;
        verify(self_test_message, &signature, &provider.public_jwk())
            .map_err(|_| EvidenceSigningError::SelfTest)?;

        Ok(Self { provider })
    }

    pub fn key_id(&self) -> &str {
        self.provider.key_id()
    }

    pub fn public_jwk(&self) -> PublicJwk {
        self.provider.public_jwk()
    }

    /// Report the current signing-provider posture without exposing key data.
    pub fn ready(&self) -> bool {
        self.provider.readiness() == KeyReadiness::Ready
    }

    /// Serialize and sign the exact JSON representation of a validated Evidence value.
    pub async fn sign_json<T: Serialize>(
        &self,
        evidence: &T,
    ) -> Result<FlattenedJws, EvidenceSigningError> {
        let payload =
            serde_json::to_vec(evidence).map_err(EvidenceSigningError::PayloadSerialization)?;
        self.sign_bytes(&payload).await
    }

    /// Sign exact UTF-8 Evidence JSON bytes as a flattened JWS JSON value.
    pub async fn sign_bytes(
        &self,
        evidence_json: &[u8],
    ) -> Result<FlattenedJws, EvidenceSigningError> {
        let protected = serde_json::to_vec(&ProtectedHeader {
            alg: "EdDSA",
            kid: self.provider.key_id(),
            typ: EVIDENCE_JWS_TYP,
            cty: EVIDENCE_JWS_CTY,
        })
        .map_err(EvidenceSigningError::HeaderSerialization)?;

        let protected = URL_SAFE_NO_PAD.encode(protected);
        let payload = URL_SAFE_NO_PAD.encode(evidence_json);
        let signing_input = [protected.as_bytes(), b".", payload.as_bytes()].concat();
        let signature = self.provider.sign(&signing_input).await?;

        Ok(FlattenedJws {
            protected,
            payload,
            signature: URL_SAFE_NO_PAD.encode(signature),
        })
    }

    /// Serialize the same assertion as a compact SD-JWT VC. The signer is the
    /// one active key already used for the flattened JWS; the profile adds no
    /// second key, algorithm, or key ceremony.
    pub async fn sign_sd_jwt_vc(
        &self,
        input: SdJwtIssuanceInput,
    ) -> Result<String, EvidenceSigningError> {
        SdJwtIssuer::from_signing_provider(Arc::clone(&self.provider))
            .issue(input)
            .await
            .map(|signed| signed.jwt)
            .map_err(EvidenceSigningError::SdJwtVc)
    }
}

pub fn jwks_document(
    active: PublicJwk,
    retired: impl IntoIterator<Item = PublicJwk>,
) -> Result<JwksDocument, EvidenceSigningError> {
    let mut seen = BTreeSet::new();
    let mut keys = Vec::new();
    for key in std::iter::once(active).chain(retired) {
        if keys.len() == MAX_PUBLISHED_KEYS {
            return Err(EvidenceSigningError::PublishedKey);
        }
        if key.algorithm().ok() != Some(SigningAlgorithm::EdDsa) {
            return Err(EvidenceSigningError::Algorithm);
        }
        let key_id = key
            .kid
            .as_deref()
            .ok_or(EvidenceSigningError::PublishedKey)?;
        validate_key_id(key_id)?;
        if !seen.insert(key_id.to_owned()) {
            return Err(EvidenceSigningError::PublishedKey);
        }
        keys.push(serde_json::to_value(key).map_err(EvidenceSigningError::KeySerialization)?);
    }
    Ok(JwksDocument { keys })
}

fn validate_provider(
    provider: &dyn SigningProvider,
    configured_active_key_id: &str,
) -> Result<(), EvidenceSigningError> {
    if provider.algorithm() != SigningAlgorithm::EdDsa {
        return Err(EvidenceSigningError::Algorithm);
    }
    validate_key_id(provider.key_id())?;
    if provider.key_id() != configured_active_key_id {
        return Err(EvidenceSigningError::ActiveKeyId);
    }
    let public = provider.public_jwk();
    if public.algorithm().ok() != Some(SigningAlgorithm::EdDsa)
        || public.kid.as_deref() != Some(provider.key_id())
    {
        return Err(EvidenceSigningError::Algorithm);
    }
    Ok(())
}

fn validate_key_id(key_id: &str) -> Result<(), EvidenceSigningError> {
    if key_id.is_empty() || key_id.len() > MAX_KEY_ID_BYTES || key_id.chars().any(char::is_control)
    {
        return Err(EvidenceSigningError::KeyId);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_crypto::{LocalJwkSigner, PrivateJwk};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    const PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"evidence-key-1"}"#;
    const FIXTURE_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"fixture-key-2026-01"}"#;
    const SAME_KID_DIFFERENT_PRIVATE_JWK: &str = r#"{"crv":"Ed25519","d":"f4QIxnAyRWzhuBOmNRgvBTE56mWePdsPL0mvCtl8Gys","x":"pv4e_hXHBLN27rcs6VDFV1ED0TiU8M3xy9vsuWFEsec","kty":"OKP","alg":"EdDSA","kid":"evidence-key-1"}"#;

    async fn signer() -> EvidenceSigner {
        let private = PrivateJwk::parse(PRIVATE_JWK).expect("test key parses");
        let provider: Arc<dyn SigningProvider> =
            Arc::new(LocalJwkSigner::new(private).expect("test signer builds"));
        EvidenceSigner::initialize(provider, "evidence-key-1")
            .await
            .expect("signer initializes")
    }

    async fn fixture_signer() -> EvidenceSigner {
        let private = PrivateJwk::parse(FIXTURE_PRIVATE_JWK).expect("test key parses");
        let provider: Arc<dyn SigningProvider> =
            Arc::new(LocalJwkSigner::new(private).expect("test signer builds"));
        EvidenceSigner::initialize(provider, "fixture-key-2026-01")
            .await
            .expect("signer initializes")
    }

    #[tokio::test]
    async fn flattened_jws_has_exact_protected_header_and_valid_signature() {
        let signer = signer().await;
        let evidence = serde_json::json!({"schema": crate::EVIDENCE_SCHEMA_V1});
        let jws = signer.sign_json(&evidence).await.expect("evidence signs");

        let protected_bytes = URL_SAFE_NO_PAD
            .decode(&jws.protected)
            .expect("protected header decodes");
        let protected: serde_json::Value =
            serde_json::from_slice(&protected_bytes).expect("protected header parses");
        assert_eq!(
            protected,
            serde_json::json!({
                "alg": "EdDSA",
                "kid": "evidence-key-1",
                "typ": "evidence+jws",
                "cty": "application/evidence+json"
            })
        );

        let signing_input = format!("{}.{}", jws.protected, jws.payload);
        let signature = URL_SAFE_NO_PAD
            .decode(&jws.signature)
            .expect("signature decodes");
        verify(signing_input.as_bytes(), &signature, &signer.public_jwk())
            .expect("signature verifies");
    }

    #[tokio::test]
    async fn configured_key_id_must_match_provider() {
        let private = PrivateJwk::parse(PRIVATE_JWK).expect("test key parses");
        let provider: Arc<dyn SigningProvider> =
            Arc::new(LocalJwkSigner::new(private).expect("test signer builds"));
        let error = EvidenceSigner::initialize(provider, "different-key")
            .await
            .expect_err("mismatched key id is rejected");
        assert!(matches!(error, EvidenceSigningError::ActiveKeyId));
    }

    #[tokio::test]
    async fn jwks_contains_public_material_only() {
        let signer = signer().await;
        let document = jwks_document(signer.public_jwk(), []).expect("JWKS builds");
        let json = serde_json::to_value(document).expect("JWKS serializes");
        assert_eq!(json["keys"].as_array().map(Vec::len), Some(1));
        assert!(json["keys"][0].get("d").is_none());

        let duplicate_private =
            PrivateJwk::parse(SAME_KID_DIFFERENT_PRIVATE_JWK).expect("rotated test key parses");
        let duplicate = LocalJwkSigner::new(duplicate_private)
            .expect("rotated signer builds")
            .public_jwk();
        assert!(matches!(
            jwks_document(signer.public_jwk(), [duplicate]),
            Err(EvidenceSigningError::PublishedKey)
        ));

        let retired = (0..32).map(|index| {
            let mut key = signer.public_jwk();
            key.kid = Some(format!("retired-evidence-key-{index:02}"));
            key
        });
        let boundary = jwks_document(signer.public_jwk(), retired).expect("33 keys are allowed");
        assert_eq!(boundary.keys.len(), 33);

        let too_many = (0..33).map(|index| {
            let mut key = signer.public_jwk();
            key.kid = Some(format!("excess-evidence-key-{index:02}"));
            key
        });
        assert!(matches!(
            jwks_document(signer.public_jwk(), too_many),
            Err(EvidenceSigningError::PublishedKey)
        ));
    }

    /// The SD-JWT VC fixture is the adopter-facing wire contract, so it must be
    /// reproduced by the production issuance path over every golden payload:
    /// the exact protected header, one root disclosure per unprojected golden
    /// value, sorted unique digests over the encoded disclosure bytes, and a
    /// trailing tilde. Structured field projection has a focused verifier test.
    #[tokio::test]
    async fn sd_jwt_vc_fixture_serialization_and_protected_header_are_exact() {
        let fixture: serde_json::Value = serde_norway::from_slice(include_bytes!(
            "../../../products/evidence/fixtures/conformance/sd-jwt-vc-cases.yaml"
        ))
        .expect("SD-JWT VC fixture parses");
        assert_eq!(
            fixture["media_type"].as_str(),
            Some(crate::EVIDENCE_SD_JWT_VC_MEDIA_TYPE)
        );
        let expected_header = fixture["protected_header"]["exact_json"]
            .as_str()
            .expect("fixture header is text");
        let signer = fixture_signer().await;

        for case in fixture["cases"]
            .as_array()
            .expect("fixture cases are an array")
        {
            let relative = case["payload"].as_str().expect("payload path is text");
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../products/evidence/fixtures/conformance")
                .join(relative);
            let evidence: crate::model::Evidence =
                serde_json::from_slice(&std::fs::read(path).expect("golden payload reads"))
                    .expect("golden payload is an Evidence document");
            let input = crate::sdjwt_vc::issuance_input(&evidence, None, &BTreeMap::new())
                .expect("golden payload maps");
            let serialized = signer
                .sign_sd_jwt_vc(input)
                .await
                .expect("golden payload serializes");

            let body = serialized
                .strip_suffix('~')
                .expect("the serialization ends with the key-binding terminator");
            let mut segments = body.split('~');
            let jwt = segments.next().expect("issuer-signed JWT segment");
            let disclosures = segments.collect::<Vec<_>>();
            assert_eq!(
                disclosures.len(),
                evidence.supported_values.len(),
                "{} discloses one root value per unprojected supported value",
                case["id"]
            );

            let parts = jwt.split('.').collect::<Vec<_>>();
            assert_eq!(parts.len(), 3, "the JWT is compact JWS serialized");
            assert_eq!(
                URL_SAFE_NO_PAD.decode(parts[0]).expect("header decodes"),
                expected_header.as_bytes()
            );
            let claims: serde_json::Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).expect("payload decodes"))
                    .expect("payload parses");
            assert_eq!(claims["_sd_alg"], serde_json::json!("sha-256"));

            let digests = claims["_sd"]
                .as_array()
                .expect("_sd is an array")
                .iter()
                .map(|value| value.as_str().expect("digest is text").to_owned())
                .collect::<Vec<_>>();
            let mut sorted = digests.clone();
            sorted.sort();
            sorted.dedup();
            assert_eq!(digests, sorted, "_sd is sorted and carries no repeat");
            for disclosure in &disclosures {
                let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(disclosure.as_bytes()));
                assert!(
                    digests.contains(&digest),
                    "a disclosure is absent from _sd in {}",
                    case["id"]
                );
            }

            let signature = URL_SAFE_NO_PAD.decode(parts[2]).expect("signature decodes");
            verify(
                format!("{}.{}", parts[0], parts[1]).as_bytes(),
                &signature,
                &signer.public_jwk(),
            )
            .expect("fixture signature verifies");
        }
    }

    #[tokio::test]
    async fn jws_fixture_payload_bytes_and_protected_header_are_exact() {
        let fixture: serde_json::Value = serde_norway::from_slice(include_bytes!(
            "../../../products/evidence/fixtures/conformance/jws-cases.yaml"
        ))
        .expect("JWS fixture parses");
        let expected_header = fixture["protected_header"]["exact_json"]
            .as_str()
            .expect("fixture header is text");
        let signer = fixture_signer().await;
        for case in fixture["cases"]
            .as_array()
            .expect("fixture cases are an array")
        {
            let relative = case["payload"].as_str().expect("payload path is text");
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../products/evidence/fixtures/conformance")
                .join(relative);
            let payload = std::fs::read(path).expect("golden payload reads");
            assert_eq!(payload.last(), Some(&b'\n'));
            let jws = signer.sign_bytes(&payload).await.expect("payload signs");
            assert_eq!(
                URL_SAFE_NO_PAD
                    .decode(&jws.protected)
                    .expect("header decodes"),
                expected_header.as_bytes()
            );
            assert_eq!(
                URL_SAFE_NO_PAD
                    .decode(&jws.payload)
                    .expect("payload decodes"),
                payload
            );
            let signing_input = format!("{}.{}", jws.protected, jws.payload);
            let signature = URL_SAFE_NO_PAD
                .decode(&jws.signature)
                .expect("signature decodes");
            verify(signing_input.as_bytes(), &signature, &signer.public_jwk())
                .expect("fixture signature verifies");
        }
    }
}
