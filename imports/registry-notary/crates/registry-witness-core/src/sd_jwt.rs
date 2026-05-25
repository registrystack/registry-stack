// SPDX-License-Identifier: Apache-2.0
//! Minimal SD-JWT VC issuer for Registry Witness claim views.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use registry_platform_crypto::{PrivateJwk, PublicJwk};
use registry_platform_sdjwt::{Disclosure, HolderConfirmation, SdJwtIssuanceInput, SdJwtIssuer};
use serde_json::{json, Value};
use std::fmt;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::config::CredentialProfileConfig;
use crate::error::EvidenceError;
use crate::model::{ClaimResultView, SD_JWT_VC_SIGNING_ALG};

#[derive(Debug, Clone)]
pub struct SignedSdJwtVc {
    pub credential_id: String,
    pub issuer: String,
    pub expires_at: String,
    pub compact: String,
    pub issuer_signed_jwt: String,
    pub disclosures: Vec<String>,
}

#[derive(Clone)]
pub struct EvidenceIssuer {
    verification_method_id: String,
    issuer: SdJwtIssuer,
    public_jwk: Value,
}

impl fmt::Debug for EvidenceIssuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EvidenceIssuer")
            .field("verification_method_id", &self.verification_method_id)
            .field("public_jwk", &"[omitted]")
            .finish_non_exhaustive()
    }
}

impl EvidenceIssuer {
    pub fn from_profile_key(
        profile: &CredentialProfileConfig,
        raw: &str,
    ) -> Result<Self, EvidenceError> {
        let verification_method_id = profile
            .issuer_kid
            .clone()
            .unwrap_or_else(|| format!("{}#evidence-issuer", profile.issuer));
        Self::from_jwk_str(raw, verification_method_id)
    }

    pub fn from_jwk_str(raw: &str, verification_method_id: String) -> Result<Self, EvidenceError> {
        let jwk = PrivateJwk::parse(raw).map_err(|_| EvidenceError::CredentialIssuanceFailed)?;
        let mut public = jwk.public();
        public.kid = Some(verification_method_id.clone());
        public
            .alg
            .get_or_insert_with(|| SD_JWT_VC_SIGNING_ALG.to_string());
        let public_jwk =
            serde_json::to_value(public).map_err(|_| EvidenceError::CredentialIssuanceFailed)?;
        let issuer =
            SdJwtIssuer::from_jwk(jwk).map_err(|_| EvidenceError::CredentialIssuanceFailed)?;
        Ok(Self {
            verification_method_id,
            issuer,
            public_jwk,
        })
    }

    #[must_use]
    pub fn public_jwk(&self) -> Value {
        self.public_jwk.clone()
    }
}

pub fn issue(
    profile: &CredentialProfileConfig,
    issuer: &EvidenceIssuer,
    results: &[ClaimResultView],
    subject_ref: &str,
    holder_id: Option<&str>,
    iat: OffsetDateTime,
) -> Result<SignedSdJwtVc, EvidenceError> {
    let holder_confirmation = holder_id.map(holder_confirmation).transpose()?;
    if profile.holder_binding.mode != "none" && holder_confirmation.is_none() {
        return Err(EvidenceError::HolderProofRequired);
    }
    if subject_ref.trim().is_empty() {
        return Err(EvidenceError::InvalidRequest);
    }
    let expires_at = iat + time::Duration::seconds(profile.validity_seconds);
    let disclosures = results
        .iter()
        .map(|result| Disclosure {
            name: result.claim_id.clone(),
            value: json!({
                "claim_id": result.claim_id,
                "version": result.claim_version,
                "value": result.value,
                "satisfied": result.satisfied,
                "subject_type": result.subject_type,
                "issued_at": result.issued_at,
            }),
        })
        .collect();
    let signed = issuer
        .issuer
        .issue(SdJwtIssuanceInput {
            iss: profile.issuer.clone(),
            sub_ref: subject_ref.to_string(),
            iat: iat.unix_timestamp(),
            exp: expires_at.unix_timestamp(),
            vct: profile.vct.clone(),
            signing_kid: issuer.verification_method_id.clone(),
            cnf: holder_confirmation,
            disclosures,
        })
        .map_err(|_| EvidenceError::CredentialIssuanceFailed)?;
    let (issuer_signed_jwt, disclosures) = split_sd_jwt_compact(&signed.jwt)?;
    Ok(SignedSdJwtVc {
        credential_id: signed.credential_id,
        issuer: profile.issuer.clone(),
        expires_at: format_time(expires_at),
        compact: signed.jwt,
        issuer_signed_jwt,
        disclosures,
    })
}

fn split_sd_jwt_compact(compact: &str) -> Result<(String, Vec<String>), EvidenceError> {
    let mut parts = compact.split('~');
    let issuer_signed_jwt = parts
        .next()
        .filter(|jwt| !jwt.is_empty())
        .ok_or(EvidenceError::CredentialIssuanceFailed)?
        .to_string();
    let disclosures = parts
        .filter(|part| !part.is_empty())
        .map(ToString::to_string)
        .collect();
    Ok((issuer_signed_jwt, disclosures))
}

fn holder_confirmation(holder_id: &str) -> Result<HolderConfirmation, EvidenceError> {
    Ok(HolderConfirmation {
        jwk: holder_jwk(holder_id)?,
        kid: Some(holder_id.to_string()),
    })
}

pub fn holder_jwk(holder_id: &str) -> Result<PublicJwk, EvidenceError> {
    let encoded = holder_id
        .strip_prefix("did:jwk:")
        .ok_or(EvidenceError::HolderProofRequired)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| EvidenceError::HolderProofRequired)?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| EvidenceError::HolderProofRequired)?;
    PublicJwk::parse(&value.to_string()).map_err(|_| EvidenceError::HolderProofRequired)
}

fn format_time(value: OffsetDateTime) -> String {
    value
        .format(&Rfc3339)
        .expect("OffsetDateTime within supported RFC3339 range")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ClaimProvenance, FORMAT_SD_JWT_VC, SD_JWT_VC_JWT_TYP};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    const RAW_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;

    #[test]
    fn signing_algorithm_header_value_is_stable() {
        let issuer = EvidenceIssuer::from_jwk_str(RAW_JWK, "did:web:issuer.test#key-1".to_string())
            .expect("test issuer builds");
        let signed = issue(
            &test_profile(),
            &issuer,
            &[claim_result("first")],
            "subject-ref",
            None,
            OffsetDateTime::now_utc(),
        )
        .expect("credential issues");
        let compact = signed.compact.split('~').next().expect("compact jwt");
        let header = compact.split('.').next().expect("compact jwt has header");
        let header: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(header)
                .expect("header decodes as base64url"),
        )
        .expect("header decodes as JSON");
        assert_eq!(header["alg"], SD_JWT_VC_SIGNING_ALG);
        assert_eq!(header["typ"], SD_JWT_VC_JWT_TYP);
    }

    #[test]
    fn issued_credential_payload_includes_jti() {
        let issuer = EvidenceIssuer::from_jwk_str(RAW_JWK, "did:web:issuer.test#key-1".to_string())
            .expect("test issuer builds");
        let signed = issue(
            &test_profile(),
            &issuer,
            &[claim_result("first")],
            "subject-ref",
            None,
            OffsetDateTime::now_utc(),
        )
        .expect("credential issues");
        let payload = payload(&signed);

        assert_eq!(payload["jti"], signed.credential_id);
        assert_eq!(payload["id"], signed.credential_id);
    }

    #[test]
    fn golden_sd_jwt_vc_fixture_matches_conformance_profile() {
        let issuer = EvidenceIssuer::from_jwk_str(RAW_JWK, "did:web:issuer.test#key-1".to_string())
            .expect("test issuer builds");
        let holder = holder_did_jwk();
        let iat = OffsetDateTime::from_unix_timestamp(1_700_000_000)
            .expect("test fixture timestamp is valid");
        let mut result = claim_result("first");
        result.subject_ref = "registry-subject-ref".to_string();
        let signed = issue(
            &holder_required_profile(),
            &issuer,
            &[result],
            &holder,
            Some(&holder),
            iat,
        )
        .expect("credential issues");

        let header = header(&signed);
        let payload = payload(&signed);

        assert_eq!(header["alg"], SD_JWT_VC_SIGNING_ALG);
        assert_eq!(header["typ"], SD_JWT_VC_JWT_TYP);
        assert_eq!(header["kid"], "did:web:issuer.test#key-1");
        assert_eq!(payload["iss"], "did:web:issuer.test");
        assert_eq!(payload["sub"], holder);
        assert_eq!(payload["iat"], iat.unix_timestamp());
        assert_eq!(payload["exp"], iat.unix_timestamp() + 60);
        assert_eq!(payload["vct"], "https://vct.example/test");
        assert_eq!(payload["jti"], signed.credential_id);
        assert_eq!(payload["id"], signed.credential_id);
        assert_eq!(payload["cnf"]["kid"], holder);
        assert_eq!(payload["cnf"]["jwk"]["kty"], "OKP");
        assert_eq!(payload["cnf"]["jwk"]["crv"], "Ed25519");
        assert!(payload["cnf"]["jwk"].get("d").is_none());
        assert_eq!(payload_sd(&signed), disclosure_digests(&signed));
        assert_eq!(signed.disclosures.len(), 1);
        assert!(
            !payload.to_string().contains("registry-subject-ref"),
            "holder-bound payload must not expose the raw registry subject_ref",
        );
    }

    #[test]
    fn issued_credential_exposes_verifiable_jwt_separately_from_disclosures() {
        let issuer = EvidenceIssuer::from_jwk_str(RAW_JWK, "did:web:issuer.test#key-1".to_string())
            .expect("test issuer builds");
        let signed = issue(
            &test_profile(),
            &issuer,
            &[claim_result("first")],
            "subject-ref",
            None,
            OffsetDateTime::now_utc(),
        )
        .expect("credential issues");

        assert_eq!(
            signed.issuer_signed_jwt,
            signed.compact.split('~').next().expect("sd-jwt has jwt")
        );
        assert!(!signed.issuer_signed_jwt.contains('~'));
        let segments = signed.issuer_signed_jwt.split('.').collect::<Vec<_>>();
        assert_eq!(segments.len(), 3);
        for segment in segments {
            URL_SAFE_NO_PAD
                .decode(segment)
                .expect("JWT segment is base64url without SD-JWT disclosure tail");
        }
        assert_eq!(signed.disclosures.len(), 1);
        assert!(signed.compact.ends_with('~'));
    }

    #[test]
    fn issued_credential_uses_platform_holder_confirmation() {
        let issuer = EvidenceIssuer::from_jwk_str(RAW_JWK, "did:web:issuer.test#key-1".to_string())
            .expect("test issuer builds");
        let holder = holder_did_jwk();
        let signed = issue(
            &test_profile(),
            &issuer,
            &[claim_result("first")],
            &holder,
            Some(&holder),
            OffsetDateTime::now_utc(),
        )
        .expect("credential issues");
        let payload = payload(&signed);

        assert_eq!(payload["cnf"]["kid"], holder);
        assert_eq!(payload["cnf"]["jwk"]["kty"], "OKP");
        assert_eq!(payload["cnf"]["jwk"]["crv"], "Ed25519");
        assert!(payload["cnf"]["jwk"].get("d").is_none());
    }

    #[test]
    fn holder_bound_credential_uses_holder_did_as_subject() {
        let issuer = EvidenceIssuer::from_jwk_str(RAW_JWK, "did:web:issuer.test#key-1".to_string())
            .expect("test issuer builds");
        let holder = holder_did_jwk();
        let mut result = claim_result("first");
        result.subject_ref = "registry-subject-ref".to_string();

        let signed = issue(
            &test_profile(),
            &issuer,
            &[result],
            &holder,
            Some(&holder),
            OffsetDateTime::now_utc(),
        )
        .expect("credential issues");
        let payload = payload(&signed);

        assert_eq!(payload["sub"], holder);
        assert!(
            !payload.to_string().contains("registry-subject-ref"),
            "holder-bound JWT payload must not expose the raw registry subject_ref",
        );
    }

    #[test]
    fn credential_without_holder_uses_registry_subject_ref() {
        let issuer = EvidenceIssuer::from_jwk_str(RAW_JWK, "did:web:issuer.test#key-1".to_string())
            .expect("test issuer builds");
        let mut result = claim_result("first");
        result.subject_ref = "registry-subject-ref".to_string();

        let signed = issue(
            &test_profile(),
            &issuer,
            &[result],
            "registry-subject-ref",
            None,
            OffsetDateTime::now_utc(),
        )
        .expect("credential issues");
        let payload = payload(&signed);

        assert_eq!(payload["sub"], "registry-subject-ref");
    }

    #[test]
    fn holder_required_profile_rejects_missing_or_unsupported_holder_binding() {
        let issuer = EvidenceIssuer::from_jwk_str(RAW_JWK, "did:web:issuer.test#key-1".to_string())
            .expect("test issuer builds");
        let profile = holder_required_profile();
        let iat = OffsetDateTime::from_unix_timestamp(1_700_000_000)
            .expect("test fixture timestamp is valid");

        let missing_holder = issue(
            &profile,
            &issuer,
            &[claim_result("first")],
            "subject-ref",
            None,
            iat,
        )
        .expect_err("holder-bound profile requires holder proof material");
        assert!(matches!(missing_holder, EvidenceError::HolderProofRequired));

        let unsupported_holder = issue(
            &profile,
            &issuer,
            &[claim_result("first")],
            "did:key:z6Mkunsupported",
            Some("did:key:z6Mkunsupported"),
            iat,
        )
        .expect_err("only did:jwk holder identifiers are supported");
        assert!(matches!(
            unsupported_holder,
            EvidenceError::HolderProofRequired
        ));
    }

    #[test]
    fn issued_credential_iat_is_threaded_through_issue_not_recomputed() {
        // Two re-issuances of the same evaluation must produce identical JWT
        // `iat` because the caller threads `result.issued_at` through. The
        // signed JWT payload `iat` is the load-bearing assertion: prior to
        // the fix it was `OffsetDateTime::now_utc()` per call and drifted.
        let issuer = EvidenceIssuer::from_jwk_str(RAW_JWK, "did:web:issuer.test#key-1".to_string())
            .expect("test issuer builds");
        let results = vec![claim_result("first"), claim_result("second")];
        // Pin iat to a fixed instant in the past so wall-clock drift between
        // the two issue() calls cannot accidentally produce equal values.
        let pinned_iat =
            OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("valid unix timestamp");

        let signed_1 = issue(
            &test_profile(),
            &issuer,
            &results,
            "subject-ref",
            None,
            pinned_iat,
        )
        .expect("first issue");
        // Force a measurable wall-clock gap between calls.
        std::thread::sleep(std::time::Duration::from_millis(20));
        let signed_2 = issue(
            &test_profile(),
            &issuer,
            &results,
            "subject-ref",
            None,
            pinned_iat,
        )
        .expect("second issue");

        let iat_1 = payload(&signed_1)["iat"]
            .as_i64()
            .expect("iat decodes as i64");
        let iat_2 = payload(&signed_2)["iat"]
            .as_i64()
            .expect("iat decodes as i64");
        assert_eq!(
            iat_1, iat_2,
            "JWT iat must be pinned to the threaded value, not OffsetDateTime::now_utc() per call",
        );
        assert_eq!(
            iat_1,
            pinned_iat.unix_timestamp(),
            "JWT iat must equal the threaded OffsetDateTime",
        );
        // exp is derived from iat + validity, so it must also match.
        let exp_1 = payload(&signed_1)["exp"].as_i64().expect("exp decodes");
        let exp_2 = payload(&signed_2)["exp"].as_i64().expect("exp decodes");
        assert_eq!(exp_1, exp_2, "exp must be derived from the threaded iat");
    }

    #[test]
    fn evidence_issuer_debug_omits_key_material() {
        let issuer = EvidenceIssuer::from_jwk_str(RAW_JWK, "did:web:issuer.test#key-1".to_string())
            .expect("test issuer builds");
        let debug = format!("{issuer:?}");

        assert!(debug.contains("EvidenceIssuer"));
        assert!(debug.contains("did:web:issuer.test#key-1"));
        assert!(!debug.contains("2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw"));
        assert!(!debug.contains("1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc"));
        assert!(!debug.contains("encoding_key"));
    }

    #[test]
    fn issued_sd_digests_are_sorted_by_digest() {
        let issuer = EvidenceIssuer::from_jwk_str(RAW_JWK, "did:web:issuer.test#key-1".to_string())
            .expect("test issuer builds");
        let results = vec![
            claim_result("third"),
            claim_result("first"),
            claim_result("second"),
            claim_result("fourth"),
        ];
        let signed = issue(
            &test_profile(),
            &issuer,
            &results,
            "subject-ref",
            None,
            OffsetDateTime::now_utc(),
        )
        .expect("credential issues");

        let sd = payload_sd(&signed);
        let mut sorted_disclosure_digests = disclosure_digests(&signed);
        sorted_disclosure_digests.sort_unstable();

        assert_eq!(sd, sorted_disclosure_digests);
    }

    fn test_profile() -> CredentialProfileConfig {
        CredentialProfileConfig {
            format: FORMAT_SD_JWT_VC.to_string(),
            issuer: "did:web:issuer.test".to_string(),
            issuer_key_env: "REGISTRY_WITNESS_ISSUER_JWK".to_string(),
            issuer_kid: Some("did:web:issuer.test#key-1".to_string()),
            vct: "https://vct.example/test".to_string(),
            validity_seconds: 60,
            holder_binding: Default::default(),
            allowed_claims: Vec::new(),
            disclosure: Default::default(),
        }
    }

    fn holder_required_profile() -> CredentialProfileConfig {
        let mut profile = test_profile();
        profile.holder_binding.mode = "did".to_string();
        profile.holder_binding.proof_of_possession = Some("required".to_string());
        profile.holder_binding.allowed_did_methods = vec!["did:jwk".to_string()];
        profile
    }

    fn claim_result(claim_id: &str) -> ClaimResultView {
        ClaimResultView {
            evaluation_id: "eval-1".to_string(),
            claim_id: claim_id.to_string(),
            claim_version: "1.0.0".to_string(),
            subject_type: "person".to_string(),
            subject_ref: "subject-ref".to_string(),
            value: Some(json!({ "claim": claim_id })),
            satisfied: Some(true),
            disclosure: "redacted".to_string(),
            format: "json".to_string(),
            issued_at: "2026-05-23T00:00:00Z".to_string(),
            expires_at: None,
            provenance: ClaimProvenance {
                source_count: 0,
                source_versions: BTreeMap::new(),
                computed_by: "test".to_string(),
            },
        }
    }

    fn holder_did_jwk() -> String {
        let public_jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc",
        });
        let encoded =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&public_jwk).expect("holder JWK serializes"));
        format!("did:jwk:{encoded}")
    }

    fn payload_sd(signed: &SignedSdJwtVc) -> Vec<String> {
        let payload = payload(signed);
        payload["_sd"]
            .as_array()
            .expect("_sd is an array")
            .iter()
            .map(|value| value.as_str().expect("_sd digest is a string").to_string())
            .collect()
    }

    fn payload(signed: &SignedSdJwtVc) -> Value {
        let compact_jwt = signed
            .compact
            .split('~')
            .next()
            .expect("sd-jwt has compact jwt");
        let payload = compact_jwt
            .split('.')
            .nth(1)
            .expect("compact jwt has payload");
        serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(payload)
                .expect("payload decodes as base64url"),
        )
        .expect("payload decodes as JSON")
    }

    fn header(signed: &SignedSdJwtVc) -> Value {
        let compact_jwt = signed
            .compact
            .split('~')
            .next()
            .expect("sd-jwt has compact jwt");
        let header = compact_jwt
            .split('.')
            .next()
            .expect("compact jwt has header");
        serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(header)
                .expect("header decodes as base64url"),
        )
        .expect("header decodes as JSON")
    }

    fn disclosure_digests(signed: &SignedSdJwtVc) -> Vec<String> {
        signed
            .compact
            .split('~')
            .skip(1)
            .filter(|disclosure| !disclosure.is_empty())
            .map(|disclosure| URL_SAFE_NO_PAD.encode(Sha256::digest(disclosure.as_bytes())))
            .collect()
    }
}
