// SPDX-License-Identifier: Apache-2.0
//! OID4VCI proof precheck, nonce, and holder-binding validation.

use super::super::*;

pub(in crate::api) fn oid4vci_single_proof_jwt(
    request: &Oid4vciCredentialRequest,
) -> Result<&str, Oid4vciWireError> {
    match request.proof_jwts() {
        [proof] if !proof.is_empty() => {
            if request.proofs.jwt.is_empty() && request.proof.proof_type != PROOF_TYPE_JWT {
                return Err(Oid4vciWireError::InvalidProof);
            }
            Ok(proof.as_str())
        }
        _ => Err(Oid4vciWireError::InvalidProof),
    }
}

pub async fn oid4vci_proof_precheck_middleware(
    State(state): State<Arc<RegistryNotaryApiState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if !oid4vci_proof_precheck_applies(request.uri().path()) {
        return next.run(request).await;
    }
    if !state.oid4vci.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let (parts, body) = request.into_parts();
    let bytes = match to_bytes(body, 64 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => return oid4vci_error_response(Oid4vciWireError::InvalidRequest),
    };
    let request = match serde_json::from_slice::<Oid4vciCredentialRequest>(&bytes) {
        Ok(request) => request,
        Err(_) => return oid4vci_error_response(Oid4vciWireError::InvalidRequest),
    };
    let proof_jwt = match oid4vci_single_proof_jwt(&request) {
        Ok(proof_jwt) => proof_jwt,
        Err(error) => return oid4vci_error_response(error),
    };
    let expected_nonce = if state.oid4vci.nonce.enabled {
        match oid4vci_proof_nonce(proof_jwt) {
            Ok(nonce) => Some(nonce),
            Err(error) => return oid4vci_error_response(error),
        }
    } else {
        None
    };
    let validated_proof = match validate_proof_jwt(
        proof_jwt,
        &ProofValidationPolicy::credential_endpoint(
            &state.oid4vci.credential_issuer,
            expected_nonce.as_deref(),
            Duration::from_secs(state.oid4vci.proof.max_age_seconds),
            Duration::from_secs(state.oid4vci.proof.max_clock_skew_seconds),
        ),
        OffsetDateTime::now_utc().unix_timestamp(),
    ) {
        Ok(proof) => proof,
        Err(_) => return oid4vci_error_response(Oid4vciWireError::InvalidProof),
    };
    if require_oid4vci_did_jwk_proof(&validated_proof).is_err() {
        return oid4vci_error_response(Oid4vciWireError::InvalidProof);
    }
    let mut request = Request::from_parts(parts, Body::from(bytes));
    request.extensions_mut().insert(validated_proof);
    next.run(request).await
}

pub(in crate::api) fn require_oid4vci_did_jwk_proof(
    proof: &ValidatedProof,
) -> Result<(), Oid4vciWireError> {
    if proof
        .kid
        .as_deref()
        .is_some_and(|kid| kid.starts_with("did:jwk:"))
        && proof.holder_id.starts_with("did:jwk:")
    {
        Ok(())
    } else {
        Err(Oid4vciWireError::InvalidProof)
    }
}
pub(in crate::api) fn oid4vci_proof_nonce(proof_jwt: &str) -> Result<String, Oid4vciWireError> {
    #[derive(Deserialize)]
    struct NonceClaims {
        nonce: Option<String>,
    }

    let mut parts = proof_jwt.split('.');
    let Some(_) = parts.next() else {
        return Err(Oid4vciWireError::InvalidProof);
    };
    let Some(payload_b64) = parts.next() else {
        return Err(Oid4vciWireError::InvalidProof);
    };
    let Some(_) = parts.next() else {
        return Err(Oid4vciWireError::InvalidProof);
    };
    if parts.next().is_some() {
        return Err(Oid4vciWireError::InvalidProof);
    }
    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| Oid4vciWireError::InvalidProof)?;
    let claims: NonceClaims =
        serde_json::from_slice(&payload).map_err(|_| Oid4vciWireError::InvalidProof)?;
    claims
        .nonce
        .filter(|nonce| !nonce.is_empty())
        .ok_or(Oid4vciWireError::InvalidProof)
}
pub(in crate::api) fn holder_key_matches_issuer_key(
    holder_jwk: &PublicJwk,
    issuer_jwk: &Value,
) -> bool {
    let Ok(issuer) = PublicJwk::parse(&issuer_jwk.to_string()) else {
        return false;
    };
    let Ok(issuer_jkt) = issuer.jkt() else {
        return false;
    };
    let Ok(holder_jkt) = holder_jwk.jkt() else {
        return false;
    };
    issuer_jkt == holder_jkt
}
pub(in crate::api) fn generate_nonce() -> Result<String, EvidenceError> {
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| EvidenceError::CredentialIssuanceFailed)?;
    Ok(URL_SAFE_NO_PAD.encode(nonce))
}

#[cfg(test)]
mod oid4vci_proof_tests {
    use super::*;

    fn proof(kid: Option<&str>) -> ValidatedProof {
        ValidatedProof {
            holder_jwk: PublicJwk::parse(
                r#"{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#,
            )
            .expect("public JWK parses"),
            holder_id: "did:jwk:eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IjFhal9yTEpzR0Zndy01djkyNUVNbWVaalBKcDQ0eGVnYWZFS2ZaYmR4YyJ9".to_string(),
            kid: kid.map(str::to_string),
            nonce: Some("nonce".to_string()),
            iat: 1,
            exp: Some(2),
            raw_claims: json!({}),
        }
    }

    #[test]
    fn oid4vci_holder_proof_requires_explicit_did_jwk_key_reference() {
        let did = proof(None).holder_id;
        assert!(require_oid4vci_did_jwk_proof(&proof(Some(&did))).is_ok());
        assert_eq!(
            require_oid4vci_did_jwk_proof(&proof(None)),
            Err(Oid4vciWireError::InvalidProof)
        );
    }
}

#[derive(Debug)]
pub(in crate::api) struct HolderProofBinding {
    pub(in crate::api) scope: ReplayScope,
    pub(in crate::api) key: ReplayKey,
    pub(in crate::api) expires_at: OffsetDateTime,
}

pub(in crate::api) fn validate_holder_request(
    profile: &CredentialProfileConfig,
    profile_id: &str,
    request: &CredentialIssueRequest,
    evaluation: &registry_notary_core::StoredEvaluation,
    holder: Option<&HolderRequest>,
    service_id: &str,
) -> Result<Option<HolderProofBinding>, EvidenceError> {
    if profile.holder_binding.mode == "none" {
        return Ok(None);
    }
    let Some(holder) = holder else {
        return Err(EvidenceError::HolderProofRequired);
    };
    if holder.binding.as_deref() != Some(profile.holder_binding.mode.as_str()) {
        return Err(EvidenceError::HolderProofRequired);
    }
    let holder_id = holder
        .id
        .as_deref()
        .ok_or(EvidenceError::HolderProofRequired)?;
    if profile.holder_binding.mode == "did"
        && !profile
            .holder_binding
            .allowed_did_methods
            .iter()
            .any(|method| holder_id.starts_with(&format!("{method}:")))
    {
        return Err(EvidenceError::HolderProofRequired);
    }
    if profile.holder_binding.proof_of_possession.as_deref() == Some("required") {
        let proof = holder
            .proof
            .as_deref()
            .ok_or(EvidenceError::HolderProofRequired)?;
        return validate_holder_proof_payload(
            proof, holder_id, profile_id, request, evaluation, service_id,
        )
        .map(Some);
    }
    Ok(None)
}

pub(in crate::api) fn validate_holder_proof_payload(
    proof: &str,
    holder_id: &str,
    profile_id: &str,
    request: &CredentialIssueRequest,
    evaluation: &registry_notary_core::StoredEvaluation,
    service_id: &str,
) -> Result<HolderProofBinding, EvidenceError> {
    let jwk = sd_jwt::holder_jwk(holder_id)?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let disclosure = request
        .disclosure
        .as_deref()
        .unwrap_or(evaluation.disclosure.as_str());
    let disclosure_hash = Sha256::digest(disclosure.as_bytes()).to_vec();
    let claims = validate_holder_proof(
        proof,
        &jwk,
        &HolderProofBindings {
            expected_sub: holder_id,
            evaluation_id: request.evaluation_id.as_str(),
            credential_profile: profile_id,
            disclosure_hash: &disclosure_hash,
            claim_set: &evaluation.claim_ids,
        },
        &HolderProofPolicy {
            audience: service_id.to_string(),
            max_lifetime: Duration::from_secs(300),
        },
        now,
    )
    .map_err(|_| EvidenceError::HolderProofRequired)?;
    let expires_at = OffsetDateTime::from_unix_timestamp(claims.exp)
        .map_err(|_| EvidenceError::HolderProofRequired)?;
    let scope = ReplayScope::holder_proof_jwt(service_id, service_id, profile_id, holder_id)
        .map_err(|_| EvidenceError::HolderProofRequired)?;
    let key = ReplayKey::new(claims.jti).map_err(|_| EvidenceError::HolderProofRequired)?;
    Ok(HolderProofBinding {
        scope,
        key,
        expires_at,
    })
}
