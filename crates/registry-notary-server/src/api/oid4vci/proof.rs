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
    let mut request = Request::from_parts(parts, Body::from(bytes));
    request.extensions_mut().insert(validated_proof);
    next.run(request).await
}
pub(in crate::api) async fn oid4vci_nonce(
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(Extension(state)) = state else {
        return oid4vci_error_response(Oid4vciWireError::ServerError);
    };
    if !state.oid4vci.enabled || !state.oid4vci.nonce.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let client_address = token_client_address(&state, &headers, connect_info.as_deref());
    if consume_public_client_address_rate_limit(&state, &client_address)
        .await
        .is_err()
    {
        return oid4vci_error_response(Oid4vciWireError::RateLimited);
    }
    let request = if body.is_empty() {
        Oid4vciNonceRequest {
            credential_configuration_id: None,
        }
    } else {
        match serde_json::from_slice::<Oid4vciNonceRequest>(&body) {
            Ok(request) => request,
            Err(_) => return oid4vci_error_response(Oid4vciWireError::InvalidRequest),
        }
    };
    let configuration_id =
        match oid4vci_nonce_configuration_id(&state.oid4vci, request.credential_configuration_id) {
            Ok(configuration_id) => configuration_id,
            Err(error) => return oid4vci_error_response(error),
        };
    let nonce = match generate_nonce() {
        Ok(nonce) => nonce,
        Err(error) => return evidence_error_response(error),
    };
    let key = match state.self_attestation_rate_keys.oid4vci_nonce(
        &state.oid4vci.credential_issuer,
        configuration_id,
        &nonce,
    ) {
        Ok(key) => key,
        Err(error) => return evidence_error_response(error.evidence_error()),
    };
    let replay_scope = match oid4vci_nonce_replay_scope(&state, configuration_id) {
        Ok(scope) => scope,
        Err(_) => return oid4vci_error_response(Oid4vciWireError::ServerError),
    };
    let replay_key = match ReplayKey::new(key) {
        Ok(key) => key,
        Err(_) => return oid4vci_error_response(Oid4vciWireError::ServerError),
    };
    let expires_at =
        OffsetDateTime::now_utc() + time::Duration::seconds(state.oid4vci.nonce.ttl_seconds as i64);
    if let Err(error) = state
        .replay
        .nonce_store()
        .reserve_nonce(&replay_scope, &replay_key, expires_at)
        .await
    {
        if replay_store_error_is_capacity(&error) {
            state.metrics.record_replay("oid4vci_nonce", "rate_limited");
            return oid4vci_error_response(Oid4vciWireError::RateLimited);
        }
        state.metrics.record_replay("oid4vci_nonce", "error");
        return oid4vci_error_response(Oid4vciWireError::ServerError);
    }
    state.metrics.record_replay("oid4vci_nonce", "reserved");
    Json(NonceResponse {
        c_nonce: nonce,
        c_nonce_expires_in: state.oid4vci.nonce.ttl_seconds,
    })
    .into_response()
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
