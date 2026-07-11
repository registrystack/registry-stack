use super::*;

/// The Notary's own self-issuance trust anchor: its access-token public key,
/// pinned issuer, header `typ`, and accepted audiences. Verification is fully
/// in-process (no self-HTTP-call to a JWKS endpoint).
#[derive(Clone)]
pub(crate) struct NotaryTokenAnchor {
    pub(in super::super) verification_keys: Vec<AccessTokenVerificationKey>,
    pub(in super::super) issuer: String,
    pub(in super::super) token_typ: String,
    pub(in super::super) audiences: Vec<String>,
    pub(in super::super) principal_claim: String,
    pub(in super::super) subject_binding_claim: Option<String>,
}

impl std::fmt::Debug for NotaryTokenAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotaryTokenAnchor")
            .field("issuer", &self.issuer)
            .field("token_typ", &self.token_typ)
            .field("audiences", &self.audiences)
            .finish_non_exhaustive()
    }
}

pub(in super::super) fn unverified_issuer(token: &str) -> Option<String> {
    let payload_b64 = token.split('.').nth(1)?;
    let bytes = BASE64_URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let payload: Value = serde_json::from_slice(&bytes).ok()?;
    payload
        .get("iss")
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

/// Verify a Notary-issued access token against the separate, separately-keyed
/// Notary anchor and map it to an `EvidencePrincipal` via `principal_from_oidc`,
/// identically to an eSignet token.
///
/// Verification pins alg (EdDSA), the access-token `typ`, the Notary `iss`, the
/// configured audiences, the signature against the dedicated access-token key,
/// and `exp`/`nbf`. Every failure collapses to `EvidenceError::MissingCredential`,
/// matching `oidc_auth_error` (no info leak).
pub(in super::super) async fn authenticate_notary_token(
    token: &str,
    anchor: &NotaryTokenAnchor,
    replay: &ReplayStores,
) -> Result<EvidencePrincipal, EvidenceError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let verified_notary = anchor
        .verification_keys
        .iter()
        .filter(|key| key.may_verify_at(now))
        .find_map(|key| {
            registry_notary_core::tokens::verify_notary_token(
                token,
                key.public_jwk(),
                &anchor.token_typ,
                &anchor.issuer,
                &anchor.audiences,
                now,
            )
            .ok()
        })
        .ok_or(EvidenceError::MissingCredential)?;
    consume_notary_token_jti(&verified_notary.payload, anchor, replay).await?;
    let verified = verified_token_from_notary_payload(&verified_notary.payload)
        .ok_or(EvidenceError::MissingCredential)?;
    // Notary tokens carry the assurance and subject-binding claims in the access
    // token itself, so both claim sources are AccessToken. This mirrors what an
    // eSignet access token would provide and reuses the consumption path
    // unchanged.
    principal_from_oidc(
        &verified,
        None,
        None,
        verified_claim_value(&anchor.token_typ),
        &anchor.principal_claim,
        anchor.subject_binding_claim.as_deref(),
        SelfAttestationClaimSource::AccessToken,
        SelfAttestationAssuranceClaimSource::AccessToken,
    )
}

pub(in super::super) async fn consume_notary_token_jti(
    payload: &Value,
    anchor: &NotaryTokenAnchor,
    replay: &ReplayStores,
) -> Result<(), EvidenceError> {
    let Some(jti) = payload.get("jti").and_then(Value::as_str) else {
        // Single-use tokens carry replay protection via `jti`. The transaction
        // token typ is required to be single-use, so a missing `jti` for that
        // typ must fail closed rather than silently skip replay protection.
        // Other typs are not single-use and legitimately have no `jti`.
        if anchor.token_typ == registry_notary_core::tokens::NOTARY_TRANSACTION_TOKEN_JWT_TYP {
            return Err(EvidenceError::MissingCredential);
        }
        return Ok(());
    };
    if jti.trim().is_empty() {
        return Err(EvidenceError::MissingCredential);
    }
    let exp = payload
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(EvidenceError::MissingCredential)?;
    let expires_at =
        OffsetDateTime::from_unix_timestamp(exp).map_err(|_| EvidenceError::MissingCredential)?;
    let scope = ReplayScope::new([
        ("protocol", "registry-notary"),
        ("flow", "notary-token-jti"),
        ("issuer", anchor.issuer.as_str()),
        ("typ", anchor.token_typ.as_str()),
    ])
    .map_err(|_| EvidenceError::MissingCredential)?;
    let key = ReplayKey::new(jti).map_err(|_| EvidenceError::MissingCredential)?;
    require_replay_insert(replay.store().as_ref(), &scope, &key, expires_at)
        .await
        .map_err(|_| EvidenceError::MissingCredential)
}

/// Adapt a verified Notary token payload into the platform `VerifiedToken` the
/// `principal_from_oidc` mapping consumes.
pub(in super::super) fn verified_token_from_notary_payload(
    payload: &Value,
) -> Option<registry_platform_oidc::VerifiedToken> {
    let claims: registry_platform_oidc::Claims = serde_json::from_value(payload.clone()).ok()?;
    let scopes = payload
        .get("scope")
        .and_then(Value::as_str)
        .map(|scope| {
            scope
                .split(' ')
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default();
    Some(registry_platform_oidc::VerifiedToken {
        claims,
        matched_client: None,
        scopes,
    })
}
