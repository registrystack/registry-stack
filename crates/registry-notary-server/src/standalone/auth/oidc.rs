use super::*;

#[allow(clippy::too_many_arguments)]
pub(in super::super) async fn authenticate_oidc(
    credentials: &RequestCredentials,
    verifier: &TokenVerifier,
    fetch_url_policy: &FetchUrlPolicy,
    principal_claim: &str,
    subject_binding_claim: Option<&str>,
    subject_binding_claim_source: SelfAttestationClaimSource,
    assurance_claim_source: SelfAttestationAssuranceClaimSource,
    userinfo_endpoint: Option<&str>,
    userinfo_issuers: &[String],
) -> Result<EvidencePrincipal, EvidenceError> {
    let Some(token) = credentials.bearer_token.as_deref() else {
        return Err(EvidenceError::MissingCredential);
    };
    let verified = verifier.verify(token).await.map_err(oidc_auth_error)?;
    let verified_userinfo = match (subject_binding_claim, subject_binding_claim_source) {
        (Some(_), SelfAttestationClaimSource::Userinfo) => {
            let endpoint = userinfo_endpoint.ok_or(EvidenceError::MissingCredential)?;
            let userinfo_jwt = fetch_userinfo_jwt_with_policy(
                endpoint,
                token,
                fetch_url_policy,
                Duration::from_secs(5),
                64 * 1024,
            )
            .await
            .map_err(oidc_auth_error)?;
            let accepted_issuers = userinfo_issuers
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>();
            let accepted_audiences = verified
                .matched_client
                .as_ref()
                .and_then(|matched| matched.split_once(':'))
                .map(|(_, client)| vec![client.to_string()])
                .unwrap_or_default();
            Some(
                verifier
                    .verify_userinfo_jwt_with_claims_policy(
                        &userinfo_jwt,
                        &verified,
                        &accepted_issuers,
                        &accepted_audiences,
                    )
                    .await
                    .map_err(oidc_auth_error)?,
            )
        }
        _ => None,
    };
    let verified_id_token = match assurance_claim_source {
        SelfAttestationAssuranceClaimSource::AccessToken => None,
        SelfAttestationAssuranceClaimSource::IdToken => {
            let Some(id_token) = credentials.id_token.as_deref() else {
                return Err(EvidenceError::MissingCredential);
            };
            let id_token = verifier
                .verify_related_token(id_token)
                .await
                .map_err(oidc_auth_error)?;
            if id_token.claims.sub != verified.claims.sub {
                return Err(EvidenceError::MissingCredential);
            }
            Some(id_token)
        }
    };
    let token_type = jsonwebtoken::decode_header(token)
        .ok()
        .and_then(|header| header.typ)
        .and_then(|typ| verified_claim_value(&typ));
    principal_from_oidc(
        &verified,
        EvidenceAuthProfileId::ExternalOidc,
        verified_userinfo.as_ref(),
        verified_id_token.as_ref(),
        token_type,
        principal_claim,
        subject_binding_claim,
        subject_binding_claim_source,
        assurance_claim_source,
    )
}

/// Read the `iss` claim from a JWT WITHOUT verifying the signature. Used only to
/// ROUTE to the correct verifier; the value is never trusted before the chosen
/// anchor fully verifies the token (signature, alg, typ, iss, aud, exp/nbf).
#[allow(clippy::too_many_arguments)]
pub(in super::super) fn principal_from_oidc(
    verified: &VerifiedToken,
    auth_profile_id: EvidenceAuthProfileId,
    userinfo: Option<&registry_platform_oidc::Claims>,
    id_token: Option<&VerifiedToken>,
    token_type: Option<VerifiedClaimValue>,
    principal_claim: &str,
    subject_binding_claim: Option<&str>,
    subject_binding_claim_source: SelfAttestationClaimSource,
    assurance_claim_source: SelfAttestationAssuranceClaimSource,
) -> Result<EvidencePrincipal, EvidenceError> {
    let principal_id = if principal_claim == "sub" {
        verified.claims.sub.clone()
    } else {
        verified
            .claims
            .extra
            .get(principal_claim)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    }
    .ok_or(EvidenceError::MissingCredential)?;
    let authorization_details = authorization_details_from_oidc(verified)?;
    Ok(EvidencePrincipal {
        auth_profile_id,
        principal_id,
        scopes: verified.scopes.clone(),
        access_mode: AccessMode::MachineClient,
        verified_claims: bounded_verified_claims_from_oidc(
            verified,
            userinfo,
            id_token,
            token_type,
            subject_binding_claim,
            subject_binding_claim_source,
            assurance_claim_source,
        ),
        authorization_details,
    })
}

pub(in super::super) fn authorization_details_from_oidc(
    verified: &VerifiedToken,
) -> Result<Option<EvidenceAuthorizationDetails>, EvidenceError> {
    let Some(details) = verified.claims.extra.get("authorization_details") else {
        return Ok(None);
    };
    let details = crate::authz_details::extract_notary_transaction_authorization_details(details)?;
    Ok(details.filter(crate::authz_details::has_transaction_scope))
}

pub(in super::super) fn bounded_verified_claims_from_oidc(
    verified: &VerifiedToken,
    userinfo: Option<&registry_platform_oidc::Claims>,
    id_token: Option<&VerifiedToken>,
    token_type: Option<VerifiedClaimValue>,
    subject_binding_claim: Option<&str>,
    subject_binding_claim_source: SelfAttestationClaimSource,
    assurance_claim_source: SelfAttestationAssuranceClaimSource,
) -> Option<BoundedVerifiedClaims> {
    let issuer = verified
        .claims
        .iss
        .as_deref()
        .and_then(verified_claim_value)?;
    let (subject_binding_claim, subject_binding_value) = if let Some(subject_binding_claim) =
        subject_binding_claim
    {
        let claim_name = VerifiedClaimName::new(subject_binding_claim).ok()?;
        let claim_value = match subject_binding_claim_source {
            SelfAttestationClaimSource::AccessToken => claim_string(verified, claim_name.as_str()),
            SelfAttestationClaimSource::Userinfo => {
                userinfo.and_then(|claims| claim_string_from_claims(claims, claim_name.as_str()))
            }
        }
        .and_then(verified_claim_value)?;
        (Some(claim_name), Some(claim_value))
    } else {
        (None, None)
    };
    let assurance_claims = match assurance_claim_source {
        SelfAttestationAssuranceClaimSource::AccessToken => &verified.claims,
        SelfAttestationAssuranceClaimSource::IdToken => &id_token?.claims,
    };
    Some(BoundedVerifiedClaims {
        issuer,
        audiences: bounded_audience(verified.claims.aud.as_ref()),
        client_id: verified_client(verified),
        token_type,
        scopes: bounded_scopes(&verified.scopes),
        subject: verified
            .claims
            .sub
            .as_deref()
            .and_then(verified_claim_value),
        subject_binding_claim,
        subject_binding_value,
        acr: assurance_claims
            .extra
            .get("acr")
            .and_then(Value::as_str)
            .and_then(verified_claim_value),
        auth_time: numeric_claim(&assurance_claims.extra, "auth_time"),
        exp: verified.claims.exp,
        iat: verified.claims.iat,
        nbf: verified.claims.nbf,
    })
}

pub(in super::super) fn claim_string<'a>(
    verified: &'a VerifiedToken,
    claim: &str,
) -> Option<&'a str> {
    if claim == "sub" {
        return verified.claims.sub.as_deref();
    }
    claim_string_from_claims(&verified.claims, claim)
}

pub(in super::super) fn claim_string_from_claims<'a>(
    claims: &'a registry_platform_oidc::Claims,
    claim: &str,
) -> Option<&'a str> {
    if claim == "sub" {
        return claims.sub.as_deref();
    }
    claims.extra.get(claim).and_then(Value::as_str)
}

pub(in super::super) fn verified_claim_value(value: &str) -> Option<VerifiedClaimValue> {
    VerifiedClaimValue::new(value).ok()
}

pub(in super::super) fn bounded_audience(audience: Option<&Audience>) -> Vec<VerifiedClaimValue> {
    let values: Vec<&str> = match audience {
        Some(Audience::One(value)) => vec![value.as_str()],
        Some(Audience::Many(values)) => values.iter().map(String::as_str).collect(),
        None => Vec::new(),
    };
    values
        .into_iter()
        .filter_map(verified_claim_value)
        .collect()
}

pub(in super::super) fn verified_client(verified: &VerifiedToken) -> Option<VerifiedClaimValue> {
    let client = verified
        .claims
        .azp
        .as_deref()
        .map(|azp| format!("azp:{azp}"))
        .or_else(|| {
            verified
                .claims
                .client_id
                .as_deref()
                .map(|client_id| format!("client_id:{client_id}"))
        })
        .or_else(|| verified.matched_client.clone())?;
    verified_claim_value(&client)
}

pub(in super::super) fn bounded_scopes(scopes: &[String]) -> Vec<VerifiedClaimValue> {
    scopes
        .iter()
        .filter_map(|scope| verified_claim_value(scope))
        .collect()
}

pub(in super::super) fn numeric_claim(extra: &Map<String, Value>, claim: &str) -> Option<i64> {
    extra.get(claim).and_then(Value::as_i64)
}

pub(in super::super) fn oidc_auth_error(error: OidcError) -> EvidenceError {
    tracing::debug!(
        target: "registry_notary_server::auth",
        error_code = oidc_internal_error_code(&error),
        error = ?error,
        "OIDC token verification failed"
    );
    EvidenceError::MissingCredential
}

pub(in super::super) fn oidc_internal_error_code(error: &OidcError) -> &'static str {
    match error {
        OidcError::Transport(_)
        | OidcError::BoundedRead(_)
        | OidcError::FetchUrl(_)
        | OidcError::HttpStatus(_)
        | OidcError::InvalidUrl
        | OidcError::Parse
        | OidcError::InvalidJwk => "auth.oidc_unavailable",
        OidcError::IssuerMismatch { .. }
        | OidcError::MalformedToken
        | OidcError::AlgorithmNotAllowed
        | OidcError::TokenTypeNotAllowed
        | OidcError::MissingKid
        | OidcError::KidTooLong
        | OidcError::UnknownKid
        | OidcError::TokenExpired
        | OidcError::TokenNotYetValid
        | OidcError::AudienceMismatch
        | OidcError::SignatureInvalid
        | OidcError::InvalidToken
        | OidcError::ClientNotAllowed => "auth.invalid_token",
        _ => "auth.invalid_token",
    }
}

pub(in super::super) fn parse_oidc_algorithm(
    algorithm: &str,
) -> Result<Algorithm, StandaloneServerError> {
    match algorithm {
        "EdDSA" => Ok(Algorithm::EdDSA),
        "RS256" => Ok(Algorithm::RS256),
        "PS256" => Ok(Algorithm::PS256),
        other => Err(StandaloneServerError::InvalidOidcConfig(format!(
            "unsupported OIDC signing algorithm '{other}'"
        ))),
    }
}
