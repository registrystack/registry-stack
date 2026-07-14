// SPDX-License-Identifier: Apache-2.0
//! OID4VCI pre-authorized-code offer and token flow.

use super::super::*;

#[derive(Debug, Deserialize)]
pub(in crate::api) struct Oid4vciOfferStartQuery {
    pub(in crate::api) credential_configuration_id: Option<String>,
}

/// `GET /oid4vci/offer/start` (public): begin the eSignet authorization-code
/// login as the confidential RP and redirect the citizen browser to eSignet.
///
/// Mints no code or credential material. Only a short-lived single-use login
/// state (PKCE verifier + nonce + selection) is reserved.
pub(in crate::api) async fn oid4vci_offer_start(
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    Query(query): Query<Oid4vciOfferStartQuery>,
) -> Response {
    let Some(Extension(state)) = state else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(preauth) = preauth_runtime(&state) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let configuration_id = match query
        .credential_configuration_id
        .as_deref()
        .map(|id| oid4vci_validated_configuration_id(&state.oid4vci, id))
        .transpose()
    {
        Ok(Some(id)) => id,
        Ok(None) => match single_credential_configuration_id(&state.oid4vci) {
            Some(id) => id,
            None => return oid4vci_error_response(Oid4vciWireError::InvalidRequest),
        },
        Err(()) => return oid4vci_error_response(Oid4vciWireError::InvalidRequest),
    };
    let (Ok(login_state), Ok(nonce), Ok(pkce_verifier)) = (
        generate_opaque_token(),
        generate_opaque_token(),
        generate_opaque_token(),
    ) else {
        return oid4vci_error_response(Oid4vciWireError::ServerError);
    };
    let pkce_challenge = pkce_s256_challenge(&pkce_verifier);
    let reserved = preauth
        .preauthorization_state()
        .reserve_login(
            &login_state,
            LoginState {
                pkce_verifier,
                nonce: nonce.clone(),
                credential_configuration_id: configuration_id,
            },
            preauth.login_state_ttl_seconds(),
        )
        .await;
    if let Err(error) = reserved {
        return match error {
            PreauthorizationStateError::LoginStateCapacity => {
                oid4vci_error_response(Oid4vciWireError::RateLimited)
            }
            PreauthorizationStateError::DuplicateLoginState
            | PreauthorizationStateError::Unavailable
            | PreauthorizationStateError::IncompatibleTransactionCodeProof
            | PreauthorizationStateError::InvalidExpiry
            | PreauthorizationStateError::SensitiveState(_) => {
                oid4vci_error_response(Oid4vciWireError::ServerError)
            }
        };
    }
    let redirect_url = match preauth.authorize_redirect_url(&login_state, &nonce, &pkce_challenge) {
        Ok(url) => url,
        Err(_) => return oid4vci_error_response(Oid4vciWireError::ServerError),
    };
    Redirect::to(&redirect_url).into_response()
}

#[derive(Debug, Deserialize)]
pub(in crate::api) struct Oid4vciOfferCallbackQuery {
    pub(in crate::api) code: Option<String>,
    pub(in crate::api) state: Option<String>,
}

/// `GET /oid4vci/offer/callback` (public): consume the login state, exchange the
/// eSignet code via `private_key_jwt`, validate the `id_token`, mint a single-use
/// `pre-authorized_code`, and render the offer page.
pub(in crate::api) async fn oid4vci_offer_callback(
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    Query(query): Query<Oid4vciOfferCallbackQuery>,
) -> Response {
    let Some(Extension(state)) = state else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(preauth) = preauth_runtime(&state) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let path = "/oid4vci/offer/callback";
    let (Some(code), Some(login_state)) = (query.code.as_deref(), query.state.as_deref()) else {
        return preauth_denied(
            &preauth,
            path,
            "GET",
            None,
            SelfAttestationDenialCode::InvalidToken,
            Oid4vciWireError::InvalidRequest,
        )
        .await;
    };
    // Single-use consume: unknown/expired/replayed state is the CSRF/replay
    // guard. A missing state yields no code.
    let stored = match preauth
        .preauthorization_state()
        .consume_login(login_state)
        .await
    {
        Ok(Some(stored)) => stored,
        Ok(None) => {
            return preauth_denied(
                &preauth,
                path,
                "GET",
                None,
                SelfAttestationDenialCode::InvalidToken,
                Oid4vciWireError::InvalidRequest,
            )
            .await;
        }
        Err(_) => {
            return preauth_denied(
                &preauth,
                path,
                "GET",
                None,
                SelfAttestationDenialCode::OperationDenied,
                Oid4vciWireError::ServerError,
            )
            .await;
        }
    };
    let subject_binding_claim = state.self_attestation.subject_binding.token_claim.clone();
    let subject = match preauth
        .exchange_code_for_subject(
            code,
            &stored.pkce_verifier,
            &stored.nonce,
            &subject_binding_claim,
        )
        .await
    {
        Ok(subject) => subject,
        Err(_) => {
            return preauth_denied(
                &preauth,
                path,
                "GET",
                Some(&stored.credential_configuration_id),
                SelfAttestationDenialCode::InvalidToken,
                Oid4vciWireError::InvalidToken,
            )
            .await;
        }
    };
    let bound_subject = BoundSubject {
        subject: subject.subject,
        subject_binding_claim,
        subject_binding_value: subject.subject_binding_value,
        client_id: subject.client_id,
        scopes: subject.scopes,
        acr: subject.acr,
        auth_time: subject.auth_time,
    };
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let Ok(jti) = generate_opaque_token() else {
        return preauth_server_error(&preauth, path, "GET", &stored.credential_configuration_id)
            .await;
    };
    let code_claims = PreAuthorizedCodeClaims {
        issuer: preauth.notary_issuer().to_string(),
        jti: jti.clone(),
        credential_configuration_id: stored.credential_configuration_id.clone(),
        subject: bound_subject,
        iat: now,
        exp: now + preauth.pre_authorized_code_ttl_seconds() as i64,
    };
    let signed_code = match mint_pre_authorized_code(
        preauth.access_token_signer(),
        PRE_AUTHORIZED_CODE_JWT_TYP,
        &code_claims,
    )
    .await
    {
        Ok(signed) => signed,
        Err(_) => {
            return preauth_server_error(
                &preauth,
                path,
                "GET",
                &stored.credential_configuration_id,
            )
            .await;
        }
    };
    let tx_code_pin = if preauth.tx_code_required() {
        let Ok(pin) = generate_numeric_tx_code(preauth.tx_code_length()) else {
            return preauth_server_error(
                &preauth,
                path,
                "GET",
                &stored.credential_configuration_id,
            )
            .await;
        };
        // Persist the PIN keyed by the code's jti so the token endpoint can verify
        // the holder-presented tx_code. The PIN is never embedded in the offer code
        // JWT (otherwise the code holder would know it).
        let expires_at = match OffsetDateTime::from_unix_timestamp(code_claims.exp) {
            Ok(expires_at) => expires_at,
            Err(_) => {
                return preauth_server_error(
                    &preauth,
                    path,
                    "GET",
                    &stored.credential_configuration_id,
                )
                .await;
            }
        };
        if !matches!(
            preauth
                .preauthorization_state()
                .reserve_transaction_code(&jti, &pin, preauth.tx_code_length(), expires_at,)
                .await,
            Ok(true)
        ) {
            return preauth_server_error(
                &preauth,
                path,
                "GET",
                &stored.credential_configuration_id,
            )
            .await;
        }
        Some(pin)
    } else {
        None
    };
    let tx_code = tx_code_pin.as_ref().map(|_| {
        TxCode::new(
            preauth.tx_code_length(),
            Some("Enter the PIN shown by the issuer".to_string()),
        )
    });
    let offer = CredentialOffer::pre_authorized_code(
        state.oid4vci.credential_issuer.clone(),
        vec![stored.credential_configuration_id.clone()],
        signed_code.compact.clone(),
        tx_code,
    );
    let offer_uri = match offer_request_uri(&offer) {
        Ok(uri) => uri,
        Err(_) => {
            return preauth_server_error(
                &preauth,
                path,
                "GET",
                &stored.credential_configuration_id,
            )
            .await;
        }
    };
    let audit = pre_auth_audit_event(
        "GET",
        path,
        StatusCode::OK.as_u16(),
        "preauth_offer_minted",
        PreAuthAuditFields {
            credential_configuration_id: registry_notary_core::ConfigMetadata::new(
                &stored.credential_configuration_id,
            )
            .ok(),
            ..PreAuthAuditFields::default()
        },
    );
    if preauth.emit_audit(&audit).await.is_err() {
        return oid4vci_error_response(Oid4vciWireError::ServerError);
    }
    state
        .metrics
        .record_credential("openid4vci_preauth", "offer_minted");
    Html(offer_page_html(&offer_uri, tx_code_pin.as_deref())).into_response()
}

/// `POST /oid4vci/token` (public): the OID4VCI token endpoint for the
/// pre-authorized-code grant. Verifies the code and optional `tx_code`, then mints a
/// short-TTL Notary access token + `c_nonce`.
pub(in crate::api) async fn oid4vci_token(
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(Extension(state)) = state else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(preauth) = preauth_runtime(&state) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let path = "/oid4vci/token";
    let client_address = token_client_address(&state, &headers, connect_info.as_deref());
    let request = match parse_token_request(&headers, &body) {
        Ok(request) => request,
        Err(error) => {
            return token_error_with_audit(
                &preauth,
                path,
                None,
                SelfAttestationDenialCode::OperationDenied,
                error,
            )
            .await;
        }
    };
    if request.grant_type != PRE_AUTHORIZED_CODE_GRANT_TYPE {
        return token_error_with_audit(
            &preauth,
            path,
            None,
            SelfAttestationDenialCode::OperationDenied,
            TokenWireError::UnsupportedGrantType,
        )
        .await;
    }
    let Some(code) = request
        .pre_authorized_code
        .as_deref()
        .filter(|c| !c.is_empty())
    else {
        return token_error_with_audit(
            &preauth,
            path,
            None,
            SelfAttestationDenialCode::OperationDenied,
            TokenWireError::InvalidRequest,
        )
        .await;
    };
    // Throttle random-code floods per client address (reuse the existing
    // invalid-token-per-address limiter bucket).
    if check_token_client_address_rate_limit(&state, &client_address)
        .await
        .is_err()
    {
        return token_error_with_audit(
            &preauth,
            path,
            None,
            SelfAttestationDenialCode::RateLimited,
            TokenWireError::SlowDown,
        )
        .await;
    }
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let verified = match preauth
        .access_token_verification_keys()
        .iter()
        .filter(|key| key.may_verify_at(now))
        .find_map(|key| {
            verify_notary_token(
                code,
                key.public_jwk(),
                PRE_AUTHORIZED_CODE_JWT_TYP,
                preauth.notary_issuer(),
                &[],
                now,
            )
            .ok()
        }) {
        Some(verified) => verified,
        None => {
            return token_error_after_invalid_attempt(
                &state,
                &preauth,
                path,
                &client_address,
                None,
                TokenWireError::InvalidGrant,
            )
            .await;
        }
    };
    let configuration_id = verified
        .claim_str("credential_configuration_id")
        .map(ToString::to_string);
    let Some(jti) = verified.claim_str("jti").map(ToString::to_string) else {
        return token_error_after_invalid_attempt(
            &state,
            &preauth,
            path,
            &client_address,
            configuration_id.as_deref(),
            TokenWireError::InvalidGrant,
        )
        .await;
    };
    let Some(code_expires_at) = verified
        .claim_i64("exp")
        .and_then(|expiry| OffsetDateTime::from_unix_timestamp(expiry).ok())
    else {
        return token_error_after_invalid_attempt(
            &state,
            &preauth,
            path,
            &client_address,
            configuration_id.as_deref(),
            TokenWireError::InvalidGrant,
        )
        .await;
    };
    let transaction_code = if preauth.tx_code_required() {
        // Cap wrong-PIN attempts per code (brute-force guard). A locked code
        // (attempts over the cap) is rejected before the PIN compare.
        if check_tx_code_attempt(&state, code).await.is_err() {
            return token_error_after_invalid_attempt(
                &state,
                &preauth,
                path,
                &client_address,
                configuration_id.as_deref(),
                TokenWireError::SlowDown,
            )
            .await;
        }
        let tx_code = request.tx_code.as_deref().unwrap_or("");
        match preauth
            .preauthorization_state()
            .verify_transaction_code(&jti, tx_code)
            .await
        {
            Ok(Some(proof)) => Some(proof),
            Ok(None) => {
                return token_error_after_invalid_attempt(
                    &state,
                    &preauth,
                    path,
                    &client_address,
                    configuration_id.as_deref(),
                    TokenWireError::InvalidGrant,
                )
                .await;
            }
            Err(_) => {
                return token_error_with_audit(
                    &preauth,
                    path,
                    configuration_id.as_deref(),
                    SelfAttestationDenialCode::OperationDenied,
                    TokenWireError::ServerError,
                )
                .await;
            }
        }
    } else {
        None
    };
    let Some(bound_subject) = bound_subject_from_code(&verified, &state) else {
        return token_error_after_invalid_attempt(
            &state,
            &preauth,
            path,
            &client_address,
            configuration_id.as_deref(),
            TokenWireError::InvalidGrant,
        )
        .await;
    };
    let Some(configuration_id) = configuration_id else {
        return token_error_after_invalid_attempt(
            &state,
            &preauth,
            path,
            &client_address,
            None,
            TokenWireError::InvalidGrant,
        )
        .await;
    };
    let Some((configuration_id, configuration)) = state
        .oid4vci
        .credential_configurations
        .get_key_value(&configuration_id)
    else {
        return token_error_after_invalid_attempt(
            &state,
            &preauth,
            path,
            &client_address,
            Some(&configuration_id),
            TokenWireError::InvalidGrant,
        )
        .await;
    };
    let mut bound_subject = bound_subject;
    add_scope_if_missing(&mut bound_subject.scopes, &configuration.scope);
    let authorization_details = match oid4vci_issuance_authorization_details(
        &state.evidence,
        &state.self_attestation,
        configuration,
    )
    .and_then(|details| {
        serde_json::to_value(details).map_err(|_| EvidenceError::CredentialIssuanceFailed)
    }) {
        Ok(details) => vec![details],
        Err(_) => {
            return token_error_with_audit(
                &preauth,
                path,
                Some(configuration_id),
                SelfAttestationDenialCode::OperationDenied,
                TokenWireError::ServerError,
            )
            .await;
        }
    };
    let replay_scope = match pre_authorized_code_replay_scope(&state) {
        Ok(scope) => scope,
        Err(()) => {
            return token_error_with_audit(
                &preauth,
                path,
                Some(configuration_id),
                SelfAttestationDenialCode::OperationDenied,
                TokenWireError::ServerError,
            )
            .await;
        }
    };
    match preauth
        .preauthorization_state()
        .redeem(&replay_scope, &jti, code_expires_at, transaction_code)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return token_error_after_invalid_attempt(
                &state,
                &preauth,
                path,
                &client_address,
                Some(configuration_id),
                TokenWireError::InvalidGrant,
            )
            .await;
        }
        Err(_) => {
            return token_error_with_audit(
                &preauth,
                path,
                Some(configuration_id),
                SelfAttestationDenialCode::OperationDenied,
                TokenWireError::ServerError,
            )
            .await;
        }
    }
    let configuration_id = configuration_id.as_str();
    let access_token_claims = AccessTokenClaims {
        issuer: preauth.notary_issuer().to_string(),
        jti: None,
        audiences: preauth.notary_audiences().to_vec(),
        token_type: "Bearer".to_string(),
        credential_configuration_id: configuration_id.to_string(),
        subject: bound_subject,
        authorization_details,
        confirmation: None,
        actor: None,
        iat: now,
        exp: now + preauth.access_token_ttl_seconds() as i64,
    };
    let access_token = match mint_access_token(
        preauth.access_token_signer(),
        preauth.access_token_typ(),
        &access_token_claims,
    )
    .await
    {
        Ok(token) => token,
        Err(_) => {
            return token_error_with_audit(
                &preauth,
                path,
                Some(configuration_id),
                SelfAttestationDenialCode::OperationDenied,
                TokenWireError::ServerError,
            )
            .await;
        }
    };
    let c_nonce = match issue_c_nonce(&state, configuration_id).await {
        Some(c_nonce) => c_nonce,
        None => {
            return token_error_with_audit(
                &preauth,
                path,
                Some(configuration_id),
                SelfAttestationDenialCode::OperationDenied,
                TokenWireError::ServerError,
            )
            .await;
        }
    };
    let audit = pre_auth_audit_event(
        "POST",
        path,
        StatusCode::OK.as_u16(),
        "preauth_token_issued",
        PreAuthAuditFields {
            credential_configuration_id: registry_notary_core::ConfigMetadata::new(
                configuration_id,
            )
            .ok(),
            ..PreAuthAuditFields::default()
        },
    );
    if preauth.emit_audit(&audit).await.is_err() {
        return token_error_response(TokenWireError::ServerError);
    }
    state
        .metrics
        .record_credential("openid4vci_preauth", "token_issued");
    Json(Oid4vciTokenResponse {
        access_token: access_token.compact,
        token_type: "Bearer".to_string(),
        expires_in: Some(preauth.access_token_ttl_seconds()),
        c_nonce: Some(c_nonce),
        c_nonce_expires_in: state
            .oid4vci
            .nonce
            .enabled
            .then_some(state.oid4vci.nonce.ttl_seconds),
    })
    .into_response()
}

/// The pre-auth runtime, present only when the flow is enabled and configured.
pub(in crate::api) fn preauth_runtime(
    state: &RegistryNotaryApiState,
) -> Option<Arc<PreAuthRuntime>> {
    if !state.oid4vci.enabled {
        return None;
    }
    state.runtime_snapshot().preauth.clone()
}

/// Validate a requested `credential_configuration_id` against the configured
/// set. Returns the canonical id, or `Err(())` if unknown.
pub(in crate::api) fn oid4vci_validated_configuration_id(
    config: &Oid4vciConfig,
    requested: &str,
) -> Result<String, ()> {
    config
        .credential_configurations
        .get_key_value(requested)
        .map(|(id, _)| id.clone())
        .ok_or(())
}

/// The single configured credential configuration id, or `None` if zero or
/// more than one are configured.
pub(in crate::api) fn single_credential_configuration_id(config: &Oid4vciConfig) -> Option<String> {
    let mut ids = config.credential_configurations.keys();
    let first = ids.next()?;
    if ids.next().is_some() {
        return None;
    }
    Some(first.clone())
}

pub(in crate::api) fn pre_authorized_code_replay_scope(
    state: &RegistryNotaryApiState,
) -> Result<ReplayScope, ()> {
    ReplayScope::new([
        ("tenant".to_string(), state.evidence.service_id.clone()),
        ("kind".to_string(), "oid4vci-preauth-code".to_string()),
        (
            "issuer".to_string(),
            state.oid4vci.credential_issuer.clone(),
        ),
    ])
    .map_err(|_| ())
}

/// Build the `openid-credential-offer://` request URI carrying the offer JSON.
pub(in crate::api) fn offer_request_uri(offer: &CredentialOffer) -> Result<String, ()> {
    let json = serde_json::to_string(offer).map_err(|_| ())?;
    let encoded = url_percent_encode(&json);
    Ok(format!(
        "openid-credential-offer://?credential_offer={encoded}"
    ))
}

/// Percent-encode a value for a query string (RFC 3986 unreserved set kept).
pub(in crate::api) fn url_percent_encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char);
            }
            other => {
                out.push('%');
                out.push(HEX[(other >> 4) as usize] as char);
                out.push(HEX[(other & 0x0F) as usize] as char);
            }
        }
    }
    out
}

/// Render the citizen-facing offer page: the QR-encodable offer URI plus an
/// out-of-band PIN when the offer requires one.
pub(in crate::api) fn offer_page_html(offer_uri: &str, pin: Option<&str>) -> String {
    let offer_uri = html_escape(offer_uri);
    let pin_html = pin.map(|pin| {
        let pin = html_escape(pin);
        format!(
            "<p>Then enter this PIN when your wallet asks:</p>\
<p><strong id=\"tx-code\">{pin}</strong></p>"
        )
    });
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<title>Credential offer</title></head><body>\
<h1>Scan to receive your credential</h1>\
<p>Scan this offer in your wallet:</p>\
<p><a id=\"credential-offer\" href=\"{offer_uri}\">{offer_uri}</a></p>\
{}\
</body></html>",
        pin_html.unwrap_or_default()
    )
}

pub(in crate::api) fn html_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Reconstruct the `BoundSubject` carried inside a verified pre-authorized code.
pub(in crate::api) fn bound_subject_from_code(
    verified: &registry_notary_core::tokens::VerifiedNotaryToken,
    state: &RegistryNotaryApiState,
) -> Option<BoundSubject> {
    let subject_binding_claim = state.self_attestation.subject_binding.token_claim.clone();
    Some(BoundSubject {
        subject: verified.claim_str("sub")?.to_string(),
        subject_binding_value: verified.claim_str(&subject_binding_claim)?.to_string(),
        subject_binding_claim,
        client_id: verified.claim_str("client_id")?.to_string(),
        scopes: verified.scopes(),
        acr: verified.claim_str("acr").map(ToString::to_string),
        auth_time: verified.claim_i64("auth_time"),
    })
}

/// Issue a `c_nonce` for the credential endpoint, reserving it in the replay
/// store exactly as the nonce endpoint does.
pub(in crate::api) async fn issue_c_nonce(
    state: &RegistryNotaryApiState,
    configuration_id: &str,
) -> Option<String> {
    if !state.oid4vci.nonce.enabled {
        // The credential endpoint requires a c_nonce; without the nonce
        // endpoint enabled there is nothing to reserve, so the value is unused.
        return generate_nonce().ok();
    }
    let nonce = generate_nonce().ok()?;
    let key = state
        .self_attestation_rate_keys
        .oid4vci_nonce(&state.oid4vci.credential_issuer, configuration_id, &nonce)
        .ok()?;
    let scope = oid4vci_nonce_replay_scope(state, configuration_id).ok()?;
    let replay_key = ReplayKey::new(key).ok()?;
    let expires_at =
        OffsetDateTime::now_utc() + time::Duration::seconds(state.oid4vci.nonce.ttl_seconds as i64);
    if state
        .replay
        .nonce_store()
        .reserve_nonce(&scope, &replay_key, expires_at)
        .await
        .is_ok()
    {
        state.metrics.record_replay("oid4vci_nonce", "reserved");
        Some(nonce)
    } else {
        None
    }
}

/// Derive a per-client identifier for public endpoint flood throttles.
///
/// Forwarding headers are accepted only from explicitly trusted proxy peers.
/// Otherwise the public OID4VCI endpoints use the socket peer so
/// caller-controlled `X-Forwarded-*` headers cannot create fresh buckets.
pub(in crate::api) fn token_client_address(
    state: &RegistryNotaryApiState,
    headers: &HeaderMap,
    connect_info: Option<&axum::extract::ConnectInfo<SocketAddr>>,
) -> String {
    token_client_address_with_trusted_proxy_ips(
        headers,
        connect_info,
        &state
            .runtime_config()
            .map(|config| config.server.trusted_proxy_ips.clone())
            .unwrap_or_default(),
    )
}

pub(in crate::api) fn token_client_address_with_trusted_proxy_ips(
    headers: &HeaderMap,
    connect_info: Option<&axum::extract::ConnectInfo<SocketAddr>>,
    trusted_proxy_ips: &[IpAddr],
) -> String {
    let Some(axum::extract::ConnectInfo(addr)) = connect_info else {
        return "unknown-client-address".to_string();
    };
    let peer_ip = addr.ip();
    if trusted_proxy_ips.contains(&peer_ip) {
        if let Some(forwarded_ip) = forwarded_client_ip(headers) {
            return forwarded_ip.to_string();
        }
    }
    peer_ip.to_string()
}

pub(in crate::api) fn forwarded_client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .split(',')
                .map(str::trim)
                .find_map(|candidate| candidate.parse::<IpAddr>().ok())
        })
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.trim().parse::<IpAddr>().ok())
        })
}

/// Per-client-address throttle so random-code floods are bounded. Reuses the
/// existing invalid-token-per-address limiter bucket. This is a check-only gate
/// (availability); the bucket is consumed only on an invalid attempt, matching
/// the auth middleware's check-before / consume-after pattern.
pub(in crate::api) async fn check_token_client_address_rate_limit(
    state: &RegistryNotaryApiState,
    client_address: &str,
) -> Result<(), SelfAttestationRateLimitError> {
    let hashed = state
        .self_attestation_rate_keys
        .client_address(client_address)?;
    state
        .self_attestation_rate_limiter
        .check_invalid_token_for_client_address_available(&hashed)
        .await
}

pub(in crate::api) async fn consume_public_client_address_rate_limit(
    state: &RegistryNotaryApiState,
    client_address: &str,
) -> Result<(), SelfAttestationRateLimitError> {
    let hashed = state
        .self_attestation_rate_keys
        .client_address(client_address)?;
    state
        .self_attestation_rate_limiter
        .check_invalid_token_for_client_address(&hashed)
        .await
}

pub(in crate::api) fn replay_store_error_is_capacity(error: &ReplayStoreError) -> bool {
    matches!(
        error,
        ReplayStoreError::Operation { message }
            if message.contains("in-memory cache store is full")
    )
}

/// Record one `tx_code` attempt against the hashed pre-authorized code. After
/// the configured cap the code is locked.
pub(in crate::api) async fn check_tx_code_attempt(
    state: &RegistryNotaryApiState,
    pre_authorized_code: &str,
) -> Result<(), SelfAttestationRateLimitError> {
    let hashed = state
        .self_attestation_rate_keys
        .pre_authorized_code(pre_authorized_code)?;
    state
        .self_attestation_rate_limiter
        .check_tx_code_attempt(&hashed)
        .await
}

/// Emit a denial audit event for a public pre-auth endpoint and return the
/// matching OID4VCI error response.
pub(in crate::api) async fn preauth_denied(
    preauth: &PreAuthRuntime,
    path: &str,
    method: &str,
    credential_configuration_id: Option<&str>,
    denial_code: SelfAttestationDenialCode,
    wire_error: Oid4vciWireError,
) -> Response {
    let response = oid4vci_error_response(wire_error);
    let status = response.status().as_u16();
    let audit = pre_auth_audit_event(
        method,
        path,
        status,
        "denied",
        PreAuthAuditFields {
            credential_configuration_id: credential_configuration_id
                .and_then(|id| registry_notary_core::ConfigMetadata::new(id).ok()),
            denial_code: Some(denial_code),
            ..PreAuthAuditFields::default()
        },
    );
    if preauth.emit_audit(&audit).await.is_err() {
        return oid4vci_error_response(Oid4vciWireError::ServerError);
    }
    response
}

pub(in crate::api) async fn preauth_server_error(
    preauth: &PreAuthRuntime,
    path: &str,
    method: &str,
    credential_configuration_id: &str,
) -> Response {
    let audit = pre_auth_audit_event(
        method,
        path,
        StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
        "denied",
        PreAuthAuditFields {
            credential_configuration_id: registry_notary_core::ConfigMetadata::new(
                credential_configuration_id,
            )
            .ok(),
            ..PreAuthAuditFields::default()
        },
    );
    let _ = preauth.emit_audit(&audit).await;
    oid4vci_error_response(Oid4vciWireError::ServerError)
}

/// Count an invalid token-endpoint attempt against the client address, emit a
/// denial audit event, and return the OAuth error. The rate counter for the
/// flood guard is consumed here so repeated random codes are throttled.
pub(in crate::api) async fn token_error_after_invalid_attempt(
    state: &RegistryNotaryApiState,
    preauth: &PreAuthRuntime,
    path: &str,
    client_address: &str,
    credential_configuration_id: Option<&str>,
    error: TokenWireError,
) -> Response {
    if let Ok(hashed) = state
        .self_attestation_rate_keys
        .client_address(client_address)
    {
        let _ = state
            .self_attestation_rate_limiter
            .check_invalid_token_for_client_address(&hashed)
            .await;
    }
    token_error_with_audit(
        preauth,
        path,
        credential_configuration_id,
        SelfAttestationDenialCode::InvalidToken,
        error,
    )
    .await
}

pub(in crate::api) async fn token_error_with_audit(
    preauth: &PreAuthRuntime,
    path: &str,
    credential_configuration_id: Option<&str>,
    denial_code: SelfAttestationDenialCode,
    error: TokenWireError,
) -> Response {
    let response = token_error_response(error);
    let audit = token_error_audit_event(
        path,
        response.status().as_u16(),
        credential_configuration_id,
        denial_code,
    );
    if preauth.emit_audit(&audit).await.is_err() {
        return token_error_after_audit_result(response, true);
    }
    token_error_after_audit_result(response, false)
}

pub(in crate::api) fn token_error_after_audit_result(
    response: Response,
    audit_failed: bool,
) -> Response {
    if audit_failed {
        token_error_response(TokenWireError::ServerError)
    } else {
        response
    }
}

pub(in crate::api) fn token_error_audit_event(
    path: &str,
    status: u16,
    credential_configuration_id: Option<&str>,
    denial_code: SelfAttestationDenialCode,
) -> EvidenceAuditEvent {
    pre_auth_audit_event(
        "POST",
        path,
        status,
        "denied",
        PreAuthAuditFields {
            credential_configuration_id: credential_configuration_id
                .and_then(|id| registry_notary_core::ConfigMetadata::new(id).ok()),
            denial_code: Some(denial_code),
            ..PreAuthAuditFields::default()
        },
    )
}

/// Parse a `TokenRequest` from a form-encoded or JSON body. A missing/other
/// grant or unparseable body is returned as a clean `invalid_request`, never a
/// deserialize panic.
pub(in crate::api) fn parse_token_request(
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<Oid4vciTokenRequest, TokenWireError> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if content_type.contains("application/json") {
        serde_json::from_slice(body).map_err(|_| TokenWireError::InvalidRequest)
    } else {
        // Default to form encoding (the OID4VCI / OAuth content type).
        parse_token_form(body)
    }
}

/// Parse an `application/x-www-form-urlencoded` token request body. Only the
/// three pre-authorized-code grant fields are recognized; a missing
/// `grant_type` is `invalid_request`.
pub(in crate::api) fn parse_token_form(
    body: &Bytes,
) -> Result<Oid4vciTokenRequest, TokenWireError> {
    let raw = std::str::from_utf8(body).map_err(|_| TokenWireError::InvalidRequest)?;
    let mut grant_type = None;
    let mut pre_authorized_code = None;
    let mut tx_code = None;
    for pair in raw.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = form_urldecode(key)?;
        let value = form_urldecode(value)?;
        match key.as_str() {
            "grant_type" => grant_type = Some(value),
            "pre-authorized_code" => pre_authorized_code = Some(value),
            "tx_code" => tx_code = Some(value),
            _ => {}
        }
    }
    Ok(Oid4vciTokenRequest {
        grant_type: grant_type.ok_or(TokenWireError::InvalidRequest)?,
        pre_authorized_code,
        tx_code,
    })
}

/// Decode one `application/x-www-form-urlencoded` component (`+` to space,
/// `%XX` to byte). Rejects malformed percent escapes.
pub(in crate::api) fn form_urldecode(value: &str) -> Result<String, TokenWireError> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' => {
                let hi = bytes
                    .get(index + 1)
                    .copied()
                    .ok_or(TokenWireError::InvalidRequest)?;
                let lo = bytes
                    .get(index + 2)
                    .copied()
                    .ok_or(TokenWireError::InvalidRequest)?;
                let byte = hex_nibble(hi)? * 16 + hex_nibble(lo)?;
                out.push(byte);
                index += 3;
            }
            other => {
                out.push(other);
                index += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| TokenWireError::InvalidRequest)
}

pub(in crate::api) fn hex_nibble(byte: u8) -> Result<u8, TokenWireError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(TokenWireError::InvalidRequest),
    }
}
