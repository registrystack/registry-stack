use super::*;

pub(in super::super) async fn auth_audit_middleware(
    State(state): State<Arc<AuthAuditState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let method = request.method().to_string();
    let path = audit_path(&request);
    let correlation_id = new_request_correlation_id();
    if is_auth_exempt_path(&path, state.auth_exemption_policy()) {
        request.extensions_mut().insert(correlation_id.clone());
        return with_request_correlation_id(correlation_id, next.run(request)).await;
    }
    let credentials = request_credentials(&request);
    let client_address = client_address_identifier(&request);
    if let Err(rate_error) =
        maybe_rate_limit_auth_rejection_before_auth(&state, &credentials, client_address.as_str())
    {
        let mut response = crate::api::evidence_error_response_with_request_id(
            rate_error.evidence_error(),
            Some(&correlation_id),
        );
        response.extensions_mut().insert(EvidenceAuditContext {
            verification_id: None,
            verification_decision: Some("auth_rate_limited".to_string()),
            claim_hash: None,
            purposes: None,
            row_count: None,
            access_mode: Some(AccessMode::Unknown),
            denial_code: Some(SelfAttestationDenialCode::RateLimited),
            token_claim_name: None,
            credential_profile: None,
            protocol: None,
            credential_configuration_id: None,
            holder_binding_mode: None,
            rate_limit_bucket: rate_error
                .bucket()
                .and_then(|bucket| RateLimitBucket::new(bucket.as_str()).ok()),
            policy_hash: None,
            target_type: None,
            target_ref_hash: None,
            requester_type: None,
            requester_ref_hash: None,
            redacted_fields: None,
            batch_items: None,
            ..EvidenceAuditContext::default()
        });
        let audit_event = build_audit_event(
            None,
            &state.audit.profile.key_hasher(),
            &method,
            &path,
            correlation_id.clone(),
            &response,
        );
        return emit_audit_or_error(&state, audit_event, response).await;
    }
    let principal = match state.authenticate(credentials.clone()).await {
        Ok(principal) => principal,
        Err(error) => {
            if let Err(rate_error) =
                consume_auth_rejection_after_auth_failure(&state, client_address.as_str())
            {
                let mut response = crate::api::evidence_error_response_with_request_id(
                    rate_error.evidence_error(),
                    Some(&correlation_id),
                );
                response.extensions_mut().insert(EvidenceAuditContext {
                    verification_id: None,
                    verification_decision: Some("auth_rate_limited".to_string()),
                    claim_hash: None,
                    purposes: None,
                    row_count: None,
                    access_mode: Some(AccessMode::Unknown),
                    denial_code: Some(SelfAttestationDenialCode::RateLimited),
                    token_claim_name: None,
                    credential_profile: None,
                    protocol: None,
                    credential_configuration_id: None,
                    holder_binding_mode: None,
                    rate_limit_bucket: rate_error
                        .bucket()
                        .and_then(|bucket| RateLimitBucket::new(bucket.as_str()).ok()),
                    policy_hash: None,
                    target_type: None,
                    target_ref_hash: None,
                    requester_type: None,
                    requester_ref_hash: None,
                    batch_items: None,
                    ..EvidenceAuditContext::default()
                });
                let audit_event = build_audit_event(
                    None,
                    &state.audit.profile.key_hasher(),
                    &method,
                    &path,
                    correlation_id.clone(),
                    &response,
                );
                return emit_audit_or_error(&state, audit_event, response).await;
            }
            let response =
                crate::api::evidence_error_response_with_request_id(error, Some(&correlation_id));
            let audit_event = build_audit_event(
                None,
                &state.audit.profile.key_hasher(),
                &method,
                &path,
                correlation_id.clone(),
                &response,
            );
            return emit_audit_or_error(&state, audit_event, response).await;
        }
    };
    request.extensions_mut().insert(principal.clone());
    request.extensions_mut().insert(correlation_id.clone());
    let response = with_request_correlation_id(correlation_id.clone(), next.run(request)).await;
    let audit_event = build_audit_event(
        Some(&principal),
        &state.audit.profile.key_hasher(),
        &method,
        &path,
        correlation_id,
        &response,
    );
    emit_audit_or_error(&state, audit_event, response).await
}

pub(in super::super) async fn emit_audit_or_error(
    state: &AuthAuditState,
    audit_event: EvidenceAuditEvent,
    response: Response,
) -> Response {
    match state.audit.emit(&audit_event).await {
        Ok(()) => {
            state.metrics.record_audit_event("success");
            response
        }
        Err(error) => {
            state.metrics.record_audit_event("failure");
            if response.status() == StatusCode::SERVICE_UNAVAILABLE
                && response
                    .extensions()
                    .get::<EvidenceErrorCodeContext>()
                    .is_some_and(|context| context.0 == "audit.write_failed")
            {
                tracing::error!(
                    target: "registry_notary_server::audit",
                    error = %error,
                    "audit event write failed while preserving prior audit failure response"
                );
                return response;
            }
            audit_error_response(error)
        }
    }
}

pub(in super::super) fn audit_path(request: &Request) -> String {
    request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_string())
        .unwrap_or_else(|| request.uri().path().to_string())
}

pub(in super::super) fn client_address_identifier(request: &Request) -> String {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip().to_string())
        .unwrap_or_else(|| "unknown-client-address".to_string())
}

pub(in super::super) fn maybe_rate_limit_auth_rejection_before_auth(
    state: &AuthAuditState,
    credentials: &RequestCredentials,
    client_address: &str,
) -> Result<(), crate::SelfAttestationRateLimitError> {
    if credentials.bearer_token.is_none() && !credentials.are_absent() {
        return Ok(());
    }
    let (Some(limiter), Some(keys)) = (
        state.self_attestation_invalid_token_limiter.as_ref(),
        state.self_attestation_rate_keys.as_ref(),
    ) else {
        return Ok(());
    };
    let client_address = keys.client_address(client_address)?;
    limiter.check_invalid_token_for_client_address_available(&client_address)
}

pub(in super::super) fn consume_auth_rejection_after_auth_failure(
    state: &AuthAuditState,
    client_address: &str,
) -> Result<(), crate::SelfAttestationRateLimitError> {
    let (Some(limiter), Some(keys)) = (
        state.self_attestation_invalid_token_limiter.as_ref(),
        state.self_attestation_rate_keys.as_ref(),
    ) else {
        return Ok(());
    };
    let client_address = keys.client_address(client_address)?;
    limiter.check_invalid_token_for_client_address(&client_address)
}

#[derive(Debug, Clone, Copy)]
pub(in super::super) struct AuthExemptionPolicy {
    pub(in super::super) openapi_requires_auth: bool,
}

impl AuthAuditState {
    fn auth_exemption_policy(&self) -> AuthExemptionPolicy {
        AuthExemptionPolicy {
            openapi_requires_auth: self.openapi_requires_auth(),
        }
    }
}

pub(in super::super) fn is_auth_exempt_path(path: &str, policy: AuthExemptionPolicy) -> bool {
    matches!(
        path,
        "/healthz"
            | "/ready"
            | "/.well-known/evidence/jwks.json"
            | "/.well-known/openid-credential-issuer"
            | "/oid4vci/credential-offer"
            | "/oid4vci/offer/start"
            | "/oid4vci/offer/callback"
            | "/oid4vci/token"
            | "/oid4vci/nonce"
            // Auth-exempt only from API-key/OIDC middleware. The federation
            // handler still requires and verifies the peer-signed JWS.
            | "/federation/v1/evaluations"
            | "/docs"
            | "/docs/scalar.js"
            | "/credentials/{*vct_path}"
            | "/v1/credentials/{credential_id}/status"
    ) || (!policy.openapi_requires_auth && path == "/openapi.json")
        || path.starts_with("/.well-known/vct/")
}

pub(in super::super) async fn admin_metrics_handler(
    State(metrics): State<Arc<AppMetrics>>,
    principal: Option<axum::Extension<EvidencePrincipal>>,
) -> Response {
    let Some(axum::Extension(principal)) = principal else {
        return crate::api::evidence_error_response(EvidenceError::MissingCredential);
    };
    if !principal.has_scope(METRICS_SCOPE) {
        return crate::api::evidence_error_response(EvidenceError::ScopeDenied {
            required: METRICS_SCOPE.to_string(),
        });
    }
    metrics_handler(State(metrics)).await
}

pub(in super::super) fn build_audit_event(
    principal: Option<&EvidencePrincipal>,
    hasher: &AuditKeyHasher,
    method: &str,
    path: &str,
    correlation_id: BoundedCorrelationId,
    response: &Response,
) -> EvidenceAuditEvent {
    let audit = response.extensions().get::<EvidenceAuditContext>();
    let error = response.extensions().get::<EvidenceErrorCodeContext>();
    let verification_id = audit.and_then(|context| context.verification_id.clone());
    let claim_hash = audit.and_then(|context| context.claim_hash.clone());
    let purposes = audit.and_then(|context| context.purposes.clone());
    let row_count = audit.and_then(|context| context.row_count);
    let relay_consultation_count = audit.and_then(|context| context.relay_consultation_count);
    let relay_consultation_ids = audit
        .map(|context| context.relay_consultation_ids.clone())
        .unwrap_or_default();
    let forwarded = audit.and_then(|context| context.forwarded);
    let access_mode = audit
        .and_then(|context| context.access_mode)
        .or_else(|| principal.map(EvidencePrincipal::access_mode));
    let denial_code = audit.and_then(|context| context.denial_code);
    let token_claim_name = audit.and_then(|context| context.token_claim_name.clone());
    let credential_profile = audit.and_then(|context| context.credential_profile.clone());
    let protocol = audit.and_then(|context| context.protocol.clone());
    let credential_configuration_id =
        audit.and_then(|context| context.credential_configuration_id.clone());
    let holder_binding_mode = audit.and_then(|context| context.holder_binding_mode.clone());
    let rate_limit_bucket = audit.and_then(|context| context.rate_limit_bucket.clone());
    let policy_hash = audit.and_then(|context| context.policy_hash.clone());
    let target_type = audit.and_then(|context| context.target_type.clone());
    let target_ref_hash = audit.and_then(|context| context.target_ref_hash.clone());
    let requester_type = audit.and_then(|context| context.requester_type.clone());
    let requester_ref_hash = audit.and_then(|context| context.requester_ref_hash.clone());
    let redacted_fields = audit.and_then(|context| context.redacted_fields.clone());
    let batch_items = audit.and_then(|context| context.batch_items.clone());
    let config = audit.and_then(|context| context.config.clone());
    let error_code = error.map(|context| context.0.clone());
    let decision = audit
        .and_then(|context| context.verification_decision.clone())
        .unwrap_or_else(|| {
            if response.status().is_success() {
                "allowed".to_string()
            } else {
                "denied".to_string()
            }
        });
    let occurred_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
    EvidenceAuditEvent {
        event_id: Ulid::new().to_string(),
        occurred_at,
        principal_id_hash: principal.map(|principal| {
            Hashed::<PrincipalIdentifier>::from_hash(hasher.hash(&principal.principal_id))
        }),
        scopes_used: principal.map_or_else(Vec::new, |principal| principal.scopes.clone()),
        decision,
        method: method.to_string(),
        path: path.to_string(),
        status: response.status().as_u16(),
        verification_id,
        claim_hash,
        purposes,
        row_count,
        relay_consultation_count,
        relay_consultation_ids,
        forwarded,
        error_code,
        access_mode,
        federation_peer_id_hash: None,
        federation_issuer: None,
        federation_profile: None,
        federation_purpose: None,
        federation_request_jti_hash: None,
        federation_subject_ref_hash: None,
        denial_code,
        token_claim_name,
        correlation_id_hash: Some(Hashed::<RequestIdentifier>::from_hash(
            hasher.hash(correlation_id.as_str()),
        )),
        credential_profile,
        protocol,
        credential_configuration_id,
        holder_binding_mode,
        rate_limit_bucket,
        policy_version: None,
        policy_hash,
        target_type,
        target_ref_hash,
        requester_type,
        requester_ref_hash,
        redacted_fields,
        batch_items,
        config,
    }
}
