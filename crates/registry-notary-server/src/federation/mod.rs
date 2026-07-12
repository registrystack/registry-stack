// SPDX-License-Identifier: Apache-2.0
//! Federated Registry Notary delegated evaluation routes.

mod audit;
mod claims;
mod errors;
mod runtime;
mod signing;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Instant;

use axum::body::{to_bytes, Body};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Router};
use jsonwebtoken::{decode_header, Algorithm};
use registry_notary_core::{
    AccessMode, ClaimRef, EvaluateRequest, EvidenceAuthProfileId, EvidenceAuthorizationDetails,
    EvidenceEntity, EvidencePrincipal, FederationEvaluationProfileConfig, SourceCapability,
    FEDERATION_REQUEST_JWT_TYP, FORMAT_CLAIM_RESULT_JSON,
};
use registry_platform_crypto::pairwise_subject_ref_hash;
use registry_platform_oidc::VerifiedToken;
use registry_platform_replay::{ReplayKey, ReplayScope, RequiredReplayError};
use time::OffsetDateTime;

use crate::{api::RegistryNotaryApiState, replay::require_replay_insert};

use audit::{federation_audit_event, FederationAuditContext, FederationDeniedOutcome};
use claims::{
    decode_unverified_jwt_payload, request_subject, request_subject_identifier,
    source_observation_is_stale, string_claim, string_extra, validate_federation_claims,
};
use errors::{apply_denial_latency, federation_problem_response, FederationProblem};
pub(crate) use runtime::FederationRuntimeState;
use signing::{FederationResponseSigner, FederationSignedOutcome};

pub fn federation_router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new().route("/federation/v1/evaluations", post(federated_evaluate))
}

async fn federated_evaluate(
    headers: HeaderMap,
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    body: Body,
) -> Response {
    let started = Instant::now();
    let Some(Extension(state)) = state else {
        return federation_problem_response(FederationProblem::server_disabled());
    };
    let Some(runtime) = state.federation_runtime() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let outcome =
        handle_federated_evaluate(&headers, Arc::clone(&state), Arc::clone(&runtime), body).await;
    finalize_federated_evaluate(
        outcome,
        started,
        state.federation.response_shaping.minimum_denial_latency_ms,
        &runtime.response_signer,
        runtime.audit.as_ref(),
    )
    .await
}

async fn finalize_federated_evaluate(
    outcome: Result<FederationSignedOutcome, FederationDeniedOutcome>,
    started: Instant,
    minimum_denial_latency_ms: u64,
    response_signer: &FederationResponseSigner,
    audit_pipeline: Option<&crate::standalone::AuditPipeline>,
) -> Response {
    let (mut response, audit) = match outcome {
        Ok(outcome) => outcome.into_response(response_signer).await,
        Err(denied) => {
            apply_denial_latency(started, minimum_denial_latency_ms).await;
            (federation_problem_response(denied.problem), denied.audit)
        }
    };
    if let Some(audit_pipeline) = audit_pipeline {
        let event = federation_audit_event(&response, audit, Some(audit_pipeline));
        if let Err(error) = audit_pipeline.emit(&event).await {
            response = crate::standalone::audit_error_response(error);
        }
    }
    response
}

async fn handle_federated_evaluate(
    headers: &HeaderMap,
    state: Arc<RegistryNotaryApiState>,
    runtime: Arc<FederationRuntimeState>,
    body: Body,
) -> Result<FederationSignedOutcome, FederationDeniedOutcome> {
    state
        .enabled_evidence()
        .map_err(|_| FederationProblem::server_disabled())?;
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or_default().trim())
        != Some("application/jwt")
    {
        return Err(FederationProblem::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-media-type",
            "Federation request content type must be application/jwt",
            "federation.unsupported_media_type",
        )
        .into());
    }
    let body = to_bytes(body, state.federation.inbound_body_limit_bytes)
        .await
        .map_err(|_| {
            FederationProblem::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload-too-large",
                "Federation request is too large",
                "federation.payload_too_large",
            )
        })?;
    let token = std::str::from_utf8(&body)
        .map(str::trim)
        .map_err(|_| FederationProblem::invalid_request("request body must be a compact JWS"))?;
    if token.split('.').count() != 3 {
        return Err(
            FederationProblem::invalid_request("request body must be a compact JWS").into(),
        );
    }
    let header = decode_header(token).map_err(|_| FederationProblem::invalid_token())?;
    if header.alg != Algorithm::EdDSA {
        return Err(FederationProblem::invalid_token().into());
    }
    if header.typ.as_deref() != Some(FEDERATION_REQUEST_JWT_TYP) {
        return Err(FederationProblem::invalid_token().into());
    }
    let kid = header
        .kid
        .as_deref()
        .ok_or_else(FederationProblem::invalid_token)?;
    if state
        .federation
        .emergency_denylist
        .kids
        .iter()
        .any(|denied| denied == kid)
    {
        return Err(FederationProblem::forbidden("signing key is denied").into());
    }
    let unverified = decode_unverified_jwt_payload(token)?;
    let issuer = string_claim(&unverified, "iss")
        .ok_or_else(FederationProblem::invalid_token)?
        .to_string();
    let peer = runtime
        .peers_by_issuer
        .get(&issuer)
        .ok_or_else(FederationProblem::invalid_token)?;
    if state
        .federation
        .emergency_denylist
        .node_ids
        .iter()
        .any(|denied| denied == &peer.config.node_id)
    {
        return Err(FederationProblem::forbidden("peer node is denied").into());
    }
    let verified = peer
        .verifier
        .verify(token)
        .await
        .map_err(|_| FederationProblem::invalid_token())?;
    let mut audit_context =
        verified_federation_audit_context(&state, &runtime, &peer.config, &verified)
            .map_err(|denied| *denied)?;
    validate_federation_claims(&state.federation, &peer.config, &verified)
        .map_err(|problem| audit_context.denied(problem))?;
    let request_jti = string_extra(&verified, "jti")
        .ok_or_else(|| audit_context.denied(FederationProblem::invalid_token()))?
        .to_string();
    let exp = verified
        .claims
        .exp
        .ok_or_else(|| audit_context.denied(FederationProblem::invalid_token()))?;
    let protocol = string_extra(&verified, "protocol")
        .ok_or_else(|| audit_context.denied(FederationProblem::invalid_request_owned()))?
        .to_string();
    let profile_id = string_extra(&verified, "profile")
        .ok_or_else(|| audit_context.denied(FederationProblem::invalid_request_owned()))?
        .to_string();
    let purpose = string_extra(&verified, "purpose")
        .ok_or_else(|| audit_context.denied(FederationProblem::invalid_request_owned()))?
        .to_string();
    let replay_scope = ReplayScope::federation_request_jwt(
        &state.federation.node_id,
        &peer.config.issuer,
        &state.federation.node_id,
        &profile_id,
    )
    .map_err(|_| audit_context.denied(FederationProblem::invalid_token()))?;
    let replay_key = ReplayKey::new(request_jti.as_str())
        .map_err(|_| audit_context.denied(FederationProblem::invalid_token()))?;
    let replay_expires_at = OffsetDateTime::from_unix_timestamp(
        exp.saturating_add(state.federation.clock_leeway_seconds as i64),
    )
    .map_err(|_| audit_context.denied(FederationProblem::invalid_token()))?;
    match require_replay_insert(
        runtime.replay.as_ref(),
        &replay_scope,
        &replay_key,
        replay_expires_at,
    )
    .await
    {
        Ok(()) => runtime
            .metrics
            .record_replay("federation_request", "accepted"),
        Err(RequiredReplayError::AlreadySeen) => {
            runtime
                .metrics
                .record_replay("federation_request", "replayed");
            return Err(audit_context.denied(FederationProblem::new(
                StatusCode::CONFLICT,
                "replay",
                "Federation request replay detected",
                "federation.replay",
            )));
        }
        Err(RequiredReplayError::Store { .. }) => {
            runtime.metrics.record_replay("federation_request", "error");
            return Err(audit_context.denied(FederationProblem::server_error(
                "required replay protection failed",
            )));
        }
        Err(_) => {
            runtime.metrics.record_replay("federation_request", "error");
            return Err(audit_context.denied(FederationProblem::server_error(
                "required replay protection failed",
            )));
        }
    }
    let profile = state
        .federation
        .evaluation_profiles
        .iter()
        .find(|candidate| candidate.id == profile_id)
        .ok_or_else(|| {
            audit_context.denied(FederationProblem::forbidden("profile is not allowed"))
        })?;
    audit_context.claim_ids = vec![profile.claim_id.clone()];
    let subject =
        request_subject(&verified, profile).map_err(|problem| audit_context.denied(problem))?;
    let principal = federation_principal(&peer.config, profile);
    let source_capability = SourceCapability::Machine {
        scopes: peer
            .config
            .source_scopes
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>(),
    };
    let request = EvaluateRequest {
        requester: None,
        target: Some(EvidenceEntity::from_subject_request(
            "Person",
            subject.clone(),
        )),
        relationship: None,
        on_behalf_of: None,
        variables: Default::default(),
        claims: vec![ClaimRef::from(profile.claim_id.clone())],
        disclosure: Some(
            profile
                .disclosure
                .clone()
                .unwrap_or_else(|| "redacted".to_string()),
        ),
        format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
        purpose: Some(purpose.clone()),
    };
    let subject_hash = pairwise_subject_ref_hash(
        runtime.pairwise_subject_hash_secret.as_slice(),
        &peer.config.node_id,
        &state.federation.node_id,
        &profile.id,
        subject.id_type.as_deref().unwrap_or(""),
        &subject.id,
    )
    .map_err(|_| {
        audit_context.denied(FederationProblem::server_error(
            "failed to hash subject reference",
        ))
    })?;
    audit_context.subject_ref_hash = Some(subject_hash.clone());
    let runtime_eval = state.runtime();
    let results = runtime_eval
        .evaluate_with_source_capability(
            Arc::clone(&state.evidence),
            Arc::clone(&state.source),
            &state.store,
            &principal,
            source_capability,
            request,
            None,
            None,
            None,
        )
        .await
        .map_err(|error| audit_context.denied(FederationProblem::from_evidence_error(error)))?;
    if source_observation_is_stale(profile, &results) {
        return Ok(FederationSignedOutcome::evaluation_error(
            &state.federation,
            &peer.config,
            &protocol,
            profile,
            &purpose,
            &request_jti,
            subject_hash,
            "urn:registry-notary:problem:federation:stale-source-observation",
            "Source observation is stale",
        ));
    }
    Ok(FederationSignedOutcome::success(
        &state.federation,
        &peer.config,
        &protocol,
        profile,
        &purpose,
        &request_jti,
        subject.id_type.as_deref().unwrap_or(""),
        subject_hash,
        &results,
    ))
}

fn verified_federation_audit_context(
    state: &RegistryNotaryApiState,
    runtime: &FederationRuntimeState,
    peer: &registry_notary_core::FederationPeerConfig,
    verified: &VerifiedToken,
) -> Result<FederationAuditContext, Box<FederationDeniedOutcome>> {
    let mut context = FederationAuditContext::from_verified(peer, verified);
    let Some(profile_id) = context.profile.as_deref() else {
        return Ok(context);
    };
    if !peer
        .allowed_profiles
        .iter()
        .any(|allowed| allowed == profile_id)
    {
        return Ok(context);
    }
    let Some(profile) = state
        .federation
        .evaluation_profiles
        .iter()
        .find(|candidate| candidate.id == profile_id)
    else {
        return Ok(context);
    };
    context.claim_ids = vec![profile.claim_id.clone()];
    let Ok(subject) = request_subject_identifier(verified, profile) else {
        return Ok(context);
    };
    let subject_hash = pairwise_subject_ref_hash(
        runtime.pairwise_subject_hash_secret.as_slice(),
        &peer.node_id,
        &state.federation.node_id,
        &profile.id,
        subject.id_type.as_deref().unwrap_or(""),
        &subject.id,
    )
    .map_err(|_| {
        Box::new(context.denied(FederationProblem::server_error(
            "failed to hash subject reference",
        )))
    })?;
    context.subject_ref_hash = Some(subject_hash);
    Ok(context)
}

fn federation_authorization_details(
    profile: &FederationEvaluationProfileConfig,
) -> Option<EvidenceAuthorizationDetails> {
    if profile.legal_basis_ref.is_none()
        && profile.consent_ref.is_none()
        && profile.jurisdiction.is_none()
        && profile.assurance_level.is_none()
    {
        return None;
    }
    Some(EvidenceAuthorizationDetails {
        detail_type: "registry-notary/evidence-authorization/v1".to_string(),
        schema_version: "v1".to_string(),
        legal_basis_ref: profile.legal_basis_ref.clone(),
        consent_ref: profile.consent_ref.clone(),
        jurisdiction: profile.jurisdiction.clone(),
        assurance_level: profile.assurance_level.clone(),
        ..EvidenceAuthorizationDetails::default()
    })
}

fn federation_principal(
    peer: &registry_notary_core::FederationPeerConfig,
    profile: &FederationEvaluationProfileConfig,
) -> EvidencePrincipal {
    EvidencePrincipal {
        auth_profile_id: EvidenceAuthProfileId::Federation,
        principal_id: peer.node_id.clone(),
        scopes: peer.source_scopes.clone(),
        access_mode: AccessMode::MachineClient,
        verified_claims: None,
        authorization_details: federation_authorization_details(profile),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::http::HeaderValue;
    use registry_notary_core::{FederationConfig, FederationPeerConfig, FEDERATION_PROTOCOL_V0_1};
    use registry_platform_audit::{
        AuditChainHasher, AuditEnvelope, AuditError, AuditSink as PlatformAuditSink,
    };
    use registry_platform_crypto::{
        PrivateJwk, PublicJwk, SigningAlgorithm, SigningError, SigningProvider,
    };
    use registry_platform_testing::fixtures;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Mutex;

    use crate::standalone::AuditPipeline;

    #[derive(Default)]
    struct MemoryAuditSink {
        envelopes: Mutex<Vec<AuditEnvelope>>,
    }

    #[async_trait]
    impl PlatformAuditSink for MemoryAuditSink {
        async fn write(&self, envelope: &AuditEnvelope) -> Result<(), AuditError> {
            self.envelopes.lock().await.push(envelope.clone());
            Ok(())
        }

        async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
            Ok(self
                .envelopes
                .lock()
                .await
                .last()
                .map(|envelope| envelope.record_hash))
        }

        async fn tail_hash_with_hasher(
            &self,
            _hasher: &AuditChainHasher,
        ) -> Result<Option<[u8; 32]>, AuditError> {
            Ok(self
                .envelopes
                .lock()
                .await
                .last()
                .map(|envelope| envelope.record_hash))
        }
    }

    struct FailingSigningProvider {
        attempts: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl SigningProvider for FailingSigningProvider {
        fn algorithm(&self) -> SigningAlgorithm {
            SigningAlgorithm::EdDsa
        }

        fn key_id(&self) -> &str {
            "registry-platform-testing-ed25519-1"
        }

        fn public_jwk(&self) -> PublicJwk {
            PrivateJwk::parse(fixtures::ED25519_PRIVATE_JWK)
                .expect("fixture private JWK parses")
                .public()
        }

        async fn sign(&self, _payload: &[u8]) -> Result<Vec<u8>, SigningError> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            Err(SigningError::external("forced federation signing failure"))
        }
    }

    #[tokio::test]
    async fn federation_response_signing_failure_emits_denial_audit_with_context() {
        let federation = FederationConfig {
            node_id: "did:web:agency-a.example.gov".to_string(),
            issuer: "https://agency-a.example.gov".to_string(),
            ..FederationConfig::default()
        };
        let peer = FederationPeerConfig {
            node_id: "did:web:agency-b.example.gov".to_string(),
            issuer: "https://agency-b.example.gov".to_string(),
            source_scopes: vec!["farmer_registry:evidence_verification".to_string()],
            ..FederationPeerConfig::default()
        };
        let profile = FederationEvaluationProfileConfig {
            id: "farmer_under_4ha".to_string(),
            claim_id: "farmer-under-4ha".to_string(),
            ..FederationEvaluationProfileConfig::default()
        };
        let request_jti = "01J9Z6Q6Q6Q6Q6Q6Q6Q6Q6Q6Q6";
        let outcome = FederationSignedOutcome::evaluation_error(
            &federation,
            &peer,
            FEDERATION_PROTOCOL_V0_1,
            &profile,
            "https://purpose.example.test/eligibility",
            request_jti,
            "hmac-sha256:subject".to_string(),
            "urn:registry-notary:problem:federation:stale-source-observation",
            "Source observation is stale",
        );
        let attempts = Arc::new(AtomicUsize::new(0));
        let signer = FederationResponseSigner {
            provider: Arc::new(FailingSigningProvider {
                attempts: Arc::clone(&attempts),
            }),
        };
        let sink = Arc::new(MemoryAuditSink::default());
        let audit_pipeline = AuditPipeline::for_sink_dev_only(sink.clone());

        let response = finalize_federated_evaluate(
            Ok(outcome),
            Instant::now(),
            0,
            &signer,
            Some(&audit_pipeline),
        )
        .await;

        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&HeaderValue::from_static("application/problem+json"))
        );
        let envelopes = sink.envelopes.lock().await;
        assert_eq!(envelopes.len(), 1);
        let record = &envelopes[0].record;
        assert_eq!(record["decision"], json!("federated_evaluate_denied"));
        assert_eq!(record["status"], json!(500));
        assert_eq!(record["error_code"], json!("federation.server_error"));
        assert!(record["claim_hash"].is_string());
        assert_eq!(
            record["scopes_used"],
            json!(["farmer_registry:evidence_verification"])
        );
        assert!(record["federation_peer_id_hash"].is_string());
        assert_eq!(
            record["federation_issuer"],
            json!("https://agency-b.example.gov")
        );
        assert_eq!(record["federation_profile"], json!("farmer_under_4ha"));
        assert_eq!(
            record["federation_purpose"],
            json!("https://purpose.example.test/eligibility")
        );
        assert!(record["federation_request_jti_hash"].is_string());
        assert_eq!(
            record["federation_subject_ref_hash"],
            json!("hmac-sha256:subject")
        );
        let serialized = serde_json::to_string(record).expect("audit record serializes");
        assert!(!serialized.contains("did:web:agency-b.example.gov"));
        assert!(!serialized.contains(request_jti));
    }

    #[test]
    fn federation_profile_can_supply_trusted_policy_context() {
        let profile = FederationEvaluationProfileConfig {
            id: "beneficiary_active_predicate".to_string(),
            legal_basis_ref: Some("demo:child-support-eligibility".to_string()),
            consent_ref: Some("demo:child-support-consent".to_string()),
            jurisdiction: Some("ZZ".to_string()),
            assurance_level: Some("substantial".to_string()),
            ..FederationEvaluationProfileConfig::default()
        };

        let details = federation_authorization_details(&profile)
            .expect("profile context should produce authorization details");

        assert_eq!(
            details.detail_type,
            "registry-notary/evidence-authorization/v1"
        );
        assert_eq!(details.schema_version, "v1");
        assert_eq!(details.purpose.as_deref(), None);
        assert_eq!(
            details.legal_basis_ref.as_deref(),
            Some("demo:child-support-eligibility")
        );
        assert_eq!(
            details.consent_ref.as_deref(),
            Some("demo:child-support-consent")
        );
        assert_eq!(details.jurisdiction.as_deref(), Some("ZZ"));
        assert_eq!(details.assurance_level.as_deref(), Some("substantial"));
        assert!(!crate::authz_details::has_transaction_scope(&details));
    }

    #[test]
    fn federation_principal_uses_stable_federation_profile() {
        let peer = FederationPeerConfig {
            node_id: "did:web:agency-b.example.gov".to_string(),
            source_scopes: vec!["farmer_registry:evidence_verification".to_string()],
            ..FederationPeerConfig::default()
        };
        let profile = FederationEvaluationProfileConfig::default();

        let principal = federation_principal(&peer, &profile);

        assert_eq!(principal.auth_profile_id, EvidenceAuthProfileId::Federation);
        assert_eq!(principal.principal_id, peer.node_id);
        assert_eq!(principal.scopes, peer.source_scopes);
    }

    #[test]
    fn federation_profile_without_policy_context_uses_peer_scopes_only() {
        let profile = FederationEvaluationProfileConfig::default();

        assert!(federation_authorization_details(&profile).is_none());
    }
}
