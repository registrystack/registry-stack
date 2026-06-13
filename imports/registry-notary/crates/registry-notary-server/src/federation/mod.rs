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
    AccessMode, ClaimRef, EvaluateRequest, EvidenceEntity, EvidencePrincipal, SourceCapability,
    FEDERATION_REQUEST_JWT_TYP, FORMAT_CLAIM_RESULT_JSON,
};
use registry_platform_crypto::pairwise_subject_ref_hash;
use registry_platform_replay::{ReplayKey, ReplayScope, RequiredReplayError};
use time::OffsetDateTime;

use crate::{api::RegistryNotaryApiState, replay::require_replay_insert};

use audit::{federation_audit_event, FederationAuditOutcome};
use claims::{
    decode_unverified_jwt_payload, request_subject, source_observation_is_stale, string_claim,
    string_extra, validate_federation_claims,
};
use errors::{apply_denial_latency, federation_problem_response, FederationProblem};
pub(crate) use runtime::FederationRuntimeState;
use signing::FederationSignedOutcome;

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
    let (mut response, audit) = match outcome {
        Ok(outcome) => outcome.into_response(&runtime.response_signer).await,
        Err(problem) => {
            apply_denial_latency(
                started,
                state.federation.response_shaping.minimum_denial_latency_ms,
            )
            .await;
            let audit = FederationAuditOutcome::denied(&problem);
            (federation_problem_response(problem), audit)
        }
    };
    if let Some(audit_pipeline) = runtime.audit.as_ref() {
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
) -> Result<FederationSignedOutcome, FederationProblem> {
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
        ));
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
        return Err(FederationProblem::invalid_request(
            "request body must be a compact JWS",
        ));
    }
    let header = decode_header(token).map_err(|_| FederationProblem::invalid_token())?;
    if header.alg != Algorithm::EdDSA {
        return Err(FederationProblem::invalid_token());
    }
    if header.typ.as_deref() != Some(FEDERATION_REQUEST_JWT_TYP) {
        return Err(FederationProblem::invalid_token());
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
        return Err(FederationProblem::forbidden("signing key is denied"));
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
        return Err(FederationProblem::forbidden("peer node is denied"));
    }
    let verified = peer
        .verifier
        .verify(token)
        .await
        .map_err(|_| FederationProblem::invalid_token())?;
    validate_federation_claims(&state.federation, &peer.config, &verified)?;
    let request_jti = string_extra(&verified, "jti")
        .ok_or_else(FederationProblem::invalid_token)?
        .to_string();
    let exp = verified
        .claims
        .exp
        .ok_or_else(FederationProblem::invalid_token)?;
    let protocol = string_extra(&verified, "protocol")
        .ok_or_else(FederationProblem::invalid_request_owned)?
        .to_string();
    let profile_id = string_extra(&verified, "profile")
        .ok_or_else(FederationProblem::invalid_request_owned)?
        .to_string();
    let purpose = string_extra(&verified, "purpose")
        .ok_or_else(FederationProblem::invalid_request_owned)?
        .to_string();
    let replay_scope = ReplayScope::federation_request_jwt(
        &state.federation.node_id,
        &peer.config.issuer,
        &state.federation.node_id,
        &profile_id,
    )
    .map_err(|_| FederationProblem::invalid_token())?;
    let replay_key =
        ReplayKey::new(request_jti.as_str()).map_err(|_| FederationProblem::invalid_token())?;
    let replay_expires_at = OffsetDateTime::from_unix_timestamp(
        exp.saturating_add(state.federation.clock_leeway_seconds as i64),
    )
    .map_err(|_| FederationProblem::invalid_token())?;
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
            return Err(FederationProblem::new(
                StatusCode::CONFLICT,
                "replay",
                "Federation request replay detected",
                "federation.replay",
            ));
        }
        Err(RequiredReplayError::Store { .. }) => {
            runtime.metrics.record_replay("federation_request", "error");
            return Err(FederationProblem::server_error(
                "required replay protection failed",
            ));
        }
        Err(_) => {
            runtime.metrics.record_replay("federation_request", "error");
            return Err(FederationProblem::server_error(
                "required replay protection failed",
            ));
        }
    }
    let profile = state
        .federation
        .evaluation_profiles
        .iter()
        .find(|candidate| candidate.id == profile_id)
        .ok_or_else(|| FederationProblem::forbidden("profile is not allowed"))?;
    let subject = request_subject(&verified, profile)?;
    let principal = EvidencePrincipal {
        principal_id: peer.config.node_id.clone(),
        scopes: peer.config.source_scopes.clone(),
        access_mode: AccessMode::MachineClient,
        verified_claims: None,
        authorization_details: None,
    };
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
    .map_err(|_| FederationProblem::server_error("failed to hash subject reference"))?;
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
        .map_err(FederationProblem::from_evidence_error)?;
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
