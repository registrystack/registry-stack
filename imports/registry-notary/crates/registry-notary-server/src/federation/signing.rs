// SPDX-License-Identifier: Apache-2.0

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use registry_notary_core::{
    FederationConfig, FederationEvaluationProfileConfig, FederationPeerConfig,
    FEDERATION_RESPONSE_JWT_TYP,
};
use registry_platform_crypto::SigningProvider;
use serde_json::{json, Map, Value};
use std::sync::Arc;
use time::OffsetDateTime;
use ulid::Ulid;

use super::audit::FederationAuditOutcome;
use super::errors::{federation_problem_response, FederationProblem};

#[derive(Debug)]
pub(super) struct FederationSignedOutcome {
    claims: Value,
    audit: FederationAuditOutcome,
}

impl FederationSignedOutcome {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn success(
        federation: &FederationConfig,
        peer: &FederationPeerConfig,
        protocol: &str,
        profile: &FederationEvaluationProfileConfig,
        purpose: &str,
        request_jti: &str,
        subject_id_type: &str,
        subject_hash: String,
        results: &[registry_notary_core::ClaimResultView],
    ) -> Self {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let evaluation_id = results
            .first()
            .map(|result| format!("eval_{}", result.evaluation_id))
            .unwrap_or_else(|| format!("eval_{}", Ulid::new()));
        let mut claims = Map::new();
        for result in results {
            claims.insert(
                result.claim_id.clone(),
                json!({
                    "satisfied": result.satisfied,
                    "disclosure": result.disclosure,
                    "value": result.value,
                }),
            );
        }
        let source_observed_at = results.first().map(|result| result.issued_at.clone());
        let subject_ref_hash = subject_hash;
        let body = federation_base_response_claims(
            federation,
            peer,
            protocol,
            &profile.id,
            request_jti,
            now,
            "result",
            json!({
                "evaluation_id": evaluation_id,
                "subject_ref": {
                    "hash": subject_ref_hash.clone(),
                    "id_type": subject_id_type,
                },
                "source_observed_at": source_observed_at,
                "claims": Value::Object(claims),
            }),
        );
        Self {
            claims: body,
            audit: FederationAuditOutcome {
                decision: "federated_evaluate".to_string(),
                verification_id: Some(evaluation_id),
                claim_ids: vec![profile.claim_id.clone()],
                error_code: None,
                peer_node_id: Some(peer.node_id.clone()),
                issuer: Some(peer.issuer.clone()),
                profile: Some(profile.id.clone()),
                purpose: Some(purpose.to_string()),
                request_jti: Some(request_jti.to_string()),
                subject_ref_hash: Some(subject_ref_hash),
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn evaluation_error(
        federation: &FederationConfig,
        peer: &FederationPeerConfig,
        protocol: &str,
        profile: &FederationEvaluationProfileConfig,
        purpose: &str,
        request_jti: &str,
        subject_hash: String,
        error_type: &str,
        title: &str,
    ) -> Self {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let body = federation_base_response_claims(
            federation,
            peer,
            protocol,
            &profile.id,
            request_jti,
            now,
            "error",
            json!({
                "type": error_type,
                "title": title,
                "code": "federation.stale_source_observation",
            }),
        );
        Self {
            claims: body,
            audit: FederationAuditOutcome {
                decision: "federated_evaluate_error".to_string(),
                verification_id: None,
                claim_ids: vec![profile.claim_id.clone()],
                error_code: Some("federation.stale_source_observation".to_string()),
                peer_node_id: Some(peer.node_id.clone()),
                issuer: Some(peer.issuer.clone()),
                profile: Some(profile.id.clone()),
                purpose: Some(purpose.to_string()),
                request_jti: Some(request_jti.to_string()),
                subject_ref_hash: Some(subject_hash),
            },
        }
    }

    pub(super) async fn into_response(
        self,
        signer: &FederationResponseSigner,
    ) -> (Response, FederationAuditOutcome) {
        match sign_federation_response(signer, &self.claims).await {
            Ok(jwt) => {
                let mut response = (StatusCode::OK, jwt).into_response();
                response.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/jwt"),
                );
                (response, self.audit)
            }
            Err(problem) => {
                let audit = FederationAuditOutcome::denied(&problem);
                (federation_problem_response(problem), audit)
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn federation_base_response_claims(
    federation: &FederationConfig,
    peer: &FederationPeerConfig,
    protocol: &str,
    profile_id: &str,
    request_jti: &str,
    now: i64,
    body_field: &str,
    result: Value,
) -> Value {
    let mut claims = Map::from_iter([
        ("iss".to_string(), json!(federation.issuer)),
        ("sub".to_string(), json!(federation.node_id)),
        ("aud".to_string(), json!(peer.node_id)),
        ("iat".to_string(), json!(now)),
        ("nbf".to_string(), json!(now)),
        ("exp".to_string(), json!(now + 300)),
        ("jti".to_string(), json!(Ulid::new().to_string())),
        ("request_jti".to_string(), json!(request_jti)),
        ("protocol".to_string(), json!(protocol)),
        ("action".to_string(), json!("evaluate")),
        ("profile".to_string(), json!(profile_id)),
    ]);
    claims.insert(body_field.to_string(), result);
    Value::Object(claims)
}

async fn sign_federation_response(
    signer: &FederationResponseSigner,
    claims: &Value,
) -> Result<String, FederationProblem> {
    let header = json!({
        "alg": "EdDSA",
        "typ": FEDERATION_RESPONSE_JWT_TYP,
        "kid": signer.provider.key_id(),
    });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).map_err(|_| {
            FederationProblem::server_error("failed to encode response header")
        })?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).map_err(|_| {
            FederationProblem::server_error("failed to encode response claims")
        })?)
    );
    let signature = signer
        .provider
        .sign(signing_input.as_bytes())
        .await
        .map_err(|_| FederationProblem::server_error("failed to sign response"))?;
    Ok(format!(
        "{}.{}",
        signing_input,
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

#[derive(Clone)]
pub(super) struct FederationResponseSigner {
    pub(super) provider: Arc<dyn SigningProvider>,
}
