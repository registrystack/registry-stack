// SPDX-License-Identifier: Apache-2.0

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use registry_notary_core::{
    FederationConfig, FederationEvaluationProfileConfig, FederationPeerConfig, SubjectRequest,
    FEDERATION_PROTOCOL_V0_1,
};
use registry_platform_oidc::VerifiedToken;
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use ulid::Ulid;

use super::errors::FederationProblem;

pub(super) fn validate_federation_claims(
    federation: &FederationConfig,
    peer: &FederationPeerConfig,
    verified: &VerifiedToken,
) -> Result<(), FederationProblem> {
    if verified.claims.sub.as_deref() != Some(peer.node_id.as_str()) {
        return Err(FederationProblem::invalid_token());
    }
    let Some(iat) = verified.claims.iat else {
        return Err(FederationProblem::invalid_token());
    };
    let Some(nbf) = verified.claims.nbf else {
        return Err(FederationProblem::invalid_token());
    };
    let Some(exp) = verified.claims.exp else {
        return Err(FederationProblem::invalid_token());
    };
    if nbf < iat.saturating_sub(federation.clock_leeway_seconds as i64) {
        return Err(FederationProblem::invalid_token());
    }
    if exp - iat > federation.max_request_lifetime_seconds as i64 {
        return Err(FederationProblem::invalid_token());
    }
    let jti = string_extra(verified, "jti").ok_or_else(FederationProblem::invalid_token)?;
    if Ulid::from_string(jti).is_err() {
        return Err(FederationProblem::invalid_token());
    }
    let protocol =
        string_extra(verified, "protocol").ok_or_else(FederationProblem::invalid_request_owned)?;
    if protocol != FEDERATION_PROTOCOL_V0_1
        || !peer
            .allowed_protocol_versions
            .iter()
            .any(|allowed| allowed == protocol)
    {
        return Err(FederationProblem::forbidden("protocol is not allowed"));
    }
    if string_extra(verified, "action") != Some("evaluate") {
        return Err(FederationProblem::invalid_request(
            "action must be evaluate",
        ));
    }
    let profile =
        string_extra(verified, "profile").ok_or_else(FederationProblem::invalid_request_owned)?;
    if !peer
        .allowed_profiles
        .iter()
        .any(|allowed| allowed == profile)
    {
        return Err(FederationProblem::forbidden("profile is not allowed"));
    }
    let purpose =
        string_extra(verified, "purpose").ok_or_else(FederationProblem::invalid_request_owned)?;
    if !peer
        .allowed_purposes
        .iter()
        .any(|allowed| allowed == purpose)
    {
        return Err(FederationProblem::forbidden("purpose is not allowed"));
    }
    Ok(())
}

pub(super) fn request_subject(
    verified: &VerifiedToken,
    profile: &FederationEvaluationProfileConfig,
) -> Result<SubjectRequest, FederationProblem> {
    let request = verified
        .claims
        .extra
        .get("request")
        .and_then(Value::as_object)
        .ok_or_else(|| FederationProblem::invalid_request("request object is required"))?;
    let subject = request
        .get("subject")
        .and_then(Value::as_object)
        .ok_or_else(|| FederationProblem::invalid_request("request.subject is required"))?;
    let id = subject
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| FederationProblem::invalid_request("request.subject.id is required"))?;
    let id_type = subject
        .get("id_type")
        .and_then(Value::as_str)
        .ok_or_else(|| FederationProblem::invalid_request("request.subject.id_type is required"))?;
    if id_type != profile.subject_id_type {
        return Err(FederationProblem::forbidden(
            "subject id type is not allowed",
        ));
    }
    let requested_claims = request
        .get("claims")
        .and_then(Value::as_array)
        .ok_or_else(|| FederationProblem::invalid_request("request.claims is required"))?;
    if requested_claims.len() != 1
        || requested_claims.first().and_then(Value::as_str) != Some(profile.claim_id.as_str())
    {
        return Err(FederationProblem::forbidden(
            "request claims do not match profile",
        ));
    }
    Ok(SubjectRequest {
        id: id.to_string(),
        id_type: Some(id_type.to_string()),
    })
}

pub(super) fn source_observation_is_stale(
    profile: &FederationEvaluationProfileConfig,
    results: &[registry_notary_core::ClaimResultView],
) -> bool {
    let Some(max_age) = profile.max_source_observed_age_seconds else {
        return false;
    };
    if max_age == 0 {
        return true;
    }
    let Some(observed_at) = results
        .first()
        .and_then(|result| OffsetDateTime::parse(&result.issued_at, &Rfc3339).ok())
    else {
        return true;
    };
    let age = OffsetDateTime::now_utc() - observed_at;
    age > time::Duration::seconds(max_age as i64)
}

pub(super) fn string_extra<'a>(verified: &'a VerifiedToken, claim: &str) -> Option<&'a str> {
    verified.claims.extra.get(claim).and_then(Value::as_str)
}

pub(super) fn string_claim<'a>(claims: &'a Value, claim: &str) -> Option<&'a str> {
    claims.get(claim).and_then(Value::as_str)
}

pub(super) fn decode_unverified_jwt_payload(token: &str) -> Result<Value, FederationProblem> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(FederationProblem::invalid_token)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| FederationProblem::invalid_token())?;
    serde_json::from_slice(&bytes).map_err(|_| FederationProblem::invalid_token())
}
