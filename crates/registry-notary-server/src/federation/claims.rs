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
    let Some(lifetime) = exp.checked_sub(iat).filter(|lifetime| *lifetime > 0) else {
        return Err(FederationProblem::invalid_token());
    };
    if lifetime as u64 > federation.max_request_lifetime_seconds {
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
    let subject = request_subject_identifier(verified, profile)?;
    let request = request_object(verified)?;
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
    Ok(subject)
}

pub(super) fn request_subject_identifier(
    verified: &VerifiedToken,
    profile: &FederationEvaluationProfileConfig,
) -> Result<SubjectRequest, FederationProblem> {
    let request = request_object(verified)?;
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
    Ok(SubjectRequest {
        id: id.to_string(),
        id_type: Some(id_type.to_string()),
    })
}

fn request_object(
    verified: &VerifiedToken,
) -> Result<&serde_json::Map<String, Value>, FederationProblem> {
    verified
        .claims
        .extra
        .get("request")
        .and_then(Value::as_object)
        .ok_or_else(|| FederationProblem::invalid_request("request object is required"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_oidc::{Claims, VerifiedToken};
    use serde_json::{json, Map};

    fn federation() -> FederationConfig {
        FederationConfig {
            max_request_lifetime_seconds: 300,
            clock_leeway_seconds: 60,
            ..FederationConfig::default()
        }
    }

    fn peer() -> FederationPeerConfig {
        FederationPeerConfig {
            node_id: "did:web:peer.example".to_string(),
            allowed_protocol_versions: vec![FEDERATION_PROTOCOL_V0_1.to_string()],
            allowed_profiles: vec!["basic".to_string()],
            allowed_purposes: vec!["https://purpose.example/federation".to_string()],
            ..FederationPeerConfig::default()
        }
    }

    fn verified_token(iat: i64, nbf: i64, exp: i64) -> VerifiedToken {
        let mut extra = Map::new();
        extra.insert("jti".to_string(), json!(Ulid::new().to_string()));
        extra.insert("protocol".to_string(), json!(FEDERATION_PROTOCOL_V0_1));
        extra.insert("action".to_string(), json!("evaluate"));
        extra.insert("profile".to_string(), json!("basic"));
        extra.insert(
            "purpose".to_string(),
            json!("https://purpose.example/federation"),
        );

        VerifiedToken {
            claims: Claims {
                sub: Some("did:web:peer.example".to_string()),
                iat: Some(iat),
                nbf: Some(nbf),
                exp: Some(exp),
                iss: None,
                aud: None,
                azp: None,
                client_id: None,
                extra,
            },
            matched_client: None,
            scopes: Vec::new(),
        }
    }

    fn validate(iat: i64, nbf: i64, exp: i64) -> Result<(), FederationProblem> {
        validate_federation_claims(&federation(), &peer(), &verified_token(iat, nbf, exp))
    }

    #[test]
    fn accepts_token_with_valid_lifetime() {
        assert!(validate(1_000, 1_000, 1_300).is_ok());
    }

    #[test]
    fn rejects_token_with_equal_exp_and_iat() {
        assert!(validate(1_000, 1_000, 1_000).is_err());
    }

    #[test]
    fn rejects_token_with_exp_before_iat() {
        assert!(validate(1_000, 1_000, 999).is_err());
    }

    #[test]
    fn rejects_token_lifetime_subtraction_overflow() {
        assert!(validate(i64::MIN, i64::MIN, i64::MAX).is_err());
    }

    #[test]
    fn accepts_extreme_values_with_valid_lifetime() {
        assert!(validate(i64::MAX - 1, i64::MAX - 1, i64::MAX).is_ok());
    }
}
