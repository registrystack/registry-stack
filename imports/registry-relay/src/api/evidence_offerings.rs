// SPDX-License-Identifier: Apache-2.0
//! Evidence-offering verification routes.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::Path;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::post;
use axum::{Extension, Router};
use registry_metadata_core as metadata_core;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use ulid::Ulid;

use crate::audit::{AuditContextExt, ErrorCodeExt, ProvenanceIssuanceExt};
use crate::auth::Principal;
use crate::claim_verification::{normalize_claims_for_hash, ClaimVerificationHasher};
use crate::config::{ClaimVerificationRulesetConfig, EvidenceVerificationRateLimitConfig};
use crate::entity::{EntityModel, EntityRegistry};
use crate::error::{AuthError, Error, InternalError, ProvenanceError, SchemaError};
use crate::provenance::{
    negotiate, EvidenceVerificationReceiptContext, IssueError, NegotiationOutcome, ProvenanceState,
    EVIDENCE_VERIFICATION_RECEIPT_MEDIA_TYPE,
};
use crate::query::{ClaimVerificationQuery, EntityQueryEngine};

const DATA_PURPOSE_HEADER: &str = "data-purpose";
const MAX_EVIDENCE_VERIFICATION_BODY_BYTES: u64 = 64 * 1024;
const MAX_EVIDENCE_VERIFICATION_RECEIPT_VALIDITY: Duration = Duration::from_secs(5 * 60);
const CLAIM_SALT_BYTES: usize = 16;

#[derive(Debug)]
pub struct EvidenceVerificationLimiter {
    enabled: bool,
    burst: u32,
    window: Duration,
    max_buckets: usize,
    buckets: Mutex<HashMap<(String, String), RateBucket>>,
}

#[derive(Debug, Clone)]
struct RateBucket {
    last_refill: Instant,
    tokens: f64,
}

impl EvidenceVerificationLimiter {
    #[must_use]
    pub fn new(config: &EvidenceVerificationRateLimitConfig) -> Self {
        Self {
            enabled: config.enabled,
            burst: config.burst,
            window: Duration::from_secs(config.window_seconds),
            max_buckets: config.max_buckets.max(1),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    fn check(&self, principal_id: &str, offering_id: &str) -> Result<(), u64> {
        if !self.enabled {
            return Ok(());
        }
        let now = Instant::now();
        let key = (principal_id.to_string(), offering_id.to_string());
        let mut buckets = self
            .buckets
            .lock()
            .expect("evidence verification rate-limit mutex is not poisoned");
        self.evict_stale_buckets(&mut buckets, now);
        if !buckets.contains_key(&key) && buckets.len() >= self.max_buckets {
            evict_oldest_bucket(&mut buckets);
        }
        let bucket = buckets.entry(key).or_insert_with(|| RateBucket {
            last_refill: now,
            tokens: f64::from(self.burst),
        });
        self.refill_bucket(bucket, now);
        if bucket.tokens < 1.0 {
            let retry_after = self.retry_after_seconds(bucket.tokens);
            return Err(retry_after.max(1));
        }
        bucket.tokens -= 1.0;
        Ok(())
    }

    fn refill_bucket(&self, bucket: &mut RateBucket, now: Instant) {
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        if elapsed <= 0.0 {
            return;
        }
        let refill_per_second = f64::from(self.burst) / self.window.as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill_per_second).min(f64::from(self.burst));
        bucket.last_refill = now;
    }

    fn retry_after_seconds(&self, tokens: f64) -> u64 {
        let refill_per_second = f64::from(self.burst) / self.window.as_secs_f64();
        ((1.0 - tokens).max(0.0) / refill_per_second).ceil() as u64
    }

    fn evict_stale_buckets(
        &self,
        buckets: &mut HashMap<(String, String), RateBucket>,
        now: Instant,
    ) {
        let stale_after = self.window.saturating_mul(2).max(Duration::from_secs(60));
        buckets.retain(|_, bucket| now.duration_since(bucket.last_refill) < stale_after);
    }
}

fn evict_oldest_bucket(buckets: &mut HashMap<(String, String), RateBucket>) {
    if let Some(oldest) = buckets
        .iter()
        .min_by_key(|(_, bucket)| bucket.last_refill)
        .map(|(key, _)| key.clone())
    {
        buckets.remove(&oldest);
    }
}

pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new().route(
        "/evidence-offerings/{offering_id}/verifications",
        post(verify_evidence_offering),
    )
}

#[derive(Debug, Deserialize)]
struct EvidenceOfferingPath {
    offering_id: String,
}

#[allow(clippy::too_many_arguments)]
async fn verify_evidence_offering(
    Path(path): Path<EvidenceOfferingPath>,
    headers: HeaderMap,
    principal: Option<Extension<Principal>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    query: Option<Extension<Arc<EntityQueryEngine>>>,
    hasher: Option<Extension<Arc<ClaimVerificationHasher>>>,
    compiled_metadata: Option<Extension<Arc<metadata_core::CompiledMetadata>>>,
    provenance: Option<Extension<Arc<ProvenanceState>>>,
    limiter: Option<Extension<Arc<EvidenceVerificationLimiter>>>,
    body: Bytes,
) -> Response {
    let Some(Extension(principal)) = principal else {
        return evidence_verification_headers(
            Error::from(AuthError::MissingCredential).into_response(),
        );
    };
    let provenance_state = provenance.as_ref().map(|Extension(state)| state);
    let signed_receipt_state = evidence_receipt_requested(provenance_state, &headers);
    if strict_evidence_jwt_requested(&headers) && signed_receipt_state.is_none() {
        return evidence_verification_headers(StatusCode::NOT_ACCEPTABLE.into_response());
    }
    if body.len() as u64 > MAX_EVIDENCE_VERIFICATION_BODY_BYTES {
        return evidence_verification_headers(
            Error::from(InternalError::PayloadTooLarge).into_response(),
        );
    }
    let request: EvidenceVerificationRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return evidence_verification_headers(request_error_response(
                EvidenceVerificationRequestError::InvalidRequest,
            ));
        }
    };
    let Some(Extension(compiled)) = compiled_metadata else {
        return evidence_verification_headers(offering_not_found());
    };
    let Some(offering) = compiled.evidence_offering(&path.offering_id).cloned() else {
        return evidence_verification_headers(offering_not_found());
    };
    if let Some(Extension(limiter)) = limiter.as_ref() {
        if let Err(retry_after) = limiter.check(&principal.principal_id, &offering.id) {
            return evidence_verification_headers(rate_limited(retry_after));
        }
    }
    let Some(Extension(registry)) = registry.as_ref() else {
        return evidence_verification_headers(query_unavailable(
            "evidence offering route matched, but entity registry is not installed",
        ));
    };
    let entity = match entity_from_registry(registry, &offering.dataset_id, &offering.entity) {
        Ok(entity) => entity,
        Err(_) => return evidence_verification_headers(offering_not_found()),
    };
    if !principal
        .scopes
        .contains(&entity.access.evidence_verification_scope)
    {
        return evidence_verification_headers(offering_not_found());
    }
    let request_purpose = purpose_header_value(&headers, DATA_PURPOSE_HEADER).map(str::to_string);
    if entity.api.require_purpose_header || !offering.policy.purpose.is_empty() {
        let Some(purpose) = request_purpose.as_deref() else {
            return evidence_verification_headers(
                Error::from(AuthError::PurposeRequired).into_response(),
            );
        };
        if !is_absolute_iri(purpose) {
            return evidence_verification_headers(invalid_purpose());
        }
        if !offering.policy.purpose.is_empty()
            && !offering
                .policy
                .purpose
                .iter()
                .any(|allowed| allowed == purpose)
        {
            return evidence_verification_headers(purpose_not_allowed());
        }
    } else if let Some(purpose) = request_purpose.as_deref() {
        if !is_absolute_iri(purpose) {
            return evidence_verification_headers(invalid_purpose());
        }
    }
    let Some((ruleset_id, ruleset)) = claim_verification_ruleset(entity, &offering.access.ruleset)
    else {
        return evidence_verification_headers(offering_not_found());
    };
    if let Some(required_scope) = ruleset.scope.as_deref() {
        if !principal.scopes.contains(required_scope) {
            return evidence_verification_headers(request_error_response(
                EvidenceVerificationRequestError::RulesetNotAllowed,
            ));
        }
    }
    if let Err(error) = validate_evidence_request(&request, ruleset) {
        return evidence_verification_headers(request_error_response(error));
    }
    let subject_id = match request
        .subject
        .as_ref()
        .and_then(|subject| subject.id.clone())
    {
        Some(id)
            if ruleset.allow_subject_id_targeting
                && principal.scopes.contains(&format!(
                    "{}:targeted",
                    entity.access.evidence_verification_scope
                )) =>
        {
            Some(json!(id))
        }
        Some(_) => {
            return evidence_verification_headers(request_error_response(
                EvidenceVerificationRequestError::RulesetNotAllowed,
            ));
        }
        None => None,
    };
    let Some(Extension(query)) = query else {
        return evidence_verification_headers(query_unavailable(
            "evidence offering route matched, but entity query state is not installed",
        ));
    };
    let Some(Extension(hasher)) = hasher else {
        return evidence_verification_headers(query_unavailable(
            "evidence offering route matched, but evidence verification hasher is not installed",
        ));
    };

    let match_values = ruleset
        .match_fields
        .iter()
        .filter_map(|(claim, field)| {
            request
                .claims
                .get(claim)
                .cloned()
                .map(|value| (field.clone(), value))
        })
        .collect::<BTreeMap<_, _>>();
    let candidate_values = ruleset
        .candidate_lookup
        .iter()
        .filter_map(|claim| {
            let field = ruleset.match_fields.get(claim)?;
            request
                .claims
                .get(claim)
                .cloned()
                .map(|value| (field.clone(), value))
        })
        .collect::<BTreeMap<_, _>>();
    let result = match query
        .verify_claims_normalized_exact(
            &offering.dataset_id,
            &offering.entity,
            ClaimVerificationQuery {
                match_values,
                candidate_values,
                subject_id,
                limit: 2,
                scan_limit: 1024,
            },
        )
        .await
    {
        Ok(result) => result,
        Err(error) => return evidence_verification_headers(error.into_response()),
    };

    let verification_id = Ulid::new().to_string();
    let claim_salt = match random_salt() {
        Ok(value) => value,
        Err(error) => return evidence_verification_headers(error.into_response()),
    };
    let checked_at = match OffsetDateTime::now_utc().format(&Rfc3339) {
        Ok(value) => value,
        Err(_) => {
            return evidence_verification_headers(
                Error::from(InternalError::Unhandled).into_response(),
            );
        }
    };
    let decision = verification_decision(result.count, ruleset.expose_ambiguous);
    let purpose = request_purpose;
    let normalized_claims = normalize_claims_for_hash(&request.claims);
    let claim_hash = match hasher.hmac_hex_for_offering(
        &offering.iri,
        &json!({
            "version": 1,
            "binding_key_id": hasher.binding_key_id(),
            "verification_id": verification_id,
            "claim_salt": claim_salt,
            "offering": offering.iri,
            "dataset_id": offering.dataset_id,
            "entity": offering.entity,
            "ruleset": ruleset_id,
            "purpose": purpose,
            "subject": request.subject,
            "claims": normalized_claims,
            "evidence": request.evidence,
        }),
    ) {
        Ok(value) => value,
        Err(error) => return evidence_verification_headers(error.into_response()),
    };
    let evidence_hash = if request.evidence.is_empty() {
        None
    } else {
        match hasher.hmac_hex_for_offering(
            &offering.iri,
            &json!({
                "version": 1,
                "binding_key_id": hasher.binding_key_id(),
                "verification_id": verification_id,
                "claim_salt": claim_salt,
                "offering": offering.iri,
                "dataset_id": offering.dataset_id,
                "entity": offering.entity,
                "ruleset": ruleset_id,
                "purpose": purpose,
                "evidence": request.evidence,
            }),
        ) {
            Ok(value) => Some(value),
            Err(error) => return evidence_verification_headers(error.into_response()),
        }
    };
    let Some(requirement) = offering.requirement_iris.first().cloned() else {
        return evidence_verification_headers(query_unavailable(
            "evidence offering route matched, but evidence type has no requirement binding",
        ));
    };
    let mut body = EvidenceVerificationResponse {
        verification_id,
        decision: decision.to_string(),
        checked_at,
        requirement,
        evidence_type: offering.evidence_type_iri,
        evidence_offering: offering.iri,
        information_concepts: offering.information_concepts,
        issuing_authority: offering.issuing_authority,
        jurisdiction: offering.jurisdiction,
        level_of_assurance: offering.level_of_assurance,
        dataset_id: offering.dataset_id.clone(),
        entity: offering.entity.clone(),
        claim_salt,
        claim_hash,
        evidence_hash,
        ingest_version: result.ingest_version,
        cccev_evidence: Value::Null,
    };
    body.cccev_evidence = build_cccev_evidence(&body, None, None);
    let response = if let Some(state) = signed_receipt_state {
        issue_evidence_receipt_response(state, &principal, &body, purpose)
    } else {
        Json(&body).into_response()
    };
    let response = with_audit_context(
        response,
        AuditContextExt {
            dataset_id: Some(body.dataset_id),
            entity_name: Some(body.entity),
            table_id: Some(entity.table_id.clone()),
            offering_id: Some(offering.id),
            verification_id: Some(body.verification_id),
            verification_decision: Some(body.decision),
            claim_hash: Some(body.claim_hash),
            evidence_hash: body.evidence_hash,
            ..AuditContextExt::default()
        },
    );
    evidence_verification_headers(response)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceVerificationRequest {
    #[serde(default)]
    claims: BTreeMap<String, Value>,
    #[serde(default)]
    subject: Option<EvidenceVerificationSubject>,
    #[serde(default)]
    evidence: Vec<Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceVerificationSubject {
    #[serde(default)]
    id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct EvidenceVerificationResponse {
    verification_id: String,
    decision: String,
    checked_at: String,
    requirement: String,
    evidence_type: String,
    evidence_offering: String,
    #[serde(skip_serializing)]
    information_concepts: Vec<String>,
    issuing_authority: metadata_core::CompiledIssuingAuthority,
    #[serde(skip_serializing_if = "Option::is_none")]
    jurisdiction: Option<metadata_core::JurisdictionManifest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    level_of_assurance: Option<String>,
    dataset_id: String,
    entity: String,
    claim_salt: String,
    claim_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence_hash: Option<String>,
    ingest_version: Option<String>,
    cccev_evidence: Value,
}

#[derive(Debug, Clone, Copy)]
enum VerificationDecision {
    Match,
    Mismatch,
    Ambiguous,
}

impl std::fmt::Display for VerificationDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            VerificationDecision::Match => "match",
            VerificationDecision::Mismatch => "mismatch",
            VerificationDecision::Ambiguous => "ambiguous",
        })
    }
}

fn claim_verification_ruleset<'a>(
    entity: &'a EntityModel,
    requested: &str,
) -> Option<(&'a str, &'a ClaimVerificationRulesetConfig)> {
    entity
        .claim_verification
        .as_ref()?
        .rulesets
        .get_key_value(requested)
        .map(|(id, ruleset)| (id.as_str(), ruleset))
}

fn validate_evidence_request(
    request: &EvidenceVerificationRequest,
    ruleset: &ClaimVerificationRulesetConfig,
) -> Result<(), EvidenceVerificationRequestError> {
    for claim in request.claims.keys() {
        if !ruleset.match_fields.contains_key(claim) {
            return Err(EvidenceVerificationRequestError::InvalidRequest);
        }
    }
    for value in request.claims.values() {
        if !is_claim_scalar(value) {
            return Err(EvidenceVerificationRequestError::InvalidRequest);
        }
    }
    if request.evidence.iter().any(|item| !item.is_object()) {
        return Err(EvidenceVerificationRequestError::InvalidRequest);
    }
    for claim in &ruleset.required_claims {
        if !request.claims.contains_key(claim) {
            return Err(EvidenceVerificationRequestError::InsufficientClaims);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum EvidenceVerificationRequestError {
    RulesetNotAllowed,
    InsufficientClaims,
    InvalidRequest,
}

fn is_claim_scalar(value: &Value) -> bool {
    matches!(
        value,
        Value::String(_) | Value::Number(_) | Value::Bool(_) | Value::Null
    )
}

fn verification_decision(count: usize, expose_ambiguous: bool) -> VerificationDecision {
    match count {
        0 => VerificationDecision::Mismatch,
        1 => VerificationDecision::Match,
        _ if expose_ambiguous => VerificationDecision::Ambiguous,
        _ => VerificationDecision::Mismatch,
    }
}

fn entity_from_registry<'a>(
    registry: &'a EntityRegistry,
    dataset_id: &str,
    entity_name: &str,
) -> Result<&'a EntityModel, Error> {
    let Some(dataset) = registry.dataset(dataset_id) else {
        return Err(SchemaError::UnknownDataset.into());
    };
    dataset
        .entity(entity_name)
        .ok_or_else(|| SchemaError::UnknownResource.into())
}

fn purpose_header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)?
        .to_str()
        .ok()
        .filter(|v| !v.trim().is_empty())
}

fn is_absolute_iri(value: &str) -> bool {
    let Some((scheme, _rest)) = value.split_once(':') else {
        return false;
    };
    !scheme.is_empty()
        && scheme
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.'))
        && scheme
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphabetic())
}

fn random_salt() -> Result<String, Error> {
    let mut bytes = [0_u8; CLAIM_SALT_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| Error::from(InternalError::Unhandled))?;
    Ok(hex_lower(&bytes))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn strict_evidence_jwt_requested(headers: &HeaderMap) -> bool {
    negotiate(
        headers,
        &[EVIDENCE_VERIFICATION_RECEIPT_MEDIA_TYPE.to_string()],
    ) == NegotiationOutcome::SignedVc
}

fn evidence_receipt_requested<'a>(
    state: Option<&'a Arc<ProvenanceState>>,
    headers: &HeaderMap,
) -> Option<&'a Arc<ProvenanceState>> {
    let state = state?;
    if !state.is_enabled()
        || !state.config().accepted_media_types.iter().any(|candidate| {
            candidate.eq_ignore_ascii_case(EVIDENCE_VERIFICATION_RECEIPT_MEDIA_TYPE)
        })
    {
        return None;
    }
    match negotiate(headers, &state.config().accepted_media_types) {
        NegotiationOutcome::SignedVc => Some(state),
        NegotiationOutcome::PlainJson => None,
    }
}

fn issue_evidence_receipt_response(
    state: &ProvenanceState,
    principal: &Principal,
    body: &EvidenceVerificationResponse,
    purpose_declared: Option<String>,
) -> Response {
    let subject = state.config().issuer_did.clone();
    let audience = format!("client:{}", principal.principal_id);
    let issuing_authority = match serde_json::to_value(&body.issuing_authority) {
        Ok(value) => value,
        Err(_) => return Error::from(InternalError::Unhandled).into_response(),
    };
    let jurisdiction = match &body.jurisdiction {
        Some(jurisdiction) => match serde_json::to_value(jurisdiction) {
            Ok(value) => Some(value),
            Err(_) => return Error::from(InternalError::Unhandled).into_response(),
        },
        None => None,
    };
    let issued_at = OffsetDateTime::now_utc();
    let validity = state
        .config()
        .claim_validity
        .verify_result
        .min(MAX_EVIDENCE_VERIFICATION_RECEIPT_VALIDITY);
    let validity = match time::Duration::try_from(validity) {
        Ok(value) => value,
        Err(_) => return Error::from(InternalError::Unhandled).into_response(),
    };
    let valid_until = match issued_at.checked_add(validity) {
        Some(value) => value,
        None => return Error::from(InternalError::Unhandled).into_response(),
    };
    let cccev_evidence = build_cccev_evidence(body, Some(issued_at), Some(valid_until));
    let signed =
        match state.issue_evidence_verification_receipt(EvidenceVerificationReceiptContext {
            subject: subject.clone(),
            audience,
            verification_id: body.verification_id.clone(),
            decision: body.decision.clone(),
            requirement: Some(body.requirement.clone()),
            evidence_type: body.evidence_type.clone(),
            evidence_offering: body.evidence_offering.clone(),
            issuing_authority,
            jurisdiction,
            level_of_assurance: body.level_of_assurance.clone(),
            dataset: body.dataset_id.clone(),
            entity: body.entity.clone(),
            purpose_declared,
            checked_at: body.checked_at.clone(),
            claim_salt: body.claim_salt.clone(),
            claim_hash: body.claim_hash.clone(),
            evidence_hash: body.evidence_hash.clone(),
            cccev_evidence,
            issued_at,
        }) {
            Ok(signed) => signed,
            Err(error) => return evidence_receipt_error_to_response(error),
        };
    let mut response = signed.compact_jws.clone().into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(EVIDENCE_VERIFICATION_RECEIPT_MEDIA_TYPE),
    );
    response.extensions_mut().insert(ProvenanceIssuanceExt {
        iss: signed.issuer,
        kid: signed.verification_method_id,
        jti: signed.jti,
        claim_type: "EvidenceVerificationReceipt".to_string(),
        subject,
        iat: signed.iat,
        nbf: signed.nbf,
        exp: signed.exp,
    });
    response
}

fn build_cccev_evidence(
    body: &EvidenceVerificationResponse,
    issued_at: Option<OffsetDateTime>,
    valid_until: Option<OffsetDateTime>,
) -> Value {
    let evidence_id = format!(
        "urn:registry-relay:evidence-verification:{}",
        body.verification_id
    );
    let period_id = format!("{evidence_id}#validity");
    let value_id = format!("{evidence_id}#decision");
    let mut validity_period = json!({
        "@id": period_id,
        "@type": "time:ProperInterval",
        "time:hasBeginning": typed_datetime(&body.checked_at),
    });
    if let Some(issued_at) = issued_at.and_then(format_rfc3339) {
        validity_period["registry_relay:issuedAt"] = typed_datetime(&issued_at);
    }
    if let Some(valid_until) = valid_until.and_then(format_rfc3339) {
        validity_period["time:hasEnd"] = typed_datetime(&valid_until);
    }

    let issuing_authority = body
        .issuing_authority
        .iri
        .as_deref()
        .map(iri_object)
        .unwrap_or_else(|| {
            json!({
                "@type": "foaf:Agent",
                "dcterms:identifier": body.issuing_authority.id,
                "foaf:name": body.issuing_authority.name,
            })
        });
    let decision_concept = "https://registry-relay.dev/ns#verificationDecision";
    let mut supports_concept = body
        .information_concepts
        .iter()
        .map(|iri| iri_object(iri))
        .collect::<Vec<_>>();
    supports_concept.push(iri_object(decision_concept));

    json!({
        "@context": {
            "cccev": "http://data.europa.eu/m8g/",
            "dcterms": "http://purl.org/dc/terms/",
            "foaf": "http://xmlns.com/foaf/0.1/",
            "registry_relay": "https://registry-relay.dev/ns#",
            "skos": "http://www.w3.org/2004/02/skos/core#",
            "time": "http://www.w3.org/2006/time#",
            "xsd": "http://www.w3.org/2001/XMLSchema#",
            "cccev:isProvidedBy": { "@type": "@id" },
            "cccev:providesValueFor": { "@type": "@id" },
            "cccev:supportsConcept": { "@type": "@id" },
            "cccev:supportsRequirement": { "@type": "@id" },
            "cccev:supportsValue": { "@type": "@id" },
            "cccev:validityPeriod": { "@type": "@id" },
            "dcterms:conformsTo": { "@type": "@id" },
            "dcterms:publisher": { "@type": "@id" },
            "time:hasBeginning": { "@type": "xsd:dateTime" },
            "time:hasEnd": { "@type": "xsd:dateTime" },
            "registry_relay:evidenceOffering": { "@type": "@id" }
        },
        "@id": evidence_id,
        "@type": "cccev:Evidence",
        "dcterms:identifier": body.verification_id,
        "dcterms:conformsTo": iri_object(&body.evidence_type),
        "dcterms:publisher": issuing_authority,
        "cccev:isProvidedBy": issuing_authority,
        "cccev:supportsRequirement": iri_object(&body.requirement),
        "cccev:supportsConcept": supports_concept,
        "cccev:supportsValue": {
            "@id": value_id,
            "@type": "cccev:SupportedValue",
            "dcterms:identifier": "verification-decision",
            "cccev:providesValueFor": {
                "@id": decision_concept,
                "@type": "cccev:InformationConcept",
                "dcterms:identifier": "verification-decision",
                "skos:prefLabel": "Verification decision",
            },
            "cccev:value": body.decision,
        },
        "cccev:validityPeriod": validity_period,
        "registry_relay:evidenceOffering": iri_object(&body.evidence_offering),
        "registry_relay:decision": body.decision,
        "registry_relay:claimHash": body.claim_hash,
        "registry_relay:evidenceHash": body.evidence_hash,
        "registry_relay:dataset": body.dataset_id,
        "registry_relay:entity": body.entity,
    })
}

fn typed_datetime(value: &str) -> Value {
    json!({
        "@value": value,
        "@type": "xsd:dateTime",
    })
}

fn format_rfc3339(value: OffsetDateTime) -> Option<String> {
    value.format(&Rfc3339).ok()
}

fn iri_object(iri: &str) -> Value {
    json!({ "@id": iri })
}

fn evidence_receipt_error_to_response(error: IssueError) -> Response {
    match error {
        IssueError::SignerUnavailable => Error::from(ProvenanceError::SignerUnavailable),
        IssueError::IssuanceFailed => Error::from(ProvenanceError::IssuanceFailed),
    }
    .into_response()
}

fn evidence_verification_headers(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::VARY,
        HeaderValue::from_static("Authorization, Accept"),
    );
    response
}

fn offering_not_found() -> Response {
    let mut response = (
        StatusCode::NOT_FOUND,
        Json(json!({
            "type": "https://data.example.gov/problems/offering/not_found",
            "title": "Evidence offering not found",
            "status": StatusCode::NOT_FOUND.as_u16(),
            "detail": "Evidence offering not found or not visible to the caller.",
            "code": "offering.not_found",
        })),
    )
        .into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    response
}

fn invalid_purpose() -> Response {
    let mut response = (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "type": "https://data.example.gov/problems/evidence-verification/purpose_invalid",
            "title": "Invalid purpose",
            "status": StatusCode::BAD_REQUEST.as_u16(),
            "detail": "Data-Purpose must be an absolute IRI for evidence verification.",
            "code": "evidence_verification.purpose_invalid",
        })),
    )
        .into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    response.extensions_mut().insert(ErrorCodeExt(
        "evidence_verification.purpose_invalid".to_string(),
    ));
    response
}

fn purpose_not_allowed() -> Response {
    let mut response = (
        StatusCode::FORBIDDEN,
        Json(json!({
            "type": "https://data.example.gov/problems/evidence-verification/purpose_not_allowed",
            "title": "Purpose not allowed",
            "status": StatusCode::FORBIDDEN.as_u16(),
            "detail": "Data-Purpose is not allowed for this evidence offering.",
            "code": "evidence_verification.purpose_not_allowed",
        })),
    )
        .into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    response.extensions_mut().insert(ErrorCodeExt(
        "evidence_verification.purpose_not_allowed".to_string(),
    ));
    response
}

fn request_error_response(error: EvidenceVerificationRequestError) -> Response {
    let (status, code, title, detail) = match error {
        EvidenceVerificationRequestError::RulesetNotAllowed => (
            StatusCode::FORBIDDEN,
            "evidence_verification.ruleset_not_allowed",
            "Ruleset not allowed",
            "the requested evidence verification binding is not available to this caller",
        ),
        EvidenceVerificationRequestError::InsufficientClaims => (
            StatusCode::BAD_REQUEST,
            "evidence_verification.insufficient_claims",
            "Insufficient claims",
            "the request did not include every claim required by the evidence offering",
        ),
        EvidenceVerificationRequestError::InvalidRequest => (
            StatusCode::BAD_REQUEST,
            "evidence_verification.invalid_request",
            "Invalid evidence verification request",
            "the request body is not valid for evidence verification",
        ),
    };
    let mut response = (
        status,
        Json(json!({
            "type": format!("https://data.example.gov/problems/{}", code.replace('.', "/")),
            "title": title,
            "status": status.as_u16(),
            "detail": detail,
            "code": code,
        })),
    )
        .into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    response
        .extensions_mut()
        .insert(ErrorCodeExt(code.to_string()));
    response
}

fn rate_limited(retry_after: u64) -> Response {
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({
            "type": "https://data.example.gov/problems/evidence-verification/rate_limited",
            "title": "Evidence verification rate limit exceeded",
            "status": StatusCode::TOO_MANY_REQUESTS.as_u16(),
            "detail": "Evidence verification rate limit exceeded for this caller and offering.",
            "code": "evidence_verification.rate_limited",
        })),
    )
        .into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    response.headers_mut().insert(
        header::RETRY_AFTER,
        HeaderValue::from_str(&retry_after.to_string()).expect("u64 renders as header value"),
    );
    response.extensions_mut().insert(ErrorCodeExt(
        "evidence_verification.rate_limited".to_string(),
    ));
    response
}

fn query_unavailable(detail: &'static str) -> Response {
    let mut response = (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "type": "https://data.example.gov/problems/entity/query_unavailable",
            "title": "Query unavailable",
            "status": StatusCode::NOT_IMPLEMENTED.as_u16(),
            "detail": detail,
            "code": "entity.query_unavailable",
        })),
    )
        .into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    response
        .extensions_mut()
        .insert(ErrorCodeExt("entity.query_unavailable".to_string()));
    response
}

fn with_audit_context(mut response: Response, context: AuditContextExt) -> Response {
    response.extensions_mut().insert(context);
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter(burst: u32, window_seconds: u64, max_buckets: usize) -> EvidenceVerificationLimiter {
        EvidenceVerificationLimiter::new(&EvidenceVerificationRateLimitConfig {
            enabled: true,
            burst,
            window_seconds,
            max_buckets,
        })
    }

    #[test]
    fn limiter_refills_gradually_instead_of_resetting_fixed_windows() {
        let limiter = limiter(2, 2, 16);

        assert!(limiter.check("client-a", "offering-a").is_ok());
        assert!(limiter.check("client-a", "offering-a").is_ok());
        assert!(limiter.check("client-a", "offering-a").is_err());

        std::thread::sleep(Duration::from_millis(1_100));

        assert!(
            limiter.check("client-a", "offering-a").is_ok(),
            "one token should refill before the whole two-second window resets"
        );
        assert!(
            limiter.check("client-a", "offering-a").is_err(),
            "only one token should have refilled"
        );
    }

    #[test]
    fn limiter_bounds_bucket_count() {
        let limiter = limiter(10, 60, 2);

        assert!(limiter.check("client-a", "offering-a").is_ok());
        assert!(limiter.check("client-b", "offering-b").is_ok());
        assert!(limiter.check("client-c", "offering-c").is_ok());

        let buckets = limiter
            .buckets
            .lock()
            .expect("evidence verification rate-limit mutex is not poisoned");
        assert_eq!(buckets.len(), 2);
    }
}
