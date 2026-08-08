//! Projection of a constructed Evidence payload onto the frozen SD-JWT VC
//! profile in `products/evidence/contracts/sd-jwt-vc-profile.yaml`, and the
//! inverse projection used by the relying-party verifier.
//!
//! The projection re-derives nothing. It re-encodes the exact payload the
//! signed-JWS format would carry: the always-disclosed claims become public
//! JWT claims, and each supported value becomes exactly one selective
//! disclosure keyed by its concept identifier. The inverse rebuilds that same
//! payload so one policy engine serves both response formats.

use std::collections::BTreeMap;

use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use registry_platform_crypto::{PublicJwk, SigningAlgorithm};
use registry_platform_sdjwt::{
    Disclosure, HolderConfirmation, ObjectDisclosure, SdJwtIssuanceInput,
};
use serde::Serialize;
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{
    model::{validate_subject_binding_shape, Evidence, HolderPublicKey, SubjectBindingMode},
    EVIDENCE_SCHEMA_V1,
};

/// Claims the issuer writes itself. `status` is absent because Version 1
/// publishes no credential status.
const ISSUER_OWNED_CLAIMS: [&str; 10] = [
    "iss", "sub", "iat", "exp", "vct", "id", "jti", "_sd", "_sd_alg", "cnf",
];

/// Every always-disclosed claim the profile can carry, across both subject
/// binding modes, in the sorted order the issuance input uses.
///
/// This is an allowlist, not a required set: it says which claims may appear.
/// Which of them must appear, and which must not, depends on the binding mode
/// and is decided by [`mode_claims_are_consistent`].
const ALWAYS_DISCLOSED_CLAIMS: [&str; 11] = [
    "assuranceProfile",
    "audience",
    "configurationRevision",
    "issuedBy",
    "observedAt",
    "providedBy",
    "purpose",
    "requestNonce",
    "subjectBinding",
    "subjects",
    "supportsRequirement",
];

/// The claims an audience-scoped assertion carries and a holder-bound one must
/// not. Both are refused by the same check so neither mode can borrow the
/// other's shape.
const AUDIENCE_SCOPED_CLAIMS: [&str; 2] = ["audience", "requestNonce"];

const STRUCTURED_VALUES_CLAIM: &str = "structuredValues";

/// A constructed payload that cannot be projected onto the profile. Every
/// variant is an internal invariant violation rather than caller input, except
/// `HolderKey`, which the runtime rejects earlier and re-checks here so the
/// unacceptable key can never reach a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SdJwtVcMappingError {
    #[error("an evidence timestamp is not an RFC 3339 instant")]
    Timestamp,
    #[error("the evidence carries no role-bound subject")]
    Subjects,
    #[error("an evidence claim is not representable as JSON")]
    Claim,
    #[error("the holder public key is not an acceptable P-256 public JWK")]
    HolderKey,
    #[error("the SD-JWT VC structured projection is inconsistent with the evidence value")]
    StructuredProjection,
    #[error("the evidence binding mode disagrees with the members it carries")]
    SubjectBindingShape,
}

/// Map a constructed payload and an optional holder key onto the issuance
/// input. The public claim set is exactly the profile's always-disclosed list
/// minus the members the issuer writes itself (`iss`, `sub`, `iat`, `exp`,
/// `vct`, `jti`, `_sd_alg`).
pub fn issuance_input(
    evidence: &Evidence,
    holder_key: Option<&HolderPublicKey>,
    structured_projections: &BTreeMap<String, String>,
) -> Result<SdJwtIssuanceInput, SdJwtVcMappingError> {
    // Re-checked here rather than trusted from the constructor, so no payload
    // whose mode disagrees with its members can reach a signature.
    validate_subject_binding_shape(evidence)
        .map_err(|_| SdJwtVcMappingError::SubjectBindingShape)?;
    // Deterministic because the kernel canonicalizes subjects to requirement
    // declaration order. The complete set travels as a public claim; `sub` is
    // a convenience projection of the first role.
    let subject = evidence
        .subjects
        .first()
        .ok_or(SdJwtVcMappingError::Subjects)?;

    let mut public_claims = BTreeMap::new();
    public_claims.insert("issuedBy".to_string(), string_claim(&evidence.issued_by));
    public_claims.insert(
        "providedBy".to_string(),
        string_claim(&evidence.provided_by),
    );
    public_claims.insert(
        "supportsRequirement".to_string(),
        string_claim(&evidence.supports_requirement),
    );
    public_claims.insert("purpose".to_string(), string_claim(&evidence.purpose));
    public_claims.insert(
        "subjectBinding".to_string(),
        claim_value(&evidence.subject_binding)?,
    );
    if let Some(audience) = evidence.audience.as_deref() {
        public_claims.insert("audience".to_string(), string_claim(audience));
    }
    public_claims.insert(
        "assuranceProfile".to_string(),
        claim_value(&evidence.assurance_profile)?,
    );
    public_claims.insert(
        "observedAt".to_string(),
        string_claim(&evidence.observed_at),
    );
    public_claims.insert(
        "configurationRevision".to_string(),
        string_claim(&evidence.configuration_revision),
    );
    if let Some(request_nonce) = evidence.request_nonce.as_deref() {
        public_claims.insert("requestNonce".to_string(), string_claim(request_nonce));
    }
    public_claims.insert("subjects".to_string(), claim_value(&evidence.subjects)?);

    let mut disclosures = Vec::with_capacity(evidence.supported_values.len());
    let mut object_disclosures = Vec::new();
    let mut structured_values = Map::new();
    for (position, supported) in evidence.supported_values.iter().enumerate() {
        if let Some(claim) = structured_projections.get(&supported.provides_value_for) {
            let crate::model::PublicValue::Structured(structured) = &supported.value else {
                return Err(SdJwtVcMappingError::StructuredProjection);
            };
            let fields = structured
                .fields
                .iter()
                .map(|(name, value)| Disclosure {
                    name: name.clone(),
                    value: value.clone(),
                })
                .collect::<Vec<_>>();
            if fields.is_empty() {
                return Err(SdJwtVcMappingError::StructuredProjection);
            }
            object_disclosures.push(ObjectDisclosure {
                name: claim.clone(),
                fields,
            });
            structured_values.insert(
                claim.clone(),
                serde_json::json!({
                    "providesValueFor": supported.provides_value_for,
                    "form": "reviewed-structured-value",
                    "schema": structured.schema,
                    "position": position,
                }),
            );
            continue;
        }
        disclosures.push(Disclosure {
            name: supported.provides_value_for.clone(),
            value: claim_value(&supported.value)?,
        });
    }
    if !structured_values.is_empty() {
        public_claims.insert(
            STRUCTURED_VALUES_CLAIM.to_string(),
            Value::Object(structured_values),
        );
    }

    Ok(SdJwtIssuanceInput {
        // The technical provider controlling the signing key, matching the
        // signed-JWS trust statement. The named legal issuer travels as
        // `issuedBy`.
        iss: evidence.provided_by.clone(),
        sub_ref: subject.binding.clone(),
        credential_id: Some(evidence.id.clone()),
        iat: unix_seconds(&evidence.issued_at)?,
        exp: unix_seconds(&evidence.valid_until)?,
        vct: evidence.is_conformant_to.clone(),
        // Version 1 publishes no credential status, so no status reference can
        // be constructed for one.
        status: None,
        public_claims,
        cnf: holder_key.map(confirmation).transpose()?,
        disclosures,
        object_disclosures,
    })
}

/// The accepted holder key as a public JSON Web Key.
///
/// Every consumer of a holder key goes through this one function, so the
/// acceptability check can never be skipped and the JWK the confirmation
/// carries is byte-identical to the one the thumbprint is taken over.
///
/// The algorithm is stated rather than carried over. An accepted key either
/// omits it or names the one algorithm the profile allows, so stating it
/// widens nothing and leaves the RFC 7638 thumbprint untouched, while a proof
/// over the confirmed key is verifiable under a named algorithm.
pub fn holder_jwk(key: &HolderPublicKey) -> Result<PublicJwk, SdJwtVcMappingError> {
    if !key.is_acceptable() {
        return Err(SdJwtVcMappingError::HolderKey);
    }
    Ok(PublicJwk {
        kty: key.kty.clone(),
        kid: key.kid.clone(),
        alg: Some(SigningAlgorithm::Es256.jwa_name().to_string()),
        crv: Some(key.crv.clone()),
        x: Some(key.x.clone()),
        y: Some(key.y.clone()),
        n: None,
        e: None,
    })
}

/// The RFC 7638 thumbprint of the accepted holder key.
///
/// Issuance and verification both derive a holder-bound subject binding from
/// this one value, so no serialization difference between the two sides can
/// fork the binding.
pub fn holder_thumbprint(key: &HolderPublicKey) -> Result<String, SdJwtVcMappingError> {
    holder_jwk(key)?
        .jkt()
        .map_err(|_| SdJwtVcMappingError::HolderKey)
}

/// Build the `cnf` member. The key identifier stays inside the JWK so the
/// confirmation carries exactly one confirmation method.
fn confirmation(key: &HolderPublicKey) -> Result<HolderConfirmation, SdJwtVcMappingError> {
    Ok(HolderConfirmation {
        jwk: holder_jwk(key)?,
        kid: None,
    })
}

fn unix_seconds(value: &str) -> Result<i64, SdJwtVcMappingError> {
    DateTime::parse_from_rfc3339(value)
        .map(|instant| instant.timestamp())
        .map_err(|_| SdJwtVcMappingError::Timestamp)
}

fn string_claim(value: &str) -> Value {
    Value::String(value.to_string())
}

fn claim_value<T: Serialize>(value: &T) -> Result<Value, SdJwtVcMappingError> {
    serde_json::to_value(value).map_err(|_| SdJwtVcMappingError::Claim)
}

/// A verified token whose claim set is not the profile's projection of an
/// Evidence payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SdJwtVcClaimError {
    #[error("the token carries a claim the profile does not publish")]
    UnexpectedClaim,
    #[error("the token is missing a claim the profile always discloses")]
    MissingClaim,
    #[error("a token claim has the wrong type or an inconsistent value")]
    ClaimShape,
    #[error("a token timestamp is not a representable instant")]
    Timestamp,
}

/// Rebuild the Evidence payload that a compact SD-JWT VC projects from.
///
/// The claim set is closed: any member outside the issuer-owned claims and the
/// profile's always-disclosed claims fails, which is how a relying party
/// detects a prohibited `status`, `aud`, `nbf`, or smuggled selector claim. The
/// result is a JSON payload, not a parsed `Evidence`, so the caller applies the
/// same contract validation and deserialization the signed-JWS path applies.
pub fn evidence_payload_from_claims(
    claims: &Map<String, Value>,
    disclosed: &[(String, Value)],
) -> Result<Value, SdJwtVcClaimError> {
    let structured = structured_value_metadata(claims)?;
    for name in claims.keys() {
        if !ISSUER_OWNED_CLAIMS.contains(&name.as_str())
            && !ALWAYS_DISCLOSED_CLAIMS.contains(&name.as_str())
            && name != STRUCTURED_VALUES_CLAIM
            && !structured.contains_key(name)
        {
            return Err(SdJwtVcClaimError::UnexpectedClaim);
        }
    }
    let subject_binding = binding_mode_of(claims)?;
    mode_claims_are_consistent(subject_binding, claims)?;

    let id = string_of(claims, "id")?;
    if string_of(claims, "jti")? != id {
        return Err(SdJwtVcClaimError::ClaimShape);
    }

    // The profile sources `iss` and `providedBy` from the same
    // `service.providerId`, so a token that disagrees with itself about the
    // technical provider is not the projection of any payload.
    if string_of(claims, "iss")? != string_of(claims, "providedBy")? {
        return Err(SdJwtVcClaimError::ClaimShape);
    }

    let subjects = claims
        .get("subjects")
        .ok_or(SdJwtVcClaimError::MissingClaim)?
        .clone();
    // `sub` is a projection of the first role-bound subject, never an
    // independent identifier.
    let first_binding = subjects
        .as_array()
        .and_then(|roles| roles.first())
        .and_then(|role| role.get("binding"))
        .and_then(Value::as_str)
        .ok_or(SdJwtVcClaimError::ClaimShape)?;
    if string_of(claims, "sub")? != first_binding {
        return Err(SdJwtVcClaimError::ClaimShape);
    }

    let mut supported_values = Vec::with_capacity(disclosed.len());
    let mut concepts = std::collections::BTreeSet::<String>::new();
    for (concept, value) in disclosed {
        if !concepts.insert(concept.clone()) {
            return Err(SdJwtVcClaimError::ClaimShape);
        }
        supported_values.push(serde_json::json!({
            "providesValueFor": concept,
            "value": value,
        }));
    }
    let mut projected = Vec::with_capacity(structured.len());
    for (claim, metadata) in structured {
        if !concepts.insert(metadata.concept.clone()) {
            return Err(SdJwtVcClaimError::ClaimShape);
        }
        let fields = claims
            .get(&claim)
            .and_then(Value::as_object)
            .filter(|fields| !fields.is_empty() && fields.len() <= 64)
            .ok_or(SdJwtVcClaimError::ClaimShape)?;
        projected.push((
            metadata.position,
            serde_json::json!({
                "providesValueFor": metadata.concept,
                "value": {
                    "form": "reviewed-structured-value",
                    "schema": metadata.schema,
                    "fields": fields,
                },
            }),
        ));
    }
    projected.sort_by_key(|(position, _)| *position);
    for (position, value) in projected {
        if position > supported_values.len() {
            return Err(SdJwtVcClaimError::ClaimShape);
        }
        supported_values.insert(position, value);
    }

    let mut payload = serde_json::json!({
        "schema": EVIDENCE_SCHEMA_V1,
        "assuranceProfile": claims.get("assuranceProfile").ok_or(SdJwtVcClaimError::MissingClaim)?,
        "subjectBinding": claims.get("subjectBinding").ok_or(SdJwtVcClaimError::MissingClaim)?,
        "id": id,
        "type": "Evidence",
        "supportsRequirement": claims.get("supportsRequirement").ok_or(SdJwtVcClaimError::MissingClaim)?,
        "isConformantTo": claims.get("vct").ok_or(SdJwtVcClaimError::MissingClaim)?,
        "issuedBy": claims.get("issuedBy").ok_or(SdJwtVcClaimError::MissingClaim)?,
        "providedBy": claims.get("providedBy").ok_or(SdJwtVcClaimError::MissingClaim)?,
        "issuedAt": rfc3339_of(claims, "iat")?,
        "observedAt": claims.get("observedAt").ok_or(SdJwtVcClaimError::MissingClaim)?,
        "validUntil": rfc3339_of(claims, "exp")?,
        "purpose": claims.get("purpose").ok_or(SdJwtVcClaimError::MissingClaim)?,
        "configurationRevision": claims.get("configurationRevision").ok_or(SdJwtVcClaimError::MissingClaim)?,
        "subjects": subjects,
        "supportedValues": supported_values,
    });
    // Present exactly for the audience-scoped mode, which
    // `mode_claims_are_consistent` has already established.
    let members = payload
        .as_object_mut()
        .ok_or(SdJwtVcClaimError::ClaimShape)?;
    for name in AUDIENCE_SCOPED_CLAIMS {
        if let Some(value) = claims.get(name) {
            members.insert(name.to_string(), value.clone());
        }
    }
    Ok(payload)
}

/// Read the declared binding mode. It is a required claim, so an assertion
/// never has its mode inferred from which other claims are absent.
fn binding_mode_of(claims: &Map<String, Value>) -> Result<SubjectBindingMode, SdJwtVcClaimError> {
    let value = claims
        .get("subjectBinding")
        .ok_or(SdJwtVcClaimError::MissingClaim)?;
    serde_json::from_value(value.clone()).map_err(|_| SdJwtVcClaimError::ClaimShape)
}

/// Enforce which always-disclosed claims the declared mode requires and which
/// it prohibits. The allowlist above only says a claim is permitted somewhere
/// in the profile, never that it belongs in this assertion.
fn mode_claims_are_consistent(
    mode: SubjectBindingMode,
    claims: &Map<String, Value>,
) -> Result<(), SdJwtVcClaimError> {
    for name in AUDIENCE_SCOPED_CLAIMS {
        match (mode, claims.contains_key(name)) {
            (SubjectBindingMode::AudienceScoped, false) => {
                return Err(SdJwtVcClaimError::MissingClaim)
            }
            (SubjectBindingMode::HolderBound, true) => {
                return Err(SdJwtVcClaimError::UnexpectedClaim)
            }
            _ => {}
        }
    }
    Ok(())
}

struct StructuredValueMetadata {
    concept: String,
    schema: String,
    position: usize,
}

fn structured_value_metadata(
    claims: &Map<String, Value>,
) -> Result<BTreeMap<String, StructuredValueMetadata>, SdJwtVcClaimError> {
    let Some(value) = claims.get(STRUCTURED_VALUES_CLAIM) else {
        return Ok(BTreeMap::new());
    };
    let object = value.as_object().ok_or(SdJwtVcClaimError::ClaimShape)?;
    if object.is_empty() || object.len() > 16 {
        return Err(SdJwtVcClaimError::ClaimShape);
    }
    let mut result = BTreeMap::new();
    let mut concepts = std::collections::BTreeSet::new();
    let mut positions = std::collections::BTreeSet::new();
    for (claim, metadata) in object {
        let metadata = metadata
            .as_object()
            .filter(|metadata| {
                metadata.len() == 4
                    && metadata.contains_key("providesValueFor")
                    && metadata.contains_key("form")
                    && metadata.contains_key("schema")
                    && metadata.contains_key("position")
            })
            .ok_or(SdJwtVcClaimError::ClaimShape)?;
        if metadata.get("form").and_then(Value::as_str) != Some("reviewed-structured-value") {
            return Err(SdJwtVcClaimError::ClaimShape);
        }
        let concept = metadata
            .get("providesValueFor")
            .and_then(Value::as_str)
            .ok_or(SdJwtVcClaimError::ClaimShape)?
            .to_owned();
        let schema = metadata
            .get("schema")
            .and_then(Value::as_str)
            .ok_or(SdJwtVcClaimError::ClaimShape)?
            .to_owned();
        let position = metadata
            .get("position")
            .and_then(Value::as_u64)
            .and_then(|position| usize::try_from(position).ok())
            .filter(|position| *position < 16)
            .ok_or(SdJwtVcClaimError::ClaimShape)?;
        if !concepts.insert(concept.clone())
            || !positions.insert(position)
            || !claims.get(claim).is_some_and(Value::is_object)
        {
            return Err(SdJwtVcClaimError::ClaimShape);
        }
        result.insert(
            claim.clone(),
            StructuredValueMetadata {
                concept,
                schema,
                position,
            },
        );
    }
    Ok(result)
}

fn string_of<'a>(claims: &'a Map<String, Value>, name: &str) -> Result<&'a str, SdJwtVcClaimError> {
    claims
        .get(name)
        .ok_or(SdJwtVcClaimError::MissingClaim)?
        .as_str()
        .ok_or(SdJwtVcClaimError::ClaimShape)
}

/// `iat` and `exp` are the profile's only numeric time claims. The kernel
/// emits every Evidence timestamp at whole-second UTC precision, so the
/// rebuilt string is the exact string the signed-JWS payload carries.
fn rfc3339_of(claims: &Map<String, Value>, name: &str) -> Result<String, SdJwtVcClaimError> {
    let seconds = claims
        .get(name)
        .ok_or(SdJwtVcClaimError::MissingClaim)?
        .as_i64()
        .ok_or(SdJwtVcClaimError::ClaimShape)?;
    Utc.timestamp_opt(seconds, 0)
        .single()
        .map(|instant| instant.to_rfc3339_opts(SecondsFormat::Secs, true))
        .ok_or(SdJwtVcClaimError::Timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::OFFLINE_EVALUATION_REQUEST_NONCE;
    use crate::model::{EvidenceObjectType, PublicValue, SubjectBinding, SupportedValue};
    use crate::EVIDENCE_SCHEMA_V1;

    fn evidence() -> Evidence {
        Evidence {
            schema: EVIDENCE_SCHEMA_V1.to_string(),
            assurance_profile: crate::AssuranceProfile::EvidenceGrade,
            subject_binding: SubjectBindingMode::AudienceScoped,
            request_nonce: Some(OFFLINE_EVALUATION_REQUEST_NONCE.to_string()),
            id: "urn:evidence:assertion:v1_2f0a".to_string(),
            evidence_type_name: EvidenceObjectType::Evidence,
            supports_requirement: "urn:example:requirement:adult-status".to_string(),
            is_conformant_to: "urn:example:evidence-type:adult-status".to_string(),
            issued_by: "urn:example:issuer:civil-registry".to_string(),
            provided_by: "urn:example:provider:evidence-service".to_string(),
            issued_at: "2026-08-02T09:15:00Z".to_string(),
            observed_at: "2026-08-02T09:14:59Z".to_string(),
            valid_until: "2026-08-02T09:20:00Z".to_string(),
            purpose: "age-gated-service".to_string(),
            audience: Some("urn:example:relying-party:library".to_string()),
            configuration_revision: "rev-7".to_string(),
            subjects: vec![
                SubjectBinding {
                    role: "applicant".to_string(),
                    binding: "urn:evidence:subject:v1_aaaa".to_string(),
                },
                SubjectBinding {
                    role: "guardian".to_string(),
                    binding: "urn:evidence:subject:v1_bbbb".to_string(),
                },
            ],
            supported_values: vec![
                SupportedValue {
                    provides_value_for: "urn:example:concept:is-adult".to_string(),
                    value: PublicValue::Boolean(true),
                },
                SupportedValue {
                    provides_value_for: "urn:example:concept:jurisdiction".to_string(),
                    value: PublicValue::String("SE".to_string()),
                },
            ],
        }
    }

    fn holder_key() -> HolderPublicKey {
        HolderPublicKey {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: "3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4".to_string(),
            y: "GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU".to_string(),
            alg: None,
            kid: None,
        }
    }

    #[test]
    fn projects_the_always_disclosed_claims() {
        let evidence = evidence();
        let input = issuance_input(&evidence, None, &BTreeMap::new()).expect("evidence maps");

        assert_eq!(input.iss, "urn:example:provider:evidence-service");
        assert_eq!(input.sub_ref, "urn:evidence:subject:v1_aaaa");
        assert_eq!(
            input.credential_id.as_deref(),
            Some("urn:evidence:assertion:v1_2f0a")
        );
        assert_eq!(input.vct, "urn:example:evidence-type:adult-status");
        assert_eq!(input.iat, 1_785_662_100);
        assert_eq!(input.exp, 1_785_662_400);
        assert!(input.status.is_none());
        assert!(input.cnf.is_none());

        assert_eq!(
            input.public_claims["issuedBy"],
            Value::String("urn:example:issuer:civil-registry".to_string())
        );
        assert_eq!(
            input.public_claims["requestNonce"],
            Value::String(OFFLINE_EVALUATION_REQUEST_NONCE.to_string())
        );
        assert_eq!(
            input.public_claims["subjects"],
            serde_json::json!([
                {"role": "applicant", "binding": "urn:evidence:subject:v1_aaaa"},
                {"role": "guardian", "binding": "urn:evidence:subject:v1_bbbb"},
            ])
        );
    }

    /// `ALWAYS_DISCLOSED_CLAIMS` is the union across both modes, so the exact
    /// public claim set is stated once per mode instead.
    #[test]
    fn an_audience_scoped_projection_carries_exactly_its_own_public_claims() {
        let input = issuance_input(&evidence(), None, &BTreeMap::new()).expect("evidence maps");
        let names: Vec<&str> = input.public_claims.keys().map(String::as_str).collect();
        assert_eq!(
            names,
            [
                "assuranceProfile",
                "audience",
                "configurationRevision",
                "issuedBy",
                "observedAt",
                "providedBy",
                "purpose",
                "requestNonce",
                "subjectBinding",
                "subjects",
                "supportsRequirement",
            ]
        );
        assert_eq!(
            input.public_claims["subjectBinding"],
            Value::String("audience-scoped".to_string())
        );
    }

    #[test]
    fn a_holder_bound_projection_carries_no_audience_and_no_request_nonce() {
        let mut evidence = evidence();
        evidence.subject_binding = SubjectBindingMode::HolderBound;
        evidence.audience = None;
        evidence.request_nonce = None;
        let input = issuance_input(&evidence, Some(&holder_key()), &BTreeMap::new()).expect("maps");
        let names: Vec<&str> = input.public_claims.keys().map(String::as_str).collect();
        assert_eq!(
            names,
            [
                "assuranceProfile",
                "configurationRevision",
                "issuedBy",
                "observedAt",
                "providedBy",
                "purpose",
                "subjectBinding",
                "subjects",
                "supportsRequirement",
            ]
        );
        assert_eq!(
            input.public_claims["subjectBinding"],
            Value::String("holder-bound".to_string())
        );
        assert!(input.cnf.is_some());
    }

    /// The mode and the members it implies are correlated in code, so a payload
    /// that disagrees with itself never reaches a signature.
    #[test]
    fn a_projection_whose_mode_disagrees_with_its_members_is_refused() {
        let mut leftover_audience = evidence();
        leftover_audience.subject_binding = SubjectBindingMode::HolderBound;
        assert_eq!(
            issuance_input(&leftover_audience, None, &BTreeMap::new()).unwrap_err(),
            SdJwtVcMappingError::SubjectBindingShape
        );

        let mut missing_audience = evidence();
        missing_audience.audience = None;
        assert_eq!(
            issuance_input(&missing_audience, None, &BTreeMap::new()).unwrap_err(),
            SdJwtVcMappingError::SubjectBindingShape
        );
    }

    #[test]
    fn selectively_discloses_exactly_one_value_per_concept() {
        let evidence = evidence();
        let input = issuance_input(&evidence, None, &BTreeMap::new()).expect("evidence maps");

        let disclosed: Vec<(&str, &Value)> = input
            .disclosures
            .iter()
            .map(|disclosure| (disclosure.name.as_str(), &disclosure.value))
            .collect();
        assert_eq!(
            disclosed,
            [
                ("urn:example:concept:is-adult", &Value::Bool(true)),
                (
                    "urn:example:concept:jurisdiction",
                    &Value::String("SE".to_string())
                ),
            ]
        );
    }

    #[test]
    fn omits_the_prohibited_claims() {
        let evidence = evidence();
        let input = issuance_input(&evidence, None, &BTreeMap::new()).expect("evidence maps");

        for prohibited in ["status", "nbf", "aud", "selector", "grant", "actor"] {
            assert!(
                !input.public_claims.contains_key(prohibited),
                "{prohibited} must not be published"
            );
            assert!(
                !input
                    .disclosures
                    .iter()
                    .any(|disclosure| disclosure.name == prohibited),
                "{prohibited} must not be disclosed"
            );
        }
    }

    #[test]
    fn embeds_an_acceptable_holder_key_as_confirmation() {
        let evidence = evidence();
        let mut key = holder_key();
        key.kid = Some("holder-1".to_string());
        key.alg = Some("ES256".to_string());

        let confirmation = issuance_input(&evidence, Some(&key), &BTreeMap::new())
            .expect("evidence maps")
            .cnf
            .expect("confirmation is present");
        assert_eq!(confirmation.jwk.kty, "EC");
        assert_eq!(confirmation.jwk.crv.as_deref(), Some("P-256"));
        assert_eq!(confirmation.jwk.x.as_deref(), Some(key.x.as_str()));
        assert_eq!(confirmation.jwk.y.as_deref(), Some(key.y.as_str()));
        assert_eq!(confirmation.jwk.kid.as_deref(), Some("holder-1"));
        assert_eq!(confirmation.jwk.alg.as_deref(), Some("ES256"));
        assert!(confirmation.kid.is_none());
    }

    /// The request may leave the holder key's algorithm unstated, and the
    /// profile accepts exactly one. The confirmation names it either way, so
    /// the confirmed key is one a key-binding proof can be verified against.
    #[test]
    fn the_confirmation_states_the_one_permitted_holder_algorithm() {
        let key = holder_key();
        assert!(key.alg.is_none(), "the request states no algorithm");

        let confirmation = issuance_input(&evidence(), Some(&key), &BTreeMap::new())
            .expect("evidence maps")
            .cnf
            .expect("confirmation is present");
        assert_eq!(confirmation.jwk.alg.as_deref(), Some("ES256"));
    }

    #[test]
    fn rejects_unacceptable_holder_keys() {
        let evidence = evidence();
        let mut wrong_curve = holder_key();
        wrong_curve.crv = "P-384".to_string();
        let mut wrong_algorithm = holder_key();
        wrong_algorithm.alg = Some("EdDSA".to_string());
        let mut wrong_key_type = holder_key();
        wrong_key_type.kty = "OKP".to_string();
        let mut short_coordinate = holder_key();
        short_coordinate.x = "11qYAYKxCrfVS_7TyWQHOg".to_string();
        let mut padded_coordinate = holder_key();
        padded_coordinate.x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo=".to_string();

        for key in [
            wrong_curve,
            wrong_algorithm,
            wrong_key_type,
            short_coordinate,
            padded_coordinate,
        ] {
            assert_eq!(
                issuance_input(&evidence, Some(&key), &BTreeMap::new()).unwrap_err(),
                SdJwtVcMappingError::HolderKey
            );
        }
    }

    /// Issuance and verification derive a holder-bound binding from one
    /// thumbprint function, so it must ignore the members RFC 7638 excludes and
    /// refuse a key the profile does not accept.
    #[test]
    fn the_holder_thumbprint_covers_only_the_required_key_members() {
        let key = holder_key();
        let baseline = holder_thumbprint(&key).expect("thumbprint succeeds");
        assert_eq!(baseline.len(), 43);
        assert_eq!(
            baseline,
            confirmation(&key)
                .expect("confirmation succeeds")
                .jwk
                .jkt()
                .expect("thumbprint succeeds")
        );

        let mut labelled = holder_key();
        labelled.kid = Some("wallet-key-1".to_string());
        labelled.alg = Some("ES256".to_string());
        assert_eq!(
            baseline,
            holder_thumbprint(&labelled).expect("thumbprint succeeds")
        );

        let mut other = holder_key();
        other.x = "jlM7b6C_e0YluzBmfAH7YH75-LioD-9bMAYocDGHsqM".to_string();
        other.y = "c-sdveAzGDZtBp-DpvWQAFPHNjPLBBshxV4ahsH0ALQ".to_string();
        assert_ne!(
            baseline,
            holder_thumbprint(&other).expect("thumbprint succeeds")
        );

        let mut unacceptable = holder_key();
        unacceptable.crv = "P-384".to_string();
        assert_eq!(
            holder_thumbprint(&unacceptable).unwrap_err(),
            SdJwtVcMappingError::HolderKey
        );
    }

    #[test]
    fn rejects_private_key_members_before_mapping() {
        let body = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4",
            "y": "GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU",
            "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
        });
        assert!(serde_json::from_value::<HolderPublicKey>(body).is_err());
    }

    #[test]
    fn rejects_payloads_the_profile_cannot_represent() {
        let mut no_subjects = evidence();
        no_subjects.subjects.clear();
        assert_eq!(
            issuance_input(&no_subjects, None, &BTreeMap::new()).unwrap_err(),
            SdJwtVcMappingError::Subjects
        );

        let mut bad_issued_at = evidence();
        bad_issued_at.issued_at = "2026-08-02 09:15:00".to_string();
        assert_eq!(
            issuance_input(&bad_issued_at, None, &BTreeMap::new()).unwrap_err(),
            SdJwtVcMappingError::Timestamp
        );

        let mut bad_valid_until = evidence();
        bad_valid_until.valid_until = "never".to_string();
        assert_eq!(
            issuance_input(&bad_valid_until, None, &BTreeMap::new()).unwrap_err(),
            SdJwtVcMappingError::Timestamp
        );
    }

    /// The claim map and resolved disclosures the verifier hands to the
    /// inverse projection once the signature and the digests check out.
    fn verified_claims(evidence: &Evidence) -> (Map<String, Value>, Vec<(String, Value)>) {
        let input = issuance_input(evidence, None, &BTreeMap::new()).expect("evidence maps");
        let credential_id = input.credential_id.clone().expect("credential identifier");
        let mut claims = Map::new();
        claims.insert("iss".to_string(), Value::String(input.iss.clone()));
        claims.insert("sub".to_string(), Value::String(input.sub_ref.clone()));
        claims.insert("iat".to_string(), Value::from(input.iat));
        claims.insert("exp".to_string(), Value::from(input.exp));
        claims.insert("vct".to_string(), Value::String(input.vct.clone()));
        claims.insert("id".to_string(), Value::String(credential_id.clone()));
        claims.insert("jti".to_string(), Value::String(credential_id));
        for (name, value) in &input.public_claims {
            claims.insert(name.clone(), value.clone());
        }
        let disclosed = input
            .disclosures
            .iter()
            .map(|disclosure| (disclosure.name.clone(), disclosure.value.clone()))
            .collect();
        (claims, disclosed)
    }

    #[test]
    fn rebuilds_the_payload_from_a_conformant_claim_set() {
        let evidence = evidence();
        let (claims, disclosed) = verified_claims(&evidence);

        let payload = evidence_payload_from_claims(&claims, &disclosed).expect("claims rebuild");

        assert_eq!(payload["providedBy"], Value::String(evidence.provided_by));
        assert_eq!(payload["issuedBy"], Value::String(evidence.issued_by));
    }

    #[test]
    fn rejects_an_issuer_claim_that_is_not_the_provider() {
        let evidence = evidence();
        let (mut claims, disclosed) = verified_claims(&evidence);
        // The profile sources `iss` and `providedBy` from the same
        // `service.providerId`, so a token that disagrees with itself about
        // who signed it is not the profile's projection of any payload.
        claims.insert(
            "iss".to_string(),
            Value::String("urn:example:provider:other-service".to_string()),
        );

        assert_eq!(
            evidence_payload_from_claims(&claims, &disclosed).unwrap_err(),
            SdJwtVcClaimError::ClaimShape
        );
    }

    #[test]
    fn rejects_a_claim_set_without_an_issuer() {
        let evidence = evidence();
        let (mut claims, disclosed) = verified_claims(&evidence);
        claims.remove("iss");

        assert_eq!(
            evidence_payload_from_claims(&claims, &disclosed).unwrap_err(),
            SdJwtVcClaimError::MissingClaim
        );
    }

    fn holder_bound_evidence() -> Evidence {
        let mut evidence = evidence();
        evidence.subject_binding = SubjectBindingMode::HolderBound;
        evidence.audience = None;
        evidence.request_nonce = None;
        evidence
    }

    #[test]
    fn rebuilds_a_holder_bound_payload_without_the_audience_scoped_members() {
        let evidence = holder_bound_evidence();
        let (claims, disclosed) = verified_claims(&evidence);

        let payload = evidence_payload_from_claims(&claims, &disclosed).expect("claims rebuild");
        let members = payload.as_object().expect("object");
        assert_eq!(
            members.get("subjectBinding"),
            Some(&Value::String("holder-bound".to_string()))
        );
        assert!(!members.contains_key("audience"));
        assert!(!members.contains_key("requestNonce"));
    }

    /// The always-disclosed list is the union across both modes, so it permits
    /// a claim without saying it belongs in this assertion. The per-mode check
    /// is what refuses a borrowed shape.
    #[test]
    fn rejects_a_claim_set_whose_mode_disagrees_with_its_claims() {
        let (mut holder_bound, disclosed) = verified_claims(&holder_bound_evidence());
        holder_bound.insert(
            "audience".to_string(),
            Value::String("urn:example:relying-party:library".to_string()),
        );
        assert_eq!(
            evidence_payload_from_claims(&holder_bound, &disclosed).unwrap_err(),
            SdJwtVcClaimError::UnexpectedClaim
        );

        let (mut audience_scoped, disclosed) = verified_claims(&evidence());
        audience_scoped.remove("audience");
        assert_eq!(
            evidence_payload_from_claims(&audience_scoped, &disclosed).unwrap_err(),
            SdJwtVcClaimError::MissingClaim
        );

        let (mut no_mode, disclosed) = verified_claims(&evidence());
        no_mode.remove("subjectBinding");
        assert_eq!(
            evidence_payload_from_claims(&no_mode, &disclosed).unwrap_err(),
            SdJwtVcClaimError::MissingClaim
        );

        let (mut bad_mode, disclosed) = verified_claims(&evidence());
        bad_mode.insert(
            "subjectBinding".to_string(),
            Value::String("holder_bound".to_string()),
        );
        assert_eq!(
            evidence_payload_from_claims(&bad_mode, &disclosed).unwrap_err(),
            SdJwtVcClaimError::ClaimShape
        );
    }
}
