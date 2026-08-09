//! Core-owned relying-procedure preparation for the local adopter path.
//!
//! Bearer-free preparation closes trusted metadata and exact request-origin
//! subject bindings without deciding whether a caller may send the request.
//! Response verification belongs to the relying-party client and its portable
//! verifier, not to this runtime-local preparation seam.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    bundle::DeploymentInputs,
    config::{AssuranceProfile, ConceptForm, ResponseFormat, SubjectBindingMode},
    model::{JwksDocument, RequestedSubject},
    runtime::{validate_verification_material, ValidatedVerificationMaterial},
    secrets::{SecretProvider, SecretResolver},
    selector::{resolve_request_origin_subjects, ResolvedSubject},
    verifier::{
        ExpectedFormDocument, ExpectedOutputDocument, ExpectedScalarFormDocument,
        ExpectedSubjectDocument,
    },
};

pub const LOCAL_RELYING_PROCEDURE_INPUT_SCHEMA_V1: &str =
    "registry.evidence.local-relying-procedure-input/v1";
pub const LOCAL_RELYING_PROCEDURE_SCHEMA_V1: &str = "registry.evidence.local-relying-procedure/v1";

/// One deliberately uninformative failure for local procedure preparation.
///
/// Shape, selector, secret, signing, and procedure failures collapse here so
/// caller-controlled values cannot reach a retained CLI diagnostic.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("local relying procedure preparation failed")]
pub struct LocalProcedureError;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LocalResponseFormat {
    SignedJws,
    SdJwtVc,
}

/// Selector-bearing local preparation input.
///
/// There is deliberately no request nonce here. The relying-party client
/// generates the nonce only after this trusted procedure has been closed. The
/// selector values are protected input and are never copied into the output.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalRelyingProcedureInput {
    pub schema: String,
    pub response_format: LocalResponseFormat,
    pub requirement: String,
    pub purpose: String,
    pub audience: String,
    pub subjects: Vec<RequestedSubject>,
}

/// Trusted local relying-procedure inputs for the portable client.
///
/// Every field is closed from the immutable deployment, the locally governed
/// client audience, or exact bindings derived from the request-owned selector
/// values. No authorization result, selector value, or binding secret crosses
/// this seam.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalRelyingProcedure {
    pub schema: String,
    pub response_format: LocalResponseFormat,
    pub trusted_jwks: JwksDocument,
    pub expected_assurance_profile: AssuranceProfile,
    pub issued_by: String,
    pub provided_by: String,
    pub requirement: String,
    pub evidence_type: String,
    pub purpose: String,
    pub audience: String,
    pub configuration_revision: String,
    pub expected_subjects: Vec<ExpectedSubjectDocument>,
    pub expected_outputs: Vec<ExpectedOutputDocument>,
    pub revoked_key_ids: Vec<String>,
    pub maximum_assertion_lifetime_seconds: u64,
    pub clock_skew_seconds: u64,
}

/// Close a local relying procedure without authenticating or authorizing the
/// eventual caller.
///
/// This operation loads only immutable deployment state and the binding and
/// signing material needed to create independent expectations. It never opens
/// audit storage, resolves source credentials, calls a source, fetches
/// authentication keys, or contacts the running Evidence service.
pub async fn prepare_local_relying_procedure(
    deployment: &DeploymentInputs,
    input: &LocalRelyingProcedureInput,
) -> Result<LocalRelyingProcedure, LocalProcedureError> {
    let bundle = &deployment.bundle;
    if input.schema != LOCAL_RELYING_PROCEDURE_INPUT_SCHEMA_V1
        || bundle.config.assurance_profile != AssuranceProfile::Local
        || input.audience.is_empty()
        || input.audience.len() > 512
        || url::Url::parse(&input.audience).is_err()
    {
        return Err(LocalProcedureError);
    }

    let configured_format = configured_response_format(input.response_format);
    if !bundle.config.response_formats.contains(&configured_format) {
        return Err(LocalProcedureError);
    }
    let requirement = bundle
        .config
        .requirements
        .iter()
        .find(|candidate| candidate.id == input.requirement)
        .ok_or(LocalProcedureError)?;
    validate_local_requirement(requirement)?;
    let configuration_revision = bundle
        .configuration_revision(&requirement.id)
        .ok_or(LocalProcedureError)?
        .to_owned();
    let resolved =
        resolve_request_origin_subjects(bundle, requirement, &input.purpose, &input.subjects)
            .map_err(|_| LocalProcedureError)?;

    let secrets = SecretResolver::new(
        [SecretProvider::File],
        &deployment.runtime.config.secret_providers.file.root,
    )
    .map_err(|_| LocalProcedureError)?;
    let ValidatedVerificationMaterial {
        subject_binding_secret,
        signer: _,
        jwks,
    } = validate_verification_material(bundle, &deployment.runtime.config.signer, &secrets)
        .await
        .map_err(|_| LocalProcedureError)?;
    let expected_subjects = expected_subjects(
        &resolved,
        subject_binding_secret.expose_secret(),
        bundle.config.subject_binding.key_version,
        &bundle.config.service.trust_domain,
        &input.audience,
        &input.purpose,
    )?;

    Ok(LocalRelyingProcedure {
        schema: LOCAL_RELYING_PROCEDURE_SCHEMA_V1.to_owned(),
        response_format: input.response_format,
        trusted_jwks: jwks,
        expected_assurance_profile: AssuranceProfile::Local,
        issued_by: bundle.config.issuer.id.clone(),
        provided_by: bundle.config.service.provider_id.clone(),
        requirement: requirement.id.clone(),
        evidence_type: requirement.evidence_type.clone(),
        purpose: input.purpose.clone(),
        audience: input.audience.clone(),
        configuration_revision,
        expected_subjects,
        expected_outputs: local_expected_outputs(requirement),
        revoked_key_ids: bundle.config.signing.revoked_key_ids.clone(),
        maximum_assertion_lifetime_seconds: requirement.validity_seconds,
        clock_skew_seconds: bundle.config.signing.verifier_clock_skew_seconds,
    })
}

fn configured_response_format(response_format: LocalResponseFormat) -> ResponseFormat {
    match response_format {
        LocalResponseFormat::SignedJws => ResponseFormat::SignedJws,
        LocalResponseFormat::SdJwtVc => ResponseFormat::SdJwtVc,
    }
}

fn validate_local_requirement(
    requirement: &crate::config::RequirementConfig,
) -> Result<(), LocalProcedureError> {
    // The local adopter path remains deliberately narrow: every value must be
    // required and use one of the four scalar forms taught by local authoring.
    if requirement.concepts.is_empty()
        || requirement
            .concepts
            .iter()
            .any(|concept| !concept.required || local_expected_form(concept.form).is_none())
    {
        return Err(LocalProcedureError);
    }
    // The local relying procedure derives an audience-scoped binding only: a
    // holder-bound requirement needs a per-request wallet key this
    // preparation seam does not have, so it is refused here rather than
    // handed a binding that can never match at the server.
    if requirement.subject_binding_mode() != SubjectBindingMode::AudienceScoped {
        return Err(LocalProcedureError);
    }
    Ok(())
}

fn expected_subjects(
    subjects: &[ResolvedSubject],
    binding_key: &[u8],
    binding_key_version: u32,
    trust_domain: &str,
    audience: &str,
    purpose: &str,
) -> Result<Vec<ExpectedSubjectDocument>, LocalProcedureError> {
    subjects
        .iter()
        .map(|subject| {
            subject
                .binding(
                    binding_key,
                    binding_key_version,
                    trust_domain,
                    // The local relying procedure is audience-scoped only: a
                    // holder-bound binding depends on a per-request wallet key
                    // and is not computable at preparation time.
                    crate::binding::SubjectBindingScope::Audience(audience),
                    purpose,
                )
                .map(|binding| ExpectedSubjectDocument {
                    role: subject.role.clone(),
                    binding,
                })
                .map_err(|_| LocalProcedureError)
        })
        .collect()
}

fn local_expected_outputs(
    requirement: &crate::config::RequirementConfig,
) -> Vec<ExpectedOutputDocument> {
    requirement
        .concepts
        .iter()
        .map(|concept| ExpectedOutputDocument {
            concept: concept.id.clone(),
            form: ExpectedFormDocument::Scalar(
                local_expected_form(concept.form).expect("the local concept forms were validated"),
            ),
        })
        .collect()
}

fn local_expected_form(form: ConceptForm) -> Option<ExpectedScalarFormDocument> {
    match form {
        ConceptForm::Boolean => Some(ExpectedScalarFormDocument::Boolean),
        ConceptForm::BoundedInteger => Some(ExpectedScalarFormDocument::Integer),
        ConceptForm::ControlledCategory => Some(ExpectedScalarFormDocument::String),
        ConceptForm::ReviewedStructuredValue => Some(ExpectedScalarFormDocument::Structured),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn bounded_integer_has_an_exact_local_verification_form() {
        assert!(matches!(
            local_expected_form(ConceptForm::BoundedInteger),
            Some(ExpectedScalarFormDocument::Integer)
        ));
    }

    #[test]
    fn local_relying_procedure_input_is_closed_and_has_no_nonce() {
        let input = json!({
            "schema": LOCAL_RELYING_PROCEDURE_INPUT_SCHEMA_V1,
            "responseFormat": "signed-jws",
            "requirement": "urn:example:requirement:status",
            "purpose": "status-check",
            "audience": "urn:example:client:relying-party",
            "subjects": [{
                "role": "subject",
                "selector": {
                    "profile": "record-reference-v1",
                    "values": {"record_reference": "synthetic-001"}
                }
            }]
        });
        let parsed: LocalRelyingProcedureInput =
            serde_json::from_value(input.clone()).expect("the closed draft parses");
        assert_eq!(parsed.response_format, LocalResponseFormat::SignedJws);

        for member in ["requestNonce", "holderKeys", "authorization"] {
            let mut changed = input.clone();
            changed[member] = json!("not-permitted");
            assert!(
                serde_json::from_value::<LocalRelyingProcedureInput>(changed).is_err(),
                "{member} is outside the closed draft"
            );
        }
    }

    #[test]
    fn local_requirement_validation_refuses_holder_bound_requirements() {
        let config = crate::config::EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/holder-bound/evidence.yaml"
        ))
        .expect("the holder-bound acceptance bundle validates");

        for requirement in &config.requirements {
            assert_eq!(
                validate_local_requirement(requirement),
                Err(LocalProcedureError),
                "{} must not receive an audience-scoped local procedure",
                requirement.id
            );
        }
    }
}
