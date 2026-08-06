//! Core-owned pre-response verification context for the local adopter path.
//!
//! Preparation authenticates and authorizes the exact retained request before
//! any source access. Verification then uses only that closed context and the
//! returned bytes. The second half cannot initialize a runtime, open audit
//! storage, resolve a source, or fetch keys over the network.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    auth::Authenticator,
    bundle::DeploymentInputs,
    config::{AssuranceProfile, ConceptForm, ResponseFormat},
    model::{request_nonce_is_canonical, Evidence, EvidenceRequest, JwksDocument},
    runtime::{validate_verification_material, ValidatedVerificationMaterial},
    secrets::{SecretProvider, SecretResolver},
    selector::{match_entitlement, resolve_selectors},
    verifier::{
        verify_flattened_jws, EvidenceVerificationPolicyDocument, ExpectedFormDocument,
        ExpectedOutputDocument, ExpectedScalarFormDocument, ExpectedSubjectDocument,
    },
};

pub const LOCAL_VERIFICATION_CONTEXT_SCHEMA_V1: &str =
    "registry.evidence.local-response-verification-context/v1";

/// One deliberately uninformative failure for the local verification seam.
///
/// Authentication, entitlement, selector, secret, signing, context, and
/// response failures collapse here so caller-controlled values cannot reach a
/// retained CLI diagnostic.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("local response verification failed")]
pub struct LocalVerificationError;

/// Closed trusted state retained before sending the corresponding request.
///
/// `responseFormat` is explicit so a future encoding can reuse the common
/// policy without ever inferring its format from attacker-controlled bytes.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalVerificationContext {
    schema: String,
    response_format: LocalResponseFormat,
    trusted_jwks: JwksDocument,
    verification_policy: EvidenceVerificationPolicyDocument,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LocalResponseFormat {
    SignedJws,
    SdJwtVc,
}

/// Authenticate and authorize one exact local request and close all response
/// expectations before source access.
pub async fn prepare_local_verification_context(
    deployment: &DeploymentInputs,
    request: &EvidenceRequest,
    bearer: &str,
) -> Result<LocalVerificationContext, LocalVerificationError> {
    prepare_local_verification_context_for_format(
        deployment,
        request,
        bearer,
        LocalResponseFormat::SignedJws,
    )
    .await
}

/// Close the local verification expectations for one explicitly selected
/// response format before any response or source access exists.
pub async fn prepare_local_verification_context_for_format(
    deployment: &DeploymentInputs,
    request: &EvidenceRequest,
    bearer: &str,
    response_format: LocalResponseFormat,
) -> Result<LocalVerificationContext, LocalVerificationError> {
    let bundle = &deployment.bundle;
    let configured_format = match response_format {
        LocalResponseFormat::SignedJws => ResponseFormat::SignedJws,
        LocalResponseFormat::SdJwtVc => ResponseFormat::SdJwtVc,
    };
    if bundle.config.assurance_profile != AssuranceProfile::Local
        || !request_nonce_is_canonical(&request.request_nonce)
        || request.holder_key.is_some()
        || !bundle.config.response_formats.contains(&configured_format)
    {
        return Err(LocalVerificationError);
    }

    let requirement = bundle
        .config
        .requirements
        .iter()
        .find(|candidate| candidate.id == request.requirement)
        .ok_or(LocalVerificationError)?;
    // The local adopter path remains deliberately narrow: every value must be
    // required and use one of the two forms taught by the shared start.
    if requirement.concepts.is_empty()
        || requirement
            .concepts
            .iter()
            .any(|concept| !concept.required || local_expected_form(concept.form).is_none())
    {
        return Err(LocalVerificationError);
    }

    let authenticator = Authenticator::from_config(
        &bundle.config.authentication,
        bundle.config.assurance_profile,
    );
    let authenticated = authenticator
        .authenticate(bearer)
        .await
        .map_err(|_| LocalVerificationError)?;
    let matched =
        match_entitlement(bundle, request, &authenticated).map_err(|_| LocalVerificationError)?;
    if !matched.permits_response_format(configured_format) {
        return Err(LocalVerificationError);
    }
    let resolved = resolve_selectors(bundle, request, &authenticated, &matched)
        .map_err(|_| LocalVerificationError)?;

    let secrets = SecretResolver::new(
        [SecretProvider::File],
        &deployment.runtime.config.secret_providers.file.root,
    )
    .map_err(|_| LocalVerificationError)?;
    let ValidatedVerificationMaterial {
        subject_binding_secret,
        signer: _,
        jwks,
    } = validate_verification_material(bundle, &deployment.runtime.config.signer, &secrets)
        .await
        .map_err(|_| LocalVerificationError)?;
    let expected_subjects = resolved
        .subjects
        .iter()
        .map(|subject| {
            subject
                .binding(
                    subject_binding_secret.expose_secret(),
                    bundle.config.subject_binding.key_version,
                    &bundle.config.service.trust_domain,
                    &resolved.audience,
                    &resolved.purpose,
                )
                .map(|binding| ExpectedSubjectDocument {
                    role: subject.role.clone(),
                    binding,
                })
                .map_err(|_| LocalVerificationError)
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(LocalVerificationContext {
        schema: LOCAL_VERIFICATION_CONTEXT_SCHEMA_V1.to_owned(),
        response_format,
        trusted_jwks: jwks,
        verification_policy: EvidenceVerificationPolicyDocument {
            expected_assurance_profile: AssuranceProfile::Local,
            issued_by: bundle.config.issuer.id.clone(),
            provided_by: bundle.config.service.provider_id.clone(),
            requirement: requirement.id.clone(),
            evidence_type: requirement.evidence_type.clone(),
            purpose: resolved.purpose,
            audience: resolved.audience,
            configuration_revision: bundle.revision().to_owned(),
            request_nonce: request.request_nonce.clone(),
            expected_subjects,
            expected_outputs: requirement
                .concepts
                .iter()
                .map(|concept| ExpectedOutputDocument {
                    concept: concept.id.clone(),
                    form: ExpectedFormDocument::Scalar(
                        local_expected_form(concept.form)
                            .expect("the local concept forms were validated"),
                    ),
                })
                .collect(),
            revoked_key_ids: bundle.config.signing.revoked_key_ids.clone(),
            maximum_assertion_lifetime_seconds: requirement.validity_seconds,
            clock_skew_seconds: bundle.config.signing.verifier_clock_skew_seconds,
        },
    })
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

/// Strictly verify one flattened JWS against a context retained before the
/// response existed. This operation is entirely offline.
pub fn verify_local_response(
    context: LocalVerificationContext,
    response: &[u8],
) -> Result<Evidence, LocalVerificationError> {
    verify_local_response_at(context, response, Utc::now())
}

/// Deterministic clock entry point used by the expiry test. Production callers
/// use [`verify_local_response`] and cannot choose the verification instant.
pub(crate) fn verify_local_response_at(
    context: LocalVerificationContext,
    response: &[u8],
    now: DateTime<Utc>,
) -> Result<Evidence, LocalVerificationError> {
    if context.schema != LOCAL_VERIFICATION_CONTEXT_SCHEMA_V1 {
        return Err(LocalVerificationError);
    }
    let policy = context.verification_policy.into_policy(now);
    match context.response_format {
        LocalResponseFormat::SignedJws => {
            verify_flattened_jws(response, &context.trusted_jwks, &policy)
        }
        LocalResponseFormat::SdJwtVc => {
            crate::verifier::verify_sd_jwt_vc(response, &context.trusted_jwks, &policy)
        }
    }
    .map_err(|_| LocalVerificationError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_integer_has_an_exact_local_verification_form() {
        assert!(matches!(
            local_expected_form(ConceptForm::BoundedInteger),
            Some(ExpectedScalarFormDocument::Integer)
        ));
    }
}
