// SPDX-License-Identifier: Apache-2.0
//! Exact OpenCRVS v1.9.0-rc.1 birth-record existence journey.
//!
//! The journey deliberately stays product-specific: one fresh OAuth exchange,
//! one fresh same-origin JWKS exchange, and one signed DCI exact search. It
//! releases only closed cardinality, never a source record or selector.

use registry_platform_httputil::destination::oauth::{FreshBearerToken, NoExpiryOAuthTokenDecoder};
use registry_platform_httputil::destination::opencrvs::{
    OpenCrvsDciV190Rc1DecodeError, OpenCrvsDciV190Rc1Decoder, OpenCrvsDciV190Rc1Expectation,
};
use registry_platform_httputil::destination::DataDestinationBody;
use time::OffsetDateTime;

use crate::source_plan::codec::dci::{DciExactSearchRequest, DciExactSearchRequestInput};
use crate::source_plan::runtime_profile::CompiledConsentProfile;
use crate::source_plan::{
    CompiledOAuthSourceCredentialProvider, CompiledProjectionMechanism, CompiledRequestCodec,
    CompiledResponseNormalization, CompiledSelectorLocation, CompiledSelectorSource,
    CompiledSourceAuth, CompiledSourcePlan, ReadMethod, SourcePlanKind,
};
use crate::state_plane::{
    AuditedConsultationDispatch, KnownFailureClass, PostgresServingFence, QuotaGrant,
};

use super::{
    map_response_error, map_unaccepted_status, prepare_public_result,
    ConcreteExecutorActivationError, ConcreteExecutorProof, ConcreteExecutorUnfinished,
    PublicResultPreparationError,
};
use crate::consultation::audit::PendingPublicationContext;
use crate::consultation::commitments::{SealedConsultationExecution, TrustedConsultationTime};
use crate::consultation::response::PublishableConsultationResponse;

const OPENCRVS_PROTOCOL_VERSION: &str = "1.0.0";
const OPENCRVS_SENDER_ID: &str = "registry-relay";
const OPENCRVS_REGISTRY_TYPE: &str = "ns:org:RegistryType:Civil";
const OPENCRVS_RECORD_TYPE: &str = "spdci-extensions-dci:Person";
const OPENCRVS_IDENTIFIER_TYPE: &str = "UIN";
const OPENCRVS_SEARCH_PATH: &str = "/registry/sync/search";
const OPENCRVS_JWKS_PATH: &str = "/.well-known/jwks.json";
const OPENCRVS_REQUESTED_MAXIMUM: u8 = 2;

enum CredentialDispatchResult {
    Token(FreshBearerToken),
    KnownFailure(KnownFailureClass),
}

enum DataBodyDispatchResult {
    Body(DataDestinationBody),
    KnownFailure(KnownFailureClass),
}

pub(super) fn validate_open_crvs_dci_exact_activation(
    plan: &CompiledSourcePlan,
) -> Result<(), ConcreteExecutorActivationError> {
    if plan.kind() != SourcePlanKind::BoundedHttp
        || plan.inputs().len() != 1
        || plan.operations().len() != 1
        || plan.steps().len() != 1
        || plan.compiled_steps().len() != 1
        || plan.credential_operation().is_none()
        || plan.credential_destination().is_none()
        || plan.data_destination().is_none()
        || !matches!(
            plan.runtime_profile().authorization().consent(),
            CompiledConsentProfile::NotRequired
        )
    {
        return Err(ConcreteExecutorActivationError::UnsupportedPlan);
    }

    let operation = plan
        .operations()
        .next()
        .ok_or(ConcreteExecutorActivationError::UnsupportedPlan)?;
    let step = plan
        .compiled_steps()
        .next()
        .ok_or(ConcreteExecutorActivationError::UnsupportedPlan)?;
    let jwks = operation
        .embedded_open_crvs_jwks()
        .ok_or(ConcreteExecutorActivationError::UnsupportedPlan)?;
    if step.condition().is_some()
        || step.condition_source_index().is_some()
        || step.condition_output_slot_index().is_some()
        || !std::ptr::eq(
            plan.steps()
                .next()
                .ok_or(ConcreteExecutorActivationError::UnsupportedPlan)?,
            operation,
        )
        || operation.method() != ReadMethod::ReadOnlyPost
        || operation.fixed_path() != OPENCRVS_SEARCH_PATH
        || operation.auth() != CompiledSourceAuth::OAuthClientCredentials
        || operation.query().len() != 0
        || operation.headers().len() != 0
        || operation.body().is_some()
        || operation.request_codec() != CompiledRequestCodec::OpenCrvsDciExactV1
        || operation.request_signer().is_some()
        || operation.max_source_records() != OPENCRVS_REQUESTED_MAXIMUM
        || operation.projection() != &CompiledProjectionMechanism::BoundedFullRecord
        || operation.response().normalization() != CompiledResponseNormalization::ArrayProbeTwo
        || operation.response().outputs().len() != 0
        || operation.response().prior_outputs().len() != 0
        || operation.response().accepted_statuses().collect::<Vec<_>>() != [200]
        || jwks.fixed_path() != OPENCRVS_JWKS_PATH
    {
        return Err(ConcreteExecutorActivationError::UnsupportedPlan);
    }

    if !matches!(
        operation.selector().source(),
        CompiledSelectorSource::ConsultationInput { input_index: 0 }
    ) || !matches!(
        operation.selector().location(),
        CompiledSelectorLocation::DciIdtypeValue
    ) || plan
        .inputs()
        .next()
        .is_none_or(|input| input.name().is_empty())
    {
        return Err(ConcreteExecutorActivationError::UnsupportedPlan);
    }

    let credential = plan
        .credential_operation()
        .ok_or(ConcreteExecutorActivationError::UnsupportedPlan)?;
    let token_response_max_bytes = usize::try_from(credential.parser().max_response_bytes())
        .map_err(|_| ConcreteExecutorActivationError::UnsupportedPlan)?;
    let jwks_max_bytes = usize::try_from(jwks.response_max_bytes())
        .map_err(|_| ConcreteExecutorActivationError::UnsupportedPlan)?;
    let response_max_bytes = usize::try_from(operation.response_max_bytes())
        .map_err(|_| ConcreteExecutorActivationError::UnsupportedPlan)?;
    if !credential.parser().is_no_expiry()
        || NoExpiryOAuthTokenDecoder::new(
            token_response_max_bytes,
            usize::from(credential.parser().access_token_max_bytes()),
        )
        .is_err()
        || OpenCrvsDciV190Rc1Expectation::new(
            "01JZ0000000000000000000000",
            OPENCRVS_SENDER_ID,
            None,
            "1234567890",
            jwks_max_bytes,
            response_max_bytes,
        )
        .is_err()
    {
        return Err(ConcreteExecutorActivationError::UnsupportedPlan);
    }
    Ok(())
}

pub(super) async fn execute_open_crvs_dci_exact(
    dispatch: &mut AuditedConsultationDispatch,
    execution: SealedConsultationExecution<'_>,
    publication: PendingPublicationContext,
    quota: QuotaGrant,
    fence: &PostgresServingFence,
    credentials: &CompiledOAuthSourceCredentialProvider,
) -> Result<ConcreteExecutorProof<PublishableConsultationResponse>, ConcreteExecutorUnfinished> {
    let bound = execution
        .into_bound()
        .map_err(|_| ConcreteExecutorUnfinished)?;
    validate_open_crvs_dci_exact_activation(bound.plan())
        .map_err(|_| ConcreteExecutorUnfinished)?;
    let operation = bound
        .plan()
        .operations()
        .next()
        .ok_or(ConcreteExecutorUnfinished)?;
    let credential_operation = bound
        .plan()
        .credential_operation()
        .ok_or(ConcreteExecutorUnfinished)?;
    let jwks_operation = operation
        .embedded_open_crvs_jwks()
        .ok_or(ConcreteExecutorUnfinished)?;
    let credential_destination = bound
        .plan()
        .credential_destination()
        .ok_or(ConcreteExecutorUnfinished)?;
    let data_destination = bound
        .plan()
        .data_destination()
        .ok_or(ConcreteExecutorUnfinished)?;
    let runtime_profile = bound.plan().runtime_profile();

    let message_id = publication.consultation_id().to_canonical_string();
    let sampled = TrustedConsultationTime::sample().map_err(|_| ConcreteExecutorUnfinished)?;
    let timestamp_nanos = i128::from(sampled.unix_ms())
        .checked_mul(1_000_000)
        .ok_or(ConcreteExecutorUnfinished)?;
    let message_timestamp = OffsetDateTime::from_unix_timestamp_nanos(timestamp_nanos)
        .map_err(|_| ConcreteExecutorUnfinished)?;
    let dci_request = DciExactSearchRequest::try_new(DciExactSearchRequestInput {
        protocol_version: OPENCRVS_PROTOCOL_VERSION,
        message_id: &message_id,
        message_timestamp,
        sender_id: OPENCRVS_SENDER_ID,
        receiver_id: None,
        registry_type: Some(OPENCRVS_REGISTRY_TYPE),
        registry_event_type: Some("birth"),
        record_type: Some(OPENCRVS_RECORD_TYPE),
        identifier_type: OPENCRVS_IDENTIFIER_TYPE,
        selector: bound.input().as_str(),
        requested_max: OPENCRVS_REQUESTED_MAXIMUM,
        signature: None,
    })
    .map_err(|_| ConcreteExecutorUnfinished)?;
    let request_body = dci_request
        .to_json_body()
        .map_err(|_| ConcreteExecutorUnfinished)?;
    drop(dci_request);
    if request_body.as_bytes().len()
        > usize::try_from(operation.request_max_bytes()).map_err(|_| ConcreteExecutorUnfinished)?
    {
        return Err(ConcreteExecutorUnfinished);
    }

    let token_response_max_bytes =
        usize::try_from(credential_operation.parser().max_response_bytes())
            .map_err(|_| ConcreteExecutorUnfinished)?;
    let token_decoder = NoExpiryOAuthTokenDecoder::new(
        token_response_max_bytes,
        usize::from(credential_operation.parser().access_token_max_bytes()),
    )
    .map_err(|_| ConcreteExecutorUnfinished)?;
    let credential_request = credentials
        .credentials_for(bound.plan(), credential_operation)
        .and_then(|capability| {
            capability.render().map_err(|_| {
                crate::source_plan::SourceCredentialProviderError::OperationBindingMismatch
            })
        })
        .map_err(|_| ConcreteExecutorUnfinished)?;
    let credential_permit = dispatch
        .credential_permit_mut()
        .map_err(|_| ConcreteExecutorUnfinished)?
        .ok_or(ConcreteExecutorUnfinished)?;
    let credential_result = fence
        .authorize_and_dispatch(
            credential_permit,
            credential_operation.id(),
            |deadline| async move {
                let response = match credential_destination
                    .send_with_deadline(credential_request, deadline)
                    .await
                {
                    Ok(response) => response,
                    Err(_) => {
                        return CredentialDispatchResult::KnownFailure(
                            KnownFailureClass::CredentialUnavailable,
                        );
                    }
                };
                if response.status().as_u16() != 200 {
                    return CredentialDispatchResult::KnownFailure(
                        KnownFailureClass::CredentialUnavailable,
                    );
                }
                if response.require_json_content_type().is_err() {
                    return CredentialDispatchResult::KnownFailure(
                        KnownFailureClass::CredentialUnavailable,
                    );
                }
                let body = match response.read_bounded(token_response_max_bytes).await {
                    Ok(body) => body,
                    Err(_) => {
                        return CredentialDispatchResult::KnownFailure(
                            KnownFailureClass::CredentialUnavailable,
                        );
                    }
                };
                match token_decoder.decode(body) {
                    Ok(token) => CredentialDispatchResult::Token(token),
                    Err(_) => CredentialDispatchResult::KnownFailure(
                        KnownFailureClass::CredentialUnavailable,
                    ),
                }
            },
        )
        .await
        .map_err(|_| ConcreteExecutorUnfinished)?;
    let token = match credential_result {
        CredentialDispatchResult::Token(token) => token,
        CredentialDispatchResult::KnownFailure(failure) => {
            drop(quota);
            return Ok(ConcreteExecutorProof::known_failure(failure));
        }
    };

    let jwks_request = jwks_operation
        .transport_template()
        .render(&[], &[], None, None)
        .map_err(|_| ConcreteExecutorUnfinished)?;
    let jwks_max_bytes = usize::try_from(jwks_operation.response_max_bytes())
        .map_err(|_| ConcreteExecutorUnfinished)?;
    let jwks_permit = dispatch
        .next_data_permit_mut()
        .map_err(|_| ConcreteExecutorUnfinished)?
        .ok_or(ConcreteExecutorUnfinished)?;
    let jwks_result = fence
        .authorize_and_dispatch(jwks_permit, jwks_operation.id(), |deadline| async move {
            let response = match data_destination
                .send_with_deadline(jwks_request, deadline)
                .await
            {
                Ok(response) => response,
                Err(_) => {
                    return DataBodyDispatchResult::KnownFailure(
                        KnownFailureClass::SourceUnavailable,
                    );
                }
            };
            if response.status().as_u16() != 200 {
                return DataBodyDispatchResult::KnownFailure(KnownFailureClass::SourceUnavailable);
            }
            if response.require_json_content_type().is_err() {
                return DataBodyDispatchResult::KnownFailure(
                    KnownFailureClass::ResponseContractViolation,
                );
            }
            match response.read_bounded(jwks_max_bytes).await {
                Ok(body) => DataBodyDispatchResult::Body(body),
                Err(error) => DataBodyDispatchResult::KnownFailure(map_response_error(error)),
            }
        })
        .await
        .map_err(|_| ConcreteExecutorUnfinished)?;
    let jwks_body = match jwks_result {
        DataBodyDispatchResult::Body(body) => body,
        DataBodyDispatchResult::KnownFailure(failure) => {
            drop(quota);
            return Ok(ConcreteExecutorProof::known_failure(failure));
        }
    };

    let authorization = token.into_authorization();
    let data_request = operation
        .transport_template()
        .render_zeroizing(
            &[],
            &[],
            Some(authorization),
            Some(request_body.into_zeroizing_bytes()),
        )
        .map_err(|_| ConcreteExecutorUnfinished)?;
    let response_max_bytes =
        usize::try_from(operation.response_max_bytes()).map_err(|_| ConcreteExecutorUnfinished)?;
    let expectation = OpenCrvsDciV190Rc1Expectation::new(
        &message_id,
        OPENCRVS_SENDER_ID,
        None,
        bound.input().as_str(),
        jwks_max_bytes,
        response_max_bytes,
    )
    .map_err(|_| ConcreteExecutorUnfinished)?;
    let decoder = OpenCrvsDciV190Rc1Decoder::new(expectation, operation.response_decoder());
    let data_permit = dispatch
        .next_data_permit_mut()
        .map_err(|_| ConcreteExecutorUnfinished)?
        .ok_or(ConcreteExecutorUnfinished)?;
    let result = fence
        .authorize_and_dispatch(data_permit, operation.id(), |deadline| async move {
            let response = match data_destination
                .send_with_deadline(data_request, deadline)
                .await
            {
                Ok(response) => response,
                Err(_) => {
                    return super::InnerDispatchResult::Known(
                        ConcreteExecutorProof::known_failure(KnownFailureClass::SourceUnavailable),
                    );
                }
            };
            let status = response.status().as_u16();
            if status != 200 {
                return super::InnerDispatchResult::Known(ConcreteExecutorProof::known_failure(
                    map_unaccepted_status(status),
                ));
            }
            if response.require_json_content_type().is_err() {
                return super::InnerDispatchResult::Known(ConcreteExecutorProof::known_failure(
                    KnownFailureClass::ResponseContractViolation,
                ));
            }
            let response_body = match response.read_bounded(response_max_bytes).await {
                Ok(body) => body,
                Err(error) => {
                    return super::InnerDispatchResult::Known(
                        ConcreteExecutorProof::known_failure(map_response_error(error)),
                    );
                }
            };
            let decoded = match decoder.decode(jwks_body, response_body) {
                Ok(decoded) => decoded,
                Err(error) => {
                    return super::InnerDispatchResult::Known(
                        ConcreteExecutorProof::known_failure(map_opencrvs_decode_error(error)),
                    );
                }
            };
            match prepare_public_result(publication, runtime_profile, decoded) {
                Ok(proof) => super::InnerDispatchResult::Known(proof),
                Err(PublicResultPreparationError::KnownFailure(failure)) => {
                    super::InnerDispatchResult::Known(ConcreteExecutorProof::known_failure(failure))
                }
                Err(PublicResultPreparationError::Unfinished) => {
                    super::InnerDispatchResult::Unfinished
                }
            }
        })
        .await
        .map_err(|_| ConcreteExecutorUnfinished)?;
    drop(quota);
    match result {
        super::InnerDispatchResult::Known(proof) => Ok(proof),
        super::InnerDispatchResult::Unfinished => Err(ConcreteExecutorUnfinished),
    }
}

const fn map_opencrvs_decode_error(error: OpenCrvsDciV190Rc1DecodeError) -> KnownFailureClass {
    match error {
        OpenCrvsDciV190Rc1DecodeError::CardinalityViolation => {
            KnownFailureClass::CardinalityViolation
        }
        OpenCrvsDciV190Rc1DecodeError::SourceRejected => KnownFailureClass::SourceUnavailable,
        OpenCrvsDciV190Rc1DecodeError::JwksTooLarge
        | OpenCrvsDciV190Rc1DecodeError::ResponseTooLarge
        | OpenCrvsDciV190Rc1DecodeError::InvalidJwks
        | OpenCrvsDciV190Rc1DecodeError::InvalidSignedResponse
        | OpenCrvsDciV190Rc1DecodeError::SigningKeyRejected
        | OpenCrvsDciV190Rc1DecodeError::SignatureVerificationFailed
        | OpenCrvsDciV190Rc1DecodeError::SignedPayloadMismatch
        | OpenCrvsDciV190Rc1DecodeError::EnvelopeContractViolation
        | OpenCrvsDciV190Rc1DecodeError::CorrelationViolation
        | OpenCrvsDciV190Rc1DecodeError::IdentityViolation
        | OpenCrvsDciV190Rc1DecodeError::SelectorBindingViolation
        | OpenCrvsDciV190Rc1DecodeError::PaginationViolation
        | OpenCrvsDciV190Rc1DecodeError::RecordContractViolation => {
            KnownFailureClass::ResponseContractViolation
        }
    }
}
