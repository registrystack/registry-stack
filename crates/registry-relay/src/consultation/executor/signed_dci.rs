// SPDX-License-Identifier: Apache-2.0
//! Product-neutral signed DCI exact-search capability.
//!
//! The reviewed pack supplies protocol identities, fixed paths, locale,
//! cardinality, and the named JWKS verification operation. The executor owns
//! OAuth, JWS/JWKS verification, correlation, and closed result release.

use std::collections::BTreeMap;

use registry_platform_httputil::destination::signed_dci::{
    remaining_signed_dci_body_limit, SignedDciDecodeError, SignedDciDecoder,
    SignedDciExactComponent, SignedDciExpectation,
};
use registry_platform_httputil::destination::DataDestinationBody;
use serde_json::Value;
use time::OffsetDateTime;
use ulid::Ulid;

use crate::rhai_worker::{DciSearchOptions, HostFailure, SourceResponse};
use crate::source_plan::codec::dci::{
    DciExactAndComponentInput, DciExactAndSearchRequestInput, DciExactSearchRequest,
    DciExactSearchRequestInput,
};
use crate::source_plan::runtime_profile::CompiledConsentProfile;
use crate::source_plan::{
    CompiledDciSelector, CompiledOAuthSourceCredentialProvider, CompiledProjectionMechanism,
    CompiledRequestCodec, CompiledResponseNormalization, CompiledSelectorLocation,
    CompiledSourceAuth, CompiledSourcePlan, ReadMethod, SourcePlanKind,
};
use crate::state_plane::{
    AuditedConsultationDispatch, KnownFailureClass, PostgresServingFence, QuotaGrant,
};

use super::{
    map_response_error, map_unaccepted_status, operation_deadline, prepare_public_result,
    ConcreteExecutorActivationError, ConcreteExecutorProof, ConcreteExecutorUnfinished,
    PublicResultPreparationError,
};
use crate::consultation::audit::PendingPublicationContext;
use crate::consultation::commitments::{
    BoundConsultationExecution, CanonicalDispatchRequestEffect, SealedConsultationExecution,
    TrustedConsultationTime,
};
use crate::consultation::response::PublishableConsultationResponse;

const MAX_SIGNED_DCI_EXACT_SELECTORS: usize = 8;

const fn supported_exact_selector_count(count: usize) -> bool {
    count >= 1 && count <= MAX_SIGNED_DCI_EXACT_SELECTORS
}

enum DataBodyDispatchResult {
    Body(DataDestinationBody),
    KnownFailure(KnownFailureClass),
}

pub(super) struct VerifiedDciSearch {
    pub(super) response: SourceResponse,
    pub(super) source_bytes: u64,
}

pub(super) fn validate_signed_dci_script_activation(
    plan: &CompiledSourcePlan,
) -> Result<bool, ConcreteExecutorActivationError> {
    let mut operations = plan
        .operations()
        .filter(|operation| operation.dci_exact().is_some());
    let Some(operation) = operations.next() else {
        return Ok(false);
    };
    if operations.next().is_some()
        || plan.kind() != SourcePlanKind::SandboxedRhai
        || plan.credential_operation().is_none()
        || plan.credential_destination().is_none()
        || plan.data_destination().is_none()
        || plan.verification_destination().is_none()
        || operation.method() != ReadMethod::ReadOnlyPost
        || operation.auth() != CompiledSourceAuth::OAuthClientCredentials
        || operation.query().len() != 0
        || operation.headers().len() != 0
        || operation.body().is_some()
        || operation.request_codec() != CompiledRequestCodec::DciExactV1
        || operation.request_signer().is_some()
        || !(1..=2).contains(&operation.max_source_records())
        || operation.response().accepted_statuses().collect::<Vec<_>>() != [200]
    {
        return Err(ConcreteExecutorActivationError::UnsupportedPlan);
    }
    let dci = operation
        .dci_exact()
        .ok_or(ConcreteExecutorActivationError::UnsupportedPlan)?;
    match dci.selector() {
        CompiledDciSelector::ExactAnd { components, .. }
            if !components.is_empty()
                && components.len() == plan.inputs().len()
                && components.iter().all(|component| {
                    component.input_index() < plan.inputs().len()
                        && !component.field().is_empty()
                        && !component.response_pointer().is_empty()
                }) => {}
        _ => return Err(ConcreteExecutorActivationError::UnsupportedPlan),
    }
    Ok(true)
}

pub(super) async fn execute_signed_dci_search_call(
    dispatch: &mut AuditedConsultationDispatch,
    bound: &BoundConsultationExecution<'_>,
    fence: &PostgresServingFence,
    credentials: &CompiledOAuthSourceCredentialProvider,
    options: DciSearchOptions,
    remaining_source_bytes: u64,
) -> Result<VerifiedDciSearch, HostFailure> {
    if !validate_signed_dci_script_activation(bound.plan())
        .map_err(|_| HostFailure::ContractViolation)?
        || !options.parameters.is_empty()
    {
        return Err(HostFailure::ContractViolation);
    }
    let operation = bound
        .plan()
        .operations()
        .find(|operation| operation.dci_exact().is_some())
        .ok_or(HostFailure::ContractViolation)?;
    let dci = operation
        .dci_exact()
        .ok_or(HostFailure::ContractViolation)?;
    let jwks_operation = dci.verification();
    let data_destination = bound
        .plan()
        .data_destination()
        .ok_or(HostFailure::ContractViolation)?;
    let verification_destination = bound
        .plan()
        .verification_destination()
        .ok_or(HostFailure::ContractViolation)?;

    let component_values = match dci.selector() {
        CompiledDciSelector::ExactAnd { components, .. } => {
            let expected_names = components
                .iter()
                .map(|component| {
                    bound
                        .plan()
                        .inputs()
                        .nth(component.input_index())
                        .map(|input| input.name())
                        .ok_or(HostFailure::ContractViolation)
                })
                .collect::<Result<Vec<_>, _>>()?;
            if options.selectors.len() != expected_names.len()
                || options
                    .selectors
                    .keys()
                    .map(String::as_str)
                    .ne(expected_names.iter().copied())
            {
                return Err(HostFailure::ContractViolation);
            }
            components
                .iter()
                .zip(expected_names)
                .map(|(component, name)| {
                    options
                        .selectors
                        .get(name)
                        .and_then(Value::as_str)
                        .filter(|value| !value.is_empty())
                        .map(|value| (component, value))
                        .ok_or(HostFailure::ContractViolation)
                })
                .collect::<Result<Vec<_>, _>>()?
        }
    };

    let message_id = Ulid::new().to_string();
    let sampled = TrustedConsultationTime::sample().map_err(|_| HostFailure::SourceUnavailable)?;
    let timestamp_nanos = i128::from(sampled.unix_ms())
        .checked_mul(1_000_000)
        .ok_or(HostFailure::SourceUnavailable)?;
    let message_timestamp = OffsetDateTime::from_unix_timestamp_nanos(timestamp_nanos)
        .map_err(|_| HostFailure::SourceUnavailable)?;
    let request_components = component_values
        .iter()
        .map(|(component, value)| DciExactAndComponentInput {
            field: component.field(),
            value,
        })
        .collect::<Vec<_>>();
    let dci_request = match dci.selector() {
        CompiledDciSelector::ExactAnd {
            identifier_type: Some(identifier_type),
            ..
        } => DciExactSearchRequest::try_new(DciExactSearchRequestInput {
            protocol_version: dci.protocol_version(),
            message_id: &message_id,
            message_timestamp,
            sender_id: dci.sender_id(),
            receiver_id: dci.receiver_id(),
            registry_type: dci.registry_type(),
            registry_event_type: dci.registry_event_type(),
            record_type: dci.record_type(),
            identifier_type,
            selector: component_values
                .first()
                .map(|(_, value)| *value)
                .ok_or(HostFailure::ContractViolation)?,
            requested_max: operation.max_source_records(),
            page_number: dci.page_number(),
            signature: None,
        }),
        CompiledDciSelector::ExactAnd {
            identifier_type: None,
            ..
        } => DciExactSearchRequest::try_new_exact_and(DciExactAndSearchRequestInput {
            protocol_version: dci.protocol_version(),
            message_id: &message_id,
            message_timestamp,
            sender_id: dci.sender_id(),
            receiver_id: dci.receiver_id(),
            registry_type: dci.registry_type(),
            registry_event_type: dci.registry_event_type(),
            record_type: dci.record_type(),
            components: &request_components,
            requested_max: operation.max_source_records(),
            page_number: dci.page_number(),
            signature: None,
        }),
    }
    .map_err(|_| HostFailure::ContractViolation)?;
    let request_body = dci_request
        .to_json_body()
        .map_err(|_| HostFailure::ContractViolation)?;
    if request_body.as_bytes().len()
        > usize::try_from(operation.request_max_bytes())
            .map_err(|_| HostFailure::ContractViolation)?
    {
        return Err(HostFailure::BudgetExceeded);
    }

    let token = match super::execute_oauth_credential(dispatch, bound, fence, credentials)
        .await
        .map_err(|_| HostFailure::SourceUnavailable)?
    {
        super::CredentialDispatchResultV1::Token(token) => token,
        super::CredentialDispatchResultV1::KnownFailure(_) => return Err(HostFailure::SourceAuth),
    };
    let jwks_request = jwks_operation
        .transport_template()
        .render(&[], &[], None, None)
        .map_err(|_| HostFailure::ContractViolation)?;
    let jwks_max_bytes =
        usize::try_from(u64::from(jwks_operation.response_max_bytes()).min(remaining_source_bytes))
            .map_err(|_| HostFailure::ContractViolation)?;
    if jwks_max_bytes == 0 {
        return Err(HostFailure::BudgetExceeded);
    }
    let jwks_commitment = dispatch
        .commit_request_effect(
            CanonicalDispatchRequestEffect::try_from_complete_value(
                jwks_request.noncredential_effect_value(verification_destination.origin_id()),
            )
            .map_err(|_| HostFailure::ContractViolation)?,
        )
        .map_err(|_| HostFailure::ContractViolation)?;
    let jwks_permit = dispatch
        .next_data_permit_mut()
        .map_err(|_| HostFailure::ContractViolation)?
        .ok_or(HostFailure::BudgetExceeded)?;
    let jwks_body = fence
        .authorize_and_dispatch(jwks_permit, jwks_commitment, |deadline| async move {
            let deadline = operation_deadline(deadline, jwks_operation.request_timeout_ms())
                .map_err(|_| HostFailure::SourceUnavailable)?;
            let response = verification_destination
                .send_with_deadline(jwks_request, deadline)
                .await
                .map_err(|_| HostFailure::SourceUnavailable)?;
            if response.status().as_u16() != 200 {
                return Err(HostFailure::SourceUnavailable);
            }
            response
                .require_json_content_type()
                .map_err(|_| HostFailure::ContractViolation)?;
            response.read_bounded(jwks_max_bytes).await.map_err(|error| {
                if matches!(error, registry_platform_httputil::destination::DestinationResponseError::BodyTooLarge) {
                    HostFailure::BudgetExceeded
                } else {
                    HostFailure::SourceUnavailable
                }
            })
        })
        .await
        .map_err(|_| HostFailure::SourceUnavailable)??;
    let authorization = token
        .bearer_authorization()
        .map_err(|_| HostFailure::SourceAuth)?;
    let data_request = operation
        .transport_template()
        .render_zeroizing(
            &[],
            &[],
            Some(authorization),
            Some(request_body.into_zeroizing_bytes()),
        )
        .map_err(|_| HostFailure::ContractViolation)?;
    let response_max_bytes = remaining_signed_dci_body_limit(
        &jwks_body,
        remaining_source_bytes,
        operation.response_max_bytes(),
    )
    .map_err(|_| HostFailure::BudgetExceeded)?;
    let expectation_components = component_values
        .iter()
        .map(|(component, value)| SignedDciExactComponent {
            response_pointer: component.response_pointer(),
            expected_value: value,
        })
        .collect::<Vec<_>>();
    let expectation = match dci.selector() {
        CompiledDciSelector::ExactAnd {
            identifier_type: Some(identifier_type),
            ..
        } => SignedDciExpectation::new_idtype_value(
            &message_id,
            dci.sender_id(),
            dci.receiver_id(),
            component_values
                .first()
                .map(|(_, value)| *value)
                .ok_or(HostFailure::ContractViolation)?,
            dci.protocol_version(),
            dci.registry_type().ok_or(HostFailure::ContractViolation)?,
            dci.record_type().ok_or(HostFailure::ContractViolation)?,
            identifier_type,
            dci.locale(),
            u64::from(dci.page_number()),
            u64::from(operation.max_source_records()),
            jwks_max_bytes,
            response_max_bytes,
        ),
        CompiledDciSelector::ExactAnd {
            identifier_type: None,
            ..
        } => SignedDciExpectation::new_exact_and(
            &message_id,
            dci.sender_id(),
            dci.receiver_id(),
            &expectation_components,
            dci.protocol_version(),
            dci.registry_type().ok_or(HostFailure::ContractViolation)?,
            dci.record_type().ok_or(HostFailure::ContractViolation)?,
            dci.locale(),
            u64::from(dci.page_number()),
            u64::from(operation.max_source_records()),
            jwks_max_bytes,
            response_max_bytes,
        ),
    }
    .map_err(|_| HostFailure::ContractViolation)?;
    let decoder = SignedDciDecoder::new(expectation, operation.response_decoder());
    let data_commitment = dispatch
        .commit_request_effect(
            CanonicalDispatchRequestEffect::try_from_complete_value(
                data_request.noncredential_effect_value(data_destination.origin_id()),
            )
            .map_err(|_| HostFailure::ContractViolation)?,
        )
        .map_err(|_| HostFailure::ContractViolation)?;
    let data_permit = dispatch
        .next_data_permit_mut()
        .map_err(|_| HostFailure::ContractViolation)?
        .ok_or(HostFailure::BudgetExceeded)?;
    let (payload, source_bytes) = fence
        .authorize_and_dispatch(data_permit, data_commitment, |deadline| async move {
            let deadline = operation_deadline(deadline, operation.request_timeout_ms())
                .map_err(|_| HostFailure::SourceUnavailable)?;
            let response = data_destination
                .send_with_deadline(data_request, deadline)
                .await
                .map_err(|_| HostFailure::SourceUnavailable)?;
            match response.status().as_u16() {
                401 | 403 => return Err(HostFailure::SourceAuth),
                429 => return Err(HostFailure::SourceRateLimited),
                200 => {}
                _ => return Err(HostFailure::SourceUnavailable),
            }
            response
                .require_json_content_type()
                .map_err(|_| HostFailure::ContractViolation)?;
            let response_body = response.read_bounded(response_max_bytes).await.map_err(|error| {
                if matches!(error, registry_platform_httputil::destination::DestinationResponseError::BodyTooLarge) {
                    HostFailure::BudgetExceeded
                } else {
                    HostFailure::SourceUnavailable
                }
            })?;
            let (payload, source_bytes) = decoder
                .decode_verified_payload_with_encoded_bytes(jwks_body, response_body)
                .map_err(|_| HostFailure::ContractViolation)?;
            let source_bytes = u64::try_from(source_bytes)
                .map_err(|_| HostFailure::BudgetExceeded)?;
            Ok((payload, source_bytes))
        })
        .await
        .map_err(|_| HostFailure::SourceUnavailable)??;
    if source_bytes > bound.plan().limits().operation().max_source_bytes {
        return Err(HostFailure::BudgetExceeded);
    }
    Ok(VerifiedDciSearch {
        response: SourceResponse {
            status: 200,
            body: payload,
            headers: BTreeMap::new(),
        },
        source_bytes,
    })
}

pub(super) fn validate_signed_dci_exact_activation(
    plan: &CompiledSourcePlan,
) -> Result<(), ConcreteExecutorActivationError> {
    if plan.kind() != SourcePlanKind::BoundedHttp
        || !supported_exact_selector_count(plan.inputs().len())
        || plan.operations().len() != 1
        || plan.steps().len() != 1
        || plan.compiled_steps().len() != 1
        || plan.credential_operation().is_none()
        || plan.credential_destination().is_none()
        || plan.data_destination().is_none()
        || plan.verification_destination().is_none()
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
    let dci = operation
        .dci_exact()
        .ok_or(ConcreteExecutorActivationError::UnsupportedPlan)?;
    let jwks = dci.verification();
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
        || operation.auth() != CompiledSourceAuth::OAuthClientCredentials
        || operation.query().len() != 0
        || operation.headers().len() != 0
        || operation.body().is_some()
        || operation.request_codec() != CompiledRequestCodec::DciExactV1
        || operation.request_signer().is_some()
        || !(1..=2).contains(&operation.max_source_records())
        || operation.projection() != &CompiledProjectionMechanism::BoundedFullRecord
        || operation.response().normalization() != CompiledResponseNormalization::ArrayProbeTwo
        || operation.response().accepted_statuses().collect::<Vec<_>>() != [200]
    {
        return Err(ConcreteExecutorActivationError::UnsupportedPlan);
    }

    let selector_valid = match dci.selector() {
        CompiledDciSelector::ExactAnd {
            components,
            identifier_type,
        } => {
            components.len() == plan.inputs().len()
                && identifier_type
                    .as_ref()
                    .is_none_or(|_| components.len() == 1)
                && components
                    .iter()
                    .enumerate()
                    .all(|(index, component)| component.input_index() == index)
                && matches!(
                    operation.selector().location(),
                    CompiledSelectorLocation::DciExactPredicate
                )
        }
    };
    if !selector_valid || plan.inputs().any(|input| input.name().is_empty()) {
        return Err(ConcreteExecutorActivationError::UnsupportedPlan);
    }

    let jwks_max_bytes = usize::try_from(jwks.response_max_bytes())
        .map_err(|_| ConcreteExecutorActivationError::UnsupportedPlan)?;
    let response_max_bytes = usize::try_from(operation.response_max_bytes())
        .map_err(|_| ConcreteExecutorActivationError::UnsupportedPlan)?;
    let expectation_valid = match dci.selector() {
        CompiledDciSelector::ExactAnd {
            components: _,
            identifier_type: Some(identifier_type),
        } => SignedDciExpectation::new_idtype_value(
            "01JZ0000000000000000000000",
            dci.sender_id(),
            dci.receiver_id(),
            "1234567890",
            dci.protocol_version(),
            dci.registry_type()
                .ok_or(ConcreteExecutorActivationError::UnsupportedPlan)?,
            dci.record_type()
                .ok_or(ConcreteExecutorActivationError::UnsupportedPlan)?,
            identifier_type,
            dci.locale(),
            u64::from(dci.page_number()),
            u64::from(operation.max_source_records()),
            jwks_max_bytes,
            response_max_bytes,
        )
        .is_ok(),
        CompiledDciSelector::ExactAnd {
            components,
            identifier_type: None,
        } => {
            let samples = components
                .iter()
                .map(|component| SignedDciExactComponent {
                    response_pointer: component.response_pointer(),
                    expected_value: "sample",
                })
                .collect::<Vec<_>>();
            SignedDciExpectation::new_exact_and(
                "01JZ0000000000000000000000",
                dci.sender_id(),
                dci.receiver_id(),
                &samples,
                dci.protocol_version(),
                dci.registry_type()
                    .ok_or(ConcreteExecutorActivationError::UnsupportedPlan)?,
                dci.record_type()
                    .ok_or(ConcreteExecutorActivationError::UnsupportedPlan)?,
                dci.locale(),
                u64::from(dci.page_number()),
                u64::from(operation.max_source_records()),
                jwks_max_bytes,
                response_max_bytes,
            )
            .is_ok()
        }
    };
    if !expectation_valid {
        return Err(ConcreteExecutorActivationError::UnsupportedPlan);
    }
    Ok(())
}

pub(super) async fn execute_signed_dci_exact(
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
    execute_signed_dci_exact_bound(dispatch, bound, publication, quota, fence, credentials).await
}

pub(super) async fn execute_signed_dci_exact_bound(
    dispatch: &mut AuditedConsultationDispatch,
    bound: BoundConsultationExecution<'_>,
    publication: PendingPublicationContext,
    quota: QuotaGrant,
    fence: &PostgresServingFence,
    credentials: &CompiledOAuthSourceCredentialProvider,
) -> Result<ConcreteExecutorProof<PublishableConsultationResponse>, ConcreteExecutorUnfinished> {
    validate_signed_dci_exact_activation(bound.plan()).map_err(|_| ConcreteExecutorUnfinished)?;
    let operation = bound
        .plan()
        .operations()
        .next()
        .ok_or(ConcreteExecutorUnfinished)?;
    let dci = operation.dci_exact().ok_or(ConcreteExecutorUnfinished)?;
    let jwks_operation = dci.verification();
    let data_destination = bound
        .plan()
        .data_destination()
        .ok_or(ConcreteExecutorUnfinished)?;
    let verification_destination = bound
        .plan()
        .verification_destination()
        .ok_or(ConcreteExecutorUnfinished)?;
    let runtime_profile = bound.plan().runtime_profile();

    let message_id = publication.consultation_id().to_canonical_string();
    let sampled = TrustedConsultationTime::sample().map_err(|_| ConcreteExecutorUnfinished)?;
    let timestamp_nanos = i128::from(sampled.unix_ms())
        .checked_mul(1_000_000)
        .ok_or(ConcreteExecutorUnfinished)?;
    let message_timestamp = OffsetDateTime::from_unix_timestamp_nanos(timestamp_nanos)
        .map_err(|_| ConcreteExecutorUnfinished)?;
    let request_components = match dci.selector() {
        CompiledDciSelector::ExactAnd { components, .. } => components
            .iter()
            .map(|component| {
                Ok(DciExactAndComponentInput {
                    field: component.field(),
                    value: bound
                        .input(component.input_index())
                        .ok_or(ConcreteExecutorUnfinished)?
                        .as_str(),
                })
            })
            .collect::<Result<Vec<_>, ConcreteExecutorUnfinished>>()?,
    };
    let dci_request = match dci.selector() {
        CompiledDciSelector::ExactAnd {
            identifier_type: Some(identifier_type),
            ..
        } => DciExactSearchRequest::try_new(DciExactSearchRequestInput {
            protocol_version: dci.protocol_version(),
            message_id: &message_id,
            message_timestamp,
            sender_id: dci.sender_id(),
            receiver_id: dci.receiver_id(),
            registry_type: dci.registry_type(),
            registry_event_type: dci.registry_event_type(),
            record_type: dci.record_type(),
            identifier_type,
            selector: bound.input(0).ok_or(ConcreteExecutorUnfinished)?.as_str(),
            requested_max: operation.max_source_records(),
            page_number: dci.page_number(),
            signature: None,
        }),
        CompiledDciSelector::ExactAnd {
            identifier_type: None,
            ..
        } => DciExactSearchRequest::try_new_exact_and(DciExactAndSearchRequestInput {
            protocol_version: dci.protocol_version(),
            message_id: &message_id,
            message_timestamp,
            sender_id: dci.sender_id(),
            receiver_id: dci.receiver_id(),
            registry_type: dci.registry_type(),
            registry_event_type: dci.registry_event_type(),
            record_type: dci.record_type(),
            components: &request_components,
            requested_max: operation.max_source_records(),
            page_number: dci.page_number(),
            signature: None,
        }),
    }
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

    let token = match super::execute_oauth_credential(dispatch, &bound, fence, credentials).await? {
        super::CredentialDispatchResultV1::Token(token) => token,
        super::CredentialDispatchResultV1::KnownFailure(failure) => {
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
    let jwks_commitment = dispatch
        .commit_request_effect(
            CanonicalDispatchRequestEffect::try_from_complete_value(
                jwks_request.noncredential_effect_value(verification_destination.origin_id()),
            )
            .map_err(|_| ConcreteExecutorUnfinished)?,
        )
        .map_err(|_| ConcreteExecutorUnfinished)?;
    let jwks_permit = dispatch
        .next_data_permit_mut()
        .map_err(|_| ConcreteExecutorUnfinished)?
        .ok_or(ConcreteExecutorUnfinished)?;
    let jwks_result = fence
        .authorize_and_dispatch(jwks_permit, jwks_commitment, |deadline| async move {
            let deadline = match operation_deadline(deadline, jwks_operation.request_timeout_ms()) {
                Ok(deadline) => deadline,
                Err(_) => {
                    return DataBodyDispatchResult::KnownFailure(
                        KnownFailureClass::SourceUnavailable,
                    );
                }
            };
            let response = match verification_destination
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

    let authorization = token
        .bearer_authorization()
        .map_err(|_| ConcreteExecutorUnfinished)?;
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
    let expectation_components = match dci.selector() {
        CompiledDciSelector::ExactAnd { components, .. } => components
            .iter()
            .map(|component| {
                Ok(SignedDciExactComponent {
                    response_pointer: component.response_pointer(),
                    expected_value: bound
                        .input(component.input_index())
                        .ok_or(ConcreteExecutorUnfinished)?
                        .as_str(),
                })
            })
            .collect::<Result<Vec<_>, ConcreteExecutorUnfinished>>()?,
    };
    let expectation = match dci.selector() {
        CompiledDciSelector::ExactAnd {
            identifier_type: Some(identifier_type),
            ..
        } => SignedDciExpectation::new_idtype_value(
            &message_id,
            dci.sender_id(),
            dci.receiver_id(),
            bound.input(0).ok_or(ConcreteExecutorUnfinished)?.as_str(),
            dci.protocol_version(),
            dci.registry_type().ok_or(ConcreteExecutorUnfinished)?,
            dci.record_type().ok_or(ConcreteExecutorUnfinished)?,
            identifier_type,
            dci.locale(),
            u64::from(dci.page_number()),
            u64::from(operation.max_source_records()),
            jwks_max_bytes,
            response_max_bytes,
        ),
        CompiledDciSelector::ExactAnd {
            identifier_type: None,
            ..
        } => SignedDciExpectation::new_exact_and(
            &message_id,
            dci.sender_id(),
            dci.receiver_id(),
            &expectation_components,
            dci.protocol_version(),
            dci.registry_type().ok_or(ConcreteExecutorUnfinished)?,
            dci.record_type().ok_or(ConcreteExecutorUnfinished)?,
            dci.locale(),
            u64::from(dci.page_number()),
            u64::from(operation.max_source_records()),
            jwks_max_bytes,
            response_max_bytes,
        ),
    }
    .map_err(|_| ConcreteExecutorUnfinished)?;
    let decoder = SignedDciDecoder::new(expectation, operation.response_decoder());
    let data_commitment = dispatch
        .commit_request_effect(
            CanonicalDispatchRequestEffect::try_from_complete_value(
                data_request.noncredential_effect_value(data_destination.origin_id()),
            )
            .map_err(|_| ConcreteExecutorUnfinished)?,
        )
        .map_err(|_| ConcreteExecutorUnfinished)?;
    let data_permit = dispatch
        .next_data_permit_mut()
        .map_err(|_| ConcreteExecutorUnfinished)?
        .ok_or(ConcreteExecutorUnfinished)?;
    let result = fence
        .authorize_and_dispatch(data_permit, data_commitment, |deadline| async move {
            let deadline = match operation_deadline(deadline, operation.request_timeout_ms()) {
                Ok(deadline) => deadline,
                Err(_) => {
                    return super::InnerDispatchResult::Known(Box::new(
                        ConcreteExecutorProof::known_failure(KnownFailureClass::SourceUnavailable),
                    ));
                }
            };
            let response = match data_destination
                .send_with_deadline(data_request, deadline)
                .await
            {
                Ok(response) => response,
                Err(_) => {
                    return super::InnerDispatchResult::Known(Box::new(
                        ConcreteExecutorProof::known_failure(KnownFailureClass::SourceUnavailable),
                    ));
                }
            };
            let status = response.status().as_u16();
            if status != 200 {
                return super::InnerDispatchResult::Known(Box::new(
                    ConcreteExecutorProof::known_failure(map_unaccepted_status(status)),
                ));
            }
            if response.require_json_content_type().is_err() {
                return super::InnerDispatchResult::Known(Box::new(
                    ConcreteExecutorProof::known_failure(
                        KnownFailureClass::ResponseContractViolation,
                    ),
                ));
            }
            let response_body = match response.read_bounded(response_max_bytes).await {
                Ok(body) => body,
                Err(error) => {
                    return super::InnerDispatchResult::Known(Box::new(
                        ConcreteExecutorProof::known_failure(map_response_error(error)),
                    ));
                }
            };
            let decoded = match decoder.decode(jwks_body, response_body) {
                Ok(decoded) => decoded,
                Err(error) => {
                    return super::InnerDispatchResult::Known(Box::new(
                        ConcreteExecutorProof::known_failure(map_signed_dci_decode_error(error)),
                    ));
                }
            };
            match prepare_public_result(publication, runtime_profile, decoded) {
                Ok(proof) => super::InnerDispatchResult::Known(Box::new(proof)),
                Err(PublicResultPreparationError::KnownFailure(failure)) => {
                    super::InnerDispatchResult::Known(Box::new(
                        ConcreteExecutorProof::known_failure(failure),
                    ))
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
        super::InnerDispatchResult::Known(proof) => Ok(*proof),
        super::InnerDispatchResult::Unfinished => Err(ConcreteExecutorUnfinished),
    }
}

const fn map_signed_dci_decode_error(error: SignedDciDecodeError) -> KnownFailureClass {
    match error {
        SignedDciDecodeError::CardinalityViolation => KnownFailureClass::CardinalityViolation,
        SignedDciDecodeError::SourceRejected => KnownFailureClass::SourceUnavailable,
        SignedDciDecodeError::JwksTooLarge
        | SignedDciDecodeError::ResponseTooLarge
        | SignedDciDecodeError::InvalidJwks
        | SignedDciDecodeError::InvalidSignedResponse
        | SignedDciDecodeError::SigningKeyRejected
        | SignedDciDecodeError::SignatureVerificationFailed
        | SignedDciDecodeError::SignedPayloadMismatch
        | SignedDciDecodeError::EnvelopeContractViolation
        | SignedDciDecodeError::CorrelationViolation
        | SignedDciDecodeError::IdentityViolation
        | SignedDciDecodeError::SelectorBindingViolation
        | SignedDciDecodeError::PaginationViolation
        | SignedDciDecodeError::RecordContractViolation => {
            KnownFailureClass::ResponseContractViolation
        }
    }
}

#[cfg(test)]
mod tests {
    use super::supported_exact_selector_count;

    #[test]
    fn signed_dci_exact_accepts_eight_selectors_and_rejects_nine() {
        assert!(supported_exact_selector_count(1));
        assert!(supported_exact_selector_count(8));
        assert!(!supported_exact_selector_count(0));
        assert!(!supported_exact_selector_count(9));
    }
}
