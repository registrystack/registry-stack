// SPDX-License-Identifier: Apache-2.0
//! Concrete one-step Basic GET consultation executor.
//!
//! This is deliberately a product journey, not an executor framework. Startup
//! accepts one closed operation shape and runtime consumes the authorization-
//! bound plan/input pair directly through the durable serving fence.

use std::time::Duration;

use registry_platform_httputil::destination::json::{
    ClosedJsonDecodeError, ClosedJsonOutcome, MAX_CLOSED_JSON_ENCODED_BODY_BYTES,
};
use registry_platform_httputil::destination::DestinationResponseError;
use thiserror::Error;

use crate::source_plan::runtime_profile::CompiledConsentProfile;
use crate::source_plan::{
    CompiledBasicSourceCredentialProvider, CompiledRequestCodec, CompiledSelectorLocation,
    CompiledSelectorSource, CompiledSourceAuth, CompiledSourcePlan, CompiledValueExpression,
    ReadMethod, SourcePlanKind,
};
use crate::state_plane::{
    AuditedConsultationDispatch, KnownConsultationCompletionFacts, KnownFailureClass,
    PostgresServingFence, PublicConsultationOutcome, QuotaGrant,
};

use super::audit::PendingPublicationContext;
use super::commitments::{
    BoundConsultationExecution, SealedConsultationExecution, TrustedConsultationTime,
};
use super::response::{ConsultationResponseError, PublishableConsultationResponse};
use super::ConsultationOutcome;

/// Value-free reason an artifact-valid plan cannot be served by the first
/// concrete product journey.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub(crate) enum BasicGetActivationError {
    #[error("consultation plan is outside the first Basic GET serving profile")]
    UnsupportedPlan,
}

/// Proof minted only after one fenced marker reaches a closed, known result.
/// Output and durable completion facts cannot be assembled independently.
pub(super) struct ConcreteExecutorProof<T> {
    output: Option<T>,
    completion_facts: KnownConsultationCompletionFacts,
}

impl<T> ConcreteExecutorProof<T> {
    pub(super) fn into_parts(self) -> (Option<T>, KnownConsultationCompletionFacts) {
        (self.output, self.completion_facts)
    }

    fn known_failure(failure: KnownFailureClass) -> Self {
        Self {
            output: None,
            completion_facts: KnownConsultationCompletionFacts::failure(failure),
        }
    }
}

/// Marker that PostgreSQL, rather than the local process, must classify the
/// terminal state of this already audited dispatch.
pub(super) struct ConcreteExecutorUnfinished;

enum InnerDispatchResult {
    Known(ConcreteExecutorProof<PublishableConsultationResponse>),
    Unfinished,
}

enum PublicResultPreparationError {
    KnownFailure(KnownFailureClass),
    Unfinished,
}

/// Reject every optional compiler shape at activation while retaining those
/// shapes as inert, hash-covered artifacts for later reviewed journeys.
pub(crate) fn validate_basic_get_activation(
    plan: &CompiledSourcePlan,
) -> Result<(), BasicGetActivationError> {
    if plan.kind() != SourcePlanKind::BoundedHttp
        || plan.inputs().len() != 1
        || plan.operations().len() != 1
        || plan.steps().len() != 1
        || plan.compiled_steps().len() != 1
        || plan.credential_operation().is_some()
        || plan.credential_destination().is_some()
        || plan.data_destination().is_none()
        || !matches!(
            plan.runtime_profile().authorization().consent(),
            CompiledConsentProfile::NotRequired
        )
    {
        return Err(BasicGetActivationError::UnsupportedPlan);
    }

    let operation = plan
        .operations()
        .next()
        .ok_or(BasicGetActivationError::UnsupportedPlan)?;
    let step = plan
        .compiled_steps()
        .next()
        .ok_or(BasicGetActivationError::UnsupportedPlan)?;
    if step.condition().is_some()
        || step.condition_source_index().is_some()
        || step.condition_output_slot_index().is_some()
        || !std::ptr::eq(
            plan.steps()
                .next()
                .ok_or(BasicGetActivationError::UnsupportedPlan)?,
            operation,
        )
        || operation.method() != ReadMethod::Get
        || operation.auth() != CompiledSourceAuth::Basic
        || operation.headers().len() != 0
        || operation.body().is_some()
        || operation.request_codec() != CompiledRequestCodec::None
        || operation.request_signer().is_some()
        || operation.response().prior_outputs().len() != 0
        || usize::try_from(operation.response_max_bytes())
            .ok()
            .is_none_or(|limit| limit > MAX_CLOSED_JSON_ENCODED_BODY_BYTES)
    {
        return Err(BasicGetActivationError::UnsupportedPlan);
    }

    let input = plan
        .inputs()
        .next()
        .ok_or(BasicGetActivationError::UnsupportedPlan)?;
    if operation.query().any(|component| {
        matches!(
            component.value(),
            CompiledValueExpression::ConsultationInput { input_index } if *input_index != 0
        ) || matches!(
            component.value(),
            CompiledValueExpression::PriorStepOutput { .. }
        )
    }) {
        return Err(BasicGetActivationError::UnsupportedPlan);
    }

    let (input_index, query_index) = match (
        operation.selector().source(),
        operation.selector().location(),
    ) {
        (
            CompiledSelectorSource::ConsultationInput { input_index },
            CompiledSelectorLocation::Query { component_index },
        ) => (input_index, *component_index),
        _ => return Err(BasicGetActivationError::UnsupportedPlan),
    };
    let selector_component = operation
        .query()
        .nth(query_index)
        .ok_or(BasicGetActivationError::UnsupportedPlan)?;
    if input_index != 0
        || !matches!(
            selector_component.value(),
            CompiledValueExpression::ConsultationInput { input_index: 0 }
        )
        || input.name().is_empty()
    {
        return Err(BasicGetActivationError::UnsupportedPlan);
    }
    let consultation_input_positions = operation
        .query()
        .enumerate()
        .filter_map(|(index, component)| {
            matches!(
                component.value(),
                CompiledValueExpression::ConsultationInput { input_index: 0 }
            )
            .then_some(index)
        })
        .collect::<Vec<_>>();
    if consultation_input_positions.as_slice() != [query_index] {
        return Err(BasicGetActivationError::UnsupportedPlan);
    }
    Ok(())
}

/// Consume one sealed execution after durable attempt persistence and run its
/// sole source call under the exact fence permit.
pub(super) async fn execute_one_step_basic_get(
    dispatch: &mut AuditedConsultationDispatch,
    execution: SealedConsultationExecution<'_>,
    publication: PendingPublicationContext,
    quota: QuotaGrant,
    fence: &PostgresServingFence,
    credentials: &CompiledBasicSourceCredentialProvider,
) -> Result<ConcreteExecutorProof<PublishableConsultationResponse>, ConcreteExecutorUnfinished> {
    let bound = execution
        .into_bound()
        .map_err(|_| ConcreteExecutorUnfinished)?;
    validate_basic_get_activation(bound.plan()).map_err(|_| ConcreteExecutorUnfinished)?;
    let operation = bound
        .plan()
        .operations()
        .next()
        .ok_or(ConcreteExecutorUnfinished)?;
    let query_values = render_query_values(&bound, operation.query())?;
    let request = credentials
        .authorization_for(bound.plan(), operation)
        .and_then(|authorization| {
            authorization.render(&query_values).map_err(|_| {
                crate::source_plan::SourceCredentialProviderError::OperationBindingMismatch
            })
        })
        .map_err(|_| ConcreteExecutorUnfinished)?;
    let destination = bound
        .plan()
        .data_destination()
        .ok_or(ConcreteExecutorUnfinished)?;
    let permit = dispatch
        .next_data_permit_mut()
        .map_err(|_| ConcreteExecutorUnfinished)?
        .ok_or(ConcreteExecutorUnfinished)?;

    let profile = bound.plan().runtime_profile();
    let inner = fence
        .authorize_and_dispatch(permit, operation.id(), |deadline| async move {
            let response = match destination.send_with_deadline(request, deadline).await {
                Ok(response) => response,
                Err(_) => {
                    return InnerDispatchResult::Known(ConcreteExecutorProof::known_failure(
                        KnownFailureClass::SourceUnavailable,
                    ));
                }
            };
            let status = response.status().as_u16();
            if !operation
                .response()
                .accepted_statuses()
                .any(|accepted| accepted == status)
            {
                return InnerDispatchResult::Known(ConcreteExecutorProof::known_failure(
                    map_unaccepted_status(status),
                ));
            }
            let max_bytes = match usize::try_from(operation.response_max_bytes()) {
                Ok(max_bytes) => max_bytes,
                Err(_) => return InnerDispatchResult::Unfinished,
            };
            let body = match response.read_bounded(max_bytes).await {
                Ok(body) => body,
                Err(error) => {
                    return InnerDispatchResult::Known(ConcreteExecutorProof::known_failure(
                        map_response_error(error),
                    ));
                }
            };
            let decoded = match operation.response_decoder().decode(body) {
                Ok(decoded) => decoded,
                Err(error) => {
                    return InnerDispatchResult::Known(ConcreteExecutorProof::known_failure(
                        map_decode_error(error),
                    ));
                }
            };
            match prepare_public_result(publication, profile, decoded) {
                Ok(proof) => InnerDispatchResult::Known(proof),
                Err(PublicResultPreparationError::KnownFailure(failure)) => {
                    InnerDispatchResult::Known(ConcreteExecutorProof::known_failure(failure))
                }
                Err(PublicResultPreparationError::Unfinished) => InnerDispatchResult::Unfinished,
            }
        })
        .await
        .map_err(|_| ConcreteExecutorUnfinished)?;
    drop(quota);
    match inner {
        InnerDispatchResult::Known(proof) => Ok(proof),
        InnerDispatchResult::Unfinished => Err(ConcreteExecutorUnfinished),
    }
}

fn render_query_values<'a>(
    bound: &'a BoundConsultationExecution<'a>,
    expressions: impl ExactSizeIterator<Item = &'a crate::source_plan::CompiledNamedExpression>,
) -> Result<Vec<&'a str>, ConcreteExecutorUnfinished> {
    expressions
        .map(|component| match component.value() {
            CompiledValueExpression::Literal(value) => Ok(value.as_ref()),
            CompiledValueExpression::ConsultationInput { input_index: 0 } => {
                Ok(bound.input().as_str())
            }
            CompiledValueExpression::DeploymentParameter { parameter_index } => bound
                .plan()
                .deployment_parameter_value(*parameter_index)
                .ok_or(ConcreteExecutorUnfinished),
            CompiledValueExpression::ConsultationInput { .. }
            | CompiledValueExpression::PriorStepOutput { .. } => Err(ConcreteExecutorUnfinished),
        })
        .collect()
}

fn prepare_public_result(
    publication: PendingPublicationContext,
    profile: &crate::source_plan::runtime_profile::CompiledRuntimeProfile,
    decoded: ClosedJsonOutcome,
) -> Result<ConcreteExecutorProof<PublishableConsultationResponse>, PublicResultPreparationError> {
    let (outcome, public_outcome, record) = match &decoded {
        ClosedJsonOutcome::NoMatch => (
            ConsultationOutcome::NoMatch,
            PublicConsultationOutcome::NoMatch,
            None,
        ),
        ClosedJsonOutcome::One(record) => (
            ConsultationOutcome::Match,
            PublicConsultationOutcome::Match,
            Some(record),
        ),
        ClosedJsonOutcome::Ambiguous => (
            ConsultationOutcome::Ambiguous,
            PublicConsultationOutcome::Ambiguous,
            None,
        ),
    };
    profile.footprint().validate_outcome(outcome).map_err(|_| {
        PublicResultPreparationError::KnownFailure(KnownFailureClass::ResponseContractViolation)
    })?;
    let acquired_at_unix_ms = TrustedConsultationTime::sample()
        .map_err(|_| PublicResultPreparationError::Unfinished)?
        .unix_ms();
    let output = PublishableConsultationResponse::from_validated_live_result(
        publication.consultation_id(),
        publication.notary_evaluation_id(),
        profile,
        outcome,
        record,
        acquired_at_unix_ms,
    )
    .map_err(|error| match error {
        ConsultationResponseError::InvalidTime => PublicResultPreparationError::Unfinished,
        ConsultationResponseError::Serialization | ConsultationResponseError::ResponseTooLarge => {
            PublicResultPreparationError::KnownFailure(KnownFailureClass::ResponseContractViolation)
        }
    })?;
    let completion_facts =
        KnownConsultationCompletionFacts::public_for_live(public_outcome, acquired_at_unix_ms)
            .map_err(|_| {
                PublicResultPreparationError::KnownFailure(
                    KnownFailureClass::ResponseContractViolation,
                )
            })?;
    Ok(ConcreteExecutorProof {
        output: Some(output),
        completion_facts,
    })
}

const fn map_response_error(error: DestinationResponseError) -> KnownFailureClass {
    match error {
        DestinationResponseError::BodyLimitTooHigh | DestinationResponseError::BodyTooLarge => {
            KnownFailureClass::ResponseContractViolation
        }
        DestinationResponseError::BodyReadFailed | DestinationResponseError::DeadlineExceeded => {
            KnownFailureClass::SourceUnavailable
        }
    }
}

const fn map_unaccepted_status(status: u16) -> KnownFailureClass {
    if matches!(status, 401 | 403) {
        KnownFailureClass::CredentialUnavailable
    } else {
        KnownFailureClass::SourceUnavailable
    }
}

const fn map_decode_error(error: ClosedJsonDecodeError) -> KnownFailureClass {
    match error {
        ClosedJsonDecodeError::CardinalityViolation => KnownFailureClass::CardinalityViolation,
        ClosedJsonDecodeError::InvalidJson
        | ClosedJsonDecodeError::ResponseContractViolation
        | ClosedJsonDecodeError::ProjectionContractViolation => {
            KnownFailureClass::ResponseContractViolation
        }
    }
}

pub(super) fn dispatch_budget(
    plan: &CompiledSourcePlan,
) -> Result<crate::state_plane::DispatchPermitBudget, BasicGetActivationError> {
    validate_basic_get_activation(plan)?;
    crate::state_plane::DispatchPermitBudget::new(Duration::from_millis(u64::from(
        plan.limits().operation().timeout_ms,
    )))
    .map_err(|_| BasicGetActivationError::UnsupportedPlan)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::source_plan::{
        bounded_runtime_vector_plan_fixture, dhis2_duplicate_selector_runtime_vector_plan_fixture,
        dhis2_runtime_vector_plan_fixture, rhai_runtime_vector_plan_fixture,
    };

    #[test]
    fn activation_accepts_only_the_maintained_one_step_basic_get_journey() {
        let dhis2 = dhis2_runtime_vector_plan_fixture();
        assert_eq!(validate_basic_get_activation(&dhis2), Ok(()));
        assert_eq!(
            dispatch_budget(&dhis2)
                .expect("DHIS2 budget")
                .as_milliseconds(),
            5_000
        );

        let oauth = bounded_runtime_vector_plan_fixture();
        assert_eq!(
            validate_basic_get_activation(&oauth),
            Err(BasicGetActivationError::UnsupportedPlan)
        );
        let rhai = rhai_runtime_vector_plan_fixture();
        assert_eq!(
            validate_basic_get_activation(&rhai),
            Err(BasicGetActivationError::UnsupportedPlan)
        );
        let duplicate_selector = dhis2_duplicate_selector_runtime_vector_plan_fixture();
        assert_eq!(
            validate_basic_get_activation(&duplicate_selector),
            Err(BasicGetActivationError::UnsupportedPlan)
        );
    }

    #[test]
    fn response_and_decoder_failures_map_to_the_frozen_terminal_classes() {
        assert_eq!(
            map_unaccepted_status(401),
            KnownFailureClass::CredentialUnavailable
        );
        assert_eq!(
            map_unaccepted_status(403),
            KnownFailureClass::CredentialUnavailable
        );
        assert_eq!(
            map_unaccepted_status(500),
            KnownFailureClass::SourceUnavailable
        );
        assert_eq!(
            map_response_error(DestinationResponseError::BodyTooLarge),
            KnownFailureClass::ResponseContractViolation
        );
        assert_eq!(
            map_response_error(DestinationResponseError::DeadlineExceeded),
            KnownFailureClass::SourceUnavailable
        );
        assert_eq!(
            map_decode_error(ClosedJsonDecodeError::CardinalityViolation),
            KnownFailureClass::CardinalityViolation
        );
        assert_eq!(
            map_decode_error(ClosedJsonDecodeError::ProjectionContractViolation),
            KnownFailureClass::ResponseContractViolation
        );
    }
}
