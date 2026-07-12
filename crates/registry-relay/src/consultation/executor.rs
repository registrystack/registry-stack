// SPDX-License-Identifier: Apache-2.0
//! Closed capability consultation executors.

mod opencrvs;

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use datafusion::execution::context::SessionContext;
use registry_platform_httputil::destination::json::{
    ClosedJsonDecodeError, ClosedJsonOutcome, ProjectedJsonScalar,
    MAX_CLOSED_JSON_ENCODED_BODY_BYTES,
};
use registry_platform_httputil::destination::{
    DestinationResponseError, MAX_DESTINATION_OPERATION_TIMEOUT,
};
use thiserror::Error;
use tokio::sync::Semaphore;
use tokio::time::Instant;
use zeroize::Zeroizing;

use crate::rhai_worker::{
    FactSchema as RhaiFactSchema, FactType as RhaiFactType, TypedValue as RhaiTypedValue,
    WorkerLimits, WorkerProcess, WorkerRequest,
};

use crate::source_backend::{
    execute_snapshot_exact, PublishedSnapshotRegistry, SnapshotExactBackendError,
    SnapshotExactBackendResult,
};
use crate::source_plan::runtime_profile::CompiledConsentProfile;
use crate::source_plan::{
    CompiledBasicSourceCredentialProvider, CompiledBodyTemplate,
    CompiledOAuthSourceCredentialProvider, CompiledOperation, CompiledRequestCodec,
    CompiledRhaiFactType, CompiledScalarShape, CompiledSelectorLocation, CompiledSelectorSource,
    CompiledSourceAuth, CompiledSourcePlan, CompiledStaticBearerSourceCredentialProvider,
    CompiledStatusOutcome, CompiledStepPredicate, CompiledValueExpression, ParsedOAuth2AccessToken,
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
use super::response::{
    ConsultationResponseError, PublishableConsultationResponse, ValidatedFactMap,
};
use super::ConsultationOutcome;

use opencrvs::{execute_signed_dci_exact_bound, validate_signed_dci_exact_activation};

/// Value-free reason an artifact-valid plan cannot be served by a maintained
/// concrete product journey.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub(crate) enum ConcreteExecutorActivationError {
    #[error("consultation plan is outside the maintained concrete serving profiles")]
    UnsupportedPlan,
}

/// Cap one outbound exchange by both its reviewed operation timeout and the
/// shared durable consultation deadline. Multi-exchange journeys may have a
/// larger total budget, but no individual destination call inherits it.
fn operation_deadline(
    consultation_deadline: Instant,
    operation_timeout_ms: u32,
) -> Result<Instant, ConcreteExecutorUnfinished> {
    let operation_deadline = Instant::now()
        .checked_add(Duration::from_millis(u64::from(operation_timeout_ms)))
        .ok_or(ConcreteExecutorUnfinished)?;
    let platform_deadline = Instant::now()
        .checked_add(MAX_DESTINATION_OPERATION_TIMEOUT)
        .ok_or(ConcreteExecutorUnfinished)?;
    Ok(consultation_deadline
        .min(operation_deadline)
        .min(platform_deadline))
}

pub(super) const fn is_anchor_execution_step(
    _operation_index: usize,
    compiled_step_index: Option<usize>,
    execution_position: usize,
    sandboxed_rhai: bool,
) -> bool {
    matches!(compiled_step_index, Some(0)) || (sandboxed_rhai && execution_position == 0)
}

/// Restart-only selection of one fully reviewed product journey.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConcreteExecutorKind {
    SnapshotExact,
    BoundedHttp,
    SandboxedRhai,
}

impl ConcreteExecutorKind {
    pub(crate) fn activate(
        plan: &CompiledSourcePlan,
    ) -> Result<Self, ConcreteExecutorActivationError> {
        if validate_snapshot_exact_activation(plan).is_ok() {
            return Ok(Self::SnapshotExact);
        }
        if validate_sandboxed_rhai_activation(plan).is_ok() {
            return Ok(Self::SandboxedRhai);
        }
        validate_bounded_http_activation(plan)?;
        Ok(Self::BoundedHttp)
    }

    pub(crate) fn permit_counts(
        self,
        plan: &CompiledSourcePlan,
    ) -> Result<(u8, u8), ConcreteExecutorActivationError> {
        let mut credential = 0_u8;
        let mut data = 0_u8;
        for (kind, ordinal, allowed) in plan.runtime_profile().permit_bindings() {
            if allowed.is_empty() {
                return Err(ConcreteExecutorActivationError::UnsupportedPlan);
            }
            match kind {
                "credential" if ordinal == credential => credential += 1,
                "data" if ordinal == data => data += 1,
                _ => return Err(ConcreteExecutorActivationError::UnsupportedPlan),
            }
        }
        (credential <= 1 && data <= 5)
            .then_some((credential, data))
            .ok_or(ConcreteExecutorActivationError::UnsupportedPlan)
    }

    pub(crate) fn dispatch_budget(
        self,
        plan: &CompiledSourcePlan,
    ) -> Result<crate::state_plane::DispatchPermitBudget, ConcreteExecutorActivationError> {
        match self {
            Self::SnapshotExact => validate_snapshot_exact_activation(plan)?,
            Self::BoundedHttp => validate_bounded_http_activation(plan)?,
            Self::SandboxedRhai => validate_sandboxed_rhai_activation(plan)?,
        }
        crate::state_plane::DispatchPermitBudget::new(Duration::from_millis(u64::from(
            plan.limits().operation().timeout_ms,
        )))
        .map_err(|_| ConcreteExecutorActivationError::UnsupportedPlan)
    }
}

fn validate_sandboxed_rhai_activation(
    plan: &CompiledSourcePlan,
) -> Result<(), ConcreteExecutorActivationError> {
    if !cfg!(target_os = "linux") {
        return Err(ConcreteExecutorActivationError::UnsupportedPlan);
    }
    if plan.kind() != SourcePlanKind::SandboxedRhai
        || plan.inputs().len() != 1
        || !(1..=5).contains(&plan.operations().len())
        || plan.steps().len() != 0
        || plan.rhai_program().is_none()
        || plan
            .runtime_profile()
            .dispatch()
            .sandboxed_rhai_limits()
            .is_none()
        || plan.data_destination().is_none()
        || !matches!(
            plan.runtime_profile().authorization().consent(),
            CompiledConsentProfile::NotRequired
        )
        || plan.operations().any(|operation| {
            operation.request_codec() != CompiledRequestCodec::None
                || operation.request_signer().is_some()
        })
    {
        return Err(ConcreteExecutorActivationError::UnsupportedPlan);
    }
    let oauth = plan
        .operations()
        .any(|operation| operation.auth() == CompiledSourceAuth::OAuthClientCredentials);
    if oauth != plan.credential_operation().is_some()
        || oauth != plan.credential_destination().is_some()
    {
        return Err(ConcreteExecutorActivationError::UnsupportedPlan);
    }
    let (_, data) = ConcreteExecutorKind::SandboxedRhai.permit_counts(plan)?;
    (data > 0)
        .then_some(())
        .ok_or(ConcreteExecutorActivationError::UnsupportedPlan)
}

/// Accept only the compiler-sealed local exact snapshot shape.
pub(crate) fn validate_snapshot_exact_activation(
    plan: &CompiledSourcePlan,
) -> Result<(), ConcreteExecutorActivationError> {
    let binding = plan
        .snapshot_binding()
        .ok_or(ConcreteExecutorActivationError::UnsupportedPlan)?;
    if plan.kind() != SourcePlanKind::SnapshotExact
        || !(1..=4).contains(&plan.inputs().len())
        || plan.operations().len() != 0
        || plan.steps().len() != 0
        || plan.compiled_steps().len() != 0
        || plan.credential_operation().is_some()
        || plan.data_destination().is_some()
        || plan.credential_destination().is_some()
        || plan.credential_reference().is_some()
        || binding.keys().len() != plan.inputs().len()
        || !binding
            .keys()
            .zip(plan.inputs())
            .all(|((key_input, _), input)| key_input == input.name())
        || !binding.keys_use_utf8_binary_equality()
        || binding.projection().len() == 0
        || !matches!(
            plan.runtime_profile().authorization().consent(),
            CompiledConsentProfile::NotRequired
        )
    {
        return Err(ConcreteExecutorActivationError::UnsupportedPlan);
    }
    Ok(())
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
    Known(Box<ConcreteExecutorProof<PublishableConsultationResponse>>),
    Unfinished,
}

enum PublicResultPreparationError {
    KnownFailure(KnownFailureClass),
    Unfinished,
}

/// Accept every production-executable BoundedHttp shape. Protocol codecs that
/// require an unavailable signing or verification capability stay rejected at
/// activation rather than becoming inert compiler output.
pub(crate) fn validate_bounded_http_activation(
    plan: &CompiledSourcePlan,
) -> Result<(), ConcreteExecutorActivationError> {
    if plan.kind() != SourcePlanKind::BoundedHttp
        || !(1..=5).contains(&plan.operations().len())
        || plan.steps().len() != plan.operations().len()
        || plan.compiled_steps().len() != plan.steps().len()
        || plan.data_destination().is_none()
        || !matches!(
            plan.runtime_profile().authorization().consent(),
            CompiledConsentProfile::NotRequired
        )
    {
        return Err(ConcreteExecutorActivationError::UnsupportedPlan);
    }
    if plan.operations().any(|operation| {
        let codec_supported = match operation.request_codec() {
            CompiledRequestCodec::None => operation.body().is_none(),
            CompiledRequestCodec::Json => operation.body().is_some(),
            CompiledRequestCodec::DciExactV1 => validate_signed_dci_exact_activation(plan).is_ok(),
            CompiledRequestCodec::FhirR4Search => {
                operation.body().is_none() && operation.fhir_r4_search().is_some()
            }
        };
        !codec_supported || operation.request_signer().is_some()
    }) {
        return Err(ConcreteExecutorActivationError::UnsupportedPlan);
    }
    let oauth = plan
        .operations()
        .any(|operation| operation.auth() == CompiledSourceAuth::OAuthClientCredentials);
    if oauth != plan.credential_operation().is_some()
        || oauth != plan.credential_destination().is_some()
    {
        return Err(ConcreteExecutorActivationError::UnsupportedPlan);
    }
    let kind = ConcreteExecutorKind::BoundedHttp;
    let (_, data) = kind.permit_counts(plan)?;
    if data == 0 {
        return Err(ConcreteExecutorActivationError::UnsupportedPlan);
    }
    Ok(())
}

/// Reject every optional compiler shape at activation while retaining those
/// shapes as inert, hash-covered artifacts for later reviewed journeys.
pub(crate) fn validate_basic_get_activation(
    plan: &CompiledSourcePlan,
) -> Result<(), ConcreteExecutorActivationError> {
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
    if step.condition().is_some()
        || step.condition_source_index().is_some()
        || step.condition_output_slot_index().is_some()
        || !std::ptr::eq(
            plan.steps()
                .next()
                .ok_or(ConcreteExecutorActivationError::UnsupportedPlan)?,
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
        return Err(ConcreteExecutorActivationError::UnsupportedPlan);
    }

    let input = plan
        .inputs()
        .next()
        .ok_or(ConcreteExecutorActivationError::UnsupportedPlan)?;
    if operation.query().any(|component| {
        matches!(
            component.value(),
            CompiledValueExpression::ConsultationInput { input_index } if *input_index != 0
        ) || matches!(
            component.value(),
            CompiledValueExpression::PriorStepOutput { .. }
        )
    }) {
        return Err(ConcreteExecutorActivationError::UnsupportedPlan);
    }

    let (input_index, query_index) = match (
        operation.selector().source(),
        operation.selector().location(),
    ) {
        (
            CompiledSelectorSource::ConsultationInput { input_index },
            CompiledSelectorLocation::Query { component_index },
        ) => (input_index, *component_index),
        _ => return Err(ConcreteExecutorActivationError::UnsupportedPlan),
    };
    let selector_component = operation
        .query()
        .nth(query_index)
        .ok_or(ConcreteExecutorActivationError::UnsupportedPlan)?;
    if input_index != 0
        || !matches!(
            selector_component.value(),
            CompiledValueExpression::ConsultationInput { input_index: 0 }
        )
        || input.name().is_empty()
    {
        return Err(ConcreteExecutorActivationError::UnsupportedPlan);
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
        return Err(ConcreteExecutorActivationError::UnsupportedPlan);
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
            authorization
                .render(None, &query_values, &[], None)
                .map_err(|_| {
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
            let deadline = match operation_deadline(deadline, operation.request_timeout_ms()) {
                Ok(deadline) => deadline,
                Err(_) => return InnerDispatchResult::Unfinished,
            };
            let response = match destination.send_with_deadline(request, deadline).await {
                Ok(response) => response,
                Err(_) => {
                    return InnerDispatchResult::Known(Box::new(
                        ConcreteExecutorProof::known_failure(KnownFailureClass::SourceUnavailable),
                    ));
                }
            };
            let status = response.status().as_u16();
            if !operation
                .response()
                .accepted_statuses()
                .any(|accepted| accepted == status)
            {
                return InnerDispatchResult::Known(Box::new(ConcreteExecutorProof::known_failure(
                    map_unaccepted_status(status),
                )));
            }
            let max_bytes = match usize::try_from(operation.response_max_bytes()) {
                Ok(max_bytes) => max_bytes,
                Err(_) => return InnerDispatchResult::Unfinished,
            };
            let body = match response.read_bounded(max_bytes).await {
                Ok(body) => body,
                Err(error) => {
                    return InnerDispatchResult::Known(Box::new(
                        ConcreteExecutorProof::known_failure(map_response_error(error)),
                    ));
                }
            };
            let decoded = match operation.response_decoder().decode(body) {
                Ok(decoded) => decoded,
                Err(error) => {
                    return InnerDispatchResult::Known(Box::new(
                        ConcreteExecutorProof::known_failure(map_decode_error(error)),
                    ));
                }
            };
            match prepare_public_result(publication, profile, decoded) {
                Ok(proof) => InnerDispatchResult::Known(Box::new(proof)),
                Err(PublicResultPreparationError::KnownFailure(failure)) => {
                    InnerDispatchResult::Known(Box::new(ConcreteExecutorProof::known_failure(
                        failure,
                    )))
                }
                Err(PublicResultPreparationError::Unfinished) => InnerDispatchResult::Unfinished,
            }
        })
        .await
        .map_err(|_| ConcreteExecutorUnfinished)?;
    drop(quota);
    match inner {
        InnerDispatchResult::Known(proof) => Ok(*proof),
        InnerDispatchResult::Unfinished => Err(ConcreteExecutorUnfinished),
    }
}

struct OperationMemory {
    prior_outputs: Vec<ProjectedJsonScalar>,
    present: bool,
}

enum CredentialDispatchResultV1 {
    Token(ParsedOAuth2AccessToken),
    KnownFailure(KnownFailureClass),
}

async fn execute_oauth_credential(
    dispatch: &mut AuditedConsultationDispatch,
    bound: &BoundConsultationExecution<'_>,
    fence: &PostgresServingFence,
    credentials: &CompiledOAuthSourceCredentialProvider,
) -> Result<CredentialDispatchResultV1, ConcreteExecutorUnfinished> {
    let operation = bound
        .plan()
        .credential_operation()
        .ok_or(ConcreteExecutorUnfinished)?;
    let destination = bound
        .plan()
        .credential_destination()
        .ok_or(ConcreteExecutorUnfinished)?;
    let request = credentials
        .credentials_for(bound.plan(), operation)
        .and_then(|capability| {
            capability.render().map_err(|_| {
                crate::source_plan::SourceCredentialProviderError::OperationBindingMismatch
            })
        })
        .map_err(|_| ConcreteExecutorUnfinished)?;
    let permit = dispatch
        .credential_permit_mut()
        .map_err(|_| ConcreteExecutorUnfinished)?
        .ok_or(ConcreteExecutorUnfinished)?;
    let parser = operation.parser();
    fence
        .authorize_and_dispatch(permit, operation.id(), |deadline| async move {
            let deadline = match operation_deadline(deadline, operation.request_timeout_ms()) {
                Ok(deadline) => deadline,
                Err(_) => {
                    return CredentialDispatchResultV1::KnownFailure(
                        KnownFailureClass::CredentialUnavailable,
                    )
                }
            };
            let response = match destination.send_with_deadline(request, deadline).await {
                Ok(response) => response,
                Err(_) => {
                    return CredentialDispatchResultV1::KnownFailure(
                        KnownFailureClass::CredentialUnavailable,
                    );
                }
            };
            let status = response.status().as_u16();
            if response.require_json_content_type().is_err() {
                return CredentialDispatchResultV1::KnownFailure(
                    KnownFailureClass::CredentialUnavailable,
                );
            }
            let max_bytes = match usize::try_from(parser.max_response_bytes()) {
                Ok(value) => value,
                Err(_) => {
                    return CredentialDispatchResultV1::KnownFailure(
                        KnownFailureClass::CredentialUnavailable,
                    )
                }
            };
            let body = match response.read_bounded(max_bytes).await {
                Ok(body) => body,
                Err(_) => {
                    return CredentialDispatchResultV1::KnownFailure(
                        KnownFailureClass::CredentialUnavailable,
                    );
                }
            };
            match parser.parse_body(status, body) {
                Ok(token) => CredentialDispatchResultV1::Token(token),
                Err(_) => CredentialDispatchResultV1::KnownFailure(
                    KnownFailureClass::CredentialUnavailable,
                ),
            }
        })
        .await
        .map_err(|_| ConcreteExecutorUnfinished)
}

#[allow(clippy::too_many_arguments)]
async fn execute_bounded_http(
    dispatch: &mut AuditedConsultationDispatch,
    execution: SealedConsultationExecution<'_>,
    publication: PendingPublicationContext,
    quota: QuotaGrant,
    fence: &PostgresServingFence,
    basic_credentials: &CompiledBasicSourceCredentialProvider,
    static_bearer_credentials: &CompiledStaticBearerSourceCredentialProvider,
    oauth_credentials: &CompiledOAuthSourceCredentialProvider,
) -> Result<ConcreteExecutorProof<PublishableConsultationResponse>, ConcreteExecutorUnfinished> {
    let bound = execution
        .into_bound()
        .map_err(|_| ConcreteExecutorUnfinished)?;
    let sandboxed_rhai = bound.plan().kind() == SourcePlanKind::SandboxedRhai;
    if sandboxed_rhai {
        validate_sandboxed_rhai_activation(bound.plan())
    } else {
        validate_bounded_http_activation(bound.plan())
    }
    .map_err(|_| ConcreteExecutorUnfinished)?;

    if !sandboxed_rhai
        && bound
            .plan()
            .operations()
            .any(|operation| operation.dci_exact().is_some())
    {
        return execute_signed_dci_exact_bound(
            dispatch,
            bound,
            publication,
            quota,
            fence,
            oauth_credentials,
        )
        .await;
    }

    let mut oauth_token = None;

    let operation_count = bound.plan().operations().len();
    let mut memory = (0..operation_count)
        .map(|_| None)
        .collect::<Vec<Option<OperationMemory>>>();
    let mut facts = Vec::<(Box<str>, ProjectedJsonScalar)>::new();
    let mut execution_order = if sandboxed_rhai {
        Vec::new()
    } else {
        bound
            .plan()
            .compiled_steps()
            .enumerate()
            .map(|(step_index, step)| (step.operation_index(), Some(step_index)))
            .collect::<Vec<_>>()
    };
    let mut executed = BTreeSet::new();
    let mut final_rhai_facts = None;
    if sandboxed_rhai {
        match evaluate_rhai_round(&bound, &memory, &executed, &execution_order).await? {
            RhaiRoundResult::Choices(choices) => {
                if choices.first() != Some(&0) {
                    return Err(ConcreteExecutorUnfinished);
                }
                execution_order.extend(choices.into_iter().map(|index| (index, None)));
            }
            RhaiRoundResult::Final(_) => return Err(ConcreteExecutorUnfinished),
        }
    }
    let mut round_end = execution_order.len();
    let mut step_position = 0_usize;
    while step_position < execution_order.len() {
        let (operation_index, compiled_step_index) = execution_order[step_position];
        let operation = bound
            .plan()
            .operations()
            .nth(operation_index)
            .ok_or(ConcreteExecutorUnfinished)?;
        let should_execute = compiled_step_index
            .map(|index| {
                bound
                    .plan()
                    .compiled_steps()
                    .nth(index)
                    .ok_or(ConcreteExecutorUnfinished)
                    .and_then(|step| step_should_execute(step, &memory))
            })
            .transpose()?
            .unwrap_or(true);
        if !should_execute {
            append_absent_operation_facts(operation, &mut facts);
            memory[operation_index] = Some(OperationMemory {
                prior_outputs: (0..operation.response().prior_outputs().len())
                    .map(|_| ProjectedJsonScalar::Null)
                    .collect(),
                present: false,
            });
            step_position += 1;
            continue;
        }
        if !executed.insert(operation_index) {
            return Err(ConcreteExecutorUnfinished);
        }

        if operation.auth() == CompiledSourceAuth::OAuthClientCredentials && oauth_token.is_none() {
            match execute_oauth_credential(dispatch, &bound, fence, oauth_credentials).await? {
                CredentialDispatchResultV1::Token(token) => oauth_token = Some(token),
                CredentialDispatchResultV1::KnownFailure(failure) => {
                    drop(quota);
                    return Ok(ConcreteExecutorProof::known_failure(failure));
                }
            }
        }

        let query = render_text_values(&bound, operation.query(), &memory)?;
        let headers = render_text_values(&bound, operation.headers(), &memory)?;
        let path_segment = operation
            .path_segment()
            .map(|expression| render_text_expression(&bound, expression, &memory))
            .transpose()?;
        let query_refs = query.iter().map(AsRef::as_ref).collect::<Vec<_>>();
        let header_refs = headers
            .iter()
            .map(|value| value.as_bytes())
            .collect::<Vec<_>>();
        let body = operation
            .body()
            .map(|body| render_body(body, &bound, &memory, operation.request_max_bytes()))
            .transpose()?;
        let request = match operation.auth() {
            CompiledSourceAuth::None => match path_segment.as_deref() {
                Some(path_segment) => operation
                    .transport_template()
                    .render_zeroizing_with_path_segment(
                        path_segment,
                        &query_refs,
                        &header_refs,
                        None,
                        body,
                    ),
                None => operation.transport_template().render_zeroizing(
                    &query_refs,
                    &header_refs,
                    None,
                    body,
                ),
            }
            .map_err(|_| ConcreteExecutorUnfinished)?,
            CompiledSourceAuth::Basic => basic_credentials
                .authorization_for(bound.plan(), operation)
                .map_err(|_| ConcreteExecutorUnfinished)?
                .render(path_segment.as_deref(), &query_refs, &header_refs, body)
                .map_err(|_| ConcreteExecutorUnfinished)?,
            CompiledSourceAuth::StaticBearer => static_bearer_credentials
                .authorization_for(bound.plan(), operation)
                .map_err(|_| ConcreteExecutorUnfinished)?
                .render(path_segment.as_deref(), &query_refs, &header_refs, body)
                .map_err(|_| ConcreteExecutorUnfinished)?,
            CompiledSourceAuth::ApiKeyHeader | CompiledSourceAuth::ApiKeyQuery => {
                static_bearer_credentials
                    .api_key_for(bound.plan(), operation)
                    .map_err(|_| ConcreteExecutorUnfinished)?
                    .render(path_segment.as_deref(), &query_refs, &header_refs, body)
                    .map_err(|_| ConcreteExecutorUnfinished)?
            }
            CompiledSourceAuth::OAuthClientCredentials => {
                let authorization = oauth_token
                    .as_ref()
                    .ok_or(ConcreteExecutorUnfinished)?
                    .bearer_authorization()
                    .map_err(|_| ConcreteExecutorUnfinished)?;
                match path_segment.as_deref() {
                    Some(path_segment) => operation
                        .transport_template()
                        .render_zeroizing_with_path_segment(
                            path_segment,
                            &query_refs,
                            &header_refs,
                            Some(authorization),
                            body,
                        ),
                    None => operation.transport_template().render_zeroizing(
                        &query_refs,
                        &header_refs,
                        Some(authorization),
                        body,
                    ),
                }
                .map_err(|_| ConcreteExecutorUnfinished)?
            }
        };
        let destination = bound
            .plan()
            .data_destination()
            .ok_or(ConcreteExecutorUnfinished)?;
        let permit = dispatch
            .next_data_permit_mut()
            .map_err(|_| ConcreteExecutorUnfinished)?
            .ok_or(ConcreteExecutorUnfinished)?;
        let decoded = fence
            .authorize_and_dispatch(permit, operation.id(), |deadline| async move {
                let deadline = match operation_deadline(deadline, operation.request_timeout_ms()) {
                    Ok(value) => value,
                    Err(_) => return Err(KnownFailureClass::SourceUnavailable),
                };
                let response = destination
                    .send_with_deadline(request, deadline)
                    .await
                    .map_err(|_| KnownFailureClass::SourceUnavailable)?;
                let status = response.status().as_u16();
                if !operation
                    .response()
                    .accepted_statuses()
                    .any(|accepted| accepted == status)
                {
                    return Err(map_unaccepted_status(status));
                }
                if let Some(outcome) = operation.response().status_outcome(status) {
                    return Ok(match outcome {
                        CompiledStatusOutcome::NoMatch => ClosedJsonOutcome::NoMatch,
                        CompiledStatusOutcome::Ambiguous => ClosedJsonOutcome::Ambiguous,
                    });
                }
                let media_type_valid =
                    if operation.request_codec() == CompiledRequestCodec::FhirR4Search {
                        response.require_fhir_json_content_type().is_ok()
                    } else {
                        response.require_json_content_type().is_ok()
                    };
                if !media_type_valid {
                    return Err(KnownFailureClass::ResponseContractViolation);
                }
                let max_bytes = usize::try_from(operation.response_max_bytes())
                    .map_err(|_| KnownFailureClass::ResponseContractViolation)?;
                let body = response
                    .read_bounded(max_bytes)
                    .await
                    .map_err(map_response_error)?;
                let body = if let Some(fhir) = operation.fhir_r4_search() {
                    match registry_platform_httputil::destination::fhir::normalize_r4_searchset(
                        body,
                        fhir.resource_type(),
                        operation.response().max_records(),
                    )
                    .map_err(|_| KnownFailureClass::ResponseContractViolation)?
                    {
                        registry_platform_httputil::destination::fhir::FhirR4SearchsetOutcome::NoMatch => {
                            return Ok(ClosedJsonOutcome::NoMatch);
                        }
                        registry_platform_httputil::destination::fhir::FhirR4SearchsetOutcome::Records(body) => body,
                        registry_platform_httputil::destination::fhir::FhirR4SearchsetOutcome::Ambiguous => {
                            return Ok(ClosedJsonOutcome::Ambiguous);
                        }
                    }
                } else {
                    body
                };
                operation
                    .response_decoder()
                    .decode(body)
                    .map_err(map_decode_error)
            })
            .await
            .map_err(|_| ConcreteExecutorUnfinished)?;
        let decoded = match decoded {
            Ok(decoded) => decoded,
            Err(failure) => {
                drop(quota);
                return Ok(ConcreteExecutorProof::known_failure(failure));
            }
        };
        let anchor_step = is_anchor_execution_step(
            operation_index,
            compiled_step_index,
            step_position,
            sandboxed_rhai,
        );
        match decoded {
            ClosedJsonOutcome::Ambiguous => {
                drop(quota);
                return prepare_fact_result(
                    publication,
                    bound.plan().runtime_profile(),
                    ConsultationOutcome::Ambiguous,
                    None,
                );
            }
            ClosedJsonOutcome::NoMatch if anchor_step => {
                drop(quota);
                return prepare_fact_result(
                    publication,
                    bound.plan().runtime_profile(),
                    ConsultationOutcome::NoMatch,
                    None,
                );
            }
            ClosedJsonOutcome::NoMatch => {
                append_absent_operation_facts(operation, &mut facts);
                memory[operation_index] = Some(OperationMemory {
                    prior_outputs: (0..operation.response().prior_outputs().len())
                        .map(|_| ProjectedJsonScalar::Null)
                        .collect(),
                    present: false,
                });
            }
            ClosedJsonOutcome::One(record) => {
                let output_count = operation.response().outputs().len();
                let mut projected = record.into_fields().into_vec();
                if projected.len() != output_count + operation.response().prior_outputs().len() {
                    return Err(ConcreteExecutorUnfinished);
                }
                let prior = projected
                    .drain(output_count..)
                    .map(|field| field.into_parts().1)
                    .collect::<Vec<_>>();
                facts.extend(projected.into_iter().map(|field| field.into_parts()));
                facts.extend(
                    operation
                        .response()
                        .presence_outputs()
                        .map(|field| (field.field().into(), ProjectedJsonScalar::Boolean(true))),
                );
                memory[operation_index] = Some(OperationMemory {
                    prior_outputs: prior,
                    present: true,
                });
            }
        }
        step_position += 1;
        if sandboxed_rhai && step_position == round_end {
            match evaluate_rhai_round(&bound, &memory, &executed, &execution_order).await? {
                RhaiRoundResult::Choices(choices) => {
                    if choices.is_empty() {
                        return Err(ConcreteExecutorUnfinished);
                    }
                    execution_order.extend(choices.into_iter().map(|index| (index, None)));
                    round_end = execution_order.len();
                }
                RhaiRoundResult::Final(worker_facts) => {
                    final_rhai_facts = Some(worker_facts);
                    break;
                }
            }
        }
    }
    drop(quota);
    let facts = if sandboxed_rhai {
        final_rhai_facts
            .ok_or(ConcreteExecutorUnfinished)?
            .into_iter()
            .map(|(name, value)| rhai_fact_value(value).map(|value| (name.into_boxed_str(), value)))
            .collect::<Result<Vec<_>, _>>()?
    } else {
        facts
    };
    let fact_map = ValidatedFactMap::try_new(bound.plan().runtime_profile(), facts)
        .map_err(|_| ConcreteExecutorUnfinished)?;
    prepare_fact_result(
        publication,
        bound.plan().runtime_profile(),
        ConsultationOutcome::Match,
        Some(&fact_map),
    )
}

enum RhaiRoundResult {
    Choices(Vec<usize>),
    Final(BTreeMap<String, RhaiTypedValue>),
}

static RHAI_WORKER_LIMITERS: OnceLock<Mutex<BTreeMap<Box<str>, Arc<Semaphore>>>> = OnceLock::new();

fn rhai_worker_limiter(
    plan: &CompiledSourcePlan,
) -> Result<Arc<Semaphore>, ConcreteExecutorUnfinished> {
    let limits = plan
        .runtime_profile()
        .dispatch()
        .sandboxed_rhai_limits()
        .ok_or(ConcreteExecutorUnfinished)?;
    let key: Box<str> = plan.profile().contract_hash().as_str().into();
    let limiters = RHAI_WORKER_LIMITERS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut limiters = limiters.lock().map_err(|_| ConcreteExecutorUnfinished)?;
    Ok(Arc::clone(limiters.entry(key).or_insert_with(|| {
        Arc::new(Semaphore::new(usize::from(limits.concurrency())))
    })))
}

async fn evaluate_rhai_round(
    bound: &BoundConsultationExecution<'_>,
    memory: &[Option<OperationMemory>],
    executed: &BTreeSet<usize>,
    execution_order: &[(usize, Option<usize>)],
) -> Result<RhaiRoundResult, ConcreteExecutorUnfinished> {
    let plan = bound.plan();
    let (script, entrypoint) = plan.rhai_program().ok_or(ConcreteExecutorUnfinished)?;
    let limits = plan
        .runtime_profile()
        .dispatch()
        .sandboxed_rhai_limits()
        .ok_or(ConcreteExecutorUnfinished)?;
    let mut request = WorkerRequest::v1(
        script,
        entrypoint,
        WorkerLimits {
            max_operations: limits.instructions(),
            max_call_levels: usize::from(limits.call_depth()),
            max_expr_depth: usize::from(limits.call_depth()),
            max_string_bytes: usize::try_from(limits.string_bytes())
                .map_err(|_| ConcreteExecutorUnfinished)?,
            max_array_items: usize::try_from(limits.array_items())
                .map_err(|_| ConcreteExecutorUnfinished)?,
            max_map_entries: usize::try_from(limits.map_entries())
                .map_err(|_| ConcreteExecutorUnfinished)?,
            max_output_bytes: usize::try_from(limits.output_bytes())
                .map_err(|_| ConcreteExecutorUnfinished)?,
            max_ipc_frame_bytes: usize::try_from(limits.ipc_frame_bytes())
                .map_err(|_| ConcreteExecutorUnfinished)?,
            max_memory_bytes: limits.memory_bytes(),
            wall_time_ms: u64::from(limits.cpu_ms()),
        },
    );
    for (index, input) in plan.inputs().enumerate() {
        let value = bound.input(index).ok_or(ConcreteExecutorUnfinished)?;
        request.input.insert(
            input.name().to_owned(),
            match input.input_type() {
                crate::source_plan::CompiledInputType::String => RhaiTypedValue::String {
                    value: Some(value.as_str().to_owned()),
                },
                crate::source_plan::CompiledInputType::FullDate => RhaiTypedValue::Date {
                    value: Some(value.as_str().to_owned()),
                },
            },
        );
    }
    for fact in plan.rhai_facts() {
        request.fact_schema.insert(
            fact.name().to_owned(),
            RhaiFactSchema {
                fact_type: match fact.fact_type() {
                    CompiledRhaiFactType::String { .. } => RhaiFactType::String,
                    CompiledRhaiFactType::Boolean => RhaiFactType::Boolean,
                    CompiledRhaiFactType::Integer { .. } => RhaiFactType::Integer,
                    CompiledRhaiFactType::Date => RhaiFactType::Date,
                    CompiledRhaiFactType::Presence => RhaiFactType::Presence,
                },
                nullable: fact.nullable(),
                max_bytes: match fact.fact_type() {
                    CompiledRhaiFactType::String { max_bytes } => {
                        Some(usize::try_from(max_bytes).map_err(|_| ConcreteExecutorUnfinished)?)
                    }
                    CompiledRhaiFactType::Boolean
                    | CompiledRhaiFactType::Integer { .. }
                    | CompiledRhaiFactType::Date
                    | CompiledRhaiFactType::Presence => None,
                },
                minimum: match fact.fact_type() {
                    CompiledRhaiFactType::Integer { minimum, .. } => Some(minimum),
                    CompiledRhaiFactType::String { .. }
                    | CompiledRhaiFactType::Boolean
                    | CompiledRhaiFactType::Date
                    | CompiledRhaiFactType::Presence => None,
                },
                maximum: match fact.fact_type() {
                    CompiledRhaiFactType::Integer { maximum, .. } => Some(maximum),
                    CompiledRhaiFactType::String { .. }
                    | CompiledRhaiFactType::Boolean
                    | CompiledRhaiFactType::Date
                    | CompiledRhaiFactType::Presence => None,
                },
            },
        );
    }
    let planned = execution_order
        .iter()
        .map(|(index, _)| *index)
        .filter(|index| !executed.contains(index))
        .collect::<BTreeSet<_>>();
    for (index, operation) in plan.operations().enumerate() {
        if !executed.contains(&index) && !planned.contains(&index) {
            request
                .allowed_operations
                .insert(operation.id().as_str().to_owned());
        }
        let Some(observed) = memory.get(index).and_then(Option::as_ref) else {
            continue;
        };
        let mut prior = BTreeMap::new();
        prior.insert(
            "presence".to_owned(),
            RhaiTypedValue::Presence {
                value: observed.present,
            },
        );
        for (slot, value) in operation
            .response()
            .prior_outputs()
            .zip(&observed.prior_outputs)
        {
            prior.insert(slot.name().to_owned(), rhai_typed_value(slot, value)?);
        }
        request
            .prior_outputs
            .insert(operation.id().as_str().to_owned(), prior);
    }
    let limiter = rhai_worker_limiter(plan)?;
    let _permit = limiter
        .acquire_owned()
        .await
        .map_err(|_| ConcreteExecutorUnfinished)?;
    let worker = WorkerProcess::dedicated_executable().map_err(|_| ConcreteExecutorUnfinished)?;
    let output = worker
        .evaluate(&request)
        .await
        .map_err(|_| ConcreteExecutorUnfinished)?;
    if output.operation_choices.is_empty() {
        return Ok(RhaiRoundResult::Final(output.facts));
    }
    if executed.len() + planned.len() + output.operation_choices.len()
        > usize::from(limits.max_calls())
    {
        return Err(ConcreteExecutorUnfinished);
    }
    let mut choices = Vec::with_capacity(output.operation_choices.len());
    for choice in output.operation_choices {
        let index = plan
            .operations()
            .position(|operation| operation.id().as_str() == choice)
            .filter(|index| !executed.contains(index) && !planned.contains(index))
            .ok_or(ConcreteExecutorUnfinished)?;
        choices.push(index);
    }
    Ok(RhaiRoundResult::Choices(choices))
}

fn rhai_fact_value(
    value: RhaiTypedValue,
) -> Result<ProjectedJsonScalar, ConcreteExecutorUnfinished> {
    match value {
        RhaiTypedValue::String { value } | RhaiTypedValue::Date { value } => Ok(value
            .map_or(ProjectedJsonScalar::Null, |value| {
                ProjectedJsonScalar::String(Zeroizing::new(value))
            })),
        RhaiTypedValue::Boolean { value } => {
            Ok(value.map_or(ProjectedJsonScalar::Null, ProjectedJsonScalar::Boolean))
        }
        RhaiTypedValue::Integer { value } => {
            Ok(value.map_or(ProjectedJsonScalar::Null, ProjectedJsonScalar::Integer))
        }
        RhaiTypedValue::Presence { value } => Ok(ProjectedJsonScalar::Boolean(value)),
    }
}

fn rhai_typed_value(
    slot: &crate::source_plan::CompiledPriorOutputSlot,
    value: &ProjectedJsonScalar,
) -> Result<RhaiTypedValue, ConcreteExecutorUnfinished> {
    if slot.is_date() {
        return match value {
            ProjectedJsonScalar::Null => Ok(RhaiTypedValue::Date { value: None }),
            ProjectedJsonScalar::String(value) => Ok(RhaiTypedValue::Date {
                value: Some(value.as_str().to_owned()),
            }),
            _ => Err(ConcreteExecutorUnfinished),
        };
    }
    match (slot.shape(), value) {
        (CompiledScalarShape::String { .. }, ProjectedJsonScalar::Null) => {
            Ok(RhaiTypedValue::String { value: None })
        }
        (CompiledScalarShape::String { .. }, ProjectedJsonScalar::String(value)) => {
            Ok(RhaiTypedValue::String {
                value: Some(value.as_str().to_owned()),
            })
        }
        (CompiledScalarShape::Boolean { .. }, ProjectedJsonScalar::Null) => {
            Ok(RhaiTypedValue::Boolean { value: None })
        }
        (CompiledScalarShape::Boolean { .. }, ProjectedJsonScalar::Boolean(value)) => {
            Ok(RhaiTypedValue::Boolean {
                value: Some(*value),
            })
        }
        (CompiledScalarShape::Integer { .. }, ProjectedJsonScalar::Null) => {
            Ok(RhaiTypedValue::Integer { value: None })
        }
        (CompiledScalarShape::Integer { .. }, ProjectedJsonScalar::Integer(value)) => {
            Ok(RhaiTypedValue::Integer {
                value: Some(*value),
            })
        }
        _ => Err(ConcreteExecutorUnfinished),
    }
}

/// Consume one sealed execution through the startup-selected product journey.
/// The closed enum keeps runtime dispatch explicit without exposing a generic
/// callback or provider surface.
#[allow(clippy::too_many_arguments)]
pub(super) async fn execute_concrete_consultation(
    kind: ConcreteExecutorKind,
    dispatch: &mut AuditedConsultationDispatch,
    execution: SealedConsultationExecution<'_>,
    publication: PendingPublicationContext,
    quota: QuotaGrant,
    fence: &PostgresServingFence,
    basic_credentials: &CompiledBasicSourceCredentialProvider,
    static_bearer_credentials: &CompiledStaticBearerSourceCredentialProvider,
    oauth_credentials: &CompiledOAuthSourceCredentialProvider,
    snapshots: &PublishedSnapshotRegistry,
    datafusion: &SessionContext,
) -> Result<ConcreteExecutorProof<PublishableConsultationResponse>, ConcreteExecutorUnfinished> {
    match kind {
        ConcreteExecutorKind::SnapshotExact => {
            execute_local_snapshot_exact(
                dispatch,
                execution,
                publication,
                quota,
                snapshots,
                datafusion,
            )
            .await
        }
        ConcreteExecutorKind::BoundedHttp | ConcreteExecutorKind::SandboxedRhai => {
            execute_bounded_http(
                dispatch,
                execution,
                publication,
                quota,
                fence,
                basic_credentials,
                static_bearer_credentials,
                oauth_credentials,
            )
            .await
        }
    }
}

async fn execute_local_snapshot_exact(
    dispatch: &mut AuditedConsultationDispatch,
    execution: SealedConsultationExecution<'_>,
    publication: PendingPublicationContext,
    quota: QuotaGrant,
    snapshots: &PublishedSnapshotRegistry,
    datafusion: &SessionContext,
) -> Result<ConcreteExecutorProof<PublishableConsultationResponse>, ConcreteExecutorUnfinished> {
    let bound = execution
        .into_bound()
        .map_err(|_| ConcreteExecutorUnfinished)?;
    validate_snapshot_exact_activation(bound.plan()).map_err(|_| ConcreteExecutorUnfinished)?;
    let snapshot = snapshots
        .capture(bound.plan())
        .map_err(|_| ConcreteExecutorUnfinished)?;
    let sampled = TrustedConsultationTime::sample().map_err(|_| ConcreteExecutorUnfinished)?;
    let now_unix_ms = sampled.unix_ms();
    let max_age_ms = i64::try_from(
        bound
            .plan()
            .snapshot_binding()
            .ok_or(ConcreteExecutorUnfinished)?
            .max_snapshot_age_ms(),
    )
    .map_err(|_| ConcreteExecutorUnfinished)?;
    if snapshot.published_at_unix_ms() > now_unix_ms
        || now_unix_ms
            .checked_sub(snapshot.published_at_unix_ms())
            .is_none_or(|age| age > max_age_ms)
    {
        drop(quota);
        return Ok(ConcreteExecutorProof::known_failure(
            KnownFailureClass::SourceUnavailable,
        ));
    }
    let deadline = dispatch.local_not_after();
    if Instant::now() >= deadline {
        return Err(ConcreteExecutorUnfinished);
    }
    let canonical_inputs = bound
        .inputs()
        .map(|input| input.as_str())
        .collect::<Vec<_>>();
    let result = match execute_snapshot_exact(
        datafusion,
        bound.plan(),
        Arc::clone(&snapshot),
        &canonical_inputs,
        deadline,
    )
    .await
    {
        Ok(result) => result,
        Err(SnapshotExactBackendError::Unavailable) => {
            drop(quota);
            return Ok(ConcreteExecutorProof::known_failure(
                KnownFailureClass::SourceUnavailable,
            ));
        }
        Err(
            SnapshotExactBackendError::InvalidPlan
            | SnapshotExactBackendError::CardinalityViolation
            | SnapshotExactBackendError::ResponseContractViolation,
        ) => {
            drop(quota);
            return Ok(ConcreteExecutorProof::known_failure(
                KnownFailureClass::ResponseContractViolation,
            ));
        }
    };
    if !snapshots.is_current(bound.plan(), &snapshot) {
        drop(quota);
        return Ok(ConcreteExecutorProof::known_failure(
            KnownFailureClass::SourceUnavailable,
        ));
    }
    drop(quota);
    prepare_snapshot_public_result(publication, bound.plan().runtime_profile(), result)
}

fn prepare_snapshot_public_result(
    publication: PendingPublicationContext,
    profile: &crate::source_plan::runtime_profile::CompiledRuntimeProfile,
    result: SnapshotExactBackendResult,
) -> Result<ConcreteExecutorProof<PublishableConsultationResponse>, ConcreteExecutorUnfinished> {
    let public_outcome = match result.outcome() {
        ConsultationOutcome::Match => PublicConsultationOutcome::Match,
        ConsultationOutcome::NoMatch => PublicConsultationOutcome::NoMatch,
        ConsultationOutcome::Ambiguous => PublicConsultationOutcome::Ambiguous,
    };
    let acquired_at_unix_ms = TrustedConsultationTime::sample()
        .map_err(|_| ConcreteExecutorUnfinished)?
        .unix_ms();
    let output = PublishableConsultationResponse::from_validated_snapshot_result(
        publication.consultation_id(),
        publication.notary_evaluation_id(),
        profile,
        result.outcome(),
        result.record(),
        acquired_at_unix_ms,
        result.source_observed_at_unix_ms(),
        result.source_revision(),
        result.snapshot(),
    )
    .map_err(|_| ConcreteExecutorUnfinished)?;
    let completion_facts = KnownConsultationCompletionFacts::public_for_snapshot(
        public_outcome,
        acquired_at_unix_ms,
        result.source_observed_at_unix_ms(),
        result.source_revision(),
        result.snapshot().generation(),
        result.snapshot().published_at_unix_ms(),
    )
    .map_err(|_| ConcreteExecutorUnfinished)?;
    Ok(ConcreteExecutorProof {
        output: Some(output),
        completion_facts,
    })
}

fn step_should_execute(
    step: &crate::source_plan::CompiledStep,
    memory: &[Option<OperationMemory>],
) -> Result<bool, ConcreteExecutorUnfinished> {
    let Some(predicate) = step.condition() else {
        return Ok(true);
    };
    let source_memory = memory
        .get(
            step.condition_source_index()
                .ok_or(ConcreteExecutorUnfinished)?,
        )
        .and_then(Option::as_ref)
        .ok_or(ConcreteExecutorUnfinished)?;
    if step.condition_uses_presence() {
        return Ok(match predicate {
            CompiledStepPredicate::Exists => source_memory.present,
            CompiledStepPredicate::BooleanEquals(expected) => source_memory.present == *expected,
            _ => false,
        });
    }
    let value = source_memory
        .prior_outputs
        .get(
            step.condition_output_slot_index()
                .ok_or(ConcreteExecutorUnfinished)?,
        )
        .ok_or(ConcreteExecutorUnfinished)?;
    Ok(match (predicate, value) {
        (CompiledStepPredicate::Exists, ProjectedJsonScalar::Null) => false,
        (CompiledStepPredicate::Exists, _) => true,
        (CompiledStepPredicate::StringEquals(expected), ProjectedJsonScalar::String(value)) => {
            value.as_str() == expected.as_ref()
        }
        (CompiledStepPredicate::BooleanEquals(expected), ProjectedJsonScalar::Boolean(value)) => {
            value == expected
        }
        (CompiledStepPredicate::IntegerEquals(expected), ProjectedJsonScalar::Integer(value)) => {
            value == expected
        }
        _ => false,
    })
}

fn append_absent_operation_facts(
    operation: &CompiledOperation,
    facts: &mut Vec<(Box<str>, ProjectedJsonScalar)>,
) {
    facts.extend(
        operation
            .response()
            .outputs()
            .map(|field| (field.field().into(), ProjectedJsonScalar::Null)),
    );
    facts.extend(
        operation
            .response()
            .presence_outputs()
            .map(|field| (field.field().into(), ProjectedJsonScalar::Boolean(false))),
    );
}

fn render_text_values<'a>(
    bound: &'a BoundConsultationExecution<'a>,
    expressions: impl ExactSizeIterator<Item = &'a crate::source_plan::CompiledNamedExpression>,
    memory: &'a [Option<OperationMemory>],
) -> Result<Vec<Cow<'a, str>>, ConcreteExecutorUnfinished> {
    expressions
        .map(|expression| render_text_expression(bound, expression.value(), memory))
        .collect()
}

fn render_text_expression<'a>(
    bound: &'a BoundConsultationExecution<'a>,
    expression: &'a CompiledValueExpression,
    memory: &'a [Option<OperationMemory>],
) -> Result<Cow<'a, str>, ConcreteExecutorUnfinished> {
    match expression {
        CompiledValueExpression::Literal(value) => Ok(Cow::Borrowed(value)),
        CompiledValueExpression::ConsultationInput { input_index } => bound
            .input(*input_index)
            .map(|value| Cow::Borrowed(value.as_str()))
            .ok_or(ConcreteExecutorUnfinished),
        CompiledValueExpression::DeploymentParameter { parameter_index } => bound
            .plan()
            .deployment_parameter_value(*parameter_index)
            .map(Cow::Borrowed)
            .ok_or(ConcreteExecutorUnfinished),
        CompiledValueExpression::PriorStepOutput {
            operation_index,
            output_slot_index,
        } => match memory
            .get(*operation_index)
            .and_then(Option::as_ref)
            .and_then(|memory| memory.prior_outputs.get(*output_slot_index))
            .ok_or(ConcreteExecutorUnfinished)?
        {
            ProjectedJsonScalar::String(value) => Ok(Cow::Borrowed(value.as_str())),
            ProjectedJsonScalar::Boolean(value) => Ok(Cow::Owned(value.to_string())),
            ProjectedJsonScalar::Integer(value) => Ok(Cow::Owned(value.to_string())),
            ProjectedJsonScalar::Null | ProjectedJsonScalar::Number(_) => {
                Err(ConcreteExecutorUnfinished)
            }
        },
    }
}

fn render_body(
    body: &CompiledBodyTemplate,
    bound: &BoundConsultationExecution<'_>,
    memory: &[Option<OperationMemory>],
    max_bytes: u32,
) -> Result<Zeroizing<Vec<u8>>, ConcreteExecutorUnfinished> {
    let limit = usize::try_from(max_bytes).map_err(|_| ConcreteExecutorUnfinished)?;
    let mut output = Zeroizing::new(Vec::with_capacity(limit.min(4_096)));
    render_body_node(body, bound, memory, &mut output, limit)?;
    Ok(output)
}

fn render_body_node(
    node: &CompiledBodyTemplate,
    bound: &BoundConsultationExecution<'_>,
    memory: &[Option<OperationMemory>],
    output: &mut Zeroizing<Vec<u8>>,
    limit: usize,
) -> Result<(), ConcreteExecutorUnfinished> {
    match node {
        CompiledBodyTemplate::Null => append_body_bytes(output, b"null", limit),
        CompiledBodyTemplate::Boolean(value) => {
            append_body_bytes(output, if *value { b"true" } else { b"false" }, limit)
        }
        CompiledBodyTemplate::Integer(value) => {
            append_body_bytes(output, value.to_string().as_bytes(), limit)
        }
        CompiledBodyTemplate::StringLiteral(value) => append_json_string(output, value, limit),
        CompiledBodyTemplate::Expression(expression) => match expression {
            CompiledValueExpression::PriorStepOutput {
                operation_index,
                output_slot_index,
            } => match memory
                .get(*operation_index)
                .and_then(Option::as_ref)
                .and_then(|memory| memory.prior_outputs.get(*output_slot_index))
                .ok_or(ConcreteExecutorUnfinished)?
            {
                ProjectedJsonScalar::Null => append_body_bytes(output, b"null", limit),
                ProjectedJsonScalar::String(value) => append_json_string(output, value, limit),
                ProjectedJsonScalar::Boolean(value) => {
                    append_body_bytes(output, if *value { b"true" } else { b"false" }, limit)
                }
                ProjectedJsonScalar::Integer(value) => {
                    append_body_bytes(output, value.to_string().as_bytes(), limit)
                }
                ProjectedJsonScalar::Number(_) => Err(ConcreteExecutorUnfinished),
            },
            _ => {
                let value = render_text_expression(bound, expression, memory)?;
                append_json_string(output, &value, limit)
            }
        },
        CompiledBodyTemplate::Array(items) => {
            append_body_bytes(output, b"[", limit)?;
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    append_body_bytes(output, b",", limit)?;
                }
                render_body_node(item, bound, memory, output, limit)?;
            }
            append_body_bytes(output, b"]", limit)
        }
        CompiledBodyTemplate::Object(fields) => {
            append_body_bytes(output, b"{", limit)?;
            for (index, field) in fields.iter().enumerate() {
                if index > 0 {
                    append_body_bytes(output, b",", limit)?;
                }
                append_json_string(output, field.name(), limit)?;
                append_body_bytes(output, b":", limit)?;
                render_body_node(field.value(), bound, memory, output, limit)?;
            }
            append_body_bytes(output, b"}", limit)
        }
    }
}

fn append_json_string(
    output: &mut Zeroizing<Vec<u8>>,
    value: &str,
    limit: usize,
) -> Result<(), ConcreteExecutorUnfinished> {
    append_body_bytes(output, b"\"", limit)?;
    for byte in value.as_bytes() {
        match byte {
            b'"' => append_body_bytes(output, b"\\\"", limit)?,
            b'\\' => append_body_bytes(output, b"\\\\", limit)?,
            b'\x08' => append_body_bytes(output, b"\\b", limit)?,
            b'\x0c' => append_body_bytes(output, b"\\f", limit)?,
            b'\n' => append_body_bytes(output, b"\\n", limit)?,
            b'\r' => append_body_bytes(output, b"\\r", limit)?,
            b'\t' => append_body_bytes(output, b"\\t", limit)?,
            0x00..=0x1f => {
                let escaped = format!("\\u00{byte:02x}");
                append_body_bytes(output, escaped.as_bytes(), limit)?;
            }
            _ => append_body_bytes(output, &[*byte], limit)?,
        }
    }
    append_body_bytes(output, b"\"", limit)
}

fn append_body_bytes(
    output: &mut Zeroizing<Vec<u8>>,
    bytes: &[u8],
    limit: usize,
) -> Result<(), ConcreteExecutorUnfinished> {
    if output
        .len()
        .checked_add(bytes.len())
        .is_none_or(|length| length > limit)
    {
        return Err(ConcreteExecutorUnfinished);
    }
    output.extend_from_slice(bytes);
    Ok(())
}

fn prepare_fact_result(
    publication: PendingPublicationContext,
    profile: &crate::source_plan::runtime_profile::CompiledRuntimeProfile,
    outcome: ConsultationOutcome,
    facts: Option<&ValidatedFactMap>,
) -> Result<ConcreteExecutorProof<PublishableConsultationResponse>, ConcreteExecutorUnfinished> {
    let public_outcome = match outcome {
        ConsultationOutcome::Match => PublicConsultationOutcome::Match,
        ConsultationOutcome::NoMatch => PublicConsultationOutcome::NoMatch,
        ConsultationOutcome::Ambiguous => PublicConsultationOutcome::Ambiguous,
    };
    profile
        .footprint()
        .validate_outcome(outcome)
        .map_err(|_| ConcreteExecutorUnfinished)?;
    let acquired_at_unix_ms = TrustedConsultationTime::sample()
        .map_err(|_| ConcreteExecutorUnfinished)?
        .unix_ms();
    let output = PublishableConsultationResponse::from_validated_live_result(
        publication.consultation_id(),
        publication.notary_evaluation_id(),
        profile,
        outcome,
        facts,
        acquired_at_unix_ms,
    )
    .map_err(|_| ConcreteExecutorUnfinished)?;
    let completion_facts =
        KnownConsultationCompletionFacts::public_for_live(public_outcome, acquired_at_unix_ms)
            .map_err(|_| ConcreteExecutorUnfinished)?;
    Ok(ConcreteExecutorProof {
        output: Some(output),
        completion_facts,
    })
}

fn render_query_values<'a>(
    bound: &'a BoundConsultationExecution<'a>,
    expressions: impl ExactSizeIterator<Item = &'a crate::source_plan::CompiledNamedExpression>,
) -> Result<Vec<&'a str>, ConcreteExecutorUnfinished> {
    expressions
        .map(|component| match component.value() {
            CompiledValueExpression::Literal(value) => Ok(value.as_ref()),
            CompiledValueExpression::ConsultationInput { input_index } => bound
                .input(*input_index)
                .map(crate::source_plan::CompiledInputValue::as_str)
                .ok_or(ConcreteExecutorUnfinished),
            CompiledValueExpression::DeploymentParameter { parameter_index } => bound
                .plan()
                .deployment_parameter_value(*parameter_index)
                .ok_or(ConcreteExecutorUnfinished),
            CompiledValueExpression::PriorStepOutput { .. } => Err(ConcreteExecutorUnfinished),
        })
        .collect()
}

fn prepare_public_result(
    publication: PendingPublicationContext,
    profile: &crate::source_plan::runtime_profile::CompiledRuntimeProfile,
    decoded: ClosedJsonOutcome,
) -> Result<ConcreteExecutorProof<PublishableConsultationResponse>, PublicResultPreparationError> {
    let (outcome, public_outcome, record) = match decoded {
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
    let facts = record
        .map(|record| {
            ValidatedFactMap::try_new(
                profile,
                record
                    .into_fields()
                    .into_vec()
                    .into_iter()
                    .map(|field| field.into_parts())
                    .collect(),
            )
        })
        .transpose()
        .map_err(|_| {
            PublicResultPreparationError::KnownFailure(KnownFailureClass::ResponseContractViolation)
        })?;
    let output = PublishableConsultationResponse::from_validated_live_result(
        publication.consultation_id(),
        publication.notary_evaluation_id(),
        profile,
        outcome,
        facts.as_ref(),
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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::source_plan::{
        bounded_runtime_vector_plan_fixture, dhis2_duplicate_selector_runtime_vector_plan_fixture,
        dhis2_runtime_vector_plan_fixture, maintained_open_crvs_runtime_plan_fixture,
        rhai_runtime_vector_plan_fixture, signed_dci_expiring_oauth_runtime_plan_fixture,
    };

    #[test]
    fn capability_activation_accepts_reviewed_platform_profiles() {
        let dhis2 = dhis2_runtime_vector_plan_fixture();
        assert_eq!(validate_bounded_http_activation(&dhis2), Ok(()));
        assert_eq!(
            ConcreteExecutorKind::activate(&dhis2),
            Ok(ConcreteExecutorKind::BoundedHttp)
        );
        assert_eq!(
            ConcreteExecutorKind::activate(&dhis2)
                .and_then(|executor| executor.dispatch_budget(&dhis2))
                .expect("DHIS2 budget")
                .as_milliseconds(),
            10_000
        );

        let oauth = bounded_runtime_vector_plan_fixture();
        assert_eq!(validate_bounded_http_activation(&oauth), Ok(()));
        let rhai = rhai_runtime_vector_plan_fixture();
        assert_eq!(
            validate_basic_get_activation(&rhai),
            Err(ConcreteExecutorActivationError::UnsupportedPlan)
        );
        if cfg!(target_os = "linux") {
            assert_eq!(validate_sandboxed_rhai_activation(&rhai), Ok(()));
            assert_eq!(
                ConcreteExecutorKind::activate(&rhai),
                Ok(ConcreteExecutorKind::SandboxedRhai)
            );
        } else {
            assert_eq!(
                validate_sandboxed_rhai_activation(&rhai),
                Err(ConcreteExecutorActivationError::UnsupportedPlan)
            );
            assert_eq!(
                ConcreteExecutorKind::activate(&rhai),
                Err(ConcreteExecutorActivationError::UnsupportedPlan)
            );
        }
        let duplicate_selector = dhis2_duplicate_selector_runtime_vector_plan_fixture();
        assert_eq!(
            validate_bounded_http_activation(&duplicate_selector),
            Ok(())
        );
    }

    #[test]
    fn rhai_worker_limiter_is_profile_scoped_and_uses_compiled_concurrency() {
        let plan = rhai_runtime_vector_plan_fixture();
        let expected = plan
            .runtime_profile()
            .dispatch()
            .sandboxed_rhai_limits()
            .expect("Rhai limits")
            .concurrency();
        let Ok(first) = rhai_worker_limiter(&plan) else {
            panic!("limiter");
        };
        let Ok(second) = rhai_worker_limiter(&plan) else {
            panic!("same limiter");
        };
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(first.available_permits(), usize::from(expected));
    }

    #[test]
    fn sandboxed_rhai_terminal_facts_preserve_the_closed_scalar_types() {
        let string = rhai_fact_value(RhaiTypedValue::String {
            value: Some("programme-a".to_owned()),
        })
        .unwrap_or_else(|_| panic!("bounded String fact"));
        assert!(matches!(
            string,
            ProjectedJsonScalar::String(value) if value.as_str() == "programme-a"
        ));

        let date = rhai_fact_value(RhaiTypedValue::Date {
            value: Some("2020-02-29".to_owned()),
        })
        .unwrap_or_else(|_| panic!("full-date fact"));
        assert!(matches!(
            date,
            ProjectedJsonScalar::String(value) if value.as_str() == "2020-02-29"
        ));

        assert!(matches!(
            rhai_fact_value(RhaiTypedValue::Boolean { value: Some(true) }),
            Ok(ProjectedJsonScalar::Boolean(true))
        ));
        assert!(matches!(
            rhai_fact_value(RhaiTypedValue::Integer { value: Some(7) }),
            Ok(ProjectedJsonScalar::Integer(7))
        ));
        assert!(matches!(
            rhai_fact_value(RhaiTypedValue::Presence { value: false }),
            Ok(ProjectedJsonScalar::Boolean(false))
        ));
        assert!(matches!(
            rhai_fact_value(RhaiTypedValue::Date { value: None }),
            Ok(ProjectedJsonScalar::Null)
        ));
    }

    #[test]
    fn activation_selects_bounded_http_for_signed_dci_and_derives_permits() {
        let opencrvs = maintained_open_crvs_runtime_plan_fixture();
        assert_eq!(validate_signed_dci_exact_activation(&opencrvs), Ok(()));
        let operation = opencrvs.operations().next().expect("OpenCRVS operation");
        assert_eq!(operation.request_timeout_ms(), 10_000);
        assert_eq!(
            operation
                .dci_exact()
                .map(|dci| dci.verification())
                .expect("OpenCRVS JWKS operation")
                .request_timeout_ms(),
            10_000
        );
        assert_eq!(
            opencrvs
                .credential_operation()
                .expect("OpenCRVS credential operation")
                .request_timeout_ms(),
            10_000
        );
        let executor = ConcreteExecutorKind::activate(&opencrvs).expect("OpenCRVS executor");
        assert_eq!(executor, ConcreteExecutorKind::BoundedHttp);
        assert_eq!(executor.permit_counts(&opencrvs), Ok((1, 2)));
        assert_eq!(
            executor
                .dispatch_budget(&opencrvs)
                .expect("OpenCRVS shared budget")
                .as_milliseconds(),
            20_000
        );
        assert_eq!(
            validate_signed_dci_exact_activation(&signed_dci_expiring_oauth_runtime_plan_fixture()),
            Ok(())
        );
    }

    #[test]
    fn operation_deadline_caps_each_exchange_inside_the_shared_journey_fence() {
        let short_consultation = Instant::now() + Duration::from_secs(1);
        assert_eq!(
            operation_deadline(short_consultation, 10_000)
                .unwrap_or_else(|_| panic!("short shared deadline")),
            short_consultation
        );

        let before = Instant::now();
        let capped = operation_deadline(before + Duration::from_secs(20), 20_000)
            .unwrap_or_else(|_| panic!("per-operation deadline"));
        let after = Instant::now();
        assert!(capped >= before + Duration::from_secs(10));
        assert!(capped <= after + Duration::from_secs(10));
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

    #[test]
    fn anchor_is_compiled_topology_not_lexical_operation_index() {
        assert!(is_anchor_execution_step(1, Some(0), 0, false));
        assert!(!is_anchor_execution_step(0, Some(1), 1, false));
        assert!(is_anchor_execution_step(3, None, 0, true));
    }
}
