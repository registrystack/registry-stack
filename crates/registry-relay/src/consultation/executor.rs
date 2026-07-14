// SPDX-License-Identifier: Apache-2.0
//! Closed capability consultation executors.

mod signed_dci;

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use datafusion::execution::context::SessionContext;
use registry_platform_crypto::canonicalize_json;
use registry_platform_httputil::destination::json::{
    decode_script_json, decode_script_text, ClosedJsonDecodeError, ClosedJsonOutcome,
    ProjectedJsonScalar, MAX_CLOSED_JSON_ENCODED_BODY_BYTES,
};
use registry_platform_httputil::destination::{
    DestinationResponseError, ScriptRequestBodyFormat, MAX_DESTINATION_OPERATION_TIMEOUT,
};
use thiserror::Error;
use tokio::sync::Semaphore;
use tokio::time::Instant;
use zeroize::Zeroizing;

use async_trait::async_trait;
use serde_json::Value as JsonValue;

use crate::rhai_worker::{
    HostFailure, OutputSchema as RhaiOutputSchema, OutputType as RhaiOutputType, ScriptFailure,
    SourceCall, SourceHost, SourceResponse, TypedValue as RhaiTypedValue, WorkerLimits,
    WorkerOutcome, WorkerOutput, WorkerProcess, WorkerRequest,
};

use crate::source_backend::{
    execute_snapshot_exact, PublishedSnapshotRegistry, SnapshotExactBackendError,
    SnapshotExactBackendResult,
};
use crate::source_plan::runtime_profile::CompiledConsentProfile;
use crate::source_plan::{
    CompiledBasicSourceCredentialProvider, CompiledBodyTemplate, CompiledInputRole,
    CompiledOAuthSourceCredentialProvider, CompiledOperation, CompiledRequestCodec,
    CompiledResponseFormat, CompiledRhaiOutputType, CompiledSelectorLocation,
    CompiledSelectorSource, CompiledSourceAuth, CompiledSourcePlan,
    CompiledStaticBearerSourceCredentialProvider, CompiledStatusOutcome, CompiledStepPredicate,
    CompiledValueExpression, ParsedOAuth2AccessToken, ReadMethod, SourcePlanKind,
};
use crate::state_plane::{
    AuditedConsultationDispatch, KnownConsultationCompletionFacts, KnownFailureClass,
    PostgresServingFence, PublicConsultationOutcome, QuotaGrant,
};

use super::audit::PendingPublicationContext;
use super::commitments::{
    BoundConsultationExecution, CanonicalDispatchRequestEffect, SealedConsultationExecution,
    TrustedConsultationTime,
};
use super::response::{
    ConsultationResponseError, PublishableConsultationResponse, ValidatedOutputMap,
};
use super::ConsultationOutcome;

use signed_dci::{
    execute_signed_dci_exact_bound, execute_signed_dci_search_call,
    validate_signed_dci_exact_activation, validate_signed_dci_script_activation,
};

const MAX_CONSULTATION_INPUTS: usize = 16;
const MAX_SELECTOR_INPUTS: usize = 8;
const MAX_DATA_OPERATIONS: usize = 16;

const fn supported_input_counts(total: usize, selectors: usize) -> bool {
    total >= 1
        && total <= MAX_CONSULTATION_INPUTS
        && selectors >= 1
        && selectors <= MAX_SELECTOR_INPUTS
        && selectors <= total
}

fn supported_input_cardinality(plan: &CompiledSourcePlan) -> bool {
    let total = plan.inputs().len();
    let selectors = plan
        .inputs()
        .filter(|input| input.role() == CompiledInputRole::Selector)
        .count();
    supported_input_counts(total, selectors)
}

pub(super) fn signed_dci_script_host_required(
    plan: &CompiledSourcePlan,
) -> Result<bool, ConcreteExecutorActivationError> {
    validate_signed_dci_script_activation(plan)
}

pub(super) fn generic_script_source_calls_allowed(plan: &CompiledSourcePlan) -> bool {
    plan.script_authority()
        .and_then(crate::source_plan::CompiledScriptAuthority::signed_dci)
        .is_none()
}

/// Value-free reason an artifact-valid plan cannot be served by a maintained
/// source capability.
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
    script: bool,
) -> bool {
    matches!(compiled_step_index, Some(0)) || (script && execution_position == 0)
}

/// Restart-only selection of one fully reviewed source capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConcreteExecutorKind {
    SnapshotExact,
    BoundedHttp,
    Script,
}

impl ConcreteExecutorKind {
    pub(crate) fn activate(
        plan: &CompiledSourcePlan,
    ) -> Result<Self, ConcreteExecutorActivationError> {
        if validate_snapshot_exact_activation(plan).is_ok() {
            return Ok(Self::SnapshotExact);
        }
        if validate_script_activation(plan).is_ok() {
            return Ok(Self::Script);
        }
        validate_bounded_http_activation(plan)?;
        Ok(Self::BoundedHttp)
    }

    pub(crate) fn permit_counts(
        self,
        plan: &CompiledSourcePlan,
    ) -> Result<(u8, u8, u8), ConcreteExecutorActivationError> {
        let mut credential = 0_u8;
        let mut verification = 0_u8;
        let mut data = 0_u8;
        for (kind, ordinal) in plan.runtime_profile().permit_bindings() {
            match kind {
                "credential" if ordinal == credential => credential += 1,
                "verification" if ordinal == verification => verification += 1,
                "data" if ordinal == data => data += 1,
                _ => return Err(ConcreteExecutorActivationError::UnsupportedPlan),
            }
        }
        (credential <= 1 && verification <= 1 && data <= 16)
            .then_some((credential, verification, data))
            .ok_or(ConcreteExecutorActivationError::UnsupportedPlan)
    }

    pub(crate) fn dispatch_budget(
        self,
        plan: &CompiledSourcePlan,
    ) -> Result<crate::state_plane::DispatchPermitBudget, ConcreteExecutorActivationError> {
        match self {
            Self::SnapshotExact => validate_snapshot_exact_activation(plan)?,
            Self::BoundedHttp => validate_bounded_http_activation(plan)?,
            Self::Script => validate_script_activation(plan)?,
        }
        crate::state_plane::DispatchPermitBudget::new(Duration::from_millis(u64::from(
            plan.limits().operation().timeout_ms,
        )))
        .map_err(|_| ConcreteExecutorActivationError::UnsupportedPlan)
    }
}

fn validate_script_activation(
    plan: &CompiledSourcePlan,
) -> Result<(), ConcreteExecutorActivationError> {
    let authority = plan
        .script_authority()
        .ok_or(ConcreteExecutorActivationError::UnsupportedPlan)?;
    let script_limits = plan
        .runtime_profile()
        .dispatch()
        .script_limits()
        .ok_or(ConcreteExecutorActivationError::UnsupportedPlan)?;
    if plan.kind() != SourcePlanKind::Script
        || !supported_input_cardinality(plan)
        || plan.operations().len() != 0
        || plan.steps().len() != 0
        || plan.rhai_program().is_none()
        || plan.data_destination().is_none()
        || !matches!(
            plan.runtime_profile().authorization().consent(),
            CompiledConsentProfile::NotRequired
        )
        || authority.allow().len() == 0
    {
        return Err(ConcreteExecutorActivationError::UnsupportedPlan);
    }
    let oauth = authority.auth() == CompiledSourceAuth::OAuthClientCredentials;
    let signed_dci = validate_signed_dci_script_activation(plan)?;
    if oauth != plan.credential_operation().is_some()
        || oauth != plan.credential_destination().is_some()
        || (signed_dci && script_limits.max_calls() != 1)
    {
        return Err(ConcreteExecutorActivationError::UnsupportedPlan);
    }
    let (_, _, data) = ConcreteExecutorKind::Script.permit_counts(plan)?;
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
        || !supported_input_cardinality(plan)
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
/// Output and durable completion outputs cannot be assembled independently.
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
        || !supported_input_cardinality(plan)
        || !(1..=MAX_DATA_OPERATIONS).contains(&plan.operations().len())
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
    let (_, _, data) = kind.permit_counts(plan)?;
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
    let request_commitment = dispatch
        .commit_request_effect(
            CanonicalDispatchRequestEffect::try_from_complete_value(
                request.noncredential_effect_value(destination.origin_id()),
            )
            .map_err(|_| ConcreteExecutorUnfinished)?,
        )
        .map_err(|_| ConcreteExecutorUnfinished)?;
    let permit = dispatch
        .next_data_permit_mut()
        .map_err(|_| ConcreteExecutorUnfinished)?
        .ok_or(ConcreteExecutorUnfinished)?;
    let profile = bound.plan().runtime_profile();
    let inner = fence
        .authorize_and_dispatch(permit, request_commitment, |deadline| async move {
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
    let parser = operation.parser();
    let request_commitment = dispatch
        .commit_request_effect(
            CanonicalDispatchRequestEffect::try_from_complete_value(
                request.credential_exchange_effect_value(destination.origin_id()),
            )
            .map_err(|_| ConcreteExecutorUnfinished)?,
        )
        .map_err(|_| ConcreteExecutorUnfinished)?;
    let permit = dispatch
        .credential_permit_mut()
        .map_err(|_| ConcreteExecutorUnfinished)?
        .ok_or(ConcreteExecutorUnfinished)?;
    fence
        .authorize_and_dispatch(permit, request_commitment, |deadline| async move {
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
    let script = bound.plan().kind() == SourcePlanKind::Script;
    if script {
        validate_script_activation(bound.plan()).map_err(|_| ConcreteExecutorUnfinished)?;
        return execute_interactive_rhai(
            dispatch,
            bound,
            publication,
            quota,
            fence,
            basic_credentials,
            static_bearer_credentials,
            oauth_credentials,
        )
        .await;
    }
    validate_bounded_http_activation(bound.plan()).map_err(|_| ConcreteExecutorUnfinished)?;

    if !script
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
    let mut outputs = Vec::<(Box<str>, ProjectedJsonScalar)>::new();
    let execution_order = bound
        .plan()
        .compiled_steps()
        .enumerate()
        .map(|(step_index, step)| (step.operation_index(), Some(step_index)))
        .collect::<Vec<_>>();
    let mut executed = BTreeSet::new();
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
            append_absent_operation_outputs(operation, &mut outputs);
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
        let request_commitment = dispatch
            .commit_request_effect(
                CanonicalDispatchRequestEffect::try_from_complete_value(match operation.auth() {
                    CompiledSourceAuth::ApiKeyHeader => {
                        request.effect_value_without_api_key_header(destination.origin_id())
                    }
                    CompiledSourceAuth::ApiKeyQuery => {
                        request.effect_value_without_api_key_query(destination.origin_id())
                    }
                    _ => request.noncredential_effect_value(destination.origin_id()),
                })
                .map_err(|_| ConcreteExecutorUnfinished)?,
            )
            .map_err(|_| ConcreteExecutorUnfinished)?;
        let permit = dispatch
            .next_data_permit_mut()
            .map_err(|_| ConcreteExecutorUnfinished)?
            .ok_or(ConcreteExecutorUnfinished)?;
        let decoded = fence
            .authorize_and_dispatch(permit, request_commitment, |deadline| async move {
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
                if response.require_json_content_type().is_err() {
                    return Err(KnownFailureClass::ResponseContractViolation);
                }
                let max_bytes = usize::try_from(operation.response_max_bytes())
                    .map_err(|_| KnownFailureClass::ResponseContractViolation)?;
                let body = response
                    .read_bounded(max_bytes)
                    .await
                    .map_err(map_response_error)?;
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
        let anchor_step =
            is_anchor_execution_step(operation_index, compiled_step_index, step_position, false);
        match decoded {
            ClosedJsonOutcome::Ambiguous => {
                drop(quota);
                return prepare_output_result(
                    publication,
                    bound.plan().runtime_profile(),
                    ConsultationOutcome::Ambiguous,
                    None,
                );
            }
            ClosedJsonOutcome::NoMatch if anchor_step => {
                drop(quota);
                return prepare_output_result(
                    publication,
                    bound.plan().runtime_profile(),
                    ConsultationOutcome::NoMatch,
                    None,
                );
            }
            ClosedJsonOutcome::NoMatch => {
                append_absent_operation_outputs(operation, &mut outputs);
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
                outputs.extend(projected.into_iter().map(|field| field.into_parts()));
                memory[operation_index] = Some(OperationMemory {
                    prior_outputs: prior,
                    present: true,
                });
            }
        }
        step_position += 1;
    }
    drop(quota);
    let output_map = ValidatedOutputMap::try_new(bound.plan().runtime_profile(), outputs)
        .map_err(|_| ConcreteExecutorUnfinished)?;
    prepare_output_result(
        publication,
        bound.plan().runtime_profile(),
        ConsultationOutcome::Match,
        Some(&output_map),
    )
}

static RHAI_WORKER_LIMITERS: OnceLock<Mutex<BTreeMap<Box<str>, Arc<Semaphore>>>> = OnceLock::new();

fn rhai_worker_limiter(
    plan: &CompiledSourcePlan,
) -> Result<Arc<Semaphore>, ConcreteExecutorUnfinished> {
    let limits = plan
        .runtime_profile()
        .dispatch()
        .script_limits()
        .ok_or(ConcreteExecutorUnfinished)?;
    let key: Box<str> = plan.profile().contract_hash().as_str().into();
    let limiters = RHAI_WORKER_LIMITERS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut limiters = limiters.lock().map_err(|_| ConcreteExecutorUnfinished)?;
    Ok(Arc::clone(limiters.entry(key).or_insert_with(|| {
        Arc::new(Semaphore::new(usize::from(limits.concurrency())))
    })))
}

fn build_rhai_request(
    bound: &BoundConsultationExecution<'_>,
) -> Result<WorkerRequest, ConcreteExecutorUnfinished> {
    let plan = bound.plan();
    let authority = plan.script_authority().ok_or(ConcreteExecutorUnfinished)?;
    let (script, entrypoint) = plan.rhai_program().ok_or(ConcreteExecutorUnfinished)?;
    let limits = plan
        .runtime_profile()
        .dispatch()
        .script_limits()
        .ok_or(ConcreteExecutorUnfinished)?;
    let largest_response_bytes =
        usize::try_from(authority.response_max_bytes()).map_err(|_| ConcreteExecutorUnfinished)?;
    let largest_text_response_bytes = if authority.response_format() == CompiledResponseFormat::Text
    {
        largest_response_bytes
    } else {
        0
    };
    let ipc_frame_bytes = usize::try_from(limits.ipc_frame_bytes())
        .map_err(|_| ConcreteExecutorUnfinished)?
        .max(largest_response_bytes.saturating_add(256 * 1024))
        .min(9 * 1024 * 1024);
    let mut request = WorkerRequest::v1(
        script,
        entrypoint,
        WorkerLimits {
            max_operations: limits.instructions(),
            max_call_levels: usize::from(limits.call_depth()),
            max_expr_depth: usize::from(limits.call_depth()),
            max_string_bytes: usize::try_from(limits.string_bytes())
                .map_err(|_| ConcreteExecutorUnfinished)?
                .max(largest_text_response_bytes),
            max_array_items: usize::try_from(limits.array_items())
                .map_err(|_| ConcreteExecutorUnfinished)?,
            max_map_entries: usize::try_from(limits.map_entries())
                .map_err(|_| ConcreteExecutorUnfinished)?,
            max_output_bytes: 64 * 1024,
            max_ipc_frame_bytes: ipc_frame_bytes,
            max_memory_bytes: limits.memory_bytes(),
            wall_time_ms: u64::from(limits.cpu_ms()),
            max_source_calls: u32::from(limits.max_calls()),
        },
    );
    for (index, input) in plan.inputs().enumerate() {
        let value = bound.input(index).ok_or(ConcreteExecutorUnfinished)?;
        request.input.insert(
            input.name().to_owned(),
            match (input.input_type(), value.transient_json_value()) {
                (crate::source_plan::CompiledInputType::String, JsonValue::String(value)) => {
                    RhaiTypedValue::String { value: Some(value) }
                }
                (crate::source_plan::CompiledInputType::FullDate, JsonValue::String(value)) => {
                    RhaiTypedValue::Date { value: Some(value) }
                }
                (crate::source_plan::CompiledInputType::Boolean, JsonValue::Bool(value)) => {
                    RhaiTypedValue::Boolean { value: Some(value) }
                }
                (crate::source_plan::CompiledInputType::Integer, JsonValue::Number(value)) => {
                    RhaiTypedValue::Integer {
                        value: value.as_i64(),
                    }
                }
                (crate::source_plan::CompiledInputType::String, JsonValue::Null) => {
                    RhaiTypedValue::String { value: None }
                }
                (crate::source_plan::CompiledInputType::FullDate, JsonValue::Null) => {
                    RhaiTypedValue::Date { value: None }
                }
                (crate::source_plan::CompiledInputType::Boolean, JsonValue::Null) => {
                    RhaiTypedValue::Boolean { value: None }
                }
                (crate::source_plan::CompiledInputType::Integer, JsonValue::Null) => {
                    RhaiTypedValue::Integer { value: None }
                }
                _ => return Err(ConcreteExecutorUnfinished),
            },
        );
    }
    for output in plan.rhai_outputs() {
        request.output_schema.insert(
            output.name().to_owned(),
            RhaiOutputSchema {
                output_type: match output.output_type() {
                    CompiledRhaiOutputType::String { .. } => RhaiOutputType::String,
                    CompiledRhaiOutputType::Boolean => RhaiOutputType::Boolean,
                    CompiledRhaiOutputType::Integer { .. } => RhaiOutputType::Integer,
                    CompiledRhaiOutputType::Date => RhaiOutputType::Date,
                },
                nullable: output.nullable(),
                max_bytes: match output.output_type() {
                    CompiledRhaiOutputType::String { max_bytes } => {
                        Some(usize::try_from(max_bytes).map_err(|_| ConcreteExecutorUnfinished)?)
                    }
                    CompiledRhaiOutputType::Boolean
                    | CompiledRhaiOutputType::Integer { .. }
                    | CompiledRhaiOutputType::Date => None,
                },
                minimum: match output.output_type() {
                    CompiledRhaiOutputType::Integer { minimum, .. } => Some(minimum),
                    CompiledRhaiOutputType::String { .. }
                    | CompiledRhaiOutputType::Boolean
                    | CompiledRhaiOutputType::Date => None,
                },
                maximum: match output.output_type() {
                    CompiledRhaiOutputType::Integer { maximum, .. } => Some(maximum),
                    CompiledRhaiOutputType::String { .. }
                    | CompiledRhaiOutputType::Boolean
                    | CompiledRhaiOutputType::Date => None,
                },
            },
        );
    }
    if signed_dci_script_host_required(plan).map_err(|_| ConcreteExecutorUnfinished)? {
        request.enable_signed_dci_search();
    }
    Ok(request)
}

fn rhai_output_value(
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
    }
}

struct PreparedRhaiCall<'a> {
    rule: &'a crate::source_plan::CompiledScriptAllowRule,
    target: String,
    headers: Vec<(String, String)>,
    body_format: Option<ScriptRequestBodyFormat>,
    body: Option<Zeroizing<Vec<u8>>>,
}

struct ProductionRhaiHost<'a, 'plan> {
    dispatch: &'a mut AuditedConsultationDispatch,
    bound: &'a BoundConsultationExecution<'plan>,
    fence: &'a PostgresServingFence,
    basic_credentials: &'a CompiledBasicSourceCredentialProvider,
    static_bearer_credentials: &'a CompiledStaticBearerSourceCredentialProvider,
    oauth_credentials: &'a CompiledOAuthSourceCredentialProvider,
    oauth_token: Option<ParsedOAuth2AccessToken>,
    request_bytes: u64,
    source_bytes: u64,
}

#[async_trait]
impl SourceHost for ProductionRhaiHost<'_, '_> {
    async fn call(&mut self, call: SourceCall) -> Result<SourceResponse, HostFailure> {
        let call = match call {
            SourceCall::DciSearch { options, .. } => {
                let authority = self
                    .bound
                    .plan()
                    .script_authority()
                    .ok_or(HostFailure::ContractViolation)?;
                let dci = authority
                    .signed_dci()
                    .ok_or(HostFailure::ContractViolation)?;
                let authored_request =
                    serde_json::to_value(&options).map_err(|_| HostFailure::ContractViolation)?;
                let authored_request_bytes = u64::try_from(
                    canonicalize_json(&authored_request)
                        .map_err(|_| HostFailure::ContractViolation)?
                        .len(),
                )
                .map_err(|_| HostFailure::BudgetExceeded)?;
                consume_aggregate_bytes(
                    &mut self.request_bytes,
                    authored_request_bytes,
                    u64::from(dci.request_max_bytes()),
                )?;
                let remaining_source_bytes = self
                    .bound
                    .plan()
                    .limits()
                    .operation()
                    .max_source_bytes
                    .checked_sub(self.source_bytes)
                    .filter(|remaining| *remaining > 0)
                    .ok_or(HostFailure::BudgetExceeded)?;
                let verified = execute_signed_dci_search_call(
                    self.dispatch,
                    self.bound,
                    self.fence,
                    self.oauth_credentials,
                    options,
                    remaining_source_bytes,
                )
                .await?;
                consume_aggregate_bytes(
                    &mut self.source_bytes,
                    verified.source_bytes,
                    self.bound.plan().limits().operation().max_source_bytes,
                )?;
                return Ok(verified.response);
            }
            call => call,
        };
        let destination = self
            .bound
            .plan()
            .data_destination()
            .ok_or(HostFailure::ContractViolation)?;
        if !generic_script_source_calls_allowed(self.bound.plan()) {
            // Signed DCI authority is protocol-owned. Generic Script source
            // methods must not expose an unverified response to Rhai.
            return Err(HostFailure::ContractViolation);
        }
        let prepared = prepare_rhai_call(self.bound.plan(), destination, call)?;
        let authority = self
            .bound
            .plan()
            .script_authority()
            .ok_or(HostFailure::ContractViolation)?;
        let rule = prepared.rule;
        consume_aggregate_bytes(
            &mut self.request_bytes,
            prepared.author_controlled_bytes()?,
            u64::from(authority.request_max_bytes()),
        )?;
        if authority.auth() == CompiledSourceAuth::OAuthClientCredentials
            && self.oauth_token.is_none()
        {
            self.oauth_token = match execute_oauth_credential(
                self.dispatch,
                self.bound,
                self.fence,
                self.oauth_credentials,
            )
            .await
            .map_err(|_| HostFailure::SourceUnavailable)?
            {
                CredentialDispatchResultV1::Token(token) => Some(token),
                CredentialDispatchResultV1::KnownFailure(_) => return Err(HostFailure::SourceAuth),
            };
        }

        let header_refs = prepared
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_bytes()))
            .collect::<Vec<_>>();
        let request = match authority.auth() {
            CompiledSourceAuth::None => rule.transport_template().render_script(
                &prepared.target,
                &header_refs,
                None,
                None,
                prepared.body_format,
                prepared.body,
            ),
            CompiledSourceAuth::Basic => self
                .basic_credentials
                .authorization_for_script(self.bound.plan(), authority)
                .map_err(|_| HostFailure::SourceAuth)?
                .render(
                    rule.transport_template(),
                    &prepared.target,
                    &header_refs,
                    prepared.body_format,
                    prepared.body,
                ),
            CompiledSourceAuth::StaticBearer => self
                .static_bearer_credentials
                .authorization_for_script(self.bound.plan(), authority)
                .map_err(|_| HostFailure::SourceAuth)?
                .render(
                    rule.transport_template(),
                    &prepared.target,
                    &header_refs,
                    prepared.body_format,
                    prepared.body,
                ),
            CompiledSourceAuth::ApiKeyHeader | CompiledSourceAuth::ApiKeyQuery => self
                .static_bearer_credentials
                .api_key_for_script(self.bound.plan(), authority)
                .map_err(|_| HostFailure::SourceAuth)?
                .render(
                    rule.transport_template(),
                    &prepared.target,
                    &header_refs,
                    prepared.body_format,
                    prepared.body,
                ),
            CompiledSourceAuth::OAuthClientCredentials => {
                let authorization = self
                    .oauth_token
                    .as_ref()
                    .ok_or(HostFailure::SourceAuth)?
                    .bearer_authorization()
                    .map_err(|_| HostFailure::SourceAuth)?;
                rule.transport_template().render_script(
                    &prepared.target,
                    &header_refs,
                    Some(authorization),
                    None,
                    prepared.body_format,
                    prepared.body,
                )
            }
        }
        .map_err(|_| HostFailure::ContractViolation)?;
        let request_commitment = self
            .dispatch
            .commit_request_effect(
                CanonicalDispatchRequestEffect::try_from_complete_value(match authority.auth() {
                    CompiledSourceAuth::ApiKeyHeader => {
                        request.effect_value_without_api_key_header(destination.origin_id())
                    }
                    CompiledSourceAuth::ApiKeyQuery => {
                        request.effect_value_without_api_key_query(destination.origin_id())
                    }
                    _ => request.noncredential_effect_value(destination.origin_id()),
                })
                .map_err(|_| HostFailure::ContractViolation)?,
            )
            .map_err(|_| HostFailure::ContractViolation)?;
        let max_bytes = remaining_response_body_limit(
            self.source_bytes,
            self.bound.plan().limits().operation().max_source_bytes,
            authority.response_max_bytes(),
        )?;
        let permit = self
            .dispatch
            .next_data_permit_mut()
            .map_err(|_| HostFailure::ContractViolation)?
            .ok_or(HostFailure::BudgetExceeded)?;
        let (response, encoded_bytes) = self
            .fence
            .authorize_and_dispatch(permit, request_commitment, |deadline| async move {
                let deadline = operation_deadline(deadline, authority.request_timeout_ms())
                    .map_err(|_| HostFailure::SourceUnavailable)?;
                let response = destination
                    .send_with_deadline(request, deadline)
                    .await
                    .map_err(|_| HostFailure::SourceUnavailable)?;
                let status = response.status().as_u16();
                match status {
                    401 | 403 => return Err(HostFailure::SourceAuth),
                    429 => return Err(HostFailure::SourceRateLimited),
                    _ => {}
                }
                if authority.response_format() == CompiledResponseFormat::Json
                    && response.require_json_content_type().is_err()
                {
                    return Err(HostFailure::ContractViolation);
                }
                let selected_headers = response
                    .selected_script_response_headers(authority.response_headers())
                    .map_err(|_| HostFailure::ContractViolation)?;
                let body = response
                    .read_bounded(max_bytes)
                    .await
                    .map_err(|error| match error {
                        DestinationResponseError::BodyTooLarge => HostFailure::BudgetExceeded,
                        _ => HostFailure::SourceUnavailable,
                    })?;
                let (body, encoded_bytes) = match authority.response_format() {
                    CompiledResponseFormat::Json => decode_script_json(body)
                        .map_err(|_| HostFailure::ContractViolation)?
                        .into_parts(),
                    CompiledResponseFormat::Text => {
                        let (body, encoded_bytes) = decode_script_text(body)
                            .map_err(|_| HostFailure::ContractViolation)?
                            .into_parts();
                        (JsonValue::String(body.to_string()), encoded_bytes)
                    }
                };
                Ok((
                    SourceResponse {
                        status,
                        body,
                        headers: authority
                            .response_headers()
                            .zip(selected_headers)
                            .map(|(name, value)| (name.to_owned(), value))
                            .collect(),
                    },
                    encoded_bytes,
                ))
            })
            .await
            .map_err(|_| HostFailure::SourceUnavailable)??;
        consume_aggregate_bytes(
            &mut self.source_bytes,
            u64::try_from(encoded_bytes).map_err(|_| HostFailure::BudgetExceeded)?,
            self.bound.plan().limits().operation().max_source_bytes,
        )?;
        Ok(response)
    }
}

fn consume_aggregate_bytes(
    consumed: &mut u64,
    additional: u64,
    limit: u64,
) -> Result<(), HostFailure> {
    *consumed = consumed
        .checked_add(additional)
        .filter(|total| *total <= limit)
        .ok_or(HostFailure::BudgetExceeded)?;
    Ok(())
}

fn remaining_response_body_limit(
    consumed: u64,
    aggregate_limit: u64,
    per_response_limit: u32,
) -> Result<usize, HostFailure> {
    let remaining = aggregate_limit
        .checked_sub(consumed)
        .filter(|remaining| *remaining > 0)
        .ok_or(HostFailure::BudgetExceeded)?;
    usize::try_from(u64::from(per_response_limit).min(remaining))
        .map_err(|_| HostFailure::BudgetExceeded)
}

impl PreparedRhaiCall<'_> {
    fn author_controlled_bytes(&self) -> Result<u64, HostFailure> {
        self.target
            .len()
            .checked_add(
                self.headers
                    .iter()
                    .try_fold(0_usize, |total, (name, value)| {
                        total.checked_add(name.len())?.checked_add(value.len())
                    })
                    .ok_or(HostFailure::BudgetExceeded)?,
            )
            .and_then(|total| total.checked_add(self.body.as_ref().map_or(0, |body| body.len())))
            .and_then(|total| u64::try_from(total).ok())
            .ok_or(HostFailure::BudgetExceeded)
    }
}

fn prepare_rhai_call<'plan>(
    plan: &'plan CompiledSourcePlan,
    destination: &registry_platform_httputil::destination::DataDestinationPolicy,
    call: SourceCall,
) -> Result<PreparedRhaiCall<'plan>, HostFailure> {
    let (method, target, options, body_format, body) = match call {
        SourceCall::Get {
            target, options, ..
        } => (ReadMethod::Get, target, options, None, None),
        SourceCall::PostJson {
            target,
            body,
            options,
            ..
        } => (
            ReadMethod::ReadOnlyPost,
            target,
            options,
            Some(ScriptRequestBodyFormat::Json),
            Some(Zeroizing::new(
                serde_json::to_vec(&body).map_err(|_| HostFailure::ContractViolation)?,
            )),
        ),
        SourceCall::PostForm {
            target,
            fields,
            options,
            ..
        } => {
            let body = encode_rhai_form(fields)?;
            (
                ReadMethod::ReadOnlyPost,
                target,
                options,
                Some(ScriptRequestBodyFormat::Form),
                Some(Zeroizing::new(body)),
            )
        }
        SourceCall::DciSearch { .. } => return Err(HostFailure::ContractViolation),
    };
    let target = destination
        .canonicalize_same_origin_target(&target)
        .map_err(|_| HostFailure::ContractViolation)?;
    let target = canonical_rhai_target(&target, options.query)?;
    let authority = plan
        .script_authority()
        .ok_or(HostFailure::ContractViolation)?;
    let matches = authority
        .allow()
        .filter_map(|rule| {
            prepare_for_script_rule(rule, method, &target, &options.headers, body_format)
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [prepared] => Ok(PreparedRhaiCall {
            rule: prepared.rule,
            target,
            headers: prepared.headers.clone(),
            body_format,
            body,
        }),
        _ => Err(HostFailure::ContractViolation),
    }
}

pub(super) fn canonical_rhai_target(
    target: &str,
    option_query: BTreeMap<String, JsonValue>,
) -> Result<String, HostFailure> {
    let (path, target_query) = split_rhai_target(target)?;
    let query = merge_rhai_query(target_query, option_query)?;
    encode_rhai_target(path, &query)
}

fn prepare_for_script_rule<'a>(
    rule: &'a crate::source_plan::CompiledScriptAllowRule,
    method: ReadMethod,
    target: &str,
    headers: &BTreeMap<String, String>,
    body_format: Option<ScriptRequestBodyFormat>,
) -> Option<PreparedRhaiCall<'a>> {
    if rule.method() != method {
        return None;
    }
    let header_names = headers.keys().map(String::as_str).collect::<Vec<_>>();
    rule.transport_template()
        .validate_script_request_shape(target, &header_names, body_format)
        .ok()?;
    Some(PreparedRhaiCall {
        rule,
        target: target.to_owned(),
        headers: headers
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
        body_format,
        body: None,
    })
}

type RhaiQuery = Vec<(String, String)>;

fn split_rhai_target(target: &str) -> Result<(&str, RhaiQuery), HostFailure> {
    if !target.starts_with('/')
        || target.starts_with("//")
        || target.contains('#')
        || target.contains(['\r', '\n'])
    {
        return Err(HostFailure::ContractViolation);
    }
    let (path, raw_query) = target.split_once('?').unwrap_or((target, ""));
    let mut query = Vec::new();
    for member in raw_query.split('&').filter(|member| !member.is_empty()) {
        let (name, value) = member.split_once('=').unwrap_or((member, ""));
        let name = decode_rhai_component(name)?;
        let value = decode_rhai_component(value)?;
        query.push((name, value));
    }
    Ok((path, query))
}

fn merge_rhai_query(
    mut target: RhaiQuery,
    options: BTreeMap<String, JsonValue>,
) -> Result<RhaiQuery, HostFailure> {
    for (name, value) in options {
        if target.iter().any(|(target_name, _)| target_name == &name) {
            return Err(HostFailure::ContractViolation);
        }
        let values = match value {
            JsonValue::Null => Vec::new(),
            JsonValue::Array(values) => values,
            value => vec![value],
        };
        for value in values {
            let value = match value {
                JsonValue::Null => continue,
                JsonValue::Bool(value) => value.to_string(),
                JsonValue::Number(value) if value.as_i64().is_some() => value.to_string(),
                JsonValue::String(value) => value,
                _ => return Err(HostFailure::ContractViolation),
            };
            target.push((name.clone(), value));
        }
    }
    Ok(target)
}

fn encode_rhai_target(path: &str, query: &[(String, String)]) -> Result<String, HostFailure> {
    let mut target = String::from(path);
    for (index, (name, value)) in query.iter().enumerate() {
        target.push(if index == 0 { '?' } else { '&' });
        target.push_str(&encode_rhai_component(name));
        target.push('=');
        target.push_str(&encode_rhai_component(value));
        if target.len() > registry_platform_httputil::destination::MAX_DESTINATION_TARGET_BYTES {
            return Err(HostFailure::BudgetExceeded);
        }
    }
    Ok(target)
}

pub(super) fn encode_rhai_form(
    fields: BTreeMap<String, JsonValue>,
) -> Result<Vec<u8>, HostFailure> {
    let mut output = String::new();
    let mut emitted = 0_usize;
    for (name, value) in fields {
        let values = match value {
            JsonValue::Null => Vec::new(),
            JsonValue::Array(values) => values,
            value => vec![value],
        };
        for value in values {
            let value = match value {
                JsonValue::Null => continue,
                JsonValue::Bool(value) => value.to_string(),
                JsonValue::Number(value) if value.as_i64().is_some() => value.to_string(),
                JsonValue::String(value) => value,
                _ => return Err(HostFailure::ContractViolation),
            };
            if emitted > 0 {
                output.push('&');
            }
            output.push_str(&encode_rhai_component(&name));
            output.push('=');
            output.push_str(&encode_rhai_component(&value));
            emitted += 1;
        }
    }
    Ok(output.into_bytes())
}

fn decode_rhai_path_segment(value: &str) -> Option<String> {
    let decoded = decode_rhai_component(value).ok()?;
    (!decoded.is_empty() && !matches!(decoded.as_str(), "." | "..") && !decoded.contains('/'))
        .then_some(decoded)
}

fn decode_rhai_component(value: &str) -> Result<String, HostFailure> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = bytes.get(index + 1).and_then(|value| hex_value(*value));
            let low = bytes.get(index + 2).and_then(|value| hex_value(*value));
            output.push(
                high.zip(low)
                    .map(|(high, low)| high * 16 + low)
                    .ok_or(HostFailure::ContractViolation)?,
            );
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).map_err(|_| HostFailure::ContractViolation)
}

fn encode_rhai_component(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(output, "%{byte:02X}");
        }
    }
    output
}

const fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute_interactive_rhai(
    dispatch: &mut AuditedConsultationDispatch,
    bound: BoundConsultationExecution<'_>,
    publication: PendingPublicationContext,
    quota: QuotaGrant,
    fence: &PostgresServingFence,
    basic_credentials: &CompiledBasicSourceCredentialProvider,
    static_bearer_credentials: &CompiledStaticBearerSourceCredentialProvider,
    oauth_credentials: &CompiledOAuthSourceCredentialProvider,
) -> Result<ConcreteExecutorProof<PublishableConsultationResponse>, ConcreteExecutorUnfinished> {
    let request = build_rhai_request(&bound)?;
    let limiter = rhai_worker_limiter(bound.plan())?;
    let _worker_permit = limiter
        .acquire_owned()
        .await
        .map_err(|_| ConcreteExecutorUnfinished)?;
    let mut host = ProductionRhaiHost {
        dispatch,
        bound: &bound,
        fence,
        basic_credentials,
        static_bearer_credentials,
        oauth_credentials,
        oauth_token: None,
        request_bytes: 0,
        source_bytes: 0,
    };
    let worker = WorkerProcess::dedicated_executable().map_err(|_| ConcreteExecutorUnfinished)?;
    let output = worker
        .evaluate_with_host(&request, &mut host)
        .await
        .map_err(|_| ConcreteExecutorUnfinished)?;
    drop(host);
    drop(quota);
    match output {
        WorkerOutput::Success {
            outcome: WorkerOutcome::NoMatch,
            ..
        } => prepare_output_result(
            publication,
            bound.plan().runtime_profile(),
            ConsultationOutcome::NoMatch,
            None,
        ),
        WorkerOutput::Success {
            outcome: WorkerOutcome::Ambiguous,
            ..
        } => prepare_output_result(
            publication,
            bound.plan().runtime_profile(),
            ConsultationOutcome::Ambiguous,
            None,
        ),
        WorkerOutput::Success {
            outcome: WorkerOutcome::Match,
            outputs,
        } => {
            let outputs = outputs
                .into_iter()
                .map(|(name, value)| {
                    rhai_output_value(value).map(|value| (name.into_boxed_str(), value))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let output_map = ValidatedOutputMap::try_new(bound.plan().runtime_profile(), outputs)
                .map_err(|_| ConcreteExecutorUnfinished)?;
            prepare_output_result(
                publication,
                bound.plan().runtime_profile(),
                ConsultationOutcome::Match,
                Some(&output_map),
            )
        }
        WorkerOutput::Failure { failure } => {
            Ok(ConcreteExecutorProof::known_failure(match failure {
                ScriptFailure::SourceUnavailable => KnownFailureClass::SourceUnavailable,
                ScriptFailure::SourceRejected | ScriptFailure::SubjectMismatch => {
                    KnownFailureClass::ResponseContractViolation
                }
            }))
        }
    }
}

/// Consume one sealed execution through the startup-selected source capability.
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
        ConcreteExecutorKind::BoundedHttp | ConcreteExecutorKind::Script => {
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

fn append_absent_operation_outputs(
    operation: &CompiledOperation,
    outputs: &mut Vec<(Box<str>, ProjectedJsonScalar)>,
) {
    outputs.extend(
        operation
            .response()
            .outputs()
            .map(|field| (field.field().into(), ProjectedJsonScalar::Null)),
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

fn prepare_output_result(
    publication: PendingPublicationContext,
    profile: &crate::source_plan::runtime_profile::CompiledRuntimeProfile,
    outcome: ConsultationOutcome,
    outputs: Option<&ValidatedOutputMap>,
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
        outputs,
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
    let outputs = record
        .map(|record| {
            ValidatedOutputMap::try_new(
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
        outputs.as_ref(),
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
        signed_dci_script_runtime_plan_fixture,
    };

    #[test]
    fn script_byte_budgets_are_aggregate_and_bound_the_next_raw_stream() {
        let mut consumed = 0;
        assert_eq!(consume_aggregate_bytes(&mut consumed, 4, 10), Ok(()));
        assert_eq!(consume_aggregate_bytes(&mut consumed, 6, 10), Ok(()));
        assert_eq!(consumed, 10);
        assert_eq!(
            consume_aggregate_bytes(&mut consumed, 1, 10),
            Err(HostFailure::BudgetExceeded)
        );
        assert_eq!(consumed, 10, "a rejected call cannot consume budget");

        assert_eq!(remaining_response_body_limit(4, 10, 8), Ok(6));
        assert_eq!(remaining_response_body_limit(4, 10, 3), Ok(3));
        assert_eq!(
            remaining_response_body_limit(10, 10, 8),
            Err(HostFailure::BudgetExceeded)
        );
    }

    #[test]
    fn signed_dci_script_seals_one_verification_and_one_data_effect() {
        let plan = signed_dci_script_runtime_plan_fixture();
        assert_eq!(validate_script_activation(&plan), Ok(()));
        assert_eq!(
            ConcreteExecutorKind::Script.permit_counts(&plan),
            Ok((1, 1, 1))
        );
        assert_eq!(
            plan.runtime_profile().permit_bindings().collect::<Vec<_>>(),
            [("credential", 0), ("verification", 0), ("data", 0)]
        );
        assert!(!generic_script_source_calls_allowed(&plan));
    }

    #[test]
    fn rhai_query_serialization_preserves_repeats_and_omits_nulls() {
        let (path, target) = split_rhai_target("/records?tag=first&tag=second").expect("target");
        let merged = merge_rhai_query(
            target,
            BTreeMap::from([
                ("active".to_owned(), JsonValue::Bool(true)),
                (
                    "page".to_owned(),
                    JsonValue::Array(vec![
                        JsonValue::from(1),
                        JsonValue::Null,
                        JsonValue::from(2),
                    ]),
                ),
                ("unused".to_owned(), JsonValue::Null),
            ]),
        )
        .expect("bounded scalar query");
        assert_eq!(
            encode_rhai_target(path, &merged).expect("canonical target"),
            "/records?tag=first&tag=second&active=true&page=1&page=2"
        );
        assert!(merge_rhai_query(
            vec![("tag".to_owned(), "one".to_owned())],
            BTreeMap::from([("tag".to_owned(), JsonValue::String("two".to_owned()))]),
        )
        .is_err());
        assert!(merge_rhai_query(
            Vec::new(),
            BTreeMap::from([("nested".to_owned(), serde_json::json!([[1]]))]),
        )
        .is_err());
    }

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
        assert_eq!(validate_script_activation(&rhai), Ok(()));
        assert_eq!(
            ConcreteExecutorKind::activate(&rhai),
            Ok(ConcreteExecutorKind::Script)
        );
        let duplicate_selector = dhis2_duplicate_selector_runtime_vector_plan_fixture();
        assert_eq!(
            validate_bounded_http_activation(&duplicate_selector),
            Ok(())
        );
    }

    #[test]
    fn activation_accepts_eight_selectors_and_rejects_nine() {
        assert!(supported_input_counts(8, 8));
        assert!(supported_input_counts(16, 8));
        assert!(!supported_input_counts(9, 9));
        assert!(!supported_input_counts(17, 8));
        assert!(!supported_input_counts(8, 0));
    }

    #[test]
    fn rhai_worker_limiter_is_profile_scoped_and_uses_compiled_concurrency() {
        let plan = rhai_runtime_vector_plan_fixture();
        let expected = plan
            .runtime_profile()
            .dispatch()
            .script_limits()
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
    fn script_terminal_outputs_preserve_the_closed_scalar_types() {
        let string = rhai_output_value(RhaiTypedValue::String {
            value: Some("programme-a".to_owned()),
        })
        .unwrap_or_else(|_| panic!("bounded String output"));
        assert!(matches!(
            string,
            ProjectedJsonScalar::String(value) if value.as_str() == "programme-a"
        ));

        let date = rhai_output_value(RhaiTypedValue::Date {
            value: Some("2020-02-29".to_owned()),
        })
        .unwrap_or_else(|_| panic!("full-date output"));
        assert!(matches!(
            date,
            ProjectedJsonScalar::String(value) if value.as_str() == "2020-02-29"
        ));

        assert!(matches!(
            rhai_output_value(RhaiTypedValue::Boolean { value: Some(true) }),
            Ok(ProjectedJsonScalar::Boolean(true))
        ));
        assert!(matches!(
            rhai_output_value(RhaiTypedValue::Integer { value: Some(7) }),
            Ok(ProjectedJsonScalar::Integer(7))
        ));
        assert!(matches!(
            rhai_output_value(RhaiTypedValue::Date { value: None }),
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
        assert_eq!(executor.permit_counts(&opencrvs), Ok((1, 1, 1)));
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
