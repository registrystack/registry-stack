// SPDX-License-Identifier: Apache-2.0
//! Restricted BReg bridge for authoritative G2P instructions.

use super::g2p_model::{
    DisbursementInstruction, G2pAttempt, G2pError, G2pRegistryBinding, PreparedG2pRegistryAction,
};
use async_trait::async_trait;
use registry_breg_client::{
    BRegActionInvocationRequest, BRegActionTargetConditionsRequest, BRegIdempotencyKey,
    BRegPreparedAction, BRegRecordOptions, BaseRegistryClient, BaseRegistryClientConfig,
    StaticToken,
};
use registry_platform_config::SecretResolver;
use serde_json::{json, Map, Value};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use uuid::Uuid;

const MAX_MINOR_UNITS: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum G2pInstructionState {
    InstructionReady,
    AttemptBound,
    ProviderConfirmed,
}

#[derive(Clone)]
pub struct G2pInstructionView {
    pub instruction: DisbursementInstruction,
    pub state: G2pInstructionState,
    pub payout_attempt_id: Option<Uuid>,
    pub provider_binding_revision: Option<String>,
    pub provider_status: Option<String>,
    pub provider_reference: Option<String>,
    pub provider_result_digest: Option<String>,
}

impl G2pInstructionView {
    pub fn decode(record_id: Uuid, data: BTreeMap<String, Value>) -> Result<Self, G2pError> {
        let string = |key: &str| {
            data.get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(G2pError::Unavailable)
        };
        let integer = |key: &str| {
            data.get(key)
                .and_then(Value::as_u64)
                .filter(|value| *value <= MAX_MINOR_UNITS)
                .ok_or(G2pError::Unavailable)
        };
        let optional = |key: &str| match data.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.clone())),
            _ => Err(G2pError::Unavailable),
        };
        let instruction = DisbursementInstruction {
            record_id,
            instruction_id: Uuid::parse_str(&string("instructionId")?)
                .map_err(|_| G2pError::Unavailable)?,
            instruction_version: integer("instructionVersion")?,
            instruction_digest: string("instructionDigest")?,
            institution_id: string("institutionId")?,
            service_id: string("serviceId")?,
            programme_id: string("programmeId")?,
            cycle_id: string("cycleId")?,
            beneficiary_id: string("beneficiaryId")?,
            beneficiary_destination: string("beneficiaryDestination")?,
            funding_account_id: string("fundingAccountId")?,
            amount_minor: integer("amountMinor")?,
            currency: string("currency")?,
            currency_scale: u8::try_from(integer("currencyScale")?)
                .map_err(|_| G2pError::Unavailable)?,
        };
        instruction.validate()?;
        let state = match string("disbursementState")?.as_str() {
            "instruction-ready" => G2pInstructionState::InstructionReady,
            "attempt-bound" => G2pInstructionState::AttemptBound,
            "provider-confirmed" => G2pInstructionState::ProviderConfirmed,
            _ => return Err(G2pError::Unavailable),
        };
        let payout_attempt_id = optional("payoutAttemptId")?
            .map(|value| Uuid::parse_str(&value).map_err(|_| G2pError::Unavailable))
            .transpose()?;
        Ok(Self {
            instruction,
            state,
            payout_attempt_id,
            provider_binding_revision: optional("providerBindingRevision")?,
            provider_status: optional("providerStatus")?,
            provider_reference: optional("providerReference")?,
            provider_result_digest: optional("providerResultDigest")?,
        })
    }

    pub fn matches_bound(&self, attempt: &G2pAttempt) -> bool {
        self.instruction == attempt.instruction
            && self.payout_attempt_id == Some(attempt.id)
            && self.provider_binding_revision.as_deref() == Some(&attempt.binding_revision)
            && matches!(
                self.state,
                G2pInstructionState::AttemptBound | G2pInstructionState::ProviderConfirmed
            )
    }

    pub fn matches_confirmation(&self, attempt: &G2pAttempt) -> bool {
        let Some(observation) = &attempt.provider_observation else {
            return false;
        };
        let Some(reference) = observation.provider_reference.as_deref() else {
            return false;
        };
        self.matches_bound(attempt)
            && self.state == G2pInstructionState::ProviderConfirmed
            && self.provider_status.as_deref() == Some("COMPLETED")
            && self.provider_reference.as_deref() == Some(reference)
            && self.provider_result_digest.as_deref() == attempt.provider_result_digest.as_deref()
    }
}

pub fn bind_inputs(attempt: &G2pAttempt) -> Result<Map<String, Value>, G2pError> {
    bind_inputs_for(&attempt.instruction, attempt.id, &attempt.binding_revision)
}

pub fn bind_inputs_for(
    instruction: &DisbursementInstruction,
    attempt_id: Uuid,
    binding_revision: &str,
) -> Result<Map<String, Value>, G2pError> {
    instruction.validate()?;
    if attempt_id.is_nil() || binding_revision.is_empty() {
        return Err(G2pError::InvalidRequest);
    }
    object(json!({
        "instructionRecordId": instruction.record_id,
        "instructionId": instruction.instruction_id,
        "instructionVersion": instruction.instruction_version,
        "instructionDigest": instruction.instruction_digest,
        "institutionId": instruction.institution_id,
        "serviceId": instruction.service_id,
        "programmeId": instruction.programme_id,
        "cycleId": instruction.cycle_id,
        "beneficiaryId": instruction.beneficiary_id,
        "beneficiaryDestination": instruction.beneficiary_destination,
        "fundingAccountId": instruction.funding_account_id,
        "amountMinor": instruction.amount_minor,
        "currency": instruction.currency,
        "currencyScale": instruction.currency_scale,
        "payoutAttemptId": attempt_id,
        "providerBindingRevision": binding_revision,
    }))
}

pub fn confirmation_inputs(attempt: &G2pAttempt) -> Result<Map<String, Value>, G2pError> {
    if attempt.state != super::g2p_model::G2pAttemptState::ProviderConfirmed {
        return Err(G2pError::Conflict);
    }
    let observation = attempt
        .provider_observation
        .as_ref()
        .ok_or(G2pError::Conflict)?;
    let reference = observation
        .provider_reference
        .as_deref()
        .ok_or(G2pError::Conflict)?;
    let mut inputs = bind_inputs(attempt)?;
    inputs.insert("providerStatus".to_owned(), json!("COMPLETED"));
    inputs.insert("providerReference".to_owned(), json!(reference));
    inputs.insert(
        "providerResultDigest".to_owned(),
        json!(attempt
            .provider_result_digest
            .as_ref()
            .ok_or(G2pError::Conflict)?),
    );
    Ok(inputs)
}

#[async_trait]
pub trait G2pRegistryPort: Send + Sync {
    async fn read_instruction(
        &self,
        binding: &G2pRegistryBinding,
        record_id: Uuid,
    ) -> Result<G2pInstructionView, G2pError>;

    async fn prepare_bind(
        &self,
        binding: &G2pRegistryBinding,
        key: &str,
        inputs: Map<String, Value>,
    ) -> Result<PreparedG2pRegistryAction, G2pError>;

    async fn invoke_bind(
        &self,
        binding: &G2pRegistryBinding,
        prepared: &PreparedG2pRegistryAction,
    ) -> Result<(), G2pError>;

    async fn prepare_confirmation(
        &self,
        binding: &G2pRegistryBinding,
        key: &str,
        inputs: Map<String, Value>,
    ) -> Result<PreparedG2pRegistryAction, G2pError>;

    async fn invoke_confirmation(
        &self,
        binding: &G2pRegistryBinding,
        prepared: &PreparedG2pRegistryAction,
    ) -> Result<(), G2pError>;
}

pub struct BregG2pBridge {
    resolver: Arc<SecretResolver>,
}

impl BregG2pBridge {
    pub fn new(resolver: Arc<SecretResolver>) -> Self {
        Self { resolver }
    }

    fn client(&self, binding: &G2pRegistryBinding) -> Result<BaseRegistryClient, G2pError> {
        binding.validate()?;
        let secret = self
            .resolver
            .resolve(binding.credential_ref.as_str())
            .map_err(|_| G2pError::Unavailable)?;
        let token =
            std::str::from_utf8(secret.expose_secret()).map_err(|_| G2pError::Unavailable)?;
        let provider = StaticToken::new(token.to_owned()).map_err(|_| G2pError::Unavailable)?;
        let url = url::Url::parse(&binding.base_url).map_err(|_| G2pError::Unavailable)?;
        BaseRegistryClient::new(
            BaseRegistryClientConfig::new(url)
                .with_token_provider(Arc::new(provider))
                .with_attempt_timeout(Duration::from_secs(15))
                .with_connect_timeout(Duration::from_secs(5))
                .with_maximum_response_bytes(65_536)
                .with_maximum_mutation_retries(0),
        )
        .map_err(|_| G2pError::Unavailable)
    }

    async fn prepare(
        &self,
        binding: &G2pRegistryBinding,
        report: bool,
        key: &str,
        inputs: Map<String, Value>,
    ) -> Result<PreparedG2pRegistryAction, G2pError> {
        let client = self.client(binding)?;
        let (action, profile) = selected(binding, report);
        let metadata = client
            .registry_contract(Some(profile))
            .await
            .map_err(|_| G2pError::Unavailable)?
            .value;
        let selected = metadata
            .select_action(action, profile)
            .map_err(|_| G2pError::Unavailable)?;
        let key = BRegIdempotencyKey::parse(key).map_err(|_| G2pError::Unavailable)?;
        let conditions = if selected.required_condition_keys().is_empty() {
            None
        } else {
            let references = selected
                .required_condition_keys()
                .iter()
                .map(|name| inputs.get(name).cloned().map(|value| (name.clone(), value)))
                .collect::<Option<Map<_, _>>>()
                .ok_or(G2pError::Unavailable)?;
            let request = BRegActionTargetConditionsRequest::new(&selected, references)
                .map_err(|_| G2pError::Unavailable)?;
            Some(
                client
                    .action_target_conditions(&selected, &request)
                    .await
                    .map_err(|_| G2pError::Unavailable)?
                    .value,
            )
        };
        let request =
            BRegActionInvocationRequest::new(&selected, inputs.clone(), conditions.as_ref())
                .map_err(|_| G2pError::Unavailable)?;
        let evidence = client
            .prepare_action(&selected, &request, &key)
            .map_err(|_| G2pError::Unavailable)?;
        let evidence = std::str::from_utf8(evidence.as_bytes())
            .map_err(|_| G2pError::Unavailable)?
            .to_owned();
        Ok(PreparedG2pRegistryAction {
            action: action.to_owned(),
            key: key.as_str().to_owned(),
            inputs,
            evidence,
        })
    }

    async fn invoke(
        &self,
        binding: &G2pRegistryBinding,
        report: bool,
        prepared: &PreparedG2pRegistryAction,
    ) -> Result<(), G2pError> {
        let client = self.client(binding)?;
        let (action, profile) = selected(binding, report);
        if prepared.action != action {
            return Err(G2pError::RecoveryHeld);
        }
        let metadata = client
            .registry_contract(Some(profile))
            .await
            .map_err(|_| G2pError::Unavailable)?
            .value;
        let selected = metadata
            .select_action(action, profile)
            .map_err(|_| G2pError::RecoveryHeld)?;
        let key = BRegIdempotencyKey::parse(&prepared.key).map_err(|_| G2pError::RecoveryHeld)?;
        let saved = BRegPreparedAction::from_slice(prepared.evidence.as_bytes())
            .map_err(|_| G2pError::RecoveryHeld)?;
        let request = client
            .recover_action(&selected, &saved, &prepared.inputs, &key)
            .map_err(|_| G2pError::RecoveryHeld)?;
        client
            .invoke_action(&selected, &request, &key)
            .await
            .map_err(|_| G2pError::OutcomeUnknown)?;
        Ok(())
    }
}

#[async_trait]
impl G2pRegistryPort for BregG2pBridge {
    async fn read_instruction(
        &self,
        binding: &G2pRegistryBinding,
        record_id: Uuid,
    ) -> Result<G2pInstructionView, G2pError> {
        let client = self.client(binding)?;
        let options = BRegRecordOptions::default()
            .access_profile(&binding.read_profile)
            .map_err(|_| G2pError::Unavailable)?;
        let response = client
            .get_record(&binding.record_route, &record_id.to_string(), &options)
            .await
            .map_err(|_| G2pError::Unavailable)?
            .value;
        if response.meta.record_type_identifier != binding.record_type
            || response.data.record_identifier != record_id.to_string()
        {
            return Err(G2pError::Unavailable);
        }
        G2pInstructionView::decode(record_id, response.data.domain_data)
    }

    async fn prepare_bind(
        &self,
        binding: &G2pRegistryBinding,
        key: &str,
        inputs: Map<String, Value>,
    ) -> Result<PreparedG2pRegistryAction, G2pError> {
        self.prepare(binding, false, key, inputs).await
    }

    async fn invoke_bind(
        &self,
        binding: &G2pRegistryBinding,
        prepared: &PreparedG2pRegistryAction,
    ) -> Result<(), G2pError> {
        self.invoke(binding, false, prepared).await
    }

    async fn prepare_confirmation(
        &self,
        binding: &G2pRegistryBinding,
        key: &str,
        inputs: Map<String, Value>,
    ) -> Result<PreparedG2pRegistryAction, G2pError> {
        self.prepare(binding, true, key, inputs).await
    }

    async fn invoke_confirmation(
        &self,
        binding: &G2pRegistryBinding,
        prepared: &PreparedG2pRegistryAction,
    ) -> Result<(), G2pError> {
        self.invoke(binding, true, prepared).await
    }
}

fn selected(binding: &G2pRegistryBinding, report: bool) -> (&str, &str) {
    if report {
        (&binding.report_action, &binding.report_profile)
    } else {
        (&binding.bind_action, &binding.bind_profile)
    }
}

fn object(value: Value) -> Result<Map<String, Value>, G2pError> {
    value.as_object().cloned().ok_or(G2pError::Unavailable)
}
